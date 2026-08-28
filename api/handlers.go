// api/handlers.go
package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/storage"
	"FusionWeb/backend/utils"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AppInterface 定义 App 的接口，用于 handlers
// 注意：这里需要导入 main 包的类型，但由于循环依赖问题，我们使用类型断言
type AppInterface interface {
	StartScanTask(config models.TaskConfig) (string, error)
	StartScanTaskWithUser(config models.TaskConfig, userID uint) (string, error)
	GetTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error)
	GetTaskDetail(taskID string, userID uint) (map[string]interface{}, error)
	PauseTask(taskID string, userID uint) error
	ResumeTask(taskID string, userID uint) error
	StopTaskWithUser(taskID string, userID uint) error
	RestartTask(taskID string, userID uint) (string, error)
	DeleteTask(taskID string, userID uint) error
	GetTaskProgressWithUser(taskID string, userID uint) (*models.ProgressInfo, error)
	GetTaskLogs(taskID string, level string, keyword string, page int, pageSize int, userID uint) (map[string]interface{}, error)
	GetReconResults(taskID string, resultType string, userID uint) ([]map[string]interface{}, error)
	GetVulnResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GetFingerprintResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GetSubdomainResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GetWeakPasswordResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GetDirectoryResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GetJSScanResults(taskID string, userID uint) ([]map[string]interface{}, error)
	GenerateHTMLReport(taskID string, userID uint) (string, error)
	GenerateExcelReport(taskID string, userID uint) (string, error)
	GenerateMDReport(taskID string, userID uint) (string, error)
	GetDashboardStats(userID uint) (map[string]interface{}, error)
}

// 任务管理 Handlers
func HandleCreateTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		var config models.TaskConfig
		if err := c.ShouldBindJSON(&config); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 验证输入长度
		if config.TaskName != "" {
			if err := utils.ValidateTaskName(config.TaskName); err != nil {
				BadRequestResponse(c, err.Error(), err)
				return
			}
		}
		// 从JWT中获取用户ID
		userID, exists := c.Get("userId")
		if !exists {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 使用 getAppInstance 辅助函数（它使用 ExtendedAppInterface）
		app := MustGetApp(c)
		// 传递用户ID到任务创建
		taskID, err := app.StartScanTaskWithUser(config, userID.(uint))
		if err != nil {
			if errors.Is(err, ErrInvalidAssignedWorker) {
				BadRequestResponse(c, err.Error(), err)
				return
			}
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"taskId": taskID})
	}
}

func HandleGetTasks() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 使用统一的权限分割逻辑
		userIDInt := int(userID)
		createdByFilter := utils.GetCreatedByFilterFromQuery(c.DefaultQuery("createdBy", ""), &userIDInt)
		// 使用 getAppInstance 辅助函数（它使用 ExtendedAppInterface）
		app := MustGetApp(c)
		tasks, err := app.GetTaskList(userID, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, tasks)
	}
}

func HandleTaskStream() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 设置 SSE Headers
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("Transfer-Encoding", "chunked")

		app := MustGetApp(c)

		// 创建 Ticker，每 3 秒推送一次
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		// 推送函数
		pushTasks := func() error {
			// 使用统一的权限分割逻辑
			userIDInt := int(userID)
			createdByFilter := utils.GetCreatedByFilterFromQuery(c.DefaultQuery("createdBy", ""), &userIDInt)

			tasks, err := app.GetTaskList(userID, createdByFilter)
			if err != nil {
				return err
			}

			jsonData, err := json.Marshal(tasks)
			if err != nil {
				return err
			}

			fmt.Fprintf(c.Writer, "data: %s\n\n", jsonData)
			c.Writer.Flush()
			return nil
		}

		// 立即推送一次
		if err := pushTasks(); err != nil {
			logger.Error("SSE 推送失败: %v", err)
			return
		}

		for {
			select {
			case <-c.Request.Context().Done():
				return
			case <-ticker.C:
				if err := pushTasks(); err != nil {
					logger.Error("SSE 推送失败: %v", err)
					return
				}
			}
		}
	}
}

func HandleGetTaskDetail() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		detail, err := app.GetTaskDetail(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, detail)
	}
}

func HandlePauseTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		if err := app.PauseTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task paused"})
	}
}

func HandleResumeTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		if err := app.ResumeTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task resumed"})
	}
}

func HandleStopTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		if err := app.StopTaskWithUser(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task stopped"})
	}
}

func HandleDeleteTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		if err := app.DeleteTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task deleted"})
	}
}

func HandleRestartTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		newTaskID, err := app.RestartTask(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"taskId": newTaskID})
	}
}

func HandleGetTaskProgress() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		progress, err := app.GetTaskProgressWithUser(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, progress)
	}
}

func HandleGetTaskLogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		level := c.DefaultQuery("level", "")
		keyword := c.DefaultQuery("keyword", "")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "50"))
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		logs, err := app.GetTaskLogs(taskID, level, keyword, page, pageSize, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, logs)
	}
}

func HandleGetTaskResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("id")
		resultType := c.DefaultQuery("type", "recon")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		results, err := app.GetReconResults(taskID, resultType, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

// 结果 Handlers
func HandleGetReconResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		resultType := c.DefaultQuery("type", "url")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		results, err := app.GetReconResults(taskID, resultType, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

func HandleGetReconScreenshot() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		resultID := c.Param("resultId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}

		var extraDataStr string
		err := database.DB.QueryRow(`
			SELECT extra_data
			FROM recon_results
			WHERE task_id = ? AND id = ? AND result_type = 'url'
		`, taskID, resultID).Scan(&extraDataStr)
		if err != nil {
			ErrorResponse(c, http.StatusNotFound, "截图记录不存在", err)
			return
		}

		var extraData map[string]interface{}
		if err := json.Unmarshal([]byte(extraDataStr), &extraData); err != nil {
			BadRequestResponse(c, "截图数据解析失败", err)
			return
		}
		screenshotKey := strings.TrimSpace(fmt.Sprint(extraData["screenshot_key"]))
		if screenshotKey == "" || screenshotKey == "<nil>" {
			screenshotKey = strings.TrimSpace(fmt.Sprint(extraData["screenshot_path"]))
		}
		if screenshotKey == "" || screenshotKey == "<nil>" {
			ErrorResponse(c, http.StatusNotFound, "当前目标没有截图", nil)
			return
		}

		if !strings.HasPrefix(strings.ReplaceAll(screenshotKey, "\\", "/"), "screenshots/") || !strings.HasSuffix(strings.ToLower(screenshotKey), ".png") {
			ForbiddenResponse(c, "截图对象不合法")
			return
		}

		object, err := storage.OpenObject(c.Request.Context(), screenshotKey)
		if err != nil {
			ErrorResponse(c, http.StatusNotFound, "截图文件不存在", err)
			return
		}
		defer object.Body.Close()

		contentType := object.ContentType
		if contentType == "" {
			contentType = "image/png"
		}
		c.Header("Cache-Control", "private, max-age=60")
		c.DataFromReader(http.StatusOK, -1, contentType, object.Body, nil)
	}
}

func HandleGetSubdomainResults() gin.HandlerFunc {
	return handleTaskScopedResult(func(app ExtendedAppInterface, taskID string, userID uint) ([]map[string]interface{}, error) {
		return app.GetSubdomainResults(taskID, userID)
	})
}

func HandleGetWeakPasswordResults() gin.HandlerFunc {
	return handleTaskScopedResult(func(app ExtendedAppInterface, taskID string, userID uint) ([]map[string]interface{}, error) {
		return app.GetWeakPasswordResults(taskID, userID)
	})
}

func HandleGetDirectoryResults() gin.HandlerFunc {
	return handleTaskScopedResult(func(app ExtendedAppInterface, taskID string, userID uint) ([]map[string]interface{}, error) {
		return app.GetDirectoryResults(taskID, userID)
	})
}

func HandleGetJSScanResults() gin.HandlerFunc {
	return handleTaskScopedResult(func(app ExtendedAppInterface, taskID string, userID uint) ([]map[string]interface{}, error) {
		return app.GetJSScanResults(taskID, userID)
	})
}

func handleTaskScopedResult(query func(app ExtendedAppInterface, taskID string, userID uint) ([]map[string]interface{}, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		app := MustGetApp(c)
		results, err := query(app, taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

func HandleGetVulnResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		results, err := app.GetVulnResults(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

func HandleGetFingerprintResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		results, err := app.GetFingerprintResults(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

// 报告 Handlers
func HandleGenerateHTMLReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		filePath, err := app.GenerateHTMLReport(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

func HandleGenerateExcelReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		filePath, err := app.GenerateExcelReport(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

func HandleGenerateMDReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		filePath, err := app.GenerateMDReport(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

// HandleDownloadReport 下载报告文件
func HandleDownloadReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("taskId")
		reportType := c.Param("type") // html, excel, json, markdown
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForTaskConfigAndRespond(c, taskID, userID, "无权访问该任务") {
			return
		}
		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		// 生成报告文件路径
		var filePath string
		var err error
		switch reportType {
		case "html":
			filePath, err = app.GenerateHTMLReport(taskID, userID)
		case "excel":
			filePath, err = app.GenerateExcelReport(taskID, userID)
		case "markdown":
			filePath, err = app.GenerateMDReport(taskID, userID)
		default:
			BadRequestResponse(c, "不支持的报告类型", nil)
			return
		}
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		// 读取文件并返回
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			InternalServerErrorResponse(c, "读取报告文件失败: "+err.Error(), err)
			return
		}

		// 任务完成后删除临时文件
		defer func() {
			if err := os.Remove(filePath); err != nil {
				logger.Warn("删除临时报告文件失败: %v", err)
			} else {
				logger.Debug("已删除临时报告文件: %s", filePath)
			}
		}()

		// 设置响应头
		fileName := filepath.Base(filePath)
		// 使用 RFC 5987 格式处理中文文件名
		// 先尝试 URL 编码文件名
		encodedFileName := url.QueryEscape(fileName)
		// 设置 Content-Disposition，使用 filename* 支持 UTF-8 编码
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", fileName, encodedFileName))
		switch reportType {
		case "html":
			c.Header("Content-Type", "text/html; charset=utf-8")
		case "excel":
			c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		case "markdown":
			c.Header("Content-Type", "text/markdown; charset=utf-8")
		}
		c.Data(http.StatusOK, "", fileData)
	}
}

// 仪表盘 Handler
func HandleGetDashboardStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			logger.Error("用户未认证")
			UnauthorizedResponse(c, "用户未认证")
			return
		}

		// 使用 getAppInstance 辅助函数（统一处理类型断言）
		app := MustGetApp(c)
		if !ok {
			logger.Error("获取 App 实例失败")
			return
		}

		stats, err := app.GetDashboardStats(userID)
		if err != nil {
			logger.Error("获取仪表盘统计失败: %v", err)
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

// 注意：由于 handlers 太多，这里只创建了基础的部分
// 其他 handlers（POC、指纹、黑名单等）需要类似的方式创建
// 为了简化，可以创建一个通用的 handler 包装器

// 通用 handler 包装器示例（需要根据实际情况调整）
type AppMethod func(interface{}, ...interface{}) (interface{}, error)

// 由于 handlers 数量很多，建议使用代码生成或反射来简化
// 这里先提供基础结构，后续可以根据需要扩展

// getUserInfoFromContext 从上下文中获取用户信息
// 注意：此函数已移动到 backend/utils/permission.go 中的 GetUserInfoFromGinContext
// 保留此函数以保持向后兼容，但建议使用 utils.GetUserInfoFromGinContext
func getUserInfoFromContext(c *gin.Context) (userID uint, ok bool) {
	return utils.GetUserInfoFromGinContext(c)
}
