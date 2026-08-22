package api

import (
	"FusionWeb/backend/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// PocTaskAppInterface defines the poc_task domain methods.
type PocTaskAppInterface interface {
	GetPocTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error)
	GetPocTaskDetail(taskID string) (map[string]interface{}, error)
	CreatePocTask(taskName string, targets []string, selectedPocs []string, config map[string]interface{}) (string, error)
	CreatePocTaskWithUser(taskName string, targets []string, selectedPocs []string, config map[string]interface{}, userID uint) (string, error)
	DeletePocTask(taskID string, userID uint) error
	GetPocTaskProgress(taskID string) (map[string]interface{}, error)
	ExecutePocTask(taskID string) error
	PausePocTask(taskID string, userID uint) error
	ResumePocTask(taskID string, userID uint) error
	StopPocTask(taskID string, userID uint) error
	GetPocScanResults(taskID string, severity string, page int, pageSize int, userID *int) (map[string]interface{}, error)
	GetPocScanResultDetail(resultID int, userID *int, taskID string) (map[string]interface{}, error)
	AddPocScanResult(result map[string]interface{}) (int64, error)
	DeletePocScanResult(resultID int) error
	DeletePocScanResultsByTask(taskID string) error
	GetPocScanResultStatistics(taskID string, userID *int) (map[string]interface{}, error)
	GeneratePocHTMLReport(taskID string) (string, error)
	GeneratePocExcelReport(taskID string) (string, error)
	GeneratePocMDReport(taskID string) (string, error)
}

func HandleGetPocTaskDetail() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		detail, err := app.GetPocTaskDetail(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, detail)
	}
}

func HandleCreatePocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		var req struct {
			TaskName     string                 `json:"taskName" binding:"required"`
			Targets      []string               `json:"targets" binding:"required"`
			SelectedPocs []string               `json:"selectedPocs" binding:"required"`
			Config       map[string]interface{} `json:"config"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 验证输入长度
		if err := utils.ValidateTaskName(req.TaskName); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 验证目标数量（防止DoS）
		if len(req.Targets) > 1000 {
			BadRequestResponse(c, "目标数量不能超过1000个", nil)
			return
		}
		// 验证每个目标长度
		for i, target := range req.Targets {
			if len(target) > 500 {
				BadRequestResponse(c, fmt.Sprintf("第%d个目标长度不能超过500个字符", i+1), nil)
				return
			}
		}
		// 验证POC数量（防止DoS）
		if len(req.SelectedPocs) > 1000 {
			BadRequestResponse(c, "POC数量不能超过1000个", nil)
			return
		}
		taskID, err := app.CreatePocTaskWithUser(req.TaskName, req.Targets, req.SelectedPocs, req.Config, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"taskId": taskID})
	}
}

func HandleDeletePocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		if err := app.DeletePocTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC task deleted"})
	}
}

func HandleGetPocTaskProgress() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		progress, err := app.GetPocTaskProgress(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, progress)
	}
}

func HandleExecutePocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		if err := app.ExecutePocTask(taskID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC task executed"})
	}
}

func HandlePausePocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		if err := app.PausePocTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task paused"})
	}
}

func HandleResumePocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		if err := app.ResumePocTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task resumed"})
	}
}

func HandleStopPocTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("id")
		if err := app.StopPocTask(taskID, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Task stopped"})
	}
}

// ============ POC 扫描结果 Handlers ============

func HandleGetPocScanResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("taskId")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		severity := c.DefaultQuery("severity", "")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
		userIDInt := int(userID)
		result, err := app.GetPocScanResults(taskID, severity, page, pageSize, &userIDInt)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

func HandleGetPocScanResultDetail() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		resultID, err := strconv.Atoi(c.Param("resultId"))
		if err != nil {
			BadRequestResponse(c, "Invalid result ID", nil)
			return
		}

		// 从 URL 中获取 taskId
		taskID := c.Param("taskId")

		detail, err := app.GetPocScanResultDetail(resultID, userID, taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, detail)
	}
}

func HandleAddPocScanResult() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var result map[string]interface{}
		if err := c.ShouldBindJSON(&result); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		id, err := app.AddPocScanResult(result)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id})
	}
}

func HandleDeletePocScanResult() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		resultID, err := strconv.Atoi(c.Param("resultId"))
		if err != nil {
			BadRequestResponse(c, "Invalid result ID", nil)
			return
		}
		if err := app.DeletePocScanResult(resultID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC scan result deleted"})
	}
}

func HandleDeletePocScanResultsByTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		taskID := c.Param("taskId")
		if err := app.DeletePocScanResultsByTask(taskID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC scan results deleted"})
	}
}

func HandleGetPocScanResultStatistics() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		taskID := c.Param("taskId")
		stats, err := app.GetPocScanResultStatistics(taskID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

// ============ POC 报告导出 Handlers ============

func HandleGeneratePocHTMLReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("taskId")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		filePath, err := app.GeneratePocHTMLReport(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

func HandleGeneratePocExcelReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("taskId")
		// 检查任务所有权并响应
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}
		filePath, err := app.GeneratePocExcelReport(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

func HandleDownloadPocReport() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		taskID := c.Param("taskId")
		reportType := c.Param("type")
		if !utils.CheckTaskOwnershipForPocScanTasksAndRespond(c, taskID, userID, "无权限操作该扫描任务") {
			return
		}

		var filePath string
		var err error
		switch reportType {
		case "html":
			filePath, err = app.GeneratePocHTMLReport(taskID)
		case "excel":
			filePath, err = app.GeneratePocExcelReport(taskID)
		case "markdown":
			filePath, err = app.GeneratePocMDReport(taskID)
		default:
			BadRequestResponse(c, "不支持的报告类型", nil)
			return
		}
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			InternalServerErrorResponse(c, "读取报告文件失败: "+err.Error(), err)
			return
		}
		defer func() {
			_ = os.Remove(filePath)
		}()

		fileName := filepath.Base(filePath)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
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
