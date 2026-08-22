package api

import (
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"strings"
)

// PocAppInterface defines the poc domain methods.
type PocAppInterface interface {
	// Cross-domain: fingerprint methods used by POC handlers
	GetFingerprintsPageByType(page, pageSize int, fpType, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error)
	GetFingerprintsPage(page, pageSize int, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error)
	DeleteAllPOCs(userID *int, createdByFilter *int) (int, error)
	ExportAllPOCs(userID *int) (string, error)
	ExportSelectedPOCs(relativePaths []string, userID *int) (string, error)
	DebugScanPOC(templateContent string, targets []string, proxy string, debug bool, logPackets bool, taskID string) ([]map[string]interface{}, error)
	StopDebugScan(taskID string) error
	ValidatePOC(content string) (map[string]interface{}, error)
	GetPocFilesPage(page, pageSize int, category, keyword, severity string, userID *int) (map[string]interface{}, error)
	GetAllPocFiles(userID *int) ([]service.PocFileInfo, error)
	GetPocCategories(userID *int) ([]string, error)
	GetPocFileContent(relativePath string) (string, error)
	SearchPocFiles(keyword string, userID *int) ([]service.PocFileInfo, error)
	GetPocFileStatistics(userID *int) (map[string]interface{}, error)
	CreatePocFile(category string, fileName string, content string, userID *int) error
	UpdatePocFile(relativePath string, content string, category string, fileName ...string) error
	DeletePocFile(relativePath string) error
	RenamePocFile(oldRelativePath string, newRelativePath string) error
	ImportPocFile(category string, fileName string, base64Content string, userID *int) error
	LogImportFailures(failedFiles []map[string]interface{}, category string) error
	LogImportSuccess(totalFiles int, categoryCount int, categories map[string]int) error
}

func HandleDeleteAllPOCs() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}

		app := MustGetApp(c)

		userIDInt := int(userID)
		createdByFilter := utils.GetCreatedByFilterFromQuery(c.Query("createdBy"), &userIDInt)
		userIDPtr := createdByFilter

		deletedCount, err := app.DeleteAllPOCs(userIDPtr, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "所有模板已删除", "deletedCount": deletedCount})
	}
}

// HandleImportPOC 已移除：poc_templates 表已移除

// HandleExportAllPOCs 导出当前用户可见的所有POC文件内容。
// GET /api/pocs/export-all?createdBy=
// 返回格式可能是YAML文本或ZIP压缩包（以"zip:"前缀区分）。
func HandleExportAllPOCs() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		userIDInt := int(userID)
		content, err := app.ExportAllPOCs(&userIDInt)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		// 检查是否是 zip 文件（以 "zip:" 开头）
		if strings.HasPrefix(content, "zip:") {
			c.JSON(http.StatusOK, gin.H{
				"type":    "zip",
				"content": strings.TrimPrefix(content, "zip:"),
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"type":    "yaml",
				"content": content,
			})
		}
	}
}

// HandleExportSelectedPOCs 导出用户选择的特定POC文件内容。
// POST /api/pocs/export-selected
// 请求体：{"relativePaths": ["path/to/poc1.yaml", "path/to/poc2.yaml"]}
// 支持YAML和ZIP两种导出格式。
func HandleExportSelectedPOCs() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		var req struct {
			RelativePaths []string `json:"relativePaths" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, "请求参数错误: "+err.Error(), err)
			return
		}
		if len(req.RelativePaths) == 0 {
			BadRequestResponse(c, "未选择任何模板", nil)
			return
		}
		app := MustGetApp(c)
		userIDInt := int(userID)
		content, err := app.ExportSelectedPOCs(req.RelativePaths, &userIDInt)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		// 检查是否是 zip 文件（以 "zip:" 开头）
		if strings.HasPrefix(content, "zip:") {
			c.JSON(http.StatusOK, gin.H{
				"type":    "zip",
				"content": strings.TrimPrefix(content, "zip:"),
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"type":    "yaml",
				"content": content,
			})
		}
	}
}

// HandleExportPOC, HandleTestPOC 已移除：poc_templates 表已移除

// HandleDebugScanPOC 在调试模式下运行POC扫描（用于POC模板开发调试）。
// POST /api/pocs/debug-scan
// 请求体包含：POC模板内容、目标列表、代理设置、是否开启调试模式。
// 适用于开发者在编写新POC后快速验证POC逻辑正确性。
func HandleDebugScanPOC() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			TemplateContent string   `json:"templateContent" binding:"required"`
			Targets         []string `json:"targets" binding:"required"`
			Proxy           string   `json:"proxy"`
			Debug           bool     `json:"debug"`
			LogPackets      bool     `json:"logPackets"`
			TaskID          string   `json:"taskId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		results, err := app.DebugScanPOC(req.TemplateContent, req.Targets, req.Proxy, req.Debug, req.LogPackets, req.TaskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

// HandleStopDebugScan 停止正在运行的调试扫描任务。
// POST /api/pocs/stop-debug-scan
// 请求体：{"taskId": "任务ID"}
func HandleStopDebugScan() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			TaskID string `json:"taskId" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		err := app.StopDebugScan(req.TaskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "扫描已停止"})
	}
}

// HandleGetPOCCategories, HandleGetPOCStatistics 已移除：poc_templates 表已移除

// HandleValidatePOC 验证POC模板内容的语法和结构是否正确。
// POST /api/pocs/validate
// 请求体：{"content": "POC的YAML内容"}
// 返回验证结果（结构是否符合规范、字段是否完整等）。
func HandleValidatePOC() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			Content string `json:"content" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		result, err := app.ValidatePOC(req.Content)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

// ============ POC 文件管理 Handlers ============
// 基于文件系统的POC管理接口。POC模板以YAML文件形式存储在服务器磁盘上，
// 按category分类目录组织，支持文件的增删改查、搜索和统计。
// 当前按单用户可信模型读取 POC 文件；userID 参数保留给历史数据筛选。

// HandleGetPocFilesPage 获取POC文件的分页列表。
// GET /api/poc-files?page=1&pageSize=20&category=&keyword=&severity=
// 支持按分类、关键词和严重程度筛选，返回分页数据和总数。
func HandleGetPocFilesPage() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
		category := c.DefaultQuery("category", "")
		keyword := c.DefaultQuery("keyword", "")
		severity := c.DefaultQuery("severity", "")
		result, err := app.GetPocFilesPage(page, pageSize, category, keyword, severity, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

// HandleGetAllPocFiles 获取当前用户可见的所有POC文件列表（不分页）。
// GET /api/poc-files/all
// 返回完整列表，适用于前端下拉选择等场景。
func HandleGetAllPocFiles() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		files, err := app.GetAllPocFiles(userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, files)
	}
}

// HandleGetPocCategories 获取POC文件的所有分类名称列表。
// GET /api/poc-files/categories
// 用于前端分类筛选下拉框的数据源。
func HandleGetPocCategories() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		categories, err := app.GetPocCategories(userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, categories)
	}
}

// HandleGetPocFileContent 获取指定POC文件的完整内容。
// GET /api/poc-files/content?relativePath=xxx
// 用于前端查看和编辑POC模板的YAML内容。
func HandleGetPocFileContent() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		relativePath := c.Query("relativePath")
		if relativePath == "" {
			BadRequestResponse(c, "relativePath is required", nil)
			return
		}
		content, err := app.GetPocFileContent(relativePath)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"content": content})
	}
}

// HandleSearchPocFiles 按关键词搜索POC文件。
// POST /api/poc-files/search
// 请求体：{"keyword": "关键词"}
// 搜索范围限制在当前用户可见的文件内。
func HandleSearchPocFiles() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		var req struct {
			Keyword string `json:"keyword" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 验证关键字长度
		if err := utils.ValidateKeyword(req.Keyword); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		files, err := app.SearchPocFiles(req.Keyword, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, files)
	}
}

// HandleGetPocFileStatistics 获取POC文件的统计信息。
// GET /api/poc-files/statistics
// 返回按分类、严重程度等维度的统计汇总数据。
func HandleGetPocFileStatistics() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		stats, err := app.GetPocFileStatistics(userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

// HandleCreatePocFile 创建新的POC文件并写入磁盘。
// POST /api/poc-files/create
// 请求体：{"category": "分类", "fileName": "xxx.yaml", "content": "YAML内容"}
// 创建成功后自动关联当前用户ID。
func HandleCreatePocFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		var req struct {
			Category string `json:"category" binding:"required"`
			FileName string `json:"fileName" binding:"required"`
			Content  string `json:"content" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.CreatePocFile(req.Category, req.FileName, req.Content, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC file created"})
	}
}

// HandleUpdatePocFile 更新POC文件的内容和所属分类。
// PUT/POST /api/poc-files/update
// 请求体：{"relativePath": "路径", "content": "新内容", "category": "新分类"}
// Category字段可选，支持只更新内容不改变分类。
func HandleUpdatePocFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			RelativePath string `json:"relativePath" binding:"required"`
			Content      string `json:"content" binding:"required"`
			Category     string `json:"category"` // 可选：分类名称
			FileName     string `json:"fileName"` // 可选：文件名
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 验证输入长度
		if err := utils.ValidateContent(req.Content, "content"); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.UpdatePocFile(req.RelativePath, req.Content, req.Category, req.FileName); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC file updated"})
	}
}

// HandleDeletePocFile 从磁盘删除指定的POC文件。
// DELETE /api/poc-files/delete
// 请求体：{"relativePath": "文件相对路径"}
func HandleDeletePocFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			RelativePath string `json:"relativePath" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.DeletePocFile(req.RelativePath); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC file deleted"})
	}
}

// HandleRenamePocFile 重命名POC文件（包括移动文件到不同路径）。
// POST /api/poc-files/rename
// 请求体：{"oldRelativePath": "旧路径", "newRelativePath": "新路径"}
func HandleRenamePocFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			OldRelativePath string `json:"oldRelativePath" binding:"required"`
			NewRelativePath string `json:"newRelativePath" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.RenamePocFile(req.OldRelativePath, req.NewRelativePath); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC file renamed"})
	}
}

// HandleImportPocFile 从Base64编码内容导入单个POC文件。
// POST /api/poc-files/import
// 请求体：{"category": "分类", "fileName": "xxx.yaml", "base64Content": "..."}
// 适用于前端上传POC文件后，将Base64内容写入服务器磁盘。
func HandleImportPocFile() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		var req struct {
			Category      string `json:"category" binding:"required"`
			FileName      string `json:"fileName" binding:"required"`
			Base64Content string `json:"base64Content" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.ImportPocFile(req.Category, req.FileName, req.Base64Content, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "POC file imported"})
	}
}

// HandleLogImportFailures 记录POC文件批量导入过程中失败的文件列表。
// POST /api/poc-files/import-failures
// 用于前端在批量导入完成后，将失败信息持久化到日志系统。
func HandleLogImportFailures() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			FailedFiles []map[string]interface{} `json:"failedFiles" binding:"required"`
			Category    string                   `json:"category"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.LogImportFailures(req.FailedFiles, req.Category); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Import failures logged"})
	}
}

// HandleLogImportSuccess 记录POC文件批量导入的成功统计信息。
// POST /api/poc-files/import-success
// 记录导入的总文件数、分类数及各分类的文件分布。
func HandleLogImportSuccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			TotalFiles    int            `json:"totalFiles" binding:"required"`
			CategoryCount int            `json:"categoryCount" binding:"required"`
			Categories    map[string]int `json:"categories"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.LogImportSuccess(req.TotalFiles, req.CategoryCount, req.Categories); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Import success logged"})
	}
}

// ============ 指纹管理 Handlers ============
// Web指纹库管理接口。指纹分为主动(active)和被动(passive)两种类型，
// 用于识别目标网站的技术栈和组件信息。
// 支持YAML格式的指纹导入导出，以及基于用户的数据隔离。

// HandleGetFingerprintsPage 获取指纹的分页列表。
// GET /api/fingerprints/page?page=1&pageSize=20&category=&keyword=&sortBy=&sortOrder=
// 智能路由：category为"active"/"passive"时按指纹类型查询，否则按分类名称查询。
// 支持多字段排序和权限过滤。
func HandleGetFingerprintsPage() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前用户信息
		userIDInterface, _ := c.Get("userId")
		var userID *int
		if userIDInterface != nil {
			userIDUint := userIDInterface.(uint)
			userIDInt := int(userIDUint)
			userID = &userIDInt
		}

		app := MustGetApp(c)
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
		category := c.DefaultQuery("category", "")
		keyword := c.DefaultQuery("keyword", "")
		sortBy := c.DefaultQuery("sortBy", "")
		sortOrder := c.DefaultQuery("sortOrder", "")
		blacklistedOnly := c.DefaultQuery("blacklisted", "") == "true"

		// 使用统一的权限分割逻辑
		createdByFilter := utils.GetCreatedByFilterFromQuery(c.DefaultQuery("createdBy", ""), userID)

		// 如果 category 是 "active" 或 "passive"，则作为指纹类型处理
		// 否则作为分类名称处理
		var result map[string]interface{}
		var err error
		if category == "active" || category == "passive" {
			// 使用 GetFingerprintsPageByType 按类型查询
			result, err = app.GetFingerprintsPageByType(page, pageSize, category, "", keyword, sortBy, sortOrder, createdByFilter, blacklistedOnly)
		} else {
			// 使用 GetFingerprintsPage 按分类查询（默认被动指纹）
			result, err = app.GetFingerprintsPage(page, pageSize, category, keyword, sortBy, sortOrder, createdByFilter, blacklistedOnly)
		}

		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

// HandleGetFingerprints 获取所有指纹的完整列表（不分页）。
// GET /api/fingerprints
