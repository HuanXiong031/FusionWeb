package api

import (
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// FingerprintAppInterface defines the fingerprint domain methods.
type FingerprintAppInterface interface {
	// Cross-domain: POC task methods used by fingerprint handlers
	GetPocTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error)
	GetFingerprintsPage(page, pageSize int, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error)
	GetFingerprintsPageByType(page, pageSize int, fpType, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error)
	GetFingerprints() ([]service.FingerprintItem, error)
	GetFingerprintCategories() ([]string, error)
	AddFingerprint(fp service.FingerprintItem, userID *int) error
	AddFingerprintWithType(fp service.FingerprintItem, fpType string, userID *int) error
	UpdateFingerprint(fp service.FingerprintItem) error
	UpdateFingerprintByOldName(oldName string, fp service.FingerprintItem) error
	DeleteFingerprint(name string) error
	DeleteAllFingerprints(userID *int, createdByFilter *int) (int, error)
	SearchFingerprints(keyword string) ([]service.FingerprintItem, error)
	ImportFingerprint(yamlContent string, fileName string) error
	ImportFingerprintWithType(yamlContent string, fileName string, fpType string) error
	ExportFingerprints() (string, error)
	ExportFingerprintsByType(exportType string) (string, error)
	ExportSingleFingerprint(name string, fpType string) (string, error)
	ExportFingerprintsToFile(exportType string) error
	GetFingerprintStatistics() (map[string]interface{}, error)
	ToggleFingerprintBlacklist(name string) error
	ToggleFingerprintEnabled(name string) error
	GetFingerprintCategoriesByType(fpType string) ([]string, error)
	AutoIdentifyFingerprint(url string) ([]string, error)
}

func HandleGetFingerprints() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		fingerprints, err := app.GetFingerprints()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, fingerprints)
	}
}

// HandleGetFingerprintCategories 获取指纹的所有分类名称列表。
// GET /api/fingerprints/categories
func HandleGetFingerprintCategories() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		categories, err := app.GetFingerprintCategories()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, categories)
	}
}

// HandleAddFingerprint 添加新的Web指纹记录。
// POST /api/fingerprints/add
// 请求体：FingerprintItem结构体（name, description, rules, type等）
// 成功后将当前用户关联为创建者。
func HandleAddFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		var fp service.FingerprintItem
		if err := c.ShouldBindJSON(&fp); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		userIDInt := int(userID)
		if err := app.AddFingerprint(fp, &userIDInt); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint added"})
	}
}

// HandleUpdateFingerprint 更新指纹记录的信息。
// POST /api/fingerprints/update
// 请求体支持可选oldName字段，当指纹名称被修改时通过oldName定位原始记录。
// 手动解析map[string]interface{}是因为FingerprintItem结构体无法直接用ShouldBindJSON绑定。
func HandleUpdateFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		// 接收请求体，可能包含 oldName 字段（用于指纹重命名场景）
		var requestBody map[string]interface{}
		if err := c.ShouldBindJSON(&requestBody); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}

		// 提取 oldName（如果存在）
		var oldName string
		if oldNameVal, ok := requestBody["oldName"]; ok {
			if oldNameStr, ok := oldNameVal.(string); ok {
				oldName = oldNameStr
			}
		}

		// 将请求体转换为 FingerprintItem（手动映射，因为已经读取了JSON）
		var fp service.FingerprintItem
		if nameVal, ok := requestBody["name"]; ok {
			if nameStr, ok := nameVal.(string); ok {
				fp.Name = nameStr
			}
		}
		if descVal, ok := requestBody["description"]; ok {
			if descStr, ok := descVal.(string); ok {
				fp.Description = descStr
			}
		}
		if rulesVal, ok := requestBody["rules"]; ok {
			if rulesArr, ok := rulesVal.([]interface{}); ok {
				fp.Rules = make([]string, len(rulesArr))
				for i, rule := range rulesArr {
					if ruleStr, ok := rule.(string); ok {
						fp.Rules[i] = ruleStr
					}
				}
			}
		}
		if typeVal, ok := requestBody["type"]; ok {
			if typeStr, ok := typeVal.(string); ok {
				fp.Type = typeStr
			}
		}
		if enabledVal, ok := requestBody["isEnabled"]; ok {
			if enabledBool, ok := enabledVal.(bool); ok {
				fp.IsEnabled = enabledBool
			}
		}
		if blacklistedVal, ok := requestBody["isBlacklisted"]; ok {
			if blacklistedBool, ok := blacklistedVal.(bool); ok {
				fp.IsBlacklisted = blacklistedBool
			}
		}

		// 如果提供了 oldName 且与新名称不同，使用 UpdateFingerprintByOldName
		if oldName != "" && oldName != fp.Name {
			if err := app.UpdateFingerprintByOldName(oldName, fp); err != nil {
				InternalServerErrorResponse(c, err.Error(), err)
				return
			}
		} else {
			// 否则使用普通的 UpdateFingerprint
			if err := app.UpdateFingerprint(fp); err != nil {
				InternalServerErrorResponse(c, err.Error(), err)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint updated"})
	}
}

// HandleDeleteFingerprint 删除指定名称的指纹记录。
// DELETE /api/fingerprints/:name
func HandleDeleteFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		name := c.Param("name")
		if err := app.DeleteFingerprint(name); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint deleted"})
	}
}

func HandleDeleteAllFingerprints() gin.HandlerFunc {
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

		deletedCount, err := app.DeleteAllFingerprints(userIDPtr, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "所有指纹已删除", "deletedCount": deletedCount})
	}
}

func HandleSearchFingerprints() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			Keyword string `json:"keyword" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		results, err := app.SearchFingerprints(req.Keyword)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

func HandleImportFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			YamlContent string `json:"yamlContent" binding:"required"`
			FileName    string `json:"fileName" binding:"required"`
			Type        string `json:"type"` // "active" 或 "passive"，可选，默认为空时使用 ImportFingerprint
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		// 如果指定了类型，使用 ImportFingerprintWithType
		if req.Type != "" && (req.Type == "active" || req.Type == "passive") {
			if err := app.ImportFingerprintWithType(req.YamlContent, req.FileName, req.Type); err != nil {
				InternalServerErrorResponse(c, err.Error(), err)
				return
			}
		} else {
			// 兼容旧版本，没有指定类型时使用 ImportFingerprint
			if err := app.ImportFingerprint(req.YamlContent, req.FileName); err != nil {
				InternalServerErrorResponse(c, err.Error(), err)
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint imported"})
	}
}

func HandleExportFingerprints() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		// 获取导出类型参数（passive/active/all，默认为all）
		exportType := c.Query("type")
		if exportType == "" {
			exportType = "all"
		}
		// 验证导出类型
		if exportType != "passive" && exportType != "active" && exportType != "all" {
			BadRequestResponse(c, "无效的导出类型，必须是 passive、active 或 all", nil)
			return
		}
		content, err := app.ExportFingerprintsByType(exportType)
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

func HandleExportSingleFingerprint() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		name := c.Query("name")
		fpType := c.Query("type")
		if name == "" {
			BadRequestResponse(c, "指纹名称不能为空", nil)
			return
		}
		if fpType == "" {
			fpType = "passive" // 默认为被动指纹
		}
		if fpType != "passive" && fpType != "active" {
			BadRequestResponse(c, "无效的指纹类型，必须是 passive 或 active", nil)
			return
		}
		content, err := app.ExportSingleFingerprint(name, fpType)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":    "yaml",
			"content": content,
		})
	}
}

func HandleGetFingerprintStatistics() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		stats, err := app.GetFingerprintStatistics()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

func HandleToggleFingerprintBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		name := c.Param("name")
		if err := app.ToggleFingerprintBlacklist(name); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint blacklist toggled"})
	}
}

func HandleToggleFingerprintEnabled() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		name := c.Param("name")
		if err := app.ToggleFingerprintEnabled(name); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fingerprint enabled toggled"})
	}
}

// ============ POC 任务管理 Handlers ============

func HandleGetPocTaskList() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		// 使用统一的权限分割逻辑
		userIDInt := int(userID)
		createdByFilter := utils.GetCreatedByFilterFromQuery(c.DefaultQuery("createdBy", ""), &userIDInt)

		tasks, err := app.GetPocTaskList(userID, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, tasks)
	}
}
