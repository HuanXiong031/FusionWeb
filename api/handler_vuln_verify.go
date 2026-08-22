package api

import (
	"FusionWeb/backend/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// VulnVerifyAppInterface defines the vuln_verify domain methods.
type VulnVerifyAppInterface interface {
	// Cross-domain: POC report methods used by vuln verify handlers
	GeneratePocMDReport(taskID string) (string, error)
	GetManualVulnVerifyList(page int, pageSize int, keyword string, userID uint, createdByFilter *int) (map[string]interface{}, error)
	AddManualVulnVerify(name string) (int64, error)
	AddManualVulnVerifyWithUser(name string, userID uint) (int64, error)
	AddManualVulnVerifyWithUserAndGroup(name string, groupID int, request string, response string, userID uint) (int64, error)
	UpdateManualVulnVerify(id int, data map[string]interface{}, userID uint) error
	DeleteManualVulnVerify(id int, userID uint) error
	GetVulnVerifyGroups(userID uint, createdByFilter *int) ([]map[string]interface{}, error)
	AddVulnVerifyGroup(name string, userID uint) (int64, error)
	UpdateVulnVerifyGroup(id int, name string, userID uint) error
	DeleteVulnVerifyGroup(id int, userID uint) error
	GetManualVulnVerifyListByGroup(groupID int, userID uint) ([]map[string]interface{}, error)
	GetVulnVerifyWorkbench(userID uint) (map[string]interface{}, error)
	SaveVulnVerifyWorkbench(userID uint, data map[string]interface{}) (map[string]interface{}, error)
	SendRawRequest(method string, urlStr string, headers map[string]string, body string, timeout int) (map[string]interface{}, error)
}

func HandleGeneratePocMDReport() gin.HandlerFunc {
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
		filePath, err := app.GeneratePocMDReport(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filePath": filePath})
	}
}

// ============ 手动漏洞验证 Handlers ============

func HandleGetManualVulnVerifyList() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
		keyword := c.DefaultQuery("keyword", "")

		// 使用统一的权限分割逻辑
		userIDInt := int(userID)
		createdByFilter := utils.GetCreatedByFilterFromQuery(c.DefaultQuery("createdBy", ""), &userIDInt)

		result, err := app.GetManualVulnVerifyList(page, pageSize, keyword, userID, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

func HandleAddManualVulnVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		var req struct {
			Name     string `json:"name" binding:"required"`
			GroupID  int    `json:"group_id"`
			Request  string `json:"request"`
			Response string `json:"response"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		id, err := app.AddManualVulnVerifyWithUserAndGroup(req.Name, req.GroupID, req.Request, req.Response, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id})
	}
}

func HandleUpdateManualVulnVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			BadRequestResponse(c, "Invalid ID", nil)
			return
		}
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.UpdateManualVulnVerify(id, data, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Vuln verify updated"})
	}
}

func HandleDeleteManualVulnVerify() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			BadRequestResponse(c, "Invalid ID", nil)
			return
		}
		if err := app.DeleteManualVulnVerify(id, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Vuln verify deleted"})
	}
}

// ============ 漏洞验证分组 Handlers ============

func HandleGetVulnVerifyGroups() gin.HandlerFunc {
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
		groups, err := app.GetVulnVerifyGroups(userID, createdByFilter)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, groups)
	}
}

func HandleAddVulnVerifyGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		var req struct {
			Name string `json:"name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		id, err := app.AddVulnVerifyGroup(req.Name, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": id})
	}
}

func HandleUpdateVulnVerifyGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			BadRequestResponse(c, "Invalid ID", nil)
			return
		}
		var req struct {
			Name string `json:"name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.UpdateVulnVerifyGroup(id, req.Name, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Group updated"})
	}
}

func HandleDeleteVulnVerifyGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			BadRequestResponse(c, "Invalid ID", nil)
			return
		}
		if err := app.DeleteVulnVerifyGroup(id, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Group deleted"})
	}
}

func HandleGetManualVulnVerifyListByGroup() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		groupID, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			BadRequestResponse(c, "Invalid group ID", nil)
			return
		}
		list, err := app.GetManualVulnVerifyListByGroup(groupID, userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, list)
	}
}

func HandleGetVulnVerifyWorkbench() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		result, err := app.GetVulnVerifyWorkbench(userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

func HandleSaveVulnVerifyWorkbench() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserInfoFromContext(c)
		if !ok {
			UnauthorizedResponse(c, "用户未认证")
			return
		}
		app := MustGetApp(c)
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		result, err := app.SaveVulnVerifyWorkbench(userID, data)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

// ============ 工具方法 Handlers ============

func HandleSendRawRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			Method  string            `json:"method" binding:"required"`
			URL     string            `json:"url" binding:"required"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
			Timeout int               `json:"timeout"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		result, err := app.SendRawRequest(req.Method, req.URL, req.Headers, req.Body, req.Timeout)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}
