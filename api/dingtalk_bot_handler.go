package api

import (
	"FusionWeb/backend/service"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

func parseID(c *gin.Context) (int, error) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		return 0, gin.Error{Err: err, Type: gin.ErrorTypePublic, Meta: "ID 不正确"}
	}
	return id, nil
}

func requireDingTalkAdmin(c *gin.Context) bool {
	if RequireRole(c, "admin") {
		return true
	}
	ForbiddenResponse(c, "需要管理员权限")
	return false
}
func HandleListDingTalkBots() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		items, err := service.NewDingTalkBotService().ListBots()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, items)
	}
}
func HandleSaveDingTalkBot() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		var item service.DingTalkBot
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := service.NewDingTalkBotService().SaveBot(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}
func HandleUpdateDingTalkBot() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		var item service.DingTalkBot
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := service.NewDingTalkBotService().SaveBot(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}
func HandleDeleteDingTalkBot() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		if err := service.NewDingTalkBotService().DeleteBot(id); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}
func HandleTestDingTalkBot() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		if err := service.NewDingTalkBotService().TestBot(id); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, gin.H{"status": "success", "message": "测试消息已发送"})
	}
}
func HandleReconnectDingTalkBot() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		if err := service.NewDingTalkBotService().ReconnectBot(id); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, gin.H{"status": "reconnecting"})
	}
}
func HandleDingTalkBotStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		item, err := service.NewDingTalkBotService().GetBotStatus(id)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, item)
	}
}

func HandleDingTalkBotDiagnostics() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "机器人 ID 不正确", err)
			return
		}
		item, err := service.NewDingTalkBotService().GetDiagnostics(id)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, item)
	}
}

func HandleGenerateDingTalkBindingCode() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		var req struct {
			BotID int `json:"botId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		uid := currentUserIDValue(c)
		if uid <= 0 {
			BadRequestResponse(c, "当前用户无效", nil)
			return
		}
		code, err := service.NewDingTalkBotService().GenerateBindingCode(req.BotID, uid)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, code)
	}
}
func HandleBindDingTalkUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		var req struct {
			BotID        int    `json:"botId"`
			DingUserID   string `json:"dingUserId"`
			DingUserName string `json:"dingUserName"`
			Code         string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		uid := currentUserIDValue(c)
		if uid <= 0 {
			BadRequestResponse(c, "当前用户无效", nil)
			return
		}
		err := service.NewDingTalkBotService().BindCode(req.BotID, uid, req.DingUserID, req.DingUserName, req.Code)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, gin.H{"message": "绑定成功"})
	}
}
func HandleListDingTalkBindings() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Query("botId"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "botId 不正确", err)
			return
		}
		items, err := service.NewDingTalkBotService().ListBindings(id)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, items)
	}
}
func HandleDeleteDingTalkBinding() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "绑定 ID 不正确", err)
			return
		}
		if err := service.NewDingTalkBotService().DeleteBinding(id); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}
func HandleListDingTalkAllowlist() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Query("botId"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "botId 不正确", err)
			return
		}
		items, err := service.NewDingTalkBotService().ListAllowlist(id)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, items)
	}
}
func HandleSaveDingTalkAllowlist() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		var item service.DingTalkAllowlist
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := service.NewDingTalkBotService().SaveAllowlist(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}
func HandleUpdateDingTalkAllowlist() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "白名单 ID 不正确", err)
			return
		}
		var item service.DingTalkAllowlist
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := service.NewDingTalkBotService().SaveAllowlist(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}
func HandleDeleteDingTalkAllowlist() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireDingTalkAdmin(c) {
			return
		}
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "白名单 ID 不正确", err)
			return
		}
		if err := service.NewDingTalkBotService().DeleteAllowlist(id); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}
