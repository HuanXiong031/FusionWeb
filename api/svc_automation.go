// api/svc_automation.go
//
// 服务账号自动化接口（Phase 3）：让 DSH 等外部智能体能够
//   - 主动向钉钉推消息（notify）
//   - 在钉钉上"提问并等待人确认"（confirmations）
//
// 全部挂在 /api/v1/svc/* 下，由 ServiceTokenAuthMiddleware 按 scope 鉴权。
package api

import (
	"strconv"
	"strings"

	"FusionWeb/backend/service"

	"github.com/gin-gonic/gin"
)

// HandleSvcNotify 主动往钉钉推送一条消息（scope: notify:send）。
// 请求体：{"text":"...", "title":"可选"}
func HandleSvcNotify() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Text  string `json:"text"`
			Title string `json:"title"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		req.Text = strings.TrimSpace(req.Text)
		if req.Text == "" {
			BadRequestResponse(c, "text 不能为空", nil)
			return
		}
		title := strings.TrimSpace(req.Title)
		if title == "" {
			title = "DSH 消息"
		}
		if err := service.SendDingTalkText(0, title, req.Text); err != nil {
			InternalServerErrorResponse(c, "发送钉钉消息失败："+err.Error(), err)
			return
		}
		SuccessResponse(c, gin.H{"sent": true})
	}
}

// HandleSvcCreateConfirmation 创建待确认请求并推送到钉钉（scope: confirm:write）。
// 请求体：{"question":"...", "timeoutSec":600, "botId":0}
func HandleSvcCreateConfirmation() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Question   string `json:"question"`
			TimeoutSec int    `json:"timeoutSec"`
			BotID      int    `json:"botId"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item, err := service.CreatePendingConfirmation(req.Question, req.BotID, req.TimeoutSec)
		if item == nil {
			BadRequestResponse(c, "创建确认请求失败："+err.Error(), err)
			return
		}
		resp := gin.H{
			"id":        item.ID,
			"code":      item.Code,
			"status":    item.Status,
			"expiresAt": item.ExpiresAt.Format("2006-01-02 15:04:05"),
			"hint":      "请在钉钉回复：<code> 1 确认 / <code> 0 取消",
		}
		if err != nil {
			// 消息未发出去（例如机器人未配置目标），仍返回记录以便排查
			resp["warning"] = err.Error()
		}
		SuccessResponse(c, resp)
	}
}

// HandleSvcGetConfirmation 查询确认结果（scope: confirm:read）。
// 返回 status: pending | confirmed | denied | expired
func HandleSvcGetConfirmation() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("id"))
		if id == "" {
			BadRequestResponse(c, "缺少确认 ID", nil)
			return
		}
		var idNum int64
		if parsed, err := strconv.ParseInt(id, 10, 64); err != nil {
			BadRequestResponse(c, "确认 ID 格式错误", err)
			return
		} else {
			idNum = parsed
		}
		item, err := service.GetPendingConfirmation(idNum)
		if err != nil {
			c.JSON(404, gin.H{"code": 1, "message": err.Error()})
			return
		}
		SuccessResponse(c, gin.H{
			"id":        item.ID,
			"code":      item.Code,
			"question":  item.Question,
			"status":    item.Status,
			"answer":    item.Answer,
			"expiresAt": item.ExpiresAt.Format("2006-01-02 15:04:05"),
		})
	}
}
