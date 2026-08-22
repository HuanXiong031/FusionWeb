package api

import (
	"FusionWeb/backend/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gin-gonic/gin"
)

// ValidateTaskTargetLimit validates scan target count before a task is created.
func ValidateTaskTargetLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			BadRequestResponse(c, "读取请求体失败", err)
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var payload struct {
			TargetInput string `json:"target_input"`
		}
		if len(bytes.TrimSpace(body)) == 0 {
			c.Next()
			return
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			c.Next()
			return
		}

		targets := utils.ParseScanTargets(payload.TargetInput)
		if len(targets) == 0 {
			BadRequestResponse(c, "请输入扫描目标", nil)
			c.Abort()
			return
		}

		limiter := utils.GetResourceLimiter()
		if err := limiter.CheckTargetLimit(len(targets)); err != nil {
			BadRequestResponse(c, fmt.Sprintf("单次扫描最多支持 %d 个目标，当前为 %d 个。请拆分为多个任务后再提交。", limiter.MaxTargets(), len(targets)), err)
			c.Abort()
			return
		}

		c.Next()
	}
}
