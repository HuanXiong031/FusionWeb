// api/password_change_middleware.go
package api

import (
	"net/http"
	"strings"

	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"

	"github.com/gin-gonic/gin"
)

// passwordChangeWhitelist 是“必须先修改初始密码”状态下仍可访问的接口白名单。
// 这些接口用于完成强制改密流程以及退出登录，其他业务接口一律拒绝。
var passwordChangeWhitelist = map[string]struct{}{
	"/api/v1/users/profile":         {},
	"/api/v1/users/change-password": {},
	"/api/v1/users/logout":          {},
}

// PasswordChangeRequiredMiddleware 强制首次登录用户先修改初始密码。
// 当 users.must_change_password = 1 时，除白名单外的 /api/v1 请求返回 403，
// 防止绕开前端强制改密页面直接调用其他接口。
func PasswordChangeRequiredMiddleware(c *gin.Context) {
	if database.DB == nil {
		c.Next()
		return
	}

	path := strings.TrimSuffix(c.Request.URL.Path, "/")
	if _, ok := passwordChangeWhitelist[path]; ok {
		c.Next()
		return
	}

	userID := c.GetUint("userId")
	if userID == 0 {
		c.Next()
		return
	}

	var mustChange int
	if err := database.DB.QueryRow("SELECT must_change_password FROM users WHERE id = ?", userID).Scan(&mustChange); err != nil {
		// 数据库抖动时不阻断请求，避免全站不可用；改密拦截以正常查询结果为准。
		logger.Warn("检查强制改密状态失败: %v", err)
		c.Next()
		return
	}
	if mustChange != 1 {
		c.Next()
		return
	}

	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":               4031,
		"message":            "首次登录必须先修改初始密码",
		"mustChangePassword": true,
	})
}
