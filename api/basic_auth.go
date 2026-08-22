package api

import (
	"FusionWeb/backend/config"
	"crypto/subtle"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// BasicAuthMiddleware protects the web shell. API calls use JWT because both
// schemes share the Authorization header; Nginx applies Basic Auth to the SPA.
func BasicAuthMiddleware() gin.HandlerFunc {
	cfg := config.Get()
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !cfg.BasicAuth || c.Request.Method == http.MethodOptions || strings.HasPrefix(path, "/api/") || path == "/ws" {
			c.Next()
			return
		}
		if strings.TrimSpace(cfg.BasicUser) == "" || cfg.BasicPass == "" {
			c.Header("WWW-Authenticate", `Basic realm="FusionWeb"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 1, "message": "Basic 认证已开启，但账号或密码未配置"})
			return
		}
		user, pass, ok := c.Request.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(cfg.BasicUser)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(cfg.BasicPass)) != 1 {
			c.Header("WWW-Authenticate", `Basic realm="FusionWeb"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
