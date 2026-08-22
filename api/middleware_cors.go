package api

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func getAllowedOrigins() []string {
	// 从环境变量读取（支持多个来源，用逗号分隔）
	if originsEnv := os.Getenv("CORS_ALLOWED_ORIGINS"); originsEnv != "" {
		origins := strings.Split(originsEnv, ",")
		// 清理空格
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		return origins
	}

	// 默认只允许本机前端开发服务跨域访问后端，便于前后端分离启动。
	// 线上跨域部署请显式设置 CORS_ALLOWED_ORIGINS。
	return []string{
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		"http://[::1]:5173",
	}
}

// corsMiddleware CORS中间件
func corsMiddleware() gin.HandlerFunc {
	allowedOrigins := getAllowedOrigins()

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// 开发环境允许所有来源
		if len(allowedOrigins) == 1 && allowedOrigins[0] == "*" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		} else if len(allowedOrigins) > 0 {
			// 检查请求来源是否在允许列表中
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}

			if allowed {
				c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			} else if origin != "" {
				// 来源不匹配，不设置CORS头（浏览器会拒绝请求）
				c.Writer.Header().Set("Access-Control-Allow-Origin", "null")
			}
		}
		// 如果allowedOrigins为空且origin为空，不设置CORS头（同源请求不需要CORS）

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// JWTAuthMiddleware JWT 身份验证中间件
