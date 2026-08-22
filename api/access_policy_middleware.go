package api

import (
	"FusionWeb/backend/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

func accessPolicyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		decision := app.CheckAccessPolicy(service.AccessRequestInfo{
			ClientIP: c.ClientIP(),
			Host:     c.Request.Host,
			Origin:   c.GetHeader("Origin"),
			Referer:  c.GetHeader("Referer"),
		})
		if decision.Allowed {
			c.Next()
			return
		}

		c.AbortWithStatus(http.StatusForbidden)
	}
}
