package api

import (
	"FusionWeb/backend/config"
	"github.com/gin-gonic/gin"
)

func HandleGetPublicAppConfig(c *gin.Context) {
	SuccessResponse(c, gin.H{"title": config.Get().WebTitle})
}
