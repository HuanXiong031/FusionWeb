package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func currentUserIDValue(c *gin.Context) int {
	if userID, ok := GetUserIDFromContext(c); ok && userID != nil {
		return *userID
	}
	return 0
}

func HandleListAIAPIKeys() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		items, err := app.ListAIAPIKeys(false, currentUserIDValue(c))
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, items)
	}
}

func HandleSaveAIAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var item service.AIAPIKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := app.SaveAIAPIKey(item, currentUserIDValue(c))
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}

func HandleUpdateAIAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "Key ID 不正确", err)
			return
		}
		var item service.AIAPIKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := app.SaveAIAPIKey(item, currentUserIDValue(c))
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, saved)
	}
}

func HandleDeleteAIAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "Key ID 不正确", err)
			return
		}
		if err := app.DeleteAIAPIKey(id, currentUserIDValue(c)); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleTestAIAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "Key ID 不正确", err)
			return
		}
		result, err := app.TestAIAPIKey(id, currentUserIDValue(c))
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, result)
	}
}

func HandleAIChat() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req service.AIChatRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		resp, err := app.ChatWithAI(req, currentUserIDValue(c))
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		SuccessResponse(c, resp)
	}
}
