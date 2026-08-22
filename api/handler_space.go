package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func HandleListSpaceEngineKeys() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		items, err := app.ListSpaceEngineKeys(userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func HandleSaveSpaceEngineKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var item service.SpaceEngineKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := app.SaveSpaceEngineKey(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleUpdateSpaceEngineKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "空间引擎配置 ID 不正确", err)
			return
		}
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var item service.SpaceEngineKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := app.SaveSpaceEngineKey(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleDeleteSpaceEngineKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "空间引擎配置 ID 不正确", err)
			return
		}
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		if err := app.DeleteSpaceEngineKey(id, userID); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleTestSpaceEngineKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "空间引擎配置 ID 不正确", err)
			return
		}
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		result, err := app.TestSpaceEngineKey(id, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}

func HandleSpaceOnlineSearch() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var req service.SpaceSearchRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		result, err := app.SearchSpace(c.Request.Context(), req, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, result)
	}
}
