package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func HandleListDingTalkKeys() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		items, err := app.ListDingTalkKeys(false)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func HandleSaveDingTalkKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var item service.DingTalkKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := app.SaveDingTalkKey(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved.Secret = ""
		c.JSON(http.StatusOK, saved)
	}
}

func HandleUpdateDingTalkKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "Key ID 不正确", err)
			return
		}
		var item service.DingTalkKey
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := app.SaveDingTalkKey(item)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved.Secret = ""
		c.JSON(http.StatusOK, saved)
	}
}

func HandleDeleteDingTalkKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil || id <= 0 {
			BadRequestResponse(c, "Key ID 不正确", err)
			return
		}
		if err := app.DeleteDingTalkKey(id); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}
