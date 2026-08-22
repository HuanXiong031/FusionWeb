// blacklist_handler.go - 黑名单管理HTTP接口处理层

package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"github.com/gin-gonic/gin"
)

type BlacklistAppInterface interface {
	GetBlacklistByCategory() (service.BlacklistConfig, error)
	AddToBlacklistWithCategory(category, item string) error
	RemoveFromBlacklistWithCategory(category, item string) error
	SaveBlacklistByCategory(config service.BlacklistConfig) error
	GetCategories() ([]string, error)
}

func HandleGetBlacklistByCategory() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		config, err := app.GetBlacklistByCategory()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, config)
	}
}

func HandleAddToBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			Category string `json:"category"`
			Value    string `json:"value"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.AddToBlacklistWithCategory(req.Category, req.Value); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleRemoveFromBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req struct {
			Category string `json:"category"`
			Value    string `json:"value"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.RemoveFromBlacklistWithCategory(req.Category, req.Value); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleSaveBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var config service.BlacklistConfig
		if err := c.ShouldBindJSON(&config); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.SaveBlacklistByCategory(config); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}