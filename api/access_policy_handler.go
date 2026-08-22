package api

import (
	"FusionWeb/backend/service"
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type accessPolicyRequest struct {
	Category        string `json:"category"`
	Value           string `json:"value"`
	DurationMinutes int    `json:"durationMinutes"`
	StartsAt        string `json:"startsAt"`
	ExpiresAt       string `json:"expiresAt"`
}

func HandleGetAccessBlacklistByCategory() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		config, err := app.GetAccessBlacklistByCategory()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, config)
	}
}

func HandleGetAccessBlacklistItems() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		items, err := app.GetAccessBlacklistItems()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func HandleAddToAccessBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req accessPolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		var err error
		if req.StartsAt != "" || req.ExpiresAt != "" {
			err = app.AddToAccessBlacklistWithPeriod(req.Category, req.Value, req.StartsAt, req.ExpiresAt)
		} else {
			err = app.AddToAccessBlacklistWithDuration(req.Category, req.Value, req.DurationMinutes)
		}
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleRemoveFromAccessBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var req accessPolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.RemoveFromAccessBlacklistWithCategory(req.Category, req.Value); err != nil && !errors.Is(err, sql.ErrNoRows) {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleSaveAccessBlacklist() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		var config service.AccessPolicyConfig
		if err := c.ShouldBindJSON(&config); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		if err := app.SaveAccessBlacklistByCategory(config); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}
