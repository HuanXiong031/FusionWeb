package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func HandleGetScanDictionaries() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		items, err := app.ListScanDictionary(c.Query("type"), c.Query("keyword"))
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func HandleGetScanDictionaryStatistics() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		stats, err := app.GetScanDictionaryStatistics()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

func HandleSaveScanDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var item service.ScanDictionaryItem
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := app.SaveScanDictionary(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleUpdateScanDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "字典 ID 不正确", err)
			return
		}
		app := MustGetApp(c)
		var item service.ScanDictionaryItem
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := app.SaveScanDictionary(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleDeleteScanDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "字典 ID 不正确", err)
			return
		}
		app := MustGetApp(c)
		if err := app.DeleteScanDictionary(id); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleDeleteScanDictionaryByType() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		if err := app.DeleteScanDictionaryByType(c.Query("type")); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleImportScanDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var req struct {
			Type    string   `json:"type"`
			Content string   `json:"content"`
			Values  []string `json:"values"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		values := req.Values
		if req.Content != "" {
			values = append(values, splitImportLines(req.Content)...)
		}
		summary, err := app.ImportScanDictionary(req.Type, values, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, summary)
	}
}
