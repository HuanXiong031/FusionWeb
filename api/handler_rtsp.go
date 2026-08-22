package api

import (
	"FusionWeb/backend/service"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func HandleGetRTSPDictionaries() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		items, err := app.ListRTSPDictionary(c.Query("type"), c.Query("keyword"))
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, items)
	}
}

func HandleGetRTSPDictionaryStatistics() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		stats, err := app.GetRTSPDictionaryStatistics()
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, stats)
	}
}

func HandleSaveRTSPDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var item service.RTSPDictionaryItem
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		saved, err := app.SaveRTSPDictionary(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleUpdateRTSPDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "字典 ID 不正确", err)
			return
		}
		app := MustGetApp(c)
		var item service.RTSPDictionaryItem
		if err := c.ShouldBindJSON(&item); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		item.ID = id
		saved, err := app.SaveRTSPDictionary(item, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, saved)
	}
}

func HandleDeleteRTSPDictionary() gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "字典 ID 不正确", err)
			return
		}
		app := MustGetApp(c)
		if err := app.DeleteRTSPDictionary(id); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleDeleteRTSPDictionaryByType() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		if err := app.DeleteRTSPDictionaryByType(c.Query("type")); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleImportRTSPDictionary() gin.HandlerFunc {
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
		summary, err := app.ImportRTSPDictionary(req.Type, values, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, summary)
	}
}

func HandleStartRTSPScan() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		var req service.RTSPScanConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		state, err := app.StartRTSPScan(req, userID)
		if err != nil {
			BadRequestResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, state)
	}
}

func HandleStopRTSPScan() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		taskID := strings.TrimSpace(c.Param("taskId"))
		if taskID == "" {
			BadRequestResponse(c, "任务 ID 不能为空", nil)
			return
		}
		if err := app.StopRTSPScan(taskID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func HandleGetRTSPScanState() gin.HandlerFunc {
	return func(c *gin.Context) {
		app := MustGetApp(c)
		taskID := strings.TrimSpace(c.Param("taskId"))
		if taskID == "" {
			BadRequestResponse(c, "任务 ID 不能为空", nil)
			return
		}
		state, err := app.GetRTSPScanState(taskID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, state)
	}
}

func HandleGetRTSPResults() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		app := MustGetApp(c)
		results, err := app.ListRTSPResults(c.Query("taskId"), userID)
		if err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, results)
	}
}

func HandleDeleteRTSPResult() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserIDValue(c)
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil || id <= 0 {
			BadRequestResponse(c, "结果 ID 不正确", err)
			return
		}
		app := MustGetApp(c)
		if err := app.DeleteRTSPResult(id, userID); err != nil {
			InternalServerErrorResponse(c, err.Error(), err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	}
}

func GetUserIDValue(c *gin.Context) int {
	userID, ok := GetUserIDFromContext(c)
	if !ok || userID == nil {
		return 0
	}
	return *userID
}

func splitImportLines(content string) []string {
	parts := strings.FieldsFunc(content, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}
