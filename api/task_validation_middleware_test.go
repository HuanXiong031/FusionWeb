package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestValidateTaskTargetLimitRejectsOversizedTask(t *testing.T) {
	gin.SetMode(gin.TestMode)

	targets := make([]string, 10001)
	for i := range targets {
		targets[i] = "http://127.0.0.1"
	}
	payload, err := json.Marshal(map[string]any{
		"target_input": strings.Join(targets, "\n"),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	router := gin.New()
	router.POST("/tasks", ValidateTaskTargetLimit(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/tasks", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "单次扫描最多支持 10000 个目标") {
		t.Fatalf("unexpected response body: %s", recorder.Body.String())
	}
}
