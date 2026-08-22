package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const auditLogQueueSize = 4096

var (
	auditLogQueue      = make(chan auditLogEntry, auditLogQueueSize)
	auditLogWorkerOnce sync.Once
)

func auditLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		path := c.Request.URL.Path
		recordAccess := shouldRecordAccessLog(c.Request.Method, path)
		recordOperation := shouldRecordOperationLog(c.Request.Method, path)
		if !recordAccess && !recordOperation {
			return
		}
		if c.Writer.Status() == http.StatusUnauthorized {
			return
		}

		userID := 0
		if value, ok := GetUserIDFromContext(c); ok && value != nil {
			userID = *value
		}
		username := ""
		if value, ok := c.Get("username"); ok {
			username, _ = value.(string)
		}

		entry := auditLogEntry{
			UserID:    userID,
			Username:  username,
			IP:        getClientIP(c),
			Method:    c.Request.Method,
			Path:      path,
			Query:     c.Request.URL.RawQuery,
			Status:    c.Writer.Status(),
			LatencyMS: time.Since(start).Milliseconds(),
			UserAgent: c.GetHeader("User-Agent"),
			CreatedAt: utils.GetCurrentTimeString(),
			Access:    recordAccess,
			Operation: recordOperation,
		}

		enqueueAuditLog(entry)
	}
}

type auditLogEntry struct {
	UserID       int
	Username     string
	IP           string
	Method       string
	Path         string
	Query        string
	Status       int
	LatencyMS    int64
	UserAgent    string
	CreatedAt    string
	Access       bool
	Operation    bool
	Unauthorized bool
	Reason       string
}

func enqueueAuditLog(entry auditLogEntry) {
	auditLogWorkerOnce.Do(func() {
		go runAuditLogWorker()
	})

	select {
	case auditLogQueue <- entry:
	default:
		logger.Warn("审计日志队列已满，已丢弃一条访问日志")
	}
}

func runAuditLogWorker() {
	for entry := range auditLogQueue {
		insertAuditLogs(entry)
	}
}

func recordUnauthorizedAccessLog(c *gin.Context, reason string) {
	enqueueAuditLog(auditLogEntry{
		IP:           getClientIP(c),
		Method:       c.Request.Method,
		Path:         c.Request.URL.Path,
		Query:        c.Request.URL.RawQuery,
		Status:       http.StatusUnauthorized,
		UserAgent:    c.GetHeader("User-Agent"),
		CreatedAt:    utils.GetCurrentTimeString(),
		Unauthorized: true,
		Reason:       strings.TrimSpace(reason),
	})
}

func shouldRecordAccessLog(method, path string) bool {
	// 访问日志只记录前端主动上报的页面/模块访问，不再记录自动轮询 API。
	return false
}

func insertAuditLogs(entry auditLogEntry) {
	if database.DB == nil {
		return
	}

	if entry.Unauthorized {
		if err := execAuditSQL(
			`INSERT INTO unauthorized_access_logs (ip_address, method, path, query, status_code, reason, user_agent, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.IP, entry.Method, entry.Path, entry.Query, entry.Status, entry.Reason, entry.UserAgent, entry.CreatedAt,
		); err != nil {
			logger.Warn("记录未授权访问日志失败: %v", err)
		}
	}

	if entry.Access {
		if err := execAuditSQL(
			`INSERT INTO access_logs (user_id, username, ip_address, method, path, query, status_code, latency_ms, user_agent, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.UserID, entry.Username, entry.IP, entry.Method, entry.Path, entry.Query, entry.Status, entry.LatencyMS, entry.UserAgent, entry.CreatedAt,
		); err != nil {
			logger.Warn("记录访问日志失败: %v", err)
		}
	}

	if !entry.Operation {
		return
	}

	if err := execAuditSQL(
		`INSERT INTO operation_logs (user_id, username, ip_address, method, path, action, target, status_code, latency_ms, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.UserID, entry.Username, entry.IP, entry.Method, entry.Path, auditActionLabel(entry.Method), auditTargetLabel(entry.Path), entry.Status, entry.LatencyMS, entry.UserAgent, entry.CreatedAt,
	); err != nil {
		logger.Warn("记录操作日志失败: %v", err)
	}
}

func execAuditSQL(query string, args ...interface{}) error {
	const maxRetries = 5
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if _, err := database.DB.Exec(query, args...); err != nil {
			lastErr = err
			if !isRetryableAuditDBError(err) {
				return err
			}
			time.Sleep(time.Duration(attempt+1) * 150 * time.Millisecond)
			continue
		}
		return nil
	}
	return lastErr
}

func isRetryableAuditDBError(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "deadlock detected") ||
		strings.Contains(errText, "lock timeout") ||
		strings.Contains(errText, "could not serialize access")
}

func shouldRecordOperationLog(method, path string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
	default:
		return false
	}
	if strings.HasPrefix(path, "/api/auth/") {
		return false
	}
	return !strings.Contains(path, "/api/v1/system/")
}

func auditActionLabel(method string) string {
	switch method {
	case "POST":
		return "新增/提交"
	case "PUT", "PATCH":
		return "修改"
	case "DELETE":
		return "删除"
	default:
		return method
	}
}

func auditTargetLabel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "-"
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) <= 2 {
		return path
	}
	end := len(parts)
	if end > 4 {
		end = 4
	}
	return "/" + strings.Join(parts[:end], "/")
}
