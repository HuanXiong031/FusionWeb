package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type accessVisitRequest struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

func HandleRecordAccessVisit(c *gin.Context) {
	var req accessVisitRequest
	_ = c.ShouldBindJSON(&req)

	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/"
	}

	userID := 0
	if value, ok := GetUserIDFromContext(c); ok && value != nil {
		userID = *value
	}
	username := ""
	if value, ok := c.Get("username"); ok {
		username, _ = value.(string)
	}

	enqueueAuditLog(auditLogEntry{
		UserID:    userID,
		Username:  username,
		IP:        getClientIP(c),
		Method:    "访问",
		Path:      path,
		Query:     "",
		Status:    http.StatusOK,
		LatencyMS: 0,
		UserAgent: c.GetHeader("User-Agent"),
		CreatedAt: utils.GetCurrentTimeString(),
		Access:    true,
	})

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "访问日志已记录"})
}

func HandleGetAccessLogs(c *gin.Context) {
	all := isAllAuditLogQuery(c)
	page, pageSize := 1, 0
	if !all {
		var err error
		page, pageSize, err = ValidatePaginationParams(c, 20, 200)
		if err != nil {
			BadRequestResponse(c, err.Error(), nil)
			return
		}
	}

	filters := []auditFilter{
		{Column: "ip_address", Operator: "LIKE", Value: c.Query("ip")},
		{Column: "method", Operator: "=", Value: c.Query("method")},
		{Column: "path", Operator: "LIKE", Value: c.Query("path")},
		{Column: "CAST(status_code AS TEXT)", Operator: "=", Value: c.Query("status")},
	}
	logs, total, err := queryAuditLogs("access_logs", accessLogSelectSQL, filters, page, pageSize, all, scanAccessLogRow)
	if err != nil {
		logger.Error("查询访问日志失败: %v", err)
		InternalServerErrorResponse(c, "查询访问日志失败", err)
		return
	}
	if all {
		pageSize = total
	}
	enrichAuditLogLocations(logs)
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"list": logs, "total": total, "page": page, "pageSize": pageSize}})
}

func HandleClearAccessLogs(c *gin.Context) {
	clearAuditTable(c, "access_logs", "访问日志已清空")
}

func HandleGetOperationLogs(c *gin.Context) {
	all := isAllAuditLogQuery(c)
	page, pageSize := 1, 0
	if !all {
		var err error
		page, pageSize, err = ValidatePaginationParams(c, 20, 200)
		if err != nil {
			BadRequestResponse(c, err.Error(), nil)
			return
		}
	}

	filters := []auditFilter{
		{Column: "username", Operator: "LIKE", Value: c.Query("username")},
		{Column: "ip_address", Operator: "LIKE", Value: c.Query("ip")},
		{Column: "method", Operator: "=", Value: c.Query("method")},
		{Column: "path", Operator: "LIKE", Value: c.Query("path")},
		{Column: "action", Operator: "LIKE", Value: c.Query("action")},
		{Column: "CAST(status_code AS TEXT)", Operator: "=", Value: c.Query("status")},
	}
	logs, total, err := queryAuditLogs("operation_logs", operationLogSelectSQL, filters, page, pageSize, all, scanOperationLogRow)
	if err != nil {
		logger.Error("查询操作日志失败: %v", err)
		InternalServerErrorResponse(c, "查询操作日志失败", err)
		return
	}
	if all {
		pageSize = total
	}
	enrichAuditLogLocations(logs)
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"list": logs, "total": total, "page": page, "pageSize": pageSize}})
}

func HandleClearOperationLogs(c *gin.Context) {
	clearAuditTable(c, "operation_logs", "操作日志已清空")
}

func HandleGetUnauthorizedAccessLogs(c *gin.Context) {
	all := isAllAuditLogQuery(c)
	page, pageSize := 1, 0
	if !all {
		var err error
		page, pageSize, err = ValidatePaginationParams(c, 20, 200)
		if err != nil {
			BadRequestResponse(c, err.Error(), nil)
			return
		}
	}

	filters := []auditFilter{
		{Column: "ip_address", Operator: "LIKE", Value: c.Query("ip")},
		{Column: "method", Operator: "=", Value: c.Query("method")},
		{Column: "path", Operator: "LIKE", Value: c.Query("path")},
		{Column: "reason", Operator: "LIKE", Value: c.Query("reason")},
		{Column: "CAST(status_code AS TEXT)", Operator: "=", Value: c.Query("status")},
	}
	logs, total, err := queryAuditLogs("unauthorized_access_logs", unauthorizedAccessLogSelectSQL, filters, page, pageSize, all, scanUnauthorizedAccessLogRow)
	if err != nil {
		logger.Error("查询未授权访问日志失败: %v", err)
		InternalServerErrorResponse(c, "查询未授权访问日志失败", err)
		return
	}
	if all {
		pageSize = total
	}
	enrichAuditLogLocations(logs)
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{"list": logs, "total": total, "page": page, "pageSize": pageSize}})
}

func HandleClearUnauthorizedAccessLogs(c *gin.Context) {
	clearAuditTable(c, "unauthorized_access_logs", "未授权访问日志已清空")
}

type auditFilter struct {
	Column   string
	Operator string
	Value    string
}

const accessLogSelectSQL = `SELECT id, user_id, username, ip_address, method, path, query, status_code, latency_ms, user_agent, CAST(created_at AS TEXT) FROM access_logs`
const operationLogSelectSQL = `SELECT id, user_id, username, ip_address, method, path, action, target, status_code, latency_ms, user_agent, CAST(created_at AS TEXT) FROM operation_logs`
const unauthorizedAccessLogSelectSQL = `SELECT id, ip_address, method, path, query, status_code, reason, user_agent, CAST(created_at AS TEXT) FROM unauthorized_access_logs`

func isAllAuditLogQuery(c *gin.Context) bool {
	value := strings.ToLower(strings.TrimSpace(c.Query("all")))
	return value == "1" || value == "true" || value == "yes"
}

func queryAuditLogs(tableName, selectSQL string, filters []auditFilter, page, pageSize int, all bool, scanner func(*sql.Rows) (gin.H, error)) ([]gin.H, int, error) {
	whereClause, args := buildAuditWhere(filters)
	var total int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM "+tableName+" WHERE "+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := selectSQL + " WHERE " + whereClause + " ORDER BY created_at DESC, id DESC"
	queryArgs := args
	if !all {
		offset := (page - 1) * pageSize
		query += " LIMIT ? OFFSET ?"
		queryArgs = append(args, pageSize, offset)
	}

	rows, err := database.DB.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := []gin.H{}
	for rows.Next() {
		log, err := scanner(rows)
		if err != nil {
			logger.Warn("扫描审计日志行失败: %v", err)
			continue
		}
		logs = append(logs, log)
	}
	return logs, total, rows.Err()
}

func buildAuditWhere(filters []auditFilter) (string, []interface{}) {
	clauses := []string{"1=1"}
	args := []interface{}{}
	for _, filter := range filters {
		value := strings.TrimSpace(filter.Value)
		if value == "" {
			continue
		}
		clauses = append(clauses, fmt.Sprintf("%s %s ?", filter.Column, filter.Operator))
		if filter.Operator == "LIKE" {
			args = append(args, "%"+value+"%")
		} else {
			args = append(args, value)
		}
	}
	return strings.Join(clauses, " AND "), args
}

func scanAccessLogRow(rows *sql.Rows) (gin.H, error) {
	var id, userID, statusCode int
	var latencyMS int64
	var username, ipAddress, method, path, query, userAgent, createdAt sql.NullString
	if err := rows.Scan(&id, &userID, &username, &ipAddress, &method, &path, &query, &statusCode, &latencyMS, &userAgent, &createdAt); err != nil {
		return nil, err
	}
	return gin.H{
		"id":         id,
		"userId":     userID,
		"username":   nullString(username),
		"ip":         nullString(ipAddress),
		"method":     nullString(method),
		"path":       nullString(path),
		"query":      nullString(query),
		"statusCode": statusCode,
		"latencyMs":  latencyMS,
		"userAgent":  nullString(userAgent),
		"created":    utils.FormatNullTimeStringForDisplay(createdAt),
	}, nil
}

func scanOperationLogRow(rows *sql.Rows) (gin.H, error) {
	var id, userID, statusCode int
	var latencyMS int64
	var username, ipAddress, method, path, action, target, userAgent, createdAt sql.NullString
	if err := rows.Scan(&id, &userID, &username, &ipAddress, &method, &path, &action, &target, &statusCode, &latencyMS, &userAgent, &createdAt); err != nil {
		return nil, err
	}
	return gin.H{
		"id":         id,
		"userId":     userID,
		"username":   nullString(username),
		"ip":         nullString(ipAddress),
		"method":     nullString(method),
		"path":       nullString(path),
		"action":     nullString(action),
		"target":     nullString(target),
		"statusCode": statusCode,
		"latencyMs":  latencyMS,
		"userAgent":  nullString(userAgent),
		"created":    utils.FormatNullTimeStringForDisplay(createdAt),
	}, nil
}

func scanUnauthorizedAccessLogRow(rows *sql.Rows) (gin.H, error) {
	var id, statusCode int
	var ipAddress, method, path, query, reason, userAgent, createdAt sql.NullString
	if err := rows.Scan(&id, &ipAddress, &method, &path, &query, &statusCode, &reason, &userAgent, &createdAt); err != nil {
		return nil, err
	}
	return gin.H{
		"id":         id,
		"ip":         nullString(ipAddress),
		"method":     nullString(method),
		"path":       nullString(path),
		"query":      nullString(query),
		"statusCode": statusCode,
		"reason":     nullString(reason),
		"userAgent":  nullString(userAgent),
		"created":    utils.FormatNullTimeStringForDisplay(createdAt),
	}, nil
}

func nullString(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func enrichAuditLogLocations(logs []gin.H) {
	ipSet := make(map[string]bool)
	for _, log := range logs {
		if ip, ok := log["ip"].(string); ok && ip != "" {
			ipSet[ip] = true
		}
	}
	ipLocationMap := make(map[string]string)
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		if isLocalNetworkIP(ip) {
			ipLocationMap[ip] = "局域网"
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) > 0 {
		if locations, err := service.QueryIPs(ips); err == nil {
			for ip, location := range locations {
				ipLocationMap[ip] = buildLocationString(location)
			}
		}
	}
	for i := range logs {
		ip, _ := logs[i]["ip"].(string)
		if ip == "" {
			logs[i]["location"] = "未知"
			continue
		}
		if location, ok := ipLocationMap[ip]; ok {
			logs[i]["location"] = location
		} else {
			logs[i]["location"] = "未知"
		}
	}
}

func clearAuditTable(c *gin.Context, tableName, message string) {
	result, err := database.DB.Exec("DELETE FROM " + tableName)
	if err != nil {
		InternalServerErrorResponse(c, message+"失败", err)
		return
	}
	deleted, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": message, "data": gin.H{"deleted": deleted}})
}
