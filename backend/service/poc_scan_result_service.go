// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现POC扫描结果的CRUD操作和统计分析。
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
)

// PocScanResultService POC扫描结果管理服务，提供结果的分页查询、详情获取、
// 添加、删除和严重等级统计功能。
type PocScanResultService struct{}

// NewPocScanResultService 创建POC扫描结果服务实例。
func NewPocScanResultService() *PocScanResultService {
	return &PocScanResultService{}
}

// GetResults 分页查询指定任务的POC扫描结果，支持按严重程度筛选。
// 返回包含total和list的统一分页格式。
//
// 参数:
//   - taskID: 任务ID
//   - severity: 严重程度过滤（空字符串表示不过滤）
//   - page: 页码（从1开始）
//   - pageSize: 每页条数
//   - userID: 用户ID（保留用于记录来源）
//   - role: 用户角色（保留用于接口兼容）
//
// 返回值:
//   - map[string]interface{}: 包含"total"（总数）和"list"（结果列表）
//   - error: 查询失败时返回错误
func (s *PocScanResultService) GetResults(taskID string, severity string, page, pageSize int, userID *int) (map[string]interface{}, error) {
	offset := (page - 1) * pageSize

	query := "SELECT id, task_id, target, template_id, severity, name, COALESCE(author, ''), COALESCE(tags, ''), CAST(discovered_at AS TEXT) FROM poc_scan_results WHERE task_id = ?"
	countQuery := "SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ?"

	var args []interface{}
	args = append(args, taskID)

	if severity != "" {
		if isKnownPocSeverity(severity) {
			query += " AND LOWER(TRIM(severity)) = LOWER(?)"
			countQuery += " AND LOWER(TRIM(severity)) = LOWER(?)"
			args = append(args, severity)
		} else {
			query += " AND (severity IS NULL OR TRIM(severity) = '' OR LOWER(TRIM(severity)) NOT IN ('critical', 'high', 'medium', 'low', 'info'))"
			countQuery += " AND (severity IS NULL OR TRIM(severity) = '' OR LOWER(TRIM(severity)) NOT IN ('critical', 'high', 'medium', 'low', 'info'))"
		}
	}

	// 分页
	query += " ORDER BY discovered_at DESC LIMIT ? OFFSET ?"
	argsWithLimit := append(args, pageSize, offset)

	var total int
	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, err
	}

	rows, err := database.DB.Query(query, argsWithLimit...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var r models.PocScanResult
		var discoveredAt string
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.TemplateID, &r.Severity, &r.Name, &r.Author, &r.Tags, &discoveredAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"id":            r.ID,
			"task_id":       r.TaskID,
			"target":        r.Target,
			"template_id":   r.TemplateID,
			"severity":      r.Severity,
			"name":          r.Name,
			"author":        r.Author,
			"tags":          r.Tags,
			"discovered_at": utils.FormatTimeStringForDisplay(discoveredAt),
		})
	}

	return map[string]interface{}{
		"total": total,
		"list":  results,
	}, nil
}

// GetResultDetail 获取单条POC扫描结果的完整详情，包含请求/响应等完整信息。
//
// 参数:
//   - resultID: 结果记录ID
//
// 返回值:
//   - map[string]interface{}: 结果详情
//   - error: 结果不存在或查询失败时返回错误
func (s *PocScanResultService) GetResultDetail(resultID int) (map[string]interface{}, error) {
	var r models.PocScanResult
	var discoveredAt string

	query := `SELECT id, task_id, target, template_id, template_path, matcher_name, severity, 
              name, COALESCE(author, ''), COALESCE(tags, ''), description, request, response, matched_at, extracted_results, metadata, CAST(discovered_at AS TEXT) 
              FROM poc_scan_results WHERE id = ?`

	err := database.DB.QueryRow(query, resultID).Scan(
		&r.ID, &r.TaskID, &r.Target, &r.TemplateID, &r.TemplatePath, &r.MatcherName, &r.Severity,
		&r.Name, &r.Author, &r.Tags, &r.Description, &r.Request, &r.Response, &r.MatchedAt, &r.ExtractedResults, &r.Metadata, &discoveredAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("结果不存在")
		}
		return nil, err
	}

	meta := NewReportService(r.TaskID).getPocMetadata(r.TemplatePath, r.TemplateID)
	if r.Author == "" {
		r.Author = meta.Author
	}
	if r.Tags == "" {
		r.Tags = meta.Tags
	}
	if r.Tags == "" {
		r.Tags = r.MatcherName
	}

	return map[string]interface{}{
		"id":                r.ID,
		"task_id":           r.TaskID,
		"target":            r.Target,
		"template_id":       r.TemplateID,
		"template_path":     r.TemplatePath,
		"matcher_name":      r.MatcherName,
		"severity":          r.Severity,
		"name":              r.Name,
		"author":            r.Author,
		"tags":              r.Tags,
		"description":       r.Description,
		"request":           r.Request,
		"response":          r.Response,
		"matched_at":        r.MatchedAt,
		"extracted_results": r.ExtractedResults,
		"metadata":          r.Metadata,
		"discovered_at":     utils.FormatTimeStringForDisplay(discoveredAt),
	}, nil
}

// AddResult 添加扫描结果
func (s *PocScanResultService) AddResult(result map[string]interface{}) (int64, error) {
	query := `INSERT INTO poc_scan_results (
		task_id, target, template_id, template_path, matcher_name, severity, 
		name, author, tags, description, request, response, matched_at, extracted_results, metadata, discovered_at, user_id
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	// 处理可选字段
	getString := func(key string) string {
		if v, ok := result[key]; ok {
			if text := pocScanResultText(v); text != "" {
				return text
			}
		}
		if info, ok := result["info"].(map[string]interface{}); ok {
			if v, ok := info[key]; ok {
				return pocScanResultText(v)
			}
		}
		return ""
	}
	getUserID := func() int {
		for _, key := range []string{"user_id", "userID", "userId"} {
			switch v := result[key].(type) {
			case int:
				return v
			case int64:
				return int(v)
			case uint:
				return int(v)
			case uint64:
				return int(v)
			case float64:
				return int(v)
			case float32:
				return int(v)
			}
		}
		return 0
	}

	id, err := database.InsertAndReturnID(query,
		getString("task_id"),
		getString("target"),
		getString("template_id"),
		getString("template_path"),
		getString("matcher_name"),
		getString("severity"),
		getString("name"),
		getString("author"),
		getString("tags"),
		getString("description"),
		getString("request"),
		getString("response"),
		getString("matched_at"),
		getString("extracted_results"),
		getString("metadata"),
		utils.GetCurrentTimeString(),
		getUserID(),
	)

	if err != nil {
		return 0, err
	}

	return id, nil
}

// DeleteResult 删除结果
func (s *PocScanResultService) DeleteResult(resultID int) error {
	_, err := database.DB.Exec("DELETE FROM poc_scan_results WHERE id = ?", resultID)
	return err
}

// DeleteResultsByTask 删除任务的所有结果
func (s *PocScanResultService) DeleteResultsByTask(taskID string) error {
	_, err := database.DB.Exec("DELETE FROM poc_scan_results WHERE task_id = ?", taskID)
	return err
}

// GetStatistics 获取统计信息
func (s *PocScanResultService) GetStatistics(taskID string) (map[string]interface{}, error) {
	// 按危害等级统计
	rows, err := database.DB.Query("SELECT severity, COUNT(*) FROM poc_scan_results WHERE task_id = ? GROUP BY severity", taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	severityStats := make(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			continue
		}
		severityStats[severity] = count
	}

	return map[string]interface{}{
		"severity_stats": severityStats,
	}, nil
}
