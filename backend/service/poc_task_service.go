package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type PocTaskService struct{}

func NewPocTaskService() *PocTaskService {
	return &PocTaskService{}
}

// GetTaskList 获取POC任务列表
func (s *PocTaskService) GetTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	query := `SELECT task_id, task_name, targets, selected_pocs, status, progress, found_vulns, CAST(created_at AS TEXT), CAST(completed_at AS TEXT), user_id 
              FROM poc_scan_tasks WHERE 1=1`

	var args []interface{}
	if createdByFilter != nil {
		query += " AND user_id = ?"
		args = append(args, *createdByFilter)
	}

	query += " ORDER BY created_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var task models.PocScanTask
		var createdAt, completedAt sql.NullString

		if err := rows.Scan(&task.TaskID, &task.TaskName, &task.Targets, &task.SelectedPocs, &task.Status, &task.Progress,
			&task.FoundVulns, &createdAt, &completedAt, &task.UserID); err != nil {
			continue
		}

		// 解析目标数量
		var targets []string
		// 尝试解析 JSON
		if err := json.Unmarshal([]byte(task.Targets), &targets); err != nil {
			// 解析失败，可能是旧数据格式（纯文本或逗号分隔）
			if task.Targets != "" {
				parts := strings.Split(task.Targets, ",")
				for _, p := range parts {
					if trimmed := strings.TrimSpace(p); trimmed != "" {
						targets = append(targets, trimmed)
					}
				}
			}
		}
		targetCount := len(targets)

		// 解析POC
		var selectedPocs []string
		if err := json.Unmarshal([]byte(task.SelectedPocs), &selectedPocs); err != nil {
			if task.SelectedPocs != "" {
				parts := strings.Split(task.SelectedPocs, ",")
				for _, p := range parts {
					if trimmed := strings.TrimSpace(p); trimmed != "" {
						selectedPocs = append(selectedPocs, trimmed)
					}
				}
			}
		}

		taskMap := map[string]interface{}{
			"task_id":      task.TaskID,
			"task_name":    task.TaskName,
			"target_count": targetCount,
			"pocs":         selectedPocs, // 返回pocs字段供前端列表使用
			"status":       task.Status,
			"progress":     task.Progress,
			"found_vulns":  task.FoundVulns,
			"created_at":   utils.FormatNullTimeStringForDisplay(createdAt),
			"user_id":      task.UserID,
		}

		if formattedCompletedAt := utils.FormatNullTimeStringForDisplay(completedAt); formattedCompletedAt != "" {
			taskMap["completed_at"] = formattedCompletedAt
		}

		tasks = append(tasks, taskMap)
	}

	return tasks, nil
}

// GetTaskDetail 获取任务详情
func (s *PocTaskService) GetTaskDetail(taskID string) (map[string]interface{}, error) {
	var task models.PocScanTask
	var createdAt, updatedAt, completedAt sql.NullString
	var threadCount, rateLimit, userID sql.NullInt64
	var httpProxy sql.NullString

	query := `SELECT task_id, task_name, targets, selected_pocs, status, progress, found_vulns, 
              CAST(created_at AS TEXT), CAST(updated_at AS TEXT), CAST(completed_at AS TEXT), thread_count, http_proxy, rate_limit, user_id 
              FROM poc_scan_tasks WHERE task_id = ?`

	err := database.DB.QueryRow(query, taskID).Scan(
		&task.TaskID, &task.TaskName, &task.Targets, &task.SelectedPocs, &task.Status,
		&task.Progress, &task.FoundVulns, &createdAt, &updatedAt, &completedAt,
		&threadCount, &httpProxy, &rateLimit, &userID,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("任务不存在")
		}
		return nil, err
	}

	if threadCount.Valid {
		task.ThreadCount = int(threadCount.Int64)
	}
	if rateLimit.Valid {
		task.RateLimit = int(rateLimit.Int64)
	}
	if userID.Valid {
		task.UserID = int(userID.Int64)
	}
	if httpProxy.Valid {
		task.HTTPProxy = httpProxy.String
	}

	// 解析 JSON 字段
	var targets []string
	var selectedPocs []string

	// 尝试解析 Targets
	if err := json.Unmarshal([]byte(task.Targets), &targets); err != nil {
		if task.Targets != "" {
			parts := strings.Split(task.Targets, ",")
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					targets = append(targets, trimmed)
				}
			}
		}
	}

	// 尝试解析 SelectedPocs
	if err := json.Unmarshal([]byte(task.SelectedPocs), &selectedPocs); err != nil {
		if task.SelectedPocs != "" {
			parts := strings.Split(task.SelectedPocs, ",")
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					selectedPocs = append(selectedPocs, trimmed)
				}
			}
		}
	}

	return map[string]interface{}{
		"task_id":       task.TaskID,
		"task_name":     task.TaskName,
		"targets":       targets,
		"selected_pocs": selectedPocs,
		"pocs":          selectedPocs, // 前端组件期望字段名为 pocs
		"status":        task.Status,
		"progress":      task.Progress,
		"found_vulns":   task.FoundVulns,
		"created_at":    utils.FormatNullTimeStringForDisplay(createdAt),
		"updated_at":    utils.FormatNullTimeStringForDisplay(updatedAt),
		"completed_at":  utils.FormatNullTimeStringForDisplay(completedAt),
		"thread_count":  task.ThreadCount,
		"http_proxy":    task.HTTPProxy,
		"rate_limit":    task.RateLimit,
		"user_id":       task.UserID,
	}, nil
}

// CreateTask 创建任务
func (s *PocTaskService) CreateTask(taskName string, targets []string, selectedPocs []string, config map[string]interface{}, userID uint) (string, error) {
	taskID := uuid.New().String()

	targetsJSON, _ := json.Marshal(targets)
	selectedPocsJSON, _ := json.Marshal(selectedPocs)

	// 解析配置
	threadCount := 50
	if val, ok := config["thread_count"].(float64); ok {
		threadCount = int(val)
	}
	httpProxy := ""
	if val, ok := config["http_proxy"].(string); ok {
		httpProxy = val
	}
	rateLimit := 0
	if val, ok := config["rate_limit"].(float64); ok {
		rateLimit = int(val)
	}

	query := `INSERT INTO poc_scan_tasks (
		task_id, task_name, targets, selected_pocs, status, created_at, updated_at, 
		thread_count, http_proxy, rate_limit, user_id
	) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)`

	now := utils.GetCurrentTimeString()
	_, err := database.DB.Exec(query,
		taskID, taskName, string(targetsJSON), string(selectedPocsJSON), now, now,
		threadCount, httpProxy, rateLimit, userID,
	)

	if err != nil {
		return "", err
	}

	return taskID, nil
}

// DeleteTask 删除任务
func (s *PocTaskService) DeleteTask(taskID string) error {
	// 首先删除关联的结果
	_, _ = database.DB.Exec("DELETE FROM poc_scan_results WHERE task_id = ?", taskID)

	// 删除任务
	result, err := database.DB.Exec("DELETE FROM poc_scan_tasks WHERE task_id = ?", taskID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("任务不存在")
	}

	return nil
}

// UpdateStatus 更新状态
func (s *PocTaskService) UpdateStatus(taskID string, status string) error {
	query := "UPDATE poc_scan_tasks SET status = ?, updated_at = ? WHERE task_id = ?"
	_, err := database.DB.Exec(query, status, utils.GetCurrentTimeString(), taskID)
	return err
}

// UpdateProgress 更新进度
func (s *PocTaskService) UpdateProgress(taskID string, progress float64) error {
	query := "UPDATE poc_scan_tasks SET progress = ?, updated_at = ? WHERE task_id = ?"
	_, err := database.DB.Exec(query, progress, utils.GetCurrentTimeString(), taskID)
	return err
}

// IncrementVulnCount 增加漏洞计数
func (s *PocTaskService) IncrementVulnCount(taskID string) error {
	query := "UPDATE poc_scan_tasks SET found_vulns = found_vulns + 1 WHERE task_id = ?"
	_, err := database.DB.Exec(query, taskID)
	return err
}

// GetTaskProgress 获取任务进度
func (s *PocTaskService) GetTaskProgress(taskID string) (map[string]interface{}, error) {
	var status string
	var progress float64
	var foundVulns int

	err := database.DB.QueryRow("SELECT status, progress, found_vulns FROM poc_scan_tasks WHERE task_id = ?", taskID).Scan(&status, &progress, &foundVulns)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"status":      status,
		"progress":    progress,
		"found_vulns": foundVulns,
	}, nil
}

// SaveScanResult 保存扫描结果
func (s *PocTaskService) SaveScanResult(taskID string, result map[string]interface{}) error {
	query := `INSERT INTO poc_scan_results (
		task_id, target, template_id, template_path, matcher_name, severity, 
		name, author, tags, description, request, response, matched_at, extracted_results, metadata, discovered_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var metadata, extracted string
	getString := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := result[key]; ok {
				if text := pocScanResultText(value); text != "" {
					return text
				}
			}
		}
		if info, ok := result["info"].(map[string]interface{}); ok {
			for _, key := range keys {
				if value, ok := info[key]; ok {
					if text := pocScanResultText(value); text != "" {
						return text
					}
				}
			}
		}
		return ""
	}

	if val, ok := result["info"]; ok {
		if bytes, err := json.Marshal(val); err == nil {
			metadata = string(bytes)
		}
	}

	if val, ok := result["extracted_results"]; ok {
		if bytes, err := json.Marshal(val); err == nil {
			extracted = string(bytes)
		}
	}

	_, err := database.DB.Exec(query,
		taskID,
		result["target"],
		result["template_id"],
		result["template_path"],
		result["matcher_name"],
		result["severity"],
		result["name"],
		getString("author"),
		getString("tags"),
		result["description"],
		result["request"],
		result["response"],
		result["matched_at"],
		extracted,
		metadata,
		utils.GetCurrentTimeString(),
	)
	return err
}

func pocScanResultText(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := pocScanResultText(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case []string:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := strings.TrimSpace(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}
