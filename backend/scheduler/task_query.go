// Package scheduler 提供异步扫描任务的调度与执行管理。
// 本文件实现任务列表查询和详情查询功能，支持实时进度获取。
package scheduler

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
)

// GetTaskList 获取任务列表。
// 返回的列表中包含端口数、URL数、指纹数和漏洞数的统计信息，
// 对于运行中的任务还会获取实时进度百分比。
//
// 参数:
//   - userID: 当前登录用户ID（保留用于接口兼容）
//   - createdByFilter: 可选，按创建者ID过滤任务
//
// 返回值:
//   - []map[string]interface{}: 任务列表，包含统计数据和进度信息
//   - error: 查询失败时返回错误
func (s *TaskScheduler) GetTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	s.repairStaleTaskStatuses()
	// 构建查询
	query := `SELECT task_id, task_name, task_type, target_input, status, 
              CAST(created_at AS TEXT), CAST(updated_at AS TEXT), CAST(completed_at AS TEXT), current_stage, user_id
              FROM task_config WHERE 1=1`

	var args []interface{}

	if createdByFilter != nil {
		query += " AND user_id = ?"
		args = append(args, *createdByFilter)
	}

	query += " ORDER BY created_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询任务列表失败: %w", err)
	}
	defer rows.Close()

	var tasks []map[string]interface{}
	for rows.Next() {
		var taskID, taskName, taskType, targetInput, status string
		var createdAt, updatedAt, completedAt, currentStage sql.NullString
		var uid int

		if err := rows.Scan(&taskID, &taskName, &taskType, &targetInput, &status,
			&createdAt, &updatedAt, &completedAt, &currentStage, &uid); err != nil {
			logger.Warn("扫描任务行失败: %v", err)
			continue
		}

		var portCount, urlCount, fingerprintCount, vulnCount int

		// 聚合统计各阶段结果数量，为前端概览卡片提供数据
		// 分别统计端口数、URL数、指纹数和漏洞数
		database.DB.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'port'", taskID).Scan(&portCount)
		urlCount = s.getDisplayURLCount(taskID)
		database.DB.QueryRow("SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ?", taskID).Scan(&fingerprintCount)
		database.DB.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ?", taskID).Scan(&vulnCount)
		moduleResultCount := s.getModuleResultCount(taskID, taskType)

		task := map[string]interface{}{
			"taskID":           taskID,
			"taskName":         taskName,
			"taskType":         taskType,
			"targetInput":      targetInput,
			"status":           status,
			"createTime":       utils.FormatNullTimeStringForDisplay(createdAt),
			"updateTime":       utils.FormatNullTimeStringForDisplay(updatedAt),
			"portCount":        portCount,
			"urlCount":         urlCount,
			"fingerprintCount": fingerprintCount,
			"vulnCount":        vulnCount,
			"moduleResultCount": moduleResultCount,
			"userID":           uid,
		}

		if completedAt.Valid {
			if formattedCompletedAt := utils.FormatNullTimeStringForDisplay(completedAt); formattedCompletedAt != "" {
				task["completedTime"] = formattedCompletedAt
			}
		}
		if currentStage.Valid {
			task["currentStage"] = currentStage.String
		}

		if runtimeStatus, progress, ok := s.runtimeTaskStatus(taskID); ok {
			status = runtimeStatus
			task["status"] = runtimeStatus
			if progress != nil {
				task["percentage"] = progress.Percentage
				task["stage"] = progress.Stage
			}
		}

		// 根据任务状态获取进度信息
		// 运行中：从调度器实时获取进度百分比和当前阶段
		// 已完成：固定为100%
		// 其他状态（pending/failed等）：进度为0
		if status == "running" {
			progress, err := s.GetProgress(taskID)
			if err == nil && progress != nil {
				task["percentage"] = progress.Percentage
				task["stage"] = progress.Stage
			}
		} else if status == "completed" {
			task["percentage"] = 100
			task["stage"] = "已完成"
		} else {
			task["percentage"] = 0
		}

		tasks = append(tasks, task)
	}

	return tasks, nil
}

// GetTaskDetail 获取单个任务的完整详情信息。
// 包含任务配置参数（端口范围、扫描模式、线程数、代理等）、
// 各阶段结果统计（端口数、URL数、指纹数、漏洞数）以及实时进度。
//
// 参数:
//   - taskID: 任务唯一标识
//
// 返回值:
//   - map[string]interface{}: 任务详情，包含配置信息和统计数据
//   - error: 任务不存在或查询失败时返回错误
func (s *TaskScheduler) GetTaskDetail(taskID string) (map[string]interface{}, error) {
	s.repairStaleTaskStatuses()
	// 第一步：查询任务基本信息与扫描配置参数
	var taskName, taskType, targetInput, status string
	var createdAt, updatedAt, completedAt, currentStage sql.NullString
	var userID int
	var portRange, scanMode, scanTool, scanOptions, noPortString, httpProxy, selectedDicts string
	var threadCount, portScanTimeout, webTimeout int
	var enableScreenshot int

	query := `SELECT task_name, task_type, target_input, status, CAST(created_at AS TEXT), CAST(updated_at AS TEXT), CAST(completed_at AS TEXT), current_stage, user_id,
              port_range, scan_mode, scan_tool, scan_options, no_port_string, thread_count, port_scan_timeout, web_timeout, http_proxy, enable_screenshot, selected_dicts
              FROM task_config WHERE task_id = ?`

	err := database.DB.QueryRow(query, taskID).Scan(
		&taskName, &taskType, &targetInput, &status, &createdAt, &updatedAt, &completedAt, &currentStage, &userID,
		&portRange, &scanMode, &scanTool, &scanOptions, &noPortString, &threadCount, &portScanTimeout, &webTimeout, &httpProxy, &enableScreenshot, &selectedDicts,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("任务不存在")
		}
		return nil, fmt.Errorf("查询任务详情失败: %w", err)
	}

	// 第二步：聚合各阶段结果统计
	var portCount, urlCount, fingerprintCount, vulnCount int
	database.DB.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'port'", taskID).Scan(&portCount)
	urlCount = s.getDisplayURLCount(taskID)
	database.DB.QueryRow("SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ?", taskID).Scan(&fingerprintCount)
	database.DB.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ?", taskID).Scan(&vulnCount)
	moduleResultCount := s.getModuleResultCount(taskID, taskType)

	result := map[string]interface{}{
		"taskID":           taskID,
		"taskName":         taskName,
		"taskType":         taskType,
		"targetInput":      targetInput,
		"status":           status,
		"createTime":       utils.FormatNullTimeStringForDisplay(createdAt),
		"updateTime":       utils.FormatNullTimeStringForDisplay(updatedAt),
		"userID":           userID,
		"portRange":        portRange,
		"scanMode":         scanMode,
		"scanTool":         scanTool,
		"scanOptions":      scanOptions,
		"noPortString":     noPortString,
		"threadCount":      threadCount,
		"portScanTimeout":  portScanTimeout,
		"webTimeout":       webTimeout,
		"enableScreenshot": database.IntBool(enableScreenshot),
		"httpProxy":        httpProxy,
		"selectedDicts":    selectedDicts,
		"portCount":        portCount,
		"urlCount":         urlCount,
		"fingerprintCount": fingerprintCount,
		"vulnCount":        vulnCount,
		"moduleResultCount": moduleResultCount,
	}

	if completedAt.Valid {
		if formattedCompletedAt := utils.FormatNullTimeStringForDisplay(completedAt); formattedCompletedAt != "" {
			result["completedTime"] = formattedCompletedAt
		}
	}
	if currentStage.Valid {
		result["currentStage"] = currentStage.String
	}

	if runtimeStatus, progress, ok := s.runtimeTaskStatus(taskID); ok {
		status = runtimeStatus
		result["status"] = runtimeStatus
		if progress != nil {
			result["percentage"] = progress.Percentage
			result["stage"] = progress.Stage
		}
	}

	// 第三步：获取实时进度（运行中的任务从调度器获取，已完成任务固定100%）
	if status == "running" {
		progress, err := s.GetProgress(taskID)
		if err == nil && progress != nil {
			result["percentage"] = progress.Percentage
			result["stage"] = progress.Stage
		}
	} else if status == "completed" {
		result["percentage"] = 100
		result["stage"] = "已完成"
	} else {
		result["percentage"] = 0
	}

	return result, nil
}

func (s *TaskScheduler) getDisplayURLCount(taskID string) int {
	results, err := s.GetReconResults(taskID, "url")
	if err == nil {
		return len(results)
	}
	var count int
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'url'", taskID).Scan(&count)
	return count
}

func (s *TaskScheduler) getModuleResultCount(taskID, taskType string) int {
	table := ""
	switch taskType {
	case "subdomain":
		table = "subdomain_results"
	case "weak_password":
		table = "weak_password_results"
	case "directory":
		table = "directory_results"
	case "js":
		table = "js_scan_results"
	default:
		return 0
	}
	var count int
	_ = database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE task_id = ?", table), taskID).Scan(&count)
	return count
}

func (s *TaskScheduler) runtimeTaskStatus(taskID string) (string, *models.ProgressInfo, bool) {
	s.mu.RLock()
	taskCtx, ok := s.tasks[taskID]
	s.mu.RUnlock()
	if !ok || taskCtx == nil {
		if runtimeState, exists := service.NewTaskRuntimeService().GetTaskState(taskID); exists {
			status := runtimeState.Status
			if status == "" {
				status = "running"
			}
			return status, runtimeState.Progress, true
		}
		return "", nil, false
	}
	status := taskCtx.Status
	if status == "" {
		status = "running"
	}
	taskCtx.progressMu.RLock()
	progress := &models.ProgressInfo{
		TaskID:           taskCtx.Progress.TaskID,
		Stage:            taskCtx.Progress.Stage,
		Percentage:       taskCtx.Progress.Percentage,
		Message:          taskCtx.Progress.Message,
		PortCount:        taskCtx.Progress.PortCount,
		URLCount:         taskCtx.Progress.URLCount,
		FingerprintCount: taskCtx.Progress.FingerprintCount,
		VulnCount:        taskCtx.Progress.VulnCount,
	}
	taskCtx.progressMu.RUnlock()
	return status, progress, true
}

func (s *TaskScheduler) repairStaleTaskStatuses() {
	type statusRepair struct {
		taskID string
		status string
	}
	var repairs []statusRepair

	rows, err := database.DB.Query(`
		SELECT t.task_id, t.status,
			(SELECT COUNT(*) FROM recon_results r WHERE r.task_id = t.task_id) +
			(SELECT COUNT(*) FROM fingerprint_results f WHERE f.task_id = t.task_id) +
			(SELECT COUNT(*) FROM vuln_results v WHERE v.task_id = t.task_id) +
			(SELECT COUNT(*) FROM subdomain_results sd WHERE sd.task_id = t.task_id) +
			(SELECT COUNT(*) FROM weak_password_results wp WHERE wp.task_id = t.task_id) +
			(SELECT COUNT(*) FROM directory_results dr WHERE dr.task_id = t.task_id) +
			(SELECT COUNT(*) FROM js_scan_results js WHERE js.task_id = t.task_id) AS result_count
		FROM task_config t
		WHERE t.status IN ('pending', 'running')
	`)
	if err != nil {
		return
	}
	for rows.Next() {
		var taskID, status string
		var resultCount int
		if err := rows.Scan(&taskID, &status, &resultCount); err != nil {
			continue
		}
		if runtimeStatus, _, running := s.runtimeTaskStatus(taskID); running && runtimeStatus == "running" {
			if status == "pending" {
				repairs = append(repairs, statusRepair{taskID: taskID, status: "running"})
			}
			continue
		}
		if resultCount > 0 {
			repairs = append(repairs, statusRepair{taskID: taskID, status: "completed"})
		}
	}
	_ = rows.Close()

	for _, repair := range repairs {
		_ = s.updateTaskStatus(repair.taskID, repair.status)
	}
}
