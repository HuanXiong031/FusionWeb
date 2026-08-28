package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrInvalidAssignedWorker = errors.New("invalid assigned worker")

func normalizeTaskConfig(config *models.TaskConfig) error {
	if config == nil {
		return nil
	}
	config.AssignedWorker = strings.TrimSpace(config.AssignedWorker)
	if strings.EqualFold(config.AssignedWorker, "auto") {
		config.AssignedWorker = ""
	}
	if config.PortsThreshold <= 0 || config.PortsThreshold > 65535 {
		config.PortsThreshold = 65535
	}
	if err := validateAssignedWorker(config.AssignedWorker); err != nil {
		return err
	}
	return nil
}

func validateAssignedWorker(workerName string) error {
	workerName = strings.TrimSpace(workerName)
	if workerName == "" {
		return nil
	}
	client := database.GetRedis()
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	values, err := client.HGetAll(ctx, database.RedisKey("worker", workerName)).Result()
	if err != nil {
		return fmt.Errorf("校验执行节点失败: %w", err)
	}
	if len(values) == 0 {
		return fmt.Errorf("%w: 指定节点不存在: %s", ErrInvalidAssignedWorker, workerName)
	}
	lastHeartbeat := strings.TrimSpace(values["last_heartbeat"])
	if lastHeartbeat == "" {
		return fmt.Errorf("%w: 指定节点尚未完成注册: %s", ErrInvalidAssignedWorker, workerName)
	}
	ts, err := time.Parse(time.RFC3339Nano, lastHeartbeat)
	if err != nil || time.Since(ts) > 120*time.Second || strings.EqualFold(strings.TrimSpace(values["status"]), "offline") {
		return fmt.Errorf("%w: 指定节点当前离线: %s", ErrInvalidAssignedWorker, workerName)
	}
	return nil
}

func (a *App) StartScanTask(config models.TaskConfig) (string, error) {
	if err := normalizeTaskConfig(&config); err != nil {
		return "", err
	}
	return a.scheduler.SubmitTask(&config)
}

// StopTaskWithUser 停止指定任务。userID 保留用于接口兼容。
func (a *App) StopTaskWithUser(taskID string, userID uint) error {
	return a.scheduler.StopTask(taskID)
}

func (a *App) StartScanTaskWithUser(config models.TaskConfig, userID uint) (string, error) {
	if err := normalizeTaskConfig(&config); err != nil {
		return "", err
	}
	return a.scheduler.SubmitTaskWithUser(&config, userID)
}

// DeleteTask 删除任务及其关联的所有扫描结果数据
func (a *App) DeleteTask(taskID string, userID uint) error {
	return a.scheduler.DeleteTask(taskID)
}

// RestartTask 重启任务。
// 返回新任务 ID（从检查点恢复时会创建新任务记录）
func (a *App) RestartTask(taskID string, userID uint) (string, error) {
	return a.scheduler.RestartTask(taskID)
}

// GenerateExcelReport 生成 Excel 报告
func (a *App) GenerateExcelReport(taskID string, userID uint) (string, error) {
	// 生成临时文件路径
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("report_%s_%d.xlsx", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GenerateExcelReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

// GenerateHTMLReport 生成 HTML 报告
func (a *App) GenerateHTMLReport(taskID string, userID uint) (string, error) {
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("report_%s_%d.html", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GenerateHTMLReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

// GenerateMDReport 生成 Markdown 报告
func (a *App) GenerateMDReport(taskID string, userID uint) (string, error) {
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("report_%s_%d.md", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GenerateMDReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

// GetTaskList 获取任务列表
func (a *App) GetTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	// 调用 Scheduler 获取任务列表
	return a.scheduler.GetTaskList(userID, createdByFilter)
}

// GetTaskDetail 获取任务详情
func (a *App) GetTaskDetail(taskID string, userID uint) (map[string]interface{}, error) {
	return a.scheduler.GetTaskDetail(taskID)
}

// PauseTask 暂停任务
func (a *App) PauseTask(taskID string, userID uint) error {
	return a.scheduler.PauseTask(taskID)
}

// ResumeTask 恢复任务
func (a *App) ResumeTask(taskID string, userID uint) error {
	return a.scheduler.ResumeTask(taskID)
}

// GetTaskProgressWithUser 获取任务进度 (Interface Implementation)
func (a *App) GetTaskProgressWithUser(taskID string, userID uint) (*models.ProgressInfo, error) {
	return a.scheduler.GetProgress(taskID)
}

// GetTaskLogs 获取任务日志
func (a *App) GetTaskLogs(taskID string, level string, keyword string, page int, pageSize int, userID uint) (map[string]interface{}, error) {
	if runtimeLogs, total, usedRuntime, err := service.NewTaskRuntimeService().QueryTaskLogs(taskID, level, keyword, page, pageSize); err == nil && usedRuntime {
		items := make([]map[string]interface{}, 0, len(runtimeLogs))
		for _, item := range runtimeLogs {
			log := item.Log
			createdAt := utils.FormatTimeForDisplay(log.CreatedAt)
			items = append(items, map[string]interface{}{
				"id":         item.StreamID,
				"task_id":    log.TaskID,
				"taskID":     log.TaskID,
				"level":      log.Level,
				"stage":      log.Stage,
				"message":    log.Message,
				"metadata":   log.Metadata,
				"created_at": createdAt,
				"createdAt":  createdAt,
			})
		}
		return map[string]interface{}{
			"items": items,
			"total": total,
		}, nil
	}

	logService := service.NewLogService(taskID, database.DB)
	logs, total, err := logService.QueryLogs(level, keyword, page, pageSize)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(logs))
	for _, log := range logs {
		createdAt := utils.FormatTimeForDisplay(log.CreatedAt)
		items = append(items, map[string]interface{}{
			"id":         log.ID,
			"task_id":    log.TaskID,
			"taskID":     log.TaskID,
			"level":      log.Level,
			"stage":      log.Stage,
			"message":    log.Message,
			"metadata":   log.Metadata,
			"created_at": createdAt,
			"createdAt":  createdAt,
		})
	}
	return map[string]interface{}{
		"items": items,
		"total": total,
	}, nil
}

// GetReconResults 获取信息收集结果
func (a *App) GetReconResults(taskID string, resultType string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetReconResults(taskID, resultType)
}

// GetVulnResults 获取漏洞结果 (Interface Implementation)
func (a *App) GetVulnResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetVulnResults(taskID)
}

// GetFingerprintResults 获取指纹结果
func (a *App) GetFingerprintResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetFingerprintResults(taskID)
}

func (a *App) GetSubdomainResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetSubdomainResults(taskID)
}

func (a *App) GetWeakPasswordResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetWeakPasswordResults(taskID)
}

func (a *App) GetDirectoryResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetDirectoryResults(taskID)
}

func (a *App) GetJSScanResults(taskID string, userID uint) ([]map[string]interface{}, error) {
	return a.scheduler.GetJSScanResults(taskID)
}

// GetDashboardStats 获取仪表盘统计
func (a *App) GetDashboardStats(userID uint) (map[string]interface{}, error) {
	return a.dashboardService.GetStats(userID)
}

// DebugScanPOC 对单个 POC 模板执行调试扫描。
// 这是 POC 模板编辑器的核心功能：用户在编辑器中编写模板后，
// 可立即对指定目标进行调试扫描，实时查看请求/响应和匹配结果。
//
// 参数：
//   - templateContent: POC YAML 模板内容
//   - targets: 目标 URL 列表（需包含协议头）
//   - proxy: HTTP 代理地址（可选）
//   - debug: 是否开启 Nuclei debug 模式
//
// 功能特点：
//   - 通过 WebSocket 实时推送扫描进度和漏洞发现事件
//   - 支持从现有 POC 目录复用已存在的模板文件
//   - 记录完整的请求/响应数据包用于分析
//   - 返回格式化的匹配结果列表
