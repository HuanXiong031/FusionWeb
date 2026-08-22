package api

import (
	"FusionWeb/backend/engine/common/callnuclei"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func (a *App) GetPocTaskList(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	return a.pocTaskService.GetTaskList(userID, createdByFilter)
}

func (a *App) GetPocTaskDetail(taskID string) (map[string]interface{}, error) {
	return a.pocTaskService.GetTaskDetail(taskID)
}

func (a *App) CreatePocTask(taskName string, targets []string, selectedPocs []string, config map[string]interface{}) (string, error) {
	return a.pocTaskService.CreateTask(taskName, targets, selectedPocs, config, 0) // Default userID 0
}

func (a *App) CreatePocTaskWithUser(taskName string, targets []string, selectedPocs []string, config map[string]interface{}, userID uint) (string, error) {
	return a.pocTaskService.CreateTask(taskName, targets, selectedPocs, config, userID)
}

func (a *App) DeletePocTask(taskID string, userID uint) error {
	return a.pocTaskService.DeleteTask(taskID)
}

func (a *App) GetPocTaskProgress(taskID string) (map[string]interface{}, error) {
	return a.pocTaskService.GetTaskProgress(taskID)
}

// ExecutePocTask 异步执行 POC 扫描任务。
// 在后台 goroutine 中执行完整扫描流程：
// 获取任务详情 → 解析目标/POC 路径 → 构建 Nuclei 参数 →
// 执行扫描 → 保存结果 → 更新进度与状态。
// 通过 WebSocket 实时推送进度和漏洞发现事件。
func (a *App) ExecutePocTask(taskID string) error {
	// 在后台 goroutine 中异步执行扫描逻辑，不阻塞 HTTP 响应
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("ExecutePocTask goroutine panic: %v", r)
				a.pocTaskService.UpdateStatus(taskID, "failed")
			}
		}()
		logger.Info("开始执行POC任务: %s", taskID)
		callnuclei.StoppedTasks.Delete(taskID)
		a.pocTaskService.UpdateStatus(taskID, "running")

		// 1. 获取任务详情
		task, err := a.pocTaskService.GetTaskDetail(taskID)
		if err != nil {
			logger.Error("获取任务详情失败: %v", err)
			a.pocTaskService.UpdateStatus(taskID, "failed")
			return
		}

		targets, ok := task["targets"].([]string)
		if !ok || len(targets) == 0 {
			logger.Error("任务无有效目标")
			a.pocTaskService.UpdateStatus(taskID, "completed")
			return
		}

		selectedPocs, ok := task["selected_pocs"].([]string)
		if !ok || len(selectedPocs) == 0 {
			logger.Error("任务未选择POC")
			a.pocTaskService.UpdateStatus(taskID, "completed")
			return
		}

		// 2. 解析 POC 路径
		dataDir := resolvePOCDataDir()
		pocRoot := filepath.Join(dataDir, "pocs")
		var pocPaths []string

		// 简单处理：尝试在 POC 根目录查找，或者假设是相对路径
		// 实际生产中可能需要更复杂的查找逻辑（如 PocFileService 的查找）
		for _, poc := range selectedPocs {
			// 1. 尝试直接作为绝对路径或相对于 CWD
			if _, err := os.Stat(poc); err == nil {
				pocPaths = append(pocPaths, poc)
				continue
			}
			// 2. 尝试相对于 POC 根目录
			path := filepath.Join(pocRoot, poc)
			if _, err := os.Stat(path); err == nil {
				pocPaths = append(pocPaths, path)
				continue
			}
			// 3. 尝试加 .yaml 后缀
			pathYaml := path + ".yaml"
			if _, err := os.Stat(pathYaml); err == nil {
				pocPaths = append(pocPaths, pathYaml)
				continue
			}

			// 4. 递归搜索 (性能较低，仅当找不到时尝试)
			// 为了性能，这里暂时略过递归搜索，假设前端传递的是正确的相对路径或文件名
			logger.Warn("POC文件未找到: %s", poc)
		}

		if len(pocPaths) == 0 {
			logger.Error("未找到有效的POC文件")
			a.pocTaskService.UpdateStatus(taskID, "completed")
			return
		}

		logger.Info("任务 [%s] 目标数: %d, POC数: %d", taskID, len(targets), len(pocPaths))

		// 3. 构建 Nuclei 参数
		targetAndPocsName := make(map[string][]string)
		for _, t := range targets {
			targetAndPocsName[t] = pocPaths
		}

		proxy := ""
		if val, ok := task["http_proxy"].(string); ok {
			proxy = val
		}

		// 进度跟踪
		totalTargets := len(targets)
		completedTargets := 0
		var progressLock sync.Mutex

		// 建立 Host 映射，用于 OnRequest 中快速匹配目标
		targetHostMap := make(map[string]string)
		for _, t := range targets {
			if u, err := url.Parse(t); err == nil {
				targetHostMap[u.Host] = t
				if hostname := u.Hostname(); hostname != u.Host {
					targetHostMap[hostname] = t
				}
			}
		}

		// 跟踪已扫描的目标
		scannedTargets := make(map[string]bool)
		var scannedTargetsLock sync.Mutex

		// 4. 执行扫描
		logService := service.NewLogService(taskID, nil)
		logWriter := logService.StartInterceptor()
		defer logService.Stop()
		params := callnuclei.NucleiParams{
			TargetAndPocsName: targetAndPocsName,
			Proxy:             proxy,
			LogWriter:         logWriter,
			EnableDebug:       false, // 任务扫描保持默认关闭，避免日志过大。如需调试 POC 任务，请使用“新建模板”中的调试功能
			NP:                pocRoot,
			TaskID:            taskID,
			CallBack: func(result output.ResultEvent) {
				// 保存扫描结果
				resMap := map[string]interface{}{
					"target":            result.Matched,
					"template_id":       result.TemplateID,
					"template_path":     result.TemplatePath,
					"matcher_name":      result.MatcherName,
					"severity":          result.Info.SeverityHolder.Severity.String(),
					"name":              result.Info.Name,
					"description":       result.Info.Description,
					"request":           result.Request,
					"response":          result.Response,
					"matched_at":        result.Matched,
					"extracted_results": result.ExtractedResults,
					"info": map[string]interface{}{
						"name":        result.Info.Name,
						"description": result.Info.Description,
						"severity":    result.Info.SeverityHolder.Severity.String(),
					},
				}

				if err := a.pocTaskService.SaveScanResult(taskID, resMap); err != nil {
					logger.Error("保存扫描结果失败: %v", err)
				}

				// 增加漏洞计数
				a.pocTaskService.IncrementVulnCount(taskID)

				// 推送漏洞发现事件
				if a.wsHub != nil {
					a.wsHub.Broadcast("task-vuln-found", map[string]interface{}{
						"task_id": taskID,
						"vuln":    resMap,
					})
				}
			},
			OnRequest: func(templateID, requestUrl, requestType string, err error) {
				// 尝试匹配当前请求属于哪个目标
				var matchedTarget string

				// 1. 尝试直接前缀匹配
				for _, t := range targets {
					if strings.HasPrefix(requestUrl, t) {
						matchedTarget = t
						break
					}
				}

				// 2. 如果没匹配到，尝试 Host 匹配
				if matchedTarget == "" {
					if u, err := url.Parse(requestUrl); err == nil {
						if t, ok := targetHostMap[u.Host]; ok {
							matchedTarget = t
						} else if t, ok := targetHostMap[u.Hostname()]; ok {
							matchedTarget = t
						}
					}
				}

				if matchedTarget != "" {
					scannedTargetsLock.Lock()
					if !scannedTargets[matchedTarget] {
						scannedTargets[matchedTarget] = true
						// 增加已完成（已开始）计数
						progressLock.Lock()
						completedTargets++
						progressLock.Unlock()
					}
					scannedTargetsLock.Unlock()
				}
			},
		}

		// 使用 timer 定期更新进度到数据库和前端
		progressDone := make(chan bool)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("ExecutePocTask progress ticker panic: %v", r)
				}
			}()
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					progressLock.Lock()
					// 计算真实进度
					var newP float64
					if totalTargets > 0 {
						newP = float64(completedTargets) / float64(totalTargets) * 100.0
						if newP > 95 {
							newP = 95 // 扫描未结束前保留一点余量
						}
					}

					// 获取当前数据库中的进度，避免回退（虽然理论上不会）
					// current, _ := a.pocTaskService.GetTaskProgress(taskID)
					// if p, ok := current["progress"].(float64); ok && p > newP {
					// 	newP = p
					// }

					a.pocTaskService.UpdateProgress(taskID, newP)

					// 推送进度
					if a.wsHub != nil {
						a.wsHub.Broadcast("task-progress", map[string]interface{}{
							"task_id":  taskID,
							"progress": newP,
							"status":   "running",
						})
					}
					progressLock.Unlock()
				case <-progressDone:
					return
				}
			}
		}()

		// 阻塞执行
		callnuclei.CallNucleiInternal(params)

		progressDone <- true

		status, statusErr := a.getPocTaskStatus(taskID)
		if statusErr != nil {
			logger.Error("获取POC任务状态失败: %v", statusErr)
			return
		}
		if status == "paused" || status == "stopped" || status == "cancelled" {
			logger.Info("POC任务已%s，跳过完成状态覆盖: %s", status, taskID)
			if a.wsHub != nil {
				a.wsHub.Broadcast("task-status", map[string]interface{}{
					"task_id": taskID,
					"status":  status,
				})
			}
			return
		}

		// 5. 完成
		a.pocTaskService.UpdateProgress(taskID, 100.0)
		a.pocTaskService.UpdateStatus(taskID, "completed")
		logger.Info("POC任务执行完成: %s", taskID)

		if a.wsHub != nil {
			a.wsHub.Broadcast("task-status", map[string]interface{}{
				"task_id":  taskID,
				"status":   "completed",
				"progress": 100.0,
			})
		}
	}()
	return nil
}

func (a *App) getPocTaskStatus(taskID string) (string, error) {
	task, err := a.pocTaskService.GetTaskDetail(taskID)
	if err != nil {
		return "", err
	}
	status, ok := task["status"].(string)
	if !ok {
		return "", fmt.Errorf("任务状态异常")
	}
	return strings.ToLower(strings.TrimSpace(status)), nil
}

func (a *App) PausePocTask(taskID string, userID uint) error {
	if err := a.pocTaskService.UpdateStatus(taskID, "paused"); err != nil {
		return err
	}
	callnuclei.StopTask(taskID)
	if a.wsHub != nil {
		a.wsHub.Broadcast("task-status", map[string]interface{}{
			"task_id": taskID,
			"status":  "paused",
		})
	}
	return nil
}

func (a *App) ResumePocTask(taskID string, userID uint) error {
	status, err := a.getPocTaskStatus(taskID)
	if err != nil {
		return err
	}
	if status != "paused" {
		return a.pocTaskService.UpdateStatus(taskID, "running")
	}
	return a.ExecutePocTask(taskID)
}

func (a *App) StopPocTask(taskID string, userID uint) error {
	if err := a.pocTaskService.UpdateStatus(taskID, "stopped"); err != nil {
		return err
	}
	callnuclei.StopTask(taskID)
	if a.wsHub != nil {
		a.wsHub.Broadcast("task-status", map[string]interface{}{
			"task_id": taskID,
			"status":  "stopped",
		})
	}
	return nil
}

// POC Scan Results
func (a *App) GetPocScanResults(taskID string, severity string, page int, pageSize int, userID *int) (map[string]interface{}, error) {
	return a.pocScanResultService.GetResults(taskID, severity, page, pageSize, userID)
}
func (a *App) GetPocScanResultDetail(resultID int, userID *int, taskID string) (map[string]interface{}, error) {
	return a.pocScanResultService.GetResultDetail(resultID)
}
func (a *App) AddPocScanResult(result map[string]interface{}) (int64, error) {
	return a.pocScanResultService.AddResult(result)
}
func (a *App) DeletePocScanResult(resultID int) error {
	return a.pocScanResultService.DeleteResult(resultID)
}
func (a *App) DeletePocScanResultsByTask(taskID string) error {
	return a.pocScanResultService.DeleteResultsByTask(taskID)
}
func (a *App) GetPocScanResultStatistics(taskID string, userID *int) (map[string]interface{}, error) {
	return a.pocScanResultService.GetStatistics(taskID)
}

// POC Reports
func (a *App) GeneratePocHTMLReport(taskID string) (string, error) {
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("poc_report_%s_%d.html", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GeneratePocHTMLReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}
func (a *App) GeneratePocExcelReport(taskID string) (string, error) {
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("poc_report_%s_%d.xlsx", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GeneratePocExcelReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

// GeneratePocMDReport
func (a *App) GeneratePocMDReport(taskID string) (string, error) {
	outputPath := filepath.Join(os.TempDir(), fmt.Sprintf("poc_report_%s_%d.md", taskID, time.Now().Unix()))
	reportService := service.NewReportService(taskID)
	err := reportService.GeneratePocMDReport(outputPath)
	if err != nil {
		return "", err
	}
	return outputPath, nil
}

// Manual Vuln Verify
