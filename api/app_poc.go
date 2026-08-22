package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/common/callnuclei"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"encoding/base64"
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func (a *App) DebugScanPOC(templateContent string, targets []string, proxy string, debug bool, logPackets bool, taskID string) ([]map[string]interface{}, error) {
	// 生成唯一的扫描任务ID
	scanTaskID := strings.TrimSpace(taskID)
	if scanTaskID == "" {
		scanTaskID = fmt.Sprintf("debug-scan-%d", time.Now().UnixNano())
	}

	// 1. 保存临时POC文件
	dataDir := resolvePOCDataDir()
	tempPocId := fmt.Sprintf("debug-%d", time.Now().Unix())
	tempCategory := "pocs_temp"

	// 确保目录存在（pocs_temp 放在 data 目录下，不在 POC 文件夹下）
	pocDir := filepath.Join(dataDir, tempCategory)
	if err := os.MkdirAll(pocDir, 0755); err != nil {
		return nil, fmt.Errorf("创建临时POC目录失败: %w", err)
	}

	// 提取模板ID（如果存在）
	var pocId string
	lines := strings.Split(templateContent, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "id:") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) == 2 {
				pocId = strings.TrimSpace(parts[1])
				break
			}
		}
	}
	if pocId == "" {
		pocId = tempPocId
	}

	// 检查POC是否已经存在于POC文件夹中
	pocRoot := filepath.Join(dataDir, "pocs")
	var pocPath string
	var useExistingPoc bool

	// 在POC根目录及其子目录中查找POC文件
	if pocId != "" {
		// 检查POC根目录是否存在
		if _, err := os.Stat(pocRoot); err == nil {
			found := false
			err := filepath.WalkDir(pocRoot, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil // 忽略错误，继续搜索
				}
				if d.IsDir() {
					return nil
				}
				// 检查文件名是否匹配（支持 .yaml 和 .yml）
				baseName := filepath.Base(path)
				if strings.EqualFold(baseName, pocId+".yaml") || strings.EqualFold(baseName, pocId+".yml") {
					// 检查文件内容是否相同
					existingContent, err := os.ReadFile(path)
					if err == nil && string(existingContent) == templateContent {
						pocPath = path
						found = true
						return filepath.SkipAll // 找到后停止搜索
					}
				}
				return nil
			})
			if err == nil && found {
				useExistingPoc = true
			}
		}
	}

	// 如果POC不存在于POC文件夹中，保存到 pocs_temp
	if !useExistingPoc {
		pocPath = filepath.Join(pocDir, pocId+".yaml")
		if err := os.WriteFile(pocPath, []byte(templateContent), 0644); err != nil {
			return nil, fmt.Errorf("保存临时POC文件失败: %w", err)
		}
		logger.Info("POC文件不存在于POC文件夹，已保存到临时目录: %s", pocPath)
	} else {
		logger.Info("POC文件已存在于POC文件夹，直接使用: %s", pocPath)
	}

	// 记录POC文件信息
	logger.Info("========== 调试模板扫描开始 [%s] ==========", scanTaskID)
	logger.Info("POC文件路径: %s", pocPath)
	logger.Info("POC ID: %s", pocId)
	logger.Info("使用现有POC: %v", useExistingPoc)
	logger.Info("POC文件大小: %d 字节", len(templateContent))

	// 2. 构建Nuclei参数
	targetAndPocsName := make(map[string][]string)
	validTargets := make([]string, 0)
	// 建立 Host 映射，用于 OnRequest 中快速匹配目标
	targetHostMap := make(map[string]string)

	for _, target := range targets {
		// 确保目标格式正确
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			continue
		}
		// 过滤掉仅有协议头的无效目标
		if target == "http://" || target == "https://" {
			continue
		}
		targetAndPocsName[target] = []string{pocId}
		validTargets = append(validTargets, target)

		// 解析 URL 并存入映射
		if u, err := url.Parse(target); err == nil {
			targetHostMap[u.Host] = target
			// 同时存储不带端口的 Hostname（如果不同）
			if hostname := u.Hostname(); hostname != u.Host {
				targetHostMap[hostname] = target
			}
		}
	}

	if len(targetAndPocsName) == 0 {
		return nil, fmt.Errorf("没有有效的目标URL")
	}

	// 记录扫描目标信息
	logger.Info("扫描目标数: %d", len(validTargets))
	logger.Info("代理设置: %s", func() string {
		if proxy != "" {
			return proxy
		}
		return "无"
	}())

	// pocRoot 已在上面定义，这里不再重复定义
	var results []output.ResultEvent
	var resultsLock sync.Mutex

	// 扫描进度跟踪
	var progressLock sync.Mutex
	currentProgress := map[string]interface{}{
		"task_id":           scanTaskID,
		"total_targets":     len(validTargets),
		"completed_targets": 0,
		"found_vulns":       0,
		"current_target":    "",
		"current_template":  pocId,
		"status":            "running",
		"percentage":        0.0,
	}

	// 跟踪已扫描的目标
	scannedTargets := make(map[string]bool)
	var scannedTargetsLock sync.Mutex
	// 跟踪每个请求的开始时间（用于耗时计算）
	requestStartTimes := sync.Map{}
	// 记录每个匹配结果的耗时（毫秒），键为 matched_at URL
	resultDurations := sync.Map{}

	// 发送初始进度事件
	if a.wsHub != nil {
		a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
			"task_id": scanTaskID,
			"type":    "started",
			"data":    currentProgress,
		})
	}

	// 启动进度更新goroutine
	progressDone := make(chan bool)
	// 定义发送进度函数
	sendProgress := func() {
		progressLock.Lock()
		// 计算进度百分比（基于已发现漏洞数估算，因为无法获取总请求数）
		completed := currentProgress["completed_targets"].(int)
		total := currentProgress["total_targets"].(int)
		if total > 0 {
			percentage := float64(completed) / float64(total) * 100.0
			if percentage < 95.0 { // 扫描完成前最多显示95%
				currentProgress["percentage"] = percentage
			}
		}
		progress := make(map[string]interface{})
		for k, v := range currentProgress {
			progress[k] = v
		}
		progressLock.Unlock()

		// 发送进度更新事件
		if a.wsHub != nil {
			a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
				"task_id": scanTaskID,
				"type":    "progress",
				"data":    progress,
			})
		}
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("DebugScanPOC progress ticker panic: %v", r)
			}
		}()
		ticker := time.NewTicker(100 * time.Millisecond) // 每100ms更新一次进度
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sendProgress()
			case <-progressDone:
				return
			}
		}
	}()

	// 3. 执行扫描
	logService := service.NewLogService(scanTaskID, database.DB)
	logWriter := logService.StartInterceptor()
	defer logService.Stop()
	params := callnuclei.NucleiParams{
		TargetAndPocsName: targetAndPocsName,
		Proxy:             proxy,
		LogWriter:         logWriter,
		EnableDebug:       debug,
		LogPackets:        logPackets,
		CallBack: func(result output.ResultEvent) {
			resultsLock.Lock()
			results = append(results, result)
			vulnCount := len(results)
			resultsLock.Unlock()

			// 确定归属的输入目标（Input Target）
			inputTarget := result.Matched
			var bestMatchLen int
			for _, t := range validTargets {
				if strings.HasPrefix(result.Matched, t) {
					if len(t) > bestMatchLen {
						inputTarget = t
						bestMatchLen = len(t)
					}
				}
			}

			// 更新已扫描的目标
			// 只有当匹配到的结果属于某个有效目标时，才更新已扫描列表
			// 避免将具体漏洞URL（如 http://example.com/vuln.php）作为新的目标添加到列表中，导致计数超出总数
			var completedCount int
			scannedTargetsLock.Lock()
			if bestMatchLen > 0 {
				// 只有找到归属目标才更新
				scannedTargets[inputTarget] = true
			}
			completedCount = len(scannedTargets)
			scannedTargetsLock.Unlock()

			severity := result.Info.SeverityHolder.Severity.String()
			if logPackets {
				logger.Info("========== 调试模板扫描数据包 [%s] ==========", scanTaskID)
				logger.Info("目标: %s", result.Matched)
				logger.Info("模板ID: %s", result.TemplateID)
				logger.Info("模板名称: %s", result.Info.Name)
				logger.Info("严重等级: %s", severity)
				logger.Info("--- 请求数据包 ---")
				if result.Request != "" {
					logger.Info("\n%s", result.Request)
				} else {
					logger.Info("(请求数据为空)")
				}
				logger.Info("--- 响应数据包 ---")
				if result.Response != "" {
					logger.Info("\n%s", result.Response)
				} else {
					logger.Info("(响应数据为空)")
				}
				logger.Info("===========================================")
			}

			// 更新进度并发送事件
			progressLock.Lock()
			currentProgress["found_vulns"] = vulnCount
			currentProgress["current_target"] = result.Matched
			currentProgress["completed_targets"] = completedCount
			progressLock.Unlock()

			// 发送漏洞发现事件
			if a.wsHub != nil {
				// 计算耗时（毫秒）
				durationMs := 0
				if startVal, ok := requestStartTimes.Load(result.Matched); ok {
					if startTime, ok2 := startVal.(time.Time); ok2 {
						if startTime.Before(time.Now()) {
							durationMs = int(time.Since(startTime).Milliseconds())
						}
					}
				} else {
					// 尝试使用前缀匹配查找开始时间（处理路径差异）
					requestStartTimes.Range(func(k, v any) bool {
						if urlStr, ok := k.(string); ok && strings.HasPrefix(result.Matched, urlStr) {
							if startTime, ok2 := v.(time.Time); ok2 {
								if startTime.Before(time.Now()) {
									durationMs = int(time.Since(startTime).Milliseconds())
									return true
								}
							}
						}
						return false
					})
				}
				// 记录耗时以便最终结果合并时使用
				resultDurations.Store(result.Matched, durationMs)
				a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
					"task_id": scanTaskID,
					"type":    "vuln_found",
					"data": map[string]interface{}{
						"template":   result.TemplateID,
						"target":     inputTarget,    // 使用计算出的归属目标
						"matched_at": result.Matched, // 保留实际匹配位置
						"severity":   result.Info.SeverityHolder.Severity.String(),
						"name":       result.Info.Name,
						"total":      len(results), // 注意：这里的 results 是空的，因为是在回调中
						"request":    result.Request,
						"response":   result.Response,
						"duration":   durationMs,
						"info": map[string]interface{}{ // 传递完整 info 对象
							"name":        result.Info.Name,
							"description": result.Info.Description,
							"severity":    result.Info.SeverityHolder.Severity.String(),
						},
					},
				})
			}
		},
		OnRequest: func(templateID, requestUrl, requestType string, err error) {
			// 尝试匹配当前请求属于哪个目标
			var matchedTarget string

			// 1. 尝试直接前缀匹配
			for _, t := range validTargets {
				if strings.HasPrefix(requestUrl, t) {
					matchedTarget = t
					break
				}
			}

			// 2. 如果没匹配到，尝试 Host 匹配（处理自动加端口或路径变化的情况）
			if matchedTarget == "" {
				if u, err := url.Parse(requestUrl); err == nil {
					// 尝试直接匹配 Host
					if t, ok := targetHostMap[u.Host]; ok {
						matchedTarget = t
					} else if t, ok := targetHostMap[u.Hostname()]; ok {
						// 尝试匹配 Hostname (去端口)
						matchedTarget = t
					}
				}
			}

			// 如果找到了匹配的目标，更新扫描进度
			if matchedTarget != "" {
				scannedTargetsLock.Lock()
				// 如果该目标尚未标记为已扫描，则进行标记并更新计数
				if !scannedTargets[matchedTarget] {
					scannedTargets[matchedTarget] = true
					completedCount := len(scannedTargets)
					scannedTargetsLock.Unlock()

					// 更新进度信息
					progressLock.Lock()
					currentProgress["completed_targets"] = completedCount
					currentProgress["current_target"] = matchedTarget
					progressLock.Unlock()

					// 立即发送一次进度更新
					sendProgress()
				} else {
					scannedTargetsLock.Unlock()
				}
			} else {
				// 即使没匹配到具体目标，也尝试更新 current_target，让用户看到正在扫什么
				// 但不更新 completed_targets，以免计数不准
				progressLock.Lock()
				currentProgress["current_target"] = requestUrl
				progressLock.Unlock()

				// 立即发送一次进度更新（虽然进度没变，但当前目标变了）
				sendProgress()
			}
			// 记录请求开始时间用于后续耗时计算
			requestStartTimes.Store(requestUrl, time.Now())
		},
		TemplateDirs: func() []string {
			// 如果使用现有POC，需要找到POC所在的目录
			if useExistingPoc {
				// 提取POC文件所在的目录
				existingPocDir := filepath.Dir(pocPath)
				return []string{existingPocDir}
			}
			// 否则使用 pocs_temp 目录
			return []string{pocDir}
		}(), // 传递完整路径，pocs_temp 在 config 文件夹下，或使用现有POC的目录
		ExcludeTags:  []string{},
		Severities:   []string{"critical", "high", "medium", "low", "info"},
		NoInteractsh: true, // 调试模式默认禁用interactsh（与任务扫描保持一致），避免未配置服务器导致扫描失败
		NP:           pocRoot,
		TaskID:       scanTaskID,
	}

	// 执行扫描（带panic恢复）
	func() {
		defer func() {
			if r := recover(); r != nil {
				// 检查是否是任务停止触发的 panic
				errStr := fmt.Sprintf("%v", r)
				if strings.Contains(errStr, "任务已停止") {
					logger.Info("扫描任务已停止: %s", scanTaskID)
					// 发送停止事件
					if a.wsHub != nil {
						a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
							"task_id": scanTaskID,
							"type":    "stopped",
							"data":    map[string]interface{}{},
						})
					}
				} else {
					logger.Error("DebugScanPOC 扫描发生 panic: %v", r)
					if a.wsHub != nil {
						a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
							"task_id": scanTaskID,
							"type":    "error",
							"data": map[string]interface{}{
								"error": fmt.Sprintf("扫描发生错误: %v", r),
							},
						})
					}
				}
				progressDone <- true
			}
		}()
		scanResults := callnuclei.CallNucleiInternal(params)
		resultsLock.Lock()
		defer resultsLock.Unlock()
		results = scanResults
		progressDone <- true
	}()

	// 4. 转换结果格式并记录扫描摘要到日志
	matchedTargetCount := countMatchedDebugTargets(results, validTargets)
	logger.Info("========== 调试模板扫描完成 [%s] ==========", scanTaskID)
	logger.Info("扫描目标数: %d", len(validTargets))
	logger.Info("扫描模板: %s", pocId)
	logger.Info("匹配结果数: %d", len(results))
	if len(results) > 0 {
		logger.Info("调试扫描匹配成功: 模板=%s, 严重等级=%s, 已命中目标数=%d, 匹配结果数=%d",
			pocId,
			results[0].Info.SeverityHolder.Severity.String(),
			matchedTargetCount,
			len(results),
		)
	}
	if len(results) == 0 {
		logger.Info("未发现匹配结果")
		logger.Info("扫描目标数: %d", len(validTargets))
		logger.Warn("未命中时不会在命令行打印 POC 模板或 HTTP 数据包，请在前端详情中查看可用信息。")
		logger.Warn("建议：检查 POC 模板是否正确，或目标是否真的存在漏洞。")
	}
	logger.Info("===========================================")

	formattedResults := make([]map[string]interface{}, 0, len(results))

	for _, result := range results {
		// 确定归属的输入目标（Input Target）
		inputTarget := result.Matched
		var bestMatchLen int
		for _, t := range validTargets {
			if strings.HasPrefix(result.Matched, t) {
				if len(t) > bestMatchLen {
					inputTarget = t
					bestMatchLen = len(t)
				}
			}
		}

		formattedResults = append(formattedResults, map[string]interface{}{
			"target":     inputTarget,
			"matched_at": result.Matched,
			"request":    result.Request,
			"response":   result.Response,
			"status":     "matched",
			"template":   result.TemplateID,
			"severity":   result.Info.SeverityHolder.Severity.String(),
			"duration": func() int {
				if v, ok := resultDurations.Load(result.Matched); ok {
					if d, ok2 := v.(int); ok2 {
						return d
					}
				}
				return 0
			}(),
			"info": map[string]interface{}{
				"name":        result.Info.Name,
				"description": result.Info.Description,
				"severity":    result.Info.SeverityHolder.Severity.String(),
			},
		})
	}

	// 发送完成事件
	if a.wsHub != nil {
		progressLock.Lock()
		currentProgress["status"] = "completed"
		currentProgress["completed_targets"] = len(validTargets)
		currentProgress["percentage"] = 100.0
		finalProgress := make(map[string]interface{})
		for k, v := range currentProgress {
			finalProgress[k] = v
		}
		progressLock.Unlock()

		a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
			"task_id": scanTaskID,
			"type":    "completed",
			"data":    finalProgress,
		})
	}

	return formattedResults, nil
}

func countMatchedDebugTargets(results []output.ResultEvent, validTargets []string) int {
	if len(results) == 0 {
		return 0
	}
	matchedTargets := make(map[string]struct{})
	for _, result := range results {
		inputTarget := result.Matched
		var bestMatchLen int
		for _, target := range validTargets {
			if strings.HasPrefix(result.Matched, target) && len(target) > bestMatchLen {
				inputTarget = target
				bestMatchLen = len(target)
			}
		}
		if inputTarget != "" {
			matchedTargets[inputTarget] = struct{}{}
		}
	}
	return len(matchedTargets)
}

func resolvePOCDataDir() string {
	dataDir := utils.GetDataDir()
	if dirHasPOCRoot(dataDir) {
		return dataDir
	}

	return dataDir
}

func dirHasPOCRoot(dataDir string) bool {
	if strings.TrimSpace(dataDir) == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(dataDir, "pocs"))
	return err == nil && info.IsDir()
}

// StopDebugScan 停止调试扫描任务
func (a *App) StopDebugScan(taskID string) error {
	callnuclei.StopTask(taskID)
	if a.wsHub != nil {
		a.wsHub.Broadcast("debug-scan-progress", map[string]interface{}{
			"task_id": taskID,
			"type":    "stopped",
			"data":    map[string]interface{}{},
		})
	}
	return nil
}

func (a *App) GetTaskProgress(taskID string) (models.ProgressInfo, error) {
	progress, err := a.scheduler.GetProgress(taskID)
	if err != nil {
		return models.ProgressInfo{}, err
	}
	if progress == nil {
		return models.ProgressInfo{}, nil
	}
	return *progress, nil
}

func (a *App) GetScanResults(taskID string) ([]models.VulnResult, error) {
	// Delegate to report service or scheduler helper
	// Assuming scheduler has access or using service directly
	return service.GetScanResults(taskID)
}

func (a *App) GetSystemInfo() (map[string]interface{}, error) {
	// 获取主机名
	hostname, _ := os.Hostname()
	// 获取当前工作目录
	wd, _ := os.Getwd()
	// 获取可执行文件路径
	exe, _ := os.Executable()

	// 尝试获取更多系统信息（依赖 runtime 包，虽然这里没有显式导入 runtime，但标准库通常包含）
	// 注意：为了更详细的信息（如内存、CPU），通常需要使用 gopsutil 库，
	// 这里仅使用标准库 os/runtime 能提供的信息，避免引入新依赖

	return map[string]interface{}{
		"os":          "windows", // 保持硬编码或使用 runtime.GOOS
		"arch":        "amd64",   // 保持硬编码或使用 runtime.GOARCH
		"hostname":    hostname,
		"work_dir":    wd,
		"exec_path":   exe,
		"num_cpu":     0, // 暂不引入 runtime.NumCPU()
		"server_time": utils.GetCurrentTimeString(),
	}, nil
}

func (a *App) GetScanConfig() (models.TaskConfig, error) {
	// 从数据库读取默认配置，配置名为 "default"
	return a.toolsService.LoadScanConfig("default")
}

func (a *App) SaveScanConfig(config models.TaskConfig) error {
	// 保存默认配置到数据库，配置名为 "default"
	return a.toolsService.SaveScanConfig("default", config)
}

func (a *App) GetVulnerabilities(page, pageSize int, taskID, severity, keyword string) ([]models.VulnResult, int, error) {
	return service.GetVulnerabilities(page, pageSize, taskID, severity, keyword)
}

func (a *App) VerifyVulnerability(vulnID int) (bool, string, error) {
	return service.VerifyVulnerability(vulnID)
}

func (a *App) GetTaskLog(taskID string) (string, error) {
	return service.GetTaskLog(taskID)
}

// ==================== ExtendedAppInterface 接口实现：POC 管理与指纹识别 ====================
// 以下方法实现 POC 模板文件管理、指纹规则管理、POC 任务调度、
// 漏洞验证、工具调用等扩展业务功能

// --- POC File Service ---

func (a *App) GetPocFilesPage(page, pageSize int, category, keyword, severity string, userID *int) (map[string]interface{}, error) {
	// 如果前端传来的 severity 是 "全部等级" 等占位符，视为空字符串（表示查询所有）
	if severity == "全部等级" {
		severity = ""
	}
	// 注意：如果 severity 是 "unknown"，我们不应该将其清空，而是应该传递给下层去匹配等级为 "unknown" 的条目

	items, total, err := a.pocFileService.GetPocFilesPageWithSeverity(page, pageSize, category, keyword, severity, userID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"items": items,
		"total": total,
	}, nil
}

func (a *App) GetAllPocFiles(userID *int) ([]service.PocFileInfo, error) {
	return a.pocFileService.GetAllPocFiles(userID)
}

func (a *App) GetPocFileContent(relativePath string) (string, error) {
	return a.pocFileService.GetPocFileContent(relativePath)
}

func (a *App) SavePocFile(relativePath, content string) error {
	return a.pocFileService.SavePocFile(relativePath, content)
}

func (a *App) DeletePocFile(relativePath string) error {
	return a.pocFileService.DeletePocFile(relativePath)
}

func (a *App) RenamePocFile(oldName, newName string) error {
	return a.pocFileService.RenamePocFile(oldName, newName)
}

func (a *App) CreatePocFile(category string, fileName string, content string, userID *int) error {
	return a.pocFileService.CreatePocFile(category, fileName, content, userID, true)
}

func (a *App) UpdatePocFile(relativePath string, content string, category string, fileName ...string) error {
	return a.pocFileService.UpdatePocFile(relativePath, content, category, fileName...)
}

// --- Fingerprint DB Service ---
func (a *App) DeleteAllPOCs(userID *int, createdByFilter *int) (int, error) {
	return a.pocFileService.DeleteAllPOCs(userID, createdByFilter)
}
func (a *App) ExportAllPOCs(userID *int) (string, error) {
	return service.ExportAllPOCs(userID)
}
func (a *App) ExportSelectedPOCs(relativePaths []string, userID *int) (string, error) {
	return service.ExportSelectedPOCs(relativePaths, userID)
}
func (a *App) ValidatePOC(content string) (map[string]interface{}, error) {
	valid, errors := a.pocFileService.ValidatePOC(content)
	return map[string]interface{}{
		"valid":  valid,
		"errors": errors,
	}, nil
}

// POC File Management (Additional)
func (a *App) GetPocCategories(userID *int) ([]string, error) {
	return a.pocFileService.GetPocCategories(userID)
}
func (a *App) SearchPocFiles(keyword string, userID *int) ([]service.PocFileInfo, error) {
	return a.pocFileService.SearchPocFiles(keyword, userID)
}
func (a *App) GetPocFileStatistics(userID *int) (map[string]interface{}, error) {
	return a.pocFileService.GetPocStatistics(userID)
}
func (a *App) LogImportFailures(failedFiles []map[string]interface{}, category string) error {
	logger.Warn("Import failures for category %s: %v", category, failedFiles)
	return nil
}
func (a *App) LogImportSuccess(totalFiles int, categoryCount int, categories map[string]int) error {
	logger.Info("Import success: %d files, %d categories. Details: %v", totalFiles, categoryCount, categories)
	return nil
}
func (a *App) ImportPocFile(category string, fileName string, base64Content string, userID *int) error {
	// Decode base64 content
	content, err := base64.StdEncoding.DecodeString(base64Content)
	if err != nil {
		return fmt.Errorf("invalid base64 content: %w", err)
	}
	return a.pocFileService.ImportPocFile(category, fileName, content, userID)
}

// POC Task Management
