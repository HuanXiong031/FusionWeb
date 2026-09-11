// Package scheduler 提供异步扫描任务的调度与执行管理。
// 实现基于Worker Pool（工作池）模式的任务调度器，支持以下核心能力：
//   - 任务提交与管理：提交、暂停、停止、删除、恢复任务
//   - 多阶段扫描流水线：Web扫描（Web探测->指纹识别->POC扫描）、端口扫描（端口服务扫描->Web联动->指纹识别->POC扫描）
//   - 并发控制与资源隔离：两级隔离模式（任务类型级+任务实例级）、内存与目标数量限制
//   - 实时进度反馈：通过WebSocket广播阶段性进度和日志
//   - 断点恢复：支持暂停后从断点继续执行
//   - 任务重启：基于已完成/失败任务配置创建新任务
//
// 设计模式：
//   - Worker Pool: 固定数量的Worker协程从任务队列中获取任务并执行
//   - 两阶段分发：第一轮非阻塞轮询，第二轮使用reflect.Select阻塞等待
//   - 读写锁保护：sync.RWMutex保护任务映射表的并发访问，progressMu保护进度信息
//   - 延迟清理：defer确保任务结束时释放资源（Context取消、清理任务映射、停止日志服务）
package scheduler

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/websocket"
	"fmt"
	"strings"
	"time"
)

func (w *Worker) runScanWorkflow(taskCtx *TaskContext) (err error) {
	// 添加全局 panic 捕获
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("扫描流程发生 panic: %v", r)
			w.logError(taskCtx.Config.TaskID, err.Error())
			websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", err.Error())
		}
	}()

	// 指纹库可能刚在 api 进程里被改动（新增/导入/启停指纹），而扫描跑在 worker 进程，
	// 两边缓存互不相通；这里先自查版本，变化了就清掉本进程缓存，避免"加了指纹扫不到"。
	if service.EnsureFingerprintCacheFresh() {
		w.logInfo(taskCtx.Config.TaskID, "检测到指纹库已更新，已重新加载指纹缓存")
		websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "指纹库已更新，本次扫描将使用最新指纹")
	}

	w.logInfo(taskCtx.Config.TaskID, "开始执行扫描任务")
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始执行扫描任务")

	// 调用真实的扫描引擎
	err = w.runRealScanWorkflow(taskCtx)
	if err != nil {
		return err
	}

	// 使用渐进式进度更新到100%
	w.updateProgressGradually(taskCtx.Config.TaskID, "completed", "扫描完成", 100.0, taskCtx)
	w.logInfo(taskCtx.Config.TaskID, "扫描任务完成")
	websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "扫描任务完成")

	return nil
}

// runSimulatedScanWorkflow 模拟扫描工作流（用于测试）
func (w *Worker) runSimulatedScanWorkflow(taskCtx *TaskContext) error {
	// 解析目标输入
	targets := parseTargets(taskCtx.Config.TargetInput)
	if len(targets) == 0 {
		return fmt.Errorf("没有有效的扫描目标")
	}

	w.logInfo(taskCtx.Config.TaskID, fmt.Sprintf("解析到 %d 个扫描目标", len(targets)))
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", fmt.Sprintf("解析到 %d 个扫描目标", len(targets)))

	// 模拟 3 个阶段
	for i := 0; i < 3; i++ {
		select {
		case <-taskCtx.Ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		stageName := ""
		switch i {
		case 0:
			stageName = "端口扫描"
			_ = w.updateTaskStage(taskCtx.Config.TaskID, "portscan")
		case 1:
			stageName = "服务识别"
			_ = w.updateTaskStage(taskCtx.Config.TaskID, "fingerprint")
		case 2:
			stageName = "Web 探测"
			_ = w.updateTaskStage(taskCtx.Config.TaskID, "web_probe")
		}

		// 使用渐进式进度更新，而不是一次性跳转
		targetPercentage := float64((i + 1) * 33)
		message := fmt.Sprintf("正在执行: %s (%d/3)", stageName, i+1)
		w.updateProgressGradually(taskCtx.Config.TaskID, stageName, message, targetPercentage, taskCtx)
		w.logInfo(taskCtx.Config.TaskID, message)
		websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", message)

		// 模拟耗时
		time.Sleep(2 * time.Second)
	}

	return nil
}

// runRealScanWorkflow 运行真实扫描工作流
func (w *Worker) runRealScanWorkflow(taskCtx *TaskContext) error {
	// 创建扫描服务实例
	scanService := service.NewScanService(taskCtx.Config.TaskID, taskCtx.Ctx)

	// 解析目标输入
	targets := parseTargets(taskCtx.Config.TargetInput)
	if len(targets) == 0 {
		return fmt.Errorf("没有有效的扫描目标")
	}

	w.logInfo(taskCtx.Config.TaskID, fmt.Sprintf("解析到 %d 个扫描目标", len(targets)))
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", fmt.Sprintf("解析到 %d 个扫描目标", len(targets)))

	// 根据任务类型执行不同的扫描逻辑
	taskType := strings.ToLower(strings.TrimSpace(taskCtx.Config.TaskType))
	logger.Debug("Worker %d: %v", w.id, taskType)

	switch taskType {
	case "web":
		return w.runWebScanWorkflow(taskCtx, scanService, targets)
	case "port":
		return w.runPortScanWorkflow(taskCtx, scanService, targets)
	case "subdomain":
		return w.runSubdomainScanWorkflow(taskCtx, scanService, targets)
	case "weak_password":
		return w.runWeakPasswordScanWorkflow(taskCtx, scanService, targets)
	case "directory":
		return w.runDirectoryScanWorkflow(taskCtx, scanService, targets)
	case "js":
		return w.runJSScanWorkflow(taskCtx, scanService, targets)
	default:
		// 默认执行 Web 扫描
		logger.Warn("未知的任务类型: %s，默认执行 Web 扫描", taskType)
		return w.runWebScanWorkflow(taskCtx, scanService, targets)
	}
}

// runWebScanWorkflow Web扫描工作流
func (w *Worker) runWebScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	mode := strings.ToLower(strings.TrimSpace(taskCtx.Config.ScanMode))
	logger.Debug("Worker %d ScanMode处理后: \"%s\" -> \"%s\"", w.id, taskCtx.Config.ScanMode, mode)
	logger.Debug("Worker %d Web扫描开始，TaskID: %s, TaskType=%s, ScanMode=%s", w.id, taskCtx.Config.TaskID, taskCtx.Config.TaskType, taskCtx.Config.ScanMode)

	// 对于 Web 扫描，直接对 URL 进行 Web 探测
	_ = w.updateTaskStage(taskCtx.Config.TaskID, "web_probe")

	// 设置进度更新回调，根据扫描结果实时更新进度
	scanService.SetProgressCallback(func(stage string, scanned, total int, basePercentage, stageWeight float64) {
		w.updateProgressByResult(taskCtx.Config.TaskID, stage, scanned, total, basePercentage, stageWeight, taskCtx)
	})

	w.logInfo(taskCtx.Config.TaskID, "开始 Web 探测")
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始 Web 探测")

	urls, err := scanService.RunWebProbe(targets, taskCtx.Config, false) // Web扫描不从数据库查询端口
	if err != nil {
		w.logError(taskCtx.Config.TaskID, fmt.Sprintf("Web 探测失败: %v", err))
		websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("Web 探测失败: %v", err))
		return err
	}

	websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", fmt.Sprintf("发现 %d 个 Web 服务", len(urls)))

	// 若仅存活检测，直接结束
	if mode == "alive" {
		logger.Debug("Worker %d start scan workflow", w.id)
		w.logInfo(taskCtx.Config.TaskID, "扫描模式为 'alive'，任务完成")
		return nil
	}

	// 主动指纹探测已在 Web 探测阶段完成（RunWebProbe 中自动执行）
	// 只保存状态码为 200 的路径到 URL 结果中
	logger.Debug("Worker %d: %v", w.id, mode)
	logger.Debug("Worker %d: %v", w.id, mode == "fingerprint")
	logger.Debug("Worker %d: %v", w.id, mode == "fingerprint_poc")

	// 在指纹识别之前保存 TaskURLMaps 副本，供后续 POC 扫描使用。
	// 因为指纹识别会删除 TaskURLMaps[taskID]，导致 POC 扫描无法获取活跃 URL
	var savedTaskURLMap map[string]structs.URLEntity
	structs.TaskURLMapsLock.Lock()
	if taskMap, exists := structs.TaskURLMaps[taskCtx.Config.TaskID]; exists {
		// 深拷贝 TaskURLMaps，避免被指纹识别删除
		savedTaskURLMap = make(map[string]structs.URLEntity)
		for k, v := range taskMap {
			savedTaskURLMap[k] = v
		}
		logger.Debug("Worker %d: %v", w.id, len(savedTaskURLMap))
	}
	structs.TaskURLMapsLock.Unlock()

	// 指纹识别
	if mode == "fingerprint" || mode == "fingerprint_poc" {
		logger.Debug("Worker %d start scan workflow", w.id)
		select {
		case <-taskCtx.Ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		fingerprintService := service.NewFingerprintService(taskCtx.Config.TaskID, taskCtx.Ctx)
		_ = w.updateTaskStage(taskCtx.Config.TaskID, "fingerprint_web")

		// 根据扫描结果更新进度，指纹识别阶段从30%开始，权重30%
		totalURLsForFingerprint := len(urls)
		if totalURLsForFingerprint > 0 {
			w.updateProgressByResult(taskCtx.Config.TaskID, "指纹识别", 0, totalURLsForFingerprint, 30.0, 30.0, taskCtx)
		} else {
			w.updateProgressGradually(taskCtx.Config.TaskID, "指纹识别", "正在执行: 指纹识别", 30.0, taskCtx)
		}

		// 设置进度回调，实时更新指纹识别进度
		if totalURLsForFingerprint > 0 {
			fingerprintService.SetProgressCallback(func(scanned, total int) {
				w.updateProgressByResult(taskCtx.Config.TaskID, "指纹识别", scanned, total, 30.0, 30.0, taskCtx)
			})
		}

		w.logInfo(taskCtx.Config.TaskID, "开始指纹识别")
		websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始指纹识别")
		// 添加 panic 恢复机制，避免指纹识别 panic 导致任务失败
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("Worker %d: %v", w.id, r)
					w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别发生 panic: %v", r))
					websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别发生 panic: %v", r))
					// 即使发生 panic，也继续执行，不中断任务流程
				}
			}()

			if err := fingerprintService.RunFingerprintIdentification(urls); err != nil {
				logger.Debug("Worker %d: %v", w.id, err)
				w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别失败: %v", err))
				websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别失败: %v", err))
				// 指纹识别失败不应该导致整个任务失败，只记录错误
			} else {
				logger.Debug("Worker %d start scan workflow", w.id)
				// 指纹识别完成时，更新进度到60%
				if totalURLsForFingerprint > 0 {
					w.updateProgressByResult(taskCtx.Config.TaskID, "指纹识别", totalURLsForFingerprint, totalURLsForFingerprint, 30.0, 30.0, taskCtx)
				} else {
					w.updateProgressGradually(taskCtx.Config.TaskID, "指纹识别", "指纹识别完成", 60.0, taskCtx)
				}
				w.logInfo(taskCtx.Config.TaskID, "指纹识别完成")
				websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "指纹识别完成")
			}
		}()
	} else {
		// 如果 ScanMode 为空或默认值，默认执行指纹识别
		if mode == "" || mode == "web" || mode == "default" {
			logger.Debug("Worker %d: %v", w.id, mode)
			select {
			case <-taskCtx.Ctx.Done():
				return fmt.Errorf("任务被取消")
			default:
			}

			fingerprintService := service.NewFingerprintService(taskCtx.Config.TaskID, taskCtx.Ctx)
			_ = w.updateTaskStage(taskCtx.Config.TaskID, "fingerprint_web")

			// 根据扫描结果更新进度，指纹识别阶段从30%开始，权重30%
			totalURLsForFingerprint := len(urls)
			if totalURLsForFingerprint > 0 {
				w.updateProgressByResult(taskCtx.Config.TaskID, "指纹识别", 0, totalURLsForFingerprint, 30.0, 30.0, taskCtx)
			} else {
				w.updateProgressGradually(taskCtx.Config.TaskID, "指纹识别", "正在执行: 指纹识别", 30.0, taskCtx)
			}

			w.logInfo(taskCtx.Config.TaskID, "开始指纹识别")
			websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始指纹识别")
			// 添加 panic 恢复机制，避免指纹识别 panic 导致任务失败
			func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Debug("Worker %d: %v", w.id, r)
						w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别发生 panic: %v", r))
						websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别发生 panic: %v", r))
						// 即使发生 panic，也继续执行，不中断任务流程
					}
				}()

				if err := fingerprintService.RunFingerprintIdentification(urls); err != nil {
					logger.Debug("Worker %d: %v", w.id, err)
					w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别失败: %v", err))
					websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别失败: %v", err))
					// 指纹识别失败不应该导致整个任务失败，只记录错误
				} else {
					logger.Debug("Worker %d start scan workflow", w.id)
					// 指纹识别完成时，更新进度到60%
					if totalURLsForFingerprint > 0 {
						w.updateProgressByResult(taskCtx.Config.TaskID, "指纹识别", totalURLsForFingerprint, totalURLsForFingerprint, 30.0, 30.0, taskCtx)
					} else {
						w.updateProgressGradually(taskCtx.Config.TaskID, "指纹识别", "指纹识别完成", 60.0, taskCtx)
					}
					w.logInfo(taskCtx.Config.TaskID, "指纹识别完成")
					websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "指纹识别完成")
				}
			}()
		} else {
			logger.Debug("Worker %d: %v", w.id, mode)
		}
	}

	logger.Debug("Worker %d: %v", w.id, mode)
	logger.Debug("Worker %d: %v", w.id, mode == "fingerprint_poc")
	logger.Debug("Worker %d: %v", w.id, mode == "poc")

	// POC 扫描
	if mode == "fingerprint_poc" || mode == "poc" {
		logger.Debug("Worker %d start scan workflow", w.id)
		select {
		case <-taskCtx.Ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		vulnService := service.NewVulnService(taskCtx.Config.TaskID, taskCtx.Ctx)
		var fpMap map[string][]string
		if mode == "fingerprint_poc" {
			fingerprintService := service.NewFingerprintService(taskCtx.Config.TaskID, taskCtx.Ctx)
			fpMap, _ = fingerprintService.GetFingerprintResults()
		} else {
			logger.Debug("Worker %d start scan workflow", w.id)
			fpMap = map[string][]string{}
		}

		// 任务隔离：优先使用任务实例状态的 URLMap
		scanTargets := urls
		taskInstanceState := structs.GetOrCreateTaskInstanceState(taskCtx.Config.TaskID, taskCtx.Config.TaskType)

		// 优先使用任务实例状态的 URLMap
		if len(taskInstanceState.URLMap) > 0 {
			alive := make([]string, 0, len(taskInstanceState.URLMap))
			for root := range taskInstanceState.URLMap {
				alive = append(alive, root)
			}
			scanTargets = alive
			logger.Debug("Worker %d: %v", w.id, len(scanTargets))
		} else if len(savedTaskURLMap) > 0 {
			// 兼容旧代码：使用保存的 TaskURLMaps 副本
			alive := make([]string, 0, len(savedTaskURLMap))
			for root := range savedTaskURLMap {
				alive = append(alive, root)
			}
			scanTargets = alive
			logger.Debug("Worker %d: %v", w.id, len(scanTargets))
		} else {
			// 如果保存的副本为空，尝试从全局 TaskURLMaps 获取（可能指纹识别没有执行）
			structs.TaskURLMapsLock.Lock()
			taskMap := structs.TaskURLMaps[taskCtx.Config.TaskID]
			structs.TaskURLMapsLock.Unlock()
			if len(taskMap) > 0 {
				alive := make([]string, 0, len(taskMap))
				for root := range taskMap {
					alive = append(alive, root)
				}
				scanTargets = alive
				logger.Debug("Worker %d: %v", w.id, len(scanTargets))
			} else {
				logger.Debug("Worker %d: %v", w.id, len(scanTargets))
			}
		}

		// 根据扫描结果更新进度，POC扫描阶段从60%开始，权重40%
		totalTargetsForPOC := len(scanTargets)
		if totalTargetsForPOC > 0 {
			w.updateProgressByResult(taskCtx.Config.TaskID, "POC 扫描", 0, totalTargetsForPOC, 60.0, 40.0, taskCtx)
		} else {
			w.updateProgressGradually(taskCtx.Config.TaskID, "POC 扫描", "正在执行: POC 扫描", 60.0, taskCtx)
		}

		// 设置进度回调，实时更新漏洞扫描进度
		if totalTargetsForPOC > 0 {
			vulnService.SetProgressCallback(func(scanned, total int) {
				w.updateProgressByResult(taskCtx.Config.TaskID, "POC 扫描", scanned, total, 60.0, 40.0, taskCtx)
			})
		}

		// 添加 panic 恢复机制，避免 POC 过多导致任务失败
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("Worker %d: %v", w.id, r)
					w.logError(taskCtx.Config.TaskID, fmt.Sprintf("POC 扫描发生 panic: %v", r))
					websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("POC 扫描发生 panic: %v", r))
					// 即使发生 panic，也继续执行，不中断任务流程
				}
			}()

			if err := vulnService.RunNucleiScan(scanTargets, fpMap, taskCtx.Config); err != nil {
				logger.Debug("Worker %d: %v", w.id, err)
				w.logError(taskCtx.Config.TaskID, fmt.Sprintf("POC 扫描失败: %v", err))
				websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("POC 扫描失败: %v", err))
				// 即使 POC 扫描失败，也继续执行，不中断任务流程
				// 因为 POC 过多可能导致内存不足或其他问题，但不应该导致整个任务失败
			} else {
				logger.Debug("Worker %d start scan workflow", w.id)
			}
		}()

		if taskCtx.Ctx.Err() != nil || strings.ToLower(strings.TrimSpace(taskCtx.Status)) != "running" {
			return fmt.Errorf("任务被取消")
		}

		// 无论 POC 扫描是否成功，都更新进度到100%
		if totalTargetsForPOC > 0 {
			w.updateProgressByResult(taskCtx.Config.TaskID, "POC 扫描", totalTargetsForPOC, totalTargetsForPOC, 60.0, 40.0, taskCtx)
		} else {
			w.updateProgressGradually(taskCtx.Config.TaskID, "POC 扫描", "POC 扫描完成", 100.0, taskCtx)
		}
		w.logInfo(taskCtx.Config.TaskID, "POC 扫描完成")
		websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "POC 扫描完成")
	} else {
		logger.Debug("Worker %d: %v", w.id, mode)
	}

	logger.Debug("Worker %d: %v", w.id, mode)
	return nil
}

// runPortScanWorkflow 端口扫描工作流
func (w *Worker) runPortScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	logger.Debug("Worker %d start scan workflow", w.id)

	// 阶段 1: 端口服务扫描
	select {
	case <-taskCtx.Ctx.Done():
		return fmt.Errorf("任务被取消")
	default:
	}

	_ = w.updateTaskStage(taskCtx.Config.TaskID, "portscan")
	w.updateProgressGradually(taskCtx.Config.TaskID, "端口服务扫描", "正在执行: 端口服务扫描 (1/4)", 40.0, taskCtx)
	w.logInfo(taskCtx.Config.TaskID, "正在执行: 端口服务扫描 (1/4)")
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始端口服务扫描")

	logger.Debug("Worker %d: port scan target count=%d", w.id, len(targets))
	openPorts, err := scanService.RunPortScan(targets, taskCtx.Config)
	if err != nil {
		logger.Debug("Worker %d: %v", w.id, err)
		w.logError(taskCtx.Config.TaskID, fmt.Sprintf("端口服务扫描失败: %v", err))
		websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("端口服务扫描失败: %v", err))
		return err
	}

	logger.Debug("Worker %d: found %d open ports", w.id, len(openPorts))
	w.logInfo(taskCtx.Config.TaskID, fmt.Sprintf("发现 %d 个开放端口服务", len(openPorts)))
	websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", fmt.Sprintf("发现 %d 个开放端口服务", len(openPorts)))

	if len(openPorts) == 0 {
		return nil
	}

	// 阶段 2: Web联动（可选）
	if taskCtx.Config.WebLink {
		select {
		case <-taskCtx.Ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		_ = w.updateTaskStage(taskCtx.Config.TaskID, "web_link")
		w.updateProgressGradually(taskCtx.Config.TaskID, "Web联动", "正在执行: Web联动探测 (2/4)", 65.0, taskCtx)
		w.logInfo(taskCtx.Config.TaskID, "正在执行: Web联动探测 (2/4)")
		websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始Web联动探测")

		logger.Debug("Worker %d: web link open port count=%d", w.id, len(openPorts))
		urls, err := scanService.RunWebProbe(openPorts, taskCtx.Config, true) // 端口扫描的Web联动需要查询数据库
		if err != nil {
			logger.Debug("Worker %d: %v", w.id, err)
			w.logError(taskCtx.Config.TaskID, fmt.Sprintf("Web联动失败: %v", err))
			websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("Web联动失败: %v", err))
		} else {
			logger.Debug("Worker %d: %v", w.id, len(urls))
			w.logInfo(taskCtx.Config.TaskID, fmt.Sprintf("发现 %d 个Web服务", len(urls)))
			websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", fmt.Sprintf("发现 %d 个Web服务", len(urls)))

			// Web探测成功后自动执行指纹识别
			if len(urls) > 0 {
				logger.Debug("Worker %d start scan workflow", w.id)
				w.logInfo(taskCtx.Config.TaskID, "开始指纹识别")
				websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始指纹识别")

				fingerprintService := service.NewFingerprintService(taskCtx.Config.TaskID, taskCtx.Ctx)
				if err := fingerprintService.RunFingerprintIdentification(urls); err != nil {
					logger.Debug("Worker %d: %v", w.id, err)
					w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别失败: %v", err))
					websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别失败: %v", err))
				} else {
					logger.Debug("Worker %d start scan workflow", w.id)
					w.logInfo(taskCtx.Config.TaskID, "指纹识别完成")
					websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "指纹识别完成")

					// 指纹识别成功后自动执行POC扫描
					logger.Debug("Worker %d start scan workflow", w.id)
					w.logInfo(taskCtx.Config.TaskID, "开始漏洞扫描")
					websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始漏洞扫描")

					// 获取指纹识别结果
					fpMap, err := fingerprintService.GetFingerprintResults()
					if err != nil {
						w.logError(taskCtx.Config.TaskID, fmt.Sprintf("获取指纹识别结果失败: %v", err))
						fpMap = make(map[string][]string) // 使用空映射继续扫描
					}

					// 执行POC扫描
					vulnService := service.NewVulnService(taskCtx.Config.TaskID, taskCtx.Ctx)
					if taskCtx.LogService != nil {
						vulnService.SetLogService(taskCtx.LogService)
					}
					if err := vulnService.RunNucleiScan(urls, fpMap, taskCtx.Config); err != nil {
						logger.Debug("Worker %d: %v", w.id, err)
						w.logError(taskCtx.Config.TaskID, fmt.Sprintf("漏洞扫描失败: %v", err))
						websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("漏洞扫描失败: %v", err))
					} else {
						logger.Debug("Worker %d start scan workflow", w.id)
						w.logInfo(taskCtx.Config.TaskID, "漏洞扫描完成")
						websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "漏洞扫描完成")
					}
				}
			}
		}

		if taskCtx.Ctx.Err() != nil || strings.ToLower(strings.TrimSpace(taskCtx.Status)) != "running" {
			return fmt.Errorf("任务被取消")
		}
	} else {
		// 未开启Web联动：默认执行Web探测 + 指纹识别，但不执行POC扫描
		select {
		case <-taskCtx.Ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		_ = w.updateTaskStage(taskCtx.Config.TaskID, "web_probe")
		// 使用渐进式进度更新
		w.updateProgressGradually(taskCtx.Config.TaskID, "Web探测", "正在执行: Web探测 (2/4)", 65.0, taskCtx)
		w.logInfo(taskCtx.Config.TaskID, "正在执行: Web探测 (2/4)")
		websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始Web探测")

		logger.Debug("Worker %d: web probe open port count=%d", w.id, len(openPorts))
		urls, err := scanService.RunWebProbe(openPorts, taskCtx.Config, true) // 端口扫描的Web联动需要查询database
		if err != nil {
			logger.Debug("Worker %d: %v", w.id, err)
			w.logError(taskCtx.Config.TaskID, fmt.Sprintf("Web探测失败: %v", err))
			websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("Web探测失败: %v", err))
		} else {
			logger.Debug("Worker %d: %v", w.id, len(urls))
			w.logInfo(taskCtx.Config.TaskID, fmt.Sprintf("发现 %d 个Web服务", len(urls)))
			websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", fmt.Sprintf("发现 %d 个Web服务", len(urls)))

			// Web探测成功后自动执行指纹识别（不执行POC）
			if len(urls) > 0 {
				_ = w.updateTaskStage(taskCtx.Config.TaskID, "fingerprint")
				// 使用渐进式进度更新
				w.updateProgressGradually(taskCtx.Config.TaskID, "指纹识别", "正在执行: 指纹识别 (3/4)", 85.0, taskCtx)
				w.logInfo(taskCtx.Config.TaskID, "正在执行: 指纹识别 (3/4)")
				websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始指纹识别")

				fingerprintService := service.NewFingerprintService(taskCtx.Config.TaskID, taskCtx.Ctx)
				if err := fingerprintService.RunFingerprintIdentification(urls); err != nil {
					logger.Debug("Worker %d: %v", w.id, err)
					w.logError(taskCtx.Config.TaskID, fmt.Sprintf("指纹识别失败: %v", err))
					websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("指纹识别失败: %v", err))
				} else {
					logger.Debug("Worker %d start scan workflow", w.id)
					w.logInfo(taskCtx.Config.TaskID, "指纹识别完成")
					websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", "指纹识别完成")
				}
			}
		}
	}

	return nil
}

func (w *Worker) runSubdomainScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	return w.runSingleStageModuleScan(taskCtx, "subdomain_scan", "子域名扫描", func() (int, error) {
		return scanService.RunSubdomainScan(targets, taskCtx.Config)
	})
}

func (w *Worker) runWeakPasswordScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	return w.runSingleStageModuleScan(taskCtx, "weak_password_scan", "弱口令扫描", func() (int, error) {
		return scanService.RunWeakPasswordScan(targets, taskCtx.Config)
	})
}

func (w *Worker) runDirectoryScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	return w.runSingleStageModuleScan(taskCtx, "directory_scan", "目录扫描", func() (int, error) {
		return scanService.RunDirectoryScan(targets, taskCtx.Config)
	})
}

func (w *Worker) runJSScanWorkflow(taskCtx *TaskContext, scanService *service.ScanService, targets []string) error {
	return w.runSingleStageModuleScan(taskCtx, "js_scan", "JS扫描", func() (int, error) {
		return scanService.RunJSScan(targets, taskCtx.Config)
	})
}

func (w *Worker) runSingleStageModuleScan(taskCtx *TaskContext, stage, label string, run func() (int, error)) error {
	select {
	case <-taskCtx.Ctx.Done():
		return fmt.Errorf("任务被取消")
	default:
	}

	_ = w.updateTaskStage(taskCtx.Config.TaskID, stage)
	w.updateProgressGradually(taskCtx.Config.TaskID, label, "正在执行: "+label, 20.0, taskCtx)
	w.logInfo(taskCtx.Config.TaskID, "开始"+label)
	websocket.BroadcastLog(taskCtx.Config.TaskID, "INFO", "开始"+label)

	count, err := run()
	if err != nil {
		w.logError(taskCtx.Config.TaskID, fmt.Sprintf("%s失败: %v", label, err))
		websocket.BroadcastLog(taskCtx.Config.TaskID, "ERROR", fmt.Sprintf("%s失败: %v", label, err))
		return err
	}
	if taskCtx.Ctx.Err() != nil || strings.ToLower(strings.TrimSpace(taskCtx.Status)) != "running" {
		return fmt.Errorf("任务被取消")
	}

	message := fmt.Sprintf("%s完成，发现 %d 条结果", label, count)
	w.updateProgressGradually(taskCtx.Config.TaskID, label, message, 95.0, taskCtx)
	w.logInfo(taskCtx.Config.TaskID, message)
	websocket.BroadcastLog(taskCtx.Config.TaskID, "SUCCESS", message)
	return nil
}

// SubmitTask 提交任务到调度器（不包含用户ID，不推荐使用）。
// 1. 生成UUID作为TaskID
// 2. 持久化任务配置到task_config表
// 3. 将任务放入缓冲队列，等待Worker获取
//
// 参数:
//   - config: 任务配置（不含TaskID和Status，由本函数填充）
//
// 返回值:
//   - string: 新生成的任务ID
//   - error: 持久化失败时返回错误
