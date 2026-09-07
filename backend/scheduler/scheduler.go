// Package scheduler 提供异步扫描任务的调度与执行管理。
// 实现基于Worker Pool（工作池）模式的任务调度器，支持以下核心能力：
//   - 任务提交与管理：提交、暂停、停止、删除、恢复任务
//   - 多阶段扫描流水线：Web扫描（Web探测->指纹识别->POC扫描）、端口扫描（端口扫描->协议检测->Web联动->指纹识别->POC扫描）
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
	"FusionWeb/backend/config"
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/common/callnuclei"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"context"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
)

// TaskScheduler 任务调度器，是整个异步任务系统的核心。
// 维护Worker Pool、任务队列和运行中任务的上下文映射。
//
// 字段说明:
//   - maxConcurrent: 最大并发Worker数量
//   - taskQueue: 待执行任务的缓冲通道（容量500）
//   - workers: Worker池，固定数量的工作协程
//   - tasks: 运行中任务的上下文映射（taskID -> TaskContext）
//   - mu: 保护tasks映射的读写锁
//   - ctx/cancel: 全局上下文，用于优雅关闭所有Worker
type TaskScheduler struct {
	maxConcurrent int
	taskQueue     chan *models.TaskConfig
	workers       []*Worker
	tasks         map[string]*TaskContext
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// TaskContext 任务上下文，封装单个任务运行时的所有状态信息。
// 每个运行中的任务对应一个TaskContext实例，存储在TaskScheduler.tasks映射中。
//
// 字段说明:
//   - Config: 任务配置（扫描参数、目标等）
//   - Progress: 进度信息（阶段、百分比、消息）
//   - Cancel/Ctx: 用于取消任务执行的context机制
//   - Status: 当前任务状态（running/paused/cancelled）
//   - LogService: 任务专属的日志服务，拦截gologger输出到任务日志文件
//   - progressMu: 保护Progress字段并发读写的锁，防止WebSocket广播时数据竞争
type TaskContext struct {
	Config     *models.TaskConfig
	Progress   *models.ProgressInfo
	Cancel     context.CancelFunc
	Ctx        context.Context
	Status     string
	LogService *service.LogService // 任务专属日志服务
	progressMu sync.RWMutex        // 保护 Progress 的并发访问
	runtimeMu  sync.Mutex
	runtimeAt  time.Time
}

// Worker 工作协程，从调度器接收任务并执行。
// 每个Worker运行在一个独立的goroutine中，通过无缓冲通道接收任务，
// 确保只有在Worker空闲时才能接收新任务（背压控制）。
//
// 字段说明:
//   - id: Worker唯一标识
//   - scheduler: 所属调度器引用，用于访问任务上下文和全局状态
//   - taskChan: 无缓冲任务通道，实现天然的背压控制
type Worker struct {
	id        int
	name      string
	scheduler *TaskScheduler
	taskChan  chan *models.TaskConfig
}

// updateProgressGradually 从当前进度平滑过渡到目标进度，避免进度条跳跃。
// 根据进度差距动态调整步长和更新间隔：
//   - 差距<10%: 步长0.5%，间隔30ms（小步慢走）
//   - 差距10-30%: 步长1%，间隔40ms
//   - 差距>30%: 步长1.5%，间隔50ms（大步快走）
//
// 参数:
//   - taskID: 任务标识
//   - stage: 当前阶段名称
//   - message: 进度消息
//   - targetPercentage: 目标进度百分比(0-100)
//   - taskCtx: 任务上下文，用于获取当前进度和检查取消信号
//
// 并发安全：使用progressMu读写锁保护Progress字段的并发访问
func NewTaskScheduler(maxConcurrent int) *TaskScheduler {
	ctx, cancel := context.WithCancel(context.Background())

	scheduler := &TaskScheduler{
		maxConcurrent: maxConcurrent,
		taskQueue:     make(chan *models.TaskConfig, 500), // 增加任务队列大小，从100增加到500
		workers:       make([]*Worker, maxConcurrent),
		tasks:         make(map[string]*TaskContext),
		ctx:           ctx,
		cancel:        cancel,
	}
	// 启动 Worker 池
	for i := 0; i < maxConcurrent; i++ {
		worker := &Worker{
			id:        i,
			name:      fmt.Sprintf("worker-%d", i),
			scheduler: scheduler,
			taskChan:  make(chan *models.TaskConfig), // 无缓冲通道，确保只有Worker空闲才能发送
		}
		scheduler.workers[i] = worker
		go worker.run()
	}

	// 启动调度协程
	go scheduler.dispatch()

	// Redis 可用时启动 API 本地消费者；可通过 FUSIONWEB_LOCAL_CONSUMER=false 关闭。
	if database.RedisEnabled() && config.Get().LocalConsumer {
		executor := NewTaskExecutor(scheduler.ctx, "api-local")
		go func() {
			if err := ConsumeStream(scheduler.ctx, "api-local", func(ctx context.Context, taskID, _ string) error {
				task, err := LoadTaskConfigFromDB(taskID)
				if err != nil {
					return err
				}
				return executor.Execute(ctx, task)
			}); err != nil && scheduler.ctx.Err() == nil {
				logger.Warn("API 本地 Stream 消费者退出: %v", err)
			}
		}()
	}

	return scheduler
}

// dispatch 任务分发协程，从任务队列中取出任务并分配给空闲Worker。
// 采用两阶段分发策略优化性能：
//
//	第一轮：快速非阻塞轮询所有Worker，无需使用reflect包，性能更好
//	第二轮：使用reflect.Select同时监听所有Worker通道，阻塞等待第一个空闲Worker
//
// 同时监听全局ctx.Done()以支持优雅关闭。
func (s *TaskScheduler) dispatch() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case task := <-s.taskQueue:
			// 优化：使用更高效的Worker选择策略
			// 先尝试快速轮询所有Worker，如果都忙则使用select等待
			assigned := false

			// 第一轮：快速非阻塞尝试
			for _, worker := range s.workers {
				select {
				case worker.taskChan <- task:
					assigned = true
					goto next_task
				default:
					continue
				}
			}

			// 第二轮：如果没有空闲Worker，使用select等待任意Worker空闲
			if !assigned {
				// 使用select同时等待所有Worker，第一个可用的Worker会获得任务
				cases := make([]reflect.SelectCase, len(s.workers)+1)
				for i, worker := range s.workers {
					cases[i] = reflect.SelectCase{
						Dir:  reflect.SelectSend,
						Chan: reflect.ValueOf(worker.taskChan),
						Send: reflect.ValueOf(task),
					}
				}
				// 替换超时case为上下文取消检查，确保在等待时能响应关闭信号
				cases[len(s.workers)] = reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(s.ctx.Done()),
				}

				chosen, _, _ := reflect.Select(cases)
				if chosen < len(s.workers) {
					assigned = true
				} else {
					// 上下文已取消，退出
					return
				}
			}
		next_task:
		}
	}
}

// run Worker的主循环，持续从taskChan接收任务并执行。
// 同时监听调度器的全局ctx.Done()以支持优雅关闭。
func (w *Worker) run() {
	for {
		select {
		case <-w.scheduler.ctx.Done():
			return
		case task := <-w.taskChan:
			w.executeTask(task)
		}
	}
}

// executeTask Worker执行单个任务的主入口。
// 执行流程：
//  1. 资源限制检查（目标数量、内存使用率），不通过则拒绝执行
//  2. 初始化LogService和TaskContext，注册到调度器
//  3. 初始化两级隔离的任务状态（任务类型级+任务实例级）
//  4. 调用runScanWorkflow执行扫描流水线
//  5. 无论成功/失败/panic，确保清理资源和发送钉钉通知
//  6. defer统一处理cleanup：删除任务上下文、停止日志服务、清理实例状态
//
// 并发安全：使用mu锁保护tasks映射的读写，progressMu保护进度信息
func (w *Worker) executeTask(task *models.TaskConfig) (execErr error) {
	logger.Debug("Worker %d start task, TaskID: %s", w.id, task.TaskID)

	runtimeService := service.NewTaskRuntimeService()
	workerName := w.workerName()
	lockOwner := fmt.Sprintf("%s:%d", workerName, time.Now().UnixNano())
	lockAcquired, lockErr := runtimeService.AcquireTaskLock(task.TaskID, lockOwner, 10*time.Minute)
	if lockErr != nil {
		logger.Debug("Worker %d Redis任务锁获取失败，继续执行本地任务: %v", w.id, lockErr)
		lockAcquired = true
	}
	if !lockAcquired {
		logger.Warn("任务 %s 已被其他Worker接管，保留 Stream Pending 消息等待原 Worker 完成", task.TaskID)
		return fmt.Errorf("任务 %s 正由其他 Worker 执行", task.TaskID)
	}
	stopHeartbeat := runtimeService.StartTaskLockHeartbeat(task.TaskID, lockOwner, 10*time.Minute, 2*time.Minute)
	defer func() {
		stopHeartbeat()
		_ = runtimeService.ReleaseTaskLock(task.TaskID, lockOwner)
	}()
	_ = runtimeService.ClearControlSignal(task.TaskID)
	_ = runtimeService.SetTaskState(task.TaskID, map[string]interface{}{
		"worker_id": workerName,
	})

	// 资源限制检查
	limiter := utils.GetResourceLimiter()

	// 检查目标数量限制
	targets := parseTargets(task.TargetInput)
	if err := limiter.CheckTargetLimit(len(targets)); err != nil {
		logger.Error("任务 %s 目标数量超过限制: %v", task.TaskID, err)
		_ = w.updateTaskStatus(task.TaskID, "failed")
		w.logError(task.TaskID, fmt.Sprintf("目标数量超过限制: %v", err))
		return
	}

	// 检查内存使用
	usedMB, limitMB, ok := limiter.CheckMemoryUsage()
	if !ok {
		logger.Warn("任务 %s 启动时内存使用率过高: %dMB / %dMB", task.TaskID, usedMB, limitMB)
		// 触发GC
		runtime.GC()
		// 等待一下再检查
		time.Sleep(1 * time.Second)
		usedMB, limitMB, ok = limiter.CheckMemoryUsage()
		if !ok {
			logger.Error("任务 %s 内存使用率仍然过高，拒绝启动: %dMB / %dMB", task.TaskID, usedMB, limitMB)
			_ = w.updateTaskStatus(task.TaskID, "failed")
			w.logError(task.TaskID, fmt.Sprintf("内存使用率过高，无法启动任务: %dMB / %dMB", usedMB, limitMB))
			return
		}
	}

	// 标记任务是否已正常完成
	taskCompleted := false

	defer func() {
		if r := recover(); r != nil {
			logger.Debug("Worker %d: %v", w.id, r)
			// 捕获 panic，确保任务状态更新为失败
			_ = w.updateTaskStatus(task.TaskID, "failed")
			w.logError(task.TaskID, fmt.Sprintf("任务崩溃: %v", r))
		} else if !taskCompleted {
			// 如果没有panic但任务未正常完成，检查并更新状态
			var currentStatus string
			err := database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", task.TaskID).Scan(&currentStatus)
			if err == nil && currentStatus == "running" {
				// 如果任务状态仍然是running，说明可能没有正常完成，更新为failed
				logger.Debug("Worker %d task status anomaly, set failed, TaskID: %s", w.id, task.TaskID)
				_ = w.updateTaskStatus(task.TaskID, "failed")
			}
		}
	}()

	logger.Debug("Worker %d start scan workflow", w.id)
	// 更新任务状态为运行中
	callnuclei.StoppedTasks.Delete(task.TaskID)
	_ = w.updateTaskStatus(task.TaskID, "running")

	// 初始化 LogService
	logService := service.NewLogService(task.TaskID, database.DB)

	// 创建任务上下文
	ctx, cancel := context.WithCancel(w.scheduler.ctx)
	taskCtx := &TaskContext{
		Config:     task,
		Progress:   &models.ProgressInfo{TaskID: task.TaskID},
		Cancel:     cancel,
		Ctx:        ctx,
		Status:     "running",
		LogService: logService,
	}

	w.scheduler.mu.Lock()
	w.scheduler.tasks[task.TaskID] = taskCtx
	w.scheduler.mu.Unlock()

	// 确保任务结束时清理资源
	defer func() {
		w.scheduler.mu.Lock()
		delete(w.scheduler.tasks, task.TaskID)
		w.scheduler.mu.Unlock()
		if logService != nil {
			logService.Stop()
		}
	}()

	// 任务隔离：按任务类型和任务实例初始化状态
	taskType := strings.ToLower(strings.TrimSpace(task.TaskType))
	if taskType == "" {
		taskType = "web" // 默认任务类型
	}

	// 第一级：获取或创建任务类型级别的状态（确保任务类型状态存在）
	_ = structs.GetOrCreateTaskTypeState(taskType)

	// 第二级：获取或创建任务实例级别的状态
	taskInstanceState := structs.GetOrCreateTaskInstanceState(task.TaskID, taskType)

	// 初始化任务实例状态（清理旧数据）
	taskInstanceState.URLMap = make(map[string]structs.URLEntity)
	taskInstanceState.ResultMap = make(map[string][]string)
	taskInstanceState.IPPortMap = make(map[string]string)

	logger.Debug("Worker %d execute task, TaskID: %s, TaskType=%s", w.id, task.TaskID, taskType)

	// 不再清理全局状态，避免影响其他并发任务
	// 全局状态应该由各个服务自己管理，不应该在这里清理
	// structs.GlobalURLMap = make(map[string]structs.URLEntity)
	// structs.GlobalResultMap = make(map[string][]string)

	// 只清理当前任务的 TaskURLMaps（如果存在）。
	structs.TaskURLMapsLock.Lock()
	if structs.TaskURLMaps != nil {
		delete(structs.TaskURLMaps, task.TaskID)
	}
	structs.TaskURLMapsLock.Unlock()

	// 执行扫描流程
	logger.Debug("Worker %d state, TaskID: %s", w.id, task.TaskID)
	workflowErr := w.runScanWorkflow(taskCtx)
	var currentStatus string
	if statusErr := database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", task.TaskID).Scan(&currentStatus); statusErr != nil {
		currentStatus = taskCtx.Status
	}
	currentStatus = strings.ToLower(strings.TrimSpace(currentStatus))

	if currentStatus == "paused" || currentStatus == "cancelled" {
		logger.Debug("Worker %d 扫描流程已%s，跳过完成/失败状态覆盖，TaskID: %s", w.id, currentStatus, task.TaskID)
		taskCompleted = true
	} else if workflowErr != nil {
		err := workflowErr
		logger.Debug("Worker %d scan workflow failed, TaskID: %s, Error: %v", w.id, task.TaskID, err)
		task.Status = "failed"
		if updateErr := w.updateTaskStatus(task.TaskID, "failed"); updateErr != nil {
			logger.Debug("Worker %d update status failed: %v", w.id, updateErr)
		}
		w.logError(task.TaskID, err.Error())

		// 即使失败也发送钉钉通知
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("DingTalk notification goroutine panic (failure case): %v", r)
				}
			}()
			service.NewDingTalkBotService().NotifyTask(task)
		}()

		taskCompleted = true // 标记为已处理（失败也算完成）
	} else {
		logger.Debug("Worker %d 扫描流程成功完成，TaskID: %s", w.id, task.TaskID)
		// 在删除任务上下文之前，确保状态更新完成
		// 先更新状态，再删除任务上下文，避免状态不一致
		task.Status = "completed"
		if updateErr := w.updateTaskStatus(task.TaskID, "completed"); updateErr != nil {
			logger.Debug("Worker %d 更新任务状态为completed失败: %v", w.id, updateErr)
		} else {
			logger.Debug("Worker %d 任务状态已更新为 completed，TaskID: %s", w.id, task.TaskID)
			// 发送钉钉通知
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logger.Error("DingTalk notification goroutine panic (success case): %v", r)
					}
				}()
				service.NewDingTalkBotService().NotifyTask(task)
			}()
		}
		taskCompleted = true // 标记为已完成
	}

	// 在状态更新完成后再清理任务上下文，确保状态一致性
	// 清理任务上下文
	// w.scheduler.mu.Lock()
	// delete(w.scheduler.tasks, task.TaskID)
	// w.scheduler.mu.Unlock()

	// 任务隔离：清理任务实例状态
	structs.DeleteTaskInstanceState(task.TaskID)
	logger.Debug("Worker %d state, TaskID: %s", w.id, task.TaskID)
	return nil
}

func (w *Worker) workerName() string {
	if strings.TrimSpace(w.name) != "" {
		return strings.TrimSpace(w.name)
	}
	return fmt.Sprintf("worker-%d", w.id)
}

// findDingTalkSourceTask makes task creation idempotent for retries of the same
// DingTalk message. Empty source fields are intentionally ignored so web-created
// tasks keep their existing behavior.
func findDingTalkSourceTask(config *models.TaskConfig) (string, bool) {
	if config == nil || config.DingTalkBotID <= 0 || strings.TrimSpace(config.DingTalkSourceMessageID) == "" || database.DB == nil {
		return "", false
	}
	var taskID string
	err := database.DB.QueryRow(`SELECT task_id FROM task_config WHERE dingtalk_bot_id=? AND dingtalk_source_message_id=? ORDER BY created_at ASC LIMIT 1`, config.DingTalkBotID, strings.TrimSpace(config.DingTalkSourceMessageID)).Scan(&taskID)
	if err != nil || strings.TrimSpace(taskID) == "" {
		return "", false
	}
	logger.Warn("检测到重复的钉钉任务创建消息，复用已有任务: bot=%d message=%s task=%s", config.DingTalkBotID, config.DingTalkSourceMessageID, taskID)
	return taskID, true
}

// runScanWorkflow 运行扫描工作流
func (s *TaskScheduler) SubmitTask(config *models.TaskConfig) (string, error) {
	if taskID, ok := findDingTalkSourceTask(config); ok {
		return taskID, nil
	}
	// 生成任务 ID
	taskID := uuid.New().String()
	config.TaskID = taskID
	config.Status = "pending"
	// 使用系统时间
	config.CreatedAt = utils.GetCurrentTime()
	config.UpdatedAt = utils.GetCurrentTime()
	timeStr := utils.GetCurrentTimeString()

	logger.Debug("SubmitTask generated TaskID: %s", taskID)

	// 持久化任务配置（不包含user_id，使用SubmitTaskWithUser）
	query := `INSERT INTO task_config 
        (task_id, task_name, task_type, parent_task_id, target_input, port_range, 
        no_port_string, scan_mode, scan_tool, scan_options, thread_count, port_scan_timeout, web_timeout, http_proxy, skip_host_discovery, no_icmp_ping, 
        tcp_ping, ports_threshold, syn_scan_rate, web_link, enable_screenshot,
        scan_all_pocs_when_no_fingerprint, full_poc_scan, enable_active_fingerprint, selected_dicts, assigned_worker, ding_talk_token, ding_talk_secret, ding_talk_key_id, dingtalk_bot_id, dingtalk_conversation_id, dingtalk_conversation_type, dingtalk_source_user_id, dingtalk_source_message_id, created_at, updated_at, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	logger.Debug("SubmitTask TaskType: %s", config.TaskType)
	_, err := database.DB.Exec(query,
		config.TaskID, config.TaskName, config.TaskType, config.ParentTaskID, config.TargetInput,
		config.PortRange, config.NoPortString, config.ScanMode, config.ScanTool, config.ScanOptions,
		config.ThreadCount, config.PortScanTimeout, config.WebTimeout, config.HTTPProxy, database.BoolInt(config.SkipHostDiscovery), database.BoolInt(config.NoICMPPing),
		database.BoolInt(config.TCPPing), config.PortsThreshold, config.SYNScanRate, database.BoolInt(config.WebLink), database.BoolInt(config.EnableScreenshot),
		database.BoolInt(config.ScanAllPOCsWhenNoFingerprint), database.BoolInt(config.FullPocScan), database.BoolInt(config.EnableActiveFingerprint), config.SelectedDicts, config.AssignedWorker, config.DingTalkToken, config.DingTalkSecret, config.DingTalkKeyID, config.DingTalkBotID, config.DingTalkConversationID, config.DingTalkConversationType, config.DingTalkSourceUserID, config.DingTalkSourceMessageID, timeStr, timeStr, config.Status)

	if err != nil {
		logger.Debug("save task error: %v", err)
		return "", fmt.Errorf("保存任务失败: %w", err)
	}

	_ = service.NewTaskRuntimeService().SetTaskState(config.TaskID, map[string]interface{}{
		"status":     "pending",
		"stage":      "待执行",
		"percentage": 0,
		"message":    "任务已提交，等待调度",
	})

	if err := s.publishOrQueue(config); err != nil {
		return "", err
	}
	logger.Debug("SubmitTask queued TaskID: %s", taskID)
	return taskID, nil
}

// SubmitTaskWithUser 提交任务到调度器（含用户归属信息）。
// 相比 SubmitTask，增加 user_id 字段，便于记录任务来源和按 createdBy 查询。
//
// 参数:
//   - config: 任务配置
//   - userID: 创建任务的用户ID
//
// 返回值:
//   - string: 新生成的任务ID
//   - error: 持久化失败时返回错误
func (s *TaskScheduler) SubmitTaskWithUser(config *models.TaskConfig, userID uint) (string, error) {
	if taskID, ok := findDingTalkSourceTask(config); ok {
		return taskID, nil
	}
	// 生成任务 ID
	taskID := uuid.New().String()
	config.TaskID = taskID
	config.Status = "pending"
	// 使用系统时间
	config.CreatedAt = utils.GetCurrentTime()
	config.UpdatedAt = utils.GetCurrentTime()
	timeStr := utils.GetCurrentTimeString()

	logger.Debug("SubmitTaskWithUser generated TaskID: %s", taskID)

	// 持久化任务配置（包含user_id）
	query := `INSERT INTO task_config 
        (task_id, task_name, task_type, parent_task_id, target_input, port_range, 
        no_port_string, scan_mode, scan_tool, scan_options, thread_count, port_scan_timeout, web_timeout, http_proxy, skip_host_discovery, no_icmp_ping, 
        tcp_ping, ports_threshold, syn_scan_rate, web_link, enable_screenshot,
        scan_all_pocs_when_no_fingerprint, full_poc_scan, enable_active_fingerprint, selected_dicts, assigned_worker, ding_talk_token, ding_talk_secret, ding_talk_key_id, dingtalk_bot_id, dingtalk_conversation_id, dingtalk_conversation_type, dingtalk_source_user_id, dingtalk_source_message_id, created_at, updated_at, status, user_id) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	logger.Debug("SubmitTaskWithUser TaskType=%s, UserID=%d", config.TaskType, userID)
	_, err := database.DB.Exec(query,
		config.TaskID, config.TaskName, config.TaskType, config.ParentTaskID, config.TargetInput,
		config.PortRange, config.NoPortString, config.ScanMode, config.ScanTool, config.ScanOptions,
		config.ThreadCount, config.PortScanTimeout, config.WebTimeout, config.HTTPProxy, database.BoolInt(config.SkipHostDiscovery), database.BoolInt(config.NoICMPPing),
		database.BoolInt(config.TCPPing), config.PortsThreshold, config.SYNScanRate, database.BoolInt(config.WebLink), database.BoolInt(config.EnableScreenshot),
		database.BoolInt(config.ScanAllPOCsWhenNoFingerprint), database.BoolInt(config.FullPocScan), database.BoolInt(config.EnableActiveFingerprint), config.SelectedDicts, config.AssignedWorker, config.DingTalkToken, config.DingTalkSecret, config.DingTalkKeyID, config.DingTalkBotID, config.DingTalkConversationID, config.DingTalkConversationType, config.DingTalkSourceUserID, config.DingTalkSourceMessageID, timeStr, timeStr, config.Status, userID)

	if err != nil {
		logger.Debug("save task error: %v", err)
		return "", fmt.Errorf("保存任务失败: %w", err)
	}

	_ = service.NewTaskRuntimeService().SetTaskState(config.TaskID, map[string]interface{}{
		"status":     "pending",
		"stage":      "待执行",
		"percentage": 0,
		"message":    "任务已提交，等待调度",
	})

	// 加入本地队列（阻塞等待，直到有空位）
	if err := s.publishOrQueue(config); err != nil {
		return "", err
	}
	logger.Debug("SubmitTaskWithUser queued TaskID: %s", taskID)
	return taskID, nil
}

// PauseTask 暂停正在运行的任务。
// 通过取消任务的Context来中断执行，更新数据库状态为"paused"。
// 对于已完成/失败/已取消的任务会返回友好的错误提示。
//
// 参数:
//   - taskID: 要暂停的任务ID
//
// 返回值:
//   - error: 任务不存在或不可暂停时返回错误；已暂停的任务返回nil
func (s *TaskScheduler) PauseTask(taskID string) error {
	_ = service.NewTaskRuntimeService().SetControlSignal(taskID, "pause")

	s.mu.RLock()
	taskCtx, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		// 检查数据库中是否存在该任务
		var status string
		err := database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", taskID).Scan(&status)
		if err != nil {
			return fmt.Errorf("任务不存在")
		}
		// 如果任务还在队列中（pending），直接更新状态
		if status == "pending" {
			return s.updateTaskStatus(taskID, "paused")
		}
		// 如果任务已经完成、失败或已取消，返回更友好的错误信息
		if status == "completed" {
			return fmt.Errorf("任务已完成，无法暂停")
		}
		if status == "failed" {
			return fmt.Errorf("任务已失败，无法暂停")
		}
		if status == "cancelled" {
			return fmt.Errorf("任务已取消，无法暂停")
		}
		// 如果状态是 running 但任务不在 s.tasks 中，说明任务可能已经完成但状态未及时更新
		// 这种情况下，应该先检查任务是否真的在运行，如果不在运行，更新状态为 completed
		if status == "running" {
			// 任务不在内存中但状态是 running，说明任务已经完成但状态未更新
			// 更新状态为 completed，避免前端显示错误的状态
			_ = s.updateTaskStatus(taskID, "completed")
			return fmt.Errorf("任务已完成，无法暂停")
		}
		// 如果状态是 paused，说明已经暂停了
		if status == "paused" {
			return nil // 已经暂停，直接返回成功
		}
		return fmt.Errorf("任务未在运行")
	}

	taskCtx.Cancel()
	taskCtx.Status = "paused"

	if err := s.updateTaskStatus(taskID, "paused"); err != nil {
		return err
	}
	callnuclei.StopTask(taskID)
	return nil
}

// StopTask 停止任务（取消执行）。
// 与PauseTask类似但更新状态为"cancelled"，已取消的任务直接返回成功。
//
// 参数:
//   - taskID: 要停止的任务ID
//
// 返回值:
//   - error: 任务不存在或不可停止时返回错误；已取消的任务返回nil
func (s *TaskScheduler) StopTask(taskID string) error {
	_ = service.NewTaskRuntimeService().SetControlSignal(taskID, "stop")

	s.mu.RLock()
	taskCtx, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		// 检查数据库中是否存在该任务
		var status string
		err := database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", taskID).Scan(&status)
		if err != nil {
			return fmt.Errorf("任务不存在")
		}
		// 如果任务已经完成、失败或已取消，返回更友好的错误信息
		if status == "completed" {
			return fmt.Errorf("任务已完成，无法停止")
		}
		if status == "failed" {
			return fmt.Errorf("任务已失败，无法停止")
		}
		if status == "cancelled" {
			return nil // 已经取消，直接返回成功
		}
		// 如果任务还在队列中（pending/paused），直接更新状态
		if status == "pending" || status == "paused" {
			return s.updateTaskStatus(taskID, "cancelled")
		}
		// 如果状态是 running 但任务不在 s.tasks 中，说明任务可能已经完成但状态未及时更新
		if status == "running" {
			// 任务不在内存中但状态是 running，说明任务已经完成但状态未更新
			// 更新状态为 completed，避免前端显示错误的状态
			_ = s.updateTaskStatus(taskID, "completed")
			return fmt.Errorf("任务已完成，无法停止")
		}
		return fmt.Errorf("任务未在运行")
	}

	taskCtx.Cancel()
	taskCtx.Status = "cancelled"

	if err := s.updateTaskStatus(taskID, "cancelled"); err != nil {
		return err
	}
	callnuclei.StopTask(taskID)
	return nil
}

// DeleteTask 删除任务及其所有关联数据。
// 使用数据库事务确保原子性，按依赖顺序依次删除：
//  1. recon_results（信息收集结果）
//  2. fingerprint_results（指纹识别结果）
//  3. vuln_results（漏洞扫描结果）
//  4. task_config（任务配置主表）
//
// 同时从内存中移除任务上下文。
//
// 参数:
//   - taskID: 要删除的任务ID
//
// 返回值:
//   - error: 事务执行失败时返回错误
func (s *TaskScheduler) DeleteTask(taskID string) error {
	// 先尝试停止任务
	_ = s.StopTask(taskID)

	s.mu.Lock()
	delete(s.tasks, taskID)
	s.mu.Unlock()

	// 开启事务，手动删除所有关联数据
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	defer tx.Rollback()

	// 1. 删除信息收集结果
	if _, err := tx.Exec("DELETE FROM recon_results WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("删除信息收集结果失败: %w", err)
	}

	// 2. 删除指纹识别结果
	if _, err := tx.Exec("DELETE FROM fingerprint_results WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("删除指纹识别结果失败: %w", err)
	}

	// 3. 删除漏洞扫描结果
	if _, err := tx.Exec("DELETE FROM vuln_results WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("删除漏洞扫描结果失败: %w", err)
	}

	// 4. 删除独立扫描模块结果
	for _, item := range []struct {
		table string
		label string
	}{
		{"subdomain_results", "子域名扫描结果"},
		{"weak_password_results", "弱口令扫描结果"},
		{"directory_results", "目录扫描结果"},
		{"js_scan_results", "JS扫描结果"},
	} {
		if _, err := tx.Exec(fmt.Sprintf("DELETE FROM %s WHERE task_id = ?", item.table), taskID); err != nil {
			return fmt.Errorf("删除%s失败: %w", item.label, err)
		}
	}

	// 5. 删除任务配置（主表）
	if _, err := tx.Exec("DELETE FROM task_config WHERE task_id = ?", taskID); err != nil {
		return fmt.Errorf("删除任务配置失败: %w", err)
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	_ = service.NewTaskRuntimeService().DeleteTaskRuntime(taskID)

	return nil
}

// ResumeTask 从暂停状态恢复任务执行。
// 仅允许状态为"paused"的任务恢复。从数据库读取原始配置，
// 使用原有TaskID（不生成新的），将任务重新放入队列。
// 如果队列已满，恢复状态为paused并返回错误。
//
// 参数:
//   - taskID: 要恢复的任务ID
//
// 返回值:
//   - error: 任务不存在/状态非暂停/队列满时返回错误
func (s *TaskScheduler) ResumeTask(taskID string) error {
	// 查询任务配置
	var config models.TaskConfig
	var skipHostDiscovery, noICMPPing, tcpPing, webLink int
	var scanAllPOCsWhenNoFingerprint, fullPocScan, enableActiveFingerprint, enableScreenshot int
	query := `
        SELECT task_id, task_name, task_type, target_input, 
               port_range, no_port_string, scan_mode, scan_tool, scan_options, thread_count, port_scan_timeout, web_timeout, http_proxy, 
               skip_host_discovery, no_icmp_ping, tcp_ping, ports_threshold, syn_scan_rate,
               web_link, scan_all_pocs_when_no_fingerprint, full_poc_scan, 
               enable_active_fingerprint, enable_screenshot, selected_dicts, assigned_worker, ding_talk_token, ding_talk_secret, ding_talk_key_id, dingtalk_bot_id, dingtalk_conversation_id, dingtalk_conversation_type, dingtalk_source_user_id, dingtalk_source_message_id, status
        FROM task_config 
        WHERE task_id = ? AND status = 'paused'
    `

	err := database.DB.QueryRow(query, taskID).Scan(
		&config.TaskID, &config.TaskName, &config.TaskType, &config.TargetInput,
		&config.PortRange, &config.NoPortString, &config.ScanMode, &config.ScanTool, &config.ScanOptions,
		&config.ThreadCount, &config.PortScanTimeout, &config.WebTimeout, &config.HTTPProxy, &skipHostDiscovery, &noICMPPing,
		&tcpPing, &config.PortsThreshold, &config.SYNScanRate, &webLink,
		&scanAllPOCsWhenNoFingerprint, &fullPocScan, &enableActiveFingerprint,
		&enableScreenshot, &config.SelectedDicts, &config.AssignedWorker, &config.DingTalkToken, &config.DingTalkSecret, &config.DingTalkKeyID, &config.DingTalkBotID, &config.DingTalkConversationID, &config.DingTalkConversationType, &config.DingTalkSourceUserID, &config.DingTalkSourceMessageID, &config.Status,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("任务不存在或状态不是暂停")
		}
		return fmt.Errorf("查询任务失败: %w", err)
	}
	config.SkipHostDiscovery = database.IntBool(skipHostDiscovery)
	config.NoICMPPing = database.IntBool(noICMPPing)
	config.TCPPing = database.IntBool(tcpPing)
	config.WebLink = database.IntBool(webLink)
	config.ScanAllPOCsWhenNoFingerprint = database.IntBool(scanAllPOCsWhenNoFingerprint)
	config.FullPocScan = database.IntBool(fullPocScan)
	config.EnableActiveFingerprint = database.IntBool(enableActiveFingerprint)
	config.EnableScreenshot = database.IntBool(enableScreenshot)

	callnuclei.StoppedTasks.Delete(taskID)
	runtimeService := service.NewTaskRuntimeService()
	_ = runtimeService.SetControlSignal(taskID, "resume")

	// 更新任务状态为 running
	if err := s.updateTaskStatus(taskID, "running"); err != nil {
		return fmt.Errorf("更新任务状态失败: %w", err)
	}

	// 将任务重新发布到 Redis Stream；发布失败时降级本地队列。
	if err := s.publishOrQueue(&config); err != nil {
		_ = s.updateTaskStatus(taskID, "paused")
		_ = runtimeService.SetControlSignal(taskID, "pause")
		return err
	}
	return nil
}

func (s *TaskScheduler) publishOrQueue(task *models.TaskConfig) error {
	if database.RedisEnabled() {
		var err error
		if strings.TrimSpace(task.AssignedWorker) != "" {
			err = PublishTaskToWorker(task.TaskID, task.TaskType, task.AssignedWorker)
		} else {
			err = PublishTask(task.TaskID, task.TaskType)
		}
		if err == nil {
			return nil
		}
		logger.Warn("Redis Stream 发布失败，降级本地: %v", err)
	}
	select {
	case s.taskQueue <- task:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// GetProgress 获取任务的实时执行进度。
// 对于运行中的任务：从内存中的TaskContext获取，使用读锁保护，返回进度副本防止外部修改。
// 对于已完成/取消的任务：上下文已清理，从数据库查询状态并构造固定的进度信息。
//
// 参数:
//   - taskID: 任务ID
//
// 返回值:
//   - *models.ProgressInfo: 进度信息（阶段、百分比、消息）
//   - error: 任务不存在或状态异常时返回错误
func (s *TaskScheduler) GetProgress(taskID string) (*models.ProgressInfo, error) {
	s.mu.RLock()
	taskCtx, exists := s.tasks[taskID]
	s.mu.RUnlock()

	if !exists {
		if runtimeState, ok := service.NewTaskRuntimeService().GetTaskState(taskID); ok && runtimeState.Progress != nil {
			return runtimeState.Progress, nil
		}

		// 任务完成后上下文被删除，从数据库查询任务状态
		var status string
		err := database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", taskID).Scan(&status)
		if err != nil {
			return nil, fmt.Errorf("任务不存在")
		}

		// 如果任务已完成、失败或取消，返回100%进度（表示任务已结束）
		if status == "completed" || status == "failed" || status == "cancelled" {
			return &models.ProgressInfo{
				TaskID:     taskID,
				Stage:      "已完成",
				Percentage: 100.0,
				Message:    "任务已完成",
			}, nil
		}

		// 如果任务状态不是运行中，可能是暂停状态
		if status == "paused" {
			return &models.ProgressInfo{
				TaskID:     taskID,
				Stage:      "已暂停",
				Percentage: 0.0,
				Message:    "任务已暂停",
			}, nil
		}

		return nil, fmt.Errorf("任务状态异常")
	}

	// 使用读锁保护 Progress 的读取，并返回副本避免外部修改影响内部状态
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

	return progress, nil
}

// updateTaskStatus 更新任务状态（Worker方法，会同时更新completed_at时间戳）。
// 当状态为completed/failed/cancelled时，额外记录完成时间。
// 更新后通过WebSocket广播状态变更通知前端。
