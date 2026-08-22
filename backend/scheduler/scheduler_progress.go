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
	"FusionWeb/backend/service"
	"FusionWeb/backend/websocket"
	"fmt"
	"time"
)

func (w *Worker) updateProgressGradually(taskID, stage, message string, targetPercentage float64, taskCtx *TaskContext) {
	// 读取当前进度（加读锁）
	taskCtx.progressMu.RLock()
	currentPercentage := taskCtx.Progress.Percentage
	taskCtx.progressMu.RUnlock()

	if currentPercentage >= targetPercentage {
		// 如果当前进度已经大于等于目标进度，直接设置（加写锁）
		taskCtx.progressMu.Lock()
		taskCtx.Progress.Percentage = targetPercentage
		taskCtx.Progress.Stage = stage
		taskCtx.Progress.Message = message
		taskCtx.progressMu.Unlock()
		websocket.BroadcastProgress(taskID, stage, targetPercentage, message)
		w.syncRuntimeProgress(taskID, stage, message, targetPercentage, taskCtx, true)
		return
	}

	// 计算差距
	diff := targetPercentage - currentPercentage

	// 根据差距动态调整步长和间隔
	// 差距小（<10%）：小步长，慢速更新，更平滑
	// 差距中（10-30%）：中等步长，中等速度
	// 差距大（>30%）：大步长，快速更新，但不要太快
	var step float64
	var interval time.Duration

	if diff < 10 {
		step = 0.5
		interval = 30 * time.Millisecond
	} else if diff < 30 {
		step = 1.0
		interval = 40 * time.Millisecond
	} else {
		step = 1.5
		interval = 50 * time.Millisecond
	}

	// 逐步更新进度
	for currentPercentage < targetPercentage {
		select {
		case <-taskCtx.Ctx.Done():
			return // 任务被取消，停止更新
		default:
		}

		currentPercentage += step
		if currentPercentage > targetPercentage {
			currentPercentage = targetPercentage
		}

		// 使用写锁保护 Progress 的更新
		taskCtx.progressMu.Lock()
		taskCtx.Progress.Percentage = currentPercentage
		taskCtx.Progress.Stage = stage
		taskCtx.Progress.Message = message
		taskCtx.progressMu.Unlock()

		websocket.BroadcastProgress(taskID, stage, currentPercentage, message)
		w.syncRuntimeProgress(taskID, stage, message, currentPercentage, taskCtx, currentPercentage >= targetPercentage)

		// 动态间隔，让进度条看起来更平滑
		time.Sleep(interval)
	}
}

// updateProgressByResult 根据扫描进度数据计算并更新任务总进度。
// 采用加权计算方式：总进度 = 阶段起始百分比 + (已扫描/总数 * 阶段权重)
// 例如：指纹识别阶段起始30%，权重30%，扫描了5/10个目标 -> 总进度 = 30 + 5/10*30 = 45%
//
// 参数:
//   - taskID: 任务标识
//   - stage: 阶段名称（如"指纹识别"、"POC 扫描"）
//   - scanned: 已扫描/已发现的目标数量
//   - total: 总目标数量
//   - basePercentage: 此阶段的起始进度百分比（已完成阶段的总和）
//   - stageWeight: 此阶段在总进度中的权重（0-100间的百分比）
func (w *Worker) updateProgressByResult(taskID, stage string, scanned, total int, basePercentage, stageWeight float64, taskCtx *TaskContext) {
	if total == 0 {
		// 如果没有总目标数，使用阶段进度
		w.updateProgressGradually(taskID, stage, fmt.Sprintf("%s: 准备中...", stage), basePercentage+stageWeight*0.5, taskCtx)
		return
	}

	// 计算当前阶段的进度百分比
	stageProgress := float64(scanned) / float64(total) * stageWeight
	if stageProgress > stageWeight {
		stageProgress = stageWeight
	}

	// 计算总进度百分比
	targetPercentage := basePercentage + stageProgress
	if targetPercentage > 100 {
		targetPercentage = 100
	}

	// 更新进度
	message := fmt.Sprintf("%s: %d/%d (%.1f%%)", stage, scanned, total, float64(scanned)/float64(total)*100)

	// 读取当前进度（加读锁）
	taskCtx.progressMu.RLock()
	currentPercentage := taskCtx.Progress.Percentage
	taskCtx.progressMu.RUnlock()

	// 优化：降低更新阈值，让进度条更平滑
	// 阈值降低到0.01%，让进度条能够一个值一个值地递进
	// 或者当扫描完成时强制更新
	if targetPercentage-currentPercentage >= 0.01 || scanned == total {
		taskCtx.progressMu.Lock()
		taskCtx.Progress.Percentage = targetPercentage
		taskCtx.Progress.Stage = stage
		taskCtx.Progress.Message = message
		taskCtx.progressMu.Unlock()

		websocket.BroadcastProgress(taskID, stage, targetPercentage, message)
		w.syncRuntimeProgress(taskID, stage, message, targetPercentage, taskCtx, scanned == total)
	}
}

func (w *Worker) syncRuntimeProgress(taskID, stage, message string, percentage float64, taskCtx *TaskContext, force bool) {
	if taskCtx == nil {
		_ = service.NewTaskRuntimeService().SetTaskState(taskID, map[string]interface{}{
			"stage":      stage,
			"message":    message,
			"percentage": percentage,
		})
		return
	}

	now := time.Now()
	taskCtx.runtimeMu.Lock()
	if !force && now.Sub(taskCtx.runtimeAt) < 800*time.Millisecond {
		taskCtx.runtimeMu.Unlock()
		return
	}
	taskCtx.runtimeAt = now
	status := taskCtx.Status
	taskCtx.runtimeMu.Unlock()
	if status == "" {
		status = "running"
	}

	_ = service.NewTaskRuntimeService().SetTaskState(taskID, map[string]interface{}{
		"status":     status,
		"stage":      stage,
		"message":    message,
		"percentage": percentage,
	})
}

// NewTaskScheduler 创建并初始化任务调度器实例。
// 初始化流程：
//   1. 创建带缓冲的任务队列（容量500）
//   2. 启动固定数量的Worker goroutine（无缓冲通道实现背压）
//   3. 启动调度分发goroutine
//
// 参数:
//   - maxConcurrent: 最大并发Worker数量
//
// 返回值:
//   - *TaskScheduler: 已初始化的调度器实例
