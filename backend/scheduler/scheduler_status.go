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
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"
	"strings"
	"time"
)

func (w *Worker) updateTaskStatus(taskID, status string) error {
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	var query string

	// 任务完成或失败时，同时更新 completed_at 字段
	if status == "completed" || status == "failed" || status == "cancelled" {
		query = `UPDATE task_config SET status = ?, updated_at = ?, completed_at = ? WHERE task_id = ?`
		err := execSchedulerDB(query, status, timeStr, timeStr, taskID)
		if err != nil {
			return err
		}
	} else {
		query = `UPDATE task_config SET status = ?, updated_at = ? WHERE task_id = ?`
		err := execSchedulerDB(query, status, timeStr, taskID)
		if err != nil {
			return err
		}
	}

	broadcastTaskStatus(taskID, status)
	_ = service.NewTaskRuntimeService().SetTaskState(taskID, map[string]interface{}{
		"status": status,
	})
	return nil
}

// updateTaskStatus 更新任务状态（Scheduler方法，不含completed_at更新）。
// 用于暂停/停止/删除等不需要记录完成时间的场景。
// 更新后通过WebSocket广播状态变更通知前端。
func (s *TaskScheduler) updateTaskStatus(taskID, status string) error {
	// 获取当前格式化时间字符串
	timeStr := utils.GetCurrentTimeString()

	query := `UPDATE task_config SET status = ?, updated_at = ? WHERE task_id = ?`
	if err := execSchedulerDB(query, status, timeStr, taskID); err != nil {
		return err
	}
	broadcastTaskStatus(taskID, status)
	_ = service.NewTaskRuntimeService().SetTaskState(taskID, map[string]interface{}{
		"status": status,
	})
	return nil
}

// logError 记录错误日志，同时写入全局logger和任务专属LogService。
func execSchedulerDB(query string, args ...interface{}) error {
	var err error
	for i := 0; i < 5; i++ {
		_, err = database.DB.Exec(query, args...)
		if err == nil {
			return nil
		}
		if !isRetryableSchedulerDBError(err) {
			return err
		}
		time.Sleep(time.Duration(i+1) * 120 * time.Millisecond)
	}
	return err
}

func isRetryableSchedulerDBError(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "deadlock detected") ||
		strings.Contains(errText, "lock timeout") ||
		strings.Contains(errText, "could not serialize access")
}

func broadcastTaskStatus(taskID, status string) {
	msg := ""
	switch status {
	case "running":
		msg = "任务已启动"
	case "completed":
		msg = "任务已完成"
	case "failed":
		msg = "任务失败"
	case "paused":
		msg = "任务已暂停"
	case "cancelled":
		msg = "任务已取消"
	}
	websocket.BroadcastStatus(taskID, status, msg)
}

// 双写机制确保日志既能在全局查看，也能在任务详情页单独查看。
func (w *Worker) logError(taskID, message string) {
	// 记录到全局日志系统
	logger.Error("[任务 %s] %s", taskID, message)

	// 同步写入任务专属日志；资源校验失败时 LogService 尚未初始化，需直接落库。
	if ctx, ok := w.scheduler.tasks[taskID]; ok && ctx.LogService != nil {
		ctx.LogService.Log("ERROR", message)
	} else if database.DB != nil {
		_, _ = database.DB.Exec(
			`INSERT INTO task_logs (task_id, level, stage, message, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			taskID, "ERROR", "scheduler", message, "{}", utils.GetCurrentTimeString(),
		)
		_ = service.NewTaskRuntimeService().AppendTaskLog(modelsTaskLog(taskID, "ERROR", "scheduler", message))
	}
}

// logInfo 记录信息日志，双写到全局logger和任务专属LogService。
func (w *Worker) logInfo(taskID, message string) {
	// 记录到全局日志
	logger.Info("[任务 %s] %s", taskID, message)

	// 如果有任务上下文且有LogService，也记录到任务日志
	if ctx, ok := w.scheduler.tasks[taskID]; ok && ctx.LogService != nil {
		ctx.LogService.Log("INFO", message)
	} else {
		_ = service.NewTaskRuntimeService().AppendTaskLog(modelsTaskLog(taskID, "INFO", "scheduler", message))
	}
}

// Shutdown 优雅关闭调度器。
// 取消全局context（通知所有Worker停止），关闭任务队列。
// 注意：不会等待正在执行的任务完成，仅阻止新任务被分配。
func (s *TaskScheduler) Shutdown() {
	s.cancel()
	close(s.taskQueue)
}

// parseTargets 解析用户输入的目标列表。
// 支持换行分隔（\n或\r\n），自动跳过空行和以#开头的注释行，去除首尾空白。
//
// 参数:
//   - input: 原始目标输入字符串
//
// 返回值:
//   - []string: 去重后的有效目标列表
//
// updateTaskStage updates the current stage of a task in the database
func (w *Worker) updateTaskStage(taskID, stage string) error {
	return execSchedulerDB("UPDATE task_config SET current_stage = ?, updated_at = ? WHERE task_id = ?", stage, utils.GetCurrentTimeString(), taskID)
}

func parseTargets(input string) []string {
	return utils.ParseScanTargets(input)
}

func modelsTaskLog(taskID, level, stage, message string) models.TaskLog {
	return models.TaskLog{
		TaskID:    taskID,
		Level:     level,
		Stage:     stage,
		Message:   message,
		Metadata:  "{}",
		CreatedAt: utils.GetCurrentTime(),
	}
}

// isDomain 判断目标字符串是否为域名（非IP地址、非CIDR）。
// 判断逻辑：不是合法IP则视为域名。
