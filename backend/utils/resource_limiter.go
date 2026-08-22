// backend/utils/resource_limiter.go
// 资源限制器模块
// 提供全局资源监控与限制功能，防止扫描任务过度消耗系统资源。
// 设计要点：
// - 单例模式（sync.Once）保证全局唯一的限制器实例
// - 支持内存、目标数量、结果数量、并发任务数四个维度的限制
// - 使用读写锁（sync.RWMutex）保护并发访问
// - 内置后台协程定期监控内存使用，超阈值自动触发 GC
// - 所有限制参数均可运行时动态调整
package utils

import (
	"FusionWeb/backend/logger"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// ResourceLimiter 资源限制器
// 全局单例对象，负责监控和限制扫描任务的资源使用。
// 包含四个维度的限制：
//   - maxMemoryMB: 内存上限（MB），超过80%触发告警与GC
//   - maxTargets: 单次任务目标数量上限
//   - maxResultsPerTask: 单任务结果数量上限，防止数据过多
//   - maxConcurrentTasks: 最大并发任务数，防止任务堆积
type ResourceLimiter struct {
	// 内存限制（MB）
	maxMemoryMB int64
	// 目标数量限制
	maxTargets int
	// 结果数量限制（单任务）
	maxResultsPerTask int
	// 并发任务限制
	maxConcurrentTasks int
	// 当前内存使用（MB）
	currentMemoryMB int64
	// 当前并发任务数
	currentConcurrentTasks int
	mu                     sync.RWMutex
}

var (
	globalLimiter *ResourceLimiter
	limiterOnce   sync.Once
)

// GetResourceLimiter 获取全局资源限制器实例（单例模式）
// 首次调用时初始化默认限制参数，后续调用返回同一实例。
// 默认值：4GB内存、10000目标、100000结果/任务、20并发任务
func GetResourceLimiter() *ResourceLimiter {
	limiterOnce.Do(func() {
		globalLimiter = &ResourceLimiter{
			maxMemoryMB:        4096,   // 默认4GB内存限制
			maxTargets:         10000,  // 默认最多10000个目标
			maxResultsPerTask:  100000, // 默认单任务最多10万条结果
			maxConcurrentTasks: 20,     // 默认最多20个并发任务
		}
	})
	return globalLimiter
}

// CheckMemoryUsage 检查内存使用情况
// 参数：无
// 返回值：
//   - usedMB: 当前内存使用量（MB）
//   - limitMB: 内存上限（MB）
//   - ok: 是否在安全阈值内（低于80%），超过时返回false并记录警告日志
func (rl *ResourceLimiter) CheckMemoryUsage() (usedMB int64, limitMB int64, ok bool) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	usedMB = int64(m.Alloc / 1024 / 1024) // 转换为MB
	limitMB = rl.maxMemoryMB

	// 如果内存使用超过80%，返回警告
	if usedMB > limitMB*80/100 {
		logger.Warn("内存使用率超过80%%: %dMB / %dMB", usedMB, limitMB)
		return usedMB, limitMB, false
	}

	return usedMB, limitMB, true
}

// CheckTargetLimit 检查目标数量是否超限
// 参数：targetCount - 要检查的目标数量
// 返回值：如果超过限制则返回错误，否则返回nil
func (rl *ResourceLimiter) CheckTargetLimit(targetCount int) error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if targetCount > rl.maxTargets {
		return fmt.Errorf("目标数量超过限制: %d > %d", targetCount, rl.maxTargets)
	}

	return nil
}

// CheckResultLimit 检查结果数量是否超限
// 参数：resultCount - 要检查的结果数量
// 返回值：如果超过限制则返回错误，否则返回nil
func (rl *ResourceLimiter) CheckResultLimit(resultCount int) error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if resultCount > rl.maxResultsPerTask {
		return fmt.Errorf("结果数量超过限制: %d > %d", resultCount, rl.maxResultsPerTask)
	}

	return nil
}

// IncrementConcurrentTasks 增加并发任务计数（原子检查+递增）
// 返回值：true表示允许执行新任务（未达上限），false表示已达并发上限
// 调用方应在成功时递增，任务完成时调用 DecrementConcurrentTasks 递减
func (rl *ResourceLimiter) IncrementConcurrentTasks() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.currentConcurrentTasks >= rl.maxConcurrentTasks {
		return false
	}

	rl.currentConcurrentTasks++
	return true
}

// DecrementConcurrentTasks 减少并发任务计数
// 任务完成或取消时必须调用此方法，以释放并发槽位
func (rl *ResourceLimiter) DecrementConcurrentTasks() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.currentConcurrentTasks > 0 {
		rl.currentConcurrentTasks--
	}
}

// GetCurrentConcurrentTasks 获取当前并发任务数
// 返回值：当前正在执行的任务数量
func (rl *ResourceLimiter) GetCurrentConcurrentTasks() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.currentConcurrentTasks
}

// SetMaxMemoryMB 设置最大内存限制（MB）
// 参数：mb - 内存上限，单位MB
// 支持运行时动态调整，无需重启
func (rl *ResourceLimiter) SetMaxMemoryMB(mb int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxMemoryMB = mb
}

// SetMaxTargets 设置最大目标数量
// 参数：count - 单任务允许的最大目标数量
func (rl *ResourceLimiter) SetMaxTargets(count int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxTargets = count
}

// SetMaxResultsPerTask 设置单任务最大结果数量
// 参数：count - 单任务允许的最大结果条数
func (rl *ResourceLimiter) SetMaxResultsPerTask(count int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxResultsPerTask = count
}

// SetMaxConcurrentTasks 设置最大并发任务数
// 参数：count - 允许同时运行的最大任务数量
func (rl *ResourceLimiter) SetMaxConcurrentTasks(count int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxConcurrentTasks = count
}

// StartMemoryMonitor 启动内存监控（后台协程定期检查内存使用）
// 参数：interval - 检查间隔，建议 30s-60s
// 启动一个后台 goroutine，定期检查内存使用率。
// 当内存使用超过 80% 时，自动触发 runtime.GC() 进行垃圾回收。
func (rl *ResourceLimiter) StartMemoryMonitor(interval time.Duration) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("resource limiter monitor panic: %v", r)
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			usedMB, limitMB, ok := rl.CheckMemoryUsage()
			if !ok {
				// 内存使用过高，触发GC
				logger.Warn("内存使用率过高，触发GC: %dMB / %dMB", usedMB, limitMB)
				runtime.GC()
			}
		}
	}()
}
