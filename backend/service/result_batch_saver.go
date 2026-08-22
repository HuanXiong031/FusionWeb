// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现批量结果保存器，使用缓冲区+定时刷新+分批插入模式优化数据库写入性能。
//
// 设计模式：缓冲写入（Buffer-Flush）模式
//   - 内存缓冲：结果先写入内存缓冲区，减少数据库交互次数
//   - 自动刷新：每5秒定时将缓冲区数据批量写入数据库
//   - 满即刷：缓冲区达到阈值立即触发批量写入
//   - 分批插入：单次数据库写入最多500条，避免锁表
//   - 重试机制：遇到SQLITE_BUSY自动重试最多3次，递增等待时间
//   - 并发安全：使用sync.Mutex保护缓冲区操作
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	backendUtils "FusionWeb/backend/utils"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ResultBatchSaver 批量结果保存器，优化大量扫描结果的数据库写入。
// 适用于信息收集阶段产生的大量端口/URL结果，将逐条写入合并为批量操作。
//
// 字段说明:
//   - taskID: 所属任务ID
//   - resultType: 结果类型（port/url）
//   - buffer: 内存缓冲区，暂存待写入的结果
//   - bufferSize: 触发立即刷新的缓冲区阈值
//   - mu: 保护buffer的互斥锁
//   - flushTicker: 定时刷新触发器（5秒间隔）
//   - stopChan: 停止信号，关闭时触发最终刷新
//   - maxBatchSize: 单次数据库插入的最大行数
type ResultBatchSaver struct {
	taskID       string
	resultType   string
	buffer       []ResultItem
	bufferSize   int
	mu           sync.Mutex
	flushTicker  *time.Ticker
	stopChan     chan struct{}
	maxBatchSize int
}

// ResultItem 单条结果数据项，包含目标地址、来源和附加数据。
type ResultItem struct {
	Target    string
	Source    string
	ExtraData []byte
}

// NewResultBatchSaver 创建批量结果保存器并启动自动刷新协程。
// bufferSize会被限制在有效范围[1, 1000]内。
//
// 参数:
//   - taskID: 任务ID
//   - resultType: 结果类型（"port" 或 "url"）
//   - bufferSize: 缓冲区大小（1-1000），超出范围会自动调整
//
// 返回值:
//   - *ResultBatchSaver: 已初始化并启动的批量保存器
func NewResultBatchSaver(taskID, resultType string, bufferSize int) *ResultBatchSaver {
	if bufferSize <= 0 {
		bufferSize = 100 // 默认缓冲区大小
	}
	if bufferSize > 1000 {
		bufferSize = 1000 // 最大缓冲区大小，避免内存过大
	}

	saver := &ResultBatchSaver{
		taskID:       taskID,
		resultType:   resultType,
		buffer:       make([]ResultItem, 0, bufferSize),
		bufferSize:   bufferSize,
		stopChan:     make(chan struct{}),
		maxBatchSize: 500, // 每次批量插入最多500条
	}

	// 启动定时刷新（每5秒刷新一次）
	saver.flushTicker = time.NewTicker(5 * time.Second)
	go saver.autoFlush()

	return saver
}

// Add 添加一条结果到缓冲区。在加锁保护下检查结果数量限制，超出限制时先刷新。
// 缓冲区满时自动触发写入。
//
// 参数:
//   - target: 目标地址（IP:Port或URL）
//   - source: 来源描述
//   - extraData: 附加数据（JSON字节）
//
// 返回值:
//   - error: 超出结果数量限制或写入失败时返回错误
func (rbs *ResultBatchSaver) Add(target, source string, extraData []byte) error {
	rbs.mu.Lock()
	defer rbs.mu.Unlock()

	// 检查结果数量限制
	limiter := utils.GetResourceLimiter()
	if err := limiter.CheckResultLimit(len(rbs.buffer) + 1); err != nil {
		// 如果超过限制，先刷新缓冲区
		if len(rbs.buffer) > 0 {
			if flushErr := rbs.flushUnsafe(); flushErr != nil {
				logger.Error("[任务 %s] 刷新缓冲区失败: %v", rbs.taskID, flushErr)
			}
		}
		return fmt.Errorf("结果数量超过限制: %v", err)
	}

	rbs.buffer = append(rbs.buffer, ResultItem{
		Target:    target,
		Source:    source,
		ExtraData: extraData,
	})

	// 如果缓冲区满了，立即刷新
	if len(rbs.buffer) >= rbs.bufferSize {
		return rbs.flushUnsafe()
	}

	return nil
}

// Flush 手动刷新缓冲区
func (rbs *ResultBatchSaver) Flush() error {
	rbs.mu.Lock()
	defer rbs.mu.Unlock()
	return rbs.flushUnsafe()
}

// flushUnsafe 刷新缓冲区（不加锁，内部使用）
func (rbs *ResultBatchSaver) flushUnsafe() error {
	if len(rbs.buffer) == 0 {
		return nil
	}

	// 分批插入，避免单次插入过多数据
	for len(rbs.buffer) > 0 {
		batchSize := rbs.maxBatchSize
		if len(rbs.buffer) < batchSize {
			batchSize = len(rbs.buffer)
		}

		batch := rbs.buffer[:batchSize]
		rbs.buffer = rbs.buffer[batchSize:]

		if err := rbs.batchInsert(batch); err != nil {
			// 插入失败，将数据放回缓冲区
			rbs.buffer = append(batch, rbs.buffer...)
			return err
		}
	}

	return nil
}

// batchInsert 批量插入数据库
func (rbs *ResultBatchSaver) batchInsert(items []ResultItem) error {
	if len(items) == 0 {
		return nil
	}

	// 构造批量插入SQL
	valueStrings := make([]string, 0, len(items))
	valueArgs := make([]interface{}, 0, len(items)*5)

	timeStr := backendUtils.GetCurrentTimeString()

	for _, item := range items {
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?)")
		extraDataStr := ""
		if item.ExtraData != nil {
			extraDataStr = string(item.ExtraData)
		}
		valueArgs = append(valueArgs, rbs.taskID, rbs.resultType, item.Target, item.Source, extraDataStr, timeStr)
	}

	query := fmt.Sprintf(
		`INSERT INTO recon_results (task_id, result_type, target, source, extra_data, discovered_at) VALUES %s ON CONFLICT DO NOTHING`,
		strings.Join(valueStrings, ","),
	)

	// 重试机制：最多重试3次
	maxRetries := 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := database.DB.Exec(query, valueArgs...)
		if err == nil {
			return nil
		}

		lastErr = err
		errStr := err.Error()

		// 检查是否是数据库短暂冲突错误
		errStr = strings.ToLower(errStr)
		if strings.Contains(errStr, "deadlock detected") ||
			strings.Contains(errStr, "lock timeout") ||
			strings.Contains(errStr, "could not serialize access") {
			// 等待后重试
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			time.Sleep(delay)
			continue
		}

		// 其他错误直接返回
		return err
	}

	return fmt.Errorf("批量插入失败（重试%d次）: %w", maxRetries, lastErr)
}

// autoFlush 自动刷新缓冲区
func (rbs *ResultBatchSaver) autoFlush() {
	for {
		select {
		case <-rbs.flushTicker.C:
			rbs.mu.Lock()
			if len(rbs.buffer) > 0 {
				if err := rbs.flushUnsafe(); err != nil {
					logger.Warn("[任务 %s] 自动刷新缓冲区失败: %v", rbs.taskID, err)
				}
			}
			rbs.mu.Unlock()
		case <-rbs.stopChan:
			// 停止时刷新剩余数据
			rbs.mu.Lock()
			if len(rbs.buffer) > 0 {
				if err := rbs.flushUnsafe(); err != nil {
					logger.Error("[任务 %s] 停止时刷新缓冲区失败: %v", rbs.taskID, err)
				}
			}
			rbs.mu.Unlock()
			return
		}
	}
}

// Close 关闭批量保存器
func (rbs *ResultBatchSaver) Close() error {
	rbs.flushTicker.Stop()
	close(rbs.stopChan)
	return rbs.Flush()
}
