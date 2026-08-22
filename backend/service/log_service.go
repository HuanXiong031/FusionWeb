// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现任务日志服务，包括任务级 writer、缓冲写入、文件存储和查询功能。
//
// 设计模式:
//   - 任务 writer：调用方显式传入 LogWriter，避免多个任务抢全局 gologger writer
//   - 缓冲写入模式：日志先存入内存缓冲区，定时或满阈值时批量写入文件
//   - 去重过滤：3秒内重复的[http]日志自动跳过，减少冗余输出
//   - 双写机制：日志同时写入专属文件（BOM标记UTF-8编码）和通过WebSocket实时推送
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger/levels"
)

// LogService 任务日志服务，管理单个任务的日志采集、存储和查询。
// 每个任务拥有独立的LogService实例和专属日志文件。
//
// 字段说明:
//   - taskID: 所属任务ID
//   - logBuffer: 内存日志缓冲区（容量100条）
//   - flushTicker: 定时刷新触发器（5秒间隔）
//   - lastMessage/lastNormalized/lastTime: 用于日志去重过滤
//   - logFile: 任务专属日志文件句柄（UTF-8 BOM编码）
type LogService struct {
	taskID         string
	db             *sql.DB
	logBuffer      []models.TaskLog
	bufferMutex    sync.Mutex
	bufferSize     int
	flushTicker    *time.Ticker
	stopChan       chan struct{}
	lastMessage    string
	lastNormalized string
	lastTime       time.Time
	interceptor    *LogWriter
	startOnce      sync.Once
	stopOnce       sync.Once
}

// LogWriter gologger输出拦截器，实现gologger.Writer接口。
// 将Nuclei等第三方工具的日志输出拦截并转发到LogService进行统一管理。
type LogWriter struct {
	service *LogService
}

// NewLogService 创建任务日志服务实例，初始化日志目录和专属日志文件。
// 日志文件位于 {exeDir}/logs/tasks/{taskID}.log，首次创建时写入UTF-8 BOM标记。
//
// 参数:
//   - taskID: 任务ID，用于命名日志文件
//   - db: 数据库连接（保留参数，task_logs表已废弃）
//
// 返回值:
//   - *LogService: 已初始化的日志服务实例
func NewLogService(taskID string, db *sql.DB) *LogService {
	return &LogService{
		taskID:      taskID,
		db:          db,
		logBuffer:   make([]models.TaskLog, 0),
		bufferSize:  100, // 缓冲区大小：100条日志批量写入
		flushTicker: time.NewTicker(5 * time.Second),
		stopChan:    make(chan struct{}),
	}
}

// StartInterceptor 返回当前任务的 gologger writer，并确保 flush loop 只启动一次。
func (s *LogService) StartInterceptor() *LogWriter {
	s.startOnce.Do(func() {
		s.interceptor = &LogWriter{service: s}
		go s.flushLoop()
	})
	return s.interceptor
}

// Write 实现gologger Writer接口，拦截日志输出
func (lw *LogWriter) Write(p []byte, level levels.Level) {
	// 解析日志内容
	logLine := string(p)
	logLevel, message := lw.parseLogLine(logLine)

	// 如果解析不出级别，使用传入的level参数
	if logLevel == "INFO" && level != levels.LevelInfo {
		switch level {
		case levels.LevelDebug:
			logLevel = "DEBUG"
		case levels.LevelWarning:
			logLevel = "WARNING"
		case levels.LevelError:
			logLevel = "ERROR"
		case levels.LevelSilent:
			logLevel = "INFO"
		}
	}

	// 创建日志记录
	log := models.TaskLog{
		TaskID:    lw.service.taskID,
		Level:     logLevel,
		Message:   LocalizeTaskLogMessage(message),
		CreatedAt: utils.GetCurrentTime(),
	}

	normalized := strings.TrimSpace(strings.ReplaceAll(log.Message, "[http]", ""))
	now := time.Now()
	skip := false
	if strings.Contains(log.Message, "[http]") && lw.service.lastNormalized == normalized && now.Sub(lw.service.lastTime) < 3*time.Second {
		skip = true
	}
	if !skip && lw.service.lastMessage == log.Message && now.Sub(lw.service.lastTime) < 3*time.Second {
		skip = true
	}
	if skip {
		return
	}
	lw.service.lastMessage = log.Message
	lw.service.lastNormalized = normalized
	lw.service.lastTime = now

	// 添加到缓冲区
	lw.service.addToBuffer(log)

	_ = NewTaskRuntimeService().AppendTaskLog(log)

	// 同时推送到WebSocket
	websocket.BroadcastLog(lw.service.taskID, logLevel, log.Message)
}

// Log 手动记录日志
func (s *LogService) Log(level, message string) {
	// 规范化级别
	level = strings.ToUpper(level)
	if level == "" {
		level = "INFO"
	}

	// 创建日志记录
	log := models.TaskLog{
		TaskID:    s.taskID,
		Level:     level,
		Message:   LocalizeTaskLogMessage(message),
		CreatedAt: utils.GetCurrentTime(),
	}

	// 添加到缓冲区
	s.addToBuffer(log)

	_ = NewTaskRuntimeService().AppendTaskLog(log)

	// 推送到WebSocket
	websocket.BroadcastLog(s.taskID, level, log.Message)
}

// parseLogLine 解析日志行，提取级别和消息
// 支持格式: [INF] message, [WRN] message, [ERR] message, [DBG] message, [SUC] message
func (lw *LogWriter) parseLogLine(line string) (level string, message string) {
	line = strings.TrimSpace(line)

	// 默认级别为INFO
	level = "INFO"
	message = line

	// 尝试从ANSI颜色代码中提取级别
	if strings.Contains(line, "[INF]") {
		level = "INFO"
		message = strings.SplitN(line, "[INF]", 2)[1]
	} else if strings.Contains(line, "[WRN]") {
		level = "WARNING"
		message = strings.SplitN(line, "[WRN]", 2)[1]
	} else if strings.Contains(line, "[ERR]") {
		level = "ERROR"
		message = strings.SplitN(line, "[ERR]", 2)[1]
	} else if strings.Contains(line, "[DBG]") {
		level = "DEBUG"
		message = strings.SplitN(line, "[DBG]", 2)[1]
	} else if strings.Contains(line, "[SUC]") || strings.Contains(line, "[✓]") {
		level = "SUCCESS"
		message = strings.SplitN(line, "[SUC]", 2)[1]
		if len(message) == 0 {
			message = strings.SplitN(line, "[✓]", 2)[1]
		}
	}

	// 移除ANSI颜色代码
	message = removeANSICodes(message)
	message = strings.TrimSpace(message)

	return level, message
}

// removeANSICodes 移除ANSI颜色代码
func removeANSICodes(s string) string {
	// 简单实现：移除常见的ANSI转义序列
	s = strings.ReplaceAll(s, "\x1b[0m", "")
	s = strings.ReplaceAll(s, "\x1b[1m", "")
	s = strings.ReplaceAll(s, "\x1b[31m", "")
	s = strings.ReplaceAll(s, "\x1b[32m", "")
	s = strings.ReplaceAll(s, "\x1b[33m", "")
	s = strings.ReplaceAll(s, "\x1b[34m", "")
	s = strings.ReplaceAll(s, "\x1b[35m", "")
	s = strings.ReplaceAll(s, "\x1b[36m", "")
	s = strings.ReplaceAll(s, "\x1b[37m", "")

	// 移除通用格式: \x1b[XXm
	for {
		start := strings.Index(s, "\x1b[")
		if start == -1 {
			break
		}
		end := strings.Index(s[start:], "m")
		if end == -1 {
			break
		}
		s = s[:start] + s[start+end+1:]
	}

	return s
}

// addToBuffer 添加日志到缓冲区（线程安全）
func (s *LogService) addToBuffer(log models.TaskLog) {
	s.bufferMutex.Lock()
	defer s.bufferMutex.Unlock()

	s.logBuffer = append(s.logBuffer, log)

	// 缓冲区满时立即刷新
	if len(s.logBuffer) >= s.bufferSize {
		s.flushBufferUnsafe()
	}
}

// flushLoop 定时刷新缓冲区
func (s *LogService) flushLoop() {
	for {
		select {
		case <-s.flushTicker.C:
			s.flushBuffer()
		case <-s.stopChan:
			// 停止前最后一次刷新
			s.flushBuffer()
			return
		}
	}
}

// flushBuffer 刷新缓冲区到数据库（线程安全）
func (s *LogService) flushBuffer() {
	s.bufferMutex.Lock()
	defer s.bufferMutex.Unlock()

	s.flushBufferUnsafe()
}

// flushBufferUnsafe 刷新缓冲区（不加锁，内部使用）
//
// 功能说明：
//
//	将缓冲区中的日志批量插入到数据库。
//	如果插入失败（特别是数据库短暂冲突错误），会保留日志在缓冲区中，等待下次重试。
//	这样可以避免日志丢失，但如果缓冲区过大（超过阈值），仍然会清空以避免内存溢出。
func (s *LogService) flushBufferUnsafe() {
	if len(s.logBuffer) == 0 {
		return
	}

	// 复制缓冲区内容，避免在插入过程中被修改
	logsToInsert := make([]models.TaskLog, len(s.logBuffer))
	copy(logsToInsert, s.logBuffer)

	// 批量插入
	err := s.batchInsertLogs(logsToInsert)
	if err != nil {
		// 检查是否是数据库短暂冲突错误
		errStr := strings.ToLower(err.Error())
		isLocked := strings.Contains(errStr, "deadlock detected") ||
			strings.Contains(errStr, "lock timeout") ||
			strings.Contains(errStr, "could not serialize access")

		// 如果是短暂冲突错误且缓冲区未过大，保留日志以便下次重试
		if isLocked && len(s.logBuffer) <= s.bufferSize*10 {
			logger.Warn("[任务 %s] 批量插入日志失败（数据库短暂冲突），保留在缓冲区等待下次重试: %v", s.taskID, err)
			return // 不清空缓冲区，等待下次重试
		}

		// 非锁定错误或缓冲区过大，清空缓冲区
		if len(s.logBuffer) > s.bufferSize*10 {
			logger.Warn("[任务 %s] 批量插入日志失败且缓冲区过大（%d 条），清空缓冲区: %v", s.taskID, len(s.logBuffer), err)
		} else {
			logger.Warn("[任务 %s] 批量插入日志失败（非锁定错误），清空缓冲区: %v", s.taskID, err)
		}
		// 清空缓冲区，避免无限增长
		s.logBuffer = make([]models.TaskLog, 0)
		return
	}

	// 插入成功，清空缓冲区
	s.logBuffer = make([]models.TaskLog, 0)
}

func (s *LogService) batchInsertLogs(logs []models.TaskLog) error {
	if s.db == nil {
		s.db = database.DB
	}
	if s.db == nil {
		return fmt.Errorf("数据库未初始化")
	}
	if len(logs) == 0 {
		return nil
	}

	valueStrings := make([]string, 0, len(logs))
	valueArgs := make([]interface{}, 0, len(logs)*5)
	for _, log := range logs {
		createdAt := log.CreatedAt
		if createdAt.IsZero() {
			createdAt = utils.GetCurrentTime()
		}
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?)")
		valueArgs = append(valueArgs, s.taskID, logLevelOrDefault(log.Level), log.Message, log.Stage, log.Metadata, utils.FormatTimeForDisplay(createdAt))
	}

	query := fmt.Sprintf(
		`INSERT INTO task_logs (task_id, level, message, stage, metadata, created_at) VALUES %s`,
		strings.Join(valueStrings, ","),
	)

	_, err := s.db.Exec(query, valueArgs...)
	return err
}

// Stop 停止日志服务
func (s *LogService) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopChan)
		s.flushTicker.Stop()
		s.flushBuffer()
	})
}

// GetLogFilePath 获取日志文件路径
// QueryLogs 查询任务日志
// 直接从数据库读取
func (s *LogService) QueryLogs(level string, keyword string, page int, pageSize int) ([]models.TaskLog, int, error) {
	if s.db == nil {
		s.db = database.DB
	}
	if s.db == nil {
		return []models.TaskLog{}, 0, fmt.Errorf("数据库未初始化")
	}

	whereClause := "task_id = ?"
	args := []interface{}{s.taskID}
	if level != "" {
		whereClause += " AND level = ?"
		args = append(args, strings.ToUpper(strings.TrimSpace(level)))
	}
	if keyword != "" {
		whereClause += " AND message LIKE ?"
		args = append(args, "%"+keyword+"%")
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM task_logs WHERE " + whereClause
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	query := "SELECT id, task_id, level, stage, message, metadata, CAST(created_at AS TEXT) FROM task_logs WHERE " + whereClause + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var matchedLogs []models.TaskLog
	for rows.Next() {
		var log models.TaskLog
		var createdAt sql.NullString
		if err := rows.Scan(&log.ID, &log.TaskID, &log.Level, &log.Stage, &log.Message, &log.Metadata, &createdAt); err != nil {
			continue
		}
		log.Message = LocalizeTaskLogMessage(log.Message)
		log.CreatedAt = utils.ParseTimeStringForDisplay(createdAt)
		matchedLogs = append(matchedLogs, log)
	}

	return matchedLogs, total, nil
}

// ExportLogs 导出日志为TXT文件
func (s *LogService) ExportLogs(outputPath string) error {
	logs, _, err := s.QueryLogs("", "", 1, 1000000)
	if err != nil {
		return err
	}
	var builder strings.Builder
	for _, log := range logs {
		builder.WriteString(fmt.Sprintf("[%s] [%s] %s\n", utils.FormatTimeForDisplay(log.CreatedAt), log.Level, log.Message))
	}
	return os.WriteFile(outputPath, []byte(builder.String()), 0644)
}

// GetLogStatistics 获取日志统计信息
func (s *LogService) GetLogStatistics() (map[string]int, error) {
	if s.db == nil {
		s.db = database.DB
	}
	if s.db == nil {
		return map[string]int{}, fmt.Errorf("数据库未初始化")
	}
	stats := map[string]int{
		"total":   0,
		"error":   0,
		"warning": 0,
	}
	var total, errorCount, warningCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM task_logs WHERE task_id = ?", s.taskID).Scan(&total)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM task_logs WHERE task_id = ? AND level = 'ERROR'", s.taskID).Scan(&errorCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM task_logs WHERE task_id = ? AND level = 'WARNING'", s.taskID).Scan(&warningCount)
	stats["total"] = total
	stats["error"] = errorCount
	stats["warning"] = warningCount
	return stats, nil
}

func logLevelOrDefault(level string) string {
	level = strings.TrimSpace(strings.ToUpper(level))
	if level == "" {
		return "INFO"
	}
	return level
}
