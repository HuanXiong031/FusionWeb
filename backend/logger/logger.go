package logger

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var LogWriter io.Writer = io.Discard
var GologWriter *GologgerWriter

type logEntry struct {
	Level     string
	Message   string
	Module    string
	Source    string
	Metadata  string
	CreatedAt time.Time
}

type taskLogMatch struct {
	TaskID  string
	Stage   string
	Message string
}

var (
	mu            sync.Mutex
	attachedDB    *sql.DB
	pendingLogs   []logEntry
	consoleOutput = true
	taskLogRegex  = regexp.MustCompile(`^\[任务\s+([^\]]+)\]\s+\[([^\]]+)\]\s*(.*)$`)
)

// InitLogger 初始化日志系统。
// 当前版本不再创建 .log 文件，所有日志统一进入数据库。
func InitLogger() error {
	LogWriter = io.Discard
	log.SetFlags(0)
	log.SetOutput(stdLogWriter{})
	if GologWriter == nil {
		GologWriter = NewGologgerWriter(nil)
	}
	return nil
}

// AttachDatabase 绑定数据库并回填启动期间的缓冲日志。
func AttachDatabase(db *sql.DB) {
	mu.Lock()
	attachedDB = db
	queued := append([]logEntry(nil), pendingLogs...)
	pendingLogs = pendingLogs[:0]
	mu.Unlock()

	for _, entry := range queued {
		_ = writeEntry(db, entry)
	}
}

// EnableConsoleOutput 保持向后兼容。
func EnableConsoleOutput() {
	consoleOutput = true
}

// CloseLogger 保持向后兼容。
func CloseLogger() {}

func Debug(format string, v ...interface{}) {
	recordSimple("DEBUG", fmt.Sprintf(format, v...))
}

func Info(format string, v ...interface{}) {
	recordSimple("INFO", fmt.Sprintf(format, v...))
}

func Warn(format string, v ...interface{}) {
	recordSimple("WARN", fmt.Sprintf(format, v...))
}

func Error(format string, v ...interface{}) {
	recordSimple("ERROR", fmt.Sprintf(format, v...))
}

func InfoStructured(msg string, args ...any) {
	recordStructured("INFO", msg, args...)
}

func ErrorStructured(msg string, args ...any) {
	recordStructured("ERROR", msg, args...)
}

func WarnStructured(msg string, args ...any) {
	recordStructured("WARN", msg, args...)
}

func DebugStructured(msg string, args ...any) {
	recordStructured("DEBUG", msg, args...)
}

func With(args ...any) *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil)).With(args...)
}

// InfoToFileOnly 旧接口：现在只是不输出到控制台，依然写入数据库。
func InfoToFileOnly(format string, v ...interface{}) {
	recordEntry(logEntry{
		Level:     "INFO",
		Message:   fmt.Sprintf(format, v...),
		CreatedAt: loggerChinaTime(),
		Source:    callerSource(2),
	}, false)
}

func recordSimple(level, message string) {
	recordEntry(logEntry{
		Level:     normalizeLevel(level),
		Message:   strings.TrimSpace(message),
		CreatedAt: loggerChinaTime(),
		Source:    callerSource(2),
	}, true)
}

func recordStructured(level, message string, args ...any) {
	recordEntry(logEntry{
		Level:     normalizeLevel(level),
		Message:   strings.TrimSpace(message),
		CreatedAt: loggerChinaTime(),
		Source:    callerSource(2),
		Metadata:  metadataFromArgs(args...),
	}, true)
}

func recordGologger(level string, message string) {
	recordEntry(logEntry{
		Level:     normalizeLevel(level),
		Message:   strings.TrimSpace(message),
		CreatedAt: loggerChinaTime(),
		Source:    "gologger",
	}, true)
}

func recordStdLog(message string) {
	level := "INFO"
	lower := strings.ToLower(message)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(message, "错误") {
		level = "ERROR"
	} else if strings.Contains(lower, "warn") || strings.Contains(message, "警告") {
		level = "WARN"
	}
	recordEntry(logEntry{
		Level:     level,
		Message:   strings.TrimSpace(message),
		CreatedAt: loggerChinaTime(),
		Source:    "stdlog",
	}, true)
}

func recordEntry(entry logEntry, echo bool) {
	entry.Level = normalizeLevel(entry.Level)
	entry.Message = strings.TrimSpace(entry.Message)
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = loggerChinaTime()
	}

	if echo && consoleOutput {
		if entry.Metadata != "" {
			fmt.Fprintf(os.Stdout, "[%s] %s %s\n", entry.Level, entry.Message, entry.Metadata)
		} else {
			fmt.Fprintf(os.Stdout, "[%s] %s\n", entry.Level, entry.Message)
		}
	}

	mu.Lock()
	db := attachedDB
	queued := pendingLogs
	pendingLogs = nil
	if db == nil {
		pendingLogs = append(pendingLogs, entry)
		mu.Unlock()
		return
	}
	mu.Unlock()

	if len(queued) > 0 {
		for _, pending := range queued {
			if err := writeEntry(db, pending); err != nil {
				mu.Lock()
				pendingLogs = append(pendingLogs, pending)
				mu.Unlock()
			}
		}
	}

	if err := writeEntry(db, entry); err != nil {
		mu.Lock()
		pendingLogs = append(pendingLogs, entry)
		mu.Unlock()
	}
}

func writeEntry(db *sql.DB, entry logEntry) error {
	if db == nil {
		return fmt.Errorf("database not attached")
	}

	createdAt := entry.CreatedAt.Format("2006-01-02 15:04:05")
	metadata := entry.Metadata
	if metadata == "" {
		metadata = ""
	}

	if task, ok := parseTaskLog(entry.Message); ok {
		_, _ = db.Exec(
			`INSERT INTO task_logs (task_id, level, stage, message, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			task.TaskID, entry.Level, task.Stage, task.Message, metadata, createdAt,
		)
	}

	return nil
}

func loggerChinaTime() time.Time {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.FixedZone("CST", 8*3600)
	}
	return time.Now().In(loc)
}

func metadataFromArgs(args ...any) string {
	if len(args) == 0 {
		return ""
	}
	if len(args)%2 == 0 {
		m := make(map[string]any, len(args)/2)
		for i := 0; i < len(args); i += 2 {
			key, ok := args[i].(string)
			if !ok || key == "" {
				key = fmt.Sprintf("arg_%d", i/2)
			}
			m[key] = args[i+1]
		}
		if data, err := json.Marshal(m); err == nil {
			return string(data)
		}
	}
	if data, err := json.Marshal(args); err == nil {
		return string(data)
	}
	return fmt.Sprint(args...)
}

func normalizeLevel(level string) string {
	level = strings.TrimSpace(strings.ToUpper(level))
	if level == "" {
		return "INFO"
	}
	return level
}

func callerSource(skip int) string {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return ""
	}
	fn := runtime.FuncForPC(pc)
	fnName := ""
	if fn != nil {
		fnName = fn.Name()
	}
	if fnName != "" {
		return fmt.Sprintf("%s:%d %s", file, line, fnName)
	}
	return fmt.Sprintf("%s:%d", file, line)
}

type stdLogWriter struct{}

func (stdLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}
	recordStdLog(msg)
	return len(p), nil
}

func parseTaskLog(message string) (*taskLogMatch, bool) {
	matches := taskLogRegex.FindStringSubmatch(strings.TrimSpace(message))
	if len(matches) != 4 {
		return nil, false
	}
	return &taskLogMatch{
		TaskID:  matches[1],
		Stage:   matches[2],
		Message: strings.TrimSpace(matches[3]),
	}, true
}
