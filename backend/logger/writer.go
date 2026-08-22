package logger

import (
	"io"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger/levels"
)

var ansiColorRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var logLabelRegex = regexp.MustCompile(`\[[^\]]*(?:调试|信息|警告|错误|致命|详细)[^\]]*\]\s*`)
var nucleiHTTPDumpRegex = regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d(?:\.\d)?`)
var nucleiHTTPResponseDumpRegex = regexp.MustCompile(`(?m)^HTTP/\d(?:\.\d)?\s+\d{3}`)
var nucleiFindingSummaryRegex = regexp.MustCompile(`^\[[^\]]+\]\s+(?:\[[a-z]+\]\s+)?\[(?:critical|high|medium|low|info|unknown)\]\s+\S+`)

type GologgerWriter struct {
	writer io.Writer
}

func NewGologgerWriter(writer io.Writer) *GologgerWriter {
	return &GologgerWriter{writer: writer}
}

func (w *GologgerWriter) Write(data []byte, level levels.Level) {
	cleanedData := ansiColorRegex.ReplaceAll(data, []byte{})
	cleanedData = logLabelRegex.ReplaceAll(cleanedData, []byte{})
	msg := strings.TrimSpace(string(cleanedData))
	if msg == "" {
		return
	}
	if shouldSuppressNucleiRawLog(msg) {
		return
	}

	switch level {
	case levels.LevelDebug:
		recordGologger("DEBUG", msg)
	case levels.LevelWarning:
		recordGologger("WARN", msg)
	case levels.LevelError, levels.LevelFatal:
		recordGologger("ERROR", msg)
	default:
		recordGologger("INFO", msg)
	}

	if w != nil && w.writer != nil {
		_, _ = w.writer.Write(cleanedData)
	}
}

func shouldSuppressNucleiRawLog(msg string) bool {
	trimmed := strings.TrimSpace(msg)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "Dumped HTTP request for ") || strings.Contains(trimmed, "Dumped HTTP response ") {
		return true
	}
	if nucleiHTTPDumpRegex.MatchString(trimmed) || nucleiHTTPResponseDumpRegex.MatchString(trimmed) {
		return true
	}
	return nucleiFindingSummaryRegex.MatchString(trimmed)
}
