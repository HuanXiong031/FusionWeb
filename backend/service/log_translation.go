package service

import (
	"regexp"
	"strings"
)

var unsignedTemplateLogPattern = regexp.MustCompile(`(?i)^Loading\s+(\d+)\s+unsigned\s+templates\s+for\s+scan\.?\s+Use\s+with\s+caution\.?$`)

// LocalizeTaskLogMessage converts common third-party scanner messages to Chinese.
// Keep the original text when there is no confident translation.
func LocalizeTaskLogMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return message
	}

	if matches := unsignedTemplateLogPattern.FindStringSubmatch(message); len(matches) == 2 {
		return "正在加载 " + matches[1] + " 个未签名模板用于扫描，请谨慎使用。"
	}

	switch strings.ToLower(message) {
	case "scan completed":
		return "扫描已完成"
	case "scan failed":
		return "扫描失败"
	case "scan cancelled":
		return "扫描已取消"
	case "scan stopped":
		return "扫描已停止"
	case "no templates provided for scan":
		return "未提供可用于扫描的模板"
	case "no results found":
		return "未发现结果"
	default:
		return message
	}
}
