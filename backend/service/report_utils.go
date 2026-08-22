package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/common"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
)

// ============================================================================
// 报告工具函数 - 被 HTML/Excel/MD 生成器共用
// ============================================================================

// formatTime 格式化时间为报告显示格式（委托到 utils/timeutil）
func formatTime(t time.Time) string {
	result := utils.FormatTimeForDisplay(t)
	if result == "未完成" {
		return "-"
	}
	return result
}

// formatTimeString 格式化时间字符串（委托到 utils/timeutil）
func formatTimeString(timeStr string) string {
	result := utils.FormatTimeStringForDisplay(timeStr)
	if result == "未完成" {
		return "-"
	}
	return result
}

// formatPacket 格式化 HTTP 报文内容，缩进处理
func formatPacket(packet string) string {
	if packet == "" {
		return ""
	}
	return strings.TrimSpace(packet)
}

// formatHttpContentForHTML 格式化 HTTP 内容用于 HTML 显示
func formatHttpContentForHTML(content string) string {
	content = normalizeHTTPPacket(content)
	if content == "" {
		content = "暂无数据包"
	}

	var html strings.Builder
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		html.WriteString(fmt.Sprintf(
			`<div class="code-line"><span class="line-number">%d</span><span class="line-content">%s</span></div>`,
			i+1,
			escapeHTML(line),
		))
	}
	return html.String()
}

func normalizeHTTPPacket(content string) string {
	content = strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	content = strings.ReplaceAll(content, "\r", "\n")
	if content == "" || strings.Contains(content, "\n") {
		return content
	}

	// 兼容历史报告数据：旧版 HTML 会把原始报文作为普通 div 输出，
	// 浏览器折叠空白后看起来像一整行。这里尽量按 HTTP 头字段切回多行。
	headerNames := []string{
		"Host:",
		"User-Agent:",
		"Connection:",
		"Content-Length:",
		"Content-Type:",
		"Accept:",
		"Accept-Language:",
		"Accept-Encoding:",
		"Authorization:",
		"Cookie:",
		"Referer:",
		"Origin:",
		"Date:",
		"Server:",
		"Set-Cookie:",
		"Cache-Control:",
		"Pragma:",
		"Expires:",
		"Transfer-Encoding:",
		"Location:",
		"Strict-Transport-Security:",
		"X-Content-Type-Options:",
		"X-Xss-Protection:",
	}

	for _, header := range headerNames {
		content = strings.ReplaceAll(content, " "+header, "\n"+header)
	}
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		content = strings.ReplaceAll(content, " "+method, "\n"+method)
	}
	content = strings.ReplaceAll(content, " <?xml", "\n\n<?xml")
	content = strings.ReplaceAll(content, " {", "\n\n{")
	content = strings.ReplaceAll(content, " [", "\n\n[")
	return strings.TrimSpace(content)
}

// formatTargetDisplay 格式化目标显示（处理多行目标）
func formatTargetDisplay(target string) string {
	if target == "" {
		return ""
	}
	return escapeHTML(target)
}

// escapeHTML HTML 转义
func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// escapeXML XML 转义
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// ConvertResultToNucleiFormat 将漏洞结果转为 Nuclei 格式
func ConvertResultToNucleiFormat(vuln VulnSummary) map[string]interface{} {
	result := make(map[string]interface{})
	result["template-id"] = vuln.TemplateID
	result["name"] = vuln.Name
	result["severity"] = vuln.Severity
	result["description"] = vuln.Description
	result["host"] = vuln.Target
	result["matcher-name"] = vuln.MatcherName
	result["request"] = vuln.Request
	result["response"] = vuln.Response
	result["author"] = vuln.Author
	result["tags"] = vuln.Tags
	return result
}

// saveReportMetadata 保存报告元数据到数据库
func (s *ReportService) saveReportMetadata(reportType, filePath string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库连接不可用")
	}
	_, err := database.DB.Exec(
		"INSERT INTO report_metadata (task_id, report_type, file_path, generated_at) VALUES (?, ?, ?, ?)",
		s.taskID, reportType, filePath, utils.GetCurrentTimeString(),
	)
	return err
}

// GetReportList 获取指定任务的报告列表
func (s *ReportService) GetReportList() ([]models.ReportMetadata, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库连接不可用")
	}
	var reports []models.ReportMetadata
	rows, err := database.DB.Query(
		"SELECT id, task_id, report_type, file_path, CAST(generated_at AS TEXT) FROM report_metadata WHERE task_id = ? ORDER BY generated_at DESC",
		s.taskID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r models.ReportMetadata
		var generatedAt sql.NullString
		if err := rows.Scan(&r.ID, &r.TaskID, &r.ReportType, &r.FilePath, &generatedAt); err != nil {
			continue
		}
		r.GeneratedAt = utils.ParseTimeStringForDisplay(generatedAt)
		reports = append(reports, r)
	}
	return reports, nil
}

// getStatistics 获取统计数据
func (s *ReportService) getStatistics() (*Statistics, error) {
	stats := &Statistics{}

	if database.DB == nil {
		return stats, nil
	}

	var db *sql.DB = database.DB

	// 根据任务类型查询不同表
	if s.isPocTask {
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ?", s.taskID).Scan(&stats.VulnCount)
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND severity = 'critical'", s.taskID).Scan(&stats.CriticalCount)
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND severity = 'high'", s.taskID).Scan(&stats.HighCount)
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND severity = 'medium'", s.taskID).Scan(&stats.MediumCount)
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND severity = 'low'", s.taskID).Scan(&stats.LowCount)
		db.QueryRow("SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND severity = 'info'", s.taskID).Scan(&stats.InfoCount)
	} else {
		db.QueryRow("SELECT COUNT(DISTINCT port) FROM recon_results WHERE task_id = ?", s.taskID).Scan(&stats.PortCount)
		db.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'url'", s.taskID).Scan(&stats.URLCount)
		db.QueryRow("SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ?", s.taskID).Scan(&stats.FingerprintCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ?", s.taskID).Scan(&stats.VulnCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND severity = 'critical'", s.taskID).Scan(&stats.CriticalCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND severity = 'high'", s.taskID).Scan(&stats.HighCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND severity = 'medium'", s.taskID).Scan(&stats.MediumCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND severity = 'low'", s.taskID).Scan(&stats.LowCount)
		db.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND severity = 'info'", s.taskID).Scan(&stats.InfoCount)
	}

	return stats, nil
}

// getReconResults 获取信息收集结果
func (r *ReconSummary) applyReconExtra(extraDataStr string) {
	if strings.TrimSpace(extraDataStr) == "" {
		return
	}
	var extra map[string]interface{}
	if err := json.Unmarshal([]byte(extraDataStr), &extra); err != nil {
		return
	}
	switch r.Type {
	case "port":
		r.Host = reportStringFromExtra(extra, "host")
		if r.Host == "" {
			r.Host = reportStringFromExtra(extra, "ip")
		}
		r.Port = reportStringFromExtra(extra, "port")
		r.Protocol = reportStringFromExtra(extra, "protocol")
		r.Service = reportStringFromExtra(extra, "service")
		if r.Service == "" || strings.EqualFold(r.Service, "tcp") {
			r.Service = reportPortGuess(r.Port)
		}
		r.Status = reportStringFromExtra(extra, "status")
		r.Banner = reportStringFromExtra(extra, "banner")
	case "url":
		r.StatusCode = reportStringFromExtra(extra, "status_code")
		r.Title = reportStringFromExtra(extra, "title")
		r.Length = reportStringFromExtra(extra, "length")
	}
}

func (s *ReportService) loadReportPortTargetSchemes() map[string]string {
	rows, err := database.DB.Query(`SELECT target, extra_data FROM recon_results WHERE task_id = ? AND result_type = 'port'`, s.taskID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	schemes := make(map[string]string)
	for rows.Next() {
		var target, extraDataStr string
		if err := rows.Scan(&target, &extraDataStr); err != nil {
			continue
		}
		host, port := splitReportHostPortText(target)
		if host == "" || port == "" {
			continue
		}
		var extra map[string]interface{}
		_ = json.Unmarshal([]byte(extraDataStr), &extra)
		protocol := reportStringFromExtra(extra, "protocol")
		service := reportDetectedService(extra)
		schemes[net.JoinHostPort(host, port)] = reportProtocolScheme(protocol, service)
	}
	return schemes
}

func normalizeReportReconURL(raw string, portSchemes map[string]string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return raw
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" || port == "" {
		return raw
	}
	key := net.JoinHostPort(host, port)
	if scheme, ok := portSchemes[key]; ok {
		if scheme == "" {
			return key
		}
		parsed.Scheme = scheme
		parsed.Host = key
		parsed.Path = ""
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	return raw
}

func reportDetectedService(extra map[string]interface{}) string {
	service := reportStringFromExtra(extra, "detected_service")
	if service != "" {
		return service
	}
	if _, hasGuess := extra["guessed_service"]; hasGuess {
		return ""
	}
	service = reportStringFromExtra(extra, "service")
	if strings.EqualFold(service, "tcp") {
		return ""
	}
	return service
}

func reportProtocolScheme(protocol, service string) string {
	for _, candidate := range []string{protocol, service} {
		scheme := reportNormalizeScheme(candidate)
		if scheme != "" && scheme != "tcp" {
			return scheme
		}
	}
	return ""
}

func reportNormalizeScheme(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	value = strings.Split(value, " ")[0]
	value = strings.Trim(value, "/")
	switch value {
	case "ssl/http", "https-alt":
		return "https"
	case "http-alt", "http-proxy":
		return "http"
	case "postgres":
		return "postgresql"
	case "mongo":
		return "mongodb"
	case "microsoft-ds":
		return "smb"
	case "ms-wbt-server":
		return "rdp"
	}
	if !reportIsURLScheme(value) {
		return ""
	}
	return value
}

func reportIsURLScheme(scheme string) bool {
	if scheme == "" || scheme[0] < 'a' || scheme[0] > 'z' {
		return false
	}
	for _, r := range scheme[1:] {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func splitReportHostPortText(target string) (string, string) {
	if host, port, err := net.SplitHostPort(strings.TrimSpace(target)); err == nil {
		return strings.Trim(host, "[]"), port
	}
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return "", ""
	}
	return strings.Trim(strings.TrimSpace(target[:idx]), "[]"), strings.TrimSpace(target[idx+1:])
}

func reportPortGuess(port string) string {
	portNumber, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return ""
	}
	return common.GuessPortService(portNumber)
}

func reportStringFromExtra(extra map[string]interface{}, key string) string {
	if extra == nil {
		return ""
	}
	value, ok := extra[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func (s *ReportService) getReconResults() ([]ReconSummary, error) {
	portSchemes := s.loadReportPortTargetSchemes()
	query := "SELECT result_type, target, source, extra_data, CAST(discovered_at AS TEXT) FROM recon_results WHERE task_id = ? ORDER BY discovered_at DESC"
	rows, err := database.DB.Query(query, s.taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	urlMap := make(map[string]ReconSummary)
	var results []ReconSummary

	for rows.Next() {
		var r ReconSummary
		var extraDataStr string
		var discoveredAt sql.NullString
		if err := rows.Scan(&r.Type, &r.Target, &r.Source, &extraDataStr, &discoveredAt); err != nil {
			continue
		}
		r.Time = formatTimeString(discoveredAt.String)
		r.applyReconExtra(extraDataStr)
		if r.Type == "url" {
			if normalized := normalizeReportReconURL(r.Target, portSchemes); normalized != "" {
				r.Target = normalized
			}
			key := r.Type + "|" + r.Target
			existing, exists := urlMap[key]
			if !exists {
				urlMap[key] = r
			} else {
				shouldReplace := false
				if existing.Source == "httpx-pending" && (r.Source == "httpx" || r.Source == "httpx-failed") {
					shouldReplace = true
				} else if existing.Source == "httpx-failed" && r.Source == "httpx" {
					shouldReplace = true
				}
				if shouldReplace {
					urlMap[key] = r
				}
			}
		} else {
			results = append(results, r)
		}
	}
	for _, r := range urlMap {
		results = append(results, r)
	}
	return results, nil
}

// getFingerprints 获取指纹识别结果
func (s *ReportService) getFingerprints() ([]FingerprintSummary, error) {
	query := "SELECT target, fingerprint_name, CAST(identified_at AS TEXT) FROM fingerprint_results WHERE task_id = ? ORDER BY identified_at DESC"
	rows, err := database.DB.Query(query, s.taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []FingerprintSummary
	for rows.Next() {
		var f FingerprintSummary
		var identifiedAt sql.NullString
		if err := rows.Scan(&f.Target, &f.Fingerprint, &identifiedAt); err != nil {
			continue
		}
		f.Time = formatTimeString(identifiedAt.String)
		results = append(results, f)
	}
	return results, nil
}

// getVulnerabilities 获取漏洞扫描结果
func (s *ReportService) getVulnerabilities() ([]VulnSummary, error) {
	var query string
	if s.isPocTask {
		query = `SELECT target, template_id, matcher_name, severity, description, request, response, CAST(discovered_at AS TEXT), COALESCE(name, ''), COALESCE(template_path, ''), COALESCE(author, ''), COALESCE(tags, '')
			FROM poc_scan_results WHERE task_id = ?
			ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END, discovered_at ASC`
	} else {
		query = `SELECT target, template_id, matcher_name, severity, description, request, response, CAST(discovered_at AS TEXT), COALESCE(name, ''), COALESCE(template_path, ''), COALESCE(author, ''), COALESCE(tags, '')
			FROM vuln_results WHERE task_id = ?
			ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END, discovered_at ASC`
	}
	rows, err := database.DB.Query(query, s.taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var results []VulnSummary
	for rows.Next() {
		var v VulnSummary
		var discoveredAt sql.NullString
		var templatePath string
		if err := rows.Scan(&v.Target, &v.TemplateID, &v.MatcherName, &v.Severity, &v.Description, &v.Request, &v.Response, &discoveredAt, &v.Name, &templatePath, &v.Author, &v.Tags); err != nil {
			continue
		}
		v.Time = formatTimeString(discoveredAt.String)
		meta := s.getPocMetadata(templatePath, v.TemplateID)
		if strings.TrimSpace(v.Author) == "" {
			v.Author = meta.Author
		}
		if strings.TrimSpace(v.Tags) == "" {
			v.Tags = meta.Tags
		}
		if v.Name == "" && meta.Name != "" {
			v.Name = meta.Name
		}
		results = append(results, v)
	}
	return results, nil
}
