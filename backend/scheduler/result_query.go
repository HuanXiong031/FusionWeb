// Package scheduler 提供异步扫描任务的调度与执行管理。
// 本文件实现扫描结果查询功能，提供信息收集、指纹识别和漏洞扫描三类结果的统一查询接口。
package scheduler

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/common"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type templateInfo struct {
	Name        string
	Author      string
	Description string
	Severity    string
	Tags        interface{}
}

// GetReconResults 获取指定任务的信息收集结果（端口、URL等）。
// 支持按resultType过滤（port/url），传入空字符串或"all"表示查询所有类型。
//
// 参数:
//   - taskID: 任务唯一标识
//   - resultType: 结果类型过滤条件（"port"、"url"或"all"）
//
// 返回值:
//   - []map[string]interface{}: 信息收集结果列表
//   - error: 查询失败时返回错误
func (s *TaskScheduler) GetReconResults(taskID string, resultType string) ([]map[string]interface{}, error) {
	portTargetSchemes := map[string]string{}
	if resultType == "url" || resultType == "all" || resultType == "" {
		portTargetSchemes = loadPortTargetSchemes(taskID)
	}
	// 构建基础查询，按任务ID过滤信息收集结果
	query := `SELECT id, task_id, result_type, target, source, extra_data, CAST(discovered_at AS TEXT)
              FROM recon_results WHERE task_id = ?`
	var args []interface{}
	args = append(args, taskID)

	// 可选的类型过滤（port/url），支持前端按类别查看结果
	if resultType != "" && resultType != "all" {
		query += " AND result_type = ?"
		args = append(args, resultType)
	}

	// 按发现时间倒序排列
	query += " ORDER BY discovered_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询信息收集结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	seenTargets := make(map[string]struct{})
	for rows.Next() {
		var r models.ReconResult
		var extraDataStr string
		var discoveredAt string

		if err := rows.Scan(&r.ID, &r.TaskID, &r.ResultType, &r.Target, &r.Source, &extraDataStr, &discoveredAt); err != nil {
			continue // 跳过解析失败的行
		}

		var extraData map[string]interface{}
		if strings.TrimSpace(extraDataStr) != "" {
			_ = json.Unmarshal([]byte(extraDataStr), &extraData)
		}

		result := map[string]interface{}{
			"id":           r.ID,
			"taskID":       r.TaskID,
			"resultType":   r.ResultType,
			"target":       r.Target,
			"source":       r.Source,
			"discoveredAt": utils.FormatTimeStringForDisplay(discoveredAt),
			"extraData":    extraDataStr,
		}

		if r.ResultType == "port" {
			host, port := splitHostPortTarget(r.Target)
			protocol := stringFromExtra(extraData, "protocol")
			service := displayPortService(extraData, port)
			banner := stringFromExtra(extraData, "banner")
			status := stringFromExtra(extraData, "status")
			if protocol == "" {
				protocol = r.Source
			}
			if status == "" {
				status = "open"
			}

			result["host"] = host
			result["ip"] = host
			result["port"] = port
			result["protocol"] = protocol
			result["service"] = service
			result["status"] = status
			result["banner"] = banner
		}

		if r.ResultType == "url" {
			displayURL := normalizeReconResultURL(r.Target, portTargetSchemes)
			if displayURL == "" {
				displayURL = r.Target
			}
			finalURL := stringFromExtra(extraData, "final_url")
			if finalURL == "" {
				finalURL = stringFromExtra(extraData, "headless_url")
			}
			if extraDisplayURL := stringFromExtra(extraData, "display_url"); extraDisplayURL != "" {
				displayURL = extraDisplayURL
			} else if finalURL != "" {
				displayURL = finalURL
			}
			if _, exists := seenTargets[displayURL]; exists {
				continue
			}
			seenTargets[displayURL] = struct{}{}
			result["url"] = displayURL
			result["target"] = displayURL
			result["displayURL"] = displayURL
			result["display_url"] = displayURL
			result["finalURL"] = finalURL
			result["final_url"] = finalURL
			screenshotKey := stringFromExtra(extraData, "screenshot_key")
			if screenshotKey == "" {
				screenshotKey = stringFromExtra(extraData, "screenshot_path")
			}
			result["screenshotKey"] = screenshotKey
			result["screenshot_key"] = screenshotKey
			result["screenshotPath"] = screenshotKey
			result["screenshot_path"] = screenshotKey
			result["statusCode"] = numberFromExtra(extraData, "status_code")
			result["status_code"] = numberFromExtra(extraData, "status_code")
			result["title"] = stringFromExtra(extraData, "title")
			result["length"] = numberFromExtra(extraData, "length")
		}

		results = append(results, result)
	}

	if resultType == "port" {
		sortReconPortResults(results)
	}

	return results, nil
}

func sortReconPortResults(results []map[string]interface{}) {
	sort.SliceStable(results, func(i, j int) bool {
		leftHost := strings.TrimSpace(fmt.Sprint(results[i]["host"]))
		rightHost := strings.TrimSpace(fmt.Sprint(results[j]["host"]))
		if leftHost != rightHost {
			return leftHost < rightHost
		}
		leftPort := comparableReconPort(results[i]["port"])
		rightPort := comparableReconPort(results[j]["port"])
		if leftPort != rightPort {
			return leftPort < rightPort
		}
		return fmt.Sprint(results[i]["target"]) < fmt.Sprint(results[j]["target"])
	})
}

func comparableReconPort(value interface{}) int {
	port, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
	if err != nil {
		return 1 << 30
	}
	return port
}

func loadPortTargetSchemes(taskID string) map[string]string {
	rows, err := database.DB.Query(`SELECT target, extra_data FROM recon_results WHERE task_id = ? AND result_type = 'port'`, taskID)
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
		host, port := splitHostPortTarget(target)
		portText := strings.TrimSpace(fmt.Sprint(port))
		if host == "" || portText == "" {
			continue
		}
		var extraData map[string]interface{}
		_ = json.Unmarshal([]byte(extraDataStr), &extraData)
		protocol := stringFromExtra(extraData, "protocol")
		service := detectedReconService(extraData)
		scheme := reconProtocolScheme(protocol, service)
		schemes[net.JoinHostPort(host, portText)] = scheme
	}
	return schemes
}

func normalizeReconResultURL(raw string, portSchemes map[string]string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return raw
	}
	host := parsed.Hostname()
	portText := parsed.Port()
	if portText == "" {
		return raw
	}
	key := net.JoinHostPort(host, portText)
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

func reconProtocolScheme(protocol, service string) string {
	for _, candidate := range []string{protocol, service} {
		scheme := normalizeReconScheme(candidate)
		if scheme != "" && scheme != "tcp" {
			return scheme
		}
	}
	return ""
}

func detectedReconService(extra map[string]interface{}) string {
	service := stringFromExtra(extra, "detected_service")
	if service != "" {
		return service
	}
	if _, hasGuess := extra["guessed_service"]; hasGuess {
		return ""
	}
	service = stringFromExtra(extra, "service")
	if strings.EqualFold(service, "tcp") {
		return ""
	}
	return service
}

func displayPortService(extra map[string]interface{}, port interface{}) string {
	service := stringFromExtra(extra, "service")
	if service != "" && !strings.EqualFold(service, "tcp") {
		return service
	}
	guessed := stringFromExtra(extra, "guessed_service")
	if guessed != "" {
		return guessed
	}
	return guessPortService(port)
}

func guessPortService(port interface{}) string {
	portNumber, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(port)))
	if err != nil {
		return ""
	}
	return common.GuessPortService(portNumber)
}

func normalizeReconScheme(value string) string {
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
	if !isReconURLScheme(value) {
		return ""
	}
	return value
}

func isReconURLScheme(scheme string) bool {
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

func splitHostPortTarget(target string) (string, interface{}) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", ""
	}

	if host, port, err := net.SplitHostPort(target); err == nil {
		if portNumber, convErr := strconv.Atoi(port); convErr == nil {
			return host, portNumber
		}
		return host, port
	}

	index := strings.LastIndex(target, ":")
	if index > 0 && index < len(target)-1 {
		host := target[:index]
		port := target[index+1:]
		if portNumber, err := strconv.Atoi(port); err == nil {
			return host, portNumber
		}
		return host, port
	}

	return target, ""
}

func stringFromExtra(extra map[string]interface{}, key string) string {
	if extra == nil {
		return ""
	}
	value, ok := extra[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func numberFromExtra(extra map[string]interface{}, key string) interface{} {
	if extra == nil {
		return nil
	}
	value, ok := extra[key]
	if !ok {
		return nil
	}
	return value
}

// GetFingerprintResults 获取指定任务的指纹识别结果。
// 指纹结果记录了目标URL匹配到的指纹规则信息，包括指纹名称和命中的匹配规则。
// 支持解析 matched_rules 字段的JSON格式，返回结构化数据供前端展示。
//
// 参数:
//   - taskID: 任务唯一标识
//
// 返回值:
//   - []map[string]interface{}: 指纹结果列表
//   - error: 查询失败时返回错误
func (s *TaskScheduler) GetFingerprintResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, target, fingerprint_name, matched_rules, CAST(identified_at AS TEXT) 
              FROM fingerprint_results WHERE task_id = ? ORDER BY identified_at DESC`

	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询指纹结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var r models.FingerprintResult
		var matchedRulesStr string
		var identifiedAt string

		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.FingerprintName, &matchedRulesStr, &identifiedAt); err != nil {
			continue
		}

		// 将 matched_rules 从JSON字符串反序列化为结构化对象
		// 解析失败时保留原始字符串，确保前端始终能获取数据
		var matchedRules interface{}
		if matchedRulesStr != "" {
			_ = json.Unmarshal([]byte(matchedRulesStr), &matchedRules)
		} else {
			matchedRules = matchedRulesStr
		}

		result := map[string]interface{}{
			"id":              r.ID,
			"taskID":          r.TaskID,
			"target":          r.Target,
			"fingerprintName": r.FingerprintName,
			"matchedRules":    matchedRules,
			"identifiedAt":    utils.FormatTimeStringForDisplay(identifiedAt),
		}
		results = append(results, result)
	}

	return results, nil
}

// GetVulnResults 获取指定任务的漏洞扫描结果。
// 返回Nuclei引擎扫描匹配到的漏洞详情，包含漏洞名称、严重程度、匹配器名称、
// HTTP请求/响应等完整信息，供报告生成和详情展示使用。
//
// 参数:
//   - taskID: 任务唯一标识
//
// 返回值:
//   - []map[string]interface{}: 漏洞结果列表
//   - error: 查询失败时返回错误
func (s *TaskScheduler) GetVulnResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, target, template_id, template_path, matcher_name, severity, 
              name, COALESCE(author, ''), COALESCE(tags, ''), description, request, response, CAST(discovered_at AS TEXT) 
              FROM vuln_results WHERE task_id = ? ORDER BY discovered_at DESC`

	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询漏洞结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	templateInfoCache := make(map[string]templateInfo)
	for rows.Next() {
		var r models.VulnResult
		var discoveredAt string
		// 注意：Scan 必须包含所有字段
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Target, &r.TemplateID, &r.TemplatePath, &r.MatcherName, &r.Severity,
			&r.Name, &r.Author, &r.Tags, &r.Description, &r.Request, &r.Response, &discoveredAt); err != nil {
			continue
		}

		info := loadTemplateInfo(r.TemplatePath, templateInfoCache)
		name := strings.TrimSpace(r.Name)
		if info.Name != "" {
			name = info.Name
		}
		if name == "" {
			name = r.TemplateID
		}
		description := strings.TrimSpace(r.Description)
		if description == "" && info.Description != "" {
			description = info.Description
		}
		severity := strings.TrimSpace(r.Severity)
		if severity == "" && info.Severity != "" {
			severity = info.Severity
		}
		author := strings.TrimSpace(r.Author)
		if author == "" {
			author = info.Author
		}
		tags := strings.TrimSpace(r.Tags)
		if tags == "" {
			tags = templateMetadataString(info.Tags)
		}
		if tags == "" {
			tags = r.MatcherName
		}

		result := map[string]interface{}{
			"id":           r.ID,
			"taskID":       r.TaskID,
			"target":       r.Target,
			"templateID":   r.TemplateID,
			"templatePath": r.TemplatePath,
			"matcherName":  r.MatcherName,
			"severity":     severity,
			"name":         name,
			"author":       author,
			"tags":         tags,
			"description":  description,
			"request":      r.Request,
			"response":     r.Response,
			"discoveredAt": utils.FormatTimeStringForDisplay(discoveredAt),
			"info": map[string]interface{}{
				"name":        info.Name,
				"author":      author,
				"description": info.Description,
				"severity":    info.Severity,
				"tags":        info.Tags,
			},
		}
		results = append(results, result)
	}

	return results, nil
}

func (s *TaskScheduler) GetSubdomainResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, domain, subdomain, ip_addresses, cname, source, extra_data, CAST(discovered_at AS TEXT)
              FROM subdomain_results WHERE task_id = ? ORDER BY discovered_at DESC`
	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询子域名结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var taskIDValue, domain, subdomain, ipAddressesStr, cname, source, extraDataStr, discoveredAt string
		if err := rows.Scan(&id, &taskIDValue, &domain, &subdomain, &ipAddressesStr, &cname, &source, &extraDataStr, &discoveredAt); err != nil {
			continue
		}
		var ipAddresses []string
		_ = json.Unmarshal([]byte(ipAddressesStr), &ipAddresses)
		results = append(results, map[string]interface{}{
			"id":           id,
			"taskID":       taskIDValue,
			"domain":       domain,
			"subdomain":    subdomain,
			"ipAddresses":  ipAddresses,
			"ip_addresses": ipAddresses,
			"cname":        cname,
			"source":       source,
			"extraData":    extraDataStr,
			"discoveredAt": utils.FormatTimeStringForDisplay(discoveredAt),
		})
	}
	return results, nil
}

func (s *TaskScheduler) GetWeakPasswordResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, target, host, port, service, username, password, severity, extra_data, CAST(discovered_at AS TEXT)
              FROM weak_password_results WHERE task_id = ? ORDER BY discovered_at DESC`
	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询弱口令结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, port int
		var taskIDValue, target, host, service, username, password, severity, extraDataStr, discoveredAt string
		if err := rows.Scan(&id, &taskIDValue, &target, &host, &port, &service, &username, &password, &severity, &extraDataStr, &discoveredAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":           id,
			"taskID":       taskIDValue,
			"target":       target,
			"host":         host,
			"port":         port,
			"service":      service,
			"username":     username,
			"password":     password,
			"severity":     severity,
			"extraData":    extraDataStr,
			"discoveredAt": utils.FormatTimeStringForDisplay(discoveredAt),
		})
	}
	return results, nil
}

func (s *TaskScheduler) GetDirectoryResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, target, url, path, status_code, content_length, content_type, redirect_location, source, extra_data, CAST(discovered_at AS TEXT)
              FROM directory_results WHERE task_id = ? ORDER BY discovered_at DESC`
	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询目录扫描结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, statusCode, contentLength int
		var taskIDValue, target, urlValue, pathValue, contentType, redirectLocation, source, extraDataStr, discoveredAt string
		if err := rows.Scan(&id, &taskIDValue, &target, &urlValue, &pathValue, &statusCode, &contentLength, &contentType, &redirectLocation, &source, &extraDataStr, &discoveredAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":               id,
			"taskID":           taskIDValue,
			"target":           target,
			"url":              urlValue,
			"path":             pathValue,
			"statusCode":       statusCode,
			"status_code":      statusCode,
			"contentLength":    contentLength,
			"content_length":   contentLength,
			"contentType":      contentType,
			"content_type":     contentType,
			"redirectLocation": redirectLocation,
			"redirect_location": redirectLocation,
			"source":           source,
			"extraData":        extraDataStr,
			"discoveredAt":     utils.FormatTimeStringForDisplay(discoveredAt),
		})
	}
	return results, nil
}

func (s *TaskScheduler) GetJSScanResults(taskID string) ([]map[string]interface{}, error) {
	query := `SELECT id, task_id, target, result_type, value, source_url, severity, extra_data, CAST(discovered_at AS TEXT)
              FROM js_scan_results WHERE task_id = ? ORDER BY discovered_at DESC`
	rows, err := database.DB.Query(query, taskID)
	if err != nil {
		return nil, fmt.Errorf("查询 JS 扫描结果失败: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var taskIDValue, target, resultType, value, sourceURL, severity, extraDataStr, discoveredAt string
		if err := rows.Scan(&id, &taskIDValue, &target, &resultType, &value, &sourceURL, &severity, &extraDataStr, &discoveredAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"id":           id,
			"taskID":       taskIDValue,
			"target":       target,
			"resultType":   resultType,
			"result_type":  resultType,
			"value":        value,
			"sourceURL":    sourceURL,
			"source_url":   sourceURL,
			"severity":     severity,
			"extraData":    extraDataStr,
			"discoveredAt": utils.FormatTimeStringForDisplay(discoveredAt),
		})
	}
	return results, nil
}

func loadTemplateInfo(templatePath string, cache map[string]templateInfo) templateInfo {
	templatePath = strings.TrimSpace(templatePath)
	if templatePath == "" {
		return templateInfo{}
	}
	if info, ok := cache[templatePath]; ok {
		return info
	}

	var parsed struct {
		Info struct {
			Name        string      `yaml:"name"`
			Author      interface{} `yaml:"author"`
			Description string      `yaml:"description"`
			Severity    string      `yaml:"severity"`
			Tags        interface{} `yaml:"tags"`
		} `yaml:"info"`
	}

	for _, candidate := range templatePathCandidates(templatePath) {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			continue
		}
		info := templateInfo{
			Name:        strings.TrimSpace(parsed.Info.Name),
			Author:      templateMetadataString(parsed.Info.Author),
			Description: strings.TrimSpace(parsed.Info.Description),
			Severity:    strings.TrimSpace(parsed.Info.Severity),
			Tags:        parsed.Info.Tags,
		}
		cache[templatePath] = info
		return info
	}

	cache[templatePath] = templateInfo{}
	return templateInfo{}
}

func templatePathCandidates(templatePath string) []string {
	candidates := []string{templatePath}
	if filepath.IsAbs(templatePath) {
		return candidates
	}
	candidates = append(candidates,
		filepath.Join(utils.GetDataDir(), "pocs", templatePath),
		filepath.Join(utils.GetDataDir(), templatePath),
	)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, templatePath))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(exeDir, templatePath), filepath.Join(filepath.Dir(exeDir), templatePath))
	}

	seen := make(map[string]struct{}, len(candidates))
	unique := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		cleaned := filepath.Clean(candidate)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique
}

func templateMetadataString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := templateMetadataString(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case []string:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := strings.TrimSpace(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}
