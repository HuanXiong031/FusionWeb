package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type DingTalkMessage struct {
	MsgType  string    `json:"msgtype"`
	Markdown *Markdown `json:"markdown,omitempty"`
}

type Markdown struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type DingTalkNotifyEvent string

const (
	DingTalkEventBlacklistAdd     DingTalkNotifyEvent = "blacklist_add"
	DingTalkEventBlacklistRemove  DingTalkNotifyEvent = "blacklist_remove"
	DingTalkEventWebScanComplete  DingTalkNotifyEvent = "web_scan_complete"
	DingTalkEventPortScanComplete DingTalkNotifyEvent = "port_scan_complete"
)

// SendDingTalkNotification 发送钉钉通知
func SendDingTalkNotification(task *models.TaskConfig) error {
	token, secret, ok := resolveTaskDingTalkCredential(task)
	if !ok {
		return nil // 未配置 Token，不发送
	}

	if strings.EqualFold(task.TaskType, "port") {
		title, text := buildPortScanDingTalkMessage(task)
		if err := SendDingTalkMarkdown(token, secret, title, text); err != nil {
			return err
		}
		logger.Info("已发送钉钉通知给任务: %s", task.TaskID)
		return nil
	}

	// 1. 获取任务统计信息
	var vulnCount int
	var criticalCount int
	var highCount int
	var mediumCount int
	var lowCount int
	var infoCount int
	var unknownCount int

	// 统一查询普通结果表
	var vulnQueryStr string
	var queryArg interface{}
	vulnQueryStr = "SELECT severity FROM vuln_results WHERE task_id = ?"
	queryArg = task.TaskID

	// 统计漏洞数量
	rows, err := database.DB.Query(vulnQueryStr, queryArg)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			if err := rows.Scan(&severity); err == nil {
				vulnCount++
				switch strings.ToLower(severity) {
				case "critical":
					criticalCount++
				case "high":
					highCount++
				case "medium":
					mediumCount++
				case "low":
					lowCount++
				case "info":
					infoCount++
				default:
					unknownCount++
				}
			}
		}
	}

	// 2. 构建消息内容
	title := "扫描任务扫描完成"
	statusIcon := "✅"

	// 如果有漏洞，修改标题和图标
	if vulnCount > 0 {
		title = "🚨 扫描任务发现安全漏洞"
		statusIcon = "🚨"
	} else {
		// 检查任务状态
		var status string
		var err error
		err = database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", task.TaskID).Scan(&status)
		if err == nil && status == "failed" {
			statusIcon = "❌"
		}
	}

	text := fmt.Sprintf("### %s 扫描完成\n\n", statusIcon)
	if vulnCount > 0 {
		text += "#### ⚠️ 发现安全漏洞，请及时处理！\n\n"
	}
	text += fmt.Sprintf("- **任务名称**: %s\n", task.TaskName)

	// 处理目标显示（截断过长的目标列表）
	targets := strings.Split(strings.ReplaceAll(task.TargetInput, "\r\n", "\n"), "\n")
	var validTargets []string
	for _, t := range targets {
		if strings.TrimSpace(t) != "" {
			validTargets = append(validTargets, strings.TrimSpace(t))
		}
	}

	targetDisplay := task.TargetInput
	if len(validTargets) > 5 {
		targetDisplay = fmt.Sprintf("%s 等 %d 个目标", strings.Join(validTargets[:5], ", "), len(validTargets))
	} else if len(task.TargetInput) > 200 {
		// 如果目标少于5个但总长度超过200字符，也进行截断
		targetDisplay = task.TargetInput[:200] + "..."
	}
	text += fmt.Sprintf("- **目标**: %s\n", targetDisplay)

	text += fmt.Sprintf("- **扫描模式**: %s\n", task.ScanMode)
	text += fmt.Sprintf("- **发现漏洞**: %d 个\n", vulnCount)
	// 手机端钉钉对列表渲染要求列表前需要空行且不缩进
	text += "\n"
	text += fmt.Sprintf("- 🔴 严重: %d\n", criticalCount)
	text += fmt.Sprintf("- 🟠 高危: %d\n", highCount)
	text += fmt.Sprintf("- 🟡 中危: %d\n", mediumCount)
	text += fmt.Sprintf("- 🔵 低危: %d\n", lowCount)
	text += fmt.Sprintf("- 🟢 信息: %d\n", infoCount)
	text += fmt.Sprintf("- ⚪ 未知: %d\n", unknownCount)

	// 列出所有漏洞（不再限制为中危以上）
	if vulnCount > 0 {
		text += "\n#### 漏洞详情:\n"

		// 统一查询所有漏洞
		var vulnQuery string
		vulnQuery = `
			SELECT name, target, severity 
			FROM vuln_results 
			WHERE task_id = ?
			ORDER BY 
				CASE severity
					WHEN 'critical' THEN 1
					WHEN 'high' THEN 2
					WHEN 'medium' THEN 3
					WHEN 'low' THEN 4
					WHEN 'info' THEN 5
					ELSE 6
				END ASC,
				discovered_at DESC
			LIMIT 20
		`

		vRows, err := database.DB.Query(vulnQuery, queryArg)
		if err == nil {
			defer vRows.Close()
			for vRows.Next() {
				var name, target, severity string
				if err := vRows.Scan(&name, &target, &severity); err == nil {
					icon := "⚪" // 默认为灰色（未知/其他）
					severityCN := "未知"

					switch strings.ToLower(severity) {
					case "critical":
						icon = "🔴"
						severityCN = "严重"
					case "high":
						icon = "🟠"
						severityCN = "高危"
					case "medium":
						icon = "🟡"
						severityCN = "中危"
					case "low":
						icon = "🔵"
						severityCN = "低危"
					case "info":
						icon = "🟢"
						severityCN = "信息"
					}
					// 格式：🔴 [严重] 漏洞名称: 目标
					text += fmt.Sprintf("- %s **[%s] %s**: %s\n", icon, severityCN, name, target)
				}
			}
		}
		if vulnCount > 20 {
			text += fmt.Sprintf("\n*(仅显示前 20 条，共 %d 条)*\n", vulnCount)
		}
		text += "\n"
	}

	// 统计指纹数量
	// - rowCount: 指纹记录总数（用于判断是否展示段落）
	// - targetCount: 不同目标数量（用于段落标题展示）
	var fingerprintCount int
	var fingerprintTargetCount int
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ?", queryArg).Scan(&fingerprintCount)
	_ = database.DB.QueryRow("SELECT COUNT(DISTINCT target) FROM fingerprint_results WHERE task_id = ?", queryArg).Scan(&fingerprintTargetCount)

	// 列出指纹信息
	if fingerprintCount > 0 {
		text += fmt.Sprintf("#### 指纹识别 (共 %d 个目标，%d 条记录):\n", fingerprintTargetCount, fingerprintCount)

		// 获取每个目标的指纹列表并在代码中去重、排序
		var fpRows *sql.Rows
		fpRows, _ = database.DB.Query(`
			SELECT target, fingerprint_name
			FROM fingerprint_results
			WHERE task_id = ?
			ORDER BY target, fingerprint_name
		`, queryArg)

		if fpRows != nil {
			defer fpRows.Close()
			type fpAgg struct {
				origOrder []string
				seen      map[string]struct{}
			}
			agg := map[string]*fpAgg{}
			targetOrder := make([]string, 0, 64)
			for fpRows.Next() {
				var target, name string
				if err := fpRows.Scan(&target, &name); err == nil {
					entry, ok := agg[target]
					if !ok {
						entry = &fpAgg{origOrder: []string{}, seen: make(map[string]struct{})}
						agg[target] = entry
						targetOrder = append(targetOrder, target)
					}
					key := strings.ToLower(strings.TrimSpace(name))
					if _, exists := entry.seen[key]; !exists {
						entry.seen[key] = struct{}{}
						entry.origOrder = append(entry.origOrder, strings.TrimSpace(name))
					}
				}
			}
			// 输出前20个目标
			index := 1
			for _, target := range targetOrder {
				entry := agg[target]
				if index > 20 {
					break
				}
				names := strings.Join(entry.origOrder, "、")
				text += fmt.Sprintf("%02d、 `%s`  %s \n\n", index, target, names)
				index++
			}
		}
		if fingerprintCount > 20 {
			text += fmt.Sprintf("\n*(仅显示前 20 个目标，共 %d 个)*\n", fingerprintCount)
		}
		text += "\n"
	}

	// 底部时间
	text += fmt.Sprintf("---\n🕒 通知时间: %s", utils.GetCurrentTimeString())

	// 3. 发送请求
	if err := SendDingTalkMarkdown(token, secret, title, text); err != nil {
		return err
	}

	logger.Info("已发送钉钉通知给任务: %s", task.TaskID)
	return nil
}

func buildPortScanDingTalkMessage(task *models.TaskConfig) (string, string) {
	stats := loadPortScanNotificationStats(task)
	title := "端口扫描结果摘要"
	if stats.VulnCount > 0 {
		title = "端口扫描发现安全风险"
	}

	text := "### 端口扫描结果摘要\n\n"
	text += fmt.Sprintf("任务：%s\n\n", defaultNotifyText(task.TaskName, task.TaskID))
	text += fmt.Sprintf("状态：%s\n\n", notifyStatusLabel(stats.Status))
	text += fmt.Sprintf("本次共扫描 %d 个IP，扫描共发现 %d 个开放端口，其中识别到 %d 个 Web 服务，命中 %d 条指纹，发现 %d 条漏洞结果。\n\n",
		stats.ScannedIPCount, stats.OpenPortCount, stats.WebServiceCount, stats.FingerprintCount, stats.VulnCount)

	text += "#### 重点关注\n\n"
	text += fmt.Sprintf("- 严重漏洞：%d\n", stats.CriticalCount)
	text += fmt.Sprintf("- 高危漏洞：%d\n", stats.HighCount)
	text += fmt.Sprintf("- 中危漏洞：%d\n", stats.MediumCount)
	text += fmt.Sprintf("- 暴露服务：%s\n\n", defaultNotifyText(strings.Join(stats.Services, "、"), "暂无"))

	if len(stats.TopPorts) > 0 {
		text += "#### 端口明细 Top 10\n\n"
		for i, item := range stats.TopPorts {
			service := strings.TrimSpace(item.Service)
			if service == "" {
				service = "unknown"
			}
			text += fmt.Sprintf("%02d、`%s` %s\n\n", i+1, item.Target, service)
		}
	}

	text += fmt.Sprintf("---\n🕒 通知时间: %s", utils.GetCurrentTimeString())
	return title, text
}

type portScanNotificationStats struct {
	Status           string
	ScannedIPCount   int
	OpenPortCount    int
	WebServiceCount  int
	FingerprintCount int
	VulnCount        int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	Services         []string
	TopPorts         []portScanNotifyPort
}

type portScanNotifyPort struct {
	Target  string
	Service string
}

func loadPortScanNotificationStats(task *models.TaskConfig) portScanNotificationStats {
	stats := portScanNotificationStats{Status: task.Status}
	_ = database.DB.QueryRow("SELECT status FROM task_config WHERE task_id = ?", task.TaskID).Scan(&stats.Status)
	stats.ScannedIPCount = estimatePortScanIPCount(task.TargetInput)

	_ = database.DB.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'port'", task.TaskID).Scan(&stats.OpenPortCount)
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'url'", task.TaskID).Scan(&stats.WebServiceCount)
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ?", task.TaskID).Scan(&stats.FingerprintCount)

	rows, err := database.DB.Query("SELECT severity FROM vuln_results WHERE task_id = ?", task.TaskID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			if err := rows.Scan(&severity); err != nil {
				continue
			}
			stats.VulnCount++
			switch strings.ToLower(strings.TrimSpace(severity)) {
			case "critical":
				stats.CriticalCount++
			case "high":
				stats.HighCount++
			case "medium":
				stats.MediumCount++
			}
		}
	}

	stats.TopPorts, stats.Services = loadPortScanNotificationTopPorts(task.TaskID)
	if stats.ScannedIPCount == 0 {
		stats.ScannedIPCount = countHostsFromPortTargets(stats.TopPorts)
	}
	return stats
}

func loadPortScanNotificationTopPorts(taskID string) ([]portScanNotifyPort, []string) {
	rows, err := database.DB.Query(`
		SELECT target, extra_data
		FROM recon_results
		WHERE task_id = ? AND result_type = 'port'
		ORDER BY discovered_at ASC
		LIMIT 10
	`, taskID)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	ports := make([]portScanNotifyPort, 0, 10)
	serviceSet := map[string]struct{}{}
	for rows.Next() {
		var target string
		var extraDataStr string
		if err := rows.Scan(&target, &extraDataStr); err != nil {
			continue
		}
		service := notifyPortService(target, extraDataStr)
		if service != "" && service != "unknown" {
			serviceSet[service] = struct{}{}
		}
		ports = append(ports, portScanNotifyPort{Target: target, Service: service})
	}

	services := make([]string, 0, len(serviceSet))
	for service := range serviceSet {
		services = append(services, service)
	}
	sort.Strings(services)
	if len(services) > 8 {
		services = services[:8]
	}
	return ports, services
}

func notifyPortService(target, extraDataStr string) string {
	var extra map[string]interface{}
	_ = json.Unmarshal([]byte(extraDataStr), &extra)
	for _, key := range []string{"detected_service", "guessed_service", "service", "protocol"} {
		value := strings.TrimSpace(fmt.Sprint(extra[key]))
		if value != "" && value != "<nil>" && !strings.EqualFold(value, "tcp") {
			return value
		}
	}
	_, port := splitNotifyHostPort(target)
	if port == "" {
		return "unknown"
	}
	switch port {
	case "21":
		return "ftp"
	case "22":
		return "ssh"
	case "23":
		return "telnet"
	case "25":
		return "smtp"
	case "53":
		return "dns"
	case "80", "8080", "8000", "8888":
		return "http"
	case "443", "8443":
		return "https"
	case "3306":
		return "mysql"
	case "3389":
		return "rdp"
	case "6379":
		return "redis"
	default:
		return "unknown"
	}
}

func estimatePortScanIPCount(targetInput string) int {
	targets := notificationTargets(targetInput)
	seen := map[string]struct{}{}
	total := 0
	for _, target := range targets {
		host := notifyTargetHost(target)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			key := ip.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				total++
			}
			continue
		}
		if _, ipNet, err := net.ParseCIDR(host); err == nil {
			total += cidrAddressCount(ipNet)
			continue
		}
		if count := ipRangeAddressCount(host); count > 0 {
			total += count
			continue
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			total++
		}
	}
	return total
}

func notificationTargets(input string) []string {
	splitter := regexp.MustCompile(`[\s,;]+`)
	items := splitter.Split(strings.TrimSpace(strings.ReplaceAll(input, "\r\n", "\n")), -1)
	targets := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			targets = append(targets, item)
		}
	}
	return targets
}

func notifyTargetHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	host, _ := splitNotifyHostPort(target)
	if host != "" {
		return host
	}
	return target
}

func splitNotifyHostPort(target string) (string, string) {
	target = strings.TrimSpace(target)
	if host, port, err := net.SplitHostPort(target); err == nil {
		return strings.Trim(host, "[]"), port
	}
	index := strings.LastIndex(target, ":")
	if index <= 0 || strings.Count(target, ":") > 1 {
		return target, ""
	}
	host := target[:index]
	port := target[index+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return target, ""
	}
	return host, port
}

func cidrAddressCount(ipNet *net.IPNet) int {
	if ipNet == nil {
		return 0
	}
	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits <= ones || bits > 32 {
		return 1
	}
	count := 1 << uint(bits-ones)
	return count
}

func ipRangeAddressCount(value string) int {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0
	}
	start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	if start == nil {
		return 0
	}
	endText := strings.TrimSpace(parts[1])
	end := net.ParseIP(endText).To4()
	if end == nil {
		prefix := strings.Split(strings.TrimSpace(parts[0]), ".")
		if len(prefix) != 4 {
			return 0
		}
		end = net.ParseIP(strings.Join(prefix[:3], ".") + "." + endText).To4()
	}
	if end == nil {
		return 0
	}
	startInt := big.NewInt(0).SetBytes(start)
	endInt := big.NewInt(0).SetBytes(end)
	diff := big.NewInt(0).Sub(endInt, startInt)
	if diff.Sign() < 0 {
		return 0
	}
	diff.Add(diff, big.NewInt(1))
	if !diff.IsInt64() {
		return 0
	}
	return int(diff.Int64())
}

func countHostsFromPortTargets(ports []portScanNotifyPort) int {
	seen := map[string]struct{}{}
	for _, item := range ports {
		host, _ := splitNotifyHostPort(item.Target)
		if host == "" {
			continue
		}
		seen[host] = struct{}{}
	}
	return len(seen)
}

func notifyStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed":
		return "已完成"
	case "failed":
		return "失败"
	case "cancelled", "canceled":
		return "已取消"
	case "paused":
		return "已暂停"
	case "running":
		return "运行中"
	default:
		return defaultNotifyText(status, "未知")
	}
}

func defaultNotifyText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func SendDingTalkMarkdown(token, secret, title, text string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	webhook := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", token)
	if secret != "" {
		timestamp := time.Now().UnixNano() / 1e6
		stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(stringToSign))
		sign := base64.StdEncoding.EncodeToString(h.Sum(nil))
		webhook = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhook, timestamp, url.QueryEscape(sign))
	}

	msg := DingTalkMessage{
		MsgType: "markdown",
		Markdown: &Markdown{
			Title: title,
			Text:  text,
		},
	}

	jsonData, _ := json.Marshal(msg)
	resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error("发送钉钉通知失败: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Error("发送钉钉通知失败，状态码: %d", resp.StatusCode)
		return fmt.Errorf("status code: %d", resp.StatusCode)
	}
	return nil
}

func NotifyDingTalkEvent(event DingTalkNotifyEvent, title, text string) {
	keys, err := NewSystemSettingsService().ListDingTalkKeys(true)
	if err != nil {
		logger.Warn("读取钉钉通知Key失败: %v", err)
		return
	}
	for _, key := range keys {
		if !dingTalkKeyAllowsEvent(key, event) {
			continue
		}
		key := key
		go func() {
			if err := SendDingTalkMarkdown(key.AccessToken, key.Secret, title, text); err != nil {
				logger.Warn("发送钉钉事件通知失败: key=%s, err=%v", key.Name, err)
			}
		}()
	}
}

func resolveTaskDingTalkCredential(task *models.TaskConfig) (string, string, bool) {
	if task == nil {
		return "", "", false
	}
	if task.DingTalkKeyID > 0 {
		key, err := NewSystemSettingsService().GetDingTalkKey(task.DingTalkKeyID, true)
		if err != nil {
			logger.Warn("读取任务钉钉Key失败: task=%s, keyID=%d, err=%v", task.TaskID, task.DingTalkKeyID, err)
			return "", "", false
		}
		event := DingTalkEventWebScanComplete
		if strings.EqualFold(task.TaskType, "port") {
			event = DingTalkEventPortScanComplete
		}
		if dingTalkKeyAllowsEvent(key, event) {
			return key.AccessToken, key.Secret, true
		}
		return "", "", false
	}
	if task.DingTalkToken != "" {
		return task.DingTalkToken, task.DingTalkSecret, true
	}
	return "", "", false
}

func dingTalkKeyAllowsEvent(key DingTalkKey, event DingTalkNotifyEvent) bool {
	if !key.Enabled {
		return false
	}
	switch event {
	case DingTalkEventBlacklistAdd:
		return key.NotifyBlacklistAdd
	case DingTalkEventBlacklistRemove:
		return key.NotifyBlacklistRemove
	case DingTalkEventWebScanComplete:
		return key.NotifyWebScanComplete
	case DingTalkEventPortScanComplete:
		return key.NotifyPortScanComplete
	default:
		return false
	}
}
