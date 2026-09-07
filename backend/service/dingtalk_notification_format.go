package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"

	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

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
