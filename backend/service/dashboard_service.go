// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现仪表盘数据聚合服务，提供任务、资产、漏洞、指纹、POC等维度的统计概览。
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DashboardService 仪表盘数据服务，聚合平台核心指标统计数据。
type DashboardService struct{}

// NewDashboardService 创建仪表盘服务实例。
func NewDashboardService() *DashboardService {
	return &DashboardService{}
}

// GetStats 获取仪表盘核心统计数据，包含以下维度的聚合信息：
//   - 任务统计：总任务数、运行中任务数
//   - 资产统计：去重的目标资产总数
//   - 漏洞统计：漏洞总数、按严重程度分布（critical/high/medium/low/info/unknown）
//   - 指纹统计：被动+主动指纹规则总数、Top10指纹出现频率
//   - POC统计：POC规则总数
//   - 趋势数据：近30天每日任务和漏洞数量趋势
//
// 参数:
//   - userID: 当前用户ID（保留用于接口兼容）
//   - role: 用户角色（保留用于接口兼容）
//
// 返回值:
//   - map[string]interface{}: 聚合统计数据
//   - error: 数据库未初始化时返回错误
func (s *DashboardService) GetStats(userID uint) (map[string]interface{}, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	stats := make(map[string]interface{})

	// 1. 任务维度统计：总数和运行中数量
	var totalTasks int
	database.DB.QueryRow("SELECT COUNT(*) FROM task_config").Scan(&totalTasks)
	stats["totalTasks"] = totalTasks

	var runningTasks int
	database.DB.QueryRow("SELECT COUNT(*) FROM task_config WHERE status = 'running'").Scan(&runningTasks)
	stats["runningTasks"] = runningTasks
	stats["completedTasks"] = queryCount("SELECT COUNT(*) FROM task_config WHERE status = 'completed'")
	stats["failedTasks"] = queryCount("SELECT COUNT(*) FROM task_config WHERE status = 'failed'")
	stats["pendingTasks"] = queryCount("SELECT COUNT(*) FROM task_config WHERE status IN ('pending', 'queued', 'created')")

	// 2. 资产维度统计：去重目标数量
	var totalAssets int
	database.DB.QueryRow("SELECT COUNT(DISTINCT target) FROM recon_results").Scan(&totalAssets)
	stats["totalAssets"] = totalAssets
	stats["portCount"] = queryCount("SELECT COUNT(*) FROM recon_results WHERE result_type = 'port'")
	stats["siteCount"] = queryCount("SELECT COUNT(*) FROM recon_results WHERE result_type = 'url'")
	stats["subdomainCount"] = queryCount("SELECT COUNT(*) FROM subdomain_results")
	stats["directoryCount"] = queryCount("SELECT COUNT(*) FROM directory_results")
	stats["jsCount"] = queryCount("SELECT COUNT(*) FROM js_scan_results")
	stats["weakPasswordCount"] = queryCount("SELECT COUNT(*) FROM weak_password_results")

	// 3. 漏洞维度统计：总数和严重程度分布
	var totalVulns int
	database.DB.QueryRow("SELECT COUNT(*) FROM vuln_results").Scan(&totalVulns)
	stats["totalVulns"] = totalVulns

	// Vuln Level Distribution
	vulnLevelDist := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}
	rows, err := database.DB.Query("SELECT severity, COUNT(*) FROM vuln_results GROUP BY severity")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var severity string
			var count int
			if err := rows.Scan(&severity, &count); err == nil {
				// Normalize severity key (lowercase)
				// Assuming severity in DB matches keys or needs mapping
				vulnLevelDist[severity] = count
			}
		}
	}
	stats["vulnLevelDist"] = vulnLevelDist

	// 4. Fingerprint Counts (Rules)
	var passiveCount int
	database.DB.QueryRow("SELECT COUNT(*) FROM passive_fingerprints").Scan(&passiveCount)
	var activeCount int
	database.DB.QueryRow("SELECT COUNT(*) FROM active_fingerprints").Scan(&activeCount)
	stats["totalFingerprints"] = passiveCount + activeCount

	// Fingerprint Top 10
	type FingerprintCount struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	var fingerprintTop10 []FingerprintCount
	fpRows, err := database.DB.Query("SELECT fingerprint_name, COUNT(*) as c FROM fingerprint_results GROUP BY fingerprint_name ORDER BY c DESC LIMIT 10")
	if err == nil {
		defer fpRows.Close()
		for fpRows.Next() {
			var name string
			var count int
			if err := fpRows.Scan(&name, &count); err == nil {
				fingerprintTop10 = append(fingerprintTop10, FingerprintCount{Name: name, Count: count})
			}
		}
	}
	// Ensure not nil for frontend
	if fingerprintTop10 == nil {
		fingerprintTop10 = []FingerprintCount{}
	}
	stats["fingerprintTop10"] = fingerprintTop10

	// 5. POC Counts
	// POC 统计：从 data/pocs 目录统计 YAML 文件数
	totalPOCs := countPocFilesFromDisk()
	stats["totalPOCs"] = totalPOCs

	// 6. Trend Data (Last 30 days)
	type TrendItem struct {
		Date  string `json:"date"`
		Tasks int    `json:"tasks"`
		Vulns int    `json:"vulns"`
	}
	// Initialize map for last 30 days
	trendMap := make(map[string]*TrendItem)
	now := utils.GetCurrentTime()
	for i := 29; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		trendMap[date] = &TrendItem{Date: date, Tasks: 0, Vulns: 0}
	}

	trendStart := now.AddDate(0, 0, -29).Format("2006-01-02")

	// Query Tasks per day
	taskTrendRows, err := database.DB.Query("SELECT CAST(created_at AS DATE)::TEXT, COUNT(*) FROM task_config WHERE CAST(created_at AS DATE) >= CAST(? AS DATE) GROUP BY CAST(created_at AS DATE)", trendStart)
	if err == nil {
		defer taskTrendRows.Close()
		for taskTrendRows.Next() {
			var date string
			var count int
			if err := taskTrendRows.Scan(&date, &count); err == nil {
				if item, ok := trendMap[date]; ok {
					item.Tasks = count
				}
			}
		}
	}

	// Query Vulns per day
	vulnTrendRows, err := database.DB.Query("SELECT CAST(discovered_at AS DATE)::TEXT, COUNT(*) FROM vuln_results WHERE CAST(discovered_at AS DATE) >= CAST(? AS DATE) GROUP BY CAST(discovered_at AS DATE)", trendStart)
	if err == nil {
		defer vulnTrendRows.Close()
		for vulnTrendRows.Next() {
			var date string
			var count int
			if err := vulnTrendRows.Scan(&date, &count); err == nil {
				if item, ok := trendMap[date]; ok {
					item.Vulns = count
				}
			}
		}
	}

	// Convert map to slice sorted by date
	var trendData []TrendItem
	for i := 29; i >= 0; i-- {
		date := now.AddDate(0, 0, -i).Format("2006-01-02")
		if item, ok := trendMap[date]; ok {
			trendData = append(trendData, *item)
		}
	}
	stats["trendData"] = trendData

	return stats, nil
}

func queryCount(query string, args ...interface{}) int {
	var count int
	if database.DB == nil {
		return 0
	}
	if err := database.DB.QueryRow(query, args...).Scan(&count); err != nil {
		return 0
	}
	return count
}

// countPocFilesFromDisk 从 data/pocs 目录统计 YAML 文件数
func countPocFilesFromDisk() int {
	pocsDir := resolvePocRoot()

	count := 0
	filepath.Walk(pocsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			name := strings.ToLower(info.Name())
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				count++
			}
		}
		return nil
	})
	return count
}
