// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现IP地理位置查询服务，基于ipip.net的ipdb数据库进行IP定位。
//
// 设计要点:
//   - 单例模式：加载成功后复用同一个IP数据库实例
//   - 读写锁保护：ipdbMutex保护数据库实例的并发访问
//   - 自动定位：从 FUSIONWEB_DATA_DIR/qqwry.ipdb加载数据库
//   - 双语言回退：查询时优先中文，失败回退英文
//
// backend/service/ip_query_service.go
package service

import (
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ipipdotnet/ipdb-go"
)

// IPLocation IP位置信息
type IPLocation struct {
	// 基本信息
	IP            string `json:"ip"`             // IP地址
	Country       string `json:"country"`        // 国家
	Province      string `json:"province"`       // 省份
	City          string `json:"city"`           // 城市
	District      string `json:"district"`       // 区县
	ISP           string `json:"isp"`            // 运营商
	OwnerDomain   string `json:"owner_domain"`   // 拥有者域名
	ContinentCode string `json:"continent_code"` // 大洲编码
	CountryCode   string `json:"country_code"`   // 国家代码
}

var (
	ipdbInstance *ipdb.City
	ipdbMutex    sync.RWMutex
	ipdbLoaded   bool // 加载标志，用于Reload时判断
)

// getIPDBDataDir 获取 IP 数据库所在的数据目录。
func getIPDBDataDir() string {
	return utils.GetDataDir()
}

// getIPDBPath 获取IP数据库文件路径（只支持ipdb格式）
func getIPDBPath() string {
	dataDir := getIPDBDataDir()
	return filepath.Join(dataDir, "qqwry.ipdb")
}

// loadIPDB 加载IP数据库文件（完全按照测试代码的方式，只支持ipdb格式）
func loadIPDB() error {
	ipdbMutex.Lock()
	defer ipdbMutex.Unlock()

	// 双重检查，避免重复加载
	if ipdbInstance != nil {
		return nil
	}

	dbPath := getIPDBPath()

	// 检查文件是否存在
	fileInfo, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		logger.Error("IP数据库文件不存在: %s", dbPath)
		return fmt.Errorf("IP数据库文件不存在: %s (请将 qqwry.ipdb 文件放置在 config 文件夹中)", dbPath)
	}
	if err != nil {
		logger.Error("检查IP数据库文件失败: %v", err)
		return fmt.Errorf("检查IP数据库文件失败: %w", err)
	}

	// 检查文件大小，如果太小可能不是有效的数据库文件
	if fileInfo.Size() < 1024 {
		return fmt.Errorf("IP数据库文件太小（%d 字节），可能不是有效的数据库文件", fileInfo.Size())
	}

	// 直接加载数据库（完全按照测试代码的方式，不使用goroutine）
	startTime := time.Now()
	db, err := ipdb.NewCity(dbPath)
	loadTime := time.Since(startTime)

	if err != nil {
		logger.Error("加载IP数据库失败 (耗时: %v): %v", loadTime, err)
		return fmt.Errorf("加载IP数据库失败: %w (请确认文件是有效的IPIP.net格式的.ipdb文件)", err)
	}

	// 保存数据库实例
	ipdbInstance = db
	ipdbLoaded = true

	// 测试查询一个IP，确保数据库可用（完全按照测试代码的方式）
	testIP := "1.1.1.1"
	testStartTime := time.Now()
	_, testErr := db.FindInfo(testIP, "CN")
	if testErr != nil {
		_, testErr = db.FindInfo(testIP, "EN")
	}
	testQueryTime := time.Since(testStartTime)
	if testErr != nil {
		logger.Warn("测试查询失败 (耗时: %v): %v，但继续使用数据库", testQueryTime, testErr)
	}

	return nil
}

// ensureIPDBLoaded 确保IP数据库已加载
func ensureIPDBLoaded() error {
	ipdbMutex.RLock()
	loaded := ipdbInstance != nil && ipdbLoaded
	ipdbMutex.RUnlock()

	if !loaded {
		if err := loadIPDB(); err != nil {
			logger.Error("loadIPDB 失败: %v", err)
			return err
		}

		ipdbMutex.RLock()
		loaded = ipdbInstance != nil && ipdbLoaded
		ipdbMutex.RUnlock()
		if !loaded {
			logger.Error("数据库加载完成但实例仍为nil")
			return fmt.Errorf("数据库加载失败：实例为nil")
		}
	}

	return nil
}

// isValidIP 验证IP地址格式
func isValidIP(ip string) bool {
	// 去除空格
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}

	// 使用 net.ParseIP 验证IP地址格式
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 支持IPv4和IPv6
	// 如果是IPv4，直接返回true
	if parsedIP.To4() != nil {
		return true
	}

	// 如果是IPv6，检查数据库是否支持
	ipdbMutex.RLock()
	db := ipdbInstance
	ipdbMutex.RUnlock()

	if db != nil && db.IsIPv6() {
		return true
	}

	// 如果数据库不支持IPv6，但IP是本地IPv6地址（::1），也允许（会在QueryIP中特殊处理）
	if ip == "::1" {
		return true
	}

	return false
}

// QueryIP 查询单个IP地址的地理位置信息（国家、省份、城市、运营商等）。
// 本地IPv6地址(::1)直接返回"本地"结果，不查数据库。
//
// 参数:
//   - ip: IP地址字符串
//
// 返回值:
//   - *IPLocation: IP位置信息结构体
//   - error: IP格式无效或数据库未加载时返回错误
func QueryIP(ip string) (*IPLocation, error) {
	// 去除空格
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, fmt.Errorf("IP地址不能为空")
	}

	// 检查是否为本地IPv6地址（::1）
	if ip == "::1" {
		return &IPLocation{
			IP:       ip,
			Country:  "本地",
			Province: "",
			City:     "",
			District: "",
			ISP:      "",
		}, nil
	}

	// 验证IP地址格式
	if !isValidIP(ip) {
		return nil, fmt.Errorf("IP地址格式不正确: %s", ip)
	}

	// 确保数据库已加载
	if err := ensureIPDBLoaded(); err != nil {
		return nil, fmt.Errorf("IP数据库加载失败: %w", err)
	}

	ipdbMutex.RLock()
	db := ipdbInstance
	ipdbMutex.RUnlock()

	if db == nil {
		logger.Error("IP数据库实例为nil，无法查询")
		return nil, fmt.Errorf("IP数据库未加载，请稍后重试")
	}

	// 直接查询IP位置（完全按照测试代码的方式）
	startTime := time.Now()

	// 尝试使用中文查询（完全按照测试代码）
	info, err := db.FindInfo(ip, "CN")
	if err != nil {
		// 如果中文失败，尝试英文
		info, err = db.FindInfo(ip, "EN")
		if err != nil {
			// 如果英文也失败，尝试使用数据库支持的第一个语言
			languages := db.Languages()
			if len(languages) > 0 {
				info, err = db.FindInfo(ip, languages[0])
			}
		}
	}

	queryTime := time.Since(startTime)

	if err != nil {
		logger.Error("查询IP %s 失败 (耗时: %v): %v", ip, queryTime, err)
		return nil, fmt.Errorf("查询IP失败: %w", err)
	}

	// 转换为我们的结构
	location := convertToIPLocation(ip, info)
	return location, nil
}

// convertToIPLocation 将CityInfo转换为IPLocation
func convertToIPLocation(ip string, info *ipdb.CityInfo) *IPLocation {
	result := &IPLocation{
		// 基本信息
		IP:            ip,
		Country:       info.CountryName,
		Province:      info.RegionName,
		City:          info.CityName,
		District:      "", // IPDB库不包含DistrictName字段，使用空字符串
		ISP:           info.IspDomain,
		OwnerDomain:   info.OwnerDomain,
		ContinentCode: info.ContinentCode,
		CountryCode:   info.CountryCode,
	}

	// 不再设置"未知"，保留空字符串
	return result
}

// QueryIPs 批量查询多个IP地址的地理位置，自动去重。
// 单个IP查询失败不会影响其他IP，失败项标记为"查询失败"。
//
// 参数:
//   - ips: IP地址列表
//
// 返回值:
//   - map[string]*IPLocation: IP到位置信息的映射
//   - error: 暂不返回错误（单个IP的错误已内处理）
func QueryIPs(ips []string) (map[string]*IPLocation, error) {
	results := make(map[string]*IPLocation)

	// 去除重复的IP地址
	ipSet := make(map[string]bool)
	uniqueIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" && !ipSet[ip] {
			ipSet[ip] = true
			uniqueIPs = append(uniqueIPs, ip)
		}
	}

	// 批量查询
	for _, ip := range uniqueIPs {
		location, err := QueryIP(ip)
		if err != nil {
			logger.Warn("查询IP %s 失败: %v", ip, err)
			results[ip] = &IPLocation{
				IP:       ip,
				Country:  "查询失败",
				Province: "",
				City:     "",
				District: "",
				ISP:      "",
			}
		} else {
			results[ip] = location
		}
	}

	return results, nil
}

// LoadIPDBAsync 异步加载IP数据库（用于程序启动时预加载）
func LoadIPDBAsync() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("IP database async load panic: %v", r)
			}
		}()
		if err := ensureIPDBLoaded(); err != nil {
			logger.Warn("IP数据库异步加载失败: %v", err)
		}
	}()
}

// ReloadIPDB 重新加载IP数据库
func ReloadIPDB() error {
	ipdbMutex.Lock()
	dbPath := getIPDBPath()

	// 如果数据库已加载，使用 Reload 方法（更高效）
	if ipdbInstance != nil && ipdbLoaded {
		if err := ipdbInstance.Reload(dbPath); err != nil {
			ipdbMutex.Unlock()
			return fmt.Errorf("重新加载IP数据库失败: %w", err)
		}
		logger.Debug("IP数据库重新加载成功: %s", dbPath)
		ipdbMutex.Unlock()
		return nil
	}

	// 如果未加载，则首次加载
	// 重置加载标志，允许重新加载
	ipdbLoaded = false
	ipdbInstance = nil
	ipdbMutex.Unlock()

	return loadIPDB()
}

// GetIPDBInfo 获取IP数据库信息
func GetIPDBInfo() (map[string]interface{}, error) {
	if err := ensureIPDBLoaded(); err != nil {
		return nil, err
	}

	ipdbMutex.RLock()
	db := ipdbInstance
	ipdbMutex.RUnlock()

	if db == nil {
		return nil, fmt.Errorf("IP数据库未加载")
	}

	info := make(map[string]interface{})
	info["is_ipv4"] = db.IsIPv4()
	info["is_ipv6"] = db.IsIPv6()
	info["build_time"] = utils.FormatTimeForDisplay(db.BuildTime())
	info["languages"] = db.Languages()
	info["fields"] = db.Fields()

	// 添加路径信息，便于调试
	info["db_path"] = getIPDBPath()
	if cwd, err := os.Getwd(); err == nil {
		info["working_dir"] = cwd
	}
	if exePath, err := os.Executable(); err == nil {
		info["exe_dir"] = filepath.Dir(exePath)
	}

	return info, nil
}
