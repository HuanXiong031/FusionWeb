package service

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/core/utils"
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/cli"
	"FusionWeb/backend/engine/common"
	"FusionWeb/backend/engine/lib/ddfinger"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/storage"
	backendUtils "FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	httpxlib "github.com/projectdiscovery/httpx"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/runner"
	"gopkg.in/yaml.v3"
)

// ScanService 扫描服务
type ScanService struct {
	taskID   string
	taskType string
	userID   int
	ctx      context.Context
	// 任务专属的协议映射，避免多任务并发时的数据污染
	portProtocolMap map[string]string
	protocolMapLock sync.Mutex
	// 任务实例状态（两级隔离：任务类型+任务实例）
	taskInstanceState *structs.TaskInstanceState
	// 进度更新回调函数（可选）
	onProgressUpdate   func(stage string, scanned, total int, basePercentage, stageWeight float64)
	portResultSaveLock sync.Mutex
}

type portScanTaskOptions struct {
	Tool                  string   `json:"tool"`
	ScanType              string   `json:"scanType"`
	Retries               int      `json:"retries"`
	IdentifyService       *bool    `json:"identifyService"`
	EnableServiceIdentify *bool    `json:"enableServiceIdentify"`
	ExcludeTargets        []string `json:"excludeTargets"`
}

// NewScanService 创建扫描服务
func NewScanService(taskID string, ctx context.Context) *ScanService {
	// 从数据库查询任务类型
	var taskType string
	query := `SELECT task_type FROM task_config WHERE task_id = ?`
	_ = database.DB.QueryRow(query, taskID).Scan(&taskType)
	if taskType == "" {
		taskType = "web" // 默认任务类型
	}
	taskType = strings.ToLower(strings.TrimSpace(taskType))

	// 查询用户ID
	var userID int
	_ = database.DB.QueryRow(`SELECT COALESCE(user_id, 0) FROM task_config WHERE task_id = ?`, taskID).Scan(&userID)

	// 获取任务实例状态
	taskInstanceState := structs.GetOrCreateTaskInstanceState(taskID, taskType)
	taskInstanceState.EnsureCaches()

	return &ScanService{
		taskID:            taskID,
		taskType:          taskType,
		userID:            userID,
		ctx:               ctx,
		portProtocolMap:   make(map[string]string),
		taskInstanceState: taskInstanceState,
		onProgressUpdate:  nil, // 默认不设置，由调用者设置
	}
}

func normalizeReconURLTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return parsed.String()
}

func reconURLTargetVariants(raw string) []string {
	canonical := normalizeReconURLTarget(raw)
	variants := []string{canonical}

	parsed, err := url.Parse(canonical)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" {
		return variants
	}

	parsed.Path = "/"
	withSlash := parsed.String()
	if withSlash != canonical {
		variants = append(variants, withSlash)
	}
	return variants
}

func reconExtraDataString(extraData []byte) string {
	if extraData == nil {
		return ""
	}
	return string(extraData)
}

func stringFromAny(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func isRetryableDBError(err error) bool {
	if err == nil {
		return false
	}
	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "deadlock detected") ||
		strings.Contains(errText, "lock timeout") ||
		strings.Contains(errText, "could not serialize access")
}

func retryReconWrite(write func(timeStr string) error) error {
	var err error
	for i := 0; i < 3; i++ {
		err = write(backendUtils.GetCurrentTimeString())
		if err == nil {
			return nil
		}
		if !isRetryableDBError(err) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func responseURL(resp runner.Result) string {
	if resp.HeadlessURL != "" {
		return resp.HeadlessURL
	}
	if resp.FinalURL != "" {
		return resp.FinalURL
	}
	return resp.URL
}

func splitRootURLAndPath(raw string) (string, string) {
	parsed, err := url.Parse(normalizeReconURLTarget(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "/"
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host), path
}

func joinRootURLPath(rootURL, path string) string {
	rootURL = strings.TrimRight(strings.TrimSpace(rootURL), "/")
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return rootURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return rootURL + path
}

func parseHTTPXPort(port string) int {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return portInt
}

func httpxResponseHashes(resp runner.Result) (string, string) {
	var bodyHash, headerHash string
	if resp.Hashes != nil {
		if value, ok := resp.Hashes["body_md5"].(string); ok {
			bodyHash = value
		}
		if value, ok := resp.Hashes["header_md5"].(string); ok {
			headerHash = value
		}
	}
	if bodyHash == "" {
		bodyHash = fmt.Sprintf("empty_%d", resp.StatusCode)
	}
	if headerHash == "" {
		headerHash = fmt.Sprintf("empty_header_%d", resp.StatusCode)
	}
	return bodyHash, headerHash
}

func (s *ScanService) urlPathEntityFromHTTPX(resp runner.Result, bodyHash, headerHash string) structs.UrlPathEntity {
	return structs.UrlPathEntity{
		Hash:             bodyHash,
		Title:            resp.Title,
		FinalURL:         responseURL(resp),
		StatusCode:       resp.StatusCode,
		ContentType:      resp.ContentType,
		Server:           resp.WebServer,
		ContentLength:    resp.ContentLength,
		HeaderHashString: headerHash,
		IconHash:         resp.FavIconMMH3,
		ScreenshotPath:   s.uploadScreenshotObjectFromBytes(responseURL(resp), resp.ScreenshotBytes),
	}
}

func upsertURLPath(urlMap map[string]structs.URLEntity, rootURL, path string, resp runner.Result, pathEntity structs.UrlPathEntity) bool {
	if current, ok := urlMap[rootURL]; ok {
		if current.WebPaths == nil {
			current.WebPaths = make(map[string]structs.UrlPathEntity)
		}
		if _, exists := current.WebPaths[path]; exists {
			return false
		}
		current.WebPaths[path] = pathEntity
		urlMap[rootURL] = current
		return true
	}

	urlMap[rootURL] = structs.URLEntity{
		IP:   resp.Host,
		Port: parseHTTPXPort(resp.Port),
		WebPaths: map[string]structs.UrlPathEntity{
			path: pathEntity,
		},
	}
	return true
}

func reconURLExtraJSON(statusCode int, title string, contentLength int) []byte {
	extraData := map[string]interface{}{
		"status_code": statusCode,
		"title":       title,
		"length":      contentLength,
	}
	extraJSON, _ := json.Marshal(extraData)
	return extraJSON
}

func reconURLPathExtraJSON(pathEntity structs.UrlPathEntity) []byte {
	extraData := map[string]interface{}{
		"status_code":  pathEntity.StatusCode,
		"title":        pathEntity.Title,
		"length":       pathEntity.ContentLength,
		"content_type": pathEntity.ContentType,
		"server":       pathEntity.Server,
	}
	if pathEntity.FinalURL != "" {
		extraData["final_url"] = pathEntity.FinalURL
		extraData["display_url"] = pathEntity.FinalURL
	}
	if pathEntity.ScreenshotPath != "" {
		extraData["screenshot_key"] = pathEntity.ScreenshotPath
		extraData["screenshot_path"] = pathEntity.ScreenshotPath
	}
	if pathEntity.IconHash != "" {
		extraData["icon_hash"] = pathEntity.IconHash
	}
	if pathEntity.Hash != "" {
		extraData["body_hash"] = pathEntity.Hash
	}
	if pathEntity.HeaderHashString != "" {
		extraData["header_hash"] = pathEntity.HeaderHashString
	}
	extraJSON, _ := json.Marshal(extraData)
	return extraJSON
}

func (s *ScanService) uploadScreenshotObjectFromBytes(targetURL string, screenshotBytes []byte) string {
	if len(screenshotBytes) == 0 {
		return ""
	}
	key := s.screenshotObjectKey(targetURL, screenshotBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := storage.UploadBytes(ctx, key, screenshotBytes, "image/png"); err != nil {
		s.logWarning(fmt.Sprintf("上传截图到 MinIO 失败: %v", err))
		return ""
	}
	return key
}

func (s *ScanService) screenshotObjectKey(targetURL string, screenshotBytes []byte) string {
	contentSum := fmt.Sprintf("%x", sha1.Sum(screenshotBytes))
	sum := fmt.Sprintf("%x", sha1.Sum([]byte(normalizeReconURLTarget(targetURL)+"|"+contentSum)))
	return fmt.Sprintf("screenshots/%s/%s.png", safeObjectSegment(s.taskID), sum)
}

func safeObjectSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "default"
	}
	return builder.String()
}

func matchedActiveFingerprintPaths(path string) []string {
	var matched []string
	for dbPath := range structs.DirDB {
		if strings.HasSuffix(path, dbPath) {
			matched = append(matched, dbPath)
		}
	}
	return matched
}

func isActiveFingerprintPath(path string) bool {
	return len(matchedActiveFingerprintPaths(path)) > 0
}

func responseTLSString(resp runner.Result) string {
	if resp.TLSData == nil {
		return ""
	}
	return fmt.Sprintf("SubjectCN: %s\nIssuerCN: %s\n", resp.TLSData.SubjectCN, resp.TLSData.IssuerCN)
}

func responseBodyMD5ForFingerprint(resp runner.Result) string {
	if resp.Hashes != nil {
		if value, ok := resp.Hashes["body_md5"].(string); ok {
			return value
		}
	}
	return "0"
}

func responsePortForFingerprint(resp runner.Result) int {
	portInt, err := strconv.Atoi(resp.Port)
	if err != nil {
		return -1
	}
	return portInt
}

func matchActiveFingerprintResponse(resp runner.Result, matchedPaths []string, allowPathOnly bool) (bool, string) {
	if len(matchedPaths) == 0 {
		return false, ""
	}
	if len(structs.FingerprintDB) == 0 {
		return allowPathOnly, ""
	}

	tlsString := responseTLSString(resp)
	bodyHash := responseBodyMD5ForFingerprint(resp)
	portInt := responsePortForFingerprint(resp)
	for _, path := range matchedPaths {
		for _, productName := range structs.DirDB[path] {
			for _, fingerprint := range structs.FingerprintDB {
				if fingerprint.ProductName != productName {
					continue
				}
				if ddfinger.SingleCheck(fingerprint, resp.Scheme, resp.Header, resp.Body, resp.WebServer, resp.Title, tlsString,
					portInt, resp.Path, bodyHash, resp.FavIconMMH3, resp.StatusCode, resp.ContentType, "") {
					return true, productName
				}
			}
		}
	}
	return false, ""
}

func activeFingerprintResultInfo(rootURL, path string, pathEntity structs.UrlPathEntity) map[string]interface{} {
	return map[string]interface{}{
		"url":          normalizeReconURLTarget(joinRootURLPath(rootURL, path)),
		"root_url":     rootURL,
		"path":         path,
		"status_code":  pathEntity.StatusCode,
		"title":        pathEntity.Title,
		"content_type": pathEntity.ContentType,
		"server":       pathEntity.Server,
		"length":       pathEntity.ContentLength,
		"hash":         pathEntity.Hash,
		"header_hash":  pathEntity.HeaderHashString,
		"icon_hash":    pathEntity.IconHash,
	}
}

func collectSuccessfulURLs(urlMap map[string]structs.URLEntity) map[string]bool {
	successful := make(map[string]bool)
	for rootURL, urlEntity := range urlMap {
		successful[normalizeReconURLTarget(rootURL)] = true
		for path := range urlEntity.WebPaths {
			successful[normalizeReconURLTarget(joinRootURLPath(rootURL, path))] = true
		}
	}
	return successful
}

func countURLPaths(urlMap map[string]structs.URLEntity) int {
	count := 0
	for _, urlEntity := range urlMap {
		count += len(urlEntity.WebPaths)
	}
	return count
}

func (s *ScanService) markPendingURLSeen(urls ...string) {
	seen := make(map[string]struct{})
	for _, rawURL := range urls {
		for _, target := range reconURLTargetVariants(rawURL) {
			if target == "" {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			_, _ = database.DB.Exec(`
				UPDATE recon_results
				SET source = 'httpx'
				WHERE task_id = ? AND result_type = 'url' AND target = ? AND source = 'httpx-pending'
			`, s.taskID, target)
		}
	}
}

func (s *ScanService) markPendingURLsFailed(successfulURLs map[string]bool) {
	query := "UPDATE recon_results SET source = 'httpx-failed' WHERE task_id = ? AND result_type = 'url' AND source = 'httpx-pending'"
	args := []interface{}{s.taskID}

	if len(successfulURLs) > 0 {
		placeholders := make([]string, 0, len(successfulURLs))
		for target := range successfulURLs {
			placeholders = append(placeholders, "?")
			args = append(args, target)
		}
		query += fmt.Sprintf(" AND target NOT IN (%s)", strings.Join(placeholders, ","))
	}

	result, err := database.DB.Exec(query, args...)
	if err != nil {
		logger.Debug("[任务 %s] [web] 标记探测失败URL失败: %v", s.taskID, err)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		logger.Debug("[任务 %s] [web] 标记了 %d 个探测失败的URL记录", s.taskID, rowsAffected)
		s.logInfo(fmt.Sprintf("标记了 %d 个探测失败的URL", rowsAffected))
	}
}

func (s *ScanService) findURLReconID(variants []string) int {
	for _, variant := range variants {
		var existingID int
		err := database.DB.QueryRow(`
			SELECT id FROM recon_results
			WHERE task_id = ? AND result_type = 'url' AND target = ?
			ORDER BY CASE source
				WHEN 'httpx' THEN 0
				WHEN 'active-fingerprint' THEN 1
				WHEN 'httpx-pending' THEN 2
				WHEN 'httpx-failed' THEN 3
				ELSE 4
			END, id
			LIMIT 1
		`, s.taskID, variant).Scan(&existingID)
		if err == nil {
			return existingID
		}
	}
	return 0
}

func (s *ScanService) deleteDuplicateURLVariants(variants []string, keepID int) {
	for _, variant := range variants {
		_, _ = database.DB.Exec(`
			DELETE FROM recon_results
			WHERE task_id = ? AND result_type = 'url' AND target = ? AND id <> ?
		`, s.taskID, variant, keepID)
	}
}

func (s *ScanService) cacheAndUpsertURLPath(urlMap map[string]structs.URLEntity, rootURL, path string, resp runner.Result) bool {
	bodyHash, headerHash := httpxResponseHashes(resp)
	s.cacheHTTPResponse(bodyHash, headerHash, resp.Body, resp.Header)
	return upsertURLPath(urlMap, rootURL, path, resp, s.urlPathEntityFromHTTPX(resp, bodyHash, headerHash))
}

func (s *ScanService) expandWebProbeTargets(targets []string) []string {
	var urls []string
	appendWithSchemes := func(target string) {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			urls = append(urls, target)
			return
		}
		urls = append(urls, "http://"+target, "https://"+target)
	}

	for _, rawTarget := range targets {
		for _, token := range strings.Split(rawTarget, ",") {
			target := strings.TrimSpace(token)
			if target == "" {
				continue
			}

			switch utils.GetInputType(target) {
			case structs.TypeCIDR:
				logger.Debug("[任务 %s] [web] 检测到 CIDR 网段: %s，展开为 IP 列表", s.taskID, target)
				for _, ip := range utils.CIDRToIP(target) {
					appendWithSchemes(ip.String())
				}
			case structs.TypeIPRange:
				logger.Debug("[任务 %s] [web] 检测到 IP 段: %s，展开为 IP 列表", s.taskID, target)
				for _, ip := range utils.RangerToIP(target) {
					appendWithSchemes(ip.String())
				}
			default:
				appendWithSchemes(target)
			}
		}
	}
	return urls
}

func (s *ScanService) rootURLsFromInputs(urls []string) []string {
	var rootURLs []string
	seen := make(map[string]struct{})
	for _, rawURL := range urls {
		rootURL, _ := splitRootURLAndPath(rawURL)
		if rootURL == "" {
			s.logWarning(fmt.Sprintf("无法解析 URL: %s", rawURL))
			continue
		}
		if _, ok := seen[rootURL]; ok {
			continue
		}
		rootURLs = append(rootURLs, rootURL)
		seen[rootURL] = struct{}{}
	}
	return rootURLs
}

// SetProgressCallback 设置进度更新回调函数
func (s *ScanService) SetProgressCallback(callback func(stage string, scanned, total int, basePercentage, stageWeight float64)) {
	s.onProgressUpdate = callback
}

// SystemResources 系统资源信息
type SystemResources struct {
	CPUCores           int     // CPU核心数
	TotalMemoryGB      float64 // 总内存（GB）
	AvailableMemoryGB  float64 // 可用内存（GB）
	MemoryUsagePercent float64 // 内存使用率（百分比）
}

var (
	systemResourcesCache     *SystemResources
	systemResourcesCacheLock sync.Mutex
	systemResourcesCacheTime time.Time
	cacheExpiry              = 30 * time.Second // 缓存30秒
)

// getSystemResources 获取系统资源信息（带缓存）
func getSystemResources() SystemResources {
	systemResourcesCacheLock.Lock()
	defer systemResourcesCacheLock.Unlock()

	// 如果缓存有效，直接返回
	if systemResourcesCache != nil && time.Since(systemResourcesCacheTime) < cacheExpiry {
		return *systemResourcesCache
	}

	// 获取CPU核心数
	cpuCores := runtime.NumCPU()

	// 获取内存信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 转换为GB
	totalMemoryBytes := m.Sys   // 系统总内存
	allocMemoryBytes := m.Alloc // 当前已分配内存
	availableMemoryBytes := totalMemoryBytes - allocMemoryBytes

	totalMemoryGB := float64(totalMemoryBytes) / (1024 * 1024 * 1024)
	availableMemoryGB := float64(availableMemoryBytes) / (1024 * 1024 * 1024)

	// 计算内存使用率
	var memoryUsagePercent float64
	if totalMemoryBytes > 0 {
		memoryUsagePercent = float64(allocMemoryBytes) * 100.0 / float64(totalMemoryBytes)
	}

	resources := SystemResources{
		CPUCores:           cpuCores,
		TotalMemoryGB:      totalMemoryGB,
		AvailableMemoryGB:  availableMemoryGB,
		MemoryUsagePercent: memoryUsagePercent,
	}

	// 更新缓存
	systemResourcesCache = &resources
	systemResourcesCacheTime = time.Now()

	return resources
}

// calculateOptimalThreadCount 根据目标数量和服务器配置动态计算最优并发线程数
// 性能优化：自动根据CPU核心数、内存和目标数量调整并发参数
func calculateOptimalThreadCount(targetCount int, baseThreadCount int) int {
	const (
		veryLargeThreshold = 500 // 超大目标数量阈值
		largeThreshold     = 60  // 大目标数量阈值
		mediumThreshold    = 20  // 中等目标数量阈值
		defaultThreads     = 100
	)

	requestedThreads := baseThreadCount
	if requestedThreads <= 0 {
		requestedThreads = defaultThreads
	}

	// 获取系统资源
	resources := getSystemResources()
	cpuCores := resources.CPUCores
	if cpuCores <= 0 {
		cpuCores = 1
	}
	availableMemoryGB := resources.AvailableMemoryGB
	memoryUsagePercent := resources.MemoryUsagePercent

	// 根据CPU核心数和内存计算基础并发能力
	// CPU限制：每个核心可支持20-50个并发线程
	cpuBasedThreads := cpuCores * 30 // 每个核心30个并发（中等配置）

	// runtime.MemStats 只能反映 Go 运行时内存，不等于系统物理内存。
	// 这里不再用它强行压低并发，只作为日志参考；真正的连接资源上限在端口扫描核心按 fd limit 兜底。
	systemCapacity := cpuBasedThreads
	if systemCapacity <= 0 {
		systemCapacity = 1
	}

	// 根据目标数量计算建议的并发数
	var targetBasedThreads int
	if targetCount >= veryLargeThreshold {
		// 超大目标（>=500）：使用高并发配置
		targetBasedThreads = 200
	} else if targetCount >= largeThreshold {
		// 大目标（>=60）：使用中等并发配置
		targetBasedThreads = 100
	} else if targetCount >= mediumThreshold {
		// 中等目标（>=20）：使用标准并发配置
		targetBasedThreads = 50
	} else {
		// 小目标（<20）：使用轻量并发，避免少量目标时也开启过多连接。
		targetBasedThreads = 30
	}

	// 取目标建议、系统能力和用户配置的最小值。
	// 用户配置是期望上限，不再作为必须达到的下限，避免 Linux 低 fd 上限下
	// 1000 并发扫描把同进程 Web 服务的连接资源耗尽。
	optimalThreads := targetBasedThreads
	if systemCapacity < optimalThreads {
		optimalThreads = systemCapacity
	}
	if requestedThreads < optimalThreads {
		optimalThreads = requestedThreads
	}
	if targetCount > 0 && targetCount < optimalThreads {
		optimalThreads = targetCount
	}
	if optimalThreads <= 0 {
		optimalThreads = 1
	}

	logger.Debug("并发优化: 目标数=%d, CPU核心=%d, 可用内存=%.1fGB, 内存使用率=%.1f%%, "+
		"CPU能力=%d, 系统能力=%d, 目标建议=%d, 用户线程上限=%d -> 最终线程=%d",
		targetCount, cpuCores, availableMemoryGB, memoryUsagePercent,
		cpuBasedThreads, systemCapacity, targetBasedThreads, requestedThreads, optimalThreads)

	return optimalThreads
}

// RunPortScan runs port discovery through external CLI tools and stores one
// structured port record per open host:port.
func (s *ScanService) RunPortScan(targets []string, config *models.TaskConfig) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	var portOptions portScanTaskOptions
	decodeTaskScanOptions(config, &portOptions)

	s.taskInstanceState.EnsureCaches()
	common.ResetAliveState()

	if _, err := database.DB.Exec(`DELETE FROM recon_results WHERE task_id = ? AND result_type IN ('port', 'protocol')`, s.taskID); err != nil {
		s.logWarning(fmt.Sprintf("清理旧端口结果失败: %v", err))
	}

	ipHosts, hostTargets, explicitTargets := s.classifyPortServiceTargets(targets)
	if len(portOptions.ExcludeTargets) > 0 {
		ipHosts = subtractStrings(ipHosts, portOptions.ExcludeTargets)
		hostTargets = subtractStrings(hostTargets, portOptions.ExcludeTargets)
		explicitTargets = subtractStrings(explicitTargets, portOptions.ExcludeTargets)
	}
	if !config.SkipHostDiscovery && len(ipHosts) > 0 {
		ipHosts = s.discoverAliveHosts(ipHosts, config)
	}

	scanHosts := utils.RemoveDuplicateElement(append(ipHosts, hostTargets...))
	explicitTargets = utils.RemoveDuplicateElement(explicitTargets)
	if len(scanHosts) == 0 && len(explicitTargets) == 0 {
		return nil, fmt.Errorf("没有可用的端口扫描目标")
	}

	portRange := strings.TrimSpace(config.PortRange)
	if portRange == "" && len(scanHosts) > 0 {
		return nil, fmt.Errorf("端口范围不能为空")
	}

	timeout := config.PortScanTimeout
	if timeout <= 0 {
		timeout = 3
	}
	estimatedTasks := len(explicitTargets) + len(scanHosts)*len(common.ParsePort(portRange))
	if estimatedTasks <= 0 {
		estimatedTasks = len(targets)
	}
	threads := calculateOptimalThreadCount(estimatedTasks, config.ThreadCount)
	if threads <= 0 {
		threads = 100
	}

	structs.GlobalConfig.Ports = portRange
	structs.GlobalConfig.NoPortString = config.NoPortString
	structs.GlobalConfig.TCPPortScanThreads = threads
	structs.GlobalConfig.TCPPortScanTimeout = timeout
	structs.GlobalConfig.PortsThreshold = config.PortsThreshold

	scanTool := strings.TrimSpace(config.ScanTool)
	if scanTool == "" {
		scanTool = strings.TrimSpace(portOptions.Tool)
	}
	identifyService := true
	if portOptions.IdentifyService != nil {
		identifyService = *portOptions.IdentifyService
	}
	if portOptions.EnableServiceIdentify != nil {
		identifyService = *portOptions.EnableServiceIdentify
	}

	s.logInfo(fmt.Sprintf("开始 CLI 端口服务扫描，工具: %s，主机数: %d，指定端口目标: %d，端口范围: %s，线程数: %d", firstNonEmptyString(scanTool, "naabu"), len(scanHosts), len(explicitTargets), portRange, threads))
	results, err := cli.RunPortScan(s.ctx, cli.PortScanOptions{
		Hosts:             scanHosts,
		ExplicitTargets:   explicitTargets,
		Ports:             portRange,
		NoPorts:           config.NoPortString,
		Tool:              scanTool,
		ScanType:          portOptions.ScanType,
		Retries:           portOptions.Retries,
		Rate:              config.SYNScanRate,
		TimeoutSeconds:    timeout,
		Threads:           threads,
		PortsThreshold:    config.PortsThreshold,
		SkipHostDiscovery: true,
		IdentifyService:   identifyService,
		Logf: func(level, format string, args ...interface{}) {
			message := fmt.Sprintf(format, args...)
			switch strings.ToUpper(level) {
			case "ERROR":
				s.logError(message)
			case "WARN":
				s.logWarning(message)
			case "DEBUG":
				logger.Debug("[任务 %s] [recon] %s", s.taskID, message)
			default:
				s.logInfo(message)
			}
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CLI 端口扫描失败: %w", err)
	}

	results = dedupePortServiceResults(results)
	if err := s.replacePortServiceResults(results); err != nil {
		s.logError(fmt.Sprintf("收敛端口服务结果失败: %v", err))
	}
	hostPorts := make([]string, 0, len(results))
	for _, result := range results {
		hostPorts = append(hostPorts, result.HostPort())
	}

	s.logInfo(fmt.Sprintf("端口服务扫描完成，共 %d 个开放端口", len(hostPorts)))
	return hostPorts, nil
}

func (s *ScanService) classifyPortServiceTargets(targets []string) (ipHosts []string, hostTargets []string, explicitTargets []string) {
	for _, rawTarget := range targets {
		target := strings.TrimSpace(rawTarget)
		if target == "" {
			continue
		}

		if strings.Contains(target, "://") {
			host, port, ok := hostPortFromURL(target)
			if ok {
				explicitTargets = append(explicitTargets, net.JoinHostPort(host, port))
				continue
			}
			s.logWarning(fmt.Sprintf("无法解析 URL 目标: %s", target))
			continue
		}

		switch utils.GetInputType(target) {
		case structs.TypeIP:
			ipHosts = append(ipHosts, target)
		case structs.TypeCIDR:
			ipList := utils.CIDRToIP(target)
			s.logInfo(fmt.Sprintf("检测到 CIDR 网段: %s，展开为 %d 个 IP", target, len(ipList)))
			for _, ip := range ipList {
				ipHosts = append(ipHosts, ip.String())
			}
		case structs.TypeIPRange:
			ipList := utils.RangerToIP(target)
			s.logInfo(fmt.Sprintf("检测到 IP 范围: %s，展开为 %d 个 IP", target, len(ipList)))
			for _, ip := range ipList {
				ipHosts = append(ipHosts, ip.String())
			}
		case structs.TypeDomain:
			hostTargets = append(hostTargets, target)
		case structs.TypeIPPort, structs.TypeDomainPort:
			if hostPort, ok := normalizeExplicitPortTarget(target); ok {
				explicitTargets = append(explicitTargets, hostPort)
			} else {
				s.logWarning(fmt.Sprintf("无法解析端口目标: %s", target))
			}
		default:
			if hostPort, ok := normalizeExplicitPortTarget(target); ok {
				explicitTargets = append(explicitTargets, hostPort)
			} else {
				s.logWarning(fmt.Sprintf("跳过不支持的端口扫描目标: %s", target))
			}
		}
	}

	return utils.RemoveDuplicateElement(ipHosts), utils.RemoveDuplicateElement(hostTargets), utils.RemoveDuplicateElement(explicitTargets)
}

func (s *ScanService) discoverAliveHosts(ipHosts []string, config *models.TaskConfig) []string {
	ipHosts = utils.RemoveDuplicateElement(ipHosts)
	if len(ipHosts) == 0 {
		return ipHosts
	}

	s.logInfo(fmt.Sprintf("开始主机存活探测，共 %d 个 IP", len(ipHosts)))
	alive := make([]string, 0, len(ipHosts))
	if !config.NoICMPPing {
		s.logInfo("执行 ICMP 存活探测")
		alive = common.CheckLive(ipHosts, false)
		s.logInfo(fmt.Sprintf("ICMP 探测发现 %d 个存活主机", len(alive)))
	}

	if config.TCPPing {
		unchecked := subtractStrings(ipHosts, alive)
		if len(unchecked) > 0 {
			timeout := config.PortScanTimeout
			if timeout <= 0 {
				timeout = 3
			}
			threads := calculateOptimalThreadCount(len(unchecked)*5, config.ThreadCount)
			s.logInfo(fmt.Sprintf("执行 TCP 存活探测，待确认主机 %d 个", len(unchecked)))
			pingResults, err := cli.RunPortScan(s.ctx, cli.PortScanOptions{
				Hosts:             unchecked,
				Ports:             "80,443,3389,445,22",
				Rate:              config.SYNScanRate,
				TimeoutSeconds:    timeout,
				Threads:           threads,
				PortsThreshold:    config.PortsThreshold,
				SkipHostDiscovery: true,
				IdentifyService:   false,
				Logf: func(level, format string, args ...interface{}) {
					if strings.ToUpper(level) == "DEBUG" {
						logger.Debug("[任务 %s] [recon] %s", s.taskID, fmt.Sprintf(format, args...))
					}
				},
			})
			if err != nil {
				s.logWarning(fmt.Sprintf("TCP 存活探测 CLI 执行失败: %v", err))
			} else {
				before := len(alive)
				for _, result := range pingResults {
					alive = append(alive, result.Host)
				}
				alive = utils.RemoveDuplicateElement(alive)
				s.logInfo(fmt.Sprintf("TCP 探测新增 %d 个存活主机", len(alive)-before))
			}
		}
	}

	if len(alive) == 0 {
		s.logWarning("未发现存活主机，将继续扫描所有 IP")
		return ipHosts
	}
	s.logInfo(fmt.Sprintf("主机存活探测完成，剩余 %d 个目标", len(alive)))
	return alive
}

func subtractStrings(all []string, remove []string) []string {
	blocked := make(map[string]struct{}, len(remove))
	for _, item := range remove {
		blocked[item] = struct{}{}
	}
	out := make([]string, 0, len(all))
	for _, item := range all {
		if _, ok := blocked[item]; ok {
			continue
		}
		out = append(out, item)
	}
	return utils.RemoveDuplicateElement(out)
}

func normalizeExplicitPortTarget(target string) (string, bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", false
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if utils.IsPort(port) && strings.TrimSpace(host) != "" {
			return net.JoinHostPort(strings.Trim(host, "[]"), port), true
		}
		return "", false
	}
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return "", false
	}
	host := strings.TrimSpace(strings.Trim(target[:idx], "[]"))
	port := strings.TrimSpace(target[idx+1:])
	if host == "" || !utils.IsPort(port) {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

func hostPortFromURL(rawURL string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return "", "", false
	}
	host := strings.TrimSpace(parsed.Hostname())
	port := strings.TrimSpace(parsed.Port())
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", "", false
		}
	}
	return host, port, host != "" && utils.IsPort(port)
}

func dedupePortServiceResults(results []common.PortServiceResult) []common.PortServiceResult {
	seen := make(map[string]int, len(results))
	out := make([]common.PortServiceResult, 0, len(results))
	for _, result := range results {
		key := result.HostPort()
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			if portServiceResultScore(result) > portServiceResultScore(out[idx]) {
				out[idx] = result
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, result)
	}
	return out
}

func portServiceResultScore(result common.PortServiceResult) int {
	score := 0
	if result.Protocol != "" && result.Protocol != "tcp" {
		score += 2
	}
	for _, value := range []string{result.Service, result.GuessedService, result.Product, result.Version, result.Info, result.Banner} {
		if strings.TrimSpace(value) != "" {
			score++
		}
	}
	return score
}

func portServiceResultExtraJSON(result common.PortServiceResult) []byte {
	protocol := strings.TrimSpace(result.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	detectedService := strings.TrimSpace(result.Service)
	guessedService := strings.TrimSpace(result.GuessedService)
	if guessedService == "" {
		guessedService = common.GuessPortService(result.Port)
	}
	service := detectedService
	if service == "" || strings.EqualFold(service, "tcp") {
		service = guessedService
	}
	extra := map[string]interface{}{
		"host":             result.Host,
		"ip":               result.Host,
		"port":             result.Port,
		"address":          result.HostPort(),
		"status":           "open",
		"protocol":         protocol,
		"service":          service,
		"detected_service": detectedService,
		"guessed_service":  guessedService,
		"product":          result.Product,
		"version":          result.Version,
		"info":             result.Info,
		"hostname":         result.Hostname,
		"os":               result.OS,
		"device":           result.Device,
		"probe_name":       result.ProbeName,
		"tls":              result.TLS,
		"banner":           result.Banner,
	}
	extraJSON, _ := json.Marshal(extra)
	return extraJSON
}

func (s *ScanService) savePortServiceResult(result common.PortServiceResult) error {
	if result.Host == "" || result.Port <= 0 {
		return fmt.Errorf("端口服务结果不完整: %s", result.String())
	}
	protocol := strings.TrimSpace(result.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}
	hostPort := result.HostPort()
	extraJSON := portServiceResultExtraJSON(result)

	s.protocolMapLock.Lock()
	s.portProtocolMap[hostPort] = protocol
	s.taskInstanceState.IPPortMap[hostPort] = protocol
	s.protocolMapLock.Unlock()

	if result.Banner != "" && s.taskInstanceState.BannerHMap != nil {
		_ = s.taskInstanceState.BannerHMap.Set(hostPort, []byte(result.Banner))
	}
	structs.GlobalIPPortMapLock.Lock()
	if structs.GlobalIPPortMap == nil {
		structs.GlobalIPPortMap = make(map[string]string)
	}
	structs.GlobalIPPortMap[hostPort] = protocol
	structs.GlobalIPPortMapLock.Unlock()
	if result.Banner != "" && structs.GlobalBannerHMap != nil {
		_ = structs.GlobalBannerHMap.Set(hostPort, []byte(result.Banner))
	}

	return s.saveReconResult("port", hostPort, "port-service", extraJSON)
}

func (s *ScanService) handlePortServiceResult(result common.PortServiceResult) {
	if result.Host == "" || result.Port <= 0 {
		return
	}
	s.portResultSaveLock.Lock()
	defer s.portResultSaveLock.Unlock()
	if err := s.savePortServiceResult(result); err != nil {
		s.logError(fmt.Sprintf("保存端口服务结果失败: %v", err))
		return
	}
	hostPort := result.HostPort()
	websocket.BroadcastRecon(s.taskID, "port", hostPort, "port-service")
}

func (s *ScanService) replacePortServiceResults(results []common.PortServiceResult) error {
	s.portResultSaveLock.Lock()
	defer s.portResultSaveLock.Unlock()

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM recon_results WHERE task_id = ? AND result_type = 'port'`, s.taskID); err != nil {
		return err
	}
	for _, result := range results {
		if result.Host == "" || result.Port <= 0 {
			continue
		}
		protocol := strings.TrimSpace(result.Protocol)
		if protocol == "" {
			protocol = "tcp"
		}
		hostPort := result.HostPort()
		extraJSON := reconExtraDataString(portServiceResultExtraJSON(result))
		now := backendUtils.FormatTimeForDisplay(time.Now())
		if _, err := tx.Exec(`
			INSERT INTO recon_results (task_id, scan_scope, user_id, result_type, target, source, extra_data, discovered_at)
			VALUES (?, ?, ?, 'port', ?, 'port-service', ?, ?)
		`, s.taskID, s.taskType, s.userID, hostPort, extraJSON, now); err != nil {
			return err
		}
		s.protocolMapLock.Lock()
		s.portProtocolMap[hostPort] = protocol
		s.taskInstanceState.IPPortMap[hostPort] = protocol
		s.protocolMapLock.Unlock()
	}

	return tx.Commit()
}

// RunActiveFingerprintDetection 运行主动指纹探测（目录路径探测）
// 兼容旧接口，内部调用 RunActiveFingerprintDetectionWithURLs
func (s *ScanService) RunActiveFingerprintDetection(config *models.TaskConfig) error {
	// 获取已发现的 URL 列表
	var urls []string
	taskMap := s.taskInstanceState.URLMap
	if len(taskMap) == 0 {
		// 兼容旧代码：尝试从 TaskURLMaps 获取
		structs.TaskURLMapsLock.Lock()
		if taskMapFromGlobal, exists := structs.TaskURLMaps[s.taskID]; exists {
			taskMap = taskMapFromGlobal
		}
		structs.TaskURLMapsLock.Unlock()
	}

	if len(taskMap) == 0 {
		s.logWarning("没有已发现的 URL，跳过主动指纹探测")
		return nil
	}

	// 从 taskMap 中提取所有 rootURL
	for rootURL := range taskMap {
		urls = append(urls, rootURL)
	}

	return s.RunActiveFingerprintDetectionWithURLs(urls, config)
}

// RunActiveFingerprintDetectionWithURLs 运行主动指纹探测（目录路径探测），使用指定的 URLs
func (s *ScanService) RunActiveFingerprintDetectionWithURLs(urls []string, config *models.TaskConfig) error {
	// 检查是否启用主动指纹探测
	if !config.EnableActiveFingerprint {
		s.logInfo("主动指纹探测未启用，跳过目录字典扫描")
		return nil
	}

	s.logInfo("主动指纹探测已启用，从数据库加载目录字典")

	// 从数据库加载目录字典
	common.ReadDirDBFromDatabase()
	if len(structs.DirDB) == 0 {
		s.logWarning("主动指纹字典为空，跳过主动指纹探测")
		return nil
	}

	s.logInfo(fmt.Sprintf("主动指纹字典已加载，共 %d 条路径", len(structs.DirDB)))

	// 确保指纹库已加载（用于指纹匹配验证）
	// 如果指纹库未加载，初始化指纹库
	if len(structs.FingerprintDB) == 0 {
		s.logInfo("指纹库未加载，正在初始化指纹库...")
		s.initFingerprintDBIfNeeded()
		if len(structs.FingerprintDB) == 0 {
			s.logWarning("指纹库初始化失败，主动指纹探测将无法进行指纹匹配验证，将保存所有匹配路径的响应")
		} else {
			s.logInfo(fmt.Sprintf("指纹库初始化成功，共 %d 条规则，将进行指纹匹配验证", len(structs.FingerprintDB)))
		}
	} else {
		s.logInfo(fmt.Sprintf("指纹库已加载，共 %d 条规则，将进行指纹匹配验证", len(structs.FingerprintDB)))
	}

	rootURLs := s.rootURLsFromInputs(urls)

	if len(rootURLs) == 0 {
		s.logWarning(fmt.Sprintf("没有可用的 URL 进行主动指纹探测。输入的 URLs: %d 个，提取的 rootURLs: %d 个", len(urls), len(rootURLs)))
		if len(urls) > 0 {
			exampleCount := 3
			if len(urls) < exampleCount {
				exampleCount = len(urls)
			}
			s.logInfo(fmt.Sprintf("输入的 URLs 示例: %v", urls[:exampleCount]))
		}
		return nil
	}

	s.logInfo(fmt.Sprintf("开始主动指纹探测，输入的 URLs: %d 个，提取的 rootURLs: %d 个", len(urls), len(rootURLs)))
	s.logInfo(fmt.Sprintf("rootURLs 列表: %v", rootURLs))

	// 当前调用内的目录探测结果，结束后再合并进任务状态。
	taskURLMap := make(map[string]structs.URLEntity)
	var taskURLMapLock sync.Mutex

	// 定义目录爆破的回调函数
	dirBruteCallback := func(resp runner.Result) {
		rootURL, pth := splitRootURLAndPath(responseURL(resp))
		if rootURL == "" {
			return
		}

		matchedPaths := matchedActiveFingerprintPaths(resp.Path)
		matched, matchedProductName := matchActiveFingerprintResponse(resp, matchedPaths, true)
		if !matched {
			return
		}

		taskURLMapLock.Lock()
		s.cacheAndUpsertURLPath(taskURLMap, rootURL, pth, resp)
		taskURLMapLock.Unlock()

		productInfo := ""
		if matchedProductName != "" {
			productInfo = fmt.Sprintf(", 产品: %s", matchedProductName)
		}
		s.logInfo(fmt.Sprintf("主动指纹探测发现路径: %s (状态码: %d%s)", resp.URL, resp.StatusCode, productInfo))
	}

	// 使用配置的超时时间，如果未设置则默认20秒
	webTimeout := 20
	if config.WebTimeout > 0 {
		webTimeout = config.WebTimeout
	}

	// 性能优化：根据目标数量动态调整并发线程数
	optimalThreads := calculateOptimalThreadCount(len(rootURLs), config.ThreadCount)
	s.logInfo(fmt.Sprintf("主动指纹探测并发优化: rootURL数=%d, 基础线程=%d -> 优化线程=%d", len(rootURLs), config.ThreadCount, optimalThreads))

	// 执行目录爆破
	httpxlib.DirBrute(rootURLs, dirBruteCallback, config.HTTPProxy, optimalThreads, webTimeout, s.taskID, config.EnableScreenshot)

	// 将发现的路径合并到任务实例状态
	if len(taskURLMap) > 0 {
		taskURLMapLock.Lock()

		// 收集所有发现的路径信息，用于保存到文件。
		var activeFingerprintResults []map[string]interface{}

		for rootURL, urlEntity := range taskURLMap {
			// 合并到任务实例状态
			if existingEntity, exists := s.taskInstanceState.URLMap[rootURL]; exists {
				// 合并 WebPaths
				for path, pathEntity := range urlEntity.WebPaths {
					existingEntity.WebPaths[path] = pathEntity
				}
				s.taskInstanceState.URLMap[rootURL] = existingEntity
			} else {
				s.taskInstanceState.URLMap[rootURL] = urlEntity
			}

			// 同时保存到数据库和收集结果
			for path, pathEntity := range urlEntity.WebPaths {
				fullURL := normalizeReconURLTarget(joinRootURLPath(rootURL, path))
				extraJSON := reconURLPathExtraJSON(pathEntity)
				if err := s.saveReconResult("url", fullURL, "active-fingerprint", extraJSON); err != nil {
					s.logError(fmt.Sprintf("保存主动指纹探测结果失败: %v", err))
				}
				urlEntity.WebPaths[path] = pathEntity

				activeFingerprintResults = append(activeFingerprintResults, activeFingerprintResultInfo(rootURL, path, pathEntity))
			}
		}
		taskURLMapLock.Unlock()

		// 保存主动指纹探测的详细信息到文件。
		if len(activeFingerprintResults) > 0 {
			if err := s.saveActiveFingerprintResultsToFile(activeFingerprintResults, config); err != nil {
				s.logWarning(fmt.Sprintf("保存主动指纹探测结果到文件失败: %v", err))
			} else {
				s.logInfo(fmt.Sprintf("主动指纹探测结果已保存到文件，共 %d 条记录", len(activeFingerprintResults)))
			}
		}

		s.logInfo(fmt.Sprintf("主动指纹探测完成，发现 %d 个新路径", countURLPaths(taskURLMap)))
	} else {
		s.logInfo("主动指纹探测完成，未发现新路径")
	}

	return nil
}

// runActiveFingerprintInWebProbe 在 Web 探测阶段执行主动指纹探测，只保存状态码为 200 的路径到 taskURLMap
func (s *ScanService) runActiveFingerprintInWebProbe(rootURLs []string, taskURLMap *map[string]structs.URLEntity, config *models.TaskConfig) error {
	// 检查是否启用主动指纹探测
	if !config.EnableActiveFingerprint {
		s.logInfo("主动指纹探测未启用，跳过目录字典扫描")
		return nil
	}

	s.logInfo("主动指纹探测已启用，从数据库加载目录字典")

	// 从数据库加载目录字典
	common.ReadDirDBFromDatabase()
	if len(structs.DirDB) == 0 {
		s.logWarning("主动指纹字典为空，跳过主动指纹探测")
		return nil
	}

	// 确保指纹库已加载
	if len(structs.FingerprintDB) == 0 {
		s.logInfo("指纹库未加载，正在初始化指纹库...")
		s.initFingerprintDBIfNeeded()
		if len(structs.FingerprintDB) == 0 {
			s.logWarning("指纹库初始化失败，主动指纹探测将无法进行指纹匹配验证")
		} else {
			s.logInfo(fmt.Sprintf("指纹库初始化成功，共 %d 条规则", len(structs.FingerprintDB)))
		}
	}

	s.logInfo(fmt.Sprintf("开始主动指纹探测（目录爆破），共 %d 个 rootURL", len(rootURLs)))

	// 从 DirDB 中获取所有路径，构造完整的 URL 列表进行探测
	var checkURLs []string
	for dbPath := range structs.DirDB {
		for _, rootURL := range rootURLs {
			checkURLs = append(checkURLs, joinRootURLPath(rootURL, dbPath))
		}
	}

	// 去重
	checkURLs = utils.RemoveDuplicateElement(checkURLs)
	s.logInfo(fmt.Sprintf("构造了 %d 个待探测 URL（从 %d 个路径和 %d 个 rootURL）", len(checkURLs), len(structs.DirDB), len(rootURLs)))

	var taskURLMapLock sync.Mutex
	activeFingerprintCount := 0

	// 定义目录爆破的回调函数
	dirBruteCallback := func(resp runner.Result) {
		// 只保存状态码为 200 的路径
		if resp.StatusCode != 200 {
			return
		}

		rootURL, pth := splitRootURLAndPath(responseURL(resp))
		if rootURL == "" {
			return
		}

		matchedPaths := matchedActiveFingerprintPaths(resp.Path)
		matched, matchedProductName := matchActiveFingerprintResponse(resp, matchedPaths, true)
		if !matched {
			return
		}

		taskURLMapLock.Lock()
		added := s.cacheAndUpsertURLPath(*taskURLMap, rootURL, pth, resp)
		if added {
			activeFingerprintCount++
		}
		taskURLMapLock.Unlock()
		if !added {
			return
		}

		productInfo := ""
		if matchedProductName != "" {
			productInfo = fmt.Sprintf(", 产品: %s", matchedProductName)
		}
		s.logInfo(fmt.Sprintf("主动指纹探测发现路径: %s (状态码: %d%s)", resp.URL, resp.StatusCode, productInfo))
	}

	// 使用配置的超时时间
	webTimeout := 20
	if config.WebTimeout > 0 {
		webTimeout = config.WebTimeout
	}

	// 性能优化：根据目标数量动态调整并发线程数
	optimalThreads := calculateOptimalThreadCount(len(checkURLs), config.ThreadCount)
	s.logInfo(fmt.Sprintf("主动指纹探测（Web探测中）并发优化: URL数=%d, 基础线程=%d -> 优化线程=%d", len(checkURLs), config.ThreadCount, optimalThreads))

	// 执行目录爆破，传入构造的完整 URL 列表（rootURL + path）
	httpxlib.DirBrute(checkURLs, dirBruteCallback, config.HTTPProxy, optimalThreads, webTimeout, s.taskID, config.EnableScreenshot)

	if activeFingerprintCount > 0 {
		s.logInfo(fmt.Sprintf("主动指纹探测完成，发现 %d 个状态码为 200 的新路径", activeFingerprintCount))
	} else {
		s.logInfo("主动指纹探测完成，未发现状态码为 200 的新路径")
	}

	return nil
}

// isWebService 判断是否为Web服务
func isWebService(service string, hostPort string) bool {
	// 将服务名转为小写进行匹配
	service = strings.ToLower(strings.TrimSpace(service))

	// 1. 直接匹配HTTP/HTTPS协议名
	webProtocols := []string{
		"http",
		"https",
		"ssl/http",
		"http-proxy",
		"http-alt",
	}
	for _, proto := range webProtocols {
		if service == proto {
			return true
		}
	}

	// 2. 匹配常见的Web服务器名称
	webServers := []string{
		"nginx",
		"apache",
		"tomcat",
		"iis",
		"lighttpd",
		"caddy",
		"websphere",
		"weblogic",
		"jboss",
		"jetty",
		"resin",
		"glassfish",
	}
	for _, server := range webServers {
		if strings.Contains(service, server) {
			return true
		}
	}

	// 3. 根据端口号判断（常见Web端口）
	if strings.Contains(hostPort, ":") {
		parts := strings.Split(hostPort, ":")
		if len(parts) == 2 {
			port := parts[1]
			// 常见Web端口
			commonWebPorts := []string{
				"80", "443", "8080", "8443", "8000", "8888",
				"9000", "9090", "3000", "5000", "7001", "8081",
			}
			for _, webPort := range commonWebPorts {
				if port == webPort {
					// 但需要排除明确不是Web的协议
					if !isNonWebProtocol(service) {
						return true
					}
				}
			}
		}
	}

	return false
}

// isNonWebProtocol 判断是否为明确的非Web协议
func isNonWebProtocol(service string) bool {
	service = strings.ToLower(strings.TrimSpace(service))

	// 明确的非Web协议列表
	nonWebProtocols := []string{
		"rdp",           // 3389
		"ms-wbt-server", // RDP别名
		"ssh",           // 22
		"ftp",           // 21
		"telnet",        // 23
		"smtp",          // 25
		"pop3",          // 110
		"imap",          // 143
		"mysql",         // 3306
		"mssql",         // 1433
		"oracle",        // 1521
		"postgresql",    // 5432
		"postgres",      // 5432
		"redis",         // 6379
		"mongodb",       // 27017
		"mongo",         // 27017
		"memcached",     // 11211
		"smb",           // 445
		"microsoft-ds",  // 445 SMB别名
		"netbios",       // 139
		"ldap",          // 389
		"vnc",           // 5900
		"rpc",           // 135
		"snmp",          // 161
	}

	for _, proto := range nonWebProtocols {
		if service == proto || strings.HasPrefix(service, proto) {
			return true
		}
	}

	return false
}

func portServiceTargetsFromDB(taskID string) (displayTargets []string, probeTargets []string) {
	rows, err := database.DB.Query(`SELECT target, extra_data FROM recon_results WHERE task_id = ? AND result_type = 'port' AND extra_data != ''`, taskID)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	for rows.Next() {
		var hostPort, extraDataStr string
		if err := rows.Scan(&hostPort, &extraDataStr); err != nil {
			continue
		}
		var extraData map[string]interface{}
		_ = json.Unmarshal([]byte(extraDataStr), &extraData)
		protocol := strings.TrimSpace(stringFromAny(extraData["protocol"]))
		service := detectedPortService(extraData)
		targetURL := protocolTargetURL(hostPort, protocol, service)
		if targetURL == "" {
			continue
		}
		displayTargets = append(displayTargets, targetURL)
		if isProbeableWebTarget(targetURL, protocol, service, hostPort) {
			probeTargets = append(probeTargets, targetURL)
		}
	}
	return utils.RemoveDuplicateElement(displayTargets), utils.RemoveDuplicateElement(probeTargets)
}

func (s *ScanService) mergePortServiceTargets(existingProbeTargets []string) ([]string, []string) {
	displayTargets, probeTargets := portServiceTargetsFromDB(s.taskID)
	for _, targetURL := range displayTargets {
		logger.Debug("[任务 %s] [web] 添加协议目标展示: %s", s.taskID, targetURL)
	}
	for _, targetURL := range probeTargets {
		logger.Debug("[任务 %s] [web] 添加Web探测目标: %s", s.taskID, targetURL)
	}
	return displayTargets, utils.RemoveDuplicateElement(append(existingProbeTargets, probeTargets...))
}

func (s *ScanService) replaceURLResultsWithDisplayTargets(targets []string) error {
	if _, err := database.DB.Exec("DELETE FROM recon_results WHERE task_id = ? AND result_type = 'url'", s.taskID); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		normalized := normalizeReconURLTarget(target)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		if err := s.saveReconResult("url", normalized, "protocol-target", reconURLExtraJSON(0, "", 0)); err != nil {
			return err
		}
	}
	return nil
}

func protocolTargetURL(hostPort, protocol, service string) string {
	host, portText, ok := splitHostPortText(hostPort)
	if !ok {
		return ""
	}
	scheme := protocolScheme(protocol, service)
	hostPort = net.JoinHostPort(host, portText)
	if scheme == "" {
		return hostPort
	}
	return scheme + "://" + hostPort
}

func detectedPortService(extraData map[string]interface{}) string {
	service := strings.TrimSpace(stringFromAny(extraData["detected_service"]))
	if service != "" {
		return service
	}
	if _, hasGuess := extraData["guessed_service"]; hasGuess {
		return ""
	}
	service = strings.TrimSpace(stringFromAny(extraData["service"]))
	if strings.EqualFold(service, "tcp") {
		return ""
	}
	return service
}

func splitHostPortText(target string) (string, string, bool) {
	if host, portText, err := net.SplitHostPort(target); err == nil {
		if host != "" && utils.IsPort(portText) {
			return strings.Trim(host, "[]"), portText, true
		}
	}
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return "", "", false
	}
	host := strings.TrimSpace(strings.Trim(target[:idx], "[]"))
	portText := strings.TrimSpace(target[idx+1:])
	if host == "" || !utils.IsPort(portText) {
		return "", "", false
	}
	return host, portText, true
}

func protocolScheme(protocol, service string) string {
	for _, candidate := range []string{protocol, service} {
		scheme := normalizeURLScheme(candidate)
		if scheme != "" && scheme != "tcp" {
			return scheme
		}
	}
	return ""
}

func normalizeURLScheme(value string) string {
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
	if !isValidURLScheme(value) {
		return ""
	}
	return value
}

func isValidURLScheme(scheme string) bool {
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

func isProbeableWebTarget(targetURL, protocol, service, hostPort string) bool {
	if !strings.Contains(targetURL, "://") {
		return false
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "http" || scheme == "https" {
		return true
	}
	return isWebService(protocol, hostPort) || isWebService(service, hostPort)
}

// RunWebProbe 运行 Web 探测
// includePortsFromDB: 是否从数据库查询当前任务的端口扫描结果（用于端口扫描的Web联动）
func (s *ScanService) RunWebProbe(targets []string, config *models.TaskConfig, includePortsFromDB bool) ([]string, error) {
	var urls []string

	s.taskInstanceState.EnsureCaches()

	// 初始化旧全局结构，仅供兼容入口读取。
	if structs.GlobalURLMap == nil {
		structs.GlobalURLMap = make(map[string]structs.URLEntity)
		logger.Debug("[任务 %s] [web] 初始化 GlobalURLMap", s.taskID)
	}
	// 确保 TaskURLMaps 已初始化
	if structs.TaskURLMaps == nil {
		structs.TaskURLMapsLock.Lock()
		structs.TaskURLMaps = make(map[string]map[string]structs.URLEntity)
		structs.TaskURLMapsLock.Unlock()
		logger.Debug("[任务 %s] [web] 初始化 TaskURLMaps", s.taskID)
	}

	// 为当前任务创建独立的 URLMap，避免与其他任务混淆
	taskURLMap := make(map[string]structs.URLEntity)
	var taskURLMapLock sync.Mutex
	logger.Debug("[任务 %s] [web] 创建任务专属 URLMap", s.taskID)

	// HTTP body/header 缓存归属于当前任务，供后续指纹识别读取。
	s.taskInstanceState.EnsureCaches()

	var displayTargets []string
	if includePortsFromDB {
		displayTargets, urls = s.mergePortServiceTargets(nil)
	} else {
		urls = append(urls, s.expandWebProbeTargets(targets)...)
		logger.Debug("[任务 %s] [web] 跳过数据库端口查询（非Web联动模式）", s.taskID)
	}

	// 去重
	urls = utils.RemoveDuplicateElement(urls)
	displayTargets = utils.RemoveDuplicateElement(displayTargets)

	if len(urls) == 0 {
		if len(displayTargets) == 0 {
			s.logWarning("没有可用的 URL 进行 Web 探测")
			return urls, nil
		}
		s.logInfo("没有可探测的 Web 服务，仅保存协议目标信息")
		if err := s.replaceURLResultsWithDisplayTargets(displayTargets); err != nil {
			s.logError(fmt.Sprintf("保存目标信息失败: %v", err))
		}
		return nil, nil
	}

	s.logInfo(fmt.Sprintf("开始 Web 探测，共 %d 个 URL", len(urls)))
	logger.Debug("[任务 %s] [web] 开始探测，URLs: %d, 任务URLMap探测前大小: %d", s.taskID, len(urls), len(s.taskInstanceState.URLMap))

	// 每次 Web 探测前清理当前任务旧 URL 结果，避免重跑残留。
	deleteResult, err := database.DB.Exec("DELETE FROM recon_results WHERE task_id = ? AND result_type = 'url'", s.taskID)
	if err == nil {
		rowsAffected, _ := deleteResult.RowsAffected()
		if rowsAffected > 0 {
			logger.Debug("[任务 %s] [web] 清理了 %d 个旧URL记录（任务重启或重复运行）", s.taskID, rowsAffected)
		}
	}

	// 先写入 pending 记录，探测失败也能展示目标。
	normalizedURLs := make(map[string]struct{})
	for _, urlStr := range displayTargets {
		normalized := normalizeReconURLTarget(urlStr)
		if _, ok := normalizedURLs[normalized]; ok {
			continue
		}
		normalizedURLs[normalized] = struct{}{}
		if err := s.saveReconResult("url", normalized, "protocol-target", reconURLExtraJSON(0, "", 0)); err != nil {
			s.logError(fmt.Sprintf("保存协议目标失败: %v", err))
		}
	}
	for _, urlStr := range urls {
		normalized := normalizeReconURLTarget(urlStr)
		if _, ok := normalizedURLs[normalized]; ok {
			continue
		}
		normalizedURLs[normalized] = struct{}{}

		// 使用规范化后的URL保存
		if err := s.saveReconResult("url", normalized, "httpx-pending", reconURLExtraJSON(0, "", 0)); err != nil {
			s.logError(fmt.Sprintf("保存 URL 初始记录失败: %v", err))
		}
	}

	callbackCount := 0
	totalURLs := len(urls)
	var callbackCountLock sync.Mutex
	callback := func(resp runner.Result) {
		callbackCountLock.Lock()
		callbackCount++
		currentCount := callbackCount
		callbackCountLock.Unlock()

		// 根据扫描结果实时更新进度
		if s.onProgressUpdate != nil && totalURLs > 0 {
			s.onProgressUpdate("Web 探测", currentCount, totalURLs, 0.0, 30.0)
		}
		rootURL, pth := splitRootURLAndPath(responseURL(resp))
		if rootURL == "" {
			return
		}

		taskURLMapLock.Lock()
		s.cacheAndUpsertURLPath(taskURLMap, rootURL, pth, resp)
		taskURLMapLock.Unlock()
		if resp.StatusCode > 0 {
			s.markPendingURLSeen(resp.URL, responseURL(resp))
		}
	}

	logger.Debug("[任务 %s] [web] 使用任务专属回调函数", s.taskID)

	// 性能优化：根据目标数量动态调整并发线程数
	optimalThreads := calculateOptimalThreadCount(len(urls), config.ThreadCount)
	s.logInfo(fmt.Sprintf("Web探测并发优化: 目标数=%d, 基础线程=%d -> 优化线程=%d", len(urls), config.ThreadCount, optimalThreads))

	// 调用 httpx 进行探测，默认超时时间 20 秒。
	webTimeout := 20
	if config.WebTimeout > 0 {
		webTimeout = config.WebTimeout
	}
	httpxlib.CallHTTPx(urls, callback, config.HTTPProxy, optimalThreads, webTimeout, s.taskID, config.EnableScreenshot)

	// 在 Web 探测完成后，如果满足条件，自动进行主动指纹探测（目录爆破）
	// 只保存状态码为 200 的路径到 URL 结果中
	if len(taskURLMap) > 0 {
		// 检查是否需要执行主动指纹探测
		shouldRunActiveFingerprint := config.ScanMode == "fingerprint" || config.ScanMode == "fingerprint_poc" ||
			config.ScanMode == "" || config.ScanMode == "web" || config.ScanMode == "default"

		if shouldRunActiveFingerprint {
			s.logInfo("Web 探测完成，开始主动指纹探测（目录爆破）")
			// 提取 rootURLs 用于目录爆破
			var rootURLs []string
			for rootURL := range taskURLMap {
				rootURLs = append(rootURLs, rootURL)
			}

			if len(rootURLs) > 0 {
				// 执行主动指纹探测，并将状态码为 200 的路径添加到 taskURLMap
				if err := s.runActiveFingerprintInWebProbe(rootURLs, &taskURLMap, config); err != nil {
					s.logWarning(fmt.Sprintf("主动指纹探测失败: %v", err))
				} else {
					s.logInfo("主动指纹探测完成，已更新 URL 列表")
				}
			}
		}
	}

	// 更新所有探测到的 URL 结果到数据库（包括主动指纹探测发现的路径）
	// 保存所有路径，而不仅仅是根 URL
	for rootURL, urlEntity := range taskURLMap {
		// 保存每个路径到数据库
		for path, pathEntity := range urlEntity.WebPaths {
			fullURL := normalizeReconURLTarget(joinRootURLPath(rootURL, path))

			// 确定 source（主动指纹探测发现的路径标记为 active-fingerprint，其他为 httpx）
			source := "httpx"
			if pathEntity.StatusCode == 200 && path != "/" && isActiveFingerprintPath(path) {
				source = "active-fingerprint"
			}

			if err := s.saveReconResult("url", fullURL, source, reconURLPathExtraJSON(pathEntity)); err != nil {
				s.logError(fmt.Sprintf("保存 URL 结果失败: %v", err))
			}
			urlEntity.WebPaths[path] = pathEntity
		}
		taskURLMap[rootURL] = urlEntity
	}

	// 未被命中的 pending 记录保留为失败结果，供前端统计展示。
	s.markPendingURLsFailed(collectSuccessfulURLs(taskURLMap))

	logger.Debug("[任务 %s] [web] 任务完成，将 taskURLMap 同步到任务实例状态", s.taskID)

	// 任务隔离：保存到任务实例状态
	s.taskInstanceState.URLMap = taskURLMap
	logger.Debug("[任务 %s] [web] 已保存任务实例 URLMap，大小: %d", s.taskID, len(taskURLMap))

	// 兼容旧代码：同时保存到 TaskURLMaps。
	structs.TaskURLMapsLock.Lock()
	if structs.TaskURLMaps == nil {
		structs.TaskURLMaps = make(map[string]map[string]structs.URLEntity)
	}
	structs.TaskURLMaps[s.taskID] = taskURLMap
	structs.TaskURLMapsLock.Unlock()

	// 返回从 taskURLMap 中提取的活跃 URLs，而不是输入的 urls
	// 这样确保只对真正活跃的 Web 服务进行后续处理
	var activeURLs []string
	for rootURL := range taskURLMap {
		activeURLs = append(activeURLs, rootURL)
	}

	return activeURLs, nil
}

// saveReconResult 保存信息收集结果（带重试逻辑和去重）
func (s *ScanService) saveReconResult(resultType, target, source string, extraData []byte) error {
	if resultType == "url" {
		return s.saveURLReconResult(target, source, extraData)
	}

	extraDataStr := reconExtraDataString(extraData)

	// 先检查是否已存在相同的记录（相同task_id, result_type, target, source）
	var exists int
	checkQuery := `SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = ? AND target = ? AND source = ?`
	err := database.DB.QueryRow(checkQuery, s.taskID, resultType, target, source).Scan(&exists)
	if err == nil && exists > 0 {
		// 如果已存在，更新记录而不是插入新记录
		updateQuery := `UPDATE recon_results SET extra_data = ?, discovered_at = ? WHERE task_id = ? AND result_type = ? AND target = ? AND source = ?`
		return retryReconWrite(func(timeStr string) error {
			_, err := database.DB.Exec(updateQuery, extraDataStr, timeStr, s.taskID, resultType, target, source)
			return err
		})
	}

	// 如果不存在，插入新记录
	query := `INSERT INTO recon_results (task_id, scan_scope, user_id, result_type, target, source, extra_data, discovered_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(query, s.taskID, s.taskType, s.userID, resultType, target, source, extraDataStr, timeStr)
		return err
	})
}

func (s *ScanService) saveURLReconResult(target, source string, extraData []byte) error {
	target = normalizeReconURLTarget(target)
	variants := reconURLTargetVariants(target)
	extraDataStr := reconExtraDataString(extraData)
	existingID := s.findURLReconID(variants)

	if existingID > 0 {
		return retryReconWrite(func(timeStr string) error {
			_, err := database.DB.Exec(`
				UPDATE recon_results
				SET target = ?, source = ?, extra_data = ?, scan_scope = ?, user_id = ?, discovered_at = ?
				WHERE id = ?
			`, target, source, extraDataStr, s.taskType, s.userID, timeStr, existingID)
			if err == nil {
				s.deleteDuplicateURLVariants(variants, existingID)
				return nil
			}
			return err
		})
	}

	return retryReconWrite(func(timeStr string) error {
		_, err := database.DB.Exec(`
			INSERT INTO recon_results (task_id, scan_scope, user_id, result_type, target, source, extra_data, discovered_at)
			VALUES (?, ?, ?, 'url', ?, ?, ?, ?)
		`, s.taskID, s.taskType, s.userID, target, source, extraDataStr, timeStr)
		return err
	})
}

func (s *ScanService) cacheHTTPResponse(bodyHash, headerHash, body, header string) {
	s.taskInstanceState.EnsureCaches()
	if s.taskInstanceState.HTTPBodyHMap != nil && bodyHash != "" {
		_ = s.taskInstanceState.HTTPBodyHMap.Set(bodyHash, []byte(body))
	}
	if s.taskInstanceState.HTTPHeaderHMap != nil && headerHash != "" {
		_ = s.taskInstanceState.HTTPHeaderHMap.Set(headerHash, []byte(header))
	}
}

// logError 记录错误日志（写入日志文件）
func (s *ScanService) logError(message string) {
	logger.Error("[任务 %s] [recon] %s", s.taskID, message)
}

// logWarning 记录警告日志（写入日志文件）
func (s *ScanService) logWarning(message string) {
	logger.Warn("[任务 %s] [recon] %s", s.taskID, message)
}

// logInfo 记录信息日志（写入日志文件）
func (s *ScanService) logInfo(message string) {
	logger.Info("[任务 %s] [recon] %s", s.taskID, message)
}

// saveActiveFingerprintResultsToFile 保存主动指纹探测结果到文件
func (s *ScanService) saveActiveFingerprintResultsToFile(results []map[string]interface{}, config *models.TaskConfig) error {
	// 获取可执行文件目录
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	exePath, err := filepath.EvalSymlinks(exe)
	if err != nil {
		exePath = exe
	}
	exeDir := filepath.Dir(exePath)

	// 创建任务结果目录
	taskResultsDir := filepath.Join(exeDir, "results", s.taskID)
	if err := os.MkdirAll(taskResultsDir, 0755); err != nil {
		return fmt.Errorf("创建结果目录失败: %w", err)
	}

	// 生成文件名（带时间戳）
	timestamp := backendUtils.GetCurrentTimeString("20060102_150405")
	fileName := fmt.Sprintf("active_fingerprint_%s.json", timestamp)
	filePath := filepath.Join(taskResultsDir, fileName)

	// 构建完整的报告数据
	reportData := map[string]interface{}{
		"task_id":     s.taskID,
		"task_name":   config.TaskName,
		"scan_time":   backendUtils.GetCurrentTimeString(),
		"total_count": len(results),
		"results":     results,
	}

	// 转换为 JSON
	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	s.logInfo(fmt.Sprintf("主动指纹探测结果已保存到: %s", filePath))
	return nil
}

// initFingerprintDBIfNeeded 初始化指纹库（如果未加载）
func (s *ScanService) initFingerprintDBIfNeeded() {
	// 已加载指纹库则跳过
	if len(structs.FingerprintDB) > 0 {
		return
	}

	// 初始化结果映射，避免 nil 写入
	if structs.GlobalResultMap == nil {
		structs.GlobalResultMap = make(map[string][]string)
	}

	// 初始化 Web 响应缓存，避免指纹阶段访问为空
	if structs.GlobalHttpBodyHMap == nil {
		if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err == nil {
			structs.GlobalHttpBodyHMap = hm
		}
	}
	if structs.GlobalHttpHeaderHMap == nil {
		if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err == nil {
			structs.GlobalHttpHeaderHMap = hm
		}
	}
	if structs.GlobalBannerHMap == nil {
		if hm, err := hybrid.New(hybrid.DefaultDiskOptions); err == nil {
			structs.GlobalBannerHMap = hm
		}
	}

	// 从数据库读取指纹（只读取启用的指纹）
	if database.DB == nil {
		s.logWarning("数据库未初始化，无法加载指纹库")
		return
	}

	// 查询启用的指纹（包括被动和主动）
	rows, err := database.DB.Query(`
		SELECT name, rules 
		FROM passive_fingerprints 
		WHERE is_enabled = 1 
		UNION ALL
		SELECT name, rules 
		FROM active_fingerprints 
		WHERE is_enabled = 1 
		ORDER BY name
	`)
	if err != nil {
		s.logWarning(fmt.Sprintf("从数据库查询指纹失败: %v", err))
		return
	}
	defer rows.Close()

	// 解析每个指纹的规则
	for rows.Next() {
		var productName, rulesYAML string
		if err := rows.Scan(&productName, &rulesYAML); err != nil {
			continue
		}

		// 解析规则YAML
		var rules []string
		if err := yaml.Unmarshal([]byte(rulesYAML), &rules); err != nil {
			s.logWarning(fmt.Sprintf("指纹 '%s' 的规则解析失败: %v", productName, err))
			continue
		}

		// 构建 FingerprintDB
		for _, ruleL := range rules {
			if ruleL == "" {
				continue // 跳过空规则
			}
			structs.FingerprintDB = append(structs.FingerprintDB, structs.FingerPEntity{
				ProductName: productName,
				Rule:        ddfinger.ParseRule(ruleL),
				AllString:   ruleL,
			})
		}
	}

	s.logInfo(fmt.Sprintf("指纹库初始化完成，共加载 %d 条规则", len(structs.FingerprintDB)))
}

// GetReconProgress 获取信息收集进度
func (s *ScanService) GetReconProgress() (*models.ProgressInfo, error) {
	var progress models.ProgressInfo
	progress.TaskID = s.taskID

	// 查询各类结果数量
	queries := map[string]*int{
		"SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'port'": &progress.PortCount,
		"SELECT COUNT(*) FROM recon_results WHERE task_id = ? AND result_type = 'url'":  &progress.URLCount,
	}

	for query, count := range queries {
		if err := database.DB.QueryRow(query, s.taskID).Scan(count); err != nil {
			return nil, fmt.Errorf("查询进度失败: %w", err)
		}
	}

	return &progress, nil
}
