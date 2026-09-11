package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/database"
	httpcommon "FusionWeb/backend/engine/common/http"
	"FusionWeb/backend/engine/lib/ddfinger"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"gopkg.in/yaml.v3"
)

type FingerprintService struct {
	taskID            string
	taskType          string
	userID            int
	scanScope         string
	ctx               context.Context
	taskInstanceState *structs.TaskInstanceState
	onProgressUpdate  func(scanned, total int) // 进度更新回调
}

// NewFingerprintService 创建指纹识别服务
func NewFingerprintService(taskID string, ctx context.Context) *FingerprintService {
	// 从数据库查询任务类型
	var taskType string
	query := `SELECT task_type FROM task_config WHERE task_id = ?`
	_ = database.DB.QueryRow(query, taskID).Scan(&taskType)
	if taskType == "" {
		taskType = "web" // 默认任务类型
	}
	taskType = strings.ToLower(strings.TrimSpace(taskType))

	// 计算 scanScope 与 userID
	scope := taskType
	var userID int
	_ = database.DB.QueryRow(`SELECT COALESCE(user_id, 0) FROM task_config WHERE task_id = ?`, taskID).Scan(&userID)

	// 获取任务实例状态
	taskInstanceState := structs.GetOrCreateTaskInstanceState(taskID, taskType)

	return &FingerprintService{
		taskID:            taskID,
		taskType:          taskType,
		userID:            userID,
		scanScope:         scope,
		ctx:               ctx,
		taskInstanceState: taskInstanceState,
		onProgressUpdate:  nil, // 默认不设置，由调用者设置
	}
}

// SetProgressCallback 设置进度更新回调函数
func (f *FingerprintService) SetProgressCallback(callback func(scanned, total int)) {
	f.onProgressUpdate = callback
}

// RunFingerprintIdentification 运行指纹识别
func (f *FingerprintService) RunFingerprintIdentification(targets []string) error {
	f.taskInstanceState.EnsureCaches()
	f.initFingerDBIfNeeded()

	logger.Debug("[任务 %s] [fingerprint] 指纹识别输入目标数量: %d", f.taskID, len(targets))

	taskMap := f.taskInstanceState.URLMap
	logger.Debug("[任务 %s] [fingerprint] 任务实例 URLMap 当前任务URL数量: %d", f.taskID, len(taskMap))
	if len(taskMap) == 0 {
		// 兼容旧代码：尝试从 TaskURLMaps 获取
		structs.TaskURLMapsLock.Lock()
		if oldMap, exists := structs.TaskURLMaps[f.taskID]; exists {
			taskMap = oldMap
			f.taskInstanceState.URLMap = oldMap
			delete(structs.TaskURLMaps, f.taskID)
		}
		structs.TaskURLMapsLock.Unlock()
	}

	if len(taskMap) == 0 {
		f.logWarning("当前任务没有活跃 URL，跳过指纹识别")
		return nil
	}

	f.logInfo(fmt.Sprintf("使用任务实例 URLMap，包含 %d 个URL", len(taskMap)))

	// 确保指纹库已加载。
	// 注意：此前指纹库只在「主动指纹探测」阶段加载，而该阶段在主动字典为空时会提前 return，
	// 结果本阶段会被整段跳过。这里自己兜底加载，避免"worker 启动后第一次扫描扫不到指纹"。
	if len(structs.FingerprintDB) == 0 {
		f.logInfo("指纹库未加载，正在初始化指纹库...")
		f.initFingerDBIfNeeded()
	}

	// 检查指纹库是否加载
	if len(structs.FingerprintDB) == 0 {
		f.logWarning("指纹库未加载或为空，跳过指纹识别")
		f.logInfo("请检查数据库中的指纹库是否为空")
		return nil
	}
	f.logInfo(fmt.Sprintf("被动指纹库已加载，共 %d 条规则", len(structs.FingerprintDB)))

	// 添加 panic 恢复机制
	defer func() {
		if r := recover(); r != nil {
			f.logError(fmt.Sprintf("指纹识别发生 panic: %v", r))
		}
	}()

	taskResultMap := f.taskInstanceState.ResultMap

	// 计算总URL数量用于进度报告
	totalURLs := 0
	for _, urlEntity := range taskMap {
		totalURLs += len(urlEntity.WebPaths)
	}

	if f.onProgressUpdate != nil && totalURLs > 0 {
		f.onProgressUpdate(0, totalURLs)
	}

	ddfinger.FingerprintIdentificationWithState(f.taskInstanceState.FingerprintState())
	if f.onProgressUpdate != nil && totalURLs > 0 {
		f.onProgressUpdate(totalURLs, totalURLs)
	}

	f.logInfo(fmt.Sprintf("指纹识别完成，识别到 %d 个URL的指纹", len(taskResultMap)))

	// 保存识别结果（直接使用任务实例的结果映射）
	count := 0
	for url, fingerprints := range taskResultMap {

		for _, fp := range fingerprints {
			// 构造匹配规则信息
			matchedRules := map[string]interface{}{
				"url":         url,
				"fingerprint": fp,
			}
			matchedJSON, _ := json.Marshal(matchedRules)

			if err := f.saveFingerprintResult(url, fp, string(matchedJSON)); err != nil {
				f.logError(fmt.Sprintf("保存指纹结果失败: %v", err))
			} else {
				count++
			}
		}
	}

	f.logInfo(fmt.Sprintf("指纹识别完成，保存了 %d 条结果", count))

	return nil
}

// initFingerDBIfNeeded 轻量初始化指纹库和结果映射
func (f *FingerprintService) initFingerDBIfNeeded() {
	// 初始化结果映射，避免 nil 写入
	if structs.GlobalResultMap == nil {
		structs.GlobalResultMap = make(map[string][]string)
	}

	// 初始化 Web 响应缓存，避免指纹阶段访问为空
	if structs.GlobalHttpBodyHMap == nil {
		// 忽略错误返回，若失败后续访问会安全失败
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

	// 已加载指纹库则跳过
	if len(structs.FingerprintDB) > 0 {
		return
	}

	// 从数据库读取指纹（只读取启用的指纹）
	if database.DB == nil {
		logger.Warn("数据库未初始化，无法加载指纹库")
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
		logger.Warn("从数据库查询指纹失败: %v", err)
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
			logger.Warn("指纹 '%s' 的规则解析失败: %v", productName, err)
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

	// 检查遍历过程中是否有错误（在循环外检查）
	if err := rows.Err(); err != nil {
		logger.Error("遍历指纹结果集失败: %v", err)
		// 注意：InitFingerprintDB 没有返回值，只能记录错误
		return
	}

	logger.Info("指纹库初始化完成，共加载 %d 条规则", len(structs.FingerprintDB))
}

// saveFingerprintResult 保存指纹识别结果
func (f *FingerprintService) saveFingerprintResult(target, fingerprintName, matchedRules string) error {
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	// 保存到常规表
	// 检查是否已存在相同的记录，避免任务恢复时重复保存
	var count int
	checkQuery := `SELECT COUNT(*) FROM fingerprint_results 
		WHERE task_id = ? AND target = ? AND fingerprint_name = ?`
	err := database.DB.QueryRow(checkQuery, f.taskID, target, fingerprintName).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查指纹结果失败: %w", err)
	}

	// 如果已存在，跳过保存
	if count > 0 {
		logger.Debug("[任务 %s] [fingerprint] 指纹结果已存在，跳过: target=%s, fingerprint=%s",
			f.taskID, target, fingerprintName)
		return nil
	}

	// 插入新记录
	query := `INSERT INTO fingerprint_results (task_id, scan_scope, user_id, target, fingerprint_name, matched_rules, identified_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = database.DB.Exec(query, f.taskID, f.scanScope, f.userID, target, fingerprintName, matchedRules, timeStr)

	// 推送指纹发现事件到 WebSocket
	if err == nil {
		websocket.BroadcastFingerprint(f.taskID, target, fingerprintName)
	}

	return err
}

// GetFingerprintResults 获取指纹识别结果
func (f *FingerprintService) GetFingerprintResults() (map[string][]string, error) {
	var query string
	query = `SELECT target, fingerprint_name FROM fingerprint_results WHERE task_id = ?`

	rows, err := database.DB.Query(query, f.taskID)
	if err != nil {
		return nil, fmt.Errorf("查询指纹结果失败: %w", err)
	}
	defer rows.Close()

	results := make(map[string][]string)
	for rows.Next() {
		var target, fingerprintName string
		if err := rows.Scan(&target, &fingerprintName); err != nil {
			return nil, fmt.Errorf("扫描指纹结果失败: %w", err)
		}

		// 将完整URL转换为rootURL（去除路径部分），以匹配buildTargetPOCNames中的targets格式
		// 例如：http://example.com:8080/login.jsp -> http://example.com:8080
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			// 解析URL，提取scheme和host（包含port）
			urlParsed := httpcommon.URLParse(target)
			rootURL := fmt.Sprintf("%s://%s", urlParsed.Scheme, urlParsed.Host)

			// 规范化：确保末尾有斜杠，以匹配buildTargetPOCNames中的格式
			if !strings.HasSuffix(rootURL, "/") {
				rootURL = rootURL + "/"
			}

			target = rootURL
		}

		results[target] = append(results[target], fingerprintName)
	}

	return results, nil
}

// GetFingerprintProgress 获取指纹识别进度
func (f *FingerprintService) GetFingerprintProgress() (*models.ProgressInfo, error) {
	var progress models.ProgressInfo
	progress.TaskID = f.taskID

	var query string
	query = `SELECT COUNT(DISTINCT target) FROM fingerprint_results WHERE task_id = ?`

	if err := database.DB.QueryRow(query, f.taskID).Scan(&progress.FingerprintCount); err != nil {
		return nil, fmt.Errorf("查询指纹进度失败: %w", err)
	}

	return &progress, nil
}

// logError 记录错误日志（写入日志文件）
func (f *FingerprintService) logError(message string) {
	logger.Error("[任务 %s] [fingerprint] %s", f.taskID, message)
}

// logInfo 记录信息日志（写入日志文件）
func (f *FingerprintService) logInfo(message string) {
	logger.Info("[任务 %s] [fingerprint] %s", f.taskID, message)
}

// logWarning 记录警告日志（写入日志文件）
func (f *FingerprintService) logWarning(message string) {
	logger.Warn("[任务 %s] [fingerprint] %s", f.taskID, message)
}
