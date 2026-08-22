package service

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/common/callnuclei"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// VulnService 漏洞扫描服务
type VulnService struct {
	taskID               string
	taskType             string
	userID               int
	scanScope            string
	ctx                  context.Context
	taskInstanceState    *structs.TaskInstanceState
	tempPocDirs          []string                 // 存储临时创建的POC目录，用于清理
	targetFingerprintMap map[string][]string      // 保存每个目标对应的指纹列表，用于结果验证
	onProgressUpdate     func(scanned, total int) // 进度更新回调
	logService           *LogService              // 外部传入的日志服务（可选）
}

// SetLogService 设置日志服务
func (v *VulnService) SetLogService(ls *LogService) {
	v.logService = ls
}

// NewVulnService 创建漏洞扫描服务
func NewVulnService(taskID string, ctx context.Context) *VulnService {
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

	return &VulnService{
		taskID:               taskID,
		taskType:             taskType,
		userID:               userID,
		scanScope:            scope,
		ctx:                  ctx,
		taskInstanceState:    taskInstanceState,
		tempPocDirs:          []string{},
		targetFingerprintMap: make(map[string][]string),
		onProgressUpdate:     nil, // 默认不设置，由调用者设置
	}
}

// SetProgressCallback 设置进度更新回调函数
func (v *VulnService) SetProgressCallback(callback func(scanned, total int)) {
	v.onProgressUpdate = callback
}

// RunNucleiScan 运行 Nuclei 扫描
func (v *VulnService) RunNucleiScan(targets []string, fingerprints map[string][]string, config *models.TaskConfig) error {
	logger.Debug("[任务 %s] [nuclei] 开始扫描，targets: %d", v.taskID, len(targets))
	logger.Debug("[任务 %s] [nuclei] fingerprints: %d 目标", v.taskID, len(fingerprints))

	// 准备任务级日志 writer，由 Nuclei 参数显式携带，避免抢占全局 gologger。
	var logService *LogService
	var logWriter *LogWriter
	if v.logService != nil {
		logService = v.logService
		logWriter = logService.StartInterceptor()
	} else {
		logService = NewLogService(v.taskID, database.DB)
		logWriter = logService.StartInterceptor()
		defer logService.Stop()
	}

	// 按目标分组，为每个目标构建专属的POC目录列表
	// 确保同一个任务中的不同目标只能调用自己对应的指纹所属的漏洞模板
	targetFingerprintMap := make(map[string][]string) // 保存每个目标对应的指纹列表

	// 构建目标到指纹的映射
	matchedCount := 0
	for target, fps := range fingerprints {
		if len(fps) > 0 { // 仅保留命中指纹的目标
			targetFingerprintMap[target] = fps
			matchedCount++
		}
	}
	if matchedCount == 0 {
		// 无指纹命中，回退到所有目标
		for _, target := range targets {
			targetFingerprintMap[target] = []string{} // 空指纹列表
		}
	}
	v.targetFingerprintMap = targetFingerprintMap

	// 关键优化：按目标分组，为每个目标构建专属的POC目录并分别调用Nuclei
	// 这样可以确保每个目标只扫描其对应指纹的POC目录
	pocRoot := v.getPOCRoot()
	logger.Debug("[任务 %s] [nuclei] POC 根目录: %s", v.taskID, pocRoot)
	logger.Debug("[任务 %s] [nuclei] 开始按目标分组扫描，共 %d 个目标", v.taskID, len(targetFingerprintMap))

	var allResults []output.ResultEvent
	targetGroups := v.groupTargetsByFingerprints(targetFingerprintMap, targets)

	// 计算总目标数用于进度报告
	totalTargets := len(targets)
	scannedTargets := 0

	// 为每个目标组分别调用Nuclei
	for groupKey, groupTargets := range targetGroups {
		select {
		case <-v.ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}

		if len(groupTargets) == 0 {
			continue
		}

		// 为当前组构建专属的POC目录列表
		groupFingerprints := make(map[string][]string)
		for _, target := range groupTargets {
			if fps, ok := targetFingerprintMap[target]; ok {
				groupFingerprints[target] = fps
			}
		}

		// 构建该组的POC目录列表（只包含该组目标的指纹对应的目录）
		groupPocDirs := v.buildPOCDirs(groupFingerprints, config)
		if len(groupPocDirs) == 0 {
			continue
		}

		// 移除日志输出：避免显示目标组信息

		// 构建该组的目标映射
		groupTargetAndPocsName := make(map[string][]string)
		for _, target := range groupTargets {
			groupTargetAndPocsName[target] = []string{} // 空列表，表示按目录扫描
		}

		// 配置 Nuclei 参数（仅针对当前组）
		params := callnuclei.NucleiParams{
			TargetAndPocsName: groupTargetAndPocsName,
			Proxy:             config.HTTPProxy,
			CallBack:          v.handleNucleiResult,
			TemplateDirs:      groupPocDirs, // 关键：每个组使用专属的POC目录列表
			ExcludeTags:       []string{},
			Severities:        []string{"critical", "high", "medium", "low", "info"},
			NoInteractsh:      true,
			NP:                pocRoot,
			InteractshServer:  "",
			InteractshToken:   "",
			TaskID:            v.taskID,
			EnableDebug:       false,
			LogWriter:         logWriter,
		}

		// 添加 panic 恢复机制，避免 POC 过多导致任务失败
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Debug("[任务 %s] [nuclei] 目标组 [%s] 扫描发生 panic: %v", v.taskID, groupKey, r)
					v.logError(fmt.Sprintf("Nuclei 扫描目标组 [%s] 发生 panic: %v", groupKey, r))
				}
			}()
			// 使用进程内 Nuclei SDK 执行扫描（仅针对当前组）
			groupResults := callnuclei.CallNucleiInternal(params)
			allResults = append(allResults, groupResults...)

			// 等待一小段时间，确保 Nuclei runner 完全关闭并释放文件句柄
			// 特别是在 Windows 上，文件句柄可能需要一些时间才能完全释放
			time.Sleep(200 * time.Millisecond)

			// 更新进度：当前组扫描完成
			scannedTargets += len(groupTargets)
			if v.onProgressUpdate != nil && totalTargets > 0 {
				v.onProgressUpdate(scannedTargets, totalTargets)
			}
		}()

		select {
		case <-v.ctx.Done():
			return fmt.Errorf("任务被取消")
		default:
		}
	}

	// 即使扫描过程中出现错误或 panic，也返回 nil，不中断任务流程
	// 这样任务可以正常完成，即使没有发现漏洞

	// 验证：检查是否有漏洞被保存到数据库
	vulnCount := 0
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM vuln_results WHERE task_id = ?", v.taskID).Scan(&vulnCount)
	if vulnCount > 0 {
		logger.Debug("[任务 %s] [nuclei] 扫描完成，数据库中已保存 %d 个漏洞", v.taskID, vulnCount)
	} else {
		logger.Debug("[任务 %s] [nuclei] 扫描完成，但数据库中没有漏洞记录（可能被过滤或保存失败）", v.taskID)
	}

	return nil
}

// findTargetFingerprints 根据URL查找目标对应的指纹列表
func (v *VulnService) findTargetFingerprints(matchedURL string, targetFingerprintMap map[string][]string) []string {
	// 尝试直接匹配
	if fps, ok := targetFingerprintMap[matchedURL]; ok {
		return fps
	}

	// 尝试去除尾部斜杠匹配
	normalizedURL := strings.TrimSuffix(matchedURL, "/")
	if fps, ok := targetFingerprintMap[normalizedURL]; ok {
		return fps
	}

	// 尝试前缀匹配（用于匹配子路径）
	for target, fps := range targetFingerprintMap {
		if strings.HasPrefix(matchedURL, target) || strings.HasPrefix(normalizedURL, strings.TrimSuffix(target, "/")) {
			return fps
		}
	}

	return []string{}
}

// extractTemplateDirFromPath 从模板路径中提取POC目录名称（指纹分类名）
func (v *VulnService) extractTemplateDirFromPath(templatePath string) string {
	if templatePath == "" {
		return ""
	}

	path := strings.ReplaceAll(templatePath, "\\", "/")
	parts := strings.Split(path, "/")

	// 查找 "temp_poc" 之后的目录名（指纹分类名）
	for i, part := range parts {
		if strings.HasPrefix(part, "temp_poc") {
			// 找到 temp_poc_xxx，下一个应该是指纹分类名
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	// 查找 "pocs" 之后的目录名
	for i, part := range parts {
		if part == "pocs" {
			// 如果 pocs 后面是 temp_poc，再往后一个才是指纹分类名
			if i+1 < len(parts) && strings.HasPrefix(parts[i+1], "temp_poc") {
				if i+2 < len(parts) {
					return parts[i+2]
				}
			} else if i+1 < len(parts) {
				// pocs 后面直接是指纹分类名
				return parts[i+1]
			}
		}
	}

	// 如果没找到，尝试返回倒数第二级目录（通常是指纹目录）
	if len(parts) >= 2 {
		secondLastPart := parts[len(parts)-2] // 可能是指纹分类名
		// 排除临时目录名
		if !strings.HasPrefix(secondLastPart, "temp_poc") && secondLastPart != "pocs" {
			return secondLastPart
		}
	}

	return ""
}

func (v *VulnService) groupTargetsByFingerprints(targetFingerprintMap map[string][]string, allTargets []string) map[string][]string {
	groups := make(map[string][]string)

	// 处理有指纹的目标
	for target, fps := range targetFingerprintMap {
		if len(fps) == 0 {
			// 无指纹的目标，使用特殊key
			key := "__NO_FINGERPRINT__"
			groups[key] = append(groups[key], target)
			continue
		}

		// 对指纹列表排序，确保相同指纹组合的目标分到同一组
		sortedFps := make([]string, len(fps))
		copy(sortedFps, fps)
		// 使用简单的排序（按字符串）
		for i := 0; i < len(sortedFps)-1; i++ {
			for j := i + 1; j < len(sortedFps); j++ {
				if sortedFps[i] > sortedFps[j] {
					sortedFps[i], sortedFps[j] = sortedFps[j], sortedFps[i]
				}
			}
		}

		// 构建指纹组合key（将排序后的指纹用|连接）
		key := strings.Join(sortedFps, "|")
		groups[key] = append(groups[key], target)
	}

	// 处理没有在fingerprints中的目标（无指纹）
	for _, target := range allTargets {
		if _, ok := targetFingerprintMap[target]; !ok {
			key := "__NO_FINGERPRINT__"
			groups[key] = append(groups[key], target)
		}
	}

	return groups
}

// handleNucleiResult Nuclei 结果回调
func (v *VulnService) handleNucleiResult(result output.ResultEvent) {

	matchedURL := result.Matched

	if len(v.targetFingerprintMap) > 0 {
		// 查找目标对应的指纹列表（用于日志记录）
		targetFingerprints := v.findTargetFingerprints(matchedURL, v.targetFingerprintMap)

		// 如果目标不在映射中，也允许通过（可能是ALL分类的漏洞）
		if len(targetFingerprints) == 0 {
			// 目标没有指纹匹配，允许通过（可能是ALL分类或其他通用漏洞）
		}
		// 有指纹匹配的目标，直接允许通过（因为已经在分组时确保只扫描对应的POC目录）
	}

	tpl := result.TemplateID
	if result.MatcherName != "" {
		tpl = tpl + ":" + result.MatcherName
	}

	// 获取协议类型（从Scheme字段，如果没有则从URL解析）
	protocol := result.Scheme
	if protocol == "" {
		// 如果Scheme为空，从URL中提取
		if strings.HasPrefix(result.Matched, "https://") {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	// 获取严重级别（转为小写）
	severity := strings.ToLower(result.Info.SeverityHolder.Severity.String())

	// 输出格式：[TemplateID:MatcherName] [protocol] [severity] URL
	show := fmt.Sprintf("[%s] [%s] [%s] %v", tpl, protocol, severity, result.Matched)
	logger.Info("%s", show)
	// 保存漏洞结果到数据库
	authorStr := strings.TrimSpace(result.Info.Authors.String())
	tagsStr := strings.TrimSpace(result.Info.Tags.String())
	if tagsStr == "" {
		tagsStr = result.MatcherName
	}

	templateID := result.TemplateID
	if templateID == "" {
		// 如果 TemplateID 为空，尝试从 info.name 获取（向后兼容）
		templateID = strings.TrimSpace(types.ToString(result.Info.Name))
		if templateID == "" || templateID == "<no value>" {
			templateID = "unknown"
		}
	}

	description := result.Info.Description

	// Ensure Name is not empty
	name := strings.TrimSpace(types.ToString(result.Info.Name))
	if name == "" || name == "<no value>" {
		name = templateID
	}

	vulnResult := &models.VulnResult{
		TaskID:       v.taskID,
		Target:       result.Matched,
		TemplateID:   templateID, // 使用模板的唯一ID，而不是漏洞名称
		MatcherName:  tagsStr,
		Severity:     result.Info.SeverityHolder.Severity.String(),
		Description:  description,
		Name:         name,
		Author:       authorStr,
		Tags:         tagsStr,
		TemplatePath: result.TemplatePath,
		MatchedAt:    result.Matched,
	}

	// 处理提取结果
	if len(result.ExtractedResults) > 0 {
		vulnResult.ExtractedResults = strings.Join(result.ExtractedResults, ", ")
	}

	// 处理元数据
	if len(result.Metadata) > 0 {
		if metaBytes, err := json.Marshal(result.Metadata); err == nil {
			vulnResult.Metadata = string(metaBytes)
		}
	}

	// 提取请求/响应
	if len(result.Request) > 0 {
		vulnResult.Request = result.Request
	}
	if len(result.Response) > 0 {
		vulnResult.Response = result.Response
	}

	// 日志已在 handleNucleiResult 开头输出（采用 dddd 格式），这里不再重复输出
	if err := v.saveNucleiResult(vulnResult); err != nil {
		v.logError(fmt.Sprintf("保存 Nuclei 结果失败: %v, Target=%s, TemplateID=%s", err, vulnResult.Target, vulnResult.TemplateID))
		logger.Error("[任务 %s] [nuclei] 保存漏洞结果失败: %v, Target=%s, TemplateID=%s", v.taskID, err, vulnResult.Target, vulnResult.TemplateID)
	} else {
		// 推送漏洞发现事件到 WebSocket
		websocket.BroadcastVuln(v.taskID, result.Matched, result.TemplateID, vulnResult.Severity)
		// 移除日志输出：避免显示漏洞保存的详细信息
	}
}

// buildPOCDirs 基于指纹构建 POC 目录列表（仅精确匹配，过滤黑名单）
func (v *VulnService) buildPOCDirs(fingerprints map[string][]string, config *models.TaskConfig) []string {
	root := v.getPOCRoot()
	dirs := []string{}
	seen := make(map[string]struct{})

	isFullPocScan := false
	if config != nil {
		if strings.ToLower(strings.TrimSpace(config.ScanMode)) == "poc" {
			isFullPocScan = true
		} else if config.FullPocScan {
			isFullPocScan = true
		}
	}

	if isFullPocScan {
		logger.Debug("[任务 %s] [nuclei] POC扫描模式：全量POC扫描，扫描所有子目录", v.taskID)
		entries, err := os.ReadDir(root)
		if err != nil {
			logger.Debug("[任务 %s] [nuclei] 无法读取 POC 目录: %v", v.taskID, err)
			return dirs
		}

		for _, e := range entries {
			if e.IsDir() {
				subDir := filepath.Join(root, e.Name())
				dirs = append(dirs, subDir)
				seen[subDir] = struct{}{}
			}
		}

		logger.Debug("[任务 %s] [nuclei] POC扫描模式：总计添加 %d 个目录（全量扫描所有子目录）", v.taskID, len(dirs))
		return dirs
	}

	// 如果没有指纹，默认行为：仅调用 ALL 文件夹中的 POC
	if len(fingerprints) == 0 {
		logger.Debug("[任务 %s] [nuclei] POC扫描模式：未识别到指纹，仅使用 ALL 目录", v.taskID)
		allDir := filepath.Join(root, "ALL")
		if _, err := os.Stat(allDir); err == nil {
			dirs = append(dirs, allDir)
			seen[allDir] = struct{}{}
		} else {
			// 尝试小写
			allDirLower := filepath.Join(root, "all")
			if _, err := os.Stat(allDirLower); err == nil {
				dirs = append(dirs, allDirLower)
				seen[allDirLower] = struct{}{}
			} else {
				logger.Debug("[任务 %s] [nuclei] ALL 目录不存在: %s", v.taskID, allDir)
			}
		}

		// 也要检查 "未分类" 目录
		unclassifiedDir := filepath.Join(root, "未分类")
		if _, err := os.Stat(unclassifiedDir); err == nil {
			dirs = append(dirs, unclassifiedDir)
			seen[unclassifiedDir] = struct{}{}
		}

		logger.Debug("[任务 %s] [nuclei] POC扫描模式：总计添加 %d 个目录（仅ALL/未分类）", v.taskID, len(dirs))
		return dirs
	}

	// 收集所有需要匹配的指纹名称（指纹分类）
	fingerprintSet := make(map[string]struct{})
	for _, fps := range fingerprints {
		for _, fp := range fps {
			fp = strings.TrimSpace(fp)
			if fp != "" {
				fingerprintSet[strings.ToLower(fp)] = struct{}{}
			}
		}
	}

	// 遍历POC目录下的子目录，匹配指纹
	entries, err := os.ReadDir(root)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			dirName := entry.Name()
			lowerDirName := strings.ToLower(dirName)

			// 检查是否命中指纹
			if _, ok := fingerprintSet[lowerDirName]; ok {
				dirPath := filepath.Join(root, dirName)
				if _, ok := seen[dirPath]; !ok {
					dirs = append(dirs, dirPath)
					seen[dirPath] = struct{}{}
				}
			}
		}
	}

	// 总是添加 ALL 目录
	allDir := filepath.Join(root, "ALL")
	if _, err := os.Stat(allDir); err == nil {
		if _, ok := seen[allDir]; !ok {
			dirs = append(dirs, allDir)
			seen[allDir] = struct{}{}
		}
	} else {
		// 尝试小写
		allDirLower := filepath.Join(root, "all")
		if _, err := os.Stat(allDirLower); err == nil {
			if _, ok := seen[allDirLower]; !ok {
				dirs = append(dirs, allDirLower)
				seen[allDirLower] = struct{}{}
			}
		}
	}

	return dirs
}

// buildPOCNamesMap 基于已匹配的POC目录为每个目标枚举YAML文件名
// 注意：此方法不再重复进行指纹匹配，直接使用buildPOCDirs已经匹配好的目录列表
func (v *VulnService) buildPOCNamesMap(targets []string, pocDirs []string) map[string][]string {
	result := make(map[string][]string)

	// 一次性枚举所有POC目录中的YAML文件（去重）
	logger.Debug("[任务 %s] [nuclei] buildPOCNamesMap 开始枚举POC文件，目录数: %d", v.taskID, len(pocDirs))
	names := make([]string, 0, 256)
	dedupe := make(map[string]struct{})
	dirCounts := make(map[string]int)

	for _, d := range pocDirs {
		filepath.WalkDir(d, func(path string, de os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if de.IsDir() {
				return nil
			}
			lower := strings.ToLower(path)
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
				_, file := splitPathAndFileName(path)
				if _, ok := dedupe[file]; !ok {
					dedupe[file] = struct{}{}
					names = append(names, file)
				}
				dir, _ := splitPathAndFileName(path)
				dirCounts[dir]++
			}
			return nil
		})
	}
	logger.Debug("[任务 %s] [nuclei] buildPOCNamesMap 枚举完成，共 %d 个POC文件", v.taskID, len(names))
	gologger.Info().Msgf("POC枚举总数: %d", len(names))
	// 显示所有POC文件名
	if len(names) > 0 {
		logger.Info("[任务 %s] [nuclei] 所有POC文件名列表:", v.taskID)
		for _, pocName := range names {
			logger.Info("[任务 %s] [nuclei]   - %s", v.taskID, pocName)
		}
	}
	if len(dirCounts) > 0 {
		logger.Info("[任务 %s] [nuclei] POC目录统计:", v.taskID)
		for dir, cnt := range dirCounts {
			logger.Info("[任务 %s] [nuclei]   POC目录: %s, 文件数: %d", v.taskID, dir, cnt)
		}
	}

	// 为每个目标分配相同的POC文件列表
	// （Nuclei内部会根据目标和POC的匹配规则自动过滤）
	for _, target := range targets {
		result[target] = names
		logger.Debug("[任务 %s] [nuclei] buildPOCNamesMap target=%s, 分配 %d 个POC文件", v.taskID, target, len(names))
	}

	return result
}

// 按目标与其指纹构建 POC 名称映射
func (v *VulnService) buildTargetPOCNames(targets []string, fingerprints map[string][]string) map[string][]string {
	return v.buildTargetPOCNamesWithConfig(targets, fingerprints, nil)
}

// 按目标与其指纹构建 POC 名称映射（带配置参数）
func (v *VulnService) buildTargetPOCNamesWithConfig(targets []string, fingerprints map[string][]string, config *models.TaskConfig) map[string][]string {
	result := make(map[string][]string)
	root := v.getPOCRoot()

	entries, err := os.ReadDir(root)
	if err != nil {
		logger.Debug("[任务 %s] [nuclei] buildTargetPOCNamesWithConfig: 无法读取POC根目录 %s: %v", v.taskID, root, err)
		return result
	}
	var subdirs []string
	for _, e := range entries {
		if e.IsDir() {
			subdirs = append(subdirs, e.Name())
		}
	}
	logger.Debug("[任务 %s] [nuclei] buildTargetPOCNamesWithConfig: POC根目录 %s 下找到 %d 个子目录", v.taskID, root, len(subdirs))

	allDir := filepath.Join(root, "ALL")
	hasAll := false
	if _, err := os.Stat(allDir); err == nil {
		hasAll = true
	}

	// 全量POC扫描模式时，为所有目标分配所有子目录的POC
	// 检查scan_mode是否为"poc"或FullPocScan配置为true
	isFullPocScan := false
	if config != nil {
		if strings.ToLower(strings.TrimSpace(config.ScanMode)) == "poc" {
			isFullPocScan = true
		} else if config.FullPocScan {
			isFullPocScan = true
		}
	}

	if isFullPocScan {
		logger.Debug("[任务 %s] [nuclei] buildTargetPOCNames: 全量POC扫描模式，为所有目标分配所有子目录的POC，子目录数量: %d", v.taskID, len(subdirs))

		if len(subdirs) == 0 {
			logger.Warn("[任务 %s] [nuclei] buildTargetPOCNames: 全量POC扫描模式下，POC根目录下没有子目录！", v.taskID)
			gologger.Info().Msgf("全量POC扫描：为 %d 个目标分配了 0 个POC文件（未找到子目录）", len(targets))
			// 为所有目标分配空列表
			for _, target := range targets {
				result[target] = []string{}
			}
			return result
		}

		dirSet := make(map[string]struct{})
		for _, sd := range subdirs {
			fullPath := filepath.Join(root, sd)
			dirSet[fullPath] = struct{}{}
		}
		logger.Debug("[任务 %s] [nuclei] buildTargetPOCNames: 待扫描目录数: %d", v.taskID, len(dirSet))

		// 枚举所有目录中的POC文件
		dedupe := make(map[string]struct{})
		names := []string{}
		for d := range dirSet {
			err := filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
				if err != nil {
					logger.Debug("[任务 %s] [nuclei] buildTargetPOCNames: WalkDir 错误在 %s: %v", v.taskID, p, err)
					return nil
				}
				if de.IsDir() {
					return nil
				}
				lower := strings.ToLower(p)
				if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
					_, file := splitPathAndFileName(p)
					if _, ok := dedupe[file]; !ok {
						dedupe[file] = struct{}{}
						names = append(names, file)
					}
				}
				return nil
			})
			if err != nil {
				logger.Debug("[任务 %s] [nuclei] buildTargetPOCNames: WalkDir 返回错误: %v", v.taskID, err)
			}
		}

		logger.Debug("[任务 %s] [nuclei] buildTargetPOCNames: 全量扫描总共找到 %d 个唯一POC文件", v.taskID, len(names))

		// 显示所有POC文件名
		if len(names) > 0 {
			logger.Info("[任务 %s] [nuclei] 全量扫描POC文件列表（共 %d 个）:", v.taskID, len(names))
			for _, pocName := range names {
				logger.Info("[任务 %s] [nuclei]   - %s", v.taskID, pocName)
			}
		}

		// 为所有目标分配相同的POC列表
		for _, target := range targets {
			result[target] = names
		}

		gologger.Info().Msgf("全量POC扫描：为 %d 个目标分配了 %d 个POC文件", len(targets), len(names))
		return result
	}

	for _, target := range targets {
		dirSet := make(map[string]struct{})
		if hasAll {
			dirSet[allDir] = struct{}{}
		}
		tKey := target
		if (strings.HasPrefix(tKey, "http://") || strings.HasPrefix(tKey, "https://")) && !strings.HasSuffix(tKey, "/") {
			tKey = tKey + "/"
		}
		fps := fingerprints[tKey]
		if len(fps) == 0 {
			tNoSlash := strings.TrimSuffix(tKey, "/")
			fps = fingerprints[tNoSlash]
		}
		for _, fp := range fps {
			fpTrim := strings.TrimSpace(fp)
			if fpTrim == "" {
				continue
			}
			matched := ""
			for _, sd := range subdirs {
				if strings.EqualFold(sd, fpTrim) {
					matched = sd
					break
				}
			}
			if matched != "" {
				dirSet[filepath.Join(root, matched)] = struct{}{}
			}
		}

		dedupe := make(map[string]struct{})
		names := []string{}
		for d := range dirSet {
			filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
				if err != nil || de.IsDir() {
					return nil
				}
				lower := strings.ToLower(p)
				if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
					_, file := splitPathAndFileName(p)
					if _, ok := dedupe[file]; !ok {
						dedupe[file] = struct{}{}
						names = append(names, file)
					}
				}
				return nil
			})
		}
		result[target] = names
		logger.Info("[任务 %s] [nuclei] 当前目标分组已解析，目录数=%d, 分配POC=%d", v.taskID, len(dirSet), len(names))
	}

	return result
}

// splitPathAndFileName 提取文件名（与 nuclei loader 匹配逻辑保持一致）
func splitPathAndFileName(p string) (string, string) {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.Contains(p, "/") {
		return "", p
	}
	t := strings.Split(p, "/")
	return strings.Join(t[:len(t)-1], "/"), t[len(t)-1]
}

// getPOCRoot 获取 POC 根目录
func (v *VulnService) getPOCRoot() string {
	if structs.GlobalConfig.NucleiTemplate != "" {
		if info, err := os.Stat(structs.GlobalConfig.NucleiTemplate); err == nil && info.IsDir() {
			return structs.GlobalConfig.NucleiTemplate
		}
	}

	root := filepath.Join(utils.GetDataDir(), "pocs")
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		return root
	}
	logger.Warn("[任务 %s] [nuclei] 未找到有效的 POC 目录: %s", v.taskID, root)
	return root
}

// 已移除外置 Nuclei 执行路径逻辑，统一使用进程内 SDK

// saveNucleiResult 保存 Nuclei 扫描结果
func (v *VulnService) saveNucleiResult(result *models.VulnResult) error {
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	// 1. 保存到 vuln_results 表 (通用扫描结果表)
	// 去重：同一任务 task_id + target + template_id + matcher_name
	var cnt int
	_ = database.DB.QueryRow(`SELECT COUNT(*) FROM vuln_results WHERE task_id = ? AND target = ? AND template_id = ? AND matcher_name = ?`,
		result.TaskID, result.Target, result.TemplateID, result.MatcherName).Scan(&cnt)

	var err error
	if cnt == 0 {
		query := `INSERT INTO vuln_results 
			(task_id, scan_scope, user_id, target, template_id, matcher_name, severity, description, request, response, discovered_at, name, author, tags, template_path) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err = database.DB.Exec(query, result.TaskID, v.scanScope, v.userID, result.Target, result.TemplateID,
			result.MatcherName, result.Severity, result.Description, result.Request,
			result.Response, timeStr, result.Name, result.Author, result.Tags, result.TemplatePath)
	}

	// 2. 如果是 POC 扫描任务 (存在于 poc_scan_tasks 表)，同步保存到 poc_scan_results 表并更新计数
	var pocTaskExists int
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM poc_scan_tasks WHERE task_id = ?", result.TaskID).Scan(&pocTaskExists)

	if pocTaskExists > 0 {
		// 去重
		var pocCnt int
		_ = database.DB.QueryRow(`SELECT COUNT(*) FROM poc_scan_results WHERE task_id = ? AND target = ? AND template_id = ? AND matcher_name = ?`,
			result.TaskID, result.Target, result.TemplateID, result.MatcherName).Scan(&pocCnt)

		if pocCnt == 0 {
			insertQuery := `INSERT INTO poc_scan_results (
				task_id, target, template_id, template_path, matcher_name, severity, 
				name, author, tags, description, request, response, matched_at, extracted_results, metadata, discovered_at, user_id
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

			_, pocErr := database.DB.Exec(insertQuery,
				result.TaskID, result.Target, result.TemplateID, result.TemplatePath,
				result.MatcherName, result.Severity, result.Name, result.Author,
				result.Tags, result.Description, result.Request, result.Response, result.MatchedAt, result.ExtractedResults,
				result.Metadata, timeStr, v.userID)

			if pocErr == nil {
				// 成功保存后，原子更新任务的漏洞计数
				database.DB.Exec("UPDATE poc_scan_tasks SET found_vulns = found_vulns + 1 WHERE task_id = ?", result.TaskID)
			} else {
				logger.Error("[任务 %s] [vuln] 保存 POC 扫描结果失败: %v", v.taskID, pocErr)
			}
		}
	}

	return err
}

// saveFingerprintResult 保存指纹扫描结果
func (v *VulnService) saveFingerprintResult(result *models.FingerprintResult) error {
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	// 保存到普通的 fingerprint_results 表
	var cnt int
	_ = database.DB.QueryRow(`SELECT COUNT(*) FROM fingerprint_results WHERE task_id = ? AND target = ? AND fingerprint_name = ?`,
		result.TaskID, result.Target, result.FingerprintName).Scan(&cnt)
	if cnt > 0 {
		return nil
	}
	query := `INSERT INTO fingerprint_results 
		(task_id, target, fingerprint_name, matched_rules, identified_at) 
		VALUES (?, ?, ?, ?, ?)`

	_, err := database.DB.Exec(query, result.TaskID, result.Target, result.FingerprintName,
		result.MatchedRules, timeStr)
	return err
}

// GetVulnResults 获取漏洞扫描结果
func (v *VulnService) GetVulnResults() ([]models.VulnResult, error) {
	query := `SELECT id, task_id, target, template_id, matcher_name, severity, 
		description, request, response, CAST(discovered_at AS TEXT), name, template_path, COALESCE(author, ''), COALESCE(tags, '')
		FROM vuln_results WHERE task_id = ? ORDER BY discovered_at ASC`

	rows, err := database.DB.Query(query, v.taskID)
	if err != nil {
		return nil, fmt.Errorf("查询漏洞结果失败: %w", err)
	}
	defer rows.Close()

	var results []models.VulnResult
	reportService := NewReportService(v.taskID)
	for rows.Next() {
		var result models.VulnResult
		var discoveredAt string
		if err := rows.Scan(&result.ID, &result.TaskID, &result.Target, &result.TemplateID,
			&result.MatcherName, &result.Severity, &result.Description, &result.Request,
			&result.Response, &discoveredAt, &result.Name, &result.TemplatePath, &result.Author, &result.Tags); err != nil {
			return nil, fmt.Errorf("扫描漏洞结果失败: %w", err)
		}
		if parsed, err := utils.ParseTimeString(discoveredAt); err == nil {
			result.DiscoveredAt = parsed
		}
		applyPocMetadataToVulnResult(reportService, &result)
		results = append(results, result)
	}

	return results, nil
}

// GetVulnProgress 获取漏洞扫描进度
func (v *VulnService) GetVulnProgress() (*models.ProgressInfo, error) {
	var progress models.ProgressInfo
	progress.TaskID = v.taskID

	query := `SELECT COUNT(*) FROM vuln_results WHERE task_id = ?`
	if err := database.DB.QueryRow(query, v.taskID).Scan(&progress.VulnCount); err != nil {
		return nil, fmt.Errorf("查询漏洞进度失败: %w", err)
	}

	return &progress, nil
}

// logInfo 记录信息日志（同时写入数据库和日志文件）
func (v *VulnService) logInfo(message string) {
	// 仅写入日志文件，不再写入数据库
	logger.Info("[任务 %s] [vuln] %s", v.taskID, message)
}

// logError 记录错误日志（同时写入数据库和日志文件）
func (v *VulnService) logError(message string) {
	// 仅写入日志文件，不再写入数据库
	logger.Error("[任务 %s] [vuln] %s", v.taskID, message)
}
