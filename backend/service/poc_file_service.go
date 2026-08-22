package service

import (
	"FusionWeb/backend/logger"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultPocCategory = "未分类"

func isKnownPocSeverity(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return true
	default:
		return false
	}
}

// PocFileService POC 文件管理服务（直接读取data/pocs目录）
type PocFileService struct {
	configPath string
	cache      []PocFileInfo // 缓存扫描结果
	cacheTime  int64         // 缓存时间戳
	mu         sync.RWMutex  // 读写锁
}

// PocFileInfo POC 文件信息
type PocFileInfo struct {
	ID              int      `json:"id"`              // 数据库ID
	RelativePath    string   `json:"relativePath"`    // 相对于POC目录的路径
	FullPath        string   `json:"fullPath"`        // 完整路径（包含POC目录前缀）
	FileName        string   `json:"fileName"`        // 文件名
	PocId           string   `json:"pocId"`           // POC ID（从yaml中读取）
	Name            string   `json:"name"`            // 漏洞名称（从yaml的info.name中读取）
	Author          string   `json:"author"`          // 作者（从yaml中读取）
	Severity        string   `json:"severity"`        // 严重等级（从yaml中读取）
	Tags            []string `json:"tags"`            // 标签（从yaml的info.tags中读取）
	Category        string   `json:"category"`        // 分类（指纹名称，从数据库读取）
	FingerprintName string   `json:"fingerprintName"` // 指纹名称（用于分类）
	FileSize        int64    `json:"fileSize"`        // 文件大小
	ModTime         string   `json:"modTime"`         // 修改时间
	IsYAML          bool     `json:"isYaml"`          // 是否为YAML文件
}

// NewPocFileService 创建 POC 文件服务
func NewPocFileService() *PocFileService {
	return &PocFileService{configPath: resolvePocRoot()}
}

// GetAllPocFilesWithCache 获取所有POC文件列表（带缓存）
// 注意：由于需要根据用户权限过滤，缓存不再适用，直接调用GetAllPocFiles
func (p *PocFileService) GetAllPocFilesWithCache(userID *int) ([]PocFileInfo, error) {
	// 由于需要根据用户权限过滤，不再使用缓存
	return p.GetAllPocFiles(userID)
}

// GetPocFilesPage 分页获取POC文件（后端分页）
// userID: 用户ID，保留用于历史数据筛选
// role: 用户角色，"user"或"admin"
func (p *PocFileService) GetPocFilesPage(page, pageSize int, category, keyword string, userID *int) ([]PocFileInfo, int, error) {
	return p.GetPocFilesPageWithSeverity(page, pageSize, category, keyword, "", userID)
}

// GetPocFilesPageWithSeverity 分页获取POC文件（后端分页，支持severity过滤）
// userID: 用户ID，保留用于历史数据筛选
// role: 用户角色，"user"或"admin"
func (p *PocFileService) GetPocFilesPageWithSeverity(page, pageSize int, category, keyword, severity string, userID *int) ([]PocFileInfo, int, error) {
	// 使用缓存加载（需要传入userID和role进行过滤）
	allFiles, err := p.GetAllPocFiles(userID)
	if err != nil {
		return nil, 0, err
	}

	// 过滤
	var filtered []PocFileInfo
	keywordLower := strings.ToLower(keyword)

	for _, file := range allFiles {
		// 分类过滤
		if category != "" && file.Category != category {
			continue
		}

		// severity过滤
		if severity != "" {
			fileSeverity := strings.ToLower(strings.TrimSpace(file.Severity))
			if strings.EqualFold(severity, "unknown") {
				if isKnownPocSeverity(fileSeverity) {
					continue
				}
			} else if !strings.EqualFold(fileSeverity, severity) {
				continue
			}
		}

		// 关键字过滤
		if keyword != "" {
			if !strings.Contains(strings.ToLower(file.FileName), keywordLower) &&
				!strings.Contains(strings.ToLower(file.RelativePath), keywordLower) &&
				!strings.Contains(strings.ToLower(file.Category), keywordLower) {
				continue
			}
		}

		filtered = append(filtered, file)
	}

	// 排序（按文件名）
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].FileName < filtered[j].FileName
	})

	total := len(filtered)

	// 分页
	start := (page - 1) * pageSize
	if start >= total {
		return []PocFileInfo{}, total, nil
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	return filtered[start:end], total, nil
}

// GetAllPocFiles 获取所有POC文件列表（带缓存）
// userID: 用户ID，role: 用户角色（当前单用户模型下返回所有文件）
func (p *PocFileService) GetAllPocFiles(userID *int) ([]PocFileInfo, error) {
	p.mu.RLock()
	if p.cache != nil {
		defer p.mu.RUnlock()
		return p.cache, nil
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check
	if p.cache != nil {
		return p.cache, nil
	}

	files, err := p.scanPocFilesFromDisk()
	if err != nil {
		return nil, err
	}
	p.cache = files
	p.cacheTime = time.Now().Unix()
	return files, nil
}

// scanPocFilesFromDisk 从磁盘扫描所有POC文件
func (p *PocFileService) scanPocFilesFromDisk() ([]PocFileInfo, error) {
	var pocFiles []PocFileInfo
	root := p.configPath

	// 确保根目录存在
	if _, err := os.Stat(root); os.IsNotExist(err) {
		// 如果目录不存在，尝试创建
		if err := os.MkdirAll(root, 0755); err != nil {
			return nil, fmt.Errorf("无法创建POC目录: %w", err)
		}
		return pocFiles, nil
	}

	idCounter := 1
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// 忽略访问错误的目录/文件，继续遍历其他
			logger.Warn("遍历POC目录出错: %v", err)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// 过滤 YAML 文件
		name := info.Name()
		lowerName := strings.ToLower(name)
		if !strings.HasSuffix(lowerName, ".yaml") && !strings.HasSuffix(lowerName, ".yml") {
			return nil
		}

		// 获取相对路径
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relPath = filepath.ToSlash(relPath)

		// 读取内容以解析元数据
		// 注意：如果文件很多，这里可能会有性能问题。后续可以考虑加缓存。
		content, err := os.ReadFile(path)
		if err != nil {
			logger.Error("无法读取文件: %s, %v", path, err)
			return nil
		}

		// 解析元数据
		pocId, name, author, severity, tags, fingerprintName := p.parseYAMLMetadata(string(content))

		// 确定分类（目录名）
		category := filepath.Dir(relPath)
		if category == "." {
			category = "未分类"
		}
		// 如果指纹名称为空，尝试使用分类名
		if fingerprintName == "" && category != "未分类" {
			fingerprintName = category
		}

		pocFile := PocFileInfo{
			ID:              idCounter, // 临时生成ID
			PocId:           pocId,
			Name:            name,
			Author:          author,
			Severity:        severity,
			Tags:            tags,
			FileName:        info.Name(),
			RelativePath:    relPath,
			FullPath:        path,
			Category:        category,
			FingerprintName: fingerprintName,
			FileSize:        info.Size(),
			ModTime:         info.ModTime().Format("2006-01-02 15:04:05"),
			IsYAML:          true,
		}
		pocFiles = append(pocFiles, pocFile)
		idCounter++
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("扫描POC文件失败: %w", err)
	}

	return pocFiles, nil
}

// GetPocFilesByCategory 按分类获取POC文件
// userID: 用户ID，保留用于历史数据筛选
// role: 用户角色，"user"或"admin"
func (p *PocFileService) GetPocFilesByCategory(category string, userID *int) ([]PocFileInfo, error) {
	allFiles, err := p.GetAllPocFiles(userID)
	if err != nil {
		return nil, err
	}

	var filtered []PocFileInfo
	for _, file := range allFiles {
		if file.Category == category {
			filtered = append(filtered, file)
		}
	}

	return filtered, nil
}

// GetPocCategories 获取所有分类（扫描目录名作为分类）
// userID: 用户ID，role: 用户角色（暂未实现）
func (p *PocFileService) GetPocCategories(userID *int) ([]string, error) {
	root := p.configPath

	// 确保根目录存在
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return []string{"未分类"}, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("无法读取POC目录: %w", err)
	}

	var categories []string
	for _, entry := range entries {
		if entry.IsDir() {
			categories = append(categories, entry.Name())
		}
	}

	if len(categories) == 0 {
		categories = append(categories, "未分类")
	}

	return categories, nil
}

// validateRelativePath 验证相对路径（防止路径遍历攻击）
func validateRelativePath(relativePath string) (string, error) {
	relativePath = strings.TrimSpace(relativePath)
	if relativePath == "" {
		return "", fmt.Errorf("路径不能为空")
	}

	if strings.Contains(relativePath, "\x00") {
		return "", fmt.Errorf("路径包含非法字符")
	}

	// 检查是否包含绝对路径
	if filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("不允许使用绝对路径")
	}

	// 清理路径（规范化路径分隔符）
	cleaned := filepath.Clean(relativePath)

	// 转换为斜杠分隔符（统一格式）
	cleaned = filepath.ToSlash(cleaned)
	if cleaned == "." {
		return "", fmt.Errorf("路径不能为空")
	}

	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("路径超出允许范围")
		}
	}

	return cleaned, nil
}

func validatePocPathSegment(value string, fallback string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if value == "" {
		return "", fmt.Errorf("路径名称不能为空")
	}
	if strings.Contains(value, "\x00") {
		return "", fmt.Errorf("路径名称包含非法字符")
	}
	if filepath.IsAbs(value) || strings.ContainsAny(value, `/\`) {
		return "", fmt.Errorf("路径名称不能包含路径分隔符")
	}
	if value == "." || value == ".." {
		return "", fmt.Errorf("路径名称非法")
	}
	if strings.ContainsAny(value, `<>:"|?*`) {
		return "", fmt.Errorf("路径名称包含Windows文件系统非法字符")
	}
	return value, nil
}

func validatePocFileName(fileName string) (string, error) {
	fileName = filepath.Base(strings.TrimSpace(fileName))
	if fileName == "" || fileName == "." || fileName == ".." {
		return "", fmt.Errorf("POC文件名不能为空")
	}
	return validatePocPathSegment(fileName, "")
}

func (p *PocFileService) resolveSafePocPath(relativePath string) (string, error) {
	cleanedPath, err := validateRelativePath(relativePath)
	if err != nil {
		return "", err
	}

	root, err := filepath.Abs(p.configPath)
	if err != nil {
		return "", fmt.Errorf("解析POC根目录失败: %w", err)
	}
	target, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(cleanedPath)))
	if err != nil {
		return "", fmt.Errorf("解析POC路径失败: %w", err)
	}

	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("校验POC路径失败: %w", err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("路径超出POC目录范围")
	}

	return target, nil
}

// GetPocFileContent 获取POC文件内容（从本地文件读取）
func (p *PocFileService) GetPocFileContent(relativePath string) (string, error) {
	fullPath, err := p.resolveSafePocPath(relativePath)
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("POC文件不存在：%s", relativePath)
		}
		return "", fmt.Errorf("读取POC文件失败: %w", err)
	}

	return string(content), nil
}

// SearchPocFiles 搜索POC文件
// userID: 用户ID，保留用于历史数据筛选
// role: 用户角色，"user"或"admin"
func (p *PocFileService) SearchPocFiles(keyword string, userID *int) ([]PocFileInfo, error) {
	allFiles, err := p.GetAllPocFiles(userID)
	if err != nil {
		return nil, err
	}

	keyword = strings.ToLower(keyword)
	var results []PocFileInfo

	for _, file := range allFiles {
		// 在文件名和相对路径中搜索
		if strings.Contains(strings.ToLower(file.FileName), keyword) ||
			strings.Contains(strings.ToLower(file.RelativePath), keyword) ||
			strings.Contains(strings.ToLower(file.Category), keyword) {
			results = append(results, file)
		}
	}

	return results, nil
}

// GetPocStatistics 获取POC统计信息
// userID: 用户ID，保留用于历史数据筛选
// role: 用户角色，"user"或"admin"
func (p *PocFileService) GetPocStatistics(userID *int) (map[string]interface{}, error) {
	allFiles, err := p.GetAllPocFiles(userID)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total": len(allFiles),
	}

	// 按分类统计
	categoryCount := make(map[string]int)
	var totalSize int64

	for _, file := range allFiles {
		categoryCount[file.Category]++
		totalSize += file.FileSize
	}

	stats["category_count"] = categoryCount
	stats["total_size"] = totalSize
	stats["categories"] = len(categoryCount)

	return stats, nil
}

// invalidateCache 清除缓存
func (p *PocFileService) invalidateCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = nil
	p.cacheTime = 0
}

// CreatePocFile 创建新的POC文件（保存到本地文件系统）
// forceCategory: 如果为true，强制使用category作为分类，忽略YAML中的fingerprintName
// userID: 创建者用户ID（目前仅用于日志，不存储到文件）
// 如果临时表中存在对应的记录，则转移到正式表；否则创建新记录到正式表
func (p *PocFileService) CreatePocFile(category string, fileName string, content string, userID *int, forceCategory ...bool) error {
	defer p.invalidateCache() // 无论成功与否，为了安全起见，或者成功后清除

	// Sanitize fileName to prevent path traversal
	fileName = filepath.Base(fileName)

	// 解析YAML内容提取元数据
	pocId, _, _, _, _, fingerprintName := p.parseYAMLMetadata(content)

	// 如果forceCategory为true（导入时），强制使用category作为分类
	// 否则，如果YAML中没有指纹名称，才使用category
	forceUseCategory := len(forceCategory) > 0 && forceCategory[0]
	if forceUseCategory && category != "" {
		fingerprintName = category
	} else if fingerprintName == "" {
		// 如果未指定指纹名称，使用category作为指纹名称
		fingerprintName = category
	}
	if fingerprintName == "" {
		fingerprintName = defaultPocCategory
	}
	fingerprintName, err := validatePocPathSegment(fingerprintName, defaultPocCategory)
	if err != nil {
		return fmt.Errorf("POC分类非法: %w", err)
	}

	// 确定目标目录
	targetDir, err := p.resolveSafePocPath(fingerprintName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 如果文件名为空或非法，尝试使用pocId
	if fileName == "" || fileName == "." || fileName == string(filepath.Separator) {
		if pocId != "" {
			fileName = pocId + ".yaml"
		} else {
			// 生成随机文件名
			fileName = fmt.Sprintf("poc_%d.yaml", time.Now().UnixNano())
		}
	}

	// 确保扩展名
	if !strings.HasSuffix(strings.ToLower(fileName), ".yaml") && !strings.HasSuffix(strings.ToLower(fileName), ".yml") {
		fileName += ".yaml"
	}
	fileName, err = validatePocFileName(fileName)
	if err != nil {
		return err
	}

	fullPath, err := p.resolveSafePocPath(filepath.ToSlash(filepath.Join(fingerprintName, fileName)))
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入POC文件失败: %w", err)
	}

	logger.Info("成功创建POC文件: %s", fullPath)
	return nil
}

// SavePocFile 保存POC文件（兼容旧接口）
func (p *PocFileService) SavePocFile(name, content string) error {
	// 默认保存到 "custom" 分类，无特定用户
	return p.CreatePocFile("custom", name, content, nil)
}

// RenamePocFile 重命名POC文件
func (p *PocFileService) RenamePocFile(oldRelativePath string, newRelativePath string) error {
	defer p.invalidateCache()

	// 验证旧路径和新路径（防止路径遍历攻击）
	oldPath, err := validateRelativePath(oldRelativePath)
	if err != nil {
		return err
	}
	newPath, err := validateRelativePath(newRelativePath)
	if err != nil {
		return err
	}

	oldFullPath, err := p.resolveSafePocPath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := p.resolveSafePocPath(newPath)
	if err != nil {
		return err
	}

	// 检查旧文件是否存在
	if _, err := os.Stat(oldFullPath); os.IsNotExist(err) {
		return fmt.Errorf("原文件不存在: %s", oldRelativePath)
	}

	// 检查新文件是否已存在
	if _, err := os.Stat(newFullPath); err == nil {
		return fmt.Errorf("目标文件已存在: %s", newRelativePath)
	}

	// 确保新目录存在
	newDir := filepath.Dir(newFullPath)
	if err := os.MkdirAll(newDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 重命名文件
	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	// 尝试清理旧目录（如果为空）
	oldDir := filepath.Dir(oldFullPath)
	configRoot, _ := filepath.Abs(p.configPath)
	if oldDir != configRoot {
		if entries, err := os.ReadDir(oldDir); err == nil && len(entries) == 0 {
			os.Remove(oldDir)
		}
	}

	return nil
}

// CleanupOldTempDirs 清理旧的临时POC目录
func (p *PocFileService) CleanupOldTempDirs() {
	pocsDir := p.configPath

	// 检查pocs目录是否存在
	if _, err := os.Stat(pocsDir); os.IsNotExist(err) {
		return // 目录不存在，无需清理
	}

	// 读取pocs目录下的所有条目
	entries, err := os.ReadDir(pocsDir)
	if err != nil {
		logger.Warn("读取pocs目录失败，无法清理临时目录: %v", err)
		return
	}

	cleanedCount := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 检查是否是临时目录（以 temp_poc_ 开头）
		if strings.HasPrefix(entry.Name(), "temp_poc_") {
			tempDir := filepath.Join(pocsDir, entry.Name())
			logger.Info("发现旧的临时POC目录，准备清理: %s", tempDir)

			// 删除临时目录
			if err := os.RemoveAll(tempDir); err != nil {
				logger.Warn("清理临时POC目录失败: %v, 目录: %s", err, tempDir)
			} else {
				logger.Info("临时POC目录清理成功: %s", tempDir)
				cleanedCount++
			}
		}
	}

	if cleanedCount > 0 {
		logger.Info("程序启动时清理了 %d 个旧的临时POC目录", cleanedCount)
	}
}

// UpdatePocFile 更新POC文件内容（本地文件）
// category: 可选，如果提供则更新分类信息
func (p *PocFileService) UpdatePocFile(relativePath string, content string, category string, fileName ...string) error {
	defer p.invalidateCache()

	// 验证相对路径（防止路径遍历攻击）
	cleanedPath, err := validateRelativePath(relativePath)
	if err != nil {
		return err
	}

	fullPath, err := p.resolveSafePocPath(cleanedPath)
	if err != nil {
		return err
	}

	// 检查原文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return fmt.Errorf("找不到要更新的POC文件: %s", relativePath)
	}

	// 解析YAML内容提取元数据
	pocId, _, _, _, _, fingerprintName := p.parseYAMLMetadata(content)

	// 如果提供了category参数，优先使用category作为分类
	if category != "" {
		fingerprintName = category
	} else if fingerprintName == "" {
		// 如果新的fingerprintName为空，尝试保持原有的分类（目录名）
		oldDir := filepath.Dir(cleanedPath)
		if oldDir != "." {
			fingerprintName = oldDir
		} else {
			fingerprintName = defaultPocCategory
		}
	}
	fingerprintName, err = validatePocPathSegment(fingerprintName, defaultPocCategory)
	if err != nil {
		return fmt.Errorf("POC分类非法: %w", err)
	}

	// 确定新的文件名
	newFileName := filepath.Base(cleanedPath)
	requestedFileName := ""
	if len(fileName) > 0 {
		requestedFileName = strings.TrimSpace(fileName[0])
	}
	if requestedFileName != "" {
		newFileName = filepath.Base(requestedFileName)
	} else {
		// 如果pocId改变了，可能需要重命名文件？这里暂时保持原文件名，或者根据pocId重命名
		// 为了简单起见，如果pocId有效且不等于原文件名（无后缀），则重命名
		if pocId != "" {
			oldBase := strings.TrimSuffix(newFileName, filepath.Ext(newFileName))
			if pocId != oldBase {
				newFileName = pocId + filepath.Ext(newFileName)
			}
		}
	}
	if !strings.HasSuffix(strings.ToLower(newFileName), ".yaml") && !strings.HasSuffix(strings.ToLower(newFileName), ".yml") {
		newFileName += ".yaml"
	}
	newFileName, err = validatePocFileName(newFileName)
	if err != nil {
		return fmt.Errorf("POC文件名非法: %w", err)
	}

	// 确定新的相对路径
	newRelativePath := filepath.Join(fingerprintName, newFileName)
	newRelativePath = filepath.ToSlash(newRelativePath)

	newFullPath, err := p.resolveSafePocPath(newRelativePath)
	if err != nil {
		return err
	}

	// 如果路径改变了（分类或文件名改变），需要移动文件
	if newFullPath != fullPath {
		// 确保新目录存在
		newDir := filepath.Dir(newFullPath)
		if err := os.MkdirAll(newDir, 0755); err != nil {
			return fmt.Errorf("创建新目录失败: %w", err)
		}

		// 删除旧文件
		if err := os.Remove(fullPath); err != nil {
			return fmt.Errorf("删除旧文件失败: %w", err)
		}

		// 写入新文件
		if err := os.WriteFile(newFullPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("写入新文件失败: %w", err)
		}
	} else {
		// 路径未变，直接覆盖
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("更新文件失败: %w", err)
		}
	}

	return nil
}

// DeletePocFile 删除POC文件（从本地文件系统删除）
func (p *PocFileService) DeletePocFile(relativePath string) error {
	defer p.invalidateCache()

	// 验证相对路径（防止路径遍历攻击）
	cleanedPath, err := validateRelativePath(relativePath)
	if err != nil {
		return err
	}

	fullPath, err := p.resolveSafePocPath(cleanedPath)
	if err != nil {
		return err
	}

	// 删除文件
	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("文件不存在: %s", relativePath)
		}
		return fmt.Errorf("删除文件失败: %w", err)
	}

	// 尝试删除空的父目录
	parentDir := filepath.Dir(fullPath)
	configRoot, _ := filepath.Abs(p.configPath)
	if parentDir != configRoot {
		// 检查目录是否为空
		entries, err := os.ReadDir(parentDir)
		if err == nil && len(entries) == 0 {
			os.Remove(parentDir) // 忽略错误
		}
	}

	return nil
}

func (p *PocFileService) ImportPocFile(category string, fileName string, content []byte, userID *int) error {
	return p.CreatePocFile(category, fileName, string(content), userID, true)
}

func (p *PocFileService) parseYAMLMetadata(content string) (pocId, name, author, severity string, tags []string, fingerprintName string) {
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &yamlData); err != nil {
		return
	}

	// 读取id字段（根级别）
	if id, ok := yamlData["id"].(string); ok {
		pocId = id
	}

	// 读取info对象下的字段
	if info, ok := yamlData["info"].(map[string]interface{}); ok {
		// 读取name字段
		if nameField, ok := info["name"]; ok {
			if nameStr, ok := nameField.(string); ok {
				name = nameStr
			} else if nameArray, ok := nameField.([]interface{}); ok && len(nameArray) > 0 {
				if firstItem, ok := nameArray[0].(string); ok {
					name = firstItem
				}
			}
		}

		// 读取author字段
		if authorField, ok := info["author"].(string); ok {
			author = authorField
		} else if authorArray, ok := info["author"].([]interface{}); ok && len(authorArray) > 0 {
			if firstAuthor, ok := authorArray[0].(string); ok {
				author = firstAuthor
			}
		}

		// 读取severity字段
		if severityField, ok := info["severity"].(string); ok {
			severity = severityField
		}

		// 读取tags字段
		if tagsField, ok := info["tags"]; ok {
			if tagsArray, ok := tagsField.([]interface{}); ok {
				for _, tagItem := range tagsArray {
					if tagStr, ok := tagItem.(string); ok {
						tags = append(tags, tagStr)
					}
				}
			} else if tagStr, ok := tagsField.(string); ok {
				tags = append(tags, tagStr)
			}
		}
	}

	// 从tags中提取指纹名称（查找包含"fingerprint"或常见指纹名称的tag）
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		// 如果tag包含常见指纹关键词，使用它作为指纹名称
		if strings.Contains(tagLower, "fingerprint") ||
			strings.Contains(tagLower, "nginx") ||
			strings.Contains(tagLower, "apache") ||
			strings.Contains(tagLower, "tomcat") ||
			strings.Contains(tagLower, "iis") ||
			strings.Contains(tagLower, "php") ||
			strings.Contains(tagLower, "java") ||
			strings.Contains(tagLower, "python") ||
			strings.Contains(tagLower, "node") ||
			strings.Contains(tagLower, "mysql") ||
			strings.Contains(tagLower, "redis") ||
			strings.Contains(tagLower, "mongodb") {
			fingerprintName = tag
			break
		}
	}

	// 如果仍未找到指纹名称，尝试从name中提取
	if fingerprintName == "" && name != "" {
		nameLower := strings.ToLower(name)
		// 检查name中是否包含常见指纹名称
		fingerprints := []string{"nginx", "apache", "tomcat", "iis", "php", "java", "python", "node", "mysql", "redis", "mongodb"}
		for _, fp := range fingerprints {
			if strings.Contains(nameLower, fp) {
				fingerprintName = fp
				break
			}
		}
	}

	return
}

// DeleteAllPOCs 删除所有 POC 模板（从本地文件系统删除）
// 目前仅支持管理员删除所有文件，忽略userID和createdByFilter（因为文件没有所有者信息）
func (p *PocFileService) DeleteAllPOCs(userID *int, createdByFilter *int) (int, error) {
	defer p.invalidateCache()

	// 统计文件数量
	count := 0
	filepath.Walk(p.configPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			name := strings.ToLower(info.Name())
			if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
				count++
			}
		}
		return nil
	})

	// 删除整个目录
	if err := os.RemoveAll(p.configPath); err != nil {
		return 0, fmt.Errorf("删除POC目录失败: %w", err)
	}

	// 重建目录
	if err := os.MkdirAll(p.configPath, 0755); err != nil {
		return count, fmt.Errorf("重建POC目录失败: %w", err)
	}

	logger.Info("已清空POC目录，共删除 %d 个文件", count)
	return count, nil
}

// ValidatePOC 验证 POC 格式
func (p *PocFileService) ValidatePOC(content string) (bool, []string) {
	var errors []string

	// 基本验证
	if strings.TrimSpace(content) == "" {
		errors = append(errors, "POC 内容不能为空")
		return false, errors
	}

	var root map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		errors = append(errors, fmt.Sprintf("YAML 语法错误: %v", err))
		return false, errors
	}
	if len(root) == 0 {
		errors = append(errors, "POC 内容必须是 YAML 对象")
		return false, errors
	}

	if id, ok := root["id"].(string); !ok || strings.TrimSpace(id) == "" {
		errors = append(errors, "缺少必要字段: id")
	}

	info, ok := root["info"].(map[string]interface{})
	if !ok || len(info) == 0 {
		errors = append(errors, "缺少必要字段: info")
	} else {
		if name, ok := info["name"].(string); !ok || strings.TrimSpace(name) == "" {
			errors = append(errors, "缺少必要字段: info.name")
		}
		if severity, exists := info["severity"]; exists {
			severityText, ok := severity.(string)
			if !ok || strings.TrimSpace(severityText) == "" {
				errors = append(errors, "info.severity 必须是非空字符串")
			} else {
				validSeverity := map[string]bool{
					"info": true, "low": true, "medium": true, "high": true, "critical": true, "unknown": true,
				}
				if !validSeverity[strings.ToLower(strings.TrimSpace(severityText))] {
					errors = append(errors, "info.severity 必须是 info/low/medium/high/critical/unknown 之一")
				}
			}
		}
	}

	protocolFields := []string{"requests", "http", "network", "dns", "ssl", "file", "headless", "javascript", "code"}
	hasProtocol := false
	for _, field := range protocolFields {
		if _, exists := root[field]; exists {
			hasProtocol = true
			break
		}
	}
	if !hasProtocol {
		errors = append(errors, "缺少协议请求配置: requests/http/network/dns/ssl/file/headless/javascript/code")
	}

	return len(errors) == 0, errors
}

// CleanupTempPocFiles 清理临时POC文件（文件系统清理已在 DeletePocFile 中处理）
// 此函数主要用于清理可能残留的空目录
func (p *PocFileService) CleanupTempPocFiles(userID int) error {
	// 遍历 pocs_temp 目录
	tempDir := filepath.Join(p.configPath, "pocs_temp")
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		return nil
	}

	// 尝试删除空的 pocs_temp
	os.Remove(tempDir)
	return nil
}
