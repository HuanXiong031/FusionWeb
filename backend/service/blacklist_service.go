// ========================================
// 黑名单服务（Blacklist Service）
//
// 功能概述：
//
//	负责管理系统中的指纹黑名单，提供完整的增删改查功能。
//	黑名单用于在漏洞扫描时过滤掉不需要扫描的指纹，提高扫描效率。
//
// 核心特性：
//  1. 数据库存储：使用 PostgreSQL 数据库持久化存储黑名单数据
//  2. 分类管理：支持按分类组织黑名单项，便于管理和查找
//  3. 数据源统一：仅从数据库读取和写入，不再依赖配置文件
//  4. 向后兼容：保留旧版纯列表接口，确保现有代码正常工作
//  5. 分页查询：支持分页、分类过滤、关键字搜索等功能
//
// 数据结构：
//   - BlacklistConfig: 按分类组织的黑名单配置（map[分类名][]条目）
//   - BlacklistItem: 单个黑名单项（包含分类和值）
//
// 主要功能：
//   - GetBlacklist: 获取所有黑名单项（扁平列表，兼容旧版）
//   - GetBlacklistByCategory: 按分类获取黑名单
//   - GetBlacklistItemsPage: 分页获取黑名单项（支持分类和关键字过滤）
//   - SaveBlacklistByCategory: 按分类保存黑名单到数据库
//   - AddToBlacklistWithCategory: 添加项到指定分类
//   - RemoveFromBlacklistWithCategory: 从指定分类移除项
//   - IsInBlacklist: 检查某个值是否在黑名单中
//
// 注意事项：
//   - 空分类会保留（使用占位符 "__EMPTY_CATEGORY__"）
//   - 所有操作都使用事务保证数据一致性
//
// ========================================
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// BlacklistService 黑名单服务结构体
//
// 负责管理黑名单的所有操作，包括读取、保存、添加、删除等。
// 数据源统一使用数据库。
type BlacklistService struct{}

// BlacklistConfig 黑名单配置结构（按分类组织）
//
// 使用 map 结构，键为分类名称，值为该分类下的黑名单项列表。
// 例如：
//
//	{
//	  "Web框架": ["Django", "Flask"],
//	  "CMS": ["WordPress", "Drupal"]
//	}
type BlacklistConfig map[string][]string

// BlacklistItem 黑名单项结构（用于前端展示和 API 返回）
//
// 包含分类和值两个字段，便于前端按分类展示和管理。
type BlacklistItem struct {
	Category string `json:"category"` // 分类名称
	Value    string `json:"value"`    // 黑名单项的值
}

// NewBlacklistService 创建黑名单服务实例
//
// 返回值：
//   - *BlacklistService: 黑名单服务实例
//
// 功能说明：
//
//		初始化服务实例，数据完全来源于数据库。
//	 如果数据库中没有黑名单数据，会自动初始化默认黑名单。
func NewBlacklistService() *BlacklistService {
	service := &BlacklistService{}
	// 尝试初始化默认数据（异步执行，不阻塞启动）
	go service.EnsureDefaults()
	return service
}

// EnsureDefaults 确保有默认的黑名单数据
func (b *BlacklistService) EnsureDefaults() {
	if database.DB == nil {
		return
	}

	// 检查是否有数据
	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM blacklist").Scan(&count)
	if err != nil {
		return
	}
	if count > 0 {
		if err := b.SyncFingerprintBlacklistFlagsFromDB(); err != nil {
			logger.Warn("同步指纹黑名单状态失败: %v", err)
		}
		return
	}

	// 初始化默认数据
	logger.Info("初始化默认指纹黑名单...")
	defaultConfig := BlacklistConfig{
		"通用干扰项": []string{
			"Apache default page",
			"IIS default page",
			"Welcome to nginx",
		},
		"无效页面": []string{
			"404 Not Found",
			"500 Internal Server Error",
			"502 Bad Gateway",
		},
	}
	_ = b.SaveBlacklistByCategory(defaultConfig)
}

// GetBlacklist 获取所有黑名单项（扁平列表，保持向后兼容）
//
// 返回值：
//   - []string: 所有黑名单项的列表（不包含分类信息）
//   - error: 错误信息，如果读取失败则返回错误
//
// 功能说明：
//
//	获取所有分类下的黑名单项，合并为一个扁平列表返回。
//	此方法主要用于兼容旧版代码，新代码建议使用 GetBlacklistByCategory。
//
// 使用场景：
//   - 需要快速检查某个值是否在黑名单中
//   - 旧版代码需要获取所有黑名单项
func (b *BlacklistService) GetBlacklist() ([]string, error) {
	// 先获取按分类组织的配置
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return nil, err
	}

	// 将所有分类的项合并为一个列表
	blacklist := make([]string, 0)
	for _, items := range config {
		for _, item := range items {
			item = strings.TrimSpace(item)
			// 过滤空项和占位符
			if item != "" {
				blacklist = append(blacklist, item)
			}
		}
	}

	return blacklist, nil
}

// GetBlacklistByCategory 按分类获取黑名单配置（从数据库读取）
//
// 返回值：
//   - BlacklistConfig: 按分类组织的黑名单配置
//   - error: 错误信息，如果读取失败则返回错误
//
// 功能说明：
//
//	从数据库读取所有分类及其下的黑名单项，返回按分类组织的配置。
//
// 数据格式：
//
//	返回的配置中，每个分类对应一个字符串数组。
//	空分类会保留（使用占位符 "__EMPTY_CATEGORY__"），但不会在结果中显示。
//
// 使用场景：
//   - 需要按分类展示黑名单
//   - 需要保存和修改黑名单配置
func (b *BlacklistService) GetBlacklistByCategory() (BlacklistConfig, error) {
	// 检查数据库是否初始化
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	// 从数据库读取所有分类（去重并按字母顺序排序）
	rows, err := database.DB.Query("SELECT DISTINCT category FROM blacklist ORDER BY category")
	if err != nil {
		return nil, fmt.Errorf("查询黑名单分类失败: %w", err)
	}
	defer rows.Close()

	result := make(BlacklistConfig)
	var categories []string

	// 收集所有分类名称
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			continue
		}
		if isUnsupportedAccessPolicyCategory(category) {
			continue
		}
		categories = append(categories, category)
	}

	// 为每个分类读取其下的所有条目
	for _, category := range categories {
		itemRows, err := database.DB.Query("SELECT item FROM blacklist WHERE category = ? ORDER BY id", category)
		if err != nil {
			logger.Warn("读取分类 %s 的条目失败: %v", category, err)
			continue
		}

		var items []string
		for itemRows.Next() {
			var item string
			if err := itemRows.Scan(&item); err != nil {
				continue
			}
			// 过滤掉占位符条目（空分类的占位符）
			if item != "__EMPTY_CATEGORY__" {
				items = append(items, item)
			}
		}
		itemRows.Close()

		// 即使为空数组也要返回，以保留空分类的结构
		result[category] = items
	}

	return result, nil
}

// GetBlacklistItemsPage 分页获取黑名单项（支持分类和关键字过滤）
//
// 参数：
//   - page: 页码（从1开始）
//   - pageSize: 每页数量
//   - category: 分类过滤（为空则不过滤）
//   - keyword: 关键字过滤（为空则不过滤，会匹配分类名和项值）
//
// 返回值：
//   - []BlacklistItem: 当前页的黑名单项列表
//   - int: 总记录数（用于前端分页计算）
//   - error: 错误信息
//
// 功能说明：
//
//	获取黑名单项的分页数据，支持按分类和关键字过滤。
//	结果会按分类和值进行排序，确保展示的一致性。
//
// 过滤规则：
//   - 分类过滤：只返回指定分类的项
//   - 关键字过滤：匹配项值或分类名（不区分大小写）
//
// 使用场景：
//   - 前端表格分页展示
//   - 搜索和筛选功能
func (b *BlacklistService) GetBlacklistItemsPage(page, pageSize int, category, keyword string) ([]BlacklistItem, int, error) {
	// 先获取所有配置
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return nil, 0, err
	}

	// 转换为列表并应用过滤条件
	var items []BlacklistItem
	keywordLower := strings.ToLower(keyword)

	// 遍历所有分类和项
	for cat, values := range config {
		// 分类过滤：如果指定了分类，只处理匹配的分类
		if category != "" && cat != category {
			continue
		}

		// 遍历该分类下的所有项
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}

			// 关键字过滤：匹配项值或分类名（不区分大小写）
			if keyword != "" {
				valueLower := strings.ToLower(value)
				catLower := strings.ToLower(cat)
				if !strings.Contains(valueLower, keywordLower) &&
					!strings.Contains(catLower, keywordLower) {
					continue
				}
			}

			// 添加到结果列表
			items = append(items, BlacklistItem{
				Category: cat,
				Value:    value,
			})
		}
	}

	// 排序：先按分类排序，同分类内按值排序
	sort.Slice(items, func(i, j int) bool {
		if items[i].Category == items[j].Category {
			return items[i].Value < items[j].Value
		}
		return items[i].Category < items[j].Category
	})

	total := len(items)

	// 计算分页范围
	start := (page - 1) * pageSize
	if start >= total {
		// 超出范围，返回空列表
		return []BlacklistItem{}, total, nil
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	// 返回当前页的数据
	return items[start:end], total, nil
}

// GetBlacklistItems 获取所有黑名单项列表（带分类信息）
//
// 返回值：
//   - []BlacklistItem: 所有黑名单项的列表
//   - error: 错误信息
//
// 功能说明：
//
//	获取所有黑名单项，包含分类信息，用于需要完整列表的场景。
//
// 使用场景：
//   - 导出黑名单数据
//   - 批量操作
func (b *BlacklistService) GetBlacklistItems() ([]BlacklistItem, error) {
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return nil, err
	}

	items := make([]BlacklistItem, 0)
	for category, values := range config {
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				items = append(items, BlacklistItem{
					Category: category,
					Value:    value,
				})
			}
		}
	}

	return items, nil
}

// GetCategories 获取所有分类名称列表
//
// 返回值：
//   - []string: 所有分类名称的列表
//   - error: 错误信息
//
// 功能说明：
//
//	获取所有黑名单分类的名称，用于前端下拉选择等场景。
//
// 使用场景：
//   - 分类选择器
//   - 分类统计
func (b *BlacklistService) GetCategories() ([]string, error) {
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return nil, err
	}

	categories := make([]string, 0, len(config))
	for category := range config {
		categories = append(categories, category)
	}

	return categories, nil
}

// SaveBlacklist 保存黑名单列表（保持向后兼容，不推荐使用）
//
// 参数：
//   - blacklist: 黑名单项列表（扁平列表）
//
// 返回值：
//   - error: 错误信息
//
// 功能说明：
//
//	将简单的字符串列表保存为黑名单，所有项会被放入"未分类"分类。
//	此方法主要用于兼容旧版代码，新代码建议使用 SaveBlacklistByCategory。
//
// 注意：
//
//	此方法会覆盖现有的"未分类"分类数据。
func (b *BlacklistService) SaveBlacklist(blacklist []string) error {
	// 将简单列表转换为分类结构（放入"未分类"分类）
	config := BlacklistConfig{
		"未分类": blacklist,
	}
	return b.SaveBlacklistByCategory(config)
}

// SaveBlacklistByCategory 按分类保存黑名单到数据库
//
// 参数：
//   - config: 按分类组织的黑名单配置
//
// 返回值：
//   - error: 错误信息，如果保存失败则返回错误
//
// 功能说明：
//
//	将黑名单配置保存到数据库，使用事务保证数据一致性。
//	保存逻辑：
//	1. 删除配置中每个分类的旧数据
//	2. 插入新数据（空分类会插入占位符）
//	3. 删除不在新配置中的分类
//
// 事务处理：
//
//	所有操作在一个事务中完成，如果任何步骤失败，整个操作会回滚。
//
// 空分类处理：
//
//	如果某个分类的项列表为空，会插入占位符 "__EMPTY_CATEGORY__" 以保留分类。
//
// 使用场景：
//   - 批量更新黑名单
//   - 导入黑名单配置
func (b *BlacklistService) SaveBlacklistByCategory(config BlacklistConfig) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	config = removeUnsupportedAccessPolicyCategories(config)

	// 开始事务
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer tx.Rollback() // 确保在出错时回滚

	// 获取所有现有分类（用于后续删除不在新配置中的分类）
	rows, err := tx.Query("SELECT DISTINCT category FROM blacklist")
	if err != nil {
		return fmt.Errorf("查询现有分类失败: %w", err)
	}

	existingCategories := make(map[string]bool)
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			continue
		}
		existingCategories[category] = true
	}
	rows.Close()

	// 处理每个分类
	for category, items := range config {
		// 删除该分类的所有旧数据
		_, err = tx.Exec("DELETE FROM blacklist WHERE category = ?", category)
		if err != nil {
			return fmt.Errorf("删除分类 %s 的旧数据失败: %w", category, err)
		}

		// 如果 items 为空，插入一个占位符以保留分类
		if len(items) == 0 {
			_, err = tx.Exec("INSERT INTO blacklist (category, item, updated_at) VALUES (?, ?, ?) ON CONFLICT (category, item) DO NOTHING", category, "__EMPTY_CATEGORY__", utils.GetCurrentTimeString())
			if err != nil {
				logger.Warn("插入空分类占位符失败: %v", err)
			}
		} else {
			// 插入新数据（使用预编译语句提高性能）
			stmt, err := tx.Prepare("INSERT INTO blacklist (category, item, updated_at) VALUES (?, ?, ?) ON CONFLICT (category, item) DO NOTHING")
			if err != nil {
				return fmt.Errorf("准备插入语句失败: %w", err)
			}

			for _, item := range items {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				if _, err := stmt.Exec(category, item, utils.GetCurrentTimeString()); err != nil {
					logger.Warn("插入黑名单条目失败: %v", err)
				}
			}
			stmt.Close()
		}
	}

	// 删除不在新配置中的分类
	for category := range existingCategories {
		if _, exists := config[category]; !exists {
			_, err = tx.Exec("DELETE FROM blacklist WHERE category = ?", category)
			if err != nil {
				logger.Warn("删除分类 %s 失败: %v", category, err)
			}
		}
	}

	if err := syncFingerprintBlacklistFlags(tx, config); err != nil {
		return err
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}

	return nil
}

func (b *BlacklistService) SyncFingerprintBlacklistFlagsFromDB() error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return err
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开始同步指纹黑名单事务失败: %w", err)
	}
	defer tx.Rollback()
	if err := syncFingerprintBlacklistFlags(tx, config); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交同步指纹黑名单事务失败: %w", err)
	}
	return nil
}

func syncFingerprintBlacklistFlags(tx *sql.Tx, config BlacklistConfig) error {
	var items []string
	for category, categoryItems := range config {
		if strings.EqualFold(strings.TrimSpace(category), "fingerprint") {
			items = categoryItems
			break
		}
	}

	for _, tableName := range []string{"passive_fingerprints", "active_fingerprints"} {
		if _, err := tx.Exec(fmt.Sprintf("UPDATE %s SET is_blacklisted = 0, updated_at = ?", tableName), utils.GetCurrentTimeString()); err != nil {
			return fmt.Errorf("重置指纹黑名单状态失败: %w", err)
		}
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" || item == "__EMPTY_CATEGORY__" {
				continue
			}
			if _, err := tx.Exec(fmt.Sprintf("UPDATE %s SET is_blacklisted = 1, updated_at = ? WHERE LOWER(name) = LOWER(?)", tableName), utils.GetCurrentTimeString(), item); err != nil {
				return fmt.Errorf("同步指纹黑名单状态失败: %w", err)
			}
		}
	}
	return nil
}

// AddToBlacklist 添加到黑名单（添加到"未分类"分类）
//
// 参数：
//   - item: 要添加的黑名单项
//
// 返回值：
//   - error: 错误信息，如果项已存在或添加失败则返回错误
//
// 功能说明：
//
//	将项添加到"未分类"分类，如果项已存在于任何分类中，会返回错误。
//
// 使用场景：
//   - 快速添加项到默认分类
func (b *BlacklistService) AddToBlacklist(item string) error {
	return b.AddToBlacklistWithCategory("未分类", item)
}

// AddToBlacklistWithCategory 添加到指定分类的黑名单
//
// 参数：
//   - category: 分类名称
//   - item: 要添加的黑名单项
//
// 返回值：
//   - error: 错误信息，如果项已存在或添加失败则返回错误
//
// 功能说明：
//
//	将项添加到指定分类，如果项已存在于任何分类中，会返回错误。
//	如果分类不存在，会自动创建该分类。
//
// 重复检查：
//
//	会检查项是否已存在于任何分类中（不区分大小写），如果存在则返回错误。
//
// 使用场景：
//   - 手动添加黑名单项
//   - 从扫描结果添加指纹到黑名单
func (b *BlacklistService) AddToBlacklistWithCategory(category, item string) error {
	item = strings.TrimSpace(item)
	if item == "" {
		return fmt.Errorf("黑名单项不能为空")
	}

	category = strings.TrimSpace(category)
	if category == "" {
		category = "未分类"
	}
	if isUnsupportedAccessPolicyCategory(category) {
		return fmt.Errorf("访问策略不再支持端口分类，请使用 IP 或域名")
	}

	// 获取当前黑名单配置
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return err
	}

	// 检查是否已存在于任何分类中（不区分大小写）
	for cat, items := range config {
		for _, existing := range items {
			if strings.EqualFold(existing, item) {
				return fmt.Errorf("黑名单中已存在: %s (分类: %s)", item, cat)
			}
		}
	}

	// 添加到指定分类（如果分类不存在则创建）
	if config[category] == nil {
		config[category] = make([]string, 0)
	}
	config[category] = append(config[category], item)

	// 保存到数据库
	return b.SaveBlacklistByCategory(config)
}

// RemoveFromBlacklist 从黑名单移除（从任意分类）
//
// 参数：
//   - item: 要移除的黑名单项
//
// 返回值：
//   - error: 错误信息，如果项不存在或移除失败则返回错误
//
// 功能说明：
//
//	从所有分类中查找并移除指定的项，如果项不存在则返回错误。
//	如果移除后某个分类为空，会删除该分类。
//
// 使用场景：
//   - 手动移除黑名单项
func (b *BlacklistService) RemoveFromBlacklist(item string) error {
	item = strings.TrimSpace(item)
	if item == "" {
		return fmt.Errorf("黑名单项不能为空")
	}

	// 获取当前黑名单配置
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return err
	}

	// 查找并移除（不区分大小写）
	found := false
	for category, items := range config {
		newItems := make([]string, 0)
		for _, existing := range items {
			if !strings.EqualFold(existing, item) {
				newItems = append(newItems, existing)
			} else {
				found = true
			}
		}
		if len(newItems) > 0 {
			config[category] = newItems
		} else {
			// 如果分类为空，删除该分类
			delete(config, category)
		}
	}

	if !found {
		return fmt.Errorf("黑名单中不存在: %s", item)
	}

	// 保存到数据库
	return b.SaveBlacklistByCategory(config)
}

// RemoveFromBlacklistWithCategory 从指定分类移除黑名单项
//
// 参数：
//   - category: 分类名称
//   - item: 要移除的黑名单项
//
// 返回值：
//   - error: 错误信息，如果分类或项不存在或移除失败则返回错误
//
// 功能说明：
//
//	从指定分类中移除项，如果分类或项不存在则返回错误。
//	如果移除后分类为空，会删除该分类。
//
// 使用场景：
//   - 从特定分类移除项
//   - 分类管理
func (b *BlacklistService) RemoveFromBlacklistWithCategory(category, item string) error {
	item = strings.TrimSpace(item)
	if item == "" {
		return fmt.Errorf("黑名单项不能为空")
	}
	if isUnsupportedAccessPolicyCategory(category) {
		_, _ = database.DB.Exec("DELETE FROM blacklist WHERE LOWER(category) = 'port'")
		return nil
	}

	// 获取当前黑名单配置
	config, err := b.GetBlacklistByCategory()
	if err != nil {
		return err
	}

	// 检查分类是否存在
	items, exists := config[category]
	if !exists {
		return fmt.Errorf("分类不存在: %s", category)
	}

	// 查找并移除（不区分大小写）
	found := false
	newItems := make([]string, 0)
	for _, existing := range items {
		if !strings.EqualFold(existing, item) {
			newItems = append(newItems, existing)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("分类 %s 中不存在: %s", category, item)
	}

	// 更新配置
	if len(newItems) > 0 {
		config[category] = newItems
	} else {
		// 如果分类为空，删除该分类
		delete(config, category)
	}

	// 保存到数据库
	return b.SaveBlacklistByCategory(config)
}

func isUnsupportedAccessPolicyCategory(category string) bool {
	return strings.EqualFold(strings.TrimSpace(category), "port")
}

func removeUnsupportedAccessPolicyCategories(config BlacklistConfig) BlacklistConfig {
	next := make(BlacklistConfig, len(config))
	for category, items := range config {
		if isUnsupportedAccessPolicyCategory(category) {
			continue
		}
		next[category] = items
	}
	return next
}

// IsInBlacklist 检查某个值是否在黑名单中
//
// 参数：
//   - item: 要检查的值
//
// 返回值：
//   - bool: true 表示在黑名单中，false 表示不在
//   - error: 错误信息，如果查询失败则返回错误
//
// 功能说明：
//
//	检查指定的值是否存在于黑名单中（不区分大小写）。
//	会检查所有分类，只要在任意分类中找到匹配项就返回 true。
//
// 匹配规则：
//
//	使用不区分大小写的字符串比较。
//
// 使用场景：
//   - 扫描前检查指纹是否应该被过滤
//   - 验证用户输入
func (b *BlacklistService) IsInBlacklist(item string) (bool, error) {
	blacklist, err := b.GetBlacklist()
	if err != nil {
		return false, err
	}

	item = strings.ToLower(strings.TrimSpace(item))
	for _, existing := range blacklist {
		if strings.ToLower(existing) == item {
			return true, nil
		}
	}

	return false, nil
}
