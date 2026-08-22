package service

import (
	"FusionWeb/backend/core/structs"
	"FusionWeb/backend/database"
	"FusionWeb/backend/engine/lib/ddfinger"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// FingerprintValidationResult 指纹验证结果
type FingerprintValidationResult struct {
	IsValid       bool     `json:"isValid"`       // 是否有效
	Issues        []string `json:"issues"`        // 问题列表
	FixedRules    []string `json:"fixedRules"`    // 修正后的规则
	OriginalRules []string `json:"originalRules"` // 原始规则
}

// FingerprintValidationError 指纹验证错误
type FingerprintValidationError struct {
	Result *FingerprintValidationResult
}

func (e *FingerprintValidationError) Error() string {
	// 将验证结果序列化为JSON，以便前端解析
	jsonData, err := json.Marshal(e.Result)
	if err != nil {
		return fmt.Sprintf("指纹规则验证失败: %s", strings.Join(e.Result.Issues, "; "))
	}
	// 返回包含JSON的错误消息，前端可以解析
	return fmt.Sprintf("FINGERPRINT_VALIDATION_ERROR:%s", string(jsonData))
}

// FingerprintItem 单个指纹项（用于前端显示和API交互）
type FingerprintItem struct {
	Name          string   `json:"name"`
	Category      string   `json:"category"`
	Type          string   `json:"type"` // "active" 或 "passive"
	Description   string   `json:"description"`
	Rules         []string `json:"rules"`
	IsBlacklisted bool     `json:"isBlacklisted"`
	IsEnabled     bool     `json:"isEnabled"`
	CreatedAt     string   `json:"createdAt"`
	UpdatedAt     string   `json:"updatedAt"`
}

type FingerprintDBService struct{}

func NewFingerprintDBService() *FingerprintDBService {
	return &FingerprintDBService{}
}

func resetFingerprintRuntimeCache() {
	structs.FingerprintDB = nil
	structs.DirDB = nil
}

func (f *FingerprintDBService) GetFingerprintsPageByType(page, pageSize int, fpType, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) ([]FingerprintItem, int, error) {
	if database.DB == nil {
		return nil, 0, fmt.Errorf("数据库未初始化")
	}

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fpType == "active" {
		tableName = "active_fingerprints"
	}

	// 验证表名（防止 SQL 注入）
	if err := ValidateTableName(tableName); err != nil {
		return nil, 0, err
	}

	// 构建查询条件
	whereClauses := []string{"1=1"} // 基础条件，确保 WHERE 子句有效
	args := []interface{}{}

	// 分类过滤（这里使用name作为分类）
	if category != "" {
		whereClauses = append(whereClauses, "name = ?")
		args = append(args, category)
	}

	// 关键字过滤（在 name、description、rules 字段中搜索）
	if keyword != "" {
		whereClauses = append(whereClauses, "(name LIKE ? OR description LIKE ? OR rules LIKE ?)")
		keywordPattern := "%" + keyword + "%"
		args = append(args, keywordPattern, keywordPattern, keywordPattern)
	}

	if blacklistedOnly {
		whereClauses = append(whereClauses, "is_blacklisted = 1")
	}

	// admin角色可以按创建者筛选
	if createdByFilter != nil {
		whereClauses = append(whereClauses, "created_by = ?")
		args = append(args, *createdByFilter)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// 查询总数
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", tableName, whereSQL)
	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("查询总数失败: %w", err)
	}

	// 分页查询
	offset := (page - 1) * pageSize

	// 验证排序字段和排序方向（防止 SQL 注入）
	validSortFields := map[string]bool{
		"name":       true,
		"created_at": true,
		"updated_at": true,
		"id":         true,
	}
	if sortBy == "" || !validSortFields[sortBy] {
		sortBy = "id" // 默认排序字段
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc" // 默认排序方向
	}

	// 执行分页查询
	query := fmt.Sprintf(`
		SELECT id, name, description, rules, is_blacklisted, is_enabled, created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT) 
		FROM %s 
		WHERE %s 
		ORDER BY %s %s
		LIMIT ? OFFSET ?
	`, tableName, whereSQL, sortBy, sortOrder)

	args = append(args, pageSize, offset)
	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询指纹失败: %w", err)
	}
	defer rows.Close()

	// 解析查询结果
	var items []FingerprintItem
	for rows.Next() {
		var item FingerprintItem
		var rulesYAML string
		var isBlacklisted, isEnabled int
		var id int
		var createdAt, updatedAt sql.NullString

		var createdBy sql.NullInt64
		err := rows.Scan(&id, &item.Name, &item.Description, &rulesYAML,
			&isBlacklisted, &isEnabled, &createdBy, &createdAt, &updatedAt)
		if err != nil {
			logger.Error("扫描指纹数据失败: %v", err)
			continue
		}
		item.CreatedAt = utils.FormatNullTimeStringForDisplay(createdAt)
		item.UpdatedAt = utils.FormatNullTimeStringForDisplay(updatedAt)

		// 解析规则YAML（从数据库中的 YAML 字符串转换为字符串数组）
		var rules []string
		if err := yaml.Unmarshal([]byte(rulesYAML), &rules); err != nil {
			rules = []string{} // 解析失败时使用空数组
		}

		// 设置指纹项属性
		item.Type = fpType
		if item.Type == "" {
			item.Type = "passive" // 默认值
		}
		item.Rules = rules
		item.Category = item.Name // 使用 name 作为分类
		item.IsBlacklisted = isBlacklisted == 1
		item.IsEnabled = isEnabled == 1

		items = append(items, item)
	}

	// 检查遍历过程中是否有错误
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("遍历结果集失败: %w", err)
	}

	return items, total, nil
}

// GetFingerprintsPage 分页获取指纹（向后兼容，默认返回被动指纹）
//
// 参数：
//   - page: 页码
//   - pageSize: 每页数量
//   - category: 分类过滤
//   - keyword: 关键字过滤
//   - sortBy: 排序字段
//   - sortOrder: 排序方向
//
// 返回值：
//   - []FingerprintItem: 指纹项列表
//   - int: 总记录数
//   - error: 错误信息
//
// 功能说明：
//
//	向后兼容方法，默认查询被动指纹。
//	新代码建议直接使用 GetFingerprintsPageByType 指定类型。
func (f *FingerprintDBService) GetFingerprintsPage(page, pageSize int, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) ([]FingerprintItem, int, error) {
	return f.GetFingerprintsPageByType(page, pageSize, "passive", category, keyword, sortBy, sortOrder, createdByFilter, blacklistedOnly)
}

// GetFingerprints 获取所有指纹
//
// 返回值：
//   - []FingerprintItem: 所有指纹项的列表
//   - error: 错误信息
//
// 功能说明：
//
//	获取所有被动指纹（最多 10000 条），用于需要完整列表的场景。
//
// 使用场景：
//   - 导出所有指纹
//   - 批量操作
func (f *FingerprintDBService) GetFingerprints() ([]FingerprintItem, error) {
	items, _, err := f.GetFingerprintsPage(1, 10000, "", "", "id", "asc", nil, false)
	return items, err
}

// GetCategories 获取所有分类名称列表（从两个表中获取）
//
// 返回值：
//   - []string: 所有分类名称的列表（已去重并排序）
//   - error: 错误信息
//
// 功能说明：
//
//	从被动指纹表和主动指纹表中获取所有唯一的分类名称（name 字段）。
//	结果会按字母顺序排序。
//
// 使用场景：
//   - 分类选择器
//   - 分类统计
func (f *FingerprintDBService) GetCategories() ([]string, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	// 从两个表中获取所有分类（使用 UNION 去重）
	rows, err := database.DB.Query(`
		SELECT DISTINCT name FROM passive_fingerprints
		UNION
		SELECT DISTINCT name FROM active_fingerprints
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("查询分类失败: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		categories = append(categories, name)
	}

	return categories, nil
}

// GetFingerprintCategoriesByType 获取指定类型的分类
func (f *FingerprintDBService) GetFingerprintCategoriesByType(fpType string) ([]string, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	tableName := "passive_fingerprints"
	if fpType == "active" {
		tableName = "active_fingerprints"
	}

	rows, err := database.DB.Query(fmt.Sprintf("SELECT DISTINCT name FROM %s ORDER BY name", tableName))
	if err != nil {
		return nil, fmt.Errorf("查询分类失败: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		categories = append(categories, name)
	}
	return categories, nil
}

// ToggleFingerprintEnabled 切换指纹启用状态（兼容旧接口）
func (f *FingerprintDBService) ToggleFingerprintEnabled(name string) error {
	return f.ToggleEnabled(name)
}

// ValidateFingerprintRules 验证指纹规则表达式
//
// 参数：
//   - rules: 指纹规则列表
//
// 返回值：
//   - *FingerprintValidationResult: 验证结果，包含问题列表和修正后的规则
//
// 功能说明：
//
//	验证指纹规则表达式是否有语法错误，并尝试自动修正。
//	检查内容包括：
//	- 规则表达式语法错误（括号不匹配、操作符错误等）
//	- 规则格式错误
//	- 自动修正常见错误
func (f *FingerprintDBService) ValidateFingerprintRules(rules []string) *FingerprintValidationResult {
	result := &FingerprintValidationResult{
		IsValid:       true,
		Issues:        []string{},
		FixedRules:    make([]string, len(rules)),
		OriginalRules: make([]string, len(rules)),
	}

	// 复制原始规则
	copy(result.OriginalRules, rules)
	copy(result.FixedRules, rules)

	if len(rules) == 0 {
		result.IsValid = false
		result.Issues = append(result.Issues, "规则列表为空")
		return result
	}

	// 验证每条规则
	for i, rule := range rules {
		if strings.TrimSpace(rule) == "" {
			result.IsValid = false
			result.Issues = append(result.Issues, fmt.Sprintf("第 %d 条规则为空", i+1))
			continue
		}

		// 构建完整的表达式（将所有规则合并）
		originalExpr := rule

		// 解析规则，检查是否有语法错误
		parsedRules := ddfinger.ParseRule(rule)
		if len(parsedRules) == 0 && strings.Contains(rule, "=") {
			// 如果规则包含 = 但解析失败，说明格式可能有问题
			result.IsValid = false
			result.Issues = append(result.Issues, fmt.Sprintf("第 %d 条规则格式错误: %s", i+1, rule))
		}

		// 尝试清理表达式
		cleanedExpr := ddfinger.CleanExpression(rule)

		// 检查清理后的表达式是否还有问题
		cleanedLeftCount := strings.Count(cleanedExpr, "(")
		cleanedRightCount := strings.Count(cleanedExpr, ")")
		cleanedHasBracketMismatch := cleanedLeftCount != cleanedRightCount
		cleanedHasExtraBrackets := strings.Contains(cleanedExpr, "[[") || strings.Contains(cleanedExpr, "]]")

		// 如果清理后的表达式与原始不同，或者清理后仍有问题
		if cleanedExpr != originalExpr || cleanedHasBracketMismatch || cleanedHasExtraBrackets {
			result.FixedRules[i] = cleanedExpr
			result.IsValid = false

			// 如果清理后的表达式与原始不同，说明已经修正了问题，只报告一次
			if cleanedExpr != originalExpr {
				// 收集所有被修正的问题类型（基于原始规则）
				var fixedIssues []string
				originalLeftCount := strings.Count(originalExpr, "(")
				originalRightCount := strings.Count(originalExpr, ")")
				if originalLeftCount != originalRightCount {
					fixedIssues = append(fixedIssues, "括号不匹配")
				}
				if strings.Contains(originalExpr, "[[") || strings.Contains(originalExpr, "]]") {
					fixedIssues = append(fixedIssues, "多余的方括号")
				}

				// 只报告一次修正信息，包含所有被修正的问题类型
				if len(fixedIssues) > 0 {
					result.Issues = append(result.Issues,
						fmt.Sprintf("第 %d 条规则检测到语法问题（%s），已自动修正: %s -> %s",
							i+1, strings.Join(fixedIssues, "、"), originalExpr, cleanedExpr))
				} else {
					result.Issues = append(result.Issues,
						fmt.Sprintf("第 %d 条规则检测到语法问题，已自动修正: %s -> %s",
							i+1, originalExpr, cleanedExpr))
				}
			} else {
				// 如果清理后表达式与原始相同，但仍有问题，说明无法自动修正
				if cleanedHasBracketMismatch {
					result.Issues = append(result.Issues,
						fmt.Sprintf("第 %d 条规则括号不匹配: 左括号 %d 个，右括号 %d 个",
							i+1, cleanedLeftCount, cleanedRightCount))
				}
				if cleanedHasExtraBrackets {
					result.Issues = append(result.Issues,
						fmt.Sprintf("第 %d 条规则包含多余的方括号", i+1))
				}
			}
		} else {
			result.FixedRules[i] = originalExpr
		}
	}

	return result
}

// AddFingerprint 添加指纹（默认添加到被动指纹）
//
// 参数：
//   - fp: 指纹项指针
//   - createdBy: 创建者用户ID（nil 表示系统导入）
//
// 返回值：
//   - error: 错误信息
//
// 功能说明：
//
//	向后兼容方法，默认添加到被动指纹表。
//	新代码建议使用 AddFingerprintWithType 指定类型。
func (f *FingerprintDBService) AddFingerprint(fp *FingerprintItem, createdBy *int) error {
	return f.AddFingerprintWithType(fp, "passive", createdBy)
}

// AddFingerprintWithType 添加指纹（指定类型）
//
// 参数：
//   - fp: 指纹项指针（包含名称、描述、规则等信息）
//   - fpType: 指纹类型（"passive" 或 "active"）
//   - createdBy: 创建者用户ID（nil 表示系统导入）
//
// 返回值：
//   - error: 错误信息，如果名称已存在或添加失败则返回错误
//   - 如果规则有问题，返回 FingerprintValidationError，包含问题和修正建议
//
// 功能说明：
//
//	将新指纹添加到指定类型的表中。
//	添加前会检查名称和创建者的组合是否已存在，如果存在则返回错误。
//	添加前会验证规则表达式，如果发现问题，返回包含问题和修正建议的错误。
//
// 验证规则：
//   - 检查名称和创建者的组合是否已存在于指定表中
//   - 如果已存在，返回错误（同一用户不能创建同名指纹，但不同用户可以）
//   - 验证规则表达式语法
//   - 如果发现问题，返回 FingerprintValidationError
//
// 默认值：
//   - is_blacklisted: 0（不在黑名单）
//   - is_enabled: 1（启用）
//
// 使用场景：
//   - 手动添加指纹
//   - 导入单个指纹
func (f *FingerprintDBService) AddFingerprintWithType(fp *FingerprintItem, fpType string, createdBy *int) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fpType == "active" || fp.Type == "active" {
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return err
	}

	// 检查名称和创建者的组合是否已存在（在指定表中检查）
	var count int
	var err error
	if createdBy != nil {
		err = database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = ? AND created_by = ?", tableName), fp.Name, *createdBy).Scan(&count)
	} else {
		err = database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = ? AND created_by IS NULL", tableName), fp.Name).Scan(&count)
	}
	if err != nil {
		return fmt.Errorf("检查指纹名称失败: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("指纹名称已存在：%s", fp.Name)
	}

	// 验证规则表达式
	validationResult := f.ValidateFingerprintRules(fp.Rules)
	if !validationResult.IsValid {
		// 返回包含问题和修正建议的错误
		return &FingerprintValidationError{Result: validationResult}
	}

	// 将规则数组转换为YAML格式
	rulesYAML, err := yaml.Marshal(fp.Rules)
	if err != nil {
		return fmt.Errorf("序列化规则失败: %w", err)
	}

	// 插入数据库
	if createdBy != nil {
		_, err = database.DB.Exec(fmt.Sprintf(`
			INSERT INTO %s (name, description, rules, is_blacklisted, is_enabled, created_by) 
			VALUES (?, ?, ?, ?, ?, ?)
		`, tableName), fp.Name, fp.Description, string(rulesYAML), 0, 1, *createdBy)
	} else {
		_, err = database.DB.Exec(fmt.Sprintf(`
			INSERT INTO %s (name, description, rules, is_blacklisted, is_enabled, created_by) 
			VALUES (?, ?, ?, ?, ?, NULL)
		`, tableName), fp.Name, fp.Description, string(rulesYAML), 0, 1)
	}

	if err != nil {
		return fmt.Errorf("插入指纹失败: %w", err)
	}

	resetFingerprintRuntimeCache()
	return nil
}

// UpdateFingerprint 更新指纹信息
//
// 参数：
//   - fp: 指纹项指针（包含要更新的信息）
//
// 返回值：
//   - error: 错误信息，如果指纹不存在或更新失败则返回错误
//
// 功能说明：
//
//	根据指纹名称更新指纹的描述和规则。
//	更新操作不会修改名称，如果需要修改名称，请使用 UpdateFingerprintByOldName。
//
// 更新字段：
//   - description: 描述信息
//   - rules: 规则列表（会序列化为 YAML）
//   - updated_at: 自动更新为当前时间
//
// 验证规则：
//   - 检查指纹是否存在（根据 fp.Type 在对应表中查找）
//   - 如果不存在，返回错误
//
// 使用场景：
//   - 编辑指纹信息
//   - 更新指纹规则
func (f *FingerprintDBService) UpdateFingerprint(fp *FingerprintItem) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fp.Type == "active" {
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return err
	}

	// 检查是否存在
	var count int
	err := database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = ?", tableName), fp.Name).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查指纹失败: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("指纹不存在：%s", fp.Name)
	}

	// 验证规则表达式
	validationResult := f.ValidateFingerprintRules(fp.Rules)
	if !validationResult.IsValid {
		// 返回包含问题和修正建议的错误
		return &FingerprintValidationError{Result: validationResult}
	}

	// 将规则数组转换为YAML格式
	rulesYAML, err := yaml.Marshal(fp.Rules)
	if err != nil {
		return fmt.Errorf("序列化规则失败: %w", err)
	}

	// 更新数据库
	// 获取UTC+8时区的当前时间
	timeStr := utils.GetCurrentTimeString()

	_, err = database.DB.Exec(fmt.Sprintf(`
		UPDATE %s 
		SET description = ?, rules = ?, updated_at = ? 
		WHERE name = ?
	`, tableName), fp.Description, string(rulesYAML), timeStr, fp.Name)

	if err != nil {
		return fmt.Errorf("更新指纹失败: %w", err)
	}

	resetFingerprintRuntimeCache()
	return nil
}

// UpdateFingerprintByOldName 根据旧名称更新指纹（支持修改名称）
//
// 参数：
//   - oldName: 旧名称（用于定位要更新的指纹）
//   - fp: 指纹项指针（包含新名称和其他要更新的信息）
//
// 返回值：
//   - error: 错误信息，如果指纹不存在、新名称已存在或更新失败则返回错误
//
// 功能说明：
//
//	根据旧名称更新指纹，支持修改名称。
//	如果修改了名称，会检查新名称是否已存在，如果存在则返回错误。
//
// 更新字段：
//   - name: 名称（如果与旧名称不同）
//   - description: 描述信息
//   - rules: 规则列表（会序列化为 YAML）
//   - updated_at: 自动更新为当前时间
//
// 验证规则：
//  1. 检查旧名称是否存在（根据 fp.Type 在对应表中查找）
//  2. 如果修改了名称，检查新名称是否已存在
//  3. 如果新名称已存在，返回错误
//
// 使用场景：
//   - 重命名指纹
//   - 编辑指纹信息并修改名称
func (f *FingerprintDBService) UpdateFingerprintByOldName(oldName string, fp *FingerprintItem) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fp.Type == "active" {
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return err
	}

	// 检查旧名称是否存在
	var count int
	err := database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = ?", tableName), oldName).Scan(&count)
	if err != nil {
		return fmt.Errorf("检查指纹失败: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("指纹不存在：%s", oldName)
	}

	// 如果修改了名称，检查新名称是否已存在（在指定表中检查）
	if oldName != fp.Name {
		var newCount int
		err := database.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE name = ?", tableName), fp.Name).Scan(&newCount)
		if err != nil {
			return fmt.Errorf("检查新名称失败: %w", err)
		}
		if newCount > 0 {
			return fmt.Errorf("指纹名称已存在：%s", fp.Name)
		}
	}

	// 验证规则表达式
	validationResult := f.ValidateFingerprintRules(fp.Rules)
	if !validationResult.IsValid {
		// 返回包含问题和修正建议的错误
		return &FingerprintValidationError{Result: validationResult}
	}

	// 将规则数组转换为YAML格式
	rulesYAML, err := yaml.Marshal(fp.Rules)
	if err != nil {
		return fmt.Errorf("序列化规则失败: %w", err)
	}

	// 更新数据库
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	_, err = database.DB.Exec(fmt.Sprintf(`
		UPDATE %s 
		SET name = ?, description = ?, rules = ?, updated_at = ? 
		WHERE name = ?
	`, tableName), fp.Name, fp.Description, string(rulesYAML), timeStr, oldName)

	if err != nil {
		return fmt.Errorf("更新指纹失败: %w", err)
	}

	resetFingerprintRuntimeCache()
	return nil
}

// DeleteFingerprint 删除指纹（通过名称，从两个表中删除）
//
// 参数：
//   - name: 要删除的指纹名称
//
// 返回值：
//   - error: 错误信息，如果指纹不存在或删除失败则返回错误
//
// 功能说明：
//
//	根据名称删除指纹，会同时检查被动指纹表和主动指纹表。
//	如果指纹在任一表中存在，都会删除。
//
// 删除逻辑：
//  1. 检查指纹是否存在于 passive_fingerprints 表
//  2. 检查指纹是否存在于 active_fingerprints 表
//  3. 如果都不存在，返回错误
//  4. 如果存在，从对应的表中删除
//
// 使用场景：
//   - 删除不需要的指纹
//   - 清理重复或错误的指纹
func (f *FingerprintDBService) DeleteFingerprint(name string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 检查是否存在（在两个表中都检查）
	var passiveCount, activeCount int
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM passive_fingerprints WHERE name = ?", name).Scan(&passiveCount)
	_ = database.DB.QueryRow("SELECT COUNT(*) FROM active_fingerprints WHERE name = ?", name).Scan(&activeCount)

	if passiveCount == 0 && activeCount == 0 {
		return fmt.Errorf("指纹不存在：%s", name)
	}

	// 从两个表中删除（如果存在）
	if passiveCount > 0 {
		_, err := database.DB.Exec("DELETE FROM passive_fingerprints WHERE name = ?", name)
		if err != nil {
			return fmt.Errorf("删除被动指纹失败: %w", err)
		}
	}
	if activeCount > 0 {
		_, err := database.DB.Exec("DELETE FROM active_fingerprints WHERE name = ?", name)
		if err != nil {
			return fmt.Errorf("删除主动指纹失败: %w", err)
		}
	}

	resetFingerprintRuntimeCache()
	return nil
}

// DeleteAllFingerprints 删除所有指纹（根据用户角色和创建者过滤）
// userID: 当前用户ID，role: 当前用户角色，createdByFilter: 创建者过滤（可选）
func (f *FingerprintDBService) DeleteAllFingerprints(userID *int, createdByFilter *int) (int, error) {
	if database.DB == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}

	var deletedCount int

	// 构建删除条件
	var passiveWhere, activeWhere string
	var args []interface{}
	// 所有用户均可删除所有指纹
	if createdByFilter != nil {
		// 如果指定了创建者过滤，只删除该创建者的指纹
		passiveWhere = "WHERE created_by = ?"
		activeWhere = "WHERE created_by = ?"
		args = []interface{}{*createdByFilter}
	} else {
		// 删除所有指纹
		passiveWhere = ""
		activeWhere = ""
		args = []interface{}{}
	}

	// 删除被动指纹
	// 确保passiveWhere安全（不包含用户直接输入）
	var passiveSQL string
	if passiveWhere != "" {
		// passiveWhere已经通过QueryBuilder构建，是安全的
		passiveSQL = "DELETE FROM passive_fingerprints WHERE " + passiveWhere
	} else {
		passiveSQL = "DELETE FROM passive_fingerprints"
	}
	passiveResult, err := database.DB.Exec(passiveSQL, args...)
	if err != nil {
		return 0, fmt.Errorf("删除被动指纹失败: %w", err)
	}
	passiveRows, _ := passiveResult.RowsAffected()
	deletedCount += int(passiveRows)

	// 删除主动指纹
	// 确保activeWhere安全（不包含用户直接输入）
	var activeSQL string
	if activeWhere != "" {
		// activeWhere已经通过QueryBuilder构建，是安全的
		activeSQL = "DELETE FROM active_fingerprints WHERE " + activeWhere
	} else {
		activeSQL = "DELETE FROM active_fingerprints"
	}
	activeResult, err := database.DB.Exec(activeSQL, args...)
	if err != nil {
		return 0, fmt.Errorf("删除主动指纹失败: %w", err)
	}
	activeRows, _ := activeResult.RowsAffected()
	deletedCount += int(activeRows)

	resetFingerprintRuntimeCache()
	return deletedCount, nil
}

// SearchFingerprints 搜索指纹
//
// 参数：
//   - keyword: 搜索关键字（为空则返回所有指纹）
//
// 返回值：
//   - []FingerprintItem: 匹配的指纹项列表
//   - error: 错误信息
//
// 功能说明：
//
//	根据关键字搜索指纹，会在 name、description、rules 字段中搜索。
//	如果关键字为空，返回所有指纹（最多 10000 条）。
//
// 使用场景：
//   - 快速查找指纹
//   - 关键字搜索功能
func (f *FingerprintDBService) SearchFingerprints(keyword string) ([]FingerprintItem, error) {
	if keyword == "" {
		return f.GetFingerprints()
	}

	items, _, err := f.GetFingerprintsPageByType(1, 10000, "", "", keyword, "id", "asc", nil, false)
	return items, err
}

// ImportFingerprint 从 YAML 内容导入指纹（默认导入到被动指纹）
//
// 参数：
//   - yamlContent: YAML 格式的指纹内容
//   - fileName: 文件名（用于日志记录，不影响导入逻辑）
//
// 返回值：
//   - error: 错误信息
//
// 功能说明：
//
//	向后兼容方法，默认导入到被动指纹表。
//	新代码建议使用 ImportFingerprintWithType 指定类型。
func (f *FingerprintDBService) ImportFingerprint(yamlContent string, fileName string) error {
	return f.ImportFingerprintWithType(yamlContent, fileName, "passive")
}

func (f *FingerprintDBService) ImportFingerprintWithType(yamlContent string, fileName string, fpType string) error {
	_, _, err := f.importFingerprintWithTypeStats(yamlContent, fpType)
	return err
}

func (f *FingerprintDBService) importFingerprintWithTypeStats(yamlContent string, fpType string) (int, int, error) {
	if database.DB == nil {
		return 0, 0, fmt.Errorf("数据库未初始化")
	}

	// 解析 YAML 内容
	var importYAML map[string][]string
	if err := yaml.Unmarshal([]byte(yamlContent), &importYAML); err != nil {
		return 0, 0, fmt.Errorf("解析YAML失败：%w", err)
	}

	// 开始事务
	tx, err := database.DB.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("开始事务失败: %w", err)
	}
	// 确保在出错时回滚，忽略已提交或已回滚的错误
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			logger.Error("回滚事务失败: %v", err)
		}
	}()

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fpType == "active" {
		tableName = "active_fingerprints"
	}
	if err := ValidateTableName(tableName); err != nil {
		return 0, 0, err
	}

	// 准备查询现有指纹的语句
	queryStmt, err := tx.Prepare(fmt.Sprintf(`
		SELECT rules FROM %s WHERE name = ?
	`, tableName))
	if err != nil {
		return 0, 0, fmt.Errorf("准备查询语句失败: %w", err)
	}
	defer queryStmt.Close()

	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	// 准备插入语句
	insertStmt, err := tx.Prepare(fmt.Sprintf(`
		INSERT INTO %s (name, description, rules, is_blacklisted, is_enabled, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?)
	`, tableName))
	if err != nil {
		return 0, 0, fmt.Errorf("准备插入语句失败: %w", err)
	}
	defer insertStmt.Close()

	// 准备更新语句
	updateStmt, err := tx.Prepare(fmt.Sprintf(`
		UPDATE %s SET rules = ?, updated_at = ? WHERE name = ?
	`, tableName))
	if err != nil {
		return 0, 0, fmt.Errorf("准备更新语句失败: %w", err)
	}
	defer updateStmt.Close()

	importedCount := 0
	updatedCount := 0

	// 遍历所有要导入的指纹
	for name, newRules := range importYAML {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		newRules = normalizeFingerprintRules(newRules)
		if len(newRules) == 0 {
			continue
		}

		// 检查是否已存在
		var existingRulesYAML string
		err := queryStmt.QueryRow(name).Scan(&existingRulesYAML)

		if err == nil {
			// 已存在，合并规则并去重
			var existingRules []string
			if err := yaml.Unmarshal([]byte(existingRulesYAML), &existingRules); err != nil {
				// 如果解析失败，使用新规则
				rulesYAML, _ := yaml.Marshal(newRules)
				if _, err := updateStmt.Exec(string(rulesYAML), timeStr, name); err != nil {
					return importedCount, updatedCount, fmt.Errorf("更新指纹失败: %w", err)
				}
				updatedCount++
				continue
			}

			// 合并规则并去重
			mergedRules := normalizeFingerprintRules(append(existingRules, newRules...))

			// 更新数据库
			rulesYAML, err := yaml.Marshal(mergedRules)
			if err != nil {
				continue
			}

			_, err = updateStmt.Exec(string(rulesYAML), timeStr, name)
			if err != nil {
				continue
			}
			updatedCount++
		} else {
			// 不存在，直接插入
			rulesYAML, err := yaml.Marshal(newRules)
			if err != nil {
				continue
			}

			_, err = insertStmt.Exec(name, "", string(rulesYAML), 0, 1, timeStr)
			if err != nil {
				continue
			}
			importedCount++
		}
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		return importedCount, updatedCount, fmt.Errorf("提交事务失败: %w", err)
	}

	resetFingerprintRuntimeCache()
	return importedCount, updatedCount, nil
}

func normalizeFingerprintRules(rules []string) []string {
	seen := make(map[string]bool)
	normalized := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" || seen[rule] {
			continue
		}
		seen[rule] = true
		normalized = append(normalized, rule)
	}
	return normalized
}

// ExportFingerprints 导出所有指纹为YAML格式
//
// 返回值：
//   - string: YAML 格式的指纹内容
//   - error: 错误信息
//
// 功能说明：
//
//	从数据库中导出所有启用的指纹（包括被动和主动），合并为单一 YAML 格式。
//	如果同一个名称在被动和主动表中都存在，会合并规则。
//
// 导出逻辑：
//  1. 查询所有启用的被动指纹
//  2. 查询所有启用的主动指纹
//  3. 合并同名指纹的规则（去重）
//  4. 序列化为 YAML 字符串
//
// 合并规则：
//   - 被动指纹优先
//   - 如果同名指纹在主动表中也存在，合并规则并去重
//
// 使用场景：
//   - 备份指纹数据
//   - 导出指纹配置
//   - 在不同环境间同步指纹数据
func (f *FingerprintDBService) ExportFingerprints() (string, error) {
	return f.ExportFingerprintsByType("all")
}

// ExportFingerprintsByType 根据类型导出指纹为YAML格式
//
// 参数：
//   - exportType: 导出类型，"passive"（被动）、"active"（主动）、"all"（全部）
//
// 返回值：
//   - string: YAML 格式的指纹内容
//   - error: 错误信息
func (f *FingerprintDBService) ExportFingerprintsByType(exportType string) (string, error) {
	if database.DB == nil {
		return "", fmt.Errorf("数据库未初始化")
	}

	// 根据导出类型构建查询
	var query string
	switch exportType {
	case "passive":
		query = `
			SELECT name, rules, 'passive' as fingerprint_type 
			FROM passive_fingerprints 
			WHERE is_enabled = 1 
			ORDER BY name
		`
	case "active":
		query = `
			SELECT name, rules, 'active' as fingerprint_type 
			FROM active_fingerprints 
			WHERE is_enabled = 1 
			ORDER BY name
		`
	case "all":
		fallthrough
	default:
		query = `
			SELECT name, rules, 'passive' as fingerprint_type 
			FROM passive_fingerprints 
			WHERE is_enabled = 1 
			UNION ALL
			SELECT name, rules, 'active' as fingerprint_type 
			FROM active_fingerprints 
			WHERE is_enabled = 1 
			ORDER BY name
		`
	}

	rows, err := database.DB.Query(query)
	if err != nil {
		return "", fmt.Errorf("查询指纹失败: %w", err)
	}
	defer rows.Close()

	passiveYAML := make(map[string][]string)
	activeYAML := make(map[string][]string)

	// 解析查询结果
	for rows.Next() {
		var name, rulesYAML, fpType string
		if err := rows.Scan(&name, &rulesYAML, &fpType); err != nil {
			continue
		}

		// 解析规则
		var rules []string
		if err := yaml.Unmarshal([]byte(rulesYAML), &rules); err != nil {
			continue
		}

		if fpType == "active" {
			activeYAML[name] = rules
		} else {
			passiveYAML[name] = rules
		}
	}

	// 根据导出类型合并结果
	resultYAML := make(map[string][]string)

	if exportType == "passive" {
		// 只导出被动指纹
		for name, rules := range passiveYAML {
			resultYAML[name] = rules
		}
	} else if exportType == "active" {
		// 只导出主动指纹
		for name, rules := range activeYAML {
			resultYAML[name] = rules
		}
	} else {
		// 导出全部：生成两个 yaml 文件并打包成 zip
		// 创建 zip 文件
		var zipBuffer bytes.Buffer
		zipWriter := zip.NewWriter(&zipBuffer)

		// 添加被动指纹文件
		if len(passiveYAML) > 0 {
			passiveYamlBytes, err := yaml.Marshal(passiveYAML)
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("序列化被动指纹YAML失败: %w", err)
			}
			passiveFile, err := zipWriter.Create("finger.yaml")
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("创建被动指纹文件失败: %w", err)
			}
			_, err = passiveFile.Write(passiveYamlBytes)
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("写入被动指纹文件失败: %w", err)
			}
		}

		// 添加主动指纹文件
		if len(activeYAML) > 0 {
			activeYamlBytes, err := yaml.Marshal(activeYAML)
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("序列化主动指纹YAML失败: %w", err)
			}
			activeFile, err := zipWriter.Create("dir.yaml")
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("创建主动指纹文件失败: %w", err)
			}
			_, err = activeFile.Write(activeYamlBytes)
			if err != nil {
				zipWriter.Close()
				return "", fmt.Errorf("写入主动指纹文件失败: %w", err)
			}
		}

		// 关闭 zip writer
		err = zipWriter.Close()
		if err != nil {
			return "", fmt.Errorf("关闭zip文件失败: %w", err)
		}

		// 返回 base64 编码的 zip 文件内容，格式：zip:base64_content
		zipBase64 := base64.StdEncoding.EncodeToString(zipBuffer.Bytes())
		return "zip:" + zipBase64, nil
	}

	// 序列化为YAML字符串（单个类型导出）
	yamlBytes, err := yaml.Marshal(resultYAML)
	if err != nil {
		return "", fmt.Errorf("序列化YAML失败: %w", err)
	}

	return string(yamlBytes), nil
}

// ExportSingleFingerprint 导出单个指纹为YAML格式
//
// 参数：
//   - name: 指纹名称
//   - fpType: 指纹类型（"passive" 或 "active"）
//
// 返回值：
//   - string: YAML 格式的指纹内容
//   - error: 错误信息
func (f *FingerprintDBService) ExportSingleFingerprint(name string, fpType string) (string, error) {
	if database.DB == nil {
		return "", fmt.Errorf("数据库未初始化")
	}

	// 根据类型选择表名
	tableName := "passive_fingerprints"
	if fpType == "active" {
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return "", err
	}

	// 查询指纹
	var rulesYAML string
	err := database.DB.QueryRow(fmt.Sprintf(`
		SELECT rules 
		FROM %s 
		WHERE name = ? AND is_enabled = 1
	`, tableName), name).Scan(&rulesYAML)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("指纹不存在或已禁用：%s", name)
		}
		return "", fmt.Errorf("查询指纹失败: %w", err)
	}

	// 解析规则
	var rules []string
	if err := yaml.Unmarshal([]byte(rulesYAML), &rules); err != nil {
		return "", fmt.Errorf("解析规则失败: %w", err)
	}

	// 构建单个指纹的 YAML 结构
	resultYAML := map[string][]string{
		name: rules,
	}

	// 序列化为YAML字符串
	yamlBytes, err := yaml.Marshal(resultYAML)
	if err != nil {
		return "", fmt.Errorf("序列化YAML失败: %w", err)
	}

	return string(yamlBytes), nil
}

// GetStatistics 获取指纹统计信息
//
// 返回值：
//   - map[string]interface{}: 统计信息字典
//   - total: 总指纹数
//   - passive: 被动指纹数
//   - active: 主动指纹数
//   - enabled: 启用的指纹数
//   - blacklisted: 黑名单中的指纹数
//   - error: 错误信息
//
// 功能说明：
//
//	统计数据库中指纹的数量信息，包括总数、分类统计、启用状态统计等。
//
// 使用场景：
//   - 仪表板展示
//   - 统计报表
func (f *FingerprintDBService) GetStatistics() (map[string]interface{}, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	var total, passive, active, enabled, blacklisted int

	// 被动指纹总数
	database.DB.QueryRow("SELECT COUNT(*) FROM passive_fingerprints").Scan(&passive)

	// 主动指纹总数
	database.DB.QueryRow("SELECT COUNT(*) FROM active_fingerprints").Scan(&active)

	// 总数
	total = passive + active

	// 启用的（从两个表统计）
	var passiveEnabled, activeEnabled int
	database.DB.QueryRow("SELECT COUNT(*) FROM passive_fingerprints WHERE is_enabled = 1").Scan(&passiveEnabled)
	database.DB.QueryRow("SELECT COUNT(*) FROM active_fingerprints WHERE is_enabled = 1").Scan(&activeEnabled)
	enabled = passiveEnabled + activeEnabled

	// 黑名单的（从两个表统计）
	var passiveBlacklisted, activeBlacklisted int
	database.DB.QueryRow("SELECT COUNT(*) FROM passive_fingerprints WHERE is_blacklisted = 1").Scan(&passiveBlacklisted)
	database.DB.QueryRow("SELECT COUNT(*) FROM active_fingerprints WHERE is_blacklisted = 1").Scan(&activeBlacklisted)
	blacklisted = passiveBlacklisted + activeBlacklisted

	return map[string]interface{}{
		"total":       total,
		"passive":     passive,
		"active":      active,
		"enabled":     enabled,
		"blacklisted": blacklisted,
	}, nil
}

func (f *FingerprintDBService) ToggleBlacklist(name string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("指纹名称不能为空")
	}

	// 检查在哪个表中
	var isBlacklisted int
	var tableName string
	err := database.DB.QueryRow("SELECT is_blacklisted FROM passive_fingerprints WHERE name = ?", name).Scan(&isBlacklisted)
	if err == nil {
		tableName = "passive_fingerprints"
	} else {
		err = database.DB.QueryRow("SELECT is_blacklisted FROM active_fingerprints WHERE name = ?", name).Scan(&isBlacklisted)
		if err != nil {
			return fmt.Errorf("查询指纹失败: %w", err)
		}
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return err
	}

	// 切换状态（0 ↔ 1）
	newValue := 1 - isBlacklisted
	timeStr := utils.GetCurrentTimeString()
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开启黑名单事务失败: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(fmt.Sprintf("UPDATE %s SET is_blacklisted = ?, updated_at = ? WHERE name = ?", tableName), newValue, timeStr, name)
	if err != nil {
		return fmt.Errorf("更新黑名单状态失败: %w", err)
	}

	if newValue == 1 {
		_, err = tx.Exec(`INSERT INTO blacklist (category, item, updated_at) VALUES (?, ?, ?) ON CONFLICT (category, item) DO NOTHING`, "fingerprint", name, timeStr)
	} else {
		_, err = tx.Exec(`DELETE FROM blacklist WHERE category = ? AND LOWER(item) = LOWER(?)`, "fingerprint", name)
	}
	if err != nil {
		return fmt.Errorf("同步指纹黑名单失败: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交黑名单事务失败: %w", err)
	}
	resetFingerprintRuntimeCache()
	return nil
}

func (f *FingerprintDBService) ToggleEnabled(name string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	// 检查在哪个表中
	var isEnabled int
	var tableName string
	err := database.DB.QueryRow("SELECT is_enabled FROM passive_fingerprints WHERE name = ?", name).Scan(&isEnabled)
	if err == nil {
		tableName = "passive_fingerprints"
	} else {
		err = database.DB.QueryRow("SELECT is_enabled FROM active_fingerprints WHERE name = ?", name).Scan(&isEnabled)
		if err != nil {
			return fmt.Errorf("查询指纹失败: %w", err)
		}
		tableName = "active_fingerprints"
	}

	// 验证表名
	if err := ValidateTableName(tableName); err != nil {
		return err
	}

	// 切换状态（0 ↔ 1）
	newValue := 1 - isEnabled
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	_, err = database.DB.Exec(fmt.Sprintf("UPDATE %s SET is_enabled = ?, updated_at = ? WHERE name = ?", tableName), newValue, timeStr, name)
	if err != nil {
		return fmt.Errorf("更新启用状态失败: %w", err)
	}

	resetFingerprintRuntimeCache()
	return nil
}

// FingerprintService 指纹识别服务
