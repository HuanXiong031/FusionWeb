package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"strings"
)

const (
	ScanDictSubdomainPrefix = "subdomain_prefix"
	ScanDictDirectoryPath   = "directory_path"
	ScanDictWeakUsername    = "weak_username"
	ScanDictWeakPassword    = "weak_password"
	ScanDictJSSensitive     = "js_sensitive_keyword"
	ScanDictJSRoute         = "js_route_keyword"
	ScanDictJSAuth          = "js_auth_keyword"
)

type ScanDictionaryItem struct {
	ID          int64  `json:"id"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
	IsBuiltin   bool   `json:"isBuiltin"`
	CreatedBy   int    `json:"createdBy,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

type ScanDictionaryImportSummary struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
	Total    int `json:"total"`
}

type ScanDictionaryService struct{}

func NewScanDictionaryService() *ScanDictionaryService {
	s := &ScanDictionaryService{}
	_ = s.SeedDefaultDictionaries()
	return s
}

func (s *ScanDictionaryService) List(dictType, keyword string) ([]ScanDictionaryItem, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	dictType = normalizeScanDictType(dictType)
	keyword = strings.TrimSpace(keyword)
	query := `SELECT id, dict_type, value, enabled, description, is_builtin, created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM scan_dictionaries WHERE 1=1`
	args := make([]interface{}, 0)
	if dictType != "" {
		args = append(args, dictType)
		query += fmt.Sprintf(" AND dict_type = $%d", len(args))
	}
	if keyword != "" {
		args = append(args, "%"+keyword+"%")
		query += fmt.Sprintf(" AND value ILIKE $%d", len(args))
	}
	query += " ORDER BY dict_type ASC, id ASC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ScanDictionaryItem, 0)
	for rows.Next() {
		item, err := scanScanDictionaryItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *ScanDictionaryService) Statistics() (map[string]int, error) {
	stats := make(map[string]int)
	rows, err := database.DB.Query(`SELECT dict_type, COUNT(*) FROM scan_dictionaries GROUP BY dict_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dictType string
		var count int
		if err := rows.Scan(&dictType, &count); err != nil {
			return nil, err
		}
		stats[dictType] = count
	}
	return stats, rows.Err()
}

func (s *ScanDictionaryService) Save(item ScanDictionaryItem, userID int) (ScanDictionaryItem, error) {
	item.Type = normalizeScanDictType(item.Type)
	item.Value = normalizeScanDictValue(item.Type, item.Value)
	item.Description = strings.TrimSpace(item.Description)
	if item.Type == "" {
		return item, fmt.Errorf("字典类型不正确")
	}
	if item.Value == "" {
		return item, fmt.Errorf("字典内容不能为空")
	}

	now := utils.GetCurrentTimeString()
	enabled := boolToInt(item.Enabled)
	if item.ID > 0 {
		existingID, exists, err := s.findID(item.Type, item.Value)
		if err != nil {
			return item, err
		}
		if exists && existingID != item.ID {
			return item, fmt.Errorf("字典内容已存在，已自动去重")
		}
		_, err = database.DB.Exec(`UPDATE scan_dictionaries
			SET dict_type = $1, value = $2, enabled = $3, description = $4, updated_at = $5
			WHERE id = $6`, item.Type, item.Value, enabled, item.Description, now, item.ID)
		if err != nil {
			return item, err
		}
		return s.Get(item.ID)
	}

	if _, exists, err := s.findID(item.Type, item.Value); err != nil {
		return item, err
	} else if exists {
		return item, fmt.Errorf("字典内容已存在，已自动去重")
	}

	id, err := database.InsertAndReturnID(`INSERT INTO scan_dictionaries
		(dict_type, value, enabled, description, is_builtin, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		item.Type, item.Value, enabled, item.Description, boolToInt(item.IsBuiltin), userID, now, now)
	if err != nil {
		return item, err
	}
	return s.Get(id)
}

func (s *ScanDictionaryService) Get(id int64) (ScanDictionaryItem, error) {
	row := database.DB.QueryRow(`SELECT id, dict_type, value, enabled, description, is_builtin, created_by, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM scan_dictionaries WHERE id = $1`, id)
	return scanScanDictionaryItem(row)
}

func (s *ScanDictionaryService) Delete(id int64) error {
	result, err := database.DB.Exec("DELETE FROM scan_dictionaries WHERE id = $1", id)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("字典不存在")
	}
	return nil
}

func (s *ScanDictionaryService) DeleteByType(dictType string) error {
	dictType = normalizeScanDictType(dictType)
	if dictType == "" {
		return fmt.Errorf("字典类型不正确")
	}
	_, err := database.DB.Exec("DELETE FROM scan_dictionaries WHERE dict_type = $1", dictType)
	return err
}

func (s *ScanDictionaryService) Import(dictType string, values []string, userID int) (ScanDictionaryImportSummary, error) {
	summary := ScanDictionaryImportSummary{Total: len(values)}
	dictType = normalizeScanDictType(dictType)
	if dictType == "" {
		return summary, fmt.Errorf("字典类型不正确")
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = normalizeScanDictValue(dictType, value)
		if value == "" {
			continue
		}
		if seen[value] {
			summary.Skipped++
			continue
		}
		seen[value] = true
		if _, exists, err := s.findID(dictType, value); err != nil {
			return summary, err
		} else if exists {
			summary.Skipped++
			continue
		}
		if _, err := s.Save(ScanDictionaryItem{Type: dictType, Value: value, Enabled: true}, userID); err != nil {
			return summary, err
		}
		summary.Imported++
	}
	return summary, nil
}

func (s *ScanDictionaryService) EnabledValues(dictType string) ([]string, error) {
	dictType = normalizeScanDictType(dictType)
	if dictType == "" || database.DB == nil {
		return nil, nil
	}
	rows, err := database.DB.Query(`SELECT value FROM scan_dictionaries
		WHERE dict_type = $1 AND enabled = 1 ORDER BY id ASC`, dictType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	return values, rows.Err()
}

func (s *ScanDictionaryService) SeedDefaultDictionaries() error {
	if database.DB == nil {
		return nil
	}
	defaults := map[string][]string{
		ScanDictSubdomainPrefix: []string{"www", "api", "admin", "dev", "test", "mail", "vpn"},
		ScanDictDirectoryPath:   []string{"admin", "login", "api", "actuator", "swagger-ui.html", "robots.txt", ".git/config", ".env"},
		ScanDictWeakUsername:    []string{"root", "admin", "user", "test", "postgres", "mysql", "redis", "ftp"},
		ScanDictWeakPassword:    []string{"123456", "password", "admin", "root", "12345678", "admin123"},
		ScanDictJSSensitive:     []string{"password", "passwd", "secret", "token", "access_token", "api_key", "private_key", "client_secret"},
		ScanDictJSRoute:         []string{"/api/", "/admin", "/swagger", "/actuator"},
		ScanDictJSAuth:          []string{"unauthorized", "forbidden", "permission denied", "access denied", "401", "403"},
	}
	for dictType, values := range defaults {
		for _, value := range values {
			value = normalizeScanDictValue(dictType, value)
			if value == "" {
				continue
			}
			_, err := database.DB.Exec(`INSERT INTO scan_dictionaries
				(dict_type, value, enabled, description, is_builtin, created_by, created_at, updated_at)
				VALUES ($1, $2, 1, $3, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				ON CONFLICT (dict_type, value) DO NOTHING`,
				dictType, value, defaultScanDictDescription(dictType))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func scanScanDictionaryItem(scanner interface {
	Scan(dest ...interface{}) error
}) (ScanDictionaryItem, error) {
	var item ScanDictionaryItem
	var enabled, isBuiltin int
	var description, createdAt, updatedAt sql.NullString
	if err := scanner.Scan(&item.ID, &item.Type, &item.Value, &enabled, &description, &isBuiltin, &item.CreatedBy, &createdAt, &updatedAt); err != nil {
		return ScanDictionaryItem{}, err
	}
	item.Enabled = enabled != 0
	item.Description = description.String
	item.IsBuiltin = isBuiltin != 0
	item.CreatedAt = utils.FormatNullTimeStringForDisplay(createdAt)
	item.UpdatedAt = utils.FormatNullTimeStringForDisplay(updatedAt)
	return item, nil
}

func (s *ScanDictionaryService) findID(dictType, value string) (int64, bool, error) {
	var id int64
	err := database.DB.QueryRow("SELECT id FROM scan_dictionaries WHERE dict_type = $1 AND value = $2", dictType, value).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func enabledScanDictionaryValues(dictType string) ([]string, error) {
	return NewScanDictionaryServiceWithoutSeed().EnabledValues(dictType)
}

func NewScanDictionaryServiceWithoutSeed() *ScanDictionaryService {
	return &ScanDictionaryService{}
}

func normalizeScanDictType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "subdomain", "subdomain_prefix":
		return ScanDictSubdomainPrefix
	case "directory", "directory_path":
		return ScanDictDirectoryPath
	case "weak_username", "username":
		return ScanDictWeakUsername
	case "weak_password", "password":
		return ScanDictWeakPassword
	case "js_sensitive", "js_sensitive_keyword":
		return ScanDictJSSensitive
	case "js_route", "js_route_keyword":
		return ScanDictJSRoute
	case "js_auth", "js_auth_keyword":
		return ScanDictJSAuth
	default:
		return ""
	}
}

func normalizeScanDictValue(dictType, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if dictType == ScanDictDirectoryPath || dictType == ScanDictJSRoute {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(value)
}

func defaultScanDictDescription(dictType string) string {
	switch dictType {
	case ScanDictSubdomainPrefix:
		return "子域名枚举前缀"
	case ScanDictDirectoryPath:
		return "目录扫描路径"
	case ScanDictWeakUsername:
		return "弱口令用户名"
	case ScanDictWeakPassword:
		return "弱口令密码"
	case ScanDictJSSensitive:
		return "JS 敏感关键词"
	case ScanDictJSRoute:
		return "JS 高危路由关键词"
	case ScanDictJSAuth:
		return "JS 鉴权响应关键词"
	default:
		return "扫描字典"
	}
}
