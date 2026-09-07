package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const accessPolicyCacheTTL = 30 * time.Second

// AccessPolicyService manages who can access FusionWeb itself.
// It does not filter scan targets.
type AccessPolicyService struct {
	cacheMu   sync.RWMutex
	cache     AccessPolicyConfig
	cacheTime time.Time
}

type AccessPolicyConfig map[string][]string

type AccessPolicyItem struct {
	ID        int    `json:"id"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	StartsAt  string `json:"startsAt,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type AccessRequestInfo struct {
	ClientIP string
	Host     string
	Origin   string
	Referer  string
}

type AccessPolicyDecision struct {
	Allowed bool
	Reason  string
}

func NewAccessPolicyService() *AccessPolicyService {
	return &AccessPolicyService{}
}

func (s *AccessPolicyService) GetBlacklistByCategory() (AccessPolicyConfig, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	s.cleanupExpiredBlacklist()
	return s.loadBlacklistByCategory()
}

func (s *AccessPolicyService) loadBlacklistByCategory() (AccessPolicyConfig, error) {
	return s.loadBlacklistByCategoryContext(context.Background())
}

func (s *AccessPolicyService) loadBlacklistByCategoryContext(ctx context.Context) (AccessPolicyConfig, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	rows, err := database.DB.QueryContext(ctx,
		`SELECT category, item
		   FROM access_blacklist
		  WHERE LOWER(category) IN ('ip', 'domain')
		    AND (starts_at IS NULL OR starts_at <= CAST(? AS TIMESTAMP))
		    AND (expires_at IS NULL OR expires_at > CAST(? AS TIMESTAMP))
		  ORDER BY id`,
		utils.GetCurrentTimeString(), utils.GetCurrentTimeString(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	config := emptyAccessPolicyConfig()
	for rows.Next() {
		var category, item string
		if err := rows.Scan(&category, &item); err != nil {
			continue
		}
		category = normalizeAccessPolicyCategory(category)
		item = strings.TrimSpace(item)
		if category == "" || item == "" {
			continue
		}
		config[category] = append(config[category], item)
	}
	return config, nil
}

func (s *AccessPolicyService) getCachedBlacklistByCategory() (AccessPolicyConfig, error) {
	now := time.Now()

	s.cacheMu.RLock()
	if s.cache != nil && now.Sub(s.cacheTime) < accessPolicyCacheTTL {
		config := cloneAccessPolicyConfig(s.cache)
		s.cacheMu.RUnlock()
		return config, nil
	}
	s.cacheMu.RUnlock()

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache != nil && now.Sub(s.cacheTime) < accessPolicyCacheTTL {
		return cloneAccessPolicyConfig(s.cache), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	config, err := s.loadBlacklistByCategoryContext(ctx)
	if err != nil {
		if s.cache != nil {
			return cloneAccessPolicyConfig(s.cache), nil
		}
		return emptyAccessPolicyConfig(), nil
	}
	s.cache = cloneAccessPolicyConfig(config)
	s.cacheTime = now
	return cloneAccessPolicyConfig(config), nil
}

func (s *AccessPolicyService) invalidateCache() {
	s.cacheMu.Lock()
	s.cache = nil
	s.cacheTime = time.Time{}
	s.cacheMu.Unlock()
}

func (s *AccessPolicyService) GetBlacklistItems() ([]AccessPolicyItem, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}

	s.cleanupExpiredBlacklist()

	rows, err := database.DB.Query(
		`SELECT id, category, item, CAST(starts_at AS TEXT), CAST(expires_at AS TEXT), CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		   FROM access_blacklist
		  WHERE LOWER(category) IN ('ip', 'domain')
		    AND (expires_at IS NULL OR expires_at > CAST(? AS TIMESTAMP))
		  ORDER BY id DESC`,
		utils.GetCurrentTimeString(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AccessPolicyItem, 0)
	for rows.Next() {
		var item AccessPolicyItem
		var startsAt, expiresAt, createdAt, updatedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Category, &item.Value, &startsAt, &expiresAt, &createdAt, &updatedAt); err != nil {
			continue
		}
		item.Category = normalizeAccessPolicyCategory(item.Category)
		item.Value = strings.TrimSpace(item.Value)
		item.StartsAt = nullStringValue(startsAt)
		item.ExpiresAt = nullStringValue(expiresAt)
		item.CreatedAt = nullStringValue(createdAt)
		item.UpdatedAt = nullStringValue(updatedAt)
		if item.Category == "" || item.Value == "" {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *AccessPolicyService) SaveBlacklistByCategory(config AccessPolicyConfig) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM access_blacklist"); err != nil {
		return fmt.Errorf("清空访问黑名单失败: %w", err)
	}

	stmt, err := tx.Prepare("INSERT INTO access_blacklist (category, item, starts_at, expires_at, updated_at) VALUES (?, ?, NULL, NULL, ?) ON CONFLICT (category, item) DO NOTHING")
	if err != nil {
		return fmt.Errorf("准备保存访问黑名单失败: %w", err)
	}
	defer stmt.Close()

	for category, items := range config {
		category = normalizeAccessPolicyCategory(category)
		if category == "" {
			continue
		}
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, err := stmt.Exec(category, item, utils.GetCurrentTimeString()); err != nil {
				return fmt.Errorf("保存访问黑名单失败: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交访问黑名单失败: %w", err)
	}
	s.invalidateCache()
	return nil
}

func (s *AccessPolicyService) AddToBlacklistWithCategory(category, item string) error {
	return s.AddToBlacklistWithDuration(category, item, 0)
}

func (s *AccessPolicyService) AddToBlacklistWithDuration(category, item string, durationMinutes int) error {
	return s.AddToBlacklistWithDurationAndSource(category, item, durationMinutes, "手动添加")
}

func (s *AccessPolicyService) AddToBlacklistWithDurationAndSource(category, item string, durationMinutes int, source string) error {
	startsAt := utils.GetCurrentTimeString()
	expiresAt := ""
	if durationMinutes > 0 {
		expiresAt = utils.GetCurrentTime().Add(time.Duration(durationMinutes) * time.Minute).Format("2006-01-02 15:04:05")
	}
	return s.AddToBlacklistWithPeriodAndSource(category, item, startsAt, expiresAt, source)
}

func (s *AccessPolicyService) AddToBlacklistWithPeriod(category, item, startsAt, expiresAt string) error {
	return s.AddToBlacklistWithPeriodAndSource(category, item, startsAt, expiresAt, "手动添加")
}

func (s *AccessPolicyService) AddToBlacklistWithPeriodAndSource(category, item, startsAt, expiresAt, source string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	category = normalizeAccessPolicyCategory(category)
	item = strings.TrimSpace(item)
	if category == "" {
		return fmt.Errorf("访问黑名单仅支持 IP 或域名")
	}
	if item == "" {
		return fmt.Errorf("黑名单项不能为空")
	}
	startsAt, err := normalizeAccessPolicyTime(startsAt, utils.GetCurrentTimeString())
	if err != nil {
		return fmt.Errorf("生效时间格式不正确")
	}
	expiresAt, err = normalizeAccessPolicyTime(expiresAt, "")
	if err != nil {
		return fmt.Errorf("解锁时间格式不正确")
	}
	if startsAt != "" && expiresAt != "" && startsAt >= expiresAt {
		return fmt.Errorf("解锁时间必须晚于生效时间")
	}

	now := utils.GetCurrentTimeString()
	result, err := database.DB.Exec(
		`UPDATE access_blacklist
		    SET starts_at = NULLIF(?, ''), expires_at = NULLIF(?, ''), updated_at = ?
		  WHERE category = ? AND LOWER(item) = LOWER(?)`,
		startsAt, expiresAt, now, category, item,
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected > 0 {
		s.invalidateCache()
		notifyAccessBlacklistChange(DingTalkEventBlacklistAdd, category, item, startsAt, expiresAt, source)
		return nil
	}

	_, err = database.DB.Exec(
		"INSERT INTO access_blacklist (category, item, starts_at, expires_at, updated_at) VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)",
		category, item, startsAt, expiresAt, now,
	)
	if err == nil {
		s.invalidateCache()
		notifyAccessBlacklistChange(DingTalkEventBlacklistAdd, category, item, startsAt, expiresAt, source)
	}
	return err
}

func (s *AccessPolicyService) RemoveFromBlacklistWithCategory(category, item string) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	category = normalizeAccessPolicyCategory(category)
	item = strings.TrimSpace(item)
	if category == "" || item == "" {
		return nil
	}

	result, err := database.DB.Exec("DELETE FROM access_blacklist WHERE category = ? AND LOWER(item) = LOWER(?)", category, item)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	s.invalidateCache()
	notifyAccessBlacklistChange(DingTalkEventBlacklistRemove, category, item, "", "", "手动解除")
	return nil
}

func (s *AccessPolicyService) CheckAccess(info AccessRequestInfo) AccessPolicyDecision {
	if isLoopbackAddress(info.ClientIP) {
		return AccessPolicyDecision{Allowed: true}
	}

	blacklist, err := s.getCachedBlacklistByCategory()
	if err != nil {
		return AccessPolicyDecision{Allowed: false, Reason: "读取访问黑名单失败"}
	}
	if matchesAccessPolicy(blacklist, info) {
		return AccessPolicyDecision{Allowed: false, Reason: "当前访问来源命中黑名单"}
	}
	return AccessPolicyDecision{Allowed: true}
}

func (s *AccessPolicyService) cleanupExpiredBlacklist() {
	if database.DB == nil {
		return
	}
	expired := make([]AccessPolicyItem, 0)
	rows, err := database.DB.Query(
		"SELECT category, item, CAST(starts_at AS TEXT), CAST(expires_at AS TEXT) FROM access_blacklist WHERE expires_at IS NOT NULL AND expires_at <= CAST(? AS TIMESTAMP)",
		utils.GetCurrentTimeString(),
	)
	if err == nil {
		for rows.Next() {
			var item AccessPolicyItem
			var startsAt, expiresAt sql.NullString
			if err := rows.Scan(&item.Category, &item.Value, &startsAt, &expiresAt); err == nil {
				item.StartsAt = nullStringValue(startsAt)
				item.ExpiresAt = nullStringValue(expiresAt)
				expired = append(expired, item)
			}
		}
		_ = rows.Close()
		for _, item := range expired {
			notifyAccessBlacklistChange(DingTalkEventBlacklistRemove, item.Category, item.Value, item.StartsAt, item.ExpiresAt, "到期自动解除")
		}
	}
	_, _ = database.DB.Exec(
		"DELETE FROM access_blacklist WHERE expires_at IS NOT NULL AND expires_at <= CAST(? AS TIMESTAMP)",
		utils.GetCurrentTimeString(),
	)
	if len(expired) > 0 {
		s.invalidateCache()
	}
}

func emptyAccessPolicyConfig() AccessPolicyConfig {
	return AccessPolicyConfig{
		"ip":     {},
		"domain": {},
	}
}

func cloneAccessPolicyConfig(config AccessPolicyConfig) AccessPolicyConfig {
	out := emptyAccessPolicyConfig()
	for category, items := range config {
		category = normalizeAccessPolicyCategory(category)
		if category == "" {
			continue
		}
		out[category] = append([]string(nil), items...)
	}
	return out
}

func normalizeAccessPolicyCategory(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "ip":
		return "ip"
	case "domain":
		return "domain"
	default:
		return ""
	}
}

func matchesAccessPolicy(config AccessPolicyConfig, info AccessRequestInfo) bool {
	for _, rule := range config["ip"] {
		if matchIPRule(info.ClientIP, rule) {
			return true
		}
	}

	domains := requestDomains(info)
	for _, rule := range config["domain"] {
		for _, domain := range domains {
			if matchDomainRule(domain, rule) {
				return true
			}
		}
	}
	return false
}

func matchIPRule(clientIP, rule string) bool {
	client := net.ParseIP(strings.TrimSpace(clientIP))
	if client == nil {
		return false
	}
	rule = strings.TrimSpace(rule)
	if _, cidr, err := net.ParseCIDR(rule); err == nil {
		return cidr.Contains(client)
	}
	return client.Equal(net.ParseIP(rule))
}

func matchDomainRule(domain, rule string) bool {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	rule = strings.ToLower(strings.Trim(strings.TrimSpace(rule), "."))
	if domain == "" || rule == "" {
		return false
	}
	if strings.HasPrefix(rule, "*.") {
		suffix := strings.TrimPrefix(rule, "*.")
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}
	return domain == rule || strings.HasSuffix(domain, "."+rule)
}

func requestDomains(info AccessRequestInfo) []string {
	seen := make(map[string]struct{})
	var domains []string
	add := func(value string) {
		host := extractHost(value)
		if host == "" {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		domains = append(domains, host)
	}
	add(info.Host)
	add(info.Origin)
	add(info.Referer)
	return domains
}

func extractHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}
		value = parsed.Host
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.ToLower(strings.Trim(strings.Trim(value, "[]"), "."))
}

func isLoopbackAddress(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.IsLoopback()
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func normalizeAccessPolicyTime(value, fallback string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	value = strings.ReplaceAll(value, "T", " ")
	if len(value) == len("2006-01-02 15:04") {
		value += ":00"
	}
	parsed, err := utils.ParseTimeString(value)
	if err != nil {
		return "", err
	}
	return parsed.In(time.FixedZone("CST", 8*3600)).Format("2006-01-02 15:04:05"), nil
}

func notifyAccessBlacklistChange(event DingTalkEvent, category, item, startsAt, expiresAt, source string) {
	action := "添加访问黑名单"
	if event == DingTalkEventBlacklistRemove {
		action = "解除访问黑名单"
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "手动添加"
		if event == DingTalkEventBlacklistRemove {
			source = "手动解除"
		}
	}
	categoryLabel := map[string]string{"ip": "IP", "domain": "域名"}[normalizeAccessPolicyCategory(category)]
	if categoryLabel == "" {
		categoryLabel = category
	}
	activeRange := "永久"
	if expiresAt != "" {
		activeRange = fmt.Sprintf("%s 至 %s", startsAt, expiresAt)
	}
	title := action
	text := fmt.Sprintf("### %s\n\n- **类型**: %s\n- **访问来源**: %s\n- **限制目标**: `%s`\n- **生效范围**: %s\n- **通知时间**: %s",
		action, categoryLabel, source, item, activeRange, utils.GetCurrentTimeString())
	NewDingTalkBotService().NotifyEvent(event, title, text)
}
