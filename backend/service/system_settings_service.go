package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"strings"
)

type DingTalkKey struct {
	ID                     int    `json:"id"`
	Name                   string `json:"name"`
	AccessToken            string `json:"accessToken,omitempty"`
	Secret                 string `json:"secret,omitempty"`
	NotifyBlacklistAdd     bool   `json:"notifyBlacklistAdd"`
	NotifyBlacklistRemove  bool   `json:"notifyBlacklistRemove"`
	NotifyWebScanComplete  bool   `json:"notifyWebScanComplete"`
	NotifyPortScanComplete bool   `json:"notifyPortScanComplete"`
	Enabled                bool   `json:"enabled"`
	CreatedAt              string `json:"createdAt,omitempty"`
	UpdatedAt              string `json:"updatedAt,omitempty"`
}

type SystemSettingsService struct{}

func NewSystemSettingsService() *SystemSettingsService {
	return &SystemSettingsService{}
}

func (s *SystemSettingsService) ListDingTalkKeys(includeSecret bool) ([]DingTalkKey, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	rows, err := database.DB.Query(`
		SELECT id, name, access_token, secret, notify_blacklist_add, notify_blacklist_remove,
		       notify_web_scan_complete, notify_port_scan_complete, enabled, created_at, updated_at
		  FROM dingtalk_keys
		 ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]DingTalkKey, 0)
	for rows.Next() {
		item, err := scanDingTalkKey(rows, includeSecret)
		if err == nil {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *SystemSettingsService) GetDingTalkKey(id int, includeSecret bool) (DingTalkKey, error) {
	if database.DB == nil {
		return DingTalkKey{}, fmt.Errorf("数据库未初始化")
	}
	row := database.DB.QueryRow(`
		SELECT id, name, access_token, secret, notify_blacklist_add, notify_blacklist_remove,
		       notify_web_scan_complete, notify_port_scan_complete, enabled, created_at, updated_at
		  FROM dingtalk_keys
		 WHERE id = ?
	`, id)
	return scanDingTalkKey(row, includeSecret)
}

func (s *SystemSettingsService) SaveDingTalkKey(item DingTalkKey) (DingTalkKey, error) {
	if database.DB == nil {
		return DingTalkKey{}, fmt.Errorf("数据库未初始化")
	}
	item.Name = strings.TrimSpace(item.Name)
	item.AccessToken = strings.TrimSpace(item.AccessToken)
	item.Secret = strings.TrimSpace(item.Secret)
	if item.Name == "" {
		return DingTalkKey{}, fmt.Errorf("请输入 Key 名称")
	}
	if item.AccessToken == "" {
		return DingTalkKey{}, fmt.Errorf("请输入钉钉 access_token")
	}
	now := utils.GetCurrentTimeString()
	if item.ID > 0 {
		_, err := database.DB.Exec(`
			UPDATE dingtalk_keys
			   SET name = ?, access_token = ?, secret = CASE WHEN ? = '' THEN secret ELSE ? END, notify_blacklist_add = ?, notify_blacklist_remove = ?,
			       notify_web_scan_complete = ?, notify_port_scan_complete = ?, enabled = ?, updated_at = ?
			 WHERE id = ?
		`, item.Name, item.AccessToken, item.Secret, item.Secret, boolToInt(item.NotifyBlacklistAdd), boolToInt(item.NotifyBlacklistRemove),
			boolToInt(item.NotifyWebScanComplete), boolToInt(item.NotifyPortScanComplete), boolToInt(item.Enabled), now, item.ID)
		if err != nil {
			return DingTalkKey{}, err
		}
		return s.GetDingTalkKey(item.ID, true)
	}
	id, err := database.InsertAndReturnID(`
		INSERT INTO dingtalk_keys
			(name, access_token, secret, notify_blacklist_add, notify_blacklist_remove,
			 notify_web_scan_complete, notify_port_scan_complete, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, item.Name, item.AccessToken, item.Secret, boolToInt(item.NotifyBlacklistAdd), boolToInt(item.NotifyBlacklistRemove),
		boolToInt(item.NotifyWebScanComplete), boolToInt(item.NotifyPortScanComplete), boolToInt(item.Enabled), now, now)
	if err != nil {
		return DingTalkKey{}, err
	}
	return s.GetDingTalkKey(int(id), true)
}

func (s *SystemSettingsService) DeleteDingTalkKey(id int) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	_, err := database.DB.Exec("DELETE FROM dingtalk_keys WHERE id = ?", id)
	return err
}

func scanDingTalkKey(scanner interface {
	Scan(dest ...interface{}) error
}, includeSecret bool) (DingTalkKey, error) {
	var item DingTalkKey
	var secret, createdAt, updatedAt sql.NullString
	var add, remove, webComplete, portComplete, enabled int
	if err := scanner.Scan(&item.ID, &item.Name, &item.AccessToken, &secret, &add, &remove, &webComplete, &portComplete, &enabled, &createdAt, &updatedAt); err != nil {
		return DingTalkKey{}, err
	}
	if includeSecret {
		item.Secret = nullStringValue(secret)
	}
	item.NotifyBlacklistAdd = add == 1
	item.NotifyBlacklistRemove = remove == 1
	item.NotifyWebScanComplete = webComplete == 1
	item.NotifyPortScanComplete = portComplete == 1
	item.Enabled = enabled == 1
	item.CreatedAt = nullStringValue(createdAt)
	item.UpdatedAt = nullStringValue(updatedAt)
	return item, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
