package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type VulnVerifyService struct{}

func NewVulnVerifyService() *VulnVerifyService {
	return &VulnVerifyService{}
}

// GetVerifyList 获取验证列表
func (s *VulnVerifyService) GetVerifyList(page, pageSize int, keyword string, userID uint, createdByFilter *int) (map[string]interface{}, error) {
	offset := (page - 1) * pageSize

	query := `SELECT v.id, v.name, v.target, v.severity, v.status, v.status_text, CAST(v.created_at AS TEXT), v.group_id, v.request, v.response, v.history, g.name as group_name
              FROM manual_vuln_verify v
              LEFT JOIN vuln_verify_group g ON v.group_id = g.id
              WHERE 1=1`

	countQuery := "SELECT COUNT(*) FROM manual_vuln_verify v WHERE 1=1"

	var args []interface{}

	if keyword != "" {
		like := "%" + keyword + "%"
		query += " AND (v.name LIKE ? OR v.target LIKE ?)"
		countQuery += " AND (v.name LIKE ? OR v.target LIKE ?)"
		args = append(args, like, like)
	}

	if createdByFilter != nil {
		query += " AND v.user_id = ?"
		countQuery += " AND v.user_id = ?"
		args = append(args, *createdByFilter)
	}

	query += " ORDER BY v.created_at DESC LIMIT ? OFFSET ?"
	argsWithLimit := append(args, pageSize, offset)

	var total int
	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, err
	}

	rows, err := database.DB.Query(query, argsWithLimit...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var v models.ManualVulnVerify
		var groupName sql.NullString
		var target, statusText, history sql.NullString
		var createdAt sql.NullString

		if err := rows.Scan(&v.ID, &v.Name, &target, &v.Severity, &v.Status, &statusText, &createdAt, &v.GroupID, &v.Request, &v.Response, &history, &groupName); err != nil {
			logger.Error("GetVerifyList scan failed: %v", err)
			continue
		}

		v.Target = target.String
		v.StatusText = statusText.String
		v.History = history.String

		item := map[string]interface{}{
			"id":          v.ID,
			"name":        v.Name,
			"target":      v.Target,
			"severity":    v.Severity,
			"status":      v.Status,
			"status_text": v.StatusText,
			"created_at":  utils.FormatNullTimeStringForDisplay(createdAt),
			"group_id":    v.GroupID,
			"request":     v.Request,
			"response":    v.Response,
			"history":     v.History,
		}

		if groupName.Valid {
			item["group_name"] = groupName.String
		}

		list = append(list, item)
	}

	return map[string]interface{}{
		"total": total,
		"list":  list,
	}, nil
}

// AddVerify 添加验证任务
func (s *VulnVerifyService) AddVerify(name string, groupID int, request string, response string, userID uint) (int64, error) {
	query := `INSERT INTO manual_vuln_verify (name, group_id, request, response, user_id, status, created_at, updated_at) 
              VALUES (?, ?, ?, ?, ?, 0, ?, ?)`

	now := utils.GetCurrentTimeString()
	id, err := database.InsertAndReturnID(query, name, groupID, request, response, userID, now, now)
	if err != nil {
		logger.Error("AddVerify failed: %v", err)
		return 0, err
	}

	return id, nil
}

// UpdateVerify 更新验证任务
func (s *VulnVerifyService) UpdateVerify(id int, data map[string]interface{}, userID uint) error {
	query := "UPDATE manual_vuln_verify SET updated_at = ?"
	args := []interface{}{utils.GetCurrentTimeString()}

	if val, ok := data["name"].(string); ok {
		query += ", name = ?"
		args = append(args, val)
	}
	if val, ok := data["target"].(string); ok {
		query += ", target = ?"
		args = append(args, val)
	}
	if val, ok := data["severity"].(string); ok {
		query += ", severity = ?"
		args = append(args, val)
	}
	if val, ok := data["status"].(float64); ok {
		query += ", status = ?"
		args = append(args, int(val))
	}
	if val, ok := data["status_text"].(string); ok {
		query += ", status_text = ?"
		args = append(args, val)
	}
	if val, ok := data["request"].(string); ok {
		query += ", request = ?"
		args = append(args, val)
	}
	if val, ok := data["response"].(string); ok {
		query += ", response = ?"
		args = append(args, val)
	}
	if val, ok := data["history"].(string); ok {
		query += ", history = ?"
		args = append(args, val)
	}

	query += " WHERE id = ?"
	args = append(args, id)

	_, err := database.DB.Exec(query, args...)
	return err
}

// DeleteVerify 删除验证任务
func (s *VulnVerifyService) DeleteVerify(id int, userID uint) error {
	_, err := database.DB.Exec("DELETE FROM manual_vuln_verify WHERE id = ?", id)
	return err
}

// GetGroups 获取分组
func (s *VulnVerifyService) GetGroups(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	query := "SELECT id, name, CAST(created_at AS TEXT) FROM vuln_verify_group WHERE 1=1"
	var args []interface{}

	if createdByFilter != nil {
		query += " AND created_by = ?"
		args = append(args, *createdByFilter)
	}

	query += " ORDER BY created_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []map[string]interface{}
	for rows.Next() {
		var g models.VulnVerifyGroup
		var createdAt sql.NullString
		if err := rows.Scan(&g.ID, &g.Name, &createdAt); err != nil {
			continue
		}
		groups = append(groups, map[string]interface{}{
			"id":         g.ID,
			"name":       g.Name,
			"created_at": utils.FormatNullTimeStringForDisplay(createdAt),
		})
	}

	return groups, nil
}

// AddGroup 添加分组
func (s *VulnVerifyService) AddGroup(name string, userID uint) (int64, error) {
	query := "INSERT INTO vuln_verify_group (name, created_by, created_at, updated_at) VALUES (?, ?, ?, ?)"
	now := utils.GetCurrentTimeString()
	return database.InsertAndReturnID(query, name, userID, now, now)
}

// UpdateGroup 更新分组
func (s *VulnVerifyService) UpdateGroup(id int, name string, userID uint) error {
	_, err := database.DB.Exec("UPDATE vuln_verify_group SET name = ?, updated_at = ? WHERE id = ?", name, utils.GetCurrentTimeString(), id)
	return err
}

// DeleteGroup 删除分组
func (s *VulnVerifyService) DeleteGroup(id int, userID uint) error {
	_, err := database.DB.Exec("DELETE FROM vuln_verify_group WHERE id = ?", id)
	return err
}

// GetVerifyListByGroup 按分组获取验证任务
func (s *VulnVerifyService) GetVerifyListByGroup(groupID int, userID uint) ([]map[string]interface{}, error) {
	query := `SELECT id, name, target, severity, status, status_text, CAST(created_at AS TEXT), request, response, history 
              FROM manual_vuln_verify 
              WHERE group_id = ?`
	var args []interface{}
	args = append(args, groupID)

	query += " ORDER BY created_at DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		logger.Error("GetVerifyListByGroup query failed: %v", err)
		return nil, err
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var v models.ManualVulnVerify
		var target, statusText, history sql.NullString
		var createdAt sql.NullString

		if err := rows.Scan(&v.ID, &v.Name, &target, &v.Severity, &v.Status, &statusText, &createdAt, &v.Request, &v.Response, &history); err != nil {
			logger.Error("GetVerifyListByGroup scan failed: %v", err)
			continue
		}

		v.Target = target.String
		v.StatusText = statusText.String
		v.History = history.String

		list = append(list, map[string]interface{}{
			"id":          v.ID,
			"name":        v.Name,
			"target":      v.Target,
			"severity":    v.Severity,
			"status":      v.Status,
			"status_text": v.StatusText,
			"created_at":  utils.FormatNullTimeStringForDisplay(createdAt),
			"request":     v.Request,
			"response":    v.Response,
			"history":     v.History,
		})
	}

	return list, nil
}

// GetWorkbench 获取新版漏洞验证发包工作台状态。
func (s *VulnVerifyService) GetWorkbench(userID uint) (map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT id, title, raw_packet, response_text, response_meta, force_https, history_cursor, active
		FROM vuln_verify_workbench_tabs
		WHERE user_id = ?
		ORDER BY sort_order ASC, updated_at ASC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tabs []map[string]interface{}
	activeTabID := ""

	for rows.Next() {
		var id string
		var title, rawPacket, responseText, responseMeta sql.NullString
		var forceHTTPS, active int
		var historyCursor sql.NullInt64
		if err := rows.Scan(&id, &title, &rawPacket, &responseText, &responseMeta, &forceHTTPS, &historyCursor, &active); err != nil {
			return nil, err
		}

		historyItems, err := s.getWorkbenchHistory(userID, id)
		if err != nil {
			return nil, err
		}

		tab := map[string]interface{}{
			"id":            id,
			"title":         title.String,
			"rawPacket":     rawPacket.String,
			"responseText":  responseText.String,
			"responseMeta":  decodeWorkbenchJSON(responseMeta.String),
			"forceHttps":    forceHTTPS == 1,
			"historyCursor": nil,
			"historyItems":  historyItems,
		}
		if historyCursor.Valid {
			tab["historyCursor"] = int(historyCursor.Int64)
		}
		if active == 1 {
			activeTabID = id
		}
		tabs = append(tabs, tab)
	}

	if activeTabID == "" && len(tabs) > 0 {
		if id, ok := tabs[0]["id"].(string); ok {
			activeTabID = id
		}
	}

	return map[string]interface{}{
		"tabs":        tabs,
		"activeTabId": activeTabID,
	}, nil
}

func (s *VulnVerifyService) getWorkbenchHistory(userID uint, tabID string) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT id, request, response, meta, CAST(created_at AS TEXT)
		FROM vuln_verify_workbench_history
		WHERE user_id = ? AND tab_id = ?
		ORDER BY sort_order ASC, created_at DESC
	`, userID, tabID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var id string
		var request, response, meta, createdAt sql.NullString
		if err := rows.Scan(&id, &request, &response, &meta, &createdAt); err != nil {
			return nil, err
		}
		history = append(history, map[string]interface{}{
			"id":        id,
			"request":   request.String,
			"response":  response.String,
			"createdAt": utils.FormatNullTimeStringForDisplay(createdAt),
			"meta":      decodeWorkbenchJSON(meta.String),
		})
	}
	return history, nil
}

// SaveWorkbench 保存新版漏洞验证发包工作台状态。
func (s *VulnVerifyService) SaveWorkbench(userID uint, data map[string]interface{}) (map[string]interface{}, error) {
	tabs := workbenchSlice(data["tabs"])
	activeTabID := workbenchString(data, "activeTabId", "active_tab_id")
	now := utils.GetCurrentTimeString()

	tx, err := database.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM vuln_verify_workbench_history WHERE user_id = ?", userID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec("DELETE FROM vuln_verify_workbench_tabs WHERE user_id = ?", userID); err != nil {
		return nil, err
	}

	seenTabs := map[string]bool{}
	for index, item := range tabs {
		tab, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		tabID := strings.TrimSpace(workbenchString(tab, "id"))
		if tabID == "" {
			tabID = workbenchGeneratedID("raw-tab", index)
		}
		if seenTabs[tabID] {
			tabID = workbenchGeneratedID(tabID, index)
		}
		seenTabs[tabID] = true
		if activeTabID == "" && index == 0 {
			activeTabID = tabID
		}

		historyCursor := workbenchOptionalInt(tab, "historyCursor", "history_cursor")
		active := 0
		if tabID == activeTabID {
			active = 1
		}
		if _, err := tx.Exec(`
			INSERT INTO vuln_verify_workbench_tabs
				(id, user_id, title, raw_packet, response_text, response_meta, force_https, history_cursor, sort_order, active, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			tabID,
			userID,
			workbenchString(tab, "title"),
			workbenchString(tab, "rawPacket", "raw_packet"),
			workbenchString(tab, "responseText", "response_text"),
			encodeWorkbenchJSON(tab["responseMeta"]),
			workbenchBool(tab, "forceHttps", "force_https"),
			historyCursor,
			index,
			active,
			now,
			now,
		); err != nil {
			return nil, err
		}

		seenHistory := map[string]bool{}
		for historyIndex, historyItem := range workbenchSlice(tab["historyItems"]) {
			itemMap, ok := historyItem.(map[string]interface{})
			if !ok {
				continue
			}
			historyID := strings.TrimSpace(workbenchString(itemMap, "id"))
			if historyID == "" {
				historyID = workbenchGeneratedID("raw-history", historyIndex)
			}
			if seenHistory[historyID] {
				historyID = workbenchGeneratedID(historyID, historyIndex)
			}
			seenHistory[historyID] = true
			createdAt := workbenchString(itemMap, "createdAt", "created_at")
			if createdAt == "" {
				createdAt = now
			}
			if _, err := tx.Exec(`
				INSERT INTO vuln_verify_workbench_history
					(id, tab_id, user_id, request, response, meta, sort_order, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`,
				historyID,
				tabID,
				userID,
				workbenchString(itemMap, "request"),
				workbenchString(itemMap, "response"),
				encodeWorkbenchJSON(itemMap["meta"]),
				historyIndex,
				createdAt,
			); err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return s.GetWorkbench(userID)
}

func workbenchString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		if text, ok := value.(string); ok {
			return text
		}
	}
	return ""
}

func workbenchBool(data map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				return 1
			}
			return 0
		case float64:
			if typed != 0 {
				return 1
			}
			return 0
		case int:
			if typed != 0 {
				return 1
			}
			return 0
		case string:
			if typed == "true" || typed == "1" {
				return 1
			}
			return 0
		}
	}
	return 0
}

func workbenchOptionalInt(data map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		value, ok := data[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		case int64:
			return typed
		}
	}
	return nil
}

func workbenchSlice(value interface{}) []interface{} {
	if list, ok := value.([]interface{}); ok {
		return list
	}
	return nil
}

func encodeWorkbenchJSON(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) == "null" {
		return ""
	}
	return string(encoded)
}

func decodeWorkbenchJSON(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return nil
	}
	return decoded
}

func workbenchGeneratedID(prefix string, index int) string {
	return fmt.Sprintf("%s-%d-%d", strings.TrimSpace(prefix), time.Now().UnixNano(), index)
}
