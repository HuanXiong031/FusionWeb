package database

import (
	"FusionWeb/backend/models"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const scanDebugPacketBase64Prefix = "__fusionweb_scan_debug_base64_v1__:"

// InsertScanDebugPacket 保存扫描调试包到数据库。
func InsertScanDebugPacket(taskID, host, templateID, eventType, data string) error {
	if DB == nil {
		return fmt.Errorf("数据库未初始化")
	}

	_, err := DB.Exec(
		`INSERT INTO scan_debug_packets (task_id, host, template_id, event_type, data, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		strings.TrimSpace(taskID),
		strings.TrimSpace(host),
		strings.TrimSpace(templateID),
		strings.TrimSpace(eventType),
		encodeScanDebugPacketData(data),
		time.Now().In(databaseChinaLocation()).Format("2006-01-02 15:04:05"),
	)
	return err
}

// GetScanDebugPackets 查询扫描调试包。
func GetScanDebugPackets(taskID string, limit, offset int) ([]models.ScanDebugPacket, error) {
	if DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := DB.Query(
		`SELECT id, task_id, host, template_id, event_type, data, CAST(created_at AS TEXT)
		   FROM scan_debug_packets
		  WHERE task_id = $1
		  ORDER BY created_at DESC, id DESC
		  LIMIT $2 OFFSET $3`,
		taskID, limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.ScanDebugPacket, 0)
	for rows.Next() {
		var item models.ScanDebugPacket
		var createdAt string
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Host, &item.TemplateID, &item.EventType, &item.Data, &createdAt); err != nil {
			continue
		}
		item.Data = decodeScanDebugPacketData(item.Data)
		if parsed, err := parseScanDebugPacketTime(createdAt); err == nil {
			item.CreatedAt = parsed
		}
		items = append(items, item)
	}
	return items, nil
}

func encodeScanDebugPacketData(data string) string {
	if isPostgresTextSafe(data) && !strings.HasPrefix(data, scanDebugPacketBase64Prefix) {
		return data
	}
	return scanDebugPacketBase64Prefix + base64.StdEncoding.EncodeToString([]byte(data))
}

func decodeScanDebugPacketData(data string) string {
	encoded, ok := strings.CutPrefix(data, scanDebugPacketBase64Prefix)
	if !ok {
		return data
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return data
	}
	return string(decoded)
}

func isPostgresTextSafe(data string) bool {
	return utf8.ValidString(data) && !strings.ContainsRune(data, '\x00')
}

func parseScanDebugPacketTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Time{}, fmt.Errorf("时间字符串为空")
	}

	formatsWithTZ := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05.999999999Z07:00",
	}
	for _, format := range formatsWithTZ {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t.In(databaseChinaLocation()), nil
		}
	}

	formatsWithoutTZ := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
	}
	loc := databaseChinaLocation()
	for _, format := range formatsWithoutTZ {
		if t, err := time.ParseInLocation(format, timeStr, loc); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("无法解析时间字符串: %s", timeStr)
}
