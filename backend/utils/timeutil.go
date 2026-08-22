// backend/utils/timeutil.go
// 时间工具模块
// 统一管理全平台的时间获取、格式化与解析逻辑。
// 设计要点：
// - 所有时间默认使用中国标准时间（Asia/Shanghai，UTC+8），确保跨服务器时区一致性
// - 容器环境缺少时区数据时自动降级为固定偏移（CST +8:00）
// - 提供多种时间格式的解析兼容（ISO 8601 / 标准格式 / 带纳秒格式）
// - 零值时间（IsZero）统一展示为"未完成"，避免显示 0001-01-01
package utils

import (
	"database/sql"
	"fmt"
	"time"
)

const displayTimeFormat = "2006-01-02 15:04:05"

func chinaLocation() *time.Location {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("CST", 8*3600)
	}
	return loc
}

// GetCurrentTime 获取当前时间（中国标准时间 CST，UTC+8）
// 无论服务器物理时区如何，返回值始终为北京时间。
// 设计理由：方便日志/数据库时间统一，方便国内用户阅读。
func GetCurrentTime() time.Time {
	loc := chinaLocation()
	return time.Now().In(loc)
}

// GetCurrentTimeString 获取当前时间的格式化字符串（北京时间）
// 参数：format - 可选的时间格式，默认 "2006-01-02 15:04:05"
// 返回值：格式化后的时间字符串
func GetCurrentTimeString(format ...string) string {
	timeFormat := displayTimeFormat
	if len(format) > 0 && format[0] != "" {
		timeFormat = format[0]
	}
	return GetCurrentTime().Format(timeFormat)
}

// FormatTime 格式化时间指针为字符串
// 参数：
//   - t: 时间指针，nil时使用当前时间
//   - format: 可选的时间格式，默认 "2006-01-02 15:04:05"
//
// 返回值：格式化后的时间字符串
func FormatTime(t *time.Time, format ...string) string {
	timeFormat := displayTimeFormat
	if len(format) > 0 && format[0] != "" {
		timeFormat = format[0]
	}

	var timeToFormat time.Time
	if t != nil {
		timeToFormat = *t
	} else {
		timeToFormat = GetCurrentTime()
	}

	return timeToFormat.In(chinaLocation()).Format(timeFormat)
}

// FormatTimeForDisplay 格式化时间用于前端展示
// 参数：t - 要格式化的时间值
// 返回值：格式化后的时间字符串，零值时间（0001-01-01）返回"未完成"
func FormatTimeForDisplay(t time.Time) string {
	if t.IsZero() {
		return "未完成"
	}
	return t.In(chinaLocation()).Format(displayTimeFormat)
}

// FormatTimeStringForDisplay 将时间字符串标准化为统一展示格式
// 参数：timeStr - 输入的时间字符串，支持多种格式（ISO 8601、标准格式等）
// 返回值：标准化后的时间字符串（2006-01-02 15:04:05），空字符串返回"未完成"
func FormatTimeStringForDisplay(timeStr string) string {
	if timeStr == "" {
		return "未完成"
	}

	if t, err := ParseTimeString(timeStr); err == nil {
		return FormatTimeForDisplay(t)
	}

	// 如果所有格式都解析失败，直接使用原值（假设已经是正确格式）
	return timeStr
}

// FormatNullTimeStringForDisplay 将数据库可空时间字符串标准化为统一展示格式。
func FormatNullTimeStringForDisplay(timeStr sql.NullString) string {
	if !timeStr.Valid {
		return ""
	}
	formatted := FormatTimeStringForDisplay(timeStr.String)
	if formatted == "未完成" {
		return ""
	}
	return formatted
}

// ParseTimeStringForDisplay 解析数据库时间字符串并返回标准展示时间。
func ParseTimeStringForDisplay(timeStr sql.NullString) time.Time {
	if !timeStr.Valid || timeStr.String == "" {
		return time.Time{}
	}
	t, err := ParseTimeString(timeStr.String)
	if err != nil {
		return time.Time{}
	}
	return t.In(chinaLocation())
}

// ParseTimeString 解析时间字符串为 time.Time 对象
// 参数：timeStr - 输入的时间字符串，支持多种格式
// 返回值：解析后的时间对象和可能的错误
// 支持格式：
//   - 带时区：RFC3339 / ISO 8601
//   - 不带时区：标准格式 / ISO 8601 无时区 / 带纳秒格式（按北京时间解析）
func ParseTimeString(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Time{}, fmt.Errorf("时间字符串为空")
	}

	formatsWithTZ := []string{
		time.RFC3339,                          // ISO 8601: 2006-01-02T15:04:05Z07:00
		"2006-01-02T15:04:05Z07:00",           // ISO 8601 with timezone
		"2006-01-02T15:04:05.999999999Z07:00", // ISO 8601 with nanoseconds
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
	}

	for _, format := range formatsWithTZ {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t, nil
		}
	}

	// 对于没有时区信息的格式，统一按北京时间解析，避免被 time.Parse 当成 UTC。
	formatsWithoutTZ := []string{
		"2006-01-02 15:04:05",           // 标准格式
		"2006-01-02T15:04:05",           // ISO 8601 without timezone
		"2006-01-02 15:04:05.999999999", // 带纳秒的标准格式
	}

	loc := chinaLocation()
	for _, format := range formatsWithoutTZ {
		if t, err := time.ParseInLocation(format, timeStr, loc); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("无法解析时间字符串: %s", timeStr)
}
