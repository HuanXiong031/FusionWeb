// backend/utils/validation.go
// 输入校验模块
// 提供统一的用户输入验证功能，防止恶意输入导致的安全问题。
// 设计要点：
// - 所有对外接口（用户名、密码、文件名等）在业务逻辑执行前均需通过校验
// - 长度限制常量集中定义，便于统一调整
// - 文件名校验：拦截路径穿越字符（../、\、/等），防止任意文件读写
// - 字符串清洗：移除不可见控制字符（ASCII 0-31），防止注入
package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// 输入长度限制常量
// 所有外部输入均受这些常量的硬性约束，防止超长输入导致的资源消耗或注入攻击
const (
	MaxUsernameLength    = 50
	MaxPasswordLength    = 128
	MaxTaskNameLength    = 200
	MaxDescriptionLength = 5000
	MaxCategoryLength    = 100
	MaxFileNameLength    = 255
	MaxKeywordLength     = 200
	MaxContentLength     = 10 * 1024 * 1024 // 10MB
)

// ValidateStringLength 验证字符串长度是否在允许范围内
// 参数：
//   - value: 要验证的字符串值
//   - fieldName: 字段名称（用于生成错误消息）
//   - maxLength: 最大允许长度
// 返回值：超长时返回错误，否则返回 nil
func ValidateStringLength(value string, fieldName string, maxLength int) error {
	if len(value) > maxLength {
		return fmt.Errorf("%s长度不能超过%d个字符", fieldName, maxLength)
	}
	return nil
}

// ValidateUsername 验证用户名格式
// 规则：
// - 不能为空
// - 长度不超过 MaxUsernameLength（50）
// - 只能包含字母、数字、下划线和连字符（正则：^[a-zA-Z0-9_-]+$）
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if err := ValidateStringLength(username, "用户名", MaxUsernameLength); err != nil {
		return err
	}
	// 用户名只能包含字母、数字、下划线和连字符
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username); !matched {
		return fmt.Errorf("用户名只能包含字母、数字、下划线和连字符")
	}
	return nil
}

// ValidatePassword 验证密码强度
// 规则：
// - 不能为空
// - 长度至少 6 位
// - 长度不超过 MaxPasswordLength（128）
func ValidatePassword(password string) error {
	if password == "" {
		return fmt.Errorf("密码不能为空")
	}
	if len(password) < 6 {
		return fmt.Errorf("密码长度至少6位")
	}
	if err := ValidateStringLength(password, "密码", MaxPasswordLength); err != nil {
		return err
	}
	return nil
}

// ValidateTaskName 验证任务名
func ValidateTaskName(taskName string) error {
	if taskName == "" {
		return fmt.Errorf("任务名不能为空")
	}
	return ValidateStringLength(taskName, "任务名", MaxTaskNameLength)
}

// ValidateDescription 验证描述
func ValidateDescription(description string) error {
	return ValidateStringLength(description, "描述", MaxDescriptionLength)
}

// ValidateCategory 验证分类名
func ValidateCategory(category string) error {
	return ValidateStringLength(category, "分类", MaxCategoryLength)
}

// ValidateFileName 验证文件名
func ValidateFileName(fileName string) error {
	if fileName == "" {
		return fmt.Errorf("文件名不能为空")
	}
	if err := ValidateStringLength(fileName, "文件名", MaxFileNameLength); err != nil {
		return err
	}
	// 检查文件名是否包含非法字符
	illegalChars := []string{"..", "/", "\\", "<", ">", ":", "\"", "|", "?", "*"}
	for _, char := range illegalChars {
		if strings.Contains(fileName, char) {
			return fmt.Errorf("文件名不能包含非法字符: %s", char)
		}
	}
	return nil
}

// ValidateKeyword 验证关键字
func ValidateKeyword(keyword string) error {
	return ValidateStringLength(keyword, "关键字", MaxKeywordLength)
}

// ValidateContent 验证内容长度
func ValidateContent(content string, fieldName string) error {
	return ValidateStringLength(content, fieldName, MaxContentLength)
}

// SanitizeString 清理字符串中的控制字符
// 参数：s - 原始字符串
// 返回值：移除控制字符后的安全字符串
//
// 保留的字符：
// - 可见 ASCII 字符（>= 32）
// - 换行符（\n）、制表符（\t）、回车符（\r）
// 移除的字符：ASCII 0-31（控制字符，除上述保留外）
// 使用场景：用户输入的预处理，防止控制字符注入
func SanitizeString(s string) string {
	// 移除控制字符（ASCII 0-31，除了换行符和制表符）
	var builder strings.Builder
	for _, r := range s {
		if r >= 32 || r == '\n' || r == '\t' || r == '\r' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
