// ========================================
// callnuclei/utils.go — 路径与文件系统工具函数
//
// 提供路径规范化和文件系统验证等通用工具函数，
// 用于 Nuclei 扫描模块中的模板目录查找、文件路径处理等场景。
//
// ========================================
package callnuclei

import (
	"os"
	"path/filepath"
	"strings"
)

// normalizePath 规范化路径为绝对路径并统一分隔符
//
// 功能说明：
//
//	对输入的路径字符串进行处理，确保返回一个规范化的绝对路径：
//	1. 去除首尾空白字符
//	2. 将反斜杠（\）统一替换为正斜杠（/），再通过 filepath.Clean 规范化
//	3. 若为相对路径，基于当前工作目录转换为绝对路径
//
// 参数：
//   - p: 待规范化的路径字符串（可为相对路径或绝对路径）
//
// 返回值：
//   - 规范化后的绝对路径字符串；输入为空时返回空字符串
//
// 使用场景：
//   - 处理用户配置的 Nuclei 模板目录路径
//   - 确保跨平台路径分隔符的一致性
//   - 将相对路径解析为绝对路径，避免工作目录变化导致的问题
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	s := strings.TrimSpace(p)
	// 将反斜杠统一为平台分隔符
	s = filepath.Clean(strings.ReplaceAll(s, "\\", "/"))
	// 若为相对路径，转换为绝对路径
	if !filepath.IsAbs(s) {
		if wd, err := os.Getwd(); err == nil {
			s = filepath.Join(wd, s)
		}
	}
	return s
}

// pathExists 判断给定路径是否存在（文件或目录均可）
//
// 功能说明：
//
//	通过 os.Stat 检查路径是否存在。若返回 nil（无错误），则路径存在；
//	若返回错误（如文件不存在、权限不足），则视为不存在。
//
// 参数：
//   - p: 待检查的文件或目录路径
//
// 返回值：
//   - true: 路径存在且可访问
//   - false: 路径不存在或无法访问
//
// 使用场景：
//   - 在扫描前验证模板目录是否存在
//   - 查找模板文件时的路径有效性检查
//   - 回退路径查找（尝试多个候选路径）
func pathExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}