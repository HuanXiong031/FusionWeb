// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现SQL表名白名单验证，防止SQL注入攻击。
package service

import (
	"fmt"
)

// allowedTableNames 允许查询的表名白名单。
// 仅此列表中的表名可通过ValidateTableName验证，其他表名将被拒绝。
// 所有动态表名查询必须经过此验证，防止SQL注入。
var allowedTableNames = map[string]bool{
	"passive_fingerprints": true,
	"active_fingerprints":  true,
	"blacklist":            true,
	"task_config":          true,
	"recon_results":        true,
	"fingerprint_results":  true,
	"vuln_results":         true,
	"poc_scan_tasks":       true,
	"poc_scan_results":     true,
}

// ValidateTableName 基于白名单验证表名，防止SQL注入。
// 这是后端唯一允许动态表名的入口，所有需要动态拼接表名的操作
// 都必须先通过此函数验证。不在白名单中的表名将直接拒绝。
//
// 参数:
//   - tableName: 要验证的表名
//
// 返回值:
//   - error: 表名不在白名单中时返回错误信息
func ValidateTableName(tableName string) error {
	if !allowedTableNames[tableName] {
		return fmt.Errorf("无效的表名: %s (不在白名单中)", tableName)
	}
	return nil
}
