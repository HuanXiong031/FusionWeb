// backend/utils/row_utils.go
// 数据库查询结果集扫描工具模块
// 提供安全的 SQL Rows 扫描封装，确保错误处理的一致性和资源正确释放。
//
// 设计要点：
// - ScanRows: 通用扫描函数，自动检查 rows.Err()，防止漏检遍历过程中的错误
// - QueryAndScan: 一站式查询+扫描，自动管理 rows 的生命周期（defer close）
// - 两个函数均以回调方式接收扫描逻辑，保持灵活性
//
// 使用建议：
// - 简单查询使用 QueryAndScan（自动管理资源）
// - 复杂场景（需要手动控制 rows 生命周期）使用 ScanRows
package utils

import (
	"FusionWeb/backend/database"
	"database/sql"
	"fmt"
)

// ScanRows 扫描查询结果集并检查遍历错误
// 参数：
//   - rows: 已执行的 SQL 查询结果集
//   - scanFn: 对每一行执行的扫描回调函数
// 返回值：扫描过程中出现的错误
//
// 注意：调用者仍需负责关闭 rows（通常在 defer 中调用 rows.Close()）
// 相比直接使用 for rows.Next()，此函数额外在遍历后调用 rows.Err()
func ScanRows(rows *sql.Rows, scanFn func() error) error {
	for rows.Next() {
		if err := scanFn(); err != nil {
			return fmt.Errorf("扫描行失败: %w", err)
		}
	}

	// 检查遍历过程中是否有错误
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历结果集失败: %w", err)
	}

	return nil
}

// QueryAndScan 执行查询并自动扫描所有结果行
// 参数：
//   - query: SQL 查询语句
//   - args: 查询参数值
//   - scanFn: 扫描回调函数，接收 *sql.Rows 参数
// 返回值：查询或扫描过程中出现的错误
//
// 自动管理 rows 生命周期：打开 → 扫描 → 关闭（defer close）
// 适用于简单的"查询-遍历所有行"场景，减少资源泄漏风险
func QueryAndScan(query string, args []interface{}, scanFn func(*sql.Rows) error) error {
	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return fmt.Errorf("执行查询失败: %w", err)
	}
	defer rows.Close()

	return ScanRows(rows, func() error {
		return scanFn(rows)
	})
}
