// backend/repository/base.go
// Repository 模式基础层
// 封装通用 CRUD 操作，提供类型安全的数据库访问抽象
package repository

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// BaseRepository 提供通用数据库操作
type BaseRepository struct {
	DB    *sql.DB
	Table string
}

// NewBaseRepository 创建基础 Repository
func NewBaseRepository(table string) *BaseRepository {
	return &BaseRepository{DB: database.GetDB(), Table: table}
}

// Query 执行查询并返回行
func (r *BaseRepository) Query(query string, args ...interface{}) (*sql.Rows, error) {
	logger.Debug("Repository.Query: %s, args: %v", query, args)
	return r.DB.Query(query, args...)
}

// QueryRow 执行单行查询
func (r *BaseRepository) QueryRow(query string, args ...interface{}) *sql.Row {
	logger.Debug("Repository.QueryRow: %s, args: %v", query, args)
	return r.DB.QueryRow(query, args...)
}

// Exec 执行写操作（INSERT/UPDATE/DELETE）
func (r *BaseRepository) Exec(query string, args ...interface{}) (sql.Result, error) {
	logger.Debug("Repository.Exec: %s, args: %v", query, args)
	return r.DB.Exec(query, args...)
}

// FindAll 查询所有记录，映射为 []map[string]interface{}
func (r *BaseRepository) FindAll(where string, args ...interface{}) ([]map[string]interface{}, error) {
	query := fmt.Sprintf("SELECT * FROM %s", r.Table)
	if where != "" {
		query += " WHERE " + where
	}

	rows, err := r.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询 %s 失败: %w", r.Table, err)
	}
	defer rows.Close()

	return scanRows(rows)
}

// FindByID 按 ID 查询单条记录
func (r *BaseRepository) FindByID(id interface{}) (map[string]interface{}, error) {
	results, err := r.FindAll("id = $1", id)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%s 记录不存在: id=%v", r.Table, id)
	}
	return results[0], nil
}

// Count 计数
func (r *BaseRepository) Count(where string, args ...interface{}) (int, error) {
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", r.Table)
	if where != "" {
		query += " WHERE " + where
	}

	var count int
	err := r.QueryRow(query, args...).Scan(&count)
	return count, err
}

// Insert 插入记录
func (r *BaseRepository) Insert(data map[string]interface{}) (int64, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("插入数据不能为空")
	}

	columns := ""
	placeholders := ""
	var args []interface{}

	for col, val := range data {
		if columns != "" {
			columns += ", "
			placeholders += ", "
		}
		columns += col
		args = append(args, val)
		placeholders += fmt.Sprintf("$%d", len(args))
	}

	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", r.Table, columns, placeholders)
	id, err := database.InsertAndReturnID(query, args...)
	if err != nil {
		return 0, fmt.Errorf("插入 %s 失败: %w", r.Table, err)
	}
	return id, nil
}

// Update 更新记录
func (r *BaseRepository) Update(id interface{}, data map[string]interface{}) error {
	if len(data) == 0 {
		return fmt.Errorf("更新数据不能为空")
	}

	setClause := ""
	var args []interface{}

	for col, val := range data {
		if setClause != "" {
			setClause += ", "
		}
		args = append(args, val)
		setClause += fmt.Sprintf("%s = $%d", col, len(args))
	}
	args = append(args, id)

	query := fmt.Sprintf("UPDATE %s SET %s WHERE id = $%d", r.Table, setClause, len(args))
	_, err := r.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("更新 %s 失败: %w", r.Table, err)
	}
	return nil
}

// Delete 删除记录
func (r *BaseRepository) Delete(id interface{}) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE id = $1", r.Table)
	result, err := r.Exec(query, id)
	if err != nil {
		return fmt.Errorf("删除 %s 失败: %w", r.Table, err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("%s 记录不存在: id=%v", r.Table, id)
	}
	return nil
}

// ============================================================
// 工具函数
// ============================================================

// scanRows 将 *sql.Rows 转换为 []map[string]interface{}
func scanRows(rows *sql.Rows) ([]map[string]interface{}, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// 处理 []byte → string
			if b, ok := val.([]byte); ok {
				row[col] = normalizeScannedValue(col, string(b))
			} else if t, ok := val.(time.Time); ok {
				row[col] = normalizeScannedValue(col, t)
			} else {
				row[col] = normalizeScannedValue(col, val)
			}
		}
		results = append(results, row)
	}

	return results, rows.Err()
}

func normalizeScannedValue(column string, value interface{}) interface{} {
	if value == nil || !isTimeLikeColumn(column) {
		return value
	}
	switch v := value.(type) {
	case time.Time:
		return utils.FormatTimeForDisplay(v)
	case string:
		if strings.TrimSpace(v) == "" {
			return v
		}
		return utils.FormatTimeStringForDisplay(v)
	default:
		return value
	}
}

func isTimeLikeColumn(column string) bool {
	column = strings.ToLower(strings.TrimSpace(column))
	return column == "created" ||
		column == "time" ||
		column == "last_login" ||
		strings.HasSuffix(column, "_at") ||
		strings.HasSuffix(column, "time")
}
