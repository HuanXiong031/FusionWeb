// backend/utils/db_utils.go
package utils

import (
	"FusionWeb/backend/database"
	"database/sql"
	"fmt"
	"strings"
)

// QueryBuilder SQL WHERE 子句构建器
// 使用链式调用方式灵活构建查询条件，避免手动拼接 SQL 字符串。
// 典型用法：
//
//	qb := NewQueryBuilder().
//	    AddCondition("status = $1", "active").
//	    AddCondition("name LIKE $2", "%test%").
//	    AddPermissionFilter(userID, "t")
//	where, args := qb.Build()  // "WHERE status = $1 AND name LIKE $2"
type QueryBuilder struct {
	whereClauses []string      // WHERE 条件片段列表（如 "name = $1"）
	args         []interface{} // 对应的参数值列表
}

// NewQueryBuilder 创建新的查询构建器
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		whereClauses: []string{},
		args:         []interface{}{},
	}
}

// AddCondition 添加查询条件
// condition: SQL条件（如 "name = $1"）
// args: 对应的参数值
func (qb *QueryBuilder) AddCondition(condition string, args ...interface{}) *QueryBuilder {
	if condition != "" {
		qb.whereClauses = append(qb.whereClauses, condition)
		qb.args = append(qb.args, args...)
	}
	return qb
}

// AddPermissionFilter 单用户模式下不追加归属过滤。
func (qb *QueryBuilder) AddPermissionFilter(userID *int, tableAlias string) *QueryBuilder {
	return qb
}

// Build 构建WHERE子句和参数
// 返回: WHERE子句（包含"WHERE "前缀，如果没有条件则返回空字符串）和参数列表
func (qb *QueryBuilder) Build() (string, []interface{}) {
	if len(qb.whereClauses) == 0 {
		return "", qb.args
	}
	return "WHERE " + strings.Join(qb.whereClauses, " AND "), qb.args
}

// BuildWhereClause 构建WHERE子句（不包含"WHERE "前缀）
func (qb *QueryBuilder) BuildWhereClause() string {
	if len(qb.whereClauses) == 0 {
		return "1=1"
	}
	return strings.Join(qb.whereClauses, " AND ")
}

// GetArgs 获取参数列表
func (qb *QueryBuilder) GetArgs() []interface{} {
	return qb.args
}

// PaginationParams 分页参数结构
// 用于统一处理列表查询的分页逻辑
type PaginationParams struct {
	Page     int
	PageSize int
}

// GetOffset 计算分页偏移量
// 公式：offset = (page - 1) * pageSize
// 用于 SQL LIMIT/OFFSET 子句
func (p *PaginationParams) GetOffset() int {
	return (p.Page - 1) * p.PageSize
}

// NewPaginationParams 创建分页参数实例
// 参数：page - 页码（从1开始），pageSize - 每页条数
// 返回值：分页参数指针
func NewPaginationParams(page, pageSize int) *PaginationParams {
	return &PaginationParams{
		Page:     page,
		PageSize: pageSize,
	}
}

// QueryWithPagination 执行分页查询
// tableName: 表名
// selectFields: SELECT字段列表（如 "id, name, created_at"）
// whereClause: WHERE子句（不包含"WHERE "前缀）
// args: 查询参数
// orderBy: 排序字段（如 "created_at DESC"）
// pagination: 分页参数
// 返回: 查询结果行和总数
func QueryWithPagination(tableName, selectFields, whereClause, orderBy string, args []interface{}, pagination *PaginationParams) (*sql.Rows, int, error) {
	// 查询总数
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", tableName, whereClause)
	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("查询总数失败: %w", err)
	}

	// 构建查询语句
	whereSQL := ""
	if whereClause != "" && whereClause != "1=1" {
		whereSQL = "WHERE " + whereClause
	}

	orderSQL := ""
	if orderBy != "" {
		orderSQL = "ORDER BY " + orderBy
	}

	// 添加分页参数
	queryArgs := append(args, pagination.PageSize, pagination.GetOffset())
	query := fmt.Sprintf("SELECT %s FROM %s %s %s LIMIT $%d OFFSET $%d",
		selectFields, tableName, whereSQL, orderSQL, len(args)+1, len(args)+2)

	// 执行查询
	rows, err := database.DB.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询列表失败: %w", err)
	}

	// 注意：调用者需要负责关闭rows
	return rows, total, nil
}

// QueryAndCount 执行查询并返回总数和结果集
// 参数同 QueryWithPagination，语义一致的快捷函数
// 返回值：查询结果行集合、总记录数、可能的错误
// 调用者需要负责关闭返回的 *sql.Rows
func QueryAndCount(tableName, selectFields, whereClause, orderBy string, args []interface{}, pagination *PaginationParams) (*sql.Rows, int, error) {
	return QueryWithPagination(tableName, selectFields, whereClause, orderBy, args, pagination)
}

// ValidateTableName 验证表名（防止SQL注入）
func ValidateTableName(tableName string) error {
	// 只允许字母、数字和下划线
	for _, char := range tableName {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return fmt.Errorf("无效的表名: %s", tableName)
		}
	}
	return nil
}
