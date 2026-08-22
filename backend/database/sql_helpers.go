package database

import (
	"database/sql"
	"fmt"
	"strings"
)

func InsertAndReturnID(query string, args ...interface{}) (int64, error) {
	if DB == nil {
		return 0, fmt.Errorf("数据库未初始化")
	}
	var id int64
	returningQuery := strings.TrimRight(strings.TrimSpace(query), ";") + " RETURNING id"
	if err := DB.QueryRow(returningQuery, args...).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func InsertAndReturnIDTx(tx *sql.Tx, query string, args ...interface{}) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("数据库事务未初始化")
	}
	var id int64
	returningQuery := strings.TrimRight(strings.TrimSpace(query), ";") + " RETURNING id"
	if err := tx.QueryRow(returningQuery, args...).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}
