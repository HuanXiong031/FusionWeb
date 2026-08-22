// backend/utils/transaction_utils.go
// 数据库事务工具模块
// 提供安全的事务封装，自动处理提交/回滚和 panic 恢复。
//
// 设计要点：
// - WithTransaction: 高阶函数模式，接收业务逻辑闭包，自动管理事务边界
// - Panic 安全：defer + recover 确保即使业务逻辑 panic，事务也能正确回滚
// - SafeRollback/SafeCommit: 忽略已结束事务的错误（sql.ErrTxDone）
//
// 使用模式：
//
//	err := WithTransaction(func(tx *sql.Tx) error {
//	    _, err := tx.Exec("INSERT INTO ...")
//	    return err  // 返回 nil 则提交，返回 error 则回滚
//	})
package utils

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"database/sql"
	"fmt"
)

// WithTransaction 在事务中执行业务函数
// 参数：fn - 接收 *sql.Tx 并返回 error 的业务函数
// 返回值：业务函数返回的错误或事务操作本身的错误
//
// 自动行为：
// - fn 返回 nil → 提交事务
// - fn 返回 error → 回滚事务
// - fn 中发生 panic → 回滚事务后重新抛出 panic（保证上层能捕获）
func WithTransaction(fn func(*sql.Tx) error) error {
	tx, err := database.DB.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %w", err)
	}

	// 确保在出错时回滚事务
	defer func() {
		if p := recover(); p != nil {
			// 发生panic，回滚事务
			if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
				logger.Error("回滚事务失败（panic恢复）: %v", rollbackErr)
			}
			panic(p) // 重新抛出panic
		} else if err != nil {
			// 发生错误，回滚事务
			if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
				logger.Error("回滚事务失败: %v", rollbackErr)
			}
		} else {
			// 成功，提交事务
			if commitErr := tx.Commit(); commitErr != nil {
				logger.Error("提交事务失败: %v", commitErr)
				err = fmt.Errorf("提交事务失败: %w", commitErr)
			}
		}
	}()

	// 执行函数
	err = fn(tx)
	return err
}

// SafeRollback 安全回滚事务
// 参数：tx - 事务对象
// 返回值：回滚错误（忽略 sql.ErrTxDone，即事务已结束的情况）
// 使用场景：defer 中安全回滚，不因事务已完成而 panic
func SafeRollback(tx *sql.Tx) error {
	if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
		return err
	}
	return nil
}

// SafeCommit 安全提交事务
// 参数：tx - 事务对象
// 返回值：提交操作的错误信息
// 相比直接调用 tx.Commit()，增加了错误包装信息
func SafeCommit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	return nil
}
