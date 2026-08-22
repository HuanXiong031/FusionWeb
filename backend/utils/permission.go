// backend/utils/permission.go
// 单用户可信模型下的身份辅助函数。
// 所有认证请求共享同一管理视角，createdBy 仅作为可选查询条件保留。
package utils

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ============================================================
// 用户信息提取
// ============================================================

// GetUserInfoFromGinContext 从 Gin 上下文获取用户 ID
func GetUserInfoFromGinContext(c *gin.Context) (userID uint, ok bool) {
	val, exists := c.Get("userId")
	if !exists {
		return 0, false
	}
	uid, ok := val.(uint)
	return uid, ok
}

// GetCreatedByFilterFromQuery 根据 createdBy 查询参数构建可选过滤。
func GetCreatedByFilterFromQuery(createdByQuery string, userID *int) *int {
	if createdByQuery != "" {
		if id, err := parseCreatedBy(createdByQuery); err == nil {
			return id
		}
	}
	return nil
}

func parseCreatedBy(s string) (*int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	id := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("not a number")
		}
		id = id*10 + int(c-'0')
	}
	return &id, nil
}

// ============================================================
// 任务归属检查
// ============================================================

// CheckTaskOwnershipForTaskConfigAndRespond 保留给仍需要按 user_id 校验的旧入口。
func CheckTaskOwnershipForTaskConfigAndRespond(c *gin.Context, taskID string, userID uint, errorMessage string) bool {
	ok, err := checkOwnership("task_config", "task_id", "user_id", taskID, userID)
	if err != nil {
		logger.Error("检查任务所有权失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查权限失败"})
		return false
	}
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errorMessage})
		return false
	}
	return true
}

// CheckTaskOwnershipForPocScanTasksAndRespond 保留给仍需要按 user_id 校验的旧入口。
func CheckTaskOwnershipForPocScanTasksAndRespond(c *gin.Context, taskID string, userID uint, errorMessage string) bool {
	ok, err := checkOwnership("poc_scan_tasks", "task_id", "user_id", taskID, userID)
	if err != nil {
		logger.Error("检查POC任务所有权失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查权限失败"})
		return false
	}
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": errorMessage})
		return false
	}
	return true
}

// checkOwnership 通用所有权检查：查询表中记录是否属于指定用户
func checkOwnership(table, idCol, userCol string, recordID string, userID uint) (bool, error) {
	if database.DB == nil {
		return false, fmt.Errorf("数据库未初始化")
	}
	var count int
	err := database.DB.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = $1 AND %s = $2", table, idCol, userCol),
		recordID, userID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
