// backend/repository/task_repo.go
// 扫描任务 Repository
package repository

import (
	"FusionWeb/backend/utils"
	"fmt"
)

// TaskRepository 扫描任务数据访问层
type TaskRepository struct {
	*BaseRepository
}

// NewTaskRepository 创建任务 Repository
func NewTaskRepository() *TaskRepository {
	return &TaskRepository{BaseRepository: NewBaseRepository("task_config")}
}

// FindByUserID 按用户 ID 查询任务列表
func (r *TaskRepository) FindByUserID(userID uint) ([]map[string]interface{}, error) {
	return r.FindAll("user_id = $1 ORDER BY created_at DESC", userID)
}

// FindAllTasks 查询所有任务（带可选创建者过滤）
func (r *TaskRepository) FindAllTasks(createdByFilter *int) ([]map[string]interface{}, error) {
	if createdByFilter != nil {
		return r.FindAll("user_id = $1 ORDER BY created_at DESC", *createdByFilter)
	}
	return r.FindAll("1=1 ORDER BY created_at DESC")
}

// FindByTaskID 按任务 ID 查询
func (r *TaskRepository) FindByTaskID(taskID string) (map[string]interface{}, error) {
	results, err := r.FindAll("task_id = $1", taskID)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("任务不存在: %s", taskID)
	}
	return results[0], nil
}

// DeleteByTaskID 按任务 ID 删除
func (r *TaskRepository) DeleteByTaskID(taskID string) error {
	result, err := r.Exec("DELETE FROM task_config WHERE task_id = $1", taskID)
	if err != nil {
		return fmt.Errorf("删除任务失败: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("任务不存在: %s", taskID)
	}
	return nil
}

// UpdateStatus 更新任务状态
func (r *TaskRepository) UpdateStatus(taskID string, status string) error {
	_, err := r.Exec("UPDATE task_config SET status = $1, updated_at = $2 WHERE task_id = $3",
		status, utils.GetCurrentTimeString(), taskID)
	return err
}

// ============================================================
// VulnResults 辅助方法
// ============================================================

// VulnResultsRepo 漏洞结果 Repository
type VulnResultsRepo struct {
	*BaseRepository
}

// NewVulnResultsRepo 创建漏洞结果 Repository
func NewVulnResultsRepo() *VulnResultsRepo {
	return &VulnResultsRepo{BaseRepository: NewBaseRepository("vuln_results")}
}

// FindByTaskID 按任务 ID 查询漏洞结果
func (r *VulnResultsRepo) FindByTaskID(taskID string) ([]map[string]interface{}, error) {
	return r.FindAll("task_id = $1", taskID)
}
