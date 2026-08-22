// backend/repository/poc_repo.go
// POC 扫描相关 Repository
package repository

import (
	"fmt"
)

// PocScanTasksRepo POC 扫描任务 Repository
type PocScanTasksRepo struct {
	*BaseRepository
}

// NewPocScanTasksRepo 创建 POC 扫描任务 Repository
func NewPocScanTasksRepo() *PocScanTasksRepo {
	return &PocScanTasksRepo{BaseRepository: NewBaseRepository("poc_scan_tasks")}
}

// FindByTaskID 按任务 ID 查询
func (r *PocScanTasksRepo) FindByTaskID(taskID string) (map[string]interface{}, error) {
	results, err := r.FindAll("task_id = $1", taskID)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("POC扫描任务不存在: %s", taskID)
	}
	return results[0], nil
}

// FindAllTasks 查询所有 POC 扫描任务
func (r *PocScanTasksRepo) FindAllTasks(createdByFilter *int) ([]map[string]interface{}, error) {
	if createdByFilter != nil {
		return r.FindAll("user_id = $1 ORDER BY created_at DESC", *createdByFilter)
	}
	return r.FindAll("1=1 ORDER BY created_at DESC")
}

// DeleteByTaskID 按任务 ID 删除
func (r *PocScanTasksRepo) DeleteByTaskID(taskID string) error {
	_, err := r.Exec("DELETE FROM poc_scan_tasks WHERE task_id = $1", taskID)
	return err
}

// ============================================================
// PocScanResultsRepo POC 扫描结果 Repository
// ============================================================

// PocScanResultsRepo POC 扫描结果 Repository
type PocScanResultsRepo struct {
	*BaseRepository
}

// NewPocScanResultsRepo 创建 POC 扫描结果 Repository
func NewPocScanResultsRepo() *PocScanResultsRepo {
	return &PocScanResultsRepo{BaseRepository: NewBaseRepository("poc_scan_results")}
}

// FindByTaskID 按任务 ID 查询结果
func (r *PocScanResultsRepo) FindByTaskID(taskID string) ([]map[string]interface{}, error) {
	return r.FindAll("task_id = $1", taskID)
}

// DeleteByTaskID 按任务 ID 删除所有结果
func (r *PocScanResultsRepo) DeleteByTaskID(taskID string) error {
	_, err := r.Exec("DELETE FROM poc_scan_results WHERE task_id = $1", taskID)
	return err
}
