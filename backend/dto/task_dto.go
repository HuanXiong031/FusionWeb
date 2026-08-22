// backend/dto/task_dto.go
// 任务模块请求/响应 DTO
package dto

// ============================================================
// 扫描任务请求
// ============================================================

// CreateTaskRequest 创建扫描任务请求
type CreateTaskRequest struct {
	TaskName    string   `json:"task_name" binding:"required"`
	Targets     []string `json:"targets" binding:"required,min=1"`
	Ports       string   `json:"ports"`
	ThreadCount int      `json:"thread_count"`
	RateLimit   int      `json:"rate_limit"`
	HTTPProxy   string   `json:"http_proxy"`
	TaskType    string   `json:"task_type"`
}

// RestartTaskRequest 重启任务请求
type RestartTaskRequest struct {
	TaskID string `json:"task_id" binding:"required"`
}

// ============================================================
// POC 任务请求
// ============================================================

// CreatePocTaskRequest 创建 POC 扫描任务请求
type CreatePocTaskRequest struct {
	TaskName     string   `json:"task_name"`
	Targets      []string `json:"targets" binding:"required,min=1"`
	SelectedPocs []string `json:"selectedPocs" binding:"required,min=1"`
	ThreadCount  int      `json:"thread_count"`
	HTTPProxy    string   `json:"http_proxy"`
	RateLimit    int      `json:"rate_limit"`
}

// ============================================================
// 漏洞验证请求
// ============================================================

// VulnVerifyListRequest 漏洞验证列表请求
type VulnVerifyListRequest struct {
	PageRequest
}

// UpdateVulnVerifyRequest 更新漏洞验证请求
type UpdateVulnVerifyRequest struct {
	ID          int                    `json:"id" binding:"required"`
	Data        map[string]interface{} `json:"data" binding:"required"`
}

// VulnVerifyGroupRequest 漏洞验证分组请求
type VulnVerifyGroupRequest struct {
	ID   int    `json:"id"`
	Name string `json:"name" binding:"required"`
}

// ============================================================
// 通用 ID 请求
// ============================================================

// IDRequest 通用 ID 路径参数请求
type IDRequest struct {
	ID int `uri:"id" binding:"required,min=1"`
}

// TaskIDRequest 通用任务 ID 路径参数请求
type TaskIDRequest struct {
	TaskID string `uri:"id" binding:"required"`
}

// ============================================================
// 任务日志查询请求
// ============================================================

// TaskLogsRequest 任务日志查询请求
type TaskLogsRequest struct {
	TaskID  string `json:"taskId" form:"taskId" uri:"id"`
	Level   string `json:"level" form:"level"`
	Keyword string `json:"keyword" form:"keyword"`
	PageRequest
}
