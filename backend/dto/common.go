// backend/dto/common.go
// 统一请求/响应 DTO（Data Transfer Object）
// 为所有 API 端点提供标准化的请求绑定和响应结构
package dto

// ============================================================
// 通用响应结构
// ============================================================

// APIResponse 统一 API 响应格式
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PageResponse 分页响应
type PageResponse struct {
	Total    int         `json:"total"`
	Page     int         `json:"page"`
	PageSize int         `json:"pageSize"`
	Items    interface{} `json:"items"`
}

// SuccessResponse 成功响应快捷方法
func SuccessResponse(data interface{}) APIResponse {
	return APIResponse{Code: 0, Message: "success", Data: data}
}

// ErrorResponse 错误响应快捷方法
func ErrorResponse(code int, message string) APIResponse {
	return APIResponse{Code: code, Message: message}
}

// ============================================================
// 分页查询请求
// ============================================================

// PageRequest 通用分页请求参数
type PageRequest struct {
	Page     int    `json:"page" form:"page" binding:"omitempty,min=1"`
	PageSize int    `json:"pageSize" form:"pageSize" binding:"omitempty,min=1,max=500"`
	Keyword  string `json:"keyword" form:"keyword"`
	Category string `json:"category" form:"category"`
	SortBy   string `json:"sortBy" form:"sortBy"`
	SortOrder string `json:"sortOrder" form:"sortOrder"`
}

// Normalize 标准化分页参数默认值
func (p *PageRequest) Normalize() {
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 {
		p.PageSize = 20
	}
	if p.PageSize > 500 {
		p.PageSize = 500
	}
}
