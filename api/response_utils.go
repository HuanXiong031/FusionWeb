// response_utils.go - 统一HTTP响应格式工具
// 本文件定义Web安全扫描平台的标准API响应结构和快捷响应函数。
// 设计目标：
//   1. 统一所有API接口的响应格式（code + message + data/error），便于前端统一处理
//   2. 提供按HTTP状态码分类的快捷函数（Success/Error/BadRequest/InternalError等）
//   3. 减少handler中重复的JSON序列化代码
// 响应码约定：
//   - code=0: 操作成功
//   - code=1: 操作失败（具体错误信息见message/error字段）

package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ResponseData 统一API响应数据结构。
// 所有API接口的HTTP响应体都使用此结构序列化为JSON。
// 字段说明:
//   - Code: 业务状态码，0表示成功，1表示失败
//   - Message: 面向用户的提示信息
//   - Data: 成功时的业务数据载荷（可选）
//   - Error: 失败时的详细错误信息（仅用于调试，不建议直接展示给用户）
type ResponseData struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// SuccessResponse 发送HTTP 200成功响应，包含业务数据。
// 参数:
//   - c: Gin上下文对象
//   - data: 响应数据载荷，可以是任意可序列化为JSON的类型
func SuccessResponse(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, ResponseData{
		Code: 0,
		Data: data,
	})
}

// SuccessResponseWithMessage 发送HTTP 200成功响应，同时包含提示消息和业务数据。
// 适用于需要给用户明确反馈的操作（如"创建成功"、"更新成功"）。
// 参数:
//   - c: Gin上下文对象
//   - message: 成功提示消息
//   - data: 响应数据载荷
func SuccessResponseWithMessage(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, ResponseData{
		Code:    0,
		Message: message,
		Data:    data,
	})
}

// ErrorResponse 发送通用错误响应，支持自定义HTTP状态码。
// 当err不为nil时，会将错误详情附带在Error字段中。
// 参数:
//   - c: Gin上下文对象
//   - statusCode: HTTP状态码（如400、403、500等）
//   - message: 面向用户的错误描述
//   - err: 原始错误对象，其Error()输出会包含在响应的error字段中
func ErrorResponse(c *gin.Context, statusCode int, message string, err error) {
	response := ResponseData{
		Code:    1,
		Message: message,
	}
	if err != nil {
		response.Error = err.Error()
	}
	c.JSON(statusCode, response)
}

// BadRequestResponse 发送HTTP 400 Bad Request错误响应。
// 用于客户端请求参数错误、格式不正确等场景。
// 参数:
//   - c: Gin上下文对象
//   - message: 错误描述信息（如"参数格式不正确"）
//   - err: 原始错误对象
func BadRequestResponse(c *gin.Context, message string, err error) {
	ErrorResponse(c, http.StatusBadRequest, message, err)
}

// InternalServerErrorResponse 发送HTTP 500 Internal Server Error错误响应。
// 用于服务器内部执行失败、数据库错误等不可预期的运行时错误。
// 参数:
//   - c: Gin上下文对象
//   - message: 错误描述信息
//   - err: 原始错误对象，其详细信息会包含在响应的error字段中
func InternalServerErrorResponse(c *gin.Context, message string, err error) {
	ErrorResponse(c, http.StatusInternalServerError, message, err)
}

// ForbiddenResponse 发送HTTP 403 Forbidden错误响应。
// 用于用户已认证但当前操作不允许的场景。
// 参数:
//   - c: Gin上下文对象
//   - message: 错误描述信息（如"权限不足"）
func ForbiddenResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusForbidden, message, nil)
}

// UnauthorizedResponse 发送HTTP 401 Unauthorized错误响应。
// 用于用户未认证或token无效的场景。
// 参数:
//   - c: Gin上下文对象
//   - message: 错误描述信息（如"请先登录"）
func UnauthorizedResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, message, nil)
}

// PaginatedResponse 发送分页数据的成功响应。
// 将分页相关的元数据（list、total、page、pageSize）封装为统一格式。
// 参数:
//   - c: Gin上下文对象
//   - list: 当前页的数据列表
//   - total: 满足条件的总记录数
//   - page: 当前页码
//   - pageSize: 每页条数
func PaginatedResponse(c *gin.Context, list interface{}, total, page, pageSize int) {
	SuccessResponse(c, gin.H{
		"list":     list,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}
