// param_utils.go - HTTP参数解析工具函数
// 本文件提供从Gin Context中安全提取HTTP请求参数的统一工具函数。
// 设计目标：
//   1. 消除各handler中重复的手动参数解析和类型转换代码
//   2. 统一错误处理逻辑，当参数缺失或格式错误时返回明确的错误信息
//   3. 支持路径参数（URL Path Param）和查询参数（Query String）两种参数来源
// 所有函数都进行了安全的类型转换，无效值会返回合理的默认值而非panic。

package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetIntParam 从URL路径参数中提取整数值（如 /api/user/:id 中的id）。
// 当参数为空字符串或无法解析为整数时，返回带参数名的描述性错误。
// 参数:
//   - c: Gin上下文对象
//   - paramName: 路径参数的名称
//
// 返回值:
//   - int: 解析后的整数值，解析失败返回0
//   - error: 参数缺失或格式无效时的错误信息
func GetIntParam(c *gin.Context, paramName string) (int, error) {
	param := c.Param(paramName)
	if param == "" {
		return 0, fmt.Errorf("参数 %s 不能为空", paramName)
	}
	value, err := strconv.Atoi(param)
	if err != nil {
		return 0, fmt.Errorf("参数 %s 无效: %w", paramName, err)
	}
	return value, nil
}

// GetIntQuery 从URL查询参数中提取整数值，解析失败时返回指定的默认值。
// 适用于可选参数场景（如分页参数 page、pageSize），调用者无需处理错误。
// 参数:
//   - c: Gin上下文对象
//   - queryName: 查询参数名称
//   - defaultValue: 参数缺失或格式无效时使用的默认值
//
// 返回值:
//   - int: 解析后的整数值或默认值
func GetIntQuery(c *gin.Context, queryName string, defaultValue int) int {
	valueStr := c.DefaultQuery(queryName, strconv.Itoa(defaultValue))
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// GetInt64Param 从URL路径参数中提取int64类型的值。
// 适用于需要64位整数的场景（如数据库自增ID可能超过int32范围）。
// 参数:
//   - c: Gin上下文对象
//   - paramName: 路径参数名称
//
// 返回值:
//   - int64: 解析后的int64值
//   - error: 参数缺失或格式无效时的错误信息
func GetInt64Param(c *gin.Context, paramName string) (int64, error) {
	param := c.Param(paramName)
	if param == "" {
		return 0, fmt.Errorf("参数 %s 不能为空", paramName)
	}
	value, err := strconv.ParseInt(param, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("参数 %s 无效: %w", paramName, err)
	}
	return value, nil
}

// GetInt64Query 从URL查询参数中提取int64值，解析失败时返回默认值。
// 可选参数场景的64位版本，如处理大数值的时间戳或ID。
// 参数:
//   - c: Gin上下文对象
//   - queryName: 查询参数名称
//   - defaultValue: 参数缺失或无效时使用的默认值
//
// 返回值:
//   - int64: 解析后的int64值或默认值
func GetInt64Query(c *gin.Context, queryName string, defaultValue int64) int64 {
	valueStr := c.DefaultQuery(queryName, strconv.FormatInt(defaultValue, 10))
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return defaultValue
	}
	return value
}

// GetStringQuery 从URL查询参数中提取字符串值，参数为空时返回默认值。
// 用于可选文本参数（如过滤关键词keyword、分类category等）。
// 参数:
//   - c: Gin上下文对象
//   - queryName: 查询参数名称
//   - defaultValue: 参数为空时使用的默认值
//
// 返回值:
//   - string: 查询参数值或默认值
func GetStringQuery(c *gin.Context, queryName string, defaultValue string) string {
	value := c.Query(queryName)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetBoolQuery 从URL查询参数中提取布尔值，解析失败时返回默认值。
// 支持 "true"/"false"、"1"/"0" 等标准布尔字符串表示。
// 参数:
//   - c: Gin上下文对象
//   - queryName: 查询参数名称
//   - defaultValue: 参数缺失或无效时使用的默认值
//
// 返回值:
//   - bool: 解析后的布尔值或默认值
func GetBoolQuery(c *gin.Context, queryName string, defaultValue bool) bool {
	valueStr := c.DefaultQuery(queryName, strconv.FormatBool(defaultValue))
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// ValidatePaginationParams 统一验证并提取分页参数（page和pageSize）。
// 自动处理page<1和pageSize<1的非法输入，并将pageSize限制在maxPageSize以内。
// 该函数被所有需要分页功能的handler复用，确保分页参数处理的一致性。
// 参数:
//   - c: Gin上下文对象
//   - defaultPageSize: 当pageSize参数未提供时使用的默认每页数量
//   - maxPageSize: 每页数量的上限，超过此值会被截断（防止DoS通过请求超大pageSize）
//
// 返回值:
//   - page: 当前页码（>=1）
//   - pageSize: 每页条数（1到maxPageSize之间）
//   - error: 参数验证失败时返回错误
func ValidatePaginationParams(c *gin.Context, defaultPageSize, maxPageSize int) (int, int, error) {
	page := GetIntQuery(c, "page", 1)
	pageSize := GetIntQuery(c, "pageSize", defaultPageSize)

	if page < 1 {
		return 0, 0, fmt.Errorf("页码必须大于0")
	}
	if pageSize < 1 {
		return 0, 0, fmt.Errorf("每页数量必须大于0")
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	return page, pageSize, nil
}
