// context_utils.go - Gin上下文工具函数
// 本文件提供统一的Gin Context数据提取工具，包括用户身份、角色等信息的获取。
// 设计目标：将上下文访问逻辑集中管理，避免在各handler中重复编写相同的类型断言和nil检查代码。
// 所有鉴权中间件在请求处理前将用户信息注入到Context中（key为"userId"和"role"），
// 后续handler通过本文件提供的函数安全地提取这些信息。

package api

import (
	"github.com/gin-gonic/gin"
)

// GetUserIDFromContext 从Gin上下文中安全地提取已认证用户的ID。
// 此函数封装了类型断言和nil检查逻辑。
// 参数:
//   - c: Gin上下文对象，必须包含由鉴权中间件注入的"userId"键
//
// 返回值:
//   - *int: 用户ID的指针，如果用户未认证或类型不匹配则返回nil
//   - bool: 是否成功获取用户ID
func GetUserIDFromContext(c *gin.Context) (*int, bool) {
	userID, exists := c.Get("userId")
	if !exists {
		// 兼容历史代码中曾使用的"userID"键。
		userID, exists = c.Get("userID")
	}
	if !exists {
		return nil, false
	}

	var uid int
	switch value := userID.(type) {
	case int:
		uid = value
	case int64:
		uid = int(value)
	case uint:
		uid = int(value)
	case uint64:
		uid = int(value)
	default:
		return nil, false
	}

	return &uid, true
}

// GetUserIDPtrFromContext 便捷方法：直接从上下文获取用户ID指针。
// 封装了GetUserIDFromContext的调用，只返回指针，忽略bool标志。
// 适用于只需用户ID指针而不关心是否存在错误场景的代码。
// 参数:
//   - c: Gin上下文对象
//
// 返回值:
//   - *int: 用户ID指针，未认证时返回nil
func GetUserIDPtrFromContext(c *gin.Context) *int {
	userID, exists := GetUserIDFromContext(c)
	if !exists {
		return nil
	}
	return userID
}

// GetRoleFromContext 从Gin上下文中安全地提取已认证用户的角色名称。
// 角色值由鉴权中间件在请求处理前注入到Context中（key为"role"）。
// 参数:
//   - c: Gin上下文对象
//
// 返回值:
//   - string: 角色名称（如 "admin"、"user"），获取失败返回空字符串
//   - bool: 是否成功获取角色信息
func GetRoleFromContext(c *gin.Context) (string, bool) {
	role, exists := c.Get("role")
	if !exists {
		return "", false
	}

	roleStr, ok := role.(string)
	if !ok {
		return "", false
	}

	return roleStr, true
}

// GetRoleFromContextOrDefault 从上下文获取用户角色，获取失败时返回指定的默认值。
// 适用于角色不是必须的场景（如只需区分管理员和非管理员的展示逻辑）。
// 参数:
//   - c: Gin上下文对象
//   - defaultValue: 当角色信息不存在时返回的默认值
//
// 返回值:
//   - string: 角色名称或默认值
func GetRoleFromContextOrDefault(c *gin.Context, defaultValue string) string {
	role, exists := GetRoleFromContext(c)
	if !exists {
		return defaultValue
	}
	return role
}

// RequireAuth 检查当前请求是否来自已认证用户。
// 通过检查Context中是否存在有效的userID来判断认证状态。
// 通常用于handler内部的权限判断，而非中间件层面的拦截。
// 参数:
//   - c: Gin上下文对象
//
// 返回值:
//   - bool: true表示用户已认证，false表示未认证
func RequireAuth(c *gin.Context) bool {
	_, exists := GetUserIDFromContext(c)
	return exists
}

// RequireRole 检查当前请求的用户是否具有指定角色中的任意一个。
// 支持传入多个角色（可变参数），只要用户的角色匹配其中任意一个即返回true。
// 这提供了灵活的多角色访问控制能力。
// 参数:
//   - c: Gin上下文对象
//   - requiredRoles: 可变参数，允许的角色列表
//
// 返回值:
//   - bool: true表示用户具有所需角色之一，false表示权限不足或未认证
func RequireRole(c *gin.Context, requiredRoles ...string) bool {
	role, exists := GetRoleFromContext(c)
	if !exists {
		return false
	}

	for _, requiredRole := range requiredRoles {
		if role == requiredRole {
			return true
		}
	}

	return false
}
