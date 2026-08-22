// handlers_extended.go - 扩展功能模块HTTP接口处理层
// 本文件是Web安全扫描平台最核心的API handler集合，覆盖了除认证和用户管理外的所有功能模块。
// 包含以下功能域：
//   1. POC文件管理：漏洞检测模板的CRUD、导入导出、搜索、统计
//   2. 指纹管理：Web指纹库的增删改查、导入导出、黑名单/启用切换
//   3. POC任务管理：扫描任务的创建、执行、暂停、恢复、停止、删除
//   4. 扫描结果管理：漏洞扫描结果的查询、详情、统计、删除
//   5. 报告导出：HTML/Excel/Markdown三种格式的扫描报告生成
//   6. 手动漏洞验证：手动渗透测试发现的漏洞记录管理和分组
//   7. 工具方法：原始HTTP请求发送等调试工具
//
// 架构设计模式：
//   - 每个Handler函数接收app interface{}参数，通过类型断言获取ExtendedAppInterface
//   - 使用闭包模式创建gin.HandlerFunc（即工厂方法模式），实现依赖注入
//   - 统一的认证检查：通过getUserInfoFromContext或c.Get("userId")获取当前用户
//   - 单用户可信模型：createdByFilter 只作为显式查询条件保留
//

package api

import (
	"FusionWeb/backend/logger"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AppMiddleware 将 App 实例注入到 Gin Context 中，供所有 handler 使用
func AppMiddleware(app *App) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("app", app)
		c.Next()
	}
}

// MustGetApp 从 Context 中获取 App 实例，不存在则 panic
func MustGetApp(c *gin.Context) *App {
	app, exists := c.Get("app")
	if !exists {
		panic("App not found in context - ensure AppMiddleware is registered")
	}
	return app.(*App)
}

// ExtendedAppInterface 定义Web安全扫描平台API层所需的全部服务层方法签名。
// 此接口是App结构体需要实现的方法集合，涵盖POC管理、指纹管理、任务管理、
// 扫描结果、报告导出、手动漏洞验证和工具方法七大功能域。
// 设计要点：
//   - 接口隔离原则：将方法按功能域分组注释，便于维护和理解
//   - 编译时类型安全：App结构体必须实现此接口的所有方法才能编译通过
//   - 依赖倒置：Handler层只依赖接口而非具体实现，便于单元测试时Mock
//
// ExtendedAppInterface is the composite of all domain interfaces.
// It exists for backward compatibility. New code should use the specific domain interfaces.
type ExtendedAppInterface interface {
	AppInterface
	PocAppInterface
	FingerprintAppInterface
	PocTaskAppInterface
	VulnVerifyAppInterface
}

// getAppInstance 从interface{}参数安全地获取ExtendedAppInterface实例。
// 这是所有扩展handler的入口保护函数，确保App实例实现了所需的方法。
// 如果类型断言失败（App实例不满足接口），会：
//   1. 记录详细的类型信息到日志（便于排查App结构体是否遗漏了方法实现）
//   2. 返回HTTP 500错误给客户端（附带实际类型信息）
//   3. 返回nil, false让调用方跳过后续业务逻辑
// 参数:
//   - c: Gin上下文对象（用于错误响应）
//   - app: App结构体实例（以interface{}传递，支持不同类型）
//
// 返回值:
//   - ExtendedAppInterface: 类型断言成功后的接口实例
//   - bool: true表示断言成功，false表示失败（已自动写入错误响应）

func getAppInstance(c *gin.Context, app interface{}) (ExtendedAppInterface, bool) {
	if app == nil {
		logger.Error("App instance is nil in getAppInstance")
		InternalServerErrorResponse(c, "App instance is nil", nil)
		return nil, false
	}

	// 尝试类型断言到 ExtendedAppInterface
	a, ok := app.(ExtendedAppInterface)
	if !ok {
		// 如果类型断言失败，记录详细信息
		appType := fmt.Sprintf("%T", app)
		logger.Error("类型断言失败: app type=%s, 期望类型=ExtendedAppInterface", appType)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":    "Invalid app type: type conversion failed",
			"app_type": appType,
			"expected": "ExtendedAppInterface",
		})
		return nil, false
	}
	return a, true
}
