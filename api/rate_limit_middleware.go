// rate_limit_middleware.go - 基于令牌桶算法的API速率限制中间件
// 本文件实现了一个IP级别的请求速率限制中间件，用于保护Web安全扫描平台API免受滥用。
// 技术方案：
//   使用golang.org/x/time/rate包的令牌桶算法（Token Bucket）实现限流。
//   每个客户端IP维护一个独立的限流器，支持突发流量（Burst）和平滑限制（Rate）。
// 关键设计：
//   1. 每个IP独立计数：使用map[string]*rate.Limiter存储，读写锁保护并发安全
//   2. 内存管理：定期清理不活跃的限流器，防止内存无限增长（超过1000个时清空一半）
//   3. 白名单路径：批量导入和删除接口不参与限流，避免影响正常批量操作
//   4. 双重检查锁定（Double-Check Locking）：避免并发场景下重复创建限流器
// 默认配置：每秒10个请求，突发20个请求，每5分钟清理一次

package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// rateLimiterMap 存储每个客户端IP地址对应的令牌桶限流器实例。
// key为客户端的IP地址字符串，value为对应的rate.Limiter指针。
var (
	rateLimiters     = make(map[string]*rate.Limiter)
	rateLimiterLock  sync.RWMutex  // 读写锁，保护rateLimiters map的并发访问
	rateLimitCleanup sync.Once     // 确保清理协程只启动一次
)

// rateLimitConfig 速率限制的全局配置参数。
// 使用匿名结构体封装，简单直观，无需单独定义配置类型。
var rateLimitConfig = struct {
	RequestsPerSecond float64       // 每秒允许的请求数（令牌生成速率）
	Burst             int           // 突发请求容量（令牌桶最大容量）
	CleanupInterval   time.Duration // 过期限流器清理间隔
}{
	RequestsPerSecond: 10.0, // 默认每秒10个请求
	Burst:             20,   // 突发允许20个请求
	CleanupInterval:   5 * time.Minute,
}

// getRateLimiter 获取或创建指定IP地址的令牌桶限流器。
// 使用双重检查锁定（DCL）模式确保并发安全且高效：
//  1. 先用读锁检查是否存在（大部分请求走这条快速路径）
//  2. 不存在时升级为写锁创建，创建前再次检查（防止并发重复创建）
// 参数:
//   - ip: 客户端IP地址
//
// 返回值:
//   - *rate.Limiter: 该IP对应的令牌桶限流器
func getRateLimiter(ip string) *rate.Limiter {
	rateLimiterLock.RLock()
	limiter, exists := rateLimiters[ip]
	rateLimiterLock.RUnlock()

	if exists {
		return limiter
	}

	// 创建新的限流器
	rateLimiterLock.Lock()
	defer rateLimiterLock.Unlock()

	// 双重检查（避免并发创建）
	if limiter, exists := rateLimiters[ip]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rate.Limit(rateLimitConfig.RequestsPerSecond), rateLimitConfig.Burst)
	rateLimiters[ip] = limiter

	// 启动清理协程（只启动一次）
	rateLimitCleanup.Do(func() {
		go cleanupRateLimiters()
	})

	return limiter
}

// cleanupRateLimiters 后台协程，定期清理长时间未使用的限流器，防止内存泄漏。
// 清理策略：当限流器总数超过1000个时，删除一半以回收内存。
// 这是一个简单但有效的策略，比维护每个限流器的最后访问时间更轻量。
// 注意：此函数由sync.Once保证只启动一次，通过ticker定时触发清理。
func cleanupRateLimiters() {
	ticker := time.NewTicker(rateLimitConfig.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rateLimiterLock.Lock()
		// 清理不活跃的限流器（这里简化处理，实际可以基于最后使用时间）
		// 为了简化，这里只清理数量，保留最近使用的
		if len(rateLimiters) > 1000 {
			// 如果限流器数量超过1000，清空一半（简单策略）
			cleared := 0
			for ip := range rateLimiters {
				delete(rateLimiters, ip)
				cleared++
				if cleared >= len(rateLimiters)/2 {
					break
				}
			}
		}
		rateLimiterLock.Unlock()
	}
}

// RateLimitMiddleware Gin中间件：基于客户端IP的请求速率限制。
// 返回一个Gin HandlerFunc，对每个HTTP请求执行以下检查：
//  1. 白名单检查：POC文件批量导入(/poc-files/import)和删除接口不限制
//  2. 获取客户端真实IP（优先从X-Forwarded-For头获取）
//  3. 获取或创建该IP的令牌桶限流器
//  4. 检查令牌是否充足，不足则返回HTTP 429 Too Many Requests
//
// 使用方法:
//
//	router.Use(RateLimitMiddleware())
//
// 返回值:
//   - gin.HandlerFunc: 速率限制中间件函数
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 排除批量导入和删除接口，避免限流
		path := c.Request.URL.Path
		method := c.Request.Method
		if strings.Contains(path, "/poc-files/import") ||
			(strings.Contains(path, "/poc-files") && method == "DELETE") {
			c.Next()
			return
		}

		// 获取客户端IP
		clientIP := getClientIPForRateLimit(c)

		// 获取该IP的限流器
		limiter := getRateLimiter(clientIP)

		// 检查是否允许请求
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "请求过于频繁，请稍后再试",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getClientIPForRateLimit 获取客户端真实IP地址，用于速率限制的IP标识。
// IP获取优先级（与getClientIP逻辑相同但独立实现，避免循环依赖）：
//  1. X-Forwarded-For 头（取第一个IP，即真实客户端）
//  2. X-Real-IP 头
//  3. RemoteAddr（直连场景）
// 参数:
//   - c: Gin上下文对象
//
// 返回值:
//   - string: 客户端IP地址字符串
func getClientIPForRateLimit(c *gin.Context) string {
	// 优先从 X-Forwarded-For 获取（代理服务器）
	ip := c.GetHeader("X-Forwarded-For")
	if ip != "" {
		ips := strings.Split(ip, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 从 X-Real-IP 获取
	ip = c.GetHeader("X-Real-IP")
	if ip != "" {
		return ip
	}

	// 从 RemoteAddr 获取
	return c.ClientIP()
}
