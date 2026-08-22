// api/router.go
package api

import (
	"FusionWeb/backend/config"
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"strings"
	"time"
)

var jwtKey []byte

// GetJWTKeyBase64 获取JWT签名密钥的Base64编码（用于日志输出）
func GetJWTKeyBase64() string {
	if len(jwtKey) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(jwtKey)
}

// initJWTKey 初始化JWT签名密钥。
// FUSIONWEB_JWT_SECRET 非空时使用固定密钥；留空时每次启动生成随机密钥。
func initJWTKey() {
	cfg := config.Get()
	if strings.TrimSpace(cfg.JWTSecret) != "" {
		jwtKey = []byte(cfg.JWTSecret)
		logger.InfoToFileOnly("JWT签名密钥已使用 FUSIONWEB_JWT_SECRET")
		return
	}

	// 每次启动自动生成32字节随机密钥
	// 注意：这意味着每次重启后，所有已登录用户的token都会失效，需要重新登录
	logger.InfoToFileOnly("正在生成新的JWT签名密钥...")
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		logger.Error("生成JWT签名密钥失败: %v", err)
		logger.Error("无法生成JWT签名密钥，程序无法启动。请检查系统随机数生成器")
		panic("JWT签名密钥生成失败，程序无法启动")
	}
	jwtKey = newKey
	keyBase64 := base64.StdEncoding.EncodeToString(jwtKey)
	logger.InfoToFileOnly("JWT签名密钥已自动生成（Base64编码）: %s", keyBase64)
	logger.InfoToFileOnly("注意：每次启动都会生成新的签名密钥，已登录用户需要重新登录")

	// 注意：加密密钥现在是完全独立的，不会从签名密钥派生
}

func init() {
	initJWTKey()
	// 注意：加密密钥现在完全独立，不再从签名密钥派生

	// 注册获取签名密钥的回调函数，以便在加密密钥初始化时输出签名密钥信息
	utils.SetGetJWTSignKeyFunc(GetJWTKeyBase64)
}

// Claims JWT Claims 结构体
// 注意：UserID、Username、Role 存储的是加密后的值（Base64 URL编码）
type Claims struct {
	UserID   string `json:"userId"`   // 加密后的用户ID（uint转string后加密）
	Username string `json:"username"` // 加密后的用户名
	Role     string `json:"role"`     // 加密后的角色
	jwt.RegisteredClaims
}

// NewRouter 创建并返回一个配置了所有 API 路由的 Gin 引擎

func abortUnauthorized(c *gin.Context, reason string) {
	recordUnauthorizedAccessLog(c, reason)
	c.AbortWithStatus(http.StatusUnauthorized)
}

func JWTAuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	var tokenString string

	if authHeader == "" {
		// 尝试从 Query 参数中获取 token (用于 SSE 等无法设置 Header 的场景)
		tokenString = c.Query("token")
		if tokenString == "" {
			// 静默返回401，不显示详细错误信息，由前端统一处理跳转
			abortUnauthorized(c, "缺少 Token")
			return
		}
	} else {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			// 静默返回401，不显示详细错误信息，由前端统一处理跳转
			abortUnauthorized(c, "Authorization 格式错误")
			return
		}
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		// 静默返回401，不显示详细错误信息，由前端统一处理跳转
		abortUnauthorized(c, "Token 无效或已过期")
		return
	}

	// 解密JWT Claims中的敏感信息
	decryptedUserIDStr, err := utils.DecryptJWTField(claims.UserID)
	if err != nil {
		logger.Warn("JWT验证失败：解密UserID失败: %v (UserID字段值长度: %d)", err, len(claims.UserID))
		abortUnauthorized(c, "Token 用户信息解密失败")
		return
	}

	decryptedUsername, err := utils.DecryptJWTField(claims.Username)
	if err != nil {
		logger.Warn("JWT验证失败：解密Username失败: %v (Username字段值长度: %d)", err, len(claims.Username))
		abortUnauthorized(c, "Token 用户名解密失败")
		return
	}

	decryptedRole, err := utils.DecryptJWTField(claims.Role)
	if err != nil {
		logger.Warn("JWT验证失败：解密Role失败: %v (Role字段值长度: %d)", err, len(claims.Role))
		abortUnauthorized(c, "Token 角色解密失败")
		return
	}

	// 将解密后的UserID转换为uint
	var decryptedUserID uint
	if _, err := fmt.Sscanf(decryptedUserIDStr, "%d", &decryptedUserID); err != nil {
		logger.Warn("JWT验证失败：UserID格式错误: %v", err)
		abortUnauthorized(c, "Token 用户 ID 格式错误")
		return
	}

	// 从数据库验证用户信息（用户ID、用户名、角色、状态）
	var dbUserID uint
	var dbUsername, dbRole, dbStatus string
	err = database.DB.QueryRow(
		"SELECT id, username, role, status FROM users WHERE id = ?",
		decryptedUserID,
	).Scan(&dbUserID, &dbUsername, &dbRole, &dbStatus)

	if err != nil {
		// 用户不存在或查询失败，拒绝访问
		if err == sql.ErrNoRows {
			logger.Warn("JWT验证失败：用户ID %d 不存在", decryptedUserID)
		} else {
			logger.Error("JWT验证失败：查询用户信息时出错: %v", err)
		}
		abortUnauthorized(c, "用户不存在或查询失败")
		return
	}

	// 验证用户ID是否匹配
	if dbUserID != decryptedUserID {
		logger.Warn("JWT验证失败：用户ID不匹配 (token: %d, db: %d)", decryptedUserID, dbUserID)
		abortUnauthorized(c, "用户 ID 不匹配")
		return
	}

	// 验证解密后的值不为空（防止攻击者使用空值绕过验证）
	if decryptedUsername == "" {
		logger.Warn("JWT验证失败：解密后的用户名为空 (userID: %d)", decryptedUserID)
		abortUnauthorized(c, "用户名为空")
		return
	}

	if decryptedRole == "" {
		logger.Warn("JWT验证失败：解密后的角色为空 (userID: %d)", decryptedUserID)
		abortUnauthorized(c, "角色为空")
		return
	}

	// 验证用户名是否匹配（防止token被复用或用户名被修改）
	if dbUsername != decryptedUsername {
		logger.Warn("JWT验证失败：用户名不匹配 (token: %s, db: %s, userID: %d)", decryptedUsername, dbUsername, decryptedUserID)
		abortUnauthorized(c, "用户名不匹配")
		return
	}

	// 验证角色是否匹配（防止权限提升攻击）
	if dbRole != decryptedRole {
		logger.Warn("JWT验证失败：角色不匹配 (token: %s, db: %s, userID: %d)", decryptedRole, dbRole, decryptedUserID)
		abortUnauthorized(c, "角色不匹配")
		return
	}

	// 验证JWT的IssuedAt时间（确保token是在最近的有效时间内生成的）
	if claims.IssuedAt != nil {
		issuedAt := claims.IssuedAt.Time
		// 检查token是否是在过去（未来时间无效）
		now := utils.GetCurrentTime()
		if issuedAt.After(now.Add(5 * time.Minute)) {
			logger.Warn("JWT验证失败：token签发时间异常（未来时间）(userID: %d, issuedAt: %v)", decryptedUserID, issuedAt)
			abortUnauthorized(c, "Token 签发时间异常")
			return
		}
		// 检查token是否过期太久（超过24小时+1天的容错时间）
		if time.Since(issuedAt) > 48*time.Hour {
			logger.Warn("JWT验证失败：token签发时间过久 (userID: %d, issuedAt: %v)", decryptedUserID, issuedAt)
			abortUnauthorized(c, "Token 签发时间过久")
			return
		}
	}

	// JWT token 已通过 HMAC 签名验证，无需额外数据库校验

	// 验证用户状态是否为active（被禁用的用户无法使用token）
	if dbStatus != "active" {
		logger.Warn("JWT验证失败：用户状态异常 (userID: %d, username: %s, status: %s)", decryptedUserID, dbUsername, dbStatus)
		abortUnauthorized(c, "用户已禁用或状态异常")
		return
	}

	// 将用户信息存入上下文（使用数据库中的最新信息，而不是token中的）
	c.Set("userId", dbUserID)
	c.Set("username", dbUsername) // 使用数据库中的用户名
	c.Set("role", dbRole)         // 本机单用户工具仍保留数据库角色语义，避免上下文与用户表不一致
	c.Next()
}
