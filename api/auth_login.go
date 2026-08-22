package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

const (
	failedLoginBlacklistThreshold = 5
	failedLoginBlacklistMinutes   = 30
)

func isLocalNetworkIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 检查IPv6本地回环地址
	if ipStr == "::1" {
		return true
	}

	// 只处理IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}

	// 127.0.0.0/8 - 回环地址
	if ipv4[0] == 127 {
		return true
	}

	// 10.0.0.0/8 - 私有网络
	if ipv4[0] == 10 {
		return true
	}

	// 172.16.0.0/12 - 私有网络 (172.16.0.0 - 172.31.255.255)
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}

	// 192.168.0.0/16 - 私有网络
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}

	// 169.254.0.0/16 - 链路本地地址
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return true
	}

	return false
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"` // SM2加密的用户名
	Password string `json:"password" binding:"required"` // SM2加密的密码
}

// getClientIP 从HTTP请求中提取客户端真实IP地址。
// 考虑了代理/负载均衡场景，按以下优先级获取：
//  1. X-Forwarded-For 头（取第一个IP，即真实客户端地址）
//  2. X-Real-IP 头（Nginx等反向代理设置的直接客户端IP）
//  3. RemoteAddr（无代理直连场景）
//
// 参数:
//   - c: Gin上下文对象
//
// 返回值:
//   - string: 客户端IP地址
func getClientIP(c *gin.Context) string {
	// 优先从 X-Forwarded-For 获取（代理服务器）
	ip := c.GetHeader("X-Forwarded-For")
	if ip != "" {
		// X-Forwarded-For 可能包含多个IP，取第一个
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

// recordFailedAttempt 记录登录失败尝试，并在同一 IP 短时间内多次失败时自动加入访问黑名单。
// 参数:
//   - ip: 登录失败的客户端IP地址
func recordFailedAttempt(ip string) {
	if database.DB == nil || strings.TrimSpace(ip) == "" {
		return
	}
	parsedIP := net.ParseIP(strings.TrimSpace(ip))
	if parsedIP == nil {
		logger.Debug("登录失败尝试，IP 无效: %s", ip)
		return
	}
	if parsedIP.IsLoopback() {
		logger.Debug("登录失败尝试，跳过本机地址自动封禁: %s", ip)
		return
	}

	cutoff := utils.GetCurrentTime().Add(-time.Duration(failedLoginBlacklistMinutes) * time.Minute).Format("2006-01-02 15:04:05")
	var failedCount int
	err := database.DB.QueryRow(
		`SELECT COUNT(*)
		   FROM login_logs
		  WHERE ip_address = ?
		    AND login_result = 'failed'
		    AND created_at >= ?`,
		ip, cutoff,
	).Scan(&failedCount)
	if err != nil {
		logger.Warn("统计登录失败次数失败: %v", err)
		return
	}

	failedCount++
	logger.Debug("登录失败尝试，IP: %s，近期失败次数: %d", ip, failedCount)
	if failedCount < failedLoginBlacklistThreshold {
		return
	}

	accessPolicy := service.NewAccessPolicyService()
	source := fmt.Sprintf("密码错误超过 %d 次自动添加", failedLoginBlacklistThreshold)
	if err := accessPolicy.AddToBlacklistWithDurationAndSource("ip", ip, failedLoginBlacklistMinutes, source); err != nil {
		logger.Warn("登录失败自动加入访问黑名单失败: %v", err)
		return
	}
	logger.Warn("登录失败次数达到阈值，已自动加入访问黑名单: IP=%s, 时长=%d分钟", ip, failedLoginBlacklistMinutes)
}

// recordSuccessAttempt 记录登录成功的审计日志。
// 封禁功能已移除，当前仅记录Debug级别日志。
// 参数:
//   - ip: 登录成功的客户端IP地址
func recordSuccessAttempt(ip string) {
	// 封禁功能已移除，不再需要清除失败计数
	logger.Debug("登录成功，IP: %s", ip)
}

// decryptPassword 使用SM2国密算法解密前端传输的加密密码。
// 解密流程：
//  1. 去除密文首尾空格
//  2. 调用utils.DecryptSM2进行SM2私钥解密
//  3. 检查解密结果中是否包含"|||"分隔符（前端可能附加时间戳防重放）
//  4. 如存在分隔符，取分隔符之前的部分作为真实密码
//
// 参数:
//   - encrypted: SM2公钥加密后的密文字符串
//
// 返回值:
//   - string: 解密后的明文密码，解密失败返回空字符串
func decryptPassword(encrypted string) string {
	// 去除首尾空格
	encrypted = strings.TrimSpace(encrypted)

	// 尝试SM2解密
	decryptedStr, err := utils.DecryptSM2(encrypted)
	if err != nil {
		logger.Error("SM2解密密码失败: %v (密文: %s...)", err, encrypted[:min(len(encrypted), 20)])
		return ""
	}

	// 提取密码部分（去掉可能存在的时间戳）
	// 使用 ||| 作为分隔符（三个连续的 |）
	separator := "|||"
	separatorIndex := strings.Index(decryptedStr, separator)
	if separatorIndex >= 0 {
		// 找到分隔符，提取密码部分
		password := strings.TrimSpace(decryptedStr[:separatorIndex])
		return password
	}

	// 如果没有分隔符，说明前端只加密了密码，直接返回
	return decryptedStr
}

// decryptUsername 使用SM2国密算法解密前端传输的加密用户名。
// 解密逻辑与decryptPassword相同，复用SM2解密并处理可能的时间戳分隔符。
// 参数:
//   - encrypted: SM2公钥加密后的密文字符串
//
// 返回值:
//   - string: 解密后的明文用户名，解密失败返回空字符串
func decryptUsername(encrypted string) string {
	// 去除首尾空格
	encrypted = strings.TrimSpace(encrypted)

	// 尝试SM2解密
	decryptedStr, err := utils.DecryptSM2(encrypted)
	if err != nil {
		logger.Error("SM2解密用户名失败: %v (密文: %s...)", err, encrypted[:min(len(encrypted), 20)])
		return ""
	}

	// 提取用户名部分（去掉可能存在的时间戳）
	// 使用 ||| 作为分隔符（三个连续的 |）
	separator := "|||"
	separatorIndex := strings.Index(decryptedStr, separator)
	if separatorIndex >= 0 {
		// 找到分隔符，提取用户名部分
		username := strings.TrimSpace(decryptedStr[:separatorIndex])
		return username
	}

	// 如果没有分隔符，说明前端只加密了用户名，直接返回
	return decryptedStr
}

// HandleGetSM2PublicKey 返回SM2加密算法的公钥给前端。
func insertLoginLog(username, ip, userAgent, result, failureReason, tokenHash string) {
	if database.DB == nil {
		return
	}
	_, err := database.DB.Exec(
		`INSERT INTO login_logs (username, ip_address, user_agent, login_result, failure_reason, token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		username, ip, userAgent, result, failureReason, tokenHash, utils.GetCurrentTimeString(),
	)
	if err != nil {
		logger.Warn("写入登录审计失败: %v", err)
	}
}

// recordLoginLog 记录登录审计信息到数据库。
func recordLoginLog(username, ip, userAgent, result, failureReason string) {
	if result == "success" {
		logger.Info("用户登录成功: %s (IP: %s, UA: %s)", username, ip, userAgent)
	} else {
		logger.Warn("用户登录失败: %s (IP: %s, 原因: %s)", username, ip, failureReason)
	}
	insertLoginLog(username, ip, userAgent, result, failureReason, "")
}

// recordLoginLogWithTokenHash 记录包含token哈希的登录审计信息到数据库。
func recordLoginLogWithTokenHash(username, ip, userAgent, result, failureReason, tokenHash string) {
	logger.Info("用户登录: %s (IP: %s, 结果: %s, TokenHash: %s)", username, ip, result, tokenHash[:16]+"...")
	insertLoginLog(username, ip, userAgent, result, failureReason, tokenHash)
}

// HandleLogin 处理用户登录请求，是整个认证流程的核心入口。
// POST /api/auth/login
// 完整登录流程：
//  1. 解析请求体并验证参数完整性
//  2. SM2解密用户名和密码（前端使用公钥加密传输）
//  3. 验证输入长度和格式
//  4. 查询数据库验证用户是否存在
//  5. bcrypt验证密码哈希
//  6. 检查密码复杂度并设置强制修改标志（must_change_password）
//  7. 检查账户状态（active/disabled）
//  8. 加密JWT Claims中的敏感字段（用户ID、用户名、角色）
//  9. 签发JWT令牌（HS256签名，24小时有效期）
//  10. 计算token的SHA256哈希用于审计追踪
//  11. 记录登录审计日志
//  12. 返回用户信息和JWT令牌
//
// 安全措施：无论用户不存在还是密码错误，都返回相同的"用户名或密码错误"消息，
// 防止攻击者通过错误消息差异枚举有效用户名。
func HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequestResponse(c, "请求参数错误: "+err.Error(), err)
		return
	}

	// 解密用户名（SM2）
	decryptedUsername := decryptUsername(req.Username)

	// 去除解密后用户名的首尾空格（防止前端加密时包含空格）
	decryptedUsername = strings.TrimSpace(decryptedUsername)

	if decryptedUsername == "" {
		logger.Error("用户名解密失败 (密文长度: %d)", len(req.Username))
		c.JSON(http.StatusBadRequest, gin.H{"message": "安全验证失败(用户名)，请刷新页面后重试"})
		return
	}

	// 调试日志：输出解密前后的用户名长度，以便排查问题
	logger.Debug("登录请求 - 加密用户名长度: %d, 解密后用户名: '%s' (长度: %d)", len(req.Username), decryptedUsername, len(decryptedUsername))

	// 验证输入长度（使用解密后的用户名）
	if err := utils.ValidateUsername(decryptedUsername); err != nil {
		BadRequestResponse(c, err.Error(), err)
		return
	}

	// 解密密码（SM2）
	decryptedPassword := decryptPassword(req.Password)

	// 去除解密后密码的首尾空格（防止前端加密时包含空格）
	decryptedPassword = strings.TrimSpace(decryptedPassword)

	if decryptedPassword == "" {
		logger.Error("密码解密失败 (密文长度: %d)", len(req.Password))
		c.JSON(http.StatusBadRequest, gin.H{"message": "安全验证失败(密码)，请刷新页面后重试"})
		return
	}

	// 验证密码格式（使用解密后的明文）
	if err := utils.ValidatePassword(decryptedPassword); err != nil {
		BadRequestResponse(c, err.Error(), err)
		return
	}

	// 获取客户端IP
	clientIP := getClientIP(c)
	userAgent := c.GetHeader("User-Agent")

	var userID uint
	var username, password, role, status string
	var mustChangePassword int
	var email, realName, avatar sql.NullString

	err := database.DB.QueryRow(`
		SELECT id, username, password, email, real_name, avatar, role, status, must_change_password
		FROM users WHERE username = ?
	`, decryptedUsername).Scan(&userID, &username, &password, &email, &realName, &avatar, &role, &status, &mustChangePassword)

	// 统一错误消息：不管是用户不存在还是密码错误，都返回相同消息
	if err != nil {
		if err == sql.ErrNoRows {
			// 用户不存在，记录失败尝试
			recordFailedAttempt(clientIP)
			recordLoginLog(decryptedUsername, clientIP, userAgent, "failed", "用户不存在")
			logger.Info("登录失败: 用户不存在 - IP: %s, Username: %s", clientIP, decryptedUsername)
		} else {
			recordLoginLog(decryptedUsername, clientIP, userAgent, "failed", "数据库查询错误")
			logger.Error("登录查询用户失败: %v", err)
		}
		// 统一返回错误消息
		c.JSON(http.StatusUnauthorized, gin.H{"message": "用户名或密码错误"})
		return
	}

	// 密码已在上文解密并验证

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(password), []byte(decryptedPassword)); err != nil {
		// 密码错误，记录失败尝试
		recordFailedAttempt(clientIP)
		recordLoginLog(username, clientIP, userAgent, "failed", "密码错误")
		logger.Info("登录失败: 密码错误 - IP: %s, Username: %s", clientIP, username)
		// 统一返回错误消息
		c.JSON(http.StatusUnauthorized, gin.H{"message": "用户名或密码错误"})
		return
	}

	// 检查密码强度，根据密码强度设置 must_change_password
	// 无论当前 must_change_password 的值是什么，都检查密码强度并更新
	valid, _ := validatePasswordStrength(decryptedPassword)
	if valid {
		// 密码符合要求，设置 must_change_password = 0（不需要强制修改）
		if mustChangePassword == 1 {
			_, err := database.DB.Exec("UPDATE users SET must_change_password = 0 WHERE id = ?", userID)
			if err != nil {
				logger.Warn("更新 must_change_password 标志失败: %v", err)
			} else {
				mustChangePassword = 0
				logger.Info("用户 %s (ID: %d) 密码符合强度要求，已清除强制修改密码标志", username, userID)
			}
		}
	} else {
		// 密码不符合要求，设置 must_change_password = 1（需要强制修改）
		if mustChangePassword == 0 {
			_, err := database.DB.Exec("UPDATE users SET must_change_password = 1 WHERE id = ?", userID)
			if err != nil {
				logger.Warn("更新 must_change_password 标志失败: %v", err)
			} else {
				mustChangePassword = 1
				logger.Info("用户 %s (ID: %d) 密码不符合强度要求，已设置强制修改密码标志", username, userID)
			}
		}
	}

	// 检查用户状态
	if status != "active" {
		recordLoginLog(username, clientIP, userAgent, "failed", "账户已被禁用")
		c.JSON(http.StatusForbidden, gin.H{"message": "账户已被禁用"})
		return
	}

	// 登录成功，清除失败计数
	recordSuccessAttempt(clientIP)
	logger.Info("用户登录成功: %s (ID: %d, Role: %s, IP: %s)", username, userID, role, clientIP)

	// 加密JWT Claims中的敏感信息
	encryptedUserID, err := utils.EncryptJWTField(strconv.FormatUint(uint64(userID), 10))
	if err != nil {
		logger.Error("加密UserID失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "生成Token失败"})
		return
	}

	encryptedUsername, err := utils.EncryptJWTField(username)
	if err != nil {
		logger.Error("加密Username失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "生成Token失败"})
		return
	}

	encryptedRole, err := utils.EncryptJWTField(role)
	if err != nil {
		logger.Error("加密Role失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "生成Token失败"})
		return
	}

	// 生成 JWT Token（Claims中存储加密后的值）
	now := utils.GetCurrentTime()
	expirationTime := now.Add(24 * time.Hour)
	claims := &Claims{
		UserID:   encryptedUserID,   // 加密后的用户ID
		Username: encryptedUsername, // 加密后的用户名
		Role:     encryptedRole,     // 加密后的角色
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "FusionWeb",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logger.Error("生成Token失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "无法生成 Token"})
		return
	}

	// 构建用户信息
	userInfo := gin.H{
		"id":       userID,
		"username": username,
		"role":     role,
	}
	if email.Valid {
		userInfo["email"] = email.String
	}
	if realName.Valid {
		userInfo["realName"] = realName.String
	}
	if avatar.Valid {
		userInfo["avatar"] = avatar.String
	}

	// 计算token的SHA256哈希值（用于后续验证token的真实性）
	tokenHash := sha256.Sum256([]byte(tokenString))
	tokenHashHex := hex.EncodeToString(tokenHash[:])
	logger.Info("用户ID: %d, 角色: %s, TokenHash: %s...", userID, role, tokenHashHex[:16])

	// 检查是否需要修改密码
	if mustChangePassword == 1 {
		userInfo["mustChangePassword"] = true
		recordLoginLogWithTokenHash(username, clientIP, userAgent, "success", "", tokenHashHex)
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"data": gin.H{
				"token": tokenString,
				"user":  userInfo,
			},
			"message": "登录成功，请修改密码",
		})
		return
	}

	// 记录成功登录日志（包含token_hash）
	recordLoginLogWithTokenHash(username, clientIP, userAgent, "success", "", tokenHashHex)
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"token": tokenString,
			"user":  userInfo,
		},
		"message": "登录成功",
	})
}
