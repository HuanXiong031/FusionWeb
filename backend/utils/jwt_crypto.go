// backend/utils/jwt_crypto.go
// JWT 字段加密与解密模块
// 对 JWT Token 中的敏感字段进行额外的 AES-256-GCM 加密保护。
// 设计要点：
// - 加密密钥与签名密钥完全独立，遵循密钥分离原则
// - 每次启动自动生成独立随机加密密钥（32字节），不持久化，重启后旧 token 失效
// - 使用 sync.Once 确保密钥只初始化一次，线程安全
// - 加密算法：AES-256-GCM，每次加密使用随机 nonce（12字节），抗重放
// - 输出格式：Base64 URL Encoding，适合在网络传输中使用
//
// 安全提示：
// - 加密密钥不持久化意味着重启后所有已签发 token 将无法解密，用户需重新登录
// - 如果随机数生成失败（极低概率），降级使用 SHA256 派生密钥（不安全，仅保证启动）
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"FusionWeb/backend/logger"
)

// 全局变量：JWT 加密密钥及相关控制
var (
	jwtEncryptKey     []byte
	jwtEncryptKeyOnce sync.Once
	getSignKeyFunc    func() string // 回调函数，用于获取签名密钥的Base64编码
)

// SetGetJWTSignKeyFunc 设置获取 JWT 签名密钥的回调函数
// 参数：fn - 返回签名密钥 Base64 字符串的回调函数
// 用于在加密密钥初始化日志中同步输出签名密钥信息
func SetGetJWTSignKeyFunc(fn func() string) {
	getSignKeyFunc = fn
}

// initJWTEncryptKey 初始化JWT加密密钥（使用sync.Once确保只初始化一次）
// 注意：加密密钥与签名密钥完全独立，每次启动都生成随机密钥
func initJWTEncryptKey() {
	jwtEncryptKeyOnce.Do(func() {
		// 每次启动生成独立的随机加密密钥
		logger.InfoToFileOnly("正在生成新的JWT加密密钥...")
		newKey := make([]byte, 32)
		if _, err := rand.Read(newKey); err != nil {
			// 如果随机生成失败，使用默认密钥（不推荐，但至少程序可以启动）
			logger.Error("生成随机JWT加密密钥失败: %v，使用默认密钥（不安全）", err)
			hash := sha256.Sum256([]byte("fusion-web-jwt-encrypt-key-default"))
			jwtEncryptKey = hash[:]
			logger.Error("使用不安全的默认加密密钥")
		} else {
			jwtEncryptKey = newKey
			keyBase64 := base64.StdEncoding.EncodeToString(jwtEncryptKey)
			logger.InfoToFileOnly("JWT加密密钥已自动生成（Base64编码）: %s", keyBase64)
			logger.InfoToFileOnly("注意：加密密钥与签名密钥完全独立，每次启动都会生成新的加密密钥")

			// 输出签名密钥信息（在加密密钥后面）
			// 通过GetJWTSignKeyBase64回调函数获取签名密钥
			if getSignKeyFunc != nil {
				signKeyBase64 := getSignKeyFunc()
				if signKeyBase64 != "" {
					logger.InfoToFileOnly("JWT签名密钥已自动生成（Base64编码）: %s", signKeyBase64)
					logger.InfoToFileOnly("注意：每次启动都会生成新的签名密钥，已登录用户需要重新登录")
				}
			}
		}
	})
}

// EncryptJWTField 使用 AES-256-GCM 加密 JWT 字段值
// 参数：value - 要加密的明文字符串
// 返回值：Base64 URL 编码的密文（包含 nonce + 密文 + 认证标签）和可能的错误
//
// 加密流程：
// 1. 初始化加密密钥（首次调用触发）
// 2. 创建 AES-256-GCM cipher
// 3. 生成 12 字节随机 nonce
// 4. GCM 加密（自动附加认证标签）
// 5. Base64 URL 编码输出（nonce 前置在密文前）
func EncryptJWTField(value string) (string, error) {
	initJWTEncryptKey()

	// 创建AES cipher
	block, err := aes.NewCipher(jwtEncryptKey)
	if err != nil {
		return "", fmt.Errorf("创建cipher失败: %w", err)
	}

	// 使用GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM失败: %w", err)
	}

	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成nonce失败: %w", err)
	}

	// 加密
	ciphertext := gcm.Seal(nonce, nonce, []byte(value), nil)

	// Base64编码
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptJWTField 使用 AES-256-GCM 解密 JWT 字段值
// 参数：encryptedValue - Base64 URL 编码的密文字符串
// 返回值：解密后的明文字符串和可能的错误
//
// 解密流程：
// 1. 初始化加密密钥（首次调用触发）
// 2. Base64 URL 解码
// 3. 提取前 12 字节 nonce
// 4. GCM 解密并验证认证标签
// 注意：如果密钥在启动间变化（正常的每次启动随机生成），旧密文将无法解密
func DecryptJWTField(encryptedValue string) (string, error) {
	initJWTEncryptKey()

	// Base64解码
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}

	// 创建AES cipher
	block, err := aes.NewCipher(jwtEncryptKey)
	if err != nil {
		return "", fmt.Errorf("创建cipher失败: %w", err)
	}

	// 使用GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM失败: %w", err)
	}

	// 提取nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("密文长度不足")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 解密
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}

	return string(plaintext), nil
}
