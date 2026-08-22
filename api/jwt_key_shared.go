// jwt_key_shared.go - JWT密钥跨包共享机制
// 本文件解决了api包和utils包之间安全共享JWT签名密钥的架构需求。
// 设计背景：
//   平台使用SM2非对称加密保护JWT Claims中的敏感字段（用户ID、用户名、角色）。
//   加密密钥从JWT签名密钥通过SHA256派生而来（密钥派生函数KDF模式），
//   确保加密密钥与JWT签名密钥具有相同的安全强度且无需额外管理。
//   utils包需要此密钥来派生加密密钥，但jwtKey变量在api包中定义。
// 使用sync.Once确保密钥只初始化一次，避免并发初始化问题。

package api

import (
	"crypto/sha256"
	"sync"
)

var (
	jwtKeyForEncrypt     []byte
	jwtKeyForEncryptOnce sync.Once
)

// GetJWTKeyForEncrypt 获取JWT签名密钥的副本，供utils包使用以派生加密密钥。
// 使用sync.Once确保只捕获一次jwtKey的值，之后始终返回相同的引用。
// 设计要点：
//   - 如果jwtKey尚未初始化（某些测试场景），返回nil
//   - 调用者（utils包）需要处理nil返回值的情况
// 返回值:
//   - []byte: JWT签名密钥的引用，或nil（如果密钥未初始化）
func GetJWTKeyForEncrypt() []byte {
	jwtKeyForEncryptOnce.Do(func() {
		// 如果jwtKey已经初始化，使用它
		if len(jwtKey) > 0 {
			jwtKeyForEncrypt = jwtKey
		} else {
			// 如果jwtKey还没有初始化，返回nil（调用者需要处理）
			jwtKeyForEncrypt = nil
		}
	})
	return jwtKeyForEncrypt
}

// SetJWTKeyForEncrypt 显式设置JWT签名密钥值（在initJWTKey完成后调用）。
// 同样使用sync.Once确保只设置一次，防止意外覆盖。
// 参数:
//   - key: JWT签名密钥的字节切片
func SetJWTKeyForEncrypt(key []byte) {
	jwtKeyForEncryptOnce.Do(func() {
		jwtKeyForEncrypt = key
	})
}

// DeriveEncryptKeyFromJWTKey 使用密钥派生函数（KDF）从JWT签名密钥派生加密密钥。
// 派生方式：SHA256(jwtKey + "-encrypt" 后缀)，取前32字节作为AES-256加密密钥。
// 这样设计的好处：
//   1. 加密密钥与JWT签名密钥相关联，不需要单独管理
//   2. 使用不同后缀可以派生多种用途的密钥（此处为"-encrypt"）
//   3. 即使加密密文泄露，也无法直接获取JWT签名密钥（单向哈希）
// 返回值:
//   - []byte: 32字节的AES-256加密密钥，或nil（如果JWT密钥未初始化）
func DeriveEncryptKeyFromJWTKey() []byte {
	key := GetJWTKeyForEncrypt()
	if key == nil {
		return nil
	}
	// 使用SHA256哈希派生加密密钥
	hash := sha256.Sum256(append(key, []byte("-encrypt")...))
	return hash[:]
}
