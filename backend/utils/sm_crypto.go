// backend/utils/sm_crypto.go
// 国密 SM2 非对称加密模块
// 实现基于 SM2 椭圆曲线的前后端加密通信，用于登录密码等敏感数据的传输保护。
// 设计要点：
// - 每次启动自动生成新的密钥对，私钥仅存在于内存中，不持久化
// - 前端使用公钥加密敏感数据（如登录密码），后端使用私钥解密
// - 支持多种密文格式兼容：C1C3C2（国标）、C1C2C3（旧标准）、ASN.1
// - 使用读写锁保护密钥对的并发访问
//
// 安全说明：
// - SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法，等效于 ECDSA + ECDH
// - 使用 tjfoc/gmsm 库实现，该库是国内广泛使用的国密 Go 实现
// - 启动时如果密钥生成失败，程序将 panic 退出（保证安全优先）
package utils

import (
	"encoding/hex"
	"fmt"
	"sync"

	"FusionWeb/backend/logger"

	"github.com/tjfoc/gmsm/sm2"
)

// 全局变量：SM2 密钥对
var (
	sm2PrivateKey *sm2.PrivateKey
	sm2PublicKey  string // Hex string (04+X+Y)
	sm2Mutex      sync.RWMutex
)

// InitSM2Keys 初始化 SM2 密钥对（每次启动生成新的随机密钥）
// 生成包含公钥和私钥的 SM2 密钥对，私钥仅存在于内存中。
// 公钥转换为十六进制字符串格式（04+X+Y），供前端使用。
// 如果密钥生成失败，程序将 panic 退出（确保安全优先于可用性）。
func InitSM2Keys() {
	sm2Mutex.Lock()
	defer sm2Mutex.Unlock()

	logger.InfoToFileOnly("正在生成新的SM2密钥对...")
	priv, err := sm2.GenerateKey(nil)
	if err != nil {
		logger.Error("生成SM2密钥失败: %v", err)
		panic("生成SM2密钥失败，程序无法启动")
	}

	sm2PrivateKey = priv

	// 生成公钥 Hex (04 + X + Y)
	pub := priv.PublicKey
	pubBytes := append([]byte{0x04}, pub.X.Bytes()...)
	pubBytes = append(pubBytes, pub.Y.Bytes()...)
	sm2PublicKey = hex.EncodeToString(pubBytes)

	logger.InfoToFileOnly("SM2密钥对已生成")
	// logger.InfoToFileOnly("公钥: %s", sm2PublicKey) // 调试用
}

// GetSM2PublicKey 获取当前 SM2 公钥（十六进制格式）
// 返回值：公钥的十六进制字符串（04+X坐标+Y坐标），未初始化时返回空字符串
// 前端使用此公钥加密登录密码等敏感数据
func GetSM2PublicKey() string {
	sm2Mutex.RLock()
	defer sm2Mutex.RUnlock()
	if sm2PublicKey == "" {
		// 懒加载防止未初始化
		// 实际上应该在main init调用，这里做个双重保障不好，因为死锁风险
		// 假设 InitSM2Keys 必定在启动时调用
		return ""
	}
	return sm2PublicKey
}

// DecryptSM2 解密 SM2 加密的数据（支持多种密文模式兼容）
// 参数：encryptedHex - 十六进制编码的密文字符串
// 返回值：解密后的明文字符串和可能的错误
//
// 尝试模式（按优先级）：
// 1. C1C3C2 模式（国标，sm-crypto 默认模式）
// 2. ASN.1 编码模式（Java/C 语言兼容）
// 3. C1C2C3 模式（旧标准兼容）
//
// 设计理由：前端可能使用不同语言的 SM2 库（JS/Python/Java），密文格式不统一
func DecryptSM2(encryptedHex string) (string, error) {
	sm2Mutex.RLock()
	privKey := sm2PrivateKey
	sm2Mutex.RUnlock()

	if privKey == nil {
		return "", fmt.Errorf("SM2私钥未初始化")
	}

	// 1. Hex Decode
	encryptedBytes, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("Hex解码失败: %v", err)
	}

	// 2. 准备数据
	// gmsm 的 C1C3C2 模式期望输入以 04 开头 (Uncompressed Point)
	var dataWith04 []byte
	if len(encryptedBytes) > 0 && encryptedBytes[0] != 0x04 {
		dataWith04 = append([]byte{0x04}, encryptedBytes...)
	} else {
		dataWith04 = encryptedBytes
	}

	// 3. 尝试解密
	// 优先尝试标准模式 C1C3C2 (sm-crypto 默认模式)
	plaintext, err := privKey.Decrypt(nil, dataWith04, sm2.C1C3C2)
	if err == nil {
		return string(plaintext), nil
	}
	firstErr := err

	// 尝试 ASN1 模式 (以防万一)
	// ASN1 格式通常是 SEQUENCE 结构，不一定以 04 开头，直接传入原始字节
	plaintext, err = privKey.DecryptAsn1(encryptedBytes)
	if err == nil {
		return string(plaintext), nil
	}

	// 尝试 C1C2C3 模式 (旧标准)
	plaintext, err = privKey.Decrypt(nil, dataWith04, sm2.C1C2C3)
	if err == nil {
		return string(plaintext), nil
	}

	return "", fmt.Errorf("解密失败: %v", firstErr)
}

// init 包初始化函数
// 在包被首次导入时自动执行，确保 SM2 密钥在程序启动时即已就绪
func init() {
	// 自动初始化 SM2 密钥对
	InitSM2Keys()
}
