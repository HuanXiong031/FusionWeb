// Package service provides authenticated encryption for persisted credentials.
package service

import (
	"FusionWeb/backend/config"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encryptedSecretPrefix = "fwenc:v1:"

// EncryptSecret protects a credential with AES-256-GCM. The server-side key is never stored in the database.
func EncryptSecret(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	keyText := strings.TrimSpace(config.Get().EncryptionKey)
	if keyText == "" {
		return "", fmt.Errorf("未配置 FUSIONWEB_ENCRYPTION_KEY，拒绝保存敏感凭据")
	}
	key := sha256.Sum256([]byte(keyText))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(value), nil)
	return encryptedSecretPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptSecret reads new encrypted records and accepts legacy plaintext only for one-time migration.
func DecryptSecret(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, encryptedSecretPrefix) {
		return value, nil
	}
	keyText := strings.TrimSpace(config.Get().EncryptionKey)
	if keyText == "" {
		return "", fmt.Errorf("未配置 FUSIONWEB_ENCRYPTION_KEY，无法解密敏感凭据")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, encryptedSecretPrefix))
	if err != nil {
		return "", fmt.Errorf("密文格式无效: %w", err)
	}
	key := sha256.Sum256([]byte(keyText))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("密文长度无效")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("密文校验失败: %w", err)
	}
	return string(plain), nil
}

func isEncryptedSecret(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), encryptedSecretPrefix)
}
