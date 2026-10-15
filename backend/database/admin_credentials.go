package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"FusionWeb/backend/logger"

	"golang.org/x/crypto/bcrypt"
)

const (
	basicUserSecretFile = "basic_user"
	basicPassSecretFile = "basic_pass"
)

// SyncBasicAuthCredentials 将管理员账号密码同步到共享 secret 文件，供 Web Basic Auth 直接使用。
// username 为空时会保留当前共享 secret 或环境变量中的用户名。
func SyncBasicAuthCredentials(username, password string) error {
	if strings.TrimSpace(password) == "" {
		password = fallbackAdminPassword
	}
	username = resolveBasicAuthUsername(username)
	return writeBasicAuthSecretFiles(username, password)
}

func ensureAdminCredentialsSynced() error {
	adminUsername, adminPassword := defaultAdminCredentials()
	targetMustChange := mustChangePasswordFlag(adminPassword)

	var adminID int64
	var currentUsername string
	var currentPasswordHash string
	var currentMustChange int
	err := DB.QueryRow(`
		SELECT id, username, password, must_change_password
		FROM users
		WHERE role = 'admin'
		ORDER BY id ASC
		LIMIT 1
	`).Scan(&adminID, &currentUsername, &currentPasswordHash, &currentMustChange)
	if err == sql.ErrNoRows {
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		if hashErr != nil {
			return fmt.Errorf("密码加密失败: %w", hashErr)
		}
		_, execErr := DB.Exec(`
			INSERT INTO users (username, password, email, real_name, role, status, must_change_password)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, adminUsername, string(hashedPassword), "admin@fusionscan.com", "系统管理员", "admin", "active", targetMustChange)
		if execErr != nil {
			return fmt.Errorf("创建默认管理员账户失败: %w", execErr)
		}
		if syncErr := SyncBasicAuthCredentials(adminUsername, adminPassword); syncErr != nil {
			return fmt.Errorf("写入 Basic Auth 凭据失败: %w", syncErr)
		}
		logger.Info("默认管理员账户已创建并与 Basic Auth 同步")
		logger.Info("默认管理员用户名: %s", adminUsername)
		logger.Info("默认管理员初始密码: %s", adminPassword)
		if targetMustChange == 1 {
			logger.Info("请首次登录后修改默认管理员密码")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("查询管理员账户失败: %w", err)
	}

	updates := make([]string, 0, 3)
	args := make([]interface{}, 0, 4)
	changed := make([]string, 0, 3)

	if currentUsername != adminUsername {
		updates = append(updates, "username = ?")
		args = append(args, adminUsername)
		changed = append(changed, "用户名")
	}
	if bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(adminPassword)) != nil {
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
		if hashErr != nil {
			return fmt.Errorf("密码加密失败: %w", hashErr)
		}
		updates = append(updates, "password = ?")
		args = append(args, string(hashedPassword))
		changed = append(changed, "密码")
	}
	if currentMustChange != targetMustChange {
		updates = append(updates, "must_change_password = ?")
		args = append(args, targetMustChange)
		changed = append(changed, "改密标记")
	}

	if len(updates) > 0 {
		args = append(args, adminID)
		query := "UPDATE users SET " + strings.Join(updates, ", ") + ", updated_at = CURRENT_TIMESTAMP WHERE id = ?"
		if _, execErr := DB.Exec(query, args...); execErr != nil {
			return fmt.Errorf("同步管理员账户失败: %w", execErr)
		}
		logger.Info("管理员账户已与 Basic Auth 同步: %s", strings.Join(changed, "、"))
	} else {
		logger.Info("管理员账户已存在，且与 Basic Auth 配置一致")
	}

	if syncErr := SyncBasicAuthCredentials(adminUsername, adminPassword); syncErr != nil {
		return fmt.Errorf("写入 Basic Auth 凭据失败: %w", syncErr)
	}
	logger.Info("默认管理员用户名: %s", adminUsername)
	logger.Info("默认管理员当前密码: %s", adminPassword)
	return nil
}

func resolveBasicAuthUsername(username string) string {
	username = strings.TrimSpace(username)
	if username != "" {
		return username
	}
	if envUser := strings.TrimSpace(os.Getenv("FUSIONWEB_BASIC_USER")); envUser != "" {
		return envUser
	}
	if secretUser := strings.TrimSpace(readSecretFileValue(basicUserSecretFile)); secretUser != "" {
		return secretUser
	}
	return "admin"
}

func writeBasicAuthSecretFiles(username, password string) error {
	secretsDir := strings.TrimSpace(os.Getenv("FUSIONWEB_SECRETS_DIR"))
	if secretsDir == "" {
		return nil
	}
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("创建 secret 目录失败: %w", err)
	}
	if err := writeSecretFileAtomic(secretsDir, basicUserSecretFile, username); err != nil {
		return err
	}
	if err := writeSecretFileAtomic(secretsDir, basicPassSecretFile, password); err != nil {
		return err
	}
	return nil
}

func readSecretFileValue(fileName string) string {
	secretsDir := strings.TrimSpace(os.Getenv("FUSIONWEB_SECRETS_DIR"))
	if secretsDir == "" {
		return ""
	}
	content, err := os.ReadFile(filepath.Join(secretsDir, fileName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(content))
}

func writeSecretFileAtomic(dir, fileName, value string) error {
	target := filepath.Join(dir, fileName)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0600); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", fileName, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("替换 %s 失败: %w", fileName, err)
	}
	return nil
}

func mustChangePasswordFlag(password string) int {
	if passwordMeetsPlatformPolicy(password) {
		return 0
	}
	return 1
}

func passwordMeetsPlatformPolicy(password string) bool {
	if len(password) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}
