package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/utils"
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// HandleGetProfile 获取当前已登录用户的完整个人信息。
// GET /api/auth/profile
// 从JWT中间件注入的userId中获取用户ID，查询users表返回详细信息。
// 返回信息包括：ID、用户名、邮箱、真实姓名、头像、角色、强制修改密码标志。
// 注意：此接口不需要额外权限检查，所有已认证用户均可访问自己的信息。
func HandleGetProfile(c *gin.Context) {
	// logger.Info("收到获取用户信息请求: %s %s", c.Request.Method, c.Request.URL.Path)

	userID, exists := c.Get("userId")
	if !exists {
		logger.Warn("获取用户信息失败: userId 不存在")
		c.JSON(http.StatusUnauthorized, gin.H{"message": "未授权"})
		return
	}

	var username, role, status string
	var mustChangePassword int
	var email, realName, avatar sql.NullString

	err := database.DB.QueryRow(`
		SELECT username, email, real_name, avatar, role, status, must_change_password
		FROM users WHERE id = ?
	`, userID).Scan(&username, &email, &realName, &avatar, &role, &status, &mustChangePassword)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"message": "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "服务器错误"})
		}
		return
	}

	userInfo := gin.H{
		"id":                 userID,
		"username":           username,
		"role":               role,
		"mustChangePassword": mustChangePassword == 1,
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

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": userInfo,
	})
}

// HandleUpdateProfile 更新当前登录用户的个人信息（邮箱、真实姓名、头像）。
// PUT /api/auth/profile
// 使用动态SQL构建更新语句，只更新前端实际传入的非空字段。
// 更新前会校验用户是否存在于数据库中。
func HandleUpdateProfile(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "未授权"})
		return
	}

	var req struct {
		Email    string `json:"email"`
		RealName string `json:"realName"`
		Avatar   string `json:"avatar"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "无效的请求参数"})
		return
	}

	// 检查用户是否存在
	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil || count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "用户不存在"})
		return
	}

	// 构建更新语句
	updates := []string{}
	args := []interface{}{}

	if req.Email != "" {
		updates = append(updates, "email = ?")
		args = append(args, req.Email)
	}
	if req.RealName != "" {
		updates = append(updates, "real_name = ?")
		args = append(args, req.RealName)
	}
	if req.Avatar != "" {
		updates = append(updates, "avatar = ?")
		args = append(args, req.Avatar)
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "没有需要更新的字段"})
		return
	}

	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	updates = append(updates, "updated_at = ?")
	args = append(args, timeStr, userID)

	query := "UPDATE users SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	_, err = database.DB.Exec(query, args...)
	if err != nil {
		logger.Error("更新用户信息失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "更新成功",
	})
}

// ChangePasswordRequest 修改密码接口的请求体结构。
// 旧密码和新密码均为必填字段，前端使用SM2加密后传输。
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" binding:"required"` // SM2加密的旧密码
	NewPassword string `json:"newPassword" binding:"required"` // SM2加密的新密码
}

// HandleChangePassword 处理用户修改密码请求。
// POST /api/auth/change-password
// 修改流程：
//  1. 校验请求参数（新密码长度预检 >= 20）
//  2. 查询当前用户的bcrypt密码哈希和must_change_password标志
//  3. SM2解密旧密码，bcrypt验证旧密码是否正确
//  4. SM2解密新密码，验证新密码复杂度（大小写+数字+符号）
//  5. bcrypt生成新密码哈希
//  6. 更新数据库并清除强制修改密码标志
// 注意：即使是首次登录强制修改密码场景，也需验证旧密码确保安全。
func HandleChangePassword(c *gin.Context) {
	userID, exists := c.Get("userId")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "未授权"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "无效的请求参数", "error": err.Error()})
		return
	}

	// 验证新密码强度（先检查长度，解密后再完整验证）
	if len(req.NewPassword) < 20 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "密码长度必须大于等于20位",
		})
		return
	}

	// 查询用户密码和 must_change_password 标志
	var currentPassword string
	var mustChangePassword int
	err := database.DB.QueryRow("SELECT password, must_change_password FROM users WHERE id = ?", userID).Scan(&currentPassword, &mustChangePassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"message": "用户不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "服务器错误"})
		}
		return
	}

	// 解密旧密码（如果已加密）
	decryptedOldPassword := decryptPassword(req.OldPassword)

	// 验证旧密码（首次登录也需要验证原密码）
	if err := bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(decryptedOldPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "原密码错误",
		})
		return
	}

	// 解密新密码（如果已加密）
	decryptedNewPassword := decryptPassword(req.NewPassword)

	// 验证新密码强度
	if valid, msg := validatePasswordStrength(decryptedNewPassword); !valid {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": msg,
		})
		return
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(decryptedNewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("密码加密失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "服务器错误"})
		return
	}

	// 更新密码并清除必须修改密码标志
	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	_, err = database.DB.Exec(`
		UPDATE users SET password = ?, must_change_password = 0, updated_at = ?
		WHERE id = ?
	`, string(hashedPassword), timeStr, userID)

	if err != nil {
		logger.Error("更新密码失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "更新密码失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "密码修改成功",
	})
}
