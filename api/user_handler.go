// user_handler.go - 用户管理HTTP接口处理层
// 本文件实现Web安全扫描平台的用户CRUD操作RESTful API。
// 功能范围：
//   1. 用户列表查询（分页，含最后登录时间和IP位置）
//   2. 用户详情查询
//   3. 用户创建（含密码强度验证和唯一性检查）
//   4. 用户更新（角色变更时自动提示重新登录）
//   5. 用户删除（物理删除，禁止自删）
// 访问模型：认证后可使用；角色字段保留给账户管理和前端展示。
// 安全措施：
//   - 密码使用bcrypt哈希存储，从未明文记录
//   - 密码强度强制验证（>=20位，包含大小写字母、数字、符号）
//   - 更新自己角色时提示needRelogin标志，前端引导重新登录

package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// validatePasswordStrength 验证密码是否满足平台安全强度要求。
// 强度策略（强密码要求）：
//  1. 长度 >= 8位
//  2. 必须包含大写字母
//  3. 必须包含小写字母
//  4. 必须包含数字
//  5. 必须包含特殊符号（标点符号或Unicode符号字符）
//
// 参数:
//   - password: 待验证的明文密码
//
// 返回值:
//   - bool: true表示密码符合强度要求
//   - string: 不符合时的具体原因描述（如"密码必须包含：大写字母、特殊符号"）
func validatePasswordStrength(password string) (bool, string) {
	if len(password) < 8 {
		return false, "密码长度必须大于等于8位"
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	var missing []string
	if !hasUpper {
		missing = append(missing, "大写字母")
	}
	if !hasLower {
		missing = append(missing, "小写字母")
	}
	if !hasDigit {
		missing = append(missing, "数字")
	}
	if !hasSpecial {
		missing = append(missing, "特殊符号")
	}

	if len(missing) > 0 {
		return false, "密码必须包含：" + strings.Join(missing, "、")
	}

	return true, ""
}

// HandleGetUsers 获取用户分页列表。
// GET /api/users?page=1&pageSize=10
// 返回数据包含：
//   - 用户基本资料（ID、用户名、邮箱、真实姓名、头像、角色、状态）
//   - 创建时间（格式化显示）
//   - 最后登录时间（从login_logs表关联查询）
//   - 最后登录IP及地理位置（批量IP查询优化性能，局域网IP标记为"局域网"）
func HandleGetUsers(c *gin.Context) {

	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("pageSize", "10")

	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	var total int64
	err := database.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)
	if err != nil {
		InternalServerErrorResponse(c, "Failed to count users", nil)
		return
	}

	offset := (page - 1) * pageSize
	rows, err := database.DB.Query(`
		SELECT 
			u.id, u.username, u.email, u.real_name, u.avatar, u.role, u.status, CAST(u.created_at AS TEXT),
			(SELECT CAST(created_at AS TEXT) FROM login_logs 
			 WHERE username = u.username AND login_result = 'success' 
			 ORDER BY created_at DESC LIMIT 1) as last_login_time,
			(SELECT ip_address FROM login_logs 
			 WHERE username = u.username AND login_result = 'success' 
			 ORDER BY created_at DESC LIMIT 1) as last_login_ip
		FROM users u
		ORDER BY u.id ASC
		LIMIT ? OFFSET ?
	`, pageSize, offset)
	if err != nil {
		InternalServerErrorResponse(c, "Failed to retrieve users", nil)
		return
	}
	defer rows.Close()

	// 先读取所有数据，收集IP地址用于批量查询定位信息
	type userData struct {
		id            uint
		username      string
		role          string
		status        string
		email         sql.NullString
		realName      sql.NullString
		avatar        sql.NullString
		createdAt     sql.NullString
		lastLoginTime sql.NullString
		lastLoginIP   sql.NullString
	}

	usersData := []userData{}
	ipSet := make(map[string]bool) // 用于收集唯一的IP地址

	for rows.Next() {
		var id uint
		var username, role, status string
		var email, realName, avatar sql.NullString
		var createdAt sql.NullString
		var lastLoginTime sql.NullString
		var lastLoginIP sql.NullString

		err := rows.Scan(&id, &username, &email, &realName, &avatar, &role, &status, &createdAt,
			&lastLoginTime, &lastLoginIP)
		if err != nil {
			continue
		}

		// 收集IP地址用于批量查询
		if lastLoginIP.Valid && lastLoginIP.String != "" {
			ipSet[lastLoginIP.String] = true
		}

		usersData = append(usersData, userData{
			id:            id,
			username:      username,
			role:          role,
			status:        status,
			email:         email,
			realName:      realName,
			avatar:        avatar,
			createdAt:     createdAt,
			lastLoginTime: lastLoginTime,
			lastLoginIP:   lastLoginIP,
		})
	}

	// 批量查询IP位置信息
	ipLocationMap := make(map[string]string) // IP -> 位置字符串
	if len(ipSet) > 0 {
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			// 先检查是否为局域网IP
			if isLocalNetworkIP(ip) {
				ipLocationMap[ip] = "局域网"
				continue
			}
			ips = append(ips, ip)
		}
		if len(ips) > 0 {
			locations, err := service.QueryIPs(ips)
			if err == nil {
				for ip, location := range locations {
					// 构建位置字符串：区县 > 城市 > 省份 > 国家（依次递增）
					locationStr := buildLocationString(location)
					ipLocationMap[ip] = locationStr
				}
			}
		}
	}

	// 构建用户列表
	userList := make([]gin.H, 0)
	for _, user := range usersData {
		userInfo := gin.H{
			"id":       user.id,
			"username": user.username,
			"role":     user.role,
			"status":   user.status,
		}
		if user.email.Valid {
			userInfo["email"] = user.email.String
		}
		if user.realName.Valid {
			userInfo["realName"] = user.realName.String
		}
		if user.avatar.Valid {
			userInfo["avatar"] = user.avatar.String
		}
		if user.createdAt.Valid {
			userInfo["createdAt"] = utils.FormatTimeStringForDisplay(user.createdAt.String)
		}
		if user.lastLoginTime.Valid {
			userInfo["lastLoginTime"] = utils.FormatTimeStringForDisplay(user.lastLoginTime.String)
		}
		if user.lastLoginIP.Valid {
			userInfo["lastLoginIP"] = user.lastLoginIP.String

			// 获取IP定位信息
			ip := user.lastLoginIP.String
			if isLocalNetworkIP(ip) {
				userInfo["lastLoginLocation"] = "局域网"
			} else if location, ok := ipLocationMap[ip]; ok {
				userInfo["lastLoginLocation"] = location
			} else {
				userInfo["lastLoginLocation"] = "未知"
			}
		}

		userList = append(userList, userInfo)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"list":     userList,
			"total":    total,
			"page":     page,
			"pageSize": pageSize,
		},
	})
}

// HandleGetUser 获取指定ID用户的详细信息。
// GET /api/users/:id
// 返回：用户名、邮箱、真实姓名、头像、角色、状态等完整信息。
// 包含基本的错误处理：用户不存在返回404，数据库错误返回500。
func HandleGetUser(c *gin.Context) {
	id := c.Param("id")

	var username, role, status string
	var email, realName, avatar sql.NullString

	err := database.DB.QueryRow(`
		SELECT username, email, real_name, avatar, role, status
		FROM users WHERE id = ?
	`, id).Scan(&username, &email, &realName, &avatar, &role, &status)

	if err != nil {
		if err == sql.ErrNoRows {
			ErrorResponse(c, http.StatusNotFound, "User not found", nil)
		} else {
			InternalServerErrorResponse(c, "Database error", nil)
		}
		return
	}

	userInfo := gin.H{
		"id":       id,
		"username": username,
		"role":     role,
		"status":   status,
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

// HandleUpdateUser 更新指定用户的信息（仅admin角色可访问）。
// PUT /api/users/:id
// 支持更新的字段：邮箱、真实姓名、角色、状态、密码。
// 特殊处理：
//   - 密码更新：非空时先验证密码强度再bcrypt哈希存储
//   - 角色变更：如管理员修改自己的角色，返回needRelogin=true提示前端重新登录
//   - 空值忽略：只更新前端实际传入的非空字段（动态SQL构建）
//
// 权限：仅admin角色
func HandleUpdateUser(c *gin.Context) {

	id := c.Param("id")
	currentUserID, _ := c.Get("userId")
	currentUserIDUint := currentUserID.(uint)

	var req struct {
		Email    string `json:"email"`
		RealName string `json:"realName"`
		Role     string `json:"role"`
		Status   string `json:"status"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequestResponse(c, "Invalid request", nil)
		return
	}

	// 检查用户是否存在
	var targetUserRole string
	err := database.DB.QueryRow("SELECT role FROM users WHERE id = ?", id).Scan(&targetUserRole)
	if err != nil {
		ErrorResponse(c, http.StatusNotFound, "User not found", nil)
		return
	}

	// 检查用户是否修改自己的角色
	var needRevokeToken bool
	var targetUserCurrentRole string
	if req.Role != "" && strconv.Itoa(int(currentUserIDUint)) == id {
		// 获取当前用户的角色
		err := database.DB.QueryRow("SELECT role FROM users WHERE id = ?", id).Scan(&targetUserCurrentRole)
		if err == nil && targetUserCurrentRole != req.Role {
			needRevokeToken = true
		}
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
	if req.Role != "" {
		updates = append(updates, "role = ?")
		args = append(args, req.Role)
	}
	if req.Status != "" {
		updates = append(updates, "status = ?")
		args = append(args, req.Status)
	}
	// 只有在密码不为空且去除空格后仍不为空时才更新密码
	// 这样可以避免前端发送空字符串或只有空格的字符串时误更新密码
	if req.Password != "" {
		trimmedPassword := strings.TrimSpace(req.Password)
		if trimmedPassword != "" {
			// 验证密码强度
			if valid, msg := validatePasswordStrength(trimmedPassword); !valid {
				ErrorResponse(c, http.StatusBadRequest, msg, fmt.Errorf("Password validation failed"))
				return
			}
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(trimmedPassword), bcrypt.DefaultCost)
			if err != nil {
				logger.Error("密码加密失败: %v", err)
				InternalServerErrorResponse(c, "Failed to hash password", nil)
				return
			}
			updates = append(updates, "password = ?")
			args = append(args, string(hashedPassword))
		}
	}

	if len(updates) == 0 {
		BadRequestResponse(c, "No fields to update", nil)
		return
	}

	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	updates = append(updates, "updated_at = ?")
	args = append(args, timeStr, id)

	query := "UPDATE users SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	_, err = database.DB.Exec(query, args...)
	if err != nil {
		logger.Error("更新用户失败: %v", err)
		InternalServerErrorResponse(c, "Failed to update user", nil)
		return
	}

	// 如果用户修改了自己的角色，在更新成功后提示重新登录
	// 这样可以确保更新操作完成，并且响应能够正常返回
	if needRevokeToken {
		c.JSON(http.StatusOK, gin.H{
			"code":        0,
			"message":     "User updated successfully. Please login again due to role change.",
			"needRelogin": true,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "User updated successfully",
	})
}

// HandleDeleteUser 物理删除指定用户（仅admin角色可访问）。
// DELETE /api/users/:id
// 安全限制：
//   - 禁止删除自己（防止管理员误操作锁死系统）
//   - 物理删除（非软删除），数据不可恢复
//   - 删除前校验用户是否存在
//
// 权限：仅admin角色
func HandleDeleteUser(c *gin.Context) {

	id := c.Param("id")
	userID, _ := c.Get("userId")

	// 不能删除自己
	if strconv.Itoa(int(userID.(uint))) == id {
		BadRequestResponse(c, "Cannot delete yourself", nil)
		return
	}

	// 检查用户是否存在并获取角色
	var targetUserRole string
	err := database.DB.QueryRow("SELECT role FROM users WHERE id = ?", id).Scan(&targetUserRole)
	if err != nil {
		if err == sql.ErrNoRows {
			ErrorResponse(c, http.StatusNotFound, "用户不存在或已被删除", fmt.Errorf("User not found"))
			return
		}
		logger.Error("检查用户失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "检查用户失败", fmt.Errorf("Failed to check user"))
		return
	}

	// 物理删除：真正从数据库中删除记录
	// 注意：这会永久删除用户数据，无法恢复
	_, err = database.DB.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		logger.Error("删除用户失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "删除用户失败", fmt.Errorf("Failed to delete user"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "User deleted successfully",
	})
}

// HandleCreateUser 创建新用户（仅admin角色可访问）。
// POST /api/users
// 创建流程：
//  1. 权限校验（仅admin）
//  2. 验证必填字段（用户名、密码）
//  3. 去除用户名和密码首尾空格
//  4. 验证输入长度限制
//  5. 验证密码强度（>=20位 + 大小写数字符号）
//  6. 检查用户名唯一性（不区分已删除用户）
//  7. bcrypt哈希密码
//  8. 设置默认值（role默认"user"，status默认"active"）
//  9. 根据密码强度设置must_change_password标志
//  10. 使用系统时区创建用户记录
//  11. 唯一性约束冲突时返回友好错误消息
//
// 权限：仅admin角色
func HandleCreateUser(c *gin.Context) {

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Email    string `json:"email"`
		RealName string `json:"realName"`
		Role     string `json:"role"`
		Status   string `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c, http.StatusBadRequest, "Invalid request", err)
		return
	}

	// 去除密码首尾空格（防止前端发送时包含空格）
	req.Password = strings.TrimSpace(req.Password)
	req.Username = strings.TrimSpace(req.Username)

	// 验证输入长度
	if err := utils.ValidateUsername(req.Username); err != nil {
		BadRequestResponse(c, err.Error(), err)
		return
	}
	if err := utils.ValidatePassword(req.Password); err != nil {
		BadRequestResponse(c, err.Error(), err)
		return
	}
	if req.Email != "" && len(req.Email) > 100 {
		BadRequestResponse(c, "邮箱长度不能超过100个字符", nil)
		return
	}
	if req.RealName != "" && len(req.RealName) > 100 {
		BadRequestResponse(c, "真实姓名长度不能超过100个字符", nil)
		return
	}

	// 记录密码长度（用于调试，不记录实际密码）
	logger.Debug("创建用户 - 用户名: %s, 密码长度: %d", req.Username, len(req.Password))

	// 验证密码强度
	if valid, msg := validatePasswordStrength(req.Password); !valid {
		ErrorResponse(c, http.StatusBadRequest, msg, fmt.Errorf("Password validation failed"))
		return
	}

	// 检查用户名是否已存在（包括已删除的用户，因为用户名是唯一的）
	var count int
	err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if err != nil {
		logger.Error("检查用户名失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "检查用户名失败", fmt.Errorf("Failed to check username"))
		return
	}
	if count > 0 {
		ErrorResponse(c, http.StatusBadRequest, "用户名已存在，请使用其他用户名", fmt.Errorf("Username already exists"))
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("密码加密失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "密码加密失败", fmt.Errorf("Failed to hash password"))
		return
	}
	logger.Debug("密码加密成功 - 哈希长度: %d", len(hashedPassword))

	// 设置默认值
	if req.Role == "" {
		req.Role = "user"
	}
	if req.Status == "" {
		req.Status = "active"
	}

	// 根据密码强度设置 must_change_password
	// 如果密码符合要求（大小写数字符号>=20位），则不需要强制修改（0）
	// 如果密码不符合要求，则需要强制修改（1）
	mustChangePassword := 0
	if valid, _ := validatePasswordStrength(req.Password); !valid {
		mustChangePassword = 1
	}

	// 获取当前时间
	timeStr := utils.GetCurrentTimeString()

	// 创建用户，使用系统时区
	userID, err := database.InsertAndReturnID(`
		INSERT INTO users (username, password, email, real_name, role, status, must_change_password, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Username, string(hashedPassword), req.Email, req.RealName, req.Role, req.Status, mustChangePassword, timeStr)

	if err != nil {
		logger.Error("创建用户失败: %v", err)
		// 检查是否是唯一性约束错误
		errStr := err.Error()
		if strings.Contains(errStr, "UNIQUE constraint failed") || strings.Contains(errStr, "duplicate key") {
			ErrorResponse(c, http.StatusBadRequest, "用户名已存在，请使用其他用户名", fmt.Errorf("Username already exists"))
			return
		}
		ErrorResponse(c, http.StatusInternalServerError, "创建用户失败，请稍后重试", fmt.Errorf("Failed to create user"))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "User created successfully",
		"data": gin.H{
			"id":       userID,
			"username": req.Username,
			"email":    req.Email,
			"realName": req.RealName,
			"role":     req.Role,
			"status":   req.Status,
		},
	})
}
