// user_handler_batch.go - 用户批量操作HTTP接口处理层
// 本文件提供用户管理的批量操作功能，包括批量创建、Excel导出和导入模板下载。
// 设计目标：
//   1. 批量创建用户：支持一次性创建多个用户，自动生成密码、逐个验证和错误收集
//   2. Excel导出：生成格式化的用户列表Excel文件，包含最后登录和IP位置信息
//   3. 导入模板下载：提供标准化的Excel用户导入模板，含示例数据和列说明
// 访问模型：认证后可使用；角色字段保留给账户管理和导入导出格式。

package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
	"golang.org/x/crypto/bcrypt"
)

// HandleBatchCreateUsers 批量创建用户（仅admin角色可访问）。
// POST /api/users/batch
// 请求体：{"users": [{"username":"...", "password":"...", "email":"...", ...}]}
// 处理策略：
//   - 密码为空时自动生成20位随机强密码（包含大小写数字符号）
//   - 逐个用户创建，失败不中断后续用户的处理
//   - 收集所有错误信息并统一返回（包括行号、用户名、失败原因）
//   - 角色和状态值支持中英文输入（如"管理员"=>"admin"，"禁用"=>"disabled"）
//
// 权限：仅admin角色
func HandleBatchCreateUsers(c *gin.Context) {

	var req struct {
		Users []struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password"`
			Email    string `json:"email"`
			RealName string `json:"realName"`
			Role     string `json:"role"`
			Status   string `json:"status"`
		} `json:"users" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c, http.StatusBadRequest, "Invalid request", err)
		return
	}

	if len(req.Users) == 0 {
		ErrorResponse(c, http.StatusBadRequest, "用户列表为空", fmt.Errorf("Users list is empty"))
		return
	}

	var successCount int
	var failCount int
	var errors []string

	// 生成随机密码的函数
	generateRandomPassword := func() string {
		const lowercase = "abcdefghijklmnopqrstuvwxyz"
		const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		const numbers = "0123456789"
		const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		const allChars = lowercase + uppercase + numbers + symbols

		password := ""
		password += string(lowercase[time.Now().UnixNano()%int64(len(lowercase))])
		password += string(uppercase[time.Now().UnixNano()%int64(len(uppercase))])
		password += string(numbers[time.Now().UnixNano()%int64(len(numbers))])
		password += string(symbols[time.Now().UnixNano()%int64(len(symbols))])

		for i := len(password); i < 20; i++ {
			password += string(allChars[time.Now().UnixNano()%int64(len(allChars))])
		}

		// 打乱字符顺序
		runes := []rune(password)
		for i := len(runes) - 1; i > 0; i-- {
			j := time.Now().UnixNano() % int64(i+1)
			runes[i], runes[j] = runes[j], runes[i]
		}
		return string(runes)
	}

	for i, userReq := range req.Users {
		// 去除用户名和密码的首尾空格
		userReq.Username = strings.TrimSpace(userReq.Username)
		userReq.Password = strings.TrimSpace(userReq.Password)

		// 如果没有提供密码，自动生成
		password := userReq.Password
		if password == "" {
			password = generateRandomPassword()
		}

		// 验证密码强度
		if valid, msg := validatePasswordStrength(password); !valid {
			failCount++
			errors = append(errors, fmt.Sprintf("第%d行用户 %s: %s", i+1, userReq.Username, msg))
			continue
		}

		// 检查用户名是否已存在
		var count int
		err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", userReq.Username).Scan(&count)
		if err != nil {
			failCount++
			errors = append(errors, fmt.Sprintf("第%d行用户 %s: 检查用户名失败", i+1, userReq.Username))
			continue
		}
		if count > 0 {
			failCount++
			errors = append(errors, fmt.Sprintf("第%d行用户 %s: 用户名已存在", i+1, userReq.Username))
			continue
		}

		// 加密密码
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			failCount++
			errors = append(errors, fmt.Sprintf("第%d行用户 %s: 密码加密失败", i+1, userReq.Username))
			continue
		}

		// 设置默认值并处理中英文值
		role := strings.ToLower(strings.TrimSpace(userReq.Role))
		if role == "" || (role != "admin" && role != "管理员") {
			role = "user"
		} else if role == "管理员" {
			role = "admin"
		}

		status := strings.ToLower(strings.TrimSpace(userReq.Status))
		if status == "" || (status != "disabled" && status != "禁用") {
			status = "active"
		} else if status == "禁用" {
			status = "disabled"
		}

		// 根据密码强度设置 must_change_password
		// 批量创建时已经验证了密码强度，所以创建成功的用户密码都符合要求，设置为 0
		mustChangePassword := 0

		// 创建用户
		_, err = database.DB.Exec(`
			INSERT INTO users (username, password, email, real_name, role, status, must_change_password)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, userReq.Username, string(hashedPassword), userReq.Email, userReq.RealName, role, status, mustChangePassword)

		if err != nil {
			failCount++
			errStr := err.Error()
			if strings.Contains(errStr, "UNIQUE constraint failed") || strings.Contains(errStr, "duplicate key") {
				errors = append(errors, fmt.Sprintf("第%d行用户 %s: 用户名已存在", i+1, userReq.Username))
			} else {
				errors = append(errors, fmt.Sprintf("第%d行用户 %s: 创建失败 - %v", i+1, userReq.Username, err))
			}
			continue
		}

		successCount++
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": fmt.Sprintf("批量创建完成：成功 %d 个，失败 %d 个", successCount, failCount),
		"data": gin.H{
			"success": successCount,
			"failed":  failCount,
			"errors":  errors,
		},
	})
}

// HandleExportUsers 导出用户列表为格式化的Excel文件（仅admin角色可访问）。
// GET /api/users/export
// 导出内容包含：
//   - 基本资料：ID、用户名、邮箱、真实姓名、角色、状态、创建时间
//   - 登录信息：最后登录时间、登录IP、IP地理位置（通过批量查询获取）
//
// Excel格式：
//   - 表头使用品牌色背景（#667EEA）白字加粗，居中显示
//   - 角色和状态自动转换为中文显示（admin=>管理员, user=>普通用户）
//   - 列宽根据内容自适应设置
//   - 文件名格式：users_export_20260101_120000.xlsx
//
// 权限：仅admin角色
func HandleExportUsers(c *gin.Context) {

	// 查询所有用户（按ID升序排序），包含最后登录信息
	rows, err := database.DB.Query(`
		SELECT 
			u.id, u.username, u.email, u.real_name, u.role, u.status, CAST(u.created_at AS TEXT),
			(SELECT CAST(created_at AS TEXT) FROM login_logs 
			 WHERE username = u.username AND login_result = 'success' 
			 ORDER BY created_at DESC LIMIT 1) as last_login_time,
			(SELECT ip_address FROM login_logs 
			 WHERE username = u.username AND login_result = 'success' 
			 ORDER BY created_at DESC LIMIT 1) as last_login_ip
		FROM users u
		ORDER BY u.id ASC
	`)
	if err != nil {
		logger.Error("查询用户列表失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "查询用户列表失败", fmt.Errorf("Failed to query users"))
		return
	}
	defer rows.Close()

	// 创建 Excel 文件
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			logger.Error("关闭Excel文件失败: %v", err)
		}
	}()

	sheetName := "用户列表"
	index, err := f.NewSheet(sheetName)
	if err != nil {
		logger.Error("创建Sheet失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "创建Excel工作表失败", fmt.Errorf("Failed to create sheet"))
		return
	}
	f.SetActiveSheet(index)
	f.DeleteSheet("Sheet1")

	// 设置表头样式
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 12, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"667EEA"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// 设置表头
	headers := []string{"ID", "用户名", "邮箱", "真实姓名", "角色", "状态", "创建时间", "最后登录时间", "登录IP", "登录位置"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// 先读取所有数据，收集IP地址用于批量查询定位信息
	type userData struct {
		id            int
		username      string
		role          string
		status        string
		createdAt     sql.NullString
		emailNull     sql.NullString
		realNameNull  sql.NullString
		lastLoginTime sql.NullString
		lastLoginIP   sql.NullString
	}

	usersData := []userData{}
	ipSet := make(map[string]bool) // 用于收集唯一的IP地址

	for rows.Next() {
		var id int
		var username, role, status string
		var emailNull, realNameNull sql.NullString
		var createdAt, lastLoginTime sql.NullString
		var lastLoginIP sql.NullString

		if err := rows.Scan(&id, &username, &emailNull, &realNameNull, &role, &status, &createdAt,
			&lastLoginTime, &lastLoginIP); err != nil {
			logger.Error("扫描用户数据失败: %v", err)
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
			createdAt:     createdAt,
			emailNull:     emailNull,
			realNameNull:  realNameNull,
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

	// 写入数据
	rowNum := 2
	for _, user := range usersData {

		email := ""
		if user.emailNull.Valid {
			email = user.emailNull.String
		}
		realName := ""
		if user.realNameNull.Valid {
			realName = user.realNameNull.String
		}

		// 转换角色和状态显示
		roleDisplay := user.role
		if user.role == "admin" {
			roleDisplay = "管理员"
		} else {
			roleDisplay = "普通用户"
		}
		statusDisplay := user.status
		if user.status == "active" {
			statusDisplay = "启用"
		} else {
			statusDisplay = "禁用"
		}

		// 格式化ID为01、02这样的格式
		idFormatted := fmt.Sprintf("%02d", user.id)

		// 格式化时间为 2006-01-02 15:04:05 格式（使用统一的时间格式化工具）
		timeFormatted := utils.FormatNullTimeStringForDisplay(user.createdAt)

		// 格式化最后登录时间
		lastLoginTimeFormatted := utils.FormatNullTimeStringForDisplay(user.lastLoginTime)

		lastLoginIPStr := ""
		if user.lastLoginIP.Valid {
			lastLoginIPStr = user.lastLoginIP.String
		}

		// 获取IP定位信息
		locationStr := ""
		if user.lastLoginIP.Valid && user.lastLoginIP.String != "" {
			ip := user.lastLoginIP.String
			// 先检查是否为局域网IP
			if isLocalNetworkIP(ip) {
				locationStr = "局域网"
			} else if location, ok := ipLocationMap[ip]; ok {
				locationStr = location
			} else {
				locationStr = "未知"
			}
		}

		f.SetCellValue(sheetName, fmt.Sprintf("A%d", rowNum), idFormatted)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", rowNum), user.username)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", rowNum), email)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", rowNum), realName)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", rowNum), roleDisplay)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", rowNum), statusDisplay)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", rowNum), timeFormatted)
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", rowNum), lastLoginTimeFormatted)
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", rowNum), lastLoginIPStr)
		f.SetCellValue(sheetName, fmt.Sprintf("J%d", rowNum), locationStr)

		rowNum++
	}

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 10)
	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "C", 30)
	f.SetColWidth(sheetName, "D", "D", 20)
	f.SetColWidth(sheetName, "E", "E", 15)
	f.SetColWidth(sheetName, "F", "F", 15)
	f.SetColWidth(sheetName, "G", "G", 20)
	f.SetColWidth(sheetName, "H", "H", 20)
	f.SetColWidth(sheetName, "I", "I", 18)
	f.SetColWidth(sheetName, "J", "J", 50)

	// 将Excel文件写入响应
	fileName := fmt.Sprintf("users_export_%s.xlsx", utils.GetCurrentTimeString("20060102_150405"))

	// 设置响应头
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))

	// 将Excel文件写入响应
	if err := f.Write(c.Writer); err != nil {
		logger.Error("写入Excel文件失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "写入Excel文件失败", fmt.Errorf("Failed to write Excel file"))
		return
	}
}

// HandleDownloadUserImportTemplate 下载标准化的用户批量导入Excel模板（仅admin角色可访问）。
// GET /api/users/import-template
// 模板特点：
//   - 第一行：中文列名（用户名、密码、邮箱、真实姓名、角色、状态）
//   - 第二行：示例数据（方便用户理解各列的数据格式）
//   - 第三行起：详细说明文档（列出每列的填写规则和可选值）
//   - 列名兼容性：支持中英文列名（前端解析时自动识别）
//   - 文件名：user_import_template.xlsx
//
// 权限：仅admin角色
func HandleDownloadUserImportTemplate(c *gin.Context) {

	// 创建 Excel 文件
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			logger.Error("关闭Excel文件失败: %v", err)
		}
	}()

	sheetName := "用户导入模板"
	f.SetSheetName("Sheet1", sheetName)

	// 设置表头（使用中文列名，前端代码支持中英文列名）
	headers := []string{"用户名", "密码", "邮箱", "真实姓名", "角色", "状态"}

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E0E0E0"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// 第一行：中文列名（也支持英文列名：username, password, email, realName, role, status）
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 20) // 用户名
	f.SetColWidth(sheetName, "B", "B", 20) // 密码
	f.SetColWidth(sheetName, "C", "C", 30) // 邮箱
	f.SetColWidth(sheetName, "D", "D", 20) // 真实姓名
	f.SetColWidth(sheetName, "E", "E", 20) // 角色
	f.SetColWidth(sheetName, "F", "F", 20) // 状态

	// 添加示例数据（第二行）
	examples := []string{"user1", "password123", "user1@example.com", "张三", "user", "active"}
	for i, example := range examples {
		cell := fmt.Sprintf("%c2", 'A'+i)
		f.SetCellValue(sheetName, cell, example)
	}

	// 添加说明（第三行开始）
	f.SetCellValue(sheetName, "A3", "说明：")
	f.SetCellValue(sheetName, "A4", "1. 用户名（username）：必填，唯一，不能为空")
	f.SetCellValue(sheetName, "A5", "2. 密码（password）：可选，不填则自动生成")
	f.SetCellValue(sheetName, "A6", "3. 邮箱（email）：可选")
	f.SetCellValue(sheetName, "A7", "4. 真实姓名（realName）：可选")
	f.SetCellValue(sheetName, "A8", "5. 角色（role）：管理员/admin 或 普通用户/user，默认为 user")
	f.SetCellValue(sheetName, "A9", "6. 状态（status）：启用/active 或 禁用/disabled，默认为 active")
	f.SetCellValue(sheetName, "A10", "")
	f.SetCellValue(sheetName, "A11", "注意：列名支持中文或英文，角色和状态的值也支持中文或英文")

	// 设置响应头
	c.Header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	c.Header("Content-Disposition", "attachment; filename=user_import_template.xlsx")

	// 写入响应
	if err := f.Write(c.Writer); err != nil {
		logger.Error("写入Excel文件失败: %v", err)
		ErrorResponse(c, http.StatusInternalServerError, "生成模板失败", fmt.Errorf("Failed to generate template"))
		return
	}
}
