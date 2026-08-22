package api

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"database/sql"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// HandleLogout 处理用户退出登录请求。
// POST /api/auth/logout
// 当前实现：直接返回成功，不维护服务端会话状态（JWT无状态设计）。
// 解析Authorization头中的Bearer token以记录过期时间信息（备用）。
// 实际的登出逻辑由前端清除本地存储的token完成。
// 注意事项：由于JWT无法主动失效，token在过期前仍然有效，
// 如需强制失效，可在未来引入token黑名单机制。
func HandleLogout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusOK, gin.H{
			"code":    0,
			"message": "退出成功",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusOK, gin.H{
			"code":    0,
			"message": "退出成功",
		})
		return
	}

	// 解析 token 获取过期时间
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err == nil && token.Valid {
		// 获取 token 的过期时间
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "退出成功",
	})
}

// HandleGetLoginLogs 获取登录审计日志的分页列表。
// GET /api/auth/login-logs?page=1&pageSize=20&username=admin&ip=&result=
// 支持按用户名、IP地址、登录结果（success/failed）筛选。
// 每条日志自动附加IP地理位置信息（通过批量IP查询优化性能）。
// 智能IP处理：局域网IP标记为"局域网"，公网IP通过IP数据库查询归属地。
func HandleGetLoginLogs(c *gin.Context) {

	all := isAllAuditLogQuery(c)
	page, pageSize := 1, 0
	if !all {
		var err error
		page, pageSize, err = ValidatePaginationParams(c, 20, 100)
		if err != nil {
			BadRequestResponse(c, err.Error(), nil)
			return
		}
	}
	username := c.Query("username")
	ip := c.Query("ip")
	result := c.Query("result")

	// 构建查询条件
	whereClause := "1=1"
	args := []interface{}{}

	if username != "" {
		whereClause += " AND username LIKE ?"
		args = append(args, "%"+username+"%")
	}
	if ip != "" {
		whereClause += " AND ip_address LIKE ?"
		args = append(args, "%"+ip+"%")
	}
	if result != "" {
		whereClause += " AND login_result = ?"
		args = append(args, result)
	}

	// 查询总数
	var total int
	countQuery := "SELECT COUNT(*) FROM login_logs WHERE " + whereClause
	if err := database.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		logger.Error("查询登录日志总数失败: %v", err)
		InternalServerErrorResponse(c, "查询失败", err)
		return
	}

	// 查询日志列表
	query := "SELECT id, username, ip_address, user_agent, login_result, failure_reason, CAST(created_at AS TEXT) FROM login_logs WHERE " + whereClause + " ORDER BY created_at DESC"
	queryArgs := args
	if !all {
		offset := (page - 1) * pageSize
		query += " LIMIT ? OFFSET ?"
		queryArgs = append(args, pageSize, offset)
	}

	rows, err := database.DB.Query(query, queryArgs...)
	if err != nil {
		logger.Error("查询登录日志失败: %v", err)
		InternalServerErrorResponse(c, "查询失败", err)
		return
	}
	defer rows.Close()

	logs := []gin.H{}
	ipSet := make(map[string]bool) // 用于收集唯一的IP地址
	for rows.Next() {
		var id int
		var username, ipAddress, userAgent, loginResult, failureReason sql.NullString
		var createdAt sql.NullString

		err := rows.Scan(&id, &username, &ipAddress, &userAgent, &loginResult, &failureReason, &createdAt)
		if err != nil {
			logger.Error("扫描登录日志失败: %v", err)
			continue
		}

		// 收集IP地址用于批量查询
		if ipAddress.Valid && ipAddress.String != "" {
			ipSet[ipAddress.String] = true
		}

		// 统一格式化时间，确保返回给前端的是 "2006-01-02 15:04:05" 格式
		// 数据库驱动可能返回 ISO 8601 格式（如 "2026-01-08T09:06:19Z"），需要转换为标准格式
		formattedTime := utils.FormatNullTimeStringForDisplay(createdAt)

		log := gin.H{
			"id":      id,
			"ip":      ipAddress.String,
			"result":  loginResult.String,
			"created": formattedTime,
		}

		if username.Valid {
			log["username"] = username.String
		} else {
			log["username"] = ""
		}

		if userAgent.Valid {
			log["userAgent"] = userAgent.String
		} else {
			log["userAgent"] = ""
		}

		if failureReason.Valid {
			log["failureReason"] = failureReason.String
		} else {
			log["failureReason"] = ""
		}

		logs = append(logs, log)
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
					// 构建位置字符串：国家 > 省/地区 > 城市 > 区县
					locationStr := buildLocationString(location)
					ipLocationMap[ip] = locationStr
				}
			}
		}
	}

	// 为每个日志添加位置信息
	for i := range logs {
		if ip, ok := logs[i]["ip"].(string); ok && ip != "" {
			// 先检查是否为局域网IP
			if isLocalNetworkIP(ip) {
				logs[i]["location"] = "局域网"
			} else if location, ok := ipLocationMap[ip]; ok {
				logs[i]["location"] = location
			} else {
				logs[i]["location"] = "未知"
			}
		} else {
			logs[i]["location"] = "未知"
		}
	}

	if all {
		pageSize = total
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"list":     logs,
			"total":    total,
			"page":     page,
			"pageSize": pageSize,
		},
	})
}

// HandleClearLoginLogs 清空登录审计日志。
// DELETE /api/v1/system/login-logs
func HandleClearLoginLogs(c *gin.Context) {
	result, err := database.DB.Exec("DELETE FROM login_logs")
	if err != nil {
		logger.Error("清空登录日志失败: %v", err)
		InternalServerErrorResponse(c, "清空登录日志失败", err)
		return
	}
	deleted, _ := result.RowsAffected()
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "登录日志已清空",
		"data": gin.H{
			"deleted": deleted,
		},
	})
}

// 封禁相关函数已全部删除

// - string: 格式化后的位置字符串，如果所有字段都无效则返回"未知"
func buildLocationString(location *service.IPLocation) string {
	parts := []string{}

	// 按照正常行政层级展示：国家 > 省/地区 > 城市 > 区县。
	if location.Country != "" && location.Country != "未知" {
		parts = append(parts, location.Country)
	}
	if location.Province != "" && location.Province != "未知" {
		parts = append(parts, location.Province)
	}
	if location.City != "" && location.City != "未知" {
		parts = append(parts, location.City)
	}
	if location.District != "" && location.District != "未知" {
		parts = append(parts, location.District)
	}

	if len(parts) == 0 {
		return "未知"
	}

	// 使用 > 分隔符连接
	return strings.Join(parts, " > ")
}

// HandleGetSM2PublicKey 返回SM2加密算法的公钥给前端。
// GET /api/auth/sm2-public-key
func HandleGetSM2PublicKey(c *gin.Context) {
	publicKey := utils.GetSM2PublicKey()
	if publicKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    1,
			"message": "公钥未初始化",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"publicKey": publicKey,
		},
		"message": "获取成功",
	})
}

// formatTimeForAPI 将数据库中的时间字符串统一格式化为 "2006-01-02 15:04:05" 格式。
// 委托到 utils/timeutil.FormatTimeStringForDisplay 处理所有时间格式解析。
//   - string: 格式化后的 "2006-01-02 15:04:05" 格式时间字符串，空字符串返回空
func formatTimeForAPI(timeStr string) string {
	if timeStr == "" {
		return ""
	}
	return utils.FormatTimeStringForDisplay(timeStr)
}
