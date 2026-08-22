// ip_query_handler.go - IP地址归属地查询HTTP接口
// 本文件提供IP地址地理定位查询的RESTful API，支持单个查询和批量查询。
// 功能包括：
//   1. 单个IP查询：返回国家、省份、城市、区县、ISP等信息
//   2. 批量IP查询：支持最多5000个IP同时查询，自动过滤无效IP
//   3. IP数据库重载：认证用户可手动触发IP数据库的热重载
//   4. IP数据库信息：查看当前使用的IP数据库元信息
// 底层依赖：IP地理位置数据库（通过service层封装）

package api

import (
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// isValidIP 使用Go标准库的net.ParseIP验证IP地址格式是否合法。
// 支持IPv4和IPv6两种格式。
// 参数:
//   - ip: 待验证的IP地址字符串
//
// 返回值:
//   - bool: true表示有效的IP地址格式
func isValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

// HandleQueryIP 查询单个IP地址的地理位置信息。
// GET /api/ip/query?ip=8.8.8.8
// 返回国家、省份、城市、区县、运营商等信息。
// 对无效IP格式和IP数据库未就绪等情况提供友好的中文错误提示。
func HandleQueryIP(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "IP地址不能为空",
		})
		return
	}

	// 去除空格
	ip = strings.TrimSpace(ip)

	// 验证IP地址格式
	if !isValidIP(ip) {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "IP地址格式不正确",
		})
		return
	}

	// 查询IP位置
	location, err := service.QueryIP(ip)
	if err != nil {
		logger.Error("查询IP %s 失败: %v", ip, err)
		errMsg := err.Error()
		// 提供更友好的错误提示
		if strings.Contains(errMsg, "文件不存在") {
			errMsg = "IP数据库文件不存在，请检查配置文件"
		} else if strings.Contains(errMsg, "加载失败") {
			errMsg = "IP数据库加载失败，请检查数据库文件格式"
		} else if strings.Contains(errMsg, "未加载") {
			errMsg = "IP数据库正在加载中，请稍后重试"
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    1,
			"message": "查询失败: " + errMsg,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": location,
	})
}

// HandleBatchQueryIPs 批量查询多个IP地址的地理位置信息。
// POST /api/ip/batch-query
// 请求体：{"ips": ["8.8.8.8", "1.1.1.1"]}
// 功能特点：
//   - 最多支持5000个IP同时查询
//   - 自动过滤无效格式的IP并记录警告日志
//   - 无效IP在结果中返回"IP地址格式错误"标记
//   - 返回map[IP地址]*IPLocation的映射
func HandleBatchQueryIPs(c *gin.Context) {
	var req struct {
		IPs []string `json:"ips" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	if len(req.IPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "IP地址列表不能为空",
		})
		return
	}

	// 限制批量查询数量
	if len(req.IPs) > 5000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "批量查询数量不能超过5000个",
		})
		return
	}

	// 验证每个IP地址格式（去除空格后验证）
	validIPs := make([]string, 0, len(req.IPs))
	invalidIPs := make([]string, 0)

	for _, ip := range req.IPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if isValidIP(ip) {
			validIPs = append(validIPs, ip)
		} else {
			invalidIPs = append(invalidIPs, ip)
		}
	}

	if len(validIPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    1,
			"message": "没有有效的IP地址",
		})
		return
	}

	// 如果有无效的IP，记录警告
	if len(invalidIPs) > 0 {
		logger.Warn("批量查询中发现无效IP地址: %v", invalidIPs)
	}

	// 批量查询IP位置
	results, err := service.QueryIPs(validIPs)
	if err != nil {
		logger.Error("批量查询IP失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    1,
			"message": "查询失败: " + err.Error(),
		})
		return
	}

	// 为无效的IP地址添加错误结果
	for _, ip := range invalidIPs {
		results[ip] = &service.IPLocation{
			IP:       ip,
			Country:  "IP地址格式错误",
			Province: "",
			City:     "",
			District: "",
			ISP:      "",
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": results,
	})
}

// HandleReloadIPDB 手动触发IP地理位置数据库的重新加载。
// POST /api/ip/reload
// 使用场景：IP数据库文件更新后，无需重启服务即可加载新数据。
// 注意：此操作是同步的，会等待数据库加载完成后才返回响应。
func HandleReloadIPDB(c *gin.Context) {

	// 同步重新加载数据库，等待加载完成
	logger.Info("开始重新加载IP数据库...")
	if err := service.ReloadIPDB(); err != nil {
		logger.Error("重新加载IP数据库失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    1,
			"message": "重新加载IP数据库失败: " + err.Error(),
		})
		return
	}

	logger.Info("IP数据库重新加载成功")
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "IP数据库重新加载成功",
	})
}

// HandleGetIPDBInfo 获取当前IP地理位置数据库的元信息。
// GET /api/ip/db-info
// 返回数据库版本、加载状态、数据条数等管理信息。
func HandleGetIPDBInfo(c *gin.Context) {
	info, err := service.GetIPDBInfo()
	if err != nil {
		logger.Error("获取IP数据库信息失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    1,
			"message": "获取数据库信息失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": info,
	})
}
