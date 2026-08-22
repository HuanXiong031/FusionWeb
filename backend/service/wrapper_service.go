// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件提供便捷的包装函数，简化常见操作（获取结果、验证漏洞、获取日志）的调用。
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"context"
	"fmt"
	"strings"
)

// GetScanResults 获取指定任务的所有漏洞扫描结果。
// 这是一个便捷包装函数，内部创建VulnService并调用其GetVulnResults方法。
//
// 参数:
//   - taskID: 任务唯一标识
//
// 返回值:
//   - []models.VulnResult: 漏洞结果列表
//   - error: 查询失败时返回错误
func GetScanResults(taskID string) ([]models.VulnResult, error) {
	vulnService := NewVulnService(taskID, context.Background())
	return vulnService.GetVulnResults()
}

// GetVulnerabilities 分页查询漏洞列表，支持按任务ID、严重程度、关键字筛选。
// 查询条件使用LIKE模糊匹配name、target、template_id字段。
//
// 参数:
//   - page: 页码（从1开始）
//   - pageSize: 每页数量
//   - taskID: 按任务ID筛选（空字符串表示不过滤）
//   - severity: 按严重程度筛选（空字符串表示不过滤）
//   - keyword: 关键字模糊搜索（空字符串表示不过滤）
//
// 返回值:
//   - []models.VulnResult: 漏洞结果列表
//   - int: 符合条件的总记录数
//   - error: 查询失败时返回错误
func GetVulnerabilities(page, pageSize int, taskID, severity, keyword string) ([]models.VulnResult, int, error) {
	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}

	whereClause := "WHERE 1=1"
	args := []interface{}{}

	if taskID != "" {
		whereClause += " AND task_id = ?"
		args = append(args, taskID)
	}

	if severity != "" {
		whereClause += " AND severity = ?"
		args = append(args, severity)
	}

	if keyword != "" {
		whereClause += " AND (name LIKE ? OR target LIKE ? OR template_id LIKE ?)"
		likeKw := "%" + keyword + "%"
		args = append(args, likeKw, likeKw, likeKw)
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM vuln_results " + whereClause
	var total int
	err := database.DB.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Query data
	query := `SELECT id, task_id, target, template_id, matcher_name, severity, 
		description, request, response, CAST(discovered_at AS TEXT), name, template_path, COALESCE(author, ''), COALESCE(tags, '')
		FROM vuln_results ` + whereClause + ` ORDER BY discovered_at DESC LIMIT ? OFFSET ?`

	args = append(args, pageSize, offset)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []models.VulnResult
	reportService := NewReportService(taskID)
	for rows.Next() {
		var result models.VulnResult
		var templatePath string
		var discoveredAt string
		// Note: database columns might differ slightly from struct, ensure order matches query
		if err := rows.Scan(&result.ID, &result.TaskID, &result.Target, &result.TemplateID,
			&result.MatcherName, &result.Severity, &result.Description, &result.Request,
			&result.Response, &discoveredAt, &result.Name, &templatePath, &result.Author, &result.Tags); err != nil {
			continue
		}
		if parsed, err := utils.ParseTimeString(discoveredAt); err == nil {
			result.DiscoveredAt = parsed
		}
		result.TemplatePath = templatePath
		applyPocMetadataToVulnResult(reportService, &result)
		results = append(results, result)
	}

	return results, total, nil
}

func applyPocMetadataToVulnResult(reportService *ReportService, result *models.VulnResult) {
	if reportService == nil || result == nil {
		return
	}
	meta := reportService.getPocMetadata(result.TemplatePath, result.TemplateID)
	if strings.TrimSpace(result.Name) == "" && meta.Name != "" {
		result.Name = meta.Name
	}
	if strings.TrimSpace(result.Author) == "" {
		result.Author = meta.Author
	}
	if strings.TrimSpace(result.Tags) == "" {
		result.Tags = meta.Tags
	}
	if strings.TrimSpace(result.Tags) == "" {
		result.Tags = result.MatcherName
	}
}

// VerifyVulnerability 验证指定漏洞是否仍然存在（当前为占位实现，仅检查数据库记录）。
// 后续可扩展为实际发送HTTP请求验证。
//
// 参数:
//   - vulnID: 漏洞记录ID
//
// 返回值:
//   - bool: true表示漏洞存在
//   - string: 验证结果消息
//   - error: 查询失败时返回错误
func VerifyVulnerability(vulnID int) (bool, string, error) {
	// 检查漏洞是否存在
	var exists bool
	err := database.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM vuln_results WHERE id = ?)", vulnID).Scan(&exists)
	if err != nil {
		return false, "", err
	}
	if !exists {
		return false, "Vulnerability not found", nil
	}
	return true, "Verified", nil
}

// GetTaskLog 获取任务日志。
func GetTaskLog(taskID string) (string, error) {
	if database.DB == nil {
		return "", fmt.Errorf("数据库未初始化")
	}

	rows, err := database.DB.Query(
		`SELECT CAST(created_at AS TEXT), level, stage, message
		   FROM task_logs
		  WHERE task_id = ?
		  ORDER BY created_at ASC, id ASC`,
		taskID,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var builder strings.Builder
	for rows.Next() {
		var createdAt, level, stage, message string
		if err := rows.Scan(&createdAt, &level, &stage, &message); err != nil {
			continue
		}
		createdAt = utils.FormatTimeStringForDisplay(createdAt)
		if stage != "" {
			builder.WriteString(fmt.Sprintf("[%s] [%s] [%s] %s\n", createdAt, level, stage, message))
		} else {
			builder.WriteString(fmt.Sprintf("[%s] [%s] %s\n", createdAt, level, message))
		}
	}
	return strings.TrimSpace(builder.String()), nil
}
