package service

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"


	"github.com/xuri/excelize/v2"
)

// GeneratePocHTMLReport 生成 HTML 报告
func (s *ReportService) GeneratePocHTMLReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	html := s.buildPocHTMLContent(data)

	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("写入 HTML 文件失败: %w", err)
	}

	// 保存元数据
	if err := s.saveReportMetadata("html", outputPath); err != nil {
		return err
	}

	return nil
}

// buildHTMLContent 构建 HTML 内容 (复用大部分样式，去掉信息收集/指纹部分)
func (s *ReportService) buildPocHTMLContent(data *ReportData) string {
	var html strings.Builder

	// 复用 ReportService 的样式，但这里我们需要自己构建，或者直接硬编码
	// 为了简化，这里直接嵌入简化的样式和结构
	html.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>FusionWeb POC扫描报告</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { font-family: 'Microsoft YaHei', Arial, sans-serif; background: #f5f5f5; padding: 20px; }
		.container { max-width: 1200px; margin: 0 auto; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		.header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; }
		.header h1 { font-size: 32px; margin-bottom: 10px; }
		.header .meta { opacity: 0.9; font-size: 14px; }
		.section { padding: 30px; border-bottom: 1px solid #eee; }
		.section:last-child { border-bottom: none; }
		.section-title { font-size: 24px; margin-bottom: 20px; color: #333; border-left: 4px solid #667eea; padding-left: 15px; }
		.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
		.stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
		.stat-card .label { font-size: 14px; color: #666; margin-bottom: 10px; }
		.stat-card .value { font-size: 32px; font-weight: bold; color: #667eea; }
		.severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-top: 20px; }
		.severity-card { padding: 15px; border-radius: 8px; text-align: center; color: white; }
		.severity-card.critical { background: #9b111e; }
		.severity-card.high { background: #ff4500; }
		.severity-card.medium { background: #ff8c00; }
		.severity-card.low { background: #ffd700; color: #333; }
		.severity-card.info { background: #4169e1; }
		.severity-card .label { font-size: 12px; opacity: 0.9; }
		.severity-card .value { font-size: 24px; font-weight: bold; margin-top: 5px; }
		.vuln-item { margin-bottom: 20px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
		.vuln-header { padding: 15px; background: #f8f9fa; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
		.vuln-header:hover { background: #e9ecef; }
		.vuln-time { white-space: nowrap; flex-shrink: 0; margin-left: 20px; font-size: 14px; color: #666; }
		.vuln-body { padding: 15px; display: none; }
		.vuln-body.active { display: block; }
		.request-response-wrapper { display: flex; gap: 20px; align-items: stretch; width: 100%; margin-top: 15px; }
		.request-response-item { flex: 1; display: flex; flex-direction: column; min-width: 0; }
		.http-header { background: #409eff; color: white; padding: 8px 15px; font-size: 14px; font-weight: 500; border-radius: 4px 4px 0 0; display: flex; align-items: center; }
		.http-header.response-header { background: #67c23a; }
		.code-container { background: #1f2933; border-radius: 0 0 4px 4px; overflow: hidden; flex: 1; display: flex; flex-direction: column; min-height: 360px; max-height: 70vh; }
		.code-content { flex: 1; overflow-x: auto; overflow-y: auto; font-family: 'Consolas', 'Monaco', 'Courier New', monospace; font-size: 13px; line-height: 1.7; background: #1f2933; }
		.code-line { display: flex; min-height: 22px; color: #e5e7eb; }
		.code-line:hover { background: #374151; }
		.line-number { flex-shrink: 0; width: 50px; padding: 0 10px; text-align: right; color: #9ca3af; background: #111827; border-right: 1px solid #374151; user-select: none; }
		.line-content { flex: 1; padding: 0 15px; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; text-align: left; color: #e5e7eb; }
		.badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; }
		.badge.critical { background: #9b111e; color: white; }
		.badge.high { background: #ff4500; color: white; }
		.badge.medium { background: #ff8c00; color: white; }
		.badge.low { background: #ffd700; color: #333; }
		.badge.info { background: #4169e1; color: white; }
		.footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
	</style>
	<script>
		function toggleVuln(id) {
			const body = document.getElementById('vuln-body-' + id);
			body.classList.toggle('active');
		}
	</script>
</head>
<body>
	<div class="container">
`)

	html.WriteString(fmt.Sprintf(`
		<div class="header">
			<h1>🔍 FusionWeb POC扫描报告</h1>
			<div class="meta">
				<p>任务名称: %s | 任务ID: %s</p>
			</div>
		</div>
`, escapeHTML(data.TaskInfo.TaskName), escapeHTML(data.TaskInfo.TaskID)))

	// 统计概览
	html.WriteString(fmt.Sprintf(`
		<div class="section">
			<h2 class="section-title">📊 统计概览</h2>
			<div class="stats-grid">
				<div class="stat-card">
					<div class="label">漏洞总数</div>
					<div class="value">%d</div>
				</div>
			</div>
			<div class="severity-grid">
				<div class="severity-card critical">
					<div class="label">严重</div>
					<div class="value">%d</div>
				</div>
				<div class="severity-card high">
					<div class="label">高危</div>
					<div class="value">%d</div>
				</div>
				<div class="severity-card medium">
					<div class="label">中危</div>
					<div class="value">%d</div>
				</div>
				<div class="severity-card low">
					<div class="label">低危</div>
					<div class="value">%d</div>
				</div>
				<div class="severity-card info">
					<div class="label">信息</div>
					<div class="value">%d</div>
				</div>
			</div>
		</div>
`, data.Statistics.VulnCount,
		data.Statistics.CriticalCount, data.Statistics.HighCount, data.Statistics.MediumCount,
		data.Statistics.LowCount, data.Statistics.InfoCount))

	// 漏洞详情
	if len(data.Vulnerabilities) > 0 {
		html.WriteString(fmt.Sprintf(`
		<div class="section">
			<h2 class="section-title">🐛 漏洞详情 (共 %d 个)</h2>
			<div id="vuln-list">
`, len(data.Vulnerabilities)))
		for i, vuln := range data.Vulnerabilities {
			matcherInfo := ""
			if vuln.MatcherName != "" {
				matcherInfo = fmt.Sprintf(" : %s", vuln.MatcherName)
			}

			displayName := vuln.Name
			if displayName == "" {
				displayName = vuln.TemplateID
			}

			html.WriteString(fmt.Sprintf(`
			<div class="vuln-item">
				<div class="vuln-header" onclick="toggleVuln(%d)">
						<div style="flex: 1; min-width: 0; padding-right: 15px;">
							<strong>%s</strong> <span style="font-size: 12px; color: #666;">(%s%s)</span> - <span class="badge %s">%s</span>
							<p style="margin-top: 5px; font-size: 14px; color: #333;">%s</p>
							<p style="margin-top: 2px; font-size: 12px; color: #999; word-break: break-all;">%s</p>
						</div>
						<div class="vuln-time">%s</div>
					</div>
				<div id="vuln-body-%d" class="vuln-body">
					<p style="word-break: break-all;"><strong>目标:</strong> %s</p>
					<p><strong>作者:</strong> %s</p>
					<p><strong>标签:</strong> %s</p>
					<p><strong>描述:</strong> %s</p>
					<div class="request-response-wrapper">
						<div class="request-response-item">
							<div class="http-header">
								<span style="margin-right: 5px;">📤</span>
								请求包
							</div>
							<div class="code-container">
								<div class="code-content">%s</div>
							</div>
						</div>
						<div class="request-response-item">
							<div class="http-header response-header">
								<span style="margin-right: 5px;">📥</span>
								响应包
							</div>
							<div class="code-container">
								<div class="code-content">%s</div>
							</div>
						</div>
					</div>
				</div>
			</div>
`, i, displayName, vuln.TemplateID, matcherInfo, vuln.Severity, strings.ToUpper(vuln.Severity),
				vuln.Description, vuln.Target, formatTimeString(vuln.Time), i, vuln.Target,
				vuln.Author, vuln.Tags, vuln.Description,
				formatHttpContentForHTML(vuln.Request), formatHttpContentForHTML(vuln.Response)))
		}
		html.WriteString(`
			</div>
		</div>
`)
	}

	// 页脚
	html.WriteString(`
		<div class="footer">
			<p>Generated by FusionWeb v1.0.0</p>
			<p>© 2025 FusionWeb Project</p>
		</div>
	</div>
</body>
</html>
`)

	return html.String()
}

// GeneratePocExcelReport 生成 Excel 报告
func (s *ReportService) GeneratePocExcelReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	f := excelize.NewFile()
	defer f.Close()

	// 创建样式
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 12, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"667EEA"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 16},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// 1. 概览表
	s.createPocOverviewSheet(f, data, headerStyle, titleStyle)

	// 2. 漏洞详情表
	if len(data.Vulnerabilities) > 0 {
		s.createPocVulnSheet(f, data, headerStyle)
	}

	// 保存文件
	if err := f.SaveAs(outputPath); err != nil {
		return fmt.Errorf("保存 Excel 文件失败: %w", err)
	}

	// 保存元数据
	if err := s.saveReportMetadata("excel", outputPath); err != nil {
		return err
	}

	return nil
}

// createOverviewSheet 创建概览表
func (s *ReportService) createPocOverviewSheet(f *excelize.File, data *ReportData, headerStyle, titleStyle int) {
	sheetName := "概览"
	f.SetSheetName("Sheet1", sheetName)

	// 标题
	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellValue(sheetName, "A1", "FusionWeb POC扫描报告")
	f.SetCellStyle(sheetName, "A1", "B1", titleStyle)
	f.SetRowHeight(sheetName, 1, 30)

	// 任务信息
	row := 3
	taskInfos := [][]interface{}{
		{"任务名称", data.TaskInfo.TaskName},
		{"任务ID", data.TaskInfo.TaskID},
	}

	for _, info := range taskInfos {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), info[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), info[1])
		row++
	}

	// 统计数据
	row += 2
	f.MergeCell(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row))
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "统计数据")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row), headerStyle)
	row++

	stats := [][]interface{}{
		{"漏洞总数", data.Statistics.VulnCount},
		{"严重漏洞", data.Statistics.CriticalCount},
		{"高危漏洞", data.Statistics.HighCount},
		{"中危漏洞", data.Statistics.MediumCount},
		{"低危漏洞", data.Statistics.LowCount},
		{"信息漏洞", data.Statistics.InfoCount},
	}

	for _, stat := range stats {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), stat[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), stat[1])
		row++
	}

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 20)
	f.SetColWidth(sheetName, "B", "B", 50)
}

// createVulnSheet 创建漏洞详情表
func (s *ReportService) createPocVulnSheet(f *excelize.File, data *ReportData, headerStyle int) {
	sheetName := "漏洞详情"
	_, _ = f.NewSheet(sheetName)

	// 表头
	headers := []string{"序号", "目标", "名称", "模板ID", "匹配器", "作者", "等级", "标签", "描述", "发现时间"}
	for i, h := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, h)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// 数据
	for i, vuln := range data.Vulnerabilities {
		row := i + 2
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), vuln.Target)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), vuln.Name)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), vuln.TemplateID)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), vuln.MatcherName)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), vuln.Author)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), strings.ToUpper(vuln.Severity))
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), vuln.Tags)
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), vuln.Description)
		f.SetCellValue(sheetName, fmt.Sprintf("J%d", row), formatTimeString(vuln.Time))
	}

	// 设置列宽
	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 30)
	f.SetColWidth(sheetName, "C", "C", 25)
	f.SetColWidth(sheetName, "D", "D", 25)
	f.SetColWidth(sheetName, "E", "E", 20)
	f.SetColWidth(sheetName, "F", "F", 15)
	f.SetColWidth(sheetName, "G", "G", 10)
	f.SetColWidth(sheetName, "H", "H", 20)
	f.SetColWidth(sheetName, "I", "I", 40)
	f.SetColWidth(sheetName, "J", "J", 20)
}

// GeneratePocJSONReport 生成 JSON 报告
func (s *ReportService) GeneratePocJSONReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入 JSON 文件失败: %w", err)
	}

	// 保存元数据
	if err := s.saveReportMetadata("json", outputPath); err != nil {
		return err
	}

	return nil
}

// GeneratePocMDReport 生成 Markdown 报告
func (s *ReportService) GeneratePocMDReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	var md strings.Builder

	// 标题
	md.WriteString("# FusionWeb POC扫描报告\n\n")
	md.WriteString(fmt.Sprintf("**任务名称**: %s\n\n", data.TaskInfo.TaskName))
	md.WriteString(fmt.Sprintf("**任务ID**: %s\n\n", data.TaskInfo.TaskID))
	md.WriteString("---\n\n")

	// 统计概览
	md.WriteString("## 📊 统计概览\n\n")
	md.WriteString(fmt.Sprintf("| 漏洞总数 | %d |\n", data.Statistics.VulnCount))
	md.WriteString("\n")

	// 漏洞等级分布
	md.WriteString("### 漏洞等级分布\n\n")
	md.WriteString("| 等级 | 数量 |\n")
	md.WriteString("|------|------|\n")
	md.WriteString(fmt.Sprintf("| 🔴 严重 | %d |\n", data.Statistics.CriticalCount))
	md.WriteString(fmt.Sprintf("| 🟠 高危 | %d |\n", data.Statistics.HighCount))
	md.WriteString(fmt.Sprintf("| 🟡 中危 | %d |\n", data.Statistics.MediumCount))
	md.WriteString(fmt.Sprintf("| 🟢 低危 | %d |\n", data.Statistics.LowCount))
	md.WriteString(fmt.Sprintf("| 🔵 信息 | %d |\n", data.Statistics.InfoCount))
	md.WriteString("\n---\n\n")

	// 漏洞详情
	if len(data.Vulnerabilities) > 0 {
		md.WriteString("## 🐛 漏洞详情\n\n")
		for i, vuln := range data.Vulnerabilities {
			displayName := vuln.Name
			if displayName == "" {
				displayName = vuln.TemplateID
			}
			md.WriteString(fmt.Sprintf("### %d. %s (%s)\n\n", i+1, displayName, vuln.TemplateID))

			if vuln.MatcherName != "" {
				md.WriteString(fmt.Sprintf("**匹配器**: %s\n\n", vuln.MatcherName))
			}

			if vuln.Author != "" {
				md.WriteString(fmt.Sprintf("**作者**: %s\n\n", vuln.Author))
			}

			if vuln.Tags != "" {
				md.WriteString(fmt.Sprintf("**标签**: %s\n\n", vuln.Tags))
			}

			md.WriteString(fmt.Sprintf("**目标**: `%s`\n\n", vuln.Target))
			md.WriteString(fmt.Sprintf("**等级**: **%s**\n\n", strings.ToUpper(vuln.Severity)))
			md.WriteString(fmt.Sprintf("**描述**: %s\n\n", vuln.Description))
			md.WriteString(fmt.Sprintf("**发现时间**: %s\n\n", formatTimeString(vuln.Time)))

			if vuln.Request != "" {
				md.WriteString("**请求**:\n\n")
				md.WriteString("```http\n")
				md.WriteString(formatPacket(vuln.Request))
				md.WriteString("\n```\n\n")
			}

			if vuln.Response != "" {
				md.WriteString("**响应**:\n\n")
				md.WriteString("```http\n")
				md.WriteString(formatPacket(vuln.Response))
				md.WriteString("\n```\n\n")
			}

			md.WriteString("---\n\n")
		}
	}

	md.WriteString("---\n\n")
	md.WriteString("*Generated by FusionWeb v1.0.0*\n")
	md.WriteString("*© 2025 FusionWeb Project*\n")

	if err := os.WriteFile(outputPath, []byte(md.String()), 0644); err != nil {
		return fmt.Errorf("写入 Markdown 文件失败: %w", err)
	}

	// 保存元数据
	if err := s.saveReportMetadata("md", outputPath); err != nil {
		return err
	}

	return nil
}

// saveReportMetadata 保存报告元数据

// 辅助函数

