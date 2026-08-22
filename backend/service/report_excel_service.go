package service

import (
	"fmt"
	"sort"
	"strings"

	"FusionWeb/backend/utils"

	"github.com/xuri/excelize/v2"
)

// GenerateExcelReport 生成 dddd 风格的 Excel 扫描报告。
func (s *ReportService) GenerateExcelReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	f := excelize.NewFile()
	defer f.Close()

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 12, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"667EEA"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border:    reportExcelBorder(),
	})
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Size: 16},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
		Border:    reportExcelBorder(),
	})
	cellStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Vertical: "center", WrapText: true},
		Border:    reportExcelBorder(),
	})

	s.createOverviewSheet(f, data, headerStyle, titleStyle, cellStyle)

	if targets := reportTargetList(data); len(targets) > 0 {
		s.createTargetSheet(f, targets, headerStyle, cellStyle)
	}

	portResults, webResults := splitReportReconResults(data.ReconResults)
	if len(webResults) > 0 {
		s.createWebServiceSheet(f, webResults, headerStyle, cellStyle)
	}
	if len(data.Fingerprints) > 0 {
		s.createFingerprintSheet(f, data, headerStyle, cellStyle)
	}
	if len(data.Vulnerabilities) > 0 {
		s.createVulnSheet(f, data, headerStyle, cellStyle)
	}
	if len(portResults) > 0 {
		s.createPortServiceSheet(f, portResults, headerStyle, cellStyle)
	}

	if err := f.SaveAs(outputPath); err != nil {
		return fmt.Errorf("保存 Excel 文件失败: %w", err)
	}
	if err := s.saveReportMetadata("excel", outputPath); err != nil {
		return err
	}
	return nil
}

func (s *ReportService) createOverviewSheet(f *excelize.File, data *ReportData, headerStyle, titleStyle, cellStyle int) {
	sheetName := "概览"
	f.SetSheetName("Sheet1", sheetName)

	f.MergeCell(sheetName, "A1", "B1")
	f.SetCellValue(sheetName, "A1", "FusionWeb 扫描报告")
	f.SetCellStyle(sheetName, "A1", "B1", titleStyle)
	f.SetRowHeight(sheetName, 1, 30)

	row := 3
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "生成时间")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), utils.GetCurrentTimeString())
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row), cellStyle)

	row += 2
	f.MergeCell(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row))
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "统计数据")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row), headerStyle)
	row++

	stats := [][]interface{}{
		{"端口数量", data.Statistics.PortCount},
		{"URL数量", data.Statistics.URLCount},
		{"指纹数量", data.Statistics.FingerprintCount},
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
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row), cellStyle)
		row++
	}

	f.SetColWidth(sheetName, "A", "A", 20)
	f.SetColWidth(sheetName, "B", "B", 60)
}

func (s *ReportService) createTargetSheet(f *excelize.File, targets []string, headerStyle, cellStyle int) {
	sheetName := "目标"
	_, _ = f.NewSheet(sheetName)
	setExcelHeaders(f, sheetName, []string{"序号", "目标"}, headerStyle)

	for i, target := range targets {
		row := i + 2
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), target)
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("B%d", row), cellStyle)
	}
	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 60)
}

func (s *ReportService) createWebServiceSheet(f *excelize.File, results []ReconSummary, headerStyle, cellStyle int) {
	sheetName := "Web服务"
	_, _ = f.NewSheet(sheetName)
	setExcelHeaders(f, sheetName, []string{"序号", "目标", "状态码", "标题"}, headerStyle)

	for i, r := range results {
		row := i + 2
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), r.Target)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), defaultText(r.StatusCode, "-"))
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), defaultText(r.Title, "-"))
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("D%d", row), cellStyle)
	}
	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 50)
	f.SetColWidth(sheetName, "C", "C", 10)
	f.SetColWidth(sheetName, "D", "D", 40)
}

func (s *ReportService) createFingerprintSheet(f *excelize.File, data *ReportData, headerStyle, cellStyle int) {
	sheetName := "指纹识别"
	_, _ = f.NewSheet(sheetName)
	setExcelHeaders(f, sheetName, []string{"序号", "目标", "指纹"}, headerStyle)

	fingerprintMap := make(map[string][]string)
	for _, fp := range data.Fingerprints {
		target := strings.TrimSpace(fp.Target)
		if target == "" {
			target = "-"
		}
		fingerprint := strings.TrimSpace(fp.Fingerprint)
		if fingerprint == "" {
			continue
		}
		fingerprintMap[target] = append(fingerprintMap[target], fingerprint)
	}

	targets := make([]string, 0, len(fingerprintMap))
	for target := range fingerprintMap {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	for i, target := range targets {
		row := i + 2
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), target)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), strings.Join(fingerprintMap[target], ", "))
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("C%d", row), cellStyle)
	}
	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 50)
	f.SetColWidth(sheetName, "C", "C", 40)
}

func (s *ReportService) createVulnSheet(f *excelize.File, data *ReportData, headerStyle, cellStyle int) {
	sheetName := "漏洞详情"
	_, _ = f.NewSheet(sheetName)
	headers := []string{"序号", "目标信息", "名称", "结果", "模板名称", "等级", "作者信息", "描述内容", "发现时间"}
	setExcelHeaders(f, sheetName, headers, headerStyle)

	for i, vuln := range data.Vulnerabilities {
		row := i + 2
		displayName := strings.TrimSpace(vuln.Name)
		if displayName == "" {
			displayName = vuln.TemplateID
		}
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), vuln.Target)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), displayName)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), vuln.Target)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), vuln.TemplateID)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), strings.ToUpper(vuln.Severity))
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), defaultText(vuln.Author, "-"))
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), defaultText(vuln.Description, "-"))
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), formatTimeString(vuln.Time))
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("I%d", row), cellStyle)
	}

	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 35)
	f.SetColWidth(sheetName, "C", "C", 30)
	f.SetColWidth(sheetName, "D", "D", 45)
	f.SetColWidth(sheetName, "E", "E", 30)
	f.SetColWidth(sheetName, "F", "F", 10)
	f.SetColWidth(sheetName, "G", "G", 15)
	f.SetColWidth(sheetName, "H", "H", 40)
	f.SetColWidth(sheetName, "I", "I", 20)
}

func (s *ReportService) createPortServiceSheet(f *excelize.File, ports []ReconSummary, headerStyle, cellStyle int) {
	sheetName := "端口服务"
	_, _ = f.NewSheet(sheetName)
	setExcelHeaders(f, sheetName, []string{"序号", "IP", "端口", "协议", "服务"}, headerStyle)

	for i, r := range ports {
		row := i + 2
		host := r.Host
		port := r.Port
		if host == "" || port == "" {
			host, port = splitReportHostPort(r.Target)
		}
		protocol := defaultText(r.Protocol, "TCP")
		service := defaultText(r.Service, "-")
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), i+1)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), host)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), port)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), strings.ToUpper(protocol))
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), service)
		f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("E%d", row), cellStyle)
	}

	f.SetColWidth(sheetName, "A", "A", 8)
	f.SetColWidth(sheetName, "B", "B", 20)
	f.SetColWidth(sheetName, "C", "C", 10)
	f.SetColWidth(sheetName, "D", "D", 10)
	f.SetColWidth(sheetName, "E", "E", 25)
}

func setExcelHeaders(f *excelize.File, sheetName string, headers []string, headerStyle int) {
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheetName, cell, h)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}
}

func reportExcelBorder() []excelize.Border {
	return []excelize.Border{
		{Type: "left", Color: "E2E8F0", Style: 1},
		{Type: "top", Color: "E2E8F0", Style: 1},
		{Type: "right", Color: "E2E8F0", Style: 1},
		{Type: "bottom", Color: "E2E8F0", Style: 1},
	}
}

func reportTargetList(data *ReportData) []string {
	seen := make(map[string]struct{})
	var targets []string
	add := func(value string) {
		for _, item := range strings.FieldsFunc(value, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';'
		}) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			targets = append(targets, item)
		}
	}
	if data != nil && data.TaskInfo != nil {
		add(data.TaskInfo.Target)
	}
	return targets
}

func splitReportHostPort(target string) (string, string) {
	idx := strings.LastIndex(target, ":")
	if idx <= 0 || idx >= len(target)-1 {
		return target, ""
	}
	return strings.Trim(target[:idx], "[]"), target[idx+1:]
}
