package service

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

const fusionWebHTMLReportCSS = `*{box-sizing:border-box}
body{margin:0;background:#eef2f6;color:#17202a;font-family:"Microsoft YaHei",Arial,sans-serif}
.page{max-width:1240px;margin:0 auto;padding:26px}
.top{background:#fff;border:1px solid #d7dfe8;border-radius:8px;padding:26px;display:flex;justify-content:space-between;gap:20px;align-items:flex-end}
.top h1{margin:0;font-size:32px;letter-spacing:0}
.sub{color:#64748b;margin-top:8px}
.stamp{border:1px solid #cbd5e1;border-radius:6px;padding:10px 14px;color:#334155;background:#f8fafc;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:16px 0}
.card{background:#fff;border:1px solid #dbe3ec;border-radius:8px;padding:18px}
.num{font-size:30px;font-weight:800;color:#0f766e}
.label{font-size:13px;color:#64748b}
.section{background:#fff;border:1px solid #d7dfe8;border-radius:8px;margin-top:16px;padding:20px}
.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.section-tools{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}
h2{margin:0;font-size:20px;letter-spacing:0}
.hint{color:#64748b;font-size:13px}
.bar{height:8px;background:#e5e7eb;border-radius:10px;overflow:hidden;display:flex}
.bar i{display:block}
.bar .critical{background:#dc2626}.bar .high{background:#ef4444}.bar .medium{background:#f59e0b}.bar .low{background:#22c55e}.bar .info{background:#2563eb}.bar .unknown{background:#64748b}
table{width:100%;border-collapse:collapse;border:1px solid #e2e8f0}
th{background:#f1f5f9;color:#334155;text-align:left;font-size:13px}
td,th{padding:11px;border:1px solid #e2e8f0;vertical-align:top}
tr:hover td{background:#f8fafc}
a{color:inherit;text-decoration:none}
a:hover{color:#2563eb;text-decoration:none}
.mono{font-family:Consolas,Monaco,"Courier New",monospace}
.url{word-break:break-all;overflow-wrap:anywhere}
.toolbar{display:flex;gap:8px;flex-wrap:wrap}
.module-search{width:220px;max-width:100%;border:1px solid #cbd5e1;border-radius:6px;padding:8px 10px;color:#334155;background:#fff}
.module-search:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
.filter{border:1px solid #cbd5e1;background:#fff;color:#334155;border-radius:6px;padding:7px 11px;cursor:pointer}
.filter:hover{border-color:#2563eb;color:#2563eb}
.filter.active{background:#2563eb;border-color:#2563eb;color:#fff}
.badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:12px;font-weight:700;margin-right:8px}
.sev-critical{background:#fee2e2;color:#7f1d1d}
.sev-high{background:#fee2e2;color:#991b1b}
.sev-medium{background:#ffedd5;color:#9a3412}
.sev-low{background:#dcfce7;color:#166534}
.sev-info{background:#dbeafe;color:#1e40af}
.sev-unknown{background:#e2e8f0;color:#334155}
.vuln-list{display:grid;gap:12px}
.vuln-item{border:1px solid #dbe3ec;border-radius:8px;overflow:hidden;background:#fff}
.vuln-title{width:100%;border:0;display:flex;justify-content:space-between;gap:12px;align-items:center;padding:13px 14px;background:#f8fafc;border-bottom:1px solid #e2e8f0;text-align:left;cursor:pointer}
.vuln-title:hover{background:#eef2f7}
.vuln-title strong{font-size:16px;overflow-wrap:anywhere}
.vuln-time{color:#64748b;font-size:13px;white-space:nowrap}
.vuln-body{display:none;padding:14px}
.vuln-item.open .vuln-body{display:block}
.kv{display:grid;grid-template-columns:110px 1fr;gap:8px;padding:7px 0;border-bottom:1px dashed #e2e8f0}
.kv b{color:#475569}
.kv span{line-height:1.55;overflow-wrap:anywhere}
.packet-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px;align-items:stretch}
.packet{display:flex;flex-direction:column;min-height:0}
.packet h4{margin:0;background:#334155;color:#fff;border-radius:6px 6px 0 0;padding:8px 10px;font-size:13px}
.code-box{display:grid;grid-template-columns:50px 1fr;grid-auto-rows:min-content;background:#111827;color:#e5e7eb;border-radius:0 0 6px 6px;overflow:auto;height:360px;font-family:Consolas,Monaco,"Courier New",monospace;font-size:13px;line-height:1.5}
.line-no{background:#0f172a;color:#94a3b8;text-align:right;padding:0 10px;user-select:none}
.line-code{padding:0 12px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word}
.fingerprint-tags{display:flex;flex-wrap:wrap;gap:8px}
.fingerprint-tag{display:inline-block;padding:4px 9px;background:#dcfce7;color:#166534;border:1px solid #bbf7d0;border-radius:999px;font-size:12px;font-weight:700}
.page-nav{display:flex;justify-content:center;align-items:center;gap:6px;margin-top:14px;flex-wrap:wrap}
.page-nav button{border:1px solid #cbd5e1;background:#fff;border-radius:6px;padding:6px 10px;cursor:pointer;color:#334155}
.page-nav button:hover{border-color:#2563eb;color:#2563eb}
.page-nav button.active{background:#2563eb;border-color:#2563eb;color:#fff}
.page-nav button:disabled{opacity:.45;cursor:not-allowed}
.page-info{font-size:13px;color:#64748b;margin-left:4px}
.filter-hidden,.search-hidden{display:none!important}
.footer{text-align:center;color:#64748b;font-size:13px;padding:22px}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.top{align-items:flex-start;flex-direction:column}.packet-grid{grid-template-columns:1fr}.vuln-title{align-items:flex-start;flex-direction:column}.vuln-time{white-space:normal}}`

const fusionWebHTMLReportScript = `<script>
function visibleItems(module){
	return Array.from(module.querySelectorAll(".page-item")).filter(function(item){
		return !item.classList.contains("filter-hidden") && !item.classList.contains("search-hidden");
	});
}
function setupPagination(module,page){
	var size=parseInt(module.dataset.pageSize,10)||10;
	var items=Array.from(module.querySelectorAll(".page-item"));
	var visible=visibleItems(module);
	var total=Math.max(1,Math.ceil(visible.length/size));
	var current=Math.min(Math.max(page||1,1),total);
	items.forEach(function(item){item.style.display="none"});
	visible.forEach(function(item,index){item.style.display=Math.floor(index/size)===current-1?"":"none"});
	var nav=module.querySelector(".page-nav");
	if(!nav)return;
	if(visible.length<=size){nav.innerHTML='<span class="page-info">共 '+visible.length+' 条</span>';return}
	var html='<button '+(current===1?'disabled':'')+' data-page="'+(current-1)+'">上一页</button>';
	for(var i=1;i<=total;i++){html+='<button class="'+(i===current?'active':'')+'" data-page="'+i+'">'+i+'</button>'}
	html+='<button '+(current===total?'disabled':'')+' data-page="'+(current+1)+'">下一页</button><span class="page-info">第 '+current+'/'+total+' 页，共 '+visible.length+' 条</span>';
	nav.innerHTML=html;
	nav.querySelectorAll("button").forEach(function(btn){btn.addEventListener("click",function(){setupPagination(module,parseInt(btn.dataset.page,10))})});
}
function initFilters(){
	var module=document.querySelector("#vuln-module");
	if(!module)return;
	document.querySelectorAll(".filter").forEach(function(btn){
		btn.addEventListener("click",function(){
			document.querySelectorAll(".filter").forEach(function(b){b.classList.remove("active")});
			btn.classList.add("active");
			var filter=btn.dataset.filter;
			module.querySelectorAll(".vuln-item").forEach(function(item){item.classList.toggle("filter-hidden",filter!=="all"&&item.dataset.severity!==filter)});
			setupPagination(module,1);
		});
	});
}
function initSearch(){
	document.querySelectorAll(".page-module").forEach(function(module){
		var input=module.querySelector(".module-search");
		if(!input)return;
		input.addEventListener("input",function(){
			var keyword=input.value.trim().toLowerCase();
			module.querySelectorAll(".page-item").forEach(function(item){item.classList.toggle("search-hidden",keyword!==""&&!item.textContent.toLowerCase().includes(keyword))});
			setupPagination(module,1);
		});
	});
}
function initVulnExpand(){
	document.querySelectorAll(".vuln-title").forEach(function(btn){
		btn.addEventListener("click",function(){btn.closest(".vuln-item").classList.toggle("open")});
	});
}
window.addEventListener("DOMContentLoaded",function(){
	document.querySelectorAll(".page-module").forEach(function(module){setupPagination(module,1)});
	initFilters();
	initSearch();
	initVulnExpand();
});
</script>`

// GenerateHTMLReport 生成 HTML 报告
func (s *ReportService) GenerateHTMLReport(outputPath string) error {
	data, err := s.CollectReportData()
	if err != nil {
		return err
	}

	html := s.buildHTMLContent(data)
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("写入 HTML 文件失败: %w", err)
	}
	if err := s.saveReportMetadata("html", outputPath); err != nil {
		return err
	}
	return nil
}

// buildHTMLContent 构建 dddd 风格的 HTML 报告页面。
func (s *ReportService) buildHTMLContent(data *ReportData) string {
	var html strings.Builder
	html.WriteString(fmt.Sprintf(`<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>FusionWeb 扫描报告</title>
	<style>%s</style>
</head>
<body>
<main class="page">
`, fusionWebHTMLReportCSS))

	writeHTMLTop(&html, data)
	writeHTMLStatsSection(&html, data)
	writeHTMLRiskSection(&html, data)

	portResults, infoResults := splitReportReconResults(data.ReconResults)
	writeHTMLReconSection(&html, infoResults)
	writeHTMLPortSection(&html, portResults)
	writeHTMLFingerprintSection(&html, data.Fingerprints)
	writeHTMLVulnSection(&html, data.Vulnerabilities)

	html.WriteString(`<div class="footer">Generated by FusionWeb</div>`)
	html.WriteString(fusionWebHTMLReportScript)
	html.WriteString(`
</main>
</body>
</html>
`)
	return html.String()
}

func writeHTMLTop(html *strings.Builder, data *ReportData) {
	taskName := "-"
	taskID := "-"
	if data != nil && data.TaskInfo != nil {
		taskName = data.TaskInfo.TaskName
		taskID = data.TaskInfo.TaskID
	}
	html.WriteString(fmt.Sprintf(`<header class="top">
	<div>
		<h1>FusionWeb 扫描报告</h1>
		<div class="sub">任务名称：%s</div>
	</div>
	<div class="stamp">任务ID：%s</div>
</header>
`, escapeHTML(taskName), escapeHTML(taskID)))
}

func writeHTMLStatsSection(html *strings.Builder, data *ReportData) {
	stats := data.Statistics
	html.WriteString(`<section class="cards">`)
	html.WriteString(fmt.Sprintf(`<div class="card"><div class="num">%d</div><div class="label">Web 服务</div></div>`, stats.URLCount))
	html.WriteString(fmt.Sprintf(`<div class="card"><div class="num">%d</div><div class="label">开放端口</div></div>`, stats.PortCount))
	html.WriteString(fmt.Sprintf(`<div class="card"><div class="num">%d</div><div class="label">指纹识别</div></div>`, stats.FingerprintCount))
	html.WriteString(fmt.Sprintf(`<div class="card"><div class="num">%d</div><div class="label">漏洞总数</div></div>`, stats.VulnCount))
	html.WriteString(fmt.Sprintf(`<div class="card"><div class="num">%d</div><div class="label">严重 / 高危</div></div>`, stats.CriticalCount+stats.HighCount))
	html.WriteString(`</section>`)
}

func writeHTMLRiskSection(html *strings.Builder, data *ReportData) {
	stats := data.Statistics
	unknown := unknownSeverityCount(data.Vulnerabilities)
	total := stats.CriticalCount + stats.HighCount + stats.MediumCount + stats.LowCount + stats.InfoCount + unknown

	html.WriteString(`<section class="section">`)
	html.WriteString(fmt.Sprintf(`<div class="section-head"><h2>风险概览</h2><span class="hint">严重 %d / 高危 %d / 中危 %d / 低危 %d / 信息 %d / 未知 %d</span></div>`,
		stats.CriticalCount, stats.HighCount, stats.MediumCount, stats.LowCount, stats.InfoCount, unknown))
	html.WriteString(`<div class="bar">`)
	html.WriteString(htmlRiskBar("critical", stats.CriticalCount, total))
	html.WriteString(htmlRiskBar("high", stats.HighCount, total))
	html.WriteString(htmlRiskBar("medium", stats.MediumCount, total))
	html.WriteString(htmlRiskBar("low", stats.LowCount, total))
	html.WriteString(htmlRiskBar("info", stats.InfoCount, total))
	html.WriteString(htmlRiskBar("unknown", unknown, total))
	html.WriteString(`</div></section>`)
}

func writeHTMLVulnSection(html *strings.Builder, vulnerabilities []VulnSummary) {
	if len(vulnerabilities) == 0 {
		return
	}

	html.WriteString(`<section class="section page-module" id="vuln-module" data-page-size="10"><div class="section-head"><h2>漏洞详情</h2></div>`)
	html.WriteString(`<div class="section-tools"><div class="toolbar"><button class="filter active" data-filter="all">全部</button><button class="filter" data-filter="critical">严重</button><button class="filter" data-filter="high">高危</button><button class="filter" data-filter="medium">中危</button><button class="filter" data-filter="low">低危</button><button class="filter" data-filter="info">信息</button><button class="filter" data-filter="unknown">未知</button></div><input class="module-search" type="search" placeholder="搜索漏洞"></div>`)
	html.WriteString(`<div class="vuln-list">`)

	for i, vuln := range vulnerabilities {
		sevClass := htmlNormalizeSeverity(vuln.Severity)
		displayName := strings.TrimSpace(vuln.Name)
		if displayName == "" {
			displayName = strings.TrimSpace(vuln.TemplateID)
		}
		if displayName == "" {
			displayName = "未命名漏洞"
		}

		templateInfo := strings.TrimSpace(vuln.TemplateID)
		if vuln.MatcherName != "" {
			templateInfo += " : " + strings.TrimSpace(vuln.MatcherName)
		}
		timeText := formatTimeString(vuln.Time)

		html.WriteString(fmt.Sprintf(`<article class="vuln-item page-item" data-severity="%s"><button class="vuln-title" type="button"><div><span class="badge sev-%s">%s</span><strong>%02d. %s</strong><span class="hint mono url"> [%s] %s</span></div><span class="vuln-time">%s</span></button><div class="vuln-body">`,
			sevClass, sevClass, htmlSeverityLabel(vuln.Severity), i+1, escapeHTML(displayName), escapeHTML(templateInfo), escapeHTML(vuln.Target), escapeHTML(timeText)))
		html.WriteString(htmlVulnKV("目标信息", vuln.Target, true))
		html.WriteString(htmlVulnKV("漏洞名称", displayName, false))
		html.WriteString(htmlVulnKV("模板名称", vuln.TemplateID, false))
		html.WriteString(htmlVulnKV("威胁类型", vuln.MatcherName, false))
		if strings.TrimSpace(vuln.Author) != "" {
			html.WriteString(htmlVulnKV("作者信息", vuln.Author, false))
		}
		if strings.TrimSpace(vuln.Tags) != "" {
			html.WriteString(htmlVulnKV("标签", vuln.Tags, false))
		}
		html.WriteString(htmlVulnKV("描述内容", vuln.Description, false))
		html.WriteString(htmlPacketGrid(vuln.Request, vuln.Response))
		html.WriteString(`</div></article>`)
	}

	html.WriteString(`</div><div class="page-nav"></div></section>`)
}

func writeHTMLPortSection(html *strings.Builder, ports []ReconSummary) {
	html.WriteString(`<section class="section page-module" data-page-size="10"><div class="section-head"><h2>端口服务</h2><input class="module-search" type="search" placeholder="搜索端口服务"></div>`)
	html.WriteString(`<table><thead><tr><th>序号</th><th>IP</th><th>端口</th><th>协议</th><th>服务</th><th>状态</th><th>Banner</th></tr></thead><tbody>`)
	if len(ports) == 0 {
		html.WriteString(`<tr class="page-item"><td colspan="7" class="hint">暂无端口服务</td></tr>`)
	}
	for i, r := range ports {
		host := r.Host
		port := r.Port
		if host == "" || port == "" {
			host, port = splitReportHostPort(r.Target)
		}
		protocol := defaultText(r.Protocol, "TCP")
		html.WriteString(fmt.Sprintf(`<tr class="page-item"><td>%02d</td><td class="mono url">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, escapeHTML(host), escapeHTML(port), escapeHTML(strings.ToUpper(protocol)), escapeHTML(r.Service), escapeHTML(r.Status), escapeHTML(r.Banner)))
	}
	html.WriteString(`</tbody></table><div class="page-nav"></div></section>`)
}

func writeHTMLReconSection(html *strings.Builder, results []ReconSummary) {
	if len(results) == 0 {
		return
	}
	html.WriteString(`<section class="section page-module" data-page-size="10"><div class="section-head"><h2>Web服务</h2><input class="module-search" type="search" placeholder="搜索Web服务"></div>`)
	html.WriteString(`<table><thead><tr><th>序号</th><th>目标</th><th>状态码</th><th>标题</th><th>长度</th><th>来源</th></tr></thead><tbody>`)
	for i, r := range results {
		statusCode := defaultText(r.StatusCode, "-")
		title := defaultText(r.Title, "-")
		length := defaultText(r.Length, "-")
		target := escapeHTML(r.Target)
		html.WriteString(fmt.Sprintf(`<tr class="page-item"><td>%02d</td><td class="url"><a href="%s" target="_blank">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, target, target, escapeHTML(statusCode), escapeHTML(title), escapeHTML(length), escapeHTML(r.Source)))
	}
	html.WriteString(`</tbody></table><div class="page-nav"></div></section>`)
}

func writeHTMLFingerprintSection(html *strings.Builder, fingerprints []FingerprintSummary) {
	if len(fingerprints) == 0 {
		return
	}

	fingerprintMap := make(map[string][]string)
	timeMap := make(map[string]string)
	for _, f := range fingerprints {
		target := strings.TrimSpace(f.Target)
		if target == "" {
			target = "-"
		}
		fp := strings.TrimSpace(f.Fingerprint)
		if fp == "" {
			continue
		}
		fingerprintMap[target] = append(fingerprintMap[target], fp)
		if _, ok := timeMap[target]; !ok {
			timeMap[target] = f.Time
		}
	}
	if len(fingerprintMap) == 0 {
		return
	}

	keys := make([]string, 0, len(fingerprintMap))
	for target := range fingerprintMap {
		keys = append(keys, target)
	}
	sort.Slice(keys, func(i, j int) bool { return timeMap[keys[i]] > timeMap[keys[j]] })

	html.WriteString(`<section class="section page-module" data-page-size="10"><div class="section-head"><h2>指纹识别</h2><input class="module-search" type="search" placeholder="搜索指纹"></div>`)
	html.WriteString(`<table><thead><tr><th>序号</th><th>目标</th><th>指纹</th><th>识别时间</th></tr></thead><tbody>`)
	for i, target := range keys {
		html.WriteString(fmt.Sprintf(`<tr class="page-item"><td>%02d</td><td class="mono url">%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, escapeHTML(target), htmlFingerprintTags(fingerprintMap[target]), escapeHTML(formatTimeString(timeMap[target]))))
	}
	html.WriteString(`</tbody></table><div class="page-nav"></div></section>`)
}

func splitReportReconResults(results []ReconSummary) ([]ReconSummary, []ReconSummary) {
	var ports []ReconSummary
	var info []ReconSummary
	for _, r := range results {
		if r.Type == "port" {
			ports = append(ports, r)
			continue
		}
		info = append(info, r)
	}
	return ports, info
}

func htmlRiskBar(class string, count, total int) string {
	if total == 0 {
		return fmt.Sprintf(`<i class="%s" style="width:0%%"></i>`, class)
	}
	width := float64(count) * 100 / float64(total)
	return fmt.Sprintf(`<i class="%s" style="width:%.2f%%"></i>`, class, width)
}

func unknownSeverityCount(vulnerabilities []VulnSummary) int {
	count := 0
	for _, vuln := range vulnerabilities {
		if htmlNormalizeSeverity(vuln.Severity) == "unknown" {
			count++
		}
	}
	return count
}

func htmlNormalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return "unknown"
	}
}

func htmlSeverityLabel(severity string) string {
	switch htmlNormalizeSeverity(severity) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return "未知"
	}
}

func htmlVulnKV(label, value string, mono bool) string {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	class := ""
	if mono {
		class = ` class="mono url"`
	}
	return fmt.Sprintf(`<div class="kv"><b>%s</b><span%s>%s</span></div>`, escapeHTML(label), class, escapeHTML(value))
}

func htmlPacketGrid(request, response string) string {
	if strings.TrimSpace(request) == "" && strings.TrimSpace(response) == "" {
		return ""
	}
	return fmt.Sprintf(`<div class="packet-grid"><div class="packet request"><h4>请求包</h4><div class="code-box">%s</div></div><div class="packet response"><h4>响应包</h4><div class="code-box">%s</div></div></div>`,
		formatCodeWithLineNumbersForHTML(request),
		formatCodeWithLineNumbersForHTML(response))
}

func formatCodeWithLineNumbersForHTML(content string) string {
	content = normalizeHTTPPacket(content)
	if strings.TrimSpace(content) == "" {
		content = "(空)"
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var html strings.Builder
	for i, line := range lines {
		if line == "" {
			line = " "
		}
		html.WriteString(fmt.Sprintf(`<div class="line-no">%d</div><div class="line-code">%s</div>`, i+1, escapeHTML(line)))
	}
	return html.String()
}

func htmlFingerprintTags(fingerprints []string) string {
	var html strings.Builder
	html.WriteString(`<div class="fingerprint-tags">`)
	for _, fp := range fingerprints {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		html.WriteString(fmt.Sprintf(`<span class="fingerprint-tag">%s</span>`, escapeHTML(fp)))
	}
	html.WriteString(`</div>`)
	return html.String()
}

func defaultText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
