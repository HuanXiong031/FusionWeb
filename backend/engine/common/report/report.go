// ========================================
// report/report.go — HTML 报告生成与写入模块
//
// 功能概述：
//
//	负责将 Nuclei 扫描结果生成为 HTML 格式的漏洞报告，
//	支持增量追加写入，每条漏洞结果在发现时实时追加到报告文件。
//
// 核心函数：
//   - GenerateHTMLReportHeader: 初始化报告文件，写入 HTML 头部和样式
//   - AddResultByResultEvent: 将单条扫描结果追加写入报告
//   - writeFile: 底层文件写入函数（追加模式）
//   - getSeverity: 严重等级枚举值到字符串的映射
//
// 报告文件命名：
//   - 若未配置 ReportName，则使用当前 Unix 时间戳命名（如 "1716393600.html"）
//   - 可通过 GlobalConfig.ReportName 自定义文件名
//
// 报告内容结构：
//   - 每条漏洞为一个表格条目，包含：
//     - 序号、模板ID、严重等级、目标URL
//     - 漏洞名称、作者、描述、参考链接
//     - 原始请求和响应数据（可展开/收起）
//   - 支持按严重等级过滤和关键词搜索（通过 default.go 的 JS 实现）
//
// 集成关系：
//   - 调用 default.go 的 defaultHeader() 生成 HTML 头部
//   - 调用 default.go 的 xssfilter() 进行安全转义
//   - 被 Nuclei 扫描回调函数调用（每个漏洞结果追加一条报告条目）
//   - 使用 structs.GlobalConfig.ReportName 作为报告文件路径
//
// ========================================
package report

import (
	"FusionWeb/backend/core/ddout"
	"FusionWeb/backend/core/structs"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func getSeverity(s severity.Severity) string {
	// getSeverity 将 nuclei 的 Severity 映射为用于展示的字符串。
	if s == severity.Info {
		return "Info"
	} else if s == severity.Low {
		return "Low"
	} else if s == severity.Medium {
		return "Medium"
	} else if s == severity.High {
		return "High"
	} else if s == severity.Critical {
		return "Critical"
	} else if s == severity.Unknown {
		return "Unknown"
	}
	return "Unknown"
}

func writeFile(result string, filename string) {
	// writeFile 以追加模式写入文本到指定文件，用于报告落盘。
	var text = []byte(result)
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	_, err = fl.Write(text)
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

// ReportIndex 报告条目的自增计数器，用于在页面中显示序号。
var ReportIndex = 1

func GenerateHTMLReportHeader() {
	// GenerateHTMLReportHeader 生成并写入 HTML 报告的头部。
	// 若未配置 `structs.GlobalConfig.ReportName`，将使用时间戳命名。
	if structs.GlobalConfig.ReportName == "" {
		structs.GlobalConfig.ReportName = strconv.Itoa(int(time.Now().Unix())) + ".html"
	}
	showData := defaultHeader()
	writeFile(showData, structs.GlobalConfig.ReportName)
}

func AddResultByResultEvent(result output.ResultEvent) {
	// AddResultByResultEvent 将 nuclei 的 ResultEvent 追加到 HTML 报告。
	// 同时标准化控制台展示：显示 `[TemplateID(:MatcherName)] [Severity] URL`。
	// 参数 `result` 为 nuclei 输出的单条事件。
	if structs.GlobalConfig.ReportName == "" {
		return
	}

	b, e := json.Marshal(result)
	if e == nil {
		// 控制台仅显示 TemplateID:MatcherName（若有），不再显示模板名称
		tpl := result.TemplateID
		if result.MatcherName != "" {
			tpl = tpl + ":" + result.MatcherName
		}
		show := fmt.Sprintf("[%s] [%s] %v", tpl,
			result.Info.SeverityHolder.Severity.String(),
			result.Matched)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:   "Nuclei",
			Nuclei: string(b),
			Show:   show,
		})
	}

	severityString := getSeverity(result.Info.SeverityHolder.Severity)

	title := fmt.Sprintf(`<table>
    <thead class="vuln-head" onclick="$(this).next('tbody').toggle()">
        <td class="vuln">%03d&nbsp;&nbsp;%s</td>
        <td class="security %s">%s</td>
        <td class="url">%s</td>
    </thead>`, ReportIndex, result.TemplateID, strings.ToLower(severityString), strings.ToUpper(severityString), result.Host)

	info := fmt.Sprintf("<b>name:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>author:</b> %s&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>security:</b> %s",
		result.Info.Name, result.Info.Authors.String(), severityString,
	)
	if len(result.Info.Description) > 0 {
		info += "<br/><b>description:</b> " + result.Info.Description
	}

	if result.Info.Reference != nil && len(result.Info.Reference.ToSlice()) > 0 {
		info += "<br/><b>reference:</b> "
		for _, rv := range result.Info.Reference.ToSlice() {
			info += "<br/>&nbsp;&nbsp;- <a href='" + rv + "' target='_blank'>" + rv + "</a>"
		}
	}

	header := "<tbody>"

	bodyinfo := fmt.Sprintf(`<tr>
			<td colspan="3">%s</td>
		</tr>`, info)

	fullurl := xssfilter(result.Matched)

	footer := "</tbody></table>"
	d := title + header + bodyinfo

	urlShow := `<tr>
        <td colspan="3"  style="border-top:1px solid #000000"><a href="` + fullurl + `" target="_blank">` + fullurl + `</a></td>
    </tr><tr>`

	bodyHeader := `
			<td colspan="3" style="background: transparent; color: #111;">
				<div class="clr">
				<div class="request w50">
				<div class="toggleR" onclick="$(this).parent().next('.response').toggle();if($(this).text()=='→'){$(this).text('←');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('→');$(this).css('background','#223b46');$(this).parent().removeClass('w100').addClass('w50')}">→</div>
<xmp>%s</xmp>
				</div>
				<div class="response w50">
				<div class="toggleL" onclick="$(this).parent().prev('.request').toggle();if($(this).text()=='←'){$(this).text('→');$(this).css('background','red');$(this).parent().removeClass('w50').addClass('w100')}else{$(this).text('←');$(this).css('background','#223b46');$(this).parent().removeClass('w100').addClass('w50')}">←</div>
<xmp>%s</xmp>
				</div>
			</div>
			</td>
		</tr>
	`

	// Use Request and Response directly in newer version
	body := urlShow + fmt.Sprintf(bodyHeader, result.Request, result.Response)
	d += body

	d += footer

	writeFile(d, structs.GlobalConfig.ReportName)

	ReportIndex += 1
}
