// backend/service/report_logo_test.go
//
// 防回归：报告 HTML 必须内嵌 Logo（此前头部用的是手写 SVG「FV」占位图，
// 与产品真实 Logo 不一致；且外部图片引用在离线打开/导出 PDF 时会丢失）。
package service

import (
	"strings"
	"testing"
)

// 内嵌 logo 必须是可用的 PNG data URI。
func TestFusionWebReportLogoDataURI(t *testing.T) {
	uri := fusionWebReportLogoDataURI()
	if !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("logo 不是 PNG data URI：%q", uri[:min(40, len(uri))])
	}
	if len(uri) < 1000 {
		t.Fatalf("logo 数据过小，可能未正确内嵌（长度 %d）", len(uri))
	}
	// PNG magic 的 base64 前缀
	if !strings.HasPrefix(strings.TrimPrefix(uri, "data:image/png;base64,"), "iVBORw0KGgo") {
		t.Fatalf("logo 数据不是有效 PNG")
	}
}

// 任务报告头部必须包含内嵌 logo 的 <img>，且不再出现手写占位 SVG。
func TestReportHeaderEmbedsLogo(t *testing.T) {
	data := &ReportData{
		TaskInfo: &TaskInfo{TaskID: "task-1", TaskName: "测试任务"},
	}
	var b strings.Builder
	writeHTMLTop(&b, data)
	html := b.String()

	if !strings.Contains(html, "data:image/png;base64,") {
		t.Fatalf("报告头部未内嵌 logo：%s", html)
	}
	if !strings.Contains(html, `class="brand-logo"`) {
		t.Fatalf("报告头部缺少 brand-logo 容器：%s", html)
	}
	if strings.Contains(html, "fwLogoBg") {
		t.Fatalf("报告头部仍在用手写 SVG 占位 logo")
	}
	if !strings.Contains(html, "测试任务") {
		t.Fatalf("报告头部未渲染任务名称：%s", html)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
