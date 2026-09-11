// backend/service/dingtalk_notify_text_test.go
//
// 防回归：Web 扫描完成通知的抬头必须与"实际是否有漏洞"一致。
// 背景：曾经把「⚠️ 发现安全漏洞，请及时处理！」写死，导致 0 漏洞也报警。
package service

import (
	"strings"
	"testing"

	"FusionWeb/backend/models"
)

func TestBuildWebScanDingTalkMessageWithoutVulns(t *testing.T) {
	// database.DB 为 nil：统计逻辑会安全跳过，等价于"没有任何漏洞记录"
	task := &models.TaskConfig{
		TaskID:      "test-no-vuln",
		TaskName:    "测试任务",
		TargetInput: "http://example.invalid",
		ScanMode:    "fingerprint_poc",
	}
	title, text := buildWebScanDingTalkMessage(task)

	if strings.Contains(text, "发现安全漏洞") {
		t.Fatalf("0 漏洞却出现告警文案：%s", text)
	}
	if strings.Contains(title, "发现安全漏洞") {
		t.Fatalf("0 漏洞却出现告警标题：%s", title)
	}
	if !strings.Contains(text, "未发现漏洞") {
		t.Fatalf("0 漏洞应明确说明未发现，实际：%s", text)
	}
	if !strings.Contains(text, "发现漏洞: 0 个") {
		t.Fatalf("统计行缺失或异常：%s", text)
	}
	// 0 漏洞时不应出现任何等级明细行（避免一堆 0 与图标尺寸不一致）
	for _, icon := range []string{"🔴", "🟠", "🟡", "🔵", "🟢", "🟤"} {
		if strings.Contains(text, icon) {
			t.Fatalf("0 漏洞却出现等级明细 %s：%s", icon, text)
		}
	}
	t.Logf("title=%s\n%s", title, text)
}

// 未知等级必须使用与其它等级同款同尺寸的大号圆（🟤），
// 而不是中等尺寸的 ⚫/⚪ 或单选按钮 🔘（钉钉里会小一圈、样式不一致）。
func TestSeverityDingIconUnknownUsesLargeCircle(t *testing.T) {
	icon, label := severityDingIcon("unknown")
	if label != "未知" {
		t.Fatalf("标签异常：%s", label)
	}
	if icon != "🟤" {
		t.Fatalf("未知等级图标应为大号圆 🟤，实际为 %q", icon)
	}
	for _, bad := range []string{"⚫", "⚪", "🔘"} {
		if icon == bad {
			t.Fatalf("未知等级不应使用中等尺寸图标 %s", bad)
		}
	}
	// 其它等级保持大号圆，确保整组尺寸一致
	for sev, want := range map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"} {
		if got, _ := severityDingIcon(sev); got != want {
			t.Fatalf("%s 图标应为 %s，实际 %s", sev, want, got)
		}
	}
}
