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
	t.Logf("title=%s\n%s", title, text)
}
