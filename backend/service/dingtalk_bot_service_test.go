package service

import (
	"testing"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
)

func TestParseDingTalkTaskCommand(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		recognized bool
		message    string
		typ        string
		target     string
		ports      string
	}{
		{name: "web target", content: "web https://example.com", recognized: true, typ: "web", target: "https://example.com"},
		{name: "port target and ports", content: "@FusionBot port 10.0.0.1 --ports 80,443", recognized: true, typ: "port", target: "10.0.0.1", ports: "80,443"},
		{name: "Chinese subdomain", content: "子域名 example.com", recognized: true, typ: "subdomain", target: "example.com"},
		{name: "missing target is recognized", content: "web", recognized: true, message: "请提供扫描目标"},
		{name: "ordinary text", content: "帮我分析这个结果", recognized: false, message: "请输入：web <网址>、port <IP> [--ports 80,443] 或 subdomain <域名>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, recognized, message := ParseDingTalkTaskCommand(tt.content)
			if recognized != tt.recognized {
				t.Fatalf("recognized = %v, want %v", recognized, tt.recognized)
			}
			if message != tt.message {
				t.Fatalf("message = %q, want %q", message, tt.message)
			}
			if tt.typ != "" && cfg.TaskType != tt.typ {
				t.Fatalf("task type = %q, want %q", cfg.TaskType, tt.typ)
			}
			if tt.target != "" && cfg.TargetInput != tt.target {
				t.Fatalf("target = %q, want %q", cfg.TargetInput, tt.target)
			}
			if tt.ports != "" && cfg.PortRange != tt.ports {
				t.Fatalf("ports = %q, want %q", cfg.PortRange, tt.ports)
			}
		})
	}
}

func TestSelectDingTalkTaskEventAvoidsDuplicateCompletion(t *testing.T) {
	bot := dingTalkNotificationBot{notifyTaskCompleted: true, notifyWebScanComplete: true, notifyPortScanComplete: true}
	if got := selectDingTalkTaskEvent("web", DingTalkEventTaskCompleted, bot); got != DingTalkEventWebScanComplete {
		t.Fatalf("web event = %q, want %q", got, DingTalkEventWebScanComplete)
	}
	if got := selectDingTalkTaskEvent("port", DingTalkEventTaskCompleted, bot); got != DingTalkEventPortScanComplete {
		t.Fatalf("port event = %q, want %q", got, DingTalkEventPortScanComplete)
	}
	if got := selectDingTalkTaskEvent("web", DingTalkEventTaskFailed, bot); got != DingTalkEventTaskFailed {
		t.Fatalf("failed event = %q, want %q", got, DingTalkEventTaskFailed)
	}
}

func TestSelectDingTalkTaskEventFallsBackToGenericCompletion(t *testing.T) {
	bot := dingTalkNotificationBot{notifyTaskCompleted: true}
	if got := selectDingTalkTaskEvent("web", DingTalkEventTaskCompleted, bot); got != DingTalkEventTaskCompleted {
		t.Fatalf("fallback event = %q, want %q", got, DingTalkEventTaskCompleted)
	}
	bot.notifyTaskCompleted = false
	if got := selectDingTalkTaskEvent("port", DingTalkEventTaskCompleted, bot); got != DingTalkEventTaskCompleted {
		t.Fatalf("disabled specialized event should still resolve generic event, got %q", got)
	}
}

func TestResolveDingTalkTarget(t *testing.T) {
	conversation, users, kind := resolveDingTalkTarget("cid-source", "2", "staff-source", "user", "staff-1")
	if conversation != "cid-source" || len(users) != 0 || kind != "group" {
		t.Fatalf("source group conversation target = (%q, %#v, %q)", conversation, users, kind)
	}
	conversation, users, kind = resolveDingTalkTarget("cid-source", "1", "staff-source", "group", "cid-default")
	if conversation != "" || len(users) != 1 || users[0] != "staff-source" || kind != "user" {
		t.Fatalf("source single conversation target = (%q, %#v, %q)", conversation, users, kind)
	}
	conversation, users, kind = resolveDingTalkTarget("", "", "", "group", "cid-default")
	if conversation != "cid-default" || len(users) != 0 || kind != "group" {
		t.Fatalf("group target = (%q, %#v, %q)", conversation, users, kind)
	}
	conversation, users, kind = resolveDingTalkTarget("", "", "", "user", "staff-1, staff-2;staff-3")
	if conversation != "" || kind != "user" || len(users) != 3 {
		t.Fatalf("user target = (%q, %#v, %q)", conversation, users, kind)
	}
}

func TestParseDingTalkBindingCommand(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "Chinese", in: "绑定 62FB2267", want: "62FB2267"},
		{name: "English case insensitive", in: "bind 62fb2267", want: "62FB2267"},
		{name: "Mention prefix", in: "@FusionWeb安全机器人 绑定 62FB2267", want: "62FB2267"},
		{name: "Non breaking space and colon", in: "@FusionWeb安全机器人\u00a0绑定：62FB2267", want: "62FB2267"},
		{name: "Full width spaces", in: " @机器人　绑定　62FB2267 ", want: "62FB2267"},
		{name: "Text around command", in: "请绑定 62FB2267，谢谢", want: "62FB2267"},
		{name: "No code", in: "绑定", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDingTalkBindingCommand(tt.in); got != tt.want {
				t.Fatalf("parseDingTalkBindingCommand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDingTalkMessageIDUsesFallbackWhenSDKOmitsMessageID(t *testing.T) {
	data := &chatbot.BotCallbackDataModel{
		ConversationId: "cid-1",
		SenderId:       "user-1",
		SenderStaffId:  "staff-1",
		CreateAt:       123,
	}
	first := dingTalkMessageID(7, data, "绑定 62FB2267")
	second := dingTalkMessageID(7, data, "绑定 62FB2267")
	if first == "" || first != second || len(first) != len("fallback-")+32 {
		t.Fatalf("fallback message id = %q, second = %q", first, second)
	}
	data.MsgId = "sdk-message-id"
	if got := dingTalkMessageID(7, data, "内容"); got != "sdk-message-id" {
		t.Fatalf("message id = %q, want SDK id", got)
	}
}

func TestDingTalkSenderIDsPrefersStaffIDAndDeduplicates(t *testing.T) {
	data := &chatbot.BotCallbackDataModel{SenderId: "user-1", SenderStaffId: "staff-1"}
	got := dingTalkSenderIDs(data)
	if len(got) != 2 || got[0] != "staff-1" || got[1] != "user-1" {
		t.Fatalf("sender ids = %#v", got)
	}
	data.SenderId = "staff-1"
	got = dingTalkSenderIDs(data)
	if len(got) != 1 || got[0] != "staff-1" {
		t.Fatalf("deduplicated sender ids = %#v", got)
	}
}
