package service

import "testing"

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
