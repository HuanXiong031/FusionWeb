// backend/service/dingtalk_dsh_bridge.go
//
// 钉钉 → DSH：把钉钉里的自然语言消息交给 DSH 执行（Phase 3）。
//
// 与旧 AI 对话的区别：不再走 ai_api_keys 里的模型配置，而是直接调用 DSH 容器内的
// OpenAI 兼容桥（FUSIONWEB_DSH_BRIDGE_URL）。桥会**立即**返回一句回执并在后台跑 DSH，
// 完成后由桥把结果推回钉钉，因此钉钉这边不会被长任务卡住。
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"FusionWeb/backend/logger"
)

// dshBridgeBaseURL 返回 DSH 桥的基址（未配置则返回空）。
func dshBridgeBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("FUSIONWEB_DSH_BRIDGE_URL")), "/")
}

// handleDingTalkDSH 尝试把消息交给 DSH。
// 返回 handled=true 时，调用方应把 ack 回给用户并结束本次处理。
func (s *DingTalkBotService) handleDingTalkDSH(ctx context.Context, botID int, content string) (bool, string) {
	base := dshBridgeBaseURL()
	if base == "" || strings.TrimSpace(content) == "" {
		return false, ""
	}

	payload := map[string]interface{}{
		"model":    "dsh",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, ""
	}

	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return false, ""
	}
	req.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(os.Getenv("FUSIONWEB_SVC_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		logger.Warn("调用 DSH 桥失败: %v", err)
		return false, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.Warn("DSH 桥返回异常状态: %d", resp.StatusCode)
		return false, ""
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&parsed)

	ack := "已交给 DSH 处理，完成后我会把结果发到这里。"
	if len(parsed.Choices) > 0 {
		if text := strings.TrimSpace(parsed.Choices[0].Message.Content); text != "" {
			ack = text
		}
	}
	return true, ack
}
