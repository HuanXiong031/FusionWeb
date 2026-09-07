package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type AIAPIKey struct {
	ID              int    `json:"id"`
	Provider        string `json:"provider"`
	Name            string `json:"name"`
	APIKey          string `json:"apiKey,omitempty"`
	MaskedAPIKey    string `json:"maskedApiKey,omitempty"`
	BaseURL         string `json:"baseUrl"`
	Model           string `json:"model"`
	Enabled         bool   `json:"enabled"`
	IsDefault       bool   `json:"isDefault"`
	Description     string `json:"description,omitempty"`
	LastTestStatus  string `json:"lastTestStatus,omitempty"`
	LastTestMessage string `json:"lastTestMessage,omitempty"`
	LastTestAt      string `json:"lastTestAt,omitempty"`
	CreatedBy       int    `json:"createdBy,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
}

type AIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AIChatRequest struct {
	KeyID        int             `json:"keyId"`
	Provider     string          `json:"provider"`
	Model        string          `json:"model"`
	SystemPrompt string          `json:"systemPrompt"`
	Messages     []AIChatMessage `json:"messages"`
	Temperature  *float64        `json:"temperature"`
	MaxTokens    int             `json:"maxTokens"`
}

type AIChatResponse struct {
	Provider string                 `json:"provider"`
	Model    string                 `json:"model"`
	Content  string                 `json:"content"`
	Usage    map[string]interface{} `json:"usage,omitempty"`
}

type AIAPIKeyTestResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	At      string `json:"at"`
}

func (s *SystemSettingsService) ListAIAPIKeys(includeSecret bool, userID int) ([]AIAPIKey, error) {
	if database.DB == nil {
		return nil, fmt.Errorf("数据库未初始化")
	}
	rows, err := database.DB.Query(`
		SELECT id, provider, name, api_key, base_url, model, enabled, is_default, description,
		       last_test_status, last_test_message, last_test_at, created_by, created_at, updated_at
		  FROM ai_api_keys
		 WHERE created_by = ?
		 ORDER BY is_default DESC, id DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AIAPIKey, 0)
	for rows.Next() {
		item, err := scanAIAPIKey(rows, includeSecret)
		if err == nil {
			items = append(items, item)
		}
	}
	return items, nil
}

func (s *SystemSettingsService) SaveAIAPIKey(item AIAPIKey, userID int) (AIAPIKey, error) {
	if database.DB == nil {
		return AIAPIKey{}, fmt.Errorf("数据库未初始化")
	}
	item.Provider = normalizeAIProvider(item.Provider)
	item.Name = strings.TrimSpace(item.Name)
	item.APIKey = strings.TrimSpace(item.APIKey)
	item.BaseURL = strings.TrimRight(strings.TrimSpace(item.BaseURL), "/")
	item.Model = strings.TrimSpace(item.Model)
	item.Description = strings.TrimSpace(item.Description)
	if item.Name == "" {
		return AIAPIKey{}, fmt.Errorf("请输入 Key 名称")
	}
	if item.Provider == "" {
		return AIAPIKey{}, fmt.Errorf("请选择模型服务商")
	}
	if item.APIKey == "" && item.ID <= 0 {
		return AIAPIKey{}, fmt.Errorf("请输入 API Key")
	}
	if item.APIKey != "" {
		protected, err := EncryptSecret(item.APIKey)
		if err != nil {
			return AIAPIKey{}, err
		}
		item.APIKey = protected
	}
	if item.BaseURL == "" {
		item.BaseURL = defaultAIBaseURL(item.Provider)
	}
	if item.Model == "" {
		item.Model = defaultAIModel(item.Provider)
	}
	if !item.Enabled && item.IsDefault {
		return AIAPIKey{}, fmt.Errorf("默认 Key 必须保持启用")
	}
	now := utils.GetCurrentTimeString()
	tx, err := database.DB.Begin()
	if err != nil {
		return AIAPIKey{}, err
	}
	defer tx.Rollback()
	if item.IsDefault {
		if _, err := tx.Exec("UPDATE ai_api_keys SET is_default = 0 WHERE created_by = ?", userID); err != nil {
			return AIAPIKey{}, err
		}
	}
	if item.ID > 0 {
		res, err := tx.Exec(`
			UPDATE ai_api_keys
			   SET provider = ?, name = ?, api_key = CASE WHEN ? = '' THEN api_key ELSE ? END,
			       base_url = ?, model = ?, enabled = ?, is_default = ?, description = ?, updated_at = ?
			 WHERE id = ? AND created_by = ?
		`, item.Provider, item.Name, item.APIKey, item.APIKey, item.BaseURL, item.Model, boolToInt(item.Enabled), boolToInt(item.IsDefault), item.Description, now, item.ID, userID)
		if err != nil {
			return AIAPIKey{}, err
		}
		if affected, _ := res.RowsAffected(); affected == 0 {
			return AIAPIKey{}, fmt.Errorf("Key 不存在或无权限")
		}
		if err := tx.Commit(); err != nil {
			return AIAPIKey{}, err
		}
		return s.GetAIAPIKey(item.ID, false, userID)
	}
	id, err := database.InsertAndReturnIDTx(tx, `
		INSERT INTO ai_api_keys
			(provider, name, api_key, base_url, model, enabled, is_default, description, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, item.Provider, item.Name, item.APIKey, item.BaseURL, item.Model, boolToInt(item.Enabled), boolToInt(item.IsDefault), item.Description, userID, now, now)
	if err != nil {
		return AIAPIKey{}, err
	}
	if err := tx.Commit(); err != nil {
		return AIAPIKey{}, err
	}
	return s.GetAIAPIKey(int(id), false, userID)
}

func (s *SystemSettingsService) GetAIAPIKey(id int, includeSecret bool, userID int) (AIAPIKey, error) {
	if database.DB == nil {
		return AIAPIKey{}, fmt.Errorf("数据库未初始化")
	}
	row := database.DB.QueryRow(`
		SELECT id, provider, name, api_key, base_url, model, enabled, is_default, description,
		       last_test_status, last_test_message, last_test_at, created_by, created_at, updated_at
		  FROM ai_api_keys
		 WHERE id = ? AND created_by = ?
	`, id, userID)
	return scanAIAPIKey(row, includeSecret)
}

func (s *SystemSettingsService) GetDefaultAIAPIKey(includeSecret bool, userID int) (AIAPIKey, error) {
	if database.DB == nil {
		return AIAPIKey{}, fmt.Errorf("数据库未初始化")
	}
	row := database.DB.QueryRow(`
		SELECT id, provider, name, api_key, base_url, model, enabled, is_default, description,
		       last_test_status, last_test_message, last_test_at, created_by, created_at, updated_at
		  FROM ai_api_keys
		 WHERE enabled = 1 AND created_by = ?
		 ORDER BY is_default DESC, id DESC
		 LIMIT 1
	`, userID)
	return scanAIAPIKey(row, includeSecret)
}

func (s *SystemSettingsService) DeleteAIAPIKey(id int, userID int) error {
	if database.DB == nil {
		return fmt.Errorf("数据库未初始化")
	}
	res, err := database.DB.Exec("DELETE FROM ai_api_keys WHERE id = ? AND created_by = ?", id, userID)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("Key 不存在或无权限")
	}
	return nil
}

func (s *SystemSettingsService) TestAIAPIKey(id int, userID int) (AIAPIKeyTestResult, error) {
	result := AIAPIKeyTestResult{At: utils.GetCurrentTimeString()}
	key, err := s.GetAIAPIKey(id, true, userID)
	if err != nil {
		return result, err
	}
	_, err = s.ChatWithAI(AIChatRequest{
		KeyID:        id,
		SystemPrompt: "你是 FusionWeb 的连接测试助手。",
		Messages:     []AIChatMessage{{Role: "user", Content: "请只回复 pong"}},
		MaxTokens:    64,
	}, userID)
	if err != nil {
		result.Status = "failed"
		result.Message = err.Error()
	} else {
		result.Status = "success"
		result.Message = fmt.Sprintf("%s/%s 连接成功", providerLabel(key.Provider), key.Model)
	}
	_, _ = database.DB.Exec("UPDATE ai_api_keys SET last_test_status = ?, last_test_message = ?, last_test_at = ?, updated_at = ? WHERE id = ?", result.Status, result.Message, result.At, result.At, id)
	return result, nil
}

func (s *SystemSettingsService) ChatWithAI(req AIChatRequest, userID int) (AIChatResponse, error) {
	if len(req.Messages) == 0 {
		return AIChatResponse{}, fmt.Errorf("请输入对话内容")
	}
	var key AIAPIKey
	var err error
	if req.KeyID > 0 {
		key, err = s.GetAIAPIKey(req.KeyID, true, userID)
	} else {
		key, err = s.GetDefaultAIAPIKey(true, userID)
	}
	if err != nil {
		if err == sql.ErrNoRows {
			return AIChatResponse{}, fmt.Errorf("请先在系统设置中添加并启用 AI API Key")
		}
		return AIChatResponse{}, err
	}
	if !key.Enabled {
		return AIChatResponse{}, fmt.Errorf("当前 AI API Key 已禁用")
	}
	key.Provider = normalizeAIProvider(firstNonEmptyAI(req.Provider, key.Provider))
	key.BaseURL = strings.TrimRight(firstNonEmptyAI(key.BaseURL, defaultAIBaseURL(key.Provider)), "/")
	key.Model = firstNonEmptyAI(req.Model, key.Model, defaultAIModel(key.Provider))
	if strings.TrimSpace(key.APIKey) == "" {
		return AIChatResponse{}, fmt.Errorf("当前 AI API Key 未配置密钥")
	}
	if isAnthropicProvider(key.Provider) {
		return sendAnthropicChat(key, req)
	}
	return sendOpenAICompatibleChat(key, req)
}

func scanAIAPIKey(scanner interface {
	Scan(dest ...interface{}) error
}, includeSecret bool) (AIAPIKey, error) {
	var item AIAPIKey
	var apiKey, baseURL, model, description, lastStatus, lastMessage, lastAt, createdAt, updatedAt sql.NullString
	var enabled, isDefault int
	if err := scanner.Scan(&item.ID, &item.Provider, &item.Name, &apiKey, &baseURL, &model, &enabled, &isDefault, &description, &lastStatus, &lastMessage, &lastAt, &item.CreatedBy, &createdAt, &updatedAt); err != nil {
		return AIAPIKey{}, err
	}
	item.Provider = normalizeAIProvider(item.Provider)
	storedKey := nullStringValue(apiKey)
	plainKey, decryptErr := DecryptSecret(storedKey)
	if decryptErr != nil {
		return AIAPIKey{}, decryptErr
	}
	if includeSecret {
		item.APIKey = plainKey
	}
	item.MaskedAPIKey = maskSecret(plainKey)
	item.BaseURL = nullStringValue(baseURL)
	item.Model = nullStringValue(model)
	item.Enabled = enabled == 1
	item.IsDefault = isDefault == 1
	item.Description = nullStringValue(description)
	item.LastTestStatus = nullStringValue(lastStatus)
	item.LastTestMessage = nullStringValue(lastMessage)
	item.LastTestAt = nullStringValue(lastAt)
	item.CreatedAt = nullStringValue(createdAt)
	item.UpdatedAt = nullStringValue(updatedAt)
	return item, nil
}

func sendOpenAICompatibleChat(key AIAPIKey, req AIChatRequest) (AIChatResponse, error) {
	messages := make([]AIChatMessage, 0, len(req.Messages)+1)
	if strings.TrimSpace(req.SystemPrompt) != "" {
		messages = append(messages, AIChatMessage{Role: "system", Content: strings.TrimSpace(req.SystemPrompt)})
	}
	for _, msg := range req.Messages {
		role := normalizeChatRole(msg.Role)
		if role == "system" || role == "user" || role == "assistant" {
			messages = append(messages, AIChatMessage{Role: role, Content: msg.Content})
		}
	}
	payload := map[string]interface{}{
		"model":    key.Model,
		"messages": messages,
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequest(http.MethodPost, openAIChatEndpoint(key.BaseURL), bytes.NewReader(body))
	if err != nil {
		return AIChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+key.APIKey)
	resp, err := aiHTTPClient().Do(httpReq)
	if err != nil {
		return AIChatResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AIChatResponse{}, fmt.Errorf("AI 接口返回 %d: %s", resp.StatusCode, truncateTextAI(string(data), 600))
	}
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
		Usage map[string]interface{} `json:"usage"`
		Model string                 `json:"model"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return AIChatResponse{}, fmt.Errorf("AI 响应解析失败: %w", err)
	}
	content := ""
	if len(decoded.Choices) > 0 {
		content = decoded.Choices[0].Message.Content
		if content == "" {
			content = decoded.Choices[0].Text
		}
	}
	if strings.TrimSpace(content) == "" {
		return AIChatResponse{}, fmt.Errorf("AI 未返回有效内容")
	}
	return AIChatResponse{Provider: key.Provider, Model: firstNonEmptyAI(decoded.Model, key.Model), Content: content, Usage: decoded.Usage}, nil
}

func sendAnthropicChat(key AIAPIKey, req AIChatRequest) (AIChatResponse, error) {
	systemParts := []string{}
	if strings.TrimSpace(req.SystemPrompt) != "" {
		systemParts = append(systemParts, strings.TrimSpace(req.SystemPrompt))
	}
	messages := make([]AIChatMessage, 0, len(req.Messages))
	for _, msg := range req.Messages {
		role := normalizeChatRole(msg.Role)
		if role == "system" {
			if strings.TrimSpace(msg.Content) != "" {
				systemParts = append(systemParts, strings.TrimSpace(msg.Content))
			}
			continue
		}
		if role != "assistant" {
			role = "user"
		}
		messages = append(messages, AIChatMessage{Role: role, Content: msg.Content})
	}
	if len(messages) == 0 {
		return AIChatResponse{}, fmt.Errorf("请输入对话内容")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	payload := map[string]interface{}{
		"model":      key.Model,
		"messages":   messages,
		"max_tokens": maxTokens,
	}
	if len(systemParts) > 0 {
		payload["system"] = strings.Join(systemParts, "\n\n")
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequest(http.MethodPost, anthropicMessagesEndpoint(key.BaseURL), bytes.NewReader(body))
	if err != nil {
		return AIChatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", key.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	resp, err := aiHTTPClient().Do(httpReq)
	if err != nil {
		return AIChatResponse{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AIChatResponse{}, fmt.Errorf("AI 接口返回 %d: %s", resp.StatusCode, truncateTextAI(string(data), 600))
	}
	var decoded struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage map[string]interface{} `json:"usage"`
		Model string                 `json:"model"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return AIChatResponse{}, fmt.Errorf("AI 响应解析失败: %w", err)
	}
	parts := []string{}
	for _, item := range decoded.Content {
		if item.Text != "" {
			parts = append(parts, item.Text)
		}
	}
	content := strings.TrimSpace(strings.Join(parts, "\n"))
	if content == "" {
		return AIChatResponse{}, fmt.Errorf("AI 未返回有效内容")
	}
	return AIChatResponse{Provider: key.Provider, Model: firstNonEmptyAI(decoded.Model, key.Model), Content: content, Usage: decoded.Usage}, nil
}

func aiHTTPClient() *http.Client {
	return &http.Client{Timeout: 120 * time.Second}
}

func normalizeAIProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gpt", "openai", "chatgpt":
		return "openai"
	case "deepseek", "deepseek-chat":
		return "deepseek"
	case "anthropic", "claude", "claude-code", "claude_code":
		return "anthropic"
	case "custom", "openai-compatible", "openai_compatible", "compatible":
		return "openai_compatible"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func defaultAIBaseURL(provider string) string {
	switch normalizeAIProvider(provider) {
	case "openai":
		return "https://api.openai.com/v1"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "anthropic":
		return "https://api.anthropic.com/v1"
	default:
		return ""
	}
}

func defaultAIModel(provider string) string {
	switch normalizeAIProvider(provider) {
	case "openai":
		return "gpt-4o-mini"
	case "deepseek":
		return "deepseek-chat"
	case "anthropic":
		return "claude-3-5-sonnet-latest"
	default:
		return ""
	}
}

func providerLabel(provider string) string {
	switch normalizeAIProvider(provider) {
	case "openai":
		return "GPT/OpenAI"
	case "deepseek":
		return "DeepSeek"
	case "anthropic":
		return "Claude/Claude Code"
	case "openai_compatible":
		return "OpenAI 兼容"
	default:
		return provider
	}
}

func isAnthropicProvider(provider string) bool {
	return normalizeAIProvider(provider) == "anthropic"
}

func normalizeChatRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return "user"
	}
	return role
}

func openAIChatEndpoint(baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(baseURL, "/chat/completions") {
		return baseURL
	}
	return baseURL + "/chat/completions"
}

func anthropicMessagesEndpoint(baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(baseURL, "/messages") {
		return baseURL
	}
	return baseURL + "/messages"
}

func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	runes := []rune(secret)
	if len(runes) <= 8 {
		return strings.Repeat("*", len(runes))
	}
	return string(runes[:4]) + strings.Repeat("*", len(runes)-8) + string(runes[len(runes)-4:])
}

func firstNonEmptyAI(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncateTextAI(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
