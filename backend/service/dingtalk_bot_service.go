package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-dingtalk/dingtalk-stream-sdk-go/chatbot"
	"github.com/open-dingtalk/dingtalk-stream-sdk-go/client"
)

type DingTalkBot struct {
	ID                     int    `json:"id"`
	Name                   string `json:"name"`
	Enabled                bool   `json:"enabled"`
	ClientID               string `json:"clientId,omitempty"`
	ClientSecret           string `json:"clientSecret,omitempty"`
	TenantID               string `json:"tenantId,omitempty"`
	WebhookToken           string `json:"webhookToken,omitempty"`
	WebhookSecret          string `json:"webhookSecret,omitempty"`
	MaskedClientSecret     string `json:"maskedClientSecret,omitempty"`
	MaskedWebhookToken     string `json:"maskedWebhookToken,omitempty"`
	MaskedWebhookSecret    string `json:"maskedWebhookSecret,omitempty"`
	DefaultTargetType      string `json:"defaultTargetType,omitempty"`
	DefaultTargetValue     string `json:"defaultTargetValue,omitempty"`
	NotifyTaskCompleted    bool   `json:"notifyTaskCompleted"`
	NotifyTaskFailed       bool   `json:"notifyTaskFailed"`
	NotifyTaskCancelled    bool   `json:"notifyTaskCancelled"`
	NotifyBlacklistAdd     bool   `json:"notifyBlacklistAdd"`
	NotifyBlacklistRemove  bool   `json:"notifyBlacklistRemove"`
	NotifyWebScanComplete  bool   `json:"notifyWebScanComplete"`
	NotifyPortScanComplete bool   `json:"notifyPortScanComplete"`
	AllowTaskCreation      bool   `json:"allowTaskCreation"`
	AllowAIChat            bool   `json:"allowAiChat"`
	NotificationOnly       bool   `json:"notificationOnly"`
	StreamStatus           string `json:"streamStatus"`
	StreamLastError        string `json:"streamLastError,omitempty"`
	StreamConnectedAt      string `json:"streamConnectedAt,omitempty"`
	MigrationPending       bool   `json:"migrationPending"`
	CreatedAt              string `json:"createdAt,omitempty"`
	UpdatedAt              string `json:"updatedAt,omitempty"`
}

type DingTalkBinding struct {
	ID             int    `json:"id"`
	BotID          int    `json:"botId"`
	UserID         int    `json:"userId"`
	DingUserID     string `json:"dingUserId"`
	DingUserName   string `json:"dingUserName"`
	ConversationID string `json:"conversationId,omitempty"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"createdAt,omitempty"`
}
type DingTalkAllowlist struct {
	ID          int    `json:"id"`
	BotID       int    `json:"botId"`
	EntryType   string `json:"entryType"`
	EntryValue  string `json:"entryValue"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}
type DingTalkBindingCode struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expiresAt"`
}
type DingTalkEvent string

const (
	DingTalkEventTaskCompleted    DingTalkEvent = "task_completed"
	DingTalkEventTaskFailed       DingTalkEvent = "task_failed"
	DingTalkEventTaskCancelled    DingTalkEvent = "task_cancelled"
	DingTalkEventBlacklistAdd     DingTalkEvent = "blacklist_add"
	DingTalkEventBlacklistRemove  DingTalkEvent = "blacklist_remove"
	DingTalkEventWebScanComplete  DingTalkEvent = "web_scan_complete"
	DingTalkEventPortScanComplete DingTalkEvent = "port_scan_complete"
)

type dingTalkMarkdownMessage struct {
	MsgType  string                  `json:"msgtype"`
	Markdown dingTalkMarkdownContent `json:"markdown"`
}

type dingTalkMarkdownContent struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type DingTalkTaskCreator func(models.TaskConfig, uint) (string, error)
type DingTalkBotService struct {
	mu          sync.Mutex
	ctx         context.Context
	taskCreator DingTalkTaskCreator
	clients     map[int]*client.StreamClient
}

var dingTalkService = &DingTalkBotService{clients: map[int]*client.StreamClient{}}

func NewDingTalkBotService() *DingTalkBotService { return dingTalkService }
func (s *DingTalkBotService) SetTaskCreator(fn DingTalkTaskCreator) {
	s.mu.Lock()
	s.taskCreator = fn
	s.mu.Unlock()
}

func (s *DingTalkBotService) ListBots() ([]DingTalkBot, error) {
	rows, err := database.DB.Query(`SELECT id,name,enabled,client_id_cipher,client_secret_cipher,tenant_id,webhook_token_cipher,webhook_secret_cipher,default_target_type,default_target_value,notify_task_completed,notify_task_failed,notify_task_cancelled,notify_blacklist_add,notify_blacklist_remove,notify_web_scan_complete,notify_port_scan_complete,allow_task_creation,allow_ai_chat,notification_only,stream_status,stream_last_error,stream_connected_at,created_at,updated_at FROM dingtalk_bots ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DingTalkBot{}
	for rows.Next() {
		var b DingTalkBot
		var en, tc, tf, tx, ba, br, w, p, at, aa, no int
		var cid, csec, wt, ws, connected, created, updated sqlNullString
		if err := rows.Scan(&b.ID, &b.Name, &en, &cid, &csec, &b.TenantID, &wt, &ws, &b.DefaultTargetType, &b.DefaultTargetValue, &tc, &tf, &tx, &ba, &br, &w, &p, &at, &aa, &no, &b.StreamStatus, &b.StreamLastError, &connected, &created, &updated); err != nil {
			return nil, err
		}
		plainClientID, decryptErr := DecryptSecret(cid.String)
		if decryptErr != nil {
			return nil, fmt.Errorf("解密钉钉机器人 Client ID 失败: %w", decryptErr)
		}
		b.ClientID = plainClientID
		b.Enabled = en == 1
		b.NotifyTaskCompleted = tc == 1
		b.NotifyTaskFailed = tf == 1
		b.NotifyTaskCancelled = tx == 1
		b.NotifyBlacklistAdd = ba == 1
		b.NotifyBlacklistRemove = br == 1
		b.NotifyWebScanComplete = w == 1
		b.NotifyPortScanComplete = p == 1
		b.AllowTaskCreation = at == 1
		b.AllowAIChat = aa == 1
		b.NotificationOnly = no == 1
		b.StreamConnectedAt = connected.String
		b.CreatedAt = created.String
		b.UpdatedAt = updated.String
		if cid.String != "" {
			b.MaskedClientSecret = "已配置"
		}
		if wt.String != "" {
			b.MaskedWebhookToken = "已配置"
		}
		if ws.String != "" {
			b.MaskedWebhookSecret = "已配置"
		}
		b.MigrationPending = b.NotificationOnly && b.ClientID == ""
		out = append(out, b)
	}
	return out, rows.Err()
}

type sqlNullString struct{ String string }

func (n *sqlNullString) Scan(v interface{}) error {
	switch x := v.(type) {
	case nil:
		n.String = ""
	case string:
		n.String = x
	case []byte:
		n.String = string(x)
	default:
		n.String = fmt.Sprint(x)
	}
	return nil
}

func scanBot(id int) (DingTalkBot, error) {
	bots, err := NewDingTalkBotService().ListBots()
	if err != nil {
		return DingTalkBot{}, err
	}
	for _, b := range bots {
		if b.ID == id {
			return b, nil
		}
	}
	return DingTalkBot{}, fmt.Errorf("钉钉机器人不存在")
}
func (s *DingTalkBotService) SaveBot(item DingTalkBot) (DingTalkBot, error) {
	if database.DB == nil {
		return DingTalkBot{}, fmt.Errorf("数据库未初始化")
	}
	item.Name = strings.TrimSpace(item.Name)
	if item.Name == "" {
		return DingTalkBot{}, fmt.Errorf("请输入机器人名称")
	}
	now := utils.GetCurrentTimeString()
	enc := func(v string) (string, error) { return EncryptSecret(strings.TrimSpace(v)) }
	var id int64
	if item.ID > 0 {
		old, err := s.loadBotSecrets(item.ID)
		if err != nil {
			return DingTalkBot{}, err
		}
		if item.ClientID == "" {
			item.ClientID = old.clientID
		}
		if item.ClientSecret == "" {
			item.ClientSecret = old.clientSecret
		}
		if item.WebhookToken == "" {
			item.WebhookToken = old.webhookToken
		}
		if item.WebhookSecret == "" {
			item.WebhookSecret = old.webhookSecret
		}
		ci, err := enc(item.ClientID)
		if err != nil {
			return DingTalkBot{}, err
		}
		cs, err := enc(item.ClientSecret)
		if err != nil {
			return DingTalkBot{}, err
		}
		wt, err := enc(item.WebhookToken)
		if err != nil {
			return DingTalkBot{}, err
		}
		ws, err := enc(item.WebhookSecret)
		if err != nil {
			return DingTalkBot{}, err
		}
		_, err = database.DB.Exec(`UPDATE dingtalk_bots SET name=?,enabled=?,client_id_cipher=?,client_secret_cipher=?,tenant_id=?,webhook_token_cipher=?,webhook_secret_cipher=?,default_target_type=?,default_target_value=?,notify_task_completed=?,notify_task_failed=?,notify_task_cancelled=?,notify_blacklist_add=?,notify_blacklist_remove=?,notify_web_scan_complete=?,notify_port_scan_complete=?,allow_task_creation=?,allow_ai_chat=?,notification_only=?,updated_at=? WHERE id=?`, item.Name, boolInt(item.Enabled), ci, cs, item.TenantID, wt, ws, item.DefaultTargetType, item.DefaultTargetValue, boolInt(item.NotifyTaskCompleted), boolInt(item.NotifyTaskFailed), boolInt(item.NotifyTaskCancelled), boolInt(item.NotifyBlacklistAdd), boolInt(item.NotifyBlacklistRemove), boolInt(item.NotifyWebScanComplete), boolInt(item.NotifyPortScanComplete), boolInt(item.AllowTaskCreation), boolInt(item.AllowAIChat), boolInt(item.NotificationOnly), now, item.ID)
		if err != nil {
			return DingTalkBot{}, err
		}
		id = int64(item.ID)
	} else {
		ci, err := enc(item.ClientID)
		if err != nil {
			return DingTalkBot{}, err
		}
		cs, err := enc(item.ClientSecret)
		if err != nil {
			return DingTalkBot{}, err
		}
		wt, err := enc(item.WebhookToken)
		if err != nil {
			return DingTalkBot{}, err
		}
		ws, err := enc(item.WebhookSecret)
		if err != nil {
			return DingTalkBot{}, err
		}
		id, err = database.InsertAndReturnID(`INSERT INTO dingtalk_bots (name,enabled,client_id_cipher,client_secret_cipher,tenant_id,webhook_token_cipher,webhook_secret_cipher,default_target_type,default_target_value,notify_task_completed,notify_task_failed,notify_task_cancelled,notify_blacklist_add,notify_blacklist_remove,notify_web_scan_complete,notify_port_scan_complete,allow_task_creation,allow_ai_chat,notification_only,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, item.Name, boolInt(item.Enabled), ci, cs, item.TenantID, wt, ws, item.DefaultTargetType, item.DefaultTargetValue, boolInt(item.NotifyTaskCompleted), boolInt(item.NotifyTaskFailed), boolInt(item.NotifyTaskCancelled), boolInt(item.NotifyBlacklistAdd), boolInt(item.NotifyBlacklistRemove), boolInt(item.NotifyWebScanComplete), boolInt(item.NotifyPortScanComplete), boolInt(item.AllowTaskCreation), boolInt(item.AllowAIChat), boolInt(item.NotificationOnly), now, now)
		if err != nil {
			return DingTalkBot{}, err
		}
	}
	saved, err := scanBot(int(id))
	if err != nil {
		return DingTalkBot{}, err
	}
	// 配置修改后立即同步 Stream 运行状态，避免必须重启整个服务才能
	// 生效。通知专用机器人或关闭入站能力时主动停止 Stream。
	if saved.Enabled && !saved.NotificationOnly && saved.ClientID != "" && (saved.AllowTaskCreation || saved.AllowAIChat) {
		if err := s.StartBot(saved.ID); err != nil {
			logger.Warn("钉钉机器人配置已保存，但 Stream 启动失败: bot=%d err=%v", saved.ID, err)
		}
	} else {
		s.StopBot(saved.ID)
	}
	return saved, nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

type botSecrets struct{ clientID, clientSecret, webhookToken, webhookSecret string }

func (s *DingTalkBotService) loadBotSecrets(id int) (botSecrets, error) {
	var a, b, c, d string
	err := database.DB.QueryRow(`SELECT client_id_cipher,client_secret_cipher,webhook_token_cipher,webhook_secret_cipher FROM dingtalk_bots WHERE id=?`, id).Scan(&a, &b, &c, &d)
	if err != nil {
		return botSecrets{}, err
	}
	aa, e := DecryptSecret(a)
	if e != nil {
		return botSecrets{}, e
	}
	bb, e := DecryptSecret(b)
	if e != nil {
		return botSecrets{}, e
	}
	cc, e := DecryptSecret(c)
	if e != nil {
		return botSecrets{}, e
	}
	dd, e := DecryptSecret(d)
	if e != nil {
		return botSecrets{}, e
	}
	return botSecrets{aa, bb, cc, dd}, nil
}
func (s *DingTalkBotService) TestBot(id int) error {
	b, err := scanBot(id)
	if err != nil {
		return err
	}
	sec, err := s.loadBotSecrets(id)
	if err != nil {
		return err
	}
	return sendDingTalkNotification(sec.webhookToken, sec.webhookSecret, sec.clientID, sec.clientSecret, "", "", "", b.DefaultTargetType, b.DefaultTargetValue, "FusionWeb 钉钉机器人测试", "### 连接测试成功\n\n统一钉钉机器人服务已正常发送测试消息。")
}
func (s *DingTalkBotService) GetBotStatus(id int) (DingTalkBot, error) { return scanBot(id) }

func (s *DingTalkBotService) DeleteBot(id int) error {
	s.StopBot(id)
	_, err := database.DB.Exec(`DELETE FROM dingtalk_bots WHERE id=?`, id)
	return err
}

func sendDingTalkMarkdown(token, secret, title, text string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("未配置出站 Webhook Token")
	}
	webhook := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", url.QueryEscape(token))
	if secret = strings.TrimSpace(secret); secret != "" {
		timestamp := time.Now().UnixNano() / 1e6
		stringToSign := fmt.Sprintf("%d\\n%s", timestamp, secret)
		h := hmac.New(sha256.New, []byte(secret))
		_, _ = h.Write([]byte(stringToSign))
		sign := base64.StdEncoding.EncodeToString(h.Sum(nil))
		webhook = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhook, timestamp, url.QueryEscape(sign))
	}
	body, err := json.Marshal(dingTalkMarkdownMessage{
		MsgType:  "markdown",
		Markdown: dingTalkMarkdownContent{Title: title, Text: text},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("钉钉 Webhook 返回状态码: %d", resp.StatusCode)
	}
	return nil
}

func (s *DingTalkBotService) NotifyEvent(event DingTalkEvent, title, text string) {
	s.notifyEventToBots(event, title, text, 0, "", "", "")
}

type dingTalkNotificationBot struct {
	id                     int
	name                   string
	clientIDCipher         string
	clientSecretCipher     string
	webhookTokenCipher     string
	webhookSecretCipher    string
	defaultTargetType      string
	defaultTargetValue     string
	notifyTaskCompleted    bool
	notifyTaskFailed       bool
	notifyTaskCancelled    bool
	notifyBlacklistAdd     bool
	notifyBlacklistRemove  bool
	notifyWebScanComplete  bool
	notifyPortScanComplete bool
}

func (b dingTalkNotificationBot) allows(event DingTalkEvent) bool {
	switch event {
	case DingTalkEventTaskCompleted:
		return b.notifyTaskCompleted
	case DingTalkEventTaskFailed:
		return b.notifyTaskFailed
	case DingTalkEventTaskCancelled:
		return b.notifyTaskCancelled
	case DingTalkEventBlacklistAdd:
		return b.notifyBlacklistAdd
	case DingTalkEventBlacklistRemove:
		return b.notifyBlacklistRemove
	case DingTalkEventWebScanComplete:
		return b.notifyWebScanComplete
	case DingTalkEventPortScanComplete:
		return b.notifyPortScanComplete
	default:
		return false
	}
}

func (s *DingTalkBotService) listNotificationBots(sourceBotID int) ([]dingTalkNotificationBot, error) {
	if database.DB == nil {
		return nil, nil
	}
	query := `SELECT id,name,client_id_cipher,client_secret_cipher,webhook_token_cipher,webhook_secret_cipher,default_target_type,default_target_value,notify_task_completed,notify_task_failed,notify_task_cancelled,notify_blacklist_add,notify_blacklist_remove,notify_web_scan_complete,notify_port_scan_complete FROM dingtalk_bots WHERE enabled=1`
	args := []interface{}{}
	if sourceBotID > 0 {
		query += ` AND id=?`
		args = append(args, sourceBotID)
	}
	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bots := make([]dingTalkNotificationBot, 0)
	for rows.Next() {
		var b dingTalkNotificationBot
		var completed, failed, cancelled, blacklistAdd, blacklistRemove, webComplete, portComplete int
		if err := rows.Scan(&b.id, &b.name, &b.clientIDCipher, &b.clientSecretCipher, &b.webhookTokenCipher, &b.webhookSecretCipher, &b.defaultTargetType, &b.defaultTargetValue, &completed, &failed, &cancelled, &blacklistAdd, &blacklistRemove, &webComplete, &portComplete); err != nil {
			continue
		}
		b.notifyTaskCompleted = completed == 1
		b.notifyTaskFailed = failed == 1
		b.notifyTaskCancelled = cancelled == 1
		b.notifyBlacklistAdd = blacklistAdd == 1
		b.notifyBlacklistRemove = blacklistRemove == 1
		b.notifyWebScanComplete = webComplete == 1
		b.notifyPortScanComplete = portComplete == 1
		bots = append(bots, b)
	}
	return bots, rows.Err()
}

func (s *DingTalkBotService) notifyEventToBots(event DingTalkEvent, title, text string, sourceBotID int, sourceConversationID, sourceConversationType, sourceUserID string) {
	bots, err := s.listNotificationBots(sourceBotID)
	if err != nil {
		logger.Warn("读取钉钉机器人失败: %v", err)
		return
	}
	for _, bot := range bots {
		if !bot.allows(event) {
			continue
		}
		s.dispatchNotification(bot, sourceConversationID, sourceConversationType, sourceUserID, title, text)
	}
}

// notifyTaskToBots emits at most one completion message per bot. Web and port
// scans prefer their specialized event switch, falling back to the generic
// task-completed switch when the specialized switch is disabled.
func selectDingTalkTaskEvent(taskType string, event DingTalkEvent, bot dingTalkNotificationBot) DingTalkEvent {
	if event != DingTalkEventTaskCompleted {
		return event
	}
	switch strings.ToLower(strings.TrimSpace(taskType)) {
	case "web":
		if bot.notifyWebScanComplete {
			return DingTalkEventWebScanComplete
		}
	case "port":
		if bot.notifyPortScanComplete {
			return DingTalkEventPortScanComplete
		}
	}
	return DingTalkEventTaskCompleted
}

func (s *DingTalkBotService) notifyTaskToBots(task *models.TaskConfig, title, text string, event DingTalkEvent) {
	bots, err := s.listNotificationBots(task.DingTalkBotID)
	if err != nil {
		logger.Warn("读取钉钉机器人失败: %v", err)
		return
	}
	for _, bot := range bots {
		notifyEvent := selectDingTalkTaskEvent(task.TaskType, event, bot)
		if !bot.allows(notifyEvent) {
			continue
		}
		s.dispatchNotification(bot, task.DingTalkConversationID, task.DingTalkConversationType, task.DingTalkSourceUserID, title, text)
	}
}

func (s *DingTalkBotService) dispatchNotification(bot dingTalkNotificationBot, sourceConversationID, sourceConversationType, sourceUserID, title, text string) {
	clientID, err1 := DecryptSecret(bot.clientIDCipher)
	clientSecret, err2 := DecryptSecret(bot.clientSecretCipher)
	token, err3 := DecryptSecret(bot.webhookTokenCipher)
	secret, err4 := DecryptSecret(bot.webhookSecretCipher)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		logger.Warn("钉钉通知凭据解密失败: bot=%s", bot.name)
		return
	}
	go func() {
		for attempt := 0; attempt < 3; attempt++ {
			if err := sendDingTalkNotification(token, secret, clientID, clientSecret, sourceConversationID, sourceConversationType, sourceUserID, bot.defaultTargetType, bot.defaultTargetValue, title, text); err == nil {
				return
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
		logger.Warn("钉钉通知重试失败: bot=%s", bot.name)
	}()
}

func sendDingTalkNotification(token, secret, clientID, clientSecret, sourceConversationID, sourceConversationType, sourceUserID, targetType, targetValue, title, text string) error {
	if strings.TrimSpace(token) != "" {
		return sendDingTalkMarkdown(token, secret, title, text)
	}
	conversationID, users, resolvedType := resolveDingTalkTarget(sourceConversationID, sourceConversationType, sourceUserID, targetType, targetValue)
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("未配置 Stream Client ID/Secret，无法使用主动通知")
	}
	if resolvedType == "" || (conversationID == "" && len(users) == 0) {
		return fmt.Errorf("未配置通知目标")
	}
	accessToken, err := fetchDingTalkAccessToken(clientID, clientSecret)
	if err != nil {
		return err
	}
	if resolvedType == "user" {
		return sendDingTalkOTOMessage(accessToken, clientID, users, title, text)
	}
	return sendDingTalkGroupMessage(accessToken, clientID, conversationID, title, text)
}

func resolveDingTalkTarget(sourceConversationID, sourceConversationType, sourceUserID, targetType, targetValue string) (string, []string, string) {
	sourceConversationID = strings.TrimSpace(sourceConversationID)
	if sourceConversationID != "" {
		if isDingTalkSingleConversation(sourceConversationType) {
			if userID := strings.TrimSpace(sourceUserID); userID != "" {
				return "", []string{userID}, "user"
			}
			return "", nil, ""
		}
		return sourceConversationID, nil, "group"
	}
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	targetValue = strings.TrimSpace(targetValue)
	if targetType == "conversation" || targetType == "group" || targetType == "群聊" {
		return targetValue, nil, "group"
	}
	if targetType == "user" || targetType == "staff" || targetType == "用户" || targetType == "单聊" {
		parts := strings.FieldsFunc(targetValue, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\t' })
		return "", parts, "user"
	}
	return "", nil, ""
}

func isDingTalkSingleConversation(conversationType string) bool {
	v := strings.ToLower(strings.TrimSpace(conversationType))
	switch v {
	case "1", "single", "private", "oto", "one_to_one", "one-to-one", "user", "单聊":
		return true
	default:
		return strings.Contains(v, "单聊") || strings.Contains(v, "single")
	}
}

func dingTalkSourceUserID(data *chatbot.BotCallbackDataModel) string {
	if data == nil {
		return ""
	}
	if staffID := strings.TrimSpace(data.SenderStaffId); staffID != "" {
		return staffID
	}
	return strings.TrimSpace(data.SenderId)
}

type dingTalkAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireIn    int64  `json:"expireIn"`
}

func fetchDingTalkAccessToken(clientID, clientSecret string) (string, error) {
	body, _ := json.Marshal(map[string]string{"appKey": clientID, "appSecret": clientSecret})
	req, err := http.NewRequest(http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/accessToken", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("钉钉 OAuth 返回状态码: %d", resp.StatusCode)
	}
	var payload dingTalkAccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return "", fmt.Errorf("钉钉 OAuth 未返回 accessToken")
	}
	return payload.AccessToken, nil
}

func sendDingTalkGroupMessage(accessToken, robotCode, conversationID, title, text string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("未配置群聊通知目标")
	}
	params, _ := json.Marshal(map[string]string{"title": title, "text": text})
	return postDingTalkOpenAPI("https://api.dingtalk.com/v1.0/robot/groupMessages/send", accessToken, map[string]string{
		"robotCode": robotCode, "msgKey": "sampleMarkdown", "msgParam": string(params), "openConversationId": conversationID,
	})
}

func sendDingTalkOTOMessage(accessToken, robotCode string, users []string, title, text string) error {
	if len(users) == 0 {
		return fmt.Errorf("未配置单聊通知用户")
	}
	params, _ := json.Marshal(map[string]string{"title": title, "text": text})
	payload := map[string]interface{}{"robotCode": robotCode, "userIds": users, "msgKey": "sampleMarkdown", "msgParam": string(params)}
	return postDingTalkOpenAPI("https://api.dingtalk.com/v1.0/robot/oToMessages/batchSend", accessToken, payload)
}

func postDingTalkOpenAPI(endpoint, accessToken string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		responseText, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("钉钉主动通知返回状态码: %d: %s", resp.StatusCode, strings.TrimSpace(string(responseText)))
	}
	return nil
}

func (s *DingTalkBotService) NotifyTask(task *models.TaskConfig) {
	if task == nil {
		return
	}
	event := DingTalkEventTaskCompleted
	if strings.EqualFold(task.Status, "failed") {
		event = DingTalkEventTaskFailed
	}
	if strings.EqualFold(task.Status, "cancelled") {
		event = DingTalkEventTaskCancelled
	}
	title := "扫描任务完成"
	if event == DingTalkEventTaskFailed {
		title = "扫描任务失败"
	}
	if event == DingTalkEventTaskCancelled {
		title = "扫描任务已取消"
	}
	text := fmt.Sprintf("### %s\n\n- **任务名称**: %s\n- **任务类型**: %s\n- **目标**: %s\n- **任务 ID**: `%s`\n- **状态**: %s\n- **详情**: /tasks/%s", title, task.TaskName, task.TaskType, truncateDing(task.TargetInput, 300), task.TaskID, task.Status, task.TaskID)
	if strings.EqualFold(task.TaskType, "port") && strings.EqualFold(task.Status, "completed") {
		title, text = buildPortScanDingTalkMessage(task)
	}
	s.notifyTaskToBots(task, title, text, event)
}

func truncateDing(v string, n int) string {
	v = strings.TrimSpace(v)
	if len(v) > n {
		return v[:n] + "..."
	}
	return v
}

func (s *DingTalkBotService) Start(ctx context.Context) {
	s.ctx = ctx
	bots, _ := s.ListBots()
	for _, b := range bots {
		if b.Enabled && !b.NotificationOnly && (b.AllowTaskCreation || b.AllowAIChat) && b.ClientID != "" {
			_ = s.StartBot(b.ID)
		}
	}
}
func (s *DingTalkBotService) StartBot(id int) error {
	b, err := scanBot(id)
	if err != nil {
		return err
	}
	sec, err := s.loadBotSecrets(id)
	if err != nil {
		return err
	}
	if b.NotificationOnly || !b.Enabled {
		return fmt.Errorf("机器人未开启入站 Stream 能力")
	}
	if sec.clientID == "" || sec.clientSecret == "" {
		return fmt.Errorf("机器人未配置 Stream Client ID/Secret")
	}
	s.StopBot(id)
	cli := client.NewStreamClient(client.WithAutoReconnect(true), client.WithAppCredential(client.NewAppCredentialConfig(sec.clientID, sec.clientSecret)))
	cli.RegisterChatBotCallbackRouter(s.callback(id))
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		if err := cli.Start(ctx); err != nil {
			logger.Warn("钉钉 Stream 连接失败: bot=%d err=%v", id, err)
			_ = s.updateStatus(id, "error", err.Error())
			return
		}
		_ = s.updateStatus(id, "connected", "")
	}()
	s.mu.Lock()
	s.clients[id] = cli
	s.mu.Unlock()
	_ = s.updateStatus(id, "connecting", "")
	_ = b
	return nil
}
func (s *DingTalkBotService) StopAll() {
	s.mu.Lock()
	ids := make([]int, 0, len(s.clients))
	for id := range s.clients {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.StopBot(id)
	}
}

func (s *DingTalkBotService) StopBot(id int) {
	s.mu.Lock()
	c := s.clients[id]
	delete(s.clients, id)
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
	_ = s.updateStatus(id, "disconnected", "")
}
func (s *DingTalkBotService) ReconnectBot(id int) error { s.StopBot(id); return s.StartBot(id) }
func (s *DingTalkBotService) updateStatus(id int, status, msg string) error {
	_, err := database.DB.Exec(`UPDATE dingtalk_bots SET stream_status=?,stream_last_error=?,stream_connected_at=CASE WHEN ?='connected' THEN CURRENT_TIMESTAMP ELSE stream_connected_at END,updated_at=CURRENT_TIMESTAMP WHERE id=?`, status, msg, status, id)
	return err
}
func (s *DingTalkBotService) callback(botID int) chatbot.IChatBotMessageHandler {
	return func(ctx context.Context, data *chatbot.BotCallbackDataModel) ([]byte, error) {
		if err := s.processMessage(ctx, botID, data); err != nil {
			logger.Warn("钉钉消息处理失败: %v", err)
			return nil, err
		}
		return []byte(""), nil
	}
}

func (s *DingTalkBotService) processMessage(ctx context.Context, botID int, data *chatbot.BotCallbackDataModel) error {
	if data == nil || strings.TrimSpace(data.MsgId) == "" {
		return nil
	}
	content := strings.TrimSpace(data.Text.Content)
	res, err := database.DB.Exec(`INSERT INTO dingtalk_messages (bot_id,message_id,conversation_id,conversation_type,sender_id,sender_staff_id,content,processed_at) VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT (bot_id,message_id) DO NOTHING`, botID, data.MsgId, data.ConversationId, data.ConversationType, data.SenderId, data.SenderStaffId, content)
	if err != nil {
		return err
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return nil
	}
	bot, err := scanBot(botID)
	if err != nil {
		return err
	}
	if !bot.Enabled {
		return nil
	}

	if bot.NotificationOnly {
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("当前机器人仅用于出站通知，未开启钉钉入站能力。"))
		return nil
	}

	// 绑定命令允许尚未绑定的用户完成首次绑定。
	if bindingCode := parseDingTalkBindingCommand(content); bindingCode != "" {
		if err := s.bindIncomingCode(botID, data, bindingCode); err != nil {
			_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("绑定失败："+err.Error()))
			return nil
		}
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("绑定成功，现在可以创建扫描任务或进行 AI 对话。"))
		return nil
	}

	userID, err := s.lookupBoundUser(botID, data)
	if err != nil {
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("请先在 FusionWeb 的钉钉机器人页面生成绑定码，然后发送：绑定 <绑定码>"))
		return nil
	}
	if !s.allowed(botID, data) {
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("当前用户或群聊不在机器人白名单中。"))
		return nil
	}

	cfg, recognized, message := ParseDingTalkTaskCommand(content)
	if recognized {
		if message != "" {
			_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte(message))
			return nil
		}
		if !bot.AllowTaskCreation {
			_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("当前机器人未开启任务创建功能。"))
			return nil
		}
		s.mu.Lock()
		creator := s.taskCreator
		s.mu.Unlock()
		if creator == nil {
			return fmt.Errorf("任务创建服务未初始化")
		}
		cfg.DingTalkBotID = botID
		cfg.DingTalkConversationID = data.ConversationId
		cfg.DingTalkConversationType = data.ConversationType
		cfg.DingTalkSourceUserID = dingTalkSourceUserID(data)
		cfg.DingTalkSourceMessageID = data.MsgId
		taskID, err := creator(cfg, uint(userID))
		if err != nil {
			_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("任务创建失败："+err.Error()))
			return nil
		}
		_, _ = database.DB.Exec(`UPDATE dingtalk_messages SET task_id=? WHERE bot_id=? AND message_id=?`, taskID, botID, data.MsgId)
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("任务已创建："+taskID))
		return nil
	}
	if !bot.AllowAIChat {
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("未识别到任务命令，且当前机器人未开启 AI 对话。可发送：web <网址>、port <IP> --ports 80,443 或 subdomain <域名>。"))
		return nil
	}
	return s.handleDingTalkAI(ctx, botID, userID, data, content)
}

func parseDingTalkBindingCommand(content string) string {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "@") {
		if index := strings.IndexAny(content, " \t\r\n"); index >= 0 {
			content = strings.TrimSpace(content[index:])
		}
	}
	parts := strings.Fields(content)
	if len(parts) == 2 && (strings.EqualFold(parts[0], "bind") || parts[0] == "绑定") {
		return strings.ToUpper(strings.TrimSpace(parts[1]))
	}
	return ""
}

func (s *DingTalkBotService) lookupBoundUser(botID int, data *chatbot.BotCallbackDataModel) (int, error) {
	ids := []string{strings.TrimSpace(data.SenderId), strings.TrimSpace(data.SenderStaffId)}
	for _, dingID := range ids {
		if dingID == "" {
			continue
		}
		var userID int
		if err := database.DB.QueryRow(`SELECT user_id FROM dingtalk_bindings WHERE bot_id=? AND ding_user_id=? AND enabled=1`, botID, dingID).Scan(&userID); err == nil {
			return userID, nil
		}
	}
	return 0, sql.ErrNoRows
}

func (s *DingTalkBotService) bindIncomingCode(botID int, data *chatbot.BotCallbackDataModel, code string) error {
	var codeID, userID int
	if err := database.DB.QueryRow(`SELECT id,user_id FROM dingtalk_binding_codes WHERE bot_id=? AND code_hash=? AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1`, botID, sha256Hex(code)).Scan(&codeID, &userID); err != nil {
		return fmt.Errorf("绑定码无效或已过期")
	}
	dingID := strings.TrimSpace(data.SenderId)
	if dingID == "" {
		dingID = strings.TrimSpace(data.SenderStaffId)
	}
	if dingID == "" {
		return fmt.Errorf("无法识别钉钉用户")
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO dingtalk_bindings (bot_id,user_id,ding_user_id,ding_user_name,conversation_id,enabled,created_at,updated_at) VALUES (?,?,?,?,?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (bot_id,ding_user_id) DO UPDATE SET user_id=excluded.user_id,ding_user_name=excluded.ding_user_name,conversation_id=excluded.conversation_id,enabled=1,updated_at=CURRENT_TIMESTAMP`, botID, userID, dingID, data.SenderNick, data.ConversationId); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE dingtalk_binding_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?`, codeID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DingTalkBotService) handleDingTalkAI(ctx context.Context, botID, userID int, data *chatbot.BotCallbackDataModel, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	conversationID := strings.TrimSpace(data.ConversationId)
	if conversationID == "" {
		conversationID = "user:" + strings.TrimSpace(data.SenderId)
	}
	var sessionID int64
	err := database.DB.QueryRow(`INSERT INTO dingtalk_ai_sessions (bot_id,user_id,conversation_id,title,created_at,updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (bot_id,user_id,conversation_id) DO UPDATE SET updated_at=CURRENT_TIMESTAMP RETURNING id`, botID, userID, conversationID, truncateDing(content, 80)).Scan(&sessionID)
	if err != nil {
		return err
	}
	if _, err := database.DB.Exec(`INSERT INTO dingtalk_ai_messages (session_id,role,content) VALUES (?,?,?)`, sessionID, "user", content); err != nil {
		return err
	}
	rows, err := database.DB.Query(`SELECT role,content FROM (SELECT id,role,content FROM dingtalk_ai_messages WHERE session_id=? ORDER BY id DESC LIMIT 20) history ORDER BY id ASC`, sessionID)
	if err != nil {
		return err
	}
	messages := make([]AIChatMessage, 0, 20)
	for rows.Next() {
		var message AIChatMessage
		if err := rows.Scan(&message.Role, &message.Content); err != nil {
			rows.Close()
			return err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	response, err := NewSystemSettingsService().ChatWithAI(AIChatRequest{
		Messages:     messages,
		SystemPrompt: "你是 FusionWeb 安全扫描平台的钉钉 AI 助手。请使用简体中文，回答清晰、准确、可执行。",
	}, userID)
	if err != nil {
		_ = chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte("AI 对话失败："+err.Error()))
		return nil
	}
	if _, err := database.DB.Exec(`INSERT INTO dingtalk_ai_messages (session_id,role,content) VALUES (?,?,?)`, sessionID, "assistant", response.Content); err != nil {
		return err
	}
	return chatbot.NewChatbotReplier().SimpleReplyMarkdown(ctx, data.SessionWebhook, []byte("AI 回复"), []byte(response.Content))
}

func (s *DingTalkBotService) allowed(botID int, data *chatbot.BotCallbackDataModel) bool {
	var n int
	_ = database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_allowlist WHERE bot_id=? AND enabled=1`, botID).Scan(&n)
	if n == 0 {
		return true
	}
	userAllowed := false
	for _, senderID := range []string{strings.TrimSpace(data.SenderId), strings.TrimSpace(data.SenderStaffId)} {
		if senderID == "" {
			continue
		}
		var count int
		_ = database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_allowlist WHERE bot_id=? AND enabled=1 AND entry_type='user' AND entry_value=?`, botID, senderID).Scan(&count)
		if count > 0 {
			userAllowed = true
			break
		}
	}
	var groupAllowed int
	_ = database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_allowlist WHERE bot_id=? AND enabled=1 AND entry_type='group' AND entry_value=?`, botID, strings.TrimSpace(data.ConversationId)).Scan(&groupAllowed)
	return userAllowed || groupAllowed > 0
}

var taskCommandRE = regexp.MustCompile(`(?i)^\s*(?:@[^\s]+\s*)?(web|port|subdomain|子域名|端口|网站|扫描)(?:\s+(.+?))?\s*$`)

func ParseDingTalkTaskCommand(content string) (models.TaskConfig, bool, string) {
	content = strings.TrimSpace(content)
	if strings.HasPrefix(content, "@") {
		if i := strings.IndexAny(content, " \t\r\n"); i >= 0 {
			content = strings.TrimSpace(content[i:])
		}
	}
	m := taskCommandRE.FindStringSubmatch(content)
	if len(m) < 3 {
		return models.TaskConfig{}, false, "请输入：web <网址>、port <IP> [--ports 80,443] 或 subdomain <域名>"
	}
	typ := strings.ToLower(m[1])
	target := strings.TrimSpace(m[2])
	if typ == "扫描" || typ == "网站" {
		typ = "web"
	}
	if typ == "端口" {
		typ = "port"
	}
	if typ == "子域名" {
		typ = "subdomain"
	}
	ports := ""
	if i := strings.Index(strings.ToLower(target), "--ports"); i >= 0 {
		ports = strings.TrimSpace(target[i+7:])
		target = strings.TrimSpace(target[:i])
	}
	if target == "" {
		return models.TaskConfig{}, true, "请提供扫描目标"
	}
	mode := "alive"
	if typ == "port" {
		mode = "port_service"
	}
	return models.TaskConfig{TaskName: "钉钉创建-" + truncateDing(target, 40), TaskType: typ, TargetInput: target, PortRange: ports, ScanMode: mode, ScanOptions: "{}", SelectedDicts: "[]", ThreadCount: 10, PortScanTimeout: 3, WebTimeout: 20, PortsThreshold: 65535, SYNScanRate: 10000}, true, ""
}

func (s *DingTalkBotService) GenerateBindingCode(botID, userID int) (DingTalkBindingCode, error) {
	raw := fmt.Sprintf("%d-%d-%d", botID, userID, time.Now().UnixNano())
	sum := sha256.Sum256([]byte(raw))
	code := strings.ToUpper(hex.EncodeToString(sum[:]))[:8]
	exp := time.Now().Add(10 * time.Minute)
	_, err := database.DB.Exec(`INSERT INTO dingtalk_binding_codes (bot_id,user_id,code_hash,expires_at) VALUES (?,?,?,?)`, botID, userID, sha256Hex(code), exp)
	return DingTalkBindingCode{Code: code, ExpiresAt: exp.Format(time.RFC3339)}, err
}
func sha256Hex(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func (s *DingTalkBotService) BindCode(botID, userID int, dingID, name, code string) error {
	var id int
	err := database.DB.QueryRow(`SELECT id FROM dingtalk_binding_codes WHERE bot_id=? AND user_id=? AND code_hash=? AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1`, botID, userID, sha256Hex(strings.ToUpper(strings.TrimSpace(code)))).Scan(&id)
	if err != nil {
		return fmt.Errorf("绑定码无效或已过期")
	}
	_, err = database.DB.Exec(`INSERT INTO dingtalk_bindings (bot_id,user_id,ding_user_id,ding_user_name,enabled,created_at,updated_at) VALUES (?,?,?,?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (bot_id,ding_user_id) DO UPDATE SET user_id=excluded.user_id,ding_user_name=excluded.ding_user_name,enabled=1,updated_at=CURRENT_TIMESTAMP`, botID, userID, dingID, name)
	if err == nil {
		_, err = database.DB.Exec(`UPDATE dingtalk_binding_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	}
	return err
}
func (s *DingTalkBotService) ListBindings(botID int) ([]DingTalkBinding, error) {
	rows, err := database.DB.Query(`SELECT id,bot_id,user_id,ding_user_id,ding_user_name,conversation_id,enabled,created_at FROM dingtalk_bindings WHERE bot_id=? ORDER BY id DESC`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DingTalkBinding{}
	for rows.Next() {
		var x DingTalkBinding
		var en int
		var at string
		if err := rows.Scan(&x.ID, &x.BotID, &x.UserID, &x.DingUserID, &x.DingUserName, &x.ConversationID, &en, &at); err != nil {
			return nil, err
		}
		x.Enabled = en == 1
		x.CreatedAt = at
		out = append(out, x)
	}
	return out, nil
}
func (s *DingTalkBotService) DeleteBinding(id int) error {
	_, err := database.DB.Exec(`DELETE FROM dingtalk_bindings WHERE id=?`, id)
	return err
}
func (s *DingTalkBotService) ListAllowlist(botID int) ([]DingTalkAllowlist, error) {
	rows, err := database.DB.Query(`SELECT id,bot_id,entry_type,entry_value,enabled,description FROM dingtalk_allowlist WHERE bot_id=? ORDER BY id DESC`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DingTalkAllowlist{}
	for rows.Next() {
		var x DingTalkAllowlist
		var en int
		if err := rows.Scan(&x.ID, &x.BotID, &x.EntryType, &x.EntryValue, &en, &x.Description); err != nil {
			return nil, err
		}
		x.Enabled = en == 1
		out = append(out, x)
	}
	return out, nil
}
func (s *DingTalkBotService) SaveAllowlist(x DingTalkAllowlist) (DingTalkAllowlist, error) {
	x.EntryType = strings.ToLower(strings.TrimSpace(x.EntryType))
	x.EntryValue = strings.TrimSpace(x.EntryValue)
	if x.EntryType != "user" && x.EntryType != "group" {
		return x, fmt.Errorf("白名单类型必须是 user 或 group")
	}
	if x.BotID <= 0 || x.EntryValue == "" {
		return x, fmt.Errorf("白名单机器人和条目不能为空")
	}
	if x.ID > 0 {
		result, err := database.DB.Exec(`UPDATE dingtalk_allowlist SET bot_id=?,entry_type=?,entry_value=?,enabled=?,description=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, x.BotID, x.EntryType, x.EntryValue, boolInt(x.Enabled), strings.TrimSpace(x.Description), x.ID)
		if err != nil {
			return x, err
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return x, fmt.Errorf("白名单记录不存在")
		}
	} else {
		_, err := database.DB.Exec(`INSERT INTO dingtalk_allowlist (bot_id,entry_type,entry_value,enabled,description) VALUES (?,?,?,?,?) ON CONFLICT (bot_id,entry_type,entry_value) DO UPDATE SET enabled=excluded.enabled,description=excluded.description,updated_at=CURRENT_TIMESTAMP`, x.BotID, x.EntryType, x.EntryValue, boolInt(x.Enabled), strings.TrimSpace(x.Description))
		if err != nil {
			return x, err
		}
	}
	items, err := s.ListAllowlist(x.BotID)
	if err != nil {
		return x, err
	}
	for _, v := range items {
		if (x.ID > 0 && v.ID == x.ID) || (x.ID == 0 && v.EntryType == x.EntryType && v.EntryValue == x.EntryValue) {
			return v, nil
		}
	}
	return x, nil
}

func (s *DingTalkBotService) DeleteAllowlist(id int) error {
	_, err := database.DB.Exec(`DELETE FROM dingtalk_allowlist WHERE id=?`, id)
	return err
}

func (s *DingTalkBotService) MigrateLegacyDingTalkKeys() error {
	rows, err := database.DB.Query(`SELECT id,name,access_token,secret,notify_blacklist_add,notify_blacklist_remove,notify_web_scan_complete,notify_port_scan_complete,enabled FROM dingtalk_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name, token, secret string
		var a, b, c, d, en int
		if err := rows.Scan(&id, &name, &token, &secret, &a, &b, &c, &d, &en); err != nil {
			return err
		}
		var n int
		_ = database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_bots WHERE migrated_from_key_id=?`, id).Scan(&n)
		if n > 0 {
			continue
		}
		tc, e := EncryptSecret(token)
		if e != nil {
			logger.Warn("迁移钉钉 Key %d 跳过: %v", id, e)
			continue
		}
		sc, e := EncryptSecret(secret)
		if e != nil {
			return e
		}
		_, e = database.DB.Exec(`INSERT INTO dingtalk_bots (name,enabled,webhook_token_cipher,webhook_secret_cipher,notify_blacklist_add,notify_blacklist_remove,notify_web_scan_complete,notify_port_scan_complete,notification_only,migrated_from_key_id) VALUES (?,?,?,?,?,?,?,?,1,?)`, name, en, tc, sc, a, b, c, d, id)
		if e != nil {
			return e
		}
	}
	return rows.Err()
}
