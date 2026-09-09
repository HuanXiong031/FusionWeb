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
	"strconv"
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
	ClearWebhook           bool   `json:"clearWebhook,omitempty"`
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

type DingTalkMessageDiagnostic struct {
	ID               int    `json:"id"`
	BotID            int    `json:"botId"`
	MessageID        string `json:"messageId"`
	ConversationID   string `json:"conversationId"`
	ConversationType string `json:"conversationType"`
	SenderID         string `json:"senderId"`
	SenderStaffID    string `json:"senderStaffId"`
	Content          string `json:"content"`
	TaskID           string `json:"taskId,omitempty"`
	ReplyError       string `json:"replyError,omitempty"`
	RepliedAt        string `json:"repliedAt,omitempty"`
	CreatedAt        string `json:"createdAt"`
}

type DingTalkDiagnostics struct {
	BotID          int                        `json:"botId"`
	StreamStatus   string                     `json:"streamStatus"`
	BindingCount   int                        `json:"bindingCount"`
	AllowlistCount int                        `json:"allowlistCount"`
	MessageCount   int                        `json:"messageCount"`
	LatestMessage  *DingTalkMessageDiagnostic `json:"latestMessage,omitempty"`
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
		// 允许管理员在界面上核对已保存的 Stream Client Secret（与钉钉后台 AppSecret 比对）。
		if csec.String != "" {
			if plainSecret, err := DecryptSecret(csec.String); err == nil {
				b.ClientSecret = plainSecret
			}
		}
		// 允许管理员在界面上核对已保存的出站 Webhook Token / Secret。
		if wt.String != "" {
			if plainToken, err := DecryptSecret(wt.String); err == nil {
				b.WebhookToken = plainToken
			}
		}
		if ws.String != "" {
			if plainSecret, err := DecryptSecret(ws.String); err == nil {
				b.WebhookSecret = plainSecret
			}
		}
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
		if csec.String != "" {
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
		if item.ClearWebhook {
			// 显式清除已保存的出站 Webhook，使通知改为通过企业应用机器人主动推送。
			item.WebhookToken = ""
			item.WebhookSecret = ""
		} else {
			if item.WebhookToken == "" {
				item.WebhookToken = old.webhookToken
			}
			if item.WebhookSecret == "" {
				item.WebhookSecret = old.webhookSecret
			}
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
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// 记录该机器人是否由遗留 dingtalk_keys 迁移而来，删除时一并清除旧记录，
	// 避免下次启动 MigrateLegacyDingTalkKeys 又重新创建该机器人。
	var migratedKeyID int
	_ = tx.QueryRow(`SELECT COALESCE(migrated_from_key_id,0) FROM dingtalk_bots WHERE id=?`, id).Scan(&migratedKeyID)
	// 级联清理该机器人的全部相关数据，避免残留孤儿记录。
	if _, err := tx.Exec(`DELETE FROM dingtalk_ai_messages WHERE session_id IN (SELECT id FROM dingtalk_ai_sessions WHERE bot_id=?)`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dingtalk_ai_sessions WHERE bot_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dingtalk_messages WHERE bot_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dingtalk_bindings WHERE bot_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dingtalk_binding_codes WHERE bot_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM dingtalk_bots WHERE id=?`, id); err != nil {
		return err
	}
	if migratedKeyID > 0 {
		if _, err := tx.Exec(`DELETE FROM dingtalk_keys WHERE id=?`, migratedKeyID); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	return primaryDingTalkSenderID(data)
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
	if strings.EqualFold(task.TaskType, "web") && strings.EqualFold(task.Status, "completed") {
		title, text = buildWebScanDingTalkMessage(task)
	}
	s.notifyTaskToBots(task, title, text, event)
}

func severityDingIcon(sev string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "🔴", "严重"
	case "high":
		return "🟠", "高危"
	case "medium":
		return "🟡", "中危"
	case "low":
		return "🔵", "低危"
	case "info":
		return "🟢", "信息"
	default:
		return "⚪", "未知"
	}
}

// buildWebScanDingTalkMessage 构建 Web 扫描完成后的富文本钉钉通知。
// 使用钉钉可识别的 Markdown：`- ` 列表项逐行换行、`\n\n` 分段、`**加粗**` 作小标题。
func buildWebScanDingTalkMessage(task *models.TaskConfig) (string, string) {
	title := "🚨 扫描完成"
	text := "⚠️ 发现安全漏洞，请及时处理！\n\n"
	text += "- 任务名称: " + task.TaskName + "\n"
	text += "- 目标: " + truncateDing(task.TargetInput, 300) + "\n"
	text += "- 扫描模式: " + truncateDing(task.ScanMode, 40) + "\n"

	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
	if database.DB != nil {
		if rows, err := database.DB.Query(`SELECT COALESCE(NULLIF(severity,''),'unknown') AS sev, COUNT(*) FROM vuln_results WHERE task_id=? GROUP BY 1`, task.TaskID); err == nil {
			for rows.Next() {
				var sev string
				var n int
				if rows.Scan(&sev, &n) == nil {
					counts[sev] = n
				}
			}
			rows.Close()
		}
	}
	total := counts["critical"] + counts["high"] + counts["medium"] + counts["low"] + counts["info"] + counts["unknown"]
	text += fmt.Sprintf("- 发现漏洞: %d 个\n", total)
	text += fmt.Sprintf("- 🔴 严重: %d\n", counts["critical"])
	text += fmt.Sprintf("- 🟠 高危: %d\n", counts["high"])
	text += fmt.Sprintf("- 🟡 中危: %d\n", counts["medium"])
	text += fmt.Sprintf("- 🔵 低危: %d\n", counts["low"])
	text += fmt.Sprintf("- 🟢 信息: %d\n", counts["info"])
	text += fmt.Sprintf("- ⚪ 未知: %d\n", counts["unknown"])

	if total > 0 && database.DB != nil {
		text += "\n**漏洞详情:**\n"
		if rows, err := database.DB.Query(`SELECT name,severity,COALESCE(target,'') FROM vuln_results WHERE task_id=? ORDER BY id ASC LIMIT 20`, task.TaskID); err == nil {
			for rows.Next() {
				var name, sev, target string
				if rows.Scan(&name, &sev, &target) == nil {
					icon, label := severityDingIcon(sev)
					text += fmt.Sprintf("- %s [%s] %s: %s\n", icon, label, name, truncateDing(target, 200))
				}
			}
			rows.Close()
		}
	}

	targets := map[string]bool{}
	fcount := 0
	var finfo strings.Builder
	if database.DB != nil {
		if rows, err := database.DB.Query(`SELECT target,COALESCE(fingerprint_name,'') FROM fingerprint_results WHERE task_id=? ORDER BY id ASC LIMIT 30`, task.TaskID); err == nil {
			for rows.Next() {
				var target, fname string
				if rows.Scan(&target, &fname) == nil {
					fcount++
					targets[target] = true
					finfo.WriteString(fmt.Sprintf("- %02d、  %s  %s\n", fcount, truncateDing(target, 120), fname))
				}
			}
			rows.Close()
		}
	}
	if fcount > 0 {
		text += fmt.Sprintf("\n**指纹识别 (共 %d 个目标，%d 条记录):**\n%s", len(targets), fcount, finfo.String())
	}

	text += "\n🕒 通知时间: " + utils.GetCurrentTimeString()
	return title, text
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
	if data == nil {
		return nil
	}
	content := normalizeDingTalkText(data.Text.Content)
	messageID := dingTalkMessageID(botID, data, content)
	logger.Info("钉钉入站消息: bot=%d msg=%s sender=%s staff=%s conv=%s content=%q", botID, maskedDingTalkValue(messageID), maskedDingTalkValue(data.SenderId), maskedDingTalkValue(data.SenderStaffId), maskedDingTalkValue(data.ConversationId), truncateDing(content, 80))
	res, err := database.DB.Exec(`INSERT INTO dingtalk_messages (bot_id,message_id,conversation_id,conversation_type,sender_id,sender_staff_id,content,processed_at) VALUES (?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT (bot_id,message_id) DO NOTHING`, botID, messageID, data.ConversationId, data.ConversationType, data.SenderId, data.SenderStaffId, content)
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
		_ = s.replyText(ctx, botID, messageID, data, "当前机器人仅用于出站通知，未开启钉钉入站能力。")
		return nil
	}

	// 绑定命令允许尚未绑定的用户完成首次绑定。
	if bindingCode := parseDingTalkBindingCommand(content); bindingCode != "" {
		if err := s.bindIncomingCode(botID, data, bindingCode); err != nil {
			_ = s.replyText(ctx, botID, messageID, data, "绑定失败："+err.Error())
			return nil
		}
		_ = s.replyText(ctx, botID, messageID, data, "绑定成功，现在可以创建扫描任务或进行 AI 对话。")
		return nil
	}

	userID, err := s.lookupBoundUser(botID, data)
	if err != nil {
		_ = s.replyText(ctx, botID, messageID, data, "请先在 FusionWeb 的钉钉机器人页面生成绑定码，然后发送：绑定 <绑定码>")
		return nil
	}
	if !s.allowed(botID, data) {
		_ = s.replyText(ctx, botID, messageID, data, "当前用户或群聊不在机器人白名单中。")
		return nil
	}

	cfg, recognized, message := ParseDingTalkTaskCommand(content)
	if recognized {
		if message != "" {
			_ = s.replyText(ctx, botID, messageID, data, message)
			return nil
		}
		if !bot.AllowTaskCreation {
			_ = s.replyText(ctx, botID, messageID, data, "当前机器人未开启任务创建功能。")
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
		cfg.DingTalkSourceMessageID = messageID
		taskID, err := creator(cfg, uint(userID))
		if err != nil {
			_ = s.replyText(ctx, botID, messageID, data, "任务创建失败："+err.Error())
			return nil
		}
		_, _ = database.DB.Exec(`UPDATE dingtalk_messages SET task_id=? WHERE bot_id=? AND message_id=?`, taskID, botID, messageID)
		_ = s.replyText(ctx, botID, messageID, data, "任务已创建："+taskID)
		return nil
	}
	if !bot.AllowAIChat {
		_ = s.replyText(ctx, botID, messageID, data, "未识别到任务命令，且当前机器人未开启 AI 对话。可发送：web <网址>、port <IP> --ports 80,443 或 subdomain <域名>。")
		return nil
	}
	return s.handleDingTalkAI(ctx, botID, userID, messageID, data, content)
}

var dingTalkBindingCommandRE = regexp.MustCompile(`(?i)(?:bind|绑定)\s*[:：]?\s*([a-z0-9]{6,16})`)

func dingTalkMessageID(botID int, data *chatbot.BotCallbackDataModel, content string) string {
	if data == nil {
		return ""
	}
	if msgID := strings.TrimSpace(data.MsgId); msgID != "" {
		return msgID
	}
	base := fmt.Sprintf("%d|%s|%s|%s|%s|%d", botID, strings.TrimSpace(data.ConversationId), strings.TrimSpace(data.SenderStaffId), strings.TrimSpace(data.SenderId), content, data.CreateAt)
	return "fallback-" + sha256Hex(base)[:32]
}

func normalizeDingTalkText(v string) string {
	replacer := strings.NewReplacer(
		"\u00a0", " ",
		"\u1680", " ",
		"\u180e", "",
		"\u2000", " ", "\u2001", " ", "\u2002", " ", "\u2003", " ", "\u2004", " ",
		"\u2005", " ", "\u2006", " ", "\u2007", " ", "\u2008", " ", "\u2009", " ", "\u200a", " ",
		"\u200b", "", "\u200c", "", "\u200d", "",
		"\u2028", " ", "\u2029", " ",
		"\u202f", " ",
		"\u205f", " ",
		"\u3000", " ",
		"\ufeff", "",
	)
	v = replacer.Replace(v)
	return strings.TrimSpace(strings.Join(strings.Fields(v), " "))
}

func parseDingTalkBindingCommand(content string) string {
	content = normalizeDingTalkText(content)
	m := dingTalkBindingCommandRE.FindStringSubmatch(content)
	if len(m) < 2 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(m[1]))
}

func dingTalkSenderIDs(data *chatbot.BotCallbackDataModel) []string {
	if data == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	for _, id := range []string{strings.TrimSpace(data.SenderStaffId), strings.TrimSpace(data.SenderId)} {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func primaryDingTalkSenderID(data *chatbot.BotCallbackDataModel) string {
	ids := dingTalkSenderIDs(data)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func maskedDingTalkValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	runes := []rune(v)
	if len(runes) <= 8 {
		return fmt.Sprintf("***(%d)", len(runes))
	}
	return string(runes[:4]) + "***" + string(runes[len(runes)-4:])
}

func (s *DingTalkBotService) lookupBoundUser(botID int, data *chatbot.BotCallbackDataModel) (int, error) {
	for _, dingID := range dingTalkSenderIDs(data) {
		var userID int
		if err := database.DB.QueryRow(`SELECT user_id FROM dingtalk_bindings WHERE bot_id=? AND ding_user_id=? AND enabled=1`, botID, dingID).Scan(&userID); err == nil {
			return userID, nil
		}
	}
	return 0, sql.ErrNoRows
}

func (s *DingTalkBotService) bindIncomingCode(botID int, data *chatbot.BotCallbackDataModel, code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	var codeID, userID int
	if err := database.DB.QueryRow(`SELECT id,user_id FROM dingtalk_binding_codes WHERE bot_id=? AND code_hash=? AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1`, botID, sha256Hex(code)).Scan(&codeID, &userID); err != nil {
		logger.Warn("钉钉绑定失败: bot=%d code=%s sender=%s staff=%s err=code_invalid", botID, maskedDingTalkValue(code), maskedDingTalkValue(data.SenderId), maskedDingTalkValue(data.SenderStaffId))
		return fmt.Errorf("绑定码无效或已过期")
	}
	dingID := primaryDingTalkSenderID(data)
	if dingID == "" {
		logger.Warn("钉钉绑定失败: bot=%d code=%s sender=%s staff=%s err=empty_sender", botID, maskedDingTalkValue(code), maskedDingTalkValue(data.SenderId), maskedDingTalkValue(data.SenderStaffId))
		return fmt.Errorf("无法识别钉钉用户")
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM dingtalk_bindings WHERE bot_id=? AND (ding_user_id=? OR user_id=?)`, botID, dingID, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO dingtalk_bindings (bot_id,user_id,ding_user_id,ding_user_name,conversation_id,enabled,created_at,updated_at) VALUES (?,?,?,?,?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, botID, userID, dingID, strings.TrimSpace(data.SenderNick), strings.TrimSpace(data.ConversationId)); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE dingtalk_binding_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?`, codeID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	logger.Info("钉钉绑定成功: bot=%d user=%d ding=%s conv=%s", botID, userID, maskedDingTalkValue(dingID), maskedDingTalkValue(data.ConversationId))
	return nil
}

func (s *DingTalkBotService) handleDingTalkAI(ctx context.Context, botID, userID int, messageID string, data *chatbot.BotCallbackDataModel, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	conversationID := strings.TrimSpace(data.ConversationId)
	if conversationID == "" {
		conversationID = "user:" + primaryDingTalkSenderID(data)
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
		_ = s.replyText(ctx, botID, messageID, data, "AI 对话失败："+err.Error())
		return nil
	}
	if _, err := database.DB.Exec(`INSERT INTO dingtalk_ai_messages (session_id,role,content) VALUES (?,?,?)`, sessionID, "assistant", response.Content); err != nil {
		return err
	}
	return s.replyMarkdown(ctx, botID, messageID, data, "AI 回复", response.Content)
}

func (s *DingTalkBotService) replyText(ctx context.Context, botID int, messageID string, data *chatbot.BotCallbackDataModel, content string) error {
	if data == nil || strings.TrimSpace(data.SessionWebhook) == "" {
		err := fmt.Errorf("钉钉回复地址为空")
		s.recordReplyError(botID, messageID, err)
		logger.Warn("钉钉回复失败: bot=%d msg=%s err=%v", botID, maskedDingTalkValue(messageID), err)
		return err
	}
	err := chatbot.NewChatbotReplier().SimpleReplyText(ctx, data.SessionWebhook, []byte(content))
	if err != nil {
		s.recordReplyError(botID, messageID, err)
		logger.Warn("钉钉回复失败: bot=%d msg=%s err=%v", botID, maskedDingTalkValue(messageID), err)
		return err
	}
	s.recordReplySuccess(botID, messageID)
	return nil
}

func (s *DingTalkBotService) replyMarkdown(ctx context.Context, botID int, messageID string, data *chatbot.BotCallbackDataModel, title, content string) error {
	if data == nil || strings.TrimSpace(data.SessionWebhook) == "" {
		err := fmt.Errorf("钉钉回复地址为空")
		s.recordReplyError(botID, messageID, err)
		logger.Warn("钉钉 Markdown 回复失败: bot=%d msg=%s err=%v", botID, maskedDingTalkValue(messageID), err)
		return err
	}
	err := chatbot.NewChatbotReplier().SimpleReplyMarkdown(ctx, data.SessionWebhook, []byte(title), []byte(content))
	if err != nil {
		s.recordReplyError(botID, messageID, err)
		logger.Warn("钉钉 Markdown 回复失败: bot=%d msg=%s err=%v", botID, maskedDingTalkValue(messageID), err)
		return err
	}
	s.recordReplySuccess(botID, messageID)
	return nil
}

func (s *DingTalkBotService) recordReplyError(botID int, messageID string, err error) {
	if database.DB != nil && strings.TrimSpace(messageID) != "" {
		_, _ = database.DB.Exec(`UPDATE dingtalk_messages SET reply_error=? WHERE bot_id=? AND message_id=?`, truncateDing(err.Error(), 500), botID, messageID)
	}
}

func (s *DingTalkBotService) recordReplySuccess(botID int, messageID string) {
	if database.DB != nil && strings.TrimSpace(messageID) != "" {
		_, _ = database.DB.Exec(`UPDATE dingtalk_messages SET reply_error='',replied_at=CURRENT_TIMESTAMP WHERE bot_id=? AND message_id=?`, botID, messageID)
	}
}

func (s *DingTalkBotService) allowed(botID int, data *chatbot.BotCallbackDataModel) bool {
	var n int
	_ = database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_allowlist WHERE bot_id=? AND enabled=1`, botID).Scan(&n)
	if n == 0 {
		return true
	}
	userAllowed := false
	for _, senderID := range dingTalkSenderIDs(data) {
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

const dingTalkHelpText = `【FusionWeb 钉钉机器人 · 支持命令】
/help 或 /?        查看支持的功能
/web <网址>        Web 扫描（默认模式 alive）
/port <IP>         端口扫描（默认 port_service）
/subdomain <域名>  子域名枚举
绑定 <绑定码>       绑定 FusionWeb 账号

参数（--key value 或 --flag，空格分隔）：
  --mode <alive|fingerprint|fingerprint_poc|poc>  Web 扫描模式（默认 alive）
  --ports <80,443|1-1000|all>   端口范围
  --threads <n>    并发线程数（默认 10）
  --timeout <秒>   Web 探测/端口扫描超时（默认 20 / 3）
  --rate <pps>     SYN 扫描速率（默认 10000）
  --screenshot     启用页面截图
  --poc-all        全量 POC（忽略指纹）
  --fingerprint    启用主动指纹探测
  --proxy <url>    HTTP 代理
  --dict <a,b,c>   子域名字典

示例：
  /web https://example.com --mode fingerprint_poc --screenshot
  /port 192.168.1.1 --ports 80,443 --timeout 3
  /subdomain example.com --threads 20`

func ParseDingTalkTaskCommand(content string) (models.TaskConfig, bool, string) {
	content = normalizeDingTalkText(content)
	if strings.HasPrefix(content, "@") {
		if i := strings.IndexAny(content, " \t\r\n"); i >= 0 {
			content = strings.TrimSpace(content[i:])
		}
	}
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return models.TaskConfig{}, false, ""
	}
	isSlash := strings.HasPrefix(fields[0], "/")
	cmd := strings.ToLower(strings.TrimPrefix(fields[0], "/"))

	if cmd == "help" || cmd == "?" || cmd == "帮助" {
		return models.TaskConfig{}, true, dingTalkHelpText
	}

	typ := ""
	switch cmd {
	case "web", "网站", "扫描":
		typ = "web"
	case "port", "端口":
		typ = "port"
	case "subdomain", "子域名":
		typ = "subdomain"
	default:
		if isSlash {
			return models.TaskConfig{}, true, "未知命令：" + fields[0] + "。发送 /help 查看支持的功能。"
		}
		return models.TaskConfig{}, false, "请输入：/web <网址>、/port <IP> [--ports 80,443] 或 /subdomain <域名>（发送 /help 查看帮助）"
	}

	// 解析 --key value 与 --flag 参数；其余 token 作为扫描目标（可含空格/URL）。
	params := map[string]string{}
	var targetParts []string
	rest := fields[1:]
	for i := 0; i < len(rest); i++ {
		t := rest[i]
		if strings.HasPrefix(t, "--") {
			key := strings.ToLower(strings.TrimPrefix(t, "--"))
			if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "--") {
				params[key] = rest[i+1]
				i++
			} else {
				params[key] = ""
			}
			continue
		}
		targetParts = append(targetParts, t)
	}
	target := strings.TrimSpace(strings.Join(targetParts, " "))
	if target == "" {
		return models.TaskConfig{}, true, "请提供扫描目标"
	}

	cfg := models.TaskConfig{
		TaskName:        "钉钉创建-" + truncateDing(target, 40),
		TaskType:        typ,
		TargetInput:     target,
		PortRange:       params["ports"],
		ScanMode:        "alive",
		ScanOptions:     "{}",
		SelectedDicts:   "[]",
		ThreadCount:     10,
		PortScanTimeout: 3,
		WebTimeout:      20,
		PortsThreshold:  65535,
		SYNScanRate:     10000,
	}
	if typ == "port" {
		cfg.ScanMode = "port_service"
	}
	if v, ok := params["mode"]; ok && v != "" {
		cfg.ScanMode = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := params["threads"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ThreadCount = n
		}
	}
	if v, ok := params["timeout"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if typ == "port" {
				cfg.PortScanTimeout = n
			} else {
				cfg.WebTimeout = n
			}
		}
	}
	if v, ok := params["rate"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SYNScanRate = n
		}
	}
	if v, ok := params["proxy"]; ok {
		cfg.HTTPProxy = strings.TrimSpace(v)
	}
	if v, ok := params["dict"]; ok && v != "" {
		items := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
		quoted := make([]string, 0, len(items))
		for _, it := range items {
			if it = strings.TrimSpace(it); it != "" {
				quoted = append(quoted, it)
			}
		}
		if len(quoted) > 0 {
			cfg.SelectedDicts = "[" + strings.Join(quoted, `","`) + "]"
		}
	}
	if _, ok := params["screenshot"]; ok {
		cfg.EnableScreenshot = true
	}
	if _, ok := params["poc-all"]; ok {
		cfg.FullPocScan = true
	}
	if _, ok := params["fingerprint"]; ok {
		cfg.EnableActiveFingerprint = true
	}
	return cfg, true, ""
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
func (s *DingTalkBotService) GetDiagnostics(botID int) (DingTalkDiagnostics, error) {
	if botID <= 0 {
		return DingTalkDiagnostics{}, fmt.Errorf("botId 不正确")
	}
	bot, err := s.GetBotStatus(botID)
	if err != nil {
		return DingTalkDiagnostics{}, err
	}
	d := DingTalkDiagnostics{BotID: botID, StreamStatus: bot.StreamStatus}
	if err := database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_bindings WHERE bot_id=? AND enabled=1`, botID).Scan(&d.BindingCount); err != nil {
		return d, err
	}
	if err := database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_allowlist WHERE bot_id=? AND enabled=1`, botID).Scan(&d.AllowlistCount); err != nil {
		return d, err
	}
	if err := database.DB.QueryRow(`SELECT COUNT(1) FROM dingtalk_messages WHERE bot_id=?`, botID).Scan(&d.MessageCount); err != nil {
		return d, err
	}
	var item DingTalkMessageDiagnostic
	var repliedAt sql.NullString
	err = database.DB.QueryRow(`SELECT id,bot_id,message_id,conversation_id,conversation_type,sender_id,sender_staff_id,content,task_id,reply_error,replied_at,created_at FROM dingtalk_messages WHERE bot_id=? ORDER BY id DESC LIMIT 1`, botID).Scan(&item.ID, &item.BotID, &item.MessageID, &item.ConversationID, &item.ConversationType, &item.SenderID, &item.SenderStaffID, &item.Content, &item.TaskID, &item.ReplyError, &repliedAt, &item.CreatedAt)
	if err == nil {
		if repliedAt.Valid {
			item.RepliedAt = repliedAt.String
		}
		d.LatestMessage = &item
	} else if err != sql.ErrNoRows {
		return d, err
	}
	return d, nil
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
