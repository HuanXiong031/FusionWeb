// backend/service/dingtalk_confirmation_service.go
//
// 待确认请求（Phase 3）：让 DSH 能在钉钉上"问一句、等回答、再执行"。
//
// 流程：
//  1. DSH 的 ask_dingtalk 工具 → POST /api/v1/svc/confirmations（带问题）→ 本服务生成短码并发送到钉钉；
//  2. 用户回复（含短码，或仅回复 1/0 且当前只有一个待确认）→ 钉钉入站消息匹配 → 写入答案并回执；
//  3. DSH 轮询 GET /api/v1/svc/confirmations/:id → 拿到 confirmed / denied / expired（超时=不执行）。
package service

import (
	"database/sql"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
)

// 短码字母表：去掉 0/O/1/I/S/B/8/2/Z 等易混字符。
const confirmationCodeAlphabet = "ACDEFGHJKLMNPQRTUVWXY34679"

var confirmationCodeRE = regexp.MustCompile(`[ACDEFGHJKLMNPQRTUVWXY34679]{4}`)

// PendingConfirmation 一条待确认请求。
type PendingConfirmation struct {
	ID        int64
	Code      string
	Question  string
	Status    string
	Answer    string
	ExpiresAt time.Time
}

func newConfirmationCode() string {
	b := make([]byte, 4)
	for i := range b {
		b[i] = confirmationCodeAlphabet[rand.Intn(len(confirmationCodeAlphabet))]
	}
	return string(b)
}

// ResolveDefaultConfirmationBotID 返回用于发送确认消息的机器人：优先已启用且配置了默认目标的。
func ResolveDefaultConfirmationBotID() int {
	if database.DB == nil {
		return 0
	}
	var id int
	err := database.DB.QueryRow(
		`SELECT id FROM dingtalk_bots WHERE enabled=1 AND COALESCE(default_target_value,'')<>'' ORDER BY id LIMIT 1`,
	).Scan(&id)
	if err == nil {
		return id
	}
	if err := database.DB.QueryRow(`SELECT id FROM dingtalk_bots WHERE enabled=1 ORDER BY id LIMIT 1`).Scan(&id); err == nil {
		return id
	}
	return 0
}

// SendDingTalkText 通过机器人的默认目标发送一条 Markdown 消息。
func SendDingTalkText(botID int, title, text string) error {
	if botID <= 0 {
		botID = ResolveDefaultConfirmationBotID()
	}
	if botID <= 0 {
		return fmt.Errorf("没有可用的钉钉机器人")
	}
	b, err := scanBot(botID)
	if err != nil {
		return fmt.Errorf("读取机器人失败：%w", err)
	}
	sec, err := loadBotSecretsByID(botID)
	if err != nil {
		return fmt.Errorf("读取机器人凭据失败：%w", err)
	}
	return sendDingTalkNotification(sec.webhookToken, sec.webhookSecret, sec.clientID, sec.clientSecret,
		"", "", "", b.DefaultTargetType, b.DefaultTargetValue, title, text)
}

// CreatePendingConfirmation 创建待确认请求并推送到钉钉，返回短码与记录 ID。
func CreatePendingConfirmation(question string, botID int, timeoutSec int) (*PendingConfirmation, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		return nil, fmt.Errorf("问题不能为空")
	}
	if timeoutSec <= 0 || timeoutSec > 3600 {
		timeoutSec = 600
	}
	if botID <= 0 {
		botID = ResolveDefaultConfirmationBotID()
	}

	code := newConfirmationCode()
	expiresAt := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	id, err := database.InsertAndReturnID(
		`INSERT INTO pending_confirmations (code,question,status,bot_id,expires_at,created_at,updated_at) VALUES (?,?,'pending',?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		code, question, botID, expiresAt,
	)
	if err != nil {
		return nil, err
	}

	text := fmt.Sprintf("%s\n\n回复 **%s 1** 确认，回复 **%s 0** 取消（%d 分钟内有效）。",
		question, code, code, timeoutSec/60)
	if err := SendDingTalkText(botID, "DSH 需要你确认", text); err != nil {
		logger.Warn("发送钉钉确认消息失败: id=%d err=%v", id, err)
		return &PendingConfirmation{ID: id, Code: code, Question: question, Status: "pending", ExpiresAt: expiresAt}, fmt.Errorf("确认消息发送失败：%w", err)
	}
	return &PendingConfirmation{ID: id, Code: code, Question: question, Status: "pending", ExpiresAt: expiresAt}, nil
}

// GetPendingConfirmation 读取待确认状态（超时的按 expired 返回，不改库）。
func GetPendingConfirmation(id int64) (*PendingConfirmation, error) {
	var item PendingConfirmation
	var expiresAt time.Time
	err := database.DB.QueryRow(
		`SELECT id,code,question,status,COALESCE(answer,''),expires_at FROM pending_confirmations WHERE id=?`, id,
	).Scan(&item.ID, &item.Code, &item.Question, &item.Status, &item.Answer, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("确认请求不存在")
		}
		return nil, err
	}
	item.ExpiresAt = expiresAt
	if item.Status == "pending" && time.Now().After(expiresAt) {
		item.Status = "expired"
	}
	return &item, nil
}

func parseConfirmationAnswer(content string) (string, bool) {
	up := strings.ToUpper(strings.TrimSpace(content))
	if up == "" {
		return "", false
	}
	compact := strings.NewReplacer(" ", "", "\t", "", "：", "", ":", "", "，", "", ",", "").Replace(up)
	switch {
	case compact == "1" || compact == "Y" || compact == "YES" || compact == "OK" ||
		strings.Contains(up, "确认") || strings.Contains(up, "同意") || strings.Contains(up, "允许"):
		return "confirmed", true
	case compact == "0" || compact == "N" || compact == "NO" ||
		strings.Contains(up, "取消") || strings.Contains(up, "拒绝") || strings.Contains(up, "不执行"):
		return "denied", true
	}
	return "", false
}

func markConfirmationAnswered(id int64, answer string) {
	if _, err := database.DB.Exec(
		`UPDATE pending_confirmations SET status=?,answer=?,answered_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'`,
		answer, answer, id,
	); err != nil {
		logger.Warn("写入确认结果失败: id=%d err=%v", id, err)
	}
}

// TryResolveConfirmationReply 判断入站消息是否是在回复某个待确认请求。
//   - 含短码：按 code 匹配（短码在待确认之间唯一）；
//   - 不含短码：内容为 1/0/确认/取消，且当前仅有一个有效待确认时按它处理。
//
// 返回 handled=true 时，调用方应直接回执 reply 并结束处理（不要再当命令或 AI 对话）。
func TryResolveConfirmationReply(botID int, content string) (reply string, handled bool) {
	if database.DB == nil {
		return "", false
	}
	answer, ok := parseConfirmationAnswer(content)
	if !ok {
		return "", false
	}
	up := strings.ToUpper(strings.TrimSpace(content))

	// ① 按短码匹配
	for _, code := range confirmationCodeRE.FindAllString(up, -1) {
		var id int64
		err := database.DB.QueryRow(
			`SELECT id FROM pending_confirmations WHERE code=? AND status='pending' AND expires_at > CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1`,
			code,
		).Scan(&id)
		if err == nil {
			markConfirmationAnswered(id, answer)
			return confirmationReplyText(answer, code), true
		}
	}

	// ② 无短码：仅当只有一个有效待确认
	rows, err := database.DB.Query(
		`SELECT id,code FROM pending_confirmations WHERE status='pending' AND expires_at > CURRENT_TIMESTAMP AND (?=0 OR bot_id=?) ORDER BY id DESC LIMIT 2`,
		botID, botID,
	)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	type pending struct {
		id   int64
		code string
	}
	var list []pending
	for rows.Next() {
		var p pending
		if rows.Scan(&p.id, &p.code) == nil {
			list = append(list, p)
		}
	}
	if len(list) == 1 {
		markConfirmationAnswered(list[0].id, answer)
		return confirmationReplyText(answer, list[0].code), true
	}
	if len(list) > 1 {
		return fmt.Sprintf("当前有多个待确认请求，请带上短码回复，例如：<短码> 1（确认）或 <短码> 0（取消）。"), true
	}
	return "", false
}

func confirmationReplyText(answer, code string) string {
	if answer == "confirmed" {
		return fmt.Sprintf("已收到确认（%s）：继续执行。", code)
	}
	return fmt.Sprintf("已收到取消（%s）：不再执行。", code)
}

// ExpirePendingConfirmations 把超时的待确认标记为 expired（由调度器周期调用）。
func ExpirePendingConfirmations() {
	if database.DB == nil {
		return
	}
	if _, err := database.DB.Exec(
		`UPDATE pending_confirmations SET status='expired',updated_at=CURRENT_TIMESTAMP WHERE status='pending' AND expires_at <= CURRENT_TIMESTAMP`,
	); err != nil {
		logger.Warn("标记超时确认失败: %v", err)
	}
}
