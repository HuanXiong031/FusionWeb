package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"
	"FusionWeb/backend/websocket"
	"bufio"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	RTSPDictPath     = "path"
	RTSPDictUsername = "username"
	RTSPDictPassword = "password"

	maxRTSPRealtimeLogs = 20000
)

type RTSPDictionaryItem struct {
	ID        int64  `json:"id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	CreatedBy int    `json:"createdBy"`
}

type RTSPDictionaryImportSummary struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
	Total    int `json:"total"`
}

type RTSPScanConfig struct {
	Targets     []string `json:"targets"`
	Port        int      `json:"port"`
	ThreadCount int      `json:"threadCount"`
	Timeout     int      `json:"timeout"`
	AuthMethod  string   `json:"authMethod"`
}

type RTSPScanTaskState struct {
	TaskID                 string           `json:"taskId"`
	Status                 string           `json:"status"`
	Progress               float64          `json:"progress"`
	TotalTargets           int              `json:"totalTargets"`
	Completed              int              `json:"completed"`
	TotalSteps             int              `json:"totalSteps,omitempty"`
	CompletedSteps         int              `json:"completedSteps,omitempty"`
	Found                  int              `json:"found"`
	StartedAt              string           `json:"startedAt"`
	CompletedAt            string           `json:"completedAt,omitempty"`
	Logs                   []RTSPScanLog    `json:"logs"`
	Results                []RTSPScanResult `json:"results"`
	cancel                 context.CancelFunc
	lastProgressBroadcast  time.Time
	lastHeartbeatBroadcast time.Time
	mu                     sync.Mutex
}

type RTSPScanLog struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type RTSPScanResult struct {
	ID         int64  `json:"id"`
	TaskID     string `json:"taskId"`
	Target     string `json:"target"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	URI        string `json:"uri"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthMethod string `json:"authMethod"`
	RTSPURL    string `json:"rtspUrl"`
	Response   string `json:"response"`
	Status     string `json:"status"`
	UserID     int    `json:"userId"`
	CreatedAt  string `json:"createdAt"`
}

type RTSPService struct {
	tasks map[string]*RTSPScanTaskState
	mu    sync.RWMutex
}

func NewRTSPService() *RTSPService {
	service := &RTSPService{tasks: make(map[string]*RTSPScanTaskState)}
	_ = service.SeedDefaultDictionaries()
	return service
}

func (s *RTSPService) ListDictionary(dictType, keyword string) ([]RTSPDictionaryItem, error) {
	dictType = normalizeRTSPDictType(dictType)
	keyword = strings.TrimSpace(keyword)
	query := `SELECT id, dict_type, value, enabled, CAST(created_at AS TEXT), CAST(updated_at AS TEXT), created_by
		FROM rtsp_dictionary WHERE 1=1`
	args := make([]interface{}, 0)
	if dictType != "" {
		args = append(args, dictType)
		query += fmt.Sprintf(" AND dict_type = $%d", len(args))
	}
	if keyword != "" {
		like := "%" + keyword + "%"
		args = append(args, like)
		query += fmt.Sprintf(" AND value ILIKE $%d", len(args))
	}
	query += " ORDER BY dict_type ASC, id ASC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]RTSPDictionaryItem, 0)
	for rows.Next() {
		var item RTSPDictionaryItem
		var enabled int
		var createdAt, updatedAt sql.NullString
		if err := rows.Scan(&item.ID, &item.Type, &item.Value, &enabled, &createdAt, &updatedAt, &item.CreatedBy); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.CreatedAt = utils.FormatNullTimeStringForDisplay(createdAt)
		item.UpdatedAt = utils.FormatNullTimeStringForDisplay(updatedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *RTSPService) GetDictionaryStatistics() (map[string]int, error) {
	stats := map[string]int{RTSPDictPath: 0, RTSPDictUsername: 0, RTSPDictPassword: 0}
	rows, err := database.DB.Query(`SELECT dict_type, COUNT(*) FROM rtsp_dictionary GROUP BY dict_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dictType string
		var count int
		if err := rows.Scan(&dictType, &count); err != nil {
			return nil, err
		}
		stats[dictType] = count
	}
	return stats, rows.Err()
}

func (s *RTSPService) SaveDictionary(item RTSPDictionaryItem, userID int) (RTSPDictionaryItem, error) {
	item.Type = normalizeRTSPDictType(item.Type)
	item.Value = normalizeRTSPDictValue(item.Type, item.Value)
	if item.Type == "" {
		return item, fmt.Errorf("字典类型不正确")
	}
	if item.Value == "" {
		return item, fmt.Errorf("字典内容不能为空")
	}

	now := utils.GetCurrentTimeString()
	enabled := 0
	if item.Enabled {
		enabled = 1
	}
	if item.ID > 0 {
		existingID, exists, err := s.findDictionaryID(item.Type, item.Value)
		if err != nil {
			return item, err
		}
		if exists && existingID != item.ID {
			return item, fmt.Errorf("字典内容已存在，已自动去重")
		}
		_, updateErr := database.DB.Exec(`UPDATE rtsp_dictionary
			SET dict_type = $1, value = $2, enabled = $3, updated_at = $4
			WHERE id = $5`, item.Type, item.Value, enabled, now, item.ID)
		if updateErr != nil {
			return item, updateErr
		}
		item.UpdatedAt = now
		return item, nil
	}

	if _, exists, err := s.findDictionaryID(item.Type, item.Value); err != nil {
		return item, err
	} else if exists {
		return item, fmt.Errorf("字典内容已存在，已自动去重")
	}

	id, err := database.InsertAndReturnID(`INSERT INTO rtsp_dictionary
		(dict_type, value, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		item.Type, item.Value, enabled, now, now, userID)
	if err != nil {
		return item, err
	}
	item.ID = id
	item.CreatedAt = now
	item.UpdatedAt = now
	item.CreatedBy = userID
	return item, nil
}

func (s *RTSPService) findDictionaryID(dictType, value string) (int64, bool, error) {
	var id int64
	err := database.DB.QueryRow("SELECT id FROM rtsp_dictionary WHERE dict_type = $1 AND value = $2", dictType, value).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (s *RTSPService) DeleteDictionary(id int64) error {
	result, err := database.DB.Exec("DELETE FROM rtsp_dictionary WHERE id = $1", id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("字典不存在")
	}
	return nil
}

func (s *RTSPService) DeleteDictionaryByType(dictType string) error {
	dictType = normalizeRTSPDictType(dictType)
	if dictType == "" {
		return fmt.Errorf("字典类型不正确")
	}
	_, err := database.DB.Exec("DELETE FROM rtsp_dictionary WHERE dict_type = $1", dictType)
	return err
}

func (s *RTSPService) ImportDictionary(dictType string, values []string, userID int) (RTSPDictionaryImportSummary, error) {
	summary := RTSPDictionaryImportSummary{Total: len(values)}
	dictType = normalizeRTSPDictType(dictType)
	if dictType == "" {
		return summary, fmt.Errorf("字典类型不正确")
	}
	seen := make(map[string]bool)
	for _, value := range values {
		normalized := normalizeRTSPDictValue(dictType, value)
		if normalized == "" {
			continue
		}
		if seen[normalized] {
			summary.Skipped++
			continue
		}
		seen[normalized] = true
		if _, exists, err := s.findDictionaryID(dictType, normalized); err != nil {
			return summary, err
		} else if exists {
			summary.Skipped++
			continue
		}
		_, err := s.SaveDictionary(RTSPDictionaryItem{
			Type:    dictType,
			Value:   normalized,
			Enabled: true,
		}, userID)
		if err != nil {
			return summary, err
		}
		summary.Imported++
	}
	return summary, nil
}

func (s *RTSPService) StartScan(config RTSPScanConfig, userID int) (*RTSPScanTaskState, error) {
	targets := normalizeRTSPTargets(config.Targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("请输入扫描目标")
	}
	if len(targets) > 2000 {
		return nil, fmt.Errorf("RTSP 扫描目标不能超过 2000 个")
	}
	if config.Port <= 0 || config.Port > 65535 {
		config.Port = 554
	}
	if config.ThreadCount <= 0 {
		config.ThreadCount = 5
	}
	if config.ThreadCount > 200 {
		config.ThreadCount = 200
	}
	if config.Timeout <= 0 {
		config.Timeout = 3
	}
	if config.Timeout > 30 {
		config.Timeout = 30
	}
	config.AuthMethod = normalizeRTSPAuthMethod(config.AuthMethod)

	uris, err := s.enabledDictionaryValues(RTSPDictPath)
	if err != nil {
		return nil, err
	}
	usernames, err := s.enabledDictionaryValues(RTSPDictUsername)
	if err != nil {
		return nil, err
	}
	passwords, err := s.enabledDictionaryValues(RTSPDictPassword)
	if err != nil {
		return nil, err
	}
	if len(uris) == 0 || len(usernames) == 0 || len(passwords) == 0 {
		return nil, fmt.Errorf("RTSP 字典不能为空，请先维护路径、账号和密码字典")
	}
	totalSteps := estimateRTSPScanSteps(len(targets), len(uris), len(usernames), len(passwords), config.AuthMethod)

	taskID := uuid.New().String()
	ctx, cancel := context.WithCancel(context.Background())
	state := &RTSPScanTaskState{
		TaskID:       taskID,
		Status:       "running",
		TotalTargets: len(targets),
		TotalSteps:   totalSteps,
		StartedAt:    utils.GetCurrentTimeString(),
		Logs:         make([]RTSPScanLog, 0, 200),
		Results:      make([]RTSPScanResult, 0),
		cancel:       cancel,
	}
	s.mu.Lock()
	s.tasks[taskID] = state
	s.mu.Unlock()

	s.log(state, "INFO", fmt.Sprintf("RTSP 扫描已启动，目标数: %d，线程数: %d，认证方式: %s", len(targets), config.ThreadCount, config.AuthMethod))
	s.log(state, "INFO", fmt.Sprintf("已加载字典：路径 %d 条，账号 %d 条，密码 %d 条", len(uris), len(usernames), len(passwords)))
	go s.runScan(ctx, state, targets, uris, usernames, passwords, config, userID)
	return s.snapshotState(state), nil
}

func (s *RTSPService) StopScan(taskID string) error {
	s.mu.RLock()
	state := s.tasks[taskID]
	s.mu.RUnlock()
	if state == nil {
		return fmt.Errorf("RTSP 任务不存在")
	}
	state.mu.Lock()
	if state.Status == "running" && state.cancel != nil {
		state.Status = "stopped"
		state.CompletedAt = utils.GetCurrentTimeString()
		state.cancel()
	}
	state.mu.Unlock()
	s.log(state, "WARN", "RTSP 扫描已停止")
	s.broadcastStatus(state, "RTSP 扫描已停止")
	return nil
}

func (s *RTSPService) GetScanState(taskID string) (*RTSPScanTaskState, error) {
	s.mu.RLock()
	state := s.tasks[taskID]
	s.mu.RUnlock()
	if state == nil {
		return nil, fmt.Errorf("RTSP 任务不存在或已重启")
	}
	return s.snapshotState(state), nil
}

func (s *RTSPService) ListResults(taskID string, userID int) ([]RTSPScanResult, error) {
	query := `SELECT id, task_id, target, host, port, uri, username, password, auth_method, rtsp_url, response, status, user_id, CAST(created_at AS TEXT)
		FROM rtsp_scan_results WHERE 1=1`
	args := make([]interface{}, 0)
	if taskID != "" {
		args = append(args, taskID)
		query += fmt.Sprintf(" AND task_id = $%d", len(args))
	}
	if userID > 0 {
		args = append(args, userID)
		query += fmt.Sprintf(" AND user_id = $%d", len(args))
	}
	query += " ORDER BY created_at DESC, id DESC"

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]RTSPScanResult, 0)
	for rows.Next() {
		var item RTSPScanResult
		var createdAt sql.NullString
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Target, &item.Host, &item.Port, &item.URI, &item.Username, &item.Password, &item.AuthMethod, &item.RTSPURL, &item.Response, &item.Status, &item.UserID, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = utils.FormatNullTimeStringForDisplay(createdAt)
		results = append(results, item)
	}
	return results, rows.Err()
}

func (s *RTSPService) DeleteResult(id int64, userID int) error {
	query := "DELETE FROM rtsp_scan_results WHERE id = $1"
	args := []interface{}{id}
	if userID > 0 {
		args = append(args, userID)
		query += fmt.Sprintf(" AND user_id = $%d", len(args))
	}
	result, err := database.DB.Exec(query, args...)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("RTSP 结果不存在")
	}
	return nil
}

func (s *RTSPService) runScan(ctx context.Context, state *RTSPScanTaskState, targets, uris, usernames, passwords []string, config RTSPScanConfig, userID int) {
	defer func() {
		state.mu.Lock()
		if state.Status == "running" {
			state.Status = "completed"
			state.Progress = 100
			state.CompletedAt = utils.GetCurrentTimeString()
		}
		status := state.Status
		state.mu.Unlock()
		if status == "completed" {
			s.log(state, "SUCCESS", fmt.Sprintf("RTSP 扫描完成，命中结果: %d", state.Found))
			s.broadcastStatus(state, "RTSP 扫描完成")
		}
	}()

	jobs := make(chan string)
	var wg sync.WaitGroup
	workers := config.ThreadCount
	if workers > len(targets) {
		workers = len(targets)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				s.scanTarget(ctx, state, target, uris, usernames, passwords, config, userID)
				s.markCompleted(state)
			}
		}()
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- target:
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *RTSPService) scanTarget(ctx context.Context, state *RTSPScanTaskState, rawTarget string, uris, usernames, passwords []string, config RTSPScanConfig, userID int) {
	target, err := parseRTSPTarget(rawTarget, config.Port)
	if err != nil {
		s.log(state, "ERROR", fmt.Sprintf("%s 目标解析失败: %v", rawTarget, err))
		return
	}
	s.log(state, "INFO", fmt.Sprintf("开始扫描 %s:%d", target.Host, target.Port))

	uri, challenge, openResponse := s.findRTSPURI(ctx, state, target, uris, config.Timeout)
	if ctx.Err() != nil {
		return
	}
	if uri == "" {
		uri = target.URI
	}
	if uri == "" {
		uri = "/"
	}
	if strings.Contains(openResponse, "200 OK") {
		result := s.buildResult(state.TaskID, target, uri, "", "", "none", openResponse, userID)
		if saved, err := s.saveResult(result); err == nil {
			s.addResult(state, saved)
			s.log(state, "SUCCESS", fmt.Sprintf("发现无需认证的 RTSP: %s", result.RTSPURL))
		}
		return
	}
	if challenge == nil && config.AuthMethod == "Digest" {
		s.log(state, "WARN", fmt.Sprintf("%s:%d 未返回 Digest 认证信息", target.Host, target.Port))
		return
	}

	totalCredentialChecks := len(usernames) * len(passwords)
	if config.AuthMethod == "Both" {
		totalCredentialChecks *= 2
	}
	credentialChecks := 0
	s.log(state, "INFO", fmt.Sprintf("%s:%d 开始验证凭据组合，预计尝试 %d 次", target.Host, target.Port, totalCredentialChecks))
	for _, username := range usernames {
		for _, password := range passwords {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if config.AuthMethod == "Basic" || config.AuthMethod == "Both" {
				ok, response := tryRTSPBasic(ctx, target, uri, username, password, config.Timeout)
				credentialChecks++
				s.advanceWork(state, 1, credentialChecks%50 == 0)
				if ok {
					result := s.buildResult(state.TaskID, target, uri, username, password, "Basic", response, userID)
					if saved, err := s.saveResult(result); err == nil {
						s.addResult(state, saved)
						s.log(state, "SUCCESS", fmt.Sprintf("爆破成功 [Basic] %s:%d %s:%s %s", target.Host, target.Port, username, password, uri))
					}
					return
				}
				s.log(state, "INFO", fmt.Sprintf("尝试失败 [Basic] %s:%d %s:%s %s (%d/%d)", target.Host, target.Port, username, password, uri, credentialChecks, totalCredentialChecks))
			}
			if (config.AuthMethod == "Digest" || config.AuthMethod == "Both") && challenge != nil {
				ok, response := tryRTSPDigest(ctx, target, uri, username, password, challenge.Realm, challenge.Nonce, config.Timeout)
				credentialChecks++
				s.advanceWork(state, 1, credentialChecks%50 == 0)
				if ok {
					result := s.buildResult(state.TaskID, target, uri, username, password, "Digest", response, userID)
					if saved, err := s.saveResult(result); err == nil {
						s.addResult(state, saved)
						s.log(state, "SUCCESS", fmt.Sprintf("爆破成功 [Digest] %s:%d %s:%s %s", target.Host, target.Port, username, password, uri))
					}
					return
				}
				s.log(state, "INFO", fmt.Sprintf("尝试失败 [Digest] %s:%d %s:%s %s (%d/%d)", target.Host, target.Port, username, password, uri, credentialChecks, totalCredentialChecks))
			}
		}
	}
	s.log(state, "INFO", fmt.Sprintf("完成 %s:%d，未命中凭据", target.Host, target.Port))
}

func (s *RTSPService) findRTSPURI(ctx context.Context, state *RTSPScanTaskState, target rtspTarget, uris []string, timeout int) (string, *rtspDigestChallenge, string) {
	preferred := make([]string, 0, len(uris)+1)
	if target.URI != "" && target.URI != "/" {
		preferred = append(preferred, normalizeRTSPURI(target.URI))
	}
	preferred = append(preferred, uris...)
	seen := make(map[string]bool)
	checked := 0
	s.log(state, "INFO", fmt.Sprintf("%s:%d 开始探测 RTSP 路径，预计尝试 %d 条", target.Host, target.Port, len(preferred)))
	for _, uri := range preferred {
		select {
		case <-ctx.Done():
			return "", nil, ""
		default:
		}
		uri = normalizeRTSPURI(uri)
		if uri == "" || seen[uri] {
			continue
		}
		seen[uri] = true
		response, err := sendRTSPDescribe(ctx, target, uri, "", timeout)
		checked++
		s.advanceWork(state, 1, checked%10 == 0)
		if err != nil {
			s.log(state, "INFO", fmt.Sprintf("路径探测失败 %s:%d %s (%d/%d): %v", target.Host, target.Port, uri, checked, len(preferred), err))
			continue
		}
		if strings.Contains(response, "200 OK") {
			s.log(state, "SUCCESS", fmt.Sprintf("%s:%d 路径可访问: %s", target.Host, target.Port, uri))
			return uri, nil, response
		}
		if strings.Contains(strings.ToLower(response), "www-authenticate") {
			challenge := parseDigestChallenge(response)
			s.log(state, "INFO", fmt.Sprintf("%s:%d 路径需要认证: %s", target.Host, target.Port, uri))
			return uri, challenge, response
		}
		s.log(state, "INFO", fmt.Sprintf("路径探测未命中 %s:%d %s (%d/%d)", target.Host, target.Port, uri, checked, len(preferred)))
	}
	s.log(state, "WARN", fmt.Sprintf("%s:%d 未找到可用 RTSP 路径，将使用默认路径继续判断", target.Host, target.Port))
	return "", nil, ""
}

func (s *RTSPService) buildResult(taskID string, target rtspTarget, uri, username, password, authMethod, response string, userID int) RTSPScanResult {
	rtspURL := buildRTSPURL(target.Host, target.Port, uri, username, password)
	return RTSPScanResult{
		TaskID:     taskID,
		Target:     target.Raw,
		Host:       target.Host,
		Port:       target.Port,
		URI:        uri,
		Username:   username,
		Password:   password,
		AuthMethod: authMethod,
		RTSPURL:    rtspURL,
		Response:   truncateText(response, 4096),
		Status:     "success",
		UserID:     userID,
		CreatedAt:  utils.GetCurrentTimeString(),
	}
}

func (s *RTSPService) saveResult(result RTSPScanResult) (RTSPScanResult, error) {
	id, err := database.InsertAndReturnID(`INSERT INTO rtsp_scan_results
		(task_id, target, host, port, uri, username, password, auth_method, rtsp_url, response, status, user_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		result.TaskID, result.Target, result.Host, result.Port, result.URI, result.Username, result.Password,
		result.AuthMethod, result.RTSPURL, result.Response, result.Status, result.UserID, result.CreatedAt)
	if err != nil {
		return result, err
	}
	result.ID = id
	return result, nil
}

func (s *RTSPService) addResult(state *RTSPScanTaskState, result RTSPScanResult) {
	state.mu.Lock()
	state.Found++
	state.Results = append([]RTSPScanResult{result}, state.Results...)
	found := state.Found
	state.mu.Unlock()
	websocket.GetHub().Broadcast(websocket.EventType("rtsp.result"), map[string]interface{}{
		"taskId": state.TaskID,
		"result": result,
		"found":  found,
	})
}

func (s *RTSPService) markCompleted(state *RTSPScanTaskState) {
	state.mu.Lock()
	state.Completed++
	if state.TotalTargets > 0 {
		targetProgress := float64(state.Completed) / float64(state.TotalTargets) * 100
		if state.TotalSteps > 0 {
			targetStepFloor := state.Completed * state.TotalSteps / state.TotalTargets
			if state.CompletedSteps < targetStepFloor {
				state.CompletedSteps = targetStepFloor
			}
			stepProgress := float64(state.CompletedSteps) / float64(state.TotalSteps) * 100
			if stepProgress > targetProgress {
				state.Progress = stepProgress
			} else {
				state.Progress = targetProgress
			}
		} else {
			state.Progress = targetProgress
		}
	}
	if state.Completed >= state.TotalTargets {
		state.Progress = 100
		if state.TotalSteps > 0 {
			state.CompletedSteps = state.TotalSteps
		}
	}
	progress := state.Progress
	completed := state.Completed
	total := state.TotalTargets
	completedSteps := state.CompletedSteps
	totalSteps := state.TotalSteps
	state.lastProgressBroadcast = time.Now()
	state.mu.Unlock()
	websocket.GetHub().Broadcast(websocket.EventType("rtsp.progress"), map[string]interface{}{
		"taskId":         state.TaskID,
		"progress":       progress,
		"completed":      completed,
		"totalTargets":   total,
		"completedSteps": completedSteps,
		"totalSteps":     totalSteps,
	})
}

func (s *RTSPService) advanceWork(state *RTSPScanTaskState, steps int, force bool) {
	if steps <= 0 {
		return
	}
	now := time.Now()
	state.mu.Lock()
	if state.Status != "running" {
		state.mu.Unlock()
		return
	}
	state.CompletedSteps += steps
	if state.TotalSteps > 0 && state.CompletedSteps > state.TotalSteps {
		state.CompletedSteps = state.TotalSteps
	}
	if state.TotalSteps > 0 {
		state.Progress = float64(state.CompletedSteps) / float64(state.TotalSteps) * 100
		if state.Progress > 99.5 && state.Completed < state.TotalTargets {
			state.Progress = 99.5
		}
	}
	shouldBroadcast := force || state.lastProgressBroadcast.IsZero() || now.Sub(state.lastProgressBroadcast) >= time.Second
	progress := state.Progress
	completed := state.Completed
	total := state.TotalTargets
	completedSteps := state.CompletedSteps
	totalSteps := state.TotalSteps
	if shouldBroadcast {
		state.lastProgressBroadcast = now
	}
	state.mu.Unlock()
	if !shouldBroadcast {
		return
	}
	websocket.GetHub().Broadcast(websocket.EventType("rtsp.progress"), map[string]interface{}{
		"taskId":         state.TaskID,
		"progress":       progress,
		"completed":      completed,
		"totalTargets":   total,
		"completedSteps": completedSteps,
		"totalSteps":     totalSteps,
	})
}

func (s *RTSPService) log(state *RTSPScanTaskState, level, message string) {
	item := RTSPScanLog{Time: utils.GetCurrentTimeString(), Level: level, Message: message}
	state.mu.Lock()
	state.Logs = append(state.Logs, item)
	if len(state.Logs) > maxRTSPRealtimeLogs {
		state.Logs = append([]RTSPScanLog(nil), state.Logs[len(state.Logs)-maxRTSPRealtimeLogs:]...)
	}
	state.mu.Unlock()
	websocket.GetHub().Broadcast(websocket.EventType("rtsp.log"), map[string]interface{}{
		"taskId": state.TaskID,
		"log":    item,
	})
}

func (s *RTSPService) broadcastStatus(state *RTSPScanTaskState, message string) {
	snapshot := s.snapshotState(state)
	websocket.GetHub().Broadcast(websocket.EventType("rtsp.status"), map[string]interface{}{
		"taskId":   state.TaskID,
		"status":   snapshot.Status,
		"progress": snapshot.Progress,
		"message":  message,
	})
}

func (s *RTSPService) snapshotState(state *RTSPScanTaskState) *RTSPScanTaskState {
	state.mu.Lock()
	defer state.mu.Unlock()
	logs := append([]RTSPScanLog(nil), state.Logs...)
	results := append([]RTSPScanResult(nil), state.Results...)
	return &RTSPScanTaskState{
		TaskID:         state.TaskID,
		Status:         state.Status,
		Progress:       state.Progress,
		TotalTargets:   state.TotalTargets,
		Completed:      state.Completed,
		TotalSteps:     state.TotalSteps,
		CompletedSteps: state.CompletedSteps,
		Found:          state.Found,
		StartedAt:      state.StartedAt,
		CompletedAt:    state.CompletedAt,
		Logs:           logs,
		Results:        results,
	}
}

func estimateRTSPScanSteps(targetCount, pathCount, usernameCount, passwordCount int, authMethod string) int {
	if targetCount <= 0 {
		return 0
	}
	if pathCount < 0 {
		pathCount = 0
	}
	authMultiplier := 1
	if authMethod == "Both" {
		authMultiplier = 2
	}
	credentialSteps := usernameCount * passwordCount * authMultiplier
	stepsPerTarget := pathCount + 1 + credentialSteps + 1
	if stepsPerTarget < 1 {
		stepsPerTarget = 1
	}
	return targetCount * stepsPerTarget
}

func (s *RTSPService) enabledDictionaryValues(dictType string) ([]string, error) {
	items, err := s.ListDictionary(dictType, "")
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		if item.Enabled {
			values = append(values, item.Value)
		}
	}
	return values, nil
}

func (s *RTSPService) SeedDefaultDictionaries() error {
	var count int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM rtsp_dictionary").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	defaults := map[string][]string{
		RTSPDictPath: {
			"/live", "/live.sdp", "/livestream", "/stream", "/stream1", "/stream2", "/video", "/video.sdp",
			"/cam/realmonitor", "/Streaming/Channels/101", "/Streaming/Channels/102", "/h264/ch1/main/av_stream",
		},
		RTSPDictUsername: {"admin", "root", "administrator", "system", "supervisor", "user", "guest", "camera", "rtsp", "hikvision"},
		RTSPDictPassword: {"123", "1234", "12345", "123456", "12345678", "hik12345", "Hik12345", "password", "qwerty", "root", "root@123", "admin123", "admin@123"},
	}

	for dictType, fileName := range map[string]string{RTSPDictPath: "uri.txt", RTSPDictUsername: "username.txt", RTSPDictPassword: "password.txt"} {
		if values := readRTSPDefaultFile(fileName); len(values) > 0 {
			defaults[dictType] = values
		}
	}

	for dictType, values := range defaults {
		for _, value := range values {
			_, err := s.SaveDictionary(RTSPDictionaryItem{
				Type:    dictType,
				Value:   value,
				Enabled: true,
			}, 0)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type rtspTarget struct {
	Raw  string
	Host string
	Port int
	URI  string
}

type rtspDigestChallenge struct {
	Realm string
	Nonce string
}

func parseRTSPTarget(value string, defaultPort int) (rtspTarget, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return rtspTarget{}, fmt.Errorf("目标为空")
	}
	if strings.HasPrefix(strings.ToLower(raw), "rtsp://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return rtspTarget{}, err
		}
		port := defaultPort
		if parsed.Port() != "" {
			if parsedPort, err := strconv.Atoi(parsed.Port()); err == nil && parsedPort > 0 && parsedPort <= 65535 {
				port = parsedPort
			}
		}
		return rtspTarget{Raw: raw, Host: parsed.Hostname(), Port: port, URI: parsed.EscapedPath()}, nil
	}

	host := raw
	port := defaultPort
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host = h
		if parsedPort, err := strconv.Atoi(p); err == nil && parsedPort > 0 && parsedPort <= 65535 {
			port = parsedPort
		}
	} else if idx := strings.LastIndex(raw, ":"); idx > -1 && idx < len(raw)-1 {
		if parsedPort, err := strconv.Atoi(raw[idx+1:]); err == nil && parsedPort > 0 && parsedPort <= 65535 {
			host = raw[:idx]
			port = parsedPort
		}
	}
	host = strings.Trim(host, "[] ")
	if host == "" {
		return rtspTarget{}, fmt.Errorf("主机为空")
	}
	return rtspTarget{Raw: raw, Host: host, Port: port, URI: "/"}, nil
}

func tryRTSPBasic(ctx context.Context, target rtspTarget, uri, username, password string, timeout int) (bool, string) {
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	auth := "Basic " + token
	response, err := sendRTSPDescribe(ctx, target, uri, auth, timeout)
	if err != nil {
		return false, ""
	}
	return strings.Contains(response, "200 OK"), response
}

func tryRTSPDigest(ctx context.Context, target rtspTarget, uri, username, password, realm, nonce string, timeout int) (bool, string) {
	rtspURL := buildRTSPURL(target.Host, target.Port, uri, "", "")
	ha1 := md5.Sum([]byte(username + ":" + realm + ":" + password))
	ha2 := md5.Sum([]byte("DESCRIBE:" + rtspURL))
	responseHash := md5.Sum([]byte(hex.EncodeToString(ha1[:]) + ":" + nonce + ":" + hex.EncodeToString(ha2[:])))
	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, rtspURL, hex.EncodeToString(responseHash[:]))
	response, err := sendRTSPDescribe(ctx, target, uri, auth, timeout)
	if err != nil {
		return false, ""
	}
	return strings.Contains(response, "200 OK"), response
}

func sendRTSPDescribe(ctx context.Context, target rtspTarget, uri, authorization string, timeout int) (string, error) {
	if timeout <= 0 {
		timeout = 3
	}
	dialer := net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	rtspURL := buildRTSPURL(target.Host, target.Port, uri, "", "")
	cseq := "4"
	if authorization != "" && strings.HasPrefix(authorization, "Digest ") {
		cseq = "5"
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("DESCRIBE %s RTSP/1.0\r\n", rtspURL))
	builder.WriteString("CSeq: " + cseq + "\r\n")
	builder.WriteString("User-Agent: FusionWeb RTSP Scanner\r\n")
	builder.WriteString("Accept: application/sdp\r\n")
	if authorization != "" {
		builder.WriteString("Authorization: " + authorization + "\r\n")
	}
	builder.WriteString("\r\n")
	if _, err := conn.Write([]byte(builder.String())); err != nil {
		return "", err
	}
	buffer := make([]byte, 8192)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

func parseDigestChallenge(response string) *rtspDigestChallenge {
	if !strings.Contains(strings.ToLower(response), "digest") {
		return nil
	}
	realm := extractAuthValue(response, "realm")
	nonce := extractAuthValue(response, "nonce")
	if realm == "" || nonce == "" {
		return nil
	}
	return &rtspDigestChallenge{Realm: realm, Nonce: nonce}
}

func extractAuthValue(response, key string) string {
	patterns := []string{
		key + `="([^"]*)"`,
		key + `=([^,\s]*)`,
		key + `='([^']*)'`,
	}
	for _, pattern := range patterns {
		match := regexp.MustCompile(pattern).FindStringSubmatch(response)
		if len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

func buildRTSPURL(host string, port int, uri, username, password string) string {
	uri = normalizeRTSPURI(uri)
	auth := ""
	if username != "" || password != "" {
		auth = url.QueryEscape(username) + ":" + url.QueryEscape(password) + "@"
	}
	return fmt.Sprintf("rtsp://%s%s:%d%s", auth, host, port, uri)
}

func normalizeRTSPDictType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "uri", "url", "path", "路径":
		return RTSPDictPath
	case "username", "user", "account", "账号", "用户名":
		return RTSPDictUsername
	case "password", "pass", "pwd", "密码":
		return RTSPDictPassword
	default:
		return ""
	}
}

func normalizeRTSPDictValue(dictType, value string) string {
	value = strings.TrimSpace(value)
	if dictType == RTSPDictPath && value != "" {
		return normalizeRTSPURI(value)
	}
	return value
}

func normalizeRTSPURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return value
}

func normalizeRTSPAuthMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "basic":
		return "Basic"
	case "both", "all", "basic+digest":
		return "Both"
	default:
		return "Digest"
	}
}

func normalizeRTSPTargets(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';'
		}) {
			target := strings.TrimSpace(part)
			if target == "" || seen[target] {
				continue
			}
			seen[target] = true
			result = append(result, target)
		}
	}
	return result
}

func readRTSPDefaultFile(fileName string) []string {
	paths := []string{
		filepath.Join("C:\\Codex\\RTSP", fileName),
		filepath.Join("RTSP", fileName),
		fileName,
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()
		values := make([]string, 0)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			if value != "" {
				values = append(values, value)
			}
		}
		sort.Strings(values)
		return values
	}
	return nil
}

func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n... truncated ..."
}
