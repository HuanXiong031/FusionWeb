// Package scheduler 提供异步扫描任务的调度与执行管理。
// 本文件实现任务重启功能，允许基于已完成/失败/已取消的任务配置创建新任务重新执行。
package scheduler

import (
	"database/sql"
	"fmt"

	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
)

// RestartTask 基于旧任务配置创建一个新任务重新执行。
// 仅允许重启状态为"已完成(completed)"、"失败(failed)"或"已取消(cancelled)"的任务，
// 防止对正在运行中的任务误操作。
//
// 参数:
//   - oldTaskID: 要重启的旧任务ID
//
// 返回值:
//   - string: 新创建的任务ID
//   - error: 操作失败时返回错误信息
func (s *TaskScheduler) RestartTask(oldTaskID string) (string, error) {
	fmt.Printf("[DEBUG] RestartTask 开始，oldTaskID: %s\n", oldTaskID)

	// 第一步：从数据库读取旧任务的完整配置
	// 读取所有与扫描行为相关的字段，包括端口范围、扫描模式、线程数等
	var cfg models.TaskConfig
	var userID int // 保留原始用户归属，确保重启后的任务权限一致
	var skipHostDiscovery, noICMPPing, tcpPing, webLink int
	var scanAllPOCsWhenNoFingerprint, fullPocScan, enableActiveFingerprint, enableScreenshot int
	// var selectedDicts string // 占位符，不使用
	query := `
        SELECT task_id, task_name, task_type, target_input,
               port_range, no_port_string, scan_mode, scan_tool, scan_options, thread_count, port_scan_timeout, web_timeout, 
               http_proxy, skip_host_discovery, no_icmp_ping, tcp_ping, 
               ports_threshold, syn_scan_rate, web_link,
               scan_all_pocs_when_no_fingerprint, full_poc_scan, enable_active_fingerprint, enable_screenshot,
               selected_dicts, assigned_worker, ding_talk_token, ding_talk_secret, ding_talk_key_id, dingtalk_bot_id, dingtalk_conversation_id, dingtalk_conversation_type, dingtalk_source_user_id, dingtalk_source_message_id, status, user_id
        FROM task_config
        WHERE task_id = ?
    `

	fmt.Printf("[DEBUG] RestartTask 查询旧任务配置\n")
	err := database.DB.QueryRow(query, oldTaskID).Scan(
		&cfg.TaskID, &cfg.TaskName, &cfg.TaskType, &cfg.TargetInput,
		&cfg.PortRange, &cfg.NoPortString, &cfg.ScanMode, &cfg.ScanTool, &cfg.ScanOptions,
		&cfg.ThreadCount, &cfg.PortScanTimeout, &cfg.WebTimeout, &cfg.HTTPProxy,
		&skipHostDiscovery, &noICMPPing, &tcpPing,
		&cfg.PortsThreshold, &cfg.SYNScanRate, &webLink,
		&scanAllPOCsWhenNoFingerprint, &fullPocScan, &enableActiveFingerprint,
		&enableScreenshot, &cfg.SelectedDicts, &cfg.AssignedWorker, &cfg.DingTalkToken, &cfg.DingTalkSecret, &cfg.DingTalkKeyID, &cfg.DingTalkBotID, &cfg.DingTalkConversationID, &cfg.DingTalkConversationType, &cfg.DingTalkSourceUserID, &cfg.DingTalkSourceMessageID, &cfg.Status, &userID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("[DEBUG] RestartTask 任务不存在\n")
			return "", fmt.Errorf("任务不存在")
		}
		fmt.Printf("[DEBUG] RestartTask 查询任务失败: %v\n", err)
		return "", fmt.Errorf("查询任务失败: %w", err)
	}
	cfg.SkipHostDiscovery = database.IntBool(skipHostDiscovery)
	cfg.NoICMPPing = database.IntBool(noICMPPing)
	cfg.TCPPing = database.IntBool(tcpPing)
	cfg.WebLink = database.IntBool(webLink)
	cfg.ScanAllPOCsWhenNoFingerprint = database.IntBool(scanAllPOCsWhenNoFingerprint)
	cfg.FullPocScan = database.IntBool(fullPocScan)
	cfg.EnableActiveFingerprint = database.IntBool(enableActiveFingerprint)
	cfg.EnableScreenshot = database.IntBool(enableScreenshot)
	fmt.Printf("[DEBUG] RestartTask 读取到旧任务: %s (状态: %s)\n", cfg.TaskName, cfg.Status)

	// 第二步：校验旧任务状态
	// 仅允许重启已完成/失败/已取消的任务，防止重复执行运行中的任务
	switch cfg.Status {
	case "completed", "failed", "cancelled":
		fmt.Printf("[DEBUG] RestartTask 状态检查通过\n")
	default:
		fmt.Printf("[DEBUG] RestartTask 状态检查失败，状态: %s\n", cfg.Status)
		return "", fmt.Errorf("仅允许重启已完成/失败/已取消任务")
	}

	// 第三步：构造新任务配置
	// 复制旧任务的所有扫描参数，但不复制旧 TaskID、状态和时间戳
	// 任务名称追加"(重启)"后缀以便区分
	// 使用 ParentTaskID 字段记录原始任务ID，便于追溯
	newCfg := &models.TaskConfig{
		TaskName:                     cfg.TaskName + " (重启)",
		TaskType:                     cfg.TaskType,
		ParentTaskID:                 oldTaskID,
		TargetInput:                  cfg.TargetInput,
		PortRange:                    cfg.PortRange,
		NoPortString:                 cfg.NoPortString,
		ScanMode:                     cfg.ScanMode,
		ScanTool:                     cfg.ScanTool,
		ScanOptions:                  cfg.ScanOptions,
		ThreadCount:                  cfg.ThreadCount,
		PortScanTimeout:              cfg.PortScanTimeout,
		WebTimeout:                   cfg.WebTimeout,
		HTTPProxy:                    cfg.HTTPProxy,
		SkipHostDiscovery:            cfg.SkipHostDiscovery,
		NoICMPPing:                   cfg.NoICMPPing,
		TCPPing:                      cfg.TCPPing,
		PortsThreshold:               cfg.PortsThreshold,
		SYNScanRate:                  cfg.SYNScanRate,
		WebLink:                      cfg.WebLink,
		ScanAllPOCsWhenNoFingerprint: cfg.ScanAllPOCsWhenNoFingerprint,
		FullPocScan:                  cfg.FullPocScan,
		EnableActiveFingerprint:      cfg.EnableActiveFingerprint,
		EnableScreenshot:             cfg.EnableScreenshot,
		SelectedDicts:                cfg.SelectedDicts,
		AssignedWorker:               cfg.AssignedWorker,
		DingTalkToken:                cfg.DingTalkToken,
		DingTalkSecret:               cfg.DingTalkSecret,
		DingTalkKeyID:                cfg.DingTalkKeyID,
		DingTalkBotID:                cfg.DingTalkBotID,
		DingTalkConversationID:       cfg.DingTalkConversationID,
		DingTalkConversationType:     cfg.DingTalkConversationType,
		DingTalkSourceUserID:         cfg.DingTalkSourceUserID,
		// 重启任务保留钉钉来源会话用于通知，但不能复用来源消息幂等键，
		// 否则 SubmitTaskWithUser 会直接返回原任务 ID。
		DingTalkSourceMessageID: "",
	}

	// 第四步：提交新任务到调度器
	// 使用 SubmitTaskWithUser 保持用户归属，确保权限一致性
	// 注意：不在此处打印 newCfg，避免输出包含 TargetInput 的敏感信息
	newTaskID, err := s.SubmitTaskWithUser(newCfg, uint(userID))
	if err != nil {
		fmt.Printf("[DEBUG] RestartTask SubmitTaskWithUser 失败: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] RestartTask SubmitTaskWithUser 成功，newTaskID: %s\n", newTaskID)
	}
	return newTaskID, err
}
