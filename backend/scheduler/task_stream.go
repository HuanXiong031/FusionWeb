package scheduler

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/models"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	taskConsumerGroup      = "fusionweb-workers"
	taskMessageLeasePeriod = 30 * time.Second
)

type TaskStreamHandler func(ctx context.Context, taskID, taskType string) error

func taskStreamKey() string     { return database.RedisKey("task", "queue") }
func TaskConsumerGroup() string { return taskConsumerGroup }

func EnsureTaskStream(ctx context.Context) error {
	client := database.GetRedis()
	if client == nil {
		return errors.New("Redis 未初始化")
	}
	err := client.XGroupCreateMkStream(ctx, taskStreamKey(), taskConsumerGroup, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("创建任务 Stream ConsumerGroup 失败: %w", err)
	}
	return nil
}

func PublishTask(taskID, taskType string) error {
	client := database.GetRedis()
	if client == nil {
		return errors.New("Redis 未初始化")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := EnsureTaskStream(ctx); err != nil {
		return err
	}
	return client.XAdd(ctx, &redis.XAddArgs{Stream: taskStreamKey(), Values: map[string]interface{}{"task_id": taskID, "task_type": taskType, "time": time.Now().UTC().Format(time.RFC3339Nano)}}).Err()
}

func ConsumeStream(ctx context.Context, consumerName string, handler TaskStreamHandler) error {
	if strings.TrimSpace(consumerName) == "" {
		return errors.New("consumerName 不能为空")
	}
	if handler == nil {
		return errors.New("handler 不能为空")
	}
	if err := EnsureTaskStream(ctx); err != nil {
		return err
	}
	client := database.GetRedis()
	for {
		streams, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: taskConsumerGroup, Consumer: consumerName, Streams: []string{taskStreamKey(), ">"}, Count: 1, Block: 5 * time.Second}).Result()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			if errors.Is(err, redis.Nil) {
				continue
			}
			logger.Warn("Redis Stream 消费失败[%s]: %v", consumerName, err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}
		for _, stream := range streams {
			for _, message := range stream.Messages {
				taskID := valueString(message.Values["task_id"])
				taskType := valueString(message.Values["task_type"])
				if taskID == "" {
					_ = client.XAck(ctx, taskStreamKey(), taskConsumerGroup, message.ID).Err()
					continue
				}
				if err := runWithMessageLease(ctx, consumerName, message.ID, func() error {
					return handler(ctx, taskID, taskType)
				}); err != nil {
					logger.Warn("任务 Stream 处理失败[%s/%s]: %v", consumerName, taskID, err)
					continue
				}
				if err := client.XAck(ctx, taskStreamKey(), taskConsumerGroup, message.ID).Err(); err != nil {
					logger.Warn("任务 Stream ACK 失败[%s/%s]: %v", consumerName, taskID, err)
				}
			}
		}
	}
}

// ReclaimPendingTasks claims stale messages once and executes them through handler.
func ReclaimPendingTasks(ctx context.Context, consumerName string, idleTimeout time.Duration, handler TaskStreamHandler) error {
	if idleTimeout <= 0 {
		idleTimeout = 2 * time.Minute
	}
	if err := EnsureTaskStream(ctx); err != nil {
		return err
	}
	client := database.GetRedis()
	start := "0-0"
	for {
		messages, next, err := client.XAutoClaim(ctx, &redis.XAutoClaimArgs{Stream: taskStreamKey(), Group: taskConsumerGroup, Consumer: consumerName, MinIdle: idleTimeout, Start: start, Count: 20}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return fmt.Errorf("认领 Pending 任务失败: %w", err)
		}
		for _, message := range messages {
			taskID := valueString(message.Values["task_id"])
			taskType := valueString(message.Values["task_type"])
			if taskID == "" {
				_ = client.XAck(ctx, taskStreamKey(), taskConsumerGroup, message.ID).Err()
				continue
			}
			if err := runWithMessageLease(ctx, consumerName, message.ID, func() error {
				return handler(ctx, taskID, taskType)
			}); err != nil {
				logger.Warn("Pending 任务处理失败[%s/%s]: %v", consumerName, taskID, err)
				continue
			}
			if err := client.XAck(ctx, taskStreamKey(), taskConsumerGroup, message.ID).Err(); err != nil {
				logger.Warn("Pending 任务 ACK 失败[%s/%s]: %v", consumerName, taskID, err)
			}
		}
		if next == "0-0" || next == start || len(messages) == 0 {
			return nil
		}
		start = next
	}
}

// runWithMessageLease 在长任务执行期间定期把 Pending 消息重新归属到当前 Consumer，
// 从而刷新 idle 时间，避免正常运行的扫描在 idleTimeout 到期后被其他 Worker 提前认领。
func runWithMessageLease(ctx context.Context, consumerName, messageID string, handler func() error) error {
	if handler == nil {
		return errors.New("handler 不能为空")
	}
	client := database.GetRedis()
	if client == nil {
		return errors.New("Redis 未初始化")
	}
	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(taskMessageLeasePeriod)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				err := client.XClaim(leaseCtx, &redis.XClaimArgs{
					Stream:   taskStreamKey(),
					Group:    taskConsumerGroup,
					Consumer: consumerName,
					MinIdle:  0,
					Messages: []string{messageID},
				}).Err()
				if err != nil && !errors.Is(err, context.Canceled) {
					logger.Warn("刷新任务 Stream lease 失败[%s/%s]: %v", consumerName, messageID, err)
				}
			}
		}
	}()

	err := handler()
	cancel()
	<-done
	return err
}

func valueString(v interface{}) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func LoadTaskConfigFromDB(taskID string) (*models.TaskConfig, error) {
	if database.DB == nil {
		return nil, errors.New("数据库未初始化")
	}
	const query = `SELECT task_id, task_name, task_type, COALESCE(parent_task_id,''), COALESCE(target_input,''),
COALESCE(port_range,''), COALESCE(no_port_string,''), COALESCE(scan_mode,''), COALESCE(scan_tool,''), COALESCE(scan_options,'{}'),
COALESCE(thread_count,10), COALESCE(port_scan_timeout,3), COALESCE(web_timeout,10), COALESCE(http_proxy,''),
COALESCE(skip_host_discovery,0), COALESCE(no_icmp_ping,0), COALESCE(tcp_ping,0), COALESCE(ports_threshold,65536), COALESCE(syn_scan_rate,10000),
COALESCE(web_link,0), COALESCE(scan_all_pocs_when_no_fingerprint,0), COALESCE(full_poc_scan,0), COALESCE(enable_active_fingerprint,0), COALESCE(enable_screenshot,0),
COALESCE(selected_dicts,''), COALESCE(ding_talk_token,''), COALESCE(ding_talk_secret,''), COALESCE(ding_talk_key_id,0), COALESCE(status,'pending'), COALESCE(current_stage,'')
FROM task_config WHERE task_id=?`
	var c models.TaskConfig
	var skip, noICMP, tcp, webLink, scanAll, full, active, shot int
	err := database.DB.QueryRow(query, taskID).Scan(&c.TaskID, &c.TaskName, &c.TaskType, &c.ParentTaskID, &c.TargetInput, &c.PortRange, &c.NoPortString, &c.ScanMode, &c.ScanTool, &c.ScanOptions, &c.ThreadCount, &c.PortScanTimeout, &c.WebTimeout, &c.HTTPProxy, &skip, &noICMP, &tcp, &c.PortsThreshold, &c.SYNScanRate, &webLink, &scanAll, &full, &active, &shot, &c.SelectedDicts, &c.DingTalkToken, &c.DingTalkSecret, &c.DingTalkKeyID, &c.Status, &c.CurrentStage)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("任务不存在: %s", taskID)
		}
		return nil, fmt.Errorf("加载任务配置失败: %w", err)
	}
	c.SkipHostDiscovery = database.IntBool(skip)
	c.NoICMPPing = database.IntBool(noICMP)
	c.TCPPing = database.IntBool(tcp)
	c.WebLink = database.IntBool(webLink)
	c.ScanAllPOCsWhenNoFingerprint = database.IntBool(scanAll)
	c.FullPocScan = database.IntBool(full)
	c.EnableActiveFingerprint = database.IntBool(active)
	c.EnableScreenshot = database.IntBool(shot)
	return &c, nil
}
