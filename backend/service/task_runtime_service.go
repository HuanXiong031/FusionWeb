package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	taskRuntimeTTL        = 7 * 24 * time.Hour
	taskControlTTL        = 48 * time.Hour
	taskRuntimeOpTimeout  = 400 * time.Millisecond
	taskLogStreamMaxLen   = 10000
	taskRunningStaleAfter = 15 * time.Minute
)

type TaskRuntimeService struct{}

type TaskRuntimeState struct {
	TaskID    string
	Status    string
	WorkerID  string
	Progress  *models.ProgressInfo
	UpdatedAt time.Time
}

type RuntimeTaskLog struct {
	StreamID string
	Log      models.TaskLog
}

var runtimeRedisMutedUntil atomic.Int64

func NewTaskRuntimeService() *TaskRuntimeService {
	return &TaskRuntimeService{}
}

func (s *TaskRuntimeService) SetTaskState(taskID string, fields map[string]interface{}) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil
	}

	values := map[string]interface{}{
		"task_id":    taskID,
		"updated_at": utils.GetCurrentTimeString(),
	}
	for key, value := range fields {
		key = strings.TrimSpace(key)
		if key != "" && value != nil {
			values[key] = value
		}
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()

	pipe := client.Pipeline()
	key := taskStateKey(taskID)
	pipe.HSet(ctx, key, values)
	pipe.Expire(ctx, key, taskRuntimeTTL)
	_, err := pipe.Exec(ctx)
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) GetTaskState(taskID string) (*TaskRuntimeState, bool) {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil, false
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()

	values, err := client.HGetAll(ctx, taskStateKey(taskID)).Result()
	if err != nil || len(values) == 0 {
		markRuntimeRedisFailure(err)
		return nil, false
	}

	progress := &models.ProgressInfo{
		TaskID:           firstNonEmptyString(values["task_id"], taskID),
		Stage:            values["stage"],
		Message:          values["message"],
		Percentage:       parseRedisFloat(values["percentage"]),
		PortCount:        parseRedisInt(values["port_count"]),
		URLCount:         parseRedisInt(values["url_count"]),
		FingerprintCount: parseRedisInt(values["fingerprint_count"]),
		VulnCount:        parseRedisInt(values["vuln_count"]),
	}
	status := strings.TrimSpace(values["status"])
	updatedAt, _ := utils.ParseTimeString(values["updated_at"])

	if strings.EqualFold(status, "running") && !s.taskLockExists(taskID) && !updatedAt.IsZero() && time.Since(updatedAt) > taskRunningStaleAfter {
		return nil, false
	}

	return &TaskRuntimeState{
		TaskID:    progress.TaskID,
		Status:    status,
		WorkerID:  values["worker_id"],
		Progress:  progress,
		UpdatedAt: updatedAt,
	}, true
}

func (s *TaskRuntimeService) AppendTaskLog(log models.TaskLog) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(log.TaskID) == "" {
		return nil
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = utils.GetCurrentTime()
	}
	log.Message = LocalizeTaskLogMessage(log.Message)

	ctx, cancel := runtimeRedisContext()
	defer cancel()

	key := taskLogsKey(log.TaskID)
	pipe := client.Pipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{
		Stream: key,
		MaxLen: taskLogStreamMaxLen,
		Approx: true,
		Values: map[string]interface{}{
			"task_id":    log.TaskID,
			"level":      logLevelOrDefault(log.Level),
			"stage":      log.Stage,
			"message":    log.Message,
			"metadata":   log.Metadata,
			"created_at": utils.FormatTimeForDisplay(log.CreatedAt),
		},
	})
	pipe.Expire(ctx, key, taskRuntimeTTL)
	_, err := pipe.Exec(ctx)
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) QueryTaskLogs(taskID, level, keyword string, page, pageSize int) ([]RuntimeTaskLog, int, bool, error) {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil, 0, false, nil
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 200
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()

	messages, err := client.XRevRangeN(ctx, taskLogsKey(taskID), "+", "-", taskLogStreamMaxLen).Result()
	if err == redis.Nil {
		return nil, 0, false, nil
	}
	if err != nil {
		markRuntimeRedisFailure(err)
		return nil, 0, false, err
	}
	if len(messages) == 0 {
		return nil, 0, false, nil
	}

	level = strings.ToUpper(strings.TrimSpace(level))
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	filtered := make([]RuntimeTaskLog, 0, len(messages))
	for _, message := range messages {
		log := redisMessageToTaskLog(taskID, message)
		log.Message = LocalizeTaskLogMessage(log.Message)
		if level != "" && strings.ToUpper(log.Level) != level {
			continue
		}
		if keyword != "" && !strings.Contains(strings.ToLower(log.Message), keyword) {
			continue
		}
		filtered = append(filtered, RuntimeTaskLog{StreamID: message.ID, Log: log})
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		return []RuntimeTaskLog{}, total, true, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return filtered[start:end], total, true, nil
}

func (s *TaskRuntimeService) SetControlSignal(taskID, action string) error {
	client, ok := runtimeRedisClient()
	action = strings.ToLower(strings.TrimSpace(action))
	if !ok || strings.TrimSpace(taskID) == "" || action == "" {
		return nil
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	err := client.Set(ctx, taskControlKey(taskID), action, taskControlTTL).Err()
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) GetControlSignal(taskID string) (string, bool) {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return "", false
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	value, err := client.Get(ctx, taskControlKey(taskID)).Result()
	if err != nil {
		if err != redis.Nil {
			markRuntimeRedisFailure(err)
		}
		return "", false
	}
	return value, true
}

func (s *TaskRuntimeService) ClearControlSignal(taskID string) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	err := client.Del(ctx, taskControlKey(taskID)).Err()
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) AcquireTaskLock(taskID, owner string, ttl time.Duration) (bool, error) {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return true, nil
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	ok, err := client.SetNX(ctx, taskLockKey(taskID), owner, ttl).Result()
	markRuntimeRedisFailure(err)
	return ok, err
}

func (s *TaskRuntimeService) RenewTaskLock(taskID, owner string, ttl time.Duration) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	script := `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("PEXPIRE", KEYS[1], ARGV[2]) else return 0 end`
	err := client.Eval(ctx, script, []string{taskLockKey(taskID)}, owner, int(ttl.Milliseconds())).Err()
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) ReleaseTaskLock(taskID, owner string) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	script := `if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`
	err := client.Eval(ctx, script, []string{taskLockKey(taskID)}, owner).Err()
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) StartTaskLockHeartbeat(taskID, owner string, ttl, interval time.Duration) func() {
	if !database.RedisEnabled() || strings.TrimSpace(taskID) == "" {
		return func() {}
	}
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = s.RenewTaskLock(taskID, owner, ttl)
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
	}
}

func (s *TaskRuntimeService) DeleteTaskRuntime(taskID string) error {
	client, ok := runtimeRedisClient()
	if !ok || strings.TrimSpace(taskID) == "" {
		return nil
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	err := client.Del(ctx, taskStateKey(taskID), taskLogsKey(taskID), taskControlKey(taskID), taskLockKey(taskID)).Err()
	markRuntimeRedisFailure(err)
	return err
}

func (s *TaskRuntimeService) taskLockExists(taskID string) bool {
	client, ok := runtimeRedisClient()
	if !ok {
		return false
	}

	ctx, cancel := runtimeRedisContext()
	defer cancel()
	n, err := client.Exists(ctx, taskLockKey(taskID)).Result()
	markRuntimeRedisFailure(err)
	return err == nil && n > 0
}

func runtimeRedisClient() (*redis.Client, bool) {
	if mutedUntil := runtimeRedisMutedUntil.Load(); mutedUntil > time.Now().UnixNano() {
		return nil, false
	}
	client := database.GetRedis()
	return client, client != nil
}

func markRuntimeRedisFailure(err error) {
	if err != nil && err != redis.Nil {
		runtimeRedisMutedUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
	}
}

func runtimeRedisContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), taskRuntimeOpTimeout)
}

func taskStateKey(taskID string) string {
	return database.RedisKey("task", taskID, "state")
}

func taskLogsKey(taskID string) string {
	return database.RedisKey("task", taskID, "logs")
}

func taskControlKey(taskID string) string {
	return database.RedisKey("task", taskID, "control")
}

func taskLockKey(taskID string) string {
	return database.RedisKey("lock", "task", taskID)
}

func redisMessageToTaskLog(taskID string, message redis.XMessage) models.TaskLog {
	createdAtText := redisValueString(message.Values["created_at"])
	createdAt, err := utils.ParseTimeString(createdAtText)
	if err != nil {
		createdAt = utils.GetCurrentTime()
	}
	return models.TaskLog{
		TaskID:    firstNonEmptyString(redisValueString(message.Values["task_id"]), taskID),
		Level:     logLevelOrDefault(redisValueString(message.Values["level"])),
		Stage:     redisValueString(message.Values["stage"]),
		Message:   redisValueString(message.Values["message"]),
		Metadata:  redisValueString(message.Values["metadata"]),
		CreatedAt: createdAt,
	}
}

func redisValueString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func parseRedisFloat(value string) float64 {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return parsed
}

func parseRedisInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	return parsed
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
