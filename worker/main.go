package main

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/scheduler"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

const workerVersion = "1.0.0"

type settings struct {
	Server, Key, Name string
	Concurrency       int
	InsecureTLS       bool
}
type report struct {
	Name           string  `json:"name"`
	OS             string  `json:"os"`
	Arch           string  `json:"arch"`
	Concurrency    int     `json:"concurrency"`
	ActiveTasks    int64   `json:"activeTasks"`
	CompletedTasks int64   `json:"completedTasks"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemoryPercent  float64 `json:"memoryPercent"`
	Version        string  `json:"version"`
}
type registerResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		PGDSN          string `json:"pgDsn"`
		RedisAddr      string `json:"redisAddr"`
		RedisPassword  string `json:"redisPassword"`
		RedisDB        int    `json:"redisDb"`
		RedisPrefix    string `json:"redisPrefix"`
		MinIOEndpoint  string `json:"minioEndpoint"`
		MinIOAccessKey string `json:"minioAccessKey"`
		MinIOSecretKey string `json:"minioSecretKey"`
		MinIOBucket    string `json:"minioBucket"`
		MinIORegion    string `json:"minioRegion"`
		MinIOUseSSL    bool   `json:"minioUseSSL"`
	} `json:"data"`
}

type workerRuntime struct {
	cfg             settings
	client          *http.Client
	active          atomic.Int64
	completed       atomic.Int64
	executors       []*scheduler.TaskExecutor
	reclaimExecutor *scheduler.TaskExecutor
	slots           chan struct{}
}

func main() {
	if err := logger.InitLogger(); err != nil {
		fmt.Printf("日志初始化失败: %v\n", err)
	}
	defer logger.CloseLogger()
	cfg, err := loadSettings()
	if err != nil {
		panic(err)
	}
	client := newHTTPClient(cfg.InsecureTLS)
	wr := &workerRuntime{cfg: cfg, client: client, slots: make(chan struct{}, cfg.Concurrency)}
	reg, err := wr.register(context.Background())
	if err != nil {
		panic(err)
	}
	applyConnectionEnvironment(reg)
	if err := database.InitDatabase(); err != nil {
		panic(fmt.Errorf("Worker 初始化运行依赖失败: %w", err))
	}
	defer database.Close()
	if err := scheduler.EnsureTaskStream(context.Background()); err != nil {
		panic(err)
	}
	if err := scheduler.EnsureWorkerTaskStream(context.Background(), cfg.Name); err != nil {
		panic(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	wr.reclaimExecutor = scheduler.NewTaskExecutor(ctx, cfg.Name)
	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		executor := scheduler.NewTaskExecutor(ctx, cfg.Name)
		wr.executors = append(wr.executors, executor)
		consumer := fmt.Sprintf("%s-%d", cfg.Name, i+1)
		wg.Add(1)
		go func(ex *scheduler.TaskExecutor, name string) {
			defer wg.Done()
			err := scheduler.ConsumeStream(ctx, name, wr.streamHandler(ex))
			if err != nil && ctx.Err() == nil {
				logger.Error("Worker 公共队列消费者 %s 退出: %v", name, err)
			}
		}(executor, consumer)
		wg.Add(1)
		go func(ex *scheduler.TaskExecutor, name string) {
			defer wg.Done()
			targetedName := name + "-targeted"
			err := scheduler.ConsumeWorkerStream(ctx, cfg.Name, targetedName, wr.streamHandler(ex))
			if err != nil && ctx.Err() == nil {
				logger.Error("Worker 定向队列消费者 %s 退出: %v", targetedName, err)
			}
		}(executor, consumer)
	}
	wg.Add(1)
	go func() { defer wg.Done(); wr.heartbeatLoop(ctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); wr.reclaimLoop(ctx) }()
	logger.Info("Worker %s 已启动，OS/Arch=%s/%s，并发=%d", cfg.Name, runtime.GOOS, runtime.GOARCH, cfg.Concurrency)
	<-ctx.Done()
	logger.Info("Worker %s 正在退出", cfg.Name)
	for _, e := range wr.executors {
		e.Close()
	}
	wr.reclaimExecutor.Close()
	wg.Wait()
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	if err := wr.post(dctx, "/api/internal/worker/deregister", wr.currentReport(), nil); err != nil {
		logger.Warn("Worker 下线通知失败: %v", err)
	}
}

func loadSettings() (settings, error) {
	host, _ := os.Hostname()
	name := env("FUSIONWEB_NAME", fmt.Sprintf("%s-%d", host, os.Getpid()))
	c := envInt("FUSIONWEB_CONCURRENCY", 5)
	if c < 1 {
		c = 1
	}
	if c > 64 {
		c = 64
	}
	s := settings{Server: strings.TrimRight(strings.TrimSpace(os.Getenv("FUSIONWEB_SERVER")), "/"), Key: os.Getenv("FUSIONWEB_KEY"), Name: name, Concurrency: c, InsecureTLS: envBool("FUSIONWEB_INSECURE_TLS", false)}
	if s.Server == "" {
		return s, fmt.Errorf("FUSIONWEB_SERVER 不能为空")
	}
	if strings.TrimSpace(s.Key) == "" {
		return s, fmt.Errorf("FUSIONWEB_KEY 不能为空")
	}
	return s, nil
}
func newHTTPClient(insecure bool) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}}}
}
func (w *workerRuntime) register(ctx context.Context) (registerResponse, error) {
	var out registerResponse
	err := w.post(ctx, "/api/internal/worker/register", w.currentReport(), &out)
	return out, err
}
func (w *workerRuntime) streamHandler(ex *scheduler.TaskExecutor) scheduler.TaskStreamHandler {
	return func(ctx context.Context, taskID, _ string) error {
		select {
		case w.slots <- struct{}{}:
			defer func() { <-w.slots }()
		case <-ctx.Done():
			return ctx.Err()
		}
		task, err := scheduler.LoadTaskConfigFromDB(taskID)
		if err != nil {
			return err
		}
		w.active.Add(1)
		defer w.active.Add(-1)
		if err := ex.Execute(ctx, task); err != nil {
			return err
		}
		w.completed.Add(1)
		return nil
	}
}
func (w *workerRuntime) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hbctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := w.post(hbctx, "/api/internal/worker/heartbeat", w.currentReport(), nil)
			cancel()
			if err != nil {
				logger.Warn("Worker 心跳失败: %v", err)
			}
		}
	}
}
func (w *workerRuntime) reclaimLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	reclaim := func() {
		if w.reclaimExecutor == nil {
			return
		}
		consumer := w.cfg.Name + "-reclaimer"
		if err := scheduler.ReclaimPendingTasks(ctx, consumer, 2*time.Minute, w.streamHandler(w.reclaimExecutor)); err != nil && ctx.Err() == nil {
			logger.Warn("Worker 公共队列 Pending 任务认领失败: %v", err)
		}
		if err := scheduler.ReclaimWorkerPendingTasks(ctx, w.cfg.Name, consumer+"-targeted", 2*time.Minute, w.streamHandler(w.reclaimExecutor)); err != nil && ctx.Err() == nil {
			logger.Warn("Worker 定向队列 Pending 任务认领失败: %v", err)
		}
	}
	// 启动后立即检查一次，避免 Worker 重启后额外等待一个周期。
	reclaim()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reclaim()
		}
	}
}
func (w *workerRuntime) currentReport() report {
	r := report{Name: w.cfg.Name, OS: runtime.GOOS, Arch: runtime.GOARCH, Concurrency: w.cfg.Concurrency, ActiveTasks: w.active.Load(), CompletedTasks: w.completed.Load(), Version: workerVersion}
	if p, err := cpu.Percent(0, false); err == nil && len(p) > 0 {
		r.CPUPercent = p[0]
	}
	if m, err := mem.VirtualMemory(); err == nil {
		r.MemoryPercent = m.UsedPercent
	}
	return r
}
func (w *workerRuntime) post(ctx context.Context, path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Server+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Key", w.cfg.Key)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var payload map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&payload)
		return fmt.Errorf("API %s 返回 %s: %v", path, resp.Status, payload)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
func applyConnectionEnvironment(r registerResponse) {
	setIfEmpty("FUSIONWEB_PG_DSN", r.Data.PGDSN)
	setIfEmpty("FUSIONWEB_REDIS_ADDR", r.Data.RedisAddr)
	setIfEmpty("FUSIONWEB_REDIS_PASSWORD", r.Data.RedisPassword)
	setIfEmpty("FUSIONWEB_REDIS_DB", strconv.Itoa(r.Data.RedisDB))
	setIfEmpty("FUSIONWEB_REDIS_PREFIX", r.Data.RedisPrefix)
	setIfEmpty("FUSIONWEB_MINIO_ENDPOINT", r.Data.MinIOEndpoint)
	setIfEmpty("FUSIONWEB_MINIO_ACCESS_KEY", r.Data.MinIOAccessKey)
	setIfEmpty("FUSIONWEB_MINIO_SECRET_KEY", r.Data.MinIOSecretKey)
	setIfEmpty("FUSIONWEB_MINIO_BUCKET", r.Data.MinIOBucket)
	setIfEmpty("FUSIONWEB_MINIO_REGION", r.Data.MinIORegion)
	setIfEmpty("FUSIONWEB_MINIO_USE_SSL", strconv.FormatBool(r.Data.MinIOUseSSL))
}
func setIfEmpty(k, v string) {
	if strings.TrimSpace(os.Getenv(k)) == "" && v != "" {
		_ = os.Setenv(k, v)
	}
}
func env(k, f string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return f
}
func envInt(k string, f int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k))); err == nil {
		return v
	}
	return f
}
func envBool(k string, f bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return f
	}
}
