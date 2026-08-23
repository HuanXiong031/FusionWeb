package api

import (
	"FusionWeb/backend/config"
	"FusionWeb/backend/database"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type workerReport struct {
	Name           string  `json:"name" binding:"required"`
	OS             string  `json:"os"`
	Arch           string  `json:"arch"`
	Concurrency    int     `json:"concurrency"`
	ActiveTasks    int64   `json:"activeTasks"`
	CompletedTasks int64   `json:"completedTasks"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemoryPercent  float64 `json:"memoryPercent"`
	Version        string  `json:"version"`
}

func workerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		expected := config.Get().WorkerKey
		if strings.TrimSpace(expected) == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 1, "message": "远程 Worker 接入未启用"})
			return
		}
		provided := c.GetHeader("X-Worker-Key")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 1, "message": "Worker Key 无效"})
			return
		}
		c.Next()
	}
}

func RegisterWorkerRoutes(r *gin.Engine, v1 *gin.RouterGroup) {
	internal := r.Group("/api/internal/worker", workerAuthMiddleware())
	internal.POST("/register", handleWorkerRegister)
	internal.POST("/heartbeat", handleWorkerHeartbeat)
	internal.POST("/deregister", handleWorkerDeregister)
	v1.GET("/workers", handleWorkerList)
	v1.DELETE("/workers/:name", handleWorkerDelete)
	v1.GET("/workers/install-command", handleWorkerInstallCommand)
}

func handleWorkerRegister(c *gin.Context) {
	var report workerReport
	if err := c.ShouldBindJSON(&report); err != nil {
		BadRequestResponse(c, "Worker 注册参数无效", err)
		return
	}
	if report.Concurrency <= 0 {
		report.Concurrency = 5
	}
	if err := saveWorker(c.Request.Context(), report, true); err != nil {
		InternalServerErrorResponse(c, "保存 Worker 注册信息失败", err)
		return
	}
	cfg := config.Get()
	// 远程 Worker 优先获得管理员显式配置的外部地址；没有配置时保留内部地址，
	// 以兼容同一 Compose 网络中的 default-worker。
	pgDSN := firstNonEmpty(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_PG_DSN"), cfg.PGDSN)
	redisAddr := firstNonEmpty(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR"), cfg.RedisAddr)
	minioEndpoint := firstNonEmpty(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT"), cfg.MinIOEndpoint)
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": gin.H{
		"registered": true, "stream": database.RedisKey("task", "queue"), "group": "fusionweb-workers",
		"pgDsn": pgDSN, "redisAddr": redisAddr, "redisPassword": cfg.RedisPassword, "redisDb": cfg.RedisDB, "redisPrefix": cfg.RedisPrefix,
		"minioEndpoint": minioEndpoint, "minioAccessKey": cfg.MinIOAccessKey, "minioSecretKey": cfg.MinIOSecretKey, "minioBucket": cfg.MinIOBucket, "minioRegion": cfg.MinIORegion, "minioUseSSL": cfg.MinIOUseSSL,
	}})
}
func handleWorkerHeartbeat(c *gin.Context) {
	var r workerReport
	if err := c.ShouldBindJSON(&r); err != nil {
		BadRequestResponse(c, "Worker 心跳参数无效", err)
		return
	}
	if err := saveWorker(c.Request.Context(), r, false); err != nil {
		InternalServerErrorResponse(c, "保存 Worker 心跳失败", err)
		return
	}
	SuccessResponse(c, gin.H{"ok": true})
}
func handleWorkerDeregister(c *gin.Context) {
	var r workerReport
	if err := c.ShouldBindJSON(&r); err != nil {
		BadRequestResponse(c, "Worker 下线参数无效", err)
		return
	}
	client := database.GetRedis()
	if client == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": 1, "message": "Redis 不可用"})
		return
	}
	key := database.RedisKey("worker", r.Name)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := client.HSet(c, key, "status", "offline", "last_heartbeat", now).Err(); err != nil {
		InternalServerErrorResponse(c, "Worker 下线失败", err)
		return
	}
	SuccessResponse(c, gin.H{"ok": true})
}

func saveWorker(ctx context.Context, r workerReport, register bool) error {
	client := database.GetRedis()
	if client == nil {
		return fmt.Errorf("Redis 不可用")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	key := database.RedisKey("worker", r.Name)
	values := map[string]interface{}{"name": r.Name, "status": "online", "os": r.OS, "arch": r.Arch, "concurrency": r.Concurrency, "active_tasks": r.ActiveTasks, "completed_tasks": r.CompletedTasks, "cpu_percent": fmt.Sprintf("%.2f", r.CPUPercent), "memory_percent": fmt.Sprintf("%.2f", r.MemoryPercent), "version": r.Version, "last_heartbeat": now}
	if register {
		values["registered_at"] = now
	}
	return client.HSet(ctx, key, values).Err()
}

type workerView struct {
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	OS             string  `json:"os"`
	Arch           string  `json:"arch"`
	Concurrency    int     `json:"concurrency"`
	ActiveTasks    int64   `json:"activeTasks"`
	CompletedTasks int64   `json:"completedTasks"`
	CPUPercent     float64 `json:"cpuPercent"`
	MemoryPercent  float64 `json:"memoryPercent"`
	Version        string  `json:"version"`
	RegisteredAt   string  `json:"registeredAt"`
	LastHeartbeat  string  `json:"lastHeartbeat"`
}

func handleWorkerList(c *gin.Context) {
	client := database.GetRedis()
	if client == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": 1, "message": "Redis 不可用"})
		return
	}
	pattern := database.RedisKey("worker", "*")
	var cursor uint64
	result := make([]workerView, 0)
	for {
		keys, next, err := client.Scan(c, cursor, pattern, 100).Result()
		if err != nil {
			InternalServerErrorResponse(c, "读取 Worker 列表失败", err)
			return
		}
		for _, key := range keys {
			m, err := client.HGetAll(c, key).Result()
			if err != nil || len(m) == 0 {
				continue
			}
			w := mapWorker(m)
			result = append(result, w)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	SuccessResponse(c, result)
}
func mapWorker(m map[string]string) workerView {
	w := workerView{Name: m["name"], Status: m["status"], OS: m["os"], Arch: m["arch"], Version: m["version"], RegisteredAt: m["registered_at"], LastHeartbeat: m["last_heartbeat"]}
	w.Concurrency, _ = strconv.Atoi(m["concurrency"])
	w.ActiveTasks, _ = strconv.ParseInt(m["active_tasks"], 10, 64)
	w.CompletedTasks, _ = strconv.ParseInt(m["completed_tasks"], 10, 64)
	w.CPUPercent, _ = strconv.ParseFloat(m["cpu_percent"], 64)
	w.MemoryPercent, _ = strconv.ParseFloat(m["memory_percent"], 64)
	if ts, err := time.Parse(time.RFC3339Nano, w.LastHeartbeat); err != nil || time.Since(ts) > 120*time.Second {
		w.Status = "offline"
	}
	return w
}
func handleWorkerDelete(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		BadRequestResponse(c, "Worker 名称不能为空", nil)
		return
	}
	client := database.GetRedis()
	if client == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": 1, "message": "Redis 不可用"})
		return
	}
	if err := client.Del(c, database.RedisKey("worker", name)).Err(); err != nil {
		InternalServerErrorResponse(c, "删除 Worker 失败", err)
		return
	}
	SuccessResponse(c, gin.H{"removed": name})
}

func handleWorkerInstallCommand(c *gin.Context) {
	cfg := config.Get()
	scheme := c.GetHeader("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "https"
	}
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.Request.Host
	}
	server := scheme + "://" + host
	image := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_IMAGE"))
	if image == "" {
		image = "crpi-bw40e2qu21b597zs.cn-hangzhou.personal.cr.aliyuncs.com/fusionweb/fusionweb-worker:0.1.0"
	}
	externalPGDSN := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_PG_DSN"))
	externalRedisAddr := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR"))
	externalMinIOEndpoint := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT"))
	missing := make([]string, 0, 4)
	if strings.TrimSpace(cfg.WorkerKey) == "" {
		missing = append(missing, "FUSIONWEB_WORKER_KEY")
	}
	if externalPGDSN == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_PG_DSN")
	}
	if externalRedisAddr == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR")
	}
	if externalMinIOEndpoint == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT")
	}
	warnings := make([]string, 0, 2)
	if !strings.Contains(image, "/") {
		warnings = append(warnings, "Worker 镜像看起来是本地镜像名；远程机器必须能够从镜像仓库拉取该镜像，或预先导入镜像。")
	}
	if len(missing) > 0 {
		warnings = append(warnings, "远程 Worker 部署参数尚未配置完整，请先在主节点 .env 中补齐缺失项并重启 API。")
	}
	compose := fmt.Sprintf("services:\n  fusionweb-worker:\n    image: %s\n    restart: unless-stopped\n    environment:\n      FUSIONWEB_SERVER: %s\n      FUSIONWEB_KEY: %s\n      FUSIONWEB_NAME: ${FUSIONWEB_NAME:-remote-worker}\n      FUSIONWEB_CONCURRENCY: ${FUSIONWEB_CONCURRENCY:-5}\n      FUSIONWEB_INSECURE_TLS: ${FUSIONWEB_INSECURE_TLS:-true}\n      FUSIONWEB_PG_DSN: %s\n      FUSIONWEB_REDIS_ADDR: %s\n      FUSIONWEB_REDIS_PASSWORD: %s\n      FUSIONWEB_REDIS_DB: %d\n      FUSIONWEB_REDIS_PREFIX: %s\n      FUSIONWEB_MINIO_ENDPOINT: %s\n      FUSIONWEB_MINIO_ACCESS_KEY: %s\n      FUSIONWEB_MINIO_SECRET_KEY: %s\n      FUSIONWEB_MINIO_BUCKET: %s\n      FUSIONWEB_MINIO_REGION: %s\n      FUSIONWEB_MINIO_USE_SSL: %t\n      FUSIONWEB_DATA_DIR: /app/data\n    volumes:\n      - fusionweb_worker_data:/app/data\nvolumes:\n  fusionweb_worker_data:\n", image, composeQuoted(server), composeQuoted(cfg.WorkerKey), composeQuoted(externalPGDSN), composeQuoted(externalRedisAddr), composeQuoted(cfg.RedisPassword), cfg.RedisDB, composeQuoted(cfg.RedisPrefix), composeQuoted(externalMinIOEndpoint), composeQuoted(cfg.MinIOAccessKey), composeQuoted(cfg.MinIOSecretKey), composeQuoted(cfg.MinIOBucket), composeQuoted(cfg.MinIORegion), cfg.MinIOUseSSL)
	encoded := base64.StdEncoding.EncodeToString([]byte(compose))
	linux := fmt.Sprintf("mkdir -p fusionweb-worker && echo '%s' | base64 -d > fusionweb-worker/docker-compose.yaml && cd fusionweb-worker && docker compose pull && docker compose up -d --wait --wait-timeout 600", encoded)
	windows := fmt.Sprintf("New-Item -ItemType Directory -Force fusionweb-worker | Out-Null; [IO.File]::WriteAllBytes('fusionweb-worker\\docker-compose.yaml',[Convert]::FromBase64String('%s')); Set-Location fusionweb-worker; docker compose pull; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; docker compose up -d --wait --wait-timeout 600", encoded)
	SuccessResponse(c, gin.H{
		"ready": len(missing) == 0, "missing": missing, "warnings": warnings,
		"server": server, "image": image, "compose": compose, "linux": linux, "windows": windows,
	})
}

func composeQuoted(value string) string {
	// Docker Compose 会对 $ 做变量插值；使用 $$ 保留凭据中的字面量 $。
	return strconv.Quote(strings.ReplaceAll(value, "$", "$$"))
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
