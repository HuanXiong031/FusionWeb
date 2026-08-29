package api

import (
	"FusionWeb/backend/config"
	"FusionWeb/backend/database"
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	r.GET("/static/fusionweb-worker/install.sh", handlePublicWorkerInstallShellScript)
	r.GET("/static/fusionweb-worker/install.ps1", handlePublicWorkerInstallPowerShell)
	r.GET("/static/fusionweb-worker/compose.yaml", handlePublicWorkerComposeTemplate)
	r.GET("/static/fusionweb-worker/bootstrap.env", handlePublicWorkerBootstrapEnv)
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

type workerInstallSteps struct {
	Download string `json:"download"`
	Run      string `json:"run"`
	OneLiner string `json:"oneLiner"`
	Logs     string `json:"logs"`
	Stop     string `json:"stop"`
	Restart  string `json:"restart"`
	Upgrade  string `json:"upgrade"`
}

type workerInstallState struct {
	Ready             bool
	Missing           []string
	Warnings          []string
	Server            string
	WorkerKey         string
	Image             string
	PGDSN             string
	RedisAddr         string
	RedisPassword     string
	RedisDB           int
	RedisPrefix       string
	MinIOEndpoint     string
	MinIOAccessKey    string
	MinIOSecretKey    string
	MinIOBucket       string
	MinIORegion       string
	MinIOUseSSL       bool
	NeedsRemoteAccess bool
	SuggestedEnv      string
}

type workerInstallResponse struct {
	Ready             bool               `json:"ready"`
	Missing           []string           `json:"missing"`
	Warnings          []string           `json:"warnings"`
	Server            string             `json:"server"`
	WorkerKey         string             `json:"workerKey"`
	Image             string             `json:"image"`
	Compose           string             `json:"compose"`
	PGDSN             string             `json:"pgDsn"`
	RedisAddr         string             `json:"redisAddr"`
	MinIOEndpoint     string             `json:"minioEndpoint"`
	NeedsRemoteAccess bool               `json:"needsRemoteAccess"`
	SuggestedEnv      string             `json:"suggestedEnv"`
	Linux             workerInstallSteps `json:"linux"`
	WindowsPowerShell workerInstallSteps `json:"windowsPowerShell"`
	WindowsCMD        workerInstallSteps `json:"windowsCmd"`
}

func handleWorkerInstallCommand(c *gin.Context) {
	state := resolveWorkerInstallState(c)
	SuccessResponse(c, buildWorkerInstallResponse(state))
}

func handlePublicWorkerInstallShellScript(c *gin.Context) {
	c.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, workerInstallShellScript())
}

func handlePublicWorkerInstallPowerShell(c *gin.Context) {
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, workerInstallPowerShellScript())
}

func handlePublicWorkerComposeTemplate(c *gin.Context) {
	c.Header("Content-Type", "application/yaml; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, workerComposeTemplate())
}

func handlePublicWorkerBootstrapEnv(c *gin.Context) {
	state := resolveWorkerInstallState(c)
	if !validateWorkerInstallKey(c, state.WorkerKey) {
		return
	}
	if !state.Ready {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": 1, "message": "主节点尚未准备好远程 Worker 接入", "missing": state.Missing, "warnings": state.Warnings})
		return
	}
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, buildWorkerBootstrapEnv(state))
}

func resolveWorkerInstallState(c *gin.Context) workerInstallState {
	cfg := config.Get()
	requestScheme := detectRequestScheme(c)
	requestHost := detectRequestHost(c)
	requestHostOnly, requestPort := splitHostPort(requestHost)
	infraBind := strings.TrimSpace(os.Getenv("FUSIONWEB_INFRA_BIND"))
	if infraBind == "" {
		infraBind = "127.0.0.1"
	}
	infraReadyHost := strings.TrimSpace(infraBind)
	if isWildcardHost(infraReadyHost) {
		infraReadyHost = requestHostOnly
	}
	if infraReadyHost == "" {
		infraReadyHost = requestHostOnly
	}
	serverHost := requestHost
	if (requestHostOnly == "" || isLoopbackHost(requestHostOnly) || isWildcardHost(requestHostOnly)) && infraReadyHost != "" && !isLoopbackHost(infraReadyHost) && !isWildcardHost(infraReadyHost) {
		serverHost = joinHostPort(infraReadyHost, requestPort)
	}
	if strings.TrimSpace(serverHost) == "" {
		serverHost = requestHost
	}
	server := strings.TrimRight(requestScheme+"://"+serverHost, "://")
	image := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_IMAGE"))
	if image == "" {
		image = "crpi-bw40e2qu21b597zs.cn-hangzhou.personal.cr.aliyuncs.com/fusionweb/fusionweb-worker:0.1.0"
	}

	explicitPGDSN := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_PG_DSN"))
	explicitRedisAddr := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR"))
	explicitMinIOEndpoint := strings.TrimSpace(os.Getenv("FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT"))
	pgPort := envOrDefault("FUSIONWEB_PG_PORT", "5432")
	redisPort := envOrDefault("FUSIONWEB_REDIS_PORT", "6379")
	minioPort := envOrDefault("FUSIONWEB_MINIO_PORT", "9000")

	derivedHost := ""
	if !isLoopbackHost(infraReadyHost) && !isWildcardHost(infraReadyHost) {
		derivedHost = infraReadyHost
	} else if !isLoopbackHost(requestHostOnly) && !isWildcardHost(requestHostOnly) {
		derivedHost = requestHostOnly
	}

	pgDSN := explicitPGDSN
	if pgDSN == "" && derivedHost != "" {
		pgDSN = buildExternalPGDSN(derivedHost, pgPort)
	}
	redisAddr := explicitRedisAddr
	if redisAddr == "" && derivedHost != "" {
		redisAddr = joinHostPort(derivedHost, redisPort)
	}
	minioEndpoint := explicitMinIOEndpoint
	if minioEndpoint == "" && derivedHost != "" {
		minioEndpoint = buildHTTPURL("http", derivedHost, minioPort)
	}

	missing := make([]string, 0, 4)
	warnings := make([]string, 0, 6)
	ready := true
	needsRemoteAccess := explicitPGDSN == "" || explicitRedisAddr == "" || explicitMinIOEndpoint == ""

	if strings.TrimSpace(cfg.WorkerKey) == "" {
		missing = append(missing, "FUSIONWEB_WORKER_KEY")
		ready = false
	}
	if strings.TrimSpace(serverHost) == "" || isLoopbackHost(extractHostOnly(serverHost)) || isWildcardHost(extractHostOnly(serverHost)) {
		warnings = append(warnings, "当前页面访问地址仍是 localhost/127.0.0.1；远程 Worker 无法回连主节点 API。请改用 https://<主机内网IP>:8988 打开前端后重新生成命令。")
		ready = false
	}
	if pgDSN == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_PG_DSN")
		ready = false
	}
	if redisAddr == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR")
		ready = false
	}
	if minioEndpoint == "" {
		missing = append(missing, "FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT")
		ready = false
	}
	if needsRemoteAccess {
		if isLoopbackHost(infraBind) {
			warnings = append(warnings, "当前 FUSIONWEB_INFRA_BIND=127.0.0.1，PostgreSQL/Redis/MinIO 只监听本机。远程 Worker 部署前必须叠加 docker-compose.remote-access.yaml，并把 FUSIONWEB_INFRA_BIND 改成主机内网 IP 或 0.0.0.0。")
			ready = false
		} else {
			warnings = append(warnings, "当前安装命令使用的是主节点自带 PostgreSQL / Redis / MinIO。请确认主节点已经通过 docker-compose.remote-access.yaml 暴露这些端口，并已放行内网防火墙。")
		}
	}
	if !strings.Contains(image, "/") {
		warnings = append(warnings, "Worker 镜像看起来是本地镜像名；远程机器必须能够从镜像仓库拉取该镜像，或预先导入镜像。")
	}

	missing = uniqueStrings(missing)
	warnings = uniqueStrings(warnings)
	suggestedEnv := buildSuggestedWorkerEnv(derivedHost, infraBind, pgPort, redisPort, minioPort, pgDSN, redisAddr, minioEndpoint)
	return workerInstallState{
		Ready:             ready,
		Missing:           missing,
		Warnings:          warnings,
		Server:            server,
		WorkerKey:         cfg.WorkerKey,
		Image:             image,
		PGDSN:             pgDSN,
		RedisAddr:         redisAddr,
		RedisPassword:     cfg.RedisPassword,
		RedisDB:           cfg.RedisDB,
		RedisPrefix:       cfg.RedisPrefix,
		MinIOEndpoint:     minioEndpoint,
		MinIOAccessKey:    cfg.MinIOAccessKey,
		MinIOSecretKey:    cfg.MinIOSecretKey,
		MinIOBucket:       cfg.MinIOBucket,
		MinIORegion:       cfg.MinIORegion,
		MinIOUseSSL:       cfg.MinIOUseSSL,
		NeedsRemoteAccess: needsRemoteAccess,
		SuggestedEnv:      suggestedEnv,
	}
}

func buildWorkerInstallResponse(state workerInstallState) workerInstallResponse {
	return workerInstallResponse{
		Ready:             state.Ready,
		Missing:           state.Missing,
		Warnings:          state.Warnings,
		Server:            state.Server,
		WorkerKey:         state.WorkerKey,
		Image:             state.Image,
		Compose:           workerComposeTemplate(),
		PGDSN:             state.PGDSN,
		RedisAddr:         state.RedisAddr,
		MinIOEndpoint:     state.MinIOEndpoint,
		NeedsRemoteAccess: state.NeedsRemoteAccess,
		SuggestedEnv:      state.SuggestedEnv,
		Linux:             buildLinuxWorkerInstallSteps(state),
		WindowsPowerShell: buildPowerShellWorkerInstallSteps(state),
		WindowsCMD:        buildCMDWorkerInstallSteps(state),
	}
}

func validateWorkerInstallKey(c *gin.Context, expected string) bool {
	if strings.TrimSpace(expected) == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 1, "message": "远程 Worker 接入未启用"})
		return false
	}
	provided := firstNonEmpty(c.GetHeader("X-Worker-Key"), c.Query("key"))
	if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 1, "message": "Worker Key 无效"})
		return false
	}
	return true
}

func buildLinuxWorkerInstallSteps(state workerInstallState) workerInstallSteps {
	scriptURL := workerStaticURL(state.Server, "install.sh")
	download := fmt.Sprintf("curl %s %s -o fusionweb-worker.sh", curlFlagsForServer(state.Server), shellQuote(scriptURL))
	run := fmt.Sprintf("FUSIONWEB_SERVER=%s FUSIONWEB_WORKER_KEY=%s bash fusionweb-worker.sh", shellQuote(state.Server), shellQuote(state.WorkerKey))
	logs := "cd fusionweb-worker && docker compose logs -f"
	stop := "cd fusionweb-worker && docker compose down"
	restart := "cd fusionweb-worker && docker compose restart"
	upgrade := download + " && " + run
	return workerInstallSteps{Download: download, Run: run, OneLiner: download + " && " + run, Logs: logs, Stop: stop, Restart: restart, Upgrade: upgrade}
}

func buildPowerShellWorkerInstallSteps(state workerInstallState) workerInstallSteps {
	scriptURL := workerStaticURL(state.Server, "install.ps1")
	download := fmt.Sprintf("$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; Invoke-WebRequest -UseBasicParsing %s -OutFile 'fusionweb-worker.ps1'", powerShellQuote(scriptURL))
	run := fmt.Sprintf("$env:FUSIONWEB_SERVER=%s; $env:FUSIONWEB_WORKER_KEY=%s; powershell -NoProfile -ExecutionPolicy Bypass -File .\fusionweb-worker.ps1", powerShellQuote(state.Server), powerShellQuote(state.WorkerKey))
	logs := "Set-Location fusionweb-worker; docker compose logs -f"
	stop := "Set-Location fusionweb-worker; docker compose down"
	restart := "Set-Location fusionweb-worker; docker compose restart"
	upgrade := download + "; " + run
	return workerInstallSteps{Download: download, Run: run, OneLiner: download + "; " + run, Logs: logs, Stop: stop, Restart: restart, Upgrade: upgrade}
}

func buildCMDWorkerInstallSteps(state workerInstallState) workerInstallSteps {
	scriptURL := workerStaticURL(state.Server, "install.ps1")
	download := fmt.Sprintf(`powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; Invoke-WebRequest -UseBasicParsing '%s' -OutFile 'fusionweb-worker.ps1'"`, scriptURL)
	run := fmt.Sprintf(`set "FUSIONWEB_SERVER=%s" && set "FUSIONWEB_WORKER_KEY=%s" && powershell -NoProfile -ExecutionPolicy Bypass -File .\fusionweb-worker.ps1`, escapeCMDEnvValue(state.Server), escapeCMDEnvValue(state.WorkerKey))
	logs := `cd /d fusionweb-worker && docker compose logs -f`
	stop := `cd /d fusionweb-worker && docker compose down`
	restart := `cd /d fusionweb-worker && docker compose restart`
	upgrade := download + " && " + run
	return workerInstallSteps{Download: download, Run: run, OneLiner: download + " && " + run, Logs: logs, Stop: stop, Restart: restart, Upgrade: upgrade}
}

func buildWorkerBootstrapEnv(state workerInstallState) string {
	lines := []string{
		"# Generated by FusionWeb remote worker installer",
		fmt.Sprintf("FUSIONWEB_IMAGE=%s", state.Image),
		fmt.Sprintf("FUSIONWEB_SERVER=%s", state.Server),
		fmt.Sprintf("FUSIONWEB_KEY=%s", state.WorkerKey),
		fmt.Sprintf("FUSIONWEB_PG_DSN=%s", state.PGDSN),
		fmt.Sprintf("FUSIONWEB_REDIS_ADDR=%s", state.RedisAddr),
		fmt.Sprintf("FUSIONWEB_REDIS_PASSWORD=%s", state.RedisPassword),
		fmt.Sprintf("FUSIONWEB_REDIS_DB=%d", state.RedisDB),
		fmt.Sprintf("FUSIONWEB_REDIS_PREFIX=%s", state.RedisPrefix),
		fmt.Sprintf("FUSIONWEB_MINIO_ENDPOINT=%s", state.MinIOEndpoint),
		fmt.Sprintf("FUSIONWEB_MINIO_ACCESS_KEY=%s", state.MinIOAccessKey),
		fmt.Sprintf("FUSIONWEB_MINIO_SECRET_KEY=%s", state.MinIOSecretKey),
		fmt.Sprintf("FUSIONWEB_MINIO_BUCKET=%s", state.MinIOBucket),
		fmt.Sprintf("FUSIONWEB_MINIO_REGION=%s", state.MinIORegion),
		fmt.Sprintf("FUSIONWEB_MINIO_USE_SSL=%t", state.MinIOUseSSL),
		"FUSIONWEB_CONCURRENCY=5",
		"FUSIONWEB_INSECURE_TLS=true",
		"FUSIONWEB_DATA_DIR=/app/data",
	}
	return strings.Join(lines, "\n") + "\n"
}

func workerComposeTemplate() string {
	return `name: fusionweb-remote-worker
services:
  fusionweb-worker:
    image: ${FUSIONWEB_IMAGE}
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - fusionweb_worker_data:/app/data
volumes:
  fusionweb_worker_data:
`
}

func workerInstallShellScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[FusionWeb] 缺少命令: $1" >&2
    exit 1
  }
}

append_override() {
  local key="$1"
  local value="$2"
  if [[ -n "$value" ]]; then
    printf '%s=%s\n' "$key" "$value" >> "$WORKDIR/.env"
  fi
}

need_cmd curl
need_cmd docker

SERVER="${FUSIONWEB_SERVER:-}"
WORKER_KEY="${FUSIONWEB_WORKER_KEY:-${FUSIONWEB_KEY:-}}"
WORKDIR="${FUSIONWEB_WORKDIR:-fusionweb-worker}"
INSECURE_TLS="${FUSIONWEB_INSECURE_TLS:-true}"

if [[ -z "$SERVER" ]]; then
  echo "[FusionWeb] FUSIONWEB_SERVER 不能为空" >&2
  exit 1
fi
if [[ -z "$WORKER_KEY" ]]; then
  echo "[FusionWeb] FUSIONWEB_WORKER_KEY 不能为空" >&2
  exit 1
fi

SERVER="${SERVER%/}"
COMPOSE_URL="${FUSIONWEB_COMPOSE_URL:-${SERVER}/static/fusionweb-worker/compose.yaml}"
BOOTSTRAP_URL="${FUSIONWEB_BOOTSTRAP_URL:-${SERVER}/static/fusionweb-worker/bootstrap.env}"
CURL_ARGS=(-fsSL)
if [[ "$INSECURE_TLS" == "true" ]]; then
  CURL_ARGS+=(-k)
fi

mkdir -p "$WORKDIR"
curl "${CURL_ARGS[@]}" "$COMPOSE_URL" -o "$WORKDIR/docker-compose.yaml"
curl "${CURL_ARGS[@]}" -H "X-Worker-Key: $WORKER_KEY" "$BOOTSTRAP_URL" -o "$WORKDIR/.env"
append_override FUSIONWEB_NAME "${FUSIONWEB_NAME:-}"
append_override FUSIONWEB_CONCURRENCY "${FUSIONWEB_CONCURRENCY:-}"
append_override FUSIONWEB_INSECURE_TLS "$INSECURE_TLS"
append_override FUSIONWEB_IMAGE "${FUSIONWEB_IMAGE:-}"

cd "$WORKDIR"
docker compose pull
docker compose up -d --wait --wait-timeout 600

echo "[FusionWeb] Worker 已启动"
echo "[FusionWeb] 查看日志: cd $WORKDIR && docker compose logs -f"
`
}

func workerInstallPowerShellScript() string {
	return `$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "[FusionWeb] 缺少命令: $Name"
    }
}

function Add-Override {
    param([string]$Key, [string]$Value)
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        Add-Content -Path (Join-Path $script:Workdir '.env') -Value ("{0}={1}" -f $Key, $Value)
    }
}

Require-Command 'docker'
$server = if ([string]::IsNullOrWhiteSpace($env:FUSIONWEB_SERVER)) { '' } else { $env:FUSIONWEB_SERVER.TrimEnd('/') }
$workerKey = $env:FUSIONWEB_WORKER_KEY
if ([string]::IsNullOrWhiteSpace($workerKey)) {
    $workerKey = $env:FUSIONWEB_KEY
}
$script:Workdir = if ([string]::IsNullOrWhiteSpace($env:FUSIONWEB_WORKDIR)) { 'fusionweb-worker' } else { $env:FUSIONWEB_WORKDIR }
$insecureTls = if ([string]::IsNullOrWhiteSpace($env:FUSIONWEB_INSECURE_TLS)) { 'true' } else { $env:FUSIONWEB_INSECURE_TLS }
if ([string]::IsNullOrWhiteSpace($server)) { throw '[FusionWeb] FUSIONWEB_SERVER 不能为空' }
if ([string]::IsNullOrWhiteSpace($workerKey)) { throw '[FusionWeb] FUSIONWEB_WORKER_KEY 不能为空' }

if ($insecureTls -eq 'true') {
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

$composeUrl = if ([string]::IsNullOrWhiteSpace($env:FUSIONWEB_COMPOSE_URL)) { "$server/static/fusionweb-worker/compose.yaml" } else { $env:FUSIONWEB_COMPOSE_URL }
$bootstrapUrl = if ([string]::IsNullOrWhiteSpace($env:FUSIONWEB_BOOTSTRAP_URL)) { "$server/static/fusionweb-worker/bootstrap.env" } else { $env:FUSIONWEB_BOOTSTRAP_URL }
New-Item -ItemType Directory -Force -Path $script:Workdir | Out-Null
Invoke-WebRequest -UseBasicParsing $composeUrl -OutFile (Join-Path $script:Workdir 'docker-compose.yaml')
Invoke-WebRequest -UseBasicParsing $bootstrapUrl -Headers @{ 'X-Worker-Key' = $workerKey } -OutFile (Join-Path $script:Workdir '.env')
Add-Override 'FUSIONWEB_NAME' $env:FUSIONWEB_NAME
Add-Override 'FUSIONWEB_CONCURRENCY' $env:FUSIONWEB_CONCURRENCY
Add-Override 'FUSIONWEB_INSECURE_TLS' $insecureTls
Add-Override 'FUSIONWEB_IMAGE' $env:FUSIONWEB_IMAGE

Set-Location $script:Workdir
docker compose pull
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose up -d --wait --wait-timeout 600
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host '[FusionWeb] Worker 已启动'
Write-Host '[FusionWeb] 查看日志: Set-Location fusionweb-worker; docker compose logs -f'
`
}

func workerStaticURL(server, fileName string) string {
	return strings.TrimRight(strings.TrimSpace(server), "/") + "/static/fusionweb-worker/" + strings.TrimLeft(strings.TrimSpace(fileName), "/")
}

func curlFlagsForServer(server string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "https://") {
		return "-fsSLk"
	}
	return "-fsSL"
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func escapeCMDEnvValue(value string) string {
	return strings.ReplaceAll(value, `"`, `""`)
}

func detectRequestScheme(c *gin.Context) string {
	scheme := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto"))
	if scheme != "" {
		return scheme
	}
	if c.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func detectRequestHost(c *gin.Context) string {
	host := strings.TrimSpace(c.GetHeader("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(c.Request.Host)
	}
	if idx := strings.Index(host, ","); idx >= 0 {
		host = strings.TrimSpace(host[:idx])
	}
	return host
}

func splitHostPort(host string) (string, string) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil {
			host = parsed.Host
		}
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(parsedHost, "[]"), parsedPort
	}
	trimmed := strings.Trim(host, "[]")
	if strings.Count(trimmed, ":") == 1 {
		parts := strings.SplitN(trimmed, ":", 2)
		return strings.Trim(parts[0], "[]"), parts[1]
	}
	return trimmed, ""
}

func extractHostOnly(host string) string {
	hostOnly, _ := splitHostPort(host)
	return hostOnly
}

func joinHostPort(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return true
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isWildcardHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return host == "0.0.0.0" || host == "::"
}

func buildExternalPGDSN(host, port string) string {
	user := envOrDefault("POSTGRES_USER", "fusionweb")
	password := os.Getenv("POSTGRES_PASSWORD")
	databaseName := envOrDefault("POSTGRES_DB", "fusionweb")
	query := url.Values{}
	query.Set("sslmode", "disable")
	return (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     joinHostPort(host, port),
		Path:     "/" + databaseName,
		RawQuery: query.Encode(),
	}).String()
}

func buildHTTPURL(scheme, host, port string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	return (&url.URL{Scheme: scheme, Host: joinHostPort(host, port)}).String()
}

func buildSuggestedWorkerEnv(host, infraBind, pgPort, redisPort, minioPort, pgDSN, redisAddr, minioEndpoint string) string {
	suggestedHost := strings.TrimSpace(host)
	if suggestedHost == "" || isLoopbackHost(suggestedHost) || isWildcardHost(suggestedHost) {
		suggestedHost = "<主节点内网IP>"
	}
	suggestedBind := strings.TrimSpace(infraBind)
	if suggestedBind == "" || isLoopbackHost(suggestedBind) || isWildcardHost(suggestedBind) {
		suggestedBind = suggestedHost
	}
	if suggestedBind == "" {
		suggestedBind = "<主节点内网IP>"
	}
	if strings.TrimSpace(pgDSN) == "" {
		user := envOrDefault("POSTGRES_USER", "fusionweb")
		databaseName := envOrDefault("POSTGRES_DB", "fusionweb")
		pgDSN = fmt.Sprintf("postgres://%s:<POSTGRES_PASSWORD>@%s/%s?sslmode=disable", user, joinHostPortForDisplay(suggestedHost, pgPort), databaseName)
	}
	if strings.TrimSpace(redisAddr) == "" {
		redisAddr = joinHostPortForDisplay(suggestedHost, redisPort)
	}
	if strings.TrimSpace(minioEndpoint) == "" {
		minioEndpoint = fmt.Sprintf("http://%s", joinHostPortForDisplay(suggestedHost, minioPort))
	}
	lines := []string{
		"# 写入 C:\\Codex\\FusionWeb\\.env 或部署目录 .env 后重启主节点 API",
		fmt.Sprintf("FUSIONWEB_INFRA_BIND=%s", suggestedBind),
		fmt.Sprintf("FUSIONWEB_WORKER_EXTERNAL_PG_DSN=%s", pgDSN),
		fmt.Sprintf("FUSIONWEB_WORKER_EXTERNAL_REDIS_ADDR=%s", redisAddr),
		fmt.Sprintf("FUSIONWEB_WORKER_EXTERNAL_MINIO_ENDPOINT=%s", minioEndpoint),
		"",
		"# 然后使用 remote-access 覆盖层重启主节点",
		"docker compose --env-file .env -f docker-compose.yaml -f docker-compose.remote-access.yaml up -d --remove-orphans --wait --wait-timeout 600",
	}
	return strings.Join(lines, "\n")
}

func joinHostPortForDisplay(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
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
