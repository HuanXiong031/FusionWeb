package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// toolkit 远程执行
//
// 背景：把扫描/审计类工具从 worker 镜像中剥离，统一放进 fusionweb-toolkit 镜像；
// worker 通过本文件把工具调用转发过去（HTTP + JSON），从而：
//   * worker 镜像显著变小、构建更快；
//   * 工具只有一个来源（toolkit），版本一致、更新只改一处；
//   * 纪律（白名单/速率/产物落盘/审计）在 toolkit 侧统一实现。
//
// 配置：
//   FUSIONWEB_TOOLKIT_URL    例如 http://fusionweb-toolkit:7001（为空则完全走本机执行）
//   FUSIONWEB_TOOLKIT_TOKEN  与 toolkit 的 TOOLKIT_TOKEN 一致
//   FUSIONWEB_TOOLKIT_WORKSPACE  传给工具的 workspace（默认 /app/data，与 toolkit 共享盘对齐）
//
// 兜底：toolkit 不可用或未配置时，自动回退本机执行（保持 worker 可独立运行）。

const toolkitPathPrefix = "toolkit:"

var (
	toolkitCacheMu   sync.Mutex
	toolkitCacheList map[string]bool
	toolkitCacheAt   time.Time
	toolkitCacheTTL  = 60 * time.Second
)

func toolkitBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("FUSIONWEB_TOOLKIT_URL")), "/")
}

func toolkitToken() string {
	return strings.TrimSpace(os.Getenv("FUSIONWEB_TOOLKIT_TOKEN"))
}

func toolkitWorkspace() string {
	if ws := strings.TrimSpace(os.Getenv("FUSIONWEB_TOOLKIT_WORKSPACE")); ws != "" {
		return ws
	}
	if dir := strings.TrimSpace(os.Getenv("FUSIONWEB_DATA_DIR")); dir != "" {
		return dir
	}
	return "/app/data"
}

// toolkitToolName 把 worker 使用的可执行名映射到 toolkit 的工具名。
func toolkitToolName(local string) string {
	switch normalizeToolName(local) {
	case "nmap":
		return "nmap_scan"
	case "masscan":
		return "masscan_scan"
	case "naabu":
		return "naabu_scan"
	case "httpx":
		return "httpx_probe"
	case "nuclei":
		return "nuclei_scan"
	case "subfinder":
		return "subfinder_enum"
	case "dnsx":
		return "dnsx_resolve"
	case "ffuf":
		return "ffuf_fuzz"
	case "semgrep":
		return "semgrep_scan"
	case "gitleaks":
		return "gitleaks_scan"
	case "jadx":
		return "jadx_decompile"
	case "apktool":
		return "apktool_decode"
	case "binwalk":
		return "binwalk_extract"
	case "yara":
		return "yara_scan"
	case "vol", "volatility3":
		return "volatility_scan"
	default:
		return normalizeToolName(local)
	}
}

type toolkitToolInfo struct {
	Name   string `json:"name"`
	Binary string `json:"binary"`
}

// ToolkitTools 返回 toolkit 的工具白名单（带 60 秒缓存）。
func ToolkitTools() (map[string]bool, error) {
	base := toolkitBaseURL()
	if base == "" {
		return nil, fmt.Errorf("未配置 FUSIONWEB_TOOLKIT_URL")
	}

	toolkitCacheMu.Lock()
	if toolkitCacheList != nil && time.Since(toolkitCacheAt) < toolkitCacheTTL {
		cached := toolkitCacheList
		toolkitCacheMu.Unlock()
		return cached, nil
	}
	toolkitCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/tools", nil)
	if err != nil {
		return nil, err
	}
	if token := toolkitToken(); token != "" {
		req.Header.Set("X-Toolkit-Token", token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("toolkit /tools 返回 %d", resp.StatusCode)
	}
	var parsed struct {
		Tools []toolkitToolInfo `json:"tools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	list := make(map[string]bool, len(parsed.Tools))
	for _, item := range parsed.Tools {
		list[strings.ToLower(item.Name)] = true
		list[strings.ToLower(item.Binary)] = true
	}

	toolkitCacheMu.Lock()
	toolkitCacheList = list
	toolkitCacheAt = time.Now()
	toolkitCacheMu.Unlock()
	return list, nil
}

// ToolkitHas 判断 toolkit 是否提供某个工具（按可执行名或工具名匹配）。
func ToolkitHas(local string) bool {
	if toolkitBaseURL() == "" {
		return false
	}
	list, err := ToolkitTools()
	if err != nil {
		return false
	}
	name := toolkitToolName(local)
	return list[strings.ToLower(name)] || list[normalizeToolName(local)]
}

// executeViaToolkit 把一次工具调用转发给 toolkit 执行。
func executeViaToolkit(ctx context.Context, tool string, args []string, options ExecuteOptions) (ExecuteResult, error) {
	base := toolkitBaseURL()
	result := ExecuteResult{
		Tool:     tool,
		Path:     toolkitPathPrefix + toolkitToolName(tool),
		Args:     append([]string(nil), args...),
		ExitCode: -1,
	}
	if base == "" {
		return result, fmt.Errorf("未配置 FUSIONWEB_TOOLKIT_URL")
	}

	timeoutSec := 0
	if options.Timeout > 0 {
		timeoutSec = int(options.Timeout.Seconds())
	}
	payload := map[string]interface{}{
		"tool":      toolkitToolName(tool),
		"args":      args,
		"workspace": toolkitWorkspace(),
		"stdin":     options.Stdin,
	}
	if timeoutSec > 0 {
		payload["timeout"] = timeoutSec
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}

	reqCtx := ctx
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, options.Timeout+15*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"/exec", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := toolkitToken(); token != "" {
		req.Header.Set("X-Toolkit-Token", token)
	}

	if options.Logf != nil {
		options.Logf("DEBUG", "[toolkit] POST %s/exec tool=%s", base, toolkitToolName(tool))
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return result, fmt.Errorf("调用 toolkit 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("toolkit 返回 %d: %s", resp.StatusCode, truncateForLog(string(raw), 300))
	}

	var parsed struct {
		ExitCode int    `json:"exitCode"`
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return result, fmt.Errorf("解析 toolkit 响应失败: %w", err)
	}
	if parsed.Error != "" {
		return result, fmt.Errorf("toolkit 执行失败: %s", parsed.Error)
	}

	result.Stdout = parsed.Stdout
	result.Stderr = parsed.Stderr
	result.ExitCode = parsed.ExitCode
	return result, nil
}

func truncateForLog(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}
