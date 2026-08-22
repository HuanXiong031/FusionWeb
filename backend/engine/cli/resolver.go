package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ResolveTool finds a CLI scanner binary from an explicit environment override or PATH.
// Production Worker images install supported tools into /usr/local/bin.
func ResolveTool(name string) (string, error) {
	name = normalizeToolName(name)
	if name == "" {
		return "", fmt.Errorf("工具名称为空")
	}

	for _, candidate := range toolCandidates(name) {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("未找到 CLI 工具 %s，请确认 Worker 镜像已安装该工具，或配置 FUSIONWEB_TOOL_%s", name, envToolName(name))
}

func normalizeToolName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func toolCandidates(name string) []string {
	candidates := make([]string, 0, 3)
	if override := strings.TrimSpace(os.Getenv("FUSIONWEB_TOOL_" + envToolName(name))); override != "" {
		candidates = append(candidates, override)
	}
	candidates = append(candidates, platformToolName(name), name)
	return dedupeStrings(candidates)
}

func platformToolName(name string) string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(name), ".exe") {
		return name + ".exe"
	}
	return name
}

func envToolName(name string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return strings.ToUpper(replacer.Replace(name))
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}
