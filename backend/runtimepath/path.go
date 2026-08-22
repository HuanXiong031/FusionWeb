package runtimepath

import (
	"FusionWeb/backend/config"
	"os"
	"path/filepath"
	"strings"
)

// DataDir returns the absolute directory used for mutable runtime data.
func DataDir() string {
	if configured := strings.TrimSpace(config.Get().DataDir); configured != "" {
		if absolute, err := filepath.Abs(configured); err == nil {
			return absolute
		}
		return filepath.Clean(configured)
	}
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "data")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			return candidate
		}
	}
	exe, err := os.Executable()
	if err != nil {
		if wd, wdErr := os.Getwd(); wdErr == nil {
			return filepath.Join(wd, "data")
		}
		return filepath.Clean("./data")
	}
	if resolved, resolveErr := filepath.EvalSymlinks(exe); resolveErr == nil {
		exe = resolved
	}
	return filepath.Join(filepath.Dir(exe), "data")
}
