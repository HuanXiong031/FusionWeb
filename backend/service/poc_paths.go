package service

import (
	"FusionWeb/backend/utils"
	"os"
	"path/filepath"
	"strings"
)

func resolvePocDataDir() string { return utils.GetDataDir() }

func resolvePocRoot() string {
	root := filepath.Join(utils.GetDataDir(), "pocs")
	if pocRootHasTemplates(root) {
		return root
	}
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		return root
	}
	return root
}

func uniquePocPathCandidates(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cleaned := filepath.Clean(p)
		key := strings.ToLower(cleaned)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique
}

func pocRootHasTemplates(root string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
