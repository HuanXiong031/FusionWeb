package api

import (
	"FusionWeb/backend/service"
	"FusionWeb/backend/utils"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *App) GetFingerprintsPage(page, pageSize int, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error) {
	items, total, err := a.fingerprintDBService.GetFingerprintsPage(page, pageSize, category, keyword, sortBy, sortOrder, createdByFilter, blacklistedOnly)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"items": items,
		"total": total,
	}, nil
}

func (a *App) GetFingerprintsPageByType(page, pageSize int, fpType, category, keyword, sortBy, sortOrder string, createdByFilter *int, blacklistedOnly bool) (map[string]interface{}, error) {
	items, total, err := a.fingerprintDBService.GetFingerprintsPageByType(page, pageSize, fpType, category, keyword, sortBy, sortOrder, createdByFilter, blacklistedOnly)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"items": items,
		"total": total,
	}, nil
}

func (a *App) GetFingerprints() ([]service.FingerprintItem, error) {
	return a.fingerprintDBService.GetFingerprints()
}

func (a *App) GetFingerprintCategories() ([]string, error) {
	return a.fingerprintDBService.GetCategories()
}

func (a *App) AddFingerprint(fp service.FingerprintItem, userID *int) error {
	return a.fingerprintDBService.AddFingerprint(&fp, userID)
}

func (a *App) AddFingerprintWithType(fp service.FingerprintItem, fpType string, userID *int) error {
	return a.fingerprintDBService.AddFingerprintWithType(&fp, fpType, userID)
}

func (a *App) UpdateFingerprint(fp service.FingerprintItem) error {
	return a.fingerprintDBService.UpdateFingerprint(&fp)
}

func (a *App) UpdateFingerprintByOldName(oldName string, fp service.FingerprintItem) error {
	return a.fingerprintDBService.UpdateFingerprintByOldName(oldName, &fp)
}

func (a *App) DeleteFingerprint(name string) error {
	return a.fingerprintDBService.DeleteFingerprint(name)
}

func (a *App) DeleteAllFingerprints(userID *int, createdByFilter *int) (int, error) {
	return a.fingerprintDBService.DeleteAllFingerprints(userID, createdByFilter)
}

func (a *App) SearchFingerprints(keyword string) ([]service.FingerprintItem, error) {
	return a.fingerprintDBService.SearchFingerprints(keyword)
}

func (a *App) ImportFingerprint(yamlContent string, fileName string) error {
	return a.fingerprintDBService.ImportFingerprint(yamlContent, fileName)
}

func (a *App) ImportFingerprintWithType(yamlContent string, fileName string, fpType string) error {
	return a.fingerprintDBService.ImportFingerprintWithType(yamlContent, fileName, fpType)
}

func (a *App) ExportFingerprints() (string, error) {
	return a.fingerprintDBService.ExportFingerprints()
}

func (a *App) ExportFingerprintsByType(exportType string) (string, error) {
	return a.fingerprintDBService.ExportFingerprintsByType(exportType)
}

func (a *App) ExportSingleFingerprint(name string, fpType string) (string, error) {
	return a.fingerprintDBService.ExportSingleFingerprint(name, fpType)
}

func (a *App) ExportFingerprintsToFile(exportType string) error {
	content, err := a.fingerprintDBService.ExportFingerprintsByType(exportType)
	if err != nil {
		return err
	}

	// 确保 exports 目录存在
	dataDir := utils.GetDataDir()
	exportDir := filepath.Join(dataDir, "exports")
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return fmt.Errorf("create exports directory failed: %w", err)
	}

	// 生成文件名
	timestamp := utils.GetCurrentTimeString("20060102_150405")
	fileName := fmt.Sprintf("fingerprints_%s_%s", exportType, timestamp)
	if strings.HasPrefix(content, "zip:") {
		fileName += ".zip"
		// 解码 base64
		parts := strings.SplitN(content, ":", 2)
		if len(parts) == 2 {
			zipData, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return fmt.Errorf("decode zip content failed: %w", err)
			}
			filePath := filepath.Join(exportDir, fileName)
			return os.WriteFile(filePath, zipData, 0644)
		}
		return fmt.Errorf("invalid zip content format")
	}

	fileName += ".yaml"
	filePath := filepath.Join(exportDir, fileName)
	return os.WriteFile(filePath, []byte(content), 0644)
}

func (a *App) GetFingerprintStatistics() (map[string]interface{}, error) {
	return a.fingerprintDBService.GetStatistics()
}

func (a *App) ToggleFingerprintBlacklist(name string) error {
	return a.fingerprintDBService.ToggleBlacklist(name)
}

func (a *App) ToggleFingerprintEnabled(name string) error {
	return a.fingerprintDBService.ToggleEnabled(name)
}

// 辅助方法（保留，虽然接口可能没定义，但前端或其他代码可能用到）
func (a *App) GetFingerprintCategoriesByType(fpType string) ([]string, error) {
	return a.fingerprintDBService.GetFingerprintCategoriesByType(fpType)
}

func (a *App) AutoIdentifyFingerprint(url string) ([]string, error) {
	// 生成临时任务ID
	taskID := fmt.Sprintf("auto-fp-%d", time.Now().UnixNano())

	// 创建指纹服务
	fpService := service.NewFingerprintService(taskID, a.ctx)

	// 运行识别
	err := fpService.RunFingerprintIdentification([]string{url})
	if err != nil {
		return nil, err
	}

	// 获取结果
	results, err := fpService.GetFingerprintResults()
	if err != nil {
		return nil, err
	}

	// 提取当前URL的指纹
	var fingerprints []string

	// 简单匹配：直接查找
	if fps, ok := results[url]; ok {
		fingerprints = append(fingerprints, fps...)
	} else {
		// 尝试添加/移除斜杠匹配
		altUrl := url
		if strings.HasSuffix(url, "/") {
			altUrl = strings.TrimSuffix(url, "/")
		} else {
			altUrl = url + "/"
		}
		if fps, ok := results[altUrl]; ok {
			fingerprints = append(fingerprints, fps...)
		}
	}

	// 如果还是没找到，可能是因为 key 被归一化了 (protocol + host)
	if len(fingerprints) == 0 {
		for _, fps := range results {
			// 如果只有一个目标，那么所有结果都是它的
			fingerprints = append(fingerprints, fps...)
		}
	}

	// 去重
	uniqueFps := make(map[string]bool)
	var finalFps []string
	for _, fp := range fingerprints {
		if !uniqueFps[fp] {
			uniqueFps[fp] = true
			finalFps = append(finalFps, fp)
		}
	}

	return finalFps, nil
}

// ============ Missing Methods Implementation (Placeholder) ============

// POC Management
