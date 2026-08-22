package service

import (
	"FusionWeb/backend/logger"
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExportAllPOCs 导出所有POC模板为zip文件
// 直接从 data/pocs 目录读取，按子目录分类组织
// 返回base64编码的zip文件内容，格式：zip:base64_content
func ExportAllPOCs(userID *int) (string, error) {
	pocsDir := resolvePocRoot()

	if _, err := os.Stat(pocsDir); os.IsNotExist(err) {
		return "", fmt.Errorf("POC目录不存在: %s", pocsDir)
	}

	// 创建zip buffer
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	fileCount := 0
	err := filepath.Walk(pocsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		name := strings.ToLower(info.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		// 读取文件内容
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Warn("导出POC时读取文件失败: %s, %v", path, readErr)
			return nil
		}

		// 计算相对路径（相对于pocsDir）
		relPath, _ := filepath.Rel(pocsDir, path)
		relPath = filepath.ToSlash(relPath)

		// 写入zip
		zipFile, zipErr := zipWriter.Create(relPath)
		if zipErr != nil {
			return zipErr
		}
		zipFile.Write(content)
		fileCount++
		return nil
	})

	if err != nil {
		zipWriter.Close()
		return "", fmt.Errorf("遍历POC目录失败: %w", err)
	}

	zipWriter.Close()

	if fileCount == 0 {
		return "", fmt.Errorf("没有找到任何POC文件")
	}

	// base64编码
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	logger.Info("导出POC完成，共 %d 个文件", fileCount)
	return fmt.Sprintf("zip:%s", encoded), nil
}

// ExportSelectedPOCs 导出选中的POC文件为zip
// relativePaths: 相对于pocs目录的文件路径列表
func ExportSelectedPOCs(relativePaths []string, userID *int) (string, error) {
	if len(relativePaths) == 0 {
		return "", fmt.Errorf("未选择任何POC文件")
	}

	pocsDir := resolvePocRoot()

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	fileCount := 0
	for _, relPath := range relativePaths {
		// 安全检查
		cleanPath := filepath.Clean(relPath)
		if strings.Contains(cleanPath, "..") {
			continue
		}

		fullPath := filepath.Join(pocsDir, cleanPath)
		content, readErr := os.ReadFile(fullPath)
		if readErr != nil {
			logger.Warn("导出选中POC时读取文件失败: %s, %v", relPath, readErr)
			continue
		}

		zipFile, zipErr := zipWriter.Create(filepath.ToSlash(cleanPath))
		if zipErr != nil {
			continue
		}
		zipFile.Write(content)
		fileCount++
	}

	zipWriter.Close()

	if fileCount == 0 {
		return "", fmt.Errorf("没有成功导出任何POC文件")
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	logger.Info("导出选中POC完成，共 %d 个文件", fileCount)
	return fmt.Sprintf("zip:%s", encoded), nil
}
