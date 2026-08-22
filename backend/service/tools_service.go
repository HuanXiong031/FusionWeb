// Package service 提供FusionWeb平台的核心业务逻辑。
// 本文件实现实用工具服务，包括扫描配置的持久化管理和原始HTTP请求发送。
package service

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/models"
	"FusionWeb/backend/utils"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// ToolsService 工具服务，提供扫描配置管理和原始HTTP请求调试功能。
type ToolsService struct{}

// NewToolsService 创建工具服务实例。
func NewToolsService() *ToolsService {
	return &ToolsService{}
}

// LoadScanConfig 从数据库按名称加载预设的扫描配置（JSON格式存储）。
//
// 参数:
//   - name: 配置名称
//
// 返回值:
//   - models.TaskConfig: 解析后的任务配置对象（不存在时返回空结构体）
//   - error: 查询或反序列化失败时返回错误
func (s *ToolsService) LoadScanConfig(name string) (models.TaskConfig, error) {
	var configJSON string
	err := database.DB.QueryRow("SELECT config FROM scan_config WHERE name = ?", name).Scan(&configJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return models.TaskConfig{}, nil // 配置不存在，返回空
		}
		return models.TaskConfig{}, err
	}

	var config models.TaskConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return models.TaskConfig{}, err
	}

	return config, nil
}

// SaveScanConfig 将扫描配置以 JSON 格式保存到 PostgreSQL。
// 使用 PostgreSQL UPSERT，同名配置自动覆盖。
//
// 参数:
//   - name: 配置名称
//   - config: 任务配置对象
//
// 返回值:
//   - error: 序列化或写入失败时返回错误
func (s *ToolsService) SaveScanConfig(name string, config models.TaskConfig) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(`
		INSERT INTO scan_config (name, config, updated_at) 
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET 
		config = excluded.config,
		updated_at = excluded.updated_at
	`, name, string(configJSON), utils.GetCurrentTimeString())

	return err
}

// SendRawRequest 发送原始HTTP请求并返回完整的请求/响应信息。
// 支持自动解压gzip/deflate内容编码，自动将GBK编码响应转换为UTF-8。
//
// 参数:
//   - method: HTTP方法（GET/POST/PUT等）
//   - urlStr: 目标URL
//   - headers: 自定义请求头映射
//   - body: 请求体字符串
//   - timeout: 超时时间（秒）
//
// 返回值:
//   - map[string]interface{}: 包含status_code、headers、body、raw_response、duration等字段
//   - error: 请求创建或发送失败时返回错误
func (s *ToolsService) SendRawRequest(method string, urlStr string, headers map[string]string, body string, timeout int) (map[string]interface{}, error) {
	// 创建请求
	req, err := http.NewRequest(method, urlStr, bytes.NewBufferString(body))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置Header
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 设置超时
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// 发送请求
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()
	duration := time.Since(start).Milliseconds()

	// 读取响应体 (DumpResponse会重置Body，所以可以继续读取)
	// 注意：如果用户设置了 Accept-Encoding，http.Client 不会自动解压
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 处理解压
	var bodyBytes []byte
	contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	switch {
	case strings.Contains(contentEncoding, "gzip"):
		reader, err := gzip.NewReader(bytes.NewReader(rawBody))
		if err == nil {
			bodyBytes, _ = io.ReadAll(reader)
			reader.Close()
		} else {
			bodyBytes = rawBody // 解压失败，回退
		}
	case strings.Contains(contentEncoding, "deflate"):
		// 尝试 zlib
		reader, err := zlib.NewReader(bytes.NewReader(rawBody))
		if err == nil {
			bodyBytes, _ = io.ReadAll(reader)
			reader.Close()
		} else {
			// 尝试 flate
			reader := flate.NewReader(bytes.NewReader(rawBody))
			bodyBytes, _ = io.ReadAll(reader)
			reader.Close()
		}
	default:
		bodyBytes = rawBody
	}

	// 获取响应头
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, "; ")
	}

	// 处理编码问题 (GBK -> UTF8)
	contentType := resp.Header.Get("Content-Type")
	bodyStr := convertToUTF8(bodyBytes, contentType)

	// raw_response 处理
	// 原始的 rawResponseBytes 包含 Header 和 Compressed Body (如果Content-Encoding存在)
	// 用户希望看到解压后的内容，所以我们需要构造一个显示用的 raw_response

	// 1. 获取 Headers 部分
	headerDump, _ := httputil.DumpResponse(resp, false)

	// 2. 拼接 Headers + Decoded Body
	// 注意：这里的 headerDump 仍然包含 Content-Encoding: gzip，但 body 是解压后的
	// 这在查看时是可以接受的，或者我们可以手动移除该 Header，但为了保持真实性，保留 Header，只展示解压后的 Body 是常见的做法
	rawResponseStr := string(headerDump) + bodyStr

	return map[string]interface{}{
		"status_code":    resp.StatusCode,
		"status":         resp.Status,
		"headers":        respHeaders,
		"body":           bodyStr,
		"raw_response":   rawResponseStr,
		"duration":       duration,
		"content_length": len(bodyBytes), // 使用解压后的大小
	}, nil
}

// convertToUTF8 智能编码转换：先检查是否为有效UTF-8，否则尝试GBK解码。
// 适用于处理中文网站常见的GBK/GB18030编码响应。
//
// 参数:
//   - data: 原始字节数据
//   - contentType: HTTP Content-Type头（保留参数，可用于扩展编码检测逻辑）
//
// 返回值:
//   - string: UTF-8编码的字符串
func convertToUTF8(data []byte, contentType string) string {
	// 1. 如果已经是有效的 UTF-8，直接返回
	if utf8.Valid(data) {
		return string(data)
	}

	// 2. 尝试根据 Content-Type 或尝试 GBK 解码
	// 这里的逻辑是：既然它不是有效的 UTF-8，那很有可能是 GBK/GB18030 (中文环境常见)
	// 无论 Header 是否声明，都尝试用 GBK 解码一下
	reader := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GBK.NewDecoder())
	d, err := io.ReadAll(reader)
	if err == nil {
		// 如果解码成功，且结果是有效的 UTF-8，就使用它
		// 注意：transform.NewReader 可能会在遇到非法字节时替换为 �，这通常也是我们想要的
		return string(d)
	}

	// 3. 如果转换失败，只能强制转换为 string（可能会有乱码）
	return string(data)
}
