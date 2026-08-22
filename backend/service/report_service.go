package service

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"FusionWeb/backend/database"
	"FusionWeb/backend/utils"

	"gopkg.in/yaml.v3"
)

// ReportService 报告生成服务
type ReportService struct {
	taskID      string
	db          *sql.DB
	pocCache    map[string]PocMeta
	pocIdToPath map[string]string
	initialized bool
	isPocTask   bool // 标记是否为 POC 扫描任务
}

// PocMeta POC元数据
type PocMeta struct {
	Name   string
	Author string
	Tags   string
}

// NewReportService 创建报告生成服务实例
func NewReportService(taskID string) *ReportService {
	return &ReportService{
		taskID:      taskID,
		db:          database.DB,
		pocCache:    make(map[string]PocMeta),
		pocIdToPath: make(map[string]string),
	}
}

// ReportData 报告数据结构
type ReportData struct {
	TaskInfo        *TaskInfo            `json:"task_info"`
	Statistics      *Statistics          `json:"statistics"`
	ReconResults    []ReconSummary       `json:"recon_results"`
	Fingerprints    []FingerprintSummary `json:"fingerprints"`
	Vulnerabilities []VulnSummary        `json:"vulnerabilities"`
}

// TaskInfo 任务信息
type TaskInfo struct {
	TaskID      string    `json:"task_id"`
	TaskName    string    `json:"task_name"`
	Target      string    `json:"target"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// Statistics 统计数据
type Statistics struct {
	PortCount        int `json:"port_count"`
	URLCount         int `json:"url_count"`
	FingerprintCount int `json:"fingerprint_count"`
	VulnCount        int `json:"vuln_count"`
	CriticalCount    int `json:"critical_count"`
	HighCount        int `json:"high_count"`
	MediumCount      int `json:"medium_count"`
	LowCount         int `json:"low_count"`
	InfoCount        int `json:"info_count"`
}

// ReconSummary 信息收集汇总
type ReconSummary struct {
	Type       string `json:"type"`
	Target     string `json:"target"`
	Source     string `json:"source"`
	Time       string `json:"time"`
	Host       string `json:"host,omitempty"`
	Port       string `json:"port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Service    string `json:"service,omitempty"`
	Status     string `json:"status,omitempty"`
	Banner     string `json:"banner,omitempty"`
	StatusCode string `json:"status_code,omitempty"`
	Title      string `json:"title,omitempty"`
	Length     string `json:"length,omitempty"`
}

// FingerprintSummary 指纹识别汇总
type FingerprintSummary struct {
	Target      string `json:"target"`
	Fingerprint string `json:"fingerprint"`
	Time        string `json:"time"`
}

// VulnSummary 漏洞汇总
type VulnSummary struct {
	Target      string `json:"target"`
	TemplateID  string `json:"template_id"`
	MatcherName string `json:"matcher_name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Request     string `json:"request"`
	Response    string `json:"response"`
	Time        string `json:"time"`
	Name        string `json:"name"`   // 漏洞名称
	Author      string `json:"author"` // 作者
	Tags        string `json:"tags"`   // 标签
}

// initPocMap 初始化POC ID映射
func (s *ReportService) initPocMap() {
	if s.initialized {
		return
	}

	pocRoot := filepath.Join(getDataDir(), "pocs")
	if _, err := os.Stat(pocRoot); err != nil {
		s.initialized = true
		return
	}

	filepath.Walk(pocRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			// 读取文件提取ID
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			contentStr := string(content)

			// 简单的ID提取
			if idx := strings.Index(contentStr, "id:"); idx != -1 {
				line := contentStr[idx:]
				if endIdx := strings.Index(line, "\n"); endIdx != -1 {
					id := strings.TrimSpace(line[3:endIdx])
					// 存储相对路径
					relPath, err := filepath.Rel(pocRoot, path)
					if err == nil {
						// 替换反斜杠为正斜杠，保持一致性
						relPath = filepath.ToSlash(relPath)
						s.pocIdToPath[id] = relPath
					}
				}
			}
		}
		return nil
	})

	s.initialized = true
}

func getDataDir() string {
	return resolvePocDataDir()
}

// getPocMetadata 获取POC元数据（作者、标签）
func (s *ReportService) getPocMetadata(templatePath, templateID string) PocMeta {
	// 如果路径为空，尝试通过ID查找
	if templatePath == "" {
		if templateID == "" {
			return PocMeta{}
		}
		// 懒加载POC映射
		s.initPocMap()

		if path, ok := s.pocIdToPath[templateID]; ok {
			templatePath = path
		} else {
			return PocMeta{}
		}
	}

	// 检查缓存
	if meta, ok := s.pocCache[templatePath]; ok {
		return meta
	}

	var content []byte
	for _, candidate := range pocMetadataPathCandidates(templatePath) {
		data, err := os.ReadFile(candidate)
		if err == nil {
			content = data
			break
		}
	}
	if len(content) == 0 {
		s.pocCache[templatePath] = PocMeta{}
		return PocMeta{}
	}

	if meta := parsePocMetadata(content); meta != (PocMeta{}) {
		s.pocCache[templatePath] = meta
		return meta
	}

	// 兜底解析：兼容缩进不规范但仍能被旧逻辑识别的模板。
	contentStr := string(content)
	var name, author, tags string
	var inInfoBlock bool

	// 使用更健壮的方式提取 author (处理缩进和空格)
	lines := strings.Split(contentStr, "\n")
	for _, line := range lines {
		// 跳过空行和注释
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		// 检查是否在 info 块中
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(line, "info:") {
				inInfoBlock = true
			} else {
				inInfoBlock = false
			}
			continue
		}

		if inInfoBlock {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "name:") {
				val := strings.TrimPrefix(trimmed, "name:")
				name = strings.Trim(strings.TrimSpace(val), "'\"")
			} else if strings.HasPrefix(trimmed, "author:") {
				val := strings.TrimPrefix(trimmed, "author:")
				author = strings.Trim(strings.TrimSpace(val), "'\"")
			} else if strings.HasPrefix(trimmed, "tags:") {
				val := strings.TrimPrefix(trimmed, "tags:")
				tags = strings.Trim(strings.TrimSpace(val), "'\"")
			}
		} else {
			// 兼容旧的解析方式（如果 info 块缩进不规范或直接在顶层）
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "author:") && author == "" {
				val := strings.TrimPrefix(trimmed, "author:")
				author = strings.Trim(strings.TrimSpace(val), "'\"")
			} else if strings.HasPrefix(trimmed, "tags:") && tags == "" {
				val := strings.TrimPrefix(trimmed, "tags:")
				tags = strings.Trim(strings.TrimSpace(val), "'\"")
			}
		}

		if name != "" && author != "" && tags != "" {
			break
		}
	}

	meta := PocMeta{Name: name, Author: author, Tags: tags}
	s.pocCache[templatePath] = meta
	return meta
}

func pocMetadataPathCandidates(templatePath string) []string {
	templatePath = strings.TrimSpace(templatePath)
	if templatePath == "" {
		return nil
	}

	candidates := []string{}
	if filepath.IsAbs(templatePath) {
		candidates = append(candidates, templatePath)
	} else {
		candidates = append(candidates,
			filepath.Join(getDataDir(), "pocs", templatePath),
			filepath.Join(getDataDir(), templatePath),
			templatePath,
		)
		if cwd, err := os.Getwd(); err == nil {
			candidates = append(candidates, filepath.Join(cwd, templatePath))
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	unique := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		cleaned := filepath.Clean(candidate)
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		unique = append(unique, cleaned)
	}
	return unique
}

func parsePocMetadata(content []byte) PocMeta {
	var parsed struct {
		Info struct {
			Name   interface{} `yaml:"name"`
			Author interface{} `yaml:"author"`
			Tags   interface{} `yaml:"tags"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		return PocMeta{}
	}
	return PocMeta{
		Name:   metadataValueString(parsed.Info.Name),
		Author: metadataValueString(parsed.Info.Author),
		Tags:   metadataValueString(parsed.Info.Tags),
	}
}

func metadataValueString(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(v)
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := metadataValueString(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case []string:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if text := strings.TrimSpace(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// CollectReportData 收集报告数据
func (s *ReportService) CollectReportData() (*ReportData, error) {
	data := &ReportData{}

	// 1. 获取任务信息
	taskInfo, err := s.getTaskInfo()
	if err != nil {
		return nil, fmt.Errorf("获取任务信息失败: %w", err)
	}
	data.TaskInfo = taskInfo

	// 2. 统计数据
	stats, err := s.getStatistics()
	if err != nil {
		return nil, fmt.Errorf("获取统计数据失败: %w", err)
	}
	data.Statistics = stats

	// 3. 信息收集结果
	reconResults, err := s.getReconResults()
	if err != nil {
		return nil, fmt.Errorf("获取信息收集结果失败: %w", err)
	}
	data.ReconResults = reconResults

	// 4. 指纹识别结果
	fingerprints, err := s.getFingerprints()
	if err != nil {
		return nil, fmt.Errorf("获取指纹识别结果失败: %w", err)
	}
	data.Fingerprints = fingerprints

	// 5. 漏洞扫描结果
	vulns, err := s.getVulnerabilities()
	if err != nil {
		return nil, fmt.Errorf("获取漏洞扫描结果失败: %w", err)
	}
	data.Vulnerabilities = vulns

	return data, nil
}

// getTaskInfo 获取任务信息
func (s *ReportService) getTaskInfo() (*TaskInfo, error) {
	// 先尝试从 task_config 获取
	query := `
		SELECT task_id, task_name, target_input, status, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
		FROM task_config
		WHERE task_id = ?
	`

	var info TaskInfo
	var createdAt, updatedAt sql.NullString
	err := s.db.QueryRow(query, s.taskID).Scan(
		&info.TaskID, &info.TaskName, &info.Target, &info.Status, &createdAt, &updatedAt,
	)

	// 如果 task_config 没有找到，尝试从 poc_scan_tasks 获取
	if err == sql.ErrNoRows {
		pocQuery := `
			SELECT task_id, task_name, targets, status, CAST(created_at AS TEXT), CAST(updated_at AS TEXT)
			FROM poc_scan_tasks
			WHERE task_id = ?
		`
		err = s.db.QueryRow(pocQuery, s.taskID).Scan(
			&info.TaskID, &info.TaskName, &info.Target, &info.Status, &createdAt, &updatedAt,
		)
		if err == nil {
			s.isPocTask = true
		}
	}

	if err != nil {
		return nil, err
	}

	// 解析创建时间
	if createdAt.Valid && createdAt.String != "" {
		// 尝试多种时间格式
		// 使用统一的 ParseTimeString 函数解析时间
		if t, err := utils.ParseTimeString(createdAt.String); err == nil {
			info.CreatedAt = t
		}
	}

	// 解析完成时间（如果任务已完成，使用 updated_at；否则使用当前时间或空值）
	if updatedAt.Valid && updatedAt.String != "" {
		// 使用统一的 ParseTimeString 函数解析时间
		if t, err := utils.ParseTimeString(updatedAt.String); err == nil {
			info.CompletedAt = t
		}
	}

	// 如果任务已完成但完成时间为空，使用更新时间
	if (info.Status == "completed" || info.Status == "failed" || info.Status == "cancelled") && info.CompletedAt.IsZero() {
		if !info.CreatedAt.IsZero() {
			info.CompletedAt = info.CreatedAt
		}
	}

	return &info, nil
}

// GetTaskInfo 获取任务信息（公开方法，供外部调用）
func (s *ReportService) GetTaskInfo() (*TaskInfo, error) {
	return s.getTaskInfo()
}

// translateStatus 翻译状态为中文
func translateStatus(status string) string {
	statusMap := map[string]string{
		"pending":   "等待中",
		"running":   "运行中",
		"paused":    "已暂停",
		"completed": "已完成",
		"failed":    "已失败",
		"cancelled": "已取消",
	}
	if chinese, ok := statusMap[status]; ok {
		return chinese
	}
	return status
}

// getStatistics 获取统计数据
