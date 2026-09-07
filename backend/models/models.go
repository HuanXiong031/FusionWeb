// 数据模型定义（与数据库记录和前端交互的结构体）
//
// 约定：
// - 所有时间字段使用 `time.Time` 存储，数据库层负责格式转换；
// - 复杂字段（如列表、映射）统一以 JSON/YAML 字符串形式持久化；
// - 字段命名与前端保持一致，便于 wails 自动生成类型。
package models

import "time"

// TaskConfig 任务配置
// 描述一次扫描任务的完整参数与生命周期状态
// 典型流程：创建 -> running -> paused/completed/failed/cancelled
// 说明：
// - TaskType: "web"/"port"/"subdomain"/"weak_password"/"directory"/"js"
// - ScanMode: 端口扫描: "port_service"；Web 扫描: "alive"/"fingerprint"/"fingerprint_poc"/"poc"
// - SelectedDicts/NoPortString 等以 JSON 字符串保存，便于扩展
type TaskConfig struct {
	TaskID                       string    `json:"task_id"`
	TaskName                     string    `json:"task_name"`
	TaskType                     string    `json:"task_type"`      // web/port/subdomain/weak_password/directory/js
	ParentTaskID                 string    `json:"parent_task_id"` // 父任务ID（重启任务时设置）
	TargetInput                  string    `json:"target_input"`
	PortRange                    string    `json:"port_range"`
	NoPortString                 string    `json:"no_port_string"` // 禁止扫描的端口
	ScanMode                     string    `json:"scan_mode"`      // port_service (端口扫描) 或 alive/fingerprint/fingerprint_poc/poc (Web扫描)
	ScanTool                     string    `json:"scan_tool"`      // 外部扫描工具或模块内工具名
	ScanOptions                  string    `json:"scan_options"`   // JSON 格式的模块专属参数
	ThreadCount                  int       `json:"thread_count"`
	PortScanTimeout              int       `json:"port_scan_timeout"` // 端口扫描超时时间（秒）
	WebTimeout                   int       `json:"web_timeout"`       // Web探测超时时间（秒），默认10秒
	EnableScreenshot             bool      `json:"enable_screenshot"` // 启用页面截图（使用无头浏览器渲染后保存截图）
	HTTPProxy                    string    `json:"http_proxy"`
	SkipHostDiscovery            bool      `json:"skip_host_discovery"`               // 跳过主机存活探测
	NoICMPPing                   bool      `json:"no_icmp_ping"`                      // 禁用ICMP探测
	TCPPing                      bool      `json:"tcp_ping"`                          // 启用TCP探测
	PortsThreshold               int       `json:"ports_threshold"`                   // 单IP端口数量阈值
	SYNScanRate                  int       `json:"syn_scan_rate"`                     // 兼容旧配置，当前端口服务扫描不使用
	WebLink                      bool      `json:"web_link"`                          // Web联动（端口扫描后自动Web探测）
	ScanAllPOCsWhenNoFingerprint bool      `json:"scan_all_pocs_when_no_fingerprint"` // 识别不到指纹时调用所有子目录的POC
	FullPocScan                  bool      `json:"full_poc_scan"`                     // 全量POC扫描（扫描所有POC目录，忽略指纹）
	EnableActiveFingerprint      bool      `json:"enable_active_fingerprint"`         // 启用主动指纹探测（目录字典扫描）
	SelectedDicts                string    `json:"selected_dicts"`                    // JSON 格式的字典/路径列表
	AssignedWorker               string    `json:"assigned_worker"`                   // 指定执行节点；为空时由调度器自动分配
	DingTalkToken                string    `json:"ding_talk_token"`                   // 钉钉机器人Token
	DingTalkSecret               string    `json:"ding_talk_secret"`                  // 钉钉机器人Secret
	DingTalkKeyID                int       `json:"ding_talk_key_id"`                  // 系统设置中选择的钉钉Key
	DingTalkBotID                int       `json:"dingtalk_bot_id"`                   // 统一钉钉机器人
	DingTalkConversationID       string    `json:"dingtalk_conversation_id"`          // 来源会话
	DingTalkConversationType     string    `json:"dingtalk_conversation_type"`        // 来源会话类型（单聊/群聊）
	DingTalkSourceUserID         string    `json:"dingtalk_source_user_id"`           // 来源钉钉用户 ID
	DingTalkSourceMessageID      string    `json:"dingtalk_source_message_id"`        // 来源消息幂等键
	CreatedAt                    time.Time `json:"created_at"`
	UpdatedAt                    time.Time `json:"updated_at"`
	Status                       string    `json:"status"` // pending/running/completed/failed/paused/cancelled
	CurrentStage                 string    `json:"current_stage"`
}

// ReconResult 信息收集结果
// result_type 枚举："port"/"url"/"protocol"，extra_data 为 JSON 详情
type ReconResult struct {
	ID           int       `json:"id"`
	TaskID       string    `json:"task_id"`
	ResultType   string    `json:"result_type"` // port/url/protocol
	Target       string    `json:"target"`
	Source       string    `json:"source"`
	ExtraData    string    `json:"extra_data"` // JSON 格式
	DiscoveredAt time.Time `json:"discovered_at"`
}

// FingerprintResult 指纹识别结果
// matched_rules 为 JSON，记录命中的规则集合与匹配细节
type FingerprintResult struct {
	ID              int       `json:"id"`
	TaskID          string    `json:"task_id"`
	Target          string    `json:"target"`
	FingerprintName string    `json:"fingerprint_name"`
	MatchedRules    string    `json:"matched_rules"` // JSON 格式
	IdentifiedAt    time.Time `json:"identified_at"`
}

// POC POC 模板（文件级）
// 对应 POC 文件本身的元信息，content 为 YAML 文本
type POC struct {
	ID        int       `json:"id"`
	Category  string    `json:"category"`
	FileName  string    `json:"file_name"`
	Content   string    `json:"content"`
	Severity  string    `json:"severity"`
	Tags      string    `json:"tags"` // JSON 数组
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// POCTemplate POC 模板（结构化）
// 解析后的模板信息，便于前端展示与筛选
type POCTemplate struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Author      string    `json:"author"`
	Severity    string    `json:"severity"` // critical/high/medium/low/info
	Category    string    `json:"category"`
	Tags        string    `json:"tags"`
	Content     string    `json:"content"`
	IsEnabled   bool      `json:"is_enabled"`
	CreatedBy   *int      `json:"created_by,omitempty"` // 创建者ID，nil表示系统导入
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// VulnResult 漏洞扫描结果
// 包含命中目标、模板元信息、请求/响应原文及严重等级。
// Author 与 Tags 来源于 POC YAML 的 info 块，命中时会随扫描结果一起落库。
type VulnResult struct {
	ID               int       `json:"id"`
	TaskID           string    `json:"task_id"`
	Target           string    `json:"target"`
	TemplateID       string    `json:"template_id"`
	TemplatePath     string    `json:"template_path"` // 模板文件路径
	MatcherName      string    `json:"matcher_name"`
	Severity         string    `json:"severity"`
	Name             string    `json:"name"` // 漏洞名称
	Author           string    `json:"author"`
	Tags             string    `json:"tags"`
	Description      string    `json:"description"`
	Request          string    `json:"request"`
	Response         string    `json:"response"`
	MatchedAt        string    `json:"matched_at"`        // 匹配位置
	ExtractedResults string    `json:"extracted_results"` // 提取结果
	Metadata         string    `json:"metadata"`          // 元数据
	DiscoveredAt     time.Time `json:"discovered_at"`
}

// TaskCheckpoint 任务断点
// 记录任务进行过程中的阶段与目标队列，用于断点续扫
type TaskCheckpoint struct {
	TaskID           string `json:"task_id"`
	CurrentStage     string `json:"current_stage"`
	CompletedTargets string `json:"completed_targets"` // JSON 数组
	PendingTargets   string `json:"pending_targets"`   // JSON 数组
	IntermediateData string `json:"intermediate_data"` // JSON 格式
}

// TaskLog 任务日志
// 结构化记录扫描过程中的日志信息与附加元数据
type TaskLog struct {
	ID        int       `json:"id"`
	TaskID    string    `json:"task_id"`
	Level     string    `json:"level"` // DEBUG/INFO/SUCCESS/WARNING/ERROR
	Stage     string    `json:"stage"` // recon/fingerprint/vuln
	Message   string    `json:"message"`
	Metadata  string    `json:"metadata"` // JSON 格式
	CreatedAt time.Time `json:"created_at"`
}

// LicenseConfig 授权配置
// 记录授权文件与所有者信息、到期时间及校验结果
type LicenseConfig struct {
	ID          int       `json:"id"`
	MachineCode string    `json:"machine_code"`
	LicenseFile string    `json:"license_file"`
	Owner       string    `json:"owner"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsValid     bool      `json:"is_valid"`
	VerifiedAt  time.Time `json:"verified_at"`
}

// ReportMetadata 报告元数据
// 记录报告类型与生成时间，便于列表展示与下载
type ReportMetadata struct {
	ID          int       `json:"id"`
	TaskID      string    `json:"task_id"`
	ReportType  string    `json:"report_type"` // html/excel/json
	FilePath    string    `json:"file_path"`
	GeneratedAt time.Time `json:"generated_at"`
}

// ProgressInfo 进度信息
// 前端展示任务进度条与实时统计的基础数据结构
type ProgressInfo struct {
	TaskID           string  `json:"task_id"`
	Stage            string  `json:"stage"`
	Percentage       float64 `json:"percentage"`
	Message          string  `json:"message"`
	PortCount        int     `json:"port_count"`
	URLCount         int     `json:"url_count"`
	FingerprintCount int     `json:"fingerprint_count"`
	VulnCount        int     `json:"vuln_count"`
}

// PocScanTask POC扫描任务
type PocScanTask struct {
	TaskID          string    `json:"task_id"`
	TaskName        string    `json:"task_name"`
	Targets         string    `json:"targets"`       // JSON array string
	SelectedPocs    string    `json:"selected_pocs"` // JSON array string
	Status          string    `json:"status"`
	Progress        float64   `json:"progress"`
	FoundVulns      int       `json:"found_vulns"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	CompletedAt     time.Time `json:"completed_at"`
	ThreadCount     int       `json:"thread_count"`
	HTTPProxy       string    `json:"http_proxy"`
	RateLimit       int       `json:"rate_limit"`
	InteractshURL   string    `json:"interactsh_url"`
	InteractshToken string    `json:"interactsh_token"`
	UserID          int       `json:"user_id"`
}

// PocScanResult POC扫描结果
// Author 与 Tags 来源于 POC YAML 的 info 块，命中时会随扫描结果一起落库。
type PocScanResult struct {
	ID               int       `json:"id"`
	TaskID           string    `json:"task_id"`
	ScanScope        string    `json:"scan_scope"`
	UserID           int       `json:"user_id"`
	Target           string    `json:"target"`
	TemplateID       string    `json:"template_id"`
	TemplatePath     string    `json:"template_path"`
	MatcherName      string    `json:"matcher_name"`
	Severity         string    `json:"severity"`
	Name             string    `json:"name"`
	Author           string    `json:"author"`
	Tags             string    `json:"tags"`
	Description      string    `json:"description"`
	Request          string    `json:"request"`
	Response         string    `json:"response"`
	MatchedAt        string    `json:"matched_at"`
	ExtractedResults string    `json:"extracted_results"`
	Metadata         string    `json:"metadata"`
	DiscoveredAt     time.Time `json:"discovered_at"`
}

// VulnVerifyGroup 漏洞验证分组
type VulnVerifyGroup struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ManualVulnVerify 手动漏洞验证
// 存储手动添加的漏洞验证记录
type ManualVulnVerify struct {
	ID         int       `json:"id"`
	GroupID    int       `json:"group_id"` // 分组ID
	Name       string    `json:"name"`
	Target     string    `json:"target"`
	Severity   string    `json:"severity"`
	Request    string    `json:"request"`
	Response   string    `json:"response"`
	Status     int       `json:"status"` // 0: 未验证, 1: 验证中, 2: 验证完成, 3: 验证失败
	StatusText string    `json:"status_text"`
	Duration   int64     `json:"duration"`
	History    string    `json:"history"` // JSON string of history records
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	UserID     int       `json:"user_id"`
}
