// 包 structs 定义扫描配置和运行期数据结构。
// FusionWeb 按单用户可信工具运行；并发任务之间依靠 taskID 隔离扫描状态。
//
// 关键数据结构：
// - Config: 扫描全局配置，涵盖目标输入、扫描策略、并发/超时、指纹与 POC 配置
// - URLEntity: 表示一个 RootURL 的基础信息与路径详情（含 TLS 证书信息）
// - TaskTypeState: 按任务类型（web/port）隔离的第一级状态容器
// - TaskInstanceState: 按任务实例（taskID）隔离的第二级状态容器
//
// Global* 变量仅保留给旧入口兼容；新扫描流程应使用 TaskInstanceState。
package structs

import (
	"net"
	"sync"

	"github.com/lcvvvv/gonmap"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

// 输入类型枚举常量
// 用于标识用户输入的目标格式类型，决定后续处理流程
const (
	TypeDomain     = 1
	TypeDomainPort = 2
	TypeIPRange    = 3
	TypeCIDR       = 4
	TypeIP         = 5
	TypeIPPort     = 6
	TypeURL        = 7
	TypeUnSupport  = 0
)

// Config 扫描引擎全局配置
// 涵盖目标输入、扫描策略、并发/超时、指纹与 POC 配置文件路径等
// 所有字段由命令行参数或 Web 前端传入后统一填充
type Config struct {
	Targets                    []string
	Ports                      string
	NoSubdomainBruteForce      bool
	Subdomain                  bool
	SubdomainBruteForceThreads int
	SkipHostDiscovery          bool
	PortScanType               string
	GetBannerThreads           int
	GetBannerTimeout           int
	TCPPortScanThreads         int
	SYNPortScanThreads         int
	PortsThreshold             int
	TCPPortScanTimeout         int
	MasscanPath                string
	AllowLocalAreaDomain       bool
	AllowCDNAssets             bool
	NoHostBind                 bool
	SubdomainWordListFile      string
	HTTPProxy                  string
	HTTPProxyTest              bool
	HTTPProxyTestURL           string
	Hunter                     bool
	HunterPageSize             int
	HunterMaxPageCount         int
	Fofa                       bool
	FofaMaxCount               int
	NoDirSearch                bool
	DirSearchYaml              string
	DisableGeneralPoc          bool
	NucleiTemplate             string
	ExcludeTags                string
	Severities                 string
	ReportName                 string
	WebThreads                 int
	WebTimeout                 int
	PocNameForSearch           string
	NoPoc                      bool
	LowPerceptionMode          bool
	Quake                      bool
	QuakeSize                  int
	NoICMPPing                 bool
	TCPPing                    bool
	NoInteractsh               bool
	OnlyIPPort                 bool
	OutputFile                 string
	OutputType                 string
	APIConfigFilePath          string
	FingerConfigFilePath       string
	PasswordFile               string
	Password                   string
	InteractshURL              string
	InteractshToken            string
	NoPortString               string
}

// CDNResult CDN 检测结果
// 记录单个域名的 CDN 检测结论
type CDNResult struct {
	Domain  string   // 被检测的域名
	IsCDN   bool     // 是否为 CDN 域名
	CDNName string   // CDN 服务商名称（非 CDN 时为空）
	IPs     []net.IP // 域名解析到的 IP 列表
}

var GlobalConfig Config

// 已移除内置 POCs 的嵌入式 FS，改为外置 config/POC 目录

var GlobalBannerHMap *hybrid.HybridMap

// GlobalIPPortMap IP:Port : Protocol
// Deprecated: 新任务流程使用 TaskInstanceState.IPPortMap。
var GlobalIPPortMap map[string]string
var GlobalIPPortMapLock sync.Mutex

// PortEntity 端口实体信息
// 记录了某个 IP:Port 上的协议和 Banner 指纹哈希
type PortEntity struct {
	Protocol   string // 协议名称（如 http、ssh、mysql）
	BannerHash string // 响应 Banner 的哈希值（用于去重比较）
}

// ProtocolResult 协议探测结果
// 记录端口扫描后对该端口进行协议探测的详细结果
type ProtocolResult struct {
	IP       string           // 目标 IP 地址
	Port     int              // 目标端口号
	Status   int              // 探测状态（0=失败, 1=成功）
	Response *gonmap.Response // gonmap 库的协议响应对象
}

// GlobalIPDomainMap 存储ip->domains的关系
var GlobalIPDomainMap map[string][]string
var GlobalIPDomainMapLock sync.Mutex

// UrlPathEntity URL 路径实体信息
// 记录了某个 URL 路径（如 "/"）的 HTTP 响应特征，用于指纹匹配
type UrlPathEntity struct {
	// Path             string // 路径，根目录为 "/"（注释掉，使用 URLEntity 的 key 表示）
	Hash             string // 响应体 MD5 哈希（用于快速去重）
	IconHash         string // favicon 的 mmh3 哈希（用于 favicon 指纹匹配）
	Title            string // HTML <title> 标签内容
	FinalURL         string // 最终跳转后的 URL
	StatusCode       int    // HTTP 状态码（如 200, 404）
	ContentType      string // Content-Type 头字段值
	Server           string // Server 头字段值（如 Apache/2.4.41）
	ContentLength    int    // Content-Length 头字段值
	HeaderHashString string // 响应头的哈希字符串（用于指纹匹配）
	ScreenshotPath   string // 截图文件路径
}

// URLEntity 表示一个 RootURL 的基础信息与路径详情（含证书信息）
type URLEntity struct {
	IP       string
	Port     int
	WebPaths map[string]UrlPathEntity
	Cert     string // TLS证书
}

// GlobalURLMap RootURL:URLEntity
// Deprecated: 新任务流程使用 TaskInstanceState.URLMap。
var GlobalURLMap map[string]URLEntity
var GlobalURLMapLock sync.Mutex

// TaskURLMaps 任务专属的 URLMap，key为taskID，value为该任务的URLMap
// Deprecated: 新任务流程使用 TaskInstanceState.URLMap。
var TaskURLMaps map[string]map[string]URLEntity
var TaskURLMapsLock sync.Mutex

var GlobalHttpBodyHMap *hybrid.HybridMap
var GlobalHttpHeaderHMap *hybrid.HybridMap

// TaskTypeState 任务类型级别的状态容器（第一级隔离）
// 按任务类型（web/port）进行隔离的同类型任务共享状态。
// - Web 扫描类型：使用 URLMap（URL 到实体映射）和 ResultMap（指纹结果映射）
// - 端口扫描类型：使用 IPPortMap（IP:Port 到 Protocol 的映射）
// 每个任务类型独立管理，避免 web 扫描与 port 扫描的状态交叉污染
type TaskTypeState struct {
	// Web扫描相关状态
	URLMap      map[string]URLEntity // RootURL:URLEntity
	ResultMap   map[string][]string  // URL:指纹列表
	URLMapsLock sync.Mutex

	// 端口扫描相关状态
	IPPortMap     map[string]string // IP:Port : Protocol
	IPPortMapLock sync.Mutex
}

// TaskTypeStates 任务类型状态映射，key为任务类型（web/port）
var TaskTypeStates = make(map[string]*TaskTypeState)
var TaskTypeStatesLock sync.RWMutex

// TaskInstanceState 保存单个任务的扫描运行态。
// URL、端口、指纹结果和响应缓存都归属于 taskID，避免并发任务串写。
// 任务完成后可通过 DeleteTaskInstanceState 清理其状态数据。
type TaskInstanceState struct {
	TaskID         string
	TaskType       string
	URLMap         map[string]URLEntity // 任务实例专属的 URLMap
	ResultMap      map[string][]string  // 任务实例专属的指纹结果
	IPPortMap      map[string]string    // 任务实例专属的 IP:Port 映射
	HTTPBodyHMap   *hybrid.HybridMap    // 任务实例专属的 HTTP body 缓存
	HTTPHeaderHMap *hybrid.HybridMap    // 任务实例专属的 HTTP header 缓存
	BannerHMap     *hybrid.HybridMap    // 任务实例专属的端口 banner 缓存
}

// FingerprintState 是指纹识别阶段需要的最小任务状态视图。
type FingerprintState struct {
	URLMap         map[string]URLEntity
	ResultMap      map[string][]string
	IPPortMap      map[string]string
	HTTPBodyHMap   *hybrid.HybridMap
	HTTPHeaderHMap *hybrid.HybridMap
	BannerHMap     *hybrid.HybridMap
}

// TaskInstanceStates 任务实例状态映射，key为taskID
var TaskInstanceStates = make(map[string]*TaskInstanceState)
var TaskInstanceStatesLock sync.RWMutex

// RuleData 指纹匹配规则数据
// 表示一条指纹规则中的单个匹配条件
// 操作符说明：0=包含(~=), 1=不等于(!=), 2=等于(==), 3=大于等于(>=), 4=小于等于(<=), 5=正则匹配(~=)
type RuleData struct {
	Start int    // 规则在原始字符串中的起始位置
	End   int    // 规则在原始字符串中的结束位置
	Op    int16  // 匹配操作符：0=包含, 1=不等于, 2=等于, 3=大于等于, 4=小于等于, 5=正则匹配
	Key   string // 匹配目标字段名（如 body="123" 中的 body）
	Value string // 匹配值（如 body="123" 中的 123）
	All   string // 原始规则字符串（如 body="123"）
}

// WorkFlowEntity 工作流实体
// 定义了扫描工作流中不同类型（根路径/目录路径/基础路径）与对应的 POC 列表
type WorkFlowEntity struct {
	RootType bool     // 是否为根路径类型
	DirType  bool     // 是否为目录路径类型
	BaseType bool     // 是否为基础路径类型
	PocsName []string // 该工作流适用的 POC 名称列表
}

// PasswordDatabaseEntity 密码字典实体
// 用于暴力破解场景中的用户名/密码/提示组合
type PasswordDatabaseEntity struct {
	Keys      []string // 匹配关键字（用于规则匹配）
	Passwords []string // 密码列表
	Hints     []string // 密码提示信息
}

// FingerPEntity 指纹产品实体
// 表示一个已知产品的指纹规则，包含匹配规则和展示信息
type FingerPEntity struct {
	ProductName      string     // 产品名称（如 Apache、Nginx、Spring Boot）
	AllString        string     // 原始指纹规则文本
	Rule             []RuleData // 解析后的匹配规则列表
	IsExposureDetect bool       // 是否为暴露检测（用于检测敏感信息泄露）
}

var FingerprintDB []FingerPEntity
var DirDB map[string][]string

// GlobalResultMap 存储识别到的指纹
// Deprecated: 新任务流程使用 TaskInstanceState.ResultMap。
var GlobalResultMap map[string][]string
var GlobalResultMapLock sync.Mutex

// FingerBlacklist 指纹黑名单（框架/组件），这些指纹将被跳过，不进行 POC 匹配
var FingerBlacklist map[string]struct{}

// UserPasswd 用户名密码对
// 用于暴力破解或弱口令检测
type UserPasswd struct {
	UserName string // 用户名
	Password string // 密码
}

// HostInfo 主机信息汇总
// 汇总单个主机的所有扫描结果（端口、URL、识别信息、口令等）
type HostInfo struct {
	Host     string   // 主机标识（IP 或域名）
	Ports    string   // 开放端口列表（逗号分隔或范围格式）
	Url      string   // Web 服务 URL
	InfoStr  []string // 识别信息列表（指纹、标题等）
	UserPass []string // 发现的口令列表
}

var AddScanNum int
var AddScanEnd int

// GetOrCreateTaskTypeState 获取或创建任务类型级别的状态容器
// 参数：taskType - 任务类型（"web" 或 "port"）
// 返回值：对应类型的 TaskTypeState 指针，不存在则自动创建
// 使用写锁保护，线程安全
func GetOrCreateTaskTypeState(taskType string) *TaskTypeState {
	TaskTypeStatesLock.Lock()
	defer TaskTypeStatesLock.Unlock()

	if state, exists := TaskTypeStates[taskType]; exists {
		return state
	}

	// 创建新任务类型状态
	state := &TaskTypeState{
		URLMap:    make(map[string]URLEntity),
		ResultMap: make(map[string][]string),
		IPPortMap: make(map[string]string),
	}
	TaskTypeStates[taskType] = state
	return state
}

// GetOrCreateTaskInstanceState 获取或创建任务实例级别的状态容器
// 参数：
//   - taskID: 任务唯一标识
//   - taskType: 任务类型（"web" 或 "port"）
//
// 返回值：对应任务实例的 TaskInstanceState 指针，不存在则自动创建
// 使用写锁保护，线程安全
func GetOrCreateTaskInstanceState(taskID, taskType string) *TaskInstanceState {
	TaskInstanceStatesLock.Lock()
	defer TaskInstanceStatesLock.Unlock()

	if state, exists := TaskInstanceStates[taskID]; exists {
		return state
	}

	state := &TaskInstanceState{
		TaskID:         taskID,
		TaskType:       taskType,
		URLMap:         make(map[string]URLEntity),
		ResultMap:      make(map[string][]string),
		IPPortMap:      make(map[string]string),
		HTTPBodyHMap:   newHybridMap(),
		HTTPHeaderHMap: newHybridMap(),
		BannerHMap:     newHybridMap(),
	}
	TaskInstanceStates[taskID] = state
	return state
}

// FingerprintState 返回指纹识别所需的任务级状态视图。
func (s *TaskInstanceState) FingerprintState() *FingerprintState {
	if s == nil {
		return nil
	}
	s.EnsureCaches()
	return &FingerprintState{
		URLMap:         s.URLMap,
		ResultMap:      s.ResultMap,
		IPPortMap:      s.IPPortMap,
		HTTPBodyHMap:   s.HTTPBodyHMap,
		HTTPHeaderHMap: s.HTTPHeaderHMap,
		BannerHMap:     s.BannerHMap,
	}
}

// EnsureCaches 补齐任务缓存，兼容旧代码创建的半初始化状态。
func (s *TaskInstanceState) EnsureCaches() {
	if s == nil {
		return
	}
	if s.URLMap == nil {
		s.URLMap = make(map[string]URLEntity)
	}
	if s.ResultMap == nil {
		s.ResultMap = make(map[string][]string)
	}
	if s.IPPortMap == nil {
		s.IPPortMap = make(map[string]string)
	}
	if s.HTTPBodyHMap == nil {
		s.HTTPBodyHMap = newHybridMap()
	}
	if s.HTTPHeaderHMap == nil {
		s.HTTPHeaderHMap = newHybridMap()
	}
	if s.BannerHMap == nil {
		s.BannerHMap = newHybridMap()
	}
}

func newHybridMap() *hybrid.HybridMap {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil
	}
	return hm
}

// DeleteTaskInstanceState 删除指定任务实例的状态数据
// 参数：taskID - 要清理的任务标识
// 用于任务完成后的资源释放，防止内存泄漏
func DeleteTaskInstanceState(taskID string) {
	TaskInstanceStatesLock.Lock()
	defer TaskInstanceStatesLock.Unlock()
	delete(TaskInstanceStates, taskID)
}
