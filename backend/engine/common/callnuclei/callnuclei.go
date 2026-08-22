// ========================================
// 包 callnuclei: Nuclei 漏洞扫描引擎封装模块
//
// 功能概述：
//
//	将 ProjectDiscovery 的 Nuclei 漏洞扫描引擎嵌入 FusionWeb 平台，
//	提供进程内扫描、结果回调、任务管理和资源优化等功能。
//	本文件定义扫描参数结构和核心数据结构。
//
// 模块组成：
//   - callnuclei.go:   定义扫描参数结构 NucleiParams
//   - internal.go:    核心扫描逻辑（初始化、执行、结果收集、配置优化）
//   - utils.go:       路径规范化等工具函数
//
// 集成关系：
//   - 被 engine 层主流程调用，接收目标列表和 POC 列表
//   - 通过 Callback/OnRequest 回调向调用方报告结果和进度
//   - 使用 nuclei/v3 库进行进程内扫描（非命令行调用）
//
// ========================================
package callnuclei

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NucleiParams 扫描参数结构体，供 Nuclei 扫描模块使用
//
// 该结构体封装了 Nuclei 扫描的所有可配置参数，包括：
//   - 目标和 POC 映射
//   - 网络代理配置
//   - 回调函数（结果和进度）
//   - 模板目录和过滤条件
//   - 交互平台（Interactsh）配置
//   - 任务管理和调试选项
//
// 字段说明：
//
//	TargetAndPocsName: 目标 URL 到 POC 文件名的映射
//	  Key: 目标 URL（如 "https://example.com"）
//	  Value: 需要对该目标执行的 POC 文件名列表（如 ["cve-2021-44228.yaml"]）
//	  若值为空表示目录扫描模式（扫描目录下所有模板）
//
//	Proxy: HTTP/SOCKS 代理地址
//	  格式如 "http://127.0.0.1:8080" 或 "socks5://127.0.0.1:1080"
//	  空字符串表示不使用代理
//
//	CallBack: 扫描结果回调函数
//	  每个成功的漏洞发现都会调用此回调
//	  参数为 Nuclei 的标准 ResultEvent（包含模板信息、匹配内容、请求/响应等）
//
//	OnRequest: 请求发送回调函数
//	  在每次发送 HTTP 请求时调用，用于进度跟踪和状态报告
//	  参数: templateID(模板ID), url(请求URL), requestType(请求类型), err(错误信息)
//
//	NameForSearch: POC 名称模糊搜索关键字
//	  用于按名称模糊匹配模板（暂未完全支持，通过模板目录实现）
//
//	NoInteractsh: 是否禁用交互平台
//	  true: 禁用 OOB（Out-of-Band）漏洞检测（如盲 SSRF、盲 XXE）
//
//	NP: Nuclei 模板根目录路径（Nuclei POC 路径）
//	  程序会自动搜索 data/pocs、data/POC 等回退路径
//
//	TemplateDirs: 模板子目录列表
//	  允许按目录选择模板子集，互斥优先于 NameForSearch 和 NP 的全局扫描
//	  例如 ["cves", "exposures", "misconfiguration"]
//
//	ExcludeTags: 排除的模板标签
//	  例如 ["dos", "intrusive"]，将跳过带有这些标签的模板
//
//	Severities: 严重等级过滤
//	  只扫描指定等级的模板，如 ["critical", "high", "medium"]
//
//	InteractshServer: 自定义 Interactsh 服务器地址
//	  用于 OOB 漏洞检测的自托管交互服务器
//
//	InteractshToken: Interactsh 认证 Token
//	  用于自托管 Interactsh 服务器的身份认证
//
//	TaskID: 任务唯一标识符
//	  用于回调隔离（防止多任务间结果混淆）和任务停止控制
//
//	EnableDebug: 是否启用调试模式
//	  true: 开启详细日志、请求/响应捕获、冗余输出
//
//	LogWriter: 自定义日志输出接口
//	  用于将 Nuclei 的内部日志重定向到自定义的 io.Writer
type NucleiParams struct {
	TargetAndPocsName map[string][]string
	Proxy             string
	CallBack          func(result output.ResultEvent)
	// OnRequest 在每次发送请求时调用，用于进度跟踪
	OnRequest     func(templateID, url, requestType string, err error)
	NameForSearch string
	NoInteractsh  bool
	NP            string
	// TemplateDirs 允许按目录选择模板（与 NameForSearch、NP 互斥优先）
	TemplateDirs     []string
	ExcludeTags      []string
	Severities       []string
	InteractshServer string
	InteractshToken  string
	// TaskID 任务ID，用于回调隔离和多任务并发时的结果归属判断
	TaskID string
	// EnableDebug 是否启用调试模式（默认false，减少日志输出）
	EnableDebug bool
	// LogPackets 是否允许 Nuclei 调试日志输出请求/响应数据包到命令行
	LogPackets bool
	// LogWriter 自定义日志输出接口，用于捕获调试日志
	LogWriter interface{}
}
