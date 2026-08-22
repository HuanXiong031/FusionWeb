// ========================================
// callnuclei/internal.go — Nuclei 扫描引擎核心实现
//
// 功能概述：
//
//	本文件是 FusionWeb 集成 Nuclei 漏洞扫描引擎的核心实现，
//	负责扫描参数的配置、Runner 创建、扫描执行、结果收集和任务管理。
//	采用进程内嵌入方式（非命令行调用），通过 Nuclei 的 exportrunner API
//	直接调用扫描引擎。
//
// 核心架构：
//  1. 全局初始化（sync.Once 确保一次）：exportrunner.ExportRunnerConfigureOptions()
//  2. 扫描参数配置：根据目标数量和系统资源动态优化并发参数
//  3. 模板目录解析：支持多目录、精确文件、回退路径
//  4. Runner 创建与执行：调用 exportrunner.ExportRunnerNew + RunEnumeration
//  5. 结果收集：通过 callbackOutputWriter 拦截 Nuclei 输出，实现回调隔离
//  6. 任务管理：支持任务停止、去重、多任务隔离
//
// 关键设计决策：
//   - 使用 callbackOutputWriter 包装原始 output.Writer，拦截 Write/Request 调用
//   - 通过反射（unsafe）访问和修改 Runner 的私有 output 字段
//   - 通过 TaskID + TaskTargets 实现多任务回调隔离
//   - 动态并发调整：根据系统 CPU/内存和目标数量自动优化扫描参数
//
// 集成关系：
//   - 输入：NucleiParams（从 HTTP 模块的 GetPocs 生成）
//   - 输出：[]output.ResultEvent（漏洞扫描结果列表）
//   - 回调：CallBack（每个漏洞结果）、OnRequest（每次请求进度）
//   - 日志：通过 logger 模块输出到系统日志和前端
//
// ========================================
package callnuclei

import (
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	apputils "FusionWeb/backend/utils"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/exportrunner"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/rs/xid"
)

// ========================================
// 常量定义
// ========================================

const (
	// --- 超时时间配置 ---

	// defaultTimeout 默认连接超时（秒）
	// Nuclei 内部 HTTP 超时 = 连接超时 × httpTimeoutMultiplier = 300秒（5分钟）
	defaultTimeout = 100
	// minTimeoutForSQLInjection 延时 SQL 注入检测所需的最小超时时间
	// 延时注入需要更长的等待时间来触发时序差异
	minTimeoutForSQLInjection = 100
	// httpTimeoutMultiplier HTTP 超时 = 连接超时 × 此倍数
	httpTimeoutMultiplier = 3

	// --- 响应大小限制 ---

	// maxResponseSizeForLog 日志中记录的最大响应大小（字节）
	// 超过此大小的响应将被截断，避免日志文件过大
	maxResponseSizeForLog = 5000
	// defaultResponseSaveSize 默认响应保存大小（10MB）
	// 调试模式下保存请求/响应到文件的最大大小
	defaultResponseSaveSize = 10 * 1024 * 1024

	// --- 交互平台（Interactsh）配置 ---

	// defaultInteractionsCacheSize 交互结果缓存大小
	// 用于 OOB 漏洞检测（盲 SSRF、盲 XXE 等）的回调结果缓存
	defaultInteractionsCacheSize = 5000
	// defaultInteractionsPollDuration 交互平台轮询间隔（秒）
	defaultInteractionsPollDuration = 5
	// defaultInteractionsCoolDownPeriod 交互平台冷却时间（秒）
	defaultInteractionsCoolDownPeriod = 5
	// defaultInteractionsEviction 交互结果过期时间（秒）
	defaultInteractionsEviction = 60

	// --- 批量扫描配置阈值 ---

	// largeTargetThreshold 大批量目标阈值
	// 目标数 >= 60 时使用高并发配置
	largeTargetThreshold = 60
	// mediumTargetThreshold 中批量目标阈值
	// 目标数 >= 20 时使用标准并发配置
	mediumTargetThreshold = 20
	// veryLargeTargetThreshold 超大批量目标阈值
	// 目标数 >= 500 时使用最大并发配置（适用于大规模资产扫描）
	veryLargeTargetThreshold = 500
)

// ========================================
// 全局变量
// ========================================

// initOnce 确保 Nuclei 全局配置只初始化一次的 sync.Once
// 使用 ExportRunnerConfigureOptions 进行初始化，避免多次调用导致状态异常
var initOnce sync.Once

// initError 存储全局初始化时的错误信息
var initError error

// RunningRunners 存储正在运行的 Nuclei Runner 实例
// Key: TaskID（字符串），Value: Nuclei Runner 接口
// 用于任务停止时找到对应的 Runner 并调用 Close()
var RunningRunners sync.Map

// StoppedTasks 存储已停止的任务 ID 集合
// Key: TaskID（字符串），Value: true
// callbackOutputWriter.Request() 中检查此集合，若任务已停止则触发 panic 中断扫描
var StoppedTasks sync.Map

// NucleiSystemResources 系统资源信息结构体
// 用于动态调整 Nuclei 扫描的并发参数，根据当前系统负载优化性能
//
// 字段：
//   - CPUCores: CPU 逻辑核心数
//   - TotalMemoryGB: Go 运行时从 OS 获取的总内存（GB）
//   - AvailableMemoryGB: 可用内存（GB）= TotalMemory - 已分配内存
//   - MemoryUsagePercent: 内存使用百分比
type NucleiSystemResources struct {
	CPUCores           int
	TotalMemoryGB      float64
	AvailableMemoryGB  float64
	MemoryUsagePercent float64
}

// 系统资源缓存变量
// 每次扫描前都读取系统资源会带来性能开销，因此使用带过期时间的缓存机制
var (
	nucleiSystemResourcesCache     *NucleiSystemResources // 缓存的系统资源信息
	nucleiSystemResourcesCacheLock sync.Mutex             // 缓存读写锁
	nucleiSystemResourcesCacheTime time.Time              // 缓存写入时间
	nucleiCacheExpiry              = 30 * time.Second     // 缓存有效期：30秒
)

type gologgerWriter interface {
	Write([]byte, levels.Level)
}

type discardGologgerWriter struct{}

func (discardGologgerWriter) Write(_ []byte, _ levels.Level) {}

func newNucleiTaskLogger(param NucleiParams) *gologger.Logger {
	taskLogger := &gologger.Logger{}
	taskLogger.SetFormatter(logger.NewPlainFormatter())
	taskLogger.SetMaxLevel(levels.LevelInfo)

	if param.EnableDebug && !param.LogPackets {
		taskLogger.SetWriter(discardGologgerWriter{})
		taskLogger.SetMaxLevel(levels.LevelDebug)
		return taskLogger
	}

	switch w := param.LogWriter.(type) {
	case gologgerWriter:
		taskLogger.SetWriter(w)
	case io.Writer:
		taskLogger.SetWriter(logger.NewGologgerWriter(w))
	default:
		if logger.GologWriter != nil {
			taskLogger.SetWriter(logger.GologWriter)
		}
	}

	if param.EnableDebug {
		taskLogger.SetMaxLevel(levels.LevelDebug)
	}
	return taskLogger
}

// getNucleiSystemResources 获取系统资源信息（带缓存）
//
// 功能说明：
//
//	获取当前系统的 CPU 核心数和内存使用情况。
//	带 30 秒缓存，避免频繁调用 runtime.ReadMemStats 带来的性能开销。
//
// 返回值：
//   - NucleiSystemResources: 包含 CPU 核心数、总内存、可用内存、内存使用率
//
// 使用场景：
//   - 保留给后续资源展示或监控使用
func getNucleiSystemResources() NucleiSystemResources {
	nucleiSystemResourcesCacheLock.Lock()
	defer nucleiSystemResourcesCacheLock.Unlock()

	// 如果缓存有效，直接返回
	if nucleiSystemResourcesCache != nil && time.Since(nucleiSystemResourcesCacheTime) < nucleiCacheExpiry {
		return *nucleiSystemResourcesCache
	}

	// 获取CPU核心数
	cpuCores := runtime.NumCPU()

	// 获取内存信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 转换为GB
	totalMemoryBytes := m.Sys
	allocMemoryBytes := m.Alloc
	availableMemoryBytes := totalMemoryBytes - allocMemoryBytes

	totalMemoryGB := float64(totalMemoryBytes) / (1024 * 1024 * 1024)
	availableMemoryGB := float64(availableMemoryBytes) / (1024 * 1024 * 1024)

	// 计算内存使用率
	var memoryUsagePercent float64
	if totalMemoryBytes > 0 {
		memoryUsagePercent = float64(allocMemoryBytes) * 100.0 / float64(totalMemoryBytes)
	}

	resources := NucleiSystemResources{
		CPUCores:           cpuCores,
		TotalMemoryGB:      totalMemoryGB,
		AvailableMemoryGB:  availableMemoryGB,
		MemoryUsagePercent: memoryUsagePercent,
	}

	// 更新缓存
	nucleiSystemResourcesCache = &resources
	nucleiSystemResourcesCacheTime = time.Now()

	return resources
}

// CallNucleiInternal 使用引入的 Nuclei 源码库执行进程内扫描
//
// 功能说明：
//
//	这是 FusionWeb 平台调用 Nuclei 漏洞扫描引擎的入口函数。
//	通过 Nuclei 的 exportrunner API 在进程内直接执行扫描（而非命令行调用），
//	支持回调机制进行结果实时通知和进度跟踪。
//
// 核心流程：
//  1. 设置 panic 恢复和任务清理（defer）
//  2. 创建任务专属的结果列表和去重集合（支持多任务隔离）
//  3. 包装回调函数 wrapperCallback：去重 + 格式化输出 + 收集结果
//  4. 解析和验证模板目录路径（多级回退：用户指定 → data/pocs → 运行数据目录）
//  5. 过滤模板子目录，确保只扫描本地模板
//  6. 精确模式检测：若指定了具体 POC 文件名，构建精确模板文件列表
//  7. 全局配置初始化（sync.Once 保证一次）：ExportRunnerConfigureOptions
//  8. 配置扫描选项：模板、代理、超时、交互平台、严重等级过滤等
//  9. 保留并发配置扩展点（当前不调整并发参数）
//  10. 创建 Nuclei Runner 实例（ExportRunnerNew）
//  11. 通过反射注入 callbackOutputWriter 拦截输出
//  12. 执行扫描（RunEnumeration），带 panic 恢复
//  13. 收集并返回所有扫描结果
//
// 参数：
//   - param: NucleiParams 扫描参数结构体（包含目标、POC、代理、回调等全部配置）
//
// 返回值：
//   - []output.ResultEvent: 扫描发现的所有漏洞结果列表
//     每个 ResultEvent 包含：模板信息、匹配内容、请求/响应、严重等级等
//
// 任务隔离机制：
//   - 通过 TaskID 实现多任务回调隔离
//   - 通过 buildTaskTargets 构建任务专属目标集合
//   - 通过 checkResultBelongsToTask 验证结果归属
//   - 使用 sync.Map 存储运行中的 Runner 和已停止任务
//
// 注意事项：
//   - 此函数会阻塞直到扫描完成
//   - 失败的扫描返回空结果列表
//   - 通过 defer 保证任务清理（删除停止标记、恢复日志输出）
func CallNucleiInternal(param NucleiParams) []output.ResultEvent {
	taskLogger := newNucleiTaskLogger(param)

	defer func() {
		if r := recover(); r != nil {
			logger.Error("CallNucleiInternal 捕获到 panic: %v", r)
		}
		if param.TaskID != "" {
			StoppedTasks.Delete(param.TaskID)
		}
	}()

	// 任务专属结果列表，用于收集回调结果
	var taskResults []output.ResultEvent
	var taskResultsLock sync.Mutex

	// 使用组合键（templateID|target）去重。
	seen := make(map[string]struct{})
	var seenLock sync.Mutex

	// 包装回调函数，同时收集到任务专属列表
	// 捕获任务ID和目标列表，用于回调隔离
	taskID := param.TaskID
	// 构建当前任务的目标URL集合（用于快速检查）
	taskTargets := buildTaskTargets(param.TargetAndPocsName)

	wrappedCallback := func(event output.ResultEvent) {
		// 检查结果是否属于当前任务
		// 由于 resultCallbacks 是全局共享的，需要确保只有属于当前任务的结果才被处理
		// 通过检查 target 是否属于当前任务的目标列表来实现任务隔离
		tgt := event.Matched
		if !checkResultBelongsToTask(tgt, taskID, taskTargets, param.TargetAndPocsName) {
			// 不属于当前任务的结果，直接跳过
			return
		}

		tid := event.TemplateID

		// 使用组合键进行去重，确保在并发情况下也能正确去重
		// 先检查是否已处理过，如果已处理则直接返回（不输出日志，避免日志噪音）
		seenLock.Lock()
		key := fmt.Sprintf("%s|%s", tid, tgt)
		if _, ex := seen[key]; ex {
			seenLock.Unlock()
			// 跳过重复结果，不输出日志
			return
		}
		// 标记为已处理（使用组合键）
		seen[key] = struct{}{}
		seenLock.Unlock()

		// 采用 dddd 的日志格式，显示 `[TemplateID(:MatcherName)] [Severity] URL`
		// 控制台仅显示 TemplateID:MatcherName（若有），不再显示模板名称
		tpl := tid
		if event.MatcherName != "" {
			tpl = tpl + ":" + event.MatcherName
		}
		show := fmt.Sprintf("[%s] [%s] %v", tpl,
			event.Info.SeverityHolder.Severity.String(),
			tgt)
		logger.Info("%s", show)

		// 只有在确认是唯一结果后才添加到结果列表
		taskResultsLock.Lock()
		taskResults = append(taskResults, event)
		taskResultsLock.Unlock()

		if param.CallBack != nil {
			param.CallBack(event)
		}
	}

	// 注意：output.RegisterCallback 和 UnregisterCallback 不存在
	// 回调功能将通过自定义 Writer 实现

	// 1) 规范化模板扫描根 NP，并计算模板根目录（NP 的父目录）
	np := normalizePath(param.NP)

	if !pathExists(np) {
		fallback := filepath.Join(apputils.GetDataDir(), "pocs")
		if pathExists(fallback) {
			np = fallback
		} else {
			logger.Error("未找到 Nuclei 模板目录: %s", normalizePath(param.NP))
			logger.Error("数据目录回退路径不存在: %s", fallback)
			return []output.ResultEvent{}
		}
	}
	// 2) 配置全局模板目录与禁用更新检查（限制在 NP 目录下）
	config.DefaultConfig.SetTemplatesDir(np)
	config.DefaultConfig.DisableUpdateCheck()

	// 3) 过滤模板目录，仅允许 NP 下的子目录，保证只扫描本地模板
	var templates []string
	if len(param.TemplateDirs) > 0 {
		for _, d := range param.TemplateDirs {
			dd := normalizePath(d)
			if pathExists(dd) {
				// 允许 NP 下的目录或同级子目录，也允许 data 目录下的其他目录（如 pocs_temp）
				rel, err := filepath.Rel(np, dd)
				if err == nil {
					// 允许 NP 下的目录
					if rel != ".." && !strings.HasPrefix(rel, "..") {
						templates = append(templates, dd)
					} else {
						// 检查是否是 data 目录下的同级目录（如 data/pocs_temp）
						dataDir := filepath.Dir(np) // 获取 data 目录
						relToConfig, err2 := filepath.Rel(dataDir, dd)
						if err2 == nil && relToConfig != ".." && !strings.HasPrefix(relToConfig, "..") {
							templates = append(templates, dd)
						}
					}
				}
			} else {
				// 如果路径不存在，尝试作为相对于 NP 的子目录
				relativePath := filepath.Join(np, d)
				if pathExists(relativePath) {
					templates = append(templates, relativePath)
				} else {
					logger.Debug("CallNucleiInternal 模板目录不存在: %s (尝试: %s)", dd, relativePath)
				}
			}
		}
		if len(templates) == 0 {
			// 回退到 NP
			templates = []string{np}
		}
	} else {
		templates = []string{np}
	}

	// 如果指定了具体的 POC 文件名，需要添加 Tags 过滤器，
	// 否则 Nuclei 会扫描目录下的所有模板，导致“选一个 POC 扫出多个漏洞”的问题。
	// 当我们传入模板目录给 Nuclei 时，它默认会扫描该目录下的所有模板。
	// 为了只扫描特定的 POC，我们需要利用 Nuclei 的 Tags 或 Templates 列表过滤功能。
	// 但由于 Nuclei Runner 的 Templates 字段只接受文件路径或目录路径，
	// 且我们为了支持按目录扫描（dddd 模式）传递了目录，
	// 所以如果想精确扫描，必须传递具体的文件路径给 opts.Templates，而不是目录。

	// 如果指定了具体的 POC，我们需要重新构建 opts.Templates，只包含这些文件
	finalTemplates := templates
	if hasSpecificPocs(param.TargetAndPocsName) {
		specificTemplates := []string{}
		pocFileSet := make(map[string]bool)
		for _, names := range param.TargetAndPocsName {
			for _, n := range names {
				pocFileSet[n] = true
			}
		}

		// 在之前的 templates 目录中查找具体的文件
		for pocName := range pocFileSet {
			if foundPath := findPocFile(pocName, templates); foundPath != "" {
				specificTemplates = append(specificTemplates, foundPath)
			}
		}
		if len(specificTemplates) > 0 {
			finalTemplates = specificTemplates
			logger.Debug("精确模式：已将扫描范围限制为 %d 个具体模板文件", len(finalTemplates))
		} else {
			logger.Warn("精确模式：未能找到任何指定的 POC 文件，回退到目录扫描")
		}
	}

	initOnce.Do(func() {
		initError = exportrunner.ExportRunnerConfigureOptions()
		if initError != nil {
			logger.Error("CallNucleiInternal 全局配置初始化失败: %v", initError)
		} else {
		}
	})
	if initError != nil {
		logger.Error("CallNucleiInternal 全局配置初始化失败，跳过扫描: %v", initError)
		return []output.ResultEvent{}
	}

	opts := types.DefaultOptions()
	opts.Logger = taskLogger

	if opts.ExecutionId == "" {
		opts.SetExecutionID(xid.New().String())
	}

	opts.Templates = finalTemplates

	opts.NoHostErrors = true

	if opts.InputFileMode == "" {
		opts.InputFileMode = "list"
	}

	if len(param.TargetAndPocsName) > 0 {
		targets := make([]string, 0, len(param.TargetAndPocsName))
		for t := range param.TargetAndPocsName {
			targets = append(targets, t)
		}
		opts.Targets = targets
		configureBulkScanOptions(opts, len(targets))
		opts.Timeout = 10
		opts.Retries = 2
	}
	// 禁用基于指纹/POC 名称的自动扫描工作流
	// FusionWeb 已经通过 buildPOCDirs 进行了指纹匹配和 POC 选择
	// 如果启用 AutomaticScan，Nuclei 会根据其内部的指纹识别结果过滤掉我们选择的 POC（如果 Nuclei 没识别出对应技术）
	opts.AutomaticScan = false
	// 可选的模糊搜索（单个关键字时用于按名称模糊匹配）
	// 注意：opts.PocNameForSearch 字段不存在，已移除
	if param.NameForSearch != "" {
		// 可以通过模板名称过滤来实现类似功能
		// 这里暂时跳过，因为该字段在 nuclei Options 中不存在
		logger.Debug("POC名称搜索参数已设置但暂不支持: %s", param.NameForSearch)
	}
	// 标签与严重等级过滤
	opts.ExcludeTags = param.ExcludeTags
	if len(param.Severities) > 0 {
		var sv severity.Severities
		if err := sv.Set(strings.Join(param.Severities, ",")); err == nil {
			opts.Severities = sv
		}
	}
	// 代理与交互平台配置
	if param.Proxy != "" {
		opts.Proxy = []string{param.Proxy}
		opts.ProxyInternal = false
		// 采用简化代理语义：不设置 httpx 的 HTTPProxy 字段
	}
	opts.NoInteractsh = param.NoInteractsh
	opts.InteractshURL = param.InteractshServer
	opts.InteractshToken = param.InteractshToken
	// 修复交互缓存大小默认值为0导致的 gcache panic
	// nuclei runner 会将 options.InteractionsCacheSize 传入 interactsh 客户端的 gcache.New(size)
	// 若为0则触发 "Cache size <= 0" panic
	if opts.InteractionsCacheSize <= 0 {
		opts.InteractionsCacheSize = defaultInteractionsCacheSize
	}
	// 修复 interactsh 轮询间隔为0导致的 NewTicker panic
	// 必须设置正数的轮询间隔，否则会触发 "non-positive interval for NewTicker" panic
	if opts.InteractionsPollDuration <= 0 {
		opts.InteractionsPollDuration = defaultInteractionsPollDuration
	}
	if opts.InteractionsCoolDownPeriod <= 0 {
		opts.InteractionsCoolDownPeriod = defaultInteractionsCoolDownPeriod
	}
	if opts.InteractionsEviction <= 0 {
		opts.InteractionsEviction = defaultInteractionsEviction
	}

	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	} else if opts.Timeout < minTimeoutForSQLInjection {

		opts.Timeout = minTimeoutForSQLInjection
	}

	opts.Output = ""
	opts.JSONL = false
	opts.Silent = false
	opts.NoColor = true
	opts.EnableProgressBar = false
	opts.OmitRawRequests = false

	// 解析其他选项（这可能会重置某些设置，因此Debug配置需在之后再次确认）
	exportrunner.ExportRunnerParseOptions(opts)
	opts.Logger = taskLogger

	// --- 重写：Nuclei Debug 模块配置 ---
	// 集中处理调试模式的开关逻辑，确保在 Runner 初始化前正确应用
	if param.EnableDebug {
		if param.LogPackets {
			logger.Debug("正在开启 Nuclei Debug 模式 (Force Enable)")
		}

		// 1. 强制开启 Nuclei 核心调试标志
		opts.Debug = true
		opts.DebugRequests = true  // 捕获请求包
		opts.DebugResponse = true  // 捕获响应包
		opts.Verbose = true        // 详细输出
		opts.VerboseVerbose = true // 更详细输出

		// 2. 确保不忽略原始请求
		opts.OmitRawRequests = false

		// 3. 不再把调试包落库，避免高并发下 SQLite 写锁竞争
		opts.StoreResponse = false
		if opts.ResponseSaveSize <= 0 || opts.ResponseSaveSize < defaultResponseSaveSize {
			opts.ResponseSaveSize = defaultResponseSaveSize
		}

		taskLogger.SetMaxLevel(levels.LevelDebug)
		taskLogger.SetFormatter(logger.NewPlainFormatter())
	} else {
		taskLogger.SetMaxLevel(levels.LevelInfo)
		taskLogger.SetFormatter(logger.NewPlainFormatter())
	}

	// 重要：在ExportRunnerParseOptions之后，可能需要重新设置Templates
	// 因为ParseOptions可能会重置某些选项
	if len(finalTemplates) > 0 {
		opts.Templates = finalTemplates
		if param.EnableDebug && param.LogPackets {
			logger.Debug("在ExportRunnerParseOptions后重新设置Templates: %v", finalTemplates)
		}
	}

	nucleiRunner, err := exportrunner.ExportRunnerNew(opts)
	if param.EnableDebug && param.LogPackets && err != nil {
		logger.Warn("创建Nuclei Runner时的错误信息: %v", err)
		logger.Warn("当前opts.Templates设置: %v (长度: %d)", opts.Templates, len(opts.Templates))
	}
	if err != nil || nucleiRunner == nil {
		logger.Error("CallNucleiInternal 创建 Nuclei Runner 失败: %v", err)
		return []output.ResultEvent{}
	}

	if param.TaskID != "" {
		RunningRunners.Store(param.TaskID, nucleiRunner)
		defer RunningRunners.Delete(param.TaskID)
	}

	if len(param.TargetAndPocsName) > 0 {
		if hasSpecificPocs(param.TargetAndPocsName) {

			totalPocs := 0
			foundPocs := 0
			foundList := []string{}

			for _, names := range param.TargetAndPocsName {
				totalPocs += len(names)
				for _, n := range names {
					if found := findPocFile(n, templates); found != "" {
						foundPocs++
						dir := filepath.Dir(found)
						foundList = append(foundList, fmt.Sprintf("%s -> %s", n, dir))
					}
				}
			}

		} else {

		}
	}

	originalWriter := getRunnerOutputWriter(nucleiRunner)
	if originalWriter == nil {
		logger.Warn("无法获取 Runner 的 output writer，回调功能可能无法正常工作")
	} else {
		callbackWriter := &callbackOutputWriter{
			writer:                 originalWriter,
			callback:               wrappedCallback,
			onRequest:              param.OnRequest,
			taskID:                 param.TaskID,
			suppressOriginalOutput: param.EnableDebug,
		}
		setRunnerOutputWriter(nucleiRunner, callbackWriter)
	}

	var runErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				errStr := fmt.Sprintf("%v", r)
				if strings.Contains(errStr, "任务已停止") {
					logger.Info("Nuclei 扫描已停止: %s", param.TaskID)
					return
				}
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				stackTrace := string(buf[:n])
				logger.Error("========== CallNucleiInternal RunEnumeration 发生 panic ==========")
				logger.Error("Panic 信息: %v", r)
				logger.Error("堆栈跟踪:")
				logger.Error("%s", stackTrace)
				logger.Error("==========================================")
				// 将 panic 转换为 error
				runErr = fmt.Errorf("panic: %v", r)
			}
		}()

		if nucleiRunner == nil {
			runErr = fmt.Errorf("nucleiRunner 为 nil，无法执行扫描")
			logger.Error("nucleiRunner 为 nil，无法执行扫描")
			return
		}

		if err := nucleiRunner.RunEnumeration(); err != nil {
			runErr = err
			logger.Error("Nuclei 扫描失败: %v", err)
		} else {

		}
	}()

	if runErr != nil {
		logger.Error("扫描执行出错: %v", runErr)
	}

	nucleiRunner.Close()

	taskResultsLock.Lock()
	finalResults := make([]output.ResultEvent, len(taskResults))
	copy(finalResults, taskResults)
	taskResultsLock.Unlock()

	return finalResults
}

// StopTask 停止指定任务的 Nuclei 扫描
//
// 功能说明：
//
//	通过 TaskID 停止正在运行的 Nuclei 扫描任务。实现方式：
//	1. 将 TaskID 标记为 StoppedTasks，使 callbackOutputWriter.Request() 检测到停止信号
//	2. 下次 Request() 回调时触发 panic，由 CallNucleiInternal 的 recover 捕获
//	3. 同时尝试直接调用 Runner 的 Close() 方法关闭扫描器
//
// 参数：
//   - taskID: 要停止的任务唯一标识符
//
// 注意事项：
//   - 停止是异步的，不会立即生效（需等到下次 Request 回调）
//   - Close() 使用反射调用，兼容不同版本的 Runner 接口
func StopTask(taskID string) {
	StoppedTasks.Store(taskID, true)
	if runner, ok := RunningRunners.Load(taskID); ok {
		logger.Info("停止任务: %s", taskID)
		if closer, ok := runner.(interface{ Close() }); ok {
			closer.Close()
		} else {
			rv := reflect.ValueOf(runner)
			method := rv.MethodByName("Close")
			if method.IsValid() {
				method.Call(nil)
			}
		}
	}
}

// callbackOutputWriter 输出写入器包装器
//
// 功能说明：
//
//	实现 output.Writer 接口，包装原始 Writer，在所有输出方法中注入自定义逻辑：
//	- Write(): 调用回调函数通知上层发现漏洞
//	- Request(): 检查任务停止标记 + 调用进度回调
//	- 其他方法透传给原始 Writer
//
// 设计目的：
//   - 无需修改 Nuclei 源码即可拦截所有输出事件
//   - 通过反射注入到 Runner 的私有 output 字段
//
// 字段：
//   - writer: 原始的 Nuclei output.Writer（通常为标准输出写入器）
//   - callback: 漏洞发现回调（每个 ResultEvent 调用一次）
//   - onRequest: 请求进度回调（每次 HTTP 请求调用一次）
//   - taskID: 关联的任务 ID（用于停止信号检测）
type callbackOutputWriter struct {
	writer                 output.Writer
	callback               func(output.ResultEvent)
	onRequest              func(templateID, url, requestType string, err error)
	taskID                 string
	suppressOriginalOutput bool
	resultCount            atomic.Int32
}

// 编译时接口检查：确保 callbackOutputWriter 实现了 output.Writer 接口
var _ output.Writer = &callbackOutputWriter{}

// Close 关闭输出写入器
func (w *callbackOutputWriter) Close() {
	if w.writer != nil {
		w.writer.Close()
	}
}

// Colorizer 返回颜色输出器（用于控制台彩色输出）
func (w *callbackOutputWriter) Colorizer() aurora.Aurora {
	if w.writer != nil {
		return w.writer.Colorizer()
	}
	return aurora.NewAurora(false)
}

// Write 处理漏洞扫描结果事件
//
// 核心逻辑：
//  1. 先调用自定义回调函数 callback（通知上层发现漏洞）
//  2. 再调用原始 writer.Write（保持原有输出链）
//
// 参数：
//   - event: Nuclei 扫描结果事件（包含模板信息、匹配内容、请求/响应等）
func (w *callbackOutputWriter) Write(event *output.ResultEvent) error {
	// 调用回调函数
	if w.callback != nil {
		w.callback(*event)
	}
	w.resultCount.Add(1)
	if w.suppressOriginalOutput {
		return nil
	}
	// 调用原始 writer
	if w.writer != nil {
		return w.writer.Write(event)
	}
	return nil
}

// WriteFailure 处理扫描失败事件
func (w *callbackOutputWriter) WriteFailure(event *output.InternalWrappedEvent) error {
	if w.writer != nil {
		return w.writer.WriteFailure(event)
	}
	return nil
}

// Request 处理 HTTP 请求发送事件
//
// 核心逻辑：
//  1. 检查任务是否已被标记为停止（StoppedTasks），若是则触发 panic 中断扫描
//  2. 调用 onRequest 回调通知上层请求进度
//  3. 调用原始 writer.Request 保持原有输出链
//
// 任务停止机制：
//   - 在每次发送 HTTP 请求前检查停止标记
//   - 触发 panic 后由 CallNucleiInternal 的 recover 捕获
//   - 这是安全优雅停止扫描的方式（避免在任意线程使用 os.Exit）
//
// 参数：
//   - templateID: 当前执行的模板 ID
//   - url: 请求目标 URL
//   - requestType: 请求类型（HTTP/DNS/TCP 等）
//   - err: 请求错误（如果有）
func (w *callbackOutputWriter) Request(templateID, url, requestType string, err error) {
	// 检查任务是否已停止
	if w.taskID != "" {
		if _, stopped := StoppedTasks.Load(w.taskID); stopped {
			// 触发 panic 来中断 RunEnumeration
			// CallNucleiInternal 中的 recover 会捕获它
			panic(fmt.Sprintf("任务已停止: %s", w.taskID))
		}
	}

	if w.onRequest != nil {
		w.onRequest(templateID, url, requestType, err)
	}
	if w.suppressOriginalOutput {
		return
	}
	if w.writer != nil {
		w.writer.Request(templateID, url, requestType, err)
	}
}

// RequestStatsLog 记录请求统计日志（响应状态码和内容）
func (w *callbackOutputWriter) RequestStatsLog(statusCode, response string) {
	if w.suppressOriginalOutput {
		return
	}
	if w.writer != nil {
		w.writer.RequestStatsLog(statusCode, response)
	}
}

// WriteStoreDebugData 写入调试数据（供调试模式使用）
func (w *callbackOutputWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	if err := database.InsertScanDebugPacket(w.taskID, host, templateID, eventType, data); err != nil {
		logger.Warn("保存扫描调试包失败: %v", err)
	}
}

// ResultCount 返回当前已发现的结果数量
func (w *callbackOutputWriter) ResultCount() int {
	if w.suppressOriginalOutput {
		return int(w.resultCount.Load())
	}
	if w.writer != nil {
		return w.writer.ResultCount()
	}
	return 0
}

// getRunnerOutputWriter 使用反射获取 Runner 的 output writer
//
// 功能说明：
//
//	通过反射（包括 unsafe 包访问私有字段）获取 Nuclei Runner 内部的
//	output.Writer 实例。这是注入 callbackOutputWriter 的前提步骤。
//
// 实现方式：
//  1. 使用 reflect.ValueOf 获取 Runner 的反射值
//  2. 通过 FieldByName("output") 定位私有字段
//  3. 使用 unsafe.Pointer 突破私有字段访问限制
//  4. 将反射值转换为 output.Writer 接口
//
// 参数：
//   - runner: Nuclei Runner 实例（任意类型，通过反射处理）
//
// 返回值：
//   - output.Writer: Runner 内部的输出写入器；若无法获取则返回 nil
//
// 注意事项：
//   - 依赖 Nuclei Runner 内部结构，版本升级可能需要调整
//   - 使用 unsafe 绕过 Go 的访问控制，需谨慎使用
func getRunnerOutputWriter(runner interface{}) output.Writer {
	if runner == nil {
		return nil
	}
	rv := reflect.ValueOf(runner)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	field := rv.FieldByName("output")
	if !field.IsValid() {
		return nil
	}

	// 使用 unsafe 访问私有字段
	ptr := unsafe.Pointer(field.UnsafeAddr())
	realValue := reflect.NewAt(field.Type(), ptr).Elem()

	if realValue.IsNil() {
		return nil
	}

	if writer, ok := realValue.Interface().(output.Writer); ok {
		return writer
	}
	return nil
}

// buildNucleiCommandLine 构建等效的 Nuclei 命令行字符串（用于日志/调试展示）
//
// 功能说明：
//
//	根据当前扫描配置生成一条等效的 nuclei CLI 命令字符串，
//	便于在日志中展示扫描配置，方便用户理解当前使用的参数。
//
// 参数：
//   - opts: Nuclei 选项配置
//   - param: FusionWeb 扫描参数
//
// 返回值：
//   - 等效的 Nuclei 命令行字符串
func buildNucleiCommandLine(opts *types.Options, param NucleiParams) string {
	var args []string

	// 目标参数 (-u 或 -l)
	if len(opts.Targets) > 0 {
		if len(opts.Targets) == 1 {
			args = append(args, "-u", opts.Targets[0])
		} else {
			args = append(args, "-l", fmt.Sprintf("<%d个目标>", len(opts.Targets)))
		}
	}

	if hasSpecificPocs(param.TargetAndPocsName) {
		pocFileSet := make(map[string]bool)
		for _, pocNames := range param.TargetAndPocsName {
			for _, pocName := range pocNames {
				pocFileSet[pocName] = true
			}
		}

		for pocName := range pocFileSet {
			if foundPath := findPocFile(pocName, opts.Templates); foundPath != "" {
				args = append(args, "-t", foundPath)
			}
		}
	} else if len(opts.Templates) > 0 {
		for _, template := range opts.Templates {
			args = append(args, "-t", template)
		}
	}

	if !opts.UpdateTemplates {
		args = append(args, "-disable-update-check")
	}

	return strings.Join(args, " ")
}

// setRunnerOutputWriter 使用反射设置 Runner 的 output writer
//
// 功能说明：
//
//	通过反射（包括 unsafe 包访问私有字段）将 callbackOutputWriter
//	注入到 Nuclei Runner 的私有 output 字段中，替换原有的 Writer。
//	这是实现回调拦截的核心机制。
//
// 参数：
//   - runner: Nuclei Runner 实例
//   - writer: 要注入的 callbackOutputWriter
//
// 注意事项：
//   - 与 getRunnerOutputWriter 配合使用：先获取，保存，注入新 writer
//   - 使用 unsafe 绕过私有字段限制
func setRunnerOutputWriter(runner interface{}, writer output.Writer) {
	if runner == nil {
		return
	}
	rv := reflect.ValueOf(runner)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	field := rv.FieldByName("output")
	if field.IsValid() {
		ptr := unsafe.Pointer(field.UnsafeAddr())
		realValue := reflect.NewAt(field.Type(), ptr).Elem()
		realValue.Set(reflect.ValueOf(writer))
	}
}

// hasSpecificPocs 判断是否存在具体的 POC 文件名（精确模式检测）
//
// 功能说明：
//
//	检查目标→POC 映射中是否包含具体的 POC 文件名。
//	若包含具体文件名，则使用精确模式（仅扫描指定文件）；
//	若值为空，则使用目录模式（扫描目录下所有模板）。
//
// 参数：
//   - targetAndPocsName: 目标到 POC 名称列表的映射
//
// 返回值：
//   - true: 至少有一个目标指定了具体的 POC 文件名
//   - false: 所有目标都未指定 POC（使用目录扫描模式）
func hasSpecificPocs(targetAndPocsName map[string][]string) bool {
	if len(targetAndPocsName) == 0 {
		return false
	}
	for _, names := range targetAndPocsName {
		if len(names) > 0 {
			return true
		}
	}
	return false
}

// configureBulkScanOptions 目前不再调整并发参数。
//
// 说明：
//   - 关闭目标数量分档
//   - 关闭 CPU / 内存限制
//   - 关闭最小值保护
//   - 完全交由 Nuclei 默认值或外部传入值控制
func configureBulkScanOptions(opts *types.Options, targetCount int) {
	_ = opts
	_ = targetCount
}

// findPocFile 在模板目录中查找指定的 POC 文件
//
// 功能说明：
//
//	在给定的模板目录列表中递归搜索匹配的 POC 文件。
//	支持多种文件名匹配方式：精确匹配、带 .yaml 后缀、带 .yml 后缀、
//	以及去除扩展名后的匹配。搜索大小写不敏感。
//
// 参数：
//   - pocName: POC 文件名（可带或不带扩展名，如 "cve-2021-44228" 或 "cve-2021-44228.yaml"）
//   - templateDirs: 要搜索的模板目录列表
//
// 返回值：
//   - 找到的 POC 文件完整路径；若未找到则返回空字符串
//
// 搜索策略：
//  1. 遍历每个 templateDir
//  2. 使用 filepath.WalkDir 递归遍历目录树
//  3. 对每个文件进行四种匹配尝试
//  4. 找到第一个匹配即返回（filepath.SkipDir 停止搜索）
func findPocFile(pocName string, templateDirs []string) string {
	for _, templateDir := range templateDirs {
		found := ""
		_ = filepath.WalkDir(templateDir, func(p string, de os.DirEntry, err error) error {
			if err != nil || de.IsDir() {
				return nil
			}
			file := filepath.Base(p)
			// 支持精确匹配和带扩展名匹配
			if strings.EqualFold(file, pocName) ||
				strings.EqualFold(file, pocName+".yaml") ||
				strings.EqualFold(file, pocName+".yml") ||
				strings.EqualFold(strings.TrimSuffix(strings.TrimSuffix(file, ".yaml"), ".yml"), pocName) {
				found = p
				return filepath.SkipDir
			}
			return nil
		})
		if found != "" {
			return found
		}
	}
	return ""
}

// buildTaskTargets 构建任务目标 URL 集合
//
// 功能说明：
//
//	从目标→POC 映射中提取所有目标的 baseURL（scheme://host:port），
//	构建一个快速查找集合，用于验证扫描结果是否属于当前任务。
//
// 参数：
//   - targetAndPocsName: 目标到 POC 名称列表的映射
//
// 返回值：
//   - map[string]bool: baseURL 集合（如 "https://example.com:443"），用于快速 O(1) 查找
//
// 使用场景：
//   - checkResultBelongsToTask 中用于快速验证结果归属
//   - 多任务并发时防止回调混淆
func buildTaskTargets(targetAndPocsName map[string][]string) map[string]bool {
	taskTargets := make(map[string]bool)
	for target := range targetAndPocsName {
		// 解析URL，提取基础URL（scheme://host:port）
		if u, err := url.Parse(target); err == nil {
			baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
			taskTargets[baseURL] = true
		} else {
			// 如果解析失败，直接使用原始target
			taskTargets[target] = true
		}
	}
	return taskTargets
}

// checkResultBelongsToTask 检查扫描结果是否属于当前任务
//
// 功能说明：
//
//	多任务并发执行时，全局共享的 resultCallbacks 可能收到属于其他任务的结果。
//	此函数通过 URL 前缀匹配验证结果是否属于当前任务，实现任务间的回调隔离。
//
// 匹配策略（两级）：
//  1. 直接前缀匹配：去除尾部斜杠后，检查 matchedURL 是否以任意任务目标为前缀
//  2. BaseURL 回退匹配：若直接匹配失败，提取 matchedURL 的 baseURL 进行二次检查
//
// 参数：
//   - matchedURL: Nuclei 匹配到的目标 URL
//   - taskID: 当前任务 ID（为空时默认处理所有结果，向后兼容）
//   - taskTargets: 当前任务的 baseURL 快速查找集合
//   - targetAndPocsName: 完整的任务目标→POC 映射
//
// 返回值：
//   - true: 结果属于当前任务，应被处理
//   - false: 结果不属于当前任务，应被丢弃
func checkResultBelongsToTask(matchedURL string, taskID string, taskTargets map[string]bool, targetAndPocsName map[string][]string) bool {
	if taskID == "" || len(taskTargets) == 0 {
		// 如果没有任务ID或目标列表，默认处理所有结果（向后兼容）
		return true
	}

	// 先尝试直接前缀匹配（最准确）
	for target := range targetAndPocsName {
		// 标准化URL：去除尾部斜杠进行比较
		normalizedTarget := strings.TrimSuffix(target, "/")
		normalizedTgt := strings.TrimSuffix(matchedURL, "/")
		if strings.HasPrefix(normalizedTgt, normalizedTarget) || strings.HasPrefix(matchedURL, target) {
			return true
		}
	}

	// 如果直接匹配失败，尝试使用baseURL匹配（兼容性检查）
	if u, err := url.Parse(matchedURL); err == nil {
		baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		if taskTargets[baseURL] {
			// baseURL匹配成功，再次尝试完整URL前缀匹配
			for target := range targetAndPocsName {
				normalizedTarget := strings.TrimSuffix(target, "/")
				if strings.HasPrefix(matchedURL, normalizedTarget) || strings.HasPrefix(matchedURL, target) {
					return true
				}
			}
		}
	}

	return false
}
