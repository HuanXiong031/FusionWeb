package api

import (
	"FusionWeb/backend/logger"
	"FusionWeb/backend/scheduler"
	"FusionWeb/backend/service"
	"FusionWeb/backend/websocket"
	"context"
	"sync"
)

// App 是应用的核心结构体，包含所有业务服务实例和运行时状态。
// 它实现了 AppInterface 和 ExtendedAppInterface 两个接口，
// 作为 HTTP 处理层与业务服务层之间的桥梁。
// 所有后端业务逻辑通过 App 的方法对外暴露，方法内部委托给对应的 Service 或 Scheduler 处理。
type App struct {
	ctx                   context.Context
	scheduler             *scheduler.TaskScheduler
	wsHub                 *websocket.Hub
	pocFileService        *service.PocFileService
	fingerprintDBService  *service.FingerprintDBService
	blacklistService      *service.BlacklistService
	accessPolicyService   *service.AccessPolicyService
	dashboardService      *service.DashboardService
	pocTaskService        *service.PocTaskService
	pocScanResultService  *service.PocScanResultService
	vulnVerifyService     *service.VulnVerifyService
	toolsService          *service.ToolsService
	systemSettingsService *service.SystemSettingsService
	rtspService           *service.RTSPService
	scanDictionaryService *service.ScanDictionaryService
	spaceService          *service.SpaceService
	pocTaskCtxs           map[string]context.CancelFunc
	pocTaskCtxsMu         sync.Mutex
	initMu                sync.Mutex
	ready                 bool
}

// NewApp 创建 App 实例，初始化 POC 任务上下文映射表。
// 注意：创建后需调用 Init() 方法完成服务初始化。
func NewApp() *App {
	return &App{
		pocTaskCtxs: make(map[string]context.CancelFunc),
	}
}

// Init 初始化应用的所有业务服务和运行时组件。
// 初始化顺序：各业务 Service → WebSocket Hub（启动消息循环）→ TaskScheduler（创建 Worker 池）
func (a *App) Init(ctx context.Context) {
	a.initMu.Lock()
	defer a.initMu.Unlock()
	if a.ready {
		return
	}
	a.ctx = ctx

	// Initialize services
	a.pocFileService = service.NewPocFileService()
	a.fingerprintDBService = service.NewFingerprintDBService()
	a.blacklistService = service.NewBlacklistService()
	a.accessPolicyService = service.NewAccessPolicyService()
	a.dashboardService = service.NewDashboardService()
	a.pocTaskService = service.NewPocTaskService()
	a.pocScanResultService = service.NewPocScanResultService()
	a.vulnVerifyService = service.NewVulnVerifyService()
	a.toolsService = service.NewToolsService()
	a.systemSettingsService = service.NewSystemSettingsService()
	a.rtspService = service.NewRTSPService()
	a.scanDictionaryService = service.NewScanDictionaryService()
	a.spaceService = service.NewSpaceService()

	// Initialize WebSocket Hub
	// Use the process-wide hub that /ws clients connect to, otherwise task events
	// are broadcast to a private hub and the frontend only sees final HTTP data.
	a.wsHub = websocket.GetHub()

	// Initialize Task Scheduler
	// NewTaskScheduler 接收最大并发数。
	a.scheduler = scheduler.NewTaskScheduler(10) // 默认并发数 10
	// a.scheduler.Start() // TaskScheduler 自动启动，无需手动 Start

	a.ready = true
	logger.Info("Application initialized")
}

func (a *App) IsReady() bool {
	a.initMu.Lock()
	defer a.initMu.Unlock()
	return a.ready
}

// ==================== AppInterface 接口实现：任务管理与扫描 ====================

// StartScanTask 提交扫描任务到调度器（无用户关联，兼容旧接口）

// Ensure App implements interfaces
var _ AppInterface = (*App)(nil)
var _ ExtendedAppInterface = (*App)(nil)

// var _ BlacklistAppInterface = (*App)(nil)
