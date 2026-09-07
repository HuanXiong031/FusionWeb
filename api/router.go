// api/router.go
package api

import (
	"FusionWeb/backend/websocket"

	"github.com/gin-gonic/gin"
)

func NewRouter(app *App) *gin.Engine {
	gin.SetMode(gin.ReleaseMode) // 使用发布模式，不显示debug信息
	r := gin.New()
	r.Use(gin.Recovery()) // 只使用Recovery中间件，不使用Logger中间件

	// API速率限制中间件（必须在所有路由之前）
	r.Use(RateLimitMiddleware())

	// 添加 CORS 中间件（必须在所有路由之前）
	r.Use(corsMiddleware())

	// API 不处理 SPA Basic Auth；生产环境由 Nginx 保护前端入口。
	r.Use(BasicAuthMiddleware())

	// 将 App 实例注入到所有请求上下文
	r.Use(AppMiddleware(app))

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 访问黑名单控制：命中 access_blacklist 的来源不能访问后台、API 或 WebSocket。
	r.Use(accessPolicyMiddleware())

	// 审计日志：记录 API 访问日志和数据变更类操作日志。
	r.Use(auditLogMiddleware())

	// 公开路由（不需要认证）
	public := r.Group("/api")
	{
		public.GET("/public/app-config", HandleGetPublicAppConfig)
		public.POST("/auth/login", HandleLogin)
		public.POST("/auth/logout", HandleLogout)             // 退出登录（可选认证，如果有 token 则加入黑名单）
		public.GET("/auth/public-key", HandleGetSM2PublicKey) // 获取SM2公钥
	}

	// WebSocket 路由（不需要JWT认证，但可以在ServeWS中验证）
	r.GET("/ws", func(c *gin.Context) {
		hub := websocket.GetHub()
		websocket.ServeWS(hub, c.Writer, c.Request)
	})

	// 需要认证的路由
	v1 := r.Group("/api/v1")
	v1.Use(JWTAuthMiddleware)
	{
		// 用户管理
		users := v1.Group("/users")
		{
			users.POST("", HandleCreateUser)                                // 创建用户
			users.POST("/batch", HandleBatchCreateUsers)                    // 批量创建用户
			users.GET("", HandleGetUsers)                                   // 获取用户列表
			users.GET("/export", HandleExportUsers)                         // 导出用户列表为Excel
			users.GET("/import/template", HandleDownloadUserImportTemplate) // 下载用户批量导入Excel模板
			users.GET("/:id", HandleGetUser)                                // 获取用户详情
			users.PUT("/:id", HandleUpdateUser)                             // 更新用户
			users.DELETE("/:id", HandleDeleteUser)                          // 删除用户
			users.GET("/profile", HandleGetProfile)                         // 获取当前用户信息
			users.PUT("/profile", HandleUpdateProfile)                      // 更新当前用户信息
			users.PUT("/change-password", HandleChangePassword)             // 修改密码
			users.POST("/logout", HandleLogout)                             // 退出登录（需要认证）
		}
		// 任务管理
		tasks := v1.Group("/tasks")
		{
			tasks.POST("", ValidateTaskTargetLimit(), HandleCreateTask()) // 创建任务
			tasks.GET("", HandleGetTasks())                               // 获取任务列表
			tasks.GET("/stream", HandleTaskStream())                      // 任务列表 SSE 流
			tasks.GET("/:id", HandleGetTaskDetail())                      // 获取任务详情
			tasks.PUT("/:id/pause", HandlePauseTask())                    // 暂停任务
			tasks.PUT("/:id/resume", HandleResumeTask())                  // 恢复任务
			tasks.PUT("/:id/stop", HandleStopTask())                      // 停止任务
			tasks.DELETE("/:id", HandleDeleteTask())                      // 删除任务
			tasks.POST("/:id/restart", HandleRestartTask())               // 重启任务
			tasks.GET("/:id/progress", HandleGetTaskProgress())           // 获取任务进度
			tasks.GET("/:id/logs", HandleGetTaskLogs())                   // 获取任务日志
			tasks.GET("/:id/results", HandleGetTaskResults())             // 获取任务结果
		}

		// 扫描结果
		results := v1.Group("/results")
		{
			results.GET("/:taskId/recon", HandleGetReconResults())                         // 获取资产结果
			results.GET("/:taskId/recon/:resultId/screenshot", HandleGetReconScreenshot()) // 获取目标截图
			results.GET("/:taskId/vuln", HandleGetVulnResults())                           // 获取漏洞结果
			results.GET("/:taskId/fingerprint", HandleGetFingerprintResults())             // 获取指纹结果
			results.GET("/:taskId/subdomains", HandleGetSubdomainResults())                // 获取子域名扫描结果
			results.GET("/:taskId/weak-passwords", HandleGetWeakPasswordResults())         // 获取弱口令扫描结果
			results.GET("/:taskId/directories", HandleGetDirectoryResults())               // 获取目录扫描结果
			results.GET("/:taskId/js", HandleGetJSScanResults())                           // 获取 JS 扫描结果
		}

		// 报告导出
		reports := v1.Group("/reports")
		{
			reports.GET("/:taskId/html", HandleGenerateHTMLReport())
			reports.GET("/:taskId/excel", HandleGenerateExcelReport())
			reports.GET("/:taskId/markdown", HandleGenerateMDReport())
			reports.GET("/:taskId/download/:type", HandleDownloadReport()) // 文件下载路由
		}

		// POC 管理
		pocs := v1.Group("/pocs")
		{
			// 保留仍在使用中的路由
			pocs.DELETE("/all", HandleDeleteAllPOCs())                // 全部删除功能
			pocs.GET("/export/all", HandleExportAllPOCs())            // 导出全部功能
			pocs.POST("/export/selected", HandleExportSelectedPOCs()) // 导出选中功能
			pocs.POST("/validate", HandleValidatePOC())               // POC模板校验
			pocs.POST("/debug", HandleDebugScanPOC())                 // POC调试扫描（PocTemplateBuilder使用）
			pocs.POST("/debug/stop", HandleStopDebugScan())           // 停止调试扫描（PocTemplateBuilder使用）
		}

		// POC 文件管理
		pocFiles := v1.Group("/poc-files")
		{
			pocFiles.GET("", HandleGetPocFilesPage())
			pocFiles.GET("/all", HandleGetAllPocFiles())
			pocFiles.GET("/categories", HandleGetPocCategories())
			pocFiles.GET("/content", HandleGetPocFileContent())
			pocFiles.POST("/search", HandleSearchPocFiles())
			pocFiles.GET("/statistics", HandleGetPocFileStatistics())
			pocFiles.POST("", HandleCreatePocFile())
			pocFiles.PUT("", HandleUpdatePocFile())
			pocFiles.PATCH("/rename", HandleRenamePocFile())
			pocFiles.DELETE("", HandleDeletePocFile())
			pocFiles.POST("/import", HandleImportPocFile())
			pocFiles.POST("/import/log-failures", HandleLogImportFailures())
			pocFiles.POST("/import/log-success", HandleLogImportSuccess())
		}

		// 指纹管理
		fingerprints := v1.Group("/fingerprints")
		{
			fingerprints.GET("", HandleGetFingerprintsPage())
			fingerprints.GET("/all", HandleGetFingerprints())
			fingerprints.GET("/categories", HandleGetFingerprintCategories())
			fingerprints.POST("", HandleAddFingerprint())
			fingerprints.PUT("", HandleUpdateFingerprint())
			fingerprints.DELETE("/:name", HandleDeleteFingerprint())
			fingerprints.DELETE("/all", HandleDeleteAllFingerprints())
			fingerprints.POST("/search", HandleSearchFingerprints())
			fingerprints.POST("/import", HandleImportFingerprint())
			fingerprints.GET("/export", HandleExportFingerprints())
			fingerprints.GET("/export/single", HandleExportSingleFingerprint())
			fingerprints.GET("/statistics", HandleGetFingerprintStatistics())
			fingerprints.PUT("/:name/blacklist", HandleToggleFingerprintBlacklist())
			fingerprints.PUT("/:name/enabled", HandleToggleFingerprintEnabled())
		}

		// RTSP 扫描与字典管理
		rtsp := v1.Group("/rtsp")
		{
			rtsp.GET("/dictionaries", HandleGetRTSPDictionaries())
			rtsp.GET("/dictionaries/statistics", HandleGetRTSPDictionaryStatistics())
			rtsp.POST("/dictionaries", HandleSaveRTSPDictionary())
			rtsp.PUT("/dictionaries/:id", HandleUpdateRTSPDictionary())
			rtsp.DELETE("/dictionaries/:id", HandleDeleteRTSPDictionary())
			rtsp.DELETE("/dictionaries", HandleDeleteRTSPDictionaryByType())
			rtsp.POST("/dictionaries/import", HandleImportRTSPDictionary())
			rtsp.POST("/scan/start", HandleStartRTSPScan())
			rtsp.POST("/scan/:taskId/stop", HandleStopRTSPScan())
			rtsp.GET("/scan/:taskId/state", HandleGetRTSPScanState())
			rtsp.GET("/results", HandleGetRTSPResults())
			rtsp.DELETE("/results/:id", HandleDeleteRTSPResult())
		}

		// 通用扫描字典管理
		dictionaries := v1.Group("/dictionaries")
		{
			scanDictionaries := dictionaries.Group("/scan")
			{
				scanDictionaries.GET("", HandleGetScanDictionaries())
				scanDictionaries.GET("/statistics", HandleGetScanDictionaryStatistics())
				scanDictionaries.POST("", HandleSaveScanDictionary())
				scanDictionaries.PUT("/:id", HandleUpdateScanDictionary())
				scanDictionaries.DELETE("/:id", HandleDeleteScanDictionary())
				scanDictionaries.DELETE("", HandleDeleteScanDictionaryByType())
				scanDictionaries.POST("/import", HandleImportScanDictionary())
			}
		}

		// 空间测绘在线搜索与 API 密钥配置
		space := v1.Group("/space")
		{
			space.GET("/engines", HandleListSpaceEngineKeys())
			space.POST("/engines", HandleSaveSpaceEngineKey())
			space.PUT("/engines/:id", HandleUpdateSpaceEngineKey())
			space.DELETE("/engines/:id", HandleDeleteSpaceEngineKey())
			space.POST("/engines/:id/test", HandleTestSpaceEngineKey())
			space.POST("/search", HandleSpaceOnlineSearch())
		}

		// 仪表盘
		dashboard := v1.Group("/dashboard")
		{
			dashboard.GET("/stats", HandleGetDashboardStats())
		}

		// IP查询
		ipQuery := v1.Group("/ip-query")
		{
			ipQuery.GET("", HandleQueryIP)              // 查询单个IP
			ipQuery.POST("/batch", HandleBatchQueryIPs) // 批量查询IP
			ipQuery.GET("/info", HandleGetIPDBInfo)     // 获取IP数据库信息
			ipQuery.POST("/reload", HandleReloadIPDB)   // 重新加载IP数据库
		}

		// POC 任务管理
		pocTasks := v1.Group("/poc-tasks")
		{
			pocTasks.GET("", HandleGetPocTaskList())
			pocTasks.GET("/:id", HandleGetPocTaskDetail())
			pocTasks.POST("", HandleCreatePocTask())
			pocTasks.DELETE("/:id", HandleDeletePocTask())
			pocTasks.GET("/:id/progress", HandleGetPocTaskProgress())
			pocTasks.POST("/:id/execute", HandleExecutePocTask())
			pocTasks.PUT("/:id/pause", HandlePausePocTask())
			pocTasks.PUT("/:id/resume", HandleResumePocTask())
			pocTasks.PUT("/:id/stop", HandleStopPocTask())
		}

		// POC 扫描结果
		pocResults := v1.Group("/poc-results")
		{
			pocResults.GET("/:taskId", HandleGetPocScanResults())
			pocResults.GET("/:taskId/detail/:resultId", HandleGetPocScanResultDetail())
			pocResults.POST("", HandleAddPocScanResult())
			pocResults.DELETE("/:resultId", HandleDeletePocScanResult())
			pocResults.DELETE("/task/:taskId", HandleDeletePocScanResultsByTask())
			pocResults.GET("/:taskId/statistics", HandleGetPocScanResultStatistics())
		}

		// POC 报告导出
		pocReports := v1.Group("/poc-reports")
		{
			pocReports.GET("/:taskId/html", HandleGeneratePocHTMLReport())
			pocReports.GET("/:taskId/excel", HandleGeneratePocExcelReport())
			pocReports.GET("/:taskId/markdown", HandleGeneratePocMDReport())
			pocReports.GET("/:taskId/download/:type", HandleDownloadPocReport())
		}

		// 手动漏洞验证
		vulnVerify := v1.Group("/vuln-verify")
		{
			vulnVerify.GET("", HandleGetManualVulnVerifyList())
			vulnVerify.POST("", HandleAddManualVulnVerify())
			vulnVerify.GET("/workbench", HandleGetVulnVerifyWorkbench())
			vulnVerify.PUT("/workbench", HandleSaveVulnVerifyWorkbench())
			vulnVerify.PUT("/:id", HandleUpdateManualVulnVerify())
			vulnVerify.DELETE("/:id", HandleDeleteManualVulnVerify())
		}

		// 漏洞验证分组
		vulnVerifyGroup := v1.Group("/vuln-verify-group")
		{
			vulnVerifyGroup.GET("", HandleGetVulnVerifyGroups())
			vulnVerifyGroup.POST("", HandleAddVulnVerifyGroup())
			vulnVerifyGroup.PUT("/:id", HandleUpdateVulnVerifyGroup())
			vulnVerifyGroup.DELETE("/:id", HandleDeleteVulnVerifyGroup())
			vulnVerifyGroup.GET("/:id/vulns", HandleGetManualVulnVerifyListByGroup())
		}

		// AI 对话
		ai := v1.Group("/ai")
		{
			ai.POST("/chat", HandleAIChat())
		}

		// 工具方法
		tools := v1.Group("/tools")
		{
			tools.POST("/raw-request", HandleSendRawRequest())
		}

		// 黑名单管理
		blacklist := v1.Group("/blacklist")
		{
			blacklist.GET("/category", HandleGetBlacklistByCategory())
			blacklist.POST("", HandleAddToBlacklist())
			blacklist.DELETE("", HandleRemoveFromBlacklist()) // 注意：部分客户端可能不支持 DELETE 带 body，需要前端注意
			blacklist.POST("/save", HandleSaveBlacklist())
		}

		// 访问黑名单管理
		accessBlacklist := v1.Group("/access-blacklist")
		{
			accessBlacklist.GET("", HandleGetAccessBlacklistItems())
			accessBlacklist.GET("/category", HandleGetAccessBlacklistByCategory())
			accessBlacklist.POST("", HandleAddToAccessBlacklist())
			accessBlacklist.DELETE("", HandleRemoveFromAccessBlacklist())
			accessBlacklist.POST("/save", HandleSaveAccessBlacklist())
		}

		system := v1.Group("/system")
		{
			system.GET("/login-logs", HandleGetLoginLogs)
			system.DELETE("/login-logs", HandleClearLoginLogs)
			system.GET("/access-logs", HandleGetAccessLogs)
			system.POST("/access-logs/visit", HandleRecordAccessVisit)
			system.DELETE("/access-logs", HandleClearAccessLogs)
			system.GET("/operation-logs", HandleGetOperationLogs)
			system.DELETE("/operation-logs", HandleClearOperationLogs)
			system.GET("/unauthorized-access-logs", HandleGetUnauthorizedAccessLogs)
			system.DELETE("/unauthorized-access-logs", HandleClearUnauthorizedAccessLogs)
			system.GET("/dingtalk-bots", HandleListDingTalkBots())
			system.POST("/dingtalk-bots", HandleSaveDingTalkBot())
			system.PUT("/dingtalk-bots/:id", HandleUpdateDingTalkBot())
			system.DELETE("/dingtalk-bots/:id", HandleDeleteDingTalkBot())
			system.POST("/dingtalk-bots/:id/test", HandleTestDingTalkBot())
			system.POST("/dingtalk-bots/:id/reconnect", HandleReconnectDingTalkBot())
			system.GET("/dingtalk-bots/:id/status", HandleDingTalkBotStatus())
			system.POST("/dingtalk-bindings/code", HandleGenerateDingTalkBindingCode())
			system.POST("/dingtalk-bindings", HandleBindDingTalkUser())
			system.GET("/dingtalk-bindings", HandleListDingTalkBindings())
			system.DELETE("/dingtalk-bindings/:id", HandleDeleteDingTalkBinding())
			system.GET("/dingtalk-allowlist", HandleListDingTalkAllowlist())
			system.POST("/dingtalk-allowlist", HandleSaveDingTalkAllowlist())
			system.PUT("/dingtalk-allowlist/:id", HandleUpdateDingTalkAllowlist())
			system.DELETE("/dingtalk-allowlist/:id", HandleDeleteDingTalkAllowlist())
			system.GET("/ai-api-keys", HandleListAIAPIKeys())
			system.POST("/ai-api-keys", HandleSaveAIAPIKey())
			system.PUT("/ai-api-keys/:id", HandleUpdateAIAPIKey())
			system.DELETE("/ai-api-keys/:id", HandleDeleteAIAPIKey())
			system.POST("/ai-api-keys/:id/test", HandleTestAIAPIKey())
		}
	}

	RegisterWorkerRoutes(r, v1)
	return r
}
