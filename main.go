// Package main starts the FusionWeb API service. The frontend is served by a separate Nginx container.
package main

import (
	"FusionWeb/api"
	"FusionWeb/backend/config"
	"FusionWeb/backend/database"
	"FusionWeb/backend/logger"
	"FusionWeb/backend/service"
	"FusionWeb/backend/websocket"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
)

func main() {
	if err := logger.InitLogger(); err != nil {
		fmt.Printf("日志初始化失败: %v\n", err)
	}
	defer logger.CloseLogger()

	if err := database.InitDatabase(); err != nil {
		logger.Error("运行依赖初始化失败: %v", err)
		panic(err)
	}
	// 管理员凭据同步仅由 API 进程执行，避免 Worker 用兜底默认密码覆盖真实管理员密码。
	if err := database.EnsureAdminCredentials(); err != nil {
		logger.Warn("初始化默认管理员账户失败: %v", err)
	}
	defer database.Close()
	logger.AttachDatabase(database.DB)
	if logger.GologWriter != nil {
		gologger.DefaultLogger.SetWriter(logger.GologWriter)
	}

	websocket.GetHub()
	app := api.NewApp()
	app.Init(context.Background())
	service.LoadIPDBAsync()

	router := api.NewRouter(app)
	addr := fmt.Sprintf(":%d", config.Get().Port)
	server := &http.Server{Addr: addr, Handler: router, ReadHeaderTimeout: 15 * time.Second}
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("FusionWeb API 正在监听 %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-signals:
		logger.Info("收到退出信号")
	case err := <-serverErr:
		logger.Error("API 服务异常: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Warn("HTTP 服务关闭失败: %v", err)
	}
	service.NewDingTalkBotService().StopAll()
}
