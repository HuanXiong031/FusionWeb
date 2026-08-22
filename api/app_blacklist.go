package api

import (
	"FusionWeb/backend/service"
)

func (a *App) GetBlacklistByCategory() (service.BlacklistConfig, error) {
	return a.blacklistService.GetBlacklistByCategory()
}

func (a *App) AddToBlacklistWithCategory(category, item string) error {
	return a.blacklistService.AddToBlacklistWithCategory(category, item)
}

func (a *App) RemoveFromBlacklistWithCategory(category, item string) error {
	return a.blacklistService.RemoveFromBlacklistWithCategory(category, item)
}

func (a *App) SaveBlacklistByCategory(config service.BlacklistConfig) error {
	return a.blacklistService.SaveBlacklistByCategory(config)
}

func (a *App) GetCategories() ([]string, error) {
	return a.blacklistService.GetCategories()
}

// 返回可执行文件所在目录下的 config 子目录，用于存储：
//   - PostgreSQL 业务数据库
//   - qqwry.ipdb（IP 地理位置数据库）
//   - pocs/（POC 模板文件目录）
//
// 降级策略：如果无法获取可执行文件路径，则使用当前工作目录下的 config
