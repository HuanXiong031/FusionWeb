package api

import "FusionWeb/backend/service"

func (a *App) GetAccessBlacklistByCategory() (service.AccessPolicyConfig, error) {
	return a.accessPolicyService.GetBlacklistByCategory()
}

func (a *App) GetAccessBlacklistItems() ([]service.AccessPolicyItem, error) {
	return a.accessPolicyService.GetBlacklistItems()
}

func (a *App) AddToAccessBlacklistWithCategory(category, item string) error {
	return a.accessPolicyService.AddToBlacklistWithCategory(category, item)
}

func (a *App) AddToAccessBlacklistWithDuration(category, item string, durationMinutes int) error {
	return a.accessPolicyService.AddToBlacklistWithDuration(category, item, durationMinutes)
}

func (a *App) AddToAccessBlacklistWithPeriod(category, item, startsAt, expiresAt string) error {
	return a.accessPolicyService.AddToBlacklistWithPeriod(category, item, startsAt, expiresAt)
}

func (a *App) RemoveFromAccessBlacklistWithCategory(category, item string) error {
	return a.accessPolicyService.RemoveFromBlacklistWithCategory(category, item)
}

func (a *App) SaveAccessBlacklistByCategory(config service.AccessPolicyConfig) error {
	return a.accessPolicyService.SaveBlacklistByCategory(config)
}

func (a *App) CheckAccessPolicy(info service.AccessRequestInfo) service.AccessPolicyDecision {
	return a.accessPolicyService.CheckAccess(info)
}
