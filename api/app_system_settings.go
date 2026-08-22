package api

import "FusionWeb/backend/service"

func (a *App) ListDingTalkKeys(includeSecret bool) ([]service.DingTalkKey, error) {
	return a.systemSettingsService.ListDingTalkKeys(includeSecret)
}

func (a *App) SaveDingTalkKey(item service.DingTalkKey) (service.DingTalkKey, error) {
	return a.systemSettingsService.SaveDingTalkKey(item)
}

func (a *App) DeleteDingTalkKey(id int) error {
	return a.systemSettingsService.DeleteDingTalkKey(id)
}
