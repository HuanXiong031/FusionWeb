package api

import "FusionWeb/backend/service"

func (a *App) ListAIAPIKeys(includeSecret bool, userID int) ([]service.AIAPIKey, error) {
	return a.systemSettingsService.ListAIAPIKeys(includeSecret, userID)
}

func (a *App) SaveAIAPIKey(item service.AIAPIKey, userID int) (service.AIAPIKey, error) {
	return a.systemSettingsService.SaveAIAPIKey(item, userID)
}

func (a *App) DeleteAIAPIKey(id int, userID int) error {
	return a.systemSettingsService.DeleteAIAPIKey(id, userID)
}

func (a *App) TestAIAPIKey(id int, userID int) (service.AIAPIKeyTestResult, error) {
	return a.systemSettingsService.TestAIAPIKey(id, userID)
}

func (a *App) ChatWithAI(req service.AIChatRequest, userID int) (service.AIChatResponse, error) {
	return a.systemSettingsService.ChatWithAI(req, userID)
}
