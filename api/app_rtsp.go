package api

import "FusionWeb/backend/service"

func (a *App) ListRTSPDictionary(dictType, keyword string) ([]service.RTSPDictionaryItem, error) {
	return a.rtspService.ListDictionary(dictType, keyword)
}

func (a *App) GetRTSPDictionaryStatistics() (map[string]int, error) {
	return a.rtspService.GetDictionaryStatistics()
}

func (a *App) SaveRTSPDictionary(item service.RTSPDictionaryItem, userID int) (service.RTSPDictionaryItem, error) {
	return a.rtspService.SaveDictionary(item, userID)
}

func (a *App) DeleteRTSPDictionary(id int64) error {
	return a.rtspService.DeleteDictionary(id)
}

func (a *App) DeleteRTSPDictionaryByType(dictType string) error {
	return a.rtspService.DeleteDictionaryByType(dictType)
}

func (a *App) ImportRTSPDictionary(dictType string, values []string, userID int) (service.RTSPDictionaryImportSummary, error) {
	return a.rtspService.ImportDictionary(dictType, values, userID)
}

func (a *App) StartRTSPScan(config service.RTSPScanConfig, userID int) (*service.RTSPScanTaskState, error) {
	return a.rtspService.StartScan(config, userID)
}

func (a *App) StopRTSPScan(taskID string) error {
	return a.rtspService.StopScan(taskID)
}

func (a *App) GetRTSPScanState(taskID string) (*service.RTSPScanTaskState, error) {
	return a.rtspService.GetScanState(taskID)
}

func (a *App) ListRTSPResults(taskID string, userID int) ([]service.RTSPScanResult, error) {
	return a.rtspService.ListResults(taskID, userID)
}

func (a *App) DeleteRTSPResult(id int64, userID int) error {
	return a.rtspService.DeleteResult(id, userID)
}
