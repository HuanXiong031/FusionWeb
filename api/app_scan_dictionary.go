package api

import "FusionWeb/backend/service"

func (a *App) ListScanDictionary(dictType, keyword string) ([]service.ScanDictionaryItem, error) {
	return a.scanDictionaryService.List(dictType, keyword)
}

func (a *App) GetScanDictionaryStatistics() (map[string]int, error) {
	return a.scanDictionaryService.Statistics()
}

func (a *App) SaveScanDictionary(item service.ScanDictionaryItem, userID int) (service.ScanDictionaryItem, error) {
	return a.scanDictionaryService.Save(item, userID)
}

func (a *App) DeleteScanDictionary(id int64) error {
	return a.scanDictionaryService.Delete(id)
}

func (a *App) DeleteScanDictionaryByType(dictType string) error {
	return a.scanDictionaryService.DeleteByType(dictType)
}

func (a *App) ImportScanDictionary(dictType string, values []string, userID int) (service.ScanDictionaryImportSummary, error) {
	return a.scanDictionaryService.Import(dictType, values, userID)
}
