package api

func (a *App) GetManualVulnVerifyList(page int, pageSize int, keyword string, userID uint, createdByFilter *int) (map[string]interface{}, error) {
	return a.vulnVerifyService.GetVerifyList(page, pageSize, keyword, userID, createdByFilter)
}
func (a *App) AddManualVulnVerify(name string) (int64, error) {
	// 默认使用 user_id = 1 (admin) 如果无法获取上下文
	// 注意：在实际调用中，应该优先使用 AddManualVulnVerifyWithUser
	return a.vulnVerifyService.AddVerify(name, 0, "", "", 1)
}
func (a *App) AddManualVulnVerifyWithUser(name string, userID uint) (int64, error) {
	return a.vulnVerifyService.AddVerify(name, 0, "", "", userID)
}
func (a *App) AddManualVulnVerifyWithUserAndGroup(name string, groupID int, request string, response string, userID uint) (int64, error) {
	return a.vulnVerifyService.AddVerify(name, groupID, request, response, userID)
}
func (a *App) UpdateManualVulnVerify(id int, data map[string]interface{}, userID uint) error {
	return a.vulnVerifyService.UpdateVerify(id, data, userID)
}
func (a *App) DeleteManualVulnVerify(id int, userID uint) error {
	return a.vulnVerifyService.DeleteVerify(id, userID)
}

// Vuln Verify Groups
func (a *App) GetVulnVerifyGroups(userID uint, createdByFilter *int) ([]map[string]interface{}, error) {
	return a.vulnVerifyService.GetGroups(userID, createdByFilter)
}
func (a *App) AddVulnVerifyGroup(name string, userID uint) (int64, error) {
	return a.vulnVerifyService.AddGroup(name, userID)
}
func (a *App) UpdateVulnVerifyGroup(id int, name string, userID uint) error {
	return a.vulnVerifyService.UpdateGroup(id, name, userID)
}
func (a *App) DeleteVulnVerifyGroup(id int, userID uint) error {
	return a.vulnVerifyService.DeleteGroup(id, userID)
}
func (a *App) GetManualVulnVerifyListByGroup(groupID int, userID uint) ([]map[string]interface{}, error) {
	return a.vulnVerifyService.GetVerifyListByGroup(groupID, userID)
}
func (a *App) GetVulnVerifyWorkbench(userID uint) (map[string]interface{}, error) {
	return a.vulnVerifyService.GetWorkbench(userID)
}
func (a *App) SaveVulnVerifyWorkbench(userID uint, data map[string]interface{}) (map[string]interface{}, error) {
	return a.vulnVerifyService.SaveWorkbench(userID, data)
}

// Tools
func (a *App) SendRawRequest(method string, urlStr string, headers map[string]string, body string, timeout int) (map[string]interface{}, error) {
	return a.toolsService.SendRawRequest(method, urlStr, headers, body, timeout)
}

// ==================== BlacklistAppInterface 接口实现：黑名单管理 ====================
