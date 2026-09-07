package service

// SystemSettingsService 是系统级设置服务的兼容入口。
// AI API Key 与 AI 对话实现位于 ai_settings_service.go；旧钉钉 Key CRUD 已迁移至 DingTalkBotService。
type SystemSettingsService struct{}

func NewSystemSettingsService() *SystemSettingsService {
	return &SystemSettingsService{}
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
