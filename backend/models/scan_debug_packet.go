package models

import "time"

// ScanDebugPacket 扫描调试包记录。
type ScanDebugPacket struct {
	ID         int       `json:"id"`
	TaskID     string    `json:"task_id"`
	Host       string    `json:"host"`
	TemplateID string    `json:"template_id"`
	EventType  string    `json:"event_type"`
	Data       string    `json:"data"`
	CreatedAt  time.Time `json:"created_at"`
}
