// backend/dto/poc_dto.go
// POC 模块请求/响应 DTO
package dto

// ============================================================
// POC 文件管理请求
// ============================================================

// CreatePocFileRequest 创建 POC 文件请求
type CreatePocFileRequest struct {
	Category string `json:"category" binding:"required"`
	FileName string `json:"fileName" binding:"required"`
	Content  string `json:"content" binding:"required"`
}

// UpdatePocFileRequest 更新 POC 文件请求
type UpdatePocFileRequest struct {
	RelativePath string `json:"relativePath" binding:"required"`
	Content      string `json:"content" binding:"required"`
	Category     string `json:"category"`
}

// RenamePocFileRequest 重命名 POC 文件请求
type RenamePocFileRequest struct {
	OldRelativePath string `json:"oldRelativePath" binding:"required"`
	NewRelativePath string `json:"newRelativePath" binding:"required"`
}

// DeletePocFileRequest 删除 POC 文件请求
type DeletePocFileRequest struct {
	RelativePath string `json:"relativePath" binding:"required"`
}

// ImportPocFileRequest 导入 POC 文件请求
type ImportPocFileRequest struct {
	Category      string `json:"category" binding:"required"`
	FileName      string `json:"fileName" binding:"required"`
	Base64Content string `json:"base64Content" binding:"required"`
}

// ExportSelectedPOCsRequest 导出选中的 POC 请求
type ExportSelectedPOCsRequest struct {
	RelativePaths []string `json:"relativePaths" binding:"required,min=1"`
}

// ============================================================
// POC 调试/扫描请求
// ============================================================

// DebugScanPOCRequest POC 调试扫描请求
type DebugScanPOCRequest struct {
	TemplateContent string   `json:"templateContent" binding:"required"`
	Targets         []string `json:"targets" binding:"required,min=1"`
	Proxy           string   `json:"proxy"`
	Debug           bool     `json:"debug"`
}

// PocFilesPageRequest POC 文件分页查询
type PocFilesPageRequest struct {
	PageRequest
	Severity string `json:"severity" form:"severity"`
}
