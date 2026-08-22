package utils

import "FusionWeb/backend/runtimepath"

// GetDataDir 获取统一的运行数据目录。
func GetDataDir() string { return runtimepath.DataDir() }
