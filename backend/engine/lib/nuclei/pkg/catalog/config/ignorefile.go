package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the nuclei ignore file returning blocked tags and paths
func ReadIgnoreFile() IgnoreFile {
	file, err := os.Open(DefaultConfig.GetIgnoreFilePath())
	if err != nil {
		// 不再输出错误日志，减少日志噪音
		return IgnoreFile{}
	}
	defer func() {
		_ = file.Close()
	}()

	ignore := IgnoreFile{}
	if err := yaml.NewDecoder(file).Decode(&ignore); err != nil {
		// 不再输出错误日志，减少日志噪音
		return IgnoreFile{}
	}
	return ignore
}
