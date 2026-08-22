package exportrunner

import (
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// ExportRunnerConfigureOptions 配置全局选项
func ExportRunnerConfigureOptions() error {
	return runner.ConfigureOptions()
}

// ExportRunnerParseOptions 解析选项
func ExportRunnerParseOptions(options *types.Options) {
	runner.ParseOptions(options)
}

// ExportRunnerNew 创建新的 Runner 实例
func ExportRunnerNew(options *types.Options) (*runner.Runner, error) {
	return runner.New(options)
}
