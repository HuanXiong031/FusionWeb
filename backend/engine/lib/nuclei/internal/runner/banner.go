// Package runner executes the enumeration process.
package runner

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
)

var banner = fmt.Sprintf(`
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   %s
`, config.Version)

// showBanner is used to show the banner to the user
func showBanner() {
	// 移除 banner 输出：避免显示 Nuclei ASCII logo 和版本信息
	// gologger.Print().Msgf("%s\n", banner)
	// gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	showBanner()
	updateutils.GetUpdateToolCallback(config.BinaryName, config.Version)()
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	showBanner()
	pdcpauth.CheckNValidateCredentials(config.BinaryName)
}
