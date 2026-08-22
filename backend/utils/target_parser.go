package utils

import "strings"

// ParseScanTargets parses user supplied scan targets in the same way the
// scheduler does: one target per line, ignoring blank lines and comments.
func ParseScanTargets(input string) []string {
	if input == "" {
		return []string{}
	}

	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	targets := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets
}
