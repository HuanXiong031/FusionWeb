//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package common

func getOpenFileLimit() int {
	return 0
}
