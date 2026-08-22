//go:build linux || darwin || freebsd || netbsd || openbsd

package common

import "syscall"

func getOpenFileLimit() int {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0
	}
	maxInt := int(^uint(0) >> 1)
	if limit.Cur > uint64(maxInt) {
		return maxInt
	}
	return int(limit.Cur)
}
