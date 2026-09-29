//go:build !linux && !darwin

package main

import (
	"fmt"
	"runtime"
)

func pidExe(pid int) (string, error) {
	return "", fmt.Errorf("peer lookup is not supported on %s", runtime.GOOS)
}
