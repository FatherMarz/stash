//go:build linux

package main

import (
	"fmt"
	"os"
)

func pidExe(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
