//go:build darwin

package main

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

func pidExe(pid int) (string, error) {
	// kern.procargs2: a 4-byte argc, then the program path, NUL-terminated.
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(raw) < 5 {
		return "", fmt.Errorf("short procargs for pid %d", pid)
	}
	path, _, _ := bytes.Cut(raw[4:], []byte{0})
	return string(path), nil
}
