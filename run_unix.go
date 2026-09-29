//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
)

const ptySupported = true

// watchResize keeps the command's terminal the same size as ours.
func watchResize(ptmx *os.File) (stop func()) {
	resize := make(chan os.Signal, 1)
	signal.Notify(resize, syscall.SIGWINCH)
	go func() {
		for range resize {
			pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	resize <- syscall.SIGWINCH
	return func() { signal.Stop(resize); close(resize) }
}
