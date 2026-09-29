//go:build windows

package main

import "os"

// The pty package cannot start a command on Windows, so stash run always
// uses pipes there.
const ptySupported = false

func watchResize(ptmx *os.File) (stop func()) { return func() {} }
