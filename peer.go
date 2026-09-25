package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// stash run needs every value to build the command's env. An agent must not
// fetch that same list with curl. So /v1/env only answers the stash binary
// itself: the server finds the process on the other end of the local TCP
// connection and checks that its program file is stash.

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// peerIsStash reports whether the local client on remoteAddr runs the same
// program as this server.
func peerIsStash(remoteAddr, localAddr string) bool {
	if !isLoopback(remoteAddr) {
		return false
	}
	_, rport, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	_, lport, err := net.SplitHostPort(localAddr)
	if err != nil {
		return false
	}
	pids, err := peerPIDs(rport, lport)
	if err != nil || len(pids) == 0 {
		return false
	}
	for _, pid := range pids {
		exe, err := pidExe(pid)
		if err != nil || !sameProgram(exe) {
			return false
		}
	}
	return true
}

// peerPIDs returns the processes, other than this one, that hold the client
// end of the connection from rport to lport.
func peerPIDs(rport, lport string) ([]int, error) {
	switch runtime.GOOS {
	case "darwin":
		return peerPIDsLsof(rport, lport)
	case "linux":
		return peerPIDsProc(rport, lport)
	}
	return nil, fmt.Errorf("peer lookup is not supported on %s", runtime.GOOS)
}

func peerPIDsLsof(rport, lport string) ([]int, error) {
	out, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-iTCP:"+rport, "-sTCP:ESTABLISHED", "-F", "pn").Output()
	if err != nil {
		return nil, err
	}
	// Records: "p<pid>" then one "n<local>-><remote>" line per socket. Keep
	// the pids whose socket runs from rport to lport.
	var pids []int
	pid := 0
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "p"):
			pid, _ = strconv.Atoi(line[1:])
		case strings.HasPrefix(line, "n"):
			local, remote, ok := strings.Cut(line[1:], "->")
			if ok && strings.HasSuffix(local, ":"+rport) && strings.HasSuffix(remote, ":"+lport) && pid != os.Getpid() {
				pids = append(pids, pid)
			}
		}
	}
	return pids, nil
}

func peerPIDsProc(rport, lport string) ([]int, error) {
	rp, _ := strconv.Atoi(rport)
	lp, _ := strconv.Atoi(lport)
	want := fmt.Sprintf(":%04X", rp)
	wantRemote := fmt.Sprintf(":%04X", lp)
	inodes := map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) > 9 && strings.HasSuffix(fields[1], want) && strings.HasSuffix(fields[2], wantRemote) {
				inodes["socket:["+fields[9]+"]"] = true
			}
		}
		fh.Close()
	}
	procs, _ := filepath.Glob("/proc/[0-9]*/fd/*")
	seen := map[int]bool{}
	var pids []int
	for _, fd := range procs {
		link, err := os.Readlink(fd)
		if err != nil || !inodes[link] {
			continue
		}
		pid, _ := strconv.Atoi(strings.Split(fd, "/")[2])
		if pid != os.Getpid() && !seen[pid] {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func pidExe(pid int) (string, error) {
	if runtime.GOOS == "linux" {
		return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	}
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

var (
	selfOnce sync.Once
	selfPath string
	selfHash string
)

// sameProgram accepts the server's own file, or any copy of it with the
// same contents.
func sameProgram(exe string) bool {
	selfOnce.Do(func() {
		if p, err := os.Executable(); err == nil {
			selfPath = p
			selfHash, _ = fileHash(p)
		}
	})
	if selfPath == "" {
		return false
	}
	a, err1 := os.Stat(exe)
	b, err2 := os.Stat(selfPath)
	if err1 == nil && err2 == nil && os.SameFile(a, b) {
		return true
	}
	h, err := fileHash(exe)
	return err == nil && selfHash != "" && h == selfHash
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
