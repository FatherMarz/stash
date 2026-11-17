//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type localControlConnKey struct{}

func ownedControlDir(dir string, private bool) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	if !st.IsDir() || st.Mode().Perm()&mask != 0 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("local control requires a private directory owned by this user")
	}
	return nil
}

// The kernel supplies the current peer PID. No request header is trusted.
func unixPeerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var lookup error
	err = raw.Control(func(fd uintptr) { pid, lookup = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) })
	if err != nil {
		return 0, err
	}
	if lookup != nil {
		return 0, lookup
	}
	if pid <= 0 {
		return 0, errors.New("local peer identity unavailable")
	}
	return pid, nil
}

func unixPeerIsStash(conn *net.UnixConn) bool {
	pid, err := unixPeerPID(conn)
	if err != nil {
		return false
	}
	exe, err := pidExe(pid)
	return err == nil && sameProgram(exe)
}

func localCallerIsStash(r *http.Request) (verified, handled bool) {
	conn, ok := r.Context().Value(localControlConnKey{}).(*net.UnixConn)
	if !ok {
		return false, false
	}
	return unixPeerIsStash(conn), true
}

func startLocalControl(dir string, handler http.Handler) (func(), error) {
	if err := ownedControlDir(dir, false); err != nil {
		return nil, err
	}
	control := filepath.Join(dir, "control")
	if err := os.Mkdir(control, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := ownedControlDir(control, true); err != nil {
		return nil, err
	}
	path := filepath.Join(control, "control.sock")
	if st, err := os.Lstat(path); err == nil {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if st.Mode()&os.ModeSocket == 0 || !ok || owner.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("refusing to replace local control path")
		}
		probe, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			probe.Close()
			return nil, errors.New("local control socket is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot verify stale local control socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, localControlConnKey{}, conn)
		}}
	go srv.Serve(listener)
	return func() { srv.Close() }, nil
}

// Only the normal local endpoint discovers the socket. Explicit remote or custom
// endpoints keep their original transport. A present socket must authenticate;
// it never silently falls back to TCP after a local identity failure.
func configureLocalHTTP(hc *http.Client, addr, dir string) {
	addr = strings.TrimSuffix(addr, "/")
	if addr != "http://127.0.0.1:8555" && addr != "http://localhost:8555" && addr != "http://[::1]:8555" {
		return
	}
	path := filepath.Join(dir, "control", "control.sock")
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return
	}
	hc.Transport = &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if err != nil {
				return nil, err
			}
			if st.Mode()&os.ModeSocket == 0 {
				return nil, errors.New("local control path is not a socket")
			}
			if err := ownedControlDir(filepath.Join(dir, "control"), true); err != nil {
				return nil, err
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			uc, ok := conn.(*net.UnixConn)
			if !ok || !unixPeerIsStash(uc) {
				conn.Close()
				return nil, errors.New("local control server is not the Stash program")
			}
			return conn, nil
		}}
}
