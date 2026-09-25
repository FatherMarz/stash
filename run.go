package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/term"
)

// stash run executes the command inside the server process, not in the
// caller. The caller never receives a secret value. Every byte the command
// prints passes through a masker that replaces secret values with ****.

const maskMinLen = 4 // shorter values would blank out ordinary text

type runRequest struct {
	Argv  []string `json:"argv"`
	Dir   string   `json:"dir"`
	Env   []string `json:"env"`
	Stdin []byte   `json:"stdin,omitempty"`
}

// runFrame is one line of the NDJSON response stream.
type runFrame struct {
	Stream int    `json:"s,omitempty"` // 1 stdout, 2 stderr
	Data   []byte `json:"d,omitempty"`
	Exit   *int   `json:"exit,omitempty"`
	Error  string `json:"error,omitempty"`
}

// masker replaces secret values in a byte stream. When a write ends in the
// start of a value, it holds back only that part, so a value split across
// two writes is still caught and all other output flows through at once.
type masker struct {
	rep     *strings.Replacer
	vals    []string
	maxLen  int
	pending []byte
	out     func([]byte)
}

func newMasker(values []string, out func([]byte)) *masker {
	var vals []string
	for _, v := range values {
		if len(v) >= maskMinLen {
			vals = append(vals, v)
		}
	}
	// Longest first, so a value that contains another value masks whole.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	var pairs []string
	maxLen := 1
	for _, v := range vals {
		pairs = append(pairs, v, "****")
		maxLen = max(maxLen, len(v))
	}
	return &masker{rep: strings.NewReplacer(pairs...), vals: vals, maxLen: maxLen, out: out}
}

// holdFrom returns the index of the earliest tail of buf that is a proper
// prefix of some value, or len(buf) when there is none.
func (m *masker) holdFrom(buf string) int {
	for i := max(0, len(buf)-m.maxLen+1); i < len(buf); i++ {
		tail := buf[i:]
		for _, v := range m.vals {
			if len(tail) < len(v) && strings.HasPrefix(v, tail) {
				return i
			}
		}
	}
	return len(buf)
}

func (m *masker) Write(p []byte) (int, error) {
	buf := m.rep.Replace(string(append(m.pending, p...)))
	cut := m.holdFrom(buf)
	if cut > 0 {
		m.out([]byte(buf[:cut]))
	}
	m.pending = []byte(buf[cut:])
	return len(p), nil
}

func (m *masker) Flush() {
	if len(m.pending) > 0 {
		m.out(m.pending)
		m.pending = nil
	}
}

// lookPath resolves name against the caller's PATH, not the server's.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			path = v
		}
	}
	for _, dir := range filepath.SplitList(path) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: command not found", name)
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *server) runCommand(w http.ResponseWriter, r *http.Request, tok *Token) {
	// Running a command on the server host is only safe for callers on the
	// same host. Over the network it would be remote code execution.
	if !isLoopback(r.RemoteAddr) {
		writeErr(w, http.StatusForbidden, "stash run only works on the machine where stash serves")
		return
	}
	var req runRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Argv) == 0 {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"argv": ["cmd", ...], "dir": "...", "env": [...]}`)
		return
	}
	all, err := s.st.All()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	env := req.Env
	values := make([]string, 0, len(all))
	for name, value := range all {
		env = append(env, envName(name)+"="+value)
		values = append(values, value)
	}
	bin, err := lookPath(req.Argv[0], req.Env)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "run", req.Argv[0])

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	send := func(f runFrame) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(f)
		rc.Flush()
	}
	stdout := newMasker(values, func(b []byte) { send(runFrame{Stream: 1, Data: b}) })
	stderr := newMasker(values, func(b []byte) { send(runFrame{Stream: 2, Data: b}) })

	cmd := exec.CommandContext(r.Context(), bin, req.Argv[1:]...)
	cmd.Args[0] = req.Argv[0]
	cmd.Dir = req.Dir
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(req.Stdin)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	stdout.Flush()
	stderr.Flush()

	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		send(runFrame{Error: err.Error()})
		code = 127
	}
	send(runFrame{Exit: &code})
}

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("usage: stash run [--] COMMAND [ARGS...]")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	req := runRequest{Argv: args, Dir: dir, Env: os.Environ()}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if req.Stdin, err = io.ReadAll(os.Stdin); err != nil {
			return err
		}
	}
	c := newClient()
	resp, err := c.stream(context.Background(), "POST", "/v1/run", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		var f runFrame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			return fmt.Errorf("bad frame from server: %w", err)
		}
		switch {
		case f.Stream == 1:
			os.Stdout.Write(f.Data)
		case f.Stream == 2:
			os.Stderr.Write(f.Data)
		case f.Error != "":
			fmt.Fprintf(os.Stderr, "stash: %s\n", f.Error)
		case f.Exit != nil:
			os.Exit(*f.Exit)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("the server closed the stream before the command finished")
}
