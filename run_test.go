package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func maskAll(values []string, chunks ...string) string {
	var out bytes.Buffer
	m := newMasker(values, func(b []byte) { out.Write(b) })
	for _, c := range chunks {
		m.Write([]byte(c))
	}
	m.Flush()
	return out.String()
}

func TestMaskerReplacesValues(t *testing.T) {
	got := maskAll([]string{"sk-secret-123"}, "key is sk-secret-123 ok\n")
	if got != "key is **** ok\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerCatchesValueSplitAcrossWrites(t *testing.T) {
	got := maskAll([]string{"sk-secret-123"}, "key is sk-se", "cret", "-123 ok\n")
	if got != "key is **** ok\n" {
		t.Fatalf("got %q", got)
	}
	got = maskAll([]string{"abcdef"}, "a", "b", "c", "d", "e", "f", "!")
	if got != "****!" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerDoesNotHoldOrdinaryOutput(t *testing.T) {
	var out bytes.Buffer
	m := newMasker([]string{strings.Repeat("x", 3000)}, func(b []byte) { out.Write(b) })
	m.Write([]byte("server ready on :5173\n"))
	if out.String() != "server ready on :5173\n" {
		t.Fatalf("held back ordinary output: %q", out.String())
	}
	m.Write([]byte("tail xx"))
	if out.String() != "server ready on :5173\ntail " {
		t.Fatalf("got %q", out.String())
	}
}

func TestMaskerLongestValueFirst(t *testing.T) {
	got := maskAll([]string{"abcd", "abcdefgh"}, "abcdefgh")
	if got != "****" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerSkipsShortValues(t *testing.T) {
	got := maskAll([]string{"1", "ab"}, "1 ab 2\n")
	if got != "1 ab 2\n" {
		t.Fatalf("got %q", got)
	}
}

func runOutput(t *testing.T, body []byte) (stdout, stderr string, exit int) {
	t.Helper()
	exit = -1
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		var f runFrame
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			t.Fatalf("bad frame %q: %v", sc.Text(), err)
		}
		switch {
		case f.Stream == 1:
			stdout += string(f.Data)
		case f.Stream == 2:
			stderr += string(f.Data)
		case f.Exit != nil:
			exit = *f.Exit
		}
	}
	return
}

func TestRunMasksOutputAndKeepsExitCode(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/api.key", map[string]string{"value": "sk-live-abc123"})

	resp, body := e.req(t, rw, "POST", "/v1/run", runRequest{
		Argv: []string{"sh", "-c", `echo "out $API_KEY"; echo "err $API_KEY" >&2; test -n "$API_KEY"; exit 3`},
		Env:  []string{"PATH=/bin:/usr/bin"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("run = %d %s", resp.StatusCode, body)
	}
	stdout, stderr, exit := runOutput(t, body)
	if stdout != "out ****\n" || stderr != "err ****\n" || exit != 3 {
		t.Fatalf("stdout=%q stderr=%q exit=%d", stdout, stderr, exit)
	}
	if strings.Contains(string(body), "abc123") {
		t.Fatalf("raw value leaked in response: %s", body)
	}
}

func TestRunPassesStdinAndDir(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	dir := t.TempDir()
	resp, body := e.req(t, rw, "POST", "/v1/run", runRequest{
		Argv:  []string{"sh", "-c", `cat; pwd`},
		Dir:   dir,
		Env:   []string{"PATH=/bin:/usr/bin"},
		Stdin: []byte("hello\n"),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("run = %d %s", resp.StatusCode, body)
	}
	stdout, _, exit := runOutput(t, body)
	if !strings.HasPrefix(stdout, "hello\n") || !strings.Contains(stdout, strings.TrimPrefix(dir, "/private")) || exit != 0 {
		t.Fatalf("stdout=%q exit=%d", stdout, exit)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	resp, _ := e.req(t, rw, "POST", "/v1/run", runRequest{Argv: []string{"no-such-cmd-xyz"}, Env: []string{"PATH=/bin"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("run = %d, want 400", resp.StatusCode)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:5000": true, "[::1]:5000": true, "10.0.0.5:5000": false, "garbage": false,
	} {
		if isLoopback(addr) != want {
			t.Fatalf("isLoopback(%q) != %v", addr, want)
		}
	}
}

func TestWrongPasswordLocksOut(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v1234"})
	for i := 0; i < guardMaxFails; i++ {
		resp, _ := e.reqPW(t, rw, "guess", "GET", "/v1/secrets/K", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("guess %d = %d, want 403", i, resp.StatusCode)
		}
	}
	resp, _ := e.reqPW(t, rw, testPW, "GET", "/v1/secrets/K", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("right password while locked = %d, want 429", resp.StatusCode)
	}
}

func TestPasswordChangeRules(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")

	resp, _ := e.reqPW(t, rw, testPW, "PUT", "/v1/password", map[string]string{"password": "new-password"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rw set password = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.req(t, e.admin, "PUT", "/v1/password", map[string]string{"password": "new-password"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin change without old password = %d, want 403", resp.StatusCode)
	}
	resp, body := e.reqPW(t, e.admin, testPW, "PUT", "/v1/password", map[string]string{"password": "new-password"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin change = %d %s", resp.StatusCode, body)
	}
	if err := e.st.CheckPassword("new-password"); err != nil {
		t.Fatal(err)
	}
}

func TestRevealWithoutPasswordSet(t *testing.T) {
	e := newTestEnv(t)
	if err := e.st.ClearPassword(); err != nil {
		t.Fatal(err)
	}
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v1234"})
	resp, body := e.reqPW(t, rw, "anything", "GET", "/v1/secrets/K", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "no owner password") {
		t.Fatalf("reveal with no password set = %d %s", resp.StatusCode, body)
	}
}
