//go:build !windows

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func runPastedTerminalInput(t *testing.T, input string, command func() error) string {
	t.Helper()
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	initial, err := term.GetState(int(terminal.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	stderr, stderrWriter := setInputFiles(t, terminal)
	output := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(master)
		output <- string(b)
	}()
	done := make(chan error, 1)
	go func() { done <- command() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err := term.GetState(int(terminal.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(initial, state) {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("command ended before disabling terminal echo: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			terminal.Close()
			<-done
			t.Fatal("terminal input did not disable echo")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := io.WriteString(master, input+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		terminal.Close()
		<-done
		t.Fatal("pasted terminal input did not complete on Enter")
	}
	restored, err := term.GetState(int(terminal.Fd()))
	if err != nil || !reflect.DeepEqual(initial, restored) {
		t.Fatal("terminal settings were not restored")
	}
	terminal.Close()
	select {
	case captured := <-output:
		if strings.Contains(captured, input) {
			t.Fatal("terminal echoed the pasted value")
		}
	case <-time.After(3 * time.Second):
		master.Close()
		t.Fatal("terminal output did not finish after input closed")
	}
	stderrWriter.Close()
	prompt, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	return string(prompt)
}

func TestGetAcceptsPastedOwnerTokenAndPassword(t *testing.T) {
	const token = "stash_owner_synthetic-paste-owner"
	const password = "synthetic-paste-password"
	const value = "synthetic-ocean-password"
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secrets/DEMO_SECRET" || r.Header.Get("Authorization") != "Bearer "+token {
			writeErr(w, http.StatusForbidden, "unexpected request or owner token")
			return
		}
		if r.Header.Get("X-Stash-Password") == "" {
			writeErr(w, http.StatusForbidden, "reading a value needs the owner password. Agents: use `stash run` or a proxy route instead")
			return
		}
		if r.Header.Get("X-Stash-Password") != password {
			writeErr(w, http.StatusForbidden, "wrong owner password")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"value": value})
	}))
	defer srv.Close()
	t.Setenv("STASH_ADDR", srv.URL)
	t.Setenv("STASH_TOKEN", "\x1b[200~"+token+"\x1b[201~")
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOutput := os.Stdout
	os.Stdout = stdoutWriter
	t.Cleanup(func() {
		os.Stdout = oldOutput
		stdout.Close()
		stdoutWriter.Close()
	})
	prompt := runPastedTerminalInput(t, "\x1b[200~"+password+"\x1b[201~", func() error {
		return cmdGet([]string{"DEMO_SECRET"})
	})
	stdoutWriter.Close()
	got, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != value+"\n" || requests.Load() != 2 {
		t.Fatal("get did not retrieve the value after the owner-password retry")
	}
	if prompt != "owner password: \n" {
		t.Fatal("owner prompt changed or disclosed the pasted value")
	}
}

func TestPastedTerminalSecretPreservesWhitespace(t *testing.T) {
	values := setInputServer(t)
	const value = "  synthetic secret with spaces  "
	prompt := runPastedTerminalInput(t, "\x1b[200~"+value+"\x1b[201~", func() error {
		return cmdSet([]string{"DEMO_SECRET"})
	})
	if got := <-values; got != value {
		t.Fatal("terminal paste changed the secret's whitespace or retained paste markers")
	}
	if prompt != "secret value: \n" {
		t.Fatal("secret prompt changed or disclosed the pasted value")
	}
}
