//go:build !windows

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

func setInputServer(t *testing.T) <-chan string {
	t.Helper()
	values := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/secrets/DEMO_SECRET" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		values <- body.Value
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("STASH_ADDR", srv.URL)
	t.Setenv("STASH_TOKEN", "stash_owner_demo-set-input")
	return values
}

func setInputFiles(t *testing.T, input *os.File) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldInput, oldError := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = input, w
	t.Cleanup(func() {
		os.Stdin, os.Stderr = oldInput, oldError
		r.Close()
		w.Close()
	})
	return r, w
}

func TestSetTerminalHidesValueAndCompletesOnEnter(t *testing.T) {
	values := setInputServer(t)
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
	go func() { done <- cmdSet([]string{"DEMO_SECRET"}) }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		state, err := term.GetState(int(terminal.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(initial, state) {
			break
		}
		if time.Now().After(deadline) {
			terminal.Close()
			<-done
			t.Fatal("terminal input did not disable echo")
		}
		time.Sleep(time.Millisecond)
	}
	const value = "demo-terminal-secret"
	if _, err := io.WriteString(master, value+"\n"); err != nil {
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
		t.Fatal("terminal input waited for EOF instead of completing on Enter")
	}
	if got := <-values; got != value {
		t.Fatal("terminal input changed the secret")
	}
	restored, err := term.GetState(int(terminal.Fd()))
	if err != nil || !reflect.DeepEqual(initial, restored) {
		t.Fatal("terminal settings were not restored")
	}
	terminal.Close()
	select {
	case captured := <-output:
		if strings.Contains(captured, value) {
			t.Fatal("terminal echoed the secret")
		}
	case <-time.After(3 * time.Second):
		master.Close()
		t.Fatal("terminal output did not finish after input closed")
	}
	stderrWriter.Close()
	b, err := io.ReadAll(stderr)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "secret value: \n" {
		t.Fatal("terminal prompt was missing or exposed the secret")
	}
}

func TestSetPreservesPipedAndInlineInput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"piped multiline", " first line\nsecond line\n\n", []string{"DEMO_SECRET"}, " first line\nsecond line\n"},
		{"piped empty", "", []string{"DEMO_SECRET"}, ""},
		{"inline", "ignored input", []string{"DEMO_SECRET", " inline\nvalue\n"}, " inline\nvalue\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := setInputServer(t)
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := io.WriteString(writer, tc.stdin); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			stderr, stderrWriter := setInputFiles(t, input)
			if err := cmdSet(tc.args); err != nil {
				t.Fatal(err)
			}
			if got := <-values; got != tc.want {
				t.Fatal("set changed the provided value")
			}
			stderrWriter.Close()
			b, err := io.ReadAll(stderr)
			if err != nil {
				t.Fatal(err)
			}
			if len(b) != 0 {
				t.Fatal("non-terminal input printed a prompt or value")
			}
		})
	}
}
