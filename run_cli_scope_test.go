package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRunCLIRejectsMissingOrMalformedScopeBeforeAnyAccess(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected access", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("STASH_ADDR", srv.URL)
	t.Setenv("STASH_TOKEN", "stash_agent_fake-scope-test")
	marker := filepath.Join(t.TempDir(), "child-ran")
	child := []string{"/bin/sh", "-c", `: > "$1"`, "child", marker}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"command without selection", child},
		{"separator without selection", append([]string{"--"}, child...)},
		{"empty name", append([]string{"--secret", "", "--"}, child...)},
		{"whitespace name", append([]string{"--secret", " \t\n", "--"}, child...)},
		{"separator used as name", append([]string{"--secret", "--"}, child...)},
		{"flag used as name", append([]string{"--secret", "--all"}, child...)},
		{"short flag used as name", append([]string{"--secret", "-x"}, child...)},
		{"missing name", []string{"--secret"}},
		{"missing command", []string{"--secret", "API_KEY"}},
		{"missing command after separator", []string{"--secret", "API_KEY", "--"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := cmdRun(tc.args); err == nil {
				t.Fatal("invalid scope started a run")
			}
			if requests.Load() != 0 {
				t.Fatal("invalid scope contacted the server")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid scope launched the child: %v", err)
			}
		})
	}
}

func TestRunCLIExplicitSelectionForwardsCommandAndRevokesToken(t *testing.T) {
	var selected []string
	var methods []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/run":
			var body struct {
				Secrets []string `json:"secrets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode request: %v", err)
			}
			selected = body.Secrets
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(runSetup{
				Token:       "stash_run_fake-scope-test",
				SecretNames: []string{"API_KEY", "OTHER_KEY"},
				Routes:      []runRoute{{Name: "api", Secret: "API_KEY"}},
			})
		case r.Method == "DELETE" && r.URL.Path == "/v1/run":
			if r.Header.Get("Authorization") != "Bearer stash_run_fake-scope-test" {
				t.Error("cleanup did not use the scoped token")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected access", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	t.Setenv("STASH_ADDR", srv.URL)
	t.Setenv("STASH_TOKEN", "stash_agent_fake-scope-test")
	t.Setenv("API_KEY", "ambient-api-value")
	t.Setenv("OTHER_KEY", "ambient-unselected-value")
	err := cmdRun([]string{"--secret", "API_KEY", "--secret", "API_KEY", "--", "/bin/sh", "-c", `
test "$1" = --child-flag || exit 11
test "$API_KEY" = stash_run_fake-scope-test || exit 12
test -z "$OTHER_KEY" || exit 13
test -z "$STASH_TOKEN" || exit 14
case "$API_KEY_BASE_URL" in */proxy/api) ;; *) exit 15 ;; esac
exit 7`, "child", "--child-flag"})
	var exit *commandExit
	if !errors.As(err, &exit) || exit.code != 7 {
		t.Fatalf("child flag/env/exit forwarding failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(selected, []string{"API_KEY", "API_KEY"}) {
		t.Fatalf("selection changed: %v", selected)
	}
	if strings.Join(methods, ",") != "POST /v1/run,DELETE /v1/run" {
		t.Fatalf("run lifecycle: %v", methods)
	}
}
