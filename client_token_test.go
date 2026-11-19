package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func tokenFallbackFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.Mkdir(filepath.Join(home, ".stash"), 0700); err != nil {
		t.Fatal(err)
	}
	const token = "stash_agent_synthetic-default"
	if err := os.WriteFile(filepath.Join(home, ".stash", "agent.token"), []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return token
}

// An empty STASH_TOKEN and a token from before 0.5 both fall back to the
// token file. There is one token, so the fallback grants nothing extra.
func TestClientUsesTokenFileForEmptyOrPre05Token(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"empty", ""},
		{"whitespace", " \t\n"},
		{"pre-0.5", "stash_" + strings.Repeat("ab", 24)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tokenFallbackFixture(t)
			t.Setenv("STASH_TOKEN", tc.input)
			c := newClient()
			if c.initErr != nil || c.token != want {
				t.Fatalf("token = %q, err = %v; want the token file", c.token, c.initErr)
			}
		})
	}
}

func TestClientPrefersTokenFileOverOldName(t *testing.T) {
	old := tokenFallbackFixture(t)
	home := os.Getenv("HOME")
	const current = "stash_agent_synthetic-current"
	if err := os.WriteFile(filepath.Join(home, ".stash", "token"), []byte(current+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STASH_TOKEN", "")
	if c := newClient(); c.token != current || c.token == old {
		t.Fatalf("token = %q, want %q", c.token, current)
	}
}

func TestClientUsesExplicitTokenInsteadOfDefault(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"owner", "stash_owner_synthetic-owner", "stash_owner_synthetic-owner"},
		{"agent", "stash_agent_synthetic-agent", "stash_agent_synthetic-agent"},
		{"run", "stash_run_synthetic-run", "stash_run_synthetic-run"},
		{"pasted owner", "\x1b[200~stash_owner_synthetic-owner\x1b[201~", "stash_owner_synthetic-owner"},
		{"pasted owner with outer whitespace", " \n\x1b[200~ stash_owner_synthetic-owner \x1b[201~\n ", "stash_owner_synthetic-owner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenFallbackFixture(t)
			header := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header <- r.Header.Get("Authorization")
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			t.Setenv("STASH_ADDR", srv.URL)
			t.Setenv("STASH_TOKEN", tc.input)
			if err := newClient().do(http.MethodGet, "/v1/tokens", nil, nil); err != nil {
				t.Fatal(err)
			}
			if got := <-header; got != "Bearer "+tc.want {
				t.Fatal("explicit token was changed or replaced with the default agent token")
			}
		})
	}
}

func TestClientUsesDefaultOnlyWhenTokenIsUnset(t *testing.T) {
	want := tokenFallbackFixture(t)
	t.Setenv("STASH_TOKEN", "cleanup-restores-original-environment")
	if err := os.Unsetenv("STASH_TOKEN"); err != nil {
		t.Fatal(err)
	}
	header := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("STASH_ADDR", srv.URL)
	if err := newClient().do(http.MethodGet, "/v1/secrets", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := <-header; got != "Bearer "+want {
		t.Fatal("unset token did not use the saved default agent token")
	}
}

func TestClientRejectsMalformedExplicitTokenWithoutFallbackOrDisclosure(t *testing.T) {
	for _, tc := range []struct {
		name, token string
	}{
		{"old format", "stash_synthetic-old-token"},
		{"bare owner prefix", "stash_owner_"},
		{"bare agent prefix", "stash_agent_"},
		{"bare run prefix", "stash_run_"},
		{"quoted", "\"stash_owner_synthetic-quoted\""},
		{"embedded newline", "stash_owner_synthetic\nprivate"},
		{"embedded escape", "stash_owner_synthetic\x1bprivate"},
		{"embedded whitespace", "stash_owner_synthetic private"},
		{"non-ASCII", "stash_owner_synthetic-prívate"},
		{"invalid punctuation", "stash_owner_synthetic/private"},
		{"unpaired paste marker", "\x1b[200~stash_owner_synthetic-private"},
	} {
		for _, stream := range []bool{false, true} {
			name := tc.name + "/request"
			if stream {
				name = tc.name + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				tokenFallbackFixture(t)
				var requests atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.WriteHeader(http.StatusNoContent)
				}))
				defer srv.Close()
				t.Setenv("STASH_ADDR", srv.URL)
				t.Setenv("STASH_TOKEN", tc.token)
				c := newClient()
				var err error
				if stream {
					var response *http.Response
					response, err = c.stream(context.Background(), http.MethodGet, "/v1/secrets", nil)
					if response != nil {
						response.Body.Close()
					}
				} else {
					err = c.do(http.MethodGet, "/v1/secrets", nil, nil)
				}
				if err == nil {
					t.Fatal("malformed explicit token was accepted or replaced with the default token")
				}
				if !strings.Contains(err.Error(), "STASH_TOKEN") {
					t.Fatal("error did not identify the malformed token override")
				}
				if len(strings.TrimSpace(tc.token)) > 0 && strings.Contains(err.Error(), tc.token) {
					t.Fatal("error disclosed the malformed token")
				}
				if requests.Load() != 0 {
					t.Fatal("malformed explicit token made a server request")
				}
			})
		}
	}
}
