package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunCLIForwardsChildFlagsAndCleansUpAfterFailure(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("API_KEY", "server-only-secret")
	e.st.SetRoute(Route{Name: "api", Secret: "API_KEY", Upstream: "https://example.invalid"})
	agent := e.mustCreateToken(t, "cli-agent", "agent")
	t.Setenv("STASH_ADDR", e.srv.URL)
	t.Setenv("STASH_TOKEN", agent)
	t.Setenv("DSH_STASH_TOKEN", "ambient-parent-token")
	t.Setenv("API_KEY", "ambient-raw-value")
	err := cmdRun([]string{"--secret", "API_KEY", "--", "/bin/sh", "-c", `
test "$1" = --raw || exit 11
case "$API_KEY" in stash_run_*) ;; *) exit 12 ;; esac
test "$API_KEY" != ambient-raw-value || exit 13
test -z "$DSH_STASH_TOKEN" || exit 14
test -z "$STASH_TOKEN" || exit 15
exit 7`, "child", "--raw"})
	var childExit *commandExit
	if !errors.As(err, &childExit) || childExit.code != 7 {
		t.Fatalf("child exit: %v", err)
	}
	entries, _ := e.st.AuditLog(100)
	var starts, ends int
	for _, entry := range entries {
		if entry.Action == "run-start" {
			starts++
		}
		if entry.Action == "run-end" {
			ends++
		}
	}
	if starts != 1 || ends != 1 {
		t.Fatalf("run lifecycle: %d starts, %d ends", starts, ends)
	}
	if err := cmdRun([]string{"--raw", "echo"}); err == nil {
		t.Fatal("raw mode remained available")
	}
}

func TestAgentCanUseBuiltInConnectionWithoutAdminRouteSetup(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("OPENROUTER_API_KEY", "never-return-this-value")
	agent := e.mustCreateToken(t, "api-agent", "agent")
	resp, body := e.req(t, agent, "POST", "/v1/run", map[string]any{"secrets": []string{"OPENROUTER_API_KEY"}})
	if resp.StatusCode != 201 {
		t.Fatalf("built-in connection: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "never-return-this-value") {
		t.Fatal("connection returned a raw key")
	}
	routes, _ := e.st.ListRoutes()
	if len(routes) != 0 {
		t.Fatal("built-in connection changed owner-managed routes")
	}
	route, ok := builtinRoute("OPENROUTER_API_KEY")
	if !ok || route.Upstream != "https://openrouter.ai/api/v1" {
		t.Fatal("wrong built-in destination")
	}
	resp, _ = e.req(t, agent, "POST", "/v1/routes", Route{Name: "evil", Secret: "OPENROUTER_API_KEY", Upstream: "https://other.invalid"})
	if resp.StatusCode != 403 {
		t.Fatal("agent selected an arbitrary destination")
	}
}

func TestRunSessionScopesProxyWithoutReadingValues(t *testing.T) {
	e := newTestEnv(t)
	const secret = "real-key-kept-at-server"
	var gotKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Authorization")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	if err := e.st.Set("API_KEY", secret); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Set("UNROUTED", "another-private-value"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetRoute(Route{Name: "service", Secret: "API_KEY", Upstream: upstream.URL}); err != nil {
		t.Fatal(err)
	}
	ro := e.mustCreateToken(t, "runner", "agent")
	resp, body := e.req(t, ro, "POST", "/v1/run", map[string]any{"secrets": []string{"API_KEY"}})
	if resp.StatusCode != 201 {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), secret) {
		t.Fatal("setup revealed a real key")
	}
	var setup runSetup
	if err := json.Unmarshal(body, &setup); err != nil {
		t.Fatal(err)
	}
	if len(setup.Routes) != 1 || setup.Token == ro {
		t.Fatal("missing scoped run credential")
	}
	resp, _ = e.req(t, setup.Token, "GET", "/proxy/service/check", nil)
	if resp.StatusCode != 200 || gotKey != "Bearer "+secret {
		t.Fatal("proxy did not inject the stored key")
	}
	for _, path := range []string{"/v1/env", "/v1/secrets/API_KEY", "/v1/tokens", "/v1/secrets"} {
		resp, _ = e.req(t, setup.Token, "GET", path, nil)
		if resp.StatusCode != 403 {
			t.Fatalf("run token accessed %s: %d", path, resp.StatusCode)
		}
	}
	resp, _ = e.req(t, setup.Token, "GET", "/proxy/other/check", nil)
	if resp.StatusCode != 403 {
		t.Fatal("run token escaped route scope")
	}
	resp, _ = e.req(t, setup.Token, "POST", "/v1/run", map[string]any{})
	if resp.StatusCode != 403 {
		t.Fatal("run token created another lease")
	}
	resp, _ = e.req(t, setup.Token, "DELETE", "/v1/run", nil)
	if resp.StatusCode != 204 {
		t.Fatal("run token cleanup failed")
	}
	resp, _ = e.req(t, setup.Token, "GET", "/proxy/service/check", nil)
	if resp.StatusCode != 401 {
		t.Fatal("run credential remained valid after cleanup")
	}
	entries, err := e.st.AuditLog(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "env" || entry.Action == "get" {
			t.Fatal("proxy setup read raw secrets")
		}
	}
}

func TestRunSessionHandsOverUnroutedAndRevokesWithParent(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("KEY", "handed-over-value")
	ro := e.mustCreateToken(t, "runner", "agent")
	resp, body := e.req(t, ro, "POST", "/v1/run", map[string]any{"secrets": []string{"KEY"}})
	var handed runSetup
	json.Unmarshal(body, &handed)
	if resp.StatusCode != 201 || handed.Values["KEY"] != "handed-over-value" {
		t.Fatalf("hand-over = %d %s", resp.StatusCode, body)
	}
	e.st.SetRoute(Route{Name: "api", Secret: "KEY", Upstream: "https://example.invalid"})
	resp, body = e.req(t, ro, "POST", "/v1/run", map[string]any{})
	if resp.StatusCode != 201 {
		t.Fatalf("setup = %d %s", resp.StatusCode, body)
	}
	var setup runSetup
	json.Unmarshal(body, &setup)
	e.st.RevokeToken("runner")
	resp, _ = e.req(t, setup.Token, "GET", "/proxy/api", nil)
	if resp.StatusCode != 401 {
		t.Fatal("revoked parent still authorizes run")
	}
}

func TestRunLeaseExpiry(t *testing.T) {
	e := newTestEnv(t)
	s := &server{st: e.st, runs: runSessions{leases: map[string]runLease{
		"stash_run_expired": {parent: e.admin, expires: time.Now().Add(-time.Second)},
	}}}
	if _, err := s.tokenForRequest("stash_run_expired"); err == nil {
		t.Fatal("expired run token accepted")
	}
}

func TestProxyEnvironmentRemovesParentAuthorityAndAmbientSecrets(t *testing.T) {
	setup := runSetup{Token: "scoped-token", SecretNames: []string{"API_KEY", "OTHER_KEY", "DB_URL"}, Routes: []runRoute{{Name: "api", Secret: "API_KEY"}}, Values: map[string]string{"DB_URL": "postgres://handed"}}
	env := strings.Join(proxyEnvironment([]string{"PATH=/bin", "STASH_TOKEN=parent-token", "DSH_STASH_TOKEN=parent-token", "API_KEY=real-value", "OTHER_KEY=other-value", "OTHER_KEY_BASE_URL=old-url"}, "http://localhost:8555", setup), "\n")
	for _, private := range []string{"parent-token", "real-value", "other-value", "old-url", "DSH_STASH_TOKEN="} {
		if strings.Contains(env, private) {
			t.Fatalf("child inherited %s", private)
		}
	}
	if strings.Contains(env, "STASH_TOKEN=") {
		t.Fatal("child got a stash token")
	}
	if !strings.Contains(env, "API_KEY=scoped-token") || !strings.Contains(env, "DB_URL=postgres://handed") || !strings.Contains(env, "API_KEY_BASE_URL=http://localhost:8555/proxy/api") {
		t.Fatal("proxy environment is incomplete")
	}
}

func TestRunTokenRenews(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("DB_URL", "postgres://x")
	agent := e.mustCreateToken(t, "agent", "agent")
	_, body := e.req(t, agent, "POST", "/v1/run", map[string]any{})
	var setup runSetup
	json.Unmarshal(body, &setup)
	if resp, _ := e.req(t, setup.Token, "POST", "/v1/run/renew", nil); resp.StatusCode != 204 {
		t.Fatalf("renew = %d", resp.StatusCode)
	}
	if resp, _ := e.req(t, agent, "POST", "/v1/run/renew", nil); resp.StatusCode != 400 {
		t.Fatalf("agent renew = %d", resp.StatusCode)
	}
}
