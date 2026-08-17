package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testEnv struct {
	srv   *httptest.Server
	admin string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	admin, _, err := st.EnsureAdmin()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newMux(st))
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &testEnv{srv: srv, admin: admin}
}

func (e *testEnv) req(t *testing.T, token, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

func (e *testEnv) mustCreateToken(t *testing.T, name, role string) string {
	t.Helper()
	resp, body := e.req(t, e.admin, "POST", "/v1/tokens", map[string]string{"name": name, "role": role})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create token: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Token string `json:"token"`
	}
	json.Unmarshal(body, &out)
	return out.Token
}

func TestHealthNeedsNoAuth(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.req(t, "", "GET", "/v1/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}
}

func TestMissingAndBadTokens(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.req(t, "", "GET", "/v1/secrets", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", resp.StatusCode)
	}
	resp, _ = e.req(t, "stash_bogus", "GET", "/v1/secrets", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token = %d, want 401", resp.StatusCode)
	}
}

func TestSecretCRUDOverHTTP(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent-rw", "rw")

	resp, body := e.req(t, rw, "PUT", "/v1/secrets/API_KEY", map[string]string{"value": "hunter2"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put = %d %s", resp.StatusCode, body)
	}

	resp, body = e.req(t, rw, "GET", "/v1/secrets/API_KEY", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get = %d", resp.StatusCode)
	}
	var got struct{ Name, Value string }
	json.Unmarshal(body, &got)
	if got.Value != "hunter2" {
		t.Fatalf("value = %q", got.Value)
	}

	resp, body = e.req(t, rw, "GET", "/v1/env", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("env = %d", resp.StatusCode)
	}
	var env map[string]string
	json.Unmarshal(body, &env)
	if env["API_KEY"] != "hunter2" {
		t.Fatalf("env = %v", env)
	}

	resp, _ = e.req(t, rw, "DELETE", "/v1/secrets/API_KEY", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d", resp.StatusCode)
	}
	resp, _ = e.req(t, rw, "GET", "/v1/secrets/API_KEY", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete = %d, want 404", resp.StatusCode)
	}
}

func TestReadOnlyTokenCannotWrite(t *testing.T) {
	e := newTestEnv(t)
	ro := e.mustCreateToken(t, "agent-ro", "ro")

	resp, _ := e.req(t, ro, "PUT", "/v1/secrets/X", map[string]string{"value": "v"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ro put = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.req(t, ro, "GET", "/v1/secrets", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ro list = %d, want 200", resp.StatusCode)
	}
}

func TestNonAdminCannotManageTokens(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent-rw", "rw")

	resp, _ := e.req(t, rw, "POST", "/v1/tokens", map[string]string{"name": "evil", "role": "admin"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rw create token = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.req(t, rw, "GET", "/v1/audit", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rw audit = %d, want 403", resp.StatusCode)
	}
}

func TestRevokedTokenStopsWorking(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent-rw", "rw")

	resp, _ := e.req(t, e.admin, "DELETE", "/v1/tokens/agent-rw", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	resp, _ = e.req(t, rw, "GET", "/v1/secrets", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d, want 401", resp.StatusCode)
	}
}

func TestAuditRecordsReads(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent-rw", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v"})
	e.req(t, rw, "GET", "/v1/secrets/K", nil)

	resp, body := e.req(t, e.admin, "GET", "/v1/audit?limit=10", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit = %d", resp.StatusCode)
	}
	var out struct {
		Entries []AuditEntry `json:"entries"`
	}
	json.Unmarshal(body, &out)
	var sawGet bool
	for _, en := range out.Entries {
		if en.Action == "get" && en.Secret == "K" && en.Token == "agent-rw" {
			sawGet = true
		}
	}
	if !sawGet {
		t.Fatalf("no audit entry for the read: %s", body)
	}
}

func TestListSecretsShape(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent-rw", "rw")
	for i := 0; i < 3; i++ {
		e.req(t, rw, "PUT", fmt.Sprintf("/v1/secrets/key_%d", i), map[string]string{"value": "v"})
	}
	resp, body := e.req(t, rw, "GET", "/v1/secrets", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d", resp.StatusCode)
	}
	var out struct {
		Secrets []string `json:"secrets"`
	}
	json.Unmarshal(body, &out)
	if len(out.Secrets) != 3 {
		t.Fatalf("secrets = %v", out.Secrets)
	}
}

func TestProxyInjectsRealKeyAndHidesIt(t *testing.T) {
	e := newTestEnv(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer real-key-123" {
			http.Error(w, "wrong auth: "+r.Header.Get("Authorization"), http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"up":"ok"}`))
	}))
	defer upstream.Close()

	resp, body := e.req(t, e.admin, "PUT", "/v1/secrets/OPENAI", map[string]string{"value": "real-key-123"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set secret = %d %s", resp.StatusCode, body)
	}
	resp, body = e.req(t, e.admin, "POST", "/v1/routes", map[string]string{
		"name": "openai", "upstream": upstream.URL, "secret": "OPENAI",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create route = %d %s", resp.StatusCode, body)
	}

	px := e.mustCreateToken(t, "bot", "proxy")
	resp, body = e.req(t, px, "POST", "/proxy/openai/v1/chat/completions", map[string]string{"model": "gpt"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy = %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"up":"ok"`)) {
		t.Fatalf("proxy body = %s", body)
	}

	// A proxy token must not read raw secrets or lists.
	resp, _ = e.req(t, px, "GET", "/v1/secrets/OPENAI", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token read secret = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.req(t, px, "GET", "/v1/env", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token env = %d, want 403", resp.StatusCode)
	}
}

func TestProxyRouteValidation(t *testing.T) {
	e := newTestEnv(t)
	resp, _ := e.req(t, e.admin, "POST", "/v1/routes", map[string]string{
		"name": "bad", "upstream": "not-a-url", "secret": "X",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad upstream = %d, want 400", resp.StatusCode)
	}
	resp, _ = e.req(t, e.admin, "POST", "/v1/routes", map[string]string{
		"name": "bad2", "upstream": "https://api.example.com", "secret": "X", "header": "no-placeholder",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad header = %d, want 400", resp.StatusCode)
	}
}

func TestProxyMissingRouteAndSecret(t *testing.T) {
	e := newTestEnv(t)
	px := e.mustCreateToken(t, "bot", "proxy")

	resp, _ := e.req(t, px, "GET", "/proxy/nope/v1/x", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing route = %d, want 404", resp.StatusCode)
	}

	e.req(t, e.admin, "POST", "/v1/routes", map[string]string{
		"name": "ghost", "upstream": "https://api.example.com", "secret": "MISSING",
	})
	resp, _ = e.req(t, px, "GET", "/proxy/ghost/v1/x", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("missing secret = %d, want 502", resp.StatusCode)
	}
}

func TestRouteDelete(t *testing.T) {
	e := newTestEnv(t)
	e.req(t, e.admin, "PUT", "/v1/secrets/K", map[string]string{"value": "v"})
	e.req(t, e.admin, "POST", "/v1/routes", map[string]string{
		"name": "r1", "upstream": "https://api.example.com", "secret": "K",
	})
	resp, _ := e.req(t, e.admin, "DELETE", "/v1/routes/r1", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete route = %d", resp.StatusCode)
	}
	px := e.mustCreateToken(t, "bot", "proxy")
	resp, _ = e.req(t, px, "GET", "/proxy/r1/x", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("deleted route = %d, want 404", resp.StatusCode)
	}
}
