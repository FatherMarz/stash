package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestEnvRequiresOwnerAndPassword(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("K", "v12345678")
	agent := e.mustCreateToken(t, "agent", "agent")
	for _, token := range []string{agent, e.admin} {
		resp, _ := e.req(t, token, "GET", "/v1/env", nil)
		if resp.StatusCode != 403 {
			t.Fatalf("export without password = %d", resp.StatusCode)
		}
	}
	resp, _ := e.reqPW(t, agent, testPW, "GET", "/v1/env", nil)
	if resp.StatusCode != 403 {
		t.Fatal("agent exported raw secrets with owner password")
	}
}

func TestEnvWithOwnerPassword(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "owner")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v12345678"})
	resp, _ := e.reqPW(t, rw, testPW, "GET", "/v1/env", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("env with password = %d, want 200", resp.StatusCode)
	}
}

func TestPeerCheckRejectsCurlLikeClients(t *testing.T) {
	// The test binary is not the stash binary, and a remote address never passes.
	if peerIsStash("10.0.0.5:5000", "127.0.0.1:8555") {
		t.Fatal("remote address passed")
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
	rw := e.mustCreateToken(t, "agent", "owner")
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
	rw := e.mustCreateToken(t, "agent", "agent")

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

func TestLockIsOffUntilPasswordSet(t *testing.T) {
	e := newTestEnv(t)
	if err := e.st.ClearPassword(); err != nil {
		t.Fatal(err)
	}
	rw := e.mustCreateToken(t, "agent", "owner")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v1234"})
	resp, body := e.req(t, rw, "GET", "/v1/secrets/K", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "v1234") {
		t.Fatalf("read with no password set = %d %s", resp.StatusCode, body)
	}
	resp, _ = e.req(t, rw, "GET", "/v1/env", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("env with no password set = %d", resp.StatusCode)
	}
}

func TestMissingPasswordDoesNotLockOut(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "owner")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v1234"})
	for i := 0; i < guardMaxFails*3; i++ {
		resp, body := e.req(t, rw, "GET", "/v1/secrets/K", nil)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "needs the owner password") {
			t.Fatalf("try %d = %d %s", i, resp.StatusCode, body)
		}
	}
	resp, _ := e.reqPW(t, rw, testPW, "GET", "/v1/secrets/K", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner after agent tries = %d, want 200", resp.StatusCode)
	}
	resp, body := e.reqPW(t, rw, "guess", "GET", "/v1/secrets/K", nil)
	if !strings.Contains(string(body), "wrong owner password") {
		t.Fatalf("wrong password = %d %s", resp.StatusCode, body)
	}
}

func TestGroupsFollowSecrets(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "owner")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v1234"})
	resp, _ := e.req(t, rw, "PUT", "/v1/groups/K", map[string]string{"group": "Client work"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set group = %d", resp.StatusCode)
	}
	resp, body := e.req(t, rw, "GET", "/v1/groups", nil)
	if !strings.Contains(string(body), `"K":"Client work"`) {
		t.Fatalf("groups = %s", body)
	}
	resp, _ = e.req(t, rw, "PUT", "/v1/groups/NOPE", map[string]string{"group": "x"})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("group for missing secret = %d, want 404", resp.StatusCode)
	}
	e.req(t, rw, "DELETE", "/v1/secrets/K", nil)
	_, body = e.req(t, rw, "GET", "/v1/groups", nil)
	if strings.Contains(string(body), "Client work") {
		t.Fatalf("group outlived its secret: %s", body)
	}
}
