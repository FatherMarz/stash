package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestEnvAnswersOnlyTheStashBinary(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v12345678"})

	resp, _ := e.req(t, rw, "GET", "/v1/env", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("env from another program = %d, want 403", resp.StatusCode)
	}

	orig := peerCheck
	peerCheck = func(string, string) bool { return true }
	t.Cleanup(func() { peerCheck = orig })
	e2 := newTestEnv(t)
	rw2 := e2.mustCreateToken(t, "agent", "rw")
	e2.req(t, rw2, "PUT", "/v1/secrets/K", map[string]string{"value": "v12345678"})
	resp, body := e2.req(t, rw2, "GET", "/v1/env", nil)
	var env map[string]string
	json.Unmarshal(body, &env)
	if resp.StatusCode != http.StatusOK || env["K"] != "v12345678" {
		t.Fatalf("env from stash = %d %s", resp.StatusCode, body)
	}
}

func TestEnvWithOwnerPassword(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
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

func TestLockIsOffUntilPasswordSet(t *testing.T) {
	e := newTestEnv(t)
	if err := e.st.ClearPassword(); err != nil {
		t.Fatal(err)
	}
	rw := e.mustCreateToken(t, "agent", "rw")
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

func TestOpenSecretSkipsPassword(t *testing.T) {
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/HELPER", map[string]string{"value": "v1234"})

	resp, _ := e.req(t, rw, "PUT", "/v1/open/HELPER", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rw open = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.req(t, e.admin, "PUT", "/v1/open/HELPER", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin open without password = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.reqPW(t, e.admin, testPW, "PUT", "/v1/open/HELPER", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin open = %d", resp.StatusCode)
	}
	resp, body := e.req(t, rw, "GET", "/v1/secrets/HELPER", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "v1234") {
		t.Fatalf("read open secret = %d %s", resp.StatusCode, body)
	}
	resp, body = e.req(t, rw, "GET", "/v1/open", nil)
	if !strings.Contains(string(body), "HELPER") {
		t.Fatalf("open list = %s", body)
	}
	e.reqPW(t, e.admin, testPW, "DELETE", "/v1/open/HELPER", nil)
	resp, _ = e.req(t, rw, "GET", "/v1/secrets/HELPER", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read closed secret = %d, want 403", resp.StatusCode)
	}
}

// TestPeerCheckWithRealProcesses starts a copy of this test binary as the
// client (it stands in for stash), then curl, against the real peer check.
func TestPeerCheckWithRealProcesses(t *testing.T) {
	if os.Getenv("STASH_TEST_CLIENT") != "" {
		return
	}
	e := newTestEnv(t)
	rw := e.mustCreateToken(t, "agent", "rw")
	e.req(t, rw, "PUT", "/v1/secrets/K", map[string]string{"value": "v12345678"})

	same := exec.Command(os.Args[0], "-test.run=^TestPeerClientHelper$")
	same.Env = append(os.Environ(), "STASH_TEST_CLIENT="+e.srv.URL+"/v1/env", "STASH_TEST_TOKEN="+rw)
	out, err := same.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "status=200") {
		t.Fatalf("same program: %v %s", err, out)
	}

	curl, err := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Authorization: Bearer "+rw, e.srv.URL+"/v1/env").Output()
	if err != nil || string(curl) != "403" {
		t.Fatalf("curl = %s %v, want 403", curl, err)
	}
}

func TestPeerClientHelper(t *testing.T) {
	url := os.Getenv("STASH_TEST_CLIENT")
	if url == "" {
		t.Skip("helper process only")
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("STASH_TEST_TOKEN"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("status=%d\n", resp.StatusCode)
}
