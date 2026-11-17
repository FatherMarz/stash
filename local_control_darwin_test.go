//go:build darwin

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func shortControlTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "stash-uc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func localFixture(t *testing.T) (string, *http.Client, string, func()) {
	t.Helper()
	dir := shortControlTemp(t)
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := st.NewToken("fixture-agent", "agent")
	if err != nil {
		t.Fatal(err)
	}
	old := peerCheck
	peerCheck = callerIsStash
	mux := newMux(st)
	peerCheck = old
	stop, err := startLocalControl(dir, mux)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 2 * time.Second}
	configureLocalHTTP(hc, "http://127.0.0.1:8555", dir)
	t.Cleanup(func() { stop(); st.Close() })
	return dir, hc, token, stop
}

func localRead(t *testing.T, hc *http.Client, token, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8555"+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestLocalControlKernelIdentityAndTokenRoles(t *testing.T) {
	dir, hc, token, _ := localFixture(t)
	path := filepath.Join(dir, "control", "control.sock")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", st, err)
	}
	ds, _ := os.Stat(filepath.Dir(path))
	if ds.Mode().Perm() != 0700 {
		t.Fatal("control directory not private")
	}
	if code, _ := localRead(t, hc, "", "/v1/routes"); code != 401 {
		t.Fatalf("missing token: %d", code)
	}
	if code, _ := localRead(t, hc, "stash_agent_invalid", "/v1/routes"); code != 401 {
		t.Fatalf("invalid token: %d", code)
	}
	if code, _ := localRead(t, hc, token, "/v1/routes"); code != 200 {
		t.Fatalf("same program agent: %d", code)
	}
	if code, _ := localRead(t, hc, token, "/v1/tokens"); code != 403 {
		t.Fatalf("agent gained owner access: %d", code)
	}
}

func TestLocalControlRejectsForeignClientWithCopiedFixtureTokenAndPIDHeader(t *testing.T) {
	dir, _, token, _ := localFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/curl", "--silent", "--show-error", "--max-time", "2", "--unix-socket", filepath.Join(dir, "control", "control.sock"), "--header", "Authorization: Bearer "+token, "--header", "X-Stash-Client-Pid: "+strconv.Itoa(os.Getpid()), "--output", "/dev/null", "--write-out", "%{http_code}", "http://localhost/v1/routes").Output()
	if err != nil || string(out) != "403" {
		t.Fatalf("foreign client result=%q error=%v", out, err)
	}
}

func TestLocalControlRefusesReplacingActiveSocket(t *testing.T) {
	dir, hc, _, _ := localFixture(t)
	stop, err := startLocalControl(dir, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err == nil {
		stop()
		t.Fatal("replaced active socket")
	}
	if code, _ := localRead(t, hc, "", "/v1/health"); code != 200 {
		t.Fatalf("active listener disturbed: %d", code)
	}
}

func TestLocalControlNoFallbackOrServerCredentialDisclosure(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python fixture unavailable")
	}
	dir := shortControlTemp(t)
	control := filepath.Join(dir, "control")
	os.Mkdir(control, 0700)
	sock := filepath.Join(control, "control.sock")
	code := `import socket,sys
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1)
print('ready',flush=True)
c,_=s.accept();print(len(c.recv(4096)),flush=True)
`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-u", "-c", code, sock)
	out, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 6)
	if _, err := io.ReadFull(out, ready); err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: time.Second}
	configureLocalHTTP(hc, "http://127.0.0.1:8555", dir)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8555/v1/routes", nil)
	req.Header.Set("Authorization", "Bearer fixture-not-a-real-token")
	_, err = hc.Do(req)
	if err == nil || !strings.Contains(err.Error(), "not the Stash program") {
		t.Fatalf("impostor server: %v", err)
	}
	rest, _ := io.ReadAll(out)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("fixture: %v %s", err, stderr.String())
	}
	if strings.TrimSpace(string(rest)) != "0" {
		t.Fatalf("sent auth bytes to impostor server: %q", rest)
	}
}

func TestLocalControlRejectsWritableOrSubstitutedPaths(t *testing.T) {
	dir := shortControlTemp(t)
	os.Chmod(dir, 0777)
	if stop, err := startLocalControl(dir, http.NewServeMux()); err == nil {
		stop()
		t.Fatal("accepted writable data directory")
	}
	os.Chmod(dir, 0700)
	os.Mkdir(filepath.Join(dir, "control"), 0700)
	path := filepath.Join(dir, "control", "control.sock")
	os.WriteFile(path, []byte("keep"), 0600)
	if stop, err := startLocalControl(dir, http.NewServeMux()); err == nil {
		stop()
		t.Fatal("replaced ordinary file")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatal("ordinary file changed")
	}
	hc := &http.Client{Timeout: time.Second}
	configureLocalHTTP(hc, "http://127.0.0.1:8555", dir)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:8555/v1/health", nil)
	if _, err := hc.Do(req); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("silently fell back to TCP: %v", err)
	}
	remote := &http.Client{}
	configureLocalHTTP(remote, "https://example.com", dir)
	if remote.Transport != nil {
		t.Fatal("changed remote transport")
	}
}

func TestLocalControlPreservesExistingDataDirectoryMode(t *testing.T) {
	dir := shortControlTemp(t)
	os.Chmod(dir, 0755)
	stop, err := startLocalControl(dir, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	st, _ := os.Stat(dir)
	if st.Mode().Perm() != 0755 {
		t.Fatal("changed existing data directory permissions")
	}
	child, _ := os.Stat(filepath.Join(dir, "control"))
	if child.Mode().Perm() != 0700 {
		t.Fatal("control directory not private")
	}
}

func TestLocalControlStreamingUsesVerifiedTransport(t *testing.T) {
	_, hc, token, _ := localFixture(t)
	c := &client{addr: "http://127.0.0.1:8555", token: token, http: hc}
	resp, err := c.stream(context.Background(), "GET", "/v1/routes", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("streaming status=%d", resp.StatusCode)
	}
}

func TestLocalControlCLIFromSeparateProcess(t *testing.T) {
	if os.Getenv("STASH_LOCAL_CONTROL_CLI_FIXTURE") == "1" {
		if err := cmdList([]string{"--json"}); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	home := shortControlTemp(t)
	dir := filepath.Join(home, ".stash")
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Set("FIXTURE_API_KEY", "fixture-value-never-valid"); err != nil {
		t.Fatal(err)
	}
	token, err := st.NewToken("fixture-agent", "agent")
	if err != nil {
		t.Fatal(err)
	}
	old := peerCheck
	peerCheck = callerIsStash
	mux := newMux(st)
	peerCheck = old
	stop, err := startLocalControl(dir, mux)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLocalControlCLIFromSeparateProcess$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "STASH_TOKEN=" + token, "STASH_LOCAL_CONTROL_CLI_FIXTURE=1"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture CLI failed: %v", err)
	}
	if !bytes.Contains(output, []byte("FIXTURE_API_KEY")) || bytes.Contains(output, []byte("fixture-value-never-valid")) || bytes.Contains(output, []byte(token)) {
		t.Fatal("fixture CLI did not list metadata safely through the private socket")
	}
}

func TestLocalControlRecoversOnlyOwnedDeadSocket(t *testing.T) {
	dir := shortControlTemp(t)
	control := filepath.Join(dir, "control")
	os.Mkdir(control, 0700)
	path := filepath.Join(control, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	listener.Close()
	stop, err := startLocalControl(dir, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		t.Fatal("dead socket was not safely replaced")
	}
}
