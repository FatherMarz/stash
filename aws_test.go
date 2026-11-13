package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAWSCredentialScopeAndHost(t *testing.T) {
	region, service, err := awsCredential("AWS4-HMAC-SHA256 Credential=STASHPROXY/20261112/ca-central-1/sts/aws4_request, SignedHeaders=host, Signature=x")
	if err != nil || region != "ca-central-1" || service != "sts" {
		t.Fatalf("scope = %s %s %v", region, service, err)
	}
	if _, _, err := awsCredential("AWS4-HMAC-SHA256 Credential=K/D/evil.com#/s3/aws4_request"); err == nil {
		t.Fatal("a region with host characters was accepted")
	}
	for in, want := range map[[2]string]string{
		{"s3", "us-west-2"}:           "s3.us-west-2.amazonaws.com",
		{"iam", "us-east-1"}:          "iam.amazonaws.com",
		{"ses", "eu-west-1"}:          "email.eu-west-1.amazonaws.com",
		{"codebuild", "ca-central-1"}: "codebuild.ca-central-1.amazonaws.com",
	} {
		if got, _ := awsHost(in[0], in[1], "/"); got != want {
			t.Fatalf("%v -> %s, want %s", in, got, want)
		}
	}
}

func TestAWSProxySignsWithStoredKeyPair(t *testing.T) {
	e := newTestEnv(t)
	var got *http.Request
	var gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`<ok>AKIAREALKEY0000 echoed</ok>`))
	}))
	defer upstream.Close()
	old := awsURL
	awsURL = func(host, path string) string { return upstream.URL + path + "#" + host }
	defer func() { awsURL = old }()

	e.st.Set("AWS_ID", "AKIAREALKEY0000")
	e.st.Set("AWS_SECRET", "real-secret-access-key")
	if err := e.st.SetRoute(Route{Name: "vigi", Kind: "aws", KeyID: "AWS_ID", Secret: "AWS_SECRET"}); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "aws-agent", "agent")
	resp, body := e.req(t, agent, "POST", "/v1/aws/vigi", map[string]string{})
	if resp.StatusCode != 201 || strings.Contains(string(body), "real-secret") {
		t.Fatalf("session = %d %s", resp.StatusCode, body)
	}
	token := strings.Split(strings.Split(string(body), `"token":"`)[1], `"`)[0]

	req, _ := http.NewRequest("POST", e.srv.URL+"/aws/vigi/", strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=STASHPROXY/20261112/ca-central-1/sts/aws4_request, SignedHeaders=host, Signature=placeholder")
	req.Header.Set("X-Amz-Security-Token", token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("aws call = %d %s", res.StatusCode, out)
	}
	auth := got.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIAREALKEY0000/") || !strings.Contains(auth, "/ca-central-1/sts/aws4_request") || strings.Contains(auth, "placeholder") {
		t.Fatalf("not re-signed: %s", auth)
	}
	if got.Header.Get("X-Amz-Security-Token") != "" || got.Header.Get("X-Amz-Date") == "" {
		t.Fatal("run token went to AWS, or the date is missing")
	}
	if gotBody != "Action=GetCallerIdentity&Version=2011-06-15" {
		t.Fatalf("body = %q", gotBody)
	}
	if strings.Contains(string(out), "AKIAREALKEY0000") {
		t.Fatal("key ID echoed back to the program")
	}

	// The token works only for this connection, and never on stash itself.
	for _, path := range []string{"/v1/secrets", "/v1/secrets/AWS_SECRET"} {
		if resp, _ := e.req(t, token, "GET", path, nil); resp.StatusCode != 403 {
			t.Fatalf("aws token reached %s: %d", path, resp.StatusCode)
		}
	}
	// AWS keys are never handed to stash run.
	resp, body = e.req(t, agent, "POST", "/v1/run", map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("run without selection = %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "real-secret") || strings.Contains(string(body), "AKIAREAL") {
		t.Fatalf("run handed over an AWS key: %s", body)
	}
	if resp, _ := e.req(t, agent, "POST", "/v1/run", map[string]any{"secrets": []string{"AWS_SECRET"}}); resp.StatusCode != 400 {
		t.Fatal("run accepted an AWS key by name")
	}
}

func TestAgentTokenOnlyThroughStashProgram(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("DB_URL", "postgres://secret")
	agent := e.mustCreateToken(t, "agent", "agent")
	peerCheck = func(*http.Request) bool { return false }
	defer func() { peerCheck = func(*http.Request) bool { return true } }()
	// newMux captured the old check. Build a fresh server for this test.
	srv := httptest.NewServer(newMux(e.st))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/run", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+agent)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 403 || strings.Contains(string(body), "postgres://secret") {
		t.Fatalf("curl with the agent token = %d %s", res.StatusCode, body)
	}
}

func TestWriteAWSProfileKeepsRegion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("[profile other]\nregion = us-east-1\n\n[profile vigi]\nregion = ca-central-1\ncredential_process = /old/script.sh\ns3 =\n    addressing_style = virtual\noutput = json\n"), 0o600)
	if err := writeAWSProfile(path, "vigi", "http://127.0.0.1:8555"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{"region = ca-central-1", "output = json", "aws creds vigi", "endpoint_url = http://127.0.0.1:8555/aws/vigi", "addressing_style = path", "[profile other]\nregion = us-east-1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/old/script.sh") || strings.Contains(text, "virtual") {
		t.Fatalf("old lines kept:\n%s", text)
	}
}

func TestFindAWSProfilesUsingStashGet(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "creds.sh")
	os.WriteFile(script, []byte("id=\"$(stash get VIGI_LENNY_KEY_ID)\"\nsecret=\"$(stash get VIGI_LENNY_KEY_SECRET)\"\n"), 0o700)
	path := filepath.Join(dir, "config")
	os.WriteFile(path, []byte("[profile vigi-lenny]\nregion = ca-central-1\ncredential_process = "+script+"\n"), 0o600)
	got := awsProfilesUsingStash(path)
	if len(got) != 1 || got[0] != (awsLegacyProfile{"vigi-lenny", "VIGI_LENNY_KEY_ID", "VIGI_LENNY_KEY_SECRET"}) {
		t.Fatalf("found %+v", got)
	}
}
