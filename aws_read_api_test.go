package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const exampleGatewayHost = "a1b2c3d4e5.execute-api.us-east-1.amazonaws.com"

func readAPI() *AWSReadAPI {
	return &AWSReadAPI{Host: exampleGatewayHost, Paths: []string{"/ops/review", "/ops/evidence/*"}}
}
func TestAWSReadAPIDefaultDenyAndBoundaries(t *testing.T) {
	route := Route{Kind: "aws", AWSReadAPI: readAPI()}
	for _, row := range []struct {
		method, region, path string
		allowed              bool
	}{
		{"GET", "us-east-1", "/ops/review", true},
		{"GET", "us-east-1", "/ops/evidence/npm/%40scope%2Fpkg/1.0.0", true},
		{"POST", "us-east-1", "/ops/review", false},
		{"HEAD", "us-east-1", "/ops/review", false},
		{"GET", "us-west-2", "/ops/review", false},
		{"GET", "us-east-1", "/ops/label", false},
		{"GET", "us-east-1", "/ops/reviewer", false},
		{"GET", "us-east-1", "/ops/evidence-more/npm/foo/1", false},
		{"GET", "us-east-1", "/ops/evidence/../label", false},
		{"GET", "us-east-1", "/ops/evidence/%2e%2e/label", false},
		{"GET", "us-east-1", "/ops/evidence/%252e%252e/label", false},
		{"GET", "us-east-1", "/ops/evidence/%5clabel", false},
		{"GET", "us-east-1", "/ops/evidence/npm/foo/1%3fpath=label", false},
		{"GET", "us-east-1", "//ops/review", false},
	} {
		host, err := awsReadAPIHost(&route, row.region, row.method, row.path)
		if (err == nil) != row.allowed || row.allowed && host != exampleGatewayHost {
			t.Errorf("%+v -> %q %v", row, host, err)
		}
	}
	route.AWSReadAPI = nil
	if _, err := awsReadAPIHost(&route, "us-east-1", "GET", "/ops/review"); err == nil {
		t.Fatal("existing connection gained access")
	}
}
func TestAWSReadAPIRejectsArbitraryDestinationsAndBroadPaths(t *testing.T) {
	for _, host := range []string{"example.com", "127.0.0.1:8555", exampleGatewayHost + ".evil.test", "https://" + exampleGatewayHost, "*.execute-api.us-east-1.amazonaws.com", exampleGatewayHost + ":443"} {
		api := readAPI()
		api.Host = host
		if validateAWSReadAPI(api) == nil {
			t.Errorf("host accepted: %s", host)
		}
	}
	for _, pattern := range []string{"/*", "/", "/ops/*/label", "/ops/../*", "/ops/%2e%2e/*", "/ops//review"} {
		api := readAPI()
		api.Paths = []string{pattern}
		if validateAWSReadAPI(api) == nil {
			t.Errorf("path accepted: %s", pattern)
		}
	}
}
func TestAWSReadAPIProxySignsOnlyApprovedReads(t *testing.T) {
	e := newTestEnv(t)
	const id = "FAKEAWSKEYID0000"
	const secret = "fake-secret-signing-key"
	e.st.Set("TEST_ID", id)
	e.st.Set("TEST_SECRET", secret)
	route := Route{Name: "demo", Kind: "aws", KeyID: "TEST_ID", Secret: "TEST_SECRET", AWSReadAPI: readAPI()}
	if err := e.st.SetRoute(route); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "reader", "agent")
	_, body := e.req(t, agent, "POST", "/v1/aws/demo", map[string]string{})
	var session struct {
		Token string `json:"token"`
	}
	json.Unmarshal(body, &session)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.EscapedPath() != "/ops/evidence/npm/%40scope%2Fpkg/1.0.0" || r.URL.RawQuery != "before=a%3Ab&limit=1" {
			t.Errorf("request changed: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("X-Amz-Security-Token") != "" {
			t.Error("run token reached upstream")
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+id+"/") || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/execute-api/aws4_request") {
			t.Error("wrong signing scope")
		}
		io.WriteString(w, "response "+id+" "+secret+" "+session.Token)
	}))
	defer server.Close()
	old := awsURL
	awsURL = func(host, p string) string {
		if host != exampleGatewayHost {
			t.Errorf("destination changed: %s", host)
		}
		return server.URL + p
	}
	defer func() { awsURL = old }()
	send := func(method, p, content string) (int, string) {
		req, _ := http.NewRequest(method, e.srv.URL+"/aws/demo"+p, strings.NewReader(content))
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=STASHPROXY/20261116/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=placeholder")
		req.Header.Set("X-Amz-Security-Token", session.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, out := send("GET", "/ops/evidence/npm/%40scope%2Fpkg/1.0.0?before=a%3Ab&limit=1", "")
	if code != 200 || strings.Contains(out, id) || strings.Contains(out, secret) || strings.Contains(out, session.Token) {
		t.Fatalf("unsafe response: code %d", code)
	}
	for _, row := range [][3]string{{"POST", "/ops/label", ""}, {"GET", "/ops/review", "body"}, {"GET", "/ops/backfill", ""}} {
		code, _ := send(row[0], row[1], row[2])
		if code == 200 {
			t.Fatalf("prohibited request passed: %v", row)
		}
	}
	if calls != 1 {
		t.Fatalf("denied requests reached upstream: %d calls", calls)
	}
	for _, token := range []string{agent, session.Token} {
		resp, _ := e.req(t, token, "POST", "/v1/routes", route)
		if resp.StatusCode != 403 {
			t.Fatalf("non-owner changed policy: %d", resp.StatusCode)
		}
	}
}

func TestAWSReadAPIConnectRequiresOwnerAndPreservesExplicitScope(t *testing.T) {
	e := newTestEnv(t)
	t.Setenv("STASH_ADDR", e.srv.URL)
	t.Setenv("STASH_TOKEN", e.admin)
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/config")
	if err := cmdAWSConnect([]string{"demo", "--key-id", "TEST_ID", "--secret-key", "TEST_SECRET", "--read-api-host", exampleGatewayHost, "--read-api-path", "/ops/review", "--read-api-path", "/ops/evidence/*"}); err != nil {
		t.Fatal(err)
	}
	route, err := e.st.GetRoute("demo")
	if err != nil || route.AWSReadAPI == nil || route.AWSReadAPI.Host != exampleGatewayHost || len(route.AWSReadAPI.Paths) != 2 {
		t.Fatal("CLI did not preserve explicit host and paths")
	}
	if err := cmdAWSConnect([]string{"other", "--key-id", "TEST_ID", "--secret-key", "TEST_SECRET", "--read-api-host", exampleGatewayHost}); err == nil {
		t.Fatal("host without paths accepted")
	}
	if err := e.st.SetRoute(Route{Name: "invalid", Kind: "direct", Secret: "OTHER", AWSReadAPI: readAPI()}); err == nil {
		t.Fatal("non-AWS route accepted gateway scope")
	}
}

func awsReadSession(t *testing.T, e *testEnv, agent string) string {
	t.Helper()
	response, body := e.req(t, agent, "POST", "/v1/aws/demo", map[string]string{})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("AWS session status=%d body=%s", response.StatusCode, body)
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.Token == "" {
		t.Fatalf("invalid AWS session: %v", err)
	}
	return session.Token
}

func awsReadRequest(t *testing.T, e *testEnv, token, method, region, path, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+"/aws/demo"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=STASHPROXY/20261116/"+region+"/execute-api/aws4_request, SignedHeaders=host, Signature=placeholder")
	req.Header.Set("X-Amz-Security-Token", token)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(data)
}

func setAWSReadFixture(t *testing.T, e *testEnv, api *AWSReadAPI) Route {
	t.Helper()
	for name, value := range map[string]string{"TEST_ID": "FAKEAWSKEYID0000", "TEST_SECRET": "fake-secret-signing-key"} {
		if err := e.st.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	route := Route{Name: "demo", Kind: "aws", KeyID: "TEST_ID", Secret: "TEST_SECRET", AWSReadAPI: api}
	if err := e.st.SetRoute(route); err != nil {
		t.Fatal(err)
	}
	return route
}

func TestAWSReadAPIReturnsRedirectWithoutFollowingIt(t *testing.T) {
	e := newTestEnv(t)
	setAWSReadFixture(t, e, readAPI())
	agent := e.mustCreateToken(t, "reader", "agent")
	token := awsReadSession(t, e, agent)
	var firstCalls, secondCalls atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		w.Header().Set("Location", second.URL+"/outside-approved-path")
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()
	old := awsURL
	awsURL = func(host, path string) string {
		if host != exampleGatewayHost {
			t.Errorf("unexpected destination: %s", host)
		}
		return first.URL + path
	}
	defer func() { awsURL = old }()
	response, _ := awsReadRequest(t, e, token, "GET", "us-east-1", "/ops/review", "")
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != second.URL+"/outside-approved-path" {
		t.Fatalf("redirect was not returned unchanged: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	if firstCalls.Load() != 1 || secondCalls.Load() != 0 {
		t.Fatalf("unexpected upstream hops: first=%d second=%d", firstCalls.Load(), secondCalls.Load())
	}
}

func TestAWSReadAPILeasesCapturePolicyAndRespectParentRevocation(t *testing.T) {
	e := newTestEnv(t)
	route := setAWSReadFixture(t, e, nil)
	agent := e.mustCreateToken(t, "reader", "agent")
	beforeGrant := awsReadSession(t, e, agent)
	route.AWSReadAPI = readAPI()
	if err := e.st.SetRoute(route); err != nil {
		t.Fatal(err)
	}
	afterGrant := awsReadSession(t, e, agent)
	route.AWSReadAPI = nil
	if err := e.st.SetRoute(route); err != nil {
		t.Fatal(err)
	}
	afterRemoval := awsReadSession(t, e, agent)
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "approved fixture response")
	}))
	defer upstream.Close()
	old := awsURL
	awsURL = func(host, path string) string {
		if host != exampleGatewayHost {
			t.Errorf("unexpected destination: %s", host)
		}
		return upstream.URL + path
	}
	defer func() { awsURL = old }()
	for _, row := range []struct {
		name, token string
		status      int
	}{
		{"before grant", beforeGrant, http.StatusBadRequest},
		{"with captured grant", afterGrant, http.StatusOK},
		{"after removal", afterRemoval, http.StatusBadRequest},
	} {
		response, _ := awsReadRequest(t, e, row.token, "GET", "us-east-1", "/ops/review", "")
		if response.StatusCode != row.status {
			t.Errorf("%s: status=%d want=%d", row.name, response.StatusCode, row.status)
		}
	}
	if err := e.st.RevokeToken("reader"); err != nil {
		t.Fatal(err)
	}
	response, _ := awsReadRequest(t, e, afterGrant, "GET", "us-east-1", "/ops/review", "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked parent still authorized captured grant: %d", response.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("denied or revoked lease reached upstream: %d calls", calls.Load())
	}
}

func TestAWSReadAPIDeniesBeforeReadingCredentials(t *testing.T) {
	e := newTestEnv(t)
	setAWSReadFixture(t, e, readAPI())
	agent := e.mustCreateToken(t, "reader", "agent")
	token := awsReadSession(t, e, agent)
	corruptPressureSecret(t, e.st, "TEST_ID")
	corruptPressureSecret(t, e.st, "TEST_SECRET")
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	old := awsURL
	awsURL = func(host, path string) string { return upstream.URL + path }
	defer func() { awsURL = old }()
	for _, row := range []struct{ name, method, region, path, body string }{
		{"method", "POST", "us-east-1", "/ops/review", ""},
		{"region", "GET", "us-west-2", "/ops/review", ""},
		{"path", "GET", "us-east-1", "/ops/label", ""},
		{"body", "GET", "us-east-1", "/ops/review", "body"},
	} {
		t.Run(row.name, func(t *testing.T) {
			response, body := awsReadRequest(t, e, token, row.method, row.region, row.path, row.body)
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("request passed policy or reached corrupt credential: status=%d body=%s", response.StatusCode, body)
			}
		})
	}
	response, body := awsReadRequest(t, e, token, "GET", "us-east-1", "/ops/review", "")
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(body, "key ID secret is missing") {
		t.Fatalf("control request did not reach corrupt credential: status=%d body=%s", response.StatusCode, body)
	}
	if calls.Load() != 0 {
		t.Fatalf("request reached upstream with corrupt credentials: %d calls", calls.Load())
	}
}
