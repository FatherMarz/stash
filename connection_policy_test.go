package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestRunRequiresSelectionAndBlocksUnconfiguredSecrets(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("UNKNOWN_API_KEY", "unconfigured-private-key")
	e.st.Set("DB_URL", "postgres://private")
	agent := e.mustCreateToken(t, "runner", "agent")
	for _, selection := range []any{map[string]any{}, map[string]any{"secrets": nil}, map[string]any{"secrets": []string{}}, map[string]any{"secrets": []string{"UNKNOWN_API_KEY"}}, map[string]any{"secrets": []string{"DB_URL"}}} {
		resp, body := e.req(t, agent, "POST", "/v1/run", selection)
		if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "unconfigured-private-key") || strings.Contains(string(body), "postgres://private") {
			t.Fatalf("selection %v: %d %s", selection, resp.StatusCode, body)
		}
	}
	resp, body := e.req(t, agent, "GET", "/v1/secrets", nil)
	var listed struct {
		Paths map[string]string `json:"paths"`
	}
	json.Unmarshal(body, &listed)
	if resp.StatusCode != 200 || listed.Paths["DB_URL"] != "blocked" || listed.Paths["UNKNOWN_API_KEY"] != "blocked" {
		t.Fatalf("paths: %d %s", resp.StatusCode, body)
	}
	entries, _ := e.st.AuditLog(100)
	for _, entry := range entries {
		if entry.Action == "run-start" {
			t.Fatal("denied request created a run")
		}
	}
}

func TestMixedDeniedSelectionDoesNotReadDirectValues(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("DB_URL", "postgres://private")
	e.st.Set("UNCONFIGURED", "private-value")
	if err := e.st.SetRoute(Route{Name: "database", Secret: "DB_URL", Kind: "direct"}); err != nil {
		t.Fatal(err)
	}
	// A read of this value fails. A blocked selection must fail before that read.
	if err := e.st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).Put([]byte("DB_URL"), []byte("invalid-ciphertext"))
	}); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "runner", "agent")
	resp, body := e.req(t, agent, "POST", "/v1/run", map[string]any{"secrets": []string{"DB_URL", "UNCONFIGURED"}})
	if resp.StatusCode != 400 || !strings.Contains(string(body), "UNCONFIGURED is blocked") {
		t.Fatalf("mixed selection: %d %s", resp.StatusCode, body)
	}
}

func TestOnlyOwnerCanApproveDirectConnection(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("DB_URL", "postgres://approved-direct-value")
	agent := e.mustCreateToken(t, "runner", "agent")
	route := Route{Name: "database", Secret: "DB_URL", Kind: "direct"}
	if resp, _ := e.req(t, agent, "POST", "/v1/routes", route); resp.StatusCode != 403 {
		t.Fatal("agent approved its own direct access")
	}
	if resp, body := e.req(t, e.admin, "POST", "/v1/routes", route); resp.StatusCode != 201 {
		t.Fatalf("owner approval: %d %s", resp.StatusCode, body)
	}
	resp, body := e.req(t, agent, "POST", "/v1/run", map[string]any{"secrets": []string{"DB_URL"}})
	var setup runSetup
	json.Unmarshal(body, &setup)
	if resp.StatusCode != 201 || setup.Values["DB_URL"] != "postgres://approved-direct-value" || len(setup.Routes) != 0 {
		t.Fatalf("approved direct: %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.req(t, agent, "GET", "/proxy/database", nil); resp.StatusCode != 400 {
		t.Fatal("direct connection accepted as an HTTP proxy")
	}
}

func TestConnectionPolicyRejectsAmbiguousAndProtectedDirectAccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		existing *Route
		bad      Route
	}{
		{"builtin", nil, Route{Name: "raw", Secret: "OPENAI_API_KEY", Kind: "direct"}},
		{"direct upstream", nil, Route{Name: "raw", Secret: "DB_URL", Kind: "direct", Upstream: "https://example.invalid"}},
		{"direct header", nil, Route{Name: "raw", Secret: "DB_URL", Kind: "direct", Header: "Authorization: {value}"}},
		{"direct key id", nil, Route{Name: "raw", Secret: "DB_URL", Kind: "direct", KeyID: "KEY_ID"}},
		{"duplicate direct", &Route{Name: "one", Secret: "DB_URL", Kind: "direct"}, Route{Name: "two", Secret: "DB_URL", Kind: "direct"}},
		{"proxy downgrade", &Route{Name: "api", Secret: "API_KEY", Upstream: "https://example.invalid"}, Route{Name: "api", Secret: "API_KEY", Kind: "direct"}},
		{"competing direct", &Route{Name: "api", Secret: "API_KEY", Upstream: "https://example.invalid"}, Route{Name: "raw", Secret: "API_KEY", Kind: "direct"}},
		{"AWS key direct", &Route{Name: "aws", Kind: "aws", KeyID: "KEY_ID", Secret: "KEY_SECRET"}, Route{Name: "raw", Kind: "direct", Secret: "KEY_ID"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := openTestStore(t)
			if tc.existing != nil {
				if err := st.SetRoute(*tc.existing); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.SetRoute(tc.bad); err == nil {
				t.Fatal("unsafe connection accepted")
			}
		})
	}
}

func TestLegacyMalformedConnectionsRemainBlocked(t *testing.T) {
	for _, routes := range [][]Route{
		{{Name: "raw", Secret: "KEY", Kind: "direct", Upstream: "https://example.invalid"}},
		{{Name: "one", Secret: "KEY", Kind: "direct"}, {Name: "two", Secret: "KEY", Upstream: "https://example.invalid"}},
		{{Name: "raw", Secret: "OPENAI_API_KEY", Kind: "direct"}},
	} {
		paths := secretKinds([]string{"KEY", "OPENAI_API_KEY"}, routes)
		if len(routes) == 1 && routes[0].Secret == "OPENAI_API_KEY" {
			if paths["OPENAI_API_KEY"] != "blocked" {
				t.Fatal("persisted direct route bypassed built-in proxy policy")
			}
		} else if paths["KEY"] != "blocked" {
			t.Fatal("malformed or ambiguous direct connection remained available")
		}
	}
	paths := secretKinds([]string{"KEY_ID", "KEY_SECRET"}, []Route{{Name: "raw", Secret: "KEY_SECRET", Kind: "direct"}, {Name: "aws", Kind: "aws", KeyID: "KEY_ID", Secret: "KEY_SECRET"}})
	if paths["KEY_ID"] != "aws" || paths["KEY_SECRET"] != "aws" {
		t.Fatal("persisted direct connection exposed an AWS pair")
	}
}

func TestDirectConnectionCLIRequiresExplicitSafeArguments(t *testing.T) {
	e := newTestEnv(t)
	t.Setenv("STASH_ADDR", e.srv.URL)
	t.Setenv("STASH_TOKEN", e.admin)
	if err := cmdRoute([]string{"create", "database", "--secret", "DB_URL", "--direct"}); err != nil {
		t.Fatal(err)
	}
	route, err := e.st.GetRoute("database")
	if err != nil || route.Kind != "direct" || route.Secret != "DB_URL" {
		t.Fatalf("direct connection: %+v %v", route, err)
	}
	for _, args := range [][]string{
		{"create", "bad", "--secret", "DB_URL", "--direct", "--upstream", "https://example.invalid"},
		{"create", "bad", "--secret", "DB_URL", "--direct", "--header", "X-Key: {value}"},
		{"create", "bad", "--direct"},
		{"create", "bad", "--secret", "DB_URL"},
	} {
		if err := cmdRoute(args); err == nil {
			t.Fatalf("invalid direct arguments accepted: %v", args)
		}
	}
}

func TestAgentCanInspectConnectionPathsWithoutReadingValues(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("UNKNOWN_API_KEY", "private-unrouted-value")
	e.st.Set("OPENAI_API_KEY", "private-proxied-value")
	e.st.Set("DB_URL", "postgres://private-value")
	if err := e.st.SetRoute(Route{Name: "database", Kind: "direct", Secret: "DB_URL"}); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "setup-agent", "agent")
	t.Setenv("STASH_ADDR", e.srv.URL)
	t.Setenv("STASH_TOKEN", agent)
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	os.Stdout = writer
	defer func() { os.Stdout = previous }()
	err = cmdList([]string{"--json"})
	writer.Close()
	os.Stdout = previous
	if err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var status struct {
		Paths map[string]string `json:"paths"`
	}
	if err := json.Unmarshal(output, &status); err != nil {
		t.Fatal(err)
	}
	if status.Paths["UNKNOWN_API_KEY"] != "blocked" || status.Paths["OPENAI_API_KEY"] != "proxy" || status.Paths["DB_URL"] != "direct" || strings.Contains(string(output), "private-") {
		t.Fatalf("unsafe setup status: %s", output)
	}
}
