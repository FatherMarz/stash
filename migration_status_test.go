package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestMigrationHealthExposesVersionAndCapabilitiesWithoutValues(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("PRIVATE", "never-include-this-value")
	response, body := e.req(t, "", "GET", "/v1/health", nil)
	var status struct {
		OK           bool     `json:"ok"`
		Version      string   `json:"version"`
		Capabilities []string `json:"capabilities"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &status) != nil || !status.OK || status.Version != version {
		t.Fatalf("invalid migration status: %d %s", response.StatusCode, body)
	}
	for _, needed := range []string{"explicit_run_scope", "blocked_unconfigured", "owner_direct_connections"} {
		if !strings.Contains(strings.Join(status.Capabilities, ","), needed) {
			t.Fatalf("missing capability %s", needed)
		}
	}
	if strings.Contains(string(body), "never-include-this-value") || strings.Contains(string(body), "PRIVATE") {
		t.Fatal("public status disclosed store data")
	}
}

func TestAgentCanExportCompleteConnectionMetadataWithoutValues(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("AWS_ID", "not-a-real-aws-id")
	e.st.Set("AWS_SECRET", "never-include-this-key")
	if err := e.st.SetRoute(Route{Name: "demo", Kind: "aws", KeyID: "AWS_ID", Secret: "AWS_SECRET"}); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "metadata-agent", "agent")
	t.Setenv("STASH_ADDR", e.srv.URL)
	t.Setenv("STASH_TOKEN", agent)
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	err = cmdRoute([]string{"list", "--json"})
	writer.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Routes []Route `json:"routes"`
	}
	if json.Unmarshal(body, &metadata) != nil || len(metadata.Routes) != 1 || metadata.Routes[0].KeyID != "AWS_ID" || metadata.Routes[0].Secret != "AWS_SECRET" {
		t.Fatalf("incomplete connection metadata: %s", body)
	}
	if strings.Contains(string(body), "never-include-this-key") || strings.Contains(string(body), "not-a-real-aws-id") {
		t.Fatal("connection export disclosed a value")
	}
}
