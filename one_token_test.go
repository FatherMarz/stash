package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenNeedsPasswordToAddPath(t *testing.T) {
	e := newTestEnv(t)
	tok := e.mustCreateToken(t, "agent", "agent")
	e.st.Set("SERVICE_KEY", "service-value")
	route := map[string]string{"name": "service", "upstream": "https://api.example.com", "secret": "SERVICE_KEY"}
	resp, _ := e.req(t, tok, "POST", "/v1/routes", route)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("add path without password = %d, want 403", resp.StatusCode)
	}
	resp, _ = e.reqPW(t, tok, "guess", "POST", "/v1/routes", route)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("add path with wrong password = %d, want 403", resp.StatusCode)
	}
	resp, body := e.reqPW(t, tok, testPW, "POST", "/v1/routes", route)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add path with password = %d %s", resp.StatusCode, body)
	}
	resp, _ = e.req(t, tok, "DELETE", "/v1/routes/service", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("remove path without password = %d, want 403", resp.StatusCode)
	}
}

func TestBlockedRunTellsAgentWhatToHandOver(t *testing.T) {
	e := newTestEnv(t)
	tok := e.mustCreateToken(t, "agent", "agent")
	e.st.Set("SERVICE_KEY", "service-value")
	resp, body := e.req(t, tok, "POST", "/v1/run", map[string]any{"secrets": []string{"SERVICE_KEY"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("blocked run = %d %s", resp.StatusCode, body)
	}
	for _, want := range []string{"SERVICE_KEY is blocked", "site address and key header", "stash ui"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("message %s lacks %q", body, want)
		}
	}
}

func TestSetupKeepsTokenAndRevokesOwnerTokens(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, _, err := st.EnsureOwner(); err != nil {
		t.Fatal(err)
	}
	old, err := st.NewToken("default-agent", "agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.token"), []byte(old+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := oneToken(st, dir)
	if err != nil || got != old {
		t.Fatalf("oneToken = %q, %v; want the existing token", got, err)
	}
	if err := revokeOwnerTokens(st); err != nil {
		t.Fatal(err)
	}
	tokens, _ := st.ListTokens()
	for _, tk := range tokens {
		if tk.Role == "owner" {
			t.Fatal("owner token survived setup")
		}
	}
	if readTokenFile(dir) != old {
		t.Fatal("token file does not hold the token")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.token")); !os.IsNotExist(err) {
		t.Fatal("old agent.token file is still there")
	}
	info, err := os.Stat(tokenFile(dir))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("token file mode = %v, %v", info.Mode().Perm(), err)
	}
	again, err := oneToken(st, dir)
	if err != nil || again != old {
		t.Fatal("a second setup changed the token")
	}
}

func TestSetupMakesTokenWhenNoneWorks(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	os.WriteFile(tokenFile(dir), []byte("stash_agent_revoked\n"), 0600)
	got, err := oneToken(st, dir)
	if err != nil || !strings.HasPrefix(got, "stash_agent_") || got == "stash_agent_revoked" {
		t.Fatalf("oneToken = %q, %v", got, err)
	}
	if tok, err := st.VerifyToken(got); err != nil || tok.Role != "agent" {
		t.Fatal("new token does not work")
	}
}

func TestSetupWritesOneShellLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	dir := filepath.Join(home, ".stash")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(home, ".zshenv"), []byte("export PATH=/x\nexport STASH_TOKEN=stash_old\n"), 0600)
	os.WriteFile(filepath.Join(home, ".zshrc"), []byte("alias ll='ls -l'\n  export STASH_TOKEN=stash_older"), 0644)

	rc, cleaned, err := writeShellLine(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rc != filepath.Join(home, ".zshrc") || len(cleaned) != 2 {
		t.Fatalf("rc = %s, cleaned = %v", rc, cleaned)
	}
	if _, _, err := writeShellLine(dir); err != nil {
		t.Fatal(err)
	}
	zshrc, _ := os.ReadFile(rc)
	zshenv, _ := os.ReadFile(filepath.Join(home, ".zshenv"))
	if strings.Contains(string(zshenv), "stash_old") || !strings.Contains(string(zshenv), "export PATH=/x") {
		t.Fatalf("zshenv = %s", zshenv)
	}
	if strings.Contains(string(zshrc), "stash_older") || !strings.Contains(string(zshrc), "alias ll") {
		t.Fatalf("zshrc = %s", zshrc)
	}
	if n := strings.Count(string(zshrc), shellMark); n != 1 {
		t.Fatalf("zshrc has %d stash lines:\n%s", n, zshrc)
	}
	if !strings.Contains(string(zshrc), `export STASH_TOKEN="$(cat "$HOME/.stash/token" 2>/dev/null)"`) {
		t.Fatalf("zshrc line = %s", zshrc)
	}
	if info, _ := os.Stat(filepath.Join(home, ".zshenv")); info.Mode().Perm() != 0600 {
		t.Fatal("setup changed the file mode")
	}
}

func TestUIShowsBlockedFirstWithPaths(t *testing.T) {
	names := []string{"WIDGET_KEY", "WIDGET_URL", "OPENAI_API_KEY", "DB_URL", "AWS_SECRET", "AWS_ID"}
	paths := map[string]string{"WIDGET_KEY": "blocked", "WIDGET_URL": "proxy", "OPENAI_API_KEY": "proxy", "DB_URL": "direct", "AWS_SECRET": "proxy", "AWS_ID": "proxy"}
	rows := groupRows(names, nil, paths)
	if !strings.HasPrefix(rows[0].header, "BLOCKED") || rows[1].name != "WIDGET_KEY" {
		t.Fatalf("first rows = %+v", rows[:2])
	}
	for _, r := range rows[2:] {
		if r.name == "WIDGET_KEY" {
			t.Fatal("blocked secret also shows in its group")
		}
	}
	m := &uiModel{names: names, paths: paths, routes: []Route{
		{Name: "widget", Secret: "WIDGET_URL", Upstream: "https://api.widget.example/v2"},
		{Name: "db", Secret: "DB_URL", Kind: "direct"},
		{Name: "prod", Kind: "aws", Secret: "AWS_SECRET", KeyID: "AWS_ID"},
	}}
	for name, want := range map[string]string{
		"WIDGET_KEY":     "blocked",
		"WIDGET_URL":     "→ api.widget.example",
		"OPENAI_API_KEY": "→ api.openai.com (built in)",
		"DB_URL":         "direct: the program gets the real value",
		"AWS_SECRET":     "AWS profile prod",
		"AWS_ID":         "AWS profile prod",
	} {
		if got := m.pathText(name); got != want {
			t.Fatalf("pathText(%s) = %q, want %q", name, got, want)
		}
	}
	if m.blockedCount() != 1 {
		t.Fatal("blocked count")
	}
}
