package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSecretRoundTrip(t *testing.T) {
	st := openTestStore(t)

	if err := st.Set("OPENAI_API_KEY", "sk-12345"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("OPENAI_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got != "sk-12345" {
		t.Fatalf("got %q, want %q", got, "sk-12345")
	}

	names, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "OPENAI_API_KEY" {
		t.Fatalf("list = %v", names)
	}

	if err := st.Delete("OPENAI_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("OPENAI_API_KEY"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := st.Delete("OPENAI_API_KEY"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestBadSecretNames(t *testing.T) {
	st := openTestStore(t)
	for _, name := range []string{"", "has space", "slash/name", "-leading-dash"} {
		if err := st.Set(name, "v"); err == nil {
			t.Fatalf("name %q was accepted", name)
		}
	}
}

func TestEncryptionAtRest(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := "super-plaintext-value-must-not-appear-on-disk"
	if err := st.Set("db_password", secret); err != nil {
		t.Fatal(err)
	}
	st.Close()

	raw, err := os.ReadFile(filepath.Join(dir, "stash.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext secret found in database file")
	}
}

func TestMasterKeyReuse(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set("a", "1"); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	got, err := st2.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1" {
		t.Fatalf("got %q after reopen", got)
	}
}

func TestTokens(t *testing.T) {
	st := openTestStore(t)

	plain, err := st.NewToken("agent-1", "rw")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := st.VerifyToken(plain)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "agent-1" || tok.Role != "rw" {
		t.Fatalf("token = %+v", tok)
	}

	if _, err := st.NewToken("agent-1", "ro"); err == nil {
		t.Fatal("duplicate token name was accepted")
	}
	if _, err := st.NewToken("agent-2", "boss"); err == nil {
		t.Fatal("invalid role was accepted")
	}
	if _, err := st.VerifyToken("stash_wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	if _, err := st.NewToken("agent-2", "ro"); err != nil {
		t.Fatal(err)
	}
	if err := st.RenameToken("agent-1", "agent-2"); err == nil {
		t.Fatal("rename onto an existing name was accepted")
	}
	if err := st.RenameToken("nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rename missing: want ErrNotFound, got %v", err)
	}
	if err := st.RenameToken("agent-1", "builder"); err != nil {
		t.Fatal(err)
	}
	if tok, err := st.VerifyToken(plain); err != nil || tok.Name != "builder" || tok.Role != "rw" {
		t.Fatalf("after rename: %+v %v", tok, err)
	}

	if err := st.RevokeToken("builder"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyToken(plain); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked token still verifies")
	}
}

func TestEnsureAndResetAdmin(t *testing.T) {
	st := openTestStore(t)

	plain, created, err := st.EnsureAdmin()
	if err != nil || !created || plain == "" {
		t.Fatalf("EnsureAdmin = %q, %v, %v", plain, created, err)
	}
	_, created, err = st.EnsureAdmin()
	if err != nil || created {
		t.Fatalf("second EnsureAdmin created another admin: %v, %v", created, err)
	}

	fresh, err := st.ResetAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyToken(plain); !errors.Is(err, ErrNotFound) {
		t.Fatal("old admin token still verifies after reset")
	}
	if _, err := st.VerifyToken(fresh); err != nil {
		t.Fatal("new admin token does not verify")
	}
}

func TestAuditLog(t *testing.T) {
	st := openTestStore(t)
	for _, name := range []string{"a", "b", "c"} {
		if err := st.Audit("admin", "set", name); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := st.AuditLog(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Secret != "c" {
		t.Fatalf("newest entry = %+v, want secret c", entries[0])
	}
}

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"openai.key":     "OPENAI_KEY",
		"OPENAI_API_KEY": "OPENAI_API_KEY",
		"db-password":    "DB_PASSWORD",
	}
	for in, want := range cases {
		if got := envName(in); got != want {
			t.Errorf("envName(%q) = %q, want %q", in, got, want)
		}
	}
}
