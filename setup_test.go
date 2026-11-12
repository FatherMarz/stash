package main

import (
	"encoding/json"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestLegacyTokensRequireFreshSetupAndSecretsSurvive(t *testing.T) {
	st := openTestStore(t)
	st.Set("KEY", "existing-secret-value")
	for _, role := range []string{"admin", "ro", "rw", "proxy"} {
		if _, err := st.NewToken(role, role); err == nil {
			t.Fatalf("old role %s accepted", role)
		}
		data, _ := json.Marshal(Token{Name: role, Role: role})
		err := st.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketTokens).Put(hashToken("legacy-"+role), data) })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.VerifyToken("legacy-" + role); err == nil {
			t.Fatalf("legacy %s credential still worked", role)
		}
	}
	if err := st.removeLegacyTokens(); err != nil {
		t.Fatal(err)
	}
	owner, created, err := st.EnsureOwner()
	if err != nil || !created || owner == "" {
		t.Fatal("new owner setup failed")
	}
	tokens, _ := st.ListTokens()
	if len(tokens) != 1 || tokens[0].Role != "owner" {
		t.Fatal("legacy token records survived setup")
	}
	value, err := st.Get("KEY")
	if err != nil || value != "existing-secret-value" {
		t.Fatal("setup changed stored secrets")
	}
}

func TestAgentNeverRevealsValues(t *testing.T) {
	e := newTestEnv(t)
	e.st.Set("OPEN", "private-value")
	agent := e.mustCreateToken(t, "agent", "agent")
	for _, password := range []string{"", testPW} {
		resp, _ := e.reqPW(t, agent, password, "GET", "/v1/secrets/OPEN", nil)
		if resp.StatusCode != 403 {
			t.Fatal("agent read a value")
		}
	}
	e.st.ClearPassword()
	resp, _ := e.req(t, agent, "GET", "/v1/secrets/OPEN", nil)
	if resp.StatusCode != 403 {
		t.Fatal("agent read a value without an owner password")
	}
}
