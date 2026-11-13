package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func pressureServer(t *testing.T) (*server, string) {
	t.Helper()
	st := openTestStore(t)
	agent, err := st.NewToken("pressure-agent", "agent")
	if err != nil {
		t.Fatal(err)
	}
	return &server{st: st, runs: runSessions{leases: map[string]runLease{}}, peerOK: func(*http.Request) bool { return true }}, agent
}

func pressureRequest(s *server, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	s.auth("agent", s.runSession)(recorder, req)
	return recorder
}

func corruptPressureSecret(t *testing.T, st *Store, name string) {
	t.Helper()
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).Put([]byte(name), []byte("deliberately-invalid-ciphertext"))
	}); err != nil {
		t.Fatal(err)
	}
}

func assertPressureDeniedWithoutLease(t *testing.T, s *server, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid selection reached a value read or succeeded: %d %s", response.Code, response.Body.String())
	}
	if len(s.runs.leases) != 0 {
		t.Fatal("invalid selection created a run lease")
	}
	entries, err := s.st.AuditLog(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Action == "run-start" || entry.Action == "get" || entry.Action == "env" {
			t.Fatalf("invalid selection caused secret access: %s", entry.Action)
		}
	}
}

func TestPressureMalformedSelectionsCannotReadValuesOrMintLeases(t *testing.T) {
	for _, body := range []string{
		`null`, `[]`, `{}`, `{"secrets":null}`, `{"secrets":[]}`,
		`{"secrets":[null]}`, `{"secrets":[17]}`, `{"secrets":"DB_URL"}`,
		`{"secrets":["DB_URL",`, `{"secrets":[""]}`, `{"secrets":[" \t\n"]}`,
		`{"secrets":["DB_URL","MISSING"]}`, `{"secrets":["MISSING","DB_URL"]}`,
		`{"secrets":["DB_URL","UNCONFIGURED"]}`, `{"secrets":["UNCONFIGURED","DB_URL"]}`,
	} {
		t.Run(body, func(t *testing.T) {
			s, agent := pressureServer(t)
			if err := s.st.Set("DB_URL", "approved-direct-value"); err != nil {
				t.Fatal(err)
			}
			if err := s.st.Set("UNCONFIGURED", "unconfigured-private-value"); err != nil {
				t.Fatal(err)
			}
			if err := s.st.SetRoute(Route{Name: "database", Kind: "direct", Secret: "DB_URL"}); err != nil {
				t.Fatal(err)
			}
			corruptPressureSecret(t, s.st, "DB_URL")
			assertPressureDeniedWithoutLease(t, s, pressureRequest(s, agent, body))
		})
	}
}

func TestPressureEnvironmentAliasesFailBeforeDirectReadsInEitherOrder(t *testing.T) {
	for _, pair := range [][2]string{
		{"OPENAI_API_KEY", "OPENAI_BASE_URL"},
		{"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL"},
		{"SERVICE_API_KEY", "SERVICE_API_KEY_BASE_URL"},
		{"DB-URL", "DB_URL"},
		{"database.url", "DATABASE_URL"},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/reverse=%v", pair[0], pair[1], reverse), func(t *testing.T) {
				s, agent := pressureServer(t)
				for i, name := range pair {
					if err := s.st.Set(name, "private-value-never-read"); err != nil {
						t.Fatal(err)
					}
					_, builtIn := builtinRoute(name)
					if !builtIn {
						route := Route{Name: fmt.Sprintf("connection-%d", i), Kind: "direct", Secret: name}
						if name == "SERVICE_API_KEY" {
							route.Kind, route.Upstream = "", "https://example.invalid"
						}
						if err := s.st.SetRoute(route); err != nil {
							t.Fatal(err)
						}
						if route.Kind == "direct" {
							corruptPressureSecret(t, s.st, name)
						}
					}
				}
				selection := []string{pair[0], pair[1]}
				if reverse {
					selection[0], selection[1] = selection[1], selection[0]
				}
				body, err := json.Marshal(map[string]any{"secrets": selection})
				if err != nil {
					t.Fatal(err)
				}
				assertPressureDeniedWithoutLease(t, s, pressureRequest(s, agent, string(body)))
			})
		}
	}
}

func TestPressureLargeStoreDoesNotExpandSelectedScope(t *testing.T) {
	s, agent := pressureServer(t)
	for i := 0; i < 500; i++ {
		if err := s.st.Set(fmt.Sprintf("UNCONFIGURED_%03d", i), "private-unselected-value"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DB_URL"} {
		if err := s.st.Set(name, "selected-private-value"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.st.SetRoute(Route{Name: "database", Kind: "direct", Secret: "DB_URL"}); err != nil {
		t.Fatal(err)
	}
	response := pressureRequest(s, agent, `{"secrets":["OPENAI_API_KEY","DB_URL","DB_URL"]}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("scoped setup failed: %d %s", response.Code, response.Body.String())
	}
	var setup runSetup
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if len(setup.Routes) != 1 || setup.Routes[0].Secret != "OPENAI_API_KEY" || len(setup.Values) != 1 || setup.Values["DB_URL"] != "selected-private-value" {
		t.Fatal("selection expanded beyond the named secrets")
	}
	if strings.Contains(response.Body.String(), "private-unselected-value") {
		t.Fatal("unselected secret value escaped the store")
	}
	if len(s.runs.leases) != 1 || len(s.runs.leases[setup.Token].routes) != 1 {
		t.Fatal("lease includes connections outside the selected scope")
	}
}

func TestPressureRunTokenCannotMutateConnectionsOrStore(t *testing.T) {
	e := newTestEnv(t)
	if err := e.st.Set("OPENAI_API_KEY", "server-only-key"); err != nil {
		t.Fatal(err)
	}
	agent := e.mustCreateToken(t, "pressure-runner", "agent")
	response, body := e.req(t, agent, "POST", "/v1/run", map[string]any{"secrets": []string{"OPENAI_API_KEY"}})
	if response.StatusCode != 201 {
		t.Fatalf("run setup: %d %s", response.StatusCode, body)
	}
	var setup runSetup
	if err := json.Unmarshal(body, &setup); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{"POST", "/v1/routes", Route{Name: "raw", Kind: "direct", Secret: "OPENAI_API_KEY"}},
		{"DELETE", "/v1/routes/anything", nil},
		{"PUT", "/v1/secrets/CREATED", map[string]string{"value": "must-not-exist"}},
		{"POST", "/v1/aws/anything", map[string]string{}},
		{"POST", "/v1/run", map[string]any{"secrets": []string{"OPENAI_API_KEY"}}},
	} {
		if response, _ := e.req(t, setup.Token, tc.method, tc.path, tc.body); response.StatusCode != http.StatusForbidden {
			t.Fatalf("run token accessed %s %s: %d", tc.method, tc.path, response.StatusCode)
		}
	}
	if _, err := e.st.Get("CREATED"); err != ErrNotFound {
		t.Fatal("run token changed the secret store")
	}
	routes, err := e.st.ListRoutes()
	if err != nil || len(routes) != 0 {
		t.Fatal("run token changed connections")
	}
}
