package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

type server struct {
	st    *Store
	guard guard
	runs  runSessions
	// peerOK reports whether the caller is the stash program itself. Agent
	// tokens only work through it, so a token copied into curl does nothing.
	peerOK func(*http.Request) bool
}

// peerCheck is a variable so tests can stand in for the stash program.
var peerCheck = callerIsStash

func callerIsStash(r *http.Request) bool {
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	return ok && peerIsStash(r.RemoteAddr, local.String())
}

func newMux(st *Store) *http.ServeMux {
	s := &server{st: st, runs: runSessions{leases: make(map[string]runLease)}, peerOK: peerCheck}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version,
			"capabilities": []string{"explicit_run_scope", "blocked_unconfigured", "owner_direct_connections"}})
	})
	mux.HandleFunc("GET /v1/secrets", s.auth("agent", s.listSecrets))
	mux.HandleFunc("GET /v1/secrets/{name}", s.auth("owner", s.getSecret))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.auth("agent", s.putSecret))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.auth("owner", s.deleteSecret))
	mux.HandleFunc("POST /v1/secrets/{name}/rename", s.auth("owner", s.renameSecret))
	mux.HandleFunc("GET /v1/env", s.auth("owner", s.envSecrets))
	mux.HandleFunc("POST /v1/run", s.auth("agent", s.runSession))
	mux.HandleFunc("DELETE /v1/run", s.auth("agent", s.revokeRun))
	mux.HandleFunc("POST /v1/run/renew", s.auth("agent", s.renewRun))
	mux.HandleFunc("GET /v1/groups", s.auth("agent", s.listGroups))
	mux.HandleFunc("PUT /v1/groups/{name}", s.auth("owner", s.setGroup))
	mux.HandleFunc("GET /v1/password", s.auth("owner", s.passwordStatus))
	mux.HandleFunc("PUT /v1/password", s.auth("owner", s.setPassword))
	mux.HandleFunc("POST /v1/tokens", s.auth("owner", s.createToken))
	mux.HandleFunc("GET /v1/tokens", s.auth("owner", s.listTokens))
	mux.HandleFunc("DELETE /v1/tokens/{name}", s.auth("owner", s.revokeToken))
	mux.HandleFunc("POST /v1/tokens/{name}/rename", s.auth("owner", s.renameToken))
	mux.HandleFunc("GET /v1/audit", s.auth("owner", s.listAudit))
	mux.HandleFunc("POST /v1/routes", s.auth("owner", s.createRoute))
	mux.HandleFunc("GET /v1/routes", s.auth("agent", s.listRoutes))
	mux.HandleFunc("DELETE /v1/routes/{name}", s.auth("owner", s.deleteRoute))
	mux.HandleFunc("/proxy/{route}", s.auth("agent", s.proxyRequest))
	mux.HandleFunc("/proxy/{route}/{rest...}", s.auth("agent", s.proxyRequest))
	mux.HandleFunc("POST /v1/aws/{route}", s.auth("agent", s.awsSession))
	mux.HandleFunc("/aws/{route}/{rest...}", s.auth("agent", s.awsRequest))
	mux.HandleFunc("/aws/{route}", s.auth("agent", s.awsRequest))
	return mux
}

// Owners manage the store. Agents can only discover names and use proxies.
func roleAllows(have, need string) bool {
	return (have == "owner" && (need == "owner" || need == "agent")) || (have == "agent" && need == "agent")
}

func isStashToken(v string) bool {
	v = strings.TrimPrefix(v, "Bearer ")
	return strings.HasPrefix(v, "stash_run_") || strings.HasPrefix(v, "stash_agent_") || strings.HasPrefix(v, "stash_owner_")
}

func requestToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	if strings.HasPrefix(r.URL.Path, "/proxy/") {
		if v := r.Header.Get("X-Api-Key"); v != "" {
			return v
		}
		// APIs use their own key header (x-apikey, X-Subscription-Token, ...).
		// Take the stand-in from whichever header carries a stash token.
		for name := range r.Header {
			if v := r.Header.Get(name); isStashToken(v) {
				return v
			}
		}
		return ""
	}
	if strings.HasPrefix(r.URL.Path, "/aws/") {
		return r.Header.Get("X-Amz-Security-Token")
	}
	return ""
}

func (s *server) auth(need string, h func(http.ResponseWriter, *http.Request, *Token)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		plain := requestToken(r)
		if plain == "" {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok, err := s.tokenForRequest(plain)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid or old token; stash 0.5 requires a new owner or agent token from stash setup")
			return
		}
		run := strings.HasPrefix(plain, "stash_run_")
		if !roleAllows(tok.Role, need) || (run && !(strings.HasPrefix(r.URL.Path, "/proxy/") || strings.HasPrefix(r.URL.Path, "/aws/") || (r.Method == "DELETE" && r.URL.Path == "/v1/run") || (r.Method == "POST" && r.URL.Path == "/v1/run/renew"))) {
			writeErr(w, http.StatusForbidden, "token role does not allow this operation")
			return
		}
		if tok.Role == "agent" && !run && !s.peerOK(r) {
			writeErr(w, http.StatusForbidden, "the agent token works only through the stash command. Use stash run")
			return
		}
		h(w, r, tok)
	}
}

func (s *server) listSecrets(w http.ResponseWriter, r *http.Request, tok *Token) {
	names, err := s.st.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "list", "")
	if names == nil {
		names = []string{}
	}
	routes, err := s.st.ListRoutes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": names, "paths": secretPaths(names, routes)})
}

func (s *server) getSecret(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	if !s.ownerPassword(w, r, tok, name) {
		return
	}
	value, err := s.st.Get(name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "get", name)
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "value": value})
}

// ownerPassword checks the X-Stash-Password header. It writes the error
// response and returns false on failure. Until the owner sets a password the
// lock is off and every token reads as before.
func (s *server) ownerPassword(w http.ResponseWriter, r *http.Request, tok *Token, secret string) bool {
	err := s.guard.check(s.st, r.Header.Get("X-Stash-Password"))
	switch {
	case err == nil, errors.Is(err, ErrNoPassword):
		return true
	case errors.Is(err, ErrNeedPassword):
		s.st.Audit(tok.Name, "reveal-denied", secret)
		writeErr(w, http.StatusForbidden, "reading a value needs the owner password. Agents: use `stash run` or a proxy route instead")
	case errors.Is(err, ErrWrongPassword):
		s.st.Audit(tok.Name, "wrong-password", secret)
		writeErr(w, http.StatusForbidden, "wrong owner password")
	case errors.Is(err, ErrLocked):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
	return false
}

func (s *server) passwordStatus(w http.ResponseWriter, r *http.Request, tok *Token) {
	has, err := s.st.HasPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"set": has})
}

// setPassword sets the owner password. To change it, the old password goes
// in X-Stash-Password.
func (s *server) setPassword(w http.ResponseWriter, r *http.Request, tok *Token) {
	var body struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"password": "..."}`)
		return
	}
	has, err := s.st.HasPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if has && !s.ownerPassword(w, r, tok, "") {
		return
	}
	if err := s.st.SetPassword(r.Header.Get("X-Stash-Password"), body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "password-set", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) putSecret(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	var body struct {
		Value string `json:"value"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"value": "..."}`)
		return
	}
	if tok.Role != "owner" {
		if _, err := s.st.Get(name); err == nil {
			writeErr(w, http.StatusForbidden, "only the owner can change an existing secret")
			return
		}
	}
	if err := s.st.Set(name, body.Value); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "set", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteSecret(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	err := s.st.Delete(name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "delete", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) renameSecret(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	var body struct {
		Name string `json:"name"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"name": "..."}`)
		return
	}
	err := s.st.Rename(name, body.Name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "rename", name+" -> "+body.Name)
	w.WriteHeader(http.StatusNoContent)
}

// envSecrets is an owner-only export guarded by the owner password.
func (s *server) envSecrets(w http.ResponseWriter, r *http.Request, tok *Token) {
	if !s.ownerPassword(w, r, tok, "") {
		return
	}
	all, err := s.st.All()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "env", "")
	writeJSON(w, http.StatusOK, all)
}

func (s *server) listGroups(w http.ResponseWriter, r *http.Request, tok *Token) {
	groups, err := s.st.Groups()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]map[string]string{"groups": groups})
}

func (s *server) setGroup(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	var body struct {
		Group string `json:"group"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"group": "..."}`)
		return
	}
	err := s.st.SetGroup(name, body.Group)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "group", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request, tok *Token) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"name": "...", "role": "owner|agent"}`)
		return
	}
	if body.Role == "" {
		body.Role = "agent"
	}
	plain, err := s.st.NewToken(body.Name, body.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "token-create", body.Name)
	writeJSON(w, http.StatusCreated, map[string]string{"name": body.Name, "role": body.Role, "token": plain})
}

func (s *server) listTokens(w http.ResponseWriter, r *http.Request, tok *Token) {
	toks, err := s.st.ListTokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if toks == nil {
		toks = []Token{}
	}
	writeJSON(w, http.StatusOK, map[string][]Token{"tokens": toks})
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	err := s.st.RevokeToken(name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "token-revoke", name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) renameToken(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	var body struct {
		Name string `json:"name"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"name": "..."}`)
		return
	}
	err := s.st.RenameToken(name, body.Name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "token-rename", name+" -> "+body.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listAudit(w http.ResponseWriter, r *http.Request, tok *Token) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.st.AuditLog(limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string][]AuditEntry{"entries": entries})
}

func (s *server) createRoute(w http.ResponseWriter, r *http.Request, tok *Token) {
	var body Route
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"name":"...","upstream":"https://...","secret":"...","header":"..."}`)
		return
	}
	if err := s.st.SetRoute(body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.st.Audit(tok.Name, "route-create", body.Name)
	w.WriteHeader(http.StatusCreated)
}

func (s *server) listRoutes(w http.ResponseWriter, r *http.Request, tok *Token) {
	routes, err := s.st.ListRoutes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if routes == nil {
		routes = []Route{}
	}
	writeJSON(w, http.StatusOK, map[string][]Route{"routes": routes})
}

func (s *server) deleteRoute(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	err := s.st.DeleteRoute(name)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.st.Audit(tok.Name, "route-delete", name)
	w.WriteHeader(http.StatusNoContent)
}

// proxyRequest forwards the request to the route's upstream with the real
// secret injected as a header. The caller's stash token never leaves this
// server, and the secret never reaches the caller.
func (s *server) proxyRequest(w http.ResponseWriter, r *http.Request, tok *Token) {
	if !s.runAllows(requestToken(r), r.PathValue("route")) {
		writeErr(w, http.StatusForbidden, "route is outside this run's scope")
		return
	}
	rt, err := s.routeForRequest(requestToken(r), r.PathValue("route"))
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rt.Kind != "" {
		writeErr(w, http.StatusBadRequest, "this connection is not an HTTP proxy")
		return
	}
	value, err := s.st.Get(rt.Secret)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusBadGateway, "the route's secret does not exist")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	upstream, err := url.Parse(rt.Upstream)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "bad upstream URL")
		return
	}
	headerName, headerValue, ok := strings.Cut(rt.Header, ":")
	if !ok {
		writeErr(w, http.StatusInternalServerError, "bad route header template")
		return
	}
	headerValue = strings.ReplaceAll(strings.TrimSpace(headerValue), "{value}", value)

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Path = "/" + r.PathValue("rest")
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			pr.Out.Header.Del("Authorization") // never forward the stash token
			pr.Out.Header.Del("X-Api-Key")
			for name := range pr.Out.Header {
				if isStashToken(pr.Out.Header.Get(name)) {
					pr.Out.Header.Del(name)
				}
			}
			pr.Out.Header.Set("Accept-Encoding", "identity")
			pr.Out.Header.Set(strings.TrimSpace(headerName), headerValue)
		},
		ModifyResponse: func(response *http.Response) error {
			return protectProxyResponse(response, []string{value, headerValue, requestToken(r)})
		},
		FlushInterval: -1, // stream responses (SSE from LLM APIs) immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeErr(w, http.StatusBadGateway, "upstream request failed")
		},
	}
	s.st.Audit(tok.Name, "proxy", rt.Name)
	proxy.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
