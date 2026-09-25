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

// peerCheck is a variable so tests can stand in for the stash binary.
var peerCheck = peerIsStash

type server struct {
	st    *Store
	guard guard
	// peerCheck reports whether the local client is the stash binary.
	peerCheck func(remoteAddr, localAddr string) bool
}

func newMux(st *Store) *http.ServeMux {
	s := &server{st: st, peerCheck: peerCheck}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /v1/secrets", s.auth("ro", s.listSecrets))
	mux.HandleFunc("GET /v1/secrets/{name}", s.auth("ro", s.getSecret))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.auth("rw", s.putSecret))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.auth("rw", s.deleteSecret))
	mux.HandleFunc("GET /v1/env", s.auth("ro", s.envSecrets))
	mux.HandleFunc("GET /v1/open", s.auth("ro", s.listOpen))
	mux.HandleFunc("PUT /v1/open/{name}", s.auth("admin", s.setOpen(true)))
	mux.HandleFunc("DELETE /v1/open/{name}", s.auth("admin", s.setOpen(false)))
	mux.HandleFunc("GET /v1/password", s.auth("admin", s.passwordStatus))
	mux.HandleFunc("PUT /v1/password", s.auth("admin", s.setPassword))
	mux.HandleFunc("POST /v1/tokens", s.auth("admin", s.createToken))
	mux.HandleFunc("GET /v1/tokens", s.auth("admin", s.listTokens))
	mux.HandleFunc("DELETE /v1/tokens/{name}", s.auth("admin", s.revokeToken))
	mux.HandleFunc("GET /v1/audit", s.auth("admin", s.listAudit))
	mux.HandleFunc("POST /v1/routes", s.auth("admin", s.createRoute))
	mux.HandleFunc("GET /v1/routes", s.auth("admin", s.listRoutes))
	mux.HandleFunc("DELETE /v1/routes/{name}", s.auth("admin", s.deleteRoute))
	mux.HandleFunc("/proxy/{route}", s.auth("proxy", s.proxyRequest))
	mux.HandleFunc("/proxy/{route}/{rest...}", s.auth("proxy", s.proxyRequest))
	return mux
}

// roleAllows reports whether a token role satisfies the required role.
// admin > rw > ro > proxy. A proxy token can only use /proxy routes, so an
// agent holding one can never read a raw secret.
func roleAllows(have, need string) bool {
	rank := map[string]int{"proxy": 1, "ro": 2, "rw": 3, "admin": 4}
	return rank[have] >= rank[need]
}

func (s *server) auth(need string, h func(http.ResponseWriter, *http.Request, *Token)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		plain := strings.TrimPrefix(header, "Bearer ")
		if plain == "" || plain == header {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tok, err := s.st.VerifyToken(plain)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if !roleAllows(tok.Role, need) {
			writeErr(w, http.StatusForbidden, "token role does not allow this operation")
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
	writeJSON(w, http.StatusOK, map[string][]string{"secrets": names})
}

func (s *server) getSecret(w http.ResponseWriter, r *http.Request, tok *Token) {
	name := r.PathValue("name")
	open, err := s.st.IsOpen(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !open && !s.ownerPassword(w, r, tok, name) {
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

// envSecrets returns every value for `stash run`. It answers the stash
// binary on this machine, or anyone with the owner password.
func (s *server) envSecrets(w http.ResponseWriter, r *http.Request, tok *Token) {
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	isStash := local != nil && s.peerCheck(r.RemoteAddr, local.String())
	if !isStash && !s.ownerPassword(w, r, tok, "") {
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

func (s *server) listOpen(w http.ResponseWriter, r *http.Request, tok *Token) {
	names, err := s.st.ListOpen()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"open": names})
}

// setOpen opens or closes one secret. It needs an admin token and the owner
// password.
func (s *server) setOpen(open bool) func(http.ResponseWriter, *http.Request, *Token) {
	return func(w http.ResponseWriter, r *http.Request, tok *Token) {
		name := r.PathValue("name")
		if !s.ownerPassword(w, r, tok, name) {
			return
		}
		if err := s.st.SetOpen(name, open); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		action := "close"
		if open {
			action = "open"
		}
		s.st.Audit(tok.Name, action, name)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) createToken(w http.ResponseWriter, r *http.Request, tok *Token) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, `body must be JSON: {"name": "...", "role": "ro|rw|admin"}`)
		return
	}
	if body.Role == "" {
		body.Role = "rw"
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
	rt, err := s.st.GetRoute(r.PathValue("route"))
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "route not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
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
			pr.Out.Header.Set(strings.TrimSpace(headerName), headerValue)
		},
		FlushInterval: -1, // stream responses (SSE from LLM APIs) immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeErr(w, http.StatusBadGateway, "upstream request failed: "+err.Error())
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
