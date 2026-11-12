package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Run credentials stay in memory, expire after an hour, and can only use the
// selected routes. Revoking their parent token also invalidates them.
type runLease struct {
	parent  string
	routes  map[string]Route
	expires time.Time
}

type runSessions struct {
	sync.Mutex
	leases map[string]runLease
}

type runRoute struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type runSetup struct {
	Token       string            `json:"token"`
	Routes      []runRoute        `json:"routes"`
	Values      map[string]string `json:"values,omitempty"`
	SecretNames []string          `json:"secret_names"`
}

// secretKinds says how each secret reaches a program. "proxy": the program
// gets a run token and stash adds the key on the way to its pinned site.
// "aws": stash signs AWS calls, the key pair never leaves stash. "direct":
// the program gets the real value, masked as **** in its output.
// People see two paths: proxy (proxy and aws) and direct.
func secretKinds(names []string, routes []Route) map[string]string {
	paths := map[string]string{}
	for _, name := range names {
		paths[name] = "direct"
		if _, ok := builtinRoute(name); ok {
			paths[name] = "proxy"
		}
	}
	for _, rt := range routes {
		if rt.Kind == "aws" {
			paths[rt.KeyID] = "aws"
			paths[rt.Secret] = "aws"
		} else if paths[rt.Secret] != "aws" {
			paths[rt.Secret] = "proxy"
		}
	}
	return paths
}

func (s *server) runSession(w http.ResponseWriter, r *http.Request, tok *Token) {
	var body struct {
		Secrets []string `json:"secrets"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "expected a JSON object with optional secrets array")
		return
	}
	names, err := s.st.List()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	routes, err := s.st.ListRoutes()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	known := map[string]bool{}
	for _, name := range names {
		known[name] = true
	}
	paths := secretKinds(names, routes)
	wanted := body.Secrets
	if len(wanted) == 0 {
		wanted = names
	}
	out := runSetup{SecretNames: names, Values: map[string]string{}}
	allowed := map[string]Route{}
	envNames := map[string]bool{}
	seen := map[string]bool{}
	for _, name := range wanted {
		if seen[name] {
			continue
		}
		seen[name] = true
		if !known[name] {
			writeErr(w, 400, "secret not found: "+name)
			return
		}
		key := envName(name)
		if key == "STASH_TOKEN" || key == "STASH_ADDR" || strings.HasPrefix(key, "DSH_STASH_") || envNames[key] {
			writeErr(w, 400, "conflicting environment name for secret: "+name)
			return
		}
		switch paths[name] {
		case "aws":
			if len(body.Secrets) > 0 {
				writeErr(w, 400, name+" is an AWS key. stash signs AWS calls for it: use the AWS profile that stash set up")
				return
			}
			continue
		case "proxy":
			var match *Route
			for i := range routes {
				if routes[i].Kind == "" && routes[i].Secret == name {
					if match != nil {
						writeErr(w, 400, "multiple proxy routes for secret: "+name)
						return
					}
					match = &routes[i]
				}
			}
			if match == nil {
				builtin, _ := builtinRoute(name)
				match = &builtin
			}
			allowed[match.Name] = *match
			out.Routes = append(out.Routes, runRoute{match.Name, name})
			envNames[key] = true
			envNames[key+"_BASE_URL"] = true
		default:
			value, err := s.st.Get(name)
			if err != nil {
				writeErr(w, 500, err.Error())
				return
			}
			out.Values[name] = value
			envNames[key] = true
		}
	}
	// A direct secret must not reuse a proxied secret's *_BASE_URL name.
	for _, rt := range out.Routes {
		for name := range out.Values {
			if envName(name) == envName(rt.Secret)+"_BASE_URL" {
				writeErr(w, 400, "conflicting environment name for secret: "+name)
				return
			}
		}
	}
	token, err := newRunToken()
	if err != nil {
		writeErr(w, 500, "cannot create run token")
		return
	}
	out.Token = token
	s.addLease(token, r, allowed, time.Hour)
	handed := make([]string, 0, len(out.Values))
	for name := range out.Values {
		handed = append(handed, name)
	}
	sort.Strings(handed)
	s.st.Audit(tok.Name, "run-start", "proxy "+strconv.Itoa(len(out.Routes))+", direct: "+strings.Join(handed, ","))
	writeJSON(w, http.StatusCreated, out)
}

// secretPaths is what people see: AWS keys are on the proxy path too.
func secretPaths(names []string, routes []Route) map[string]string {
	paths := secretKinds(names, routes)
	for name, kind := range paths {
		if kind == "aws" {
			paths[name] = "proxy"
		}
	}
	return paths
}

func newRunToken() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "stash_run_" + hex.EncodeToString(raw), nil
}

func (s *server) addLease(token string, r *http.Request, routes map[string]Route, ttl time.Duration) {
	lease := runLease{parent: requestToken(r), routes: routes, expires: time.Now().Add(ttl)}
	s.runs.Lock()
	for t, old := range s.runs.leases {
		if time.Now().After(old.expires) {
			delete(s.runs.leases, t)
		}
	}
	s.runs.leases[token] = lease
	s.runs.Unlock()
}

// renewRun keeps a run token alive while its stash run process lives. If
// that process dies, the token stops working within the hour.
func (s *server) renewRun(w http.ResponseWriter, r *http.Request, tok *Token) {
	plain := requestToken(r)
	s.runs.Lock()
	lease, ok := s.runs.leases[plain]
	if ok {
		lease.expires = time.Now().Add(time.Hour)
		s.runs.leases[plain] = lease
	}
	s.runs.Unlock()
	if !ok {
		writeErr(w, 400, "use the run token to renew its own session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) revokeRun(w http.ResponseWriter, r *http.Request, tok *Token) {
	plain := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.runs.Lock()
	_, ok := s.runs.leases[plain]
	delete(s.runs.leases, plain)
	s.runs.Unlock()
	if !ok {
		writeErr(w, 400, "use the run token to end its own session")
		return
	}
	s.st.Audit(tok.Name, "run-end", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) tokenForRequest(plain string) (*Token, error) {
	if !strings.HasPrefix(plain, "stash_run_") {
		return s.st.VerifyToken(plain)
	}
	s.runs.Lock()
	lease, ok := s.runs.leases[plain]
	s.runs.Unlock()
	if !ok || time.Now().After(lease.expires) {
		return nil, ErrNotFound
	}
	parent, err := s.st.VerifyToken(lease.parent)
	if err != nil {
		return nil, err
	}
	return &Token{Name: parent.Name + "/run", Role: "agent"}, nil
}

func (s *server) runAllows(plain, route string) bool {
	if !strings.HasPrefix(plain, "stash_run_") {
		return true
	}
	s.runs.Lock()
	defer s.runs.Unlock()
	_, ok := s.runs.leases[plain].routes[route]
	return ok
}

// Built-in connections fix both the destination and authentication header.
// Agents cannot supply a host, URL, or header template for these connections.
func builtinRoute(secret string) (Route, bool) {
	key := envName(secret)
	upstream, header := "", "Authorization: Bearer {value}"
	switch {
	case strings.Contains(key, "OPENROUTER") && strings.HasSuffix(key, "API_KEY"):
		upstream = "https://openrouter.ai/api/v1"
	case key == "OPENAI_API_KEY":
		upstream = "https://api.openai.com/v1"
	case key == "ANTHROPIC_API_KEY":
		upstream, header = "https://api.anthropic.com", "x-api-key: {value}"
	default:
		return Route{}, false
	}
	sum := sha256.Sum256([]byte(secret))
	return Route{Name: "builtin-" + hex.EncodeToString(sum[:8]), Secret: secret, Upstream: upstream, Header: header}, true
}

func (s *server) routeForRequest(plain, name string) (*Route, error) {
	if !strings.HasPrefix(plain, "stash_run_") {
		return s.st.GetRoute(name)
	}
	s.runs.Lock()
	rt, ok := s.runs.leases[plain].routes[name]
	s.runs.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return &rt, nil
}
