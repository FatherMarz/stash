package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

// client talks to a running stash server. It reads STASH_ADDR and
// STASH_TOKEN from the environment.
type client struct {
	addr     string
	token    string
	password string // owner password, sent on owner actions
	// ask lets a command ask for the owner password at the terminal and
	// try again. stash ui asks on its own screen instead.
	ask     bool
	http    *http.Client
	initErr error
}

func stripTerminalPaste(value string) string {
	const start, end = "\x1b[200~", "\x1b[201~"
	if strings.HasPrefix(value, start) && strings.HasSuffix(value, end) {
		return value[len(start) : len(value)-len(end)]
	}
	return value
}

func validClientToken(token string) bool {
	validPrefix := false
	for _, prefix := range []string{"stash_owner_", "stash_agent_", "stash_run_"} {
		if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
			validPrefix = true
			break
		}
	}
	if !validPrefix {
		return false
	}
	for _, ch := range token {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

// cliPassword is empty outside tests. Tests set it to stand in for a person
// who types the owner password.
var cliPassword string

var legacyToken = regexp.MustCompile(`^stash_[0-9a-f]{48}$`)

// tokenFile is where setup keeps the one stash token. agent.token is the
// name before 0.7.
func tokenFile(dir string) string { return filepath.Join(dir, "token") }

func readTokenFile(dir string) string {
	for _, name := range []string{tokenFile(dir), filepath.Join(dir, "agent.token")} {
		if data, err := os.ReadFile(name); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func newClient() *client {
	addr := os.Getenv("STASH_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8555"
	}
	// STASH_TOKEN wins when it holds anything. An empty one counts as unset,
	// so the ~/.zshrc line works before setup has written the token file.
	token := strings.TrimSpace(stripTerminalPaste(strings.TrimSpace(os.Getenv("STASH_TOKEN"))))
	var initErr error
	if legacyToken.MatchString(token) {
		// A token from before 0.5 still sits in many shells. It works nowhere,
		// and the token file is the same one token, so it is safe to skip.
		token = ""
	}
	if token != "" {
		if !validClientToken(token) {
			initErr = errors.New("STASH_TOKEN is not a current stash token. Remove the old STASH_TOKEN, or run stash setup in your own terminal")
		}
	} else {
		token = readTokenFile(defaultDataDir())
		if token != "" && !validClientToken(token) {
			initErr = errors.New("the stash token file is invalid. Run stash setup in your own terminal")
		}
	}
	c := &client{
		addr:     addr,
		token:    token,
		ask:      term.IsTerminal(int(os.Stdin.Fd())),
		password: cliPassword,
		http:     &http.Client{Timeout: 10 * time.Second},
		initErr:  initErr,
	}
	configureLocalHTTP(c.http, c.addr, defaultDataDir())
	return c
}

func (c *client) request(ctx context.Context, hc *http.Client, method, path string, in any) (*http.Response, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	if c.token == "" {
		return nil, errors.New("no stash token. Run stash setup in your own terminal")
	}
	var body *bytes.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.password != "" {
		req.Header.Set("X-Stash-Password", c.password)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}
	return resp, nil
}

// stream sends a request with no timeout and returns the open response.
func (c *client) stream(ctx context.Context, method, path string, in any) (*http.Response, error) {
	return c.request(ctx, &http.Client{Transport: c.http.Transport}, method, path, in)
}

func (c *client) do(method, path string, in, out any) error {
	resp, err := c.request(context.Background(), c.http, method, path, in)
	if isPasswordErr(err) && c.ask && c.password == "" {
		if c.password, err = readPassword("owner password: "); err != nil {
			return err
		}
		resp, err = c.request(context.Background(), c.http, method, path, in)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
