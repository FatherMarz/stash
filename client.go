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
	"strings"
	"time"
)

// client talks to a running stash server. It reads STASH_ADDR and
// STASH_TOKEN from the environment.
type client struct {
	addr     string
	token    string
	password string // owner password, sent only on reveal requests
	http     *http.Client
	initErr  error
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

func newClient() *client {
	addr := os.Getenv("STASH_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8555"
	}
	token, explicit := os.LookupEnv("STASH_TOKEN")
	var initErr error
	if explicit {
		token = strings.TrimSpace(stripTerminalPaste(strings.TrimSpace(token)))
		if !validClientToken(token) {
			initErr = errors.New("STASH_TOKEN is invalid. Supply an owner, agent, or run token, or unset STASH_TOKEN to use the default agent token")
		}
	} else {
		if data, err := os.ReadFile(filepath.Join(defaultDataDir(), "agent.token")); err == nil {
			token = strings.TrimSpace(string(data))
			if !validClientToken(token) {
				initErr = errors.New("the default agent token is invalid. Supply a current STASH_TOKEN")
			}
		}
	}
	c := &client{
		addr:    addr,
		token:   token,
		http:    &http.Client{Timeout: 10 * time.Second},
		initErr: initErr,
	}
	configureLocalHTTP(c.http, c.addr, defaultDataDir())
	return c
}

func (c *client) request(ctx context.Context, hc *http.Client, method, path string, in any) (*http.Response, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	if c.token == "" {
		return nil, errors.New("STASH_TOKEN is not set")
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
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
