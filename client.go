package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// client talks to a running stash server. It reads STASH_ADDR and
// STASH_TOKEN from the environment.
type client struct {
	addr     string
	token    string
	password string // owner password, sent only on reveal requests
	http     *http.Client
}

func newClient() *client {
	addr := os.Getenv("STASH_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8555"
	}
	return &client{
		addr:  addr,
		token: os.Getenv("STASH_TOKEN"),
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *client) request(ctx context.Context, hc *http.Client, method, path string, in any) (*http.Response, error) {
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
	return c.request(ctx, &http.Client{}, method, path, in)
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
