package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyRedactsReflectedCredentialsAndAcceptsSDKHeader(t *testing.T) {
	e := newTestEnv(t)
	const key = "server-only-real-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != key || r.Header.Get("Authorization") != "" {
			t.Error("wrong SDK authentication")
		}
		w.Header().Set("X-Reflected-Key", key)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: "+key[:9])
		w.(http.Flusher).Flush()
		io.WriteString(w, key[9:]+"\n\n")
	}))
	defer upstream.Close()
	e.st.Set("ANTHROPIC_API_KEY", key)
	e.st.SetRoute(Route{Name: "sdk", Secret: "ANTHROPIC_API_KEY", Upstream: upstream.URL, Header: "X-Api-Key: {value}"})
	agent := e.mustCreateToken(t, "sdk-agent", "agent")
	req, _ := http.NewRequest("GET", e.srv.URL+"/proxy/sdk/events", nil)
	req.Header.Set("X-Api-Key", agent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %d %v", resp.StatusCode, err)
	}
	if strings.Contains(string(body), key) || strings.Contains(resp.Header.Get("X-Reflected-Key"), key) {
		t.Fatal("upstream reflected a real credential")
	}
	if !strings.Contains(string(body), "data: ****\n\n") {
		t.Fatalf("SSE framing changed: %q", body)
	}
}

func TestProxyRedactsCompressedResponses(t *testing.T) {
	e := newTestEnv(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		zip := gzip.NewWriter(w)
		io.WriteString(zip, "error: short-key")
		zip.Close()
	}))
	defer upstream.Close()
	e.st.Set("KEY", "short-key")
	e.st.SetRoute(Route{Name: "gzip", Secret: "KEY", Upstream: upstream.URL})
	agent := e.mustCreateToken(t, "gzip-agent", "agent")
	resp, body := e.req(t, agent, "GET", "/proxy/gzip/check", nil)
	if resp.StatusCode != 200 || strings.Contains(string(body), "short-key") || !strings.Contains(string(body), "****") {
		t.Fatal("compressed error exposed a key")
	}
}

func TestProxyClassifiesEncodingBeforeRedactingHeaders(t *testing.T) {
	for _, encoding := range []string{"gzip", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			var data bytes.Buffer
			if encoding == "gzip" {
				writer := gzip.NewWriter(&data)
				io.WriteString(writer, "response "+encoding)
				writer.Close()
			} else {
				data.WriteString("response " + encoding)
			}
			response := &http.Response{
				Header:  http.Header{"Content-Encoding": []string{encoding}},
				Body:    io.NopCloser(&data),
				Request: &http.Request{Method: http.MethodGet},
			}
			if err := protectProxyResponse(response, []string{encoding}); err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "response ****" || response.Header.Get("Content-Encoding") != "" {
				t.Fatalf("response decoding or masking failed: body=%q encoding=%q error=%v", body, response.Header.Get("Content-Encoding"), err)
			}
		})
	}
}

func TestProxyTakesStandInFromRouteHeader(t *testing.T) {
	const key = "real-vt-key"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Apikey") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	e := newTestEnv(t)
	e.st.Set("VT_KEY", key)
	e.st.SetRoute(Route{Name: "vt", Secret: "VT_KEY", Upstream: upstream.URL, Header: "x-apikey: {value}"})
	agent := e.mustCreateToken(t, "vt-agent", "agent")
	req, _ := http.NewRequest("GET", e.srv.URL+"/proxy/vt/files/abc", nil)
	req.Header.Set("x-apikey", agent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestProxyKeepsContentLengthOnHead(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "br"} {
		t.Run(encoding, func(t *testing.T) {
			e := newTestEnv(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "154")
				w.Header().Set("Content-Encoding", encoding)
				w.Header().Set("X-Reflected-Key", "head-only-real-key")
			}))
			defer upstream.Close()
			e.st.Set("HEAD_KEY", "head-only-real-key")
			e.st.SetRoute(Route{Name: "head", Secret: "HEAD_KEY", Upstream: upstream.URL, Header: "X-Api-Key: {value}"})
			agent := e.mustCreateToken(t, "head-agent", "agent")
			req, _ := http.NewRequest("HEAD", e.srv.URL+"/proxy/head/object", nil)
			req.Header.Set("X-Api-Key", agent)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.ContentLength != 154 || resp.Header.Get("Content-Encoding") != encoding {
				t.Fatalf("HEAD metadata changed: status=%d length=%d encoding=%q", resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Encoding"))
			}
			if resp.Header.Get("X-Reflected-Key") != "****" {
				t.Fatal("HEAD response exposed reflected credentials")
			}
		})
	}
}
