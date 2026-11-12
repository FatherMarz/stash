package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type maskedBody struct {
	source io.ReadCloser
	mask   *masker
	ready  []byte
	err    error
	finish func()
}

func newMaskedBody(source io.ReadCloser, values []string, finish func()) *maskedBody {
	body := &maskedBody{source: source, finish: finish}
	body.mask = newMaskerMinLength(values, func(data []byte) { body.ready = append(body.ready, data...) }, 1)
	return body
}

func (b *maskedBody) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	}
	for len(b.ready) == 0 && b.err == nil {
		var data [32768]byte
		n, err := b.source.Read(data[:])
		if n > 0 {
			b.mask.Write(data[:n])
		}
		if err != nil {
			b.mask.Flush()
			b.err = err
			if b.finish != nil {
				b.finish()
			}
		}
	}
	n := copy(out, b.ready)
	b.ready = b.ready[n:]
	if n > 0 {
		return n, nil
	}
	return 0, b.err
}

func (b *maskedBody) Close() error { return b.source.Close() }

type gzipBody struct {
	*gzip.Reader
	source io.Closer
}

func (b *gzipBody) Close() error { b.Reader.Close(); return b.source.Close() }

// Redact reflected credentials from responses, including streamed API errors.
func protectProxyResponse(response *http.Response, values []string) error {
	switch response.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip":
		reader, err := gzip.NewReader(response.Body)
		if err != nil {
			return err
		}
		response.Body = &gzipBody{reader, response.Body}
		response.Header.Del("Content-Encoding")
	default:
		return fmt.Errorf("unsupported upstream response encoding")
	}
	redact := func(headers http.Header) {
		for key, entries := range headers {
			for i, entry := range entries {
				for _, value := range values {
					if value != "" {
						entry = strings.ReplaceAll(entry, value, "****")
					}
				}
				entries[i] = entry
			}
			headers[key] = entries
		}
	}
	redact(response.Header)
	response.Header.Del("Content-Length")
	response.ContentLength = -1
	response.Body = newMaskedBody(response.Body, values, func() { redact(response.Trailer) })
	return nil
}
