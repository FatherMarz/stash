package main

import (
	"bytes"
	"strings"
	"testing"
)

func maskAll(values []string, chunks ...string) string {
	var out bytes.Buffer
	m := newMasker(values, func(b []byte) { out.Write(b) })
	for _, c := range chunks {
		m.Write([]byte(c))
	}
	m.Flush()
	return out.String()
}

func TestMaskerReplacesValues(t *testing.T) {
	got := maskAll([]string{"sk-secret-123"}, "key is sk-secret-123 ok\n")
	if got != "key is **** ok\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerCatchesValueSplitAcrossWrites(t *testing.T) {
	got := maskAll([]string{"sk-secret-123"}, "key is sk-se", "cret", "-123 ok\n")
	if got != "key is **** ok\n" {
		t.Fatalf("got %q", got)
	}
	got = maskAll([]string{"abcdefgh"}, "a", "b", "c", "d", "e", "f", "g", "h", "!")
	if got != "****!" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerDoesNotHoldOrdinaryOutput(t *testing.T) {
	var out bytes.Buffer
	m := newMasker([]string{strings.Repeat("x", 3000)}, func(b []byte) { out.Write(b) })
	m.Write([]byte("server ready on :5173\n"))
	if out.String() != "server ready on :5173\n" {
		t.Fatalf("held back ordinary output: %q", out.String())
	}
	m.Write([]byte("tail xx"))
	if out.String() != "server ready on :5173\ntail " {
		t.Fatalf("got %q", out.String())
	}
}

func TestMaskerLongestValueFirst(t *testing.T) {
	got := maskAll([]string{"abcdefgh", "abcdefghijkl"}, "abcdefghijkl")
	if got != "****" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerSkipsShortValues(t *testing.T) {
	got := maskAll([]string{"1", "3000", "true"}, "1 3000 true\n")
	if got != "1 3000 true\n" {
		t.Fatalf("got %q", got)
	}
}
