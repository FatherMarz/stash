package main

import (
	"sort"
	"strings"
)

// maskMinLen skips short values. Masking a 4-character value would blank
// out ordinary words and numbers in every command's output.
const maskMinLen = 8

// masker replaces secret values in a byte stream. When a write ends in the
// start of a value, it holds back only that part, so a value split across
// two writes is still caught and all other output flows through at once.
type masker struct {
	rep     *strings.Replacer
	vals    []string
	maxLen  int
	pending []byte
	out     func([]byte)
}

func newMasker(values []string, out func([]byte)) *masker {
	var vals []string
	for _, v := range values {
		if len(v) >= maskMinLen {
			vals = append(vals, v)
		}
	}
	// Longest first, so a value that contains another value masks whole.
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	var pairs []string
	maxLen := 1
	for _, v := range vals {
		pairs = append(pairs, v, "****")
		maxLen = max(maxLen, len(v))
	}
	return &masker{rep: strings.NewReplacer(pairs...), vals: vals, maxLen: maxLen, out: out}
}

// holdFrom returns the index of the earliest tail of buf that is a proper
// prefix of some value, or len(buf) when there is none.
func (m *masker) holdFrom(buf string) int {
	for i := max(0, len(buf)-m.maxLen+1); i < len(buf); i++ {
		tail := buf[i:]
		for _, v := range m.vals {
			if len(tail) < len(v) && strings.HasPrefix(v, tail) {
				return i
			}
		}
	}
	return len(buf)
}

func (m *masker) Write(p []byte) (int, error) {
	buf := m.rep.Replace(string(append(m.pending, p...)))
	cut := m.holdFrom(buf)
	if cut > 0 {
		m.out([]byte(buf[:cut]))
	}
	m.pending = []byte(buf[cut:])
	return len(p), nil
}

func (m *masker) Flush() {
	if len(m.pending) > 0 {
		m.out(m.pending)
		m.pending = nil
	}
}
