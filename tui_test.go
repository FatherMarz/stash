package main

import (
	"reflect"
	"testing"
)

func TestGroupRows(t *testing.T) {
	rows := groupRows([]string{"VIGI_KEY", "vigi-token", "seaport-admin", "seaport-ws1", "ADMIN_KEY", "solo"})
	var got []string
	for _, r := range rows {
		if r.header != "" {
			got = append(got, "#"+r.header)
		} else {
			got = append(got, r.name)
		}
	}
	want := []string{"#SEAPORT (2)", "seaport-admin", "seaport-ws1", "#VIGI (2)", "vigi-token", "VIGI_KEY", "#OTHER (2)", "ADMIN_KEY", "solo"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\nb", 20); got != "a⏎b" {
		t.Fatalf("got %q", got)
	}
	if got := oneLine("abcdefghijklmnop", 10); got != "abcdefghi…" {
		t.Fatalf("got %q", got)
	}
}
