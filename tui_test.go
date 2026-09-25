package main

import (
	"reflect"
	"testing"
)

func TestGroupRows(t *testing.T) {
	rows := groupRows([]string{"VIGI_KEY", "vigi-token", "seaport-admin", "seaport-ws1", "ADMIN_KEY", "solo"}, nil)
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

func rowNames(rows []uiRow) []string {
	var got []string
	for _, r := range rows {
		if r.header != "" {
			got = append(got, "#"+r.header)
		} else {
			got = append(got, r.name)
		}
	}
	return got
}

func TestGroupRowsCustom(t *testing.T) {
	custom := map[string]string{"ADMIN_KEY": "Client work", "seaport-admin": "Client work", "solo": "Solo", "VIGI_KEY": "vigi"}
	got := rowNames(groupRows([]string{"VIGI_KEY", "vigi-token", "seaport-admin", "seaport-ws1", "ADMIN_KEY", "solo"}, custom))
	want := []string{"#Client work (2)", "ADMIN_KEY", "seaport-admin", "#Solo (1)", "solo", "#vigi (2)", "vigi-token", "VIGI_KEY", "#OTHER (1)", "seaport-ws1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestCompleteText(t *testing.T) {
	names := []string{"VIGI_BB_REPO_TOKEN", "VIGI_BB_SITE_TOKEN", "VIGI_HIT_SALT", "seaport-admin"}
	for in, want := range map[string]string{
		"vi":     "VIGI_",
		"vigi_b": "VIGI_BB_",
		"sea":    "seaport-admin",
		"SALT":   "VIGI_HIT_SALT",
		"zzz":    "zzz",
		"":       "",
	} {
		if got := completeText(in, names); got != want {
			t.Fatalf("completeText(%q) = %q, want %q", in, got, want)
		}
	}
}
