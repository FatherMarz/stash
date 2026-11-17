package main

import (
	"reflect"
	"testing"
)

func TestGroupRows(t *testing.T) {
	rows := groupRows([]string{"WIDGET_KEY", "widget-token", "acme-admin", "acme-ws1", "ADMIN_KEY", "solo"}, nil)
	var got []string
	for _, r := range rows {
		if r.header != "" {
			got = append(got, "#"+r.header)
		} else {
			got = append(got, r.name)
		}
	}
	want := []string{"#ACME (2)", "acme-admin", "acme-ws1", "#WIDGET (2)", "widget-token", "WIDGET_KEY", "#OTHER (2)", "ADMIN_KEY", "solo"}
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
	custom := map[string]string{"ADMIN_KEY": "Client work", "acme-admin": "Client work", "solo": "Solo", "WIDGET_KEY": "widget"}
	got := rowNames(groupRows([]string{"WIDGET_KEY", "widget-token", "acme-admin", "acme-ws1", "ADMIN_KEY", "solo"}, custom))
	want := []string{"#Client work (2)", "acme-admin", "ADMIN_KEY", "#Solo (1)", "solo", "#widget (2)", "widget-token", "WIDGET_KEY", "#OTHER (1)", "acme-ws1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestCompleteText(t *testing.T) {
	names := []string{"WIDGET_BB_REPO_TOKEN", "WIDGET_BB_SITE_TOKEN", "WIDGET_HIT_SALT", "acme-admin"}
	for in, want := range map[string]string{
		"wi":       "WIDGET_",
		"widget_b": "WIDGET_BB_",
		"acm":      "acme-admin",
		"SALT":     "WIDGET_HIT_SALT",
		"zzz":      "zzz",
		"":         "",
	} {
		if got := completeText(in, names); got != want {
			t.Fatalf("completeText(%q) = %q, want %q", in, got, want)
		}
	}
}
