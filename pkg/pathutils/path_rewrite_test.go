package pathutils

import "testing"

func TestParseBuildRoundTrip(t *testing.T) {
	parts := Parse("/a/b/c/")
	if len(parts) != 3 || parts[0] != "a" || parts[2] != "c" {
		t.Fatalf("unexpected parts: %#v", parts)
	}

	if got := Build(parts); got != "/a/b/c" {
		t.Fatalf("unexpected build: %s", got)
	}
}

func TestDeleteKeepsTrailingSlash(t *testing.T) {
	got := Delete("/a/b/c/", "b")
	if got != "/a/c/" {
		t.Fatalf("unexpected delete result: %s", got)
	}
}

func TestDeleteNoFragments(t *testing.T) {
	got := Delete("/", "a")
	if got != "//" {
		t.Fatalf("unexpected delete result: %s", got)
	}
}

func TestReplaceAndClean(t *testing.T) {
	got := Replace("/a/old/b//", map[string]string{"old": "new"})
	if got != "/a/new/b" {
		t.Fatalf("unexpected replace result: %s", got)
	}
}
