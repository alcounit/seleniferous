package store

import "testing"

func TestDefaultStoreSetGetDeleteLenList(t *testing.T) {
	s := NewDefaultStore()

	if got := s.Len(); got != 0 {
		t.Fatalf("expected empty store, got len=%d", got)
	}

	s.Set("a", 1)
	s.Set("b", "two")

	if got := s.Len(); got != 2 {
		t.Fatalf("expected len=2, got %d", got)
	}

	val, ok := s.Get("a")
	if !ok || val.(int) != 1 {
		t.Fatalf("expected key a=1, got %v (ok=%v)", val, ok)
	}

	s.Delete("a")
	if _, ok := s.Get("a"); ok {
		t.Fatal("expected key a to be deleted")
	}

	items := s.List()
	if len(items) != 1 {
		t.Fatalf("expected list len=1, got %d", len(items))
	}
	if items[0] != "two" {
		t.Fatalf("expected list item 'two', got %v", items[0])
	}
}
