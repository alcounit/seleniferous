package service

import "testing"

func TestEventValidate(t *testing.T) {
	if err := (Event{}).Validate(); err == nil {
		t.Fatal("expected error for empty event type")
	}

	if err := (Event{Type: EventTypeCreated}).Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
