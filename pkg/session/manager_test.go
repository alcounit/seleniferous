package session

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerTimeoutFires(t *testing.T) {
	ch := make(chan string, 1)
	m := NewManager(20*time.Millisecond, func(id string) {
		ch <- id
	})

	m.Touch("s1")

	select {
	case got := <-ch:
		if got != "s1" {
			t.Fatalf("expected session s1, got %s", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timeout handler did not fire")
	}
}

func TestManagerStopPreventsTimeout(t *testing.T) {
	ch := make(chan string, 1)
	m := NewManager(20*time.Millisecond, func(id string) {
		ch <- id
	})

	m.Touch("s1")
	m.Stop("s1")

	select {
	case <-ch:
		t.Fatal("unexpected timeout after stop")
	case <-time.After(60 * time.Millisecond):
	}
}

func TestManagerTouchResetsTimer(t *testing.T) {
	var calls int32
	m := NewManager(30*time.Millisecond, func(id string) {
		atomic.AddInt32(&calls, 1)
	})

	m.Touch("s1")
	time.Sleep(20 * time.Millisecond)
	m.Touch("s1")

	time.Sleep(40 * time.Millisecond)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 timeout call, got %d", got)
	}
}
