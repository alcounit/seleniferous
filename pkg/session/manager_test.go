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

func TestManagerTimeoutWithoutHandler(t *testing.T) {
	m := NewManager(10*time.Millisecond, nil)
	m.Touch("s1")

	time.Sleep(40 * time.Millisecond)

	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected session removed after timeout, got %d entries", n)
	}
}

func TestManagerStopUnknownSession(t *testing.T) {
	m := NewManager(time.Second, nil)
	m.Stop("missing")

	m.Touch("s1")
	m.Stop("s1")

	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no entries after stop, got %d", n)
	}
}

func TestManagerStartTimerFiresWithoutActivity(t *testing.T) {
	ch := make(chan struct{}, 1)
	m := NewManager(time.Second, nil)
	m.StartTimer(20*time.Millisecond, func() { ch <- struct{}{} })

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("start timer did not fire")
	}
}

func TestManagerStartTimerWithoutHandler(t *testing.T) {
	m := NewManager(time.Second, nil)
	m.StartTimer(5*time.Millisecond, nil)

	time.Sleep(30 * time.Millisecond)

	m.mu.Lock()
	armed := m.startTimer != nil
	m.mu.Unlock()
	if armed {
		t.Fatal("expected start timer cleared after firing")
	}
}

func TestManagerStartTimerStoppedByTouch(t *testing.T) {
	var calls int32
	m := NewManager(time.Second, nil)
	m.StartTimer(20*time.Millisecond, func() { atomic.AddInt32(&calls, 1) })

	m.Touch("s1")
	defer m.Stop("s1")

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected start timer stopped by touch, got %d calls", got)
	}
}

func TestManagerStartTimerStoppedByBegin(t *testing.T) {
	var calls int32
	m := NewManager(time.Second, nil)
	m.StartTimer(20*time.Millisecond, func() { atomic.AddInt32(&calls, 1) })

	m.Begin("s1")
	defer m.Stop("s1")

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected start timer stopped by begin, got %d calls", got)
	}
}

func TestManagerStartTimerRestartReplacesPrevious(t *testing.T) {
	var first, second int32
	m := NewManager(time.Second, nil)
	m.StartTimer(20*time.Millisecond, func() { atomic.AddInt32(&first, 1) })
	m.StartTimer(40*time.Millisecond, func() { atomic.AddInt32(&second, 1) })

	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&first); got != 0 {
		t.Fatalf("expected replaced start timer not to fire, got %d", got)
	}
	if got := atomic.LoadInt32(&second); got != 1 {
		t.Fatalf("expected new start timer to fire once, got %d", got)
	}
}

func TestManagerStartTimerFireRacesWithTouch(t *testing.T) {
	var calls int32
	m := NewManager(time.Second, nil)
	m.StartTimer(time.Millisecond, func() { atomic.AddInt32(&calls, 1) })

	m.mu.Lock()
	time.Sleep(30 * time.Millisecond)
	m.stopStartTimer()
	m.mu.Unlock()

	time.Sleep(30 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected fired start timer to be ignored after stop, got %d", got)
	}
}

func TestManagerBeginSuspendsIdle(t *testing.T) {
	ch := make(chan string, 1)
	m := NewManager(20*time.Millisecond, func(id string) { ch <- id })

	m.Begin("s1")

	select {
	case <-ch:
		t.Fatal("idle timer fired while request in flight")
	case <-time.After(80 * time.Millisecond):
	}

	m.End("s1")

	select {
	case got := <-ch:
		if got != "s1" {
			t.Fatalf("expected session s1, got %s", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("idle timer did not fire after request ended")
	}
}

func TestManagerBeginOnExistingSession(t *testing.T) {
	ch := make(chan string, 1)
	m := NewManager(20*time.Millisecond, func(id string) { ch <- id })

	m.Touch("s1")
	m.Begin("s1")

	select {
	case <-ch:
		t.Fatal("idle timer fired while request in flight")
	case <-time.After(60 * time.Millisecond):
	}

	m.End("s1")

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("idle timer did not fire after request ended")
	}
}

func TestManagerEndRearmsFromEnd(t *testing.T) {
	var calls int32
	m := NewManager(40*time.Millisecond, func(id string) { atomic.AddInt32(&calls, 1) })

	m.Begin("s1")
	time.Sleep(30 * time.Millisecond)
	m.End("s1")

	time.Sleep(25 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected idle counted from end of request, got %d calls", got)
	}

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 timeout call, got %d", got)
	}
}

func TestManagerNestedBeginKeepsIdleSuspended(t *testing.T) {
	var calls int32
	m := NewManager(20*time.Millisecond, func(id string) { atomic.AddInt32(&calls, 1) })

	m.Begin("s1")
	m.Begin("s1")
	m.End("s1")

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected idle suspended while one request in flight, got %d", got)
	}

	m.End("s1")

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 timeout call, got %d", got)
	}
}

func TestManagerEndWithoutBegin(t *testing.T) {
	var calls int32
	m := NewManager(20*time.Millisecond, func(id string) { atomic.AddInt32(&calls, 1) })

	m.End("missing")

	m.Touch("s1")
	m.End("s1")

	m.mu.Lock()
	inflight := m.sessions["s1"].inflight
	m.mu.Unlock()
	if inflight != 0 {
		t.Fatalf("expected inflight to stay 0, got %d", inflight)
	}

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 timeout call, got %d", got)
	}
}

func TestManagerTouchDuringInflightDoesNotArm(t *testing.T) {
	var calls int32
	m := NewManager(20*time.Millisecond, func(id string) { atomic.AddInt32(&calls, 1) })

	m.Begin("s1")
	m.Touch("s1")

	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected touch not to arm idle while in flight, got %d", got)
	}
	m.Stop("s1")
}

func TestManagerHandleTimeoutSkipsInflight(t *testing.T) {
	var calls int32
	m := NewManager(time.Hour, func(id string) { atomic.AddInt32(&calls, 1) })

	m.Begin("s1")
	defer m.Stop("s1")

	m.handleTimeout("s1")
	m.handleTimeout("missing")

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected no timeout call, got %d", got)
	}

	m.mu.Lock()
	_, ok := m.sessions["s1"]
	m.mu.Unlock()
	if !ok {
		t.Fatal("expected in-flight session to be kept")
	}
}

func BenchmarkManagerTouch(b *testing.B) {
	m := NewManager(time.Hour, nil)
	m.Touch("s1")
	defer m.Stop("s1")

	b.ReportAllocs()
	for b.Loop() {
		m.Touch("s1")
	}
}

func BenchmarkManagerBeginEnd(b *testing.B) {
	m := NewManager(time.Hour, nil)
	m.Touch("s1")
	defer m.Stop("s1")

	b.ReportAllocs()
	for b.Loop() {
		m.Begin("s1")
		m.End("s1")
	}
}
