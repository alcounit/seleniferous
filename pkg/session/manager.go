package session

import (
	"sync"
	"time"
)

type TimeoutHandler func(sessionId string)

type entry struct {
	timer    *time.Timer
	inflight int
}

type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*entry
	idleTimeout time.Duration
	onTimeout   TimeoutHandler
	startTimer  *time.Timer
}

func NewManager(idleTimeout time.Duration, handler TimeoutHandler) *Manager {
	return &Manager{
		sessions:    make(map[string]*entry),
		idleTimeout: idleTimeout,
		onTimeout:   handler,
	}
}

func (m *Manager) StartTimer(d time.Duration, onExpire func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopStartTimer()

	var t *time.Timer
	t = time.AfterFunc(d, func() {
		m.mu.Lock()
		if m.startTimer != t {
			m.mu.Unlock()
			return
		}
		m.startTimer = nil
		m.mu.Unlock()

		if onExpire != nil {
			onExpire()
		}
	})
	m.startTimer = t
}

func (m *Manager) Touch(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopStartTimer()

	if e, ok := m.sessions[sessionID]; ok {
		if e.inflight == 0 {
			e.timer.Reset(m.idleTimeout)
		}
		return
	}

	m.sessions[sessionID] = &entry{timer: m.newTimer(sessionID)}
}

func (m *Manager) Begin(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopStartTimer()

	e, ok := m.sessions[sessionID]
	if !ok {
		e = &entry{timer: m.newTimer(sessionID)}
		m.sessions[sessionID] = e
	}
	e.timer.Stop()
	e.inflight++
}

func (m *Manager) End(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.sessions[sessionID]
	if !ok || e.inflight == 0 {
		return
	}

	e.inflight--
	if e.inflight == 0 {
		e.timer.Reset(m.idleTimeout)
	}
}

func (m *Manager) newTimer(sessionID string) *time.Timer {
	return time.AfterFunc(m.idleTimeout, func() {
		m.handleTimeout(sessionID)
	})
}

func (m *Manager) stopStartTimer() {
	if m.startTimer != nil {
		m.startTimer.Stop()
		m.startTimer = nil
	}
}

func (m *Manager) handleTimeout(sessionID string) {
	m.mu.Lock()

	e, ok := m.sessions[sessionID]
	if !ok || e.inflight > 0 {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, sessionID)
	m.mu.Unlock()

	if m.onTimeout != nil {
		m.onTimeout(sessionID)
	}
}

func (m *Manager) Stop(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.sessions[sessionID]; ok {
		e.timer.Stop()
		delete(m.sessions, sessionID)
	}
}
