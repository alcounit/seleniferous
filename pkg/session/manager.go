package session

import (
	"sync"
	"time"
)

type TimeoutHandler func(sessionId string)

type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*time.Timer
	idleTimeout time.Duration
	onTimeout   TimeoutHandler
}

func NewManager(idleTimeout time.Duration, handler TimeoutHandler) *Manager {
	return &Manager{
		sessions:    make(map[string]*time.Timer),
		idleTimeout: idleTimeout,
		onTimeout:   handler,
	}
}

func (m *Manager) Touch(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if timer, ok := m.sessions[sessionID]; ok {
		timer.Reset(m.idleTimeout)
		return
	}

	m.sessions[sessionID] = time.AfterFunc(m.idleTimeout, func() {
		m.handleTimeout(sessionID)
	})
}

func (m *Manager) handleTimeout(sessionID string) {
	m.mu.Lock()

	if _, ok := m.sessions[sessionID]; !ok {
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
	if timer, ok := m.sessions[sessionID]; ok {
		timer.Stop()
		delete(m.sessions, sessionID)
	}
}
