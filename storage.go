package seleniferous

import (
	"net/url"
	"sync"
)

type session struct {
	ID         string
	URL        *url.URL
	OnTimeout  chan struct{}
	CancelFunc func()
}

type storage struct {
	sessions map[string]*session
	sync.RWMutex
}

func newStorage() *storage {
	return &storage{
		sessions: make(map[string]*session, 1),
	}
}

func (s *storage) get(sessionID string) (*session, bool) {
	s.Lock()
	defer s.Unlock()
	platform, ok := s.sessions[sessionID]

	return platform, ok
}

func (s *storage) put(sessionID string, platform *session) {
	s.Lock()
	defer s.Unlock()
	s.sessions[sessionID] = platform
}

func (s *storage) isEmpty() bool {
	s.Lock()
	defer s.Unlock()
	
	return len(s.sessions) == 0
}
