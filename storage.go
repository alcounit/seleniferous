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

type Storage struct {
	sessions map[string]*session
	sync.RWMutex
}

//NewStorage ...
func NewStorage() *Storage {
	return &Storage{
		sessions: make(map[string]*session, 1),
	}
}

func (s *Storage) get(sessionID string) (*session, bool) {
	s.Lock()
	defer s.Unlock()
	platform, ok := s.sessions[sessionID]

	return platform, ok
}

func (s *Storage) put(sessionID string, platform *session) {
	s.Lock()
	defer s.Unlock()
	s.sessions[sessionID] = platform
}

//IsEmpty ...
func (s *Storage) IsEmpty() bool {
	s.Lock()
	defer s.Unlock()

	return len(s.sessions) == 0
}
