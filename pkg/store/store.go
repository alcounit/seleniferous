package store

import (
	"sync"
)

type Store interface {
	Set(key string, val any)
	Get(key string) (val any, ok bool)
	Delete(key string)
	Len() int
	List() []any
}

type DefaultStore struct {
	mu   sync.RWMutex
	data map[string]any
}

func NewDefaultStore() Store {
	return &DefaultStore{
		data: make(map[string]any),
	}
}

func (s *DefaultStore) Set(key string, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = val
}

func (s *DefaultStore) Get(key string) (val any, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok = s.data[key]
	return
}

func (s *DefaultStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

func (s *DefaultStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

func (s *DefaultStore) List() []any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]any, 0, len(s.data))
	for _, v := range s.data {
		out = append(out, v)
	}
	return out
}
