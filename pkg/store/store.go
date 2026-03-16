package store

import (
	"sync"
)

type Store[V any] interface {
	Set(key string, val V)
	Get(key string) (val V, ok bool)
	Delete(key string)
	Len() int
	List() []V
}

type DefaultStore[V any] struct {
	mu   sync.RWMutex
	data map[string]V
}

func NewDefaultStore[V any]() Store[V] {
	return &DefaultStore[V]{
		data: make(map[string]V),
	}
}

func (s *DefaultStore[V]) Set(key string, val V) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = val
}

func (s *DefaultStore[V]) Get(key string) (val V, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok = s.data[key]
	return
}

func (s *DefaultStore[V]) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
}

func (s *DefaultStore[V]) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

func (s *DefaultStore[V]) List() []V {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]V, 0, len(s.data))
	for _, v := range s.data {
		out = append(out, v)
	}
	return out
}
