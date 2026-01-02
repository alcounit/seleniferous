package internal

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidEvent = errors.New("notifications: invalid event")

type EventType string

const (
	EventTypeCreated  EventType = "created"
	EventTypeUpdated  EventType = "updated"
	EventTypeDeleted  EventType = "deleted"
	EventTypeTimedout EventType = "timedout"
	EventTypeError    EventType = "error"
)

type Event struct {
	Type      EventType
	Data      string
	Timestamp time.Time
}

func (e Event) Validate() error {
	if e.Type == "" {
		return fmt.Errorf("%w: empty event type", ErrInvalidEvent)
	}
	return nil
}
