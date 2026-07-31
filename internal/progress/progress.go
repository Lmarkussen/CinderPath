package progress

import (
	"sync"
	"time"
)

type Type string

const (
	RunStarted      Type = "run_started"
	StageStarted    Type = "stage_started"
	ModuleStarted   Type = "module_started"
	TargetStarted   Type = "target_started"
	TargetCompleted Type = "target_completed"
	ModuleCompleted Type = "module_completed"
	ModuleSkipped   Type = "module_skipped"
	Warning         Type = "warning"
	Error           Type = "error"
	RunCompleted    Type = "run_completed"
)

type Event struct {
	Type    Type           `json:"type"`
	RunID   string         `json:"run_id,omitempty"`
	Module  string         `json:"module,omitempty"`
	Target  string         `json:"target,omitempty"`
	Message string         `json:"message,omitempty"`
	At      time.Time      `json:"at"`
	Data    map[string]any `json:"data,omitempty"`
}
type Sink interface{ Publish(Event) }
type Nop struct{}

func (Nop) Publish(Event) {}

type Collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *Collector) Publish(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	c.events = append(c.events, e)
}
func (c *Collector) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events...)
}
