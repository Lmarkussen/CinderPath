package progress

import (
	"sync"
	"testing"
)

func TestCollectorConcurrent(t *testing.T) {
	var c Collector
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Publish(Event{Type: TargetCompleted}) }()
	}
	wg.Wait()
	if len(c.Events()) != 20 {
		t.Fatalf("events=%d", len(c.Events()))
	}
}
