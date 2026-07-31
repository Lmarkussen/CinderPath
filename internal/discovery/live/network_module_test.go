package live

import (
	"context"
	"errors"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkConcurrencyBounded(t *testing.T) {
	var active, max atomic.Int64
	s := networkScanner{ports: []int{1, 2}, hostTimeout: time.Second, concurrency: 2, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := active.Add(1)
		for {
			old := max.Load()
			if n <= old || max.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return nil, errors.New("closed")
	}}
	assets := make([]models.Asset, 8)
	for i := range assets {
		assets[i] = models.Asset{IPAddresses: []string{"127.0.0.1"}, Properties: map[string]string{}}
	}
	_ = s.probe(context.Background(), assets, modulesRun())
	if max.Load() > 2 || s.maxActive.Load() > 2 {
		t.Fatalf("max=%d scanner=%d", max.Load(), s.maxActive.Load())
	}
}
func TestNetworkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := networkScanner{ports: []int{80}, hostTimeout: time.Second, concurrency: 1, dial: func(context.Context, string, string) (net.Conn, error) { t.Fatal("dial called"); return nil, nil }}
	_ = s.probe(ctx, []models.Asset{{IPAddresses: []string{"127.0.0.1"}, Properties: map[string]string{}}}, modulesRun())
}
