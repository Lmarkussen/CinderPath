package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"github.com/Lmarkussen/CinderPath/internal/scope"
)

func TestMockWorkflowIsDeduplicated(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(dir, "cinderpath.db")
	cfg.OutputDir = filepath.Join(dir, "reports")
	a := &Application{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := a.Discover(ctx, []string{"discover"}); err != nil {
			t.Fatal(err)
		}
		out, err := a.Assess(ctx, []string{"assess"})
		if err != nil {
			t.Fatal(err)
		}
		if out.Assets != 8 || totalFindings(out) != 4 || out.AttackPaths != 1 {
			t.Fatalf("iteration %d: assets=%d findings=%d paths=%d", i, out.Assets, totalFindings(out), out.AttackPaths)
		}
	}
	out, err := a.Report(ctx, []string{"report"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{out.ReportPaths.JSON, out.ReportPaths.HTML} {
		info, err := os.Stat(path)
		if err != nil || info.Size() == 0 {
			t.Fatalf("invalid report %s: info=%v err=%v", path, info, err)
		}
	}
	store, err := database.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assets, _ := store.ListAssets(ctx)
	findings, _ := store.ListFindings(ctx)
	paths, _ := store.ListAttackPaths(ctx)
	if len(assets) != 8 || len(findings) != 4 || len(paths) != 1 {
		t.Fatalf("stored assets=%d findings=%d paths=%d", len(assets), len(findings), len(paths))
	}
}

func TestCancelledDiscoveryDoesNotPanic(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "cancel.db")
	a := &Application{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Discover(ctx, nil); err == nil {
		t.Fatal("expected cancellation error")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	_, _ = a.Discover(ctx, nil)
}

func totalFindings(out Outcome) int {
	total := 0
	for _, count := range out.Findings {
		total += count
	}
	return total
}

func TestRepeatedLoopbackLiveDiscoveryDeduplicates(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(dir, "live.db")
	a := &Application{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	opts := DiscoverOptions{Provider: "live", Live: live.Options{Scope: scope.Input{Targets: []string{"127.0.0.1"}, MaxTargets: 4}, Ports: []int{1}, ConnectTimeout: 10 * time.Millisecond, HostTimeout: 100 * time.Millisecond, Concurrency: 1, HTTP: live.HTTPOptions{UserAgent: "test", MaxBodyBytes: 32, MaxRedirects: 1, Timeout: 100 * time.Millisecond}, LDAP: live.LDAPOptions{SearchTimeout: time.Second}}}
	var last Outcome
	for i := 0; i < 2; i++ {
		var err error
		last, err = a.DiscoverWithOptions(context.Background(), nil, opts)
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[progress.Type]bool{}
	for _, event := range last.Events {
		seen[event.Type] = true
	}
	for _, typ := range []progress.Type{progress.RunStarted, progress.StageStarted, progress.ModuleStarted, progress.TargetCompleted, progress.ModuleCompleted, progress.ModuleSkipped, progress.RunCompleted} {
		if !seen[typ] {
			t.Fatalf("missing progress event %s", typ)
		}
	}
	store, err := database.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assets, _ := store.ListAssets(context.Background())
	evidence, _ := store.ListEvidence(context.Background())
	if len(assets) != 1 {
		t.Fatalf("assets=%d", len(assets))
	}
	if len(evidence) != 5 {
		t.Fatalf("evidence=%d", len(evidence))
	}
}
