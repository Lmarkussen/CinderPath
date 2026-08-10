package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/policy"
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

func TestCRED1LookupTargetUsesEvidencedTransport(t *testing.T) {
	t.Setenv("CINDERPATH_CONFIGMGR_AUTHORITY", "MECM.SCCM.LAB")
	t.Setenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP", "10.1.10.41")
	if got := cred1LookupTarget("mecm.sccm.lab"); got != "10.1.10.41" {
		t.Fatalf("lookup target=%q", got)
	}
	if got := cred1LookupTarget("other.sccm.lab"); got != "other.sccm.lab" {
		t.Fatalf("unrelated target rewritten: %q", got)
	}
}

func TestDryRunPersistsRunStagesAndAllModuleDecisions(t *testing.T) {
	c := config.Defaults()
	c.DBPath = filepath.Join(t.TempDir(), "dry.db")
	c.Project.Name = "lab.local"
	c.Profile = config.ProfileAggressive
	a := &Application{Config: c, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	p := BuildWorkflowPlan(c, true)
	r, err := a.PersistDryRun(context.Background(), p, []string{"run", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary["dry_run"] != true || r.Summary["target_observations"] != 0 {
		t.Fatalf("bad dry summary: %#v", r.Summary)
	}
	s, err := database.Open(context.Background(), c.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stages, _ := s.ListWorkflowStages(context.Background())
	decisions, _ := s.ListWorkflowModuleDecisions(context.Background())
	if len(stages) != len(p.Stages) || len(decisions) != len(p.Modules) {
		t.Fatalf("history mismatch stages=%d/%d decisions=%d/%d", len(stages), len(p.Stages), len(decisions), len(p.Modules))
	}
	for _, d := range decisions {
		if d.Data["implemented"] == false && (d.State == "completed" || d.State == "completed_with_errors") {
			t.Fatalf("future module completed: %#v", d)
		}
		if strings.Contains(fmt.Sprint(d.Data["reason"]), "SyntheticPassword") {
			t.Fatal("secret in decision")
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	r2, err := a.PersistDryRun(cancelled, p, []string{"run", "--dry-run"})
	if err != nil || r2.Status != models.RunCancelled || r2.ID == r.ID {
		t.Fatalf("cancelled dry-run history not preserved: %#v %v", r2, err)
	}
}

func TestPolicyFixturePersistenceIsRedactedAndRecordsResponseState(t *testing.T) {
	c := config.Defaults()
	c.DBPath = filepath.Join(t.TempDir(), "policy.db")
	a := &Application{Config: c, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fixtureDir, err := filepath.Abs(filepath.Join("..", "policy", "testdata", "example01"))
	if err != nil {
		t.Fatal(err)
	}
	f, contract, err := policy.ImportDirectory(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	p, candidates, err := policy.ParsePolicy(context.Background(), f.ResponseBody)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.PersistPolicyFixture(context.Background(), "run-policy", f, contract, p, candidates); err != nil {
		t.Fatal(err)
	}
	s, err := database.Open(context.Background(), c.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	docs, _ := s.ListPolicyRecords(context.Background(), "policy_documents")
	contracts, _ := s.ListPolicyRecords(context.Background(), "protocol_contracts")
	if len(docs) != 1 || docs[0].Data["acquisition_state"] != string(policy.ProtectedCredential) {
		t.Fatalf("documents=%+v", docs)
	}
	if len(contracts) < 2 || !strings.Contains(fmt.Sprint(contracts), "cred2_policy_acquisition_contract") {
		t.Fatalf("contracts=%+v", contracts)
	}
	for _, table := range []string{"policy_documents", "policy_candidates", "protocol_contracts"} {
		records, _ := s.ListPolicyRecords(context.Background(), table)
		if strings.Contains(fmt.Sprint(records), "SyntheticPassword123!") {
			t.Fatalf("secret persisted in %s", table)
		}
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

func TestRECON3StatusAggregation(t *testing.T) {
	runID := "run-recon3"
	tests := []struct {
		name       string
		summary    modules.Summary
		evidence   []models.Evidence
		wantStatus string
	}{
		{name: "all connection failures", summary: modules.Summary{Failed: 1, Executions: []models.ModuleExecution{{Error: "connection_failed: refused"}}}, evidence: []models.Evidence{{RunID: runID, Type: "sccm_http_recon_summary", Data: map[string]any{"failure_count": 10, "successful_response_count": 0}}}, wantStatus: "connection_failed"},
		{name: "all resolution failures", summary: modules.Summary{Failed: 1, Executions: []models.ModuleExecution{{Error: "endpoint_resolution_failed: no such host"}}}, evidence: []models.Evidence{{RunID: runID, Type: "sccm_http_recon_summary", Data: map[string]any{"failure_count": 10, "successful_response_count": 0}}}, wantStatus: "endpoint_resolution_failed"},
		{name: "mixed outcome", summary: modules.Summary{Failed: 1, Executions: []models.ModuleExecution{{Error: "collection_failed: some requests failed"}}}, evidence: []models.Evidence{{RunID: runID, Type: "sccm_http_recon_summary", Data: map[string]any{"failure_count": 2, "successful_response_count": 8}}}, wantStatus: "completed_with_errors"},
		{name: "no evidence", summary: modules.Summary{}, evidence: []models.Evidence{{RunID: runID, Type: "sccm_http_recon_summary", Data: map[string]any{"failure_count": 0, "successful_response_count": 10, "relevant_evidence_count": 0}}}, wantStatus: "completed_no_sccm_evidence"},
		{name: "SCCM evidence", summary: modules.Summary{}, evidence: []models.Evidence{{RunID: runID, Type: "sccm_http_recon_summary", Data: map[string]any{"failure_count": 0, "successful_response_count": 10, "relevant_evidence_count": 1}}}, wantStatus: "completed_with_sccm_evidence"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveRECON3Status(tc.summary, tc.evidence, runID); got != tc.wantStatus {
				t.Fatalf("status=%q want=%q", got, tc.wantStatus)
			}
		})
	}
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
