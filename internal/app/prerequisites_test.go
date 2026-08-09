package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/planner"
	"github.com/Lmarkussen/CinderPath/internal/scope"
)

type prerequisiteTestModule struct {
	name string
	run  func(modules.RunContext) (*modules.Result, error)
}

func (m prerequisiteTestModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: m.name, Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}
func (m prerequisiteTestModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (m prerequisiteTestModule) Run(_ context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	return m.run(run)
}

func prerequisiteTestOptions() live.Options {
	return live.Options{DC: "dc.sccm.lab", Ports: []int{389}, Concurrency: 1, ConnectTimeout: time.Second, HostTimeout: time.Second, Scope: scope.Input{Targets: []string{"dc.sccm.lab"}, MaxTargets: 1}, HTTP: live.HTTPOptions{Timeout: time.Second, MaxBodyBytes: 1024}}
}

func prerequisiteTestApplication(t *testing.T, module modules.Module) *Application {
	t.Helper()
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "cinderpath.db")
	return &Application{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), prerequisiteModuleSet: func(live.Options) []modules.Module { return []modules.Module{module} }}
}

func TestSafePrerequisiteModuleSelectionIsBoundedAndDeduplicated(t *testing.T) {
	a := &Application{}
	modules, err := a.safePrerequisiteModules(live.Options{}, []string{"live.ldap.rootdse", "live.ldap.rootdse", "live.ldap.sccm_directory"})
	if err != nil || len(modules) != 2 || modules[0].Metadata().Name != "live.ldap.rootdse" || modules[1].Metadata().Name != "live.ldap.sccm_directory" {
		t.Fatalf("modules=%v err=%v", moduleNames(modules), err)
	}
	if _, err := a.safePrerequisiteModules(live.Options{}, []string{"live.smb.share_metadata"}); err == nil {
		t.Fatal("non-registered prerequisite module accepted")
	}
}

func TestSafePrerequisiteExecutionPersistsEvidence(t *testing.T) {
	module := prerequisiteTestModule{name: "live.ldap.rootdse", run: func(modules.RunContext) (*modules.Result, error) {
		e := models.Evidence{Type: "ldap_rootdse", Data: map[string]any{"server": "dc.sccm.lab"}}
		e.Prepare(time.Now().UTC())
		return &modules.Result{Evidence: []models.Evidence{e}}, nil
	}}
	a := prerequisiteTestApplication(t, module)
	result, err := a.ExecuteSafePrerequisites(context.Background(), PrerequisiteExecutionRequest{TechniqueID: "CRED-2", Modules: []string{"live.ldap.rootdse"}, Live: prerequisiteTestOptions(), Args: []string{"assess", "CRED-2"}})
	if err != nil || result.Outcome.Run.ID == "" || result.Outcome.ModuleSummary.Executed != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	store, err := database.Open(context.Background(), a.Config.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	evidence, err := store.ListEvidence(context.Background())
	if err != nil || len(evidence) != 1 || evidence[0].RunID != result.Outcome.Run.ID {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestSafePrerequisiteResolutionStopsOnNoProgress(t *testing.T) {
	module := prerequisiteTestModule{name: "live.ldap.rootdse", run: func(modules.RunContext) (*modules.Result, error) { return &modules.Result{}, nil }}
	a := prerequisiteTestApplication(t, module)
	plan := planner.Plan{Technique: "CRED-2", Prerequisites: []planner.Decision{{State: planner.Collect, Module: "live.ldap.rootdse"}}}
	result, err := a.ResolveSafePrerequisites(context.Background(), PrerequisiteResolutionRequest{PrerequisiteExecutionRequest: PrerequisiteExecutionRequest{TechniqueID: "CRED-2", Live: prerequisiteTestOptions()}, Plan: plan, Replan: func(string) planner.Plan { return plan }})
	if err == nil || len(result.Runs) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSafePrerequisiteResolutionReplansAfterPersistingEvidence(t *testing.T) {
	module := prerequisiteTestModule{name: "live.ldap.rootdse", run: func(modules.RunContext) (*modules.Result, error) { return &modules.Result{}, nil }}
	a := prerequisiteTestApplication(t, module)
	plan := planner.Plan{Technique: "CRED-2", Prerequisites: []planner.Decision{{State: planner.Collect, Module: "live.ldap.rootdse"}}}
	var replannedRun string
	result, err := a.ResolveSafePrerequisites(context.Background(), PrerequisiteResolutionRequest{PrerequisiteExecutionRequest: PrerequisiteExecutionRequest{TechniqueID: "CRED-2", Live: prerequisiteTestOptions()}, Plan: plan, Replan: func(runID string) planner.Plan {
		replannedRun = runID
		return planner.Plan{Technique: "CRED-2", Prerequisites: []planner.Decision{{State: planner.Current}}}
	}})
	if err != nil || len(result.Runs) != 1 || replannedRun == "" || result.Plan.Prerequisites[0].State != planner.Current {
		t.Fatalf("result=%+v replan_run=%q err=%v", result, replannedRun, err)
	}
}

func TestSafePrerequisiteFailurePropagates(t *testing.T) {
	module := prerequisiteTestModule{name: "live.ldap.rootdse", run: func(modules.RunContext) (*modules.Result, error) { return nil, errors.New("authentication failed") }}
	a := prerequisiteTestApplication(t, module)
	plan := planner.Plan{Technique: "CRED-2", Prerequisites: []planner.Decision{{State: planner.Collect, Module: "live.ldap.rootdse"}}}
	result, err := a.ResolveSafePrerequisites(context.Background(), PrerequisiteResolutionRequest{PrerequisiteExecutionRequest: PrerequisiteExecutionRequest{TechniqueID: "CRED-2", Live: prerequisiteTestOptions()}, Plan: plan})
	if err == nil || len(result.Runs) != 1 || result.Runs[0].ModuleSummary.Failed != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPrerequisiteModuleSelectionDoesNotRepeatAttemptedModule(t *testing.T) {
	plan := planner.Plan{Prerequisites: []planner.Decision{{State: planner.Collect, Module: "live.ldap.rootdse"}, {State: planner.Collect, Module: "live.ldap.rootdse"}, {State: planner.Collect, Module: "live.ldap.sccm_directory"}}}
	selected := plannerPrerequisiteModules(plan, map[string]bool{"live.ldap.rootdse": true})
	if len(selected) != 1 || selected[0] != "live.ldap.sccm_directory" {
		t.Fatalf("selected=%v", selected)
	}
}
