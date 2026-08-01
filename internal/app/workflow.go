package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

type StageDecision struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}
type WorkflowPlan struct {
	Project        string
	Profile        config.Profile
	Provider       string
	DryRun         bool
	Scope          int
	Stages         []StageDecision
	NotImplemented int
	Outputs        []string
	Modules        []ModuleDecision
}
type ModuleDecision struct {
	ModuleName, Category                                                              string
	Implemented, Selected                                                             bool
	DecisionState, ReasonCode, DecisionReason                                         string
	Requirements                                                                      []string
	NetworkBoundary                                                                   string
	MayContactNetwork, MayAuthenticate, MayDownload, MayExtractSecrets, MayAlterState bool
}

type ModuleRegistration struct {
	Name              string
	Category          string
	Implemented       bool
	SafetyLevel       string
	Profiles          []config.Profile
	Requirements      []string
	StateChanging     bool
	MayAuthenticate   bool
	MayDownload       bool
	MayExtractSecrets bool
	MayExecute        bool
}

func FutureModuleRegistry() []ModuleRegistration {
	names := []string{"live_policy_collection", "policy_protected_secret_decryption", "policy_access", "policy_retrieval", "policy_secret_extraction", "dp_content_metadata", "dp_content_download", "dp_artifact_inspection", "pxe_metadata", "pxe_material_collection", "task_sequence_parsing", "naa_recovery", "local_client_inspection", "live_attack_path_correlation"}
	out := make([]ModuleRegistration, 0, len(names))
	for _, name := range names {
		r := ModuleRegistration{Name: name, Category: "future", Implemented: false, SafetyLevel: "unavailable", Profiles: []config.Profile{config.ProfileAggressive, config.ProfileYolo}}
		r.MayDownload = name == "policy_retrieval" || name == "dp_content_download" || name == "pxe_material_collection"
		r.MayExtractSecrets = name == "policy_secret_extraction" || name == "naa_recovery"
		out = append(out, r)
	}
	return out
}

func BuildWorkflowPlan(c config.Config, dry bool) WorkflowPlan {
	p := WorkflowPlan{Project: c.Project.Name, Profile: c.Profile, Provider: c.Workflow.Provider, DryRun: dry, Scope: len(c.WorkflowScope.Targets) + len(c.WorkflowScope.IncludeCIDRs)}
	if p.Provider == "" {
		p.Provider = "mock"
	}
	add := func(n, s, r string) { p.Stages = append(p.Stages, StageDecision{n, s, r}) }
	add("configuration validation", "ready", "")
	if c.Identity.Username != "" {
		add("identity inspection", "ready", "")
	} else {
		add("identity inspection", "blocked", "no primary identity; anonymous workflow continues")
	}
	add("scope preparation", "ready", "")
	add("discovery", "ready", p.Provider+" provider")
	add("endpoint validation", "ready", "")
	add("topology correlation", "ready", "")
	add("temporal analysis", "ready", "")
	add("authentication planning", "ready", "")
	if c.Profile == config.ProfileSafe {
		add("authentication validation", "skipped", "safe profile never authenticates")
	} else if !c.Workflow.Authentication || !c.Safety.AllowAuthentication {
		add("authentication validation", "blocked", "authentication is disabled")
	} else if !c.Workflow.AcknowledgeLockoutRisk {
		add("authentication validation", "blocked", "lockout acknowledgement missing")
	} else if c.Identity.Username == "" {
		add("authentication validation", "blocked", "primary identity missing")
	} else {
		add("authentication validation", "planned", "exact validated endpoint and attempt budgets are still required")
	}
	add("assessment", "ready", "")
	add("policy protocol contract", "blocked", "no approved live protocol contract; live execution unavailable")
	if c.Policy.Fixtures.Enabled && len(c.Policy.Fixtures.Directories) > 0 {
		add("policy fixture import", "ready", "offline only")
		add("policy fixture analysis", "ready", "offline only")
		add("policy offline assignment parsing", "ready", "no network access")
		add("policy offline document parsing", "ready", "no network access")
		add("policy secret classification", "ready", "fixture-derived")
		add("policy secret output", "ready", "dedicated output controls apply")
	} else {
		add("policy fixture import", "not applicable", "no fixture directories configured")
	}
	if c.Policy.Research.Enabled {
		for _, n := range []string{"protocol bundle verification", "protocol research set validation", "protocol cross capture analysis", "protocol field correlation", "protocol sequence analysis", "protocol expected result validation"} {
			add(n, "ready", "offline research only")
		}
		if c.Policy.Research.DeriveCandidateContract {
			add("protocol candidate contract derivation", "ready", "candidate_contract only; live execution blocked")
		}
		if c.Policy.Research.GenerateDossier {
			add("protocol contract dossier generation", "ready", "redacted offline evidence")
		}
		for _, n := range []string{"capture input validation", "capture ingestion", "packet decoding", "flow reconstruction", "exchange pairing", "sequence derivation", "structured body parsing", "parser candidate derivation", "controlled matrix analysis", "corpus expected analysis", "capture findings", "capture capabilities", "capture dossier generation", "capture report generation"} {
			add(n, "ready", "offline capture research only; zero live requests")
		}
	}
	if c.Profile == config.ProfileAggressive || c.Profile == config.ProfileYolo {
		for _, m := range FutureModuleRegistry() {
			if m.Name == "live_policy_collection" {
				add(m.Name, "blocked", "no approved live protocol contract")
				continue
			}
			add(m.Name, "not implemented", "registered future module")
			p.NotImplemented++
		}
	}
	add("reporting", "ready", "")
	for _, s := range p.Stages {
		name := strings.ReplaceAll(s.Name, " ", "_")
		state := strings.ReplaceAll(s.Status, " ", "_")
		selected := state == "ready" || state == "planned"
		implemented := state != "not_implemented" && name != "live_policy_collection"
		category := "workflow"
		if !implemented {
			category = "future"
			selected = false
		}
		boundary := "none"
		mayNet := false
		if name == "discovery" && p.Provider == "live" {
			boundary = "live_target"
			mayNet = true
		} else if strings.Contains(name, "replay") {
			boundary = "loopback_only"
		} else if strings.Contains(name, "fixture") || strings.Contains(name, "policy_") {
			boundary = "local_files_only"
		}
		code := "planner_" + state
		if s.Reason == "" {
			code = "planner_default"
		}
		p.Modules = append(p.Modules, ModuleDecision{name, category, implemented, selected, state, code, s.Reason, nil, boundary, mayNet, false, false, name == "policy_secret_classification", false})
	}
	for _, m := range FutureModuleRegistry() {
		found := false
		for _, x := range p.Modules {
			if x.ModuleName == m.Name {
				found = true
			}
		}
		if !found {
			state := "not_implemented"
			reason := "registered future module is unavailable"
			if m.Name == "live_policy_collection" {
				state = "blocked"
				reason = "no approved live protocol contract"
			}
			p.Modules = append(p.Modules, ModuleDecision{m.Name, m.Category, false, false, state, "future_module_unavailable", reason, m.Requirements, func() string {
				if m.Name == "live_policy_collection" {
					return "live_target"
				}
				return "none"
			}(), false, m.MayAuthenticate, m.MayDownload, m.MayExtractSecrets, m.StateChanging})
		}
	}
	p.Outputs = []string{c.Output.Directory + "/cinderpath-report.html", c.Output.Directory + "/cinderpath-report.json"}
	return p
}

func (a *Application) PersistDryRun(ctx context.Context, plan WorkflowPlan, args []string) (models.Run, error) {
	persistCtx := context.WithoutCancel(ctx)
	store, e := database.Open(persistCtx, a.Config.DBPath)
	if e != nil {
		return models.Run{}, e
	}
	defer store.Close()
	r, e := store.CreateRun(persistCtx, "run dry-run", string(plan.Profile), version.Current().Version, args)
	if e != nil {
		return models.Run{}, e
	}
	status := models.RunCompleted
	if ctx.Err() != nil {
		status = models.RunCancelled
	}
	if e = a.persistPlan(ctx, store, r.ID, plan, true); e != nil {
		status = models.RunCompletedWithErrors
	}
	summary := map[string]any{"dry_run": true, "project": plan.Project, "provider": plan.Provider, "scope_estimate": plan.Scope, "effective_profile": plan.Profile, "stage_count": len(plan.Stages), "module_decision_count": len(plan.Modules), "authentication_budget_consumed": 0, "target_observations": 0, "live_policy_requests": 0}
	if e != nil {
		summary["planning_error"] = "plan_persistence_failed"
	}
	_ = store.FinishRun(persistCtx, r.ID, status, summary)
	now := time.Now().UTC()
	r.FinishedAt = &now
	r.Status = status
	r.Summary = summary
	return *r, e
}
func PrintWorkflowPlan(w io.Writer, p WorkflowPlan) {
	fmt.Fprintln(w, "CinderPath execution plan")
	fmt.Fprintf(w, "\nProject: %s\nProfile: %s\nProvider: %s\nScope: %d explicit inputs\n\nStages:\n", p.Project, p.Profile, p.Provider, p.Scope)
	for _, s := range p.Stages {
		fmt.Fprintf(w, "  %-30s %s", s.Name, s.Status)
		if s.Reason != "" {
			fmt.Fprintf(w, ": %s", s.Reason)
		}
		fmt.Fprintln(w)
	}
	if p.DryRun {
		fmt.Fprintln(w, "\nNetwork activity: none; dry-run")
	}
}
