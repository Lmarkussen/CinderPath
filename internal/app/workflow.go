package app

import (
	"fmt"
	"io"

	"github.com/Lmarkussen/CinderPath/internal/config"
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
	names := []string{"policy_access", "policy_retrieval", "policy_secret_extraction", "dp_content_metadata", "dp_content_download", "dp_artifact_inspection", "pxe_metadata", "pxe_material_collection", "task_sequence_parsing", "naa_recovery", "local_client_inspection", "live_attack_path_correlation"}
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
	if c.Profile == config.ProfileAggressive || c.Profile == config.ProfileYolo {
		for _, m := range FutureModuleRegistry() {
			add(m.Name, "not implemented", "registered future module")
			p.NotImplemented++
		}
	}
	add("reporting", "ready", "")
	p.Outputs = []string{c.Output.Directory + "/cinderpath-report.html", c.Output.Directory + "/cinderpath-report.json"}
	return p
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
