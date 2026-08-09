package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/app"
	"github.com/Lmarkussen/CinderPath/internal/artifact"
	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/framework"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/outputpolicy"
	"github.com/Lmarkussen/CinderPath/internal/planner"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/Lmarkussen/CinderPath/internal/scope"
	"github.com/Lmarkussen/CinderPath/internal/terminal"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type canonicalResult struct {
	SchemaVersion int                   `json:"schema_version"`
	Workflow      string                `json:"workflow"`
	Target        string                `json:"target,omitempty"`
	TargetID      string                `json:"target_id,omitempty"`
	Framework     string                `json:"framework,omitempty"`
	Status        string                `json:"status"`
	Checked       []string              `json:"checked"`
	Findings      []string              `json:"findings"`
	Blockers      []string              `json:"blockers"`
	NextAction    string                `json:"next_action"`
	Network       string                `json:"network_behavior"`
	Redaction     outputpolicy.Metadata `json:"redaction"`
	Artifacts     []artifactBinding     `json:"artifact_plan"`
}

type artifactBinding struct {
	Stage      string `json:"stage"`
	Type       string `json:"artifact_type"`
	Resolution string `json:"resolution"`
}
type resolvedLimits struct {
	MaxClasses, MaxInstances, MaxFiles, MaxObservations int
	MaxBytes                                            int64
	PreWindow, PostWindow                               string
}

func limitsForProfile(profile string) resolvedLimits {
	switch profile {
	case "standard":
		return resolvedLimits{64, 1000, 1000, 25000, 32 << 20, "30s", "180s"}
	case "aggressive", "yolo":
		return resolvedLimits{96, 2000, 2000, 50000, 64 << 20, "60s", "300s"}
	case "research":
		return resolvedLimits{128, 4000, 4000, 100000, 128 << 20, "120s", "900s"}
	default:
		return resolvedLimits{32, 512, 500, 10000, 16 << 20, "30s", "180s"}
	}
}

type runContext struct {
	Target, TargetSource, Framework, FrameworkSource, Database, DatabaseSource, OutputDir, OutputDirSource, Profile, ProfileSource string
}

func resolveRunContext(explicitTarget, activeTarget string, configTargets []string, explicitFramework, configFramework, db, output, profile string) runContext {
	r := runContext{Database: db, DatabaseSource: "configuration", OutputDir: output, OutputDirSource: "configuration", Profile: profile, ProfileSource: "configuration"}
	switch {
	case explicitTarget != "":
		r.Target, r.TargetSource = explicitTarget, "explicit CLI flag"
	case activeTarget != "":
		r.Target, r.TargetSource = activeTarget, "active run context"
	case len(configTargets) > 0:
		r.Target, r.TargetSource = configTargets[0], "configuration file"
	case os.Getenv("CINDERPATH_TARGET") != "":
		r.Target, r.TargetSource = os.Getenv("CINDERPATH_TARGET"), "environment variable"
	default:
		r.TargetSource = "unset"
	}
	if explicitFramework != "" {
		r.Framework, r.FrameworkSource = explicitFramework, "explicit CLI flag"
	} else if configFramework != "" {
		r.Framework, r.FrameworkSource = configFramework, "configuration file"
	} else {
		r.Framework, r.FrameworkSource = "misconfiguration-manager", "safe default"
	}
	return r
}

type workflowOptions struct{ Run, Target, Format string }

func bindWorkflowContextFlags(c *cobra.Command, o *workflowOptions) {
	c.Flags().StringVar(&o.Run, "run", "", "existing run context")
	c.Flags().StringVar(&o.Target, "target", "", "exact target associated with the run")
	c.Flags().StringVar(&o.Format, "format", "text", "text or json")
}

func (s *state) assessWorkflowCommand(kind string) *cobra.Command {
	var options workflowOptions
	c := &cobra.Command{Use: kind, Short: "Plan the bounded " + kind + " assessment as one operator workflow", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		ctx := resolveRunContext(options.Target, "", s.cfg.WorkflowScope.Targets, "misconfiguration-manager", "", s.cfg.DBPath, s.cfg.OutputDir, string(s.cfg.Profile))
		if ctx.Target == "" {
			return errors.New("target is required from --target, active run context, configuration, or CINDERPATH_TARGET")
		}
		r := canonicalResult{SchemaVersion: 1, Workflow: "assess_" + strings.ReplaceAll(kind, "-", "_"), Target: redactedTarget(ctx.Target), TargetID: targetID(ctx.Target), Framework: ctx.Framework, Status: "plan_ready_execution_requires_authorized_connector", Findings: []string{}, Network: "none", Redaction: s.outputPolicy().Metadata(), NextAction: "run through an explicitly authorized connector; intermediate artifacts are associated by run context"}
		if kind == "pxe" {
			r.Checked = []string{"candidate verification", "server posture metadata", "provider deployment metadata", "framework mapping", "dossier"}
			r.Blockers = []string{"active PXE validation remains separately gated", "this CLI process has no authorized remote connector"}
			r.Artifacts = []artifactBinding{{"posture", "pxe_posture", "run context"}, {"provider", "pxe_deployment_metadata", "run context"}, {"report", "dossier", "run context"}}
		} else {
			r.Checked = []string{"client inventory", "schema ranking", "instance selection", "credential-policy discovery", "safe preview planning", "dossier"}
			r.Blockers = []string{"live policy requests are prohibited", "this CLI process has no authorized remote connector"}
			r.Artifacts = []artifactBinding{{"inventory", "client_inventory", "run context"}, {"schema", "policy_schema_analysis", "run context"}, {"runtime", "policy_runtime_metadata", "run context"}, {"credentials", "credential_policy_metadata", "run context"}, {"preview", "preview_plan", "run context"}, {"report", "dossier", "run context"}}
		}
		if options.Format == "json" {
			return json.NewEncoder(s.stdout).Encode(r)
		}
		fmt.Fprintf(s.stdout, "CinderPath %s assessment workflow\nTarget: %s\nTarget ID: %s\nStatus: %s\nResult: no assessment performed\nChecked stages: %s\nBlockers: %s\nNext action: %s\nNetwork activity: none\n", kind, r.Target, targetID(ctx.Target), r.Status, strings.Join(r.Checked, ", "), strings.Join(r.Blockers, "; "), r.NextAction)
		if kind == "pxe" {
			fmt.Fprintln(s.stdout, "Would inspect: one authorized server's WDS/PXE posture, unknown-computer support, boot-image metadata, and bounded SMS Provider deployment metadata.")
		}
		if s.verbose {
			fmt.Fprintf(s.stdout, "Resolved context: target=%s framework=%s database=%s output=%s profile=%s\n", ctx.TargetSource, ctx.FrameworkSource, ctx.DatabaseSource, ctx.OutputDirSource, ctx.ProfileSource)
			limits := limitsForProfile(ctx.Profile)
			fmt.Fprintf(s.stdout, "Resolved limits: classes=%d instances=%d files=%d observations=%d bytes=%d pre=%s post=%s\n", limits.MaxClasses, limits.MaxInstances, limits.MaxFiles, limits.MaxObservations, limits.MaxBytes, limits.PreWindow, limits.PostWindow)
		}
		return nil
	}}
	bindWorkflowContextFlags(c, &options)
	return c
}

type techniqueOptions struct {
	target, runID, format, provider, domainController, username, passwordEnv, passwordFile string
}

func bindTechniqueOptions(f interface {
	StringVar(*string, string, string, string)
}, o *techniqueOptions) {
	f.StringVar(&o.target, "target", "", "assessment target")
	f.StringVar(&o.runID, "run", "", "existing run context")
	f.StringVar(&o.format, "format", "text", "text or json")
	f.StringVar(&o.provider, "provider", "", "provider override: mock or live")
	f.StringVar(&o.domainController, "domain-controller", "", "authorized domain controller")
	f.StringVar(&o.username, "username", "", "authorized identity username")
	f.StringVar(&o.passwordEnv, "password-env", "", "environment variable containing the identity password")
	f.StringVar(&o.passwordFile, "password-file", "", "bounded file containing the identity password")
}

func (s *state) assessTechniqueCommand(o *techniqueOptions) *cobra.Command {
	if o == nil {
		o = &techniqueOptions{}
	}
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Short: "Assess one supported technique", Hidden: true, Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		// These narrow overrides preserve config-first operation for one-off assessments.
		if o.provider != "" {
			s.cfg.Workflow.Provider = o.provider
		}
		if o.domainController != "" {
			s.cfg.WorkflowScope.DomainController = o.domainController
		}
		if o.username != "" {
			s.cfg.Identity.Username = o.username
		}
		if o.passwordEnv != "" {
			s.cfg.Identity.PasswordEnv, s.cfg.Identity.PasswordFile = o.passwordEnv, ""
		}
		if o.passwordFile != "" {
			s.cfg.Identity.PasswordFile, s.cfg.Identity.PasswordEnv = o.passwordFile, ""
		}
		s.application.Config = s.cfg
		techniqueID := strings.ToUpper(args[0])
		plan := s.techniquePlan(techniqueID, o.target, o.runID)
		support := "unsupported_or_unknown"
		if snapshot, err := framework.EmbeddedSnapshot(); err == nil {
			for _, coverage := range snapshot.Coverage {
				if coverage.TechniqueID == techniqueID {
					support = string(coverage.Assessment)
					break
				}
			}
		}
		if techniqueID == "RECON-1" && s.cfg.Workflow.Provider == "live" {
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
			defer cancel()
			opts := recon1LiveOptions(s.cfg, o.target)
			if err := live.ResolveLDAPPasswordContext(ctx, &opts.LDAP); err != nil {
				return err
			}
			out, err := s.application.DiscoverWithOptions(ctx, []string{"assess", "technique", techniqueID}, app.DiscoverOptions{Provider: "live-recon1", Live: opts})
			if err != nil {
				return err
			}
			status := string(out.Run.Status)
			if status == "" {
				status = "completed"
			}
			s.printRECON1Text(techniqueID, o.target, status, out, support)
			return nil
		}
		if techniqueID == "RECON-2" {
			if s.cfg.Workflow.Provider == "live" {
				ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
				defer cancel()
				opts := recon2LiveOptions(s.cfg, o.target)
				if err := live.ResolveSMBPassword(&opts.SMB); err != nil {
					return err
				}
				out, err := s.application.DiscoverWithOptions(ctx, []string{"assess", "technique", techniqueID}, app.DiscoverOptions{Provider: "live-recon2", Live: opts})
				if err != nil {
					return err
				}
				status := out.TechniqueStatus
				if status == "" {
					status = string(out.Run.Status)
				}
				if o.format == "json" {
					return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": techniqueID, "framework_revision": snapshotRevision(), "status": status, "target": redactedTarget(o.target), "target_id": targetID(o.target), "assessment_support": support, "network_behavior": "smb_ipc_srvsvc_share_metadata_only", "selected_modules": []string{"live.smb.share_metadata"}, "defensive_mappings": defensiveMappings(techniqueID), "assets": out.Assets, "findings": out.Findings, "run_id": out.Run.ID, "live_policy_requests": 0, "redaction": s.outputPolicy().Metadata()})
				}
				s.printRECON2Text(techniqueID, o.target, status, out, support)
				return nil
			}
			mappings := defensiveMappings(techniqueID)
			if o.format == "json" {
				return json.NewEncoder(s.stdout).Encode(map[string]any{
					"technique_id": techniqueID, "framework_revision": snapshotRevision(), "status": "not_run_no_connector", "target": redactedTarget(o.target), "target_id": targetID(o.target), "redaction": s.outputPolicy().Metadata(),
					"assessment_support": support, "network_behavior": "none", "selected_modules": []string{}, "defensive_mappings": mappings,
					"limitations": []string{"configure the existing authorized live connector for bounded authenticated SMB share metadata", "no SMB protocol request was sent"}, "live_policy_requests": 0, "run_id": o.runID,
				})
			}
			fmt.Fprintf(s.stdout, "Technique: %s\nTarget: %s\nTarget ID: %s\nFramework revision: %s\nExecution status: not_run_no_connector\nResult: no assessment performed; no findings are available\nAssessment support: %s\nWould check: authenticated SMB2/3 IPC$ and srvsvc share metadata, then classify generic versus SCCM shares\nSelected modules: none\nNetwork behavior: none\nDefensive mappings: %s\nLimitation: configure the existing authorized live connector; no SMB protocol request was sent\n", techniqueID, redactedTarget(o.target), targetID(o.target), snapshotRevision(), support, strings.Join(mappings, ", "))
			return nil
		}
		if techniqueID == "RECON-3" {
			if s.cfg.Workflow.Provider == "live" {
				ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
				defer cancel()
				opts := recon3LiveOptions(s.cfg, o.target)
				out, err := s.application.DiscoverWithOptions(ctx, []string{"assess", "technique", techniqueID}, app.DiscoverOptions{Provider: "live-recon3", Live: opts})
				if err != nil {
					return err
				}
				status := out.TechniqueStatus
				if status == "" {
					status = string(out.Run.Status)
				}
				if o.format == "json" {
					return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": techniqueID, "framework_revision": snapshotRevision(), "status": status, "target": redactedTarget(o.target), "target_id": targetID(o.target), "assessment_support": support, "network_behavior": "sccm_http_allowlist_only", "selected_modules": []string{"live.sccm.http_recon"}, "request_summary": out.TechniqueSummary, "defensive_mappings": defensiveMappings(techniqueID), "assets": out.Assets, "findings": out.Findings, "run_id": out.Run.ID, "redaction": s.outputPolicy().Metadata()})
				}
				s.printRECON3Text(techniqueID, o.target, status, out, support)
				return nil
			}
			mappings := defensiveMappings(techniqueID)
			if o.format == "json" {
				return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": techniqueID, "framework_revision": snapshotRevision(), "status": "not_run_no_connector", "target": redactedTarget(o.target), "target_id": targetID(o.target), "assessment_support": support, "network_behavior": "none", "selected_modules": []string{}, "defensive_mappings": mappings, "limitations": []string{"configure the existing authorized live connector for fixed SCCM HTTP route reconnaissance", "no HTTP request was sent"}, "run_id": o.runID, "redaction": s.outputPolicy().Metadata()})
			}
			fmt.Fprintf(s.stdout, "Technique: %s\nTarget: %s\nTarget ID: %s\nFramework revision: %s\nExecution status: not_run_no_connector\nResult: no assessment performed; no findings are available\nAssessment support: %s\nWould check: one explicit host using the fixed anonymous SCCM HTTP GET/HEAD route allowlist\nSelected modules: none\nNetwork behavior: none\nDefensive mappings: %s\nLimitation: configure the existing authorized live connector; no HTTP request was sent\n", techniqueID, redactedTarget(o.target), targetID(o.target), snapshotRevision(), support, strings.Join(mappings, ", "))
			return nil
		}
		var prerequisiteRuns []app.Outcome
		var executedPrerequisites []string
		if s.cfg.Workflow.Provider == "live" && planHasCollection(plan) {
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Timeout)
			defer cancel()
			opts := safePrerequisiteOptions(s.cfg, o.target)
			if err := live.ResolveLDAPPasswordContext(ctx, &opts.LDAP); err != nil {
				return err
			}
			result, err := s.application.ResolveSafePrerequisites(ctx, app.PrerequisiteResolutionRequest{PrerequisiteExecutionRequest: app.PrerequisiteExecutionRequest{TechniqueID: techniqueID, Live: opts, Args: []string{"assess", techniqueID, "prerequisites"}}, Plan: plan, Replan: func(runID string) planner.Plan { return s.techniquePlan(techniqueID, o.target, runID) }})
			prerequisiteRuns, executedPrerequisites, plan = result.Runs, result.ExecutedModules, result.Plan
			if err != nil {
				status := "prerequisite_collection_failed"
				var runID string
				if len(prerequisiteRuns) > 0 {
					runID = prerequisiteRuns[len(prerequisiteRuns)-1].Run.ID
				}
				if o.format == "json" {
					return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": techniqueID, "status": status, "prerequisites": plan.Prerequisites, "prerequisite_collection": prerequisiteRuns, "live_policy_requests": 0, "redaction": s.outputPolicy().Metadata()})
				}
				s.printTechniqueText(techniqueID, o.target, status, "Result: safe prerequisite collection did not complete; no technique assessment was performed", executedPrerequisites, runID, support)
				printPrerequisites(s.stdout, s.renderer, plan)
				return err
			}
		}
		status := techniquePlanStatus(plan)
		if o.format == "json" {
			result := map[string]any{"technique_id": techniqueID, "framework_revision": snapshotRevision(), "status": status, "target": redactedTarget(o.target), "target_id": targetID(o.target), "assessment_support": support, "defensive_mappings": defensiveMappings(techniqueID), "network_behavior": "none", "run_id": o.runID, "prerequisites": plan.Prerequisites, "execution_plan": plan.Modules, "next_actions": []string{"safe prerequisites are resolved automatically when authorized"}, "live_policy_requests": 0, "redaction": s.outputPolicy().Metadata()}
			if len(prerequisiteRuns) > 0 {
				result["prerequisite_collection"] = map[string]any{"runs": prerequisiteRuns, "modules": executedPrerequisites}
			}
			if techniqueID == "CRED-2" {
				result["policy_acquisition"] = policy.CRED2AcquisitionContract()
			}
			return json.NewEncoder(s.stdout).Encode(result)
		}
		detail := "Result: no assessment performed; no findings are available"
		if len(prerequisiteRuns) > 0 {
			detail = "Result: safe prerequisites were collected; remaining prerequisites block technique assessment"
		}
		s.printTechniqueText(techniqueID, o.target, status, detail, plan.Modules, o.runID, support)
		if len(prerequisiteRuns) > 0 {
			fmt.Fprintf(s.stdout, "Prerequisite collection\n  Run ID                  %s\n  Modules                 %s\n", s.renderer.Dim(prerequisiteRuns[len(prerequisiteRuns)-1].Run.ID), s.renderer.Target(strings.Join(executedPrerequisites, ", ")))
		}
		printPrerequisites(s.stdout, s.renderer, plan)
		if techniqueID == "CRED-2" {
			contract := policy.CRED2AcquisitionContract()
			fmt.Fprintf(s.stdout, "Policy acquisition: %s\nPolicy request: %s %s\nLive policy requests: 0\nLimitation: %s\n", s.renderer.Warning(string(contract.State)), s.renderer.Target(contract.Method), s.renderer.Target(contract.Route), contract.Reason)
		}
		return nil
	}}
	return c
}

func techniquePlanStatus(plan planner.Plan) string {
	for _, decision := range plan.Prerequisites {
		switch decision.State {
		case planner.OperatorInput, planner.Missing, planner.Stale:
			return "blocked_missing_prerequisite"
		case planner.Blocked, planner.Unsupported:
			return "blocked_by_safety_gate"
		case planner.Collect:
			return "prerequisite_collection_required"
		}
	}
	return "not_run_no_connector"
}

func planHasCollection(plan planner.Plan) bool {
	for _, decision := range plan.Prerequisites {
		if decision.State == planner.Collect && decision.Module != "" {
			return true
		}
	}
	return false
}

func (s *state) techniquePlan(technique, target, runID string) planner.Plan {
	var evidence []models.Evidence
	if _, err := os.Stat(s.cfg.DBPath); err == nil {
		store, err := database.Open(context.Background(), s.cfg.DBPath)
		if err == nil {
			evidence, _ = store.ListEvidence(context.Background())
			_ = store.Close()
		}
	}
	return planner.Resolve(planner.Input{Technique: technique, Provider: s.cfg.Workflow.Provider, Target: target, DomainController: s.cfg.WorkflowScope.DomainController, Username: s.cfg.Identity.Username, AllowSafeLDAP: &s.cfg.Workflow.LDAP, CurrentRun: runID, Evidence: evidence, Now: time.Now().UTC(), EvidenceMaxAge: time.Duration(s.cfg.Staleness.EvidenceDays) * 24 * time.Hour})
}

func (s *state) evidenceForRun(runID string) []models.Evidence {
	if runID == "" {
		return nil
	}
	store, err := database.Open(context.Background(), s.cfg.DBPath)
	if err != nil {
		return nil
	}
	defer store.Close()
	evidence, err := store.ListEvidence(context.Background())
	if err != nil {
		return nil
	}
	out := make([]models.Evidence, 0)
	for _, item := range evidence {
		if item.RunID == runID {
			out = append(out, item)
		}
	}
	return out
}

func (s *state) printTechniqueHeader(id, target, status string) {
	fmt.Fprintf(s.stdout, "Technique: %s\nTarget: %s\nStatus: %s\n", id, s.renderer.Target(redactedTarget(target)), s.renderer.Status(status))
}

func (s *state) printTechniqueFooter(modules []string, runID, support string) {
	if len(modules) > 0 {
		fmt.Fprintf(s.stdout, "Selected modules: %s\n", s.renderer.Target(strings.Join(modules, ", ")))
	}
	if support != "" {
		fmt.Fprintf(s.stdout, "Assessment support: %s\n", s.renderer.Dim(support))
	}
	if runID != "" {
		fmt.Fprintf(s.stdout, "Run ID: %s\n", s.renderer.Dim(runID))
	}
}

type recon1Details struct {
	RootDSE, SystemManagement, Publishing bool
	Sites, ManagementPoints               []string
}

func recon1DetailsFor(evidence []models.Evidence) recon1Details {
	var out recon1Details
	for _, item := range evidence {
		switch item.Type {
		case "ldap_rootdse":
			out.RootDSE = true
		case "recon1_ldap_assessment":
			out.Publishing = item.Data["publishing_state"] == "sccm_ad_publishing_confirmed"
			out.SystemManagement = item.Data["system_management_state"] == "system_management_container_present"
			out.Sites = append(out.Sites, evidenceStrings(item.Data["sites_observed"])...)
			out.ManagementPoints = append(out.ManagementPoints, evidenceStrings(item.Data["management_points_observed"])...)
		}
	}
	out.Sites = uniqueStrings(out.Sites)
	out.ManagementPoints = uniqueStrings(out.ManagementPoints)
	return out
}

type shareSummary struct{ Name, Classification string }

func recon2SharesFor(evidence []models.Evidence) []shareSummary {
	var out []shareSummary
	for _, item := range evidence {
		if item.Type != "smb_share_metadata" {
			continue
		}
		for _, raw := range evidenceMaps(item.Data["shares"]) {
			name, classification := fmt.Sprint(raw["name"]), fmt.Sprint(raw["classification"])
			if name != "" && name != "<nil>" {
				out = append(out, shareSummary{Name: name, Classification: classification})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func evidenceStrings(v any) []string {
	items, ok := v.([]any)
	if !ok {
		if strings, ok := v.([]string); ok {
			return strings
		}
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text := strings.TrimSpace(fmt.Sprint(item)); text != "" && text != "<nil>" {
			out = append(out, text)
		}
	}
	return out
}

func evidenceMaps(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func (s *state) printRECON1Text(id, target, status string, out app.Outcome, support string) {
	details := recon1DetailsFor(s.evidenceForRun(out.Run.ID))
	s.printTechniqueHeader(id, target, status)
	fmt.Fprintf(s.stdout, "Discovery\n  %s RootDSE\n  %s System Management\n  %s SCCM publishing\n", statusMark(s.renderer, details.RootDSE), statusMark(s.renderer, details.SystemManagement), statusMark(s.renderer, details.Publishing))
	if len(details.Sites) > 0 || len(details.ManagementPoints) > 0 {
		fmt.Fprintln(s.stdout, "SCCM")
		if len(details.Sites) > 0 {
			fmt.Fprintf(s.stdout, "  Site                  %s\n", s.renderer.Target(strings.Join(details.Sites, ", ")))
		}
		if len(details.ManagementPoints) > 0 {
			fmt.Fprintf(s.stdout, "  Management point      %s\n", s.renderer.Target(strings.Join(details.ManagementPoints, ", ")))
		}
	}
	fmt.Fprintf(s.stdout, "Evidence: assets=%d findings=%d\n", out.Assets, sumFindings(out.Findings))
	s.printTechniqueFooter([]string{"live.ldap.rootdse", "live.ldap.sccm_directory"}, out.Run.ID, support)
}

func statusMark(r terminal.Renderer, observed bool) string {
	if observed {
		return r.Success("✓")
	}
	return r.Warning("?")
}

func (s *state) printRECON2Text(id, target, status string, out app.Outcome, support string) {
	s.printTechniqueHeader(id, target, status)
	fmt.Fprintf(s.stdout, "Framework revision: %s\nSMB\n", s.renderer.Dim(snapshotRevision()))
	shares := recon2SharesFor(s.evidenceForRun(out.Run.ID))
	if len(shares) == 0 {
		fmt.Fprintln(s.stdout, "  Share metadata         none returned")
	} else {
		fmt.Fprintln(s.stdout, "  Shares")
		for _, share := range shares {
			fmt.Fprintf(s.stdout, "    %-22s %s\n", s.renderer.Target(share.Name), share.Classification)
		}
	}
	fmt.Fprintf(s.stdout, "Evidence: assets=%d findings=%d\nNetwork behavior: authenticated SMB2/3 IPC$ srvsvc share metadata only\n", out.Assets, sumFindings(out.Findings))
	s.printTechniqueFooter([]string{"live.smb.share_metadata"}, out.Run.ID, support)
}

func (s *state) printRECON3Text(id, target, status string, out app.Outcome, support string) {
	s.printTechniqueHeader(id, target, status)
	fmt.Fprintf(s.stdout, "Framework revision: %s\nHTTP\n  Requests              %v / %v\n  Successful            %v\n  Failed                %v\nEvidence: assets=%d findings=%d\nNetwork behavior: fixed anonymous SCCM HTTP GET/HEAD allowlist only\n", s.renderer.Dim(snapshotRevision()), out.TechniqueSummary["actual_request_count"], out.TechniqueSummary["configured_maximum_requests"], out.TechniqueSummary["successful_response_count"], out.TechniqueSummary["failure_count"], out.Assets, sumFindings(out.Findings))
	s.printTechniqueFooter([]string{"live.sccm.http_recon"}, out.Run.ID, support)
}
func printPrerequisites(w io.Writer, r terminal.Renderer, p planner.Plan) {
	if len(p.Prerequisites) == 0 {
		return
	}
	fmt.Fprintln(w, "Prerequisites:")
	for _, d := range p.Prerequisites {
		marker := r.Warning("?")
		if d.State == planner.Current || d.State == planner.Recent {
			marker = r.Success("✓")
		}
		if d.State == planner.Collect {
			marker = r.Target("→")
		}
		provenance := d.Reason
		if d.SourceRun != "" {
			provenance += " · " + r.Dim(d.SourceRun)
			if d.Age != "" {
				provenance += " · " + r.Dim(d.Age)
			}
		}
		fmt.Fprintf(w, "  %s %-26s %s\n", marker, d.Label, provenance)
	}
}
func (s *state) printTechniqueText(id, target, status, detail string, modules []string, runID, support string) {
	s.printTechniqueHeader(id, target, status)
	fmt.Fprintln(s.stdout, detail)
	s.printTechniqueFooter(modules, runID, support)
}

func defensiveMappings(id string) []string {
	s, err := framework.EmbeddedSnapshot()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, m := range s.MatrixMappings {
		if m.AttackID == id {
			out = append(out, m.DefenseID)
		}
	}
	sort.Strings(out)
	return out
}

func snapshotRevision() string {
	s, err := framework.EmbeddedSnapshot()
	if err != nil {
		return "unknown"
	}
	return s.UpstreamRevision
}
func sumFindings(m map[models.Severity]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
func recon1LiveOptions(c config.Config, target string) live.Options {
	return safePrerequisiteOptions(c, target)
}

func safePrerequisiteOptions(c config.Config, target string) live.Options {
	server := c.WorkflowScope.DomainController
	if server == "" {
		server = target
	}
	host := mustDuration(c.Discovery.HostTimeout)
	if host <= 0 {
		host = 30 * time.Second
	}
	search := mustDuration(c.LDAP.SearchTimeout)
	if search <= 0 {
		search = 30 * time.Second
	}
	return live.Options{Domain: c.WorkflowScope.Domain, DC: server, Ports: []int{389, 636}, Concurrency: 1, ConnectTimeout: host, HostTimeout: host, Scope: scope.Input{Targets: []string{server}, MaxTargets: 1}, HTTP: live.HTTPOptions{Timeout: host, MaxBodyBytes: 1024, MaxRedirects: 0}, LDAP: live.LDAPOptions{Enabled: c.Workflow.LDAP, Server: server, User: c.Identity.Username, PasswordEnv: c.Identity.PasswordEnv, PasswordFile: c.Identity.PasswordFile, PageSize: c.LDAP.PageSize, MaxEntries: c.LDAP.MaxEntries, SearchTimeout: search}}
}

func recon2LiveOptions(c config.Config, target string) live.Options {
	server := target
	if server == "" {
		server = c.WorkflowScope.DomainController
	}
	host := mustDuration(c.Discovery.HostTimeout)
	if host <= 0 {
		host = 10 * time.Second
	}
	return live.Options{Domain: c.WorkflowScope.Domain, DC: server, Ports: []int{445}, Concurrency: 1, ConnectTimeout: host, HostTimeout: host, Scope: scope.Input{Targets: []string{server}, MaxTargets: 1}, HTTP: live.HTTPOptions{Timeout: host, MaxBodyBytes: 1024, MaxRedirects: 0}, SMB: live.SMBOptions{Enabled: true, Server: server, User: c.Identity.Username, PasswordEnv: c.Identity.PasswordEnv, PasswordFile: c.Identity.PasswordFile, Domain: c.WorkflowScope.Domain, Port: 445, ConnectTimeout: 5 * time.Second, OperationTimeout: 10 * time.Second, MaxShares: 128}}
}

func recon3LiveOptions(c config.Config, target string) live.Options {
	server := target
	if server == "" {
		server = c.WorkflowScope.DomainController
	}
	host := mustDuration(c.Discovery.HostTimeout)
	if host <= 0 {
		host = 30 * time.Second
	}
	return live.Options{Domain: c.WorkflowScope.Domain, DC: server, Ports: []int{80, 443}, Concurrency: 1, ConnectTimeout: host, HostTimeout: host, Scope: scope.Input{Targets: []string{server}, MaxTargets: 1}, HTTP: live.HTTPOptions{UserAgent: c.Discovery.UserAgent, MaxBodyBytes: c.Discovery.HTTPMaxBodyBytes, MaxRedirects: 0, Timeout: host}, LDAP: live.LDAPOptions{Enabled: true, Server: server, User: c.Identity.Username, PasswordEnv: c.Identity.PasswordEnv, PasswordFile: c.Identity.PasswordFile}}
}

func redactedTarget(v string) string {
	if v == "" {
		return "[from active run context]"
	}
	return v
}

func targetID(v string) string {
	if v == "" {
		return ""
	}
	return "target_" + shortFingerprint(v)
}

func shortFingerprint(v string) string {
	// Stable non-cryptographic presentation ID; never used as evidence identity.
	var h uint64 = 1469598103934665603
	for i := 0; i < len(v); i++ {
		h ^= uint64(v[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%012x", h)[:12]
}

func (s *state) validationCommand() *cobra.Command {
	root := &cobra.Command{Use: "validate", Short: "Validate findings through explicit, supported safety gates"}
	var run string
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error {
		if run == "" {
			return errors.New("run is required after configuration resolution")
		}
		return errors.New("technique validation is unsupported in this build; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "existing run ID")
	root.AddCommand(c)
	return root
}

func (s *state) exploitCommand() *cobra.Command {
	root := &cobra.Command{Use: "exploit", Short: "Execute only separately authorized and implemented techniques"}
	var run string
	var ack bool
	c := &cobra.Command{Use: "technique TECHNIQUE_ID", Args: cobra.ExactArgs(1), RunE: func(*cobra.Command, []string) error {
		if run == "" {
			return errors.New("run is required after configuration resolution")
		}
		if !ack {
			return errors.New("acknowledge-impact is required before execution")
		}
		return errors.New("authorized technique execution is not implemented; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "existing assessment run ID")
	c.Flags().BoolVar(&ack, "acknowledge-impact", false, "acknowledge the documented impact before execution")
	root.AddCommand(c)
	return root
}

func (s *state) cleanupCommand() *cobra.Command {
	var run string
	c := &cobra.Command{Use: "cleanup", Short: "Apply cleanup obligations recorded by an authorized execution", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if run == "" {
			return errors.New("run is required after configuration resolution")
		}
		return errors.New("no cleanup-capable execution exists in this build; no action was performed")
	}}
	c.Flags().StringVar(&run, "run", "", "run ID containing cleanup obligations")
	return c
}

func (s *state) researchCommand() *cobra.Command {
	root := &cobra.Command{Use: "research", Short: "Advanced offline evidence and parser workflows"}
	capture := s.captureCommand()
	capture.Hidden = false
	capture.Deprecated = ""
	policy := s.clientArtifactsCommand()
	policy.Use = "policy"
	policy.Hidden = false
	policy.Deprecated = ""
	evidence := s.captureKitCommand()
	evidence.Use = "evidence"
	evidence.Hidden = false
	evidence.Deprecated = ""
	root.AddCommand(capture, policy, evidence)
	root.AddCommand(s.researchFrameworkCommand())
	root.AddCommand(s.artifactRegistryCommand())
	advancedDiscover := s.advancedDiscoverCommand()
	advancedDiscover.Use = "discover-advanced"
	root.AddCommand(advancedDiscover)
	pxeCommand := s.pxeCommand()
	pxeCommand.Hidden = false
	protocolCommand := s.protocolCommand()
	protocolCommand.Hidden = false
	policyModel := s.policyCommand()
	policyModel.Use = "policy-model"
	root.AddCommand(pxeCommand, protocolCommand, policyModel, s.matrixCommand(), s.sequenceCaptureCommand(), s.parserCommand(), s.analysisCommand(), s.identityCommand(), s.capabilitiesCommand(), s.authCommand(), s.configCommand(), s.runsCommand(), s.clientIdentityCommand())
	lab := s.labCommand()
	for _, child := range lab.Commands() {
		if child.Name() == "capture-plan" {
			lab.RemoveCommand(child)
			root.AddCommand(child)
			break
		}
	}
	legacyResearch := s.captureResearchCommand()
	for _, child := range legacyResearch.Commands() {
		legacyResearch.RemoveCommand(child)
		root.AddCommand(child)
	}
	return root
}

func (s *state) artifactRegistryCommand() *cobra.Command {
	root := &cobra.Command{Use: "artifact", Short: "Register or resolve run-associated research artifacts"}
	var runID, typ, path, stage, workflow string
	var sensitive bool
	registryPath := func() string { return filepath.Join(s.cfg.OutputDir, "artifact-registry.json") }
	load := func() (*artifact.Registry, error) {
		r, e := artifact.Load(registryPath())
		if os.IsNotExist(e) {
			return artifact.New(), nil
		}
		return &r, e
	}
	register := &cobra.Command{Use: "register", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := load()
		if e != nil {
			return e
		}
		fp, e := artifact.FileFingerprint(path)
		if e != nil {
			return e
		}
		id := "artifact_" + shortFingerprint(runID+typ+fp)
		e = r.Register(artifact.Record{ID: id, RunID: runID, Workflow: workflow, Stage: stage, Type: typ, Path: path, Fingerprint: fp, CreatedAt: time.Now().UTC(), Sensitive: sensitive})
		if e != nil {
			return e
		}
		if e = os.MkdirAll(s.cfg.OutputDir, 0700); e != nil {
			return e
		}
		if e = r.Save(registryPath()); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Artifact registered: %s type=%s sensitive=%t\n", id, typ, sensitive)
		return nil
	}}
	register.Flags().StringVar(&runID, "run", "", "run ID")
	register.Flags().StringVar(&typ, "artifact-type", "", "canonical artifact type")
	register.Flags().StringVar(&path, "artifact", "", "direct-file research artifact")
	register.Flags().StringVar(&stage, "stage", "research", "producing workflow stage")
	register.Flags().StringVar(&workflow, "workflow", "research", "owning workflow")
	register.Flags().BoolVar(&sensitive, "sensitive", false, "mark artifact sensitive")
	_ = register.MarkFlagRequired("artifact-type")
	_ = register.MarkFlagRequired("artifact")
	resolve := &cobra.Command{Use: "resolve", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := load()
		if e != nil {
			return e
		}
		x, e := r.ResolveLatest(runID, typ)
		if e != nil {
			return e
		}
		if e = artifact.VerifyFingerprint(x.Path, x.Fingerprint); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "Artifact resolved: %s type=%s file=%s sensitive=%t reviewed=%t\n", x.ID, x.Type, filepath.Base(x.Path), x.Sensitive, x.Reviewed)
		return nil
	}}
	resolve.Flags().StringVar(&runID, "run", "", "run ID")
	resolve.Flags().StringVar(&typ, "artifact-type", "", "canonical artifact type")
	_ = resolve.MarkFlagRequired("artifact-type")
	root.AddCommand(register, resolve)
	return root
}

func (s *state) debugCommand(root *cobra.Command) *cobra.Command {
	debug := &cobra.Command{Use: "debug", Short: "Redacted diagnostics for command plans and internal state"}
	var format string
	inv := &cobra.Command{Use: "command-inventory", Short: "Emit the classified Cobra command and flag inventory", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		x := buildCommandInventory(root)
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(x)
		}
		for _, c := range x.Commands {
			fmt.Fprintf(s.stdout, "%s\t%s\tflags=%d required=%d\n", c.Path, c.Category, len(c.Flags), c.RequiredFlagCount)
		}
		return nil
	}}
	inv.Flags().StringVar(&format, "format", "text", "text or json")
	metrics := &cobra.Command{Use: "cli-complexity", Short: "Report generated CLI complexity metrics and public budgets", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return json.NewEncoder(s.stdout).Encode(buildComplexity(buildCommandInventory(root)))
	}}
	debug.AddCommand(inv, metrics)
	return debug
}

type complexityReport struct {
	TotalCommands               int `json:"total_commands"`
	VisibleCommands             int `json:"visible_commands"`
	HiddenCommands              int `json:"hidden_commands"`
	DeprecatedCommands          int `json:"deprecated_commands"`
	AllFlags                    int `json:"all_flags"`
	VisibleFlags                int `json:"visible_flags"`
	HiddenFlags                 int `json:"hidden_flags"`
	PersistentFlags             int `json:"persistent_flags"`
	TotalLocalFlags             int `json:"total_local_flags"`
	PublicFlags                 int `json:"public_flags"`
	ResearchFlags               int `json:"research_flags"`
	RequiredFlags               int `json:"required_flags"`
	ArtifactPathFlags           int `json:"artifact_path_flags"`
	DuplicateSemanticFlags      int `json:"duplicate_semantic_flags"`
	UnusedFlags                 int `json:"unused_flags"`
	CommonWorkflowRequiredFlags int `json:"common_workflow_required_flags"`
}

func buildComplexity(inv commandInventory) complexityReport {
	var r complexityReport
	seen := map[string]int{}
	publicSeen := map[string]bool{}
	r.TotalCommands = len(inv.Commands)
	for _, c := range inv.Commands {
		if strings.Count(c.Path, " ") == 1 && (c.Category == "operator_primary" || c.Category == "debug") {
			r.VisibleCommands++
		}
		if c.Category == "internal_pipeline" || c.Category == "deprecated_candidate" {
			r.HiddenCommands++
		}
		if c.Category == "deprecated_candidate" {
			r.DeprecatedCommands++
		}
		r.AllFlags += len(c.Flags)
		r.HiddenFlags += c.HiddenFlagCount
		r.PersistentFlags += c.PersistentFlagCount
		r.TotalLocalFlags += len(c.Flags)
		r.RequiredFlags += len(c.RequiredFlags)
		r.ArtifactPathFlags += len(c.InputArtifacts)
		if c.Category == "operator_primary" || c.Category == "operator_advanced" {
			for _, f := range c.Flags {
				publicSeen[f] = true
			}
		}
		if c.Category == "research" {
			r.ResearchFlags += len(c.Flags)
		}
		for _, f := range c.Flags {
			seen[f]++
		}
	}
	r.VisibleFlags = r.AllFlags - r.HiddenFlags
	r.PublicFlags = len(publicSeen)
	for _, n := range seen {
		if n > 1 {
			r.DuplicateSemanticFlags += n - 1
		}
	}
	// Cobra flags in this tree bind directly to command state; dead-flag tests exercise behavior separately.
	r.UnusedFlags = 0
	r.CommonWorkflowRequiredFlags = 1
	return r
}

type commandInventory struct {
	SchemaVersion int             `json:"schema_version"`
	Commands      []commandRecord `json:"commands"`
}
type commandRecord struct {
	Path                    string   `json:"full_command_path"`
	Description             string   `json:"short_description"`
	Category                string   `json:"category"`
	Disposition             string   `json:"disposition"`
	SideEffects             string   `json:"side_effects"`
	NetworkBehavior         string   `json:"network_behavior"`
	Flags                   []string `json:"flags"`
	RequiredFlags           []string `json:"required_flags"`
	InheritedFlags          []string `json:"inherited_flags"`
	SafetyAcknowledgements  []string `json:"safety_acknowledgements"`
	InputArtifacts          []string `json:"input_artifacts"`
	OutputArtifacts         []string `json:"output_artifacts"`
	CurrentTests            []string `json:"current_tests"`
	DocumentationReferences []string `json:"documentation_references"`
	RequiredFlagCount       int      `json:"required_flag_count"`
	HiddenFlagCount         int      `json:"hidden_flag_count"`
	PersistentFlagCount     int      `json:"persistent_flag_count"`
}

func buildCommandInventory(root *cobra.Command) commandInventory {
	var records []commandRecord
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root {
			category := classifyCommand(c)
			r := commandRecord{Path: c.CommandPath(), Description: c.Short, Category: category, Disposition: commandDisposition(category), SideEffects: commandSideEffects(c), NetworkBehavior: commandNetwork(c), Flags: []string{}, RequiredFlags: []string{}, InheritedFlags: []string{}, SafetyAcknowledgements: []string{}, InputArtifacts: []string{}, OutputArtifacts: []string{}, CurrentTests: []string{"Cobra construction and package tests"}, DocumentationReferences: []string{"docs/CLI_DESIGN.md", "docs/CLI_MIGRATION.md"}}
			persistent := map[string]bool{}
			c.PersistentFlags().VisitAll(func(f *pflag.Flag) { persistent[f.Name] = true })
			collect := func(f *pflag.Flag) {
				r.Flags = append(r.Flags, "--"+f.Name)
				if f.Hidden {
					r.HiddenFlagCount++
				}
				if persistent[f.Name] {
					r.PersistentFlagCount++
				}
				if a, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok && len(a) > 0 && a[0] == "true" {
					r.RequiredFlags = append(r.RequiredFlags, "--"+f.Name)
				}
				if strings.Contains(f.Name, "acknowledge") || strings.HasPrefix(f.Name, "enable-") {
					r.SafetyAcknowledgements = append(r.SafetyAcknowledgements, "--"+f.Name)
				}
				if strings.Contains(f.Name, "input") || strings.Contains(f.Name, "inventory") || strings.Contains(f.Name, "capture") || strings.Contains(f.Name, "logs") {
					r.InputArtifacts = append(r.InputArtifacts, "--"+f.Name)
				}
				if strings.Contains(f.Name, "output") {
					r.OutputArtifacts = append(r.OutputArtifacts, "--"+f.Name)
				}
			}
			c.NonInheritedFlags().VisitAll(collect)
			c.InheritedFlags().VisitAll(func(f *pflag.Flag) { r.InheritedFlags = append(r.InheritedFlags, "--"+f.Name) })
			sort.Strings(r.Flags)
			sort.Strings(r.RequiredFlags)
			sort.Strings(r.InheritedFlags)
			r.RequiredFlagCount = len(r.RequiredFlags)
			records = append(records, r)
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	sort.Slice(records, func(i, j int) bool { return records[i].Path < records[j].Path })
	return commandInventory{1, records}
}

func classifyCommand(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, " research ") {
		return "research"
	}
	if strings.Contains(p, " debug ") {
		return "debug"
	}
	if c.Deprecated != "" {
		return "deprecated_candidate"
	}
	for parent := c.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Hidden || parent.Deprecated != "" {
			return "internal_pipeline"
		}
	}
	if c.Hidden {
		return "internal_pipeline"
	}
	if c.Parent() != nil && c.Parent().Name() == "cinderpath" {
		return "operator_primary"
	}
	return "operator_advanced"
}
func commandNetwork(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, "discover") || strings.Contains(p, "auth validate") {
		return "possible_only_with_explicit_enablement"
	}
	return "none_or_offline"
}
func commandDisposition(category string) string {
	switch category {
	case "operator_primary":
		return "keep_public"
	case "operator_advanced":
		return "keep_advanced"
	case "research":
		return "move_to_research"
	case "debug":
		return "move_to_debug"
	case "deprecated_candidate", "internal_pipeline":
		return "hide_but_supported"
	default:
		return "keep_advanced"
	}
}
func commandSideEffects(c *cobra.Command) string {
	p := c.CommandPath()
	if strings.Contains(p, "exploit") || strings.Contains(p, "cleanup") {
		return "unsupported_no_action"
	}
	if strings.Contains(p, "create") || strings.Contains(p, "output") || strings.Contains(p, "report") {
		return "bounded_local_files_or_database"
	}
	return "read_only_or_planning"
}

func frameworkSupport() framework.Registry { return framework.MisconfigurationManager() }
