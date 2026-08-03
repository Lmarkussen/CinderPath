package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/assessment"
	"github.com/Lmarkussen/CinderPath/internal/authvalidate"
	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/discovery"
	"github.com/Lmarkussen/CinderPath/internal/discovery/live"
	"github.com/Lmarkussen/CinderPath/internal/identity"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/modules/mock"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"github.com/Lmarkussen/CinderPath/internal/report"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

type Application struct {
	Config config.Config
	Logger *slog.Logger
}
type Outcome struct {
	Run              models.Run
	ModuleSummary    modules.Summary
	Assets           int
	Findings         map[models.Severity]int
	AttackPaths      int
	DatabasePath     string
	ReportPaths      report.Paths
	Provider         string
	Discovery        DiscoverySummary
	Events           []progress.Event
	TechniqueStatus  string
	TechniqueSummary map[string]any
}

type DiscoverySummary struct {
	ScopeTargets, Excluded, DNSResolved, DNSUnresolved, ReachableHosts, OpenPorts, HTTPEndpoints, SCCMDirectoryObjects int
	LDAPBind, DefaultNamingContext                                                                                     string
	Roles                                                                                                              map[string]int
}
type DiscoverOptions struct {
	Provider string
	Live     live.Options
}
type IdentityOutcome struct {
	Identity     models.Credential
	Identities   []models.Credential
	Capabilities []models.Capability
	Requirements []identity.AuthRequirement
	DatabasePath string
}
type AuthOutcome struct {
	Run          models.Run
	Attempts     []models.AuthenticationAttempt
	DatabasePath string
}

func (a *Application) ValidateAuthentication(ctx context.Context, args []string, o authvalidate.Options) (AuthOutcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return AuthOutcome{}, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "auth validate", string(a.Config.Profile), version.Current().Version, args)
	if err != nil {
		return AuthOutcome{}, err
	}
	runs, _ := store.ListRuns(ctx)
	latest := ""
	for _, r := range runs {
		if r.Command == "discover" && fmt.Sprint(r.Summary["provider"]) == "live" && (r.Status == models.RunCompleted || r.Status == models.RunCompletedWithErrors) {
			latest = r.ID
			break
		}
	}
	attempts, execErr := authvalidate.Validate(ctx, store, run.ID, latest, o)
	for _, attempt := range attempts {
		cap := capabilityFromAttempt(attempt)
		_, _ = store.UpsertCapability(context.WithoutCancel(ctx), &cap)
	}
	status := models.RunCompleted
	if execErr != nil {
		status = models.RunFailed
	}
	if ctx.Err() != nil {
		status = models.RunCancelled
	}
	summary := map[string]any{"attempts": len(attempts), "actual_attempts": countActualAttempts(attempts)}
	if execErr != nil {
		summary["error"] = execErr.Error()
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, status, summary)
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = status
	run.Summary = summary
	return AuthOutcome{Run: *run, Attempts: attempts, DatabasePath: store.Path()}, execErr
}
func (a *Application) AuthenticationResults(ctx context.Context) (AuthOutcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return AuthOutcome{}, err
	}
	defer store.Close()
	attempts, err := store.ListAuthenticationAttempts(ctx)
	return AuthOutcome{Attempts: attempts, DatabasePath: store.Path()}, err
}
func countActualAttempts(v []models.AuthenticationAttempt) int {
	n := 0
	for _, a := range v {
		if a.Attempted {
			n++
		}
	}
	return n
}
func capabilityFromAttempt(a models.AuthenticationAttempt) models.Capability {
	name, state, available := "authentication_validation_planned", models.CapabilityRequiresValidation, false
	switch a.Status {
	case models.AuthSucceeded:
		name, state, available = a.AuthenticationMethod+"_auth_validated", models.CapabilityAvailable, true
	case models.AuthRejected:
		name, state = "authentication_validation_rejected", models.CapabilityUnavailable
	case models.AuthInconclusive:
		name = "authentication_validation_inconclusive"
	case models.AuthBlocked:
		name, state = "authentication_validation_blocked", models.CapabilityBlockedBySafety
	}
	return models.Capability{Name: name, Available: available, State: state, Reason: a.Reason, Source: "auth.validate", CredentialID: a.IdentityID, AssetID: a.AssetID, RelatedEndpoint: a.Origin, RelatedRoute: a.Route, AuthenticationMethod: a.AuthenticationMethod, EvidenceIDs: a.EvidenceIDs, SafetyBlocked: a.Status == models.AuthBlocked, Stale: a.EvidenceFreshness != models.TemporalCurrent}
}

func (a *Application) InspectIdentity(ctx context.Context, in identity.Input) (IdentityOutcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return IdentityOutcome{}, err
	}
	defer store.Close()
	id, err := identity.Parse(in, time.Now().UTC(), a.Config.Staleness.CertificateWarningDays)
	if err != nil {
		return IdentityOutcome{}, err
	}
	if _, err = store.UpsertCredential(ctx, &id); err != nil {
		return IdentityOutcome{}, err
	}
	evidence, _ := store.ListEvidence(ctx)
	req := identity.Requirements(evidence, time.Now().UTC(), a.Config.Staleness.EvidenceDays, latestDiscoveryRunID(ctx, store))
	ids, _ := store.ListCredentials(ctx)
	caps := identity.Plan(ids, req)
	for i := range caps {
		if _, err = store.UpsertCapability(ctx, &caps[i]); err != nil {
			return IdentityOutcome{}, err
		}
	}
	return IdentityOutcome{Identity: id, Identities: ids, Capabilities: caps, Requirements: req, DatabasePath: store.Path()}, nil
}
func (a *Application) ListIdentities(ctx context.Context) (IdentityOutcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return IdentityOutcome{}, err
	}
	defer store.Close()
	ids, err := store.ListCredentials(ctx)
	return IdentityOutcome{Identities: ids, DatabasePath: store.Path()}, err
}
func (a *Application) PlanCapabilities(ctx context.Context) (IdentityOutcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return IdentityOutcome{}, err
	}
	defer store.Close()
	ids, _ := store.ListCredentials(ctx)
	evidence, _ := store.ListEvidence(ctx)
	req := identity.Requirements(evidence, time.Now().UTC(), a.Config.Staleness.EvidenceDays, latestDiscoveryRunID(ctx, store))
	caps := identity.Plan(ids, req)
	for i := range caps {
		_, _ = store.UpsertCapability(ctx, &caps[i])
	}
	return IdentityOutcome{Identities: ids, Capabilities: caps, Requirements: req, DatabasePath: store.Path()}, nil
}
func latestDiscoveryRunID(ctx context.Context, store *database.Store) string {
	runs, _ := store.ListRuns(ctx)
	for _, r := range runs {
		if r.Command == "discover" && fmt.Sprint(r.Summary["provider"]) == "live" && (r.Status == models.RunCompleted || r.Status == models.RunCompletedWithErrors) {
			return r.ID
		}
	}
	return ""
}

func (a *Application) Discover(ctx context.Context, args []string) (Outcome, error) {
	return a.DiscoverWithOptions(ctx, args, DiscoverOptions{Provider: "mock"})
}
func (a *Application) DiscoverWithOptions(ctx context.Context, args []string, options DiscoverOptions) (Outcome, error) {
	switch options.Provider {
	case "", "mock":
		return a.executeModules(ctx, "discover", args, "mock", discovery.Select(mock.All()))
	case "live":
		if err := live.ValidateOptions(options.Live); err != nil {
			return Outcome{}, err
		}
		return a.executeModules(ctx, "discover", args, "live", discovery.Select(live.All(options.Live)))
	case "live-recon1":
		if err := live.ValidateOptions(options.Live); err != nil {
			return Outcome{}, err
		}
		return a.executeModules(ctx, "assess RECON-1", args, "live", live.LDAPOnly(options.Live))
	case "live-recon2":
		if err := live.ValidateOptions(options.Live); err != nil {
			return Outcome{}, err
		}
		return a.executeModules(ctx, "assess RECON-2", args, "live", live.SMBOnly(options.Live))
	case "live-recon3":
		if err := live.ValidateOptions(options.Live); err != nil {
			return Outcome{}, err
		}
		return a.executeModules(ctx, "assess RECON-3", args, "live", live.SCCMHTTPOnly(options.Live))
	default:
		return Outcome{}, fmt.Errorf("invalid discovery provider %q (use mock or live)", options.Provider)
	}
}
func (a *Application) Assess(ctx context.Context, args []string) (Outcome, error) {
	return a.executeModules(ctx, "assess", args, "mock", assessment.Select(mock.All()))
}

func (a *Application) executeModules(ctx context.Context, command string, args []string, provider string, list []modules.Module) (Outcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return Outcome{}, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, command, string(a.Config.Profile), version.Current().Version, args)
	if err != nil {
		return Outcome{}, err
	}
	a.Logger.Info("run started", "run_id", run.ID, "command", command, "profile", run.Profile, "database", store.Path())
	assets, err := store.ListAssets(ctx)
	if err != nil {
		return Outcome{}, a.finishError(store, run, ctx, err)
	}
	if command == "assess" && len(assets) == 0 {
		return Outcome{}, a.finishError(store, run, ctx, errors.New("no assets found; run cinderpath discover first"))
	}
	events := &progress.Collector{}
	events.Publish(progress.Event{Type: progress.RunStarted, RunID: run.ID, Message: command, Data: map[string]any{"provider": provider}})
	rc := modules.RunContext{RunID: run.ID, Profile: string(a.Config.Profile), Mock: provider == "mock", Store: store, Logger: a.Logger, Progress: events}
	summary, execErr := modules.NewOrchestrator(store).Execute(ctx, rc, list, assets)
	status := models.RunCompleted
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status = models.RunCancelled
	} else if execErr != nil {
		status = models.RunFailed
	} else if summary.Failed > 0 {
		status = models.RunCompletedWithErrors
	}
	allAssets, _ := store.ListAssets(context.WithoutCancel(ctx))
	allEvidence, _ := store.ListEvidence(context.WithoutCancel(ctx))
	findings, _ := store.ListFindings(context.WithoutCancel(ctx))
	paths, _ := store.ListAttackPaths(context.WithoutCancel(ctx))
	counts := severityCounts(findings)
	discoverySummary := summarizeDiscovery(context.WithoutCancel(ctx), store, provider)
	runSummary := map[string]any{"provider": provider, "modules_executed": summary.Executed, "modules_skipped": summary.Skipped, "modules_failed": summary.Failed, "assets": len(allAssets), "findings": counts, "attack_paths": len(paths), "mock_data": provider == "mock", "scope_targets": discoverySummary.ScopeTargets, "excluded_targets": discoverySummary.Excluded}
	techniqueStatus := ""
	var techniqueSummary map[string]any
	if command == "assess RECON-3" {
		techniqueStatus = deriveRECON3Status(summary, allEvidence, run.ID)
		techniqueSummary = recon3SummaryForRun(allEvidence, run.ID)
		runSummary["technique_status"] = techniqueStatus
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, status, runSummary)
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = status
	run.Summary = runSummary
	events.Publish(progress.Event{Type: progress.RunCompleted, RunID: run.ID, Data: map[string]any{"status": status}})
	out := Outcome{Run: *run, ModuleSummary: summary, Assets: len(allAssets), Findings: counts, AttackPaths: len(paths), DatabasePath: store.Path(), Provider: provider, Discovery: discoverySummary, Events: events.Events(), TechniqueStatus: techniqueStatus, TechniqueSummary: techniqueSummary}
	if execErr != nil {
		return out, execErr
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

func deriveRECON3Status(summary modules.Summary, evidence []models.Evidence, runID string) string {
	requestSummary := recon3SummaryForRun(evidence, runID)
	if requestSummary != nil && evidenceInt(requestSummary["failure_count"]) > 0 && evidenceInt(requestSummary["successful_response_count"]) > 0 {
		return "completed_with_errors"
	}
	if summary.Failed > 0 {
		text := ""
		for _, execution := range summary.Executions {
			text += " " + execution.Error
		}
		switch {
		case strings.Contains(text, "endpoint_resolution_failed"):
			return "endpoint_resolution_failed"
		case strings.Contains(text, "connection_failed"):
			return "connection_failed"
		default:
			return "collection_failed"
		}
	}
	for _, item := range evidence {
		if item.RunID == runID && item.Type == "sccm_http_recon_summary" && evidenceInt(item.Data["relevant_evidence_count"]) > 0 {
			return "completed_with_sccm_evidence"
		}
	}
	return "completed_no_sccm_evidence"
}

func recon3SummaryForRun(evidence []models.Evidence, runID string) map[string]any {
	for _, item := range evidence {
		if item.RunID == runID && item.Type == "sccm_http_recon_summary" {
			return item.Data
		}
	}
	return nil
}

func evidenceInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func summarizeDiscovery(ctx context.Context, store *database.Store, provider string) DiscoverySummary {
	d := DiscoverySummary{Roles: map[string]int{}}
	assets, _ := store.ListAssets(ctx)
	evidence, _ := store.ListEvidence(ctx)
	caps, _ := store.ListCapabilities(ctx)
	for _, a := range assets {
		if provider == "live" && a.Properties["observation_origin"] != "live" {
			continue
		}
		if a.Properties["normalized_target"] != "" {
			d.ScopeTargets++
		}
		if a.Properties["reachable"] == "true" {
			d.ReachableHosts++
		}
		if a.Properties["open_ports"] != "" {
			d.OpenPorts += len(strings.Split(a.Properties["open_ports"], ","))
		}
		if a.Properties["http_endpoints"] != "" {
			d.HTTPEndpoints += len(strings.Split(a.Properties["http_endpoints"], ","))
		}
		for _, role := range a.Roles {
			d.Roles[role]++
		}
	}
	for _, e := range evidence {
		switch e.Type {
		case "scope_decision":
			switch x := e.Data["excluded"].(type) {
			case []any:
				d.Excluded = len(x)
			case []string:
				d.Excluded = len(x)
			}
		case "dns_resolution":
			switch x := e.Data["answers"].(type) {
			case []any:
				if len(x) > 0 {
					d.DNSResolved++
				} else {
					d.DNSUnresolved++
				}
			case []string:
				if len(x) > 0 {
					d.DNSResolved++
				} else {
					d.DNSUnresolved++
				}
			}
		case "ldap_rootdse":
			d.DefaultNamingContext = fmt.Sprint(e.Data["default_naming_context"])
		case "ldap_sccm_object":
			d.SCCMDirectoryObjects++
		}
	}
	for _, c := range caps {
		if c.Name == "ldap_bind_successful" {
			if c.Available {
				d.LDAPBind = "successful"
			} else {
				d.LDAPBind = "failed"
			}
		}
	}
	return d
}

func (a *Application) Report(ctx context.Context, args []string) (Outcome, error) {
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return Outcome{}, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "report", string(a.Config.Profile), version.Current().Version, args)
	if err != nil {
		return Outcome{}, err
	}
	assets, err := store.ListAssets(ctx)
	if err != nil {
		return Outcome{}, a.finishError(store, run, ctx, err)
	}
	if len(assets) == 0 {
		return Outcome{}, a.finishError(store, run, ctx, errors.New("no stored assets available to report"))
	}
	findings, _ := store.ListFindings(ctx)
	paths, _ := store.ListAttackPaths(ctx)
	mockData := false
	liveData := false
	for _, asset := range assets {
		mockData = mockData || asset.Properties["mock"] == "true"
		liveData = liveData || asset.Properties["observation_origin"] == "live"
	}
	summary := map[string]any{"assets": len(assets), "findings": len(findings), "attack_paths": len(paths), "mock_data": mockData, "live_data": liveData}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, summary)
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = models.RunCompleted
	run.Summary = summary
	reportPaths, err := report.Generate(ctx, store, a.Config.OutputDir, store.Path(), version.Current().Version, run, a.Config.Staleness)
	if err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"error": err.Error()})
		return Outcome{}, err
	}
	return Outcome{Run: *run, Assets: len(assets), Findings: severityCounts(findings), AttackPaths: len(paths), DatabasePath: store.Path(), ReportPaths: reportPaths}, nil
}

func (a *Application) finishError(store *database.Store, run *models.Run, ctx context.Context, err error) error {
	status := models.RunFailed
	if ctx.Err() != nil {
		status = models.RunCancelled
	}
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, status, map[string]any{"error": err.Error()})
	return err
}
func severityCounts(items []models.Finding) map[models.Severity]int {
	out := map[models.Severity]int{models.SeverityCritical: 0, models.SeverityHigh: 0, models.SeverityMedium: 0, models.SeverityLow: 0, models.SeverityInformational: 0}
	for _, f := range items {
		out[f.Severity]++
	}
	return out
}

func ProfileNotice(p config.Profile) string {
	if p == config.ProfileSafe {
		return "safe, read-only modules only"
	}
	return fmt.Sprintf("%s is a placeholder; this release still runs safe, read-only mock modules only", p)
}
