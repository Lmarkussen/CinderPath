package live

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type sccmHTTPReconModule struct{ opts Options }

func sccmHTTPReconRequestBound() int {
	return maxSCCMRoutesPerHost
}

func sccmHTTPReconOrigins(target string) []string {
	return []string{
		"http://" + net.JoinHostPort(target, "80"),
		"https://" + net.JoinHostPort(target, "443"),
	}
}

func (m *sccmHTTPReconModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.sccm.http_recon", Description: "Probes one target using the fixed anonymous SCCM HTTP route allowlist", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe}
}

func (m *sccmHTTPReconModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	if m.target() == "" {
		return false, "SCCM HTTP target was not supplied"
	}
	return true, ""
}

func (m *sccmHTTPReconModule) target() string {
	if m.opts.DC != "" {
		return m.opts.DC
	}
	if len(m.opts.Scope.Targets) > 0 {
		return m.opts.Scope.Targets[0]
	}
	return ""
}

func (m *sccmHTTPReconModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	target := m.target()
	if target == "" {
		return nil, fmt.Errorf("SCCM HTTP target was not supplied")
	}
	host := normalizeHost(target)
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: target, Domain: strings.ToUpper(m.opts.Domain), Roles: []string{"sccm_http_candidate"}, Source: m.Metadata().Name, Confidence: models.ConfidenceLow, Properties: map[string]string{"observation_origin": "live", "network_behavior": "sccm_http_allowlist_only"}}
	asset.Prepare(time.Now().UTC())
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "fixed SCCM HTTP route reconnaissance"})
	httpOpts := m.opts.HTTP
	if httpOpts.Timeout <= 0 {
		httpOpts.Timeout = 10 * time.Second
	}
	if httpOpts.MaxBodyBytes <= 0 {
		httpOpts.MaxBodyBytes = 32 * 1024
	}
	httpOpts.MaxRedirects = 0
	if httpOpts.UserAgent == "" {
		httpOpts.UserAgent = "CinderPath-safe-discovery"
	}
	scoped := map[string]bool{host: true}
	origins := sccmHTTPReconOrigins(target)
	var observations []routeObservation
	for _, origin := range origins {
		if ctx.Err() != nil {
			break
		}
		observations = append(observations, probeSCCMOrigin(ctx, asset.ID, origin, nil, scoped, httpOpts)...)
	}
	result := &modules.Result{Assets: []models.Asset{asset}}
	var relevant, failures int
	for _, observation := range observations {
		routeEvidence := routeEvidenceFromObservation(observation, m.Metadata().Name)
		accessEvidence := accessEvidenceFromObservation(observation, routeEvidence.ID, m.Metadata().Name)
		result.Evidence = append(result.Evidence, routeEvidence, accessEvidence)
		if observation.ParserOutcome == "valid_sccm_mp_list" || len(observation.SCCMMarkers) > 0 {
			relevant++
		}
		if observation.Error != "" {
			failures++
		}
	}
	methods := []string{}
	seenMethods := map[string]bool{}
	for _, observation := range observations {
		if !seenMethods[observation.Method] {
			seenMethods[observation.Method] = true
			methods = append(methods, observation.Method)
		}
	}
	summaryEvidence := models.Evidence{Type: "sccm_http_recon_summary", Title: "SCCM HTTP reconnaissance request summary", Summary: "The fixed SCCM HTTP route allowlist was evaluated for one target.", Data: map[string]any{
		"target": target, "route_count": len(sccmRouteAllowlist), "scheme_count": len(origins), "methods": methods,
		"configured_maximum_requests": sccmHTTPReconRequestBound(), "actual_request_count": len(observations),
		"successful_response_count": len(observations) - failures, "failure_count": failures, "relevant_evidence_count": relevant,
		"network_behavior": "sccm_http_allowlist_only",
	}, SourceModule: m.Metadata().Name, AssetID: asset.ID, Sensitivity: models.SensitivityInternal}
	summaryEvidence.Prepare(time.Now().UTC())
	result.Evidence = append(result.Evidence, summaryEvidence)
	if len(observations) == 0 || failures == len(observations) {
		classification := classifySCCMHTTPFailure(observations)
		result.Errors = append(result.Errors, modules.ResultError{Message: classification + ": all allowlisted SCCM HTTP route requests failed"})
		result.Warnings = append(result.Warnings, classification)
	} else if failures > 0 {
		result.Errors = append(result.Errors, modules.ResultError{Message: "collection_failed: some allowlisted SCCM HTTP route requests failed"})
		result.Warnings = append(result.Warnings, "partial_collection")
	} else if relevant > 0 {
		finding := models.Finding{RuleID: "SCCM-RECON-3-HTTP-EVIDENCE", Title: "SCCM HTTP route evidence observed", Summary: "An allowlisted SCCM HTTP route returned protocol-specific evidence.", Description: "This is informational reconnaissance evidence; route responses do not authorize authentication, content retrieval, or role changes.", Severity: models.SeverityInformational, Confidence: models.ConfidenceMedium, Status: models.FindingOpen, AssetIDs: []string{asset.ID}, EvidenceIDs: evidenceIDs(result.Evidence), Tags: []string{"reconnaissance", "sccm", "http", "read_only"}, Remediation: "Review SCCM HTTP route exposure and retain the intended anonymous access boundary."}
		finding.Prepare(time.Now().UTC())
		result.Findings = append(result.Findings, finding)
	} else {
		result.Warnings = append(result.Warnings, "completed_no_evidence: no protocol-specific SCCM route response was observed")
	}
	cred := models.Credential{Username: m.opts.LDAP.User, Domain: m.opts.Domain, Type: models.CredentialPasswordRef, Source: m.Metadata().Name, HasSecret: m.opts.LDAP.PasswordReference != "", SecretReference: m.opts.LDAP.PasswordReference, Properties: map[string]string{"storage": "reference_only", "http_authentication": "not_attempted"}}
	cred.Prepare()
	result.Credentials = []models.Credential{cred}
	cap := models.Capability{Name: "sccm_http_allowlist_observed", Available: failures < len(observations) && len(observations) > 0, Reason: fmt.Sprintf("completed %d fixed allowlisted SCCM HTTP route observations", len(observations)), Source: m.Metadata().Name, AssetID: asset.ID, EvidenceIDs: evidenceIDs(result.Evidence)}
	cap.Prepare()
	result.Capabilities = append(result.Capabilities, cap)
	run.Emit(progress.Event{Type: progress.ModuleCompleted, Module: m.Metadata().Name, Message: "SCCM HTTP route reconnaissance completed", Data: map[string]any{"observations": len(observations), "relevant": relevant}})
	return result, nil
}

func classifySCCMHTTPFailure(observations []routeObservation) string {
	if len(observations) == 0 {
		return "collection_failed"
	}
	allResolution, allConnection := true, true
	for _, observation := range observations {
		err := strings.ToLower(observation.Error)
		allResolution = allResolution && (strings.Contains(err, "no such host") || strings.Contains(err, "name or service not known"))
		allConnection = allConnection && (strings.Contains(err, "connection refused") || strings.Contains(err, "connection timed out") || strings.Contains(err, "i/o timeout"))
	}
	switch {
	case allResolution:
		return "endpoint_resolution_failed"
	case allConnection:
		return "connection_failed"
	default:
		return "collection_failed"
	}
}
