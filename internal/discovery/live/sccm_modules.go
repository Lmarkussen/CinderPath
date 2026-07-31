package live

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type profiledOrigin struct {
	Asset       models.Asset
	Origin      string
	RootProfile map[string]any
}

type sccmHTTPRoutesModule struct{ opts Options }

func (m *sccmHTTPRoutesModule) Metadata() modules.Metadata {
	return modules.Metadata{
		Name:        "live.sccm.http_routes",
		Description: "Probes a fixed read-only allowlist of SCCM HTTP routes",
		Category:    modules.CategoryDiscovery,
		Safety:      modules.SafetySafe,
		Requirements: []modules.Requirement{{
			Capability:  "http_profiling",
			Description: "successful HTTP profiling must identify an origin on port 80 or 443",
		}},
	}
}

func (m *sccmHTTPRoutesModule) Applicable(ctx context.Context, run modules.RunContext, _ *models.Asset) (bool, string) {
	origins, err := loadProfiledSCCMOrigins(ctx, run)
	if err != nil {
		return false, "profiled HTTP origins could not be evaluated"
	}
	if len(origins) == 0 {
		return false, "no successfully profiled HTTP or HTTPS endpoints exist on scoped ports 80 or 443"
	}
	return true, ""
}

func (m *sccmHTTPRoutesModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "strictly read-only SCCM HTTP route validation"})
	origins, err := loadProfiledSCCMOrigins(ctx, run)
	if err != nil {
		return nil, err
	}
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	scopedHosts := explicitScopedHosts(assets)
	byAsset := map[string][]profiledOrigin{}
	for _, origin := range origins {
		if len(byAsset[origin.Asset.ID]) < maxSCCMOriginsPerHost {
			byAsset[origin.Asset.ID] = append(byAsset[origin.Asset.ID], origin)
		}
	}
	assetIDs := make([]string, 0, len(byAsset))
	for assetID := range byAsset {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Strings(assetIDs)
	var observations []routeObservation
	var mu sync.Mutex
	parallel(ctx, m.opts.Concurrency, len(assetIDs), func(index int) {
		assetID := assetIDs[index]
		hostCtx, cancel := context.WithTimeout(ctx, m.opts.HostTimeout)
		defer cancel()
		run.Emit(progress.Event{Type: progress.TargetStarted, Module: m.Metadata().Name, Target: targetAddress(byAsset[assetID][0].Asset)})
		var hostObservations []routeObservation
		for _, origin := range byAsset[assetID] {
			if len(hostObservations) >= maxSCCMRoutesPerHost || hostCtx.Err() != nil {
				break
			}
			hostObservations = append(hostObservations, probeSCCMOrigin(hostCtx, assetID, origin.Origin, origin.RootProfile, scopedHosts, m.opts.HTTP)...)
		}
		if len(hostObservations) > maxSCCMRoutesPerHost {
			hostObservations = hostObservations[:maxSCCMRoutesPerHost]
		}
		mu.Lock()
		observations = append(observations, hostObservations...)
		mu.Unlock()
		run.Emit(progress.Event{Type: progress.TargetCompleted, Module: m.Metadata().Name, Target: targetAddress(byAsset[assetID][0].Asset), Data: map[string]any{"route_observations": len(hostObservations)}})
	})
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].AssetID != observations[j].AssetID {
			return observations[i].AssetID < observations[j].AssetID
		}
		if observations[i].Origin != observations[j].Origin {
			return observations[i].Origin < observations[j].Origin
		}
		return observations[i].RouteID < observations[j].RouteID
	})
	out := &modules.Result{}
	for _, observation := range observations {
		routeEvidence := routeEvidenceFromObservation(observation, m.Metadata().Name)
		accessEvidence := accessEvidenceFromObservation(observation, routeEvidence.ID, m.Metadata().Name)
		out.Evidence = append(out.Evidence, routeEvidence, accessEvidence)
	}
	capability := models.Capability{Name: "sccm_http_route_probing", Available: true, Reason: fmt.Sprintf("completed %d bounded allowlisted route observations", len(observations)), Source: m.Metadata().Name, EvidenceIDs: evidenceIDs(out.Evidence)}
	capability.Prepare()
	out.Capabilities = append(out.Capabilities, capability)
	return out, ctx.Err()
}

type sccmManagementPointModule struct{ opts Options }

func (m *sccmManagementPointModule) Metadata() modules.Metadata {
	return modules.Metadata{
		Name:        "live.sccm.management_point",
		Description: "Classifies management points from stored SCCM route and LDAP evidence without network traffic",
		Category:    modules.CategoryDiscovery,
		Safety:      modules.SafetySafe,
	}
}

func (m *sccmManagementPointModule) Applicable(ctx context.Context, run modules.RunContext, _ *models.Asset) (bool, string) {
	if origins, err := loadProfiledSCCMOrigins(ctx, run); err != nil || len(origins) == 0 {
		return false, "no successfully profiled HTTP or HTTPS endpoints exist on scoped ports 80 or 443"
	}
	return storedRouteApplicable(ctx, run, sccmRouteMPList)
}

func (m *sccmManagementPointModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "stored SCCM management-point evidence classification"})
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	assetByID := make(map[string]models.Asset, len(assets))
	for _, asset := range assets {
		assetByID[asset.ID] = asset
	}
	out := &modules.Result{}
	now := time.Now()
	type mpCapabilityAggregate struct {
		state       SCCMAccessState
		evidenceIDs []string
	}
	capabilityAggregates := map[string]mpCapabilityAggregate{}
	for _, item := range evidence {
		observation, ok := routeObservationFromEvidence(item)
		if !ok || observation.RouteID != sccmRouteMPList {
			continue
		}
		classification := "unverified"
		confidence := "unverified"
		supporting := []string{item.ID}
		remaining := observation.UnverifiedReason
		if observation.AccessState.ProtocolValidated && observation.ParserOutcome == "valid_sccm_mp_list" {
			classification = "protocol_validated_management_point"
			confidence = string(models.ConfidenceHigh)
			remaining = "The endpoint was validated as an SCCM management point, but authentication, policy access, and newly referenced hosts were not tested."
		} else if observation.AccessState.AuthenticationRequested {
			ldapIDs := ldapEvidenceForHost(evidence, assetByID[observation.AssetID], "management_point")
			if len(ldapIDs) > 0 {
				classification = "likely_management_point_authentication_required"
				confidence = string(models.ConfidenceMedium)
				supporting = append(supporting, ldapIDs...)
				remaining = "The SCCM-specific route requested authentication and LDAP independently references this host; no authentication was attempted and protocol content was not parsed."
			}
		} else if observation.AccessState.HTTPResponseReceived && observation.StatusCode != http.StatusNotFound && observation.StatusCode < 500 {
			classification = "low_confidence_route_behavior"
			confidence = string(models.ConfidenceLow)
			remaining = "Route behavior alone does not validate an SCCM management point."
		}
		protocolEvidence := models.Evidence{Type: "sccm_mp_protocol", Title: "SCCM management-point validation for " + observation.Origin, Summary: mpClassificationSummary(classification), Data: map[string]any{
			"asset_id": observation.AssetID, "origin": observation.Origin, "route_id": observation.RouteID, "classification": classification, "confidence": confidence,
			"parser_outcome": observation.ParserOutcome, "site_codes": observation.SiteCodes, "referenced_hosts": observation.ReferencedHosts,
			"supporting_evidence": normalizedStrings(supporting), "access_state": accessStateData(observation.AccessState), "what_remains_unverified": remaining,
		}, SourceModule: m.Metadata().Name, AssetID: observation.AssetID, Sensitivity: models.SensitivityInternal}
		protocolEvidence.Prepare(now)
		out.Evidence = append(out.Evidence, protocolEvidence)
		positive := classification == "protocol_validated_management_point" || classification == "likely_management_point_authentication_required"
		aggregate := capabilityAggregates[observation.AssetID]
		aggregate.state.TransportReachable = aggregate.state.TransportReachable || observation.AccessState.TransportReachable
		aggregate.state.HTTPResponseReceived = aggregate.state.HTTPResponseReceived || observation.AccessState.HTTPResponseReceived
		aggregate.state.AnonymousRequest = aggregate.state.AnonymousRequest || observation.AccessState.AnonymousRequest
		aggregate.state.AuthenticationRequested = aggregate.state.AuthenticationRequested || observation.AccessState.AuthenticationRequested
		aggregate.state.UsableReadAccess = aggregate.state.UsableReadAccess || observation.AccessState.UsableReadAccess
		aggregate.state.ProtocolValidated = aggregate.state.ProtocolValidated || observation.AccessState.ProtocolValidated
		aggregate.evidenceIDs = append(aggregate.evidenceIDs, protocolEvidence.ID)
		capabilityAggregates[observation.AssetID] = aggregate
		if positive {
			modelConfidence := models.ConfidenceMedium
			if confidence == string(models.ConfidenceHigh) {
				modelConfidence = models.ConfidenceHigh
			}
			finding := models.Finding{RuleID: "DISCOVERY-SCCM-MP-ENDPOINT", Title: "Likely SCCM management-point endpoint validated", Summary: mpClassificationSummary(classification), Description: remaining, Severity: models.SeverityInformational, Confidence: modelConfidence, AssetIDs: []string{observation.AssetID}, EvidenceIDs: append(normalizedStrings(supporting), protocolEvidence.ID), Tags: []string{"discovery", "sccm", "management_point", "read_only"}, Remediation: "Confirm the role in authorized SCCM inventory and retain appropriate anonymous and authenticated access controls."}
			finding.Prepare(now)
			out.Findings = append(out.Findings, finding)
		}
	}
	for _, assetID := range sortedMapKeys(capabilityAggregates) {
		aggregate := capabilityAggregates[assetID]
		for _, capability := range managementPointCapabilities(assetID, aggregate.state, normalizedStrings(aggregate.evidenceIDs), m.Metadata().Name) {
			out.Capabilities = append(out.Capabilities, capability)
		}
	}
	return out, nil
}

type sccmDistributionPointModule struct{ opts Options }

func (m *sccmDistributionPointModule) Metadata() modules.Metadata {
	return modules.Metadata{
		Name:        "live.sccm.distribution_point",
		Description: "Classifies distribution points from stored exact-route evidence without network traffic",
		Category:    modules.CategoryDiscovery,
		Safety:      modules.SafetySafe,
	}
}

func (m *sccmDistributionPointModule) Applicable(ctx context.Context, run modules.RunContext, _ *models.Asset) (bool, string) {
	if origins, err := loadProfiledSCCMOrigins(ctx, run); err != nil || len(origins) == 0 {
		return false, "no successfully profiled HTTP or HTTPS endpoints exist on scoped ports 80 or 443"
	}
	return storedRouteApplicable(ctx, run, "distribution_point")
}

func (m *sccmDistributionPointModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "stored SCCM distribution-point evidence classification"})
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	assetByID := make(map[string]models.Asset, len(assets))
	for _, asset := range assets {
		assetByID[asset.ID] = asset
	}
	groups := map[string][]struct {
		evidence    models.Evidence
		observation routeObservation
	}{}
	for _, item := range evidence {
		observation, ok := routeObservationFromEvidence(item)
		if !ok || !strings.HasPrefix(observation.RouteID, "dp_") {
			continue
		}
		key := observation.AssetID + "\x00" + observation.Origin
		groups[key] = append(groups[key], struct {
			evidence    models.Evidence
			observation routeObservation
		}{item, observation})
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := &modules.Result{}
	now := time.Now()
	type dpCapabilityAggregate struct {
		reachable, response, anonymous, accessControlled, likely bool
		evidenceIDs                                              []string
	}
	capabilityAggregates := map[string]dpCapabilityAggregate{}
	for _, key := range keys {
		items := groups[key]
		classification, confidence, supporting, remaining := classifyDistributionPoint(items, evidence, assetByID[items[0].observation.AssetID])
		accessControlled := false
		reachable := false
		for _, item := range items {
			reachable = reachable || item.observation.AccessState.TransportReachable
			accessControlled = accessControlled || item.observation.AccessState.AuthenticationRequested || item.observation.StatusCode == http.StatusForbidden
		}
		dpEvidence := models.Evidence{Type: "sccm_dp_virtual_directory", Title: "SCCM distribution-point route validation for " + items[0].observation.Origin, Summary: dpClassificationSummary(classification), Data: map[string]any{
			"asset_id": items[0].observation.AssetID, "origin": items[0].observation.Origin, "classification": classification, "confidence": confidence,
			"route_ids": dpRouteIDs(items), "supporting_evidence": supporting, "route_reachable": reachable, "access_controlled": accessControlled,
			"usable_read_access": false, "protocol_validated": false, "what_remains_unverified": remaining,
		}, SourceModule: m.Metadata().Name, AssetID: items[0].observation.AssetID, Sensitivity: models.SensitivityInternal}
		dpEvidence.Prepare(now)
		out.Evidence = append(out.Evidence, dpEvidence)
		likely := classification == "likely_distribution_point"
		aggregate := capabilityAggregates[items[0].observation.AssetID]
		aggregate.reachable = aggregate.reachable || reachable
		for _, item := range items {
			aggregate.response = aggregate.response || item.observation.AccessState.HTTPResponseReceived
			aggregate.anonymous = aggregate.anonymous || item.observation.AccessState.AnonymousRequest
		}
		aggregate.accessControlled = aggregate.accessControlled || accessControlled
		aggregate.likely = aggregate.likely || likely
		aggregate.evidenceIDs = append(aggregate.evidenceIDs, supporting...)
		aggregate.evidenceIDs = append(aggregate.evidenceIDs, dpEvidence.ID)
		capabilityAggregates[items[0].observation.AssetID] = aggregate
		if likely {
			modelConfidence := models.ConfidenceMedium
			if confidence == string(models.ConfidenceHigh) {
				modelConfidence = models.ConfidenceHigh
			}
			finding := models.Finding{RuleID: "DISCOVERY-SCCM-DP-ENDPOINT", Title: "Likely SCCM distribution-point endpoint identified", Summary: dpClassificationSummary(classification), Description: remaining, Severity: models.SeverityInformational, Confidence: modelConfidence, AssetIDs: []string{items[0].observation.AssetID}, EvidenceIDs: append(supporting, dpEvidence.ID), Tags: []string{"discovery", "sccm", "distribution_point", "read_only"}, Remediation: "Confirm the role in authorized SCCM inventory and retain appropriate access control at distribution-point virtual-directory roots."}
			finding.Prepare(now)
			out.Findings = append(out.Findings, finding)
		}
	}
	for _, assetID := range sortedMapKeys(capabilityAggregates) {
		aggregate := capabilityAggregates[assetID]
		for _, capability := range distributionPointCapabilities(assetID, aggregate.reachable, aggregate.response, aggregate.anonymous, aggregate.accessControlled, aggregate.likely, normalizedStrings(aggregate.evidenceIDs), m.Metadata().Name) {
			out.Capabilities = append(out.Capabilities, capability)
		}
	}
	return out, nil
}

func loadProfiledSCCMOrigins(ctx context.Context, run modules.RunContext) ([]profiledOrigin, error) {
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	assetByID := map[string]models.Asset{}
	for _, asset := range filterLiveTargets(assets) {
		assetByID[asset.ID] = asset
	}
	selected := map[string]profiledOrigin{}
	selectedAt := map[string]time.Time{}
	for _, item := range evidence {
		asset, ok := assetByID[item.AssetID]
		if !ok || item.Type != "http_profile" || intFromAny(item.Data["status_code"]) == 0 {
			continue
		}
		endpoint := strings.TrimSpace(fmt.Sprint(item.Data["endpoint"]))
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			continue
		}
		validOrigin := (u.Scheme == "http" && effectivePort(u) == 80) || (u.Scheme == "https" && effectivePort(u) == 443)
		if !validOrigin {
			continue
		}
		if finalRaw := mapString(item.Data, "final_url"); finalRaw != "" {
			finalURL, finalErr := url.Parse(finalRaw)
			if finalErr != nil || !strings.EqualFold(finalURL.Scheme, u.Scheme) || !strings.EqualFold(normalizeHost(finalURL.Hostname()), normalizeHost(u.Hostname())) || effectivePort(finalURL) != effectivePort(u) {
				continue
			}
		}
		if !parseOpenPorts(asset.Properties["open_ports"])[effectivePort(u)] || !strings.EqualFold(normalizeHost(u.Hostname()), normalizeHost(targetAddress(asset))) {
			continue
		}
		key := asset.ID + "\x00" + canonicalOrigin(u)
		if existing, ok := selectedAt[key]; ok && !item.CollectedAt.After(existing) {
			continue
		}
		selectedAt[key] = item.CollectedAt
		selected[key] = profiledOrigin{Asset: asset, Origin: canonicalOrigin(u), RootProfile: item.Data}
	}
	var out []profiledOrigin
	for _, key := range sortedMapKeys(selected) {
		out = append(out, selected[key])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Asset.ID != out[j].Asset.ID {
			return out[i].Asset.ID < out[j].Asset.ID
		}
		return out[i].Origin < out[j].Origin
	})
	return out, nil
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func explicitScopedHosts(assets []models.Asset) map[string]bool {
	out := map[string]bool{}
	for _, asset := range filterLiveTargets(assets) {
		out[normalizeHost(targetAddress(asset))] = true
		for _, address := range asset.IPAddresses {
			out[normalizeHost(address)] = true
		}
	}
	return out
}

func routeEvidenceFromObservation(observation routeObservation, source string) models.Evidence {
	data := routeObservationData(observation)
	evidence := models.Evidence{Type: "sccm_http_route", Title: observation.Method + " " + observation.Path + " on " + observation.Origin, Summary: routeObservationSummary(observation), Data: data, SourceModule: source, AssetID: observation.AssetID, Sensitivity: models.SensitivityInternal}
	evidence.Prepare(time.Now())
	return evidence
}

func accessEvidenceFromObservation(observation routeObservation, routeEvidenceID, source string) models.Evidence {
	evidence := models.Evidence{Type: "sccm_access_state", Title: "Anonymous SCCM route access state for " + observation.RouteID + " on " + observation.Origin, Summary: accessStateSummary(observation.AccessState), Data: map[string]any{
		"asset_id": observation.AssetID, "origin": observation.Origin, "route_id": observation.RouteID, "route_evidence_id": routeEvidenceID, "access_state": accessStateData(observation.AccessState),
	}, SourceModule: source, AssetID: observation.AssetID, Sensitivity: models.SensitivityInternal}
	evidence.Prepare(time.Now())
	return evidence
}

func routeObservationData(observation routeObservation) map[string]any {
	data := map[string]any{
		"asset_id": observation.AssetID, "origin": observation.Origin, "scheme": observation.Scheme, "host": observation.Host, "port": observation.Port,
		"route_id": observation.RouteID, "path": observation.Path, "method": observation.Method, "status_code": observation.StatusCode,
		"selected_headers": observation.SelectedHeaders, "authentication_schemes": observation.AuthenticationSchemes, "redirect_decision": observation.RedirectDecision,
		"response_length": observation.ResponseLength, "truncated": observation.Truncated, "parser_outcome": observation.ParserOutcome, "sccm_markers": observation.SCCMMarkers,
		"site_codes": observation.SiteCodes, "referenced_hosts": observation.ReferencedHosts, "access_state": accessStateData(observation.AccessState),
		"unverified_reason": observation.UnverifiedReason, "matches_root_profile": observation.MatchesRootProfile,
	}
	if observation.Preview != "" {
		data["bounded_preview"] = observation.Preview
	}
	if observation.Error != "" {
		data["error"] = observation.Error
	}
	return data
}

func routeObservationFromEvidence(item models.Evidence) (routeObservation, bool) {
	if item.Type != "sccm_http_route" {
		return routeObservation{}, false
	}
	observation := routeObservation{
		AssetID: item.AssetID, Origin: fmt.Sprint(item.Data["origin"]), Scheme: fmt.Sprint(item.Data["scheme"]), Host: fmt.Sprint(item.Data["host"]),
		Port: intFromAny(item.Data["port"]), RouteID: fmt.Sprint(item.Data["route_id"]), Path: fmt.Sprint(item.Data["path"]), Method: fmt.Sprint(item.Data["method"]),
		StatusCode: intFromAny(item.Data["status_code"]), AuthenticationSchemes: anyStringsLocal(item.Data["authentication_schemes"]), RedirectDecision: fmt.Sprint(item.Data["redirect_decision"]),
		ResponseLength: int64(intFromAny(item.Data["response_length"])), Truncated: boolFromAny(item.Data["truncated"]), ParserOutcome: fmt.Sprint(item.Data["parser_outcome"]),
		SCCMMarkers: anyStringsLocal(item.Data["sccm_markers"]), SiteCodes: anyStringsLocal(item.Data["site_codes"]), ReferencedHosts: anyStringsLocal(item.Data["referenced_hosts"]),
		UnverifiedReason: fmt.Sprint(item.Data["unverified_reason"]), Preview: fmt.Sprint(item.Data["bounded_preview"]), MatchesRootProfile: boolFromAny(item.Data["matches_root_profile"]), Error: fmt.Sprint(item.Data["error"]),
	}
	observation.AccessState = accessStateFromAny(item.Data["access_state"])
	if headers, ok := item.Data["selected_headers"].(map[string]any); ok {
		observation.SelectedHeaders = map[string]string{}
		for key, value := range headers {
			observation.SelectedHeaders[key] = fmt.Sprint(value)
		}
	} else if headers, ok := item.Data["selected_headers"].(map[string]string); ok {
		observation.SelectedHeaders = headers
	}
	return observation, observation.RouteID != ""
}

func accessStateData(state SCCMAccessState) map[string]any {
	return map[string]any{
		"transport_reachable": state.TransportReachable, "http_response_received": state.HTTPResponseReceived, "anonymous_request": state.AnonymousRequest,
		"authentication_requested": state.AuthenticationRequested, "authentication_attempted": state.AuthenticationAttempted, "authenticated": state.Authenticated,
		"usable_read_access": state.UsableReadAccess, "protocol_validated": state.ProtocolValidated,
	}
}

func accessStateFromAny(value any) SCCMAccessState {
	data, _ := value.(map[string]any)
	return SCCMAccessState{
		TransportReachable: boolFromAny(data["transport_reachable"]), HTTPResponseReceived: boolFromAny(data["http_response_received"]), AnonymousRequest: boolFromAny(data["anonymous_request"]),
		AuthenticationRequested: boolFromAny(data["authentication_requested"]), AuthenticationAttempted: boolFromAny(data["authentication_attempted"]), Authenticated: boolFromAny(data["authenticated"]),
		UsableReadAccess: boolFromAny(data["usable_read_access"]), ProtocolValidated: boolFromAny(data["protocol_validated"]),
	}
}

func boolFromAny(value any) bool {
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	parsed, _ := strconv.ParseBool(fmt.Sprint(value))
	return parsed
}

func storedRouteApplicable(ctx context.Context, run modules.RunContext, routeID string) (bool, string) {
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return false, "stored SCCM route evidence could not be evaluated"
	}
	for _, item := range evidence {
		observation, ok := routeObservationFromEvidence(item)
		if ok && (observation.RouteID == routeID || (routeID == "distribution_point" && strings.HasPrefix(observation.RouteID, "dp_"))) {
			return true, ""
		}
	}
	return false, "no profiled SCCM route evidence is available for classification"
}

func ldapEvidenceForHost(evidence []models.Evidence, asset models.Asset, role string) []string {
	host := normalizeHost(targetAddress(asset))
	var out []string
	for _, item := range evidence {
		if item.Type != "ldap_sccm_object" {
			continue
		}
		roles := anyStringsLocal(item.Data["inferred_roles"])
		if !containsString(roles, role) {
			continue
		}
		for _, reference := range anyStringsLocal(item.Data["referenced_hosts"]) {
			if strings.EqualFold(normalizeHost(reference), host) {
				out = append(out, item.ID)
			}
		}
	}
	return normalizedStrings(out)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func classifyDistributionPoint(items []struct {
	evidence    models.Evidence
	observation routeObservation
}, allEvidence []models.Evidence, asset models.Asset) (classification, confidence string, supporting []string, remaining string) {
	var strong []models.Evidence
	accessControlledByRoute := map[string]models.Evidence{}
	for _, item := range items {
		observation := item.observation
		if observation.MatchesRootProfile {
			continue
		}
		if observation.StatusCode >= 200 && observation.StatusCode < 300 {
			strong = append(strong, item.evidence)
		}
		if observation.StatusCode == http.StatusUnauthorized || observation.StatusCode == http.StatusForbidden {
			accessControlledByRoute[observation.RouteID] = item.evidence
		}
	}
	var accessControlled []models.Evidence
	for _, routeID := range sortedMapKeys(accessControlledByRoute) {
		accessControlled = append(accessControlled, accessControlledByRoute[routeID])
	}
	if len(strong) > 0 {
		for _, item := range strong {
			supporting = append(supporting, item.ID)
		}
		return "likely_distribution_point", string(models.ConfidenceHigh), normalizedStrings(supporting), "An exact SCCM distribution-point virtual-directory root returned a distinct 2xx response. No directory listing, package, signature, manifest, or content was requested; absolute role confirmation remains unverified."
	}
	independent := ldapEvidenceForHost(allEvidence, asset, "distribution_point")
	independent = append(independent, sccmProtocolEvidenceForAsset(allEvidence, asset.ID)...)
	if len(accessControlled) >= 2 || (len(accessControlled) > 0 && len(independent) > 0) {
		for _, item := range accessControlled {
			supporting = append(supporting, item.ID)
		}
		supporting = append(supporting, independent...)
		return "likely_distribution_point", string(models.ConfidenceMedium), normalizedStrings(supporting), "Multiple distinct non-catch-all exact DP routes were access controlled, or an access-controlled route was corroborated by independent SCCM evidence. Authentication and usable content access were not attempted or validated."
	}
	for _, item := range items {
		supporting = append(supporting, item.evidence.ID)
	}
	return "unverified", "unverified", normalizedStrings(supporting), "Responses were missing, generic, catch-all, denied without corroboration, timed out, rejected on redirect, or otherwise inconclusive."
}

func sccmProtocolEvidenceForAsset(evidence []models.Evidence, assetID string) []string {
	var out []string
	for _, item := range evidence {
		if item.AssetID == assetID && item.Type == "sccm_mp_protocol" {
			classification := fmt.Sprint(item.Data["classification"])
			if classification == "protocol_validated_management_point" || classification == "likely_management_point_authentication_required" {
				out = append(out, item.ID)
			}
		}
	}
	return normalizedStrings(out)
}

func managementPointCapabilities(assetID string, state SCCMAccessState, evidenceIDs []string, source string) []models.Capability {
	items := []models.Capability{
		{Name: "sccm_mp_endpoint_reachable", Available: state.TransportReachable, Reason: "transport reached an allowlisted MP route", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_mp_http_response_received", Available: state.HTTPResponseReceived, Reason: "an HTTP response was received for an allowlisted MP route", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_mp_anonymous_request", Available: state.AnonymousRequest, Reason: "the MP route was requested anonymously without credentials", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_mp_authentication_required", Available: state.AuthenticationRequested, Reason: "401, WWW-Authenticate, or TLS client-certificate request observed without an authentication attempt", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_mp_usable_read_access", Available: state.UsableReadAccess, Reason: "usable read access requires a bounded successful SCCM MP-list parse", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_mp_protocol_validated", Available: state.ProtocolValidated, Reason: "protocol validation requires meaningful SCCM-specific parsed fields", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
	}
	for index := range items {
		items[index].Prepare()
	}
	return items
}

func distributionPointCapabilities(assetID string, reachable, response, anonymous, accessControlled, likely bool, evidenceIDs []string, source string) []models.Capability {
	items := []models.Capability{
		{Name: "sccm_dp_route_reachable", Available: reachable, Reason: "transport reached an allowlisted exact DP virtual-directory root", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_dp_http_response_received", Available: response, Reason: "an HTTP response was received for an exact DP virtual-directory root", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_dp_anonymous_request", Available: anonymous, Reason: "DP route roots were requested anonymously without credentials", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_dp_access_controlled", Available: accessControlled, Reason: "an exact DP route returned 401/403; this does not mean authentication succeeded", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
		{Name: "sccm_dp_likely", Available: likely, Reason: "positive DP classification after catch-all protection and evidence correlation", Source: source, AssetID: assetID, EvidenceIDs: evidenceIDs},
	}
	for index := range items {
		items[index].Prepare()
	}
	return items
}

func dpRouteIDs(items []struct {
	evidence    models.Evidence
	observation routeObservation
}) []string {
	var out []string
	for _, item := range items {
		out = append(out, item.observation.RouteID)
	}
	return normalizedStrings(out)
}

func routeObservationSummary(observation routeObservation) string {
	if observation.Error != "" {
		return "The bounded anonymous request did not complete: " + observation.UnverifiedReason + "."
	}
	return fmt.Sprintf("Anonymous %s received HTTP %d; usable_read_access=%t; protocol_validated=%t.", observation.Method, observation.StatusCode, observation.AccessState.UsableReadAccess, observation.AccessState.ProtocolValidated)
}

func accessStateSummary(state SCCMAccessState) string {
	return fmt.Sprintf("transport=%t response=%t anonymous=%t authentication_requested=%t authentication_attempted=%t authenticated=%t usable=%t protocol_validated=%t", state.TransportReachable, state.HTTPResponseReceived, state.AnonymousRequest, state.AuthenticationRequested, state.AuthenticationAttempted, state.Authenticated, state.UsableReadAccess, state.ProtocolValidated)
}

func mpClassificationSummary(classification string) string {
	switch classification {
	case "protocol_validated_management_point":
		return "A bounded SCCM management-point list parsed successfully with meaningful SCCM-specific fields."
	case "likely_management_point_authentication_required":
		return "The SCCM MP-list route requested authentication and independent LDAP evidence references the same host."
	case "low_confidence_route_behavior":
		return "The SCCM-specific route responded, but route behavior alone does not validate a management point."
	default:
		return "The management-point route result is inconclusive and no management-point finding was created."
	}
}

func dpClassificationSummary(classification string) string {
	switch classification {
	case "likely_distribution_point":
		return "Exact SCCM distribution-point virtual-directory evidence supports a likely distribution point after catch-all protection."
	case "access_controlled_routes_unverified":
		return "Access-controlled exact routes lack sufficient independent evidence for a distribution-point classification."
	default:
		return "Distribution-point route results are inconclusive and no distribution-point finding was created."
	}
}
