package live

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
	"github.com/Lmarkussen/CinderPath/internal/scope"
)

type roleModule struct{ opts Options }
type roleConclusion struct {
	Role, Reason, Origin string
	Confidence           models.Confidence
	EvidenceIDs          []string
	Precedence           int
}

func (m *roleModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.roles.infer", Description: "Infers likely SCCM roles conservatively from normalized evidence", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "network_probe_completed"}}}
}
func (m *roleModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (m *roleModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "evidence-based SCCM role inference"})
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	out := &modules.Result{}
	now := time.Now()
	domainID := ""
	for _, a := range assets {
		if a.Kind == models.AssetDomain && domainID == "" {
			domainID = a.ID
		}
	}
	for _, a := range assets {
		if a.Properties["observation_origin"] != "live" || a.Kind != models.AssetUnknown {
			continue
		}
		conclusions := inferRoles(a, m.opts.Hints, evidence)
		if len(conclusions) == 0 {
			continue
		}
		var roles []string
		var supportingEvidence []string
		for _, c := range conclusions {
			roles = append(roles, c.Role)
			supportingEvidence = append(supportingEvidence, c.EvidenceIDs...)
		}
		e := models.Evidence{Type: "role_inference", Title: "SCCM role inference for " + targetAddress(a), Summary: roleSummary(conclusions), Data: map[string]any{"host": targetAddress(a), "conclusions": conclusionsData(conclusions), "origin": "inferred_conclusion", "unverified": "Role-specific protocol behavior and SCCM configuration remain unverified."}, SourceModule: m.Metadata().Name, AssetID: a.ID, Sensitivity: models.SensitivityInternal}
		e.Prepare(now)
		out.Evidence = append(out.Evidence, e)
		a.Roles = mergeUnique(a.Roles, roles)
		a.Properties = cloneMap(a.Properties)
		a.Properties["role_inference_origin"] = "inferred"
		for _, c := range conclusions {
			if c.Origin == "user_input" {
				a.Properties["has_user_hint"] = "true"
			}
		}
		a.Properties["role_evidence_ids"] = strings.Join(normalizedStrings(append(supportingEvidence, e.ID)), ",")
		a.Confidence = maxConfidence(conclusions)
		out.Assets = append(out.Assets, a)
		from := domainID
		if from == "" {
			from = a.ID
		}
		for _, c := range conclusions {
			relType := models.RelationshipDomainContainsAsset
			switch c.Role {
			case "management_point":
				relType = models.RelationshipPossibleManagementPoint
			case "distribution_point":
				relType = models.RelationshipPossibleDistributionPoint
			case "site_server":
				relType = models.RelationshipPossibleSiteServer
			default:
				relType = models.RelationshipDomainContainsAsset
			}
			rel := models.Relationship{FromID: from, ToID: a.ID, Type: relType, Properties: map[string]string{"origin": c.Origin, "role": c.Role, "reason": c.Reason}, EvidenceIDs: normalizedStrings(append(c.EvidenceIDs, e.ID)), Confidence: c.Confidence}
			rel.Prepare()
			out.Relationships = append(out.Relationships, rel)
		}
		for _, c := range conclusions {
			rule, title, ok := roleFinding(c.Role)
			if !ok {
				continue
			}
			f := models.Finding{RuleID: rule, Title: title, Summary: c.Reason + " This is a discovery conclusion, not a vulnerability.", Description: "CinderPath inferred this role from safe metadata. Role-specific SCCM behavior remains unverified.", Severity: models.SeverityInformational, Confidence: c.Confidence, AssetIDs: []string{a.ID}, EvidenceIDs: normalizedStrings(append(c.EvidenceIDs, e.ID)), Tags: []string{"discovery", "inferred", c.Role}, Remediation: "Validate the inferred role against authorized SCCM configuration and inventory."}
			f.Prepare(now)
			out.Findings = append(out.Findings, f)
		}
	}
	return out, nil
}
func inferRoles(a models.Asset, h RoleHints, evidence []models.Evidence) []roleConclusion {
	host := strings.ToLower(targetAddress(a))
	open := parseOpenPorts(a.Properties["open_ports"])
	byRole := map[string]roleConclusion{}
	add := func(c roleConclusion) {
		old, ok := byRole[c.Role]
		if !ok || confidenceRank(c.Confidence) > confidenceRank(old.Confidence) || (confidenceRank(c.Confidence) == confidenceRank(old.Confidence) && c.Precedence > old.Precedence) {
			byRole[c.Role] = c
		} else if confidenceRank(c.Confidence) == confidenceRank(old.Confidence) && c.Precedence == old.Precedence {
			old.EvidenceIDs = normalizedStrings(append(old.EvidenceIDs, c.EvidenceIDs...))
			byRole[c.Role] = old
		}
	}
	for _, r := range a.Roles {
		if a.Properties["role_basis"] == "ldap_sccm_object" {
			add(roleConclusion{Role: r, Reason: "LDAP SCCM object explicitly referenced this host as " + r, Origin: "live_observation", Confidence: models.ConfidenceHigh, EvidenceIDs: ldapEvidenceForHost(evidence, a, r), Precedence: 5})
		}
	}
	for _, e := range evidence {
		if e.AssetID != a.ID {
			continue
		}
		switch e.Type {
		case "sccm_mp_protocol":
			classification := fmt.Sprint(e.Data["classification"])
			if classification == "protocol_validated_management_point" {
				add(roleConclusion{Role: "management_point", Reason: "A bounded SCCM management-point list parsed with meaningful protocol fields", Origin: "live_observation", Confidence: models.ConfidenceHigh, EvidenceIDs: []string{e.ID}, Precedence: 6})
			} else if classification == "likely_management_point_authentication_required" {
				add(roleConclusion{Role: "management_point", Reason: "The SCCM MP-list route requested authentication and LDAP independently references this host", Origin: "inferred_conclusion", Confidence: models.ConfidenceMedium, EvidenceIDs: []string{e.ID}, Precedence: 4})
			}
		case "sccm_dp_virtual_directory":
			if fmt.Sprint(e.Data["classification"]) == "likely_distribution_point" {
				confidence := models.ConfidenceMedium
				if fmt.Sprint(e.Data["confidence"]) == string(models.ConfidenceHigh) {
					confidence = models.ConfidenceHigh
				}
				add(roleConclusion{Role: "distribution_point", Reason: "Exact SCCM distribution-point virtual-directory evidence passed catch-all protection", Origin: "inferred_conclusion", Confidence: confidence, EvidenceIDs: []string{e.ID}, Precedence: 4})
			}
		}
	}
	for role, items := range map[string][]string{"management_point": h.ManagementPoints, "distribution_point": h.DistributionPoints, "site_server": h.SiteServers, "sql_server": h.SQLServers} {
		for _, item := range items {
			normalized, _, _ := scope.NormalizeValue(item, "")
			if strings.EqualFold(normalized, host) {
				add(roleConclusion{Role: role, Reason: "User supplied a non-confirmed " + role + " hint for this host", Origin: "user_input", Confidence: models.ConfidenceMedium})
			}
		}
	}
	if open[8530] || open[8531] {
		add(roleConclusion{Role: "software_update_point", Reason: "TCP 8530/8531 is reachable, supporting possible WSUS/software update functionality", Origin: "live_observation", Confidence: models.ConfidenceMedium})
	}
	if open[1433] {
		add(roleConclusion{Role: "sql_server", Reason: "TCP 1433 is reachable; SCCM database association is unverified", Origin: "live_observation", Confidence: models.ConfidenceLow})
	}
	if open[10123] {
		add(roleConclusion{Role: "client", Reason: "TCP 10123 is reachable and is SCCM-related supporting evidence", Origin: "live_observation", Confidence: models.ConfidenceLow})
	}
	if strings.Contains(host, "sccm") || strings.Contains(host, "configmgr") {
		add(roleConclusion{Role: "site_server", Reason: "Hostname pattern suggests SCCM infrastructure; no role-specific protocol was verified", Origin: "inferred_conclusion", Confidence: models.ConfidenceLow})
	}
	if strings.HasPrefix(host, "dp") && open[80] {
		add(roleConclusion{Role: "distribution_point", Reason: "Hostname pattern plus HTTP reachability weakly suggests a distribution point", Origin: "inferred_conclusion", Confidence: models.ConfidenceLow})
	}
	if strings.Contains(host, "pxe") && (open[80] || open[443]) {
		add(roleConclusion{Role: "pxe_service_point", Reason: "Hostname pattern plus web reachability weakly suggests PXE-related infrastructure", Origin: "inferred_conclusion", Confidence: models.ConfidenceLow})
	}
	for _, e := range evidence {
		if e.AssetID != a.ID || e.Type != "http_profile" {
			continue
		}
		text := strings.ToLower(fmt.Sprint(e.Data["page_title"]) + " " + fmt.Sprint(e.Data["server"]) + " " + fmt.Sprint(e.Data["authentication_headers"]))
		if strings.Contains(text, "configuration manager") || strings.Contains(text, "sms management") {
			add(roleConclusion{Role: "management_point", Reason: "Bounded HTTP metadata contained Configuration Manager terminology", Origin: "live_observation", Confidence: models.ConfidenceMedium, EvidenceIDs: []string{e.ID}})
		}
		if strings.Contains(text, "wsus") {
			add(roleConclusion{Role: "software_update_point", Reason: "Bounded HTTP metadata contained WSUS terminology", Origin: "live_observation", Confidence: models.ConfidenceMedium, EvidenceIDs: []string{e.ID}})
		}
	}
	var out []roleConclusion
	for _, c := range byRole {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}
func confidenceRank(c models.Confidence) int {
	switch c {
	case models.ConfidenceConfirmed:
		return 4
	case models.ConfidenceHigh:
		return 3
	case models.ConfidenceMedium:
		return 2
	default:
		return 1
	}
}
func maxConfidence(c []roleConclusion) models.Confidence {
	out := models.ConfidenceLow
	for _, v := range c {
		if confidenceRank(v.Confidence) > confidenceRank(out) {
			out = v.Confidence
		}
	}
	return out
}
func roleSummary(c []roleConclusion) string {
	parts := make([]string, len(c))
	for i, v := range c {
		parts[i] = fmt.Sprintf("%s (%s): %s", v.Role, v.Confidence, v.Reason)
	}
	return strings.Join(parts, "; ")
}
func conclusionsData(c []roleConclusion) []map[string]any {
	out := make([]map[string]any, len(c))
	for i, v := range c {
		out[i] = map[string]any{"role": v.Role, "confidence": v.Confidence, "reason": v.Reason, "origin": v.Origin, "evidence_ids": v.EvidenceIDs}
	}
	return out
}
func roleFinding(role string) (string, string, bool) {
	switch role {
	case "pxe_service_point":
		return "DISCOVERY-PXE", "Likely PXE service point discovered", true
	case "software_update_point":
		return "DISCOVERY-SUP", "Likely software update point discovered", true
	}
	return "", "", false
}
