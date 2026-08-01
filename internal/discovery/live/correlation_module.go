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

const correlationSource = "live.sccm.correlate"

type correlationModule struct{ opts Options }

func (m *correlationModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: correlationSource, Description: "Correlates stored SCCM, LDAP, DNS, and TLS evidence without network traffic", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "network_probe_completed"}}}
}
func (m *correlationModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (m *correlationModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: correlationSource, Message: "passive SCCM evidence correlation"})
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	evidence, err := run.Store.ListEvidence(ctx)
	if err != nil {
		return nil, err
	}
	return correlateSCCMEvidence(assets, evidence, time.Now()), nil
}

type hostCorrelation struct {
	asset                                               models.Asset
	aliases, addresses, ldap, tls, mpRefs, roles, sites []string
	protocolValidated                                   bool
	roleConfidence                                      models.Confidence
	supporting                                          []string
	conflicts                                           []map[string]any
}

func correlateSCCMEvidence(assets []models.Asset, evidence []models.Evidence, now time.Time) *modules.Result {
	out := &modules.Result{}
	hosts := map[string]*hostCorrelation{}
	nameIndex, addressIndex := map[string][]string{}, map[string][]string{}
	observed := map[string]bool{}
	for _, a := range assets {
		if a.Kind != models.AssetUnknown || a.Properties["observation_origin"] != "live" {
			continue
		}
		h := &hostCorrelation{asset: a, aliases: normalizedStrings([]string{a.FQDN, a.Hostname}), addresses: normalizedStrings(a.IPAddresses), roles: normalizedStrings(a.Roles), sites: normalizedStrings([]string{a.SiteCode}), roleConfidence: a.Confidence}
		hosts[a.ID] = h
		observed[a.ID] = a.Properties["normalized_target"] != "" || a.Properties["reachable"] == "true"
		for _, n := range h.aliases {
			nameIndex[normalizeHost(n)] = append(nameIndex[normalizeHost(n)], a.ID)
		}
		for _, ip := range h.addresses {
			addressIndex[normalizeHost(ip)] = append(addressIndex[normalizeHost(ip)], a.ID)
		}
	}
	// Add persisted DNS aliases and addresses before matching directory and MP-list references.
	for _, e := range evidence {
		if e.Type != "dns_resolution" || hosts[e.AssetID] == nil {
			continue
		}
		h := hosts[e.AssetID]
		if len(anyStringsLocal(e.Data["answers"])) > 0 {
			observed[e.AssetID] = true
		}
		for _, v := range anyStringsLocal(e.Data["answers"]) {
			if net.ParseIP(v) != nil {
				h.addresses = append(h.addresses, v)
			} else {
				h.aliases = append(h.aliases, v)
			}
		}
		if cname := normalizeHost(fmt.Sprint(e.Data["cname"])); cname != "" {
			h.aliases = append(h.aliases, cname)
		}
	}
	nameIndex, addressIndex = map[string][]string{}, map[string][]string{}
	for id, h := range hosts {
		h.aliases, h.addresses = normalizedStrings(h.aliases), normalizedStrings(h.addresses)
		for _, n := range h.aliases {
			nameIndex[normalizeHost(n)] = append(nameIndex[normalizeHost(n)], id)
		}
		for _, ip := range h.addresses {
			addressIndex[normalizeHost(ip)] = append(addressIndex[normalizeHost(ip)], id)
		}
	}
	match := func(ref string) []string {
		ref = normalizeHost(ref)
		ids := append([]string(nil), nameIndex[ref]...)
		if ip := net.ParseIP(ref); ip != nil {
			ids = append(ids, addressIndex[normalizeHost(ip.String())]...)
		}
		if !strings.Contains(ref, ".") && net.ParseIP(ref) == nil {
			for name, candidates := range nameIndex {
				if strings.Split(name, ".")[0] == ref {
					ids = append(ids, candidates...)
				}
			}
		}
		return normalizedStrings(ids)
	}
	ldapReferenced := map[string]bool{}
	for _, e := range evidence {
		switch e.Type {
		case "dns_resolution":
			h := hosts[e.AssetID]
			if h == nil {
				continue
			}
			answers := anyStringsLocal(e.Data["answers"])
			h.supporting = append(h.supporting, e.ID)
			for _, v := range answers {
				if net.ParseIP(v) != nil {
					h.addresses = append(h.addresses, v)
				} else {
					h.aliases = append(h.aliases, v)
				}
			}
			if cname := normalizeHost(fmt.Sprint(e.Data["cname"])); cname != "" {
				h.aliases = append(h.aliases, cname)
			}
		case "http_profile":
			h := hosts[e.AssetID]
			if h == nil {
				continue
			}
			tls, _ := e.Data["tls"].(map[string]any)
			names := anyStringsLocal(tls["dns_names"])
			names = append(names, anyStringsLocal(tls["ip_addresses"])...)
			h.tls = append(h.tls, names...)
			if len(names) > 0 {
				h.supporting = append(h.supporting, e.ID)
				for _, name := range names {
					addReferenceRelationship(out, models.StableID("certname", models.StableFingerprint(name)), h.asset.ID, models.RelationshipCertificateNamesHost, name, e.ID, models.ConfidenceMedium)
				}
			}
			contacted := normalizeHost(targetAddress(h.asset))
			if len(names) > 0 && !certificateMatches(contacted, names) {
				addConflict(h, "certificate_name_mismatch", []string{contacted}, names, []string{e.ID}, "medium", "The certificate names do not identify the contacted hostname.", "Certificate deployment intent and alternate-name ownership remain unverified.")
			}
		case "ldap_sccm_object":
			for _, ref := range anyStringsLocal(e.Data["referenced_hosts"]) {
				ids := match(ref)
				if len(ids) == 0 {
					addUnresolved(out, "unresolved_directory_reference", ref, e.ID, "LDAP references a host that was not resolved or discovered.", now)
					continue
				}
				resolved := false
				for _, id := range ids {
					resolved = resolved || observed[id]
				}
				if !resolved {
					addUnresolved(out, "unresolved_directory_reference", ref, e.ID, "LDAP references a host that has no successful DNS or scoped network observation.", now)
				}
				for _, id := range ids {
					h := hosts[id]
					h.ldap = append(h.ldap, ref)
					h.supporting = append(h.supporting, e.ID)
					ldapReferenced[id] = true
					addReferenceRelationship(out, models.StableID("ldapobj", models.StableFingerprint(fmt.Sprint(e.Data["distinguished_name"]))), id, models.RelationshipDirectoryReferencesHost, ref, e.ID, models.ConfidenceHigh)
				}
			}
		case "sccm_mp_protocol":
			h := hosts[e.AssetID]
			if h == nil {
				continue
			}
			if fmt.Sprint(e.Data["classification"]) == "protocol_validated_management_point" {
				h.protocolValidated = true
				h.roles = append(h.roles, "management_point")
				h.roleConfidence = models.ConfidenceHigh
				addReferenceRelationship(out, h.asset.ID, h.asset.ID, models.RelationshipValidatedManagementPoint, "management_point", e.ID, models.ConfidenceHigh)
			}
			h.sites = append(h.sites, anyStringsLocal(e.Data["site_codes"])...)
			h.supporting = append(h.supporting, e.ID)
			for _, ref := range anyStringsLocal(e.Data["referenced_hosts"]) {
				ids := match(ref)
				if len(ids) == 0 {
					addUnresolved(out, "unmatched_mp_list_reference", ref, e.ID, "A validated management-point list references a host absent from discovered assets.", now)
					continue
				}
				for _, id := range ids {
					hosts[id].mpRefs = append(hosts[id].mpRefs, ref)
					addReferenceRelationship(out, e.AssetID, id, models.RelationshipMPListReferencesHost, ref, e.ID, models.ConfidenceHigh)
				}
			}
		case "sccm_dp_virtual_directory":
			h := hosts[e.AssetID]
			if h != nil && fmt.Sprint(e.Data["classification"]) == "likely_distribution_point" {
				h.roles = append(h.roles, "distribution_point")
				h.supporting = append(h.supporting, e.ID)
				addReferenceRelationship(out, h.asset.ID, h.asset.ID, models.RelationshipLikelyDistributionPoint, "distribution_point", e.ID, models.ConfidenceMedium)
			}
		}
	}
	// A shared address is ambiguous: preserve every asset and annotate all participants.
	shared := map[string][]string{}
	for id, h := range hosts {
		h.aliases = normalizedStrings(h.aliases)
		h.addresses = normalizedStrings(h.addresses)
		for _, ip := range h.addresses {
			shared[ip] = append(shared[ip], id)
		}
	}
	for ip, ids := range shared {
		ids = normalizedStrings(ids)
		if len(ids) == 2 && ((hosts[ids[0]].asset.FQDN == "") != (hosts[ids[1]].asset.FQDN == "")) {
			from, to := ids[0], ids[1]
			if hosts[from].asset.FQDN == "" {
				from, to = to, from
			}
			addReferenceRelationship(out, from, to, models.RelationshipSameLogicalHost, ip, firstEvidence(hosts[from].supporting), models.ConfidenceHigh)
			continue
		}
		if len(ids) > 1 {
			for _, id := range ids {
				addConflict(hosts[id], "shared_ip_ambiguous", []string{ip}, ids, nil, "medium", "Multiple distinct host identities share one address; they were not merged.", "Whether the address is shared, stale, load-balanced, or reassigned remains unverified.")
			}
		}
	}
	for name, ids := range nameIndex {
		ids = normalizedStrings(ids)
		if len(ids) < 2 {
			continue
		}
		var sites []string
		for _, id := range ids {
			sites = append(sites, hosts[id].sites...)
		}
		sites = normalizedStrings(sites)
		for _, id := range ids {
			addConflict(hosts[id], "name_identity_ambiguous", []string{name}, ids, nil, "medium", "The same normalized host name identifies multiple stable assets; they were not merged.", "Whether site metadata is stale or the records represent one logical host remains unverified.")
			if len(sites) > 1 {
				addConflict(hosts[id], "site_code_conflict", sites, ids, nil, "high", "Different SCCM site codes are associated with assets sharing the same host name.", "The authoritative current site assignment remains unverified.")
			}
		}
	}
	for id, h := range hosts {
		h.sites = normalizedStrings(h.sites)
		if len(h.sites) > 1 {
			addConflict(h, "site_code_conflict", h.sites, nil, h.supporting, "high", "Different SCCM site codes are associated with the same correlated host.", "The authoritative current site assignment remains unverified.")
		}
		if h.protocolValidated && !ldapReferenced[id] {
			addConflict(h, "validated_endpoint_absent_from_ldap", []string{targetAddress(h.asset)}, nil, h.supporting, "high", "The endpoint is protocol-validated as a management point but no collected LDAP object references it.", "LDAP search coverage and directory replication state remain unverified.")
		}
		for _, c := range h.conflicts {
			out.Evidence = append(out.Evidence, conflictEvidence(id, c, now))
		}
		version := models.SCCMVersionObservation{Product: "Microsoft Configuration Manager", Value: "unknown", State: "unknown", Reliable: false, Confidence: models.ConfidenceLow, SupportingEvidence: []string{}, Unverified: "No reliable protocol-specific SCCM product version field was collected."}
		data := map[string]any{"canonical_host_identity": canonicalName(h.asset), "aliases": normalizedStrings(h.aliases), "resolved_addresses": normalizedStrings(h.addresses), "sccm_roles": normalizedStrings(h.roles), "site_codes": h.sites, "role_confidence": h.roleConfidence, "protocol_validated": h.protocolValidated, "ldap_references": normalizedStrings(h.ldap), "tls_names": normalizedStrings(h.tls), "mp_list_references": normalizedStrings(h.mpRefs), "identity_conflicts": h.conflicts, "version": version, "supporting_evidence": normalizedStrings(h.supporting), "origin": "inferred_conclusion"}
		e := models.Evidence{Type: "sccm_topology_correlation", Title: "Passive SCCM topology correlation for " + canonicalName(h.asset), Summary: "Correlated existing LDAP, DNS, TLS, role-hint, and SCCM route evidence without network activity. SCCM version: unknown.", Data: data, SourceModule: correlationSource, AssetID: id, Sensitivity: models.SensitivityInternal}
		e.Prepare(now)
		out.Evidence = append(out.Evidence, e)
	}
	return out
}

func canonicalName(a models.Asset) string {
	if a.FQDN != "" {
		return normalizeHost(a.FQDN)
	}
	if a.Hostname != "" {
		return normalizeHost(a.Hostname)
	}
	if len(a.IPAddresses) > 0 {
		return normalizeHost(a.IPAddresses[0])
	}
	return a.ID
}
func certificateMatches(host string, names []string) bool {
	for _, n := range names {
		n = normalizeHost(n)
		if n == host || (strings.HasPrefix(n, "*.") && strings.HasSuffix(host, n[1:]) && strings.Count(host, ".") == strings.Count(n, ".")) {
			return true
		}
	}
	return false
}
func addConflict(h *hostCorrelation, kind string, observed, compared, sources []string, confidence, why, unverified string) {
	h.conflicts = append(h.conflicts, map[string]any{"type": kind, "sources": normalizedStrings(sources), "observed_values": normalizedStrings(observed), "compared_values": normalizedStrings(compared), "confidence": confidence, "why_it_matters": why, "what_remains_unverified": unverified})
}
func conflictEvidence(assetID string, data map[string]any, now time.Time) models.Evidence {
	e := models.Evidence{Type: "identity_conflict", Title: "SCCM identity conflict: " + fmt.Sprint(data["type"]), Summary: fmt.Sprint(data["why_it_matters"]), Data: data, SourceModule: correlationSource, AssetID: assetID, Sensitivity: models.SensitivityInternal}
	e.Prepare(now)
	return e
}
func addUnresolved(out *modules.Result, kind, ref, evidenceID, why string, now time.Time) {
	data := map[string]any{"type": kind, "reference": normalizeHost(ref), "sources": []string{evidenceID}, "confidence": "high", "why_it_matters": why, "what_remains_unverified": "DNS state, discovery scope, and whether the reference is stale remain unverified."}
	e := models.Evidence{Type: kind, Title: "Unmatched SCCM host reference: " + normalizeHost(ref), Summary: why, Data: data, SourceModule: correlationSource, Sensitivity: models.SensitivityInternal}
	e.Prepare(now)
	out.Evidence = append(out.Evidence, e)
	f := models.Finding{RuleID: "DISCOVERY-SCCM-UNRESOLVED-REFERENCE", Title: "SCCM host reference could not be correlated", Summary: why, Description: fmt.Sprintf("Source %s observed %q. Confidence: high. %s", evidenceID, ref, data["what_remains_unverified"]), Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, EvidenceIDs: []string{evidenceID, e.ID}, Tags: []string{"discovery", "sccm", "correlation"}, Remediation: "Validate the reference against authorized DNS, AD, and SCCM inventory."}
	f.Prepare(now)
	out.Findings = append(out.Findings, f)
}
func addReferenceRelationship(out *modules.Result, from, to string, typ models.RelationshipType, value, evidenceID string, confidence models.Confidence) {
	r := models.Relationship{FromID: from, ToID: to, Type: typ, Properties: map[string]string{"reference": normalizeHost(value), "origin": "correlated_evidence"}, EvidenceIDs: []string{evidenceID}, Confidence: confidence}
	r.Prepare()
	out.Relationships = append(out.Relationships, r)
}
func firstEvidence(values []string) string {
	if len(values) > 0 {
		return values[0]
	}
	return ""
}
