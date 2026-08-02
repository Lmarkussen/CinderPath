package capture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const EndpointAlgorithmVersion = "capture-endpoint-attribution-v1"

type InventoryEndpointEvidence struct {
	HostnameFingerprint  string   `json:"hostname_fingerprint,omitempty"`
	Source               string   `json:"source"`
	Observed             bool     `json:"observed"`
	OperatorAsserted     bool     `json:"operator_asserted"`
	SitePresent          bool     `json:"site_present"`
	ClientVersionPresent bool     `json:"client_version_present"`
	Warnings             []string `json:"warnings,omitempty"`
}

type EndpointEdge struct {
	ID                    string    `json:"edge_id"`
	From                  string    `json:"from"`
	To                    string    `json:"to"`
	Kind                  string    `json:"kind"`
	EvidenceRef           string    `json:"evidence_ref"`
	TimestampRelationship string    `json:"timestamp_relationship,omitempty"`
	Confidence            string    `json:"confidence"`
	Warnings              []string  `json:"warnings,omitempty"`
	Timestamp             time.Time `json:"timestamp,omitempty"`
}

type EndpointCandidate struct {
	ID                    string    `json:"endpoint_candidate_id"`
	HostnameFingerprint   string    `json:"hostname_fingerprint,omitempty"`
	AddressFingerprints   []string  `json:"address_fingerprints,omitempty"`
	SourceTypes           []string  `json:"source_types"`
	FirstSeen             time.Time `json:"first_seen,omitempty"`
	LastSeen              time.Time `json:"last_seen,omitempty"`
	EvidenceRefs          []string  `json:"evidence_refs"`
	Roles                 []string  `json:"roles"`
	Score                 int       `json:"score"`
	Confidence            string    `json:"confidence"`
	SupportingEvidence    []string  `json:"supporting_evidence"`
	ContradictingEvidence []string  `json:"contradicting_evidence"`
	Warnings              []string  `json:"warnings,omitempty"`
}

type TLSEndpointLink struct {
	FlowID                string   `json:"flow_id"`
	EndpointCandidateID   string   `json:"endpoint_candidate_id,omitempty"`
	EndpointConfidence    string   `json:"endpoint_confidence"`
	FlowConfidence        string   `json:"flow_confidence"`
	PolicyEventConfidence string   `json:"policy_event_confidence"`
	Score                 int      `json:"score"`
	ObservedPorts         []uint16 `json:"observed_ports,omitempty"`
	TLSVersion            string   `json:"tls_version,omitempty"`
	SNIPresent            bool     `json:"sni_present"`
	ALPNPresent           bool     `json:"alpn_present"`
	SupportingEvidence    []string `json:"supporting_evidence"`
	ContradictingEvidence []string `json:"contradicting_evidence"`
}

type EndpointCorrelationResult struct {
	SchemaVersion          int                         `json:"schema_version"`
	AlgorithmVersion       string                      `json:"algorithm_version"`
	Trigger                Trigger                     `json:"trigger"`
	DNS                    []DNSEvent                  `json:"dns_events"`
	Inventory              []InventoryEndpointEvidence `json:"inventory_evidence"`
	Endpoints              []EndpointCandidate         `json:"endpoint_candidates"`
	Edges                  []EndpointEdge              `json:"endpoint_evidence_graph"`
	TLSLinks               []TLSEndpointLink           `json:"tls_endpoint_links"`
	EndpointClassification string                      `json:"endpoint_classification"`
	FlowClassification     string                      `json:"flow_classification"`
	Warnings               []string                    `json:"warnings,omitempty"`
	Findings               []ResearchFinding           `json:"findings"`
	Capabilities           []string                    `json:"capabilities"`
	LivePolicyRequests     int                         `json:"live_policy_requests"`
}

func LoadInventoryEvidence(path string) ([]InventoryEndpointEvidence, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 2<<20 {
		return nil, errors.New("client inventory exceeds 2 MiB")
	}
	var root map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err = d.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse client inventory: %w", err)
	}
	var out []InventoryEndpointEvidence
	if authority, ok := objectValue(root, "sccm_authority"); ok {
		if mp := stringValue(authority, "CurrentManagementPoint", "current_management_point", "management_point"); mp != "" {
			out = append(out, InventoryEndpointEvidence{HostnameFingerprint: endpointFingerprint(mp), Source: "windows_client_inventory", Observed: true, SitePresent: stringValue(authority, "Name", "site_code") != ""})
		}
	}
	if mp := stringValue(root, "management_point"); mp != "" {
		out = append(out, InventoryEndpointEvidence{HostnameFingerprint: endpointFingerprint(mp), Source: "operator_capture_metadata", OperatorAsserted: true, Warnings: []string{"operator assertion is not independently verified"}})
	}
	if len(out) == 0 {
		out = append(out, InventoryEndpointEvidence{Source: "windows_client_inventory", Warnings: []string{"management-point metadata unavailable"}})
	}
	if client, ok := objectValue(root, "sccm_client"); ok {
		present := stringValue(client, "ClientVersion", "client_version") != ""
		for i := range out {
			out[i].ClientVersionPresent = present
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostnameFingerprint != out[j].HostnameFingerprint {
			return out[i].HostnameFingerprint < out[j].HostnameFingerprint
		}
		return out[i].Source < out[j].Source
	})
	return out, nil
}

func objectValue(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	x, ok := v.(map[string]any)
	return x, ok
}
func stringValue(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" && len(v) <= 4096 {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func CorrelateEndpoints(c NormalizedCapture, logs []SemanticLogEvent, inventory []InventoryEndpointEvidence, trigger Trigger, w CorrelationWindow) (EndpointCorrelationResult, error) {
	if trigger.Timestamp.IsZero() {
		return EndpointCorrelationResult{}, errors.New("trigger timestamp is required")
	}
	if w.PreTrigger < 0 || w.PostTrigger <= 0 || w.PreTrigger+w.PostTrigger > w.Maximum {
		return EndpointCorrelationResult{}, errors.New("invalid correlation window")
	}
	r := EndpointCorrelationResult{SchemaVersion: 1, AlgorithmVersion: EndpointAlgorithmVersion, Trigger: trigger, DNS: append([]DNSEvent(nil), c.DNSEvents...), Inventory: inventory, LivePolicyRequests: 0}
	type build struct {
		c                        EndpointCandidate
		inventory, log, dns, sni bool
		dnsFlow                  bool
		roleHints                []string
	}
	byHost := map[string]*build{}
	get := func(fp string) *build {
		if fp == "" {
			return nil
		}
		b := byHost[fp]
		if b == nil {
			b = &build{c: EndpointCandidate{ID: stableID("endpoint_candidate", fp), HostnameFingerprint: fp}}
			byHost[fp] = b
		}
		return b
	}
	for _, x := range inventory {
		if b := get(x.HostnameFingerprint); b != nil {
			b.inventory = true
			addSource(&b.c, x.Source, "inventory:"+x.Source)
			b.c.SupportingEvidence = append(b.c.SupportingEvidence, "passive client inventory names an endpoint")
		}
	}
	for _, x := range logs {
		if b := get(x.EndpointFingerprint); b != nil {
			b.log = true
			addSource(&b.c, "log", x.EventID)
			updateSeen(&b.c, x.Timestamp)
			b.c.SupportingEvidence = append(b.c.SupportingEvidence, "fixture-supported log structure contains endpoint fingerprint")
		}
	}
	for _, x := range c.Exchanges {
		if x.Request == nil {
			continue
		}
		for _, h := range x.Request.Headers {
			if h.Name != "host" || h.Value.Fingerprint == "" {
				continue
			}
			fp := h.Value.Fingerprint
			if len(fp) > 16 {
				fp = fp[:16]
			}
			b := get(fp)
			if b == nil {
				continue
			}
			addSource(&b.c, "http_host", x.ID)
			updateSeen(&b.c, x.StartedAt)
			lower := strings.ToLower(x.Request.Route)
			switch {
			case strings.Contains(lower, "authroot") || strings.Contains(lower, "trustedr") || strings.Contains(lower, "disallowedcert"):
				b.roleHints = append(b.roleHints, "trust_list_endpoint")
				b.c.ContradictingEvidence = append(b.c.ContradictingEvidence, "visible HTTP route is operating-system trust-list traffic")
			case strings.Contains(lower, "/update/"):
				b.roleHints = append(b.roleHints, "windows_update_endpoint")
				b.c.ContradictingEvidence = append(b.c.ContradictingEvidence, "visible HTTP route is operating-system update traffic")
			}
		}
	}
	for _, x := range c.DNSEvents {
		b := get(x.QueryNameFingerprint)
		if b == nil {
			continue
		}
		b.dns = true
		addSource(&b.c, "dns", x.ID)
		updateSeen(&b.c, x.Timestamp)
		b.c.AddressFingerprints = append(b.c.AddressFingerprints, x.AnswerFingerprints...)
		for _, a := range x.AnswerFingerprints {
			r.Edges = append(r.Edges, newEndpointEdge(x.QueryNameFingerprint, a, "time_bounded_dns_resolution", x.ID, x.Timestamp, "high"))
		}
		for _, cn := range x.CNAMEChainFingerprints {
			r.Edges = append(r.Edges, newEndpointEdge(x.QueryNameFingerprint, cn, "exact_fingerprint_match", x.ID, x.Timestamp, "high"))
		}
	}
	for _, f := range c.Flows {
		if !f.TLS {
			continue
		}
		if b := get(f.SNI); b != nil {
			b.sni = true
			addSource(&b.c, "tls_sni", f.ID)
			updateSeen(&b.c, f.StartedAt)
			b.c.SupportingEvidence = append(b.c.SupportingEvidence, "TLS SNI fingerprint identifies the same hostname")
			r.Edges = append(r.Edges, newEndpointEdge(f.SNI, f.ID, "sni_to_hostname_match", f.ID, f.StartedAt, "high"))
		}
		for _, b := range byHost {
			for _, a := range b.c.AddressFingerprints {
				if a == f.Client.AddressFingerprint || a == f.Server.AddressFingerprint {
					b.dnsFlow = true
					r.Edges = append(r.Edges, newEndpointEdge(a, f.ID, "address_to_flow_match", f.ID, f.StartedAt, "high"))
				}
			}
		}
	}
	keys := make([]string, 0, len(byHost))
	for k := range byHost {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := byHost[k]
		b.c.AddressFingerprints = uniqueSorted(b.c.AddressFingerprints)
		b.c.SourceTypes = uniqueSorted(b.c.SourceTypes)
		b.c.EvidenceRefs = uniqueSorted(b.c.EvidenceRefs)
		b.c.SupportingEvidence = uniqueSorted(b.c.SupportingEvidence)
		independent := 0
		if b.inventory {
			b.c.Score += 25
			independent++
		}
		if b.log {
			b.c.Score += 25
			independent++
		}
		if b.dns && b.dnsFlow {
			b.c.Score += 30
			independent++
		}
		if b.sni {
			b.c.Score += 20
			independent++
		}
		if b.inventory && b.log {
			r.Edges = append(r.Edges, newEndpointEdge(k, k, "log_to_inventory_match", b.c.ID, time.Time{}, "high"))
		}
		if len(b.roleHints) > 0 {
			b.c.Roles = append(b.c.Roles, b.roleHints...)
			b.c.Score -= 40
		}
		if b.inventory && independent >= 2 {
			b.c.Roles = append(b.c.Roles, "management_point_candidate")
		} else if len(b.roleHints) == 0 && (b.sni || b.dns) {
			b.c.Roles = append(b.c.Roles, "generic_https_endpoint")
		} else if len(b.roleHints) == 0 {
			b.c.Roles = append(b.c.Roles, "unknown_endpoint")
		}
		if b.c.Score < 0 {
			b.c.Score = 0
		}
		b.c.Roles = uniqueSorted(b.c.Roles)
		b.c.ContradictingEvidence = uniqueSorted(b.c.ContradictingEvidence)
		switch {
		case b.c.Score >= 70 && independent >= 3:
			b.c.Confidence = "high"
		case b.c.Score >= 45 && independent >= 2:
			b.c.Confidence = "medium"
		default:
			b.c.Confidence = "low"
		}
		if independent < 2 {
			b.c.Warnings = append(b.c.Warnings, "independent endpoint evidence is insufficient for strong attribution")
		}
		r.Endpoints = append(r.Endpoints, b.c)
	}
	sort.Slice(r.Endpoints, func(i, j int) bool {
		if r.Endpoints[i].Score != r.Endpoints[j].Score {
			return r.Endpoints[i].Score > r.Endpoints[j].Score
		}
		return r.Endpoints[i].ID < r.Endpoints[j].ID
	})
	sort.Slice(r.Edges, func(i, j int) bool { return r.Edges[i].ID < r.Edges[j].ID })
	r.EndpointClassification = classifyEndpoints(r.Endpoints)
	r.TLSLinks = linkTLSFlows(c.Flows, r.Endpoints, trigger, w)
	r.FlowClassification = classifyEndpointFlows(r.TLSLinks, r.EndpointClassification)
	r.Findings = endpointFindings(r)
	r.Capabilities = []string{"offline_dns_evidence_available", "endpoint_evidence_graph_available", "management_point_attribution_available", "tls_endpoint_flow_correlation_available", "live_policy_collection_blocked"}
	return r, nil
}

func addSource(c *EndpointCandidate, source, ref string) {
	c.SourceTypes = append(c.SourceTypes, source)
	c.EvidenceRefs = append(c.EvidenceRefs, ref)
}
func updateSeen(c *EndpointCandidate, at time.Time) {
	if at.IsZero() {
		return
	}
	at = at.UTC()
	if c.FirstSeen.IsZero() || at.Before(c.FirstSeen) {
		c.FirstSeen = at
	}
	if c.LastSeen.IsZero() || at.After(c.LastSeen) {
		c.LastSeen = at
	}
}
func newEndpointEdge(from, to, kind, ref string, at time.Time, confidence string) EndpointEdge {
	return EndpointEdge{ID: stableID("endpoint_edge", from, to, kind, ref), From: from, To: to, Kind: kind, EvidenceRef: ref, Timestamp: at.UTC(), TimestampRelationship: "capture_observed", Confidence: confidence}
}

func classifyEndpoints(xs []EndpointCandidate) string {
	var strong []EndpointCandidate
	for _, x := range xs {
		if containsString(x.Roles, "management_point_candidate") && (x.Confidence == "high" || x.Confidence == "medium") {
			strong = append(strong, x)
		}
	}
	if len(strong) > 1 {
		return "multiple_indistinguishable_endpoints"
	}
	if len(strong) == 1 {
		if strong[0].Confidence == "high" {
			return "high_confidence_management_point_endpoint"
		}
		return "medium_confidence_management_point_endpoint"
	}
	for _, x := range xs {
		if containsString(x.Roles, "management_point_candidate") {
			return "low_confidence_management_point_endpoint"
		}
	}
	if len(xs) == 0 {
		return "insufficient_endpoint_metadata"
	}
	return "no_management_point_endpoint_identified"
}

func linkTLSFlows(flows []Flow, endpoints []EndpointCandidate, trigger Trigger, w CorrelationWindow) []TLSEndpointLink {
	var out []TLSEndpointLink
	for _, f := range flows {
		if !f.TLS {
			continue
		}
		ports := []uint16{f.Client.Port, f.Server.Port}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		x := TLSEndpointLink{FlowID: f.ID, EndpointConfidence: "none", FlowConfidence: "low", PolicyEventConfidence: "low", ObservedPorts: ports, TLSVersion: f.TLSVersion, SNIPresent: f.SNI != "", ALPNPresent: f.ALPNFingerprint != ""}
		if f.Client.Port == 5985 || f.Client.Port == 5986 || f.Server.Port == 5985 || f.Server.Port == 5986 {
			x.ContradictingEvidence = append(x.ContradictingEvidence, "known WinRM control-channel port")
			x.Score -= 50
		}
		for _, ep := range endpoints {
			match := f.SNI != "" && f.SNI == ep.HostnameFingerprint
			for _, a := range ep.AddressFingerprints {
				if a == f.Client.AddressFingerprint || a == f.Server.AddressFingerprint {
					match = true
				}
			}
			if match && containsString(ep.Roles, "management_point_candidate") {
				x.EndpointCandidateID, x.EndpointConfidence = ep.ID, ep.Confidence
				x.Score += ep.Score / 2
				x.SupportingEvidence = append(x.SupportingEvidence, "flow destination matches independently attributed endpoint")
			}
		}
		d := f.StartedAt.Sub(trigger.Timestamp)
		if d >= -w.PreTrigger && d <= w.PostTrigger {
			x.Score += 10
			x.PolicyEventConfidence = "medium"
			x.SupportingEvidence = append(x.SupportingEvidence, "flow timing overlaps controlled policy window")
		}
		if x.Score < 0 {
			x.Score = 0
		}
		if x.Score > 100 {
			x.Score = 100
		}
		if x.EndpointConfidence == "high" && x.Score >= 45 {
			x.FlowConfidence = "high"
		} else if (x.EndpointConfidence == "high" || x.EndpointConfidence == "medium") && x.Score >= 30 {
			x.FlowConfidence = "medium"
		}
		if x.EndpointCandidateID == "" {
			x.SupportingEvidence = append(x.SupportingEvidence, "generic TLS timing/port evidence is non-specific")
		}
		x.SupportingEvidence = uniqueSorted(x.SupportingEvidence)
		x.ContradictingEvidence = uniqueSorted(x.ContradictingEvidence)
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].FlowID < out[j].FlowID
	})
	return out
}
func classifyEndpointFlows(xs []TLSEndpointLink, endpointClass string) string {
	if strings.HasPrefix(endpointClass, "no_") || endpointClass == "insufficient_endpoint_metadata" {
		return "no_correlatable_sccm_flow"
	}
	n := 0
	best := "low"
	for _, x := range xs {
		if x.EndpointCandidateID != "" {
			n++
			if x.FlowConfidence == "high" {
				best = "high"
			} else if x.FlowConfidence == "medium" && best != "high" {
				best = "medium"
			}
		}
	}
	if n == 0 {
		return "endpoint_identified_but_flow_ambiguous"
	}
	if n > 1 {
		return "endpoint_identified_but_flow_ambiguous"
	}
	return best + "_confidence_sccm_tls_flow"
}
func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
func endpointFindings(r EndpointCorrelationResult) []ResearchFinding {
	out := []ResearchFinding{}
	if len(r.DNS) > 0 {
		out = append(out, ResearchFinding{ID: "SCCM-DNS-EVIDENCE-OBSERVED", State: "observed", Description: "Bounded offline DNS evidence was present.", Vulnerability: false})
	}
	switch r.EndpointClassification {
	case "high_confidence_management_point_endpoint", "medium_confidence_management_point_endpoint", "low_confidence_management_point_endpoint":
		out = append(out, ResearchFinding{ID: "SCCM-MANAGEMENT-POINT-ENDPOINT-CANDIDATE", State: r.EndpointClassification, Description: "Passive evidence produced a management-point endpoint candidate.", Vulnerability: false})
	case "multiple_indistinguishable_endpoints":
		out = append(out, ResearchFinding{ID: "SCCM-ENDPOINT-ATTRIBUTION-AMBIGUOUS", State: "observed", Description: "Multiple endpoint candidates remain indistinguishable.", Vulnerability: false})
	default:
		out = append(out, ResearchFinding{ID: "SCCM-ENDPOINT-ATTRIBUTION-FAILED", State: r.EndpointClassification, Description: "Passive evidence did not identify a management-point endpoint.", Vulnerability: false})
	}
	if strings.Contains(r.FlowClassification, "sccm_tls_flow") {
		out = append(out, ResearchFinding{ID: "SCCM-TLS-FLOW-ENDPOINT-CORRELATED", State: r.FlowClassification, Description: "An opaque TLS flow was linked to attributed endpoint evidence.", Vulnerability: false})
	}
	out = append(out, ResearchFinding{ID: "SCCM-POLICY-PAYLOAD-NOT-VISIBLE", State: "confirmed", Description: "Endpoint attribution does not reveal encrypted policy payloads.", Vulnerability: false})
	return out
}
