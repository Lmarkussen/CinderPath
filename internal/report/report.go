package report

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/temporal"
)

type Store interface {
	modules.QueryStore
	ListCredentials(context.Context) ([]models.Credential, error)
	ListModuleExecutions(context.Context) ([]models.ModuleExecution, error)
	ListRuns(context.Context) ([]models.Run, error)
	ListAuthenticationAttempts(context.Context) ([]models.AuthenticationAttempt, error)
}

type Metadata struct {
	GeneratedAt      time.Time   `json:"generated_at"`
	GeneratorVersion string      `json:"generator_version"`
	DatabasePath     string      `json:"database_path"`
	MockData         bool        `json:"mock_data"`
	LiveData         bool        `json:"live_data"`
	UserInputData    bool        `json:"user_input_data"`
	InferredData     bool        `json:"inferred_data"`
	ConfirmedData    bool        `json:"confirmed_data"`
	LatestRun        *models.Run `json:"latest_run,omitempty"`
}
type DiscoverySummary struct {
	InputScope           []string       `json:"input_scope"`
	Exclusions           []string       `json:"exclusions"`
	DNSResolved          int            `json:"dns_resolved"`
	DNSUnresolved        int            `json:"dns_unresolved"`
	ReachableSystems     int            `json:"reachable_systems"`
	OpenServicePorts     int            `json:"open_service_ports"`
	HTTPEndpoints        int            `json:"http_endpoints"`
	SCCMDirectoryObjects int            `json:"sccm_directory_objects"`
	LDAPEnvironment      map[string]any `json:"ldap_environment"`
	InferredRoles        map[string]int `json:"inferred_roles"`
}
type Summary struct {
	AssetCount         int                      `json:"asset_count"`
	FindingCount       int                      `json:"finding_count"`
	AttackPathCount    int                      `json:"attack_path_count"`
	AssetsByType       map[models.AssetKind]int `json:"assets_by_type"`
	FindingsBySeverity map[models.Severity]int  `json:"findings_by_severity"`
}
type JSONReport struct {
	Metadata                        Metadata                       `json:"metadata"`
	Summary                         Summary                        `json:"summary"`
	Assets                          []models.Asset                 `json:"assets"`
	Capabilities                    []models.Capability            `json:"capabilities"`
	Identities                      []models.Credential            `json:"identities"`
	NoRemoteAuthenticationStatement string                         `json:"remote_authentication_statement"`
	Findings                        []models.Finding               `json:"findings"`
	Relationships                   []models.Relationship          `json:"relationships"`
	AttackPaths                     []models.AttackPath            `json:"attack_paths"`
	ModuleExecutions                []models.ModuleExecution       `json:"module_executions"`
	Evidence                        []models.Evidence              `json:"evidence"`
	Discovery                       DiscoverySummary               `json:"discovery"`
	SCCMEndpoints                   []SCCMEndpointValidation       `json:"sccm_endpoint_validation"`
	SCCMTopology                    []SCCMTopologyHost             `json:"sccm_topology"`
	AuthenticationAttempts          []models.AuthenticationAttempt `json:"authentication_validation"`
	Temporal                        temporal.Result                `json:"temporal_correlation"`
}

type SCCMTopologyHost struct {
	AssetID              string                        `json:"asset_id"`
	CanonicalIdentity    string                        `json:"canonical_host_identity"`
	Aliases              []string                      `json:"aliases"`
	ResolvedAddresses    []string                      `json:"resolved_addresses"`
	Roles                []string                      `json:"sccm_roles"`
	SiteCodes            []string                      `json:"site_codes"`
	RoleConfidence       string                        `json:"role_confidence"`
	ProtocolValidated    bool                          `json:"protocol_validated"`
	LDAPReferences       []string                      `json:"ldap_references"`
	TLSNames             []string                      `json:"tls_names"`
	MPListReferences     []string                      `json:"mp_list_references"`
	IdentityConflicts    []map[string]any              `json:"identity_conflicts"`
	UnresolvedReferences []map[string]any              `json:"unresolved_references"`
	Version              models.SCCMVersionObservation `json:"version"`
}

type SCCMEndpointValidation struct {
	AssetID                 string   `json:"asset_id"`
	Host                    string   `json:"host"`
	Origin                  string   `json:"origin"`
	Route                   string   `json:"route"`
	Method                  string   `json:"method"`
	StatusCode              int      `json:"status_code,omitempty"`
	AuthenticationSchemes   []string `json:"authentication_schemes"`
	ParserResult            string   `json:"parser_result"`
	Classification          string   `json:"classification"`
	Confidence              string   `json:"confidence"`
	SupportingEvidence      []string `json:"supporting_evidence"`
	WhatRemainsUnverified   string   `json:"what_remains_unverified"`
	TransportReachable      bool     `json:"transport_reachable"`
	HTTPResponseReceived    bool     `json:"http_response_received"`
	AnonymousRequest        bool     `json:"anonymous_request"`
	AuthenticationRequested bool     `json:"authentication_requested"`
	AuthenticationAttempted bool     `json:"authentication_attempted"`
	Authenticated           bool     `json:"authenticated"`
	UsableReadAccess        bool     `json:"usable_read_access"`
	ProtocolValidated       bool     `json:"protocol_validated"`
	InferredRole            string   `json:"inferred_role"`
	ConfirmedConclusion     bool     `json:"confirmed_conclusion"`
}
type Paths struct {
	JSON string
	HTML string
}

func Generate(ctx context.Context, store Store, outputDir, dbPath, version string, latest *models.Run, thresholds ...config.StalenessConfig) (Paths, error) {
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return Paths{}, fmt.Errorf("create report directory: %w", err)
	}
	assets, err := store.ListAssets(ctx)
	if err != nil {
		return Paths{}, err
	}
	caps, err := store.ListCapabilities(ctx)
	if err != nil {
		return Paths{}, err
	}
	findings, err := store.ListFindings(ctx)
	if err != nil {
		return Paths{}, err
	}
	rels, err := store.ListRelationships(ctx)
	if err != nil {
		return Paths{}, err
	}
	paths, err := store.ListAttackPaths(ctx)
	if err != nil {
		return Paths{}, err
	}
	execs, err := store.ListModuleExecutions(ctx)
	if err != nil {
		return Paths{}, err
	}
	evidence, err := store.ListEvidence(ctx)
	if err != nil {
		return Paths{}, err
	}
	mock, liveData, userInput, inferred, confirmed := false, false, false, false, false
	for _, a := range assets {
		if strings.EqualFold(a.Properties["mock"], "true") {
			mock = true
		}
		origin := a.Properties["observation_origin"]
		liveData = liveData || origin == "live"
		userInput = userInput || origin == "user_input"
		userInput = userInput || a.Properties["has_user_hint"] == "true"
		inferred = inferred || a.Properties["role_inference_origin"] == "inferred"
		confirmed = confirmed || a.Properties["conclusion_origin"] == "confirmed"
	}
	for _, e := range evidence {
		origin := fmt.Sprint(e.Data["origin"])
		userInput = userInput || origin == "user_input"
		inferred = inferred || origin == "inferred_conclusion"
		liveData = liveData || strings.HasPrefix(e.SourceModule, "live.")
	}
	summary := Summary{AssetCount: len(assets), FindingCount: len(findings), AttackPathCount: len(paths), AssetsByType: map[models.AssetKind]int{}, FindingsBySeverity: map[models.Severity]int{}}
	for _, a := range assets {
		summary.AssetsByType[a.Kind]++
	}
	for _, f := range findings {
		summary.FindingsBySeverity[f.Severity]++
	}
	endpoints := buildSCCMEndpointValidations(evidence)
	for _, endpoint := range endpoints {
		confirmed = confirmed || endpoint.ConfirmedConclusion
		inferred = inferred || endpoint.InferredRole != ""
	}
	credentials, _ := store.ListCredentials(ctx)
	attempts, _ := store.ListAuthenticationAttempts(ctx)
	runs, _ := store.ListRuns(ctx)
	assetDays, evidenceDays := 30, 30
	if len(thresholds) > 0 {
		assetDays = thresholds[0].AssetDays
		evidenceDays = thresholds[0].EvidenceDays
	}
	temporalResult := temporal.Analyze(temporal.Input{Runs: runs, Assets: assets, Evidence: evidence, Executions: execs, Now: time.Now().UTC(), AssetDays: assetDays, EvidenceDays: evidenceDays})
	attempted := false
	for _, a := range attempts {
		attempted = attempted || a.Attempted
	}
	statement := "No remote authentication was attempted during this phase."
	if attempted {
		statement = "Authentication validation was performed. Results are exact identity-, endpoint-, route-, and method-specific."
	}
	r := JSONReport{Metadata: Metadata{GeneratedAt: time.Now().UTC(), GeneratorVersion: version, DatabasePath: dbPath, MockData: mock, LiveData: liveData, UserInputData: userInput, InferredData: inferred, ConfirmedData: confirmed, LatestRun: latest}, Summary: summary, Assets: nonNil(assets), Capabilities: nonNil(caps), Identities: nonNil(credentials), NoRemoteAuthenticationStatement: statement, Findings: nonNil(findings), Relationships: nonNil(rels), AttackPaths: nonNil(paths), ModuleExecutions: nonNil(execs), Evidence: nonNil(evidence), Discovery: buildDiscoverySummary(assets, evidence), SCCMEndpoints: nonNil(endpoints), SCCMTopology: buildSCCMTopology(evidence), AuthenticationAttempts: nonNil(attempts), Temporal: temporalResult}
	jp := filepath.Join(outputDir, "cinderpath-report.json")
	hp := filepath.Join(outputDir, "cinderpath-report.html")
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Paths{}, err
	}
	if err := os.WriteFile(jp, append(b, '\n'), 0o640); err != nil {
		return Paths{}, fmt.Errorf("write JSON report: %w", err)
	}
	view := htmlView{Report: r, Evidence: makeEvidenceViews(evidence), SeverityOrder: []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInformational}}
	f, err := os.OpenFile(hp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return Paths{}, err
	}
	defer f.Close()
	if err := htmlTemplate.Execute(f, view); err != nil {
		return Paths{}, fmt.Errorf("render HTML report: %w", err)
	}
	return Paths{JSON: jp, HTML: hp}, nil
}

func buildSCCMTopology(evidence []models.Evidence) []SCCMTopologyHost {
	var unresolved []map[string]any
	for _, e := range evidence {
		if e.Type == "unresolved_directory_reference" || e.Type == "unmatched_mp_list_reference" {
			unresolved = append(unresolved, e.Data)
		}
	}
	var out []SCCMTopologyHost
	for _, e := range evidence {
		if e.Type != "sccm_topology_correlation" {
			continue
		}
		v := models.SCCMVersionObservation{Product: "Microsoft Configuration Manager", Value: "unknown", State: "unknown", Confidence: models.ConfidenceLow, SupportingEvidence: []string{}, Unverified: "No reliable protocol-specific SCCM product version field was collected."}
		if raw, ok := e.Data["version"]; ok {
			if b, err := json.Marshal(raw); err == nil {
				_ = json.Unmarshal(b, &v)
			}
		}
		conflicts := []map[string]any{}
		if raw, ok := e.Data["identity_conflicts"]; ok {
			if b, err := json.Marshal(raw); err == nil {
				_ = json.Unmarshal(b, &conflicts)
			}
		}
		out = append(out, SCCMTopologyHost{AssetID: e.AssetID, CanonicalIdentity: fmt.Sprint(e.Data["canonical_host_identity"]), Aliases: anyStrings(e.Data["aliases"]), ResolvedAddresses: anyStrings(e.Data["resolved_addresses"]), Roles: anyStrings(e.Data["sccm_roles"]), SiteCodes: anyStrings(e.Data["site_codes"]), RoleConfidence: fmt.Sprint(e.Data["role_confidence"]), ProtocolValidated: reportBool(e.Data["protocol_validated"]), LDAPReferences: anyStrings(e.Data["ldap_references"]), TLSNames: anyStrings(e.Data["tls_names"]), MPListReferences: anyStrings(e.Data["mp_list_references"]), IdentityConflicts: conflicts, UnresolvedReferences: unresolved, Version: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CanonicalIdentity < out[j].CanonicalIdentity })
	return nonNil(out)
}

func buildSCCMEndpointValidations(evidence []models.Evidence) []SCCMEndpointValidation {
	classifications := map[string]models.Evidence{}
	for _, item := range evidence {
		switch item.Type {
		case "sccm_mp_protocol":
			for _, evidenceID := range anyStrings(item.Data["supporting_evidence"]) {
				classifications[evidenceID] = item
			}
		case "sccm_dp_virtual_directory":
			for _, evidenceID := range anyStrings(item.Data["supporting_evidence"]) {
				classifications[evidenceID] = item
			}
		}
	}
	var out []SCCMEndpointValidation
	for _, item := range evidence {
		if item.Type != "sccm_http_route" {
			continue
		}
		routeID := fmt.Sprint(item.Data["route_id"])
		origin := fmt.Sprint(item.Data["origin"])
		state, _ := item.Data["access_state"].(map[string]any)
		validation := SCCMEndpointValidation{
			AssetID: item.AssetID, Host: fmt.Sprint(item.Data["host"]), Origin: origin, Route: fmt.Sprint(item.Data["path"]), Method: fmt.Sprint(item.Data["method"]),
			StatusCode: reportInt(item.Data["status_code"]), AuthenticationSchemes: anyStrings(item.Data["authentication_schemes"]), ParserResult: fmt.Sprint(item.Data["parser_outcome"]),
			Classification: "unverified", Confidence: "unverified", SupportingEvidence: []string{item.ID}, WhatRemainsUnverified: fmt.Sprint(item.Data["unverified_reason"]),
			TransportReachable: reportBool(state["transport_reachable"]), HTTPResponseReceived: reportBool(state["http_response_received"]), AnonymousRequest: reportBool(state["anonymous_request"]),
			AuthenticationRequested: reportBool(state["authentication_requested"]), AuthenticationAttempted: reportBool(state["authentication_attempted"]), Authenticated: reportBool(state["authenticated"]),
			UsableReadAccess: reportBool(state["usable_read_access"]), ProtocolValidated: reportBool(state["protocol_validated"]),
		}
		if classified, ok := classifications[item.ID]; ok {
			validation.Classification = fmt.Sprint(classified.Data["classification"])
			validation.Confidence = fmt.Sprint(classified.Data["confidence"])
			validation.SupportingEvidence = append(validation.SupportingEvidence, classified.ID)
			validation.SupportingEvidence = append(validation.SupportingEvidence, anyStrings(classified.Data["supporting_evidence"])...)
			validation.WhatRemainsUnverified = fmt.Sprint(classified.Data["what_remains_unverified"])
		}
		if routeID == "mp_list" && (validation.Classification == "protocol_validated_management_point" || validation.Classification == "likely_management_point_authentication_required") {
			validation.InferredRole = "management_point"
		}
		if strings.HasPrefix(routeID, "dp_") && validation.Classification == "likely_distribution_point" {
			validation.InferredRole = "distribution_point"
		}
		validation.ConfirmedConclusion = validation.ProtocolValidated && validation.Classification == "protocol_validated_management_point"
		validation.SupportingEvidence = uniqueSorted(validation.SupportingEvidence)
		out = append(out, validation)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AssetID != out[j].AssetID {
			return out[i].AssetID < out[j].AssetID
		}
		if out[i].Origin != out[j].Origin {
			return out[i].Origin < out[j].Origin
		}
		return out[i].Route < out[j].Route
	})
	return out
}

func reportBool(value any) bool {
	valueText := strings.TrimSpace(fmt.Sprint(value))
	return strings.EqualFold(valueText, "true")
}

func reportInt(value any) int {
	var out int
	_, _ = fmt.Sscan(fmt.Sprint(value), &out)
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func buildDiscoverySummary(assets []models.Asset, evidence []models.Evidence) DiscoverySummary {
	d := DiscoverySummary{InputScope: []string{}, Exclusions: []string{}, LDAPEnvironment: map[string]any{}, InferredRoles: map[string]int{}}
	for _, a := range assets {
		if a.Properties["normalized_target"] != "" {
			d.InputScope = append(d.InputScope, a.Properties["normalized_target"])
		}
		if a.Properties["reachable"] == "true" {
			d.ReachableSystems++
		}
		if ports := a.Properties["open_ports"]; ports != "" {
			d.OpenServicePorts += len(strings.Split(ports, ","))
		}
		if endpoints := a.Properties["http_endpoints"]; endpoints != "" {
			d.HTTPEndpoints += len(strings.Split(endpoints, ","))
		}
		if a.Properties["role_inference_origin"] == "inferred" {
			for _, r := range a.Roles {
				d.InferredRoles[r]++
			}
		}
	}
	for _, e := range evidence {
		switch e.Type {
		case "scope_decision":
			d.Exclusions = anyStrings(e.Data["excluded"])
		case "dns_resolution":
			if len(anyStrings(e.Data["answers"])) > 0 {
				d.DNSResolved++
			} else {
				d.DNSUnresolved++
			}
		case "ldap_rootdse":
			d.LDAPEnvironment = e.Data
		case "ldap_sccm_object":
			d.SCCMDirectoryObjects++
		}
	}
	sort.Strings(d.InputScope)
	return d
}
func anyStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		out := make([]string, 0, len(x))
		for _, v := range x {
			out = append(out, fmt.Sprint(v))
		}
		return out
	}
	return []string{}
}

func nonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}

type evidenceView struct{ ID, Title, Summary, Data string }

func makeEvidenceViews(items []models.Evidence) []evidenceView {
	out := make([]evidenceView, 0, len(items))
	for _, e := range items {
		b, _ := json.Marshal(e.Data)
		data := string(b)
		if len(data) > 1000 {
			data = data[:1000] + "… [truncated]"
		}
		out = append(out, evidenceView{e.ID, e.Title, e.Summary, data})
	}
	return out
}

type htmlView struct {
	Report        JSONReport
	Evidence      []evidenceView
	SeverityOrder []models.Severity
}

func (v htmlView) FindingsFor(s models.Severity) []models.Finding {
	var out []models.Finding
	for _, f := range v.Report.Findings {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}
func (v htmlView) SortedAssetKinds() []models.AssetKind {
	var out []models.AssetKind
	for k := range v.Report.Summary.AssetsByType {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"upper": strings.ToUpper}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CinderPath Assessment Report</title>
<style>:root{--bg:#0c111b;--panel:#151d2b;--text:#e8edf5;--muted:#9ba9bd;--accent:#ff7733;--border:#2b3749}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:2rem}.hero{border-left:5px solid var(--accent);padding-left:1rem}.banner{background:#5b2d09;border:1px solid #ff9b59;padding:1rem;margin:1rem 0;font-weight:700}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}.card,section{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem;margin:1rem 0}.metric{font-size:2rem;font-weight:700}.muted{color:var(--muted)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.55rem;border-bottom:1px solid var(--border);vertical-align:top}.sev-critical{color:#ff4d6d}.sev-high{color:#ff7733}.sev-medium{color:#ffc857}.sev-low{color:#72a7ff}.sev-informational{color:#9ba9bd}code{overflow-wrap:anywhere}details{margin:.5rem 0}h1,h2,h3{line-height:1.2}footer{color:var(--muted);margin-top:2rem}</style></head><body><main>
<header class="hero"><h1>CinderPath Assessment Report</h1><div class="muted">Generated {{.Report.Metadata.GeneratedAt}} · Version {{.Report.Metadata.GeneratorVersion}}</div></header>
{{if .Report.Metadata.MockData}}<div class="banner">MOCK DATA — This report contains only synthetic demonstration data. It is not evidence from a live SCCM environment.</div>{{end}}
{{if .Report.Metadata.LiveData}}<div class="banner" style="background:#123a2d;border-color:#38c98b">LIVE OBSERVATIONS — Safe, read-only metadata from explicitly scoped targets. Inferred roles remain unconfirmed unless stated otherwise.</div>{{end}}
<div class="banner" style="background:#123a2d;border-color:#38c98b">{{.Report.NoRemoteAuthenticationStatement}}</div>
<section><h2>Executive summary</h2><div class="grid"><div class="card"><div class="metric">{{.Report.Summary.AssetCount}}</div>Assets</div><div class="card"><div class="metric">{{.Report.Summary.FindingCount}}</div>Findings</div><div class="card"><div class="metric">{{.Report.Summary.AttackPathCount}}</div>Attack paths</div></div></section>
<section><h2>Run metadata</h2>{{with .Report.Metadata.LatestRun}}<table><tr><th>Run ID</th><td><code>{{.ID}}</code></td></tr><tr><th>Command</th><td>{{.Command}}</td></tr><tr><th>Profile</th><td>{{.Profile}}</td></tr><tr><th>Status</th><td>{{.Status}}</td></tr><tr><th>Started</th><td>{{.StartedAt}}</td></tr></table>{{end}}</section>
<section><h2>Discovery summary</h2><div class="grid"><div class="card"><div class="metric">{{len .Report.Discovery.InputScope}}</div>Scoped targets</div><div class="card"><div class="metric">{{.Report.Discovery.DNSResolved}}</div>DNS resolved</div><div class="card"><div class="metric">{{.Report.Discovery.ReachableSystems}}</div>Reachable systems</div><div class="card"><div class="metric">{{.Report.Discovery.OpenServicePorts}}</div>Open ports</div><div class="card"><div class="metric">{{.Report.Discovery.HTTPEndpoints}}</div>HTTP endpoints</div><div class="card"><div class="metric">{{.Report.Discovery.SCCMDirectoryObjects}}</div>SCCM directory objects</div></div><details><summary>Scope and exclusions</summary><p><strong>Scope:</strong> {{range .Report.Discovery.InputScope}}<code>{{.}} </code>{{end}}</p><p><strong>Excluded:</strong> {{range .Report.Discovery.Exclusions}}<code>{{.}} </code>{{end}}</p></details><h3>Inferred roles</h3><table><tr><th>Role</th><th>Count</th></tr>{{range $role,$count := .Report.Discovery.InferredRoles}}<tr><td>{{$role}}</td><td>{{$count}}</td></tr>{{end}}</table></section>
<section><h2>Assets and topology</h2><div class="grid">{{range .SortedAssetKinds}}<div class="card"><strong>{{.}}</strong><div class="metric">{{index $.Report.Summary.AssetsByType .}}</div></div>{{end}}</div><table><tr><th>From</th><th>Relationship</th><th>To</th><th>Confidence</th></tr>{{range .Report.Relationships}}<tr><td><code>{{.FromID}}</code></td><td>{{.Type}}</td><td><code>{{.ToID}}</code></td><td>{{.Confidence}}</td></tr>{{end}}</table></section>
<section><h2>SCCM topology correlation</h2><p class="muted">Passive correlation only; uncertain identities remain distinct. Product versions require reliable protocol-specific evidence.</p>{{range .Report.SCCMTopology}}<article class="card"><h3>{{.CanonicalIdentity}}</h3><p><strong>SCCM version:</strong> {{.Version.Value}} · <strong>Roles:</strong> {{range .Roles}}<code>{{.}} </code>{{else}}none{{end}} · Confidence: {{.RoleConfidence}} · Protocol validated: {{.ProtocolValidated}}</p><p><strong>Aliases:</strong> {{range .Aliases}}<code>{{.}} </code>{{else}}none{{end}}<br><strong>Addresses:</strong> {{range .ResolvedAddresses}}<code>{{.}} </code>{{else}}none{{end}}<br><strong>Site codes:</strong> {{range .SiteCodes}}<code>{{.}} </code>{{else}}none{{end}}</p><details><summary>Directory, certificate, and MP-list references</summary><p>LDAP: {{range .LDAPReferences}}<code>{{.}} </code>{{else}}none{{end}}<br>TLS: {{range .TLSNames}}<code>{{.}} </code>{{else}}none{{end}}<br>MP list: {{range .MPListReferences}}<code>{{.}} </code>{{else}}none{{end}}</p></details>{{range .IdentityConflicts}}<p class="sev-informational"><strong>Identity conflict:</strong> {{index . "type"}} — {{index . "why_it_matters"}} <span class="muted">{{index . "what_remains_unverified"}}</span></p>{{end}}<p class="muted">{{.Version.Unverified}}</p></article>{{else}}<p class="muted">No passive SCCM topology correlation is stored.</p>{{end}}</section>
<section><h2>Capabilities</h2><table><tr><th>Name</th><th>Available</th><th>Reason</th><th>Source</th></tr>{{range .Report.Capabilities}}<tr><td>{{.Name}}</td><td>{{.Available}}</td><td>{{.Reason}}</td><td>{{.Source}}</td></tr>{{end}}</table></section>
<section><h2>Identity and authentication capability model</h2><p class="muted">References and certificate metadata are validated locally only. Paths are redacted. Any remote result is exact identity-, endpoint-, route-, and method-specific below.</p><table><tr><th>Identity</th><th>Kind</th><th>Reference</th><th>Local validation</th><th>Remote authentication</th></tr>{{range .Report.Identities}}<tr><td>{{if .Principal}}{{.Principal}}{{else}}{{.Domain}}\{{.Username}}{{end}}</td><td>{{.Kind}}</td><td>{{.RedactedReference}}</td><td>{{.Validated}} — {{.ValidationReason}}</td><td>See exact validation results; no global state is inferred.</td></tr>{{else}}<tr><td colspan="5">No modeled identities.</td></tr>{{end}}</table></section>
<section><h2>Authentication validation</h2><p class="muted">Potential authentication remains distinct from attempted, validated, rejected, and inconclusive authentication.</p><table><tr><th>Identity</th><th>Endpoint / route</th><th>Method</th><th>Result</th><th>Budget / safety</th><th>Uncertainty</th></tr>{{range .Report.AuthenticationAttempts}}<tr><td><code>{{.IdentityID}}</code></td><td>{{.Origin}}<br><code>{{.Method}} {{.Route}}</code></td><td>{{.AuthenticationMethod}}</td><td>{{.Status}}<br>Attempted: {{.Attempted}}<br>Status: {{.StatusCode}}<br>{{.FailureCategory}}</td><td>Cost: {{.BudgetCost}}<br>Previous: {{.PreviousAttempts}}<br>Acknowledged: {{.SafetyAcknowledged}}<br>Freshness: {{.EvidenceFreshness}}</td><td>{{.Reason}}<br><span class="muted">{{.RemainingUncertainty}}</span></td></tr>{{else}}<tr><td colspan="6">No authentication validation results.</td></tr>{{end}}</table></section>
<section><h2>Temporal correlation</h2><table><tr><th>Type</th><th>State</th><th>Asset / endpoint</th><th>Reason</th></tr>{{range .Report.Temporal.Observations}}<tr><td>{{.Type}}</td><td>{{.State}}</td><td><code>{{.AssetID}}</code><br>{{.Endpoint}}</td><td>{{.Reason}}</td></tr>{{else}}<tr><td colspan="4">No run-aware temporal observations.</td></tr>{{end}}</table></section>
<section><h2>SCCM endpoint validation</h2><p class="muted">All requests were anonymous and read-only. Authentication requested is distinct from authentication attempted or authenticated. Distribution-point HEAD responses never establish usable content access.</p><table><tr><th>Host / origin</th><th>Route</th><th>Status</th><th>Access state</th><th>Parser / classification</th><th>Conclusion</th></tr>{{range .Report.SCCMEndpoints}}<tr><td><code>{{.Host}}</code><br>{{.Origin}}</td><td><code>{{.Method}} {{.Route}}</code><br>Auth schemes: {{range .AuthenticationSchemes}}<code>{{.}} </code>{{else}}none{{end}}</td><td>{{.StatusCode}}</td><td>Transport reachable: {{.TransportReachable}}<br>HTTP response: {{.HTTPResponseReceived}}<br>Anonymous request: {{.AnonymousRequest}}<br>Authentication required: {{.AuthenticationRequested}}<br>Authentication attempted: {{.AuthenticationAttempted}}<br>Authenticated: {{.Authenticated}}<br>Usable read access: {{.UsableReadAccess}}<br>Protocol validated: {{.ProtocolValidated}}</td><td>Parser: {{.ParserResult}}<br>Classification: {{.Classification}}<br>Confidence: {{.Confidence}}<br>Role: {{if .InferredRole}}{{.InferredRole}}{{else}}none{{end}}</td><td>{{if .ConfirmedConclusion}}validated protocol conclusion{{else}}unconfirmed{{end}}<br><span class="muted">{{.WhatRemainsUnverified}}</span><br>Evidence: {{range .SupportingEvidence}}<code>{{.}} </code>{{end}}</td></tr>{{else}}<tr><td colspan="6" class="muted">No SCCM endpoint-validation observations are stored.</td></tr>{{end}}</table></section>
<section><h2>Findings by severity</h2>{{range .SeverityOrder}}{{$items := $.FindingsFor .}}{{if $items}}<h3 class="sev-{{.}}">{{upper (printf "%s" .)}} ({{len $items}})</h3>{{range $items}}<article class="card"><strong>{{.Title}}</strong><p>{{.Summary}}</p><p class="muted">Confidence: {{.Confidence}} · Rule: {{.RuleID}} · Evidence: {{range .EvidenceIDs}}<code>{{.}} </code>{{end}}</p><details><summary>Details and remediation</summary><p>{{.Description}}</p><p><strong>Remediation:</strong> {{.Remediation}}</p></details></article>{{end}}{{end}}{{end}}</section>
<section><h2>Attack paths</h2>{{range .Report.AttackPaths}}<article class="card"><h3>{{.Title}}</h3><p>{{.Summary}}</p><p class="sev-{{.Severity}}">Severity: {{.Severity}} · Confidence: {{.Confidence}}</p><ol>{{range .Steps}}<li><code>{{.FromID}}</code> — <strong>{{.RelationshipType}}</strong> → <code>{{.ToID}}</code><br><span class="muted">{{.Description}}</span></li>{{end}}</ol></article>{{else}}<p class="muted">No attack paths were generated.</p>{{end}}</section>
<section><h2>Evidence references</h2><p class="muted">Evidence data is bounded to 1,000 characters per record in this portable report.</p>{{range .Evidence}}<details><summary><code>{{.ID}}</code> — {{.Title}}</summary><p>{{.Summary}}</p><code>{{.Data}}</code></details>{{end}}</section>
<section><h2>Module execution summary</h2><table><tr><th>Module</th><th>Asset</th><th>Status</th><th>Skip/error</th></tr>{{range .Report.ModuleExecutions}}<tr><td>{{.ModuleName}}</td><td><code>{{.AssetID}}</code></td><td>{{.Status}}</td><td>{{if .SkipReason}}{{.SkipReason}}{{else}}{{.Error}}{{end}}</td></tr>{{end}}</table></section>
<footer>CinderPath · Authorized security assessments and controlled labs only.</footer></main></body></html>`))
