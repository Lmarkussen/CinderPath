package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestSCCMEndpointValidationReportsAccessStates(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := database.Open(ctx, filepath.Join(dir, "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: "mp01.lab.local", Hostname: "mp01", Domain: "lab.local", Properties: map[string]string{"observation_origin": "live", "normalized_target": "mp01.lab.local"}, Source: "test", Confidence: models.ConfidenceHigh}
	asset.Prepare(time.Now())
	if _, err := store.UpsertAsset(ctx, &asset); err != nil {
		t.Fatal(err)
	}
	route := models.Evidence{Type: "sccm_http_route", Title: "GET MP list", Summary: "fixture", SourceModule: "live.sccm.http_routes", AssetID: asset.ID, Sensitivity: models.SensitivityInternal, Data: map[string]any{
		"origin": "https://mp01.lab.local:443", "host": "mp01.lab.local", "route_id": "mp_list", "path": "/SMS_MP/.sms_aut?MPLIST", "method": "GET", "status_code": 200,
		"authentication_schemes": []string{}, "parser_outcome": "valid_sccm_mp_list", "unverified_reason": "authentication and policy access were not tested",
		"access_state": map[string]any{"transport_reachable": true, "http_response_received": true, "anonymous_request": true, "authentication_requested": false, "authentication_attempted": false, "authenticated": false, "usable_read_access": true, "protocol_validated": true},
	}}
	route.Prepare(time.Now())
	if _, err := store.UpsertEvidence(ctx, &route); err != nil {
		t.Fatal(err)
	}
	protocol := models.Evidence{Type: "sccm_mp_protocol", Title: "MP protocol", Summary: "fixture", SourceModule: "live.sccm.management_point", AssetID: asset.ID, Sensitivity: models.SensitivityInternal, Data: map[string]any{
		"origin": "https://mp01.lab.local:443", "route_id": "mp_list", "classification": "protocol_validated_management_point", "confidence": "high", "supporting_evidence": []string{route.ID}, "what_remains_unverified": "authentication and policy access were not tested",
	}}
	protocol.Prepare(time.Now())
	if _, err := store.UpsertEvidence(ctx, &protocol); err != nil {
		t.Fatal(err)
	}
	paths, err := Generate(ctx, store, filepath.Join(dir, "reports"), store.Path(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.SCCMEndpoints) != 1 {
		t.Fatalf("endpoints=%+v", report.SCCMEndpoints)
	}
	endpoint := report.SCCMEndpoints[0]
	if !endpoint.TransportReachable || !endpoint.HTTPResponseReceived || !endpoint.AnonymousRequest || endpoint.AuthenticationRequested || endpoint.AuthenticationAttempted || endpoint.Authenticated || !endpoint.UsableReadAccess || !endpoint.ProtocolValidated || !endpoint.ConfirmedConclusion {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	html, err := os.ReadFile(paths.HTML)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"SCCM endpoint validation", "Authentication attempted: false", "Authenticated: false", "Usable read access: true", "Protocol validated: true"} {
		if !strings.Contains(string(html), label) {
			t.Fatalf("HTML report missing %q", label)
		}
	}
	if strings.Contains(strings.ToLower(string(data)), "cookie") || strings.Contains(strings.ToLower(string(data)), "authorization") {
		t.Fatal("report contains forbidden cookie or authorization material")
	}
}

func TestSCCMTopologyReportRendersExplicitUnknownVersion(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := database.Open(ctx, filepath.Join(dir, "topology.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	asset := models.Asset{Kind: models.AssetUnknown, FQDN: "mp01.lab.local", Hostname: "mp01", Properties: map[string]string{"observation_origin": "live"}, Source: "test", Confidence: models.ConfidenceHigh}
	asset.Prepare(time.Now())
	if _, err := store.UpsertAsset(ctx, &asset); err != nil {
		t.Fatal(err)
	}
	e := models.Evidence{Type: "sccm_topology_correlation", Title: "topology", Summary: "fixture", SourceModule: "live.sccm.correlate", AssetID: asset.ID, Sensitivity: models.SensitivityInternal, Data: map[string]any{"canonical_host_identity": "mp01.lab.local", "aliases": []string{"mp01", "mp01.lab.local"}, "resolved_addresses": []string{"192.0.2.10"}, "sccm_roles": []string{"management_point"}, "site_codes": []string{"LAB"}, "role_confidence": "high", "protocol_validated": true, "ldap_references": []string{"mp01.lab.local"}, "tls_names": []string{"mp01.lab.local"}, "mp_list_references": []string{"mp01.lab.local"}, "identity_conflicts": []map[string]any{}, "version": models.SCCMVersionObservation{Product: "Microsoft Configuration Manager", Value: "unknown", State: "unknown", Reliable: false, Confidence: models.ConfidenceLow, SupportingEvidence: []string{}, Unverified: "No reliable protocol-specific SCCM product version field was collected."}}}
	e.Prepare(time.Now())
	if _, err := store.UpsertEvidence(ctx, &e); err != nil {
		t.Fatal(err)
	}
	paths, err := Generate(ctx, store, filepath.Join(dir, "reports"), store.Path(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	var got JSONReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.SCCMTopology) != 1 || got.SCCMTopology[0].Version.Value != "unknown" || got.SCCMTopology[0].Version.Reliable {
		t.Fatalf("topology=%+v", got.SCCMTopology)
	}
	html, err := os.ReadFile(paths.HTML)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "SCCM version:</strong> unknown") {
		t.Fatal("HTML does not explicitly render unknown SCCM version")
	}
}

func TestAuthenticationReportDistinguishesAttemptAndDoesNotLeakSecret(t *testing.T) {
	const secret = "REPORT_AUTH_SENTINEL_52c9"
	ctx := context.Background()
	dir := t.TempDir()
	store, err := database.Open(ctx, filepath.Join(dir, "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	asset := models.Asset{Kind: models.AssetManagementPoint, FQDN: "mp.lab", Source: "test", Properties: map[string]string{"observation_origin": "live"}}
	if _, err := store.UpsertAsset(ctx, &asset); err != nil {
		t.Fatal(err)
	}
	cred := models.Credential{Kind: models.CredentialPasswordRef, Type: models.CredentialPasswordRef, Username: "alice", Domain: "LAB", Source: "test", SecretReference: "env:REPORT_PASSWORD", RedactedReference: "env:REPORT_PASSWORD"}
	if _, err := store.UpsertCredential(ctx, &cred); err != nil {
		t.Fatal(err)
	}
	run, err := store.CreateRun(ctx, "auth validate", "safe", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	attempt := models.AuthenticationAttempt{ID: "auth_result", RunID: run.ID, IdentityID: cred.ID, AssetID: asset.ID, Origin: "https://mp.lab", Route: "/SMS_MP/.sms_aut?MPLIST", Method: "GET", AuthenticationMethod: "basic", StartedAt: now, Status: models.AuthRejected, Attempted: true, Rejected: true, StatusCode: 401, FailureCategory: "invalid_credentials", Reason: "endpoint returned 401", BudgetCost: 1, SafetyAcknowledged: true, EvidenceFreshness: models.TemporalCurrent}
	if err := store.SaveAuthenticationAttempt(ctx, &attempt); err != nil {
		t.Fatal(err)
	}
	paths, err := Generate(ctx, store, filepath.Join(dir, "reports"), store.Path(), "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	jsonRaw, _ := os.ReadFile(paths.JSON)
	htmlRaw, _ := os.ReadFile(paths.HTML)
	combined := string(jsonRaw) + string(htmlRaw)
	if strings.Contains(combined, secret) || strings.Contains(combined, "Authorization") || strings.Contains(combined, "Set-Cookie") {
		t.Fatal("authentication report leaked secret-bearing material")
	}
	if !strings.Contains(combined, "Authentication validation was performed") || !strings.Contains(combined, "invalid_credentials") {
		t.Fatal("authentication result distinction missing")
	}
}
