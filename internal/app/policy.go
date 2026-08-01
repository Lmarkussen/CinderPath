package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/policy"
)

const policyParserVersion = "policy-xml-v1"

func digest(b []byte) string { x := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(x[:]) }
func mapOf(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (a *Application) PersistPolicyFixture(ctx context.Context, runID string, f policy.Fixture, c policy.Contract, p policy.ParsedPolicy, candidates []policy.Candidate) error {
	store, e := database.Open(ctx, a.Config.DBPath)
	if e != nil {
		return e
	}
	defer store.Close()
	now := time.Now().UTC()
	cData := mapOf(c)
	delete(cData, "verified_at")
	if e = store.UpsertPolicyRecord(ctx, "protocol_contracts", database.PolicyRecord{ID: c.ID, Fingerprint: digest([]byte(c.ID)), ObservedAt: now, Data: cData}); e != nil {
		return e
	}
	fixtureData := map[string]any{"contract_id": c.ID, "name": f.Metadata.Name, "synthetic": f.Metadata.Synthetic, "sanitized": f.Metadata.Sanitized, "source_type": "offline_fixture", "source_path_redacted": filepath.Base(f.Directory), "request_body_sha256": digest(f.RequestBody), "response_body_sha256": digest(f.ResponseBody), "request_size": len(f.RequestBody), "response_size": len(f.ResponseBody), "sanitizer_version": "fixture-sanitizer-v1"}
	if e = store.UpsertPolicyRecord(ctx, "protocol_fixtures", database.PolicyRecord{ID: f.ID, Fingerprint: digest(append(append([]byte{}, f.RequestBody...), f.ResponseBody...)), ObservedAt: now, Data: fixtureData}); e != nil {
		return e
	}
	assignments, _ := policy.ParseAssignments(ctx, f.ResponseBody, f.ID)
	for _, x := range assignments {
		d := mapOf(x)
		id := "assignment_" + x.Fingerprint[:20]
		_ = store.UpsertPolicyRecord(ctx, "policy_assignments", database.PolicyRecord{ID: id, RunID: runID, Fingerprint: x.Fingerprint, ObservedAt: now, Data: d})
	}
	docID := "policy_" + hex.EncodeToString(sha256Bytes([]byte(f.ID + p.PolicyID + p.Version))[:10])
	protected, plain, confirmed, scripts := 0, 0, 0, 0
	for _, x := range candidates {
		if x.Protected {
			protected++
		}
		if x.State == "plaintext_candidate" {
			plain++
		}
		if x.State == "confirmed_plaintext" {
			confirmed++
		}
		if x.Category == "sensitive_script" {
			scripts++
		}
	}
	doc := map[string]any{"fixture_id": f.ID, "policy_id": p.PolicyID, "policy_type": p.Type, "policy_category": p.Category, "policy_version": p.Version, "content_fingerprint": digest(f.ResponseBody), "parser_status": "parsed", "parser_version": policyParserVersion, "raw_size": len(f.ResponseBody), "protected_value_count": protected, "plaintext_candidate_count": plain, "confirmed_plaintext_count": confirmed, "sensitive_script_count": scripts}
	if e = store.UpsertPolicyRecord(ctx, "policy_documents", database.PolicyRecord{ID: docID, RunID: runID, Fingerprint: digest(f.ResponseBody), ObservedAt: now, Data: doc}); e != nil {
		return e
	}
	parsed := map[string]any{"fixture_id": f.ID, "policy_id": p.PolicyID, "type": p.Type, "category": p.Category, "version": p.Version, "setting_count": len(p.Settings), "unknown_fingerprint": p.UnknownFingerprint, "parser_version": policyParserVersion}
	_ = store.UpsertPolicyRecord(ctx, "parsed_policies", database.PolicyRecord{ID: docID + "_parsed", RunID: runID, Fingerprint: digest([]byte(fmt.Sprint(parsed))), ObservedAt: now, Data: parsed})
	for _, x := range candidates {
		r := policy.Redacted(x)
		d := mapOf(r)
		delete(d, "value")
		d["policy_document_id"] = docID
		_ = store.UpsertPolicyRecord(ctx, "policy_candidates", database.PolicyRecord{ID: x.ID, RunID: runID, Fingerprint: x.Fingerprint, ObservedAt: now, Data: d})
		capName := "policy_secret_classification_available"
		if x.State == "confirmed_plaintext" {
			capName = "policy_confirmed_plaintext_present_in_fixture"
		}
		if x.Protected {
			capName = "policy_protected_candidate_present_in_fixture"
		}
		cap := models.Capability{Name: capName, Available: true, State: models.CapabilityAvailable, Reason: "Offline fixture-derived metadata; live target validation not performed", Source: "policy.fixture"}
		cap.Prepare()
		_, _ = store.UpsertCapability(ctx, &cap)
		rule, severity := "SCCM-POLICY-PLAINTEXT-SECRET-CANDIDATE", models.SeverityMedium
		if x.State == "confirmed_plaintext" {
			rule, severity = "SCCM-POLICY-CONFIRMED-PLAINTEXT", models.SeverityHigh
		}
		if x.Protected {
			rule, severity = "SCCM-POLICY-PROTECTED-SECRET-CANDIDATE", models.SeverityInformational
		}
		finding := models.Finding{RuleID: rule, Title: "Offline policy fixture secret material identified", Summary: "Source type: offline fixture. Live target validation: not performed.", Description: "CinderPath classified redacted policy metadata from a synthetic or sanitized local fixture. No live SCCM policy request was sent and no protected value was decrypted.", Severity: severity, Confidence: models.ConfidenceHigh, Tags: []string{"offline_fixture", "sccm_policy"}, Remediation: "Review the authorized source environment and rotate confirmed exposed plaintext credentials."}
		finding.Prepare(now)
		_, _ = store.UpsertFinding(ctx, &finding)
	}
	for _, name := range []string{"policy_fixture_import_available", "policy_protocol_analysis_available", "policy_local_replay_available", "policy_document_parser_available", "secure_secret_output_available"} {
		cap := models.Capability{Name: name, Available: true, State: models.CapabilityAvailable, Reason: "Offline fixture capability", Source: "policy.fixture"}
		cap.Prepare()
		_, _ = store.UpsertCapability(ctx, &cap)
	}
	for _, name := range []string{"live_policy_contract_missing", "live_policy_collection_blocked"} {
		cap := models.Capability{Name: name, Available: false, State: models.CapabilityBlockedBySafety, Reason: "No approved live protocol contract", Source: "policy.fixture", SafetyBlocked: true}
		cap.Prepare()
		_, _ = store.UpsertCapability(ctx, &cap)
	}
	return nil
}
func sha256Bytes(b []byte) []byte { x := sha256.Sum256(b); return x[:] }

func (a *Application) PersistWorkflowPlan(ctx context.Context, runID string, plan WorkflowPlan, dry bool) error {
	store, e := database.Open(ctx, a.Config.DBPath)
	if e != nil {
		return e
	}
	defer store.Close()
	return a.persistPlan(ctx, store, runID, plan, dry)
}
func (a *Application) persistPlan(ctx context.Context, store *database.Store, runID string, plan WorkflowPlan, dry bool) error {
	now := time.Now().UTC()
	var first error
	for _, s := range plan.Stages {
		id := "stage_" + hex.EncodeToString(sha256Bytes([]byte(runID + s.Name))[:10])
		state := s.Status
		if state == "ready" {
			state = "planned"
		}
		data := map[string]any{"planned_state": state, "final_state": state, "reason": s.Reason, "profile": string(plan.Profile), "dry_run": dry, "network_activity": "none_for_fixture_stages", "authentication": "none", "secret_handling": "redacted_metadata_only"}
		if e := store.SaveWorkflowStage(context.WithoutCancel(ctx), database.WorkflowRecord{ID: id, RunID: runID, Name: s.Name, State: state, StartedAt: &now, FinishedAt: &now, Data: data}); e != nil && first == nil {
			first = e
		}
	}
	for _, m := range plan.Modules {
		state := m.DecisionState
		if dry && m.Selected && state == "ready" {
			state = "selected"
		} else if !dry && m.Selected && state == "ready" {
			state = "completed"
		}
		id := "decision_" + hex.EncodeToString(sha256Bytes([]byte(runID + m.ModuleName))[:10])
		data := map[string]any{"category": m.Category, "implemented": m.Implemented, "selected": m.Selected, "decision_state": state, "reason_code": m.ReasonCode, "reason": m.DecisionReason, "profile": string(plan.Profile), "requirements": m.Requirements, "network_boundary": m.NetworkBoundary, "may_contact_network": m.MayContactNetwork, "may_authenticate": m.MayAuthenticate, "may_download": m.MayDownload, "may_extract_secrets": m.MayExtractSecrets, "may_alter_state": m.MayAlterState, "dry_run": dry}
		if !m.Implemented && (state == "completed" || state == "completed_with_errors") {
			state = "not_implemented"
			data["decision_state"] = state
		}
		if e := store.SaveWorkflowModuleDecision(context.WithoutCancel(ctx), database.WorkflowRecord{ID: id, RunID: runID, Name: m.ModuleName, State: state, Data: data}); e != nil && first == nil {
			first = e
		}
	}
	return first
}
