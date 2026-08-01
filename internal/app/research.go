package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"time"
)

func (a *Application) PersistResearchAnalysis(ctx context.Context, runID, setID string, x policy.ResearchAnalysis, c *policy.CandidateContract) error {
	s, e := database.Open(ctx, a.Config.DBPath)
	if e != nil {
		return e
	}
	defer s.Close()
	save := func(table, id string, v any) {
		b, _ := json.Marshal(v)
		var d map[string]any
		_ = json.Unmarshal(b, &d)
		sum := sha256.Sum256(b)
		_ = s.UpsertResearchRecord(context.WithoutCancel(ctx), table, database.ResearchRecord{ID: id, RunID: runID, ResearchSetID: setID, Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), ObservedAt: time.Now().UTC(), Data: d})
	}
	save("research_sets", "research_set_"+shortHash(setID), map[string]any{"name": x.ResearchSet, "algorithm_version": x.AlgorithmVersion, "excluded": x.Excluded, "bundle_states": x.BundleStates, "live_policy_requests": 0})
	for i, v := range x.Variables {
		save("research_variables", "research_variable_"+shortHash(setID+string(rune(i))), v)
	}
	for i, v := range x.Comparisons {
		save("cross_fixture_observations", "cross_observation_"+shortHash(setID+v.Property+string(rune(i))), v)
	}
	for i, v := range x.Correlations {
		save("field_correlations", "field_correlation_"+shortHash(setID+v.Observation+string(rune(i))), v)
	}
	for i, v := range x.Sequences {
		save("request_sequences", "request_sequence_"+shortHash(setID+v.ID+string(rune(i))), v)
	}
	if c != nil {
		save("candidate_contracts", c.ID, *c)
	}
	findings := []models.Finding{}
	if c != nil {
		findings = append(findings, models.Finding{RuleID: "SCCM-PROTOCOL-CANDIDATE-CONTRACT-DERIVED", Title: "Offline candidate protocol contract derived", Summary: "Research evidence only; live SCCM execution is not approved.", Description: "Multiple reviewed fixture observations were compared with counterexamples and unknowns preserved.", Severity: models.SeverityInformational, Confidence: models.ConfidenceMedium, Tags: []string{"offline_research", "candidate_contract"}})
	}
	for _, p := range x.Comparisons {
		rule, title := "", ""
		switch p.Classification {
		case "constant_across_set":
			rule, title = "SCCM-PROTOCOL-STABLE-REQUEST-PROPERTY", "Stable offline protocol property observed"
		case "conflicting":
			rule, title = "SCCM-PROTOCOL-CONFLICTING-OBSERVATION", "Conflicting offline protocol observation"
		}
		if rule != "" {
			findings = append(findings, models.Finding{RuleID: rule, Title: title, Summary: "Offline research observation; not a vulnerability and not live validation.", Description: "Redacted comparison metadata retained sample coverage and classification.", Severity: models.SeverityInformational, Confidence: models.ConfidenceMedium, Tags: []string{"offline_research"}})
		}
	}
	for i := range findings {
		findings[i].Prepare(time.Now().UTC())
		_, _ = s.UpsertFinding(ctx, &findings[i])
	}
	for _, name := range []string{"research_bundle_signing_available", "multi_capture_comparison_available", "field_correlation_analysis_available", "sequence_modeling_available", "candidate_contract_derivation_available", "contract_dossier_available", "signed_expected_result_testing_available"} {
		cap := models.Capability{Name: name, Available: true, State: models.CapabilityAvailable, Reason: "Offline protocol research capability; no live SCCM policy request", Source: "policy.research"}
		cap.Prepare()
		_, _ = s.UpsertCapability(ctx, &cap)
	}
	blocked := models.Capability{Name: "live_policy_collection_blocked", Available: false, State: models.CapabilityBlockedBySafety, Reason: "Candidate contracts do not approve live execution", Source: "policy.research", SafetyBlocked: true}
	blocked.Prepare()
	_, _ = s.UpsertCapability(ctx, &blocked)
	return nil
}
func shortHash(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:10]) }
func (a *Application) PersistSafetyReview(ctx context.Context, setID string, r policy.SafetyReview) error {
	s, e := database.Open(ctx, a.Config.DBPath)
	if e != nil {
		return e
	}
	defer s.Close()
	b, _ := json.Marshal(r)
	var d map[string]any
	_ = json.Unmarshal(b, &d)
	return s.UpsertResearchRecord(ctx, "safety_reviews", database.ResearchRecord{ID: r.ReviewID, ResearchSetID: setID, Fingerprint: "sha256:" + shortHash(string(b)), Data: d})
}
func (a *Application) PersistBundleSignature(ctx context.Context, bundleID string, v policy.SignatureVerification) error {
	s, e := database.Open(ctx, a.Config.DBPath)
	if e != nil {
		return e
	}
	defer s.Close()
	b, _ := json.Marshal(v)
	var d map[string]any
	_ = json.Unmarshal(b, &d)
	return s.UpsertResearchRecord(ctx, "bundle_signatures", database.ResearchRecord{ID: "bundle_signature_" + shortHash(bundleID+v.SignerKeyID), Fingerprint: "sha256:" + shortHash(string(b)), Data: d})
}
