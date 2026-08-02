package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/capturekit"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

func (s *state) persistKitLifecycle(ctx context.Context, command, dir string, v capturekit.Validation, extra map[string]any) error {
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, command, string(s.cfg.Profile), version.Version, []string{"offline", "redacted", filepath.Base(dir)})
	if e != nil {
		return e
	}
	fail := func(err error) error {
		_ = db.FinishRun(ctx, run.ID, models.RunFailed, map[string]any{"kit_id": v.KitID, "live_requests": 0})
		return err
	}
	put := func(table, id, fp string, data any) error {
		return db.UpsertCaptureRecord(ctx, table, database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: v.KitID, Fingerprint: fp, ObservedAt: time.Now().UTC(), Data: data})
	}
	kitData := map[string]any{"kit_id": v.KitID, "fingerprint": v.Fingerprint, "state": v.State, "blockers": v.Blockers, "metadata_schema_version": capturekit.SchemaVersion, "source_name": filepath.Base(dir), "live_policy_requests": 0}
	for k, x := range extra {
		kitData[k] = x
	}
	if e = put("capture_kits", v.KitID, v.Fingerprint, kitData); e != nil {
		return fail(e)
	}
	transitionID := models.StableID("capture_kit_validation", models.StableFingerprint(v.KitID, run.ID, string(v.State)))
	if e = put("capture_kit_validation_results", transitionID, v.Fingerprint, map[string]any{"state": v.State, "blockers": v.Blockers, "warnings": v.Warnings, "errors": v.Errors}); e != nil {
		return fail(e)
	}
	for _, f := range append(append([]capturekit.File{}, v.RawFiles...), v.Sanitized...) {
		id := models.StableID("capture_kit_file", models.StableFingerprint(v.KitID, f.Path, f.SHA256))
		if e = put("capture_kit_files", id, f.SHA256, map[string]any{"safe_path": f.Path, "safe_name": filepath.Base(f.Path), "sha256": f.SHA256, "size": f.Size, "kind": f.Kind, "redacted": f.Redacted, "reviewed": f.Reviewed}); e != nil {
			return fail(e)
		}
	}
	if m, x := capturekit.LoadMetadata(dir); x == nil {
		rid := models.StableID("capture_kit_review", models.StableFingerprint(v.KitID, run.ID))
		if e = put("capture_kit_reviews", rid, v.Fingerprint, m.Review); e != nil {
			return fail(e)
		}
	}
	for _, item := range []struct{ rel, table, prefix string }{{"metadata/client-inventory.json", "windows_client_inventories", "windows_client_inventory"}, {"metadata/tool-inventory.json", "capture_tool_inventories", "capture_tool_inventory"}, {"output/windows-log-inspection.json", "windows_log_inspections", "windows_log_inspection"}} {
		p := filepath.Join(dir, item.rel)
		if b, x := os.ReadFile(p); x == nil && len(b) <= 8<<20 {
			sum := sha256.Sum256(b)
			fp := hex.EncodeToString(sum[:])
			id := models.StableID(item.prefix, models.StableFingerprint(v.KitID, fp))
			data := map[string]any{"safe_name": filepath.Base(p), "sha256": fp, "size": len(b), "redacted_summary_only": true}
			if item.table == "windows_log_inspections" {
				data["inspection_state"] = "completed"
			}
			if e = put(item.table, id, fp, data); e != nil {
				return fail(e)
			}
		}
	}
	for _, name := range []string{"lab_capture_kit_generation_available", "windows_passive_inventory_available", "capture_kit_validation_available", "windows_log_structural_inspection_available", "capture_evidence_bundle_available", "capture_evidence_bundle_signing_available", "guided_capture_import_available", "capture_kit_matrix_integration_available"} {
		c := models.Capability{Name: name, Available: true, State: models.CapabilityAvailable, Reason: "passive offline capture-kit capability; no live SCCM request", Source: "capture-kit.lifecycle"}
		_, _ = db.UpsertCapability(ctx, &c)
	}
	blocked := models.Capability{Name: "live_policy_collection_blocked", Available: false, State: models.CapabilityBlockedBySafety, Reason: "capture evidence does not authorize live policy collection", Source: "capture-kit.lifecycle", SafetyBlocked: true}
	_, _ = db.UpsertCapability(ctx, &blocked)
	rule, title := "SCCM-LAB-CAPTURE-KIT-INCOMPLETE", "Capture kit requires additional offline preparation"
	switch v.State {
	case capturekit.ReadyForCapture:
		rule, title = "SCCM-LAB-CAPTURE-KIT-CREATED", "Passive lab capture kit created"
	case capturekit.RequiresSanitization:
		rule, title = "SCCM-LAB-CAPTURE-SANITIZATION-INCOMPLETE", "Capture sanitization is incomplete"
	case capturekit.RequiresManualReview, capturekit.ReviewFailed:
		rule, title = "SCCM-LAB-CAPTURE-REVIEW-REQUIRED", "Capture review is required"
	case capturekit.ReadyForImport, capturekit.ReadyForEvidenceBundle:
		rule, title = "SCCM-LAB-CAPTURE-READY-FOR-IMPORT", "Capture kit is ready for offline import"
	}
	finding := models.Finding{RuleID: rule, Title: title, Summary: "Operational capture-kit state; not a vulnerability or live validation.", Description: "CinderPath performed passive offline preparation or analysis only. Live SCCM policy requests: 0.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, Tags: []string{"offline_research", "capture_kit", "operational"}}
	_, _ = db.UpsertFinding(ctx, &finding)
	if n, ok := extra["sensitive_indicators"].(int); ok && n > 0 {
		f := models.Finding{RuleID: "SCCM-LAB-CAPTURE-LOG-SENSITIVE-INDICATOR", Title: "Windows log contains a sensitive indicator", Summary: "Redacted structural observation requires remediation before export.", Description: "The indicator value was not persisted or reported.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, Tags: []string{"offline_research", "windows_log", "operational"}}
		_, _ = db.UpsertFinding(ctx, &f)
	}
	_ = db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"kit_id": v.KitID, "state": v.State, "live_requests": 0})
	return nil
}

func persistBundle(ctx context.Context, dbPath, command string, info capturekit.EvidenceBundleInfo) error {
	db, e := database.Open(ctx, dbPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, command, "safe", version.Version, []string{"offline", "capture_evidence", "redacted"})
	if e != nil {
		return e
	}
	bid := info.Manifest.BundleID
	if e = db.UpsertCaptureRecord(ctx, "capture_evidence_bundles", database.CaptureRecord{ID: bid, RunID: run.ID, CaptureID: info.Manifest.KitID, Fingerprint: info.Manifest.KitFingerprint, Data: info}); e != nil {
		return e
	}
	for _, m := range info.Manifest.Members {
		id := models.StableID("capture_evidence_member", models.StableFingerprint(bid, m.Path, m.SHA256))
		if e = db.UpsertCaptureRecord(ctx, "capture_evidence_bundle_members", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: info.Manifest.KitID, Fingerprint: m.SHA256, Data: map[string]any{"bundle_id": bid, "safe_path": m.Path, "safe_name": filepath.Base(m.Path), "size": m.Size, "sha256": m.SHA256}}); e != nil {
			return e
		}
	}
	capability := models.Capability{Name: "capture_evidence_bundle_available", Available: true, State: models.CapabilityAvailable, Reason: "dedicated offline capture-evidence bundle format", Source: "capture-kit.bundle"}
	_, _ = db.UpsertCapability(ctx, &capability)
	finding := models.Finding{RuleID: "SCCM-LAB-CAPTURE-EVIDENCE-BUNDLE-EXPORTED", Title: "Capture-evidence bundle processed", Summary: "Integrity metadata for reviewed offline capture evidence; not protocol approval.", Description: "The bundle has no live execution or contract-promotion effect.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, Tags: []string{"offline_research", "capture_evidence", "operational"}}
	_, _ = db.UpsertFinding(ctx, &finding)
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"bundle_id": bid, "kit_id": info.Manifest.KitID, "signature_state": info.SignatureState, "live_requests": 0})
}

func (s *state) persistMatrixLink(ctx context.Context, matrixPath, kit string) error {
	v, e := capturekit.Validate(kit)
	if e != nil {
		return e
	}
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "matrix add-kit", string(s.cfg.Profile), version.Version, []string{"offline", "redacted", filepath.Base(matrixPath)})
	if e != nil {
		return e
	}
	id := models.StableID("capture_kit_matrix_link", models.StableFingerprint(v.KitID, filepath.Base(matrixPath)))
	e = db.UpsertCaptureRecord(ctx, "capture_kit_matrix_links", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: v.KitID, Fingerprint: v.Fingerprint, Data: map[string]any{"matrix_name": filepath.Base(matrixPath), "kit_id": v.KitID, "state": "linked", "analysis_started": false, "live_requests": 0}})
	if e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"kit_id": v.KitID, "matrix": filepath.Base(matrixPath), "live_requests": 0})
}
