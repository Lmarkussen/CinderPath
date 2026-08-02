package capturekit

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func GenerateKitDossier(kit, output string, v Validation, bundle *EvidenceBundleInfo, force bool) error {
	if output == "" {
		return errors.New("dossier output is required")
	}
	if _, e := os.Lstat(output); e == nil && !force {
		return errors.New("dossier output already exists")
	}
	tmp, e := os.MkdirTemp(filepath.Dir(output), ".capture-kit-dossier-")
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	if e = os.Chmod(tmp, 0o700); e != nil {
		return e
	}
	meta, e := LoadMetadata(kit)
	if e != nil {
		return e
	}
	writeJSON := func(name string, x any) error {
		b, e := json.MarshalIndent(x, "", "  ")
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(tmp, name), append(b, '\n'), 0o600)
	}
	_ = writeJSON("capture-kit-summary.json", map[string]any{"kit_id": v.KitID, "fingerprint": v.Fingerprint, "state": v.State, "blockers": v.Blockers, "metadata_schema_version": meta.SchemaVersion, "live_policy_requests": 0})
	_ = writeJSON("kit-state-history.json", []any{map[string]any{"state": v.State, "evidence": "current offline validation"}})
	copyJSONSummary(kit, "metadata/client-inventory.json", tmp, "client-inventory.json")
	copyJSONSummary(kit, "metadata/tool-inventory.json", tmp, "tool-inventory.json")
	f, err := os.Create(filepath.Join(tmp, "file-inventory.csv"))
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"path", "kind", "size", "sha256", "reviewed", "redacted"})
	for _, x := range append(append([]File{}, v.RawFiles...), v.Sanitized...) {
		_ = w.Write([]string{filepath.Base(x.Path), x.Kind, fmtInt(x.Size), x.SHA256, boolText(x.Reviewed), boolText(x.Redacted)})
	}
	w.Flush()
	_ = f.Close()
	if w.Error() != nil {
		return w.Error()
	}
	if b, e := os.ReadFile(filepath.Join(kit, "output/windows-log-inspection.json")); e == nil && len(b) <= 8<<20 {
		var li LogInspection
		if json.Unmarshal(b, &li) == nil {
			_ = writeJSON("windows-log-summary.json", map[string]any{"files": len(li.Files), "observations": len(li.Observations), "sensitive_indicators": li.SensitiveIndicators, "truncated": li.Truncated})
			_ = writeJSON("windows-log-observations.json", li.Observations)
		}
	} else {
		_ = writeJSON("windows-log-summary.json", map[string]any{"state": "not_run"})
		_ = writeJSON("windows-log-observations.json", []any{})
	}
	_ = writeJSON("sanitization-summary.json", map[string]any{"sanitized": meta.Review.Sanitized, "sanitized_file_count": len(v.Sanitized)})
	_ = writeJSON("review-summary.json", meta.Review)
	_ = writeJSON("leakage-check-summary.json", map[string]any{"passed": meta.Review.LeakageChecksPassed, "cannot_override_positive_detection": true})
	if bundle != nil {
		_ = writeJSON("bundle-provenance.json", bundle)
	} else {
		_ = writeJSON("bundle-provenance.json", map[string]any{"state": "local_kit"})
	}
	_ = writeJSON("matrix-link.json", map[string]any{"state": "not_linked"})
	_ = os.WriteFile(filepath.Join(tmp, "gaps-and-next-actions.md"), []byte("# Gaps and next actions\n\n"+strings.Join(v.Blockers, "\n")+"\n\n"+strings.Join(v.AllowedNextActions, "\n")+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(tmp, "safety-boundaries.md"), []byte("# Safety boundaries\n\nNo client registration, policy trigger, automatic capture, active replay, authentication, or live SCCM policy request occurred. Capture evidence is not protocol approval.\n"), 0o600)
	if force {
		_ = os.RemoveAll(output)
	}
	if e = os.Rename(tmp, output); e != nil {
		return e
	}
	ok = true
	return nil
}
func copyJSONSummary(root, rel, out, name string) {
	b, e := os.ReadFile(filepath.Join(root, rel))
	if e != nil || len(b) > 1<<20 {
		_ = os.WriteFile(filepath.Join(out, name), []byte("{\"state\":\"unavailable\"}\n"), 0o600)
		return
	}
	var x any
	if json.Unmarshal(b, &x) != nil {
		x = map[string]any{"state": "malformed"}
	}
	clean, _ := json.MarshalIndent(x, "", "  ")
	_ = os.WriteFile(filepath.Join(out, name), append(clean, '\n'), 0o600)
}
func fmtInt(v int64) string { return fmt.Sprintf("%d", v) }
func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
