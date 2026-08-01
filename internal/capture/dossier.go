package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// GenerateDossier writes only normalized, redacted research evidence.
func GenerateDossier(output string, a Analysis, force bool) error {
	if output == "" {
		return errors.New("dossier output is required")
	}
	if _, e := os.Lstat(output); e == nil && !force {
		return errors.New("dossier output already exists")
	}
	parent := filepath.Dir(output)
	tmp, e := os.MkdirTemp(parent, ".cinderpath-dossier-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = os.Chmod(tmp, 0o700); e != nil {
		return e
	}
	files := map[string]any{"capture-inventory.json": a.Capture.Source, "matrix-validation.json": a.Matrix, "exchange-summary.json": a.Capture.Exchanges, "sequence-model.json": a.Capture.Sequence, "structured-observations.json": a.Capture.Observations, "parser-candidates.json": a.Candidates, "counterexamples.json": []string{}, "ambiguities.json": a.Capture.Source.Warnings, "expected-analysis.json": map[string]any{"analysis_fingerprint": a.Fingerprint, "algorithm_version": AlgorithmVersion}, "review.json": map[string]any{"state": "not_reviewed", "live_permission_effect": "none"}}
	for name, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		b = append(b, '\n')
		if e = os.WriteFile(filepath.Join(tmp, name), b, 0o600); e != nil {
			return e
		}
	}
	readme := "Offline SCCM capture research dossier\n\nLive SCCM execution is blocked. This dossier contains redacted normalized evidence, not raw captures or authorization. Opaque and unsupported traffic remains explicitly limited.\n"
	if e = os.WriteFile(filepath.Join(tmp, "README.txt"), []byte(readme), 0o600); e != nil {
		return e
	}
	if force {
		if st, e := os.Lstat(output); e == nil {
			if !st.IsDir() {
				return fmt.Errorf("refuse to replace non-directory dossier output")
			}
			return errors.New("force replacement of an existing dossier is intentionally unsupported in this build")
		}
	}
	return os.Rename(tmp, output)
}
