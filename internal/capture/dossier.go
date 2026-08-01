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
	files := map[string]any{"capture-summary.json": a.Capture.Source, "interfaces.json": a.Capture.Interfaces, "packets-metadata.json": a.Capture.Packets, "flows.json": a.Capture.Flows, "exchanges.json": a.Capture.Exchanges, "sequences.json": a.Capture.Sequence, "sequence-graph.json": a.Capture.Sequence, "structured-observations.json": a.Capture.Observations, "parser-candidates.json": a.Candidates, "matrix-summary.json": a.Matrix, "corpus-results.json": map[string]any{"state": "not_run"}, "counterexamples.json": []string{}, "ambiguities.json": a.Capture.Source.Warnings, "expected-analysis.json": map[string]any{"analysis_fingerprint": a.Fingerprint, "algorithm_version": AlgorithmVersion}, "review.json": map[string]any{"state": "not_reviewed", "live_permission_effect": "none"}}
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
			backup, e := os.MkdirTemp(parent, ".cinderpath-old-dossier-")
			if e != nil {
				return e
			}
			if e = os.Remove(backup); e != nil {
				return e
			}
			if e = os.Rename(output, backup); e != nil {
				return e
			}
			if e = os.Rename(tmp, output); e != nil {
				_ = os.Rename(backup, output)
				return e
			}
			return os.RemoveAll(backup)
		}
	}
	return os.Rename(tmp, output)
}
