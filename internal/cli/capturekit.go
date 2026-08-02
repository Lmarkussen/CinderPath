package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/capture"
	"github.com/Lmarkussen/CinderPath/internal/capturekit"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
	"github.com/spf13/cobra"
)

func (s *state) captureKitCommand() *cobra.Command {
	root := &cobra.Command{Use: "capture-kit", Short: "Prepare and validate passive authorized Windows lab capture kits"}
	var o capturekit.CreateOptions
	var format string
	create := &cobra.Command{Use: "create", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if e := capturekit.Create(o); e != nil {
			return e
		}
		v, e := capturekit.Validate(o.Output)
		if e != nil {
			return e
		}
		if e = s.persistKitLifecycle(context.Background(), "lab capture-kit create", o.Output, v, nil); e != nil {
			return e
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(v)
		}
		fmt.Fprintf(s.stdout, "Created passive capture kit: %s\nState: %s\nNetwork activity: none\nPacket capture started: no\nPolicy retrieval triggered: no\nLive SCCM policy requests: 0\n", filepath.Base(o.Output), v.State)
		return nil
	}}
	f := create.Flags()
	f.StringVar(&o.Output, "output", "", "new capture-kit directory")
	f.StringVar(&o.SiteCode, "site-code", "", "optional metadata only; never resolved")
	f.StringVar(&o.ManagementPoint, "management-point", "", "optional metadata only; never contacted or resolved")
	f.StringVar(&o.ClientLabel, "client-label", "", "safe operator label")
	f.StringVar(&o.CaptureLabel, "capture-label", "", "safe capture label")
	f.StringVar(&o.CaptureAction, "capture-action", "normal_policy_retrieval", "operator-declared action metadata")
	f.BoolVar(&o.Force, "force", false, "atomically replace an existing kit")
	f.StringVar(&format, "format", "text", "text or json")
	_ = create.MarkFlagRequired("output")
	var dir string
	validate := &cobra.Command{Use: "validate", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := capturekit.Validate(dir)
		if e != nil {
			return e
		}
		if e = s.persistKitLifecycle(context.Background(), "lab capture-kit validate", dir, v, nil); e != nil {
			return e
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(v)
		}
		fmt.Fprintf(s.stdout, "Capture kit: %s\nCapture kit state: %s\nFingerprint: %s\nRaw files: %d\nSanitized files: %d\n", v.KitID, v.State, v.Fingerprint, len(v.RawFiles), len(v.Sanitized))
		if len(v.Blockers) > 0 {
			fmt.Fprintln(s.stdout, "\nBlocking conditions:")
			for _, x := range v.Blockers {
				fmt.Fprintln(s.stdout, "  "+x)
			}
		}
		if len(v.AllowedNextActions) > 0 {
			fmt.Fprintln(s.stdout, "\nAllowed next actions:")
			for _, x := range v.AllowedNextActions {
				fmt.Fprintln(s.stdout, "  "+x)
			}
		}
		fmt.Fprintln(s.stdout, "\nLive SCCM policy requests: 0")
		for _, x := range v.Errors {
			fmt.Fprintln(s.stdout, "ERROR:", x)
		}
		for _, x := range v.Warnings {
			fmt.Fprintln(s.stdout, "WARNING:", x)
		}
		if v.State == capturekit.Invalid {
			return errors.New("capture kit is invalid")
		}
		return nil
	}}
	show := &cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		m, e := capturekit.LoadMetadata(dir)
		if e != nil {
			return e
		}
		v, e := capturekit.Validate(dir)
		if e != nil {
			return e
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(map[string]any{"metadata": m, "validation": v})
		}
		fmt.Fprintf(s.stdout, "Capture: %s\nClient: %s\nState: %s\nBlockers: %s\nSite: %s\nManagement point metadata: %s\nAuthorized lab assertion: %t (operator supplied, unverified)\nDisposable assertion: %t (operator supplied, unverified)\n", m.Capture.Label, m.Client.Label, v.State, strings.Join(v.Blockers, "; "), m.Client.SiteCode, m.Client.ManagementPoint, m.Capture.AuthorizedLab, m.Environment.Disposable)
		return nil
	}}
	finalize := &cobra.Command{Use: "finalize", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := capturekit.Validate(dir)
		if e != nil {
			return e
		}
		if v.State == capturekit.Invalid {
			return errors.New("cannot finalize invalid kit")
		}
		b, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "kit_id": v.KitID, "raw_sensitive": true, "safe_for_sharing": false, "files": v.RawFiles, "live_policy_requests": 0}, "", "  ")
		if e = atomicCaptureWrite(filepath.Join(dir, "output", "linux-validation-summary.json"), append(b, '\n')); e != nil {
			return e
		}
		return s.persistKitLifecycle(context.Background(), "lab capture-kit finalize", dir, v, map[string]any{"raw_finalized": true})
	}}
	for _, c := range []*cobra.Command{validate, show, finalize} {
		c.Flags().StringVar(&dir, "directory", "", "capture-kit directory")
		c.Flags().StringVar(&format, "format", "text", "text or json")
		_ = c.MarkFlagRequired("directory")
	}
	inspectLogs := &cobra.Command{Use: "inspect-logs", Short: "Inspect local Windows/SCCM logs structurally with bounded redacted output", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := capturekit.InspectLogs(dir, time.Time{}, capturekit.DefaultLogLimits())
		if e != nil {
			return e
		}
		b, _ := json.MarshalIndent(r, "", "  ")
		if e = atomicCaptureWrite(filepath.Join(dir, "output", "windows-log-inspection.json"), append(b, '\n')); e != nil {
			return e
		}
		v, e := capturekit.Validate(dir)
		if e != nil {
			return e
		}
		if e = s.persistKitLifecycle(context.Background(), "lab capture-kit inspect-logs", dir, v, map[string]any{"log_files": len(r.Files), "log_observations": len(r.Observations), "sensitive_indicators": r.SensitiveIndicators}); e != nil {
			return e
		}
		if format == "json" {
			_, e = s.stdout.Write(append(b, '\n'))
			return e
		}
		fmt.Fprintf(s.stdout, "Kit: %s\nLog files inspected: %d\nObservations: %d\nSensitive indicators: %d\nTruncated: %t\nSemantic SCCM parsers: not implemented\nLive SCCM policy requests: 0\n", r.KitID, len(r.Files), len(r.Observations), r.SensitiveIndicators, r.Truncated)
		return nil
	}}
	inspectLogs.Flags().StringVar(&dir, "directory", "", "capture-kit directory")
	inspectLogs.Flags().StringVar(&format, "format", "text", "text or json")
	_ = inspectLogs.MarkFlagRequired("directory")
	root.AddCommand(create, validate, show, finalize, inspectLogs, s.captureKitBundleCommand())
	return root
}

func (s *state) captureKitBundleCommand() *cobra.Command {
	root := &cobra.Command{Use: "bundle", Short: "Manage dedicated reviewed capture-evidence bundles; never protocol-contract bundles"}
	var dir, input, output, key, format string
	var force bool
	export := &cobra.Command{Use: "export", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		info, e := capturekit.ExportEvidenceBundle(capturekit.ExportOptions{Directory: dir, Output: output, ToolVersion: version.Version, Force: force})
		if e != nil {
			return e
		}
		marker, _ := json.MarshalIndent(map[string]any{"bundle_id": info.Manifest.BundleID, "safe_name": filepath.Base(output), "signature_state": info.SignatureState, "live_policy_requests": 0}, "", "  ")
		if e = atomicCaptureWrite(filepath.Join(dir, "output", "evidence-bundle.json"), append(marker, '\n')); e != nil {
			return e
		}
		if e = persistBundle(context.Background(), s.cfg.DBPath, "lab capture-kit bundle export", info); e != nil {
			return e
		}
		return printBundleInfo(s.stdout, format, info)
	}}
	export.Flags().StringVar(&dir, "directory", "", "reviewed capture-kit directory")
	export.Flags().StringVar(&output, "output", "", "new .capture-bundle.tar.gz output outside the kit")
	export.Flags().BoolVar(&force, "force", false, "atomically replace output")
	export.Flags().StringVar(&format, "format", "text", "text or json")
	_ = export.MarkFlagRequired("directory")
	_ = export.MarkFlagRequired("output")
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		info, _, e := capturekit.InspectEvidenceBundle(input)
		if e != nil {
			return e
		}
		return printBundleInfo(s.stdout, format, info)
	}}
	verify := &cobra.Command{Use: "verify", Args: cobra.NoArgs, RunE: inspect.RunE}
	for _, c := range []*cobra.Command{inspect, verify} {
		c.Flags().StringVar(&input, "input", "", "capture-evidence bundle")
		c.Flags().StringVar(&format, "format", "text", "text or json")
		_ = c.MarkFlagRequired("input")
	}
	imp := &cobra.Command{Use: "import", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		info, e := capturekit.ImportEvidenceBundle(capturekit.ImportOptions{Input: input, Output: output, Force: force})
		if e != nil {
			return e
		}
		if e = persistBundle(context.Background(), s.cfg.DBPath, "lab capture-kit bundle import", info); e != nil {
			return e
		}
		return printBundleInfo(s.stdout, format, info)
	}}
	imp.Flags().StringVar(&input, "input", "", "capture-evidence bundle")
	imp.Flags().StringVar(&output, "output", "", "new imported offline-evidence directory")
	imp.Flags().BoolVar(&force, "force", false, "atomically replace output directory")
	imp.Flags().StringVar(&format, "format", "text", "text or json")
	_ = imp.MarkFlagRequired("input")
	_ = imp.MarkFlagRequired("output")
	sign := &cobra.Command{Use: "sign", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		info, e := capturekit.SignEvidenceBundle(input, key, output, force)
		if e != nil {
			return e
		}
		if e = persistBundle(context.Background(), s.cfg.DBPath, "lab capture-kit bundle sign", info); e != nil {
			return e
		}
		return printBundleInfo(s.stdout, format, info)
	}}
	sign.Flags().StringVar(&input, "input", "", "unsigned capture-evidence bundle")
	sign.Flags().StringVar(&key, "key", "", "mode-0600 Ed25519 research signing key")
	sign.Flags().StringVar(&output, "output", "", "new signed capture-evidence bundle")
	sign.Flags().BoolVar(&force, "force", false, "atomically replace output")
	sign.Flags().StringVar(&format, "format", "text", "text or json")
	_ = sign.MarkFlagRequired("input")
	_ = sign.MarkFlagRequired("key")
	_ = sign.MarkFlagRequired("output")
	root.AddCommand(export, inspect, imp, sign, verify)
	return root
}
func printBundleInfo(w io.Writer, format string, info capturekit.EvidenceBundleInfo) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	if format != "text" {
		return errors.New("format must be text or json")
	}
	fmt.Fprintf(w, "Bundle type: %s\nBundle: %s\nKit: %s\nMembers: %d\nIntegrity: %s\nSignature: %s\nTrust effect: none\nProtocol-contract promotion: none\nLive SCCM policy requests: 0\n", info.Manifest.BundleType, info.Manifest.BundleID, info.Manifest.KitID, len(info.Manifest.Members), info.Integrity, info.SignatureState)
	return nil
}

func (s *state) guidedImportCommand() *cobra.Command {
	var kit, bundleInput, dossierOut, bundleOut, format, secretsOutput, secretsFormat, matrixPath string
	var dry, showSecrets, hideSecrets bool
	c := &cobra.Command{Use: "guided-import", Short: "Validate, inspect, and import reviewed sanitized lab captures offline", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		sourceDir := kit
		var provenance *capturekit.EvidenceBundleInfo
		var cleanup func()
		if bundleInput != "" {
			info, _, e := capturekit.InspectEvidenceBundle(bundleInput)
			if e != nil {
				return e
			}
			tmp, e := os.MkdirTemp("", "cinderpath-capture-evidence-")
			if e != nil {
				return e
			}
			cleanup = func() { _ = os.RemoveAll(tmp) }
			defer cleanup()
			sourceDir = filepath.Join(tmp, "kit")
			if _, e = capturekit.ImportEvidenceBundle(capturekit.ImportOptions{Input: bundleInput, Output: sourceDir}); e != nil {
				return e
			}
			provenance = &info
		}
		var v capturekit.Validation
		var e error
		if provenance != nil {
			v, e = capturekit.ValidateImportedEvidence(sourceDir, *provenance)
		} else {
			v, e = capturekit.Validate(sourceDir)
		}
		if e != nil {
			return e
		}
		if provenance == nil && v.State != capturekit.ReadyForImport && v.State != capturekit.ReadyForEvidenceBundle && v.State != capturekit.Imported {
			return fmt.Errorf("capture kit state %s is not ready for import", v.State)
		}
		if dry && (showSecrets || secretsOutput != "") {
			return errors.New("dry-run cannot enable plaintext secret output")
		}
		_ = hideSecrets
		_ = secretsFormat
		files := append([]capturekit.File(nil), v.Sanitized...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		type imported struct {
			Path          string `json:"path"`
			Format        string `json:"format"`
			CaptureID     string `json:"capture_id"`
			Fingerprint   string `json:"fingerprint"`
			TLSVisibility string `json:"tls_visibility"`
		}
		out := struct {
			KitID              string     `json:"kit_id"`
			State              string     `json:"state"`
			SourceType         string     `json:"source_type"`
			BundleID           string     `json:"bundle_id,omitempty"`
			SignatureState     string     `json:"signature_state,omitempty"`
			DryRun             bool       `json:"dry_run"`
			Imported           []imported `json:"imported"`
			Unsupported        []string   `json:"unsupported"`
			LivePolicyRequests int        `json:"live_policy_requests"`
			SafetyBanner       string     `json:"safety_banner"`
		}{KitID: v.KitID, State: string(v.State), SourceType: "local_kit", DryRun: dry, LivePolicyRequests: 0, SafetyBanner: "This workflow prepared or analyzed an authorized lab capture kit. CinderPath did not register a client, trigger policy retrieval, start packet capture, or send a live SCCM policy request."}
		if provenance != nil {
			out.SourceType = "capture_evidence_bundle"
			out.BundleID = provenance.Manifest.BundleID
			out.SignatureState = provenance.SignatureState
		}
		for _, f := range files {
			if f.Kind == "unsupported" || f.Kind == "windows_log" || f.Kind == "event_trace" {
				out.Unsupported = append(out.Unsupported, f.Path)
				continue
			}
			p := filepath.Join(sourceDir, f.Path)
			cap, e := loadCapture(p, "")
			if e != nil {
				return fmt.Errorf("inspect %s: %w", filepath.Base(p), e)
			}
			tls := "plaintext_or_not_observed"
			for _, flow := range cap.Flows {
				if strings.Contains(strings.ToLower(flow.State+" "+strings.Join(flow.Warnings, " ")), "tls") {
					tls = "opaque"
					break
				}
			}
			out.Imported = append(out.Imported, imported{Path: filepath.Base(p), Format: cap.Source.Format, CaptureID: cap.Source.ID, Fingerprint: cap.Source.Fingerprint, TLSVisibility: tls})
			if !dry {
				if e = s.persistCapture(cap); e != nil {
					return e
				}
			}
		}
		if len(out.Imported) == 0 {
			return errors.New("no supported reviewed sanitized capture found")
		}
		if !dry && dossierOut != "" {
			if e = capturekit.GenerateKitDossier(sourceDir, dossierOut, v, provenance, false); e != nil {
				return e
			}
		}
		if bundleOut != "" {
			if dry {
				return errors.New("dry-run does not create bundle output")
			}
			if provenance != nil {
				return errors.New("bundle input cannot also request bundle export")
			}
			if _, e = capturekit.ExportEvidenceBundle(capturekit.ExportOptions{Directory: sourceDir, Output: bundleOut, ToolVersion: version.Version}); e != nil {
				return e
			}
		}
		if !dry {
			marker, _ := json.MarshalIndent(out, "", "  ")
			if provenance == nil {
				if e = atomicCaptureWrite(filepath.Join(sourceDir, "output", "guided-import.json"), append(marker, '\n')); e != nil {
					return e
				}
				v, _ = capturekit.Validate(sourceDir)
			}
			extra := map[string]any{"import_status": "imported", "source_type": out.SourceType, "bundle_id": out.BundleID, "signature_state": out.SignatureState}
			if e = s.persistKitLifecycle(context.Background(), "capture guided-import", sourceDir, v, extra); e != nil {
				return e
			}
			if provenance != nil {
				if e = persistBundle(context.Background(), s.cfg.DBPath, "capture guided-import bundle provenance", *provenance); e != nil {
					return e
				}
			}
			if e = persistKitImport(context.Background(), s.cfg.DBPath, v, out); e != nil {
				return e
			}
			if dossierOut != "" {
				db, e := database.Open(context.Background(), s.cfg.DBPath)
				if e == nil {
					id := models.StableID("capture_kit_dossier", models.StableFingerprint(v.KitID, filepath.Base(dossierOut)))
					_ = db.UpsertCaptureRecord(context.Background(), "capture_kit_dossiers", database.CaptureRecord{ID: id, CaptureID: v.KitID, Fingerprint: v.Fingerprint, Data: map[string]any{"safe_name": filepath.Base(dossierOut), "state": "generated", "live_requests": 0}})
					_ = db.Close()
				}
			}
			if matrixPath != "" {
				if provenance != nil {
					return errors.New("matrix linking from an imported bundle requires an explicitly imported local kit")
				}
				if e = addKitToMatrix(matrixPath, sourceDir); e != nil {
					return e
				}
				if e = s.persistMatrixLink(context.Background(), matrixPath, sourceDir); e != nil {
					return e
				}
			}
		}
		if format == "json" {
			enc := json.NewEncoder(s.stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		fmt.Fprintf(s.stdout, "Kit: %s\nState: %s\nImported: %d\nUnsupported: %d\nUsable: unvalidated\nLive SCCM policy requests: 0\n%s\n", out.KitID, out.State, len(out.Imported), len(out.Unsupported), out.SafetyBanner)
		return nil
	}}
	f := c.Flags()
	f.StringVar(&kit, "kit", "", "capture-kit directory")
	f.StringVar(&bundleInput, "bundle", "", "validated capture-evidence bundle (mutually exclusive with --kit)")
	f.BoolVar(&dry, "dry-run", false, "plan without persistence, dossiers, bundles, or plaintext secret reads")
	f.StringVar(&dossierOut, "dossier-output", "", "optional new redacted dossier directory")
	f.StringVar(&bundleOut, "bundle-output", "", "optional dedicated capture-evidence bundle output")
	f.StringVar(&matrixPath, "matrix", "", "optional controlled matrix to link after local-kit import")
	f.BoolVar(&showSecrets, "show-secrets", false, "use existing deliberate offline secret display policy")
	f.BoolVar(&hideSecrets, "hide-secrets", false, "always suppress plaintext secrets")
	f.StringVar(&secretsOutput, "secrets-output", "", "optional atomic mode-0600 secure secret output")
	f.StringVar(&secretsFormat, "secrets-format", "text", "text or json")
	f.StringVar(&format, "format", "text", "text or json")
	c.PreRunE = func(*cobra.Command, []string) error {
		_, e := capturekit.SelectImportSource(kit, bundleInput)
		return e
	}
	return c
}

func persistKitImport(ctx context.Context, dbPath string, v capturekit.Validation, data any) error {
	db, e := database.Open(ctx, dbPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "capture guided-import", "safe", version.Version, []string{"offline", "redacted"})
	if e != nil {
		return e
	}
	id := models.StableID("capture_kit_import", models.StableFingerprint(v.KitID, v.Fingerprint, run.ID))
	e = db.UpsertCaptureRecord(ctx, "capture_kit_imports", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: v.KitID, Fingerprint: v.Fingerprint, Data: data})
	for _, name := range []string{"lab_capture_kit_generation_available", "windows_passive_inventory_available", "capture_kit_validation_available", "windows_log_structural_inspection_available", "capture_evidence_bundle_available", "capture_evidence_bundle_signing_available", "guided_capture_import_available", "capture_kit_matrix_integration_available"} {
		capability := models.Capability{Name: name, Available: true, State: models.CapabilityAvailable, Reason: "passive offline capture-kit workflow; no live SCCM request", Source: "capture.guided-import"}
		_, _ = db.UpsertCapability(ctx, &capability)
	}
	blocked := models.Capability{Name: "live_policy_collection_blocked", Available: false, State: models.CapabilityBlockedBySafety, Reason: "capture-kit evidence cannot authorize live collection", Source: "capture.guided-import", SafetyBlocked: true}
	_, _ = db.UpsertCapability(ctx, &blocked)
	for _, item := range []struct{ rule, title, summary string }{
		{"SCCM-LAB-CAPTURE-READY-FOR-IMPORT", "Lab capture kit passed import gates", "Reviewed sanitized input was available for bounded offline import."},
		{"SCCM-LAB-CAPTURE-IMPORTED", "Lab capture kit imported offline", "Operational research evidence only; not a vulnerability or live validation."},
	} {
		finding := models.Finding{RuleID: item.rule, Title: item.title, Summary: item.summary, Description: "Authorized lab capture-kit operational state. CinderPath sent zero live SCCM policy requests.", Severity: models.SeverityInformational, Confidence: models.ConfidenceHigh, Tags: []string{"offline_research", "capture_kit", "operational"}}
		_, _ = db.UpsertFinding(ctx, &finding)
	}
	status := models.RunCompleted
	if e != nil {
		status = models.RunFailed
	}
	_ = db.FinishRun(ctx, run.ID, status, map[string]any{"kit_id": v.KitID, "live_requests": 0})
	return e
}

func addKitToMatrix(matrixPath, kit string) error {
	v, e := capturekit.Validate(kit)
	if e != nil {
		return e
	}
	if v.State != capturekit.ReadyForImport && v.State != capturekit.ReadyForEvidenceBundle && v.State != capturekit.Imported && v.State != capturekit.EvidenceBundleExported {
		return fmt.Errorf("kit state %s is not reviewed for analysis", v.State)
	}
	m, e := readMatrix(matrixPath)
	if e != nil {
		return e
	}
	meta, e := capturekit.LoadMetadata(kit)
	if e != nil {
		return e
	}
	if len(v.Sanitized) == 0 {
		return errors.New("kit has no sanitized capture")
	}
	f := v.Sanitized[0]
	if f.Kind == "unsupported" || f.Kind == "windows_log" || f.Kind == "event_trace" {
		return errors.New("kit has no supported sanitized capture")
	}
	vars := map[string]string{"client": meta.Client.Label, "os": meta.Client.OperatingSystem, "site": meta.Client.SiteCode, "management_point": meta.Client.ManagementPoint, "client_version": meta.Client.ClientVersion, "action": meta.Capture.Action, "capture_tool": meta.Tools.PacketCapture, "format": f.Kind, "tls_visibility": "operator_declared_unknown", "signature_state": "unsigned"}
	for _, k := range append(append([]string{}, m.Controlled...), m.Fixed...) {
		if strings.TrimSpace(vars[k]) == "" {
			return fmt.Errorf("missing controlled or fixed variable: %s", k)
		}
	}
	for _, x := range m.Members {
		if x.Fingerprint == f.SHA256 {
			return errors.New("duplicate matrix cell fingerprint")
		}
	}
	m.Members = append(m.Members, capture.MatrixMember{Label: meta.Capture.Label, CapturePath: f.Path, Fingerprint: f.SHA256, Variables: vars})
	return writeYAML(matrixPath, m)
}

var _ = os.ErrNotExist
