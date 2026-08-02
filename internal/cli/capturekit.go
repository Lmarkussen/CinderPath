package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(v)
		}
		fmt.Fprintf(s.stdout, "Capture kit: %s\nState: %s\nFingerprint: %s\nRaw files: %d\nSanitized files: %d\nLive SCCM policy requests: 0\n", v.KitID, v.State, v.Fingerprint, len(v.RawFiles), len(v.Sanitized))
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
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(m)
		}
		fmt.Fprintf(s.stdout, "Capture: %s\nClient: %s\nSite: %s\nManagement point metadata: %s\nAuthorized lab assertion: %t (operator supplied, unverified)\nDisposable assertion: %t (operator supplied, unverified)\n", m.Capture.Label, m.Client.Label, m.Client.SiteCode, m.Client.ManagementPoint, m.Capture.AuthorizedLab, m.Environment.Disposable)
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
		return atomicCaptureWrite(filepath.Join(dir, "output", "linux-validation-summary.json"), append(b, '\n'))
	}}
	for _, c := range []*cobra.Command{validate, show, finalize} {
		c.Flags().StringVar(&dir, "directory", "", "capture-kit directory")
		c.Flags().StringVar(&format, "format", "text", "text or json")
		_ = c.MarkFlagRequired("directory")
	}
	root.AddCommand(create, validate, show, finalize)
	return root
}

func (s *state) guidedImportCommand() *cobra.Command {
	var kit, dossierOut, bundleOut, format, secretsOutput, secretsFormat string
	var dry, showSecrets, hideSecrets bool
	c := &cobra.Command{Use: "guided-import", Short: "Validate, inspect, and import reviewed sanitized lab captures offline", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := capturekit.Validate(kit)
		if e != nil {
			return e
		}
		if v.State != capturekit.ReadyForImport && v.State != capturekit.ReadyForBundleExport {
			return fmt.Errorf("capture kit state %s is not ready for import", v.State)
		}
		if dry && (showSecrets || secretsOutput != "") {
			return errors.New("dry-run cannot enable plaintext secret output")
		}
		_ = hideSecrets
		_ = secretsFormat
		files := append([]capturekit.File(nil), v.Sanitized...)
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		type imported struct{ Path, Format, CaptureID, Fingerprint, TLSVisibility string }
		out := struct {
			KitID, State       string
			DryRun             bool
			Imported           []imported
			Unsupported        []string
			LivePolicyRequests int
			SafetyBanner       string
		}{KitID: v.KitID, State: string(v.State), DryRun: dry, LivePolicyRequests: 0, SafetyBanner: "This workflow prepared or analyzed an authorized lab capture kit. CinderPath did not register a client, trigger policy retrieval, start packet capture, or send a live SCCM policy request."}
		var first *capture.NormalizedCapture
		for _, f := range files {
			if f.Kind == "unsupported" || f.Kind == "windows_log" || f.Kind == "event_trace" {
				out.Unsupported = append(out.Unsupported, f.Path)
				continue
			}
			p := filepath.Join(kit, f.Path)
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
			if first == nil {
				x := cap
				first = &x
			}
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
			if first == nil {
				return errors.New("dossier requires an imported capture")
			}
			if e = capture.GenerateDossier(dossierOut, capture.Analyze(*first), false); e != nil {
				return e
			}
		}
		if bundleOut != "" {
			if v.State != capturekit.ReadyForBundleExport {
				return errors.New("bundle export requires ready_for_bundle_export review state")
			}
			if dry {
				return errors.New("dry-run does not create bundle output")
			}
			return errors.New("capture-kit bundle export is unavailable: use the existing reviewed protocol bundle workflow with an observed contract")
		}
		if !dry {
			if e = persistKitImport(context.Background(), s.cfg.DBPath, v, out); e != nil {
				return e
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
	f.BoolVar(&dry, "dry-run", false, "plan without persistence, dossiers, bundles, or plaintext secret reads")
	f.StringVar(&dossierOut, "dossier-output", "", "optional new redacted dossier directory")
	f.StringVar(&bundleOut, "bundle-output", "", "optional reviewed sanitized bundle output (currently unavailable for generic captures)")
	f.BoolVar(&showSecrets, "show-secrets", false, "use existing deliberate offline secret display policy")
	f.BoolVar(&hideSecrets, "hide-secrets", false, "always suppress plaintext secrets")
	f.StringVar(&secretsOutput, "secrets-output", "", "optional atomic mode-0600 secure secret output")
	f.StringVar(&secretsFormat, "secrets-format", "text", "text or json")
	f.StringVar(&format, "format", "text", "text or json")
	_ = c.MarkFlagRequired("kit")
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
	id := models.StableID("capture_kit_import", models.StableFingerprint(v.KitID, v.Fingerprint))
	e = db.UpsertCaptureRecord(ctx, "capture_kit_imports", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: v.KitID, Fingerprint: v.Fingerprint, Data: data})
	for _, name := range []string{"lab_capture_kit_generation_available", "windows_passive_inventory_available", "capture_kit_validation_available", "guided_capture_import_available", "capture_kit_matrix_integration_available", "windows_log_inventory_available"} {
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
	if v.State != capturekit.ReadyForImport && v.State != capturekit.ReadyForBundleExport {
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
