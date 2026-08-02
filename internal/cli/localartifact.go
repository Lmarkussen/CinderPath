package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/localartifact"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
	"github.com/spf13/cobra"
)

func (s *state) clientArtifactsCommand() *cobra.Command {
	root := &cobra.Command{Use: "client-artifacts", Short: "Generate and analyze bounded read-only local SCCM artifact metadata"}
	var output, site, client, inventory, format string
	var force bool
	var maxFiles, maxClasses, maxInstances int
	discover := &cobra.Command{Use: "discover", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if e := localartifact.Create(localartifact.CreateOptions{Output: output, SiteCode: site, ClientLabel: client, MaxFiles: maxFiles, MaxClasses: maxClasses, MaxInstances: maxInstances, Force: force}); e != nil {
			return e
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(map[string]any{"output": filepath.Base(output), "script": "Discover-CinderPathPolicyArtifacts.ps1", "network_activity": "none", "live_policy_requests": 0})
		}
		fmt.Fprintf(s.stdout, "Created passive local-artifact discovery kit: %s\nScript: Discover-CinderPathPolicyArtifacts.ps1\nNetwork activity: none\nSCCM client methods invoked: 0\nLive SCCM policy requests: 0\n", filepath.Base(output))
		return nil
	}}
	discover.Flags().StringVar(&output, "output", "", "new owner-only discovery-kit directory")
	discover.Flags().StringVar(&site, "site-code", "", "safe site metadata")
	discover.Flags().StringVar(&client, "client-label", "", "safe client label")
	discover.Flags().IntVar(&maxFiles, "max-files", 2000, "generated runtime file limit (1-2000)")
	discover.Flags().IntVar(&maxClasses, "max-classes", 1024, "generated runtime class limit (1-1024)")
	discover.Flags().IntVar(&maxInstances, "max-instances", 128, "generated runtime per-class instance limit (1-128)")
	discover.Flags().BoolVar(&force, "force", false, "replace output when safely supported")
	discover.Flags().StringVar(&format, "format", "text", "text or json")
	_ = discover.MarkFlagRequired("output")
	inspect := &cobra.Command{Use: "inspect", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := localartifact.Load(inventory, localartifact.DefaultLimits())
		if e != nil {
			return e
		}
		r := localartifact.Analyze(v)
		if e = localartifact.GenerateDossier(output, r); e != nil {
			return e
		}
		if e = s.persistLocalArtifacts(r, output); e != nil {
			return e
		}
		return printLocalArtifacts(s, r, format, output)
	}}
	show := &cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := localartifact.Load(inventory, localartifact.DefaultLimits())
		if e != nil {
			return e
		}
		return printLocalArtifacts(s, localartifact.Analyze(v), format, "")
	}}
	exportPlan := &cobra.Command{Use: "export-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := localartifact.Load(inventory, localartifact.DefaultLimits())
		if e != nil {
			return e
		}
		r := localartifact.Analyze(v)
		b, e := json.MarshalIndent(map[string]any{"schema_version": 1, "inventory_fingerprint": r.InventoryFingerprint, "items": r.ExportPlan, "automatic_copies": 0, "raw_sensitive": true, "live_policy_requests": 0}, "", "  ")
		if e != nil {
			return e
		}
		return atomicCaptureWrite(output, append(b, '\n'))
	}}
	for _, c := range []*cobra.Command{inspect, show, exportPlan} {
		c.Flags().StringVar(&inventory, "inventory", "", "schema-v1 local-artifacts JSON")
		c.Flags().StringVar(&format, "format", "text", "text or json")
		_ = c.MarkFlagRequired("inventory")
	}
	inspect.Flags().StringVar(&output, "output", "", "new owner-only dossier directory")
	_ = inspect.MarkFlagRequired("output")
	exportPlan.Flags().StringVar(&output, "output", "", "mode-0600 export-plan JSON")
	_ = exportPlan.MarkFlagRequired("output")
	root.AddCommand(discover, inspect, show, exportPlan)
	return root
}

func printLocalArtifacts(s *state, r localartifact.Result, format, output string) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported output format %q", format)
	}
	if format == "json" {
		return json.NewEncoder(s.stdout).Encode(r)
	}
	fmt.Fprintf(s.stdout, "Local SCCM policy artifact discovery\nNamespaces: %d\nClass schemas: %d\nInstance metadata records: %d\nFile artifacts: %d\nRegistry artifacts: %d\nCandidates: %d\nSecret readiness: %s\n", len(r.Inventory.Namespaces), len(r.Inventory.Classes), len(r.Inventory.Instances), len(r.Inventory.Files), len(r.Inventory.Registry), len(r.Candidates), r.SecretReadiness)
	if output != "" {
		fmt.Fprintf(s.stdout, "Dossier: %s\n", filepath.Base(output))
	}
	for i, c := range r.Candidates {
		if i >= 10 {
			fmt.Fprintln(s.stdout, "Candidate output truncated at 10 rows")
			break
		}
		fmt.Fprintf(s.stdout, "  %s source=%s role=%s confidence=%s secret_likelihood=%s copy_eligible=%t\n", c.CandidateID, c.SourceType, c.PolicyRole, c.Confidence, c.SecretLikelihood, c.CopyEligible)
	}
	fmt.Fprintln(s.stdout, "Safety: read-only metadata; no SCCM method invocation, policy retrieval, credential extraction, or live request.")
	fmt.Fprintln(s.stdout, "Live SCCM policy requests: 0")
	return nil
}

func (s *state) persistLocalArtifacts(r localartifact.Result, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab client-artifacts inspect", string(s.cfg.Profile), version.Version, []string{"offline", "local_read_only", "redacted", "live_requests=0"})
	if e != nil {
		return e
	}
	rid := models.StableID("local_artifact_run", r.InventoryFingerprint)
	data := map[string]any{"inventory_fingerprint": r.InventoryFingerprint, "namespace_count": len(r.Inventory.Namespaces), "class_count": len(r.Inventory.Classes), "instance_count": len(r.Inventory.Instances), "file_count": len(r.Inventory.Files), "registry_count": len(r.Inventory.Registry), "candidates": r.Candidates, "secret_readiness": r.SecretReadiness, "dossier": filepath.Base(dossier), "live_policy_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: rid, RunID: run.ID, CaptureID: "local_artifacts", Fingerprint: r.InventoryFingerprint, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"local_artifact_run": rid, "live_requests": 0})
}
