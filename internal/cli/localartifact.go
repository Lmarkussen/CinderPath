package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

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
	schemaCommand := func(use string, dossier bool) *cobra.Command {
		var schemaInventory, schemaOutput, schemaFormat string
		var schemaMaxClasses, schemaMaxInstances int
		var schemaIncludeIntrinsic bool
		cmd := &cobra.Command{Use: use, Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
			v, e := localartifact.Load(schemaInventory, localartifact.DefaultLimits())
			if e != nil {
				return e
			}
			a := localartifact.AnalyzeSchemas(v, localartifact.SchemaOptions{MaxClasses: schemaMaxClasses, MaxInstances: schemaMaxInstances, IncludeIntrinsic: schemaIncludeIntrinsic})
			if dossier {
				if e = localartifact.GenerateSchemaDossier(schemaOutput, a); e != nil {
					return e
				}
				if e = s.persistPolicySchemaAnalysis(a, schemaOutput); e != nil {
					return e
				}
			} else if schemaOutput != "" {
				b, _ := json.MarshalIndent(a, "", "  ")
				if e = atomicCaptureWrite(schemaOutput, append(b, '\n')); e != nil {
					return e
				}
			}
			return printSchemaAnalysis(s, a, schemaFormat, use, schemaOutput)
		}}
		cmd.Flags().StringVar(&schemaInventory, "inventory", "", "schema-v1 local-artifacts JSON")
		cmd.Flags().StringVar(&schemaOutput, "output", "", "new dossier directory or mode-0600 JSON")
		cmd.Flags().IntVar(&schemaMaxClasses, "max-classes", 96, "maximum selected concrete classes (1-96)")
		cmd.Flags().IntVar(&schemaMaxInstances, "max-instances", 2000, "maximum planned total instances (1-2000)")
		cmd.Flags().BoolVar(&schemaIncludeIntrinsic, "include-intrinsic", false, "include intrinsic classes diagnostically; never grants content eligibility")
		cmd.Flags().StringVar(&schemaFormat, "format", "text", "text or json")
		_ = cmd.MarkFlagRequired("inventory")
		if dossier {
			_ = cmd.MarkFlagRequired("output")
		}
		return cmd
	}
	root.AddCommand(discover, inspect, show, exportPlan, schemaCommand("rank-schemas", false), schemaCommand("plan-instances", false), schemaCommand("inspect-instances", true), schemaCommand("parser-status", false), schemaCommand("content-plan", false))
	var previewInventory, previewOutput, previewScript string
	previewPlan := &cobra.Command{Use: "preview-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		v, e := localartifact.Load(previewInventory, localartifact.DefaultLimits())
		if e != nil {
			return e
		}
		p := localartifact.BuildPreviewPlan(v)
		if e = localartifact.WritePreviewPlan(previewOutput, previewScript, p); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "SCCM policy property preview plan\nCandidates planned: %d\nMaximum preview characters: 256\nRaw-copy eligible: 0\nSCCM client methods invoked: 0\nLive SCCM policy requests: 0\n", len(p.Candidates))
		return nil
	}}
	previewPlan.Flags().StringVar(&previewInventory, "inventory", "", "schema-v1 local-artifacts JSON")
	previewPlan.Flags().StringVar(&previewOutput, "output", "", "mode-0600 preview plan JSON")
	previewPlan.Flags().StringVar(&previewScript, "script-output", "", "generated exact-allowlist PowerShell collector")
	_ = previewPlan.MarkFlagRequired("inventory")
	_ = previewPlan.MarkFlagRequired("output")
	_ = previewPlan.MarkFlagRequired("script-output")
	var previewInput, planInput, previewDossier, previewFormat string
	inspectPreviews := &cobra.Command{Use: "inspect-previews", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		p, e := localartifact.LoadPreviewPlan(planInput)
		if e != nil {
			return e
		}
		c, e := localartifact.LoadPreviewCollection(previewInput)
		if e != nil {
			return e
		}
		a := localartifact.AnalyzePreviews(p, c)
		if e = localartifact.GeneratePreviewDossier(previewDossier, a); e != nil {
			return e
		}
		if e = s.persistPreviewAnalysis(a, previewDossier); e != nil {
			return e
		}
		if previewFormat == "json" {
			return json.NewEncoder(s.stdout).Encode(a)
		}
		well, emitted, rejected := 0, 0, 0
		for _, x := range c.Previews {
			if x.Structure.WellFormed {
				well++
			}
			if x.PreviewEmitted {
				emitted++
			}
			if x.PreviewRejected {
				rejected++
			}
		}
		fmt.Fprintf(s.stdout, "Reviewed SCCM policy property previews\nCandidates planned: %d\nCandidates found: %d\nProperties read: %d\nWell-formed XML: %d\nMalformed XML: %d\nPreviews emitted: %d\nPreviews rejected: %d\nRaw-copy candidates: 0\nRaw values copied: 0\nSecret readiness: %s\nDossier: %s\n", c.CandidatesPlanned, c.CandidatesFound, c.PropertiesRead, well, len(c.Previews)-well, emitted, rejected, a.Readiness, filepath.Base(previewDossier))
		for _, x := range a.Classifications {
			fmt.Fprintf(s.stdout, "  %s classification=%s confidence=%s raw_copy=%s\n", x.CandidateID, x.Classification, x.Confidence, x.RawCopyRecommendation)
		}
		fmt.Fprintln(s.stdout, "Safety: structure-only redacted previews; no SCCM methods, policy retrieval, raw copy, credential extraction, or live request.\nLive SCCM policy requests: 0")
		return nil
	}}
	inspectPreviews.Flags().StringVar(&previewInput, "input", "", "schema-v1 property preview JSON")
	inspectPreviews.Flags().StringVar(&planInput, "plan", "", "matching preview plan JSON")
	inspectPreviews.Flags().StringVar(&previewDossier, "output", "", "new owner-only preview dossier")
	inspectPreviews.Flags().StringVar(&previewFormat, "format", "text", "text or json")
	_ = inspectPreviews.MarkFlagRequired("input")
	_ = inspectPreviews.MarkFlagRequired("plan")
	_ = inspectPreviews.MarkFlagRequired("output")
	root.AddCommand(previewPlan, inspectPreviews)
	credentialTargets := &cobra.Command{Use: "credential-targets", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		t := localartifact.CredentialTargets()
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(t)
		}
		fmt.Fprintf(s.stdout, "SCCM credential-policy target registry\nRegistry schema: 1\nTargets: %d\n", len(t))
		for _, x := range t {
			fmt.Fprintf(s.stdout, "  %s category=%s support=%s\n", x.TargetID, x.Category, x.SupportLevel)
		}
		fmt.Fprintln(s.stdout, "Safety: detection metadata only; no decryption, SCCM method, policy retrieval, or live request.\nLive SCCM policy requests: 0")
		return nil
	}}
	credentialTargets.Flags().StringVar(&format, "format", "text", "text or json")
	var credInventory, credOutput, credFormat, credScript, credRuntime string
	findCredentials := &cobra.Command{Use: "find-credential-policies", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		v, e := localartifact.Load(credInventory, localartifact.DefaultLimits())
		if e != nil {
			return e
		}
		if credRuntime != "" {
			x, le := localartifact.LoadCredentialRuntime(credRuntime)
			if le != nil {
				return le
			}
			v.Instances = x
		}
		a := localartifact.AnalyzeCredentialPolicies(v)
		if credOutput != "" {
			if e = localartifact.WriteCredentialAnalysis(credOutput, a); e != nil {
				return e
			}
		}
		if credScript != "" {
			if e = atomicCaptureWrite(credScript, []byte(localartifact.CredentialCollectorPowerShell(a))); e != nil {
				return e
			}
		}
		if e = s.persistCredentialAnalysis(a, credOutput); e != nil {
			return e
		}
		if credFormat == "json" {
			return json.NewEncoder(s.stdout).Encode(a)
		}
		selected, strong, medium, weak, opaque := 0, 0, 0, 0, 0
		for _, m := range a.SchemaMatches {
			if m.Selected {
				selected++
			}
			strong += len(m.StrongEvidence)
			medium += len(m.MediumEvidence)
			weak += len(m.WeakEvidence)
		}
		for _, c := range a.Instances {
			opaque += c.OpaqueFields
		}
		fmt.Fprintf(s.stdout, "Targeted SCCM credential-policy discovery\nTargets evaluated: %d\nSchemas matched: %d\nClasses selected: %d\nInstances observed: %d\nNAA candidates: %d\nTask-sequence candidates: %d\nVariable candidates: %d\nOpaque/protected fields: %d\nPreview candidates: %d\nRaw-copy candidates: 0\nEvidence signals: strong=%d medium=%d weak=%d\nReadiness: %s\n", len(a.Targets), len(a.SchemaMatches), selected, len(a.Instances), len(a.NAACandidates), len(a.TaskSequenceCandidates), len(a.VariableCandidates), opaque, len(a.PreviewPlan), strong, medium, weak, a.Readiness)
		for i, m := range a.SchemaMatches {
			if i >= 12 {
				fmt.Fprintln(s.stdout, "Schema output truncated at 12 rows")
				break
			}
			fmt.Fprintf(s.stdout, "  %s\\%s targets=%s score=%d confidence=%s selected=%t\n", m.Namespace, m.Class, strings.Join(m.TargetIDs, ","), m.Score, m.Confidence, m.Selected)
		}
		fmt.Fprintln(s.stdout, "Safety: targeted offline/read-only metadata; no SCCM methods, policy retrieval, raw copy, decryption, or live request.\nLive SCCM policy requests: 0")
		return nil
	}}
	findCredentials.Flags().StringVar(&credInventory, "inventory", "", "schema-v1 retained local-artifact inventory")
	findCredentials.Flags().StringVar(&credOutput, "output", "", "new owner-only credential-policy dossier")
	findCredentials.Flags().StringVar(&credScript, "script-output", "", "generated exact-class-allowlist PowerShell metadata collector")
	findCredentials.Flags().StringVar(&credRuntime, "runtime-metadata", "", "optional schema-v1 exact-allowlist runtime instance metadata")
	findCredentials.Flags().StringVar(&credFormat, "format", "text", "text or json")
	_ = findCredentials.MarkFlagRequired("inventory")
	root.AddCommand(credentialTargets, findCredentials)
	return root
}

func (s *state) persistCredentialAnalysis(a localartifact.CredentialAnalysis, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab client-artifacts find-credential-policies", string(s.cfg.Profile), version.Version, []string{"offline", "targeted", "redacted", "raw_copies=0", "live_requests=0"})
	if e != nil {
		return e
	}
	id := models.StableID("credential_policy_analysis", a.InventoryFingerprint+"|"+a.AlgorithmVersion)
	data := map[string]any{"targets": a.Targets, "schema_matches": a.SchemaMatches, "instances": a.Instances, "relationships": a.Relationships, "preview_plan": a.PreviewPlan, "content_plan": a.ContentPlan, "readiness": a.Readiness, "dossier": filepath.Base(dossier), "raw_values_copied": 0, "live_policy_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: "credential_policy_analysis", Fingerprint: a.InventoryFingerprint, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"credential_policy_analysis": id, "live_requests": 0})
}

func (s *state) persistPreviewAnalysis(a localartifact.PreviewAnalysis, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab client-artifacts inspect-previews", string(s.cfg.Profile), version.Version, []string{"offline", "redacted_preview", "raw_copies=0", "live_requests=0"})
	if e != nil {
		return e
	}
	finger := models.StableID("policy_preview", a.Plan.InventoryFingerprint)
	data := map[string]any{"candidate_fingerprints": a.Plan.Candidates, "property_hashes": a.Collection.Previews, "xml_structures": a.Structures, "semantic_classifications": a.Classifications, "parser_lifecycle": a.Parsers, "export_decisions": a.RawExportDecisions, "readiness": a.Readiness, "dossier": filepath.Base(dossier), "raw_values_copied": 0, "live_policy_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: finger, RunID: run.ID, CaptureID: "policy_previews", Fingerprint: a.Plan.InventoryFingerprint, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"policy_preview": finger, "live_requests": 0})
}

func (s *state) persistPolicySchemaAnalysis(a localartifact.SchemaAnalysis, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab client-artifacts inspect-instances", string(s.cfg.Profile), version.Version, []string{"offline", "local_read_only", "schema_analysis", "live_requests=0"})
	if e != nil {
		return e
	}
	rid := models.StableID("policy_schema_analysis", a.InventoryFingerprint+"|"+a.AlgorithmVersion)
	data := map[string]any{"schema_rankings": a.Rankings, "schema_families": a.Families, "instance_selection_plan": a.InstancePlan, "instance_fingerprints": a.SelectedInstances, "relationship_edges": a.Relationships, "parser_lifecycle": a.Parsers, "content_plan": a.ContentPlan, "secret_readiness": a.Readiness, "dossier": filepath.Base(dossier), "live_policy_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: rid, RunID: run.ID, CaptureID: "policy_schema_analysis", Fingerprint: a.InventoryFingerprint, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"policy_schema_analysis": rid, "live_requests": 0})
}

func printSchemaAnalysis(s *state, a localartifact.SchemaAnalysis, format, operation, output string) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("unsupported output format %q", format)
	}
	if format == "json" {
		return json.NewEncoder(s.stdout).Encode(a)
	}
	selected := 0
	excluded := 0
	eligible := 0
	for _, p := range a.InstancePlan {
		if p.Selected {
			selected++
		}
	}
	for _, r := range a.Rankings {
		if r.ExcludedByDefault {
			excluded++
		}
	}
	for _, p := range a.ContentPlan {
		if p.Eligible {
			eligible++
		}
	}
	fmt.Fprintf(s.stdout, "SCCM policy schema analysis\nOperation: %s\nSchemas ranked: %d\nIntrinsic/noise excluded by default: %d\nSchema families: %d\nClasses selected for bounded instance inspection: %d\nConcrete selected instances: %d\nRelationship edges: %d\nParser-relevant preview candidates: %d\nContent copied: 0\nSecret readiness: %s\n", operation, len(a.Rankings), excluded, len(a.Families), selected, len(a.SelectedInstances), len(a.Relationships), eligible, a.Readiness)
	if output != "" {
		fmt.Fprintf(s.stdout, "Output: %s\n", filepath.Base(output))
	}
	for i, r := range a.Rankings {
		if i == 10 {
			fmt.Fprintln(s.stdout, "Schema ranking truncated at 10 rows")
			break
		}
		fmt.Fprintf(s.stdout, "  %s\\%s classification=%s score=%d confidence=%s selected=%t\n", r.Namespace, r.Class, r.Classification, r.Score, r.Confidence, planSelected(a.InstancePlan, r.SchemaID))
	}
	fmt.Fprintln(s.stdout, "Safety: offline/read-only metadata; no SCCM methods, policy retrieval, content copy, credential extraction, or live request.")
	fmt.Fprintln(s.stdout, "Live SCCM policy requests: 0")
	return nil
}
func planSelected(p []localartifact.InstanceSelection, id string) bool {
	for _, x := range p {
		if x.SchemaID == id {
			return x.Selected
		}
	}
	return false
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
