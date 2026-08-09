package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/pxe"
	"github.com/Lmarkussen/CinderPath/internal/version"
	"github.com/spf13/cobra"
)

func (s *state) pxeCommand() *cobra.Command {
	root := &cobra.Command{Use: "pxe", Short: "Bounded offline and server-local PXE/OSD posture assessment"}
	var alias, site, output, format, input string
	candidates := &cobra.Command{Use: "candidates", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		c := pxe.CandidateFromEvidence(alias, site, []string{"sccm_site_server"}, []string{"GOAD SCCM inventory membership"})
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(c)
		}
		fmt.Fprintf(s.stdout, "PXE/OSD server candidates\nCandidates: 1\n  %s\nSafety: inventory evidence only; port-only evidence is insufficient.\nLive PXE requests: 0\n", pxe.RedactedCandidateText(c))
		return nil
	}}
	candidates.Flags().StringVar(&alias, "candidate", "", "exact approved inventory alias")
	candidates.Flags().StringVar(&site, "site-code", "", "safe SCCM site code")
	candidates.Flags().StringVar(&format, "format", "text", "text or json")
	_ = candidates.MarkFlagRequired("candidate")
	plan := &cobra.Command{Use: "inspect-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		c := pxe.CandidateFromEvidence(alias, site, []string{"sccm_site_server"}, []string{"GOAD SCCM inventory membership"})
		p := pxe.BuildPlan(c)
		if e := pxe.WritePlan(output, p); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "PXE/OSD inspection plan\nCandidate: %s\nMaximum targets: 1\nMaximum commands: %d\nConnection: %s\nCredential source: %s\nStop conditions: authentication failure; endpoint mismatch; write requirement; additional target\nLive PXE requests: 0\n", c.CandidateID, p.MaximumCommands, p.ConnectionMethod, p.CredentialSource)
		return nil
	}}
	plan.Flags().StringVar(&alias, "candidate", "", "exact approved inventory alias")
	plan.Flags().StringVar(&site, "site-code", "", "safe SCCM site code")
	plan.Flags().StringVar(&output, "output", "", "mode-0600 inspection plan")
	_ = plan.MarkFlagRequired("candidate")
	collector := &cobra.Command{Use: "collector-script", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return atomicCaptureWrite(output, []byte(pxe.CollectorPowerShell()))
	}}
	collector.Flags().StringVar(&output, "output", "", "generated Windows PowerShell 5.1 collector")
	analyze := &cobra.Command{Use: "analyze", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := pxe.LoadRuntime(input)
		if e != nil {
			return e
		}
		c := pxe.CandidateFromEvidence(alias, site, []string{"sccm_site_server"}, []string{"GOAD SCCM inventory membership"})
		p := pxe.BuildPlan(c)
		a := pxe.Analyze(c, p, r)
		if e = pxe.WriteDossier(output, a); e != nil {
			return e
		}
		if e = s.persistPXE(a, output); e != nil {
			return e
		}
		if format == "json" {
			return json.NewEncoder(s.stdout).Encode(a)
		}
		fmt.Fprintf(s.stdout, "SCCM PXE/OSD posture assessment\nCandidate servers: 1\nConfirmed inventory roles: %v\nPXE responder: %s\nWDS installed: %t\nConfigMgr PXE responder installed: %t\nPXE enabled: %t\nUnknown-computer posture: %s\nPXE password posture: %s\nBoot images: %d state=%s\nPXE deployments: %d state=%s\nAssessment: %s\nActive validation: %s\nMisconfiguration Manager: pxe_dp_assessment=assessment_supported pxe_unknown_computer=discovery_supported\nDossier: %s\nLive PXE requests: 0\n", a.Candidate.ObservedRoles, a.PXEResponderType, a.WDSInstalled, a.ConfigMgrPXEResponderInstalled, a.PXEEnabled, a.UnknownComputerPosture, a.PXEPasswordPosture, a.BootImageCount, a.BootImageMetadataState, a.PXEDeploymentCount, a.DeploymentMetadataState, a.Classification, a.ActiveValidationReadiness, filepath.Base(output))
		return nil
	}}
	analyze.Flags().StringVar(&input, "inventory", "", "schema-v1 returned PXE posture metadata")
	analyze.Flags().StringVar(&alias, "candidate", "", "exact approved inventory alias")
	analyze.Flags().StringVar(&site, "site-code", "", "safe SCCM site code")
	analyze.Flags().StringVar(&output, "output", "", "new owner-only PXE assessment dossier")
	analyze.Flags().StringVar(&format, "format", "text", "text or json")
	_ = analyze.MarkFlagRequired("inventory")
	_ = analyze.MarkFlagRequired("candidate")
	root.AddCommand(candidates, plan, collector, analyze)
	var providerServer, providerSite, providerOutput string
	providerPlan := &cobra.Command{Use: "provider-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		c := pxe.CandidateFromEvidence(providerServer, providerSite, []string{"sccm_site_server", "pxe_enabled_distribution_point"}, []string{"existing PXE posture assessment"})
		p := pxe.BuildPlan(c)
		p.ReadOnlyChecks = []string{"root\\SMS provider availability", "root\\SMS\\site_" + providerSite + " exact class schemas", "bounded selected provider instance metadata", "bounded redacted smspxe templates"}
		if e := pxe.WritePlan(providerOutput, p); e != nil {
			return e
		}
		fmt.Fprintf(s.stdout, "PXE provider inspection plan\nCandidate: %s\nNamespaces: root\\SMS, root\\SMS\\site_%s\nMaximum structurally selected classes: 32\nMaximum targets: 1\nSQL access: prohibited\nTask-sequence bodies: prohibited\nLive PXE requests: 0\n", c.CandidateID, providerSite)
		return nil
	}}
	providerPlan.Flags().StringVar(&providerServer, "server", "", "exact approved SCCM provider alias")
	providerPlan.Flags().StringVar(&providerSite, "site-code", "", "safe site code")
	providerPlan.Flags().StringVar(&providerOutput, "output", "", "mode-0600 provider plan")
	_ = providerPlan.MarkFlagRequired("server")
	_ = providerPlan.MarkFlagRequired("site-code")
	deploymentCollector := &cobra.Command{Use: "deployment-metadata", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return atomicCaptureWrite(providerOutput, []byte(pxe.DeploymentCollectorPowerShell(providerSite)))
	}}
	deploymentCollector.Flags().StringVar(&providerSite, "site-code", "", "safe site code embedded in exact provider namespace")
	deploymentCollector.Flags().StringVar(&providerOutput, "output", "", "generated Windows PowerShell 5.1 collector")
	_ = deploymentCollector.MarkFlagRequired("site-code")
	var deploymentInput, deploymentDossier, deploymentFormat string
	analyzeDeployments := &cobra.Command{Use: "analyze-deployments", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		r, e := pxe.LoadDeploymentRuntime(deploymentInput)
		if e != nil {
			return e
		}
		a := pxe.AnalyzeDeployments(r)
		if e = pxe.WriteDeploymentDossier(deploymentDossier, a); e != nil {
			return e
		}
		if e = s.persistPXEDeployments(a, deploymentDossier); e != nil {
			return e
		}
		if deploymentFormat == "json" {
			return json.NewEncoder(s.stdout).Encode(a)
		}
		fmt.Fprintf(s.stdout, "SCCM PXE deployment metadata assessment\nProvider available: %t\nNamespaces inspected: %d\nClasses inspected: %d\nTask sequences observed: %d\nDeployments observed: %d\nPXE-available deployments: %d\nUnknown-computer deployments: %d\nBoot-image relationships: %d\nPXE password posture: %s\nLog observations: %d\nAssessment: %s\nActive validation: %s\nDossier: %s\nTask-sequence bodies read: 0\nCollection members read: 0\nSQL queries: 0\nLive PXE requests: 0\n", a.ProviderAvailable, len(r.Namespaces), len(r.Classes), a.TaskSequenceCount, a.DeploymentCount, a.PXEDeploymentCount, a.UnknownComputerDeploymentCount, a.BootRelationshipCount, a.PXEPasswordPosture, len(r.LogObservations), a.Classification, a.ActiveValidationReadiness, filepath.Base(deploymentDossier))
		return nil
	}}
	analyzeDeployments.Flags().StringVar(&deploymentInput, "deployments", "", "schema-v1 returned provider metadata")
	analyzeDeployments.Flags().StringVar(&deploymentDossier, "output", "", "new owner-only deployment dossier")
	analyzeDeployments.Flags().StringVar(&deploymentFormat, "format", "text", "text or json")
	_ = analyzeDeployments.MarkFlagRequired("deployments")
	root.AddCommand(providerPlan, deploymentCollector, analyzeDeployments)
	return root
}

func (s *state) persistPXE(a pxe.Assessment, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab pxe analyze", string(s.cfg.Profile), version.Version, []string{"offline", "server_local_read_only", "live_pxe_requests=0"})
	if e != nil {
		return e
	}
	id := models.StableID("pxe_assessment", a.Candidate.ServerFingerprint+"|"+a.Runtime.CollectedAt)
	data := map[string]any{"candidate": a.Candidate, "role_evidence": a.PXEResponderType, "services": a.Runtime.Services, "registry_metadata": a.Runtime.Registry, "log_metadata": a.Runtime.Logs, "boot_image_count": a.BootImageCount, "deployment_count": a.PXEDeploymentCount, "unknown_computer_posture": a.UnknownComputerPosture, "pxe_password_posture": a.PXEPasswordPosture, "classification": a.Classification, "readiness": a.ActiveValidationReadiness, "dossier": filepath.Base(dossier), "live_pxe_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: "pxe_assessment", Fingerprint: a.Candidate.ServerFingerprint, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"pxe_assessment": id, "live_pxe_requests": 0})
}

func (s *state) persistPXEDeployments(a pxe.DeploymentAssessment, dossier string) error {
	ctx := context.Background()
	db, e := database.Open(ctx, s.cfg.DBPath)
	if e != nil {
		return e
	}
	defer db.Close()
	run, e := db.CreateRun(ctx, "lab pxe analyze-deployments", string(s.cfg.Profile), version.Version, []string{"offline", "provider_metadata", "no_content", "live_pxe_requests=0"})
	if e != nil {
		return e
	}
	id := models.StableID("pxe_deployment_assessment", a.Runtime.CollectedAt)
	data := map[string]any{"provider_available": a.ProviderAvailable, "namespace_count": len(a.Runtime.Namespaces), "class_count": len(a.Runtime.Classes), "task_sequence_count": a.TaskSequenceCount, "deployment_count": a.DeploymentCount, "pxe_deployment_count": a.PXEDeploymentCount, "unknown_computer_deployment_count": a.UnknownComputerDeploymentCount, "relationships": a.Relationships, "password_posture": a.PXEPasswordPosture, "classification": a.Classification, "readiness": a.ActiveValidationReadiness, "dossier": filepath.Base(dossier), "live_pxe_requests": 0}
	if e = db.UpsertCaptureRecord(ctx, "capture_observations", database.CaptureRecord{ID: id, RunID: run.ID, CaptureID: "pxe_deployment_assessment", Fingerprint: id, Data: data}); e != nil {
		return e
	}
	return db.FinishRun(ctx, run.ID, models.RunCompleted, map[string]any{"pxe_deployment_assessment": id, "live_pxe_requests": 0})
}
