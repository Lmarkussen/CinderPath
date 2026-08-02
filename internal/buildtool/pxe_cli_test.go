package buildtool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPXECLI(t *testing.T) {
	d := t.TempDir()
	out, stderr, e := runCLI(t, "lab", "pxe", "candidates", "--candidate", "synthetic-sccm", "--site-code", "ABC")
	if e != nil || !strings.Contains(out, "Live PXE requests: 0") {
		t.Fatalf("%v %s %s", e, out, stderr)
	}
	plan := filepath.Join(d, "plan.json")
	if out, stderr, e = runCLI(t, "lab", "pxe", "inspect-plan", "--candidate", "synthetic-sccm", "--output", plan); e != nil || !strings.Contains(out, "Maximum targets: 1") {
		t.Fatalf("%v %s %s", e, out, stderr)
	}
	script := filepath.Join(d, "collector.ps1")
	if _, stderr, e = runCLI(t, "lab", "pxe", "collector-script", "--output", script); e != nil {
		t.Fatalf("%v %s", e, stderr)
	}
	runtime := filepath.Join(d, "runtime.json")
	data := `{"schema_version":1,"collected_at":"2026-01-01T00:00:00Z","services":[{"Name":"SccmPxe","State":"Running","StartMode":"Auto","Present":true}],"features":[],"registry_metadata":[{"KeyFingerprint":"x","SafeKeyLabel":"DP","ValueName":"SupportUnknownMachines","ValueType":"Int32","ValueShape":"integer","SafeState":"enabled"}],"log_metadata":[],"boot_image_metadata":[],"task_sequence_deployment_metadata":[],"sccm_methods_invoked":0,"live_pxe_requests":0,"tftp_requests":0,"dhcp_requests":0,"content_downloads":0}`
	if e = os.WriteFile(runtime, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	dossier := filepath.Join(d, "dossier")
	out, stderr, e = runCLI(t, "--db", filepath.Join(d, "db.sqlite"), "lab", "pxe", "analyze", "--inventory", runtime, "--candidate", "synthetic-sccm", "--output", dossier)
	if e != nil || !strings.Contains(out, "PXE enabled: true") || !strings.Contains(out, "Live PXE requests: 0") {
		t.Fatalf("%v %s %s", e, out, stderr)
	}
	providerPlan := filepath.Join(d, "provider-plan.json")
	if out, stderr, e = runCLI(t, "lab", "pxe", "provider-plan", "--server", "synthetic-sccm", "--site-code", "ABC", "--output", providerPlan); e != nil || !strings.Contains(out, "Maximum structurally selected classes: 32") {
		t.Fatalf("%v %s %s", e, out, stderr)
	}
	deploymentScript := filepath.Join(d, "deployment.ps1")
	if _, stderr, e = runCLI(t, "lab", "pxe", "deployment-metadata", "--site-code", "ABC", "--output", deploymentScript); e != nil {
		t.Fatalf("%v %s", e, stderr)
	}
	deploymentRuntime := filepath.Join(d, "deployment.json")
	deploymentData := `{"schema_version":1,"collected_at":"2026-01-01T00:00:00Z","provider_available":true,"namespaces":[],"classes":[],"task_sequences":[],"deployments":[],"collection_targets":[],"boot_images":[],"log_observations":[],"pxe_password_posture":"pxe_password_status_unknown","sccm_methods_invoked":0,"live_pxe_requests":0,"sql_queries":0,"content_downloads":0}`
	if e = os.WriteFile(deploymentRuntime, []byte(deploymentData), 0600); e != nil {
		t.Fatal(e)
	}
	if out, stderr, e = runCLI(t, "--db", filepath.Join(d, "deployment.sqlite"), "lab", "pxe", "analyze-deployments", "--deployments", deploymentRuntime, "--output", filepath.Join(d, "deployment-dossier")); e != nil || !strings.Contains(out, "Provider available: true") || !strings.Contains(out, "Live PXE requests: 0") {
		t.Fatalf("%v %s %s", e, out, stderr)
	}
}
