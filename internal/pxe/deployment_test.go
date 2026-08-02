package pxe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentAssessmentReadiness(t *testing.T) {
	r := DeploymentRuntime{SchemaVersion: 1, ProviderAvailable: true, TaskSequences: []TaskSequence{{Fingerprint: "ts", PackageFingerprint: "pkg", BootImageFingerprint: "boot"}}, Deployments: []Deployment{{Fingerprint: "dep", PackageFingerprint: "pkg", CollectionFingerprint: "unknown", Availability: "pxe_available", UnknownComputerTarget: true}}, Collections: []CollectionTarget{{Fingerprint: "unknown", UnknownComputer: true}}, BootImages: []BootImageMetadata{{PackageFingerprint: "boot"}}, PXEPasswordPosture: "pxe_password_configured"}
	a := AnalyzeDeployments(r)
	if a.Classification != "pxe_active_validation_justified" || a.PXEDeploymentCount != 1 || a.UnknownComputerDeploymentCount != 1 || a.BootRelationshipCount != 1 {
		t.Fatalf("%+v", a)
	}
}
func TestDeploymentAssessmentConservative(t *testing.T) {
	r := DeploymentRuntime{SchemaVersion: 1, ProviderAvailable: true, TaskSequences: []TaskSequence{{Fingerprint: "ts", PackageFingerprint: "pkg"}}, Deployments: []Deployment{{Fingerprint: "dep", PackageFingerprint: "pkg", Availability: "availability_unknown"}}}
	a := AnalyzeDeployments(r)
	if a.ActiveValidationReadiness != "not_justified" || a.PXEDeploymentCount != 0 || a.Classification != "pxe_deployment_metadata_observed" {
		t.Fatalf("%+v", a)
	}
}
func TestDeploymentAssessmentProviderNegativeResult(t *testing.T) {
	a := AnalyzeDeployments(DeploymentRuntime{SchemaVersion: 1, ProviderAvailable: true})
	if a.Classification != "pxe_present_no_exposure_established" || len(a.Findings) != 1 || a.Findings[0].ID != "SCCM-PXE-EVIDENCE-INSUFFICIENT" {
		t.Fatalf("%+v", a)
	}
}
func TestDeploymentCollectorSafety(t *testing.T) {
	s := DeploymentCollectorPowerShell("P01")
	for _, w := range []string{"$site='P01'", "root\\SMS\\site_", "*TaskSequence*", "*Advertisement*", "$candidates.Count-ge512", "Select-Object -First 32", "$total-ge2000", "Select-Object -First 256", "Task-sequence bodies read: 0", "SQL queries: 0", "Live PXE requests: 0", "FileShare]::ReadWrite"} {
		if !strings.Contains(s, w) {
			t.Fatalf("missing %s", w)
		}
	}
	for _, bad := range []string{"Invoke-CimMethod", "Invoke-WmiMethod", "Set-CimInstance", "Set-WmiInstance", "New-CimInstance", "Remove-CimInstance", "Invoke-Sqlcmd", "sqlcmd", "Start-BitsTransfer", "Invoke-WebRequest", "tftp", "wdsutil", "Set-ItemProperty", "Restart-Service", "SequenceData", "CollectionMembers"} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(bad)) {
			t.Fatalf("forbidden %s", bad)
		}
	}
	if strings.Contains(s, "return@") {
		t.Fatal("PowerShell 5.1-incompatible return syntax")
	}
	if strings.Contains(s, "return$") {
		t.Fatal("PowerShell return expression lacks required whitespace")
	}
	if strings.Contains(s, "return'") || strings.Contains(s, "return(") {
		t.Fatal("PowerShell return expression lacks required whitespace")
	}
	if strings.Contains(strings.ToLower(s), "$pid=") {
		t.Fatal("PowerShell reserved PID variable overwritten")
	}
	if strings.Contains(s, "CimClassMethods.Keys") {
		t.Fatal("provider method collection incorrectly treated as a dictionary")
	}
}
func TestDeploymentDossierModes(t *testing.T) {
	d := filepath.Join(t.TempDir(), "d")
	if e := WriteDeploymentDossier(d, AnalyzeDeployments(DeploymentRuntime{SchemaVersion: 1})); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(d)
	if st.Mode().Perm() != 0700 {
		t.Fatal(st.Mode())
	}
	es, _ := os.ReadDir(d)
	if len(es) != 12 {
		t.Fatalf("files=%d", len(es))
	}
	for _, e := range es {
		st, _ := e.Info()
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s %v", e.Name(), st.Mode())
		}
	}
}
func TestDeploymentRuntimeSafety(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(p, []byte(`{"schema_version":1,"provider_available":false,"namespaces":[],"classes":[],"task_sequences":[],"deployments":[],"collection_targets":[],"boot_images":[],"log_observations":[],"pxe_password_posture":"pxe_password_status_unknown","sccm_methods_invoked":0,"live_pxe_requests":0,"sql_queries":1,"content_downloads":0}`), 0600)
	if _, e := LoadDeploymentRuntime(p); e == nil {
		t.Fatal("SQL state accepted")
	}
}
func FuzzPXEDeploymentRuntime(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"provider_available":false,"namespaces":[],"classes":[],"task_sequences":[],"deployments":[],"collection_targets":[],"boot_images":[],"log_observations":[],"pxe_password_posture":"pxe_password_status_unknown","sccm_methods_invoked":0,"live_pxe_requests":0,"sql_queries":0,"content_downloads":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "x")
		_ = os.WriteFile(p, b, 0600)
		_, _ = LoadDeploymentRuntime(p)
	})
}
