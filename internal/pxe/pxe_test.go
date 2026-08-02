package pxe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func base() (Candidate, InspectionPlan) {
	c := CandidateFromEvidence("srv01", "P01", []string{"sccm_site_server"}, []string{"inventory"})
	return c, BuildPlan(c)
}
func TestCandidateAndPosture(t *testing.T) {
	c, p := base()
	if p.MaximumTargets != 1 || c.Classification != "osd_capable_site_system" {
		t.Fatal(c, p)
	}
	r := RuntimeInventory{SchemaVersion: 1, Services: []Service{{Name: "SccmPxe", Present: true, State: "Running"}}, Registry: []RegistryObservation{{ValueName: "UnknownComputerSupport", SafeState: "enabled"}, {ValueName: "PXEPassword", SafeState: "configured"}}, BootImages: []BootImageMetadata{{IdentifierFingerprint: "x"}}, Deployments: []DeploymentMetadata{{DeploymentFingerprint: "y"}}}
	a := Analyze(c, p, r)
	if a.Classification != "pxe_active_validation_justified" || a.UnknownComputerPosture != "unknown_computer_support_enabled" || a.PXEPasswordPosture != "pxe_password_configured" {
		t.Fatalf("%+v", a)
	}
}
func TestNoPXEAndWDS(t *testing.T) {
	c, p := base()
	a := Analyze(c, p, RuntimeInventory{SchemaVersion: 1, Services: []Service{{Name: "WDSServer", Present: false}}})
	if a.Classification != "no_pxe_osd_evidence" {
		t.Fatal(a.Classification)
	}
	a = Analyze(c, p, RuntimeInventory{SchemaVersion: 1, Features: []Feature{{Name: "WDS", Present: true}}})
	if !a.WDSInstalled || a.PXEEnabled {
		t.Fatal(a)
	}
}
func TestSafetyAndDossier(t *testing.T) {
	s := CollectorPowerShell()
	for _, w := range []string{"Set-StrictMode", "Get-CimInstance Win32_Service", "Get-WindowsFeature", "FileShare]::ReadWrite", "FileShare]::Delete", "C:\\RemoteInstall\\SMSImages", "Select-Object -First 256", "ContentLocationFingerprint", "Live PXE requests: 0", "TFTP requests: 0", "Content downloads: 0", "UTF8Encoding($false)"} {
		if !strings.Contains(s, w) {
			t.Fatalf("missing %s", w)
		}
	}
	for _, bad := range []string{"Set-CimInstance", "Set-WmiInstance", "New-ItemProperty", "Set-ItemProperty", "Install-WindowsFeature", "Enable-WindowsOptionalFeature", "Restart-Service", "Start-Service", "Stop-Service", "Invoke-WebRequest", "Start-BitsTransfer", "wdsutil /initialize", "wdsutil /set-server"} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(bad)) {
			t.Fatalf("forbidden %s", bad)
		}
	}
	c, p := base()
	d := filepath.Join(t.TempDir(), "d")
	if e := WriteDossier(d, Analyze(c, p, RuntimeInventory{SchemaVersion: 1})); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(d)
	if st.Mode().Perm() != 0700 {
		t.Fatal(st.Mode())
	}
	entries, _ := os.ReadDir(d)
	if len(entries) != 14 {
		t.Fatalf("files=%d", len(entries))
	}
	for _, e := range entries {
		st, _ := e.Info()
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s %v", e.Name(), st.Mode())
		}
	}
}
func TestRuntimeBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(p, []byte(`{"schema_version":1,"services":[],"features":[],"registry_metadata":[],"log_metadata":[],"boot_image_metadata":[],"task_sequence_deployment_metadata":[],"sccm_methods_invoked":0,"live_pxe_requests":1,"tftp_requests":0,"dhcp_requests":0,"content_downloads":0}`), 0600)
	if _, e := LoadRuntime(p); e == nil {
		t.Fatal("unsafe runtime accepted")
	}
}
func FuzzPXERuntime(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"services":[],"features":[],"registry_metadata":[],"log_metadata":[],"boot_image_metadata":[],"task_sequence_deployment_metadata":[],"sccm_methods_invoked":0,"live_pxe_requests":0,"tftp_requests":0,"dhcp_requests":0,"content_downloads":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "x")
		_ = os.WriteFile(p, b, 0600)
		_, _ = LoadRuntime(p)
	})
}
