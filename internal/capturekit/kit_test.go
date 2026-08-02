package capturekit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func testKit(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kit")
	e := Create(CreateOptions{Output: p, SiteCode: "ABC", ManagementPoint: "mp01.lab.local", ClientLabel: "win11-client-a", CaptureLabel: "baseline-01", Now: time.Date(2026, 8, 2, 1, 2, 3, 0, time.UTC)})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestCreateLayoutModesAndPassiveScripts(t *testing.T) {
	p := testKit(t)
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	for _, rel := range required {
		st, e := os.Stat(filepath.Join(p, rel))
		if e != nil {
			t.Fatal(rel, e)
		}
		want := os.FileMode(0o600)
		if strings.HasPrefix(rel, "linux/") || strings.HasSuffix(rel, ".ps1") {
			want = 0o700
		}
		if st.Mode().Perm() != want {
			t.Fatalf("%s mode=%o", rel, st.Mode().Perm())
		}
	}
	joined := ""
	for _, rel := range []string{"windows/Collect-CinderPathInventory.ps1", "windows/Prepare-CinderPathCapture.ps1", "windows/Finalize-CinderPathCapture.ps1"} {
		b, _ := os.ReadFile(filepath.Join(p, rel))
		joined += string(b)
	}
	for _, bad := range []string{"Invoke-WebRequest", "Invoke-RestMethod", "TriggerSchedule", "RequestMachinePolicy", "EvaluateMachinePolicy", "ResetPolicy", "ccmrepair", "ccmsetup", "Export-PfxCertificate", "Set-ExecutionPolicy", "Restart-Service", "Start-Process"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("unsafe generated token %q", bad)
		}
	}
	for _, incompatible := range []string{"SHA256]::HashData", "Convert]::ToHexString", "-Encoding utf8NoBOM"} {
		if strings.Contains(joined, incompatible) {
			t.Fatalf("Windows PowerShell 5.1-incompatible generated token %q", incompatible)
		}
	}
	if !strings.Contains(joined, "[IO.File]::WriteAllText") || !strings.Contains(joined, "[Text.UTF8Encoding]::new($false)") {
		t.Fatal("expected Windows PowerShell 5.1-compatible UTF-8-no-BOM writes")
	}
	if !strings.Contains(joined, "schema_version=1") || !strings.Contains(joined, "Get-FileHash") || !strings.Contains(joined, "[switch]$IncludeClientLogs") {
		t.Fatal("expected bounded inventory/finalization features absent")
	}
	v, e := Validate(p)
	if e != nil || v.State != ReadyForCapture {
		t.Fatalf("%v %+v", e, v)
	}
}
func TestCreateRefusesAndForceReplaces(t *testing.T) {
	p := testKit(t)
	if e := Create(CreateOptions{Output: p}); e == nil {
		t.Fatal("overwrite accepted")
	}
	if e := Create(CreateOptions{Output: p, Force: true, Now: time.Unix(1, 0)}); e != nil {
		t.Fatal(e)
	}
}
func TestMetadataValidationAndStates(t *testing.T) {
	p := testKit(t)
	m, e := LoadMetadata(p)
	if e != nil {
		t.Fatal(e)
	}
	m.Capture.StartedAt = "2026-08-02T01:00:00Z"
	m.Capture.StoppedAt = "2026-08-02T01:05:00Z"
	m.Review = Review{RawSensitive: true, MetadataReviewed: true, BinaryReviewed: true, Sanitized: true, LeakageChecksPassed: true}
	b, _ := yaml.Marshal(m)
	if e = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600); e != nil {
		t.Fatal(e)
	}
	har := `{"log":{"version":"1.2","entries":[]}}`
	if e = os.WriteFile(filepath.Join(p, "sanitized/sample.har"), []byte(har), 0o600); e != nil {
		t.Fatal(e)
	}
	v, e := Validate(p)
	if e != nil || v.State != ReadyForImport {
		t.Fatalf("%v %+v", e, v)
	}
	m.Capture.StartedAt = "not-time"
	b, _ = yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600)
	v, _ = Validate(p)
	if v.State != Invalid {
		t.Fatalf("state=%s", v.State)
	}
}
func TestTraversalAndSensitiveFilesRejected(t *testing.T) {
	p := testKit(t)
	m, _ := LoadMetadata(p)
	m.Files = []File{{Path: "../escape"}}
	b, _ := yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600)
	v, _ := Validate(p)
	if v.State != Invalid {
		t.Fatal("traversal accepted")
	}
	_ = os.WriteFile(filepath.Join(p, "raw/client.pfx"), []byte("synthetic"), 0o600)
	v, _ = Validate(p)
	if v.State != Invalid {
		t.Fatal("private key container accepted")
	}
}

func TestStateMachineImportExportAndSentinel(t *testing.T) {
	p := testKit(t)
	m, _ := LoadMetadata(p)
	m.Capture.StartedAt = "2026-08-02T10:00:00Z"
	m.Capture.StoppedAt = "2026-08-02T10:01:00Z"
	b, _ := yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600)
	_ = os.WriteFile(filepath.Join(p, "raw/sample.pcap"), []byte("raw"), 0o600)
	v, _ := Validate(p)
	if v.State != RequiresSanitization {
		t.Fatalf("state=%s", v.State)
	}
	_ = os.WriteFile(filepath.Join(p, "sanitized/sample.har"), []byte(`{"log":{"version":"1.2","entries":[]}}`), 0o600)
	v, _ = Validate(p)
	if v.State != RequiresManualReview {
		t.Fatalf("state=%s", v.State)
	}
	m.Review = Review{RawSensitive: true, MetadataReviewed: true, BinaryReviewed: true, Sanitized: true, LeakageChecksPassed: true}
	b, _ = yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600)
	v, _ = Validate(p)
	if v.State != ReadyForImport {
		t.Fatalf("state=%s", v.State)
	}
	_ = os.WriteFile(filepath.Join(p, "output/guided-import.json"), []byte("{}"), 0o600)
	v, _ = Validate(p)
	if v.State != Imported {
		t.Fatalf("state=%s", v.State)
	}
	m.Review.BundleExportApproved = true
	b, _ = yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata/capture.template.yaml"), b, 0o600)
	_ = os.WriteFile(filepath.Join(p, "raw/CINDERPATH_SYNTHETIC_LEAK_SENTINEL.txt"), []byte("sentinel"), 0o600)
	v, _ = Validate(p)
	if v.State != Invalid {
		t.Fatalf("sentinel state=%s", v.State)
	}
	_ = os.Remove(filepath.Join(p, "raw/CINDERPATH_SYNTHETIC_LEAK_SENTINEL.txt"))
	v, _ = Validate(p)
	if v.State != ReadyForEvidenceBundle {
		t.Fatalf("state=%s blockers=%v", v.State, v.Blockers)
	}
	_ = os.WriteFile(filepath.Join(p, "output/evidence-bundle.json"), []byte("{}"), 0o600)
	v, _ = Validate(p)
	if v.State != EvidenceBundleExported {
		t.Fatalf("state=%s", v.State)
	}
}
func FuzzMetadataParser(f *testing.F) {
	f.Add([]byte("schema_version: 1\ncapture:\n  authorized_lab: true\nenvironment:\n  disposable: true\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m Metadata
		_ = yaml.Unmarshal(b, &m)
		_ = validateMetadata(m)
	})
}
func FuzzSafePath(f *testing.F) {
	for _, s := range []string{"raw/a.pcap", "../x", "/tmp/x", "a/../../b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		_ = safeRelative(s)
	})
}
func FuzzStateEvaluator(f *testing.F) {
	f.Add(uint8(0), false, false, false)
	f.Fuzz(func(t *testing.T, s uint8, reviewed, leak, approved bool) {
		states := []State{Created, ReadyForCapture, CaptureInProgress, RawCaptureComplete, RequiresSanitization, RequiresManualReview, ReviewFailed, ReadyForImport, Imported, ReadyForEvidenceBundle, EvidenceBundleExported, Invalid}
		m := Metadata{Review: Review{MetadataReviewed: reviewed, BinaryReviewed: reviewed, LeakageChecksPassed: leak, BundleExportApproved: approved}}
		v := Validation{State: states[int(s)%len(states)]}
		_, _ = explain(v.State, m, v)
	})
}
func FuzzImportSourceSelector(f *testing.F) {
	f.Add("kit", "")
	f.Add("", "bundle")
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a)+len(b) > 4096 {
			return
		}
		_, _ = SelectImportSource(a, b)
	})
}
