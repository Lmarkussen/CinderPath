package buildtool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/capturekit"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"gopkg.in/yaml.v3"
)

func TestCaptureKitCLIOffline(t *testing.T) {
	d := t.TempDir()
	kit := filepath.Join(d, "kit")
	db := filepath.Join(d, "kit.db")
	out, stderr, e := runCLI(t, "--db", db, "lab", "capture-kit", "create", "--output", kit, "--site-code", "ABC", "--management-point", "mp01.lab.local", "--client-label", "win11-client-a", "--capture-label", "baseline-01")
	if e != nil {
		t.Fatalf("create: %v %s", e, stderr)
	}
	if !bytes.Contains([]byte(out), []byte("Live SCCM policy requests: 0")) {
		t.Fatal(out)
	}
	if _, _, e = runCLI(t, "--db", db, "lab", "capture-kit", "validate", "--directory", kit); e != nil {
		t.Fatal(e)
	}
	m, e := capturekit.LoadMetadata(kit)
	if e != nil {
		t.Fatal(e)
	}
	m.Capture.StartedAt = "2026-08-02T10:00:00Z"
	m.Capture.StoppedAt = "2026-08-02T10:01:00Z"
	m.Review = capturekit.Review{RawSensitive: true, MetadataReviewed: true, BinaryReviewed: true, Sanitized: true, LeakageChecksPassed: true}
	b, _ := yaml.Marshal(m)
	if e = os.WriteFile(filepath.Join(kit, "metadata/capture.template.yaml"), b, 0o600); e != nil {
		t.Fatal(e)
	}
	har := `{"log":{"version":"1.2","entries":[{"startedDateTime":"2026-08-02T10:00:00Z","request":{"method":"GET","url":"http://synthetic.invalid/","httpVersion":"HTTP/1.1","headers":[]},"response":{"status":200,"httpVersion":"HTTP/1.1","headers":[]}}]}}`
	if e = os.WriteFile(filepath.Join(kit, "sanitized/sample.har"), []byte(har), 0o600); e != nil {
		t.Fatal(e)
	}
	out, stderr, e = runCLI(t, "--db", db, "capture", "guided-import", "--kit", kit, "--dry-run", "--format", "json")
	if e != nil {
		t.Fatalf("dry: %v %s", e, stderr)
	}
	if bytes.Contains([]byte(out), []byte("Authorization")) {
		t.Fatal("secret marker leaked")
	}
	before, _ := os.ReadFile(filepath.Join(kit, "sanitized/sample.har"))
	out, stderr, e = runCLI(t, "--db", db, "capture", "guided-import", "--kit", kit)
	if e != nil {
		t.Fatalf("import: %v %s", e, stderr)
	}
	after, _ := os.ReadFile(filepath.Join(kit, "sanitized/sample.har"))
	if !bytes.Equal(before, after) {
		t.Fatal("source modified")
	}
	raw, _ := os.ReadFile(db)
	if bytes.Contains(raw, []byte("synthetic.invalid")) {
		t.Fatal("database contains raw URL")
	}
}

func TestCaptureEvidenceBundleCLIOffline(t *testing.T) {
	d := t.TempDir()
	kit := filepath.Join(d, "kit")
	db := filepath.Join(d, "db.sqlite")
	if _, _, e := runCLI(t, "--db", db, "lab", "capture-kit", "create", "--output", kit); e != nil {
		t.Fatal(e)
	}
	m, _ := capturekit.LoadMetadata(kit)
	m.Capture.StartedAt = "2026-08-02T10:00:00Z"
	m.Capture.StoppedAt = "2026-08-02T10:01:00Z"
	m.Review = capturekit.Review{RawSensitive: true, MetadataReviewed: true, BinaryReviewed: true, Sanitized: true, LeakageChecksPassed: true, BundleExportApproved: true}
	b, _ := yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(kit, "metadata/capture.template.yaml"), b, 0o600)
	_ = os.WriteFile(filepath.Join(kit, "sanitized/sample.har"), []byte(`{"log":{"version":"1.2","entries":[]}}`), 0o600)
	bundle := filepath.Join(d, "sample.capture-bundle.tar.gz")
	if _, stderr, e := runCLI(t, "--db", db, "lab", "capture-kit", "bundle", "export", "--directory", kit, "--output", bundle, "--format", "json"); e != nil {
		t.Fatalf("export %v %s", e, stderr)
	}
	out, _, e := runCLI(t, "lab", "capture-kit", "bundle", "inspect", "--input", bundle, "--format", "json")
	if e != nil || !bytes.Contains([]byte(out), []byte(`"bundle_type": "capture_evidence"`)) {
		t.Fatalf("inspect %v %s", e, out)
	}
	key := filepath.Join(d, "key")
	if _, e = policy.GenerateSigningKey(key, false); e != nil {
		t.Fatal(e)
	}
	signed := filepath.Join(d, "signed.capture-bundle.tar.gz")
	if _, _, e = runCLI(t, "--db", db, "lab", "capture-kit", "bundle", "sign", "--input", bundle, "--key", key, "--output", signed); e != nil {
		t.Fatal(e)
	}
	if _, _, e = runCLI(t, "lab", "capture-kit", "bundle", "verify", "--input", signed); e != nil {
		t.Fatal(e)
	}
	if _, _, e = runCLI(t, "--db", db, "capture", "guided-import", "--bundle", signed, "--dry-run"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = runCLI(t, "capture", "guided-import", "--kit", kit, "--bundle", signed); e == nil {
		t.Fatal("mutually exclusive sources accepted")
	}
}
