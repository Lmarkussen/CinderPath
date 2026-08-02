package buildtool

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/capturekit"
	"gopkg.in/yaml.v3"
)

func TestCaptureKitCLIOffline(t *testing.T) {
	d := t.TempDir()
	kit := filepath.Join(d, "kit")
	out, stderr, e := runCLI(t, "lab", "capture-kit", "create", "--output", kit, "--site-code", "ABC", "--management-point", "mp01.lab.local", "--client-label", "win11-client-a", "--capture-label", "baseline-01")
	if e != nil {
		t.Fatalf("create: %v %s", e, stderr)
	}
	if !bytes.Contains([]byte(out), []byte("Live SCCM policy requests: 0")) {
		t.Fatal(out)
	}
	if _, _, e = runCLI(t, "lab", "capture-kit", "validate", "--directory", kit); e != nil {
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
	db := filepath.Join(d, "kit.db")
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
