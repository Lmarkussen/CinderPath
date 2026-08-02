package capturekit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/policy"
	"gopkg.in/yaml.v3"
)

func readyEvidenceKit(t *testing.T) string {
	t.Helper()
	p := testKit(t)
	m, e := LoadMetadata(p)
	if e != nil {
		t.Fatal(e)
	}
	m.Capture.StartedAt = "2026-08-02T10:00:00Z"
	m.Capture.StoppedAt = "2026-08-02T10:01:00Z"
	m.Review = Review{RawSensitive: true, MetadataReviewed: true, BinaryReviewed: true, Sanitized: true, LeakageChecksPassed: true, BundleExportApproved: true}
	b, _ := yaml.Marshal(m)
	_ = os.WriteFile(filepath.Join(p, "metadata", "capture.template.yaml"), b, 0o600)
	_ = os.WriteFile(filepath.Join(p, "sanitized", "sample.har"), []byte(`{"log":{"version":"1.2","entries":[]}}`), 0o600)
	v, e := Validate(p)
	if e != nil || v.State != ReadyForEvidenceBundle {
		t.Fatalf("%v %+v", e, v)
	}
	return p
}
func TestEvidenceBundleExportInspectImportAndSigning(t *testing.T) {
	p := readyEvidenceKit(t)
	raw := []byte("RAW_SENTINEL_NEVER_BUNDLED")
	_ = os.WriteFile(filepath.Join(p, "raw", "raw.pcap"), raw, 0o600)
	out := filepath.Join(t.TempDir(), "baseline.capture-bundle.tar.gz")
	info, e := ExportEvidenceBundle(ExportOptions{Directory: p, Output: out, ToolVersion: "test"})
	if e != nil {
		t.Fatal(e)
	}
	if info.Manifest.BundleType != "capture_evidence" {
		t.Fatal(info)
	}
	archive, _ := os.ReadFile(out)
	if strings.Contains(string(archive), string(raw)) {
		t.Fatal("raw evidence included")
	}
	checked, _, e := InspectEvidenceBundle(out)
	if e != nil || checked.Integrity != "all members verified" {
		t.Fatalf("%v %+v", e, checked)
	}
	dest := filepath.Join(t.TempDir(), "imported")
	if _, e = ImportEvidenceBundle(ImportOptions{Input: out, Output: dest}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dest, "sanitized", "sample.har")); e != nil {
		t.Fatal(e)
	}
	key := filepath.Join(t.TempDir(), "key")
	if _, e = policy.GenerateSigningKey(key, false); e != nil {
		t.Fatal(e)
	}
	signed := filepath.Join(t.TempDir(), "signed.capture-bundle.tar.gz")
	if _, e = SignEvidenceBundle(out, key, signed, false); e != nil {
		t.Fatal(e)
	}
	verified, _, e := InspectEvidenceBundle(signed)
	if e != nil || verified.SignatureState != "signature_valid" || verified.ContractPromotion != "none" {
		t.Fatalf("%v %+v", e, verified)
	}
	if b, _ := os.ReadFile(signed); strings.Contains(string(b), "private_key") {
		t.Fatal("private key entered signed bundle")
	}
}
func TestEvidenceBundleGatesAndOutputSafety(t *testing.T) {
	p := testKit(t)
	if _, e := ExportEvidenceBundle(ExportOptions{Directory: p, Output: filepath.Join(t.TempDir(), "x.tar.gz")}); e == nil {
		t.Fatal("raw/unreviewed kit exported")
	}
	p = readyEvidenceKit(t)
	if _, e := ExportEvidenceBundle(ExportOptions{Directory: p, Output: filepath.Join(p, "output", "x.tar.gz")}); e == nil {
		t.Fatal("output inside kit accepted")
	}
	_ = os.WriteFile(filepath.Join(p, "sanitized", "leak.log"), []byte("Authorization: Bearer SECRET"), 0o600)
	if _, e := ExportEvidenceBundle(ExportOptions{Directory: p, Output: filepath.Join(t.TempDir(), "x.tar.gz")}); e == nil {
		t.Fatal("leakage exported")
	}
}
func TestEvidenceBundleRejectsTraversalAndWrongType(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	writeTestTar(t, bad, map[string][]byte{"../escape": []byte("x")})
	if _, _, e := InspectEvidenceBundle(bad); e == nil {
		t.Fatal("traversal accepted")
	}
	wrong := filepath.Join(t.TempDir(), "wrong.tar.gz")
	b, _ := yaml.Marshal(EvidenceManifest{SchemaVersion: 1, BundleType: "protocol_contract"})
	writeTestTar(t, wrong, map[string][]byte{"bundle.yaml": b})
	if _, _, e := InspectEvidenceBundle(wrong); e == nil {
		t.Fatal("wrong bundle type accepted")
	}
}
func writeTestTar(t *testing.T, p string, m map[string][]byte) {
	t.Helper()
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for n, b := range m {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = f.Close()
}
func FuzzEvidenceManifest(f *testing.F) {
	f.Add([]byte("schema_version: 1\nbundle_type: capture_evidence\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m EvidenceManifest
		_ = yaml.Unmarshal(b, &m)
	})
}
func FuzzEvidencePath(f *testing.F) {
	f.Add("kit/sanitized/a.har")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		_ = safeBundlePath(s)
	})
}
func FuzzEvidenceArchiveValidator(f *testing.F) {
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = readEvidenceArchiveReader(bytes.NewReader(b))
	})
}
func FuzzEvidenceArchiveExtractor(f *testing.F) {
	f.Add("kit/sanitized/a.har", []byte("x"))
	f.Fuzz(func(t *testing.T, p string, b []byte) {
		if len(p) > 4096 || len(b) > 1<<20 {
			return
		}
		if safeBundlePath(p) {
			_ = filepath.Clean(filepath.Join("/tmp/cinderpath-fuzz-bounded", filepath.FromSlash(strings.TrimPrefix(p, "kit/"))))
		}
	})
}
func FuzzCaptureKitReportSerializer(f *testing.F) {
	f.Add("capture_kit_a", "ready_for_import")
	f.Fuzz(func(t *testing.T, id, state string) {
		if len(id)+len(state) > 8192 {
			return
		}
		_, _ = json.Marshal(Validation{KitID: id, State: State(state), LiveRequests: 0})
	})
}

var _ = time.Time{}
