package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBinaryInspectionExpandedAndDeterministic(t *testing.T) {
	b := []byte("ASCII https://host.example.invalid/path {00112233-4455-6677-8899-aabbccddeeff} S-1-5-21-1-2-3\x00")
	u := make([]byte, len("WideHost")*2)
	for i, r := range "WideHost" {
		binary.LittleEndian.PutUint16(u[i*2:], uint16(r))
	}
	b = append(b, u...)
	b = append(b, []byte{'P', 'K', 1, 2}...)
	a, e := InspectBinary(b)
	if e != nil {
		t.Fatal(e)
	}
	again, _ := InspectBinary(b)
	if len(a.Observations) == 0 || len(a.Observations) != len(again.Observations) {
		t.Fatal("missing or nondeterministic observations")
	}
	found := map[string]bool{}
	for _, o := range a.Observations {
		found[o.Description] = true
		if o.Classification == "" || o.Length < 1 {
			t.Fatalf("incomplete observation: %#v", o)
		}
	}
	for _, want := range []string{"embedded URL", "text GUID", "SID-like text", "ZIP central-directory hint"} {
		if !found[want] {
			t.Errorf("missing %s", want)
		}
	}
}

func TestSanitizationModesAndReview(t *testing.T) {
	src := copyFixture(t)
	original, _ := os.ReadFile(filepath.Join(src, "request.body"))
	out := filepath.Join(t.TempDir(), "metadata")
	m, e := SanitizeDirectory(SanitizeOptions{Input: src, Output: out, BinaryMode: BinaryMetadataOnly})
	if e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(out, "request.body"))
	if !bytes.Equal(original, got) || !m.ManualReviewRequired || m.BodiesSanitized != 0 {
		t.Fatal("metadata-only contract violated")
	}
	m, e = ReviewSanitization(out, []string{"request.body", "response.body"}, "LAB_REVIEW_001")
	if e != nil || !m.ManualReviewCompleted {
		t.Fatalf("review: %v", e)
	}
	textSrc := copyFixture(t)
	body := []byte("REALDOMAIN")
	_ = os.WriteFile(filepath.Join(textSrc, "request.body"), body, 0600)
	textOut := filepath.Join(t.TempDir(), "text")
	m, e = SanitizeDirectory(SanitizeOptions{Input: textSrc, Output: textOut, BinaryMode: BinaryTextRegions, Replacements: []Replacement{{"REALDOMAIN", "DOMAIN_001", "domain"}}})
	if e != nil {
		t.Fatal(e)
	}
	got, _ = os.ReadFile(filepath.Join(textOut, "request.body"))
	if len(got) != len(body) || string(got) != "DOMAIN_001" || m.RegionsModified != 1 {
		t.Fatalf("text replacement failed: %q %#v", got, m)
	}
}
func TestUnsafeReplacementFailsClosed(t *testing.T) {
	src := copyFixture(t)
	_ = os.WriteFile(filepath.Join(src, "request.body"), []byte("REALDOMAIN"), 0600)
	out := filepath.Join(t.TempDir(), "out")
	_, e := SanitizeDirectory(SanitizeOptions{Input: src, Output: out, BinaryMode: BinaryTextRegions, Replacements: []Replacement{{"REALDOMAIN", "SHORT", "domain"}}})
	if e == nil {
		t.Fatal("unsafe replacement accepted")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("partial output exists")
	}
}

func TestBundleRoundTripAndTraversal(t *testing.T) {
	f, c, e := ImportDirectory("testdata/example01")
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "bundle.tar.gz")
	m, e := ExportBundle(BundleExportOptions{Contract: c, FixtureDirectories: []string{"testdata/example01"}, Output: out, ToolVersion: "test"})
	if e != nil {
		t.Fatal(e)
	}
	if len(m.FixtureIDs) != 1 || m.FixtureIDs[0] != f.ID {
		t.Fatal("fixture missing")
	}
	info, e := InspectBundle(out)
	if e != nil {
		t.Fatal(e)
	}
	if info.Manifest.BundleID == "" {
		t.Fatal("bundle ID missing")
	}
	if _, e = ImportBundle(out, filepath.Join(t.TempDir(), "imports")); e != nil {
		t.Fatal(e)
	}
}

func TestFixtureServerOnceIgnoresNonmatch(t *testing.T) {
	f, _, e := ImportDirectory("testdata/example01")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint, done, e := ServeFixture(ctx, f, ServerOptions{Listen: "127.0.0.1:0", Once: true, RequestTimeout: time.Second, IdleTimeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	resp, e := http.Get(endpoint + "/wrong")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	select {
	case <-done:
		t.Fatal("nonmatch consumed once")
	default:
	}
	req, _ := http.NewRequest(f.Metadata.Request.Method, endpoint+f.Metadata.Request.Route, bytes.NewReader(f.RequestBody))
	resp, e = http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("matching request did not stop server")
	}
}

func TestCapturePlan(t *testing.T) {
	out := filepath.Join(t.TempDir(), "plan")
	if e := CreateCapturePlan(CapturePlanOptions{Output: out}); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"README.txt", "metadata.template.yaml", "replacements.template.yaml", "review-checklist.txt", "commands-linux.txt", "commands-windows.txt", "expected-layout.txt", ".gitignore"} {
		st, e := os.Stat(filepath.Join(out, n))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode/error: %v %o", n, e, st.Mode().Perm())
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "README.txt"))
	if !strings.Contains(string(b), "does not capture traffic") {
		t.Fatal("safety warning missing")
	}
}

func copyFixture(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, n := range []string{"metadata.yaml", "request.headers", "request.body", "response.headers", "response.body"} {
		b, e := os.ReadFile(filepath.Join("testdata/example01", n))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(d, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return d
}
