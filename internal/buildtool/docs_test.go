package buildtool

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/cli"
)

func TestDocumentationConsistency(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	read := func(n string) string {
		b, e := os.ReadFile(filepath.Join(root, n))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	readme, status, makefile, cfg := read("README.md"), read("docs/STATUS.md"), read("Makefile"), read("config.example.yaml")
	cmd := cli.New(os.Stdout, os.Stderr)
	for _, path := range [][]string{{"protocol", "inspect-binary"}, {"protocol", "sanitize"}, {"protocol", "review-sanitization"}, {"protocol", "bundle", "export"}, {"protocol", "bundle", "inspect"}, {"protocol", "bundle", "import"}, {"protocol", "bundle", "sign"}, {"protocol", "bundle", "verify"}, {"protocol", "bundle", "test"}, {"protocol", "signing-key", "generate"}, {"protocol", "research-set", "create"}, {"protocol", "research-set", "analyze"}, {"protocol", "contract", "derive"}, {"protocol", "contract", "dossier"}, {"protocol", "serve-fixtures"}, {"lab", "capture-plan"}, {"runs", "list"}, {"policy", "fixtures"}} {
		c := cmd
		for _, name := range path {
			x, _, e := c.Find([]string{name})
			if e != nil || x == c {
				t.Fatalf("documented command missing: %v", path)
			}
			c = x
		}
	}
	for _, target := range []string{"protocol-test:", "protocol-report-test:", "protocol-bundle-test:", "protocol-signing-test:", "protocol-research-test:", "protocol-contract-test:", "protocol-dossier-test:", "protocol-expected-results-test:", "policy-offline-test:", "fuzz-policy:", "fuzz-protocol:", "fuzz-protocol-research:", "docs-check:", "help:"} {
		if !strings.Contains(makefile, target) {
			t.Errorf("Makefile target missing: %s", target)
		}
	}
	joined := readme + status
	if !strings.Contains(joined, "Live SCCM policy requests remain blocked") && !strings.Contains(joined, "Live policy collection remains blocked") {
		t.Fatal("live policy blocker not documented")
	}
	if strings.Contains(cfg, "approved_live: true") {
		t.Fatal("configuration can promote approved_live")
	}
	for _, mode := range []string{"metadata_only", "text_regions", "structured_known"} {
		if !strings.Contains(joined, mode) {
			t.Errorf("sanitization mode undocumented: %s", mode)
		}
	}
	guide := read("docs/PROTOCOL_RESEARCH.md")
	for _, term := range []string{"Ed25519", "candidate_contract", "not authorization", "research-set"} {
		if !strings.Contains(guide, term) {
			t.Errorf("protocol research guide missing %s", term)
		}
	}
}
