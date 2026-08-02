package buildtool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/localartifact"
)

func TestLocalArtifactCLIOffline(t *testing.T) {
	d := t.TempDir()
	kit := filepath.Join(d, "kit")
	out, stderr, e := runCLI(t, "lab", "client-artifacts", "discover", "--output", kit, "--site-code", "P01", "--client-label", "client-a")
	if e != nil {
		t.Fatalf("discover: %v %s", e, stderr)
	}
	if !strings.Contains(out, "Live SCCM policy requests: 0") {
		t.Fatal(out)
	}
	v := localartifact.Inventory{SchemaVersion: 1, CollectedAt: time.Now().UTC(), ClientLabel: "client-a", SiteCode: "P01", Namespaces: []localartifact.Namespace{{Namespace: `root\ccm\Policy`, Exists: true, Accessible: true}}, Classes: []localartifact.ClassSchema{{ID: "class_1", Namespace: `root\ccm\Policy`, Name: "SyntheticPolicy", Classification: "policy_configuration_metadata"}}}
	b, _ := json.Marshal(v)
	inv := filepath.Join(d, "inventory.json")
	_ = os.WriteFile(inv, b, 0600)
	dossier := filepath.Join(d, "dossier")
	out, stderr, e = runCLI(t, "--db", filepath.Join(d, "db.sqlite"), "lab", "client-artifacts", "inspect", "--inventory", inv, "--output", dossier)
	if e != nil {
		t.Fatalf("inspect: %v %s", e, stderr)
	}
	if !strings.Contains(out, "Local SCCM policy artifact discovery") || !strings.Contains(out, "Live SCCM policy requests: 0") {
		t.Fatal(out)
	}
	plan := filepath.Join(d, "plan.json")
	if _, stderr, e = runCLI(t, "lab", "client-artifacts", "export-plan", "--inventory", inv, "--output", plan); e != nil {
		t.Fatalf("plan: %v %s", e, stderr)
	}
	pb, _ := os.ReadFile(plan)
	if strings.Contains(string(pb), "CLIENT_SECRET_SENTINEL") {
		t.Fatal("secret leaked")
	}
	var parsed any
	if e = json.Unmarshal(pb, &parsed); e != nil {
		t.Fatal(e)
	}
}
