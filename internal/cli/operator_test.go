package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func executeForTest(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errout bytes.Buffer
	c := New(&out, &errout)
	c.SetArgs(args)
	e := c.Execute()
	return out.String(), errout.String(), e
}

func TestPublicSurface(t *testing.T) {
	c := New(&bytes.Buffer{}, &bytes.Buffer{})
	want := map[string]bool{"discover": true, "assess": true, "validate": true, "exploit": true, "cleanup": true, "report": true, "run": true, "framework": true, "research": true, "debug": true}
	for _, x := range c.Commands() {
		if want[x.Name()] {
			delete(want, x.Name())
		}
		if !x.Hidden && x.Name() != "completion" && x.Name() != "help" && x.Name() != "version" {
			switch x.Name() {
			case "discover", "assess", "validate", "exploit", "cleanup", "report", "run", "framework", "research", "debug":
			default:
				t.Fatalf("internal top-level command exposed: %s", x.Name())
			}
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing public commands: %v", want)
	}
}

func TestComplexityBudgets(t *testing.T) {
	r := buildComplexity(buildCommandInventory(New(&bytes.Buffer{}, &bytes.Buffer{})))
	if r.VisibleCommands > 15 || r.PublicFlags > 35 || r.CommonWorkflowRequiredFlags > 2 {
		t.Fatalf("public CLI budget exceeded: %+v", r)
	}
	if r.ArtifactPathFlags > 43 || r.TotalLocalFlags >= 580 {
		t.Fatalf("complexity not materially reduced: %+v", r)
	}
}

func TestNoPublicArtifactPathFlags(t *testing.T) {
	for _, c := range buildCommandInventory(New(&bytes.Buffer{}, &bytes.Buffer{})).Commands {
		if c.Category == "operator_primary" && len(c.InputArtifacts) > 0 {
			t.Fatalf("public artifact handoff: %s %v", c.Path, c.InputArtifacts)
		}
	}
}

func TestCommandInventoryCompleteAndClassified(t *testing.T) {
	c := New(&bytes.Buffer{}, &bytes.Buffer{})
	inv := buildCommandInventory(c)
	if len(inv.Commands) < 80 {
		t.Fatalf("inventory too small: %d", len(inv.Commands))
	}
	for _, x := range inv.Commands {
		if x.Path == "" || x.Category == "" || x.NetworkBehavior == "" || x.SideEffects == "" {
			t.Fatalf("unclassified: %+v", x)
		}
	}
}

func TestCommandInventoryJSONClean(t *testing.T) {
	out, errout, e := executeForTest(t, "debug", "command-inventory", "--format", "json")
	if e != nil || errout != "" {
		t.Fatalf("%v %q", e, errout)
	}
	var x commandInventory
	if json.Unmarshal([]byte(out), &x) != nil || len(x.Commands) == 0 {
		t.Fatal("invalid inventory JSON")
	}
}

func TestAssessWorkflowAndContextPrecedence(t *testing.T) {
	t.Setenv("CINDERPATH_TARGET", "environment.example")
	r := resolveRunContext("explicit.example", "active.example", []string{"config.example"}, "", "", "db", "reports", "safe")
	if r.Target != "explicit.example" || r.TargetSource != "explicit CLI flag" {
		t.Fatalf("%+v", r)
	}
	out, errout, e := executeForTest(t, "assess", "pxe", "--target", "srv01", "--format", "json")
	if e != nil || errout != "" {
		t.Fatalf("%v %q", e, errout)
	}
	if strings.Contains(out, "srv01") || !strings.Contains(out, "plan_ready_execution_requires_authorized_connector") || !strings.Contains(out, "\"network_behavior\":\"none\"") {
		t.Fatal(out)
	}
}

func TestRECON2ReportsNoConnectorWithoutNetwork(t *testing.T) {
	out, stderr, err := executeForTest(t, "assess", "technique", "RECON-2", "--target", "srv01", "--format", "json")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if result["status"] != "not_run_no_connector" || result["network_behavior"] != "none" {
		t.Fatalf("result=%v", result)
	}
	if strings.Contains(out, "srv01") || !strings.Contains(out, "no SMB protocol request was sent") {
		t.Fatalf("unsafe or unredacted output: %s", out)
	}
}

func TestProfileLimits(t *testing.T) {
	safe, research := limitsForProfile("safe"), limitsForProfile("research")
	if safe.MaxClasses != 32 || research.MaxClasses <= safe.MaxClasses || research.MaxBytes <= safe.MaxBytes {
		t.Fatalf("safe=%+v research=%+v", safe, research)
	}
}

func TestArtifactContextCLI(t *testing.T) {
	d := t.TempDir()
	p := d + "/preview.json"
	if e := os.WriteFile(p, []byte(`{"safe":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	out, stderr, e := executeForTest(t, "--output-dir", d, "research", "artifact", "register", "--run", "run-1", "--artifact-type", "property_previews", "--artifact", p, "--sensitive")
	if e != nil || stderr != "" || !strings.Contains(out, "Artifact registered") {
		t.Fatalf("%v %q %q", e, out, stderr)
	}
	out, stderr, e = executeForTest(t, "--output-dir", d, "research", "artifact", "resolve", "--run", "run-1", "--artifact-type", "property_previews")
	if e != nil || stderr != "" || !strings.Contains(out, "file=preview.json") || strings.Contains(out, d) {
		t.Fatalf("%v %q %q", e, out, stderr)
	}
}

func TestUnsupportedExecutionPreservesGates(t *testing.T) {
	_, _, e := executeForTest(t, "exploit", "technique", "PXE-1", "--run", "run-1")
	if e == nil || !strings.Contains(e.Error(), "required flag") {
		t.Fatalf("impact acknowledgement not required: %v", e)
	}
	_, _, e = executeForTest(t, "exploit", "technique", "PXE-1", "--run", "run-1", "--acknowledge-impact")
	if e == nil || !strings.Contains(e.Error(), "not implemented") {
		t.Fatalf("unsupported execution advertised: %v", e)
	}
}

func TestObsoleteDuplicateAliasRemoved(t *testing.T) {
	c := New(&bytes.Buffer{}, &bytes.Buffer{})
	for _, x := range c.Commands() {
		if x.Name() == "capture" {
			t.Fatal("duplicate top-level capture tree retained")
		}
	}
	out, stderr, e := executeForTest(t, "research", "capture", "--help")
	if e != nil || stderr != "" || !strings.Contains(out, "authorized captures offline") {
		t.Fatalf("replacement unavailable: %v %q %q", e, out, stderr)
	}
}

func TestPublicHelpGoldenSurface(t *testing.T) {
	out, stderr, e := executeForTest(t, "--help")
	if e != nil || stderr != "" {
		t.Fatalf("%v %q", e, stderr)
	}
	for _, line := range []string{"assess", "cleanup", "discover", "exploit", "framework", "report", "research", "run", "validate"} {
		if !strings.Contains(out, line) {
			t.Fatalf("public help missing %s", line)
		}
	}
	for _, hidden := range []string{"client-artifacts", "capture-kit", "analyze-deployments"} {
		if strings.Contains(out, hidden) {
			t.Fatalf("internal command leaked into top-level help: %s", hidden)
		}
	}
}

func TestWorkflowHelpGoldenSurfaces(t *testing.T) {
	cases := map[string][]string{
		"assess":               {"client-policy", "pxe", "technique", "--framework", "--target"},
		"assess pxe":           {"--run", "--target", "--format"},
		"assess client-policy": {"--run", "--target", "--format"},
		"research":             {"artifact", "capture", "discover-advanced", "evidence", "policy", "pxe"},
	}
	for path, wants := range cases {
		args := append(strings.Fields(path), "--help")
		out, stderr, e := executeForTest(t, args...)
		if e != nil || stderr != "" {
			t.Fatalf("%s: %v %q", path, e, stderr)
		}
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Fatalf("%s help missing %s", path, want)
			}
		}
	}
}
