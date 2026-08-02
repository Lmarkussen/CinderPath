package cli

import (
	"bytes"
	"encoding/json"
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

func TestLegacyAliasHiddenAndDeprecated(t *testing.T) {
	c := New(&bytes.Buffer{}, &bytes.Buffer{})
	var captureFound bool
	for _, x := range c.Commands() {
		if x.Name() == "capture" {
			captureFound = true
			if !x.Hidden || x.Deprecated == "" {
				t.Fatalf("legacy command not hidden/deprecated")
			}
		}
	}
	if !captureFound {
		t.Fatal("legacy capture alias removed")
	}
	_, stderr, e := executeForTest(t, "--db", t.TempDir()+"/test.sqlite", "capture", "list")
	if e != nil || !strings.Contains(stderr, "deprecated") || !strings.Contains(stderr, "research") {
		t.Fatalf("migration warning missing: %v %q", e, stderr)
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
