package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/app"
	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/cred1"
	"github.com/Lmarkussen/CinderPath/internal/cred2"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/planner"
	"github.com/Lmarkussen/CinderPath/internal/policy"
	"github.com/Lmarkussen/CinderPath/internal/terminal"
)

func executeForTest(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errout bytes.Buffer
	c := New(&out, &errout)
	c.SetArgs(args)
	e := c.Execute()
	return out.String(), errout.String(), e
}

func TestCRED1RequiresExplicitLiveTarget(t *testing.T) {
	for _, args := range [][]string{
		{"assess", "CRED-1", "--target", "MECM.SCCM.LAB"},
		{"assess", "CRED-1", "--provider", "live"},
	} {
		_, _, err := executeForTest(t, args...)
		if err == nil || !strings.Contains(err.Error(), "CRED-1") {
			t.Fatalf("args=%v err=%v", args, err)
		}
	}
}

func TestLivePrerequisitesAreTechniqueAware(t *testing.T) {
	c := config.Defaults()
	c.Workflow.Provider = "live"
	s := &state{cfg: c}
	if got := s.localPrerequisites("RECON-3", "target", true); len(got) != 1 || got[0].ID != "platform" {
		t.Fatalf("RECON-3 unexpectedly requires capture prerequisites: %+v", got)
	}
	if got := s.localPrerequisites("CRED-1", "target", true); len(got) < 2 {
		t.Fatalf("CRED-1 capture prerequisites missing: %+v", got)
	}
}

func TestLocalTechniqueContextIsBlockedRatherThanFailed(t *testing.T) {
	t.Setenv("CINDERPATH_DB", filepath.Join(t.TempDir(), "test.db"))
	out, stderr, err := executeForTest(t, "assess", "CRED-ALL", "--provider", "live", "--target", "MECM.SCCM.LAB", "--format", "json")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	var result map[string]any
	if json.Unmarshal([]byte(out), &result) != nil {
		t.Fatal("invalid family JSON")
	}
	techniques, _ := result["techniques"].([]any)
	for _, raw := range techniques {
		item, _ := raw.(map[string]any)
		id, _ := item["technique_id"].(string)
		if id == "CRED-2" || id == "CRED-3" {
			if item["status"] != "blocked" {
				t.Fatalf("%s status=%v", id, item["status"])
			}
		}
	}
	if !strings.Contains(out, "sccm_client_context") {
		t.Fatalf("locality prerequisite missing: %s", out)
	}
}

func TestCRED1CurrentOutputDoesNotReuseHistoricalSecret(t *testing.T) {
	fresh := cred1.PolicyResult{TaskSequences: []cred1.TaskSequence{{
		PackageID: "P01TEST", DeploymentID: "P01DEPLOYMENT",
		Variables: []cred1.RecoveredVariable{{Name: "ExampleVariable", Value: "Example-Secret-Value"}},
	}}}
	if got := cred1Secrets(fresh, false); len(got) != 1 || got[0]["value"] != "Example-Secret-Value" {
		t.Fatalf("fresh CRED-1 result=%v", got)
	}
	// This models run N+1 after a fresh assignment does not contain the seed
	// policy. Rendering receives only its fresh in-memory result; historical
	// database evidence cannot contribute a secret value.
	if got := cred1Secrets(cred1.PolicyResult{}, false); len(got) != 0 {
		t.Fatalf("historical secret leaked into current CRED-1 output: %v", got)
	}
	if got := cred1Secrets(fresh, true); len(got) != 1 || got[0]["value"] != "<redacted>" {
		t.Fatalf("CRED-1 redaction=%v", got)
	}
}

func TestCRED2SecretOutputRedaction(t *testing.T) {
	fresh := cred2.Credential{Username: "Example\\naa", Password: "Example-Secret"}
	if got := cred2SecretOutput(fresh, false); got["username"] != fresh.Username || got["password"] != fresh.Password {
		t.Fatalf("unexpected current CRED-2 output: %v", got)
	}
	if got := cred2SecretOutput(fresh, true); got["username"] != "<redacted>" || got["password"] != "<redacted>" {
		t.Fatalf("CRED-2 redaction failed: %v", got)
	}
	if got := cred2SecretOutput(cred2.Credential{}, false); got["username"] != "" || got["password"] != "" {
		t.Fatalf("historical CRED-2 credential leaked into empty current result: %v", got)
	}
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
	if r.VisibleCommands > 15 || r.PublicFlags > 30 || r.CommonWorkflowRequiredFlags > 2 {
		t.Fatalf("public CLI budget exceeded: %+v", r)
	}
	if r.ArtifactPathFlags > 43 || r.TotalLocalFlags >= 410 || r.RequiredFlags >= 100 {
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
	if !strings.Contains(out, "srv01") || !strings.Contains(out, "target_id") || !strings.Contains(out, "plan_ready_execution_requires_authorized_connector") || !strings.Contains(out, "\"network_behavior\":\"none\"") {
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
	if !strings.Contains(out, "srv01") || !strings.Contains(out, "target_id") || !strings.Contains(out, "no SMB protocol request was sent") {
		t.Fatalf("unsafe or unredacted output: %s", out)
	}
}

func TestRedactSecretsFlagIsReportedInJSON(t *testing.T) {
	out, stderr, err := executeForTest(t, "--redact-secrets", "assess", "technique", "RECON-2", "--target", "SCCM.LAB", "--format", "json")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	if !strings.Contains(out, `"target":"SCCM.LAB"`) || !strings.Contains(out, `"target_id":"target_`) || !strings.Contains(out, `"secrets_redacted":true`) {
		t.Fatalf("operator output policy metadata missing: %s", out)
	}
}

func TestRECON3ReportsNoConnectorWithoutNetwork(t *testing.T) {
	out, stderr, err := executeForTest(t, "assess", "technique", "RECON-3", "--target", "srv01", "--format", "json")
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
	if _, ok := result["defensive_mappings"]; ok {
		t.Fatalf("defensive mappings leaked into product result: %v", result)
	}
	if !strings.Contains(out, "srv01") || !strings.Contains(out, "target_id") || !strings.Contains(out, "no HTTP request was sent") {
		t.Fatalf("unsafe or unredacted output: %s", out)
	}
}

func TestDefensiveTechniquesAreOutOfProductScope(t *testing.T) {
	for _, family := range []string{"CRED", "ELEVATE", "EXEC", "RECON", "TAKEOVER", "COERCE"} {
		out, stderr, err := executeForTest(t, "assess", "technique", family+"-999", "--target", "srv01", "--format", "json")
		if err != nil || stderr != "" || !strings.Contains(out, `"technique_id"`) {
			t.Fatalf("attack family %s was not accepted: out=%q stderr=%q err=%v", family, out, stderr, err)
		}
	}
	for _, family := range []string{"PREVENT", "DETECT", "CANARY"} {
		_, _, err := executeForTest(t, "assess", "technique", family+"-1", "--target", "srv01")
		if err == nil || !strings.Contains(err.Error(), "out of scope") {
			t.Fatalf("defensive family %s was not rejected: %v", family, err)
		}
		_, _, err = executeForTest(t, "framework", "technique", family+"-1")
		if err == nil || !strings.Contains(err.Error(), "out of scope") {
			t.Fatalf("framework exposed defensive family %s: %v", family, err)
		}
		_, _, err = executeForTest(t, "framework", "family", family)
		if err == nil || !strings.Contains(err.Error(), "out of scope") {
			t.Fatalf("framework exposed defensive family %s: %v", family, err)
		}
	}
}

func TestTechniquePlannerAndColorControlsRemainMachineClean(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	out, stderr, err := executeForTest(t, "--color", "always", "assess", "technique", "CRED-2", "--target", "SCCM.LAB", "--format", "json")
	if err != nil || stderr != "" || strings.Contains(out, "\x1b[") || !strings.Contains(out, "policy_acquisition") {
		t.Fatalf("err=%v stderr=%q output=%q", err, stderr, out)
	}
	out, _, err = executeForTest(t, "--color", "always", "assess", "technique", "RECON-1", "--target", "SCCM.LAB")
	if err != nil || !strings.Contains(out, "\x1b[36mSCCM.LAB") {
		t.Fatalf("err=%v output=%q", err, out)
	}
}

func TestColorControlsAndTechniqueSemanticRendering(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var text bytes.Buffer
	s := &state{stdout: &text, renderer: terminal.New(terminal.Always, &text)}
	s.printRECON1Text("RECON-1", "SCCM.LAB", "completed", app.Outcome{}, "supported")
	if got := text.String(); !strings.Contains(got, "\x1b[36mSCCM.LAB") || !strings.Contains(got, "\x1b[32m✓ completed") {
		t.Fatalf("RECON-1 semantic rendering missing: %q", got)
	}
	text.Reset()
	s.printRECON2Text("RECON-2", "MECM.SCCM.LAB", "completed", app.Outcome{}, "supported")
	if got := text.String(); !strings.Contains(got, "\x1b[36mMECM.SCCM.LAB") || !strings.Contains(got, "\x1b[32m✓ completed") || !strings.Contains(got, "\x1b[36mlive.smb.share_metadata") {
		t.Fatalf("RECON-2 semantic rendering missing: %q", got)
	}
	text.Reset()
	s.printRECON3Text("RECON-3", "MECM.SCCM.LAB", "connection_failed", app.Outcome{}, "partial")
	if got := text.String(); !strings.Contains(got, "\x1b[31m✗ connection_failed") || !strings.Contains(got, "\x1b[36mlive.sccm.http_recon") {
		t.Fatalf("RECON-3 semantic rendering missing: %q", got)
	}

	out, _, err := executeForTest(t, "--no-color", "--color", "always", "assess", "RECON-1", "--target", "SCCM.LAB")
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") || strings.Contains(out, "\x1b[") {
		t.Fatalf("conflicting color controls: err=%v output=%q", err, out)
	}
	out, _, err = executeForTest(t, "--no-color", "assess", "RECON-1", "--target", "SCCM.LAB")
	if err != nil || strings.Contains(out, "\x1b[") {
		t.Fatalf("--no-color: err=%v output=%q", err, out)
	}
	t.Setenv("NO_COLOR", "1")
	out, _, err = executeForTest(t, "--color", "always", "assess", "RECON-1", "--target", "SCCM.LAB")
	if err != nil || strings.Contains(out, "\x1b[") {
		t.Fatalf("NO_COLOR: err=%v output=%q", err, out)
	}
}

func TestLegacyColorFlagIsHidden(t *testing.T) {
	c := New(&bytes.Buffer{}, &bytes.Buffer{})
	flag := c.PersistentFlags().Lookup("color")
	if flag == nil || !flag.Hidden || flag.DefValue != "auto" {
		t.Fatalf("legacy color flag=%+v", flag)
	}
}

func TestBoundedTechniqueSummariesUseExistingEvidence(t *testing.T) {
	recon1 := recon1DetailsFor([]models.Evidence{
		{Type: "ldap_rootdse"},
		{Type: "recon1_ldap_assessment", Data: map[string]any{
			"publishing_state":           "sccm_ad_publishing_confirmed",
			"system_management_state":    "system_management_container_present",
			"sites_observed":             []any{"P01"},
			"management_points_observed": []any{"MECM.SCCM.LAB"},
		}},
	})
	if !recon1.RootDSE || !recon1.SystemManagement || !recon1.Publishing || strings.Join(recon1.Sites, ",") != "P01" || strings.Join(recon1.ManagementPoints, ",") != "MECM.SCCM.LAB" {
		t.Fatalf("RECON-1 details=%+v", recon1)
	}
	shares := recon2SharesFor([]models.Evidence{{Type: "smb_share_metadata", Data: map[string]any{"shares": []any{
		map[string]any{"name": "IPC$", "classification": "generic_administrative_share"},
		map[string]any{"name": "SMSPKG", "classification": "sccm_content_share"},
	}}}})
	if len(shares) != 2 || shares[0].Name != "IPC$" || shares[1].Classification != "sccm_content_share" {
		t.Fatalf("RECON-2 shares=%+v", shares)
	}
}

func TestPrerequisiteProvenanceRendering(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var out bytes.Buffer
	printPrerequisites(&out, terminal.New(terminal.Always, &out), planner.Plan{Prerequisites: []planner.Decision{{Requirement: planner.Requirement{Fact: planner.RootDSE, Label: "RootDSE"}, State: planner.Recent, Reason: "compatible retained evidence", SourceRun: "run_prior", Age: "14m0s"}}})
	got := out.String()
	if !strings.Contains(got, "run_prior") || !strings.Contains(got, "14m0s") || !strings.Contains(got, "\x1b[2m") {
		t.Fatalf("provenance not rendered: %q", got)
	}
}

func TestImportedClientIdentityFeedsCRED2Planner(t *testing.T) {
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	cfg.WorkflowScope.Domain = "SCCM.LAB"
	a := &app.Application{Config: cfg}
	identity, err := policy.ParseClientIdentity([]byte("kind: existing_sccm_client\nclient_id: 11111111-2222-3333-4444-555555555555\ndomain: SCCM.LAB\nsource:\n  type: local_sccm_client_artifact\n  verified: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err = a.ImportClientIdentity(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	s := &state{cfg: cfg, application: a}
	plan := s.techniquePlan("CRED-2", "SCCM.LAB", "")
	for _, decision := range plan.Prerequisites {
		if decision.Fact == planner.ClientIdentity && decision.State != planner.Current {
			t.Fatalf("client identity=%+v", decision)
		}
	}
}

func TestPolicySecretRenderingHonorsGlobalRedaction(t *testing.T) {
	fixtureDir, err := filepath.Abs(filepath.Join("..", "policy", "testdata", "example01"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--profile", "standard", "research", "policy-model", "secrets", "--directory", fixtureDir, "--show-secrets"}
	out, _, err := executeForTest(t, args...)
	if err != nil || !strings.Contains(out, "SyntheticPassword123!") {
		t.Fatalf("default secret rendering: err=%v output=%q", err, out)
	}
	out, _, err = executeForTest(t, append([]string{"--redact-secrets"}, args...)...)
	if err != nil || strings.Contains(out, "SyntheticPassword123!") {
		t.Fatalf("redacted secret rendering: err=%v output=%q", err, out)
	}
}

func TestSimplifiedAssessmentAndRunForms(t *testing.T) {
	out, stderr, err := executeForTest(t, "assess", "RECON-1", "--target", "SCCM.LAB", "--format", "json")
	if err != nil || stderr != "" || !strings.Contains(out, `"technique_id":"RECON-1"`) {
		t.Fatalf("direct technique: err=%v stderr=%q output=%q", err, stderr, out)
	}
	out, _, err = executeForTest(t, "assess", "SCCM.LAB")
	if err != nil || !strings.Contains(out, "safe plan only; no network activity") {
		t.Fatalf("domain plan: err=%v output=%q", err, out)
	}
	db := t.TempDir() + "/run.db"
	out, _, err = executeForTest(t, "--db", db, "run", "SCCM.LAB", "--dry-run")
	if err != nil || !strings.Contains(out, "Project: SCCM.LAB") || !strings.Contains(out, "Network activity: none; dry-run") {
		t.Fatalf("positional run: err=%v output=%q", err, out)
	}
}

func TestFamilySelectorsAreRegistryBackedAndDeterministic(t *testing.T) {
	out, stderr, err := executeForTest(t, "assess", "RECON-ALL", "--target", "SCCM.LAB", "--format", "json")
	if err != nil || stderr != "" || !strings.Contains(out, `"family":"RECON"`) || !strings.Contains(out, `"technique_id":"RECON-7"`) {
		t.Fatalf("RECON-ALL: err=%v stderr=%q output=%q", err, stderr, out)
	}
	var result struct {
		Techniques []struct {
			ID string `json:"technique_id"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil || len(result.Techniques) != 7 || result.Techniques[0].ID != "RECON-1" || result.Techniques[6].ID != "RECON-7" {
		t.Fatalf("unexpected deterministic family result: err=%v result=%+v", err, result)
	}
	out, _, err = executeForTest(t, "assess", "CRED-ALL", "--target", "SCCM.LAB", "--format", "json")
	if err != nil || !strings.Contains(out, `"family":"CRED"`) || !strings.Contains(out, `"technique_id":"CRED-3"`) {
		t.Fatalf("CRED-ALL: err=%v output=%q", err, out)
	}
	_, _, err = executeForTest(t, "assess", "UNKNOWN-ALL", "--target", "SCCM.LAB")
	if err == nil || !strings.Contains(err.Error(), "not a framework technique") {
		t.Fatalf("unknown family was not rejected: %v", err)
	}
}

func TestFrameworkProvenanceText(t *testing.T) {
	out, stderr, err := executeForTest(t, "framework", "coverage", "--framework", "misconfiguration-manager")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	for _, want := range []string{"Framework: Misconfiguration Manager", "Upstream project: https://github.com/subat0mik/Misconfiguration-Manager", "Upstream revision: 394c53baf98c4eeb5ba001d195c4653216ac3141", "Implementation: CinderPath independent adapter"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	if strings.Contains(out, "Warnings: unknown section") || !strings.Contains(out, "Import warnings:") {
		t.Fatalf("coverage output should summarize importer warnings: %s", out)
	}
}

func TestFrameworkCoverageVerboseWarnings(t *testing.T) {
	out, stderr, err := executeForTest(t, "--verbose", "framework", "coverage", "--framework", "misconfiguration-manager")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	if !strings.Contains(out, "Import warnings\n  - unknown section") {
		t.Fatalf("verbose coverage output omitted warning details: %s", out)
	}
}

func TestFrameworkProvenanceJSON(t *testing.T) {
	out, stderr, err := executeForTest(t, "framework", "technique", "RECON-1", "--format", "json")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	p, ok := result["framework"].(map[string]any)
	if !ok || p["name"] != "Misconfiguration Manager" || p["upstream_revision"] != "394c53baf98c4eeb5ba001d195c4653216ac3141" || p["implementation"] != "CinderPath independent adapter" {
		t.Fatalf("unexpected provenance: %#v", result["framework"])
	}
}

func TestFrameworkCoverageIsAttackOnly(t *testing.T) {
	out, stderr, err := executeForTest(t, "framework", "coverage", "--format", "json")
	if err != nil || stderr != "" {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
	if strings.Contains(out, `"family":"PREVENT"`) || strings.Contains(out, `"family":"DETECT"`) || strings.Contains(out, `"family":"CANARY"`) || strings.Contains(out, "matrix_mappings") {
		t.Fatalf("defensive framework data exposed as product coverage: %s", out)
	}
	for _, family := range []string{"CRED", "ELEVATE", "EXEC", "RECON", "TAKEOVER", "COERCE"} {
		if !strings.Contains(out, `"`+family+`"`) {
			t.Fatalf("attack family %s missing from product coverage: %s", family, out)
		}
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
	if e == nil || !strings.Contains(e.Error(), "acknowledge-impact is required") {
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
		"assess":               {"client-policy", "pxe", "--framework", "--target"},
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
