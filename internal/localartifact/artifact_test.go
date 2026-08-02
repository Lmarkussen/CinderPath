package localartifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func syntheticInventory() Inventory {
	return Inventory{SchemaVersion: 1, CollectedAt: time.Date(2026, 8, 2, 1, 2, 3, 0, time.UTC), ClientLabel: "client-a", SiteCode: "P01", Namespaces: []Namespace{{Namespace: `root\ccm\Policy\Machine\ActualConfig`, Exists: true, Accessible: true, ClassCount: 1}}, Classes: []ClassSchema{{ID: "class_1", Namespace: `root\ccm\Policy\Machine\ActualConfig`, Name: "CCM_SyntheticPolicy", Classification: "policy_configuration_metadata", Properties: []PropertySchema{{Name: "PolicyID", CIMType: "String", Key: true}}, Methods: []string{"ObservedButNeverInvoked"}, InstanceCount: 1, CountState: "bounded"}}, Instances: []InstanceMetadata{{ID: "instance_1", Namespace: `root\ccm\Policy\Machine\ActualConfig`, Class: "CCM_SyntheticPolicy", Fingerprint: "fixture", Properties: []InstanceProperty{{Name: "OpaqueData", CIMType: "String", State: "non_null", Shape: "encrypted_or_opaque", Fingerprint: "synthetic", LengthBucket: "257-4096"}}}}, Files: []FileArtifact{{ID: "file_1", SafeRelativePath: `Policy\synthetic.xml`, SHA256: "synthetic", Extension: ".xml", Shape: "XML_like", Size: 100, XML: true}}, LivePolicyRequests: 0}
}

func TestCreatePassivePowerShell51(t *testing.T) {
	d := filepath.Join(t.TempDir(), "kit")
	if e := Create(CreateOptions{Output: d, SiteCode: "P01", ClientLabel: "client-a", MaxFiles: 100, MaxClasses: 100, MaxInstances: 10}); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(d, "Discover-CinderPathPolicyArtifacts.ps1"))
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, bad := range []string{"Invoke-WebRequest", "Invoke-RestMethod", "TriggerSchedule", "RequestMachinePolicy", "EvaluateMachinePolicy", "Set-CimInstance", "Set-WmiInstance", "Set-ItemProperty", "Restart-Service", "Start-Service", "Stop-Service", "Export-PfxCertificate", "PrivateKey", "SHA256]::HashData", "Convert]::ToHexString", "utf8NoBOM"} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden generated token %q", bad)
		}
	}
	for _, want := range []string{"Set-StrictMode", "Get-CimClass", "Get-CimInstance", "GetValueNames", "[Security.Cryptography.SHA256]::Create()", "New-Object Text.UTF8Encoding($false)", "MaxFiles = 100", "live_policy_requests=0"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if !strings.Contains(s, `$depth=@($rel.ToCharArray()|Where-Object{$_-eq'\'}).Count`) {
		t.Fatal("strict-mode-safe empty pipeline count missing")
	}
	if !strings.Contains(s, `catch{$sample=New-Object byte[] 0`) || !strings.Contains(s, `catch{""}finally`) {
		t.Fatal("locked files must be nonfatal")
	}
	if !strings.Contains(s, "[IO.FileShare]::ReadWrite") || strings.Contains(s, "$c.CimClassMethods.Name") {
		t.Fatal("PowerShell 5.1 collection/file-share compatibility missing")
	}
	if !strings.Contains(s, "Get-Entropy $sample") {
		t.Fatal("bounded file entropy calculation missing")
	}
	if !strings.Contains(s, `-not $c.CimClassName.StartsWith('__')`) {
		t.Fatal("intrinsic WMI classes must not consume selected-instance budget")
	}
	if !strings.Contains(s, `$row.CimInstanceProperties|Select-Object -First $MaxProperties`) {
		t.Fatal("concrete instance properties must be inventoried independently of inherited/empty class properties")
	}
}

func TestLoadAnalyzeAndDossier(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "inventory.json")
	b, _ := json.Marshal(syntheticInventory())
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	v, e := Load(p, DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	r := Analyze(v)
	if r.SecretReadiness != "ready_for_encrypted_value_classifier" {
		t.Fatalf("readiness=%s", r.SecretReadiness)
	}
	if len(r.Candidates) < 3 || r.LivePolicyRequests != 0 {
		t.Fatalf("%#v", r)
	}
	if len(r.Relationships) != 1 || r.Relationships[0].Kind != "instance_of_observed_schema" {
		t.Fatalf("relationships=%#v", r.Relationships)
	}
	foundHash := false
	for _, p := range r.ExportPlan {
		if p.SourceType == "file_metadata" && p.SHA256 == "synthetic" {
			foundHash = true
		}
	}
	if !foundHash {
		t.Fatal("file fingerprint missing from export plan")
	}
	out := filepath.Join(d, "dossier")
	if e = GenerateDossier(out, r); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0700 {
		t.Fatalf("mode=%o", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 13 {
		t.Fatalf("files=%d", len(entries))
	}
	for _, x := range entries {
		st, _ = os.Stat(filepath.Join(out, x.Name()))
		if st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode=%o", x.Name(), st.Mode().Perm())
		}
	}
}

func TestPasswordNameDoesNotProveSecret(t *testing.T) {
	v := syntheticInventory()
	v.Instances[0].Properties = []InstanceProperty{{Name: "Password", CIMType: "String", State: "non_null", Shape: "plaintext_text", Fingerprint: "redacted", LengthBucket: "1-32"}}
	r := Analyze(v)
	for _, c := range r.Candidates {
		if c.SourceType == "wmi_instance_metadata" && c.SecretLikelihood == "likely_plaintext_secret" {
			t.Fatal("name-only secret classification")
		}
	}
}

func TestIntrinsicWMIClassDoesNotProvePolicyOrEncryptedValue(t *testing.T) {
	v := syntheticInventory()
	v.Classes[0].Name = "__EventFilter"
	v.Instances[0].Class = "__EventFilter"
	r := Analyze(v)
	for _, c := range r.Candidates {
		if c.ClassOrFileType == "__EventFilter" && (c.SecretLikelihood == "likely_encrypted_value" || c.Confidence == "medium_value_policy_artifact_candidate" || c.Confidence == "high_value_policy_artifact_candidate") {
			t.Fatalf("intrinsic class overclassified: %#v", c)
		}
	}
}
func TestBoundsAndUnknownSchema(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x.json")
	v := syntheticInventory()
	v.SchemaVersion = 99
	b, _ := json.Marshal(v)
	_ = os.WriteFile(p, b, 0600)
	if _, e := Load(p, DefaultLimits()); e == nil {
		t.Fatal("unknown schema accepted")
	}
	v.SchemaVersion = 1
	v.Files = make([]FileArtifact, DefaultLimits().MaxFiles+1)
	b, _ = json.Marshal(v)
	_ = os.WriteFile(p, b, 0600)
	if _, e := Load(p, DefaultLimits()); e == nil {
		t.Fatal("bounds ignored")
	}
}

func FuzzInventoryParser(f *testing.F) {
	b, _ := json.Marshal(syntheticInventory())
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		p := filepath.Join(t.TempDir(), "i.json")
		_ = os.WriteFile(p, b, 0600)
		_, _ = Load(p, DefaultLimits())
	})
}
func FuzzValueShapeClassifier(f *testing.F) {
	f.Add("Password", "plaintext_text")
	f.Fuzz(func(t *testing.T, n, shape string) {
		if len(n) > 128 || len(shape) > 128 {
			return
		}
		v := syntheticInventory()
		v.Instances[0].Properties = []InstanceProperty{{Name: n, Shape: shape}}
		_ = Analyze(v)
	})
}
func FuzzCandidateScorer(f *testing.F) {
	f.Add("Policy", "binary_blob")
	f.Fuzz(func(t *testing.T, n, s string) {
		if len(n) > 128 || len(s) > 128 {
			return
		}
		v := syntheticInventory()
		v.Classes[0].Name = n
		v.Instances[0].Properties[0].Shape = s
		_ = Analyze(v)
	})
}
func FuzzDossierSerializer(f *testing.F) {
	f.Add("not_ready_no_policy_artifact")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 128 {
			return
		}
		r := Analyze(syntheticInventory())
		r.SecretReadiness = "not_ready_no_policy_artifact"
		_ = GenerateDossier(filepath.Join(t.TempDir(), "d"), r)
	})
}

func TestSchemaRankingSelectionFamiliesAndDossier(t *testing.T) {
	v := syntheticInventory()
	v.Classes = append(v.Classes, ClassSchema{ID: "intrinsic", Namespace: `root\ccm\Policy`, Name: "__EventFilter", InstanceCount: 5, CountState: "bounded", Properties: []PropertySchema{{Name: "Password", CIMType: "String"}}})
	a := AnalyzeSchemas(v, SchemaOptions{MaxClasses: 96, MaxInstances: 2000})
	if len(a.Rankings) != 2 || len(a.Families) != 2 {
		t.Fatalf("rankings=%d families=%d", len(a.Rankings), len(a.Families))
	}
	if !a.Rankings[1].ExcludedByDefault || a.Rankings[1].Classification != "intrinsic_wmi_class" {
		t.Fatalf("intrinsic=%#v", a.Rankings[1])
	}
	if len(a.SelectedInstances) != 1 || a.Readiness != "ready_for_policy_instance_parser" {
		t.Fatalf("instances=%d readiness=%s", len(a.SelectedInstances), a.Readiness)
	}
	if len(a.ContentPlan) != 1 || !a.ContentPlan[0].Eligible || a.ContentPlan[0].Mode != "redacted_preview" {
		t.Fatalf("content=%#v", a.ContentPlan)
	}
	d := filepath.Join(t.TempDir(), "dossier")
	if e := GenerateSchemaDossier(d, a); e != nil {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(d)
	if len(entries) != 11 {
		t.Fatalf("files=%d", len(entries))
	}
	for _, e := range entries {
		st, _ := os.Stat(filepath.Join(d, e.Name()))
		if st.Mode().Perm() != 0600 {
			t.Fatalf("mode %s=%o", e.Name(), st.Mode().Perm())
		}
	}
}

func TestSchemaRankingDoesNotTrustNamesAlone(t *testing.T) {
	v := syntheticInventory()
	v.Classes[0].Namespace = `root\ccm`
	v.Classes[0].Name = "PasswordSecretToken"
	v.Classes[0].InstanceCount = 0
	v.Classes[0].CountState = "bounded"
	v.Instances = nil
	a := AnalyzeSchemas(v, SchemaOptions{})
	if a.Rankings[0].Score >= 45 || a.Readiness != "ready_for_policy_schema_parser" {
		t.Fatalf("ranking=%#v readiness=%s", a.Rankings[0], a.Readiness)
	}
}

func TestInstancePlanBoundsAndDeterminism(t *testing.T) {
	v := syntheticInventory()
	a := AnalyzeSchemas(v, SchemaOptions{MaxClasses: 1, MaxInstances: 1})
	b := AnalyzeSchemas(v, SchemaOptions{MaxClasses: 1, MaxInstances: 1})
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatal("analysis nondeterministic")
	}
}
func TestFixtureParsers(t *testing.T) {
	for _, n := range []string{"policy_authority_v1.json", "policy_assignment_v1.json", "policy_configuration_v1.json", "deployment_state_v1.json"} {
		b, e := os.ReadFile(filepath.Join("..", "..", "testdata", "localartifact", n))
		if e != nil {
			t.Fatal(e)
		}
		p, e := ParsePolicyFixture(b)
		if e != nil || p.Lifecycle != "fixture_validated" {
			t.Fatalf("%s %#v %v", n, p, e)
		}
	}
	if _, e := ParsePolicyFixture([]byte(`{"schema_version":1}`)); e == nil {
		t.Fatal("malformed fixture accepted")
	}
}
func FuzzPolicyFixtureParser(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"namespace":"root\\ccm","class":"CCM_Authority","properties":{}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = ParsePolicyFixture(b)
	})
}

func FuzzSchemaClassifier(f *testing.F) {
	f.Add("CCM_Policy", "root\\ccm\\Policy")
	f.Fuzz(func(t *testing.T, n, ns string) {
		if len(n) > 128 || len(ns) > 256 {
			return
		}
		_ = rankSchema(ClassSchema{ID: "x", Name: n, Namespace: ns})
	})
}
func FuzzSchemaClustering(f *testing.F) {
	f.Add("PolicyID", "String")
	f.Fuzz(func(t *testing.T, n, typ string) {
		if len(n) > 128 || len(typ) > 64 {
			return
		}
		_ = clusterSchemas([]ClassSchema{{ID: "x", Name: "X", Properties: []PropertySchema{{Name: n, CIMType: typ}}}})
	})
}
func FuzzInstancePlanner(f *testing.F) {
	f.Add("CCM_Policy", 1)
	f.Fuzz(func(t *testing.T, n string, count int) {
		if len(n) > 128 || count < 0 || count > 5000 {
			return
		}
		v := syntheticInventory()
		v.Classes[0].Name = n
		v.Classes[0].InstanceCount = count
		_ = AnalyzeSchemas(v, SchemaOptions{})
	})
}
func FuzzContentGate(f *testing.F) {
	f.Add("XML_like", "Data")
	f.Fuzz(func(t *testing.T, shape, name string) {
		if len(shape) > 64 || len(name) > 128 {
			return
		}
		x := syntheticInventory().Instances[0]
		x.Properties[0].Shape = shape
		x.Properties[0].Name = name
		_ = contentPlans(x, syntheticInventory().Classes[0])
	})
}
