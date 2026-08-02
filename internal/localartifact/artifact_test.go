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
