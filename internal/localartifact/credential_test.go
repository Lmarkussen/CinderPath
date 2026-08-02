package localartifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func credentialInventory() Inventory {
	ns := `root\ccm\Policy\Machine\ActualConfig`
	classes := []ClassSchema{
		{ID: "naa-schema", Namespace: ns, Name: "CCM_NetworkAccessAccount", InstanceCount: 1, Properties: []PropertySchema{{Name: "NetworkAccessUsername", CIMType: "String"}, {Name: "NetworkAccessPassword", CIMType: "String"}, {Name: "PolicyID", CIMType: "String", Key: true}}},
		{ID: "ts-schema", Namespace: ns, Name: "CCM_TaskSequence", InstanceCount: 1, Properties: []PropertySchema{{Name: "TaskSequence", CIMType: "String"}, {Name: "Account", CIMType: "String"}, {Name: "Password", CIMType: "String"}}},
		{ID: "var-schema", Namespace: ns, Name: "CCM_CollectionVariable", InstanceCount: 1, Properties: []PropertySchema{{Name: "Name", CIMType: "String"}, {Name: "Value", CIMType: "String"}, {Name: "Protected", CIMType: "Boolean"}}},
		{ID: "weak", Namespace: ns, Name: "GenericAccount", InstanceCount: 1, Properties: []PropertySchema{{Name: "Password", CIMType: "String"}}},
		{ID: "authority", Namespace: ns, Name: "CCM_Authority", InstanceCount: 1, Properties: []PropertySchema{{Name: "Capabilities", CIMType: "String"}}},
		{ID: "provider", Namespace: ns, Name: "CCM_CredentialProvider", InstanceCount: 1, Properties: []PropertySchema{{Name: "Password", CIMType: "String"}}},
	}
	instances := []InstanceMetadata{{ID: "naa-i", Namespace: ns, Class: "CCM_NetworkAccessAccount", Properties: []InstanceProperty{{Name: "NetworkAccessUsername", Shape: "plaintext_text"}, {Name: "NetworkAccessPassword", Shape: "encrypted_or_opaque", Fingerprint: "abcdef", LengthBucket: "33-256"}}}, {ID: "ts-i", Namespace: ns, Class: "CCM_TaskSequence", Properties: []InstanceProperty{{Name: "TaskSequence", Shape: "XML_like", Fingerprint: "1234", LengthBucket: "257-4096"}}}, {ID: "var-i", Namespace: ns, Class: "CCM_CollectionVariable", Properties: []InstanceProperty{{Name: "Value", Shape: "base64_like", Fingerprint: "5678", LengthBucket: "33-256"}}}}
	return Inventory{SchemaVersion: 1, Classes: classes, Instances: instances}
}

func TestCredentialRegistryAndAnalysis(t *testing.T) {
	targets := CredentialTargets()
	if len(targets) != 8 {
		t.Fatalf("targets=%d", len(targets))
	}
	for i := 1; i < len(targets); i++ {
		if targets[i-1].TargetID >= targets[i].TargetID {
			t.Fatal("not deterministic")
		}
	}
	a := AnalyzeCredentialPolicies(credentialInventory())
	if len(a.NAACandidates) != 1 || a.NAACandidates[0].Classification != "naa_protected_value_candidate" {
		t.Fatalf("naa=%+v", a.NAACandidates)
	}
	if len(a.TaskSequenceCandidates) == 0 || len(a.VariableCandidates) == 0 {
		t.Fatal("secondary targets missing")
	}
	for _, m := range a.SchemaMatches {
		if m.Class == "GenericAccount" || m.Class == "CCM_Authority" || m.Class == "CCM_CredentialProvider" {
			t.Fatalf("weak/noise class matched: %s", m.Class)
		}
	}
	if a.Readiness != "ready_for_targeted_policy_instance_parser" {
		t.Fatal(a.Readiness)
	}
}

func TestCredentialNegativeAndDossier(t *testing.T) {
	v := Inventory{SchemaVersion: 1, Classes: []ClassSchema{{ID: "x", Namespace: `root\ccm\Policy\Machine`, Name: "Unknown", Properties: []PropertySchema{{Name: "Password", CIMType: "String"}}, InstanceCount: 1}}}
	a := AnalyzeCredentialPolicies(v)
	if len(a.SchemaMatches) != 0 || a.Readiness != "no_credential_policy_evidence" {
		t.Fatalf("false positive: %+v", a)
	}
	d := filepath.Join(t.TempDir(), "dossier")
	a = AnalyzeCredentialPolicies(credentialInventory())
	if e := WriteCredentialAnalysis(d, a); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(d)
	if st.Mode().Perm() != 0700 {
		t.Fatal(st.Mode())
	}
	for _, n := range []string{"credential-target-registry.json", "naa-candidates.json", "credential-readiness.json", "safety-boundaries.md"} {
		st, e := os.Stat(filepath.Join(d, n))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("%s %v", n, e)
		}
	}
}

func TestCredentialCollectorSafety(t *testing.T) {
	s := CredentialCollectorPowerShell(AnalyzeCredentialPolicies(credentialInventory()))
	for _, want := range []string{"Get-CimInstance", "Select-Object -First 128", "function Buckets", "entropy_bucket", "reference_fingerprints", "SCCM client methods invoked: 0", "Live SCCM policy requests: 0", "SHA256]::Create", "UTF8Encoding($false)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, bad := range []string{"TriggerSchedule", "RequestMachinePolicy", "EvaluateMachinePolicy", "Invoke-WebRequest", "Set-CimInstance", "Set-WmiInstance", "SHA256.HashData", "Convert.ToHexString", "utf8NoBOM"} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %s", bad)
		}
	}
}

func FuzzCredentialRuntime(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"instances":[],"classes_planned":0,"instances_observed":0,"sccm_methods_invoked":0,"live_policy_requests":0,"raw_values_copied":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "x.json")
		_ = os.WriteFile(p, b, 0600)
		_, _ = LoadCredentialRuntime(p)
	})
}
