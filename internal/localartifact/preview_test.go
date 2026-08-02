package localartifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func previewInventory() Inventory {
	v := syntheticInventory()
	v.Instances[0].Properties = []InstanceProperty{{Name: "Capabilities", CIMType: "String", Shape: "XML_like", Fingerprint: "abc", LengthBucket: "33-256"}}
	return v
}

func TestPreviewPlanAndPowerShellSafety(t *testing.T) {
	p := BuildPreviewPlan(previewInventory())
	if len(p.Candidates) != 1 || p.Candidates[0].RawCopyEligible {
		t.Fatalf("%#v", p)
	}
	s := PreviewPowerShell(p)
	for _, want := range []string{"DtdProcessing]::Prohibit", "XmlResolver=$null", "Get-CimInstance", "original_sha256", "raw_values_copied=0", "New-Object Text.UTF8Encoding($false)"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, bad := range []string{"Invoke-WebRequest", "Invoke-RestMethod", "TriggerSchedule", "RequestMachinePolicy", "EvaluateMachinePolicy", "Set-CimInstance", "Set-WmiInstance", "Set-ItemProperty", "Export-PfxCertificate", "SHA256]::HashData", "Convert]::ToHexString", "utf8NoBOM"} {
		if strings.Contains(s, bad) {
			t.Fatalf("forbidden %s", bad)
		}
	}
}

func TestPreviewAnalysisAndDossier(t *testing.T) {
	p := BuildPreviewPlan(previewInventory())
	x := PropertyPreview{CandidateID: p.Candidates[0].CandidateID, Class: "SMS_Authority", Property: "Capabilities", Found: true, PreviewEmitted: true, RedactedPreview: "<Capabilities>[TEXT_REDACTED len=4]</Capabilities>", Structure: XMLStructure{WellFormed: true, RootElement: "Capabilities", ElementNames: map[string]int{"Capabilities": 1}, AttributeNames: map[string]int{}, Warnings: []string{}}}
	c := PreviewCollection{SchemaVersion: 1, CandidatesPlanned: 1, CandidatesFound: 1, PropertiesRead: 1, Previews: []PropertyPreview{x}}
	a := AnalyzePreviews(p, c)
	if a.Classifications[0].Classification != "authority_capability_metadata" || a.Parsers[0].Lifecycle != "runtime_preview_validated" {
		t.Fatalf("%#v", a)
	}
	d := filepath.Join(t.TempDir(), "d")
	if e := GeneratePreviewDossier(d, a); e != nil {
		t.Fatal(e)
	}
	es, _ := os.ReadDir(d)
	if len(es) != 9 {
		t.Fatalf("files=%d", len(es))
	}
}

func TestPreviewCollectionBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(p, []byte(`{"schema_version":1,"candidates_planned":4,"previews":[],"sccm_methods_invoked":0,"live_policy_requests":0,"raw_values_copied":0}`), 0600)
	if _, e := LoadPreviewCollection(p); e == nil {
		t.Fatal("unsafe collection accepted")
	}
}

func FuzzPreviewCollection(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"previews":[],"live_policy_requests":0,"raw_values_copied":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		p := filepath.Join(t.TempDir(), "x")
		_ = os.WriteFile(p, b, 0600)
		_, _ = LoadPreviewCollection(p)
	})
}
