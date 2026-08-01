package policy

import (
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"net/http"
	"testing"
)

func FuzzFixtureMetadataParser(f *testing.F) {
	f.Add([]byte("name: synthetic\nsynthetic: true\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m Metadata
		_ = yaml.Unmarshal(b, &m)
	})
}
func FuzzFixtureHeaderParser(f *testing.F) {
	f.Add([]byte("Content-Type: text/xml\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = parseHeaders(b)
	})
}
func FuzzSanitizationManifestParser(f *testing.F) {
	f.Add([]byte(`{"BinaryMode":"metadata_only"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m SanitizationManifest
		_ = json.Unmarshal(b, &m)
	})
}
func FuzzBinaryTextRegionDetector(f *testing.F) {
	f.Add([]byte("ascii\x00w\x00i\x00d\x00e\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFixtureBytes {
			return
		}
		_ = detectTextRegions(b)
	})
}
func FuzzBinaryStringDecoder(f *testing.F) {
	f.Add("value", "replacement", "utf-8")
	f.Fuzz(func(t *testing.T, a, b, e string) {
		if len(a)+len(b) > 1<<16 {
			return
		}
		_, _, _ = encoded(a, b, e)
	})
}
func FuzzReplacementPlanner(f *testing.F) {
	f.Add([]byte("REALDOMAIN"), "REALDOMAIN", "DOMAIN_001")
	f.Fuzz(func(t *testing.T, b []byte, a, r string) {
		if len(b) > 1<<20 || len(a)+len(r) > 1<<16 {
			return
		}
		_, _, _ = replaceText("body", b, []Replacement{{a, r, "fuzz"}})
	})
}
func FuzzStructuredKnownSanitizer(f *testing.F) {
	f.Add([]byte(`<Policy PolicyID="P"/>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFixtureBytes {
			return
		}
		_, _, _ = ParsePolicy(context.Background(), b)
	})
}
func FuzzAssignmentParser(f *testing.F) {
	f.Add([]byte(`<Assignments><Assignment PolicyID="P"/></Assignments>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxFixtureBytes {
			return
		}
		_, _ = ParseAssignments(context.Background(), b, "fixture_fuzz")
	})
}
func FuzzCandidateClassifier(f *testing.F) {
	f.Add("Password", "value")
	f.Fuzz(func(t *testing.T, n, v string) {
		if len(n)+len(v) > 1<<16 {
			return
		}
		_ = Classify(ParsedPolicy{PolicyID: "P", Settings: []Setting{{Name: n, Value: v, Path: "/Policy"}}}, "fixture")
	})
}
func FuzzBundleManifestParser(f *testing.F) {
	f.Add([]byte("schema_version: 1\nbundle_id: bundle_test\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var m BundleManifest
		_ = yaml.Unmarshal(b, &m)
	})
}
func FuzzBundleArchiveValidator(f *testing.F) {
	f.Add("fixtures/example/request.body")
	f.Fuzz(func(t *testing.T, n string) {
		if len(n) > 4096 {
			return
		}
		_ = unsafeMember(n)
	})
}
func FuzzBundleExtractor(f *testing.F) {
	f.Add("bundle.yaml")
	f.Fuzz(func(t *testing.T, n string) {
		if len(n) > 4096 {
			return
		}
		_ = unsafeMember(n)
	})
}
func FuzzFixtureServerRequestMatcher(f *testing.F) {
	f.Add("CCM_POST", "/ccm_system/request")
	f.Fuzz(func(t *testing.T, m, p string) {
		if len(m)+len(p) > 1<<16 {
			return
		}
		r, _ := http.NewRequest(m, "http://127.0.0.1"+p, nil)
		if r != nil {
			_ = r.URL.Path == p
		}
	})
}
func FuzzCanonicalSigningManifest(f *testing.F) {
	f.Add("bundle_x", "key_x")
	f.Fuzz(func(t *testing.T, bundle, key string) {
		if len(bundle)+len(key) > 4096 {
			return
		}
		m := BundleManifest{SchemaVersion: 1, BundleID: bundle, MemberFingerprints: map[string]string{}}
		_, _, _ = canonicalSigning(m, map[string][]byte{}, key)
	})
}
func FuzzSignatureEnvelopeParser(f *testing.F) {
	f.Add([]byte("version: 1\nalgorithm: ed25519\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var x SignatureEnvelope
		_ = yaml.Unmarshal(b, &x)
	})
}
func FuzzResearchSetParser(f *testing.F) {
	f.Add([]byte("schema_version: 1\nname: fuzz\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var x ResearchSet
		_ = yaml.Unmarshal(b, &x)
	})
}
func FuzzComparisonPlanner(f *testing.F) {
	f.Add("route", "a", "b")
	f.Fuzz(func(t *testing.T, k, a, b string) {
		if len(k)+len(a)+len(b) > 1<<16 {
			return
		}
		_ = compareCaptures([]captureProperties{{label: "a", props: map[string]string{k: a}, present: map[string]bool{k: true}}, {label: "b", props: map[string]string{k: b}, present: map[string]bool{k: true}}}, ResearchSet{})
	})
}
func FuzzCorrelationEngine(f *testing.F) {
	f.Add("property", "variable")
	f.Fuzz(func(t *testing.T, p, v string) {
		if len(p)+len(v) > 1<<16 {
			return
		}
		_ = correlate([]PropertyComparison{{Property: p, Classification: "variable_unexplained"}}, ResearchSet{}, nil)
	})
}
func FuzzCandidateContractSerializer(f *testing.F) {
	f.Add("candidate", "unknown")
	f.Fuzz(func(t *testing.T, n, u string) {
		if len(n)+len(u) > 1<<16 {
			return
		}
		_, _ = yaml.Marshal(CandidateContract{Name: n, Unknown: []string{u}, LiveExecutionAllowed: false})
	})
}
func FuzzExpectedAnalysisManifest(f *testing.F) {
	f.Add("name", "sha256:00")
	f.Fuzz(func(t *testing.T, k, v string) {
		if len(k)+len(v) > 1<<16 {
			return
		}
		_, _ = yaml.Marshal(BundleManifest{ExpectedAnalysisFingerprints: map[string]string{k: v}})
	})
}
func FuzzSequenceParser(f *testing.F) {
	f.Add([]byte("- index: 0\n  method: GET\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		var x []SequenceStep
		_ = yaml.Unmarshal(b, &x)
	})
}
func FuzzDossierGeneratorInputs(f *testing.F) {
	f.Add("candidate", "unknown")
	f.Fuzz(func(t *testing.T, id, u string) {
		if len(id)+len(u) > 1<<16 {
			return
		}
		_, _ = yaml.Marshal(struct {
			Contract CandidateContract
			Analysis ResearchAnalysis
		}{CandidateContract{ID: id, Unknown: []string{u}}, ResearchAnalysis{}})
	})
}
