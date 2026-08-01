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
