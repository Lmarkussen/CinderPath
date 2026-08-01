package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func makeUnsignedBundle(t *testing.T, path string) Contract {
	t.Helper()
	_, c, e := ImportDirectory("testdata/example01")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ExportBundle(BundleExportOptions{Contract: c, FixtureDirectories: []string{"testdata/example01"}, Output: path, ToolVersion: "test"}); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestSigningKeySignVerifyAndExpectedResults(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "research-key")
	id, e := GenerateSigningKey(key, false)
	if e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(key)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("private mode %o", st.Mode().Perm())
	}
	if _, e = GenerateSigningKey(key, false); e == nil {
		t.Fatal("overwrote key")
	}
	unsigned := filepath.Join(d, "unsigned.tar.gz")
	makeUnsignedBundle(t, unsigned)
	v, e := VerifyBundle(unsigned, "")
	if e != nil || v.State != "unsigned" {
		t.Fatalf("unsigned: %#v %v", v, e)
	}
	signed := filepath.Join(d, "signed.tar.gz")
	env, e := SignBundle(unsigned, key, signed)
	if e != nil {
		t.Fatal(e)
	}
	if env.KeyID != id {
		t.Fatal("key ID mismatch")
	}
	v, e = VerifyBundle(signed, "")
	if e != nil || v.State != "signature_valid" || v.ContractPromotion != "none" {
		t.Fatalf("verify: %#v %v", v, e)
	}
	trusted := filepath.Join(d, "trusted")
	_ = os.Mkdir(trusted, 0700)
	pub, _ := os.ReadFile(key + ".pub")
	_ = os.WriteFile(filepath.Join(trusted, "key.pub"), pub, 0644)
	v, e = VerifyBundle(signed, trusted)
	if e != nil || !v.SignerKnown {
		t.Fatalf("trusted: %#v %v", v, e)
	}
	r, e := TestBundleExpected(signed, trusted)
	if e != nil || r.LiveTraffic != "none" || r.ExpectedAnalysis != "not_present" {
		t.Fatalf("expected: %#v %v", r, e)
	}
	info2, members2, e := readBundleMembers(unsigned)
	if e != nil {
		t.Fatal(e)
	}
	info2.Manifest.ExpectedAnalysisFingerprints = map[string]string{"offline_analysis_v1": offlineAnalysisFingerprint(info2.Manifest, members2)}
	members2["bundle.yaml"], _ = yaml.Marshal(info2.Manifest)
	withExpected := filepath.Join(d, "expected.tar.gz")
	if e = writeBundle(withExpected, members2); e != nil {
		t.Fatal(e)
	}
	signedExpected := filepath.Join(d, "expected.signed.tar.gz")
	if _, e = SignBundle(withExpected, key, signedExpected); e != nil {
		t.Fatal(e)
	}
	r, e = TestBundleExpected(signedExpected, trusted)
	if e != nil || r.ExpectedAnalysis != "passed" {
		t.Fatalf("signed expected analysis: %#v %v", r, e)
	}
	_, members, e := readBundleMembers(signed)
	if e != nil {
		t.Fatal(e)
	}
	for n, b := range members {
		if strings.Contains(string(b), "PRIVATE") && n != "fixtures/" {
			t.Fatalf("private marker in %s", n)
		}
	}
}
func TestSignatureModificationRejected(t *testing.T) {
	d := t.TempDir()
	key := filepath.Join(d, "key")
	_, _ = GenerateSigningKey(key, false)
	u := filepath.Join(d, "u.tar.gz")
	makeUnsignedBundle(t, u)
	s := filepath.Join(d, "s.tar.gz")
	_, _ = SignBundle(u, key, s)
	info, members, e := readBundleMembers(s)
	if e != nil {
		t.Fatal(e)
	}
	_ = info
	members["schemas/README.txt"] = []byte("changed")
	bad := filepath.Join(d, "bad.tar.gz")
	if e = writeBundle(bad, members); e != nil {
		t.Fatal(e)
	}
	v, e := VerifyBundle(bad, "")
	if e == nil || v.State != "member_fingerprint_mismatch" {
		t.Fatalf("modified accepted %#v %v", v, e)
	}
}
func TestResearchSetComparisonCandidateAndDossier(t *testing.T) {
	d := t.TempDir()
	b1 := filepath.Join(d, "a.tar.gz")
	b2 := filepath.Join(d, "b.tar.gz")
	makeUnsignedBundle(t, b1)
	makeUnsignedBundle(t, b2)
	set := filepath.Join(d, "set.yaml")
	if e := CreateResearchSet("baseline", "synthetic", set); e != nil {
		t.Fatal(e)
	}
	if e := SetResearchVariables(set, []string{"client_identity"}, []string{"management_point"}); e != nil {
		t.Fatal(e)
	}
	if _, e := AddResearchBundle(set, b1, "client-a", map[string]string{"client_identity": "CLIENT_A"}, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := AddResearchBundle(set, b2, "client-b", map[string]string{"client_identity": "CLIENT_B"}, ""); e != nil {
		t.Fatal(e)
	}
	a, e := AnalyzeResearchSet(set, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(a.Comparisons) == 0 || len(a.Sequences) != 2 {
		t.Fatal("analysis incomplete")
	}
	for _, v := range a.Variables {
		if strings.Contains(v.ValueRedacted, "CLIENT_") {
			t.Fatal("variable leaked")
		}
	}
	candidate := filepath.Join(d, "candidate.yaml")
	c, e := DeriveCandidateContract(set, candidate, false)
	if e != nil {
		t.Fatal(e)
	}
	if c.VerificationState != CandidateContractState || c.LiveExecutionAllowed {
		t.Fatal("candidate trust violation")
	}
	dossier := filepath.Join(d, "dossier")
	if e = CreateDossier(c, a, dossier, false); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"README.md", "contract.yaml", "evidence-summary.json", "fixture-matrix.csv", "property-provenance.csv", "correlation-candidates.csv", "counterexamples.csv", "unknowns.md", "replay-coverage.md", "safety-review.md", "live-approval-checklist.md"} {
		if _, e = os.Stat(filepath.Join(dossier, n)); e != nil {
			t.Fatal(n, e)
		}
	}
	readme, _ := os.ReadFile(filepath.Join(dossier, "README.md"))
	if !bytes.Contains(readme, []byte("not approved")) {
		t.Fatal("live warning missing")
	}
}
func TestSafetyReviewCannotApproveLive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "review.yaml")
	if e := SaveSafetyReview(p, SafetyReview{ContractID: "candidate", ReviewerReference: "LAB_REVIEW_1", Decision: "approved_live"}); e == nil {
		t.Fatal("approved_live review accepted")
	}
}

var _ = tar.TypeReg
var _ = gzip.BestSpeed
