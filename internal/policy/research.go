package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ResearchSetSchemaVersion   = 1
	ComparisonAlgorithmVersion = "cross-capture-v1"
	MaxResearchMembers         = 64
)

type ResearchVariables struct {
	Controlled []string `yaml:"controlled,flow" json:"controlled"`
	Fixed      []string `yaml:"fixed,flow" json:"fixed"`
}
type ResearchMember struct {
	Label, Bundle, Fingerprint string
	Expected                   map[string]string `yaml:"expected,omitempty" json:"expected,omitempty"`
	SignatureState             string            `yaml:"signature_state" json:"signature_state"`
}
type ResearchSet struct {
	SchemaVersion     int `yaml:"schema_version" json:"schema_version"`
	Name, Description string
	Variables         struct {
		Controlled []string `yaml:"controlled"`
		Fixed      []string `yaml:"fixed"`
	} `yaml:"variables"`
	Members               []ResearchMember `yaml:"members"`
	RequireValidSignature bool             `yaml:"require_valid_signature,omitempty" json:"require_valid_signature,omitempty"`
	RequireKnownSigner    bool             `yaml:"require_known_signer,omitempty" json:"require_known_signer,omitempty"`
	CreatedAt             time.Time        `yaml:"created_at"`
	Fingerprint           string           `yaml:"fingerprint"`
}
type ExperimentalVariable struct {
	Name, Category, ValueRedacted, Source string
	Controlled                            bool
	Confidence                            string
	FixtureIDs                            []string
}
type PropertyComparison struct {
	Property, Classification, ChangesWith, Confidence, RequirementStatus string
	ObservedFixtures, TotalFixtures                                      int
	Values                                                               []string
	Counterexamples                                                      []string
}
type Correlation struct {
	Observation, Variable, Interpretation, EvidenceType, Confidence string
	Matches, SampleSize, Collisions                                 int
	Counterexamples                                                 []string
}
type SequenceStep struct {
	Index                                                           int
	Method, Route, ResponseClass                                    string
	TimingDelta                                                     string
	SharedIdentifiers, PrecedingDependencies, FollowingDependencies []string
}
type SequenceModel struct {
	ID, Classification string
	Steps              []SequenceStep
	ReplayCoverage     string
}
type ResearchAnalysis struct {
	ResearchSet, AlgorithmVersion string
	BundleStates                  map[string]string
	Variables                     []ExperimentalVariable
	Comparisons                   []PropertyComparison
	Correlations                  []Correlation
	Sequences                     []SequenceModel
	Excluded, Warnings            []string
}
type CandidateContract struct {
	SchemaVersion                                                       int `yaml:"schema_version"`
	ID, Name                                                            string
	VerificationState                                                   VerificationState `yaml:"verification_state"`
	DerivationAlgorithmVersion                                          string            `yaml:"derivation_algorithm_version"`
	ResearchSetFingerprint                                              string            `yaml:"research_set_fingerprint"`
	RequiredObservedHeaders, OptionalObservedHeaders, VariableHeaders   []string
	ConstantObserved, VariableObserved, Heuristic, Unknown, Conflicting []string
	FixtureCoverage, ReplayCoverage, ParserCoverage                     string
	KnownCounterexamples                                                []string
	SafetyReviewState                                                   string
	LiveExecutionAllowed                                                bool `yaml:"live_execution_allowed"`
}
type SafetyReview struct {
	ReviewID, ContractID, ReviewerReference                                                                                                        string
	ReviewTimestamp                                                                                                                                time.Time
	Scope, ReadOnlyEvidence, StateChangeEvidence                                                                                                   string
	IdentityPrerequisitesReviewed, AuthenticationReviewed, RequestBodyReviewed, ResponseHandlingReviewed, RateLimitsReviewed, FailureModesReviewed bool
	UnknownsAccepted                                                                                                                               []string
	Decision, NotesRedacted                                                                                                                        string
}

var variableCategories = map[string]bool{"client_identity": true, "client_guid": true, "client_certificate": true, "site_code": true, "management_point": true, "management_point_version": true, "client_version": true, "operating_system": true, "domain": true, "authentication_method": true, "transport": true, "policy_action": true, "capture_time": true, "request_sequence": true, "unknown": true}

func CreateResearchSet(name, description, output string) error {
	if strings.TrimSpace(name) == "" || len(name) > 128 {
		return errors.New("bounded research-set name is required")
	}
	r := ResearchSet{SchemaVersion: 1, Name: name, Description: description, CreatedAt: time.Now().UTC()}
	r.Fingerprint = researchFingerprint(r)
	b, _ := yaml.Marshal(r)
	return atomicWrite(output, b, 0600, false)
}
func SetResearchVariables(path string, controlled, fixed []string) error {
	r, e := LoadResearchSet(path)
	if e != nil {
		return e
	}
	for _, v := range append(append([]string{}, controlled...), fixed...) {
		if !variableCategories[v] {
			return fmt.Errorf("unsupported experimental variable %s", v)
		}
	}
	r.Variables.Controlled = append([]string(nil), controlled...)
	r.Variables.Fixed = append([]string(nil), fixed...)
	sort.Strings(r.Variables.Controlled)
	sort.Strings(r.Variables.Fixed)
	r.Fingerprint = researchFingerprint(r)
	b, _ := yaml.Marshal(r)
	return atomicWrite(path, b, 0600, true)
}
func LoadResearchSet(path string) (ResearchSet, error) {
	var r ResearchSet
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	if len(b) > 1<<20 {
		return r, errors.New("research set exceeds limit")
	}
	if e = yaml.Unmarshal(b, &r); e != nil || r.SchemaVersion != 1 {
		return r, errors.New("invalid research set")
	}
	if len(r.Members) > MaxResearchMembers {
		return r, errors.New("research set member limit exceeded")
	}
	return r, nil
}
func researchFingerprint(r ResearchSet) string {
	r.Fingerprint = ""
	b, _ := json.Marshal(r)
	x := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(x[:])
}
func AddResearchBundle(setPath, bundle, label string, expected map[string]string, trusted string) (ResearchSet, error) {
	r, e := LoadResearchSet(setPath)
	if e != nil {
		return r, e
	}
	if label == "" || len(label) > 128 {
		return r, errors.New("bounded member label is required")
	}
	for _, m := range r.Members {
		if m.Label == label {
			return r, errors.New("duplicate research-set label")
		}
	}
	info, e := InspectBundle(bundle)
	if e != nil {
		return r, e
	}
	v, e := VerifyBundle(bundle, trusted)
	if e != nil && v.State != "unsigned" && v.State != "unknown_signer" {
		return r, e
	}
	if r.RequireValidSignature && v.State != "signature_valid" && v.State != "unknown_signer" {
		return r, errors.New("research set requires valid signatures")
	}
	if r.RequireKnownSigner && !v.SignerKnown {
		return r, errors.New("research set requires a known signer")
	}
	for k := range expected {
		if !variableCategories[k] {
			return r, fmt.Errorf("unsupported experimental variable %s", k)
		}
	}
	for k, v := range expected {
		if k == "client_identity" || k == "client_guid" || k == "client_certificate" || k == "domain" || k == "management_point" {
			expected[k] = redactResearch(v)
		}
	}
	sum := sha256.Sum256([]byte(info.Manifest.BundleID + fmt.Sprint(info.Manifest.MemberFingerprints)))
	r.Members = append(r.Members, ResearchMember{label, bundle, "sha256:" + hex.EncodeToString(sum[:]), expected, v.State})
	sort.Slice(r.Members, func(i, j int) bool { return r.Members[i].Label < r.Members[j].Label })
	r.Fingerprint = researchFingerprint(r)
	b, _ := yaml.Marshal(r)
	return r, atomicWrite(setPath, b, 0600, true)
}

type captureProperties struct {
	label    string
	fixtures []string
	props    map[string]string
	present  map[string]bool
}

func AnalyzeResearchSet(path, trusted string) (ResearchAnalysis, error) {
	r, e := LoadResearchSet(path)
	if e != nil {
		return ResearchAnalysis{}, e
	}
	a := ResearchAnalysis{r.Name, ComparisonAlgorithmVersion, map[string]string{}, nil, nil, nil, nil, nil, nil}
	var captures []captureProperties
	for _, member := range r.Members {
		v, ve := VerifyBundle(member.Bundle, trusted)
		a.BundleStates[member.Label] = v.State
		if ve != nil && v.State != "unknown_signer" {
			a.Excluded = append(a.Excluded, member.Label+": "+v.State)
			continue
		}
		info, data, e := readBundleMembers(member.Bundle)
		if e != nil {
			a.Excluded = append(a.Excluded, member.Label+": invalid_bundle")
			continue
		}
		cp := captureProperties{member.Label, info.Manifest.FixtureIDs, map[string]string{}, map[string]bool{}}
		var steps []SequenceStep
		for stepIndex, fid := range info.Manifest.FixtureIDs {
			base := "fixtures/" + fid + "/"
			var m Metadata
			if yaml.Unmarshal(data[base+"metadata.yaml"], &m) != nil {
				continue
			}
			steps = append(steps, SequenceStep{Index: stepIndex, Method: m.Request.Method, Route: m.Request.Route, ResponseClass: strconv.Itoa(m.Response.Status), TimingDelta: "unknown"})
			setProp(&cp, "request.method", m.Request.Method)
			setProp(&cp, "request.route", m.Request.Route)
			setProp(&cp, "response.status", strconv.Itoa(m.Response.Status))
			setProp(&cp, "request.content_type", m.Request.ContentType)
			setProp(&cp, "response.content_type", m.Response.ContentType)
			setProp(&cp, "request.body_size", strconv.Itoa(len(data[base+"request.body"])))
			setProp(&cp, "response.body_size", strconv.Itoa(len(data[base+"response.body"])))
			setProp(&cp, "request.body_fingerprint", hashRedacted(data[base+"request.body"]))
			setProp(&cp, "response.body_fingerprint", hashRedacted(data[base+"response.body"]))
			for _, side := range []string{"request", "response"} {
				h, _ := parseHeaders(data[base+side+".headers"])
				names := make([]string, 0, len(h))
				for k, v := range h {
					names = append(names, k)
					setProp(&cp, side+".header."+strings.ToLower(k), hashRedacted([]byte(strings.Join(v, "\x00"))))
				}
				sort.Strings(names)
				setProp(&cp, side+".header_names", strings.Join(names, ","))
			}
			for _, side := range []string{"request", "response"} {
				bi, _ := InspectBinary(data[base+side+".body"])
				desc := make([]string, 0, len(bi.Observations))
				for _, o := range bi.Observations {
					desc = append(desc, fmt.Sprintf("%d:%d:%s:%s", o.Offset, o.Length, o.Classification, o.Description))
				}
				setProp(&cp, side+".binary_observations", hashRedacted([]byte(strings.Join(desc, "|"))))
			}
		}
		captures = append(captures, cp)
		for k, v := range member.Expected {
			a.Variables = append(a.Variables, ExperimentalVariable{k, k, redactResearch(v), "operator_supplied", contains(r.Variables.Controlled, k), "high", info.Manifest.FixtureIDs})
		}
		class := "single_request"
		if len(steps) > 1 {
			class = "not_comparable_order_not_preserved"
			a.Warnings = append(a.Warnings, member.Label+": multiple exchanges present but capture ordering metadata is absent")
		}
		a.Sequences = append(a.Sequences, SequenceModel{"sequence_" + member.Label, class, steps, "not_tested"})
	}
	a.Comparisons = compareCaptures(captures, r)
	a.Correlations = correlate(a.Comparisons, r, captures)
	for _, c := range a.Correlations {
		for i := range a.Comparisons {
			if a.Comparisons[i].Property == c.Observation {
				a.Comparisons[i].Classification = "variable_with_controlled_factor"
				a.Comparisons[i].ChangesWith = c.Variable
			}
		}
	}
	if len(captures) < 2 {
		a.Warnings = append(a.Warnings, "fewer than two comparable captures; required fields cannot be high confidence")
	}
	return a, nil
}
func setProp(c *captureProperties, k, v string) {
	if old, ok := c.props[k]; ok && old != v {
		c.props[k] = "[conflicting]"
	}
	c.present[k] = true
	if _, ok := c.props[k]; !ok {
		c.props[k] = v
	}
}
func compareCaptures(cs []captureProperties, r ResearchSet) []PropertyComparison {
	keys := map[string]bool{}
	for _, c := range cs {
		for k := range c.present {
			keys[k] = true
		}
	}
	var out []PropertyComparison
	for k := range keys {
		vals := map[string][]string{}
		present := 0
		for _, c := range cs {
			if c.present[k] {
				present++
				vals[c.props[k]] = append(vals[c.props[k]], c.label)
			}
		}
		p := PropertyComparison{Property: k, ObservedFixtures: present, TotalFixtures: len(cs), RequirementStatus: "observed, not approved", Confidence: "medium"}
		for v := range vals {
			p.Values = append(p.Values, v)
		}
		sort.Strings(p.Values)
		switch {
		case present < len(cs):
			p.Classification = "present_in_subset"
		case len(vals) == 1:
			p.Classification = "constant_across_set"
			if len(cs) >= 3 {
				p.Confidence = "high"
			}
		case vals["[conflicting]"] != nil:
			p.Classification = "conflicting"
		default:
			p.Classification = "variable_unexplained"
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Property < out[j].Property })
	return out
}
func correlate(ps []PropertyComparison, r ResearchSet, cs []captureProperties) []Correlation {
	var out []Correlation
	for _, p := range ps {
		if p.Classification != "variable_unexplained" {
			continue
		}
		for _, v := range r.Variables.Controlled {
			values := map[string]string{}
			matches := 0
			counter := []string{}
			for _, c := range cs {
				var rv string
				for _, m := range r.Members {
					if m.Label == c.label {
						rv = m.Expected[v]
					}
				}
				if rv == "" {
					continue
				}
				key := hashRedacted([]byte(rv))
				if prev, ok := values[key]; !ok || prev == c.props[p.Property] {
					matches++
					values[key] = c.props[p.Property]
				} else {
					counter = append(counter, c.label)
				}
			}
			if matches >= 2 {
				conf := "low"
				if matches >= 4 && len(counter) == 0 {
					conf = "medium"
				}
				out = append(out, Correlation{p.Property, v, "possible association with declared controlled variable; causation not established", "correlation_only", conf, matches, matches + len(counter), 0, counter})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Observation+out[i].Variable < out[j].Observation+out[j].Variable })
	return out
}
func hashRedacted(b []byte) string {
	x := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(x[:])
}
func redactResearch(v string) string {
	if v == "" {
		return "[unknown]"
	}
	return "fingerprint:" + strings.TrimPrefix(hashRedacted([]byte(strings.TrimSpace(strings.ToLower(v)))), "sha256:")[:16]
}
func contains(v []string, x string) bool {
	for _, s := range v {
		if s == x {
			return true
		}
	}
	return false
}
func DeriveCandidateContract(setPath, output string, single bool) (CandidateContract, error) {
	r, e := LoadResearchSet(setPath)
	if e != nil {
		return CandidateContract{}, e
	}
	a, e := AnalyzeResearchSet(setPath, "")
	if e != nil {
		return CandidateContract{}, e
	}
	if len(r.Members) < 2 && !single {
		return CandidateContract{}, errors.New("candidate derivation requires two comparable fixtures or explicit single-fixture research")
	}
	c := CandidateContract{SchemaVersion: 1, Name: r.Name, VerificationState: CandidateContractState, DerivationAlgorithmVersion: ComparisonAlgorithmVersion, ResearchSetFingerprint: r.Fingerprint, FixtureCoverage: fmt.Sprintf("%d comparable; %d excluded", len(r.Members)-len(a.Excluded), len(a.Excluded)), ReplayCoverage: "local replay evidence only", ParserCoverage: "bounded fixture metadata and binary observations", SafetyReviewState: "not_reviewed", LiveExecutionAllowed: false, Unknown: []string{"identity prerequisites", "live read-only behavior", "version coverage", "failure semantics"}}
	for _, p := range a.Comparisons {
		switch p.Classification {
		case "constant_across_set":
			c.ConstantObserved = append(c.ConstantObserved, p.Property)
			if strings.Contains(p.Property, "header.") && len(r.Members) >= 2 {
				c.RequiredObservedHeaders = append(c.RequiredObservedHeaders, strings.TrimPrefix(p.Property, "request.header."))
			}
		case "variable_unexplained", "variable_with_controlled_factor":
			c.VariableObserved = append(c.VariableObserved, p.Property)
		case "conflicting":
			c.Conflicting = append(c.Conflicting, p.Property)
			c.KnownCounterexamples = append(c.KnownCounterexamples, p.Counterexamples...)
		}
	}
	raw, _ := yaml.Marshal(c)
	x := sha256.Sum256(raw)
	c.ID = "candidate_contract_" + hex.EncodeToString(x[:10])
	raw, _ = yaml.Marshal(c)
	return c, atomicWrite(output, raw, 0600, false)
}
func CreateDossier(c CandidateContract, a ResearchAnalysis, output string, force bool) error {
	if _, e := os.Lstat(output); e == nil && !force {
		return errors.New("dossier output already exists")
	}
	parent := filepath.Dir(output)
	_ = os.MkdirAll(parent, 0700)
	tmp, e := os.MkdirTemp(parent, ".dossier-*")
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	contract, _ := yaml.Marshal(c)
	summary, _ := json.MarshalIndent(a, "", "  ")
	files := map[string][]byte{"README.md": []byte("# Protocol contract dossier\n\nLive SCCM execution is not approved.\nThis dossier is research evidence, not authorization.\n"), "contract.yaml": contract, "evidence-summary.json": summary, "fixture-matrix.csv": csvComparisons(a.Comparisons), "property-provenance.csv": []byte("property,source,requirement_status\n"), "correlation-candidates.csv": csvCorrelations(a.Correlations), "counterexamples.csv": []byte("property,counterexample\n"), "unknowns.md": []byte("# Unresolved unknowns\n\n" + strings.Join(c.Unknown, "\n")), "replay-coverage.md": []byte("# Replay coverage\n\n" + c.ReplayCoverage + "\n"), "safety-review.md": []byte("# Safety review\n\nState: " + c.SafetyReviewState + "\n"), "live-approval-checklist.md": []byte("# Informational checklist only\n\nThis file does not grant approval or change execution permissions.\n")}
	for n, b := range files {
		if e = atomicWrite(filepath.Join(tmp, n), b, 0600, false); e != nil {
			return e
		}
	}
	_ = os.Chmod(tmp, 0700)
	backup := ""
	if force {
		if _, e = os.Lstat(output); e == nil {
			backup = output + ".previous"
			if _, e = os.Lstat(backup); e == nil {
				return errors.New("dossier backup already exists")
			}
			if e = os.Rename(output, backup); e != nil {
				return e
			}
		}
	}
	if e = os.Rename(tmp, output); e != nil {
		if backup != "" {
			_ = os.Rename(backup, output)
		}
		return e
	}
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	ok = true
	return nil
}
func csvComparisons(v []PropertyComparison) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"property", "classification", "observed", "total", "confidence"})
	for _, p := range v {
		_ = w.Write([]string{p.Property, p.Classification, strconv.Itoa(p.ObservedFixtures), strconv.Itoa(p.TotalFixtures), p.Confidence})
	}
	w.Flush()
	return b.Bytes()
}
func csvCorrelations(v []Correlation) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"observation", "variable", "matches", "sample_size", "confidence"})
	for _, c := range v {
		_ = w.Write([]string{c.Observation, c.Variable, strconv.Itoa(c.Matches), strconv.Itoa(c.SampleSize), c.Confidence})
	}
	w.Flush()
	return b.Bytes()
}
func SaveSafetyReview(path string, r SafetyReview) error {
	allowed := map[string]bool{"not_reviewed": true, "needs_more_evidence": true, "rejected": true, "candidate_read_only": true, "approved_for_local_replay": true}
	if !allowed[r.Decision] {
		return errors.New("invalid safety review decision")
	}
	if r.ReviewerReference == "" || len(r.ReviewerReference) > 128 {
		return errors.New("bounded reviewer reference is required")
	}
	if len(r.NotesRedacted) > 512 {
		return errors.New("redacted review notes exceed limit")
	}
	low := strings.ToLower(r.NotesRedacted)
	for _, bad := range []string{"password=", "authorization:", "bearer ", "private key"} {
		if strings.Contains(low, bad) {
			return errors.New("review notes contain a forbidden sensitive indicator")
		}
	}
	r.ReviewTimestamp = time.Now().UTC()
	seed, _ := json.Marshal(r)
	x := sha256.Sum256(seed)
	r.ReviewID = "safety_review_" + hex.EncodeToString(x[:10])
	b, _ := yaml.Marshal(r)
	return atomicWrite(path, b, 0600, false)
}

type ExpectedTestResult struct {
	Signature, Members, ExpectedAnalysis, ParserVersion string
	LiveTraffic                                         string
}

func TestBundleExpected(path, trusted string) (ExpectedTestResult, error) {
	v, e := VerifyBundle(path, trusted)
	r := ExpectedTestResult{v.State, v.Integrity, "passed", "compatible", "none"}
	if e != nil {
		return r, e
	}
	if v.State != "signature_valid" && v.State != "unknown_signer" {
		r.ExpectedAnalysis = "not_run"
		return r, errors.New("signed bundle required")
	}
	info, members, e := readBundleMembers(path)
	if e != nil {
		return r, e
	}
	if len(info.Manifest.ExpectedAnalysisFingerprints) == 0 {
		r.ExpectedAnalysis = "not_present"
		return r, nil
	}
	compatible := false
	for _, v := range info.Manifest.ParserVersions {
		if v == "policy-xml-v1" {
			compatible = true
		}
	}
	if !compatible {
		r.ParserVersion = "incompatible"
		r.ExpectedAnalysis = "not_run"
		return r, errors.New("parser version mismatch")
	}
	for k, v := range info.Manifest.ExpectedAnalysisFingerprints {
		if k == "" || !strings.HasPrefix(v, "sha256:") {
			r.ExpectedAnalysis = "failed"
			return r, errors.New("invalid expected-analysis fingerprint")
		}
		if k == "offline_analysis_v1" {
			got := offlineAnalysisFingerprint(info.Manifest, members)
			if got != v {
				r.ExpectedAnalysis = "failed"
				return r, errors.New("expected offline analysis mismatch")
			}
		}
	}
	return r, nil
}
func offlineAnalysisFingerprint(m BundleManifest, members map[string][]byte) string {
	summary := map[string]any{"fixtures": len(m.FixtureIDs), "assignments": 0, "policies": 0, "candidate_categories": map[string]int{}, "protected": 0, "plaintext": 0, "binary": []string{}}
	cats := summary["candidate_categories"].(map[string]int)
	var bins []string
	for _, fid := range m.FixtureIDs {
		base := "fixtures/" + fid + "/"
		body := members[base+"response.body"]
		if a, e := ParseAssignments(context.Background(), body, fid); e == nil {
			summary["assignments"] = summary["assignments"].(int) + len(a)
		}
		if _, cs, e := ParsePolicy(context.Background(), body); e == nil {
			summary["policies"] = summary["policies"].(int) + 1
			for _, c := range cs {
				cats[c.Category]++
				if c.Protected {
					summary["protected"] = summary["protected"].(int) + 1
				}
				if c.State == "confirmed_plaintext" || c.State == "plaintext_candidate" {
					summary["plaintext"] = summary["plaintext"].(int) + 1
				}
			}
		}
		for _, side := range []string{"request", "response"} {
			x, _ := InspectBinary(members[base+side+".body"])
			raw, _ := json.Marshal(x.Observations)
			bins = append(bins, hashRedacted(raw))
		}
	}
	sort.Strings(bins)
	summary["binary"] = bins
	raw, _ := json.Marshal(summary)
	return hashRedacted(raw)
}
