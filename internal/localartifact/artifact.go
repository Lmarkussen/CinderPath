package localartifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var safeLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,64}$`)

func fp(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func id(prefix string, parts ...string) string {
	return prefix + "_" + fp(strings.Join(parts, "\x00"))[:20]
}

func Load(path string, limits Limits) (Inventory, error) {
	f, e := os.Open(path)
	if e != nil {
		return Inventory{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 32<<20+1))
	if e != nil {
		return Inventory{}, e
	}
	if len(b) > 32<<20 {
		return Inventory{}, errors.New("artifact inventory exceeds 32 MiB")
	}
	var v Inventory
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&v); e != nil {
		return v, fmt.Errorf("parse local artifact inventory: %w", e)
	}
	if v.SchemaVersion != SchemaVersion {
		return v, fmt.Errorf("unsupported local artifact schema %d", v.SchemaVersion)
	}
	if len(v.Namespaces) > limits.MaxNamespaces || len(v.Classes) > limits.MaxClasses || len(v.Files) > limits.MaxFiles || len(v.Instances) > limits.MaxObservations {
		return v, errors.New("local artifact inventory exceeds configured bounds")
	}
	if !safeLabel.MatchString(v.ClientLabel) || !safeLabel.MatchString(v.SiteCode) {
		return v, errors.New("unsafe client or site label")
	}
	return v, nil
}

func Analyze(v Inventory) Result {
	b, _ := json.Marshal(v)
	r := Result{SchemaVersion: 1, AlgorithmVersion: AlgorithmVersion, InventoryFingerprint: fp(string(b)), Inventory: v, LivePolicyRequests: 0}
	classCandidates := make(map[string]string)
	for _, c := range v.Classes {
		score := 0
		support := []string{}
		lower := strings.ToLower(c.Namespace + " " + c.Name)
		systemClass := strings.HasPrefix(c.Name, "__")
		if strings.Contains(strings.ToLower(c.Namespace), `root\ccm\policy`) && !systemClass {
			score += 45
			support = append(support, "confirmed SCCM policy namespace")
		}
		if !systemClass && (strings.Contains(lower, "policy") || strings.Contains(lower, "assignment")) {
			score += 20
			support = append(support, "policy-related class schema")
		}
		role := c.Classification
		if role == "" {
			role = "generic_sccm_state"
		}
		cand := Candidate{CandidateID: id("artifact_candidate", c.ID), SourceType: "wmi_class_schema", NamespaceOrPathFingerprint: fp(c.Namespace)[:16], ClassOrFileType: c.Name, PolicyRole: role, SecretLikelihood: "unknown", SupportingEvidence: support, ReviewRequired: true}
		setCandidateScore(&cand, score)
		r.Candidates = append(r.Candidates, cand)
		classCandidates[c.Namespace+"\x00"+c.Name] = cand.CandidateID
	}
	for _, x := range v.Instances {
		score := 0
		support := []string{}
		opaque := false
		for _, p := range x.Properties {
			if p.Shape == "encrypted_or_opaque" || p.Shape == "binary_blob" {
				opaque = true
			}
		}
		systemClass := strings.HasPrefix(x.Class, "__")
		if strings.Contains(strings.ToLower(x.Namespace), `root\ccm\policy`) && !systemClass {
			score += 45
			support = append(support, "instance belongs to confirmed SCCM policy namespace")
		}
		if opaque && !systemClass {
			score += 20
			support = append(support, "opaque value shape with policy provenance")
		}
		secret := "unlikely"
		if opaque && score >= 60 {
			secret = "likely_encrypted_value"
		}
		cand := Candidate{CandidateID: id("artifact_candidate", x.ID), SourceType: "wmi_instance_metadata", NamespaceOrPathFingerprint: fp(x.Namespace)[:16], ClassOrFileType: x.Class, PolicyRole: "policy_configuration_metadata", SecretLikelihood: secret, SupportingEvidence: support, ReviewRequired: true}
		setCandidateScore(&cand, score)
		r.Candidates = append(r.Candidates, cand)
		if classID := classCandidates[x.Namespace+"\x00"+x.Class]; classID != "" {
			r.Relationships = append(r.Relationships, Relationship{ID: id("artifact_relationship", cand.CandidateID, classID), From: cand.CandidateID, To: classID, Kind: "instance_of_observed_schema", Confidence: "high", Reason: "namespace and class name match the observed read-only schema"})
		}
	}
	for _, x := range v.Files {
		score := 0
		support := []string{"file lies under approved SCCM client root"}
		if strings.Contains(strings.ToLower(x.SafeRelativePath), "policy") {
			score += 15
			support = append(support, "path name is weak policy evidence")
		}
		if x.XML || x.JSON {
			score += 15
			support = append(support, "bounded structured-content indicator")
		}
		cand := Candidate{CandidateID: id("artifact_candidate", x.ID), SourceType: "file_metadata", NamespaceOrPathFingerprint: fp(x.SafeRelativePath)[:16], ClassOrFileType: x.Extension, ObservedAt: x.LastWriteTime, Size: x.Size, SHA256: x.SHA256, ContentShape: x.Shape, Entropy: x.Entropy, PrintableRatio: x.PrintableRatio, PolicyRole: "generic_sccm_state", SecretLikelihood: "unknown", SupportingEvidence: support, ReviewRequired: true, CopyEligible: false}
		setCandidateScore(&cand, score)
		r.Candidates = append(r.Candidates, cand)
	}
	sort.Slice(r.Candidates, func(i, j int) bool {
		rank := func(x string) int {
			switch x {
			case "high_value_policy_artifact_candidate":
				return 3
			case "medium_value_policy_artifact_candidate":
				return 2
			case "low_value_policy_artifact_candidate":
				return 1
			}
			return 0
		}
		a, b := rank(r.Candidates[i].Confidence), rank(r.Candidates[j].Confidence)
		if a != b {
			return a > b
		}
		return r.Candidates[i].CandidateID < r.Candidates[j].CandidateID
	})
	for _, c := range r.Candidates {
		mode := "metadata_only"
		if c.SourceType == "wmi_class_schema" {
			mode = "schema_only"
		}
		if c.SecretLikelihood == "likely_encrypted_value" {
			mode = "redacted_preview"
		}
		if c.CopyEligible && c.Size <= 1<<20 {
			mode = "bounded_content_copy"
		}
		r.ExportPlan = append(r.ExportPlan, ExportPlanItem{CandidateID: c.CandidateID, SourceType: c.SourceType, SafeSourceReference: c.NamespaceOrPathFingerprint, SHA256: c.SHA256, ContentShape: c.ContentShape, PolicyEvidence: strings.Join(c.SupportingEvidence, "; "), SecretLikelihood: c.SecretLikelihood, Size: c.Size, RecommendedMode: mode, ReviewRequirements: []string{"manual provenance and sensitivity review"}, SanitizationRequirements: []string{"replace identifiers; preserve structure only"}})
	}
	r.SecretReadiness = "not_ready_no_policy_artifact"
	for _, c := range r.Candidates {
		if c.Confidence == "high_value_policy_artifact_candidate" || c.Confidence == "medium_value_policy_artifact_candidate" {
			r.SecretReadiness = "ready_for_policy_schema_parser"
		}
		if c.SecretLikelihood == "likely_encrypted_value" && (c.Confidence == "high_value_policy_artifact_candidate" || c.Confidence == "medium_value_policy_artifact_candidate") {
			r.SecretReadiness = "ready_for_encrypted_value_classifier"
			break
		}
	}
	r.Findings = findings(r)
	r.Capabilities = []string{"local_sccm_policy_artifact_discovery_available", "local_wmi_schema_inventory_available", "local_policy_candidate_classification_available", "local_policy_export_planning_available", "live_policy_collection_blocked"}
	return r
}
func setCandidateScore(c *Candidate, score int) {
	switch {
	case score >= 70:
		c.Confidence = "high_value_policy_artifact_candidate"
	case score >= 45:
		c.Confidence = "medium_value_policy_artifact_candidate"
	case score > 0:
		c.Confidence = "low_value_policy_artifact_candidate"
	default:
		c.Confidence = "metadata_only_candidate"
	}
	if score < 45 {
		c.ContradictingEvidence = append(c.ContradictingEvidence, "insufficient independent policy provenance")
	}
}
func findings(r Result) []Finding {
	f := []Finding{}
	n := 0
	for _, x := range r.Inventory.Namespaces {
		if x.Exists && strings.Contains(strings.ToLower(x.Namespace), `root\ccm\policy`) {
			n++
		}
	}
	if n > 0 {
		f = append(f, Finding{"SCCM-LOCAL-POLICY-NAMESPACE-OBSERVED", "observed", "Read-only namespace inventory found SCCM policy namespaces.", false})
	}
	if len(r.Inventory.Classes) > 0 {
		f = append(f, Finding{"SCCM-LOCAL-POLICY-CLASS-OBSERVED", "observed", "Read-only class-schema metadata was recorded; methods were not invoked.", false})
	}
	for _, c := range r.Candidates {
		if c.SecretLikelihood == "likely_encrypted_value" {
			f = append(f, Finding{"SCCM-LOCAL-ENCRYPTED-VALUE-CANDIDATE", "candidate", "Opaque value shape has policy provenance and requires review.", false})
			break
		}
	}
	if len(r.Candidates) > 0 {
		f = append(f, Finding{"SCCM-LOCAL-POLICY-ARTIFACT-CANDIDATE", "observed", "Metadata-only artifact candidates require review.", false}, Finding{"SCCM-LOCAL-POLICY-ARTIFACT-REVIEW-REQUIRED", "required", "No candidate is automatically approved for content copy.", false})
	} else {
		f = append(f, Finding{"SCCM-LOCAL-POLICY-ARTIFACT-NOT-FOUND", "observed", "No bounded candidate was identified.", false})
	}
	return f
}

func GenerateDossier(output string, r Result) error {
	if output == "" {
		return errors.New("dossier output required")
	}
	if _, e := os.Lstat(output); e == nil {
		return errors.New("dossier already exists")
	}
	tmp, e := os.MkdirTemp(filepath.Dir(output), ".cinderpath-local-artifacts-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = os.Chmod(tmp, 0700); e != nil {
		return e
	}
	files := map[string]any{"local-artifact-summary.json": map[string]any{"schema_version": r.SchemaVersion, "inventory_fingerprint": r.InventoryFingerprint, "secret_readiness": r.SecretReadiness, "live_policy_requests": 0}, "namespaces.json": r.Inventory.Namespaces, "class-schemas.json": r.Inventory.Classes, "instance-metadata.json": r.Inventory.Instances, "file-artifacts.json": r.Inventory.Files, "registry-artifacts.json": r.Inventory.Registry, "artifact-candidates.json": r.Candidates, "artifact-relationships.json": r.Relationships, "export-plan.json": r.ExportPlan, "copied-artifacts.json": []any{}, "secret-readiness.json": map[string]any{"state": r.SecretReadiness, "plaintext_secrets_recovered": 0}}
	for n, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		b = append(b, '\n')
		if e = os.WriteFile(filepath.Join(tmp, n), b, 0600); e != nil {
			return e
		}
	}
	for n, s := range map[string]string{"gaps-and-next-actions.md": "# Gaps and next actions\n\nReview candidate provenance before selecting any bounded content copy. No secret extraction is implemented.\n", "safety-boundaries.md": "# Safety boundaries\n\nRead-only local metadata only. No client method was invoked and live SCCM policy requests were zero.\n"} {
		if e = os.WriteFile(filepath.Join(tmp, n), []byte(s), 0600); e != nil {
			return e
		}
	}
	return os.Rename(tmp, output)
}
