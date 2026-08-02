package localartifact

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func ParsePolicyFixture(data []byte) (ParsedPolicyFixture, error) {
	if len(data) > 1<<20 {
		return ParsedPolicyFixture{}, errors.New("policy fixture exceeds 1 MiB")
	}
	var v struct {
		SchemaVersion int            `json:"schema_version"`
		Namespace     string         `json:"namespace"`
		Class         string         `json:"class"`
		Properties    map[string]any `json:"properties"`
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if e := d.Decode(&v); e != nil {
		return ParsedPolicyFixture{}, e
	}
	if v.SchemaVersion != 1 {
		return ParsedPolicyFixture{}, errors.New("unsupported policy fixture schema")
	}
	if v.Namespace == "" || v.Class == "" {
		return ParsedPolicyFixture{}, errors.New("fixture namespace and class required")
	}
	p := ParsedPolicyFixture{Namespace: v.Namespace, Class: v.Class, Lifecycle: "fixture_validated", Relationships: map[string]string{}}
	l := strings.ToLower(v.Class)
	switch {
	case strings.Contains(l, "authority"):
		p.ParserID = "policy_authority_v1"
	case strings.Contains(l, "assignment"):
		p.ParserID = "policy_assignment_v1"
	case strings.Contains(l, "policy") || strings.Contains(l, "config"):
		p.ParserID = "policy_configuration_v1"
	case strings.Contains(l, "deployment") || strings.Contains(l, "pending"):
		p.ParserID = "deployment_state_v1"
	default:
		p.ParserID = "unknown"
		p.Lifecycle = "observed_structure"
		p.Warnings = append(p.Warnings, "no positively identified parser")
	}
	for _, n := range []string{"Authority", "PolicyID", "MessageID"} {
		if x, ok := v.Properties[n]; ok {
			p.Relationships[n] = fp(stringValue(x))[:16]
		}
	}
	return p, nil
}
func stringValue(v any) string { b, _ := json.Marshal(v); return string(b) }

type SchemaOptions struct {
	MaxClasses       int
	MaxInstances     int
	IncludeIntrinsic bool
}

func AnalyzeSchemas(v Inventory, o SchemaOptions) SchemaAnalysis {
	if o.MaxClasses <= 0 || o.MaxClasses > 96 {
		o.MaxClasses = 96
	}
	if o.MaxInstances <= 0 || o.MaxInstances > 2000 {
		o.MaxInstances = 2000
	}
	b, _ := json.Marshal(v)
	a := SchemaAnalysis{SchemaVersion: 1, AlgorithmVersion: SchemaAnalysisVersion, InventoryFingerprint: fp(string(b)), Previews: []any{}, LivePolicyRequests: 0}
	classByKey := map[string]ClassSchema{}
	for _, c := range v.Classes {
		classByKey[c.Namespace+"\x00"+c.Name] = c
		a.Rankings = append(a.Rankings, rankSchema(c))
	}
	sort.Slice(a.Rankings, func(i, j int) bool {
		if a.Rankings[i].Score != a.Rankings[j].Score {
			return a.Rankings[i].Score > a.Rankings[j].Score
		}
		if a.Rankings[i].Namespace != a.Rankings[j].Namespace {
			return a.Rankings[i].Namespace < a.Rankings[j].Namespace
		}
		return a.Rankings[i].Class < a.Rankings[j].Class
	})
	a.Families = clusterSchemas(v.Classes)
	selected := 0
	instances := 0
	for _, r := range a.Rankings {
		p := InstanceSelection{SchemaID: r.SchemaID, Namespace: r.Namespace, Class: r.Class, Score: r.Score, Confidence: r.Confidence, EstimatedInstanceCount: r.EstimatedInstanceCount, Reasons: append([]string{}, r.SupportingEvidence...)}
		if r.ExcludedByDefault && !o.IncludeIntrinsic {
			p.Warnings = append(p.Warnings, r.ExclusionReason)
		} else if r.Score >= 45 && selected < o.MaxClasses && instances+max(0, r.EstimatedInstanceCount) <= o.MaxInstances {
			p.Selected = true
			selected++
			instances += max(0, r.EstimatedInstanceCount)
		}
		if r.CountState == "inaccessible" {
			p.Selected = false
			p.Warnings = append(p.Warnings, "provider inaccessible")
		}
		a.InstancePlan = append(a.InstancePlan, p)
	}
	selectedKeys := map[string]bool{}
	for _, p := range a.InstancePlan {
		if p.Selected {
			selectedKeys[p.Namespace+"\x00"+p.Class] = true
		}
	}
	for _, x := range v.Instances {
		if selectedKeys[x.Namespace+"\x00"+x.Class] {
			a.SelectedInstances = append(a.SelectedInstances, x)
			c := classByKey[x.Namespace+"\x00"+x.Class]
			a.Relationships = append(a.Relationships, Relationship{ID: id("policy_edge", x.ID, c.ID), From: x.ID, To: c.ID, Kind: "instance_of", Confidence: "high", Reason: "exact namespace and class-schema match"})
			a.ContentPlan = append(a.ContentPlan, contentPlans(x, c)...)
		}
	}
	a.Parsers = parserStatuses(a.Rankings)
	a.Readiness = "ready_for_policy_schema_parser"
	if hasConcreteParserInstance(a) {
		a.Readiness = "ready_for_policy_instance_parser"
	}
	a.Findings = []Finding{{ID: "SCCM-POLICY-SCHEMA-CANDIDATE", State: "observed", Description: "Fixture-supported schema candidates were ranked without invoking methods.", Vulnerability: false}}
	if len(a.SelectedInstances) > 0 {
		a.Findings = append(a.Findings, Finding{ID: "SCCM-POLICY-INSTANCE-CANDIDATE", State: "observed", Description: "Bounded concrete instance metadata matched selected schemas.", Vulnerability: false})
	}
	if len(a.Relationships) > 0 {
		a.Findings = append(a.Findings, Finding{ID: "SCCM-POLICY-RELATIONSHIP-OBSERVED", State: "observed", Description: "Explicit schema-to-instance relationships were observed.", Vulnerability: false})
	}
	a.Capabilities = []string{"sccm_policy_schema_ranking_available", "sccm_policy_instance_selection_available", "sccm_policy_schema_parser_available", "sccm_policy_relationship_graph_available", "sccm_policy_content_export_planning_available", "live_policy_collection_blocked"}
	return a
}

func rankSchema(c ClassSchema) SchemaRanking {
	lower := strings.ToLower(c.Name)
	ns := strings.ToLower(c.Namespace)
	intrinsic := strings.HasPrefix(c.Name, "__") || strings.HasPrefix(c.Name, "CIM_") || strings.HasPrefix(c.Name, "Win32_")
	r := SchemaRanking{SchemaID: c.ID, Namespace: c.Namespace, Class: c.Name, EstimatedInstanceCount: c.InstanceCount, CountState: c.CountState, Classification: "unknown_sccm_class", Features: []SchemaFeature{{Name: "superclass", Value: c.Superclass}, {Name: "property_count", Value: itoa(len(c.Properties))}, {Name: "method_count", Value: itoa(len(c.Methods))}}}
	if intrinsic {
		r.Classification = "intrinsic_wmi_class"
		r.ExcludedByDefault = true
		r.ExclusionReason = "intrinsic/system class excluded from instance budget"
		r.ContradictingEvidence = append(r.ContradictingEvidence, r.ExclusionReason)
	}
	if strings.Contains(ns, `root\ccm\policy`) && !intrinsic {
		r.Score += 40
		r.SupportingEvidence = append(r.SupportingEvidence, "confirmed non-intrinsic SCCM policy namespace")
	}
	keys, structured, refs := 0, 0, 0
	for _, p := range c.Properties {
		n := strings.ToLower(p.Name)
		r.Features = append(r.Features, SchemaFeature{Name: "property", Value: p.Name})
		if p.Key {
			keys++
		}
		if strings.Contains(n, "xml") || strings.Contains(n, "data") || strings.Contains(n, "body") || p.CIMType == "UInt8" {
			structured++
		}
		if strings.Contains(n, "id") || strings.Contains(n, "authority") || strings.Contains(n, "policy") {
			refs++
		}
	}
	if keys > 0 {
		r.Score += 10
		r.SupportingEvidence = append(r.SupportingEvidence, "stable key-property structure")
	}
	if structured > 0 {
		r.Score += 10
		r.SupportingEvidence = append(r.SupportingEvidence, "parser-relevant structured property schema")
	}
	if refs > 0 {
		r.Score += 5
		r.SupportingEvidence = append(r.SupportingEvidence, "policy/reference-like property structure")
	}
	infrastructure := strings.Contains(lower, "registration") || strings.Contains(lower, "consumer") || strings.Contains(lower, "provider")
	switch {
	case infrastructure:
		r.Classification = "infrastructure_class"
		r.Score -= 35
		r.ContradictingEvidence = append(r.ContradictingEvidence, "provider/registration infrastructure is not policy content")
		r.ExcludedByDefault = true
		r.ExclusionReason = "provider/registration infrastructure excluded from instance budget"
	case strings.Contains(lower, "authority"):
		r.Classification = "policy_authority_class"
		r.Score += 20
	case strings.Contains(lower, "assignment"):
		r.Classification = "policy_assignment_class"
		r.Score += 20
	case strings.Contains(lower, "pendingdeployment") || strings.Contains(lower, "deploymentstate"):
		r.Classification = "deployment_state_class"
		r.Score += 15
	case strings.Contains(lower, "message"):
		r.Classification = "message_metadata_class"
		r.Score += 15
	case strings.Contains(lower, "policy") && structured > 0:
		r.Classification = "policy_payload_container"
		r.Score += 15
	case strings.Contains(lower, "policy") || strings.Contains(lower, "config"):
		r.Classification = "policy_configuration_class"
		r.Score += 10
	case strings.Contains(lower, "client"):
		r.Classification = "client_state_class"
	case intrinsic:
	default:
		r.Classification = "infrastructure_class"
	}
	if c.InstanceCount > 0 {
		r.Score += 60
		r.SupportingEvidence = append(r.SupportingEvidence, "bounded instances observed")
	}
	if c.InstanceCount == 0 && c.CountState == "bounded" {
		r.Score -= 40
		r.ContradictingEvidence = append(r.ContradictingEvidence, "no instances observed")
	}
	if len(c.Methods) > 8 {
		r.Score -= 10
		r.ContradictingEvidence = append(r.ContradictingEvidence, "method-heavy surface; methods remain uninvoked")
	}
	if intrinsic {
		r.Score = 0
	}
	switch {
	case r.Score >= 70:
		r.Confidence = "high"
	case r.Score >= 45:
		r.Confidence = "medium"
	case r.Score > 0:
		r.Confidence = "low"
	default:
		r.Confidence = "excluded"
	}
	r.Features = append(r.Features, SchemaFeature{Name: "key_properties", Value: itoa(keys)}, SchemaFeature{Name: "structured_properties", Value: itoa(structured)}, SchemaFeature{Name: "reference_properties", Value: itoa(refs)})
	return r
}

func clusterSchemas(classes []ClassSchema) []SchemaFamily {
	groups := map[string][]string{}
	types := map[string]string{}
	for _, c := range classes {
		names := make([]string, 0, len(c.Properties))
		for _, p := range c.Properties {
			names = append(names, strings.ToLower(p.Name)+":"+p.CIMType)
		}
		sort.Strings(names)
		structural := fp(c.Superclass + "|" + strings.Join(names, ","))[:20]
		typ := familyType(rankSchema(c).Classification)
		groups[typ+"|"+structural] = append(groups[typ+"|"+structural], c.ID)
		types[typ+"|"+structural] = typ
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]SchemaFamily, 0, len(keys))
	for _, k := range keys {
		sort.Strings(groups[k])
		out = append(out, SchemaFamily{FamilyID: id("schema_family", k), FamilyType: types[k], StructuralKey: strings.Split(k, "|")[1], SchemaIDs: groups[k], Warnings: []string{"structural similarity is supporting evidence only"}})
	}
	return out
}
func familyType(c string) string {
	switch c {
	case "policy_authority_class":
		return "authority_family"
	case "policy_assignment_class":
		return "assignment_family"
	case "policy_configuration_class", "policy_payload_container":
		return "configuration_family"
	case "message_metadata_class":
		return "message_family"
	case "deployment_state_class":
		return "deployment_state_family"
	default:
		return "unknown_family"
	}
}
func contentPlans(x InstanceMetadata, c ClassSchema) []ContentPlan {
	out := []ContentPlan{}
	for _, p := range x.Properties {
		eligibleShape := p.Shape == "XML_like" || p.Shape == "JSON_like" || p.Shape == "base64_like" || p.Shape == "hex_like" || p.Shape == "binary_blob" || p.Shape == "encrypted_or_opaque"
		sensitiveIdentifier := strings.Contains(strings.ToLower(p.Name), "sid") || strings.Contains(strings.ToLower(p.Name), "clsid") || strings.Contains(strings.ToLower(p.Name), "guid")
		infrastructure := strings.Contains(strings.ToLower(c.Name), "registration") || strings.Contains(strings.ToLower(c.Name), "consumer") || strings.Contains(strings.ToLower(c.Name), "provider")
		cp := ContentPlan{CandidateID: id("content_candidate", x.ID, p.Name), InstanceID: x.ID, Property: p.Name, Shape: p.Shape, OriginalLength: p.LengthBucket, Fingerprint: p.Fingerprint, Mode: "metadata_only", ReviewRequired: true, Reasons: []string{"concrete instance metadata and schema property match"}}
		if eligibleShape && !strings.HasPrefix(c.Name, "__") && !sensitiveIdentifier && !infrastructure {
			cp.Mode = "redacted_preview"
			cp.Eligible = true
			cp.Reasons = append(cp.Reasons, "parser-relevant structural shape")
		} else {
			cp.Blockers = append(cp.Blockers, "property lacks reviewed parser-relevant content shape or is infrastructure/identifier metadata")
		}
		out = append(out, cp)
	}
	return out
}
func parserStatuses(rs []SchemaRanking) []ParserStatus {
	defs := []struct {
		id, class string
		props     []string
	}{{"policy_authority_v1", "policy_authority_class", []string{"Name", "PolicyOrder"}}, {"policy_assignment_v1", "policy_assignment_class", []string{"PolicyID"}}, {"policy_configuration_v1", "policy_configuration_class", []string{"PolicyID"}}, {"deployment_state_v1", "deployment_state_class", []string{"State"}}}
	out := []ParserStatus{}
	for _, d := range defs {
		p := ParserStatus{ParserID: d.id, Classification: d.class, Lifecycle: "fixture_validated", Fixture: "testdata/localartifact/" + d.id + ".json", RequiredProperties: d.props}
		for _, r := range rs {
			if r.Classification == d.class && r.EstimatedInstanceCount > 0 && rankingHasProperties(r.SchemaID, d.props, rs) {
				p.ObservedSchemas = append(p.ObservedSchemas, r.SchemaID)
				p.Lifecycle = "runtime_metadata_validated"
			}
		}
		sort.Strings(p.ObservedSchemas)
		out = append(out, p)
	}
	return out
}

// rankingHasProperties is replaced by observed schema features only when the
// ranker recorded every required property name. Required-property evidence is
// encoded as feature entries to avoid consulting values.
func rankingHasProperties(schemaID string, required []string, rs []SchemaRanking) bool {
	for _, r := range rs {
		if r.SchemaID == schemaID {
			for _, need := range required {
				found := false
				for _, f := range r.Features {
					if f.Name == "property" && strings.EqualFold(f.Value, need) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
			return true
		}
	}
	return false
}
func hasConcreteParserInstance(a SchemaAnalysis) bool {
	if len(a.SelectedInstances) == 0 {
		return false
	}
	for _, p := range a.Parsers {
		if p.Lifecycle == "runtime_metadata_validated" {
			return true
		}
	}
	return false
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	b := make([]byte, 0, 12)
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func GenerateSchemaDossier(output string, a SchemaAnalysis) error {
	if output == "" {
		return errors.New("dossier output required")
	}
	if _, e := os.Lstat(output); e == nil {
		return errors.New("dossier already exists")
	}
	tmp, e := os.MkdirTemp(filepath.Dir(output), ".cinderpath-policy-schema-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = os.Chmod(tmp, 0700); e != nil {
		return e
	}
	files := map[string]any{"schema-ranking.json": a.Rankings, "schema-families.json": a.Families, "instance-selection-plan.json": a.InstancePlan, "selected-instance-metadata.json": a.SelectedInstances, "parser-status.json": a.Parsers, "relationship-graph.json": a.Relationships, "content-export-plan.json": a.ContentPlan, "content-previews.json": a.Previews, "secret-readiness.json": map[string]any{"state": a.Readiness, "live_policy_requests": 0}}
	for n, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		if e = os.WriteFile(filepath.Join(tmp, n), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	for n, s := range map[string]string{"gaps-and-next-actions.md": "# Gaps and next actions\n\nReviewed parser-relevant content is still required before encrypted-value classification or decoder research.\n", "safety-boundaries.md": "# Safety boundaries\n\nRead-only metadata analysis. SCCM methods invoked: 0. Live SCCM policy requests: 0. Content copied: 0.\n"} {
		if e = os.WriteFile(filepath.Join(tmp, n), []byte(s), 0600); e != nil {
			return e
		}
	}
	return os.Rename(tmp, output)
}
