package localartifact

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const PreviewSchemaVersion = 1

type PreviewPlanItem struct {
	CandidateID        string   `json:"candidate_id"`
	Namespace          string   `json:"namespace"`
	Class              string   `json:"class"`
	InstanceID         string   `json:"instance_fingerprint"`
	Index              int      `json:"instance_index"`
	Property           string   `json:"property"`
	CIMType            string   `json:"cim_type"`
	OriginalLength     string   `json:"original_length_bucket"`
	OriginalSHA256     string   `json:"original_sha256"`
	ObservedShape      string   `json:"observed_shape"`
	SelectionReason    string   `json:"selection_reason"`
	PreviewEligible    bool     `json:"preview_eligible"`
	RawCopyEligible    bool     `json:"raw_copy_eligible"`
	ReviewRequirements []string `json:"review_requirements"`
}
type PreviewPlan struct {
	SchemaVersion        int               `json:"schema_version"`
	InventoryFingerprint string            `json:"inventory_fingerprint"`
	Candidates           []PreviewPlanItem `json:"candidates"`
	Limits               map[string]int    `json:"limits"`
	LivePolicyRequests   int               `json:"live_policy_requests"`
}
type XMLStructure struct {
	WellFormed            bool           `json:"well_formed"`
	RootElement           string         `json:"root_element,omitempty"`
	NamespaceFingerprints []string       `json:"namespace_fingerprints"`
	ElementNames          map[string]int `json:"element_names"`
	AttributeNames        map[string]int `json:"attribute_names"`
	MaximumDepth          int            `json:"maximum_depth"`
	ElementCount          int            `json:"element_count"`
	AttributeCount        int            `json:"attribute_count"`
	TextNodeCount         int            `json:"text_node_count"`
	TextLengthBuckets     map[string]int `json:"text_length_buckets"`
	CDATA                 bool           `json:"cdata_present"`
	Base64Nodes           int            `json:"base64_shaped_node_count"`
	HexNodes              int            `json:"hex_shaped_node_count"`
	GUIDNodes             int            `json:"guid_shaped_node_count"`
	URLNodes              int            `json:"url_shaped_node_count"`
	OpaqueNodes           int            `json:"opaque_high_entropy_node_count"`
	Truncated             bool           `json:"truncated"`
	Warnings              []string       `json:"warnings"`
}
type PropertyPreview struct {
	CandidateID         string       `json:"candidate_id"`
	Namespace           string       `json:"namespace"`
	Class               string       `json:"class"`
	InstanceID          string       `json:"instance_fingerprint"`
	Property            string       `json:"property"`
	OriginalLength      int          `json:"original_length"`
	OriginalSHA256      string       `json:"original_sha256"`
	ObservedShape       string       `json:"observed_shape"`
	Found               bool         `json:"found"`
	PreviewEmitted      bool         `json:"preview_emitted"`
	PreviewRejected     bool         `json:"preview_rejected"`
	RedactedPreview     string       `json:"redacted_preview,omitempty"`
	SensitiveNamedField bool         `json:"sensitive_named_field_present"`
	LeakageIndicators   []string     `json:"leakage_indicators"`
	Structure           XMLStructure `json:"xml_structure"`
	Warnings            []string     `json:"warnings"`
}
type PreviewCollection struct {
	SchemaVersion      int               `json:"schema_version"`
	CollectedAt        string            `json:"collected_at"`
	CandidatesPlanned  int               `json:"candidates_planned"`
	CandidatesFound    int               `json:"candidates_found"`
	PropertiesRead     int               `json:"properties_read"`
	Previews           []PropertyPreview `json:"previews"`
	SCCMMethodsInvoked int               `json:"sccm_methods_invoked"`
	LivePolicyRequests int               `json:"live_policy_requests"`
	RawValuesCopied    int               `json:"raw_values_copied"`
}
type SemanticClassification struct {
	CandidateID            string   `json:"candidate_id"`
	Classification         string   `json:"classification"`
	Confidence             string   `json:"confidence"`
	SupportingStructure    []string `json:"supporting_structure"`
	ContradictingStructure []string `json:"contradicting_structure,omitempty"`
	ParserUsefulness       string   `json:"parser_usefulness"`
	RawCopyRecommendation  string   `json:"raw_copy_recommendation"`
}
type PreviewAnalysis struct {
	SchemaVersion      int                      `json:"schema_version"`
	Plan               PreviewPlan              `json:"preview_plan"`
	Collection         PreviewCollection        `json:"property_previews"`
	Structures         []XMLStructure           `json:"xml_structures"`
	Classifications    []SemanticClassification `json:"semantic_classifications"`
	Parsers            []ParserStatus           `json:"parser_status"`
	RawExportDecisions []map[string]any         `json:"raw_export_decisions"`
	Readiness          string                   `json:"secret_readiness"`
	LivePolicyRequests int                      `json:"live_policy_requests"`
}

func BuildPreviewPlan(v Inventory) PreviewPlan {
	a := AnalyzeSchemas(v, SchemaOptions{})
	p := PreviewPlan{SchemaVersion: 1, InventoryFingerprint: a.InventoryFingerprint, Limits: map[string]int{"max_candidates": 3, "max_preview_characters": 256, "max_xml_depth": 32, "max_xml_elements": 2048, "max_attributes": 4096, "max_property_bytes": 1 << 20, "max_total_bytes": 2 << 20}, LivePolicyRequests: 0}
	byID := map[string]InstanceMetadata{}
	for _, x := range a.SelectedInstances {
		byID[x.ID] = x
	}
	for _, c := range a.ContentPlan {
		if !c.Eligible || len(p.Candidates) >= 3 {
			continue
		}
		x := byID[c.InstanceID]
		var typ string
		for _, q := range x.Properties {
			if q.Name == c.Property {
				typ = q.CIMType
			}
		}
		p.Candidates = append(p.Candidates, PreviewPlanItem{CandidateID: c.CandidateID, Namespace: x.Namespace, Class: x.Class, InstanceID: x.ID, Index: x.Index, Property: c.Property, CIMType: typ, OriginalLength: c.OriginalLength, OriginalSHA256: c.Fingerprint, ObservedShape: c.Shape, SelectionReason: "selected concrete policy instance plus parser-relevant XML shape", PreviewEligible: true, RawCopyEligible: false, ReviewRequirements: []string{"structure-only review", "leakage review", "explicit raw-copy approval"}})
	}
	return p
}

func WritePreviewPlan(path, script string, p PreviewPlan) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	if e := os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		return e
	}
	if script != "" {
		return os.WriteFile(script, []byte(PreviewPowerShell(p)), 0700)
	}
	return nil
}
func PreviewPowerShell(p PreviewPlan) string {
	b, _ := json.Marshal(p.Candidates)
	encoded := strings.ReplaceAll(string(b), "'", "''")
	return strings.ReplaceAll(fmt.Sprintf(previewPS, encoded), "$parts.Add(", "$null=$parts.Add(")
}

const previewPS = `# CinderPath exact-allowlist SCCM policy property preview collector.
[CmdletBinding()] param([string]$OutputPath=".\property-previews.json")
Set-StrictMode -Version 2
$ErrorActionPreference="Stop"
function Hash-Text([string]$Value){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace("-","").ToLowerInvariant())}finally{$h.Dispose()}}
function Write-UTF8([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))}
$Plan=ConvertFrom-Json @'
%s
'@
$Out=@();$found=0;$read=0
foreach($c in $Plan){$warning=@();$structure=[ordered]@{well_formed=$false;root_element='';namespace_fingerprints=@();element_names=[ordered]@{};attribute_names=[ordered]@{};maximum_depth=0;element_count=0;attribute_count=0;text_node_count=0;text_length_buckets=[ordered]@{};cdata_present=$false;base64_shaped_node_count=0;hex_shaped_node_count=0;guid_shaped_node_count=0;url_shaped_node_count=0;opaque_high_entropy_node_count=0;truncated=$false;warnings=@()};$preview='';$reject=$false;$value='';try{$rows=@(Get-CimInstance -Namespace $c.namespace -ClassName $c.class -ErrorAction Stop);if($c.instance_index-ge$rows.Count){throw 'selected instance missing'};$row=$rows[$c.instance_index];$prop=$row.CimInstanceProperties[$c.property];if($null-eq$prop){throw 'selected property missing'};$value=[string]$prop.Value;$read++;if((Hash-Text $value)-ne$c.original_sha256){throw 'property fingerprint mismatch'};$found++;if($value.Length-gt1048576){throw 'property exceeds 1 MiB'};if($value-match '(?i)BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization:\s*(Basic|Bearer)|Cookie:\s*\S+|password\s*=\s*[^\s<]+|Data Protection API'){ $reject=$true;$warning+=@('positive leakage indicator') }else{$settings=New-Object Xml.XmlReaderSettings;$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$reader=[Xml.XmlReader]::Create((New-Object IO.StringReader($value)),$settings);$depth=0;$parts=New-Object Collections.Generic.List[string];while($reader.Read()){if($reader.Depth-gt32){throw 'XML depth exceeds 32'};if($reader.NodeType-eq[Xml.XmlNodeType]::Element){$structure.element_count++;if($structure.element_count-gt2048){throw 'XML element count exceeds 2048'};if($structure.root_element-eq''){$structure.root_element=$reader.LocalName};$structure.maximum_depth=[Math]::Max($structure.maximum_depth,$reader.Depth);$structure.element_names[$reader.LocalName]=1+[int]$structure.element_names[$reader.LocalName];$parts.Add('<'+$reader.LocalName);if($reader.HasAttributes){while($reader.MoveToNextAttribute()){$structure.attribute_count++;if($structure.attribute_count-gt4096){throw 'XML attribute count exceeds 4096'};$structure.attribute_names[$reader.LocalName]=1+[int]$structure.attribute_names[$reader.LocalName];$parts.Add(' '+$reader.LocalName+'="[REDACTED len='+$reader.Value.Length+']"')};$reader.MoveToElement()};$parts.Add('>')}elseif($reader.NodeType-eq[Xml.XmlNodeType]::EndElement){$parts.Add('</'+$reader.LocalName+'>')}elseif($reader.NodeType-eq[Xml.XmlNodeType]::Text-or$reader.NodeType-eq[Xml.XmlNodeType]::CDATA){$structure.text_node_count++;if($reader.NodeType-eq[Xml.XmlNodeType]::CDATA){$structure.cdata_present=$true};$parts.Add('[TEXT_REDACTED len='+$reader.Value.Length+']')}};$reader.Dispose();$structure.well_formed=$true;$preview=($parts-join'');if($preview.Length-gt256){$preview=$preview.Substring(0,240)+'...[TRUNCATED]';$structure.truncated=$true}}}catch{$reject=$true;$warning+=@($_.Exception.Message)};$Out+=[ordered]@{candidate_id=$c.candidate_id;namespace=$c.namespace;class=$c.class;instance_fingerprint=$c.instance_fingerprint;property=$c.property;original_length=$value.Length;original_sha256=$(if($value){Hash-Text $value}else{$c.original_sha256});observed_shape=$c.observed_shape;found=($value-ne'');preview_emitted=($preview-ne'' -and (-not $reject));preview_rejected=$reject;redacted_preview=$(if($reject){''}else{$preview});sensitive_named_field_present=($c.property-match'(?i)password|secret|credential|token|account');leakage_indicators=$(if($reject){@('redacted_positive_indicator_or_parse_failure')}else{@()});xml_structure=$structure;warnings=$warning}}
$Result=[ordered]@{schema_version=1;collected_at=(Get-Date).ToUniversalTime().ToString('o');candidates_planned=$Plan.Count;candidates_found=$found;properties_read=$read;previews=$Out;sccm_methods_invoked=0;live_policy_requests=0;raw_values_copied=0}
Write-UTF8 $OutputPath ($Result|ConvertTo-Json -Depth 12 -Compress)
Write-Host ("Policy property preview collection complete: planned={0} found={1} read={2} emitted={3} rejected={4} raw_copied=0"-f$Plan.Count,$found,$read,@($Out|Where-Object{$_.preview_emitted}).Count,@($Out|Where-Object{$_.preview_rejected}).Count)
Write-Host "SCCM client methods invoked: 0"
Write-Host "Live SCCM policy requests: 0"
`

func LoadPreviewCollection(path string) (PreviewCollection, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return PreviewCollection{}, e
	}
	if len(b) > 4<<20 {
		return PreviewCollection{}, errors.New("preview collection exceeds 4 MiB")
	}
	b = []byte(strings.ReplaceAll(string(b), `"leakage_indicators":{}`, `"leakage_indicators":[]`))
	var c PreviewCollection
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if c.SchemaVersion != 1 || c.CandidatesPlanned < 0 || c.CandidatesPlanned > 3 || c.PropertiesRead < 0 || c.PropertiesRead > 3 || len(c.Previews) > 3 || c.LivePolicyRequests != 0 || c.RawValuesCopied != 0 {
		return c, errors.New("invalid preview collection bounds or safety state")
	}
	return c, nil
}
func AnalyzePreviews(p PreviewPlan, c PreviewCollection) PreviewAnalysis {
	a := PreviewAnalysis{SchemaVersion: 1, Plan: p, Collection: c, Readiness: "ready_for_policy_instance_parser", LivePolicyRequests: 0}
	for _, x := range c.Previews {
		a.Structures = append(a.Structures, x.Structure)
		s := classifyXML(x)
		a.Classifications = append(a.Classifications, s)
		decision := "preview_only"
		if x.Structure.WellFormed && !x.PreviewRejected {
			decision = "schema_fixture_sufficient"
		}
		a.RawExportDecisions = append(a.RawExportDecisions, map[string]any{"candidate_id": x.CandidateID, "decision": decision, "raw_copy_eligible": false, "blockers": []string{"structure-only preview sufficient or explicit raw review absent"}})
	}
	a.Parsers = []ParserStatus{{ParserID: "authority_capabilities_preview_v1", Classification: "policy_authority_class", Lifecycle: lifecycleFor(a.Classifications, "authority_capability_metadata"), Fixture: "testdata/localartifact/authority_capabilities_preview.xml"}, {ParserID: "deployment_message_preview_v1", Classification: "deployment_state_class", Lifecycle: lifecycleFor(a.Classifications, "deployment_state_message"), Fixture: "testdata/localartifact/deployment_message_preview.xml"}}
	return a
}
func classifyXML(x PropertyPreview) SemanticClassification {
	s := SemanticClassification{CandidateID: x.CandidateID, Classification: "unknown_xml_value", Confidence: "low", ParserUsefulness: "structure unavailable", RawCopyRecommendation: "do_not_export"}
	if !x.Structure.WellFormed {
		s.Classification = "malformed_structured_value"
		return s
	}
	names := x.Structure.ElementNames
	if strings.Contains(strings.ToLower(x.Class), "authority") && len(names) > 0 {
		s.Classification = "authority_capability_metadata"
		s.Confidence = "high"
		s.SupportingStructure = []string{"authority instance provenance", "well-formed bounded XML structure"}
		s.ParserUsefulness = "sufficient for structure-only authority capability fixture"
		s.RawCopyRecommendation = "schema_fixture_sufficient"
	} else if strings.Contains(strings.ToLower(x.Class), "deployment") && len(names) > 0 {
		s.Classification = "deployment_state_message"
		s.Confidence = "high"
		s.SupportingStructure = []string{"deployment-state instance provenance", "well-formed bounded XML structure"}
		s.ParserUsefulness = "sufficient for structure-only deployment message fixture"
		s.RawCopyRecommendation = "schema_fixture_sufficient"
	}
	return s
}
func lifecycleFor(xs []SemanticClassification, want string) string {
	for _, x := range xs {
		if x.Classification == want && x.Confidence == "high" {
			return "runtime_preview_validated"
		}
	}
	return "fixture_validated"
}
func LoadPreviewPlan(path string) (PreviewPlan, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return PreviewPlan{}, e
	}
	var p PreviewPlan
	if e = json.Unmarshal(b, &p); e != nil {
		return p, e
	}
	if p.SchemaVersion != 1 || len(p.Candidates) > 3 {
		return p, errors.New("invalid preview plan")
	}
	return p, nil
}
func GeneratePreviewDossier(out string, a PreviewAnalysis) error {
	if _, e := os.Lstat(out); e == nil {
		return errors.New("preview dossier exists")
	}
	tmp, e := os.MkdirTemp(filepath.Dir(out), ".cinderpath-preview-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	_ = os.Chmod(tmp, 0700)
	files := map[string]any{"preview-plan.json": a.Plan, "property-previews.json": a.Collection, "xml-structures.json": a.Structures, "semantic-classifications.json": a.Classifications, "parser-status.json": a.Parsers, "raw-export-decisions.json": a.RawExportDecisions, "secret-readiness.json": map[string]any{"state": a.Readiness, "live_policy_requests": 0}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, _ := json.MarshalIndent(files[n], "", "  ")
		if e = os.WriteFile(filepath.Join(tmp, n), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	for n, s := range map[string]string{"gaps-and-next-actions.md": "# Gaps\n\nStructure-only fixtures are sufficient; raw export and encrypted-value work remain blocked.\n", "safety-boundaries.md": "# Safety\n\nExact allowlist, redacted previews, raw values copied: 0, live SCCM requests: 0.\n"} {
		if e = os.WriteFile(filepath.Join(tmp, n), []byte(s), 0600); e != nil {
			return e
		}
	}
	return os.Rename(tmp, out)
}
