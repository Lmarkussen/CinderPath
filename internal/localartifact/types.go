// Package localartifact implements bounded, metadata-only SCCM client artifact discovery.
package localartifact

import "time"

const SchemaVersion = 1
const AlgorithmVersion = "local-sccm-artifact-v1"

const SchemaAnalysisVersion = "sccm-policy-schema-v1"

type Limits struct {
	MaxNamespaces, MaxClasses, MaxSelectedClasses, MaxInstances, MaxProperties int
	MaxFiles, MaxDepth, MaxObservations                                        int
	MaxStringBytes, MaxBinaryBytes, MaxMetadataBytes                           int64
}

func DefaultLimits() Limits {
	return Limits{32, 1024, 64, 128, 128, 2000, 4, 20000, 16 << 10, 64 << 10, 32 << 20}
}

type Namespace struct {
	Namespace  string   `json:"namespace"`
	Exists     bool     `json:"exists"`
	Accessible bool     `json:"accessible"`
	ClassCount int      `json:"class_count"`
	DurationMS int64    `json:"enumeration_duration_ms"`
	Warnings   []string `json:"warnings,omitempty"`
}
type PropertySchema struct {
	Name    string `json:"name"`
	CIMType string `json:"cim_type"`
	Array   bool   `json:"array"`
	Key     bool   `json:"key"`
	Read    bool   `json:"read"`
	Write   bool   `json:"write"`
}
type ClassSchema struct {
	ID             string           `json:"id"`
	Namespace      string           `json:"namespace"`
	Name           string           `json:"name"`
	Superclass     string           `json:"superclass,omitempty"`
	Classification string           `json:"classification"`
	Qualifiers     []string         `json:"qualifiers"`
	Properties     []PropertySchema `json:"properties"`
	Methods        []string         `json:"methods"`
	InstanceCount  int              `json:"instance_count"`
	CountState     string           `json:"count_state"`
	Warnings       []string         `json:"warnings,omitempty"`
}
type InstanceProperty struct {
	Name                  string   `json:"name"`
	CIMType               string   `json:"cim_type"`
	State                 string   `json:"state"`
	Shape                 string   `json:"shape"`
	Fingerprint           string   `json:"fingerprint,omitempty"`
	LengthBucket          string   `json:"length_bucket"`
	EntropyBucket         string   `json:"entropy_bucket,omitempty"`
	PrintableRatioBucket  string   `json:"printable_ratio_bucket,omitempty"`
	ReferenceFingerprints []string `json:"reference_fingerprints,omitempty"`
	Array                 bool     `json:"array"`
	Warnings              []string `json:"warnings,omitempty"`
}
type InstanceMetadata struct {
	ID          string             `json:"id"`
	Namespace   string             `json:"namespace"`
	Class       string             `json:"class"`
	Fingerprint string             `json:"fingerprint"`
	Index       int                `json:"index"`
	Properties  []InstanceProperty `json:"properties"`
	ObservedAt  time.Time          `json:"observed_at"`
	Warnings    []string           `json:"warnings,omitempty"`
}
type FileArtifact struct {
	ID               string    `json:"id"`
	SafeRelativePath string    `json:"safe_relative_path"`
	SHA256           string    `json:"sha256"`
	Extension        string    `json:"extension"`
	ContentType      string    `json:"content_type"`
	Shape            string    `json:"shape"`
	Size             int64     `json:"size"`
	CreationTime     time.Time `json:"creation_time"`
	LastWriteTime    time.Time `json:"last_write_time"`
	Entropy          float64   `json:"entropy"`
	PrintableRatio   float64   `json:"printable_ratio"`
	XML              bool      `json:"xml"`
	JSON             bool      `json:"json"`
	Multipart        bool      `json:"multipart"`
	Opaque           bool      `json:"opaque"`
	Warnings         []string  `json:"warnings,omitempty"`
}
type RegistryArtifact struct {
	ID             string   `json:"id"`
	KeyFingerprint string   `json:"key_fingerprint"`
	SafeKeyLabel   string   `json:"safe_key_label"`
	ValueName      string   `json:"value_name"`
	ValueType      string   `json:"value_type"`
	LengthBucket   string   `json:"length_bucket"`
	Shape          string   `json:"shape"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}
type Candidate struct {
	CandidateID                string    `json:"candidate_id"`
	SourceType                 string    `json:"source_type"`
	NamespaceOrPathFingerprint string    `json:"namespace_or_path_fingerprint"`
	ClassOrFileType            string    `json:"class_or_file_type"`
	ObservedAt                 time.Time `json:"observed_at,omitempty"`
	Size                       int64     `json:"size,omitempty"`
	SHA256                     string    `json:"sha256,omitempty"`
	ContentShape               string    `json:"content_shape,omitempty"`
	Entropy                    float64   `json:"entropy,omitempty"`
	PrintableRatio             float64   `json:"printable_ratio,omitempty"`
	Identifiers                []string  `json:"identifiers,omitempty"`
	PolicyRole                 string    `json:"policy_role"`
	SecretLikelihood           string    `json:"secret_likelihood"`
	Confidence                 string    `json:"confidence"`
	SupportingEvidence         []string  `json:"supporting_evidence"`
	ContradictingEvidence      []string  `json:"contradicting_evidence,omitempty"`
	ReviewRequired             bool      `json:"review_required"`
	CopyEligible               bool      `json:"copy_eligible"`
	Warnings                   []string  `json:"warnings,omitempty"`
}
type Relationship struct {
	ID         string `json:"id"`
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}
type Inventory struct {
	SchemaVersion      int                `json:"schema_version"`
	CollectedAt        time.Time          `json:"collected_at"`
	ClientLabel        string             `json:"client_label"`
	SiteCode           string             `json:"site_code"`
	Namespaces         []Namespace        `json:"namespaces"`
	Classes            []ClassSchema      `json:"class_schemas"`
	Instances          []InstanceMetadata `json:"instance_metadata"`
	Files              []FileArtifact     `json:"file_artifacts"`
	Registry           []RegistryArtifact `json:"registry_artifacts"`
	Errors             []string           `json:"errors,omitempty"`
	Warnings           []string           `json:"warnings,omitempty"`
	LivePolicyRequests int                `json:"live_policy_requests"`
}
type ExportPlanItem struct {
	CandidateID              string   `json:"candidate_id"`
	SourceType               string   `json:"source_type"`
	SafeSourceReference      string   `json:"safe_source_reference"`
	SHA256                   string   `json:"sha256,omitempty"`
	Size                     int64    `json:"size,omitempty"`
	ContentShape             string   `json:"content_shape"`
	PolicyEvidence           string   `json:"policy_evidence"`
	SecretLikelihood         string   `json:"secret_likelihood"`
	ReviewRequirements       []string `json:"review_requirements"`
	SanitizationRequirements []string `json:"sanitization_requirements"`
	RecommendedMode          string   `json:"recommended_export_mode"`
}
type Result struct {
	SchemaVersion        int              `json:"schema_version"`
	AlgorithmVersion     string           `json:"algorithm_version"`
	InventoryFingerprint string           `json:"inventory_fingerprint"`
	Inventory            Inventory        `json:"inventory"`
	Candidates           []Candidate      `json:"artifact_candidates"`
	Relationships        []Relationship   `json:"artifact_relationships"`
	ExportPlan           []ExportPlanItem `json:"export_plan"`
	SecretReadiness      string           `json:"secret_readiness"`
	Findings             []Finding        `json:"findings"`
	Capabilities         []string         `json:"capabilities"`
	LivePolicyRequests   int              `json:"live_policy_requests"`
}
type Finding struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	Description   string `json:"description"`
	Vulnerability bool   `json:"vulnerability"`
}

type SchemaFeature struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type SchemaRanking struct {
	SchemaID               string          `json:"schema_id"`
	Namespace              string          `json:"namespace"`
	Class                  string          `json:"class"`
	Classification         string          `json:"classification"`
	Confidence             string          `json:"confidence"`
	Score                  int             `json:"score"`
	EstimatedInstanceCount int             `json:"estimated_instance_count"`
	CountState             string          `json:"count_state"`
	SupportingEvidence     []string        `json:"supporting_evidence"`
	ContradictingEvidence  []string        `json:"contradicting_evidence,omitempty"`
	Features               []SchemaFeature `json:"schema_features"`
	ExcludedByDefault      bool            `json:"excluded_by_default"`
	ExclusionReason        string          `json:"exclusion_reason,omitempty"`
}

type SchemaFamily struct {
	FamilyID      string   `json:"family_id"`
	FamilyType    string   `json:"family_type"`
	StructuralKey string   `json:"structural_key"`
	SchemaIDs     []string `json:"schema_ids"`
	Warnings      []string `json:"warnings,omitempty"`
}

type InstanceSelection struct {
	SchemaID               string   `json:"schema_id"`
	Namespace              string   `json:"namespace"`
	Class                  string   `json:"class"`
	Score                  int      `json:"selection_score"`
	Confidence             string   `json:"confidence"`
	EstimatedInstanceCount int      `json:"estimated_instance_count"`
	Reasons                []string `json:"reasons"`
	Warnings               []string `json:"warnings,omitempty"`
	Selected               bool     `json:"selected"`
}

type ParserStatus struct {
	ParserID           string   `json:"parser_id"`
	Classification     string   `json:"classification"`
	Lifecycle          string   `json:"lifecycle"`
	Fixture            string   `json:"supporting_fixture,omitempty"`
	RequiredProperties []string `json:"required_properties"`
	ObservedSchemas    []string `json:"observed_schemas,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
}
type ParsedPolicyFixture struct {
	ParserID      string            `json:"parser_id"`
	Lifecycle     string            `json:"lifecycle"`
	Namespace     string            `json:"namespace"`
	Class         string            `json:"class"`
	Relationships map[string]string `json:"relationships,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
}

type ContentPlan struct {
	CandidateID    string   `json:"candidate_id"`
	InstanceID     string   `json:"instance_id"`
	Property       string   `json:"property"`
	Shape          string   `json:"shape"`
	OriginalLength string   `json:"original_length_bucket"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	Mode           string   `json:"recommended_export_mode"`
	Eligible       bool     `json:"eligible"`
	ReviewRequired bool     `json:"review_required"`
	Reasons        []string `json:"reasons"`
	Blockers       []string `json:"blockers,omitempty"`
}

type SchemaAnalysis struct {
	SchemaVersion        int                 `json:"schema_version"`
	AlgorithmVersion     string              `json:"algorithm_version"`
	InventoryFingerprint string              `json:"inventory_fingerprint"`
	Rankings             []SchemaRanking     `json:"schema_rankings"`
	Families             []SchemaFamily      `json:"schema_families"`
	InstancePlan         []InstanceSelection `json:"instance_selection_plan"`
	SelectedInstances    []InstanceMetadata  `json:"selected_instance_metadata"`
	Parsers              []ParserStatus      `json:"parser_status"`
	Relationships        []Relationship      `json:"relationship_graph"`
	ContentPlan          []ContentPlan       `json:"content_export_plan"`
	Previews             []any               `json:"content_previews"`
	Readiness            string              `json:"secret_readiness"`
	Findings             []Finding           `json:"findings"`
	Capabilities         []string            `json:"capabilities"`
	LivePolicyRequests   int                 `json:"live_policy_requests"`
}
