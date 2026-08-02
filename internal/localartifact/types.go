// Package localartifact implements bounded, metadata-only SCCM client artifact discovery.
package localartifact

import "time"

const SchemaVersion = 1
const AlgorithmVersion = "local-sccm-artifact-v1"

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
	Name         string   `json:"name"`
	CIMType      string   `json:"cim_type"`
	State        string   `json:"state"`
	Shape        string   `json:"shape"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	LengthBucket string   `json:"length_bucket"`
	Array        bool     `json:"array"`
	Warnings     []string `json:"warnings,omitempty"`
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
