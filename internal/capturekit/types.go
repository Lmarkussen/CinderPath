package capturekit

import "time"

const SchemaVersion = 1

type Metadata struct {
	SchemaVersion int         `yaml:"schema_version" json:"schema_version"`
	Capture       Capture     `yaml:"capture" json:"capture"`
	Client        Client      `yaml:"client" json:"client"`
	Environment   Environment `yaml:"environment" json:"environment"`
	Tools         Tools       `yaml:"tools" json:"tools"`
	Files         []File      `yaml:"files" json:"files"`
	Review        Review      `yaml:"review" json:"review"`
}
type Capture struct {
	Label             string `yaml:"label" json:"label"`
	Action            string `yaml:"action" json:"action"`
	StartedAt         string `yaml:"started_at" json:"started_at"`
	StoppedAt         string `yaml:"stopped_at" json:"stopped_at"`
	OperatorReference string `yaml:"operator_reference" json:"operator_reference"`
	AuthorizedLab     bool   `yaml:"authorized_lab" json:"authorized_lab"`
}
type Client struct {
	Label             string `yaml:"label" json:"label"`
	OperatingSystem   string `yaml:"operating_system" json:"operating_system"`
	ClientVersion     string `yaml:"client_version" json:"client_version"`
	SiteCode          string `yaml:"site_code" json:"site_code"`
	ManagementPoint   string `yaml:"management_point" json:"management_point"`
	IdentityReference string `yaml:"identity_reference" json:"identity_reference"`
}
type Environment struct {
	Disposable            bool   `yaml:"disposable" json:"disposable"`
	SnapshotReference     string `yaml:"snapshot_reference" json:"snapshot_reference"`
	ProductionDataPresent bool   `yaml:"production_data_present" json:"production_data_present"`
}
type Tools struct {
	PacketCapture string `yaml:"packet_capture" json:"packet_capture"`
	LogCollection string `yaml:"log_collection" json:"log_collection"`
	HARCapture    string `yaml:"har_capture" json:"har_capture"`
}
type File struct {
	Path           string `yaml:"path" json:"path"`
	SHA256         string `yaml:"sha256" json:"sha256"`
	Kind           string `yaml:"kind" json:"kind"`
	ModifiedAt     string `yaml:"modified_at" json:"modified_at"`
	SourceCategory string `yaml:"source_category" json:"source_category"`
	Size           int64  `yaml:"size" json:"size"`
	Copied         bool   `yaml:"copied" json:"copied"`
	Redacted       bool   `yaml:"redacted" json:"redacted"`
	Reviewed       bool   `yaml:"reviewed" json:"reviewed"`
}
type Review struct {
	RawSensitive         bool `yaml:"raw_sensitive" json:"raw_sensitive"`
	MetadataReviewed     bool `yaml:"metadata_reviewed" json:"metadata_reviewed"`
	BinaryReviewed       bool `yaml:"binary_reviewed" json:"binary_reviewed"`
	Sanitized            bool `yaml:"sanitized" json:"sanitized"`
	LeakageChecksPassed  bool `yaml:"leakage_checks_passed" json:"leakage_checks_passed"`
	BundleExportApproved bool `yaml:"bundle_export_approved" json:"bundle_export_approved"`
}
type Manifest struct {
	SchemaVersion int      `yaml:"schema_version" json:"schema_version"`
	KitID         string   `yaml:"kit_id" json:"kit_id"`
	Fingerprint   string   `yaml:"fingerprint" json:"fingerprint"`
	CreatedAt     string   `yaml:"created_at" json:"created_at"`
	RequiredFiles []string `yaml:"required_files" json:"required_files"`
	Safety        string   `yaml:"safety" json:"safety"`
}
type State string

const (
	ReadyForCapture      State = "ready_for_capture"
	CaptureInProgress    State = "capture_in_progress"
	RawCaptureComplete   State = "raw_capture_complete"
	RequiresSanitization State = "requires_sanitization"
	RequiresManualReview State = "requires_manual_review"
	ReadyForImport       State = "ready_for_import"
	ReadyForBundleExport State = "ready_for_bundle_export"
	Invalid              State = "invalid"
)

type Validation struct {
	State        State    `json:"state" yaml:"state"`
	KitID        string   `json:"kit_id" yaml:"kit_id"`
	Fingerprint  string   `json:"fingerprint" yaml:"fingerprint"`
	Errors       []string `json:"errors" yaml:"errors"`
	Warnings     []string `json:"warnings" yaml:"warnings"`
	RawFiles     []File   `json:"raw_files" yaml:"raw_files"`
	Sanitized    []File   `json:"sanitized_files" yaml:"sanitized_files"`
	LiveRequests int      `json:"live_policy_requests" yaml:"live_policy_requests"`
}
type CreateOptions struct {
	Output, SiteCode, ManagementPoint, ClientLabel, CaptureLabel, CaptureAction string
	Force                                                                       bool
	Now                                                                         time.Time
}
