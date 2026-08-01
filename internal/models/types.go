package models

import "time"

type AssetKind string

const (
	AssetDomain            AssetKind = "domain"
	AssetDomainController  AssetKind = "domain_controller"
	AssetSite              AssetKind = "site"
	AssetSiteServer        AssetKind = "site_server"
	AssetManagementPoint   AssetKind = "management_point"
	AssetDistributionPoint AssetKind = "distribution_point"
	AssetPXEServicePoint   AssetKind = "pxe_service_point"
	AssetSQLServer         AssetKind = "sql_server"
	AssetClient            AssetKind = "client"
	AssetUnknown           AssetKind = "unknown"
)

type Confidence string

const (
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed"
)

type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

type Asset struct {
	ID                string            `json:"id"`
	Kind              AssetKind         `json:"kind"`
	Hostname          string            `json:"hostname,omitempty"`
	FQDN              string            `json:"fqdn,omitempty"`
	IPAddresses       []string          `json:"ip_addresses,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	SiteCode          string            `json:"site_code,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
	Properties        map[string]string `json:"properties,omitempty"`
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
	Source            string            `json:"source"`
	Confidence        Confidence        `json:"confidence"`
	Fingerprint       string            `json:"fingerprint"`
	LastObservedRunID string            `json:"last_observed_run_id,omitempty"`
}

type CredentialType string

const (
	CredentialUsernamePassword CredentialType = "username_password"
	CredentialNTLMHash         CredentialType = "ntlm_hash"
	CredentialKerberosTicket   CredentialType = "kerberos_ticket"
	CredentialMachineAccount   CredentialType = "machine_account"
	CredentialCertificate      CredentialType = "certificate"
	CredentialCurrentProcess   CredentialType = "current_process"
	CredentialAnonymous        CredentialType = "anonymous"
	CredentialDomainUser       CredentialType = "domain_user"
	CredentialPasswordRef      CredentialType = "username_password_reference"
	CredentialNTLMHashRef      CredentialType = "ntlm_hash_reference"
	CredentialKerberosCacheRef CredentialType = "kerberos_cache_reference"
	CredentialCertificateRef   CredentialType = "certificate_reference"
	CredentialSCCMClientRef    CredentialType = "sccm_client_identity_reference"
	CredentialUnknown          CredentialType = "unknown"
)

type Credential struct {
	ID                     string               `json:"id"`
	Username               string               `json:"username"`
	Domain                 string               `json:"domain,omitempty"`
	Principal              string               `json:"principal,omitempty"`
	MachineName            string               `json:"machine_name,omitempty"`
	Type                   CredentialType       `json:"type"`
	Kind                   CredentialType       `json:"kind,omitempty"`
	Source                 string               `json:"source"`
	HasSecret              bool                 `json:"has_secret"`
	SecretReference        string               `json:"-"`
	ReferenceType          string               `json:"reference_type,omitempty"`
	RedactedReference      string               `json:"redacted_reference,omitempty"`
	CertificateReference   string               `json:"certificate_reference,omitempty"`
	KerberosCacheReference string               `json:"kerberos_cache_reference,omitempty"`
	Confidence             Confidence           `json:"confidence,omitempty"`
	Validated              bool                 `json:"validated"`
	ValidationReason       string               `json:"validation_reason,omitempty"`
	Certificate            *CertificateMetadata `json:"certificate,omitempty"`
	Properties             map[string]string    `json:"properties,omitempty"`
}

type CertificateMetadata struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	EmailAddresses     []string  `json:"email_addresses,omitempty"`
	ExtendedKeyUsage   []string  `json:"extended_key_usage,omitempty"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"not_yet_valid"`
	HasClientAuthEKU   bool      `json:"has_client_auth_eku"`
	NearExpiry         bool      `json:"near_expiry"`
}

type CapabilityState string

const (
	CapabilityAvailable          CapabilityState = "available"
	CapabilityUnavailable        CapabilityState = "unavailable"
	CapabilityUnknown            CapabilityState = "unknown"
	CapabilityBlockedBySafety    CapabilityState = "blocked_by_safety"
	CapabilityRequiresValidation CapabilityState = "requires_validation"
)

type Capability struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	Available            bool            `json:"available"`
	State                CapabilityState `json:"state,omitempty"`
	Reason               string          `json:"reason,omitempty"`
	Source               string          `json:"source"`
	CredentialID         string          `json:"credential_id,omitempty"`
	AssetID              string          `json:"asset_id,omitempty"`
	EvidenceIDs          []string        `json:"evidence_ids,omitempty"`
	RequiredInputs       []string        `json:"required_inputs,omitempty"`
	AvailableInputs      []string        `json:"available_inputs,omitempty"`
	MissingInputs        []string        `json:"missing_inputs,omitempty"`
	RelatedEndpoint      string          `json:"related_endpoint,omitempty"`
	SafetyBlocked        bool            `json:"safety_blocked"`
	Stale                bool            `json:"stale"`
	AuthenticationMethod string          `json:"authentication_method,omitempty"`
	RelatedRoute         string          `json:"related_route,omitempty"`
}

type Sensitivity string

const (
	SensitivityPublic     Sensitivity = "public"
	SensitivityInternal   Sensitivity = "internal"
	SensitivitySensitive  Sensitivity = "sensitive"
	SensitivityRestricted Sensitivity = "restricted"
)

type Evidence struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Title        string         `json:"title"`
	Summary      string         `json:"summary"`
	Data         map[string]any `json:"data,omitempty"`
	SourceModule string         `json:"source_module"`
	AssetID      string         `json:"asset_id,omitempty"`
	CredentialID string         `json:"credential_id,omitempty"`
	CollectedAt  time.Time      `json:"collected_at"`
	Sensitivity  Sensitivity    `json:"sensitivity"`
	Fingerprint  string         `json:"fingerprint"`
	RunID        string         `json:"run_id,omitempty"`
}

type TemporalState string

const (
	TemporalCurrent          TemporalState = "current"
	TemporalStale            TemporalState = "stale"
	TemporalMissingLatest    TemporalState = "missing_in_latest_run"
	TemporalNotInLatestScope TemporalState = "not_in_latest_scope"
	TemporalUnknown          TemporalState = "unknown"
	TemporalSuperseded       TemporalState = "superseded"
	TemporalConflicting      TemporalState = "conflicting"
)

type TemporalObservation struct {
	Type        string        `json:"type"`
	State       TemporalState `json:"state"`
	AssetID     string        `json:"asset_id,omitempty"`
	Endpoint    string        `json:"endpoint,omitempty"`
	EvidenceIDs []string      `json:"evidence_ids,omitempty"`
	LatestRunID string        `json:"latest_run_id,omitempty"`
	Reason      string        `json:"reason"`
}

type AuthenticationAttemptStatus string

const (
	AuthPlanned      AuthenticationAttemptStatus = "planned"
	AuthDryRun       AuthenticationAttemptStatus = "dry_run"
	AuthSucceeded    AuthenticationAttemptStatus = "succeeded"
	AuthRejected     AuthenticationAttemptStatus = "rejected"
	AuthInconclusive AuthenticationAttemptStatus = "inconclusive"
	AuthBlocked      AuthenticationAttemptStatus = "blocked"
	AuthCancelled    AuthenticationAttemptStatus = "cancelled"
	AuthError        AuthenticationAttemptStatus = "error"
)

type AuthenticationAttempt struct {
	ID                      string                      `json:"id"`
	RunID                   string                      `json:"run_id"`
	IdentityID              string                      `json:"identity_id"`
	AssetID                 string                      `json:"asset_id,omitempty"`
	Origin                  string                      `json:"origin"`
	Route                   string                      `json:"route"`
	Method                  string                      `json:"method"`
	AuthenticationMethod    string                      `json:"authentication_method"`
	StartedAt               time.Time                   `json:"started_at"`
	FinishedAt              *time.Time                  `json:"finished_at,omitempty"`
	Status                  AuthenticationAttemptStatus `json:"status"`
	Attempted               bool                        `json:"attempted"`
	Succeeded               bool                        `json:"succeeded"`
	Rejected                bool                        `json:"rejected"`
	Inconclusive            bool                        `json:"inconclusive"`
	TransportSucceeded      bool                        `json:"transport_succeeded"`
	HTTPResponseReceived    bool                        `json:"http_response_received"`
	StatusCode              int                         `json:"status_code,omitempty"`
	ChallengeBefore         []string                    `json:"challenge_before,omitempty"`
	ChallengeAfter          []string                    `json:"challenge_after,omitempty"`
	ProtocolValidatedBefore bool                        `json:"protocol_validated_before"`
	UsableAccessAfter       bool                        `json:"usable_access_after"`
	FailureCategory         string                      `json:"failure_category,omitempty"`
	Reason                  string                      `json:"reason"`
	EvidenceIDs             []string                    `json:"evidence_ids,omitempty"`
	BudgetCost              int                         `json:"budget_cost"`
	SafetyAcknowledged      bool                        `json:"safety_acknowledged"`
	PreviousAttempts        int                         `json:"previous_attempts"`
	EvidenceFreshness       TemporalState               `json:"evidence_freshness"`
	RemainingUncertainty    string                      `json:"remaining_uncertainty,omitempty"`
	RepeatOverride          bool                        `json:"repeat_override"`
}

type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"
	FindingAccepted      FindingStatus = "accepted"
	FindingResolved      FindingStatus = "resolved"
	FindingFalsePositive FindingStatus = "false_positive"
)

type Finding struct {
	ID            string        `json:"id"`
	RuleID        string        `json:"rule_id"`
	Title         string        `json:"title"`
	Summary       string        `json:"summary"`
	Description   string        `json:"description"`
	Severity      Severity      `json:"severity"`
	Confidence    Confidence    `json:"confidence"`
	Status        FindingStatus `json:"status"`
	AssetIDs      []string      `json:"asset_ids,omitempty"`
	CredentialIDs []string      `json:"credential_ids,omitempty"`
	EvidenceIDs   []string      `json:"evidence_ids,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
	Remediation   string        `json:"remediation,omitempty"`
	Fingerprint   string        `json:"fingerprint"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

type RelationshipType string

const (
	RelationshipHostsRole                 RelationshipType = "hosts_role"
	RelationshipMemberOfSite              RelationshipType = "member_of_site"
	RelationshipCommunicatesWith          RelationshipType = "communicates_with"
	RelationshipManages                   RelationshipType = "manages"
	RelationshipAuthenticatesTo           RelationshipType = "authenticates_to"
	RelationshipCanAccess                 RelationshipType = "can_access"
	RelationshipContains                  RelationshipType = "contains"
	RelationshipDependsOn                 RelationshipType = "depends_on"
	RelationshipDomainContainsAsset       RelationshipType = "domain_contains_asset"
	RelationshipSiteContainsRole          RelationshipType = "site_contains_role"
	RelationshipHostExposesService        RelationshipType = "host_exposes_service"
	RelationshipDirectoryReferencesHost   RelationshipType = "directory_references_host"
	RelationshipResolvesTo                RelationshipType = "resolves_to"
	RelationshipPossibleManagementPoint   RelationshipType = "possible_management_point"
	RelationshipPossibleDistributionPoint RelationshipType = "possible_distribution_point"
	RelationshipPossibleSiteServer        RelationshipType = "possible_site_server"
	RelationshipSameLogicalHost           RelationshipType = "same_logical_host"
	RelationshipCertificateNamesHost      RelationshipType = "certificate_names_host"
	RelationshipMPListReferencesHost      RelationshipType = "mp_list_references_host"
	RelationshipValidatedManagementPoint  RelationshipType = "validated_as_management_point"
	RelationshipLikelyDistributionPoint   RelationshipType = "likely_distribution_point"
	RelationshipIdentityConflict          RelationshipType = "identity_conflict"
)

type Relationship struct {
	ID          string            `json:"id"`
	FromID      string            `json:"from_id"`
	ToID        string            `json:"to_id"`
	Type        RelationshipType  `json:"type"`
	Properties  map[string]string `json:"properties,omitempty"`
	EvidenceIDs []string          `json:"evidence_ids,omitempty"`
	Confidence  Confidence        `json:"confidence"`
	Fingerprint string            `json:"fingerprint"`
}

type AttackPathStep struct {
	Order            int              `json:"order"`
	FromID           string           `json:"from_id"`
	ToID             string           `json:"to_id"`
	RelationshipType RelationshipType `json:"relationship_type"`
	Description      string           `json:"description"`
	EvidenceIDs      []string         `json:"evidence_ids,omitempty"`
}

type AttackPath struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Summary     string           `json:"summary"`
	Severity    Severity         `json:"severity"`
	Confidence  Confidence       `json:"confidence"`
	StartNodeID string           `json:"start_node_id"`
	EndNodeID   string           `json:"end_node_id"`
	Steps       []AttackPathStep `json:"steps"`
	EvidenceIDs []string         `json:"evidence_ids,omitempty"`
	Fingerprint string           `json:"fingerprint"`
}

// SCCMVersionObservation is a normalized, passive product-version conclusion.
// Reliable is true only when protocol-specific evidence directly supplies Value.
type SCCMVersionObservation struct {
	Product            string     `json:"product"`
	Value              string     `json:"value"`
	State              string     `json:"state"`
	Reliable           bool       `json:"reliable"`
	Confidence         Confidence `json:"confidence"`
	SourceField        string     `json:"source_field,omitempty"`
	SupportingEvidence []string   `json:"supporting_evidence"`
	Unverified         string     `json:"what_remains_unverified"`
}

type RunStatus string

const (
	RunRunning             RunStatus = "running"
	RunCompleted           RunStatus = "completed"
	RunCompletedWithErrors RunStatus = "completed_with_errors"
	RunFailed              RunStatus = "failed"
	RunCancelled           RunStatus = "cancelled"
)

type Run struct {
	ID         string         `json:"id"`
	Command    string         `json:"command"`
	Profile    string         `json:"profile"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Status     RunStatus      `json:"status"`
	Version    string         `json:"version"`
	Arguments  []string       `json:"arguments,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
}

type ModuleExecutionStatus string

const (
	ModuleExecutionRunning   ModuleExecutionStatus = "running"
	ModuleExecutionSuccess   ModuleExecutionStatus = "success"
	ModuleExecutionSkipped   ModuleExecutionStatus = "skipped"
	ModuleExecutionFailed    ModuleExecutionStatus = "failed"
	ModuleExecutionCancelled ModuleExecutionStatus = "cancelled"
)

type ModuleExecution struct {
	ID              string                `json:"id"`
	RunID           string                `json:"run_id"`
	ModuleName      string                `json:"module_name"`
	AssetID         string                `json:"asset_id,omitempty"`
	StartedAt       time.Time             `json:"started_at"`
	FinishedAt      *time.Time            `json:"finished_at,omitempty"`
	Status          ModuleExecutionStatus `json:"status"`
	SkipReason      string                `json:"skip_reason,omitempty"`
	Error           string                `json:"error,omitempty"`
	AssetsCreated   int                   `json:"assets_created"`
	EvidenceCreated int                   `json:"evidence_created"`
	FindingsCreated int                   `json:"findings_created"`
}
