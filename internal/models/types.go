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
	ID          string            `json:"id"`
	Kind        AssetKind         `json:"kind"`
	Hostname    string            `json:"hostname,omitempty"`
	FQDN        string            `json:"fqdn,omitempty"`
	IPAddresses []string          `json:"ip_addresses,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	SiteCode    string            `json:"site_code,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Source      string            `json:"source"`
	Confidence  Confidence        `json:"confidence"`
	Fingerprint string            `json:"fingerprint"`
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
)

type Credential struct {
	ID              string            `json:"id"`
	Username        string            `json:"username"`
	Domain          string            `json:"domain,omitempty"`
	Type            CredentialType    `json:"type"`
	Source          string            `json:"source"`
	HasSecret       bool              `json:"has_secret"`
	SecretReference string            `json:"-"`
	Properties      map[string]string `json:"properties,omitempty"`
}

type Capability struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Available    bool     `json:"available"`
	Reason       string   `json:"reason,omitempty"`
	Source       string   `json:"source"`
	CredentialID string   `json:"credential_id,omitempty"`
	AssetID      string   `json:"asset_id,omitempty"`
	EvidenceIDs  []string `json:"evidence_ids,omitempty"`
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
