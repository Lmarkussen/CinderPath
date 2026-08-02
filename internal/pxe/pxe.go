package pxe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const SchemaVersion = 1

type Candidate struct {
	CandidateID, ServerFingerprint, SiteCode, Classification, Confidence             string
	ObservedRoles, EvidenceRefs, SupportingEvidence, ContradictingEvidence, Warnings []string
}
type InspectionPlan struct {
	SchemaVersion                                    int       `json:"schema_version"`
	Candidate                                        Candidate `json:"candidate"`
	ConnectionMethod, CredentialSource               string
	ReadOnlyChecks, StopConditions                   []string
	MaximumTargets, MaximumCommands, LivePXERequests int
}
type Service struct {
	Name, State, StartMode string
	Present                bool
}
type Feature struct {
	Name, InstallState string
	Present            bool
}
type RegistryObservation struct{ KeyFingerprint, SafeKeyLabel, ValueName, ValueType, ValueShape, SafeState string }
type LogMetadata struct {
	SafeName                               string
	Exists                                 bool
	Size                                   int64
	SHA256, LastWrite, StructuralIndicator string
}
type BootImageMetadata struct{ IdentifierFingerprint, Architecture, PackageFingerprint, Version, SizeBucket, DistributionState, PXEEligibility, LastUpdate, ContentLocationFingerprint string }
type DeploymentMetadata struct{ DeploymentFingerprint, TaskSequenceFingerprint, CollectionFingerprint, PXEAvailability, UnknownComputerTargeting, DeploymentState, ScheduleBucket, BootImageFingerprint, ProtectionState string }
type RuntimeInventory struct {
	SchemaVersion           int                   `json:"schema_version"`
	CollectedAt             string                `json:"collected_at"`
	Services                []Service             `json:"services"`
	Features                []Feature             `json:"features"`
	Registry                []RegistryObservation `json:"registry_metadata"`
	Logs                    []LogMetadata         `json:"log_metadata"`
	BootImages              []BootImageMetadata   `json:"boot_image_metadata"`
	Deployments             []DeploymentMetadata  `json:"task_sequence_deployment_metadata"`
	BootImageMetadataState  string                `json:"boot_image_metadata_state,omitempty"`
	DeploymentMetadataState string                `json:"task_sequence_deployment_metadata_state,omitempty"`
	SCCMMethodsInvoked      int                   `json:"sccm_methods_invoked"`
	LivePXERequests         int                   `json:"live_pxe_requests"`
	TFTPRequests            int                   `json:"tftp_requests"`
	DHCPRequests            int                   `json:"dhcp_requests"`
	ContentDownloads        int                   `json:"content_downloads"`
}
type Finding struct {
	ID, State, Description, Confidence string
	Vulnerability                      bool
}
type Assessment struct {
	SchemaVersion                                                                                           int              `json:"schema_version"`
	Candidate                                                                                               Candidate        `json:"candidate"`
	Plan                                                                                                    InspectionPlan   `json:"inspection_plan"`
	Runtime                                                                                                 RuntimeInventory `json:"runtime"`
	PXEResponderType, UnknownComputerPosture, PXEPasswordPosture, Classification, ActiveValidationReadiness string
	WDSInstalled, ConfigMgrPXEResponderInstalled, PXEEnabled                                                bool
	BootImageCount, PXEDeploymentCount                                                                      int
	BootImageMetadataState, DeploymentMetadataState                                                         string
	Findings                                                                                                []Finding
	LivePXERequests                                                                                         int
}

func fingerprint(s string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(h[:])[:20]
}

func CandidateFromEvidence(alias, site string, roles, refs []string) Candidate {
	c := Candidate{CandidateID: "pxe_candidate_" + fingerprint(alias), ServerFingerprint: fingerprint(alias), SiteCode: site, ObservedRoles: sorted(roles), EvidenceRefs: sorted(refs), Classification: "insufficient_metadata", Confidence: "low"}
	for _, r := range roles {
		if strings.EqualFold(r, "sccm_site_server") {
			c.Classification = "osd_capable_site_system"
			c.Confidence = "medium"
			c.SupportingEvidence = append(c.SupportingEvidence, "explicit GOAD SCCM inventory membership")
		}
	}
	return c
}
func BuildPlan(c Candidate) InspectionPlan {
	return InspectionPlan{SchemaVersion: 1, Candidate: c, ConnectionMethod: "existing Ansible WinRM inventory; exact host alias only", CredentialSource: "existing inventory credential resolution; values never copied", ReadOnlyChecks: []string{"fixed service metadata", "fixed Windows feature metadata", "fixed PXE/WDS registry metadata", "fixed SCCM PXE log metadata"}, StopConditions: []string{"authentication failure", "endpoint mismatch", "unexpected write requirement", "more than one target"}, MaximumTargets: 1, MaximumCommands: 4, LivePXERequests: 0}
}

func Analyze(c Candidate, p InspectionPlan, r RuntimeInventory) Assessment {
	a := Assessment{SchemaVersion: 1, Candidate: c, Plan: p, Runtime: r, PXEResponderType: "none_observed", UnknownComputerPosture: "unknown_computer_support_unknown", PXEPasswordPosture: "pxe_password_status_unknown", Classification: "pxe_present_no_exposure_established", ActiveValidationReadiness: "not_justified", BootImageCount: len(r.BootImages), PXEDeploymentCount: len(r.Deployments)}
	a.BootImageMetadataState = r.BootImageMetadataState
	if a.BootImageMetadataState == "" {
		if len(r.BootImages) > 0 {
			a.BootImageMetadataState = "server_local_file_metadata_observed"
		} else {
			a.BootImageMetadataState = "no_server_local_boot_image_metadata"
		}
	}
	a.DeploymentMetadataState = r.DeploymentMetadataState
	if a.DeploymentMetadataState == "" {
		a.DeploymentMetadataState = "unavailable_without_existing_read_only_provider"
	}
	if r.LivePXERequests != 0 || r.TFTPRequests != 0 || r.DHCPRequests != 0 || r.ContentDownloads != 0 {
		a.Classification = "invalid_runtime_safety_state"
		return a
	}
	for _, x := range r.Features {
		if x.Present && strings.Contains(strings.ToLower(x.Name), "wds") {
			a.WDSInstalled = true
		}
	}
	for _, x := range r.Services {
		n := strings.ToLower(x.Name)
		if x.Present && (n == "wdserver" || n == "wdsserver") {
			a.WDSInstalled = true
			a.PXEResponderType = "wds"
		}
		if x.Present && n == "sccmpxe" {
			a.ConfigMgrPXEResponderInstalled = true
			a.PXEResponderType = "configmgr_pxe_responder"
		}
		if x.Present && (n == "wdserver" || n == "wdsserver" || n == "sccmpxe") {
			a.PXEEnabled = true
		}
	}
	for _, x := range r.Registry {
		n := strings.ToLower(x.ValueName)
		if strings.Contains(n, "unknown") && x.SafeState == "enabled" {
			a.UnknownComputerPosture = "unknown_computer_support_enabled"
		}
		if strings.Contains(n, "unknown") && x.SafeState == "disabled" {
			a.UnknownComputerPosture = "unknown_computer_support_disabled"
		}
		if strings.Contains(n, "password") && x.SafeState == "configured" {
			a.PXEPasswordPosture = "pxe_password_configured"
		}
		if strings.Contains(n, "password") && x.SafeState == "not_configured" {
			a.PXEPasswordPosture = "pxe_password_not_configured"
		}
	}
	if !a.PXEEnabled {
		a.Classification = "no_pxe_osd_evidence"
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-EVIDENCE-INSUFFICIENT", "observed", "No installed PXE responder or WDS role was observed on the exact SCCM server candidate.", "high", false})
	} else {
		a.Candidate.Classification = "confirmed_pxe_enabled_distribution_point"
		a.Candidate.Confidence = "high"
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-ENABLED-DP-OBSERVED", "observed", "A server-local PXE responder role was observed; enablement alone is not a vulnerability.", "high", false})
		if a.UnknownComputerPosture == "unknown_computer_support_enabled" {
			a.Findings = append(a.Findings, Finding{"SCCM-PXE-UNKNOWN-COMPUTER-SUPPORT-ENABLED", "observed", "Read-only configuration metadata indicates unknown-computer support.", "medium", false})
		}
		if a.BootImageCount > 0 {
			a.Findings = append(a.Findings, Finding{"SCCM-PXE-BOOT-IMAGE-AVAILABLE", "observed", "Boot-image metadata was observed without content retrieval.", "medium", false})
		}
		if a.PXEDeploymentCount > 0 {
			a.Findings = append(a.Findings, Finding{"SCCM-PXE-TASK-SEQUENCE-DEPLOYMENT-OBSERVED", "observed", "PXE deployment metadata was observed without task-sequence retrieval.", "medium", false})
		}
		if a.UnknownComputerPosture == "unknown_computer_support_enabled" && a.PXEDeploymentCount > 0 {
			a.Classification = "pxe_active_validation_justified"
			a.ActiveValidationReadiness = "justified_but_not_authorized_or_performed"
		} else {
			a.Classification = "pxe_present_no_exposure_established"
		}
	}
	return a
}

func LoadRuntime(path string) (RuntimeInventory, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return RuntimeInventory{}, e
	}
	if len(b) > 4<<20 {
		return RuntimeInventory{}, errors.New("PXE runtime metadata exceeds 4 MiB")
	}
	var r RuntimeInventory
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil {
		return r, e
	}
	if r.SchemaVersion != 1 || len(r.Services) > 16 || len(r.Features) > 32 || len(r.Registry) > 128 || len(r.Logs) > 16 || len(r.BootImages) > 256 || len(r.Deployments) > 512 || r.SCCMMethodsInvoked != 0 || r.LivePXERequests != 0 || r.TFTPRequests != 0 || r.DHCPRequests != 0 || r.ContentDownloads != 0 {
		return r, errors.New("invalid PXE runtime bounds or safety state")
	}
	return r, nil
}

func WritePlan(path string, p InspectionPlan) error {
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0600)
}
func WriteDossier(dir string, a Assessment) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	files := map[string]any{"pxe-candidates.json": []Candidate{a.Candidate}, "pxe-inspection-plan.json": a.Plan, "pxe-role-evidence.json": map[string]any{"roles": a.Candidate.ObservedRoles, "responder": a.PXEResponderType}, "pxe-services.json": a.Runtime.Services, "pxe-registry-metadata.json": a.Runtime.Registry, "pxe-log-metadata.json": a.Runtime.Logs, "boot-image-metadata.json": a.Runtime.BootImages, "task-sequence-deployment-metadata.json": a.Runtime.Deployments, "unknown-computer-posture.json": map[string]string{"state": a.UnknownComputerPosture}, "pxe-password-posture.json": map[string]string{"state": a.PXEPasswordPosture}, "pxe-findings.json": a.Findings, "pxe-readiness.json": map[string]any{"classification": a.Classification, "active_validation": a.ActiveValidationReadiness, "live_pxe_requests": 0}}
	for n, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		if e := os.WriteFile(filepath.Join(dir, n), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "gaps-and-next-actions.md"), []byte("# Gaps and next actions\n\nActive PXE validation remains separately authorized and was not performed.\n"), 0600); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "safety-boundaries.md"), []byte("# Safety boundaries\n\nLive PXE, DHCP, TFTP, boot-media, WIM, task-sequence, and content requests: 0.\n"), 0600)
}

func CollectorPowerShell() string { return collectorPS }

const collectorPS = `# CinderPath read-only server-local SCCM PXE/OSD posture collector.
[CmdletBinding()]param([string]$OutputPath='.\pxe-posture.json')
Set-StrictMode -Version 2
$ErrorActionPreference='Stop'
function Hash-Text([string]$v){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($v))).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function Hash-File([string]$p){$h=[Security.Cryptography.SHA256]::Create();$s=New-Object IO.FileStream($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete));try{([BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant())}finally{$s.Dispose();$h.Dispose()}}
$services=@();foreach($n in @('WDSServer','WdsServer','SccmPxe','SMS_EXECUTIVE','SMS_SITE_COMPONENT_MANAGER')){$x=Get-CimInstance Win32_Service -Filter ("Name='"+$n+"'") -ErrorAction SilentlyContinue;$services+=@([ordered]@{Name=$n;State=$(if($x){$x.State}else{'absent'});StartMode=$(if($x){$x.StartMode}else{''});Present=($null-ne$x)})}
$features=@();if(Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue){foreach($x in @(Get-WindowsFeature -Name 'WDS*' -ErrorAction SilentlyContinue|Select-Object -First 32)){$features+=@([ordered]@{Name=$x.Name;InstallState=[string]$x.InstallState;Present=($x.Installed-eq$true)})}}
$registry=@();foreach($kp in @('HKLM:\SOFTWARE\Microsoft\SMS\DP','HKLM:\SOFTWARE\Microsoft\SMS\PXE','HKLM:\SYSTEM\CurrentControlSet\Services\WDSServer\Providers\WDSPXE')){if(Test-Path -LiteralPath $kp){$item=Get-ItemProperty -LiteralPath $kp -ErrorAction SilentlyContinue;foreach($p in @($item.PSObject.Properties|Where-Object{$_.Name-notmatch'^PS'}|Select-Object -First 64)){$v=$p.Value;$safe='present';if($v-is[int]){$safe=$(if($v-eq0){'disabled'}else{'enabled'})}elseif($p.Name-match'(?i)password'){$safe=$(if([string]::IsNullOrEmpty([string]$v)){'not_configured'}else{'configured'})};$registry+=@([ordered]@{KeyFingerprint=(Hash-Text $kp).Substring(0,20);SafeKeyLabel=(Split-Path $kp -Leaf);ValueName=$p.Name;ValueType=$v.GetType().Name;ValueShape=$(if($v-is[int]){'integer'}else{'redacted'});SafeState=$safe})}}}
$logs=@();foreach($n in @('smspxe.log','distmgr.log','pulldp.log','pkgxfermgr.log')){$paths=@("C:\Program Files\Microsoft Configuration Manager\Logs\$n","C:\SMS_DP$\sms\logs\$n");$found=$null;foreach($p in $paths){if(Test-Path -LiteralPath $p){$found=Get-Item -LiteralPath $p;break}};$logs+=@([ordered]@{SafeName=$n;Exists=($null-ne$found);Size=$(if($found){$found.Length}else{0});SHA256=$(if($found){Hash-File $found.FullName}else{''});LastWrite=$(if($found){$found.LastWriteTimeUtc.ToString('o')}else{''});StructuralIndicator=$(if($found){'bounded_file_metadata'}else{'absent'})})}
$boot=@();$bootRoot='C:\RemoteInstall\SMSImages';if(Test-Path -LiteralPath $bootRoot){foreach($f in @(Get-ChildItem -LiteralPath $bootRoot -File -Recurse -ErrorAction SilentlyContinue|Where-Object{$_.Extension-eq'.wim'}|Select-Object -First 256)){$rel=$f.FullName.Substring($bootRoot.Length).TrimStart('\');$arch=$(if($rel-match'(?i)x64|amd64'){'x64'}elseif($rel-match'(?i)x86'){'x86'}elseif($rel-match'(?i)arm64'){'arm64'}else{'unknown'});$boot+=@([ordered]@{IdentifierFingerprint=(Hash-Text $rel).Substring(0,20);Architecture=$arch;PackageFingerprint=(Hash-Text $f.Name).Substring(0,20);Version='unknown';SizeBucket=$(if($f.Length-lt104857600){'under_100MiB'}elseif($f.Length-lt1073741824){'100MiB_to_1GiB'}else{'over_1GiB'});DistributionState='server_local_file_observed';PXEEligibility='unknown';LastUpdate=$f.LastWriteTimeUtc.ToString('o');ContentLocationFingerprint=(Hash-Text $f.DirectoryName).Substring(0,20)})}}
$result=[ordered]@{schema_version=1;collected_at=(Get-Date).ToUniversalTime().ToString('o');services=$services;features=$features;registry_metadata=$registry;log_metadata=$logs;boot_image_metadata=$boot;boot_image_metadata_state='server_local_file_metadata_only';task_sequence_deployment_metadata=@();task_sequence_deployment_metadata_state='unavailable_without_existing_read_only_provider';sccm_methods_invoked=0;live_pxe_requests=0;tftp_requests=0;dhcp_requests=0;content_downloads=0}
[IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 8 -Compress),(New-Object Text.UTF8Encoding($false)))
Write-Host ("PXE posture metadata complete: services={0} features={1} registry={2} logs={3} boot_images={4} deployments=0"-f$services.Count,$features.Count,$registry.Count,$logs.Count,$boot.Count)
Write-Host 'Live PXE requests: 0';Write-Host 'TFTP requests: 0';Write-Host 'DHCP requests: 0';Write-Host 'Content downloads: 0';Write-Host 'SCCM methods invoked: 0'
`

func sorted(x []string) []string { y := append([]string{}, x...); sort.Strings(y); return y }
func RedactedCandidateText(c Candidate) string {
	return fmt.Sprintf("%s roles=%s classification=%s confidence=%s", c.CandidateID, strings.Join(c.ObservedRoles, ","), c.Classification, c.Confidence)
}
