package pxe

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ProviderNamespace struct {
	Namespace                              string
	Accessible                             bool
	ClassCount                             int
	ProviderFingerprint, SiteCode, Warning string
}
type ProviderClass struct {
	Namespace, Class, Classification string
	Properties, Methods              []string
	InstanceCount                    int
	Accessible                       bool
	Warnings                         []string
}
type TaskSequence struct{ Fingerprint, PackageFingerprint, BootImageFingerprint, ModifiedBucket string }
type Deployment struct {
	Fingerprint, PackageFingerprint, CollectionFingerprint, Availability, Intent, ScheduleBucket string
	PXEFlags                                                                                     []string
	UnknownComputerTarget                                                                        bool
	Confidence                                                                                   string
	Evidence, Contradictions                                                                     []string
}
type CollectionTarget struct {
	Fingerprint     string
	UnknownComputer bool
	Evidence        []string
}
type BootRelationship struct {
	ID, TaskSequenceFingerprint, BootImageFingerprint, DeploymentFingerprint, Confidence string
	Evidence, Contradictions                                                             []string
}
type LogObservation struct{ ObservationID, SafeLog, Category, Classification, Fingerprint, TimestampBucket string }
type DeploymentRuntime struct {
	SchemaVersion      int                 `json:"schema_version"`
	CollectedAt        string              `json:"collected_at"`
	ProviderAvailable  bool                `json:"provider_available"`
	Namespaces         []ProviderNamespace `json:"namespaces"`
	Classes            []ProviderClass     `json:"classes"`
	TaskSequences      []TaskSequence      `json:"task_sequences"`
	Deployments        []Deployment        `json:"deployments"`
	Collections        []CollectionTarget  `json:"collection_targets"`
	BootImages         []BootImageMetadata `json:"boot_images"`
	LogObservations    []LogObservation    `json:"log_observations"`
	PXEPasswordPosture string              `json:"pxe_password_posture"`
	SCCMMethodsInvoked int                 `json:"sccm_methods_invoked"`
	LivePXERequests    int                 `json:"live_pxe_requests"`
	SQLQueries         int                 `json:"sql_queries"`
	ContentDownloads   int                 `json:"content_downloads"`
}
type DeploymentAssessment struct {
	SchemaVersion                                                                                                 int               `json:"schema_version"`
	Runtime                                                                                                       DeploymentRuntime `json:"runtime"`
	ProviderAvailable                                                                                             bool              `json:"provider_available"`
	TaskSequenceCount, DeploymentCount, PXEDeploymentCount, UnknownComputerDeploymentCount, BootRelationshipCount int
	Relationships                                                                                                 []BootRelationship `json:"relationships"`
	Findings                                                                                                      []Finding          `json:"findings"`
	Classification, ActiveValidationReadiness, PXEPasswordPosture                                                 string
	LivePXERequests                                                                                               int
}

func AnalyzeDeployments(r DeploymentRuntime) DeploymentAssessment {
	a := DeploymentAssessment{SchemaVersion: 1, Runtime: r, ProviderAvailable: r.ProviderAvailable, TaskSequenceCount: len(r.TaskSequences), DeploymentCount: len(r.Deployments), PXEPasswordPosture: r.PXEPasswordPosture, Classification: "pxe_present_no_exposure_established", ActiveValidationReadiness: "not_justified"}
	if a.PXEPasswordPosture == "" {
		a.PXEPasswordPosture = "pxe_password_status_unknown"
	}
	if r.LivePXERequests != 0 || r.SCCMMethodsInvoked != 0 || r.SQLQueries != 0 || r.ContentDownloads != 0 {
		a.Classification = "invalid_runtime_safety_state"
		return a
	}
	boot := map[string]bool{}
	for _, b := range r.BootImages {
		boot[b.PackageFingerprint] = true
	}
	for _, d := range r.Deployments {
		if d.Availability == "pxe_available" || d.Availability == "pxe_required" || d.Availability == "media_and_pxe" {
			a.PXEDeploymentCount++
		}
		if d.UnknownComputerTarget {
			a.UnknownComputerDeploymentCount++
		}
		for _, t := range r.TaskSequences {
			if t.PackageFingerprint != "" && t.PackageFingerprint == d.PackageFingerprint && t.BootImageFingerprint != "" {
				conf := "medium"
				contra := []string{}
				if !boot[t.BootImageFingerprint] {
					conf = "low"
					contra = []string{"referenced boot-image metadata not observed"}
				}
				a.Relationships = append(a.Relationships, BootRelationship{ID: "pxe_edge_" + fingerprint(d.Fingerprint+t.Fingerprint), TaskSequenceFingerprint: t.Fingerprint, BootImageFingerprint: t.BootImageFingerprint, DeploymentFingerprint: d.Fingerprint, Confidence: conf, Evidence: []string{"exact package fingerprint relationship"}, Contradictions: contra})
			}
		}
	}
	a.BootRelationshipCount = len(a.Relationships)
	if a.DeploymentCount > 0 {
		a.Classification = "pxe_deployment_metadata_observed"
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-TASK-SEQUENCE-DEPLOYMENT-OBSERVED", "observed", "Read-only provider metadata exposed task-sequence deployment relationships.", "medium", false})
	}
	if a.ProviderAvailable && a.DeploymentCount == 0 {
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-EVIDENCE-INSUFFICIENT", "observed", "The provider was accessible but exposed no deployment relationship instances.", "high", false})
	}
	if a.UnknownComputerDeploymentCount > 0 {
		a.Classification = "pxe_unknown_computer_path_observed"
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-UNKNOWN-COMPUTER-DEPLOYMENT-OBSERVED", "observed", "A deployment relationship targets an unknown-computer collection.", "high", false})
	}
	if a.PXEDeploymentCount > 0 && a.UnknownComputerDeploymentCount > 0 && a.BootRelationshipCount > 0 {
		a.Classification = "pxe_active_validation_justified"
		a.ActiveValidationReadiness = "justified_but_not_authorized_or_performed"
	}
	if !a.ProviderAvailable && len(r.LogObservations) > 0 {
		a.Findings = append(a.Findings, Finding{"SCCM-PXE-LOG-EVIDENCE-OBSERVED", "observed", "Bounded redacted log templates supplemented unavailable provider metadata.", "low", false})
	}
	return a
}

func LoadDeploymentRuntime(path string) (DeploymentRuntime, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return DeploymentRuntime{}, e
	}
	if len(b) > 8<<20 {
		return DeploymentRuntime{}, errors.New("PXE deployment metadata exceeds 8 MiB")
	}
	var r DeploymentRuntime
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil {
		return r, e
	}
	if r.SchemaVersion != 1 || len(r.Namespaces) > 8 || len(r.Classes) > 512 || len(r.TaskSequences) > 256 || len(r.Deployments) > 512 || len(r.Collections) > 512 || len(r.BootImages) > 256 || len(r.LogObservations) > 5000 || r.SCCMMethodsInvoked != 0 || r.LivePXERequests != 0 || r.SQLQueries != 0 || r.ContentDownloads != 0 {
		return r, errors.New("invalid PXE deployment bounds or safety state")
	}
	return r, nil
}

func WriteDeploymentDossier(dir string, a DeploymentAssessment) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	files := map[string]any{"provider-availability.json": map[string]any{"available": a.ProviderAvailable, "namespaces": a.Runtime.Namespaces}, "provider-class-schemas.json": a.Runtime.Classes, "task-sequence-metadata.json": a.Runtime.TaskSequences, "deployment-metadata.json": a.Runtime.Deployments, "collection-targeting.json": a.Runtime.Collections, "boot-image-relationships.json": a.Relationships, "pxe-password-posture.json": map[string]string{"state": a.PXEPasswordPosture}, "pxe-deployment-graph.json": a.Relationships, "pxe-deployment-findings.json": a.Findings, "pxe-active-validation-readiness.json": map[string]any{"classification": a.Classification, "readiness": a.ActiveValidationReadiness, "live_pxe_requests": 0}}
	for n, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		if e := os.WriteFile(filepath.Join(dir, n), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "gaps-and-next-actions.md"), []byte("# Gaps and next actions\n\nActive PXE validation and content retrieval remain unavailable in this phase.\n"), 0600); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "safety-boundaries.md"), []byte("# Safety boundaries\n\nPXE, DHCP, TFTP, SQL, policy, task-sequence body, media, WIM, and content requests: 0.\n"), 0600)
}

func DeploymentCollectorPowerShell(site string) string {
	site = strings.ToUpper(strings.TrimSpace(site))
	if site == "" {
		site = "P01"
	}
	return strings.ReplaceAll(deploymentPS, "SITE_CODE", site)
}

const deploymentPS = `# CinderPath read-only SCCM PXE deployment metadata collector.
[CmdletBinding()]param([string]$OutputPath='.\pxe-deployments.json')
Set-StrictMode -Version 2
$ErrorActionPreference='Stop'
function Hash-Text([string]$v){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($v))).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function FP([object]$v){if($null-eq$v-or[string]::IsNullOrEmpty([string]$v)){return ''};return (Hash-Text([string]$v)).Substring(0,20)}
$site='SITE_CODE';$siteNS='root\SMS\site_'+$site;$namespaces=@();$classes=@();$provider=$false
foreach($ns in @('root\SMS',$siteNS)){try{$cs=@(Get-CimClass -Namespace $ns -ErrorAction Stop|Select-Object -First 512);$namespaces+=@([ordered]@{Namespace=$ns;Accessible=$true;ClassCount=$cs.Count;ProviderFingerprint=(FP $ns);SiteCode=$site;Warning=''});$provider=$true}catch{$namespaces+=@([ordered]@{Namespace=$ns;Accessible=$false;ClassCount=0;ProviderFingerprint='';SiteCode=$site;Warning='unavailable'})}}
$patterns=@('*TaskSequence*','*Advertisement*','*Deployment*','*Collection*','*BootImage*');$seen=@{};$candidates=@()
foreach($pat in $patterns){try{foreach($c in @(Get-CimClass -Namespace $siteNS -ClassName $pat -ErrorAction Stop|Sort-Object CimClassName)){if($candidates.Count-ge512){break};$cn=[string]$c.CimClassName;if($cn.StartsWith('__')-or$seen.ContainsKey($cn)){continue};$pn=@($c.CimClassProperties|Select-Object -ExpandProperty Name|Sort-Object);$score=0;if(($pn-contains'AdvertisementID')-and($pn-contains'CollectionID')-and($pn-contains'PackageID')){$score=100}elseif(($pn-contains'PackageID')-and($pn-contains'BootImageID')){$score=95}elseif(($pn-contains'CollectionID')-and($pn-contains'Name')){$score=90}elseif(($cn-match'(?i)BootImage')-and($pn-contains'PackageID')){$score=85}elseif(($cn-match'(?i)TaskSequence')-and($pn-contains'PackageID')){$score=60}elseif(($pn-contains'DeploymentID')-or($pn-contains'AssignmentID')){$score=50};if($score-eq0){continue};$seen[$cn]=$true;$candidates+=@([pscustomobject]@{ClassObject=$c;Name=$cn;Score=$score})}}catch{}}
$selected=@($candidates|Sort-Object @{Expression='Score';Descending=$true},Name|Select-Object -First 32)
foreach($entry in $selected){$c=$entry.ClassObject;$cn=$entry.Name;$pn=@($c.CimClassProperties|Select-Object -ExpandProperty Name|Sort-Object);$mn=@($c.CimClassMethods|ForEach-Object{$_.Name}|Where-Object{$_}|Sort-Object);$kind=$(if(($pn-contains'AdvertisementID')-and($pn-contains'CollectionID')-and($pn-contains'PackageID')){'deployment'}elseif(($pn-contains'PackageID')-and($pn-contains'BootImageID')){'task_sequence'}elseif(($pn-contains'CollectionID')-and($pn-contains'Name')){'collection'}elseif(($cn-match'(?i)BootImage')-and($pn-contains'PackageID')){'boot_image'}else{'unknown'});$classes+=@([ordered]@{Namespace=$siteNS;Class=$cn;Classification=$kind;Properties=$pn;Methods=$mn;InstanceCount=-1;Accessible=$true;Warnings=@(('structural selection score '+$entry.Score))})}
$script:rowError='';function Rows([string]$cn){$script:rowError='';try{return @(Get-CimInstance -Namespace $siteNS -ClassName $cn -ErrorAction Stop|Select-Object -First 256)}catch{$script:rowError='instance_query_unavailable';return @()}}
function Val([object]$x,[string]$n){$p=$x.CimInstanceProperties[$n];if($null-eq$p){return $null};return $p.Value}
$ts=@();$collections=@();$deploy=@();$boots=@();$total=0
foreach($c in $classes){if($total-ge2000){break};$rows=@(Rows $c.Class);$c.InstanceCount=$rows.Count;if($script:rowError){$c.Warnings+=@($script:rowError)};foreach($x in $rows){if($total-ge2000){break};$total++;$cn=$c.Class;if($c.Classification-eq'task_sequence'){$packageValue=Val $x 'PackageID';if($null-ne$packageValue){$boot=Val $x 'BootImageID';if($null-eq$boot){$boot=Val $x 'BootImagePackageID'};$ts+=@([ordered]@{Fingerprint=(FP (([string]$packageValue)+'|ts'));PackageFingerprint=(FP $packageValue);BootImageFingerprint=(FP $boot);ModifiedBucket=$(if($null-ne(Val $x 'LastRefreshTime')){'timestamp_present'}else{'unknown'})})}}elseif($c.Classification-eq'collection'){$cid=Val $x 'CollectionID';if($null-ne$cid){$name=[string](Val $x 'Name');$unknown=($name-match'(?i)unknown computer');$collections+=@([ordered]@{Fingerprint=(FP $cid);UnknownComputer=$unknown;Evidence=$(if($unknown){@('provider collection name matched built-in unknown-computer role; name not retained')}else{@('provider collection metadata')})})}}elseif($c.Classification-eq'deployment'){$id=Val $x 'AdvertisementID';if($null-eq$id){$id=Val $x 'DeploymentID'};if($null-eq$id){$id=Val $x 'AssignmentID'};$packageValue=Val $x 'PackageID';$cid=Val $x 'CollectionID';if($null-ne$id-and$null-ne$packageValue-and$null-ne$cid){$flags=@();if($null-ne(Val $x 'AdvertFlags')){$flags+=@('advert_flags_present')};$deploy+=@([ordered]@{Fingerprint=(FP $id);PackageFingerprint=(FP $packageValue);CollectionFingerprint=(FP $cid);Availability='availability_unknown';Intent='unknown';ScheduleBucket=$(if($null-ne(Val $x 'PresentTime')){'timestamp_present'}else{'unknown'});PXEFlags=$flags;UnknownComputerTarget=$false;Confidence='low';Evidence=@('provider deployment identifiers and relationships observed');Contradictions=@('PXE availability and intent flag semantics not positively established')})}}elseif($c.Classification-eq'boot_image'){$packageValue=Val $x 'PackageID';if($null-ne$packageValue){$boots+=@([ordered]@{IdentifierFingerprint=(FP $packageValue);Architecture=$(if($null-ne(Val $x 'Architecture')){[string](Val $x 'Architecture')}else{'unknown'});PackageFingerprint=(FP $packageValue);Version=$(if($null-ne(Val $x 'Version')){[string](Val $x 'Version')}else{'unknown'});SizeBucket='unknown';DistributionState='provider_metadata_observed';PXEEligibility='unknown';LastUpdate=$(if($null-ne(Val $x 'SourceDate')){'timestamp_present'}else{'unknown'});ContentLocationFingerprint=''})}}}}
$unknownByID=@{};foreach($x in $collections){$unknownByID[$x.Fingerprint]=$x.UnknownComputer}
foreach($x in $deploy){$x.UnknownComputerTarget=($unknownByID[$x.CollectionFingerprint]-eq$true)}
$logs=@();$lp='C:\Program Files\Microsoft Configuration Manager\Logs\smspxe.log';if(Test-Path -LiteralPath $lp){$fs=New-Object IO.FileStream($lp,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite-bor[IO.FileShare]::Delete));try{$max=[Math]::Min($fs.Length,2097152);$fs.Seek(-$max,[IO.SeekOrigin]::End)|Out-Null;$buf=New-Object byte[] $max;$read=$fs.Read($buf,0,$max);$text=[Text.Encoding]::Default.GetString($buf,0,$read);$i=0;foreach($pat in @('unknown computer','task sequence','boot image','advertisement')){$count=[regex]::Matches($text,$pat,[Text.RegularExpressions.RegexOptions]::IgnoreCase).Count;if($count-gt0){$logs+=@([ordered]@{ObservationID=(FP ($pat+'|'+$count));SafeLog='smspxe.log';Category=($pat-replace' ','_');Classification='structural_template_observed';Fingerprint=(FP $pat);TimestampBucket='capture_window_unknown'});$i++;if($i-ge5000){break}}}}finally{$fs.Dispose()}}
$result=[ordered]@{schema_version=1;collected_at=(Get-Date).ToUniversalTime().ToString('o');provider_available=$provider;namespaces=$namespaces;classes=$classes;task_sequences=$ts;deployments=$deploy;collection_targets=$collections;boot_images=$boots;log_observations=$logs;pxe_password_posture='pxe_password_status_unknown';sccm_methods_invoked=0;live_pxe_requests=0;sql_queries=0;content_downloads=0}
[IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 10 -Compress),(New-Object Text.UTF8Encoding($false)))
Write-Host ("PXE deployment metadata complete: provider={0} namespaces={1} classes={2} task_sequences={3} deployments={4} collections={5} boot_images={6} log_observations={7}"-f$provider,$namespaces.Count,$classes.Count,$ts.Count,$deploy.Count,$collections.Count,$boots.Count,$logs.Count)
Write-Host 'Task-sequence bodies read: 0';Write-Host 'Collection members read: 0';Write-Host 'SQL queries: 0';Write-Host 'Live PXE requests: 0';Write-Host 'Content downloads: 0';Write-Host 'SCCM methods invoked: 0'
`

func sortedDeployments(x []Deployment) {
	sort.Slice(x, func(i, j int) bool { return x[i].Fingerprint < x[j].Fingerprint })
}
