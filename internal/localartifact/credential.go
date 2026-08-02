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

const CredentialAnalysisVersion = "sccm-credential-policy-v1"

type CredentialTarget struct {
	TargetID, Name, Category                                                         string
	KnownPolicyRoles, KnownClassSignals, KnownPropertySignals, KnownNamespaceSignals []string
	KnownRelationshipSignals, KnownArtifactSignals, RequiredEvidence, WeakEvidence   []string
	Contradictions, References, Warnings                                             []string
	SupportLevel                                                                     string
}

type CredentialSchemaMatch struct {
	SchemaID, Namespace, Class                                   string
	TargetIDs                                                    []string
	Score                                                        int
	Confidence                                                   string
	StrongEvidence, MediumEvidence, WeakEvidence, Contradictions []string
	EstimatedInstanceCount                                       int
	Selected                                                     bool
	SelectionReason                                              string
}

type CredentialInstanceCandidate struct {
	CandidateID, InstanceID, Namespace, Class, TargetID, Classification, Confidence string
	StrongEvidence, MediumEvidence, WeakEvidence, Contradictions                    []string
	Properties                                                                      []InstanceProperty
	OpaqueFields                                                                    int
}

type CredentialRelationship struct {
	ID, From, To, Kind, Confidence                              string
	SupportingEvidence, ContradictingEvidence, SourceReferences []string
}

type CredentialPreviewPlanItem struct {
	CandidateID, InstanceID, Namespace, Class, Property, Shape, LengthBucket, Fingerprint string
	TargetIDs                                                                             []string
	Eligible                                                                              bool
	Reasons, Blockers                                                                     []string
}

type CredentialContentPlan struct {
	CandidateID, Recommendation  string
	ReviewRequired, CopyEligible bool
	Reasons, Blockers            []string
}

type CredentialAnalysis struct {
	SchemaVersion                                             int                           `json:"schema_version"`
	AlgorithmVersion                                          string                        `json:"algorithm_version"`
	InventoryFingerprint                                      string                        `json:"inventory_fingerprint"`
	Targets                                                   []CredentialTarget            `json:"credential_targets"`
	SchemaMatches                                             []CredentialSchemaMatch       `json:"credential_schema_matches"`
	Instances                                                 []CredentialInstanceCandidate `json:"credential_instance_candidates"`
	NAACandidates, TaskSequenceCandidates, VariableCandidates []CredentialInstanceCandidate
	Relationships                                             []CredentialRelationship    `json:"credential_relationship_graph"`
	PreviewPlan                                               []CredentialPreviewPlanItem `json:"credential_preview_plan"`
	ContentPlan                                               []CredentialContentPlan     `json:"credential_content_plan"`
	Readiness                                                 string                      `json:"credential_readiness"`
	LivePolicyRequests, RawValuesCopied                       int
}

func CredentialTargets() []CredentialTarget {
	policyNS := []string{`root\ccm\Policy\Machine`, `root\ccm\Policy\Machine\ActualConfig`, `root\ccm\Policy\Machine\RequestedConfig`}
	t := []CredentialTarget{
		{TargetID: "naa", Name: "Network Access Account", Category: "policy_secret", KnownClassSignals: []string{"CCM_NetworkAccessAccount", "CCM_SoftwareDistributionClientConfig"}, KnownPropertySignals: []string{"NetworkAccessUsername", "NetworkAccessPassword"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete policy instance", "known class and username/protected-value property combination"}, WeakEvidence: []string{"account or password name alone", "opaque shape alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "task_sequence_account", Name: "Task-sequence account", Category: "task_sequence", KnownClassSignals: []string{"CCM_TaskSequence"}, KnownPropertySignals: []string{"Sequence", "TaskSequence", "Account", "Password"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete task-sequence policy instance", "structured account-bearing step"}, WeakEvidence: []string{"task-sequence class without credential structure"}, SupportLevel: "discovery_supported"},
		{TargetID: "network_folder_account", Name: "Network-folder account", Category: "task_sequence", KnownClassSignals: []string{"CCM_TaskSequence"}, KnownPropertySignals: []string{"NetworkFolder", "Connect", "Account", "Password"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete structured network-folder step with account fields"}, WeakEvidence: []string{"folder property alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "domain_join_account", Name: "Domain-join account", Category: "osd", KnownClassSignals: []string{"CCM_TaskSequence"}, KnownPropertySignals: []string{"Domain", "Join", "Account", "Password"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete structured domain-join step with protected field"}, WeakEvidence: []string{"domain name alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "collection_variable_secret", Name: "Collection variable secret", Category: "variable", KnownClassSignals: []string{"CCM_CollectionVariable", "CCM_CollectionProperty"}, KnownPropertySignals: []string{"Name", "Value", "IsSecret", "Hidden", "Protected"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete policy variable", "protected flag plus opaque value"}, WeakEvidence: []string{"variable name alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "deployment_variable_secret", Name: "Deployment variable secret", Category: "variable", KnownClassSignals: []string{"CCM_TaskSequence", "CCM_CollectionVariable"}, KnownPropertySignals: []string{"Variable", "Value", "Hidden", "Protected"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete deployment variable with protection evidence"}, WeakEvidence: []string{"value property alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "legacy_package_account", Name: "Legacy package account", Category: "package", KnownClassSignals: []string{"CCM_PeerDP_Package", "CCM_SoftwareDistribution"}, KnownPropertySignals: []string{"AccessAccounts", "PackageID"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete package policy linked to access-account structure"}, WeakEvidence: []string{"package identifier alone"}, SupportLevel: "discovery_supported"},
		{TargetID: "osd_service_account", Name: "OSD service account", Category: "osd", KnownClassSignals: []string{"CCM_TaskSequence"}, KnownPropertySignals: []string{"OSD", "Account", "Password", "Service"}, KnownNamespaceSignals: policyNS, RequiredEvidence: []string{"concrete OSD policy structure with account and protected field"}, WeakEvidence: []string{"OSD token alone"}, SupportLevel: "discovery_supported"},
	}
	sort.Slice(t, func(i, j int) bool { return t[i].TargetID < t[j].TargetID })
	return t
}

func AnalyzeCredentialPolicies(v Inventory) CredentialAnalysis {
	b, _ := json.Marshal(v)
	a := CredentialAnalysis{SchemaVersion: 1, AlgorithmVersion: CredentialAnalysisVersion, InventoryFingerprint: fp(string(b)), Targets: CredentialTargets(), Readiness: "no_credential_policy_evidence"}
	bySchema := map[string]CredentialSchemaMatch{}
	for _, c := range v.Classes {
		m := matchCredentialSchema(c, a.Targets)
		if len(m.TargetIDs) > 0 {
			bySchema[c.Namespace+"\x00"+c.Name] = m
			a.SchemaMatches = append(a.SchemaMatches, m)
		}
	}
	sort.Slice(a.SchemaMatches, func(i, j int) bool {
		if a.SchemaMatches[i].Score != a.SchemaMatches[j].Score {
			return a.SchemaMatches[i].Score > a.SchemaMatches[j].Score
		}
		if a.SchemaMatches[i].Namespace != a.SchemaMatches[j].Namespace {
			return a.SchemaMatches[i].Namespace < a.SchemaMatches[j].Namespace
		}
		return a.SchemaMatches[i].Class < a.SchemaMatches[j].Class
	})
	selected := 0
	for i := range a.SchemaMatches {
		if a.SchemaMatches[i].Score >= 45 && selected < 48 {
			a.SchemaMatches[i].Selected = true
			selected++
			a.SchemaMatches[i].SelectionReason = "target registry class/property combination in SCCM machine policy namespace"
			k := a.SchemaMatches[i].Namespace + "\x00" + a.SchemaMatches[i].Class
			bySchema[k] = a.SchemaMatches[i]
		}
	}
	for _, x := range v.Instances {
		m, ok := bySchema[x.Namespace+"\x00"+x.Class]
		if !ok || !m.Selected {
			continue
		}
		for _, tid := range m.TargetIDs {
			c := classifyCredentialInstance(x, m, tid)
			a.Instances = append(a.Instances, c)
			switch {
			case tid == "naa":
				a.NAACandidates = append(a.NAACandidates, c)
			case strings.Contains(tid, "task_sequence") || tid == "network_folder_account" || tid == "domain_join_account" || tid == "osd_service_account":
				a.TaskSequenceCandidates = append(a.TaskSequenceCandidates, c)
			case strings.Contains(tid, "variable"):
				a.VariableCandidates = append(a.VariableCandidates, c)
			}
		}
	}
	for _, c := range a.Instances {
		a.Relationships = append(a.Relationships, CredentialRelationship{ID: id("credential_edge", c.CandidateID, c.TargetID), From: c.CandidateID, To: c.TargetID, Kind: "instance_matches_target", Confidence: c.Confidence, SupportingEvidence: c.StrongEvidence, ContradictingEvidence: c.Contradictions, SourceReferences: []string{c.InstanceID}})
		for _, p := range c.Properties {
			structured := p.Shape == "XML_like" || p.Shape == "JSON_like" || p.Shape == "base64_like" || p.Shape == "hex_like" || p.Shape == "binary_blob" || p.Shape == "encrypted_or_opaque"
			if !structured || len(a.PreviewPlan) >= 12 {
				continue
			}
			eligible := c.Confidence == "high" || c.Confidence == "medium"
			a.PreviewPlan = append(a.PreviewPlan, CredentialPreviewPlanItem{CandidateID: id("credential_preview", c.CandidateID, p.Name), InstanceID: c.InstanceID, Namespace: c.Namespace, Class: c.Class, Property: p.Name, Shape: p.Shape, LengthBucket: p.LengthBucket, Fingerprint: p.Fingerprint, TargetIDs: []string{c.TargetID}, Eligible: eligible, Reasons: []string{"concrete target-associated instance and structured property metadata"}, Blockers: []string{"values remain redacted; explicit reviewed export required"}})
		}
	}
	for _, c := range a.Instances {
		rec := "metadata_only"
		block := []string{"no concrete protected credential value established"}
		if c.OpaqueFields > 0 && c.Confidence == "high" {
			rec = "structure_preview"
			block = []string{"opaque field requires reviewed structure before copy"}
		}
		a.ContentPlan = append(a.ContentPlan, CredentialContentPlan{CandidateID: c.CandidateID, Recommendation: rec, ReviewRequired: true, CopyEligible: false, Reasons: append([]string{}, c.StrongEvidence...), Blockers: block})
	}
	if len(a.Instances) > 0 {
		a.Readiness = "ready_for_targeted_policy_instance_parser"
	}
	return a
}

func matchCredentialSchema(c ClassSchema, targets []CredentialTarget) CredentialSchemaMatch {
	m := CredentialSchemaMatch{SchemaID: c.ID, Namespace: c.Namespace, Class: c.Name, EstimatedInstanceCount: c.InstanceCount}
	if strings.HasPrefix(c.Name, "__") || strings.HasPrefix(c.Name, "CIM_") || strings.Contains(strings.ToLower(c.Name), "provider") || strings.Contains(strings.ToLower(c.Name), "consumer") {
		return m
	}
	ns := strings.ToLower(c.Namespace)
	if !strings.Contains(ns, `root\ccm\policy\machine`) {
		return m
	}
	props := map[string]bool{}
	for _, p := range c.Properties {
		props[strings.ToLower(p.Name)] = true
	}
	for _, t := range targets {
		classExact := false
		for _, s := range t.KnownClassSignals {
			if strings.EqualFold(c.Name, s) {
				classExact = true
			}
		}
		if !classExact {
			continue
		}
		m.TargetIDs = append(m.TargetIDs, t.TargetID)
		m.Score += 35
		m.MediumEvidence = append(m.MediumEvidence, "known target class in machine policy namespace")
		matches := 0
		for _, s := range t.KnownPropertySignals {
			if props[strings.ToLower(s)] {
				matches++
			}
		}
		if matches >= 2 {
			m.Score += 35
			m.StrongEvidence = append(m.StrongEvidence, "known class plus multiple target property signals")
		} else if matches == 1 {
			m.Score += 10
			m.WeakEvidence = append(m.WeakEvidence, "single target property signal")
		}
	}
	if c.InstanceCount > 0 {
		m.Score += 25
		m.StrongEvidence = append(m.StrongEvidence, "concrete instance count observed")
	} else if c.InstanceCount == 0 {
		m.Contradictions = append(m.Contradictions, "no instances observed in retained inventory")
	}
	if m.Score >= 70 {
		m.Confidence = "high"
	} else if m.Score >= 45 {
		m.Confidence = "medium"
	} else {
		m.Confidence = "low"
	}
	sort.Strings(m.TargetIDs)
	return m
}

func classifyCredentialInstance(x InstanceMetadata, m CredentialSchemaMatch, target string) CredentialInstanceCandidate {
	c := CredentialInstanceCandidate{CandidateID: id("credential_candidate", x.ID, target), InstanceID: x.ID, Namespace: x.Namespace, Class: x.Class, TargetID: target, Classification: target + "_instance_candidate", Confidence: "medium", MediumEvidence: []string{"concrete instance of target-matched policy schema"}, Properties: x.Properties}
	structured := 0
	for _, p := range x.Properties {
		if p.Shape == "encrypted_or_opaque" || p.Shape == "base64_like" || p.Shape == "hex_like" || p.Shape == "binary_blob" {
			structured++
			c.OpaqueFields++
		}
	}
	if len(m.StrongEvidence) > 0 {
		c.StrongEvidence = append(c.StrongEvidence, m.StrongEvidence...)
	}
	if structured > 0 && len(c.StrongEvidence) > 0 {
		c.Confidence = "high"
		c.StrongEvidence = append(c.StrongEvidence, "concrete opaque or encoded field with target schema provenance")
	} else {
		c.WeakEvidence = append(c.WeakEvidence, "no concrete protected-value structure observed")
	}
	if target == "naa" {
		if c.OpaqueFields > 0 && c.Confidence == "high" {
			c.Classification = "naa_protected_value_candidate"
		} else {
			c.Classification = "naa_instance_candidate"
		}
	}
	return c
}

func WriteCredentialAnalysis(dir string, a CredentialAnalysis) error {
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	files := map[string]any{"credential-target-registry.json": a.Targets, "credential-schema-matches.json": a.SchemaMatches, "credential-instance-candidates.json": a.Instances, "naa-candidates.json": a.NAACandidates, "task-sequence-candidates.json": a.TaskSequenceCandidates, "variable-secret-candidates.json": a.VariableCandidates, "credential-relationship-graph.json": a.Relationships, "credential-preview-plan.json": a.PreviewPlan, "credential-content-plan.json": a.ContentPlan, "credential-readiness.json": map[string]any{"readiness": a.Readiness, "live_policy_requests": 0, "raw_values_copied": 0}}
	for n, v := range files {
		b, _ := json.MarshalIndent(v, "", "  ")
		if e := os.WriteFile(filepath.Join(dir, n), append(b, '\n'), 0600); e != nil {
			return e
		}
	}
	if e := os.WriteFile(filepath.Join(dir, "gaps-and-next-actions.md"), []byte("# Gaps and next actions\n\nA concrete protected credential field is required before encrypted-value classification.\n"), 0600); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "safety-boundaries.md"), []byte("# Safety boundaries\n\nOffline/read-only metadata only. Live SCCM policy requests: 0. Raw values copied: 0.\n"), 0600)
}

func CredentialCollectorPowerShell(a CredentialAnalysis) string {
	allow := []map[string]string{}
	for _, m := range a.SchemaMatches {
		if m.Selected {
			allow = append(allow, map[string]string{"namespace": m.Namespace, "class": m.Class})
		}
	}
	b, _ := json.Marshal(allow)
	return fmt.Sprintf(credentialPS, strings.ReplaceAll(string(b), "'", "''"))
}

const credentialPS = `# CinderPath targeted credential-policy metadata collector. Read-only; no SCCM methods or network.
[CmdletBinding()]param([string]$OutputPath=".\credential-instance-metadata.json")
Set-StrictMode -Version 2
$ErrorActionPreference='Stop'
function Hash-Text([string]$v){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($v))).Replace('-','').ToLowerInvariant())}finally{$h.Dispose()}}
function Shape([object]$v){if($null-eq$v){return'empty'};$s=[string]$v;if($s-match'^\s*<[^>]+>'){return'XML_like'};if($s-match'^[A-Za-z0-9+/]{32,}={0,2}$'){return'base64_like'};if($s-match'^[0-9A-Fa-f]{32,}$'){return'hex_like'};if($v-is[byte[]]){return'binary_blob'};return'plaintext_text'}
function Buckets([string]$s){if(-not$s){return@('none','none')};$n=[Math]::Min($s.Length,16384);$counts=@{};$printable=0;for($i=0;$i-lt$n;$i++){$ch=[int][char]$s[$i];if(($ch-ge32-and$ch-le126)-or$ch-eq9-or$ch-eq10-or$ch-eq13){$printable++};if($counts.ContainsKey($ch)){$counts[$ch]++}else{$counts[$ch]=1}};$entropy=0.0;foreach($count in $counts.Values){$p=$count/$n;$entropy-=($p*[Math]::Log($p,2))};$eb=$(if($entropy-lt2){'low'}elseif($entropy-lt5){'medium'}else{'high'});$ratio=$printable/$n;$pb=$(if($ratio-lt0.25){'low'}elseif($ratio-lt0.75){'mixed'}else{'high'});return@($eb,$pb)}
$Allow=ConvertFrom-Json @'
%s
'@
$out=@();$total=0
foreach($a in $Allow){try{$rows=@(Get-CimInstance -Namespace $a.namespace -ClassName $a.class -ErrorAction Stop|Select-Object -First 128);$idx=0;foreach($r in $rows){if($total-ge1000){break};$props=@();foreach($p in @($r.CimInstanceProperties|Select-Object -First 128)){$v=$p.Value;$s=$(if($null-eq$v){''}else{[string]$v});$b=Buckets $s;$refs=@();if($s-and$p.Name-match'(?i)(id|authority|policy|reference|ref)$'){$refs=@((Hash-Text $s).Substring(0,16))};$props+=@([ordered]@{name=$p.Name;cim_type=[string]$p.CimType;state=$(if($null-eq$v){'null'}else{'non_null'});shape=(Shape $v);fingerprint=$(if($s){Hash-Text $s}else{''});length_bucket=$(if($s.Length-eq0){'0'}elseif($s.Length-le32){'1-32'}elseif($s.Length-le256){'33-256'}elseif($s.Length-le4096){'257-4096'}else{'4097+'});entropy_bucket=$b[0];printable_ratio_bucket=$b[1];reference_fingerprints=$refs;array=($v-is[Array]);warnings=@()})};$out+=@([ordered]@{id=(Hash-Text ($a.namespace+'|'+$a.class+'|'+$idx));namespace=$a.namespace;class=$a.class;fingerprint=(Hash-Text ($a.namespace+'|'+$a.class+'|'+$idx));index=$idx;properties=$props;observed_at=(Get-Date).ToUniversalTime().ToString('o');warnings=@()});$idx++;$total++}}catch{}}
$result=[ordered]@{schema_version=1;instances=$out;classes_planned=$Allow.Count;instances_observed=$out.Count;sccm_methods_invoked=0;live_policy_requests=0;raw_values_copied=0}
[IO.File]::WriteAllText($OutputPath,($result|ConvertTo-Json -Depth 10 -Compress),(New-Object Text.UTF8Encoding($false)))
Write-Host ("Targeted credential-policy metadata complete: classes={0} instances={1} raw_copied=0"-f$Allow.Count,$out.Count)
Write-Host 'SCCM client methods invoked: 0';Write-Host 'Live SCCM policy requests: 0'
`

func LoadCredentialRuntime(path string) ([]InstanceMetadata, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) > 16<<20 {
		return nil, errors.New("credential runtime metadata exceeds 16 MiB")
	}
	var x struct {
		SchemaVersion                                                                              int                `json:"schema_version"`
		Instances                                                                                  []InstanceMetadata `json:"instances"`
		ClassesPlanned, InstancesObserved, SCCMMethodsInvoked, LivePolicyRequests, RawValuesCopied int
	}
	if e = json.Unmarshal(b, &x); e != nil {
		return nil, e
	}
	if x.SchemaVersion != 1 || len(x.Instances) > 1000 || x.SCCMMethodsInvoked != 0 || x.LivePolicyRequests != 0 || x.RawValuesCopied != 0 {
		return nil, errors.New("invalid credential runtime safety state")
	}
	return x.Instances, nil
}
