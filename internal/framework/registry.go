package framework

import "sort"

type Objective struct {
	ID         string `json:"id"`
	Track      string `json:"track"`
	Name       string `json:"name"`
	Support    string `json:"support"`
	SafetyNote string `json:"safety_note"`
}
type Registry struct {
	SchemaVersion int         `json:"schema_version"`
	Framework     string      `json:"framework"`
	Objectives    []Objective `json:"objectives"`
}

func MisconfigurationManager() Registry {
	xs := []Objective{{"policy_secrets_naa", "policy_secrets", "NAA policy discovery and recovery", "discovery_supported", "Targeted metadata discovery only; no secret extraction."}, {"policy_secrets_task_sequence", "policy_secrets", "task-sequence credential discovery", "discovery_supported", "Targeted metadata discovery only; reviewed evidence required."}, {"policy_secrets_collection_variables", "policy_secrets", "deployment and collection-variable secret discovery", "discovery_supported", "Targeted metadata discovery only; no live collection."}, {"pxe_dp_assessment", "pxe_osd", "PXE-enabled distribution-point assessment", "planned", "Network action requires separate authorization."}, {"pxe_unknown_computer", "pxe_osd", "PXE password and unknown-computer posture", "planned", "Assessment only."}, {"pxe_boot_media", "pxe_osd", "boot-media acquisition under explicit authorization", "planned", "Not implemented."}, {"pxe_task_sequence_media", "pxe_osd", "task-sequence media analysis", "planned", "Offline analysis planned."}, {"pxe_wim", "pxe_osd", "WIM/image offline inspection", "planned", "Offline analysis planned."}, {"identity_ad_acl", "sccm_identity_attack_paths", "SCCM identity to AD ACL correlation", "planned", "No AD modification."}, {"identity_shadow_prereq", "sccm_identity_attack_paths", "Shadow Credentials prerequisite detection", "planned", "Discovery only planned."}, {"identity_shadow_execute", "sccm_identity_attack_paths", "Shadow Credentials explicitly authorized execution and cleanup", "planned", "Separate explicit authorization and cleanup required."}, {"coverage_registry", "hierarchy_takeover", "Misconfiguration Manager technique coverage registry", "documented", "Planning metadata only."}, {"defensive_mapping", "defensive_controls", "PREVENT/DETECT/CANARY mappings", "planned", "Defensive guidance planned."}}
	sort.Slice(xs, func(i, j int) bool { return xs[i].ID < xs[j].ID })
	return Registry{1, "misconfiguration-manager", xs}
}
