package framework

import "testing"

func TestMisconfigurationManagerRoadmapTruthful(t *testing.T) {
	r := MisconfigurationManager()
	if len(r.Objectives) < 10 {
		t.Fatal("missing roadmap")
	}
	seen := map[string]bool{}
	for _, x := range r.Objectives {
		if seen[x.ID] {
			t.Fatal("duplicate")
		}
		seen[x.ID] = true
		if x.Support != "planned" && x.Support != "documented" && x.Support != "discovery_supported" && x.Support != "assessment_supported" {
			t.Fatalf("untruthful support %s", x.Support)
		}
	}
	for _, id := range []string{"policy_secrets_naa", "pxe_dp_assessment", "pxe_boot_media", "identity_shadow_prereq", "identity_shadow_execute", "defensive_mapping"} {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
	for _, x := range r.Objectives {
		if (x.ID == "policy_secrets_naa" || x.ID == "policy_secrets_task_sequence" || x.ID == "policy_secrets_collection_variables") && x.Support != "discovery_supported" {
			t.Fatalf("targeted discovery coverage missing for %s", x.ID)
		}
		if x.Track == "sccm_identity_attack_paths" && x.Support != "planned" {
			t.Fatalf("unimplemented execution track advanced: %s", x.ID)
		}
		if (x.ID == "pxe_boot_media" || x.ID == "pxe_task_sequence_media" || x.ID == "pxe_wim") && x.Support != "planned" {
			t.Fatalf("content track advanced: %s", x.ID)
		}
	}
}
