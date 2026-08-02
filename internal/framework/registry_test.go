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
		if x.Support != "planned" && x.Support != "documented" {
			t.Fatalf("untruthful support %s", x.Support)
		}
	}
	for _, id := range []string{"policy_secrets_naa", "pxe_dp_assessment", "pxe_boot_media", "identity_shadow_prereq", "identity_shadow_execute", "defensive_mapping"} {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
}
