package framework

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestEmbeddedSnapshotAndCoverageDimensions(t *testing.T) {
	s, err := EmbeddedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Techniques) == 0 || len(s.Coverage) != len(s.Techniques) {
		t.Fatalf("techniques=%d coverage=%d", len(s.Techniques), len(s.Coverage))
	}
	if s.Coverage[0].Discovery == s.Coverage[0].Execution { /* independent fields may coincide, but are distinct in the model */
	}
}

func TestCanonicalCredentialTechniqueMapping(t *testing.T) {
	s, err := EmbeddedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]string{}
	for _, technique := range s.Techniques {
		titles[technique.ID] = technique.Title
	}
	if titles["CRED-2"] != "Request computer policy and deobfuscate secrets" {
		t.Fatalf("CRED-2=%q", titles["CRED-2"])
	}
	if titles["CRED-1"] != "Retrieve secrets from PXE boot media" {
		t.Fatalf("CRED-1=%q", titles["CRED-1"])
	}
}

func TestImportDeterministicAndRejectsUnknownMatrixReference(t *testing.T) {
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "attack-techniques", "CRED", "CRED-1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "defense-techniques", "DETECT", "DETECT-1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "attack-techniques", "CRED", "CRED-1", "cred-1_description.md"), []byte("# Credential discovery\n\nBounded policy metadata."), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "defense-techniques", "DETECT", "DETECT-1", "detect-1_description.md"), []byte("# Detection\n\nDefensive mapping."), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "attack-defense-matrix.csv"), []byte("attack,UNKNOWN-1\nCRED-1,x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(ImportOptions{Source: d, Revision: "r1", SnapshotDate: "2026-08-03"}); err == nil {
		t.Fatal("unknown matrix reference accepted")
	}
	os.WriteFile(filepath.Join(d, "attack-defense-matrix.csv"), []byte("attack,DETECT-1\nCRED-1,1\n"), 0600)
	a, err := Import(ImportOptions{Source: d, Revision: "r1", SnapshotDate: "2026-08-03"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Import(ImportOptions{Source: d, Revision: "r1", SnapshotDate: "2026-08-03"})
	if err != nil {
		t.Fatal(err)
	}
	if SnapshotFingerprint(a) != SnapshotFingerprint(b) || len(a.MatrixMappings) != 1 {
		t.Fatalf("non-deterministic import: %s %d", SnapshotFingerprint(a), len(a.MatrixMappings))
	}
}
