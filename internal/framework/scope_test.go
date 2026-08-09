package framework

import "testing"

func TestProductAttackFamilyScope(t *testing.T) {
	for _, family := range []string{"CRED", "ELEVATE", "EXEC", "RECON", "TAKEOVER", "COERCE"} {
		if !IsProductAttackFamily(family) || !IsProductTechnique(family+"-1") {
			t.Fatalf("attack family %s is not accepted", family)
		}
	}
	for _, family := range []string{"PREVENT", "DETECT", "CANARY"} {
		if IsProductAttackFamily(family) || IsProductTechnique(family+"-1") {
			t.Fatalf("defensive family %s is in product scope", family)
		}
	}
}

func TestProductSnapshotFiltersDefensiveRecordsAndMappings(t *testing.T) {
	snapshot, err := EmbeddedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	visible := ProductSnapshot(snapshot)
	if len(visible.Techniques) == 0 || len(visible.Techniques) >= len(snapshot.Techniques) {
		t.Fatalf("unexpected technique filtering: product=%d upstream=%d", len(visible.Techniques), len(snapshot.Techniques))
	}
	if len(visible.Coverage) != len(visible.Techniques) || len(visible.MatrixMappings) != 0 {
		t.Fatalf("coverage=%d techniques=%d mappings=%d", len(visible.Coverage), len(visible.Techniques), len(visible.MatrixMappings))
	}
	for _, technique := range visible.Techniques {
		if !IsProductAttackFamily(technique.Family) || technique.Kind != "attack" {
			t.Fatalf("non-product technique exposed: %+v", technique)
		}
	}
}
