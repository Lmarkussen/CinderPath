package models

import (
	"testing"
	"time"
)

func TestAssetFingerprintIsStableAndNormalized(t *testing.T) {
	now := time.Unix(100, 0)
	a := Asset{Kind: AssetManagementPoint, FQDN: "sccm01.lab.local", Domain: "lab.local", SiteCode: "lab"}
	b := Asset{Kind: AssetManagementPoint, FQDN: " SCCM01.LAB.LOCAL ", Domain: "LAB.LOCAL", SiteCode: "LAB"}
	a.Prepare(now)
	b.Prepare(now.Add(time.Hour))
	if a.ID != b.ID {
		t.Fatalf("IDs differ: %s != %s", a.ID, b.ID)
	}
	if a.FQDN != "SCCM01.LAB.LOCAL" {
		t.Fatalf("FQDN not normalized: %q", a.FQDN)
	}
}

func TestFindingFingerprintIgnoresEvidenceAndOrdering(t *testing.T) {
	now := time.Now()
	a := Finding{RuleID: "CP-1", AssetIDs: []string{"b", "a"}, EvidenceIDs: []string{"old"}}
	b := Finding{RuleID: "cp-1", AssetIDs: []string{"a", "b"}, EvidenceIDs: []string{"new"}}
	a.Prepare(now)
	b.Prepare(now)
	if a.ID != b.ID {
		t.Fatalf("finding IDs differ: %s != %s", a.ID, b.ID)
	}
}

func TestRelationshipDirectionAffectsFingerprint(t *testing.T) {
	a := Relationship{FromID: "a", ToID: "b", Type: RelationshipManages}
	b := Relationship{FromID: "b", ToID: "a", Type: RelationshipManages}
	a.Prepare()
	b.Prepare()
	if a.ID == b.ID {
		t.Fatal("directed relationships must differ")
	}
}
