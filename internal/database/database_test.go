package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestUpsertDeduplicatesAssetsAndFindings(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 2; i++ {
		a := &models.Asset{Kind: models.AssetSiteServer, FQDN: "sccm01.lab.local", Domain: "LAB.LOCAL", SiteCode: "LAB"}
		created, err := s.UpsertAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if created != (i == 0) {
			t.Fatalf("asset created=%v iteration=%d", created, i)
		}
		f := &models.Finding{RuleID: "MOCK-1", AssetIDs: []string{a.ID}, Title: "mock", Severity: models.SeverityLow}
		created, err = s.UpsertFinding(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if created != (i == 0) {
			t.Fatalf("finding created=%v iteration=%d", created, i)
		}
	}
	assets, _ := s.ListAssets(ctx)
	findings, _ := s.ListFindings(ctx)
	if len(assets) != 1 || len(findings) != 1 {
		t.Fatalf("got %d assets, %d findings", len(assets), len(findings))
	}
}
