package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
)

func TestSchemaV2AuthenticationAttemptHistoryPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.CreateRun(ctx, "auth validate", "safe", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	a := models.AuthenticationAttempt{ID: "auth_one", RunID: run.ID, IdentityID: "cred", Origin: "https://mp.lab", Route: "/SMS_MP/.sms_aut?MPLIST", Method: "GET", AuthenticationMethod: "basic", StartedAt: time.Now().UTC(), Status: models.AuthRejected, Attempted: true}
	if err := s.SaveAuthenticationAttempt(ctx, &a); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.ListAuthenticationAttempts(ctx)
	if err != nil || len(got) != 1 || !got[0].Attempted {
		t.Fatalf("history %#v %v", got, err)
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatalf("schema=%d %v", version, err)
	}
}

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
