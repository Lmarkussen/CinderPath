package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/policy"
)

func clientIdentityApplication(t *testing.T) *Application {
	t.Helper()
	cfg := config.Defaults()
	cfg.DBPath = filepath.Join(t.TempDir(), "identity.db")
	return &Application{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func testClientIdentity(domain, id string) policy.ClientIdentity {
	return policy.ClientIdentity{Kind: "existing_sccm_client", ClientID: id, Domain: domain, Source: struct {
		Type       string `yaml:"type" json:"type"`
		CapturedAt string `yaml:"captured_at" json:"captured_at,omitempty"`
		Verified   bool   `yaml:"verified" json:"verified"`
	}{Type: "local_sccm_client_artifact", Verified: true}}
}

func TestImportedClientIdentityIsReusableAndDeduplicated(t *testing.T) {
	a := clientIdentityApplication(t)
	id := testClientIdentity("SCCM.LAB", "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	for range 2 {
		if err := a.ImportClientIdentity(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := a.StoredClientIdentity(context.Background(), "sccm.lab", time.Hour)
	if err != nil || resolved.Identity.ClientID != "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
}

func TestImportedClientIdentityRejectsCrossDomainAndStaleRecords(t *testing.T) {
	a := clientIdentityApplication(t)
	if err := a.ImportClientIdentity(context.Background(), testClientIdentity("OTHER.LAB", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.StoredClientIdentity(context.Background(), "SCCM.LAB", time.Hour); err == nil {
		t.Fatal("cross-domain client identity accepted")
	}
	if _, err := a.StoredClientIdentity(context.Background(), "OTHER.LAB", time.Nanosecond); err == nil {
		t.Fatal("stale client identity accepted")
	}
}
