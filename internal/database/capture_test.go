package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSchemaV6MigratesPopulatedV4(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v4.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range [][]string{schemaV1, schemaV2, schemaV3, schemaV4} {
		for _, q := range group {
			if _, e = db.ExecContext(ctx, q); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO research_sets(id,run_id,research_set_id,fingerprint,observed_at,data) VALUES('research_keep','','research_keep','fp','2026-01-01T00:00:00Z','{}')`); e != nil {
		t.Fatal(e)
	}
	if _, e = db.ExecContext(ctx, "PRAGMA user_version = 4"); e != nil {
		t.Fatal(e)
	}
	_ = db.Close()
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var version, count int
	if e = s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version != schemaVersion {
		t.Fatalf("version=%d err=%v", version, e)
	}
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM research_sets WHERE id='research_keep'").Scan(&count); e != nil || count != 1 {
		t.Fatalf("preservation count=%d err=%v", count, e)
	}
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM capture_sources").Scan(&count); e != nil {
		t.Fatal(e)
	}
}

func TestSchemaV6MigratesPopulatedV5(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v5.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range [][]string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5} {
		for _, q := range group {
			if _, e = db.ExecContext(ctx, q); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO capture_sources(id,run_id,fingerprint,observed_at,data) VALUES('capture_keep','','fp','2026-01-01T00:00:00Z','{}')`); e != nil {
		t.Fatal(e)
	}
	_, _ = db.ExecContext(ctx, "PRAGMA user_version = 5")
	_ = db.Close()
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var count int
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM capture_sources WHERE id='capture_keep'").Scan(&count); e != nil || count != 1 {
		t.Fatalf("preservation=%d %v", count, e)
	}
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM capture_flows").Scan(&count); e != nil {
		t.Fatal(e)
	}
}
