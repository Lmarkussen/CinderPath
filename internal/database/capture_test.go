package database

import (
	"context"
	"database/sql"
	"fmt"
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

func TestCaptureKitPersistenceTablesReadWriteAndHistory(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "kit.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tables := []string{"capture_kits", "capture_kit_files", "capture_kit_validation_results", "capture_kit_reviews", "capture_kit_imports", "windows_client_inventories", "capture_tool_inventories", "capture_kit_matrix_links", "capture_kit_dossiers", "capture_evidence_bundles", "capture_evidence_bundle_members", "windows_log_inspections"}
	for i, table := range tables {
		id := fmt.Sprintf("record_%d", i)
		if e = s.UpsertCaptureRecord(ctx, table, CaptureRecord{ID: id, RunID: "run_a", CaptureID: "capture_kit_a", Fingerprint: "sha256_redacted", Data: map[string]any{"safe_name": "sample.json", "state": "offline", "live_requests": 0}}); e != nil {
			t.Fatalf("%s: %v", table, e)
		}
		rows, e := s.ListCaptureRecords(ctx, table)
		if e != nil || len(rows) != 1 {
			t.Fatalf("%s rows=%d err=%v", table, len(rows), e)
		}
	}
	for _, id := range []string{"validation_run_a", "validation_run_b"} {
		if e = s.UpsertCaptureRecord(ctx, "capture_kit_validation_results", CaptureRecord{ID: id, RunID: id, CaptureID: "capture_kit_a", Fingerprint: "fp", Data: map[string]any{"state": "requires_manual_review"}}); e != nil {
			t.Fatal(e)
		}
	}
	rows, _ := s.ListCaptureRecords(ctx, "capture_kit_validation_results")
	if len(rows) != 3 {
		t.Fatalf("history=%d", len(rows))
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

func TestSchemaV7MigratesPopulatedV6(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v6.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range [][]string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6} {
		for _, q := range group {
			if _, e = db.ExecContext(ctx, q); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO capture_sources(id,run_id,fingerprint,observed_at,data) VALUES('capture_keep','','fp','2026-01-01T00:00:00Z','{}')`); e != nil {
		t.Fatal(e)
	}
	_, _ = db.ExecContext(ctx, "PRAGMA user_version = 6")
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
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM capture_kit_imports").Scan(&count); e != nil {
		t.Fatal(e)
	}
}

func TestSchemaV8MigratesPopulatedV7(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v7.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range [][]string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7} {
		for _, q := range group {
			if _, e = db.ExecContext(ctx, q); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = db.ExecContext(ctx, `INSERT INTO capture_kits(id,run_id,fingerprint,observed_at,data) VALUES('capture_kit_keep','','fp','2026-01-01T00:00:00Z','{}')`); e != nil {
		t.Fatal(e)
	}
	_, _ = db.ExecContext(ctx, "PRAGMA user_version = 7")
	_ = db.Close()
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var count int
	if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM capture_kits WHERE id='capture_kit_keep'").Scan(&count); e != nil || count != 1 {
		t.Fatalf("preservation=%d %v", count, e)
	}
	for _, table := range []string{"capture_evidence_bundles", "capture_evidence_bundle_members", "windows_log_inspections"} {
		if e = s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); e != nil {
			t.Fatal(e)
		}
	}
}
