package database

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"path/filepath"
	"testing"
)

func TestSchemaV4MigratesV3AndPreservesData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v3.db")
	db, e := sql.Open("sqlite", p)
	if e != nil {
		t.Fatal(e)
	}
	for _, group := range [][]string{schemaV1, schemaV2, schemaV3} {
		for _, q := range group {
			if _, e = db.Exec(q); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = db.Exec(`INSERT INTO runs(id,command,profile,started_at,status,version,arguments,summary) VALUES('run_old','test','safe','2026-01-01T00:00:00Z','completed','test','[]','{}')`); e != nil {
		t.Fatal(e)
	}
	_, _ = db.Exec("PRAGMA user_version = 3")
	_ = db.Close()
	s, e := Open(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var version int
	if e = s.db.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version != 4 {
		t.Fatalf("version=%d %v", version, e)
	}
	if _, e = s.GetRun(context.Background(), "run_old"); e != nil {
		t.Fatal("v3 data lost", e)
	}
	if e = s.UpsertResearchRecord(context.Background(), "research_sets", ResearchRecord{ID: "research_set_test", ResearchSetID: "set", Fingerprint: "sha256:test", Data: map[string]any{"live_policy_requests": 0}}); e != nil {
		t.Fatal(e)
	}
}
