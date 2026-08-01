package database

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestSchemaV3PolicyPersistenceRedacted(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now().UTC()
	r := PolicyRecord{ID: "candidate_test", RunID: "", Fingerprint: "fp", ObservedAt: now, Data: map[string]any{"redacted_preview": "Syn...!", "state": "confirmed_plaintext"}}
	if e = s.UpsertPolicyRecord(ctx, "policy_candidates", r); e != nil {
		t.Fatal(e)
	}
	got, e := s.ListPolicyRecords(ctx, "policy_candidates")
	if e != nil || len(got) != 1 {
		t.Fatalf("%v %#v", e, got)
	}
	b, _ := json.Marshal(got)
	if string(b) == "" {
		t.Fatal("empty")
	}
	var version int
	if e = s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); e != nil || version != schemaVersion {
		t.Fatalf("schema=%d %v", version, e)
	}
}
