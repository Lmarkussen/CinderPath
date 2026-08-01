package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var researchTables = map[string]bool{"research_sets": true, "research_set_members": true, "research_variables": true, "cross_fixture_observations": true, "field_correlations": true, "request_sequences": true, "candidate_contracts": true, "contract_derivations": true, "contract_dossiers": true, "bundle_signatures": true, "trusted_research_keys": true, "safety_reviews": true, "expected_analysis_results": true}

type ResearchRecord struct {
	ID, RunID, ResearchSetID, Fingerprint string
	ObservedAt                            time.Time
	Data                                  map[string]any
}

func (s *Store) UpsertResearchRecord(ctx context.Context, table string, r ResearchRecord) error {
	if !researchTables[table] {
		return errors.New("unsupported research table")
	}
	if !safeID.MatchString(r.ID) {
		return errors.New("invalid record ID")
	}
	if r.ObservedAt.IsZero() {
		r.ObservedAt = time.Now().UTC()
	}
	b, e := json.Marshal(r.Data)
	if e != nil {
		return e
	}
	q := fmt.Sprintf(`INSERT INTO %s(id,run_id,research_set_id,fingerprint,observed_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id,research_set_id=excluded.research_set_id,fingerprint=excluded.fingerprint,observed_at=excluded.observed_at,data=excluded.data`, table)
	_, e = s.db.ExecContext(ctx, q, r.ID, r.RunID, r.ResearchSetID, r.Fingerprint, timeText(r.ObservedAt), string(b))
	return e
}
func (s *Store) ListResearchRecords(ctx context.Context, table string) ([]ResearchRecord, error) {
	if !researchTables[table] {
		return nil, errors.New("unsupported research table")
	}
	q := fmt.Sprintf(`SELECT id,run_id,research_set_id,fingerprint,observed_at,data FROM %s ORDER BY research_set_id,id`, table)
	rows, e := s.db.QueryContext(ctx, q)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []ResearchRecord
	for rows.Next() {
		var r ResearchRecord
		var ts, raw string
		if e = rows.Scan(&r.ID, &r.RunID, &r.ResearchSetID, &r.Fingerprint, &ts, &raw); e != nil {
			return nil, e
		}
		r.ObservedAt, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(raw), &r.Data)
		out = append(out, r)
	}
	return out, rows.Err()
}
