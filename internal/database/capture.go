package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var captureTables = map[string]bool{"capture_sources": true, "capture_exchanges": true, "capture_sequences": true, "capture_observations": true, "capture_parser_candidates": true, "capture_matrices": true, "capture_ambiguities": true}

type CaptureRecord struct {
	ID, RunID, CaptureID, Fingerprint string
	ObservedAt                        time.Time
	Data                              any
}

func (s *Store) UpsertCaptureRecord(ctx context.Context, table string, r CaptureRecord) error {
	if !captureTables[table] {
		return errors.New("unsupported capture table")
	}
	if !safeID.MatchString(r.ID) {
		return errors.New("invalid capture record ID")
	}
	if r.ObservedAt.IsZero() {
		r.ObservedAt = time.Now().UTC()
	}
	b, e := json.Marshal(r.Data)
	if e != nil {
		return e
	}
	if table == "capture_sources" || table == "capture_matrices" {
		q := fmt.Sprintf(`INSERT INTO %s(id,run_id,fingerprint,observed_at,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,observed_at=excluded.observed_at,data=excluded.data`, table)
		_, e = s.db.ExecContext(ctx, q, r.ID, r.RunID, r.Fingerprint, timeText(r.ObservedAt), string(b))
	} else {
		q := fmt.Sprintf(`INSERT INTO %s(id,run_id,capture_id,fingerprint,observed_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,observed_at=excluded.observed_at,data=excluded.data`, table)
		_, e = s.db.ExecContext(ctx, q, r.ID, r.RunID, r.CaptureID, r.Fingerprint, timeText(r.ObservedAt), string(b))
	}
	return e
}
