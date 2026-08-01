package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var captureTables = map[string]bool{"capture_sources": true, "capture_exchanges": true, "capture_sequences": true, "capture_observations": true, "capture_parser_candidates": true, "capture_matrices": true, "capture_ambiguities": true, "capture_files": true, "capture_interfaces": true, "capture_packets": true, "capture_flows": true, "capture_sequence_edges": true, "parser_validation_results": true, "capture_matrix_cells": true, "capture_matrix_findings": true, "capture_corpus_results": true, "capture_dossiers": true}

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
func (s *Store) ListCaptureRecords(ctx context.Context, table string) ([]CaptureRecord, error) {
	if !captureTables[table] {
		return nil, errors.New("unsupported capture table")
	}
	cols := "id,run_id,'' as capture_id,fingerprint,observed_at,data"
	if table != "capture_sources" && table != "capture_matrices" {
		cols = "id,run_id,capture_id,fingerprint,observed_at,data"
	}
	rows, e := s.db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s ORDER BY id", cols, table))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []CaptureRecord
	for rows.Next() {
		var r CaptureRecord
		var ts, raw string
		if e = rows.Scan(&r.ID, &r.RunID, &r.CaptureID, &r.Fingerprint, &ts, &raw); e != nil {
			return nil, e
		}
		r.ObservedAt, _ = time.Parse(time.RFC3339Nano, ts)
		var data map[string]any
		_ = json.Unmarshal([]byte(raw), &data)
		r.Data = data
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) GetCaptureRecord(ctx context.Context, table, id string) (CaptureRecord, error) {
	if !captureTables[table] {
		return CaptureRecord{}, errors.New("unsupported capture table")
	}
	cols := "id,run_id,'' as capture_id,fingerprint,observed_at,data"
	if table != "capture_sources" && table != "capture_matrices" {
		cols = "id,run_id,capture_id,fingerprint,observed_at,data"
	}
	var r CaptureRecord
	var ts, raw string
	e := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM %s WHERE id=?", cols, table), id).Scan(&r.ID, &r.RunID, &r.CaptureID, &r.Fingerprint, &ts, &raw)
	if e != nil {
		return r, e
	}
	r.ObservedAt, _ = time.Parse(time.RFC3339Nano, ts)
	var data map[string]any
	_ = json.Unmarshal([]byte(raw), &data)
	r.Data = data
	return r, nil
}
