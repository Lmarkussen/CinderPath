package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var policyTables = map[string]bool{"protocol_contracts": true, "protocol_fixtures": true, "protocol_observations": true, "protocol_replay_results": true, "policy_assignments": true, "policy_documents": true, "parsed_policies": true, "policy_candidates": true, "client_identity_metadata": true, "sanitization_manifests": true}
var safeID = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)

type PolicyRecord struct {
	ID, RunID, Fingerprint string
	ObservedAt             time.Time
	Data                   map[string]any
}
type WorkflowRecord struct {
	ID, RunID, Name, State string
	StartedAt, FinishedAt  *time.Time
	Data                   map[string]any
}

func (s *Store) UpsertPolicyRecord(ctx context.Context, table string, r PolicyRecord) error {
	if !policyTables[table] {
		return errors.New("unsupported policy table")
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
	q := ""
	if table == "protocol_contracts" || table == "protocol_fixtures" || table == "client_identity_metadata" || table == "sanitization_manifests" {
		q = fmt.Sprintf(`INSERT INTO %s(id,fingerprint,created_at,last_observed_at,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,last_observed_at=excluded.last_observed_at,data=excluded.data`, table)
		_, e = s.db.ExecContext(ctx, q, r.ID, r.Fingerprint, timeText(r.ObservedAt), timeText(r.ObservedAt), string(b))
	} else {
		q = fmt.Sprintf(`INSERT INTO %s(id,run_id,fingerprint,observed_at,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, table)
		_, e = s.db.ExecContext(ctx, q, r.ID, r.RunID, r.Fingerprint, timeText(r.ObservedAt), string(b))
	}
	return e
}
func (s *Store) ListPolicyRecords(ctx context.Context, table string) ([]PolicyRecord, error) {
	if !policyTables[table] {
		return nil, errors.New("unsupported policy table")
	}
	timeCol := "observed_at"
	runCol := "run_id"
	if table == "protocol_contracts" || table == "protocol_fixtures" || table == "client_identity_metadata" || table == "sanitization_manifests" {
		timeCol = "last_observed_at"
		runCol = "''"
	}
	q := fmt.Sprintf(`SELECT id,%s,fingerprint,%s,data FROM %s ORDER BY id`, runCol, timeCol, table)
	rows, e := s.db.QueryContext(ctx, q)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var r PolicyRecord
		var ts, raw string
		if e = rows.Scan(&r.ID, &r.RunID, &r.Fingerprint, &ts, &raw); e != nil {
			return nil, e
		}
		r.ObservedAt, _ = time.Parse(time.RFC3339Nano, ts)
		_ = json.Unmarshal([]byte(raw), &r.Data)
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) SaveWorkflowStage(ctx context.Context, r WorkflowRecord) error {
	b, _ := json.Marshal(r.Data)
	var st, ft any
	if r.StartedAt != nil {
		st = timeText(*r.StartedAt)
	}
	if r.FinishedAt != nil {
		ft = timeText(*r.FinishedAt)
	}
	_, e := s.db.ExecContext(ctx, `INSERT INTO workflow_stage_executions(id,run_id,stage_name,state,started_at,finished_at,data) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,started_at=excluded.started_at,finished_at=excluded.finished_at,data=excluded.data`, r.ID, r.RunID, r.Name, r.State, st, ft, string(b))
	return e
}
func (s *Store) SaveWorkflowModuleDecision(ctx context.Context, r WorkflowRecord) error {
	b, _ := json.Marshal(r.Data)
	_, e := s.db.ExecContext(ctx, `INSERT INTO workflow_module_decisions(id,run_id,module_name,state,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data`, r.ID, r.RunID, r.Name, r.State, string(b))
	return e
}
func (s *Store) ListWorkflowStages(ctx context.Context) ([]WorkflowRecord, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,run_id,stage_name,state,started_at,finished_at,data FROM workflow_stage_executions ORDER BY run_id,stage_name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []WorkflowRecord
	for rows.Next() {
		var r WorkflowRecord
		var st, ft *string
		var raw string
		if e = rows.Scan(&r.ID, &r.RunID, &r.Name, &r.State, &st, &ft, &raw); e != nil {
			return nil, e
		}
		if st != nil {
			x, _ := time.Parse(time.RFC3339Nano, *st)
			r.StartedAt = &x
		}
		if ft != nil {
			x, _ := time.Parse(time.RFC3339Nano, *ft)
			r.FinishedAt = &x
		}
		_ = json.Unmarshal([]byte(raw), &r.Data)
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) ListWorkflowModuleDecisions(ctx context.Context) ([]WorkflowRecord, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,run_id,module_name,state,data FROM workflow_module_decisions ORDER BY run_id,module_name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []WorkflowRecord
	for rows.Next() {
		var r WorkflowRecord
		var raw string
		if e = rows.Scan(&r.ID, &r.RunID, &r.Name, &r.State, &raw); e != nil {
			return nil, e
		}
		_ = json.Unmarshal([]byte(raw), &r.Data)
		out = append(out, r)
	}
	return out, rows.Err()
}
