package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	path string
}

func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.path }

func (s *Store) initialize(ctx context.Context) error {
	for _, statement := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000"} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure sqlite: %w", err)
		}
	}
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > schemaVersion {
		return fmt.Errorf("database schema %d is newer than supported version %d", version, schemaVersion)
	}
	if version == 0 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV1 {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v1: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit schema: %w", err)
		}
		version = 1
	}
	if version == 1 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV2 {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v2: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit schema v2: %w", err)
		}
		version = 2
	}
	if version == 2 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV3 {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v3: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 3"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit schema v3: %w", err)
		}
		version = 3
	}
	if version == 3 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV4 {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v4: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version = 4"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit schema v4: %w", err)
		}
		version = 4
	}
	if version == 4 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV5 {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v5: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version = 5"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit schema v5: %w", err)
		}
		version = 5
	}
	if version == 5 {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, statement := range schemaV6 {
			if _, err = tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply schema v6: %w", err)
			}
		}
		if _, err = tx.ExecContext(ctx, "PRAGMA user_version = 6"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit schema v6: %w", err)
		}
	}
	return nil
}

func newRunID(command string, now time.Time) string {
	fp := models.StableFingerprint(command, now.UTC().Format(time.RFC3339Nano))
	return models.StableID("run", fp)
}

func (s *Store) CreateRun(ctx context.Context, command, profile, ver string, args []string) (*models.Run, error) {
	now := time.Now().UTC()
	r := &models.Run{ID: newRunID(command, now), Command: command, Profile: profile, StartedAt: now, Status: models.RunRunning, Version: ver, Arguments: args}
	b, _ := json.Marshal(r.Arguments)
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs(id,command,profile,started_at,status,version,arguments,summary) VALUES(?,?,?,?,?,?,?,?)`, r.ID, r.Command, r.Profile, timeText(r.StartedAt), r.Status, r.Version, string(b), "{}")
	if err != nil {
		return nil, fmt.Errorf("create run: %w", err)
	}
	return r, nil
}

func (s *Store) FinishRun(ctx context.Context, id string, status models.RunStatus, summary map[string]any) error {
	now := time.Now().UTC()
	b, _ := json.Marshal(summary)
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished_at=?,status=?,summary=? WHERE id=?`, timeText(now), status, string(b), id)
	return err
}

func (s *Store) LatestRun(ctx context.Context) (*models.Run, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,command,profile,started_at,finished_at,status,version,arguments,summary FROM runs ORDER BY started_at DESC LIMIT 1`)
	return scanRun(row)
}

func (s *Store) ListRuns(ctx context.Context) ([]models.Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,command,profile,started_at,finished_at,status,version,arguments,summary FROM runs ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}
func (s *Store) GetRun(ctx context.Context, id string) (*models.Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, `SELECT id,command,profile,started_at,finished_at,status,version,arguments,summary FROM runs WHERE id=?`, id))
}

type scanner interface{ Scan(...any) error }

func scanRun(s scanner) (*models.Run, error) {
	var r models.Run
	var started string
	var finished sql.NullString
	var args, summary string
	if err := s.Scan(&r.ID, &r.Command, &r.Profile, &started, &finished, &r.Status, &r.Version, &args, &summary); err != nil {
		return nil, err
	}
	r.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	if finished.Valid {
		t, _ := time.Parse(time.RFC3339Nano, finished.String)
		r.FinishedAt = &t
	}
	_ = json.Unmarshal([]byte(args), &r.Arguments)
	_ = json.Unmarshal([]byte(summary), &r.Summary)
	return &r, nil
}

func (s *Store) UpsertAsset(ctx context.Context, a *models.Asset) (bool, error) {
	now := time.Now().UTC()
	a.Prepare(now)
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM assets WHERE id=?`, a.ID).Scan(&existing)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return false, err
	}
	if !created {
		var old models.Asset
		if json.Unmarshal([]byte(existing), &old) == nil {
			if !old.FirstSeen.IsZero() {
				a.FirstSeen = old.FirstSeen
			}
			a.IPAddresses = mergeStrings(old.IPAddresses, a.IPAddresses)
			a.Roles = mergeStrings(old.Roles, a.Roles)
			if a.Properties == nil {
				a.Properties = map[string]string{}
			}
			for key, value := range old.Properties {
				if _, exists := a.Properties[key]; !exists {
					a.Properties[key] = value
				}
			}
		}
	}
	b, _ := json.Marshal(a)
	_, err = s.db.ExecContext(ctx, `INSERT INTO assets(id,fingerprint,kind,fqdn,data,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,fqdn=excluded.fqdn,data=excluded.data,last_seen=excluded.last_seen`, a.ID, a.Fingerprint, a.Kind, a.FQDN, string(b), timeText(a.FirstSeen), timeText(a.LastSeen))
	return created, err
}

func (s *Store) UpsertCredential(ctx context.Context, v *models.Credential) (bool, error) {
	v.Prepare()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM credentials WHERE id=?`, v.ID).Scan(&n); err != nil {
		return false, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO credentials(id,secret_reference,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET secret_reference=excluded.secret_reference,data=excluded.data`, v.ID, v.SecretReference, string(b))
	return n == 0, err
}
func (s *Store) UpsertCapability(ctx context.Context, v *models.Capability) (bool, error) {
	v.Prepare()
	return s.upsertJSON(ctx, "capabilities", v.ID, "", v)
}
func (s *Store) UpsertEvidence(ctx context.Context, v *models.Evidence) (bool, error) {
	v.Prepare(time.Now())
	return s.upsertJSON(ctx, "evidence", v.ID, v.Fingerprint, v)
}
func (s *Store) UpsertRelationship(ctx context.Context, v *models.Relationship) (bool, error) {
	v.Prepare()
	return s.upsertJSON(ctx, "relationships", v.ID, v.Fingerprint, v)
}
func (s *Store) UpsertAttackPath(ctx context.Context, v *models.AttackPath) (bool, error) {
	v.Prepare()
	return s.upsertJSON(ctx, "attack_paths", v.ID, v.Fingerprint, v)
}

func (s *Store) UpsertFinding(ctx context.Context, v *models.Finding) (bool, error) {
	now := time.Now().UTC()
	v.Prepare(now)
	var oldData string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM findings WHERE id=?`, v.ID).Scan(&oldData)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return false, err
	}
	if !created {
		var old models.Finding
		if json.Unmarshal([]byte(oldData), &old) == nil {
			if !old.CreatedAt.IsZero() {
				v.CreatedAt = old.CreatedAt
			}
			v.EvidenceIDs = mergeStrings(old.EvidenceIDs, v.EvidenceIDs)
			v.Tags = mergeStrings(old.Tags, v.Tags)
		}
	}
	b, _ := json.Marshal(v)
	_, err = s.db.ExecContext(ctx, `INSERT INTO findings(id,fingerprint,severity,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,severity=excluded.severity,data=excluded.data`, v.ID, v.Fingerprint, v.Severity, string(b))
	return created, err
}

func (s *Store) upsertJSON(ctx context.Context, table, id, fingerprint string, v any) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE id=?`, id).Scan(&n)
	if err != nil {
		return false, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	if table == "credentials" || table == "capabilities" {
		_, err = s.db.ExecContext(ctx, `INSERT INTO `+table+`(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, id, string(b))
	} else {
		_, err = s.db.ExecContext(ctx, `INSERT INTO `+table+`(id,fingerprint,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,data=excluded.data`, id, fingerprint, string(b))
	}
	return n == 0, err
}

func listJSON[T any](ctx context.Context, db *sql.DB, table string) ([]T, error) {
	rows, err := db.QueryContext(ctx, `SELECT data FROM `+table+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]T, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("decode %s: %w", table, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListAssets(ctx context.Context) ([]models.Asset, error) {
	return listJSON[models.Asset](ctx, s.db, "assets")
}
func (s *Store) ListCredentials(ctx context.Context) ([]models.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data,secret_reference FROM credentials ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Credential
	for rows.Next() {
		var raw string
		var credential models.Credential
		if err := rows.Scan(&raw, &credential.SecretReference); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &credential); err != nil {
			return nil, err
		}
		out = append(out, credential)
	}
	return out, rows.Err()
}
func (s *Store) ListCapabilities(ctx context.Context) ([]models.Capability, error) {
	return listJSON[models.Capability](ctx, s.db, "capabilities")
}
func (s *Store) ListEvidence(ctx context.Context) ([]models.Evidence, error) {
	return listJSON[models.Evidence](ctx, s.db, "evidence")
}
func (s *Store) ListFindings(ctx context.Context) ([]models.Finding, error) {
	return listJSON[models.Finding](ctx, s.db, "findings")
}
func (s *Store) ListRelationships(ctx context.Context) ([]models.Relationship, error) {
	return listJSON[models.Relationship](ctx, s.db, "relationships")
}
func (s *Store) ListAttackPaths(ctx context.Context) ([]models.AttackPath, error) {
	return listJSON[models.AttackPath](ctx, s.db, "attack_paths")
}

func (s *Store) SaveModuleExecution(ctx context.Context, e *models.ModuleExecution) error {
	if e.ID == "" {
		e.ID = models.StableID("mex", models.StableFingerprint(e.RunID, e.ModuleName, e.AssetID, e.StartedAt.Format(time.RFC3339Nano)))
	}
	b, _ := json.Marshal(e)
	_, err := s.db.ExecContext(ctx, `INSERT INTO module_executions(id,run_id,module_name,asset_id,started_at,status,data) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,data=excluded.data`, e.ID, e.RunID, e.ModuleName, e.AssetID, timeText(e.StartedAt), e.Status, string(b))
	return err
}

func (s *Store) ListModuleExecutions(ctx context.Context) ([]models.ModuleExecution, error) {
	return listJSON[models.ModuleExecution](ctx, s.db, "module_executions")
}
func (s *Store) SaveAuthenticationAttempt(ctx context.Context, a *models.AuthenticationAttempt) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO authentication_attempts(id,run_id,identity_id,asset_id,origin,authentication_method,started_at,status,data) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id,identity_id=excluded.identity_id,asset_id=excluded.asset_id,origin=excluded.origin,authentication_method=excluded.authentication_method,started_at=excluded.started_at,status=excluded.status,data=excluded.data`, a.ID, a.RunID, a.IdentityID, a.AssetID, a.Origin, a.AuthenticationMethod, timeText(a.StartedAt), a.Status, string(b))
	return err
}
func (s *Store) ListAuthenticationAttempts(ctx context.Context) ([]models.AuthenticationAttempt, error) {
	return listJSON[models.AuthenticationAttempt](ctx, s.db, "authentication_attempts")
}
func (s *Store) AcquireAuthenticationLock(ctx context.Context, identityID string) (bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO authentication_locks(identity_id,acquired_at) VALUES(?,?)`, identityID, timeText(time.Now().UTC()))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
func (s *Store) ReleaseAuthenticationLock(ctx context.Context, identityID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM authentication_locks WHERE identity_id=?`, identityID)
	return err
}
func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func mergeStrings(groups ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range groups {
		for _, value := range group {
			if value != "" && !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	return out
}
