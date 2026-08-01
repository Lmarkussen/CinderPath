package database

const schemaVersion = 2

var schemaV1 = []string{
	`CREATE TABLE runs (id TEXT PRIMARY KEY, command TEXT NOT NULL, profile TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, version TEXT NOT NULL, arguments TEXT NOT NULL, summary TEXT NOT NULL)`,
	`CREATE TABLE assets (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, fqdn TEXT, data TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)`,
	`CREATE INDEX idx_assets_kind ON assets(kind)`,
	`CREATE TABLE credentials (id TEXT PRIMARY KEY, secret_reference TEXT NOT NULL DEFAULT '', data TEXT NOT NULL)`,
	`CREATE TABLE capabilities (id TEXT PRIMARY KEY, data TEXT NOT NULL)`,
	`CREATE TABLE evidence (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, data TEXT NOT NULL)`,
	`CREATE TABLE findings (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, severity TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE INDEX idx_findings_severity ON findings(severity)`,
	`CREATE TABLE relationships (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, data TEXT NOT NULL)`,
	`CREATE TABLE attack_paths (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, data TEXT NOT NULL)`,
	`CREATE TABLE module_executions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, module_name TEXT NOT NULL, asset_id TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES runs(id))`,
	`CREATE INDEX idx_module_executions_run ON module_executions(run_id)`,
}

var schemaV2 = []string{
	`CREATE TABLE authentication_attempts (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, identity_id TEXT NOT NULL, asset_id TEXT NOT NULL DEFAULT '', origin TEXT NOT NULL, authentication_method TEXT NOT NULL, started_at TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES runs(id))`,
	`CREATE INDEX idx_auth_attempts_identity_endpoint ON authentication_attempts(identity_id, origin, authentication_method)`,
	`CREATE INDEX idx_auth_attempts_run ON authentication_attempts(run_id)`,
	`CREATE TABLE authentication_locks (identity_id TEXT PRIMARY KEY, acquired_at TEXT NOT NULL)`,
}
