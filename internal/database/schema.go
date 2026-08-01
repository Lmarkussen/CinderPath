package database

const schemaVersion = 4

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

var schemaV3 = []string{
	`CREATE TABLE protocol_contracts (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE protocol_fixtures (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE protocol_observations (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE protocol_replay_results (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE policy_assignments (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE policy_documents (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE parsed_policies (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE policy_candidates (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE client_identity_metadata (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE sanitization_manifests (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, created_at TEXT NOT NULL, last_observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE workflow_stage_executions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, stage_name TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT, finished_at TEXT, data TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES runs(id))`,
	`CREATE INDEX idx_workflow_stages_run ON workflow_stage_executions(run_id)`,
	`CREATE TABLE workflow_module_decisions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, module_name TEXT NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES runs(id))`,
	`CREATE INDEX idx_workflow_modules_run ON workflow_module_decisions(run_id)`,
}
var schemaV4 = []string{
	`CREATE TABLE research_sets (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE research_set_members (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE research_variables (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE cross_fixture_observations (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE field_correlations (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE request_sequences (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE candidate_contracts (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE contract_derivations (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE contract_dossiers (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE bundle_signatures (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE trusted_research_keys (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE safety_reviews (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
	`CREATE TABLE expected_analysis_results (id TEXT PRIMARY KEY, run_id TEXT NOT NULL DEFAULT '', research_set_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL)`,
}
