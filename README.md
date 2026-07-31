# CinderPath

CinderPath is an early-stage SCCM discovery, assessment, topology-mapping, and attack-path correlation platform. Its long-term goal is to maintain a normalized model of an SCCM environment, understand the capabilities available to an assessor, run applicable modules, preserve evidence, suppress duplicate noise, and prioritize attack paths.

> **CinderPath is intended for authorized security assessments and controlled lab environments. Users are responsible for ensuring they have explicit permission before assessing any system.**

## Current status

This release provides the original mock pipeline plus a first **explicit, safe, read-only live discovery provider**. Live mode only normalizes user scope, performs DNS queries, attempts bounded TCP connections, collects bounded HTTP/TLS metadata, and—only when explicitly enabled—performs bounded LDAP RootDSE and SCCM directory searches. It does not register clients, retrieve policy, recover credentials, authenticate to SMB/SQL, enumerate shares, execute code, relay authentication, create deployments, or modify a target.

`discover` defaults to `--provider mock`. CinderPath never silently changes to live mode or contacts network systems without `--provider live`.

The `safe` profile is the default and the only functionally meaningful profile. `standard` and `aggressive` reserve names for future policy definitions; in this release they still execute only safe mock modules.

## Architecture

```text
Cobra CLI
   │
   ├── configuration (flags > CINDERPATH_* environment > YAML > defaults)
   ├── application services (run lifecycle and context timeouts)
   │      │
   │      ├── module orchestrator ── mock discovery/assessment/correlation
   │      └── report service ─────── portable JSON + HTML
   │
   └── SQLite store (versioned schema and deterministic upserts)
               │
               └── typed assets, credentials, capabilities, evidence,
                   findings, relationships, attack paths, runs, executions
```

Core application logic is outside Cobra handlers. `internal/modules.Module` exposes metadata, applicability, and execution methods. The orchestrator enforces safety, evaluates capability requirements, records skips, respects cancellation, continues after non-fatal module failures, persists each result incrementally, and produces a run summary.

Key packages:

| Package | Responsibility |
| --- | --- |
| `cmd/cinderpath` | Binary entry point |
| `internal/cli` | Cobra commands and terminal rendering |
| `internal/app` | Discover, assess, and report use cases |
| `internal/config` | Defaults, YAML, environment, and CLI precedence |
| `internal/models` | Strong domain types and stable fingerprints |
| `internal/database` | SQLite schema, migrations, upserts, and queries |
| `internal/modules` | Module contracts and safe orchestrator |
| `internal/modules/mock` | Synthetic SCCM topology and findings |
| `internal/discovery`, `internal/assessment` | Module selection by workflow |
| `internal/capabilities` | Capability helpers |
| `internal/report` | JSON model and self-contained HTML renderer |
| `internal/logging`, `internal/version` | Structured logging and build metadata |

## Build and run

Requirements: Go 1.25 or newer. SQLite is provided by a pure-Go driver; a system SQLite library and CGO are not required.

```bash
go build -o cinderpath ./cmd/cinderpath
./cinderpath version
./cinderpath discover
./cinderpath assess
./cinderpath report
```

The same mock workflow can be run without building:

```bash
go run ./cmd/cinderpath discover --provider mock
go run ./cmd/cinderpath assess
go run ./cmd/cinderpath report
```

Defaults create `./cinderpath.db`, `./reports/cinderpath-report.json`, and `./reports/cinderpath-report.html`.

### Global options

```text
--config PATH          optional YAML configuration file
--db PATH              SQLite database path (default cinderpath.db)
--output-dir PATH      report directory (default reports)
--log-level LEVEL      debug, info, warn, or error
--no-color             disable ANSI output
--timeout DURATION     whole-command timeout (default 2m)
--profile PROFILE      safe, standard, or aggressive
```

Environment variables use the `CINDERPATH_` prefix: `CINDERPATH_DB`, `CINDERPATH_OUTPUT_DIR`, `CINDERPATH_LOG_LEVEL`, `CINDERPATH_NO_COLOR`, `CINDERPATH_TIMEOUT`, `CINDERPATH_PROFILE`, and `CINDERPATH_CONFIG`.

Configuration precedence is:

```text
explicit CLI flag > environment variable > YAML file > built-in default
```

See [`config.example.yaml`](config.example.yaml).

## Mock demonstration

Use an isolated database and report directory:

```bash
mkdir -p demo
go run ./cmd/cinderpath --db demo/cinderpath.db --output-dir demo/reports discover
go run ./cmd/cinderpath --db demo/cinderpath.db --output-dir demo/reports assess
go run ./cmd/cinderpath --db demo/cinderpath.db --output-dir demo/reports report
```

The generated model includes `LAB.LOCAL`, site `LAB`, site server and management point `SCCM01.LAB.LOCAL`, distribution/PXE point `DP01.LAB.LOCAL`, SQL server `SQL01.LAB.LOCAL`, and client `WS01.LAB.LOCAL`. Assessment produces four mock findings and correlation builds one hypothetical path from stored capability, finding, relationship, and evidence records.

Re-running discovery and assessment updates stable records rather than adding duplicate assets or findings.

## Safe live discovery

Live discovery must be explicitly selected and must have explicit scope:

```bash
cinderpath discover --provider live \
  --domain lab.local \
  --target sccm01.lab.local \
  --target 192.0.2.10 \
  --include-cidr 192.0.2.16/29 \
  --exclude-host 192.0.2.18 \
  --exclude-cidr 192.0.2.20/31 \
  --ports 80,443,389,445,1433,8530-8531 \
  --profile safe
```

Scope is normalized and deduplicated before any network stage. Hostnames are lowercased, trailing DNS dots are removed, IP addresses are canonicalized, and a supplied domain is appended to short hostnames. Excluded hosts and CIDRs always win. CIDRs that exceed `scope.max_expanded_targets` or `--max-targets` are rejected before expansion. The default limit is 4,096 targets.

Targets files accept one hostname, FQDN, IPv4 address, IPv6 address, or CIDR per line. Blank lines and lines beginning with `#` are ignored; trailing comments are supported:

```text
# Placeholder lab scope
sccm01.lab.local
192.0.2.10
2001:db8::10
192.0.2.16/29 # bounded subnet
```

### Discovery stages

1. **Scope normalization:** creates provisional, explicitly unverified assets and records original inputs and exclusions.
2. **DNS:** uses Go-native A/AAAA/CNAME or supporting PTR lookups. `--dns-server` selects a resolver without invoking external commands. DNS success or failure is evidence, not a finding.
3. **Reachability:** uses bounded TCP connect attempts with global concurrency, per-host timeouts, and per-connection timeouts. Closed ports are summarized once per host. SMB, LDAP, SQL, and TCP 10123 receive no protocol messages in this stage.
4. **HTTP/TLS:** performs bounded `HEAD /` and `GET /` requests only on open web ports. Bodies, redirects, and request duration are capped. Certificate verification is evaluated and recorded; self-signed certificates remain collectable without being treated as vulnerabilities.
5. **Optional LDAP:** validates only the explicitly selected bind, reads a fixed RootDSE attribute list, and performs paged, size-limited searches for SCCM-related service connection points and objects.
6. **Role inference:** combines LDAP references, open ports, HTTP metadata, hostname patterns, and user hints. Hostname-only conclusions remain low confidence. An open SQL or WSUS port supports a possibility but does not prove SCCM database or software-update roles.

### LDAP and secret handling

LDAP never runs unless `--ldap` is supplied with `--ldap-server` or `--dc`. Anonymous bind is never a fallback; it requires `--ldap-anonymous`. Passwords are accepted only through an environment-variable reference or a bounded password file:

```bash
# Every name and value below is an example placeholder for a controlled GOAD-style lab.
export CINDERPATH_LDAP_PASSWORD='example-only'

cinderpath discover \
  --provider live \
  --domain sevenkingdoms.local \
  --dc dc01.sevenkingdoms.local \
  --ldap \
  --ldap-user 'sevenkingdoms.local\hodor' \
  --ldap-password-env CINDERPATH_LDAP_PASSWORD \
  --target sccm01.sevenkingdoms.local \
  --profile safe
```

Supported transports are LDAP, LDAPS (`--ldap-use-tls`), and STARTTLS (`--ldap-starttls`). `--ldap-insecure-skip-verify` is explicit and its use is recorded in evidence. LDAP searches use the discovered default/configuration naming contexts or `--ldap-base-dn`, request only relevant attributes, use paging, and enforce entry/time limits.

Plaintext passwords exist only in process memory for the bind. CinderPath stores a reference such as `env:CINDERPATH_LDAP_PASSWORD`, never the value. Password values are excluded from structured models, logs, SQLite JSON, HTML, and JSON reports. Failed authentication is operational evidence, not a vulnerability finding.

User role hints (`--management-point`, `--distribution-point`, `--site-server`, `--sql-server`, and `--site-code`) are labeled `user_input` and remain unconfirmed. Reports distinguish mock observations, live observations, user input, and inferred conclusions.

## Data, evidence, and reporting

The SQLite schema is versioned with `PRAGMA user_version`. Runs and module executions retain operational history while the current environment model is upserted by stable identity. JSON is intended for automation. HTML has embedded CSS, no external assets, severity grouping, topology/capability summaries, bounded evidence previews, execution history, and an unavoidable mock-data banner when synthetic assets exist.

Credentials distinguish metadata and secret availability. Plaintext secrets are not serialized to JSON, reports, or normal logs. A `SecretReference` is persisted separately for future integration with an external secret store; it is not itself secret material.

Evidence supports sensitivity labels and structured data. HTML evidence data is capped at 1,000 characters per record. Future collectors must impose their own bounded-read and redaction policies before persistence.

## Fingerprints and deduplication

Identifiers use a typed prefix plus the first 80 bits of a SHA-256 fingerprint. Inputs are trimmed and case-normalized; unordered identity collections are sorted.

* Assets: kind, FQDN, hostname, domain, and site code.
* Evidence: source module, evidence type, linked asset/credential, title, and canonical JSON data. Collection time is excluded.
* Findings: rule ID plus sorted affected asset and credential IDs. Changing evidence does not create a second finding.
* Relationships: directed `from`, `to`, and relationship type.
* Attack paths: start/end nodes plus the ordered relationship edges.

On conflict, mutable records are updated. Asset first-seen time is preserved and roles, addresses, and properties are merged. Finding first-created time, evidence references, and tags are preserved/merged.

## Module design

A module declares:

* name, description, category, and safety level;
* required capabilities and supported asset kinds;
* an applicability decision with a human-readable skip reason;
* a context-aware execution method returning normalized results.

Categories are `discovery`, `profiling`, `assessment`, `collection`, and `correlation`. Safety levels are `safe`, `active`, and `intrusive`. The current orchestrator refuses anything except `safe`, regardless of selected placeholder profile.

New modules should be deterministic, read-only by default, bounded by context, avoid credential logging, and return evidence that distinguishes reachability, authentication, usable access, and collected proof.

## Development and testing

```bash
go fmt ./...
go vet ./...
go test ./...
go build ./...
```

Focused tests cover scope files, normalization, CIDR limits, exclusions, port ranges, concurrency, cancellation, bounded HTTP bodies and redirects, TLS metadata, LDAP parsers, role confidence, password redaction, progress events, mock/live deduplication, and report creation. Tests use loopback fixtures and parser fakes; normal tests require no AD, SCCM, external DNS, or Internet access.

Optional LDAP integration testing skips unless all fixture variables exist:

```bash
CINDERPATH_TEST_LDAP_SERVER=dc01.example.invalid \
CINDERPATH_TEST_LDAP_USER='EXAMPLE\user' \
CINDERPATH_TEST_LDAP_PASSWORD='example-only' \
go test -tags=integration ./internal/discovery/live
```

Version values can be injected at build time:

```bash
go build -ldflags "-X github.com/Lmarkussen/CinderPath/internal/version.Version=v0.1.0 \
  -X github.com/Lmarkussen/CinderPath/internal/version.Commit=$(git rev-parse --short HEAD) \
  -X github.com/Lmarkussen/CinderPath/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o cinderpath ./cmd/cinderpath
```

## Planned capabilities

Future work may add protocol-aware but still read-only SCCM management/distribution point validation, richer DNS discovery, authenticated LDAP mechanisms beyond simple reference binds, evidence encryption, machine-readable schemas, and more general graph correlation. Active or intrusive SCCM operations require separate design, authorization controls, availability safeguards, and tests; they remain intentionally absent.

## Known limitations

* Live discovery only accepts explicit targets; it does not perform broad AD/DNS enumeration automatically.
* SMB, SQL, LDAP probe ports, and TCP 10123 are reachability-only unless the explicit LDAP modules are enabled.
* LDAP currently uses simple bind, explicit anonymous bind, LDAPS, or STARTTLS; current-process Kerberos/SASL providers are future work.
* Role inference is intentionally conservative and cannot confirm an SCCM role from ports or hostnames alone.
* `standard` and `aggressive` do not enable additional behavior.
* SQLite migration history currently contains only schema version 1.
* Correlation uses an in-memory breadth-first traversal suitable for the small mock graph.
* There is no TUI, live credential provider, evidence encryption, distributed execution, or real network collector.
