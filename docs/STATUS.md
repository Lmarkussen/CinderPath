# CinderPath status and handover

This document is the implementation handover for the next Codex session. It describes the repository at the current `main` branch state.

## Project identity and safety statement

- Repository and Go module: `github.com/Lmarkussen/CinderPath`
- Binary: `cinderpath`
- Go version: 1.25 or newer
- Primary database: SQLite through the pure-Go `modernc.org/sqlite` driver

> CinderPath is intended for authorized security assessments and controlled lab environments. Users are responsible for ensuring they have explicit permission before assessing any system.

CinderPath is an early-stage SCCM discovery, assessment, topology-mapping, and attack-path correlation platform. It now has a safe mock pipeline and an explicit-scope, read-only live discovery pipeline. It does not yet perform SCCM protocol-aware endpoint validation or any SCCM abuse.

## Current architecture

```text
cmd/cinderpath
    └── internal/cli                 Cobra commands, flags, terminal summaries
            └── internal/app         run lifecycle and discover/assess/report services
                    ├── internal/modules
                    │       ├── orchestrator, requirements, safety gates
                    │       ├── internal/modules/mock
                    │       └── internal/discovery/live
                    ├── internal/database
                    ├── internal/report
                    └── internal/progress

Supporting packages:
    internal/models                  typed domain models and fingerprints
    internal/config                  defaults, YAML, environment, CLI precedence
    internal/scope                   target parsing/normalization/exclusions
    internal/discovery               discovery module selection
    internal/assessment              assessment/correlation module selection
    internal/capabilities            capability helpers
    internal/logging                 structured slog setup and masking
    internal/version                 version/build metadata
```

Application logic is intentionally outside Cobra handlers. Modules return normalized assets, credentials, capabilities, evidence, findings, relationships, and attack paths. The orchestrator evaluates safety and capability requirements, records skips, publishes progress, persists results incrementally, and continues after non-fatal module failures.

## Commands

### `cinderpath version`

Prints version, commit, build date, and Go toolchain information. Values can be injected with `-ldflags` as documented in `README.md`.

### `cinderpath discover`

Runs the selected discovery provider. Default provider is `mock`; live discovery never starts implicitly.

```bash
cinderpath discover --provider mock
cinderpath discover --provider live --target 127.0.0.1
```

Discovery flags:

```text
--provider mock|live
--target HOST                         repeatable; also accepts an address or CIDR
--targets-file PATH                   repeatable
--domain DOMAIN
--dns-server IP_OR_HOSTPORT
--dc HOST
--include-cidr CIDR                   repeatable
--exclude-host HOST                   repeatable
--exclude-cidr CIDR                   repeatable
--max-targets NUMBER
--ports PORTS                         comma-separated values and bounded ranges
--connect-timeout DURATION
--host-timeout DURATION
--concurrency NUMBER

--ldap
--ldap-server HOST
--ldap-port PORT
--ldap-base-dn DN
--ldap-user USER
--ldap-password-env ENV_NAME
--ldap-password-file PATH
--ldap-use-tls
--ldap-starttls
--ldap-insecure-skip-verify
--ldap-anonymous

--management-point HOST               repeatable, unconfirmed hint
--distribution-point HOST             repeatable, unconfirmed hint
--site-server HOST                    repeatable, unconfirmed hint
--sql-server HOST                     repeatable, unconfirmed hint
--site-code CODE
```

### `cinderpath assess`

Runs the existing mock assessment and mock attack-path correlation modules against stored assets. The current real implementation is discovery-focused; there are no live vulnerability or abuse modules.

### `cinderpath report`

Reads stored data and creates:

```text
reports/cinderpath-report.json
reports/cinderpath-report.html
```

The HTML report is portable with embedded CSS. Reports distinguish mock data, live observations, user input, inferred conclusions, and confirmed conclusions. Evidence previews are bounded.

### Global flags

```text
--config PATH
--db PATH
--output-dir PATH
--log-level debug|info|warn|error
--no-color
--timeout DURATION
--profile safe|standard|aggressive
```

Configuration precedence is explicit CLI flag, environment variable, YAML file, then default. `safe` is the only functionally meaningful profile. `standard` and `aggressive` remain placeholders and still execute only safe modules.

## Mock behavior

The default workflow remains network-free:

```bash
go run ./cmd/cinderpath discover --provider mock
go run ./cmd/cinderpath assess
go run ./cmd/cinderpath report
```

Mock discovery creates:

- Domain `LAB.LOCAL`
- Site code `LAB`
- Site server and management point `SCCM01.LAB.LOCAL`
- Distribution point and PXE service point `DP01.LAB.LOCAL`
- SQL server `SQL01.LAB.LOCAL`
- Client `WS01.LAB.LOCAL`
- Realistic synthetic relationships and capabilities

Mock assessment creates four clearly labeled synthetic findings:

- Management point identified and reachable — informational
- Distribution point permits content enumeration — low
- PXE functionality detected — informational
- Hypothetical policy credential exposure — high, medium confidence, explicitly hypothetical

Mock correlation consumes stored relationships, capabilities, findings, and evidence to create one hypothetical two-step attack path. No real secret exists or is recovered.

## Live discovery behavior

Live discovery requires both `--provider live` and non-empty explicit scope after exclusions. Current live behavior is safe and read-only but does make network connections to the supplied targets.

### Module pipeline

```text
live.scope.normalize
live.dns.resolve
live.network.probe
live.http.profile
live.ldap.rootdse
live.ldap.sccm_directory
live.roles.infer
```

All current live modules are marked `safe`.

Capabilities gate later modules. Examples include:

```text
scope_normalized
dns_resolution
network_probe_completed
http_profiling
ldap_endpoint_reachable
ldap_bind_successful
ldap_authenticated
ldap_anonymous
rootdse_readable
default_naming_context_known
configuration_naming_context_known
sccm_directory_objects_discovered
```

LDAP modules record an applicability skip when LDAP was not explicitly enabled or a required capability is unavailable.

## Progress event architecture

`internal/progress` defines a transport-neutral `Sink` interface and `Event` model. `Collector` is thread-safe, and `Nop` is available when progress is not consumed.

Event types:

```text
run_started
stage_started
module_started
target_started
target_completed
module_completed
module_skipped
warning
error
run_completed
```

`modules.RunContext` carries a progress sink and exposes `Emit`. The application emits run lifecycle events, the orchestrator emits module lifecycle events, and live modules emit stage and target events. The application includes collected events in its outcome. Modules do not print directly, so a future TUI, JSON event stream, or terminal subscriber can consume the same events.

## Database and deterministic fingerprints

The database uses schema version 1. No schema change was needed for live discovery because existing JSON-backed records already support provenance and stage data.

Persisted record types:

- Runs
- Assets
- Credentials
- Capabilities
- Evidence
- Findings
- Relationships
- Attack paths
- Module executions

Deterministic IDs are typed prefixes plus the first 80 bits of a SHA-256 fingerprint. Inputs are trimmed and case-normalized.

Fingerprint identities:

- Named asset: kind, FQDN, hostname, domain, and site code. This preserves the original schema-v1 strategy.
- IP-only asset: named-asset fields plus sorted canonical addresses.
- Evidence: source module, type, linked asset/credential, title, and canonical structured data. Collection time, observation time, and duration fields are excluded so identical observations deduplicate. Material state changes can coexist.
- Finding: rule ID plus sorted affected asset and credential IDs. Evidence changes update the same finding.
- Relationship: directed source, target, and type; role or port is included where one relationship pair needs multiple semantic edges.
- Attack path: start/end nodes plus ordered relationship edges.

Upserts preserve asset `FirstSeen`, update `LastSeen`, merge addresses/roles/properties, preserve finding creation time, and merge finding evidence/tags. Repeated identical mock and live runs do not duplicate stable assets, evidence, findings, or relationships. Run and module-execution history intentionally grows.

## Scope normalization and exclusions

`internal/scope` accepts:

- Hostnames
- FQDNs
- IPv4 addresses
- IPv6 addresses
- CIDRs
- Target files containing those values

Target files ignore blank lines, full-line `#` comments, and trailing comments. Hostnames are lowercased, trailing DNS dots are removed, short names receive the supplied domain, and IP addresses are canonicalized/unmapped where appropriate.

CIDRs are expanded only after their size is checked. The default maximum is 4,096 targets and is configurable through:

```yaml
scope:
  max_expanded_targets: 4096
```

or `--max-targets`. Excessive scope is rejected before network activity. Excluded hosts and networks always take precedence. A scope reduced to zero targets is rejected clearly.

Original input, normalized targets, excluded targets, expansion counts, maximum size, and supplied domain are recorded as `scope_decision` evidence and summarized in the run/report.

## DNS behavior

DNS uses Go-native resolvers; it never shells out to `dig`, `host`, or `nslookup`.

- Hostnames/FQDNs: A, AAAA, and optional supporting CNAME lookup
- IP addresses: PTR lookup as supporting evidence only
- Explicit resolver: `--dns-server`, with port 53 added when omitted
- Resolver environment: bounded parsing of local nameserver and search-domain metadata
- Concurrency: bounded by the configured worker limit
- Timeout: bounded per target and by command context

DNS evidence includes query, record type, answers, resolver, duration, and error. PTR data does not overwrite an explicitly supplied hostname. DNS success or failure does not create a security finding.

## TCP behavior

The default probe ports are:

```text
53,80,88,135,389,443,445,636,1433,3268,3269,8530,8531,10123
```

`--ports` accepts comma-separated ports and bounded ranges. The scanner uses a fixed global host-worker limit, sequential bounded port checks per host, a per-host deadline, a per-connection deadline, context cancellation, and no unbounded work queue.

One summarized `network_probe` evidence record is created per host with attempted, open, timed-out, and failed ports. Accepted connections create `host_exposes_service` relationships. Closed ports do not flood stdout or create individual findings.

TCP 445, generic LDAP ports, TCP 1433, and TCP 10123 are connect-only in this stage. There is no authentication, share enumeration, SQL query, LDAP query, or SCCM notification message.

## HTTP and TLS behavior

HTTP profiling runs only for open ports 80, 443, 8530, and 8531.

- Sends bounded `HEAD /` and `GET /`
- Uses a dedicated user agent
- Does not use environment proxy settings
- Follows only a small number of same-host redirects
- Cannot redirect outside the explicitly scoped host
- Caps total request time and response-body bytes
- Stores a small UTF-8 preview and page title when available

Captured metadata includes status, server, location, content type, authentication headers, final URL, duration, truncation, and request errors.

TLS collection uses a scoped client that permits certificate collection and then evaluates verification independently. Evidence records that behavior. Certificate metadata includes subject, issuer, DNS/IP names, serial number, validity, signature algorithm, SHA-256 fingerprint, verification success, and verification error. A self-signed certificate is collectable but is not treated as a vulnerability.

## LDAP behavior

LDAP runs only when `--ldap` is explicit and a server is identified with `--ldap-server` or `--dc`.

Supported transports:

- LDAP
- LDAPS with `--ldap-use-tls`
- STARTTLS with `--ldap-starttls`
- Explicit verification bypass with `--ldap-insecure-skip-verify`; the choice is recorded

For credentialed binds, environment-variable reference takes precedence over password file. Explicit anonymous bind is a separate selection and never an implicit fallback. Plaintext password CLI arguments do not exist.

The connection deadline is the smaller of the configured LDAP timeout and command context deadline. A successful bind performs a bounded RootDSE base-object query for an allowlist including:

```text
defaultNamingContext
configurationNamingContext
rootDomainNamingContext
schemaNamingContext
dnsHostName
supportedLDAPVersion
supportedSASLMechanisms
domainFunctionality
forestFunctionality
domainControllerFunctionality
isGlobalCatalogReady
```

SCCM directory discovery searches the supplied base DN or discovered default/configuration contexts. Searches are paged, entry-limited, time-limited, and request only:

```text
objectClass
cn
distinguishedName
dNSHostName
name
keywords
serviceBindingInformation
serviceClassName
```

Current bounded filters look for SCCM/SMS/ConfigMgr-related service connection points, `mSSMSManagementPoint`, `mSSMSSite`, System Management, SCCM, and SMS naming patterns. Only relevant attributes are normalized into evidence. Full raw entries are not stored.

Failed connection or authentication creates operational evidence and unavailable capabilities, not a vulnerability finding. A credential-reference record is retained even when validation fails.

## SCCM role inference

`live.roles.infer` is conservative and evidence-driven:

- LDAP SCCM object explicitly referencing a host as a role: high confidence
- User-supplied role hint: medium confidence and labeled `user_input`; never automatically confirmed
- TCP 8530/8531: possible software update point, medium confidence
- TCP 1433: SQL service availability only, low confidence; does not prove an SCCM database
- TCP 10123: SCCM-related supporting evidence, low confidence
- Hostname containing `sccm` or `configmgr`: possible site server, low confidence
- `dp*` hostname plus open HTTP: possible distribution point, low confidence
- Hostname containing `pxe` plus open HTTP/HTTPS: possible PXE service point, low confidence
- HTTP title/header metadata containing Configuration Manager/SMS Management terminology: possible management point, medium confidence
- HTTP metadata containing WSUS terminology: possible software update point, medium confidence

Possible live roles include:

```text
site_server
management_point
distribution_point
pxe_service_point
sql_server
software_update_point
client
unknown
```

Informational role findings explain the evidence, confidence, and what remains unverified. No high-severity live finding is created merely because a service exists.

## Safety boundaries

The current implementation must remain within these boundaries:

- Mock is the default provider.
- Live discovery requires explicit provider and scope.
- Only modules marked `safe` run; placeholder profiles do not override this.
- No SCCM client registration.
- No policy retrieval or secret extraction.
- No password spraying or credential attacks.
- No NTLM relay.
- No package/content download during discovery.
- No deployment creation or modification.
- No SMB authentication or share enumeration.
- No SQL authentication, query, or modification.
- No WMI, remote command execution, payload execution, persistence, or availability testing.
- Network, response, search, paging, redirect, body, entry, and concurrency limits are mandatory.
- A scanner match, port, hostname, or certificate is supporting evidence rather than automatic vulnerability confirmation.

## Secret-handling guarantees

- There is no ordinary plaintext LDAP password CLI flag.
- `--ldap-password-env` reads a named environment variable into process memory.
- `--ldap-password-file` performs a bounded read and strips only trailing line endings.
- The credential model persists only a `SecretReference`, for example `env:CINDERPATH_LDAP_PASSWORD`.
- `Credential.SecretReference` is omitted from normal JSON serialization.
- Plaintext values are not logged, placed in run arguments, SQLite JSON, HTML, or JSON reports.
- Failed binds retain reference metadata but not the secret.
- Anonymous bind is explicit and never a fallback.
- Tests use synthetic values and verify that password material is not serialized.

## Tests

Existing tests cover:

- Model fingerprint normalization and directed relationships
- Database asset/finding deduplication and merging
- Configuration precedence
- Secret masking
- Complete mock workflow twice with stable asset/finding/path counts
- Report generation
- Cancellation and timeout behavior
- Repeated loopback live discovery deduplication
- Target-file parsing
- Host/IP normalization
- CIDR expansion limits
- Exclusion precedence
- Port/range parsing and invalid inputs
- Global network concurrency bounds
- Network cancellation
- HTTP body-size limits
- HTTP redirect limits
- TLS metadata normalization and self-signed verification result
- DNS result normalization
- Resolver-configuration parsing
- LDAP deadline cancellation
- RootDSE parsing
- SCCM LDAP object parsing
- Role-inference confidence
- LDAP password serialization redaction
- Concurrent progress-event collection and emitted workflow events

Local HTTP/TLS tests use loopback fixture servers. LDAP unit tests operate at parser/client boundaries and do not require AD. The integration-tag LDAP test skips cleanly unless all fixture variables are present:

```text
CINDERPATH_TEST_LDAP_SERVER
CINDERPATH_TEST_LDAP_USER
CINDERPATH_TEST_LDAP_PASSWORD
```

## Validation commands

Required after Go changes:

```bash
go fmt ./...
go vet ./...
go test ./...
go build ./...
```

Optional integration-tag validation:

```bash
go test -tags=integration ./...
```

Mock regression workflow:

```bash
go run ./cmd/cinderpath discover --provider mock
go run ./cmd/cinderpath assess
go run ./cmd/cinderpath report
```

Safe local live smoke test:

```bash
go run ./cmd/cinderpath discover \
  --provider live \
  --target 127.0.0.1 \
  --ports 80,443,389 \
  --timeout 30s
```

## Known limitations

- Live discovery is explicit-target only; there is no broad AD/DNS enumeration.
- There is no protocol-aware SCCM HTTP route identification yet.
- Distribution point identity is inferred rather than validated through SCCM endpoints.
- There is no content-location metadata inspection yet.
- Generic SMB, SQL, LDAP, and TCP 10123 checks are reachability-only.
- LDAP authentication is simple bind or explicit anonymous; current-process Kerberos/SASL providers are not implemented.
- Role inference cannot confirm SCCM roles from ports or hostname patterns alone.
- Service graph targets use deterministic endpoint node identifiers rather than separately persisted service assets.
- Schema migration history contains only version 1.
- Attack-path correlation remains an in-memory breadth-first traversal designed around the mock graph.
- Live discovery does not currently generate real attack paths.
- There is no TUI, event-stream CLI, general credential-provider abstraction, evidence encryption, or distributed execution.
- `standard` and `aggressive` are placeholders.

## Exact recommended next task

Implement **protocol-aware, read-only SCCM endpoint validation** without changing the existing safe defaults or adding authentication attacks/state-changing behavior.

Required scope:

1. **Management point endpoint identification**
   - Identify management points using SCCM-specific, documented HTTP response characteristics rather than ports or hostnames alone.
   - Normalize positive and negative evidence and state precisely what is verified.

2. **SCCM-specific HTTP route fingerprinting**
   - Probe a small, reviewed allowlist of read-only SCCM routes.
   - Use bounded methods, response sizes, redirects, timeouts, and same-host policy.
   - Avoid client registration, policy retrieval, secret-bearing endpoints, or authentication attacks.

3. **Distribution point identification**
   - Distinguish a generic web server from a likely SCCM distribution point using protocol-aware metadata.
   - Correlate results with DNS, LDAP references, certificates, and existing role hints.

4. **Content-location metadata inspection without downloading packages**
   - Inspect only bounded metadata required to identify SCCM content-location behavior.
   - Do not enumerate unlimited content, retrieve package payloads, or save package data.

5. **Unauthenticated versus authenticated access**
   - Record separately whether an endpoint is reachable, responds anonymously, requests authentication, was authenticated, and provides usable read access.
   - Do not label a credential valid based only on a banner or HTTP status.

6. **Protocol and version confidence**
   - Add structured protocol observations and confidence rules.
   - Do not claim a specific SCCM version unless direct bounded evidence supports it.

7. **Local HTTP fixtures**
   - Add local fixture handlers for every supported management-point and distribution-point endpoint pattern.
   - Cover positive, negative, authentication-required, redirects, oversized bodies, malformed responses, cancellation, deduplication, and report output.

Suggested module names:

```text
live.sccm.http_routes
live.sccm.management_point
live.sccm.distribution_point
live.sccm.content_location
```

All modules must remain `safe`, require an explicitly selected live provider and existing HTTP/network capabilities, publish progress events, and produce conservative informational findings only.

Suggested commit message for that next task:

```text
Add read-only SCCM endpoint validation
```
