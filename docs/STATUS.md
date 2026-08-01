# CinderPath status and handover

This document is the implementation handover for the next Codex session. It describes the repository at the current `main` branch state.

## Project identity and safety statement

- Repository and Go module: `github.com/Lmarkussen/CinderPath`
- Binary: `cinderpath`
- Go version: 1.25 or newer
- Primary database: SQLite through the pure-Go `modernc.org/sqlite` driver

> CinderPath is intended for authorized security assessments and controlled lab environments. Users are responsible for ensuring they have explicit permission before assessing any system.

CinderPath is an early-stage SCCM discovery, assessment, topology-mapping, and attack-path correlation platform. It has a safe mock pipeline, explicit-scope read-only live discovery, and a separate disabled-by-default authentication-validation workflow. Authentication validation is restricted to user-selected identities and exact previously observed SCCM routes; it does not retrieve policy/content, recover secrets, register clients, or modify targets.

It also has local SCCM identity and authentication-capability modeling. `identity inspect` normalizes logical identities, validates local references, and parses bounded public PEM/DER certificates. `capabilities` correlates references with persisted anonymous SCCM route challenges. Identity fingerprints exclude secret values and reference locations. Reports show basename-only file references. Authentication results are exact identity/origin/route/method observations and never imply global SCCM authentication.

Capability states distinguish `available`, `unavailable`, `unknown`, `requires_validation`, and `blocked_by_safety`. Run-attributed temporal states distinguish current, stale, missing, out-of-scope, unknown, superseded, and conflicting observations. Missing states require latest scope plus successful stage execution. Stale or missing endpoint evidence cannot authorize an authentication attempt.

### `cinderpath auth validate` and `auth results`

`auth validate` supports Basic and TLS client-certificate validation only. It requires exact stored identity selection and either exact origin selection or validated-management-point selection. Actual requests require `--enable-auth-validation` and `--acknowledge-lockout-risk`; multiple planned attempts require an additional acknowledgement. The request reuses only the exact GET/HEAD route already observed, has no body, proxy, cookie jar, redirect, retry, or ambient credentials. `--dry-run` reads no secret and sends no traffic. Schema version 2 preserves actual attempt history so restarting the CLI does not erase budget state.

Authentication validation may cause account lockout or security alerts. Use only with explicit authorization and carefully selected identities.

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

### `cinderpath identity` and `cinderpath capabilities`

`identity inspect` accepts domain/user, machine, current-process, password/hash environment or file references, Kerberos cache references, and public-certificate/private-key path references. It never accepts plaintext secret CLI values and does not read private keys or ticket contents. The separate guarded validator may parse a selected bounded PEM private key solely to verify pairing and construct one TLS client-auth request. `identity list` shows redacted stored models.

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
live.sccm.http_routes
live.sccm.management_point
live.sccm.distribution_point
live.roles.infer
live.sccm.correlate
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
sccm_http_route_probing
sccm_mp_endpoint_reachable
sccm_mp_http_response_received
sccm_mp_anonymous_request
sccm_mp_protocol_validated
sccm_mp_authentication_required
sccm_mp_usable_read_access
sccm_dp_route_reachable
sccm_dp_http_response_received
sccm_dp_anonymous_request
sccm_dp_access_controlled
sccm_dp_likely
```

LDAP modules record an applicability skip when LDAP was not explicitly enabled or a required capability is unavailable.

The three SCCM modules are global discovery modules. They record an applicability skip when no successful HTTP/HTTPS profile exists on a scoped port 80/443 endpoint. Only `live.sccm.http_routes` performs network requests; the MP and DP modules classify persisted route evidence without additional traffic.

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

The database uses schema version 2. Migration 1 is unchanged; migration 2 adds durable authentication-attempt history. Existing model records remain JSON-backed.

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

Passive correlation requires no migration and does not alter schema-v1 asset fingerprints. It adds deterministic JSON-backed evidence and relationships over existing asset IDs.

## Passive SCCM topology correlation

`live.sccm.correlate` is the final live stage and performs no network activity. It correlates normalized FQDN, short-name, IP, DNS/CNAME, LDAP host reference, TLS certificate name, MP-list reference/site-code, validated-route, inferred-role, and user-hint observations already in the store.

A `same_logical_host` relationship requires a unique explicit DNS join between one named and one IP-only asset. Multiple named assets sharing an address remain distinct. LDAP and MP-list references match only existing assets and never expand scope. Certificate mismatches, shared addresses, conflicting site codes, validated MPs absent from collected LDAP, unresolved LDAP references, and unmatched MP-list references retain source IDs, values, confidence, assessment relevance, and what remains unverified. They are evidence or informational discovery findings, not vulnerabilities.

JSON and HTML topology output includes canonical identity, aliases, addresses, SCCM roles, site codes, role confidence, protocol-validation state, LDAP/TLS/MP-list references, conflicts, unresolved references, and normalized version evidence. Only a documented protocol-specific field can establish a product version. IIS/Windows headers, generic HTTP fields, certificate dates, and hostname patterns are excluded; current reports explicitly show `SCCM version: unknown` when no reliable field exists.

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

`live.roles.infer` is conservative and evidence-driven. Its precedence is:

1. Successfully parsed SCCM management-point protocol evidence
2. Explicit SCCM LDAP host/role reference
3. Correlated SCCM-specific route observations
4. User-supplied role hint
5. Generic HTTP metadata
6. Open-port or hostname pattern

Current conclusions include:

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

## SCCM HTTP endpoint validation

The network collector operates only on already-profiled origins using the standard scheme/port pairs `http:80` and `https:443`. It sends the following exact allowlist, sequentially per host:

```text
GET  /SMS_MP/.sms_aut?MPLIST
HEAD /SMS_DP_SMSPKG$/
HEAD /SMS_DP_SMSSIG$/
HEAD /NOCERT_SMS_DP_SMSPKG$/
HEAD /NOCERT_SMS_DP_SMSSIG$/
```

Limits are five initial route probes per origin, at most two origins and ten initial route probes per host, no retries, existing bounded host concurrency, the configured per-host/client timeouts, and the existing bounded MP response-body limit. Redirects are capped at `min(configured, 2)` and must remain on the same scheme, hostname, and port inside explicit scope. Redirects never add targets to scope.

The dedicated transport has no proxy callback or cookie jar, sends no client certificate, disables keep-alive reuse, and permits only GET/HEAD with nil bodies. Authorization, proxy authorization, cookies, ambient Windows credentials, NTLM/Negotiate authentication, POST/PUT/PATCH/DELETE/OPTIONS/PROPFIND, WebDAV, BITS, and SCCM messaging are absent and rejected by testable request guards.

Each `sccm_http_route` record has an independent `sccm_access_state`:

```text
transport_reachable
http_response_received
anonymous_request
authentication_requested
authentication_attempted
authenticated
usable_read_access
protocol_validated
```

All current probes are anonymous; authentication is never attempted and `authenticated` is always false. A `401`, an advertised authentication challenge, or a TLS client-certificate request means authentication was requested. A `403` means denial, not authentication. Reports expose every state separately.

### Management-point rules

The bounded parser accepts only a well-formed SCCM MP-list root containing MP elements and meaningful normalized host/site fields. It rejects HTML, generic XML, malformed XML, empty bodies, and bodies exceeding the configured limit. Referenced hosts and site codes remain bounded evidence; they are not persisted as new active targets and are never contacted.

* **High:** meaningful SCCM MP-list parse; usable read access and protocol validation are true.
* **Medium:** the exact route requests authentication and SCCM LDAP evidence independently references the same host.
* **Low:** route/status behavior only; no finding.
* **Unverified:** generic/malformed/oversized/empty content, rejected redirect, timeout, `404`, `405`, or `5xx`; no finding.

Positive results use `DISCOVERY-SCCM-MP-ENDPOINT`. Generic route existence or `200/401/403` never creates a finding by itself.

### Distribution-point rules

DP requests use `HEAD` and do not read response bodies. A distinct `2xx` from one exact virtual-directory root is strong, high-confidence evidence for a likely DP, not absolute confirmation. A `401/403` route requires either a second distinct non-catch-all DP response or independent SCCM LDAP/protocol evidence. Responses identical to the stored root HTTP status/authentication signature are suppressed as IIS catch-all behavior. `404`, `405`, `5xx`, timeouts, and rejected redirects remain inconclusive.

Positive results use `DISCOVERY-SCCM-DP-ENDPOINT`. The implementation never requests package IDs, signature files, directory listings, CAB/MSI files, manifests, payloads, content metadata below a virtual-directory root, or returned content URLs.

Normalized evidence types are `sccm_http_route`, `sccm_access_state`, `sccm_mp_protocol`, and `sccm_dp_virtual_directory`. Stable data excludes timings and never captures Date, request/correlation IDs, cookies, raw authorization, or unbounded bodies. Status, parser, access, and redirect state are material fingerprint inputs, so identical runs deduplicate while material response changes remain observable. Schema version 1 is unchanged.

## Safety boundaries

The current implementation must remain within these boundaries:

- Mock is the default provider.
- Live discovery requires explicit provider and scope.
- Only modules marked `safe` run; placeholder profiles do not override this.
- No SCCM client registration.
- No policy retrieval or secret extraction.
- No content-location request or package/content download. Content-location requests remain deferred because they can initiate on-demand distribution and alter target state.
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
- LDAP password-file reads limited to 64 KiB plus one sentinel byte, including exact-limit, oversized, empty, and cancellation cases
- Valid, generic, malformed, authentication-required, and oversized MP-list fixtures
- Passive handling of MP-list host references with no scope expansion
- Exact DP `HEAD` allowlist and positive, missing, catch-all `200`, and catch-all `401` behavior
- Same-origin, cross-host, cross-port, cross-scheme, out-of-scope, and redirect-limit policy
- Absence of authorization, cookies, request bodies, client certificates, and environment proxy traffic
- SCCM request cancellation, timeout return, request budgets, stable fingerprints, finding deduplication, and report access states
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
- SCCM route validation is restricted to standard HTTP/HTTPS ports 80/443 and five exact routes; custom SCCM ports and CMG paths are not inspected.
- DP identity remains high- or medium-confidence inference because only exact virtual-directory-root `HEAD` behavior is observed.
- The MP-list parser is conservative and may reject undocumented or customized structures.
- Authentication-required routes remain unparsed during discovery. The separate guarded validator can test only Basic or TLS client certificates on the exact observed route.
- Content-location inspection is deliberately absent because requests may cause on-demand distribution and target-state changes.
- Generic SMB, SQL, LDAP, and TCP 10123 checks are reachability-only.
- LDAP authentication is simple bind or explicit anonymous; current-process Kerberos/SASL providers are not implemented.
- Role inference cannot confirm SCCM roles from ports or hostname patterns alone.
- Service graph targets use deterministic endpoint node identifiers rather than separately persisted service assets.
- Schema migration version 2 stores authentication attempt history; pre-v2 evidence lacks run attribution and is classified as unknown until observed again.
- Attack-path correlation remains an in-memory breadth-first traversal designed around the mock graph.
- Live discovery does not currently generate real attack paths.
- There is no TUI, event-stream CLI, general credential-provider abstraction, evidence encryption, or distributed execution.
- `standard` and `aggressive` are placeholders.

## Recommended next task

Harden the guarded validator with OS-backed secret providers, explicit CA/trust-bundle configuration, and operator-supplied lockout-policy metadata. Preserve exact route selection and do not add policy, content, registration, messaging, account mutation, or broader authentication methods.

Explicitly continue to defer `ContentLocationRequest`, `CCM_System/request`, token authentication, `.sms_pol`/`.sms_dcm`, policy assignments, registration, certificate enrollment, machine identity creation, Network Access Account/task-sequence recovery, package or DP enumeration/download, PXE collection, NTLM/Kerberos authentication, relay, deployments, execution, SQL, and SMB authentication.

Suggested commit message for the completed phase:

```text
Add guarded SCCM authentication validation
```
