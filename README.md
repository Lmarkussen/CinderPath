# CinderPath

CinderPath is an early-stage SCCM discovery, assessment, topology-mapping, and attack-path correlation platform. Its long-term goal is to maintain a normalized model of an SCCM environment, understand the capabilities available to an assessor, run applicable modules, preserve evidence, suppress duplicate noise, and prioritize attack paths.

> **CinderPath is intended for authorized security assessments and controlled lab environments. Users are responsible for ensuring they have explicit permission before assessing any system.**

## Current status

CinderPath now provides a complete passive cross-platform Windows SCCM lab capture-kit lifecycle: read-only local inventory, preparation/finalization scripts, bounded redacted Windows-log inspection, deterministic review states, guided offline import, controlled-matrix attachment, atomic redacted dossiers, and a dedicated signed capture-evidence bundle format. Capture-evidence bundles are separate from protocol-contract research bundles and require no observed contract; importing or signing one never validates live SCCM protocol behavior. CinderPath does not start capture, trigger policy retrieval, contact SCCM, or register a client. See [`docs/CAPTURE_KIT.md`](docs/CAPTURE_KIT.md).

The generated scripts have been runtime-validated on one disposable GOAD client: Windows Server 2019 Standard Evaluation 10.0.17763 (build 17763), Windows PowerShell Desktop 5.1.17763.8510, and Configuration Manager client 5.00.9128.1007. All three scripts completed under an administrator test account with process-scoped execution-policy bypass; this does not establish that administrator privileges are required or claim compatibility with other Windows releases. The isolated test used the lab's pre-existing certificate-ignoring WinRM inventory solely for that VM.

A subsequent ten-minute, manually controlled passive baseline used the already installed Windows `pktmon` 10.0.17763.3650 on one active adapter. No SCCM action was triggered. The tool recorded 212 packets with zero reported drops to ETL and converted a preserved copy to PCAPNG locally. Offline CinderPath ingestion decoded all 212 packet records but reconstructed no supported flows or HTTP exchanges; it reported opaque TLS and conservative TCP-reassembly warnings. The result is therefore `sccm_endpoint_metadata_only`, not a policy exchange or live-contract validation. Raw evidence remains outside Git and blocked from import/export pending sanitization and manual review.

A second controlled capture invoked the installed client's standard **Request & Evaluate Machine Policy** control-panel action exactly once while CinderPath only observed. During a 205-second `pktmon` window, 407 packets were recorded with zero reported drops. Two allowlisted logs correlated the action with a machine-assignment request and a no-new-assignments result. Offline parsing reconstructed one partial flow and three visible HTTP exchanges, but those exchanges were unrelated Windows trust-list downloads; SCCM traffic remained opaque and could not be structurally attributed to a policy exchange. Readiness remains `not_ready_no_policy_evidence`.

Offline `capture correlate` places fixture-supported log events, packet metadata,
flow starts, and a controlled trigger on one UTC timeline. It ranks opaque TLS
candidates using timing plus independent fingerprinted endpoint/SNI evidence,
reports contradictions and capture quality, and writes an owner-only redacted
dossier. Timing alone is always low confidence; correlation neither decrypts
TLS nor validates a policy contract.

```bash
# Synthetic local evidence only.
cinderpath capture correlate --capture synthetic.pcapng \
  --logs synthetic-logs --trigger policy-trigger.json \
  --pre-window 30s --post-window 3m --output reports/correlation
```

Applying the correlator offline to the retained controlled capture produced 908
timeline events, 431 timestamped log events, ten flows, and six opaque-TLS
candidates. One assignment request and one no-new-assignments event fell inside
the trigger window. The nearest timing match used the known WinRM control port
and was rejected; the HTTPS candidate lacked matching log endpoint evidence.
Attribution is `no_correlatable_tls_flow`, and secret readiness remains
`not_ready_no_policy_evidence`.

Offline `capture correlate-endpoints` now joins bounded captured DNS records,
TLS SNI, fingerprinted flow addresses, fixture-supported log endpoint hints,
and passive Windows client-inventory metadata. It performs no DNS lookup and
never emits raw hostnames or addresses. Endpoint confidence and flow confidence
remain separate; port 443 and timing cannot create strong attribution.

```text
Offline SCCM endpoint attribution
DNS events: 12
Endpoint candidates: 5
Evidence edges: 13
TLS flows considered: 6
Endpoint classification: medium_confidence_management_point_endpoint
Flow classification: endpoint_identified_but_flow_ambiguous
Live SCCM policy requests: 0
Safety: offline fingerprint correlation only; endpoint identity does not reveal TLS payloads.
```

This redacted output is from the retained authorized capture. Inventory and log
fingerprints identified one management-point candidate, but neither captured
DNS/address evidence nor the visible SNI connected it to a TLS flow. The result
does not establish policy framing or improve secret readiness beyond
`not_ready_no_policy_evidence`. Raw capture and logs remain outside Git.

Because encrypted packet capture has reached diminishing returns, CinderPath
also generates a bounded read-only local SCCM policy-artifact discovery script.
`lab client-artifacts discover|inspect|show|export-plan` inventories class
schemas and redacted value shapes, ranks candidates, writes an advisory export
plan, and produces an owner-only dossier. It does not invoke client methods,
copy policy bodies automatically, recover credentials, or send a live request.
See [`docs/LOCAL_POLICY_ARTIFACTS.md`](docs/LOCAL_POLICY_ARTIFACTS.md). A single
authorized Windows Server 2019 / PowerShell 5.1 run successfully inventoried 10
namespace records, 1,024 bounded class schemas, 8 instance records, 85 file
records, and 33 registry records with zero live requests. It found policy
schemas but no supported encrypted-value candidate, supporting
`ready_for_policy_schema_parser` only; no content was copied and no secret or
decryption claim was made.

Fixture-driven follow-on analysis now ranks schemas, clusters families, filters
intrinsic/provider noise, plans concrete instance inspection, and separates
preview planning from copying. The verified run selected 10 concrete records
and three XML preview candidates while copying zero content. Readiness is
`ready_for_policy_instance_parser`; encrypted-value work remains blocked.

```bash
# Synthetic authorized-lab metadata only.
cinderpath lab capture-kit create --output ~/cinderpath-lab-kit \
  --site-code ABC --client-label win11-client-a --capture-label baseline-01
cinderpath lab capture-kit validate --directory ~/cinderpath-lab-kit
cinderpath lab capture-kit inspect-logs --directory ~/cinderpath-lab-kit
cinderpath lab capture-kit bundle export --directory ~/cinderpath-lab-kit \
  --output baseline-01.capture-bundle.tar.gz
cinderpath capture guided-import --kit ~/cinderpath-lab-kit --dry-run
cinderpath matrix add-kit --matrix research-matrix.yaml --kit ~/cinderpath-lab-kit
```

The offline SCCM protocol-research subsystem now includes durable workflow
module decisions and standalone dry-run histories, bounded binary inspection,
three explicit sanitization modes, auditable body-review records, sanitized
research bundles, a complete loopback fixture-server lifecycle, passive lab
capture-plan generation, and filtered policy inventories. These facilities are
implemented for synthetic fixtures and explicitly authorized lab captures.
They do not validate a live target or approve a live protocol contract.

Optional Ed25519-signed bundles, multi-capture research sets, redacted
comparison/correlation, candidate contracts, safety reviews, expected offline
results, and contract dossiers are implemented. Signatures and candidate
contracts have no live-execution or automatic trust effect. See
[`docs/PROTOCOL_RESEARCH.md`](docs/PROTOCOL_RESEARCH.md).

The offline capture phase adds versioned HAR, classic-PCAP, bounded PCAPNG, and
normalized-JSON ingestion; redacted exchange metadata; evidence-backed sequence
graphs; controlled-matrix checks; conservative binary observations; and
deterministic parser candidates. PCAPNG section, interface, enhanced-packet,
and simple-packet blocks are decoded for Ethernet; unknown blocks and link
types remain explicit limitations. Encrypted TLS and multiplexed HTTP remain
opaque where framing evidence is unsupported. No importer or analysis
command contacts an SCCM system. See [`docs/CAPTURE_INGESTION.md`](docs/CAPTURE_INGESTION.md).

```bash
cinderpath protocol capture import --input synthetic.har
cinderpath protocol capture normalize --input synthetic.har --output normalized.json
cinderpath protocol sequence analyze --input synthetic.har
cinderpath protocol analysis replay --input normalized.json --output analysis.json
cinderpath analysis corpus replay --directory testdata/capture-corpus
```

## Recommended operator workflow

Routine assessments use a generated configuration and the unified runner:

```bash
cinderpath config init
cinderpath run --config lab_local.yaml
```

For noninteractive automation (all values below are placeholders):

```bash
export CINDERPATH_PASSWORD='example-only'
cinderpath config init --non-interactive --domain lab.local \
  --username 'LAB\alice' --password-env CINDERPATH_PASSWORD --profile aggressive

cinderpath run --domain lab.local --username 'LAB\alice' \
  --password-env CINDERPATH_PASSWORD --profile yolo --save-config
```

Generated filenames are lower-case domain names with separators normalized to
underscores (`corp.example.com` becomes `corp_example_com.yaml`). Files are
atomically written with mode `0600` and contain references only, never password
values, tickets, keys, hashes, or tokens. Use `config validate FILE`, `config
show FILE --format yaml|json`, and `run --config FILE --dry-run` to review the
effective plan without network activity or authentication-budget consumption.

Profiles are explicit defaults: `safe` never authenticates; `standard` permits
guarded authentication only with all existing gates; `aggressive` requests
deeper read-only coverage; and `yolo` is the fully automated authorized-assessment
profile. The latter two list unavailable future modules as `not implemented`.
Secret-recovery, policy/content retrieval, registration, messaging, relay,
state changes, and remote execution remain unimplemented. Granular commands
remain supported for troubleshooting and expert control.

This release provides the original mock pipeline plus an **explicit, safe, read-only live discovery provider**. Live mode normalizes user scope, performs DNS queries, attempts bounded TCP connections, collects bounded HTTP/TLS metadata, optionally performs bounded LDAP RootDSE and SCCM directory searches, validates a fixed allowlist of SCCM management-point and distribution-point HTTP routes, and passively correlates stored topology evidence. It does not register clients, retrieve policy, recover credentials, request content locations, download packages, authenticate to SCCM/SMB/SQL, enumerate shares or DP content, execute code, relay authentication, create deployments, or modify a target.

`discover` defaults to `--provider mock`. CinderPath never silently changes to live mode or contacts network systems without `--provider live`.

The `safe` profile remains the default. Unified planning also understands `standard`, `aggressive`, and `yolo`; hard safety gates continue to apply regardless of profile.

## Identity and authentication-capability modeling

CinderPath can normalize locally available identity references and correlate them with already-collected SCCM authentication challenges. This phase is passive with respect to targets: it sends no credentials or authorization headers and performs no NTLM, Negotiate, Kerberos, Basic, Digest, or client-certificate authentication.

```bash
export CINDERPATH_PASSWORD='placeholder-only'
cinderpath identity inspect --identity-kind username_password_reference \
  --identity-domain LAB --identity-user alice --password-env CINDERPATH_PASSWORD
cinderpath identity list
cinderpath capabilities
```

Supported kinds are `anonymous`, `domain_user`, `machine_account`, `current_process`, `username_password_reference`, `ntlm_hash_reference`, `kerberos_cache_reference`, `certificate_reference`, `sccm_client_identity_reference`, and `unknown`. IDs describe the logical identity and do not depend on secret values or reference locations.

Passwords and hashes are accepted only through environment or bounded-file references. Kerberos caches and private keys are checked for local existence only; ticket and private-key contents are not parsed. Persisted and reported file references contain only the basename. Public PEM and DER certificates are bounded and parsed for subject, issuer, validity, names, usages, algorithms, SHA-256 fingerprint, and client-auth EKU. PFX/PKCS#12 and certificate stores are unsupported.

Endpoint challenges are normalized as `anonymous`, `negotiate`, `ntlm`, `kerberos`, `basic`, `digest`, `client_certificate`, or `unknown`. An advertised scheme is not proof it can be used. Capability states are `available`, `unavailable`, `unknown`, `requires_validation`, and `blocked_by_safety`; “potentially available” always means future applicability, never successful authentication. Reports explicitly state whether guarded authentication validation was performed.

Passive staleness uses stored timestamps and run attribution. The latest completed discovery run is distinguished from report and authentication runs. Missing observations require current explicit scope and a successfully completed relevant stage; skipped, failed, cancelled, pre-provenance, and out-of-scope records remain uncertain. Asset, evidence, and certificate-warning thresholds are configured under `staleness`; stale inputs downgrade planned capabilities to `requires_validation` and do not create vulnerabilities.

## Guarded authentication validation

Authentication validation is disabled by default and exists only under `auth validate`. It never runs from `discover`, `assess`, or `report`.

```bash
cinderpath auth validate --dry-run \
  --identity-id cred_placeholder \
  --endpoint https://sccm01.lab.example \
  --authentication-method basic

cinderpath auth validate \
  --enable-auth-validation \
  --acknowledge-lockout-risk \
  --identity-id cred_placeholder \
  --endpoint https://sccm01.lab.example \
  --authentication-method basic
```

> **Authentication validation may cause account lockout or security alerts. Use only with explicit authorization and carefully selected identities.**

Only Basic and TLS client-certificate validation are supported. Basic requires an existing password reference, an exact previously observed Basic challenge, and HTTPS unless `--allow-basic-over-http` is explicitly supplied. TLS client authentication requires bounded PEM certificate/key files, a locally verified pair, current validity, client-auth EKU, and a previously observed client-certificate request. Redirects, retries, proxies, cookies, request bodies, arbitrary paths, ambient credentials, Kerberos, NTLM, Negotiate, PFX/P12, and encrypted keys are unsupported.

Actual attempts additionally require `--enable-auth-validation` and `--acknowledge-lockout-risk`. Plans with more than one request require `--acknowledge-multiple-attempts`. Defaults allow three total historical attempts and one per identity, endpoint, and identity/endpoint tuple, with sequential execution and a two-second minimum delay. `--dry-run` reads no secret and sends no network traffic. `auth results` shows durable history without authorization material.

## Fixture-driven SCCM policy research

Live SCCM policy requests remain blocked because no approved request contract is
present. CinderPath does not invent `CCM_POST` bodies, client identifiers, or
registration state. It can import synthetic or sanitized captures, analyze
observed fields, replay them only against loopback fixture servers, and parse
policy XML offline.

```bash
# All paths and values are synthetic examples for authorized research.
cinderpath lab capture-plan --output capture-plan
cinderpath protocol inspect-binary captures/raw-example/request.body
cinderpath protocol sanitize --input captures/raw-example --output captures/sanitized-example --binary-mode metadata_only
cinderpath protocol review-sanitization --directory captures/sanitized-example \
  --approve-body request.body --approve-body response.body --reviewer-reference LAB_REVIEW_001
cinderpath protocol import --directory testdata/policy-captures/example01
cinderpath protocol analyze --directory testdata/policy-captures/example01
cinderpath protocol replay contract_placeholder --directory testdata/policy-captures/example01 --endpoint http://127.0.0.1:8080
cinderpath policy secrets --directory testdata/policy-captures/example01 --show-secrets --secrets-output reports/fixture/secrets.txt
```

Contract states are `unknown`, `fixture_only`, `captured_unverified`,
`verified_local_replay`, `candidate_contract`, `approved_live`, and `rejected`. Normal commands cannot
create `approved_live`; current contracts are local-replay-only. Existing SCCM
client metadata may be imported with `client-identity import --metadata FILE`,
but this neither registers nor validates a client.

Confirmed fixture plaintext is held only in memory until the dedicated output
component displays it or atomically writes a mode-`0600` text/JSON file. Safe
never displays it, standard requires `--show-secrets`, aggressive/yolo use TTY
defaults, `--hide-secrets` wins, and non-TTY output is hidden unless explicitly
enabled. Ordinary reports, logs, progress, and contract metadata receive no
plaintext. Protected values are identified but not decrypted; offline
credentials are always labeled unvalidated.

Schema v4 persists redacted contract, fixture, assignment, policy-document,
candidate, and workflow-stage intelligence. HTML and JSON reports include a
dedicated offline policy section and safety banner; raw bodies and plaintext are
excluded. Binary inspection reports observed encodings/magic separately from
heuristic length candidates:

```bash
# Synthetic/authorized-lab examples only.
cinderpath protocol inspect-binary captures/raw-example/request.body
cinderpath protocol serve-fixtures --directory testdata/policy-captures/example01 --listen 127.0.0.1:0 --strict
```

`inspect-binary` emits deterministic bounded observations for ASCII, UTF-8,
UTF-16LE/BE, BOMs, XML, URLs/routes, UNC paths, hostname-like strings,
GUID/SID-like values, MIME/multipart, compression/archive magic, padding,
repeated blocks, entropy, and candidate lengths. Heuristics are labeled as
such and never asserted to be protocol fields or SCCM roles.

Sanitization defaults to `metadata_only`, which leaves opaque bodies unchanged
and requires review. `text_regions` permits only operator-supplied,
length-preserving replacements while preserving offsets and encoding.
`structured_known` touches only positively identified supported structures and
flags unsupported regions. Mode-`0600` replacement maps are never copied into
fixtures or bundles. Review records attest to inspection; they do not sanitize
bytes, override leakage detection, or promote contracts.

```bash
# Synthetic or explicitly authorized-lab examples only.
cinderpath protocol bundle export --contract CONTRACT_ID \
  --directory captures/sanitized-example --output sanitized-policy-bundle.tar.gz
cinderpath protocol bundle inspect --input sanitized-policy-bundle.tar.gz
cinderpath protocol bundle import --input sanitized-policy-bundle.tar.gz
cinderpath policy fixtures --format table
cinderpath policy assignments --run-id RUN_ID --format json
cinderpath policy documents --fixture-id FIXTURE_ID
cinderpath policy candidates --policy-id POLICY_ID
cinderpath runs list --dry-run
cinderpath runs show RUN_ID
```

Bundle export requires explicit fixture directories and completed review where
needed. Import validates paths, regular-file members, counts, sizes, totals, and
SHA-256 fingerprints before atomic extraction. Imported trust remains
fixture-only/captured-unverified and can never become `approved_live`. Bundles
are fingerprinted and may optionally be Ed25519-signed without changing trust.

Dry-runs persist configuration/profile summaries, scope estimates, stages, and
all module decisions while creating no target observations, authentication
attempts, fixture body reads, secret output, or network activity.

See [`docs/WINDOWS_POLICY_CAPTURE.md`](docs/WINDOWS_POLICY_CAPTURE.md) before
preparing lab material. Raw captures must remain encrypted, access-controlled,
and outside source control. Local replay is not live SCCM validation.

## Architecture

```text
Cobra CLI
   │
   ├── configuration (flags > CINDERPATH_* environment > YAML > defaults)
   ├── application services (run lifecycle and context timeouts)
   │      │
   │      ├── module orchestrator ── mock pipeline + explicit safe live discovery
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
| `internal/discovery/live` | Explicit-scope DNS, TCP, HTTP/TLS, LDAP, SCCM route validation, and role-inference modules |
| `internal/discovery`, `internal/assessment` | Module selection by workflow |
| `internal/scope` | Target parsing, CIDR expansion, normalization, and exclusions |
| `internal/progress` | Transport-neutral progress events and collectors |
| `internal/capabilities` | Capability helpers |
| `internal/report` | JSON model and self-contained HTML renderer |
| `internal/logging`, `internal/version` | Structured logging and build metadata |

## Build and run

Requirements: Go 1.25 or newer. SQLite is provided by a pure-Go driver; a system SQLite library and CGO are not required.

```bash
make build
./bin/cinderpath version
./bin/cinderpath discover
./bin/cinderpath assess
./bin/cinderpath report
```

The Makefile keeps output project-local at `bin/cinderpath`. `make help` lists
the supported targets and safety properties. Focused offline targets include
`protocol-test`, `protocol-report-test`, `protocol-bundle-test`,
`policy-offline-test`, `fuzz-policy`, `fuzz-protocol`, and `docs-check`.
No target performs live SCCM policy traffic or live authentication.

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
6. **SCCM HTTP route validation:** only already-profiled HTTP/HTTPS origins on ports 80/443 receive the fixed anonymous allowlist below. The route collector performs the network requests; separate MP and DP modules classify stored evidence without more traffic.
7. **Role inference:** combines protocol validation, LDAP references, SCCM route correlation, user hints, generic HTTP metadata, ports, and hostname patterns in that precedence order. Hostname-only conclusions remain low confidence.
8. **Passive topology correlation:** reads persisted DNS, LDAP, TLS, role-hint, MP-list, and validated-route evidence without sending requests.

### Passive SCCM topology correlation

Exact normalized FQDNs, unique short-name matches, explicit DNS answers, IP identities, and certificate aliases support correlation. A named asset and an IP-only asset receive `same_logical_host` only when an explicit DNS answer uniquely joins that pair. Multiple names sharing an address remain distinct and receive conflict annotations. LDAP and MP-list references never expand scope.

Reports show canonical identity, aliases, addresses, roles and confidence, site codes, protocol validation, LDAP/TLS/MP-list references, conflicts, unresolved references, and version evidence. Conflicts are evidence or informational findings—not vulnerabilities—and explain sources, values, confidence, relevance, and what remains unverified. Product versions require reliable protocol-specific fields; IIS/Windows headers, generic HTTP metadata, certificate dates, and hostname patterns are excluded. Without reliable evidence, reports state `SCCM version: unknown`.

### Read-only SCCM HTTP validation

The live pipeline includes:

```text
live.sccm.http_routes
live.sccm.management_point
live.sccm.distribution_point
```

They run after optional LDAP discovery and before `live.roles.infer`. If no successful root HTTP profile exists on a scoped port 80/443 origin, all three record an applicability skip. Only `live.sccm.http_routes` sends requests. Per origin the exact allowlist is:

```text
GET  /SMS_MP/.sms_aut?MPLIST
HEAD /SMS_DP_SMSPKG$/
HEAD /SMS_DP_SMSSIG$/
HEAD /NOCERT_SMS_DP_SMSPKG$/
HEAD /NOCERT_SMS_DP_SMSSIG$/
```

The collector makes at most five initial route probes per origin, uses at most HTTP and HTTPS per host, has no retries, probes routes sequentially per host, and reuses bounded host concurrency and timeouts. Its dedicated transport disables environment proxies, cookies, client certificates, and keep-alive reuse. Requests never contain bodies, authorization, ambient Windows credentials, NTLM/Negotiate authentication attempts, or state-changing, WebDAV, BITS, SCCM messaging, package, policy, content-location, or arbitrary-directory operations.

Redirects are limited to the lower of the configured limit and two and must preserve scheme, hostname, and port and remain in explicit scope. Cross-host, cross-port, cross-scheme, and out-of-scope redirects are rejected; redirect destinations never expand scope.

Every route independently records:

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

This phase always records an anonymous request with `authentication_attempted=false` and `authenticated=false`. `401` means authentication was requested; `403` means access was denied. Neither status proves authentication. Usable MP read access and protocol validation require a bounded successful parse of a meaningful SCCM MP-list XML structure. Generic HTML, generic/malformed XML, empty or oversized responses, route existence, and generic `200/401/403` responses do not validate an MP. MP-list host references and site codes are normalized as evidence only and are never contacted or added to scope.

An exact DP virtual-directory root returning a distinct `2xx` response is strong, high-confidence route evidence, not absolute confirmation. `401/403` requires a second distinct non-catch-all DP route or independent SCCM LDAP/protocol evidence. Responses matching the existing root status/authentication profile are treated as generic IIS catch-all behavior. `404`, `405`, `5xx`, timeout, and rejected redirect results remain inconclusive. DP probes never read bodies or request package IDs, signature files, directory listings, CAB/MSI files, manifests, payloads, or content below the four virtual-directory roots.

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

The recommended next phase is authentication-provider hardening: OS-backed secret references, operator-supplied lockout-policy metadata, and stronger certificate trust configuration without adding routes or methods. Policy retrieval, registration, account creation, certificate enrollment, content access, SCCM messaging, relay, SQL/SMB authentication, execution, and all state-changing operations remain deferred.

## Known limitations

* Live policy collection, SCCM registration, client identity generation,
  protected-secret decryption, content requests/download, and state-changing
  operations remain blocked or unimplemented.
* Binary inspection and sanitizer classifications are conservative research
  aids; unknown binary structures still require manual lab review.
* Research signatures provide integrity and key provenance, not capture
  authenticity, sanitization completeness, safety approval, or live support.

* Live discovery only accepts explicit targets; it does not perform broad AD/DNS enumeration automatically.
* SMB, SQL, LDAP probe ports, and TCP 10123 are reachability-only unless the explicit LDAP modules are enabled.
* LDAP currently uses simple bind, explicit anonymous bind, LDAPS, or STARTTLS; current-process Kerberos/SASL providers are future work.
* Role inference is intentionally conservative and cannot confirm an SCCM role from ports or hostnames alone.
* `standard` and `aggressive` do not enable additional behavior.
* SQLite schema version 4 includes durable authentication history plus offline
  protocol/policy, sanitization, workflow, signing, research-set, comparison,
  candidate-contract, dossier, review, and expected-result records;
  passive model records remain JSON-backed and preserve schema-v1 fingerprints.
* Correlation is in-memory and cannot independently resolve stale, load-balanced, or reassigned identities.
* SCCM HTTP validation is limited to standard ports 80/443 and the five exact routes above; custom ports, CMG paths, policy endpoints, package/content paths, and authenticated behavior are not tested.
* A DP conclusion remains a high- or medium-confidence inference because this phase uses only virtual-directory-root `HEAD` responses.
* MP-list parsing is intentionally conservative and may reject undocumented or vendor-modified response structures. Current evidence normally leaves SCCM version unknown.
* There is no TUI, general credential-provider abstraction, evidence encryption, or distributed execution.

Targeted credential-policy discovery now recognizes NAA, task-sequence, network-folder, domain-join, protected-variable, legacy-package, and OSD account schemas through class/property combinations and policy provenance. Names alone never establish a secret. The validated run selected 18 exact classes but observed no concrete credential-policy instances and copied no values. See [the focused guide](docs/CREDENTIAL_POLICY_DISCOVERY.md).

PXE/OSD posture assessment now identifies one exact SCCM server candidate before access and performs bounded server-local service, feature, registry, log-metadata, and boot-image-metadata checks. The validated GOAD server used WDS, had PXE and unknown-computer support enabled, and exposed three server-local boot-image metadata records; PXE password and task-sequence deployment posture remained unknown. No PXE, DHCP, TFTP, boot-media, WIM, or content request occurred. See [PXE and OSD posture assessment](docs/PXE_OSD_ASSESSMENT.md).

Reviewed exact-allowlist previews now summarize two authority `Capabilities`
properties and one deployment `MessageDetails` property. All were well-formed
XML and structure-only fixtures were sufficient; no raw value was copied and
readiness did not advance. Broader planning is exposed truthfully through
`framework coverage --framework misconfiguration-manager`; see
[`docs/MISCONFIGURATION_MANAGER_ROADMAP.md`](docs/MISCONFIGURATION_MANAGER_ROADMAP.md).
