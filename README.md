# CinderPath

**Automated SCCM discovery, Misconfiguration Manager assessment, credential-path analysis, and attack-path validation.**

CinderPath is a Go-based security assessment platform for Microsoft Configuration Manager (SCCM/MECM) environments. It discovers SCCM infrastructure, maps roles and trust relationships, evaluates techniques from the Misconfiguration Manager framework, preserves evidence, and plans or performs explicitly authorized validation. The long-term goal is one workflow that takes an assessor from initial discovery through credential recovery, PXE and policy analysis, privilege-path validation, cleanup, and professional reporting.

```text
discover SCCM infrastructure
  -> map topology, roles, identities, and capabilities
  -> evaluate Misconfiguration Manager techniques
  -> identify credential and privilege paths
  -> perform explicitly authorized validation
  -> preserve evidence
  -> correlate downstream attack paths
  -> clean up state-changing actions
  -> generate professional reports
```

| Capability | Status |
|---|---|
| SCCM infrastructure discovery | Implemented |
| LDAP site and role enumeration | Runtime validated in GOAD |
| SMB role enumeration | Runtime validated in GOAD |
| HTTP SCCM route assessment | RECON-3 implemented and GOAD validated |
| Evidence database and JSON/HTML reports | Implemented |
| Local client policy analysis | Implemented; current NAA recovery supported on Windows SCCM clients |
| PXE/OSD posture analysis | Implemented; active deployment path not proven |
| NAA credential recovery | CRED-2/CRED-3 implemented and GOAD validated |
| Task-sequence secret recovery | CRED-1 PXE path implemented and GOAD validated |
| Execution and hierarchy takeover | Planned |

## Why CinderPath exists

SCCM assessments span directory services, site roles, client policy, content distribution, operating-system deployment, credentials, certificates, and downstream Active Directory privileges. Useful conclusions rarely come from one probe. They come from correlating bounded observations, retaining provenance, and distinguishing what was discovered from what was inferred or validated.

CinderPath is being built to make that process repeatable. It combines a simple engagement lifecycle with a framework-driven planner, reusable protocol modules, a durable evidence and relationship model, explicit approval gates, and reportable cleanup obligations.

## Misconfiguration Manager acknowledgement

CinderPath is built around the research, terminology, and technique model published by the [Misconfiguration Manager project](https://github.com/subat0mik/Misconfiguration-Manager). The upstream snapshot retains its attack-and-defense research provenance; CinderPath implements only the attack families `CRED`, `ELEVATE`, `EXEC`, `RECON`, `TAKEOVER`, and `COERCE`.

A huge amount of credit belongs to the Misconfiguration Manager maintainers and contributors for organizing SCCM attack and defense research into a clear and practical framework.

CinderPath is an independent implementation and is not affiliated with or endorsed by the upstream project. It adds automation, evidence persistence, protocol adapters, runtime support tracking, validation workflows, cleanup planning, and reporting around that model. The deterministic embedded snapshot currently represents upstream revision `394c53baf98c4eeb5ba001d195c4653216ac3141`; normal runtime never downloads the upstream catalog.

## What CinderPath can do today

### Framework-driven assessment

CinderPath embeds a deterministic upstream snapshot, while its product-visible coverage contains only `CRED`, `ELEVATE`, `EXEC`, `RECON`, `TAKEOVER`, and `COERCE`. Upstream defensive records and mappings remain provenance only and are not CinderPath capabilities. Each visible technique has independent support states for documentation, prerequisites, discovery, assessment, validation, execution, cleanup, and lab validation. A documented technique is not automatically executable.

Use `cinderpath framework coverage` to inspect the current matrix. Full support details live in the [framework roadmap](docs/MISCONFIGURATION_MANAGER_ROADMAP.md) and [implementation status](docs/STATUS.md).

### Runtime-validated reconnaissance

**RECON-1 — SCCM roles and site information via LDAP.** Authenticated RootDSE collection, `System Management` discovery, SCCM Active Directory publishing detection, site-code and management-point discovery, and evidence-backed assets and relationships have been runtime validated in GOAD. See [RECON-1](docs/TECHNIQUES/RECON-1.md).

**RECON-2 — SCCM role reconnaissance via SMB.** The bounded adapter authenticates with SMB2/3, uses only `IPC$` and `srvsvc`, performs one `NetShareEnumAll` operation, distinguishes generic shares from SCCM shares, and persists evidence. It has been runtime validated in GOAD; the validated target exposed generic administrative shares but no SCCM-specific share. See [RECON-2](docs/TECHNIQUES/RECON-2.md).

**RECON-3 — SCCM role reconnaissance via HTTP.** The bounded adapter accepts one explicit SCCM host and makes at most ten anonymous requests across a fixed HTTP/HTTPS SCCM route allowlist. It persists normalized request evidence, distinguishes transport failure from a completed run with no SCCM evidence, and permits one bounded TLS renegotiation required by the GOAD IIS endpoint. GOAD validation observed the anonymous MP list and bounded DP route responses. See [RECON-3](docs/TECHNIQUES/RECON-3.md).

**RECON-4 through RECON-7 — additional reconnaissance.** RECON-4 is live validated through the explicit Kerberos/Negotiate AdminService path with one bounded `OperatingSystem` CMPivot query against one device. RECON-5 is live validated through an explicit Kerberos/Negotiate AdminService WMI query of bounded user/device-affinity metadata. RECON-6 is live validated through authenticated SMB2/3 `IPC$` → `winreg` MS-RRP reads using a fixed read-only SCCM registry allowlist. RECON-7 has a bounded offline/local-artifact metadata foundation but is not yet a normal live assessment. Family selectors report these states individually and never claim unsupported execution.

### SCCM discovery and topology

The discovery pipeline supports explicit-scope DNS and bounded endpoint discovery, TCP connect checks, HTTP/TLS profiling, LDAP SCCM directory discovery, fixed management-point and distribution-point route checks, and passive role inference. Normalized assets, relationships, evidence, findings, credentials references, and capabilities are incrementally persisted in SQLite and rendered as machine-clean JSON or portable HTML reports.

Live is the normal provider for operator-selected discovery and technique assessment. Use `--provider mock` only for deterministic development and testing; CinderPath never silently changes an explicitly requested provider.

### Credential and policy research

Credential and policy analysis is a major in-progress capability area. The current offline-first foundation includes local SCCM policy-artifact discovery across WMI, the registry, files, and logs; schema ranking; exact NAA, task-sequence, and variable candidate targeting; bounded structural previews; HAR, PCAP, and PCAPNG ingestion; conservative TCP reassembly; XML, JSON, and multipart parsing; fixture replay; redaction; and provenance tracking.

**CinderPath has identified credential-related SCCM policy schemas, but it has not yet recovered a concrete live NAA or task-sequence credential from the current lab.** Targeted runtime discovery found zero concrete credential-policy instances and copied zero values. Details are in [local policy artifacts](docs/LOCAL_POLICY_ARTIFACTS.md), [capture ingestion](docs/CAPTURE_INGESTION.md), and [protocol research](docs/PROTOCOL_RESEARCH.md).

### PXE and OSD posture

Read-only, one-target posture work has established a PXE-enabled distribution point, installed and running WDS, unknown-computer support, boot-image file metadata, local WIM presence, and SMS Provider availability in the authorized lab. It has not proven an active PXE deployment pathway: relationship-bearing task-sequence, advertisement, collection, and boot-image schemas returned zero instances.

The intended endgame is to identify deployed task sequences, validate PXE exposure, acquire authorized boot media, inspect WIM and task-sequence content, recover protected variables or credentials, and correlate them with downstream access. Media acquisition, WIM inspection, protected-variable recovery, and active PXE validation are not implemented. See [PXE/OSD assessment](docs/PXE_OSD_ASSESSMENT.md).

## Current technique coverage

| Technique coverage | Current state |
|---|---|
| RECON-1 — Enumerate SCCM site information via LDAP | Supported and GOAD runtime validated |
| RECON-2 — Enumerate SCCM roles via SMB | Supported and GOAD runtime validated |
| RECON-3 — Enumerate SCCM roles via HTTP | Complete and GOAD runtime validated |
| RECON-4 — Query client devices via CMPivot | Complete and GOAD runtime validated; fixed single-device OperatingSystem query |
| RECON-5 — Locate users via SMS Provider | Complete; GOAD validated |
| RECON-6 — Enumerate SCCM roles via SMB Named Pipe winreg | Complete; GOAD runtime validated |
| RECON-7 — Enumerate SCCM site information via local files | Partial; offline metadata foundation only |
| CRED-1 — Retrieve secrets from PXE boot media | Complete and GOAD validated |
| CRED-2 — Network Access Account Credential Recovery | Complete and GOAD validated |
| CRED-3 — Dump Currently Deployed NAA Credentials | Complete and GOAD validated |
| Remaining framework techniques | Cataloged and mapped, but not fully implemented |

CinderPath reports support per capability dimension. It does not turn framework mappings or nearby reusable modules into broad implementation claims. See the [Misconfiguration Manager roadmap](docs/MISCONFIGURATION_MANAGER_ROADMAP.md) for the complete matrix and [current status](docs/STATUS.md) for verified results and limitations.

## Planned capabilities and endgame

### Reconnaissance and topology

Complete RECON coverage; correlate LDAP, SMB, HTTP, DNS, SCCM Provider, and client metadata; and build an evidence-backed hierarchy graph of sites, roles, identities, capabilities, and trust relationships.

### Credential paths

Discover and analyze Network Access Account policies, task-sequence secrets, collection variables, client-push credentials, distribution-point and site-database paths, and certificate material. Recovery and validation will require concrete evidence, an exact supported parser or adapter, and the applicable approval gates.

### PXE and operating-system deployment

Correlate task-sequence deployments with unknown-computer and PXE posture, support separately authorized media acquisition, inspect WIM and policy content offline, and recover protected variables only where a reviewed implementation and evidence justify it.

### Escalation and takeover

Implement selected ELEVATE, EXEC, COERCE, and TAKEOVER techniques; correlate SCCM identities with downstream Active Directory paths; validate explicitly authorized actions; track state changes; and clean them up. These capabilities are planned, not generally available today.

## How it works

1. Configuration and profiles resolve explicit scope, identity references, resource limits, and acknowledgements.
2. The technique planner compares prerequisites with retained evidence and current support dimensions.
3. Reusable modules perform only the bounded operations selected by the plan.
4. Evidence and relationships are persisted before findings and attack paths are rendered.
5. Validation, state changes, and cleanup remain separate lifecycle stages with their own gates and obligations.

## Architecture

```text
Cobra CLI
   |
Configuration and profiles
   |
Technique planner
   |
Reusable bounded modules
   |-- LDAP
   |-- SMB
   |-- HTTP/TLS
   |-- Windows artifacts
   `-- Capture and parser research
   |
Evidence and relationship model
   |
SQLite
   |
JSON / HTML / dossiers
```

Framework records describe techniques and their independent support dimensions. Adapters translate a supported technique into a bounded plan; modules provide reusable protocol or offline-analysis operations. The application layer persists normalized evidence before producing conclusions, and safety gates remain active under every profile. Developer-level package boundaries and persistence details are maintained in [docs/STATUS.md](docs/STATUS.md).

## Operating philosophy

- Truthful support claims and evidence before conclusions.
- Safe defaults, explicit authorization, and bounded protocol operations.
- Reusable modules instead of one-off exploits.
- Offline-first protocol and parser research.
- Cleanup as a first-class capability for every state-changing action.
- A simple operator CLI over a sophisticated internal model.

**YOLO does not bypass safety gates.** It means: run every currently justified and authorized capability automatically, and stop where prerequisites or approval are missing.

## Quick start

Go 1.25 or newer is required.

```bash
make build
./bin/cinderpath version
./bin/cinderpath framework coverage
./bin/cinderpath research config init
./bin/cinderpath run --config example.yaml --dry-run
```

`research config init` writes an owner-only configuration; use the path it reports in place of `example.yaml`. The repository also includes [config.example.yaml](config.example.yaml) as a safe mock configuration.

Assess one technique after configuring an explicitly authorized connector:

```bash
./bin/cinderpath assess RECON-1 --target example.local
./bin/cinderpath assess RECON-ALL --target example.local --format json
./bin/cinderpath assess CRED-ALL --target example.local --format json
```

Operators select techniques and intent; CinderPath resolves safe prerequisites
from retained compatible evidence or existing bounded modules. An authorized
one-off LDAP assessment needs no separate `discover` command or LDAP-enable flag:

```bash
export CINDERPATH_PASSWORD='example-only'
./bin/cinderpath assess RECON-1 --target SCCM.LAB \
  --domain-controller DC.SCCM.LAB \
  --username cinderpath-ldap@SCCM.LAB --password-env CINDERPATH_PASSWORD
```

If an explicit identity or other safe prerequisite is missing, the technique command returns a concise truthful `BLOCKED` result rather than requiring a manual discovery ceremony.

## Example operator workflows

Network-free planning and reporting:

```bash
./bin/cinderpath assess SCCM.LAB
./bin/cinderpath run SCCM.LAB --dry-run
./bin/cinderpath run SCCM.LAB --profile yolo --dry-run
./bin/cinderpath run --config config.example.yaml --dry-run
./bin/cinderpath discover --provider mock  # deterministic development/testing
./bin/cinderpath assess
./bin/cinderpath report
```

`assess technique RECON-1` remains a compatibility form. `assess TARGET`
creates a safe target plan and never implies live validation; a technique ID is
recognized from the embedded framework registry rather than hostname syntax.
Family selectors such as `RECON-ALL` and `CRED-ALL` are bounded orchestration
layers. Their target is an environment/root starting point; each child plan
resolves the appropriate discovered role (for example, a management point for
HTTP or a client device for CMPivot) instead of blindly inheriting that string.
They execute in deterministic registry order, report each technique's name and
state, and leave unavailable or context-incompatible techniques blocked rather
than attempting remote orchestration. A blocked prerequisite (missing identity,
topology, or local context) is distinct from an adapter that is unsupported and
from an operation that actually failed.

Before a live technique starts, CinderPath checks only the prerequisites that
technique needs. For example, CRED-1 checks the Linux/libpcap capture path and
reports a concise, actionable `BLOCKED` result when capture capability is
missing; it does not check packet capture for RECON-only commands. Interactive
terminals may offer an explicitly confirmed local `setcap` repair. Non-TTY and
JSON runs never prompt and return structured prerequisite metadata. `BLOCKED`
means a required context, identity, or local dependency is unavailable;
`FAILED` means an operation was attempted and unexpectedly failed. Local-only
techniques such as CRED-2 and CRED-3 are reported as blocked when the current
host is not an SCCM client rather than being run against a server target.
For bounded local repairs, an interactive terminal may ask for consent and
invoke `sudo` only for the specific repair (for example, granting capture
capabilities to the CinderPath binary); CinderPath itself is not run as root.
Automation and JSON/non-TTY runs never elevate or prompt. Rebuilt binaries
may need their local file capabilities granted again because the executable
state is checked each run.

Explicit-scope discovery for an authorized target:

```bash
./bin/cinderpath discover --target sccm01.example.local
```

The live provider is selected by default for operator discovery and technique
assessment; `--provider live` remains accepted for compatibility and
`--provider mock` is reserved for deterministic testing. Individual techniques
and family selectors acquire safe prerequisites directly, so a manual
`discover` or `RECON-ALL` ceremony is not required. Focused research commands,
capture workflows, and advanced diagnostics live below `research` and `debug`.

## Safety model

CinderPath is intended for authorized security assessments and controlled labs. Safe, read-only behavior is the default.

- `discover` and live technique assessment default to the live provider; mock activity requires explicit `--provider mock`.
- Exclusions and target-expansion limits are enforced before network activity.
- Protocol operations are bounded by context, concurrency, timeouts, response limits, and exact route or class allowlists.
- Reachability and naming patterns are supporting evidence, not vulnerabilities or confirmed SCCM roles.
- Secret references and bounded metadata are persisted by default; reports follow the selected output policy and are owner-only.
- Validation is separately gated. State-changing execution and cleanup are not generally implemented.
- Research signatures, candidate contracts, capture bundles, and offline parser results never authorize live execution.

The detailed current boundary is documented in [docs/STATUS.md](docs/STATUS.md) and enforced in code and tests.

## Output and secret redaction

CinderPath is designed for authorized operator use. Interactive output shows operational target values and recovered results by default, including hostnames, domains, addresses, site codes, usernames, and any secret value that an implemented workflow actually recovers. Stable IDs remain available as supplemental correlation metadata.

Use `--redact-secrets` when sharing terminal output, reports, screenshots, tickets, or transcripts with people who should not receive recovered secret material:

```bash
./bin/cinderpath assess CRED-2 --target SCCM.LAB --redact-secrets
```

The flag changes rendering, not the underlying assessment result. It replaces secret values with `<redacted>` while leaving normal operational values such as hostnames, site codes, usernames, and share names visible. Reports use the same policy, include `redaction.secrets_redacted`, and are written owner-only. Debug logs never print secret values. Offline capture and fixture sanitization remain separate conservative workflows.

Terminal scrollback, shell multiplexers, CI logs, and copied output can retain visible secrets. Protect unredacted output accordingly.

Interactive text output uses semantic color automatically. Use `--no-color` or
a non-empty `NO_COLOR` environment variable to disable ANSI styling. JSON,
HTML, SQLite, files, and non-interactive output remain ANSI-free. Redaction
occurs before rendering, so `<redacted>` never receives secret styling. The
hidden compatibility flag `--color auto|always|never` remains available for
existing scripts and transcript tests.

## Project maturity and limitations

CinderPath is early-stage software under active development. RECON-1 through
RECON-5 are supported and GOAD-runtime-validated. RECON-6 is audited but
blocked pending a safe adapter, and RECON-7 remains partial. CRED-1,
CRED-2, and CRED-3 are implemented and GOAD validated. The remaining catalog
is documentation and planning metadata.

Credential recovery, task-sequence content access, boot-media acquisition, active PXE validation, exploitation, hierarchy takeover, and automated state-changing cleanup are not currently supported. Lab validation covers specific GOAD systems and does not establish compatibility with every SCCM, Windows, PowerShell, or network configuration. Consult [docs/STATUS.md](docs/STATUS.md) before relying on a capability claim.

## Documentation

| Topic | Document |
|---|---|
| Current implementation and verified results | [docs/STATUS.md](docs/STATUS.md) |
| RECON family audit | [docs/RECON_AUDIT.md](docs/RECON_AUDIT.md) |
| Framework coverage and roadmap | [docs/MISCONFIGURATION_MANAGER_ROADMAP.md](docs/MISCONFIGURATION_MANAGER_ROADMAP.md) |
| Technique documentation | [docs/TECHNIQUES](docs/TECHNIQUES) |
| CLI design and public surface | [docs/CLI_DESIGN.md](docs/CLI_DESIGN.md) |
| Configuration | [config.example.yaml](config.example.yaml) |
| Protocol research | [docs/PROTOCOL_RESEARCH.md](docs/PROTOCOL_RESEARCH.md) |
| Capture ingestion | [docs/CAPTURE_INGESTION.md](docs/CAPTURE_INGESTION.md) |
| Windows capture workflow | [docs/WINDOWS_POLICY_CAPTURE.md](docs/WINDOWS_POLICY_CAPTURE.md) |
| Local policy artifacts | [docs/LOCAL_POLICY_ARTIFACTS.md](docs/LOCAL_POLICY_ARTIFACTS.md) |
| PXE and OSD research | [docs/PXE_OSD_ASSESSMENT.md](docs/PXE_OSD_ASSESSMENT.md) |

## Contributing

Start with [docs/STATUS.md](docs/STATUS.md), the relevant focused document, and the tests around the package you intend to change. Keep Cobra handlers thin, implement reusable behavior through bounded modules, preserve deterministic persistence and machine-clean JSON, and never promote a framework mapping or lab observation into a broader support claim.

Before submitting a change, run `make check`, the relevant focused test targets, and `make docs-check`. New protocol behavior or state-changing capabilities require a separately scoped safety design and explicit authorization model.

## License and acknowledgements

This repository does not currently include a license file. Do not assume permission to redistribute or reuse the code until the project publishes licensing terms.

CinderPath's technique model is based on the independent [Misconfiguration Manager](https://github.com/subat0mik/Misconfiguration-Manager) research project. Upstream project names, research, and source material remain the property of their respective maintainers and contributors; CinderPath-specific support claims and behavior belong to this implementation.
