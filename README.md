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
| HTTP SCCM route assessment | Implemented; partial GOAD validation |
| Evidence database and JSON/HTML reports | Implemented |
| Local client policy analysis | Implemented; secret recovery pending |
| PXE/OSD posture analysis | Implemented; active deployment path not proven |
| NAA credential recovery | Research foundation present; recovery not implemented |
| Task-sequence secret recovery | Research foundation present; recovery not implemented |
| Execution and hierarchy takeover | Planned |
| Defensive framework assessment | Mapped; assessment support is partial |

## Why CinderPath exists

SCCM assessments span directory services, site roles, client policy, content distribution, operating-system deployment, credentials, certificates, and downstream Active Directory privileges. Useful conclusions rarely come from one probe. They come from correlating bounded observations, retaining provenance, and distinguishing what was discovered from what was inferred or validated.

CinderPath is being built to make that process repeatable. It combines a simple engagement lifecycle with a framework-driven planner, reusable protocol modules, a durable evidence and relationship model, explicit approval gates, and reportable cleanup obligations.

## Misconfiguration Manager acknowledgement

CinderPath is built around the research, terminology, and technique model published by the [Misconfiguration Manager project](https://github.com/subat0mik/Misconfiguration-Manager). Misconfiguration Manager provides the foundational SCCM attack-and-defense research model used for CinderPath's technique families, prerequisites, and defensive mappings.

A huge amount of credit belongs to the Misconfiguration Manager maintainers and contributors for organizing SCCM attack and defense research into a clear and practical framework.

CinderPath is an independent implementation and is not affiliated with or endorsed by the upstream project. It adds automation, evidence persistence, protocol adapters, runtime support tracking, validation workflows, cleanup planning, and reporting around that model. The deterministic embedded snapshot currently represents upstream revision `394c53baf98c4eeb5ba001d195c4653216ac3141`; normal runtime never downloads the upstream catalog.

## What CinderPath can do today

### Framework-driven assessment

CinderPath embeds a deterministic snapshot containing 67 techniques: 34 attack techniques, 33 defensive techniques, and 130 attack-defense mappings. Each technique has independent support states for documentation, prerequisites, discovery, assessment, validation, execution, cleanup, defense assessment, and lab validation. A documented or mapped technique is not automatically executable.

Use `cinderpath framework coverage` to inspect the current matrix. Full support details live in the [framework roadmap](docs/MISCONFIGURATION_MANAGER_ROADMAP.md) and [implementation status](docs/STATUS.md).

### Runtime-validated reconnaissance

**RECON-1 — SCCM roles and site information via LDAP.** Authenticated RootDSE collection, `System Management` discovery, SCCM Active Directory publishing detection, site-code and management-point discovery, evidence-backed assets and relationships, and defensive mappings have been runtime validated in GOAD. See [RECON-1](docs/TECHNIQUES/RECON-1.md).

**RECON-2 — SCCM role reconnaissance via SMB.** The bounded adapter authenticates with SMB2/3, uses only `IPC$` and `srvsvc`, performs one `NetShareEnumAll` operation, distinguishes generic shares from SCCM shares, and persists evidence. It has been runtime validated in GOAD; the validated target exposed generic administrative shares but no SCCM-specific share. See [RECON-2](docs/TECHNIQUES/RECON-2.md).

**RECON-3 — SCCM role reconnaissance via HTTP.** The implemented adapter accepts one explicit SCCM host and makes at most ten anonymous requests across a fixed HTTP/HTTPS SCCM route allowlist. It persists request evidence and distinguishes transport failure from a completed run with no SCCM evidence. GOAD collection reached the selected target, but ports 80 and 443 refused connections, so RECON-3 remains only partially runtime validated. See [RECON-3](docs/TECHNIQUES/RECON-3.md).

### SCCM discovery and topology

The discovery pipeline supports explicit-scope DNS and bounded endpoint discovery, TCP connect checks, HTTP/TLS profiling, LDAP SCCM directory discovery, fixed management-point and distribution-point route checks, and passive role inference. Normalized assets, relationships, evidence, findings, credentials references, and capabilities are incrementally persisted in SQLite and rendered as machine-clean JSON or portable HTML reports.

The default discovery provider is `mock`. Network discovery occurs only when an operator explicitly selects the live provider and supplies scope.

### Credential and policy research

Credential and policy analysis is a major in-progress capability area. The current offline-first foundation includes local SCCM policy-artifact discovery across WMI, the registry, files, and logs; schema ranking; exact NAA, task-sequence, and variable candidate targeting; bounded structural previews; HAR, PCAP, and PCAPNG ingestion; conservative TCP reassembly; XML, JSON, and multipart parsing; fixture replay; redaction; and provenance tracking.

**CinderPath has identified credential-related SCCM policy schemas, but it has not yet recovered a concrete live NAA or task-sequence credential from the current lab.** Targeted runtime discovery found zero concrete credential-policy instances and copied zero values. Details are in [local policy artifacts](docs/LOCAL_POLICY_ARTIFACTS.md), [capture ingestion](docs/CAPTURE_INGESTION.md), and [protocol research](docs/PROTOCOL_RESEARCH.md).

### PXE and OSD posture

Read-only, one-target posture work has established a PXE-enabled distribution point, installed and running WDS, unknown-computer support, boot-image file metadata, local WIM presence, and SMS Provider availability in the authorized lab. It has not proven an active PXE deployment pathway: relationship-bearing task-sequence, advertisement, collection, and boot-image schemas returned zero instances.

The intended endgame is to identify deployed task sequences, validate PXE exposure, acquire authorized boot media, inspect WIM and task-sequence content, recover protected variables or credentials, and correlate them with downstream access. Media acquisition, WIM inspection, protected-variable recovery, and active PXE validation are not implemented. See [PXE/OSD assessment](docs/PXE_OSD_ASSESSMENT.md).

## Current technique coverage

| Technique coverage | Current state |
|---|---|
| RECON-1 | Supported and GOAD runtime validated |
| RECON-2 | Supported and GOAD runtime validated |
| RECON-3 | Implemented; partial GOAD runtime validation |
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

### Defense

Assess PREVENT, DETECT, and CANARY controls, compare offensive evidence with defensive coverage, and produce prioritized remediation reports. Defensive mappings exist today; broad automated defense assessment does not.

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
./bin/cinderpath config init
./bin/cinderpath run --config example.yaml --dry-run
```

`config init` writes an owner-only configuration; use the path it reports in place of `example.yaml`. The repository also includes [config.example.yaml](config.example.yaml) as a safe mock configuration.

Assess one technique after configuring an explicitly authorized connector:

```bash
./bin/cinderpath assess technique RECON-1 --target example.local
```

Without a configured live connector, the technique command returns a truthful plan and performs no network activity.

## Example operator workflows

Network-free planning and reporting:

```bash
./bin/cinderpath run --config config.example.yaml --dry-run
./bin/cinderpath discover --provider mock
./bin/cinderpath assess
./bin/cinderpath report
```

Explicit-scope discovery for an authorized target:

```bash
./bin/cinderpath discover --provider live --target sccm01.example.local
```

The live provider is never selected implicitly. Focused research commands, capture workflows, and advanced diagnostics live below `research` and `debug`; see the documentation index instead of treating those primitives as the primary product interface.

## Safety model

CinderPath is intended for authorized security assessments and controlled labs. Safe, read-only behavior is the default.

- `discover` defaults to `--provider mock`; live activity requires an explicit provider and scope.
- Exclusions and target-expansion limits are enforced before network activity.
- Protocol operations are bounded by context, concurrency, timeouts, response limits, and exact route or class allowlists.
- Reachability and naming patterns are supporting evidence, not vulnerabilities or confirmed SCCM roles.
- Secret references, not secret values, are persisted; ordinary reports remain redacted.
- Validation is separately gated. State-changing execution and cleanup are not generally implemented.
- Research signatures, candidate contracts, capture bundles, and offline parser results never authorize live execution.

The detailed current boundary is documented in [docs/STATUS.md](docs/STATUS.md) and enforced in code and tests.

## Project maturity and limitations

CinderPath is early-stage software under active development. RECON-1 and RECON-2 are the only fully supported, GOAD-runtime-validated framework techniques; RECON-3 has partial runtime validation. Most of the 67-technique catalog remains documentation and planning metadata.

Credential recovery, task-sequence content access, boot-media acquisition, active PXE validation, broad defensive assessment, exploitation, hierarchy takeover, and automated state-changing cleanup are not currently supported. Lab validation covers specific GOAD systems and does not establish compatibility with every SCCM, Windows, PowerShell, or network configuration. Consult [docs/STATUS.md](docs/STATUS.md) before relying on a capability claim.

## Documentation

| Topic | Document |
|---|---|
| Current implementation and verified results | [docs/STATUS.md](docs/STATUS.md) |
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
