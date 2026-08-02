# Passive Windows SCCM lab capture kit

The capture kit is an offline preparation and import workflow for an explicitly authorized disposable Windows lab with an already configured SCCM client. It generates instructions, passive inventory scripts, local evidence directories, review forms, and Linux wrappers. It does **not** register a client, change identity, trigger policy retrieval, contact a management point, start packet capture, install tools, weaken TLS, upload data, or approve live execution.

## Verified Windows runtime

On 2026-08-02, a generated kit was tested on one disposable GOAD MECM client running Windows Server 2019 Standard Evaluation 10.0.17763 (build 17763), Windows PowerShell Desktop 5.1.17763.8510, and Configuration Manager client 5.00.9128.1007. The execution account was an administrator and each script used process-scoped `-ExecutionPolicy Bypass`; the test does not establish that administrator privileges are required.

`Collect-CinderPathInventory.ps1` produced valid schema-v1 client and tool JSON. `Prepare-CinderPathCapture.ps1` created `raw/capture`, `raw/capture-started-at.txt`, and the synthetic leakage sentinel without starting capture. `Finalize-CinderPathCapture.ps1`, with both optional flags omitted, produced valid `raw/local-raw-manifest.json`, copied no client logs, created no archive, and retained `raw_sensitive: true` and `safe_for_sharing: false`. Bounded pre/post checks found no changes to the SCCM service/start mode, client version, site assignment, fingerprinted identity candidates, execution-policy scopes, firewall profiles, certificate-store counts/fingerprints, scheduled-task count, installed-software count, or known capture-process set. No script-created network activity was observed by these bounded checks; they are not an exhaustive network trace.

The remote test harness used the isolated GOAD lab inventory's existing self-signed WinRM HTTPS exception for only that authorized VM. CinderPath did not create, modify, or generalize that exception. Runtime coverage is limited to this exact environment; other Windows and PowerShell versions remain unverified.

The same client was subsequently observed for exactly ten minutes without triggering policy retrieval or creating artificial traffic. The existing `pktmon` 10.0.17763.3650 captured one active adapter with a 64 MiB circular limit and full packet snapshots. It reported 212 packets and no drops, preserved a 50,331,648-byte ETL, and locally converted it to a 192,444-byte PCAPNG. Offline CinderPath parsing decoded 212 packet records but reconstructed no supported flows or visible HTTP exchanges; opaque-TLS and incomplete/conflicting TCP-reassembly warnings remained. The capture is classified as `sccm_endpoint_metadata_only`, not a policy exchange. Its sentinel, raw ETL, and PCAPNG remain sensitive, unreviewed, outside Git, and ineligible for guided import or evidence-bundle export.

Generated `raw/capture-started-at.txt` and `raw/local-raw-manifest.json` are lifecycle evidence. Validation treats them as preparation and finalization markers, respectively, so a returned finalized kit with blank operator timestamp fields is still `requires_sanitization` rather than `ready_for_capture`.

## Controlled machine-policy observation

On the same verified client, the installed Configuration Manager control-panel interface enumerated a combined `Request & Evaluate Machine Policy` action. An authorized lab harness invoked that existing local action exactly once while CinderPath remained observational; it did not construct, authenticate, or send an SCCM request. A 205-second `pktmon` session recorded 407 packets with no reported drops and preserved ETL plus PCAPNG. Only changed allowlisted `CcmMessaging.log` and `PolicyAgent.log` snapshots were copied. The logs confirm a machine-assignment request and no new assignments, but CinderPath could not structurally associate opaque TLS with a policy exchange. Three visible HTTP exchanges were unrelated operating-system trust-list downloads.

Representative redacted output was:

```text
Capture kit state: requires_sanitization
Raw files: 7
Blocking conditions:
  raw evidence is sensitive and sanitized evidence is absent

Capture: capture_<REDACTED>
Format: pcapng
Exchanges: 3
Sequence: fully_ordered
Live SCCM execution: blocked
```

The sentinel, identifiers in copied logs, opaque binary regions, and incomplete TCP reconstruction require sanitization and manual review. Raw captures and logs remain outside Git. This evidence is `machine_policy_trigger_observed_logs_only` and secret-extraction readiness is `not_ready_no_policy_evidence`.

An already returned authorized capture and log set can be correlated in a
separate offline workspace:

```bash
cinderpath capture correlate --capture synthetic.pcapng --logs synthetic-logs \
  --trigger trigger.json --output reports/correlation
```

The correlation dossier is atomic mode `0700`; its files are mode `0600` and
contain redacted summaries and endpoint fingerprints only. This operation does
not change kit review, sanitization, guided-import, or bundle-export gates.

The retained kit was correlated offline without contacting Windows. Its 407
packets yielded ten flows and six opaque-TLS candidates, but known WinRM control
traffic contradicted the closest timing match and no independent endpoint match
supported the HTTPS candidate. The result is `no_correlatable_tls_flow`; raw-kit
review and sanitization blockers remain unchanged.

All names below are synthetic authorized-lab examples:

```bash
cinderpath lab capture-kit create \
  --output ~/cinderpath-lab-kit \
  --site-code ABC \
  --management-point mp01.lab.local \
  --client-label win11-client-a \
  --capture-label baseline-01
```

Site and management-point values are operator metadata only; CinderPath does not resolve or contact them. Creation is atomic, refuses overwrite unless `--force`, and creates owner-only directories and files. Copy the kit using the operator's separately authorized transfer procedure, then read its safety and checklist files.

```powershell
.\windows\Collect-CinderPathInventory.ps1
.\windows\Prepare-CinderPathCapture.ps1
```

Inventory reads bounded local OS, service, SCCM class-availability, log, certificate-metadata, adapter, proxy, executable-presence, and event-channel metadata. SCCM namespaces/classes vary by client version and environment. It records errors and never reads or exports a private key. Preparation only makes local directories, timestamps the session, creates a synthetic leakage sentinel, and prints instructions.

The operator separately starts and stops an approved capture tool. A normal policy retrieval must occur naturally or through a separately approved lab procedure. The kit contains no policy-trigger command.

```powershell
.\windows\Finalize-CinderPathCapture.ps1
```

Finalization inventories bounded raw files and SHA-256 hashes locally. Client-log copy and a clearly named raw-sensitive local archive are opt-in through `-IncludeClientLogs` and `-CreateArchive`; both default false. Raw inputs are not modified, deleted, sanitized, uploaded, or declared safe.

## Tool-neutral evidence

| Category | Level/format | TLS visibility | Import and limitation |
|---|---|---|---|
| Wireshark/dumpcap | Packet PCAP/PCAPNG | Normally opaque | Direct offline import; plaintext is not promised |
| pktmon | Packet/event ETL | Normally opaque | ETL inventory only; approved conversion/review required |
| netsh trace | Event/packet-like ETL | Normally opaque | ETL inventory only; not direct HTTP-body evidence |
| EDR/sensor | Vendor dependent | Vendor dependent | Review/convert if a supported format results |
| Browser/proxy HAR | HTTP-level HAR | May expose secrets | Import only after sanitization and review |

No generated command installs/runs tools, configures interception, installs a root certificate, or disables certificate validation.

## Linux review and import

Transfer raw evidence back only through an authorized channel. Optional `linux/*.sh` wrappers invoke the compiled CLI and do not duplicate parser logic. Direct equivalents are:

```bash
cinderpath lab capture-kit validate --directory ~/cinderpath-lab-kit
cinderpath protocol inspect-binary ~/cinderpath-lab-kit/raw/example.body
cinderpath protocol sanitize --input raw-fixture --output sanitized-fixture \
  --replacement-map replacement-map.yaml
cinderpath capture guided-import --kit ~/cinderpath-lab-kit \
  --dossier-output reports/baseline-01
cinderpath matrix add-kit --matrix research-matrix.yaml \
  --kit ~/cinderpath-lab-kit
```

Replacement maps must be mode `0600` and never enter command history or export directories. Complete identifier, binary, and leakage reviews manually and update `metadata/capture.template.yaml`. The deterministic states are `created`, `ready_for_capture`, `capture_in_progress`, `raw_capture_complete`, `requires_sanitization`, `requires_manual_review`, `review_failed`, `ready_for_import`, `imported`, `ready_for_evidence_bundle`, `evidence_bundle_exported`, and `invalid`. `validate` and `show` explain blockers and allowed next actions. Raw finalization never makes evidence exportable; import does not imply export approval; review cannot override a hash, sentinel, or leakage failure.

Guided import accepts supported files under `sanitized/` from either a local kit or a dedicated capture-evidence bundle, runs existing bounded offline parsing, leaves its source unchanged, persists redacted attribution, and may create an atomic dossier. `--kit` and `--bundle` are mutually exclusive. Dry-run performs validation and planning without persistence or secret output.

## Bounded Windows-log inspection

```bash
# Synthetic or explicitly authorized-lab example.
cinderpath lab capture-kit inspect-logs --directory ~/cinderpath-lab-kit
```

The generic inspector reads only `.log` files already under `raw/` or `sanitized/`. It bounds file count, bytes per file, total bytes, lines, line length, and observations; rejects symlinks; recognizes UTF-8, UTF-16LE, and UTF-16BE; and classifies opaque binary input as unsupported. It emits fingerprints and redacted structural categories for timestamps, components, severity-like tokens, URLs, addresses, GUIDs, SIDs, paths, status codes, and correlation-like identifiers. Authorization, bearer, cookie, and private-key indicators are never copied into previews. Password-like text remains an unconfirmed heuristic. No filename establishes SCCM semantics, and no semantic SCCM log parser is currently fixture-validated.

## Capture-evidence bundles

```bash
# Synthetic or explicitly authorized-lab examples.
cinderpath lab capture-kit bundle export --directory ~/cinderpath-lab-kit \
  --output baseline-01.capture-bundle.tar.gz
cinderpath lab capture-kit bundle inspect --input baseline-01.capture-bundle.tar.gz
cinderpath lab capture-kit bundle sign --input baseline-01.capture-bundle.tar.gz \
  --key ~/.config/cinderpath/research-signing-key \
  --output baseline-01.signed.capture-bundle.tar.gz
cinderpath lab capture-kit bundle verify --input baseline-01.signed.capture-bundle.tar.gz
cinderpath capture guided-import --bundle baseline-01.capture-bundle.tar.gz \
  --dossier-output reports/baseline-01
```

A capture-evidence bundle is a distinct `bundle_type: capture_evidence` archive. It does not require or contain an observed protocol contract. It contains the canonical bundle manifest, kit manifest, bounded metadata, reviewed sanitized evidence, review records, and optional redacted inspection/import summaries. It excludes `raw/`, replacement maps, secure-secret files, signing keys, tool binaries, raw archives, symlinks, and unsafe paths. Export requires authorized/disposable assertions, current hashes, completed metadata/binary review, passed leakage checks, explicit bundle approval, and removal of the synthetic sentinel and all positive leakage indicators. Output must be outside the kit.

Archive inspection/import enforce member-count, per-member, total-size, regular-file, traversal, duplicate-path, and fingerprint limits. Import is atomic and remains offline evidence. Ed25519 signing reuses the research signing-key format and covers the canonical capture-evidence manifest, whose member hashes bind every member. A valid signature proves integrity and signer identity only; it does not prove sanitization, protocol correctness, client identity, or live approval. Capture-evidence bundles are rejected by protocol-contract bundle commands because the formats remain separate.

The schema-v7 audit wires every retained kit table to a real workflow: stable kits/files and run-attributed validation, review, import, inventory, matrix-link, and dossier records. Because migration 7 was already published, schema v8 safely adds capture-evidence bundle/member and Windows-log inspection tables for existing databases. Stored paths are safe relative paths or basenames; raw bodies, complete log lines, authorization values, cookies, bearer tokens, passwords, private keys, and replacement maps are excluded.

Capture-kit dossiers are atomic owner-only directories containing kit/state summaries, redacted client/tool inventories, file inventory, log categories, review/sanitization/leakage summaries, bundle provenance, matrix state, gaps, and safety boundaries. They contain no raw bodies or complete sensitive log lines.

Matrix attachment requires reviewed sanitized data, records operator-declared client/OS/site/MP/version/action/tool/format/TLS/signature labels, rejects missing variables and duplicate fingerprints, and does not run analysis.

Confirmed plaintext from later offline analysis retains existing controls: `--hide-secrets` wins; safe never displays plaintext; standard requires `--show-secrets`; aggressive/yolo defaults require an interactive TTY; non-TTY hides plaintext unless explicitly enabled. A dedicated secrets file is atomic mode `0600`. Ordinary JSON, HTML, SQLite fields, dossiers, manifests, logs, paths, and errors remain redacted. Offline usability is `unvalidated`.

Windows execution is not part of normal Linux CI; PowerShell is covered by static and golden safety tests and must still receive optional manual validation in a disposable Windows lab. The live blocker remains reviewed, sanitized, reproducible captures from an already configured client across controlled versions and conditions, with exact framing, identity prerequisites, failure behavior, and proven read-only semantics. Live collection and `approved_live` promotion remain absent.

The retained controlled kit was also processed by the offline endpoint
correlator. It extracted 12 captured DNS events and joined fingerprint-only DNS,
SNI, flow, log, and passive inventory metadata. Inventory and logs supported a
medium-confidence management-point candidate, while no DNS/address or SNI edge
linked it to a TLS flow. The distinct flow classification is
`endpoint_identified_but_flow_ambiguous`; kit review, sanitization, import, and
export readiness are unchanged.
