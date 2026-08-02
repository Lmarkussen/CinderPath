# Passive Windows SCCM lab capture kit

The capture kit is an offline preparation and import workflow for an explicitly authorized disposable Windows lab with an already configured SCCM client. It generates instructions, passive inventory scripts, local evidence directories, review forms, and Linux wrappers. It does **not** register a client, change identity, trigger policy retrieval, contact a management point, start packet capture, install tools, weaken TLS, upload data, or approve live execution.

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

Replacement maps must be mode `0600` and never enter command history or export directories. Complete identifier, binary, and leakage reviews manually and update `metadata/capture.template.yaml`. States are `ready_for_capture`, `capture_in_progress`, `raw_capture_complete`, `requires_sanitization`, `requires_manual_review`, `ready_for_import`, `ready_for_bundle_export`, and `invalid`. Raw evidence is never ready for sharing. All kit metadata is an operator assertion, not independent verification.

Guided import accepts only supported files under `sanitized/`, runs existing bounded offline parsing, leaves `raw/` unchanged, persists redacted attribution, and may create an atomic dossier. Dry-run performs no persistence or secret output. Generic capture-kit bundle export is intentionally unavailable in this phase: use the existing reviewed protocol-bundle workflow only when an observed contract and compatible sanitized fixture exist. Signatures do not grant trust.

Matrix attachment requires reviewed sanitized data, records operator-declared client/OS/site/MP/version/action/tool/format/TLS/signature labels, rejects missing variables and duplicate fingerprints, and does not run analysis.

Confirmed plaintext from later offline analysis retains existing controls: `--hide-secrets` wins; safe never displays plaintext; standard requires `--show-secrets`; aggressive/yolo defaults require an interactive TTY; non-TTY hides plaintext unless explicitly enabled. A dedicated secrets file is atomic mode `0600`. Ordinary JSON, HTML, SQLite fields, dossiers, manifests, logs, paths, and errors remain redacted. Offline usability is `unvalidated`.

The live blocker remains reviewed, sanitized, reproducible captures from an already configured client across controlled versions and conditions, with exact framing, identity prerequisites, failure behavior, and proven read-only semantics. Live collection and `approved_live` promotion remain absent.
