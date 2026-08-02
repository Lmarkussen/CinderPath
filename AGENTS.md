# CinderPath contributor guidance

## Project identity

- Repository and Go module: `github.com/Lmarkussen/CinderPath`
- Binary: `cinderpath`
- Language: Go 1.25 or newer
- Current detailed handover: [`docs/STATUS.md`](docs/STATUS.md)

## Current safety boundary

CinderPath is for authorized assessments and controlled labs. Preserve safe, read-only defaults.

- `discover` defaults to `--provider mock`.
- Never contact a network unless the user explicitly selects `--provider live` and supplies scope.
- Exclusions and target expansion limits must be enforced before network activity.
- Do not add client registration, policy retrieval, secret extraction, credential attacks, NTLM relay, deployment modification, SQL writes, WMI execution, remote command execution, or other state-changing behavior without a separately authorized task and explicit safety design.
- Generic TCP probing must remain connect-only. SMB, SQL, LDAP, and SCCM notification ports do not receive protocol actions unless an explicitly enabled safe module owns that protocol.
- Keep all network operations bounded by context, concurrency, per-host timeouts, per-connection timeouts, response-size limits, and redirect limits.
- SCCM HTTP validation is restricted to anonymous `GET /SMS_MP/.sms_aut?MPLIST` and `HEAD` requests to the four documented DP virtual-directory roots on already-profiled ports 80/443. Do not extend that allowlist without a separately reviewed safety task.
- Discovery SCCM HTTP requests never carry bodies, authorization, cookies, client certificates, ambient credentials, proxy traffic, or state-changing/WebDAV/BITS methods. Only `live.sccm.http_routes` may generate discovery traffic; MP and DP classifiers consume persisted evidence.
- `auth validate` is the sole authentication workflow. It is disabled by default and requires explicit enablement, identity, exact known endpoint selection, lockout acknowledgement, freshness, and attempt-budget checks. It may send one Basic header or one selected TLS client certificate only to the exact previously observed allowlisted route. It never redirects, retries, uses proxies/cookies/ambient credentials, or broadens scope.

## Architecture rules

- Keep Cobra handlers thin; application behavior belongs under `internal/app` and domain packages.
- Implement discovery and assessment behavior through `internal/modules.Module`.
- Mark modules with accurate category, requirements, supported assets, applicability reason, and safety level.
- Publish progress through `internal/progress`; do not bind modules to terminal rendering.
- Return normalized models and evidence rather than printing module-specific output.
- Persist results incrementally through the existing database abstraction and deterministic upserts.
- Preserve mock behavior and the default mock provider.
- Treat ports and hostname patterns as supporting evidence, not confirmation of SCCM roles.

## Evidence and secrets

- Distinguish user input, mock observations, live observations, inferred conclusions, and confirmed conclusions.
- Do not create vulnerability findings merely because a service is reachable.
- Bound evidence and body previews before persistence and reporting.
- Never accept normal plaintext-password CLI arguments.
- LDAP passwords may come from an environment-variable reference or bounded file, and may exist only in process memory for the bind.
- Store only `SecretReference` metadata; never log, persist, report, or fixture real secret values.
- Anonymous LDAP bind must remain explicit and must never be a fallback.

## Before modifying code

```bash
pwd
git status --short
git branch --show-current
git log -5 --oneline
```

Read `README.md`, `docs/STATUS.md`, `go.mod`, `config.example.yaml`, and the relevant source/tests. Preserve existing package boundaries and avoid unrelated redesigns.

## Validation

After modifying Go code, run:

```bash
go fmt ./...
go vet ./...
go test ./...
go build ./...
```

When applicable, also run:

```bash
go test -tags=integration ./...
go run ./cmd/cinderpath discover --provider mock
go run ./cmd/cinderpath assess
go run ./cmd/cinderpath report
```

Live smoke tests must use explicitly authorized targets; prefer loopback fixture servers. Integration LDAP tests must skip cleanly when fixture environment variables are absent. Do not commit credentials or generated customer evidence.

## Current offline research state and next task

The primary operator workflow remains mock-safe. Policy research is offline and fixture/capture-driven; schema-v8 persistence and ordinary reports contain redacted metadata only. Durable planning, sanitizer review, Ed25519 research signatures, multi-capture comparison/correlation, candidate contracts, safety reviews, expected offline results, dossiers, and loopback fixtures are implemented. Signatures and candidate contracts never promote trust or permit live execution. Preserve deliberate secret-output controls and Windows capture safeguards. Capture ingestion remains offline and must never enable registration, content requests, protected-secret decryption, identity generation, or state changes.

The passive Windows lab capture kit is implemented under `internal/capturekit` and `lab capture-kit`. Preserve owner-only atomic generation, bounded redacted log inspection, the manual-capture boundary, raw/sanitized separation, operator-assertion labels, guided-import review gates, dedicated capture-evidence bundle type, and schema-v8 redacted persistence. Capture-evidence bundles are not protocol-contract bundles and never grant live approval. Generated scripts must never start capture, trigger policy retrieval, contact SCCM, install tools, or upload.

The scripts were runtime-tested on one disposable GOAD Windows Server 2019 build 17763 client with Windows PowerShell Desktop 5.1 and Configuration Manager client 5.00.9128.1007. Keep generated PowerShell compatible with Windows PowerShell 5.1: do not use `SHA256.HashData`, `Convert.ToHexString`, or the PowerShell 7-only `utf8NoBOM` encoding name. Use explicit UTF-8-no-BOM file writes and retain static regression checks. This single lab result does not establish wider Windows compatibility or authorize reuse of the lab's certificate-ignoring WinRM exception.

The first controlled natural-activity capture used installed `pktmon` for ten minutes and produced ETL plus PCAPNG with 212 packets and zero tool-reported drops. Offline analysis produced no supported flows or HTTP exchanges and retained opaque-TLS/TCP-reassembly warnings. Treat it as metadata-only evidence; raw lab captures must remain outside Git. Generated start and finalization markers are lifecycle evidence even when operator metadata timestamps are blank.

The second authorized controlled capture invoked the installed client's combined `Request & Evaluate Machine Policy` control-panel action exactly once while CinderPath remained observational. It recorded 407 packets over about 205 seconds with zero reported drops and copied only changed allowlisted `CcmMessaging.log` and `PolicyAgent.log` snapshots. Logs confirm the request and no-new-assignments result, but visible HTTP was unrelated Windows trust-list traffic and SCCM TLS could not be structurally attributed. Treat this as logs-only trigger evidence with readiness `not_ready_no_policy_evidence`; raw artifacts remain outside Git. Arbitrary binary inspection must preserve offsets with ASCII-only marker folding because Unicode case conversion can change byte length.
