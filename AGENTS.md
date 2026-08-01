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

## Next task

The primary operator workflow remains mock-safe. Policy research is offline and fixture-driven; live policy execution must remain blocked unless a separately reviewed contract reaches `approved_live`. Normal commands may not promote contracts. Preserve loopback-only replay, bounded parsers, client-metadata-only import, dedicated plaintext output, and redaction from ordinary persistence. The next task is reviewing sanitized real captures and documenting an exact contract without adding registration, content requests, protected-secret decryption, or state changes.
