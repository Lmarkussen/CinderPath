# CLI design

CinderPath separates engagement workflows from offline research plumbing:

```text
discover → assess → validate → exploit → cleanup → report
                    run and framework provide orchestration and coverage
```

`validate`, `exploit`, and `cleanup` are visible so the lifecycle is honest, but currently return an unsupported result without action. Exploitation retains a required `--acknowledge-impact` gate even while unsupported.

Normal assessment is positional and intent-first:

```bash
cinderpath assess SCCM.LAB
cinderpath assess RECON-1 --target SCCM.LAB
cinderpath run SCCM.LAB --profile yolo
```

The existing `assess technique RECON-1` spelling is retained as a compatibility
form. The embedded framework registry distinguishes technique IDs from targets.
`run` keeps only target, authorized connector identity, provider, and dry-run
inputs; configuration generation and offline artifact controls remain under
`research`.

## Public commands

```bash
cinderpath discover --provider mock
cinderpath assess --framework misconfiguration-manager --target lab.example
cinderpath assess client-policy --target ws01
cinderpath assess pxe --target srv01
cinderpath assess technique policy_secrets_naa --target ws01
cinderpath report
cinderpath run --profile safe --dry-run
cinderpath framework coverage --framework misconfiguration-manager
```

The focused assessment commands emit a canonical workflow result and a complete artifact plan associated with one context. Operational values are readable by default; `--redact-secrets` changes only secret rendering. They do not pretend an authorized remote connector exists: execution remains blocked until one is supplied through a separately authorized workflow. Normal operators no longer need to understand intermediate inventory, ranking, preview, provider, or dossier filenames.

## Research and debug

Offline primitives remain available under:

```bash
cinderpath research capture ...
cinderpath research policy ...
cinderpath research evidence ...
cinderpath research analyze-captures ...
cinderpath research artifact register --run <run-id> --artifact-type <type> --artifact <file>
cinderpath research artifact resolve --run <run-id> --artifact-type <type>
cinderpath debug command-inventory --format json
```

The inventory walks the actual Cobra tree and records each path, description, classification, disposition, flags, required and inherited flags, safety acknowledgements, artifact inputs and outputs, side effects, network behavior, tests, and documentation. It is the authoritative machine-readable audit and performs no network operation.

## Context resolution

Important values use this precedence:

1. explicit CLI flag;
2. active run context;
3. configuration file;
4. environment variable;
5. safe default.

`--verbose` displays source categories and resolved limits. Targets are readable in workflow output with deterministic IDs retained as supplemental metadata. `--redact-secrets` is an explicit output policy for secret values. The current model resolves target, framework, database, output directory, profile, and redaction policy. Public assessment workflows share definitions for `--run`, `--target`, and `--format`. Site code, client label, roles, dossiers, and evidence associations remain domain observations rather than duplicated global flags.

## Canonical result

High-level workflows emit one schema-v1 result containing workflow, readable target, supplemental target ID, framework, status, checked stages, findings, blockers, next action, network behavior, and redaction metadata where applicable. Dossiers and domain evidence remain separate provenance records; this result does not replace raw evidence or parser lifecycle details.

The canonical artifact registry stores run ID, target fingerprint, workflow, stage, artifact type, timestamp, SHA-256 fingerprint, path, sensitivity, review, and superseded state. It resolves the latest unambiguous artifact for a run and type and refuses equal-time ambiguity. Research direct-file mode remains available through generic artifact flags.

## Profiles

## Technique Planning And Terminal Output

Operators select intent; CinderPath resolves safe prerequisites:

```text
Operator intent
      |
Technique planner
      |
Prerequisite resolver
      |
Reusable bounded modules
      |
Evidence + relationships
      |
Assessment
      |
CLI / JSON / HTML
```

The resolver evaluates domain context, RootDSE, site, management point, identity,
SMB target, and HTTP target facts against compatible retained evidence and its
configured age. It schedules LDAP only when a technique declares LDAP facts and
the live connector has an exact domain controller and authorized identity.
Explicit RECON-2 is SMB-only and explicit RECON-3 is HTTP-only. Unsupported
CRED paths may show a plan but never collect policies or recover credentials.

Technique one-off values may use `--provider`, `--domain-controller`,
`--username`, `--password-env`, and `--password-file`; module limits remain
configuration/profile values. Interactive text uses semantic colors
automatically. `--no-color` or a non-empty `NO_COLOR` disables ANSI styling;
JSON, HTML, SQLite, files, and non-TTY output are ANSI-free. The hidden
compatibility flag `--color auto|always|never` remains for existing scripts and
transcript tests. Green marks success, yellow warnings/stale states, red
failures, cyan targets/modules, magenta shown secrets, and dim supplemental IDs.

Research output destinations are no longer Cobra-required flags. They remain
explicit advanced inputs where the command needs a separate artifact location;
normal lifecycle output uses the global output root and deterministic report
paths. This removes Cobra's pre-merge rejection so configuration/default
resolution can remain authoritative.

Profiles express policy, not shortcuts around gates:

| Profile | Network | Authentication | Active validation | Secret display | Chaining | Cleanup |
|---|---|---|---|---|---|---|
| `safe` | mock/offline by default | blocked | blocked | blocked | safe stages | none |
| `standard` | explicit live provider only | separately enabled and bounded | blocked unless implemented | blocked | supported stages | recorded when applicable |
| `aggressive` | explicit scope only | separately acknowledged | implemented gates only | deliberate secure route only | broader implemented stages | required for changes |
| `yolo` | same explicit scope rules | same acknowledgements | incomplete | deliberate secure route only | not complete | required |
| `research` | offline by default | blocked unless separately enabled | blocked | redacted by default | larger offline bounds | none |

`yolo` is a placeholder, not a complete automatic attack workflow. Profiles never override scope, lockout, protocol, impact, or cleanup gates.

## Persistence assessment

`capture_observations` and `capture_dossiers` currently hold redacted PXE, local-policy, credential-discovery, and endpoint-correlation records. Their generic shape—run ID, evidence association, fingerprint, timestamp, bounded JSON—is intentionally adequate and preserves deterministic upserts. The names are awkward, but a migration would currently be aesthetic rather than a correctness or lifecycle fix. A future generic observation model is warranted when cross-domain querying requires typed referential integrity; committed migrations must not be rewritten.

## Metrics

The cleanup baseline contained 218 command nodes, 580 local flags, 198 required flags, 86 artifact handoffs, 138 hidden pipeline nodes, and 14 deprecated parents. The reduced tree contains 151 command nodes, 411 local flags, 126 required flags, 42 artifact handoffs, zero hidden pipeline nodes, and zero deprecated parents. The visible surface remains 13 Cobra commands including help/completion/version. The complete tree is measurable through `debug command-inventory` and `debug cli-complexity`.

Common PXE usage changes from manually coordinating candidate, plan, collector, posture, provider, deployment, and dossier paths to:

```bash
cinderpath assess pxe --target srv01
```

This plans the supported pipeline and reports a missing authorized connector without network activity.
