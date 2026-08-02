# CLI migration

The initial local audit temporarily created hidden top-level aliases. They were never pushed or released and instantiated entire Cobra trees twice. This cleanup removes those duplicate aliases before release while retaining every unique implementation once under `research`. JSON output remains machine-clean.

| Previous command | Preferred command | Disposition |
|---|---|---|
| `capture ...` | `research capture ...` | duplicate alias removed before release |
| `lab capture-kit ...` | `research evidence ...` | duplicate alias removed before release |
| `lab client-artifacts ...` | `research policy ...` | duplicate alias removed before release |
| `lab pxe ...` | `research pxe ...` or public `assess pxe` | duplicate alias removed before release |
| `parser`, `analysis`, `matrix`, `sequence` | matching `research` path | duplicate aliases removed before release |
| `auth`, `identity`, `runs`, `config` | matching `research` path | unique implementation retained once |

No tested implementation was deleted. Duplicate Cobra mounts and their duplicate flag instances were removed. Active acknowledgements, target bounds, redaction, and read-only defaults are unchanged.

## Concrete reductions

- Removed 67 duplicate command nodes and 169 duplicate command-local flag instances.
- Removed 44 duplicated artifact-path handoffs; the remaining 42 are research direct-file inputs.
- Removed all 14 unreleased deprecated parent aliases and 138 hidden duplicate pipeline nodes.
- Removed duplicated capture/matrix/sequence/parser/analysis mounts from `protocol`; their single implementations remain directly under `research`.
- Public `discover` now exposes only `--provider` and `--target`. LDAP tuning, target files, CIDR exclusions, port/time/concurrency bounds, role hints, and TLS controls moved intact to `research discover-advanced`.
- Public client-policy and PXE assessments share `--run`, `--target`, and `--format`; bounds resolve from profiles.

No safety acknowledgement flag was removed or satisfied by a profile.

The machine-readable disposition for every command is available with:

```bash
cinderpath debug command-inventory --format json
```

Removal requires a later compatibility review, tested replacement coverage, documentation, and an announced release boundary.
