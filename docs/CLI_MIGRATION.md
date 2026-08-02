# CLI migration

Low-level commands remain supported for at least one compatibility cycle. Old top-level parents are hidden from normal help and emit concise Cobra deprecation guidance on use. JSON payloads remain machine-clean because warnings use stderr.

| Previous command | Preferred command | Disposition |
|---|---|---|
| `capture ...` | `research capture ...` | hidden compatibility alias |
| `lab capture-kit ...` | `research evidence ...` | hidden compatibility alias |
| `lab client-artifacts ...` | `research policy ...` | hidden compatibility alias |
| `lab pxe ...` | `assess pxe --target <target>` for normal use | hidden advanced pipeline |
| `parser ...`, `analysis ...`, `matrix ...`, `sequence ...` | research workflows | hidden compatibility aliases |
| `auth ...`, `identity ...`, `runs ...`, `config ...` | advanced compatibility paths | hidden; safety unchanged |

No command was deleted. Existing flags and implementations remain intact. Active acknowledgements, target bounds, redaction, and read-only defaults are unchanged.

The machine-readable disposition for every command is available with:

```bash
cinderpath debug command-inventory --format json
```

Removal requires a later compatibility review, tested replacement coverage, documentation, and an announced release boundary.
