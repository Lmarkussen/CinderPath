# Misconfiguration Manager coverage

CinderPath’s catalog is based on the research and organizational model of the
[Misconfiguration Manager project](https://github.com/subat0mik/Misconfiguration-Manager).
The embedded snapshot represents upstream revision
`394c53baf98c4eeb5ba001d195c4653216ac3141`. Technique definitions and
attack-defense mappings originate upstream; support dimensions and runtime
validation results describe the independent CinderPath implementation only.

CinderPath uses an embedded, offline framework snapshot. Normal runtime never downloads upstream content. A snapshot records its upstream revision, snapshot date, matrix fingerprint, technique summaries, attack/defense mappings, and independent coverage dimensions.

Inspect coverage with:

```text
cinderpath framework coverage --framework misconfiguration-manager
cinderpath framework technique CRED-1
cinderpath framework family CRED
cinderpath framework gaps
```

The catalog is planning metadata. Prerequisites, discovery, assessment, validation, execution, cleanup, defense assessment, and lab validation are reported separately. A supported prerequisite does not imply supported execution. Shadow Credentials remains a downstream AD primitive and is not enabled by the framework snapshot.

Upstream imports are development-only and require a local export:

```text
cinderpath research framework import --source /path/to/Misconfiguration-Manager --revision <commit> --output internal/framework/data/misconfiguration-manager.json
cinderpath research framework validate --snapshot internal/framework/data/misconfiguration-manager.json
```

The embedded snapshot is currently imported from the local Misconfiguration
Manager revision recorded in the file. Re-importing is a development operation;
runtime remains fully offline. CinderPath is not an official Misconfiguration
Manager implementation and the upstream project does not endorse or own
CinderPath behavior.
