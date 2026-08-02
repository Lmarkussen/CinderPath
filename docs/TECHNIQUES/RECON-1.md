# RECON-1 — Enumerate SCCM site information via LDAP

`RECON-1` uses the existing bounded LDAP discovery modules to read RootDSE and
SCCM-published directory objects. It is LDAP-only: no DNS, HTTP, SMB, PXE,
SMS Provider, or SCCM client action is part of this technique.

Run it with an authorized configuration that enables the existing live provider:

```text
cinderpath assess technique RECON-1 --target <domain-or-scope>
```

Without that connector, CinderPath returns a plan and performs no network
activity. Results retain site and management-point assets, evidence-backed
relationships, publishing-state findings, and the upstream defensive mappings.
Naming matches remain weak hints and never establish a role. Validation and
execution are not applicable to this read-only reconnaissance technique.
