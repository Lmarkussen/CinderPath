# RECON family audit

The canonical technique definitions come from the embedded Misconfiguration
Manager snapshot. CinderPath keeps the upstream IDs and names while reporting
its own implementation and runtime state.

| Technique | Canonical semantics | CinderPath state | Execution boundary |
|---|---|---|---|
| RECON-1 — Enumerate SCCM site information via LDAP | Authenticated LDAP discovery of System Management, sites, and management points | Complete; GOAD validated | Authorized assessment host with LDAP credentials |
| RECON-2 — Enumerate SCCM roles via SMB | Authenticated SMB2/3 `IPC$`/`srvsvc` share metadata | Complete; GOAD validated | Authorized assessment host with SMB credentials |
| RECON-3 — Enumerate SCCM roles via HTTP | Fixed anonymous SCCM route reconnaissance on an explicit site-system host | Implemented; partial GOAD runtime validation | Authorized assessment host; no content retrieval |
| RECON-4 — Query client devices via CMPivot | Authenticated ConfigMgr CMPivot query against a collection or device | Complete; GOAD validated | One explicit Kerberos/Negotiate AdminService request targets one device with the fixed `OperatingSystem` query; polling and result normalization are bounded |
| RECON-5 — Locate users via SMS Provider | Read-only SMS Provider inventory and user-device affinity queries | Blocked | Requires authenticated SMS Provider/AdminService access |
| RECON-6 — Enumerate SCCM roles via SMB Named Pipe winreg | Read-only remote registry metadata through the `winreg` named pipe | Blocked | Requires a bounded SMB named-pipe/Remote Registry adapter |
| RECON-7 — Enumerate SCCM site information via local files | Read SCCM client logs and management-point registry metadata | Partial | Requires local SCCM client access; current artifact workflow is metadata-only/offline |

`RECON-ALL` runs implemented techniques in registry order and reports blocked
techniques individually. It does not create remote execution or ConfigMgr
orchestration capabilities implicitly.

The RECON-4 AdminService oracle returned the expected unauthenticated `401`
with `WWW-Authenticate: Negotiate`. The explicit Kerberos/SPNEGO transport
then authenticated to `MECM.SCCM.LAB` using `HTTP/mecm.sccm.lab`. The bounded
adapter resolves one `Device`, submits `{"InputQuery":"OperatingSystem"}`,
accepts the server's short-lived 404 pre-materialization state, checks the
bounded `SMS_CMPivotStatus` entity, and retrieves the completed
`AdminService.CMPivotResult`. No ambient credentials, NTLM fallback, arbitrary
queries, or collection-wide execution are used.
