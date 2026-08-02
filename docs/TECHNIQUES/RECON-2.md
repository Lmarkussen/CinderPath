# RECON-2 — Enumerate SCCM roles via SMB

The embedded Misconfiguration Manager record defines RECON-2 as an SMB-based
read-only reconnaissance technique. It requires authorized domain credentials
and bounded share enumeration on an already identified SCCM site system.

CinderPath uses `github.com/hirochachacha/go-smb2` v1.1.0 (BSD-2-Clause) for
SMB2/3 negotiation and one authenticated session. Its `ListSharenames` path
mounts `IPC$`, opens only `srvsvc`, performs the minimum DCE/RPC bind and one
`NetShareEnumAll` request, then closes all resources.

The module is bounded and read-only: one explicitly scoped host, one
authentication attempt, at most 128 share records, bounded names, and
connection/operation deadlines. It never opens ordinary shares, lists
directories, reads files, downloads content, writes, probes hosts, or falls
back to SMB1. Dialect and signing details are reported as unknown because the
library does not expose negotiated values. Upstream defensive mapping is
loaded from the framework snapshot (`PREVENT-20`); this does not mean that
CinderPath assesses that defense.

Run the current truthful plan with:

```text
cinderpath assess technique RECON-2 --target <identified-sccm-host>
```

The authorized GOAD runtime validation completed with generic administrative
shares only. Discovery and assessment are now supported; no SCCM-role finding
was created and validation/execution remain not applicable.
