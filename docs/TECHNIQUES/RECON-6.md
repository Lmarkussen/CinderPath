# RECON-6 — Enumerate SCCM roles via the SMB Named Pipe winreg

CinderPath implements the canonical Misconfiguration Manager RECON-6 behavior
as a bounded, read-only remote registry assessment. It authenticates to the
selected site system with explicit domain credentials, connects to `IPC$`,
opens `\\PIPE\\winreg`, binds MS-RRP (`338CD001-2244-31F1-AAAA-900038001003`),
and reads only the SCCM paths required for role/site metadata.

The fixed allowlist is:

- `HKLM\\SOFTWARE\\Microsoft\\SMS` (role subkeys)
- `HKLM\\SOFTWARE\\Microsoft\\SMS\\DP` values `SiteCode`, `SiteServer`,
  `ManagementPoints`, `IsAnonymousAccessEnabled`, and `IsPXE`
- `HKLM\\SOFTWARE\\Microsoft\\SMS\\COMPONENTS\\SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers`
  (site-database relationship)

No arbitrary registry path input or registry mutation operation is exposed.
SMB2/3, IPC$, MS-RRP calls, response sizes, subkey counts, and value lengths
are bounded. The logical hostname remains separate from an evidenced transport
address. The Remote Registry service must already be available; CinderPath does
not start or enable it.
