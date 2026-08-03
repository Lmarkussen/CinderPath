# RECON-3 — Enumerate SCCM roles via HTTP

RECON-3 is a read-only HTTP reconnaissance technique from the embedded
Misconfiguration Manager snapshot. It uses one explicitly selected SCCM site
system and the existing fixed route allowlist.

The adapter selects only `live.sccm.http_recon`. It sends at most five
anonymous requests to each of `http://target:80` and `https://target:443`,
for an explicit maximum of 10 network requests per run: one `GET
/SMS_MP/.sms_aut?MPLIST` and four `HEAD` requests to the documented
distribution-point virtual-directory roots. Each request produces bounded
route and access evidence, so 10 requests can result in up to 20 evidence
records. Requests have no bodies,
authorization headers, cookies, client certificates, redirects, or proxy use.

No DNS enumeration, TCP scanning, SMB, LDAP, WinRM, PXE, SMS Provider, SQL,
file access, content download, writes, authentication attempt, or execution is
performed. Credentials are required by the upstream prerequisite and are
resolved as a reference for run provenance; HTTP authentication is not
attempted.

Evidence records route status, bounded headers/body preview, parser outcome,
SCCM markers, site codes, access state, and errors. A protocol-specific route
response is informational evidence, not a vulnerability or proof of a role.
Transport failure is distinct from a completed run with no SCCM evidence.

Before GOAD validation, discovery and assessment are partial. Runtime
validation should use one authoritative SCCM target through the established
Kali/controller route and must not expand scope.
