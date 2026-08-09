# CRED-2: Request computer policy and deobfuscate secrets

The embedded Misconfiguration Manager snapshot identifies CRED-2 as the SCCM
client-policy credential path. Its canonical prerequisites include a domain
computer identity (or the ability to create one), rather than an arbitrary user
credential; PKI certificates are not required by default. CinderPath currently
supports bounded offline analysis of an already obtained policy response.

When a live CRED-2 plan needs domain, RootDSE, site, or management-point facts,
CinderPath automatically executes only the declared safe LDAP prerequisites,
persists a dedicated prerequisite run, and re-plans. Operators do not enable
LDAP manually. Existing compatible evidence is reused with its source run and
age when available. Missing client identity remains a blocker and does not
authorize policy collection.

The CRED-2 contract records the only retained observed transport facts:
`CCM_POST /ccm_system/request` and an `application/octet-stream` request
content type. The retained request body is synthetic, client identity details
are redacted, certificate semantics are absent, and no required headers or
typed request envelope are structurally established. Consequently CinderPath
does not send this request to a management point.

Offline response analysis distinguishes empty/no-policy responses,
authentication rejection, non-credential policy, credential indicators,
protected material, concrete supplied plaintext, and parser failure. Protected
material is identified but never decrypted. Candidate metadata persisted to
SQLite is redacted; a concrete plaintext value can be displayed only from the
in-memory supplied response under the existing secret-output policy.

No live CRED-2 collection or recovery has been runtime validated.
