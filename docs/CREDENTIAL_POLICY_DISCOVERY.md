# Targeted SCCM credential-policy discovery

CinderPath ends broad schema exploration before this workflow begins. The commands evaluate a versioned registry of eight credential-policy categories against an already collected read-only inventory:

```bash
cinderpath lab client-artifacts credential-targets --format text
cinderpath lab client-artifacts find-credential-policies \
  --inventory local-artifacts.json \
  --output reports/credential-policy \
  --script-output Collect-CinderPathCredentialPolicyMetadata.ps1
```

The generated Windows PowerShell 5.1 script embeds an exact class allowlist derived offline. It reads bounded instance metadata only: property names and types, null state, length buckets, shapes, and fingerprints. It invokes no SCCM method, retrieves no policy, contacts no endpoint, copies no property value, and performs no decryption.

The first target is `CCM_NetworkAccessAccount` with the known username/protected-value property combination and machine-policy provenance. A password-like name, entropy, base64 appearance, or recent timestamp alone is weak evidence. Task-sequence, network-folder, domain-join, collection/deployment-variable, legacy-package, and OSD service-account targets use the same independent-evidence rule.

The August 2026 disposable Windows Server 2019 runtime selected 18 exact classes but observed zero concrete instances. It produced zero NAA, task-sequence, variable, opaque-field, preview, and copy candidates. Readiness is `no_credential_policy_evidence`; no raw content was copied. This supports discovery logic, not credential recovery.

PXE/OSD remains a separate planned track. Raw evidence stays outside Git. Policy actions, management-point requests, decryption, and credential validation require separate authorization and evidence.
