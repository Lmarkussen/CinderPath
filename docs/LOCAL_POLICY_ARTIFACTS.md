# Local SCCM policy-artifact discovery

Normal operators should start with `cinderpath assess client-policy --target <client>`. Schema ranking, instance selection, credential targeting, preview planning, and dossier generation are internal pipeline stages associated through one run context. Advanced fixture and parser work remains under `cinderpath research policy`.

Targeted credential-policy work follows this generic inventory and does not repeat broad exploration. `credential-targets` and `find-credential-policies` require known class/property combinations plus machine-policy provenance; password/account names, entropy, and encoding alone remain weak evidence. See [CREDENTIAL_POLICY_DISCOVERY.md](CREDENTIAL_POLICY_DISCOVERY.md).

Packet capture reached diminishing returns in the authorized disposable lab:
the management-point endpoint could be identified, but policy traffic remained
inside opaque TLS and no flow could be attributed. Local SCCM client policy
metadata exists above TLS, so CinderPath provides a metadata-first, read-only
discovery workflow.

```bash
# Synthetic metadata labels; this only generates a local script.
cinderpath lab client-artifacts discover --output local-artifact-kit \
  --site-code ABC --client-label client-a
```

Representative bounded output from Linux generation is:

```text
Created passive local-artifact discovery kit: local-artifact-kit
Script: Discover-CinderPathPolicyArtifacts.ps1
Network activity: none
SCCM client methods invoked: 0
Live SCCM policy requests: 0
```

## Reviewed property previews

The exact-allowlist collector read only two authority `Capabilities` values and
one deployment-state `MessageDetails` value. All three were well-formed XML.
Authority values had a `Capabilities` root with `Property` structure; the
deployment value had a `ClientDeploymentMessage` root. Attribute and text
values were replaced by length markers.

All results were `schema_fixture_sufficient`; zero raw values were copied.
Authority-capability and deployment-message parsers reached
`runtime_preview_validated`. Readiness remains
`ready_for_policy_instance_parser` because no encrypted field was observed.

`Discover-CinderPathPolicyArtifacts.ps1` is Windows PowerShell 5.1 compatible.
It examines a fixed list of `root\ccm` namespaces, class schemas, bounded
instance shapes, known SCCM client directories, and two SCCM registry roots.
It records fingerprints, type/shape metadata, sizes, and bounded structural
indicators. It never invokes a CIM method, triggers policy, contacts SCCM,
writes WMI or the registry, changes a service, accesses private keys, or dumps
credential stores.

Run it only through a separately authorized local or remote procedure:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\Discover-CinderPathPolicyArtifacts.ps1 `
  -OutputPath .\local-artifacts.json
```

The bypass is process-scoped. The script writes only its requested output.
Class methods are recorded as schema metadata and are never invoked. Property
values are reduced to null state, type, length bucket, shape, and fingerprint.
File samples are bounded to 64 KiB for classification; approved files are
hashed without modifying them. Reparse points are excluded.

On Linux:

```bash
cinderpath lab client-artifacts inspect --inventory local-artifacts.json \
  --output reports/local-artifacts
cinderpath lab client-artifacts show --inventory local-artifacts.json
cinderpath lab client-artifacts export-plan --inventory local-artifacts.json \
  --output artifact-export-plan.json
```

The export plan is advisory and copies nothing. `metadata_only`, `schema_only`,
`redacted_preview`, `bounded_content_copy`, and `do_not_export` express the
recommended review mode. Content copy requires separate candidate review,
approved-root and size checks, positive policy provenance, and raw-sensitive
handling. No automatic content-copy command is implemented in this phase.

Candidate names, recent timestamps, base64 shape, or entropy alone cannot prove
a policy secret. Readiness states are `not_ready_no_policy_artifact`,
`ready_for_policy_schema_parser`, `ready_for_encrypted_value_classifier`,
`ready_for_fixture_driven_secret_decoder`, and
`ready_for_local_secret_validation`. The latter two require reviewed repeated
structure and are not granted automatically.

Generated dossiers are atomic mode `0700` with mode-`0600` files. They contain
redacted metadata and fingerprints, not full WMI values, registry values, policy
bodies, credentials, or private keys. Raw candidate artifacts remain outside
Git.

The script was runtime-validated once on the authorized disposable Windows
Server 2019 build 17763 client with Windows PowerShell Desktop 5.1.17763.8510
and Configuration Manager client 5.00.9128.1007. The administrator test account
used a process-scoped execution-policy bypass. The read-only run reported 10
namespace records, 1,024 bounded class schemas, 8 instance-metadata records,
85 file-metadata records, 33 registry-metadata records, and zero live policy
requests. Four policy namespaces were accessible; `Reduced`, `DM`, and `User`
were reported unavailable without aborting the run.

Runtime testing found and fixed PowerShell 5.1 behavior around empty pipeline
counts, locked log files, collection-property enumeration, and error handling.
This is evidence for that one VM only, not general Windows compatibility. The
pre-existing certificate-ignoring WinRM setting was used only in the isolated
authorized lab. No policy action ran and no candidate content was copied.

The corrected real metadata contained policy schemas but no structurally
supported encrypted-value candidate, so the result was
`ready_for_policy_schema_parser`. Intrinsic WMI system classes are explicitly
excluded from policy-instance scoring; their binary fields cannot establish a
policy secret. No fixture-driven decoder work is justified yet.

## Fixture-driven schema and instance analysis

`rank-schemas`, `plan-instances`, `inspect-instances`, `parser-status`, and
`content-plan` distinguish schemas from concrete instances. A 1,024-class
inventory is not 1,024 policies. The verified analysis excluded 430
intrinsic/provider schemas, formed 355 structural families, and selected 10
concrete metadata records from 15 observed instances. Fixture-backed authority,
assignment, configuration, and deployment-state parsers reach at most
`runtime_metadata_validated`.

Three XML-shaped properties were planned as `redacted_preview` candidates, but
nothing was copied. CLSIDs are `GUID_like`, not JSON, and SID/CLSID/provider
metadata is ineligible. Readiness is `ready_for_policy_instance_parser`;
encrypted-value and decoder work remain unjustified.

```text
Schemas ranked: 1024
Intrinsic/noise excluded by default: 430
Schema families: 355
Concrete selected instances: 10
Relationship edges: 10
Parser-relevant preview candidates: 3
Content copied: 0
Secret readiness: ready_for_policy_instance_parser
Live SCCM policy requests: 0
```
