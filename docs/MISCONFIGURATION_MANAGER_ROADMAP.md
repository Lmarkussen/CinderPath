# Misconfiguration Manager roadmap

Normal coverage review now starts with `cinderpath assess --framework misconfiguration-manager --target <scope>` or `cinderpath framework coverage`. The embedded offline snapshot is canonical; only discovery and assessment support recorded in its coverage records is selected, while planned validation or execution remains blocked. Low-level evidence commands remain available under `research`.

NAA, task-sequence credential, and collection/deployment-variable objectives are now `discovery_supported`: targeted metadata-only class and instance discovery exists. The validated lab produced no concrete credential-policy instance, so this does not imply protected-value recovery, safe validation, or execution support. PXE/OSD acquisition and Shadow Credentials remain planned.

`pxe_dp_assessment` is now `assessment_supported` for exact one-target,
server-local read-only posture inspection. `pxe_unknown_computer` is
`discovery_supported`. Boot-media acquisition, task-sequence-media analysis,
and WIM analysis remain `planned`; the posture command never retrieves them.

`cinderpath framework coverage --framework misconfiguration-manager` exposes
versioned planning metadata. It does not execute techniques or claim planned
capabilities are implemented.

The `policy_secrets` track plans Network Access Account policy discovery and
recovery first, then task-sequence credentials and deployment or
collection-variable secrets. No secret extraction or decryption is implemented.

The `pxe_osd` track plans PXE-enabled DP posture, PXE password and unknown
computer assessment, separately authorized boot-media acquisition,
task-sequence media analysis, and offline WIM/image inspection.

The `sccm_identity_attack_paths` track separates SCCM identity-to-AD ACL
correlation and Shadow Credentials prerequisite detection from explicitly
authorized Shadow Credentials execution and cleanup. Execution is unavailable.

The `defensive_controls` track plans PREVENT, DETECT, and CANARY mappings.
Current registry entries are truthfully `planned` or `documented` only.

`RECON-1` is mapped to the existing LDAP discovery path. Its assessment remains
runtime-validated through the authorized GOAD controller; validation and
execution remain not applicable.

`RECON-2` is mapped to the upstream SMB role-enumeration technique. Its
reviewed module performs only authenticated SMB2/3 `IPC$`/`srvsvc`
`NetShareEnumAll` share-metadata enumeration; it never reads share contents.
Discovery and assessment remain partial until an authorized runtime validation
is completed.
Provider-backed deployment discovery is implemented, but the validated lab returned zero task-sequence, advertisement, collection, and boot-image instances from the relationship-bearing schemas. Consequently `pxe_unknown_computer` remains `discovery_supported`, while PXE boot-media, task-sequence-media retrieval, and WIM analysis remain `planned`. No active PXE validation is justified.
