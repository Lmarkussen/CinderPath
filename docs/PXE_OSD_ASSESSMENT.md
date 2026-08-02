# SCCM PXE and OSD posture assessment

CinderPath separates PXE discovery, server-local assessment, active validation, and content analysis. This phase implements the first two only. It never sends DHCP, PXE, TFTP, boot-media, WIM, task-sequence, or distribution-point content requests.

```bash
cinderpath lab pxe candidates --candidate srv01 --site-code P01
cinderpath lab pxe inspect-plan --candidate srv01 --output plan.json
cinderpath lab pxe collector-script --output Collect-CinderPathPXEPosture.ps1
cinderpath lab pxe analyze --inventory pxe-posture.json \
  --candidate srv01 --site-code P01 --output reports/pxe
```

The candidate must be established independently before access. The generated Windows PowerShell 5.1 collector performs fixed, server-local checks for WDS and ConfigMgr PXE responder services, WDS features, bounded SCCM/WDS registry metadata, four known log-file metadata records, and bounded `.wim` file metadata beneath the fixed server-local SMSImages root. It reads files opened with shared-read semantics, emits fingerprints instead of paths, and never copies image or log contents.

The authorized GOAD run identified one SCCM inventory server. WDS was installed and running; the separate `SccmPxe` responder was absent. DP registry metadata reported PXE installed/enabled and unknown-computer support enabled. Three server-local boot-image files were observed by fingerprint and size bucket. PXE password posture remained unknown. Task-sequence deployment metadata was unavailable because no existing authorized read-only provider was present; CinderPath did not add SQL or provider access.

The result is `pxe_present_no_exposure_established`, not a vulnerability and not authorization to boot, retrieve media, or download a WIM. Active validation is not justified until a PXE deployment or other bounded pathway is positively established. Existing Ansible inventory credentials were used; operator fallback credentials were not used or stored.

Representative output:

```text
PXE responder: wds
PXE enabled: true
Unknown-computer posture: unknown_computer_support_enabled
PXE password posture: pxe_password_status_unknown
Boot images: 3 state=server_local_file_metadata_observed
PXE deployments: 0 state=unavailable_without_existing_read_only_provider
Assessment: pxe_present_no_exposure_established
Active validation: not_justified
Live PXE requests: 0
```
