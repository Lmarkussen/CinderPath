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

The authorized GOAD run identified one SCCM inventory server. WDS was installed and running; the separate `SccmPxe` responder was absent. DP registry metadata reported PXE installed/enabled and unknown-computer support enabled. Three server-local boot-image files were observed by fingerprint and size bucket. PXE password posture remained unknown.

## Provider deployment metadata

The follow-up metadata workflow uses only `root\SMS` and `root\SMS\site_<site>`. It ranks at most 32 schemas by identifier and relationship structure, reads at most 2,000 instances, fingerprints identifiers, and never requests sequence bodies, variables, scripts, collection members, package content, SQL, or PXE traffic:

```bash
cinderpath lab pxe provider-plan --server srv01 --site-code P01 --output provider-plan.json
cinderpath lab pxe deployment-metadata --site-code P01 --output Collect-CinderPathPXEDeploymentMetadata.ps1
cinderpath lab pxe analyze-deployments --deployments pxe-deployments.json --output reports/pxe-deployments
```

On the tested server both provider namespaces were accessible (66 and at least 512 bounded schemas). The relationship-bearing `SMS_TaskSequencePackage`, `SMS_Advertisement`, `SMS_Collection`, and `SMS_BootImagePackage` schemas were present but returned zero instances. One unrelated auto-deployment helper instance query was unavailable and was reported explicitly. A bounded `smspxe.log` template observation referenced boot images, but did not establish a deployment relationship. Therefore task sequences, deployments, unknown-computer deployments, and boot-image relationships were all zero; password posture remained unknown.

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

The newer provider run reports `Provider available: true`, `Classes inspected: 32`, and zero deployment instances. Provider availability is not deployment evidence. Active validation remains unjustified.
