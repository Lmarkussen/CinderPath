package capturekit

const readmeFirst = `CinderPath passive Windows SCCM lab capture kit

This kit prepares an authorized disposable lab workflow. It does not register a
client, trigger policy retrieval, start packet capture, contact SCCM, install
software, upload files, or approve live protocol execution.

1. Read SAFETY.txt and WINDOWS-CHECKLIST.txt.
2. On Windows, run Collect-CinderPathInventory.ps1.
3. Run Prepare-CinderPathCapture.ps1; it only prepares folders/instructions.
4. Separately start and stop an approved capture tool under your lab procedure.
5. Run Finalize-CinderPathCapture.ps1; raw output remains sensitive.
6. Transfer locally through your authorized channel, then follow LINUX-CHECKLIST.txt.
`
const safety = `AUTHORIZED DISPOSABLE LAB USE ONLY

CinderPath does not perform capture or policy retrieval. Do not place production
data, passwords, tokens, cookies, private keys, replacement maps, or secure
secret files in this kit. Raw files are sensitive and are never safe to share
merely because they were inventoried or hashed. TLS payloads normally remain opaque.
`
const windowsChecklist = `WINDOWS CHECKLIST
[ ] Confirm authorization, disposable snapshot, and existing configured SCCM client.
[ ] Review scripts before execution; SCCM classes vary by client/version.
[ ] Run passive inventory and preparation.
[ ] Start/stop an approved capture tool manually.
[ ] Observe only a naturally occurring or separately approved normal lab action.
[ ] Finalize locally. Do not call raw evidence sanitized.
`
const linuxChecklist = `LINUX CHECKLIST
[ ] Validate the kit.
[ ] Inspect formats and opaque binary limitations.
[ ] Sanitize into sanitized/ without modifying raw/.
[ ] Complete identifier, binary, and leakage review records manually.
[ ] Validate ready_for_import before guided import.
[ ] Export a bundle only after explicit review approval and passing leakage checks.
`
const protectGitignore = `*
!.gitignore
!README.txt
# Raw captures, ETL, logs, archives, keys, maps, and secure secret output remain ignored.
*.pcap
*.pcapng
*.cap
*.etl
*.har
*.log
*.zip
*.tar
*.tar.gz
*.key
*.pem
*.pfx
*.p12
*replacement*
*secret*
`
const inventoryPS = `# Passive, bounded Windows/SCCM metadata inventory. No network or state changes.
[CmdletBinding()] param([string]$OutputPath = "")
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $Root "metadata\client-inventory.json" }
$Errors = [System.Collections.Generic.List[object]]::new()
function Safe-Read([string]$Name, [scriptblock]$Action) {
  try { & $Action } catch { $Errors.Add([ordered]@{ item=$Name; error=$_.Exception.Message.Substring(0,[Math]::Min(256,$_.Exception.Message.Length)) }); $null }
}
# OS build is local diagnostic metadata.
$OS = Safe-Read "windows_version" { Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber }
# The hostname is fingerprinted so the clear identifier is not written.
$HostHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME))).ToLowerInvariant()
# Read-only service presence; no service is started, stopped, or restarted.
$Service = Safe-Read "ccmexec_service" { Get-Service -Name CcmExec -ErrorAction Stop | Select-Object Name,Status }
# SCCM namespaces/classes differ by version and environment; unavailable is explicit.
$Client = Safe-Read "root_ccm_sms_client" { Get-CimInstance -Namespace root\ccm -ClassName SMS_Client -ErrorAction Stop | Select-Object ClientVersion }
$Authority = Safe-Read "root_ccm_authority" { Get-CimInstance -Namespace root\ccm -ClassName SMS_Authority -ErrorAction Stop | Select-Object Name,CurrentManagementPoint }
# Certificate metadata only; private key material and certificate bytes are never read/exported.
$Certs = Safe-Read "certificate_metadata" { @(Get-ChildItem Cert:\LocalMachine\My | Select-Object -First 128 | ForEach-Object { [ordered]@{store="LocalMachine/My";subject=$_.Subject;issuer=$_.Issuer;thumbprint=$_.Thumbprint;not_before=$_.NotBefore.ToUniversalTime().ToString("o");not_after=$_.NotAfter.ToUniversalTime().ToString("o");eku=@($_.EnhancedKeyUsageList | Select-Object -ExpandProperty ObjectId);private_key_present=[bool]$_.HasPrivateKey} }) }
# Adapter and proxy configuration are local metadata; no address is contacted or resolved.
$Adapters = Safe-Read "network_adapters" { @(Get-NetAdapter | Select-Object -First 64 Name,InterfaceDescription,Status,MacAddress,LinkSpeed) }
$Proxy = Safe-Read "proxy_metadata" { netsh winhttp show proxy | Select-Object -First 32 }
# Executable presence only; detected tools are never run.
$Tools = @("dumpcap.exe","Wireshark.exe","pktmon.exe","netsh.exe") | ForEach-Object { [ordered]@{name=$_;present=[bool](Get-Command $_ -ErrorAction SilentlyContinue)} }
$Logs = Safe-Read "ccm_log_inventory" { @(Get-ChildItem "$env:windir\CCM\Logs" -File -ErrorAction Stop | Select-Object -First 256 Name,Length,LastWriteTimeUtc) }
$Channels = Safe-Read "event_log_channels" { @(Get-WinEvent -ListLog "Microsoft-Windows-*" -ErrorAction Stop | Select-Object -First 128 LogName,IsEnabled,RecordCount) }
$Result = [ordered]@{schema_version=1;collected_at=(Get-Date).ToUniversalTime().ToString("o");hostname_sha256=$HostHash;windows=$OS;timezone=[TimeZoneInfo]::Local.Id;ccmexec_service=$Service;sccm_client=$Client;sccm_authority=$Authority;certificates=$Certs;network_adapters=$Adapters;proxy=$Proxy;capture_tools=$Tools;ccm_logs=$Logs;event_log_channels=$Channels;errors=$Errors}
$Result | ConvertTo-Json -Depth 6 -Compress | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Write-Host "Passive inventory written locally to metadata/client-inventory.json"
`
const preparePS = `# Prepares local directories and instructions only. It never starts capture or SCCM actions.
[CmdletBinding()] param()
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "manifest.yaml"))) { throw "Run from the generated kit windows directory." }
$Session = Join-Path $Root "raw\capture"
New-Item -ItemType Directory -Force -Path $Session | Out-Null
$Started = (Get-Date).ToUniversalTime().ToString("o")
Set-Content -LiteralPath (Join-Path $Root "raw\capture-started-at.txt") -Value $Started -Encoding ascii
Set-Content -LiteralPath (Join-Path $Root "raw\CINDERPATH_SYNTHETIC_LEAK_SENTINEL.txt") -Value "CINDERPATH_SYNTHETIC_LEAK_SENTINEL" -Encoding ascii
Write-Host "Prepared raw/capture locally at $Started."
Write-Host "CinderPath DID NOT start packet capture or trigger policy retrieval."
Write-Host "Separately start and stop your approved tool. See commands-manual.txt."
Write-Host "Likely logs: $env:windir\CCM\Logs (copying is opt-in during finalization)."
`
const finalizePS = `# Local passive finalization. No upload, sanitization, deletion, or source modification.
[CmdletBinding()] param([switch]$Finalize, [switch]$IncludeClientLogs, [switch]$CreateArchive)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "manifest.yaml"))) { throw "Run from the generated kit windows directory." }
$Raw = Join-Path $Root "raw"
if ($IncludeClientLogs) {
  $Dest = Join-Path $Raw "client-logs"; New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  Get-ChildItem "$env:windir\CCM\Logs" -File -ErrorAction Stop | Select-Object -First 64 | ForEach-Object { if ($_.Length -le 16777216) { Copy-Item -LiteralPath $_.FullName -Destination $Dest -ErrorAction Stop } }
}
$Files = @(Get-ChildItem $Raw -File -Recurse | Where-Object { $_.Length -le 67108864 } | Select-Object -First 512 | ForEach-Object { [ordered]@{path=$_.FullName.Substring($Root.Length+1);size=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();extension=$_.Extension;modified_at=$_.LastWriteTimeUtc.ToString("o");source_category=if($_.Extension -eq ".log"){"sccm_client_log"}else{"operator_supplied_raw"};copied=[bool]$IncludeClientLogs;redacted=$false;reviewed=$false} })
$Manifest = [ordered]@{schema_version=1;stopped_at=(Get-Date).ToUniversalTime().ToString("o");raw_sensitive=$true;safe_for_sharing=$false;files=$Files;warnings=@("Raw evidence may contain identifiers, credentials, cookies, and opaque binary content.")}
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Raw "local-raw-manifest.json") -Encoding utf8NoBOM
if ($CreateArchive) { $Archive=Join-Path $Root "output\cinderpath-RAW-SENSITIVE.zip";if(Test-Path $Archive){throw "Raw archive already exists"};Compress-Archive -LiteralPath $Raw -DestinationPath $Archive -CompressionLevel Optimal;Write-Warning "Archive remains RAW AND SENSITIVE; it is not sanitized." }
Write-Host "Finalized local raw manifest. Uploads: none. Live SCCM policy requests: 0."
`
const manualCommands = `PASSIVE EXAMPLES ONLY — SCCM namespaces/classes vary by version and environment.

Get-ComputerInfo
Get-CimInstance -Namespace root\ccm -ClassName SMS_Client
Get-ChildItem C:\Windows\CCM\Logs
Get-ChildItem Cert:\LocalMachine\My |
  Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter, HasPrivateKey

Packet capture is operator-controlled and manual. Possible categories:
- Wireshark/dumpcap: packet-level PCAP/PCAPNG; TLS normally opaque; CinderPath imports PCAP/PCAPNG.
- pktmon: packet/event-level ETL; convert separately with approved built-in procedures; ETL is not directly ingested.
- netsh trace: event/packet-like ETL; TLS normally opaque; ETL is not directly ingested.
- Approved EDR/sensor export: format/vendor dependent; manual review and conversion may be required.
- Browser/proxy HAR: HTTP-level; may expose headers/bodies and secrets; CinderPath imports reviewed HAR.

No capture tool is started by this kit. A normal policy retrieval must occur naturally
or be initiated separately under the operator's approved lab procedure. This kit
contains no policy-trigger, client-registration, repair, or certificate-export command.
`
const eventNotes = `Inventory records channel availability only. Event logs may contain identifiers.
Export, collection, retention, and redaction are separate operator-reviewed actions.
`
const shellCommon = `#!/usr/bin/env bash
set -euo pipefail
KIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
CINDERPATH_BIN=${CINDERPATH_BIN:-cinderpath}
`
const inspectSH = shellCommon + `printf '%s\n' "$CINDERPATH_BIN lab capture-kit validate --directory $KIT_DIR"
exec "$CINDERPATH_BIN" lab capture-kit validate --directory "$KIT_DIR"
`
const sanitizeSH = shellCommon + `printf '%s\n' "Sanitization is explicit and format-dependent. Raw files are not modified."
printf '%s\n' "Use: $CINDERPATH_BIN protocol sanitize --input <raw-fixture-dir> --output $KIT_DIR/sanitized/<label> --replacement-map <mode-0600-file>"
exit 2
`
const reviewSH = shellCommon + `printf '%s\n' "Complete review/*.md and metadata/capture.template.yaml manually."
printf '%s\n' "$CINDERPATH_BIN lab capture-kit validate --directory $KIT_DIR"
exec "$CINDERPATH_BIN" lab capture-kit validate --directory "$KIT_DIR"
`
const importSH = shellCommon + `printf '%s\n' "$CINDERPATH_BIN capture guided-import --kit $KIT_DIR"
exec "$CINDERPATH_BIN" capture guided-import --kit "$KIT_DIR"
`
const bundleSH = shellCommon + `printf '%s\n' "Bundle export is blocked unless review approval and leakage checks are recorded."
printf '%s\n' "$CINDERPATH_BIN capture guided-import --kit $KIT_DIR --bundle-output <reviewed-output>"
exit 2
`
const preReview = "# Pre-capture review\n\n- [ ] Authorized disposable lab confirmed\n- [ ] Existing configured client confirmed\n- [ ] Approved manual capture procedure selected\n"
const postReview = "# Post-capture review\n\n- [ ] Raw evidence remains local and sensitive\n- [ ] Start/stop timestamps recorded\n- [ ] No raw file was modified\n"
const identifierReview = "# Identifier review\n\n- [ ] Hostnames, GUIDs, SIDs, URLs, usernames, tokens, and certificates reviewed\n"
const binaryReview = "# Binary review\n\n- [ ] Opaque binary regions reviewed manually\n- [ ] TLS visibility and unsupported formats recorded\n"
const leakageReview = "# Leakage check\n\n- [ ] Synthetic sentinel absent from export\n- [ ] Authorization, cookie, bearer-token, key, replacement-map, and secure-secret markers absent\n"
