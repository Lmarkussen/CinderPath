package localartifact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CreateOptions struct {
	Output, SiteCode, ClientLabel      string
	MaxFiles, MaxClasses, MaxInstances int
	Force                              bool
}

func Create(o CreateOptions) error {
	if o.Output == "" {
		return errors.New("output is required")
	}
	if !safeLabel.MatchString(o.SiteCode) || !safeLabel.MatchString(o.ClientLabel) {
		return errors.New("site-code and client-label must be bounded safe labels")
	}
	parent := filepath.Dir(o.Output)
	tmp, e := os.MkdirTemp(parent, ".cinderpath-local-artifacts-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	if e = os.Chmod(tmp, 0700); e != nil {
		return e
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 2000
	}
	if o.MaxClasses == 0 {
		o.MaxClasses = 1024
	}
	if o.MaxInstances == 0 {
		o.MaxInstances = 128
	}
	if o.MaxFiles < 1 || o.MaxFiles > 2000 || o.MaxClasses < 1 || o.MaxClasses > 1024 || o.MaxInstances < 1 || o.MaxInstances > 128 {
		return errors.New("generated discovery limits out of range")
	}
	script := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(discoveryPS, "__SITE__", o.SiteCode), "__CLIENT__", o.ClientLabel), "__MAX_FILES__", fmt.Sprint(o.MaxFiles)), "__MAX_CLASSES__", fmt.Sprint(o.MaxClasses)), "__MAX_INSTANCES__", fmt.Sprint(o.MaxInstances))
	// Windows PowerShell 5.1 strict mode does not expose Count on a null
	// pipeline result. Force the path-separator pipeline to an array.
	script = strings.ReplaceAll(script, `$depth=($rel.ToCharArray()|Where-Object{$_-eq'\'}).Count`, `$depth=@($rel.ToCharArray()|Where-Object{$_-eq'\'}).Count`)
	script = strings.ReplaceAll(script, `$s=[IO.File]::OpenRead($f.FullName);try{$n=$s.Read($sample,0,$sample.Length)}finally{$s.Dispose()};if($n-lt $sample.Length){$sample=$sample[0..([Math]::Max(0,$n-1))]}`, `$n=0;try{$s=[IO.File]::OpenRead($f.FullName);try{$n=$s.Read($sample,0,$sample.Length)}finally{$s.Dispose()}}catch{$sample=New-Object byte[] 0;$Errors.Add(('file '+$f.Name+': unreadable').Substring(0,[Math]::Min(256,('file '+$f.Name+': unreadable').Length)))};if($n-eq 0){$sample=New-Object byte[] 0}elseif($n-lt $sample.Length){$sample=$sample[0..($n-1)]}`)
	script = strings.ReplaceAll(script, `[IO.File]::OpenRead($f.FullName)`, `[IO.File]::Open($f.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)`)
	script = strings.ReplaceAll(script, `$qs=@($p.Qualifiers.Name)`, `$qs=@($p.Qualifiers|ForEach-Object{$_.Name})`)
	script = strings.ReplaceAll(script, `qualifiers=@($c.CimClassQualifiers.Name|Sort-Object)`, `qualifiers=@($c.CimClassQualifiers|ForEach-Object{$_.Name}|Sort-Object)`)
	script = strings.ReplaceAll(script, `methods=@($c.CimClassMethods.Name|Sort-Object)`, `methods=@($c.CimClassMethods|ForEach-Object{$_.Name}|Sort-Object)`)
	script = strings.ReplaceAll(script, `$relevant=($ns-like 'root\ccm\Policy*' -or $combined-match 'policy|assignment|message|authority|cache')`, `$relevant=(-not $c.CimClassName.StartsWith('__'))-and($ns-like 'root\ccm\Policy*' -or $combined-match 'policy|assignment|message|authority|cache')`)
	script = strings.ReplaceAll(script, `entropy=0;printable_ratio=`, `entropy=(Get-Entropy $sample);printable_ratio=`)
	for n, b := range map[string]string{"Discover-CinderPathPolicyArtifacts.ps1": script, "README.txt": "Passive local SCCM artifact discovery. The script inventories bounded metadata only; it invokes no client method and performs no network request.\n"} {
		if e = os.WriteFile(filepath.Join(tmp, n), []byte(b), 0700); e != nil {
			return e
		}
	}
	if _, e = os.Lstat(o.Output); e == nil {
		if !o.Force {
			return errors.New("output already exists")
		}
		return errors.New("force replacement is intentionally unavailable for local artifact scripts")
	}
	return os.Rename(tmp, o.Output)
}

const discoveryPS = `# CinderPath passive SCCM policy-artifact metadata discovery.
# Read-only: no SCCM methods, network calls, registry/WMI writes, service changes, or content export.
[CmdletBinding()] param(
  [string]$OutputPath = ".\local-artifacts.json",
  [ValidateRange(1,2000)][int]$MaxFiles = __MAX_FILES__,
  [ValidateRange(1,1024)][int]$MaxClasses = __MAX_CLASSES__,
  [ValidateRange(1,128)][int]$MaxInstances = __MAX_INSTANCES__
)
Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"
$MaxNamespaces=32; $MaxSelectedClasses=64; $MaxProperties=128; $MaxDepth=4; $MaxSampleBytes=65536; $MaxObservations=20000
$Errors=New-Object System.Collections.Generic.List[string]
function Hash-Text([string]$Value){$h=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))).Replace("-","").ToLowerInvariant())}finally{$h.Dispose()}}
function Hash-File([string]$Path){$h=[Security.Cryptography.SHA256]::Create();$s=$null;try{$s=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);([BitConverter]::ToString($h.ComputeHash($s)).Replace("-","").ToLowerInvariant())}catch{""}finally{if($null-ne$s){$s.Dispose()};$h.Dispose()}}
function Write-UTF8([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,(New-Object Text.UTF8Encoding($false)))}
function Bucket([long]$N){if($N-eq 0){"0"}elseif($N-le 32){"1-32"}elseif($N-le 256){"33-256"}elseif($N-le 4096){"257-4096"}elseif($N-le 16384){"4097-16384"}else{"over-16384"}}
function Get-Entropy([byte[]]$Bytes){if($null-eq $Bytes-or$Bytes.Length-eq 0){return 0.0};$counts=@{};foreach($b in $Bytes){$k=[int]$b;if($counts.ContainsKey($k)){$counts[$k]++}else{$counts[$k]=1}};$e=0.0;foreach($n in $counts.Values){$p=[double]$n/$Bytes.Length;$e-=$p*([Math]::Log($p,2))};return [Math]::Round($e,4)}
function Shape($Value){if($null-eq $Value){return "empty"};if($Value-is [bool]){return "boolean"};if($Value-is [byte[]]){return "binary_blob"};if($Value-is [ValueType]){return "integer"};$s=[string]$Value;if($s.Length-eq 0){return "empty"};if($s-match '^\s*<[^>]+>'){return "XML_like"};if($s-match '^\s*[\{\[]'){return "JSON_like"};if($s-match '^[0-9A-Fa-f]{32,}$'){return "hex_like"};if($s-match '^[A-Za-z0-9+/]{32,}={0,2}$'){return "base64_like"};if($s-match '(?i)^https?://'){return "URL_like"};if($s-match '^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$'){return "GUID_like"};if($s.Length-gt 256){return "encrypted_or_opaque"};return "plaintext_text"}
$NamespaceNames=@('root\ccm','root\ccm\Policy','root\ccm\Policy\Machine','root\ccm\Policy\Machine\ActualConfig','root\ccm\Policy\Machine\RequestedConfig','root\ccm\Policy\Machine\Reduced','root\ccm\Policy\Machine\DM','root\ccm\Policy\User','root\ccm\SoftMgmtAgent','root\ccm\ClientSDK')
$Namespaces=@();$Classes=@();$Instances=@();$TotalClasses=0;$Selected=0;$Observations=0
foreach($ns in ($NamespaceNames|Select-Object -First $MaxNamespaces)){$sw=[Diagnostics.Stopwatch]::StartNew();try{$cs=@(Get-CimClass -Namespace $ns -ErrorAction Stop|Sort-Object CimClassName);$remain=[Math]::Max(0,$MaxClasses-$TotalClasses);$cs=@($cs|Select-Object -First $remain);$Namespaces+=[ordered]@{namespace=$ns;exists=$true;accessible=$true;class_count=$cs.Count;enumeration_duration_ms=0;warnings=@()};foreach($c in $cs){$props=@();foreach($p in @($c.CimClassProperties|Select-Object -First $MaxProperties)){$qs=@($p.Qualifiers.Name);$props+=[ordered]@{name=$p.Name;cim_type=[string]$p.CimType;array=([string]$p.Flags-match 'Array');key=($qs-contains 'Key');read=$true;write=($qs-contains 'Write')}};$classify='unknown_sccm_class';$combined=($ns+' '+$c.CimClassName).ToLowerInvariant();if($combined-match 'assignment'){$classify='policy_assignment_metadata'}elseif($combined-match 'policy|config'){$classify='policy_configuration_metadata'}elseif($combined-match 'authority'){$classify='policy_authority_metadata'}elseif($combined-match 'message'){$classify='message_metadata'}elseif($combined-match 'cache'){$classify='cache_metadata'};$relevant=($ns-like 'root\ccm\Policy*' -or $combined-match 'policy|assignment|message|authority|cache');$count=-1;$countState='not_selected';if($relevant-and $Selected-lt $MaxSelectedClasses){$Selected++;try{$rows=@(Get-CimInstance -Namespace $ns -ClassName $c.CimClassName -ErrorAction Stop|Select-Object -First $MaxInstances);$count=$rows.Count;$countState='bounded';$idx=0;foreach($row in $rows){$ip=@();foreach($p in @($c.CimClassProperties|Select-Object -First $MaxProperties)){if($Observations-ge $MaxObservations){break};$Observations++;$value=$row.CimInstanceProperties[$p.Name].Value;$length=0;if($null-ne $value){if($value-is [byte[]]){$length=$value.Length}else{$length=([string]$value).Length}};$shape=Shape $value;$finger='';if($null-ne $value){$finger=Hash-Text ([string]$value)};$ip+=[ordered]@{name=$p.Name;cim_type=[string]$p.CimType;state=$(if($null-eq $value){'null'}else{'non_null'});shape=$shape;fingerprint=$finger;length_bucket=(Bucket $length);array=([string]$p.Flags-match 'Array');warnings=@()}};$seed=$ns+'|'+$c.CimClassName+'|'+$idx+'|'+(($ip|ForEach-Object{$_.fingerprint})-join '|');$Instances+=[ordered]@{id=('instance_'+(Hash-Text $seed).Substring(0,20));namespace=$ns;class=$c.CimClassName;fingerprint=(Hash-Text $seed);index=$idx;properties=$ip;observed_at=(Get-Date).ToUniversalTime().ToString('o');warnings=@()};$idx++}}catch{$countState='inaccessible';$Errors.Add(('instance '+$ns+' '+$c.CimClassName+': '+$_.Exception.Message).Substring(0,[Math]::Min(256,('instance '+$ns+' '+$c.CimClassName+': '+$_.Exception.Message).Length)))}};$Classes+=[ordered]@{id=('class_'+(Hash-Text ($ns+'|'+$c.CimClassName)).Substring(0,20));namespace=$ns;name=$c.CimClassName;superclass=[string]$c.CimSuperClassName;classification=$classify;qualifiers=@($c.CimClassQualifiers.Name|Sort-Object);properties=$props;methods=@($c.CimClassMethods.Name|Sort-Object);instance_count=$count;count_state=$countState;warnings=@()}};$TotalClasses+=$cs.Count}catch{$Namespaces+=[ordered]@{namespace=$ns;exists=$false;accessible=$false;class_count=0;enumeration_duration_ms=0;warnings=@('unavailable')}}finally{$sw.Stop();$Namespaces[-1].enumeration_duration_ms=$sw.ElapsedMilliseconds}}
$Roots=@("$env:windir\CCM\Policy","$env:windir\CCM\CcmStore","$env:windir\CCM\Cache","$env:windir\CCM\Temp","$env:windir\CCM\Logs")
$Files=@();foreach($root in $Roots){if(-not(Test-Path -LiteralPath $root -PathType Container)){continue};$items=@(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue|Where-Object{($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-eq 0}|Sort-Object FullName);foreach($f in $items){if($Files.Count-ge $MaxFiles){break};$rel=$f.FullName.Substring($root.Length).TrimStart('\');$depth=($rel.ToCharArray()|Where-Object{$_-eq'\'}).Count;if($depth-gt $MaxDepth){continue};$sample=New-Object byte[] ([Math]::Min($MaxSampleBytes,[int][Math]::Min($f.Length,[int]::MaxValue)));$s=[IO.File]::OpenRead($f.FullName);try{$n=$s.Read($sample,0,$sample.Length)}finally{$s.Dispose()};if($n-lt $sample.Length){$sample=$sample[0..([Math]::Max(0,$n-1))]};$print=0;foreach($b in $sample){if(($b-ge 32-and$b-le126)-or$b-eq9-or$b-eq10-or$b-eq13){$print++}};$ratio=if($sample.Length){$print/$sample.Length}else{0};$text=[Text.Encoding]::UTF8.GetString($sample);$xml=$text.TrimStart().StartsWith('<');$json=$text.TrimStart().StartsWith('{')-or$text.TrimStart().StartsWith('[');$shape=if($xml){'XML_like'}elseif($json){'JSON_like'}elseif($ratio-ge.8){'plaintext_text'}else{'binary_blob'};$safe=([IO.Path]::GetFileName($root)+'\'+$rel);$Files+=[ordered]@{id=('file_'+(Hash-Text $safe).Substring(0,20));safe_relative_path=$safe;sha256=(Hash-File $f.FullName);extension=$f.Extension.ToLowerInvariant();content_type='bounded_file_metadata';shape=$shape;size=$f.Length;creation_time=$f.CreationTimeUtc.ToString('o');last_write_time=$f.LastWriteTimeUtc.ToString('o');entropy=0;printable_ratio=[Math]::Round($ratio,4);xml=$xml;json=$json;multipart=($text-match '(?i)content-type:\s*multipart/');opaque=($shape-eq'binary_blob');warnings=@()}}}
$Registry=@();$RegistryKeys=@('HKLM:\SOFTWARE\Microsoft\CCM','HKLM:\SOFTWARE\Microsoft\CCMSetup');foreach($key in $RegistryKeys){if(-not(Test-Path -LiteralPath $key)){continue};try{$item=Get-Item -LiteralPath $key;foreach($name in @($item.GetValueNames()|Sort-Object|Select-Object -First 128)){$kind=[string]$item.GetValueKind($name);$v=$item.GetValue($name,$null,'DoNotExpandEnvironmentNames');$len=if($null-eq$v){0}else{([string]$v).Length};$Registry+=[ordered]@{id=('registry_'+(Hash-Text ($key+'|'+$name)).Substring(0,20));key_fingerprint=(Hash-Text $key).Substring(0,16);safe_key_label=[IO.Path]::GetFileName($key);value_name=$name;value_type=$kind;length_bucket=(Bucket $len);shape=(Shape $v);fingerprint=$(if($null-eq$v){''}else{Hash-Text ([string]$v)});warnings=@()}}}catch{$Errors.Add(('registry '+[IO.Path]::GetFileName($key)+': unavailable'))}}
$Result=[ordered]@{schema_version=1;collected_at=(Get-Date).ToUniversalTime().ToString('o');client_label='__CLIENT__';site_code='__SITE__';namespaces=$Namespaces;class_schemas=$Classes;instance_metadata=$Instances;file_artifacts=$Files;registry_artifacts=$Registry;errors=$Errors;warnings=@();live_policy_requests=0}
Write-UTF8 $OutputPath ($Result|ConvertTo-Json -Depth 10 -Compress)
Write-Host ("Passive local artifact discovery complete: namespaces={0} classes={1} instances={2} files={3} registry={4}" -f $Namespaces.Count,$Classes.Count,$Instances.Count,$Files.Count,$Registry.Count)
Write-Host "SCCM client methods invoked: 0"
Write-Host "Live SCCM policy requests: 0"
`

func Script() string { return discoveryPS }
func Summary(o CreateOptions) string {
	return fmt.Sprintf("client=%s site=%s", o.ClientLabel, o.SiteCode)
}
