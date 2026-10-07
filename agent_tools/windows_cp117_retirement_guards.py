"""Narrow, non-mutating guards for retiring CP117's fixed Windows stage.

The stage receipt is the authority for the original staging result.  These
helpers turn its immutable intent into a deletion-time PowerShell census and
validate that census before a caller may remove the stage.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts.windows_fixture_stage_acl import (
    ADMINISTRATORS_SID,
    SYSTEM_SID,
    stage_acl_powershell,
    validate_stage_acl_receipt,
)


class RetirementGuardError(ValueError):
    """The locally saved intent or guest deletion census is unsafe."""


_STAGE_PREFIX = r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-"
_MAX_JOURNAL_BYTES = 16_384


def stage_root(correlation_id: str) -> str:
    """Return the only guest path this helper will admit for retirement."""
    try:
        if str(uuid.UUID(correlation_id)) != correlation_id:
            raise ValueError
    except (AttributeError, ValueError) as error:
        raise RetirementGuardError("stage correlation must be a canonical UUID") from error
    return _STAGE_PREFIX + correlation_id


def secure_directory(directory: Path) -> Path:
    """Create or admit an owner-only local journal directory."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RetirementGuardError("retirement journal directory is unsafe")
    return directory


def secure_read(path: Path) -> dict[str, Any] | None:
    """Read one bounded private JSON journal record without following links."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > _MAX_JOURNAL_BYTES):
            raise RetirementGuardError("retirement journal record is unsafe")
        try:
            value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise RetirementGuardError("retirement journal record is invalid") from error
    if not isinstance(value, dict):
        raise RetirementGuardError("retirement journal record is invalid")
    return value


def secure_write_create(path: Path, value: Mapping[str, Any]) -> None:
    """Durably create one private journal record; never replace a reservation."""
    data = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > _MAX_JOURNAL_BYTES:
        raise RetirementGuardError("retirement journal record is too large")
    secure_directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _intent_manifest(intent: Mapping[str, Any], correlation_id: str) -> tuple[str, int, dict[str, str]]:
    """Extract the fixed stage's immutable bundle and content manifest."""
    if not isinstance(intent, Mapping):
        raise RetirementGuardError("stage intent is invalid")
    request = intent.get("request")
    bundle_hash, bundle_size, files = intent.get("bundleSha256"), intent.get("bundleSize"), intent.get("fileHashes")
    if (not isinstance(request, Mapping) or request.get("correlationId") != correlation_id
            or not isinstance(bundle_hash, str) or len(bundle_hash) != 64
            or not isinstance(bundle_size, int) or not 0 < bundle_size <= 1_075_838_976
            or not isinstance(files, Mapping) or not files):
        raise RetirementGuardError("stage intent is invalid")
    manifest: dict[str, str] = {}
    for name, digest in files.items():
        if (not isinstance(name, str) or not name or name.startswith("/") or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or not isinstance(digest, str) or len(digest) != 64):
            raise RetirementGuardError("stage intent manifest is invalid")
        manifest[name] = digest.lower()
    return bundle_hash.lower(), bundle_size, manifest


def deletion_census_powershell(intent: Mapping[str, Any], correlation_id: str, recipient_sid: str) -> str:
    """Generate a read-only, exact-tree and ACL census bound to saved intent.

    ``stage_acl_powershell`` remains the authoritative ACL shape generator used
    at creation.  This code deliberately only reads the same three principal
    record shape so retirement cannot repair a weakened ACL before deleting it.
    """
    bundle_hash, bundle_size, manifest = _intent_manifest(intent, correlation_id)
    root = stage_root(correlation_id)
    # Validate the canonical expected ACL input through the creation authority;
    # discard its mutating script and emit a read-only verifier below.
    stage_acl_powershell(root, recipient_sid)
    expected = "\n".join(
        "$expected[{0}]={1}".format(_ps_literal(name), _ps_literal(digest))
        for name, digest in sorted(manifest.items())
    )
    directories = sorted({"/".join(name.split("/")[:index])
                          for name in manifest for index in range(1, len(name.split("/")))})
    expected_directories = "\n".join(
        "$expectedDirectories[{0}]=$true".format(_ps_literal(name)) for name in directories
    )
    return r'''$ErrorActionPreference='Stop'
$root=@ROOT@;$content=Join-Path $root 'content';$recipient=@SID@;$expected=@{};$expectedDirectories=@{}
@EXPECTED@
@EXPECTED_DIRECTORIES@
function Records([string]$path){$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;@($acl.Access|ForEach-Object {[ordered]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})}
function Safe([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'REPARSE'};return $item}
function AssertAcl([string]$path){$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;if(-not $acl.AreAccessRulesProtected){throw 'ACL_PROTECTED'};$expectedAcl=@{'S-1-5-18'=2032127;'S-1-5-32-544'=2032127;$recipient=1179817};$records=@(Records $path);if($records.Count -ne $expectedAcl.Count){throw 'ACL_COUNT'};$seen=@{};foreach($record in $records){if($record.type -ne 'Allow' -or $record.inherited -or $record.inheritance -ne 3 -or $record.propagation -ne 0 -or $seen.ContainsKey($record.sid) -or -not $expectedAcl.ContainsKey($record.sid) -or $expectedAcl[$record.sid] -ne $record.rights){throw 'ACL'};$seen[$record.sid]=$true};foreach($sid in $expectedAcl.Keys){if(-not $seen.ContainsKey($sid)){throw 'ACL'}}}
$rootItem=Safe $root;if(-not $rootItem.PSIsContainer){throw 'ROOT_TYPE'}
for($ancestor=$rootItem;$null -ne $ancestor;$ancestor=$ancestor.Parent){if(($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'ANCESTOR_REPARSE'}}
$all=@(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop);if(@($all|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0}).Count-ne 0){throw 'REPARSE'}
$names=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop|ForEach-Object {$_.Name}|Sort-Object);if(($names -join "`n") -cne ('bundle.zip' + "`ncontent`nresult.json`nserver-state")){throw 'TREE'}
$bundle=Safe (Join-Path $root 'bundle.zip');if($bundle.PSIsContainer -or $bundle.Length -ne @SIZE@ -or (Get-FileHash -LiteralPath $bundle.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne @HASH@){throw 'BUNDLE'}
$contentItem=Safe $content;if(-not $contentItem.PSIsContainer){throw 'CONTENT_TYPE'};AssertAcl $root;AssertAcl $content
$state=Safe (Join-Path $root 'server-state');if(-not $state.PSIsContainer){throw 'STATE_TYPE'};$stateNames=@($state.GetFileSystemInfos()|ForEach-Object {$_.Name}|Sort-Object);if(($stateNames -join "`n") -cne 'probe-events'){throw 'STATE_TREE'};$probe=Safe (Join-Path $state.FullName 'probe-events');if(-not $probe.PSIsContainer -or @($probe.GetFileSystemInfos()).Count -ne 0){throw 'PROBE_EVENTS'}
$result=Safe (Join-Path $root 'result.json');if($result.PSIsContainer){throw 'RESULT'};$receipt=Get-Content -LiteralPath $result.FullName -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop;if($receipt.correlationId -cne @CORR@ -or $receipt.bundleSha256 -cne @HASH@){throw 'RESULT'}
$directories=@(Get-ChildItem -LiteralPath $content -Force -Recurse -Directory -ErrorAction Stop);if($directories.Count -ne $expectedDirectories.Count){throw 'DIRECTORY_COUNT'};foreach($directory in $directories){$relative=$directory.FullName.Substring($content.Length+1).Replace('\','/');if(-not $expectedDirectories.ContainsKey($relative)){throw 'DIRECTORY_TREE'}}
$files=@(Get-ChildItem -LiteralPath $content -Force -Recurse -File -ErrorAction Stop);if($files.Count -ne $expected.Count){throw 'FILE_COUNT'};foreach($file in $files){$relative=$file.FullName.Substring($content.Length+1).Replace('\','/');if(-not $expected.ContainsKey($relative) -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$relative]){throw 'FILE_HASH'}}
$owner=(Get-Acl -LiteralPath $root -ErrorAction Stop).Owner;try{$owner=[Security.Principal.NTAccount]$owner;$owner=$owner.Translate([Security.Principal.SecurityIdentifier]).Value}catch{};if($owner -cnotin @('S-1-5-18','S-1-5-32-544')){throw 'OWNER'}
[ordered]@{owner=$owner;rootAcl=[ordered]@{stage=$root;protected=(Get-Acl -LiteralPath $root).AreAccessRulesProtected;acl=(Records $root)};contentAcl=[ordered]@{stage=$content;protected=(Get-Acl -LiteralPath $content).AreAccessRulesProtected;acl=(Records $content)};files=@($expected.Keys|Sort-Object)}|ConvertTo-Json -Compress -Depth 5
'''.replace("@ROOT@", _ps_literal(root)).replace("@SID@", _ps_literal(recipient_sid)).replace("@EXPECTED@", expected).replace("@EXPECTED_DIRECTORIES@", expected_directories).replace("@SIZE@", str(bundle_size)).replace("@HASH@", _ps_literal(bundle_hash)).replace("@CORR@", _ps_literal(correlation_id))


def validate_deletion_census(receipt: Mapping[str, Any], intent: Mapping[str, Any], correlation_id: str,
                             recipient_sid: str) -> None:
    """Require a trusted creator-owned root and the original protected ACLs."""
    _bundle_hash, _bundle_size, manifest = _intent_manifest(intent, correlation_id)
    if not isinstance(receipt, Mapping) or set(receipt) != {"owner", "rootAcl", "contentAcl", "files"}:
        raise RetirementGuardError("deletion census is invalid")
    if receipt["owner"] not in {SYSTEM_SID, ADMINISTRATORS_SID}:
        raise RetirementGuardError("stage root is not owned by a trusted creator")
    try:
        validate_stage_acl_receipt(receipt["rootAcl"], recipient_sid, stage_root(correlation_id))
        validate_stage_acl_receipt(receipt["contentAcl"], recipient_sid, stage_root(correlation_id) + r"\content")
    except ValueError as error:
        raise RetirementGuardError("stage ACL differs from the original protected ACL") from error
    if receipt["files"] != sorted(manifest):
        raise RetirementGuardError("deletion census manifest differs from saved stage intent")


def remaining_result_census_powershell(intent: Mapping[str, Any], correlation_id: str, recipient_sid: str) -> str:
    """Read-only census for the observed post-retirement root containing result only.

    The result is opened with ``FileShare.None`` so an uncertain competing writer
    yields a blocked observation rather than a stale read classification.
    """
    bundle_hash, _bundle_size, _manifest = _intent_manifest(intent, correlation_id)
    root = stage_root(correlation_id)
    stage_acl_powershell(root, recipient_sid)
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@
function Safe([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'REPARSE'};return $item}
$rootItem=Safe $root;if(-not $rootItem.PSIsContainer){throw 'ROOT'};for($ancestor=$rootItem;$null -ne $ancestor;$ancestor=$ancestor.Parent){if(($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'ANCESTOR'}}
$children=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop|ForEach-Object {$_.Name}|Sort-Object);if(($children -join "`n") -cne 'result.json'){throw 'TREE'}
$result=Safe (Join-Path $root 'result.json');if($result.PSIsContainer){throw 'RESULT_TYPE'};$stream=[IO.File]::Open($result.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{$reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true);try{$receipt=$reader.ReadToEnd()|ConvertFrom-Json -ErrorAction Stop}finally{$reader.Dispose()}}finally{$stream.Dispose()};if($receipt.correlationId -cne @CORR@ -or $receipt.bundleSha256 -cne @HASH@){throw 'RESULT'}
$acl=Get-Acl -LiteralPath $root -ErrorAction Stop;$records=@($acl.Access|ForEach-Object {[ordered]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}});[ordered]@{rootAcl=[ordered]@{stage=$root;protected=$acl.AreAccessRulesProtected;acl=$records};result='bound'}|ConvertTo-Json -Compress -Depth 4
'''.replace("@ROOT@", _ps_literal(root)).replace("@CORR@", _ps_literal(correlation_id)).replace("@HASH@", _ps_literal(bundle_hash))


def validate_remaining_result_census(receipt: Mapping[str, Any], correlation_id: str, recipient_sid: str) -> None:
    """Validate the redacted remaining-result census before reconciling it."""
    if not isinstance(receipt, Mapping) or set(receipt) != {"rootAcl", "result"} or receipt["result"] != "bound":
        raise RetirementGuardError("remaining result census is invalid")
    try:
        validate_stage_acl_receipt(receipt["rootAcl"], recipient_sid, stage_root(correlation_id))
    except ValueError as error:
        raise RetirementGuardError("remaining result root ACL is invalid") from error


def remaining_result_lock_diagnostic_powershell(correlation_id: str) -> str:
    """Return a read-only Restart Manager lock diagnosis for the fixed result file.

    The result deliberately contains neither a guest path nor process identity
    details.  Restart Manager is used only to enumerate; shutdown/restart calls
    are absent by construction.
    """
    result = stage_root(correlation_id) + r"\result.json"
    return r'''$ErrorActionPreference='Stop';$result=@RESULT@
try {
 $cause='none';try{$probe=[IO.File]::Open($result,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$probe.Dispose()}catch{$lockException=$_.Exception;while($null -ne $lockException.InnerException){$lockException=$lockException.InnerException};$low=([int64]$lockException.HResult -band 0xffff);$cause=if($low -eq 32){'low-hresult-32'}elseif($low -eq 33){'low-hresult-33'}else{'other'}}
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class VpnControlRestartManager {
 [StructLayout(LayoutKind.Sequential)] public struct RM_UNIQUE_PROCESS {public int dwProcessId;public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct RM_PROCESS_INFO {public RM_UNIQUE_PROCESS Process;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string strAppName;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)]public string strServiceShortName;public uint ApplicationType;public uint AppStatus;public uint TSSessionId;[MarshalAs(UnmanagedType.Bool)]public bool bRestartable;}
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] public static extern int RmStartSession(out uint handle,int flags,System.Text.StringBuilder key);
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] public static extern int RmRegisterResources(uint handle,uint files,string[] fileNames,uint apps,IntPtr app,uint services,string[] serviceNames);
 [DllImport("rstrtmgr.dll")] public static extern int RmGetList(uint handle,out uint needed,ref uint count,[In,Out] RM_PROCESS_INFO[] processes,ref uint rebootReasons);
 [DllImport("rstrtmgr.dll")] public static extern int RmEndSession(uint handle);
}
'@ -ErrorAction Stop
 $key=[Text.StringBuilder]::new(64);$handle=0;if([VpnControlRestartManager]::RmStartSession([ref]$handle,0,$key)-ne 0){throw 'RM_START'}
 try {
  if([VpnControlRestartManager]::RmRegisterResources($handle,1,@($result),0,[IntPtr]::Zero,0,$null)-ne 0){throw 'RM_REGISTER'}
  $needed=0;$count=0;$reasons=0;$code=[VpnControlRestartManager]::RmGetList($handle,[ref]$needed,[ref]$count,$null,[ref]$reasons)
  if($code -eq 234 -and $needed -gt 0){$count=$needed;$items=New-Object 'VpnControlRestartManager+RM_PROCESS_INFO[]' $count;$code=[VpnControlRestartManager]::RmGetList($handle,[ref]$needed,[ref]$count,$items,[ref]$reasons)}else{$items=@()}
  if($code -ne 0){throw ('RM_LIST_'+$code)}
  $processes=@($items|Select-Object -First $count);$classified=@();$exact=$false;foreach($rmProcess in $processes){try{$lockPid=[int]$rmProcess.Process.dwProcessId;$process=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$lockPid) -ErrorAction Stop;$name=[string]$process.Name;$service=@(Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object {[int]$_.ProcessId -eq $lockPid});if($name -imatch '^qemu-ga(\.exe)?$' -and @($service|Where-Object {$_.Name -ieq 'qemu-ga' -and $_.State -ieq 'Running' -and $_.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM')}).Count -eq 1){$classified+='qemu-ga';if($processes.Count -eq 1){$exact=$true}}elseif($name -imatch '^powershell(\.exe)?$'){$classified+='powershell'}else{$classified+='other'}}catch{$classified+='other'}}
  $kind=if($classified -contains 'qemu-ga'){'qemu-ga'}elseif($classified -contains 'powershell'){'powershell'}elseif($classified.Count -eq 0){'absent'}else{'other'};$bounded=[Math]::Min([int]$classified.Count,16)
  [ordered]@{cause=$cause;lockingProcess=$kind;count=$bounded;qemuGaExactLocalSystem=$exact}|ConvertTo-Json -Compress
 } finally {[void][VpnControlRestartManager]::RmEndSession($handle)}
} catch {
 if($cause -eq 'none'){$lockException=$_.Exception;while($null -ne $lockException.InnerException){$lockException=$lockException.InnerException};$low=([int64]$lockException.HResult -band 0xffff);$cause=if($low -eq 32){'low-hresult-32'}elseif($low -eq 33){'low-hresult-33'}else{'other'}};[ordered]@{cause=$cause;lockingProcess='other';count=0;qemuGaExactLocalSystem=$false}|ConvertTo-Json -Compress
}
'''.replace("@RESULT@", _ps_literal(result))


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"
