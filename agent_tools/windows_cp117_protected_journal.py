"""Protected SYSTEM journal primitives for one fixed CP117 recovery task.

The PowerShell is intentionally generated from a caller supplied *fixed* root
and a finite set of leaf names.  It has no general path API and no deletion or
replacement operation.

Windows does not expose POSIX inode identity through the managed file APIs.
The reader therefore uses a FileShare.None handle, verifies the object before
and after the handle read, and treats every sharing or metadata change as a
failure.  This OS limitation is explicit: callers must keep a failed read
unknown and never turn it into a retry permission.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


class ProtectedJournalError(ValueError):
    pass


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
_FULL = 2_032_127
_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.json\Z")
_LEGACY_ROOT = re.compile(r"C:\\ProgramData\\VpnControl\\[A-Za-z0-9_.-]{1,80}\Z")
_DIRECT_ROOT = re.compile(
    r"C:\\ProgramData\\VpnControlCp117-(?:guest-agent|retirement)-"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_MAX_BYTES = 16_384


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _leaves(allowed_leaves: Sequence[str]) -> tuple[str, ...]:
    if isinstance(allowed_leaves, (str, bytes)):
        raise ProtectedJournalError("journal leaves must be a finite sequence")
    values = tuple(allowed_leaves)
    if not values or len(values) > 8 or len(set(values)) != len(values) or any(not isinstance(x, str) or not _LEAF.fullmatch(x) for x in values):
        raise ProtectedJournalError("journal leaves are invalid")
    return values


def acl_construction_powershell() -> str:
    """Build the exact protected journal ACL without touching the filesystem."""
    return r'''$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544')){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new(
  [Security.Principal.SecurityIdentifier]::new($sid),
  [Security.AccessControl.FileSystemRights]::FullControl,
  ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
  [Security.AccessControl.PropagationFlags]::None,
  [Security.AccessControl.AccessControlType]::Allow)
 [void]$acl.AddAccessRule($rule)
}'''


def powershell(rootpath: str, allowed_leaves: Sequence[str]) -> str:
    """Generate the fixed no-follow reader and create-only writer program."""
    if (not isinstance(rootpath, str)
            or not (_LEGACY_ROOT.fullmatch(rootpath) or _DIRECT_ROOT.fullmatch(rootpath))):
        raise ProtectedJournalError("journal root is outside the fixed ProgramData namespace")
    leaves = _leaves(allowed_leaves)
    allowed = ",".join(_literal(x) for x in leaves)
    return r'''$ErrorActionPreference='Stop'
$JournalRoot=@ROOT@;$AllowedLeaves=@(@LEAVES@);$MaxBytes=@MAX@
function Assert-NoReparse([IO.FileSystemInfo]$item,[string]$code){if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw $code}}
function Assert-Ancestors([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;for($node=$item;$null -ne $node;$node=$node.Parent){Assert-NoReparse $node 'ANCESTOR_REPARSE'}}
function AclRows([string]$path){$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;@($acl.Access|ForEach-Object {[ordered]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=[bool]$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})}
function Assert-LeafItem([IO.FileSystemInfo]$item,[string]$name){if($name -notin $AllowedLeaves){throw 'LEAF'};if($item.PSIsContainer){throw 'LEAF_TYPE'};Assert-NoReparse $item 'LEAF_REPARSE';if($item.Length -lt 1 -or $item.Length -gt $MaxBytes){throw 'LEAF_SIZE'};$acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop;if($acl.AreAccessRulesProtected){throw 'LEAF_ACL_PROTECTED'};$owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value;if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'LEAF_OWNER'};$rows=@(AclRows $item.FullName);if($rows.Count -ne 2){throw 'LEAF_ACL_COUNT'};$seen=@{};foreach($row in $rows){if($row.type -ne 'Allow' -or -not $row.inherited -or $row.inheritance -ne 0 -or $row.propagation -ne 0 -or $row.rights -ne 2032127 -or $row.sid -notin @('S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($row.sid)){throw 'LEAF_ACL'};$seen[$row.sid]=$true};if($seen.Count -ne 2){throw 'LEAF_ACL'};return $item}
function Assert-Root([string]$path){$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if(-not $item.PSIsContainer){throw 'ROOT_TYPE'};Assert-NoReparse $item 'ROOT_REPARSE';Assert-Ancestors $path;$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;if(-not $acl.AreAccessRulesProtected){throw 'ROOT_ACL_PROTECTED'};$owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value;if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw 'ROOT_OWNER'};$rows=@(AclRows $path);if($rows.Count -ne 2){throw 'ROOT_ACL_COUNT'};$seen=@{};foreach($row in $rows){if($row.type -ne 'Allow' -or $row.inherited -or $row.inheritance -ne 3 -or $row.propagation -ne 0 -or $row.rights -ne 2032127 -or $row.sid -notin @('S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($row.sid)){throw 'ROOT_ACL'};$seen[$row.sid]=$true};if($seen.Count -ne 2){throw 'ROOT_ACL'};foreach($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)){[void](Assert-LeafItem $child $child.Name)};return $item}
function Assert-Leaf([string]$name){if($name -notin $AllowedLeaves){throw 'LEAF'};[void](Assert-Root $JournalRoot);return (Assert-LeafItem (Get-Item -LiteralPath (Join-Path $JournalRoot $name) -Force -ErrorAction Stop) $name)}
function Initialize-SecureJournal {if(-not (Test-Path -LiteralPath $JournalRoot)){$parent=Split-Path -Parent $JournalRoot;if(-not (Test-Path -LiteralPath $parent)){throw 'PARENT_ABSENT'};Assert-Ancestors $parent;@ACL@[IO.Directory]::CreateDirectory($JournalRoot,$acl)|Out-Null};[void](Assert-Root $JournalRoot)}
function Read-SecureJson([string]$name){[void](Assert-Root $JournalRoot);$before=Assert-Leaf $name;$stream=[IO.File]::Open($before.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{if($stream.Length -ne $before.Length -or $stream.Length -lt 1 -or $stream.Length -gt $MaxBytes){throw 'HANDLE_SIZE'};$bytes=New-Object byte[] ([int]$stream.Length);$offset=0;while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw 'HANDLE_READ'};$offset+=$count};$after=Assert-Leaf $name;if($after.Length -ne $bytes.Length -or $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc){throw 'HANDLE_CHANGED'};return ([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -ErrorAction Stop)}finally{$stream.Dispose()}}
function Write-SecureJsonCreate([string]$name,[string]$json){Initialize-SecureJournal;if($name -notin $AllowedLeaves){throw 'LEAF'};if([string]::IsNullOrEmpty($json)){throw 'JSON'};$bytes=[Text.Encoding]::UTF8.GetBytes($json);if($bytes.Length -lt 2 -or $bytes.Length -gt $MaxBytes){throw 'JSON_SIZE'};[void]($json|ConvertFrom-Json -ErrorAction Stop);$path=Join-Path $JournalRoot $name;$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()};[void](Assert-Leaf $name)}
'''.replace("@ROOT@", _literal(rootpath)).replace("@LEAVES@", allowed).replace("@MAX@", str(_MAX_BYTES)).replace("@ACL@", acl_construction_powershell())


def validate_census(receipt: Mapping[str, Any], allowed_leaves: Sequence[str]) -> None:
    """Portable validation of the finite redacted PowerShell census shape."""
    leaves = _leaves(allowed_leaves)
    if not isinstance(receipt, Mapping) or set(receipt) != {"owner", "rootAcl", "leaves"}:
        raise ProtectedJournalError("journal census shape is invalid")
    if receipt["owner"] not in {SYSTEM_SID, ADMINISTRATORS_SID}:
        raise ProtectedJournalError("journal owner is invalid")
    _validate_acl(receipt["rootAcl"], inherited=False)
    rows = receipt["leaves"]
    if not isinstance(rows, list) or len(rows) > len(leaves):
        raise ProtectedJournalError("journal leaf census is invalid")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {"name", "bytes", "owner", "acl"} or row.get("name") not in leaves or row["name"] in seen or row.get("owner") not in {SYSTEM_SID, ADMINISTRATORS_SID} or type(row.get("bytes")) is not int or not 1 <= row["bytes"] <= _MAX_BYTES:
            raise ProtectedJournalError("journal leaf census is invalid")
        _validate_acl(row["acl"], inherited=True)
        seen.add(row["name"])


def _validate_acl(value: Any, *, inherited: bool) -> None:
    if not isinstance(value, Mapping) or set(value) != {"protected", "acl"} or value.get("protected") is not (not inherited):
        raise ProtectedJournalError("journal ACL is invalid")
    rows = value["acl"]
    if not isinstance(rows, list) or len(rows) != 2:
        raise ProtectedJournalError("journal ACL is invalid")
    seen: set[str] = set()
    for row in rows:
        if (not isinstance(row, Mapping) or set(row) != {"sid", "rights", "type", "inherited", "inheritance", "propagation"}
                or row.get("sid") not in {SYSTEM_SID, ADMINISTRATORS_SID} or row["sid"] in seen
                or row.get("rights") != _FULL or row.get("type") != "Allow" or row.get("inherited") is not inherited
                or row.get("inheritance") != (0 if inherited else 3) or row.get("propagation") != 0):
            raise ProtectedJournalError("journal ACL is invalid")
        seen.add(row["sid"])
