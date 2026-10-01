"""One-shot CP117 publication of a same-source, read-only update fixture bundle.

This stages data only.  It does not create TLS credentials, start the HTTPS
server, change JVM trust, or authorize an update check/download/install.
"""
from __future__ import annotations

import ast
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
import zipfile
from typing import Any, BinaryIO, Mapping

from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_cp117_lease as campaign_lease
from scripts.windows_fixture_stage_acl import stage_acl_powershell, validate_stage_acl_receipt


class WindowsUpdateFixtureStageError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GROUP = ".rag_index/windows-update-fixture-stage"
_GUEST = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_MODULES = ("prepare_desktop_update_fixture.py", "fixture_environment.py",
            "macos_packaging_jdk_preflight.py")


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId",
              "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsUpdateFixtureStageError("Fixture stage requires exact CP117 inputs.")
    for name, pattern in (("correlationId", _UUID), ("sourceSha", _SHA),
                          ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsUpdateFixtureStageError("Invalid fixture stage " + name + ".")
    if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
        raise WindowsUpdateFixtureStageError("Fixture stage correlation is not canonical.")
    return dict(value)


def _require_cross_route_lease(root: Path, request: Mapping[str, str], config: Any,
                               target: Any, descriptor: tuple[Any, ...]) -> str:
    """Read the exact active base campaign; its role is claimed after intent fsync."""
    return base._verified_active_campaign(root, request, descriptor, config, target,
                                          require_server=False)


def _closed_stage_history(root: Path, current_lease_id: str) -> None:
    """Retain prior stage evidence and admit only remotely confirmed closure."""
    detail = _closed_stage_history_detail(root, current_lease_id)
    if detail == "history-malformed-name":
        raise WindowsUpdateFixtureStageError("Fixture stage history is unknown.")
    if detail != "confirmed":
        raise WindowsUpdateFixtureStageError("Fixture stage history is active or unknown.")


def _closed_stage_history_detail(root: Path, current_lease_id: str) -> str:
    """Bound the prior-history admission without exposing leases or paths."""
    directory = root / _GROUP
    if not directory.exists():
        return "confirmed"
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        return "history-invalid"
    try:
        config, target, descriptor = base._descriptor(root)
        remote = base._campaign_remote(config, target)
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return "unknown"
    for path in directory.iterdir():
        if path.suffix != ".json":
            continue
        if not _UUID.fullmatch(path.stem) or str(uuid.UUID(path.stem)) != path.stem:
            return "history-malformed-name"
        try:
            prior = _read_intent(root, path.stem)
        except (OSError, ValueError, WindowsUpdateFixtureStageError):
            return "history-record-invalid"
        prior_lease = prior.get("leaseId") if prior else None
        if prior_lease is None or prior_lease == current_lease_id:
            return "history-record-invalid"
        # A filename and lease alone do not authorize historical admission.
        # Bind the original stage request, admitted source fingerprint and the
        # exact QEMU generation to the closed campaign identity before either
        # direct or successor remote confirmation can be used.
        try:
            prior_request = _request(prior.get("request", {}))
            pair = public._admit_pair(root, prior_request["sourceSha"], prior_request["fixtureReceiptArtifactId"],
                                      prior_request["baseMsiArtifactId"], prior_request["targetMsiArtifactId"])
            expected_identity = base._campaign_identity({**prior_request, "correlationId": prior_lease}, descriptor)
            if (prior_request["correlationId"] != path.stem
                    or prior.get("sourceFingerprint") != pair.get("sourceFingerprint")
                    or any(prior.get(name) != expected for name, expected in (("environment", descriptor[0]),
                        ("socketPath", descriptor[1]), ("pid", descriptor[2]), ("startTicks", descriptor[3]),
                        ("expectedSid", descriptor[4])))):
                return "history-record-invalid"
        except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
            return "history-record-invalid"
        try:
            campaign_directory, lock = campaign_lease._locked(root)
            try:
                closed = campaign_lease._closed(campaign_directory, prior_lease)
            finally:
                os.close(lock)
        except (OSError, ValueError, campaign_lease.Cp117LeaseError):
            return "unknown"
        if closed is None:
            return "old-closed-missing"
        if closed.get("identity") != expected_identity:
            return "history-record-invalid"
        if campaign_lease._remote_confirm(remote, "status", closed, None):
            continue
        # A campaign rebase keeps the old closed receipt locally while the
        # remote journal has a distinct active successor.  Its dedicated proof
        # binds both records in one read-only observation; no general bypass of
        # the ordinary closed-status requirement is allowed.
        try:
            active = campaign_lease._active(campaign_directory)
            current_identity = active.get("identity") if isinstance(active, dict) else None
            if (not isinstance(current_identity, dict) or current_identity.get("leaseId") != current_lease_id):
                return "remote-status-mismatch"
            from . import windows_cp117_campaign_status as campaign_status
            if not campaign_status._remote_closed_proof(config, target, closed, current_identity):
                return "remote-status-mismatch"
        except (OSError, ValueError, TypeError, ImportError, campaign_lease.Cp117LeaseError,
                base.WindowsMsiBasePrepareError):
            return "remote-status-mismatch"
    return "confirmed"


def _source_module(root: Path, source: str, name: str) -> bytes:
    if name not in _MODULES:
        raise WindowsUpdateFixtureStageError("Unexpected fixture entrypoint module.")
    try:
        result = subprocess.run(["git", "-C", str(root), "show", source + ":scripts/" + name],
                                capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WindowsUpdateFixtureStageError("Exact-source fixture module is unavailable.") from error
    if result.returncode or not 0 < len(result.stdout) <= 512 * 1024:
        raise WindowsUpdateFixtureStageError("Exact-source fixture module is unavailable.")
    return result.stdout


def _modules(root: Path, source: str) -> dict[str, bytes]:
    modules = {name: _source_module(root, source, name) for name in _MODULES}
    try:
        tree = ast.parse(modules[_MODULES[0]].decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError) as error:
        raise WindowsUpdateFixtureStageError("Exact-source fixture entrypoint is invalid.") from error
    _require_split_server_layout(tree)
    imports = {name for name in (
        [node.module.split(".", 1)[0] for node in ast.walk(tree)
         if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module] +
        [alias.name.split(".", 1)[0] for node in ast.walk(tree)
         if isinstance(node, ast.Import) for alias in node.names]
    )}
    try:
        listed = subprocess.run(["git", "-C", str(root), "ls-tree", "--name-only", source + ":scripts"],
                                capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WindowsUpdateFixtureStageError("Exact-source fixture import inventory is unavailable.") from error
    if listed.returncode != 0:
        raise WindowsUpdateFixtureStageError("Exact-source fixture import inventory is unavailable.")
    local = imports & {Path(name).stem for name in listed.stdout.splitlines() if name.endswith(".py")}
    expected = {Path(name).stem for name in _MODULES[1:]}
    if local != expected:
        raise WindowsUpdateFixtureStageError("Exact-source fixture import inventory changed.")
    return modules


def _require_split_server_layout(tree: ast.Module) -> None:
    """Admit only an entrypoint with the Windows immutable/private sibling layout."""
    serve = next((node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == "serve"), None)
    if serve is None:
        raise WindowsUpdateFixtureStageError("Exact-source fixture server layout is unavailable.")
    strings = {node.value for node in ast.walk(serve)
               if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    calls = {node.func.id for node in ast.walk(serve)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    if (not {"content", "server-state", "ready.json", "fixture-receipt.json"}.issubset(strings)
            or not {"require_windows_private_acl", "probe_events_path",
                    "write_private_ready_json"}.issubset(calls)
            or not any(isinstance(node, ast.IfExp) and isinstance(node.test, ast.Name)
                       and node.test.id == "windows" and isinstance(node.body, ast.Name)
                       and node.body.id == "state" for node in ast.walk(serve))):
        raise WindowsUpdateFixtureStageError("Exact-source fixture server layout is unavailable.")


def _open_registered(path: Path, maximum: int) -> BinaryIO:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        os.close(fd)
        raise WindowsUpdateFixtureStageError("Registered fixture file is unsafe.")
    return os.fdopen(fd, "rb")


def _bundle(root: Path, request: Mapping[str, str], pair: Mapping[str, Any]) -> tuple[BinaryIO, dict[str, str], int, str]:
    receipt = public._verified_location(root, request["fixtureReceiptArtifactId"],
                                        "fixture-receipt", request["sourceSha"])
    target = public._verified_location(root, request["targetMsiArtifactId"],
                                       "desktop-package", request["sourceSha"])
    modules = _modules(root, request["sourceSha"])
    with _open_registered(receipt, 1024 * 1024) as stream:
        receipt_bytes = stream.read(1024 * 1024 + 1)
    if hashlib.sha256(receipt_bytes).hexdigest() != request["fixtureReceiptArtifactId"].removeprefix("sha256-"):
        raise WindowsUpdateFixtureStageError("Registered fixture receipt changed.")
    members = {"fixture-receipt.json": receipt_bytes,
               **{"server/" + name: data for name, data in modules.items()}}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in members.items()}
    target_member = "packages/target/" + target.name
    hashes[target_member] = pair["targetMsiSha256"]
    output = tempfile.TemporaryFile(mode="w+b")
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for name in sorted(members):
                archive.writestr(name, members[name])
            digest = hashlib.sha256()
            count = 0
            with _open_registered(target, 1024 ** 3) as source, archive.open(target_member, "w", force_zip64=True) as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(chunk)
                    digest.update(chunk)
                    count += len(chunk)
            if digest.hexdigest() != pair["targetMsiSha256"] or count != pair["targetMsiSize"]:
                raise WindowsUpdateFixtureStageError("Registered target MSI changed during staging.")
    except BaseException:
        output.close()
        raise
    size = output.tell()
    if size > 1024 ** 3 + 2 * 1024 * 1024:
        output.close()
        raise WindowsUpdateFixtureStageError("Fixture stage bundle is too large.")
    output.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: output.read(1024 * 1024), b""):
        digest.update(chunk)
    output.seek(0)
    return output, hashes, size, digest.hexdigest()


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    try:
        fd = os.open(_intent_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsUpdateFixtureStageError("Fixture stage intent is unsafe.")
        try: value = json.load(stream)
        except (ValueError, TypeError) as error:
            raise WindowsUpdateFixtureStageError("Fixture stage intent is invalid.") from error
    if (not isinstance(value, dict) or not isinstance(value.get("request"), dict)
            or value["request"].get("correlationId") != correlation
            or not isinstance(value.get("sourceFingerprint"), str)
            or not _HASH.fullmatch(value["sourceFingerprint"])
            or not isinstance(value.get("bundleSha256"), str)
            or not _HASH.fullmatch(value["bundleSha256"])
            or not isinstance(value.get("fileHashes"), dict)):
        raise WindowsUpdateFixtureStageError("Fixture stage intent is invalid.")
    if not isinstance(value.get("leaseId"), str) or not _UUID.fullmatch(value["leaseId"]) or \
            str(uuid.UUID(value["leaseId"])) != value["leaseId"]:
        raise WindowsUpdateFixtureStageError("Fixture stage lease identity is invalid.")
    return value


def _reserve(root: Path, record: dict[str, Any], bundle: BinaryIO) -> Path:
    _closed_stage_history(root, record["leaseId"])
    directory = root / _GROUP
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureStageError("Fixture stage journal is unsafe.")
    lock = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT |
                   getattr(os, "O_NOFOLLOW", 0), 0o600)
    correlation = record["request"]["correlationId"]
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _closed_stage_history(root, record["leaseId"])
        bundle_path = directory / (correlation + ".zip")
        fd = os.open(bundle_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            shutil.copyfileobj(bundle, stream, 1024 * 1024)
            stream.flush(); os.fsync(stream.fileno())
        fd = os.open(_intent_path(root, correlation), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY)
        try: os.fsync(parent)
        finally: os.close(parent)
        return bundle_path
    finally:
        os.close(lock)


def _stage_script(correlation: str, sid: str, hashes: Mapping[str, str], bundle_hash: str) -> str:
    stage = _GUEST + "\\mcp-update-fixture-" + correlation
    content = stage + "\\content"
    state = stage + "\\server-state"
    names = sorted(hashes)
    assignments = "\n".join("$expected[@NAME@]=@HASH@".replace("@NAME@", public._ps_literal(name))
                             .replace("@HASH@", public._ps_literal(hashes[name])) for name in names)
    acl = stage_acl_powershell(content, sid)
    root_acl = stage_acl_powershell(stage, sid)
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$content=@CONTENT@;$download=Join-Path $root 'download';$incoming=Join-Path $download 'bundle.zip';$archive=Join-Path $root 'bundle.zip'
try {
 if(-not [IO.File]::Exists($incoming) -or (Get-FileHash -LiteralPath $incoming -Algorithm SHA256).Hash.ToLowerInvariant() -cne @BUNDLE_HASH@){throw 'BUNDLE_HASH'}
 Move-Item -LiteralPath $incoming -Destination $archive -ErrorAction Stop
 Remove-Item -LiteralPath $download -Force -Recurse -ErrorAction Stop
 if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne @BUNDLE_HASH@){throw 'PLACED_BUNDLE_HASH'}
 if([IO.Directory]::Exists($content)){throw 'EXISTING_CONTENT'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 [IO.Compression.ZipFile]::ExtractToDirectory($archive,$content)
 $expected=@{}
@ASSIGNMENTS@
 $files=@(Get-ChildItem -LiteralPath $content -Recurse -File)
 if($files.Count -ne $expected.Count){throw 'FILE_COUNT'}
 $targetCount=0
 foreach($file in $files){
  if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'REPARSE'}
  $relative=$file.FullName.Substring($content.Length+1).Replace('\','/')
  if(-not $expected.ContainsKey($relative) -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$relative]){throw 'FILE_HASH'}
  if($relative -cmatch '^packages/target/[^/\\]+\.msi$'){
   $targetCount++
   $file.IsReadOnly=$true
   $file.Refresh()
   if(-not $file.IsReadOnly -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$relative]){throw 'TARGET_READONLY'}
  }
 }
 if($targetCount -ne 1){throw 'TARGET_COUNT'}
 $aclReceipt=(& { @ACL@ })
 $aclObject=ConvertFrom-Json -InputObject ($aclReceipt|Out-String)
 if($aclObject.stage -cne $content -or $aclObject.protected -ne $true){throw 'ACL'}
 $rootReceipt=(& { @ROOT_ACL@ })
 $rootObject=ConvertFrom-Json -InputObject ($rootReceipt|Out-String)
 $statePath=Join-Path $root 'server-state';$stateItem=Get-Item -LiteralPath $statePath -Force
 if(-not $stateItem.PSIsContainer -or @($stateItem.GetFileSystemInfos()).Count -ne 0){throw 'STATE_NOT_EMPTY'}
 $stateAcl=Get-Acl -LiteralPath $statePath
 $stateRecords=@($stateAcl.Access|ForEach-Object {[pscustomobject]@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})
 $stateObject=[pscustomobject]@{stage=$statePath;protected=$stateAcl.AreAccessRulesProtected;acl=$stateRecords}
 ([pscustomobject]@{version=1;correlationId=@CORR@;code='STAGED_NOT_SERVER_READY';bundleSha256=@BUNDLE_HASH@;files=$expected;acl=$aclObject;rootAcl=$rootObject;stateAcl=$stateObject}|ConvertTo-Json -Depth 8 -Compress)|Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8
}catch{([pscustomobject]@{version=1;correlationId=@CORR@;code='UNKNOWN'}|ConvertTo-Json -Compress)|Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8;exit 1}
'''.replace("@ROOT@", public._ps_literal(stage)).replace("@CONTENT@", public._ps_literal(content)).replace(
        "@BUNDLE_HASH@", public._ps_literal(bundle_hash)).replace("@ASSIGNMENTS@", assignments).replace(
        "@ACL@", acl).replace("@ROOT_ACL@", root_acl).replace("@CORR@", public._ps_literal(correlation))


def _create_script(correlation: str, sid: str) -> str:
    """Atomically create immutable RX parent and empty private writable state."""
    root = _GUEST + "\\mcp-update-fixture-" + correlation
    return r'''$ErrorActionPreference='Stop';$root=@ROOT@;$recipient=@SID@
function SafeAncestors([string]$path) {
 $current=$path
 while($null -ne $current -and $current -ne ''){
  # Re-fetch every ancestor.  ``DirectoryInfo.Parent`` loses the provider's
  # PSIsContainer note, which can turn a valid ancestor into a false type
  # failure before any fixture directory is created.
  $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'REPARSE_ANCESTOR'}
  $parent=Split-Path -Parent $current
  if($parent -ceq $current){break}
  $current=$parent
 }
}
SafeAncestors (Split-Path -Parent $root)
if([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)){throw 'EXISTING_STAGE'}
function Security([bool]$private) {
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
 foreach($sid in @('S-1-5-18','S-1-5-32-544',$recipient)){
  $rights=if($sid -ceq $recipient -and -not $private){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
  $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),$rights,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
  [void]$acl.AddAccessRule($rule)
 }
 return $acl
}
[IO.Directory]::CreateDirectory($root,(Security $false))|Out-Null
[IO.Directory]::CreateDirectory((Join-Path $root 'download'),(Security $true))|Out-Null
[IO.Directory]::CreateDirectory((Join-Path $root 'server-state'),(Security $true))|Out-Null
SafeAncestors $root
SafeAncestors (Join-Path $root 'download')
SafeAncestors (Join-Path $root 'server-state')
'''.replace("@ROOT@", public._ps_literal(root)).replace("@SID@", public._ps_literal(sid))


def _validate_state_acl(receipt: Any, sid: str, expected_path: str) -> None:
    if not isinstance(receipt, dict) or set(receipt) != {"stage", "protected", "acl"} or \
            receipt["stage"] != expected_path or receipt["protected"] is not True or \
            not isinstance(receipt["acl"], list) or len(receipt["acl"]) != 3:
        raise WindowsUpdateFixtureStageError("Fixture server state ACL is invalid.")
    expected = {"S-1-5-18", "S-1-5-32-544", sid}
    observed = set()
    for entry in receipt["acl"]:
        if (not isinstance(entry, dict) or set(entry) != {"sid", "rights", "type", "inherited",
                "inheritance", "propagation"} or entry["sid"] not in expected or
                entry["sid"] in observed or entry["rights"] != 0x1F01FF or
                entry["type"] != "Allow" or entry["inherited"] is not False or
                entry["inheritance"] != 3 or entry["propagation"] != 0):
            raise WindowsUpdateFixtureStageError("Fixture server state ACL is invalid.")
        observed.add(entry["sid"])
    if observed != expected:
        raise WindowsUpdateFixtureStageError("Fixture server state ACL is invalid.")


def _complete_stage_lease(root: Path, intent: Mapping[str, Any], result: Mapping[str, Any],
                          config: Any, target: Any, descriptor: tuple[Any, ...]) -> bool:
    lease_id = intent.get("leaseId")
    if not isinstance(lease_id, str) or not _UUID.fullmatch(lease_id) or str(uuid.UUID(lease_id)) != lease_id:
        return False
    remote = base._campaign_remote(config, target)
    directory, lock = campaign_lease._locked(root)
    try:
        current = campaign_lease._active(directory)
        expected = base._campaign_identity({**intent["request"], "correlationId": lease_id}, descriptor)
        if current is None or current["identity"] != expected or current["server"] not in {
                "stopped", "starting", "live", "stopping"}:
            return False
        if current["state"] == "role-active" and current["role"] == "stage" and \
                current["correlationId"] == intent["request"]["correlationId"] and current["server"] == "stopped":
            pending = True
        elif current["state"] == "active" and current["role"] is None:
            pending = False
        elif current["state"] == "role-active" and current["role"] in {
                "credentials", "credentials-cleanup", "server-start", "server-stop", "target", "public"}:
            pending = False
        else:
            return False
        if not campaign_lease._remote_confirm(remote, "status", current, None):
            return False
    finally:
        os.close(lock)
    if pending:
        digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        completed = campaign_lease.finish_role(root, lease_id, "stage",
                                               intent["request"]["correlationId"],
                                               digest, "succeeded", remote)
        return completed.get("state") == "active"
    return True


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value)
    corr = request["correlationId"]
    prior = _read_intent(root, corr)
    if prior is not None:
        if prior.get("request") != request:
            raise WindowsUpdateFixtureStageError("Correlation binds another fixture stage.")
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    bundle, hashes, bundle_size, bundle_hash = _bundle(root, request, pair)
    try:
        script = _stage_script(corr, sid, hashes, bundle_hash)
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        create_encoded = base64.b64encode(_create_script(corr, sid).encode("utf-16le")).decode("ascii")
        if len(encoded) >= 30000 or len(create_encoded) >= 30000:
            raise WindowsUpdateFixtureStageError("Fixed fixture stage script exceeds QGA command admission.")
        lease_id = _require_cross_route_lease(root, request, config, target, descriptor)
        record = {"request": request, "environment": env, "socketPath": socket, "pid": pid,
                  "startTicks": ticks, "expectedSid": sid, "sourceFingerprint": pair["sourceFingerprint"],
                  "bundleSha256": bundle_hash, "bundleSize": bundle_size, "fileHashes": hashes,
                  "commandSha256": hashlib.sha256(script.encode("utf-16le")).hexdigest(),
                  "leaseId": lease_id}
        source = _reserve(root, record, bundle)
    finally:
        bundle.close()
    claimed = campaign_lease.claim_role(root, lease_id, "stage", corr,
                                        base._campaign_remote(config, target))
    if claimed.get("state") != "role-active":
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    raw = base._remote(config, _REMOTE_START, (str(target.fixture_transfer_root), env, lease_id, corr, socket,
        str(pid), str(ticks), sid, str(bundle_size), bundle_hash, create_encoded, encoded,
        request["sourceSha"], pair["sourceFingerprint"], request["fixtureReceiptArtifactId"],
        request["baseMsiArtifactId"], request["targetMsiArtifactId"]), source, 1800)
    try: result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): result = {}
    if not isinstance(result, dict) or result.get("state") != "submitted" or result.get("correlationId") != corr:
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    return {"state": "submitted", "correlationId": corr, "replayAllowed": False}


_PRIVATE_REMOTE_JSON = r'''
def save_private_json(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 if not 0<len(raw)<=8192:raise ValueError()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as file:
  info=os.fstat(file.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  file.write(raw);file.flush();os.fsync(file.fileno())
 parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
 try:os.fsync(parent)
 finally:os.close(parent)
'''


_REMOTE_START = base._QGA + campaign_lease.remote_role_guard() + _PRIVATE_REMOTE_JSON + r'''import fcntl,time,uuid
root,env,lease,corr,sock,pid,ticks,sid,size_text,bundle_hash,create_encoded,encoded,source,fingerprint,receipt_id,base_id,target_id=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 require_campaign_role(root,env,lease,'stage',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-update-fixture-stage')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  info=os.fstat(lock)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(lock,fcntl.LOCK_EX)
  for name in os.listdir(group):
   if name=='.environment.lock':continue
   old_job=os.path.join(group,name);info=os.lstat(old_job)
   if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700 or str(uuid.UUID(name))!=name:raise ValueError()
   binding_path=os.path.join(old_job,'binding.json');info=os.lstat(binding_path)
   if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>8192:raise ValueError()
   with open(binding_path,encoding='utf-8') as file:old=json.load(file)
   old_lease=old.get('leaseId')
   if old.get('correlationId')!=name or not isinstance(old_lease,str) or str(uuid.UUID(old_lease))!=old_lease or old_lease==lease:raise ValueError()
   closed_path=os.path.join(parent,'windows-cp117-campaign',old_lease+'.closed.json');info=os.lstat(closed_path)
   if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError()
   with open(closed_path,encoding='utf-8') as file:closed=json.load(file)
   identity=closed.get('identity',{})
   if closed.get('state')!='closed' or closed.get('server')!='stopped' or closed.get('credentials')=='ready' or identity.get('leaseId')!=old_lease or identity.get('sourceSha')!=old.get('sourceSha') or identity.get('fixtureReceiptArtifactId')!=old.get('fixtureReceiptArtifactId') or identity.get('baseMsiArtifactId')!=old.get('baseMsiArtifactId') or identity.get('targetMsiArtifactId')!=old.get('targetMsiArtifactId') or identity.get('socketPath')!=old.get('socketPath') or identity.get('qemuPid')!=old.get('pid') or identity.get('startTicks')!=old.get('startTicks'):raise ValueError()
  stage=os.path.join(group,corr);os.mkdir(stage,0o700)
 finally:os.close(lock)
 binding={'correlationId':corr,'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'leaseId':lease,'sourceSha':source,'sourceFingerprint':fingerprint,'bundleSha256':bundle_hash,'expectedSid':sid,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id}
 save_private_json(os.path.join(stage,'binding.json'),binding)
 size=int(size_text)
 if not 0<size<=1075838976 or len(encoded)>30000 or len(create_encoded)>30000:raise ValueError()
 guest='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-'+corr
 create=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',create_encoded],'capture-output':True})
 for i in range(30):
  state=call(sock,'guest-exec-status',{'pid':create['pid']})
  if state.get('exited') is True:
   if state.get('exitcode')!=0:raise ValueError()
   break
  time.sleep(.2)
 else:raise ValueError()
 handle=call(sock,'guest-file-open',{'path':guest+'\\download\\bundle.zip','mode':'wb'});h=hashlib.sha256();remaining=size
 try:
  while remaining:
   part=sys.stdin.buffer.read(min(49152,remaining))
   if not part:raise ValueError()
   h.update(part);remaining-=len(part);offset=0
   while offset<len(part):
    written=call(sock,'guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part[offset:]).decode()})['count']
    if type(written) is not int or not 0<written<=len(part)-offset:raise ValueError()
    offset+=written
  if sys.stdin.buffer.read(1):raise ValueError()
  call(sock,'guest-file-flush',{'handle':handle})
 finally:call(sock,'guest-file-close',{'handle':handle})
 if h.hexdigest()!=bundle_hash:raise ValueError()
 task=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 save_private_json(os.path.join(stage,'dispatch.json'),{'pid':task['pid']})
 out({'state':'submitted','correlationId':corr})
except FileExistsError:out({'state':'unknown','correlationId':corr,'reason':'existing-intent'})
except Exception:out({'state':'unknown','correlationId':corr,'reason':'submission-uncertain'})
'''


_REMOTE_STATUS = base._QGA + r'''root,env,lease,corr,sock,pid,ticks,sid,source,fingerprint,bundle_hash,receipt_id,base_id,target_id=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 stage=os.path.join(root,env,'windows-update-fixture-stage',corr)
 for path in (root,os.path.join(root,env),os.path.dirname(stage),stage):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 for name in ('binding.json','dispatch.json'):
  info=os.lstat(os.path.join(stage,name))
  if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>8192:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 if binding!={'correlationId':corr,'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'leaseId':lease,'sourceSha':source,'sourceFingerprint':fingerprint,'bundleSha256':bundle_hash,'expectedSid':sid,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id}:raise ValueError()
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if type(dispatch.get('pid')) is not int or dispatch['pid']<=0:raise ValueError()
 # QGA guest-exec-status may be consumed by the original one-shot wait.  A
 # bounded result receipt is therefore the first terminal proof.  The caller
 # still validates its full hashes and ACLs before completing the stage lease.
 raw=read(sock,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-'+corr+'\\result.json')
 if raw is not None:
  if not 0<len(raw)<=8192:raise ValueError()
  out({'state':'observed','correlationId':corr,'result':json.loads(decode(raw))});raise SystemExit(0)
 process=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 if process.get('exited') is not True:out({'state':'running','correlationId':corr});raise SystemExit(0)
 if process.get('exitcode')!=0 or process.get('out-truncated') is not False or process.get('err-truncated') is not False:raise ValueError()
 out({'state':'unknown','correlationId':corr})
except Exception:out({'state':'unknown','correlationId':corr})
'''


# This projection is deliberately read-only.  It exists for a lost stage
# response: a one-shot QGA bundle write cannot be safely retried merely because
# the observer did not receive its receipt.  It reveals no guest path, account,
# handle, process identifier, or raw receipt/log content.
_REMOTE_DIAGNOSTIC = base._QGA + r'''import time
root,env,lease,corr,sock,pid,ticks,sid,source,fingerprint,bundle_hash,size_text,receipt_id,base_id,target_id=sys.argv[1:]
def out(phase,binding='exact'):print(json.dumps({'state':'diagnosed','correlationId':corr,'binding':binding,'phase':phase},separators=(',',':'),sort_keys=True))
def directory(path):
 info=os.lstat(path)
 return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
def private_file(path):
 info=os.lstat(path)
 return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=8192
def guest_stage():
 script="$ErrorActionPreference='Stop';$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-"+corr+"\\download';$bundle=Join-Path $leaf 'bundle.zip';$expected="+size_text+";$hash='"+bundle_hash+"';try{if(-not [IO.Directory]::Exists($leaf) -or -not [IO.File]::Exists($bundle)){[Console]::Out.WriteLine('{\"version\":1,\"stage\":\"absent\"}')}else{$item=Get-Item -LiteralPath $bundle -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'TYPE'};$ok=($item.Length -eq $expected -and (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $hash);$state=if($ok){'full'}else{'partial'};[Console]::Out.WriteLine(([pscustomobject]@{version=1;stage=$state}|ConvertTo-Json -Compress))}}catch{[Console]::Out.WriteLine('{\"version\":1,\"stage\":\"unknown\"}');exit 1}"
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 if len(encoded)>=30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (type(item.get('exitcode')) is not int or item.get('exitcode')!=0
     or item.get('out-truncated') is not False or item.get('err-truncated') is not False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if value not in ({'version':1,'stage':'absent'},{'version':1,'stage':'partial'},{'version':1,'stage':'full'}):raise ValueError()
 return value['stage']
try:
 if env!='windows-cp117' or not live(sock,pid,ticks) or not 0<int(size_text)<=1075838976:raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-update-fixture-stage');stage=os.path.join(group,corr)
 if not all(directory(path) for path in (root,parent)):out('remote-layout-invalid');raise SystemExit(0)
 if not os.path.lexists(group):out('remote-stage-absent');raise SystemExit(0)
 if not directory(group):out('remote-layout-invalid');raise SystemExit(0)
 if not os.path.lexists(stage):out('remote-stage-absent');raise SystemExit(0)
 if not directory(stage):out('remote-stage-partial');raise SystemExit(0)
 names=set(os.listdir(stage))
 if 'binding.json' not in names or not private_file(os.path.join(stage,'binding.json')):out('remote-binding-mismatch','mismatch');raise SystemExit(0)
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 expected={'correlationId':corr,'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'leaseId':lease,'sourceSha':source,'sourceFingerprint':fingerprint,'bundleSha256':bundle_hash,'expectedSid':sid,'fixtureReceiptArtifactId':receipt_id,'baseMsiArtifactId':base_id,'targetMsiArtifactId':target_id}
 if binding!=expected:out('remote-binding-mismatch','mismatch');raise SystemExit(0)
 if names=={'binding.json'}:
  try:stage_state=guest_stage()
  except Exception:out('guest-stage-probe-failed');raise SystemExit(0)
  out('guest-stage-'+stage_state);raise SystemExit(0)
 if names!={'binding.json','dispatch.json'} or not private_file(os.path.join(stage,'dispatch.json')):out('remote-dispatch-malformed');raise SystemExit(0)
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:out('remote-dispatch-malformed');raise SystemExit(0)
 # A durable result receipt remains observable after the original QGA status
 # poll consumed the child status.  It is only a diagnostic here; status()
 # performs full receipt, hash, and ACL validation before reconciliation.
 try:raw=read(sock,'C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-'+corr+'\\result.json')
 except Exception:out('result-read-failed');raise SystemExit(0)
 if raw is not None:
  if not 0<len(raw)<=8192:out('receipt-invalid');raise SystemExit(0)
  try:value=json.loads(decode(raw))
  except Exception:out('receipt-invalid');raise SystemExit(0)
  if not isinstance(value,dict) or value.get('correlationId')!=corr:out('receipt-invalid');raise SystemExit(0)
  out('receipt-present-unverified');raise SystemExit(0)
 try:process=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 except Exception:out('dispatch-status-unknown');raise SystemExit(0)
 if process.get('exited') is False:out('receipt-pending');raise SystemExit(0)
 if (process.get('exited') is not True or type(process.get('exitcode')) is not int
     or process.get('out-truncated') is not False or process.get('err-truncated') is not False):out('dispatch-status-unknown');raise SystemExit(0)
 out('receipt-absent')
except Exception:out('qga-protocol','unverified')
'''


_DIAGNOSTIC_PHASES = {
    "remote-layout-invalid", "remote-stage-absent", "remote-stage-partial",
    "remote-binding-mismatch", "remote-dispatch-malformed", "guest-stage-absent",
    "guest-stage-partial", "guest-stage-full", "guest-stage-probe-failed",
    "dispatch-status-unknown", "receipt-pending", "receipt-absent",
    "result-read-failed", "receipt-invalid", "receipt-present-unverified",
    "qga-protocol",
}


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Bound an uncertain stage to its original source, campaign, and VM generation."""
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not isinstance(value["correlationId"], str) or not _UUID.fullmatch(value["correlationId"])
            or str(uuid.UUID(value["correlationId"])) != value["correlationId"]):
        raise WindowsUpdateFixtureStageError("Fixture stage diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    unknown = {"state": "unknown", "correlationId": corr, "binding": "unverified",
               "phase": "local-intent", "replayAllowed": False, "nativeActionAllowed": False}
    root = Path(root).resolve(strict=True)
    try:
        intent = _read_intent(root, corr)
        if intent is None:
            return unknown
        request = _request(intent["request"])
        if (not isinstance(intent.get("bundleSize"), int) or not 0 < intent["bundleSize"] <= 1075838976
                or not isinstance(intent.get("bundleSha256"), str) or not _HASH.fullmatch(intent["bundleSha256"])
                or not isinstance(intent.get("fileHashes"), dict)):
            return unknown
        pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                  request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if intent["sourceFingerprint"] != pair["sourceFingerprint"]:
            return {**unknown, "phase": "local-artifact"}
        config, target, descriptor = base._descriptor(root)
        env, socket, pid, ticks, sid = descriptor
        if any(intent.get(key) != expected for key, expected in (
                ("environment", env), ("socketPath", socket), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid))):
            return {**unknown, "binding": "mismatch", "phase": "descriptor"}
        base._verified_claimed_campaign(root, request, descriptor, config, target,
                                       intent["leaseId"], "stage")
        raw = base._remote(config, _REMOTE_DIAGNOSTIC, (str(target.fixture_transfer_root), env,
            intent["leaseId"], corr, socket, str(pid), str(ticks), sid, request["sourceSha"],
            pair["sourceFingerprint"], intent["bundleSha256"], str(intent["bundleSize"]),
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"]), None, 120)
        observed = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError, WindowsUpdateFixtureStageError,
            base.WindowsMsiBasePrepareError):
        return {**unknown, "phase": "qga-protocol"}
    if (not isinstance(observed, dict) or set(observed) != {"state", "correlationId", "binding", "phase"}
            or observed.get("state") != "diagnosed" or observed.get("correlationId") != corr
            or observed.get("binding") not in {"exact", "mismatch", "unverified"}
            or observed.get("phase") not in _DIAGNOSTIC_PHASES):
        return {**unknown, "phase": "qga-protocol"}
    phase, binding = observed["phase"], observed["binding"]
    if phase == "remote-binding-mismatch" and binding != "mismatch":
        return {**unknown, "phase": "qga-protocol"}
    if phase != "remote-binding-mismatch" and binding != "exact" and phase != "qga-protocol":
        return {**unknown, "phase": "qga-protocol"}
    return {"state": "unknown", "correlationId": corr, "binding": binding, "phase": phase,
            "replayAllowed": False, "nativeActionAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not isinstance(value["correlationId"], str) or not _UUID.fullmatch(value["correlationId"]):
        raise WindowsUpdateFixtureStageError("Fixture stage status requires exact correlationId.")
    root = Path(root).resolve(strict=True); corr = value["correlationId"]
    intent = _read_intent(root, corr)
    unknown = {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    if intent is None: return unknown
    if not isinstance(intent.get("leaseId"), str) or not _UUID.fullmatch(intent["leaseId"]): return unknown
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", socket),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))): return unknown
    raw = base._remote(config, _REMOTE_STATUS, (str(target.fixture_transfer_root), env, intent["leaseId"], corr,
        socket, str(pid), str(ticks), sid, intent["request"]["sourceSha"], intent["sourceFingerprint"],
        intent["bundleSha256"], intent["request"]["fixtureReceiptArtifactId"],
        intent["request"]["baseMsiArtifactId"], intent["request"]["targetMsiArtifactId"]), None, 30)
    try: observed = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): return unknown
    if not isinstance(observed, dict) or observed.get("correlationId") != corr: return unknown
    if observed.get("state") == "running": return {"state": "running", "correlationId": corr, "replayAllowed": False}
    result = observed.get("result")
    if observed.get("state") != "observed" or not isinstance(result, dict): return unknown
    if (set(result) != {"version", "correlationId", "code", "bundleSha256", "files", "acl", "rootAcl", "stateAcl"}
            or result["version"] != 1 or result["correlationId"] != corr
            or result["code"] != "STAGED_NOT_SERVER_READY"
            or result["bundleSha256"] != intent["bundleSha256"]
            or result["files"] != intent["fileHashes"]): return unknown
    try:
        validate_stage_acl_receipt(result["acl"], sid, _GUEST + "\\mcp-update-fixture-" + corr + "\\content")
        validate_stage_acl_receipt(result["rootAcl"], sid, _GUEST + "\\mcp-update-fixture-" + corr)
        _validate_state_acl(result["stateAcl"], sid, _GUEST + "\\mcp-update-fixture-" + corr + "\\server-state")
    except ValueError: return unknown
    if not _complete_stage_lease(root, intent, result, config, target, descriptor):
        return unknown
    return {"state": "staged-not-server-ready", "correlationId": corr,
            "sourceSha": intent["request"]["sourceSha"], "targetMsiSha256": intent["request"]["targetMsiArtifactId"].removeprefix("sha256-"),
            "bundleSha256": intent["bundleSha256"], "fileHashes": dict(intent["fileHashes"]),
            "serverReady": False, "replayAllowed": False}


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable, redacted stage observation; never server admission."""
    return status(root, value)
