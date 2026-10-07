"""Retire the fixed, source-invalid CP117 staged update fixture.

This deliberately has no generic correlation input.  It is an escape hatch for
one fully staged fixture which cannot be reused after the server ACL repair.
The preflight is read-only.  ``start`` is one-shot and only delegates the
guest/host removal after the preflight evidence has been durably reserved.
"""
from __future__ import annotations

import hashlib
import base64
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_fixture_phase_status as phase
from . import windows_fixture_credentials as credentials
from . import windows_fixture_server_second_abort_successor as server_recovery
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_stage as stage
from . import windows_update_fixture_server as server
from . import windows_cp117_retirement_guards as guards


class WindowsCp117StagedFixtureRetireError(ValueError):
    pass


_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_LEASE = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
_STAGE = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
_SERVER = "316e6189-5be0-4ea0-bca1-a3905816d815"
_CREDENTIAL_CLEANUP = "3b4e5ab8-16d0-460f-8e96-8a9cf71b8eb4"
_SERVER_CLEANUP_SHA256 = "9b0082788cf56f3d9f6d79fae5884bcd01333bb097faa77266af2ea8c3cdeef2"
_CREDENTIAL_CLEANUP_SHA256 = "02377ac3321c1afae18c6a392c7546e5944be9f79f2a546f4f3ecd7b70084738"
_DIR = ".rag_index/windows-cp117-staged-fixture-retire"
_UNKNOWN = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False,
            "productAction": False}

_REMOTE_DIAGNOSTIC = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='guest-exec'
try:
 if not live(sock,pid,ticks):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 phase='guest-status'
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if item.get('exitcode')!=0:out({'state':'diagnosed','phase':'powershell-nonzero'});raise SystemExit()
 if item.get('out-truncated',False) or item.get('err-truncated',False):out({'state':'diagnosed','phase':'stdout-truncated'});raise SystemExit()
 phase='stdout-missing'
 raw=item.get('out-data')
 if not isinstance(raw,str) or not raw:raise ValueError()
 phase='json-shape'
 value=json.loads(decode(base64.b64decode(raw,validate=True)))
 if not isinstance(value,dict) or set(value)!={'stage','owner','reparse','serverTask','serverProcess','listener','credentials','runtime'}:raise ValueError()
 out({'state':'observed','receipt':value})
except SystemExit:raise
except Exception:out({'state':'diagnosed','phase':phase})
'''

_REMOTE_PARSER = base._QGA + r'''import base64,json,sys,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 ps="""$ErrorActionPreference='Stop';$source=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"""+encoded+"""'));$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)|Out-Null;$syntax=if($errors.Count -eq 0){'valid'}else{'invalid'};$runtime=if((Get-Command powershell.exe -ErrorAction SilentlyContinue)){'available'}else{'unavailable'};[Console]::Out.WriteLine((@{syntax=$syntax;runtime=$runtime}|ConvertTo-Json -Compress))"""
 if len(ps)>28000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',ps],'capture-output':True})['pid']
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 value=json.loads(decode(base64.b64decode(item.get('out-data',''),validate=True)))
 if value not in ({'syntax':'valid','runtime':'available'},{'syntax':'valid','runtime':'unavailable'},{'syntax':'invalid','runtime':'available'},{'syntax':'invalid','runtime':'unavailable'}):raise ValueError()
 out({'state':'observed','receipt':value})
except Exception:out({'state':'diagnosed','phase':'parser-qga'})
'''

_REMOTE_GUARD_DIAGNOSTIC = _REMOTE_DIAGNOSTIC.replace(
    "{'stage','owner','reparse','serverTask','serverProcess','listener','credentials','runtime'}",
    "{'guard','category'}")

_REMOTE_TREE_DIAGNOSTIC = _REMOTE_DIAGNOSTIC.replace(
    "{'stage','owner','reparse','serverTask','serverProcess','listener','credentials','runtime'}",
    "{'root','bundle','content','result','serverState','probeEvents','unexpectedRootCount','contentFileCount','probeEntryCount','resultAccess','resultReadOnly','otherPowerShellCount'}")


def _read(path: Path) -> dict[str, Any] | None:
    if not path.parent.exists() and not path.parent.is_symlink():
        return None
    guards.secure_directory(path.parent)
    return guards.secure_read(path)


def _admitted(root: Path) -> tuple[dict[str, Any], dict[str, Any], tuple[Any, ...]] | None:
    """Read only durable identities; do not call status routes that can finish roles."""
    try:
        intent = stage._read_intent(root, _STAGE)
        config, target, descriptor = base._descriptor(root)
        directory, lock = lease._locked(root)
        try:
            active = lease._active(directory)
        finally:
            os.close(lock)
        cleanup = credentials._cleanup_intent(root, _CREDENTIAL_CLEANUP)
        if not isinstance(intent, dict):
            return None
        expected = base._campaign_identity({**intent["request"], "correlationId": _LEASE}, descriptor)
        recovery = server_recovery._recovery_read(root)
        if (intent.get("leaseId") != _LEASE
                or intent.get("request", {}).get("sourceSha") != _SOURCE
                or not isinstance(active, dict) or active.get("identity") != expected
                or active.get("state") != "active" or active.get("role") is not None
                or active.get("server") != "stopped" or active.get("credentials") != "cleaned"
                or active.get("lastEvidenceSha256") != _CREDENTIAL_CLEANUP_SHA256
                or active.get("lastOutcome") != "succeeded"
                or not isinstance(cleanup, dict)
                or cleanup.get("request", {}).get("correlationId") != _CREDENTIAL_CLEANUP
                or cleanup.get("request", {}).get("leaseId") != _LEASE
                or cleanup.get("request", {}).get("stageCorrelationId") != _STAGE):
            return None
        # The active receipt reflects the latest credential cleanup.  The earlier
        # server recovery remains a separate immutable recovery record.
        if (not isinstance(cleanup.get("binding"), dict) or cleanup["binding"].get("sourceSha") != _SOURCE
                or not isinstance(recovery, dict) or server_recovery._digest(recovery, descriptor) != _SERVER_CLEANUP_SHA256):
            return None
        return intent, active, descriptor
    except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, credentials.WindowsFixtureCredentialsError,
            stage.WindowsUpdateFixtureStageError):
        return None


def _fresh(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> bool:
    """Use only observers: installed-idle, terminal transfer, and exact stage receipt."""
    try:
        idle = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.19"})
        if (idle.get("state") != "ready" or idle.get("ready") is not True
                or idle.get("installedVersion") != "2.1.19" or idle.get("productCount") != 1
                or idle.get("activeCount") != 0 or idle.get("activeProcesses") != []):
            return False
        staged = stage.status(root, {"correlationId": _STAGE})
        listener = phase.http_stage.listener_status(root, {"correlationId": _STAGE})
        return (staged.get("state") == "staged-not-server-ready"
                and staged.get("sourceSha") == _SOURCE
                and staged.get("targetMsiSha256") == intent["request"]["targetMsiArtifactId"].removeprefix("sha256-")
                and staged.get("serverReady") is False
                and listener.get("state") in {"served", "stopped"})
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return False


def _recovery_fresh(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any,...]) -> bool:
    """Observe the idle campaign after partial removal; tree proof is separate."""
    try:
        admitted = _admitted(root)
        if admitted is None or admitted[0] != intent or admitted[2] != descriptor:
            return False
        config, target, actual = base._descriptor(root)
        if actual != descriptor or not lease._remote_confirm(base._campaign_remote(config,target),"status",admitted[1],None):
            return False
        idle = base.readiness(root,{"host":"archlinux","expectedCurrentVersion":"2.1.19"})
        listener = phase.http_stage.listener_status(root,{"correlationId":_STAGE})
        return (idle.get("state") == "ready" and idle.get("ready") is True
                and idle.get("installedVersion") == "2.1.19" and idle.get("productCount") == 1
                and idle.get("activeCount") == 0 and idle.get("activeProcesses") == []
                and listener.get("state") in {"served","stopped"})
    except (OSError,ValueError,TypeError,KeyError,base.WindowsMsiBasePrepareError,lease.Cp117LeaseError):
        return False

def preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed retirement preflight takes no inputs.")
    path = Path(root).resolve(strict=True)
    admitted = _admitted(path)
    if admitted is None:
        return {**_UNKNOWN, "state": "blocked", "reason": "durable-binding"}
    intent, _active, descriptor = admitted
    if not _fresh(path, intent, descriptor):
        return {**_UNKNOWN, "state": "blocked", "reason": "fresh-native-evidence"}
    guest = _guest_preflight(path)
    if guest.get("state") != "ready":
        return {**_UNKNOWN, "state": "blocked", "reason": "native-guard",
                "guard": guest.get("guard", "unknown")}
    return {**_UNKNOWN, "state": "ready", "leaseId": _LEASE, "stageCorrelationId": _STAGE,
            "serverCorrelationId": _SERVER, "serverCleanupReceiptSha256": _SERVER_CLEANUP_SHA256,
            "credentialCleanupReceiptSha256": _CREDENTIAL_CLEANUP_SHA256,
            "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed retirement status takes no inputs.")
    path = Path(root).resolve(strict=True)
    record = _read(path / _DIR / "intent.json")
    if record is None:
        return {**_UNKNOWN, "state": "not-started"}
    # A completed one-shot is represented by a receipt; no status call can retry it.
    receipt = _read(path / _DIR / "receipt.json")
    if receipt == {"stageCorrelationId": _STAGE, "leaseId": _LEASE, "removed": True}:
        try:
            config, target, _ = base._descriptor(path)
            reconciled = lease.reconcile(path, _LEASE, base._campaign_remote(config, target))
            if reconciled.get("state") == "closed":
                return {**_UNKNOWN, "state": "retired", "stageCorrelationId": _STAGE, "leaseId": _LEASE}
        except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            pass
    completed = [step for step in ("guest-removed", "host-submitted", "host-removed", "close-submitted")
                 if _read(path / _DIR / (step + ".json")) == _step(step)]
    return {**_UNKNOWN, "phase": completed[-1] if completed else "guest-submitted"}


_SCRIPT_TEMPLATES = {'retire': '$ErrorActionPreference=\'Stop\';$server=\'@SERVER@\';$root=@ROOT@;$creds=@CREDS@;$sid=@SID@;$python=@PYTHON@;$arguments=@ARGUMENTS@;$task=\'VpnControlMcpFixtureServer-\'+$server;$tasks=@(Get-ScheduledTask -TaskPath \'\\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task});$fixture=@(Get-CimInstance Win32_Process -Filter "Name = \'python.exe\'" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $python -and $_.CommandLine -like (\'*\'+$arguments)});$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.OwningProcess -in @($fixture|ForEach-Object {[int]$_.ProcessId})});$runtime=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match \'^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$\'});if($tasks.Count -ne 0 -or $fixture.Count -ne 0 -or $listeners.Count -ne 0 -or $runtime.Count -ne 0 -or [IO.Directory]::Exists($creds) -or -not [IO.Directory]::Exists($root)){throw \'PRECONDITION\'};$item=Get-Item -LiteralPath $root -Force -ErrorAction Stop;$owner=([Security.Principal.NTAccount]$item.GetAccessControl().Owner).Translate([Security.Principal.SecurityIdentifier]).Value;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $owner -cne $sid -or @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -ne 0){throw \'UNSAFE\'};Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop;if([IO.Directory]::Exists($root)){throw \'PRESENT\'}', 'preflight': '$ErrorActionPreference=\'Stop\';$root=@ROOT@;$creds=@CREDS@;$sid=@SID@;$python=@PYTHON@;$arguments=@ARGUMENTS@;$task=\'VpnControlMcpFixtureServer-@SERVER@\';$tasks=@(Get-ScheduledTask -TaskPath \'\\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task});$fixture=@(Get-CimInstance Win32_Process -Filter "Name = \'python.exe\'" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $python -and $_.CommandLine -like (\'*\'+$arguments)});$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.OwningProcess -in @($fixture|ForEach-Object {[int]$_.ProcessId})});$runtime=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match \'^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$\'});$item=Get-Item -LiteralPath $root -Force -ErrorAction Stop;$owner=([Security.Principal.NTAccount]$item.GetAccessControl().Owner).Translate([Security.Principal.SecurityIdentifier]).Value;if($tasks.Count -ne 0 -or $fixture.Count -ne 0 -or $listeners.Count -ne 0 -or $runtime.Count -ne 0 -or [IO.Directory]::Exists($creds) -or -not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $owner -cne $sid -or @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -ne 0){throw \'BLOCKED\'}', 'diagnostic': '$ErrorActionPreference=\'Stop\';$root=@ROOT@;$creds=@CREDS@;$sid=@SID@;$python=@PYTHON@;$arguments=@ARGUMENTS@;$task=\'VpnControlMcpFixtureServer-@SERVER@\';try{function C($x){if($x){\'present\'}else{\'absent\'}};try{$item=Get-Item -LiteralPath $root -Force -ErrorAction Stop;$stage=if($item.PSIsContainer){\'present\'}else{\'unsafe\'};$owner=try{if(([Security.Principal.NTAccount]$item.GetAccessControl().Owner).Translate([Security.Principal.SecurityIdentifier]).Value -ceq $sid){\'original-user\'}elseif(([Security.Principal.NTAccount]$item.GetAccessControl().Owner).Translate([Security.Principal.SecurityIdentifier]).Value -ceq \'S-1-5-18\'){\'system\'}elseif(([Security.Principal.NTAccount]$item.GetAccessControl().Owner).Translate([Security.Principal.SecurityIdentifier]).Value -ceq \'S-1-5-32-544\'){\'administrators\'}else{\'other\'}}catch{\'unknown\'};$reparse=if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -ne 0){\'present\'}else{\'absent\'}}catch{$stage=\'absent\';$owner=\'not-applicable\';$reparse=\'unknown\'};$t=@(Get-ScheduledTask -TaskPath \'\\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task});$p=@(Get-CimInstance Win32_Process -Filter "Name = \'python.exe\'" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $python -and $_.CommandLine -like (\'*\'+$arguments)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match \'^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$\'});[Console]::Out.WriteLine((@{stage=$stage;owner=$owner;reparse=$reparse;serverTask=C($t.Count -ne 0);serverProcess=C($p.Count -ne 0);listener=C($l.Count -ne 0);credentials=C([IO.Directory]::Exists($creds));runtime=C($r.Count -ne 0)}|ConvertTo-Json -Compress))}catch{exit 1}'}

def _script(root: Path, kind: str) -> str:
    descriptor = base._descriptor(root)[2]
    intent = server._read_intent(root, _SERVER)
    request = server._request(intent["request"])
    python = intent["pythonPath"]
    arguments = server._launch_arguments(request, {"paths": credentials._fixed_paths(_STAGE)})
    if not isinstance(python, str) or not isinstance(arguments, str):
        raise ValueError("Invalid historical server identity")
    replacements = {"@SERVER@": _SERVER,
                    "@ROOT@": stage.public._ps_literal(stage._GUEST + r"\mcp-update-fixture-" + _STAGE),
                    "@CREDS@": stage.public._ps_literal(credentials._fixed_paths(_STAGE)["directory"]),
                    "@SID@": stage.public._ps_literal(descriptor[4]),
                    "@PYTHON@": stage.public._ps_literal(python),
                    "@ARGUMENTS@": stage.public._ps_literal(arguments)}
    source = _SCRIPT_TEMPLATES[kind]
    for token, literal in replacements.items():
        source = source.replace(token, literal)
    if kind in {"preflight", "retire"}:
        # The stage creator is SYSTEM. Its immutable root/content ACLs, exact
        # manifest and failed-server tree establish authority for deletion.
        source = source.replace("$owner -cne $sid -or ", "")
        census = guards.deletion_census_powershell(stage._read_intent(root, _STAGE), _STAGE, descriptor[4])
        checked = "& { " + census + " } | Out-Null;"
        if kind == "retire":
            source = source.replace("Remove-Item -LiteralPath $root", checked + "Remove-Item -LiteralPath $root", 1)
        else:
            source += ";" + checked
    return source


def _guest_retire(root: Path) -> bool:
    """Remove the fixed stage only after the same guarded native census."""
    try:
        script = _script(root, "retire")
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return False
    return _run_guard(root, script, "created")


def _run_guard(root: Path, script: str, expected: str) -> bool:
    """Use the bound idle campaign; a completed stage role cannot be reclaimed."""
    try:
        config, _target, descriptor = base._descriptor(root)
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        if len(encoded) > 30000 or expected not in {"created", "staged"}:
            return False
        raw = base._remote(config, phase.http_stage._REMOTE_QGA_PS,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded, expected), None, 180)
        return raw is not None and json.loads(raw) == {"state": expected}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return False


def _guest_preflight(root: Path) -> dict[str, str]:
    """Read-only census using the exact generated retirement guards."""
    try:
        script = _script(root, "preflight")
        if not _run_guard(root, script, "staged"):
            observed = diagnose_guard(root, {})
            return {"state": "blocked", "guard": observed.get("guard", "unknown")}
        return {"state": "ready", "stagePath": "present", "owner": "system-creator", "reparse": "absent", "server": "absent", "credentials": "absent", "runtime": "off"}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {"state": "blocked"}


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only finite classification for a blocked guest preflight."""
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed retirement diagnostic takes no inputs.")
    try:
        path = Path(root).resolve(strict=True); descriptor = base._descriptor(path)[2]
        script = _script(path, "diagnostic")
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(base._descriptor(path)[0], _REMOTE_DIAGNOSTIC,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 30)
        observed = json.loads(raw) if raw is not None else None
        if isinstance(observed, dict) and observed.get("state") == "observed":
            receipt = observed.get("receipt")
            allowed = {"present","absent","unsafe","original-user","system","administrators","other","not-applicable","unknown"}
            if isinstance(receipt, dict) and set(receipt) == {"stage","owner","reparse","serverTask","serverProcess","listener","credentials","runtime"} and all(v in allowed for v in receipt.values()):
                return {"state":"observed", **receipt, "replayAllowed":False, "nativeActionAllowed":False, "productAction":False}
        phases = {"guest-exec", "guest-status", "powershell-nonzero", "stdout-missing", "stdout-truncated", "json-shape"}
        phase_name = observed.get("phase") if isinstance(observed, dict) else "transport"
        return {"state":"diagnosed", "phase":phase_name if phase_name in phases else "transport", "replayAllowed":False, "nativeActionAllowed":False, "productAction":False}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {"state":"diagnosed", "phase":"admission", "replayAllowed":False, "nativeActionAllowed":False, "productAction":False}


def diagnose_parser(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Parser-only probe for the fixed diagnostic/preflight PowerShell grammar."""
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed retirement parser takes no inputs.")
    try:
        path = Path(root).resolve(strict=True); descriptor = base._descriptor(path)[2]
        scripts = {}
        for kind in ("diagnostic", "preflight", "retire"):
            source = _script(path, kind)
            raw = base._remote(base._descriptor(path)[0], _REMOTE_PARSER,
                               (descriptor[1], str(descriptor[2]), str(descriptor[3]),
                                base64.b64encode(source.encode("utf-16le")).decode()), None, 30)
            observed = json.loads(raw) if raw is not None else None
            receipt = observed.get("receipt") if isinstance(observed, dict) else None
            if (not isinstance(observed, dict) or observed.get("state") != "observed"
                    or not isinstance(receipt, dict) or set(receipt) != {"syntax", "runtime"}
                    or receipt["syntax"] not in {"valid", "invalid"}
                    or receipt["runtime"] not in {"available", "unavailable"}):
                return {"state": "diagnosed", "phase": "parser-qga", "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
            scripts[kind] = receipt
        return {"state": "observed", "scripts": scripts, "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}

    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return {"state": "diagnosed", "phase": "parser-admission", "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}


def diagnose_guard(root: Path | str, value: Mapping[str, Any], *, retirement_boundary: bool = False) -> dict[str, Any]:
    """Execute only the read-only guard and report its fixed rejection code."""
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed guard diagnostic takes no inputs.")
    flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        path = Path(root).resolve(strict=True)
        if _admitted(path) is None:
            return {"state": "diagnosed", "phase": "admission", **flags}
        config, _target, descriptor = base._descriptor(path)
        source = _script(path, "retire" if retirement_boundary else "preflight")
        if retirement_boundary:
            deletion = "Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop"
            if source.count(deletion) != 1:
                return {"state": "diagnosed", "phase": "guard-source", **flags}
            source = source.replace(deletion, "throw 'DELETION_READY'")
        codes = sorted(set(re.findall(r"throw '([A-Z_]+)'", source)))
        literals = ",".join(stage.public._ps_literal(code) for code in codes)
        program = ("$ErrorActionPreference='Stop';try{ " + source
                   + ";[Console]::Out.WriteLine('{\"guard\":\"ready\",\"category\":\"None\"}')"
                   + "}catch{$code=if($_.Exception.Message -cin @(" + literals
                   + ")){$_.Exception.Message}else{'runtime-error'};"
                   + "[Console]::Out.WriteLine((@{guard=$code;category=$_.CategoryInfo.Category.ToString()}|ConvertTo-Json -Compress))}")
        encoded = base64.b64encode(program.encode("utf-16le")).decode()
        if len(encoded) > 30000:
            return {"state": "diagnosed", "phase": "guard-oversize", **flags}
        raw = base._remote(config, _REMOTE_GUARD_DIAGNOSTIC,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 45)
        observed = json.loads(raw) if raw is not None else None
        receipt = observed.get("receipt") if isinstance(observed, dict) else None
        if (isinstance(receipt, dict) and set(receipt) == {"guard", "category"}
                and receipt["guard"] in {*codes, "ready", "runtime-error"}
                and isinstance(receipt["category"], str) and re.fullmatch(r"[A-Za-z]{1,40}", receipt["category"])):
            return {"state": "observed", **receipt, **flags}
        return {"state": "diagnosed", "phase": "guard-transport", **flags}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return {"state": "diagnosed", "phase": "guard-admission", **flags}


def diagnose_retirement_boundary(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return diagnose_guard(root, value, retirement_boundary=True)


def diagnose_tree(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("Fixed tree diagnostic takes no inputs.")
    flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        path = Path(root).resolve(strict=True); config, _target, descriptor = base._descriptor(path)
        guest = guards.stage_root(_STAGE)
        script = r'''$ErrorActionPreference='Stop';$root=@ROOT@;function Exists([string]$p){if(Test-Path -LiteralPath $p){'present'}else{'absent'}};$names=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop);$content=Join-Path $root 'content';$state=Join-Path $root 'server-state';$probe=Join-Path $state 'probe-events';$files=if(Test-Path -LiteralPath $content){@(Get-ChildItem -LiteralPath $content -Force -Recurse -File -ErrorAction Stop).Count}else{0};$entries=if(Test-Path -LiteralPath $probe){@(Get-ChildItem -LiteralPath $probe -Force -ErrorAction Stop).Count}else{0};$resultPath=Join-Path $root 'result.json';$access='absent';$ro='absent';if(Test-Path -LiteralPath $resultPath){$item=Get-Item -LiteralPath $resultPath -Force;$ro=if(($item.Attributes -band [IO.FileAttributes]::ReadOnly)-ne 0){'present'}else{'absent'};try{$stream=[IO.File]::Open($resultPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);$stream.Dispose();$access='exclusive-read'}catch [IO.IOException]{$access='sharing-or-io'}catch [UnauthorizedAccessException]{$access='denied'}catch{$access='unknown'}};$otherPs=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('powershell.exe','pwsh.exe') -and $_.ProcessId -ne $PID}).Count;[Console]::Out.WriteLine((@{root=Exists $root;bundle=Exists (Join-Path $root 'bundle.zip');content=Exists $content;result=Exists (Join-Path $root 'result.json');serverState=Exists $state;probeEvents=Exists $probe;unexpectedRootCount=@($names|Where-Object {$_.Name -cnotin @('bundle.zip','content','result.json','server-state')}).Count;contentFileCount=$files;probeEntryCount=$entries;resultAccess=$access;resultReadOnly=$ro;otherPowerShellCount=$otherPs}|ConvertTo-Json -Compress))'''.replace("@ROOT@", stage.public._ps_literal(guest))
        raw = base._remote(config, _REMOTE_TREE_DIAGNOSTIC,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), base64.b64encode(script.encode("utf-16le")).decode()), None, 45)
        observed = json.loads(raw) if raw is not None else None
        receipt = observed.get("receipt") if isinstance(observed, dict) else None
        expected = {"root", "bundle", "content", "result", "serverState", "probeEvents", "unexpectedRootCount", "contentFileCount", "probeEntryCount", "otherPowerShellCount", "resultAccess", "resultReadOnly"}
        if (isinstance(receipt, dict) and set(receipt) == expected and all(receipt.get(k) in {"present", "absent"} for k in
                ("root", "bundle", "content", "result", "serverState", "probeEvents"))
                and all(type(receipt.get(k)) is int and 0 <= receipt[k] <= 1000 for k in
                        ("unexpectedRootCount", "contentFileCount", "probeEntryCount", "otherPowerShellCount"))
                and receipt.get("resultAccess") in {"absent", "exclusive-read", "sharing-or-io", "denied", "unknown"}
                and receipt.get("resultReadOnly") in {"present", "absent"}):
            return {"state": "observed", **receipt, **flags}
        return {"state": "diagnosed", "phase": "tree-transport", **flags}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {"state": "diagnosed", "phase": "tree-admission", **flags}



def diagnose_locks(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Enumerate lock owners for the sole remaining fixed result; never stop them."""
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("Fixed lock diagnostic takes no inputs.")
    flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        path = Path(root).resolve(strict=True)
        if _admitted(path) is None:
            return {"state": "diagnosed", "phase": "lock-admission", **flags}
        config, _target, descriptor = base._descriptor(path)
        source = guards.remaining_result_lock_diagnostic_powershell(_STAGE)
        encoded = base64.b64encode(source.encode("utf-16le")).decode()
        if len(encoded) > 30000:
            return {"state": "diagnosed", "phase": "lock-oversize", **flags}
        remote = _REMOTE_DIAGNOSTIC.replace(
            "{'stage','owner','reparse','serverTask','serverProcess','listener','credentials','runtime'}",
            "{'cause','lockingProcess','count','qemuGaExactLocalSystem'}")
        raw = base._remote(config, remote,
                           (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 45)
        observed = json.loads(raw) if raw is not None else None
        receipt = observed.get("receipt") if isinstance(observed, dict) else None
        if (isinstance(receipt, dict) and set(receipt) == {"cause", "lockingProcess", "count", "qemuGaExactLocalSystem"}
                and receipt["cause"] in {"none", "low-hresult-32", "low-hresult-33", "other"}
                and receipt["lockingProcess"] in {"absent", "qemu-ga", "powershell", "other"}
                and type(receipt["count"]) is int and 0 <= receipt["count"] <= 100
                and type(receipt["qemuGaExactLocalSystem"]) is bool
                and (not receipt["qemuGaExactLocalSystem"] or (receipt["lockingProcess"] == "qemu-ga" and receipt["count"] == 1))):
            return {"state": "observed", **receipt, **flags}
        phases = {"guest-exec", "guest-status", "powershell-nonzero", "stdout-missing", "stdout-truncated", "json-shape"}
        phase_name = observed.get("phase") if isinstance(observed, dict) else None
        return {"state": "diagnosed", "phase": phase_name if phase_name in phases else "lock-shape" if receipt is not None else "lock-transport", **flags}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {"state": "diagnosed", "phase": "lock-admission", **flags}


def _remove_host(root: Path) -> bool:
    """Use the existing terminal-listener cleanup; it removes payloads, never journals."""
    intent = stage._read_intent(root, _STAGE)
    record = phase.http_stage._read(root, _STAGE)
    if (not isinstance(intent, dict) or not isinstance(record, dict)
            or record["request"] != intent["request"] or record["leaseId"] != _LEASE
            or record["bundleSha256"] != intent["bundleSha256"]
            or record["bundleSize"] != intent["bundleSize"]):
        return False
    bundle = Path(record["bundlePath"])
    expected = root / stage._GROUP / (_STAGE + ".zip")
    if bundle != expected:
        return False
    phase.http_stage._artifact(bundle, record["bundleSha256"], record["bundleSize"])
    result = phase.http_stage.cleanup(root, {"correlationId": _STAGE})
    if result.get("state") != "cleaned":
        return False
    if phase.http_stage._read(root, _STAGE) != record:
        return False
    try:
        if bundle.resolve(strict=True) != expected.resolve(strict=True) or not bundle.is_file() or bundle.is_symlink():
            return False
        bundle.unlink()
        return not bundle.exists()
    except OSError:
        return False


def _step(name: str) -> dict[str, Any]:
    return {"stageCorrelationId": _STAGE, "leaseId": _LEASE, "step": name}


def _record_step(root: Path, name: str) -> None:
    guards.secure_write_create(root / _DIR / (name + ".json"), _step(name))


def _close(root: Path, active: Mapping[str, Any], descriptor: tuple[Any, ...]) -> bool:
    try:
        config, target, _ = base._descriptor(root)
        receipt = {"stageCorrelationId": _STAGE, "leaseId": _LEASE, "removed": True}
        digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        cleanup = {"guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]},
                   "serverStopped": True, "credentialsCleaned": True, "protectedJobsTerminalCleaned": True,
                   "activeInstallerProcessesAbsent": True, "cleanupReceiptSha256": digest}
        return lease.close(root, _LEASE, cleanup, base._campaign_remote(config, target),
                           expected_current=active).get("state") == "closed"
    except (OSError, ValueError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return False


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Reserve once, retire the exact guest/host payload, then close the lease."""
    if value != {}:
        raise WindowsCp117StagedFixtureRetireError("The fixed retirement action takes no inputs.")
    result = preflight(root, {})
    if result["state"] != "ready":
        return result
    path = Path(root).resolve(strict=True); directory = path / _DIR
    guards.secure_directory(directory)
    intent = {"stageCorrelationId": _STAGE, "leaseId": _LEASE,
              "serverCleanupReceiptSha256": _SERVER_CLEANUP_SHA256,
              "credentialCleanupReceiptSha256": _CREDENTIAL_CLEANUP_SHA256}
    existing = _read(directory / "intent.json")
    if existing is not None:
        return dict(_UNKNOWN)
    guards.secure_write_create(directory / "intent.json", intent)
    admitted = _admitted(path)
    if admitted is None:
        return {**_UNKNOWN, "state": "unknown"}
    _intent, active, descriptor = admitted
    if not _fresh(path, _intent, descriptor):
        return {**_UNKNOWN, "state": "unknown"}
    if not _guest_retire(path):
        return {**_UNKNOWN, "state": "unknown"}
    _record_step(path, "guest-removed")
    _record_step(path, "host-submitted")
    if not _remove_host(path):
        return {**_UNKNOWN, "phase": "host-submitted"}
    _record_step(path, "host-removed")
    receipt = {"stageCorrelationId": _STAGE, "leaseId": _LEASE, "removed": True}
    guards.secure_write_create(directory / "receipt.json", receipt)
    _record_step(path, "close-submitted")
    if not _close(path, active, descriptor):
        return {**_UNKNOWN, "state": "unknown"}
    return {**_UNKNOWN, "state": "retired", "stageCorrelationId": _STAGE, "leaseId": _LEASE}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "preflight": return preflight(root, inputs)
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    if action == "diagnose_parser": return diagnose_parser(root, inputs)
    raise WindowsCp117StagedFixtureRetireError("Unknown staged fixture retirement action.")
