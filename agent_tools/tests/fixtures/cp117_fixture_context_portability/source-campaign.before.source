"""Source-bound CP117 same-version base campaign and its read-only admission.

The prior CP117 fixture used source ``19be…``.  Its installed 2.1.19 is a
version observation only: it cannot prove that the current d32 base package is
installed.  It admits a one-shot source-bound replacement only after the fixed
old fixture has a terminal retirement receipt, a closed remote lease, and a
fresh absence census.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_cp117_staged_fixture_retire as retirement
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage


class WindowsCp117SourceCampaignError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OLD_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_OLD_LEASE = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
_OLD_STAGE = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
_SOURCE = "d32f719a08db57e5d40ce2bf77e0d7c5b42de557"
_RECEIPT = "sha256-31634170c6d0c358ee1aed84314170725b27b79895f76f5977133a5e466f94bb"
_BASE = "sha256-539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd"
_TARGET = "sha256-f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc"
_BASE_VERSION = "2.1.19"
_TARGET_VERSION = "2.2.2"
_HISTORICAL_BASE = "c32cb108-4d48-407e-9153-40774559ba50"
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}
_SOURCE_DIAGNOSTIC_PHASES = frozenset({
    "local-intent", "artifact", "registered-pair", "pair", "descriptor",
    "command", "legacy-job", "legacy-idle", "legacy-tasks", "legacy-history",
    "pre-effect", "observer-error",
})
_REVIEWED_TASKS = {
    "legacy": "VpnControlMcpMsi-" + base._LEGACY_CORRELATION,
    "c32": "VpnControlMcpBase-" + _HISTORICAL_BASE,
    "recovery": "VpnControlCp117GuestAgentRecovery-c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58",
    "retirement": "VpnControlCp117RetirementRecovery-f72ecafe-1890-4e17-a954-1d045dfa0ea3",
}
_TASK_PURPOSE_PREFIXES = {
    "base": "VpnControlMcpBase-", "msi": "VpnControlMcpMsi-",
    "transfer": "VpnControlMcpTransfer-", "target": "VpnControlMcpTarget-",
    "owner-observe": "VpnControlMcpOwnerObserve-", "owner-network": "VpnControlMcpOwnerNetwork-",
    "network-probe": "VpnControlMcpNetworkProbe-", "fixture-server": "VpnControlMcpFixtureServer-",
    "fixture-http": "VpnControlMcpFixtureHttp-", "cp95-acquire": "VpnControlMcpCp95Acquire-",
    "cp95-python": "VpnControlMcpCp95Python-",
}
_TASK_STATES = frozenset({"ready", "running", "queued", "disabled", "other"})


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"host", "leaseId"} or value.get("host") != "archlinux":
        raise WindowsCp117SourceCampaignError("New-source CP117 admission requires host and a new lease ID.")
    lease_id = value.get("leaseId")
    if not isinstance(lease_id, str) or not _UUID.fullmatch(lease_id) or str(uuid.UUID(lease_id)) != lease_id:
        raise WindowsCp117SourceCampaignError("New-source CP117 lease ID is invalid.")
    if lease_id == _OLD_LEASE:
        raise WindowsCp117SourceCampaignError("New-source CP117 admission cannot reuse the retired lease.")
    return {"host": "archlinux", "leaseId": lease_id}


def _read_receipt(path: Path) -> Mapping[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 4096):
            return None
        try:
            value = json.load(stream)
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, dict) else None


def _retirement_terminal(root: Path, descriptor: tuple[Any, ...], config: Any, target: Any) -> bool:
    """Prove the fixed retired stage, close receipt, and remote closed lease."""
    receipt = _read_receipt(root / retirement._DIR / "receipt.json")
    if receipt != {"stageCorrelationId": _OLD_STAGE, "leaseId": _OLD_LEASE, "removed": True}:
        return False
    old_intent = stage._read_intent(root, _OLD_STAGE)
    if not isinstance(old_intent, Mapping) or old_intent.get("leaseId") != _OLD_LEASE:
        return False
    request = old_intent.get("request")
    if not isinstance(request, Mapping) or request.get("sourceSha") != _OLD_SOURCE:
        return False
    try:
        expected = base._campaign_identity({**request, "correlationId": _OLD_LEASE}, descriptor)
        directory, lock = lease._locked(root)
        try:
            if lease._active(directory) is not None:
                return False
            closed = lease._closed(directory, _OLD_LEASE)
        finally:
            os.close(lock)
        if (not isinstance(closed, Mapping) or closed.get("identity") != expected
                or closed.get("state") != "closed" or closed.get("role") is not None
                or closed.get("server") != "stopped" or closed.get("credentials") == "ready"
                or not isinstance(closed.get("lastEvidenceSha256"), str)
                or not _HASH.fullmatch(closed["lastEvidenceSha256"])):
            return False
        return lease._remote_confirm(base._campaign_remote(config, target), "status", closed, None)
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError):
        return False


def _fresh_absence(root: Path) -> bool:
    """Require a new observer result, not the historical retirement receipt."""
    observed = retirement.diagnose(root, {})
    return (observed.get("state") == "observed"
            and all(observed.get(name) == "absent" for name in
                    ("stage", "serverTask", "serverProcess", "listener", "credentials", "runtime")))


def _new_pair(root: Path) -> Mapping[str, Any] | None:
    try:
        pair = public._admit_pair(root, _SOURCE, _RECEIPT, _BASE, _TARGET)
    except (OSError, ValueError, TypeError, KeyError, public.WindowsMsiPreinstallStatusError):
        return None
    if (pair.get("sourceSha") != _SOURCE or pair.get("sourceSha") == _OLD_SOURCE
            or pair.get("receiptArtifactId") != _RECEIPT or pair.get("baseArtifactId") != _BASE
            or pair.get("targetArtifactId") != _TARGET or pair.get("baseVersion") != _BASE_VERSION
            or pair.get("targetVersion") != _TARGET_VERSION):
        return None
    return pair


def _reservation_readiness(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], correlation: str) -> tuple[bool, str]:
    """Read the exact local reservation namespace without altering it.

    This does not promote any historical file.  The generic base owner remains
    authoritative for archived-record recognition; this merely prevents source
    start from disguising its pre-effect refusal as an unknown guest outcome.
    """
    if base._intent_path(root, correlation).exists():
        return False, "new-correlation-present"
    directory = root / base._LOCAL
    if not directory.exists(): return True, "ready"
    try:
        archived = base._archived_base_record_names(root, config, target, descriptor)
        extras = sorted(item.name for item in directory.iterdir()
                        if item.suffix == ".json" and item.name not in archived)
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return False, "journal-unreadable"
    if extras:
        # Keep each record in place.  In particular c32 requires a fixed
        # native terminal/absence observer before the generic owner may add it
        # to its archive allow-list.
        return False, "historical-base-unresolved" if _HISTORICAL_BASE + ".json" in extras else "journal-unresolved"
    return True, "ready"

def _historical_closure_phase(root: Path, config: Any, target: Any, descriptor: tuple[Any,...], correlation: str) -> str:
    """Explain one fixed archived-profile failure without changing its predicate."""
    try:
        profile=base._unknown_recovery_profile(correlation)
        if profile is None:return 'profile'
        request,command=profile; intent=base._private_intent(root,correlation)
        if not isinstance(intent,dict) or intent.get('request')!=request or intent.get('commandSha256')!=command:return 'intent-profile'
        if not base._unknown_marker_valid(root,intent,descriptor,correlation):return 'marker'
        directory,lock=lease._locked(root)
        try: active=lease._active(directory);closed=lease._closed(directory,correlation)
        finally: os.close(lock)
        if active is not None:return 'active-lease'
        if not isinstance(closed,dict) or closed.get('identity')!=base._campaign_identity(request,descriptor) or closed.get('lastOutcome')!='unknown-cleaned':return 'closed-lease'
        first=base._unknown_cleanup_observe(config,target,intent,descriptor,'status',correlation)
        second=base._unknown_cleanup_observe(config,target,intent,descriptor,'status',correlation)
        for item in (first,second):
            if not isinstance(item,dict):return 'census-transport'
            if item.get('state')=='unknown':return 'census-'+str(item.get('phase','unknown'))
            unsafe=base._unknown_cleanup_unsafe_project(item,correlation)
            if unsafe is not None:
                if unsafe.get('product')=='single' and unsafe.get('installedVersion')=='2.1.19':return 'installed-version'
                return 'guest-unsafe'
            if base._unknown_cleanup_project(item,'status',correlation) is None:
                # The only expected current projection difference is the
                # completed c32 baseline's 2.1.19 product version.
                if item.get('state')=='observed' and item.get('product')=='single' and item.get('installedVersion')=='2.1.19':return 'installed-version'
                return 'census-projection'
        if any(item.get(k)!='absent' for item in (first,second) for k in ('remoteStage','leaf','task','result','correlationPowerShell','installer')):return 'absence'
        if any(item.get('product')!='single' for item in (first,second)):return 'product'
        if any(item.get('installedVersion')!='2.1.17' for item in (first,second)):return 'installed-version'
        evidence={'afterFirst':first,'afterSecond':second,'closeIntent':correlation}
        return 'evidence-hash' if closed.get('lastEvidenceSha256')!=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest() else 'archived'
    except (OSError,ValueError,TypeError,KeyError,lease.Cp117LeaseError):return 'diagnostic-unknown'


def reservation_diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify fixed journal blockers using read-only historical admission."""
    request = _request(value); path = Path(root).resolve(strict=True)
    directory = path / base._LOCAL
    if not directory.exists():
        return {**_UNKNOWN, "state":"observed", "newIntent":"absent", "historical":"absent"}
    try:
        config,target,descriptor=base._descriptor(path)
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            return {**_UNKNOWN,"state":"unknown"}
        names=sorted(item.name for item in directory.iterdir() if item.suffix==".json")
        if request['leaseId']+'.json' in names:
            return {**_UNKNOWN,"state":"observed","newIntent":"present",
                    "historical":"present" if (_HISTORICAL_BASE+'.json') in names else "absent",
                    "knownRecordCount":len(names)}
        allowed={_HISTORICAL_BASE+".json", "45e4514a-c629-4f3b-99bc-aad599640d29.json", "45e4514a-c629-4f3b-99bc-aad599640d29.unknown-close.json", "2ace6a48-ba60-4705-9200-4ff857f2aba6.json", "2ace6a48-ba60-4705-9200-4ff857f2aba6.unknown-close.json", "30a6f33b-3ea2-42d0-8818-3d6711b34169.json", "30a6f33b-3ea2-42d0-8818-3d6711b34169.pre-effect-closed.json"}
        from . import windows_cp117_source_pre_effect_close as source_closure
        source_names = {source_closure._CORRELATION + ".json", source_closure._CORRELATION + source_closure._MARKER_SUFFIX}
        allowed.update(source_names)
        if any(name not in allowed for name in names):return {**_UNKNOWN,"state":"unknown"}
        archived=base._archived_base_record_names(path,config,target,descriptor)
        blockers=[]
        if any(name in names and name not in archived for name in source_names):
            proof = source_closure.archive_proof(path, descriptor)
            phase = proof.get("phase") if isinstance(proof, dict) else None
            blockers.append({"record": "source-pre-effect", "phase": phase if phase in {"intent", "marker", "binding", "fresh", "verified"} else "unknown"})
        if _HISTORICAL_BASE+'.json' in names and _HISTORICAL_BASE+'.json' not in archived:
            from . import windows_cp117_c32_archive_admission as archive
            observed=archive.preflight(path,{"leaseId":request['leaseId']})
            if observed.get('state')!='ready':blockers.append({'record':'c32','phase':observed.get('phase','unknown')})
        if '30a6f33b-3ea2-42d0-8818-3d6711b34169.json' in names and '30a6f33b-3ea2-42d0-8818-3d6711b34169.json' not in archived:
            blockers.append({'record':'pre-effect','phase':'closure'})
        for corr,label in (('45e4514a-c629-4f3b-99bc-aad599640d29','transfer-recovery'),('2ace6a48-ba60-4705-9200-4ff857f2aba6','unknown-closure')):
            if corr+'.json' in names and corr+'.json' not in archived:
                blockers.append({'record':label,'phase':_historical_closure_phase(path,config,target,descriptor,corr)})
        if blockers:return {**_UNKNOWN,'state':'observed','newIntent':'absent','historical':'present' if _HISTORICAL_BASE+'.json' in names else 'absent','knownRecordCount':len(names),'blockers':blockers}
        return {**_UNKNOWN,"state":"observed", "newIntent":"present" if (request['leaseId']+'.json') in names else "absent",
                "historical":"present" if (_HISTORICAL_BASE+'.json') in names else "absent",
                "knownRecordCount":len(names)}
    except OSError:return {**_UNKNOWN,"state":"unknown"}


def preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a source-bound base-install plan without reserving a campaign."""
    request = _request(value)
    path = Path(root).resolve(strict=True)
    try:
        config, target, descriptor = base._descriptor(path)
        if not _retirement_terminal(path, descriptor, config, target) or not _fresh_absence(path):
            return {**_UNKNOWN, "state": "blocked", "reason": "retirement-not-terminal"}
        idle = base.readiness(path, {"host": "archlinux", "expectedCurrentVersion": _BASE_VERSION})
        if (idle.get("state") != "ready" or idle.get("ready") is not True
                or idle.get("installedVersion") != _BASE_VERSION or idle.get("productCount") != 1
                or idle.get("activeCount") != 0 or idle.get("activeProcesses") != []):
            return {**_UNKNOWN, "state": "blocked", "reason": "base-not-idle"}
        if _new_pair(path) is None:
            return {**_UNKNOWN, "state": "blocked", "reason": "new-source-pair"}
        available, reason = _reservation_readiness(path, config, target, descriptor, request["leaseId"])
        if not available:
            return {**_UNKNOWN, "state": "blocked", "reason": reason}
        legacy_phase = _legacy_admission_phase(path, descriptor, idle, request["leaseId"])
        if legacy_phase is not None:
            return {**_UNKNOWN, "state": "blocked", "reason": legacy_phase}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)
    # A matching display version is intentionally insufficient: only a later
    # source-bound base terminal receipt can establish these d32 bytes.
    base_inputs = {"host": "archlinux", "correlationId": request["leaseId"], "sourceSha": _SOURCE,
                   "fixtureReceiptArtifactId": _RECEIPT, "baseMsiArtifactId": _BASE,
                   "targetMsiArtifactId": _TARGET, "expectedCurrentVersion": _BASE_VERSION}
    return {**_UNKNOWN, "state": "ready", "leaseId": request["leaseId"], "sourceSha": _SOURCE,
            "fixtureReceiptArtifactId": _RECEIPT, "baseMsiArtifactId": _BASE,
            "targetMsiArtifactId": _TARGET, "retiredLeaseId": _OLD_LEASE,
            "retiredStageCorrelationId": _OLD_STAGE, "baseInstallRequired": True,
            "generalBaseRouteAllowed": False, "nextAction": "source-bound-base-install",
            "sourceBaseInstallInputs": base_inputs}


def transfer_admission(root: Path | str, value: Mapping[str, Any]) -> Path:
    """Admit only the fixed d32 base into the ordinary one-use transfer path.

    The transfer remains generic after this narrow admission: its immutable
    journal, host staging, guest download, and ready-for-base observer are all
    still the existing implementations.  This only replaces the ordinary
    version-increase predicate, which cannot describe a same-version source
    replacement.
    """
    expected = {"host": "archlinux", "sourceSha": _SOURCE,
                "fixtureReceiptArtifactId": _RECEIPT, "baseMsiArtifactId": _BASE,
                "targetMsiArtifactId": _TARGET, "expectedCurrentVersion": _BASE_VERSION}
    if not isinstance(value, Mapping) or set(value) != set(expected) | {"correlationId"}:
        raise WindowsCp117SourceCampaignError("Source campaign transfer inputs are invalid.")
    if any(value.get(name) != item for name, item in expected.items()):
        raise WindowsCp117SourceCampaignError("Source campaign transfer identity changed.")
    request = _request({"host": value["host"], "leaseId": value["correlationId"]})
    result = preflight(root, request)
    if result.get("state") != "ready":
        raise WindowsCp117SourceCampaignError("Source campaign transfer prerequisites are unavailable.")
    path = Path(root).resolve(strict=True)
    artifact = public._verified_location(path, _BASE, "desktop-package", _SOURCE)
    if not artifact.is_file() or artifact.is_symlink():
        raise WindowsCp117SourceCampaignError("Source campaign base artifact is unavailable.")
    return artifact


def _replacement_task(correlation: str, pair: Mapping[str, Any], sid: str) -> str:
    """Use the proven per-user task, adding a verified remove-to-zero boundary."""
    ordinary = base._task(correlation, dict(pair), _BASE_VERSION, sid)
    before = r'''$workspace='C:\Users\vpncp117\.vpn-control-desktop\workspace.json'
$workspacePresent=Test-Path -LiteralPath $workspace -PathType Leaf
$workspaceHash=if($workspacePresent){(Get-FileHash -LiteralPath $workspace -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
$oldCode=$products[0].PSChildName
$installLocation=$products[0].InstallLocation.TrimEnd('\\').ToLowerInvariant()
if($products[0].PSDrive.Name -cne 'HKCU' -or $installLocation -cne 'c:\users\vpncp117\appdata\local\vpn-control' -or $oldCode -notmatch '^\{[0-9A-Fa-f-]{36}\}$'){throw 'PRODUCT_IDENTITY'}
$stage='REMOVE';$remove=Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList ('/x '+$oldCode+' /qn /norestart REBOOT=ReallySuppress MSIINSTALLPERUSER=1') -PassThru -Wait
$none=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
if($remove.ExitCode -ne 0 -or $none.Count -ne 0){throw 'REMOVE'}
'''
    after = r'''$workspaceAfter=Test-Path -LiteralPath $workspace -PathType Leaf
$workspaceAfterHash=if($workspaceAfter){(Get-FileHash -LiteralPath $workspace -Algorithm SHA256).Hash.ToLowerInvariant()}else{$null}
if($workspaceAfter -ne $workspacePresent -or $workspaceAfterHash -cne $workspaceHash){throw 'WORKSPACE'}
'''
    # The scheduled task must refuse a newly appeared runtime/installer before
    # removing anything; an earlier host preflight cannot supply this fact.
    install_boundary = "$stage='INSTALL';P"
    if ordinary.count(install_boundary) != 1:
        raise WindowsCp117SourceCampaignError("Replacement installer boundary is ambiguous.")
    ordinary = ordinary.replace(install_boundary, before + install_boundary, 1)
    ordinary = ordinary.replace("$ok=$installer.ExitCode", after + "$ok=$installer.ExitCode", 1)
    return ordinary


def _replacement_bootstrap(correlation: str, pair: Mapping[str, Any], sid: str) -> str:
    original = base._task(correlation, dict(pair), _BASE_VERSION, sid)
    original_packed = base64.b64encode(gzip.compress(original.encode("utf-16le"), mtime=0)).decode()
    replacement_packed = base64.b64encode(gzip.compress(_replacement_task(correlation, pair, sid).encode("utf-16le"), mtime=0)).decode()
    rendered = base._bootstrap(correlation, dict(pair), _BASE_VERSION, sid)
    if rendered.count(original_packed) != 1:
        raise WindowsCp117SourceCampaignError("Replacement bootstrap task substitution is ambiguous.")
    return rendered.replace(original_packed, replacement_packed)


def replacement_powershell_preflight_script(corr: str, pair: Mapping[str, Any], sid: str) -> str:
    """Parse the exact replacement bootstrap and its decompressed task on PS5."""
    if not isinstance(corr, str) or not _UUID.fullmatch(corr):
        raise WindowsCp117SourceCampaignError("Replacement parser correlation is invalid.")
    bootstrap = _replacement_bootstrap(corr, pair, sid)
    packed = base64.b64encode(gzip.compress(bootstrap.encode("utf-16le"), mtime=0)).decode()
    expected = _action_sha(corr, pair, sid)
    # Decode the submitted compressed bootstrap, then extract and decompress the
    # one embedded task body.  This proves the parsed task is the dispatched one.
    return ("$ErrorActionPreference='Stop';try{$z=[Convert]::FromBase64String('"+packed+"');$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();$g.CopyTo($o);$b=[Text.Encoding]::Unicode.GetString($o.ToArray());$x=$null;$e=$null;[Management.Automation.Language.Parser]::ParseInput($b,[ref]$x,[ref]$e)|Out-Null;if($e.Count){throw 'BOOTSTRAP'};$m=[regex]::Matches($b,\"FromBase64String\\('([^']+)'\\)\");if($m.Count -ne 1){throw 'TASK_COUNT'};$z=[Convert]::FromBase64String($m[0].Groups[1].Value);$i=[IO.MemoryStream]::new([byte[]]$z);$g=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();$g.CopyTo($o);$t=[Text.Encoding]::Unicode.GetString($o.ToArray());$x=$null;$e=$null;[Management.Automation.Language.Parser]::ParseInput($t,[ref]$x,[ref]$e)|Out-Null;if($e.Count){throw 'TASK'};$h=[Security.Cryptography.SHA256]::Create();$a='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($t));$actual=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($a)))).Replace('-','').ToLowerInvariant();if($actual -cne '"+expected+"'){throw 'ACTION'};[Console]::Out.WriteLine('{\"version\":1,\"code\":\"OK\"}')}catch{[Console]::Out.WriteLine('{\"version\":1,\"code\":\"FAILED\"}');exit 1}")


def parser(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Run the fixed public PS5 parser against the actual future payload."""
    request = _request(value); path = Path(root).resolve(strict=True)
    try:
        config, _target, (env, socket, pid, ticks, sid) = base._descriptor(path)
        pair = _new_pair(path)
        if (env != "windows-cp117" or not isinstance(socket,str) or not socket
                or type(pid) is not int or pid<=0 or type(ticks) is not int or ticks<=0
                or not isinstance(sid,str) or not sid or pair is None): return {**_UNKNOWN, "correlationId": request["leaseId"]}
        encoded = base64.b64encode(replacement_powershell_preflight_script(request["leaseId"], pair, sid).encode("utf-16le")).decode()
        if len(encoded) >= 30000: return {**_UNKNOWN, "correlationId": request["leaseId"]}
        raw = base.windows_credential_probe_ssh._run_ssh(config, "archlinux", base.windows_credential_probe_ssh._remote_command(public._REMOTE_PREFLIGHT, socket, str(pid), str(ticks), encoded), None, 30)
        observed = json.loads(raw) if raw is not None else {}
        if observed.get("state") in {"passed", "failed"}:
            return {"state":observed["state"],"correlationId":request["leaseId"],"checks":["ps5-parse","gzip","embedded-task","action-hash"],"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError): pass
    return {**_UNKNOWN, "correlationId": request["leaseId"]}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Dispatch once after the ordinary immutable transfer proves guest MSI bytes."""
    request = _request(value); path = Path(root).resolve(strict=True)
    try:
        from . import windows_msi_http_transfer as transfer
        ready = preflight(path, request)
        if ready.get("state") != "ready":
            return ({**_UNKNOWN, "state":"blocked", "reason":ready.get("reason", "preflight")}
                    if ready.get("state")=="blocked" else dict(_UNKNOWN))
        config, target, descriptor = base._descriptor(path)
        handoff = transfer.ready_for_base(path, config, target.fixture_transfer_root, request["leaseId"])
        if handoff.get("state") != "ready-for-base" or handoff.get("sourceSha") != _SOURCE or handoff.get("baseMsiArtifactId") != _BASE:
            return dict(_UNKNOWN)
        pair = _new_pair(path)
        if pair is None: return dict(_UNKNOWN)
        command = _replacement_bootstrap(request["leaseId"], pair, descriptor[4])
        command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
        record = {"request": {"host":"archlinux", "correlationId":request["leaseId"], "sourceSha":_SOURCE,
                  "fixtureReceiptArtifactId":_RECEIPT, "baseMsiArtifactId":_BASE, "targetMsiArtifactId":_TARGET,
                  "expectedCurrentVersion":_BASE_VERSION}, "pair":pair, "environment":descriptor[0],
                  "socketPath":descriptor[1], "pid":descriptor[2], "startTicks":descriptor[3],
                  "expectedSid":descriptor[4], "commandSha256":command_hash, "leaseId":request["leaseId"]}
        try:
            base._reserve(path, record, config=config, target=target, descriptor=descriptor)
        except base.WindowsMsiBasePrepareError:
            return {**_UNKNOWN, "state":"blocked", "phase":"reservation", "correlationId":request["leaseId"]}
        base._open_base_campaign(path, record["request"], config, target, descriptor)
        args = (str(target.fixture_transfer_root), descriptor[0], request["leaseId"], request["leaseId"], descriptor[1],
                str(descriptor[2]), str(descriptor[3]), descriptor[4], str(handoff["length"]),
                base64.b64encode(command.encode("utf-16le")).decode(), command_hash, _SOURCE,
                pair["sourceFingerprint"], _RECEIPT, _BASE, _TARGET, "preverified")
        raw = base._remote(config, base._STAGE, args, None, 1800)
        result = json.loads(raw) if raw is not None else {}
        if result == {"state":"submitted", "correlationId":request["leaseId"]}:
            return {"state":"submitted", "correlationId":request["leaseId"], "replayAllowed":False, "nativeActionAllowed":False, "productAction":True}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        pass
    return {**_UNKNOWN, "correlationId": request["leaseId"]}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value)
    try:
        observed = base.status(Path(root).resolve(strict=True), {"correlationId": request["leaseId"]})
        if observed.get("state") == "unknown": observed = terminal_reconcile(root, value)
        if observed.get("state") in {"running", "terminal", "unknown"}:
            return {**observed, "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": observed.get("state") != "unknown"}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        pass
    return {**_UNKNOWN, "correlationId": request["leaseId"]}


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Locate the read-only pre-dispatch checkpoint for one reserved source run.

    The ordinary base diagnostic is bound to the ordinary task action hash.  A
    same-source replacement has a different, deliberately source-specific
    bootstrap, so using that observer here only converts a local admission
    refusal into an unhelpful ``unknown``.  This observer stops before legacy
    attestation or campaign claiming and exposes only a finite checkpoint.
    """
    request = _request(value); path = Path(root).resolve(strict=True)
    try:
        phase, legacy_tasks = _pre_dispatch_phase(path, request)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, base.WindowsMsiBasePrepareError):
        phase, legacy_tasks = "observer-error", None
    if phase not in _SOURCE_DIAGNOSTIC_PHASES:
        phase = "observer-error"
    result = {**_UNKNOWN, "state": "observed", "correlationId": request["leaseId"],
              "phase": phase}
    if phase == "legacy-tasks" and legacy_tasks is not None:
        result["legacyTaskState"] = "observed"
        result["legacyTasks"] = {name: legacy_tasks[name] for name in
                                 ("legacy", "c32", "recovery", "retirement", "other", "activeInstallerCount")}
        result["legacyTaskIdentities"] = legacy_tasks["identities"]
        result["unclassifiedTaskCount"] = legacy_tasks["unclassifiedTaskCount"]
    return result


def _pre_dispatch_phase(path: Path, request: Mapping[str, str]) -> tuple[str, dict[str, int] | None]:
    """Observe the exact checks before `_open_base_campaign` can dispatch.

    In particular, do not call `_require_reconciled_legacy`: its successful
    path writes a legacy attestation.  The four reads below reproduce only its
    predicates in order, then stop before that write and lease acquisition.
    """
    correlation = request["leaseId"]
    intent = base._private_intent(path, correlation)
    expected_request = {"host": "archlinux", "correlationId": correlation,
                        "sourceSha": _SOURCE, "fixtureReceiptArtifactId": _RECEIPT,
                        "baseMsiArtifactId": _BASE, "targetMsiArtifactId": _TARGET,
                        "expectedCurrentVersion": _BASE_VERSION}
    if (not isinstance(intent, Mapping) or intent.get("request") != expected_request
            or intent.get("leaseId") != correlation):
        return "local-intent", None
    pair, _ = base._stage_artifact_readonly(path, intent)
    registered = _new_pair(path)
    if registered is None:
        return "registered-pair", None
    if pair != registered:
        return "pair", None
    config, _target, descriptor = base._descriptor(path)
    env, socket, pid, ticks, sid = descriptor
    if any(intent.get(key) != expected for key, expected in (
            ("environment", env), ("socketPath", socket), ("pid", pid),
            ("startTicks", ticks), ("expectedSid", sid))):
        return "descriptor", None
    command = _replacement_bootstrap(correlation, pair, sid)
    if intent.get("commandSha256") != hashlib.sha256(command.encode("utf-16le")).hexdigest():
        return "command", None
    legacy_phase = _legacy_admission_phase(path, descriptor, lease_id=correlation)
    if legacy_phase is not None:
        return legacy_phase, (_legacy_task_inventory(path, descriptor)
                              if legacy_phase == "legacy-tasks" else None)
    # `attest_legacy_closed`, campaign lease begin, and claim role all write.
    # A clean result therefore proves only that start reached its first effect.
    return "pre-effect", None


def _legacy_task_inventory_script() -> str:
    """Count only the fixed reviewed task names and the MCP namespace remainder."""
    literals = {key: public._ps_literal(name) for key, name in _REVIEWED_TASKS.items()}
    purposes = ";".join("@{{purpose='{0}';prefix='{1}'}}".format(purpose, prefix)
                         for purpose, prefix in _TASK_PURPOSE_PREFIXES.items())
    return r'''$ErrorActionPreference='Stop'
try {
 $tokens=$null;$errors=$null
 [Management.Automation.Language.Parser]::ParseInput($MyInvocation.MyCommand.Definition,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'AST'}
 $names=@{legacy=@LEGACY@;c32=@C32@;recovery=@RECOVERY@;retirement=@RETIREMENT@}
 $all=@(Get-ScheduledTask -ErrorAction Stop)
 $selected=@($all|Where-Object {$_.TaskName -match '^VpnControl(Mcp|Cp117)' -or $_.TaskName -in @($names.Values)})
 $known=@($names.Values)
 $other=@($selected|Where-Object {$_.TaskName -cnotin $known -or $_.TaskPath -cne '\'})
 $prefixes=@(@PURPOSES@)
 if($other.Count -gt 16){throw 'BOUND'}
 $identities=@();$unclassified=0
 foreach($task in $other){
  if($task.TaskPath -cne '\'){$unclassified++;continue}
  $matched=@($prefixes|Where-Object {$task.TaskName.StartsWith($_.prefix,[StringComparison]::Ordinal)})
  if($matched.Count -ne 1){$unclassified++;continue}
  $suffix=$task.TaskName.Substring($matched[0].prefix.Length);$guid=[Guid]::Empty
  if(-not [Guid]::TryParse($suffix,[ref]$guid) -or $guid.ToString() -cne $suffix){$unclassified++;continue}
  $state=switch($task.State.ToString()){'Ready'{'ready'};'Running'{'running'};'Queued'{'queued'};'Disabled'{'disabled'};default{'other'}}
  $identities+=([pscustomobject]@{purpose=$matched[0].purpose;correlationId=$suffix;taskState=$state})
 }
 if($identities.Count+$unclassified -ne $other.Count -or @($identities|Group-Object purpose,correlationId|Where-Object {$_.Count -ne 1}).Count -ne 0){throw 'IDENTITIES'}
 $installers=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'})
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;legacy=@($selected|Where-Object {$_.TaskName -ceq $names.legacy -and $_.TaskPath -ceq '\'}).Count;c32=@($selected|Where-Object {$_.TaskName -ceq $names.c32 -and $_.TaskPath -ceq '\'}).Count;recovery=@($selected|Where-Object {$_.TaskName -ceq $names.recovery -and $_.TaskPath -ceq '\'}).Count;retirement=@($selected|Where-Object {$_.TaskName -ceq $names.retirement -and $_.TaskPath -ceq '\'}).Count;other=$other.Count;activeInstallerCount=$installers.Count;identities=$identities;unclassifiedTaskCount=$unclassified}|ConvertTo-Json -Depth 3 -Compress))
} catch {[Console]::Out.WriteLine('{"version":1,"legacy":-1,"c32":-1,"recovery":-1,"retirement":-1,"other":-1,"activeInstallerCount":-1}');exit 1}
'''.replace("@LEGACY@", literals["legacy"]).replace("@C32@", literals["c32"]).replace(
        "@RECOVERY@", literals["recovery"]).replace("@RETIREMENT@", literals["retirement"]).replace("@PURPOSES@", purposes)


def _legacy_task_inventory(path: Path, descriptor: tuple[Any, ...]) -> dict[str, int] | None:
    """Use the bounded QGA readiness reader for a non-admitting task census."""
    config, _target, current = base._descriptor(path)
    if current != descriptor:
        return None
    _env, socket, pid, ticks, _sid = descriptor
    encoded = base64.b64encode(_legacy_task_inventory_script().encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        return None
    raw = base._remote(config, base._READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    try:
        observed = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None
    item = observed.get("inventory") if isinstance(observed, Mapping) and observed.get("state") == "observed" else None
    fields = {"version", "legacy", "c32", "recovery", "retirement", "other", "activeInstallerCount",
              "identities", "unclassifiedTaskCount"}
    if (not isinstance(item, Mapping) or set(item) != fields or item.get("version") != 1
            or any(type(item.get(name)) is not int or not 0 <= item[name] <= 1000
                   for name in ("legacy", "c32", "recovery", "retirement", "other", "activeInstallerCount"))
            or any(item[name] > 1 for name in ("legacy", "c32", "recovery", "retirement"))
            or type(item.get("unclassifiedTaskCount")) is not int or not 0 <= item["unclassifiedTaskCount"] <= 16
            or not isinstance(item.get("identities"), list) or len(item["identities"]) > 16
            or len(item["identities"]) + item["unclassifiedTaskCount"] != item["other"]):
        return None
    identities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in item["identities"]:
        if (not isinstance(entry, Mapping) or set(entry) != {"purpose", "correlationId", "taskState"}
                or entry.get("purpose") not in _TASK_PURPOSE_PREFIXES
                or not isinstance(entry.get("correlationId"), str) or not _UUID.fullmatch(entry["correlationId"])
                or str(uuid.UUID(entry["correlationId"])) != entry["correlationId"]
                or entry.get("taskState") not in _TASK_STATES
                or (entry["purpose"], entry["correlationId"]) in seen):
            return None
        seen.add((entry["purpose"], entry["correlationId"]))
        identities.append({"purpose": entry["purpose"], "correlationId": entry["correlationId"],
                           "taskState": entry["taskState"]})
    return {**{name: item[name] for name in ("legacy", "c32", "recovery", "retirement", "other", "activeInstallerCount")},
            "identities": identities, "unclassifiedTaskCount": item["unclassifiedTaskCount"]}


def _legacy_admission_phase(path: Path, descriptor: tuple[Any, ...],
                            idle: Mapping[str, Any] | None = None, lease_id: str | None = None) -> str | None:
    """Read each legacy admission predicate without writing its attestation."""
    legacy = public.preinstall_status(path, "archlinux", base._LEGACY_JOB)
    if (legacy.get("state") != "observed" or legacy.get("jobId") != base._LEGACY_JOB
            or legacy.get("phase") != "Failed" or legacy.get("code") != "RUNTIME_FAILED"
            or type(legacy.get("sequence")) is not int or legacy["sequence"] < 3):
        return "legacy-job"
    if idle is None:
        idle = base.readiness(path, {"host": "archlinux", "expectedCurrentVersion": _BASE_VERSION})
    if idle.get("state") != "ready" or idle.get("activeCount") != 0:
        return "legacy-idle"
    if base._legacy_task_observation(path, descriptor, lease_id).get("state") != "cleaned":
        return "legacy-tasks"
    if base._legacy_history_observation(path, descriptor).get("state") != "clean":
        return "legacy-history"
    return None


def _action_sha(correlation: str, pair: Mapping[str, Any], sid: str) -> str:
    task = _replacement_task(correlation, pair, sid)
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(task.encode("utf-16le")).decode()
    return hashlib.sha256(arguments.encode("utf-8")).hexdigest()


def terminal_reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the consumed bootstrap using its replacement-task action hash."""
    request = _request(value); path = Path(root).resolve(strict=True); unknown = {**_UNKNOWN, "correlationId": request["leaseId"]}
    try:
        intent = base._private_intent(path, request["leaseId"])
        expected_request = {"host":"archlinux","correlationId":request["leaseId"],"sourceSha":_SOURCE,
                            "fixtureReceiptArtifactId":_RECEIPT,"baseMsiArtifactId":_BASE,
                            "targetMsiArtifactId":_TARGET,"expectedCurrentVersion":_BASE_VERSION}
        if intent is None or intent.get("request") != expected_request or intent.get("leaseId") != request["leaseId"]: return unknown
        pair, _ = base._stage_artifact_readonly(path, intent)
        expected_pair = _new_pair(path)
        if expected_pair is None or pair != expected_pair: return unknown
        config, target, (env, sock, pid, ticks, sid) = base._descriptor(path)
        if any(intent.get(key) != expected for key, expected in (("environment",env),("socketPath",sock),("pid",pid),("startTicks",ticks),("expectedSid",sid))): return unknown
        command = _replacement_bootstrap(request["leaseId"], pair, sid)
        if intent.get("commandSha256") != hashlib.sha256(command.encode("utf-16le")).hexdigest(): return unknown
        raw = base._remote(config, base._TERMINAL_RECONCILE, (str(target.fixture_transfer_root),env,request["leaseId"],sock,str(pid),str(ticks),_SOURCE,pair["sourceFingerprint"],_RECEIPT,_BASE,_TARGET,intent["commandSha256"],sid,_action_sha(request["leaseId"],pair,sid),pair["baseCliSha256"],pair["baseAppJarSha256"],pair["baseHelperSha256"],pair["baseAppJarName"]), None, 120)
        observed = json.loads(raw) if raw is not None else {}
        payload = observed.get("result") if isinstance(observed, Mapping) else None
        if (observed.get("state") != "observed" or observed.get("correlationId") != request["leaseId"] or not isinstance(payload, Mapping)
                or payload.get("result") != "PASSED" or payload.get("stage") != "READBACK" or payload.get("exitCode") != 0
                or payload.get("originalSid") != sid or payload.get("limited") is not True or payload.get("sessionId") != 1
                or payload.get("msiSha256") != _BASE.removeprefix("sha256-") or payload.get("installedVersion") != _BASE_VERSION
                or payload.get("cliSha256") != pair["baseCliSha256"] or payload.get("jarSha256") != pair["baseAppJarSha256"]
                or payload.get("helperSha256") != pair["baseHelperSha256"]
                or not base._unique_product(payload.get("priorProducts"), _BASE_VERSION)
                or not base._unique_product(payload.get("installedProducts"), _BASE_VERSION)):
            return unknown
        return {"state":"terminal","correlationId":request["leaseId"],"result":"PASSED","stage":"READBACK","exitCode":0,"sourceSha":_SOURCE,"baseArtifactId":_BASE,"replayAllowed":False}
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError): return unknown


def finish(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); path = Path(root).resolve(strict=True)
    try:
        terminal = terminal_reconcile(path, request)
        if terminal.get("state") != "terminal": return {**_UNKNOWN,"correlationId":request["leaseId"]}
        intent = base._private_intent(path, request["leaseId"]); config,target,descriptor = base._descriptor(path)
        if intent is None: return {**_UNKNOWN,"correlationId":request["leaseId"]}
        idle = base.readiness(path,{"host":"archlinux","expectedCurrentVersion":_BASE_VERSION})
        if idle.get("state") != "ready" or idle.get("activeCount") != 0: return {**_UNKNOWN,"correlationId":request["leaseId"]}
        base._verified_claimed_campaign(path,intent["request"],descriptor,config,target,request["leaseId"],"base")
        evidence=hashlib.sha256(json.dumps({"terminal":terminal,"idle":idle,"leaseId":request["leaseId"]},sort_keys=True,separators=(",",":")).encode()).hexdigest()
        return lease.finish_role(path,request["leaseId"],"base",request["leaseId"],evidence,"succeeded",base._campaign_remote(config,target))
    except (OSError, ValueError, TypeError, KeyError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError): return {**_UNKNOWN,"correlationId":request["leaseId"]}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "preflight":
        return preflight(root, inputs)
    if action == "parser": return parser(root, inputs)
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "diagnose": return diagnose(root, inputs)
    if action == "reservation-diagnose": return reservation_diagnose(root, inputs)
    if action == "terminal-reconcile": return terminal_reconcile(root, inputs)
    if action == "finish": return finish(root, inputs)
    raise WindowsCp117SourceCampaignError("Unknown new-source CP117 campaign action.")
