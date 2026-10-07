"""One-shot device admission for the source-bound Android HTTPS/SOCKS fixture.

Only an explicitly configured disposable emulator may receive the fixture CA and
two fixed ADB reverses.  Unknown submissions retain both leases for inspection.
This module has no public app mutation, package install, VPN, or force-stop path.
"""

from __future__ import annotations

import base64
import errno
import zlib
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from agent_tools import (android_admission_readback, android_native_fixture,
                         android_native_fixture_lifecycle, android_observation,
                         native_artifact_registry, ssh_transfer, ssh_transport)


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")
_MAX_CA = 65_536
_READMISSION_ROUTING_CLI_SECONDS = 300
_READMISSION_ROUTING_PROCESS_SECONDS = 315
_MOUNT_FAILURE_DIAGNOSTIC_COMMAND_BOUNDS = {30: 250, 10: 82}
# Serial subprocess limits for each generated successful proof, including all
# UID checks and fixed adapter preflights outside the public CLI subprocess.
# Tests execute the generated paths and independently count every actual call.
_READMISSION_COMMAND_BOUNDS = {
    'root-snapshot': {30: 230, 10: 53, 315: 1},
    'shell-snapshot': {30: 27, 315: 1},
    'root-public': {30: 215, 10: 52, 315: 1},
    'retired-root-public': {30: 199, 10: 52, 315: 1},
    'shell-public': {30: 23, 315: 1},
    'principal': {30: 48, 10: 13},
    'mount-observation': {30: 11},
    'retired-root-native': {30: 7, 10: 1},
    'retired-shell-native': {30: 1},
    'root-effects': {30: 3},
    'shell-effects': {30: 5},
    'terminal': {30: 12},
    'terminal-namespace': {30: 5, 10: 50},
    'terminal-shell-public': {30: 19, 315: 1},
    'recovery-native': {30: 150, 10: 1},
    'recovery-post-native': {30: 149, 10: 1},
    'recovery-effect': {30: 1},
}
_READMISSION_PATH_PROOFS = {
    'recovery-readmit': ({'root-snapshot': 2, 'recovery-native': 2},),
    'recovery-status': ({'root-snapshot': 2, 'recovery-native': 2}, {'root-public': 2, 'recovery-post-native': 2}),
    'recovery-unmount': ({'root-snapshot': 2, 'recovery-native': 3, 'root-public': 3, 'recovery-post-native': 2, 'recovery-effect': 1},),
    'cleanup-readmit': ({'root-snapshot': 2}, {'shell-snapshot': 2}),
    'cleanup-readmission-status': ({'root-snapshot': 2}, {'shell-snapshot': 2}),
    'cleanup-readmitted-status': ({'terminal-shell-public': 2, 'terminal-namespace': 2},),
    'cleanup-mount-diagnostic': ({'principal': 1, 'root-public': 4, 'mount-observation': 2},),
    'cleanup': (
        {'root-snapshot': 5, 'retired-root-public': 2, 'shell-public': 2,
         'retired-root-native': 1, 'retired-shell-native': 1, 'root-effects': 1, 'terminal': 1},
        {'shell-snapshot': 3, 'root-snapshot': 3, 'retired-root-public': 2, 'shell-public': 2,
         'retired-root-native': 1, 'retired-shell-native': 1, 'shell-effects': 1, 'terminal': 1}),
}


# Generated remaining-stage proof paths, counted independently by routine tests.
# Values are serial subprocess ceilings, not wall-clock estimates.
_REMAINING_COMMAND_BOUNDS = {
    'remaining-cleanup-admit': ({30:424,10:148,315:2},),
    'remaining-cleanup-once': ({30:1007,10:640,315:7},),
    'remaining-cleanup-status': ({30:424,10:148,315:2},{30:104,10:232,315:2}),
    'remaining-cleanup-collect': ({30:156,10:348,315:3},),
}


def _readmission_transport_seconds(action: str, remote: dict[str, Any]) -> int:
    if action in _REMAINING_COMMAND_BOUNDS and isinstance(remote.get('cleanupRemaining'),dict):
        return max(sum(seconds*calls for seconds,calls in path.items()) for path in _REMAINING_COMMAND_BOUNDS[action])+60
    if action == 'mount-failure-diagnostic' and isinstance(remote.get('mountDiagnosticCorrelation'), str) and _UUID.fullmatch(remote['mountDiagnosticCorrelation']):
        return sum(seconds * calls for seconds, calls in _MOUNT_FAILURE_DIAGNOSTIC_COMMAND_BOUNDS.items()) + 60
    if (action in _READMISSION_PATH_PROOFS and (isinstance(remote.get('cleanupReadmission'), dict) or
            action.startswith('recovery-') and isinstance(remote.get('cleanupRecovery'), dict)) and
            (action != 'cleanup' or isinstance(remote['cleanupReadmission'].get('receipt'), dict))):
        # Retain the existing 60s transport/result allowance after every serial
        # subprocess has consumed its own bound. No native guard estimate.
        return max(sum(count * sum(seconds * calls for seconds, calls in _READMISSION_COMMAND_BOUNDS[proof].items())
                       for proof, count in path.items()) for path in _READMISSION_PATH_PROOFS[action]) + 60
    return 60


_COMMAND_PHASES = frozenset({'private', 'public-environment', 'device-identity', 'device-package',
    'package-hash', 'public-status', 'public-operations', 'public-routing', 'reverse-inventory',
    'zygote-generation', 'zygote-namespace', 'stage-inode', 'stage-ca', 'target-membership',
    'stage-membership', 'target-mountinfo', 'target-ca', 'unknown'})
_COMMAND_OUTCOMES = frozenset({'nonzero', 'timeout', 'unavailable', 'oversized', 'encoding', 'guard-rejected'})
_COMMAND_STDERR_CLASSES = frozenset({'none', 'permission', 'not-found', 'syntax', 'no-process', 'other'})


def _bounded_command_diagnostic(value: Any) -> dict[str, str] | None:
    if (isinstance(value, dict) and set(value) == {'phase', 'outcome', 'stderrClass'} and
            isinstance(value.get('phase'), str) and value['phase'] in _COMMAND_PHASES and
            isinstance(value.get('outcome'), str) and value['outcome'] in _COMMAND_OUTCOMES and
            isinstance(value.get('stderrClass'), str) and value['stderrClass'] in _COMMAND_STDERR_CLASSES):
        return dict(value)
    return None

_AOSP_SU_HELP = "usage: su [WHO [COMMAND...]]\n\nSwitch to WHO (default 'root') and run the given COMMAND (default sh).\n\nWHO is a comma-separated list of user, group, and supplementary groups\nin that order."


def _bounded_principal_preflight(value: Any) -> dict[str, str] | None:
    fields = {'grammar': {'aosp-who-command', 'unsupported', 'unavailable'},
              'helperIdentity': {'verified', 'unverified'}, 'shellUid': {'verified', 'unverified'},
              'providerAccess': {'verified', 'denied', 'unverified'}}
    if (isinstance(value, dict) and set(value) == set(fields) and
            all(isinstance(value.get(key), str) and value[key] in choices for key, choices in fields.items()) and
            (value['shellUid'] != 'verified' or (value['grammar'] == 'aosp-who-command' and value['helperIdentity'] == 'verified')) and
            (value['providerAccess'] == 'unverified' or value['shellUid'] == 'verified')):
        return dict(value)
    return None

_PUBLIC_FAILURE_EXITS = {**dict.fromkeys(('INVALID_ARGUMENT', 'NOT_FOUND', 'AMBIGUOUS_LOCATION',
    'READ_ONLY_SOURCE', 'BUSY', 'CONFLICT', 'UNSUPPORTED', 'INTERACTION_REQUIRED',
    'PERMISSION_DENIED', 'PERSISTENCE_FAILED', 'RUNTIME_FAILED'), 1),
    **dict.fromkeys(('TIMEOUT', 'OUTCOME_UNKNOWN', 'UNAVAILABLE', 'INCOMPATIBLE_PROTOCOL'), 2), 'CANCELLED': 130}


def _bounded_public_failure(value: Any) -> dict[str, Any] | None:
    if (isinstance(value, dict) and set(value) == {'code', 'exitDisposition', 'final'} and
            isinstance(value.get('code'), str) and value['code'] in _PUBLIC_FAILURE_EXITS and
            isinstance(value.get('exitDisposition'), str) and value['exitDisposition'] in {'matched', 'mismatched'} and type(value.get('final')) is bool and
            value['final'] == (value['code'] not in {'TIMEOUT', 'OUTCOME_UNKNOWN'})):
        return dict(value)
    return None


def _bounded_readmission_diagnostics(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, validator in (('commandDiagnostic', _bounded_command_diagnostic),
                            ('publicFailure', _bounded_public_failure)):
        bounded = validator(value.get(name))
        if bounded is not None:
            result[name] = bounded
    return result

_READMISSION_REASONS = frozenset({
    'cleanup_readmission_unverified', 'transport_or_receipt_unknown', 'command_outcome_unknown',
    'readmission_terminal_lease_present', 'readmission_terminal_native_unverified', 'readmission_terminal_owned_path_present', 'cleaned_changed', 'owner_changed',
    'command_failed', 'command_encoding', 'cli_environment_unavailable', 'remote_root_unsafe', 'job_unsafe', 'intent_changed',
    'lease_changed', 'lease_unsafe', 'lease_replaced', 'private_path_invalid', 'private_parent_unsafe',
    'private_file_unsafe', 'private_file_changed', 'private_file_unavailable', 'device_identity_changed',
    'package_path_changed', 'package_changed', 'backup_changed', 'history_unknown', 'runtime_not_off',
    'state_or_cleanup_uncertain', 'readmission_requires_rooted_api29', 'readmission_requires_api29_shell_or_root', 'readmission_failed_mount_unverified', 'readmission_reverse_present',
    'readmission_phase_invalid', 'readmission_child_present', 'readmission_child_inventory_unknown',
    'mount_intent_invalid', 'readmission_stage_changed', 'readmission_namespace_changed',
    'readmission_ca_changed', 'readmission_membership_invalid', 'readmission_namespace_foreign',
    'readmission_mount_present_or_foreign', 'readmission_mountinfo_invalid', 'readmission_rules_invalid',
    'readmission_public_invalid', 'readmission_principal_unverified', 'readmission_target_ca_present', 'readmission_target_ca_unverified', 'readmission_owner_changed', 'readmission_status_changed',
    'readmission_rules_changed', 'readmission_native_changed', 'readmission_binding_invalid',
    'readmission_observation_changed', 'readmission_receipt_changed', 'readmission_receipt_stale',
    'readmission_receipt_absent', 'readmission_receipt_present', 'readmission_target_mount_observed', 'readmission_mount_diagnostic_invalid', 'zygote_identity_invalid',
    'zygote_generation_invalid', 'zygote_namespace_invalid', 'staging_identity_invalid',
})


def _readmission_reason(value: Any) -> str:
    return value if isinstance(value, str) and value in _READMISSION_REASONS else 'cleanup_readmission_unverified'



def _stable_ca(root: Path, artifact_id: str, source_sha: str) -> bytes:
    if not isinstance(artifact_id, str) or not _ARTIFACT.fullmatch(artifact_id):
        raise ValueError("Android endpoint requires exact CA artifact ID")
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    item, location = verified.get("artifact", {}), verified.get("location", {})
    if (verified.get("verification") != "verified" or item.get("platform") != "android" or
            item.get("artifactKind") != "fixture-ca" or item.get("sha256") != artifact_id[7:] or
            not isinstance(location.get("localPath"), str)):
        raise ValueError("Android endpoint CA artifact is unverified")
    if item.get("sourceSha") != source_sha:
        raise ValueError("Android endpoint CA artifact belongs to another source")
    path = Path(location["localPath"])
    if not path.is_absolute():
        raise ValueError("Android endpoint CA location is not absolute")
    if any(stat.S_ISLNK(parent.lstat().st_mode) for parent in (path.parent, *path.parent.parents)):
        raise ValueError("Android endpoint CA path has symlink ancestry")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or not 0 < before.st_size <= _MAX_CA):
            raise ValueError("Android endpoint CA file is unsafe")
        payload = os.read(descriptor, _MAX_CA + 1)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                len(payload) != before.st_size or hashlib.sha256(payload).hexdigest() != item["sha256"]):
            raise ValueError("Android endpoint CA bytes changed")
        return payload
    finally:
        os.close(descriptor)


def _local_directory(root: Path) -> Path:
    directory = root / ".rag_index" / "android-endpoint-admission"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android endpoint journal directory is unsafe")
    return directory


def _intent_path(root: Path, correlation_id: str) -> Path:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android endpoint requires canonical correlation UUID")
    return _local_directory(root) / (correlation_id + ".json")


@contextmanager
def _shared_device_lease(root: Path, host: str, device: str):
    """Serialize endpoint and installer claims on the same exact AVD."""
    directory = root / ".rag_index" / "android-native-device-leases"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Android shared device lease directory is unsafe")
    lease = directory / ("lease-" + host + "-" + device + ".json")
    lock = directory / ("lock-" + host + "-" + device + ".json")
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        meta = os.fstat(descriptor)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o600:
            raise ValueError("Android shared device lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield lease
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_intent(root: Path, correlation_id: str) -> dict[str, Any]:
    return android_native_fixture_lifecycle._read_plan(_intent_path(root, correlation_id))


def _status_intent(root: Path, correlation_id: str) -> dict[str, Any] | None:
    """Read an existing private intent without creating any status-side state."""
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android endpoint requires canonical correlation UUID")
    directory = root / ".rag_index" / "android-endpoint-admission"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Android endpoint journal directory is unsafe")
    path = directory / (correlation_id + ".json")
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return android_native_fixture_lifecycle._read_plan(path)


def _response(state: str, correlation_id: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    return {"ok": state in {"ready", "cleaned"}, "state": state, "reason": reason,
            "correlationId": correlation_id, "replayAllowed": False,
            "productMutationAllowed": False, "installerTargetAdmitted": False, **extra}


def _runtime_parent_correlation(root: Path, endpoint_correlation_id: str) -> tuple[str, str] | None:
    """Read the one runtime child binding without creating local status state."""
    directory = root / ".rag_index" / "android-runtime-acceptance"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("runtime child journal directory is unsafe")
    path = directory / ("parent-" + endpoint_correlation_id + ".lease")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_nlink != 1 or not 0 < info.st_size <= 1024):
            raise ValueError("runtime child lease is unsafe")
        raw = os.read(descriptor, 1025)
        after = os.fstat(descriptor)
        if (len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("runtime child lease changed")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError, TypeError) as error:
        raise ValueError("runtime child lease is invalid") from error
    correlation = value.get("runtimeCorrelationId") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or set(value) != {"parentCorrelationId", "runtimeCorrelationId"} or
            value.get("parentCorrelationId") != endpoint_correlation_id or
            not isinstance(correlation, str) or not _UUID.fullmatch(correlation)):
        raise ValueError("runtime child lease is invalid")
    return correlation, hashlib.sha256(raw).hexdigest()


_RUNTIME_CHILD_STATUS = android_observation._canonical_cli_environment_source() + r"""
import json,os,pathlib,stat,subprocess,sys
root_raw,correlation,expected_json=sys.argv[1:]
root=pathlib.Path(root_raw); expected=json.loads(expected_json)
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,**extra},separators=(',',':'))); raise SystemExit(0)
def private(name,limit=8192):
 path=root/name
 try:
  fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  with os.fdopen(fd,'rb') as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=limit: emit('unknown','child_record_unsafe')
   raw=source.read(limit+1); after=os.fstat(source.fileno())
  if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): emit('unknown','child_record_changed')
  return json.loads(raw)
 except FileNotFoundError: return None
 except (OSError,ValueError,TypeError,UnicodeError): emit('unknown','child_record_unavailable')
def command(argv,env):
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,check=False,env=env)
 except (OSError,subprocess.TimeoutExpired): emit('unknown','child_status_unavailable')
 if done.returncode or len(done.stdout)>65536: emit('unknown','child_status_unavailable')
 try: return json.loads(done.stdout.decode('utf-8','strict'))
 except (UnicodeError,ValueError): emit('unknown','child_status_invalid')
try:
 info=root.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit('unknown','remote_root_unsafe')
 activity=private('android-runtime-acceptance-'+correlation+'.json')
 endpoint={'state':'ready','correlationId':expected['parentCorrelationId'],'sourcePackageSha256':expected['sourcePackageSha256'],'owner':expected['expectedOwner']}
 fixture={'campaignId':expected['campaignId'],'deviceUid':'2000','api':expected['api'],'avd':expected['avd']}
 required={'schema':1,'kind':'android-runtime-acceptance','state':'running','parentCorrelationId':expected['parentCorrelationId'],'runtimeCorrelationId':correlation,'campaignId':expected['campaignId'],'sourcePackageSha256':expected['sourcePackageSha256'],'expectedOwner':expected['expectedOwner'],'parentLeaseSha256':expected['parentLeaseSha256'],'endpoint':endpoint,'fixture':fixture}
 if activity!=required: emit('unknown','child_activity_invalid')
 terminal=private('android-runtime-acceptance-'+correlation+'.terminal.json')
 if terminal is None: emit('running','child_terminal_absent')
 closing=terminal.get('closingRevision') if isinstance(terminal,dict) else None
 restore={'settings':True,'source':True,'routing':True,'locationsEmpty':True,'selectedNull':True,'activeNull':True,'runtimeOff':True}
 if type(closing) is not int or closing<=expected['openingRevision']: emit('unknown','child_terminal_invalid')
 exact={'schema':1,'kind':'android-runtime-acceptance','state':'stopped','parentCorrelationId':expected['parentCorrelationId'],'runtimeCorrelationId':correlation,'campaignId':expected['campaignId'],'sourcePackageSha256':expected['sourcePackageSha256'],'expectedOwner':expected['expectedOwner'],'parentLeaseSha256':expected['parentLeaseSha256'],'closingOwner':expected['expectedOwner'],'closingRevision':closing,'admittedMode':terminal.get('admittedMode') if isinstance(terminal,dict) else None,'restoration':restore,'terminal':True}
 if terminal!=exact or terminal.get('admittedMode') not in {'vpn-authorized','proxy-only'}: emit('unknown','child_terminal_invalid')
 environment=public_cli_environment(expected['adb'],pathlib.Path(expected['cli']))
 value=command([expected['cli'],'--json','--android','--serial',expected['serial'],'--timeout-seconds','30','status'],environment)
 data=value.get('data') if isinstance(value,dict) else None
 if (value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=expected['expectedOwner'] or value.get('configurationRevision')!=closing or not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped' or data.get('selectedLocationId') is not None or data.get('activeLocationId') is not None): emit('unknown','child_fresh_restoration_invalid')
 emit('terminal',closingRevision=closing)
except (KeyError,TypeError,ValueError): emit('unknown','child_status_invalid')
"""


def _runtime_child_status(root: Path, intent: dict[str, Any], runtime_correlation_id: str, parent_lease_sha256: str) -> str:
    """Observe a child under its parent binding; no endpoint cleanup effect occurs here."""
    try:
        remote = intent["remote"]
        config = ssh_transport.load_config(root)
        host = intent["host"]
        if (host not in config.hosts or ssh_transport.connection_host(config, host).password is not None or
                config.hosts[host].fixture_transfer_root is None or
                str(config.hosts[host].fixture_transfer_root) != intent["remoteRoot"]):
            return "unknown"
        expected = {"parentCorrelationId": intent["correlationId"], "campaignId": remote["campaignId"],
                    "sourcePackageSha256": remote["packageSha256"], "expectedOwner": remote["owner"],
                    "openingRevision": remote["revision"], "parentLeaseSha256": parent_lease_sha256,
                    "api": remote["api"], "avd": remote["avd"], "adb": remote["adb"],
                    "cli": remote["cli"], "serial": remote["serial"]}
        argv = ssh_transport.build_ssh_argv(
            config, host, 60,
            command=ssh_transfer._python_command(_RUNTIME_CHILD_STATUS, str(config.hosts[host].fixture_transfer_root),
                                                  runtime_correlation_id,
                                                  json.dumps(expected, sort_keys=True, separators=(",", ":"))))
        code, output = ssh_transfer._bounded_run(argv, None, 60)
        value = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
    except (KeyError, OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        return "unknown", None
    if not isinstance(value, dict) or value.get("correlationId") != runtime_correlation_id:
        return "unknown", None
    if value.get("state") == "terminal" and type(value.get("closingRevision")) is int:
        return "terminal", value["closingRevision"]
    if value.get("state") in {"running", "unknown"}:
        return value["state"], None
    return "unknown", None


def _runtime_child_cleanup_guard(root: Path, intent: dict[str, Any]) -> tuple[str | None, int | None]:
    """Allow cleanup only with no child binding or a freshly observed terminal child."""
    try:
        correlation = _runtime_parent_correlation(root, intent["correlationId"])
    except ValueError:
        return "blocked_child_unknown", None
    if correlation is None:
        return None, None
    runtime_correlation_id, parent_lease_sha256 = correlation
    state, closing_revision = _runtime_child_status(root, intent, runtime_correlation_id, parent_lease_sha256)
    if state == "terminal" and type(closing_revision) is int and closing_revision > intent["remote"]["revision"]:
        return None, closing_revision
    return ("blocked_child_running" if state == "running" else "blocked_child_unknown"), None


def _mount_proof(expected: dict[str, Any], observed: dict[str, Any], mountinfo: str) -> bool:
    """Require a unique bind in the same zygote generation and mount namespace."""
    if (not isinstance(expected, dict) or not isinstance(observed, dict) or
            observed != {key: expected.get(key) for key in ("pid", "startTicks", "namespace")} or
            not isinstance(mountinfo, str)):
        return False
    target, staging = expected.get("target"), expected.get("staging")
    if not isinstance(target, str) or not isinstance(staging, str):
        return False
    entries = []
    for line in mountinfo.splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) >= 5 and fields[4] == target:
            entries.append(fields[3])
    return bool(entries) and entries[-1] == staging


_ENDPOINT_ADB_ADAPTER = r'''
import hashlib,json,os,pathlib,re,stat,sys
args=sys.argv[1:]; config=json.loads(CONFIG)
uid=r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
URI='content://com.kardinal.vpncontrol.control'
def reject(): raise SystemExit(126)
def marker(identifier):
 if not re.fullmatch(uid,identifier): reject()
 return pathlib.Path(__file__).parent/('request-'+identifier)
def accepted(identifier):
 path=marker(identifier)
 try:
  info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>256: reject()
  return json.loads(path.read_bytes())
 except (OSError,ValueError): reject()
if args==['devices']: os.execv(config['adb'],[config['adb'],*args])
if args[:5]!=['-s',config['serial'],'shell','-T','content']: reject()
words=args[5:]; payload=None
if len(words)==4 and words[:3]==['write','--uri',URI+'/document-uploads']:
 reject()
elif len(words)==3 and words[:2]==['write','--uri']:
 match=re.fullmatch(re.escape(URI)+r'/(?:document-uploads/('+uid+r')/0|requests/('+uid+r'))',words[2])
 if not match: reject()
 identifier=match[1] or match[2]; payload=sys.stdin.buffer.read(65537)
 if len(payload)>65536: reject()
 try: request=json.loads(payload)
 except (ValueError,UnicodeError): reject()
 if (not isinstance(request,dict) or set(request)!={'schemaVersion','requestId','controllerId','ifRevision','interactive','asynchronous','command'} or
     type(request.get('schemaVersion')) is not int or request['schemaVersion']!=1 or not isinstance(request.get('requestId'),str) or not re.fullmatch(uid,request['requestId']) or
     (request.get('controllerId')!=config['owner'] if config['owner'] is not None else request.get('controllerId') is not None or config['operation']!='status') or (request.get('ifRevision') is not None and (type(request.get('ifRevision')) is not int or request['ifRevision']!=config['revision'])) or request.get('interactive') is not False or request.get('asynchronous') is not False or
     request.get('command')!={'operation':config['operation'],'arguments':{}}): reject()
 data={'sha256':hashlib.sha256(payload).hexdigest(),'byteCount':len(payload)}
 try:
  fd=os.open(marker(identifier),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'w') as out: json.dump(data,out)
 except OSError: reject()
elif len(words)==3 and words[:2]==['read','--uri']:
 match=re.fullmatch(re.escape(URI)+r'/results/('+uid+r')',words[2])
 if not match: reject()
 accepted(match[1])
elif len(words) in (5,7) and words[:4]==['call','--uri',URI,'--method']:
 method=words[4]; argument=words[6] if len(words)==7 and words[5]=='--arg' else None
 if len(words)==7 and words[5]!='--arg': reject()
 if method=='document-begin':
  if argument is None or not re.fullmatch(uid,argument): reject()
 elif method=='create':
  if argument is not None: reject()
 elif method=='document-seal':
  match=re.fullmatch('('+uid+r'):(0|[1-9][0-9]*):([0-9a-f]{64})',argument or '')
  if not match or accepted(match[1])!={'sha256':match[3],'byteCount':int(match[2])}: reject()
 elif method=='document-read':
  match=re.fullmatch('('+uid+r'):(0|[1-9][0-9]*):([1-9][0-9]*)',argument or '')
  if not match or int(match[3])>65536: reject()
  accepted(match[1])
 elif method in {'document-submit','document-status','document-result','document-result-status','status'}:
  accepted(argument or '')
 elif method in {'document-discard','delete'}:
  # Cleanup of an existing transfer is allowed even when request upload failed.
  marker(argument or '')
 else: reject()
else: reject()
import subprocess
for probe, wanted in ((['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su'],config['suIdentity'][0]),(['sha256sum','/system/xbin/su'],config['suIdentity'][1])):
 try:
  result=subprocess.run([config['adb'],'-s',config['serial'],'shell','-T',*probe],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
  if result.returncode or result.stderr or len(result.stdout)>4096 or result.stdout.decode('utf-8','strict').strip()!=wanted: reject()
 except (OSError,subprocess.TimeoutExpired,UnicodeError): reject()
argv=[config['adb'],'-s',config['serial'],'shell','-T','/system/xbin/su','2000,2000','/system/bin/content',*words]
if payload is None: os.execv(config['adb'],argv)
import subprocess
result=subprocess.run(argv,input=payload,check=False)
raise SystemExit(result.returncode)
'''

_REMOTE = ('ENDPOINT_ADAPTER = ' + repr(_ENDPOINT_ADB_ADAPTER) + '\n' +
           'ROUTING_CLI_SECONDS = ' + repr(_READMISSION_ROUTING_CLI_SECONDS) + '\n' +
           'ROUTING_PROCESS_SECONDS = ' + repr(_READMISSION_ROUTING_PROCESS_SECONDS) + '\n' +
           'AOSP_HELP = ' + repr(_AOSP_SU_HELP.strip()) + '\n') + r'''
import base64,fcntl,hashlib,json,os,pathlib,re,shlex,stat,subprocess,sys,tempfile
action,root_raw,device,correlation,expected_json=sys.argv[1:]
root=pathlib.Path(root_raw); expected=json.loads(expected_json)
recovery=expected.pop('cleanupRecovery',None)
readmission=expected.pop('cleanupReadmission',None)
remaining=expected.pop('cleanupRemaining',None)
if recovery is not None: readmission={'correlationId':recovery.get('correlationId'),'originalIntentSha256':recovery.get('originalIntentSha256')}
mount_diagnostic_correlation=expected.pop('mountDiagnosticCorrelation',None)
original_revision=expected.pop('cleanupOriginalRevision',None)
if original_revision is not None:
 if action!='cleanup' or type(original_revision) is not int or type(expected.get('revision')) is not int or expected['revision']<=original_revision: raise ValueError('cleanup_revision_invalid')
stored_expected=dict(expected)
if original_revision is not None: stored_expected['revision']=original_revision
if readmission is not None and action in {'cleanup','cleanup-readmitted-status'}:
 receipt=readmission.get('receipt') if isinstance(readmission,dict) else None
 if not isinstance(receipt,dict): raise ValueError('cleanup_readmission_invalid')
 stored_expected['owner']=receipt.get('originalOwner'); stored_expected['revision']=receipt.get('originalRevision')
job=root/('android-endpoint-'+correlation)
lease=root/('android-native-device-'+device+'.lease')
lock=root/('android-native-device-'+device+'.lock')
def emit(state,reason=None,**extra):
 print(json.dumps({'state':state,'reason':reason,'correlationId':correlation,**extra},sort_keys=True,separators=(',',':')),flush=True)
 raise SystemExit(0)
diagnostic_actions={'remaining-cleanup-admit','remaining-cleanup-once','remaining-cleanup-status','remaining-cleanup-collect','cleanup-readmit','cleanup-readmission-status','cleanup-mount-diagnostic','cleanup-readmitted-status','mount-failure-diagnostic','recovery-readmit','recovery-unmount','recovery-status'}
diagnostic_phase='private'
principal_preflight=None
principal_identity=None
observed_readmission_owner=None
readmission_stage_retired=False
readmission_mount_pin=None
def principal_extra(): return {'principalPreflight':principal_preflight} if principal_preflight is not None else {}
def step(phase):
 global diagnostic_phase
 if action in diagnostic_actions: diagnostic_phase=phase
def unknown(reason):
 extra={'commandDiagnostic':{'phase':diagnostic_phase,'outcome':'guard-rejected','stderrClass':'none'}} if action in diagnostic_actions else {}
 emit('unknown',reason,**extra,**principal_extra())
def private(path,limit=67108864):
 step('private')
 try:
  parts=path.relative_to(root).parts
  if not parts or any(part in ('','.','..') for part in parts): unknown('private_path_invalid')
  parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
  try:
   for part in parts[:-1]:
    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
    os.close(parent); parent=child
    info=os.fstat(parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('private_parent_unsafe')
   fd=os.open(parts[-1],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=parent)
   with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>limit: unknown('private_file_unsafe')
    raw=stream.read(limit+1); after=os.fstat(stream.fileno())
    named=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
    generation=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
    if len(raw)!=info.st_size or generation(info)!=generation(after) or generation(after)!=generation(named): unknown('private_file_changed')
    return raw
  finally: os.close(parent)
 except (OSError,ValueError): unknown('private_file_unavailable')
def record(path,value):
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
 directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0)); os.fsync(directory); os.close(directory)
def public_words(argv):
 words=argv[7:]
 if words[:1]==['--controller-id']:
  if len(words)<3 or not isinstance(words[1],str) or not 0<len(words[1])<=256 or any(ord(char)<32 for char in words[1]): unknown('readmission_public_invalid')
  words=words[2:]
 return words
def command_phase(argv):
 if argv[0]==expected['cli']:
  words=public_words(argv)
  return 'public-status' if words==['status'] else 'public-operations' if words==['operations','list'] else 'public-routing' if words==['routing','show'] else 'unknown'
 if argv[3:5]==['reverse','--list']: return 'reverse-inventory'
 if argv[3:5]!=['shell','-T']: return 'unknown'
 words=argv[5:]
 if words[:1] in (['id'],['getprop']): return 'device-identity'
 if words[:2]==['pm','path']: return 'device-package'
 if words[:1]==['sha256sum']: return 'package-hash' if words[1].startswith('/data/app/') else 'stage-ca'
 if words[:1]==['readlink']: return 'zygote-namespace'
 if words[:1]==['stat']: return 'stage-inode'
 if words[:1]==['cat']: return 'target-mountinfo' if words[1].endswith('/mountinfo') else 'zygote-generation'
 if words[:2]==['sh','-c']:
  source=words[2]
  if '__VPN_CONTROL_MOUNTINFO__' in source: return 'stage-membership' if '/data/local/tmp/vpn-control-endpoint-'+correlation in source else 'target-membership'
  if 'sha256sum ' in source: return 'target-ca'
 return 'unknown'
def command_failure(reason,outcome,stderr=b'',public_failure=None):
 if action not in diagnostic_actions: unknown(reason)
 try: error=stderr[:4096].decode('utf-8','replace')
 except (TypeError,AttributeError): error=''
 kind='permission' if 'Permission denied' in error or 'Operation not permitted' in error else 'not-found' if 'No such file' in error or 'not found' in error else 'syntax' if 'syntax error' in error.lower() else 'no-process' if 'No such process' in error else 'other' if error else 'none'
 extra={'publicFailure':public_failure} if public_failure is not None else {}
 emit('unknown',reason,commandDiagnostic={'phase':diagnostic_phase,'outcome':outcome,'stderrClass':kind},**extra,**principal_extra())
def command(argv,timeout=30,max_bytes=1048576,env=None):
 step(command_phase(argv))
 try:
  if argv[0]==expected['cli'] and ((remaining is not None or action=='cleanup' and (isinstance(readmission,dict) or os.path.lexists(job/'mount-intent.json')) or action in {'cleanup-mount-diagnostic','cleanup-readmit','cleanup-readmission-status','recovery-readmit','recovery-unmount','recovery-status'} and isinstance(readmission,dict)) or action=='mount-failure-diagnostic') and shell('id','-u')=='0':
   result=rooted_public_read(argv,timeout,env); step(command_phase(argv))
  else: result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE if action in diagnostic_actions else subprocess.DEVNULL,timeout=timeout,check=False,env=env)
 except subprocess.TimeoutExpired: command_failure('command_outcome_unknown','timeout')
 except OSError: command_failure('command_outcome_unknown','unavailable')
 if result.returncode:
  failure=None
  if action in diagnostic_actions and argv[0]==expected['cli'] and len(result.stdout)<=65536:
   try:
    value=json.loads(result.stdout)
    exits={**dict.fromkeys(('INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE','BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED'),1),**dict.fromkeys(('TIMEOUT','OUTCOME_UNKNOWN','UNAVAILABLE','INCOMPATIBLE_PROTOCOL'),2),'CANCELLED':130}
    if isinstance(value,dict) and type(value.get('schemaVersion')) is int and value['schemaVersion']==1 and value.get('ok') is False and isinstance(value.get('code'),str) and value['code'] in exits and type(value.get('final')) is bool and value['final']==(value['code'] not in {'TIMEOUT','OUTCOME_UNKNOWN'}):
     failure={'code':value['code'],'exitDisposition':'matched' if result.returncode==exits[value['code']] else 'mismatched','final':value['final']}
   except (ValueError,UnicodeError): pass
  command_failure('command_failed','nonzero',result.stderr,failure)
 if len(result.stdout)>max_bytes: command_failure('command_failed','oversized')
 try: return result.stdout.decode('utf-8','strict').strip()
 except UnicodeError: command_failure('command_encoding','encoding')
adb=expected['adb']; cli=expected['cli']; serial=expected['serial']; api=str(expected['api']); avd=expected['avd']
step('public-environment')
try: environment=public_cli_environment(adb,pathlib.Path(cli))
except (OSError,ValueError,TypeError): unknown('cli_environment_unavailable')
def adb_call(*args,timeout=30,max_bytes=1048576): return command([adb,'-s',serial,*args],timeout,max_bytes)
def shell(*args): return adb_call('shell','-T',*args)
def identity(uid='2000'):
 if shell('id','-u')!=uid or shell('getprop','ro.build.version.sdk')!=api or {x for x in (shell('getprop','ro.kernel.qemu.avd_name'),shell('getprop','ro.boot.qemu.avd_name')) if x}!={avd} or shell('getprop','ro.product.cpu.abi')!='x86_64': unknown('device_identity_changed')
def installed():
 paths=[x.removeprefix('package:') for x in shell('pm','path','com.kardinal.vpncontrol').splitlines() if x.startswith('package:') and x.endswith('/base.apk')]
 if len(paths)!=1 or not paths[0].startswith('/data/app/'): unknown('package_path_changed')
 parts=shell('sha256sum',paths[0]).split()
 if len(parts)!=2 or parts[1]!=paths[0] or parts[0]!=expected['packageSha256']: unknown('package_changed')
def public_argv(words,routing=False):
 owner=observed_readmission_owner if remaining is not None else expected['owner'] if action=='mount-failure-diagnostic' or action=='cleanup' and readmission is None else None
 if isinstance(readmission,dict):
  owner=expected['owner'] if isinstance(readmission.get('receipt'),dict) else observed_readmission_owner
 if owner is not None and (not isinstance(owner,str) or not owner or len(owner)>256 or any(ord(x)<32 for x in owner)): unknown('readmission_public_invalid')
 argv=[cli,'--json','--android','--serial',serial,'--timeout-seconds',str(ROUTING_CLI_SECONDS) if routing else '30']
 return [*argv,*(['--controller-id',owner] if owner is not None else []),*words]
def public(*args):
 value=json.loads(command(public_argv(args),max_bytes=65536,env=environment))
 if not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=expected['owner'] or value.get('configurationRevision')!=expected['revision']: unknown('owner_changed')
 return value
def guard(uid='2000'):
 identity(uid); installed()
 status=public('status'); data=status.get('data')
 if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped': unknown('runtime_not_off')
 ops=public('operations','list').get('data',{}).get('operations')
 if not isinstance(ops,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in ops): unknown('history_unknown')
 backup=pathlib.Path(expected['backupPath'])
 if not backup.is_relative_to(root) or hashlib.sha256(private(backup)).hexdigest()!=expected['backupSha256']: unknown('backup_changed')
 return status
def routes():
 raw=adb_call('reverse','--list',max_bytes=16384); result={}
 for line in raw.splitlines():
  fields=line.split()
  if len(fields)==3:
   prefix=fields[0]
   # `adb -s` binds the selected server transport; this label is syntax only.
   if prefix not in {serial,'host','UsbFfs'} and not (re.fullmatch(r'host-([1-9][0-9]{0,9})',prefix) and int(prefix[5:])<=2147483647): unknown('reverse_inventory_invalid')
   fields=fields[1:]
  if len(fields)!=2 or any(not re.fullmatch(r'tcp:[0-9]+',x) for x in fields): unknown('reverse_inventory_invalid')
  port=int(fields[0][4:]); host=int(fields[1][4:])
  if not 1<=port<=65535 or not 1<=host<=65535 or port in result: unknown('reverse_inventory_invalid')
  result[port]=host
 return result
def fixture_routes():
 current=routes()
 if current!={18080:expected['httpsHostPort'],18081:expected['socksHostPort']}: unknown('fixture_reverse_changed_or_foreign')
 return current
def reverse_inventory_diagnostic():
 # This observer classifies syntax only.  It never treats a prefix as device identity.
 try:
  completed=subprocess.run([adb,'-s',serial,'reverse','--list'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
  if completed.returncode or len(completed.stdout)>16384: return {'state':'unknown'}
  raw=completed.stdout.decode('utf-8','strict')
 except (OSError,subprocess.TimeoutExpired,UnicodeError): return {'state':'unknown'}
 lines=raw.splitlines()
 if len(lines)>16: return {'state':'unknown'}
 records=[]
 for line in lines:
  fields=line.split()
  if not fields: continue
  form='two-endpoint' if len(fields)==2 else 'three-host' if len(fields)==3 and fields[0]=='host' else 'three-configured-serial' if len(fields)==3 and fields[0]==serial else 'three-usb-ffs' if len(fields)==3 and fields[0]=='UsbFfs' else 'three-adb-host-transport' if len(fields)==3 and re.fullmatch(r'host-([1-9][0-9]{0,9})',fields[0]) and int(fields[0][5:])<=2147483647 else 'three-other' if len(fields)==3 else 'invalid'
  ports=[]
  endpoints=fields if len(fields)==2 else fields[1:] if len(fields)==3 else ()
  valid=len(endpoints)==2 and all(re.fullmatch(r'tcp:[1-9][0-9]{0,4}',x) and 1<=int(x[4:])<=65535 for x in endpoints)
  if valid: ports=[int(x[4:]) for x in endpoints]
  records.append({'form':form,'ports':ports,'portsValid':valid})
 return {'state':'observed','recordCount':len(records),'records':records}
def checkpoint(phase):
 if phase not in {'root','stage','mount','unroot','https-reverse','socks-reverse','cleanup-unroot','cleanup-reverse-https','cleanup-reverse-socks','cleanup-root','cleanup-unmount','cleanup-stage-remove','cleanup-final-unroot'}: unknown('checkpoint_invalid')
 record(job/('checkpoint-'+phase+'.json'),{'phase':phase})
def partial_diagnostic():
 # Only fixed local records and read-only selected-device observations are used here.
 def plan(name):
  try:
   path=job/name; item=path.lstat()
   if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600 or item.st_size>8192: return None
   fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
   try: raw=os.read(fd,8193)
   finally: os.close(fd)
   value=json.loads(raw)
   return value if isinstance(value,dict) else None
  except (OSError,ValueError,UnicodeError): return None
 def uid():
  try:
   done=subprocess.run([adb,'-s',serial,'shell','-T','id','-u'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
   raw=done.stdout.decode('utf-8','strict').strip()
   return 'root' if done.returncode==0 and raw=='0' else 'shell' if done.returncode==0 and raw=='2000' else 'other' if done.returncode==0 else 'unknown'
  except (OSError,subprocess.TimeoutExpired,UnicodeError): return 'unknown'
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'; staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 stage=plan('stage.json'); mount=plan('mount-intent.json'); owned=plan('stage-owned.json')
 stage_state='before-root' if stage=={'phase':'before_root','target':target,'staging':staging} else 'absent' if stage is None else 'invalid'
 mount_state='recorded' if isinstance(mount,dict) and mount.get('target')==target and mount.get('staging')==staging else 'absent' if mount is None else 'invalid'
 zygote_state='recorded' if isinstance(mount,dict) and isinstance(mount.get('zygote'),dict) and isinstance(mount['zygote'].get('pid'),str) and mount['zygote']['pid'].isdecimal() and type(mount['zygote'].get('startTicks')) is int and isinstance(mount['zygote'].get('namespace'),str) else 'absent' if mount is None else 'invalid'
 staging_state='recorded' if isinstance(owned,dict) and owned.get('staging')==staging and isinstance(owned.get('stagingIdentity'),str) and re.fullmatch(r'0:755:[0-9]+:[0-9]+',owned['stagingIdentity']) else 'absent' if owned is None else 'invalid'
 phase='none'
 for name in ('socks-reverse','https-reverse','unroot','mount','stage','root'):
  item=plan('checkpoint-'+name+'.json')
  if item is not None:
   phase=name if item=={'phase':name} else 'invalid'; break
 ca='absent'
 try:
  item=(job/'ca.pem').lstat(); ca='present' if stat.S_ISREG(item.st_mode) and item.st_uid==os.getuid() and stat.S_IMODE(item.st_mode)==0o600 and item.st_size>0 else 'invalid'
 except OSError: pass
 current_uid=uid(); mounted='unobserved'
 if current_uid=='root' and mount_state=='recorded' and zygote_state=='recorded':
  try:
   done=subprocess.run([adb,'-s',serial,'shell','-T','cat','/proc/'+mount['zygote']['pid']+'/mountinfo'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
   raw=done.stdout.decode('utf-8','strict')
   entries=[line.split(' - ',1)[0].split()[3] for line in raw.splitlines() if len(line.split(' - ',1)[0].split())>=5 and line.split(' - ',1)[0].split()[4]==mount['target']]
   mounted='present' if done.returncode==0 and entries and entries[-1]==mount['staging'] else 'absent' if done.returncode==0 else 'unknown'
  except (OSError,subprocess.TimeoutExpired,UnicodeError): mounted='unknown'
 def mount_diagnostic():
  result={'state':'unobserved','generation':'unknown','namespaceUid':'unknown','target':'unknown','staging':'unknown','exit':'unavailable','errorClass':'none','nsenterBinary':'unknown','nsenterId':'unavailable','absoluteId':'unavailable','failurePhase':'unknown','outsideBind':'unknown','insideBind':'unknown','relativeMount':'unknown','targetMountMembership':'unknown','outsideCapSysAdmin':'unknown','insideCapSysAdmin':'unknown','selinux':'unknown','domain':'unknown'}
  if current_uid!='root' or mount_state!='recorded' or zygote_state!='recorded' or staging_state!='recorded': return result
  pid=mount['zygote']['pid']
  def run(words):
   try:
    done=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    if len(done.stdout)>4096 or len(done.stderr)>4096: return None,'unavailable','other'
    err=done.stderr.decode('utf-8','strict')
    kind='not-found' if ('No such file' in err or 'not found' in err) else 'permission' if ('Permission denied' in err or 'Operation not permitted' in err) else 'no-process' if 'No such process' in err else 'invalid' if 'Invalid argument' in err else 'other' if done.returncode else 'none'
    return done,('ok' if done.returncode==0 else 'nonzero'),kind
   except (OSError,subprocess.TimeoutExpired,UnicodeError): return None,'unavailable','other'
  before,exit_code,error=run(['cat','/proc/'+pid+'/stat'])
  namespace,namespace_exit,namespace_error=run(['readlink','/proc/'+pid+'/ns/mnt'])
  if before is None or namespace is None:
   result.update({'state':'unknown','exit':'unavailable','errorClass':'other'}); return result
  try:
   ticks=int(before.stdout.decode('ascii','strict').rsplit(')',1)[1].split()[19]); namespace_text=namespace.stdout.decode('ascii','strict').strip()
   result['generation']='stable' if exit_code=='ok' and namespace_exit=='ok' and ticks==mount['zygote']['startTicks'] and namespace_text==mount['zygote']['namespace'] else 'reused'
  except (UnicodeError,ValueError,IndexError): result['generation']='unknown'
  if result['generation']!='stable': return result
  def cap(words):
   done,code,_=run(words)
   if done is None or code!='ok': return 'unknown'
   try:
    line=[x for x in done.stdout.decode('ascii','strict').splitlines() if x.startswith('CapEff:')]
    return 'present' if len(line)==1 and (int(line[0].split(':',1)[1].strip(),16)&0x200000) else 'absent' if len(line)==1 else 'unknown'
   except (UnicodeError,ValueError): return 'unknown'
  def bind_help(words):
   done,code,_=run(words)
   if done is None or code!='ok': return 'unavailable'
   try: return 'supported' if '--bind' in done.stdout.decode('utf-8','strict') else 'unsupported'
   except UnicodeError: return 'unavailable'
  result['outsideBind']=bind_help(['/system/bin/mount','--help'])
  result['insideBind']=bind_help(['nsenter','-t',pid,'-m','--','/system/bin/mount','--help'])
  relative_mount,mount_exit,mount_error=run(['nsenter','-t',pid,'-m','--','mount','--help'])
  result['relativeMount']='available' if mount_exit=='ok' else 'missing' if mount_error=='not-found' else 'unknown'
  def path_mount_membership(path):
   # adbd flattens argv.  The only compound shell is a fixed read-only script;
   # each exact plan path and pid are pinned before it is constructed.
   inner='exec 3<'+shlex.quote(path)+"; cat /proc/$$/fdinfo/3; printf '%s\\n' __VPN_CONTROL_MOUNTINFO__; /system/bin/cut -d ' ' -f1 /proc/$$/mountinfo"
   outer='nsenter -t '+shlex.quote(pid)+' -m -- /system/bin/sh -c '+shlex.quote(inner)
   try:
    done=subprocess.run([adb,'-s',serial,'shell','-T','sh','-c',shlex.quote(outer)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
   except (OSError,subprocess.TimeoutExpired): return ('unknown','command-unavailable',0,0,'unknown',0,0)
   size=min(len(done.stdout),4097)
   if done.returncode: return ('unknown','command-nonzero',size,0,'unknown',0,0)
   if len(done.stdout)>4096: return ('unknown','output-size',4097,0,'unknown',0,0)
   try:
    pieces=done.stdout.decode('utf-8','strict').split('__VPN_CONTROL_MOUNTINFO__\n')
   except UnicodeError: return ('unknown','encoding',size,0,'unknown',0,0)
   if len(pieces)!=2: return ('unknown','delimiter',size,0,'unknown',0,0)
   fdinfo,mountinfo=pieces
   keys=[line for line in fdinfo.splitlines() if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*:\s*.*',line)]
   raw_ids=re.findall(r'^mnt_id:\s*(.*)$',fdinfo,re.MULTILINE)
   key_count=min(len(keys),17); id_count=min(len(raw_ids),17)
   fd_format=('valid' if len(raw_ids)==1 and re.fullmatch(r'[1-9][0-9]{0,9}',raw_ids[0]) and int(raw_ids[0])<=2147483647 else
              'missing' if not raw_ids else 'duplicate' if len(raw_ids)>1 else 'invalid')
   if fd_format!='valid': return ('unknown','malformed-fdinfo',size,0,fd_format,key_count,id_count)
   lines=mountinfo.splitlines()
   if len(lines)>256: return ('unknown','capped-mount-ids',size,257,fd_format,key_count,id_count)
   if not lines or any(not re.fullmatch(r'[1-9][0-9]{0,9}',line) or int(line)>2147483647 for line in lines): return ('unknown','malformed-mount-ids',size,len(lines),fd_format,key_count,id_count)
   members=set(lines)
   return ('member' if raw_ids[0] in members else 'foreign','ok',size,len(lines),fd_format,key_count,id_count)
  membership,membership_reason,membership_bytes,membership_entries,fd_format,fd_keys,fd_ids=path_mount_membership(mount['target'])
  staging_membership,*_=path_mount_membership(mount['staging'])
  result.update({'targetMountMembership':membership,'targetMountMembershipReason':membership_reason,'targetMountMembershipBytes':membership_bytes,'targetMountMembershipEntries':membership_entries,'targetMountFdinfoFormat':fd_format,'targetMountFdinfoKeyCount':fd_keys,'targetMountFdinfoMntIdCount':fd_ids,'stagingMountMembership':staging_membership})
  result['outsideCapSysAdmin']=cap(['/system/bin/cat','/proc/self/status'])
  result['insideCapSysAdmin']=cap(['nsenter','-t',pid,'-m','--','/system/bin/cat','/proc/self/status'])
  enforce,enforce_code,_=run(['/system/bin/getenforce'])
  if enforce is not None and enforce_code=='ok':
   try: result['selinux']=enforce.stdout.decode('ascii','strict').strip().lower() if enforce.stdout.decode('ascii','strict').strip().lower() in {'enforcing','permissive','disabled'} else 'unknown'
   except UnicodeError: pass
  domain,domain_code,_=run(['/system/bin/cat','/proc/self/attr/current'])
  if domain is not None and domain_code=='ok':
   try:
    value=domain.stdout.decode('ascii','strict').strip(); result['domain']='su' if value.startswith('u:r:su:') else 'shell' if value.startswith('u:r:shell:') else 'other' if value.startswith('u:r:') else 'unknown'
   except UnicodeError: pass
  relative,relative_exit,relative_error=run(['nsenter','-t',pid,'-m','--','id','-u'])
  absolute,absolute_exit,absolute_error=run(['nsenter','-t',pid,'-m','--','/system/bin/id','-u'])
  result.update({'nsenterId':relative_exit,'absoluteId':absolute_exit,'nsenterBinary':'available' if relative_exit!='unavailable' or absolute_exit!='unavailable' else 'unknown'})
  if result['nsenterBinary']!='available':
   result.update({'state':'failed','exit':relative_exit,'errorClass':relative_error,'failurePhase':'nsenter-launch'})
  elif relative_exit!='ok' and absolute_exit=='ok':
   result.update({'state':'failed','exit':relative_exit,'errorClass':relative_error,'failurePhase':'exec-target-missing'})
  elif relative_exit!='ok' or absolute_exit!='ok':
   result.update({'state':'failed','exit':absolute_exit if absolute_exit!='ok' else relative_exit,'errorClass':absolute_error if absolute_exit!='ok' else relative_error,'failurePhase':'namespace-open'})
  else:
   # ADB flattens shell arguments.  Keep each namespace observation a single
   # absolute executable invocation: no compound shell source reaches adb.
   target_probe,target_exit,target_error=run(['nsenter','-t',pid,'-m','--','/system/bin/stat','-c','%F:%u:%a',mount['target']])
   staging_probe,staging_exit,staging_error=run(['nsenter','-t',pid,'-m','--','/system/bin/stat','-c','%u:%a:%d:%i',mount['staging']])
   try:
    absolute_uid=absolute.stdout.decode('ascii','strict').strip() if absolute is not None else ''
    result['namespaceUid']='root' if absolute_uid=='0' else 'shell' if absolute_uid=='2000' else 'other' if absolute_uid.isdecimal() else 'unknown'
   except UnicodeError: pass
   if target_exit!='ok': result.update({'state':'failed','exit':target_exit,'errorClass':target_error,'failurePhase':'target-stat'})
   elif staging_exit!='ok': result.update({'state':'failed','exit':staging_exit,'errorClass':staging_error,'failurePhase':'staging-stat'})
   else:
    result.update({'state':'observed','exit':'ok','errorClass':'none','failurePhase':'none'})
    try:
     target_text=target_probe.stdout.decode('utf-8','strict').strip(); staging_text=staging_probe.stdout.decode('utf-8','strict').strip()
     result['target']='exact-directory' if target_text=='directory:0:755' else 'other'
     result['staging']='exact' if staging_text==mount['stagingIdentity'] else 'changed'
    except (AttributeError,UnicodeError): pass
  after,after_exit,_=run(['cat','/proc/'+pid+'/stat'])
  after_namespace,after_namespace_exit,_=run(['readlink','/proc/'+pid+'/ns/mnt'])
  if after is None or after_namespace is None or after_exit!='ok' or after_namespace_exit!='ok': result['generation']='unknown'
  else:
   try:
    if (int(after.stdout.decode('ascii','strict').rsplit(')',1)[1].split()[19])!=mount['zygote']['startTicks'] or
        after_namespace.stdout.decode('ascii','strict').strip()!=mount['zygote']['namespace']): result['generation']='reused'
   except (UnicodeError,ValueError,IndexError): result['generation']='unknown'
  return result
 def failure_receipt():
  try:
   path=job/'mount-failure.json'; fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
   try:
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=1024: return None
    raw=os.read(fd,1025); after=os.fstat(fd)
   finally: os.close(fd)
   if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): return None
   value=json.loads(raw)
   return value if isinstance(value,dict) and (set(value)=={'phase','exit','errorClass'} or set(value)=={'phase','exit','errorClass','errorOrigin'}) else None
  except (OSError,ValueError,UnicodeError): return None
 failure=failure_receipt()
 return {'uid':current_uid,'stage':stage_state,'mountPlan':mount_state,'zygoteGeneration':zygote_state,'stagingIdentity':staging_state,'mount':mounted,'ca':ca,'commandPhase':phase,'mountDiagnostic':mount_diagnostic(),'mountFailure':failure}
def host_fixture_leaf():
 path=root/('android-native-fixture-'+expected['campaignId'])/'certificate.pem'
 raw=private(path,65536)
 if hashlib.sha256(raw).hexdigest()!=expected['leafSha256']: unknown('host_fixture_leaf_changed')
 return raw
def zygote_identity(pid):
 if not isinstance(pid,str) or not pid.isdecimal() or int(pid)<1: unknown('zygote_identity_invalid')
 raw=shell('cat','/proc/'+pid+'/stat')
 try: ticks=int(raw.rsplit(')',1)[1].split()[19])
 except (IndexError,ValueError): unknown('zygote_generation_invalid')
 namespace=shell('readlink','/proc/'+pid+'/ns/mnt')
 if ticks<1 or not re.fullmatch(r'mnt:\[[0-9]+\]',namespace): unknown('zygote_namespace_invalid')
 return {'pid':pid,'startTicks':ticks,'namespace':namespace}
def staging_identity(path):
 raw=shell('stat','-c','%u:%a:%d:%i',path)
 if not re.fullmatch(r'0:755:[0-9]+:[0-9]+',raw): unknown('staging_identity_invalid')
 return raw
def mount_layout(plan,raw):
 # mountinfo roots are relative to each filesystem, not absolute device paths.
 entries=[];ids=set();filesystems={}
 for line in raw.splitlines():
  halves=line.split(' - ',1);fields=halves[0].split()
  if len(halves)!=2 or len(fields)<6 or len(halves[1].split())<3 or not all(re.fullmatch(r'[0-9]+',item) for item in fields[:2]) or not re.fullmatch(r'[0-9]+:[0-9]+',fields[2]) or fields[0] in ids: unknown('mount_layout_invalid')
  ids.add(fields[0]);entries.append(fields);filesystems[fields[0]]=halves[1].split()[0]
 stage=plan['staging'];parts=plan['stagingIdentity'].split(':')
 if len(parts)!=4 or not parts[2].isdecimal(): unknown('staging_replaced')
 number=int(parts[2]);major=((number>>8)&0xfff)|((number>>32)&0xfffff000);minor=(number&0xff)|((number>>12)&0xffffff00)
 device=str(major)+':'+str(minor)
 def ancestor(parent,child): return parent=='/' or child==parent or child.startswith(parent+'/')
 sources=[entry for entry in entries if ancestor(entry[4],stage)]
 if not sources: unknown('mount_source_unverified')
 longest=max(len(entry[4]) for entry in sources);sources=[entry for entry in sources if len(entry[4])==longest]
 if len(sources)!=1 or sources[0][2]!=device: unknown('mount_source_unverified')
 source=sources[0];root=source[3]
 if not root.startswith('/') or '\\' in root or str(pathlib.PurePosixPath(root))!=root or any(item in {'.','..'} for item in root.split('/')) or root.endswith('//deleted'): unknown('mount_source_unverified')
 relative=stage[len(source[4]):] if source[4]!='/' else stage
 expected_root=root.rstrip('/')+'/'+relative.lstrip('/') if relative else root
 targets=[entry for entry in entries if entry[4]==plan['target']]
 owned=[entry for entry in targets if entry[2]==device and entry[3]==expected_root and filesystems[entry[0]]==filesystems[source[0]]]
 references=[entry for entry in entries if (entry[2]==device and (entry[3]==expected_root or entry[3].startswith(expected_root+'/'))) or entry[4]==stage or entry[4].startswith(stage+'/')]
 return {'targets':targets,'owned':owned,'references':references,'root':expected_root,'device':device}
def mount_observation_reader(plan):
 # Public commands and ordinary inode/generation reads stay shell UID2000.
 # Only these two namespace observations need the fixed AOSP su principal.
 pid=plan['zygote']['pid']
 if not isinstance(pid,str) or not pid.isdecimal() or int(pid)<1: unknown('zygote_identity_invalid')
 allowed={('readlink','/proc/'+plan['zygote']['pid']+'/ns/mnt'),('cat','/proc/'+plan['zygote']['pid']+'/mountinfo')}
 uid=shell('id','-u')
 if uid not in {'0','2000'}: unknown('mount_observation_principal_unverified')
 def probe(words,limit=4096):
  try:
   result=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
   help_probe=words==['/system/xbin/su','--help']
   if result.returncode or len(result.stdout)>limit or len(result.stderr)>4096 or result.stderr and (not help_probe or result.stdout): unknown('mount_observation_principal_unverified')
   return (result.stdout or result.stderr if help_probe else result.stdout).decode('utf-8','strict').strip()
  except (OSError,subprocess.TimeoutExpired,UnicodeError): unknown('mount_observation_principal_unverified')
 def binary():
  info=shell('stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su'); digest=shell('sha256sum','/system/xbin/su')
  if not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',info) or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',digest): unknown('mount_observation_principal_unverified')
  return info,digest
 pin=None
 if uid=='2000':
  pin=binary()
  if probe(['/system/xbin/su','--help'])!=AOSP_HELP or binary()!=pin: unknown('mount_observation_principal_unverified')
  if probe(['/system/xbin/su','0,0','/system/bin/id','-u'])!='0' or binary()!=pin: unknown('mount_observation_principal_unverified')
 def read(*words):
  if words not in allowed or shell('id','-u')!=uid: unknown('mount_observation_principal_unverified')
  if uid=='0': return shell(*words)
  if binary()!=pin: unknown('mount_observation_principal_unverified')
  value=probe(['/system/xbin/su','0,0','/system/bin/'+words[0],*words[1:]],1048576)
  if binary()!=pin or shell('id','-u')!='2000': unknown('mount_observation_principal_unverified')
  return value
 return read
def mount_observation_generation(plan,read):
 pid=plan['zygote']['pid']
 if not isinstance(pid,str) or not pid.isdecimal() or int(pid)<1: unknown('zygote_identity_invalid')
 raw=shell('cat','/proc/'+pid+'/stat')
 try: ticks=int(raw.rsplit(')',1)[1].split()[19])
 except (IndexError,ValueError): unknown('zygote_generation_invalid')
 namespace=read('readlink','/proc/'+pid+'/ns/mnt')
 if ticks<1 or not re.fullmatch(r'mnt:\[[0-9]+\]',namespace): unknown('zygote_namespace_invalid')
 return {'pid':pid,'startTicks':ticks,'namespace':namespace}
def mount_observed(plan):
 read=mount_observation_reader(plan)
 if mount_observation_generation(plan,read)!=plan['zygote']: unknown('zygote_reused')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('staging_replaced')
 layout=mount_layout(plan,read('cat','/proc/'+plan['zygote']['pid']+'/mountinfo'))
 if len(layout['targets'])!=1 or len(layout['owned'])!=1: unknown('fixture_mount_missing_or_changed')
 if mount_observation_generation(plan,read)!=plan['zygote']: unknown('zygote_reused')
 return True
def mount_target_preflight(plan):
 # An open/stat-able target can still be the disconnected root of an old bind mount.
 # Reject that retained mount without attempting to replace or unmount it.
 text=shell('/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--','/system/bin/stat','-c','%d:%i:%h:%F',plan['target'])
 fields=text.split(':')
 if len(fields)!=4 or fields[3]!='directory' or not all(re.fullmatch(r'[0-9]{1,20}',item) for item in fields[:3]) or int(fields[2])==0: unknown('mount_target_unlinked_or_unverified')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_before_mount')
def mount_exact(plan):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_before_mount')
 mount_target_preflight(plan)
 argv=[adb,'-s',serial,'shell','-T','nsenter','-t',plan['zygote']['pid'],'-m','--','mount','--bind',plan['staging'],plan['target']]
 def origin(err):
  if err.startswith('nsenter:'): return 'nsenter-launch'
  if plan['staging'] in err or plan['target'] in err: return 'mount-path-pair'
  if 'fstab' in err.lower(): return 'fstab'
  if '/proc/filesystems' in err: return 'proc-filesystems'
  return 'other' if err else 'unknown'
 try: done=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 except (OSError,subprocess.TimeoutExpired):
  receipt={'phase':'mount','exit':'unavailable','errorClass':'other','errorOrigin':'unknown'}; record(job/'mount-failure.json',receipt); emit('unknown','mount_command_failed',phase='mount',mountFailure=receipt)
 if done.returncode:
  def stream(raw):
   return {'base64':base64.b64encode(raw[:4096]).decode('ascii'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'truncated':len(raw)>4096}
  record(job/'mount-command-evidence.json',{'schema':1,'argv':argv,'returncode':done.returncode,'stdout':stream(done.stdout),'stderr':stream(done.stderr)})
  try: err=done.stderr[:4096].decode('utf-8','strict')
  except UnicodeError: err=''
  kind='not-found' if ('No such file' in err or 'not found' in err) else 'permission' if ('Permission denied' in err or 'Operation not permitted' in err) else 'no-process' if 'No such process' in err else 'invalid' if 'Invalid argument' in err else 'other'
  receipt={'phase':'mount','exit':'nonzero','errorClass':kind,'errorOrigin':origin(err)}; record(job/'mount-failure.json',receipt); emit('unknown','mount_command_failed',phase='mount',mountFailure=receipt)
 if len(done.stdout)>4096 or len(done.stderr)>4096: unknown('mount_command_uncertain')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_after_mount')
def unmount_exact(plan):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_before_umount')
 shell('nsenter','-t',plan['zygote']['pid'],'-m','--','umount',plan['target'])
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused_after_umount')
def lease_lock():
 fd=os.open(lock,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: unknown('device_lock_unsafe')
 fcntl.flock(fd,fcntl.LOCK_EX)
 return fd
def release_lock(fd): fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
def validate_mount(plan):
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 zygote=plan.get('zygote') if isinstance(plan,dict) else None
 if (not isinstance(plan,dict) or plan.get('target')!=target or plan.get('staging')!=staging or
     not re.fullmatch(r'0:755:[0-9]+:[0-9]+',str(plan.get('stagingIdentity',''))) or
     not isinstance(zygote,dict) or not isinstance(zygote.get('pid'),str) or not zygote['pid'].isdecimal() or
     type(zygote.get('startTicks')) is not int or zygote['startTicks']<1 or
     not isinstance(zygote.get('namespace'),str) or not re.fullmatch(r'mnt:\[[0-9]+\]',zygote['namespace'])): unknown('mount_intent_invalid')
 return plan
def exact_lease_present():
 try: item=lease.lstat()
 except FileNotFoundError: return None
 if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o600: unknown('lease_unsafe')
 if json.loads(private(lease,1024))!={'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']}: unknown('lease_changed')
 after=lease.lstat()
 if (item.st_dev,item.st_ino,item.st_size)!=(after.st_dev,after.st_ino,after.st_size): unknown('lease_replaced')
 return item
def release_exact_lease():
 guard_fd=lease_lock()
 try:
  item=exact_lease_present()
  if item is not None:
   after=lease.lstat()
   if (item.st_dev,item.st_ino,item.st_size)!=(after.st_dev,after.st_ino,after.st_size): unknown('lease_replaced')
   lease.unlink()
 finally: release_lock(guard_fd)
def finish_cleaned():
 guard()
 if routes(): unknown('reverse_after_cleanup')
 record(job/'cleaned.json',{'correlationId':correlation,'caSha256':expected['caSha256']})
 release_exact_lease()
 emit('cleaned',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[])
def cleaned_terminal():
 if json.loads(private(job/'cleaned.json',8192))!={'correlationId':correlation,'caSha256':expected['caSha256']}: unknown('cleaned_changed')
 guard()
 if routes(): unknown('reverse_after_cleanup')
 if exact_lease_present() is not None:
  if action!='cleanup': emit('partial','remote_lease_release_pending',phase='terminal')
  release_exact_lease()
 emit('cleaned',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[])
def cleanup_before_mount():
 stage=json.loads(private(job/'stage.json',8192))
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 if stage!={'phase':'before_root','target':target,'staging':staging}: unknown('stage_intent_changed')
 if routes(): unknown('foreign_reverse_before_premount_cleanup')
 uid=shell('id','-u')
 if uid=='0': guard('0')
 elif uid=='2000': guard()
 else: unknown('device_uid_changed')
 owned_path=job/'stage-owned.json'
 if owned_path.exists():
  owned=json.loads(private(owned_path,8192))
  if (owned.get('staging')!=staging or not re.fullmatch(r'0:755:[0-9]+:[0-9]+',str(owned.get('stagingIdentity',''))) or
      not isinstance(owned.get('zygote'),dict)): unknown('stage_ownership_changed')
  if uid=='2000':
   guard()
   if routes(): unknown('foreign_reverse_before_root')
   adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
  if zygote_identity(owned['zygote'].get('pid'))!=owned['zygote']: unknown('zygote_reused')
  if staging_identity(staging)!=owned['stagingIdentity']: unknown('staging_replaced')
  guard('0')
  if routes(): unknown('foreign_reverse_before_premount_remove')
  if zygote_identity(owned['zygote'].get('pid'))!=owned['zygote']: unknown('zygote_reused')
  if staging_identity(staging)!=owned['stagingIdentity']: unknown('staging_replaced')
  shell('rm','-r',staging)
  guard('0')
  if routes(): unknown('foreign_reverse_before_premount_unroot')
  adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 else:
  # No staged inode was durably recorded. Never delete an unowned path.
  observed=shell('sh','-c','if [ -e '+staging+' ] || [ -L '+staging+' ]; then echo present; else echo absent; fi')
  if uid=='0':
   guard('0')
   if routes(): unknown('foreign_reverse_before_premount_unroot')
   adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
  if observed!='absent': unknown('unowned_stage_possible')
 finish_cleaned()
def canonical_rules(document):
 if not isinstance(document,dict) or document.get('type')!='vpn_control_routing_rules' or document.get('version')!=7: unknown('readmission_rules_invalid')
 rules=document.get('rules')
 if (not isinstance(rules,dict) or set(rules)!={'ignore_rules','block_quic_udp_443','proxy_packages','direct_domain_suffixes'} or
     type(rules['ignore_rules']) is not bool or type(rules['block_quic_udp_443']) is not bool or
     not isinstance(rules['proxy_packages'],list) or not isinstance(rules['direct_domain_suffixes'],list) or
     any(not isinstance(x,str) for x in rules['proxy_packages']+rules['direct_domain_suffixes'])): unknown('readmission_rules_invalid')
 return hashlib.sha256(json.dumps(rules,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def namespace_member(plan,path):
 inner='exec 3<'+shlex.quote(path)+"; cat /proc/$$/fdinfo/3; printf '%s\\n' __VPN_CONTROL_MOUNTINFO__; /system/bin/cut -d ' ' -f1 /proc/$$/mountinfo"
 outer='nsenter -t '+shlex.quote(plan['zygote']['pid'])+' -m -- /system/bin/sh -c '+shlex.quote(inner)
 pieces=adb_call('shell','-T','sh','-c',shlex.quote(outer),max_bytes=4096).split('__VPN_CONTROL_MOUNTINFO__\n')
 if len(pieces)!=2: unknown('readmission_membership_invalid')
 ids=re.findall(r'^mnt_id:\s*(.*)$',pieces[0],re.MULTILINE); members=pieces[1].splitlines()
 if (len(ids)!=1 or not members or len(members)>256 or
     any(not re.fullmatch(r'[1-9][0-9]{0,9}',x) or int(x)>2147483647 for x in [*ids,*members]) or ids[0] not in members): unknown('readmission_namespace_foreign')
def readmission_unowned_target_proof(plan,retired=False):
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
 namespace_member(plan,plan['target'])
 if not retired: namespace_member(plan,plan['staging'])
 raw=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo'); targets=0; identifiers=set()
 lines=raw.splitlines()
 if not lines or len(lines)>1024: unknown('readmission_mountinfo_invalid')
 for line in lines:
  pieces=line.split(' - '); fields=pieces[0].split(); tail=pieces[1].split() if len(pieces)==2 else []
  if len(pieces)!=2 or len(fields)<6 or len(tail)<3 or not re.fullmatch(r'[1-9][0-9]*',fields[0]) or not fields[1].isdecimal() or fields[0] in identifiers: unknown('readmission_mountinfo_invalid')
  identifiers.add(fields[0])
  if any(path==plan['staging'] or path.startswith(plan['staging']+'/') for path in (fields[3],fields[4])): unknown('readmission_mount_present_or_foreign')
  if fields[4]==plan['target']:
   targets+=1
   if tail[0]!='ext4': unknown('readmission_mount_present_or_foreign')
 if targets!=1: unknown('readmission_mountinfo_invalid')
 target_ca=plan['target']+'/'+expected['caStoreName']
 step('target-ca')
 try: present=subprocess.run([adb,'-s',serial,'shell','-T','nsenter','-t',plan['zygote']['pid'],'-m','--','/system/bin/stat','-c','%F',target_ca],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 except (OSError,subprocess.TimeoutExpired): unknown('readmission_target_ca_unverified')
 if len(present.stdout)>4096 or len(present.stderr)>4096: unknown('readmission_target_ca_unverified')
 if present.returncode==0: unknown('readmission_target_ca_present')
 try: error=present.stderr.decode('utf-8','strict').strip()
 except UnicodeError: unknown('readmission_target_ca_unverified')
 missing={"stat: '"+target_ca+"': No such file or directory",'stat: '+target_ca+': No such file or directory'}
 if present.returncode!=1 or present.stdout or error not in missing: unknown('readmission_target_ca_unverified')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
 return hashlib.sha256(raw.encode()).hexdigest()
def readmission_snapshot():
 global observed_readmission_owner
 uid=shell('id','-u')
 if api!='29' or uid not in {'0','2000'}: unknown('readmission_requires_api29_shell_or_root')
 identity(uid); installed()
 if routes(): unknown('readmission_reverse_present')
 if (job/'ready.json').exists() or (job/'cleaned.json').exists() or (job/'cleanup-intent.json').exists(): unknown('readmission_phase_invalid')
 children=list(root.glob('android-runtime-acceptance-*.json'))
 if len(children)>256: unknown('readmission_child_inventory_unknown')
 for child in children:
  activity=json.loads(private(child,8192))
  if not isinstance(activity,dict): unknown('readmission_child_inventory_unknown')
  if activity.get('parentCorrelationId')==correlation: unknown('readmission_child_present')
 failure=json.loads(private(job/'mount-failure.json',1024))
 if (not isinstance(failure,dict) or set(failure) not in ({'phase','exit','errorClass'},{'phase','exit','errorClass','errorOrigin'}) or failure.get('phase')!='mount' or failure.get('exit')!='nonzero' or failure.get('errorClass')!='not-found' or ('errorOrigin' in failure and failure['errorOrigin'] not in {'nsenter-launch','mount-path-pair','fstab','proc-filesystems','other','unknown'})): unknown('readmission_failed_mount_unverified')
 plan=validate_mount(json.loads(private(job/'mount-intent.json',8192)))
 owned=json.loads(private(job/'stage-owned.json',8192))
 if owned!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
 if uid=='0' and zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_stage_changed')
 ca_path=plan['staging']+'/'+expected['caStoreName']; ca_hash=shell('sha256sum',ca_path).split()
 if len(ca_hash)!=2 or ca_hash!=[expected['caSha256'],ca_path]: unknown('readmission_ca_changed')
 mount_proof=readmission_unowned_target_proof(plan) if uid=='0' else None
 backup=pathlib.Path(expected['backupPath']); raw=private(backup)
 if hashlib.sha256(raw).hexdigest()!=expected['backupSha256']: unknown('backup_changed')
 baseline=canonical_rules(json.loads(raw))
 def read(*words):
  routing=words==('routing','show')
  value=json.loads(command(public_argv(words,routing),timeout=ROUTING_PROCESS_SECONDS if routing else 30,max_bytes=67108864,env=environment))
  if (not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or
      not isinstance(value.get('controllerId'),str) or not value['controllerId'] or type(value.get('configurationRevision')) is not int or value['configurationRevision']<0): unknown('readmission_public_invalid')
  return value
 status=read('status'); owner=status['controllerId']; revision=status['configurationRevision']; data=status.get('data')
 if observed_readmission_owner is not None and owner!=observed_readmission_owner: unknown('readmission_owner_changed')
 observed_readmission_owner=owner
 if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped' or data.get('activeLocationId') is not None or data.get('selectedLocationId') is not None: unknown('runtime_not_off')
 operations=read('operations','list'); routing=read('routing','show'); closing=read('status')
 for value in (operations,routing,closing):
  if value.get('controllerId')!=owner or value.get('configurationRevision')!=revision: unknown('readmission_owner_changed')
 ops=operations.get('data',{}).get('operations')
 if not isinstance(ops,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in ops): unknown('history_unknown')
 if closing.get('data')!=data: unknown('readmission_status_changed')
 if canonical_rules(routing.get('data',{}).get('routing'))!=baseline: unknown('readmission_rules_changed')
 if (uid=='0' and zygote_identity(plan['zygote']['pid'])!=plan['zygote']) or staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_native_changed')
 identity(uid); installed()
 if routes(): unknown('readmission_reverse_present')
 extra={'unownedTargetMountsSha256':mount_proof} if mount_proof is not None else {}
 return {**extra,'owner':owner,'revision':revision,'mount':plan,'rulesSha256':baseline,'uid':uid,'api':29,'avd':avd,'abi':'x86_64','reversePorts':[],
         'mountFailure':failure,'mountObservation':('owned-stage-unreferenced' if mount_proof is not None else 'absent') if uid=='0' else 'unobserved','namespaceObservation':'verified' if uid=='0' else 'unobserved'}
def readmission_receipt_path():
 if (not isinstance(readmission,dict) or set(readmission) not in ({'correlationId','originalIntentSha256'},{'correlationId','originalIntentSha256','receipt'}) or
     not isinstance(readmission.get('correlationId'),str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',readmission['correlationId']) or
     not isinstance(readmission.get('originalIntentSha256'),str) or not re.fullmatch(r'[0-9a-f]{64}',readmission['originalIntentSha256'])): unknown('readmission_binding_invalid')
 return job/('cleanup-readmission-'+readmission['correlationId']+'.json')
def readmit_cleanup():
 path=readmission_receipt_path()
 first=readmission_snapshot(); second=readmission_snapshot()
 if first!=second: unknown('readmission_observation_changed')
 if private(job/'intent.json',8192)!=remote_intent_raw: unknown('intent_changed')
 receipt={'schema':1,'kind':'android-endpoint-cleanup-readmission','endpointCorrelationId':correlation,
          'readmissionCorrelationId':readmission['correlationId'],'originalIntentSha256':readmission['originalIntentSha256'],
          'remoteIntentSha256':hashlib.sha256(private(job/'intent.json',8192)).hexdigest(),
          'originalOwner':stored_expected['owner'],'originalRevision':stored_expected['revision'],'snapshot':second}
 # Exclusive immutable publication. Existing correlations are never overwritten.
 record(path,receipt)
 emit('ready',readmission=receipt)
def readmission_status():
 path=readmission_receipt_path()
 if exact_lease_present() is None: unknown('lease_changed')
 first=readmission_snapshot(); second=readmission_snapshot()
 if first!=second: unknown('readmission_observation_changed')
 if private(job/'intent.json',8192)!=remote_intent_raw: unknown('intent_changed')
 if path.exists() or path.is_symlink():
  receipt=json.loads(private(path,8192))
  exact={'schema':1,'kind':'android-endpoint-cleanup-readmission','endpointCorrelationId':correlation,
         'readmissionCorrelationId':readmission['correlationId'],'originalIntentSha256':readmission['originalIntentSha256'],
         'remoteIntentSha256':hashlib.sha256(remote_intent_raw).hexdigest(),
         'originalOwner':stored_expected['owner'],'originalRevision':stored_expected['revision'],'snapshot':second}
  if receipt!=exact: unknown('readmission_receipt_stale')
  emit('partial','readmission_receipt_present')
 emit('partial','readmission_receipt_absent')
def validate_cleanup_readmission():
 path=readmission_receipt_path(); receipt=json.loads(private(path,8192))
 if receipt!=readmission.get('receipt'): unknown('readmission_receipt_changed')
 first=readmission_snapshot(); second=readmission_snapshot()
 if private(job/'intent.json',8192)!=remote_intent_raw: unknown('intent_changed')
 exact={'schema':1,'kind':'android-endpoint-cleanup-readmission','endpointCorrelationId':correlation,
        'readmissionCorrelationId':readmission['correlationId'],'originalIntentSha256':readmission['originalIntentSha256'],
        'remoteIntentSha256':hashlib.sha256(private(job/'intent.json',8192)).hexdigest(),
        'originalOwner':stored_expected['owner'],'originalRevision':stored_expected['revision'],'snapshot':second}
 if receipt!=exact or first!=second or second['owner']!=expected['owner'] or second['revision']!=expected['revision']: unknown('readmission_receipt_stale')
def readmission_records_guard(unreceipted=False):
 if recovery is not None:
  recovery_records();return
 if private(job/'intent.json',8192)!=remote_intent_raw: unknown('intent_changed')
 if not unreceipted and json.loads(private(readmission_receipt_path(),8192))!=readmission['receipt']: unknown('readmission_receipt_changed')
 if action=='cleanup-readmitted-status':
  if os.path.lexists(lease): unknown('readmission_terminal_lease_present')
 else:
  if exact_lease_present() is None: unknown('lease_changed')
 children=list(root.glob('android-runtime-acceptance-*.json'))
 if len(children)>256: unknown('readmission_child_inventory_unknown')
 for child in children:
  activity=json.loads(private(child,8192))
  if not isinstance(activity,dict): unknown('readmission_child_inventory_unknown')
  if activity.get('parentCorrelationId')==correlation: unknown('readmission_child_present')
def readmission_public_proof(uid):
 identity(uid); installed()
 if routes(): unknown('readmission_reverse_present')
 raw=private(pathlib.Path(expected['backupPath']))
 if hashlib.sha256(raw).hexdigest()!=expected['backupSha256']: unknown('backup_changed')
 baseline=canonical_rules(json.loads(raw))
 if baseline!=readmission['receipt']['snapshot']['rulesSha256']: unknown('readmission_rules_changed')
 status=public('status'); data=status.get('data')
 if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped' or data.get('selectedLocationId') is not None or data.get('activeLocationId') is not None: unknown('runtime_not_off')
 operations=public('operations','list').get('data',{}).get('operations')
 if not isinstance(operations,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in operations): unknown('history_unknown')
 routing=json.loads(command(public_argv(('routing','show'),True),timeout=ROUTING_PROCESS_SECONDS,max_bytes=67108864,env=environment))
 if (not isinstance(routing,dict) or routing.get('ok') is not True or routing.get('final') is not True or routing.get('code')!='OK' or routing.get('controllerId')!=expected['owner'] or routing.get('configurationRevision')!=expected['revision']): unknown('owner_changed')
 if canonical_rules(routing.get('data',{}).get('routing'))!=baseline: unknown('readmission_rules_changed')
 if public('status').get('data')!=data: unknown('readmission_status_changed')
 identity(uid); installed()
 if routes(): unknown('readmission_reverse_present')
 readmission_records_guard()
def readmission_retired_proof(plan,uid):
 readmission_records_guard(); readmission_public_proof(uid)
 absent='if [ -e '+shlex.quote(plan['staging'])+' ] || [ -L '+shlex.quote(plan['staging'])+' ]; then echo present; else echo absent; fi'
 if shell('sh','-c',shlex.quote(absent))!='absent': unknown('readmission_stage_retirement_uncertain')
 if uid=='0':
  proof=readmission_unowned_target_proof(plan,retired=True)
  if proof!=(readmission['receipt']['snapshot'].get('unownedTargetMountsSha256') or readmission_mount_pin): unknown('readmission_native_changed')
 readmission_records_guard(); readmission_public_proof(uid)
def readmission_principal_preflight(plan):
 def gate():
  if action=='mount-failure-diagnostic':
   mount_diagnostic_gate(plan); return
  readmission_records_guard(unreceipted=not isinstance(readmission.get('receipt'),dict)); readmission_receipt_path(); identity('0'); installed()
  if json.loads(private(job/'mount-intent.json',8192))!=plan or json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
  failure=json.loads(private(job/'mount-failure.json',1024))
  if not isinstance(failure,dict) or failure.get('phase')!='mount' or failure.get('exit')!='nonzero' or failure.get('errorClass')!='not-found': unknown('readmission_failed_mount_unverified')
  if routes(): unknown('readmission_reverse_present')
  if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
  if readmission_stage_retired:
   absent='if [ -e '+shlex.quote(plan['staging'])+' ] || [ -L '+shlex.quote(plan['staging'])+' ]; then echo present; else echo absent; fi'
   if shell('sh','-c',shlex.quote(absent))!='absent': unknown('readmission_stage_retirement_uncertain')
  else:
   if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_stage_changed')
   ca_path=plan['staging']+'/'+expected['caStoreName']
   if shell('sha256sum',ca_path).split()!=[expected['caSha256'],ca_path]: unknown('readmission_ca_changed')
 fixed_principal_preflight(gate)
def fixed_principal_preflight(gate):
 global principal_preflight,principal_identity
 principal_preflight={'grammar':'unavailable','helperIdentity':'unverified','shellUid':'unverified','providerAccess':'unverified'}
 def probe(*words):
  try:
   result=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
   if len(result.stdout)>4096 or len(result.stderr)>4096: return None
   return result.returncode,result.stdout.decode('utf-8','strict').strip(),result.stderr.decode('utf-8','strict').strip()
  except (OSError,subprocess.TimeoutExpired,UnicodeError): return None
 def binary():
  info=probe('stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su')
  if info is None or info[0]!=0 or info[2] or not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',info[1]): return None
  digest=probe('sha256sum','/system/xbin/su')
  if digest is None or digest[0]!=0 or digest[2] or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',digest[1]): return None
  return info[1],digest[1]
 gate(); opening=binary()
 if opening is None: return
 if principal_identity is not None and opening!=principal_identity: return
 principal_identity=opening
 principal_preflight['helperIdentity']='verified'
 help_result=probe('/system/xbin/su','--help')
 if help_result is None: return
 principal_preflight['grammar']='unsupported'
 help_text=help_result[1] or help_result[2]
 if help_result[0]!=0 or (help_result[1] and help_result[2]) or help_text!="usage: su [WHO [COMMAND...]]\n\nSwitch to WHO (default 'root') and run the given COMMAND (default sh).\n\nWHO is a comma-separated list of user, group, and supplementary groups\nin that order.": return
 if binary()!=opening: principal_preflight['helperIdentity']='unverified'; return
 principal_preflight['grammar']='aosp-who-command'
 gate()
 if binary()!=opening: principal_preflight['helperIdentity']='unverified'; principal_preflight['grammar']='unsupported'; return
 uid=probe('/system/xbin/su','2000,2000','/system/bin/id','-u')
 if uid is None or uid!=(0,'2000',''): return
 principal_preflight['shellUid']='verified'
 gate()
 if binary()!=opening:
  principal_preflight={'grammar':'unsupported','helperIdentity':'unverified','shellUid':'unverified','providerAccess':'unverified'}; return
 # Provider authorizes UID/DUMP before rejecting this unsupported method.
 # The sentinel is not a domain action or transfer and creates no operation.
 access=probe('/system/xbin/su','2000,2000','/system/bin/content','call','--uri','content://com.kardinal.vpncontrol.control','--method','endpoint-read-only-principal-preflight')
 if access is not None:
  text=access[1]+'\n'+access[2]
  if 'PERMISSION_DENIED' in text or 'SecurityException' in text: principal_preflight['providerAccess']='denied'
  elif access[0] in (0,1) and not access[1] and re.search(r'^(?:java\.lang\.)?IllegalArgumentException: UNSUPPORTED\r?$',access[2],re.MULTILINE): principal_preflight['providerAccess']='verified'
 gate()
 if binary()!=opening:
  principal_preflight={'grammar':'unsupported','helperIdentity':'unverified','shellUid':'unverified','providerAccess':'unverified'}
def rooted_public_read(argv,timeout,env):
 words=public_words(argv)
 operations={('status',):'status',('operations','list'):'operations.list',('routing','show'):'routing.show'}
 if tuple(words) not in operations or action=='mount-failure-diagnostic' and words not in (['status'],['operations','list']): unknown('readmission_public_invalid')
 receipt=readmission.get('receipt') if isinstance(readmission,dict) else None
 owner=argv[8] if argv[7:8]==['--controller-id'] else None
 remaining_mode=remaining is not None
 ordinary=action=='cleanup' and readmission is None
 pinned=observed_readmission_owner if remaining_mode else expected['owner'] if isinstance(receipt,dict) or action=='mount-failure-diagnostic' or ordinary else observed_readmission_owner
 if owner!=pinned or owner is None and words!=['status']: unknown('readmission_public_invalid')
 if api!='29': unknown('readmission_binding_invalid')
 plan=validate_mount(receipt.get('snapshot',{}).get('mount') if isinstance(receipt,dict) else json.loads(private(job/'mount-intent.json',8192)))
 if remaining_mode: fixed_principal_preflight(lambda: remaining_records_guard(native=True))
 elif ordinary:
  def gate():
   identity('0'); installed()
   if json.loads(private(job/'intent.json',8192))!=stored_expected or exact_lease_present() is None: unknown('intent_changed')
   if json.loads(private(job/'mount-intent.json',8192))!=plan or json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
   if routes(): unknown('readmission_reverse_present')
   if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
  fixed_principal_preflight(gate)
 else: readmission_principal_preflight(plan)
 if principal_preflight!={'grammar':'aosp-who-command','helperIdentity':'verified','shellUid':'verified','providerAccess':'verified'}: unknown('readmission_principal_unverified')
 configuration={'adb':adb,'serial':serial,'owner':owner,'revision':remaining.get('receipt',{}).get('snapshot',{}).get('public',{}).get('revision') if remaining_mode else expected['revision'] if isinstance(receipt,dict) or action=='mount-failure-diagnostic' or ordinary else None,'operation':operations[tuple(words)],'suIdentity':principal_identity}
 source=('#!'+sys.executable+'\nCONFIG='+repr(json.dumps(configuration,sort_keys=True))+'\n'+ENDPOINT_ADAPTER).encode()
 digest=hashlib.sha256(source).hexdigest()
 with tempfile.TemporaryDirectory(prefix='endpoint-read-',dir=job) as temporary:
  directory=pathlib.Path(temporary); os.chmod(directory,0o700); path=directory/'adb'
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o700)
  with os.fdopen(fd,'wb') as output: output.write(source)
  info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700 or info.st_nlink!=1 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: unknown('readmission_principal_unverified')
  child_env=dict(os.environ if env is None else env); child_env['PATH']=str(directory)+os.pathsep+child_env.get('PATH',os.defpath)
  step(command_phase(argv))
  return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False,env=child_env)
def readmission_mount_diagnostic():
 receipt=readmission.get('receipt')
 if not isinstance(receipt,dict) or set(receipt)!={'schema','kind','endpointCorrelationId','readmissionCorrelationId','originalIntentSha256','remoteIntentSha256','originalOwner','originalRevision','snapshot'}: unknown('readmission_receipt_changed')
 snapshot=receipt.get('snapshot')
 if (receipt.get('schema')!=1 or receipt.get('kind')!='android-endpoint-cleanup-readmission' or receipt.get('endpointCorrelationId')!=correlation or
     receipt.get('readmissionCorrelationId')!=readmission['correlationId'] or receipt.get('originalIntentSha256')!=readmission['originalIntentSha256'] or
     receipt.get('remoteIntentSha256')!=hashlib.sha256(remote_intent_raw).hexdigest() or receipt.get('originalOwner')!=stored_expected['owner'] or receipt.get('originalRevision')!=stored_expected['revision'] or
     not isinstance(snapshot,dict) or api!='29'): unknown('readmission_receipt_changed')
 plan=validate_mount(snapshot.get('mount'))
 if set(plan)!={'zygote','target','staging','stagingIdentity'}: unknown('mount_intent_invalid')
 if plan!=json.loads(private(job/'mount-intent.json',8192)): unknown('mount_intent_invalid')
 if json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
 expected['owner']=snapshot.get('owner'); expected['revision']=snapshot.get('revision')
 readmission_principal_preflight(plan)
 def observe():
  readmission_records_guard(); readmission_public_proof('0')
  if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
  if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_stage_changed')
  ca_path=plan['staging']+'/'+expected['caStoreName']; ca=shell('sha256sum',ca_path).split()
  if ca!=[expected['caSha256'],ca_path]: unknown('readmission_ca_changed')
  namespace_member(plan,plan['target']); namespace_member(plan,plan['staging'])
  raw=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo'); entries=[]
  for line in raw.splitlines():
   halves=line.split(' - '); fields=halves[0].split(); tail=halves[1].split() if len(halves)==2 else []
   if len(halves)!=2 or len(fields)<6 or len(tail)<3 or not fields[0].isdecimal() or not fields[1].isdecimal(): unknown('readmission_mountinfo_invalid')
   if fields[4]!=plan['target']: continue
   mount_root=fields[3]
   relation='stage-exact' if mount_root==plan['staging'] else 'stage-descendant' if mount_root.startswith(plan['staging']+'/') else 'target-exact' if mount_root==plan['target'] else 'target-descendant' if mount_root.startswith(plan['target']+'/') else 'root' if mount_root=='/' else 'other'
   filesystem=tail[0] if tail[0] in {'ext4','tmpfs','overlay','erofs','fuse','f2fs'} else 'other'
   entries.append({'rootRelation':relation,'filesystem':filesystem})
  if len(entries)>16: unknown('readmission_mount_diagnostic_invalid')
  target_ca=plan['target']+'/'+expected['caStoreName']
  inner='if [ -f '+shlex.quote(target_ca)+' ] && [ ! -L '+shlex.quote(target_ca)+' ]; then sha256sum '+shlex.quote(target_ca)+'; elif [ -e '+shlex.quote(target_ca)+' ] || [ -L '+shlex.quote(target_ca)+' ]; then echo other; else echo absent; fi'
  outer='nsenter -t '+shlex.quote(plan['zygote']['pid'])+' -m -- /system/bin/sh -c '+shlex.quote(inner)
  target_raw=adb_call('shell','-T','sh','-c',shlex.quote(outer),max_bytes=4096)
  if target_raw in {'absent','other'}: ca_relation=target_raw
  else:
   parts=target_raw.split()
   if len(parts)!=2 or parts[1]!=target_ca or not re.fullmatch(r'[0-9a-f]{64}',parts[0]): unknown('readmission_mount_diagnostic_invalid')
   ca_relation='owned' if parts[0]==expected['caSha256'] else 'foreign'
  if zygote_identity(plan['zygote']['pid'])!=plan['zygote'] or staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_native_changed')
  readmission_public_proof('0'); readmission_records_guard()
  diagnostic={'targetEntryCount':len(entries),'entries':entries,'ownCaRelation':ca_relation,'openingTargetMountRecorded':False}
  return diagnostic,raw,target_raw
 first=observe(); second=observe()
 if first!=second: unknown('readmission_observation_changed')
 emit('partial','readmission_target_mount_observed',mountDiagnostic=second[0],**principal_extra())
def mount_diagnostic_gate(plan):
 if api!='29' or private(job/'intent.json',8192)!=remote_intent_raw: unknown('intent_changed')
 if exact_lease_present() is None: unknown('lease_changed')
 if (job/'ready.json').exists() or (job/'cleaned.json').exists(): unknown('readmission_phase_invalid')
 if json.loads(private(job/'mount-intent.json',8192))!=plan or json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
 failure=json.loads(private(job/'mount-failure.json',1024))
 if failure not in ({'phase':'mount','exit':'nonzero','errorClass':'not-found'}, {'phase':'mount','exit':'nonzero','errorClass':'not-found','errorOrigin':'mount-path-pair'}): unknown('readmission_failed_mount_unverified')
 children=list(root.glob('android-runtime-acceptance-*.json'))
 if len(children)>256: unknown('readmission_child_inventory_unknown')
 for child in children:
  if json.loads(private(child,8192)).get('parentCorrelationId')==correlation: unknown('readmission_child_present')
 identity('0'); installed()
 if routes(): unknown('readmission_reverse_present')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('readmission_namespace_changed')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('readmission_stage_changed')
 ca=plan['staging']+'/'+expected['caStoreName']
 if shell('sha256sum',ca).split()!=[expected['caSha256'],ca]: unknown('readmission_ca_changed')
def recovery_records():
 if not isinstance(recovery,dict) or set(recovery) not in ({'correlationId','historicalCorrelationId','originalIntentSha256','historicalIntentSha256','historicalExpected'},{'correlationId','historicalCorrelationId','originalIntentSha256','historicalIntentSha256','historicalExpected','receipt'}): unknown('recovery_binding_invalid')
 uuid=r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
 if not all(isinstance(recovery.get(key),str) and re.fullmatch(uuid,recovery[key]) for key in ('correlationId','historicalCorrelationId')) or len({correlation,recovery['correlationId'],recovery['historicalCorrelationId']})!=3: unknown('recovery_binding_invalid')
 if not all(isinstance(recovery.get(key),str) and re.fullmatch(r'[0-9a-f]{64}',recovery[key]) for key in ('originalIntentSha256','historicalIntentSha256')): unknown('recovery_binding_invalid')
 historical=recovery['historicalExpected']
 if not isinstance(historical,dict) or set(historical)!=set(stored_expected) or any(historical.get(key)!=stored_expected.get(key) for key in ('host','adb','cli','serial','api','avd','packageSha256','caSha256','caStoreName','campaignId')): unknown('recovery_binding_invalid')
 if private(job/'intent.json',8192)!=remote_intent_raw or exact_lease_present() is None: unknown('recovery_original_changed')
 old=root/('android-endpoint-'+recovery['historicalCorrelationId']);records={};fingerprints={}
 for name,limit in (('intent.json',8192),('mount-intent.json',8192),('stage-owned.json',8192),('cleanup-intent.json',8192),('cleaned.json',1024)):
  path=old/name;before=path.lstat()
  def pin(info):return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,stat.S_IMODE(info.st_mode),info.st_uid,info.st_nlink]
  raw=private(path,limit);after=path.lstat()
  if before.st_nlink!=1 or pin(before)!=pin(after): unknown('recovery_historical_changed')
  records[name]=json.loads(raw);fingerprints[name]={'fingerprint':pin(after),'sha256':hashlib.sha256(raw).hexdigest()}
 if records['intent.json']!=historical: unknown('recovery_historical_changed')
 historical_backup=private(pathlib.Path(historical['backupPath']))
 current_backup=private(pathlib.Path(stored_expected['backupPath']))
 if hashlib.sha256(historical_backup).hexdigest()!=historical['backupSha256'] or hashlib.sha256(current_backup).hexdigest()!=stored_expected['backupSha256'] or canonical_rules(json.loads(historical_backup))!=canonical_rules(json.loads(current_backup)): unknown('recovery_historical_changed')
 plan=records['mount-intent.json'];zygote=plan.get('zygote') if isinstance(plan,dict) else None
 if (not isinstance(plan,dict) or set(plan)!={'zygote','target','staging','stagingIdentity'} or plan['target']!='/system/etc/security/cacerts' or plan['staging']!='/data/local/tmp/vpn-control-endpoint-'+recovery['historicalCorrelationId'] or not re.fullmatch(r'0:755:[0-9]+:[1-9][0-9]*',str(plan['stagingIdentity'])) or not isinstance(zygote,dict) or set(zygote)!={'pid','startTicks','namespace'} or not isinstance(zygote['pid'],str) or not re.fullmatch(r'[1-9][0-9]*',zygote['pid']) or type(zygote['startTicks']) is not int or zygote['startTicks']<1 or not re.fullmatch(re.escape('mnt:[')+r'[0-9]+'+re.escape(']'),str(zygote['namespace']))): unknown('recovery_historical_changed')
 if records['stage-owned.json']!={key:plan[key] for key in ('zygote','staging','stagingIdentity')} or records['cleanup-intent.json']!={'correlationId':recovery['historicalCorrelationId'],'mount':plan} or records['cleaned.json']!={'correlationId':recovery['historicalCorrelationId'],'caSha256':historical['caSha256']}: unknown('recovery_historical_changed')
 children=list(root.glob('android-runtime-acceptance-*.json'))
 if len(children)>256: unknown('recovery_child_unknown')
 for child in children:
  item=json.loads(private(child,8192))
  if not isinstance(item,dict) or item.get('parentCorrelationId') in {correlation,recovery['historicalCorrelationId']}: unknown('recovery_child_present')
 return plan,fingerprints
def recovery_native(post=False):
 old,pins=recovery_records();current=validate_mount(json.loads(private(job/'mount-intent.json',8192)))
 identity('0');installed()
 if routes() or current['zygote']!=old['zygote'] or zygote_identity(old['zygote']['pid'])!=old['zygote']: unknown('recovery_namespace_changed')
 if staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']]: unknown('recovery_current_stage_changed')
 ns=['/system/bin/nsenter','-t',old['zygote']['pid'],'-m','--']
 absent='if [ -e '+shlex.quote(old['staging'])+' ] || [ -L '+shlex.quote(old['staging'])+' ]; then echo present; else echo absent; fi'
 for prefix in ([],ns):
  outer=' '.join(shlex.quote(word) for word in [*prefix,'/system/bin/sh','-c',absent])
  if shell('/system/bin/sh','-c',shlex.quote(outer))!='absent': unknown('recovery_historical_stage_present')
 raw=shell('cat','/proc/'+old['zygote']['pid']+'/mountinfo');layout=mount_layout(old,raw)
 if mount_layout(current,raw)['references']: unknown('recovery_current_stage_changed')
 inside=shell(*ns,'/system/bin/stat','-c','%d:%i:%h:%F',old['target']).split(':');original=old['stagingIdentity'].split(':')[2:]
 if post:
  if len(inside)!=4 or not all(re.fullmatch(r'[0-9]+',x) for x in inside[:3]) or inside[3]!='directory' or int(inside[2])<1 or inside[:2]==original or layout['references']: unknown('recovery_post_unverified')
 else:
  if inside!=[*original,'0','directory'] or len(layout['targets'])!=1: unknown('recovery_target_changed')
  entry=layout['targets'][0]
  if entry[2]!=layout['device'] or entry[3]!=layout['root']+'//deleted' or len(layout['references'])!=1 or layout['references'][0]!=entry: unknown('recovery_target_changed')
  inner='exec 3<'+shlex.quote(old['target'])+"; /system/bin/readlink /proc/$$/fd/3; printf '%s\n' __VPN_CONTROL_DESCRIPTOR__; /system/bin/stat -L -c '%d:%i:%F' /proc/$$/fd/3; /system/bin/cat /proc/$$/fdinfo/3"
  outer=' '.join(shlex.quote(word) for word in [*ns,'/system/bin/sh','-c',inner]);text=shell('/system/bin/sh','-c',shlex.quote(outer))
  parts=text.split('__VPN_CONTROL_DESCRIPTOR__\n')
  if len(parts)!=2 or parts[0].strip()!=old['target']+' (deleted)' or parts[1].splitlines()[0]!=':'.join([*original,'directory']) or re.findall(r'^mnt_id:\s*([0-9]+)$',parts[1],re.MULTILINE)!=[entry[0]]: unknown('recovery_descriptor_changed')
 same_device=[]
 for line in raw.splitlines():
  fields=line.split(' - ',1)[0].split()
  if fields[2]==layout['device']: same_device.append(fields[4])
 if len(same_device)>128 or len(same_device)!=len(set(same_device)): unknown('recovery_inode_inventory_unknown')
 matches=0
 for point in same_device:
  if not re.fullmatch(r'/[A-Za-z0-9/._-]*',point): unknown('recovery_inode_inventory_unknown')
  inode=shell(*ns,'/system/bin/stat','-c','%d:%i',shlex.quote(point)).split(':')
  if len(inode)!=2 or not all(re.fullmatch(r'[0-9]+',x) for x in inode): unknown('recovery_inode_inventory_unknown')
  if inode==original:
   matches+=1
   if post or point!=old['target']: unknown('recovery_inode_inventory_unknown')
 if matches!=(0 if post else 1): unknown('recovery_inode_inventory_unknown')
 target_ca=old['target']+'/'+expected['caStoreName']
 result=subprocess.run([adb,'-s',serial,'shell','-T',*ns,'/system/bin/stat','-c','%F',target_ca],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 if len(result.stdout)>4096 or len(result.stderr)>4096 or result.returncode!=1 or result.stdout or result.stderr.decode('utf-8','strict').strip() not in {"stat: '"+target_ca+"': No such file or directory",'stat: '+target_ca+': No such file or directory'}: unknown('recovery_target_ca_unverified')
 if staging_identity(current['staging'])!=current['stagingIdentity'] or shell('sha256sum',current['staging']+'/'+expected['caStoreName']).split()!=[expected['caSha256'],current['staging']+'/'+expected['caStoreName']] or shell('cat','/proc/'+old['zygote']['pid']+'/mountinfo')!=raw: unknown('recovery_native_changed')
 if zygote_identity(old['zygote']['pid'])!=old['zygote'] or recovery_records()!=(old,pins): unknown('recovery_native_changed')
 return {'historicalMount':old,'historicalRecords':pins,'mountinfoSha256':hashlib.sha256(raw.encode()).hexdigest(),'targetEntry':layout['targets'][0] if not post else None,'targetIdentity':inside,'currentMount':current}
def recover_endpoint():
 if action=='recovery-status' and not os.path.lexists(lock): unknown('recovery_lock_unverified')
 # One host lock covers observation, immutable fence, sole effect, and readback.
 descriptor=lease_lock()
 try: recover_endpoint_locked()
 finally: release_lock(descriptor)
def recover_endpoint_locked():
 global readmission,observed_readmission_owner
 plan,pins=recovery_records();path=job/('mount-recovery-'+recovery['correlationId']+'.json');attempt=job/('mount-recovery-'+recovery['correlationId']+'.attempt.json');complete=job/('mount-recovery-'+recovery['correlationId']+'.complete.json')
 binding={key:value for key,value in recovery.items() if key!='receipt'}
 if action=='recovery-readmit':
  if os.path.lexists(path) or os.path.lexists(attempt) or os.path.lexists(complete): unknown('recovery_already_recorded')
  first={'public':readmission_snapshot(),'native':recovery_native()};second={'public':readmission_snapshot(),'native':recovery_native()}
  if first!=second: unknown('recovery_observation_changed')
  receipt={'schema':1,'kind':'android-endpoint-deleted-mount-recovery','binding':binding,'snapshot':second}
  record(path,receipt);emit('ready',recovery=receipt)
 receipt=json.loads(private(path,8192))
 if receipt!=recovery.get('receipt') or type(receipt.get('schema')) is not int or receipt.get('schema')!=1 or receipt.get('kind')!='android-endpoint-deleted-mount-recovery' or receipt.get('binding')!=binding: unknown('recovery_receipt_changed')
 snapshot=receipt['snapshot'];expected['owner']=snapshot['public']['owner'];expected['revision']=snapshot['public']['revision'];observed_readmission_owner=expected['owner']
 readmission={**readmission,'receipt':{'snapshot':snapshot['public']}}
 if action=='recovery-status' and os.path.lexists(attempt):
  if json.loads(private(attempt,1024))!={'schema':1,'receiptSha256':hashlib.sha256(private(path,8192)).hexdigest()}: unknown('recovery_receipt_changed')
  readmission_public_proof('0');first=recovery_native(post=True);readmission_public_proof('0');second=recovery_native(post=True)
  if first!=second or second['historicalRecords']!=snapshot['native']['historicalRecords']: unknown('recovery_post_unverified')
  emit('partial','recovery_target_restored',recoveryCorrelationId=recovery['correlationId'])
 if os.path.lexists(attempt) or os.path.lexists(complete): unknown('recovery_attempt_already_recorded')
 first={'public':readmission_snapshot(),'native':recovery_native()};second={'public':readmission_snapshot(),'native':recovery_native()}
 if first!=second or second!=snapshot: unknown('recovery_receipt_stale')
 if action=='recovery-status': emit('partial','recovery_ready',recoveryCorrelationId=recovery['correlationId'])
 # Create-only attempt is the replay fence, before the sole native effect.
 record(attempt,{'schema':1,'receiptSha256':hashlib.sha256(private(path,8192)).hexdigest()})
 readmission_public_proof('0')
 if recovery_native()!=snapshot['native']: unknown('recovery_receipt_stale')
 ns=['/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--','/system/bin/umount',plan['target']]
 try:result=subprocess.run([adb,'-s',serial,'shell','-T',*ns],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 except (OSError,subprocess.TimeoutExpired): unknown('recovery_unmount_uncertain')
 record(job/('mount-recovery-'+recovery['correlationId']+'.command.json'),{'schema':1,'argv':ns,'returncode':result.returncode,'stdout':base64.b64encode(result.stdout[:4096]).decode(),'stderr':base64.b64encode(result.stderr[:4096]).decode(),'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),'truncated':len(result.stdout)>4096 or len(result.stderr)>4096})
 if result.returncode or len(result.stdout)>4096 or len(result.stderr)>4096: unknown('recovery_unmount_uncertain')
 readmission_public_proof('0');first=recovery_native(post=True);readmission_public_proof('0');second=recovery_native(post=True)
 if first!=second or second['historicalRecords']!=snapshot['native']['historicalRecords']: unknown('recovery_post_unverified')
 record(complete,{'schema':1,'receiptSha256':hashlib.sha256(private(path,8192)).hexdigest(),'post':second});emit('partial','recovery_target_restored',recoveryCorrelationId=recovery['correlationId'])
def mount_failure_diagnostic():
 if (not isinstance(mount_diagnostic_correlation,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',mount_diagnostic_correlation) or mount_diagnostic_correlation==correlation): unknown('readmission_binding_invalid')
 plan=validate_mount(json.loads(private(job/'mount-intent.json',8192))); mount_diagnostic_gate(plan); guard('0')
 capture=[]; facts={}; ns=['/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--']
 def probe(label,words):
  step('target-ca' if label.startswith('target') else 'stage-inode' if label.startswith('stage') else 'private')
  try:
   result=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
   output=result.stdout; error=result.stderr; code=result.returncode
  except (OSError,subprocess.TimeoutExpired): output=b'';error=b'';code=None
  # Raw diagnostic material stays in this private create-only host journal.
  capture.append({'label':label,'argv':words,'returncode':code,'stdout':base64.b64encode(output[:4096]).decode(),'stderr':base64.b64encode(error[:4096]).decode(),'stdoutSha256':hashlib.sha256(output).hexdigest(),'stderrSha256':hashlib.sha256(error).hexdigest(),'truncated':len(output)>4096 or len(error)>4096})
  if code!=0 or len(output)>1048576 or len(error)>4096: return None
  try: return output.decode('utf-8','strict').strip()
  except UnicodeError: return None
 for label,path in (('target',plan['target']),('stage',plan['staging'])):
  outside=probe(label+'-lstat',['/system/bin/stat','-c','%F:%u:%a:%d:%i',path])
  inside=probe(label+'-namespace-lstat',[*ns,'/system/bin/stat','-c','%F:%u:%a:%d:%i',path])
  followed=probe(label+'-namespace-stat',[*ns,'/system/bin/stat','-L','-c','%F:%u:%a:%d:%i',path])
  canonical=probe(label+'-namespace-realpath',[*ns,'/system/bin/readlink','-f',path])
  parent=probe(label+'-namespace-parent',[*ns,'/system/bin/stat','-c','%F:%u:%a:%d:%i',str(pathlib.PurePosixPath(path).parent)])
  facts[label]={'lstat':'directory' if inside and inside.startswith('directory:') else 'symlink' if inside and inside.startswith('symbolic link:') else 'unavailable' if inside is None else 'other',
    'followed':'directory' if followed and followed.startswith('directory:') else 'unavailable' if followed is None else 'other',
    'outsideInside':'same' if outside is not None and outside==inside else 'different' if outside is not None and inside is not None else 'unavailable',
    'canonical':'exact' if canonical==path else 'different' if canonical is not None else 'unavailable',
    'parent':'directory' if parent and parent.startswith('directory:') else 'unavailable' if parent is None else 'other'}
 link_identity={}
 for label,path in (('target',plan['target']),('stage',plan['staging'])):
  text=probe(label+'-namespace-links',[*ns,'/system/bin/stat','-c','%d:%i:%h:%F',path])
  parts=text.split(':') if text is not None else []
  valid=len(parts)==4 and all(re.fullmatch(r'[0-9]{1,20}',item) for item in parts[:3]) and parts[3]=='directory'
  link_identity[label]=parts[:2] if valid else None
  facts[label+'LinkCount']='zero' if valid and int(parts[2])==0 else 'positive' if valid else 'unavailable'
 inner='exec 3<'+shlex.quote(plan['target'])+"; /system/bin/readlink /proc/$$/fd/3; printf '%s\\n' __VPN_CONTROL_DESCRIPTOR__; /system/bin/stat -L -c '%d:%i:%F' /proc/$$/fd/3; /system/bin/cat /proc/$$/fdinfo/3"
 outer='/system/bin/nsenter -t '+shlex.quote(plan['zygote']['pid'])+' -m -- /system/bin/sh -c '+shlex.quote(inner)
 text=probe('targetDescriptor',['/system/bin/sh','-c',shlex.quote(outer)])
 parts=text.split('__VPN_CONTROL_DESCRIPTOR__\n') if text is not None else []
 facts['targetDescriptor']='unavailable';facts['targetDescriptorIdentity']='unavailable'
 if len(parts)==2:
  link=parts[0].rstrip('\n');lines=parts[1].splitlines();identity=lines[0].split(':') if lines else []
  facts['targetDescriptor']='deleted' if link.endswith(' (deleted)') else 'linked' if link==plan['target'] else 'other'
  if len(identity)==3 and identity[2]=='directory' and all(re.fullmatch(r'[0-9]{1,20}',item) for item in identity[:2]):
   facts['targetDescriptorIdentity']='exact' if link_identity['target']==identity[:2] else 'different'
 # Filter inside the pinned namespace before capture; retain at most sixteen exact-target records.
 inner="/system/bin/awk -v target="+shlex.quote(plan['target'])+" "+shlex.quote('$5 == target { if (++n <= 16) print; else exit 1 }')+' /proc/self/mountinfo'
 outer='/system/bin/nsenter -t '+shlex.quote(plan['zygote']['pid'])+' -m -- /system/bin/sh -c '+shlex.quote(inner)
 text=probe('targetMountinfo',['/system/bin/sh','-c',shlex.quote(outer)])
 entries=[];valid=text is not None
 for line in (text.splitlines() if text is not None else []):
  split=line.split(' - ',1);fields=split[0].split()
  if len(split)!=2 or len(fields)<6 or fields[4]!=plan['target'] or not all(re.fullmatch(r'[1-9][0-9]{0,9}',item) for item in fields[:2]): valid=False;break
  entries.append(fields)
 facts['targetMountCount']='unavailable' if not valid else 'zero' if not entries else 'one' if len(entries)==1 else 'multiple'
 facts['targetMountRoot']='unavailable'
 if valid and len(entries)==1:
  root=entries[0][3];facts['targetMountRoot']='root' if root=='/' else 'stage' if root==plan['staging'] else 'target' if root==plan['target'] else 'other'
 kernel=probe('kernelVersion',['/system/bin/uname','-r']);facts['kernelVersion']='readable' if kernel and len(kernel)<=256 and re.fullmatch(r'[A-Za-z0-9._+\-]+',kernel) else 'unavailable'
 for label,path in (('rootMembership','/'),('targetMembership',plan['target']),('stageMembership',plan['staging'])):
  inner='exec 3<'+shlex.quote(path)+"; cat /proc/$$/fdinfo/3; printf '%s\\n' __VPN_CONTROL_MOUNTINFO__; /system/bin/cut -d ' ' -f1 /proc/$$/mountinfo"
  outer='/system/bin/nsenter -t '+shlex.quote(plan['zygote']['pid'])+' -m -- /system/bin/sh -c '+shlex.quote(inner)
  text=probe(label,['/system/bin/sh','-c',shlex.quote(outer)])
  try:
   parts=text.split('__VPN_CONTROL_MOUNTINFO__\n'); ids=re.findall(r'^mnt_id:\s*(.*)$',parts[0],re.MULTILINE); members=parts[1].splitlines()
   valid=(len(parts)==2 and len(ids)==1 and 0<len(members)<=1024 and len(members)==len(set(members)) and all(re.fullmatch(r'[1-9][0-9]{0,9}',item) and int(item)<=2147483647 for item in [*ids,*members]))
   facts[label]='member' if valid and ids[0] in members else 'foreign' if valid else 'unavailable'
  except (AttributeError,IndexError): facts[label]='unavailable'
 current_ns=probe('namespaceIdentity',[*ns,'/system/bin/readlink','/proc/self/ns/mnt'])
 facts['namespaceIdentity']='exact' if current_ns==plan['zygote']['namespace'] else 'different' if current_ns is not None else 'unavailable'
 for label,path in (('mountHelper','/system/bin/mount'),('nsenterHelper','/system/bin/nsenter')):
  link=probe(label+'-realpath',['/system/bin/readlink','-f',path]); outer=probe(label+'-outside-hash',['/system/bin/sha256sum',path]); inner=probe(label+'-inside-hash',[*ns,'/system/bin/sha256sum',path])
  facts[label]={'canonical':'toybox' if link=='/system/bin/toybox' else 'self' if link==path else 'other' if link is not None else 'unavailable',
    'namespaceIdentity':'same' if outer is not None and inner==outer else 'different' if outer is not None and inner is not None else 'unavailable'}
 for label,path in (('procFilesystems','/proc/filesystems'),('procMounts','/proc/mounts')):
  text=probe(label,[*ns,'/system/bin/cat',path]);facts[label]='readable' if text is not None else 'unavailable'
 enforcing=probe('selinux',['/system/bin/getenforce']);facts['selinux']=enforcing.lower() if enforcing is not None and enforcing.lower() in {'enforcing','permissive','disabled'} else 'unavailable'
 domain=probe('domain',['/system/bin/cat','/proc/self/attr/current']);facts['domain']='su' if domain is not None and domain.startswith('u:r:su:') else 'shell' if domain is not None and domain.startswith('u:r:shell:') else 'other' if domain is not None else 'unavailable'
 avc=probe('kernelAvc',['/system/bin/logcat','-d','-b','kernel','-t','128'])
 matches=[] if avc is None else [line for line in avc.splitlines() if 'avc: denied' in line and (any(path in line for path in (plan['target'],plan['staging'])) or 'name="'+pathlib.PurePosixPath(plan['staging']).name+'"' in line) and ('mount' in line or 'nsenter' in line)]
 # Do not retain unrelated kernel lines, even in the private capture.
 capture[-1]['stdout']=base64.b64encode(('\n'.join(matches)).encode()[:4096]).decode()
 facts['avc']='unavailable' if avc is None else 'matching-denial' if matches else 'none'
 mount_diagnostic_gate(plan); guard('0'); mount_diagnostic_gate(plan)
 source='unavailable'
 if os.path.lexists(job/'mount-command-evidence.json'):
  trace=json.loads(private(job/'mount-command-evidence.json',16384))
  exact=[adb,'-s',serial,'shell','-T','nsenter','-t',plan['zygote']['pid'],'-m','--','mount','--bind',plan['staging'],plan['target']]
  if not isinstance(trace,dict) or trace.get('argv')!=exact or type(trace.get('returncode')) is not int or trace['returncode']==0: unknown('readmission_observation_changed')
  source='present'
 record(job/('mount-diagnostic-'+mount_diagnostic_correlation+'.json'),{'schema':1,'endpointCorrelationId':correlation,'diagnosticCorrelationId':mount_diagnostic_correlation,'originalIntentSha256':hashlib.sha256(remote_intent_raw).hexdigest(),'originalCommandEvidence':source,'probes':capture})
 emit('partial','mount_failure_observed',diagnosticCorrelationId=mount_diagnostic_correlation,originalCommandEvidence=source,mountFailureDiagnostic=facts)
def readmitted_terminal_status():
 receipt=readmission.get('receipt') if isinstance(readmission,dict) else None
 path=readmission_receipt_path()
 if not isinstance(receipt,dict) or set(receipt)!={'schema','kind','endpointCorrelationId','readmissionCorrelationId','originalIntentSha256','remoteIntentSha256','originalOwner','originalRevision','snapshot'} or json.loads(private(path,8192))!=receipt: unknown('readmission_receipt_changed')
 opening=receipt['snapshot']
 if (type(receipt['schema']) is not int or receipt['schema']!=1 or type(receipt['originalRevision']) is not int or receipt['kind']!='android-endpoint-cleanup-readmission' or receipt['endpointCorrelationId']!=correlation or receipt['readmissionCorrelationId']!=readmission['correlationId'] or receipt['originalIntentSha256']!=readmission['originalIntentSha256'] or receipt['remoteIntentSha256']!=hashlib.sha256(remote_intent_raw).hexdigest() or receipt['originalOwner']!=stored_expected['owner'] or receipt['originalRevision']!=stored_expected['revision'] or not isinstance(opening,dict) or api!='29' or opening.get('uid')!='0' or opening.get('namespaceObservation')!='verified' or opening.get('mountObservation')!='owned-stage-unreferenced' or not re.fullmatch(r'[0-9a-f]{64}',opening.get('unownedTargetMountsSha256',''))): unknown('readmission_receipt_changed')
 if (set(opening)!={'owner','revision','mount','rulesSha256','uid','api','avd','abi','reversePorts','mountFailure','mountObservation','namespaceObservation','unownedTargetMountsSha256'} or
     not isinstance(opening.get('owner'),str) or not 0<len(opening['owner'])<=256 or any(ord(char)<32 for char in opening['owner']) or
     opening['owner']!=expected['owner'] or type(opening.get('revision')) is not int or opening['revision']<0 or opening['revision']!=expected['revision'] or
     type(opening.get('api')) is not int or opening['api']!=29 or opening.get('avd')!=avd or opening.get('abi')!='x86_64' or opening.get('reversePorts')!=[]): unknown('readmission_receipt_changed')
 plan=validate_mount(opening.get('mount'))
 if set(plan)!={'zygote','target','staging','stagingIdentity'} or set(plan['zygote'])!={'pid','startTicks','namespace'}: unknown('mount_intent_invalid')
 def records():
  readmission_records_guard()
  if json.loads(private(job/'cleaned.json',8192))!={'correlationId':correlation,'caSha256':expected['caSha256']}: unknown('cleaned_changed')
  if json.loads(private(job/'mount-failure.json',1024))!=opening['mountFailure']: unknown('readmission_failed_mount_unverified')
  if json.loads(private(job/'mount-intent.json',8192))!=plan or json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')}: unknown('readmission_stage_changed')
  for phase in ('cleanup-stage-remove','cleanup-final-unroot'):
   if json.loads(private(job/('checkpoint-'+phase+'.json'),1024))!={'phase':phase}: unknown('readmission_phase_invalid')
 def native_phase(words):
  if words[:2]==['/system/xbin/su','0,0']: words=words[2:]
  if words[:1]==['/system/bin/nsenter']: words=words[5:]
  if words[:1]==['/system/bin/stat']: return 'stage-inode' if words[-1]==plan['staging'] else 'target-ca'
  if words[:1]==['/system/bin/cat']: return 'target-mountinfo' if words[-1].endswith('/mountinfo') else 'zygote-generation'
  if words[:1]==['/system/bin/readlink']: return 'zygote-namespace'
  if words[:1]==['/system/bin/id']: return 'device-identity'
  return 'private'
 def probe(words):
  step(native_phase(words))
  try: result=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
  except (OSError,subprocess.TimeoutExpired): unknown('readmission_terminal_native_unverified')
  if len(result.stdout)>1048576 or len(result.stderr)>4096: unknown('readmission_terminal_native_unverified')
  try: return result.returncode,result.stdout.decode('utf-8','strict').strip(),result.stderr.decode('utf-8','strict').strip()
  except UnicodeError: unknown('readmission_terminal_native_unverified')
 def binary():
  info=probe(['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']); digest=probe(['sha256sum','/system/xbin/su'])
  if info[0]!=0 or info[2] or not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',info[1]) or digest[0]!=0 or digest[2] or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',digest[1]): unknown('readmission_principal_unverified')
  return info[1],digest[1]
 pin=None
 def native(words,absent=None):
  if binary()!=pin: unknown('readmission_principal_unverified')
  value=probe(['/system/xbin/su','0,0',*words])
  if binary()!=pin: unknown('readmission_principal_unverified')
  step(native_phase(words))
  if absent is not None:
   if value[0]==0: unknown('readmission_terminal_owned_path_present')
   if value[0]!=1 or value[1] or value[2] not in {"stat: '"+absent+"': No such file or directory",'stat: '+absent+': No such file or directory'}: unknown('readmission_terminal_native_unverified')
   return None
  if value[0]!=0 or value[2]: unknown('readmission_terminal_native_unverified')
  return value[1]
 def generation():
  raw=native(['/system/bin/cat','/proc/'+plan['zygote']['pid']+'/stat'])
  try: ticks=int(raw.rsplit(')',1)[1].split()[19])
  except (ValueError,IndexError): unknown('readmission_namespace_changed')
  namespace=native(['/system/bin/readlink','/proc/'+plan['zygote']['pid']+'/ns/mnt'])
  if ticks!=plan['zygote']['startTicks'] or namespace!=plan['zygote']['namespace']: unknown('readmission_namespace_changed')
 for _ in range(2):
  records(); readmission_public_proof('2000')
  current=binary()
  if pin is not None and current!=pin: unknown('readmission_principal_unverified')
  pin=current
  help_result=probe(['/system/xbin/su','--help'])
  help_text=help_result[1] or help_result[2]
  if help_result[0]!=0 or help_result[1] and help_result[2] or help_text!=AOSP_HELP: unknown('readmission_principal_unverified')
  if binary()!=pin: unknown('readmission_principal_unverified')
  if native(['/system/bin/id','-u'])!='0': unknown('readmission_principal_unverified')
  generation()
  native(['/system/bin/stat','-c','%F',plan['staging']],absent=plan['staging'])
  ns=['/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--']
  native([*ns,'/system/bin/stat','-c','%F',plan['staging']],absent=plan['staging'])
  raw=native(['/system/bin/cat','/proc/'+plan['zygote']['pid']+'/mountinfo'])
  if hashlib.sha256(raw.encode()).hexdigest()!=opening['unownedTargetMountsSha256']: unknown('readmission_native_changed')
  ca=plan['target']+'/'+expected['caStoreName']
  native([*ns,'/system/bin/stat','-c','%F',ca],absent=ca)
  generation(); records(); identity('2000')
 emit('cleaned',None,device={'uid':'2000','api':29,'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[])
def cleanup_readmitted_effects():
 global readmission_stage_retired,readmission_mount_pin
 # Shell admission leaves mount/namespace unobserved. The first guarded root
 # is followed by full namespace proof before stage removal. Retire while
 # root, then unroot once. Every native effect has fresh proof. Each
 # checkpoint is followed by fresh proof, and owned retirement is observed
 # explicitly without editing the original receipt or treating drift as owned.
 receipt=readmission['receipt']; opening=receipt['snapshot']; plan=opening['mount']
 if opening['uid']=='2000':
  checkpoint('cleanup-root')
  readmission_records_guard()
  if readmission_snapshot()!=opening: unknown('readmission_receipt_stale')
  readmission_records_guard()
  adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30)
 rooted=opening if opening['uid']=='0' else {**opening,'uid':'0','mountObservation':'owned-stage-unreferenced','namespaceObservation':'verified'}
 first=readmission_snapshot(); second=readmission_snapshot()
 if opening['uid']=='2000':
  pin=first.get('unownedTargetMountsSha256')
  if not isinstance(pin,str) or not re.fullmatch(r'[0-9a-f]{64}',pin): unknown('readmission_native_changed')
  rooted={**rooted,'unownedTargetMountsSha256':pin}
 if first!=rooted or second!=rooted: unknown('readmission_receipt_stale')
 readmission_mount_pin=rooted.get('unownedTargetMountsSha256')
 checkpoint('cleanup-stage-remove')
 readmission_records_guard()
 if readmission_snapshot()!=rooted: unknown('readmission_receipt_stale')
 readmission_records_guard()
 shell('rm','-r',plan['staging'])
 readmission_stage_retired=True
 checkpoint('cleanup-final-unroot')
 readmission_retired_proof(plan,'0')
 adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 readmission_retired_proof(plan,'2000')
 finish_cleaned()
def cleanup_effects(plan):
 plan=validate_mount(plan)
 uid=shell('id','-u')
 if uid=='0':
  guard('0')
  if routes(): unknown('foreign_reverse_before_unroot')
  checkpoint('cleanup-unroot')
  guard('0')
  adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 elif uid!='2000': unknown('device_uid_changed')
 guard()
 current=routes()
 if any(port not in (18080,18081) or host!={18080:expected['httpsHostPort'],18081:expected['socksHostPort']}[port] for port,host in current.items()): unknown('foreign_reverse_before_cleanup')
 for port in (18081,18080):
  if current.get(port) is not None:
   checkpoint('cleanup-reverse-socks' if port==18081 else 'cleanup-reverse-https')
   adb_call('reverse','--remove','tcp:'+str(port))
   if routes().get(port) is not None: unknown('reverse_remove_uncertain')
 if routes(): unknown('foreign_reverse_before_unmount')
 guard()
 if not (job/'cleanup-intent.json').exists(): record(job/'cleanup-intent.json',{'correlationId':correlation,'mount':plan})
 elif json.loads(private(job/'cleanup-intent.json',8192))!={'correlationId':correlation,'mount':plan}: unknown('cleanup_intent_changed')
 if routes(): unknown('foreign_reverse_before_root')
 checkpoint('cleanup-root')
 adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('staging_replaced')
 mounted=shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo')
 layout=mount_layout(plan,mounted)
 if layout['owned'] and len(layout['targets'])!=1: unknown('foreign_overlay_above_fixture')
 if len(layout['owned'])==1:
  if shell('nsenter','-t',plan['zygote']['pid'],'-m','--','sha256sum',plan['target']+'/'+expected['caStoreName']).split()[0]!=expected['caSha256']: unknown('mounted_ca_changed')
  checkpoint('cleanup-unmount')
  guard('0')
  unmount_exact(plan)
 guard('0')
 if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('zygote_reused')
 if staging_identity(plan['staging'])!=plan['stagingIdentity']: unknown('staging_replaced')
 remaining=mount_layout(plan,shell('cat','/proc/'+plan['zygote']['pid']+'/mountinfo'))
 if remaining['references']: unknown('fixture_mount_remaining')
 checkpoint('cleanup-stage-remove')
 shell('rm','-r',plan['staging'])
 checkpoint('cleanup-final-unroot')
 guard('0')
 adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 finish_cleaned()
def remaining_fp(i): return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_nlink]
def remaining_pin(path,limit=8192):
 before=path.lstat();raw=private(path,limit);after=path.lstat()
 if before.st_nlink!=1 or remaining_fp(before)!=remaining_fp(after): unknown('remaining_record_changed')
 return {'generation':remaining_fp(before),'sha256':hashlib.sha256(raw).hexdigest()}
def remaining_names():
 return ['remaining-stage-admission.json','intent.json','stage.json','ca.pem','mount-intent.json','stage-owned.json','cleanup-intent.json',*[ 'checkpoint-'+x+'.json' for x in ('cleanup-reverse-https','cleanup-reverse-socks','cleanup-root','cleanup-unmount')]]
def remaining_records_guard(native=False):
 if api!='29' or not isinstance(remaining,dict) or set(remaining) not in ({'correlationId','originalIntentSha256'},{'correlationId','originalIntentSha256','receipt','receiptPin'}): unknown('remaining_binding_invalid')
 if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',str(remaining.get('correlationId',''))) or remaining['correlationId']==correlation or not re.fullmatch(r'[0-9a-f]{64}',str(remaining.get('originalIntentSha256',''))): unknown('remaining_binding_invalid')
 reservation=job/'remaining-stage-admission.json'
 if os.path.lexists(reservation):
  if json.loads(private(reservation,8192))!={key:remaining[key] for key in ('correlationId','originalIntentSha256')}:unknown('remaining_already_recorded')
 elif action!='remaining-cleanup-admit':unknown('remaining_binding_invalid')
 for directory in (root,job):
  info=directory.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('remaining_record_changed')
 if private(job/'intent.json',8192)!=remote_intent_raw: unknown('remaining_record_changed')
 if os.path.lexists(lease):
  if exact_lease_present() is None: unknown('remaining_record_changed')
 elif not os.path.lexists(job/('remaining-stage-'+remaining['correlationId']+'.release.json')): unknown('remaining_record_changed')
 for name in ('ready.json','cleaned.json','checkpoint-cleanup-stage-remove.json','checkpoint-cleanup-final-unroot.json'):
  if os.path.lexists(job/name): unknown('remaining_old_phase_changed')
 plan=validate_mount(json.loads(private(job/'mount-intent.json',8192)))
 if json.loads(private(job/'stage.json',8192))!={'phase':'before_root','target':plan['target'],'staging':plan['staging']} or hashlib.sha256(private(job/'ca.pem',65536)).hexdigest()!=expected['caSha256']: unknown('remaining_record_changed')
 if json.loads(private(job/'stage-owned.json',8192))!={key:plan[key] for key in ('zygote','staging','stagingIdentity')} or json.loads(private(job/'cleanup-intent.json',8192))!={'correlationId':correlation,'mount':plan}: unknown('remaining_record_changed')
 for phase in ('cleanup-reverse-https','cleanup-reverse-socks','cleanup-root','cleanup-unmount'):
  if json.loads(private(job/('checkpoint-'+phase+'.json'),1024))!={'phase':phase}: unknown('remaining_old_phase_changed')
 receipt=remaining.get('receipt')
 if isinstance(receipt,dict):
  if receipt.get('binding')!={key:remaining[key] for key in ('correlationId','originalIntentSha256')} or receipt.get('kind')!='android-endpoint-remaining-stage' or type(receipt.get('schema')) is not int or receipt['schema']!=1: unknown('remaining_receipt_changed')
  for name,pin in receipt['snapshot']['records'].items():
   path=lease if name=='lease' else root if name=='root' else job if name=='job' else pathlib.Path(expected['backupPath']) if name=='backup' else job/name
   if name in {'root','job'}:
    i=path.lstat(); current=[i.st_dev,i.st_ino,i.st_mode,i.st_uid]
   elif name=='lease' and not os.path.lexists(lease):current=pin
   else:current=remaining_pin(path,67108864 if name=='backup' else 65536 if name=='ca.pem' else 8192)
   if current!=pin: unknown('remaining_record_changed')
  own=job/('remaining-stage-'+remaining['correlationId']+'.json')
  if json.loads(private(own,65536))!=receipt or remaining_pin(own,65536)!=remaining.get('receiptPin'): unknown('remaining_receipt_changed')
  if not os.path.lexists(lease):
   terminal=job/('remaining-stage-'+remaining['correlationId']+'.terminal.json');release=json.loads(private(job/('remaining-stage-'+remaining['correlationId']+'.release.json'),8192))
   if release!={'schema':1,'terminalSha256':remaining_pin(terminal,65536)['sha256'],'receiptSha256':remaining['receiptPin']['sha256'],'lease':receipt['snapshot']['records']['lease']}: unknown('remaining_release_changed')
 children=[*root.glob('android-runtime-acceptance-*.json'),*root.glob('android-installer-*.json')]
 if len(children)>256: unknown('remaining_child_unknown')
 for child in children:
  activity=json.loads(private(child,8192))
  if not isinstance(activity,dict): unknown('remaining_child_unknown')
  if activity.get('parentCorrelationId')==correlation or activity.get('endpointCorrelationId')==correlation: unknown('remaining_child_present')
 if native:
  identity('0'); installed()
  if routes(): unknown('remaining_reverse_changed')
  if zygote_identity(plan['zygote']['pid'])!=plan['zygote']: unknown('remaining_native_changed')
 return plan
def remaining_native(plan,retired=False,uid='0'):
 identity(uid);installed()
 if routes(): unknown('remaining_reverse_changed')
 def probe(words):
  try:
   value=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
   if len(value.stdout)>1048576 or len(value.stderr)>4096: unknown('remaining_native_changed')
   return value.returncode,value.stdout.decode('utf-8','strict').strip(),value.stderr.decode('utf-8','strict').strip()
  except (OSError,subprocess.TimeoutExpired,UnicodeError): unknown('remaining_native_changed')
 def binary():
  i=probe(['stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su']);h=probe(['sha256sum','/system/xbin/su'])
  if i[0] or i[2] or not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',i[1]) or h[0] or h[2] or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',h[1]): unknown('remaining_principal_unverified')
  return i[1],h[1]
 pin=None
 if uid=='2000':
  pin=binary();help_result=probe(['/system/xbin/su','--help'])
  if help_result[0] or help_result[1] and help_result[2] or (help_result[1] or help_result[2])!=AOSP_HELP or binary()!=pin: unknown('remaining_principal_unverified')
  if probe(['/system/xbin/su','0,0','/system/bin/id','-u'])!=(0,'0','') or binary()!=pin: unknown('remaining_principal_unverified')
 def read(words,absent=None):
  if pin is not None and binary()!=pin: unknown('remaining_principal_unverified')
  result=probe((['/system/xbin/su','0,0'] if uid=='2000' else [])+words)
  if pin is not None and binary()!=pin: unknown('remaining_principal_unverified')
  if absent is not None:
   if result[0]!=1 or result[1] or result[2] not in {"stat: '"+absent+"': No such file or directory",'stat: '+absent+': No such file or directory'}: unknown('remaining_owned_path_present')
   return None
  if result[0] or result[2]: unknown('remaining_native_changed')
  return result[1]
 def generation():
  raw=read(['/system/bin/cat','/proc/'+plan['zygote']['pid']+'/stat'])
  try:ticks=int(raw.rsplit(')',1)[1].split()[19])
  except (ValueError,IndexError):unknown('remaining_native_changed')
  namespace=read(['/system/bin/readlink','/proc/'+plan['zygote']['pid']+'/ns/mnt'])
  if ticks!=plan['zygote']['startTicks'] or namespace!=plan['zygote']['namespace']:unknown('remaining_native_changed')
 generation();ns=['/system/bin/nsenter','-t',plan['zygote']['pid'],'-m','--'];fmt='%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F'
 stage=plan['staging'];ca=stage+'/'+expected['caStoreName']
 stage_pin=read(['/system/bin/stat','-c',fmt,stage],absent=stage if retired else None)
 ca_pin=read(['/system/bin/stat','-c',fmt,ca],absent=ca if retired else None)
 if not retired:
  fields=stage_pin.split(':');cfields=ca_pin.split(':')
  if len(fields)!=10 or fields[:3]!=['0','0','755'] or fields[-1]!='directory' or not all(x.isdecimal() for x in fields[:9]) or int(fields[5])<2 or ':'.join((fields[0],fields[2],fields[3],fields[4]))!=plan['stagingIdentity']:unknown('remaining_stage_changed')
  if len(cfields)!=10 or cfields[:3]!=['0','0','644'] or cfields[-1]!='regular file' or not all(x.isdecimal() for x in cfields[:9]) or cfields[5]!='1' or read(['/system/bin/sha256sum',ca]).split()!=[expected['caSha256'],ca]:unknown('remaining_stage_changed')
 target=read([*ns,'/system/bin/stat','-c','%d:%i:%h:%F',plan['target']]);outside=read(['/system/bin/stat','-c','%d:%i:%h:%F',plan['target']]);fields=target.split(':')
 if target!=outside or len(fields)!=4 or not all(x.isdecimal() for x in fields[:3]) or int(fields[2])<1 or fields[-1]!='directory':unknown('remaining_target_unlinked')
 raw=read(['/system/bin/cat','/proc/'+plan['zygote']['pid']+'/mountinfo']);layout=mount_layout(plan,raw)
 if layout['references'] or layout['owned'] or len(layout['targets'])>1:unknown('remaining_mount_referenced')
 target_ca=plan['target']+'/'+expected['caStoreName'];read([*ns,'/system/bin/stat','-c','%F',target_ca],absent=target_ca)
 generation();identity(uid);installed()
 return {'stageGeneration':stage_pin,'caGeneration':ca_pin,'targetIdentity':target,'mountinfoSha256':hashlib.sha256(raw.encode()).hexdigest()}
def remaining_public(uid):
 global observed_readmission_owner
 identity(uid);installed()
 if routes():unknown('remaining_reverse_changed')
 backup=private(pathlib.Path(expected['backupPath']))
 if hashlib.sha256(backup).hexdigest()!=expected['backupSha256']:unknown('backup_changed')
 rules=canonical_rules(json.loads(backup))
 def read(words):
  routing=words==('routing','show');value=json.loads(command(public_argv(words,routing),timeout=ROUTING_PROCESS_SECONDS if routing else 30,max_bytes=67108864 if routing else 65536,env=environment))
  if not isinstance(value,dict) or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or not isinstance(value.get('controllerId'),str) or not value['controllerId'] or type(value.get('configurationRevision')) is not int or value['configurationRevision']<0:unknown('remaining_public_changed')
  return value
 status=read(('status',));owner=status['controllerId'];rev=status['configurationRevision'];data=status.get('data')
 if observed_readmission_owner is not None and owner!=observed_readmission_owner:unknown('remaining_owner_changed')
 observed_readmission_owner=owner
 if not isinstance(data,dict) or data.get('runtimeRunning') is not False or data.get('runtimeObservation')!='stopped' or data.get('selectedLocationId') is not None or data.get('activeLocationId') is not None:unknown('runtime_not_off')
 operations=read(('operations','list'));routing=read(('routing','show'));closing=read(('status',))
 if any(x['controllerId']!=owner or x['configurationRevision']!=rev for x in (operations,routing,closing)) or closing.get('data')!=data:unknown('remaining_owner_changed')
 ops=operations.get('data',{}).get('operations')
 if not isinstance(ops,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in ops):unknown('history_unknown')
 if canonical_rules(routing.get('data',{}).get('routing'))!=rules:unknown('remaining_rules_changed')
 identity(uid);installed()
 return {'owner':owner,'revision':rev,'rulesSha256':rules}
def remaining_snapshot(retired=False,uid='0'):
 plan=remaining_records_guard();first=remaining_native(plan,retired,uid);public=remaining_public(uid);second=remaining_native(plan,retired,uid);remaining_records_guard()
 if first!=second:unknown('remaining_native_changed')
 records={name:remaining_pin(job/name,65536 if name=='ca.pem' else 8192) for name in remaining_names()};records['lease']=remaining_pin(lease,1024) if os.path.lexists(lease) else remaining['receipt']['snapshot']['records']['lease'];records['backup']=remaining_pin(pathlib.Path(expected['backupPath']),67108864)
 for name,path in (('root',root),('job',job)):
  i=path.lstat();records[name]=[i.st_dev,i.st_ino,i.st_mode,i.st_uid]
 return {'public':public,'native':second,'records':records}
def remaining_endpoint():
 lock_fd=lease_lock()
 try:
  plan=remaining_records_guard();rid=remaining['correlationId'];path=job/('remaining-stage-'+rid+'.json');attempt=job/('remaining-stage-'+rid+'.attempt.json');unroot=job/('remaining-stage-'+rid+'.unroot.json');terminal=job/('remaining-stage-'+rid+'.terminal.json')
  if action=='remaining-cleanup-admit':
   if any(os.path.lexists(x) for x in (path,attempt,unroot,terminal)):unknown('remaining_already_recorded')
   if os.path.lexists(job/'remaining-stage-admission.json'):unknown('remaining_already_recorded')
   record(job/'remaining-stage-admission.json',{key:remaining[key] for key in ('correlationId','originalIntentSha256')})
   first=remaining_snapshot();second=remaining_snapshot()
   if first!=second:unknown('remaining_observation_changed')
   receipt={'schema':1,'kind':'android-endpoint-remaining-stage','binding':dict(remaining),'snapshot':second}
   record(path,receipt);emit('ready',remaining=receipt,remainingReceiptPin=remaining_pin(path,65536))
  receipt=remaining.get('receipt')
  if receipt is None and action=='remaining-cleanup-status' and os.path.lexists(path):
   receipt=json.loads(private(path,65536));remaining['receipt']=receipt;remaining['receiptPin']=remaining_pin(path,65536)
  if not isinstance(receipt,dict) or json.loads(private(path,65536))!=receipt:unknown('remaining_receipt_changed')
  observed=receipt['snapshot'];observed_readmission_owner_local=observed['public']['owner']
  global observed_readmission_owner
  observed_readmission_owner=observed_readmission_owner_local
  if action=='remaining-cleanup-once':
   if any(os.path.lexists(x) for x in (attempt,unroot,terminal)):unknown('remaining_attempt_recorded')
   if remaining_snapshot()!=observed:unknown('remaining_receipt_stale')
   record(attempt,{'schema':1,'receiptSha256':hashlib.sha256(private(path,65536)).hexdigest()})
   attempt_pin=remaining_pin(attempt)
   if remaining_snapshot()!=observed or remaining_pin(attempt)!=attempt_pin:unknown('remaining_receipt_stale')
   remaining_records_guard();shell('rm','-r',plan['staging'])
   post=remaining_snapshot(True)
   if post['public']!=observed['public'] or post['native']['targetIdentity']!=observed['native']['targetIdentity'] or post['native']['mountinfoSha256']!=observed['native']['mountinfoSha256'] or remaining_pin(attempt)!=attempt_pin:unknown('remaining_post_changed')
   record(unroot,{'schema':1,'receiptSha256':hashlib.sha256(private(path,65536)).hexdigest(),'post':post})
   unroot_pin=remaining_pin(unroot)
   if remaining_snapshot(True)!=post or remaining_pin(attempt)!=attempt_pin or remaining_pin(unroot)!=unroot_pin:unknown('remaining_post_changed')
   remaining_records_guard();adb_call('unroot',timeout=30);adb_call('wait-for-device',timeout=30)
   final=remaining_snapshot(True,'2000')
   if final!=post or remaining_pin(attempt)!=attempt_pin or remaining_pin(unroot)!=unroot_pin:unknown('remaining_post_changed')
   record(terminal,{'schema':1,'receiptSha256':hashlib.sha256(private(path,65536)).hexdigest(),'attempt':attempt_pin,'unroot':unroot_pin,'post':final})
  if action=='remaining-cleanup-status' and not os.path.lexists(attempt):
   first=remaining_snapshot();second=remaining_snapshot()
   if first!=second or first!=observed:unknown('remaining_receipt_stale')
   emit('ready',remaining=receipt,remainingReceiptPin=remaining_pin(path,65536))
  if action not in {'remaining-cleanup-once','remaining-cleanup-status','remaining-cleanup-collect'}:unknown('remaining_binding_invalid')
  complete=json.loads(private(terminal,65536));terminal_pin=remaining_pin(terminal,65536)
  if complete.get('schema')!=1 or complete.get('receiptSha256')!=hashlib.sha256(private(path,65536)).hexdigest() or complete.get('attempt')!=remaining_pin(attempt) or complete.get('unroot')!=remaining_pin(unroot):unknown('remaining_terminal_changed')
  first=remaining_snapshot(True,'2000');second=remaining_snapshot(True,'2000')
  if first!=second or second!=complete.get('post') or remaining_pin(terminal,65536)!=terminal_pin:unknown('remaining_post_changed')
  if action=='remaining-cleanup-collect':
   release=job/('remaining-stage-'+rid+'.release.json');payload={'schema':1,'terminalSha256':terminal_pin['sha256'],'receiptSha256':remaining['receiptPin']['sha256'],'lease':observed['records']['lease']}
   if not os.path.lexists(release):record(release,payload)
   elif json.loads(private(release,8192))!=payload:unknown('remaining_release_changed')
   release_pin=remaining_pin(release)
   if remaining_snapshot(True,'2000')!=second or remaining_pin(terminal,65536)!=terminal_pin or remaining_pin(release)!=release_pin:unknown('remaining_post_changed')
   if os.path.lexists(lease):
    if remaining_pin(lease,1024)!=observed['records']['lease']:unknown('remaining_record_changed')
    remaining_records_guard();lease.unlink()
   if os.path.lexists(lease):unknown('remaining_release_changed')
  emit('cleaned','remaining_stage_retired',remainingCorrelationId=rid,owner=second['public']['owner'],revision=second['public']['revision'],terminalSha256=terminal_pin['sha256'],leaseReleased=not os.path.lexists(lease),originalOutcome='unknown')
 finally:release_lock(lock_fd)
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown('remote_root_unsafe')
if action=='start':
 try: payload=json.load(sys.stdin); ca=base64.b64decode(payload['ca'],validate=True)
 except (ValueError,KeyError,UnicodeError): unknown('ca_payload_invalid')
 if not 0<len(ca)<=65536 or hashlib.sha256(ca).hexdigest()!=expected['caSha256']: unknown('ca_payload_changed')
 # A durable job and intent precede the exclusive lease and every guest command.
 try:
  job.mkdir(mode=0o700)
  record(job/'intent.json',expected)
  fd=os.open(job/'ca.pem',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as output: output.write(ca); output.flush(); os.fsync(output.fileno())
  guard_fd=lease_lock()
  try: record(lease,{'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']})
  finally: release_lock(guard_fd)
 except (OSError,ValueError): unknown('submission_uncertain')
 leaf=host_fixture_leaf()
 leaf_fd=os.open(job/'leaf.pem',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(leaf_fd,'wb') as output: output.write(leaf); output.flush(); os.fsync(output.fileno())
 command(['openssl','verify','-CAfile',str(job/'ca.pem'),str(job/'leaf.pem')],max_bytes=2048)
 guard()
 if routes(): unknown('foreign_reverse_present')
 if shell('settings','get','global','http_proxy') not in ('null',':0'): unknown('proxy_not_disconnected')
 target='/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts'
 staging='/data/local/tmp/vpn-control-endpoint-'+correlation
 record(job/'stage.json',{'phase':'before_root','target':target,'staging':staging})
 if routes(): unknown('foreign_reverse_before_root')
 checkpoint('root')
 adb_call('root',timeout=30); adb_call('wait-for-device',timeout=30); identity('0')
 zygote=shell('pidof','zygote64').split()
 if len(zygote)!=1 or not zygote[0].isdecimal() or int(zygote[0])<1: unknown('zygote_identity')
 generation=zygote_identity(zygote[0])
 mount_target_preflight({'zygote':generation,'target':target})
 label=shell('ls','-Zd',target).split()[0]
 if not re.fullmatch(r'u:object_r:[a-z0-9_]+:s[0-9]+',label): unknown('ca_store_label')
 if shell('stat','-c','%a',target)!='755': unknown('ca_store_mode')
 checkpoint('stage')
 shell('mkdir','-m','0755',staging)
 staged_inode=staging_identity(staging)
 record(job/'stage-owned.json',{'staging':staging,'stagingIdentity':staged_inode,'zygote':generation})
 shell('cp','-a',target+'/.',staging+'/')
 children=shell('find',staging,'-mindepth','1','-maxdepth','1','-print').splitlines()
 regular=shell('find',staging,'-mindepth','1','-maxdepth','1','-type','f','-print').splitlines()
 if not children or len(children)!=len(set(children)) or set(children)!=set(regular) or any(not re.fullmatch(re.escape(staging)+r'/[A-Za-z0-9._-]+',x) for x in children): unknown('ca_store_shape')
 staged=staging+'/'+expected['caStoreName']
 if staged in children: unknown('ca_entry_exists')
 adb_call('push',str(job/'ca.pem'),staged,timeout=30,max_bytes=4096)
 shell('chmod','0644',staged)
 for child in [staging,*children,staged]: shell('chcon',label,child)
 if shell('stat','-c','%a',staged)!='644' or shell('ls','-Zd',staged).split()[0]!=label or shell('sha256sum',staged).split()[0]!=expected['caSha256']: unknown('ca_stage_changed')
 mount_plan={'zygote':generation,'target':target,'staging':staging,'stagingIdentity':staged_inode}
 record(job/'mount-intent.json',mount_plan)
 checkpoint('mount')
 mount_exact(mount_plan)
 if shell('nsenter','-t',zygote[0],'-m','--','sha256sum',target+'/'+expected['caStoreName']).split()[0]!=expected['caSha256']: unknown('ca_mount_unknown')
 checkpoint('unroot')
 adb_call('unroot',timeout=30); adb_call('wait-for-device',timeout=30)
 guard()
 if routes(): unknown('reverse_changed_after_unroot')
 record(job/'https-reverse-intent.json',{'devicePort':18080,'hostPort':expected['httpsHostPort']})
 checkpoint('https-reverse')
 adb_call('reverse','tcp:18080','tcp:'+str(expected['httpsHostPort']))
 if routes().get(18080)!=expected['httpsHostPort']: unknown('https_reverse_unknown')
 record(job/'socks-reverse-intent.json',{'devicePort':18081,'hostPort':expected['socksHostPort']})
 checkpoint('socks-reverse')
 adb_call('reverse','tcp:18081','tcp:'+str(expected['socksHostPort']))
 fixture_routes(); guard()
 mount_observed(mount_plan)
 record(job/'ready.json',{'correlationId':correlation,'caSha256':expected['caSha256'],'leafSha256':expected['leafSha256'],'mount':mount_plan,'httpsHostPort':expected['httpsHostPort'],'socksHostPort':expected['socksHostPort']})
 emit('ready',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[18080,18081])
try:
 item=job.lstat()
 if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.getuid() or stat.S_IMODE(item.st_mode)!=0o700: unknown('job_unsafe')
 remote_intent_raw=private(job/'intent.json',8192)
 if json.loads(remote_intent_raw)!=stored_expected: unknown('intent_changed')
 if remaining is not None: remaining_endpoint()
 if action in {'recovery-readmit','recovery-unmount','recovery-status'}: recover_endpoint()
 if action=='mount-failure-diagnostic': mount_failure_diagnostic()
 if action=='cleanup-readmitted-status': readmitted_terminal_status()
 if action=='cleanup-mount-diagnostic': readmission_mount_diagnostic()
 if action=='cleanup-readmission-status': readmission_status()
 if action=='cleanup-readmit':
  if exact_lease_present() is None: unknown('lease_changed')
  readmit_cleanup()
 if readmission is not None:
  if action!='cleanup' or original_revision is not None: unknown('readmission_action_invalid')
  validate_cleanup_readmission()
  cleanup_readmitted_effects()
 if (job/'cleaned.json').exists():
  cleaned_terminal()
 if json.loads(private(lease,1024))!={'owner':'android-endpoint','correlationId':correlation,'device':device,'host':expected['host']}: unknown('lease_changed')
 if not (job/'ready.json').exists():
  phase='mount-intent' if (job/'mount-intent.json').exists() else 'before-root' if (job/'stage.json').exists() else 'journaled'
  if action=='cleanup' and (job/'mount-intent.json').exists():
   cleanup_effects(json.loads(private(job/'mount-intent.json',8192)))
  if action=='cleanup' and (job/'stage.json').exists(): cleanup_before_mount()
  diagnostic=reverse_inventory_diagnostic() if action=='status' else None
  emit('partial','setup_incomplete',phase=phase,reverseInventory=diagnostic,partialDiagnostic=partial_diagnostic() if action=='status' else None)
 ready=json.loads(private(job/'ready.json',8192))
 mount=ready.get('mount')
 if (ready.get('correlationId')!=correlation or ready.get('caSha256')!=expected['caSha256'] or ready.get('leafSha256')!=expected['leafSha256'] or ready.get('httpsHostPort')!=expected['httpsHostPort'] or ready.get('socksHostPort')!=expected['socksHostPort'] or not isinstance(mount,dict) or mount.get('target')!=('/apex/com.android.conscrypt/cacerts' if api=='35' else '/system/etc/security/cacerts') or mount.get('staging')!='/data/local/tmp/vpn-control-endpoint-'+correlation or mount!=json.loads(private(job/'mount-intent.json',8192))): unknown('ready_changed')
 guard(); fixture_routes()
 if action=='status': host_fixture_leaf(); mount_observed(mount)
 if action=='status': emit('ready',None,device={'uid':'2000','api':int(api),'avd':avd},packageSha256=expected['packageSha256'],owner=expected['owner'],revision=expected['revision'],caSha256=expected['caSha256'],reversePorts=[18080,18081])
 if action!='cleanup': unknown('action_invalid')
 cleanup_effects(mount)
except (OSError,ValueError,KeyError,TypeError,IndexError): unknown('state_or_cleanup_uncertain')
'''


def _endpoint_python_command(program: str, *arguments: str) -> tuple[str, ...]:
    """Bound and authenticate this endpoint's source without consuming payload stdin."""
    raw = program.encode('utf-8')
    if not 0 < len(raw) <= 262144:
        raise ValueError('endpoint_source_size')
    encoded = base64.b64encode(zlib.compress(raw, 9)).decode('ascii')
    wrapper = ("import base64,hashlib,zlib\n" +
               "p=base64.b64decode(" + repr(encoded) + ",validate=True)\n" +
               "d=zlib.decompressobj()\n" +
               "s=d.decompress(p," + str(len(raw) + 1) + ")\n" +
               "if not d.eof or d.unused_data or d.unconsumed_tail or len(s)!=" + str(len(raw)) +
               " or hashlib.sha256(s).hexdigest()!=" + repr(hashlib.sha256(raw).hexdigest()) +
               ": raise ValueError('endpoint_source_integrity')\n" +
               "exec(compile(s.decode('utf-8'),'<android-endpoint>','exec'))")
    command = ('python3', '-c', 'exec(' + repr(wrapper) + ')', *arguments)
    if any(not isinstance(part, str) or len(part.encode('utf-8')) >= 65536 for part in command):
        raise ValueError('endpoint_argument_size')
    return command


def _bounded_endpoint_transport(value: Any) -> dict[str, Any]:
    fields = {'phase': {'local-build', 'local-spawn', 'runner', 'remote-result'},
              'outcome': {'argument-limit', 'source-limit', 'unavailable', 'timeout', 'output-limit', 'io-error', 'nonzero', 'invalid-result'},
              'stdout': {'unavailable', 'empty', 'not-json', 'invalid-json'}}
    if (not isinstance(value, dict) or set(value) != {*fields, 'exit'} or
            any(not isinstance(value.get(key), str) or value[key] not in allowed for key, allowed in fields.items()) or
            value['exit'] is not None and (type(value['exit']) is not int or not -255 <= value['exit'] <= 255)):
        return {}
    return {'transportDiagnostic': value}


def _remote(root: Path, intent: dict[str, Any], action: str, payload: bytes | None = None) -> dict[str, Any]:
    host = intent["host"]
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android endpoint requires configured private-key host")
    remote_root = config.hosts[host].fixture_transfer_root
    if remote_root is None or str(remote_root) != intent["remoteRoot"]:
        raise ValueError("Android endpoint remote root changed")
    diagnostic = {'phase': 'local-build', 'outcome': 'unavailable', 'stdout': 'unavailable', 'exit': None}
    try:
        command = _endpoint_python_command(android_observation._canonical_cli_environment_source() + _REMOTE,
            action, str(remote_root), intent['device'], intent['correlationId'],
            json.dumps(intent['remote'], sort_keys=True, separators=(',', ':')))
        argv = ssh_transport.build_ssh_argv(config, host, 60, command=command)
        if any(len(part.encode('utf-8')) >= 65536 for part in argv):
            raise ValueError('endpoint_argument_size')
        diagnostic['phase'] = 'runner'
        if action in _REMAINING_COMMAND_BOUNDS and isinstance(intent['remote'].get('cleanupRemaining'),dict):
            if payload is not None:raise ValueError('remaining_payload_forbidden')
            code,output=android_observation._run_probe(argv,_readmission_transport_seconds(action,intent['remote']))
        else:
            code, output = ssh_transfer._bounded_run(argv, payload, _readmission_transport_seconds(action, intent['remote']))
        diagnostic = {'phase': 'remote-result', 'outcome': 'nonzero' if code else 'invalid-result',
                      'stdout': 'empty' if not output else 'not-json', 'exit': code if type(code) is int and -255 <= code <= 255 else None}
        if code == 0:
            value = json.loads(output.decode('utf-8', 'strict'))
            diagnostic['stdout'] = 'invalid-json'
            if isinstance(value, dict) and value.get('correlationId') == intent['correlationId'] and value.get('state') in {'ready', 'cleaned', 'partial', 'unknown'}:
                return value
    except (OSError, ValueError, UnicodeError, RuntimeError, ssh_transfer.SshTransferError) as error:
        underlying = error if isinstance(error, OSError) else error.__cause__
        if isinstance(underlying, OSError) and underlying.errno == errno.E2BIG:
            diagnostic.update(phase='local-spawn', outcome='argument-limit')
        elif str(error) in {'endpoint_source_size', 'endpoint_argument_size'}:
            diagnostic.update(phase='local-build', outcome='source-limit' if str(error) == 'endpoint_source_size' else 'argument-limit')
        elif action in _REMAINING_COMMAND_BOUNDS and isinstance(error,(RuntimeError,TimeoutError)):
            diagnostic.update(phase='runner',outcome='timeout' if isinstance(error,TimeoutError) else 'output-limit' if str(error)=='oversized_output' else 'unavailable')
        elif isinstance(error, ssh_transfer.SshTransferError):
            diagnostic.update(phase='runner', outcome={'timeout': 'timeout', 'oversized_remote_output': 'output-limit', 'ssh_io_error': 'io-error'}.get(str(error), 'unavailable'))
    return {'state': 'unknown', 'reason': 'transport_or_receipt_unknown', 'correlationId': intent['correlationId'],
            **_bounded_endpoint_transport(diagnostic)}



def _bound_result(intent: dict[str, Any], value: dict[str, Any], action: str) -> dict[str, Any]:
    """Never turn a merely named terminal response into device admission."""
    state = value.get("state")
    if state in {"unknown", "partial"}:
        failure = value.get("mountFailure")
        exact_failure = (isinstance(failure, dict) and set(failure) in ({"phase", "exit", "errorClass"}, {"phase", "exit", "errorClass", "errorOrigin"}) and
                         all(isinstance(failure.get(key), str) for key in failure) and failure.get("phase") == "mount" and
                         failure.get("exit") in {"nonzero", "unavailable"} and
                         failure.get("errorClass") in {"not-found", "permission", "no-process", "invalid", "other"} and
                         ("errorOrigin" not in failure or failure.get("errorOrigin") in {"nsenter-launch", "mount-path-pair", "fstab", "proc-filesystems", "other", "unknown"}))
        extra: dict[str, Any] = {"phase": value.get("phase")} if state == "partial" else {}
        extra.update(_bounded_endpoint_transport(value.get('transportDiagnostic')))
        if state == "unknown" and value.get("reason") == "mount_command_failed" and value.get("phase") == "mount" and exact_failure:
            extra.update({"phase": "mount", "mountFailure": failure})
        diagnostic = value.get("reverseInventory")
        if state == "partial" and isinstance(diagnostic, dict):
            records = diagnostic.get("records")
            if (diagnostic.get("state") == "observed" and type(diagnostic.get("recordCount")) is int and
                    0 <= diagnostic["recordCount"] <= 16 and isinstance(records, list) and
                    len(records) == diagnostic["recordCount"] and all(
                        isinstance(record, dict) and set(record) == {"form", "ports", "portsValid"} and
                        record.get("form") in {"two-endpoint", "three-host", "three-configured-serial", "three-usb-ffs", "three-adb-host-transport", "three-other", "invalid"} and
                        isinstance(record.get("ports"), list) and len(record["ports"]) in (0, 2) and
                        all(type(port) is int and 1 <= port <= 65535 for port in record["ports"]) and
                        type(record.get("portsValid")) is bool and
                        (record["portsValid"] == (len(record["ports"]) == 2)) for record in records)):
                extra["reverseInventory"] = diagnostic
        partial = value.get("partialDiagnostic")
        durable_failure = partial.get("mountFailure") if isinstance(partial, dict) else None
        if (state == "partial" and isinstance(durable_failure, dict) and set(durable_failure) in ({"phase", "exit", "errorClass"}, {"phase", "exit", "errorClass", "errorOrigin"}) and
                all(isinstance(durable_failure.get(key), str) for key in durable_failure) and durable_failure.get("phase") == "mount" and
                durable_failure.get("exit") in {"nonzero", "unavailable"} and durable_failure.get("errorClass") in {"not-found", "permission", "no-process", "invalid", "other"} and
                ("errorOrigin" not in durable_failure or durable_failure.get("errorOrigin") in {"nsenter-launch", "mount-path-pair", "fstab", "proc-filesystems", "other", "unknown"})): extra["mountFailure"] = durable_failure
        mount_diagnostic = partial.get("mountDiagnostic") if isinstance(partial, dict) else None
        if (state == "partial" and isinstance(mount_diagnostic, dict) and
                set(mount_diagnostic) == {"state", "generation", "namespaceUid", "target", "staging", "exit", "errorClass", "nsenterBinary", "nsenterId", "absoluteId", "failurePhase", "outsideBind", "insideBind", "relativeMount", "targetMountMembership", "targetMountMembershipReason", "targetMountMembershipBytes", "targetMountMembershipEntries", "targetMountFdinfoFormat", "targetMountFdinfoKeyCount", "targetMountFdinfoMntIdCount", "stagingMountMembership", "outsideCapSysAdmin", "insideCapSysAdmin", "selinux", "domain"} and
                mount_diagnostic.get("state") in {"unobserved", "unknown", "observed", "failed"} and
                mount_diagnostic.get("generation") in {"stable", "reused", "unknown"} and
                mount_diagnostic.get("namespaceUid") in {"root", "shell", "other", "unknown"} and
                mount_diagnostic.get("target") in {"exact-directory", "absent", "other", "unknown"} and
                mount_diagnostic.get("staging") in {"exact", "absent", "changed", "unknown"} and
                mount_diagnostic.get("exit") in {"ok", "nonzero", "unavailable"} and
                mount_diagnostic.get("errorClass") in {"none", "not-found", "permission", "no-process", "invalid", "other"} and
                mount_diagnostic.get("nsenterBinary") in {"available", "missing", "unknown"} and
                mount_diagnostic.get("nsenterId") in {"ok", "nonzero", "unavailable"} and
                mount_diagnostic.get("absoluteId") in {"ok", "nonzero", "unavailable"} and
                mount_diagnostic.get("failurePhase") in {"none", "nsenter-launch", "namespace-open", "exec-target-missing", "target-stat", "staging-stat", "unknown"} and mount_diagnostic.get("outsideBind") in {"supported","unsupported","unavailable","unknown"} and mount_diagnostic.get("insideBind") in {"supported","unsupported","unavailable","unknown"} and isinstance(mount_diagnostic.get("targetMountMembership"), str) and mount_diagnostic.get("targetMountMembership") in {"member","foreign","unknown"} and isinstance(mount_diagnostic.get("targetMountMembershipReason"), str) and mount_diagnostic.get("targetMountMembershipReason") in {"ok","command-nonzero","command-unavailable","output-size","encoding","delimiter","malformed-fdinfo","malformed-mount-ids","capped-mount-ids"} and type(mount_diagnostic.get("targetMountMembershipBytes")) is int and 0 <= mount_diagnostic["targetMountMembershipBytes"] <= 4097 and type(mount_diagnostic.get("targetMountMembershipEntries")) is int and 0 <= mount_diagnostic["targetMountMembershipEntries"] <= 257 and mount_diagnostic.get("targetMountFdinfoFormat") in {"valid","missing","duplicate","invalid","unknown"} and type(mount_diagnostic.get("targetMountFdinfoKeyCount")) is int and 0 <= mount_diagnostic["targetMountFdinfoKeyCount"] <= 17 and type(mount_diagnostic.get("targetMountFdinfoMntIdCount")) is int and 0 <= mount_diagnostic["targetMountFdinfoMntIdCount"] <= 17 and isinstance(mount_diagnostic.get("stagingMountMembership"), str) and mount_diagnostic.get("stagingMountMembership") in {"member","foreign","unknown"} and mount_diagnostic.get("relativeMount") in {"available","missing","unknown"} and mount_diagnostic.get("outsideCapSysAdmin") in {"present","absent","unknown"} and mount_diagnostic.get("insideCapSysAdmin") in {"present","absent","unknown"} and mount_diagnostic.get("selinux") in {"enforcing","permissive","disabled","unknown"} and mount_diagnostic.get("domain") in {"su","shell","other","unknown"}):
            extra["mountDiagnostic"] = mount_diagnostic
        partial_allowed = {
            "uid": {"root", "shell", "other", "unknown"},
            "stage": {"before-root", "absent", "invalid"},
            "mountPlan": {"recorded", "absent", "invalid"},
            "zygoteGeneration": {"recorded", "absent", "invalid"},
            "stagingIdentity": {"recorded", "absent", "invalid"},
            "mount": {"unobserved", "present", "absent", "unknown"},
            "ca": {"present", "absent", "invalid"},
            "commandPhase": {"none", "invalid", "root", "stage", "mount", "unroot", "https-reverse", "socks-reverse",
                             "cleanup-unroot", "cleanup-reverse-https", "cleanup-reverse-socks", "cleanup-root",
                             "cleanup-unmount", "cleanup-stage-remove", "cleanup-final-unroot"},
        }
        partial_core = ({key: value for key, value in partial.items() if key not in {"mountDiagnostic", "mountFailure"}}
                        if isinstance(partial, dict) else None)
        if (state == "partial" and isinstance(partial_core, dict) and set(partial_core) == set(partial_allowed) and
                all(isinstance(partial_core.get(key), str) and partial_core[key] in allowed
                    for key, allowed in partial_allowed.items())):
            extra["partialDiagnostic"] = partial_core
        return _response(state, intent["correlationId"], value.get("reason") or "native_outcome_unknown", **extra)
    remote = intent["remote"]
    expected_state = state if action == "status" and state in {"ready", "cleaned"} else "cleaned" if action == "cleanup" else "ready"
    ports = [] if expected_state == "cleaned" else [18080, 18081]
    if (state != expected_state or value.get("correlationId") != intent["correlationId"] or
            value.get("device") != {"uid": "2000", "api": remote["api"], "avd": remote["avd"]} or
            value.get("packageSha256") != remote["packageSha256"] or
            value.get("owner") != remote["owner"] or value.get("revision") != remote["revision"] or
            value.get("caSha256") != remote["caSha256"] or value.get("reversePorts") != ports):
        return _response("unknown", intent["correlationId"], "terminal_binding_invalid")
    return _response(state, intent["correlationId"], result=value)


def start(root: Path | str, host: str, device: str, correlation_id: str, campaign_id: str,
          source_sha: str, target_artifact_id: str, ca_artifact_id: str,
          backup_correlation_id: str, expected_owner: str, expected_revision: int,
          expected_backup_sha256: str, *, source_root: Path | str | None = None) -> dict[str, Any]:
    """Submit one native setup after exact source, campaign, package and OFF admission."""
    root = Path(root).resolve()
    if (not all(isinstance(x, str) and _UUID.fullmatch(x) for x in (correlation_id, campaign_id, backup_correlation_id)) or
            not all(isinstance(x, str) and _ALIAS.fullmatch(x) for x in (host, device)) or
            not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or
            not isinstance(expected_owner, str) or not expected_owner or
            type(expected_revision) is not int or expected_revision < 0 or
            not isinstance(expected_backup_sha256, str) or not _SHA.fullmatch(expected_backup_sha256)):
        raise ValueError("Android endpoint identity is invalid")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or device not in config.hosts[host].android_devices or config.hosts[host].fixture_transfer_root is None:
        raise ValueError("Android endpoint host/device is not configured")
    if ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android endpoint requires private-key SSH")
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    source_checkout = android_native_fixture._source_root(root, source_root)
    requirements = android_native_fixture.prepare_requirements(root, source_sha, source_root=source_checkout)
    target = android_native_fixture.verify_target(root, requirements, target_artifact_id,
                                                  source_root=source_checkout)
    package_hash = target["targetSha256"]
    campaign = android_native_fixture_lifecycle.status(root, campaign_id)
    campaign_intent = android_native_fixture_lifecycle._read_plan(
        android_native_fixture_lifecycle._directory(root) / (campaign_id + ".json"))
    if (campaign.get("state") != "running" or campaign_intent.get("host") != host or
            campaign_intent.get("device") != device or campaign_intent.get("sourceSha") != source_sha or
            campaign.get("endpoint", {}).get("hostHttpsPort") is None or
            campaign.get("endpoint", {}).get("hostSocksPort") is None):
        raise ValueError("Android endpoint host fixture is not admitted")
    opening = android_admission_readback.async_collect(root, backup_correlation_id)
    result = opening.get("result", {})
    guard, backup = result.get("guard", {}), result.get("backup", {})
    if (opening.get("state") != "complete" or opening.get("ok") is not True or
            result.get("package", {}).get("baseSha256") != package_hash or
            result.get("device") != {"uid": "2000", "api": profile["api"], "avd": profile["expectedAvd"],
                                     "abi": "x86_64"} or
            guard.get("controllerId") != expected_owner or guard.get("configurationRevision") != expected_revision or
            backup.get("sha256") != expected_backup_sha256):
        raise ValueError("Android endpoint opening readback is not admitted")
    live = android_admission_readback.readback_status(root, host, device, backup_correlation_id)
    observed = live.get("result", {})
    if (live.get("ok") is not True or observed.get("deviceIdentity") is not True or
            observed.get("stage") != "backup_present" or observed.get("controllerId") != expected_owner or
            observed.get("configurationRevision") != expected_revision or
            observed.get("backup", {}).get("sha256") != expected_backup_sha256):
        raise ValueError("Android endpoint live owner or backup changed")
    ca = _stable_ca(root, ca_artifact_id, source_sha)
    if not ca.startswith(b"-----BEGIN CERTIFICATE-----") or b"-----END CERTIFICATE-----" not in ca:
        raise ValueError("Android endpoint CA artifact is not PEM")
    endpoint = campaign["endpoint"]
    ports = (endpoint["hostHttpsPort"], endpoint["hostSocksPort"])
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Android endpoint host ports are invalid")
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        cert_path = Path(temporary) / "ca.pem"
        cert_path.write_bytes(ca)
        subject = subprocess.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-subject_hash_old"],
                                 check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    if not re.fullmatch(r"[0-9a-fA-F]{8}", subject):
        raise ValueError("Android endpoint CA subject hash is invalid")
    remote = {"host": host, "adb": profile["adb"], "cli": profile["cli"], "serial": profile["serial"],
              "avd": profile["expectedAvd"], "api": profile["api"], "packageSha256": package_hash,
              "owner": expected_owner, "revision": expected_revision, "backupPath": backup["path"],
              "backupSha256": expected_backup_sha256, "campaignId": campaign_id,
              "leafSha256": campaign_intent["certificateSha256"], "caSha256": hashlib.sha256(ca).hexdigest(),
              "caStoreName": subject.lower() + ".0", "httpsHostPort": ports[0], "socksHostPort": ports[1]}
    intent = {"host": host, "device": device, "correlationId": correlation_id,
              "sourceSha": source_sha, "targetArtifactId": target_artifact_id,
              "caArtifactId": ca_artifact_id, "backupCorrelationId": backup_correlation_id,
              "remoteRoot": str(config.hosts[host].fixture_transfer_root), "remote": remote}
    path = _intent_path(root, correlation_id)
    android_native_fixture.write_private_plan(path, intent)
    with _shared_device_lease(root, host, device) as lease:
        android_native_fixture.write_private_plan(lease, {"owner": "android-endpoint", "correlationId": correlation_id,
                                                  "host": host, "device": device})
    payload = json.dumps({"ca": base64.b64encode(ca).decode("ascii")}, separators=(",", ":")).encode()
    value = _remote(root, intent, "start", payload)
    return _bound_result(intent, value, "start")


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Read only the exact durable job; unknown results never authorize replay."""
    root = Path(root).resolve()
    intent = _status_intent(root, correlation_id)
    if intent is None:
        return _response("unknown", correlation_id, "missing_local_intent")
    value = _remote(root, intent, "status")
    bounded = _bound_result(intent, value, "status")
    if bounded["state"] != "ready":
        return bounded
    campaign = android_native_fixture_lifecycle.status(root, intent["remote"]["campaignId"])
    endpoint = campaign.get("endpoint") if isinstance(campaign, dict) else None
    if (campaign.get("state") != "running" or not isinstance(endpoint, dict) or
            endpoint.get("hostHttpsPort") != intent["remote"]["httpsHostPort"] or
            endpoint.get("hostSocksPort") != intent["remote"]["socksHostPort"]):
        return _response("unknown", correlation_id, "host_fixture_changed")
    return bounded


def cleanup(root: Path | str, correlation_id: str) -> dict[str, Any]:
    """Remove only this campaign's two reverses and verified temporary CA mount."""
    root = Path(root).resolve()
    intent = _read_intent(root, correlation_id)
    # The same lock is held while a runtime child publishes its local parent
    # binding, so a cleanup cannot pass admission between child claim and effect.
    with _shared_device_lease(root, intent["host"], intent["device"]) as lease:
        blocked, closing_revision = _runtime_child_cleanup_guard(root, intent)
        if blocked is not None:
            return _response("unknown", correlation_id, blocked)
        dispatch_intent = intent
        if closing_revision is not None:
            dispatch_remote = dict(intent["remote"])
            dispatch_remote["cleanupOriginalRevision"] = dispatch_remote["revision"]
            dispatch_remote["revision"] = closing_revision
            dispatch_intent = {**intent, "remote": dispatch_remote}
        value = _remote(root, dispatch_intent, "cleanup")
        bounded = _bound_result(dispatch_intent, value, "cleanup")
        if bounded["state"] != "cleaned":
            return bounded
        before = lease.lstat()
        if android_native_fixture_lifecycle._read_plan(lease) != {"owner": "android-endpoint", "correlationId": correlation_id,
                                                               "host": intent["host"], "device": intent["device"]}:
            return _response("unknown", correlation_id, "local_lease_changed")
        after = lease.lstat()
        if (not stat.S_ISREG(before.st_mode) or
                (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size)):
            return _response("unknown", correlation_id, "local_lease_replaced")
        lease.unlink()
        return bounded


def _private_snapshot(path: Path) -> tuple[dict[str, Any], str]:
    """Pin exact private bytes, including same-inode changes and path replacement."""
    android_native_fixture_lifecycle._read_plan(path)  # ancestry, owner and mode checks
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or not 0 < before.st_size <= 8192):
            raise ValueError('Android cleanup private record is unsafe')
        raw = os.read(descriptor, 8193)
        after = os.fstat(descriptor); named = path.lstat()
        def generation(info):
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        if generation(before) != generation(after) or generation(after) != generation(named) or len(raw) != before.st_size:
            raise ValueError('Android cleanup private record changed')
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Android cleanup private record is invalid')
    return value, hashlib.sha256(raw).hexdigest()


def _readmission_path(root: Path, correlation_id: str, suffix: str = '.json') -> Path:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError('Android cleanup readmission requires a canonical UUID')
    return _local_directory(root) / ('cleanup-readmission-' + correlation_id + suffix)


def _readmission_local_guard(root: Path, intent: dict[str, Any], lease: Path, *, terminal: bool = False) -> None:
    remote = intent['remote']
    if remote.get('api') != 29:
        raise ValueError('Android cleanup readmission is limited to API29')
    if _runtime_parent_correlation(root, intent['correlationId']) is not None:
        raise ValueError('Android cleanup readmission has a runtime child')
    if terminal:
        if os.path.lexists(lease):
            raise ValueError('Android cleanup readmission terminal lease present')
    elif android_native_fixture_lifecycle._read_plan(lease) != {
            'owner': 'android-endpoint', 'correlationId': intent['correlationId'],
            'host': intent['host'], 'device': intent['device']}:
        raise ValueError('Android cleanup readmission local lease changed')
    config = ssh_transport.load_config(root)
    profile = android_observation._profile(config.hosts[intent['host']].android_devices[intent['device']])
    if any(profile.get(key) != remote.get(field) for key, field in (
            ('adb', 'adb'), ('cli', 'cli'), ('serial', 'serial'), ('api', 'api'), ('expectedAvd', 'avd'))):
        raise ValueError('Android cleanup readmission configured device changed')


def cleanup_readmission(root: Path | str, correlation_id: str,
                        readmission_correlation_id: str) -> dict[str, Any]:
    """Observe a replacement owner twice and retain immutable cleanup-only proof."""
    root = Path(root).resolve()
    path = _readmission_path(root, readmission_correlation_id)
    original_path = _intent_path(root, correlation_id)
    intent, digest = _private_snapshot(original_path)
    if intent.get('correlationId') != correlation_id or readmission_correlation_id == correlation_id:
        raise ValueError('Android cleanup readmission correlations are invalid')
    binding = {'correlationId': readmission_correlation_id, 'originalIntentSha256': digest}
    with _shared_device_lease(root, intent['host'], intent['device']) as lease:
        _readmission_local_guard(root, intent, lease)
        request = {'schema': 1, 'endpointCorrelationId': correlation_id, **binding}
        android_native_fixture.write_private_plan(_readmission_path(root, readmission_correlation_id, '.request.json'), request)
        dispatch = {**intent, 'remote': {**intent['remote'], 'cleanupReadmission': binding}}
        value = _remote(root, dispatch, 'cleanup-readmit')
        receipt = value.get('readmission')
        snapshot = receipt.get('snapshot') if isinstance(receipt, dict) else None
        if (value.get('state') != 'ready' or value.get('correlationId') != correlation_id or
                not isinstance(receipt, dict) or set(receipt) != {'schema', 'kind', 'endpointCorrelationId',
                    'readmissionCorrelationId', 'originalIntentSha256', 'remoteIntentSha256', 'originalOwner',
                    'originalRevision', 'snapshot'} or receipt.get('schema') != 1 or
                receipt.get('kind') != 'android-endpoint-cleanup-readmission' or
                receipt.get('endpointCorrelationId') != correlation_id or
                receipt.get('readmissionCorrelationId') != readmission_correlation_id or
                receipt.get('originalIntentSha256') != digest or
                receipt.get('originalOwner') != intent['remote']['owner'] or
                receipt.get('originalRevision') != intent['remote']['revision'] or
                not isinstance(receipt.get('remoteIntentSha256'), str) or not _SHA.fullmatch(receipt['remoteIntentSha256']) or
                not isinstance(snapshot, dict) or not isinstance(snapshot.get('owner'), str) or not snapshot['owner'] or
                type(snapshot.get('revision')) is not int or snapshot['revision'] < 0 or
                snapshot.get('uid') not in {'0', '2000'} or snapshot.get('api') != 29 or
                snapshot.get('mountObservation') != (('owned-stage-unreferenced' if 'unownedTargetMountsSha256' in snapshot else 'absent') if snapshot.get('uid') == '0' else 'unobserved') or
                ('unownedTargetMountsSha256' in snapshot and (snapshot.get('uid') != '0' or not isinstance(snapshot.get('unownedTargetMountsSha256'), str) or not _SHA.fullmatch(snapshot['unownedTargetMountsSha256']))) or
                snapshot.get('namespaceObservation') != ('verified' if snapshot.get('uid') == '0' else 'unobserved') or
                snapshot.get('avd') != intent['remote']['avd'] or snapshot.get('abi') != 'x86_64' or
                snapshot.get('reversePorts') != []):
            return _response('unknown', correlation_id, _readmission_reason(value.get('reason')),
                             readmissionCorrelationId=readmission_correlation_id,
                             **(_bounded_readmission_diagnostics(value) if value.get('correlationId') == correlation_id and value.get('state') == 'unknown' else {}))
        if _private_snapshot(original_path) != (intent, digest):
            return _response('unknown', correlation_id, 'original_intent_changed')
        _readmission_local_guard(root, intent, lease)
        android_native_fixture.write_private_plan(path, receipt)
        return _response('ready', correlation_id, readmissionCorrelationId=readmission_correlation_id,
                         owner=snapshot['owner'], revision=snapshot['revision'], cleanupOnly=True)


def cleanup_readmitted(root: Path | str, correlation_id: str,
                       readmission_correlation_id: str) -> dict[str, Any]:
    """Consume only a matching private receipt; ordinary cleanup stays unchanged."""
    root = Path(root).resolve()
    original_path = _intent_path(root, correlation_id)
    intent, digest = _private_snapshot(original_path)
    receipt, receipt_hash = _private_snapshot(_readmission_path(root, readmission_correlation_id))
    if (receipt.get('endpointCorrelationId') != correlation_id or
            receipt.get('readmissionCorrelationId') != readmission_correlation_id or
            receipt.get('originalIntentSha256') != digest or
            receipt.get('kind') != 'android-endpoint-cleanup-readmission' or receipt.get('schema') != 1 or
            receipt.get('originalOwner') != intent['remote']['owner'] or
            receipt.get('originalRevision') != intent['remote']['revision']):
        raise ValueError('Android cleanup readmission receipt binding changed')
    snapshot = receipt['snapshot']
    with _shared_device_lease(root, intent['host'], intent['device']) as lease:
        _readmission_local_guard(root, intent, lease)
        if (_private_snapshot(original_path) != (intent, digest) or
                _private_snapshot(_readmission_path(root, readmission_correlation_id)) != (receipt, receipt_hash)):
            raise ValueError('Android cleanup readmission record changed before dispatch')
        binding = {'correlationId': readmission_correlation_id, 'originalIntentSha256': digest, 'receipt': receipt}
        dispatch = {**intent, 'remote': {**intent['remote'], 'owner': snapshot['owner'],
                    'revision': snapshot['revision'], 'cleanupReadmission': binding}}
        bounded = _bound_result(dispatch, _remote(root, dispatch, 'cleanup'), 'cleanup')
        if bounded['state'] != 'cleaned':
            return bounded
        before = lease.lstat()
        if android_native_fixture_lifecycle._read_plan(lease) != {
                'owner': 'android-endpoint', 'correlationId': correlation_id,
                'host': intent['host'], 'device': intent['device']}:
            return _response('unknown', correlation_id, 'local_lease_changed')
        after = lease.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            return _response('unknown', correlation_id, 'local_lease_replaced')
        lease.unlink()
        return bounded



_MOUNT_DIAGNOSTIC_FETCH = r'''
import base64,hashlib,json,os,pathlib,re,stat,sys
base,correlation,diagnostic,expected,request=sys.argv[1:]
base=pathlib.Path(base);intent=json.loads(expected);request=json.loads(request)
name='mount-diagnostic-'+diagnostic+'.json'
limits={'intent.json':8192,'mount-intent.json':8192,'stage-owned.json':8192,'mount-failure.json':1024,name:524288}
def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_nlink]
def dfp(i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid]
def directory(i):
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def read(filename):
 root_fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0));job_fd=None
 try:
  root_info=os.fstat(root_fd);directory(root_info)
  job_name='android-endpoint-'+correlation
  job_fd=os.open(job_name,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0),dir_fd=root_fd)
  job_info=os.fstat(job_fd);directory(job_info)
  fd=os.open(filename,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=job_fd)
  with os.fdopen(fd,'rb') as f:
   before=os.fstat(f.fileno())
   if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=limits[filename]:raise ValueError()
   raw=f.read(limits[filename]+1)
   if len(raw)!=before.st_size or fp(before)!=fp(os.fstat(f.fileno())) or fp(before)!=fp(os.stat(filename,dir_fd=job_fd,follow_symlinks=False)):raise ValueError()
  if dfp(root_info)!=dfp(base.lstat()) or dfp(job_info)!=dfp(os.stat(job_name,dir_fd=root_fd,follow_symlinks=False)):raise ValueError()
  return raw,fp(before),{'base':dfp(root_info),'job':dfp(job_info)}
 finally:
  if job_fd is not None:os.close(job_fd)
  os.close(root_fd)
def census():
 data={};files={};directories=None
 for filename in limits:
  raw,fingerprint,current=read(filename)
  if directories is not None and directories!=current:raise ValueError()
  directories=current;data[filename]=raw;files[filename]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'fingerprint':fingerprint}
 if json.loads(data['intent.json'])!=intent or type(intent.get('api')) is not int or intent['api']!=29:raise ValueError()
 capture=json.loads(data[name]);plan=json.loads(data['mount-intent.json']);owned=json.loads(data['stage-owned.json']);failure=json.loads(data['mount-failure.json'])
 if (not isinstance(capture,dict) or set(capture)!={'schema','endpointCorrelationId','diagnosticCorrelationId','originalIntentSha256','originalCommandEvidence','probes'} or
     type(capture['schema']) is not int or capture['schema']!=1 or capture['endpointCorrelationId']!=correlation or capture['diagnosticCorrelationId']!=diagnostic or
     capture['originalIntentSha256']!=files['intent.json']['sha256'] or capture['originalCommandEvidence'] not in ('present','unavailable') or
     not isinstance(capture['probes'],list) or not 0<len(capture['probes'])<=64):raise ValueError()
 if (not isinstance(plan,dict) or set(plan)!={'zygote','target','staging','stagingIdentity'} or plan['target']!='/system/etc/security/cacerts' or
     plan['staging']!='/data/local/tmp/vpn-control-endpoint-'+correlation or owned!={k:plan[k] for k in ('zygote','staging','stagingIdentity')} or
     not isinstance(failure,dict) or failure.get('phase')!='mount' or failure.get('exit')!='nonzero' or failure.get('errorClass')!='not-found'):raise ValueError()
 return {'files':files,'directories':directories}
try:
 for identifier in (correlation,diagnostic):
  if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',identifier):raise ValueError()
 if correlation==diagnostic:raise ValueError()
 before=census()
 if request=={'mode':'metadata'}:reply={'state':'ready','source':before}
 else:
  if (not isinstance(request,dict) or set(request)!={'mode','offset','source'} or request['mode']!='chunk' or request['source']!=before or
      type(request['offset']) is not int or not 0<=request['offset']<before['files'][name]['bytes'] or request['offset']%8192):raise ValueError()
  raw,fingerprint,directories=read(name);offset=request['offset'];chunk=raw[offset:offset+8192]
  if fingerprint!=before['files'][name]['fingerprint'] or directories!=before['directories']:raise ValueError()
  reply={'state':'chunk','offset':offset,'bytes':len(chunk),'data':base64.b64encode(chunk).decode(),'sha256':before['files'][name]['sha256']}
 if census()!=before:raise ValueError()
 print(json.dumps(reply,separators=(',',':')))
except (OSError,ValueError,KeyError,TypeError,UnicodeError):print('{"state":"unknown"}')
'''


def mount_diagnostic_collect(root: Path | str, correlation_id: str,
                             diagnostic_correlation_id: str) -> dict[str, Any]:
    """Collect only one bound private diagnostic through unchanged 16 KiB transport."""
    root = Path(root).resolve()
    if (not all(isinstance(value,str) and _UUID.fullmatch(value) for value in (correlation_id,diagnostic_correlation_id)) or
            correlation_id==diagnostic_correlation_id):
        raise ValueError('Android mount collection requires distinct canonical correlations')
    flags={'diagnosticCorrelationId':diagnostic_correlation_id,'observationOnly':True}
    original_path=root/'.rag_index/android-endpoint-admission'/(correlation_id+'.json')
    directory_fd=None
    try:
        intent,original_sha=_private_snapshot(original_path)
        def fingerprint(i): return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_nlink]
        original_fp=fingerprint(original_path.lstat())
        if intent.get('correlationId')!=correlation_id or type(intent['remote'].get('api')) is not int or intent['remote']['api']!=29:
            raise ValueError('original binding')
        config=ssh_transport.load_config(root);host=intent['host']
        if host not in config.hosts or ssh_transport.connection_host(config,host).password is not None or str(config.hosts[host].fixture_transfer_root)!=intent['remoteRoot']:
            raise ValueError('configured route')
        profile=android_observation._profile(config.hosts[host].android_devices[intent['device']])
        if any(profile[key]!=intent['remote'][field] for key,field in (('adb','adb'),('cli','cli'),('serial','serial'),('api','api'),('expectedAvd','avd'))):
            raise ValueError('configured profile')
        def original_current():
            if _private_snapshot(original_path)!=(intent,original_sha) or fingerprint(original_path.lstat())!=original_fp:
                raise ValueError('original changed')
        def fetch(request):
            original_current()
            argv=ssh_transport.build_ssh_argv(config,host,60,command=('python3','-I','-B','-c','exec('+repr(_MOUNT_DIAGNOSTIC_FETCH)+')',
                intent['remoteRoot'],correlation_id,diagnostic_correlation_id,json.dumps(intent['remote'],sort_keys=True,separators=(',',':')),
                json.dumps(request,sort_keys=True,separators=(',',':'))))
            code,out=android_observation._run_probe(argv,120)
            if code!=0 or len(out)>android_observation.MAX_OUTPUT_BYTES:raise ValueError('bounded transport')
            value=json.loads(out)
            if not isinstance(value,dict):raise ValueError('response')
            original_current();return value
        metadata=fetch({'mode':'metadata'})
        if set(metadata)!={'state','source'} or metadata['state']!='ready':raise ValueError('metadata')
        source=metadata['source'];name='mount-diagnostic-'+diagnostic_correlation_id+'.json'
        limits={'intent.json':8192,'mount-intent.json':8192,'stage-owned.json':8192,'mount-failure.json':1024,name:524288}
        if not isinstance(source,dict) or set(source)!={'files','directories'} or not isinstance(source['files'],dict) or set(source['files'])!=set(limits):raise ValueError('source')
        if (not isinstance(source['directories'],dict) or set(source['directories'])!={'base','job'} or
                any(not isinstance(fp,list) or len(fp)!=4 or any(type(i) is not int for i in fp) for fp in source['directories'].values())):raise ValueError('directories')
        for fp in source['directories'].values():
            if fp[0]<0 or fp[1]<1 or not stat.S_ISDIR(fp[2]) or stat.S_IMODE(fp[2])!=0o700 or fp[3]<0:raise ValueError('directory fingerprint')
        if source['directories']['base'][3]!=source['directories']['job'][3]:raise ValueError('directory owner')
        for filename,limit in limits.items():
            item=source['files'][filename]
            if (not isinstance(item,dict) or set(item)!={'sha256','bytes','fingerprint'} or not isinstance(item['sha256'],str) or not _SHA.fullmatch(item['sha256']) or
                    type(item['bytes']) is not int or not 0<item['bytes']<=limit or not isinstance(item['fingerprint'],list) or len(item['fingerprint'])!=8 or any(type(i) is not int for i in item['fingerprint'])):raise ValueError('file metadata')
            fp=item['fingerprint']
            if fp[0]<0 or fp[1]<1 or fp[2]!=item['bytes'] or not stat.S_ISREG(fp[5]) or stat.S_IMODE(fp[5])!=0o600 or fp[6]!=source['directories']['job'][3] or fp[7]!=1:raise ValueError('file fingerprint')
        parent=original_path.parent;parent_info=parent.lstat();directory=parent/('mount-diagnostic-'+correlation_id+'-'+diagnostic_correlation_id)
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid!=os.getuid() or stat.S_IMODE(parent_info.st_mode)!=0o700:raise ValueError('private parent')
        directory.mkdir(mode=0o700);directory_info=directory.lstat()
        directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
        def parents_current():
            original_current()
            for path,old in ((parent,parent_info),(directory,directory_info)):
                now=path.lstat()
                if (now.st_dev,now.st_ino,now.st_mode,now.st_uid)!=(old.st_dev,old.st_ino,old.st_mode,old.st_uid):raise ValueError('parent changed')
            held=os.fstat(directory_fd)
            if (held.st_dev,held.st_ino,held.st_mode,held.st_uid)!=(directory_info.st_dev,directory_info.st_ino,directory_info.st_mode,directory_info.st_uid):raise ValueError('directory changed')
        parents_current();target=directory/'mount-diagnostic.json';item=source['files'][name]
        fd=os.open('mount-diagnostic.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=directory_fd)
        digest=hashlib.sha256();offset=0
        with os.fdopen(fd,'wb') as output:
            while offset<item['bytes']:
                parents_current();value=fetch({'mode':'chunk','offset':offset,'source':source})
                if (set(value)!={'state','offset','bytes','data','sha256'} or value['state']!='chunk' or type(value['offset']) is not int or value['offset']!=offset or
                        type(value['bytes']) is not int or value['bytes']!=min(8192,item['bytes']-offset) or value['sha256']!=item['sha256'] or
                        not isinstance(value['data'],str) or len(value['data'])>10924):raise ValueError('chunk')
                raw=base64.b64decode(value['data'],validate=True)
                if len(raw)!=value['bytes']:raise ValueError('chunk size')
                parents_current();output.write(raw);digest.update(raw);offset+=len(raw)
            output.flush();os.fsync(output.fileno());info=os.fstat(output.fileno())
            if (digest.hexdigest()!=item['sha256'] or info.st_size!=item['bytes'] or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or fingerprint(info)!=fingerprint(target.lstat())):raise ValueError('local artifact')
        if fetch({'mode':'metadata'})!=metadata:raise ValueError('final source changed')
        parents_current()
        fd=os.open('mount-diagnostic.json',os.O_RDONLY|getattr(os,'O_NOFOLLOW',0),dir_fd=directory_fd)
        with os.fdopen(fd,'rb') as final:
            raw=final.read(524289)
            if fingerprint(info)!=fingerprint(os.fstat(final.fileno())) or fingerprint(info)!=fingerprint(target.lstat()) or hashlib.sha256(raw).hexdigest()!=item['sha256'] or len(raw)!=item['bytes']:raise ValueError('final local artifact')
        capture=json.loads(raw)
        if (not isinstance(capture,dict) or set(capture)!={'schema','endpointCorrelationId','diagnosticCorrelationId','originalIntentSha256','originalCommandEvidence','probes'} or
                type(capture['schema']) is not int or capture['schema']!=1 or capture['endpointCorrelationId']!=correlation_id or
                capture['diagnosticCorrelationId']!=diagnostic_correlation_id or capture['originalIntentSha256']!=source['files']['intent.json']['sha256'] or
                capture['originalCommandEvidence'] not in ('present','unavailable') or not isinstance(capture['probes'],list) or not 0<len(capture['probes'])<=64):raise ValueError('capture binding')
        receipt={'schema':1,'endpointCorrelationId':correlation_id,'diagnosticCorrelationId':diagnostic_correlation_id,'originalLocalIntentSha256':original_sha,'source':source}
        parents_current();fd=os.open('collected.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600,dir_fd=directory_fd)
        with os.fdopen(fd,'wb') as output:output.write(json.dumps(receipt,sort_keys=True,separators=(',',':')).encode());output.flush();os.fsync(output.fileno())
        os.fsync(directory_fd);parents_current()
        return {**_response('complete',correlation_id,**flags),'ok':True,'localPath':str(target),'sha256':item['sha256'],'bytes':item['bytes']}
    except (OSError,RuntimeError,TimeoutError,ValueError,UnicodeError,KeyError,TypeError):
        return _response('unknown',correlation_id,'mount_diagnostic_collection_unknown',**flags)
    finally:
        if directory_fd is not None:os.close(directory_fd)


def mount_failure_diagnostic(root: Path | str, correlation_id: str,
                             diagnostic_correlation_id: str) -> dict[str, Any]:
    """Inspect one retained failed API29 mount; no admission, retry, or device mutation."""
    root = Path(root).resolve()
    if (not all(isinstance(value, str) and _UUID.fullmatch(value) for value in (correlation_id, diagnostic_correlation_id)) or
            correlation_id == diagnostic_correlation_id):
        raise ValueError('Android mount diagnostic requires distinct canonical correlations')
    extra = {'diagnosticCorrelationId': diagnostic_correlation_id, 'observationOnly': True}
    path = root / '.rag_index/android-endpoint-admission' / (correlation_id + '.json')
    try:
        intent, digest = _private_snapshot(path)
        if intent.get('correlationId') != correlation_id:
            return _response('unknown', correlation_id, 'intent_changed', **extra)
        lease = root / '.rag_index/android-native-device-leases' / ('lease-' + intent['host'] + '-' + intent['device'] + '.json')
        _readmission_local_guard(root, intent, lease)
        dispatch = {**intent, 'remote': {**intent['remote'], 'mountDiagnosticCorrelation': diagnostic_correlation_id}}
        value = _remote(root, dispatch, 'mount-failure-diagnostic')
        _readmission_local_guard(root, intent, lease)
        if _private_snapshot(path) != (intent, digest):
            return _response('unknown', correlation_id, 'intent_changed', **extra)
        facts = value.get('mountFailureDiagnostic')
        path_fields = {'lstat': {'directory', 'symlink', 'other', 'unavailable'}, 'followed': {'directory', 'other', 'unavailable'},
                       'outsideInside': {'same', 'different', 'unavailable'}, 'canonical': {'exact', 'different', 'unavailable'},
                       'parent': {'directory', 'other', 'unavailable'}}
        helper_fields = {'canonical': {'toybox', 'self', 'other', 'unavailable'}, 'namespaceIdentity': {'same', 'different', 'unavailable'}}
        scalar_fields = {'procFilesystems': {'readable', 'unavailable'}, 'procMounts': {'readable', 'unavailable'},
                         'avc': {'unavailable', 'matching-denial', 'none'}, 'selinux': {'enforcing', 'permissive', 'disabled', 'unavailable'},
                         'domain': {'su', 'shell', 'other', 'unavailable'}, 'namespaceIdentity': {'exact', 'different', 'unavailable'},
                         'rootMembership': {'member', 'foreign', 'unavailable'}, 'targetMembership': {'member', 'foreign', 'unavailable'},
                         'stageMembership': {'member', 'foreign', 'unavailable'},
                         'targetLinkCount': {'zero', 'positive', 'unavailable'}, 'stageLinkCount': {'zero', 'positive', 'unavailable'},
                         'targetDescriptor': {'linked', 'deleted', 'other', 'unavailable'},
                         'targetDescriptorIdentity': {'exact', 'different', 'unavailable'},
                         'targetMountCount': {'zero', 'one', 'multiple', 'unavailable'},
                         'targetMountRoot': {'root', 'stage', 'target', 'other', 'unavailable'},
                         'kernelVersion': {'readable', 'unavailable'}}
        def finite(node, fields):
            return (isinstance(node, dict) and set(node) == set(fields) and
                    all(isinstance(node.get(key), str) and node[key] in choices for key, choices in fields.items()))
        valid = (isinstance(facts, dict) and set(facts) == {'target', 'stage', 'mountHelper', 'nsenterHelper', *scalar_fields} and
                 all(finite(facts.get(key), path_fields) for key in ('target', 'stage')) and
                 all(finite(facts.get(key), helper_fields) for key in ('mountHelper', 'nsenterHelper')) and
                 all(isinstance(facts.get(key), str) and facts[key] in choices for key, choices in scalar_fields.items()))
        if (value.get('correlationId') != correlation_id or value.get('diagnosticCorrelationId') != diagnostic_correlation_id or
                value.get('state') != 'partial' or value.get('reason') != 'mount_failure_observed' or
                value.get('originalCommandEvidence') not in {'present', 'unavailable'} or not valid):
            return _response('unknown', correlation_id, _readmission_reason(value.get('reason')), **extra,
                             **_bounded_readmission_diagnostics(value))
        return _response('partial', correlation_id, 'mount_failure_observed', **extra,
                         originalCommandEvidence=value['originalCommandEvidence'], mountFailureDiagnostic=facts)
    except (OSError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'readmission_local_record_unverified', **extra)


def cleanup_readmitted_status(root: Path | str, correlation_id: str,
                              readmission_correlation_id: str) -> dict[str, Any]:
    """Observe a completed receipted API29 cleanup without acquiring or releasing state."""
    root = Path(root).resolve()
    if (not all(isinstance(value, str) and _UUID.fullmatch(value) for value in (correlation_id, readmission_correlation_id)) or
            correlation_id == readmission_correlation_id):
        raise ValueError('Android cleanup terminal status requires distinct canonical correlations')
    extra = {'readmissionCorrelationId': readmission_correlation_id, 'observationOnly': True}
    try:
        directory = root / '.rag_index/android-endpoint-admission'
        original_path = directory / (correlation_id + '.json')
        receipt_path = directory / ('cleanup-readmission-' + readmission_correlation_id + '.json')
        request_path = receipt_path.with_suffix('.request.json')
        intent, digest = _private_snapshot(original_path)
        receipt, receipt_hash = _private_snapshot(receipt_path)
        request, request_hash = _private_snapshot(request_path)
        binding = {'correlationId': readmission_correlation_id, 'originalIntentSha256': digest}
        if (intent.get('correlationId') != correlation_id or
                request != {'schema': 1, 'endpointCorrelationId': correlation_id, **binding} or
                receipt.get('endpointCorrelationId') != correlation_id or receipt.get('readmissionCorrelationId') != readmission_correlation_id or
                receipt.get('originalIntentSha256') != digest or receipt.get('kind') != 'android-endpoint-cleanup-readmission' or
                set(receipt) != {'schema', 'kind', 'endpointCorrelationId', 'readmissionCorrelationId', 'originalIntentSha256',
                                 'remoteIntentSha256', 'originalOwner', 'originalRevision', 'snapshot'} or
                type(receipt.get('schema')) is not int or receipt.get('schema') != 1 or receipt.get('originalOwner') != intent['remote']['owner'] or
                type(receipt.get('originalRevision')) is not int or receipt.get('originalRevision') != intent['remote']['revision']):
            return _response('unknown', correlation_id, 'readmission_receipt_changed', **extra)
        lease = root / '.rag_index/android-native-device-leases' / ('lease-' + intent['host'] + '-' + intent['device'] + '.json')
        _readmission_local_guard(root, intent, lease, terminal=True)
        snapshot = receipt['snapshot']
        dispatch = {**intent, 'remote': {**intent['remote'], 'owner': snapshot['owner'], 'revision': snapshot['revision'],
                    'cleanupReadmission': {**binding, 'receipt': receipt}}}
        value = _remote(root, dispatch, 'cleanup-readmitted-status')
        _readmission_local_guard(root, intent, lease, terminal=True)
        if (_private_snapshot(original_path) != (intent, digest) or _private_snapshot(receipt_path) != (receipt, receipt_hash) or
                _private_snapshot(request_path) != (request, request_hash)):
            return _response('unknown', correlation_id, 'readmission_receipt_changed', **extra)
        bounded = _bound_result(dispatch, value, 'status')
        if bounded['state'] != 'cleaned':
            return _response('unknown', correlation_id, _readmission_reason(value.get('reason')),
                             **extra, **_bounded_readmission_diagnostics(value), **_bounded_endpoint_transport(value.get('transportDiagnostic')))
        bounded['result'] = {key: bounded['result'][key] for key in ('state', 'reason', 'correlationId', 'device',
                            'packageSha256', 'owner', 'revision', 'caSha256', 'reversePorts')}
        return {**bounded, **extra}
    except (OSError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'readmission_terminal_unverified', **extra)


def cleanup_readmission_status(root: Path | str, correlation_id: str,
                              readmission_correlation_id: str) -> dict[str, Any]:
    """Read the exact original request and current guard without replay or writes."""
    root = Path(root).resolve()
    if not all(isinstance(value, str) and _UUID.fullmatch(value)
               for value in (correlation_id, readmission_correlation_id)):
        raise ValueError('Android cleanup status requires canonical correlations')
    if correlation_id == readmission_correlation_id:
        raise ValueError('Android cleanup status requires distinct correlations')
    extra = {'readmissionCorrelationId': readmission_correlation_id, 'observationOnly': True}
    directory = root / '.rag_index' / 'android-endpoint-admission'
    original_path = directory / (correlation_id + '.json')
    request_path = directory / ('cleanup-readmission-' + readmission_correlation_id + '.request.json')
    try:
        intent, digest = _private_snapshot(original_path)
        request, request_hash = _private_snapshot(request_path)
        binding = {'correlationId': readmission_correlation_id, 'originalIntentSha256': digest}
        if (intent.get('correlationId') != correlation_id or
                request != {'schema': 1, 'endpointCorrelationId': correlation_id, **binding}):
            return _response('unknown', correlation_id, 'readmission_request_changed', **extra)
        lease = root / '.rag_index/android-native-device-leases' / ('lease-' + intent['host'] + '-' + intent['device'] + '.json')
        try:
            _readmission_local_guard(root, intent, lease)
        except ValueError as error:
            classified = {
                'Android cleanup readmission is limited to API29': 'readmission_local_api_changed',
                'Android cleanup readmission has a runtime child': 'readmission_local_child_present',
                'Android cleanup readmission local lease changed': 'readmission_local_lease_changed',
                'Android cleanup readmission configured device changed': 'readmission_local_device_changed',
            }.get(str(error), 'readmission_local_guard_unverified')
            return _response('unknown', correlation_id, classified, **extra)
        dispatch = {**intent, 'remote': {**intent['remote'], 'cleanupReadmission': binding}}
        value = _remote(root, dispatch, 'cleanup-readmission-status')
        if (_private_snapshot(original_path) != (intent, digest) or
                _private_snapshot(request_path) != (request, request_hash)):
            return _response('unknown', correlation_id, 'readmission_request_changed', **extra)
        if value.get('correlationId') != correlation_id or value.get('state') not in {'unknown', 'partial'}:
            return _response('unknown', correlation_id, 'cleanup_readmission_unverified', **extra)
        reason = _readmission_reason(value.get('reason'))
        extra.update(_bounded_readmission_diagnostics(value))
        verified = value.get('state') == 'partial' and reason in {'readmission_receipt_absent', 'readmission_receipt_present'}
        return _response('partial' if verified else 'unknown', correlation_id, reason,
                         freshGuardVerified=verified, receiptPresent=reason == 'readmission_receipt_present', **extra)
    except (OSError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'readmission_local_record_unverified', **extra)



def cleanup_mount_diagnostic(root: Path | str, correlation_id: str,
                             readmission_correlation_id: str) -> dict[str, Any]:
    """Observe current target mounts; never infer an unrecorded stock baseline."""
    root = Path(root).resolve()
    if (not all(isinstance(value, str) and _UUID.fullmatch(value)
                for value in (correlation_id, readmission_correlation_id)) or correlation_id == readmission_correlation_id):
        raise ValueError('Android mount diagnostic requires distinct canonical correlations')
    extra = {'readmissionCorrelationId': readmission_correlation_id, 'observationOnly': True}
    directory = root / '.rag_index/android-endpoint-admission'
    paths = [directory / (correlation_id + '.json'),
             directory / ('cleanup-readmission-' + readmission_correlation_id + '.request.json'),
             directory / ('cleanup-readmission-' + readmission_correlation_id + '.json')]
    try:
        records = [_private_snapshot(path) for path in paths]
        (intent, digest), (request, _), (receipt, _) = records
        binding = {'correlationId': readmission_correlation_id, 'originalIntentSha256': digest}
        if (intent.get('correlationId') != correlation_id or
                request != {'schema': 1, 'endpointCorrelationId': correlation_id, **binding} or
                receipt.get('endpointCorrelationId') != correlation_id or receipt.get('readmissionCorrelationId') != readmission_correlation_id or
                receipt.get('originalIntentSha256') != digest or receipt.get('originalOwner') != intent['remote']['owner'] or
                receipt.get('originalRevision') != intent['remote']['revision']):
            return _response('unknown', correlation_id, 'readmission_request_changed', **extra)
        lease = root / '.rag_index/android-native-device-leases' / ('lease-' + intent['host'] + '-' + intent['device'] + '.json')
        _readmission_local_guard(root, intent, lease)
        dispatch = {**intent, 'remote': {**intent['remote'], 'cleanupReadmission': {**binding, 'receipt': receipt}}}
        value = _remote(root, dispatch, 'cleanup-mount-diagnostic')
        if records != [_private_snapshot(path) for path in paths]:
            return _response('unknown', correlation_id, 'readmission_request_changed', **extra)
        principal = _bounded_principal_preflight(value.get('principalPreflight'))
        if principal is not None:
            extra['principalPreflight'] = principal
        diagnostic = value.get('mountDiagnostic')
        valid = (value.get('correlationId') == correlation_id and value.get('state') == 'partial' and
                 value.get('reason') == 'readmission_target_mount_observed' and isinstance(diagnostic, dict) and
                 set(diagnostic) == {'targetEntryCount', 'entries', 'ownCaRelation', 'openingTargetMountRecorded'} and
                 type(diagnostic.get('targetEntryCount')) is int and 0 <= diagnostic['targetEntryCount'] <= 16 and
                 isinstance(diagnostic.get('entries'), list) and len(diagnostic['entries']) == diagnostic['targetEntryCount'] and
                 diagnostic.get('ownCaRelation') in {'absent', 'owned', 'foreign', 'other'} and diagnostic.get('openingTargetMountRecorded') is False and
                 all(isinstance(entry, dict) and set(entry) == {'rootRelation', 'filesystem'} and
                     entry.get('rootRelation') in {'stage-exact', 'stage-descendant', 'target-exact', 'target-descendant', 'root', 'other'} and
                     entry.get('filesystem') in {'ext4', 'tmpfs', 'overlay', 'erofs', 'fuse', 'f2fs', 'other'} for entry in diagnostic['entries']))
        if not valid:
            command_diagnostic = _bounded_command_diagnostic(value.get('commandDiagnostic'))
            if command_diagnostic is not None:
                extra['commandDiagnostic'] = command_diagnostic
            public_failure = _bounded_public_failure(value.get('publicFailure'))
            if public_failure is not None:
                extra['publicFailure'] = public_failure
            return _response('unknown', correlation_id, _readmission_reason(value.get('reason')), **extra)
        return _response('partial', correlation_id, 'readmission_target_mount_observed', mountDiagnostic=diagnostic, **extra)
    except (OSError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'readmission_local_record_unverified', **extra)


_REMAINING_REASONS = frozenset({'remaining_binding_invalid','remaining_record_changed','remaining_old_phase_changed',
    'remaining_receipt_changed','remaining_release_changed','remaining_child_unknown','remaining_child_present',
    'remaining_reverse_changed','remaining_native_changed','remaining_principal_unverified','remaining_owned_path_present',
    'remaining_stage_changed','remaining_target_unlinked','remaining_mount_referenced','remaining_public_changed',
    'remaining_owner_changed','remaining_rules_changed','remaining_already_recorded','remaining_observation_changed',
    'remaining_attempt_recorded','remaining_receipt_stale','remaining_post_changed','remaining_terminal_changed',
    'remaining_stage_retired'})


def _remaining_path(root: Path, correlation_id: str, suffix: str = '.json') -> Path:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError('Remaining cleanup requires canonical correlation')
    return _local_directory(root) / ('remaining-stage-' + correlation_id + suffix)


def _remaining_receipt(envelope: Any, binding: dict[str, Any], intent: dict[str, Any]) -> bool:
    if not isinstance(envelope, dict) or set(envelope) != {'receipt', 'remotePin'}:
        return False
    receipt, pin = envelope['receipt'], envelope['remotePin']
    if (not isinstance(receipt, dict) or set(receipt) != {'schema','kind','binding','snapshot'} or
            type(receipt.get('schema')) is not int or receipt['schema'] != 1 or receipt['kind'] != 'android-endpoint-remaining-stage' or receipt['binding'] != binding):
        return False
    def private_pin(value):
        if not isinstance(value, dict) or set(value) != {'generation','sha256'} or not isinstance(value['sha256'], str) or not _SHA.fullmatch(value['sha256']):
            return False
        g=value['generation']
        return (isinstance(g,list) and len(g)==8 and all(type(x) is int and x>=0 for x in g) and g[1]>0 and
                stat.S_ISREG(g[5]) and stat.S_IMODE(g[5])==0o600 and g[7]==1)
    raw=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode()
    if not private_pin(pin) or pin['sha256'] != hashlib.sha256(raw).hexdigest() or pin['generation'][2] != len(raw):
        return False
    snap=receipt['snapshot']
    if not isinstance(snap,dict) or set(snap)!={'public','native','records'}:
        return False
    public,native,records=snap['public'],snap['native'],snap['records']
    if (not isinstance(public,dict) or set(public)!={'owner','revision','rulesSha256'} or not isinstance(public['owner'],str) or
            not 0<len(public['owner'])<=256 or any(ord(x)<32 for x in public['owner']) or type(public['revision']) is not int or public['revision']<0 or
            not isinstance(public['rulesSha256'],str) or not _SHA.fullmatch(public['rulesSha256']) or
            not isinstance(native,dict) or set(native)!={'stageGeneration','caGeneration','targetIdentity','mountinfoSha256'} or
            not isinstance(native['stageGeneration'],str) or not re.fullmatch(r'0:0:755:[0-9]+:[1-9][0-9]*:[1-9][0-9]*:[0-9]+:[0-9]+:[0-9]+:directory',native['stageGeneration']) or
            not isinstance(native['caGeneration'],str) or not re.fullmatch(r'0:0:644:[0-9]+:[1-9][0-9]*:1:[0-9]+:[0-9]+:[0-9]+:regular file',native['caGeneration']) or
            not isinstance(native['targetIdentity'],str) or not re.fullmatch(r'[0-9]+:[1-9][0-9]*:[1-9][0-9]*:directory',native['targetIdentity']) or
            not isinstance(native['mountinfoSha256'],str) or not _SHA.fullmatch(native['mountinfoSha256'])):
        return False
    names={'remaining-stage-admission.json','intent.json','stage.json','ca.pem','mount-intent.json','stage-owned.json','cleanup-intent.json',
        'checkpoint-cleanup-reverse-https.json','checkpoint-cleanup-reverse-socks.json','checkpoint-cleanup-root.json','checkpoint-cleanup-unmount.json',
        'lease','backup','root','job'}
    if not isinstance(records,dict) or set(records)!=names:
        return False
    for name,value in records.items():
        if name in {'root','job'}:
            if not isinstance(value,list) or len(value)!=4 or any(type(x) is not int or x<0 for x in value) or not stat.S_ISDIR(value[2]) or stat.S_IMODE(value[2])!=0o700:
                return False
        elif not private_pin(value):return False
    return True


def _remaining_call(root: Path | str, correlation_id: str, recovery_correlation_id: str, action: str) -> dict[str, Any]:
    root=Path(root).resolve()
    if (not isinstance(correlation_id,str) or not _UUID.fullmatch(correlation_id) or not isinstance(recovery_correlation_id,str) or
            not _UUID.fullmatch(recovery_correlation_id) or correlation_id==recovery_correlation_id):
        raise ValueError('Remaining cleanup requires two distinct canonical correlations')
    extra={'remainingCorrelationId':recovery_correlation_id,'originalOutcome':'unknown','cleanupOnly':True}
    try:
        original=_intent_path(root,correlation_id);original_pin=_recovery_local_snapshot(original);intent,digest,_=original_pin
        if intent.get('correlationId')!=correlation_id:raise ValueError('Remaining original correlation')
        binding={'correlationId':recovery_correlation_id,'originalIntentSha256':digest}
        request=_remaining_path(root,recovery_correlation_id,'.request.json');path=_remaining_path(root,recovery_correlation_id)
        attempt=_remaining_path(root,recovery_correlation_id,'.attempt.json');closed=_remaining_path(root,recovery_correlation_id,'.closed.json')
        with _shared_device_lease(root,intent['host'],intent['device']) as lease:
            released=not os.path.lexists(lease)
            _readmission_local_guard(root,intent,lease,terminal=released)
            if released and (action!='remaining-cleanup-collect' and action!='remaining-cleanup-status' or not os.path.lexists(closed)):
                raise ValueError('Remaining local lease absent')
            lease_pin=_recovery_local_snapshot(lease) if not released else None
            if action=='remaining-cleanup-admit':
                requests=list(path.parent.glob('remaining-stage-*.request.json'))
                if len(requests)>256:raise ValueError('Remaining request census unknown')
                for prior in requests:
                    if prior!=request and _recovery_local_snapshot(prior)[0].get('endpointCorrelationId')==correlation_id:
                        return _response('unknown',correlation_id,'remaining_already_recorded',**extra)
                if any(os.path.lexists(x) for x in (request,path,attempt,closed)):return _response('unknown',correlation_id,'remaining_already_recorded',**extra)
                android_native_fixture.write_private_plan(request,{'schema':1,'endpointCorrelationId':correlation_id,'binding':binding})
            request_pin=_recovery_local_snapshot(request)
            if request_pin[0]!={'schema':1,'endpointCorrelationId':correlation_id,'binding':binding}:raise ValueError('Remaining request changed')
            receipt_pin=_recovery_local_snapshot(path) if os.path.lexists(path) else None
            if receipt_pin is not None:
                if not _remaining_receipt(receipt_pin[0],binding,intent):raise ValueError('Remaining receipt changed')
                binding={**binding,'receipt':receipt_pin[0]['receipt'],'receiptPin':receipt_pin[0]['remotePin']}
            if action in {'remaining-cleanup-once','remaining-cleanup-collect'} and receipt_pin is None:raise ValueError('Remaining receipt absent')
            if action=='remaining-cleanup-once':
                if os.path.lexists(attempt):return _response('unknown',correlation_id,'remaining_attempt_recorded',**extra)
                android_native_fixture.write_private_plan(attempt,{'schema':1,'receiptSha256':receipt_pin[1]})
            attempt_pin=_recovery_local_snapshot(attempt) if os.path.lexists(attempt) else None
            if attempt_pin is not None and (receipt_pin is None or attempt_pin[0]!={'schema':1,'receiptSha256':receipt_pin[1]}):raise ValueError('Remaining attempt changed')
            closed_pin=_recovery_local_snapshot(closed) if os.path.lexists(closed) else None
            if closed_pin is not None:
                marker=closed_pin[0];generation=marker.get('leasePin')
                if (receipt_pin is None or set(marker)!={'schema','originalIntentSha256','receiptSha256','terminalSha256','leasePin'} or
                        type(marker.get('schema')) is not int or marker['schema']!=1 or marker['originalIntentSha256']!=digest or marker['receiptSha256']!=receipt_pin[1] or
                        not isinstance(marker['terminalSha256'],str) or not _SHA.fullmatch(marker['terminalSha256']) or not isinstance(generation,list) or len(generation)!=8 or
                        any(type(x) is not int or x<0 for x in generation) or generation[5]!=0o600 or generation[7]!=1 or
                        lease_pin is not None and generation!=list(lease_pin[2])):raise ValueError('Remaining local closure changed')
            def guard():
                if _recovery_local_snapshot(original)!=original_pin or _recovery_local_snapshot(request)!=request_pin:raise ValueError('Remaining local generation changed')
                for file,pin in ((path,receipt_pin),(attempt,attempt_pin),(closed,closed_pin),(lease,lease_pin)):
                    if pin is not None and _recovery_local_snapshot(file)!=pin:raise ValueError('Remaining local generation changed')
                _readmission_local_guard(root,intent,lease,terminal=released)
            guard();value=_remote(root,{**intent,'remote':{**intent['remote'],'cleanupRemaining':binding}},action);guard()
            if value.get('correlationId')!=correlation_id:raise ValueError('Remaining response correlation')
            if value.get('state')=='ready' and action in {'remaining-cleanup-admit','remaining-cleanup-status'}:
                envelope={'receipt':value.get('remaining'),'remotePin':value.get('remainingReceiptPin')}
                base={key:binding[key] for key in ('correlationId','originalIntentSha256')}
                if not _remaining_receipt(envelope,base,intent):raise ValueError('Remaining response shape')
                if receipt_pin is None:android_native_fixture.write_private_plan(path,envelope)
                elif envelope!=receipt_pin[0]:raise ValueError('Remaining receipt replaced')
                public=envelope['receipt']['snapshot']['public']
                return _response('ready',correlation_id,owner=public['owner'],revision=public['revision'],**extra)
            if (value.get('state')=='cleaned' and value.get('reason')=='remaining_stage_retired' and value.get('remainingCorrelationId')==recovery_correlation_id and
                    receipt_pin is not None and (closed_pin is None or value.get('terminalSha256')==closed_pin[0]['terminalSha256']) and value.get('owner')==receipt_pin[0]['receipt']['snapshot']['public']['owner'] and
                    type(value.get('revision')) is int and value['revision']==receipt_pin[0]['receipt']['snapshot']['public']['revision'] and
                    value.get('originalOutcome')=='unknown' and type(value.get('leaseReleased')) is bool and
                    isinstance(value.get('terminalSha256'),str) and _SHA.fullmatch(value['terminalSha256'])):
                if action=='remaining-cleanup-collect':
                    if value['leaseReleased'] is not True:raise ValueError('Remaining remote lease retained')
                    marker={'schema':1,'originalIntentSha256':digest,'receiptSha256':receipt_pin[1],'terminalSha256':value['terminalSha256'],
                        'leasePin':list(lease_pin[2]) if lease_pin is not None else closed_pin[0]['leasePin']}
                    if closed_pin is None:
                        android_native_fixture.write_private_plan(closed,marker);closed_pin=_recovery_local_snapshot(closed)
                    elif closed_pin[0]!=marker:raise ValueError('Remaining local marker changed')
                    guard()
                    if lease_pin is not None:
                        if _recovery_local_snapshot(lease)!=lease_pin:raise ValueError('Remaining local lease replaced')
                        lease.unlink()
                    if os.path.lexists(lease):raise ValueError('Remaining local lease retained')
                    return _response('cleaned',correlation_id,'remaining_stage_retired',leaseReleased=True,**extra)
                return _response('cleaned',correlation_id,'remaining_stage_retired',leaseReleased=value['leaseReleased'] and released,**extra)
            reason=value.get('reason');reason=reason if reason in _REMAINING_REASONS else _readmission_reason(reason)
            return _response('unknown',correlation_id,reason,**extra,**_bounded_readmission_diagnostics(value),**_bounded_endpoint_transport(value.get('transportDiagnostic')))
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,IndexError):
        return _response('unknown',correlation_id,'remaining_local_unverified',**extra)


def remaining_cleanup_readmission(root: Path | str, correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    return _remaining_call(root,correlation_id,recovery_correlation_id,'remaining-cleanup-admit')


def remaining_cleanup_once(root: Path | str, correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    return _remaining_call(root,correlation_id,recovery_correlation_id,'remaining-cleanup-once')


def remaining_cleanup_status(root: Path | str, correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    return _remaining_call(root,correlation_id,recovery_correlation_id,'remaining-cleanup-status')


def remaining_cleanup_collect(root: Path | str, correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    return _remaining_call(root,correlation_id,recovery_correlation_id,'remaining-cleanup-collect')


def _recovery_local_snapshot(path: Path) -> tuple[dict[str, Any], str, tuple[int, ...]]:
    before = path.lstat()
    value, digest = _private_snapshot(path)
    def pin(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink)
    if pin(before) != pin(path.lstat()):
        raise ValueError('Recovery local generation changed')
    return value, digest, pin(before)


def _recovery_call_locked(root: Path | str, correlation_id: str, historical_correlation_id: str,
                   recovery_correlation_id: str, action: str) -> dict[str, Any]:
    root = Path(root).resolve()
    ids = (correlation_id, historical_correlation_id, recovery_correlation_id)
    if not all(isinstance(x, str) and _UUID.fullmatch(x) for x in ids) or len(set(ids)) != 3:
        raise ValueError('Recovery requires three distinct canonical correlations')
    directory = root / '.rag_index/android-endpoint-admission'
    original = directory / (correlation_id + '.json'); historical = directory / (historical_correlation_id + '.json')
    request = directory / ('mount-recovery-' + recovery_correlation_id + '.request.json')
    receipt_path = directory / ('mount-recovery-' + recovery_correlation_id + '.json')
    attempt = directory / ('mount-recovery-' + recovery_correlation_id + '.attempt.json')
    extra = {'recoveryCorrelationId': recovery_correlation_id, 'historicalCorrelationId': historical_correlation_id,
             'observationOnly': action != 'recovery-unmount', 'replayAllowed': False}
    try:
        originals = [_recovery_local_snapshot(path) for path in (original, historical)]
        (intent, digest, _), (old, old_digest, _) = originals
        if (intent.get('correlationId') != correlation_id or old.get('correlationId') != historical_correlation_id or
                any(old.get(key) != intent.get(key) for key in ('host', 'device', 'remoteRoot', 'sourceSha', 'targetArtifactId', 'caArtifactId'))):
            raise ValueError('Recovery originals mismatch')
        lease = root / '.rag_index/android-native-device-leases' / ('lease-' + intent['host'] + '-' + intent['device'] + '.json')
        _readmission_local_guard(root, intent, lease)
        if _runtime_parent_correlation(root, historical_correlation_id) is not None:
            raise ValueError('Recovery historical runtime child')
        binding = {'correlationId': recovery_correlation_id, 'historicalCorrelationId': historical_correlation_id,
                   'originalIntentSha256': digest, 'historicalIntentSha256': old_digest, 'historicalExpected': old['remote']}
        requested = {'schema': 1, 'endpointCorrelationId': correlation_id, 'binding': binding}
        if action == 'recovery-readmit':
            if any(os.path.lexists(path) for path in (request, receipt_path, attempt)):
                return _response('unknown', correlation_id, 'recovery_already_recorded', **extra)
            android_native_fixture.write_private_plan(request, requested)
        request_record = _recovery_local_snapshot(request)
        if type(request_record[0].get('schema')) is not int or request_record[0] != requested:
            raise ValueError('Recovery request changed')
        receipt_record = None
        if action != 'recovery-readmit':
            receipt_record = _recovery_local_snapshot(receipt_path)
            receipt = receipt_record[0]
            if receipt.get('binding') != binding or type(receipt.get('schema')) is not int or receipt.get('schema') != 1 or receipt.get('kind') != 'android-endpoint-deleted-mount-recovery':
                raise ValueError('Recovery receipt binding')
            binding = {**binding, 'receipt': receipt}
            if action == 'recovery-unmount':
                if os.path.lexists(attempt):
                    return _response('unknown', correlation_id, 'recovery_attempt_already_recorded', **extra)
                android_native_fixture.write_private_plan(attempt, {'schema': 1, 'receiptSha256': receipt_record[1]})
        attempt_record = _recovery_local_snapshot(attempt) if os.path.lexists(attempt) else None
        if attempt_record is not None and (type(attempt_record[0].get('schema')) is not int or receipt_record is None or attempt_record[0] != {'schema': 1, 'receiptSha256': receipt_record[1]}):
            raise ValueError('Recovery attempt binding')
        def guard():
            if attempt_record is not None and _recovery_local_snapshot(attempt) != attempt_record:
                raise ValueError('Recovery attempt generation changed')
            if [_recovery_local_snapshot(path) for path in (original, historical)] != originals or _recovery_local_snapshot(request) != request_record:
                raise ValueError('Recovery local generation changed')
            if receipt_record is not None and _recovery_local_snapshot(receipt_path) != receipt_record:
                raise ValueError('Recovery receipt changed')
            _readmission_local_guard(root, intent, lease)
            if _runtime_parent_correlation(root, historical_correlation_id) is not None:
                raise ValueError('Recovery historical child changed')
        guard()
        value = _remote(root, {**intent, 'remote': {**intent['remote'], 'cleanupRecovery': binding}}, action)
        guard()
        if value.get('correlationId') != correlation_id:
            raise ValueError('Recovery response correlation')
        if action == 'recovery-readmit' and value.get('state') == 'ready':
            receipt = value.get('recovery'); snapshot = receipt.get('snapshot') if isinstance(receipt, dict) else None
            public = snapshot.get('public') if isinstance(snapshot, dict) else None
            native = snapshot.get('native') if isinstance(snapshot, dict) else None
            if (not isinstance(receipt, dict) or set(receipt) != {'schema', 'kind', 'binding', 'snapshot'} or type(receipt['schema']) is not int or receipt['schema'] != 1 or
                    receipt['kind'] != 'android-endpoint-deleted-mount-recovery' or receipt['binding'] != binding or
                    not isinstance(snapshot, dict) or set(snapshot) != {'public', 'native'} or not isinstance(public, dict) or
                    not isinstance(native, dict) or set(native) != {'historicalMount', 'historicalRecords', 'mountinfoSha256', 'targetEntry', 'targetIdentity', 'currentMount'} or
                    not isinstance(public.get('owner'), str) or not _UUID.fullmatch(public['owner']) or type(public.get('revision')) is not int or public['revision'] < 0 or
                    public.get('uid') != '0' or public.get('api') != 29 or public.get('avd') != intent['remote']['avd'] or public.get('abi') != 'x86_64' or public.get('reversePorts') != [] or
                    public.get('mount') != native['currentMount'] or not isinstance(native['mountinfoSha256'], str) or not _SHA.fullmatch(native['mountinfoSha256']) or
                    not isinstance(native['historicalRecords'], dict) or set(native['historicalRecords']) != {'intent.json', 'mount-intent.json', 'stage-owned.json', 'cleanup-intent.json', 'cleaned.json'}):
                raise ValueError('Recovery receipt shape')
            android_native_fixture.write_private_plan(receipt_path, receipt)
            return _response('ready', correlation_id, owner=public['owner'], revision=public['revision'], recoveryOnly=True, **extra)
        reason = value.get('reason')
        allowed = {'recovery_lock_unverified', 'recovery_ready', 'recovery_target_restored', 'recovery_binding_invalid', 'recovery_original_changed', 'recovery_historical_changed',
                   'recovery_child_unknown', 'recovery_child_present', 'recovery_namespace_changed', 'recovery_current_stage_changed', 'recovery_historical_stage_present',
                   'recovery_post_unverified', 'recovery_inode_inventory_unknown', 'recovery_target_changed', 'recovery_descriptor_changed', 'recovery_target_ca_unverified', 'recovery_native_changed',
                   'recovery_already_recorded', 'recovery_observation_changed', 'recovery_receipt_changed', 'recovery_attempt_already_recorded', 'recovery_receipt_stale', 'recovery_unmount_uncertain'}
        reason = reason if reason in allowed else _readmission_reason(reason)
        observed = value.get('state') == 'partial' and reason in {'recovery_ready', 'recovery_target_restored'} and value.get('recoveryCorrelationId') == recovery_correlation_id
        return _response('partial' if observed else 'unknown', correlation_id, reason, **extra, **_bounded_readmission_diagnostics(value), **_bounded_endpoint_transport(value.get('transportDiagnostic')))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'recovery_local_unverified', **extra)


def _recovery_call(root: Path | str, correlation_id: str, historical_correlation_id: str,
                   recovery_correlation_id: str, action: str) -> dict[str, Any]:
    root = Path(root).resolve()
    ids = (correlation_id, historical_correlation_id, recovery_correlation_id)
    if not all(isinstance(x, str) and _UUID.fullmatch(x) for x in ids) or len(set(ids)) != 3:
        raise ValueError('Recovery requires three distinct canonical correlations')
    original = root / '.rag_index/android-endpoint-admission' / (correlation_id + '.json')
    extra = {'recoveryCorrelationId': recovery_correlation_id, 'historicalCorrelationId': historical_correlation_id,
             'observationOnly': action != 'recovery-unmount', 'replayAllowed': False}
    try:
        pinned = _recovery_local_snapshot(original)
        intent = pinned[0]
        lock_path = root / '.rag_index/android-native-device-leases' / ('lock-' + intent['host'] + '-' + intent['device'] + '.json')
        if action == 'recovery-status' and not os.path.lexists(lock_path):
            return _response('unknown', correlation_id, 'recovery_lock_unverified', **extra)
        with _shared_device_lease(root, intent['host'], intent['device']):
            if _recovery_local_snapshot(original) != pinned:
                raise ValueError('Recovery original changed while acquiring lock')
            return _recovery_call_locked(root, correlation_id, historical_correlation_id, recovery_correlation_id, action)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return _response('unknown', correlation_id, 'recovery_local_unverified', **extra)


def recovery_readmission(root: Path | str, correlation_id: str, historical_correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    """Create immutable admission for one proved historical deleted bind; no native effect."""
    return _recovery_call(root, correlation_id, historical_correlation_id, recovery_correlation_id, 'recovery-readmit')


def recovery_unmount_once(root: Path | str, correlation_id: str, historical_correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    """Dispatch one exact guarded unmount; both local and remote fences prevent replay."""
    return _recovery_call(root, correlation_id, historical_correlation_id, recovery_correlation_id, 'recovery-unmount')


def recovery_status(root: Path | str, correlation_id: str, historical_correlation_id: str, recovery_correlation_id: str) -> dict[str, Any]:
    """Observe the admitted mount or its proved retirement without changing records."""
    return _recovery_call(root, correlation_id, historical_correlation_id, recovery_correlation_id, 'recovery-status')
