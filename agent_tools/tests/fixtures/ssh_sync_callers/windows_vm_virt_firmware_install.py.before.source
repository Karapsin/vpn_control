"""Install one pinned Secure Boot firmware package through the configured Arch route.

The MCP surface can only name the configured Arch host and a canonical operation
correlation.  The sudo credential is read from the fixed private local file and
travels only through SSH stdin to the fixed remote ``sudo -S pacman`` process.
Neither the request, command argv, environment, journal, nor public result holds
credential bytes.  An accepted intent is one shot: uncertain transport outcomes
must be reconciled through ``status`` and are never replayed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # fixed MCP CLI fallback
    import ssh_transport  # type: ignore[no-redef]


HOST = "archlinux"
PACKAGE = "virt-firmware"
VERSION = "26.9-1"
REPOSITORY = "extra"
FIRMWARE_TOOL = "/usr/bin/virt-fw-vars"
CREDENTIAL_RELATIVE_PATH = Path(".codex") / "arch-sudo.local"
_UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
_MAX_CREDENTIAL_BYTES = 512

# The remote program deliberately emits only this typed result.  pacman is run
# without output forwarding, so a sudo or package diagnostic can never become a
# journal entry or an MCP result.  The normal pacman transaction performs its
# configured repository/package signature verification; Qkk supplies the
# post-install package file integrity proof.
_REMOTE = r'''import json,os,stat,subprocess,sys
HOST='archlinux';PACKAGE='virt-firmware';VERSION='26.9-1';REPOSITORY='extra';TOOL='/usr/bin/virt-fw-vars';MODE=__MODE__;CORR=__CORR__
def emit(state,signature=False,integrity=False):
 print(json.dumps({'schemaVersion':1,'host':HOST,'correlationId':CORR,'state':state,'package':PACKAGE,'version':VERSION,'pacmanSignatureVerified':signature,'packageIntegrityVerified':integrity,'firmwareToolPresent':state=='verified'},separators=(',',':'),sort_keys=True))
def executable(path):
 try:
  item=os.lstat(path)
  return stat.S_ISREG(item.st_mode) and os.access(path,os.X_OK)
 except OSError:return False
def run(argv,**kwargs):
 return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C',**kwargs.pop('env',{})},**kwargs)
def installed():
 # Re-run with a bounded private capture only for exact package identity; its
 # contents are not emitted and cannot contain the credential.
 detail=subprocess.run(['/usr/bin/pacman','-Q',PACKAGE],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
 if detail.returncode!=0 or len(detail.stdout)>128:return False
 return detail.stdout.decode('utf-8','strict').strip()==PACKAGE+' '+VERSION
try:
 if MODE=='start':
  secret=sys.stdin.buffer.read(513)
  if not 1<=len(secret)<=512 or b'\0' in secret:raise ValueError()
  # Deliberately omit --needed: a same-version installed package must still
  # traverse pacman's signature-checked transaction before signature success
  # can be published.
  install=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/pacman','-S','--noconfirm',REPOSITORY+'/'+PACKAGE+'='+VERSION],input=secret,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
  if install.returncode!=0:
   # stderr is deliberately suppressed to protect the credential.  It cannot
   # truthfully distinguish sudo authentication from a pacman transaction
   # failure, so retain one generic terminal outcome.
   emit('transaction-failed');raise SystemExit
  signature=True
 else: signature=False
 if not installed():emit('package-verification-failed');raise SystemExit
 integrity=run(['/usr/bin/pacman','-Qkk',PACKAGE]).returncode==0
 if not integrity or not executable(TOOL):emit('package-verification-failed',signature,integrity);raise SystemExit
 emit('verified',signature,True)
except (OSError,ValueError,UnicodeDecodeError,subprocess.TimeoutExpired):emit('unknown')
'''

_SIGNATURE_POLICY_REMOTE = r'''import json,os,stat,subprocess
def emit(state):
 print(json.dumps({'schemaVersion':1,'host':'archlinux','state':state},separators=(',',':'),sort_keys=True))
try:
 phase='path'
 info=os.stat('/usr/bin/pacman-conf')
 if not stat.S_ISREG(info.st_mode) or not os.access('/usr/bin/pacman-conf',os.X_OK):raise ValueError()
 def query(argv):return subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
 phase='repo-query';run=query(['/usr/bin/pacman-conf','--repo','extra','SigLevel'])
 if run.returncode!=0 or not 0<len(run.stdout)<=256:
  # pacman-conf returns nonzero for an unset repo-local value.  Determine
  # whether extra declares one without exporting it; only then inherit the
  # global effective value.  Any explicit repo SigLevel remains fail-closed.
  phase='repo-listing';listing=query(['/usr/bin/pacman-conf','--repo','extra'])
  if listing.returncode!=0 or len(listing.stdout)>4096:emit('repo-listing-failed');raise SystemExit
  lines=listing.stdout.decode('utf-8','strict').splitlines()
  if any(line.strip().startswith('SigLevel') for line in lines):emit('repo-override-unreadable');raise SystemExit
  phase='global-query';run=query(['/usr/bin/pacman-conf','SigLevel'])
  if run.returncode!=0:emit('global-query-failed');raise SystemExit
 if not 0<len(run.stdout)<=256:raise ValueError()
 phase='policy-parse';values=set(run.stdout.decode('utf-8','strict').split())
 rejected={'Never','Optional','PackageNever','PackageOptional','TrustAll','PackageTrustAll'}
 signatures=bool({'Required','PackageRequired'}&values)
 explicit=bool({'TrustedOnly','PackageTrustedOnly'}&values)
 # pacman defaults to TrustedOnly when TrustAll is absent; pacman-conf omits
 # that default from otherwise effective output, so expose it categorically.
 if signatures and not values.intersection(rejected):emit('required-trusted-explicit' if explicit else 'required-trusted-implicit')
 else:emit('rejected')
except (OSError,ValueError,UnicodeDecodeError,subprocess.TimeoutExpired):emit('unavailable-'+phase)
'''

_RUNTIME_REMOTE = r'''import json,os,stat
def executable(path):
 try:
  info=os.stat(path);return stat.S_ISREG(info.st_mode) and os.access(path,os.X_OK)
 except OSError:return False
state='remote-python-unavailable' if not executable('/usr/bin/python3') else 'pacman-conf-unavailable' if not executable('/usr/bin/pacman-conf') else 'ready'
print(json.dumps({'schemaVersion':1,'host':'archlinux','state':state},separators=(',',':'),sort_keys=True))
'''


def _validate(host: str, correlation_id: str, timeout_seconds: int) -> None:
    if (host != HOST or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id)
            or type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 300):
        raise ValueError("Virt-firmware install requires fixed host, canonical correlation and bounded timeout.")


def _credential_path(root: str | Path, override: Path | None = None) -> Path:
    return Path(override) if override is not None else Path(root).resolve() / CREDENTIAL_RELATIVE_PATH


def _read_credential(root: str | Path, *, credential_path: Path | None = None) -> bytes:
    """Read a small regular owner-only credential without following symlinks."""
    path = _credential_path(root, credential_path)
    if not path.is_absolute():
        raise ValueError("Arch sudo credential path is unsafe.")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent = os.open(path.parent, directory_flags)
    except OSError as error:
        raise ValueError("Arch sudo credential parent is unsafe.") from error
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_info = os.fstat(parent)
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.getuid()
                or directory_info.st_mode & 0o022):
            raise ValueError("Arch sudo credential parent is unsafe.")
        try:
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(path.name, flags, dir_fd=parent)
        except OSError as error:
            raise ValueError("Arch sudo credential is unavailable.") from error
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(named.st_mode) or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= _MAX_CREDENTIAL_BYTES
                    or (named.st_dev, named.st_ino, named.st_mtime_ns, named.st_size) !=
                       (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)):
                raise ValueError("Arch sudo credential is unsafe.")
            value = os.read(descriptor, _MAX_CREDENTIAL_BYTES + 1)
            if len(value) != info.st_size or b"\0" in value:
                raise ValueError("Arch sudo credential is unsafe.")
            return value
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _credential_metadata(root: str | Path) -> bool:
    """Validate only credential filesystem metadata; never open for reading."""
    path = _credential_path(root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent = os.open(path.parent, flags)
        try:
            directory = os.fstat(parent)
            item = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            return (stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
                    and not directory.st_mode & 0o022 and stat.S_ISREG(item.st_mode)
                    and item.st_uid == os.getuid() and stat.S_IMODE(item.st_mode) == 0o600
                    and 0 < item.st_size <= _MAX_CREDENTIAL_BYTES)
        finally:
            os.close(parent)
    except OSError:
        return False


def _journal(root: str | Path, *, create: bool) -> Path:
    directory = Path(root).resolve() / ".rag_index" / "windows-vm-virt-firmware-install"
    if create:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("Virt-firmware install journal directory is unsafe.")
    return directory / "intent.json"


def _intent(correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "correlationId": correlation_id, "host": HOST,
            "repository": REPOSITORY, "package": PACKAGE, "version": VERSION, "firmwareTool": FIRMWARE_TOOL}


def _save_intent(path: Path, correlation_id: str) -> None:
    payload = json.dumps(_intent(correlation_id), sort_keys=True, separators=(",", ":")).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _read_intent(path: Path, correlation_id: str) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 2048):
            raise ValueError("Virt-firmware install intent is unsafe.")
        raw = os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)
    if len(raw) != info.st_size or json.loads(raw) != _intent(correlation_id):
        raise ValueError("Virt-firmware install intent changed.")


def _parse_result(value: object, correlation_id: str) -> dict[str, Any]:
    states = {"verified", "transaction-failed", "package-verification-failed", "unknown"}
    required = {"schemaVersion", "host", "correlationId", "state", "package", "version",
                "pacmanSignatureVerified", "packageIntegrityVerified", "firmwareToolPresent"}
    if (not isinstance(value, Mapping) or set(value) != required or value.get("schemaVersion") != 1
            or value.get("host") != HOST or value.get("correlationId") != correlation_id
            or value.get("state") not in states or value.get("package") != PACKAGE
            or value.get("version") != VERSION
            or any(type(value.get(key)) is not bool for key in
                   ("pacmanSignatureVerified", "packageIntegrityVerified", "firmwareToolPresent"))):
        raise ValueError("Virt-firmware install response is invalid.")
    verified = value["state"] == "verified"
    if verified != (value["packageIntegrityVerified"] and value["firmwareToolPresent"]):
        raise ValueError("Virt-firmware install verification is contradictory.")
    if value["state"] == "unknown" and any(value[key] for key in
                                               ("pacmanSignatureVerified", "packageIntegrityVerified", "firmwareToolPresent")):
        raise ValueError("Virt-firmware install uncertainty is contradictory.")
    return dict(value)


def _remote(root: str | Path, correlation_id: str, mode: str, timeout_seconds: int,
            *, credential: bytes | None = None) -> dict[str, Any]:
    program = _REMOTE.replace("__MODE__", repr(mode)).replace("__CORR__", repr(correlation_id))
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60),
        command=("/usr/bin/python3", "-c", "exec(" + repr(program) + ")"),
        ssh_binary="/usr/bin/ssh", nested_ssh_binary="/usr/bin/ssh")
    completed = subprocess.run(argv, input=credential, stdin=subprocess.DEVNULL if credential is None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=timeout_seconds, check=False)
    if completed.returncode != 0 or not 0 < len(completed.stdout) <= 1024:
        raise ValueError("Virt-firmware install transport is unknown.")
    return _parse_result(json.loads(completed.stdout), correlation_id)


def _signature_policy_state(root: str | Path, timeout_seconds: int) -> str:
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        return "unavailable"
    argv = ssh_transport.build_ssh_argv(
        config, HOST, min(timeout_seconds, 60),
        command=("/usr/bin/python3", "-c", "exec(" + repr(_SIGNATURE_POLICY_REMOTE) + ")"),
        ssh_binary="/usr/bin/ssh", nested_ssh_binary="/usr/bin/ssh")
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
        if completed.returncode != 0 or not 0 < len(completed.stdout) <= 256:
            return "unavailable"
        value = json.loads(completed.stdout)
        if (isinstance(value, Mapping) and set(value) == {"schemaVersion", "host", "state"}
                and value.get("schemaVersion") == 1 and value.get("host") == HOST
                and (value.get("state") in {"required-trusted-explicit", "required-trusted-implicit", "rejected", "repo-listing-failed", "repo-override-unreadable", "global-query-failed"}
                     or isinstance(value.get("state"), str) and value["state"].startswith("unavailable-"))):
            return value["state"]
        return "unavailable"
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return "unavailable"


def _transport_diagnostic(root: str | Path, timeout_seconds: int) -> str:
    """Check only fixed executable/hop facts; no credential or raw diagnostics."""
    local = Path("/usr/bin/ssh")
    if not local.is_file() or not os.access(local, os.X_OK):
        return "local-ssh-unavailable"
    try:
        config = ssh_transport.load_config(Path(root).resolve(strict=True))
        gateway = ssh_transport.connection_host(config, HOST)
        fixed = {"ssh_binary": "/usr/bin/ssh", "nested_ssh_binary": "/usr/bin/ssh"}
        gateway_argv = ssh_transport.build_ssh_argv(config, gateway.alias, min(timeout_seconds, 60),
                                                     command=("/usr/bin/test", "-x", "/usr/bin/ssh"), **fixed)
        gateway_run = subprocess.run(gateway_argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
        if gateway_run.returncode != 0:
            return "gateway-ssh-unavailable"
        target_argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60),
                                                    command=("/usr/bin/true",), **fixed)
        target_run = subprocess.run(target_argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
        if target_run.returncode != 0:
            return "nested-ssh-unavailable"
        runtime_argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60),
            command=("/usr/bin/python3", "-c", "exec(" + repr(_RUNTIME_REMOTE) + ")"), **fixed)
        runtime = subprocess.run(runtime_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=timeout_seconds, check=False)
        if runtime.returncode != 0 or not 0 < len(runtime.stdout) <= 256:
            return "remote-runtime-unavailable"
        payload = json.loads(runtime.stdout)
        if (isinstance(payload, Mapping) and set(payload) == {"schemaVersion", "host", "state"}
                and payload.get("schemaVersion") == 1 and payload.get("host") == HOST
                and payload.get("state") in {"ready", "remote-python-unavailable", "pacman-conf-unavailable"}):
            return payload["state"]
        return "remote-runtime-unavailable"
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return "transport-unavailable"


def _signature_policy(root: str | Path, timeout_seconds: int) -> bool:
    return _signature_policy_state(root, timeout_seconds).startswith("required-trusted-")


def _intent_state(root: str | Path, correlation_id: str) -> str:
    try:
        path = _journal(root, create=False)
    except FileNotFoundError:
        return "absent"
    try:
        _read_intent(path, correlation_id)
        return "existing"
    except (OSError, ValueError):
        return "existing"


def preflight(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    """Return categorical read-only admission facts without reading credentials."""
    _validate(host, correlation_id, timeout_seconds)
    policy: str | None = None
    diagnostic: str | None = None
    if _intent_state(root, correlation_id) != "absent":
        state = "intent-existing"
    else:
        diagnostic = _transport_diagnostic(root, timeout_seconds)
        if diagnostic != "ready":
            state = "transport-unavailable"
        else:
            policy = _signature_policy_state(root, timeout_seconds)
            if policy.startswith("unavailable-") or policy in {"repo-listing-failed", "repo-override-unreadable", "global-query-failed"}:
                state = "signature-policy-unavailable"
            elif policy == "rejected":
                state = "signature-policy-rejected"
            elif not _credential_metadata(root):
                state = "credential-metadata-invalid"
            else:
                state = "ready"
    return {"correlationId": correlation_id, "host": HOST, "state": state,
            "signaturePolicy": policy,
            "transportDiagnostic": diagnostic,
            "credentialMetadataValid": state == "ready", "safeStartAllowed": state == "ready",
            "newCorrelationRequired": True, "nativeActionAllowed": False}


def _public(result: Mapping[str, Any], correlation_id: str) -> dict[str, Any]:
    state = result.get("state", "unknown")
    return {"correlationId": correlation_id, "host": HOST, "state": state,
            "package": PACKAGE, "version": VERSION,
            "pacmanSignatureVerified": result.get("pacmanSignatureVerified") is True,
            "packageIntegrityVerified": result.get("packageIntegrityVerified") is True,
            "firmwareToolPresent": result.get("firmwareToolPresent") is True,
            "replayAllowed": False, "nativeActionAllowed": False}


def start(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 180,
          credential_path: Path | None = None) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    try:
        existing = _journal(root, create=False)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        _read_intent(existing, correlation_id)
        raise ValueError("Virt-firmware install intent already exists; use exact status.")
    if not _signature_policy(root, timeout_seconds):
        raise ValueError("Arch pacman signature policy is unavailable.")
    # Admit the private input before claiming the one-shot correlation.  A
    # corrected local file may then be submitted without manufacturing an
    # irreversible unknown remote operation.
    credential = _read_credential(root, credential_path=credential_path)
    path = _journal(root, create=True)
    try:
        _save_intent(path, correlation_id)
    except FileExistsError as error:
        raise ValueError("Virt-firmware install intent already exists; use exact status.") from error
    try:
        # The only test seam is the private local file path; MCP never supplies it.
        result = _remote(root, correlation_id, "start", timeout_seconds, credential=credential)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return _public(result, correlation_id)


def status(root: str | Path, *, host: str, correlation_id: str, timeout_seconds: int = 60) -> dict[str, Any]:
    _validate(host, correlation_id, timeout_seconds)
    try:
        _read_intent(_journal(root, create=False), correlation_id)
    except FileNotFoundError:
        return {"correlationId": correlation_id, "host": HOST, "state": "intent-absent",
                "package": PACKAGE, "version": VERSION, "pacmanSignatureVerified": False,
                "packageIntegrityVerified": False, "firmwareToolPresent": False,
                "replayAllowed": False, "nativeActionAllowed": False}
    try:
        result = _remote(root, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return _public(result, correlation_id)
