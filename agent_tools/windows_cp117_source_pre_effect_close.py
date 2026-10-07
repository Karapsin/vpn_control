"""Fixed, evidence-only closure for source campaign 67's lost pre-effect start reply."""
from __future__ import annotations

import base64
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_cp117_protected_journal as protected_journal
from . import windows_cp117_retirement_guards as guards
from . import windows_cp117_source_campaign as source
from . import windows_msi_base_prepare as base

_CORRELATION = "67eeeedb-a618-42d5-8e31-821650d16302"
_HASH = __import__("re").compile(r"[0-9a-f]{64}\Z")
_UNKNOWN = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
PHASES = frozenset({"local-intent", "pair", "descriptor", "local-journal", "remote-journal", "guest-census", "readiness", "marker-conflict", "verified-absence", "closed"})
_GUEST_CENSUS_PHASES = frozenset({"observed", "unsafe", *base._UNKNOWN_CLEANUP_PHASES})
_MARKER_SUFFIX = ".source-pre-effect-closed.json"
_GUEST_FIELDS = frozenset({"state", "correlationId", "remoteStage", "mutation", "task", "leaf", "result", "correlationPowerShell", "product", "installedVersion", "installer"})
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
_LEAF_RETIREMENT = "43825a56-5562-4283-a05c-3666d82cf7fa"
_LEAF_SIZE = 131101044
_LEAF_SHA256 = "539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd"
_LEAF_RETIRE_DIR = ".rag_index/windows-cp117-source67-leaf-retire"
_LEAF_JOURNAL = r"C:\ProgramData\VpnControlCp117-retirement-" + _LEAF_RETIREMENT
_LEAF_JOURNAL_LEAVES = ("binding.json", "archive.json", "terminal.json")
def _no_effect_program() -> str:
    """Keep the inherited census read-only and parse its exact PS5 payload."""
    program = base._UNKNOWN_CLEANUP.replace("'2.1.17'", "'2.1.19'")
    # A plain correlation search misses EncodedCommand. Conservatively block
    # every other PowerShell process in this disposable guest.
    program = program.replace("$_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match [regex]::Escape($corr)",
                              "$_.ProcessId -ne $PID")
    program = program.replace("name='msiexec.exe'", "name='msiexec.exe' OR name='consent.exe'")
    args = "root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid,mode=sys.argv[1:]"
    program = program.replace(args, args + "\nif corr!='67eeeedb-a618-42d5-8e31-821650d16302' or mode!='status':raise ValueError('fixed observation only')", 1)
    guard = "  if len(encoded)>=30000:raise ValueError()\n"
    parser = r'''  import gzip
  packed=base64.b64encode(gzip.compress(script.encode('utf-16le'),mtime=0)).decode('ascii')
  parser="$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([byte[]][Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$z.CopyTo($o);$s=[Text.Encoding]::Unicode.GetString($o.ToArray())}finally{$z.Dispose();$i.Dispose();$o.Dispose()};$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);[Console]::Out.WriteLine((@{version=1;valid=($e.Count -eq 0)}|ConvertTo-Json -Compress))"
  parser_encoded=base64.b64encode(parser.encode('utf-16le')).decode('ascii')
  if len(parser_encoded)>=30000:raise ValueError()
  parser_child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',parser_encoded],'capture-output':True})['pid']
  if type(parser_child)is not int or parser_child<=0:raise ValueError()
  for _ in range(40):
   parsed=call(sock,'guest-exec-status',{'pid':parser_child})
   if not isinstance(parsed,dict):raise ValueError()
   if parsed.get('exited')is True:break
   if parsed.get('exited')is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if type(parsed.get('exitcode'))is not int or parsed['exitcode']!=0 or parsed.get('out-truncated',False) or parsed.get('err-truncated',False):raise ValueError()
  parser_raw=base64.b64decode(parsed.get('out-data',''),validate=True)
  if not 0<len(parser_raw)<=256:raise ValueError()
  if json.loads(decode(parser_raw).strip())!={'version':1,'valid':True}:raise ValueError()
'''
    if program.count(guard) != 1:
        raise ValueError("Fixed census parser insertion is ambiguous.")
    return program.replace(guard, guard + parser, 1)


_NO_EFFECT_REMOTE = _no_effect_program()

# Runs over the already bound QGA channel. It reads no arbitrary paths and never creates a journal.
_REMOTE_JOURNAL = base._QGA + r'''import fcntl,json,os,re,stat,sys
root,env,corr,sock,pid,ticks=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
def safe_dir(path):
 info=os.lstat(path);return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
try:
 if env!='windows-cp117' or not live(sock,pid,ticks) or corr!='67eeeedb-a618-42d5-8e31-821650d16302':raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-cp117-campaign')
 if not safe_dir(root):raise ValueError()
 if not os.path.lexists(parent):out({'state':'absent'});raise SystemExit(0)
 if not safe_dir(parent):raise ValueError()
 if not os.path.lexists(group):out({'state':'absent'});raise SystemExit(0)
 if not safe_dir(group):raise ValueError()
 lock=os.path.join(group,'.environment.lock')
 if not os.path.lexists(lock):raise ValueError()
 fd=os.open(lock,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError()
  fcntl.flock(fd,fcntl.LOCK_SH)
  names=set(os.listdir(group));allowed={'.environment.lock','active.json',corr+'.closed.json'}
  if any(name not in allowed and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.closed\.json',name) is None for name in names):raise ValueError()
  if 'active.json' in names or corr+'.closed.json' in names:out({'state':'present'});raise SystemExit(0)
  out({'state':'absent'})
 finally:os.close(fd)
except Exception:out({'state':'unknown'})
'''


def _marker(root: Path) -> Path:
    return root / base._LOCAL / (_CORRELATION + _MARKER_SUFFIX)


def _exact_request() -> dict[str, str]:
    return {"host": "archlinux", "correlationId": _CORRELATION, "sourceSha": source._SOURCE,
            "fixtureReceiptArtifactId": source._RECEIPT, "baseMsiArtifactId": source._BASE,
            "targetMsiArtifactId": source._TARGET, "expectedCurrentVersion": source._BASE_VERSION}


def _read_marker(path: Path, expected: Mapping[str, Any] | None = None) -> Mapping[str, Any] | None:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192:
            return None
        try: value = json.load(stream)
        except (ValueError, TypeError): return None
    if not isinstance(value, Mapping) or set(value) != {"version", "state", "correlationId", "intentSha256", "commandSha256", "pairSha256", "guestGeneration", "proof", "proofSha256"}:
        return None
    if (value.get("version") != 1 or value.get("state") != "verified-pre-effect-absence" or value.get("correlationId") != _CORRELATION
            or any(not isinstance(value.get(k), str) or _HASH.fullmatch(value[k]) is None for k in ("intentSha256", "commandSha256", "pairSha256", "proofSha256"))
            or not isinstance(value.get("guestGeneration"), Mapping) or not isinstance(value.get("proof"), Mapping)
            or hashlib.sha256(json.dumps(value["proof"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() != value["proofSha256"]):
        return None
    return value if expected is None or value == dict(expected) else None


def _intent(root: Path, descriptor: tuple[Any, ...]) -> tuple[Mapping[str, Any], Mapping[str, Any], str] | None:
    try:
        intent = base._private_intent(root, _CORRELATION)
        pair, _size = base._stage_artifact_readonly(root, intent)
        registered = source._new_pair(root)
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError):
        return None
    if (not isinstance(intent, Mapping) or intent.get("request") != _exact_request() or intent.get("leaseId") != _CORRELATION
            or not isinstance(registered, Mapping) or pair != registered or intent.get("pair") != pair):
        return None
    env, sock, pid, ticks, sid = descriptor
    if any(intent.get(key) != value for key, value in (("environment", env), ("socketPath", sock), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return None
    command = source._replacement_bootstrap(_CORRELATION, pair, sid)
    command_sha = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    if intent.get("commandSha256") != command_sha:
        return None
    return intent, pair, command_sha


def _leaf_retire_intent(root: Path) -> Path:
    return root / _LEAF_RETIRE_DIR / "intent.json"


def _leaf_retire_binding(root: Path, descriptor: tuple[Any, ...]) -> Mapping[str, Any] | None:
    """Bind the retained bytes only to source-67's original admitted pair."""
    if (not isinstance(descriptor, tuple) or len(descriptor) != 5 or descriptor[0] != "windows-cp117"
            or not isinstance(descriptor[1], str) or not descriptor[1]
            or type(descriptor[2]) is not int or descriptor[2] <= 0
            or type(descriptor[3]) is not int or descriptor[3] <= 0):
        return None
    admitted = _intent(root, descriptor)
    if admitted is None or descriptor[4] != "S-1-5-21-2404255130-2183793310-3766671872-1002":
        return None
    intent, pair, command = admitted
    try:
        _verified_pair, artifact_size = base._stage_artifact_readonly(root, intent)
    except (OSError, ValueError, TypeError, KeyError):
        return None
    if (artifact_size != _LEAF_SIZE or type(artifact_size) is not int or pair.get("baseArtifactId") != "sha256-" + _LEAF_SHA256
            or intent["request"].get("baseMsiArtifactId") != "sha256-" + _LEAF_SHA256):
        return None
    return {"retirementCorrelationId": _LEAF_RETIREMENT, "sourceCorrelationId": _CORRELATION,
            "commandSha256": command, "baseMsiSha256": _LEAF_SHA256, "baseMsiBytes": _LEAF_SIZE,
            "originalIntentSha256": _leaf_sha(intent), "pairSha256": _leaf_sha(pair),
            "generation": {"environment": descriptor[0], "socketPath": descriptor[1],
                           "qemuPid": descriptor[2], "startTicks": descriptor[3], "expectedSid": descriptor[4]}}


def _local_absent(root: Path, locks_held: bool = False) -> bool:
    directory = root / lease._DIR
    try: info = directory.lstat()
    except FileNotFoundError: return True
    try:
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return False
        lock = directory / ".environment.lock"
        fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            lock_info = os.fstat(fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or stat.S_IMODE(lock_info.st_mode) != 0o600:
                return False
            if not locks_held: fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            for item in (directory / "active.json", directory / (_CORRELATION + ".closed.json")):
                try: item.lstat()
                except FileNotFoundError: continue
                return False
            return True
        finally: os.close(fd)
    except OSError:
        return False


@contextmanager
def _closure_locks(root: Path):
    """Hold the existing base and lease locks from final proof through marker creation."""
    paths = (root / base._LOCAL / ".environment.lock", root / lease._DIR / ".environment.lock")
    fds: list[int] = []
    try:
        for path in paths:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                os.close(fd); raise OSError("unsafe closure lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); fds.append(fd)
        yield
    finally:
        for fd in reversed(fds): os.close(fd)


def _remote_absent(config: Any, target: Any, descriptor: tuple[Any, ...]) -> bool:
    env, sock, pid, ticks, _sid = descriptor
    try:
        raw = base._remote(config, _REMOTE_JOURNAL, (str(target.fixture_transfer_root), env, _CORRELATION, sock, str(pid), str(ticks)), None, 30)
        return json.loads(raw) == {"state": "absent"}
    except (OSError, ValueError, TypeError):
        return False


def _guest_census_shape(observed: Any) -> bool:
    """Accept only the bounded census grammar before exposing its outcome."""
    if (not isinstance(observed, Mapping) or set(observed) != _GUEST_FIELDS
            or observed.get("state") != "observed" or observed.get("correlationId") != _CORRELATION
            or observed.get("mutation") != "none" or observed.get("remoteStage") not in {"absent", "empty", "present"}
            or any(type(observed.get(key)) is not str or observed[key] not in {"absent", "present"}
                   for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))
            or observed.get("product") not in {"absent", "single", "multiple"}):
        return False
    version = observed.get("installedVersion")
    return ((observed["product"] == "single" and type(version) is str and _VERSION.fullmatch(version) is not None)
            or (observed["product"] != "single" and version is None))


def _guest_absence(observed: Any) -> Mapping[str, Any] | None:
    if not _guest_census_shape(observed):
        return None
    if (observed.get("remoteStage") != "absent" or observed.get("product") != "single"
            or observed.get("installedVersion") != source._BASE_VERSION
            or any(observed.get(key) != "absent" for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))):
        return None
    return dict(observed)


def _guest_absent(config: Any, target: Any, intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> Mapping[str, Any] | None:
    env, sock, pid, ticks, sid = descriptor
    request, pair = intent["request"], intent["pair"]
    try:
        raw = base._remote(config, _NO_EFFECT_REMOTE, (str(target.fixture_transfer_root), env, _CORRELATION,
            sock, str(pid), str(ticks), request["sourceSha"], pair["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid, "status"), None, 120)
        observed = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    return _guest_absence(observed)


def _guest_census_phase(config: Any, target: Any, intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> str | None:
    """Return only the fixed observer outcome; never disclose its census payload."""
    env, sock, pid, ticks, sid = descriptor
    request, pair = intent["request"], intent["pair"]
    try:
        raw = base._remote(config, _NO_EFFECT_REMOTE, (str(target.fixture_transfer_root), env, _CORRELATION,
            sock, str(pid), str(ticks), request["sourceSha"], pair["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid, "status"), None, 120)
        observed = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    if (isinstance(observed, Mapping) and set(observed) == {"state", "correlationId", "phase"}
            and observed.get("state") == "unknown" and observed.get("correlationId") == _CORRELATION
            and observed.get("phase") in _GUEST_CENSUS_PHASES):
        return str(observed["phase"])
    if _guest_absence(observed) is not None:
        return "observed"
    if _guest_census_shape(observed):
        return "unsafe"
    return None


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only, bounded failure locator for the fixed no-effect census."""
    if value != {}:
        raise ValueError("fixed source 67 census diagnostic requires empty inputs")
    path = Path(root).resolve(strict=True)
    try:
        config, target, descriptor = base._descriptor(path)
    except (OSError, ValueError, TypeError, KeyError):
        return {**_UNKNOWN, "state": "unknown", "phase": "descriptor", "correlationId": _CORRELATION}
    admitted = _intent(path, descriptor)
    if admitted is None:
        return {**_UNKNOWN, "state": "unknown", "phase": "local-intent", "correlationId": _CORRELATION}
    intent, _pair, _command_sha = admitted
    census_phase = _guest_census_phase(config, target, intent, descriptor)
    if census_phase is None:
        return {**_UNKNOWN, "state": "unknown", "phase": "guest-census", "correlationId": _CORRELATION}
    return {**_UNKNOWN, "state": "observed" if census_phase == "observed" else "unknown",
            "phase": "guest-census", "guestCensusPhase": census_phase, "correlationId": _CORRELATION}


def _ready(root: Path) -> Mapping[str, Any] | None:
    value = base.readiness(root, {"host": "archlinux", "expectedCurrentVersion": source._BASE_VERSION})
    if (not isinstance(value, Mapping) or value.get("state") != "ready" or value.get("ready") is not True
            or value.get("installedVersion") != source._BASE_VERSION or value.get("productCount") != 1
            or value.get("activeCount") != 0 or value.get("activeProcesses") != []):
        return None
    return {key: value[key] for key in ("installedVersion", "productCount", "activeCount", "activeProcesses")}


def _status(root: Path, *, locks_held: bool = False) -> tuple[str, Mapping[str, Any] | None]:
    try:
        config, target, descriptor = base._descriptor(root)
    except (OSError, ValueError, TypeError, KeyError):
        return "descriptor", None
    admitted = _intent(root, descriptor)
    if admitted is None: return "local-intent", None
    intent, pair, command_sha = admitted
    marker = _marker(root)
    if not _local_absent(root, locks_held): return "local-journal", None
    if not _remote_absent(config, target, descriptor) or not _remote_absent(config, target, descriptor): return "remote-journal", None
    first = _guest_absent(config, target, intent, descriptor); second = _guest_absent(config, target, intent, descriptor)
    if first is None or second is None: return "guest-census", None
    before = _ready(root); after = _ready(root)
    if before is None or after is None: return "readiness", None
    intent_sha = hashlib.sha256(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    pair_sha = hashlib.sha256(json.dumps(pair, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    env, sock, pid, ticks, sid = descriptor
    proof = {"first": first, "second": second, "before": before, "after": after,
             "remoteJournalAbsent": True, "localJournalAbsent": True}
    marker_value = {"version": 1, "state": "verified-pre-effect-absence", "correlationId": _CORRELATION,
                    "intentSha256": intent_sha, "commandSha256": command_sha, "pairSha256": pair_sha,
                    "guestGeneration": {"environment": env, "socketPath": sock, "qemuPid": pid, "startTicks": ticks, "expectedSid": sid}, "proof": proof,
                    "proofSha256": hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    try:
        _fresh_config, _fresh_target, refreshed = base._descriptor(root)
    except (OSError, ValueError, TypeError, KeyError):
        return "descriptor", None
    if refreshed != descriptor or _intent(root, refreshed) is None or not _local_absent(root, locks_held) or not _remote_absent(config, target, refreshed):
        return "descriptor", None
    if marker.exists():
        stored = _read_marker(marker)
        bindings = ("version", "state", "correlationId", "intentSha256", "commandSha256", "pairSha256", "guestGeneration")
        return ("closed", stored) if stored is not None and all(stored[key] == marker_value[key] for key in bindings) else ("marker-conflict", None)
    return "verified-absence", marker_value


def status(root: Path | str) -> dict[str, Any]:
    path = Path(root).resolve(strict=True)
    phase, _value = _status(path)
    state = "observed" if phase in {"verified-absence", "closed"} else "unknown"
    return {**_UNKNOWN, "state": state, "phase": phase, "correlationId": _CORRELATION}


def _archive_file(path: Path) -> bytes:
    """Read one immutable private archive input, without following links."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 1 <= before.st_size <= 8192):
            raise ValueError("archive input unavailable")
        raw = stream.read(8193)
        after = os.fstat(stream.fileno()); current = path.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_nlink)
        if len(raw) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
            raise ValueError("archive input changed")
        return raw


def archive_proof(root: Path | str, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """Recognize only the fixed closed marker with fresh same-generation proof.

    A retained intent remains consumed. This helper neither writes the marker nor
    submits an operation, and a changed guest generation stays blocked.
    """
    unknown = {**_UNKNOWN, "state": "unknown", "correlationId": _CORRELATION}
    phase = "intent"
    try:
        path = Path(root).resolve(strict=True)
        directory = path / base._LOCAL; info = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return {**unknown, "phase": phase}
        original = base._intent_path(path, _CORRELATION)
        intent_raw = _archive_file(original)
        admitted = _intent(path, descriptor)
        if admitted is None:
            return {**unknown, "phase": phase}
        intent, pair, command_sha = admitted
        if json.loads(intent_raw) != intent:
            return {**unknown, "phase": phase}
        phase = "marker"
        marker_raw = _archive_file(_marker(path)); marker = _read_marker(_marker(path))
        if marker is None or json.loads(marker_raw) != marker or type(marker["version"]) is not int:
            return {**unknown, "phase": phase}
        phase = "binding"
        generation = {"environment": descriptor[0], "socketPath": descriptor[1], "qemuPid": descriptor[2],
                      "startTicks": descriptor[3], "expectedSid": descriptor[4]}
        canonical_sha = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (marker["intentSha256"] != canonical_sha(intent) or marker["pairSha256"] != canonical_sha(pair)
                or marker["commandSha256"] != command_sha or marker["guestGeneration"] != generation
                or type(marker["guestGeneration"].get("qemuPid")) is not int
                or type(marker["guestGeneration"].get("startTicks")) is not int
                or type(intent.get("pid")) is not int or type(intent.get("startTicks")) is not int):
            return {**unknown, "phase": phase}
        proof = marker["proof"]
        if (set(proof) != {"first", "second", "before", "after", "remoteJournalAbsent", "localJournalAbsent"}
                or proof["remoteJournalAbsent"] is not True or proof["localJournalAbsent"] is not True):
            return {**unknown, "phase": phase}
        guest = {"state": "observed", "correlationId": _CORRELATION, "remoteStage": "absent", "mutation": "none",
                 "task": "absent", "leaf": "absent", "result": "absent", "correlationPowerShell": "absent",
                 "product": "single", "installedVersion": source._BASE_VERSION, "installer": "absent"}
        ready = {"installedVersion": source._BASE_VERSION, "productCount": 1, "activeCount": 0, "activeProcesses": []}
        if proof["first"] != guest or proof["second"] != guest or proof["before"] != ready or proof["after"] != ready:
            return {**unknown, "phase": phase}
        if any(type(proof[key].get(field)) is not int for key in ("before", "after") for field in ("productCount", "activeCount")):
            return {**unknown, "phase": phase}
        phase = "fresh"
        if base._descriptor(path)[2] != descriptor:
            return {**unknown, "phase": phase}
        observed = status(path)
        expected = {**_UNKNOWN, "state": "observed", "phase": "closed", "correlationId": _CORRELATION}
        if observed != expected or any(observed.get(key) is not False for key in _UNKNOWN if key != "state"):
            return {**unknown, "phase": phase}
        if (base._descriptor(path)[2] != descriptor or _archive_file(original) != intent_raw
                or _archive_file(_marker(path)) != marker_raw or _intent(path, descriptor) != admitted):
            return {**unknown, "phase": phase}
        return {**unknown, "state": "archived", "phase": "verified",
                "markerSha256": hashlib.sha256(marker_raw).hexdigest(),
                "intentSha256": marker["intentSha256"], "pairSha256": marker["pairSha256"],
                "commandSha256": command_sha, "closureReceiptSha256": marker["proofSha256"]}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError):
        return {**unknown, "phase": phase}


def close(root: Path | str) -> dict[str, Any]:
    path = Path(root).resolve(strict=True)
    try:
        with _closure_locks(path):
            phase, marker_value = _status(path, locks_held=True)
            if phase == "closed" and marker_value is not None:
                return {**_UNKNOWN, "state": "closed", "correlationId": _CORRELATION, "closureReceiptSha256": marker_value["proofSha256"]}
            if phase != "verified-absence" or marker_value is None:
                return {**_UNKNOWN, "state": "unknown", "phase": phase, "correlationId": _CORRELATION}
            if not _local_absent(path, locks_held=True):
                return {**_UNKNOWN, "state": "unknown", "phase": "local-journal", "correlationId": _CORRELATION}
            marker = _marker(path); data = (json.dumps(marker_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            try: fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError: return {**_UNKNOWN, "state": "unknown", "phase": "marker-conflict", "correlationId": _CORRELATION}
            with os.fdopen(fd, "wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
            parent = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(parent)
            finally: os.close(parent)
            if _read_marker(marker, marker_value) is None:
                return {**_UNKNOWN, "state": "unknown", "phase": "marker-conflict", "correlationId": _CORRELATION}
            return {**_UNKNOWN, "state": "closed", "correlationId": _CORRELATION, "closureReceiptSha256": marker_value["proofSha256"]}
    except OSError:
        return {**_UNKNOWN, "state": "unknown", "phase": "local-journal", "correlationId": _CORRELATION}


def workflow(root: Path | str, action: str, value: Mapping[str, Any]) -> dict[str, Any]:
    if action not in {"status", "close", "diagnose"} or value != {}:
        raise ValueError("fixed source 67 closure action requires empty inputs")
    if action == "status": return status(root)
    if action == "close": return close(root)
    return diagnose(root, value)



def _leaf_guest_census(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], *, retained: bool) -> bool:
    admitted = _intent(root, descriptor)
    if admitted is None: return False
    intent, pair, command = admitted
    env, sock, pid, ticks, sid = descriptor
    try:
        raw = base._remote(config, _NO_EFFECT_REMOTE, (str(target.fixture_transfer_root), env, _CORRELATION,
            sock, str(pid), str(ticks), intent["request"]["sourceSha"], pair["sourceFingerprint"],
            intent["request"]["fixtureReceiptArtifactId"], intent["request"]["baseMsiArtifactId"],
            intent["request"]["targetMsiArtifactId"], command, sid, "status"), None, 120)
        value = json.loads(raw) if raw is not None else None
        return (_guest_census_shape(value) and value["remoteStage"] == "absent" and value["product"] == "single"
            and value["installedVersion"] == source._BASE_VERSION and value["leaf"] == ("present" if retained else "absent")
            and all(value[k] == "absent" for k in ("task", "result", "correlationPowerShell", "installer")))
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _leaf_retire_record(root: Path) -> Mapping[str, Any] | None:
    path = _leaf_retire_intent(root)
    try:
        for directory in (path.parent.parent, path.parent):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o022 or (directory == path.parent and stat.S_IMODE(info.st_mode) != 0o700)):
                raise ValueError("unsafe leaf retirement journal directory")
        value = json.loads(_archive_file(path))
        return value if isinstance(value, Mapping) else None
    except FileNotFoundError:
        return None

def _leaf_sha(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _leaf_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _leaf_common(binding: Mapping[str, Any]) -> str:
    encoded = base64.b64encode(json.dumps(dict(binding), sort_keys=True, separators=(",", ":")).encode()).decode()
    return protected_journal.powershell(_LEAF_JOURNAL, _LEAF_JOURNAL_LEAVES) + r'''
$bindingText=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@BINDING@'));$binding=$bindingText|ConvertFrom-Json
$leaf='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-67eeeedb-a618-42d5-8e31-821650d16302'
$archiveLeaf='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-retired-43825a56-5562-4283-a05c-3666d82cf7fa'
$sid=$binding.generation.expectedSid
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class LeafIdentity {
 [StructLayout(LayoutKind.Sequential)] public struct Info {public uint attr; public uint createdLow; public uint createdHigh; public uint accessedLow; public uint accessedHigh; public uint writtenLow; public uint writtenHigh; public uint volume; public uint highSize; public uint lowSize; public uint links; public uint highId; public uint lowId;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sec,uint d,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static string Id(SafeFileHandle h) {Info i;if(!GetFileInformationByHandle(h,out i)||i.links!=1)throw new Exception("IDENTITY");return i.volume.ToString("x8")+":"+i.highId.ToString("x8")+i.lowId.ToString("x8");}
}
'@
function Identity([string]$path){$h=[LeafIdentity]::CreateFile($path,0,7,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero);try{if($h.IsInvalid){throw 'IDENTITY'};return [LeafIdentity]::Id($h)}finally{$h.Dispose()}}
function Digest([byte[]]$bytes){return ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}
function Ordered([object]$v){
 if($null-eq $v){return $null}
 if($v-is [Collections.IDictionary]){$o=[ordered]@{};foreach($k in @($v.Keys|Sort-Object)){$o[$k]=Ordered $v[$k]};return ,$o}
 if($v-is [pscustomobject]){$o=[ordered]@{};foreach($p in @($v.PSObject.Properties|Sort-Object Name)){$o[$p.Name]=Ordered $p.Value};return ,$o}
 if($v-is [array]){$a=@();foreach($i in $v){$a+=,(Ordered $i)};return ,$a};return $v
}
function Json([object]$v){return (ConvertTo-Json -InputObject (Ordered $v) -Depth 12 -Compress)}
function Metadata([string]$path,[bool]$directory){
 $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;Assert-NoReparse $item 'REPARSE';Assert-Ancestors $path
 if([bool]$item.PSIsContainer-ne $directory){throw 'TYPE'}
 $acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
 if($owner-cne $sid -or $acl.AreAccessRulesProtected){throw 'OWNER_ACL'}
 $expectedSddl='O:'+ $sid+'G:S-1-5-21-2404255130-2183793310-3766671872-513D:'+$(if($directory){'(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;'+$sid+')'}else{'(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;'+$sid+')'})
 if($acl.Sddl-cne $expectedSddl -or [int]$item.Attributes-ne $(if($directory){16}else{32})){throw 'SDDL_METADATA'}
 $rows=@(AclRows $path|Sort-Object sid);if($rows.Count-ne 3){throw 'ACL_COUNT'};$seen=@{}
 foreach($r in $rows){if($r.sid-notin @($sid,'S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($r.sid) -or $r.type-cne 'Allow' -or -not $r.inherited -or $r.propagation-ne 0 -or $r.inheritance-ne $(if($directory){3}else{0}) -or $r.rights-ne 2032127){throw 'ACL'};$seen[$r.sid]=$true}
 return [ordered]@{identity=(Identity $path);owner=$owner;protected=[bool]$acl.AreAccessRulesProtected;acl=$rows;sddl=$acl.Sddl;created=$item.CreationTimeUtc.Ticks.ToString();written=$item.LastWriteTimeUtc.Ticks.ToString();attributes=[int]$item.Attributes}
}
function Idle {
 if(@(Get-ScheduledTask -TaskPath '\' -TaskName 'VpnControlMcpBase-67eeeedb-a618-42d5-8e31-821650d16302' -ErrorAction SilentlyContinue).Count-ne 0){throw 'TASK'}
 $result=Join-Path $leaf 'result.json';if(Test-Path -LiteralPath $result){throw 'RESULT'}
 $p=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ProcessId-ne $PID -and $_.Name-match '^(powershell|pwsh|msiexec|consent|sing-box|vpn-control-cli)\.exe$'});if($p.Count-ne 0){throw 'ACTIVE'}
 $hku='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall';$hku32='Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
 $records=@();foreach($p in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',$hku,$hku32)){if(Test-Path -LiteralPath $p){$records+=@(Get-ItemProperty -Path ($p+'\*') -ErrorAction Stop)}};$products=@($records|Where-Object {$_.DisplayName-eq 'vpn-control'})
 if($products.Count-ne 1 -or $products[0].DisplayVersion-cne '2.1.19'){throw 'PRODUCT'}
}
function Snapshot([string]$path){
 $root=Metadata $path $true;$children=@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)
 if($children.Count-ne 1 -or $children[0].Name-cne 'base.msi' -or $children[0].PSIsContainer -or $children[0].Length-ne 131101044){throw 'MEMBERS'}
 $file=Join-Path $path 'base.msi';$before=Metadata $file $false
 $stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($stream.Length-ne 131101044){throw 'SIZE'};$id=[LeafIdentity]::Id($stream.SafeFileHandle);$hash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream))).Replace('-','').ToLowerInvariant();if($hash-cne '539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd' -or $id-cne $before.identity){throw 'HASH_ID'};$after=Metadata $file $false;if((Json $after)-cne (Json $before)){throw 'FILE_CHANGED'}}finally{$stream.Dispose()}
 $again=Metadata $path $true;if((Json $again)-cne (Json $root)){throw 'ROOT_CHANGED'}
 return [ordered]@{root=$root;file=$before;bytes=131101044;sha256=$hash}
}
'''.replace('@BINDING@', encoded)


def _leaf_script(binding: Mapping[str, Any], mode: str, proof: Mapping[str, Any] | None = None) -> str:
    if mode not in {'preflight', 'start', 'status'}:
        raise ValueError('fixed leaf retirement mode')
    common = _leaf_common(binding)
    if mode == 'preflight':
        return common + r'''
Idle;if(Test-Path -LiteralPath $JournalRoot){throw 'JOURNAL_PRESENT'};if(Test-Path -LiteralPath $archiveLeaf){throw 'DESTINATION_PRESENT'}
$first=Snapshot $leaf;Idle;$second=Snapshot $leaf;if((Json $first)-cne (Json $second)){throw 'SNAPSHOT_CHANGED'}
[Console]::Out.WriteLine((Json $second))
'''
    proof_text = json.dumps(dict(proof or {}), sort_keys=True, separators=(',', ':'))
    expected = base64.b64encode(proof_text.encode()).decode()
    common += "$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + expected + "'))|ConvertFrom-Json\n"
    if mode == 'start':
        return common + r'''
Idle;if(Test-Path -LiteralPath $JournalRoot){throw 'JOURNAL_PRESENT'};if(Test-Path -LiteralPath $archiveLeaf){throw 'DESTINATION_PRESENT'}
$first=Snapshot $leaf;if((Json $first)-cne (Json $expected)){throw 'PREIMAGE'}
$actionHash=Digest ([Text.Encoding]::UTF8.GetBytes($s));if([string]::IsNullOrEmpty($s)){throw 'ACTION_SOURCE'}
Write-SecureJsonCreate 'binding.json' (Json ([ordered]@{binding=$binding;mutationSha256=$actionHash}))
Write-SecureJsonCreate 'archive.json' (Json $first)
$b=Read-SecureJson 'binding.json';$a=Read-SecureJson 'archive.json'
if(@($b.PSObject.Properties).Count-ne 2 -or (Json $b.binding)-cne (Json $binding) -or $b.mutationSha256-cne $actionHash -or (Json $a)-cne (Json $expected)){throw 'ARCHIVE_READ'}
Idle;$second=Snapshot $leaf;if((Json $second)-cne (Json $a)){throw 'PREIMAGE_CHANGED'}
if(Test-Path -LiteralPath $archiveLeaf){throw 'DESTINATION_PRESENT'}
[IO.Directory]::Move($leaf,$archiveLeaf)
if(Test-Path -LiteralPath $leaf){throw 'SOURCE_PRESENT'}
$archived=Snapshot $archiveLeaf;if((Json $archived)-cne (Json $a)){throw 'ARCHIVE_CHANGED'};Idle
Write-SecureJsonCreate 'terminal.json' (Json ([ordered]@{state='retired';bindingSha256=(Digest ([Text.Encoding]::UTF8.GetBytes($bindingText)));archiveSha256=(Digest ([Text.Encoding]::UTF8.GetBytes((Json $a))))}))
[Console]::Out.WriteLine('{"state":"terminal"}')
'''
    action_hash = hashlib.sha256(_leaf_script(binding, 'start', proof).encode()).hexdigest()
    return common + r'''
Idle;$b=Read-SecureJson 'binding.json';$a=Read-SecureJson 'archive.json';$t=Read-SecureJson 'terminal.json'
if(@($b.PSObject.Properties).Count-ne 2 -or @($t.PSObject.Properties).Count-ne 3 -or (Json $b.binding)-cne (Json $binding) -or $b.mutationSha256-cne '@ACTIONHASH@' -or (Json $a)-cne (Json $expected) -or $t.state-cne 'retired' -or $t.bindingSha256-cne (Digest ([Text.Encoding]::UTF8.GetBytes($bindingText))) -or $t.archiveSha256-cne (Digest ([Text.Encoding]::UTF8.GetBytes((Json $a))))){throw 'JOURNAL'}
if(Test-Path -LiteralPath $leaf){throw 'SOURCE_PRESENT'};$current=Snapshot $archiveLeaf;if((Json $current)-cne (Json $a)){throw 'ARCHIVE_CHANGED'};Idle
[Console]::Out.WriteLine('{"state":"terminal"}')
'''.replace('@ACTIONHASH@', action_hash)


def _leaf_proof(value: Any, binding: Mapping[str, Any]) -> bool:
    if (not isinstance(value, Mapping) or set(value) != {'root', 'file', 'bytes', 'sha256'}
            or type(value['bytes']) is not int or value['bytes'] != _LEAF_SIZE or value['sha256'] != _LEAF_SHA256):
        return False
    sid = binding['generation']['expectedSid']
    for key, inheritance in (('root', 3), ('file', 0)):
        item = value[key]
        if (not isinstance(item, Mapping) or set(item) != {'identity','owner','protected','acl','sddl','created','written','attributes'}
                or item['owner'] != sid or item['protected'] is not False
                or not isinstance(item['identity'], str) or re.fullmatch('[0-9a-f]{8}:[0-9a-f]{16}', item['identity']) is None
                or not isinstance(item['sddl'], str) or not 1 <= len(item['sddl']) <= 2048
                or any(not isinstance(item[x], str) or re.fullmatch('[0-9]{1,19}', item[x]) is None for x in ('created','written'))
                or type(item['attributes']) is not int or item['attributes'] != (16 if key == 'root' else 32)):
            return False
        expected_sddl = 'O:' + sid + 'G:S-1-5-21-2404255130-2183793310-3766671872-513D:'
        flag = 'OICIID' if key == 'root' else 'ID'
        expected_sddl += '(A;' + flag + ';FA;;;SY)(A;' + flag + ';FA;;;BA)(A;' + flag + ';FA;;;' + sid + ')'
        if item['sddl'] != expected_sddl: return False
        rows = item['acl']
        if not isinstance(rows, list) or len(rows) != 3:
            return False
        seen = set()
        for row in rows:
            if (not isinstance(row, Mapping) or set(row) != {'sid','rights','type','inherited','inheritance','propagation'}
                    or row['sid'] not in {sid,'S-1-5-18','S-1-5-32-544'} or row['sid'] in seen
                    or type(row['rights']) is not int or row['rights'] != 2032127 or row['type'] != 'Allow'
                    or row['inherited'] is not True or type(row['inheritance']) is not int or row['inheritance'] != inheritance
                    or type(row['propagation']) is not int or row['propagation'] != 0):
                return False
            seen.add(row['sid'])
    return value['root']['identity'][:8] == value['file']['identity'][:8]


def _leaf_wrapper(script: str) -> str:
    import gzip
    packed = base64.b64encode(gzip.compress(script.encode(), mtime=0)).decode()
    return ("$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([byte[]][Convert]::FromBase64String('"+packed+"'));"
            "$z=[IO.Compression.GzipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();"
            "try{$z.CopyTo($o);$s=[Text.Encoding]::UTF8.GetString($o.ToArray())}finally{$z.Dispose();$i.Dispose();$o.Dispose()};"
            "& ([scriptblock]::Create($s))")


_LEAF_READ_REMOTE = base._READINESS.replace('range(40)', 'range(240)').replace('len(raw)>4096', 'len(raw)>8192')


def _leaf_run(config: Any, descriptor: tuple[Any, ...], script: str) -> Mapping[str, Any] | None:
    encoded = base64.b64encode(_leaf_wrapper(script).encode('utf-16le')).decode()
    if len(encoded) >= 30000: return None
    raw = base._remote(config, _LEAF_READ_REMOTE, (descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 90)
    try:
        if raw is None or len(raw) > 9000: return None
        outer = json.loads(raw)
        if not isinstance(outer, Mapping) or set(outer) != {'state','inventory'} or outer['state'] != 'observed' or not isinstance(outer['inventory'], Mapping): return None
        return dict(outer['inventory'])
    except (TypeError, ValueError):
        return None


def _leaf_parse(config: Any, descriptor: tuple[Any, ...], script: str) -> bool:
    from . import windows_cp117_c32_retained_task_retire as transport
    # The compressed parser contains the full prospective source and does not invoke it.
    return _leaf_run(config, descriptor, transport._parse_script(script)) == {'valid': True}


def _leaf_retire_dispatch(root: Path, config: Any, descriptor: tuple[Any, ...], script: str) -> Mapping[str, Any] | None:
    from . import windows_cp117_c32_retained_task_retire as transport
    encoded = base64.b64encode(_leaf_wrapper(script).encode('utf-16le')).decode()
    if len(encoded) >= 30000: return None
    _config, target, fresh = base._descriptor(root)
    if fresh != descriptor: return None
    remote = transport._REMOTE_DISPATCH.replace('range(80)', 'range(240)')
    raw = base._remote(config, remote, (str(target.fixture_transfer_root), descriptor[0], descriptor[1], str(descriptor[2]), str(descriptor[3]), encoded), None, 90)
    try:
        if raw is None or len(raw) > 1024: return None
        outer = json.loads(raw)
        return {'state':'terminal'} if outer == {'state':'observed','receipt':{'state':'terminal'}} else None
    except (TypeError, ValueError):
        return None


def _leaf_retire_ready(root: Path, *, locks_held: bool = False):
    phase = 'descriptor'
    try:
        config, target, descriptor = base._descriptor(root)
        binding = _leaf_retire_binding(root, descriptor)
        if binding is None: return None, None, None, None, 'binding'
        phase = 'lease'
        if not _local_absent(root, locks_held): return None, None, None, None, phase
        phase = 'remote-journal'
        if not _remote_absent(config, target, descriptor) or not _remote_absent(config, target, descriptor):
            return None, None, None, None, phase
        phase = 'guest-census'
        if not _leaf_guest_census(root, config, target, descriptor, retained=True): return None, None, None, None, phase
        phase = 'readiness'
        if _ready(root) is None or _ready(root) is None: return None, None, None, None, phase
        phase = 'parser'
        preflight = _leaf_script(binding, 'preflight')
        if not _leaf_parse(config, descriptor, preflight): return None, None, None, None, phase
        phase = 'owned-leaf'
        proof = _leaf_run(config, descriptor, preflight)
        if not _leaf_proof(proof, binding): return None, None, None, None, phase
        second = _leaf_run(config, descriptor, preflight)
        if second != proof or base._descriptor(root)[2] != descriptor or _leaf_retire_binding(root, descriptor) != binding or not _leaf_guest_census(root, config, target, descriptor, retained=True):
            return None, None, None, None, 'recheck'
        phase = 'parser'
        if not _leaf_parse(config, descriptor, _leaf_script(binding, 'start', proof)) or not _leaf_parse(config, descriptor, _leaf_script(binding, 'status', proof)):
            return None, None, None, None, phase
        return config, descriptor, binding, proof, 'ready'
    except (OSError, ValueError, TypeError, KeyError):
        return None, None, None, None, phase


def leaf_retire_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}: raise ValueError('fixed source67 leaf retirement takes no inputs')
    path = Path(root).resolve(strict=True)
    if os.path.lexists(_leaf_retire_intent(path)): return {**_UNKNOWN, 'state':'blocked','phase':'intent'}
    _, _, _, _, phase = _leaf_retire_ready(path)
    return {**_UNKNOWN, 'state':'ready' if phase == 'ready' else 'blocked', 'phase':phase, 'retirementCorrelationId':_LEAF_RETIREMENT}


def leaf_retire_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if value != {}: raise ValueError('fixed source67 leaf retirement takes no inputs')
    path = Path(root).resolve(strict=True)
    if os.path.lexists(_leaf_retire_intent(path)): return leaf_retire_status(path, {})
    phase = 'locks'
    try:
        with _closure_locks(path):
            if os.path.lexists(_leaf_retire_intent(path)): return leaf_retire_status(path, {}, _locks_held=True)
            if not _local_absent(path, True): return {**_UNKNOWN,'state':'blocked','phase':'lease'}
            config, descriptor, binding, proof, phase = _leaf_retire_ready(path, locks_held=True)
            if phase != 'ready': return {**_UNKNOWN,'state':'blocked','phase':phase}
            script = _leaf_script(binding, 'start', proof)
            intent = {'version':1,'binding':binding,'proof':proof,'bindingSha256':_leaf_sha(binding),'proofSha256':_leaf_sha(proof),
                      'mutationSha256':hashlib.sha256(script.encode()).hexdigest()}
            journal_parent = path / '.rag_index'
            parent_info = journal_parent.lstat()
            if not stat.S_ISDIR(parent_info.st_mode) or journal_parent.is_symlink() or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
                return {**_UNKNOWN,'state':'blocked','phase':'intent'}
            guards.secure_write_create(_leaf_retire_intent(path), intent)
            phase = 'recheck'
            if base._descriptor(path)[2] != descriptor or not _local_absent(path, True):
                return {**_UNKNOWN,'state':'unknown','phase':phase}
            phase = 'dispatch'
            if _leaf_retire_dispatch(path, config, descriptor, script) != {'state':'terminal'}:
                return {**_UNKNOWN,'state':'unknown','phase':phase}
    except (OSError, ValueError, TypeError, KeyError):
        return {**_UNKNOWN,'state':'unknown','phase':phase}
    return leaf_retire_status(path, {})


def leaf_retire_status(root: Path | str, value: Mapping[str, Any], *, _locks_held: bool = False) -> dict[str, Any]:
    if value != {}: raise ValueError('fixed source67 leaf retirement takes no inputs')
    path = Path(root).resolve(strict=True); phase = 'intent'
    try:
        intent = _leaf_retire_record(path)
        if not isinstance(intent, Mapping) or set(intent) != {'version','binding','proof','bindingSha256','proofSha256','mutationSha256'} or type(intent['version']) is not int or intent['version'] != 1:
            return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase = 'binding';config, target, descriptor = base._descriptor(path);binding = _leaf_retire_binding(path, descriptor)
        proof = intent['proof']
        if (binding is None or intent['binding'] != binding or intent['bindingSha256'] != _leaf_sha(binding)
                or not _leaf_proof(proof, binding) or intent['proofSha256'] != _leaf_sha(proof)
                or intent['mutationSha256'] != hashlib.sha256(_leaf_script(binding, 'start', proof).encode()).hexdigest()):
            return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase = 'lease'
        if not _local_absent(path, _locks_held) or not _remote_absent(config, target, descriptor) or _ready(path) is None:
            return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase = 'parser';reader = _leaf_script(binding, 'status', proof)
        if not _leaf_parse(config, descriptor, reader): return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase = 'terminal'
        for _ in range(2):
            if (_leaf_run(config, descriptor, reader) != {'state':'terminal'} or base._descriptor(path)[2] != descriptor
                    or _leaf_retire_binding(path, descriptor) != binding or not _local_absent(path, _locks_held)
                    or not _remote_absent(config, target, descriptor) or _ready(path) is None or not _leaf_guest_census(path, config, target, descriptor, retained=False)
                    or _leaf_retire_record(path) != intent):
                return {**_UNKNOWN,'state':'unknown','phase':phase}
        return {**_UNKNOWN,'state':'retired','phase':'verified','retirementCorrelationId':_LEAF_RETIREMENT}
    except (OSError, ValueError, TypeError, KeyError):
        return {**_UNKNOWN,'state':'unknown','phase':phase}


_LEAF_DIAG_REMOTE = base._QGA + r'''import time
sock,pid,ticks,encoded=sys.argv[1:]
phase='generation';exit_code=None
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or len(encoded)>=30000:raise ValueError()
 phase='guest-submit'
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child)is not int or child<=0:raise ValueError()
 phase='guest-wait'
 for _ in range(240):
  state=call(sock,'guest-exec-status',{'pid':child})
  if not isinstance(state,dict):raise ValueError()
  if state.get('exited')is True:break
  if state.get('exited')is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 phase='generation'
 if not live(sock,pid,ticks):raise ValueError()
 phase='guest-exit'
 if type(state.get('exitcode'))is not int or not 0<=state['exitcode']<=4294967295:raise ValueError()
 exit_code=state['exitcode']
 if exit_code!=0:raise ValueError()
 phase='guest-output'
 if state.get('out-truncated',False)is not False or state.get('err-truncated',False)is not False:raise ValueError()
 raw=base64.b64decode(state.get('out-data',''),validate=True)
 if not 0<len(raw)<=1024:raise ValueError()
 lines=decode(raw).splitlines()
 if len(lines)!=1:raise ValueError()
 out({'state':'observed','inventory':json.loads(lines[0])})
except Exception:
 result={'state':'unknown','phase':phase}
 if phase=='guest-exit' and exit_code is not None:result['exitCode']=exit_code
 out(result)
'''
_LEAF_DIAG_TRANSPORT_PHASES = frozenset({'generation','guest-submit','guest-wait','guest-exit','guest-output','transport'})
_LEAF_DIAG_PS_PHASES = frozenset({'construction','idle-before','journal-read','journal-binding','source-absence','archive-snapshot','archive-match','idle-after','verified'})
_LEAF_DIAG_PS_CODES = frozenset({'TASK','RESULT','ACTIVE','PRODUCT','JOURNAL','SOURCE_PRESENT','ARCHIVE_CHANGED',
    'REPARSE','ANCESTOR_REPARSE','TYPE','OWNER_ACL','SDDL_METADATA','ACL_COUNT','ACL','MEMBERS','SIZE','HASH_ID',
    'FILE_CHANGED','ROOT_CHANGED','ROOT_TYPE','ROOT_REPARSE','ROOT_ACL_PROTECTED','ROOT_OWNER','ROOT_ACL_COUNT','ROOT_ACL',
    'LEAF','LEAF_TYPE','LEAF_REPARSE','LEAF_SIZE','LEAF_ACL_PROTECTED','LEAF_OWNER','LEAF_ACL_COUNT','LEAF_ACL',
    'HANDLE_SIZE','HANDLE_READ','HANDLE_CHANGED','other'})


def _leaf_diagnostic_script(binding: Mapping[str, Any], proof: Mapping[str, Any]) -> str:
    """Observe the exact retained terminal reader with finite, redacted failures.

    This derives only from the read-only status source. The original mutation
    rendering and its journal hash remain byte-for-byte unchanged.
    """
    reader = _leaf_script(binding, 'status', proof)
    anchor = "\nIdle;$b=Read-SecureJson 'binding.json'"
    if reader.count(anchor) != 1:
        raise ValueError('fixed terminal diagnostic boundary unavailable')
    definitions, body = reader.split(anchor, 1)
    body = "Idle;$b=Read-SecureJson 'binding.json'" + body
    body = body.replace("Idle;$b=", "$diagPhase='idle-before';Idle;$diagPhase='journal-read';$b=", 1)
    body = body.replace("\nif(@($b.PSObject.Properties)", "\n$diagPhase='journal-binding';if(@($b.PSObject.Properties)", 1)
    body = body.replace("\nif(Test-Path -LiteralPath $leaf)", "\n$diagPhase='source-absence';if(Test-Path -LiteralPath $leaf)", 1)
    body = body.replace("$current=Snapshot $archiveLeaf", "$diagPhase='archive-snapshot';$current=Snapshot $archiveLeaf", 1)
    body = body.replace("if((Json $current)-cne (Json $a))", "$diagPhase='archive-match';if((Json $current)-cne (Json $a))", 1)
    body = body.replace("{throw 'ARCHIVE_CHANGED'};Idle", "{throw 'ARCHIVE_CHANGED'};$diagPhase='idle-after';Idle", 1)
    body = body.replace("[Console]::Out.WriteLine('{\"state\":\"terminal\"}')", "[Console]::Out.WriteLine('{\"state\":\"checked\",\"phase\":\"verified\",\"guardCode\":\"none\"}')", 1)
    allowed = ','.join(_leaf_ps(code) for code in sorted(_LEAF_DIAG_PS_CODES - {'other'}))
    return "$diagPhase='construction';try{\n" + definitions + body + "\n}catch{$code='other';$message=$_.Exception.Message;if($message -cin @("+allowed+")){$code=$message};[Console]::Out.WriteLine((@{state='unknown';phase=$diagPhase;guardCode=$code}|ConvertTo-Json -Compress))}\n"


def _leaf_diag_run(config: Any, descriptor: tuple[Any, ...], script: str) -> Mapping[str, Any]:
    unknown = {'state':'unknown','phase':'transport'}
    encoded = base64.b64encode(_leaf_wrapper(script).encode('utf-16le')).decode()
    if len(encoded) >= 30000: return unknown
    try:
        raw = base._remote(config, _LEAF_DIAG_REMOTE, (descriptor[1],str(descriptor[2]),str(descriptor[3]),encoded),None,90)
        if raw is None or len(raw) > 1536: return unknown
        outer = json.loads(raw)
        if not isinstance(outer, Mapping): return unknown
        if (set(outer) in ({'state','phase'},{'state','phase','exitCode'}) and outer.get('state') == 'unknown'
                and outer.get('phase') in _LEAF_DIAG_TRANSPORT_PHASES):
            if 'exitCode' in outer and (outer['phase'] != 'guest-exit' or type(outer['exitCode']) is not int or not 0 <= outer['exitCode'] <= 4294967295): return unknown
            return dict(outer)
        value = outer.get('inventory')
        if set(outer) != {'state','inventory'} or outer.get('state') != 'observed' or not isinstance(value,Mapping) or set(value) != {'state','phase','guardCode'}:
            return unknown
        if value.get('state') == 'checked' and value.get('phase') == 'verified' and value.get('guardCode') == 'none': return dict(value)
        if value.get('state') == 'unknown' and value.get('phase') in _LEAF_DIAG_PS_PHASES - {'verified'} and value.get('guardCode') in _LEAF_DIAG_PS_CODES: return dict(value)
        return unknown
    except (OSError,ValueError,TypeError,KeyError):
        return unknown


def leaf_retire_diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only finite failure locator; its checked state is no retirement proof."""
    if value != {}: raise ValueError('fixed source67 leaf diagnostic takes no inputs')
    path = Path(root).resolve(strict=True); phase = 'intent'
    try:
        intent = _leaf_retire_record(path)
        if not isinstance(intent,Mapping) or set(intent) != {'version','binding','proof','bindingSha256','proofSha256','mutationSha256'} or type(intent['version']) is not int or intent['version'] != 1:
            return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase='descriptor';config,target,descriptor=base._descriptor(path)
        phase='binding';binding=_leaf_retire_binding(path,descriptor);proof=intent['proof']
        if (binding is None or intent['binding'] != binding or intent['bindingSha256'] != _leaf_sha(binding)
                or not _leaf_proof(proof,binding) or intent['proofSha256'] != _leaf_sha(proof)
                or intent['mutationSha256'] != hashlib.sha256(_leaf_script(binding,'start',proof).encode()).hexdigest()):
            return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase='local-lease'
        if not _local_absent(path): return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase='remote-lease'
        if not _remote_absent(config,target,descriptor): return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase='parser';script=_leaf_diagnostic_script(binding,proof)
        if not _leaf_parse(config,descriptor,script): return {**_UNKNOWN,'state':'unknown','phase':phase}
        phase='terminal-reader';result=_leaf_diag_run(config,descriptor,script)
        if result.get('state') != 'checked':
            return {**_UNKNOWN,'state':'unknown','phase':phase,'terminalDiagnostic':dict(result)}
        for code,check in (
                ('generation',lambda:base._descriptor(path)[2] == descriptor),
                ('binding-recheck',lambda:_leaf_retire_binding(path,descriptor) == binding),
                ('local-lease-recheck',lambda:_local_absent(path)),
                ('remote-lease-recheck',lambda:_remote_absent(config,target,descriptor)),
                ('readiness',lambda:_ready(path) is not None),
                ('guest-census',lambda:_leaf_guest_census(path,config,target,descriptor,retained=False)),
                ('intent-recheck',lambda:_leaf_retire_record(path) == intent)):
            phase=code
            if not check(): return {**_UNKNOWN,'state':'unknown','phase':phase}
        return {**_UNKNOWN,'state':'checked','phase':'verified','retirementCorrelationId':_LEAF_RETIREMENT}
    except (OSError,ValueError,TypeError,KeyError):
        return {**_UNKNOWN,'state':'unknown','phase':phase}
