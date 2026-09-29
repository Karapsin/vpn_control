"""One-shot, source-bound Linux DEB/RPM and Arch fixture build admission.

The fixed Arch host driver is deliberately separate from the intent gate.  A
correlation and the sole build-host claim are durable before submission; an
uncertain response is observed and never retried by this adapter.
"""

from __future__ import annotations

import json
import base64
import hashlib
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Mapping
from uuid import UUID


_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REQUEST = {"sourceSha", "baseVersion", "targetVersion", "correlationId"}
_JOURNAL = Path(".rag_index/linux-package-fixture-build")
_HOST = "archlinux"


class LinuxPackageFixtureBuildError(ValueError):
    pass


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise LinuxPackageFixtureBuildError(reason)


def _correlation(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except (TypeError, ValueError):
        return False


def _request(raw: Mapping[str, Any]) -> dict[str, str]:
    _need(isinstance(raw, Mapping) and set(raw) == _REQUEST,
          "Linux build requires exact fixed request fields")
    from scripts.version_metadata import parse_version
    source, base, target, correlation = (raw[key] for key in
                                         ("sourceSha", "baseVersion", "targetVersion", "correlationId"))
    _need(isinstance(source, str) and _SHA.fullmatch(source) is not None and
          isinstance(base, str) and isinstance(target, str) and _correlation(correlation),
          "Linux build source, versions or correlation are invalid")
    try:
        versions_valid = parse_version(base) < parse_version(target)
    except ValueError:
        versions_valid = False
    _need(versions_valid, "Linux build version order is invalid")
    return dict(raw)


def preflight(root: Path | str, raw: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only source/host gate; a dirty or unfrozen source cannot build."""
    request = _request(raw)
    root = Path(root).resolve(strict=True)
    source = request["sourceSha"]
    probes = (
        (["git", "-C", str(root), "rev-parse", "HEAD"], source),
        (["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c",
          "core.untrackedCache=false", "-C", str(root), "status", "--porcelain=v1",
          "--untracked-files=all"], ""),
        (["git", "-C", str(root), "ls-remote", "origin", "refs/heads/dev"],
         source + "\trefs/heads/dev"),
    )
    for argv, expected in probes:
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise LinuxPackageFixtureBuildError("Linux build source probe unavailable") from error
        _need(result.returncode == 0 and result.stdout.strip() == expected,
              "Linux build requires clean exact origin/dev source")
    tracked = subprocess.run(["git", "-C", str(root), "show", source + ":gradle.properties"],
                             capture_output=True, text=True, timeout=30, check=False)
    _need(tracked.returncode == 0 and
          re.search(r"^vpnControlVersion=" + re.escape(request["targetVersion"]) + r"$",
                    tracked.stdout, re.MULTILINE) is not None,
          "Linux build target version differs from frozen source")
    from . import ssh_transport
    config = ssh_transport.load_config(root)
    _need(_HOST in config.hosts, "Fixed Arch build host is not configured")
    return {"state": "ready", "sourceSha": source, "baseVersion": request["baseVersion"],
            "targetVersion": request["targetVersion"], "host": _HOST,
            "packageFamilies": ["default", "arch"], "nativeActionAllowed": False}


def _directory(root: Path, create: bool) -> Path | None:
    index = root / ".rag_index"
    path = root / _JOURNAL
    if create:
        index.mkdir(mode=0o700, exist_ok=True)
    if not index.exists() and not index.is_symlink():
        return None
    for entry in (index,):
        info = entry.lstat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o700,
              "Linux build journal ancestor is unsafe")
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
          stat.S_IMODE(info.st_mode) == 0o700,
          "Linux build journal is unsafe")
    return path


def _write_once(path: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8192,
              "Linux build journal file is unsafe")
        raw = os.read(fd, info.st_size + 1)
        _need(len(raw) == info.st_size, "Linux build journal changed during read")
        value = json.loads(raw)
        _need(isinstance(value, dict), "Linux build journal is invalid")
        return value
    finally:
        os.close(fd)


def _unknown(correlation: str, reason: str) -> dict[str, Any]:
    return {"state": "unknown", "correlationId": correlation, "reason": reason,
            "replayAllowed": False}


def start(root: Path | str, raw: Mapping[str, Any], *, driver=None, admission=None) -> dict[str, Any]:
    request = _request(raw)
    root = Path(root).resolve(strict=True)
    directory = _directory(root, create=True)
    assert directory is not None
    path = directory / (request["correlationId"] + ".json")
    if path.exists() or path.is_symlink():
        saved = _read(path)
        _need(saved == request, "Build correlation binds another immutable intent")
        return _unknown(request["correlationId"], "already-journaled")
    claim = directory / "archlinux.claim"
    if claim.exists() or claim.is_symlink():
        return {"state": "blocked", "correlationId": request["correlationId"],
                "reason": "build-host-already-claimed", "replayAllowed": False}
    admitted = (admission or preflight)(root, request)
    _need(isinstance(admitted, Mapping) and admitted.get("ready") is True or
          isinstance(admitted, Mapping) and admitted.get("state") == "ready",
          "Linux build preflight is not ready")
    driver = driver or FixedArchDriver(root)
    try:
        _write_once(claim, {"correlationId": request["correlationId"], "host": _HOST})
    except FileExistsError:
        return {"state": "blocked", "correlationId": request["correlationId"],
                "reason": "build-host-already-claimed", "replayAllowed": False}
    _write_once(path, request)
    try:
        result = driver.submit(request)
    except (OSError, ValueError, RuntimeError):
        return _unknown(request["correlationId"], "submission-response-lost")
    if isinstance(result, Mapping) and result.get("state") == "submitted" and result.get("correlationId") == request["correlationId"]:
        return {"state": "submitted", "correlationId": request["correlationId"],
                "replayAllowed": False}
    return _unknown(request["correlationId"], "submission-response-uncertain")


def status(root: Path | str, raw: Mapping[str, Any], *, driver=None) -> dict[str, Any]:
    _need(isinstance(raw, Mapping) and set(raw) == {"correlationId"} and
          _correlation(raw["correlationId"]), "Linux build status correlation is invalid")
    correlation = raw["correlationId"]
    directory = _directory(Path(root).resolve(strict=True), create=False)
    if directory is None:
        return _unknown(correlation, "missing-journal")
    request = _read(directory / (correlation + ".json"))
    if request is None:
        return _unknown(correlation, "missing-journal")
    _need(_request(request) == request, "Linux build intent journal differs")
    claim = _read(directory / "archlinux.claim")
    if claim != {"correlationId": correlation, "host": _HOST}:
        return _unknown(correlation, "build-host-claim-differs")
    driver = driver or FixedArchDriver(root)
    try:
        result = driver.status(request)
    except (OSError, ValueError, RuntimeError):
        return _unknown(correlation, "build-status-unavailable")
    if (not isinstance(result, Mapping) or result.get("correlationId") != correlation or
            result.get("sourceSha") != request["sourceSha"] or
            result.get("state") not in ("running", "failed", "unknown", "ready")):
        return _unknown(correlation, "build-status-identity-differs")
    return {**result, "replayAllowed": False}


def collect(root: Path | str, raw: Mapping[str, Any], *, driver=None) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    driver = driver or FixedArchDriver(root)
    observed = status(root, raw, driver=driver)
    if observed["state"] != "ready":
        return observed
    if not hasattr(driver, "collect"):
        return _unknown(raw["correlationId"], "fixed-build-collector-unavailable")
    return driver.collect(_request(_read(_directory(root, False) /
                                      (raw["correlationId"] + ".json"))), observed)


def _ended_worker(pid: int, expected_start: str) -> bool:
    """Require positive ps evidence that this exact local worker generation ended."""
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="],
                                capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    observed = result.stdout.strip()
    return ((result.returncode == 1 and not observed) or
            (result.returncode == 0 and 0 < len(observed) <= 128 and
             "\n" not in observed and observed != expected_start))


def pre_effect_status(root: Path | str, raw: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the one known SSH argv rejection occurred before any remote spawn."""
    _need(isinstance(raw, Mapping) and set(raw) == {"correlationId"} and
          _correlation(raw["correlationId"]), "Build pre-effect status requires exact correlation")
    correlation = raw["correlationId"]
    unknown = _unknown(correlation, "pre-effect-proof-unavailable")
    directory = _directory(Path(root).resolve(strict=True), create=False)
    if directory is None:
        return unknown
    request = _read(directory / (correlation + ".json"))
    claim_path = directory / "archlinux.claim"
    if request is None or _request(request) != request:
        return unknown
    job = directory / correlation
    try:
        job_info = job.lstat()
        files = set(os.listdir(job))
        base_files = {"state.json", "worker-pid.json", "worker.log"}
        if (not stat.S_ISDIR(job_info.st_mode) or job_info.st_uid != os.getuid() or
                stat.S_IMODE(job_info.st_mode) != 0o700 or
                files not in (base_files, base_files | {"pre-effect-closure.json"})):
            return unknown
        closure = _read(job / "pre-effect-closure.json") if "pre-effect-closure.json" in files else None
        claim_value = _read(claim_path)
        own_claim = claim_value == {"correlationId": correlation, "host": _HOST}
        claim_info = claim_path.lstat() if own_claim else None
        if own_claim and (not stat.S_ISREG(claim_info.st_mode) or
                          claim_info.st_uid != os.getuid() or
                          stat.S_IMODE(claim_info.st_mode) != 0o600 or
                          claim_info.st_nlink != 1):
            return unknown
        if not own_claim and closure is None:
            return unknown
        state = _read(job / "state.json")
        worker = _read(job / "worker-pid.json")
        log_path = job / "worker.log"
        log_fd = os.open(log_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            log_info = os.fstat(log_fd)
            if (not stat.S_ISREG(log_info.st_mode) or log_info.st_uid != os.getuid() or
                    stat.S_IMODE(log_info.st_mode) not in (0o600, 0o644) or log_info.st_nlink != 1 or
                    log_info.st_size != 0):
                return unknown
        finally:
            os.close(log_fd)
        if (state != {"state": "unknown", "reason": "SshConfigError",
                      "correlationId": correlation, "sourceSha": request["sourceSha"]} or
                not isinstance(worker, dict) or set(worker) != {"pid", "start"} or
                type(worker["pid"]) is not int or worker["pid"] <= 0 or
                not isinstance(worker["start"], str) or not worker["start"] or
                not _ended_worker(worker["pid"], worker["start"])):
            return unknown
        if closure is not None and (not isinstance(closure, dict) or
                set(closure) != {"state", "correlationId", "sourceSha", "closureDigest",
                                 "claimDevice", "claimInode"} or
                closure.get("state") != "closed-pre-effect" or
                closure.get("correlationId") != correlation or
                closure.get("sourceSha") != request["sourceSha"] or
                not isinstance(closure.get("closureDigest"), str) or
                re.fullmatch(r"[0-9a-f]{64}", closure["closureDigest"]) is None or
                type(closure.get("claimDevice")) is not int or closure["claimDevice"] <= 0 or
                type(closure.get("claimInode")) is not int or closure["claimInode"] <= 0):
            return unknown
        claim_device = claim_info.st_dev if own_claim else closure["claimDevice"]
        claim_inode = claim_info.st_ino if own_claim else closure["claimInode"]
        facts = {"correlationId": correlation, "sourceSha": request["sourceSha"],
                 "workerPid": worker["pid"], "workerStart": worker["start"],
                 "jobDevice": job_info.st_dev, "jobInode": job_info.st_ino,
                 "claimDevice": claim_device, "claimInode": claim_inode,
                 "reason": "SshConfigError", "remoteSpawnObserved": False}
        digest = hashlib.sha256((json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
        if closure is not None and (closure["closureDigest"] != digest or
                (own_claim and (closure["claimDevice"], closure["claimInode"]) !=
                 (claim_device, claim_inode))):
            return unknown
        return {"state": "ready" if closure is None else "closing" if own_claim else "closed",
                "correlationId": correlation,
                "sourceSha": request["sourceSha"], "closureDigest": digest,
                "claimDevice": claim_device, "claimInode": claim_inode,
                "remoteSpawnObserved": False, "replayAllowed": False}
    except (OSError, ValueError, TypeError):
        return unknown


def pre_effect_close(root: Path | str, raw: Mapping[str, Any]) -> dict[str, Any]:
    _need(isinstance(raw, Mapping) and set(raw) == {"correlationId", "closureDigest"} and
          _correlation(raw["correlationId"]) and isinstance(raw["closureDigest"], str) and
          re.fullmatch(r"[0-9a-f]{64}", raw["closureDigest"]) is not None,
          "Build pre-effect close requires exact proof digest")
    observed = pre_effect_status(root, {"correlationId": raw["correlationId"]})
    if observed.get("state") not in {"ready", "closing", "closed"} or \
            observed.get("closureDigest") != raw["closureDigest"]:
        return _unknown(raw["correlationId"], "pre-effect-proof-differs")
    if observed["state"] == "closed":
        return {"state": "closed", "correlationId": raw["correlationId"],
                "sourceSha": observed["sourceSha"], "closureDigest": raw["closureDigest"],
                "oldIntentPreserved": True, "replayAllowed": False}
    directory = _directory(Path(root).resolve(strict=True), create=False)
    assert directory is not None
    claim = directory / "archlinux.claim"
    current = claim.lstat()
    if (current.st_dev, current.st_ino) != (observed["claimDevice"], observed["claimInode"]):
        return _unknown(raw["correlationId"], "build-host-claim-changed")
    job = directory / raw["correlationId"]
    if observed["state"] == "ready":
        _write_once(job / "pre-effect-closure.json", {
            "state": "closed-pre-effect", "correlationId": raw["correlationId"],
            "sourceSha": observed["sourceSha"], "closureDigest": raw["closureDigest"],
            "claimDevice": observed["claimDevice"], "claimInode": observed["claimInode"]})
    claim.unlink()
    return {"state": "closed", "correlationId": raw["correlationId"],
            "sourceSha": observed["sourceSha"], "closureDigest": raw["closureDigest"],
            "oldIntentPreserved": True, "replayAllowed": False}


def terminal_ready_status(root: Path | str, raw: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only proof that one collected, ended build owns the fixed host claim."""
    _need(isinstance(raw, Mapping) and set(raw) == {"correlationId"} and
          _correlation(raw["correlationId"]), "Build terminal closure requires exact correlation")
    correlation = raw["correlationId"]
    unknown = _unknown(correlation, "terminal-ready-proof-unavailable")
    root = Path(root).resolve(strict=True)
    directory = _directory(root, create=False)
    if directory is None:
        return unknown
    try:
        request = _read(directory / (correlation + ".json"))
        if request is None or _request(request) != request:
            return unknown
        job = directory / correlation
        job_info = job.lstat()
        if (not stat.S_ISDIR(job_info.st_mode) or job_info.st_uid != os.getuid() or
                stat.S_IMODE(job_info.st_mode) != 0o700):
            return unknown
        state = _read(job / "state.json")
        worker = _read(job / "worker-pid.json")
        if (state != {"state": "ready", "liveReady": True,
                      "correlationId": correlation, "sourceSha": request["sourceSha"]} or
                not isinstance(worker, dict) or set(worker) != {"pid", "start"} or
                type(worker["pid"]) is not int or worker["pid"] <= 0 or
                not isinstance(worker["start"], str) or not worker["start"] or
                not _ended_worker(worker["pid"], worker["start"])):
            return unknown
        from . import native_artifact_registry
        paths = _verify_built(job / "output", request)
        snapshot = json.loads((job / "output/default/snapshot.json").read_bytes())
        fingerprint = snapshot["sourceFingerprint"]
        artifact_facts = []
        for path in paths:
            if path.name != "fixture-receipt.json" and "packages" not in path.parts:
                continue
            size, digest = _digest(path)
            verified = native_artifact_registry.verify_artifact(root, "sha256-" + digest)
            record, location = verified.get("artifact", {}), verified.get("location", {})
            if (verified.get("verification") != "verified" or
                    record.get("platform") != "linux" or
                    record.get("artifactKind") != ("fixture-receipt" if path.name == "fixture-receipt.json" else "package") or
                    record.get("sourceSha") != request["sourceSha"] or
                    record.get("sourceFingerprint") != fingerprint or
                    record.get("sha256") != digest or record.get("size") != size or
                    location.get("evidenceClass") != "local-verified" or
                    location.get("localPath") != str(path)):
                return unknown
            artifact_facts.append({"path": str(path.relative_to(job / "output")),
                                   "sha256": digest, "size": size})
        if len(artifact_facts) != 10:
            return unknown
        timing = job / "output/.rag_index/build-timings"
        timing_files = _timing_inventory(timing, request)
        for path in timing_files:
            published = root / ".rag_index/build-timings" / path.name
            if _digest(path, 4096) != _digest(published, 4096):
                return unknown
        claim_path = directory / "archlinux.claim"
        claim_value = _read(claim_path)
        own_claim = claim_value == {"correlationId": correlation, "host": _HOST}
        if claim_value is not None and not own_claim:
            return unknown
        claim_info = claim_path.lstat() if own_claim else None
        if own_claim and (not stat.S_ISREG(claim_info.st_mode) or
                          claim_info.st_uid != os.getuid() or
                          stat.S_IMODE(claim_info.st_mode) != 0o600 or
                          claim_info.st_nlink != 1):
            return unknown
        marker = _read(job / "terminal-ready-closure.json")
        if not own_claim and marker is None:
            return unknown
        claim_device = claim_info.st_dev if own_claim else marker.get("claimDevice")
        claim_inode = claim_info.st_ino if own_claim else marker.get("claimInode")
        if type(claim_device) is not int or claim_device <= 0 or type(claim_inode) is not int or claim_inode <= 0:
            return unknown
        facts = {"correlationId": correlation, "sourceSha": request["sourceSha"],
                 "workerPid": worker["pid"], "workerStart": worker["start"],
                 "jobDevice": job_info.st_dev, "jobInode": job_info.st_ino,
                 "claimDevice": claim_device, "claimInode": claim_inode,
                 "artifacts": sorted(artifact_facts, key=lambda item: item["path"]),
                 "timings": sorted((path.name, _digest(path, 4096)[1]) for path in timing_files)}
        digest = hashlib.sha256((json.dumps(facts, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()
        expected_marker = {"state": "closed-terminal-ready", "correlationId": correlation,
                           "sourceSha": request["sourceSha"], "closureDigest": digest,
                           "claimDevice": claim_device, "claimInode": claim_inode}
        if marker is not None and marker != expected_marker:
            return unknown
        return {"state": "ready" if marker is None else "closing" if own_claim else "closed",
                "correlationId": correlation, "sourceSha": request["sourceSha"],
                "closureDigest": digest, "claimDevice": claim_device,
                "claimInode": claim_inode, "oldIntentPreserved": True,
                "replayAllowed": False}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return unknown


def terminal_ready_close(root: Path | str, raw: Mapping[str, Any]) -> dict[str, Any]:
    _need(isinstance(raw, Mapping) and set(raw) == {"correlationId", "closureDigest"} and
          _correlation(raw["correlationId"]) and
          isinstance(raw["closureDigest"], str) and
          re.fullmatch(r"[0-9a-f]{64}", raw["closureDigest"]) is not None,
          "Build terminal closure requires exact correlation and proof")
    observed = terminal_ready_status(root, {"correlationId": raw["correlationId"]})
    if (observed.get("state") not in {"ready", "closing", "closed"} or
            observed.get("closureDigest") != raw["closureDigest"]):
        return _unknown(raw["correlationId"], "terminal-ready-proof-differs")
    if observed["state"] == "closed":
        return observed
    directory = _directory(Path(root).resolve(strict=True), create=False)
    assert directory is not None
    claim = directory / "archlinux.claim"
    if (_read(claim) != {"correlationId": raw["correlationId"], "host": _HOST} or
            (claim.lstat().st_dev, claim.lstat().st_ino) !=
            (observed["claimDevice"], observed["claimInode"])):
        return _unknown(raw["correlationId"], "build-host-claim-changed")
    if observed["state"] == "ready":
        _write_once(directory / raw["correlationId"] / "terminal-ready-closure.json", {
            "state": "closed-terminal-ready", "correlationId": raw["correlationId"],
            "sourceSha": observed["sourceSha"], "closureDigest": observed["closureDigest"],
            "claimDevice": observed["claimDevice"], "claimInode": observed["claimInode"]})
    claim.unlink()
    return {"state": "closed", "correlationId": raw["correlationId"],
            "sourceSha": observed["sourceSha"], "closureDigest": observed["closureDigest"],
            "oldIntentPreserved": True, "replayAllowed": False}


_BOOTSTRAP = r'''
import base64,json,os,pathlib,subprocess,sys
request=json.loads(base64.b64decode(sys.argv[1],validate=True))
correlation=request['correlationId'];source=request['sourceSha']
root=pathlib.Path('/home/kardinal/.vpn-control-linux-package-fixture')
root.mkdir(mode=0o700,exist_ok=True)
if root.is_symlink() or root.stat().st_uid!=os.getuid() or root.stat().st_mode&0o077:raise SystemExit(31)
job=root/correlation
job.mkdir(mode=0o700)
repository=job/'source'
subprocess.run(['git','clone','--no-checkout','https://github.com/Karapsin/vpn_control.git',str(repository)],check=True,stdout=sys.stderr)
subprocess.run(['git','-C',str(repository),'checkout','--detach',source],check=True,stdout=sys.stderr)
head=subprocess.run(['git','-C',str(repository),'rev-parse','HEAD'],check=True,capture_output=True,text=True).stdout.strip()
if head!=source:raise SystemExit(32)
result=subprocess.run(['python3','-B','-m','agent_tools.linux_package_fixture_build','--remote-run',str(job),sys.argv[1]],cwd=repository,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer)
raise SystemExit(result.returncode)
'''


def _digest(path: Path, maximum: int = 1024 * 1024 * 1024) -> tuple[int, str]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
              "Build output file is unsafe")
        sha = hashlib.sha256()
        total = 0
        while block := os.read(fd, 1024 * 1024):
            total += len(block)
            _need(total <= maximum, "Build output exceeds bound")
            sha.update(block)
        after = os.fstat(fd)
        _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
              "Build output changed during verification")
        return total, sha.hexdigest()
    finally:
        os.close(fd)


def _run_build(argv: list[str], cwd: Path, log: Path, timeout: int) -> None:
    started = time.monotonic_ns()
    with log.open("wb") as output:
        result = subprocess.run(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, check=False)
    _need(result.returncode == 0, "Fixed Linux package build failed")
    _need(time.monotonic_ns() > started, "Build timing clock is invalid")


def _remote_run(job: Path, request: Mapping[str, Any]) -> None:
    """Execute only the two fixed fixture families in an exact-source clone."""
    request = _request(request)
    source = job / "source"
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                          capture_output=True, text=True, timeout=20, check=False)
    _need(head.returncode == 0 and head.stdout.strip() == request["sourceSha"],
          "Remote build source differs")
    runtime = source / "desktopApp/src/main/resources/bin/linux-amd64/sing-box"
    _run_build(["bash", "scripts/prepare_sing_box_desktop_runtime.sh"], source,
               job / "runtime-prep.log", 900)
    _need(runtime.is_file() and not runtime.is_symlink(), "Remote native runtime is unavailable")
    timing = job / ".rag_index" / "build-timings"
    for family in ("default", "arch"):
        destination = job / family
        prepare = ["python3", "scripts/prepare_desktop_update_fixture.py", "prepare",
                   "--repository", str(source), "--output", str(destination),
                   "--base-version", request["baseVersion"], "--target-version", request["targetVersion"],
                   "--runtime", str(runtime), "--platform", "linux", "--architecture", "x86_64"]
        if family == "arch":
            prepare += ["--package-family", "arch"]
        _run_build(prepare, source, job / (family + "-prepare.log"), 120)
        build = ["python3", "scripts/prepare_desktop_update_fixture.py", "build",
                 "--directory", str(destination), "--confirm-owned-native-host-build",
                 "--discard-completed-builds", "--timing-directory", str(timing),
                 "--timing-pipeline-id", "linux-package-" + family,
                 "--timing-run-id", request["correlationId"],
                 "--timing-host-alias", _HOST]
        _run_build(build, source, job / (family + "-build.log"), 3600)
    files = _verify_built(job, request)
    timing_files = _timing_inventory(timing, request)
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        for path in (*files, *timing_files):
            archive.add(path, arcname=str(path.relative_to(job)), recursive=False)


def _verify_timing(path: Path, request: Mapping[str, Any]) -> dict[str, Any]:
    _digest(path, 4096)
    data = json.loads(path.read_bytes())
    _need(isinstance(data, dict) and set(data) ==
          {"schemaVersion", "sourceSha", "pipelineId", "runId", "hostAlias",
           "phase", "startedMonotonicNs", "finishedMonotonicNs"} and
          data.get("schemaVersion") == 1 and data.get("sourceSha") == request["sourceSha"] and
          data.get("pipelineId") in ("linux-package-default", "linux-package-arch") and
          data.get("runId") == request["correlationId"] and
          data.get("hostAlias") == _HOST and
          data.get("phase") in ("gradle", "runtime-prep", "packaging") and
          type(data.get("startedMonotonicNs")) is int and
          type(data.get("finishedMonotonicNs")) is int and
          0 < data["finishedMonotonicNs"] - data["startedMonotonicNs"] <= 86400 * 10**9,
          "Build timing receipt identity differs")
    return data


def _timing_inventory(directory: Path, request: Mapping[str, Any]) -> list[Path]:
    """Require every fixed family × stage × phase timing, with no extras."""
    expected = {f"linux-package-{family}-{request['correlationId']}-{phase}-{stage}.json"
                for family in ("default", "arch")
                for stage in ("base", "target")
                for phase in ("runtime-prep", "gradle", "packaging")}
    observed = list(directory.iterdir()) if directory.is_dir() and not directory.is_symlink() else []
    _need({path.name for path in observed} == expected and len(observed) == len(expected),
          "Build timing stage inventory is incomplete or excessive")
    for path in observed:
        data = _verify_timing(path, request)
        stage = path.name.removeprefix(data["pipelineId"] + "-" + request["correlationId"] + "-" + data["phase"] + "-").removesuffix(".json")
        _need(stage in ("base", "target") and
              path.name == f"{data['pipelineId']}-{request['correlationId']}-{data['phase']}-{stage}.json",
              "Build timing stage name differs")
    return sorted(observed)


def _publish_timing(root: Path, paths: list[Path]) -> list[dict[str, str]]:
    """Retain verified phase receipts at the fixed build-timing report location."""
    parent = root / ".rag_index"
    directory = parent / "build-timings"
    for entry in (parent, directory):
        entry.mkdir(mode=0o700, exist_ok=True)
        info = entry.lstat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o700,
              "Build timing publication directory is unsafe")
    references = []
    for source in paths:
        _, digest = _digest(source, 4096)
        destination = directory / source.name
        if destination.exists() or destination.is_symlink():
            _need(_digest(destination, 4096)[1] == digest,
                  "Build timing publication conflicts")
        else:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                raw = os.read(fd, 4097)
                _need(len(raw) <= 4096 and hashlib.sha256(raw).hexdigest() == digest,
                      "Build timing source changed")
            finally:
                os.close(fd)
            _write_once(destination, json.loads(raw))
            _need(_digest(destination, 4096)[1] == digest,
                  "Build timing publication differs")
        references.append({"path": ".rag_index/build-timings/" + source.name,
                           "sha256": digest})
    return references


def _process_generation(pid: int) -> str | None:
    """Observe this coordinator worker's PID generation without guessing reuse."""
    if type(pid) is not int or pid <= 0:
        return None
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="],
                                capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    start = result.stdout.strip()
    return start if result.returncode == 0 and 0 < len(start) <= 128 and "\n" not in start else None


def _verify_built(job: Path, request: Mapping[str, Any]) -> list[Path]:
    """Independently bind both receipts to source, code and package bytes."""
    fingerprints = set()
    codes = set()
    output: list[Path] = []
    for family, types in (("default", ("deb", "rpm", "arch-bundle")),
                          ("arch", ("arch-bundle",))):
        directory = job / family
        snapshot = directory / "snapshot.json"
        receipt_path = directory / "fixture-receipt.json"
        plan = directory / "build-plan.json"
        for path in (snapshot, receipt_path, plan):
            _digest(path, 1024 * 1024)
        snapshot_data = json.loads(snapshot.read_bytes())
        receipt = json.loads(receipt_path.read_bytes())
        plan_data = json.loads(plan.read_bytes())
        fingerprint = snapshot_data.get("sourceFingerprint")
        _need(snapshot_data.get("sourceHead") == request["sourceSha"] and
              isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint) and
              receipt.get("sourceFingerprint") == plan_data.get("sourceFingerprint") == fingerprint and
              receipt.get("testOnly") is True and receipt.get("productionTrustChanged") is False and
              plan_data.get("packageFamily") == family,
              "Build family source or policy differs")
        fingerprints.add(fingerprint)
        builds = receipt.get("builds")
        _need(isinstance(builds, list) and len(builds) == 2, "Build receipt stages differ")
        for index, (label, version) in enumerate((("base", request["baseVersion"]),
                                                   ("target", request["targetVersion"]))):
            build = builds[index]
            _need(build.get("label") == label and build.get("version") == version and
                  build.get("sourceFingerprint") == fingerprint,
                  "Build label, version or source differs")
            code = build.get("codeFingerprint")
            _need(isinstance(code, str) and re.fullmatch(r"[0-9a-f]{64}", code),
                  "Build executable fingerprint is invalid")
            codes.add(code)
            assets = build.get("assets")
            _need(isinstance(assets, list) and set(item.get("packageType") for item in assets) == set(types) and
                  len(assets) == len(types), "Build package families differ")
            for asset in assets:
                name = asset.get("fileName")
                _need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", name) and
                      name not in (".", ".."), "Build package name is unsafe")
                path = directory / "packages" / label / name
                _need(not any(part.is_symlink() for part in (directory, directory / "packages", path.parent, path)),
                      "Build package path is unsafe")
                size, digest = _digest(path)
                _need(asset.get("sizeBytes") == size and asset.get("sha256") == digest,
                      "Build package bytes differ from receipt")
                output.append(path)
        _need(receipt.get("manifest", {}).get("assets") == builds[1]["assets"],
              "Build target manifest differs")
        output.extend((snapshot, plan, receipt_path))
    _need(len(fingerprints) == len(codes) == 1, "Default and Arch source or code differs")
    return output


class FixedArchDriver:
    """One local worker submits one fixed SSH build and verifies its tar response."""

    def __init__(self, root: Path | str):
        self.root = Path(root).resolve(strict=True)

    def _job(self, request: Mapping[str, Any]) -> Path:
        directory = _directory(self.root, create=False)
        _need(directory is not None, "Build journal is missing")
        return directory / request["correlationId"]

    def submit(self, request: Mapping[str, Any]) -> dict[str, Any]:
        job = self._job(request)
        job.mkdir(mode=0o700)
        with (job / "worker.log").open("xb") as output:
            process = subprocess.Popen([sys.executable, "-m", "agent_tools.linux_package_fixture_build",
                                        "--local-worker", str(self.root), request["correlationId"]],
                                       cwd=self.root, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        start = _process_generation(process.pid)
        _need(start is not None, "Detached build worker generation is unavailable")
        _write_once(job / "worker-pid.json", {"pid": process.pid, "start": start})
        return {"state": "submitted", "correlationId": request["correlationId"]}

    def status(self, request: Mapping[str, Any]) -> dict[str, Any]:
        job = self._job(request)
        state = _read(job / "state.json")
        if state is None:
            return {"state": "unknown", "correlationId": request["correlationId"],
                    "sourceSha": request["sourceSha"]}
        if state.get("state") == "running":
            worker = _read(job / "worker-pid.json")
            if (not isinstance(worker, dict) or set(worker) != {"pid", "start"} or
                    type(worker["pid"]) is not int or worker["pid"] <= 0 or
                    not isinstance(worker["start"], str) or
                    _process_generation(worker["pid"]) != worker["start"]):
                return {"state": "unknown", "correlationId": request["correlationId"],
                        "sourceSha": request["sourceSha"], "reason": "worker-generation-unavailable"}
        return state

    def collect(self, request: Mapping[str, Any], observed: Mapping[str, Any]) -> dict[str, Any]:
        job = self._job(request)
        paths = _verify_built(job / "output", request)
        from . import native_artifact_registry
        snapshot = json.loads((job / "output/default/snapshot.json").read_bytes())
        fingerprint = snapshot["sourceFingerprint"]
        records: list[dict[str, Any]] = []
        for path in paths:
            if path.name not in ("fixture-receipt.json",) and "packages" not in path.parts:
                continue
            size, digest = _digest(path)
            registered = native_artifact_registry.register_artifact(self.root, {
                "platform": "linux", "artifactKind": "fixture-receipt" if path.name == "fixture-receipt.json" else "package",
                "localPath": str(path), "sha256": digest, "size": size,
                "evidenceClass": "local-verified", "sourceSha": request["sourceSha"],
                "sourceFingerprint": fingerprint})
            records.append({"family": path.relative_to(job / "output").parts[0],
                            "relativePath": str(path.relative_to(job / "output")),
                            "artifactId": registered["artifactId"], "sha256": digest, "size": size})
        _need(len(records) == 10, "Collected Linux fixture artifact count differs")
        timing = job / "output/.rag_index/build-timings"
        timing_files = _timing_inventory(timing, request)
        timings = []
        for path in timing_files:
            value = _verify_timing(path, request)
            timings.append({"phase": value["phase"], "pipelineId": value["pipelineId"],
                            "sha256": _digest(path, 4096)[1], "path": str(path)})
        references = _publish_timing(self.root, timing_files)
        return {"state": "ready", "correlationId": request["correlationId"],
                "sourceSha": request["sourceSha"], "sourceFingerprint": fingerprint,
                "artifacts": records, "timingReceipts": timings,
                "timingReferences": references, "replayAllowed": False}


def _state(job: Path, value: Mapping[str, Any]) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = job / "state.next"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, job / "state.json")


def _stream_bounded(source_fd: int, sink, maximum: int, deadline: float) -> None:
    """Cap SSH bytes before they reach disk, including archive headers/padding."""
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        _need(remaining > 0, "Remote build transfer timed out")
        ready, _, _ = select.select([source_fd], [], [], min(remaining, 5.0))
        if not ready:
            continue
        block = os.read(source_fd, 1024 * 1024)
        if not block:
            return
        total += len(block)
        _need(total <= maximum, "Remote build transfer exceeds bound")
        sink.write(block)


def _local_worker(root: Path, correlation: str) -> None:
    directory = _directory(root, create=False)
    _need(directory is not None, "Build journal is missing")
    request = _read(directory / (correlation + ".json"))
    _need(request is not None and _request(request) == request,
          "Build intent journal differs")
    job = directory / correlation
    identity = {"correlationId": correlation, "sourceSha": request["sourceSha"]}
    _state(job, {**identity, "state": "running"})
    try:
        from . import ssh_transport
        encoded = base64.b64encode((json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()).decode()
        config = ssh_transport.load_config(root)
        bootstrap = base64.b64encode(_BOOTSTRAP.encode("utf-8")).decode("ascii")
        fixed_command = f"import base64;exec(base64.b64decode('{bootstrap}'))"
        argv = ssh_transport.build_ssh_argv(config, _HOST, 60,
                                             command=["python3", "-I", "-B", "-c", fixed_command, encoded])
        archive = job / "result.tar"
        with archive.open("xb") as output, (job / "remote.log").open("xb") as errors:
            process = subprocess.Popen(argv, cwd=root, stdout=subprocess.PIPE, stderr=errors)
            try:
                assert process.stdout is not None
                _stream_bounded(process.stdout.fileno(), output,
                                3 * 1024 * 1024 * 1024 + 16 * 1024 * 1024,
                                time.monotonic() + 10800)
                code = process.wait(timeout=10)
            except Exception:
                process.kill()
                process.wait(timeout=10)
                raise
        _need(code == 0, "Remote Linux fixture build did not complete")
        output = job / "output"
        output.mkdir(mode=0o700)
        with tarfile.open(archive, "r:") as stream:
            names: set[str] = set()
            total = 0
            for member in stream:
                name = member.name
                parts = Path(name).parts
                _need(member.isfile() and parts and parts[0] in ("default", "arch", ".rag_index") and
                      ".." not in parts and not name.startswith("/") and name not in names and
                      len(names) < 32 and 0 < member.size <= 1024 * 1024 * 1024,
                      "Remote build archive member is unsafe")
                names.add(name)
                total += member.size
                _need(total <= 3 * 1024 * 1024 * 1024, "Remote build archive exceeds bound")
                target = output / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = stream.extractfile(member)
                _need(source is not None, "Remote build member cannot be read")
                with target.open("xb") as sink:
                    while block := source.read(1024 * 1024):
                        sink.write(block)
        _verify_built(output, request)
        _timing_inventory(output / ".rag_index/build-timings", request)
        _state(job, {**identity, "state": "ready", "liveReady": True})
    except Exception as error:
        _state(job, {**identity, "state": "unknown", "reason": type(error).__name__})


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--local-worker":
        _local_worker(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "--remote-run":
        request = json.loads(base64.b64decode(sys.argv[3], validate=True))
        _remote_run(Path(sys.argv[2]), request)
    else:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
