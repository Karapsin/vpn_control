"""One-shot CP117 base MSI preparation for the public update acceptance fixture.

The original-user MSI task is a fixture setup operation. It never submits the
target update. Local and remote reservations deliberately survive uncertainty.
"""
from __future__ import annotations

import base64
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from typing import Any, Mapping

from . import ssh_transport, windows_credential_probe_ssh, windows_msi_public_scenario
from . import windows_cp117_lease as campaign_lease


class WindowsMsiBasePrepareError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_LOCAL = ".rag_index/windows-msi-base-prepare"
_PRE_EFFECT_REJECTED_CORRELATION = "30a6f33b-3ea2-42d0-8818-3d6711b34169"
_PRE_EFFECT_REJECTED_COMMAND_SHA256 = "f490e8582bc84145fff84b92a5bb5b05ac6e4593c429289779de8eac5aa713ca"
_PRE_EFFECT_REJECTED_REQUEST = {
    "host": "archlinux", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION,
    "sourceSha": "a876f46fa4582e6218d341ac7012fd31bc919758",
    "fixtureReceiptArtifactId": "sha256-086cf41006f4340e378123220b51c21f97649193b59237c529231727b2e29782",
    "baseMsiArtifactId": "sha256-9a63e408ef6856234a2b40c121ede02a60482b5e8a6d8e624f3bd7bf70bce476",
    "targetMsiArtifactId": "sha256-dff5b596f13fb0c9469ed4b9a4f67eaea9211f2a457e99697739b034731448b7",
    "expectedCurrentVersion": "2.1.17"}
# This is the one CP117 base submission whose SSH caller lost the outcome after
# creating a remote stage. Keep recovery source-bound: accepting arbitrary
# correlations here would make a recovery action a general guest cleaner.
_UNKNOWN_CLOSURE_CORRELATION = "2ace6a48-ba60-4705-9200-4ff857f2aba6"
_UNKNOWN_CLOSURE_REQUEST = {
    "host": "archlinux", "correlationId": _UNKNOWN_CLOSURE_CORRELATION,
    "sourceSha": "19be9df22cbab8086c26e5ca907d9569a5a28a08",
    "fixtureReceiptArtifactId": "sha256-d437b2931db91c7b0ad97fb2809dfa0b224cb9f98d28634f4c4948e1117a705d",
    "baseMsiArtifactId": "sha256-0fada9685bb308346723e6ca74c102c699dc86ffda8fb097fc99303c5ab5aaa3",
    "targetMsiArtifactId": "sha256-5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234",
    "expectedCurrentVersion": "2.1.17"}
_UNKNOWN_CLOSURE_COMMAND_SHA256 = "ee63db4dae5e4bf9f5cea9ca7bf600dde164b7377c50330058219f2ce00f224b"
# A second, separately accepted CP117 submission lost its transport result after
# staging a partial MSI.  Keep it an explicit recovery profile: this is not a
# general purpose guest-cleanup interface.
_TRANSFER_RECOVERY_CORRELATION = "45e4514a-c629-4f3b-99bc-aad599640d29"
_TRANSFER_RECOVERY_REQUEST = {
    **_UNKNOWN_CLOSURE_REQUEST, "correlationId": _TRANSFER_RECOVERY_CORRELATION}
_TRANSFER_RECOVERY_COMMAND_SHA256 = "b791a2235c6965fbcda068d88136f1ef73f8538ed1d6d8a30ae6f506cb832b88"
_UNKNOWN_RECOVERY_PROFILES = {
    _UNKNOWN_CLOSURE_CORRELATION: (_UNKNOWN_CLOSURE_REQUEST, _UNKNOWN_CLOSURE_COMMAND_SHA256),
    _TRANSFER_RECOVERY_CORRELATION: (_TRANSFER_RECOVERY_REQUEST, _TRANSFER_RECOVERY_COMMAND_SHA256),
}
_ROOT = r"C:\Users\vpncp117\AppData\Local\VpnControl"
_ACCOUNT = r"VPNMSIX64\vpncp117"
_PRODUCT = re.compile(r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}\Z")
_INSTALL = "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\"
_LEGACY_CORRELATION = "99126312-977f-4a61-a9ef-fb6884d2d26f"
_LEGACY_JOB = "9107428f-9c80-4284-9f4e-926350105a59"


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId",
              "baseMsiArtifactId", "targetMsiArtifactId", "expectedCurrentVersion"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsMsiBasePrepareError("Windows base preparation requires exact CP117 inputs.")
    for key, pattern in (("correlationId", _UUID), ("sourceSha", _SHA),
                         ("fixtureReceiptArtifactId", _ARTIFACT), ("baseMsiArtifactId", _ARTIFACT),
                         ("targetMsiArtifactId", _ARTIFACT), ("expectedCurrentVersion", _VERSION)):
        if not isinstance(value[key], str) or not pattern.fullmatch(value[key]):
            raise WindowsMsiBasePrepareError("Invalid Windows base preparation " + key + ".")
    if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
        raise WindowsMsiBasePrepareError("Correlation is not canonical.")
    return dict(value)


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _LOCAL / (correlation + ".json")


def _private_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    path = _intent_path(root, correlation)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192:
            raise WindowsMsiBasePrepareError("Base preparation intent is unsafe.")
        record = json.load(stream)
    if not isinstance(record, dict) or record.get("request", {}).get("correlationId") != correlation:
        raise WindowsMsiBasePrepareError("Base preparation intent is invalid.")
    return record


def _pre_effect_marker(root: Path) -> Path:
    return root / _LOCAL / (_PRE_EFFECT_REJECTED_CORRELATION + ".pre-effect-closed.json")


def _unknown_closure_marker(root: Path, correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> Path:
    return root / _LOCAL / (correlation + ".unknown-close.json")


def _unknown_recovery_profile(correlation: str) -> tuple[dict[str, str], str] | None:
    """Return only one of the two reviewed, source-bound recovery profiles."""
    return _UNKNOWN_RECOVERY_PROFILES.get(correlation)


def _write_private_once(path: Path, value: Mapping[str, Any]) -> bool:
    """Persist an immutable intent before a recovery can mutate a guest."""
    data = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > 8192:
        raise WindowsMsiBasePrepareError("Base closure intent is too large.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(parent)
    finally: os.close(parent)
    return True


def _read_private_exact(path: Path, expected: Mapping[str, Any]) -> bool:
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return False
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiBasePrepareError("Base closure intent is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError): return False
    return value == dict(expected)


def _unknown_marker_valid(root: Path, intent: Mapping[str, Any], descriptor: tuple[Any, ...],
                          correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> bool:
    """A prior close intent can resume only on the same guest generation."""
    path = _unknown_closure_marker(root, correlation)
    try: fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return False
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiBasePrepareError("Base unknown closure marker is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError): return False
    env, sock, pid, ticks, sid = descriptor
    return (isinstance(value, dict) and set(value) == {"version", "state", "correlationId", "commandSha256",
            "sourceSha", "guestGeneration", "preMutationEvidenceSha256"} and value.get("version") == 1
            and value.get("state") == "close-intent" and value.get("correlationId") == correlation
            and value.get("commandSha256") == intent.get("commandSha256")
            and value.get("sourceSha") == intent.get("request", {}).get("sourceSha")
            and value.get("guestGeneration") == {"environment": env, "socketPath": sock, "qemuPid": pid,
                                                  "startTicks": ticks, "expectedSid": sid}
            and isinstance(value.get("preMutationEvidenceSha256"), str)
            and _HASH.fullmatch(value["preMutationEvidenceSha256"]) is not None)


def _pre_effect_closed(root: Path) -> bool:
    intent = _private_intent(root, _PRE_EFFECT_REJECTED_CORRELATION)
    if (intent is None or intent.get("request") != _PRE_EFFECT_REJECTED_REQUEST
            or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("environment") != "windows-cp117"
            or intent.get("pid") != 589342 or intent.get("startTicks") != 520739
            or not isinstance(intent.get("socketPath"), str)
            or not isinstance(intent.get("expectedSid"), str)):
        return False
    marker = _pre_effect_marker(root)
    try: fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return False
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8192):
            raise WindowsMsiBasePrepareError("Base pre-effect closure is unsafe.")
        marker_value = json.load(stream)
    if (not isinstance(marker_value, dict) or set(marker_value) != {
            "correlationId", "commandSha256", "state", "cleanupReceiptSha256"}
            or marker_value.get("correlationId") != _PRE_EFFECT_REJECTED_CORRELATION
            or marker_value.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or marker_value.get("state") != "pre-effect-closed"
            or not isinstance(marker_value.get("cleanupReceiptSha256"), str)
            or not _HASH.fullmatch(marker_value["cleanupReceiptSha256"])):
        return False
    # This is a read-only archive predicate. Reuse a validated campaign SH
    # scope when closure admission already holds it; taking EX on another fd
    # here would deadlock against our own SH. Writers still require EX.
    from . import windows_cp117_historical_base_archives as historical_archives
    with historical_archives._history_lock(root):
        closed = campaign_lease._closed(root / campaign_lease._DIR, _PRE_EFFECT_REJECTED_CORRELATION)
    expected_identity = _campaign_identity(_PRE_EFFECT_REJECTED_REQUEST,
        (intent["environment"], intent["socketPath"], intent["pid"],
         intent["startTicks"], intent["expectedSid"]))
    return (closed is not None and closed["identity"] == expected_identity
            and closed["lastOutcome"] == "failed-cleaned"
            and closed["lastEvidenceSha256"] == marker_value["cleanupReceiptSha256"]
            and intent["pid"] == 589342 and intent["startTicks"] == 520739)


def _unknown_closure_archived(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...],
                              correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> bool:
    """Recognize only a durable, source-bound reviewed uncertain cleanup archive.

    The original intent and campaign journal remain in place.  Two fresh
    read-only censuses must still prove that its exact remote stage and guest
    leaf are absent before a new base correlation can be admitted.
    """
    try:
        profile = _unknown_recovery_profile(correlation)
        if profile is None:
            return False
        request, command_hash = profile
        intent = _private_intent(root, correlation)
        if (intent is None or intent.get("request") != request
                or intent.get("commandSha256") != command_hash
                or intent.get("leaseId") != correlation
                or not isinstance(intent.get("pair"), Mapping)
                or intent["pair"].get("sourceSha") != request["sourceSha"]
                or not isinstance(intent["pair"].get("sourceFingerprint"), str)
                or _HASH.fullmatch(intent["pair"]["sourceFingerprint"]) is None
                or not _unknown_marker_valid(root, intent, descriptor, correlation)):
            return False
        directory, lock = campaign_lease._locked(root)
        try:
            active = campaign_lease._active(directory)
            closed = campaign_lease._closed(directory, correlation)
        finally:
            os.close(lock)
        if active is not None or closed is None:
            return False
        if (closed.get("identity") != _campaign_identity(request, descriptor)
                or closed.get("lastOutcome") != "unknown-cleaned"):
            return False
        first = _unknown_cleanup_census(config, target, intent, descriptor, "status", correlation)
        second = _unknown_cleanup_census(config, target, intent, descriptor, "status", correlation)
        if not (_unknown_both_absent(first or {}) and _unknown_both_absent(second or {})):
            return False
        evidence = {"afterFirst": first, "afterSecond": second,
                    "closeIntent": correlation}
        evidence_sha = hashlib.sha256(json.dumps(evidence, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        return closed.get("lastEvidenceSha256") == evidence_sha
    except (OSError, ValueError, TypeError, KeyError, campaign_lease.Cp117LeaseError):
        return False


def _archived_base_record_names(root: Path, config: Any | None = None, target: Any | None = None,
                                descriptor: tuple[Any, ...] | None = None) -> set[str]:
    names: set[str] = set()
    if _pre_effect_closed(root):
        names.update({_PRE_EFFECT_REJECTED_CORRELATION + ".json",
                      _PRE_EFFECT_REJECTED_CORRELATION + ".pre-effect-closed.json"})
    if config is not None and target is not None and descriptor is not None:
        from . import windows_cp117_source_pre_effect_close as source_closure
        source_correlation = source_closure._CORRELATION
        if _intent_path(root, source_correlation).exists():
            source_archive = source_closure.archive_proof(root, descriptor)
            archive_fields = {"state", "phase", "correlationId", "replayAllowed", "nativeActionAllowed", "productAction",
                              "markerSha256", "intentSha256", "pairSha256", "commandSha256", "closureReceiptSha256"}
            if (isinstance(source_archive, dict) and set(source_archive) == archive_fields
                    and source_archive.get("state") == "archived" and source_archive.get("phase") == "verified"
                    and source_archive.get("correlationId") == source_correlation
                    and all(source_archive.get(key) is False for key in ("replayAllowed", "nativeActionAllowed", "productAction"))
                    and all(isinstance(source_archive.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", source_archive[key])
                            for key in ("markerSha256", "intentSha256", "pairSha256", "commandSha256", "closureReceiptSha256"))):
                names.update({source_correlation + ".json", source_correlation + source_closure._MARKER_SUFFIX})
        historical_names: set[str] = set()
        fixed = {"45e4514a-c629-4f3b-99bc-aad599640d29", "2ace6a48-ba60-4705-9200-4ff857f2aba6"}
        if all(_intent_path(root, correlation).exists() for correlation in fixed):
            from . import windows_cp117_historical_base_archives as historical_archives
            observed = historical_archives.observe(root, {})
            if (isinstance(observed, dict) and set(observed) == {"state", "phases", "replayAllowed", "nativeActionAllowed", "productAction"}
                    and observed.get("state") == "ready"
                    and observed.get("phases") == {"transfer-recovery": "archived", "unknown-closure": "archived"}
                    and all(observed.get(key) is False for key in ("replayAllowed", "nativeActionAllowed", "productAction"))):
                historical_names = fixed
        for correlation in _UNKNOWN_RECOVERY_PROFILES:
            if correlation in historical_names or _unknown_closure_archived(root, config, target, descriptor, correlation):
                names.update({correlation + ".json", correlation + ".unknown-close.json"})
        # Retain this completed baseline record.  Its later failed fixture-stage
        # closure needs its own historical terminal and fresh absence proof.
        historical = "c32cb108-4d48-407e-9153-40774559ba50"
        if _intent_path(root, historical).exists():
            from . import windows_cp117_c32_archive_admission as archive
            observed = archive.preflight(root, {"leaseId": "67eeeedb-a618-42d5-8e31-821650d16302"})
            if (observed.get("state") == "ready" and observed.get("correlationId") == historical
                    and all(observed.get(key) is False for key in
                            ("replayAllowed", "nativeActionAllowed", "productAction"))):
                names.add(historical + ".json")
    return names


def _reserve(root: Path, record: dict[str, Any], *, config: Any | None = None,
             target: Any | None = None, descriptor: tuple[Any, ...] | None = None) -> None:
    try:
        import fcntl
    except ModuleNotFoundError as exc:
        raise WindowsMsiBasePrepareError('Base preparation requires POSIX locking.') from exc
    directory = root / _LOCAL
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsMsiBasePrepareError("Base preparation journal is unsafe.")
    lock_fd = os.open(directory / ".environment.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        lock_info = os.fstat(lock_fd)
        def recheck_lock() -> None:
            current = (directory / ".environment.lock").lstat()
            parent = directory.lstat()
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid()
                    or stat.S_IMODE(lock_info.st_mode) != 0o600
                    or not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or (lock_info.st_dev, lock_info.st_ino) != (current.st_dev, current.st_ino)
                    or (info.st_dev, info.st_ino) != (parent.st_dev, parent.st_ino)
                    or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                    or stat.S_IMODE(parent.st_mode) != 0o700):
                raise WindowsMsiBasePrepareError("Base preparation lock changed or is unsafe.")
        recheck_lock()
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        recheck_lock()
        archived = _archived_base_record_names(root, config, target, descriptor)
        if any(item.suffix == ".json" and item.name not in archived
                for item in directory.iterdir()):
            raise WindowsMsiBasePrepareError("CP117 has an active or unknown base preparation.")
        # Static retirement publishes its intent under this same exclusive
        # base-journal lock. Recheck after acquiring it, before consuming a new
        # source correlation; a preflight receipt cannot cover that interval.
        if not _static_task_retirement_admitted(root, descriptor):
            raise WindowsMsiBasePrepareError("STATIC_RETIREMENT_UNVERIFIED")
        recheck_lock()
        path = _intent_path(root, record["request"]["correlationId"])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        os.close(lock_fd)


def _descriptor(root: Path):
    config = ssh_transport.load_config(root)
    target = config.hosts.get("archlinux")
    if target is None or target.fixture_transfer_root is None:
        raise WindowsMsiBasePrepareError("Owned Windows transfer host is unavailable.")
    env, socket, pid, ticks, account, sid, _ = windows_credential_probe_ssh._descriptor(target)
    if env != "windows-cp117" or account != "vpncp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    return config, target, (env, socket, pid, ticks, sid)


def _admit(root: Path, request: dict[str, str]) -> tuple[dict[str, Any], Path, int]:
    pair = windows_msi_public_scenario._admit_pair(root, request["sourceSha"],
        request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    if tuple(map(int, pair["baseVersion"].split("."))) <= tuple(map(int, request["expectedCurrentVersion"].split("."))):
        raise WindowsMsiBasePrepareError("Base MSI must be newer than the installed version.")
    path = windows_msi_public_scenario._verified_location(root, request["baseMsiArtifactId"],
                                                            "desktop-package", request["sourceSha"])
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or not 0 < info.st_size <= 1024 * 1024 * 1024:
        raise WindowsMsiBasePrepareError("Base MSI location is unsafe.")
    return pair, path, info.st_size


def _stage_artifact_readonly(root: Path, intent: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """Bind the staged MSI to an existing current registry record without writes."""
    request = _request(intent.get("request", {}))
    pair = intent.get("pair")
    required = {"sourceSha", "sourceFingerprint", "receiptArtifactId", "baseArtifactId", "targetArtifactId",
                "baseVersion", "targetVersion", "baseCliSha256", "baseAppJarSha256", "baseHelperSha256",
                "baseAppJarName", "baseRuntimeSha256", "targetMsiSha256", "targetMsiSize"}
    if (not isinstance(pair, Mapping) or set(pair) != required or pair.get("sourceSha") != request["sourceSha"]
            or pair.get("receiptArtifactId") != request["fixtureReceiptArtifactId"]
            or pair.get("baseArtifactId") != request["baseMsiArtifactId"]
            or pair.get("targetArtifactId") != request["targetMsiArtifactId"]
            or pair.get("targetMsiSha256") != request["targetMsiArtifactId"].removeprefix("sha256-")
            or isinstance(pair.get("targetMsiSize"), bool) or not isinstance(pair.get("targetMsiSize"), int)
            or not 0 < pair["targetMsiSize"] <= 1024 * 1024 * 1024
            or not isinstance(pair.get("sourceFingerprint"), str) or not _HASH.fullmatch(pair["sourceFingerprint"])
            or not isinstance(pair.get("baseVersion"), str) or not _VERSION.fullmatch(pair["baseVersion"])
            or not isinstance(pair.get("targetVersion"), str) or not _VERSION.fullmatch(pair["targetVersion"])
            or any(not isinstance(pair.get(key), str) or not _HASH.fullmatch(pair[key])
                   for key in ("baseCliSha256", "baseAppJarSha256", "baseHelperSha256", "baseRuntimeSha256"))
            or not isinstance(pair.get("targetMsiSha256"), str) or not _HASH.fullmatch(pair["targetMsiSha256"])
            or not isinstance(pair.get("baseAppJarName"), str)
            or not re.fullmatch(r"desktopApp-[A-Za-z0-9._-]+\.jar", pair["baseAppJarName"])):
        raise WindowsMsiBasePrepareError("Base stage intent is invalid.")
    verified = windows_msi_public_scenario.native_artifact_registry.verify_artifact_readonly(
        root, request["baseMsiArtifactId"])
    artifact, location = verified.get("artifact"), verified.get("location")
    if (verified.get("verification") != "verified" or not isinstance(artifact, Mapping)
            or not isinstance(location, Mapping) or artifact.get("platform") != "windows"
            or artifact.get("artifactKind") != "desktop-package" or artifact.get("sourceSha") != request["sourceSha"]
            or artifact.get("sourceFingerprint") != pair["sourceFingerprint"]
            or artifact.get("sha256") != request["baseMsiArtifactId"].removeprefix("sha256-")
            or not isinstance(artifact.get("size"), int) or not 0 < artifact["size"] <= 1024 * 1024 * 1024
            or location.get("evidenceClass") != "local-verified"
            or verified.get("observedSize") != artifact["size"]
            or verified.get("observedSha256") != artifact["sha256"]):
        raise WindowsMsiBasePrepareError("Base MSI artifact is unavailable for read-only stage verification.")
    return dict(pair), artifact["size"]


def _unique_product(value: Any, version: str) -> bool:
    """Accept one exact HKLM/HKCU registration for CP117's original user."""
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return False
    product = value[0]
    return (set(product) == {"version", "productCode", "installLocation", "hive"}
            and product["hive"] in {"HKLM", "HKCU"}
            and product["version"] == version
            and isinstance(product["productCode"], str) and bool(_PRODUCT.fullmatch(product["productCode"]))
            and isinstance(product["installLocation"], str)
            and product["installLocation"].rstrip("\\").casefold() == _INSTALL.rstrip("\\").casefold())


_QGA = r'''import base64,hashlib,json,os,re,secrets,socket,stat,sys
def live(sock,pid,ticks):
 if not stat.S_ISSOCK(os.lstat(sock).st_mode):return False
 raw=open('/proc/%s/stat'%pid,'rb').read().split()
 if len(raw)<22 or raw[21].decode()!=ticks:return False
 inodes=set()
 for name in os.listdir('/proc/%s/fd'%pid):
  try:
   link=os.readlink('/proc/%s/fd/%s'%(pid,name))
   if link.startswith('socket:[') and link.endswith(']'):inodes.add(link[8:-1].encode())
  except OSError:pass
 return any(len(f)==8 and f[6] in inodes and f[7]==os.fsencode(sock) for f in (line.split() for line in open('/proc/net/unix','rb')))
def call(sock,command,args):
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(20)
 try:
  c.connect(sock);sid=secrets.randbits(63)
  c.sendall(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  for i in range(8192):
   if c.recv(1)==b'\xff':break
  else:raise ValueError()
  def line():
   raw=bytearray()
   for i in range(32768):
    x=c.recv(1)
    if x==b'\n':return json.loads(raw)
    if not x:raise ValueError()
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid:raise ValueError()
  c.sendall(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  result=line()
  if 'return' not in result:raise ValueError()
  return result['return']
 finally:c.close()
def read(sock,path,maxsize=8192):
 try:handle=call(sock,'guest-file-open',{'path':path,'mode':'rb'})
 except ValueError:return None
 raw=bytearray()
 try:
  while len(raw)<maxsize:
   v=call(sock,'guest-file-read',{'handle':handle,'count':min(4096,maxsize-len(raw))})
   part=base64.b64decode(v['buf-b64'],validate=True)
   if v.get('count')!=len(part):raise ValueError()
   raw.extend(part)
   if v.get('eof') is True or not part:return bytes(raw)
  raise ValueError()
 finally:call(sock,'guest-file-close',{'handle':handle})
def decode(raw):
 if raw.startswith(b'\xff\xfe'):return raw.decode('utf-16')
 if raw.startswith(b'\xef\xbb\xbf'):return raw.decode('utf-8-sig')
 return raw.decode('utf-8')
'''


_STAGE = _QGA + campaign_lease.remote_role_guard() + r'''import fcntl,struct
args=sys.argv[1:]
if len(args)==16:mode='stream'
elif len(args)==17 and args[-1]=='preverified':mode=args.pop()
else:raise ValueError()
root,env,lease,corr,sock,pid,ticks,expected,size_text,encoded,command_hash,source,fingerprint,receipt_id,base_id,target_id=args
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='host-admission';offset=0;transferred=0;size=0
try:
 phase='host-admission'
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 phase='campaign-guard'
 require_campaign_role(root,env,lease,'base',corr,source,receipt_id,base_id,target_id,sock,pid,ticks)
 phase='remote-stage'
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base')
 for path in (root,parent,group):
  if not os.path.exists(path):os.mkdir(path,0o700)
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 lock=os.open(os.path.join(group,'.environment.lock'),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
 try:
  fcntl.flock(lock,fcntl.LOCK_EX)
  if any(name!='.environment.lock' for name in os.listdir(group)):raise FileExistsError()
  # Earlier public receipts remain archival; fixed CP176 terminal/task cleanup
  # is checked before the shared campaign is reserved. The shared remote role
  # guard above serializes all new routes across those historical directories.
  stage=os.path.join(group,corr);os.mkdir(stage,0o700)
 finally:os.close(lock)
 binding={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':expected}
 with open(os.path.join(stage,'binding.json'),'x',encoding='utf-8') as file:json.dump(binding,file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 phase='input-admission';size=int(size_text)
 if not 0<size<=1073741824 or len(encoded)>30000 or hashlib.sha256(base64.b64decode(encoded,validate=True)).hexdigest()!=command_hash:raise ValueError()
 # The first guest mutation creates only this correlation's staging directory.
 phase='guest-directory';guest='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+corr
 if mode=='stream':
  ps='[IO.Directory]::CreateDirectory(\''+guest+'\')|Out-Null'
  create=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(ps.encode('utf-16le')).decode()],'capture-output':True})
  child=create['pid']
  for i in range(30):
   state=call(sock,'guest-exec-status',{'pid':child})
   if state.get('exited') is True:
    if type(state.get('exitcode')) is not int or state['exitcode']!=0:raise ValueError()
    break
   __import__('time').sleep(.2)
  else:raise ValueError()
 if mode=='stream':
  phase='guest-file-open';dest=guest+'\\base.msi';handle=call(sock,'guest-file-open',{'path':dest,'mode':'wb'});h=hashlib.sha256();remaining=size
  try:
   while remaining:
    part=sys.stdin.buffer.read(min(49152,remaining))
    if not part:raise ValueError()
    h.update(part);remaining-=len(part);offset=0
    while offset<len(part):
     written=call(sock,'guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part[offset:]).decode()})['count']
     if type(written) is not int or not 0<written<=len(part)-offset:raise ValueError()
     offset+=written;transferred+=written
   if sys.stdin.buffer.read(1):raise ValueError()
   call(sock,'guest-file-flush',{'handle':handle})
  finally:call(sock,'guest-file-close',{'handle':handle})
  phase='guest-file-verify'
  if h.hexdigest()!=base_id.removeprefix('sha256-'):raise ValueError()
 else:
  phase='guest-file-verify'
  script=base64.b64decode('PREVERIFIED_PS_B64').decode()
  for key,value in (('__CORR__',corr),('__SID__',expected),('__SIZE__',str(size)),('__HASH__',base_id.removeprefix('sha256-'))):script=script.replace(key,value)
  check=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True})
  check_pid=check['pid']
  if type(check_pid) is not int or check_pid<=0:raise ValueError()
  for i in range(40):
   observed=call(sock,'guest-exec-status',{'pid':check_pid})
   if observed.get('exited') is True:break
   if observed.get('exited') is not False:raise ValueError()
   __import__('time').sleep(.25)
  else:raise ValueError()
  if (set(observed)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'}
   or type(observed.get('exitcode')) is not int or observed['exitcode']!=0
   or observed.get('out-truncated',False) is not False or observed.get('err-truncated',False) is not False):raise ValueError()
  raw=base64.b64decode(observed.get('out-data',''),validate=True)
  if not 0<len(raw)<=512:raise ValueError()
  lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
  proof=json.loads(lines[0]) if len(lines)==1 else None
  if proof!={'version':1,'sha256':base_id.removeprefix('sha256-'),'length':size,'ownerSid':expected}:raise ValueError()
 phase='bootstrap-dispatch'
 result=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=result['pid']
 with open(os.path.join(stage,'dispatch.json'),'x',encoding='utf-8') as file:json.dump({'pid':child},file,separators=(',',':'));file.flush();os.fsync(file.fileno())
 out({'state':'submitted','correlationId':corr})
except FileExistsError:out({'state':'unknown','reason':'existing-intent','correlationId':corr,'phase':phase,'offset':min(max(transferred,0),max(size,0))})
except Exception:out({'state':'unknown','reason':'submission-uncertain','correlationId':corr,'phase':phase if phase in {'host-admission','campaign-guard','remote-stage','input-admission','guest-directory','guest-file-open','guest-file-verify','bootstrap-dispatch'} else 'protocol','offset':min(max(transferred,0),max(size,0))})
'''

_PREVERIFIED_PS = r'''$ErrorActionPreference='Stop'
$sid='__SID__';$corr='__CORR__';$size=__SIZE__;$hash='__HASH__'
$profile='C:\Users\vpncp117';$app=Join-Path $profile 'AppData';$local=Join-Path $app 'Local';$product=Join-Path $local 'VpnControl';$stage=Join-Path $product ('mcp-base-'+$corr);$msi=Join-Path $stage 'base.msi'
foreach($path in @($profile,$app,$local,$product,$stage)) {
 $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
 if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'DIRECTORY' }
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $path).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if($path -ceq $profile) {
  if($owner -cne $sid -and $owner -cne 'S-1-5-18') { throw 'OWNER' }
 } elseif($owner -cne $sid) { throw 'OWNER' }
}
$item=Get-Item -LiteralPath $msi -Force -ErrorAction Stop
if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or $item.Length -ne $size) { throw 'FILE' }
$owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $msi).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
if($owner -cne $sid) { throw 'OWNER' }
$actual=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if($actual -cne $hash) { throw 'HASH' }
[Console]::Out.WriteLine(([pscustomobject]@{version=1;sha256=$actual;length=$item.Length;ownerSid=$owner}|ConvertTo-Json -Compress))
'''
_STAGE = _STAGE.replace('PREVERIFIED_PS_B64', base64.b64encode(_PREVERIFIED_PS.encode()).decode())


def _task(correlation: str, pair: dict[str, Any], expected_current: str, sid: str) -> str:
    root = _ROOT + "\\mcp-base-" + correlation
    return r"""$ErrorActionPreference='Stop';$root={root};$msi=Join-Path $root 'base.msi';$stage='IDENTITY'
function P([string]$result,[int]$exitCode){{([pscustomobject]@{{version=1;correlationId={corr};stage=$stage;result=$result;exitCode=$exitCode;originalSid=$identity.User.Value;sessionId=(Get-Process -Id $PID).SessionId;limited=$limited;msiSha256=$observedMsiHash;installedVersion=$observedVersion;cliSha256=$observedCliHash;jarSha256=$observedJarHash;helperSha256=$observedHelperHash;priorProducts=$priorProducts;installedProducts=$installedProducts}}|ConvertTo-Json -Depth 5 -Compress)|Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding UTF8}}
try{{
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($identity.User.Value -cne {sid} -or (Get-Process -Id $PID).SessionId -ne 1 -or -not $limited){{throw 'IDENTITY'}}
$stage='ADMISSION'
$observedMsiHash=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if($observedMsiHash -cne {hash}){{throw 'MSI_HASH'}}
$products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {{$_.DisplayName -eq 'vpn-control'}})
if($products.Count -ne 1 -or $products[0].DisplayVersion -cne {current}){{throw 'CURRENT_PRODUCT'}}
$priorProducts=@($products|ForEach-Object {{[pscustomobject]@{{version=$_.DisplayVersion;productCode=$_.PSChildName;installLocation=$_.InstallLocation;hive=$_.PSDrive.Name}}}})
$active=@(Get-CimInstance Win32_Process|Where-Object {{$_.Name -match '^(vpn-control-cli|msiexec|consent|sing-box)\.exe$'}})
if($active.Count -ne 0){{throw 'ACTIVE_PROCESS'}}
$stage='INSTALL';P 'IN_PROGRESS' -1
$arguments='/i "'+$msi+'" /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1 /L*v "'+(Join-Path $root 'base-msi.log')+'"'
$installer=Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList $arguments -PassThru -Wait
$stage='READBACK'
$after=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {{$_.DisplayName -eq 'vpn-control'}})
$cli='C:\Users\vpncp117\AppData\Local\vpn-control\vpn-control-cli.exe'
$jar=Join-Path 'C:\Users\vpncp117\AppData\Local\vpn-control\app' {jar}
$helper='C:\Users\vpncp117\AppData\Local\vpn-control\app\native\windows-amd64\vpn-control-install-helper.exe'
$observedVersion=if($after.Count -eq 1){{$after[0].DisplayVersion}}else{{$null}}
$installedProducts=@($after|ForEach-Object {{[pscustomobject]@{{version=$_.DisplayVersion;productCode=$_.PSChildName;installLocation=$_.InstallLocation;hive=$_.PSDrive.Name}}}})
$observedCliHash=(Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
$observedJarHash=(Get-FileHash -LiteralPath $jar -Algorithm SHA256).Hash.ToLowerInvariant()
$observedHelperHash=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant()
$ok=$installer.ExitCode -eq 0 -and $observedVersion -ceq {base_version} -and
 $observedCliHash -ceq {cli_hash} -and $observedJarHash -ceq {jar_hash} -and $observedHelperHash -ceq {helper_hash}
if($ok){{P 'PASSED' $installer.ExitCode}}else{{P 'FAILED' $installer.ExitCode}}
}}catch{{P 'FAILED' -1;exit 1}}
""".format(root=windows_msi_public_scenario._ps_literal(root), corr=windows_msi_public_scenario._ps_literal(correlation),
           sid=windows_msi_public_scenario._ps_literal(sid), hash=windows_msi_public_scenario._ps_literal(pair["baseArtifactId"].removeprefix("sha256-")),
           current=windows_msi_public_scenario._ps_literal(expected_current), base_version=windows_msi_public_scenario._ps_literal(pair["baseVersion"]),
           jar=windows_msi_public_scenario._ps_literal(pair["baseAppJarName"]), cli_hash=windows_msi_public_scenario._ps_literal(pair["baseCliSha256"]),
           jar_hash=windows_msi_public_scenario._ps_literal(pair["baseAppJarSha256"]), helper_hash=windows_msi_public_scenario._ps_literal(pair["baseHelperSha256"]))


def _bootstrap(correlation: str, pair: dict[str, Any], current: str, sid: str) -> str:
    root = _ROOT + "\\mcp-base-" + correlation
    task = "VpnControlMcpBase-" + correlation
    packed_task = base64.b64encode(gzip.compress(_task(correlation, pair, current, sid).encode("utf-16le"), mtime=0)).decode()
    return r"""$ErrorActionPreference='Stop';$root={root};$task={task}
try{{
if(-not [IO.Directory]::Exists($root) -or (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue)){{throw 'EXCLUSIVE'}}
$msi=Join-Path $root 'base.msi'
if((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne {hash}){{throw 'MSI_HASH'}}
$compressed=[Convert]::FromBase64String({packed_task})
$inputStream=[IO.MemoryStream]::new([byte[]]$compressed)
$decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
$outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
$body=[Convert]::ToBase64String($outputStream.ToArray())
$decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$body)
$principal=New-ScheduledTaskPrincipal -UserId {account} -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings|Out-Null
Start-ScheduledTask -TaskName $task
([pscustomobject]@{{version=1;correlationId={corr};triggered=$true}}|ConvertTo-Json -Compress)
}}catch{{([pscustomobject]@{{version=1;correlationId={corr};triggered=$false}}|ConvertTo-Json -Compress);exit 1}}
""".format(root=windows_msi_public_scenario._ps_literal(root), task=windows_msi_public_scenario._ps_literal(task),
           hash=windows_msi_public_scenario._ps_literal(pair["baseArtifactId"].removeprefix("sha256-")),
           packed_task=windows_msi_public_scenario._ps_literal(packed_task),
           account=windows_msi_public_scenario._ps_literal(_ACCOUNT), corr=windows_msi_public_scenario._ps_literal(correlation))


def _powershell_preflight_script() -> str:
    """Parse both fixed CP117 programs on PowerShell 5.1 without running them."""
    pair = {"baseArtifactId": "sha256-" + "a" * 64, "baseVersion": "2.1.19",
            "baseCliSha256": "b" * 64, "baseAppJarSha256": "c" * 64,
            "baseHelperSha256": "d" * 64, "baseAppJarName": "desktopApp-fixed.jar"}
    corr = "11111111-1111-4111-8111-111111111111"
    bootstrap = _bootstrap(corr, pair, "2.1.17", "S-1-5-21-1-2-3-1002")
    task = _task(corr, pair, "2.1.17", "S-1-5-21-1-2-3-1002")
    readiness = _readiness_script("2.1.17", "S-1-5-21-1-2-3-1002")
    def packed(value: str) -> str:
        return base64.b64encode(gzip.compress(value.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
function Expand([string]$body) {
 $packed=[Convert]::FromBase64String($body)
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 return $body
}
try {
 $bootstrap=Expand '@BOOTSTRAP@';$task=Expand '@TASK@';$readiness=Expand '@READINESS@'
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($bootstrap,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'BOOTSTRAP_SYNTAX'}
 [System.Management.Automation.Language.Parser]::ParseInput($task,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'TASK_SYNTAX'}
 [System.Management.Automation.Language.Parser]::ParseInput($readiness,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'READINESS_SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@BOOTSTRAP@", packed(bootstrap)).replace("@TASK@", packed(task)).replace("@READINESS@", packed(readiness))


def _preverified_powershell_preflight_script() -> str:
    """Parse the fixed guest hash/owner proof in PS5 without executing it."""
    sample = (_PREVERIFIED_PS.replace("__CORR__", "11111111-1111-4111-8111-111111111111")
              .replace("__SID__", "S-1-5-21-1-2-3-1002")
              .replace("__SIZE__", "131101044")
              .replace("__HASH__", "a" * 64))
    packed = base64.b64encode(gzip.compress(sample.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
try {
 $packed=[Convert]::FromBase64String('@SCRIPT@')
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@SCRIPT@", packed)


def _terminal_reconcile_powershell_preflight_script() -> str:
    """Parse the read-only durable terminal probe on Windows PowerShell 5.1."""
    sample = (_TERMINAL_PS.replace("__CORR__", "11111111-1111-4111-8111-111111111111")
              .replace("__SID__", "S-1-5-21-1-2-3-1002")
              .replace("__ACTION__", "a" * 64).replace("__BASE_HASH__", "b" * 64)
              .replace("__CLI_HASH__", "c" * 64).replace("__JAR_HASH__", "d" * 64)
              .replace("__HELPER_HASH__", "e" * 64)
              .replace("__JAR_NAME__", "desktopApp-2.1.19.jar"))
    packed = base64.b64encode(gzip.compress(sample.encode("utf-16le"), mtime=0)).decode()
    return r'''$ErrorActionPreference='Stop'
try {
 $packed=[Convert]::FromBase64String('@SCRIPT@')
 $inputStream=[IO.MemoryStream]::new([byte[]]$packed)
 $decompressor=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress)
 $outputStream=[IO.MemoryStream]::new();$decompressor.CopyTo($outputStream)
 $body=[Text.Encoding]::Unicode.GetString($outputStream.ToArray())
 $decompressor.Dispose();$inputStream.Dispose();$outputStream.Dispose()
 $tokens=$null;$errors=$null
 [System.Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'SYNTAX'}
 [Console]::Out.WriteLine('{"version":1,"code":"OK"}')
}catch{[Console]::Out.WriteLine('{"version":1,"code":"FAILED"}');exit 1}
'''.replace("@SCRIPT@", packed)


def powershell_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or value.get("host") != "archlinux"
            or dict(value) not in ({"host": "archlinux"},
                                   {"host": "archlinux", "profile": "preverified"},
                                   {"host": "archlinux", "profile": "terminal-reconcile"})):
        raise WindowsMsiBasePrepareError("Base PS5 preflight requires exact owned host.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, _) = _descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    script = (_preverified_powershell_preflight_script() if value.get("profile") == "preverified"
              else _terminal_reconcile_powershell_preflight_script() if value.get("profile") == "terminal-reconcile"
              else _powershell_preflight_script())
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base PS5 preflight exceeds Windows command admission.")
    raw = windows_credential_probe_ssh._run_ssh(config, "archlinux",
        windows_credential_probe_ssh._remote_command(windows_msi_public_scenario._REMOTE_PREFLIGHT,
            socket, str(pid), str(ticks), encoded), None, 30)
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        result = {}
    if not isinstance(result, dict) or result.get("state") not in {"passed", "failed"}:
        return {"state": "unknown", "checks": []}
    return {"state": result["state"], "checks": ["ps5-parse", "gzip"]}


def _readiness_script(expected_version: str, expected_sid: str) -> str:
    """Read installed registration and idle original-user session without changes."""
    version = windows_msi_public_scenario._ps_literal(expected_version)
    sid = windows_msi_public_scenario._ps_literal(expected_sid)
    return r'''$ErrorActionPreference='Stop'
try {
 $sid=@SID@;$expected=@VERSION@
 $hku='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
 $hku32='Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
 $products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',$hku,$hku32 -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control-cli|msiexec|consent|sing-box)\.exe$'})
 if($active.Count -gt 16){throw 'ACTIVE_BOUND'}
 $lockPid=$null
 try{$lockRaw=(Get-Content -LiteralPath 'C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state\vpn-control.lock' -Raw -ErrorAction Stop).Trim();if($lockRaw -match '^[0-9]{1,10}$'){$lockPid=[int]$lockRaw}}catch{}
 $activeProcesses=@($active|ForEach-Object {
  $process=$_;$kind=$process.Name.ToLowerInvariant().Replace('.exe','')
  $role=switch($kind){'msiexec'{'installer'}'consent'{'authorization'}'sing-box'{'runtime'}default{'unknown'}}
  if($kind -eq 'vpn-control-cli'){
   if($null -eq $process.CommandLine){$role='unknown'}
   elseif($process.CommandLine -match '(^|\s)serve(\s|$)'){$role='owner'}
   else{$role='command'}
  }
  $processOwner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  [pscustomobject]@{kind=$kind;pid=[int]$process.ProcessId;parentPid=[int]$process.ParentProcessId;startedAtUtc=$process.CreationDate.ToUniversalTime().ToString('o');sessionId=[int]$process.SessionId;originalUser=($processOwner.ReturnValue -eq 0 -and $processOwner.Sid -ceq $sid);role=$role;currentWorkspaceOwner=($null -ne $lockPid -and $process.ProcessId -eq $lockPid)}
 })
 $activeKinds=@($active|ForEach-Object {$_.Name.ToLowerInvariant().Replace('.exe','')}|Sort-Object -Unique)
 $explorers=@(Get-CimInstance Win32_Process -Filter "name='explorer.exe'"|Where-Object {$_.SessionId -eq 1})
 $owned=0
 foreach($process in $explorers){$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid;if($owner.ReturnValue -eq 0 -and $owner.Sid -ceq $sid){$owned++}}
 $version=if($products.Count -eq 1){$products[0].DisplayVersion}else{$null}
 $ready=$products.Count -eq 1 -and $version -ceq $expected -and $active.Count -eq 0 -and $owned -eq 1
 $code=if($ready){'READY'}elseif($products.Count -ne 1){'PRODUCT_COUNT'}elseif($version -cne $expected){'PRODUCT_VERSION'}elseif($active.Count -ne 0){'ACTIVE_PROCESS'}else{'SESSION_OWNER'}
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;code=$code;installedVersion=$version;productCount=$products.Count;activeCount=$active.Count;activeKinds=$activeKinds;activeProcesses=$activeProcesses;workspaceLockPid=$lockPid;ownedExplorerCount=$owned}|ConvertTo-Json -Depth 5 -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}
'''.replace("@SID@", sid).replace("@VERSION@", version)


_READINESS = _QGA + r'''import time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or len(encoded)>=30000:raise ValueError()
 start=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})
 child=start['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for attempt in range(40):
  state=call(sock,'guest-exec-status',{'pid':child})
  if state.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 if (state.get('out-truncated') is True or state.get('err-truncated') is True
     or ('out-truncated' in state and type(state.get('out-truncated')) is not bool)
     or ('err-truncated' in state and type(state.get('err-truncated')) is not bool)):raise ValueError()
 raw=base64.b64decode(state.get('out-data',''),validate=True)
 if len(raw)>4096:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if type(state.get('exitcode')) is not int or state['exitcode']!=0 or len(lines)!=1:raise ValueError()
 out({'state':'observed','inventory':json.loads(lines[0])})
except Exception:out({'state':'unknown'})
'''


def readiness(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, Mapping) or set(value) != {"host", "expectedCurrentVersion"}
            or value["host"] != "archlinux" or not isinstance(value["expectedCurrentVersion"], str)
            or not _VERSION.fullmatch(value["expectedCurrentVersion"])):
        raise WindowsMsiBasePrepareError("Base readiness requires exact CP117 host and version.")
    root = Path(root).resolve(strict=True)
    config, _, (env, socket, pid, ticks, sid) = _descriptor(root)
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("Owned CP117 guest identity changed.")
    encoded = base64.b64encode(_readiness_script(value["expectedCurrentVersion"], sid).encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base readiness exceeds Windows command admission.")
    raw = _remote(config, _READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    unknown = {"state": "unknown", "ready": False, "productAction": False}
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        return unknown
    if not isinstance(result, dict) or result.get("state") != "observed" or not isinstance(result.get("inventory"), dict):
        return unknown
    inventory = result["inventory"]
    codes = {"READY", "PRODUCT_COUNT", "PRODUCT_VERSION", "ACTIVE_PROCESS", "SESSION_OWNER"}
    if (set(inventory) != {"version", "code", "installedVersion", "productCount", "activeCount", "activeKinds", "activeProcesses", "workspaceLockPid", "ownedExplorerCount"}
            or inventory["version"] != 1 or inventory["code"] not in codes
            or type(inventory["productCount"]) is not int or inventory["productCount"] < 0
            or type(inventory["activeCount"]) is not int or inventory["activeCount"] < 0
            or not isinstance(inventory["activeKinds"], list) or len(inventory["activeKinds"]) > 4
            or len(set(x for x in inventory["activeKinds"] if isinstance(x, str))) != len(inventory["activeKinds"])
            or any(x not in {"vpn-control-cli", "msiexec", "consent", "sing-box"} for x in inventory["activeKinds"])
            or (inventory["activeCount"] == 0) != (len(inventory["activeKinds"]) == 0)
            or not isinstance(inventory["activeProcesses"], list)
            or len(inventory["activeProcesses"]) != inventory["activeCount"]
            or len(inventory["activeProcesses"]) > 16
            or (inventory["workspaceLockPid"] is not None and
                (type(inventory["workspaceLockPid"]) is not int or inventory["workspaceLockPid"] <= 0))
            or type(inventory["ownedExplorerCount"]) is not int or inventory["ownedExplorerCount"] < 0
            or (inventory["installedVersion"] is not None and (not isinstance(inventory["installedVersion"], str)
                or not _VERSION.fullmatch(inventory["installedVersion"])))):
        return unknown
    roles = {"vpn-control-cli": {"owner", "command", "unknown"}, "msiexec": {"installer"},
             "consent": {"authorization"}, "sing-box": {"runtime"}}
    for process in inventory["activeProcesses"]:
        if (not isinstance(process, dict) or set(process) != {"kind", "pid", "parentPid", "startedAtUtc", "sessionId", "originalUser", "role", "currentWorkspaceOwner"}
                or process.get("kind") not in roles or process.get("role") not in roles[process["kind"]]
                or type(process.get("pid")) is not int or process["pid"] <= 0
                or type(process.get("parentPid")) is not int or process["parentPid"] < 0
                or not isinstance(process.get("startedAtUtc"), str)
                or type(process.get("sessionId")) is not int or process["sessionId"] < 0
                or type(process.get("originalUser")) is not bool
                or type(process.get("currentWorkspaceOwner")) is not bool):
            return unknown
        try:
            datetime.fromisoformat(process["startedAtUtc"].replace("Z", "+00:00"))
        except ValueError:
            return unknown
    if sorted({p["kind"] for p in inventory["activeProcesses"]}) != inventory["activeKinds"]:
        return unknown
    if any(p["currentWorkspaceOwner"] != (p["pid"] == inventory["workspaceLockPid"])
           for p in inventory["activeProcesses"]):
        return unknown
    ready = (inventory["code"] == "READY" and inventory["productCount"] == 1
             and inventory["installedVersion"] == value["expectedCurrentVersion"]
             and inventory["activeCount"] == 0 and inventory["ownedExplorerCount"] == 1)
    if inventory["code"] == "READY" and not ready:
        return unknown
    return {"state": "ready" if ready else "blocked", "ready": ready, "code": inventory["code"],
            "installedVersion": inventory["installedVersion"], "productCount": inventory["productCount"],
            "activeCount": inventory["activeCount"], "activeKinds": inventory["activeKinds"],
            "activeProcesses": inventory["activeProcesses"],
            "workspaceLockPid": inventory["workspaceLockPid"],
            "ownedExplorerCount": inventory["ownedExplorerCount"],
            "productAction": False}


def _remote(config: Any, program: str, args: tuple[str, ...], source: Path | None, timeout: int) -> bytes | None:
    command = windows_credential_probe_ssh._remote_command(program, *args)
    argv = ssh_transport.build_ssh_argv(config, "archlinux", min(timeout, 60), command=command)
    try:
        if source is None:
            completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=timeout, check=False)
        else:
            with source.open("rb") as stream:
                completed = subprocess.run(argv, stdin=stream, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, timeout=timeout, check=False)
        return completed.stdout if completed.returncode == 0 and len(completed.stdout) <= 16384 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


_PRE_EFFECT_STATUS = _QGA + r'''import time
root,env,corr,sock,pid,ticks=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or corr!='30a6f33b-3ea2-42d0-8818-3d6711b34169' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base')
 for path in (root,parent):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 if os.path.lexists(os.path.join(group,corr)):
  out({'state':'present','correlationId':corr});raise SystemExit(0)
 if os.path.lexists(group):
  info=os.lstat(group)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 script="$ErrorActionPreference='Stop';$corr='"+corr+"';$task='VpnControlMcpBase-'+$corr;$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr;try{$registered=Get-ScheduledTask -TaskPath '\\' -TaskName $task -ErrorAction SilentlyContinue;if($registered -or [IO.Directory]::Exists($leaf) -or [IO.File]::Exists($leaf)){[Console]::Out.WriteLine('{\"version\":1,\"state\":\"present\"}')}else{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"absent\"}')}}catch{[Console]::Out.WriteLine('{\"version\":1,\"state\":\"unknown\"}');exit 1}"
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if observed.get('exited') is True:break
  time.sleep(.25)
 else:raise ValueError()
 if (type(observed.get('exitcode')) is not int or observed['exitcode']!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True
     or ('out-truncated' in observed and type(observed.get('out-truncated')) is not bool)
     or ('err-truncated' in observed and type(observed.get('err-truncated')) is not bool)):raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 if len(lines)!=1 or json.loads(lines[0])!={'version':1,'state':'absent'}:raise ValueError()
 out({'state':'absent','correlationId':corr,'qemuPid':int(pid),'startTicks':int(ticks)})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def pre_effect_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiBasePrepareError("Base pre-effect status requires exact owned host.")
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, _PRE_EFFECT_REJECTED_CORRELATION)
    if (intent is None or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("leaseId") != _PRE_EFFECT_REJECTED_CORRELATION
            or intent.get("request", {}).get("correlationId") != _PRE_EFFECT_REJECTED_CORRELATION):
        raise WindowsMsiBasePrepareError("Base pre-effect identity changed.")
    config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    if any(intent.get(key) != observed for key, observed in (("environment", env),
            ("socketPath", sock), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return {"state": "unknown", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION}
    raw = _remote(config, _PRE_EFFECT_STATUS,
        (str(target.fixture_transfer_root), env, _PRE_EFFECT_REJECTED_CORRELATION,
         sock, str(pid), str(ticks)), None, 30)
    try: observed = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError): observed = {}
    exact = {"state": "absent", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION,
             "qemuPid": pid, "startTicks": ticks}
    return exact if observed == exact else {"state": "unknown", "correlationId": _PRE_EFFECT_REJECTED_CORRELATION}


def close_pre_effect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close only the known pre-dispatch SSH validation failure, preserving its intent."""
    if not isinstance(value, Mapping) or set(value) != {"host"} or value["host"] != "archlinux":
        raise WindowsMsiBasePrepareError("Base pre-effect closure requires exact owned host.")
    root = Path(root).resolve(strict=True)
    corr = _PRE_EFFECT_REJECTED_CORRELATION
    intent = _private_intent(root, corr)
    if (intent is None or intent.get("request") != _PRE_EFFECT_REJECTED_REQUEST
            or intent.get("commandSha256") != _PRE_EFFECT_REJECTED_COMMAND_SHA256
            or intent.get("leaseId") != corr):
        raise WindowsMsiBasePrepareError("Base pre-effect intent changed.")
    config, target, descriptor = _descriptor(root)
    env, sock, pid, ticks, sid = descriptor
    if (pid != 589342 or ticks != 520739 or
            any(intent.get(key) != observed for key, observed in (("environment", env),
                ("socketPath", sock), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
        raise WindowsMsiBasePrepareError("Base pre-effect guest generation changed.")
    expected_absence = {"state": "absent", "correlationId": corr, "qemuPid": pid, "startTicks": ticks}
    if (pre_effect_status(root, {"host": "archlinux"}) != expected_absence
            or pre_effect_status(root, {"host": "archlinux"}) != expected_absence):
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
    if (idle.get("state") != "ready" or idle.get("ready") is not True
            or idle.get("code") != "READY" or idle.get("installedVersion") != "2.1.17"
            or idle.get("productCount") != 1 or idle.get("activeCount") != 0
            or idle.get("activeProcesses") != []):
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    identity = _campaign_identity(_PRE_EFFECT_REJECTED_REQUEST, descriptor)
    proof = {"correlationId": corr, "commandSha256": _PRE_EFFECT_REJECTED_COMMAND_SHA256,
             "sourceSha": _PRE_EFFECT_REJECTED_REQUEST["sourceSha"], "qemuPid": pid,
             "startTicks": ticks, "remoteStageTaskGuestLeafAbsent": True,
             "installedVersion": "2.1.17", "productCount": 1, "activeCount": 0,
             "failure": "ssh-connect-timeout-rejected-before-dispatch"}
    evidence_sha = hashlib.sha256(json.dumps(proof, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()
    cleanup = {"guestGeneration": {"socketPath": sock, "qemuPid": pid, "startTicks": ticks},
               "serverStopped": True, "credentialsCleaned": True,
               "protectedJobsTerminalCleaned": True, "activeInstallerProcessesAbsent": True,
               "cleanupReceiptSha256": hashlib.sha256((evidence_sha + ":campaign-closed").encode()).hexdigest()}
    remote = _campaign_remote(config, target)
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        closed = campaign_lease._closed(directory, corr) if record is None else None
        if record is not None and record["identity"] != identity:
            raise WindowsMsiBasePrepareError("Base campaign identity changed.")
        if closed is not None and closed["identity"] != identity:
            raise WindowsMsiBasePrepareError("Closed base campaign identity changed.")
    finally: os.close(lock)
    if record is not None and record["state"] in {"pending-finish", "pending-close"}:
        resumed = campaign_lease.reconcile(root, corr, remote)
        if resumed["state"] == "unknown":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        directory, lock = campaign_lease._locked(root)
        try:
            record = campaign_lease._active(directory)
            closed = campaign_lease._closed(directory, corr) if record is None else None
        finally: os.close(lock)
    if (record is not None and record["state"] == "role-active"
            and record["role"] == "base" and record["correlationId"] == corr
            and record["server"] == "stopped" and record["credentials"] == "absent"
            and record["lastEvidenceSha256"] is None):
        if not campaign_lease._remote_confirm(remote, "status", record, None):
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        finished = campaign_lease.finish_role(root, corr, "base", corr, evidence_sha,
                                               "failed-cleaned", remote)
        if finished["state"] != "active":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        directory, lock = campaign_lease._locked(root)
        try: record = campaign_lease._active(directory)
        finally: os.close(lock)
    if record is not None:
        if (record["state"] != "active" or record["role"] is not None
                or record["correlationId"] is not None or record["server"] != "stopped"
                or record["credentials"] != "absent" or record["lastOutcome"] != "failed-cleaned"
                or record["lastEvidenceSha256"] != evidence_sha):
            raise WindowsMsiBasePrepareError("Base campaign is not verified failed-cleaned.")
        if not campaign_lease._remote_confirm(remote, "status", record, None):
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
        finished = campaign_lease.close(root, corr, cleanup, remote)
        if finished["state"] != "closed":
            return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    if campaign_lease.reconcile(root, corr, remote)["state"] != "closed":
        return {"state": "unknown", "correlationId": corr, "replayAllowed": False}
    marker = _pre_effect_marker(root)
    marker_value = {"correlationId": corr, "commandSha256": _PRE_EFFECT_REJECTED_COMMAND_SHA256,
                    "state": "pre-effect-closed", "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"]}
    if marker.exists():
        if not _pre_effect_closed(root):
            raise WindowsMsiBasePrepareError("Base pre-effect marker changed.")
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(marker_value, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        parent = os.open(marker.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    if not _pre_effect_closed(root):
        raise WindowsMsiBasePrepareError("Base pre-effect closure did not verify.")
    return {"state": "pre-effect-closed", "correlationId": corr,
            "cleanupReceiptSha256": cleanup["cleanupReceiptSha256"], "replayAllowed": False}


def _campaign_remote(config: Any, target: Any):
    """Fixed journal transport; no QGA guest-exec or product action."""
    def send(action: str, payload: Mapping[str, Any]) -> bytes | None:
        return _remote(config, campaign_lease.remote_program(),
            campaign_lease.remote_arguments(target.fixture_transfer_root, action, payload), None, 30)
    return send


def _campaign_identity(request: Mapping[str, Any], descriptor: tuple[Any, ...]) -> dict[str, Any]:
    env, socket, pid, ticks, _sid = descriptor
    return {"host": "archlinux", "environment": env, "leaseId": request["correlationId"],
            "operator": "windows-base", "sourceSha": request["sourceSha"],
            "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"],
            "socketPath": socket, "qemuPid": pid, "startTicks": ticks}


_FIXED_C32_TASK = "VpnControlMcpBase-c32cb108-4d48-407e-9153-40774559ba50"
_FIXED_RECOVERY_TASK = "VpnControlCp117GuestAgentRecovery-c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58"


def _legacy_task_script() -> str:
    """Read every owned task namespace; counts never prove terminal bindings."""
    return r'''$ErrorActionPreference='Stop'
try {
 $tokens=$null;$errors=$null
 [Management.Automation.Language.Parser]::ParseInput($MyInvocation.MyCommand.Definition,[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count -ne 0){throw 'AST'}
 $all=@(Get-ScheduledTask -ErrorAction Stop)
 $tasks=@($all|Where-Object {$_.TaskName -match '^VpnControl(Mcp|Cp117)'})
 if($tasks.Count -gt 64){throw 'BOUND'}
 $active=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'})
 $legacy=@($tasks|Where-Object {$_.TaskName -ceq @LEGACY@ -and $_.TaskPath -ceq '\'})
 $c32=@($tasks|Where-Object {$_.TaskName -ceq @C32@ -and $_.TaskPath -ceq '\'})
 $recovery=@($tasks|Where-Object {$_.TaskName -ceq @RECOVERY@ -and $_.TaskPath -ceq '\'})
 $other=@($tasks|Where-Object {$_.TaskName -cnotin @(@LEGACY@,@C32@,@RECOVERY@) -or $_.TaskPath -cne '\'})
 [Console]::Out.WriteLine(([pscustomobject]@{version=2;legacyTaskCount=$legacy.Count;
 c32TaskCount=$c32.Count;recoveryTaskCount=$recovery.Count;otherTaskCount=$other.Count;
 activeInstallerCount=$active.Count}|ConvertTo-Json -Compress))
}catch{[Console]::Out.WriteLine('{"version":2,"code":"UNKNOWN"}');exit 1}
'''.replace("@LEGACY@", windows_msi_public_scenario._ps_literal("VpnControlMcpMsi-" + _LEGACY_CORRELATION)).replace(
        "@C32@", windows_msi_public_scenario._ps_literal(_FIXED_C32_TASK)).replace(
        "@RECOVERY@", windows_msi_public_scenario._ps_literal(_FIXED_RECOVERY_TASK))


def _fixed_c32_task_terminal(root: Path, descriptor: tuple[Any, ...], lease_id: str | None) -> bool:
    """The archive adapter verifies exact action/principal, terminal and no work."""
    from . import windows_cp117_c32_archive_admission as archive
    if not isinstance(lease_id, str) or not _UUID.fullmatch(lease_id):
        return False
    proof = archive.preflight(root, {"leaseId": lease_id})
    return (proof.get("state") == "ready"
            and proof.get("correlationId") == _FIXED_C32_TASK.removeprefix("VpnControlMcpBase-")
            and _descriptor(root)[2] == descriptor)


def _fixed_recovery_task_status_script() -> str:
    """Reject automatic execution settings before the protected terminal read."""
    from . import windows_cp117_guest_agent_recovery_successor as recovery
    prefix = r'''$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseInput($MyInvocation.MyCommand.Definition,[ref]$tokens,[ref]$errors)|Out-Null
if($errors.Count -ne 0){throw 'AST'}
$task=Get-ScheduledTask -TaskName @TASK@ -TaskPath '\' -ErrorAction Stop
$triggers=@($task.Triggers|Where-Object {$null -ne $_})
[xml]$taskXml=Export-ScheduledTask -TaskName @TASK@ -TaskPath '\' -ErrorAction Stop
$ns=[Xml.XmlNamespaceManager]::new($taskXml.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
$xmlTriggers=@($taskXml.SelectNodes('/t:Task/t:Triggers/*',$ns))
$xmlRestart=@($taskXml.SelectNodes('/t:Task/t:Settings/t:RestartOnFailure',$ns))
if($triggers.Count -ne 0 -or $xmlTriggers.Count -ne 0 -or $xmlRestart.Count -ne 0 -or $task.Settings.RestartCount -ne 0){throw 'RECOVERY_AUTOSTART'}
'''.replace("@TASK@", windows_msi_public_scenario._ps_literal(_FIXED_RECOVERY_TASK))
    return prefix + recovery._status_script()


def _fixed_recovery_task_terminal(root: Path, descriptor: tuple[Any, ...]) -> bool:
    """Read existing local and fresh protected guest terminal; never promote it."""
    from . import windows_cp117_guest_agent_recovery_successor as recovery
    from . import windows_cp117_historical_base_archives as history
    directory = root / recovery._DIR
    for parent in (root / ".rag_index", directory):
        if not parent.exists():
            return False
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or info.st_uid != os.getuid()
                or (parent == directory and stat.S_IMODE(info.st_mode) != 0o700)):
            return False
    intent = history._read(directory / "intent.json")
    terminal = history._read(directory / "terminal.json")
    action = history._read(directory / "action.json")
    if (not isinstance(intent, dict) or set(intent) != {"recoveryCorrelationId", "service", "guestGeneration"}
            or intent.get("recoveryCorrelationId") != recovery._RECOVERY
            or recovery.original._identity(intent.get("service", {})) is None):
        return False
    digest = recovery._digest(intent)
    expected_action = recovery._action(intent["service"], digest)
    if (terminal != {"intentSha256": digest, "outcome": "restarted"}
            or action != {"intentSha256": digest, "actionSha256": expected_action}
            or intent.get("guestGeneration") != {"socketPath": descriptor[1],
                 "qemuPid": descriptor[2], "startTicks": descriptor[3]}):
        return False
    config, _target, current = _descriptor(root)
    if current != descriptor:
        return False
    observed = recovery.original._run_ps(config, descriptor, _fixed_recovery_task_status_script())
    fields = {"binding", "terminalBinding", "outcome", "taskSystem", "taskState", "actionSha256",
              "service", "recoveryCorrelationId", "childPid", "childStartTicks"}
    return (isinstance(observed, dict) and set(observed) == fields
            and observed["binding"] == digest and observed["terminalBinding"] == digest
            and observed["actionSha256"] == expected_action and observed["outcome"] == "restarted"
            and observed["taskSystem"] is True and observed["taskState"] == "Ready"
            and observed["recoveryCorrelationId"] == recovery._RECOVERY
            and type(observed["childPid"]) is int and observed["childPid"] > 0
            and type(observed["childStartTicks"]) is int and observed["childStartTicks"] > 0
            and recovery.original._restarted_identity(intent["service"], observed["service"])
            and _descriptor(root)[2] == descriptor)


def _static_task_retirement_admitted(root: Path, descriptor: tuple[Any, ...]) -> bool:
    """A consumed static-task intent excludes new work until fresh closure proof.

    The remote shared lock may outlive SSH observation. Its local durable intent
    therefore remains an exclusion independently of a transport deadline.
    """
    from . import windows_cp117_static_tasks_retire as retirement
    directory = root / retirement._DIR
    try:
        if os.path.lexists(directory):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink()
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                return False
        if not os.path.lexists(directory / "intent.json"):
            return True
        proof = retirement.status(root, {})
        return (isinstance(proof, Mapping)
                and all(proof.get(flag) is False for flag in
                        ("replayAllowed", "nativeActionAllowed", "productAction"))
                and proof == {"state": "retired", "phase": "complete",
                          "retirementCorrelationId": retirement._RETIREMENT,
                          "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
                and _descriptor(root)[2] == descriptor)
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _legacy_task_observation(root: Path, descriptor: tuple[Any, ...],
                             lease_id: str | None = None) -> dict[str, Any]:
    env, socket, pid, ticks, _sid = descriptor
    if env != "windows-cp117":
        return {"state": "unknown"}
    config, _target, current = _descriptor(root)
    if current != descriptor:
        return {"state": "unknown"}
    if not _static_task_retirement_admitted(root, descriptor):
        return {"state": "blocked", "code": "STATIC_RETIREMENT_UNVERIFIED"}
    encoded = base64.b64encode(_legacy_task_script().encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        return {"state": "unknown"}
    raw = _remote(config, _READINESS, (socket, str(pid), str(ticks), encoded), None, 30)
    try:
        value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError):
        return {"state": "unknown"}
    item = value.get("inventory") if isinstance(value, dict) and value.get("state") == "observed" else None
    counts = {"legacyTaskCount", "otherTaskCount", "activeInstallerCount", "c32TaskCount", "recoveryTaskCount"}
    if (not isinstance(item, dict) or set(item) != counts | {"version"}
            or type(item["version"]) is not int or item["version"] != 2
            or any(type(item[key]) is not int or not 0 <= item[key] <= 1000 for key in counts)
            or item["c32TaskCount"] > 1 or item["recoveryTaskCount"] > 1):
        return {"state": "unknown"}
    clean = all(item[key] == 0 for key in ("legacyTaskCount", "otherTaskCount", "activeInstallerCount"))
    try:
        if clean and item["c32TaskCount"]:
            clean = _fixed_c32_task_terminal(root, descriptor, lease_id)
        if clean and item["recoveryTaskCount"]:
            clean = _fixed_recovery_task_terminal(root, descriptor)
        if clean:
            clean = _descriptor(root)[2] == descriptor
    except (OSError, ValueError, TypeError, KeyError):
        clean = False
    return {"state": "cleaned" if clean else "blocked", **item}


_LEGACY_HISTORY = _QGA + r'''root,env,sock,pid,ticks,corr=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()
 parent=os.path.join(root,env)
 for path in (root,parent):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 groups=('windows-msi-base','windows-msi-target','windows-msi-public')
 result={}
 for group in groups:
  path=os.path.join(parent,group)
  if not os.path.lexists(path):result[group]=[];continue
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
  lock=os.path.join(path,'.environment.lock')
  if os.path.lexists(lock):
   item=os.lstat(lock)
   if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600:raise ValueError()
  names=sorted(name for name in os.listdir(path) if name!='.environment.lock')
  if len(names)>1 or (names and (group!='windows-msi-public' or names!=[corr])):raise ValueError()
  for name in names:
   item=os.lstat(os.path.join(path,name))
   if not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700:raise ValueError()
  result[group]=names
 out({'version':1,'state':'clean','groups':result})
except Exception:out({'version':1,'state':'unknown'})
'''


def _legacy_history_observation(root: Path, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    config, target, current = _descriptor(root)
    if current != descriptor:
        return {"state": "unknown"}
    env, socket, pid, ticks, _sid = descriptor
    raw = _remote(config, _LEGACY_HISTORY, (str(target.fixture_transfer_root), env,
        socket, str(pid), str(ticks), _LEGACY_CORRELATION), None, 30)
    try: value = json.loads(raw) if raw is not None else None
    except (TypeError, ValueError): return {"state": "unknown"}
    expected = {"windows-msi-base": [], "windows-msi-target": [],
                "windows-msi-public": []}
    if (not isinstance(value, dict) or set(value) != {"version", "state", "groups"}
            or value["version"] != 1 or value["state"] != "clean"
            or not isinstance(value["groups"], dict)
            or value["groups"] not in (expected,
                dict(expected, **{"windows-msi-public": [_LEGACY_CORRELATION]}))):
        return {"state": "unknown"}
    return {"state": "clean", "groups": value["groups"]}


def _require_reconciled_legacy(root: Path, descriptor: tuple[Any, ...],
                               expected_version: str, lease_id: str | None = None) -> None:
    """Read the exact old protected job and idle guest before a new campaign.

    The failed legacy task must be absent. Only the two fixed historical tasks
    may remain after their exact current terminal bindings are verified. Prior
    route journals still require their separate historical cleanup proof.
    """
    env, _socket, _pid, _ticks, _sid = descriptor
    if env != "windows-cp117":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    try:
        status = windows_msi_public_scenario.preinstall_status(root, "archlinux", _LEGACY_JOB)
    except ValueError as error:
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE") from error
    if (status.get("state") != "observed" or status.get("jobId") != _LEGACY_JOB
            or status.get("phase") != "Failed" or status.get("code") != "RUNTIME_FAILED"
            or type(status.get("sequence")) is not int or status["sequence"] < 3):
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    inventory = readiness(root, {"host": "archlinux", "expectedCurrentVersion": expected_version})
    if inventory.get("state") != "ready" or inventory.get("activeCount") != 0:
        raise WindowsMsiBasePrepareError("CP117_LEGACY_RECONCILIATION_UNAVAILABLE")
    tasks = _legacy_task_observation(root, descriptor, lease_id)
    if tasks.get("state") != "cleaned":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_CLEANUP_UNVERIFIED")
    history = _legacy_history_observation(root, descriptor)
    if history.get("state") != "clean":
        raise WindowsMsiBasePrepareError("CP117_LEGACY_ROUTE_HISTORY_UNVERIFIED")
    proof = {"correlationId": _LEGACY_CORRELATION,
             "guestGeneration": {"socketPath": _socket, "qemuPid": _pid, "startTicks": _ticks},
             "terminalJobId": _LEGACY_JOB, "terminalPhase": "Failed", "cleanupCode": "OK",
             "activeInstallerProcessesAbsent": True,
             "evidenceSha256": hashlib.sha256(json.dumps({"protected": status, "tasks": tasks,
                 "history": history,
                 "generation": [_socket, _pid, _ticks]}, sort_keys=True,
                 separators=(",", ":")).encode()).hexdigest()}
    campaign_lease.attest_legacy_closed(root, proof)


def _require_base_route_free(root: Path, config: Any | None = None, target: Any | None = None,
                             descriptor: tuple[Any, ...] | None = None) -> None:
    directory = root / _LOCAL
    if not os.path.lexists(directory):
        return
    def fp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    parents = (directory.parent, directory)
    parent_pins = []
    for path in parents:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise WindowsMsiBasePrepareError("Base route ancestry is unsafe.")
        # The shared .rag_index parent can receive unrelated platform entries.
        # Its inode/type/permissions/owner bind ancestry; base inventory below
        # retains full generations for the owned directory and every record.
        parent_pins.append(fp(info)[:5] if path == directory.parent else fp(info))
    source = Path(__file__)
    def source_pin():
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_size > 1048576):
                raise WindowsMsiBasePrepareError("Base route source is unsafe.")
            data = os.read(fd, 1048577)
            if len(data) != info.st_size:
                raise WindowsMsiBasePrepareError("Base route source read is incomplete.")
            if fp(os.fstat(fd)) != fp(info) or fp(source.lstat()) != fp(info):
                raise WindowsMsiBasePrepareError("Base route source changed.")
            return fp(info), hashlib.sha256(data).hexdigest()
        finally: os.close(fd)
    source_before = source_pin()
    held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def ancestry():
            current_parents = (fp(directory.parent.lstat())[:5], fp(directory.lstat()))
            if (current_parents != tuple(parent_pins)
                    or fp(os.fstat(held)) != parent_pins[-1]):
                raise WindowsMsiBasePrepareError("Base route ancestry changed.")
        def inventory():
            ancestry()
            names = sorted(os.listdir(held))
            if len(names) > 128 or '.environment.lock' not in names:
                raise WindowsMsiBasePrepareError("Base route inventory is unsafe.")
            result = {}
            for name in names:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=held)
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                            or info.st_size > 1048576):
                        raise WindowsMsiBasePrepareError("Base route record is unsafe.")
                    data = os.read(fd, 1048577)
                    if len(data) != info.st_size:
                        raise WindowsMsiBasePrepareError("Base route record read is incomplete.")
                    named = os.stat(name, dir_fd=held, follow_symlinks=False)
                    if fp(os.fstat(fd)) != fp(info) or fp(named) != fp(info):
                        raise WindowsMsiBasePrepareError("Base route record changed.")
                    result[name] = (fp(info), hashlib.sha256(data).hexdigest())
                finally: os.close(fd)
            if source_pin() != source_before:
                raise WindowsMsiBasePrepareError("Base route source changed.")
            ancestry()
            if sorted(os.listdir(held)) != names:
                raise WindowsMsiBasePrepareError("Base route inventory changed.")
            if any(fp(os.stat(name, dir_fd=held, follow_symlinks=False)) != value[0]
                   for name, value in result.items()):
                raise WindowsMsiBasePrepareError("Base route record changed after observation.")
            ancestry()
            return result
        before = inventory()
        # Fresh census is used only for this guarded inventory, never cached
        # across calls. Every archive's original evidence predicates still run.
        archived = _archived_base_record_names(root, config, target, descriptor)
        after = inventory()
        if (before != after or any(Path(name).suffix == '.json' and name not in archived for name in before)):
            raise WindowsMsiBasePrepareError("CP117 base route has active or unknown history.")
    finally: os.close(held)


def _open_base_campaign(root: Path, request: Mapping[str, Any], config: Any,
                        target: Any, descriptor: tuple[Any, ...]) -> str:
    """Internal: begin and claim only after an exact fsynced local intent."""
    intent = _private_intent(root, request["correlationId"])
    if (intent is None or intent.get("request") != dict(request)
            or intent.get("leaseId") != request["correlationId"]
            or any(intent.get(key) != observed for key, observed in
                   (("environment", descriptor[0]), ("socketPath", descriptor[1]),
                    ("pid", descriptor[2]), ("startTicks", descriptor[3]),
                    ("expectedSid", descriptor[4])))):
        raise WindowsMsiBasePrepareError("CP117 base intent is absent or changed.")
    _require_reconciled_legacy(root, descriptor, request["expectedCurrentVersion"], request["correlationId"])
    identity = _campaign_identity(request, descriptor)
    remote = _campaign_remote(config, target)
    opened = campaign_lease.begin(root, identity, remote)
    if opened["state"] != "active":
        raise WindowsMsiBasePrepareError("CP117 campaign reservation is unknown; inspect, do not replay.")
    claimed = campaign_lease.claim_role(root, identity["leaseId"], "base",
                                        request["correlationId"], remote)
    if claimed["state"] != "role-active":
        raise WindowsMsiBasePrepareError("CP117 base route claim is unknown; inspect, do not replay.")
    return identity["leaseId"]


def _verified_active_campaign(root: Path, request: Mapping[str, Any],
                              descriptor: tuple[Any, ...], config: Any, target: Any,
                              *, require_server: bool) -> str:
    """Internal: bind a previously verified pair and guest to both lease journals."""
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        if record is None or record["state"] != "active" or record["role"] is not None:
            raise WindowsMsiBasePrepareError("CP117 campaign is absent, busy, or unknown.")
        identity = dict(record["identity"])
        expected = _campaign_identity({**request, "correlationId": identity["leaseId"]}, descriptor)
        if identity != expected or (require_server and record["server"] != "live"):
            raise WindowsMsiBasePrepareError("CP117 campaign or server identity changed.")
        if not campaign_lease._remote_confirm(_campaign_remote(config, target), "status", record, None):
            raise WindowsMsiBasePrepareError("CP117 remote campaign state is unknown.")
        return identity["leaseId"]
    finally:
        os.close(lock)


def _verified_claimed_campaign(root: Path, request: Mapping[str, Any],
                               descriptor: tuple[Any, ...], config: Any, target: Any,
                               lease_id: str, role: str) -> None:
    """Recheck the exact native route claim in both journals before its intent."""
    directory, lock = campaign_lease._locked(root)
    try:
        record = campaign_lease._active(directory)
        expected = _campaign_identity({**request, "correlationId": lease_id}, descriptor)
        if (record is None or record["identity"] != expected
                or record["state"] != "role-active" or record["role"] != role
                or record["correlationId"] != request["correlationId"]
                or record["server"] != ("live" if role in {"target", "public"} else "stopped")
                or record["credentials"] != ("ready" if role in {"target", "public"} else "absent")
                or not campaign_lease._remote_confirm(_campaign_remote(config, target),
                                                      "status", record, None)):
            raise WindowsMsiBasePrepareError("CP117 route claim is absent or unknown.")
    finally:
        os.close(lock)
    if role in {"target", "public"}:
        from . import windows_update_fixture_server
        receipt = windows_update_fixture_server.verified_live_receipt(root, lease_id)
        if not _live_receipt_matches(receipt, expected):
            raise WindowsMsiBasePrepareError("CP117 live fixture changed after route claim.")


def _live_receipt_matches(receipt: Any, expected: Mapping[str, Any]) -> bool:
    return (isinstance(receipt, dict) and
            all(receipt.get(key) == expected[key] for key in (
                "leaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
                "targetMsiArtifactId", "socketPath", "qemuPid", "startTicks"))
            and receipt.get("serverReady") is True
            and isinstance(receipt.get("liveReceiptSha256"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt["liveReceiptSha256"])))


def _require_verified_live_fixture(root: Path, request: Mapping[str, Any],
                                   descriptor: tuple[Any, ...], config: Any, target: Any) -> str:
    """Join only one fixed, source-bound live server; no caller-supplied proof."""
    lease_id = _verified_active_campaign(root, request, descriptor, config, target,
                                         require_server=True)
    from . import windows_update_fixture_server
    receipt = windows_update_fixture_server.verified_live_receipt(root, lease_id)
    expected = _campaign_identity({**request, "correlationId": lease_id}, descriptor)
    if not _live_receipt_matches(receipt, expected):
        raise WindowsMsiBasePrepareError("CP117 live fixture receipt does not match campaign.")
    return lease_id


def _transfer_ready_for_base(root: Path, config: Any, target: Any,
                             correlation: str) -> dict[str, Any]:
    from . import windows_msi_http_transfer
    return windows_msi_http_transfer.ready_for_base(
        root, config, target.fixture_transfer_root, correlation)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    return _start(root, value, preverified=False)


def start_from_transfer(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Use a fully verified CP117 guest MSI without repeating QGA byte writes."""
    return _start(root, value, preverified=True)


def _start(root: Path | str, value: Mapping[str, Any], *, preverified: bool) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    request = _request(value)
    correlation = request["correlationId"]
    existing = _private_intent(root, correlation)
    if existing is not None:
        if existing.get("request") != request:
            raise WindowsMsiBasePrepareError("Correlation binds another base preparation.")
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    pair, source, size = _admit(root, request)
    config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    if preverified:
        observed = _transfer_ready_for_base(root, config, target, correlation)
        expected = {"state": "ready-for-base", "correlationId": correlation,
                    "sourceSha": request["sourceSha"],
                    "baseMsiArtifactId": request["baseMsiArtifactId"],
                    "sha256": request["baseMsiArtifactId"].removeprefix("sha256-"),
                    "length": size,
                    "guestPath": (r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-"
                                  + correlation + r"\base.msi"),
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False}
        if observed != expected:
            raise WindowsMsiBasePrepareError("Verified CP117 transfer handoff is unavailable.")
    command = _bootstrap(correlation, pair, request["expectedCurrentVersion"], sid)
    encoded = base64.b64encode(command.encode("utf-16le")).decode()
    if len(encoded) >= 30000:
        raise WindowsMsiBasePrepareError("Fixed base bootstrap exceeds Windows command admission.")
    command_hash = hashlib.sha256(command.encode("utf-16le")).hexdigest()
    record = {"request": request, "pair": pair, "environment": env, "socketPath": sock,
              "pid": pid, "startTicks": ticks, "expectedSid": sid, "commandSha256": command_hash}
    _require_reconciled_legacy(root, (env, sock, pid, ticks, sid), request["expectedCurrentVersion"], correlation)
    _require_base_route_free(root, config, target, (env, sock, pid, ticks, sid))
    stage_args = (str(target.fixture_transfer_root), env, correlation, correlation, sock,
                  str(pid), str(ticks), sid, str(size), encoded, command_hash,
                  request["sourceSha"], pair["sourceFingerprint"],
                  request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
                  request["targetMsiArtifactId"])
    if preverified:
        stage_args += ("preverified",)
    ssh_transport.build_ssh_argv(config, "archlinux", 60,
        command=windows_credential_probe_ssh._remote_command(_STAGE, *stage_args))
    record["leaseId"] = correlation
    _reserve(root, record, config=config, target=target, descriptor=(env, sock, pid, ticks, sid))
    _open_base_campaign(root, request, config, target, (env, sock, pid, ticks, sid))
    raw = _remote(config, _STAGE, stage_args, None if preverified else source, 1800)
    try:
        result = json.loads(raw) if raw is not None else {}
    except (TypeError, ValueError):
        result = {}
    if result == {"state": "unknown", "reason": "submission-uncertain", "correlationId": correlation,
                  "phase": result.get("phase"), "offset": result.get("offset")}:
        phase, offset = result["phase"], result["offset"]
        if (phase in {"host-admission", "campaign-guard", "remote-stage", "input-admission", "guest-directory",
                      "guest-file-open", "guest-file-verify", "bootstrap-dispatch", "protocol"}
                and type(offset) is int and 0 <= offset <= size):
            return {"state": "unknown", "correlationId": correlation, "stagePhase": phase,
                    "stageOffset": offset, "replayAllowed": False}
    if not isinstance(result, dict) or result.get("state") != "submitted" or result.get("correlationId") != correlation:
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "submitted", "correlationId": correlation, "replayAllowed": False}


_STATUS = _QGA + r'''root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 stage=os.path.join(root,env,'windows-msi-base',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 if set(binding)!={'socketPath','pid','startTicks','sourceSha','sourceFingerprint','receiptArtifactId','baseArtifactId','targetArtifactId','commandSha256','expectedSid'}:raise ValueError()
 if binding!={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}:raise ValueError()
 if not live(sock,pid,ticks):raise ValueError()
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 status=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 if type(status.get('exited')) is not bool:raise ValueError()
 if status['exited'] is False:out({'state':'running','correlationId':corr});raise SystemExit(0)
 if (status.get('out-truncated') is True or status.get('err-truncated') is True
     or ('out-truncated' in status and type(status.get('out-truncated')) is not bool)
     or ('err-truncated' in status and type(status.get('err-truncated')) is not bool)):raise ValueError()
 if type(status.get('exitcode')) is not int:raise ValueError()
 output=base64.b64decode(status.get('out-data',''),validate=True)
 if len(output)>8192:raise ValueError()
 lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
 if not lines:raise ValueError()
 trigger=json.loads(lines[-1])
 if trigger=={'version':1,'correlationId':corr,'triggered':False}:
  if status['exitcode']==0:raise ValueError()
  # The bootstrap catches both pre-registration failures and a throw after
  # Register-ScheduledTask or Start-ScheduledTask.  Its generic false record
  # cannot establish that the task had no effect.
  out({'state':'observed','correlationId':corr,'failure':{'phase':'bootstrap','code':'task_trigger_outcome_ambiguous'}});raise SystemExit(0)
 if trigger!={'version':1,'correlationId':corr,'triggered':True} or status['exitcode']!=0:raise ValueError()
 path='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+corr+'\\result.json'
 raw=read(sock,path)
 if raw is None:out({'state':'running','correlationId':corr});raise SystemExit(0)
 result=json.loads(decode(raw))
 if set(result)!={'version','correlationId','stage','result','exitCode','originalSid','sessionId','limited','msiSha256','installedVersion','cliSha256','jarSha256','helperSha256','priorProducts','installedProducts'} or result['version']!=1 or result['correlationId']!=corr:raise ValueError()
 out({'state':'observed','correlationId':corr,'result':result})
except Exception:out({'state':'unknown','correlationId':corr})
'''


def _terminal_task_arguments_sha(correlation: str, intent: Mapping[str, Any]) -> str:
    """Reconstruct the fixed task action submitted by this source-bound intent."""
    script = _task(correlation, intent["pair"], intent["request"]["expectedCurrentVersion"],
                   intent["expectedSid"])
    arguments = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(script.encode("utf-16le")).decode()
    return hashlib.sha256(arguments.encode("utf-8")).hexdigest()


_TERMINAL_PS = r'''$ErrorActionPreference='Stop'
try {
 $corr='__CORR__';$sid='__SID__';$expectedAction='__ACTION__';$baseHash='__BASE_HASH__'
 $cliHash='__CLI_HASH__';$jarHash='__JAR_HASH__';$helperHash='__HELPER_HASH__';$jarName='__JAR_NAME__'
 $root='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+$corr
 $taskName='VpnControlMcpBase-'+$corr
 $tasks=@(Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction Stop)
 if($tasks.Count -ne 1 -or $tasks[0].State -eq 'Running') { throw 'TASK' }
 $task=$tasks[0]
 $taskInfo=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName -ErrorAction Stop
 if($taskInfo.LastTaskResult -ne 0 -or $taskInfo.LastRunTime.Year -lt 2020) { throw 'TASK_RESULT' }
 if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') { throw 'ACTION' }
 $hasher=[Security.Cryptography.SHA256]::Create()
 try { $actualAction=([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($task.Actions[0].Arguments)))).Replace('-','').ToLowerInvariant() }
 finally { $hasher.Dispose() }
 if($actualAction -cne $expectedAction) { throw 'ACTION' }
 $principal=$task.Principal
 $principalSid=if($principal.UserId -match '^S-1-') {$principal.UserId} else {([Security.Principal.NTAccount]::new($principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
 if($principalSid -cne $sid -or [string]$principal.LogonType -cne 'Interactive' -or [string]$principal.RunLevel -cne 'Limited') { throw 'PRINCIPAL' }
 $profile='C:\Users\vpncp117';$app=Join-Path $profile 'AppData';$local=Join-Path $app 'Local';$product=Join-Path $local 'VpnControl'
 foreach($path in @($profile,$app,$local,$product,$root)) {
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if(-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'DIRECTORY' }
  $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $path).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  if($path -ceq $profile) { if($owner -cne $sid -and $owner -cne 'S-1-5-18') { throw 'OWNER' } }
  elseif($owner -cne $sid) { throw 'OWNER' }
 }
 foreach($path in @((Join-Path $root 'result.json'),(Join-Path $root 'base.msi'))) {
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'FILE' }
  $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $path).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  if($owner -cne $sid) { throw 'OWNER' }
 }
 if((Get-FileHash -LiteralPath (Join-Path $root 'base.msi') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $baseHash) { throw 'MSI' }
 $install='C:\Users\vpncp117\AppData\Local\vpn-control'
 $cli=Join-Path $install 'vpn-control-cli.exe';$jar=Join-Path (Join-Path $install 'app') $jarName
 $helper=Join-Path $install 'app\native\windows-amd64\vpn-control-install-helper.exe'
 foreach($entry in @([pscustomobject]@{Path=$cli;Hash=$cliHash},[pscustomobject]@{Path=$jar;Hash=$jarHash},[pscustomobject]@{Path=$helper;Hash=$helperHash})) {
  $item=Get-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
  if($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'INSTALLED_FILE' }
  if((Get-FileHash -LiteralPath $entry.Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Hash) { throw 'INSTALLED_HASH' }
 }
 $result=Get-Content -LiteralPath (Join-Path $root 'result.json') -Raw -Encoding UTF8|ConvertFrom-Json -ErrorAction Stop
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;correlationId=$corr;result=$result}|ConvertTo-Json -Depth 10 -Compress))
} catch { [Console]::Out.WriteLine('{"version":1,"state":"unknown"}');exit 1 }
'''


_TERMINAL_RECONCILE = _QGA + r'''root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid,action_sha,cli_sha,jar_sha,helper_sha,jar_name=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 stage=os.path.join(root,env,'windows-msi-base',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
 expected={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
 if set(binding)!=set(expected) or binding!=expected or not live(sock,pid,ticks):raise ValueError()
 dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
 if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 script=TERMINAL_PS.replace('__CORR__',corr).replace('__SID__',sid).replace('__ACTION__',action_sha).replace('__BASE_HASH__',base_id.removeprefix('sha256-')).replace('__CLI_HASH__',cli_sha).replace('__JAR_HASH__',jar_sha).replace('__HELPER_HASH__',helper_sha).replace('__JAR_NAME__',jar_name)
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True})['pid']
 import time
 for attempt in range(160):
  observed=call(sock,'guest-exec-status',{'pid':child})
  if type(observed.get('exited')) is not bool:raise ValueError()
  if observed['exited']:break
  time.sleep(.25)
 else:raise ValueError()
 if observed.get('exitcode')!=0 or observed.get('out-truncated') is True or observed.get('err-truncated') is True:raise ValueError()
 raw=base64.b64decode(observed.get('out-data',''),validate=True)
 if not 0<len(raw)<=8192:raise ValueError()
 lines=[x for x in decode(raw).splitlines() if x.startswith('{') and x.endswith('}')]
 if len(lines)!=1:raise ValueError()
 proof=json.loads(lines[0])
 if set(proof)!={'version','correlationId','result'} or proof['version']!=1 or proof['correlationId']!=corr:raise ValueError()
 out({'state':'observed','correlationId':corr,'result':proof['result']})
except Exception:out({'state':'unknown','correlationId':corr})
'''.replace('TERMINAL_PS',repr(_TERMINAL_PS))


# This is deliberately separate from _STATUS.  Status establishes an installer
# outcome only from its complete durable result.  The diagnostic only tells an
# operator which bounded observation checkpoint could not be proven for an
# already-accepted correlation; it never turns a missing checkpoint into proof
# that the bootstrap had no effect.
_DIAGNOSTIC = _QGA + r'''root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid=sys.argv[1:]
def unknown_proof():return {'task':'unknown','leaf':'unknown','result':'unknown','correlationPowerShell':'unknown','product':'unknown','installedVersion':None,'installer':'unknown'}
def out(binding,checkpoint,proof=None,proof_failure=None,proof_failure_phase=None,proof_projection_reason=None,proof_projection_schema=None):
 value={'state':'diagnosed','correlationId':corr,'binding':binding,'checkpoint':checkpoint}
 if proof is not None:value['guestProof']=proof
 if proof_failure is not None:value['guestProofFailure']=proof_failure
 if proof_failure_phase is not None:value['guestProofFailurePhase']=proof_failure_phase
 if proof_projection_reason is not None:value['guestProofProjectionReason']=proof_projection_reason
 if proof_projection_schema is not None:value['guestProofProjectionSchema']=proof_projection_schema
 print(json.dumps(value,separators=(',',':'),sort_keys=True))
def dispatch_absent_proof():
 proof=unknown_proof()
 schema_keys=('version','phase','task','leaf','result','correlationPowerShell','product','installedVersion','installer')
 def schema_mask(value):
  if not isinstance(value,dict):return {'presenceMask':'000000000','extraFieldCount':0}
  return {'presenceMask':''.join('1' if key in value else '0' for key in schema_keys),'extraFieldCount':min(9,len(set(value)-set(schema_keys)))}
 try:
  script="$ErrorActionPreference='Stop';$corr='"+corr+"';$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+base64.b64encode(sid.encode()).decode('ascii')+"'));$hku='Registry::HKEY_USERS\\'+$sid+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall';$hku32='Registry::HKEY_USERS\\'+$sid+'\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall';$phase='task';try{$task='VpnControlMcpBase-'+$corr;$taskState=if(@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task}).Count -eq 0){'absent'}else{'present'};$phase='leaf';$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr;$leafState=if([IO.Directory]::Exists($leaf)){'present'}else{'absent'};$resultState=if([IO.File]::Exists((Join-Path $leaf 'result.json'))){'present'}else{'absent'};$phase='process';$ps=@(Get-CimInstance Win32_Process -Filter \"name='powershell.exe' OR name='pwsh.exe'\"|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match [regex]::Escape($corr)});$psState=if($ps.Count -eq 0){'absent'}else{'present'};$phase='product';$records=@();foreach($path in @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',$hku,$hku32)){if(Test-Path -LiteralPath $path){$records+=@(Get-ItemProperty -Path ($path+'\\*') -ErrorAction Stop)}};$products=@($records|Where-Object {$_.DisplayName -eq 'vpn-control'});$productState=if($products.Count -eq 0){'absent'}elseif($products.Count -eq 1 -and $products[0].DisplayVersion -match '^(?:[1-9]|1[0-9])\\.(?:0|[1-9]|1[0-9])\\.(?:0|[1-9]|1[0-9])$'){'single'}else{'multiple'};$version=if($productState -eq 'single'){$products[0].DisplayVersion}else{$null};$phase='installer';$installerState=if(@(Get-CimInstance Win32_Process -Filter \"name='msiexec.exe'\").Count -eq 0){'absent'}else{'present'};$phase='output';[Console]::Out.WriteLine(([pscustomobject]@{version=1;phase=$phase;task=$taskState;leaf=$leafState;result=$resultState;correlationPowerShell=$psState;product=$productState;installedVersion=$version;installer=$installerState}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine(([pscustomobject]@{version=1;phase=$phase;task='unknown';leaf='unknown';result='unknown';correlationPowerShell='unknown';product='unknown';installedVersion=$null;installer='unknown'}|ConvertTo-Json -Compress));exit 1}"
  encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
  if len(encoded)>=30000:raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
 except Exception:return proof,'qga-exec-rpc-or-protocol','unavailable','unavailable',None
 import time
 for _ in range(40):
  try:
   observed=call(sock,'guest-exec-status',{'pid':child})
   exited=observed.get('exited')
  except Exception:return proof,'qga-status-rpc-or-protocol','unavailable','unavailable',None
  if type(exited) is not bool:return proof,'qga-status-exited-malformed','unavailable','unavailable',None
  if exited is True:break
  time.sleep(.25)
 else:return proof,'qga-status-running-timeout','unavailable','unavailable',None
 if (('out-truncated' in observed and type(observed.get('out-truncated')) is not bool)
     or ('err-truncated' in observed and type(observed.get('err-truncated')) is not bool)
     or type(observed.get('exitcode')) is not int):return proof,'qga-status-terminal-fields-malformed','unavailable','unavailable',None
 if observed.get('out-truncated') is True or observed.get('err-truncated') is True:return proof,'qga-truncated','unavailable','unavailable',None
 try:
  raw=base64.b64decode(observed.get('out-data',''),validate=True)
  if not 0<len(raw)<=2048:raise ValueError()
  lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
  value=json.loads(lines[0]) if len(lines)==1 else None
 except Exception:return proof,'powershell-empty-or-malformed-output','unavailable','unavailable',None
 try:
  required={'version','phase','task','leaf','result','correlationPowerShell','product','installedVersion','installer'}
  unknown={'task':'unknown','leaf':'unknown','result':'unknown','correlationPowerShell':'unknown','product':'unknown','installedVersion':None,'installer':'unknown'}
  phases={'task','leaf','process','product','installer','output'}
  if not isinstance(value,dict) or set(value)!=required:raise ValueError('missing-or-extra-fields')
  if type(value.get('version')) is not int or value.get('version')!=1 or not isinstance(value.get('phase'),str) or value['phase'] not in phases:raise ValueError('version-or-phase-invalid')
  if observed['exitcode']!=0:
   if {key:value[key] for key in unknown}!=unknown:raise ValueError('nonzero-failure-envelope-invalid')
   return unknown,'powershell-nonzero',value['phase'],'unavailable',None
  if (value.get('phase')!='output'
      or any(not isinstance(value.get(key),str) or value[key] not in {'present','absent'} for key in ('task','leaf','result','correlationPowerShell','installer'))
      or not isinstance(value.get('product'),str) or value['product'] not in {'absent','single','multiple'}):raise ValueError('success-enum-invalid')
  if ((value['product']=='single' and (not isinstance(value.get('installedVersion'),str) or not re.fullmatch(r'(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])',value['installedVersion'])))
      or (value['product']!='single' and value.get('installedVersion') is not None)):raise ValueError('product-version-invalid')
  proof={key:value[key] for key in required if key not in {'version','phase'}}
 except ValueError as error:
  reason=str(error);return unknown_proof(),'projection','unavailable',reason,(schema_mask(value) if reason=='missing-or-extra-fields' else None)
 except Exception:return unknown_proof(),'projection','unavailable','internal-error',None
 return proof,'none','none','none',None
try:
 stage=os.path.join(root,env,'windows-msi-base',corr)
 try:
  info=os.lstat(stage)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 except Exception:
  out('exact','remote-stage');raise SystemExit(0)
 try:
  binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
  expected={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
  if set(binding)!=set(expected) or binding!=expected:raise ValueError()
 except Exception:
  out('mismatch','remote-binding');raise SystemExit(0)
 try:
  if not live(sock,pid,ticks):raise ValueError()
 except Exception:
  out('exact','qga-protocol');raise SystemExit(0)
 try:
  dispatch=json.load(open(os.path.join(stage,'dispatch.json'),encoding='utf-8'))
  if set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 except FileNotFoundError:
  proof,proof_failure,proof_failure_phase,proof_projection_reason,proof_projection_schema=dispatch_absent_proof()
  out('exact','remote-dispatch-absent',proof,proof_failure,proof_failure_phase,proof_projection_reason,proof_projection_schema);raise SystemExit(0)
 except Exception:
  out('exact','remote-dispatch-malformed');raise SystemExit(0)
 try:
  status=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
  if type(status.get('exited')) is not bool:raise ValueError()
  if status['exited'] is False:out('exact','bootstrap-result-proof');raise SystemExit(0)
  if (status.get('out-truncated') is True or status.get('err-truncated') is True
      or ('out-truncated' in status and type(status.get('out-truncated')) is not bool)
      or ('err-truncated' in status and type(status.get('err-truncated')) is not bool)
      or type(status.get('exitcode')) is not int):raise ValueError()
  output=base64.b64decode(status.get('out-data',''),validate=True)
  if not 0<len(output)<=8192:raise ValueError()
 except Exception:
  out('exact','qga-protocol');raise SystemExit(0)
 try:
  lines=[x for x in decode(output).splitlines() if x.startswith('{') and x.endswith('}')]
  if not lines:raise ValueError()
  trigger=json.loads(lines[-1])
  if trigger=={'version':1,'correlationId':corr,'triggered':False}:
   out('exact','bootstrap-result-proof');raise SystemExit(0)
  if trigger!={'version':1,'correlationId':corr,'triggered':True} or status['exitcode']!=0:raise ValueError()
  path='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+corr+'\\result.json'
  raw=read(sock,path)
  if raw is None:out('exact','bootstrap-result-proof');raise SystemExit(0)
  result=json.loads(decode(raw))
  required={'version','correlationId','stage','result','exitCode','originalSid','sessionId','limited','msiSha256','installedVersion','cliSha256','jarSha256','helperSha256','priorProducts','installedProducts'}
  if set(result)!=required or result.get('version')!=1 or result.get('correlationId')!=corr:raise ValueError()
  out('exact','bootstrap-result-proof')
 except Exception:
  out('exact','bootstrap-result-proof')
except Exception:out('unverified','qga-protocol')
'''


# This observer is intentionally independent of ``_DIAGNOSTIC``.  It reads a
# single already-bound guest file using a guest-side digest, so MSI bytes never
# leave the guest.  It neither creates a leaf nor starts a task or installer.
_STAGE_DIAGNOSTIC = _QGA + r'''root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid,size_text=sys.argv[1:]
def out(binding,checkpoint,guest_stage=None,observed_size=None,size_matches=None,sha256_matches=None):
 value={'state':'stage-diagnosed','correlationId':corr,'binding':binding,'checkpoint':checkpoint}
 if guest_stage is not None:
  value.update({'guestStage':guest_stage,'observedSize':observed_size,'sizeMatches':size_matches,'sha256Matches':sha256_matches})
 print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 expected_size=int(size_text)
 if not 0<expected_size<=1073741824:raise ValueError()
 stage=os.path.join(root,env,'windows-msi-base',corr)
 try:
  info=os.lstat(stage)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 except Exception:
  out('exact','remote-stage');raise SystemExit(0)
 try:
  binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
  expected={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
  if set(binding)!=set(expected) or binding!=expected:raise ValueError()
 except Exception:
  out('mismatch','remote-binding');raise SystemExit(0)
 try:
  if not live(sock,pid,ticks):raise ValueError()
 except Exception:
  out('exact','qga-protocol');raise SystemExit(0)
 try:
  script="$ErrorActionPreference='Stop';$corr='"+corr+"';$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr;$msi=Join-Path $leaf 'base.msi';$expectedSize="+str(expected_size)+";$expectedHash='"+base_id.removeprefix('sha256-')+"';try{if(-not [IO.Directory]::Exists($leaf) -or -not [IO.File]::Exists($msi)){[Console]::Out.WriteLine(([pscustomobject]@{version=1;guestStage='absent';observedSize=$null;sizeMatches=$false;sha256Matches=$false}|ConvertTo-Json -Compress))}else{$size=[IO.FileInfo]$msi|ForEach-Object {$_.Length};$sizeMatches=($size -eq $expectedSize);$sha256Matches=((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expectedHash);$guestStage=if($sizeMatches -and $sha256Matches){'full'}else{'partial'};[Console]::Out.WriteLine(([pscustomobject]@{version=1;guestStage=$guestStage;observedSize=$size;sizeMatches=$sizeMatches;sha256Matches=$sha256Matches}|ConvertTo-Json -Compress))}}catch{[Console]::Out.WriteLine('{\"version\":1,\"guestStage\":\"unknown\",\"observedSize\":null,\"sizeMatches\":null,\"sha256Matches\":null}');exit 1}"
  encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
  if len(encoded)>=30000:raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
 except Exception:
  out('exact','qga-protocol');raise SystemExit(0)
 import time
 for _ in range(40):
  try:
   observed=call(sock,'guest-exec-status',{'pid':child})
   exited=observed.get('exited')
  except Exception:
   out('exact','qga-protocol');raise SystemExit(0)
  if type(exited) is not bool:
   out('exact','qga-protocol');raise SystemExit(0)
  if exited is True:break
  time.sleep(.25)
 else:
  out('exact','qga-protocol');raise SystemExit(0)
 if (type(observed.get('exitcode')) is not int or observed.get('out-truncated') is True or observed.get('err-truncated') is True
     or ('out-truncated' in observed and type(observed.get('out-truncated')) is not bool)
     or ('err-truncated' in observed and type(observed.get('err-truncated')) is not bool)):
  out('exact','qga-protocol');raise SystemExit(0)
 try:
  raw=base64.b64decode(observed.get('out-data',''),validate=True)
  if not 0<len(raw)<=1024:raise ValueError()
  lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
  value=json.loads(lines[0]) if len(lines)==1 else None
  required={'version','guestStage','observedSize','sizeMatches','sha256Matches'}
  if not isinstance(value,dict) or set(value)!=required or value.get('version')!=1:raise ValueError()
  if observed['exitcode']!=0:
   if value!={'version':1,'guestStage':'unknown','observedSize':None,'sizeMatches':None,'sha256Matches':None}:raise ValueError()
   raise ValueError()
  if value.get('guestStage')=='absent':
   if value.get('observedSize') is not None or value.get('sizeMatches') is not False or value.get('sha256Matches') is not False:raise ValueError()
  elif value.get('guestStage')=='partial':
   if type(value.get('observedSize')) is not int or not 0<=value['observedSize']<=1073741824 or type(value.get('sizeMatches')) is not bool or type(value.get('sha256Matches')) is not bool or (value['sizeMatches'] and value['sha256Matches']):raise ValueError()
  elif value.get('guestStage')=='full':
   if value.get('observedSize')!=expected_size or value.get('sizeMatches') is not True or value.get('sha256Matches') is not True:raise ValueError()
  else:raise ValueError()
  out('exact','guest-stage',value['guestStage'],value['observedSize'],value['sizeMatches'],value['sha256Matches'])
 except Exception:
  out('exact','qga-protocol')
except Exception:out('unverified','qga-protocol')
'''


# A deliberately narrow cleaner for the one lost CP117 base submission.  The
# caller writes a durable local intent before selecting ``cleanup``.  This
# program has no installer, task-start, server, credential, or VPN operation.
_UNKNOWN_CLEANUP = _QGA + r'''import time
root,env,corr,sock,pid,ticks,source,fingerprint,receipt_id,base_id,target_id,command_hash,sid,mode=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def unknown(phase):out({'state':'unknown','correlationId':corr,'phase':phase})
guest_failure='protocol'
def guest():
 global guest_failure
 try:
  script="$ErrorActionPreference='Stop';$corr='"+corr+"';$task='VpnControlMcpBase-'+$corr;$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-'+$corr;$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+base64.b64encode(sid.encode()).decode('ascii')+"'));$phase='task';try{$tasks=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $task});$taskState=if($tasks.Count -eq 0){'absent'}else{'present'};$phase='leaf';$leafState=if(Test-Path -LiteralPath $leaf){'present'}else{'absent'};$resultState=if(Test-Path -LiteralPath ($leaf+'\\result.json')){'present'}else{'absent'};$phase='process';$ps=@(Get-CimInstance Win32_Process -Filter \"name='powershell.exe' OR name='pwsh.exe'\"|Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match [regex]::Escape($corr)});$processState=if($ps.Count -eq 0){'absent'}else{'present'};$phase='product';$hku='Registry::HKEY_USERS\\'+$sid+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall';$hku32='Registry::HKEY_USERS\\'+$sid+'\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall';$records=@();foreach($path in @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',$hku,$hku32)){if(Test-Path -LiteralPath $path){$records+=@(Get-ItemProperty -Path ($path+'\\*') -ErrorAction Stop)}};$products=@($records|Where-Object {$_.DisplayName -eq 'vpn-control'});$productState=if($products.Count -eq 1){'single'}elseif($products.Count -eq 0){'absent'}else{'multiple'};$version=if($products.Count -eq 1){$products[0].DisplayVersion}else{$null};$phase='installer';$installerState=if(@(Get-CimInstance Win32_Process -Filter \"name='msiexec.exe'\").Count -eq 0){'absent'}else{'present'};$phase='output';[Console]::Out.WriteLine(([pscustomobject]@{version=1;phase=$phase;task=$taskState;leaf=$leafState;result=$resultState;correlationPowerShell=$processState;product=$productState;installedVersion=$version;installer=$installerState}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine(([pscustomobject]@{version=1;phase=$phase;task='unknown';leaf='unknown';result='unknown';correlationPowerShell='unknown';product='unknown';installedVersion=$null;installer='unknown'}|ConvertTo-Json -Compress));exit 1}"
  encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
  if len(encoded)>=30000:raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
 except Exception:guest_failure='qga-exec';raise ValueError()
 for _ in range(40):
  try:item=call(sock,'guest-exec-status',{'pid':child})
  except Exception:guest_failure='qga-status-rpc';raise ValueError()
  if not isinstance(item,dict):guest_failure='qga-status-rpc';raise ValueError()
  if item.get('exited') is True:break
  if item.get('exited') is not False:guest_failure='qga-status-exited-malformed';raise ValueError()
  time.sleep(.25)
 else:guest_failure='qga-status-running-timeout';raise ValueError()
 if (type(item.get('exitcode')) is not int or ('out-truncated' in item and type(item.get('out-truncated')) is not bool) or ('err-truncated' in item and type(item.get('err-truncated')) is not bool)):guest_failure='qga-status-terminal-fields';raise ValueError()
 if item.get('out-truncated') is True or item.get('err-truncated') is True:guest_failure='qga-status-truncated';raise ValueError()
 try:
  raw=base64.b64decode(item.get('out-data',''),validate=True)
  if not 0<len(raw)<=2048:raise ValueError()
  lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
  if len(lines)!=1:raise ValueError()
  value=json.loads(lines[0])
 except Exception:guest_failure='empty-or-malformed-output';raise ValueError()
 required={'version','phase','task','leaf','result','correlationPowerShell','product','installedVersion','installer'}
 try:
  if not isinstance(value,dict) or set(value)!=required or value.get('version')!=1 or value.get('phase') not in {'task','leaf','process','product','installer','output'}:raise ValueError()
  if item['exitcode']!=0:
   if any(value.get(key)!='unknown' for key in ('task','leaf','result','correlationPowerShell','product','installer')) or value.get('installedVersion') is not None:raise ValueError()
   guest_failure=value['phase'];raise RuntimeError()
  if value['phase']!='output':raise ValueError()
  if any(value.get(key) not in {'present','absent'} for key in ('task','leaf','result','correlationPowerShell','installer')) or value.get('product') not in {'absent','single','multiple'}:raise ValueError()
  if value['product']=='single':
   if not isinstance(value.get('installedVersion'),str) or not re.fullmatch(r'(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])',value['installedVersion']):raise ValueError()
  elif value.get('installedVersion') is not None:raise ValueError()
 except RuntimeError:raise ValueError()
 except Exception:guest_failure='projection';raise ValueError()
 return {key:value[key] for key in required if key not in {'version','phase'}}
def delete_leaf():
 script="$ErrorActionPreference='Stop';$leaf='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-"+corr+"';if(Test-Path -LiteralPath $leaf){Remove-Item -LiteralPath $leaf -Force -Recurse};if(Test-Path -LiteralPath $leaf){exit 1};[Console]::Out.WriteLine('{\"version\":1,\"state\":\"absent\"}')"
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated') is True or item.get('err-truncated') is True or ('out-truncated' in item and type(item.get('out-truncated')) is not bool) or ('err-truncated' in item and type(item.get('err-truncated')) is not bool)):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if json.loads(decode(raw).strip())!={'version':1,'state':'absent'}:raise ValueError()
try:
 phase='host-guard'
 if env!='windows-cp117' or mode not in ('status','cleanup') or not live(sock,pid,ticks):raise ValueError()
 phase='host-root'
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base');stage=os.path.join(group,corr)
 for path in (root,parent):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 remote='absent'
 if os.path.lexists(stage):
  phase='remote-stage'
  if not os.path.lexists(group):raise ValueError()
  info=os.lstat(group)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
  info=os.lstat(stage)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
  names=set(os.listdir(stage))
  if names=={'binding.json'}:
   binding=json.load(open(os.path.join(stage,'binding.json'),encoding='utf-8'))
   expected={'socketPath':sock,'pid':int(pid),'startTicks':int(ticks),'sourceSha':source,'sourceFingerprint':fingerprint,'receiptArtifactId':receipt_id,'baseArtifactId':base_id,'targetArtifactId':target_id,'commandSha256':command_hash,'expectedSid':sid}
   if binding!=expected:raise ValueError()
   remote='present'
  elif names==set():remote='empty'
  else:raise ValueError()
 phase='guest-census';proof=guest()
 safe=(proof['task']=='absent' and proof['result']=='absent' and proof['correlationPowerShell']=='absent' and proof['installer']=='absent' and proof['product']=='single' and proof['installedVersion']=='2.1.17')
 if not safe:
  if mode=='status':out({'state':'guest-unsafe','correlationId':corr,**proof});raise SystemExit(0)
  raise ValueError()
 mutation='none'
 if mode=='cleanup' and proof['leaf']=='present':phase='guest-cleanup';delete_leaf();mutation='guest-leaf';phase='guest-recheck';proof=guest();safe=(proof['task']=='absent' and proof['result']=='absent' and proof['correlationPowerShell']=='absent' and proof['installer']=='absent' and proof['product']=='single' and proof['installedVersion']=='2.1.17')
 if mode=='cleanup' and not (safe and proof['leaf']=='absent'):raise ValueError()
 if mode=='cleanup' and remote in ('present','empty'):
  phase='remote-stage-cleanup'
  if remote=='present':os.unlink(os.path.join(stage,'binding.json'))
  os.rmdir(stage);parentfd=os.open(group,os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parentfd);os.close(parentfd);remote='absent';mutation='both' if mutation=='guest-leaf' else 'remote-stage'
 out({'state':'observed','correlationId':corr,'remoteStage':remote,'mutation':mutation,**proof})
except Exception:
 if phase in ('guest-census','guest-recheck') and guest_failure in {'task','leaf','process','product','installer','output','qga-exec','qga-status-rpc','qga-status-exited-malformed','qga-status-running-timeout','qga-status-terminal-fields','qga-status-truncated','empty-or-malformed-output','projection','unexpected-internal'}:unknown('guest-'+guest_failure)
 else:unknown(phase if phase in ('host-guard','host-root','remote-stage','guest-census','guest-cleanup','guest-recheck','remote-stage-cleanup') else 'protocol')
'''


_DIAGNOSTIC_CHECKPOINTS = {
    "local-intent", "descriptor", "remote-stage", "remote-binding",
    "remote-dispatch-absent", "remote-dispatch-malformed", "qga-protocol",
    "bootstrap-result-proof",
}
_STAGE_DIAGNOSTIC_CHECKPOINTS = {"remote-stage", "remote-binding", "qga-protocol", "guest-stage"}

# Read-only admission for a later durable transfer design.  It intentionally
# checks only QGA execution and whether the fixed original-user volume has
# enough room for the immutable MSI plus a bounded staging margin.  It neither
# opens a guest file nor creates a task, leaf, server, or credential.
_TRANSFER_PREFLIGHT = _QGA + r'''import time
sock,pid,ticks,size_text=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks):raise ValueError()
 size=int(size_text)
 if not 0<size<=1073741824:raise ValueError()
 # One extra MSI-sized allocation bounds an atomic download/rename strategy.
 required=size*2
 script="$ErrorActionPreference='Stop';$free=(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace;if($null -eq $free){throw 'DISK'};$state=if([int64]$free -ge "+str(required)+"){ 'enough' }else{ 'insufficient' };[Console]::Out.WriteLine(([pscustomobject]@{version=1;disk=$state}|ConvertTo-Json -Compress))"
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
 if (type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated') is True or item.get('err-truncated') is True or ('out-truncated' in item and type(item.get('out-truncated')) is not bool) or ('err-truncated' in item and type(item.get('err-truncated')) is not bool)):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if not isinstance(value,dict) or value not in ({'version':1,'disk':'enough'},{'version':1,'disk':'insufficient'}):raise ValueError()
 out({'state':'observed','qga':'healthy','disk':value['disk']})
except Exception:out({'state':'unknown'})
'''


def transfer_preflight(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only source-bound CP117 transfer admission for the partial stage."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base transfer preflight requires the exact correlationId.")
    correlation = value["correlationId"]
    profile = _unknown_recovery_profile(correlation) if isinstance(correlation, str) else None
    if profile is None:
        raise WindowsMsiBasePrepareError("Base transfer preflight requires the exact correlationId.")
    request, command_hash = profile
    unknown = {"state": "unknown", "correlationId": correlation, "qga": "unknown",
               "disk": "unknown", "replayAllowed": False, "nativeActionAllowed": False}
    root = Path(root).resolve(strict=True)
    try:
        intent = _private_intent(root, correlation)
        if (intent is None or intent.get("request") != request or intent.get("commandSha256") != command_hash
                or intent.get("leaseId") != correlation):
            return unknown
        _, expected_size = _stage_artifact_readonly(root, intent)
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
        if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
            return unknown
        raw = _remote(config, _TRANSFER_PREFLIGHT, (sock, str(pid), str(ticks), str(expected_size)), None, 30)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiBasePrepareError):
        return unknown
    if result == {"state": "observed", "qga": "healthy", "disk": "enough"}:
        return {"state": "ready", "correlationId": correlation, "qga": "healthy", "disk": "enough",
                "replayAllowed": False, "nativeActionAllowed": False}
    if result == {"state": "observed", "qga": "healthy", "disk": "insufficient"}:
        return {"state": "blocked", "correlationId": correlation, "qga": "healthy", "disk": "insufficient",
                "replayAllowed": False, "nativeActionAllowed": False}
    return unknown


# This is deliberately topology admission only.  It proves the current CP117
# QEMU generation has one user-mode NIC and that the guest has the matching
# QEMU SLIRP default gateway.  A later transfer implementation must still pick
# and bind a fresh port after its own collision check; this observer never
# opens a listener, changes QEMU networking, or connects from the guest.
_TRANSFER_NETWORK_QEMU_TOPOLOGY = r'''import subprocess
def single_user_network(argv, device_is_network):
 if not isinstance(argv,list) or not argv or any(not isinstance(v,bytes) for v in argv):raise ValueError()
 if os.path.basename(argv[0])!=b'qemu-system-x86_64':raise ValueError()
 def fields(value):
  parts=value.split(b',')
  if not parts or not parts[0]:raise ValueError()
  options={}
  for part in parts[1:]:
   if b'=' not in part:raise ValueError()
   key,item=part.split(b'=',1)
   if not key or not item or key in options:raise ValueError()
   options[key]=item
  return parts[0],options
 netdev=[];devices=[];nic=[];legacy=[];i=1
 while i<len(argv):
  arg=argv[i]
  if arg in (b'-nic',b'-netdev',b'-device',b'-net'):
   if i+1>=len(argv):raise ValueError()
   value=argv[i+1]
   if not value:raise ValueError()
   if arg==b'-nic':nic.append(value)
   elif arg==b'-netdev':netdev.append(value)
   elif arg==b'-device':devices.append(value)
   else:legacy.append(value)
   i+=2;continue
  i+=1
 if legacy or len(nic)>1 or len(netdev)>1:raise ValueError()
 if len(nic)==1:
  value=nic[0]
  if not (value==b'user' or value.startswith(b'user,')) or netdev:raise ValueError()
  if any(device_is_network(fields(v)[0]) for v in devices):raise ValueError()
  return True
 if len(netdev)!=1 or nic:raise ValueError()
 model,options=fields(netdev[0])
 if model!=b'user' or b'id' not in options or not re.fullmatch(b'[A-Za-z0-9_.-]{1,32}',options[b'id']):raise ValueError()
 bound=[]
 for value in devices:
  model,opts=fields(value)
  if b'netdev' in opts:
   if opts[b'netdev']!=options[b'id']:raise ValueError()
   bound.append(value)
  elif device_is_network(model):raise ValueError()
 if len(bound)!=1:raise ValueError()
 return True
def user_network(pid):
 raw=open('/proc/'+pid+'/cmdline','rb').read(16385)
 if not raw or len(raw)>16384:raise ValueError()
 exe=os.readlink('/proc/'+pid+'/exe')
 info=os.stat(exe)
 if not stat.S_ISREG(info.st_mode) or os.path.basename(exe)!='qemu-system-x86_64':raise ValueError()
 def device_is_network(model):
  if not re.fullmatch(b'[A-Za-z0-9_.-]{1,64}',model):raise ValueError()
  result=subprocess.run((exe,'-device',model.decode('ascii')+',help'),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,timeout=3,check=False)
  if result.returncode!=0 or not 0<len(result.stdout)<=65536:raise ValueError()
  return re.search(rb'(?m)^\s*netdev(?:[=<\s])',result.stdout) is not None
 return single_user_network(raw.rstrip(b'\0').split(b'\0'),device_is_network)
'''


_TRANSFER_NETWORK_ADMISSION = _QGA + _TRANSFER_NETWORK_QEMU_TOPOLOGY + r'''import time
sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
phase='qga-protocol'
try:
 if not live(sock,pid,ticks):raise ValueError()
 phase='qemu-topology'
 user_network(pid)
 phase='guest-adapter'
 script="$ErrorActionPreference='Stop';$adapters=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'});if($adapters.Count -ne 1){throw 'NETWORK'};$rows=@(Get-NetIPConfiguration | Where-Object {$_.InterfaceIndex -eq $adapters[0].ifIndex -and $null -ne $_.IPv4DefaultGateway} | ForEach-Object {$ips=@($_.IPv4Address | ForEach-Object {$_.IPAddress} | Where-Object {$_ -match '^10\\.0\\.2\\.(?:[0-9]{1,3})$'});[pscustomobject]@{gateway=[string]$_.IPv4DefaultGateway.NextHop;addresses=$ips}});if($rows.Count -ne 1){throw 'NETWORK'};$row=$rows[0];if($row.gateway -ne '10.0.2.2' -or $row.addresses.Count -ne 1 -or $row.addresses[0] -eq '10.0.2.2'){throw 'NETWORK'};[Console]::Out.WriteLine(([pscustomobject]@{version=1;network='slirp';gateway='10.0.2.2';guestAddress='10.0.2'}|ConvertTo-Json -Compress))"
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
 if (type(item.get('exitcode')) is not int or item['exitcode']!=0 or item.get('out-truncated') is True or item.get('err-truncated') is True or ('out-truncated' in item and type(item.get('out-truncated')) is not bool) or ('err-truncated' in item and type(item.get('err-truncated')) is not bool)):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if value!={'version':1,'network':'slirp','gateway':'10.0.2.2','guestAddress':'10.0.2'}:raise ValueError()
 out({'state':'observed','qga':'healthy','qemuNetwork':'user-mode','guestGateway':'slirp-gateway'})
except Exception:out({'state':'unknown','reason':phase})
'''


def transfer_network_admission(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only proof for a future CP117 loopback-bound transfer endpoint."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base transfer network admission requires the exact correlationId.")
    correlation = value["correlationId"]
    if correlation != _TRANSFER_RECOVERY_CORRELATION:
        raise WindowsMsiBasePrepareError("Base transfer network admission requires the reviewed transfer correlationId.")
    unknown = {"state": "unknown", "correlationId": correlation, "qga": "unknown",
               "network": "unknown", "endpointEligibility": "unknown", "replayAllowed": False,
               "nativeActionAllowed": False}
    root = Path(root).resolve(strict=True)
    try:
        request, command_hash = _UNKNOWN_RECOVERY_PROFILES[correlation]
        intent = _private_intent(root, correlation)
        if (intent is None or intent.get("request") != request or intent.get("commandSha256") != command_hash
                or intent.get("leaseId") != correlation):
            return unknown
        config, _target, (env, sock, pid, ticks, sid) = _descriptor(root)
        if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
            return unknown
        raw = _remote(config, _TRANSFER_NETWORK_ADMISSION, (sock, str(pid), str(ticks)), None, 30)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiBasePrepareError):
        return unknown
    if result != {"state": "observed", "qga": "healthy", "qemuNetwork": "user-mode",
                  "guestGateway": "slirp-gateway"}:
        return unknown
    return {"state": "ready", "correlationId": correlation, "qga": "healthy", "network": "slirp",
            "endpointEligibility": "eligible", "hostBindAddress": "127.0.0.1",
            "guestHostAddress": "10.0.2.2", "replayAllowed": False, "nativeActionAllowed": False}


def _diagnostic_result(correlation: str, binding: str, checkpoint: str,
                       guest_proof: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Project one bounded diagnostic fact without authorizing further action."""
    result = {"state": "unknown", "correlationId": correlation, "binding": binding,
              "checkpoint": checkpoint, "replayAllowed": False, "nativeActionAllowed": False}
    if guest_proof is not None:
        result["guestProof"] = dict(guest_proof)
    return result


def _observe(root: Path | str, value: Mapping[str, Any], *, timeout: int) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base status requires exact correlationId.")
    correlation = value["correlationId"]
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation) or str(uuid.UUID(correlation)) != correlation:
        raise WindowsMsiBasePrepareError("Invalid base correlationId.")
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    unknown = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    if intent is None:
        return unknown
    try:
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
        if any(intent.get(key) != value for key, value in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
            return unknown
        request = intent["request"]
        raw = _remote(config, _STATUS, (str(target.fixture_transfer_root), env, correlation, sock,
            str(pid), str(ticks), request["sourceSha"], intent["pair"]["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"], request["targetMsiArtifactId"],
            intent["commandSha256"], sid), None, timeout)
        result = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError):
        return unknown
    if not isinstance(result, dict) or result.get("correlationId") != correlation:
        return unknown
    if result.get("state") == "running":
        if set(result) != {"state", "correlationId"}:
            return unknown
        return {"state": "running", "correlationId": correlation, "replayAllowed": False}
    failure = result.get("failure")
    if (result.get("state") == "observed" and isinstance(failure, dict)
            and failure == {"phase": "bootstrap", "code": "task_trigger_outcome_ambiguous"}):
        if set(result) != {"state", "correlationId", "failure"}:
            return unknown
        return {"state": "unknown", "correlationId": correlation,
                "failurePhase": "bootstrap", "failureType": "task_trigger_outcome_ambiguous",
                "code": "task_trigger_outcome_ambiguous", "replayAllowed": False}
    payload = result.get("result")
    if result.get("state") != "observed" or not isinstance(payload, dict):
        return unknown
    required_payload = {"version", "correlationId", "stage", "result", "exitCode", "originalSid",
                        "sessionId", "limited", "msiSha256", "installedVersion", "cliSha256",
                        "jarSha256", "helperSha256", "priorProducts", "installedProducts"}
    if (set(result) != {"state", "correlationId", "result"} or set(payload) != required_payload
            or payload.get("version") != 1 or payload.get("correlationId") != correlation
            or payload.get("stage") not in {"IDENTITY", "ADMISSION", "INSTALL", "READBACK"}
            or payload.get("result") not in {"IN_PROGRESS", "PASSED", "FAILED"}
            or type(payload.get("exitCode")) is not int):
        return unknown
    if payload["result"] == "PASSED" and (payload["stage"] != "READBACK" or payload["exitCode"] != 0):
        return unknown
    if payload["result"] == "PASSED" and (payload.get("originalSid") != intent["expectedSid"]
            or payload.get("sessionId") != 1 or payload.get("limited") is not True
            or payload.get("msiSha256") != intent["request"]["baseMsiArtifactId"].removeprefix("sha256-")
            or payload.get("installedVersion") != intent["pair"]["baseVersion"]
            or payload.get("cliSha256") != intent["pair"]["baseCliSha256"]
            or payload.get("jarSha256") != intent["pair"]["baseAppJarSha256"]
            or payload.get("helperSha256") != intent["pair"]["baseHelperSha256"]
            or not _unique_product(payload.get("priorProducts"), intent["request"]["expectedCurrentVersion"])
            or not _unique_product(payload.get("installedProducts"), intent["pair"]["baseVersion"])):
        return unknown
    return {"state": "terminal" if payload["result"] != "IN_PROGRESS" else "running",
            "correlationId": correlation, "result": payload["result"], "stage": payload["stage"],
            "exitCode": payload["exitCode"], "sourceSha": intent["request"]["sourceSha"],
            "baseArtifactId": intent["request"]["baseMsiArtifactId"], "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Observe one existing correlation with the ordinary bounded status window."""
    return _observe(root, value, timeout=30)


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only durable facts for one uncertain correlation in a fixed window.

    This cannot start, retry, close, or clean up a CP117 operation. Missing
    evidence remains unknown and never establishes a successful installation.
    """
    return _observe(root, value, timeout=120)


def terminal_reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read a durable base result after QGA has retired the bootstrap PID.

    This observer independently verifies the fixed scheduled task, principal,
    private result leaf, staged MSI and installed package bytes. It never
    starts the installer or treats a caller supplied terminal claim as proof.
    """
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base terminal reconciliation requires exact correlationId.")
    correlation = value["correlationId"]
    if (not isinstance(correlation, str) or not _UUID.fullmatch(correlation)
            or str(uuid.UUID(correlation)) != correlation):
        raise WindowsMsiBasePrepareError("Invalid base terminal correlationId.")
    root = Path(root).resolve(strict=True)
    unknown = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    try:
        intent = _private_intent(root, correlation)
        if intent is None:
            return unknown
        request = _request(intent["request"])
        pair, _ = _stage_artifact_readonly(root, intent)
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
        if any(intent.get(key) != expected for key, expected in (
                ("environment", env), ("socketPath", sock), ("pid", pid),
                ("startTicks", ticks), ("expectedSid", sid))):
            return unknown
        action_sha = _terminal_task_arguments_sha(correlation, intent)
        raw = _remote(config, _TERMINAL_RECONCILE, (str(target.fixture_transfer_root), env,
            correlation, sock, str(pid), str(ticks), request["sourceSha"], pair["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid, action_sha,
            pair["baseCliSha256"], pair["baseAppJarSha256"], pair["baseHelperSha256"],
            pair["baseAppJarName"]), None, 120)
        observed = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiBasePrepareError):
        return unknown
    if (not isinstance(observed, dict) or set(observed) != {"state", "correlationId", "result"}
            or observed.get("state") != "observed" or observed.get("correlationId") != correlation):
        return unknown
    payload = observed["result"]
    required = {"version", "correlationId", "stage", "result", "exitCode", "originalSid",
                "sessionId", "limited", "msiSha256", "installedVersion", "cliSha256",
                "jarSha256", "helperSha256", "priorProducts", "installedProducts"}
    if (not isinstance(payload, dict) or set(payload) != required
            or payload.get("version") != 1 or payload.get("correlationId") != correlation
            or payload.get("stage") != "READBACK" or payload.get("result") != "PASSED"
            or type(payload.get("exitCode")) is not int or payload["exitCode"] != 0
            or payload.get("originalSid") != sid or payload.get("sessionId") != 1
            or payload.get("limited") is not True
            or payload.get("msiSha256") != request["baseMsiArtifactId"].removeprefix("sha256-")
            or payload.get("installedVersion") != pair["baseVersion"]
            or payload.get("cliSha256") != pair["baseCliSha256"]
            or payload.get("jarSha256") != pair["baseAppJarSha256"]
            or payload.get("helperSha256") != pair["baseHelperSha256"]
            or not _unique_product(payload.get("priorProducts"), request["expectedCurrentVersion"])
            or not _unique_product(payload.get("installedProducts"), pair["baseVersion"])):
        return unknown
    return {"state": "terminal", "correlationId": correlation, "result": "PASSED",
            "stage": "READBACK", "exitCode": 0, "sourceSha": request["sourceSha"],
            "baseArtifactId": request["baseMsiArtifactId"], "replayAllowed": False}


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one bounded missing-proof checkpoint for an uncertain base run.

    This is a read-only observer for a pre-existing intent.  Every result keeps
    the original correlation unknown and non-replayable, including a missing
    stage, binding, dispatch record, or result receipt.
    """
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base diagnostic requires exact correlationId.")
    correlation = value["correlationId"]
    if (not isinstance(correlation, str) or not _UUID.fullmatch(correlation)
            or str(uuid.UUID(correlation)) != correlation):
        raise WindowsMsiBasePrepareError("Invalid base diagnostic correlationId.")
    root = Path(root).resolve(strict=True)
    try:
        intent = _private_intent(root, correlation)
    except (OSError, ValueError, TypeError, KeyError):
        return _diagnostic_result(correlation, "unverified", "local-intent")
    if intent is None:
        return _diagnostic_result(correlation, "unverified", "local-intent")
    try:
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    except (OSError, ValueError, TypeError, KeyError):
        return _diagnostic_result(correlation, "unverified", "descriptor")
    if any(intent.get(key) != expected for key, expected in (
            ("environment", env), ("socketPath", sock), ("pid", pid),
            ("startTicks", ticks), ("expectedSid", sid))):
        return _diagnostic_result(correlation, "mismatch", "descriptor")
    try:
        request = intent["request"]
        raw = _remote(config, _DIAGNOSTIC, (str(target.fixture_transfer_root), env, correlation,
            sock, str(pid), str(ticks), request["sourceSha"], intent["pair"]["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid), None, 120)
        result = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError):
        return _diagnostic_result(correlation, "exact", "qga-protocol")
    base_fields = {"state", "correlationId", "binding", "checkpoint"}
    if (not isinstance(result, dict) or not base_fields.issubset(result)
            or result.get("state") != "diagnosed" or result.get("correlationId") != correlation
            or not isinstance(result.get("binding"), str)
            or result["binding"] not in {"exact", "mismatch", "unverified"}
            or not isinstance(result.get("checkpoint"), str)
            or result["checkpoint"] not in _DIAGNOSTIC_CHECKPOINTS):
        return _diagnostic_result(correlation, "unverified", "qga-protocol")
    if result["checkpoint"] == "remote-binding" and result["binding"] != "mismatch":
        return _diagnostic_result(correlation, "unverified", "qga-protocol")
    if result["checkpoint"] != "remote-binding" and result["binding"] != "exact":
        return _diagnostic_result(correlation, "unverified", "qga-protocol")
    proof = result.get("guestProof")
    proof_failure = result.get("guestProofFailure")
    proof_failure_phase = result.get("guestProofFailurePhase")
    proof_projection_reason = result.get("guestProofProjectionReason")
    proof_projection_schema = result.get("guestProofProjectionSchema")
    proof_fields = {"task", "leaf", "result", "correlationPowerShell", "product",
                    "installedVersion", "installer"}
    if result["checkpoint"] != "remote-dispatch-absent":
        if set(result) != base_fields:
            return _diagnostic_result(correlation, "unverified", "qga-protocol")
        return _diagnostic_result(correlation, result["binding"], result["checkpoint"])
    failure_codes = {"none", "qga-exec-rpc-or-protocol", "qga-status-rpc-or-protocol",
                     "qga-status-exited-malformed", "qga-status-terminal-fields-malformed",
                     "qga-status-running-timeout", "qga-truncated", "powershell-nonzero",
                     "powershell-empty-or-malformed-output", "projection"}
    unknown_proof = {"task": "unknown", "leaf": "unknown", "result": "unknown",
                     "correlationPowerShell": "unknown", "product": "unknown",
                     "installedVersion": None, "installer": "unknown"}
    phases = {"task", "leaf", "process", "product", "installer", "output"}
    projection_reasons = {"missing-or-extra-fields", "version-or-phase-invalid",
                          "nonzero-failure-envelope-invalid", "success-enum-invalid",
                          "product-version-invalid", "internal-error"}
    schema_fields = {"presenceMask", "extraFieldCount"}
    has_schema = (proof_failure == "projection"
                  and proof_projection_reason == "missing-or-extra-fields")
    expected_fields = base_fields | {"guestProof", "guestProofFailure", "guestProofFailurePhase",
                                     "guestProofProjectionReason"}
    if has_schema:
        expected_fields |= {"guestProofProjectionSchema"}
    if (set(result) != expected_fields
            or not isinstance(proof_failure, str) or proof_failure not in failure_codes
            or not isinstance(proof_failure_phase, str) or not isinstance(proof_projection_reason, str)
            or not isinstance(proof, Mapping) or set(proof) != proof_fields
            or any(not isinstance(proof.get(key), str)
                   or proof[key] not in {"present", "absent", "unknown"}
                   for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))
            or not isinstance(proof.get("product"), str)
            or proof["product"] not in {"absent", "single", "multiple", "unknown"}
            or (proof["product"] == "single" and (not isinstance(proof.get("installedVersion"), str)
                or not _VERSION.fullmatch(proof["installedVersion"])))
            or (proof["product"] != "single" and proof.get("installedVersion") is not None)
            or (proof_failure == "none" and "unknown" in proof.values())
            or (proof_failure == "none" and (proof_failure_phase != "none" or proof_projection_reason != "none"))
            or (proof_failure == "powershell-nonzero" and (proof_failure_phase not in phases
                or proof_projection_reason != "unavailable"))
            or (proof_failure == "projection" and (proof_failure_phase != "unavailable"
                or proof_projection_reason not in projection_reasons))
            or (has_schema and (not isinstance(proof_projection_schema, Mapping)
                or set(proof_projection_schema) != schema_fields
                or not isinstance(proof_projection_schema.get("presenceMask"), str)
                or not re.fullmatch(r"[01]{9}", proof_projection_schema["presenceMask"])
                or type(proof_projection_schema.get("extraFieldCount")) is not int
                or not 0 <= proof_projection_schema["extraFieldCount"] <= 9))
            or (proof_failure not in {"none", "powershell-nonzero", "projection"}
                and (proof_failure_phase != "unavailable" or proof_projection_reason != "unavailable"))
            or (proof_failure != "none" and dict(proof) != unknown_proof)):
        return _diagnostic_result(correlation, "unverified", "qga-protocol")
    projected = _diagnostic_result(correlation, result["binding"], result["checkpoint"], proof)
    projected["guestProofFailure"] = proof_failure
    projected["guestProofFailurePhase"] = proof_failure_phase
    projected["guestProofProjectionReason"] = proof_projection_reason
    if has_schema:
        projected["guestProofProjectionSchema"] = dict(proof_projection_schema)
    return projected


def stage_diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the one guest MSI staged by an uncertain base correlation.

    The stage outcome is diagnostic evidence only.  In particular, a complete
    byte-for-byte MSI proves neither that the scheduled task ran nor that the
    MSI installed, and every outcome remains non-replayable.
    """
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base stage diagnostic requires exact correlationId.")
    correlation = value["correlationId"]
    if (not isinstance(correlation, str) or not _UUID.fullmatch(correlation)
            or str(uuid.UUID(correlation)) != correlation):
        raise WindowsMsiBasePrepareError("Invalid base stage diagnostic correlationId.")
    unknown = {"state": "unknown", "correlationId": correlation, "binding": "unverified",
               "checkpoint": "local-intent", "replayAllowed": False, "nativeActionAllowed": False}
    root = Path(root).resolve(strict=True)
    try:
        intent = _private_intent(root, correlation)
    except (OSError, ValueError, TypeError, KeyError):
        return unknown
    if intent is None:
        return unknown
    try:
        request = _request(intent["request"])
        pair, expected_size = _stage_artifact_readonly(root, intent)
        config, target, (env, sock, pid, ticks, sid) = _descriptor(root)
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiBasePrepareError):
        return {**unknown, "checkpoint": "local-artifact"}
    if any(intent.get(key) != expected for key, expected in (
            ("environment", env), ("socketPath", sock), ("pid", pid),
            ("startTicks", ticks), ("expectedSid", sid))):
        return {**unknown, "binding": "mismatch", "checkpoint": "descriptor"}
    try:
        raw = _remote(config, _STAGE_DIAGNOSTIC, (str(target.fixture_transfer_root), env, correlation,
            sock, str(pid), str(ticks), request["sourceSha"], pair["sourceFingerprint"],
            request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid, str(expected_size)), None, 120)
        result = json.loads(raw) if raw is not None else {}
    except (OSError, ValueError, TypeError, KeyError):
        return {**unknown, "binding": "exact", "checkpoint": "qga-protocol"}
    base_fields = {"state", "correlationId", "binding", "checkpoint"}
    if (not isinstance(result, dict) or not base_fields.issubset(result)
            or result.get("state") != "stage-diagnosed" or result.get("correlationId") != correlation
            or result.get("binding") not in {"exact", "mismatch", "unverified"}
            or result.get("checkpoint") not in _STAGE_DIAGNOSTIC_CHECKPOINTS):
        return {**unknown, "checkpoint": "qga-protocol"}
    checkpoint, binding = result["checkpoint"], result["binding"]
    if checkpoint == "remote-binding":
        if binding != "mismatch" or set(result) != base_fields:
            return {**unknown, "checkpoint": "qga-protocol"}
        return {**unknown, "binding": binding, "checkpoint": checkpoint}
    if checkpoint != "guest-stage":
        if binding != "exact" or set(result) != base_fields:
            return {**unknown, "checkpoint": "qga-protocol"}
        return {**unknown, "binding": binding, "checkpoint": checkpoint}
    fields = base_fields | {"guestStage", "observedSize", "sizeMatches", "sha256Matches"}
    stage = result.get("guestStage")
    valid = set(result) == fields and binding == "exact"
    if stage == "absent":
        valid = valid and result.get("observedSize") is None and result.get("sizeMatches") is False and result.get("sha256Matches") is False
    elif stage == "partial":
        valid = (valid and type(result.get("observedSize")) is int and 0 <= result["observedSize"] <= 1024 * 1024 * 1024
                 and type(result.get("sizeMatches")) is bool and type(result.get("sha256Matches")) is bool
                 and not (result["sizeMatches"] and result["sha256Matches"]))
    elif stage == "full":
        valid = (valid and result.get("observedSize") == expected_size and result.get("sizeMatches") is True
                 and result.get("sha256Matches") is True)
    else:
        valid = False
    if not valid:
        return {**unknown, "binding": "exact", "checkpoint": "qga-protocol"}
    return {"state": "unknown", "correlationId": correlation, "binding": "exact",
            "checkpoint": "guest-stage", "guestStage": stage, "observedSize": result["observedSize"],
            "sizeMatches": result["sizeMatches"], "sha256Matches": result["sha256Matches"],
            "replayAllowed": False, "nativeActionAllowed": False}


_UNKNOWN_CENSUS_FIELDS = {"state", "correlationId", "remoteStage", "mutation", "task", "leaf",
                          "result", "correlationPowerShell", "product", "installedVersion", "installer"}
_UNKNOWN_UNSAFE_FIELDS = {"state", "correlationId", "task", "leaf", "result", "correlationPowerShell",
                          "product", "installedVersion", "installer"}
_UNKNOWN_CLEANUP_PHASES = {"host-guard", "host-root", "remote-stage", "guest-census", "guest-cleanup",
                           "guest-recheck", "remote-stage-cleanup", "protocol", "guest-task", "guest-leaf",
                           "guest-process", "guest-product", "guest-installer", "guest-output", "guest-qga-exec",
                           "guest-qga-status-rpc", "guest-qga-status-exited-malformed", "guest-qga-status-running-timeout",
                           "guest-qga-status-terminal-fields", "guest-qga-status-truncated",
                           "guest-empty-or-malformed-output", "guest-projection", "guest-unexpected-internal"}


def _unknown_cleanup_observe(config: Any, target: Any, intent: Mapping[str, Any],
                             descriptor: tuple[Any, ...], mode: str, correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any] | None:
    """Project a bounded remote cleanup observation without promoting it."""
    env, sock, pid, ticks, sid = descriptor
    request, pair = intent["request"], intent["pair"]
    try:
        raw = _remote(config, _UNKNOWN_CLEANUP, (str(target.fixture_transfer_root), env,
            correlation, sock, str(pid), str(ticks), request["sourceSha"],
            pair["sourceFingerprint"], request["fixtureReceiptArtifactId"], request["baseMsiArtifactId"],
            request["targetMsiArtifactId"], intent["commandSha256"], sid, mode), None, 120)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    if (isinstance(result, dict) and result == {"state": "unknown", "correlationId": correlation,
                  "phase": result.get("phase")} and result.get("phase") in _UNKNOWN_CLEANUP_PHASES):
        return {"state": "unknown", "phase": result["phase"]}
    return dict(result) if isinstance(result, dict) else None


def _unknown_cleanup_project(result: Any, mode: str, correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any] | None:
    """Validate one already received cleanup envelope; no transport retry."""
    if (not isinstance(result, dict) or set(result) != _UNKNOWN_CENSUS_FIELDS
            or result.get("state") != "observed" or result.get("correlationId") != correlation
            or result.get("remoteStage") not in {"present", "empty", "absent"}
            or result.get("mutation") not in {"none", "guest-leaf", "remote-stage", "both"}
            or any(result.get(key) not in {"present", "absent"}
                   for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))
            or result.get("product") != "single" or result.get("installedVersion") != "2.1.17"):
        return None
    if mode == "status" and result["mutation"] != "none":
        return None
    return dict(result)


def _unknown_cleanup_unsafe_project(result: Any, correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any] | None:
    """Accept only the read-only, validated unsafe guest census projection."""
    if (not isinstance(result, dict) or set(result) != _UNKNOWN_UNSAFE_FIELDS
            or result.get("state") != "guest-unsafe" or result.get("correlationId") != correlation
            or any(result.get(key) not in {"present", "absent"}
                   for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))
            or result.get("product") not in {"absent", "single", "multiple"}):
        return None
    installed = result.get("installedVersion")
    if ((result["product"] == "single" and (not isinstance(installed, str) or not _VERSION.fullmatch(installed)))
            or (result["product"] != "single" and installed is not None)):
        return None
    return {key: result[key] for key in sorted(_UNKNOWN_UNSAFE_FIELDS - {"state", "correlationId"})}


def _unknown_cleanup_census(config: Any, target: Any, intent: Mapping[str, Any],
                            descriptor: tuple[Any, ...], mode: str,
                            correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any] | None:
    """One exact remote/QGA census or cleanup response; malformed means unknown."""
    result = _unknown_cleanup_observe(config, target, intent, descriptor, mode, correlation)
    return _unknown_cleanup_project(result, mode, correlation)


def _unknown_pre_mutation_proof(value: Mapping[str, Any]) -> bool:
    return (value.get("remoteStage") == "present" and value.get("leaf") == "present"
            and all(value.get(key) == "absent" for key in
                    ("task", "result", "correlationPowerShell", "installer"))
            and value.get("product") == "single" and value.get("installedVersion") == "2.1.17")


def _unknown_pre_mutation_guest(value: Mapping[str, Any]) -> bool:
    return (value.get("leaf") == "present" and all(value.get(key) == "absent" for key in
            ("task", "result", "correlationPowerShell", "installer"))
            and value.get("product") == "single" and value.get("installedVersion") == "2.1.17")


def _unknown_diagnostic_valid(value: Mapping[str, Any], correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> bool:
    fields = {"state", "correlationId", "binding", "checkpoint", "replayAllowed", "nativeActionAllowed",
              "guestProof", "guestProofFailure", "guestProofFailurePhase", "guestProofProjectionReason"}
    return (isinstance(value, Mapping) and set(value) == fields and value.get("state") == "unknown"
            and value.get("correlationId") == correlation
            and value.get("binding") == "exact" and value.get("checkpoint") == "remote-dispatch-absent"
            and value.get("replayAllowed") is False and value.get("nativeActionAllowed") is False
            and value.get("guestProofFailure") == "none" and value.get("guestProofFailurePhase") == "none"
            and value.get("guestProofProjectionReason") == "none"
            and _unknown_pre_mutation_guest(value.get("guestProof", {})))


def _unknown_both_absent(value: Mapping[str, Any]) -> bool:
    return (value.get("remoteStage") == "absent" and value.get("leaf") == "absent"
            and all(value.get(key) == "absent" for key in
                    ("task", "result", "correlationPowerShell", "installer"))
            and value.get("product") == "single" and value.get("installedVersion") == "2.1.17")


def _unknown_cleanup_admitted(value: Mapping[str, Any]) -> bool:
    """Permit any of the four leaf/stage partial states after the marker exists."""
    return (value.get("remoteStage") in {"present", "empty", "absent"} and value.get("leaf") in {"present", "absent"}
            and all(value.get(key) == "absent" for key in
                    ("task", "result", "correlationPowerShell", "installer"))
            and value.get("product") == "single" and value.get("installedVersion") == "2.1.17")


def _unknown_close_marker_value(intent: Mapping[str, Any], descriptor: tuple[Any, ...],
                                first: Mapping[str, Any], second: Mapping[str, Any],
                                correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any]:
    env, sock, pid, ticks, sid = descriptor
    evidence = {"first": {key: first[key] for key in sorted(_UNKNOWN_CENSUS_FIELDS - {"state", "correlationId", "mutation"})},
                "second": {key: second[key] for key in sorted(_UNKNOWN_CENSUS_FIELDS - {"state", "correlationId", "mutation"})},
                "readiness": "2.1.17"}
    return {"version": 1, "state": "close-intent", "correlationId": correlation,
            "commandSha256": intent["commandSha256"], "sourceSha": intent["request"]["sourceSha"],
            "guestGeneration": {"environment": env, "socketPath": sock, "qemuPid": pid,
                                "startTicks": ticks, "expectedSid": sid},
            "preMutationEvidenceSha256": hashlib.sha256(json.dumps(evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()}


def _unknown_lease_status(root: Path, correlation: str = _UNKNOWN_CLOSURE_CORRELATION) -> dict[str, Any]:
    """Read the existing campaign receipt without creating its journal or lock."""
    directory = root / campaign_lease._DIR
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return {"state": "unknown"}
        active = campaign_lease._active(directory)
        closed = campaign_lease._closed(directory, correlation)
    except (OSError, ValueError, campaign_lease.Cp117LeaseError):
        return {"state": "unknown"}
    if active is not None and closed is not None:
        return {"state": "unknown"}
    record = closed if closed is not None else active
    if record is None or record.get("identity", {}).get("leaseId") != correlation:
        return {"state": "absent"}
    return {"state": record["state"], "role": record["role"], "server": record["server"],
            "lastOutcome": record["lastOutcome"]}


def close_unknown_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read only phase/status evidence for one reviewed unknown-base closure."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base unknown closure status requires the exact correlationId.")
    correlation = value["correlationId"]
    profile = _unknown_recovery_profile(correlation) if isinstance(correlation, str) else None
    if profile is None:
        raise WindowsMsiBasePrepareError("Base unknown closure status requires the exact correlationId.")
    request, command_hash = profile
    profile_args = () if correlation == _UNKNOWN_CLOSURE_CORRELATION else (correlation,)
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    if (intent is None or intent.get("request") != request
            or intent.get("commandSha256") != command_hash
            or intent.get("leaseId") != correlation
            or not isinstance(intent.get("pair"), Mapping)
            or not isinstance(intent["pair"].get("sourceFingerprint"), str)):
        return {"state": "unknown", "correlationId": correlation,
                "phase": "local-intent", "reason": "missing-or-changed", "replayAllowed": False}
    try: config, target, descriptor = _descriptor(root)
    except (OSError, ValueError, TypeError, KeyError):
        return {"state": "unknown", "correlationId": correlation,
                "phase": "descriptor", "reason": "unavailable", "replayAllowed": False}
    env, sock, pid, ticks, sid = descriptor
    if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return {"state": "unknown", "correlationId": correlation,
                "phase": "descriptor", "reason": "changed", "replayAllowed": False}
    marker_present = _unknown_closure_marker(root, correlation).exists()
    if marker_present and not _unknown_marker_valid(root, intent, descriptor, correlation):
        return {"state": "unknown", "correlationId": correlation,
                "phase": "post-close-evidence", "reason": "marker-invalid", "replayAllowed": False}
    if not marker_present and _unknown_lease_status(root, *profile_args).get("state") == "closed":
        return {"state": "unknown", "correlationId": correlation,
                "phase": "post-close-evidence", "reason": "marker-missing", "replayAllowed": False}
    if marker_present:
        lease = _unknown_lease_status(root, *profile_args)
        if lease.get("state") == "closed":
            if lease.get("lastOutcome") != "unknown-cleaned":
                return {"state": "unknown", "correlationId": correlation,
                        "phase": "post-close-evidence", "reason": "lease-outcome", "replayAllowed": False}
            observed = _unknown_cleanup_observe(config, target, intent, descriptor, "status", *profile_args)
            census = _unknown_cleanup_project(observed, "status", correlation)
            if census is None or not _unknown_both_absent(census):
                return {"state": "unknown", "correlationId": correlation,
                        "phase": "post-close-evidence", "reason": "both-absent", "replayAllowed": False}
            idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
            if (idle.get("state") != "ready" or idle.get("ready") is not True
                    or idle.get("installedVersion") != "2.1.17" or idle.get("productCount") != 1
                    or idle.get("activeCount") != 0 or idle.get("activeProcesses") != []):
                return {"state": "unknown", "correlationId": correlation,
                        "phase": "post-close-evidence", "reason": "readiness", "replayAllowed": False}
            return {"state": "closed", "correlationId": correlation,
                    "phase": "closed", "outcome": "unknown-cleaned", "census": census, "lease": lease,
                    "markerPresent": True, "replayAllowed": False}
    diagnostics = [diagnose(root, {"correlationId": correlation}) for _ in range(2)]
    if not all(_unknown_diagnostic_valid(item, correlation) for item in diagnostics):
        item = next(item for item in diagnostics if not _unknown_diagnostic_valid(item, correlation))
        return {"state": "unknown", "correlationId": correlation,
                "phase": "diagnostic", "reason": item.get("checkpoint", "invalid"),
                "replayAllowed": False}
    observed = _unknown_cleanup_observe(config, target, intent, descriptor, "status", *profile_args)
    if observed is None:
        return {"state": "unknown", "correlationId": correlation,
                "phase": "cleanup-status", "reason": "transport-or-parse", "replayAllowed": False}
    if observed.get("state") == "unknown":
        return {"state": "unknown", "correlationId": correlation,
                "phase": "cleanup-status", "reason": observed["phase"], "replayAllowed": False}
    unsafe = _unknown_cleanup_unsafe_project(observed, correlation)
    if unsafe is not None:
        return {"state": "unknown", "correlationId": correlation,
                "phase": "cleanup-status", "reason": "guest-unsafe", "guestProof": unsafe,
                "replayAllowed": False}
    census = _unknown_cleanup_project(observed, "status", correlation)
    if census is None:
        return {"state": "unknown", "correlationId": correlation,
                "phase": "cleanup-status", "reason": "projection", "replayAllowed": False}
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
    if idle.get("state") != "ready" or idle.get("ready") is not True:
        return {"state": "unknown", "correlationId": correlation,
                "phase": "readiness", "reason": idle.get("code", "unavailable"),
                "census": census, "replayAllowed": False}
    lease = _unknown_lease_status(root, *profile_args)
    return {"state": "observed", "correlationId": correlation,
            "phase": "lease", "reason": lease["state"], "census": census, "lease": lease,
            "markerPresent": _unknown_closure_marker(root, correlation).exists(), "replayAllowed": False}


def close_unknown(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close the one lost base submission after durable uncertain-idle cleanup proof.

    This does not infer that the original installer was not invoked.  It only
    clears its exact abandoned leaf and remote stage after two fresh censuses,
    then records the base campaign as ``unknown-cleaned``.
    """
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise WindowsMsiBasePrepareError("Base unknown closure requires the exact correlationId.")
    correlation = value["correlationId"]
    profile = _unknown_recovery_profile(correlation) if isinstance(correlation, str) else None
    if profile is None:
        raise WindowsMsiBasePrepareError("Base unknown closure requires the exact correlationId.")
    request, command_hash = profile
    profile_args = () if correlation == _UNKNOWN_CLOSURE_CORRELATION else (correlation,)
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    if (intent is None or intent.get("request") != request
            or intent.get("commandSha256") != command_hash
            or intent.get("leaseId") != correlation
            or not isinstance(intent.get("pair"), Mapping)
            or not isinstance(intent["pair"].get("sourceFingerprint"), str)):
        raise WindowsMsiBasePrepareError("Base unknown closure intent changed.")
    config, target, descriptor = _descriptor(root)
    env, sock, pid, ticks, sid = descriptor
    if any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
            ("pid", pid), ("startTicks", ticks), ("expectedSid", sid))):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    marker_path = _unknown_closure_marker(root, correlation)
    has_marker = marker_path.exists()
    if has_marker and not _unknown_marker_valid(root, intent, descriptor, correlation):
        raise WindowsMsiBasePrepareError("Base unknown closure marker changed.")
    # Before the first mutation, the diagnostic checks the original remote
    # binding and absent dispatch. A durable marker permits a retry to resume
    # any partial leaf/stage state left by a lost cleanup response.
    if not has_marker:
        first_diagnostic = diagnose(root, {"correlationId": correlation})
        second_diagnostic = diagnose(root, {"correlationId": correlation})
        if not all(_unknown_diagnostic_valid(item, correlation) for item in (first_diagnostic, second_diagnostic)):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    first = _unknown_cleanup_census(config, target, intent, descriptor, "status", *profile_args)
    second = _unknown_cleanup_census(config, target, intent, descriptor, "status", *profile_args)
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
    precondition = _unknown_cleanup_admitted if has_marker else _unknown_pre_mutation_proof
    if (first is None or second is None or not precondition(first)
            or not precondition(second) or idle.get("state") != "ready"
            or idle.get("ready") is not True or idle.get("installedVersion") != "2.1.17"
            or idle.get("productCount") != 1 or idle.get("activeCount") != 0
            or idle.get("activeProcesses") != []):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    marker = _unknown_close_marker_value(intent, descriptor, first, second, correlation)
    if not has_marker:
        if not _write_private_once(marker_path, marker) or not _unknown_marker_valid(root, intent, descriptor, correlation):
            raise WindowsMsiBasePrepareError("Base unknown closure marker changed.")
    elif not _unknown_marker_valid(root, intent, descriptor, correlation):
        raise WindowsMsiBasePrepareError("Base unknown closure marker changed.")
    # Status first, then one idempotent phase-specific cleanup.  A lost cleanup
    # response is resolved only by two later both-absent censuses.
    before = _unknown_cleanup_census(config, target, intent, descriptor, "status", *profile_args)
    if before is None or not _unknown_cleanup_admitted(before):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    cleanup = _unknown_cleanup_census(config, target, intent, descriptor, "cleanup", *profile_args)
    after_first = _unknown_cleanup_census(config, target, intent, descriptor, "status", *profile_args)
    after_second = _unknown_cleanup_census(config, target, intent, descriptor, "status", *profile_args)
    if (cleanup is None or after_first is None or after_second is None
            or not _unknown_both_absent(after_first) or not _unknown_both_absent(after_second)):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    evidence = {"afterFirst": after_first, "afterSecond": after_second,
                "closeIntent": correlation}
    evidence_sha = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    identity = _campaign_identity(request, descriptor)
    remote = _campaign_remote(config, target)
    try:
        current = campaign_lease.inspect(root, correlation)
        if current["state"] in {"pending-finish", "pending-close"}:
            current = campaign_lease.reconcile(root, correlation, remote)
        if current["state"] == "closed":
            return {"state": "closed", "correlationId": correlation, "replayAllowed": False}
        directory, lock = campaign_lease._locked(root)
        try: record = campaign_lease._active(directory)
        finally: os.close(lock)
        if (record is None or record.get("identity") != identity or record.get("server") != "stopped"
                or record.get("credentials") != "absent"
                or not campaign_lease._remote_confirm(remote, "status", record, None)):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        if (record.get("state") == "role-active" and record.get("role") == "base"
                and record.get("correlationId") == correlation):
            if campaign_lease.finish_role(root, correlation, "base",
                                          correlation, evidence_sha,
                                          "unknown-cleaned", remote).get("state") != "active":
                return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        elif not (record.get("state") == "active" and record.get("role") is None
                  and record.get("correlationId") is None and record.get("lastOutcome") == "unknown-cleaned"
                  and record.get("lastEvidenceSha256") == evidence_sha):
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
        cleanup_proof = {"guestGeneration": {"socketPath": sock, "qemuPid": pid, "startTicks": ticks},
                         "serverStopped": True, "credentialsCleaned": True,
                         "protectedJobsTerminalCleaned": True, "activeInstallerProcessesAbsent": True,
                         "cleanupReceiptSha256": evidence_sha}
        if campaign_lease.close(root, correlation, cleanup_proof, remote).get("state") != "closed":
            return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    except (campaign_lease.Cp117LeaseError, OSError, ValueError, KeyError):
        return {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
    return {"state": "closed", "correlationId": correlation,
            "outcome": "unknown-cleaned", "replayAllowed": False}


def finish_observed(root: Path | str, correlation: str) -> dict[str, Any]:
    """Internal: release base role after exact installed readback and idle guest.

    A caller cannot provide terminal or cleanup claims. Both observations are
    reread from fixed native routes before the lease transition.
    """
    root = Path(root).resolve(strict=True)
    intent = _private_intent(root, correlation)
    if intent is None or intent.get("leaseId") != correlation:
        raise WindowsMsiBasePrepareError("CP117 base intent is absent or unbound.")
    observed = status(root, {"correlationId": correlation})
    if observed.get("state") == "unknown":
        observed = terminal_reconcile(root, {"correlationId": correlation})
    request = intent["request"]
    if (observed.get("state") != "terminal" or observed.get("result") != "PASSED"
            or observed.get("stage") != "READBACK" or observed.get("exitCode") != 0
            or observed.get("sourceSha") != request["sourceSha"]
            or observed.get("baseArtifactId") != request["baseMsiArtifactId"]):
        raise WindowsMsiBasePrepareError("CP117 base terminal readback is unavailable.")
    idle = readiness(root, {"host": "archlinux", "expectedCurrentVersion": intent["pair"]["baseVersion"]})
    if (idle.get("state") != "ready" or idle.get("activeCount") != 0
            or idle.get("installedVersion") != intent["pair"]["baseVersion"]):
        raise WindowsMsiBasePrepareError("CP117 base cleanup is not observed.")
    config, target, descriptor = _descriptor(root)
    _verified_claimed_campaign(root, request, descriptor, config, target, correlation, "base")
    evidence = hashlib.sha256(json.dumps({"terminal": observed, "idle": idle,
        "leaseId": correlation}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return campaign_lease.finish_role(root, correlation, "base", correlation,
                                      evidence, "succeeded", _campaign_remote(config, target))
