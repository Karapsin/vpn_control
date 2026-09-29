"""Exact Android self-update target admission and durable driver receipts.

The fixture driver owns the actual public PackageInstaller session. This module
never substitutes an ADB package replacement for that product action.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_PACKAGE = "com.kardinal.vpncontrol"
_MAX_RECEIPT = 1_048_576


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
        raise ValueError("Android installer artifact is not a regular single-link file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (item.st_dev, item.st_ino, item.st_size):
            raise ValueError("Android installer artifact changed before hash")
        while block := source.read(65536):
            digest.update(block)
        closing = os.fstat(source.fileno())
        if (closing.st_dev, closing.st_ino, closing.st_size) != (item.st_dev, item.st_ino, item.st_size):
            raise ValueError("Android installer artifact changed during hash")
    return digest.hexdigest()


def _private_file(path: Path, limit: int) -> bytes:
    if os.name != "posix":
        raise ValueError("Android installer private evidence requires POSIX file APIs")
    parent = path.parent.lstat()
    item = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or
            stat.S_IMODE(parent.st_mode) != 0o700 or not stat.S_ISREG(item.st_mode) or
            item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o600 or
            item.st_nlink != 1 or item.st_size > limit):
        raise ValueError("Android installer private evidence is unsafe")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (item.st_dev, item.st_ino, item.st_size):
            raise ValueError("Android installer evidence changed before read")
        data = source.read(limit + 1)
        closing = os.fstat(source.fileno())
        if (closing.st_dev, closing.st_ino, closing.st_size) != (item.st_dev, item.st_ino, item.st_size):
            raise ValueError("Android installer evidence changed during read")
    if len(data) != item.st_size:
        raise ValueError("Android installer evidence length changed")
    return data


def _write_private(path: Path, value: dict[str, Any]) -> None:
    if os.name != "posix":
        raise ValueError("Android installer private evidence requires POSIX file APIs")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _artifact(root: Path, artifact_id: str) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    from agent_tools import android_package_install, native_artifact_registry
    if not isinstance(artifact_id, str) or not _ARTIFACT.fullmatch(artifact_id):
        raise ValueError("Android installer requires exact artifact IDs")
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    item = verified.get("artifact") if isinstance(verified, dict) else None
    location = verified.get("location") if isinstance(verified, dict) else None
    if (verified.get("verification") != "verified" or not isinstance(item, dict) or
            not isinstance(location, dict) or item.get("platform") != "android" or
            item.get("artifactKind") not in {"apk", "native-fixture-apk"} or
            item.get("sha256") != artifact_id[7:] or not isinstance(location.get("localPath"), str)):
        raise ValueError("Android installer artifact is not verified")
    path = Path(location["localPath"])
    if _hash(path) != artifact_id[7:]:
        raise ValueError("Android installer artifact bytes changed")
    package = android_package_install._inspect_apk(root, path)
    if (package.get("package") != _PACKAGE or package.get("abi") != "x86_64" or
            package.get("debuggable") is not False):
        raise ValueError("Android installer APK is not a nondebuggable x86_64 product")
    return item, path, package


def admit_pair(root: Path | str, source_sha: str, base_artifact_id: str,
               target_artifact_id: str, installed_base_sha256: str) -> dict[str, Any]:
    """Prove a fixed 2.2.0 to 2.2.1 update against actual installed bytes."""
    root = Path(root)
    from agent_tools import android_package_install
    if (not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or
            not isinstance(installed_base_sha256, str) or not _SHA.fullmatch(installed_base_sha256)):
        raise ValueError("Android installer source or installed digest is invalid")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    if head != source_sha:
        raise ValueError("Android installer target source differs from checkout")
    base, base_path, old = _artifact(root, base_artifact_id)
    target, target_path, new = _artifact(root, target_artifact_id)
    if (base.get("sha256") != installed_base_sha256 or
            old.get("version") != "2.2.0" or old.get("code") != 16800 or
            new.get("version") != "2.2.1" or new.get("code") != 16820 or
            android_package_install._version_identity(old) >= android_package_install._version_identity(new) or
            old.get("signerSha256") != new.get("signerSha256") or
            target.get("sourceSha") != source_sha):
        raise ValueError("Android installer target is not an exact compatible version increase")
    return {"sourceSha": source_sha, "baseArtifactId": base_artifact_id,
            "baseSha256": base["sha256"], "basePath": str(base_path),
            "baseVersion": old["version"], "baseCode": old["code"],
            "targetArtifactId": target_artifact_id, "targetSha256": target["sha256"],
            "targetPath": str(target_path), "targetVersion": new["version"],
            "targetCode": new["code"], "signerSha256": new["signerSha256"]}


def verify_staged_pair(pair: dict[str, Any], base_path: Path | str, target_path: Path | str) -> None:
    """The remote driver checks the exact bytes admitted by the local registry."""
    if (not isinstance(pair, dict) or pair.get("baseVersion") != "2.2.0" or
            pair.get("baseCode") != 16800 or pair.get("targetVersion") != "2.2.1" or
            pair.get("targetCode") != 16820 or
            not isinstance(pair.get("sourceSha"), str) or not re.fullmatch(r"[0-9a-f]{40}", pair["sourceSha"]) or
            not isinstance(pair.get("signerSha256"), str) or not _SHA.fullmatch(pair["signerSha256"]) or
            pair.get("baseArtifactId") != "sha256-" + str(pair.get("baseSha256")) or
            pair.get("targetArtifactId") != "sha256-" + str(pair.get("targetSha256"))):
        raise ValueError("Android installer staged pair identity changed")
    if _hash(Path(base_path)) != pair["baseSha256"] or _hash(Path(target_path)) != pair["targetSha256"]:
        raise ValueError("Android installer staged APK bytes changed")


def create_intent(root: Path | str, output: Path | str, correlation_id: str,
                  pair: dict[str, Any], *, host: str, device: str,
                  backup_correlation_id: str, inspect_correlation_id: str,
                  expected_avd: str, expected_api: int, expected_owner: str,
                  expected_revision: int, backup_path: Path | str, backup_sha256: str,
                  expected_terminal: str) -> dict[str, Any]:
    """Write one immutable plan before fixture setup or a public update action."""
    output = Path(output)
    from agent_tools import android_admission_readback, android_public_inspect
    backup_path = Path(backup_path)
    if (not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id) or
            not isinstance(backup_correlation_id, str) or not _UUID.fullmatch(backup_correlation_id) or
            not isinstance(inspect_correlation_id, str) or not _UUID.fullmatch(inspect_correlation_id) or
            not isinstance(host, str) or not host or not isinstance(device, str) or not device or
            expected_api not in (29, 35) or type(expected_api) is not int or
            not isinstance(expected_avd, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", expected_avd) or
            not isinstance(expected_owner, str) or not expected_owner or
            type(expected_revision) is not int or expected_revision < 0 or
            expected_terminal not in {"installed", "cancelled"} or
            not isinstance(backup_sha256, str) or not _SHA.fullmatch(backup_sha256)):
        raise ValueError("Android installer intent identity is invalid")
    if not output.is_absolute() or not backup_path.is_absolute() or output.exists():
        raise ValueError("Android installer output must be a new absolute directory")
    if not isinstance(pair, dict):
        raise ValueError("Android installer target pair is invalid")
    try:
        fresh_pair = admit_pair(root, pair["sourceSha"], pair["baseArtifactId"],
                                pair["targetArtifactId"], pair["baseSha256"])
    except (KeyError, TypeError) as error:
        raise ValueError("Android installer target pair is incomplete") from error
    if fresh_pair != pair:
        raise ValueError("Android installer target pair changed")
    observed = android_admission_readback.readback_status(root, host, device, backup_correlation_id)
    opening = android_admission_readback.async_collect(root, backup_correlation_id)
    state = observed.get("result", {})
    result = opening.get("result", {})
    guard, package, backup, identity = (result.get(key, {}) for key in ("guard", "package", "backup", "device"))
    if (observed.get("ok") is not True or state.get("stage") != "backup_present" or
            state.get("deviceIdentity") is not True or state.get("controllerId") != expected_owner or
            state.get("configurationRevision") != expected_revision or
            state.get("backup", {}).get("sha256") != backup_sha256 or
            state.get("backup", {}).get("formatValid") is not True or
            opening.get("ok") is not True or opening.get("state") != "complete" or
            package.get("baseSha256") != pair["baseSha256"] or
            guard.get("controllerId") != expected_owner or guard.get("configurationRevision") != expected_revision or
            backup.get("sha256") != backup_sha256 or backup.get("path") != str(backup_path) or
            backup.get("type") != "vpn_control_routing_rules" or backup.get("version") != 7 or
            backup.get("rulesValid") is not True or
            type(backup.get("size")) is not int or not 0 < backup["size"] <= 67_108_864 or
            state.get("backup", {}).get("size") != backup["size"] or
            identity.get("uid") != "2000" or identity.get("avd") != expected_avd or
            identity.get("api") != expected_api):
        raise ValueError("Android installer opening readback changed")
    public = android_public_inspect.inspect(root, host, device, inspect_correlation_id,
                                            pair["baseSha256"], expected_owner, expected_revision)
    public_result = public.get("result", {})
    if (public.get("ok") is not True or public.get("outcome") != "admitted" or
            public_result.get("packageSha256") != pair["baseSha256"] or
            public_result.get("controllerId") != expected_owner or
            public_result.get("configurationRevision") != expected_revision or
            public_result.get("device", {}).get("uid") != "2000" or
            public_result.get("device", {}).get("avd") != expected_avd or
            public_result.get("device", {}).get("api") != expected_api or
            public_result.get("runtime", {}).get("running") is not False or
            public_result.get("runtime", {}).get("observation") != "stopped" or
            type(public_result.get("operationCount")) is not int):
        raise ValueError("Android installer public owner or runtime changed")
    parent = output.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or
            stat.S_IMODE(parent.st_mode) != 0o700):
        raise ValueError("Android installer intent parent is not private")
    output.mkdir(mode=0o700)
    intent = {"schema": 1, "correlationId": correlation_id, "pair": pair,
              "host": host, "device": device,
              "backupCorrelationId": backup_correlation_id,
              "inspectCorrelationId": inspect_correlation_id,
              "expectedAvd": expected_avd, "expectedApi": expected_api,
              "expectedOwner": expected_owner, "expectedRevision": expected_revision,
              "backupPath": str(backup_path), "backupSha256": backup_sha256,
              "backupSize": backup["size"], "expectedTerminal": expected_terminal,
              "replayAllowed": False}
    _write_private(output / "intent.json", intent)
    return {"ok": True, "state": "prepared", "correlationId": correlation_id,
            "intentPath": str(output / "intent.json"), "replayAllowed": False}


def load_intent(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    value = json.loads(_private_file(path, 8192))
    if (not isinstance(value, dict) or value.get("schema") != 1 or
            not isinstance(value.get("correlationId"), str) or not _UUID.fullmatch(value["correlationId"]) or
            value.get("replayAllowed") is not False):
        raise ValueError("Android installer intent is invalid")
    return value


def status(output: Path | str, correlation_id: str) -> dict[str, Any]:
    """Read bounded private session evidence without re-submitting an update."""
    output = Path(output)
    try:
        intent = load_intent(output / "intent.json")
        if intent["correlationId"] != correlation_id:
            raise ValueError("correlation_changed")
        marker_path = output / "run-started.json"
        marker_present = marker_path.exists()
        if marker_present:
            marker = json.loads(_private_file(marker_path, 1024))
            if marker != {"correlationId": correlation_id, "state": "may_have_started"}:
                raise ValueError("run_marker_changed")
        checkpoint = output / "probe.json"
        if not checkpoint.exists():
            if marker_present:
                return {"ok": False, "state": "unknown", "reason": "runner_may_have_started",
                        "correlationId": correlation_id, "replayAllowed": False}
            return {"ok": True, "state": "prepared", "correlationId": correlation_id,
                    "replayAllowed": False}
        if not marker_present:
            raise ValueError("checkpoint_without_run_marker")
        probe = json.loads(_private_file(checkpoint, _MAX_RECEIPT))
        lifecycle = probe.get("callbackReceipt", {}).get("installerLifecycle")
        if not isinstance(lifecycle, dict) or not isinstance(lifecycle.get("operationId"), str):
            raise ValueError("checkpoint_invalid")
        terminal_path = output / "lifecycle-receipt.json"
        if not terminal_path.exists():
            return {"ok": True, "state": "submitted", "correlationId": correlation_id,
                    "operationId": lifecycle["operationId"], "replayAllowed": False}
        receipt = json.loads(_private_file(terminal_path, _MAX_RECEIPT))
        handoff_path = output / "handoff.json"
        handoff = json.loads(_private_file(handoff_path, _MAX_RECEIPT)) if handoff_path.exists() else None
        return _terminal(intent, probe, receipt, handoff)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"ok": False, "state": "unknown", "correlationId": correlation_id,
                "replayAllowed": False}


def _terminal(intent: dict[str, Any], checkpoint: dict[str, Any], receipt: dict[str, Any],
              handoff: dict[str, Any] | None = None) -> dict[str, Any]:
    correlation_id = intent["correlationId"]
    lifecycle = receipt.get("probe", {}) if isinstance(receipt, dict) else None
    if not isinstance(lifecycle, dict):
        raise ValueError("terminal_lifecycle_missing")
    original = checkpoint.get("callbackReceipt", {}).get("installerLifecycle", {})
    accepted = original.get("interactiveAccepted", {}) if isinstance(original, dict) else None
    response = accepted.get("response", {}) if isinstance(accepted, dict) else None
    if (not isinstance(response, dict) or accepted.get("exit") != 0 or
            response.get("ok") is not True or response.get("code") != "ACCEPTED" or
            response.get("final") is not False or response.get("operationId") != lifecycle.get("operationId") or
            lifecycle.get("operationId") != original.get("operationId") or
            response.get("controllerId") != intent["expectedOwner"] or
            response.get("configurationRevision") != intent["expectedRevision"]):
        raise ValueError("original_submission_not_bound")
    if lifecycle.get("acceptance") != "terminal-confirmed" or lifecycle.get("targetSha256") != intent["pair"]["targetSha256"]:
        raise ValueError("terminal_not_confirmed")
    operation = lifecycle.get("operationId")
    original_operation = lifecycle.get("originalOperation", {})
    identity = original_operation.get("identity", {}) if isinstance(original_operation, dict) else None
    if (not isinstance(operation, str) or not operation or not isinstance(identity, dict) or
            identity.get("operationId") != operation or
            identity.get("version") != intent["pair"]["targetVersion"] or
            identity.get("targetSha256") != intent["pair"]["targetSha256"] or
            not isinstance(identity.get("receiptId"), str) or not identity["receiptId"] or
            type(identity.get("sessionId")) is not int):
        raise ValueError("terminal_identity_changed")
    if handoff is not None:
        handed = handoff.get("identity") if isinstance(handoff, dict) else None
        original_handoff = handoff.get("originalOperation") if isinstance(handoff, dict) else None
        if (not isinstance(handed, dict) or handed != identity or
                not isinstance(original_handoff, dict) or
                original_handoff.get("response") != response or
                handoff.get("targetSha256") != intent["pair"]["targetSha256"] or
                handoff.get("targetVersion") != intent["pair"]["targetVersion"] or
                handoff.get("targetCode") != intent["pair"]["targetCode"]):
            raise ValueError("historical_handoff_identity_changed")
    elif intent["expectedTerminal"] == "installed":
        raise ValueError("installed_handoff_missing")
    if (lifecycle.get("terminalExpectation") != intent["expectedTerminal"] or
            receipt.get("installerIntent") != {"correlationId": correlation_id,
                "sourceSha": intent["pair"]["sourceSha"],
                "targetArtifactId": intent["pair"]["targetArtifactId"],
                "backupSha256": intent["backupSha256"]} or
            receipt.get("frozenBaseSha256") != intent["pair"]["baseSha256"] or
            receipt.get("targetInstall") is not True or
            not isinstance(receipt.get("baseline"), dict) or
            receipt["baseline"].get("controllerId") != intent["expectedOwner"] or
            receipt["baseline"].get("installedBaseSha256") != intent["pair"]["baseSha256"]):
        raise ValueError("terminal_opening_admission_not_bound")
    if intent["expectedTerminal"] == "installed":
        if lifecycle.get("installedBaseSha256") != intent["pair"]["targetSha256"]:
            raise ValueError("target_bytes_not_installed")
    terminal_response = lifecycle.get("reconciliation", {}).get("terminal", {}).get("response")
    if not isinstance(terminal_response, dict):
        terminal_response = original_operation.get("status", {}).get("response") if isinstance(original_operation, dict) else None
    data = terminal_response.get("data") if isinstance(terminal_response, dict) else None
    observed = data.get("installReceipt") if isinstance(data, dict) and isinstance(data.get("installReceipt"), dict) else data
    terminal_owner = terminal_response.get("controllerId") if isinstance(terminal_response, dict) else None
    terminal_revision = terminal_response.get("configurationRevision") if isinstance(terminal_response, dict) else None
    if (not isinstance(observed, dict) or observed.get("installReceiptId") != identity["receiptId"] or
            observed.get("installSessionId") != identity["sessionId"] or
            observed.get("installPhase") != intent["expectedTerminal"] or
            observed.get("installed") is not (intent["expectedTerminal"] == "installed") or
            not isinstance(terminal_owner, str) or not terminal_owner or
            type(terminal_revision) is not int or terminal_revision < 0):
        raise ValueError("terminal_session_receipt_not_bound")
    if (intent["expectedTerminal"] == "cancelled" and
            (terminal_owner != intent["expectedOwner"] or
             terminal_revision != intent["expectedRevision"])):
        raise ValueError("cancelled_owner_changed")
    if receipt.get("cleanupFailures"):
        raise ValueError("fixture_cleanup_uncertain")
    return {"ok": True, "state": "complete", "correlationId": correlation_id,
            "terminal": intent["expectedTerminal"], "operationId": operation,
            "receiptId": identity["receiptId"], "sessionId": identity["sessionId"],
            "terminalOwner": terminal_owner, "terminalRevision": terminal_revision,
            "replayAllowed": False}


def collect(output: Path | str, correlation_id: str) -> dict[str, Any]:
    """Return only a bound terminal; a missing/unknown result never permits replay."""
    result = status(output, correlation_id)
    return result if result.get("state") == "complete" else {**result, "ok": False}
