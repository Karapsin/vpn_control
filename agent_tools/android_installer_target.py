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
_VERSION = re.compile(r"[1-9][0-9]?\.(?:0|[1-9][0-9]?)\.(?:0|[1-9][0-9]?)\Z")
_PAIR_FIELDS = {"sourceSha", "baseArtifactId", "baseSha256", "basePath", "baseVersion", "baseCode",
                "targetArtifactId", "targetSha256", "targetPath", "targetVersion", "targetCode",
                "signerSha256"}


def _product_version(version: Any, code: Any) -> tuple[int, int, int]:
    """Validate the canonical product version and its non-displayed code."""
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None or type(code) is not int:
        raise ValueError("Android installer product version identity is invalid")
    values = tuple(int(part) for part in version.split("."))
    if any(part > 19 for part in values) or code != ((values[0] * 20 + values[1]) * 20 + values[2]) * 20:
        raise ValueError("Android installer product version code is invalid")
    return values


def _pair_identity(pair: Any) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    """Keep the immutable pair schema while allowing any canonical increase."""
    if not isinstance(pair, dict) or set(pair) != _PAIR_FIELDS:
        raise ValueError("Android installer staged pair identity changed")
    if (not isinstance(pair["sourceSha"], str) or not re.fullmatch(r"[0-9a-f]{40}", pair["sourceSha"]) or
            not isinstance(pair["baseSha256"], str) or _SHA.fullmatch(pair["baseSha256"]) is None or
            not isinstance(pair["targetSha256"], str) or _SHA.fullmatch(pair["targetSha256"]) is None or
            pair["baseArtifactId"] != "sha256-" + pair["baseSha256"] or
            pair["targetArtifactId"] != "sha256-" + pair["targetSha256"] or
            not isinstance(pair["signerSha256"], str) or _SHA.fullmatch(pair["signerSha256"]) is None or
            not all(isinstance(pair[name], str) and pair[name]
                    for name in ("basePath", "targetPath"))):
        raise ValueError("Android installer staged pair identity changed")
    base = _product_version(pair["baseVersion"], pair["baseCode"])
    target = _product_version(pair["targetVersion"], pair["targetCode"])
    if base >= target:
        raise ValueError("Android installer staged pair is not an increase")
    return base, target


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
    """Prove one canonical, source-bound Android product-version increase."""
    root = Path(root)
    if (not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha) or
            not isinstance(installed_base_sha256, str) or not _SHA.fullmatch(installed_base_sha256)):
        raise ValueError("Android installer source or installed digest is invalid")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    if head != source_sha:
        raise ValueError("Android installer target source differs from checkout")
    base, base_path, old = _artifact(root, base_artifact_id)
    target, target_path, new = _artifact(root, target_artifact_id)
    old_version = _product_version(old.get("version"), old.get("code"))
    new_version = _product_version(new.get("version"), new.get("code"))
    if (base.get("sha256") != installed_base_sha256 or old_version >= new_version or
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
    _pair_identity(pair)
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
        return _terminal(intent, probe, receipt, handoff, intent_path=output / "intent.json")
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"ok": False, "state": "unknown", "correlationId": correlation_id,
                "replayAllowed": False}


def component_action_binding(intent_path: Path | str) -> dict[str, Any]:
    """Reopen the original intent and its separate fixed component action epoch.

    Root/unroot and force-stop can create a new public owner. That owner belongs
    to the durable action admission; it never replaces the immutable baseline.
    """
    from . import android_installer_component_bundle as component
    path = Path(intent_path)
    raw, pin = component._read(path, True)
    intent = load_intent(path)
    action_path = path.parent / "component-guard-action-admission.json"
    action_raw, action_pin = component._read(action_path, True)
    envelope = json.loads(action_raw)
    action = envelope.get("record")
    same = lambda a, b: component._raw(a) == component._raw(b)
    binding = {"correlationId": intent["correlationId"], "sourceSha": intent["pair"]["sourceSha"],
        "targetArtifactId": intent["pair"]["targetArtifactId"],
        "intentCanonicalSha256": hashlib.sha256(json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    keys = {"originalIntentPin", "setupFacts", "actionFacts", "owner", "revision", "transport", "sameCampaignAndLease", "reservation"}
    if (path.name != "intent.json" or json.loads(raw) != intent or type(envelope) is not dict or
            envelope.get("kind") != "android-installer-component-current-guard" or
            type(envelope.get("schema")) is not int or envelope["schema"] != 1 or
            not same(envelope.get("binding"), binding) or type(action) is not dict or set(action) != keys or
            not same(action["originalIntentPin"], pin) or type(action["owner"]) is not str or
            _UUID.fullmatch(action["owner"]) is None or type(action["revision"]) is not int or
            action["revision"] != intent["expectedRevision"] or
            type(action["reservation"]) is not dict or not action["reservation"]):
        raise ValueError("component_action_admission_changed")
    lease_path = path.parent.parent / ("android-native-device-" + intent["device"] + ".lease")
    lease_raw, lease_pin = component._read(lease_path, True)
    lease_value = {"owner": "android-installer", "host": intent["host"], "device": intent["device"], "correlationId": intent["correlationId"]}
    expected_lease = {"path": str(lease_path), "pin": lease_pin, "value": lease_value}
    if not same(json.loads(lease_raw), lease_value) or not same(action["sameCampaignAndLease"], expected_lease):
        raise ValueError("component_action_lease_changed")
    admission_raw, admission_pin = component._read(path.parent / "component-guard-current-admission.json", True)
    admission = json.loads(admission_raw)
    original = admission.get("record", {})
    if (not same(admission.get("binding"), binding) or original.get("owner") != intent["expectedOwner"] or
            type(original.get("revision")) is not int or original["revision"] != intent["expectedRevision"] or
            not same(original.get("intentPin"), pin) or not same(original.get("lease"), expected_lease) or
            not same(original.get("facts"), action["setupFacts"])):
        raise ValueError("component_action_original_admission_changed")
    accepted_path = path.parent / "component-guard-accepted-operation.json"
    accepted_raw, accepted_pin = component._read(accepted_path, True)
    accepted = json.loads(accepted_raw)
    captured = accepted.get("record", {})
    if (not same(accepted.get("binding"), binding) or
            captured.get("owner") != action["owner"] or type(captured.get("revision")) is not int or
            captured["revision"] != action["revision"] or
            not same(captured.get("actionAdmission"), {"path": str(action_path), "pin": action_pin}) or
            type(captured.get("operationId")) is not str or _UUID.fullmatch(captured["operationId"]) is None):
        raise ValueError("component_action_accepted_lineage_changed")
    reply_pin = captured.get("rawReplyPin")
    if (type(reply_pin) is not dict or set(reply_pin) != {"path", "snapshot", "sha256"} or
            type(reply_pin["path"]) is not str):
        raise ValueError("component_action_raw_capture_changed")
    reply_path = Path(reply_pin["path"])
    if reply_path.parent != path.parent or re.fullmatch(r"component-cli-[0-9]{5}\.json", reply_path.name) is None:
        raise ValueError("component_action_raw_capture_changed")
    reply_raw, reply_source_pin = component._read(reply_path, True)
    # Frozen availability snapshot order: dev,ino,size,mtime,ctime,mode,uid,gid,nlink.
    generation = reply_source_pin["generation"]
    availability_pin = [generation[index] for index in (0,1,6,7,8,2,3,4,5)]
    reply_record = json.loads(reply_raw).get("record", {})
    if (not same(reply_pin["snapshot"], availability_pin) or reply_pin["sha256"] != reply_source_pin["sha256"] or
            type(reply_record) is not dict or reply_record.get("phase") != "install-interactive" or
            reply_record.get("words") != ["updates", "install"] or reply_record.get("owner") != action["owner"] or
            type(reply_record.get("revision")) is not int or reply_record["revision"] != action["revision"] or
            type(reply_record.get("returncode")) is not int or reply_record["returncode"] != 0 or
            reply_record.get("stderrRaw") != "" or type(reply_record.get("stdoutRaw")) is not str):
        raise ValueError("component_action_raw_capture_changed")
    response = json.loads(reply_record["stdoutRaw"])
    if (type(response) is not dict or response.get("ok") is not True or response.get("final") is not False or
            response.get("code") != "ACCEPTED" or response.get("operationId") != captured["operationId"] or
            response.get("controllerId") != action["owner"] or type(response.get("configurationRevision")) is not int or
            response["configurationRevision"] != action["revision"]):
        raise ValueError("component_action_raw_capture_changed")
    # Close original held/named evidence again after every body read above.
    for leaf, expected in ((path, (raw, pin)), (action_path, (action_raw, action_pin)),
            (lease_path, (lease_raw, lease_pin)), (path.parent / "component-guard-current-admission.json", (admission_raw, admission_pin)),
            (accepted_path, (accepted_raw, accepted_pin))):
        closing_raw, closing_pin = component._read(leaf, True)
        if closing_raw != expected[0] or not same(closing_pin, expected[1]):
            raise ValueError("component_action_evidence_changed")
    component._evidence_generation_closure({path:pin,action_path:action_pin,lease_path:lease_pin,
        path.parent / "component-guard-current-admission.json":admission_pin,accepted_path:accepted_pin,reply_path:reply_source_pin})
    return {"owner": action["owner"], "revision": action["revision"], "originalOwner": intent["expectedOwner"],
        "originalIntentPin": pin, "actionAdmissionPin": action_pin, "lease": expected_lease,
        "operationId": captured["operationId"], "acceptedOperationPin": accepted_pin, "acceptedResponse": response, "rawReplySourcePin": reply_source_pin}


def _terminal(intent: dict[str, Any], checkpoint: dict[str, Any], receipt: dict[str, Any],
              handoff: dict[str, Any] | None = None, *, intent_path: Path | str | None = None) -> dict[str, Any]:
    correlation_id = intent["correlationId"]
    action = None
    if intent_path is not None:
        path = Path(intent_path)
        if json.dumps(load_intent(path), sort_keys=True) != json.dumps(intent, sort_keys=True):
            raise ValueError("component_terminal_original_intent_changed")
        if (path.parent / "component-guard-action-admission.json").exists():
            action = component_action_binding(path)
    accepted_owner = action["owner"] if action is not None else intent["expectedOwner"]
    accepted_revision = action["revision"] if action is not None else intent["expectedRevision"]
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
            response.get("controllerId") != accepted_owner or
            type(response.get("configurationRevision")) is not int or
            response.get("configurationRevision") != accepted_revision):
        raise ValueError("original_submission_not_bound")
    if action is not None and json.dumps(response, sort_keys=True) != json.dumps(action["acceptedResponse"], sort_keys=True):
        raise ValueError("component_terminal_accepted_capture_changed")
    if lifecycle.get("acceptance") != "terminal-confirmed" or lifecycle.get("targetSha256") != intent["pair"]["targetSha256"]:
        raise ValueError("terminal_not_confirmed")
    operation = lifecycle.get("operationId")
    if action is not None and action["operationId"] != operation:
        raise ValueError("component_terminal_operation_changed")
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
        if (not isinstance(handed, dict) or json.dumps(handed, sort_keys=True) != json.dumps(identity, sort_keys=True) or
                not isinstance(original_handoff, dict) or
                json.dumps(original_handoff.get("response"), sort_keys=True) != json.dumps(response, sort_keys=True) or
                handoff.get("targetSha256") != intent["pair"]["targetSha256"] or
                handoff.get("targetVersion") != intent["pair"]["targetVersion"] or
                (type(handoff.get("targetCode")) not in (int, str) or
                 handoff.get("targetCode") not in (intent["pair"]["targetCode"], str(intent["pair"]["targetCode"])) )):
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
    if action is not None and json.dumps(component_action_binding(intent_path), sort_keys=True) != json.dumps(action, sort_keys=True):
        raise ValueError("component_terminal_action_changed")
    return {"ok": True, "state": "complete", "correlationId": correlation_id,
            "terminal": intent["expectedTerminal"], "operationId": operation,
            "receiptId": identity["receiptId"], "sessionId": identity["sessionId"],
            "terminalOwner": terminal_owner, "terminalRevision": terminal_revision,
            "replayAllowed": False}


def collect(output: Path | str, correlation_id: str) -> dict[str, Any]:
    """Return only a bound terminal; a missing/unknown result never permits replay."""
    result = status(output, correlation_id)
    return result if result.get("state") == "complete" else {**result, "ok": False}
