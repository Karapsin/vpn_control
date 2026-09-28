"""Fail-closed CP117 HTTPS fixture server admission and receipt classification.

This module deliberately has no launcher until a private, fixed certificate/key
and JVM trust descriptor and a reviewed QGA process observer exist. Static ready
files and fixture events cannot by themselves establish a live server.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_msi_public_scenario as public
from . import windows_update_fixture_stage as stage


class WindowsUpdateFixtureServerError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_START = re.compile(r"windows:[1-9][0-9]*\Z")
_GROUP = ".rag_index/windows-update-fixture-server"


def _canonical(value: Any) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    fields = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha",
              "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("host") != "archlinux":
        raise WindowsUpdateFixtureServerError("Server start requires exact CP117 fields.")
    if not all(_canonical(value[name]) for name in ("leaseId", "stageCorrelationId", "serverCorrelationId")):
        raise WindowsUpdateFixtureServerError("Server campaign correlations are invalid.")
    if value["stageCorrelationId"] == value["serverCorrelationId"]:
        raise WindowsUpdateFixtureServerError("Server and stage correlations must differ.")
    for name, pattern in (("sourceSha", _SHA), ("fixtureReceiptArtifactId", _ARTIFACT),
                          ("baseMsiArtifactId", _ARTIFACT), ("targetMsiArtifactId", _ARTIFACT)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise WindowsUpdateFixtureServerError("Invalid server " + name + ".")
    return dict(value)


def _intent_path(root: Path, correlation: str) -> Path:
    return root / _GROUP / (correlation + ".json")


def _read_intent(root: Path, correlation: str) -> dict[str, Any] | None:
    try: fd = os.open(_intent_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError: return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsUpdateFixtureServerError("Server intent is unsafe.")
        try: value = json.load(stream)
        except (TypeError, ValueError) as error:
            raise WindowsUpdateFixtureServerError("Server intent is invalid.") from error
    if (not isinstance(value, dict) or not isinstance(value.get("request"), dict)
            or value["request"].get("serverCorrelationId") != correlation):
        raise WindowsUpdateFixtureServerError("Server intent is invalid.")
    return value


def _private_tls_descriptor(root: Path, request: Mapping[str, str]) -> Mapping[str, Any]:
    """Future private inventory lookup; credentials are never accepted in MCP inputs."""
    raise WindowsUpdateFixtureServerError("FIXTURE_SERVER_CREDENTIAL_DESCRIPTOR_UNAVAILABLE")


def _admit_campaign(root: Path, request: Mapping[str, str]) -> tuple[dict[str, Any], tuple[Any, ...]]:
    pair = public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                              request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    _, _, guest = base._descriptor(root)
    environment, socket, pid, ticks, sid = guest
    if environment != "windows-cp117":
        raise WindowsUpdateFixtureServerError("Owned guest generation changed.")
    staged = stage.status(root, {"correlationId": request["stageCorrelationId"]})
    if (staged.get("state") != "staged-not-server-ready" or staged.get("sourceSha") != request["sourceSha"]
            or staged.get("targetMsiSha256") != pair["targetMsiSha256"]):
        raise WindowsUpdateFixtureServerError("Exact stage is not admitted.")
    observed = lease.inspect(root, request["leaseId"])
    if (observed.get("state") != "active" or observed.get("server") != "stopped"
            or observed.get("role") is not None):
        raise WindowsUpdateFixtureServerError("CP117 campaign is not ready for server start.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = current.get("identity") if isinstance(current, dict) else None
        expected = {"host": "archlinux", "environment": "windows-cp117",
                    "leaseId": request["leaseId"], "operator": "windows-base",
                    "sourceSha": request["sourceSha"],
                    "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": request["baseMsiArtifactId"],
                    "targetMsiArtifactId": request["targetMsiArtifactId"],
                    "socketPath": socket, "qemuPid": pid, "startTicks": ticks}
        if identity != expected:
            raise WindowsUpdateFixtureServerError("CP117 campaign identity changed.")
    finally:
        os.close(lock)
    return pair, (socket, pid, ticks, sid)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed before a guest effect while private TLS/trust admission is absent."""
    root = Path(root).resolve(strict=True); request = _request(value)
    correlation = request["serverCorrelationId"]
    prior = _read_intent(root, correlation)
    if prior is not None:
        if prior.get("request") != request:
            raise WindowsUpdateFixtureServerError("Server correlation binds another request.")
        return {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
    _private_tls_descriptor(root, request)
    _admit_campaign(root, request)
    # A future reviewed launcher must claim lease role server-start, fsync a
    # one-shot intent, then submit only the fixed guest command. Never infer a
    # submission from this validation path.
    raise WindowsUpdateFixtureServerError("FIXTURE_SERVER_LAUNCH_UNAVAILABLE")


def _fixture_manifest(root: Path, request: Mapping[str, str]) -> dict[str, Any]:
    path = public._verified_location(root, request["fixtureReceiptArtifactId"],
                                     "fixture-receipt", request["sourceSha"])
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1024 * 1024:
            raise WindowsUpdateFixtureServerError("Fixture receipt is unsafe.")
        raw = stream.read(1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != request["fixtureReceiptArtifactId"].removeprefix("sha256-"):
        raise WindowsUpdateFixtureServerError("Fixture receipt changed.")
    try: receipt = json.loads(raw)
    except (TypeError, ValueError) as error:
        raise WindowsUpdateFixtureServerError("Fixture receipt is invalid.") from error
    manifest = receipt.get("manifest") if isinstance(receipt, dict) else None
    if not isinstance(manifest, dict):
        raise WindowsUpdateFixtureServerError("Fixture manifest is invalid.")
    return manifest


def _validate_live_ready(ready: Mapping[str, Any], observed: Mapping[str, Any], *,
                         request: Mapping[str, str], pair: Mapping[str, Any],
                         manifest: Mapping[str, Any], descriptor: Mapping[str, Any],
                         guest: tuple[str, int, int, str]) -> dict[str, Any]:
    """Require a fresh kernel/QGA observation; ready.json alone is never proof."""
    socket, qemu_pid, qemu_ticks, sid = guest
    ready_fields = {"port", "serverInstanceId", "serverPid", "serverProcessStartIdentity",
                    "sourceFingerprint", "fixtureReceiptSha256", "manifestSha256",
                    "peerCertificateSha256", "manifest"}
    if not isinstance(ready, Mapping) or set(ready) != ready_fields:
        raise WindowsUpdateFixtureServerError("Server ready receipt shape changed.")
    if (not _canonical(ready["serverInstanceId"]) or type(ready["port"]) is not int
            or not 1 <= ready["port"] <= 65535 or type(ready["serverPid"]) is not int
            or ready["serverPid"] <= 0 or not isinstance(ready["serverProcessStartIdentity"], str)
            or not _WINDOWS_START.fullmatch(ready["serverProcessStartIdentity"])):
        raise WindowsUpdateFixtureServerError("Server ready generation is invalid.")
    body = json.dumps(manifest, separators=(",", ":")).encode()
    if (ready["sourceFingerprint"] != pair["sourceFingerprint"]
            or ready["fixtureReceiptSha256"] != request["fixtureReceiptArtifactId"].removeprefix("sha256-")
            or ready["manifest"] != manifest
            or ready["manifestSha256"] != hashlib.sha256(body).hexdigest()
            or ready["peerCertificateSha256"] != descriptor.get("peerCertificateSha256")):
        raise WindowsUpdateFixtureServerError("Server manifest or certificate binding changed.")
    if type(manifest.get("buildNumber")) is not int or manifest["buildNumber"] <= 0:
        raise WindowsUpdateFixtureServerError("Server manifest build number is invalid.")
    target_assets = [asset for asset in manifest.get("assets", []) if isinstance(asset, dict)
                     and asset.get("platform") == "windows" and asset.get("architecture") == "x86_64"
                     and asset.get("fileName") == "vpn-control-" + pair["targetVersion"] + ".msi"]
    if (len(target_assets) != 1 or target_assets[0].get("sha256") != pair["targetMsiSha256"]
            or target_assets[0].get("sizeBytes") != pair["targetMsiSize"]
            or target_assets[0].get("displayVersion") != pair["targetVersion"]):
        raise WindowsUpdateFixtureServerError("Server manifest target changed.")
    expected_observation = {"qgaSocketPath": socket, "qemuPid": qemu_pid, "qemuStartTicks": qemu_ticks,
        "serverPid": ready["serverPid"], "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
        "serverInstanceId": ready["serverInstanceId"], "originalSid": sid, "sessionId": 1,
        "limited": True, "listenerAddress": "127.0.0.1", "listenerPort": ready["port"],
        "listenerPid": ready["serverPid"], "taskState": "Running",
        "pythonExeSha256": descriptor.get("pythonExeSha256"),
        "launchCommandSha256": descriptor.get("launchCommandSha256"),
        "certificateSha256": descriptor.get("peerCertificateSha256"),
        "privateKeySha256": descriptor.get("privateKeySha256"),
        "trustStoreSha256": descriptor.get("trustStoreSha256")}
    if not isinstance(observed, Mapping) or dict(observed) != expected_observation:
        raise WindowsUpdateFixtureServerError("Live server process observation changed.")
    if any(not isinstance(descriptor.get(key), str) or not _HASH.fullmatch(descriptor[key])
           for key in ("pythonExeSha256", "launchCommandSha256", "peerCertificateSha256", "privateKeySha256", "trustStoreSha256")):
        raise WindowsUpdateFixtureServerError("Private server descriptor is incomplete.")
    return {"state": "live", "serverInstanceId": ready["serverInstanceId"],
            "serverPid": ready["serverPid"], "serverProcessStartIdentity": ready["serverProcessStartIdentity"],
            "manifestSha256": ready["manifestSha256"],
            "peerCertificateSha256": ready["peerCertificateSha256"],
            "targetVersion": pair["targetVersion"], "manifestBuildNumber": manifest.get("buildNumber"),
            "targetMsiSha256": pair["targetMsiSha256"], "targetMsiSize": pair["targetMsiSize"],
            "serverReady": True, "cleanupRequired": True, "replayAllowed": False}


def _validate_probe_event(event: Mapping[str, Any], probe: Mapping[str, Any],
                          live: Mapping[str, Any], *, probe_correlation_id: str,
                          manifest_bytes: int) -> dict[str, Any]:
    if not _canonical(probe_correlation_id) or not isinstance(event, Mapping) or not isinstance(probe, Mapping):
        raise WindowsUpdateFixtureServerError("Probe correlation is invalid.")
    if (set(event) != {"schemaVersion", "correlationId", "serverInstanceId", "connectAccepted",
                       "tlsSucceeded", "exactManifestGet", "manifestSha256", "peerCertificateSha256", "servedBytes"}
            or event["schemaVersion"] != 1 or event["correlationId"] != probe_correlation_id
            or event["serverInstanceId"] != live["serverInstanceId"]
            or event["connectAccepted"] is not True or event["tlsSucceeded"] is not True
            or event["exactManifestGet"] is not True or event["manifestSha256"] != live["manifestSha256"]
            or event["peerCertificateSha256"] != live["peerCertificateSha256"]
            or type(event["servedBytes"]) is not int or event["servedBytes"] != manifest_bytes):
        raise WindowsUpdateFixtureServerError("Fixture probe event is stale or forged.")
    fields = {"correlationId", "manifestSha256", "peerCertificateSha256", "manifestBuildNumber", "availableVersion",
              "assetSha256", "assetSizeBytes"}
    if (set(probe) != fields or probe["correlationId"] != probe_correlation_id
            or probe["manifestSha256"] != live["manifestSha256"]
            or probe["peerCertificateSha256"] != live["peerCertificateSha256"]
            or probe["manifestBuildNumber"] != live["manifestBuildNumber"]
            or probe["availableVersion"] != live["targetVersion"]
            or probe["assetSha256"] != live["targetMsiSha256"]
            or probe["assetSizeBytes"] != live["targetMsiSize"]):
        raise WindowsUpdateFixtureServerError("Public probe disagrees with live fixture.")
    return {"state": "correlated", "probeCorrelationId": probe_correlation_id,
            "serverInstanceId": live["serverInstanceId"],
            "manifestSha256": live["manifestSha256"], "targetMsiSha256": live["targetMsiSha256"],
            "cleanupRequired": True, "replayAllowed": False}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"serverCorrelationId"} or not _canonical(value["serverCorrelationId"]):
        raise WindowsUpdateFixtureServerError("Server status requires exact correlation.")
    root = Path(root).resolve(strict=True); correlation = value["serverCorrelationId"]
    intent = _read_intent(root, correlation)
    if intent is None:
        return {"state": "unknown", "serverCorrelationId": correlation,
                "cleanupRequired": False, "replayAllowed": False}
    # Fixed QGA observation will be added only alongside the reviewed launcher.
    return {"state": "unknown", "serverCorrelationId": correlation,
            "cleanupRequired": True, "replayAllowed": False}


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Retain uncertainty and cleanup need; never synthesize a server verdict."""
    return status(root, value)


def verified_live_receipt(root: Path | str, lease_id: str) -> dict[str, Any]:
    """Internal target/public join point; unavailable until fixed QGA readback exists."""
    if not _canonical(lease_id):
        raise WindowsUpdateFixtureServerError("Server join identity is invalid.")
    # A future observer must discover exactly one private intent for this lease,
    # bind it to the active lease and current QEMU generation, then verify a
    # fresh native process/listener and public probe event before returning it.
    raise WindowsUpdateFixtureServerError("LIVE_FIXTURE_RECEIPT_UNAVAILABLE")
