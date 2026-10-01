"""One-use HTTP transport for the source-bound CP117 update-fixture bundle.

This adapter deliberately owns only delivery of the immutable ``bundle.zip``.
The existing :mod:`windows_update_fixture_stage` module remains the authority
for fixture contents, ACL receipts, campaign role completion, and server
admission.  This prevents the large ZIP from travelling through QGA stdin.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import uuid
from typing import Any, Mapping

from . import windows_msi_base_prepare as base
from . import windows_update_fixture_stage as stage
from . import windows_large_artifact_transfer as large_transfer


class WindowsUpdateFixtureHttpStageError(ValueError):
    pass


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GROUP = ".rag_index/windows-update-fixture-http-stage"
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

# This is a deliberately non-general recovery admission for the one historical
# attempt which advanced the local transfer phase then raised before
# ``subprocess.run`` could be reached.  It is not a facility for importing
# arbitrary console output as a native receipt.
_E66_CORRELATION = "e66d02a7-a40c-41e0-8f8b-674624f98a54"
_LEGACY_DOWNLOAD_CORRELATIONS = frozenset({"07708dc7-6884-40a5-9a78-c75dbb391dbd"})
_E66_EVIDENCE = (".runtime/parity-evidence/windows-cp117-current/target-update/"
                 "e66-stage-start-transcript.json")
_E66_INPUT = (".runtime/parity-evidence/windows-cp117-current/target-update/"
              "fixture-http-stage-start-2.json")
_E66_INPUT_SHA256 = "5d2c185fa27a4d6394146180a9e16d67dd43065279be4ad7eedeb54bf304a583"
_E66_TASK = "01a0e7a7-0fd0-73d2-b2fa-8ec84c377099"
_E66_TURN = "01a0eeaa-490f-71b3-ae09-a44ba196ffa7"
_E66_ITEM = "exec-fdf15cf3-2a96-4fb7-b2c3-a21537dfc4f0"
_E66_LEASE = "94238e9e-4296-4a70-9b0a-0762f82aaf07"
_E66_COMMAND = ("/bin/zsh -lc './agent_tools/mcp_tool.sh vm-workflow windows-update-fixture-http-transfer "
                "--inputs-file .runtime/parity-evidence/windows-cp117-current/target-update/"
                "fixture-http-stage-start-2.json'")
_E66_FAILURE = {"kind": "base-remote-source-open",
                "fingerprint": "c6c553f6e19d719427187d9db49f0d584fe7345346b7337e9d879d8f42c02a90"}
_E66_TRANSCRIPT_SHA256 = "13606c02289ee91302a3a2eac03308baad889273b7624126c88c653d85c3192d"


def _private_file(path: Path, maximum: int, modes: tuple[int, ...] = (0o600,)) -> bytes:
    """Read one owned evidence input without following a caller-controlled link."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise WindowsUpdateFixtureHttpStageError("Historical evidence is unavailable.") from error
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) not in modes or not 0 < info.st_size <= maximum):
            raise WindowsUpdateFixtureHttpStageError("Historical evidence is unsafe.")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise WindowsUpdateFixtureHttpStageError("Historical evidence is too large.")
    return raw


def _e66_transcript(root: Path) -> dict[str, Any]:
    """Validate the exported Codex item before it can become a local receipt.

    The export is intentionally a bounded, exact projection of a single app
    item.  The adapter never accepts a task, command, stack trace, or path from
    workflow input, so this cannot turn a generic failed command into a replay
    waiver.
    """
    input_path = root / _E66_INPUT
    # The original CLI input is a hash-bound, owner-owned read-only artifact.
    # Unlike the app transcript it contains no private output and existing MCP
    # evidence uses 0644, so accept that established immutable-input mode.
    input_raw = _private_file(input_path, 1024, (0o600, 0o644))
    if hashlib.sha256(input_raw).hexdigest() != _E66_INPUT_SHA256:
        raise WindowsUpdateFixtureHttpStageError("Historical input changed.")
    try:
        frozen_input = json.loads(input_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsUpdateFixtureHttpStageError("Historical input is invalid.") from error
    if frozen_input != {"correlationId": _E66_CORRELATION, "phase": "stage-start"}:
        raise WindowsUpdateFixtureHttpStageError("Historical input does not bind the stage.")
    raw = _private_file(root / _E66_EVIDENCE, 65536)
    transcript_sha256 = hashlib.sha256(raw).hexdigest()
    if transcript_sha256 != _E66_TRANSCRIPT_SHA256:
        raise WindowsUpdateFixtureHttpStageError("Historical transcript bytes changed.")
    try:
        evidence = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsUpdateFixtureHttpStageError("Historical transcript is invalid.") from error
    if (not isinstance(evidence, dict)
            or set(evidence) != {"taskId", "turnId", "itemId", "command", "exitCode", "output"}
            or evidence.get("taskId") != _E66_TASK or evidence.get("turnId") != _E66_TURN
            or evidence.get("itemId") != _E66_ITEM or evidence.get("command") != _E66_COMMAND
            or evidence.get("exitCode") != 1 or not isinstance(evidence.get("output"), str)):
        raise WindowsUpdateFixtureHttpStageError("Historical transcript does not identify the failed command.")
    output = evidence["output"]
    # The source-open frame is before the only subprocess invocation in
    # base._remote.  Require the complete causal chain rather than matching a
    # free-standing exception string from an unrelated command.
    required = (
        "agent_tools/windows_update_fixture_http_stage.py",
        "in stage_start",
        "base._remote(",
        "agent_tools/windows_msi_base_prepare.py",
        "in _remote",
        'with source.open("rb") as stream:',
        "AttributeError: '_io.BufferedReader' object has no attribute 'open'",
    )
    if any(token not in output for token in required):
        raise WindowsUpdateFixtureHttpStageError("Historical transcript does not prove pre-dispatch failure.")
    return {"transcriptSha256": transcript_sha256,
            "commandSha256": hashlib.sha256(_E66_COMMAND.encode()).hexdigest(),
            "inputSha256": _E66_INPUT_SHA256}


def _e66_import_receipt(root: Path, transcript: Mapping[str, str]) -> bool:
    """Fsync one immutable public-safe binding before a later close may run."""
    directory = _directory(root, True)
    assert directory is not None
    receipt = {"correlationId": _E66_CORRELATION, "failure": _E66_FAILURE,
               "inputSha256": transcript["inputSha256"],
               "commandSha256": transcript["commandSha256"],
               "transcriptSha256": transcript["transcriptSha256"]}
    if not _write_once(directory / (_E66_CORRELATION + ".pre-effect-import.json"), receipt):
        return False
    # File fsync alone does not make its directory entry durable across a
    # crash.  Do this before reporting an import that can admit a later close.
    return _fsync_e66_import_directory(root)


def _fsync_e66_import_directory(root: Path) -> bool:
    """Durably publish an import receipt name after its file was fsynced."""
    try:
        directory = _directory(root, False)
        if directory is None:
            return False
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        return False
    return True


def _e66_imported(root: Path, transcript: Mapping[str, str]) -> bool:
    """Check the immutable import binding without accepting a partial receipt."""
    try:
        raw = _private_file(_directory(root, False) / (_E66_CORRELATION + ".pre-effect-import.json"), 2048)  # type: ignore[operator]
        receipt = json.loads(raw)
    except (OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError, WindowsUpdateFixtureHttpStageError):
        return False
    return receipt == {"correlationId": _E66_CORRELATION, "failure": _E66_FAILURE,
                       "inputSha256": transcript["inputSha256"],
                       "commandSha256": transcript["commandSha256"],
                       "transcriptSha256": transcript["transcriptSha256"]}


def _large_binding(record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> dict[str, Any]:
    environment, socket, pid, ticks, sid = descriptor
    request = record["request"]
    return {"correlationId": request["correlationId"], "sourceSha": request["sourceSha"],
            "artifactId": "sha256-" + record["bundleSha256"], "kind": "fixture-zip",
            "environment": environment, "socketPath": socket, "qemuPid": pid,
            "startTicks": ticks, "expectedSid": sid}


def _large_advance(root: Path, record: Mapping[str, Any], descriptor: tuple[Any, ...], phase: str) -> bool:
    """Persist a fixture phase before its effect; failures block dispatch."""
    try:
        result = large_transfer.advance(root, record["request"]["correlationId"], phase)
        return result.get("state") == phase
    except (OSError, ValueError, KeyError, large_transfer.WindowsLargeArtifactTransferError):
        return False


def _authority_binding(record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> dict[str, Any]:
    """The exact receipt schema consumed by windows_update_fixture_stage.status."""
    _environment, socket, pid, ticks, sid = descriptor
    request = record["request"]
    return {"correlationId": request["correlationId"], "socketPath": socket, "pid": pid,
            "startTicks": ticks, "leaseId": record["leaseId"], "sourceSha": request["sourceSha"],
            "sourceFingerprint": record["sourceFingerprint"], "bundleSha256": record["bundleSha256"],
            "expectedSid": sid, "fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"],
            "targetMsiArtifactId": request["targetMsiArtifactId"]}


def _canonical(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID.fullmatch(value)) and str(uuid.UUID(value)) == value


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    """The normal fixture-stage request is the sole public request shape."""
    return stage._request(value)


def _directory(root: Path, create: bool) -> Path | None:
    path = root / _GROUP
    if not path.exists() and not path.is_symlink():
        if not create:
            return None
        path.mkdir(mode=0o700, parents=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage journal is unsafe.")
    return path


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    if not _canonical(correlation):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage correlation is invalid.")
    directory = _directory(root, False)
    if directory is None:
        return None
    try:
        fd = os.open(directory / (correlation + ".json"), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise WindowsUpdateFixtureHttpStageError("HTTP stage intent is unsafe.")
        value = json.load(stream)
    if (not isinstance(value, dict) or set(value) != {"request", "leaseId", "bundlePath", "bundleSha256",
                                                       "bundleSize", "routeNonce", "sourceFingerprint"}
            or not isinstance(value["request"], dict) or _request(value["request"])["correlationId"] != correlation
            or not _canonical(value["leaseId"]) or not isinstance(value["bundlePath"], str)
            or not Path(value["bundlePath"]).is_absolute() or not isinstance(value["bundleSize"], int)
            or not 0 < value["bundleSize"] <= 1075838976 or not isinstance(value["bundleSha256"], str)
            or not _HASH.fullmatch(value["bundleSha256"]) or not isinstance(value["routeNonce"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["routeNonce"])
            or not isinstance(value["sourceFingerprint"], str) or not _HASH.fullmatch(value["sourceFingerprint"])):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage intent is invalid.")
    return value


def _write_once(path: Path, value: Mapping[str, Any]) -> bool:
    raw = (json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 16384:
        raise WindowsUpdateFixtureHttpStageError("HTTP stage intent is too large.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return True


def _artifact(path: Path, digest: str, length: int) -> None:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or info.st_size != length):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage bundle is unsafe.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)); actual = hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            actual.update(part)
        after = os.fstat(stream.fileno())
    if (before.st_ino != info.st_ino or after.st_ino != info.st_ino or after.st_size != info.st_size
            or actual.hexdigest() != digest):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage bundle changed.")


def prepare(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Freeze the same ZIP the normal stage would use, without touching CP117."""
    root = Path(root).resolve(strict=True); request = _request(value); corr = request["correlationId"]
    if _read(root, corr) is not None:
        return {**_UNKNOWN, "correlationId": corr}
    pair = stage.public._admit_pair(root, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                    request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    bundle, hashes, size, digest = stage._bundle(root, request, pair)
    try:
        directory = _directory(root, True); assert directory is not None
        config, target, descriptor = base._descriptor(root)
        env, socket, pid, ticks, sid = descriptor
        lease_id = stage._require_cross_route_lease(root, request, config, target, descriptor)
        # Reserve the authoritative existing-stage intent before any host or
        # guest action.  Its ZIP is subsequently the only transport source.
        stage_record = {"request": request, "environment": env, "socketPath": socket, "pid": pid,
                        "startTicks": ticks, "expectedSid": sid, "sourceFingerprint": pair["sourceFingerprint"],
                        "bundleSha256": digest, "bundleSize": size, "fileHashes": hashes,
                        "commandSha256": hashlib.sha256(stage._stage_script(corr, sid, hashes, digest).encode("utf-16le")).hexdigest(),
                        "leaseId": lease_id}
        bundle_path = stage._reserve(root, stage_record, bundle)
        _artifact(bundle_path, digest, size)
        claimed = stage.campaign_lease.claim_role(root, lease_id, "stage", corr,
                                                   base._campaign_remote(config, target))
        if claimed.get("state") != "role-active":
            return {**_UNKNOWN, "correlationId": corr}
        record = {"request": request, "leaseId": lease_id, "bundlePath": str(bundle_path),
                  "bundleSha256": digest, "bundleSize": size, "routeNonce": secrets.token_urlsafe(32),
                  "sourceFingerprint": pair["sourceFingerprint"]}
        mirrored = large_transfer.prepare(root, _large_binding(record, descriptor), bundle_path)
        if mirrored.get("state") != "prepared":
            return {**_UNKNOWN, "correlationId": corr}
        if not _write_once(directory / (corr + ".json"), record):
            return {**_UNKNOWN, "correlationId": corr}
    finally:
        bundle.close()
    return {"state": "prepared", "correlationId": corr, "bundleSha256": digest, "bundleSize": size,
            "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}


def prepare_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify only local, pre-effect admission for a failed fresh prepare.

    This intentionally does not build a ZIP, reserve a stage directory, claim
    a campaign role, contact the fixture host, or invoke QGA.  It returns no
    paths, account names, artifact IDs, or guest details.
    """
    request = _request(value)
    corr = request["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        if _read(root_path, corr) is not None:
            return {**result, "phase": "http-intent-present"}
        if stage._read_intent(root_path, corr) is not None:
            return {**result, "phase": "stage-intent-present"}
        if large_transfer.read(root_path, corr) is not None:
            return {**result, "phase": "shared-intent-present"}
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError, large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "local-journal-unreadable"}
    try:
        pair = stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                         request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if not isinstance(pair, Mapping) or not isinstance(pair.get("sourceFingerprint"), str) or not _HASH.fullmatch(pair["sourceFingerprint"]):
            return {**result, "phase": "source-unadmitted"}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "phase": "source-unadmitted"}
    try:
        config, target, descriptor = base._descriptor(root_path)
        if len(descriptor) != 5:
            return {**result, "phase": "vm-unbound"}
        campaign_dir = root_path / stage.campaign_lease._DIR
        info = campaign_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or campaign_dir.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return {**result, "phase": "campaign-unbound"}
        active = stage.campaign_lease._active(campaign_dir)
        identity = active.get("identity") if isinstance(active, Mapping) else None
        lease_id = identity.get("leaseId") if isinstance(identity, Mapping) else None
        expected = base._campaign_identity({**request, "correlationId": lease_id}, descriptor) if _canonical(lease_id) else None
        if (active is None or active.get("state") != "active" or active.get("role") is not None
                or active.get("server") != "stopped" or active.get("credentials") != "absent"
                or identity != expected):
            return {**result, "phase": "campaign-unbound"}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError,
            stage.WindowsUpdateFixtureStageError):
        return {**result, "phase": "campaign-unbound"}
    return {**result, "phase": "ready-to-reserve"}


def bundle_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Exercise only the real source ZIP constructor for a failed prepare.

    ``_bundle`` is the last source-only operation before the HTTP and stage
    journals are created.  Its temporary stream is always closed; this route
    neither reserves a journal, claims a campaign role, reads VM state, nor
    invokes a remote transport.
    """
    request = _request(value)
    corr = request["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    stream = None
    try:
        root_path = Path(root).resolve(strict=True)
        pair = stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                         request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        stream, hashes, size, digest = stage._bundle(root_path, request, pair)
        if (not isinstance(hashes, Mapping) or type(size) is not int or not 0 < size <= 1075838976
                or not isinstance(digest, str) or not _HASH.fullmatch(digest)):
            return {**result, "phase": "bundle-invalid"}
        return {**result, "phase": "bundle-ready"}
    except (OSError, ValueError, KeyError, TypeError, stage.WindowsUpdateFixtureStageError):
        return {**result, "phase": "bundle-unbuildable"}
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def reserve_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the remaining local admissions before ``stage._reserve`` writes.

    Prior-stage closure confirmation deliberately remains out of this route:
    the production helper contacts the fixture host, while this diagnostic is
    strictly local and only reports that such confirmation is required.
    """
    request = _request(value)
    corr = request["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        # Existing unsafe HTTP state blocks the later mkdir/write before reserve.
        _directory(root_path, False)
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError):
        return {**result, "phase": "http-journal-unsafe"}
    try:
        config, target, descriptor = base._descriptor(root_path)
        if len(descriptor) != 5:
            return {**result, "phase": "vm-unbound"}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {**result, "phase": "vm-unbound"}
    try:
        campaign_dir = root_path / stage.campaign_lease._DIR
        info = campaign_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or campaign_dir.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return {**result, "phase": "campaign-unbound"}
        active = stage.campaign_lease._active(campaign_dir)
        identity = active.get("identity") if isinstance(active, Mapping) else None
        lease_id = identity.get("leaseId") if isinstance(identity, Mapping) else None
        expected = base._campaign_identity({**request, "correlationId": lease_id}, descriptor) if _canonical(lease_id) else None
        if (active is None or active.get("state") != "active" or active.get("role") is not None
                or active.get("server") != "stopped" or active.get("credentials") != "absent" or identity != expected):
            return {**result, "phase": "campaign-unbound"}
    except (OSError, ValueError, KeyError, TypeError, stage.campaign_lease.Cp117LeaseError):
        return {**result, "phase": "campaign-unbound"}
    try:
        stage_dir = root_path / stage._GROUP
        if not stage_dir.exists():
            return {**result, "phase": "reserve-ready-local"}
        info = stage_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stage_dir.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return {**result, "phase": "stage-history-unsafe"}
        for path in stage_dir.iterdir():
            if path.name == ".environment.lock":
                continue
            if path.suffix != ".json":
                continue
            if not _canonical(path.stem):
                return {**result, "phase": "stage-history-unsafe"}
            prior = stage._read_intent(root_path, path.stem)
            if prior is None:
                return {**result, "phase": "stage-history-unsafe"}
            if path.stem == corr:
                return {**result, "phase": "stage-intent-present"}
            return {**result, "phase": "prior-stage-needs-confirmation"}
        return {**result, "phase": "reserve-ready-local"}
    except (OSError, ValueError, KeyError, TypeError, stage.WindowsUpdateFixtureStageError):
        return {**result, "phase": "stage-history-unsafe"}


def prior_stage_confirmation(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only confirmation that earlier stage receipts are remotely closed."""
    request = _request(value)
    corr = request["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        stage_dir = root_path / stage._GROUP
        if not stage_dir.exists():
            return {**result, "phase": "confirmed"}
        info = stage_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stage_dir.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return {**result, "phase": "history-invalid"}
        prior_ids = []
        for path in stage_dir.iterdir():
            if path.name == ".environment.lock" or path.suffix != ".json":
                continue
            if not _canonical(path.stem) or stage._read_intent(root_path, path.stem) is None:
                return {**result, "phase": "history-invalid"}
            if path.stem == corr:
                return {**result, "phase": "history-invalid"}
            prior_ids.append(path.stem)
        if not prior_ids:
            return {**result, "phase": "confirmed"}
        pair = stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                         request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        config, target, descriptor = base._descriptor(root_path)
        lease_id = stage._require_cross_route_lease(root_path, request, config, target, descriptor)
        if not _canonical(lease_id):
            return {**result, "phase": "unknown"}
        # This helper performs only remote campaign status confirmations for
        # prior receipts.  It makes no new directory, campaign, or guest write.
        detail = stage._closed_stage_history_detail(root_path, lease_id)
        if detail in {"history-malformed-name", "history-record-invalid"}:
            return {**result, "phase": "history-invalid"}
        if detail in {"confirmed", "old-closed-missing", "remote-status-mismatch", "history-invalid", "unknown"}:
            return {**result, "phase": detail}
        return {**result, "phase": "unknown"}
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {**result, "phase": "unknown"}


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only local provenance view.  It never creates journals or retries work."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage status requires exact correlationId.")
    corr = value["correlationId"]
    try:
        root_path = Path(root).resolve(strict=True)
        record = _read(root_path, corr)
        if record is None: return {**_UNKNOWN, "correlationId": corr}
        _artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError):
        return {**_UNKNOWN, "correlationId": corr}
    if corr == _E66_CORRELATION:
        # The generic HTTP intent remains prepared after e66's source-open
        # failure.  Do not present it as a reusable prepared transfer when the
        # shared journal has durably closed that exact attempt.
        try:
            # The aborted transfer remains observable after retirement has
            # released the stage role, so admit either its active stage claim
            # or the matching idle campaign record.
            _root, bound, _config, _target = _record(root_path, corr, campaign_mode="stage-or-idle")
            descriptor = base._descriptor(_root)[2]
            transcript = _e66_transcript(_root)
            core = large_transfer.read(_root, corr)
            if (bound.get("leaseId") != _E66_LEASE or not _e66_imported(_root, transcript)
                    or core is None or core.get("binding") != _large_binding(bound, descriptor)
                    or core.get("sha256") != bound.get("bundleSha256") or core.get("length") != bound.get("bundleSize")
                    or core.get("phase") != "aborted" or core.get("dispatchFailure") != _E66_FAILURE
                    or core.get("preEffectClose") != {"reason": "source-not-path", "remoteStage": "absent"}):
                return {**_UNKNOWN, "correlationId": corr}
        except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureHttpStageError,
                stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError,
                stage.campaign_lease.Cp117LeaseError, large_transfer.WindowsLargeArtifactTransferError):
            return {**_UNKNOWN, "correlationId": corr}
        return {"state": "aborted", "correlationId": corr, "bundleSha256": bound["bundleSha256"],
                "bundleSize": bound["bundleSize"], "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    return {"state": "prepared", "correlationId": corr, "bundleSha256": record["bundleSha256"],
            "bundleSize": record["bundleSize"], "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


# The root agent runs this fixed program on the Arch fixture host, passing the
# verified ZIP via stdin.  It is intentionally separate from QGA.
_REMOTE_STAGE = r'''import base64,hashlib,json,os,stat,sys
root,corr,digest,size,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 binding=json.loads(base64.b64decode(encoded,validate=True))
 if (not os.path.isabs(root) or not __import__('re').fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not __import__('re').fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<int(size)<=1075838976):raise ValueError()
 if (not isinstance(binding,dict) or binding.get('correlationId')!=corr or binding.get('bundleSha256')!=digest
  or set(binding)!={'correlationId','socketPath','pid','startTicks','leaseId','sourceSha','sourceFingerprint','bundleSha256','expectedSid','fixtureReceiptArtifactId','baseMsiArtifactId','targetMsiArtifactId'}):raise ValueError()
 group=os.path.join(root,'windows-cp117','windows-update-fixture-http-stage');stage=os.path.join(group,corr)
 authority_group=os.path.join(root,'windows-cp117','windows-update-fixture-stage');authority=os.path.join(authority_group,corr)
 for p in (root,os.path.join(root,'windows-cp117'),group):
  if not os.path.lexists(p):os.mkdir(p,0o700)
  i=os.lstat(p)
  if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 if not os.path.lexists(authority_group):os.mkdir(authority_group,0o700)
 i=os.lstat(authority_group)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 if os.path.lexists(stage):raise ValueError()
 if os.path.lexists(authority):raise ValueError()
 os.mkdir(authority,0o700)
 fd=os.open(os.path.join(authority,'binding.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(binding,separators=(',',':'),sort_keys=True).encode());f.flush();os.fsync(f.fileno())
 os.mkdir(stage,0o700);p=os.path.join(stage,'bundle.zip');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 h=hashlib.sha256();left=int(size)
 with os.fdopen(fd,'wb') as f:
  while left:
   b=sys.stdin.buffer.read(min(1048576,left))
   if not b:break
   f.write(b);h.update(b);left-=len(b)
  f.flush();os.fsync(f.fileno())
 if left or sys.stdin.buffer.read(1) or h.hexdigest()!=digest:raise ValueError()
 fd=os.open(os.path.join(stage,'binding.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps({'sha256':digest,'length':int(size)},separators=(',',':'),sort_keys=True).encode());f.flush();os.fsync(f.fileno())
 out({'state':'staged','sha256':digest,'length':int(size)})
except Exception:out({'state':'unknown'})
'''


# One connection, one opaque path, and a re-hash immediately before streaming.
# The route nonce is intentionally kept in the private journal; callers receive
# only the ready/done receipt projection from the enclosing MCP action.
# The guest must create and start a limited-user scheduled task after the
# listener is ready.  Two minutes was shorter than that controlled orchestration
# path under a busy VM, so use a fixed ten-minute ceiling.  This is deliberately
# a constant in the remote worker: no MCP input can extend host exposure.
_HTTP_LISTENER_TIMEOUT_SECONDS = 600

_HTTP_WORKER = r'''import hashlib,http.server,json,os,stat,sys,time
stage=sys.argv[1]
raw=sys.stdin.buffer.read(1025);v=json.loads(raw) if 0<len(raw)<=1024 else None
if not isinstance(v,dict) or set(v)!={'path','sha256','length'}:raise SystemExit(2)
path,digest,length=v['path'],v['sha256'],v['length']
if not isinstance(path,str) or not __import__('re').fullmatch(r'/[A-Za-z0-9_-]{32,128}',path) or not isinstance(length,int) or length<=0:raise SystemExit(2)
def once(name,value):
 p=os.path.join(stage,name);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(value,separators=(',',':'),sort_keys=True).encode());f.flush();os.fsync(f.fileno())
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_CONNECT(self):self.send_error(405)
 def do_GET(self):
  if self.path!=path or self.headers.get('Proxy-Connection') is not None:self.send_error(404);return
  fd=os.open(os.path.join(stage,'bundle.zip'),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));h=hashlib.sha256()
  with os.fdopen(fd,'rb') as f:
   i=os.fstat(f.fileno())
   if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size!=length:self.send_error(500);return
   for part in iter(lambda:f.read(1048576),b''):h.update(part)
   if h.hexdigest()!=digest:self.send_error(500);return
   f.seek(0);self.send_response(200);self.send_header('Content-Length',str(length));self.send_header('Connection','close');self.end_headers()
   for part in iter(lambda:f.read(1048576),b''):self.wfile.write(part)
  self.server.served=True;self.server.attempted=True
class Server(http.server.HTTPServer):allow_reuse_address=False
server=Server(('127.0.0.1',0),Handler);server.timeout=.2;server.served=False;server.attempted=False
# CP117's Arch host has procfs.  The fallback keeps the deterministic host test
# portable; production admission separately requires the Linux start-ticks form.
try:ticks=open('/proc/self/stat','rb').read().split()[21].decode()
except OSError:ticks=str(os.getpid())
once('listener-ready.json',{'pid':os.getpid(),'startTicks':ticks,'port':server.server_address[1],'pathSha256':hashlib.sha256(path.encode()).hexdigest()})
deadline=time.monotonic()+@TIMEOUT_SECONDS@
while time.monotonic()<deadline and not server.attempted:server.handle_request()
server.server_close();once('listener-done.json',{'served':server.served})
'''.replace('@TIMEOUT_SECONDS@',str(_HTTP_LISTENER_TIMEOUT_SECONDS))

_REMOTE_LISTENER_START = r'''import base64,hashlib,json,os,re,stat,subprocess,sys,time
root,corr,digest,size,path,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def private_dir(p):
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def private_json(p,limit):
 i=os.lstat(p)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:raw=f.read(limit+1)
 if len(raw)>limit:raise ValueError()
 return json.loads(raw)
def bundle(p,length,expected):
 i=os.lstat(p)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size!=length:raise ValueError()
 fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));h=hashlib.sha256()
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno())
  for part in iter(lambda:f.read(1048576),b''):h.update(part)
  after=os.fstat(f.fileno())
 if before.st_ino!=i.st_ino or after.st_ino!=i.st_ino or after.st_size!=i.st_size or h.hexdigest()!=expected:raise ValueError()
try:
 if not isinstance(encoded,str) or not 4<=len(encoded)<=4096 or not re.fullmatch(r'[A-Za-z0-9+/=]+',encoded):raise ValueError()
 binding=json.loads(base64.b64decode(encoded,validate=True));length=int(size)
 if (not os.path.isabs(root) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<length<=1075838976 or not re.fullmatch(r'/[A-Za-z0-9_-]{32,128}',path)
  or not isinstance(binding,dict) or binding.get('correlationId')!=corr or binding.get('bundleSha256')!=digest
  or set(binding)!={'correlationId','socketPath','pid','startTicks','leaseId','sourceSha','sourceFingerprint','bundleSha256','expectedSid','fixtureReceiptArtifactId','baseMsiArtifactId','targetMsiArtifactId'}):raise ValueError()
 parent=os.path.join(root,'windows-cp117');group=os.path.join(parent,'windows-update-fixture-http-stage');authority_group=os.path.join(parent,'windows-update-fixture-stage')
 stage=os.path.join(group,corr);authority=os.path.join(authority_group,corr)
 for p in (root,parent,group,authority_group,stage,authority):private_dir(p)
 if (private_json(os.path.join(authority,'binding.json'),4096)!=binding
  or private_json(os.path.join(stage,'binding.json'),512)!={'sha256':digest,'length':length}):raise ValueError()
 bundle(os.path.join(stage,'bundle.zip'),length,digest)
 ready=os.path.join(stage,'listener-ready.json')
 if os.path.lexists(ready) or os.path.lexists(os.path.join(stage,'listener-done.json')):raise ValueError()
 worker=base64.b64decode('WORKER');child=subprocess.Popen((sys.executable,'-c',worker,stage),stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 child.stdin.write(json.dumps({'path':path,'sha256':digest,'length':length},separators=(',',':')).encode());child.stdin.close()
 for _ in range(100):
  if os.path.lexists(ready):break
  if child.poll() is not None:raise ValueError()
  time.sleep(.02)
 else:raise ValueError()
 value=json.load(open(ready));
 if set(value)!={'pid','startTicks','port','pathSha256'} or type(value['port']) is not int or not 1<=value['port']<=65535:raise ValueError()
 out({'state':'listening','port':value['port']})
except Exception:out({'state':'unknown'})
'''.replace("WORKER", base64.b64encode(_HTTP_WORKER.encode()).decode())

_REMOTE_LISTENER_STATUS = r'''import json,os,re,sys
root,corr=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr):raise ValueError()
 stage=os.path.join(root,'windows-cp117','windows-update-fixture-http-stage',corr);ready=os.path.join(stage,'listener-ready.json');done=os.path.join(stage,'listener-done.json')
 if not os.path.lexists(ready):out({'state':'absent'})
 elif os.path.lexists(done):out({'state':'served' if json.load(open(done))=={'served':True} else 'stopped'})
 else:out({'state':'listening'})
except Exception:out({'state':'unknown'})
'''

# The normal listener status deliberately hides its completion bit from action
# callers.  This forensic projection exposes only that one bit and no endpoint
# details, so a guest-download diagnostic can distinguish an unserved stop
# from a completed one-use transfer.
_REMOTE_LISTENER_FORENSIC = r'''import json,os,re,stat,sys
root,corr,expected_path_sha256=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def private_dir(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def private_json(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:raw=f.read(limit+1)
 if len(raw)>limit:raise ValueError()
 return json.loads(raw)
try:
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr) or not re.fullmatch(r'[0-9a-f]{64}',expected_path_sha256):raise ValueError()
 private_dir(root);parent=os.path.join(root,'windows-cp117');group=os.path.join(parent,'windows-update-fixture-http-stage');stage=os.path.join(group,corr);private_dir(parent);private_dir(group);private_dir(stage);ready=os.path.join(stage,'listener-ready.json');done=os.path.join(stage,'listener-done.json')
 if not os.path.lexists(ready):out({'state':'absent','served':'unknown','port':None})
 else:
  ready_value=private_json(ready,512)
  if (not isinstance(ready_value,dict) or set(ready_value)!={'pid','startTicks','port','pathSha256'}
   or type(ready_value['pid']) is not int or type(ready_value['port']) is not int or not 1<=ready_value['port']<=65535
   or not isinstance(ready_value['startTicks'],str) or not re.fullmatch(r'[0-9]+',ready_value['startTicks'])
   or not isinstance(ready_value['pathSha256'],str) or ready_value['pathSha256']!=expected_path_sha256):raise ValueError()
  if not os.path.lexists(done):out({'state':'listening','served':'unknown','port':ready_value['port']})
  else:
   receipt=private_json(done,64)
   if receipt=={'served':True}:out({'state':'served','served':'true','port':ready_value['port']})
   elif receipt=={'served':False}:out({'state':'stopped','served':'false','port':ready_value['port']})
   else:raise ValueError()
except Exception:out({'state':'unknown','served':'unknown','port':None})
'''

# Read-only forensic check for the one deterministic pre-effect failure that
# occurred when an adapter handed ``base._remote`` a BufferedReader instead of
# its required immutable Path.  A completed host-stage invocation creates at
# least one of these correlation directories before accepting payload bytes.
_REMOTE_HOST_STAGE_ABSENT = r'''import json,os,re,stat,sys
root,corr=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def private_dir(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def optional_private_dir(path):
 try:private_dir(path);return True
 except FileNotFoundError:return False
try:
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr):raise ValueError()
 private_dir(root)
 parent=os.path.join(root,'windows-cp117')
 if not optional_private_dir(parent):out({'state':'absent'});raise SystemExit(0)
 http_group=os.path.join(parent,'windows-update-fixture-http-stage');authority_group=os.path.join(parent,'windows-update-fixture-stage')
 http_exists=optional_private_dir(http_group);authority_exists=optional_private_dir(authority_group)
 def leaf(group,exists):
  if not exists:return False
  try:private_dir(os.path.join(group,corr));return True
  except FileNotFoundError:return False
 if leaf(http_group,http_exists) or leaf(authority_group,authority_exists):out({'state':'present'})
 else:out({'state':'absent'})
except Exception:out({'state':'unknown'})
'''

# This is a strict read-only counterpart to ``_REMOTE_STAGE``.  It accepts the
# complete authority binding rather than just a correlation so a stale or
# unrelated host leaf can never make a local ``host-staged`` journal eligible
# for listener startup.  It deliberately returns only a finite projection: no
# host paths, account names, or malformed receipt contents leave the host.
_REMOTE_HOST_STAGE_PROBE = r'''import base64,hashlib,json,os,re,stat,sys
root,corr,digest,size,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
class Partial(Exception):pass
def private_dir(path):
 i=os.lstat(path)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def optional_dir(path):
 try:private_dir(path);return True
 except FileNotFoundError:return False
def private_json(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 with os.fdopen(fd,'rb') as f:
  raw=f.read(limit+1)
 if len(raw)>limit:raise ValueError()
 return json.loads(raw)
def bundle(path,length,digest):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_size!=length:raise ValueError()
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0));h=hashlib.sha256()
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno())
  for part in iter(lambda:f.read(1048576),b''):h.update(part)
  after=os.fstat(f.fileno())
 if before.st_ino!=i.st_ino or after.st_ino!=i.st_ino or after.st_size!=i.st_size or h.hexdigest()!=digest:raise ValueError()
try:
 binding=json.loads(base64.b64decode(encoded,validate=True));length=int(size)
 if (not os.path.isabs(root) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr)
  or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit() or not 0<length<=1075838976
  or not isinstance(binding,dict) or binding.get('correlationId')!=corr or binding.get('bundleSha256')!=digest
  or set(binding)!={'correlationId','socketPath','pid','startTicks','leaseId','sourceSha','sourceFingerprint','bundleSha256','expectedSid','fixtureReceiptArtifactId','baseMsiArtifactId','targetMsiArtifactId'}):raise ValueError()
 private_dir(root);parent=os.path.join(root,'windows-cp117')
 if not optional_dir(parent):out({'state':'absent'});raise SystemExit(0)
 http_group=os.path.join(parent,'windows-update-fixture-http-stage');authority_group=os.path.join(parent,'windows-update-fixture-stage')
 http_group_exists=optional_dir(http_group);authority_group_exists=optional_dir(authority_group)
 http_leaf=os.path.join(http_group,corr);authority_leaf=os.path.join(authority_group,corr)
 def leaf(path,group_exists):
  if not group_exists:return False
  try:private_dir(path);return True
  except FileNotFoundError:return False
 http_exists=leaf(http_leaf,http_group_exists);authority_exists=leaf(authority_leaf,authority_group_exists)
 if not http_exists and not authority_exists:out({'state':'absent'});raise SystemExit(0)
 if not http_exists or not authority_exists:raise Partial()
 if (private_json(os.path.join(authority_leaf,'binding.json'),4096)!=binding
  or private_json(os.path.join(http_leaf,'binding.json'),512)!={'sha256':digest,'length':length}):raise Partial()
 try:bundle(os.path.join(http_leaf,'bundle.zip'),length,digest)
 except ValueError:raise Partial()
 out({'state':'complete'})
except Partial:out({'state':'partial'})
except Exception:out({'state':'unknown'})
'''

_REMOTE_CLEANUP = r'''import json,os,re,shutil,sys
root,corr,digest,size=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr) or not re.fullmatch(r'[0-9a-f]{64}',digest) or not size.isdigit():raise ValueError()
 group=os.path.join(root,'windows-cp117','windows-update-fixture-http-stage');stage=os.path.join(group,corr);done=os.path.join(stage,'listener-done.json')
 if not os.path.lexists(done) or json.load(open(done)) not in ({'served':True},{'served':False}):raise ValueError()
 binding=json.load(open(os.path.join(stage,'binding.json')))
 if binding!={'sha256':digest,'length':int(size)}:raise ValueError()
 for name in os.listdir(stage):
  p=os.path.join(stage,name)
  if not os.path.isfile(p) or os.path.islink(p):raise ValueError()
 shutil.rmtree(stage);open(os.path.join(group,corr+'.closed.json'),'x').write(json.dumps(binding,separators=(',',':'),sort_keys=True));out({'state':'cleaned'})
except Exception:out({'state':'unknown'})
'''

# Fixed QGA wrapper for the two short SYSTEM-only fixture setup actions.  It
# carries scripts as UTF-16 PowerShell arguments and never carries fixture bytes.
_REMOTE_QGA_PS = base._QGA + r'''import base64,json,re,time
sock,pid,ticks,encoded,expected=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not re.fullmatch(r'[A-Za-z0-9+/=]{4,30000}',encoded) or expected not in ('created','staged'):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(240):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 out({'state':expected})
except Exception:out({'state':'unknown'})
'''

# This observation wrapper deliberately does not share ``_REMOTE_QGA_PS``:
# that helper treats any nonzero PowerShell result as unknown and suppresses
# the finite evidence needed to distinguish a lost create response from a
# malformed generated script or an unsafe guest leaf.  The fixed program below
# only parses the exact generated script and reads guest metadata.
_REMOTE_QGA_GUEST_CREATE_DIAGNOSTIC = base._QGA + r'''import base64,json,re,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not re.fullmatch(r'[A-Za-z0-9+/=]{4,30000}',encoded):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 observed=json.loads(raw)
 if (not isinstance(observed,dict) or set(observed)!={'state','interpreter'}
  or observed['state'] not in ('syntax-invalid','ancestor-type','ancestor-reparse','acl-construction-failed','parent-absent','parent-type','parent-reparse','leaf-absent','leaf-type','leaf-reparse','leaf-directory','unknown')
  or observed['interpreter'] not in ('absent','present','unknown')):raise ValueError()
 out(observed)
except Exception:out({'state':'unknown','interpreter':'unknown'})
'''

# Read-only counterpart to the scheduled limited-user downloader.  It never
# starts, stops, deletes, or alters a task.  Its PowerShell payload only parses
# the already frozen download script, reads the scheduler's public state, and
# hashes the fixed guest leaf.  Keeping this apart from ``_REMOTE_QGA_DOWNLOAD``
# means a lost submit response cannot be mistaken for permission to submit
# another task.
_REMOTE_QGA_GUEST_DOWNLOAD_DIAGNOSTIC = base._QGA + r'''import base64,json,re,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not re.fullmatch(r'[A-Za-z0-9+/=]{4,30000}',encoded):raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:out({'state':'wrapper-timeout','task':'unknown','taskResult':'unknown','download':'unknown','actionSha256':'unknown'});raise SystemExit(0)
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 observed=json.loads(raw)
 if (not isinstance(observed,dict) or set(observed)!={'state','task','taskResult','download','actionSha256'}
  or observed['state'] not in ('syntax-invalid','observed','wrapper-timeout','wrapper-failed','unknown')
  or observed['task'] not in ('absent','running','completed','failed','metadata-error','principal-mismatch','action-count-mismatch','state-unsupported','task-info-failed','action-hash-unknown','unknown')
  or observed['download'] not in ('absent','complete','hash-mismatch','read-error','unknown')
  or (observed['taskResult']!='unknown' and (type(observed['taskResult']) is not int or not 0<=observed['taskResult']<=4294967295))
  or (observed['actionSha256']!='unknown' and not re.fullmatch(r'[0-9a-f]{64}',observed['actionSha256']))):raise ValueError()
 out(observed)
except Exception:out({'state':'wrapper-failed','task':'unknown','taskResult':'unknown','download':'unknown','actionSha256':'unknown'})
'''


# The SYSTEM placement action also creates the exact receipt consumed by the
# pre-existing stage.status verifier.  It writes dispatch.json immediately
# after QGA accepts guest-exec and before waiting for the script result.
_REMOTE_QGA_STAGE_EXTRACT = base._QGA + r'''import base64,json,os,re,stat,time
root,env,corr,sock,pid,ticks,encoded,binding64=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def private(path):
 i=os.lstat(path);return stat.S_ISREG(i.st_mode) and not stat.S_ISLNK(i.st_mode) and i.st_uid==os.geteuid() and stat.S_IMODE(i.st_mode)==0o600
def save(path,value):
 raw=json.dumps(value,separators=(',',':'),sort_keys=True).encode();fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
try:
 binding=json.loads(base64.b64decode(binding64,validate=True))
 if env!='windows-cp117' or not live(sock,pid,ticks) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr):raise ValueError()
 stage=os.path.join(root,env,'windows-update-fixture-stage',corr);binding_path=os.path.join(stage,'binding.json');dispatch=os.path.join(stage,'dispatch.json')
 if not private(binding_path) or os.path.lexists(dispatch) or json.load(open(binding_path,encoding='utf-8'))!=binding:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 save(dispatch,{'pid':child})
 for _ in range(240):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated') is not False or item.get('err-truncated') is not False:raise ValueError()
 out({'state':'staged'})
except Exception:out({'state':'unknown'})
'''

# The downloader always runs with the interactive, limited fixture owner.  Its
# action hash remains private and is rechecked by the root-owned QGA status path.
_REMOTE_QGA_DOWNLOAD = base._QGA + base._TRANSFER_NETWORK_QEMU_TOPOLOGY + r'''import base64,json,re,time
sock,pid,ticks,sid,corr,encoded=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',sid) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',corr):raise ValueError()
 user_network(pid)
 task='VpnControlMcpFixtureHttp-'+corr;account='VPNMSIX64\\vpncp117'
 bootstrap="$ErrorActionPreference='Stop';$n='"+task+"';$a='"+account+"';$sid=([Security.Principal.NTAccount]::new($a)).Translate([Security.Principal.SecurityIdentifier]).Value;if($sid -cne '"+sid+"'){throw 'SID'};if(Get-ScheduledTask -TaskPath '\' -TaskName $n -ErrorAction SilentlyContinue){throw 'EXISTS'};$action=New-ScheduledTaskAction -Execute 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand "+encoded+"');$principal=New-ScheduledTaskPrincipal -UserId $a -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5);Register-ScheduledTask -TaskName $n -Action $action -Principal $principal -Settings $settings|Out-Null;Start-ScheduledTask -TaskName $n;[Console]::Out.WriteLine('{\"state\":\"submitted\"}')"
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(bootstrap.encode('utf-16le')).decode()],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(240):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.5)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated',False) or item.get('err-truncated',False):raise ValueError()
 out({'state':'submitted'})
except Exception:out({'state':'unknown'})
'''


def listener_payload(record: Mapping[str, Any]) -> tuple[str, bytes]:
    """Return the private host-stage leaf and stdin for the fixed one-use worker."""
    if not isinstance(record, Mapping):
        raise WindowsUpdateFixtureHttpStageError("HTTP listener record is invalid.")
    digest, length, nonce = record.get("bundleSha256"), record.get("bundleSize"), record.get("routeNonce")
    corr = record.get("request", {}).get("correlationId") if isinstance(record.get("request"), Mapping) else None
    if not _canonical(corr) or not isinstance(digest, str) or not _HASH.fullmatch(digest) or type(length) is not int or length <= 0 or not isinstance(nonce, str):
        raise WindowsUpdateFixtureHttpStageError("HTTP listener record is invalid.")
    return corr, json.dumps({"path": "/" + nonce, "sha256": digest, "length": length}, separators=(",", ":")).encode()

# PowerShell 5 parser preflight is deliberately a distinct, short script.  It
# validates the exact unexpanded transfer template before a QGA task is made.
_GUEST_PS5_PREFLIGHT = r'''$ErrorActionPreference='Stop'
$script=@'@SCRIPT@'@
try {[void][scriptblock]::Create($script);[Console]::Out.WriteLine('{"state":"ps5-parsed"}')}catch{[Console]::Out.WriteLine('{"state":"unknown"}');exit 1}
'''


def ps5_preflight_script(guest_script: str) -> str:
    if not isinstance(guest_script, str) or not guest_script or len(guest_script.encode("utf-16le")) > 28000:
        raise WindowsUpdateFixtureHttpStageError("Guest transfer script is not admissible.")
    # Here-string termination cannot be safely embedded in the fixed preflight.
    if "'@" in guest_script or "@'" in guest_script:
        raise WindowsUpdateFixtureHttpStageError("Guest transfer script cannot be parser-checked safely.")
    return _GUEST_PS5_PREFLIGHT.replace("@SCRIPT@", guest_script)


def guest_download_script(*, correlation_id: str, sid: str, sha256: str, length: int,
                          port: int, path: str) -> str:
    """Build the limited-user PS5 download action for an already-created stage root.

    The caller must run ``stage._create_script`` first and ``stage._stage_script``
    afterwards.  This action only creates ``bundle.zip`` with exact bytes.
    """
    if (not _canonical(correlation_id) or not isinstance(sid, str) or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", sid)
            or not isinstance(sha256, str) or not _HASH.fullmatch(sha256) or type(length) is not int or not 0 < length <= 1075838976
            or type(port) is not int or not 1 <= port <= 65535 or not isinstance(path, str)
            or not re.fullmatch(r"/[A-Za-z0-9_-]{32,128}", path)):
        raise WindowsUpdateFixtureHttpStageError("Guest HTTP download binding is invalid.")
    return r'''$ErrorActionPreference='Stop'
$sid='@SID@';$corr='@CORR@';$expected='@HASH@';$length=@LENGTH@;$port=@PORT@;$path='@PATH@'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'SID'}
$root='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-'+$corr;$download=Join-Path $root 'download';$leaf=Join-Path $download 'bundle.zip'
 $item=Get-Item -LiteralPath $download -Force -ErrorAction Stop
if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or [IO.File]::Exists($leaf)){throw 'STAGE'}
Add-Type -AssemblyName System.Net.Http;$handler=[Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false;$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(180)
try{$response=$client.GetAsync(('http://10.0.2.2:'+$port+$path),[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult();try{
 if(-not $response.IsSuccessStatusCode -or $response.Content.Headers.ContentLength -ne $length){throw 'HTTP'}
 $in=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult();try{$out=[IO.FileStream]::new($leaf,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$hash=[Security.Cryptography.SHA256]::Create();$count=[int64]0;try{$buffer=New-Object byte[] 65536;while(($n=$in.Read($buffer,0,$buffer.Length)) -gt 0){$count+=$n;if($count -gt $length){throw 'LENGTH'};$out.Write($buffer,0,$n);[void]$hash.TransformBlock($buffer,0,$n,$buffer,0)};[void]$hash.TransformFinalBlock((New-Object byte[] 0),0,0);$out.Flush($true);$actual=([BitConverter]::ToString($hash.Hash)).Replace('-','').ToLowerInvariant()}finally{$out.Dispose();$hash.Dispose()}}finally{$in.Dispose()}
}finally{$response.Dispose()};if($count -ne $length -or $actual -cne $expected){throw 'DIGEST'};[Console]::Out.WriteLine((@{state='downloaded';sha256=$actual;length=$count}|ConvertTo-Json -Compress))}finally{$client.Dispose();$handler.Dispose()}
'''.replace("@SID@", sid).replace("@CORR@", correlation_id).replace("@HASH@", sha256).replace(
        "@LENGTH@", str(length)).replace("@PORT@", str(port)).replace("@PATH@", path)


def _submitted_download_script(**kwargs: Any) -> str:
    """Reconstruct the exact pre-fix command for the one frozen submitted task."""
    script = guest_download_script(**kwargs)
    if kwargs.get("correlation_id") in _LEGACY_DOWNLOAD_CORRELATIONS:
        return script.replace("Add-Type -AssemblyName System.Net.Http;", "")
    return script


def guest_status_script(*, correlation_id: str, sha256: str, length: int) -> str:
    """Small read-only PS5 result used before stage extraction or cleanup."""
    if not _canonical(correlation_id) or not isinstance(sha256, str) or not _HASH.fullmatch(sha256) or type(length) is not int or length <= 0:
        raise WindowsUpdateFixtureHttpStageError("Guest HTTP status binding is invalid.")
    return r'''$ErrorActionPreference='Stop';$p='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-@CORR@\download\bundle.zip'
try{if(-not [IO.File]::Exists($p)){[Console]::Out.WriteLine('{"state":"absent"}');exit 0};$i=Get-Item -LiteralPath $p -Force;if($i.PSIsContainer -or ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'TYPE'};$h=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();[Console]::Out.WriteLine((if($i.Length -eq @LENGTH@ -and $h -ceq '@HASH@'){@{state='downloaded';sha256=$h;length=$i.Length}}else{@{state='hash-mismatch'}}|ConvertTo-Json -Compress))}catch{[Console]::Out.WriteLine('{"state":"unknown"}');exit 1}
'''.replace("@CORR@", correlation_id).replace("@LENGTH@", str(length)).replace("@HASH@", sha256)


def project_remote_stage(raw: bytes | None, record: Mapping[str, Any]) -> dict[str, Any]:
    """Strict bounded projection used by the MCP route after host staging."""
    try: value = json.loads(raw) if raw is not None and len(raw) <= 512 else None
    except (TypeError, ValueError): value = None
    expected = {"state": "staged", "sha256": record.get("bundleSha256"), "length": record.get("bundleSize")}
    return expected if value == expected else dict(_UNKNOWN)


def collect(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Project the existing authoritative stage receipt after HTTP delivery.

    No HTTP receipt is accepted as a fixture-stage result.  Only the existing
    stage verifier checks the extraction hashes, ACLs, empty private state, and
    completes the ``stage`` campaign role.
    """
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage collection requires exact correlationId.")
    corr = value["correlationId"]
    try:
        local = _read(Path(root).resolve(strict=True), corr)
        if local is None:
            return {**_UNKNOWN, "correlationId": corr}
        observed = stage.status(root, {"correlationId": corr})
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError, stage.WindowsUpdateFixtureStageError):
        return {**_UNKNOWN, "correlationId": corr}
    if (observed.get("state") != "staged-not-server-ready" or observed.get("correlationId") != corr
            or observed.get("bundleSha256") != local["bundleSha256"]):
        return {**_UNKNOWN, "correlationId": corr}
    # stage.status is the authoritative SYSTEM-side ACL, hash and placement
    # receipt.  It is the only observation permitted to reconcile placement.
    try:
        descriptor = base._descriptor(Path(root).resolve(strict=True))[2]
        core = large_transfer.read(Path(root).resolve(strict=True), corr)
        if core is None or core.get("phase") != "placed":
            return {**_UNKNOWN, "correlationId": corr}
    except (OSError, ValueError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": corr}
    return observed


def _record(root: Path | str, correlation: str, *, campaign_mode: str = "stage") -> tuple[Path, dict[str, Any], Any, Any]:
    root_path = Path(root).resolve(strict=True); record = _read(root_path, correlation)
    if record is None:
        raise WindowsUpdateFixtureHttpStageError("HTTP stage correlation is unknown.")
    _artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
    request = _request(record["request"])
    if request["correlationId"] != correlation:
        raise WindowsUpdateFixtureHttpStageError("HTTP stage correlation changed.")
    pair = stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                    request["baseMsiArtifactId"], request["targetMsiArtifactId"])
    config, target, descriptor = base._descriptor(root_path)
    environment, socket, pid, ticks, sid = descriptor
    intent = stage._read_intent(root_path, correlation)
    core = large_transfer.read(root_path, correlation)
    expected_core = _large_binding(record, descriptor)
    if (core is None or core.get("binding") != expected_core or core.get("sha256") != record["bundleSha256"]
            or core.get("length") != record["bundleSize"] or record.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or intent is None or intent.get("request") != request or intent.get("leaseId") != record["leaseId"]
            or intent.get("sourceFingerprint") != pair.get("sourceFingerprint")
            or intent.get("bundleSha256") != record["bundleSha256"] or intent.get("bundleSize") != record["bundleSize"]
            or any(intent.get(name) != expected for name, expected in (("environment", environment),
                ("socketPath", socket), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage binding changed.")
    # ``prepare`` checks the unclaimed base campaign before persisting its
    # stage intent.  Pre-effect actions require that exact ``stage`` claim.
    # ``collect`` completes it to the same exact campaign identity with no
    # role, which is the only state permitted for terminal observation and
    # task-owned host cleanup.
    if campaign_mode == "stage":
        base._verified_claimed_campaign(root_path, request, descriptor, config, target,
                                        record["leaseId"], "stage")
    elif campaign_mode == "idle":
        if base._verified_active_campaign(root_path, request, descriptor, config, target,
                                          require_server=False) != record["leaseId"]:
            raise WindowsUpdateFixtureHttpStageError("HTTP stage idle lease changed.")
    elif campaign_mode == "stage-or-idle":
        try:
            base._verified_claimed_campaign(root_path, request, descriptor, config, target,
                                            record["leaseId"], "stage")
        except base.WindowsMsiBasePrepareError:
            if base._verified_active_campaign(root_path, request, descriptor, config, target,
                                              require_server=False) != record["leaseId"]:
                raise WindowsUpdateFixtureHttpStageError("HTTP stage lease changed.")
    else:
        raise WindowsUpdateFixtureHttpStageError("HTTP stage campaign mode is invalid.")
    return root_path, record, config, target


def stage_start_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Locate the read-only admission boundary before ``stage_start`` copies bytes.

    This is deliberately a projection of the same checks performed by
    :func:`_record`.  It never advances the shared phase, opens the remote
    transfer program, or sends fixture data.  The final ``remote-host-next``
    result means every local and read-only campaign admission passed and the
    next production boundary would be the host copy.
    """
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not _canonical(value.get("correlationId"))):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        root_path = Path(root).resolve(strict=True)
        record = _read(root_path, corr)
        if record is None:
            return {**result, "phase": "intent-core-binding-invalid"}
        _artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
        request = _request(record["request"])
        if request["correlationId"] != corr:
            return {**result, "phase": "intent-core-binding-invalid"}
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError):
        return {**result, "phase": "artifact-invalid"}
    try:
        pair = stage.public._admit_pair(root_path, request["sourceSha"], request["fixtureReceiptArtifactId"],
                                         request["baseMsiArtifactId"], request["targetMsiArtifactId"])
        if (not isinstance(pair, Mapping) or pair.get("sourceFingerprint") != record.get("sourceFingerprint")
                or not isinstance(pair.get("sourceFingerprint"), str) or not _HASH.fullmatch(pair["sourceFingerprint"])):
            return {**result, "phase": "pair-fingerprint-invalid"}
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "phase": "pair-fingerprint-invalid"}
    try:
        config, target, descriptor = base._descriptor(root_path)
        if len(descriptor) != 5:
            return {**result, "phase": "descriptor-invalid"}
        environment, socket, pid, ticks, sid = descriptor
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {**result, "phase": "descriptor-invalid"}
    try:
        intent = stage._read_intent(root_path, corr)
        core = large_transfer.read(root_path, corr)
        expected_core = _large_binding(record, descriptor)
        if (core is None or core.get("binding") != expected_core or core.get("sha256") != record["bundleSha256"]
                or core.get("length") != record["bundleSize"] or intent is None or intent.get("request") != request
                or intent.get("leaseId") != record["leaseId"] or intent.get("sourceFingerprint") != pair["sourceFingerprint"]
                or intent.get("bundleSha256") != record["bundleSha256"] or intent.get("bundleSize") != record["bundleSize"]
                or any(intent.get(name) != expected for name, expected in (("environment", environment),
                    ("socketPath", socket), ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
            return {**result, "phase": "intent-core-binding-invalid"}
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError, large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "intent-core-binding-invalid"}
    try:
        base._verified_claimed_campaign(root_path, request, descriptor, config, target,
                                        record["leaseId"], "stage")
    except (OSError, ValueError, KeyError, TypeError, base.WindowsMsiBasePrepareError):
        return {**result, "phase": "campaign-not-claimed"}
    if core.get("phase") != "prepared":
        return {**result, "phase": "phase-ineligible"}
    # Reading target configuration is the final non-delivery boundary.  Do not
    # contact the fixture host merely to diagnose a failed stage-start.
    try:
        # Match stage_start exactly: the configured target may provide either a
        # Path or an absolute string, and production passes its string form to
        # the fixed host program.
        str(target.fixture_transfer_root)
    except (AttributeError, TypeError, ValueError):
        return {**result, "phase": "remote-host-invalid"}
    return {**result, "phase": "remote-host-next"}


def stage_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Copy exact frozen bytes to the Arch fixture host only; no QGA action."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP stage start requires exact correlationId.")
    corr = value["correlationId"]
    try:
        _root, record, config, target = _record(root, corr)
        descriptor = base._descriptor(_root)[2]
        binding = base64.b64encode(json.dumps(_authority_binding(record, descriptor),
                                              sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        if not _large_advance(_root, record, descriptor, "host-staged"):
            raise WindowsUpdateFixtureHttpStageError("Host stage phase is not reserved.")
        # base._remote owns the file opening and requires this immutable Path;
        # passing an already-open BufferedReader fails locally before SSH.
        raw = base._remote(config, _REMOTE_STAGE, (str(target.fixture_transfer_root), corr,
                           record["bundleSha256"], str(record["bundleSize"]), binding),
                           Path(record["bundlePath"]), 1800)
        result = project_remote_stage(raw, record)
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        result = dict(_UNKNOWN)
    return {**result, "correlationId": corr}


def host_staged_pre_effect_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only proof for the historical Path-vs-stream dispatch exception."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP host-stage diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        root_path, record, config, target = _record(root, corr)
        core = large_transfer.read(root_path, corr)
        if core is None or core.get("phase") != "host-staged":
            return {**result, "phase": "not-host-staged"}
        raw = base._remote(config, _REMOTE_HOST_STAGE_ABSENT,
                           (str(target.fixture_transfer_root), corr), None, 30)
        observed = json.loads(raw) if raw is not None else None
        if observed == {"state": "absent"}:
            return {**result, "phase": "host-stage-absent"}
        if observed == {"state": "present"}:
            return {**result, "phase": "host-stage-present"}
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, large_transfer.WindowsLargeArtifactTransferError):
        pass
    return {**result, "phase": "unknown"}


def host_stage_probe(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only, hash-bound admission for the subsequent listener start.

    A lost ``stage-start`` response cannot be reconciled from the local phase
    alone: the host receipt and frozen bytes must both still match the exact
    local authority binding.  Only ``host-stage-complete`` permits the caller
    to choose ``listener-start``.
    """
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not _canonical(value.get("correlationId"))):
        raise WindowsUpdateFixtureHttpStageError("HTTP host-stage probe requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False,
              "productAction": False, "listenerStartAllowed": False}
    try:
        root_path, record, config, target = _record(root, corr)
        descriptor = base._descriptor(root_path)[2]
        core = large_transfer.read(root_path, corr)
        if (core is None or core.get("phase") != "host-staged"
                or core.get("binding") != _large_binding(record, descriptor)
                or core.get("sha256") != record["bundleSha256"]
                or core.get("length") != record["bundleSize"]):
            return {**result, "phase": "not-host-staged"}
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError,
            large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "local-binding-invalid"}
    try:
        binding = base64.b64encode(json.dumps(_authority_binding(record, descriptor),
                                              sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        raw = base._remote(config, _REMOTE_HOST_STAGE_PROBE,
                           (str(target.fixture_transfer_root), corr, record["bundleSha256"],
                            str(record["bundleSize"]), binding), None, 60)
        observed = json.loads(raw) if raw is not None and len(raw) <= 128 else None
        if observed == {"state": "complete"}:
            return {**result, "phase": "host-stage-complete", "listenerStartAllowed": True}
        if observed == {"state": "partial"}:
            return {**result, "phase": "host-stage-partial"}
        if observed == {"state": "absent"}:
            return {**result, "phase": "host-stage-absent"}
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError,
            large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "unknown"}
    return {**result, "phase": "unknown"}


def host_staged_pre_effect_close(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close only the proven local Path-vs-stream failure; never replay it."""
    diagnostic = host_staged_pre_effect_diagnostic(root, value)
    corr = value["correlationId"]
    if diagnostic.get("phase") != "host-stage-absent":
        return {**_UNKNOWN, "correlationId": corr}
    try:
        closed = large_transfer.close_host_staged_pre_effect(Path(root).resolve(strict=True), corr)
    except (OSError, ValueError, large_transfer.WindowsLargeArtifactTransferError):
        closed = dict(_UNKNOWN)
    return {**closed, "correlationId": corr}


def e66_pre_effect_recovery(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Close only the recorded e66 source-open failure after transcript import.

    This is intentionally fixed to one app command.  It first stores an
    immutable binding to the full exported command result, then asks the shared
    journal to record its one supported pre-dispatch failure.  Only after both
    durable writes does the ordinary close path run its fresh remote absence
    observation.  A loss at any boundary leaves the original stage attempt
    armed; it is never replayed.
    """
    if not isinstance(value, Mapping) or value != {"correlationId": _E66_CORRELATION}:
        raise WindowsUpdateFixtureHttpStageError("E66 recovery requires its exact correlationId.")
    try:
        root_path = Path(root).resolve(strict=True)
        _record(root_path, _E66_CORRELATION)
        core = large_transfer.read(root_path, _E66_CORRELATION)
        if core is None or core.get("phase") != "host-staged":
            return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
        transcript = _e66_transcript(root_path)
        if not _e66_imported(root_path, transcript):
            if not _e66_import_receipt(root_path, transcript):
                return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
        if not _fsync_e66_import_directory(root_path):
            return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
        # The shared core owns this journal mutation.  Its fixed method writes
        # only _E66_FAILURE and rejects every other phase or existing value.
        large_transfer.record_predispatch_failure(root_path, _E66_CORRELATION)
        fresh = large_transfer.read(root_path, _E66_CORRELATION)
        if fresh is None or fresh.get("phase") != "host-staged" or fresh.get("dispatchFailure") != _E66_FAILURE:
            return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError,
            large_transfer.WindowsLargeArtifactTransferError, AttributeError):
        return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
    return host_staged_pre_effect_close(root_path, {"correlationId": _E66_CORRELATION})


def _e66_retirement_receipt(root: Path, value: Mapping[str, Any], *, create: bool) -> dict[str, Any] | None:
    """Read or durably create the one terminal proof for the aborted stage role."""
    directory = _directory(root, create)
    if directory is None:
        return None
    path = directory / (_E66_CORRELATION + ".retirement.json")
    expected = dict(value)
    try:
        raw = _private_file(path, 4096)
    except WindowsUpdateFixtureHttpStageError:
        raw = None
    if raw is not None:
        try:
            stored = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return expected if stored == expected else None
    if not create or not _write_once(path, expected) or not _fsync_e66_import_directory(root):
        return None
    return expected


def _e66_retirement_admission(root: Path, *, reconcile_pending: bool) -> tuple[str, tuple[Any, ...] | None]:
    """Prove every immutable and fresh fact needed to retire e66's stage role."""
    try:
        # A successful finish releases the stage role.  The terminal evidence
        # must remain observable through the matching idle campaign record.
        root_path, record, config, target = _record(root, _E66_CORRELATION, campaign_mode="stage-or-idle")
        if record.get("leaseId") != _E66_LEASE:
            return "unknown", None
        descriptor = base._descriptor(root_path)[2]
        transcript = _e66_transcript(root_path)
        if not _e66_imported(root_path, transcript):
            return "unknown", None
        core = large_transfer.read(root_path, _E66_CORRELATION)
        if (core is None or core.get("phase") != "aborted" or core.get("dispatchFailure") != _E66_FAILURE
                or core.get("preEffectClose") != {"reason": "source-not-path", "remoteStage": "absent"}):
            return "unknown", None
        raw = base._remote(config, _REMOTE_HOST_STAGE_ABSENT,
                           (str(target.fixture_transfer_root), _E66_CORRELATION), None, 30)
        if (json.loads(raw) if raw is not None else None) != {"state": "absent"}:
            return "unknown", None
        remote = base._campaign_remote(config, target)
        directory, lock = stage.campaign_lease._locked(root_path)
        try:
            current = stage.campaign_lease._active(directory)
            expected_identity = base._campaign_identity({**record["request"], "correlationId": _E66_LEASE}, descriptor)
            if current is None or current.get("identity") != expected_identity:
                return "unknown", None
            if current.get("state") == "pending-finish":
                pending = True
            elif current.get("state") == "role-active" and current.get("role") == "stage" and current.get("correlationId") == _E66_CORRELATION:
                pending = False
            elif current.get("state") == "active" and current.get("role") is None:
                pending = False
            else:
                return "unknown", None
            if not pending and not stage.campaign_lease._remote_confirm(remote, "status", current, None):
                return "unknown", None
        finally:
            os.close(lock)
        if pending:
            if not reconcile_pending:
                return "pending-finish", None
            reconciled = stage.campaign_lease.reconcile(root_path, _E66_LEASE, remote)
            if reconciled.get("state") != "active":
                return "unknown", None
            return _e66_retirement_admission(root_path, reconcile_pending=False)
        guest = {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}
        receipt = {"correlationId": _E66_CORRELATION, "leaseId": _E66_LEASE,
                   "sourceFingerprint": record["sourceFingerprint"], "bundleSha256": record["bundleSha256"],
                   "guestGeneration": guest, "transcriptSha256": transcript["transcriptSha256"],
                   "coreSha256": hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                   "remoteStage": "absent", "remoteCampaign": "confirmed"}
        receipt_sha = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if current["state"] == "active":
            if current.get("lastOutcome") != "failed-cleaned" or current.get("lastEvidenceSha256") != receipt_sha:
                return "unknown", None
            if _e66_retirement_receipt(root_path, receipt, create=False) is None:
                return "unknown", None
            return "retired", (root_path, record, config, target, remote, receipt, receipt_sha)
        return "ready", (root_path, record, config, target, remote, receipt, receipt_sha)
    except (OSError, ValueError, KeyError, TypeError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError,
            stage.campaign_lease.Cp117LeaseError, large_transfer.WindowsLargeArtifactTransferError):
        return "unknown", None


def e66_retire_aborted_stage_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value != {"correlationId": _E66_CORRELATION}:
        raise WindowsUpdateFixtureHttpStageError("E66 retirement status requires its exact correlationId.")
    # This is an observation surface.  A pending finish is reported as such;
    # only the explicit retirement action may reconcile its durable mutation.
    state, _details = _e66_retirement_admission(Path(root).resolve(strict=True), reconcile_pending=False)
    return {"state": state, "correlationId": _E66_CORRELATION, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def e66_retire_aborted_stage(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Finish only e66's already-aborted stage campaign role; never transfer bytes."""
    if not isinstance(value, Mapping) or value != {"correlationId": _E66_CORRELATION}:
        raise WindowsUpdateFixtureHttpStageError("E66 retirement requires its exact correlationId.")
    state, details = _e66_retirement_admission(Path(root).resolve(strict=True), reconcile_pending=True)
    if state == "retired":
        return {"state": "retired", "correlationId": _E66_CORRELATION, **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
    if state != "ready" or details is None:
        return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
    root_path, record, _config, _target, remote, receipt, receipt_sha = details
    if _e66_retirement_receipt(root_path, receipt, create=True) is None:
        return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
    try:
        finished = stage.campaign_lease.finish_role(root_path, _E66_LEASE, "stage", _E66_CORRELATION,
                                                    receipt_sha, "failed-cleaned", remote)
    except (OSError, ValueError, stage.campaign_lease.Cp117LeaseError):
        return {**_UNKNOWN, "correlationId": _E66_CORRELATION}
    return ({"state": "retired", "correlationId": _E66_CORRELATION,
             **{k: v for k, v in _UNKNOWN.items() if k != "state"}}
            if finished.get("state") == "active" else {**_UNKNOWN, "correlationId": _E66_CORRELATION})


def listener_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Start the single-use host listener after immutable remote stage proof."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP listener start requires exact correlationId.")
    corr = value["correlationId"]
    try:
        admission = host_stage_probe(root, value)
        if admission.get("phase") != "host-stage-complete" or admission.get("listenerStartAllowed") is not True:
            raise WindowsUpdateFixtureHttpStageError("Host stage is not complete.")
        _root, record, config, target = _record(root, corr)
        path, payload = listener_payload(record)
        if path != corr: raise WindowsUpdateFixtureHttpStageError("HTTP listener correlation changed.")
        route = json.loads(payload)["path"]
        binding = base64.b64encode(json.dumps(_authority_binding(record, base._descriptor(_root)[2]),
                                              sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        if len(binding) > 4096:
            raise WindowsUpdateFixtureHttpStageError("HTTP listener authority binding is too large.")
        # Reserve the listener phase before the remote process spawn.  A lost
        # result is therefore read back through listener_status instead of
        # creating another one-use endpoint.
        if not _large_advance(_root, record, base._descriptor(_root)[2], "listening"):
            raise WindowsUpdateFixtureHttpStageError("Listener phase is not reserved.")
        raw = base._remote(config, _REMOTE_LISTENER_START, (str(target.fixture_transfer_root), corr,
                           record["bundleSha256"], str(record["bundleSize"]), route, binding), None, 30)
        observed = json.loads(raw) if raw is not None else None
        if not isinstance(observed, dict) or set(observed) != {"state", "port"} or observed.get("state") != "listening" or type(observed.get("port")) is not int:
            raise WindowsUpdateFixtureHttpStageError("HTTP listener start is unknown.")
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": corr}
    # No endpoint/port is exposed by this adapter; guest dispatch receives it through
    # the root-owned fixed QGA route only.
    return {"state": "listening", "correlationId": corr, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def listener_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP listener status requires exact correlationId.")
    corr = value["correlationId"]
    try:
        _root, _record_value, config, target = _record(root, corr, campaign_mode="stage-or-idle")
        raw = base._remote(config, _REMOTE_LISTENER_STATUS, (str(target.fixture_transfer_root), corr), None, 30)
        observed = json.loads(raw) if raw is not None else None
        if not isinstance(observed, dict) or set(observed) != {"state"} or observed["state"] not in {"absent", "listening", "served", "stopped"}:
            raise ValueError()
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": corr}
    return {**observed, "correlationId": corr, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def cleanup(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Guarded host cleanup: only a finished one-use listener can be removed."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("HTTP cleanup requires exact correlationId.")
    corr = value["correlationId"]
    try:
        _root, record, config, target = _record(root, corr, campaign_mode="idle")
        status_value = listener_status(root, value)
        if status_value.get("state") not in {"served", "stopped"}: raise WindowsUpdateFixtureHttpStageError("Listener is not terminal.")
        if not _large_advance(_root, record, base._descriptor(_root)[2], "cleaned"):
            raise WindowsUpdateFixtureHttpStageError("Cleanup phase is not admitted.")
        raw = base._remote(config, _REMOTE_CLEANUP, (str(target.fixture_transfer_root), corr,
                           record["bundleSha256"], str(record["bundleSize"])), None, 30)
        observed = json.loads(raw) if raw is not None else None
        if observed != {"state": "cleaned"}: raise ValueError()
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": corr}
    return {"state": "cleaned", "correlationId": corr, "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _qga_action(root: Path | str, correlation: str, script: str, expected: str) -> dict[str, Any]:
    """Run one bounded no-byte QGA action and project only its finite result."""
    try:
        root_path, _record_value, config, _target = _record(root, correlation)
        _env, socket, pid, ticks, _sid = base._descriptor(root_path)[2]
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        if len(encoded) > 30000: raise WindowsUpdateFixtureHttpStageError("QGA action exceeds admission.")
        raw = base._remote(config, _REMOTE_QGA_PS, (socket, str(pid), str(ticks), encoded, expected), None, 180)
        observed = json.loads(raw) if raw is not None else None
        return {"state": expected} if observed == {"state": expected} else dict(_UNKNOWN)
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return dict(_UNKNOWN)


def _guest_create_diagnostic_script(correlation: str, sid: str, create_script: str) -> str:
    """Return the fixed read-only guest observation for one generated script.

    The generated script is supplied as data solely to PowerShell's parser;
    it is never invoked.  Its root is independently fixed from the correlation
    so parsing cannot select an observation path.
    """
    encoded = base64.b64encode(create_script.encode("utf-16le")).decode("ascii")
    root = stage._GUEST + "\\mcp-update-fixture-" + correlation
    return r'''$ErrorActionPreference='Stop';$script=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('@SCRIPT@'));$root=@ROOT@;$recipient=@SID@;$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseInput($script,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count -ne 0){[Console]::Out.WriteLine('{"state":"syntax-invalid","interpreter":"unknown"}');exit 0};$interpreter='unknown';try{$interpreter=if(@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -in @('powershell.exe','pwsh.exe') -and $_.ProcessId -ne $PID}).Count -gt 0){'present'}else{'absent'}}catch{$interpreter='unknown'};function Result([string]$state){[Console]::Out.WriteLine((@{state=$state;interpreter=$interpreter}|ConvertTo-Json -Compress));exit 0};try{$current=Split-Path -Parent $root;while($null -ne $current -and $current -ne ''){$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop;if(-not $item.PSIsContainer){Result 'ancestor-type'};if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Result 'ancestor-reparse'};$parent=Split-Path -Parent $current;if($parent -ceq $current){break};$current=$parent}}catch{Result 'unknown'};try{$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false);$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;foreach($identity in @('S-1-5-18','S-1-5-32-544',$recipient)){$rights=if($identity -ceq $recipient){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl};$rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),$rights,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);[void]$acl.AddAccessRule($rule)}}catch{Result 'acl-construction-failed'};try{$parent=Split-Path -Parent $root;if(-not [IO.Directory]::Exists($parent)){Result 'parent-absent'};$p=Get-Item -LiteralPath $parent -Force -ErrorAction Stop;if(-not $p.PSIsContainer){Result 'parent-type'};if(($p.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Result 'parent-reparse'};if(-not (Test-Path -LiteralPath $root)){Result 'leaf-absent'};$leaf=Get-Item -LiteralPath $root -Force -ErrorAction Stop;if(-not $leaf.PSIsContainer){$state='leaf-type'}elseif(($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$state='leaf-reparse'}else{$state='leaf-directory'};Result $state}catch{Result 'unknown'}'''.replace("@SCRIPT@", encoded).replace("@ROOT@", stage.public._ps_literal(root)).replace("@SID@", stage.public._ps_literal(sid))


def guest_create_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a prior guest-create attempt without advancing or replaying it."""
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not _canonical(value.get("correlationId"))):
        raise WindowsUpdateFixtureHttpStageError("Guest create diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False,
              "interpreter": "unknown"}
    try:
        root_path, record, config, _target = _record(root, corr)
        descriptor = base._descriptor(root_path)[2]
        if large_transfer.read(root_path, corr).get("phase") != "guest-created":
            return {**result, "phase": "not-guest-created"}
        script = _guest_create_diagnostic_script(corr, descriptor[4], stage._create_script(corr, descriptor[4]))
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        if len(encoded) > 30000:
            return {**result, "phase": "diagnostic-script-oversize"}
        _env, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_QGA_GUEST_CREATE_DIAGNOSTIC,
                           (socket, str(pid), str(ticks), encoded), None, 90)
        observed = json.loads(raw) if raw is not None and len(raw) <= 256 else None
        if (not isinstance(observed, dict) or set(observed) != {"state", "interpreter"}
                or observed.get("state") not in {"syntax-invalid", "ancestor-type", "ancestor-reparse",
                                                  "acl-construction-failed", "parent-absent", "parent-type",
                                                  "parent-reparse", "leaf-absent", "leaf-type",
                                                  "leaf-reparse", "leaf-directory", "unknown"}
                or observed.get("interpreter") not in {"absent", "present", "unknown"}):
            return {**result, "phase": "unknown"}
        state = observed["state"]
        if state == "leaf-directory":
            phase = "guest-create-may-have-completed"
        elif state in {"syntax-invalid", "ancestor-type", "ancestor-reparse", "acl-construction-failed",
                       "parent-absent", "parent-type", "parent-reparse", "leaf-absent", "leaf-type", "leaf-reparse"}:
            phase = "guest-create-not-confirmed-" + state
        else:
            phase = "unknown"
        return {**result, "phase": phase, "interpreter": observed["interpreter"]}
    except (AttributeError, OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError,
            large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "unknown"}


def _guest_download_diagnostic_script_base(correlation: str, sid: str, sha256: str, length: int,
                                           download_script: str) -> str:
    """Build one parser-only and metadata-only read for a submitted download.

    ``download_script`` is parsed, never invoked.  The fixed scheduler task
    name and guest path are derived entirely from the bound correlation, while
    its expected SID, bytes and digest are inherited from the immutable intent.
    """
    if (not _canonical(correlation) or not isinstance(sid, str)
            or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", sid)
            or not isinstance(sha256, str) or not _HASH.fullmatch(sha256)
            or type(length) is not int or length <= 0 or not isinstance(download_script, str)):
        raise WindowsUpdateFixtureHttpStageError("Guest download diagnostic binding is invalid.")
    encoded = base64.b64encode(download_script.encode("utf-16le")).decode("ascii")
    return r'''$ErrorActionPreference='Stop';$encodedDownload='@SCRIPT@';$script=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedDownload));$corr='@CORR@';$expectedSid='@SID@';$expectedHash='@HASH@';$expectedLength=@LENGTH@;$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseInput($script,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count -ne 0){[Console]::Out.WriteLine('{"state":"syntax-invalid","task":"unknown","download":"unknown","actionSha256":"unknown"}');exit 0};$taskState='unknown';$actionSha256='unknown';$downloadState='unknown';try{$name='VpnControlMcpFixtureHttp-'+$corr;$task=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue;if($null -eq $task){$taskState='absent'}else{$principal=$task.Principal.UserId;if($principal -ceq 'VPNMSIX64\\vpncp117'){$principal=([Security.Principal.NTAccount]::new($principal)).Translate([Security.Principal.SecurityIdentifier]).Value};$actions=@($task.Actions);if($principal -cne $expectedSid){$taskState='principal-mismatch'}elseif($actions.Count -ne 1){$taskState='action-count-mismatch'}else{try{$utf8=[Text.Encoding]::UTF8;$bytes=$utf8.GetBytes($actions[0].Execute+[char]0+$actions[0].Arguments);$hash=[Security.Cryptography.SHA256]::Create();try{$actionSha256=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}}catch{$taskState='action-hash-unknown'};if($taskState -eq 'action-hash-unknown'){}elseif($task.State -in @('Running','Queued')){$taskState='running'}elseif($task.State -ne 'Ready'){$taskState='state-unsupported'}else{try{$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $name -ErrorAction Stop;if($info.LastTaskResult -eq 0){$taskState='completed'}else{$taskState='failed'}}catch{$taskState='task-info-failed'}}}}}catch{$taskState='metadata-error';$actionSha256='unknown'};try{$path='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-'+$corr+'\download\bundle.zip';if(-not [IO.File]::Exists($path)){$downloadState='absent'}else{$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){$downloadState='read-error'}else{$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();if($item.Length -eq $expectedLength -and $hash -ceq $expectedHash){$downloadState='complete'}else{$downloadState='hash-mismatch'}}}}catch{$downloadState='read-error'};[Console]::Out.WriteLine((@{state='observed';task=$taskState;download=$downloadState;actionSha256=$actionSha256}|ConvertTo-Json -Compress))'''.replace("@SCRIPT@", encoded).replace("@CORR@", correlation).replace("@SID@", sid).replace("@HASH@", sha256).replace("@LENGTH@", str(length))


def _guest_download_diagnostic_script(correlation: str, sid: str, sha256: str, length: int,
                                      download_script: str) -> str:
    # The base literal is raw Python source; normalize this Windows account at
    # the rendering boundary so PowerShell receives its single path separator.
    rendered = _guest_download_diagnostic_script_base(correlation, sid, sha256, length, download_script).replace(
        "VPNMSIX64\\\\vpncp117", "VPNMSIX64\\vpncp117")
    rendered = rendered.replace(
        "$principal=$task.Principal.UserId;if($principal -ceq 'VPNMSIX64\\vpncp117'){$principal=([Security.Principal.NTAccount]::new($principal)).Translate([Security.Principal.SecurityIdentifier]).Value};$actions=",
        "$principal=$task.Principal.UserId;if($principal -notmatch '^S-1-5-(?:[0-9]+-)*[0-9]+$'){$principal=([Security.Principal.NTAccount]::new($principal)).Translate([Security.Principal.SecurityIdentifier]).Value};$actions=")
    return rendered.replace("$taskState='unknown';$actionSha256='unknown';$downloadState='unknown';",
                            "$taskState='unknown';$taskResult='unknown';$actionSha256='unknown';$downloadState='unknown';").replace(
        "$info=Get-ScheduledTaskInfo -TaskPath '\\' -TaskName $name -ErrorAction Stop;if($info.LastTaskResult -eq 0)",
        "$info=Get-ScheduledTaskInfo -TaskPath '\\' -TaskName $name -ErrorAction Stop;$rawResult=$info.LastTaskResult;if($null -eq $rawResult){throw 'TASK_INFO'};$typeCode=[Convert]::GetTypeCode($rawResult);if($typeCode -notin @([TypeCode]::SByte,[TypeCode]::Int16,[TypeCode]::Int32,[TypeCode]::Int64,[TypeCode]::Byte,[TypeCode]::UInt16,[TypeCode]::UInt32,[TypeCode]::UInt64)){throw 'TASK_INFO'};$taskResult=[int64]$rawResult;if($taskResult -lt -2147483648 -or $taskResult -gt 4294967295){throw 'TASK_INFO'};if($taskResult -lt 0){$taskResult+=4294967296};if($taskResult -eq 0)").replace(
        "task=$taskState;download=$downloadState;actionSha256=$actionSha256",
        "task=$taskState;taskResult=$taskResult;download=$downloadState;actionSha256=$actionSha256").replace(
        '"task":"unknown","download":"unknown","actionSha256":"unknown"',
        '"task":"unknown","taskResult":"unknown","download":"unknown","actionSha256":"unknown"')


def _download_task_action(download_script: str) -> tuple[str, str]:
    """The immutable executable and arguments registered by the submit action."""
    if not isinstance(download_script, str) or not download_script:
        raise WindowsUpdateFixtureHttpStageError("Guest download action is invalid.")
    return (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile -NonInteractive -EncodedCommand "
            + base64.b64encode(download_script.encode("utf-16le")).decode("ascii"))


def _task_action_fingerprint(executable: str, arguments: str) -> str:
    if not isinstance(executable, str) or not isinstance(arguments, str):
        raise WindowsUpdateFixtureHttpStageError("Guest task action is invalid.")
    return hashlib.sha256((executable + "\0" + arguments).encode("utf-8")).hexdigest()


def _project_guest_download_observation(observed: Mapping[str, Any], expected_action_sha256: str) -> tuple[str, str, str, int | str] | None:
    """Fail closed unless the observed task action is the exact frozen action."""
    if isinstance(observed, Mapping) and "taskResult" not in observed:
        observed = {**observed, "taskResult": "unknown"}
    if (not isinstance(observed, Mapping) or not isinstance(expected_action_sha256, str)
            or not _HASH.fullmatch(expected_action_sha256)
            or set(observed) != {"state", "task", "taskResult", "download", "actionSha256"}
            or observed.get("state") not in {"syntax-invalid", "observed", "wrapper-timeout", "wrapper-failed", "unknown"}
            or observed.get("task") not in {"absent", "running", "completed", "failed", "metadata-error", "principal-mismatch", "action-count-mismatch", "state-unsupported", "task-info-failed", "action-hash-unknown", "unknown"}
            or observed.get("download") not in {"absent", "complete", "hash-mismatch", "read-error", "unknown"}
            or (observed.get("taskResult") != "unknown" and (type(observed.get("taskResult")) is not int or not 0 <= observed["taskResult"] <= 4294967295))
            or (observed.get("actionSha256") != "unknown" and not _HASH.fullmatch(observed.get("actionSha256")))):
        return None
    if observed["state"] == "wrapper-timeout":
        return "qga-wrapper-timeout", "unknown", "unknown", "unknown"
    if observed["state"] == "wrapper-failed":
        return "qga-wrapper-failed", "unknown", "unknown", "unknown"
    if observed["state"] == "syntax-invalid":
        return "syntax-invalid", "unknown", "unknown", "unknown"
    task, download = observed["task"], observed["download"]
    if task not in {"absent", "unknown", "metadata-error", "principal-mismatch", "action-count-mismatch", "state-unsupported", "task-info-failed", "action-hash-unknown"} and observed["actionSha256"] != expected_action_sha256:
        return "task-action-mismatch", "unknown", download, "unknown"
    if task in {"metadata-error", "principal-mismatch", "action-count-mismatch", "state-unsupported", "task-info-failed", "action-hash-unknown"}:
        return "task-" + task, task, download, "unknown"
    if task == "unknown": return "unknown", task, download, "unknown"
    if task == "absent": return "task-absent", task, download, "unknown"
    result = observed["taskResult"] if task in {"completed", "failed"} else "unknown"
    if download == "complete": return "download-complete", task, download, result
    if download == "hash-mismatch": return "download-hash-mismatch", task, download, result
    if download == "read-error": return "guest-file-read-error", task, download, result
    if task == "running": return "task-running", task, download, result
    if task == "failed": return "task-failed", task, download, result
    if download == "absent": return "download-absent", task, download, result
    return "unknown", task, download, result


def _listener_forensic(root_path: Path, config: Any, target: Any, correlation: str,
                        route_nonce: str) -> tuple[str, str, int | None]:
    """Return only finite listener completion facts for download diagnosis."""
    try:
        route = "/" + route_nonce
        raw = base._remote(config, _REMOTE_LISTENER_FORENSIC,
                           (str(target.fixture_transfer_root), correlation,
                            hashlib.sha256(route.encode()).hexdigest()), None, 30)
        observed = json.loads(raw) if raw is not None and len(raw) <= 128 else None
        if (not isinstance(observed, dict) or set(observed) != {"state", "served", "port"}
                or observed.get("state") not in {"absent", "listening", "served", "stopped", "unknown"}
                or observed.get("served") not in {"true", "false", "unknown"}
                or (observed.get("port") is not None and (type(observed["port"]) is not int
                                                           or not 1 <= observed["port"] <= 65535))):
            raise ValueError()
        if ((observed["state"] == "served" and observed["served"] != "true")
                or (observed["state"] == "stopped" and observed["served"] != "false")
                or (observed["state"] in {"absent", "listening", "unknown"}
                    and observed["served"] != "unknown")
                or ((observed["state"] in {"listening", "served", "stopped"})
                    != (type(observed["port"]) is int))):
            raise ValueError()
        return observed["state"], observed["served"], observed["port"]
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError):
        return "unknown", "unknown", None


def guest_download_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one submitted download without dispatching or extracting it."""
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not _canonical(value.get("correlationId"))):
        raise WindowsUpdateFixtureHttpStageError("Guest download diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "preEffect": True,
              "replayAllowed": False, "nativeActionAllowed": False, "productAction": False,
              "listener": "unknown", "listenerServed": "unknown", "task": "unknown",
              "taskResult": "unknown", "download": "unknown"}
    try:
        root_path, record, config, target = _record(root, corr)
        descriptor = base._descriptor(root_path)[2]
        core = large_transfer.read(root_path, corr)
        if core is None or core.get("phase") != "download-submitted":
            return {**result, "phase": "not-submitted"}
        listener, served, port = _listener_forensic(root_path, config, target, corr, record["routeNonce"])
        if port is None:
            return {**result, "phase": "unknown", "listener": listener, "listenerServed": served}
        route = "/" + record["routeNonce"]
        script = _submitted_download_script(correlation_id=corr, sid=descriptor[4],
                                       sha256=record["bundleSha256"], length=record["bundleSize"],
                                       port=port, path=route)
        expected_action_sha256 = _task_action_fingerprint(*_download_task_action(script))
        diagnostic = _guest_download_diagnostic_script(corr, descriptor[4], record["bundleSha256"],
                                                        record["bundleSize"], script)
        encoded = base64.b64encode(diagnostic.encode("utf-16le")).decode("ascii")
        if len(encoded) > 30000:
            return {**result, "phase": "diagnostic-script-oversize", "listener": listener,
                    "listenerServed": served}
        _env, socket, pid, ticks, _sid = descriptor
        raw = base._remote(config, _REMOTE_QGA_GUEST_DOWNLOAD_DIAGNOSTIC,
                           (socket, str(pid), str(ticks), encoded), None, 90)
        observed = json.loads(raw) if raw is not None and len(raw) <= 256 else None
        projection = _project_guest_download_observation(observed, expected_action_sha256) if isinstance(observed, Mapping) else None
        if projection is None:
            return {**result, "phase": "unknown", "listener": listener, "listenerServed": served}
        phase, task, download, task_result = projection
        return {**result, "phase": phase, "listener": listener, "listenerServed": served,
                "task": task, "taskResult": task_result, "download": download}
    except (AttributeError, OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError,
            large_transfer.WindowsLargeArtifactTransferError):
        return {**result, "phase": "unknown"}


def guest_create(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("Guest creation requires exact correlationId.")
    corr = value["correlationId"]
    try:
        root_path, record, _config, _target = _record(root, corr)
        descriptor = base._descriptor(root_path)[2]
        sid = descriptor[4]
        if not _large_advance(root_path, record, descriptor, "guest-created"):
            raise WindowsUpdateFixtureHttpStageError("Guest create phase is not reserved.")
        observed = _qga_action(root_path, corr, stage._create_script(corr, sid), "created")
    except (OSError, ValueError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        observed = dict(_UNKNOWN)
    return {**observed, "correlationId": corr, "replayAllowed": False}


def guest_download(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("Guest download requires exact correlationId.")
    corr = value["correlationId"]
    try:
        root_path, record, config, target = _record(root, corr)
        state = listener_status(root_path, value)
        if state.get("state") != "listening": raise WindowsUpdateFixtureHttpStageError("Listener is not ready.")
        # Read endpoint privately from the fixed host stage.  The public listener
        # projection intentionally suppresses port and opaque path.
        raw = base._remote(config, r'''import json,os,sys
root,corr=sys.argv[1:];v=json.load(open(os.path.join(root,'windows-cp117','windows-update-fixture-http-stage',corr,'listener-ready.json')));print(json.dumps({'port':v.get('port'),'pathSha256':v.get('pathSha256')}))''', (str(target.fixture_transfer_root), corr), None, 30)
        # Route nonce reconstructs the only permitted path; never accept host path input.
        endpoint = json.loads(raw) if raw is not None else None
        route = "/" + record["routeNonce"]
        if not isinstance(endpoint, dict) or set(endpoint) != {"port", "pathSha256"} or type(endpoint["port"]) is not int or endpoint["pathSha256"] != hashlib.sha256(route.encode()).hexdigest(): raise ValueError()
        _env, socket, pid, ticks, sid = base._descriptor(root_path)[2]
        script = guest_download_script(correlation_id=corr, sid=sid, sha256=record["bundleSha256"], length=record["bundleSize"], port=endpoint["port"], path=route)
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        if len(encoded) > 30000: raise ValueError()
        # The limited fixture owner owns this leaf.  Record the intent before
        # QGA dispatch so response loss cannot replay its scheduled task.
        if not _large_advance(root_path, record, (_env, socket, pid, ticks, sid), "download-submitted"):
            raise WindowsUpdateFixtureHttpStageError("Guest download phase is not reserved.")
        raw = base._remote(config, _REMOTE_QGA_DOWNLOAD, (socket, str(pid), str(ticks), sid, corr, encoded), None, 180)
        observed = json.loads(raw) if raw is not None else None
        if observed != {"state": "submitted"}: raise ValueError()
    except (OSError, ValueError, TypeError, WindowsUpdateFixtureHttpStageError, base.WindowsMsiBasePrepareError):
        return {**_UNKNOWN, "correlationId": corr}
    return {"state": "submitted", "correlationId": corr, "replayAllowed": False}


def stage_extract(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or not _canonical(value.get("correlationId")):
        raise WindowsUpdateFixtureHttpStageError("Fixture extraction requires exact correlationId.")
    corr = value["correlationId"]
    try:
        root_path, record, config, target = _record(root, corr)
        descriptor = base._descriptor(root_path)[2]
        _env, socket, pid, ticks, sid = descriptor
        # Existing script is the sole source of extraction, file-hash and ACL rules.
        # A caller supplies stage's immutable file hashes through its private intent.
        stage_intent = stage._read_intent(root_path, corr)
        if stage_intent is None or stage_intent.get("bundleSha256") != record["bundleSha256"]: raise ValueError()
        script = stage._stage_script(corr, sid, stage_intent["fileHashes"], record["bundleSha256"])
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        binding = base64.b64encode(json.dumps(_authority_binding(record, descriptor), sort_keys=True,
                                              separators=(",", ":")).encode()).decode("ascii")
        if len(encoded) > 30000: raise ValueError()
        # Reserve the SYSTEM placement before QGA accepts it.  The subsequent
        # stage.status receipt, not this intent, remains proof of ACL/hash
        # placement after a lost response.
        if (not _large_advance(root_path, record, descriptor, "downloaded")
                or not _large_advance(root_path, record, descriptor, "placed")):
            raise WindowsUpdateFixtureHttpStageError("Placement phase is not reserved.")
        raw = base._remote(config, _REMOTE_QGA_STAGE_EXTRACT,
                           (str(target.fixture_transfer_root), _env, corr, socket, str(pid), str(ticks), encoded, binding),
                           None, 180)
        observed = {"state": "staged"} if raw == b'{"state":"staged"}\n' or raw == b'{"state":"staged"}' else dict(_UNKNOWN)
    except (OSError, ValueError, KeyError, WindowsUpdateFixtureHttpStageError, stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError):
        observed = dict(_UNKNOWN)
    return {**observed, "correlationId": corr, "replayAllowed": False}


# The placement invocation below can lose its final response after it has
# written ``dispatch.json``.  Do not call ``stage_extract`` again in that
# case: its one-shot reservation has already crossed the dispatch boundary.
# ``stage.diagnose`` is the existing QGA observer for precisely this journal.
# It verifies the frozen source/guest binding, observes the recorded QGA child
# through guest-exec-status, checks bounded exit/output metadata, and only then
# reads the bounded stage receipt.  This adapter adds the HTTP bundle and
# large-transfer bindings, so an unrelated stage journal cannot be inspected
# through the HTTP route.
_STAGE_EXTRACT_DIAGNOSTIC_PHASES = frozenset({
    "local-binding-invalid", "not-placed", "remote-layout-invalid",
    "remote-stage-absent", "remote-stage-partial", "remote-binding-mismatch",
    "remote-dispatch-malformed", "guest-stage-absent", "guest-stage-partial",
    "guest-stage-full", "guest-stage-probe-failed", "dispatch-status-unknown",
    "receipt-pending", "receipt-absent", "result-read-failed", "receipt-invalid",
    "receipt-present-unverified", "qga-protocol",
})


def stage_extract_diagnostic(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read one uncertain extraction without replaying its QGA dispatch.

    The response intentionally contains only the fixed public observer phase;
    no process id, guest path, output, receipt data, or host endpoint is
    surfaced.  A successful receipt is still reconciled only by ``collect``.
    """
    if (not isinstance(value, Mapping) or set(value) != {"correlationId"}
            or not _canonical(value.get("correlationId"))):
        raise WindowsUpdateFixtureHttpStageError("Fixture extraction diagnostic requires exact correlationId.")
    corr = value["correlationId"]
    result = {"state": "diagnosed", "correlationId": corr, "binding": "unverified",
              "phase": "local-binding-invalid", "replayAllowed": False,
              "nativeActionAllowed": False, "productAction": False}
    try:
        root_path, record, _config, _target = _record(root, corr)
        core = large_transfer.read(root_path, corr)
        if core is None or core.get("phase") != "placed":
            return {**result, "binding": "exact", "phase": "not-placed"}
        observed = stage.diagnose(root_path, {"correlationId": corr})
    except (OSError, ValueError, TypeError, KeyError, WindowsUpdateFixtureHttpStageError,
            stage.WindowsUpdateFixtureStageError, base.WindowsMsiBasePrepareError,
            large_transfer.WindowsLargeArtifactTransferError):
        return result
    if (not isinstance(observed, Mapping) or set(observed) != {
            "state", "correlationId", "binding", "phase", "replayAllowed", "nativeActionAllowed"}
            or observed.get("state") != "unknown" or observed.get("correlationId") != corr
            or observed.get("binding") not in {"exact", "mismatch", "unverified"}
            or observed.get("phase") not in _STAGE_EXTRACT_DIAGNOSTIC_PHASES
            or observed.get("replayAllowed") is not False or observed.get("nativeActionAllowed") is not False):
        return result
    return {**result, "binding": observed["binding"], "phase": observed["phase"]}


_PHASES = {
    "status": status, "stage-start": stage_start, "listener-start": listener_start,
    "listener-status": listener_status, "guest-create": guest_create,
    "guest-download": guest_download, "stage-extract": stage_extract,
    "collect": collect, "cleanup": cleanup,
}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Fixed adapter entry point for the remote ZIP and guest dispatch phases.

    The caller cannot select a path, port, account, endpoint, or file hash.  All
    phases after preparation accept only their durable correlation, which keeps
    response-loss reconciliation bounded to the frozen source receipt.
    """
    if not isinstance(action, str) or not isinstance(inputs, Mapping):
        raise WindowsUpdateFixtureHttpStageError("Invalid HTTP fixture workflow request.")
    if action == "prepare":
        return prepare(root, inputs)
    if action == "prepare-diagnostic":
        return prepare_diagnostic(root, inputs)
    if action == "bundle-diagnostic":
        return bundle_diagnostic(root, inputs)
    if action == "reserve-diagnostic":
        return reserve_diagnostic(root, inputs)
    if action == "prior-stage-confirmation":
        return prior_stage_confirmation(root, inputs)
    if action == "stage-start-diagnostic":
        return stage_start_diagnostic(root, inputs)
    if action == "host-staged-pre-effect-diagnostic":
        return host_staged_pre_effect_diagnostic(root, inputs)
    if action == "host-stage-probe":
        return host_stage_probe(root, inputs)
    if action == "guest-create-diagnostic":
        return guest_create_diagnostic(root, inputs)
    if action == "guest-download-diagnostic":
        return guest_download_diagnostic(root, inputs)
    if action == "stage-extract-diagnostic":
        return stage_extract_diagnostic(root, inputs)
    if action == "host-staged-pre-effect-close":
        return host_staged_pre_effect_close(root, inputs)
    if action == "e66-pre-effect-recovery":
        return e66_pre_effect_recovery(root, inputs)
    if action == "e66-retire-aborted-stage-status":
        return e66_retire_aborted_stage_status(root, inputs)
    if action == "e66-retire-aborted-stage":
        return e66_retire_aborted_stage(root, inputs)
    method = _PHASES.get(action)
    if method is None or set(inputs) != {"correlationId"}:
        raise WindowsUpdateFixtureHttpStageError("HTTP fixture phase requires exact correlationId.")
    return method(root, inputs)
