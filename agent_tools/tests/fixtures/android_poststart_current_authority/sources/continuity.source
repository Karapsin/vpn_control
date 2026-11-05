"""Opt-in custody qualification for one original Android component operation.

This is an internal evidence primitive, not a lease-release API. A trusted
adapter authenticates the original anchor hashes and native host/filesystem and
remote observations before calling it. The returned receipt preserves the old
pins; it never teaches ordinary readers to ignore device numbers. The adapter
must retain those native probe bytes and revalidate immediately before effects.
"""
from __future__ import annotations

import hashlib
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import sys
import time
import uuid
from typing import Any

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_FILE_LIMIT = 8 * 1024 * 1024
_TOTAL_LIMIT = 64 * 1024 * 1024


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _token(value: Any) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _uuid(value: str) -> None:
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value,
              "continuity_operation_invalid")
    except (TypeError, AttributeError, ValueError):
        raise ValueError("continuity_operation_invalid") from None


def _absolute(value: Any) -> Path:
    _need(type(value) is str and "\x00" not in value,
          "continuity_path_invalid")
    path = Path(value)
    _need(path.is_absolute() and str(path) == value and
          all(part not in (".", "..") for part in path.parts),
          "continuity_path_invalid")
    return path


def _pin(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _integers(value: Any, length: int) -> bool:
    return (type(value) is list and len(value) == length and
            all(type(item) is int and item >= 0 for item in value))


def _decode(raw: bytes) -> Any:
    def unique(items):
        result = {}
        for key, value in items:
            _need(key not in result, "continuity_anchor_duplicate_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("continuity_anchor_invalid") from None


def _anchored(raw: bytes, expected: str, limit: int) -> None:
    _need(type(raw) is bytes and 0 < len(raw) <= limit and
          _digest(expected) and _sha(raw) == expected,
          "continuity_anchor_changed")


def _parent_names(path: Path) -> list[str]:
    names = ["/"]
    for part in path.parent.parts[1:]:
        names.append(str(Path(names[-1]) / part))
    return names


def _record(value: Any) -> tuple[Path, dict[str, Any]]:
    _need(type(value) is dict and set(value) == {"path", "pin"},
          "continuity_original_record_invalid")
    path = _absolute(value["path"])
    pin = value["pin"]
    _need(type(pin) is dict and set(pin) == {"generation", "parents", "sha256"},
          "continuity_original_record_invalid")
    generation = pin["generation"]
    _need(_integers(generation, 9) and stat.S_ISREG(generation[2]) and
          generation[0] > 0 and generation[1] > 0 and generation[5] == 1 and
          generation[6] <= _FILE_LIMIT and _digest(pin["sha256"]),
          "continuity_original_record_invalid")
    parents = pin["parents"]
    _need(type(parents) is dict and set(parents) == set(_parent_names(path)) and
          all(_integers(row, 5) and row[0] > 0 and row[1] > 0 and
              stat.S_ISDIR(row[2]) for row in parents.values()),
          "continuity_original_parents_invalid")
    return path, pin


def _device_only(original: list[int], current: list[int], before: int,
                 after: int) -> bool:
    # Other filesystems in the ancestry retain strict equality. This mapping
    # applies only to the explicitly anchored old device and this qualification.
    expected_device = after if original[0] == before else original[0]
    return current[0] == expected_device and current[1:] == original[1:]


def _fresh(value: Any, now: int, max_age: int) -> None:
    _need(type(value) is int and 0 < value <= now and now - value <= max_age,
          "continuity_observation_stale")


def _bindings(host: dict[str, Any], filesystem: dict[str, Any],
              proofs: list[dict[str, Any]], operation_id: str,
              now: int, max_age: int) -> list[dict[str, Any]]:
    _need(type(host) is dict and set(host) == {
        "machineId", "bootId", "uid", "observedAtNs", "probeSha256"} and
        _token(host["machineId"]) and _token(host["bootId"]) and
        type(host["uid"]) is int and host["uid"] == os.getuid() == os.geteuid() and
        _digest(host["probeSha256"]), "continuity_host_binding_invalid")
    _fresh(host["observedAtNs"], now, max_age)
    _need(type(filesystem) is dict and set(filesystem) == {
        "device", "fsid", "volumeId", "mountPoint", "observedAtNs", "probeSha256"} and
        type(filesystem["device"]) is int and filesystem["device"] > 0 and
        type(filesystem["fsid"]) is int and filesystem["fsid"] >= 0 and
        _token(filesystem["volumeId"]) and _digest(filesystem["probeSha256"]),
        "continuity_filesystem_binding_invalid")
    _absolute(filesystem["mountPoint"])
    _fresh(filesystem["observedAtNs"], now, max_age)
    _need(type(proofs) is list and 1 <= len(proofs) <= 16,
          "continuity_remote_proof_missing")
    result = []
    roles = set()
    for proof in proofs:
        _need(type(proof) is dict and set(proof) == {
            "role", "operationId", "observedAtNs", "sha256", "raw"} and
            _token(proof["role"]) and proof["role"] not in roles and
            proof["operationId"] == operation_id,
            "continuity_remote_proof_invalid")
        _fresh(proof["observedAtNs"], now, max_age)
        _anchored(proof["raw"], proof["sha256"], _FILE_LIMIT)
        roles.add(proof["role"])
        result.append({key: value for key, value in proof.items() if key != "raw"})
    return result


def qualify_records(manifest_raw: bytes, manifest_sha256: str,
                    operation_raw: bytes, operation_sha256: str,
                    operation_id: str, selected_paths: list[str], *,
                    host_binding: dict[str, Any],
                    filesystem_binding: dict[str, Any],
                    remote_proofs: list[dict[str, Any]],
                    max_age_ns: int = 120_000_000_000) -> dict[str, Any]:
    """Measure narrowly selected immutable records and retain both identities.

    Anchor hashes come from authenticated original-operation custody, not a
    public request. Host/filesystem probe hashes and complete remote proof bytes
    must already have passed the native adapter's authentication and predicates.
    This function checks freshness and their exact receipt binding, then measures
    current file/ancestor descriptors and the live filesystem ID independently.
    A receipt alone grants neither adoption, replay nor lease-release authority.
    """
    _need(os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
          hasattr(os, "O_DIRECTORY") and hasattr(os, "fstatvfs"),
          "continuity_posix_descriptors_required")
    _uuid(operation_id)
    _anchored(manifest_raw, manifest_sha256, 2 * 1024 * 1024)
    _anchored(operation_raw, operation_sha256, _FILE_LIMIT)
    _need(operation_id.encode() in operation_raw,
          "continuity_operation_anchor_mismatch")
    _need(type(max_age_ns) is int and 0 < max_age_ns <= 600_000_000_000,
          "continuity_age_bound_invalid")
    now = time.time_ns()
    proofs = _bindings(host_binding, filesystem_binding, remote_proofs,
                       operation_id, now, max_age_ns)
    manifest = _decode(manifest_raw)
    _need(type(manifest) is list and 1 <= len(manifest) <= 4096,
          "continuity_manifest_invalid")
    _need(type(selected_paths) is list and 1 <= len(selected_paths) <= 512 and
          all(type(path) is str for path in selected_paths) and
          len(set(selected_paths)) == len(selected_paths),
          "continuity_scope_invalid")
    selected = set(selected_paths)
    originals = {}
    seen = set()
    for row in manifest:
        _need(type(row) is dict and type(row.get("path")) is str and
              row["path"] not in seen, "continuity_manifest_invalid")
        seen.add(row["path"])
        if row["path"] in selected:
            path, pin = _record(row)
            originals[str(path)] = pin
    _need(set(originals) == selected, "continuity_scope_not_anchored")
    old_devices = {pin["generation"][0] for pin in originals.values()}
    _need(len(old_devices) == 1, "continuity_multiple_original_devices")
    before = next(iter(old_devices))
    after = filesystem_binding["device"]
    _need(before != after, "continuity_device_unchanged")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    held = []
    rows = []
    total = 0
    try:
        for name in sorted(originals):
            path = Path(name)
            expected = originals[name]
            _need(filesystem_binding["mountPoint"] in _parent_names(path),
                  "continuity_mount_scope_changed")
            chain = []
            fd = None
            try:
                directory = os.open("/", flags | os.O_DIRECTORY)
                chain.append(("/", directory))
                for part in path.parent.parts[1:]:
                    directory = os.open(part, flags | os.O_DIRECTORY,
                                        dir_fd=chain[-1][1])
                    chain.append((str(Path(chain[-1][0]) / part), directory))
                fd = os.open(path.name, flags, dir_fd=chain[-1][1])
                pin = _pin(os.fstat(fd))
                _need(_device_only(expected["generation"], pin, before, after),
                      "continuity_file_metadata_changed")
                _need(stat.S_ISREG(pin[2]) and pin[5] == 1 and
                      pin[3] == host_binding["uid"], "continuity_file_unsafe")
                _need(os.fstatvfs(fd).f_fsid == filesystem_binding["fsid"],
                      "continuity_filesystem_changed")
                parents = {parent: _pin(os.fstat(parent_fd))[:5]
                           for parent, parent_fd in chain}
                _need(all(_device_only(expected["parents"][parent], actual,
                                       before, after)
                          for parent, actual in parents.items()),
                      "continuity_parent_metadata_changed")
                chunks = []
                length = 0
                while True:
                    chunk = os.read(fd, min(65536, _FILE_LIMIT + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    _need(length <= _FILE_LIMIT, "continuity_file_bound")
                raw = b"".join(chunks)
                total += length
                _need(total <= _TOTAL_LIMIT and length == pin[6] and
                      _sha(raw) == expected["sha256"],
                      "continuity_file_bytes_changed")
                held.append((path, chain, fd, pin, parents))
                chain = []
                fd = None
                rows.append({"path": name, "originalPin": expected,
                             "currentPin": {"generation": pin, "parents": parents,
                                            "sha256": _sha(raw)}})
            finally:
                if fd is not None:
                    os.close(fd)
                for _, directory in reversed(chain):
                    os.close(directory)
        # Retain all descriptors until every read has finished; no later read
        # can exchange a prior file/parent without this final census noticing.
        for path, chain, fd, pin, parents in held:
            _need(_pin(os.fstat(fd)) == pin and
                  _pin(os.stat(path.name, dir_fd=chain[-1][1],
                               follow_symlinks=False)) == pin,
                  "continuity_file_changed")
            for parent, directory in chain:
                _need(_pin(os.fstat(directory))[:5] == parents[parent] and
                      _pin(os.stat(parent, follow_symlinks=False))[:5] == parents[parent],
                      "continuity_parent_changed")
        finished = time.time_ns()
        _bindings(host_binding, filesystem_binding, remote_proofs,
                  operation_id, finished, max_age_ns)
        receipt = {"schema": 1, "kind": "android-component-filesystem-continuity",
                   "originalOperationId": operation_id,
                   "anchors": {"manifestSha256": manifest_sha256,
                               "operationSha256": operation_sha256},
                   "hostBinding": host_binding, "filesystemBinding": filesystem_binding,
                   "remoteProofs": proofs, "deviceChange": {"original": before, "current": after},
                   "records": rows, "observedAtNs": finished,
                   "historicalPinsChanged": False, "adoptionGranted": False,
                   "releaseGranted": False, "replayAllowed": False}
        receipt = _decode(_canonical(receipt))
        return {**receipt, "receiptSha256": _sha(_canonical(receipt))}
    finally:
        for _, chain, fd, _, _ in reversed(held):
            os.close(fd)
            for _, directory in reversed(chain):
                os.close(directory)


def _measure_alias(path: Path, expected: dict[str, Any], fsid: int) -> dict[str, Any]:
    """Read one explicit alias without changing any historical identity."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    chain = []
    fd = None
    try:
        chain.append(("/", os.open("/", flags | os.O_DIRECTORY)))
        for part in path.parent.parts[1:]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=chain[-1][1])
            chain.append((str(Path(chain[-1][0]) / part), child))
        fd = os.open(path.name, flags, dir_fd=chain[-1][1])
        pin = _pin(os.fstat(fd))
        _need(pin == expected["generation"] and stat.S_ISREG(pin[2]) and
              pin[5] == 1 and 0 <= pin[6] <= _FILE_LIMIT and
              pin[3] == os.getuid(), "continuity_alias_file_changed")
        _need(os.fstatvfs(fd).f_fsid == fsid, "continuity_filesystem_changed")
        parents = {name: _pin(os.fstat(directory))[:5]
                   for name, directory in chain}
        chunks = []
        length = 0
        while True:
            part = os.read(fd, min(65536, _FILE_LIMIT + 1 - length))
            if not part:
                break
            chunks.append(part)
            length += len(part)
            _need(length <= _FILE_LIMIT, "continuity_file_bound")
        digest = _sha(b"".join(chunks))
        _need(length == pin[6] and digest == expected["sha256"] and
              _pin(os.fstat(fd)) == pin and
              _pin(os.stat(path.name, dir_fd=chain[-1][1], follow_symlinks=False)) == pin,
              "continuity_alias_file_changed")
        for name, directory in chain:
            _need(_pin(os.fstat(directory))[:5] == parents[name] and
                  _pin(os.stat(name, follow_symlinks=False))[:5] == parents[name],
                  "continuity_parent_changed")
        return {"generation": pin, "parents": parents, "sha256": digest}
    finally:
        if fd is not None:
            os.close(fd)
        for _, directory in reversed(chain):
            os.close(directory)


def validate_lease_receipt(receipt: dict[str, Any], lease_path: Path | str,
                           old_private8: dict[str, Any],
                           expected_fd9_pin: dict[str, Any], *,
                           max_age_ns: int = 120_000_000_000) -> dict[str, Any]:
    """Validate one qualified local lease and freshly measure its explicit alias.

    The sealed caller supplies the unchanged original admitted private8 item and
    the actual release primitive's current FD9 pin. A different path is allowed
    only for this same full file generation and content, with both explicit
    no-follow chains retained. This function does not authorize a remote release.
    """
    keys = {"schema", "kind", "originalOperationId", "anchors", "hostBinding",
            "filesystemBinding", "remoteProofs", "deviceChange", "records",
            "observedAtNs", "historicalPinsChanged", "adoptionGranted",
            "releaseGranted", "replayAllowed", "receiptSha256"}
    _need(type(receipt) is dict and set(receipt) == keys and
          type(receipt["schema"]) is int and receipt["schema"] == 1 and
          receipt["kind"] == "android-component-filesystem-continuity" and
          _digest(receipt["receiptSha256"]), "continuity_receipt_invalid")
    body = {key: value for key, value in receipt.items() if key != "receiptSha256"}
    _need(_sha(_canonical(body)) == receipt["receiptSha256"] and
          all(receipt[key] is False for key in
              ("historicalPinsChanged", "adoptionGranted", "releaseGranted", "replayAllowed")),
          "continuity_receipt_changed")
    _uuid(receipt["originalOperationId"])
    _need(type(max_age_ns) is int and 0 < max_age_ns <= 600_000_000_000,
          "continuity_age_bound_invalid")
    now = time.time_ns()
    _fresh(receipt["observedAtNs"], now, max_age_ns)
    host = receipt["hostBinding"]
    filesystem = receipt["filesystemBinding"]
    proofs = receipt["remoteProofs"]
    _need(type(host) is dict and type(filesystem) is dict and
          type(proofs) is list and 1 <= len(proofs) <= 16,
          "continuity_receipt_binding_invalid")
    _need(host.get("uid") == os.getuid() == os.geteuid(),
          "continuity_host_binding_invalid")
    for observation in [host, filesystem, *proofs]:
        _need(type(observation) is dict, "continuity_receipt_binding_invalid")
        _fresh(observation.get("observedAtNs"), now, max_age_ns)
    _need(all(proof.get("operationId") == receipt["originalOperationId"] and
              _digest(proof.get("sha256")) for proof in proofs),
          "continuity_remote_proof_invalid")
    rows = receipt["records"]
    _need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and
          set(rows[0]) == {"path", "originalPin", "currentPin"},
          "continuity_lease_scope_invalid")
    row = rows[0]
    qualified = _absolute(row["path"])
    release = _absolute(str(lease_path) if isinstance(lease_path, Path) else lease_path)
    _, original = _record({"path": row["path"], "pin": row["originalPin"]})
    _, current = _record({"path": row["path"], "pin": row["currentPin"]})
    mapping = receipt["deviceChange"]
    _need(type(mapping) is dict and set(mapping) == {"original", "current"} and
          all(type(value) is int and value > 0 for value in mapping.values()) and
          mapping["original"] != mapping["current"] and
          mapping["current"] == filesystem.get("device") and
          _device_only(original["generation"], current["generation"],
                       mapping["original"], mapping["current"]) and
          original["generation"][0] == mapping["original"] and
          original["sha256"] == current["sha256"] and
          all(_device_only(original["parents"][name], actual,
                           mapping["original"], mapping["current"])
              for name, actual in current["parents"].items()),
          "continuity_lease_mapping_changed")
    generation = original["generation"]
    projected = [generation[0], generation[1], generation[6], generation[7],
                 generation[8], stat.S_IMODE(generation[2]), generation[3], generation[5]]
    _need(type(old_private8) is dict and old_private8 == {
        "principal": "local-lease", "format": "private8",
        "generation": projected, "sha256": original["sha256"]},
        "continuity_original_lease_changed")
    _need(type(expected_fd9_pin) is dict and set(expected_fd9_pin) == {
        "generation", "parents", "sha256"} and
        expected_fd9_pin["generation"] == current["generation"] and
        expected_fd9_pin["sha256"] == current["sha256"],
        "continuity_current_lease_changed")
    measured = _measure_alias(qualified, current, filesystem["fsid"])
    _need(measured == current, "continuity_qualified_path_changed")
    alias = _measure_alias(release, current, filesystem["fsid"])
    alias_parents = [alias["parents"][name] for name in _parent_names(release) if name != "/"]
    _need(alias_parents == expected_fd9_pin["parents"],
          "continuity_release_parent_changed")
    return {"receiptSha256": receipt["receiptSha256"],
            "qualifiedPath": str(qualified), "releasePath": str(release),
            "originalPin": original, "currentPin": current, "releasePin": alias}


# This separate, source-owned campaign scope does not relax qualify_records or
# validate_lease_receipt. It cannot be selected or changed by a public request.
_API35_RELOCATION_SCOPE = {
    "operationId": "7310f227-aaed-4f3b-878a-1b7bf0b49215",
    "installerId": "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b",
    "manifestSha256": "30ead6e10e0cc5c6fef027a2cab984cd28bb52ae7fedeb5e68d59552ece6bbe8",
    "operationSha256": "982dd6db1743fa2b14a5bc79dc575551eab10a880db0db27860d0fafb34f94da",
    "leaseSha256": "44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a",
    "originalPath": "/Users/karapsin_de/Nextcloud/projects/vpn_control/.rag_index/android-native-device-leases/lease-archlinux-api35.json",
    "currentPath": "/Users/karapsin_de/projects/vpn_control/.rag_index/android-native-device-leases/lease-archlinux-api35.json",
    "originalMovedDirectory": "/Users/karapsin_de/Nextcloud/projects",
    "currentMovedDirectory": "/Users/karapsin_de/projects",
    "originalMovedMode": 0o40777,
    "currentMovedMode": 0o40755,
    "originalDevice": 16777234,
    "historicalLinkMode": 0o120755,
    "logicalPrefix": "/Users",
    "physicalPrefix": "/System/Volumes/Data/Users",
    "mountPoint": "/System/Volumes/Data",
    "firmlinkTablePath": "/usr/share/firmlinks",
    "firmlinkEntry": ["/Users", "Users"],
    "firmlinkTableUid": 0,
    "firmlinkTableGid": 0,
    "firmlinkTableMode": 0o100444,
    "mountUid": 0,
    "platform": "darwin",
}


@contextmanager
def _relocation_chain(path: Path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    chain = []
    try:
        _need(len(path.parts) <= 128, "relocated_lease_path_bound")
        chain.append(("/", os.open("/", flags)))
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=chain[-1][1])
            chain.append((str(Path(chain[-1][0]) / part), child))
        parents = {name: _pin(os.fstat(fd))[:5] for name, fd in chain}
        fsids = {name: os.fstatvfs(fd).f_fsid for name, fd in chain}
        def guard():
            for name, fd in chain:
                _need(_pin(os.fstat(fd))[:5] == parents[name] and
                      _pin(os.stat(name, follow_symlinks=False))[:5] == parents[name] and
                      os.fstatvfs(fd).f_fsid == fsids[name],
                      "relocated_lease_parent_changed")
        guard()
        yield chain, parents, fsids, guard
        guard()
    finally:
        for _, fd in reversed(chain):
            os.close(fd)


@contextmanager
def _relocation_file(path: Path, limit: int):
    with _relocation_chain(path.parent) as (chain, parents, fsids, guard_parents):
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=chain[-1][1])
        try:
            generation = _pin(os.fstat(fd))
            _need(stat.S_ISREG(generation[2]) and generation[5] == 1 and
                  0 < generation[6] <= limit, "relocated_lease_file_unsafe")
            chunks = []
            count = 0
            while True:
                part = os.read(fd, min(65536, limit + 1 - count))
                if not part:
                    break
                count += len(part)
                _need(count <= limit, "relocated_lease_file_bound")
                chunks.append(part)
            raw = b"".join(chunks)
            _need(len(raw) == generation[6], "relocated_lease_file_changed")
            fsid = os.fstatvfs(fd).f_fsid
            def guard():
                guard_parents()
                _need(_pin(os.fstat(fd)) == generation and
                      _pin(os.stat(path.name, dir_fd=chain[-1][1],
                                   follow_symlinks=False)) == generation and
                      os.fstatvfs(fd).f_fsid == fsid,
                      "relocated_lease_file_changed")
            record = {"generation": generation, "parents": parents,
                      "parentFilesystemIds": fsids, "sha256": _sha(raw),
                      "bytes": len(raw), "fsid": fsid}
            guard()
            yield raw, record, guard
            guard()
        finally:
            os.close(fd)


@contextmanager
def _relocation_link(path: Path):
    # The old entry is measured with lstat/readlink relative to the held parent.
    # It is never opened or followed to find the current lease.
    with _relocation_chain(path.parent) as (chain, parents, fsids, guard_parents):
        def read():
            before = _pin(os.stat(path.name, dir_fd=chain[-1][1], follow_symlinks=False))
            _need(stat.S_ISLNK(before[2]) and before[5] == 1,
                  "relocated_lease_historical_entry_invalid")
            target = os.readlink(path.name, dir_fd=chain[-1][1])
            _need(type(target) is str and 0 < len(os.fsencode(target)) <= 4096 and
                  "\x00" not in target, "relocated_lease_historical_target_invalid")
            _need(_pin(os.stat(path.name, dir_fd=chain[-1][1], follow_symlinks=False)) == before,
                  "relocated_lease_historical_entry_changed")
            guard_parents()
            return {"path": str(path), "generation": before, "target": target,
                    "parents": parents, "parentFilesystemIds": fsids}
        record = read()
        def guard():
            _need(read() == record, "relocated_lease_historical_entry_changed")
        yield record, guard
        guard()


def _relocation_diskutil(raw: bytes, binding: dict[str, Any], scope: dict[str, Any]) -> None:
    _anchored(raw, binding["probeSha256"], 65536)
    try:
        value = plistlib.loads(raw)
    except Exception:
        raise ValueError("relocated_lease_diskutil_invalid") from None
    _need(type(value) is dict and value.get("FilesystemType") == "apfs" and
          value.get("MountPoint") == scope["mountPoint"] == binding["mountPoint"] and
          type(value.get("VolumeUUID")) is str and
          value["VolumeUUID"].lower() == binding["volumeId"].lower() and
          type(value.get("DeviceIdentifier")) is str and
          re.fullmatch(r"disk[0-9]+s[0-9]+", value["DeviceIdentifier"]) is not None and
          value.get("DeviceNode") == "/dev/" + value["DeviceIdentifier"] and
          value.get("GlobalPermissionsEnabled") is True and
          value.get("WholeDisk") is False,
          "relocated_lease_diskutil_binding_changed")
    _uuid(binding["volumeId"].lower())


def _relocation_firmlink(raw: bytes, record: dict[str, Any], scope: dict[str, Any]) -> None:
    generation = record["generation"]
    _need(generation[2:6] == [scope["firmlinkTableMode"], scope["firmlinkTableUid"],
                              scope["firmlinkTableGid"], 1] and
          generation[2] & 0o222 == 0 and 0 < len(raw) <= 4096 and b"\x00" not in raw,
          "relocated_lease_firmlink_table_unsafe")
    expected = "\t".join(scope["firmlinkEntry"]).encode()
    selected = []
    for line in raw.splitlines():
        fields = line.split()
        if not fields or line.startswith(b"#"):
            continue
        _need(len(fields) == 2, "relocated_lease_firmlink_table_invalid")
        if fields[0].lstrip(b"/") == scope["firmlinkEntry"][0].encode().lstrip(b"/"):
            selected.append(line)
    _need(selected == [expected], "relocated_lease_firmlink_entry_changed")


def _relocation_verify_physical(raw: bytes, direct: dict[str, Any], physical_raw: bytes,
                                 physical_record: dict[str, Any], filesystem: dict[str, Any],
                                 scope: dict[str, Any]) -> None:
    """Application-controlled admission of already measured native alias facts."""
    logical = Path(scope["logicalPrefix"])
    physical_prefix = Path(scope["physicalPrefix"])
    _need(physical_record["generation"] == direct["generation"] and physical_raw == raw and
          physical_record["sha256"] == direct["sha256"] and
          physical_record["fsid"] == direct["fsid"] == filesystem["fsid"],
          "relocated_lease_physical_identity_changed")
    for name, pin in physical_record["parents"].items():
        path = Path(name)
        if path == physical_prefix or physical_prefix in path.parents:
            logical_name = str(logical / path.relative_to(physical_prefix))
            _need(direct["parents"].get(logical_name) == pin,
                  "relocated_lease_physical_ancestry_changed")
    mount = physical_record["parents"].get(scope["mountPoint"])
    _need(mount is not None and mount[0] == filesystem["device"] and
          mount[3] == scope["mountUid"] and stat.S_ISDIR(mount[2]) and mount[2] & 0o022 == 0 and
          physical_record["parentFilesystemIds"][scope["mountPoint"]] == filesystem["fsid"],
          "relocated_lease_physical_mount_changed")


def _relocation_measure(original: dict[str, Any], host: dict[str, Any],
                        filesystem: dict[str, Any], filesystem_probe_raw: bytes,
                        scope: dict[str, Any]) -> dict[str, Any]:
    _need(sys.platform == scope["platform"] and os.name == "posix" and
          hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and
          hasattr(os, "fstatvfs"), "relocated_lease_native_platform_required")
    original_path = _absolute(scope["originalPath"])
    current_path = _absolute(scope["currentPath"])
    moved_old = _absolute(scope["originalMovedDirectory"])
    moved_current = _absolute(scope["currentMovedDirectory"])
    logical = _absolute(scope["logicalPrefix"])
    physical_prefix = _absolute(scope["physicalPrefix"])
    _need(original_path.relative_to(moved_old) == current_path.relative_to(moved_current),
          "relocated_lease_source_scope_invalid")
    physical = physical_prefix / current_path.relative_to(logical)
    _relocation_diskutil(filesystem_probe_raw, filesystem, scope)
    before = scope["originalDevice"]
    after = filesystem["device"]
    generation = original["generation"]
    _need(generation[0] == before != after and generation[2] == 0o100600 and
          generation[3] == host["uid"] and generation[5:7] == [1, 121] and
          original["sha256"] == scope["leaseSha256"],
          "relocated_lease_original_leaf_changed")
    original_parents = original["parents"]
    moved_pin = original_parents[str(moved_old)]
    _need(moved_pin[0] == before and moved_pin[2] == scope["originalMovedMode"] and
          moved_pin[3:5] == generation[3:5], "relocated_lease_original_directory_changed")
    expected_parents = {}
    for name, pin in original_parents.items():
        path = Path(name)
        if path == moved_old or moved_old in path.parents:
            mapped = moved_current / path.relative_to(moved_old)
        elif name in _parent_names(current_path):
            mapped = path
        else:
            _need(path == moved_old.parent, "relocated_lease_original_ancestry_changed")
            continue
        expected = list(pin)
        if expected[0] == before:
            expected[0] = after
        if path == moved_old:
            expected[2] = scope["currentMovedMode"]
        expected_parents[str(mapped)] = expected
    _need(set(expected_parents) == set(_parent_names(current_path)),
          "relocated_lease_current_ancestry_changed")
    current_generation = [after, *generation[1:]]
    with _relocation_file(current_path, 1024) as (raw, direct, direct_guard), \
         _relocation_file(physical, 1024) as (physical_raw, physical_record, physical_guard), \
         _relocation_file(_absolute(scope["firmlinkTablePath"]), 4096) as (table, table_record, table_guard), \
         _relocation_link(moved_old) as (link, link_guard):
        _need(direct["generation"] == current_generation and direct["sha256"] == original["sha256"] and
              direct["parents"] == expected_parents and direct["fsid"] == filesystem["fsid"],
              "relocated_lease_current_identity_changed")
        _relocation_verify_physical(raw, direct, physical_raw, physical_record, filesystem, scope)
        _relocation_firmlink(table, table_record, scope)
        expected_link_parents = {name: pin for name, pin in original_parents.items()
                                 if name in _parent_names(moved_old)}
        _need(set(link["parents"]) == set(expected_link_parents) and
              all(_device_only(expected_link_parents[name], pin, before, after)
                  for name, pin in link["parents"].items()) and
              link["generation"][2:6] == [scope["historicalLinkMode"], generation[3], generation[4], 1] and
              link["target"] == str(moved_current),
              "relocated_lease_historical_entry_changed")
        for guard in (direct_guard, physical_guard, table_guard, link_guard):
            guard()
        current = {key: direct[key] for key in ("generation", "parents", "sha256")}
        return {"record": {"originalPath": str(original_path), "currentPath": str(current_path),
                           "originalPin": original, "currentPin": current},
                "relocation": {"originalDirectoryPath": str(moved_old),
                               "originalDirectoryPin": moved_pin,
                               "currentDirectoryPath": str(moved_current),
                               "currentDirectoryPin": direct["parents"][str(moved_current)],
                               "historicalEntry": link},
                "filesystemAlias": {"logicalPrefix": str(logical),
                                    "physicalPrefix": str(physical_prefix),
                                    "physicalPath": str(physical),
                                    "physicalPin": physical_record,
                                    "firmlinkTable": {"path": scope["firmlinkTablePath"],
                                                      **table_record},
                                    "firmlinkEntry": scope["firmlinkEntry"]}}


def qualify_relocated_api35_lease(manifest_raw: bytes, manifest_sha256: str,
                                  operation_raw: bytes, operation_sha256: str, *,
                                  host_binding: dict[str, Any],
                                  filesystem_binding: dict[str, Any],
                                  filesystem_probe_raw: bytes,
                                  remote_proofs: list[dict[str, Any]],
                                  max_age_ns: int = 120_000_000_000) -> dict[str, Any]:
    """Derive custody of only the fixed original API35 lease at its current path.

    This different receipt records a directory move, one exact permission
    tightening and the actual APFS firmlink relation. It neither qualifies the
    old symlink path for access nor changes the strict device-only primitive.
    Trusted native callers authenticate and retain all supplied probe bytes.
    """
    scope = _decode(_canonical(_API35_RELOCATION_SCOPE))
    _need(manifest_sha256 == scope["manifestSha256"] and
          operation_sha256 == scope["operationSha256"],
          "relocated_lease_anchor_scope_changed")
    _anchored(manifest_raw, manifest_sha256, 2 * 1024 * 1024)
    _anchored(operation_raw, operation_sha256, _FILE_LIMIT)
    _need(scope["operationId"].encode() in operation_raw and
          scope["installerId"].encode() in operation_raw,
          "relocated_lease_operation_anchor_changed")
    _need(type(max_age_ns) is int and 0 < max_age_ns <= 600_000_000_000,
          "continuity_age_bound_invalid")
    now = time.time_ns()
    proofs = _bindings(host_binding, filesystem_binding, remote_proofs,
                       scope["operationId"], now, max_age_ns)
    manifest = _decode(manifest_raw)
    _need(type(manifest) is list and 1 <= len(manifest) <= 4096,
          "relocated_lease_manifest_invalid")
    matches = [row for row in manifest if type(row) is dict and row.get("path") == scope["originalPath"]]
    _need(len(matches) == 1, "relocated_lease_original_scope_missing")
    _, original = _record(matches[0])
    measured = _relocation_measure(original, host_binding, filesystem_binding,
                                   filesystem_probe_raw, scope)
    finished = time.time_ns()
    _bindings(host_binding, filesystem_binding, remote_proofs,
              scope["operationId"], finished, max_age_ns)
    receipt = {"schema": 1, "kind": "android-component-relocated-api35-lease-custody",
               "originalOperationId": scope["operationId"],
               "originalInstallerId": scope["installerId"],
               "scopeSha256": _sha(_canonical(scope)),
               "anchors": {"manifestSha256": manifest_sha256, "operationSha256": operation_sha256},
               "hostBinding": host_binding, "filesystemBinding": filesystem_binding,
               "filesystemProbeBase64": base64.b64encode(filesystem_probe_raw).decode(),
               "remoteProofs": proofs, "records": [measured["record"]],
               "relocation": measured["relocation"], "filesystemAlias": measured["filesystemAlias"],
               "observedAtNs": finished, "historicalPinsChanged": False,
               "adoptionGranted": False, "releaseGranted": False, "replayAllowed": False}
    receipt = _decode(_canonical(receipt))
    return {**receipt, "receiptSha256": _sha(_canonical(receipt))}


def validate_relocated_lease_receipt(receipt: dict[str, Any], lease_path: Path | str,
                                     old_private8: dict[str, Any],
                                     expected_fd9_pin: dict[str, Any], *,
                                     max_age_ns: int = 120_000_000_000) -> dict[str, Any]:
    """Reobserve the fixed current path without rewriting the original proof."""
    scope = _decode(_canonical(_API35_RELOCATION_SCOPE))
    keys = {"schema", "kind", "originalOperationId", "originalInstallerId", "scopeSha256",
            "anchors", "hostBinding", "filesystemBinding", "filesystemProbeBase64",
            "remoteProofs", "records", "relocation", "filesystemAlias", "observedAtNs",
            "historicalPinsChanged", "adoptionGranted", "releaseGranted", "replayAllowed",
            "receiptSha256"}
    _need(type(receipt) is dict and set(receipt) == keys and
          type(receipt["schema"]) is int and receipt["schema"] == 1 and
          receipt["kind"] == "android-component-relocated-api35-lease-custody" and
          _digest(receipt["receiptSha256"]), "relocated_lease_receipt_invalid")
    body = {key: value for key, value in receipt.items() if key != "receiptSha256"}
    _need(_sha(_canonical(body)) == receipt["receiptSha256"] and
          receipt["scopeSha256"] == _sha(_canonical(scope)) and
          receipt["originalOperationId"] == scope["operationId"] and
          receipt["originalInstallerId"] == scope["installerId"] and
          receipt["anchors"] == {key: scope[key] for key in ("manifestSha256", "operationSha256")} and
          all(receipt[key] is False for key in
              ("historicalPinsChanged", "adoptionGranted", "releaseGranted", "replayAllowed")),
          "relocated_lease_receipt_changed")
    _need(type(max_age_ns) is int and 0 < max_age_ns <= 600_000_000_000,
          "continuity_age_bound_invalid")
    now = time.time_ns()
    _fresh(receipt["observedAtNs"], now, max_age_ns)
    for observation in [receipt["hostBinding"], receipt["filesystemBinding"], *receipt["remoteProofs"]]:
        _need(type(observation) is dict, "relocated_lease_receipt_binding_invalid")
        _fresh(observation.get("observedAtNs"), now, max_age_ns)
    _need(receipt["hostBinding"].get("uid") == os.getuid() == os.geteuid() and
          type(receipt["remoteProofs"]) is list and 1 <= len(receipt["remoteProofs"]) <= 16 and
          all(proof.get("operationId") == scope["operationId"] and _digest(proof.get("sha256"))
              for proof in receipt["remoteProofs"]), "relocated_lease_receipt_binding_invalid")
    _need(str(lease_path) == scope["currentPath"] and type(receipt["records"]) is list and
          len(receipt["records"]) == 1, "relocated_lease_release_scope_changed")
    row = receipt["records"][0]
    _need(type(row) is dict and set(row) == {"originalPath", "currentPath", "originalPin", "currentPin"} and
          row["originalPath"] == scope["originalPath"] and row["currentPath"] == scope["currentPath"],
          "relocated_lease_release_scope_changed")
    _, original = _record({"path": row["originalPath"], "pin": row["originalPin"]})
    generation = original["generation"]
    projected = [generation[0], generation[1], generation[6], generation[7], generation[8],
                 stat.S_IMODE(generation[2]), generation[3], generation[5]]
    _need(old_private8 == {"principal": "local-lease", "format": "private8",
                          "generation": projected, "sha256": original["sha256"]},
          "continuity_original_lease_changed")
    try:
        _need(type(receipt["filesystemProbeBase64"]) is str and
              len(receipt["filesystemProbeBase64"]) <= 90000, "relocated_lease_probe_bound")
        probe = base64.b64decode(receipt["filesystemProbeBase64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("relocated_lease_probe_invalid") from None
    measured = _relocation_measure(original, receipt["hostBinding"], receipt["filesystemBinding"], probe, scope)
    _need(measured == {"record": row, "relocation": receipt["relocation"],
                       "filesystemAlias": receipt["filesystemAlias"]},
          "relocated_lease_current_custody_changed")
    current = measured["record"]["currentPin"]
    parents = [current["parents"][name] for name in _parent_names(Path(scope["currentPath"])) if name != "/"]
    _need(expected_fd9_pin == {"generation": current["generation"], "parents": parents,
                              "sha256": current["sha256"]},
          "continuity_current_lease_changed")
    finished = time.time_ns()
    for observation in [receipt["hostBinding"], receipt["filesystemBinding"], *receipt["remoteProofs"]]:
        _fresh(observation["observedAtNs"], finished, max_age_ns)
    return {"receiptSha256": receipt["receiptSha256"], "originalPin": original,
            "currentPin": current, "qualifiedPath": scope["originalPath"],
            "releasePath": scope["currentPath"], "releasePin": current}
