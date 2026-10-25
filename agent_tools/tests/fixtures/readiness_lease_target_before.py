"""Finite, temporary keep-awake leases owned outside the client/server lifetime.

The public API never accepts program source or a command. A lease is a durable
job with its original UUID and machine binding; a disconnect only observes that
job. Cancellation publishes a correlated request, never signals an arbitrary PID.
macOS assertions are process scoped and additionally timed. Android changes only
``stay_on_while_plugged_in``, journals its original value before applying it, and
restores it with a compare-before-write guard. Credential locking and automatic
sign-in settings are never changed. Native qualification is recorded separately;
the capability table does not assert that a provider was tested.

Windows needs a Windows durable execution owner before a process-scoped execution
state assertion can safely be admitted. Headless Linux has no GUI lease.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any
import uuid

from . import durable_remote_job as jobs

MAX_TTL_SECONDS = 18_000
ADB_PATHS = frozenset({"/opt/homebrew/share/android-commandlinetools/platform-tools/adb",
                       "/usr/bin/adb", "/opt/android-sdk/platform-tools/adb"})
PROVIDERS = {
    "native-macos": {"backend": "macos", "available": True, "reason": "local_process_scoped_assertions"},
    "tart-macos": {"backend": None, "available": False, "reason": "bound_guest_executor_required"},
    "android-emulator": {"backend": "android", "available": True, "reason": "journaled_bridge_setting"},
    "raw-qemu-windows": {"backend": None, "available": False, "reason": "windows_durable_owner_required"},
    "libvirt-windows": {"backend": None, "available": False, "reason": "windows_durable_owner_required"},
    "raw-qemu-linux": {"backend": None, "available": False, "reason": "headless_no_gui_lease"},
    "tart-linux": {"backend": None, "available": False, "reason": "headless_no_gui_lease"},
}


class LeaseError(ValueError):
    """Finite public reason; no subprocess stderr or private path is exposed."""


def _need(condition: bool, reason: str) -> None:
    if not condition:
        raise LeaseError(reason)


@dataclass(frozen=True)
class LeaseSpec:
    provider: str
    ttl_seconds: float
    adb_path: str | None = None
    adb_serial: str | None = None
    adb_port: int = 5037
    guest_boot: str | None = None
    guest_avd: str | None = None

    def __post_init__(self):
        _need(type(self.provider) is str and self.provider in PROVIDERS, "provider_invalid")
        _need(type(self.ttl_seconds) in (int, float) and math.isfinite(self.ttl_seconds)
              and 0.1 <= self.ttl_seconds <= MAX_TTL_SECONDS, "lease_ttl_invalid")
        _need(type(self.adb_port) is int and 1 <= self.adb_port <= 65535, "adb_port_invalid")
        if self.provider == "android-emulator":
            _need(type(self.adb_path) is str and self.adb_path in ADB_PATHS, "adb_path_invalid")
            _need(type(self.adb_serial) is str and
                  bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.adb_serial)), "adb_serial_invalid")
            try:
                _need(type(self.guest_boot) is str and str(uuid.UUID(self.guest_boot)) == self.guest_boot,
                      "guest_boot_invalid")
            except (ValueError, TypeError, AttributeError):
                raise LeaseError("guest_boot_invalid") from None
            _need(type(self.guest_avd) is str and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.guest_avd)),
                  "guest_avd_invalid")
        else:
            _need(self.adb_path is None and self.adb_serial is None and self.adb_port == 5037
                  and self.guest_boot is None and self.guest_avd is None,
                  "unexpected_adb_parameters")


def capabilities(provider: str) -> dict[str, Any]:
    _need(provider in PROVIDERS, "provider_invalid")
    return {"provider": provider, **PROVIDERS[provider], "nativeAcceptanceRequired": True,
            "credentialLockingChanged": False, "automaticSignInChanged": False}


def native_macos_binding() -> jobs.MachineBinding:
    """Bind the actual executing Mac; this never represents a remote Tart VM."""
    _need(sys.platform == "darwin", "lease_platform_mismatch")
    try:
        result = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                                close_fds=True, env={"PATH": os.defpath})
        _need(result.returncode == 0 and len(result.stdout) <= 262144 and len(result.stderr) <= 1024,
              "native_machine_identity_unavailable")
        matches = re.findall(rb'"IOPlatformUUID"\s*=\s*"([A-Fa-f0-9-]{36})"', result.stdout)
        _need(len(matches) == 1, "native_machine_identity_unavailable")
        machine = "native-macos-" + str(uuid.UUID(matches[0].decode("ascii")))
        return jobs.current_binding("native-macos-local", machine)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise LeaseError("native_machine_identity_unavailable") from None


def _config(spec: LeaseSpec) -> dict[str, Any]:
    item = PROVIDERS[spec.provider]
    _need(item["available"], item["reason"])
    backend = item["backend"]
    _need(os.name == "posix", "durable_owner_platform_unsupported")
    if backend == "macos":
        _need(sys.platform == "darwin", "lease_platform_mismatch")
    return {"backend": backend, "ttlSeconds": spec.ttl_seconds,
            "adbPath": spec.adb_path, "adbSerial": spec.adb_serial, "adbPort": spec.adb_port,
            "guestBoot": spec.guest_boot, "guestAvd": spec.guest_avd}


def _program(root: Path, operation_id: str, binding: jobs.MachineBinding,
             config: dict[str, Any]) -> jobs.Program:
    # Both snapshots are fixed adapter source. Only bounded, validated identifiers
    # and paths are data; no credentials, environment or arbitrary argv enter it.
    payload = {**config, "job": str(root / operation_id), "operationId": operation_id,
               "binding": jobs.asdict(binding)}
    from .readiness_lease_reconciliation import _RESTORED_HISTORY
    source = ("import sys, types\nM = types.ModuleType('durable_lease_snapshot')\n"
              "sys.modules[M.__name__] = M\nD = M.__dict__\nexec(" + repr(jobs.owner_source()) + ", D)\n" +
              _RESTORED_HISTORY + _OWNER + "\nlease_run(" + repr(payload) + ")\n").encode()
    return jobs.Program("temporary-keep-awake-v1", source, stream_limit=4096)


def acquire(root: Path | str, operation_id: str, binding: jobs.MachineBinding, spec: LeaseSpec, *,
            generation: tuple[int, int]) -> dict[str, Any]:
    """At-most-once admission. Repeat only observes the same source-bound job."""
    config = _config(spec)
    if spec.provider == "native-macos":
        _need(binding == native_macos_binding(), "native_machine_binding_mismatch")
    root = jobs._root(root, generation)
    operation_id = jobs._uuid(operation_id)
    jobs.submit(root, operation_id, binding, _program(root, operation_id, binding, config), generation=generation)
    return inspect(root, operation_id, binding, generation=generation)


def _lease_record(root: Path, operation_id: str, binding: jobs.MachineBinding,
                  filename: str) -> dict[str, Any]:
    job = root / operation_id
    intent = jobs._intent(job, operation_id, binding)
    value = jobs._record(job / filename)
    jobs._correlate(value, intent)
    _need(type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1, "lease_record_invalid")
    return value


def inspect(root: Path | str, operation_id: str, binding: jobs.MachineBinding, *,
            generation: tuple[int, int]) -> dict[str, Any]:
    """Observation only, including after client death or a server restart."""
    status = jobs.observe(root, operation_id, binding, generation=generation)
    result = {"schemaVersion": 1, "operationId": operation_id, "jobState": status["state"],
              "state": "unknown", "reason": status["reason"], "replayAllowed": False,
              "nextAction": "observe_original"}
    if status["state"] == "unsubmitted":
        result.update(state="unsubmitted", nextAction="prepare_original")
        return result
    try:
        path = jobs._root(root, generation)
        job = path / jobs._uuid(operation_id)
        if (job / "lease-terminal.json").exists():
            receipt = _lease_record(path, operation_id, binding, "lease-terminal.json")
            _need(set(receipt) == {"operationId", "generation", "binding", "programSha256", "schemaVersion",
                                  "state", "reason", "restored", "acquired", "leaseOwner"}
                  and receipt.get("state") in {"expired", "cancelled", "failed", "restore_blocked"}
                  and type(receipt.get("restored")) is bool and type(receipt.get("acquired")) is bool
                  and receipt.get("reason") in {"lease_deadline_reached", "original_lease_cancelled",
                                                "lease_acquisition_failed", "lease_execution_failed",
                                                "lease_resource_busy", "lease_previous_restoration_unknown",
                                                "original_setting_restoration_unverified"},
                  "lease_record_invalid")
            result.update(state=receipt["state"], reason=receipt["reason"], restored=receipt["restored"],
                          nextAction=("none" if receipt["restored"] and receipt["state"] != "failed" else
                                      "resolve_lease_blocker" if receipt["restored"] else "resolve_restoration_blocker"))
            if receipt["restored"] and status["state"] == "running":
                # The settings receipt precedes the durable wrapper's final
                # retained-stream receipt. Keep observing that original owner.
                result["nextAction"] = "observe_original"
            elif receipt["restored"] and status["state"] == "unknown":
                result.update(state="unknown", reason="lease_restored_job_result_unknown", nextAction="resolve_blocker")
        elif (job / "lease-acquired.json").exists():
            acquired = _lease_record(path, operation_id, binding, "lease-acquired.json")
            _need(set(acquired) == {"operationId", "generation", "binding", "programSha256", "schemaVersion",
                                   "backend", "leaseOwner", "helper", "ttlSeconds"}
                  and type(acquired.get("leaseOwner")) is dict and set(acquired["leaseOwner"]) == {"pid", "birth"}
                  and type(acquired["leaseOwner"].get("pid")) is int and acquired["leaseOwner"]["pid"] > 0
                  and type(acquired["leaseOwner"].get("birth")) is str,
                  "lease_record_invalid")
            owner = acquired["leaseOwner"]
            if status["state"] == "running" and jobs._birth(owner["pid"]) == owner["birth"]:
                result.update(state="active", reason="original_lease_owner_running")
            else:
                result.update(reason="lease_owner_missing", nextAction="resolve_restoration_blocker")
        if result["state"] == "restore_blocked" and status["state"] == "terminal":
            from .readiness_lease_reconciliation import overlay
            return overlay(result, root, operation_id, binding, generation=generation)
        return result
    except (OSError, ValueError, TypeError, KeyError):
        result.update(state="unknown", reason="lease_record_unavailable")
        return result


def cancel(root: Path | str, operation_id: str, binding: jobs.MachineBinding, *,
           generation: tuple[int, int]) -> dict[str, Any]:
    """A correlated create-only request; acknowledgement is observation only."""
    root = jobs._root(root, generation)
    operation_id = jobs._uuid(operation_id)
    intent = jobs._intent(root / operation_id, operation_id, binding)
    jobs._binding_live(binding)
    request = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    request["schemaVersion"] = 1
    try:
        jobs._publish(root / operation_id / "lease-cancel.json", request)
    except FileExistsError:
        existing = _lease_record(root, operation_id, binding, "lease-cancel.json")
        _need(existing == request, "cancel_request_invalid")
    return inspect(root, operation_id, binding, generation=generation)


def _acquire_controlled(root: Path, operation_id: str, binding: jobs.MachineBinding, setting: Path, ttl: float, *,
                        generation: tuple[int, int]) -> dict[str, Any]:
    """Private deterministic fixture: one protected file, never executable input."""
    _need(type(ttl) in (int, float) and math.isfinite(ttl) and 0.1 <= ttl <= MAX_TTL_SECONDS, "lease_ttl_invalid")
    root = jobs._root(root, generation)
    jobs._private(setting, directory=False)
    _need(setting.is_absolute() and setting.resolve() == setting, "setting_invalid")
    config = {"backend": "controlled", "ttlSeconds": ttl, "setting": str(setting)}
    jobs.submit(root, operation_id, binding, _program(root, operation_id, binding, config), generation=generation)
    return inspect(root, operation_id, binding, generation=generation)


# Standalone snapshot executed inside the durable job's retained child. D is a
# snapshot of durable_remote_job and supplies its private-path/generation guards.
_OWNER = r'''
import fcntl, hashlib, json, math, os, re, subprocess, sys, time
from pathlib import Path

def lease_run(config):
    job = Path(config["job"])
    binding = D["MachineBinding"].from_dict(config["binding"])
    intent = D["_intent"](job, config["operationId"], binding)
    D["_binding_live"](binding)
    correlation = {key: intent[key] for key in ("operationId", "generation", "binding", "programSha256")}
    correlation["schemaVersion"] = 1
    identity = {"pid": os.getpid(), "birth": D["_birth"](os.getpid())}
    D["_need"](identity["birth"] is not None, "lease_owner_generation_unavailable")
    backend = config["backend"]
    helper = None
    helper_birth = None
    original = None
    applied = "7" if backend == "android" else "awake"
    acquired = False
    lock_fd = None
    state, reason, restored = "failed", "lease_acquisition_failed", True
    deadline = time.monotonic() + config["ttlSeconds"]

    def command(tail, shell=True):
        # Fixed adb executable set is validated before admission. The target
        # serial is passed as one argument; no shell interpolation is involved.
        # Explicit remote-host mode never starts an adb server if the owned
        # listener disappears after admission; loopback alone is insufficient.
        argv = [config["adbPath"], "-H", "127.0.0.1", "-P", str(config["adbPort"]), "-s", config["adbSerial"]]
        argv += (["shell"] if shell else []) + tail
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
                                close_fds=True, env={"PATH": os.defpath})
        D["_need"](result.returncode == 0 and len(result.stdout) <= 1024 and len(result.stderr) <= 1024,
                    "android_setting_unavailable")
        return result.stdout.decode("ascii").strip()

    def android_identity():
        name = command(["emu", "avd", "name"], shell=False).splitlines()
        D["_need"](name == [config["guestAvd"], "OK"], "guest_identity_changed")
        D["_need"](command(["cat", "/proc/sys/kernel/random/boot_id"]) == config["guestBoot"],
                    "guest_boot_changed")

    def read_setting():
        if backend == "android":
            android_identity()
            value = command(["settings", "get", "global", "stay_on_while_plugged_in"])
            D["_need"](value == "null" or bool(re.fullmatch(r"[0-7]", value)), "android_setting_invalid")
            return value
        raw = D["_read"](Path(config["setting"]), 128).decode("ascii")
        D["_need"](raw in {"sleep", "awake"}, "controlled_setting_invalid")
        return raw

    def write_setting(value):
        if backend == "android":
            android_identity()
            if value == "null":
                command(["settings", "delete", "global", "stay_on_while_plugged_in"])
            else:
                command(["settings", "put", "global", "stay_on_while_plugged_in", value])
        else:
            path = Path(config["setting"])
            # Never follow an externally replaced symlink or rewrite the inode.
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                D["_need"]((info.st_dev, info.st_ino) == tuple(setting_generation), "controlled_setting_changed")
                os.ftruncate(fd, 0)
                os.write(fd, value.encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)

    try:
        if backend == "macos":
            D["_need"](sys.platform == "darwin", "lease_platform_mismatch")
            # -t bounds orphan lifetime; -w also releases when this exact child
            # dies. Neither changes persistent power/credential-lock settings.
            helper = subprocess.Popen(["/usr/bin/caffeinate", "-d", "-i", "-t",
                                       str(math.ceil(config["ttlSeconds"])), "-w", str(os.getpid())],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, close_fds=True,
                                      env={"PATH": os.defpath})
            time.sleep(0.05)
            helper_birth = D["_birth"](helper.pid)
            D["_need"](helper.poll() is None and helper_birth is not None, "assertion_owner_unavailable")
            original = "process_scoped"
        else:
            # Every configured target must reuse its pinned private lease root.
            # A separate lock inode is held through restoration. Its immutable
            # history refuses replacement after an uncertain prior owner death.
            resource = config["setting"] if backend == "controlled" else config["adbSerial"] + ":" + str(config["adbPort"])
            resource = hashlib.sha256((backend + ":" + resource).encode()).hexdigest()
            resource_dir = job.parent / ("lease-resource-" + resource)
            try:
                resource_dir.mkdir(mode=0o700)
                D["_sync_directory"](job.parent)
            except FileExistsError:
                pass
            D["_private"](resource_dir, directory=True)
            lock = resource_dir / "lock"
            try:
                D["_create"](lock, b"keep-awake-resource-lock-v1\n")
            except FileExistsError:
                pass
            info = D["_private"](lock, directory=False)
            lock_fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
            actual = os.fstat(lock_fd)
            D["_need"]((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino), "lease_resource_busy")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                D["_need"](False, "lease_resource_busy")
            history = list(resource_dir.iterdir())
            D["_need"](len(history) <= 10000, "lease_previous_restoration_unknown")
            for record in history:
                if record.name == "lock":
                    continue
                previous = D["_record"](record)
                old_job = job.parent / D["_uuid"](previous["operationId"])
                old_intent = D["_intent"](old_job, previous["operationId"], binding)
                D["_correlate"](previous, old_intent)
                terminal = old_job / "lease-terminal.json"
                D["_need"](terminal.exists(), "lease_previous_restoration_unknown")
                terminal_value = D["_record"](terminal)
                D["_correlate"](terminal_value, old_intent)
                if terminal_value.get("restored") is not True:
                    try:
                        lease_restored_history(old_job, binding)
                    except Exception:
                        D["_need"](False, "lease_previous_restoration_unknown")
            D["_publish"](resource_dir / (config["operationId"] + ".json"), correlation)
            if backend == "controlled":
                info = D["_private"](Path(config["setting"]), directory=False)
                setting_generation = (info.st_dev, info.st_ino)
            original = read_setting()
            # Original state is durable before any settings write. A lost
            # acquisition acknowledgement never permits a replacement lease.
            D["_publish"](job / "lease-original.json", {**correlation, "backend": backend,
                           "original": original, "applied": applied, "leaseOwner": identity})
            write_setting(applied)
            D["_need"](read_setting() == applied, "lease_apply_unverified")
        acquired = True
        D["_publish"](job / "lease-acquired.json", {**correlation, "backend": backend,
                       "leaseOwner": identity, "helper": None if helper is None else
                       {"pid": helper.pid, "birth": helper_birth}, "ttlSeconds": config["ttlSeconds"]})
        state, reason = "expired", "lease_deadline_reached"
        while time.monotonic() < deadline:
            cancel = job / "lease-cancel.json"
            if cancel.exists() or cancel.is_symlink():
                request = D["_record"](cancel)
                D["_correlate"](request, intent)
                D["_need"](set(request) == set(correlation), "cancel_request_invalid")
                state, reason = "cancelled", "original_lease_cancelled"
                break
            if helper is not None and helper.poll() is not None:
                D["_need"](False, "assertion_owner_ended_early")
            time.sleep(min(0.05, max(0, deadline-time.monotonic())))
    except Exception as error:
        state, reason = "failed", "lease_execution_failed"
        if isinstance(error, D["DurableJobError"]) and str(error) in {
                "lease_resource_busy", "lease_previous_restoration_unknown"}:
            reason = str(error)
    finally:
        try:
            if helper is not None:
                if helper.poll() is None:
                    D["_need"](D["_birth"](helper.pid) == helper_birth, "assertion_owner_changed")
                    helper.terminate()
                helper.wait(timeout=5)
            elif original is not None:
                current = read_setting()
                D["_need"](current in {original, applied}, "setting_changed_by_another_operator")
                if current != original:
                    write_setting(original)
                D["_need"](read_setting() == original, "restoration_unverified")
        except Exception:
            state, reason, restored = "restore_blocked", "original_setting_restoration_unverified", False
        receipt = {**correlation, "state": state, "reason": reason, "restored": restored,
                   "acquired": acquired, "leaseOwner": identity}
        D["_publish"](job / "lease-terminal.json", receipt)
        if lock_fd is not None:
            os.close(lock_fd)
        print(json.dumps({"state": state, "reason": reason, "restored": restored}, sort_keys=True))
'''
