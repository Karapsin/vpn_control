"""Internal state-bound Mac display wake; no provider capability is implied.

The fixed LEFT_SHIFT pair is admitted only from an authenticated ordinary
console session whose display is positively sleeping.  A lost acknowledgement
is observation-only.  This module never unlocks a session, reads an ordinary
password, changes settings, or sends periodic input.
"""
from __future__ import annotations

from contextlib import contextmanager

import hashlib
import json
import math
import os
from pathlib import Path
import sys
import stat
import time
from uuid import UUID

from . import private_inventory_lock as private
from . import readiness
from . import readiness_tart_vnc as rfb

NATIVE_QUALIFIED = False
_EXECUTING_CODE = sys._getframe().f_code


class WakeBlocked(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise WakeBlocked(reason)


def _id(value):
    try:
        _need(type(value) is str and str(UUID(value)) == value, "macos_wake_operation_invalid")
    except (ValueError, AttributeError, TypeError):
        raise WakeBlocked("macos_wake_operation_invalid") from None
    return value


def _binding(observed):
    _need(type(observed) is readiness.Observation and observed.trusted and observed.owned
          and observed.integrity and not observed.coordinator_host
          and observed.transport == "ready" and observed.guest == "running"
          and observed.guest_agent and observed.ordinary_session in {"ready", "locked"}
          and all(type(getattr(observed, key)) is str and getattr(observed, key)
                  for key in ("target", "machine", "connection", "boot", "account", "session")),
          "macos_wake_session_unrecognized")
    return {key: getattr(observed, key) for key in
            ("target", "machine", "connection", "boot", "account", "session")}


def _publish(directory, name, value):
    directory.guard()
    # The held directory fd prevents path replacement redirecting the record.
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory.fd)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
        stream.flush(); os.fsync(stream.fileno())
    os.fsync(directory.fd)
    directory.guard()


def _read(directory, name):
    directory.guard()
    try:
        with private.Snapshot(directory, name) as snapshot:
            return json.loads(snapshot.body)
    except FileNotFoundError:
        return None


def status(backend, operation_id, *, deadline):
    """Observe the original phase and actual display; never repeat its input."""
    operation_id = _id(operation_id)
    with backend.operation_scope(deadline=deadline):
        with private.Directory(backend.custody.lifecycle_root) as held:
            original = _read(held, "macos-wake-" + operation_id + ".json")
            if original is None:
                return {"operationId": operation_id, "state": "unsubmitted"}
            current = backend.observe(readiness.Requirements(frozenset({"guest_agent"})), deadline)
            _need(_binding(current) == original["binding"], "macos_wake_identity_changed")
            return {"operationId": operation_id, "state": "observed_ready" if current.display == "ready" else "unknown",
                    "display": current.display, "ordinarySession": current.ordinary_session,
                    "replacementForbidden": True}


@contextmanager
def _held_source():
    """Pin this executing producer until the original input group is closed."""
    path = Path(__file__)
    presented = private.PresentedPath(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
              and info.st_nlink == 1 and not info.st_mode & 0o022 and 0 < info.st_size <= 131072,
              "macos_wake_source_unsafe")
        generation = private._generation(info)
        raw = os.read(fd, info.st_size + 1)
        _need(len(raw) == info.st_size and _EXECUTING_CODE == compile(raw, __file__, "exec",
              dont_inherit=True, optimize=sys.flags.optimize), "macos_wake_source_changed")
        def guard():
            presented.guard()
            _need(private._generation(os.fstat(fd)) == private._generation(path.lstat()) == generation,
                  "macos_wake_source_changed")
        guard()
        yield guard
    finally:
        os.close(fd)


def wake_once(backend, operation_id, *, deadline):
    with _held_source() as source_guard:
        return _wake_once(backend, operation_id, deadline=deadline, source_guard=source_guard)


def _wake_once(backend, operation_id, *, deadline, source_guard):
    """Internal native qualification entrypoint; exactly one key down/up group.

    The source-owned backend/custody supplies actual identity, endpoint and FD.
    The ordinary credential is not accessed. Every key event rechecks the real
    machine, boot and ordinary console session. Failure after admission remains
    UNKNOWN; there is deliberately no automatic key release or retry.
    """
    operation_id = _id(operation_id)
    _need(type(deadline) in {int, float} and math.isfinite(deadline)
          and time.monotonic() < deadline <= time.monotonic() + 180,
          "macos_wake_deadline")
    _need(os.name == "posix", "macos_wake_platform_unsupported")
    _need(_EXECUTING_CODE == compile(Path(__file__).read_bytes(), __file__, "exec",
                                    dont_inherit=True, optimize=sys.flags.optimize),
          "macos_wake_source_changed")
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    requirements = readiness.Requirements(frozenset({"guest_agent"}))
    with backend.operation_scope(deadline=deadline):
        before = backend.observe(requirements, deadline)
        binding = _binding(before)
        _need(before.display == "sleeping", "macos_wake_display_not_sleeping")
        custody = backend.custody
        with private.Directory(custody.lifecycle_root) as held:
            name = "macos-wake-" + operation_id + ".json"
            _need(_read(held, name) is None, "macos_wake_original_pending")
            intent = {"schemaVersion": 1, "operationId": operation_id,
                      "binding": binding, "action": "one_left_shift_down_up",
                      "state": "unknown", "replacementForbidden": True,
                      "sourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            # UNKNOWN precedes authentication/input. A fresh caller must use
            # status even if the connection failed before the first key event.
            source_guard()
            _publish(held, name, intent)
            def guard():
                source_guard(); held.guard()
                current = backend.observe(requirements, deadline)
                _need(_binding(current) == binding and current.display in {"ready", "sleeping"},
                      "macos_wake_identity_changed")
                source_guard()
            fd = custody._credentials["vnc"].credential_fd()
            try:
                with rfb.ProtectedVncSession(port=custody.endpoint["port"], credential_fd=fd,
                                             guard=guard, timeout=min(20, deadline-time.monotonic())) as connection:
                    connection.key("LEFT_SHIFT")
            finally:
                os.close(fd)
            _publish(held, "macos-wake-" + operation_id + "-transport.json",
                     {"operationId": operation_id, "state": "input_group_transport_closed"})
            # Native WindowServer/display state can settle after the input
            # acknowledgement. Poll only observations; never add another input.
            until = min(deadline, time.monotonic() + 20)
            while time.monotonic() < until:
                current = backend.observe(requirements, deadline)
                _need(_binding(current) == binding, "macos_wake_identity_changed")
                if current.display == "ready":
                    value = {"operationId": operation_id, "state": "observed_ready",
                             "binding": binding, "display": current.display,
                             "ordinarySession": current.ordinary_session,
                             "inputGroups": 1, "replacementForbidden": True}
                    _publish(held, "macos-wake-" + operation_id + "-observed.json", value)
                    return value
                _need(current.display == "sleeping", "macos_wake_display_unrecognized")
                time.sleep(min(.2, max(0, until-time.monotonic())))
            raise WakeBlocked("macos_wake_original_outcome_unknown")
