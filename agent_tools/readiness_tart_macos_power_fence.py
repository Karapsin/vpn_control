"""Durable same-target admission fence around Mac power operations.

This internal module neither powers a VM nor authorizes an idle assertion.
The registered custody must hold its actual per-target operator flock from
reservation through dispatch. All new mutations check ``guard_admission`` under
that same flock and again immediately before dispatch. Observations use a
source-owned original-operation scope; its bypass never authorizes mutations.

A reservation is not a clean-stop receipt. In particular a shutdown whose
acknowledgement was lost remains UNKNOWN after physical OFF admission. No
resolution/retirement API is provided until its native proof producer exists.
"""
from __future__ import annotations

from contextlib import contextmanager
import contextvars
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from . import private_inventory_lock as private
from . import readiness

_EXECUTING_CODE = sys._getframe().f_code
_OBSERVING = contextvars.ContextVar("macos_original_power_observation", default=None)
_PREFIX = "macos-power-reservation-"
_LIMIT = 2048


class PowerPending(ValueError):
    """Finite public reasons only, without caller data or exception details."""


def _need(value, reason):
    if not value:
        raise PowerPending(reason)


def _rid(value):
    _need(type(value) is str and re.fullmatch("[a-f0-9]{64}", value), "macos_power_recovery_invalid")
    return value


def _uuid(value):
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value, "macos_power_owner_invalid")
    except (ValueError, TypeError, AttributeError):
        raise PowerPending("macos_power_owner_invalid") from None
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class PowerFence:
    """Original lifecycle-root records, shared by every registered alias.

    ``operator_guard`` is the actual registered custody lock guard, not a DTO or
    caller ownership flag. Missing lock visibility prevents every admission.
    The trusted adapter alone constructs this object. Local inspection remains
    read-only and does not acquire a lock, connect, wake or create directories.
    """
    def __init__(self, root, target, machine, operator_guard):
        _need(type(target) is str and target and type(machine) is str and machine
              and callable(operator_guard), "macos_power_binding_invalid")
        self.root = Path(root)
        self.target, self.machine, self._operator_guard = target, machine, operator_guard
        self.directory = private.Directory(self.root)

    def close(self):
        self.directory.close()

    def _guard(self):
        self._operator_guard()
        self.directory.guard()
        _need(_EXECUTING_CODE == compile(Path(__file__).read_bytes(), __file__, "exec",
                                        dont_inherit=True, optimize=sys.flags.optimize),
              "macos_power_fence_source_changed")

    def _read(self, name):
        with private.Snapshot(self.directory, name) as held:
            def pairs(rows):
                result = {}
                for key, value in rows:
                    _need(key not in result, "macos_power_reservation_invalid")
                    result[key] = value
                return result
            try:
                return json.loads(held.body, object_pairs_hook=pairs,
                                  parse_constant=lambda _: (_ for _ in ()).throw(
                                      PowerPending("macos_power_reservation_invalid")))
            except (ValueError, TypeError, UnicodeError):
                raise PowerPending("macos_power_reservation_invalid") from None

    def _validate(self, value, recovery):
        fields = {"schemaVersion", "recoveryId", "action", "target", "machine", "originalRunOperationId",
                  "before", "idleVisibility", "idleBlockers", "state", "producerSha256"}
        _need(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
              and value["schemaVersion"] == 1 and value["recoveryId"] == recovery
              and type(value["action"]) is str and value["action"] in {"shutdown", "reboot", "suspend"}
              and value["target"] == self.target and value["machine"] == self.machine
              and value["state"] == "pending" and value["idleVisibility"] == sorted(readiness.IDLE_VISIBILITY)
              and value["idleBlockers"] == [] and type(value["producerSha256"]) is str
              and re.fullmatch("[a-f0-9]{64}", value["producerSha256"]), "macos_power_reservation_invalid")
        _uuid(value["originalRunOperationId"])
        before = value["before"]
        _need(type(before) is dict and set(before) == {"connection", "boot", "account", "session"}
              and all(before[key] is None or type(before[key]) is str for key in before)
              and before["connection"] and before["boot"], "macos_power_reservation_invalid")
        return value

    def inspect(self):
        """Pure durable status, including records from a previous agent process."""
        self.directory.guard()
        names = os.listdir(self.directory.fd)
        candidates = [name for name in names if name.startswith(_PREFIX)]
        _need(len(candidates) <= _LIMIT, "macos_power_history_overflow")
        values = []
        for name in sorted(candidates):
            match = re.fullmatch(re.escape(_PREFIX) + "([a-f0-9]{64})\\.json", name)
            _need(match is not None, "macos_power_reservation_invalid")
            values.append(self._validate(self._read(name), match[1]))
        self.directory.guard()
        _need(len(values) <= 1, "macos_power_competing_originals")
        return values[0] if values else None

    def reserve(self, recovery_id, action, observed, *, original_run_operation):
        self._guard(); _rid(recovery_id); _uuid(original_run_operation)
        _need(type(observed) is readiness.Observation and observed.trusted and observed.owned
              and observed.integrity and not observed.coordinator_host and observed.guest == "running"
              and observed.guest_agent and observed.transport == "ready"
              and (observed.target, observed.machine) == (self.target, self.machine),
              "macos_power_guest_not_ready")
        _need(observed.idle_visibility == readiness.IDLE_VISIBILITY and not observed.idle_blockers,
              "macos_power_idle_incomplete")
        _need(type(action) is str and action in {"shutdown", "reboot", "suspend"}, "macos_power_action_invalid")
        value = {"schemaVersion": 1, "recoveryId": recovery_id, "action": action,
                 "target": self.target, "machine": self.machine, "originalRunOperationId": original_run_operation,
                 "before": {key: getattr(observed, key) for key in ("connection", "boot", "account", "session")},
                 "idleVisibility": sorted(observed.idle_visibility), "idleBlockers": [], "state": "pending",
                 "producerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        self._validate(value, recovery_id)
        current = self.inspect()
        if current is not None:
            _need(current == value, "macos_original_power_pending")
            return current
        name = _PREFIX + recovery_id + ".json"
        stage = ".power-stage-" + str(uuid.uuid4())
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory.fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
                stream.flush(); os.fsync(stream.fileno())
            self._guard()
            os.link(stage, name, src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd, follow_symlinks=False)
            os.fsync(self.directory.fd)
            self._guard()
        finally:
            os.unlink(stage, dir_fd=self.directory.fd)
        return value

    def guard_admission(self):
        """Always blocks new work; an observer context is never mutation authority."""
        self._guard()
        _need(self.inspect() is None, "macos_original_power_pending")

    def guard_scope(self):
        """An authenticated original observer can inspect through the fence."""
        self._guard()
        pending = self.inspect()
        if pending is not None:
            _need(_OBSERVING.get() == (id(self), pending["recoveryId"], _digest(pending)),
                  "macos_original_power_pending")

    @contextmanager
    def observing_original(self, recovery_id):
        """Private source-owned observer route only; never exposed as a request flag.

        Mutating dispatchers still call guard_admission, which ignores this
        context. The original power dispatcher additionally owns its once-only
        journal; this fence does not permit or repeat a power action.
        """
        self._guard(); _rid(recovery_id)
        pending = self.inspect()
        _need(pending is not None and pending["recoveryId"] == recovery_id,
              "macos_original_power_not_admitted")
        token = _OBSERVING.set((id(self), recovery_id, _digest(pending)))
        try:
            self.guard_scope()
            yield
            self.guard_scope()
        finally:
            _OBSERVING.reset(token)
