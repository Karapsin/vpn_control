"""Inert Mac idle evidence review; no native collector or reboot authority.

Only normalized facts from a future source-owned zero-argument root helper may
enter this internal interface. Unexpected argv, paths, environment and their
digests/lengths never belong in packets or diagnostics. Process identity alone,
an Apple-looking name, or an Apple signature does not establish service idleness.
Until actual launchd/code/namespace facts are qualified, every non-observer
process remains a blocker and the native projection is deliberately unavailable.

The pure candidate review joins the seven readiness categories without changing
any process, guest, namespace, file, power state or credential setting. It can
support controlled protocol tests; it is not native acceptance evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sys
from uuid import UUID

from . import readiness

_EXECUTING_CODE = sys._getframe().f_code
NATIVE_QUALIFIED = False
_HOST = frozenset({"reservations", "lifecycle_phases", "operators"})
_GUEST_JOBS = frozenset({"running_jobs", "unknown_jobs"})
_SOURCE = re.compile(r"[0-9a-f]{64}\Z")
_BIRTH = re.compile(r"darwin:[1-9][0-9]*:[0-9]{1,6}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NAMESPACES = frozenset({"guest-jobs", "gui-leases"})


class MacIdleError(ValueError):
    """Finite reason only; never include a rejected value or raw native reply."""


def _need(value, reason):
    if not value:
        raise MacIdleError(reason)


def _uuid(value):
    try:
        _need(type(value) is str and str(UUID(value)) == value.lower(), "macos_idle_identity_invalid")
    except (ValueError, TypeError, AttributeError):
        raise MacIdleError("macos_idle_identity_invalid") from None
    return value


def _generation(value):
    _need(type(value) in (tuple, list) and len(value) == 2 and all(type(item) is int and item >= 0 for item in value),
          "macos_idle_namespace_generation_invalid")
    return tuple(value)


def _actor(value):
    _need(type(value) is dict and set(value) == {"pid", "birth"} and type(value["pid"]) is int
          and value["pid"] > 0 and type(value["birth"]) is str and _BIRTH.fullmatch(value["birth"]),
          "macos_idle_actor_invalid")


@dataclass(frozen=True)
class IdleBinding:
    target: str
    machine: str
    boot: str
    ordinary_uid: int
    observer_pid: int
    observer_birth: str

    def __post_init__(self):
        _need(type(self.target) is str and _TOKEN.fullmatch(self.target), "macos_idle_identity_invalid")
        _uuid(self.machine); _uuid(self.boot)
        _need(type(self.ordinary_uid) is int and 501 <= self.ordinary_uid <= 2**32-2,
              "macos_idle_account_invalid")
        _actor({"pid": self.observer_pid, "birth": self.observer_birth})


def _processes(rows):
    _need(type(rows) is list and 0 < len(rows) <= 65536, "macos_idle_process_census_invalid")
    result = {}
    for row in rows:
        _need(type(row) is dict and set(row) == {"pid", "uid", "birth", "executableRole"},
              "macos_idle_process_census_invalid")
        _actor({"pid": row["pid"], "birth": row["birth"]})
        _need(type(row["uid"]) is int and 0 <= row["uid"] <= 2**32-2 and row["pid"] not in result
              and type(row["executableRole"]) is str
              and row["executableRole"] in {"verified_probe", "protected_runtime", "installer", "unmanaged"},
              "macos_idle_process_census_invalid")
        result[row["pid"]] = row
    return result


def _stream(value):
    _need(type(value) is dict and set(value) == {"overflow", "retainedBytes", "totalBytes", "sha256"}
          and value["overflow"] is False and type(value["retainedBytes"]) is int
          and type(value["totalBytes"]) is int and 0 <= value["retainedBytes"] == value["totalBytes"] <= 4194304
          and type(value["sha256"]) is str and _SOURCE.fullmatch(value["sha256"]),
          "macos_idle_terminal_stream_unverified")


def _job(value, binding):
    common = {"schemaVersion", "operationId", "state", "reason", "replayAllowed"}
    _need(type(value) is dict and common <= set(value) and type(value["schemaVersion"]) is int
          and value["schemaVersion"] == 1 and value["replayAllowed"] is False
          and type(value["state"]) is str and value["state"] in {"running", "terminal", "unknown", "unsubmitted"},
          "macos_idle_job_invalid")
    operation = _uuid(value["operationId"])
    _need(operation == operation.lower(), "macos_idle_job_invalid")
    identity = value.get("binding")
    if identity is not None:
        _need(type(identity) is dict and set(identity) == {"target", "machine", "boot", "account"}
              and (identity["target"], identity["machine"], identity["account"]) ==
                  (binding.target, binding.machine, str(binding.ordinary_uid)), "macos_idle_job_identity_changed")
        _uuid(identity["boot"])
    if "owner" in value: _actor(value["owner"])
    if value["state"] == "running":
        _need(identity is not None and "owner" in value, "macos_idle_job_identity_changed")
    if value["state"] != "terminal":
        _need(set(value) <= common | {"binding", "owner"}, "macos_idle_job_invalid")
        return operation, value["state"]
    _need(set(value) == common | {"binding", "owner", "terminal"} and value["reason"] == "correlated_terminal",
          "macos_idle_job_invalid")
    _need(identity is not None, "macos_idle_job_identity_changed")
    _actor(value["owner"])
    terminal = value["terminal"]
    _need(type(terminal) is dict and set(terminal) == {"operationId", "generation", "binding", "programSha256",
              "owner", "exitCode", "streamsClosed", "stdout", "stderr"}
          and terminal["operationId"] == operation and terminal["binding"] == identity
          and terminal["owner"] == value["owner"] and type(terminal["exitCode"]) is int
          and terminal["streamsClosed"] is True and type(terminal["programSha256"]) is str
          and _SOURCE.fullmatch(terminal["programSha256"]), "macos_idle_job_identity_changed")
    _uuid(terminal["generation"]); _stream(terminal["stdout"]); _stream(terminal["stderr"])
    return operation, "terminal"


def _namespaces(expected, observed, binding, observer_enrollment=None):
    roles = _NAMESPACES
    if observer_enrollment is not None:
        from . import readiness_tart_macos_unlock_observer as observer
        _need(type(observer_enrollment) is observer.ObserverIdleEnrollment, "macos_idle_observer_enrollment_required")
        observer_enrollment.guard(binding, expected.get("unlock-observers") if type(expected) is dict else None)
        roles |= {"unlock-observers"}
    _need(type(expected) is dict and set(expected) == roles
          and type(observed) is dict and set(observed) <= roles, "macos_idle_namespace_invalid")
    complete = set(observed) == roles
    running, unknown = [], []
    for name, generations in expected.items():
        _need(type(generations) is tuple and len(generations) == 2, "macos_idle_namespace_invalid")
        for generation in generations: _generation(generation)
        packet = observed.get(name)
        if packet is None:
            unknown.append({"role": "namespace_unobserved"}); continue
        _need(type(packet) is dict and set(packet) == {"generation", "admissionGeneration", "visibilityComplete", "jobs", "idle"}
              and type(packet["visibilityComplete"]) is bool and type(packet["idle"]) is bool
              and type(packet["jobs"]) is list and len(packet["jobs"]) <= 1024,
              "macos_idle_namespace_changed")
        _need((_generation(packet["generation"]), _generation(packet["admissionGeneration"])) ==
              tuple(_generation(value) for value in generations), "macos_idle_namespace_changed")
        complete &= packet["visibilityComplete"]
        operations = set(); all_terminal = True
        for row in packet["jobs"]:
            operation, state = _job(row, binding)
            _need(operation not in operations, "macos_idle_duplicate_job")
            operations.add(operation)
            all_terminal &= state == "terminal"
            if state == "running": running.append({"operationId": operation, "role": "durable_running"})
            elif state != "terminal": unknown.append({"operationId": operation, "role": "durable_unresolved"})
        _need(packet["idle"] == all_terminal, "macos_idle_namespace_changed")
    return complete, running, unknown


def review(packet, binding, *, expected_namespaces, host, observer_enrollment=None):
    """Diagnostic candidate only; never a readiness/reboot projection.

    The host projection must itself come from original reservation, lifecycle
    and operator observers. It cannot claim visibility over guest categories.
    A service census cannot classify a process solely by a familiar name.
    """
    _need(type(binding) is IdleBinding, "macos_idle_identity_invalid")
    fields = {"schemaVersion", "machine", "boot", "observerUid", "first", "second", "namespaces"}
    _need(type(packet) is dict and set(packet) == fields and type(packet["schemaVersion"]) is int
          and packet["schemaVersion"] == 1 and packet["machine"] == binding.machine
          and packet["boot"] == binding.boot and type(packet["observerUid"]) is int
          and packet["observerUid"] == 0, "macos_idle_census_identity_changed")
    _need(type(host) is dict and set(host) == {"visibility", "blockers"}
          and type(host["visibility"]) is frozenset and host["visibility"] <= _HOST
          and type(host["blockers"]) is frozenset and host["blockers"] <= _HOST,
          "macos_idle_host_projection_invalid")
    one, two = _processes(packet["first"]), _processes(packet["second"])
    observer = {"pid": binding.observer_pid, "uid": 0, "birth": binding.observer_birth,
                "executableRole": "verified_probe"}
    _need(one.get(binding.observer_pid) == observer and two.get(binding.observer_pid) == observer,
          "macos_idle_observer_identity_changed")
    _need(not any(row["executableRole"] == "verified_probe" and row != observer
                  for row in [*one.values(), *two.values()]), "macos_idle_observer_identity_changed")
    visibility, blockers = set(host["visibility"]), set(host["blockers"])
    reasons = {"native_producer_unqualified"}
    if one == two: visibility |= {"protected_processes", "installers"}
    else: reasons.add("process_generation_or_census_changed")
    roles = []
    seen_roles = set()
    for row in [*one.values(), *two.values()]:
        pid = row["pid"]
        role = row["executableRole"]
        if role == "protected_runtime": blockers.add("protected_processes")
        if role == "installer": blockers.add("installers")
        if role != "verified_probe":
            # No Apple/path/name allowlist: native code, service account,
            # launchd parent/plist and work-namespace facts are not yet proven.
            blockers |= {"running_jobs", "unknown_jobs"}
            reasons.add("process_service_activity_unqualified")
        key = (pid, row["birth"], role)
        if key not in seen_roles:
            roles.append({"pid": pid, "birth": row["birth"], "role": role}); seen_roles.add(key)
    complete, running, unknown = _namespaces(expected_namespaces, packet["namespaces"], binding, observer_enrollment)
    if complete: visibility |= _GUEST_JOBS
    else: reasons.add("namespace_visibility_incomplete"); blockers.add("unknown_jobs")
    if running: blockers.add("running_jobs")
    if unknown: blockers.add("unknown_jobs")
    # Completeness of installer/package/session/lifecycle producers must also
    # be qualified by the installed native helper before these candidates can
    # ever feed readiness. This API intentionally has no 'visibility' field.
    return {"nativeQualified": False, "nativeIdle": False,
            "candidateVisibility": frozenset(visibility), "candidateBlockers": frozenset(blockers),
            "missingCategories": readiness.IDLE_VISIBILITY - visibility,
            "reasons": frozenset(reasons), "processRoles": tuple(roles),
            "runningJobs": tuple(running), "unknownJobs": tuple(unknown)}
