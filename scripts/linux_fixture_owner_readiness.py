"""Bound one disposable Linux fixture owner readiness observation."""

from dataclasses import dataclass
from typing import Any, Callable, Mapping
import time


class OwnerReadinessError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    uid: int


@dataclass(frozen=True)
class EndpointIdentity:
    workspace: str
    process: ProcessIdentity
    controller_id: str


@dataclass(frozen=True)
class StatusObservation:
    exit_code: int
    envelope: Mapping[str, Any] | None


def wait_for_exact_owner_ready(*, workspace: str, expected: ProcessIdentity,
                               observe_live: Callable[[], ProcessIdentity | None],
                               observe_endpoint: Callable[[], EndpointIdentity | None],
                               observe_status: Callable[[], StatusObservation],
                               timeout_seconds: float = 20.0, poll_seconds: float = 0.1,
                               clock: Callable[[], float] = time.monotonic,
                               sleep: Callable[[float], None] = time.sleep) -> Mapping[str, Any]:
    """Wait for the spawned PID and its authenticated public status.

    Callbacks are bound by the caller to one workspace. This helper performs no
    subprocess or file operation itself. A missing endpoint or pre-authenticated
    UNAVAILABLE status can be transient; a changed process, endpoint or
    authenticated controller cannot.
    """
    if (not isinstance(workspace, str) or not workspace or not isinstance(expected, ProcessIdentity)
            or expected.pid <= 0 or expected.start_ticks <= 0 or expected.uid < 0
            or timeout_seconds <= 0 or poll_seconds <= 0):
        raise ValueError("Invalid fixture owner readiness inputs")
    deadline = clock() + timeout_seconds
    pinned_controller = None
    while True:
        if observe_live() != expected:
            raise OwnerReadinessError("Spawned fixture owner identity changed")
        endpoint = observe_endpoint()
        if endpoint is None:
            if pinned_controller is not None:
                raise OwnerReadinessError("Pinned fixture owner endpoint disappeared")
        else:
            if (not isinstance(endpoint, EndpointIdentity) or endpoint.workspace != workspace
                    or endpoint.process != expected or not endpoint.controller_id):
                raise OwnerReadinessError("Fixture owner endpoint belongs to another process")
            if pinned_controller is None:
                pinned_controller = endpoint.controller_id
            elif endpoint.controller_id != pinned_controller:
                raise OwnerReadinessError("Fixture owner endpoint controller changed")
            observed = observe_status()
            if not isinstance(observed, StatusObservation):
                raise OwnerReadinessError("Fixture owner status observation is invalid")
            envelope = observed.envelope
            if not isinstance(envelope, Mapping):
                raise OwnerReadinessError("Fixture owner status envelope is invalid")
            reported_controller = envelope.get("controllerId")
            if (observed.exit_code == 0 and envelope.get("schemaVersion") == 1
                    and envelope.get("ok") is True and envelope.get("code") == "OK"
                    and envelope.get("final") is True):
                if reported_controller != pinned_controller:
                    raise OwnerReadinessError("Authenticated fixture controller differs from spawned owner")
                if observe_live() != expected or observe_endpoint() != endpoint:
                    raise OwnerReadinessError("Fixture owner changed during readiness observation")
                return envelope
            if not (observed.exit_code == 2 and envelope.get("code") == "UNAVAILABLE"
                    and reported_controller is None):
                raise OwnerReadinessError("Fixture owner status failed before readiness")
        remaining = deadline - clock()
        if remaining <= 0:
            raise OwnerReadinessError("Fixture owner readiness deadline elapsed")
        sleep(min(poll_seconds, remaining))
