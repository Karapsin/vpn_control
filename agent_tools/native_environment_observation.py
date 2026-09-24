"""Compose bounded, read-only observations of configured native environments.

The composer deliberately owns no lifecycle action.  It joins the existing
narrow SSH, Android, job, and artifact observers into one small status envelope
without exposing command output, exception text, credentials, or VM controls.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import time
from typing import Any, Mapping

try:  # Keep the direct MCP CLI fallback importable too.
    from . import android_observation, native_artifact_registry, native_host_observation, ssh_jobs, ssh_transport
except ImportError:  # pragma: no cover - exercised by standalone import tests.
    import android_observation  # type: ignore[no-redef]
    import native_artifact_registry  # type: ignore[no-redef]
    import native_host_observation  # type: ignore[no-redef]
    import ssh_jobs  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ARTIFACT = re.compile(r"^sha256-[0-9a-f]{64}$")
_LOCATION = re.compile(r"^location-[0-9a-f]{64}$")
_MAX_TIMEOUT_SECONDS = 30


class NativeEnvironmentObservationError(ValueError):
    """The requested composition is incomplete or unsafe."""


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise NativeEnvironmentObservationError(f"{field} is invalid")
    return value


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NativeEnvironmentObservationError("environment observation request must be an object")
    allowed = {"hostAlias", "device", "jobIdentity", "artifactId", "locationId", "timeoutSeconds", "observations", "observeHost", "vmIdentity"}
    if set(value) - allowed:
        raise NativeEnvironmentObservationError("environment observation request has unsupported fields")
    result: dict[str, Any] = {"hostAlias": _name(value.get("hostAlias"), "host alias")}
    if "device" in value:
        result["device"] = _name(value["device"], "Android device alias")
    if "jobIdentity" in value:
        if not isinstance(value["jobIdentity"], Mapping):
            raise NativeEnvironmentObservationError("job identity must be an object")
        # Validate before a live connection and retain only the reviewed shape.
        result["jobIdentity"] = ssh_jobs.JobIdentity.from_mapping(value["jobIdentity"]).as_dict()
        if value["jobIdentity"].get("receiptPath") is not None:
            result["jobIdentity"]["receiptPath"] = value["jobIdentity"]["receiptPath"]
    artifact = value.get("artifactId")
    location = value.get("locationId")
    if artifact is not None:
        if not isinstance(artifact, str) or not _ARTIFACT.fullmatch(artifact):
            raise NativeEnvironmentObservationError("artifact ID is invalid")
        result["artifactId"] = artifact
    if location is not None:
        if "artifactId" not in result or not isinstance(location, str) or not _LOCATION.fullmatch(location):
            raise NativeEnvironmentObservationError("artifact location ID is invalid")
        result["locationId"] = location
    timeout = value.get("timeoutSeconds", _MAX_TIMEOUT_SECONDS)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= _MAX_TIMEOUT_SECONDS:
        raise NativeEnvironmentObservationError("timeoutSeconds must be between 1 and 30")
    result["timeoutSeconds"] = timeout
    receipts = value.get("observations", [])
    if receipts is None:
        receipts = []
    if not isinstance(receipts, list):
        raise NativeEnvironmentObservationError("observations must be a list")
    result["observations"] = receipts
    if "observeHost" in value and not isinstance(value["observeHost"], bool):
        raise NativeEnvironmentObservationError("observeHost must be boolean")
    result["observeHost"] = value.get("observeHost", False) or "vmIdentity" in value
    if "vmIdentity" in value:
        result["vmIdentity"] = native_host_observation._identity(value["vmIdentity"])
    return result


def _component(status: str, timestamp: int, scope: str, *, fresh: str = "fresh", **evidence: Any) -> dict[str, Any]:
    return {"status": status, "observedAtUnixMs": timestamp, "freshness": fresh,
            "evidenceScope": scope, **evidence}


def _unknown(timestamp: int, scope: str, reason: str) -> dict[str, Any]:
    # Reasons are fixed categorical labels, never exception or command text.
    return _component("unknown", timestamp, scope, reason=reason)


def _budget(deadline: float, per_call: int) -> int | None:
    # Existing SSH observers wait up to timeout + one second while draining a
    # child process.  Reserve that overhead so the composition has one real
    # deadline instead of a sequence of nominally bounded waits.
    remaining = int(deadline - time.monotonic())
    if remaining <= 1:
        return None
    return min(per_call, remaining - 1)


def _supplied(receipts: list[Any], timestamp: int) -> dict[str, Any]:
    kinds = sorted({item.get("kind") for item in receipts if isinstance(item, Mapping)
                    and item.get("kind") in {"vm", "memory"}})
    return _component("supplied" if kinds else "unknown", timestamp, "caller-receipts",
                      fresh="not-live", observed=False, kinds=kinds)


def observe_environment(root: str | Path, request: Mapping[str, Any]) -> dict[str, Any]:
    """Observe configured existing resources once within one shared deadline.

    This never starts or stops a VM, changes configuration, or signals a job.
    Windows is explicitly unsupported because the private SSH inventory cannot
    yet be opened with equivalent ACL guarantees.
    """
    requested = _request(request)
    timestamp = time.time_ns() // 1_000_000
    components: dict[str, dict[str, Any]] = {
        "supplied": _supplied(requested["observations"], timestamp),
    }
    if os.name != "posix":
        components["ssh"] = _unknown(timestamp, "configured-host-connectivity", "unsupported_platform")
        for name, scope in (("android", "configured-android-device"), ("job", "existing-job-identity"),
                            ("artifact", "registered-local-artifact")):
            if (name == "android" and "device" in requested) or (name == "job" and "jobIdentity" in requested) or (name == "artifact" and "artifactId" in requested):
                components[name] = _unknown(timestamp, scope, "unsupported_platform")
        return {"state": "UNKNOWN", "ready": False, "requestedProbesReady": False,
                "nativeActionAllowed": False, "source": "live-tool", "observationStatus": "unknown",
                "observedAtUnixMs": timestamp, "timeoutSeconds": requested["timeoutSeconds"], "components": components}

    deadline = time.monotonic() + requested["timeoutSeconds"]
    network_count = 1 + int("device" in requested) + int("jobIdentity" in requested) + int(requested["observeHost"])
    # Reserve equal slices up front.  A fast earlier observer must not enlarge
    # later calls and turn this into sequential full-timeout probing.
    # Every network observer has a one-second bounded drain overhead.  If the
    # requested deadline cannot give every selected observer at least one
    # useful second, leave signals unknown rather than exceeding the deadline.
    available_for_probes = requested["timeoutSeconds"] - network_count
    network_timeout = available_for_probes // network_count if available_for_probes >= network_count else 0
    ssh_timeout = _budget(deadline, network_timeout) if network_timeout else None
    if ssh_timeout is None:
        components["ssh"] = _unknown(timestamp, "configured-host-connectivity", "deadline_exhausted")
    else:
        try:
            probe = ssh_transport.probe(root, requested["hostAlias"], timeout_seconds=ssh_timeout)
            status = "available" if probe.ok else ("unavailable" if probe.status is ssh_transport.ProbeStatus.CONFIG_ERROR else "unknown")
            components["ssh"] = _component(status, time.time_ns() // 1_000_000, "configured-host-connectivity", probeStatus=probe.status.value)
        except (ssh_transport.SshConfigError, OSError, ValueError):
            components["ssh"] = _unknown(timestamp, "configured-host-connectivity", "observer_failed")

    if requested["observeHost"]:
        timeout = _budget(deadline, network_timeout)
        if timeout is None:
            components["host"] = _unknown(time.time_ns() // 1_000_000, "live-linux-host", "deadline_exhausted")
        else:
            try:
                observed_host = native_host_observation.observe_host(root, requested["hostAlias"], timeout, requested.get("vmIdentity"))
                known = observed_host.get("measurementAvailability") == "complete"
                if "vmIdentity" in requested:
                    known = known and (observed_host.get("vmIdentity") or {}).get("state") == "matched"
                components["host"] = _component("available" if known else "unknown", time.time_ns() // 1_000_000,
                    "live-linux-host", observation=observed_host)
            except (ValueError, OSError):
                components["host"] = _unknown(time.time_ns() // 1_000_000, "live-linux-host", "observer_failed")

    profile: Mapping[str, Any] | None = None
    if "device" in requested:
        try:
            config = ssh_transport.load_config(root)
            host = config.hosts.get(requested["hostAlias"])
            if host is None:
                raise ValueError
            profile = host.android_devices.get(requested["device"])
            if profile is None:
                raise ValueError
        except (ssh_transport.SshConfigError, KeyError, AttributeError, ValueError):
            components["android"] = _unknown(timestamp, "configured-android-device", "profile_unavailable")
    if "device" in requested and "android" not in components:
        timeout = _budget(deadline, network_timeout) if network_timeout else None
        if timeout is None:
            components["android"] = _unknown(timestamp, "configured-android-device", "deadline_exhausted")
        else:
            try:
                observed = android_observation.observe(root, requested["hostAlias"], profile, timeout_seconds=timeout)
                available = observed.get("available")
                status = "available" if available is True else "unavailable" if observed.get("outcome") == "unavailable" else "unknown"
                components["android"] = _component(status, time.time_ns() // 1_000_000, "configured-android-device", reason=observed.get("reason", "unknown"))
            except (android_observation.AndroidObservationError, ssh_transport.SshConfigError,
                    TimeoutError, RuntimeError, OSError, ValueError):
                components["android"] = _unknown(timestamp, "configured-android-device", "observer_failed")

    if "jobIdentity" in requested:
        timeout = _budget(deadline, network_timeout) if network_timeout else None
        if timeout is None:
            components["job"] = _unknown(timestamp, "existing-job-identity", "deadline_exhausted")
        else:
            try:
                observed = ssh_jobs.observe(root, requested["hostAlias"], requested["jobIdentity"], timeout_seconds=timeout)
                status = observed.status.value
                components["job"] = _component(status, time.time_ns() // 1_000_000, "existing-job-identity", reason=observed.reason)
            except (ssh_jobs.SshJobError, ssh_transport.SshConfigError, OSError, ValueError):
                components["job"] = _unknown(timestamp, "existing-job-identity", "observer_failed")

    if "artifactId" in requested:
        try:
            verified = native_artifact_registry.verify_artifact(root, requested["artifactId"], requested.get("locationId"))
            verification = verified.get("verification")
            status = "verified" if verification == "verified" else "unavailable" if verification in {"mismatch", "missing-or-unsafe", "unverified-remote"} else "unknown"
            components["artifact"] = _component(status, time.time_ns() // 1_000_000, "registered-local-artifact", verification=verification)
        except (native_artifact_registry.NativeArtifactRegistryError, OSError, ValueError):
            components["artifact"] = _unknown(timestamp, "registered-local-artifact", "observer_failed")

    required = [components["ssh"]]
    if "host" in components:
        required.append(components["host"])
    for name, success in (("android", "available"), ("job", None), ("artifact", "verified")):
        if name in components:
            required.append(components[name])
    requested_probes_ready = all(item["status"] not in {"unknown", "unavailable"} for item in required)
    if "android" in components:
        requested_probes_ready = requested_probes_ready and components["android"]["status"] == "available"
    if "artifact" in components:
        requested_probes_ready = requested_probes_ready and components["artifact"]["status"] == "verified"
    # There is no live VM or memory observer.  Do not turn SSH reachability
    # into an environment-ready assertion when those facts were not supplied.
    # Caller labels are historical context, not proof of a live VM or healthy host.
    live_host = components.get("host", {}).get("observation", {})
    ready = requested_probes_ready and (live_host.get("vmIdentity") or {}).get("state") == "matched" and \
        (live_host.get("measurement") or {}).get("pressure") == "normal"
    state = "READY" if ready else "UNKNOWN"
    return {"state": state, "ready": ready, "requestedProbesReady": requested_probes_ready,
            "nativeActionAllowed": False, "source": "live-tool",
            "observationStatus": "requested-probes-ready" if requested_probes_ready else "unknown",
            "observedAtUnixMs": time.time_ns() // 1_000_000, "timeoutSeconds": requested["timeoutSeconds"], "components": components}
