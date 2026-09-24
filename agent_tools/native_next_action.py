"""Fail-closed guidance for the next safe public MCP workflow action.

The classifier turns durable workflow observations into a small, displayable
recommendation.  It never reconstructs a mutation: uncertain publishes,
forwards, and jobs are observed with their existing identity, and every
unrecognised response asks the caller to inspect evidence.
"""
from __future__ import annotations

import re
from typing import Any, Mapping


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_JOB_IDENTITY = frozenset(("jobId", "pid", "startTicks", "receiptPath"))


def _guidance(kind: str, reason: str, *, action: dict[str, Any] | None = None,
              replay_allowed: bool = False, fresh: bool | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "kind": kind,
        "reason": reason,
        "replayAllowed": replay_allowed,
    }
    if action is not None:
        value["action"] = action
    if fresh is not None:
        value["requiresFreshEvidence"] = fresh
    return value


def _host(result: Mapping[str, Any]) -> str | None:
    value = result.get("host")
    return value if isinstance(value, str) and _TOKEN.fullmatch(value) else None


def _job_identity(result: Mapping[str, Any]) -> dict[str, Any] | None:
    value = result.get("identity")
    if not isinstance(value, Mapping) or set(value) - _JOB_IDENTITY or not {"jobId", "pid", "startTicks"} <= set(value):
        return None
    if not isinstance(value["jobId"], str) or not _TOKEN.fullmatch(value["jobId"]):
        return None
    if any(isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 1 for key in ("pid", "startTicks")):
        return None
    if "receiptPath" in value and (not isinstance(value["receiptPath"], str) or not value["receiptPath"].startswith("/")):
        return None
    return dict(value)


def _observe_job(result: Mapping[str, Any], reason: str) -> dict[str, Any]:
    host, identity = _host(result), _job_identity(result)
    if host is None or identity is None:
        return _guidance("inspect-evidence", reason + "; the job correlation is incomplete", fresh=True)
    return _guidance("observe-job", reason, action={"tool": "ssh_workflow", "action": "job-status",
                     "args": {"host": host, "identity": identity}}, fresh=True)


def _observe_transfer(action: str, result: Mapping[str, Any], reason: str) -> dict[str, Any]:
    # Transfer status needs the original host alias.  It is not present in all
    # historical transfer receipts, so never invent one from a path or message.
    host = _host(result)
    identity = result.get("identity")
    status_action = "apk-status" if action.startswith("apk-") else "fixture-status"
    if host is None or not isinstance(identity, Mapping):
        return _guidance("inspect-evidence", reason + "; retain the existing transfer identity and host alias", fresh=True)
    return _guidance("observe-transfer", reason, action={"tool": "ssh_workflow", "action": status_action,
                     "args": {"host": host, "identity": dict(identity)}}, fresh=True)


def _retry_probe(result: Mapping[str, Any], reason: str) -> dict[str, Any]:
    host = _host(result)
    if host is None:
        return _guidance("inspect-evidence", reason + "; the host alias is absent", fresh=True)
    return _guidance("retry-readonly", reason, action={"tool": "ssh_workflow", "action": "probe",
                     "args": {"host": host}}, replay_allowed=True, fresh=True)


def _scenario_status(result: Mapping[str, Any], reason: str) -> dict[str, Any]:
    correlation_id = result.get("correlationId")
    if not isinstance(correlation_id, str) or not _TOKEN.fullmatch(correlation_id):
        return _guidance("inspect-evidence", reason + "; the scenario correlation is incomplete", fresh=True)
    # vm_workflow takes its payload in ``inputs``.  Keeping correlationId there
    # makes this a real public RPC shape instead of a convenient but invalid
    # top-level argument.
    return _guidance("observe-scenario", reason, action={"tool": "vm_workflow", "action": "scenario-status",
                     "args": {"inputs": {"correlationId": correlation_id}}}, fresh=True)


def next_action(tool: str, action: str, result: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Classify one public workflow response without making a state change.

    ``action`` in the returned value always names an existing public MCP route;
    its arguments contain only a result-derived host alias and durable identity.
    """
    if not isinstance(result, Mapping):
        return _guidance("inspect-evidence", "workflow response is not an object", fresh=True)
    if tool not in {"ssh_workflow", "vm_workflow"}:
        return _guidance("inspect-evidence", "unknown workflow tool", fresh=True)
    state = result.get("state")
    status = result.get("status")
    verification = result.get("verification")
    summary = " ".join(str(result.get(key, "")) for key in ("summary", "message", "reason")).lower()

    if tool == "ssh_workflow" and action == "job-status":
        if status == "running":
            return _observe_job(result, "the correlated job is still running")
        if status == "terminal":
            return _guidance("inspect-evidence", "the correlated job is terminal; inspect its receipt before any new request", fresh=True)
        return _observe_job(result, "job observation is unknown")

    if tool == "ssh_workflow" and action in {"fixture-publish", "apk-publish", "fixture-status", "apk-status"}:
        if state in {"published", "unknown", "submitted"}:
            return _observe_transfer(action, result, "transfer outcome requires status evidence")

    if tool == "ssh_workflow" and action in {"forward-open", "forward-status", "forward-close"}:
        if state in {"pending", "remote_created", "remote_forward_pending", "local_pending", "local_forward_pending", "closing", "close_pending", "ready", "owner_unknown", "unavailable"}:
            host = _host(result)
            if host is not None:
                return _guidance("observe-forward", "existing forward has a durable state", action={"tool": "ssh_workflow", "action": "forward-status", "args": {"host": host}}, fresh=True)
            return _guidance("inspect-evidence", "existing forward must be observed with its original host alias", fresh=True)

    if tool == "ssh_workflow" and action == "probe" and status in {"timeout", "connection_failed", "ssh_failed"}:
        return _retry_probe(result, "the bounded read-only connectivity probe did not establish a result")

    if tool == "vm_workflow" and action in {"scenario-start", "scenario-status", "scenario-resume", "scenario-collect"}:
        if state in {"submitted", "submitting", "unknown"}:
            return _scenario_status(result, "the durable scenario has not reached a correlated terminal receipt")
        if state == "terminal":
            exit_code = result.get("exitCode")
            if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0:
                return _guidance("complete", "the scenario completed with exit code 0", fresh=False)
            return _guidance("inspect-evidence", "the scenario is terminal without a successful exit receipt", fresh=True)

    if tool == "vm_workflow" and action == "environment-status":
        observations = result.get("observations")
        stale = result.get("freshness") == "stale" or (
            isinstance(observations, list) and any(isinstance(item, Mapping) and item.get("stale") is True for item in observations)
        )
        if stale:
            return _guidance("refresh-measurement", "supplied environment facts are stale", fresh=True)
        if state == "UNKNOWN" and result.get("requestedProbesReady") is True:
            return _guidance("missing-dependency", "requested probes are ready but required environment facts are absent", fresh=True)
        if state == "UNKNOWN":
            return _guidance("inspect-evidence", "environment evidence remains unknown; do not replay a reservation", fresh=True)

    if verification == "verified":
        return _guidance("complete", "artifact evidence is verified", fresh=False)
    if verification == "unverified-remote":
        return _guidance("verify-artifact", "remote artifact evidence still needs independent verification", fresh=True)
    if verification in {"missing-or-unsafe", "mismatch"}:
        return _guidance("missing-dependency", "artifact verification did not establish usable local evidence", fresh=True)

    if result.get("freshness") == "stale" or "not recent" in summary:
        return _guidance("refresh-measurement", "measurement evidence is stale", fresh=True)
    if state in {"unsupported_host", "unsupported_platform"} or "unsupported" in summary:
        return _guidance("unsupported", "the requested operation is explicitly unsupported", fresh=False)
    if "installer" in summary and (result.get("ok") is False or state in {"failed", "terminal"}):
        return _guidance("inspect-evidence", "installer failure is terminal; inspect evidence rather than rerunning it", fresh=True)
    if state in {"unknown", "recovery_intent_pending", "configured_master_unknown", "remote_master_unknown"}:
        return _guidance("inspect-evidence", "existing state is uncertain; do not replay the mutation", fresh=True)
    return _guidance("inspect-evidence", "workflow response has no recognised safe continuation", fresh=True)
