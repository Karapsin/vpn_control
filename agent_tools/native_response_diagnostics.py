"""Deterministic, redacted failure grouping and admission gaps for MCP receipts."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_REGRESSIONS = {
    ("connection-master-status", "cached_socket_refused"):
        "agent_tools/tests/test_ssh_connection_recovery.py::test_exact_refusal_is_finite_cause_without_absence_authority",
    ("linux-rpm-workspace-cleanup-start", "owner-quit-unavailable"):
        "agent_tools/tests/test_linux_rpm_workspace_recovery.py::test_cleanup_requires_independent_exact_replacement_owner_quit",
    ("linux-rpm-workspace-cleanup-start", "workspace-reference-unknown"):
        "agent_tools/tests/test_linux_rpm_workspace_recovery.py::test_cleanup_requires_absent_scanner_before_durable_intent",
    ("linux-rpm-workspace-cleanup-start", "existing-intent"):
        "agent_tools/tests/test_linux_rpm_workspace_recovery.py::test_cleanup_response_loss_never_resubmits_same_correlation",
    ("linux-rpm-workspace-cleanup-status", "guest-status-unavailable"):
        "agent_tools/tests/test_linux_rpm_workspace_recovery.py::test_cleanup_status_rejects_symlink_foreign_pointer_and_inode_mismatch",
    ("android-consent-acceptance-preflight", "permission_granted"):
        "agent_tools/tests/test_android_consent_acceptance.py::test_read_only_preflight_classifies_existing_permission_without_raw_diagnostics",
    ("android-endpoint-admission-status", "missing_local_intent"):
        "agent_tools/tests/test_android_endpoint_admission.py::test_status_missing_local_intent_is_bounded_unknown_without_remote_observation",
    ("android-endpoint-admission-status", "reverse_inventory_invalid"):
        "agent_tools/tests/test_android_endpoint_admission.py::test_remote_reverse_inventory_rejects_duplicate_or_malformed_routes",
    ("windows-vm-driver-fetch-start", "driver-fetch-boundary-unknown"):
        "agent_tools/tests/test_native_optimization_routes.py::test_driver_fetch_unexpected_boundary_exception_keeps_correlation_and_status_only",
    ("windows-vm-driver-fetch-start", "driver-fetch-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_driver_fetch_route_exact_identity_and_status_read_only",
    ("windows-vm-disk-probe-start", "windows-disk-probe-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_disk_probe_routes_preserve_exact_one_shot_identity",
    ("windows-vm-fresh-start", "windows-fresh-setup-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_fresh_start_status_require_exact_reservation",
}
_CHANNEL_ACTIONS = {"connection-channel-prepare", "connection-channel-status", "connection-channel-ensure"}
_SNAPSHOT_REASONS = {"fd_changed", "master_check", "listener_owner"}
_SNAPSHOT_CLASSES = {"ValueError", "FileNotFoundError", "PermissionError", "OSError",
                     "KeyError", "TimeoutExpired", "SubprocessError", "other"}
for _action in ("connection-channel-prepare", "connection-channel-status", "connection-channel-ensure"):
    _REGRESSIONS[(_action, "invalid_channel_input")] = (
        "agent_tools/tests/test_ssh_channel_mcp_routes.py::test_invalid_inputs_do_not_reach_provider")
    for _reason in _SNAPSHOT_REASONS:
        _REGRESSIONS[(_action, _reason)] = (
            "agent_tools/tests/test_ssh_channel_mcp_routes.py::test_snapshot_refusal_retains_only_complete_finite_diagnostics")
_MISSING_FACT = {
    "fd_changed": "stable current master descriptor and listener ownership observation",
    "master_check": "successful current check of the exact channel master",
    "listener_owner": "exact current socket listener owned by the admitted master",
    "invalid_channel_input": "valid typed connection identity; no remote action was dispatched",
    "cached_socket_refused": "verified fresh transport channel on the same trusted route; preserve original job identities",
    "owner-quit-unavailable": "terminal public quit for the exact replacement owner",
    "workspace-reference-unknown": "fresh absent workspace and process references",
    "target-package-or-runtime-unavailable": "exact installed target package and stopped runtime",
    "existing-intent": "terminal status of the existing cleanup intent",
    "cleanup-response-uncertain": "terminal status of the existing cleanup intent",
    "missing-intent": "durable cleanup intent for this correlation",
    "missing_local_intent": "durable Android endpoint admission intent for this correlation",
    "reverse_inventory_invalid": "fresh bounded Android reverse-inventory observation",
    "guest-status-unavailable": "fresh correlated guest cleanup receipt",
    "final-guard-unavailable": "exact guest guard and ownership proof",
    "permission_granted": "ungranted Android VPN consent state",
    "mode_not_vpn": "VPN mode selected in the existing Android owner",
    "runtime_running": "stopped Android VPN runtime before the denial fixture",
    "ambiguous_runtime": "one unambiguous public Android runtime section",
    "diagnostics_unavailable": "fresh public Android diagnostics",
    "device_unknown": "owned Android device and staged CLI identity",
    "rebuild-required": "verified same-source package bytes and unchanged product inputs",
    "incomplete_or_conflicting_inventory": "complete all-process file-holder census and QEMU generation recheck",
    "unknown": "fresh exact-correlation driver download status",
    "partial": "complete fixed driver download and exact SHA256/size verification",
    "linked-partial": "complete fixed driver download and exact SHA256/size verification",
    "mismatch": "correct fixed driver ISO bytes at the private destination",
    "driver-fetch-boundary-unknown": "fresh status of the existing one-shot driver fetch intent",
    "driver-fetch-outcome-unavailable": "fresh status of the existing one-shot driver fetch intent",
    "windows-disk-probe-outcome-unavailable": "fresh status of the existing one-shot disk probe intent",
    "windows-disk-probe-boundary-unknown": "fresh status of the existing one-shot disk probe intent",
    "windows-fresh-setup-outcome-unavailable": "fresh status of the existing one-shot Windows VM intent",
    "windows-fresh-setup-boundary-unknown": "fresh status of the existing one-shot Windows VM intent",
}
_C32_ARCHIVE_ACTIONS = {"windows-cp117-c32-archive-diagnose", "windows-cp117-c32-archive-preflight"}
_RETAINED_GUARDS = {"ready", "TASK", "TASK_COUNT", "TASK_STATE", "TASK_ACTION_COUNT", "TASK_EXEC",
                    "TASK_TRIGGER_COUNT", "TASK_TRIGGER_NULL", "TASK_INFO", "PRINCIPAL", "ACTION", "ROOT",
                    "OWNER", "TREE", "FILE", "RESULT_SIZE", "RESULT_READ", "RESULT_JSON", "RESULT_UTF8_BOM",
                    "RESULT_UTF16_LE", "RESULT_UTF16_BE", "runtime-error"}
_RETAINED_PHASES = {"binding", "script", "transport", "guest-exec", "guest-status", "running", "terminal",
                    "json-shape", "task", "task-info", "principal", "action", "root", "owner", "tree",
                    "file", "result"}
_HOST_FAILURES = {"parents", "group", "leaf", "binding", "dispatch"}
_SOURCE_RESERVATION_ACTION = "windows-cp117-source-campaign-reservation-diagnose"
_SOURCE_BLOCKER_PHASES = {
    "c32": {"request", "history", "transfer-binding", "terminal-cleanup-dispatch", "local-ready", "closed",
            "cleanup", "absence", "host-history", "unknown"},
    "pre-effect": {"closure"},
    "transfer-recovery": {"closure-or-absence", "profile", "intent-profile", "marker", "active-lease",
                          "closed-lease", "census", "absence", "product", "installed-version", "evidence-hash",
                          "archived", "unknown", "diagnostic-unknown", "guest-unsafe", "census-transport",
                          "census-projection", "census-unknown"},
    "unknown-closure": {"closure-or-absence", "profile", "intent-profile", "marker", "active-lease",
                        "closed-lease", "census", "absence", "product", "installed-version", "evidence-hash",
                        "archived", "unknown", "diagnostic-unknown", "guest-unsafe", "census-transport",
                        "census-projection", "census-unknown"},
}
_SOURCE_CENSUS_PHASES = {"host-guard", "host-root", "remote-stage", "guest-census", "guest-cleanup",
                         "guest-recheck", "remote-stage-cleanup", "protocol", "guest-task", "guest-leaf",
                         "guest-process", "guest-product", "guest-installer", "guest-output", "guest-qga-exec",
                         "guest-qga-status-rpc", "guest-qga-status-exited-malformed",
                         "guest-qga-status-running-timeout", "guest-qga-status-terminal-fields",
                         "guest-qga-status-truncated", "guest-empty-or-malformed-output", "guest-projection",
                         "guest-unexpected-internal"}
for _record in ("transfer-recovery", "unknown-closure"):
    _SOURCE_BLOCKER_PHASES[_record].update("census-" + phase for phase in _SOURCE_CENSUS_PHASES)
_CAUSAL_REGRESSIONS = {
    ("TASK_TRIGGER_NULL", "task"):
        "agent_tools/tests/test_windows_cp117_c32_absence.py::test_windows_trigger_guard_accepts_only_empty_or_single_null",
    ("RESULT_UTF8_BOM", "result"):
        "agent_tools/tests/test_windows_cp117_c32_absence.py::test_windows_result_decoder_accepts_only_utf8_with_optional_bom",
    ("source-reservation",):
        "agent_tools/tests/test_windows_cp117_source_projection.py::test_reservation_blockers_are_finite_and_private_data_rejected",
}

# Public fingerprints use declared enums, never arbitrary regex-safe text from
# native receipts. A known token also belongs only to its declared route family.
_REASON_ACTIONS: dict[str, set[str]] = {}
for _known_action, _known_reason in _REGRESSIONS:
    _REASON_ACTIONS.setdefault(_known_action, set()).add(_known_reason)
for _known_action in _CHANNEL_ACTIONS:
    _REASON_ACTIONS[_known_action].add("channel_admission_unknown")
for _known_action in ("linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status"):
    _REASON_ACTIONS.setdefault(_known_action, set()).update({
        "owner-quit-unavailable", "workspace-reference-unknown", "target-package-or-runtime-unavailable",
        "existing-intent", "cleanup-response-uncertain", "missing-intent", "guest-status-unavailable",
        "final-guard-unavailable"})
for _known_action in ("android-consent-acceptance-preflight", "android-consent-acceptance-start",
                      "android-consent-acceptance-status"):
    _REASON_ACTIONS.setdefault(_known_action, set()).update({
        "permission_granted", "mode_not_vpn", "runtime_running", "ambiguous_runtime",
        "diagnostics_unavailable", "device_unknown"})
for _known_action in ("artifact-reuse-check", "artifact-cache-check"):
    _REASON_ACTIONS[_known_action] = {"rebuild-required"}
_REASON_ACTIONS["windows-vm-baseline-inventory"] = {"incomplete_or_conflicting_inventory"}
for _known_action in ("windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                      "windows-vm-disk-probe-start", "windows-vm-disk-probe-status",
                      "windows-vm-fresh-start", "windows-vm-fresh-status"):
    _REASON_ACTIONS.setdefault(_known_action, set()).update({"unknown", "partial", "linked-partial", "mismatch"})
_REASON_ACTIONS["windows-vm-disk-probe-start"].add("windows-disk-probe-boundary-unknown")
_REASON_ACTIONS["windows-vm-fresh-start"].add("windows-fresh-setup-boundary-unknown")
_PHASE_ACTIONS = {action: {"master_snapshot"} for action in _CHANNEL_ACTIONS}
_PHASE_ACTIONS["connection-master-status"] = {"socket_parser"}
for _known_action in ("linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status"):
    _PHASE_ACTIONS[_known_action] = {"owner_probe", "admission", "dispatch", "status", "closing"}


def _archive_basis(action: str, result: Mapping[str, Any]) -> dict[str, str]:
    if action not in _C32_ARCHIVE_ACTIONS:
        return {}
    guard = result.get("retainedGuard")
    phase = result.get("retainedPhase")
    host = result.get("hostFailure")
    return {"retainedGuard": guard if isinstance(guard, str) and guard in _RETAINED_GUARDS else "unspecified",
            "retainedPhase": phase if isinstance(phase, str) and phase in _RETAINED_PHASES else "unspecified",
            "hostFailure": host if isinstance(host, str) and host in _HOST_FAILURES else "unspecified"}


def _source_reservation_basis(action: str, result: Mapping[str, Any]) -> dict[str, list[list[str]]]:
    if action != _SOURCE_RESERVATION_ACTION:
        return {}
    blockers = result.get("blockers")
    if not isinstance(blockers, list) or not 1 <= len(blockers) <= 4:
        return {"sourceReservationBlockers": []}
    projected: list[list[str]] = []
    seen: set[str] = set()
    for blocker in blockers:
        if (not isinstance(blocker, Mapping) or set(blocker) != {"record", "phase"}
                or not isinstance(blocker.get("record"), str) or not isinstance(blocker.get("phase"), str)
                or blocker["record"] in seen or blocker["record"] not in _SOURCE_BLOCKER_PHASES
                or blocker["phase"] not in _SOURCE_BLOCKER_PHASES[blocker["record"]]):
            return {"sourceReservationBlockers": []}
        seen.add(blocker["record"])
        projected.append([blocker["record"], blocker["phase"]])
    return {"sourceReservationBlockers": projected}


def _causal_regression(action: str, reason: str, basis: Mapping[str, Any]) -> str | None:
    if action in _C32_ARCHIVE_ACTIONS:
        regression = _CAUSAL_REGRESSIONS.get((basis.get("retainedGuard"), basis.get("retainedPhase")))
        if regression is not None:
            return regression
    if action == _SOURCE_RESERVATION_ACTION and basis.get("sourceReservationBlockers"):
        if any(phase == "installed-version" and record in {"transfer-recovery", "unknown-closure"}
               for record, phase in basis["sourceReservationBlockers"]):
            return "agent_tools/tests/test_windows_cp117_source_campaign.py::test_historical_closure_diagnostic_reports_version_only_after_absence"
        return _CAUSAL_REGRESSIONS[("source-reservation",)]
    return _REGRESSIONS.get((action, reason))


def acceptance_guidance(result: Mapping[str, Any]) -> dict[str, Any]:
    """Name the next review gap from a read-only acceptance snapshot."""
    platforms = result.get("platforms")
    rows = platforms if isinstance(platforms, list) else []
    unmet = [gate for platform in rows if isinstance(platform, Mapping)
             for gate in platform.get("unmetGates", []) if isinstance(gate, Mapping)]
    first = next((gate.get("requirementId") for gate in unmet
                  if isinstance(gate.get("requirementId"), str)), None)
    if result.get("matrixGate") == "passed" and result.get("checkoutExact") is True:
        fact = "final exact-SHA delivery checks for this clean checkout"
    elif result.get("checkoutExact") is not True:
        fact = "clean exact-source checkout and reviewed native matrix evidence"
    else:
        fact = "reviewed current-source native matrix evidence"
    return {"nextAction": {"kind": "review-current-source-native-evidence",
                           "reason": fact, "replayAllowed": False,
                           "requiresFreshEvidence": True},
            "admissionGap": {"missingFact": fact, "requirementId": first,
                             "readOnlyAction": None, "nativeActionAllowed": False}}


def describe(tool: str, action: str, result: Mapping[str, Any]) -> dict[str, Any]:
    """No I/O, no command execution, no mutation authorization."""
    reason = result.get("reason") or result.get("code") or result.get("failureType") or result.get("decision")
    if (tool == "ssh_workflow" and action in _CHANNEL_ACTIONS
            and result.get("state") == "unknown" and result.get("failurePhase") == "master_snapshot"
            and type(result.get("failureReason")) is str and result["failureReason"] in _SNAPSHOT_REASONS
            and type(result.get("exceptionClass")) is str and result["exceptionClass"] in _SNAPSHOT_CLASSES
            and "errno" in result and (result["errno"] is None
                or (type(result["errno"]) is int and 0 <= result["errno"] <= 255))
            and result.get("nativeActionAllowed") is False and result.get("replayAllowed") is False):
        reason = result["failureReason"]
    if (tool == "ssh_workflow" and action == "connection-master-status"
            and result.get("state") == "unknown" and result.get("nestedState") == "unknown"
            and result.get("socketState") == "refused" and result.get("failurePhase") == "socket_parser"
            and all(result.get(key) is False for key in ("replayAllowed", "launchAllowed", "nativeActionAllowed"))):
        reason = "cached_socket_refused"
    if action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                  "windows-vm-disk-probe-start", "windows-vm-disk-probe-status",
                  "windows-vm-fresh-start", "windows-vm-fresh-status"} and not reason:
        reason = result.get("state")
    if not isinstance(reason, str) or reason not in _REASON_ACTIONS.get(action, ()):
        reason = "unclassified"
    phase = result.get("failurePhase")
    if not isinstance(phase, str) or phase not in _PHASE_ACTIONS.get(action, ()):
        phase = "unspecified"
    classification = "unknown" if (str(result.get("state", "")).lower() in {
        "unknown", "submitting", "pending", "closing", "owner_unknown"} or
        action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                   "windows-vm-baseline-inventory", "windows-vm-disk-probe-start",
                   "windows-vm-disk-probe-status", "windows-vm-fresh-start",
                   "windows-vm-fresh-status"}) else "failed"
    basis = {"tool": tool, "action": action, "classification": classification,
             "phase": phase, "reason": reason}
    basis.update(_archive_basis(action, result))
    basis.update(_source_reservation_basis(action, result))
    fingerprint = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    regression = _causal_regression(action, reason, basis)
    missing = _MISSING_FACT.get(reason, "fresh correlated admission or terminal evidence")
    read: dict[str, Any] | None = None
    if (action in _C32_ARCHIVE_ACTIONS and basis.get("retainedGuard") not in {"unspecified", "ready"}):
        read = {"tool": "vm_workflow", "action": "windows-cp117-c32-retained-parser", "inputs": {}}
    elif action in {"linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status"}:
        correlation = result.get("correlationId")
        if isinstance(correlation, str) and _UUID.fullmatch(correlation):
            read = {"tool": "vm_workflow", "action": "linux-rpm-workspace-cleanup-status",
                    "inputs": {"cleanupCorrelationId": correlation}}
    elif action in {"android-consent-acceptance-start", "android-consent-acceptance-status"}:
        correlation = result.get("correlationId")
        if isinstance(correlation, str) and _UUID.fullmatch(correlation):
            read = {"tool": "vm_workflow", "action": "android-consent-acceptance-status",
                    "inputs": {"correlationId": correlation}}
    elif action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status"}:
        correlation = result.get("correlationId")
        if isinstance(correlation, str) and _UUID.fullmatch(correlation):
            read = {"tool": "vm_workflow", "action": "windows-vm-driver-fetch-status",
                    "inputs": {"host": "archlinux", "correlationId": correlation,
                               "timeoutSeconds": 120}}
    elif action in {"windows-vm-disk-probe-start", "windows-vm-disk-probe-status"}:
        correlation = result.get("correlationId")
        if isinstance(correlation, str) and _UUID.fullmatch(correlation):
            read = {"tool": "vm_workflow", "action": "windows-vm-disk-probe-status",
                    "inputs": {"host": "archlinux", "correlationId": correlation,
                               "timeoutSeconds": 60}}
    elif action in {"windows-vm-fresh-start", "windows-vm-fresh-status"}:
        correlation = result.get("correlationId")
        if isinstance(correlation, str) and _UUID.fullmatch(correlation):
            read = {"tool": "vm_workflow", "action": "windows-vm-fresh-status",
                    "inputs": {"host": "archlinux", "correlationId": correlation,
                               "timeoutSeconds": 60}}
    return {"failureSignature": {"fingerprint": fingerprint, "basis": basis,
                                 "causalRegression": regression,
                                 "regressionRequired": regression is None},
            "admissionGap": {"missingFact": missing, "readOnlyAction": read,
                             "nativeActionAllowed": False}}
