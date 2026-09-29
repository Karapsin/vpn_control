"""Deterministic, redacted failure grouping and admission gaps for MCP receipts."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


_TOKEN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_REGRESSIONS = {
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
    ("windows-vm-driver-fetch-start", "driver-fetch-boundary-unknown"):
        "agent_tools/tests/test_native_optimization_routes.py::test_driver_fetch_unexpected_boundary_exception_keeps_correlation_and_status_only",
    ("windows-vm-driver-fetch-start", "driver-fetch-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_driver_fetch_route_exact_identity_and_status_read_only",
    ("windows-vm-disk-probe-start", "windows-disk-probe-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_disk_probe_routes_preserve_exact_one_shot_identity",
    ("windows-vm-fresh-start", "windows-fresh-setup-outcome-unavailable"):
        "agent_tools/tests/test_native_optimization_routes.py::test_windows_fresh_start_status_require_exact_reservation",
}
_MISSING_FACT = {
    "owner-quit-unavailable": "terminal public quit for the exact replacement owner",
    "workspace-reference-unknown": "fresh absent workspace and process references",
    "target-package-or-runtime-unavailable": "exact installed target package and stopped runtime",
    "existing-intent": "terminal status of the existing cleanup intent",
    "cleanup-response-uncertain": "terminal status of the existing cleanup intent",
    "missing-intent": "durable cleanup intent for this correlation",
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
    if action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                  "windows-vm-disk-probe-start", "windows-vm-disk-probe-status",
                  "windows-vm-fresh-start", "windows-vm-fresh-status"} and not reason:
        reason = result.get("state")
    if not isinstance(reason, str) or not _TOKEN.fullmatch(reason):
        reason = "unclassified"
    phase = result.get("failurePhase")
    if not isinstance(phase, str) or not _TOKEN.fullmatch(phase):
        phase = "unspecified"
    classification = "unknown" if (str(result.get("state", "")).lower() in {
        "unknown", "submitting", "pending", "closing", "owner_unknown"} or
        action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                   "windows-vm-baseline-inventory", "windows-vm-disk-probe-start",
                   "windows-vm-disk-probe-status", "windows-vm-fresh-start",
                   "windows-vm-fresh-status"}) else "failed"
    basis = {"tool": tool, "action": action, "classification": classification,
             "phase": phase, "reason": reason}
    fingerprint = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    regression = _REGRESSIONS.get((action, reason))
    missing = _MISSING_FACT.get(reason, "fresh correlated admission or terminal evidence")
    read: dict[str, Any] | None = None
    if action in {"linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status"}:
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
