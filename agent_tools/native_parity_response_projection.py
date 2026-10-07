"""Pure, finite public DTOs for four fixed native parity route families.

This module authenticates response structure and request correlation, not native
receipt authority. Native helpers retain their own source/lease/owner admission.
No helper import, filesystem access, transport, or product effect occurs here.
"""
from __future__ import annotations
import re
from copy import deepcopy

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA = re.compile(r"[0-9a-f]{64}")
_CP = "windows-cp117-staged-fixture-retire"
_STAGE = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
_LEASE = "e59a7483-4e38-4e7b-b8fa-0d8b2356916a"
_SERVER = "316e6189-5be0-4ea0-bca1-a3905816d815"
_SERVER_SHA = "9b0082788cf56f3d9f6d79fae5884bcd01333bb097faa77266af2ea8c3cdeef2"
_CREDENTIAL_SHA = "02377ac3321c1afae18c6a392c7546e5944be9f79f2a546f4f3ecd7b70084738"
_GRANT = "android-consent-grant-acceptance"
_RESET = "android-vpn-permission-reset"
_RUNTIME = "android-runtime-acceptance"
_FLAGS = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
_RESTORE = {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
            "selectedNull": True, "activeNull": True, "runtimeOff": True}
_GUARDS = frozenset("ACL ACL_COUNT ACL_PROTECTED ANCESTOR ANCESTOR_REPARSE BUNDLE CONTENT_TYPE DELETION_READY DIRECTORY_COUNT DIRECTORY_TREE FILE_COUNT FILE_HASH OWNER PROBE_EVENTS REPARSE RESULT RESULT_TYPE ROOT ROOT_TYPE STATE_TREE STATE_TYPE TREE PRECONDITION PRESENT UNSAFE BLOCKED ready runtime-error unknown".split())
_CATEGORIES = frozenset("NotSpecified OpenError CloseError DeviceError DeadlockDetected InvalidArgument InvalidData InvalidOperation InvalidResult InvalidType MetadataError NotImplemented NotInstalled ObjectNotFound OperationStopped OperationTimeout SyntaxError ParserError PermissionDenied ResourceBusy ResourceExists ResourceUnavailable ReadError WriteError FromStdErr SecurityError ProtocolError ConnectionError AuthenticationError LimitsExceeded QuotaExceeded NotEnabled None".split())
_GRANT_REASONS = frozenset("admitted_backup_changed baseline_not_empty_off cli_stage_changed collection_marker_changed command_encoding command_failed command_outcome_unknown device_changed device_lease_active device_lease_changed device_lease_missing device_lease_unsafe device_lock_busy device_lock_unsafe diagnostics_ambiguous durable_record_failed identity_invalid intent_changed job_unsafe mode_invalid on_not_accepted operation_not_no_location operation_terminal_changed operations_active operations_invalid owner_or_revision_changed package_changed pending_operation_changed pending_operation_missing permission_or_runtime_changed pre_effect_state_changed pre_tap_state_changed private_directory_unsafe private_file_changed private_file_unavailable private_file_unsafe prompt_changed prompt_deadline_expired prompt_not_owned proof_unavailable public_invalid restoration_changed routing_changed routing_shape_invalid scenario_unknown terminal_binding_invalid worker_failed worker_unknown worker_receipt_invalid missing_worker_receipt existing_intent_no_replay missing_or_invalid_local_intent missing_local_intent submit_unknown transport_or_proof_unknown fresh_postcondition_or_closure_unknown ui_observation_invalid preexisting_consent_prompt prompt_evidence_invalid diagnostic_export_cleanup_unknown diagnostic_export_invalid diagnostic_export_unsafe observation_history_changed observation_receipt_bound observation_receipt_invalid observation_receipt_unknown observation_receipt_unsafe routing_export_cleanup_unknown routing_export_invalid routing_export_unsafe".split())
_RESET_REASONS = frozenset("cli_stage_changed endpoint_lease_active existing_intent_no_replay fresh_postcondition_unknown identity_invalid intent_invalid intent_mismatch lease_release_unconfirmed missing_local_intent missing_worker_receipt remote_record_changed remote_record_unavailable route_unavailable status_unavailable submit_unknown terminal_binding_invalid transport_or_receipt_unknown unsafe_job unsafe_remote_record".split())
_RUNTIME_REASONS = frozenset("activity_binding_invalid activity_create_unknown activity_terminal_invalid fixture_outbound_not_proved identity_invalid intent_mismatch intent_profile_invalid local_intent_invalid missing_job_or_intent missing_local_intent missing_worker_receipt oversized_file parent_endpoint_changed route_changed status_unavailable submission_unknown terminal_binding_invalid transport_or_receipt_unknown unsafe_file unsafe_job".split())


def _keys(value, required, optional=()):
    return type(value) is dict and set(required) <= set(value) <= set(required) | set(optional)


def _uuid(value):
    return type(value) is str and _UUID.fullmatch(value) is not None


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _int(value, lower=0, upper=9223372036854775807):
    return type(value) is int and lower <= value <= upper


def _identity(value):
    return value is None or (_keys(value, {"pid", "startTicks"}) and _int(value["pid"], 1, 2147483647) and _int(value["startTicks"], 1))


def _grant_result(value, correlation):
    fixed = {"state": "complete", "reason": None, "correlationId": correlation,
             "operationCode": "INVALID_ARGUMENT", "permissionGranted": True,
             "runtimeStarted": False, "noLocation": True, "scope": "grant-only"}
    return (_keys(value, {*fixed, "operationId", "owner", "revision", "intentSha256"})
            and all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items())
            and _uuid(value["operationId"]) and _uuid(value["owner"])
            and _int(value["revision"]) and _sha(value["intentSha256"]))


def _runtime_result(value):
    required = {"state", "sourcePackageSha256", "parentCorrelationId", "campaignId", "opening", "closingOwner", "closingRevision", "selectedProxy", "outboundEvidence", "statsObserved", "admittedMode", "restoration"}
    return (_keys(value, required) and type(value["state"]) is str and value["state"] == "complete"
            and _sha(value["sourcePackageSha256"]) and _uuid(value["parentCorrelationId"])
            and _uuid(value["campaignId"]) and _keys(value["opening"], {"owner", "revision"})
            and _uuid(value["opening"]["owner"]) and _int(value["opening"]["revision"])
            and _uuid(value["closingOwner"]) and value["closingOwner"] == value["opening"]["owner"]
            and _int(value["closingRevision"]) and value["closingRevision"] > value["opening"]["revision"]
            and all(value[k] is True for k in ("selectedProxy", "outboundEvidence", "statsObserved"))
            and type(value["admittedMode"]) is str and value["admittedMode"] in {"vpn-authorized", "proxy-only"}
            and _keys(value["restoration"], _RESTORE) and all(value["restoration"][k] is True for k in _RESTORE))


def _reset_result(value):
    fixed = {"state": "complete", "api": 29, "package": "com.kardinal.vpncontrol", "appOp": "ACTIVATE_VPN", "mode": "ignore", "runtimeOff": True, "permissionAbsent": True}
    return (_keys(value, {*fixed, "owner", "revision"})
            and all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items())
            and _uuid(value["owner"]) and _int(value["revision"]))


def _worker_receipt(value, family):
    return (_keys(value, {"state", "result", "reason"}) and type(value["state"]) is str and value["state"] == "complete"
            and value["reason"] is None and (_runtime_result(value["result"]) if family == _RUNTIME else _reset_result(value["result"])))


def _android(family, method, correlation, value):
    required = {"ok", "state", "correlationId", "replayAllowed"}
    if family != _RESET: required.add("reason")
    if family == _RUNTIME: required.add("nativeMutationAllowed")
    optional = {"reason", "identity", "receipt", "result", "checkpoint", "leaseReleased", "nativeActionAllowed", "productAction"}
    if not _keys(value, required, optional) or not _uuid(correlation) or value["correlationId"] != correlation:
        return False
    state = value["state"]
    if type(state) is not str or state not in ({"submitted", "unknown", "blocked"} if method == "start" else {"complete", "unknown"} if family == _RESET else {"running", "complete", "unknown"}): return False
    if type(value["ok"]) is not bool or value["ok"] != (state in {"submitted", "running", "complete"}): return False
    if value["replayAllowed"] is not False or any(value[k] is not False for k in ("nativeMutationAllowed", "nativeActionAllowed", "productAction") if k in value): return False
    reason = value.get("reason")
    reasons = {_GRANT: _GRANT_REASONS, _RESET: _RESET_REASONS, _RUNTIME: _RUNTIME_REASONS}[family]
    if reason is not None and (type(reason) is not str or reason not in reasons): return False
    if state in {"submitted", "running", "complete"} and reason is not None: return False
    if state == "blocked" and reason not in ({"device_lease_active", "preexisting_consent_prompt"} if family == _GRANT else {"endpoint_lease_active"} if family == _RESET else set()): return False
    if "identity" in value and not _identity(value["identity"]): return False
    if state == "submitted" and ("identity" not in value or value["identity"] is None): return False
    if "checkpoint" in value and (family != _GRANT or state != "unknown" or value["checkpoint"] != "worker-returned-unknown"): return False
    if "leaseReleased" in value and (family == _RUNTIME or method != "collect" or state != "complete" or value["leaseReleased"] is not True): return False
    if "receipt" in value:
        if family == _GRANT: return False
        if value["receipt"] is not None and (state != "complete" or not _worker_receipt(value["receipt"], family)): return False
    if "result" in value:
        if state != "complete": return False
        if family == _GRANT:
            if not _grant_result(value["result"], correlation): return False
        elif family == _RUNTIME:
            result = value["result"]
            if method != "collect" or not _keys(result, {"selectedProxy", "outboundEvidence", "statsObserved", "fixtureSocksAndTrafficObserved", "admittedMode", "restoredEmptyBaseline"}) or not all(result[k] is True for k in result if k != "admittedMode") or type(result["admittedMode"]) is not str or result["admittedMode"] not in {"vpn-authorized", "proxy-only"}: return False
        else: return False
    payload_keys = set(value) - required - {"reason", "nativeActionAllowed", "productAction"}
    if state == "submitted" and payload_keys != {"identity"}: return False
    if state == "running":
        if family == _GRANT and payload_keys: return False
        if family == _RUNTIME and payload_keys != {"identity", "receipt"}: return False
    if state in {"unknown", "blocked"} and payload_keys - {"identity", "receipt", "checkpoint"}: return False
    if state == "complete":
        expected_payload = ({"result", "leaseReleased"} if method == "collect" else {"result"}) if family == _GRANT else ({"result"} if method == "collect" else {"identity", "receipt"}) if family == _RUNTIME else ({"leaseReleased"} if method == "collect" else {"identity", "receipt"})
        if payload_keys != expected_payload: return False
        if "identity" in value and value["identity"] is None: return False
        if family == _GRANT and "result" not in value: return False
        if family == _RUNTIME and not ("result" in value if method == "collect" else value.get("receipt") is not None): return False
        if family == _RESET and not (value.get("leaseReleased") is True if method == "collect" else value.get("receipt") is not None): return False
    return True


def _cp(method, value):
    if not _keys(value, {"state", *_FLAGS}, {"reason", "phase", "guard", "category", "stageCorrelationId", "leaseId", "serverCorrelationId", "serverCleanupReceiptSha256", "credentialCleanupReceiptSha256", "stage", "owner", "reparse", "serverTask", "serverProcess", "listener", "credentials", "runtime", "scripts", "root", "bundle", "content", "result", "serverState", "probeEvents", "unexpectedRootCount", "contentFileCount", "probeEntryCount", "otherPowerShellCount", "resultAccess", "resultReadOnly", "cause", "lockingProcess", "count", "qemuGaExactLocalSystem"}): return False
    if any(value[k] is not False for k in _FLAGS): return False
    state = value["state"]
    base = {"state", *_FLAGS}
    fields = set(value) - base
    if method in {"preflight", "start", "status"}:
        if state == "ready":
            fixed = {"stageCorrelationId": _STAGE, "leaseId": _LEASE, "serverCorrelationId": _SERVER, "serverCleanupReceiptSha256": _SERVER_SHA, "credentialCleanupReceiptSha256": _CREDENTIAL_SHA}
            return method == "preflight" and fields == set(fixed) and all(value[k] == v for k, v in fixed.items())
        if state == "retired": return method in {"start", "status"} and fields == {"stageCorrelationId", "leaseId"} and value["stageCorrelationId"] == _STAGE and value["leaseId"] == _LEASE
        if state == "not-started": return method == "status" and not fields
        if state == "blocked": return method in {"preflight", "start"} and ((fields == {"reason"} and value.get("reason") in {"durable-binding", "fresh-native-evidence"}) or (fields == {"reason", "guard"} and value.get("reason") == "native-guard" and type(value["guard"]) is str and value["guard"] in _GUARDS))
        return state == "unknown" and (not fields or fields == {"phase"} and value["phase"] in {"guest-submitted", "guest-removed", "host-submitted", "host-removed", "close-submitted"})
    if state == "diagnosed":
        phases = {"diagnose": {"guest-exec", "guest-status", "powershell-nonzero", "stdout-missing", "stdout-truncated", "json-shape", "transport", "admission"}, "parser": {"parser-qga", "parser-admission"}, "guard-diagnostic": {"admission", "guard-source", "guard-oversize", "guard-transport", "guard-admission"}, "boundary": {"admission", "guard-source", "guard-oversize", "guard-transport", "guard-admission"}, "tree": {"tree-transport", "tree-admission"}, "locks": {"guest-exec", "guest-status", "powershell-nonzero", "stdout-missing", "stdout-truncated", "json-shape", "lock-shape", "lock-transport", "lock-admission", "lock-oversize"}}
        return fields == {"phase"} and type(value["phase"]) is str and value["phase"] in phases[method]
    if state == "unknown": return not fields
    if state != "observed": return False
    if method == "diagnose":
        names = {"stage", "owner", "reparse", "serverTask", "serverProcess", "listener", "credentials", "runtime"}
        return fields == names and all(type(value[k]) is str and value[k] in {"present", "absent", "unsafe", "original-user", "system", "administrators", "other", "not-applicable", "unknown"} for k in names)
    if method == "parser":
        scripts = value.get("scripts")
        return fields == {"scripts"} and _keys(scripts, {"diagnostic", "preflight", "retire"}) and all(_keys(v, {"syntax", "runtime"}) and type(v["syntax"]) is str and v["syntax"] in {"valid", "invalid"} and type(v["runtime"]) is str and v["runtime"] in {"available", "unavailable"} for v in scripts.values())
    if method in {"guard-diagnostic", "boundary"}: return fields == {"guard", "category"} and type(value["guard"]) is str and value["guard"] in _GUARDS - {"unknown"} and type(value["category"]) is str and value["category"] in _CATEGORIES
    if method == "tree":
        paths = {"root", "bundle", "content", "result", "serverState", "probeEvents"}; counts = {"unexpectedRootCount", "contentFileCount", "probeEntryCount", "otherPowerShellCount"}
        return fields == paths | counts | {"resultAccess", "resultReadOnly"} and all(type(value[k]) is str and value[k] in {"present", "absent"} for k in paths | {"resultReadOnly"}) and all(_int(value[k], 0, 1000) for k in counts) and type(value["resultAccess"]) is str and value["resultAccess"] in {"absent", "exclusive-read", "sharing-or-io", "denied", "unknown"}
    return method == "locks" and fields == {"cause", "lockingProcess", "count", "qemuGaExactLocalSystem"} and type(value["cause"]) is str and value["cause"] in {"none", "low-hresult-32", "low-hresult-33", "other"} and type(value["lockingProcess"]) is str and value["lockingProcess"] in {"absent", "qemu-ga", "powershell", "other"} and _int(value["count"], 0, 100) and type(value["qemuGaExactLocalSystem"]) is bool and (not value["qemuGaExactLocalSystem"] or value["lockingProcess"] == "qemu-ga" and value["count"] == 1)


def project(action, requested_correlation, response):
    """Return a copied explicit DTO, or a fixed unknown without private values.

    ``action`` is the complete fixed vm_workflow action. CP117 requires None as
    correlation because its identity is fixed in source. Android requires the
    exact validated public request UUID. This is not an effects admission API.
    """
    unknown = {"ok": False, "state": "unknown", "reason": "response_projection_invalid", **_FLAGS}
    if type(action) is not str: return unknown
    family = next((f for f in (_CP, _GRANT, _RESET, _RUNTIME) if action.startswith(f + "-")), None)
    if family is None: return unknown
    method = action[len(family) + 1:]
    if family != _CP and _uuid(requested_correlation): unknown["correlationId"] = requested_correlation
    if family == _RUNTIME: unknown["nativeMutationAllowed"] = False
    try:
        if family == _CP:
            if requested_correlation is not None or method not in {"preflight", "start", "status", "diagnose", "parser", "guard-diagnostic", "boundary", "tree", "locks"} or not _cp(method, response): return unknown
        elif method not in {"start", "status", "collect"} or not _android(family, method, requested_correlation, response): return unknown
        result = deepcopy(response)
        if family == _CP: result["ok"] = result["state"] in {"ready", "retired", "observed", "diagnosed"}
        result["productAction"] = family != _CP and method == "start" and result["state"] == "submitted"
        return result
    except (KeyError, TypeError, ValueError, RecursionError):
        return unknown
