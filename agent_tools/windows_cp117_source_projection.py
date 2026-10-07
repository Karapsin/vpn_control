"""Finite MCP projections for the fixed CP117 source campaign.

The campaign module retains private journals and can return useful internal
diagnostic detail.  This boundary exposes only the exact facts that a caller
needs to drive the fixed one-shot sequence.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from . import windows_cp117_source_campaign as campaign
from . import windows_msi_base_prepare as base


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False, "ok": False}
_ACTIONS = {"preflight", "start", "status", "diagnose", "terminal-reconcile", "finish", "parser", "reservation-diagnose"}


def _id(value: Any) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def _enum(value: Any, allowed: set[str] | frozenset[str]) -> bool:
    """Accept only a string member of a finite response enum."""
    return isinstance(value, str) and value in allowed


def unknown() -> dict[str, Any]:
    """Return the only fallback shape used by every rejected projection."""
    return dict(_UNKNOWN)


def _unknown_from(value: Mapping[str, Any], correlation_key: str | None) -> dict[str, Any]:
    """Keep a validated correlation useful for inspection, never other detail."""
    expected = {"state", "replayAllowed", "nativeActionAllowed", "productAction"}
    if correlation_key is not None and _id(value.get(correlation_key)):
        expected |= {correlation_key}
        if set(value) == expected and value.get("state") == "unknown" and value.get("replayAllowed") is False and value.get("nativeActionAllowed") is False and value.get("productAction") is False:
            return {**dict(_UNKNOWN), correlation_key: value[correlation_key]}
    if set(value) == expected - ({correlation_key} if correlation_key else set()) and value.get("state") == "unknown" and value.get("replayAllowed") is False and value.get("nativeActionAllowed") is False and value.get("productAction") is False:
        return unknown()
    return unknown()


def _common(value: Mapping[str, Any], correlation_key: str) -> bool:
    return (value.get("replayAllowed") is False
            and value.get("nativeActionAllowed") is False
            and _id(value.get(correlation_key)))


def _preflight(value: Mapping[str, Any]) -> dict[str, Any]:
    expected_inputs = {"host": "archlinux", "correlationId": value.get("leaseId"),
                       "sourceSha": campaign._SOURCE,
                       "fixtureReceiptArtifactId": campaign._RECEIPT,
                       "baseMsiArtifactId": campaign._BASE,
                       "targetMsiArtifactId": campaign._TARGET,
                       "expectedCurrentVersion": campaign._BASE_VERSION}
    expected = {
        "state", "leaseId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId",
        "targetMsiArtifactId", "retiredLeaseId", "retiredStageCorrelationId",
        "baseInstallRequired", "generalBaseRouteAllowed", "nextAction", "sourceBaseInstallInputs",
        "replayAllowed", "nativeActionAllowed", "productAction",
    }
    if value.get("state") == "blocked":
        blocked = {"state", "reason", "replayAllowed", "nativeActionAllowed", "productAction"}
        if (set(value) == blocked and _enum(value.get("reason"), {"retirement-not-terminal", "base-not-idle", "new-source-pair", "new-correlation-present", "journal-unreadable", "historical-base-unresolved", "journal-unresolved", "legacy-job", "legacy-idle", "legacy-tasks", "legacy-history"})
                and value.get("replayAllowed") is False and value.get("nativeActionAllowed") is False
                and value.get("productAction") is False):
            return {**dict(value), "ok": False}
        return unknown()
    if (set(value) != expected or value.get("state") != "ready" or not _common(value, "leaseId")
            or value.get("productAction") is not False
            or value.get("sourceSha") != campaign._SOURCE
            or value.get("fixtureReceiptArtifactId") != campaign._RECEIPT
            or value.get("baseMsiArtifactId") != campaign._BASE
            or value.get("targetMsiArtifactId") != campaign._TARGET
            or value.get("retiredLeaseId") != campaign._OLD_LEASE
            or value.get("retiredStageCorrelationId") != campaign._OLD_STAGE
            or value.get("baseInstallRequired") is not True
            or value.get("generalBaseRouteAllowed") is not False
            or value.get("nextAction") != "source-bound-base-install"
            or value.get("sourceBaseInstallInputs") != expected_inputs):
        return unknown()
    return {**dict(value), "ok": True}


def _submitted(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"state", "correlationId", "replayAllowed", "nativeActionAllowed", "productAction"}
    if (set(value) != expected or value.get("state") != "submitted" or not _common(value, "correlationId")
            or value.get("productAction") is not True):
        return unknown()
    return {**dict(value), "ok": True}


def _terminal(value: Mapping[str, Any], *, product_action: bool) -> dict[str, Any]:
    expected = {"state", "correlationId", "result", "stage", "exitCode", "sourceSha",
                "baseArtifactId", "replayAllowed"}
    if (set(value) != expected or value.get("state") != "terminal" or not _id(value.get("correlationId"))
            or value.get("result") != "PASSED" or value.get("stage") != "READBACK"
            or type(value.get("exitCode")) is not int or value.get("exitCode") != 0 or value.get("sourceSha") != campaign._SOURCE
            or value.get("baseArtifactId") != campaign._BASE or value.get("replayAllowed") is not False):
        return unknown()
    return {**dict(value), "nativeActionAllowed": False, "productAction": product_action, "ok": True}


def _status(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("state") == "terminal":
        expected = {"state", "correlationId", "result", "stage", "exitCode", "sourceSha",
                    "baseArtifactId", "replayAllowed", "nativeActionAllowed", "productAction"}
        if (set(value) != expected or value.get("nativeActionAllowed") is not False
                or value.get("productAction") is not True):
            return unknown()
        terminal = _terminal({key: value[key] for key in expected - {"nativeActionAllowed", "productAction"}},
                             product_action=False)
        return terminal
    expected = {"state", "correlationId", "replayAllowed", "nativeActionAllowed", "productAction"}
    if (set(value) != expected or value.get("state") != "running" or not _common(value, "correlationId")
            or value.get("productAction") is not True):
        return unknown()
    # Status is observational even though the underlying operation is a product action.
    return {**dict(value), "productAction": False, "ok": True}


def _parser(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"state", "correlationId", "checks", "replayAllowed", "nativeActionAllowed", "productAction"}
    checks = ["ps5-parse", "gzip", "embedded-task", "action-hash"]
    if (set(value) != expected or not _enum(value.get("state"), {"passed", "failed"})
            or not _common(value, "correlationId") or value.get("productAction") is not False
            or value.get("checks") != checks):
        return unknown()
    return {**dict(value), "ok": value["state"] == "passed"}


def _finish(value: Mapping[str, Any]) -> dict[str, Any]:
    # campaign_lease.finish_role returns active after it atomically releases the role.
    expected = {"state", "leaseId", "replayAllowed"}
    if (set(value) != expected or value.get("state") != "active" or not _id(value.get("leaseId"))
            or value.get("replayAllowed") is not False):
        return unknown()
    return {**dict(value), "nativeActionAllowed": False, "productAction": False, "ok": True}


def _diagnose(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("state") == "observed":
        fields = {"state", "correlationId", "phase", "replayAllowed", "nativeActionAllowed", "productAction"}
        extras = {"legacyTaskState", "legacyTasks"}
        detail = {"legacyTaskIdentities", "unclassifiedTaskCount"}
        valid = set(value) == fields
        if set(value) in (fields | extras, fields | extras | detail) and value.get("phase") == "legacy-tasks":
            counts = value.get("legacyTasks")
            identities = {"legacy", "c32", "recovery", "retirement"}
            valid = (value.get("legacyTaskState") == "observed" and isinstance(counts, Mapping)
                     and set(counts) == identities | {"other", "activeInstallerCount"}
                     and all(type(counts[k]) is int and 0 <= counts[k] <= (1 if k in identities else 1000)
                             for k in counts))
            if detail.issubset(value) and valid:
                items = value["legacyTaskIdentities"]
                unclassified = value["unclassifiedTaskCount"]
                purposes = {"base", "msi", "transfer", "target", "owner-observe", "owner-network",
                            "network-probe", "fixture-server", "fixture-http", "cp95-acquire", "cp95-python"}
                valid = (isinstance(items, list) and len(items) <= 16
                         and type(unclassified) is int and 0 <= unclassified <= 16
                         and len(items) + unclassified == counts["other"])
                seen = set()
                if valid:
                    for item in items:
                        if (not isinstance(item, Mapping) or set(item) != {"purpose", "correlationId", "taskState"}
                                or not isinstance(item.get("purpose"), str) or item["purpose"] not in purposes
                                or not _id(item.get("correlationId"))
                                or not _enum(item.get("taskState"), {"ready", "running", "queued", "disabled", "other"})):
                            valid = False; break
                        identity = (item["purpose"], item["correlationId"])
                        if identity in seen:
                            valid = False; break
                        seen.add(identity)
        if (valid and _common(value, "correlationId")
                and value.get("productAction") is False
                and _enum(value.get("phase"), campaign._SOURCE_DIAGNOSTIC_PHASES)):
            return {**dict(value), "ok": True}
        return unknown()
    expected = {"state", "correlationId", "binding", "checkpoint", "replayAllowed", "nativeActionAllowed"}
    if value.get("state") == "unknown":
        pairs = {("unverified", "local-intent"), ("unverified", "descriptor"),
                 ("mismatch", "descriptor"), ("unverified", "qga-protocol"),
                 ("exact", "qga-protocol")}
        if (set(value) == expected and _common(value, "correlationId")
                and _enum(value.get("binding"), {"exact", "mismatch", "unverified"})
                and _enum(value.get("checkpoint"), {"local-intent", "descriptor", "qga-protocol"})
                and (value.get("binding"), value.get("checkpoint")) in pairs):
            return {**dict(value), "productAction": False, "ok": False}
        return unknown()
    if (not expected.issubset(value) or value.get("state") != "diagnosed" or not _common(value, "correlationId")
            or not _enum(value.get("binding"), {"exact", "mismatch", "unverified"})
            or not _enum(value.get("checkpoint"), base._DIAGNOSTIC_CHECKPOINTS)):
        return unknown()
    if ((value["checkpoint"] == "remote-binding") != (value["binding"] == "mismatch")
            and value["checkpoint"] != "local-intent"):
        return unknown()
    if value["checkpoint"] != "remote-dispatch-absent":
        if set(value) != expected:
            return unknown()
        return {**dict(value), "productAction": False, "ok": True}
    detail = {"guestProof", "guestProofFailure", "guestProofFailurePhase", "guestProofProjectionReason"}
    optional = {"guestProofProjectionSchema"}
    if set(value) != expected | detail and set(value) != expected | detail | optional:
        return unknown()
    proof = value.get("guestProof")
    proof_fields = {"task", "leaf", "result", "correlationPowerShell", "product", "installedVersion", "installer"}
    if (not isinstance(proof, Mapping) or set(proof) != proof_fields
            or any(not _enum(proof.get(key), {"present", "absent", "unknown"})
                   for key in ("task", "leaf", "result", "correlationPowerShell", "installer"))
            or not _enum(proof.get("product"), {"absent", "single", "multiple", "unknown"})
            or (proof["product"] == "single" and (not isinstance(proof.get("installedVersion"), str)
                                                     or base._VERSION.fullmatch(proof["installedVersion"]) is None))
            or (proof["product"] != "single" and proof.get("installedVersion") is not None)
            or not _enum(value.get("guestProofFailure"), {"none", "qga-exec-rpc-or-protocol", "qga-status-rpc-or-protocol",
                                                        "qga-status-exited-malformed", "qga-status-terminal-fields-malformed",
                                                        "qga-status-running-timeout", "qga-truncated", "powershell-nonzero",
                                                        "powershell-empty-or-malformed-output", "projection"})
            or not _enum(value.get("guestProofFailurePhase"), {"none", "task", "leaf", "process", "product", "installer", "output", "unavailable"})
            or not _enum(value.get("guestProofProjectionReason"), {"none", "unavailable", "missing-or-extra-fields",
                                                                  "version-or-phase-invalid", "nonzero-failure-envelope-invalid",
                                                                  "success-enum-invalid", "product-version-invalid", "internal-error"})):
        return unknown()
    if "guestProofProjectionSchema" in value:
        schema = value["guestProofProjectionSchema"]
        if (not isinstance(schema, Mapping) or set(schema) != {"presenceMask", "extraFieldCount"}
                or not isinstance(schema.get("presenceMask"), str) or re.fullmatch(r"[01]{9}", schema["presenceMask"]) is None
                or type(schema.get("extraFieldCount")) is not int or not 0 <= schema["extraFieldCount"] <= 9):
            return unknown()
    return {**dict(value), "guestProof": dict(proof), "productAction": False, "ok": True}


def project(action: str, value: Any) -> dict[str, Any]:
    """Project one campaign response, rejecting every unrecognised shape."""
    if not _enum(action, _ACTIONS) or not isinstance(value, Mapping):
        return unknown()
    correlation_key = "leaseId" if action == "preflight" else "correlationId"
    if value.get("state") == "unknown":
        if action == "diagnose" and "checkpoint" in value:
            return _diagnose(value)
        return _unknown_from(value, correlation_key)
    if action == "preflight":
        return _preflight(value)
    if action == "reservation-diagnose":
        expected={"state","newIntent","historical","replayAllowed","nativeActionAllowed","productAction"}
        if (set(value) not in (expected,expected|{"knownRecordCount"},expected|{"knownRecordCount","blockers"}) or value.get("state")!="observed"
            or not _enum(value.get("newIntent"), {"absent","present"}) or not _enum(value.get("historical"), {"absent","present"})
            or value.get("replayAllowed") is not False or value.get("nativeActionAllowed") is not False
            or value.get("productAction") is not False
            or ("knownRecordCount" in value and (type(value["knownRecordCount"]) is not int or not 0<=value["knownRecordCount"]<=10))):return unknown()
        if "blockers" in value:
            blockers=value["blockers"]
            phases={"c32":{"request","history","transfer-binding","terminal-cleanup-dispatch","local-ready","closed","cleanup","absence","host-history","unknown"},
                    "pre-effect":{"closure"},"source-pre-effect":{"intent","marker","binding","fresh","verified","unknown"},"transfer-recovery":{"closure-or-absence","profile","intent-profile","marker","active-lease","closed-lease","census","absence","product","installed-version","evidence-hash","archived","unknown","diagnostic-unknown"},"unknown-closure":{"closure-or-absence","profile","intent-profile","marker","active-lease","closed-lease","census","absence","product","installed-version","evidence-hash","archived","unknown","diagnostic-unknown"}}
            for label in ("transfer-recovery","unknown-closure"):
                phases[label].update({"guest-unsafe","census-transport","census-projection","census-unknown",*("census-"+phase for phase in base._UNKNOWN_CLEANUP_PHASES)})
            if not isinstance(blockers,list) or not 1<=len(blockers)<=5:return unknown()
            seen=set()
            for item in blockers:
                if not isinstance(item,dict) or set(item)!={"record","phase"} or not isinstance(item["record"],str) or not isinstance(item["phase"],str):return unknown()
                if item["record"] not in phases or item["record"] in seen or item["phase"] not in phases[item["record"]]:return unknown()
                seen.add(item["record"])
        return {**dict(value),"ok":True}
    if action == "start":
        if value.get("state")=="blocked":
            expected={"state","phase","correlationId","replayAllowed","nativeActionAllowed","productAction"}
            if (set(value)==expected and value.get("phase")=="reservation" and _common(value,"correlationId") and value.get("productAction") is False):return {**dict(value),"ok":False}
            return _preflight(value)
        return _submitted(value)
    if action == "status":
        return _status(value)
    if action == "terminal-reconcile":
        return _terminal(value, product_action=False)
    if action == "finish":
        return _finish(value)
    if action == "parser":
        return _parser(value)
    return _diagnose(value)
