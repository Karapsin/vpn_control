"""Pure admission of explicitly named native SSH wire event evidence.

The caller owns file selection, immutable hash/generation9 custody and source
closing. This helper never discovers files, reads paths, runs code or processes,
changes native state, or establishes a successful native operation by itself.
"""
from __future__ import annotations

import re
import uuid


KINDS = ("stage", "execute", "verify")
AUTHORITY_FIELDS = frozenset({
    "qualificationId", "automaticCorrelation", "allowedCodeSha256", "carrierBytes",
    "carrierSha256", "expectedArgv", "expectedPrincipal",
})
EVENT_FIELDS = frozenset({
    "argvSha256", "automaticCorrelation", "commandBytes", "controlMaster", "forwarding",
    "freshOneShot", "kind", "localUid", "maxArgumentBytes", "parentPid", "pid",
    "qualificationId", "remoteCarrierCodeSha256", "replayAllowed", "sshExecutable",
})
_NAME = re.compile(r"wire-([0-9a-f]{32})\.json\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CORRELATION = re.compile(r"[0-9a-f]{32}\Z")
_PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class WireEvidenceError(ValueError):
    """Explicit source-held evidence did not match its complete expectation."""


def _require(condition, reason):
    if not condition:
        raise WireEvidenceError(reason)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _qualification(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _argv(value):
    return (type(value) in (list, tuple) and len(value) <= 128
            and all(type(item) is str and not any(ord(char) < 32 or ord(char) == 127 for char in item)
                    and len(item.encode("utf-8")) <= 60000 for item in value))


def validate_wire_evidence(authority, named_events, *, expected_qualification_id,
                           expected_correlation, current_uid, expected_code_sha256,
                           expected_pids, expected_parent_pid, expected_carrier_bytes,
                           expected_carrier_sha256, expected_argv, expected_principal):
    """Validate exactly three supplied events separately from their authority.

    ``named_events`` is an explicit filename-to-decoded-dict mapping. Each name
    must be ``wire-<32 lowercase hex>.json``; a directory glob and an authority
    document never constitute event admission. Expected PIDs and their common
    parent must come from the caller's independently held process evidence.
    """
    _require(_qualification(expected_qualification_id), "wire_expected_qualification")
    _require(type(expected_correlation) is str and _CORRELATION.fullmatch(expected_correlation) is not None,
             "wire_expected_correlation")
    _require(_integer(current_uid, 0, 2**32 - 1), "wire_expected_uid")
    _require(_integer(expected_parent_pid, 1, 2**63 - 1), "wire_expected_parent")
    _require(type(expected_code_sha256) is dict and set(expected_code_sha256) == set(KINDS)
             and all(_sha(value) for value in expected_code_sha256.values()), "wire_expected_code")
    _require(type(expected_pids) is dict and set(expected_pids) == set(KINDS)
             and all(_integer(value, 1, 2**63 - 1) for value in expected_pids.values())
             and len(set(expected_pids.values())) == 3
             and expected_parent_pid not in expected_pids.values(), "wire_expected_pids")
    _require(_integer(expected_carrier_bytes, 1, 8 * 1024 * 1024), "wire_expected_carrier_bytes")
    _require(_sha(expected_carrier_sha256), "wire_expected_carrier_sha256")
    _require(_argv(expected_argv), "wire_expected_argv")
    _require(type(expected_principal) is str and _PRINCIPAL.fullmatch(expected_principal) is not None,
             "wire_expected_principal")

    _require(type(authority) is dict and set(authority) == AUTHORITY_FIELDS, "wire_authority_schema")
    _require(authority["qualificationId"] == expected_qualification_id
             and authority["automaticCorrelation"] == expected_correlation, "wire_authority_identity")
    _require(type(authority["allowedCodeSha256"]) is dict
             and set(authority["allowedCodeSha256"]) == set(KINDS)
             and all(_sha(value) for value in authority["allowedCodeSha256"].values())
             and authority["allowedCodeSha256"] == expected_code_sha256, "wire_authority_code")
    _require(_integer(authority["carrierBytes"], 1, 8 * 1024 * 1024)
             and authority["carrierBytes"] == expected_carrier_bytes
             and _sha(authority["carrierSha256"])
             and authority["carrierSha256"] == expected_carrier_sha256, "wire_authority_carrier")
    _require(type(authority["expectedArgv"]) is list and _argv(authority["expectedArgv"])
             and authority["expectedArgv"] == list(expected_argv)
             and type(authority["expectedPrincipal"]) is str
             and authority["expectedPrincipal"] == expected_principal, "wire_authority_arguments")

    _require(type(named_events) is dict and len(named_events) == 3, "wire_event_count")
    by_kind = {}
    names_by_kind = {}
    ids = set()
    pids = set()
    for name, event in named_events.items():
        match = _NAME.fullmatch(name) if type(name) is str else None
        _require(match is not None, "wire_event_filename")
        _require(match.group(1) not in ids, "wire_event_duplicate_id")
        ids.add(match.group(1))
        _require(type(event) is dict and set(event) == EVENT_FIELDS, "wire_event_schema")
        kind = event["kind"]
        _require(type(kind) is str and kind in KINDS and kind not in by_kind, "wire_event_kind")
        _require(type(event["qualificationId"]) is str
                 and event["qualificationId"] == expected_qualification_id
                 and type(event["automaticCorrelation"]) is str
                 and event["automaticCorrelation"] == expected_correlation, "wire_event_identity")
        _require(_integer(event["localUid"], 0, 2**32 - 1)
                 and event["localUid"] == current_uid, "wire_event_uid")
        _require(_integer(event["pid"], 1, 2**63 - 1)
                 and event["pid"] == expected_pids[kind] and event["pid"] not in pids
                 and _integer(event["parentPid"], 1, 2**63 - 1)
                 and event["parentPid"] == expected_parent_pid, "wire_event_process")
        pids.add(event["pid"])
        _require(_integer(event["commandBytes"], 1, 60000)
                 and _integer(event["maxArgumentBytes"], 1, 60000), "wire_event_size")
        _require(_sha(event["argvSha256"]) and _sha(event["remoteCarrierCodeSha256"])
                 and event["remoteCarrierCodeSha256"] == expected_code_sha256[kind], "wire_event_code")
        _require(type(event["sshExecutable"]) is str and event["sshExecutable"] == "/usr/bin/ssh"
                 and event["freshOneShot"] is True and event["controlMaster"] is False
                 and event["forwarding"] is False and event["replayAllowed"] is False, "wire_event_safety")
        by_kind[kind] = dict(event)
        names_by_kind[kind] = name
    _require(set(by_kind) == set(KINDS), "wire_event_kinds")
    return {"state": "validated", "eventCount": 3,
            "eventNames": {kind: names_by_kind[kind] for kind in KINDS},
            "wireRecords": [by_kind[kind] for kind in KINDS], "replayAllowed": False}
