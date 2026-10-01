"""Read-only durable status for the CP117 HTTP update-fixture phases.

The action routes reserve their own intent before an effect.  This projection is
for the response-loss path: it consumes only that local intent, the immutable
stage intent, the bound VM descriptor, and the campaign receipt.  Its optional
host/guest probes execute no fixture mutation and it never invokes an action
route.  In particular, it must not call ``stage_start``, ``listener_start``,
``guest_create``, ``guest_download``, ``stage_extract``, ``cleanup`` or
``collect`` (the last can complete a campaign role).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_lease as campaign
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_http_stage as http_stage
from . import windows_update_fixture_stage as stage
from . import windows_large_artifact_transfer as large_transfer


PHASES = frozenset({
    "intent-absent", "source-receipt-mismatch", "vm-binding-mismatch",
    "campaign-unbound", "transfer-unobserved", "guest-create-or-download-unobserved",
    "extract-unobserved", "collected", "observation-unknown", "pre-effect-aborted",
})
NEXT_FACTS = frozenset({
    "prepare-not-accepted", "inspect-source-receipts", "inspect-vm-binding",
    "inspect-campaign-receipt", "observe-transfer-receipt", "observe-guest-receipt",
    "observe-extract-receipt", "collection-receipt-present", "observation-incomplete",
    "retire-aborted-stage",
})

_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def _request(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping) or set(value) != {"correlationId"}:
        raise ValueError("Fixture phase status requires exact correlationId.")
    correlation = value.get("correlationId")
    if not http_stage._canonical(correlation):
        raise ValueError("Fixture phase status correlation is invalid.")
    return correlation


def _bound(record: Mapping[str, Any], intent: Mapping[str, Any], descriptor: tuple[Any, ...]) -> bool:
    """Check only durable identities before any host/guest observation."""
    if (record.get("request") != intent.get("request")
            or record.get("leaseId") != intent.get("leaseId")
            or record.get("bundleSha256") != intent.get("bundleSha256")
            or record.get("bundleSize") != intent.get("bundleSize")
            or record.get("sourceFingerprint") != intent.get("sourceFingerprint")):
        return False
    environment, socket, pid, ticks, sid = descriptor
    return all(intent.get(name) == expected for name, expected in (
        ("environment", environment), ("socketPath", socket), ("pid", pid),
        ("startTicks", ticks), ("expectedSid", sid)))


_REMOTE_GUEST_STATUS = base._QGA + r'''import base64,json,time
sock,pid,ticks,encoded=sys.argv[1:]
def out(value):print(json.dumps(value,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or len(encoded)>30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(80):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if item.get('exitcode')!=0 or item.get('out-truncated') is not False or item.get('err-truncated') is not False:raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 value=json.loads(decode(raw))
 if value not in ({'state':'absent'},{'state':'created'},{'state':'downloaded'},{'state':'hash-mismatch'}):raise ValueError()
 out(value)
except Exception:out({'state':'unknown'})
'''


def _guest_observation(root: Path, correlation: str, record: Mapping[str, Any]) -> str:
    """Read the bounded guest leaf; this runs no scheduled task or fixture script."""
    try:
        _root, _record, config, _target = http_stage._record(root, correlation)
        _environment, socket, pid, ticks, _sid = base._descriptor(root)[2]
        script = r'''$ErrorActionPreference='Stop';$root='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-@CORR@';$file=Join-Path $root 'bundle.zip';try{if(-not [IO.Directory]::Exists($root)){[Console]::Out.WriteLine('{"state":"absent"}')}elseif(-not [IO.File]::Exists($file)){[Console]::Out.WriteLine('{"state":"created"}')}else{$item=Get-Item -LiteralPath $file -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'TYPE'};$hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant();[Console]::Out.WriteLine((if($item.Length -eq @SIZE@ -and $hash -ceq '@HASH@'){@{state='downloaded'}}else{@{state='hash-mismatch'}}|ConvertTo-Json -Compress))}}catch{exit 1}'''.replace("@CORR@", correlation).replace("@SIZE@", str(record["bundleSize"])).replace("@HASH@", record["bundleSha256"])
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        raw = base._remote(config, _REMOTE_GUEST_STATUS,
                           (socket, str(pid), str(ticks), encoded), None, 30)
        value = json.loads(raw) if raw is not None else None
        return value["state"] if isinstance(value, dict) and set(value) == {"state"} and value["state"] in {
            "absent", "created", "downloaded", "hash-mismatch", "unknown"} else "unknown"
    except (OSError, ValueError, TypeError, KeyError, base.WindowsMsiBasePrepareError,
            http_stage.WindowsUpdateFixtureHttpStageError):
        return "unknown"


def _terminal_collect(root: Path, correlation: str, record: Mapping[str, Any],
                      intent: Mapping[str, Any], config: Any, target: Any,
                      descriptor: tuple[Any, ...]) -> str:
    """Read an already-written stage receipt without completing its lease.

    A result.json alone is not terminal collection evidence.  The exact same
    receipt digest must already be committed as the successful ``stage`` role
    outcome in the source/VM/lease-bound campaign journal.  This is what makes
    a lost *collect* response observable without calling ``stage.status``.
    """
    try:
        core = large_transfer.read(root, correlation)
        if (core is None or core.get("binding") != http_stage._large_binding(record, descriptor)
                or core.get("phase") != "placed"):
            return "absent"
        directory, lock = campaign._locked(root)
        try:
            campaign_record = campaign._active(directory)
        finally:
            os.close(lock)
        expected_identity = base._campaign_identity(
            {**intent["request"], "correlationId": intent["leaseId"]}, descriptor)
        if (campaign_record is None or campaign_record.get("identity") != expected_identity
                or not campaign._remote_confirm(base._campaign_remote(config, target), "status", campaign_record, None)):
            return "absent"
        environment, socket, pid, ticks, sid = descriptor
        request = intent["request"]
        raw = base._remote(config, stage._REMOTE_STATUS, (
            str(target.fixture_transfer_root), environment, intent["leaseId"], correlation,
            socket, str(pid), str(ticks), sid, request["sourceSha"], intent["sourceFingerprint"],
            intent["bundleSha256"], request["fixtureReceiptArtifactId"],
            request["baseMsiArtifactId"], request["targetMsiArtifactId"]), None, 30)
        observed = json.loads(raw) if raw is not None else None
        result = observed.get("result") if isinstance(observed, dict) else None
        if (not isinstance(result, dict)
                or set(result) != {"version", "correlationId", "code", "bundleSha256", "files", "acl", "rootAcl", "stateAcl"}
                or result.get("version") != 1 or result.get("correlationId") != correlation
                or result.get("code") != "STAGED_NOT_SERVER_READY"
                or result.get("bundleSha256") != intent["bundleSha256"]
                or result.get("files") != intent["fileHashes"]):
            return "absent"
        stage.validate_stage_acl_receipt(result["acl"], sid,
                                         stage._GUEST + "\\mcp-update-fixture-" + correlation + "\\content")
        stage.validate_stage_acl_receipt(result["rootAcl"], sid,
                                         stage._GUEST + "\\mcp-update-fixture-" + correlation)
        stage._validate_state_acl(result["stateAcl"], sid,
                                  stage._GUEST + "\\mcp-update-fixture-" + correlation + "\\server-state")
        digest = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return "collected" if (campaign_record.get("state") == "active"
                               and campaign_record.get("role") is None
                               and campaign_record.get("lastOutcome") == "succeeded"
                               and campaign_record.get("lastEvidenceSha256") == digest) else "absent"
    except (OSError, ValueError, TypeError, KeyError, campaign.Cp117LeaseError,
            base.WindowsMsiBasePrepareError, stage.WindowsUpdateFixtureStageError,
            large_transfer.WindowsLargeArtifactTransferError):
        return "absent"


def _observe(root: Path, correlation: str, record: Mapping[str, Any], intent: Mapping[str, Any],
             config: Any, target: Any, descriptor: tuple[Any, ...]) -> dict[str, str]:
    """Read-only host and guest observations.  Collection is deliberately unclaimed.

    ``stage.collect`` is excluded because it can finish the campaign stage role.
    ``_terminal_collect`` instead reads its already committed receipt and lease
    digest, so status cannot create that terminal state.
    """
    try:
        listener_value = http_stage.listener_status(root, {"correlationId": correlation})
        listener = listener_value.get("state") if isinstance(listener_value, dict) else "unknown"
    except (OSError, ValueError, TypeError, http_stage.WindowsUpdateFixtureHttpStageError):
        listener = "unknown"
    if listener not in {"absent", "listening", "served", "stopped"}:
        listener = "unknown"
    return {"listener": listener, "guest": _guest_observation(root, correlation, record),
            "collect": _terminal_collect(root, correlation, record, intent, config, target, descriptor)}


def _result(correlation: str, phase: str, next_fact: str, *, source: str,
            vm: str, campaign_state: str, observation: Mapping[str, str] | None = None) -> dict[str, Any]:
    assert phase in PHASES and next_fact in NEXT_FACTS
    value: dict[str, Any] = {"state": "observed", "correlationId": correlation,
                             "phase": phase, "nextFact": next_fact, "source": source,
                             "vm": vm, "campaign": campaign_state,
                             "replayAllowed": False, "nativeActionAllowed": False,
                             "productAction": False}
    if observation is not None:
        value["observation"] = dict(observation)
    return value


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Return one finite fact for an uncertain CP117 HTTP fixture operation.

    This function is intentionally observation-only.  It never creates a journal,
    sends fixture bytes, starts a listener, creates a guest directory, downloads,
    extracts, cleans up, or completes a campaign lease.
    """
    correlation = _request(value)
    root_path = Path(root).resolve(strict=True)
    try:
        record = http_stage._read(root_path, correlation)
    except (OSError, ValueError, http_stage.WindowsUpdateFixtureHttpStageError):
        record = None
    if record is None:
        return _result(correlation, "intent-absent", "prepare-not-accepted",
                       source="absent", vm="unobserved", campaign_state="unobserved")
    try:
        http_stage._artifact(Path(record["bundlePath"]), record["bundleSha256"], record["bundleSize"])
    except (OSError, ValueError, KeyError, http_stage.WindowsUpdateFixtureHttpStageError):
        return _result(correlation, "source-receipt-mismatch", "inspect-source-receipts",
                       source="unverified", vm="unobserved", campaign_state="unobserved")
    try:
        intent = stage._read_intent(root_path, correlation)
    except (OSError, ValueError, stage.WindowsUpdateFixtureStageError):
        intent = None
    if intent is None or record.get("request") != intent.get("request"):
        return _result(correlation, "source-receipt-mismatch", "inspect-source-receipts",
                       source="mismatch", vm="unobserved", campaign_state="unobserved")
    try:
        config, target, descriptor = base._descriptor(root_path)
    except (OSError, ValueError, base.WindowsMsiBasePrepareError):
        return _result(correlation, "vm-binding-mismatch", "inspect-vm-binding",
                       source="bound", vm="unobserved", campaign_state="unobserved")
    if not _bound(record, intent, descriptor):
        return _result(correlation, "vm-binding-mismatch", "inspect-vm-binding",
                       source="bound", vm="mismatch", campaign_state="unobserved")
    try:
        campaign_value = campaign.inspect(root_path, intent["leaseId"])
        campaign_state = campaign_value.get("state") if isinstance(campaign_value, dict) else "unknown"
    except (OSError, ValueError, KeyError, campaign.Cp117LeaseError):
        campaign_state = "unknown"
    if campaign_state not in {"active", "role-active", "pending-role", "pending-finish", "closed"}:
        return _result(correlation, "campaign-unbound", "inspect-campaign-receipt",
                       source="bound", vm="bound", campaign_state="unknown")
    if correlation == http_stage._E66_CORRELATION:
        try:
            core = large_transfer.read(root_path, correlation)
            transcript = http_stage._e66_transcript(root_path)
            aborted = (core is not None
                       and core.get("binding") == http_stage._large_binding(record, descriptor)
                       and core.get("phase") == "aborted"
                       and core.get("dispatchFailure") == http_stage._E66_FAILURE
                       and core.get("preEffectClose") == {
                           "reason": "source-not-path", "remoteStage": "absent"}
                       and http_stage._e66_imported(root_path, transcript))
        except (OSError, ValueError, TypeError, KeyError,
                large_transfer.WindowsLargeArtifactTransferError,
                http_stage.WindowsUpdateFixtureHttpStageError):
            aborted = False
        if aborted:
            return _result(correlation, "pre-effect-aborted",
                           "retire-aborted-stage" if campaign_state == "role-active"
                           else "inspect-campaign-receipt",
                           source="bound", vm="bound", campaign_state=campaign_state)
    observation = _observe(root_path, correlation, record, intent, config, target, descriptor)
    if observation.get("collect") == "collected":
        return _result(correlation, "collected", "collection-receipt-present", source="bound",
                       vm="bound", campaign_state=campaign_state, observation=observation)
    if observation.get("guest") == "downloaded":
        return _result(correlation, "extract-unobserved", "observe-extract-receipt", source="bound",
                       vm="bound", campaign_state=campaign_state, observation=observation)
    if observation.get("listener") in {"listening", "served", "stopped"}:
        return _result(correlation, "guest-create-or-download-unobserved", "observe-guest-receipt",
                       source="bound", vm="bound", campaign_state=campaign_state, observation=observation)
    if observation.get("listener") == "absent" and observation.get("guest") in {"absent", "created"}:
        return _result(correlation, "transfer-unobserved", "observe-transfer-receipt", source="bound",
                       vm="bound", campaign_state=campaign_state, observation=observation)
    return _result(correlation, "observation-unknown", "observation-incomplete", source="bound",
                   vm="bound", campaign_state=campaign_state, observation=observation)
