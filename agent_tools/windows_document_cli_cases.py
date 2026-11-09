"""Finite ordinary-worker entry point for authenticated document subcases.

Integrates only through the shared worker's reviewed run(owner, workspace,
identity, harness) convention. The task request must contain documentAcceptance
with the exact schema below. No observed bindings are filled from this file.
The separate real-principal, GUI and cold-owner actions remain required.
"""
import json
from pathlib import Path
import time
import uuid

# The error types of this module's own finite document- codes; the harness's AssertionError is known too.
KNOWN_ERRORS = ("RuntimeError", "Refused")


def need(value, code):
    if not value:
        raise RuntimeError(code)


def _inputs(owner):
    inputs = owner.request["documentAcceptance"]
    need(type(inputs) is dict and set(inputs) == {"schemaVersion", "clientPath", "windowsPath", "racePath",
        "largeRoutingInputPath", "spoolTempParent", "contexts", "endpointPinBeforeObservation"},
        "document-finite-action-input-schema")
    need(inputs["schemaVersion"] == 1 and inputs["endpointPinBeforeObservation"] is None,
         "document-endpoint-must-be-observed-after-owner-readiness")
    contexts = inputs["contexts"]
    need(type(contexts) is list and len(contexts) == 52 and len(set(contexts)) == 52,
         "document-fifty-two-reserved-disjoint-contexts")
    need(all(type(value) is str and str(uuid.UUID(value)) == value for value in contexts),
         "document-reserved-canonical-context-uuids")
    return inputs


def configure_launch(owner, workspace):
    """Sole merger calls this immediately BEFORE its original serve child.

    The workspace is still absent. Only the separately admitted, already existing
    private temp parent is pinned here. The run() phase pins the created workspace.
    """
    owner.guard()
    inputs = _inputs(owner)
    workspace, temp = Path(workspace), Path(inputs["spoolTempParent"])
    need(workspace == Path(owner.request["workspace"]) and workspace.parent == Path(owner.root)
         and not workspace.exists(), "document-configure-before-fresh-serve")
    need(temp.parent == Path(owner.root) and temp != workspace and temp.is_dir(),
         "document-dedicated-temp-assigned-scope")
    pins = [pin for pin in owner.pins if getattr(pin, "directory", False) and pin.path == temp]
    need(len(pins) == 1, "document-admitted-prelaunch-temp-directory-pin")
    pins[0].current()
    owner.document_temp_pin = pins[0]
    owner.environment["TEMP"] = str(temp)
    owner.environment["TMP"] = str(temp)
    marker = {"tempParent": str(temp), "workspace": str(workspace),
              "expectedServeOrdinal": len(owner.children), "sourcePath": __file__}
    owner.document_launch_marker = marker
    owner.event("document-temp-configured-before-serve", {**marker,
        "tempNativeIdentity": pins[0].record["nativeIdentity"], "workspaceStillAbsent": True,
        "actualSpoolProofStillRequired": True})
    return marker


def run(owner, workspace, identity, harness):
    inputs = _inputs(owner)
    contexts = inputs["contexts"]
    need(type(harness) is dict and callable(harness.get("envelope")), "document-shared-harness-dict-api")
    marker = owner.document_launch_marker
    need(marker["workspace"] == str(workspace) and marker["sourcePath"] == __file__ and
         marker["tempParent"] == inputs["spoolTempParent"] and
         owner.environment.get("TEMP") == marker["tempParent"] and
         owner.environment.get("TMP") == marker["tempParent"], "document-temp-launch-marker-required")
    serves = [child for child in owner.children if tuple(child.argv) == (owner.request["cliPath"],
        "--state-dir", str(workspace), "serve")]
    need(len(serves) == 1 and serves[0].ordinal == marker["expectedServeOrdinal"]
         and serves[0].process.poll() is None, "document-original-serve-launched-after-temp-binding")
    owner.document_original_serve = serves[0]
    owner.document_temp_pin.current()
    suffix = owner.operation.replace("-", "")
    module = owner.module(inputs["clientPath"], "document_client_" + suffix)
    windows = owner.module(inputs["windowsPath"], "document_windows_" + suffix)
    race = owner.module(inputs["racePath"], "document_export_race_" + suffix)
    for context in contexts: module.canonical_id(context)
    need(identity not in contexts, "document-context-owner-id-disjoint")
    windows.admit_created_workspace(owner, workspace)
    before = harness["envelope"](owner.invoke(workspace, "--json", "status"))
    need(before["controllerId"] == identity and before["data"]["runtimeRunning"] is False,
         "document-same-disconnected-installed-owner")
    native_endpoint_pin = windows.observe_endpoint(owner, workspace, identity)
    client = windows.admit_endpoint(owner, workspace, identity, native_endpoint_pin, module)
    owner.document_client = client  # Its open sockets decide whether a later failure is known.
    # Transfer capacity must be tested before deliberately retaining an expiry
    # entry or a mutable-spool failure. No active borrowed entries are evicted.
    windows.resource_capacity(owner, client, module, contexts[8:41])
    module.transport_adversaries(client, contexts[:8])
    expiry = module.begin_expiry(client, contexts[41])
    owner.document_expiry_ticket = expiry
    source = owner.by_path[str(Path(inputs["largeRoutingInputPath"]).resolve()).casefold()]
    data = source.digest(True, maximum=64 * 1024 * 1024)
    need(len(data) > 10 * 1024 * 1024, "document-large-input-more-than-ten-mib")
    routing = data.decode("utf-8", "strict")
    original = module.exact_retry(client, "doc-exact-" + contexts[42], contexts[42], contexts[43],
                                   routing, before["configurationRevision"])
    module.committed_no_op(client, "doc-noop-" + contexts[44], contexts[44], routing,
                           original["configurationRevision"])
    module.retained_operation(client, original["operationId"], "doc-status-" + contexts[45],
        "doc-wait-" + contexts[46], contexts[45:47], original)
    loss = module.lose_response_and_reconcile(client, "doc-loss-" + contexts[47], contexts[47],
        contexts[48], routing, original["configurationRevision"])
    need(loss["state"] == "known-final" and loss["result"]["code"] == "OK",
         "document-loss-remains-unreconciled-no-replay")
    exported = Path(owner.root) / "document export 東京.json"
    windows.private_export_no_overwrite(owner, workspace, identity, exported, harness)
    readback = windows.Held(owner.native, exported)
    exported_bytes = readback.bytes(64 * 1024 * 1024)
    readback.close()
    need(semantic_routing(exported_bytes) == semantic_routing(data), "document-large-import-readback")
    owner.event("document-large-import-readback", {"inputSha256": source.record["sha256"], "inputBytes": len(data),
        "exportBytes": len(exported_bytes), "semanticComparison": "type-version-rules-excluding-exported_at"})
    race.run_public_export_race(owner, workspace, identity, client, module, windows, harness, "parent")
    race.run_public_export_race(owner, workspace, identity, client, module, windows, harness, "destination")
    # The serve's endpoint stays live through the idle wait below: the job's SYSTEM program runs one
    # LOCAL SERVICE probe against it in this window (a different real principal), and the owner never waits on it.
    owner.event("document-principal-window", {"endpoint": {k: native_endpoint_pin[k] for k in ("path", "nativeIdentity", "sha256")},
        "controllerId": identity, "differentPrincipal": "S-1-5-19", "ownerWaits": False})
    # At least a minute of this quiet wait follows the window, so the job's 5 s status polls see it
    # among the last sixteen events however long the transfers above took.
    window_until = time.monotonic_ns() + 60_000_000_000

    def idle():
        return (time.monotonic_ns() - expiry["startedMonotonicNs"] < 301_000_000_000
                or time.monotonic_ns() < window_until)
    # Real idle time, not clock injection, is used against the installed store.
    while idle():
        owner.event("document-expiry-pending", {"context": expiry["context"],
            "elapsedSeconds": (time.monotonic_ns() - expiry["startedMonotonicNs"]) // 1_000_000_000,
            "originalEntryRetained": True, "replayAllowed": False})
        for _ in range(30):
            if not idle(): break
            time.sleep(1)
    module.finish_expiry(client, expiry)
    current = harness["envelope"](owner.invoke(workspace, "--json", "status"))
    setting = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
                                            "settings", "show", "validation.batch-size"))
    need(setting["controllerId"] == identity and setting["configurationRevision"] == current["configurationRevision"],
         "document-persistence-setting-same-revision")
    new_value = 8 if setting["data"]["validation.batch-size"] == 7 else 7
    windows.persistence_fault(owner, workspace, client, module, "doc-persist-" + contexts[49],
        contexts[49], current, new_value)
    after = harness["envelope"](owner.invoke(workspace, "--json", "status"))
    need(after["controllerId"] == identity and after["configurationRevision"] == current["configurationRevision"]
         and after["data"]["runtimeRunning"] is False, "document-failed-persistence-owner-state")
    setting_after = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
                                                  "settings", "show", "validation.batch-size"))
    need(setting_after["data"] == setting["data"] and
         setting_after["configurationRevision"] == setting["configurationRevision"],
         "document-failed-setting-must-remain-unchanged")
    temp = Path(inputs["spoolTempParent"])
    fixture = windows.spool_intake(owner, temp, [p.name for p in temp.iterdir()], contexts[50], client)
    original_snapshot = ("cli\tcontrol-snapshot\t" + module.encoded_text(identity)).encode()
    replacement_snapshot = ("cli\tcontrol-snapshot\t" + module.encoded_text(contexts[51])).encode()
    windows.mutate_sealed_spool(owner, client, module, fixture, original_snapshot, replacement_snapshot,
                                after["configurationRevision"])
    # The known-refused transfer is now safe to release. Close only these exact
    # native handles before product discard erases its own spool leaves.
    fixture["payload"].close(); fixture["root"].close(); client.discard(contexts[50])
    spool_after = harness["envelope"](owner.invoke(workspace, "--json", "status"))
    need(spool_after["controllerId"] == identity and
         spool_after["configurationRevision"] == after["configurationRevision"] and
         spool_after["data"]["runtimeRunning"] is False, "document-spool-adversary-state-unchanged")
    owner.guard(); client.guard()
    owner.document_endpoint_handle.close()
    owner.document_workspace_handle.current(); owner.document_workspace_handle.close()
    outcome = {"state": "native-subcases-observed", "controllerId": identity,
        "fullSixteenMembershipsComplete": False, "remainingSeparateActions": [
            "actual-different-principal-credential-refusal", "native-cache-bytes-readback",
            "native-legacy-newline-import-and-cold-read", "real-GUI-import-export-and-cold-reopen",
            "responsive-status-and-cancel-during-cancellable-owner-work"],
        "productProtobufStoreOnWindows": False}
    owner.event("document-authenticated-segment-finished", outcome)
    return outcome


def semantic_routing(raw):
    """A routing document as the product compares it: type, version and rules, never exported_at."""
    value = json.loads(raw.decode("utf-8", "strict"))
    need(type(value) is dict and value.get("type") == "vpn_control_routing_rules" and type(value.get("rules")) is dict,
         "document-routing-document-shape")
    return {key: value.get(key) for key in ("type", "version", "rules")}


def _held_open(value):
    return value is not None and not getattr(value, "closed", True)


def close_known(owner, error, serve, identity):
    """A finite document oracle failure with nothing in flight: release this module's observers, name the owner.

    Known only for the harness's AssertionError on a completed public call and this module's own
    document- codes raised as RuntimeError (need) or the client's Refused, after every exchange
    closed its socket, every export relay stopped, and the persistence
    and spool fixtures were released. Their own failures already park inside them. The open
    endpoint and workspace observers are closed so the product removes its descriptor on quit.
    Returns (serve, identity) for the owner's closing, or None to keep every original for the park.
    """
    try:
        client = getattr(owner, "document_client", None)
        relays = getattr(owner, "document_export_relays", [])
        fixtures = [*(getattr(owner, "document_persistence_fault", None) or {}).values(),
                    *(value for key, value in (getattr(owner, "document_spool_fault", None) or {}).items()
                      if key in ("root", "payload", "writer"))]
        name = type(error).__name__
        if (not (name == "AssertionError" or name in KNOWN_ERRORS and str(error).startswith("document-"))
                or (client is not None and (client.original_sockets or (client.last_exchange or {}).get("secondary")))
                or any(not relay.stop.is_set() or relay.connections or relay.thread.is_alive() for relay in relays)
                or any(_held_open(value) for value in fixtures)
                or _held_open(getattr(owner, "document_export_descriptor", None))):
            return None
        for name in ("document_endpoint_handle", "document_workspace_handle"):
            held = getattr(owner, name, None)
            if _held_open(held):
                held.close()
        owner.event("document-known-failure-observers-released", {"reason": str(error)[:120],
            "socketsOpen": 0, "relaysOpen": 0, "fixturesHeld": 0, "replayAllowed": False})
        return serve, identity
    except Exception as closing:
        owner.park("document-known-failure-release-unknown", closing)
