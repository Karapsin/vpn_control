"""Finite ordinary-worker entry point for the responsive document subcases.

Integrates only through the shared worker's reviewed run(owner, workspace,
identity, harness) convention. The task request must contain documentAcceptance
with the exact schema below. No observed bindings are filled from this file.
The separate real-principal, GUI and cold-owner actions remain required.
"""
from pathlib import Path
import uuid

# The error types of this module's own finite codes; the harness's and the responsive cases' AssertionError is known too.
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


def _responsive_modules(owner):
    # Fixed source-held implementation paths; no caller callback or decoded
    # verdict can substitute for the actual existing retained Owner/client.
    values = owner.request["responsiveWork"]
    need(type(values) is dict and set(values) == {"schemaVersion", "casesPath", "runtimeStagesPath",
        "fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath",
        "trustStorePath", "contexts", "largeRoutingInputPath"} and values["schemaVersion"] == 1,
        "responsive-finite-request-schema")
    for key in ("casesPath", "runtimeStagesPath"):
        need(str(Path(values[key])).casefold() in owner.by_path, "responsive-source-held-module")
    responsive = owner.module(values["casesPath"], "document_responsive_" + owner.operation.replace("-", ""))
    runtime = owner.module(values["runtimeStagesPath"], "document_work_runtime_" + owner.operation.replace("-", ""))
    inputs = {key: value for key, value in values.items() if key not in ("casesPath", "runtimeStagesPath")}
    return responsive, runtime, inputs


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
    responsive, runtime, work_inputs = _responsive_modules(owner)
    # Loaded before the fixture starts: if it does not become ready, the census of who holds its files is journaled.
    owner.document_windows_module = owner.module(inputs["windowsPath"], "document_windows_" + owner.operation.replace("-", ""))
    lease = responsive.prepare_before_serve(owner, workspace, work_inputs, runtime, owner.document_windows_module)
    owner.document_responsive_modules = (responsive, runtime, lease)
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
    windows = owner.document_windows_module
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
    responsive, runtime, lease = owner.document_responsive_modules
    responsive.after_original_serve_started(owner, lease, serves[0])
    responsive_result = responsive.run(owner, workspace, identity, client, module, lease)
    responsive.stop_after_known_cases(owner, lease)
    owner.guard(); client.guard()
    owner.document_endpoint_handle.close()
    owner.document_workspace_handle.current(); owner.document_workspace_handle.close()
    # Responsive work is its own action: the document subcases run in document-acceptance,
    # so one responsive failure never blocks them and no retry waits out their expiry.
    outcome = {"state": "responsive-subcases-observed", "controllerId": identity,
        "fullSixteenMembershipsComplete": False, "remainingSeparateActions": ["document-acceptance"],
        "responsiveLongWorkContributions": responsive_result,
        "productProtobufStoreOnWindows": False}
    owner.event("document-authenticated-segment-finished", outcome)
    return outcome


def _held_open(value):
    return value is not None and not getattr(value, "closed", True)


def close_known(owner, error, serve, identity):
    """A finite failure of this row with no refresh in flight: end the work fixture, release the observers, name the owner.

    Known only for an AssertionError of the harness or the responsive cases on a completed public call and
    this module's own document- and responsive- codes raised as RuntimeError (need) or the client's Refused,
    after every exchange closed its socket, and only while no phase's refresh is open (close_known_work).
    The owner's work fixture is then ended by one termination of its original child and awaited, and the
    open endpoint and workspace observers are closed so the product removes its descriptor on quit.
    Returns (serve, identity) for the owner's closing, which quits the serve, or None to keep every
    original for the park.
    """
    try:
        modules = getattr(owner, "document_responsive_modules", None)
        client = getattr(owner, "document_client", None)
        name = type(error).__name__
        if (modules is None
                or not (name == "AssertionError" or name in KNOWN_ERRORS and str(error).startswith(("document-", "responsive-")))
                or (client is not None and (client.original_sockets or (client.last_exchange or {}).get("secondary")))):
            return None
        if not modules[0].close_known_work(owner, modules[2], error):
            return None
        for name in ("document_endpoint_handle", "document_workspace_handle"):
            held = getattr(owner, name, None)
            if _held_open(held):
                held.close()
        owner.event("document-known-failure-observers-released", {"reason": str(error)[:120],
            "socketsOpen": 0, "workFixtureEnded": True, "replayAllowed": False})
        return serve, identity
    except Exception as closing:
        owner.park("document-known-failure-release-unknown", closing)
