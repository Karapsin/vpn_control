"""Cold and GUI-owner document cases on the installed package, through the public CLI only.

The shared worker's document-acceptance action loads this module as its cases module. Its
variant is the job's literal input beside it (document-cold-input.json, pinned like every
other file): one routing document is imported, exported and compared, the original serve
is quit, the same workspace is opened again by an independent owner, and the export is
compared again. No observed value is copied into an expected one: the job computes the
expected semantic digest from the same fixed recipe that produced the document.

- cold-reopen: the large routing document, reopened by a new serve (cold-independent-reopen).
- legacy-newline: a routing document whose domain entries are legacy newline-, CR-, tab- and
  comma-joined lists, normalized at import and read cold (protobuf-newline-compatibility, the
  Windows form of the shared newline token boundary).
- gui-owner: the large document, reopened by the installed GUI, which starts its own
  controller; the CLI then imports and exports it through that GUI-started owner. This is only
  the CLI half of gui-cli-transfer: the GUI's own import and export are not exercised, so it
  never stands for that scenario.
"""
import hashlib
import json
from pathlib import Path
import time
import uuid

VARIANTS = ("cold-reopen", "legacy-newline", "gui-owner")
INPUT_LEAF = "document-cold-input.json"
INPUT_FIELDS = {"schemaVersion", "variant", "operationId", "routingInputPath", "expectedSemanticSha256", "expectedSuffixCount"}
READY_SECONDS = {"serve": 30, "gui": 90}
CLOSE_SECONDS = 120


def need(value, code):
    if not value:
        raise RuntimeError(code)


def semantic_sha256(raw):
    """sha256 of the canonical type, version and rules of a routing document; exported_at never counts."""
    value = json.loads(raw.decode("utf-8", "strict"))
    need(type(value) is dict and value.get("type") == "vpn_control_routing_rules" and type(value.get("rules")) is dict,
         "document-cold-routing-shape")
    semantic = {key: value.get(key) for key in ("type", "version", "rules")}
    suffixes = value["rules"].get("direct_domain_suffixes")
    need(type(suffixes) is list, "document-cold-routing-suffixes")
    canonical = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest(), len(suffixes)


def literal_input(owner):
    path = Path(__file__).with_name(INPUT_LEAF)
    pin = owner.by_path[str(path).casefold()]
    value = json.loads(pin.digest(True, maximum=65536).decode("utf-8", "strict"))
    need(type(value) is dict and set(value) == INPUT_FIELDS and value["schemaVersion"] == 1 and value["variant"] in VARIANTS
         and value["operationId"] == owner.operation and type(value["expectedSuffixCount"]) is int
         and type(value["expectedSemanticSha256"]) is str and len(value["expectedSemanticSha256"]) == 64
         and str(value["routingInputPath"]).casefold() in owner.by_path, "document-cold-input-schema")
    return value


def _inputs(owner):
    inputs = owner.request["documentAcceptance"]
    need(type(inputs) is dict and inputs["schemaVersion"] == 1 and inputs["endpointPinBeforeObservation"] is None
         and type(inputs["contexts"]) is list and len(set(inputs["contexts"])) == 52
         and all(type(value) is str and str(uuid.UUID(value)) == value for value in inputs["contexts"]),
         "document-cold-action-input-schema")
    return inputs


def configure_launch(owner, workspace):
    """The serve and any later owner of this workspace spool transfers in the admitted temp parent only."""
    owner.guard()
    inputs = _inputs(owner)
    workspace, temp = Path(workspace), Path(inputs["spoolTempParent"])
    need(workspace == Path(owner.request["workspace"]) and workspace.parent == Path(owner.root)
         and not workspace.exists() and temp.parent == Path(owner.root) and temp != workspace and temp.is_dir(),
         "document-cold-configure-before-fresh-serve")
    pins = [pin for pin in owner.pins if getattr(pin, "directory", False) and pin.path == temp]
    need(len(pins) == 1, "document-cold-admitted-temp-directory-pin")
    pins[0].current()
    owner.environment["TEMP"] = str(temp)
    owner.environment["TMP"] = str(temp)
    owner.document_launch_marker = {"tempParent": str(temp), "workspace": str(workspace),
                                    "expectedServeOrdinal": len(owner.children), "sourcePath": __file__}
    owner.event("document-temp-configured-before-serve", {**owner.document_launch_marker, "workspaceStillAbsent": True})


def _export(owner, workspace, identity, harness, windows, leaf):
    destination = Path(owner.root) / leaf
    need(not destination.exists(), "document-cold-export-new-leaf")
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
                                              "routing", "export", "--output", str(destination)))
    need(result["controllerId"] == identity and result["final"] is True, "document-cold-export-owner")
    held = windows.Held(owner.native, destination)
    try:
        raw = held.bytes(64 * 1024 * 1024)
    finally:
        held.close()
    return semantic_sha256(raw), len(raw)


def _ready(owner, workspace, child, seconds, previous):
    """A status loop that never starts an owner: the new owner answers OK under a new controller."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        need(child.process.poll() is None, "document-cold-owner-ended-before-readiness")
        status = owner.invoke(workspace, "--json", "status")
        body = json.loads(status.stdout)
        if status.returncode == 0:
            need(status.stderr == "" and body["code"] == "OK" and body["final"] is True
                 and body["data"]["runtimeRunning"] is False and type(body["controllerId"]) is str
                 and body["controllerId"] != previous, "document-cold-reopened-owner-status")
            return body["controllerId"]
        need(status.returncode == 2 and body["code"] == "UNAVAILABLE", "document-cold-unexpected-readiness")
        time.sleep(0.2)
    owner.park("document-cold-reopened-owner-readiness-unknown")


def run(owner, workspace, identity, harness):
    _inputs(owner)
    case = literal_input(owner)
    variant, expected = case["variant"], (case["expectedSemanticSha256"], case["expectedSuffixCount"])
    need(type(harness) is dict and callable(harness.get("envelope")), "document-cold-shared-harness-dict-api")
    marker = owner.document_launch_marker
    cli = owner.request["cliPath"]
    serves = [child for child in owner.children if tuple(child.argv) == (cli, "--state-dir", str(workspace), "serve")]
    need(marker["workspace"] == str(workspace) and marker["sourcePath"] == __file__ and len(serves) == 1
         and serves[0].ordinal == marker["expectedServeOrdinal"] and serves[0].process.poll() is None,
         "document-cold-original-serve")
    original = serves[0]
    windows = owner.module(owner.request["documentAcceptance"]["windowsPath"], "document_cold_windows_" + owner.operation.replace("-", ""))
    before = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "status"))
    need(before["controllerId"] == identity and before["data"]["runtimeRunning"] is False, "document-cold-disconnected-owner")
    source = case["routingInputPath"]
    imported = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "--if-revision",
                                                str(before["configurationRevision"]), "routing", "import", "--input", source))
    need(imported["controllerId"] == identity and imported["final"] is True, "document-cold-import-owner")
    warm, warm_bytes = _export(owner, workspace, identity, harness, windows, "document-cold-export-warm.json")
    need(warm == expected, "document-cold-warm-readback")
    owner.event("document-cold-warm-readback", {"variant": variant, "semanticSha256": warm[0], "suffixes": warm[1],
                                                "exportBytes": warm_bytes, "controllerId": identity})
    # Cold: the original owner ends through the same public quit a pass sends, and its descriptor goes with it.
    owner.event("document-cold-quit-intent", {"child": original.ordinal, "controllerId": identity, "replayAllowed": False})
    quit_body = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "quit"))
    need(quit_body["controllerId"] == identity and quit_body["final"] is True, "document-cold-quit-acknowledged")
    terminal = original.wait()
    need(terminal["exitCode"] == 0 and not (Path(workspace) / "activation.port").exists(), "document-cold-original-closed")
    gui = variant == "gui-owner"
    if gui:
        launcher = str(Path(cli).with_name("vpn-control.exe"))
        need(launcher.casefold() in owner.by_path, "document-cold-installed-gui-pin")
        child = owner.child("document-gui-owner", [launcher, "--state-dir", str(workspace)])
    else:
        child = owner.child("document-cold-serve", [cli, "--state-dir", str(workspace), "serve"])
    reopened = _ready(owner, workspace, child, READY_SECONDS["gui" if gui else "serve"], identity)
    # From here the owner closes this one, on a pass and on a known failure alike.
    owner.document_reopened_owner = {"child": child, "controllerId": reopened, "gui": gui}
    owner.event("document-cold-reopened", {"variant": variant, "child": child.ordinal, "controllerId": reopened,
                                           "byInstalledGui": gui, "originalControllerId": identity})
    cold, cold_bytes = _export(owner, workspace, reopened, harness, windows, "document-cold-export-reopened.json")
    need(cold == expected, "document-cold-reopened-readback")
    result = {"variant": variant, "semanticSha256": cold[0], "suffixes": cold[1], "exportBytes": cold_bytes,
              "controllerId": reopened, "independentOwner": True}
    if gui:
        # The CLI's large upload and download, both through the transfer store of the GUI-started controller.
        current = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", reopened, "status"))
        again = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", reopened, "--if-revision",
                                                 str(current["configurationRevision"]), "routing", "import", "--input", source))
        need(again["controllerId"] == reopened and again["final"] is True, "document-gui-owner-import")
        after, after_bytes = _export(owner, workspace, reopened, harness, windows, "document-gui-export.json")
        need(after == expected and child.process.poll() is None, "document-gui-owner-readback")
        result.update(guiOwnerImport=True, guiExportBytes=after_bytes)
    owner.event("document-cold-observed", {**result, "nativeAcceptanceComplete": False})
    return result


def close_known(owner, error, serve, identity):
    """A finite oracle failure with nothing in flight names the owner still running; anything else returns None.

    Known: the harness's AssertionError, or this module's own document- codes. A GUI-started owner is
    closed here by one journaled public quit and its exit, because the owner's closing knows only
    serves; a reopened serve is returned for that closing, and before any reopen the original is.
    """
    try:
        name = type(error).__name__
        if not (name == "AssertionError" or name in ("RuntimeError", "Refused") and str(error).startswith("document-")):
            return None
        reopened = getattr(owner, "document_reopened_owner", None)
        if reopened is None or reopened["child"].terminal is not None:
            return serve, identity
        if not reopened["gui"]:
            return reopened["child"], reopened["controllerId"]
        child, controller, workspace = reopened["child"], reopened["controllerId"], Path(owner.request["workspace"])
        owner.event("document-gui-owner-quit-intent", {"child": child.ordinal, "controllerId": controller, "replayAllowed": False})
        result = owner.invoke(workspace, "--json", "--controller-id", controller, "quit")
        body = json.loads(result.stdout)
        if not (result.returncode == 0 and result.stderr == "" and body.get("controllerId") == controller and body.get("final") is True):
            owner.park("document-gui-owner-quit-not-acknowledged", error)
        until = time.monotonic() + CLOSE_SECONDS
        while child.observe() is None or (workspace / "activation.port").exists():
            if time.monotonic() >= until:
                owner.park("document-gui-owner-exit-unknown", error)
            time.sleep(0.1)
        owner.event("document-gui-owner-closed", {"child": child.ordinal, "terminal": child.terminal, "endpointReleased": True})
        return serve, identity
    except Exception as closing:
        owner.park("document-cold-known-failure-closing-unknown", closing)
