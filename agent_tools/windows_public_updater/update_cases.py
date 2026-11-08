"""Private installed Windows public updater cases; no action occurs on import.

Entry point: run_update(owner, harness). This MUST use a dedicated ordinary-task
dispatch before any generic fresh serve/finalizer. The harness's UPDATE_INPUTS is
an immutable, reviewed source constant populated only from actual admissions.
All mutation/observation processes remain in the existing original Owner.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import time
import uuid


VARIANTS = frozenset(("public-ready", "download-cancelled", "checksum-rejected", "uac-denied",
    "install-cancelled", "participating-copy-lock", "protected-storage-rejected", "native-install-failed",
    "success-off", "success-reconnect", "different-admin", "wait-client-loss", "installer-wait-client-loss", "transport-loss"))
INSTALL_VARIANTS = VARIANTS - {"public-ready", "download-cancelled", "checksum-rejected"}
SUCCESS_VARIANTS = frozenset(("success-off", "success-reconnect", "different-admin", "wait-client-loss", "installer-wait-client-loss", "transport-loss"))
# A returned CANCELLED ends these known. The async installer wait needs a native terminal to rule out a
# running helper, and protected storage leaves its counterfeit root behind, so both keep parking.
GRANT_VARIANTS = INSTALL_VARIANTS - {"uac-denied", "install-cancelled", "installer-wait-client-loss", "protected-storage-rejected"}


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def json_result(result, *, codes=("OK",), final=True):
    require(result.stderr == "" and len(result.stdout.encode("utf-8")) <= 2 * 1024 * 1024,
            "public-cli-full-terminal-streams")
    value = json.loads(result.stdout)
    require(type(value) is dict and value.get("schemaVersion") == 1 and value.get("code") in codes
            and (final is None or value.get("final") is final), "public-envelope-result")
    code = value["code"]
    expected_exit = 0 if code in {"OK", "ACCEPTED"} else 130 if code == "CANCELLED" else 2 if code in {
        "UNAVAILABLE", "TIMEOUT", "OUTCOME_UNKNOWN", "INCOMPATIBLE_PROTOCOL"} else 1
    require(result.returncode == expected_exit and value.get("ok") == (expected_exit == 0), "public-code-exit-agreement")
    return value


def returned_cancelled(result):
    """Peek only; anything but the product's own CANCELLED stays with the checks that follow."""
    try:
        value = json.loads(result.stdout)
    except ValueError:
        return False
    return type(value) is dict and value.get("code") == "CANCELLED"


def inventory(value):
    require(type(value) is dict and 1 <= len(value) <= 16384, "complete-package-file-inventory")
    seen = set()
    for name, item in value.items():
        require(type(name) is str and name and "\\" not in name and not name.startswith("/")
                and all(p not in {"", ".", ".."} and ":" not in p and not p.endswith((".", " ")) for p in name.split("/"))
                and name.casefold() not in seen and type(item) is dict
                and set(item) == {"sizeBytes", "sha256"} and type(item["sizeBytes"]) is int
                and item["sizeBytes"] >= 0 and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]),
                "immutable-package-inventory-item")
        seen.add(name.casefold())
    return value


def validate_inputs(owner, value):
    required = {"schemaVersion", "variant", "sourceSha", "sourceFingerprint", "modules", "fixture",
        "baseVersion", "targetVersion", "installedRoot", "guiPath", "baseInventory", "targetInventory",
        "baseRegistration", "targetRegistration", "programData", "evidenceRoot", "collectorSourceSha256",
        "ordinarySid", "ordinarySessionId", "approvingAdminSid", "initialIntent", "trafficInputs",
        "faultInputs", "returnGuiRequired", "connectionFixturePath"}
    require(type(value) is dict and set(value) == required and value["schemaVersion"] == 1
            and value["variant"] in VARIANTS, "finite-update-input-schema")
    require(all(value[k] is not None for k in required - {"trafficInputs", "connectionFixturePath", "approvingAdminSid"}),
            "actual-updater-bindings-pending")
    require(re.fullmatch(r"[0-9a-f]{40}", value["sourceSha"])
            and re.fullmatch(r"[0-9a-f]{64}", value["sourceFingerprint"])
            and re.fullmatch(r"[0-9a-f]{64}", value["collectorSourceSha256"]), "exact-update-source-bindings")
    for version in (value["baseVersion"], value["targetVersion"]):
        require(type(version) is str and re.fullmatch(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])", version), "product-version")
    require(tuple(map(int, value["targetVersion"].split("."))) > tuple(map(int, value["baseVersion"].split("."))), "newer-target-version")
    inventory(value["baseInventory"])
    inventory(value["targetInventory"])
    require(value["ordinarySid"] == owner.request["context"]["ordinarySid"]
            and value["ordinarySessionId"] == owner.request["context"]["ordinarySessionId"]
            and value["initialIntent"] in {"off", "reconnect"} and type(value["returnGuiRequired"]) is bool,
            "actual-ordinary-updater-context")
    if value["variant"] == "success-reconnect":
        require(value["initialIntent"] == "reconnect" and type(value["trafficInputs"]) is dict,
                "connected-variant-requires-live-traffic-fixture")
    else:
        require(value["initialIntent"] == "off", "disconnected-variant-off-intent")
    require(value["baseVersion"] == owner.request["productVersion"], "admitted-public-base-product-version")
    if value["variant"] in INSTALL_VARIANTS:
        require(type(value["approvingAdminSid"]) is str and re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", value["approvingAdminSid"]),
                "actual-approving-admin-required")
    if value["variant"] == "different-admin":
        require(value["approvingAdminSid"] != value["ordinarySid"], "different-approving-administrator")
    modules = value["modules"]
    require(type(modules) is dict and set(modules) == {"receipts", "server", "fixture_environment",
        "macos_packaging_jdk_preflight", "prepare_desktop_update_fixture", "broker_observer", "lifecycle", "collector"}, "fixed-held-update-modules")
    for path in modules.values():
        require(type(path) is str and path.casefold() in owner.by_path, "pinned-update-module-source")
    require(type(value["fixture"]) is dict and set(value["fixture"]) == {"fixtureId", "content", "state",
        "certificate", "privateKey", "trustStore", "certificateSha256"}, "current-update-fixture-schema")
    require(value["collectorSourceSha256"] == owner.by_path[modules["collector"].casefold()].record["sha256"],
            "actual-collector-source-pin")
    require(type(value["faultInputs"]) is dict, "finite-fault-inputs")
    require(value["variant"] != "transport-loss", "outer-transport-loss-semantic-producer-not-yet-prepared")
    return value


def load_modules(owner, inputs):
    paths = inputs["modules"]
    modules = {}
    # Stage-entrypoint's existing exact sibling closure is loaded normally.
    for key in ("fixture_environment", "macos_packaging_jdk_preflight"):
        modules[key] = owner.module(paths[key], key)
    for key in ("receipts", "server", "prepare_desktop_update_fixture", "broker_observer", "lifecycle"):
        modules[key] = owner.module(paths[key], "_current_windows_update_" + key)
    return modules


def public(owner, workspace, identity, *arguments, revision=None, asynchronous=False, codes=("OK",), final=True):
    guards = ["--json", "--controller-id", identity]
    if revision is not None:
        guards += ["--if-revision", str(revision)]
    if asynchronous:
        guards += ["--async"]
    value = json_result(owner.invoke(workspace, *guards, *arguments), codes=codes, final=final)
    require(value.get("controllerId") == identity, "same-authenticated-updater-owner")
    return value


def await_ready(owner, workspace, serve, *, previous=None):
    noticed = time.monotonic()
    while True:
        require(serve is None or serve.process.poll() is None, "original-serve-ended-before-readiness")
        answer = json_result(owner.invoke(workspace, "--json", "status"), codes=("OK", "UNAVAILABLE"), final=None)
        if answer["code"] == "OK":
            require(answer.get("final") is True and type(answer.get("controllerId")) is str
                    and answer["controllerId"] and answer["controllerId"] != previous, "fresh-or-returned-owner-identity")
            return answer
        if time.monotonic() - noticed >= 30:
            owner.event("update-owner-readiness-pending", {"previousControllerId": previous,
                "originalServeChild": None if serve is None else serve.ordinal, "replayAllowed": False})
            noticed = time.monotonic()
        time.sleep(0.2)


def invariant_status(before, after):
    require(before["controllerId"] == after["controllerId"]
            and before["configurationRevision"] == after["configurationRevision"], "update-preparation-owner-config-continuity")
    for key in ("runtimeRunning", "selectedLocationId", "activeLocationId", "activeMode", "pendingRestart"):
        if key in before["data"]:
            require(after["data"].get(key) == before["data"][key], "update-preparation-runtime-continuity-" + key)


def close_disconnected(owner, workspace, identity, serve, gui=None):
    status = public(owner, workspace, identity, "status")
    require(status["data"].get("runtimeRunning") is False, "known-disconnected-update-cleanup")
    public(owner, workspace, identity, "quit")
    serve.wait()
    if gui is not None:
        gui.wait()
    require(not (workspace / "activation.port").exists(), "original-owner-endpoint-released")


def native_evidence(owner, inputs, modules, stage, *, job=None, operation=None):
    """Consume one create-only machine-protected native collector output.

    This file is produced by the sole VM operator's current read-only collector,
    not by an ordinary task. Missing means pending, never permission or success.
    A new source/task cannot use an old evidence file because all four identities
    and exact stage/job/operation must match the current native record.
    """
    require(stage in {"before-install", "authorization", "terminal-actors", "returned-gui", "fault-ready", "transport-restored", "returned-cleanup"}, "finite-native-evidence-stage")
    receipts = modules["receipts"]
    root = str(receipts.canonical_path(inputs["evidenceRoot"]))
    require(receipts.canonical_path(root).parent == receipts.canonical_path(inputs["programData"]), "native-evidence-exact-programdata-parent")
    require(receipts.canonical_path(root).name == "update-evidence-" + owner.operation, "current-native-evidence-root")
    path = str(receipts.canonical_path(root) / (stage + ".json"))
    owner.event("update-native-observation-needed", {"stage": stage, "jobId": job, "productOperationId": operation,
        "ordinaryTaskOperationId": owner.operation, "evidenceFile": path,
        "collectorSourceSha256": inputs["collectorSourceSha256"], "resubmitAllowed": False})
    while True:
        owner.guard()
        try:
            held = receipts.FileObservation(owner, path)
        except OSError as error:
            if getattr(error, "winerror", None) not in {2, 3, 32}:
                raise
            time.sleep(0.2)
            continue
        root_lease = receipts.FileObservation(owner, root, directory=True)
        try:
            receipts.machine_security(root_lease.opening["security"], True)
            receipts.machine_security(held.opening["security"], False)
            raw = held.read(256 * 1024)
            value = json.loads(raw)
            require(type(value) is dict and set(value) == {"schemaVersion", "ordinaryTaskOperationId", "stage",
                "sourceSha", "collectorSourceSha256", "bootIdentifier", "jobId", "productOperationId", "observations"}
                and value["schemaVersion"] == 1 and value["ordinaryTaskOperationId"] == owner.operation
                and value["stage"] == stage and value["sourceSha"] == inputs["sourceSha"]
                and value["collectorSourceSha256"] == inputs["collectorSourceSha256"]
                and value["bootIdentifier"] == owner.request["context"]["bootIdentifier"]
                and value["jobId"] == job and value["productOperationId"] == operation
                and type(value["observations"]) is dict, "current-protected-native-observation-binding")
            owner.event("update-native-observation-read", {"stage": stage, "nativeFile": held.opening,
                "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "readOnly": True})
            return value["observations"]
        finally:
            held.close()
            root_lease.close()


def known_operation(owner, workspace, identity, operation, *, codes=("OK",)):
    return public(owner, workspace, identity, "operations", "wait", operation,
                  codes=codes, final=True)


def verify_downloaded_asset(owner, workspace, asset, receipts, *, checksum_matches):
    name = asset["fileName"]
    require(type(name) is str and name and not any(c in name for c in "\\/:\0")
            and name.lower().endswith(".msi"), "one-exact-downloaded-msi-name")
    path = str(PureWindowsPath(str(workspace)) / "updates" / name)
    value = receipts.FileObservation(owner, path)
    try:
        digest, length = hashlib.sha256(), 0
        for block in owner.native.read_blocks(value.handle):
            length += len(block)
            require(length <= asset["sizeBytes"], "downloaded-package-byte-bound")
            digest.update(block)
        require(length == asset["sizeBytes"] and value.describe() == value.opening,
                "downloaded-package-exact-size-generation")
        value._canonical()
        require((digest.hexdigest() == asset["sha256"]) is checksum_matches,
                "independent-downloaded-package-checksum")
        owner.event("update-downloaded-package-observed", {"nativeFile": value.opening,
            "sizeBytes": length, "sha256": digest.hexdigest(), "expectedSha256": asset["sha256"],
            "matchesManifest": checksum_matches, "readOnly": True})
    finally:
        value.close()


def observed_download(owner, workspace, identity, operation, target_bytes):
    while True:
        state = public(owner, workspace, identity, "updates", "status")
        data = state["data"]
        if data.get("phase") == "downloading" and 0 < data.get("downloadedBytes", 0) < target_bytes:
            owner.event("update-download-in-flight", {"operationId": operation,
                "downloadedBytes": data["downloadedBytes"], "totalBytes": target_bytes})
            return state
        require(data.get("phase") not in {"ready", "failed", "idle"}, "required-in-flight-download-was-not-observed")
        time.sleep(0.05)


def terminate_exact_wait_client(owner, child, identity, operation):
    expected = (owner.request["cliPath"], "--state-dir", str(owner.request["workspace"]),
                "--json", "--controller-id", identity, "operations", "wait", operation)
    require(child.argv == expected and child.terminal is None and child.process.poll() is None
            and owner.native.birth(int(child.process._handle)) == child.birth,
            "exact-original-read-only-wait-client")
    owner.event("update-wait-client-loss-intent", {"child": child.ordinal, "pid": child.pid,
        "birthFileTimeUtc": child.birth, "operationId": operation, "installerOrOwnerTargeted": False})
    api = owner.native.k.TerminateProcess
    api.argtypes, api.restype = (W.HANDLE, W.UINT), W.BOOL
    require(api(W.HANDLE(int(child.process._handle)), 29), "exact-wait-client-termination")
    child.wait()


def _run_update(owner, harness):
    inputs = validate_inputs(owner, harness["UPDATE_INPUTS"])
    modules = load_modules(owner, inputs)
    receipts, prepared = modules["receipts"], modules["prepare_desktop_update_fixture"]
    variant = inputs["variant"]
    workspace = Path(owner.request["workspace"])
    require(workspace.parent == owner.root and not workspace.exists(), "new-isolated-update-workspace")
    require(receipts.within(owner.request["cliPath"], inputs["installedRoot"])
            and receipts.within(inputs["guiPath"], inputs["installedRoot"]), "exact-installed-update-launchers")
    owner.update_retained_source_paths = [*inputs["modules"].values(), owner.request["casesPath"],
        owner.request["harnessPath"], str(owner.pins[0].path), type(owner).guard.__code__.co_filename,
        *[inputs["fixture"][x] for x in ("content", "state", "certificate", "privateKey", "trustStore")]]
    lease = receipts.InstalledApplicationLease(owner, inputs["installedRoot"], inputs["baseInventory"], inputs["targetInventory"])
    baseline_registration = receipts.installed_registration(inputs["baseRegistration"], owner.native)
    mode = "paced" if variant in {"download-cancelled", "wait-client-loss"} else "checksum-corrupt" if variant == "checksum-rejected" else "exact"
    fixture = modules["server"].UpdateFixture(owner, prepared, inputs["fixture"], mode)
    owner.update_fixture = fixture  # Retain across every exception/UNKNOWN.
    require(fixture.ready["sourceFingerprint"] == inputs["sourceFingerprint"], "source-matched-update-fixture")
    asset = fixture.manifest["assets"][0]
    require(asset["displayVersion"] == inputs["targetVersion"], "actual-target-fixture-version")
    clean_environment = dict(owner.environment)
    owner.environment.update(fixture.owner_jvm_environment())
    # Only this explicit persistent owner gets fixture-local proxy/trust. Public
    # one-shot clients keep the original clean ordinary environment.
    serve = owner.child("update-public-serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
    owner.environment.clear()
    owner.environment.update(clean_environment)
    before = await_ready(owner, workspace, serve)
    identity = before["controllerId"]
    require(before["data"].get("runtimeRunning") is False, "fresh-update-owner-disconnected")
    traffic_before = traffic_after = None
    if inputs["initialIntent"] == "reconnect":
        profile_path = inputs["connectionFixturePath"]
        require(type(profile_path) is str and profile_path.casefold() in owner.by_path,
                "held-owned-loopback-connection-profile")
        profile = owner.by_path[profile_path.casefold()].digest(True).decode("utf-8", "strict")
        require(re.fullmatch(r"socks5://127\.0\.0\.1:[0-9]{1,5}#Update%20fixture\n?", profile),
                "owned-no-egress-socks-connection-profile")
        revision = before["configurationRevision"]
        mode = public(owner, workspace, identity, "settings", "set", "mode", "proxy-only", revision=revision)
        added = public(owner, workspace, identity, "locations", "add", "--input", profile_path,
            revision=mode["configurationRevision"])
        location_id = added["data"].get("id")
        require(type(location_id) is str and location_id, "public-loopback-location-id")
        selected = public(owner, workspace, identity, "locations", "select", location_id,
            revision=added["configurationRevision"])
        public(owner, workspace, identity, "on", revision=selected["configurationRevision"])
        traffic_before = modules["lifecycle"].prepare_update_traffic(owner, workspace, identity, inputs["trafficInputs"])
        before = public(owner, workspace, identity, "status")
        require(before["data"].get("runtimeRunning") is True, "connected-update-fixture-active")
    receipts.preserve(owner, "update-baseline-context.json", {"status": before,
        "registration": baseline_registration, "variant": variant, "sourceSha": inputs["sourceSha"],
        "sourceFingerprint": inputs["sourceFingerprint"]})
    probe_id = str(uuid.uuid4())
    probe = public(owner, workspace, identity, "updates", "transport-probe", probe_id)
    owner.event("update-public-transport-probe", probe)
    public(owner, workspace, identity, "updates", "check")
    checked = public(owner, workspace, identity, "updates", "status")
    require(checked["data"].get("available") is True and checked["data"].get("compatible") is True
            and checked["data"].get("availableVersion") == inputs["targetVersion"]
            and checked["data"].get("totalBytes") == asset["sizeBytes"], "public-source-matched-update-available")
    invariant_status(before, public(owner, workspace, identity, "status"))
    download = public(owner, workspace, identity, "updates", "download", asynchronous=True, codes=("ACCEPTED",), final=False)
    operation = receipts.canonical_uuid(download.get("operationId"))
    if variant in {"download-cancelled", "wait-client-loss"}:
        observed_download(owner, workspace, identity, operation, asset["sizeBytes"])
        if variant == "download-cancelled":
            public(owner, workspace, identity, "operations", "cancel", operation, final=None)
            known_operation(owner, workspace, identity, operation, codes=("CANCELLED",))
            require(public(owner, workspace, identity, "updates", "status")["data"].get("phase") != "ready", "cancelled-download-never-ready")
            invariant_status(before, public(owner, workspace, identity, "status"))
            close_disconnected(owner, workspace, identity, serve)
            fixture.close_known(all_update_operations_terminal=True, cancelled_download=True)
            return 0
        wait = owner.child("exact-download-wait-client", [owner.request["cliPath"], "--state-dir", str(workspace),
            "--json", "--controller-id", identity, "operations", "wait", operation])
        terminate_exact_wait_client(owner, wait, identity, operation)
    if variant == "checksum-rejected":
        failed = known_operation(owner, workspace, identity, operation, codes=("RUNTIME_FAILED", "INVALID_ARGUMENT"))
        require(public(owner, workspace, identity, "updates", "status")["data"].get("phase") == "failed", "checksum-never-install-ready")
        invariant_status(before, public(owner, workspace, identity, "status"))
        verify_downloaded_asset(owner, workspace, asset, receipts, checksum_matches=False)
        owner.event("update-checksum-rejected", failed)
        close_disconnected(owner, workspace, identity, serve)
        fixture.close_known(all_update_operations_terminal=True)
        return 0
    known_operation(owner, workspace, identity, operation)
    ready = public(owner, workspace, identity, "updates", "status")
    prepared.require_install_ready(ready, inputs["targetVersion"])
    require(ready["data"].get("downloadedBytes") == asset["sizeBytes"], "public-complete-verified-download")
    verify_downloaded_asset(owner, workspace, asset, receipts, checksum_matches=True)
    invariant_status(before, public(owner, workspace, identity, "status"))
    if variant == "public-ready":
        close_disconnected(owner, workspace, identity, serve)
        fixture.close_known(all_update_operations_terminal=True)
        return 0
    gui_child = None
    if inputs["returnGuiRequired"]:
        lifecycle = modules["lifecycle"]
        gui_child = lifecycle.start_gui(owner, workspace, identity, inputs["guiPath"],
            modules["broker_observer"].WindowsNative(), lifecycle.GuiWindows())
    pre_native = native_evidence(owner, inputs, modules, "before-install")
    observed_owner = pre_native.get("ordinaryOwner", {})
    require(observed_owner.get("token", {}).get("sid") == inputs["ordinarySid"]
            and observed_owner["token"].get("elevated") == 0
            and observed_owner.get("pid") == serve.pid
            and observed_owner.get("creationFileTime") == int(serve.birth)
            and observed_owner.get("image", "").casefold() == owner.request["cliPath"].casefold()
            and observed_owner.get("sha256") == owner.by_path[owner.request["cliPath"].casefold()].record["sha256"],
            "native-original-retained-update-owner")
    if gui_child is not None:
        observed_gui = pre_native.get("originalGui", {})
        require(observed_gui.get("pid") == gui_child.pid
                and observed_gui.get("creationFileTime") == int(gui_child.birth)
                and observed_gui.get("image", "").casefold() == inputs["guiPath"].casefold()
                and observed_gui.get("sha256") == owner.by_path[inputs["guiPath"].casefold()].record["sha256"]
                and observed_gui.get("token", {}).get("sid") == inputs["ordinarySid"]
                and observed_gui["token"].get("sessionId") == inputs["ordinarySessionId"]
                and observed_gui["token"].get("elevated") == 0, "native-original-retained-update-gui")
    blocking_copy = None
    if variant == "participating-copy-lock":
        require(set(inputs["faultInputs"]) == {"kind", "installedCliPath", "blockingWorkspace"}
                and inputs["faultInputs"]["kind"] == variant
                and inputs["faultInputs"]["installedCliPath"] == owner.request["cliPath"],
                "one-fixed-participating-copy-fixture")
        blocking_workspace = Path(inputs["faultInputs"]["blockingWorkspace"])
        require(blocking_workspace.parent == owner.root and not blocking_workspace.exists()
                and blocking_workspace != workspace, "distinct-owned-copy-lock-workspace")
        blocking_copy = owner.child("participating-installed-copy", [owner.request["cliPath"],
            "--state-dir", str(blocking_workspace), "serve"])
        blocking_status = await_ready(owner, blocking_workspace, blocking_copy)
        require(blocking_status["data"].get("runtimeRunning") is False, "copy-lock-fixture-disconnected")
        owner.event("update-participating-copy-lock-ready", {"child": blocking_copy.ordinal,
            "pid": blocking_copy.pid, "birthFileTimeUtc": blocking_copy.birth,
            "controllerId": blocking_status["controllerId"], "workspace": str(blocking_workspace)})
    if variant in {"protected-storage-rejected", "native-install-failed", "participating-copy-lock"}:
        fault = native_evidence(owner, inputs, modules, "fault-ready")
        require(fault.get("kind") == variant and fault.get("binding") == inputs["faultInputs"], "actual-finite-fault-preparation")
    arguments = prepared.desktop_install_arguments(ready, inputs["targetVersion"],
        asynchronous=variant in {"install-cancelled", "installer-wait-client-loss"})
    install_child = owner.child("one-public-update-install", [owner.request["cliPath"], "--state-dir", str(workspace), *arguments])
    owner.event("update-uac-action-pending", {"ordinaryTaskOperationId": owner.operation,
        "originalCliPid": install_child.pid, "originalCliBirth": install_child.birth,
        "controllerId": identity, "variant": variant, "approvingAdminSid": inputs["approvingAdminSid"],
        "action": "hold-current-prompt" if variant in {"install-cancelled", "installer-wait-client-loss"}
            else "deny-current-prompt" if variant == "uac-denied" else "approve-current-prompt",
        "freshSecureDesktopObservationRequired": True, "replayAllowed": False})
    # Native operator observes the current secure desktop and uses the authorized
    # fixture account. This is a pending native action, never a permission prompt
    # or a fabricated successful authorization flag.
    result = install_child.completed()
    if variant == "installer-wait-client-loss":
        original_pending = json_result(result, codes=("ACCEPTED",), final=False)
        require(original_pending.get("controllerId") == identity
                and original_pending.get("data", {}).get("handoffReady") is False,
                "installer-loss-must-precede-committed-handoff")
        install_operation = receipts.canonical_uuid(original_pending.get("operationId"))
        wait = owner.child("exact-installer-wait-client", [owner.request["cliPath"], "--state-dir", str(workspace),
            "--json", "--controller-id", identity, "operations", "wait", install_operation])
        terminate_exact_wait_client(owner, wait, identity, install_operation)
        owner.event("update-installer-wait-client-lost", {"terminal": wait.terminal,
            "originalAccepted": original_pending, "freshPromptAction": "approve-current-prompt-after-wait-client-loss",
            "installerReissued": False})
        while True:
            observation = owner.invoke(workspace, "--json", "--controller-id", identity,
                "operations", "status", install_operation)
            current = json_result(observation, codes=("ACCEPTED", "OUTCOME_UNKNOWN", "TIMEOUT"), final=False)
            require(current.get("controllerId") == identity and current.get("operationId") == install_operation,
                    "same-original-installer-after-wait-client-loss")
            if current["code"] == "ACCEPTED" and current.get("data", {}).get("handoffReady") is True:
                recovered_handoff = receipts.join_ready_handoff(original_pending, current)
                receipts.preserve(owner, "update-installer-wait-loss-readiness.json", {
                    "originalAccepted": original_pending, "sameOperationReadiness": current})
                result = type(observation)(observation.args, 0, json.dumps(recovered_handoff), "")
                break
            time.sleep(0.1)
    if variant == "install-cancelled":
        pending = json_result(result, codes=("ACCEPTED",), final=False)
        require(pending.get("controllerId") == identity
                and pending.get("data", {}).get("handoffReady") is False,
                "cancellation-before-committed-installer-handoff")
        install_operation = receipts.canonical_uuid(pending.get("operationId"))
        public(owner, workspace, identity, "operations", "cancel", install_operation, final=None)
        owner.event("update-install-cancel-requested-before-authorization", {
            "operationId": install_operation, "originalControllerId": identity,
            "freshPromptAction": "approve-current-prompt-after-cancellation-request",
            "replayAllowed": False})
        cancelled = known_operation(owner, workspace, identity, install_operation, codes=("CANCELLED",))
        cancel_rows = public(owner, workspace, identity, "updates", "status")["data"].get("installations", [])
        cancel_matches = [x for x in cancel_rows if x.get("originControllerId") == identity
                          and x.get("operationId") == install_operation]
        require(len(cancel_matches) == 1 and cancel_matches[0].get("final") is True
                and cancel_matches[0].get("installed") is False, "exact-cancelled-public-installation")
        cancel_job = receipts.canonical_uuid(cancel_matches[0].get("jobId"))
        native_cancel = native_evidence(owner, inputs, modules, "terminal-actors",
            job=cancel_job, operation=install_operation)
        require(native_cancel.get("protectedReceipt", {}).get("phase") == "CANCELLED",
                "native-cancellation-terminal-not-request-acceptance")
        invariant_status(before, public(owner, workspace, identity, "status"))
        for pin in lease.files:
            pin.digest()
        close_disconnected(owner, workspace, identity, serve, gui_child)
        fixture.close_known(all_update_operations_terminal=True)
        return 0
    if variant == "uac-denied":
        denied = json_result(result, codes=("CANCELLED", "PERMISSION_DENIED", "INTERACTION_REQUIRED"))
        require(denied.get("controllerId") == identity, "denial-original-controller")
        denial_rows = public(owner, workspace, identity, "updates", "status")["data"].get("installations", [])
        denial_matches = [x for x in denial_rows if x.get("originControllerId") == identity
                         and x.get("operationId") == denied.get("operationId")
                         and x.get("originRequestId") == denied.get("requestId")]
        require(len(denial_matches) == 1 and denial_matches[0].get("final") is True
                and denial_matches[0].get("installed") is False, "exact-denied-public-installation")
        denial_job = receipts.canonical_uuid(denial_matches[0].get("jobId"))
        observed = native_evidence(owner, inputs, modules, "terminal-actors",
            job=denial_job, operation=denied.get("operationId"))
        require(observed.get("notStartedDisposition", {}).get("disposition") == "NOT_STARTED"
                and observed.get("protectedJobAbsence", {}).get("nativeError") in {2, 3}, "native-definite-uac-denial")
        invariant_status(before, public(owner, workspace, identity, "status"))
        for pin in lease.files:
            pin.digest()
        close_disconnected(owner, workspace, identity, serve, gui_child)
        fixture.close_known(all_update_operations_terminal=True)
        return 0
    if variant in GRANT_VARIANTS and returned_cancelled(result):
        # An expired prompt reaches a grant as the product's own CANCELLED, with no handoff and nothing
        # installed. This closes what the case started and is a known failure, so the clone does not park.
        cancelled = json_result(result, codes=("CANCELLED",))
        require(cancelled.get("controllerId") == identity, "cancelled-grant-original-controller")
        rows = public(owner, workspace, identity, "updates", "status")["data"].get("installations", [])
        matches = [x for x in rows if x.get("originControllerId") == identity
                   and x.get("operationId") == cancelled.get("operationId")]
        require(len(matches) == 1 and matches[0].get("final") is True and matches[0].get("installed") is False,
                "exact-cancelled-grant-public-installation")
        invariant_status(before, public(owner, workspace, identity, "status"))
        for pin in lease.files:
            pin.digest()
        if blocking_copy is not None:
            close_disconnected(owner, blocking_workspace, blocking_status["controllerId"], blocking_copy)
        if traffic_before is not None:
            modules["lifecycle"].cleanup_update_traffic(owner, traffic_before)
        if before["data"].get("runtimeRunning") is True:
            public(owner, workspace, identity, "off")
        close_disconnected(owner, workspace, identity, serve, gui_child)
        fixture.close_known(all_update_operations_terminal=True)
        owner.update_cancelled_grant = {"variant": variant, "operationId": cancelled.get("operationId")}
        owner.event("update-grant-cancelled-known", {**owner.update_cancelled_grant, "knownFailure": True, "replayAllowed": False})
        return 1
    if variant == "protected-storage-rejected":
        refused = json_result(result, codes=("OUTCOME_UNKNOWN", "RUNTIME_FAILED", "PERMISSION_DENIED"), final=None)
        receipts.preserve(owner, "update-protected-storage-refusal.json", {"public": refused,
            "native": native_evidence(owner, inputs, modules, "terminal-actors", operation=refused.get("operationId"))})
        # A refused malicious root may leave the product's original operation
        # UNKNOWN. Keep its controller, all pins and the fixture; no fake cleanup.
        owner.park("protected-storage-refused-requires-exact-native-reconciliation")
    accepted = receipts.handoff(result, identity)
    receipts.preserve(owner, "update-original-handoff.json", accepted)
    collector = receipts.ProtectedReceiptCollector(owner, inputs["programData"], accepted["data"]["jobId"])
    owner.update_collector = collector
    first = collector.observe()
    require(first["phase"] in {"AUTHORIZED", "WAITING_FOR_EXIT"}, "handoff-before-msi-replacement")
    authorization = native_evidence(owner, inputs, modules, "authorization", job=accepted["data"]["jobId"], operation=accepted["operationId"])
    require(authorization.get("coordinator", {}).get("token", {}).get("sid") == inputs["approvingAdminSid"]
            and authorization["coordinator"]["token"].get("elevated") == 1
            and authorization.get("originalUserWorker", {}).get("token", {}).get("sid") == inputs["ordinarySid"]
            and authorization["originalUserWorker"]["token"].get("elevated") == 0
            and authorization["originalUserWorker"]["token"].get("sessionId") == inputs["ordinarySessionId"],
            "native-admin-coordinator-original-user-worker-boundary")
    lease.retire_after_committed_handoff(accepted, identity)
    serve.wait()  # Same original owner and full binary EOF, never lookup/kill.
    if gui_child is not None:
        gui_child.wait()
    terminal = collector.terminal()
    receipts.preserve(owner, "update-protected-terminal.json", terminal)
    native_terminal = native_evidence(owner, inputs, modules, "terminal-actors", job=accepted["data"]["jobId"], operation=accepted["operationId"])
    require(native_terminal.get("protectedReceipt") == terminal, "native-terminal-same-protected-receipt")
    require(native_terminal.get("actorExpectations") == authorization.get("actorExpectations")
            and set(native_terminal.get("actorExpectations", {})) == {"coordinator", "worker"}
            and len(native_terminal.get("actorExitObservations", [])) == 2
            and all(x.get("originalAbsent") is True for x in native_terminal["actorExitObservations"]),
            "exact-original-installer-actors-known-closed")
    if variant in {"participating-copy-lock", "native-install-failed", "install-cancelled"}:
        expected = "CANCELLED" if variant == "install-cancelled" else "FAILED"
        require(terminal["phase"] == expected, "expected-native-installer-negative-terminal")
        lease.admit_observed_target(terminal, expected_phase=expected)
        receipts.installed_registration(inputs["baseRegistration"], owner.native)
        if variant == "participating-copy-lock":
            require(terminal["code"] == "BUSY" and blocking_copy is not None,
                    "participating-copy-gate-native-busy")
            close_disconnected(owner, blocking_workspace, blocking_status["controllerId"], blocking_copy)
        if variant == "native-install-failed":
            require(native_terminal.get("workerResult", {}).get("exitCode") not in {None, 0, 3010},
                    "actual-msi-native-error-not-preinstall-failure")
    else:
        require(terminal["phase"] == "SUCCEEDED" and terminal["code"] == "OK", "actual-native-msi-success")
        lease.admit_observed_target(terminal)
        registration = receipts.installed_registration(inputs["targetRegistration"], owner.native)
        owner.event("update-target-msi-registration", registration)
    collector.close_terminal()
    version = owner.child("updated-installed-public-version", [owner.request["cliPath"], "--version"]).completed()
    expected_version = inputs["targetVersion"] if terminal["phase"] == "SUCCEEDED" else inputs["baseVersion"]
    require(version.returncode == 0 and version.stderr == "" and version.stdout.strip() == expected_version,
            "installed-replacement-public-version")
    # The original-user worker owns the single relaunch. Do not start a second
    # GUI/controller to hide a missing or wrong-user return.
    recovery_serve = None
    if terminal["phase"] != "SUCCEEDED":
        # The product worker returns automatically only on success. Once a known
        # failed/cancelled protected terminal and old bytes have been admitted,
        # starting a new ordinary owner is an explicit recovery action, not an
        # installer retry or a fabricated automatic GUI return.
        recovery_serve = owner.child("negative-installer-next-owner", [owner.request["cliPath"],
            "--state-dir", str(workspace), "serve"])
    returned = await_ready(owner, workspace, recovery_serve, previous=identity)
    new_identity = returned["controllerId"]
    recovery = public(owner, workspace, new_identity, "operations", "status", accepted["operationId"],
        codes=(terminal["code"],), final=True)
    owner.event("update-next-owner-recovery", receipts.verify_recovery(accepted, terminal, recovery))
    owner_binding = receipts.endpoint_actor(owner, workspace, "activation.port", new_identity, modules["broker_observer"])
    owner_admission = receipts.preserve(owner, "update-returned-owner-native-admission.json", {
        "status": returned, "endpointNativeBinding": owner_binding, "sourceSha": inputs["sourceSha"],
        "jobId": terminal["jobId"], "operationId": accepted["operationId"]})
    returned_actors = {"owner": owner_binding["actor"]}
    if inputs["returnGuiRequired"] and terminal["phase"] == "SUCCEEDED":
        frontend_binding = receipts.endpoint_actor(owner, workspace, "frontend.port", None, modules["broker_observer"])
        returned_actors["gui"] = frontend_binding["actor"]
        installed_artifact = (owner.root / "update-target-installed-admission.json").read_bytes()
        gui_inputs = {"schemaVersion": 1, "ownerActor": owner_binding["actor"], "guiActor": frontend_binding["actor"],
            "installedAdmissionArtifactId": hashlib.sha256(installed_artifact).hexdigest(),
            "targetOwnerAdmissionArtifactId": owner_admission["sha256"]}
        lifecycle = modules["lifecycle"]
        lifecycle.observe_existing_gui(owner, workspace, new_identity, gui_inputs,
            modules["broker_observer"], lifecycle.GuiWindows())
    require(returned["data"].get("runtimeRunning") == (inputs["initialIntent"] == "reconnect"), "off-or-reconnect-intent-preserved")
    if inputs["initialIntent"] == "reconnect":
        traffic_after = modules["lifecycle"].verify_update_traffic(owner, workspace, new_identity, inputs["trafficInputs"])
    if variant == "transport-loss":
        restored = native_evidence(owner, inputs, modules, "transport-restored", job=accepted["data"]["jobId"], operation=accepted["operationId"])
        require(restored.get("originalOrdinaryTaskOperationId") == owner.operation
                and restored.get("originalOrdinaryWorkerPid") == os.getpid()
                and set(restored.get("transportReceipts", {})) == {"detachReceipt", "reattachReceipt", "originalSubmissionIntent"},
                "same-original-worker-after-transport-loss")
    owner.event("update-case-product-terminal", {"variant": variant, "jobId": terminal["jobId"],
        "operationId": accepted["operationId"], "protectedPhase": terminal["phase"],
        "targetInstalledBytesAdmitted": terminal["phase"] == "SUCCEEDED", "nativeAcceptanceClosed": False,
        "remaining": ["exact-returned-controller-and-frontend-known-cleanup", "matching-MCP-case"]})
    # Returned owner/frontend were created by the product worker, not Owner.child.
    # Keep their actual native collector handles with the sole native operator.
    # No finalizer kills them or silently pretends they are original children.
    if inputs["initialIntent"] == "reconnect":
        modules["lifecycle"].cleanup_update_traffic(owner, traffic_before, traffic_after)
    if returned["data"].get("runtimeRunning") is True:
        public(owner, workspace, new_identity, "off")
    public(owner, workspace, new_identity, "quit")
    if recovery_serve is not None:
        recovery_serve.wait()
    owner.event("update-returned-cleanup-expected-actors", {"actors": returned_actors,
        "jobId": terminal["jobId"], "operationId": accepted["operationId"]})
    native_cleanup = native_evidence(owner, inputs, modules, "returned-cleanup",
        job=accepted["data"]["jobId"], operation=accepted["operationId"])
    require(native_cleanup.get("actorExpectations") == returned_actors
            and native_cleanup.get("ownerOriginalAbsent") is True
            and ("gui" not in returned_actors or native_cleanup.get("guiOriginalAbsent") is True),
            "exact-returned-actors-known-closed")
    fixture.close_known(all_update_operations_terminal=True)
    return 0


def run_update(owner, harness):
    try:
        return _run_update(owner, harness)
    except BaseException as error:
        fixture = getattr(owner, "update_fixture", None)
        lease = getattr(owner, "update_application_lease", None)
        if (fixture is not None and not fixture.closed) or (lease is not None and lease.retired and not lease.admitted):
            owner.park("update-scenario-failed-with-retained-owned-resources", error)
        raise
