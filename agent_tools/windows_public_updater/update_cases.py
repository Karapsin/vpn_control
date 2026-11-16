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
    "success-off", "success-reconnect", "success-explicit-off", "different-admin", "wait-client-loss", "installer-wait-client-loss",
    "transport-loss"))
INSTALL_VARIANTS = VARIANTS - {"public-ready", "download-cancelled", "checksum-rejected"}
SUCCESS_VARIANTS = frozenset(("success-off", "success-reconnect", "success-explicit-off", "different-admin", "wait-client-loss",
                              "installer-wait-client-loss", "transport-loss"))
# A returned CANCELLED ends these known. The async installer wait needs a native terminal to rule out a
# running helper, so it keeps parking; protected storage settles every answer through settle_counterfeit.
GRANT_VARIANTS = INSTALL_VARIANTS - {"uac-denied", "install-cancelled", "installer-wait-client-loss", "protected-storage-rejected"}
# Connected before the update: a loopback location through the case's own in-guest SOCKS upstream on its fixed port.
# success-reconnect is updated connected, so its remembered intent is on. success-explicit-off turns that connected owner
# off explicitly first (DESKTOP-004: explicit off clears the intent): its returned owner keeps a selected location that
# carried traffic, and so could reconnect, and must not. success-off's fresh workspace has no location at all, so its
# off intent is never tested by a returned owner that could connect.
CONNECTED_VARIANTS = frozenset({"success-reconnect", "success-explicit-off"})
CONNECTED_INTENT = {"success-reconnect": "reconnect", "success-explicit-off": "off"}
UPSTREAM_FIELDS = frozenset({"schemaVersion", "sourcePath", "port", "token"})
# ProxyLinkParser dispatches socks://, never socks5://: the owner answers any other scheme INVALID_ARGUMENT, as the proxy
# rows met natively at their own locations add. The product renders socks:// as a SOCKS5 outbound.
CONNECTION_PROFILE = re.compile(r"socks://127\.0\.0\.1:([0-9]{1,5})#Update%20fixture\n?")
# The returned owner restores the remembered intent itself. It is read until its runtime runs, at most this long after it
# first answers, and the whole outage from the handoff (the runtime stops before the commit) stays within the second
# bound: the coordinator's own three-minute exit deadline, the install and the relaunch.
RECONNECT_SECONDS = 180
OUTAGE_SECONDS = 900
# install-cancelled waits at most this long for its cancelled operation: a prompt the decision answers within its 90 s,
# the coordinator's three-minute precommit deadline and a margin. A TIMEOUT then parks with the public reply kept.
CANCEL_WAIT_SECONDS = 420
# What a participating copy leaves the installer: its inventory stage never admits the copy, so the coordinator waits
# out its exit deadline and publishes FAILED RUNTIME_FAILED beside this protected diagnostic
# (VpnInstallHelperRoles.RunCoordinator, PublishProtectedPreinstallDiagnostic). It never stops the copy.
COPY_LOCK_DIAGNOSTIC = {"version": 1, "stage": "INVENTORY", "kind": "OTHER"}
# protected-storage-rejected: before its approved install the ordinary user plants the product's machine storage root,
# which the product's elevated coordinator would make itself (ProgramData\vpn-control-install-jobs), owned by that user
# with the full control a squatter keeps, and one canary file in it. The job names the bytes and both SDDLs. The product
# must refuse that root. It may answer OUTCOME_UNKNOWN, since its only store of the job is the root it refused, or a
# definite RUNTIME_FAILED or PERMISSION_DENIED; any other definite answer is this row's known failure.
COUNTERFEIT_REFUSALS = ("OUTCOME_UNKNOWN", "RUNTIME_FAILED", "PERMISSION_DENIED")
COUNTERFEIT_FIELDS = frozenset(("kind", "path", "canary", "canaryText", "rootSddl", "canarySddl"))
COUNTERFEIT_CANARY = "counterfeit-canary.json"
COUNTERFEIT_ROOT_SDDL = "O:{sid}G:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
COUNTERFEIT_CANARY_SDDL = "O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"


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
        "faultInputs", "returnGuiRequired", "connectionFixturePath", "upstreamFixture"}
    require(type(value) is dict and set(value) == required and value["schemaVersion"] == 1
            and value["variant"] in VARIANTS, "finite-update-input-schema")
    require(all(value[k] is not None for k in required - {"trafficInputs", "connectionFixturePath", "approvingAdminSid", "upstreamFixture"}),
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
    if value["variant"] in CONNECTED_VARIANTS:
        upstream = value["upstreamFixture"]
        require(value["initialIntent"] == CONNECTED_INTENT[value["variant"]] and type(value["trafficInputs"]) is dict
                and type(value["connectionFixturePath"]) is str and type(upstream) is dict,
                "connected-variant-requires-live-traffic-fixture")
        require(set(upstream) == UPSTREAM_FIELDS and upstream["schemaVersion"] == 1 and type(upstream["port"]) is int
                and 1024 <= upstream["port"] <= 65535 and type(upstream["token"]) is str
                and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", upstream["token"]) is not None
                and type(upstream["sourcePath"]) is str and upstream["sourcePath"].casefold() in owner.by_path,
                "owned-loopback-upstream-fixture")
        # windows_lifecycle_cases._update_probe's closed form: the sampler and its input are held before any effect.
        traffic = value["trafficInputs"]
        require(set(traffic) == {"schemaVersion", "trafficWorkerPath", "trafficInputPath", "fixtureAdmissionArtifactId",
                                 "sourceArtifactId"} and traffic["schemaVersion"] == 1
                and all(type(traffic[key]) is str and traffic[key] for key in traffic if key != "schemaVersion")
                and all(traffic[key].casefold() in owner.by_path for key in ("trafficWorkerPath", "trafficInputPath")),
                "held-update-traffic-inputs")
    else:
        require(value["initialIntent"] == "off" and value["trafficInputs"] is None and value["connectionFixturePath"] is None
                and value["upstreamFixture"] is None, "disconnected-variant-off-intent")
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
    if value["variant"] == "protected-storage-rejected":
        counterfeit_binding(value)  # A counterfeit the job did not bind is never planted: refused before any effect.
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
    require(stage in {"before-install", "cancel-actors", "authorization", "terminal-actors", "returned-gui", "fault-ready",
                      "transport-restored", "returned-cleanup"}, "finite-native-evidence-stage")
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


def start_upstream(owner, upstream):
    """The in-guest SOCKS upstream the loopback location names, on its fixed port: this owner's child until stopped."""
    ready = owner.root / "update-upstream.ready"
    require(not ready.exists(), "fresh-owned-upstream-ready-file")
    child = owner.child("update-upstream", [owner.request["pythonRuntime"]["interpreterPath"], "-I", "-B", upstream["sourcePath"],
        "--port", str(upstream["port"]), "--token", upstream["token"], "--ready-file", str(ready)])
    owner.update_upstream = child  # Retained on every path: a live upstream is a live child of this owner.
    until = time.monotonic() + 30
    while not ready.exists():
        require(child.process.poll() is None, "owned-upstream-ended-before-ready")
        if time.monotonic() >= until:
            owner.park("update-upstream-readiness-unknown-no-replay")
        time.sleep(0.1)
    time.sleep(0.2)
    require(ready.read_text(encoding="utf-8").strip() == str(upstream["port"]) and child.process.poll() is None,
            "owned-upstream-fixed-port")
    owner.event("update-upstream-ready", {"child": child.ordinal, "pid": child.pid, "port": upstream["port"]})
    return child


def stop_upstream(owner, child):
    """Exactly one journaled termination of the case's own upstream, then its known exit."""
    require(child.terminal is None and child.process.poll() is None, "live-original-update-upstream")
    owner.event("update-upstream-stop-intent", {"child": child.ordinal, "pid": child.pid, "birthFileTimeUtc": child.birth,
                                                "replayAllowed": False})
    child.process.terminate()
    until = time.monotonic() + 15
    while child.observe() is None:
        if time.monotonic() >= until:
            owner.park("update-upstream-stop-unknown-no-replay")
        time.sleep(0.05)
    owner.event("update-upstream-stopped", child.terminal)


def await_reconnect(owner, workspace, identity, connected, handoff):
    """The returned owner restores the remembered reconnect intent by itself: the same location in the same mode, a
    runtime of its own, within both bounds. Nothing here asks it to connect, so a returned owner that stays off fails."""
    answered = time.monotonic()
    while True:
        status = public(owner, workspace, identity, "status")
        if status["data"].get("runtimeRunning") is True:
            break
        require(time.monotonic() - answered < RECONNECT_SECONDS, "returned-owner-reconnect-unbounded")
        time.sleep(0.5)
    restored = time.monotonic()
    data, before = status["data"], connected["data"]
    require(data.get("activeLocationId") == before.get("activeLocationId") and data.get("selectedLocationId") == before.get("selectedLocationId")
            and data.get("activeMode") == "proxy-only", "returned-owner-restored-same-location")
    require(restored - handoff <= OUTAGE_SECONDS, "update-reconnect-outage-unbounded")
    owner.event("update-reconnect-restored", {"status": status, "secondsAfterHandoff": round(restored - handoff, 3),
        "secondsAfterReturnedOwner": round(restored - answered, 3), "boundSeconds": OUTAGE_SECONDS,
        "runtimeBefore": {key: before.get(key) for key in ("runtimeId", "runtimeStartedAt")},
        "runtimeAfter": {key: data.get(key) for key in ("runtimeId", "runtimeStartedAt")}, "replayAllowed": False})
    return status


def await_off_kept(owner, workspace, identity, kept):
    """The returned owner of an explicit off keeps it: read for as long as a reconnect is given, it never runs, and the
    location it could connect to stays selected in the same mode. One read that runs fails the case."""
    answered = time.monotonic()
    reads = 0
    while True:
        status = public(owner, workspace, identity, "status")
        reads += 1
        data = status["data"]
        require(data.get("runtimeRunning") is False, "returned-owner-explicit-off-kept")
        require(data.get("selectedLocationId") == kept["data"].get("selectedLocationId") and data.get("configuredMode") == "proxy-only",
                "returned-owner-explicit-off-same-selection")
        if time.monotonic() - answered >= RECONNECT_SECONDS:
            break
        time.sleep(0.5)
    owner.event("update-explicit-off-kept", {"status": status, "reads": reads, "watchedSeconds": round(time.monotonic() - answered, 3),
                                             "boundSeconds": RECONNECT_SECONDS, "replayAllowed": False})
    return status


def preinstall_diagnostic(owner, inputs, receipts, job):
    """The coordinator's protected pre-install diagnostic of one job, read as the ordinary owner reads its receipt."""
    path = str(receipts.canonical_path(inputs["programData"]) / "vpn-control-install-jobs" / job / "preinstall-diagnostic.json")
    value = receipts.FileObservation(owner, path)
    try:
        receipts.machine_security(value.opening["security"], False)
        raw = value.read(4096)
    finally:
        value.close()
    found = json.loads(raw)
    owner.event("update-preinstall-diagnostic-observed", {"nativeFile": value.opening, "value": found,
        "sha256": hashlib.sha256(raw).hexdigest(), "readOnly": True})
    return found


def helper_sha256(inputs):
    """The installed base's installer helper, as the base inventory records it: the image both installer actors run."""
    rows = [item for name, item in inputs["baseInventory"].items()
            if name.casefold() == "app/native/windows-amd64/vpn-control-install-helper.exe"]
    require(len(rows) == 1, "installed-base-install-helper")
    return rows[0]["sha256"]


def cancelled_installer_actors(watched, inputs, job):
    """What the SYSTEM watch saw between the approval and the cancelled terminal: exactly the job's coordinator, elevated
    as the approving administrator, and its original-user worker, unelevated, born after it; both gone, and no other
    elevated helper left running. The watch was armed before the install was asked for, so it saw neither yet."""
    helper = helper_sha256(inputs)
    actors = watched.get("actors") if type(watched.get("actors")) is list else []
    roles = {}
    for row in actors:
        require(type(row) is dict and row.get("role") in {"coordinator", "worker"} and row.get("role") not in roles,
                "cancel-watch-one-actor-per-role")
        roles[row["role"]] = row
    require(watched.get("armedBeforeActors") is True and watched.get("complete") is True and watched.get("timedOut") is False
            and watched.get("jobId") == job and set(roles) == {"coordinator", "worker"}, "cancel-watch-complete-job-actors")
    coordinator, worker = roles["coordinator"], roles["worker"]
    for row, sid, elevated in ((coordinator, inputs["approvingAdminSid"], 1), (worker, inputs["ordinarySid"], 0)):
        require(row.get("jobId") == job and row.get("sha256") == helper and row.get("sid") == sid and row.get("elevated") == elevated
                and row.get("sessionId") == inputs["ordinarySessionId"] and row.get("originalAbsent") is True,
                "cancel-watch-" + row["role"] + "-identity")
    require(type(worker.get("creationFileTime")) is int and type(coordinator.get("creationFileTime")) is int
            and worker["creationFileTime"] > coordinator["creationFileTime"], "cancel-watch-worker-generation")
    others = watched.get("others") if type(watched.get("others")) is list else None
    require(others is not None and all(type(row) is dict and (row.get("elevated") != 1 or row.get("originalAbsent") is True)
                                       for row in others), "cancel-watch-no-elevated-helper-left")
    return {"coordinator": coordinator, "worker": worker, "others": len(others)}


class _FileInformation(ctypes.Structure):
    _fields_ = [("attributes", W.DWORD), ("creation", W.FILETIME), ("access", W.FILETIME), ("write", W.FILETIME),
                ("volume", W.DWORD), ("sizeHigh", W.DWORD), ("sizeLow", W.DWORD), ("links", W.DWORD),
                ("indexHigh", W.DWORD), ("indexLow", W.DWORD)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


class CounterfeitNative:
    """The ordinary user's few Win32 calls for its counterfeit root: create one directory and one file, each create-only
    with an exact security descriptor; list the directory; and delete one object only through a handle whose volume
    and file index are first checked against the identity recorded when it was made. Its own library instances."""

    def __init__(self):
        require(os.name == "nt", "counterfeit-root-windows-only")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)
        for name, arguments, result in (
                ("CreateDirectoryW", (W.LPCWSTR, ctypes.POINTER(_SecurityAttributes)), W.BOOL),
                ("CreateFileW", (W.LPCWSTR, W.DWORD, W.DWORD, ctypes.POINTER(_SecurityAttributes), W.DWORD, W.DWORD, W.HANDLE), W.HANDLE),
                ("WriteFile", (W.HANDLE, ctypes.c_char_p, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID), W.BOOL),
                ("FlushFileBuffers", (W.HANDLE,), W.BOOL), ("CloseHandle", (W.HANDLE,), W.BOOL),
                ("LocalFree", (W.HLOCAL,), W.HLOCAL), ("GetFileAttributesW", (W.LPCWSTR,), W.DWORD),
                ("GetFileInformationByHandle", (W.HANDLE, ctypes.POINTER(_FileInformation)), W.BOOL),
                ("SetFileInformationByHandle", (W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD), W.BOOL)):
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result
        convert = self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW
        convert.argtypes, convert.restype = (W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD)), W.BOOL

    def _attributes(self, sddl):
        descriptor = W.LPVOID()
        require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None)
                and descriptor.value, "counterfeit-security-descriptor")
        return _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False), descriptor

    def create_directory(self, path, sddl):
        attributes, descriptor = self._attributes(sddl)
        try:
            if not self.k.CreateDirectoryW(path, ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                require(error != 183, "counterfeit-root-present")  # ERROR_ALREADY_EXISTS: never this case's own.
                raise ctypes.WinError(error)
        finally:
            self.k.LocalFree(descriptor)

    def create_file(self, path, sddl, raw):
        attributes, descriptor = self._attributes(sddl)
        try:
            handle = self.k.CreateFileW(path, 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)  # GENERIC_WRITE, CREATE_NEW
            if handle in (None, ctypes.c_void_p(-1).value):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.k.LocalFree(descriptor)
        try:
            written = W.DWORD()
            require(self.k.WriteFile(handle, raw, len(raw), ctypes.byref(written), None) and written.value == len(raw)
                    and self.k.FlushFileBuffers(handle), "counterfeit-canary-write")
        finally:
            require(self.k.CloseHandle(handle), "counterfeit-canary-close")

    def names(self, path):
        return sorted(os.listdir(path))

    def remove(self, path, directory, identity):
        # DELETE|FILE_READ_ATTRIBUTES|SYNCHRONIZE, all sharing, the object itself even were it a link.
        flags = 0x00200000 | (0x02000000 if directory else 0)
        handle = self.k.CreateFileW(path, 0x00110080, 7, None, 3, flags, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = _FileInformation()
            require(self.k.GetFileInformationByHandle(handle, ctypes.byref(info)), "counterfeit-identity-read")
            require(not info.attributes & 0x400 and bool(info.attributes & 0x10) == directory
                    and {"volumeSerial": info.volume, "fileIndex": info.indexHigh << 32 | info.indexLow}
                    == {key: identity[key] for key in ("volumeSerial", "fileIndex")}, "counterfeit-identity-changed")
            delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile
            require(self.k.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), 1), "counterfeit-delete")
        finally:
            require(self.k.CloseHandle(handle), "counterfeit-delete-close")

    def absent(self, path):
        if self.k.GetFileAttributesW(path) != 0xFFFFFFFF:
            return False
        return ctypes.get_last_error() in (2, 3)


def counterfeit_binding(inputs):
    """The job's binding of this row's counterfeit, checked against the fixed forms; returns it and the canary bytes."""
    value, sid = inputs["faultInputs"], inputs["ordinarySid"]
    root = PureWindowsPath(inputs["programData"]) / "vpn-control-install-jobs"
    require(type(value) is dict and set(value) == COUNTERFEIT_FIELDS and value["kind"] == "protected-storage-rejected"
            and type(value["canaryText"]) is str and 0 < len(value["canaryText"]) <= 4096, "counterfeit-root-binding")
    raw = value["canaryText"].encode("ascii")
    require(value["path"] == str(root) and value["canary"] == {"path": str(root / COUNTERFEIT_CANARY),
                                                                "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)}
            and value["rootSddl"] == COUNTERFEIT_ROOT_SDDL.format(sid=sid)
            and value["canarySddl"] == COUNTERFEIT_CANARY_SDDL.format(sid=sid), "counterfeit-root-binding")
    return value, raw


def counterfeit_view(owner, receipts, counterfeit, native):
    """This case's own read-only view of its counterfeit: the root's and the canary's identity and security, the
    canary's bytes and the root's entries. Each handle closes before it returns."""
    binding = counterfeit["binding"]
    root = receipts.FileObservation(owner, binding["path"], directory=True)
    try:
        root_opening = root.opening
    finally:
        root.close()
    canary = receipts.FileObservation(owner, binding["canary"]["path"])
    try:
        raw = canary.read(4096)
        canary_opening = canary.opening
    finally:
        canary.close()
    return {"root": root_opening, "canary": canary_opening, "canarySha256": hashlib.sha256(raw).hexdigest(),
            "names": native.names(binding["path"])}


def plant_counterfeit_root(owner, inputs, receipts, native):
    """Create the counterfeit root and its canary as the ordinary user, each create-only, before the install.

    A root that already exists is never this case's: the plant refuses, and nothing of it is removed. The custody
    record exists before the first effect, so any failure from here on parks with the counterfeit in place.
    """
    binding, raw = counterfeit_binding(inputs)
    counterfeit = {"binding": binding, "root": None, "canary": None, "created": [], "removed": False}
    owner.update_counterfeit = counterfeit
    owner.event("update-counterfeit-root-intent", {"path": binding["path"], "canary": binding["canary"],
        "rootSddl": binding["rootSddl"], "canarySddl": binding["canarySddl"], "replayAllowed": False})
    native.create_directory(binding["path"], binding["rootSddl"])
    counterfeit["created"].append("root")
    native.create_file(binding["canary"]["path"], binding["canarySddl"], raw)
    counterfeit["created"].append("canary")
    view = counterfeit_view(owner, receipts, counterfeit, native)
    sid = inputs["ordinarySid"]
    require(view["root"]["security"]["ownerSid"] == sid and view["canary"]["security"]["ownerSid"] == sid
            and view["canarySha256"] == binding["canary"]["sha256"] and view["names"] == [COUNTERFEIT_CANARY],
            "counterfeit-root-planted")
    counterfeit.update(root=view["root"], canary=view["canary"])
    owner.event("update-counterfeit-root-planted", {"root": view["root"], "canary": view["canary"], "names": view["names"]})
    return counterfeit


def remove_counterfeit(owner, counterfeit, native):
    """Delete the canary, then the empty root, each through a handle that is the object this case created."""
    binding = counterfeit["binding"]
    native.remove(binding["canary"]["path"], False, counterfeit["canary"]["nativeIdentity"])
    noticed = time.monotonic()
    while not native.absent(binding["canary"]["path"]):
        # Another program's open handle defers the delete; the root stays until its canary is gone.
        require(time.monotonic() - noticed < 30, "counterfeit-canary-delete-deferred")
        time.sleep(0.2)
    native.remove(binding["path"], True, counterfeit["root"]["nativeIdentity"])
    require(native.absent(binding["path"]), "counterfeit-root-left")
    counterfeit["removed"] = True
    owner.event("update-counterfeit-root-removed", {"path": binding["path"], "canary": binding["canary"]["path"],
        "absent": True})


def _reply_code(result):
    """The product's own code from a completed public call; the envelope checks follow in json_result."""
    try:
        value = json.loads(result.stdout)
    except ValueError:
        return None
    code = value.get("code") if type(value) is dict else None
    return code if type(code) is str and re.fullmatch(r"[A-Z][A-Z_]{1,63}", code) else None


def settle_counterfeit(owner, inputs, modules, counterfeit, fault, result, *, before, serve, gui, lease, fixture, native):
    """protected-storage-rejected once its approved install returned: end known with proof, or park.

    Passed (0): the product refused (COUNTERFEIT_REFUSALS). Failed (1): the product gave any other definite answer, an
    expired prompt's CANCELLED among them. Either needs all of: the reply from the original controller; SYSTEM's
    terminal-actors, which the job serves only once no process of the installed helper image is left, seeing the root
    and canary exactly as at fault-ready; this case's own view of them unchanged, the root holding the canary alone;
    the same owner, configuration and disconnected runtime; the base registration in place and every base file the
    owner pinned unchanged; then the serve quit, the fixture closed and the counterfeit removed by its own handles. An
    accepted install (OK or ACCEPTED: an installer job exists somewhere), an unreadable reply, a changed root or canary
    and any failing step park, the counterfeit kept, and nothing is retried.
    """
    receipts, workspace, identity = modules["receipts"], Path(owner.request["workspace"]), before["controllerId"]
    code = _reply_code(result)
    require(code is not None, "counterfeit-install-reply")
    reply = json_result(result, codes=(code,), final=None)  # Envelope, empty stderr and exit code agree, whatever the code.
    require(reply.get("controllerId") == identity, "counterfeit-original-controller")
    owner.event("update-counterfeit-install-answered", {"code": code, "operationId": reply.get("operationId"),
        "refusal": code in COUNTERFEIT_REFUSALS, "replayAllowed": False})
    if code in ("OK", "ACCEPTED"):
        owner.park("counterfeit-root-install-accepted-open", reply)
    observed = native_evidence(owner, inputs, modules, "terminal-actors", operation=reply.get("operationId"))
    require(observed.get("protectedStorageRefusal") == fault, "counterfeit-root-system-changed")
    view = counterfeit_view(owner, receipts, counterfeit, native)
    require(view == {"root": counterfeit["root"], "canary": counterfeit["canary"], "canarySha256": counterfeit["binding"]["canary"]["sha256"],
                     "names": [COUNTERFEIT_CANARY]}, "counterfeit-root-changed")
    invariant_status(before, public(owner, workspace, identity, "status"))
    receipts.installed_registration(inputs["baseRegistration"], owner.native)
    for pin in lease.files:
        pin.digest()
    close_disconnected(owner, workspace, identity, serve, gui)
    fixture.close_known(all_update_operations_terminal=True)
    remove_counterfeit(owner, counterfeit, native)
    outcome = 0 if code in COUNTERFEIT_REFUSALS else 1
    owner.update_counterfeit_settled = {"variant": "protected-storage-rejected", "result": outcome, "code": code,
        "operationId": reply.get("operationId"), "systemUnchanged": True, "rootRemoved": True}
    owner.event("update-counterfeit-settled", {**owner.update_counterfeit_settled, "knownFailure": outcome == 1,
        "replayAllowed": False})
    return outcome


def _run_update(owner, harness):
    inputs = validate_inputs(owner, harness["UPDATE_INPUTS"])
    modules = load_modules(owner, inputs)
    receipts, prepared = modules["receipts"], modules["prepare_desktop_update_fixture"]
    variant = inputs["variant"]
    workspace = Path(owner.request["workspace"])
    require(workspace.parent == owner.root and not workspace.exists(), "new-isolated-update-workspace")
    require(receipts.within(owner.request["cliPath"], inputs["installedRoot"])
            and receipts.within(inputs["guiPath"], inputs["installedRoot"]), "exact-installed-update-launchers")
    connection = ([] if inputs["upstreamFixture"] is None else
                  [inputs["upstreamFixture"]["sourcePath"], inputs["connectionFixturePath"], inputs["trafficInputs"]["trafficWorkerPath"],
                   inputs["trafficInputs"]["trafficInputPath"]])
    owner.update_retained_source_paths = [*inputs["modules"].values(), owner.request["casesPath"],
        owner.request["harnessPath"], str(owner.pins[0].path), type(owner).guard.__code__.co_filename,
        *[inputs["fixture"][x] for x in ("content", "state", "certificate", "privateKey", "trustStore")], *connection]
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
    traffic_before = traffic_after = upstream_child = None
    if variant in CONNECTED_VARIANTS:
        profile_path = inputs["connectionFixturePath"]
        require(type(profile_path) is str and profile_path.casefold() in owner.by_path,
                "held-owned-loopback-connection-profile")
        profile = owner.by_path[profile_path.casefold()].digest(True).decode("utf-8", "strict")
        found = CONNECTION_PROFILE.fullmatch(profile)
        require(found is not None and int(found[1]) == inputs["upstreamFixture"]["port"],
                "owned-no-egress-socks-connection-profile")
        # The location's upstream runs before any runtime names it, and stays until the returned owner is closed.
        upstream_child = start_upstream(owner, inputs["upstreamFixture"])
        revision = before["configurationRevision"]
        mode = public(owner, workspace, identity, "settings", "set", "mode", "proxy-only", revision=revision)
        # A fresh workspace reads subscriptions, and locations add answers READ_ONLY_SOURCE there.
        source = public(owner, workspace, identity, "source", "set", "current-locations",
            revision=mode["configurationRevision"])
        added = public(owner, workspace, identity, "locations", "add", "--input", profile_path,
            revision=source["configurationRevision"])
        location_id = added["data"].get("id")
        require(type(location_id) is str and location_id, "public-loopback-location-id")
        selected = public(owner, workspace, identity, "locations", "select", location_id,
            revision=added["configurationRevision"])
        # As the proxy rows' runtime, which carried traffic natively: every connection through the loopback location.
        public(owner, workspace, identity, "routing", "set", "ignore-rules", "true", revision=selected["configurationRevision"])
        # Runtime commands take no revision guard: the product answers UNSUPPORTED to one.
        public(owner, workspace, identity, "on")
        traffic_before = modules["lifecycle"].prepare_update_traffic(owner, workspace, identity, inputs["trafficInputs"])
        before = public(owner, workspace, identity, "status")
        require(before["data"].get("runtimeRunning") is True and before["data"].get("activeLocationId") == location_id
                and before["data"].get("activeMode") == "proxy-only", "connected-update-fixture-active")
        if inputs["initialIntent"] == "off":
            # The public explicit off, which clears the remembered intent; the location stays selected in its mode.
            public(owner, workspace, identity, "off")
            before = public(owner, workspace, identity, "status")
            require(before["data"].get("runtimeRunning") is False and before["data"].get("selectedLocationId") == location_id
                    and before["data"].get("configuredMode") == "proxy-only", "explicit-off-update-fixture-selected")
            owner.event("update-explicit-off-before-update", {"status": before, "replayAllowed": False})
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
    counterfeit = counterfeit_native = None
    if variant == "protected-storage-rejected":
        # Planted last before the install: every public call before it ran against a machine without the root. Its
        # binding was checked with the inputs, before any effect.
        counterfeit_native = CounterfeitNative()
        counterfeit = plant_counterfeit_root(owner, inputs, receipts, counterfeit_native)
    if variant in {"protected-storage-rejected", "native-install-failed", "participating-copy-lock"}:
        fault = native_evidence(owner, inputs, modules, "fault-ready")
        require(fault.get("kind") == variant and fault.get("binding") == inputs["faultInputs"], "actual-finite-fault-preparation")
        if variant == "participating-copy-lock":
            # SYSTEM saw the very copy this owner started, live and unelevated as the ordinary user, running the
            # installed launcher the installer must replace.
            copy = fault.get("participatingCopy") if type(fault.get("participatingCopy")) is dict else {}
            token = copy.get("token") if type(copy.get("token")) is dict else {}
            require(copy.get("pid") == blocking_copy.pid and copy.get("creationFileTime") == int(blocking_copy.birth)
                    and token.get("sid") == inputs["ordinarySid"] and token.get("elevated") == 0
                    and token.get("sessionId") == inputs["ordinarySessionId"]
                    and copy.get("sha256") == owner.by_path[owner.request["cliPath"].casefold()].record["sha256"],
                    "native-participating-copy-actor")
        if counterfeit is not None:
            # SYSTEM saw the very objects this case made: the user's root its machine policy refuses, and the canary.
            require(fault.get("root") == counterfeit["root"]
                    and fault.get("canary") == {"nativeFile": counterfeit["canary"], "sha256": counterfeit["binding"]["canary"]["sha256"]},
                    "counterfeit-root-system-join")
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
    if variant == "protected-storage-rejected":
        return settle_counterfeit(owner, inputs, modules, counterfeit, fault, result, before=before, serve=serve, gui=gui_child,
                                  lease=lease, fixture=fixture, native=counterfeit_native)
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
        # Bounded: a cancellation the product never ends comes back TIMEOUT, its reply kept in this child's own stream.
        cancelled = json_result(owner.invoke(workspace, "--json", "--controller-id", identity, "--timeout-seconds",
                                             str(CANCEL_WAIT_SECONDS), "operations", "wait", install_operation),
                                codes=("CANCELLED",), final=True)
        require(cancelled.get("controllerId") == identity, "same-authenticated-updater-owner")
        cancel_rows = public(owner, workspace, identity, "updates", "status")["data"].get("installations", [])
        cancel_matches = [x for x in cancel_rows if x.get("originControllerId") == identity
                          and x.get("operationId") == install_operation]
        require(len(cancel_matches) == 1 and cancel_matches[0].get("final") is True
                and cancel_matches[0].get("installed") is False, "exact-cancelled-public-installation")
        cancel_job = receipts.canonical_uuid(cancel_matches[0].get("jobId"))
        # The coordinator and worker live only from the approval to the product's own CANCELLED. The SYSTEM watch armed
        # with before-install saw them both, live, and saw them go.
        watched = native_evidence(owner, inputs, modules, "cancel-actors", job=cancel_job)
        actors = cancelled_installer_actors(watched, inputs, cancel_job)
        owner.event("update-install-cancel-actors-observed", {"jobId": cancel_job, "operationId": install_operation,
            "coordinator": actors["coordinator"], "worker": actors["worker"], "otherHelperProcesses": actors["others"]})
        native_cancel = native_evidence(owner, inputs, modules, "terminal-actors",
            job=cancel_job, operation=install_operation)
        require(native_cancel.get("protectedReceipt", {}).get("phase") == "CANCELLED",
                "native-cancellation-terminal-not-request-acceptance")
        expected = native_cancel.get("actorExpectations") if type(native_cancel.get("actorExpectations")) is dict else {}
        exits = native_cancel.get("actorExitObservations") if type(native_cancel.get("actorExitObservations")) is list else []
        require(set(expected) == {"coordinator", "worker"}
                and all(expected[role].get("pid") == actors[role]["pid"]
                        and expected[role].get("creationFileTime") == actors[role]["creationFileTime"] for role in expected)
                and len(exits) == 2 and all(type(x) is dict and x.get("originalAbsent") is True for x in exits),
                "native-cancelled-installer-actors-known-closed")
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
        if upstream_child is not None:
            stop_upstream(owner, upstream_child)
        fixture.close_known(all_update_operations_terminal=True)
        owner.update_cancelled_grant = {"variant": variant, "operationId": cancelled.get("operationId")}
        owner.event("update-grant-cancelled-known", {**owner.update_cancelled_grant, "knownFailure": True, "replayAllowed": False})
        return 1
    accepted = receipts.handoff(result, identity)
    handoff = time.monotonic()  # The runtime stopped before the commit this reply acknowledges.
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
            # The product's documented outcome: the copy is never stopped, the inventory stage never admits it, and the
            # coordinator ends FAILED RUNTIME_FAILED at its exit deadline with the protected INVENTORY diagnostic. The
            # copy this owner started is still running when that terminal is read; the owner then closes it itself.
            require(terminal["code"] == "RUNTIME_FAILED" and blocking_copy is not None and blocking_copy.terminal is None
                    and blocking_copy.process.poll() is None, "participating-copy-gate-native-failure")
            require(preinstall_diagnostic(owner, inputs, receipts, terminal["jobId"]) == COPY_LOCK_DIAGNOSTIC,
                    "participating-copy-inventory-diagnostic")
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
    if inputs["initialIntent"] == "reconnect":
        # A returned owner that answers before its resumed runtime runs is not yet a failure: it is read, bounded.
        returned = await_reconnect(owner, workspace, new_identity, before, handoff)
        traffic_after = modules["lifecycle"].verify_update_traffic(owner, workspace, new_identity, inputs["trafficInputs"])
    elif variant in CONNECTED_VARIANTS:
        returned = await_off_kept(owner, workspace, new_identity, before)
    require(returned["data"].get("runtimeRunning") == (inputs["initialIntent"] == "reconnect"), "off-or-reconnect-intent-preserved")
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
    if traffic_before is not None:
        modules["lifecycle"].cleanup_update_traffic(owner, *(item for item in (traffic_before, traffic_after) if item is not None))
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
    if upstream_child is not None:
        stop_upstream(owner, upstream_child)  # Every runtime that named it is off and its owner gone.
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
        # A counterfeit storage root this case made and has not removed stays on the clone: never a known end.
        counterfeit = getattr(owner, "update_counterfeit", None)
        if counterfeit is not None and counterfeit["created"] and not counterfeit["removed"]:
            owner.park("update-counterfeit-root-retained", error)
        raise
