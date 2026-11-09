"""Finite installed-Windows lifecycle adapters. Preparation only; no main.

Use only inside the already qualified ordinary retained Owner namespace. Imports
do not load native APIs. The sole Windows operator binds source/artifact/context,
active fixture/runtime actors, workspace, and original child handles. A pending
binding is a refusal before effects. These functions never create receipts that
claim the 64-member acceptance set is complete.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import json
import ntpath
from pathlib import Path
import re
import subprocess
import time


CRASH_EXIT = 0xE0421001
# A GUI whose attach the owner refuses prints this one line on stdout and returns from main (Main.kt), so its
# JVM, and the jpackage launcher that waits for it and exits with its code, both exit 0 before any window.
GUI_ATTACH_REFUSED = b"UNAVAILABLE: could not attach graphical frontend.\n"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def json_result(result, identity, *, codes=("OK",), exits=(0,)):
    require(result.returncode in exits and result.stderr == "", "public-cli-exit-or-stderr")
    body = json.loads(result.stdout)
    require(type(body) is dict and body.get("schemaVersion") == 1
            and body.get("controllerId") == identity and body.get("code") in codes
            and body.get("ok") == (result.returncode == 0) and body.get("final") is True,
            "public-cli-owner-envelope")
    return body


def read(owner, workspace, identity, *arguments):
    require(str(workspace) == owner.request["workspace"] and Path(workspace).parent == owner.root,
            "owned-lifecycle-workspace-only")
    return json_result(owner.invoke(workspace, "--json", "--controller-id", identity,
                                   *arguments), identity)


def active(status):
    data = status["data"]
    require(data.get("runtimeRunning") is True and data.get("runtimeId")
            and data.get("activeLocationId") and data.get("activeMode"), "active-runtime-required")
    return {key: data.get(key) for key in ("runtimeId", "runtimeStartedAt",
            "runtimeRunning", "activeLocationId", "activeMode")}


def config_bytes(path):
    """Observation, not independent file admission; caller holds config generation."""
    with Path(path).open("rb") as stream:
        raw = stream.read(32 * 1024 * 1024 + 1)
    require(0 < len(raw) <= 32 * 1024 * 1024, "runtime-config-bound")
    return {"sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class LiveConfig:
    """Observe live product data without blocking its normal writes or deletion.

    This is not a source Pin: product configuration must never enter immutable
    Owner.filePins. Sharing read/write/delete preserves product cleanup behavior.
    During a continuity window the original file ID, metadata, ACL and bytes must
    still match both retained and current named observations.
    """
    def __init__(self, owner, workspace, path):
        require(Path(path) == Path(workspace) / "runtime-config.json"
                and str(Path(path)).casefold() not in owner.by_path,
                "live-product-config-is-not-an-immutable-source-pin")
        self.owner, self.path, self.handle = owner, Path(path), None
        if not hasattr(owner, "lifecycle_config_observations"):
            owner.lifecycle_config_observations = []
        owner.lifecycle_config_observations.append(self)  # Custody before native open.
        self.handle = owner.native.k.CreateFileW(str(self.path), 0x80020000, 7, None, 3, 0x02200000, None)
        require(self.handle != ctypes.c_void_p(-1).value, "live-config-observation-open")
        self.identity = owner.native.identity(self.handle)
        self.security = owner.native.security(self.handle)
        require(self.security["ownerSid"] == owner.request["context"]["ordinarySid"],
                "ordinary-live-config-owner")
        self.initial = self.snapshot()

    def snapshot(self):
        require(self.handle is not None and self.handle != ctypes.c_void_p(-1).value,
                "live-config-observation-closed")
        native = self.owner.native
        require(native.identity(self.handle) == self.identity
                and native.security(self.handle) == self.security
                and 0 < self.identity["sizeBytes"] <= 32 * 1024 * 1024,
                "live-config-generation-or-security-changed")
        digest, total = hashlib.sha256(), 0
        for block in native.read_blocks(self.handle):
            total += len(block)
            require(total <= 32 * 1024 * 1024, "live-config-byte-bound")
            digest.update(block)
        named = native.k.CreateFileW(str(self.path), 0x20080, 7, None, 3, 0x02200000, None)
        require(named != ctypes.c_void_p(-1).value, "live-config-named-observation")
        try:
            require(native.identity(named) == self.identity and native.security(named) == self.security
                    and native.identity(self.handle) == self.identity and total == self.identity["sizeBytes"],
                    "live-config-held-named-closing")
        finally:
            require(bool(native.k.CloseHandle(named)), "live-config-named-observer-close")
        return {"nativeIdentity": self.identity, "security": self.security,
                "sizeBytes": total, "sha256": digest.hexdigest()}

    def close(self):
        require(self.snapshot() == self.initial, "live-config-final-bytes-changed")
        require(bool(self.owner.native.k.CloseHandle(self.handle)), "live-config-observer-close")
        self.handle = None


def exact_actor(native, expected, *, elevated):
    require(type(expected) is dict and set(expected) == {"pid", "creationFileTime",
            "image", "sha256", "sid", "sessionId"}, "exact-actor-fields")
    require(type(expected["pid"]) is int and expected["pid"] > 0
            and type(expected["creationFileTime"]) is int and expected["creationFileTime"] > 0,
            "actual-native-actor-required")
    with native.open_process(expected["pid"], 0x101000) as process:
        actual = process.describe()
        require(process.wait() == 258, "exact-actor-live")
        require(actual["creationFileTime"] == expected["creationFileTime"]
                and ntpath.normcase(actual["image"]) == ntpath.normcase(expected["image"])
                and actual["sha256"] == expected["sha256"]
                and actual["token"]["sid"] == expected["sid"]
                and actual["token"]["sessionId"] == expected["sessionId"]
                and actual["token"]["elevated"] == int(elevated), "exact-actor-generation-token-image")
        return actual


def gui_record(owner, child, native):
    require(child in owner.children and child.process is not None and child.label == "lifecycle-gui"
            and child.process.poll() is None and child.pid == child.process.pid
            and owner.native.birth(int(child.process._handle)) == child.birth,
            "original-gui-child-handle-required")
    pin = owner.by_path[str(Path(child.argv[0])).casefold()]
    expected = {"pid": child.pid, "creationFileTime": int(child.birth),
                "image": child.argv[0], "sha256": pin.record["sha256"],
                "sid": owner.request["context"]["ordinarySid"],
                "sessionId": owner.request["context"]["ordinarySessionId"]}
    actual = exact_actor(native, expected, elevated=False)
    owner.guard()
    return {"pid": child.pid, **actual}


class GuiWindows:
    """Only windows belonging to one retained, exact GUI generation are exposed."""
    def __init__(self):
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        self.user.EnumWindows.argtypes = (self.callback, W.LPARAM)
        self.user.EnumWindows.restype = W.BOOL
        self.user.GetWindowThreadProcessId.argtypes = (W.HWND, ctypes.POINTER(W.DWORD))
        self.user.GetWindowThreadProcessId.restype = W.DWORD
        self.user.IsWindowVisible.argtypes = (W.HWND,)
        self.user.IsWindowVisible.restype = W.BOOL
        self.user.GetWindowRect.argtypes = (W.HWND, ctypes.POINTER(W.RECT))
        self.user.GetWindowRect.restype = W.BOOL
        self.user.PostMessageW.argtypes = (W.HWND, W.UINT, W.WPARAM, W.LPARAM)
        self.user.PostMessageW.restype = W.BOOL

    def windows(self, pid):
        found, errors = [], []
        def visit(hwnd, _):
            observed = W.DWORD()
            self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(observed))
            if observed.value == pid:
                rect = W.RECT()
                if not self.user.GetWindowRect(hwnd, ctypes.byref(rect)):
                    errors.append(ctypes.get_last_error())
                    return False
                found.append({"hwnd": int(hwnd), "pid": pid,
                    "visible": bool(self.user.IsWindowVisible(hwnd)),
                    "width": rect.right - rect.left, "height": rect.bottom - rect.top})
            return True
        callback = self.callback(visit)
        require(bool(self.user.EnumWindows(callback, 0)) and not errors, "native-window-enumeration")
        return found

    def close(self, hwnd, expected_pid):
        observed = W.DWORD()
        require(bool(self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(observed)))
                and observed.value == expected_pid, "exact-window-process-before-close")
        require(bool(self.user.PostMessageW(hwnd, 0x0010, 0, 0)), "exact-window-close-submission")


def relaunched_frontends(owner, child, native, launcher, access=0x101000):
    """Open each child of a GUI launcher; the JVM is the one of its own image, born after it.

    A jpackage launcher whose PATH lacks its app folder starts itself again and waits: its
    windows belong to that second process. A launcher that did not relaunch is its own JVM.
    Returns every opened process and the at most one JVM; the caller closes them. Callers
    opt in with ``relaunching``: the packaged product's launchers relaunch, so
    gui_continuity always does; without it the launcher is taken to be its own JVM.
    """
    opened, found = [], []
    try:
        for entry in native.processes():
            if entry["parentPid"] != child.pid:
                continue
            process = native.open_process(entry["pid"], access)
            opened.append(process)
            value = process.describe()
            if (process.wait() == 258 and value["creationFileTime"] >= launcher["creationFileTime"]
                    and ntpath.normcase(value["image"]) == ntpath.normcase(launcher["image"])
                    and value["sha256"] == launcher["sha256"]):
                require(value["token"]["sid"] == owner.request["context"]["ordinarySid"]
                        and value["token"]["sessionId"] == owner.request["context"]["ordinarySessionId"]
                        and value["token"]["elevated"] == 0, "ordinary-frontend-jvm-token")
                found.append((process, {"pid": entry["pid"], **value}))
        require(len(found) <= 1, "one-relaunched-frontend-jvm")
    except BaseException:
        for process in opened:
            process.__exit__(None, None, None)
        raise
    return opened, (found[0] if found else None)


def window_state(owner, child, native, windows, relaunching=False):
    record = gui_record(owner, child, native)
    opened, frontend = relaunched_frontends(owner, child, native, record) if relaunching else ([], None)
    try:
        pids = [child.pid] + ([] if frontend is None else [frontend[1]["pid"]])
        records = [row for pid in pids for row in windows.windows(pid)]
    finally:
        for process in opened:
            process.__exit__(None, None, None)
    gui_record(owner, child, native)
    owner.event("lifecycle-gui-windows", {"actor": record, "frontendJvm": None if frontend is None else frontend[1],
                 "windows": records, "windowContentOrGuiCallbackProven": False})
    return records


def ended_gui(owner, child):
    """The GUI launcher the case started has ended: refuse, naming the owner's refusal of its attach.

    Only exit 0 with exactly GUI_ATTACH_REFUSED on stdout and nothing on stderr is that refusal. Nothing
    is started again: the caller's closing collects the rest.
    """
    require(child in owner.children and child.label == "lifecycle-gui", "original-gui-child-handle-required")
    terminal = child.wait()
    streams = [(owner.root / f"child-{child.ordinal:04d}.{name}.raw").read_bytes() for name in ("stdout", "stderr")]
    refused = (terminal["exitCode"] == 0 and terminal["eof"] == {"stdout": True, "stderr": True}
               and streams == [GUI_ATTACH_REFUSED, b""])
    owner.event("lifecycle-gui-ended", {"child": child.ordinal, "pid": child.pid, "birthFileTimeUtc": child.birth,
                 "terminal": terminal, "ownerRefusedAttach": refused, "replayAllowed": False})
    require(not refused, "gui-attach-refused-by-owner")
    require(False, "original-gui-child-handle-required")


def await_window(owner, child, native, windows, visible, seconds=30, relaunching=False):
    require(type(visible) is bool and 0 < seconds <= 60, "finite-window-observation")
    until = time.monotonic() + seconds
    while True:
        if child.process is not None and child.process.poll() is not None:
            ended_gui(owner, child)
        records = window_state(owner, child, native, windows, relaunching)
        main = [row for row in records if row["width"] >= 500 and row["height"] >= 300]
        selected = [row for row in main if row["visible"] is visible]
        if visible and len(selected) == 1:
            return selected[0]
        if not visible and main and not any(row["visible"] for row in main):
            return main[0]
        if time.monotonic() >= until:
            owner.park("gui-visibility-unresolved-no-replay")
        time.sleep(0.1)


def start_gui(owner, workspace, identity, gui_path, native, windows, relaunching=False):
    owner.guard()
    require(str(Path(gui_path)).casefold() in owner.by_path, "installed-gui-source-pin")
    before = read(owner, workspace, identity, "status")
    child = owner.child("lifecycle-gui", [gui_path, "--state-dir", str(workspace)])
    main = await_window(owner, child, native, windows, True, relaunching=relaunching)
    after = read(owner, workspace, identity, "status")
    require(after["configurationRevision"] == before["configurationRevision"]
            and after["data"] == before["data"], "gui-attach-changed-owner-runtime")
    owner.event("lifecycle-gui-attached", {"actor": gui_record(owner, child, native),
                 "window": main, "controllerId": identity, "fullAcceptance": False})
    return child


def close_window(owner, child, hwnd, native, windows, relaunching=False):
    records = window_state(owner, child, native, windows, relaunching)
    matches = [row for row in records if row["hwnd"] == hwnd and row["visible"]]
    require(len(matches) == 1, "exact-current-visible-window")
    gui_record(owner, child, native)
    require(not getattr(child, "_lifecycle_close_attempted", False), "window-close-already-attempted")
    child._lifecycle_close_attempted = True
    owner.event("lifecycle-wm-close-intent", {"pid": child.pid, "birthFileTimeUtc": child.birth,
                 "windowPid": matches[0]["pid"], "hwnd": hwnd, "oneEffect": True, "replayAllowed": False})
    windows.close(hwnd, matches[0]["pid"])  # One WM_CLOSE only. Close-to-tray may hide, not detach.


def crash_frontend(owner, child, native, relaunching=False):
    """Deliberate frontend termination of the process that runs the GUI.

    That is the JVM a relaunching launcher started, through the very handle that identified
    it, or the launcher's own retained handle when it is its own JVM. The launcher then
    ends with its JVM's code, so the original child's terminal still carries the crash.
    """
    record = gui_record(owner, child, native)
    require(not getattr(child, "_lifecycle_crash_attempted", False), "frontend-crash-already-attempted")
    # Terminate, query and synchronize: the handle that proves the JVM is the one that ends it.
    opened, frontend = relaunched_frontends(owner, child, native, record, 0x101001) if relaunching else ([], None)
    try:
        child._lifecycle_crash_attempted = True
        owner.event("lifecycle-frontend-crash-intent", {"pid": child.pid,
                     "birthFileTimeUtc": child.birth, "originalHandleRetained": True,
                     "frontendJvm": None if frontend is None else frontend[1],
                     "exitCode": CRASH_EXIT, "replayAllowed": False})
        terminate = native.api(native.k, "TerminateProcess", W.BOOL, [W.HANDLE, W.UINT])
        handle = int(child.process._handle) if frontend is None else frontend[0].handle
        if not terminate(handle, CRASH_EXIT):
            owner.park("original-frontend-termination-outcome-unknown")
    finally:
        for process in opened:
            process.__exit__(None, None, None)
    terminal = child.wait()
    require(terminal["exitCode"] == CRASH_EXIT and all(terminal["eof"].values()),
            "original-frontend-crash-terminal")
    owner.event("lifecycle-frontend-crashed", terminal)
    return terminal


def retained_run(owner, launcher, curl, workspace, identity):
    """Strict callback for the existing scheduled read-only collector.

    Collector subprocess timeouts become notices. Its curl --max-time remains an
    in-program network bound; no Popen timeout, termination, or replay occurs.
    """
    ordinal = 0
    prefix = [launcher, "--state-dir", str(workspace), "--json"]
    def run(argv, **options):
        nonlocal ordinal
        require(set(options) == {"capture_output", "text", "timeout"}
                and options["capture_output"] is True and options["text"] is True,
                "scheduled-collector-run-options")
        argv = list(argv)
        if argv[:len(prefix)] == prefix:
            tail = argv[len(prefix):]
            require(tail in (["status"], ["operations", "list"])
                    or len(tail) == 3 and tail[:2] == ["operations", "wait"]
                    and bool(tail[2]), "scheduled-read-command-only")
            argv = prefix + ["--controller-id", identity] + tail
        else:
            require(argv[0] == curl and len(argv) == 13
                    and argv[1:5] == ["--silent", "--show-error", "--fail", "--max-time"]
                    and argv[6:9] == ["--noproxy", "", "--proxy"]
                    and argv[9].startswith("socks5h://127.0.0.1:")
                    and argv[10] == "--cacert" and argv[12].startswith("https://localhost:"),
                    "scheduled-owned-loopback-curl-only")
            socks = re.fullmatch(r"socks5h://127\.0\.0\.1:([0-9]{1,5})", argv[9])
            https = re.fullmatch(r"https://localhost:([0-9]{1,5})/subscription", argv[12])
            require(socks and https and all(1 <= int(match[1]) <= 65535 for match in (socks, https))
                    and str(Path(argv[11])).casefold() in owner.by_path,
                    "scheduled-fixture-endpoint-ca-pins")
        ordinal += 1
        result = owner.child(f"scheduled-read-{ordinal:04d}", argv).completed()
        owner.event("scheduled-retained-read", {"ordinal": ordinal,
                    "observerTimeoutNoticeOnly": options["timeout"], "replayAllowed": False})
        return result
    return run


def observe_existing_gui(owner, workspace, identity, inputs, observer, windows):
    """Read-only target-owner GUI return observation for the installer worker.

    The installer observer admits the target installed tree and exact GUI/owner
    role association. PID/image/token/window observations alone do not establish
    installer completion or GUI content/callback parity.
    """
    require(type(inputs) is dict and set(inputs) == {"schemaVersion", "ownerActor",
            "guiActor", "installedAdmissionArtifactId", "targetOwnerAdmissionArtifactId"}
            and inputs["schemaVersion"] == 1 and all(inputs.get(key) for key in
            ("ownerActor", "guiActor", "installedAdmissionArtifactId", "targetOwnerAdmissionArtifactId")),
            "original-user-gui-return-native-inputs-pending")
    native = observer.WindowsNative()
    for role in ("ownerActor", "guiActor"):
        require(inputs[role]["sid"] == owner.request["context"]["ordinarySid"]
                and inputs[role]["sessionId"] == owner.request["context"]["ordinarySessionId"],
                "original-user-gui-return-principal")
    opening = read(owner, workspace, identity, "status")
    actual_owner = exact_actor(native, inputs["ownerActor"], elevated=False)
    actual_gui = exact_actor(native, inputs["guiActor"], elevated=False)
    records = windows.windows(inputs["guiActor"]["pid"])
    main = [row for row in records if row["visible"] and row["width"] >= 500 and row["height"] >= 300]
    require(len(main) == 1, "returned-target-gui-window-unavailable")
    exact_actor(native, inputs["ownerActor"], elevated=False)
    exact_actor(native, inputs["guiActor"], elevated=False)
    closing = read(owner, workspace, identity, "status")
    require(opening["controllerId"] == closing["controllerId"], "returned-target-owner-epoch-changed")
    owner.event("original-user-gui-return-observed", {"owner": actual_owner,
        "gui": actual_gui, "window": main[0], "status": closing,
        "installedAdmissionArtifactId": inputs["installedAdmissionArtifactId"],
        "targetOwnerAdmissionArtifactId": inputs["targetOwnerAdmissionArtifactId"],
        "readOnly": True, "installerCompletionOrGuiContentProven": False})
    return {"owner": actual_owner, "gui": actual_gui, "window": main[0], "status": closing}


def gui_continuity(owner, workspace, identity, inputs):
    """One finite GUI sequence around an already active admitted proxy runtime.

    It returns with the last GUI and original runtime retained. Its caller owns
    explicit OFF/quit and endpoint/actor cleanup, never an implicit finally kill.
    """
    required = {"schemaVersion", "stateDir", "controllerId", "guiPath", "observerPath",
        "trafficWorkerPath", "trafficInputPath", "runtimeConfigPath", "ownerActor", "runtimeActor",
        "installedAdmissionArtifactId", "fixtureAdmissionArtifactId", "sourceArtifactId",
        "frontendCrashScenario", "fixtureSocksPort", "trayAdmissionArtifactId", "runtimeArtifact"}
    require(type(inputs) is dict and set(inputs) == required and inputs["schemaVersion"] == 1,
            "gui-continuity-input-fields")
    require(all(inputs[key] is not None for key in required)
            and inputs["stateDir"] == str(workspace) and inputs["controllerId"] == identity
            and inputs["frontendCrashScenario"] == "exact-owned-original-gui-handle", "gui-continuity-native-inputs-pending")
    for key in ("guiPath", "observerPath", "trafficWorkerPath", "trafficInputPath"):
        require(str(Path(inputs[key])).casefold() in owner.by_path, "lifecycle-held-input-required")
    observer = owner.module(inputs["observerPath"], "_owned_windows_lifecycle_observer")
    native, windows = observer.WindowsNative(), GuiWindows()
    opening = read(owner, workspace, identity, "status")
    observed_config = LiveConfig(owner, workspace, inputs["runtimeConfigPath"])
    original, config = active(opening), observed_config.initial
    require(original["activeMode"] == "proxy-only", "ordinary-proxy-only-lifecycle-precondition")
    serves = [child for child in owner.children if child.label == "serve"]
    require(len(serves) == 1 and serves[0].pid == inputs["ownerActor"]["pid"]
            and int(serves[0].birth) == inputs["ownerActor"]["creationFileTime"]
            and serves[0].process.poll() is None, "original-retained-serve-role")
    for actor in (inputs["ownerActor"], inputs["runtimeActor"]):
        require(actor["sid"] == owner.request["context"]["ordinarySid"]
                and actor["sessionId"] == owner.request["context"]["ordinarySessionId"],
                "ordinary-proxy-actor-token-role")
    owner_image = str(Path(inputs["ownerActor"]["image"])).casefold()
    require(owner_image in owner.by_path
            and owner.by_path[owner_image].record["sha256"] == inputs["ownerActor"]["sha256"],
            "ordinary-owner-installed-launcher-role")
    artifact = inputs["runtimeArtifact"]
    require(type(artifact) is dict and set(artifact) == {"installedAdmissionArtifactId", "runtimeImagePath", "runtimeSha256"}
            and artifact["installedAdmissionArtifactId"] == inputs["installedAdmissionArtifactId"]
            and Path(artifact["runtimeImagePath"]) == Path(workspace) / "runtime" / "tools" / "sing-box.exe"
            and inputs["runtimeActor"]["image"].casefold() == artifact["runtimeImagePath"].casefold()
            and inputs["runtimeActor"]["sha256"] == artifact["runtimeSha256"]
            and re.fullmatch(r"[a-f0-9]{64}", artifact["runtimeSha256"]),
            "actual-generated-runtime-to-installed-bundled-artifact-role")
    actions = []
    def stable(label):
        owner.guard()
        status = read(owner, workspace, identity, "status")
        require(active(status) == original and status["configurationRevision"] == opening["configurationRevision"]
                and observed_config.snapshot() == config, "gui-action-interrupted-active-runtime")
        exact_actor(native, inputs["ownerActor"], elevated=False)
        exact_actor(native, inputs["runtimeActor"], elevated=False)
        owner.event(label, {"status": status, "runtimeConfig": config,
                           "runtimeActor": inputs["runtimeActor"]})
    stable("lifecycle-opening")
    mixed_port = product_traffic_port(inputs["runtimeConfigPath"], inputs["fixtureSocksPort"])
    traffic = owner.child("lifecycle-traffic", [owner.request["pythonRuntime"]["interpreterPath"],
                          "-I", "-B", inputs["trafficWorkerPath"], "--input", inputs["trafficInputPath"],
                          "--mixed-port", str(mixed_port)])
    raw = owner.root / f"child-{traffic.ordinal:04d}.stdout.raw"
    ready_by = time.monotonic() + 30
    while True:
        require(traffic.process.poll() is None, "traffic-child-ended-before-gui-sequence")
        lines = raw.read_bytes().split(b"\n")[:-1]
        if len(lines) >= 2:
            first = [json.loads(line) for line in lines[:2]]
            require(all(row.get("kind") == "sample" and row.get("succeeded") is True for row in first),
                    "traffic-opening-samples-failed")
            break
        if time.monotonic() >= ready_by:
            owner.park("traffic-opening-not-observed-no-replay")
        time.sleep(0.05)
    def action(label, function):
        require(traffic.process.poll() is None, "traffic-child-ended-before-action")
        started = time.time()
        value = function()
        finished = time.time()
        stable("lifecycle-" + label + "-stable")
        actions.append({"action": label, "startedAt": started, "finishedAt": finished})
        return value
    # The packaged GUI launcher relaunches itself: its JVM owns the windows and is what a crash ends.
    gui = action("attach", lambda: start_gui(owner, workspace, identity, inputs["guiPath"], native, windows, relaunching=True))
    def visibility(visible):
        read(owner, workspace, identity, "gui", "show" if visible else "hide")
        return await_window(owner, gui, native, windows, visible, relaunching=True)
    action("hide", lambda: visibility(False))
    action("show", lambda: visibility(True))
    action("repeat-show", lambda: visibility(True))
    main = await_window(owner, gui, native, windows, True, relaunching=True)
    def close_to_tray():
        close_window(owner, gui, main["hwnd"], native, windows, relaunching=True)
        return await_window(owner, gui, native, windows, False, relaunching=True)
    action("wm-close-to-tray", close_to_tray)
    action("show-after-close", lambda: visibility(True))
    action("frontend-crash", lambda: crash_frontend(owner, gui, native, relaunching=True))
    # Reopened at once, as a user would: its attach retires the held lease of a frontend whose captured process is
    # gone (DesktopControllerOwner.execute). An owner that refuses it ends this as gui-attach-refused-by-owner.
    gui = action("reopen", lambda: start_gui(owner, workspace, identity, inputs["guiPath"], native, windows, relaunching=True))
    terminal = traffic.wait()
    require(terminal["exitCode"] == 0 and all(terminal["eof"].values()), "traffic-original-child-terminal")
    stdout = (owner.root / f"child-{traffic.ordinal:04d}.stdout.raw").read_text(encoding="utf-8")
    stderr = (owner.root / f"child-{traffic.ordinal:04d}.stderr.raw").read_bytes()
    require(not stderr, "traffic-observer-stderr")
    measured = traffic_window(stdout, actions)
    require(all(json.loads(line).get("mixedPort") == mixed_port
                for line in stdout.splitlines() if json.loads(line).get("kind") == "sample"),
            "lifecycle-sampler-product-port-binding")
    stable("lifecycle-closing")
    owner.event("lifecycle-gui-traffic-observed", {"actions": actions, "measuredTraffic": measured,
        "trafficTerminal": terminal, "guiActor": gui_record(owner, gui, native),
        "originalRuntimeStillOwned": True, "cleanupPending": True, "fullAcceptance": False})
    observed_config.close()
    return {"guiChild": gui, "trafficChild": traffic, "measuredTraffic": measured}


def product_traffic_port(config_path, fixture_port):
    """Bind the sampler to the product mixed-in, never directly to its fixture."""
    require(type(fixture_port) is int and 1 <= fixture_port <= 65535,
            "actual-upstream-fixture-port-required")
    with Path(config_path).open("rb") as source:
        raw = source.read(32 * 1024 * 1024 + 1)
    require(len(raw) <= 32 * 1024 * 1024, "product-traffic-config-bound")
    inbounds = json.loads(raw)["inbounds"]
    matches = [row for row in inbounds if row.get("type") == "mixed"
               and row.get("tag") == "mixed-in" and row.get("listen") == "127.0.0.1"]
    require(len(matches) == 1 and type(matches[0].get("listen_port")) is int
            and 1 <= matches[0]["listen_port"] <= 65535
            and matches[0]["listen_port"] != fixture_port,
            "distinct-product-mixed-port-required")
    return matches[0]["listen_port"]


def traffic_window(raw, actions):
    require(raw.endswith("\n"), "traffic-terminal-newline")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) >= 5 and rows[-1].get("kind") == "terminal"
            and all(row.get("kind") == "sample" for row in rows[:-1]), "traffic-full-terminal-stream")
    samples, terminal = rows[:-1], rows[-1]
    require([row["ordinal"] for row in samples] == list(range(len(samples)))
            and terminal["sampleCount"] == len(samples), "traffic-complete-sample-sequence")
    require(terminal["allSamplesSucceeded"] is True and all(row["succeeded"] is True for row in samples),
            "traffic-failed-sample-retained")
    coverage = []
    for action in actions:
        before = [row for row in samples if row["finishedAt"] <= action["startedAt"]]
        during = [row for row in samples if row["startedAt"] <= action["finishedAt"]
                  and row["finishedAt"] >= action["startedAt"]]
        after = [row for row in samples if row["startedAt"] >= action["finishedAt"]]
        require(before and during and after, "traffic-did-not-cover-native-action")
        coverage.append({"action": action["action"], "beforeSamples": len(before),
                         "duringSamples": len(during), "afterSamples": len(after)})
    return {"allSamplesSucceeded": True, "sampleCount": len(samples), "coverage": coverage,
            "maxGapBeforeSeconds": max(row["gapBeforeSeconds"] for row in samples),
            "continuousBytesOrZeroUnsampledLossProven": False}


def scheduled_refresh(owner, workspace, identity, arguments, collector, fixture_admission,
                      original_gui_child, observer):
    """Observe one scheduled refresh only after the retained GUI is confirmed gone.

    Caller has already configured a real subscription, scoped trust and the
    product's >= five-minute refresh interval. No settings or runtime mutations
    occur here. Never call collector.observe with its default subprocess runner.
    """
    require(type(fixture_admission) is str and fixture_admission.startswith("sha256-")
            and len(fixture_admission) == 71, "actual-scheduled-fixture-admission-pending")
    require(original_gui_child in owner.children and original_gui_child.label == "lifecycle-gui"
            and original_gui_child.terminal is not None
            and all(original_gui_child.terminal["eof"].values()), "confirmed-detached-original-gui-required")
    require(all(child.terminal is not None and all(child.terminal["eof"].values())
                for child in owner.children if child.label == "lifecycle-gui"),
            "later-owned-gui-still-live")
    require(arguments.launcher == owner.request["cliPath"] and arguments.state_dir == str(workspace)
            and Path(arguments.evidence_dir).parent == owner.root
            and 0 < arguments.max_duration <= 900, "owned-scheduled-observation-inputs")
    for path in (arguments.launcher, arguments.curl, arguments.ca_file):
        require(str(Path(path)).casefold() in owner.by_path, "scheduled-executable-ca-pins")
    # Readiness is generated only after the fixture child starts, so it cannot
    # be a prelaunch source pin. Its original native immutable data lease is
    # created by runtime_stages.read_ready after atomic fixture publication.
    ready_leases = [lease for lease in getattr(owner, "fixture_data_leases", [])
                    if lease.path == Path(arguments.ready_file) and lease.handle is not None and not lease.directory]
    require(len(ready_leases) == 1, "scheduled-original-generated-readiness-lease")
    ready_leases[0].current()
    opening = read(owner, workspace, identity, "status")
    active(opening)
    native = observer.WindowsNative()
    def absent_gui(label):
        observations = []
        for entry in native.processes():
            if entry["name"].casefold() != ntpath.basename(original_gui_child.argv[0]).casefold():
                continue
            try:
                with native.open_process(entry["pid"], 0x101000) as process:
                    record = process.describe()
                    live = process.wait()
                    require(live in (0, 258), "candidate-gui-wait-unknown")
                    observations.append({"pid": entry["pid"], **record, "waitState": live})
                    require(live == 0 or not observer.same_path(record["image"], original_gui_child.argv[0]),
                            "installed-gui-still-running-during-scheduled-observation")
            except observer.ProcessAbsent:
                observations.append({"pid": entry["pid"], "originalAbsent": True})
        owner.event(label, {"observations": observations, "installedGuiObservedAbsent": True,
                           "observationOnlyAtThisEdge": True})
    absent_gui("scheduled-gui-opening-absence")
    owner.event("scheduled-without-gui-observation-intent", {"fixtureAdmissionArtifactId": fixture_admission,
        "controllerId": identity, "originalGuiTerminal": original_gui_child.terminal,
        "readOnly": True, "replayAllowed": False})
    receipt = collector.observe(arguments, run=retained_run(owner, arguments.launcher,
                                arguments.curl, workspace, identity))
    absent_gui("scheduled-gui-closing-absence")
    owner.guard()
    owner.event("scheduled-without-gui-observation-result", receipt)
    require(receipt.get("result") == "passed" and receipt.get("partial") is False,
            "scheduled-continuity-not-established")
    return receipt


def pending_selection(owner, workspace, identity, pending_selector, runtime_config, native,
                      owner_actor, runtime_actor):
    """A is already active; B is a different committed pending location.

    This finite reversible check never restarts, elevates, or stops A. It proves
    pending selection, idempotent on, and revert to A through real public calls.
    The caller supplies A's original public selector for the final revert.
    """
    require(type(pending_selector) is dict and set(pending_selector) == {"active", "pending"}
            and all(type(value) is str and value for value in pending_selector.values())
            and pending_selector["active"] != pending_selector["pending"], "exact-active-pending-selectors")
    opening = read(owner, workspace, identity, "status")
    original = active(opening)
    observed_config = LiveConfig(owner, workspace, runtime_config)
    config = observed_config.initial
    exact_actor(native, owner_actor, elevated=False)
    exact_actor(native, runtime_actor, elevated=False)
    require(opening["data"]["selectedLocationId"] == original["activeLocationId"]
            and opening["restartRequired"] is False, "initial-active-selection-required")
    def unchanged(label):
        status = read(owner, workspace, identity, "status")
        require(active(status) == original and observed_config.snapshot() == config,
                "pending-change-replaced-active-runtime-or-config")
        exact_actor(native, owner_actor, elevated=False)
        exact_actor(native, runtime_actor, elevated=False)
        owner.event(label, {"status": status, "runtimeConfig": config,
                           "nativeRuntimeActor": runtime_actor})
        return status
    result = json_result(owner.invoke(workspace, "--json", "--controller-id", identity,
        "--if-revision", str(opening["configurationRevision"]), "locations", "select",
        pending_selector["pending"]), identity)
    pending = unchanged("lifecycle-pending-b")
    require(pending["configurationRevision"] == opening["configurationRevision"] + 1
            and result["configurationRevision"] == pending["configurationRevision"]
            and pending["data"]["selectedLocationId"] != original["activeLocationId"]
            and pending["restartRequired"] is True, "pending-b-not-explicit")
    read(owner, workspace, identity, "on")
    idempotent = unchanged("lifecycle-on-idempotent")
    require(idempotent["configurationRevision"] == pending["configurationRevision"]
            and idempotent["restartRequired"] is True, "on-applied-pending-configuration")
    json_result(owner.invoke(workspace, "--json", "--controller-id", identity,
        "--if-revision", str(idempotent["configurationRevision"]), "locations", "select",
        pending_selector["active"]), identity)
    closing = unchanged("lifecycle-reverted-to-active-a")
    require(closing["configurationRevision"] == pending["configurationRevision"] + 1
            and closing["data"]["selectedLocationId"] == original["activeLocationId"]
            and closing["restartRequired"] is False, "revert-to-active-did-not-clear-pending")
    observed_config.close()
    return {"opening": opening, "pending": pending, "closing": closing}


def off_proxy_and_disconnected_serve(owner, workspace, identity, observer, owner_actor, runtime_actor):
    """Explicit OFF of the admitted guest proxy, then persistent-owner checks.

    Does not quit/restart the owner or remove files. Reboot/autostart and next
    owner reconnect remain separate native scenarios after this observation.
    """
    require(not any(item.handle is not None for item in
                    getattr(owner, "lifecycle_config_observations", [])),
            "close-live-config-observations-before-explicit-off")
    native = observer.WindowsNative()
    opening = read(owner, workspace, identity, "status")
    require(active(opening)["activeMode"] == "proxy-only", "explicit-off-owned-proxy-precondition")
    exact_actor(native, owner_actor, elevated=False)
    exact_actor(native, runtime_actor, elevated=False)
    stopped = read(owner, workspace, identity, "off")
    closing = read(owner, workspace, identity, "status")
    require(closing["data"]["runtimeRunning"] is False
            and all(closing["data"][key] is None for key in
                    ("runtimeId", "runtimeStartedAt", "activeLocationId", "activeMode"))
            and closing["restartRequired"] is False, "explicit-off-runtime-state")
    exits = observer.observe_exit([runtime_actor], native)
    require(len(exits) == 1 and exits[0].get("originalAbsent") is True,
            "explicit-off-original-runtime-exit-unproven")
    exact_actor(native, owner_actor, elevated=False)
    with (Path(workspace) / "workspace.json").open("rb") as stream:
        raw = stream.read(64 * 1024 * 1024 + 1)
    require(len(raw) <= 64 * 1024 * 1024
            and json.loads(raw)["resume_connection_on_launch"] is False,
            "explicit-off-durable-intent")
    second = owner.child("lifecycle-second-serve", [owner.request["cliPath"],
                         "--state-dir", str(workspace), "serve"]).completed()
    # The lock is held, so serve adopts the running owner (DesktopExistingService.adopt) and exits 0.
    # Every headless-controller line goes to stderr: DesktopHeadlessController.handleArgs prints through
    # writeDesktopCliLine(System.err, ...), one line ending in LF (native b3d71dca, child 40).
    require(second.returncode == 0 and second.stdout == ""
            and second.stderr == "VPN Control is already running.\n",
            "second-serve-existing-owner-result")
    final = read(owner, workspace, identity, "status")
    require(final["data"] == closing["data"] and final["configurationRevision"] == closing["configurationRevision"],
            "disconnected-serve-or-query-implicitly-reconnected")
    exact_actor(native, owner_actor, elevated=False)
    owner.event("explicit-off-disconnected-serve-observed", {"off": stopped, "closing": final,
        "runtimeExit": exits, "resumeConnectionOnLaunch": False,
        "workspaceSizeBytes": len(raw), "workspaceSha256": hashlib.sha256(raw).hexdigest(),
        "originalOwnerStillLive": True, "rebootOrAutostartProven": False, "cleanupPending": True})
    return {"off": stopped, "closing": final, "runtimeExit": exits}


def _update_probe(owner, workspace, identity, inputs, label):
    require(type(inputs) is dict and set(inputs) == {"schemaVersion", "trafficWorkerPath",
        "trafficInputPath", "fixtureAdmissionArtifactId", "sourceArtifactId"}
        and inputs["schemaVersion"] == 1 and all(inputs[key] for key in inputs),
        "update-traffic-native-inputs-pending")
    for role in ("trafficWorkerPath", "trafficInputPath"):
        require(str(Path(inputs[role])).casefold() in owner.by_path, "update-traffic-held-source-input")
    status = read(owner, workspace, identity, "status")
    runtime = active(status)
    # Observe the new epoch's actual listener. A previous epoch's mixed port is
    # never reused by assumption after an installer/restart.
    with (Path(workspace) / "runtime-config.json").open("rb") as stream:
        config = stream.read(32 * 1024 * 1024 + 1)
    require(len(config) <= 32 * 1024 * 1024, "update-runtime-config-bound")
    inbounds = json.loads(config)["inbounds"]
    matches = [item for item in inbounds if item.get("type") == "mixed"
               and item.get("tag") == "mixed-in" and item.get("listen") == "127.0.0.1"]
    require(len(matches) == 1 and type(matches[0].get("listen_port")) is int
            and 1 <= matches[0]["listen_port"] <= 65535, "update-actual-mixed-listener")
    port = matches[0]["listen_port"]
    child = owner.child("update-traffic-" + label, [owner.request["pythonRuntime"]["interpreterPath"],
        "-I", "-B", inputs["trafficWorkerPath"], "--input", inputs["trafficInputPath"],
        "--mixed-port", str(port)])
    terminal = child.wait()
    require(terminal["exitCode"] == 0 and all(terminal["eof"].values()), "update-traffic-original-child-terminal")
    raw = (owner.root / f"child-{child.ordinal:04d}.stdout.raw").read_text(encoding="utf-8")
    error = (owner.root / f"child-{child.ordinal:04d}.stderr.raw").read_bytes()
    require(not error, "update-traffic-stderr")
    measured = traffic_window(raw, [])
    rows = [json.loads(line) for line in raw.splitlines()]
    require(all(row.get("mixedPort") == port for row in rows[:-1]), "update-traffic-port-binding")
    closing = read(owner, workspace, identity, "status")
    require(active(closing) == runtime and closing["configurationRevision"] == status["configurationRevision"],
            "update-probe-runtime-epoch-changed")
    owner.event("update-traffic-" + label + "-observed", {"status": closing, "mixedPort": port,
        "runtimeConfigSha256": hashlib.sha256(config).hexdigest(), "traffic": measured,
        "terminal": terminal, "fixtureAdmissionArtifactId": inputs["fixtureAdmissionArtifactId"],
        "handoffContinuityOrExactDowntimeProven": False})
    return {"child": child, "identity": identity, "runtime": runtime, "mixedPort": port,
            "measured": measured, "terminal": terminal}


def prepare_update_traffic(owner, workspace, identity, traffic_inputs):
    """Connected pre-update proof. A short, independently admitted input is required."""
    return _update_probe(owner, workspace, identity, traffic_inputs, "before")


def verify_update_traffic(owner, workspace, new_identity, traffic_inputs):
    """Connected target-owner proof after the updater has admitted that new owner."""
    return _update_probe(owner, workspace, new_identity, traffic_inputs, "after")


def cleanup_update_traffic(owner, *observations):
    """Only verify original sampler closure; never stop an owner, VPN, or fixture."""
    require(1 <= len(observations) <= 2, "finite-update-traffic-observations")
    for observation in observations:
        child = observation["child"]
        require(child in owner.children and child.label in {"update-traffic-before", "update-traffic-after"}
                and child.terminal == observation["terminal"] and child.terminal is not None
                and all(child.terminal["eof"].values()), "update-traffic-original-closure")
    owner.event("update-traffic-original-children-closed", {"children": [item["terminal"] for item in observations],
        "fixtureOrProductStopped": False, "fixtureCleanupStillOwnedByCaller": True})
