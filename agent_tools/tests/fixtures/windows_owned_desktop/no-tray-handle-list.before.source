"""One owned no-shell desktop; no Explorer/default-desktop process is stopped.

The small Owner.Child startupinfo seam is proposed privately. Native use requires the
exact retained lease's sole inheritable desktop handle in Popen handle_list.
Python 3.13 does not forward a dynamically attached STARTUPINFO.lpDesktop field.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
import hashlib
import inspect
import subprocess
import time
import uuid


def require(value, reason):
    if not value:
        raise AssertionError(reason)


class Attributes(ctypes.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


class OwnedNoTrayDesktop:
    ACCESS = 0x00020000 | 0x0001 | 0x0002 | 0x0004 | 0x0040 | 0x0080 | 0x0100
    def __init__(self, owner, gui_path, workspace, startup_kind="normal"):
        require(startup_kind in {"normal", "autostart"} and str(workspace) == owner.request["workspace"]
                and str(gui_path).casefold() in owner.by_path, "owned-no-tray-launch-scope")
        self.owner, self.gui_path, self.workspace, self.startup_kind = owner, gui_path, str(workspace), startup_kind
        self.handle = self.original = self.child = None
        self.used = self.switched = False
        self.name = "VcParityNoTray-" + uuid.uuid4().hex
        if not hasattr(owner, "no_tray_desktop_leases"):
            owner.no_tray_desktop_leases = []
        owner.no_tray_desktop_leases.append(self)  # Custody precedes native opens.
        owner.guard()
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        def api(library, name, result, arguments):
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments
            return function
        self.open_input = api(self.user, "OpenInputDesktop", W.HANDLE, [W.DWORD, W.BOOL, W.DWORD])
        self.open_desktop = api(self.user, "OpenDesktopW", W.HANDLE, [W.LPCWSTR, W.DWORD, W.BOOL, W.DWORD])
        self.close_desktop = api(self.user, "CloseDesktop", W.BOOL, [W.HANDLE])
        self.switch_desktop = api(self.user, "SwitchDesktop", W.BOOL, [W.HANDLE])
        self.get_thread = api(self.user, "GetThreadDesktop", W.HANDLE, [W.DWORD])
        self.set_thread = api(self.user, "SetThreadDesktop", W.BOOL, [W.HANDLE])
        self.thread_id = api(self.kernel, "GetCurrentThreadId", W.DWORD, [])()
        self.get_station = api(self.user, "GetProcessWindowStation", W.HANDLE, [])
        self.get_info = api(self.user, "GetUserObjectInformationW", W.BOOL,
            [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)])
        self.get_security = api(self.user, "GetUserObjectSecurity", W.BOOL,
            [W.HANDLE, ctypes.POINTER(W.DWORD), W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)])
        self.create = api(self.user, "CreateDesktopW", W.HANDLE,
            [W.LPCWSTR, W.LPCWSTR, W.LPVOID, W.DWORD, W.DWORD, ctypes.POINTER(Attributes)])
        convert = api(self.adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL,
            [W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD)])
        free = api(self.kernel, "LocalFree", W.HANDLE, [W.HANDLE])
        require(self.object_name(self.get_station()) == "WinSta0", "ordinary-interactive-window-station")
        self.original = self.open_input(0, False, 0x00020000 | 0x0001 | 0x0100)
        require(self.original and self.object_name(self.original) == "Default", "original-default-input-desktop-required")
        require(self.object_name(self.get_thread(self.thread_id)) == "Default", "original-owned-calling-thread-desktop")
        probe = self.open_desktop(self.name, 0, False, 0x0001)
        if probe:
            self.close_desktop(probe)
            raise AssertionError("new-no-tray-desktop-name-already-exists")
        require(ctypes.get_last_error() == 2, "no-tray-desktop-absence-unknown")
        descriptor = W.LPVOID()
        sid = owner.request["context"]["ordinarySid"]
        sddl = "O:" + sid + "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
        require(bool(convert(sddl, 1, ctypes.byref(descriptor), None)), "private-desktop-security-descriptor")
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, True)
        owner.event("no-tray-desktop-create-intent", {"name": self.name, "ordinarySid": sid,
            "ordinarySessionId": owner.request["context"]["ordinarySessionId"], "sddl": sddl,
            "existingExplorerOrDesktopStopped": False, "replayAllowed": False})
        try:
            self.handle = self.create(self.name, None, None, 0, self.ACCESS, ctypes.byref(attributes))
            require(bool(self.handle), "owned-private-desktop-create")
        finally:
            require(not free(descriptor), "private-desktop-security-buffer-release")
        current_thread = self.object_name(self.get_thread(self.thread_id))
        require(current_thread in {self.name, "Default"}, "owned-calling-thread-desktop-after-create")
        if current_thread == self.name:
            require(bool(self.set_thread(self.original)), "restore-owned-calling-thread-desktop")
        require(self.object_name(self.get_thread(self.thread_id)) == "Default", "owned-calling-thread-default-restored")
        self.security = self.security_bytes(self.handle)
        self.current()

    def object_name(self, handle):
        text, needed = ctypes.create_unicode_buffer(256), W.DWORD()
        require(bool(self.get_info(handle, 2, text, ctypes.sizeof(text), ctypes.byref(needed)))
                and 0 < needed.value <= ctypes.sizeof(text), "desktop-object-name")
        return text.value

    def security_bytes(self, handle):
        information, needed = W.DWORD(5), W.DWORD()
        self.get_security(handle, ctypes.byref(information), None, 0, ctypes.byref(needed))
        require(0 < needed.value <= 65536, "desktop-security-bound")
        data = ctypes.create_string_buffer(needed.value)
        require(bool(self.get_security(handle, ctypes.byref(information), data, len(data), ctypes.byref(needed))),
                "desktop-security-observation")
        return data.raw[:needed.value]

    def current(self):
        self.owner.guard()
        require(self.handle and self.object_name(self.handle) == self.name
                and self.security_bytes(self.handle) == self.security, "original-private-desktop-changed")

    def startup_info(self, owner, label, argv):
        self.current()
        expected = [self.gui_path, *( ["--autostart"] if self.startup_kind == "autostart" else []),
                    "--state-dir", self.workspace]
        require(owner is self.owner and self in owner.no_tray_desktop_leases and not self.used
                and label == "lifecycle-gui" and list(argv) == expected, "closed-no-tray-child-role")
        self.used = True  # Consume before the first possible CreateProcess.
        self.owner.event("no-tray-gui-child-intent", {"desktop": self.name,
            "desktopSecuritySha256": hashlib.sha256(self.security).hexdigest(),
            "onlyInheritedDesktop": int(self.handle), "startupKind": self.startup_kind,
            "replayAllowed": False})
        return subprocess.STARTUPINFO(lpAttributeList={"handle_list": [int(self.handle)]})

    def child_started(self, child):
        require(self.used and self.child is None and child in self.owner.children
                and child.owner is self.owner and child.label == "lifecycle-gui"
                and child.process is not None and child.process.poll() is None
                and child.pid == child.process.pid and child.birth is not None
                and self.owner.native.birth(int(child.process._handle)) == child.birth,
                "original-no-tray-gui-child")
        self.child = child
        self.current()

    def observe_assigned_window(self, child, hwnd, native, cases, *, require_foreground=False):
        """Observe a real GUI window after readiness; never close its borrowed HDESK.

        No input is performed or admitted here. The input backend must independently
        bind a current frame/control/geometry before any keyboard or pointer action.
        A zero/foreign foreground observation is retained truthfully unless the
        caller explicitly requires the GUI to be foreground.
        """
        require(type(require_foreground) is bool and type(hwnd) is int and 0 < hwnd < 2**64,
                "owned-desktop-window-observation-shape")
        self.current()
        require(self.child is child and child.owned_desktop is self and self.used
                and self.input_name() in {"Default", self.name}, "owned-desktop-original-current-gui")
        input_desktop = self.input_name()
        opening = cases.gui_record(self.owner, child, native)
        rows = desktop_windows(self, native)
        require(all(row["pid"] == child.pid for row in rows), "unowned-process-window-on-private-desktop")
        selected = [row for row in rows if row["hwnd"] == hwnd and row["pid"] == child.pid]
        require(len(selected) == 1, "original-window-not-on-held-desktop")
        window_pid = native.api(self.user, "GetWindowThreadProcessId", W.DWORD,
                               [W.HWND, ctypes.POINTER(W.DWORD)])
        get_rect = native.api(self.user, "GetWindowRect", W.BOOL, [W.HWND, ctypes.POINTER(W.RECT)])
        is_visible = native.api(self.user, "IsWindowVisible", W.BOOL, [W.HWND])
        get_metric = native.api(self.user, "GetSystemMetrics", ctypes.c_int, [ctypes.c_int])
        get_dpi = native.api(self.user, "GetDpiForWindow", W.UINT, [W.HWND])
        get_window_context = native.api(self.user, "GetWindowDpiAwarenessContext", W.HANDLE, [W.HWND])
        get_thread_context = native.api(self.user, "GetThreadDpiAwarenessContext", W.HANDLE, [])
        get_awareness = native.api(self.user, "GetAwarenessFromDpiAwarenessContext", ctypes.c_int, [W.HANDLE])
        get_foreground = native.api(self.user, "GetForegroundWindow", W.HWND, [])
        current_thread = native.api(self.kernel, "GetCurrentThreadId", W.DWORD, [])()
        require(current_thread == self.thread_id, "owned-desktop-observer-thread-changed")
        pid = W.DWORD()
        thread = window_pid(hwnd, ctypes.byref(pid))
        require(thread and pid.value == child.pid and selected[0]["threadId"] == thread,
                "owned-desktop-window-original-process")
        borrowed = self.get_thread(thread)
        require(borrowed and self.object_name(borrowed) == self.name, "owned-gui-thread-desktop-mismatch")
        rect = W.RECT()
        require(bool(get_rect(hwnd, ctypes.byref(rect))) and bool(is_visible(hwnd)),
                "owned-gui-window-visible-geometry")
        window_context, observer_context = get_window_context(hwnd), get_thread_context()
        require(window_context and observer_context, "owned-desktop-dpi-awareness-unavailable")
        screen = {"logicalWidth": get_metric(0), "logicalHeight": get_metric(1), "windowDpi": get_dpi(hwnd),
            "windowAwareness": get_awareness(window_context), "observerAwareness": get_awareness(observer_context)}
        require((screen["logicalWidth"], screen["logicalHeight"], screen["windowDpi"]) == (1280, 800, 96)
                and screen["windowAwareness"] in {1, 2} and screen["observerAwareness"] in {0, 1, 2},
                "owned-desktop-unsupported-display-geometry")
        require(0 < rect.right - rect.left <= 1280 + 32 and 0 < rect.bottom - rect.top <= 800 + 32
                and rect.left < 1280 and rect.top < 800 and rect.right > 0 and rect.bottom > 0,
                "owned-desktop-window-geometry-unavailable")
        foreground = get_foreground()
        foreground_pid = W.DWORD()
        foreground_thread = window_pid(foreground, ctypes.byref(foreground_pid)) if foreground else 0
        require(not foreground or foreground_thread, "owned-desktop-foreground-identity-unavailable")
        caller_desktop = self.object_name(self.get_thread(current_thread))
        foreground_qualified = bool(caller_desktop == self.name and input_desktop == self.name and foreground
            and any(row["hwnd"] == foreground and row["pid"] == foreground_pid.value
                    and row["threadId"] == foreground_thread for row in rows))
        if require_foreground:
            require(foreground_qualified and foreground == hwnd and foreground_pid.value == child.pid,
                    "owned-desktop-gui-foreground-unobserved")
        closing_pid = W.DWORD()
        closing_thread = window_pid(hwnd, ctypes.byref(closing_pid))
        require(closing_pid.value == child.pid and closing_thread == thread
                and self.object_name(self.get_thread(closing_thread)) == self.name,
                "owned-desktop-window-closing-identity-changed")
        closing_rows = desktop_windows(self, native)
        require(all(row["pid"] == child.pid for row in closing_rows)
                and len([row for row in closing_rows if row["hwnd"] == hwnd
                         and row["threadId"] == thread]) == 1,
                "owned-desktop-window-closing-census-changed")
        closing = cases.gui_record(self.owner, child, native)
        self.current()
        require(self.input_name() == input_desktop, "owned-desktop-input-context-changed")
        value = {"child": child.ordinal, "pid": child.pid, "birthFileTimeUtc": child.birth,
            "hwnd": hwnd, "guiThreadId": thread, "desktop": self.name,
            "inputDesktop": input_desktop, "ownedDesktopIsInput": input_desktop == self.name,
            "desktopSecuritySha256": hashlib.sha256(self.security).hexdigest(),
            "windowRect": {"left": rect.left, "top": rect.top, "right": rect.right, "bottom": rect.bottom},
            "display": screen, "physicalDisplayQualified": False,
            "foreground": {"hwnd": foreground or None,
                "pid": foreground_pid.value or None, "threadId": foreground_thread or None,
                "callerDesktop": caller_desktop, "ownedDesktopQualified": foreground_qualified},
            "actorOpening": opening, "actorClosing": closing,
            "readOnly": True, "inputQualified": False, "uiaControlQualified": False}
        self.owner.event("owned-desktop-gui-assignment-observed", value)
        return value

    def input_name(self):
        handle = self.open_input(0, False, 0x0001)
        require(bool(handle), "current-input-desktop-observation")
        try:
            return self.object_name(handle)
        finally:
            require(bool(self.close_desktop(handle)), "input-desktop-observer-close")

    def show(self):
        self.current()
        require(not self.switched and self.input_name() == "Default", "default-desktop-before-private-switch")
        self.switched = True  # Unknown switch is not replayed.
        self.owner.event("private-desktop-switch-intent", {"name": self.name, "replayAllowed": False})
        if not self.switch_desktop(self.handle):
            self.owner.park("private-desktop-switch-outcome-unknown")
        require(self.input_name() == self.name, "private-desktop-not-observed-current")

    def restore(self):
        self.current()
        observed = self.input_name()
        require(observed in {self.name, "Default"}, "foreign-input-desktop-do-not-switch")
        if observed == self.name:
            self.owner.event("original-default-desktop-restore-intent", {"from": self.name, "replayAllowed": False})
            if not self.switch_desktop(self.original):
                self.owner.park("default-desktop-restore-outcome-unknown")
        require(self.input_name() == "Default", "original-default-desktop-restore-unproven")

    def close(self):
        self.current()
        require(self.child is not None and self.child.terminal is not None
                and all(self.child.terminal["eof"].values()) and self.input_name() == "Default",
                "original-gui-terminal-and-default-restore-before-desktop-close")
        require(bool(self.close_desktop(self.handle)) and bool(self.close_desktop(self.original)),
                "owned-private-desktop-original-handle-close")
        self.handle = self.original = None


def desktop_windows(lease, native):
    lease.current()
    callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    enumerate_windows = native.api(lease.user, "EnumDesktopWindows", W.BOOL,
                                  [W.HANDLE, callback_type, W.LPARAM])
    class_name = native.api(lease.user, "GetClassNameW", ctypes.c_int, [W.HWND, W.LPWSTR, ctypes.c_int])
    process_id = native.api(lease.user, "GetWindowThreadProcessId", W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)])
    rows, errors = [], []
    def visit(hwnd, _):
        if len(rows) >= 256:
            errors.append("window-count-bound")
            return False
        text, pid = ctypes.create_unicode_buffer(256), W.DWORD()
        thread = process_id(hwnd, ctypes.byref(pid))
        if not class_name(hwnd, text, len(text)) or not thread:
            errors.append(ctypes.get_last_error())
            return False
        rows.append({"hwnd": int(hwnd), "pid": pid.value, "threadId": thread, "class": text.value})
        return True
    callback = callback_type(visit)
    require(bool(enumerate_windows(lease.handle, callback, 0)) and not errors, "owned-desktop-window-census")
    require(not any(row["class"] in {"Shell_TrayWnd", "Shell_SecondaryTrayWnd"} for row in rows),
            "owned-desktop-has-tray-host")
    lease.current()
    return rows


def require_child_api(owner):
    require("owned_desktop" in inspect.signature(owner.child).parameters,
            "OWNED_DESKTOP_CHILD_API_MISSING: Child.__init__ must pass retained lease.startup_info into Popen and call child_started")


def no_tray_close_case(owner, state, inputs, cases, observer):
    """Real no-tray WM_CLOSE detach on an owned private desktop, runtime A intact."""
    require(type(inputs) is dict and set(inputs) == {"guiPath", "trafficWorkerPath", "trafficInputPath", "startupKind"}
            and all(inputs[key] is not None for key in inputs), "no-tray-native-inputs-pending")
    require_child_api(owner)  # Refuse the missing seam before any native mutation.
    require(all(child.terminal is not None for child in owner.children if child.label == "lifecycle-gui"),
            "prior-original-gui-must-be-closed")
    workspace, identity = state["workspace"], state["identity"]
    opening = cases.read(owner, workspace, identity, "status")
    active = cases.active(opening)
    mixed = cases.product_traffic_port(str(workspace / "runtime-config.json"), state["ready"]["advertisedSocksPort"])
    for name in ("trafficWorkerPath", "trafficInputPath"):
        require(inputs[name].casefold() in owner.by_path, "no-tray-traffic-held-source-input")
    traffic = owner.child("no-tray-traffic", [owner.request["pythonRuntime"]["interpreterPath"], "-I", "-B",
        inputs["trafficWorkerPath"], "--input", inputs["trafficInputPath"], "--mixed-port", str(mixed)])
    source = owner.root / f"child-{traffic.ordinal:04d}.stdout.raw"
    until = time.monotonic() + 30
    while len(source.read_bytes().split(b"\n")[:-1]) < 2:
        require(traffic.process.poll() is None, "no-tray-traffic-ended-before-ready")
        if time.monotonic() >= until:
            owner.park("no-tray-traffic-readiness-unknown")
        time.sleep(0.05)
    native = observer.WindowsNative()
    lease = OwnedNoTrayDesktop(owner, inputs["guiPath"], workspace, inputs["startupKind"])
    require(desktop_windows(lease, native) == [], "new-owned-desktop-must-have-no-foreign-windows")
    argv = [inputs["guiPath"], *( ["--autostart"] if inputs["startupKind"] == "autostart" else []),
            "--state-dir", str(workspace)]
    gui = owner.child("lifecycle-gui", argv, owned_desktop=lease)
    require(lease.child is gui, "original-owned-desktop-child-join")
    ordinary_windows = cases.GuiWindows()
    class PrivateWindows:
        def windows(self, pid):
            rows = []
            for row in desktop_windows(lease, native):
                if row["pid"] != pid:
                    raise AssertionError("unowned-process-window-on-private-desktop")
                rect = W.RECT()
                require(bool(ordinary_windows.user.GetWindowRect(row["hwnd"], ctypes.byref(rect))), "private-window-rect")
                rows.append({**row, "visible": bool(ordinary_windows.user.IsWindowVisible(row["hwnd"])),
                             "width": rect.right - rect.left, "height": rect.bottom - rect.top})
            return rows
        def close(self, hwnd, pid):
            ordinary_windows.close(hwnd, pid)
    windows = PrivateWindows()
    main = cases.await_window(owner, gui, native, windows, True)
    lease.observe_assigned_window(gui, main["hwnd"], native, cases)
    lease.show()
    require(lease.input_name() == lease.name, "owned-desktop-after-switch-observation")
    lease.observe_assigned_window(gui, main["hwnd"], native, cases)
    owner.event("no-tray-visible-frontend-observed", {"actor": cases.gui_record(owner, gui, native),
        "desktop": lease.name, "window": main, "trayHostWindows": [], "startupKind": inputs["startupKind"]})
    started = time.time()
    cases.close_window(owner, gui, main["hwnd"], native, windows)
    terminal = gui.wait()
    require(terminal["exitCode"] == 0 and all(terminal["eof"].values()), "no-tray-graceful-original-gui-detach")
    time.sleep(0.4)
    finished = time.time()
    closing = cases.read(owner, workspace, identity, "status")
    require(cases.active(closing) == active and closing["configurationRevision"] == opening["configurationRevision"],
            "no-tray-close-stopped-owner-or-runtime")
    lease.restore()
    lease.close()
    traffic_terminal = traffic.wait()
    require(traffic_terminal["exitCode"] == 0 and all(traffic_terminal["eof"].values()), "no-tray-original-traffic-terminal")
    raw = source.read_text(encoding="utf-8")
    measured = cases.traffic_window(raw, [{"action": "no-tray-close-detach", "startedAt": started, "finishedAt": finished}])
    owner.event("no-tray-close-detach-observed", {"guiTerminal": terminal, "traffic": measured,
        "closingStatus": closing, "originalDefaultDesktopRestored": True,
        "explorerOrUnrelatedProcessStopped": False, "fullAcceptance": False})
    return {"gui": gui, "traffic": traffic, "terminal": terminal, "measuredTraffic": measured}
