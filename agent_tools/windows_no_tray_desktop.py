"""One owned no-shell desktop and the no-tray close row; no Explorer/default-desktop process is stopped.

Python's subprocess cannot name a desktop. The Owner's Child starts the one GUI child of a retained lease
through its CreateProcessW path (windows_ordinary_process_owner.DesktopProcess) with STARTUPINFO.lpDesktop
"WinSta0\\<name>", which desktop_for_child hands it for the closed argv only: the installed GUI with
--state-dir. A relaunched jpackage launcher's JVM inherits that desktop. Window messages pass only between
threads of one desktop, so the one WM_CLOSE, like every read of this desktop's windows, runs on a fresh
owner thread that SetThreadDesktop put there.

windows-proxy-lifecycle.no-tray-close (DESKTOP-002) reads from the product source:
- Main.kt: a window close hides the window when trayWindowState.canHideToTray (traySupported and
  trayAvailable), and otherwise detaches the frontend, which exits 0 after its teardown released the owner's
  lease (finishDesktopFrontendProcess). With canHideToTray false the frontend answers gui hide UNSUPPORTED
  and changes nothing.
- DesktopTray.kt: on Windows the tray is supported when AWT says so and available once AWT takes the icon
  (AwtTrayHandle.installTrayIcon). A refused icon is retried every TrayInstallRetryDelayMillis up to
  TrayInstallMaxAttempts, then reported unavailable, so the decision is final SETTLE_SECONDS after the window.
- DesktopGuiVisibilityControl answers gui hide NOT_FOUND when the owner holds no frontend; status has no
  frontend field. DesktopOwnerFrontendLifecycle drops a lease nobody released only LEASE_MILLIS after its last
  heartbeat, and a frontend's teardown releases it at once (DesktopGuiOwnerConnection.closeAndDetach).
The private desktop has no Shell_TrayWnd. A product that still decides it has a tray hides a closed window
into none: that GUI is live and invisible, and the row fails gui-hidden-without-usable-tray.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
import hashlib
import inspect
import json
import ntpath
import threading
import time
import uuid


INPUT_FIELDS = frozenset({"schemaVersion", "guiPath", "trafficWorkerPath", "trafficInputPath", "installedAdmissionArtifactId",
                          "fixtureAdmissionArtifactId"})
GUI_LEAF = "vpn-control.exe"
SETTLE_SECONDS = 75  # TrayInstallMaxAttempts x TrayInstallRetryDelayMillis is 60 s; the rest is the JVM's slack.
WINDOW_SECONDS = 60  # A JVM started cold on the private desktop shows its window within this, or the row parks.
EXIT_SECONDS = 30  # A detached frontend's teardown and exit after its close.
# DesktopOwnerFrontendLifecycle.LEASE_MILLIS and the heartbeatMillis of DesktopGuiOwnerConnection.connect. A live
# frontend touched its lease at most one heartbeat before the close was posted, so a lease nobody released is still
# held until LEASE - HEARTBEAT after the post: only an earlier NOT_FOUND is a lease the close released.
LEASE_SECONDS, HEARTBEAT_SECONDS = 15, 5
RELEASE_SECONDS = LEASE_SECONDS - HEARTBEAT_SECONDS - 1
POLL_SECONDS = 1.0
DESKTOP_THREAD_SECONDS = 120
WM_CLOSE = 0x0010
MAIN_WIDTH, MAIN_HEIGHT = 500, 300  # As windows_lifecycle_cases.await_window tells a main window from AWT's others.
TRAY_HOSTS = frozenset({"Shell_TrayWnd", "Shell_SecondaryTrayWnd"})
INVALID_WINDOW = 1400  # ERROR_INVALID_WINDOW_HANDLE: the window was destroyed while its list was read.
RUNTIME_KEYS = ("runtimeRunning", "runtimeId", "runtimeStartedAt", "activeLocationId", "activeMode", "selectedLocationId")


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def win32(value, reason):
    """require for the result of a Win32 call: the refusal carries this thread's last error for the owner's records."""
    if not value:
        error = AssertionError(reason)
        error.winerror = ctypes.get_last_error()
        raise error


class Attributes(ctypes.Structure):
    _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]


class OwnedNoTrayDesktop:
    ACCESS = 0x00020000 | 0x0001 | 0x0002 | 0x0004 | 0x0040 | 0x0080 | 0x0100
    def __init__(self, owner, gui_path, workspace):
        require(str(workspace) == owner.request["workspace"] and str(gui_path).casefold() in owner.by_path
                and ntpath.basename(str(gui_path)).casefold() == GUI_LEAF, "owned-no-tray-launch-scope")
        self.owner, self.gui_path, self.workspace = owner, str(gui_path), str(workspace)
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
        win32(bool(self.original), "original-default-input-desktop-required")
        require(self.object_name(self.original) == "Default", "original-default-input-desktop-required")
        require(self.object_name(self.get_thread(self.thread_id)) == "Default", "original-owned-calling-thread-desktop")
        probe = self.open_desktop(self.name, 0, False, 0x0001)
        if probe:
            self.close_desktop(probe)
            raise AssertionError("new-no-tray-desktop-name-already-exists")
        require(ctypes.get_last_error() == 2, "no-tray-desktop-absence-unknown")
        descriptor = W.LPVOID()
        sid = owner.request["context"]["ordinarySid"]
        sddl = "O:" + sid + "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")"
        win32(bool(convert(sddl, 1, ctypes.byref(descriptor), None)), "private-desktop-security-descriptor")
        # Not inheritable: the GUI child is put here by name, and inherits its three standard handles alone.
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        owner.event("no-tray-desktop-create-intent", {"name": self.name, "ordinarySid": sid,
            "ordinarySessionId": owner.request["context"]["ordinarySessionId"], "sddl": sddl,
            "existingExplorerOrDesktopStopped": False, "replayAllowed": False})
        try:
            self.handle = self.create(self.name, None, None, 0, self.ACCESS, ctypes.byref(attributes))
            win32(bool(self.handle), "owned-private-desktop-create")
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
        win32(bool(self.get_info(handle, 2, text, ctypes.sizeof(text), ctypes.byref(needed)))
              and 0 < needed.value <= ctypes.sizeof(text), "desktop-object-name")
        return text.value

    def security_bytes(self, handle):
        information, needed = W.DWORD(5), W.DWORD()
        self.get_security(handle, ctypes.byref(information), None, 0, ctypes.byref(needed))
        require(0 < needed.value <= 65536, "desktop-security-bound")
        data = ctypes.create_string_buffer(needed.value)
        win32(bool(self.get_security(handle, ctypes.byref(information), data, len(data), ctypes.byref(needed))),
              "desktop-security-observation")
        return data.raw[:needed.value]

    def current(self):
        self.owner.guard()
        require(self.handle and self.object_name(self.handle) == self.name
                and self.security_bytes(self.handle) == self.security, "original-private-desktop-changed")

    def desktop_for_child(self, owner, label, argv):
        """The lpDesktop of this lease's one GUI child, for its closed argv only; consumed before CreateProcessW."""
        self.current()
        require(owner is self.owner and any(held is self for held in owner.no_tray_desktop_leases) and not self.used
                and label == "lifecycle-gui" and list(argv) == [self.gui_path, "--state-dir", self.workspace],
                "closed-no-tray-child-role")
        self.used = True  # Consume before the first possible CreateProcessW.
        desktop = "WinSta0\\" + self.name
        self.owner.event("no-tray-gui-child-intent", {"desktop": self.name, "lpDesktop": desktop, "argv": list(argv),
            "desktopSecuritySha256": hashlib.sha256(self.security).hexdigest(),
            "inheritedHandles": ["stdin", "stdout", "stderr"], "replayAllowed": False})
        return desktop

    def child_started(self, child):
        require(self.used and self.child is None and child in self.owner.children
                and child.owner is self.owner and child.label == "lifecycle-gui"
                and child.process is not None and child.process.poll() is None
                and child.pid == child.process.pid and child.birth is not None
                and self.owner.native.birth(int(child.process._handle)) == child.birth,
                "original-no-tray-gui-child")
        self.child = child
        self.current()

    def on_desktop(self, native, function):
        """function() on a fresh owner thread that SetThreadDesktop put on this desktop; its value or its error.

        A fresh thread owns no window or hook, so the switch is allowed; the thread ends with function.
        """
        self.current()
        outcome = {}
        def body():
            try:
                thread = native.api(self.kernel, "GetCurrentThreadId", W.DWORD, [])()
                require(thread != self.thread_id, "no-tray-desktop-thread-switch")
                win32(bool(self.set_thread(self.handle)), "no-tray-desktop-thread-switch")
                require(self.object_name(self.get_thread(thread)) == self.name, "no-tray-desktop-thread-not-private")
                outcome["value"] = function()
            except BaseException as error:
                outcome["error"] = error
        worker = threading.Thread(target=body, name="no-tray-desktop-" + uuid.uuid4().hex[:8], daemon=False)
        worker.start()
        worker.join(DESKTOP_THREAD_SECONDS)
        if worker.is_alive():
            self.owner.park("no-tray-desktop-thread-outcome-unknown")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]

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
        win32(bool(handle), "current-input-desktop-observation")
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
        """Both desktop handles, once the one GUI child is terminal or none was ever started, and a switch restored."""
        self.current()
        require((self.child is None and not self.used or self.child is not None and self.child.terminal is not None
                 and all(self.child.terminal["eof"].values())) and (not self.switched or self.input_name() == "Default"),
                "original-gui-terminal-and-default-restore-before-desktop-close")
        win32(bool(self.close_desktop(self.handle)) and bool(self.close_desktop(self.original)),
              "owned-private-desktop-original-handle-close")
        self.handle = self.original = None


def desktop_windows(lease, native, geometry=False):
    lease.current()
    callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    enumerate_windows = native.api(lease.user, "EnumDesktopWindows", W.BOOL,
                                  [W.HANDLE, callback_type, W.LPARAM])
    class_name = native.api(lease.user, "GetClassNameW", ctypes.c_int, [W.HWND, W.LPWSTR, ctypes.c_int])
    process_id = native.api(lease.user, "GetWindowThreadProcessId", W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)])
    if geometry:
        get_rect = native.api(lease.user, "GetWindowRect", W.BOOL, [W.HWND, ctypes.POINTER(W.RECT)])
        is_visible = native.api(lease.user, "IsWindowVisible", W.BOOL, [W.HWND])
    rows, errors = [], []
    def read_window(hwnd):
        if len(rows) >= 256:
            errors.append("window-count-bound")
            return False
        text, pid, rect, visible = ctypes.create_unicode_buffer(256), W.DWORD(), W.RECT(), None
        thread = process_id(hwnd, ctypes.byref(pid))
        read = bool(thread) and bool(class_name(hwnd, text, len(text)))
        if read and geometry:
            # The rectangle is read after the visibility bit: a window still there for it had that bit.
            visible = bool(is_visible(hwnd))
            read = bool(get_rect(hwnd, ctypes.byref(rect)))
        if not read:
            code = ctypes.get_last_error()
            if code == INVALID_WINDOW:
                return True  # Destroyed while listed: no window of this desktop any more.
            errors.append(code)
            return False
        row = {"hwnd": int(hwnd), "pid": pid.value, "threadId": thread, "class": text.value}
        if geometry:
            row.update(visible=visible, width=rect.right - rect.left, height=rect.bottom - rect.top)
        rows.append(row)
        return True
    def visit(hwnd, _):
        # ctypes would drop an exception raised here and go on: it is a failed census instead, never a shorter list.
        try:
            return read_window(hwnd)
        except BaseException as error:
            errors.append("callback-" + type(error).__name__)
            return False
    callback = callback_type(visit)
    ctypes.set_last_error(0)
    listed = bool(enumerate_windows(lease.handle, callback, 0))
    code = 0 if listed else ctypes.get_last_error()
    # user32 answers FALSE, and sets no error, for a desktop that has no window at all (InternalEnumWindows).
    if errors or not listed and (rows or code):
        error = AssertionError("owned-desktop-window-census")
        error.winerror = next((value for value in errors if type(value) is int), code)
        error.detail = [str(value) for value in errors][:8]
        raise error
    require(not any(row["class"] in TRAY_HOSTS for row in rows), "owned-desktop-has-tray-host")
    lease.current()
    return rows


def default_desktop(lease, native, pids):
    """On the thread that made the lease, which is on Default: windows of these processes there, and the shell tray host."""
    current = native.api(lease.kernel, "GetCurrentThreadId", W.DWORD, [])()
    require(current == lease.thread_id and lease.object_name(lease.get_thread(current)) == "Default",
            "no-tray-default-desktop-observer")
    callback_type = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
    enumerate_windows = native.api(lease.user, "EnumWindows", W.BOOL, [callback_type, W.LPARAM])
    class_name = native.api(lease.user, "GetClassNameW", ctypes.c_int, [W.HWND, W.LPWSTR, ctypes.c_int])
    process_id = native.api(lease.user, "GetWindowThreadProcessId", W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)])
    found, counts, failed = [], {"windows": 0, "vanished": 0, "trayHosts": 0}, []
    def read_window(hwnd):
        counts["windows"] += 1
        if counts["windows"] > 8192:
            return False
        text, pid = ctypes.create_unicode_buffer(256), W.DWORD()
        thread = process_id(hwnd, ctypes.byref(pid))
        if not thread or not class_name(hwnd, text, len(text)):
            counts["vanished"] += 1  # Destroyed while listed: no window of these processes, which live elsewhere.
            return True
        counts["trayHosts"] += text.value in TRAY_HOSTS
        if pid.value in pids:
            found.append({"hwnd": int(hwnd), "pid": pid.value, "threadId": thread, "class": text.value})
        return True
    def visit(hwnd, _):
        try:
            return read_window(hwnd)
        except BaseException as error:  # As in desktop_windows: a callback that raised is a failed census.
            failed.append("callback-" + type(error).__name__)
            return False
    callback = callback_type(visit)
    ctypes.set_last_error(0)
    listed = bool(enumerate_windows(callback, 0))
    if failed or counts["windows"] > 8192 or not (listed or counts["windows"] == 0 and ctypes.get_last_error() == 0):
        error = AssertionError("no-tray-default-desktop-census")
        error.winerror, error.detail = ctypes.get_last_error(), failed[:8]
        raise error
    return {"guiWindows": found, "trayHost": counts["trayHosts"] > 0, **counts}


def input_or_none(lease):
    """The input desktop's name for the record, or None where a locked session's Winlogon desktop refuses the read."""
    try:
        return lease.input_name()
    except AssertionError:
        return None


def require_child_api(owner):
    require("owned_desktop" in inspect.signature(owner.child).parameters,
            "OWNED_DESKTOP_CHILD_API_MISSING: Child must start a lease's GUI through DesktopProcess and call child_started")


def runtime_view(status):
    return {key: status["data"].get(key) for key in RUNTIME_KEYS}


def actors_view(actors):
    return {role: actors[role] for role in ("owner", "jvm", "runtime")}


def envelope(value, identity, code, exit_code):
    """One final envelope of this controller on stdout, nothing on stderr; whether it has exactly this code and exit."""
    require(value.stderr == "", "no-tray-public-cli-stderr")
    body = json.loads(value.stdout)
    require(type(body) is dict and body.get("schemaVersion") == 1 and body.get("controllerId") == identity,
            "no-tray-public-cli-envelope")
    return (value.returncode == exit_code and body.get("code") == code and body.get("final") is True
            and body.get("ok") is (exit_code == 0)), body


def one_runtime(owner, native, observer, image, actor, label):
    """Every live process of the owned runtime image is the one runtime this owner runs."""
    seen = []
    for entry in native.processes():
        if entry["name"].casefold() != ntpath.basename(image).casefold():
            continue
        try:
            with native.open_process(entry["pid"], 0x101000) as process:
                record, state = process.describe(), process.wait()
        except observer.ProcessAbsent:
            continue
        require(state in (0, 258), "no-tray-runtime-census-wait-unknown")
        if state == 258 and ntpath.normcase(record["image"]) == ntpath.normcase(image):
            seen.append({"pid": entry["pid"], "creationFileTime": record["creationFileTime"]})
    owner.event("no-tray-runtime-census", {"label": label, "runtimes": seen, "replayAllowed": False})
    require(seen == [{"pid": actor["pid"], "creationFileTime": actor["creationFileTime"]}], "no-tray-one-runtime-owner")


def opening_samples(owner, traffic):
    """The sampler's first two samples succeeded before the GUI starts; it is never started again."""
    raw = owner.root / f"child-{traffic.ordinal:04d}.stdout.raw"
    until = time.monotonic() + 30
    while True:
        require(traffic.process.poll() is None, "no-tray-traffic-ended-before-ready")
        lines = raw.read_bytes().split(b"\n")[:-1]
        if len(lines) >= 2:
            first = [json.loads(line) for line in lines[:2]]
            require(all(row.get("kind") == "sample" and row.get("succeeded") is True for row in first),
                    "no-tray-traffic-opening-samples-failed")
            return first
        if time.monotonic() >= until:
            owner.park("no-tray-traffic-readiness-unknown")
        time.sleep(0.05)


def gui_windows(owner, gui, native, lease, cases):
    """Every window of the private desktop, then the launcher and its relaunched JVM, which must own them all."""
    rows = lease.on_desktop(native, lambda: desktop_windows(lease, native, geometry=True))
    launcher = cases.gui_record(owner, gui, native)
    opened, frontend = cases.relaunched_frontends(owner, gui, native, launcher)
    for process in opened:
        process.__exit__(None, None, None)
    jvm = None if frontend is None else {key: frontend[1][key] for key in ("pid", "creationFileTime", "image", "sha256")}
    pids = {gui.pid} | (set() if jvm is None else {jvm["pid"]})
    if not all(row["pid"] in pids for row in rows):
        owner.event("no-tray-foreign-window-on-private-desktop", {"windows": rows, "launcher": launcher, "jvm": jvm,
                                                                   "replayAllowed": False})
        raise AssertionError("unowned-process-window-on-private-desktop")
    main = [row for row in rows if row["width"] >= MAIN_WIDTH and row["height"] >= MAIN_HEIGHT]
    return {"launcher": launcher, "jvm": jvm, "pids": pids, "rows": rows, "main": main}


def empty_desktop(owner, lease, native, step, reason):
    """The private desktop lists no window: before the GUI starts, and again after it ended."""
    rows = lease.on_desktop(native, lambda: desktop_windows(lease, native))
    if rows:
        owner.event("no-tray-desktop-not-empty", {"step": step, "windows": rows, "replayAllowed": False})
        raise AssertionError(reason)


def hidden_gui(owner, seen, step):
    """A live GUI whose main window exists and none of it is visible: hidden into a tray this desktop does not have."""
    if seen["main"] and not any(row["visible"] for row in seen["main"]):
        owner.event("no-tray-gui-hidden", {"step": step, "launcher": seen["launcher"], "jvm": seen["jvm"],
            "windows": seen["rows"], "privateDesktopTrayHost": False, "liveGui": True, "replayAllowed": False})
        raise AssertionError("gui-hidden-without-usable-tray")


def visible_main(owner, gui, native, lease, cases, window, step):
    """The GUI is live and the same one main window is visible; a live GUI never hides into no tray."""
    if gui.process.poll() is not None:
        owner.event("no-tray-gui-ended", {"step": step, "terminal": gui.wait(), "replayAllowed": False})
        raise AssertionError("no-tray-gui-exited-before-close")
    seen = gui_windows(owner, gui, native, lease, cases)
    hidden_gui(owner, seen, step)
    visible = [row for row in seen["main"] if row["visible"]]
    if len(visible) != 1 or visible[0]["hwnd"] != window["hwnd"] or visible[0]["pid"] != window["pid"]:
        owner.event("no-tray-main-window-unexpected", {"step": step, "expected": window, "windows": seen["rows"],
                                                        "replayAllowed": False})
        raise AssertionError("no-tray-main-window-changed" if visible else "no-tray-gui-window-lost")
    return seen


def await_private_window(owner, gui, native, lease, cases):
    """The GUI's one visible main window on the private desktop, with none of its windows on Default."""
    until = time.monotonic() + WINDOW_SECONDS
    while True:
        if gui.process.poll() is not None:
            cases.ended_gui(owner, gui)  # Names the owner's attach refusal; any other end keeps its own reason.
        seen = gui_windows(owner, gui, native, lease, cases)
        elsewhere = default_desktop(lease, native, seen["pids"])
        if elsewhere["guiWindows"]:
            owner.event("no-tray-gui-window-on-default-desktop", {"windows": elsewhere["guiWindows"],
                "launcher": seen["launcher"], "jvm": seen["jvm"], "replayAllowed": False})
            raise AssertionError("no-tray-gui-not-on-private-desktop")
        visible = [row for row in seen["main"] if row["visible"]]
        if len(visible) == 1:
            return {**seen, "window": visible[0], "defaultDesktop": elsewhere}
        if time.monotonic() >= until:
            owner.event("no-tray-gui-window-unresolved", {"windows": seen["rows"], "launcher": seen["launcher"],
                "jvm": seen["jvm"], "defaultDesktop": elsewhere, "replayAllowed": False})
            owner.park("no-tray-gui-window-unresolved-no-replay")
        time.sleep(0.1)


def post_close(lease, native, window):
    """On a thread of the private desktop: the window is still the GUI's, and one WM_CLOSE is posted to it."""
    process_id = native.api(lease.user, "GetWindowThreadProcessId", W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)])
    post = native.api(lease.user, "PostMessageW", W.BOOL, [W.HWND, W.UINT, W.WPARAM, W.LPARAM])
    pid = W.DWORD()
    thread = process_id(window["hwnd"], ctypes.byref(pid))
    require(thread == window["threadId"] and pid.value == window["pid"], "exact-window-process-before-close")
    ctypes.set_last_error(0)
    at = time.monotonic()  # Before the post: the frontend was live, and heartbeating, at least until here.
    posted = bool(post(window["hwnd"], WM_CLOSE, 0, 0))
    return {"posted": posted, "error": 0 if posted else ctypes.get_last_error(), "pid": pid.value, "threadId": thread,
            "at": at}


def no_tray_close_case(owner, state, inputs, runtime, cases, observer):
    """On with traffic sampled, the GUI attached on an owned desktop with no notification area, then one WM_CLOSE.

    Returns the actors of the runtime the row's own explicit off stops next.
    """
    require(type(inputs) is dict and set(inputs) == INPUT_FIELDS and type(inputs["schemaVersion"]) is int
            and inputs["schemaVersion"] == 1 and all(type(inputs[key]) is str and inputs[key] for key in INPUT_FIELDS - {"schemaVersion"}),
            "no-tray-native-inputs-pending")
    require_child_api(owner)  # Refuse the missing seam before any native mutation.
    require(not any(child.label == "lifecycle-gui" for child in owner.children), "no-tray-row-started-a-gui")
    stage = ["opening"]
    try:
        return _close_case(owner, state, inputs, runtime, cases, observer, stage)
    except AssertionError as error:
        # Where the row stopped and, for a refused Win32 call, its error code; the reason stays the driver's to close on.
        code, detail = getattr(error, "winerror", None), getattr(error, "detail", None)
        owner.event("no-tray-close-failed", {"stage": stage[0], "reason": str(error)[:120],
                                             "winerror": code if type(code) is int else None,
                                             "detail": detail if type(detail) is list else None, "replayAllowed": False})
        raise


def _close_case(owner, state, inputs, runtime, cases, observer, stage):
    workspace, identity = state["workspace"], state["identity"]
    native = observer.WindowsNative()
    opening = runtime.result(owner, workspace, identity, "status")
    view = runtime_view(opening)
    require(view["runtimeRunning"] is True and view["activeMode"] == "proxy-only" and opening["restartRequired"] is False,
            "no-tray-opening-proxy-a")
    image, image_sha = state["inputs"]["runtimeImagePath"], state["inputs"]["runtimeSha256"]
    actors = runtime.capture_proxy_actors(owner, state["serve"], native, image, image_sha)
    require(actors_view(actors) == actors_view(state["actors"]), "no-tray-opening-runtime-owner")
    one_runtime(owner, native, observer, image, actors["runtime"], "opening")
    def stable(label, reason):
        status = runtime.result(owner, workspace, identity, "status")
        require(runtime_view(status) == view and status["restartRequired"] is False
                and status["configurationRevision"] == opening["configurationRevision"], reason)
        for role in ("owner", "runtime"):
            cases.exact_actor(native, actors[role], elevated=False)
        owner.event("no-tray-owner-serving", {"label": label, "status": status, "replayAllowed": False})
        return status
    mixed = cases.product_traffic_port(str(workspace / "runtime-config.json"), state["ready"]["advertisedSocksPort"])
    traffic = owner.child("lifecycle-traffic", [owner.request["pythonRuntime"]["interpreterPath"], "-I", "-B",
                                                inputs["trafficWorkerPath"], "--input", inputs["trafficInputPath"],
                                                "--mixed-port", str(mixed)])
    opening_samples(owner, traffic)
    stage[0] = "desktop"
    lease = OwnedNoTrayDesktop(owner, inputs["guiPath"], workspace)
    empty_desktop(owner, lease, native, "new", "new-owned-desktop-must-have-no-foreign-windows")
    actions = []
    started = time.time()
    stage[0] = "gui-start"
    gui = owner.child("lifecycle-gui", [inputs["guiPath"], "--state-dir", str(workspace)], owned_desktop=lease)
    require(lease.child is gui, "original-owned-desktop-child-join")
    stage[0] = "await-window"
    shown = await_private_window(owner, gui, native, lease, cases)
    window = shown["window"]
    stage[0] = "attached"
    # The GUI ran on the private desktop: its window is listed there and none of its windows is on Default. Its
    # thread's own desktop is named too where GetThreadDesktop finds this process a handle like the thread's.
    borrowed = lease.get_thread(window["threadId"])
    thread_desktop = lease.object_name(borrowed) if borrowed else None
    require(thread_desktop in (None, lease.name), "no-tray-gui-thread-desktop-mismatch")
    owner.event("no-tray-gui-desktop-observed", {"desktop": lease.name, "lpDesktop": "WinSta0\\" + lease.name,
        "launcher": shown["launcher"], "jvm": shown["jvm"], "window": window, "guiThreadDesktop": thread_desktop,
        "privateDesktopWindows": shown["rows"], "privateDesktopTrayHost": False,
        "defaultDesktop": shown["defaultDesktop"], "desktopSecuritySha256": hashlib.sha256(lease.security).hexdigest(),
        "inputDesktop": input_or_none(lease), "replayAllowed": False})
    stable("attached", "no-tray-attach-changed-owner-runtime")
    actions.append({"action": "no-tray-attach", "startedAt": started, "finishedAt": time.time()})
    # The tray decision is final only after every install attempt the product makes: never an invisible GUI meanwhile.
    stage[0] = "settle"
    settled, observations = time.monotonic() + SETTLE_SECONDS, 0
    while True:
        require(traffic.process.poll() is None, "no-tray-traffic-ended-before-close")
        visible_main(owner, gui, native, lease, cases, window, "settle")
        observations += 1
        if time.monotonic() >= settled:
            break
        time.sleep(POLL_SECONDS)
    # The product's own decision, read through the frontend: without a usable tray gui hide is UNSUPPORTED and does nothing.
    stage[0] = "decision-probe"
    started = time.time()
    probe = owner.invoke(workspace, "--json", "--controller-id", identity, "gui", "hide")
    matched, decision = envelope(probe, identity, "UNSUPPORTED", 1)
    finished = time.time()
    if not matched:
        owner.event("no-tray-decision-probe-answer", {"code": decision.get("code"), "exitCode": probe.returncode,
            "final": decision.get("final"), "replayAllowed": False})
        if decision.get("code") == "OK":
            if gui.process.poll() is None:
                hidden_gui(owner, gui_windows(owner, gui, native, lease, cases), "gui-hide-probe")
            raise AssertionError("no-tray-gui-decided-it-has-a-tray")
        raise AssertionError("no-tray-decision-probe-unexpected")
    visible_main(owner, gui, native, lease, cases, window, "gui-hide-probe")
    actions.append({"action": "no-tray-hide-probe", "startedAt": started, "finishedAt": finished})
    # One WM_CLOSE from a thread of the GUI's own desktop: the close must detach and end the GUI.
    stage[0] = "close"
    require(traffic.process.poll() is None, "no-tray-traffic-ended-before-close")
    current = visible_main(owner, gui, native, lease, cases, window, "before-close")
    require(not getattr(gui, "_lifecycle_close_attempted", False), "window-close-already-attempted")
    gui._lifecycle_close_attempted = True
    started = time.time()
    owner.event("no-tray-wm-close-intent", {"pid": gui.pid, "birthFileTimeUtc": gui.birth, "window": window,
        "jvm": current["jvm"], "desktop": lease.name, "oneEffect": True, "replayAllowed": False})
    posted = lease.on_desktop(native, lambda: post_close(lease, native, window))
    owner.event("no-tray-wm-close-posted", posted)
    require(posted["posted"], "no-tray-close-post-refused")
    until = time.monotonic() + EXIT_SECONDS
    while gui.process.poll() is None:
        if time.monotonic() >= until:
            seen = gui_windows(owner, gui, native, lease, cases)
            hidden_gui(owner, seen, "wm-close")
            owner.event("no-tray-close-gui-still-live", {"windows": seen["rows"], "jvm": seen["jvm"], "replayAllowed": False})
            raise AssertionError("no-tray-close-kept-the-window" if any(row["visible"] for row in seen["main"])
                                 else "no-tray-close-gui-did-not-exit")
        time.sleep(0.1)
    # The owner's own answer at once, before anything else is collected: it holds no frontend, so gui hide is NOT_FOUND
    # (status has no frontend field), and it says so while a lease nobody released would still be held.
    stage[0] = "lease-read"
    reader = owner.child("public-cli", [owner.request["cliPath"], "--state-dir", str(workspace), "--json",
                                        "--controller-id", identity, "gui", "hide"])
    while reader.process.poll() is None:
        time.sleep(0.05)
    seconds = time.monotonic() - posted["at"]
    released, answer = envelope(reader.completed(), identity, "NOT_FOUND", 1)
    owner.event("no-tray-lease-read", {"code": answer.get("code"), "secondsFromPost": seconds, "boundSeconds": RELEASE_SECONDS,
                                       "replayAllowed": False})
    require(released, "no-tray-close-left-frontend-attached")
    require(seconds < RELEASE_SECONDS, "no-tray-close-release-unproven")
    stage[0] = "gui-terminal"
    terminal = gui.wait()
    require(terminal["exitCode"] == 0 and terminal["eof"] == {"stdout": True, "stderr": True}, "no-tray-close-gui-terminal")
    exits = [] if current["jvm"] is None else observer.observe_exit([current["jvm"]], native)
    if not all(row.get("originalAbsent") is True for row in exits):
        owner.event("no-tray-jvm-exit-unproven", {"jvm": current["jvm"], "observed": exits, "replayAllowed": False})
        raise AssertionError("no-tray-close-jvm-exit-unproven")
    finished = time.time()
    actions.append({"action": "no-tray-wm-close", "startedAt": started, "finishedAt": finished})
    stage[0] = "closing"
    empty_desktop(owner, lease, native, "closed", "no-tray-closed-gui-left-a-window")
    closing = stable("closing", "no-tray-close-stopped-owner-or-runtime")
    require(actors_view(runtime.capture_proxy_actors(owner, state["serve"], native, image, image_sha)) == actors_view(actors),
            "no-tray-close-changed-runtime-owner")
    one_runtime(owner, native, observer, image, actors["runtime"], "closing")
    lease.close()
    stage[0] = "traffic"
    traffic_terminal = traffic.wait()
    require(traffic_terminal["exitCode"] == 0 and all(traffic_terminal["eof"].values()), "no-tray-traffic-original-child-terminal")
    stdout = (owner.root / f"child-{traffic.ordinal:04d}.stdout.raw").read_text(encoding="utf-8")
    require(not (owner.root / f"child-{traffic.ordinal:04d}.stderr.raw").read_bytes(), "no-tray-traffic-observer-stderr")
    measured = cases.traffic_window(stdout, actions)
    require(all(row.get("mixedPort") == mixed for row in map(json.loads, stdout.splitlines()) if row.get("kind") == "sample"),
            "no-tray-sampler-product-port-binding")
    owner.event("no-tray-close-detach-observed", {"desktop": lease.name, "window": window, "jvm": current["jvm"],
        "settleObservations": observations, "decision": decision, "guiTerminal": terminal, "jvmExit": exits,
        "frontendReleased": answer, "releaseSecondsFromPost": seconds, "closingStatus": closing, "actors": actors_view(actors), "actions": actions,
        "measuredTraffic": measured, "trafficTerminal": traffic_terminal,
        "installedAdmissionArtifactId": inputs["installedAdmissionArtifactId"],
        "fixtureAdmissionArtifactId": inputs["fixtureAdmissionArtifactId"],
        "explorerOrUnrelatedProcessStopped": False, "nativeAcceptanceComplete": False})
    return {"actors": actors, "gui": gui, "traffic": traffic, "terminal": terminal, "measuredTraffic": measured}
