"""windows-proxy-lifecycle.no-tray-close, offline: the full row in test_windows_proxy_lifecycle's world.

The world's guest gains its desktops: Default with Explorer's Shell_TrayWnd, and the private desktop the lease creates
through declared user32, advapi32 and kernel32 peers. A window lives on the desktop its process started on, a thread
moves only through SetThreadDesktop, an empty desktop lists no window (EnumDesktopWindows answers FALSE without an
error), and a window message passes only between threads of one desktop. The product gains what the row reads from
the Kotlin source: the GUI's tray decision (DesktopTray.kt: a tray AWT supports is available once AWT takes the icon,
and a refused icon is retried every TrayInstallRetryDelayMillis up to TrayInstallMaxAttempts), Main.kt's close and its
gui hide handler, and the owner's frontend lease, which a detaching GUI releases. Whether AWT takes an icon on a
desktop with no Shell_TrayWnd is a JDK fact this world cannot know: it is the switch icon_without_tray_host, and each
answer runs. Every row runs through the real dedicated driver, runtime stages, lifecycle cases and no-tray module.
Nothing here proves a Windows behaviour.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import re
import tempfile
import threading
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_lifecycle_cases as lifecycle_cases
from agent_tools import windows_lifecycle_runtime_stages as runtime_stages
from agent_tools import windows_no_tray_desktop as desktop
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_scenario_proxy as proxy
from agent_tools.tests import test_windows_proxy_lifecycle as world

ROOT = world.ROOT
VARIANT = "no-tray-close"
SCENARIO = "windows-proxy-lifecycle." + VARIANT
TRAFFIC_INPUT = "C:\\W\\proxy-traffic.json"
EXPLORER = 4
PRIVATE, DEFAULT, STATION = 42, 43, 50
SECURITY = b"O:S-1-5-21-1-2-3-1000D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1000)"
# The product rules the fake GUI follows, each pinned where the source states it.
INSTALL = (r"fun installTrayIcon\(icon: TrayIcon\) \{\n\s+if \(disposed\) return\n\s+trayIcon = icon\n"
           r"\s+if \(desktopTrayPlatform\(\) != DesktopTrayPlatform\.Linux\) \{\n\s+markAvailable\(\)\n\s+return\n")
TAKEN = (r"tray\.add\(trayIcon\)\n\s+if \(tray\.trayIcons\.any \{ it === trayIcon \}\) \{\n\s+TrayInstallResult\.Installed\(trayIcon\)")
RETRIED = (r"TrayInstallResult\.RetryableFailure -> handleRetryableFailure\(\)[\s\S]*?"
           r"if \(attempts >= retryPolicy\.maxAttempts\) \{\n\s+reportUnavailable\(\)")
CLOSE = (r"onCloseRequest = \{\n\s+if \(trayWindowState\.canHideToTray\) \{\n\s+trayWindowState = trayWindowState\."
         r"withCloseRequestHiddenToTray\(\)\n\s+\} else \{\n\s+detachFrontend\(\)\n")
HIDE = r"if \(!shown && !trayWindowState\.canHideToTray\) com\.kardinal\.vpncontrol\.model\.ControlCode\.UNSUPPORTED\n"
CAN_HIDE = r"val canHideToTray: Boolean\n\s+get\(\) = traySupported && trayAvailable\n"
UNAVAILABLE = r"fun DesktopTrayWindowState\.withTrayUnavailable\(\): DesktopTrayWindowState \{\n\s+return copy\(\n\s+traySupported = false,"


def kotlin(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def tray_rules():
    """TrayInstallMaxAttempts and TrayInstallRetryDelayMillis in seconds, read where DesktopTray.kt sets them."""
    tray = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTray.kt")
    attempts = re.findall(r"\nprivate const val TrayInstallMaxAttempts = ([0-9_]+)\n", tray)
    delay = re.findall(r"\nprivate const val TrayInstallRetryDelayMillis = ([0-9_]+)\n", tray)
    if len(attempts) != 1 or len(delay) != 1 or not re.search(INSTALL, tray) or not re.search(TAKEN, tray) or not re.search(RETRIED, tray):
        raise AssertionError("the tray decision is not where the fake GUI reads it")
    return int(attempts[0].replace("_", "")), int(delay[0].replace("_", "")) / 1000


def foreign_window(hwnd, place):
    """A window of a live process that is neither the GUI's launcher nor its JVM, on the named desktop."""
    return {"hwnd": hwnd, "pid": EXPLORER, "visible": True, "width": 300, "height": 200, "class": "#32770", "threadId": 5001,
            "desktop": place}


class Function:
    """A declared native function: ctypes sets restype and argtypes on it, the guest answers the call.

    Each argument is first converted by its declared type's from_param, as ctypes converts it for the real call, so an
    argument the real call would refuse is refused here too. A callback type is an inert peer here and converts nothing.
    """

    def __init__(self, name, body):
        self.name, self.body, self.argtypes = name, body, None

    def __call__(self, *arguments):
        if self.argtypes is not None:
            if len(arguments) != len(self.argtypes):
                raise TypeError("%s takes %d arguments, not %d" % (self.name, len(self.argtypes), len(arguments)))
            for kind, value in zip(self.argtypes, arguments):
                if hasattr(kind, "from_param"):
                    kind.from_param(value)
        return self.body(*arguments)


class Library:
    def __init__(self, functions):
        self.functions = functions

    def __getattr__(self, name):
        if name not in self.functions:
            raise AttributeError("closed native call " + name)
        return Function(name, self.functions[name])


class Guest(world.World):
    """The world's process table, plus the guest's desktops, their windows and the threads that read them."""

    def __init__(self):
        super().__init__()
        self.last_error, self.product, self.private_name = 0, None, None
        self.names = {DEFAULT: "Default", STATION: "WinSta0"}
        self.inputs = []  # Every OpenInputDesktop handle, the lease's original first.
        # GetThreadDesktop gives a caller only a handle of its own like the other process's thread handle; False: it has none.
        self.matching_thread_handle = True
        self.destroyed = []  # Handles still listed on the private desktop whose windows are already gone.
        self.thread_desktops, self.gui_threads = {}, {}
        self.closed_desktops, self.posted, self.refused_posts, self.switches = [], [], [], []
        self.windows[EXPLORER] = [{"hwnd": 0x10010, "pid": EXPLORER, "visible": True, "width": 1280, "height": 40,
                                   "class": "Shell_TrayWnd", "threadId": 5000, "desktop": "Default"}]
        self.user32 = Library({
            "OpenInputDesktop": self.open_input,
            "OpenDesktopW": self.open_desktop, "CloseDesktop": lambda handle: self.closed_desktops.append(handle) or 1,
            "SwitchDesktop": lambda handle: self.switches.append(handle) or 1,
            "GetThreadDesktop": self.thread_desktop, "SetThreadDesktop": self.set_thread_desktop,
            "GetProcessWindowStation": lambda: STATION, "GetUserObjectInformationW": self.object_name,
            "GetUserObjectSecurity": self.object_security, "CreateDesktopW": self.create_desktop,
            "EnumDesktopWindows": lambda handle, callback, _: self.enumerate(self.names[handle], callback),
            "EnumWindows": lambda callback, _: self.enumerate(self.current_desktop(), callback),
            "GetClassNameW": self.class_name, "GetWindowThreadProcessId": self.window_process,
            "GetWindowRect": self.window_rect, "IsWindowVisible": lambda hwnd: bool(self.row(hwnd) and self.row(hwnd)["visible"]),
            "PostMessageW": self.post})
        self.kernel32 = Library({"GetCurrentThreadId": threading.get_ident, "LocalFree": lambda pointer: 0,
                                 "TerminateProcess": self.terminate})
        self.advapi32 = Library({"ConvertStringSecurityDescriptorToSecurityDescriptorW": self.convert})
        self.k = self.kernel32

    def library(self, name, use_last_error=False):
        return {"user32": self.user32, "kernel32": self.kernel32, "advapi32": self.advapi32}[name]

    def native(self):
        base = super().native()

        class Native(type(base)):
            k = self.kernel32

            @staticmethod
            def api(library, name, result, arguments):
                function = getattr(library, name)
                function.restype, function.argtypes = result, arguments
                return function
        return Native()

    def open_input(self, flags, inherit, access):
        handle = 60 + 4 * len(self.inputs)
        self.inputs.append(handle)
        self.names[handle] = "Default"  # The row never switches: Default stays the input desktop.
        return handle

    def current_desktop(self):
        return self.thread_desktops.get(threading.get_ident(), "Default")

    def open_desktop(self, name, flags, inherit, access):
        if name in self.names.values() and name != "WinSta0":
            return next(handle for handle, value in self.names.items() if value == name)
        self.last_error = 2
        return 0

    def create_desktop(self, name, device, mode, flags, access, attributes):
        self.private_name = self.names[PRIVATE] = name
        return PRIVATE

    def convert(self, sddl, revision, descriptor, size):
        self.sddl = sddl
        descriptor._obj.value = 0x5000
        return 1

    def object_name(self, handle, index, buffer, size, needed):
        if handle not in self.names:
            self.last_error = 6
            return 0
        buffer.value = self.names[handle]
        needed._obj.value = (len(self.names[handle]) + 1) * 2
        return 1

    def object_security(self, handle, information, buffer, size, needed):
        needed._obj.value = len(SECURITY)
        if buffer is None:
            self.last_error = 122
            return 0
        ctypes.memmove(buffer, SECURITY, len(SECURITY))
        return 1

    def thread_desktop(self, thread):
        if thread in self.gui_threads and not self.matching_thread_handle:
            self.last_error = 5
            return 0
        name = self.gui_threads.get(thread) or self.thread_desktops.get(thread, "Default")
        return PRIVATE if name == self.private_name else DEFAULT

    def set_thread_desktop(self, handle):
        self.thread_desktops[threading.get_ident()] = self.names[handle]
        return 1

    def live_rows(self, desktop_name=None):
        return [row for pid, rows in self.windows.items() for row in rows
                if (pid == EXPLORER or self.live(pid) is not None) and (desktop_name is None or row.get("desktop", "Default") == desktop_name)]

    def row(self, hwnd):
        found = [row for row in self.live_rows() if row["hwnd"] == hwnd]
        return found[0] if found else None

    def enumerate(self, desktop_name, callback):
        listed = [row["hwnd"] for row in self.live_rows(desktop_name)]
        if desktop_name == self.private_name:
            listed = self.destroyed + listed
        if not listed:
            return 0  # user32 InternalEnumWindows: no window listed is FALSE, with no error set.
        for hwnd in listed:
            if not callback(hwnd, 0):
                return 0
        return 1

    def class_name(self, hwnd, buffer, size):
        row = self.row(hwnd)
        if row is None:
            self.last_error = 1400
            return 0
        buffer.value = row["class"]
        return len(row["class"])

    def window_process(self, hwnd, pid):
        row = self.row(hwnd)
        if row is None:
            self.last_error = 1400
            return 0
        pid._obj.value = row["pid"]
        return row["threadId"]

    def window_rect(self, hwnd, rect):
        row = self.row(hwnd)
        if row is None:
            self.last_error = 1400
            return 0
        rect._obj.left, rect._obj.top, rect._obj.right, rect._obj.bottom = 10, 10, 10 + row["width"], 10 + row["height"]
        return 1

    def post(self, hwnd, message, wparam, lparam):
        """PostMessageW: a window message passes only between threads of one desktop."""
        row, caller = self.row(hwnd), self.current_desktop()
        if row is None or row.get("desktop", "Default") != caller:
            self.refused_posts.append((hwnd, message, caller))
            self.last_error = 5
            return 0
        self.posted.append((hwnd, message, caller))
        if message == desktop.WM_CLOSE:
            self.product.close_window(row)
        return 1


class NoTrayProduct(world.Product):
    """The world's product with the GUI's tray decision, Main.kt's close and its gui hide handler."""

    def __init__(self, world_, owner):
        super().__init__(world_, owner)
        self.attempts, self.delay = tray_rules()
        self.icon_without_tray_host = "refused"  # What AWT does with an icon where no Shell_TrayWnd is.
        self.close_fault = None
        self.next_desktop = "Default"
        self.frontends = {}
        self.teardowns, self.late_exits = {}, []  # JVM pid -> when its heartbeat stopped; (JVM, when it ends).

    def launch_frontend(self, parent):
        launcher, jvm, streams = super().launch_frontend(parent)
        if self.frontend is not None and self.frontend[0] is jvm:
            # An attached GUI: its frame, and AWT's hidden toolkit window, on the desktop its launcher started on.
            thread, place = jvm.pid * 16 + 1, self.next_desktop
            for row in self.world.windows[jvm.pid]:
                row.update({"class": "SunAwtFrame", "threadId": thread, "desktop": place})
            self.world.windows[jvm.pid].append({"hwnd": jvm.pid * 16 + 2, "pid": jvm.pid, "visible": False, "width": 0,
                                                "height": 0, "class": "SunAwtToolkit", "threadId": thread, "desktop": place})
            self.world.gui_threads[thread] = place
            self.frontends[jvm.pid] = {"desktop": place, "launched": self.owner.clock.now}
        return launcher, jvm, streams

    def tray_available_at(self, jvm):
        """When trayAvailable turns true: at AWT's first take where a tray host exists; otherwise per the JDK switch."""
        state = self.frontends[jvm.pid]
        first = state["launched"] + 0.5
        if state["desktop"] == "Default":
            return first
        return {"refused": None, "taken": first, "late": first + (self.attempts // 2 - 1) * self.delay}[self.icon_without_tray_host]

    def can_hide(self, jvm):
        at = self.tray_available_at(jvm)
        return at is not None and self.owner.clock.now >= at

    def tick(self):
        """A teardown that takes its time ends its JVM when the fake clock reaches it."""
        for jvm, at in list(self.late_exits):
            if self.owner.clock.now >= at:
                self.late_exits.remove((jvm, at))
                jvm.end(0)

    def registration(self):
        """The world's lease, except that a frontend in teardown stopped its heartbeat there (beginClose)."""
        if self.frontend is not None and self.frontend[0].pid in self.teardowns:
            jvm, attached, _ = self.frontend
            stopped = self.teardowns[jvm.pid]
            touched = attached + self.heartbeat_seconds * ((stopped - attached) // self.heartbeat_seconds)
            if self.owner.clock.now - touched >= self.lease_seconds:
                self.frontend = None
            return None if self.frontend is None else jvm
        return super().registration()

    def run(self, words):
        self.tick()
        return super().run(words)

    def visibility(self, show):
        frontend = self.registration()
        if frontend is not None and frontend.exit_code is None and not show and not self.can_hide(frontend):
            return 1, self.envelope("UNSUPPORTED")  # Main.kt: no tray to hide into, so nothing changes.
        return super().visibility(show)

    def close_window(self, row):
        """Main.kt onCloseRequest: hidden when canHideToTray, otherwise detachFrontend, teardown and exit 0."""
        jvm, fault = self.world.live(row["pid"]), self.close_fault
        if fault == "ignored":
            return
        if fault == "hides-anyway" or self.can_hide(jvm):
            for each in self.world.windows[jvm.pid]:
                each["visible"] = False
            return
        if fault == "exits-late-without-detach":
            # closeAndDetach swallows a failed detach: the heartbeat is off, the window is gone, and the JVM ends 0
            # only after the lease nobody released has run out.
            self.teardowns[jvm.pid] = self.owner.clock.now
            self.world.windows[jvm.pid] = []
            self.late_exits.append((jvm, self.owner.clock.now + self.lease_seconds + 1))
            return
        if fault == "launcher-ends-first":
            # The launcher ends 0 while the JVM it started, detached and without a window, is still running.
            self.frontend = None
            self.world.windows[jvm.pid] = []
            self.world.live(jvm.parent).end(0)
            return
        if fault == "leaves-a-window":
            self.world.windows[EXPLORER].append(foreign_window(0x20030, row["desktop"]))
        if fault == "drops-traffic":
            self.owner.sampler_failing = (self.owner.clock.now - 0.1, self.owner.clock.now + 0.1)
        if fault != "keeps-lease" and self.frontend is not None and self.frontend[0] is jvm:
            self.frontend = None  # closeAndDetach released the owner's lease.
        if fault == "stops-runtime" and self.running:
            self.runtime.end(0)
            self.running, self.active = False, None
        if fault == "second-runtime":
            self.world.spawn(jvm.pid, str(Path(self.owner.request["workspace"]) / "runtime" / "tools" / "sing-box.exe"), world.RUNTIME_SHA)
        jvm.end(1 if fault == "exits-nonzero" else 0)  # The launcher that waits for its JVM ends with its code.


class Sampler(world.Traffic):
    """The world's sampler; a product that dropped traffic as the GUI closed fails the samples of that moment."""

    def failed(self):
        failing = getattr(self.owner, "sampler_failing", None)
        path = self.owner.root / f"child-{self.ordinal:04d}.stdout.raw"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            if failing and row["kind"] == "sample" and row["startedAt"] <= failing[1] and row["finishedAt"] >= failing[0]:
                row.update(succeeded=False, errorClass="ConnectionResetError", reason="peer reset")
            if row["kind"] == "terminal":
                row["allSamplesSucceeded"] = all(item["succeeded"] for item in rows if item["kind"] == "sample")
        path.write_bytes("".join(json.dumps(row) + "\n" for row in rows).encode())
        return any(row["kind"] == "sample" and not row["succeeded"] for row in rows)

    def wait(self):
        if self.terminal is None:
            self.write(self.owner.clock.now + 1, terminal=True)
            self.os_process.end(1 if self.failed() else 0)
        return world.Child.wait(self)


class NoTrayOwner(world.StartOwner):
    """The dedicated driver's owner over the guest: the real stage, cases and no-tray module, the extended product."""

    def __init__(self, root, guest):
        super().__init__(root, guest)
        self.product = guest.product = NoTrayProduct(guest, self)
        self.placement = None  # A launcher whose windows land on Default whatever its lpDesktop says.

    def module(self, path, name):
        if name == "_owned_dedicated_no_tray_desktop":
            self.loaded.append(name)
            return desktop
        return super().module(path, name)

    def event(self, kind, value):
        # The real Owner journals strict JSON with sorted keys, at most 256 KiB an event, and parks on anything else
        # (windows_ordinary_process_owner.encoded, Owner.event). The world's own journal would stringify it instead.
        if kind.startswith("no-tray-"):
            data = json.dumps({"kind": kind, "value": value}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if len(data.encode("utf-8")) > 256 * 1024:
                raise TypeError("event-byte-bound " + kind)
        super().event(kind, value)

    def child(self, label, argv, *, new_console=False, owned_desktop=None):
        if owned_desktop is not None:
            # Child's DesktopProcess path: the lease names the desktop for its closed argv, and the GUI starts there.
            named = owned_desktop.desktop_for_child(self, label, argv)
            self.product.next_desktop = self.placement or named.split("\\", 1)[1]
            first, _, streams = self.product.launch_frontend(None)
            child = world.Child(self, label, argv, first)
            for name, value in zip(("stdout", "stderr"), streams):
                (self.root / f"child-{child.ordinal:04d}.{name}.raw").write_bytes(value)
            poll = child.process.poll
            child.process.poll = lambda: (self.product.tick(), poll())[1]
            owned_desktop.child_started(child)
            return child
        if label == "lifecycle-traffic":
            return Sampler(self, label, argv)
        return super().child(label, argv)


class NoTrayBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.guest = Guest()
        self.world = self.guest
        self.owner = NoTrayOwner(self.root, self.guest)
        guest = self.guest
        def set_last_error(value):
            guest.last_error = value
        for patcher in (mock.patch.object(runtime_stages, "os", world.NtOs()), mock.patch.object(runtime_stages, "time", world.Clock()),
                        mock.patch.object(lifecycle_cases, "time", self.owner.clock), mock.patch.object(desktop, "time", self.owner.clock),
                        mock.patch.object(desktop.ctypes, "WinDLL", guest.library, create=True),
                        mock.patch.object(desktop.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True),
                        mock.patch.object(desktop.ctypes, "set_last_error", set_last_error, create=True),
                        mock.patch.object(desktop.ctypes, "get_last_error", lambda: guest.last_error, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def harness(self):
        harness = world.StartFailureTests.harness(self, VARIANT)
        owner = self.owner
        owner.pin(world.GUI, world.GUI_SHA)
        owner.pin(world.CLI, world.LAUNCHER_SHA)
        owner.pin(TRAFFIC_INPUT, "6" * 64)
        inputs = harness.LIFECYCLE_INPUTS
        inputs["modules"]["noTray"] = owner.source("agent_tools/windows_no_tray_desktop.py")
        inputs["noTray"] = {"schemaVersion": 1, "guiPath": world.GUI,
                            "trafficWorkerPath": owner.source("agent_tools/windows_lifecycle_traffic_worker.py"),
                            "trafficInputPath": TRAFFIC_INPUT, "installedAdmissionArtifactId": "installed", "fixtureAdmissionArtifactId": "fixture"}
        return harness

    def run_row(self):
        return dedicated_driver.run_lifecycle(self.owner, lifecycle_cases, self.harness())

    def commands(self):
        return world.StartFailureTests.commands(self)

    def events(self, kind):
        return [value for name, value in self.owner.events if name == kind]

    def gui(self):
        found = [child for child in self.owner.children if child.label == "lifecycle-gui"]
        self.assertEqual(1, len(found), "one GUI, never started again")
        return found[0]

    def assert_closed(self):
        self.assertTrue(all(child.terminal is not None for child in self.owner.children), "every child the row started has ended")
        self.assertEqual(0, self.owner.product.jvm.exit_code, "the serve's owner quit")
        self.assertTrue((self.root / "fixture" / "stop.json").exists(), "the fixture ended on its own stop record")
        self.assertEqual(1, self.commands().count(("quit",)), "one quit, never sent again")
        lease = self.owner.no_tray_desktop_leases[0]
        self.assertEqual((None, None), (lease.handle, lease.original))
        self.assertEqual([PRIVATE, self.guest.inputs[0]], self.guest.closed_desktops[-2:], "the private desktop, then the original input handle")
        self.assertEqual([], self.guest.switches, "the input desktop is never switched")

    def assert_known_failure(self, reason, stage):
        self.assertEqual(1, self.run_row())
        self.assertEqual([reason], [value["reason"] for value in self.events("dedicated-proxy-lifecycle-known-failure")])
        # The module's own record of where it stopped, once, before the driver closes.
        self.assertEqual([(stage, reason)], [(value["stage"], value["reason"]) for value in self.events("no-tray-close-failed")])
        self.assert_closed()


class NoTrayRowTests(NoTrayBase):
    def test_a_gui_without_a_usable_tray_closes_detaches_and_ends_while_the_runtime_serves(self):
        self.assertEqual(0, self.run_row())
        self.assertEqual(["_owned_dedicated_runtime_stages", "_owned_dedicated_proxy_observer", "_owned_dedicated_no_tray_desktop"],
                         self.owner.loaded)
        self.assertEqual([], self.events("dedicated-proxy-lifecycle-known-failure"))
        self.assertEqual([], self.events("no-tray-close-failed"))
        self.assertEqual([VARIANT], [value["variant"] for value in self.events("dedicated-proxy-lifecycle-known-closed")])
        gui = self.gui()
        self.assertEqual((0, {"stdout": True, "stderr": True}), (gui.terminal["exitCode"], gui.terminal["eof"]))
        # The GUI ran on the private desktop: started there, its window's thread there, nothing of it on Default.
        intent = self.events("no-tray-gui-child-intent")[0]
        self.assertEqual(("WinSta0\\" + self.guest.private_name, [world.GUI, "--state-dir", self.owner.request["workspace"]]),
                         (intent["lpDesktop"], intent["argv"]))
        placed = self.events("no-tray-gui-desktop-observed")[0]
        self.assertEqual(self.guest.private_name, placed["guiThreadDesktop"])
        self.assertEqual(([], True), (placed["defaultDesktop"]["guiWindows"], placed["defaultDesktop"]["trayHost"]))
        self.assertEqual({"SunAwtFrame", "SunAwtToolkit"}, {row["class"] for row in placed["privateDesktopWindows"]})
        self.assertEqual(placed["jvm"]["pid"], placed["window"]["pid"], "the relaunched JVM owns the window")
        # The product's own decision first, then one WM_CLOSE from a thread of that desktop.
        self.assertEqual("UNSUPPORTED", self.events("no-tray-close-detach-observed")[0]["decision"]["code"])
        self.assertEqual(2, self.commands().count(("gui", "hide")), "the decision, then the lease")
        self.assertEqual([(placed["window"]["hwnd"], desktop.WM_CLOSE, self.guest.private_name)], self.guest.posted)
        self.assertEqual([], self.guest.refused_posts)
        observed = self.events("no-tray-close-detach-observed")[0]
        self.assertEqual("NOT_FOUND", observed["frontendReleased"]["code"])
        self.assertLess(observed["releaseSecondsFromPost"], desktop.RELEASE_SECONDS)
        self.assertLess(self.commands().index(("gui", "hide")), len(self.commands()) - 1)
        self.assertTrue(all(row["originalAbsent"] for row in observed["jvmExit"]))
        self.assertGreaterEqual(observed["settleObservations"], desktop.SETTLE_SECONDS // desktop.POLL_SECONDS)
        self.assertEqual(["no-tray-attach", "no-tray-hide-probe", "no-tray-wm-close"], [row["action"] for row in observed["measuredTraffic"]["coverage"]])
        self.assertTrue(all(row["beforeSamples"] and row["duringSamples"] and row["afterSamples"] for row in observed["measuredTraffic"]["coverage"]))
        # One runtime owner throughout: the same owner, JVM and runtime at each census, and the row's own off stopped it.
        self.assertEqual(["opening", "closing"], [value["label"] for value in self.events("no-tray-runtime-census")])
        self.assertEqual(1, len({json.dumps(value["runtimes"]) for value in self.events("no-tray-runtime-census")}))
        self.assertEqual(0, self.owner.product.runtime.exit_code)
        self.assertEqual(1, self.commands().count(("off",)))
        self.assert_closed()


    def test_a_window_destroyed_while_it_was_listed_is_no_window_of_the_desktop(self):
        self.guest.destroyed = [0xDEAD0]
        self.assertEqual(0, self.run_row())
        placed = self.events("no-tray-gui-desktop-observed")[0]
        self.assertNotIn(0xDEAD0, [row["hwnd"] for row in placed["privateDesktopWindows"]])

    def test_the_proof_of_the_desktop_needs_no_handle_like_the_guis_own(self):
        self.guest.matching_thread_handle = False
        self.assertEqual(0, self.run_row())
        placed = self.events("no-tray-gui-desktop-observed")[0]
        self.assertIsNone(placed["guiThreadDesktop"])
        self.assertIn(placed["window"]["hwnd"], [row["hwnd"] for row in placed["privateDesktopWindows"]])
        self.assertEqual([], placed["defaultDesktop"]["guiWindows"])


class NoTrayControlTests(NoTrayBase):
    """A wrong product answer ends the row 1 with everything it started closed; nothing is sent again."""

    def test_a_gui_that_takes_its_icon_without_a_tray_host_hides_into_none_and_fails_named(self):
        # What DesktopTray.kt does on Windows if AWT takes the icon where no Shell_TrayWnd exists.
        self.owner.product.icon_without_tray_host = "taken"
        self.assert_known_failure("gui-hidden-without-usable-tray", "decision-probe")
        self.assertEqual(["gui-hide-probe"], [value["step"] for value in self.events("no-tray-gui-hidden")])
        self.assertEqual([], self.guest.posted, "no close after the product hid its window")
        self.assertEqual(0, self.gui().terminal["exitCode"], "the closing's quit ended the hidden GUI")

    def test_a_tray_taken_only_at_a_later_retry_is_still_caught_after_the_settle(self):
        self.owner.product.icon_without_tray_host = "late"
        self.assert_known_failure("gui-hidden-without-usable-tray", "decision-probe")

    def test_a_probe_before_the_last_install_attempt_would_have_passed_that_product(self):
        self.owner.product.icon_without_tray_host = "late"
        attempts, delay = tray_rules()
        with mock.patch.object(desktop, "SETTLE_SECONDS", (attempts // 2 - 10) * delay):
            self.assertEqual(0, self.run_row(), "a settle shorter than the product's retries passes a GUI that later hides")

    def test_a_close_that_hides_without_a_tray_fails_named(self):
        self.owner.product.close_fault = "hides-anyway"
        self.assert_known_failure("gui-hidden-without-usable-tray", "close")
        self.assertEqual(["wm-close"], [value["step"] for value in self.events("no-tray-gui-hidden")])

    def test_a_close_the_gui_ignores_fails_named(self):
        self.owner.product.close_fault = "ignored"
        self.assert_known_failure("no-tray-close-kept-the-window", "close")

    def test_a_gui_that_exits_without_releasing_its_lease_fails_named(self):
        self.owner.product.close_fault = "keeps-lease"
        self.assert_known_failure("no-tray-close-left-frontend-attached", "lease-read")

    def test_a_gui_that_never_detached_and_outlived_its_lease_is_unproven_never_passed(self):
        # The owner answers NOT_FOUND here too, because the lease ran out: only the bound from the posted close tells.
        self.owner.product.close_fault = "exits-late-without-detach"
        self.assert_known_failure("no-tray-close-release-unproven", "lease-read")
        read = self.events("no-tray-lease-read")[0]
        self.assertEqual("NOT_FOUND", read["code"])
        self.assertGreaterEqual(read["secondsFromPost"], self.owner.product.lease_seconds)

    def test_a_close_that_stopped_the_runtime_fails_named(self):
        self.owner.product.close_fault = "stops-runtime"
        self.assert_known_failure("no-tray-close-stopped-owner-or-runtime", "closing")
        self.assertNotIn(("off",), self.commands(), "the closing turns off nothing that is not running")

    def test_a_second_runtime_after_the_close_fails_named(self):
        self.owner.product.close_fault = "second-runtime"
        self.assert_known_failure("no-tray-one-runtime-owner", "closing")
        self.assertEqual([("opening", 1), ("closing", 2)],
                         [(value["label"], len(value["runtimes"])) for value in self.events("no-tray-runtime-census")],
                         "the refused census is recorded with both runtimes")

    def test_traffic_dropped_as_the_gui_closed_fails_named(self):
        self.owner.product.close_fault = "drops-traffic"
        self.assert_known_failure("no-tray-traffic-original-child-terminal", "traffic")
        self.assertEqual([1], [child.terminal["exitCode"] for child in self.owner.children if child.label == "lifecycle-traffic"])

    def test_a_gui_whose_windows_land_on_default_fails_named(self):
        self.owner.placement = "Default"
        self.assert_known_failure("no-tray-gui-not-on-private-desktop", "await-window")
        self.assertEqual(1, len(self.events("no-tray-gui-window-on-default-desktop")))

    def test_a_new_desktop_that_already_lists_a_window_is_refused_with_what_it_lists(self):
        guest, create = self.guest, self.guest.create_desktop
        def created(name, *rest):
            guest.windows[EXPLORER].append(foreign_window(0x20010, name))
            return create(name, *rest)
        guest.user32.functions["CreateDesktopW"] = created
        self.assert_known_failure("new-owned-desktop-must-have-no-foreign-windows", "desktop")
        self.assertEqual([("new", [(0x20010, EXPLORER, "#32770")])],
                         [(value["step"], [(row["hwnd"], row["pid"], row["class"]) for row in value["windows"]])
                          for value in self.events("no-tray-desktop-not-empty")])
        self.assertNotIn("lifecycle-gui", [child.label for child in self.owner.children])

    def test_a_window_of_another_process_beside_the_guis_is_refused_with_every_window(self):
        guest, product = self.guest, self.owner.product
        launch = product.launch_frontend
        def launched(parent):
            value = launch(parent)
            guest.windows[EXPLORER].append(foreign_window(0x20020, product.next_desktop))
            return value
        product.launch_frontend = launched
        self.assert_known_failure("unowned-process-window-on-private-desktop", "await-window")
        seen = self.events("no-tray-foreign-window-on-private-desktop")
        self.assertEqual(1, len(seen))
        self.assertEqual({"#32770", "SunAwtFrame", "SunAwtToolkit"}, {row["class"] for row in seen[0]["windows"]})
        self.assertNotIn(EXPLORER, (seen[0]["launcher"]["pid"], seen[0]["jvm"]["pid"]))
        self.assertEqual([], self.guest.posted, "no close once the desktop is not the GUI's alone")

    def test_a_window_left_on_the_desktop_after_the_gui_ended_fails_named(self):
        self.owner.product.close_fault = "leaves-a-window"
        self.assert_known_failure("no-tray-closed-gui-left-a-window", "closing")
        self.assertEqual([("closed", [0x20030])], [(value["step"], [row["hwnd"] for row in value["windows"]])
                                                    for value in self.events("no-tray-desktop-not-empty")])

    def test_a_launcher_that_ended_before_its_jvm_fails_named_with_the_jvm_it_saw(self):
        self.owner.product.close_fault = "launcher-ends-first"
        self.assert_known_failure("no-tray-close-jvm-exit-unproven", "gui-terminal")
        unproven = self.events("no-tray-jvm-exit-unproven")
        self.assertEqual(1, len(unproven))
        self.assertEqual([unproven[0]["jvm"]["pid"]], [row["pid"] for row in unproven[0]["observed"]])
        self.assertIsNot(True, unproven[0]["observed"][0]["originalAbsent"])
        self.assertEqual(0, self.gui().terminal["exitCode"])

    def test_a_close_posted_from_the_default_desktop_is_refused_and_named(self):
        on_desktop = desktop.OwnedNoTrayDesktop.on_desktop
        def posting_here(lease, native, function):
            # Every read still goes through the private desktop; the post alone stays on the caller's thread.
            return function() if getattr(function, "__name__", "") == "<lambda>" and "post_close" in function.__code__.co_names else on_desktop(lease, native, function)
        with mock.patch.object(desktop.OwnedNoTrayDesktop, "on_desktop", posting_here):
            self.assert_known_failure("no-tray-close-post-refused", "close")
        self.assertEqual([("Default",)], [refused[2:] for refused in self.guest.refused_posts])
        self.assertEqual([], self.guest.posted)

    def test_a_refused_win32_call_names_its_stage_and_error_code_before_any_gui_starts(self):
        guest = self.guest
        def refused(handle, callback, _):
            guest.last_error = 5
            return 0
        guest.user32.functions["EnumDesktopWindows"] = refused
        self.assert_known_failure("owned-desktop-window-census", "desktop")
        self.assertEqual([5], [value["winerror"] for value in self.events("no-tray-close-failed")])
        self.assertNotIn("lifecycle-gui", [child.label for child in self.owner.children])

    def raising_class_name(self, place):
        """GetClassNameW raises inside the enumeration callback of the named desktop's census."""
        guest, class_name = self.guest, self.guest.class_name
        def raising(hwnd, buffer, size):
            if (guest.current_desktop() == "Default") == (place == "Default"):
                raise RuntimeError("declared failure inside the enumeration callback")
            return class_name(hwnd, buffer, size)
        guest.user32.functions["GetClassNameW"] = raising

    def test_a_census_callback_that_raised_is_a_failed_census_never_a_shorter_list(self):
        # ctypes drops an exception a callback raises and goes on: the census must refuse instead of listing less.
        self.raising_class_name("private")
        self.assert_known_failure("owned-desktop-window-census", "await-window")
        self.assertEqual([["callback-RuntimeError"]], [value["detail"] for value in self.events("no-tray-close-failed")])
        self.assertEqual([], self.guest.posted)

    def test_a_default_desktop_census_whose_callback_raised_is_refused_too(self):
        self.raising_class_name("Default")
        self.assert_known_failure("no-tray-default-desktop-census", "await-window")
        self.assertEqual([["callback-RuntimeError"]], [value["detail"] for value in self.events("no-tray-close-failed")])
        self.assertEqual([], self.guest.posted)

    def test_a_gui_that_exits_nonzero_after_the_close_closes_everything_and_the_closing_names_its_terminal(self):
        self.owner.product.close_fault = "exits-nonzero"
        with self.assertRaisesRegex(ValueError, "^dedicated-known-failure-terminal-and-eof$"):
            self.run_row()
        self.assertEqual(["no-tray-close-gui-terminal"], [value["reason"] for value in self.events("dedicated-proxy-lifecycle-known-failure-closing")])
        self.assertEqual(["gui-terminal"], [value["stage"] for value in self.events("no-tray-close-failed")])
        self.assertTrue(all(child.terminal is not None for child in self.owner.children), "the owner can still finish 1")
        self.assertEqual(1, self.gui().terminal["exitCode"])


class AdmissionTests(unittest.TestCase):
    """The row exists end to end: the driver's variant, the job's files and harness, the matrix scenarios it proves."""

    def test_the_variant_is_a_row_the_driver_and_the_job_both_know(self):
        row = windows._row(SCENARIO)
        self.assertIn(VARIANT, dedicated_driver.NO_TRAY_VARIANTS)
        self.assertEqual({"variant": VARIANT}, row["proxy"])
        self.assertIn(("agent_tools/windows_no_tray_desktop.py", "noTray", "data"), row["guestFiles"])
        self.assertIn(("agent_tools/windows_lifecycle_traffic_worker.py", "traffic", "data"), row["guestFiles"])
        self.assertEqual(proxy.generated_roles(VARIANT), tuple(role for role, _ in row["generated"]))
        self.assertIsNone(row.get("refusal"))
        sampler = json.loads(proxy.traffic_input(VARIANT, str(uuid.uuid4())))
        self.assertEqual((1800, 0.2), (sampler["sampleCount"], sampler["intervalSeconds"]))
        # The sampler starts before the GUI and must outlast its window, the settle and the exit with samples to spare.
        self.assertGreater(sampler["sampleCount"] * sampler["intervalSeconds"],
                           desktop.WINDOW_SECONDS + desktop.SETTLE_SECONDS + desktop.EXIT_SECONDS + 60)

    def test_the_matrix_counts_it_for_a_detach_by_close(self):
        named = sorted(name + ":" + scenario for name, table in windows.MATRIX_SCENARIOS.items() for scenario, rows in table.items() if SCENARIO in rows)
        self.assertEqual(["windows-native-cli:gui-attach-detach", "windows-owner-lifecycle:close-detach-traffic"], named)
        self.assertEqual((SCENARIO,), windows.MATRIX_SCENARIOS["windows-owner-lifecycle"]["close-detach-traffic"])
        # An attach and a crash are gui-pending's; the detach only a close without a tray makes is this row's.
        self.assertEqual(("windows-proxy-lifecycle.gui-pending", SCENARIO), windows.MATRIX_SCENARIOS["windows-native-cli"]["gui-attach-detach"])


class NoTrayDecisionTests(unittest.TestCase):
    """The product facts the row's oracles stand on, read from the source; a change to any of them reviews the row."""

    def test_a_close_detaches_only_without_a_usable_tray_and_hide_refuses_there(self):
        main = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/Main.kt")
        self.assertRegex(main, CLOSE)
        self.assertRegex(main, HIDE)
        self.assertRegex(main, CAN_HIDE)
        self.assertRegex(main, UNAVAILABLE)
        application = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopFrontendApplication.kt")
        self.assertRegex(application, r"teardown\(\)\n[\s\S]*?terminate\(0\)\n}", "a detached frontend tears down, then exits 0")

    def test_the_tray_decision_is_final_within_the_settle(self):
        attempts, delay = tray_rules()
        self.assertGreaterEqual(desktop.SETTLE_SECONDS, attempts * delay + 10)
        tray = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopTray.kt")
        self.assertRegex(tray, r"DesktopTrayPlatform\.Windows,\n\s+DesktopTrayPlatform\.MacOs,\n\s+DesktopTrayPlatform\.Other,\n\s+-> isAwtDesktopTraySupported\(\)")

    def test_the_lease_and_the_owner_answers_the_row_reads(self):
        lease_seconds, heartbeat_seconds, _ = world.product_frontend()
        self.assertEqual((lease_seconds, heartbeat_seconds), (desktop.LEASE_SECONDS, desktop.HEARTBEAT_SECONDS))
        self.assertEqual(lease_seconds - heartbeat_seconds - 1, desktop.RELEASE_SECONDS,
                         "a lease nobody released is still held one heartbeat short of its length after the post")
        connection = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopGuiOwnerConnection.kt")
        self.assertRegex(connection, r"suspend fun closeAndDetach\(\) \{\n\s+if \(!beginClose\(\)\) return\n\s+withContext\(NonCancellable\) \{ runCatching \{ detach\(\) \} \}\n",
                         "a teardown releases the lease before the frontend exits, and swallows a detach that failed")
        self.assertRegex(connection, r"private fun beginClose\(\): Boolean \{\n\s+if \(!closed\.compareAndSet\(false, true\)\) return false\n\s+heartbeat\.cancel\(\)\n")
        visibility = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopGuiVisibilityControl.kt")
        self.assertRegex(visibility, r"if \(frontend == null\) \{\n\s+if \(input\.command\.operation == ControlOperationId\.GUI_HIDE\) \{\n\s+code = ControlCode\.NOT_FOUND\n")
        snapshot = kotlin("shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/control/ControlSnapshotValues.kt")
        self.assertNotIn("frontend", snapshot.lower(), "status has no frontend field: gui hide NOT_FOUND is the owner's own answer")

    def test_the_module_constants_are_the_rows_own(self):
        cases = (ROOT / "agent_tools/windows_lifecycle_cases.py").read_text(encoding="utf-8")
        self.assertIn('main = [row for row in records if row["width"] >= 500 and row["height"] >= 300]', cases)
        self.assertEqual((500, 300), (desktop.MAIN_WIDTH, desktop.MAIN_HEIGHT))
        self.assertEqual(desktop.GUI_LEAF, windows.host_job.PRODUCT_GUI)
        self.assertEqual(set(desktop.INPUT_FIELDS), set(dedicated_driver.SCHEDULED_FIELDS))
        self.assertEqual(hashlib.sha256((ROOT / "agent_tools/windows_no_tray_desktop.py").read_bytes()).hexdigest(), dedicated_driver.NO_TRAY_SHA)


if __name__ == "__main__":
    unittest.main()
