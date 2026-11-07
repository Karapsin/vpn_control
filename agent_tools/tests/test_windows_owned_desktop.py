"""Declared-native-peer checks; no process, desktop, input or network is started."""
from __future__ import annotations
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures/windows_owned_desktop"


def load(path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


OWNER = load(ROOT / "agent_tools/windows_ordinary_process_owner.py", "_owned_desktop_owner")
DESKTOP = load(ROOT / "agent_tools/windows_no_tray_desktop.py", "_owned_desktop_lease")


class StartupInfoPeer:
    def __init__(self, *, lpAttributeList):
        self.lpAttributeList = lpAttributeList


class ParkedPeer(Exception):
    pass


class ThreadPeer:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
    def start(self):
        pass


class ChildBoundary:
    """Real owner/Child code and real raw files, with declared inert native peers."""
    GUI = r"C:\Installed App\vpn-control.exe"
    WORKSPACE = r"C:\Owned\state"
    def __init__(self, module=OWNER, *, constructor_failure=False):
        self.module, self.constructor_failure = module, constructor_failure
        self.temp = tempfile.TemporaryDirectory(prefix="owned-desktop-peer-")
        self.owner = object.__new__(module.Owner)
        self.owner.root = Path(self.temp.name)
        self.owner.children, self.owner.events_seen = [], []
        self.owner.environment, self.owner.raw_limit = {"DECLARED_PEER": "1"}, 4096
        self.owner.by_path = {self.GUI.casefold(): types.SimpleNamespace(record={"sha256": "1" * 64})}
        self.owner.request = {"context": {"ordinarySid": "S-1-5-21-1-2-3-1001", "ordinarySessionId": 2}}
        self.owner.guard = lambda: None
        self.owner.native = types.SimpleNamespace(birth=lambda _: "134369000000000000")
        self.owner.event = lambda kind, value: self.owner.events_seen.append((kind, value))
        def park(reason, error=None):
            self.owner.parked_peer = {"reason": reason, "error": error}
            raise ParkedPeer(reason)
        self.owner.park = park
        self.lease = object.__new__(DESKTOP.OwnedNoTrayDesktop)
        self.lease.owner, self.lease.gui_path, self.lease.workspace = self.owner, self.GUI, self.WORKSPACE
        self.lease.startup_kind, self.lease.name, self.lease.handle = "normal", "VcParityNoTray-peer", 42
        self.lease.security, self.lease.used, self.lease.child = b"declared-private-desktop", False, None
        self.lease.current = lambda: None
        self.owner.no_tray_desktop_leases = [self.lease]
        self.calls = []
        boundary = self
        class PopenPeer:
            def __init__(self, argv, **kwargs):
                if not boundary.owner.children or boundary.owner.children[-1].process is not self:
                    raise AssertionError("original-Popen-not-retained-before-constructor")
                boundary.calls.append((tuple(argv), kwargs, self))
                self.pid, self._handle = 700, 99
                if boundary.constructor_failure:
                    raise OSError("declared exception after native child handle")
            def poll(self):
                return None
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(module.subprocess, "Popen", PopenPeer))
        self.stack.enter_context(patch.object(module.subprocess, "CREATE_NO_WINDOW", 8, create=True))
        self.stack.enter_context(patch.object(module.subprocess, "CREATE_NEW_CONSOLE", 16, create=True))
        self.stack.enter_context(patch.object(module.subprocess, "STARTUPINFO", StartupInfoPeer, create=True))
        self.stack.enter_context(patch.object(module.threading, "Thread", ThreadPeer))

    def launch(self, *, lease=True, console=False, argv=None):
        return self.module.Owner.child(self.owner, "lifecycle-gui",
            argv or [self.GUI, "--state-dir", self.WORKSPACE],
            new_console=console, owned_desktop=self.lease if lease else None)

    def close(self):
        self.stack.close()
        for child in self.owner.children:
            for stream in child.streams.values():
                stream.close()
        self.temp.cleanup()

    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.close()


def exact_launch_oracle(module):
    with ChildBoundary(module) as peer:
        child = peer.launch()
        assert len(peer.calls) == 1
        assert peer.lease.child is child and child.owned_desktop is peer.lease
        assert child.birth == "134369000000000000"
        args = peer.calls[0][1]
        assert args["startupinfo"].lpAttributeList == {"handle_list": [42]}
        assert args["creationflags"] == 8 and args["close_fds"] is True
        assert args["env"] is peer.owner.environment
        assert args["stdin"] == module.subprocess.DEVNULL
        assert args["stdout"] == args["stderr"] == module.subprocess.PIPE


class ChildSeamTests(unittest.TestCase):
    def test_exact_lease_original_child_and_unchanged_io_flags(self):
        exact_launch_oracle(OWNER)

    def test_original_missing_framework_api_actual_red_and_proposal_green(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        before_path = FIXTURES / "owner.before.source"
        self.assertEqual(provenance["ownerBeforeSha256"], hashlib.sha256(before_path.read_bytes()).hexdigest())
        before = load(before_path, "_owned_desktop_original_missing_api")
        red = unittest.TestResult()
        unittest.FunctionTestCase(lambda: exact_launch_oracle(before)).run(red)
        self.assertEqual(1, len(red.errors), red.failures)
        self.assertIn("owned_desktop", red.errors[0][1])
        green = unittest.TestResult()
        unittest.FunctionTestCase(lambda: exact_launch_oracle(OWNER)).run(green)
        self.assertTrue(green.wasSuccessful(), green.errors + green.failures)

    def test_default_and_console_children_keep_existing_behavior(self):
        for console, expected in ((False, 8), (True, 16)):
            with self.subTest(console=console), ChildBoundary() as peer:
                peer.launch(lease=False, console=console)
                self.assertIsNone(peer.calls[0][1]["startupinfo"])
                self.assertEqual(expected, peer.calls[0][1]["creationflags"])
                self.assertFalse(peer.lease.used)

    def test_foreign_or_equal_lease_is_not_a_retained_capability(self):
        with ChildBoundary() as peer:
            class EqualPeer:
                def __eq__(self, _):
                    return True
            peer.owner.no_tray_desktop_leases = [EqualPeer()]
            with self.assertRaisesRegex(OWNER.Refused, "owned-desktop-lease-not-held"):
                peer.launch()
            self.assertEqual([], peer.calls)
            self.assertEqual([], peer.owner.children)

    def test_console_conflict_and_wrong_argv_refuse_before_popen(self):
        with ChildBoundary() as peer:
            with self.assertRaisesRegex(OWNER.Refused, "owned-desktop-console-conflict"):
                peer.launch(console=True)
            self.assertFalse(peer.lease.used)
            with self.assertRaisesRegex(AssertionError, "closed-no-tray-child-role"):
                peer.launch(argv=[peer.GUI, "--state-dir", r"C:\Other\state"])
            self.assertFalse(peer.lease.used)
            self.assertEqual([], peer.calls)

    def test_consumed_lease_never_launches_second_child(self):
        with ChildBoundary() as peer:
            original = peer.launch()
            with self.assertRaisesRegex(AssertionError, "closed-no-tray-child-role"):
                peer.launch()
            self.assertEqual(1, len(peer.calls))
            self.assertIs(peer.lease.child, original)

    def test_partial_constructor_failure_retains_original_capability(self):
        with ChildBoundary(constructor_failure=True) as peer:
            with self.assertRaisesRegex(ParkedPeer, "post-start-admission-unknown"):
                peer.launch()
            self.assertEqual(1, len(peer.calls))
            self.assertIs(peer.owner.children[0].process, peer.calls[0][2])
            self.assertTrue(peer.lease.used)
            self.assertIsNone(peer.lease.child)
            self.assertEqual("post-start-admission-unknown", peer.owner.parked_peer["reason"])


class AssignmentBoundary:
    """Native results are declared peers; this never creates Windows proof."""
    def __init__(self):
        self.owner = types.SimpleNamespace(children=[], events_seen=[])
        self.owner.event = lambda kind, value: self.owner.events_seen.append((kind, value))
        self.lease = object.__new__(DESKTOP.OwnedNoTrayDesktop)
        self.lease.owner, self.lease.name, self.lease.security = self.owner, "VcParityNoTray-peer", b"private"
        self.lease.handle, self.lease.thread_id, self.lease.used = 42, 123, True
        self.lease.current = lambda: None
        self.input = "Default"
        self.lease.input_name = lambda: self.input
        self.thread_name, self.caller_name = self.lease.name, "Default"
        self.lease.get_thread = lambda tid: 43 if tid == 123 else 44
        self.lease.object_name = lambda handle: self.caller_name if handle == 43 else self.thread_name
        self.child = types.SimpleNamespace(owner=self.owner, pid=700, birth="134369000000000000",
            ordinal=0, label="lifecycle-gui", owned_desktop=self.lease)
        self.owner.children = [self.child]
        self.lease.child = self.child
        self.rows = [(100, 700, 11, "SunAwtFrame")]
        self.query_count, self.census_count, self.actor_reads = 0, 0, 0
        self.foreground, self.dpi, self.awareness = 100, 96, 2
        self.current_thread = 123
        self.screen, self.changed_thread, self.duplicate, self.foreign_census = (1280, 800), False, False, False
        def window_pid(hwnd, pid):
            self.query_count += 1
            pid._obj.value = 700 if hwnd == 100 else 900
            return 12 if self.changed_thread and self.query_count >= 4 else 11
        def rect(_, result):
            result._obj.left, result._obj.top, result._obj.right, result._obj.bottom = 0, 0, 1000, 700
            return True
        def enum(_, callback, __):
            self.census_count += 1
            rows = self.rows * (2 if self.duplicate else 1)
            if self.foreign_census:
                rows = [(100, 900, 11, "foreign")]
            for hwnd, _, _, _ in rows:
                if not callback(hwnd, 0):
                    return False
            return True
        def class_name(_, text, __):
            text.value = "SunAwtFrame"
            return len(text.value)
        functions = {"GetWindowThreadProcessId": window_pid, "GetWindowRect": rect,
            "IsWindowVisible": lambda _: True, "GetSystemMetrics": lambda item: self.screen[item],
            "GetDpiForWindow": lambda _: self.dpi, "GetWindowDpiAwarenessContext": lambda _: 10,
            "GetThreadDpiAwarenessContext": lambda: 20,
            "GetAwarenessFromDpiAwarenessContext": lambda context: self.awareness if context == 10 else 0,
            "GetForegroundWindow": lambda: self.foreground,
            "GetCurrentThreadId": lambda: self.current_thread,
            "EnumDesktopWindows": enum, "GetClassNameW": class_name}
        self.lease.user = types.SimpleNamespace()
        self.lease.kernel = types.SimpleNamespace()
        self.native = types.SimpleNamespace(api=lambda library, name, *_: functions[name])
        def actor(owner, child, native):
            self.actor_reads += 1
            if child.birth != "134369000000000000":
                raise AssertionError("original-gui-child-handle-required")
            return {"pid": child.pid, "creationFileTime": int(child.birth), "kernelTime100ns": self.actor_reads}
        self.cases = types.SimpleNamespace(gui_record=actor)

    def observe(self, **kwargs):
        with patch.object(DESKTOP.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True):
            return self.lease.observe_assigned_window(self.child, 100, self.native, self.cases, **kwargs)


class AssignmentTests(unittest.TestCase):
    def test_actual_observer_thread_before_red_and_current_green(self):
        before_path = FIXTURES / "assignment-thread.before.source"
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        self.assertEqual(provenance["observerThreadBeforeSha256"], hashlib.sha256(before_path.read_bytes()).hexdigest())
        before = load(before_path, "_owned_desktop_observer_thread_before")
        def oracle(module):
            peer = AssignmentBoundary()
            peer.current_thread = 124
            with patch.object(module.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True):
                with self.assertRaisesRegex(AssertionError, "observer-thread-changed"):
                    module.OwnedNoTrayDesktop.observe_assigned_window(
                        peer.lease, peer.child, 100, peer.native, peer.cases)
        red = unittest.TestResult()
        unittest.FunctionTestCase(lambda: oracle(before)).run(red)
        self.assertEqual(1, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        green = unittest.TestResult()
        unittest.FunctionTestCase(lambda: oracle(DESKTOP)).run(green)
        self.assertTrue(green.wasSuccessful(), green.errors + green.failures)

    def test_private_foreground_scope_before_red_and_current_green(self):
        before_path = FIXTURES / "assignment-foreground.before.source"
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        self.assertEqual(provenance["foregroundBeforeSha256"], hashlib.sha256(before_path.read_bytes()).hexdigest())
        before = load(before_path, "_owned_desktop_foreground_scope_before")
        def oracle(module):
            peer = AssignmentBoundary()
            peer.input = peer.lease.name
            with patch.object(module.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True):
                with self.assertRaisesRegex(AssertionError, "foreground-unobserved"):
                    module.OwnedNoTrayDesktop.observe_assigned_window(
                        peer.lease, peer.child, 100, peer.native, peer.cases, require_foreground=True)
        red = unittest.TestResult()
        unittest.FunctionTestCase(lambda: oracle(before)).run(red)
        self.assertEqual(1, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        green = unittest.TestResult()
        unittest.FunctionTestCase(lambda: oracle(DESKTOP)).run(green)
        self.assertTrue(green.wasSuccessful(), green.errors + green.failures)

    def test_exact_assigned_window_bracketed_by_actor_and_thread_checks(self):
        peer = AssignmentBoundary()
        result = peer.observe()
        self.assertEqual(2, peer.actor_reads)
        self.assertEqual(2, peer.census_count)
        self.assertNotEqual(result["actorOpening"]["kernelTime100ns"], result["actorClosing"]["kernelTime100ns"])
        self.assertEqual("Default", result["inputDesktop"])
        self.assertFalse(result["foreground"]["ownedDesktopQualified"])
        self.assertFalse(result["inputQualified"])
        self.assertFalse(result["uiaControlQualified"])
        self.assertEqual((1280, 800), (result["display"]["logicalWidth"], result["display"]["logicalHeight"]))
        self.assertFalse(result["physicalDisplayQualified"])

    def test_missing_foreign_or_duplicate_hwnd_refuses(self):
        for change in ("missing", "duplicate", "foreign"):
            with self.subTest(change=change):
                peer = AssignmentBoundary()
                if change == "missing": peer.rows = []
                if change == "duplicate": peer.duplicate = True
                if change == "foreign": peer.rows = [(101, 900, 11, "foreign")]
                with self.assertRaises(AssertionError): peer.observe()
                self.assertEqual([], peer.owner.events_seen)

    def test_gui_thread_desktop_and_closing_thread_mismatch_refuse(self):
        for change in ("desktop", "thread", "birth"):
            with self.subTest(change=change):
                peer = AssignmentBoundary()
                if change == "desktop": peer.thread_name = "Foreign"
                if change == "thread": peer.changed_thread = True
                if change == "birth": peer.child.birth = "134369000000000001"
                with self.assertRaises(AssertionError): peer.observe()
                self.assertEqual([], peer.owner.events_seen)

    def test_default_foreground_is_not_private_desktop_authority(self):
        peer = AssignmentBoundary()
        peer.input = peer.lease.name
        with self.assertRaisesRegex(AssertionError, "foreground-unobserved"):
            peer.observe(require_foreground=True)
        self.assertEqual([], peer.owner.events_seen)

    def test_explicit_same_desktop_foreground_peer_can_be_observed(self):
        peer = AssignmentBoundary()
        peer.input = peer.caller_name = peer.lease.name
        self.assertTrue(peer.observe(require_foreground=True)["foreground"]["ownedDesktopQualified"])

    def test_null_foreground_and_unsupported_geometry_never_qualify_input(self):
        peer = AssignmentBoundary(); peer.foreground = 0
        result = peer.observe()
        self.assertIsNone(result["foreground"]["hwnd"])
        for dpi, screen, awareness in ((192, (1280, 800), 2), (96, (1920, 1080), 2), (96, (1280, 800), 0)):
            with self.subTest(dpi=dpi, screen=screen, awareness=awareness):
                peer = AssignmentBoundary(); peer.dpi, peer.screen, peer.awareness = dpi, screen, awareness
                with self.assertRaisesRegex(AssertionError, "unsupported-display-geometry"):
                    peer.observe()
                self.assertEqual([], peer.owner.events_seen)

    def test_owned_desktop_window_census_is_bounded(self):
        peer = AssignmentBoundary(); peer.rows = [(100, 700, 11, "SunAwtFrame")] * 257
        with self.assertRaisesRegex(AssertionError, "window-census"):
            peer.observe()
        self.assertEqual([], peer.owner.events_seen)


if __name__ == "__main__":
    unittest.main()
