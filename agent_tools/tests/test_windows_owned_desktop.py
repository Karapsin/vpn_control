"""Declared-native-peer checks; no process, desktop, input or network is started.

The owner's Child starts a lease's one GUI child through DesktopProcess (CreateProcessW with lpDesktop), every other
child through Popen. Its native calls are declared peers here, except one control that runs the real raw pumps over
local pipes.
"""
from __future__ import annotations
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import threading
import time
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
GUI = r"C:\Installed App\vpn-control.exe"
WORKSPACE = r"C:\Owned\state"
DESKTOP_NAME = "VcParityNoTray-peer"
PROCESS, THREAD, PID = 900, 901, 700
REAL_THREAD = threading.Thread  # The boundary replaces threading.Thread with an inert peer.


def declared_ctypes():
    """The Windows-only ctypes calls the lease module makes, as inert peers: a callback is the function itself."""
    stack = contextlib.ExitStack()
    stack.enter_context(patch.object(DESKTOP.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True))
    stack.enter_context(patch.object(DESKTOP.ctypes, "set_last_error", lambda value: 0, create=True))
    stack.enter_context(patch.object(DESKTOP.ctypes, "get_last_error", lambda: 0, create=True))
    return stack


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


class ReaderPeer:
    def __init__(self, handle):
        self.handle, self.closed = handle, False
    def fileno(self):
        return self.handle
    def close(self):
        self.closed = True


class NativePeer:
    """DesktopProcessNative's calls as declared peers: handles are numbers, CreateProcessW is recorded once."""

    def __init__(self, boundary):
        self.boundary, self.next = boundary, 100
        self.created, self.closed, self.descriptors, self.inherited, self.pipes = [], [], [], {}, []
        self.exit_code_value = None
        self.reader_failure = self.create_failure = False

    def handle(self):
        self.next += 4
        return self.next

    def pipe(self):
        self.pipes.append((self.handle(), self.handle()))
        return self.pipes[-1]

    def null(self):
        self.null_handle = self.handle()  # The descriptor's own handle: closing the descriptor closes it.
        return 77, self.null_handle

    def inheritable(self, handle):
        duplicate = self.handle()
        self.inherited[duplicate] = handle
        return duplicate

    def close(self, handle):
        self.closed.append(handle)

    def close_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    def reader(self, handle):
        if self.reader_failure:
            raise OSError("declared reader failure after the child started")
        return ReaderPeer(handle)

    def create(self, application, command_line, environment, cwd, desktop, handles):
        children = self.boundary.owner.children
        if not children or not isinstance(children[-1].process, self.boundary.module.DesktopProcess):
            raise AssertionError("original-desktop-process-not-retained-before-create")
        self.created.append({"application": application, "commandLine": command_line, "environment": environment,
                             "cwd": cwd, "desktop": desktop, "handles": list(handles)})
        if self.create_failure:
            raise OSError(5, "declared CreateProcessW failure")
        return PROCESS, THREAD, PID

    def wait(self, handle):
        return 258 if self.exit_code_value is None else 0

    def exit_code(self, handle):
        return self.exit_code_value


class ChildBoundary:
    """Real owner/Child code with the lease of one module version, real raw files and declared inert native peers."""

    def __init__(self, module=OWNER, desktop=DESKTOP):
        self.module, self.desktop = module, desktop
        self.temp = tempfile.TemporaryDirectory(prefix="owned-desktop-peer-")
        self.owner = object.__new__(module.Owner)
        self.owner.root = Path(self.temp.name)
        self.owner.children, self.owner.events_seen = [], []
        self.owner.environment, self.owner.raw_limit = {"DECLARED_PEER": "1", "Path": "C:\\Windows"}, 4096
        self.owner.by_path = {GUI.casefold(): types.SimpleNamespace(record={"sha256": "1" * 64})}
        self.owner.request = {"context": {"ordinarySid": "S-1-5-21-1-2-3-1001", "ordinarySessionId": 2}}
        self.owner.guard = lambda: None
        self.births = []
        def birth(handle):
            self.births.append(handle)
            return "134369000000000000"
        self.owner.native = types.SimpleNamespace(birth=birth)
        self.owner.event = lambda kind, value: self.owner.events_seen.append((kind, value))
        def park(reason, error=None):
            self.owner.parked_peer = {"reason": reason, "error": error}
            raise ParkedPeer(reason)
        self.owner.park = park
        self.lease = object.__new__(desktop.OwnedNoTrayDesktop)
        self.lease.owner, self.lease.gui_path, self.lease.workspace = self.owner, GUI, WORKSPACE
        self.lease.startup_kind, self.lease.name, self.lease.handle = "normal", DESKTOP_NAME, 42
        self.lease.security, self.lease.used, self.lease.child = b"declared-private-desktop", False, None
        self.lease.current = lambda: None
        self.owner.no_tray_desktop_leases = [self.lease]
        self.popen, self.native, self.natives = [], NativePeer(self), 0
        boundary = self
        class PopenPeer:
            def __init__(self, argv, **kwargs):
                if not boundary.owner.children or boundary.owner.children[-1].process is not self:
                    raise AssertionError("original-Popen-not-retained-before-constructor")
                boundary.popen.append((tuple(argv), kwargs, self))
                self.pid, self._handle = PID, 99
            def poll(self):
                return None
        def native():
            boundary.natives += 1
            return boundary.native
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(module.subprocess, "Popen", PopenPeer))
        self.stack.enter_context(patch.object(module.subprocess, "CREATE_NO_WINDOW", 8, create=True))
        self.stack.enter_context(patch.object(module.subprocess, "CREATE_NEW_CONSOLE", 16, create=True))
        self.stack.enter_context(patch.object(module.subprocess, "STARTUPINFO", StartupInfoPeer, create=True))
        self.stack.enter_context(patch.object(module, "DesktopProcessNative", native, create=True))
        self.stack.enter_context(patch.object(module.threading, "Thread", ThreadPeer))

    def launch(self, *, lease=True, console=False, argv=None):
        return self.module.Owner.child(self.owner, "lifecycle-gui", argv or [GUI, "--state-dir", WORKSPACE],
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


def desktop_launch_oracle(module, desktop):
    """The lease's GUI child starts once, through CreateProcessW naming the lease's desktop, with Popen's custody."""
    with ChildBoundary(module, desktop) as peer:
        child = peer.launch()
        assert peer.popen == [], "the lease's GUI child started through Popen, which names no desktop"
        assert len(peer.native.created) == 1, peer.native.created
        created = peer.native.created[0]
        assert created["desktop"] == "WinSta0\\" + DESKTOP_NAME
        assert created["application"] == GUI and created["commandLine"] == subprocess.list2cmdline([GUI, "--state-dir", WORKSPACE])
        assert created["environment"] == module.environment_block(peer.owner.environment) and created["cwd"] == str(peer.owner.root)
        # Exactly the three standard handles are inherited, each a duplicate of DEVNULL or a pipe's write end.
        stdin, stdout, stderr = created["handles"]
        assert len({stdin, stdout, stderr}) == 3 and all(handle in peer.native.inherited for handle in created["handles"])
        (out_read, out_write), (err_read, err_write) = peer.native.pipes
        assert (peer.native.inherited[stdin], peer.native.inherited[stdout], peer.native.inherited[stderr]) == (
            peer.native.null_handle, out_write, err_write), "DEVNULL and each pipe's write end, in order"
        assert (child.process.stdout.handle, child.process.stderr.handle) == (out_read, err_read), "the parent reads the same pipes"
        # Popen's custody: the process handle retained, the thread handle and every child end closed, the read ends kept.
        # Child and the lease's child_started read the birth of that same retained handle.
        assert child.process._handle == PROCESS and child.pid == PID and peer.births == [PROCESS, PROCESS]
        assert child.birth == "134369000000000000" and child.process.poll() is None
        assert set(peer.native.closed) == {THREAD, stdin, stdout, stderr, peer.native.inherited[stdout], peer.native.inherited[stderr]}
        assert peer.native.descriptors == [77] and PROCESS not in peer.native.closed
        assert {child.process.stdout.handle, child.process.stderr.handle}.isdisjoint(peer.native.closed)
        assert peer.lease.child is child and child.owned_desktop is peer.lease and peer.lease.used
        started = [value for kind, value in peer.owner.events_seen if kind == "child-started"]
        assert [value["startupDesktop"] for value in started] == ["WinSta0\\" + DESKTOP_NAME]


class ChildSeamTests(unittest.TestCase):
    def test_exact_lease_desktop_child_and_popen_custody(self):
        desktop_launch_oracle(OWNER, DESKTOP)

    def test_the_popen_seam_named_no_desktop_actual_red_and_createprocess_green(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        owner_path, lease_path = FIXTURES / "owner-popen-seam.before.source", FIXTURES / "no-tray-handle-list.before.source"
        self.assertEqual(provenance["popenSeamOwnerBeforeSha256"], hashlib.sha256(owner_path.read_bytes()).hexdigest())
        self.assertEqual(provenance["popenSeamLeaseBeforeSha256"], hashlib.sha256(lease_path.read_bytes()).hexdigest())
        before_owner, before_lease = load(owner_path, "_owned_desktop_popen_seam"), load(lease_path, "_owned_desktop_handle_list")
        red = unittest.TestResult()
        unittest.FunctionTestCase(lambda: desktop_launch_oracle(before_owner, before_lease)).run(red)
        self.assertEqual(1, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        self.assertIn("started through Popen, which names no desktop", red.failures[0][1])
        green = unittest.TestResult()
        unittest.FunctionTestCase(lambda: desktop_launch_oracle(OWNER, DESKTOP)).run(green)
        self.assertTrue(green.wasSuccessful(), green.errors + green.failures)

    def test_original_missing_framework_api_actual_red_and_proposal_green(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        before_path = FIXTURES / "owner.before.source"
        self.assertEqual(provenance["ownerBeforeSha256"], hashlib.sha256(before_path.read_bytes()).hexdigest())
        before = load(before_path, "_owned_desktop_original_missing_api")
        red = unittest.TestResult()
        unittest.FunctionTestCase(lambda: desktop_launch_oracle(before, DESKTOP)).run(red)
        self.assertEqual(1, len(red.errors), red.failures)
        self.assertIn("owned_desktop", red.errors[0][1])
        green = unittest.TestResult()
        unittest.FunctionTestCase(lambda: desktop_launch_oracle(OWNER, DESKTOP)).run(green)
        self.assertTrue(green.wasSuccessful(), green.errors + green.failures)

    def test_default_and_console_children_keep_existing_behavior(self):
        for console, expected in ((False, 8), (True, 16)):
            with self.subTest(console=console), ChildBoundary() as peer:
                peer.launch(lease=False, console=console)
                args = peer.popen[0][1]
                self.assertNotIn("startupinfo", args)
                self.assertEqual(expected, args["creationflags"])
                self.assertTrue(args["close_fds"])
                self.assertIs(args["env"], peer.owner.environment)
                self.assertEqual((OWNER.subprocess.DEVNULL, OWNER.subprocess.PIPE, OWNER.subprocess.PIPE),
                                 (args["stdin"], args["stdout"], args["stderr"]))
                self.assertEqual((0, []), (peer.natives, peer.native.created))
                self.assertFalse(peer.lease.used)

    def test_foreign_or_equal_lease_is_not_a_retained_capability(self):
        with ChildBoundary() as peer:
            class EqualPeer:
                def __eq__(self, _):
                    return True
            peer.owner.no_tray_desktop_leases = [EqualPeer()]
            with self.assertRaisesRegex(OWNER.Refused, "owned-desktop-lease-not-held"):
                peer.launch()
            self.assertEqual(([], []), (peer.popen, peer.native.created))
            self.assertEqual([], peer.owner.children)

    def test_console_conflict_and_wrong_argv_refuse_before_any_process(self):
        with ChildBoundary() as peer:
            with self.assertRaisesRegex(OWNER.Refused, "owned-desktop-console-conflict"):
                peer.launch(console=True)
            self.assertFalse(peer.lease.used)
            for argv in ([GUI, "--state-dir", r"C:\Other\state"], [GUI, "--autostart", "--state-dir", WORKSPACE]):
                with self.assertRaisesRegex(AssertionError, "closed-no-tray-child-role"):
                    peer.launch(argv=argv)
            self.assertFalse(peer.lease.used)
            self.assertEqual(([], [], 0), (peer.popen, peer.native.created, peer.natives))
            self.assertFalse(hasattr(peer.owner, "parked_peer"), "a refusal before any process is known, never parked")

    def test_consumed_lease_never_launches_second_child(self):
        with ChildBoundary() as peer:
            original = peer.launch()
            with self.assertRaisesRegex(AssertionError, "closed-no-tray-child-role"):
                peer.launch()
            self.assertEqual(1, len(peer.native.created))
            self.assertIs(peer.lease.child, original)

    def test_failure_after_createprocess_retains_the_original_process_handle(self):
        with ChildBoundary() as peer:
            peer.native.reader_failure = True
            with self.assertRaisesRegex(ParkedPeer, "post-start-admission-unknown"):
                peer.launch()
            process = peer.owner.children[0].process
            self.assertEqual((PROCESS, PID), (process._handle, process.pid))
            self.assertNotIn(PROCESS, peer.native.closed)
            self.assertTrue(set(process._pipes.values()).isdisjoint(peer.native.closed), "a live child's pipes stay open")
            self.assertTrue(peer.lease.used)
            self.assertIsNone(peer.lease.child)

    def test_a_refused_createprocess_closes_only_what_it_made(self):
        with ChildBoundary() as peer:
            peer.native.create_failure = True
            with self.assertRaisesRegex(ParkedPeer, "post-start-admission-unknown"):
                peer.launch()
            self.assertIsNone(peer.owner.children[0].process._handle)
            made = set(range(104, peer.native.next + 1, 4)) - {peer.native.null_handle}
            self.assertEqual(sorted(made), sorted(peer.native.closed), "both pipes and the three duplicates, nothing else")
            self.assertEqual([77], peer.native.descriptors)

    def test_the_environment_block_is_sorted_without_regard_to_case(self):
        self.assertEqual("a=1\0B=2\0c=3\0\0", OWNER.environment_block({"c": "3", "B": "2", "a": "1"}))
        self.assertEqual("=C:=C:\\\0PATH=x\0\0", OWNER.environment_block({"PATH": "x", "=C:": "C:\\"}))
        for bad in ({}, {"": "x"}, {"A=B": "x"}, {"A": "x\0y"}, {"Path": "a", "PATH": "b"}, {"A": 1}):
            with self.subTest(bad=bad), self.assertRaisesRegex(OWNER.Refused, "desktop-child-environment"):
                OWNER.environment_block(bad)


class KernelPeer:
    """kernel32's four calls of DesktopProcessNative.create as declared peers.

    Each argument is first converted by its declared type's from_param, as ctypes converts it for the real call, so an
    argument the real call would refuse is refused here too.
    """

    def __init__(self, refuse=False):
        self.refuse, self.calls, self.attributes = refuse, [], None

    def __getattr__(self, name):
        if name not in OWNER.DesktopProcessNative.SIGNATURES:
            raise AttributeError(name)
        arguments = OWNER.DesktopProcessNative.SIGNATURES[name][1]

        def call(*values):
            if len(values) != len(arguments):
                raise TypeError(name + " takes %d arguments" % len(arguments))
            for kind, value in zip(arguments, values):
                kind.from_param(value)
            return getattr(self, "declared_" + name)(*values)
        return call

    def declared_InitializeProcThreadAttributeList(self, buffer, count, flags, size):
        self.calls.append(("initialize", buffer is None, count, flags))
        if buffer is None:
            size._obj.value = 48  # Only the size is answered: FALSE, as ERROR_INSUFFICIENT_BUFFER.
            return 0
        self.attributes = buffer
        return 1

    def declared_UpdateProcThreadAttribute(self, buffer, flags, attribute, value, size, previous, returned):
        self.calls.append(("update", buffer is self.attributes, flags, attribute, bytes(value), size, previous, returned))
        return 1

    def declared_CreateProcessW(self, application, command, process_attributes, thread_attributes, inherit, flags,
                                environment, cwd, startup, information):
        extended = startup._obj
        given = extended.StartupInfo
        self.calls.append(("create", {
            "application": application, "commandLine": command.value, "securityAttributes": (process_attributes, thread_attributes),
            "inheritHandles": inherit, "flags": flags, "environment": environment.raw, "cwd": cwd,
            "cb": given.cb, "size": ctypes.sizeof(extended), "desktop": given.lpDesktop, "startFlags": given.dwFlags,
            "standard": [given.hStdInput, given.hStdOutput, given.hStdError],
            "attributeListIsTheInitializedOne": extended.lpAttributeList == ctypes.addressof(self.attributes),
            "unset": [given.lpReserved, given.lpTitle, given.wShowWindow, given.cbReserved2, given.lpReserved2]}))
        if self.refuse:
            return 0
        answer = information._obj
        answer.hProcess, answer.hThread, answer.dwProcessId, answer.dwThreadId = PROCESS, THREAD, PID, PID + 1
        return 1

    def declared_DeleteProcThreadAttributeList(self, buffer):
        self.calls.append(("delete", buffer is self.attributes))


@unittest.skipUnless(struct.calcsize("P") == 8, "the owner admits only an amd64 interpreter")
class NativeLayoutTests(unittest.TestCase):
    """What a host without Windows can check of the one native call: the amd64 layout and flags CreateProcessW is given."""

    def create(self, kernel):
        native = OWNER.DesktopProcessNative.__new__(OWNER.DesktopProcessNative)  # Its constructor needs kernel32 itself.
        native.k = kernel
        block = OWNER.environment_block({"SystemRoot": "C:\\Windows", "Path": "C:\\Windows\\System32"})
        return block, lambda: native.create(GUI, subprocess.list2cmdline([GUI, "--state-dir", WORKSPACE]), block,
                                            "C:\\Owned\\root", "WinSta0\\" + DESKTOP_NAME, [104, 108, 112])

    def test_createprocess_is_given_the_desktop_the_three_handles_and_the_block(self):
        kernel = KernelPeer()
        block, create = self.create(kernel)
        self.assertEqual((PROCESS, THREAD, PID), create())
        self.assertEqual(["initialize", "initialize", "update", "create", "delete"], [call[0] for call in kernel.calls])
        self.assertEqual([("initialize", True, 1, 0), ("initialize", False, 1, 0)], kernel.calls[:2])
        self.assertEqual(("update", True, 0, 0x00020002, struct.pack("<3Q", 104, 108, 112), 24, None, None), kernel.calls[2],
                         "exactly the three standard handles are inherited")
        self.assertEqual({
            "application": GUI, "commandLine": '"C:\\Installed App\\vpn-control.exe" --state-dir C:\\Owned\\state',
            "securityAttributes": (None, None), "inheritHandles": True, "flags": 0x08080400,
            "environment": block.encode("utf-16-le") + b"\0", "cwd": "C:\\Owned\\root", "cb": 112, "size": 112,
            "desktop": "WinSta0\\" + DESKTOP_NAME, "startFlags": 0x00000100, "standard": [104, 108, 112],
            "attributeListIsTheInitializedOne": True, "unset": [None, None, 0, 0, None]}, kernel.calls[3][1])
        self.assertTrue(kernel.calls[3][1]["environment"].endswith(b"\0\0\0\0"), "the block ends in two wide NULs")
        self.assertEqual(("delete", True), kernel.calls[4])

    def test_a_refused_createprocess_raises_its_error_and_still_deletes_the_attribute_list(self):
        kernel = KernelPeer(refuse=True)
        _, create = self.create(kernel)
        refusal = PermissionError(5, "declared refusal")
        with patch.object(OWNER.ctypes, "get_last_error", lambda: 5, create=True), \
                patch.object(OWNER.ctypes, "WinError", lambda code: refusal if code == 5 else None, create=True), \
                self.assertRaises(PermissionError) as raised:
            create()
        self.assertIs(refusal, raised.exception)
        self.assertEqual(["initialize", "initialize", "update", "create", "delete"], [call[0] for call in kernel.calls])

    def test_the_startup_and_process_structures_have_the_amd64_layout(self):
        startup, extended, process = OWNER._StartupInfo, OWNER._StartupInfoEx, OWNER._ProcessInformation
        self.assertEqual((104, 112, 24), (ctypes.sizeof(startup), ctypes.sizeof(extended), ctypes.sizeof(process)))
        offsets = {"cb": 0, "lpReserved": 8, "lpDesktop": 16, "lpTitle": 24, "dwX": 32, "dwY": 36, "dwXSize": 40, "dwYSize": 44,
                   "dwXCountChars": 48, "dwYCountChars": 52, "dwFillAttribute": 56, "dwFlags": 60, "wShowWindow": 64,
                   "cbReserved2": 66, "lpReserved2": 72, "hStdInput": 80, "hStdOutput": 88, "hStdError": 96}
        self.assertEqual(offsets, {name: getattr(startup, name).offset for name, _ in startup._fields_})
        self.assertEqual((0, 104), (extended.StartupInfo.offset, extended.lpAttributeList.offset))
        self.assertEqual({"hProcess": 0, "hThread": 8, "dwProcessId": 16, "dwThreadId": 20},
                         {name: getattr(process, name).offset for name, _ in process._fields_})

    def test_the_creation_flags_are_popens_own_with_the_extended_startup_information(self):
        # Where subprocess has the constant (Windows) it is read; elsewhere the documented value stands in.
        self.assertEqual(getattr(subprocess, "STARTF_USESTDHANDLES", 0x00000100), OWNER._STARTF_USESTDHANDLES)
        no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        self.assertEqual(0x00000400 | 0x00080000 | no_window, OWNER._DESKTOP_CHILD_FLAGS,
                         "CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT and Popen's CREATE_NO_WINDOW")
        self.assertEqual(0x00020002, OWNER._PROC_THREAD_ATTRIBUTE_HANDLE_LIST)

    @unittest.skipIf(os.name == "nt", "a Windows host constructs it")
    def test_the_native_calls_are_refused_off_windows_before_any_import(self):
        with self.assertRaisesRegex(OWNER.Refused, "^windows-desktop-child-required$"):
            OWNER.DesktopProcessNative()


class PipePeer(NativePeer):
    """Real pipes for the real pumps: a handle is a descriptor and the child writes through its own duplicates."""

    def __init__(self, boundary):
        super().__init__(boundary)
        self.child_ends = []

    def pipe(self):
        return os.pipe()

    def null(self):
        descriptor = os.open(os.devnull, os.O_RDWR)
        return descriptor, descriptor

    def inheritable(self, handle):
        duplicate = os.dup(handle)
        self.inherited[duplicate] = handle
        return duplicate

    def close(self, handle):
        super().close(handle)
        if handle != THREAD:  # The declared thread handle is no descriptor.
            os.close(handle)

    def close_descriptor(self, descriptor):
        super().close_descriptor(descriptor)
        os.close(descriptor)

    def reader(self, handle):
        return open(handle, "rb", buffering=0)

    def create(self, application, command_line, environment, cwd, desktop, handles):
        value = super().create(application, command_line, environment, cwd, desktop, handles)
        self.child_ends = [os.dup(handles[1]), os.dup(handles[2])]  # What the child process holds.
        return value


class CaptureTests(unittest.TestCase):
    def test_a_desktop_child_has_the_same_raw_capture_and_terminal_accounting(self):
        with ChildBoundary() as peer:
            peer.native = PipePeer(peer)
            peer.stack.enter_context(patch.object(OWNER.threading, "Thread", REAL_THREAD))
            child = peer.launch()
            stdout, stderr = peer.native.child_ends
            os.write(stdout, b"attached\n")
            os.write(stderr, b"")
            os.close(stdout)
            os.close(stderr)
            peer.native.exit_code_value = 0
            deadline = time.monotonic() + 10
            while child.observe() is None:  # Child.wait itself has no bound: a pump that never reached EOF must fail here.
                self.assertLess(time.monotonic(), deadline, "the real pumps reached EOF on both pipes")
                time.sleep(0.01)
            terminal = child.terminal
            self.assertEqual((0, {"stdout": True, "stderr": True}, {"stdout": 9, "stderr": 0}),
                             (terminal["exitCode"], terminal["eof"], terminal["counts"]))
            self.assertEqual(hashlib.sha256(b"attached\n").hexdigest(), terminal["sha256"]["stdout"])
            self.assertEqual(b"attached\n", (peer.owner.root / "child-0000.stdout.raw").read_bytes())
            self.assertTrue(child.process.stdout.closed and child.process.stderr.closed)
            self.assertEqual(["child-intent", "no-tray-gui-child-intent", "child-started", "child-terminal"],
                             [kind for kind, _ in peer.owner.events_seen])


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
        with declared_ctypes():
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
            with declared_ctypes():
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
            with declared_ctypes():
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


class EmptyDesktopTests(unittest.TestCase):
    """A fresh desktop lists no window: user32 answers that FALSE, with no error set (InternalEnumWindows)."""

    def census(self, module, error):
        lease = object.__new__(module.OwnedNoTrayDesktop)
        lease.handle, lease.current, lease.user = 42, lambda: None, types.SimpleNamespace()
        state = {"error": 0}
        def enumerate_windows(handle, callback, _):
            state["error"] = error
            return 0
        native = types.SimpleNamespace(api=lambda library, name, *_: {"EnumDesktopWindows": enumerate_windows,
            "GetClassNameW": lambda *_: 0, "GetWindowThreadProcessId": lambda *_: 0}[name])
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module.ctypes, "WINFUNCTYPE", lambda *_: lambda function: function, create=True))
            stack.enter_context(patch.object(module.ctypes, "set_last_error", lambda value: state.__setitem__("error", value), create=True))
            stack.enter_context(patch.object(module.ctypes, "get_last_error", lambda: state["error"], create=True))
            return module.desktop_windows(lease, native)

    def test_an_empty_desktop_lists_no_window_before_red_current_green(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        before_path = FIXTURES / "no-tray-handle-list.before.source"
        self.assertEqual(provenance["popenSeamLeaseBeforeSha256"], hashlib.sha256(before_path.read_bytes()).hexdigest())
        before = load(before_path, "_owned_desktop_empty_census_before")
        with self.assertRaisesRegex(AssertionError, "^owned-desktop-window-census$"):
            self.census(before, 0)  # The old census required TRUE, so the new desktop refused itself.
        self.assertEqual([], self.census(DESKTOP, 0))

    def test_a_false_census_that_sets_an_error_still_refuses(self):
        with self.assertRaisesRegex(AssertionError, "^owned-desktop-window-census$"):
            self.census(DESKTOP, 5)


if __name__ == "__main__":
    unittest.main()
