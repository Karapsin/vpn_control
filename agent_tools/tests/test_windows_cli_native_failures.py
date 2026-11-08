"""Two native failures of the first family's CLI rows (2026-11-08), as offline oracles.

windows-streaming-client-interrupt (operation 866c885f) and windows-disconnected-cli-config
(operation 98c8c95a) both ended UNKNOWN, owner-parked, and consumed their clones:

* the console helper refused a third console member, the installed launcher's own
  restart child, so the stream case failed with its client still running;
* a known case failure with the owner's own serve (and stream client) still running
  parked the owner, although nothing was uncertain.

Each oracle reproduces its native situation with inert logical peers, is RED on the
preserved module (fixtures/windows_cli_native_failures/*.before.source) and GREEN on the
current one. The controls keep refusing or parking. No process, console, socket or
Win32 call is made.

Two review findings on that fix are oracles too, GREEN here: a helper failure once its
create-only intent exists is recorded as unknown, never refused, and a serve a case
already sent a quit, whatever that quit answered, is awaited and never quit again. Their
RED ran on the fix's first bytes, which never landed.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_disconnected_cli_cases as disconnected_cases
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_streaming_cli_cases as streaming_cases


FIXTURES = Path(__file__).parent / "fixtures/windows_cli_native_failures"
PROVENANCE = Path(__file__).parent / "fixtures/windows_cli_native_failures/provenance.json"
OWNER_SHA256 = "3037a3e13b177d09fccd11bc54c2ec5f5659a78ce8e77d1e180f314ae9255b62"
STREAMING_SHA256 = "4b34a0bb6b695ae3dedd932fecdd68d8b0fc53b827baef8e370e08f8367c8d92"
# Recorded by the native streaming row (operation 866c885f's events): the client, helper, worker
# (owner) and serve pids, the client's birth and its ordinary session. Modelled, not recorded: the
# native helper refused before it named any member (thirdMemberIdentityRecorded false), so RESTART
# and its row in native_processes() (parent CLIENT, the LAUNCHER image, born BIRTH + 23000) follow
# the OpenJDK 17.0.21 launcher's restart; the other rows' parents, images and births are modelled too.
CLIENT, HELPER, WORKER, SERVE, RESTART = 8672, 9664, 9760, 3668, 7316
BIRTH = 134385816510418586
SESSION = 2
LAUNCHER = r"C:\Users\winparityUser\AppData\Local\vpn-control\vpn-control-cli.exe"
PYTHON = r"C:\Users\winparityUser\AppData\Local\Programs\Python\Python313\python.exe"
CASES = r"C:\ProgramData\VpnControlOrdinaryTask-866c885f-27da-4a37-90c5-9dbc5861629d\windows_streaming_cli_cases.py"


def _load(test, raw, fixture, digest, name):
    test.assertEqual(digest, hashlib.sha256(raw).hexdigest())
    provenance = json.loads(PROVENANCE.read_bytes())["fixtures"][fixture]
    test.assertEqual((digest, len(raw)), (provenance["sha256"], provenance["sizeBytes"]))
    module = types.ModuleType(name)
    module.__file__ = str(FIXTURES / fixture)
    sys.modules[name] = module
    test.addCleanup(sys.modules.pop, name, None)
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def before_owner(test):
    return _load(test, (FIXTURES / "owner-known-failure.before.source").read_bytes(),
                 "owner-known-failure.before.source", OWNER_SHA256, "_native_failure_before_owner")


def before_streaming(test):
    return _load(test, (FIXTURES / "streaming-console-fence.before.source").read_bytes(),
                 "streaming-console-fence.before.source", STREAMING_SHA256, "_native_failure_before_streaming")


# ---- Defect 1: the console fence ------------------------------------------------------


def process(parent, image=LAUNCHER, *, session=SESSION, creation=BIRTH + 23000, live=True):
    return {"parent": parent, "image": image, "session": session, "creation": creation, "live": live}


def native_processes():
    """The streaming row's console: the client, its own restart child, and the helper."""
    return {CLIENT: process(WORKER, creation=BIRTH), RESTART: process(CLIENT),
            HELPER: process(WORKER, PYTHON, creation=BIRTH + 27000000),
            WORKER: process(7068, PYTHON, creation=BIRTH - 9000000), SERVE: process(WORKER, creation=BIRTH - 3000000)}


class Call:
    """One logical kernel export: its argtypes and restype may be set; it is only called here."""
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class ConsoleKernel:
    """A logical console and process table. Its integers are never given to a real Win32 call."""
    def __init__(self, processes, console, *, closing=None, submit=True):
        self.processes, self.console, self.closing, self.submit = processes, list(console), closing, submit
        self.handles, self.snapshots, self.cursor, self.closed = {}, {}, {}, []
        self.signals, self.lists, self.violations = 0, 0, []
        exports = dict(OpenProcess=self.open, CloseHandle=self.close, GetProcessTimes=self.times,
            WaitForSingleObject=self.wait, ProcessIdToSessionId=self.session, FreeConsole=lambda: 1,
            AttachConsole=lambda pid: int(pid == CLIENT), GetConsoleProcessList=self.members,
            SetConsoleCtrlHandler=lambda routine, add: int((routine, add) == (None, True)),
            GenerateConsoleCtrlEvent=self.generate, CreateToolhelp32Snapshot=self.snapshot,
            Process32FirstW=self.first, Process32NextW=self.next, QueryFullProcessImageNameW=self.image)
        for name, function in exports.items():
            setattr(self, name, Call(function))

    def open(self, access, inherit, pid):
        if (access, inherit) != (0x101000, False):
            self.violations.append(("OpenProcess", access, inherit))
            return 0
        if pid not in self.processes:
            return 0
        handle = 0x7000 + 4 * len(self.handles)
        self.handles[handle] = pid
        return handle

    def close(self, handle):
        if handle not in self.handles and handle not in self.snapshots or handle in self.closed:
            self.violations.append(("CloseHandle", handle))
            return 0
        self.closed.append(handle)
        return 1

    def times(self, handle, creation, *_):
        if handle not in self.handles:
            self.violations.append(("GetProcessTimes", handle))
            return 0
        value = self.processes[self.handles[handle]]["creation"]
        creation._obj.dwLowDateTime, creation._obj.dwHighDateTime = value & 0xFFFFFFFF, value >> 32
        return 1

    def wait(self, handle, milliseconds):
        if milliseconds != 0 or handle not in self.handles:
            self.violations.append(("WaitForSingleObject", handle, milliseconds))
            return 0xFFFFFFFF
        return 0x102 if self.processes[self.handles[handle]]["live"] else 0

    def session(self, pid, result):
        if pid not in self.processes:
            return 0
        result._obj.value = self.processes[pid]["session"]
        return 1

    def members(self, values, bound):
        self.lists += 1
        current = self.closing if self.closing is not None and self.lists > 1 else self.console
        for index, value in enumerate(current):
            values[index] = value
        return len(current)

    def generate(self, event, group):
        if (event, group) != (0, 0):
            self.violations.append(("GenerateConsoleCtrlEvent", event, group))
        self.signals += 1
        return int(self.submit)

    def snapshot(self, flags, pid):
        if (flags, pid) != (2, 0):
            self.violations.append(("CreateToolhelp32Snapshot", flags, pid))
            return ctypes_invalid()
        handle = 0x9000 + 4 * len(self.snapshots)
        self.snapshots[handle] = sorted(self.processes)
        return handle

    def first(self, handle, entry):
        self.cursor[handle] = 0
        return self.next(handle, entry)

    def next(self, handle, entry):
        if handle not in self.snapshots or entry._obj.size != streaming_cases.ctypes.sizeof(type(entry._obj)):
            self.violations.append(("Process32", handle))
            return 0
        rows, index = self.snapshots[handle], self.cursor[handle]
        if index >= len(rows):
            return 0
        self.cursor[handle] = index + 1
        row = self.processes[rows[index]]
        entry._obj.pid, entry._obj.parentPid = rows[index], row["parent"]
        entry._obj.name = PureWindowsPath(row["image"]).name
        return 1

    def image(self, handle, flags, text, length):
        if handle not in self.handles or flags != 0:
            self.violations.append(("QueryFullProcessImageNameW", handle, flags))
            return 0
        path = self.processes[self.handles[handle]]["image"]
        text.value = path
        length._obj.value = len(path)
        return 1


def ctypes_invalid():
    return streaming_cases.ctypes.c_void_p(-1).value


def helper_patches(module, kernel, root, output=None):
    patches = [mock.patch.object(module.ctypes, "WinDLL", return_value=kernel, create=True),
               mock.patch.object(module, "os", types.SimpleNamespace(name="nt", getpid=lambda: HELPER, fsync=os.fsync)),
               mock.patch.object(module.time, "sleep", return_value=None),
               mock.patch.object(Path, "cwd", return_value=root)]
    if output is not None:
        patches.append(mock.patch.object(module, "sys", output))
    return patches


def run_helper(module, kernel, root):
    patches = helper_patches(module, kernel, root)
    for patch in patches:
        patch.start()
    try:
        return module.interrupt_owned_console(CLIENT, str(BIRTH), SESSION, WORKER, SERVE,
                                              root / "child-0010.ctrl-c.intent.json")
    finally:
        for patch in reversed(patches):
            patch.stop()


def run_main(module, kernel, root, *extra):
    """The helper's real main(): its exit code and the bytes it wrote to stdout and stderr."""
    output = types.SimpleNamespace(stdout=types.SimpleNamespace(buffer=io.BytesIO()),
                                   stderr=types.SimpleNamespace(buffer=io.BytesIO()))
    patches = [*helper_patches(module, kernel, root, output), *extra]
    for patch in patches:
        patch.start()
    try:
        code = module.main(["--interrupt-owned-console", str(CLIENT), str(BIRTH), str(SESSION), str(WORKER),
                            str(SERVE), str(root / "child-0010.ctrl-c.intent.json")])
    finally:
        for patch in reversed(patches):
            patch.stop()
    return code, output.stdout.buffer.getvalue(), output.stderr.buffer.getvalue()


class ShortIntent:
    """The intent the helper opens create-only, whose one write stores all but its last byte."""
    def __init__(self, raw):
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *failure):
        self.raw.close()

    def write(self, data):
        return self.raw.write(data[:-1])

    def fileno(self):
        return self.raw.fileno()


def identity(pid, processes):
    row = processes[pid]
    return {"pid": pid, "parentPid": row["parent"], "image": PureWindowsPath(row["image"]).name, "sessionId": row["session"]}


class ConsoleFenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def fresh(self):
        return Path(tempfile.mkdtemp(dir=self.root))

    def console_oracle(self, module):
        """The native console: client, its restart child and the helper. One signal, one intent."""
        root, processes = self.fresh(), native_processes()
        kernel = ConsoleKernel(processes, [CLIENT, RESTART, HELPER])
        receipt = run_helper(module, kernel, root)
        restart = {"pid": RESTART, "parentPid": CLIENT, "image": "vpn-control-cli.exe", "sessionId": SESSION,
                   "creationFileTime": str(BIRTH + 23000)}
        self.assertEqual(("signal-submitted", [RESTART, CLIENT, HELPER], restart, 1),
                         (receipt["state"], receipt["consolePids"], receipt["restartChild"], receipt["signalAttempts"]))
        intent = json.loads((root / "child-0010.ctrl-c.intent.json").read_bytes())
        self.assertEqual(("intent", 1, restart), (intent["state"], intent["signalAttempts"], intent["restartChild"]))
        self.assertEqual((1, []), (kernel.signals, kernel.violations))
        self.assertEqual(set(kernel.handles) | set(kernel.snapshots), set(kernel.closed))

    def record_oracle(self, module):
        """A refusal is one finite stderr record naming each member, never a traceback."""
        root, processes = self.fresh(), native_processes()
        processes[4404] = process(1200, r"C:\Windows\explorer.exe", creation=BIRTH - 5)
        kernel = ConsoleKernel(processes, [CLIENT, HELPER, 4404])
        code, stdout, stderr = run_main(module, kernel, root)
        self.assertEqual((1, b""), (code, stdout))
        self.assertEqual({"schemaVersion": 1, "state": "refused", "reason": "only-owned-console-members",
                          "intentCreated": False, "signalAttempted": False,
                          "consoleMembers": [identity(pid, processes) for pid in sorted((CLIENT, HELPER, 4404))],
                          "replayAllowed": False}, json.loads(stderr))
        self.assertEqual((0, False, []), (kernel.signals, (root / "child-0010.ctrl-c.intent.json").exists(),
                                          kernel.violations))

    def test_the_launchers_restart_child_is_admitted_as_the_one_third_member(self):
        before = before_streaming(self)
        # RED: the preserved helper refused exactly as the native row did, before any intent or signal.
        with self.assertRaisesRegex(AssertionError, "only-two-owned-console-members"):
            self.console_oracle(before)
        self.console_oracle(streaming_cases)

    def test_a_refusal_names_every_member_in_one_finite_stderr_record(self):
        before = before_streaming(self)
        with self.assertRaisesRegex(AssertionError, "only-two-owned-console-members"):
            self.record_oracle(before)  # The preserved helper raised; its stderr had only a traceback.
        self.record_oracle(streaming_cases)

    def test_every_other_member_still_refuses_before_any_intent_or_signal(self):
        launcher_elsewhere = r"C:\Users\winparityUser\Downloads\vpn-control-cli.exe"
        gui = r"C:\Users\winparityUser\AppData\Local\vpn-control\vpn-control.exe"
        controls = {
            "foreign-member": ({4404: process(1200, r"C:\Windows\explorer.exe")}, [CLIENT, HELPER, 4404], None),
            "non-child": ({4404: process(WORKER)}, [CLIENT, HELPER, 4404], None),
            "different-image": ({4404: process(CLIENT, gui)}, [CLIENT, HELPER, 4404], None),
            "same-name-other-folder": ({4404: process(CLIENT, launcher_elsewhere)}, [CLIENT, HELPER, 4404], None),
            "other-session": ({4404: process(CLIENT, session=SESSION + 1)}, [CLIENT, HELPER, 4404], None),
            "born-before-the-client": ({4404: process(CLIENT, creation=BIRTH - 1)}, [CLIENT, HELPER, 4404], None),
            "born-with-the-client": ({4404: process(CLIENT, creation=BIRTH)}, [CLIENT, HELPER, 4404], None),
            "ended-restart-child": ({RESTART: process(CLIENT, live=False)}, [CLIENT, HELPER, RESTART], None),
            "two-restart-children": ({4404: process(CLIENT)}, [CLIENT, HELPER, RESTART, 4404], None),
            "unopenable-member": ({}, [CLIENT, HELPER, 4404], None),
            "helper-not-attached": ({}, [CLIENT, RESTART], None),
            "closing-change": ({4404: process(1200, r"C:\Windows\explorer.exe")}, [CLIENT, HELPER, RESTART],
                               [CLIENT, HELPER, RESTART, 4404]),
        }
        for label, (changes, console, closing) in controls.items():
            with self.subTest(label=label):
                root, processes = self.fresh(), native_processes()
                processes.update(changes)
                if label == "unopenable-member":
                    processes.pop(4404, None)
                kernel = ConsoleKernel(processes, console, closing=closing)
                with self.assertRaises(streaming_cases.ConsoleRefused) as refused:
                    run_helper(streaming_cases, kernel, root)
                reason = "console-membership-closing-changed" if closing else "only-owned-console-members"
                self.assertEqual(reason, str(refused.exception))
                shown = closing or console
                self.assertEqual([member["pid"] for member in refused.exception.members], sorted(shown))
                for member in refused.exception.members:
                    if member["pid"] in processes:
                        self.assertEqual(identity(member["pid"], processes), member)
                    else:
                        self.assertEqual({"pid": member["pid"], "parentPid": None, "image": None, "sessionId": None}, member)
                self.assertEqual((0, False, []), (kernel.signals, (root / "child-0010.ctrl-c.intent.json").exists(),
                                                  kernel.violations))
                self.assertEqual(set(kernel.handles) | set(kernel.snapshots), set(kernel.closed))

    def test_an_uncertain_signal_still_forbids_a_second_attempt_with_three_members(self):
        root = self.fresh()
        kernel = ConsoleKernel(native_processes(), [CLIENT, RESTART, HELPER], submit=False)
        with self.assertRaisesRegex(AssertionError, "owned-console-ctrl-c-submit"):
            run_helper(streaming_cases, kernel, root)
        original = (root / "child-0010.ctrl-c.intent.json").read_bytes()
        with self.assertRaises(FileExistsError):
            run_helper(streaming_cases, kernel, root)
        self.assertEqual((1, original), (kernel.signals, (root / "child-0010.ctrl-c.intent.json").read_bytes()))

    def test_a_failure_once_the_intent_exists_is_recorded_unknown_never_refused(self):
        # The record says what was done: the create-only intent exists, and whether the one signal
        # call was made. An attempted signal whose call failed may still have been delivered.
        short = mock.patch.object(Path, "open", lambda path, *args, **options: ShortIntent(io.open(path, *args, **options)))
        controls = {"signal-call-failed": (False, (), True, "owned-console-ctrl-c-submit"),
                    "short-intent-write": (True, (short,), False, "console-intent-full-write")}
        for label, (submit, extra, attempted, reason) in controls.items():
            with self.subTest(label=label):
                root = self.fresh()
                kernel = ConsoleKernel(native_processes(), [CLIENT, RESTART, HELPER], submit=submit)
                code, stdout, stderr = run_main(streaming_cases, kernel, root, *extra)
                self.assertEqual((1, b""), (code, stdout))
                self.assertEqual({"schemaVersion": 1, "state": "unknown", "reason": reason, "intentCreated": True,
                                  "signalAttempted": attempted, "consoleMembers": None, "replayAllowed": False},
                                 json.loads(stderr))
                self.assertEqual((int(attempted), True, []), (kernel.signals,
                                 (root / "child-0010.ctrl-c.intent.json").exists(), kernel.violations))


# ---- Owner and guest peers for the case module and the generic owner path ----------------


class Parked(BaseException):
    """Stands in for the owner's park, which never returns."""


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class GuestChild:
    """One inert child with a declared outcome; never a native process."""
    def __init__(self, guest, owner, label, argv, new_console):
        self.guest, self.owner, self.label, self.argv = guest, owner, label, tuple(argv)
        self.new_console, self.ordinal = new_console, len(owner.children)
        self.pid, self.birth = 5000 + 4 * self.ordinal, str(BIRTH + 1000 * self.ordinal)
        self.terminal, self.outcome = None, None
        self.eof = {"stdout": False, "stderr": False}
        self.process = types.SimpleNamespace(poll=self.poll, _handle=self.pid)
        guest.births[self.pid] = self.birth
        for name in ("stdout", "stderr"):
            (owner.root / f"child-{self.ordinal:04d}.{name}.raw").write_bytes(b"")

    def ended(self):
        if self.outcome is None:
            self.outcome = self.guest.outcome(self)
        return self.outcome

    def poll(self):
        outcome = self.ended()
        return None if outcome is None else outcome[0]

    def observe(self):
        if self.terminal is None and self.ended() is not None:
            code, stdout, stderr = self.outcome
            for name, text in (("stdout", stdout), ("stderr", stderr)):
                (self.owner.root / f"child-{self.ordinal:04d}.{name}.raw").write_bytes(text.encode())
            self.eof = {"stdout": True, "stderr": True}
            self.terminal = {"child": self.ordinal, "pid": self.pid, "birthFileTimeUtc": self.birth, "exitCode": code,
                             "eof": dict(self.eof), "sourceClosing": True, "originalHandleRetained": True}
            self.guest.trace.append(("terminal", self.label, code))
        return self.terminal

    def wait(self):
        if self.observe() is None:
            raise RuntimeError("peer-wait-on-a-live-child")
        return self.terminal

    def completed(self):
        terminal = self.wait()
        return subprocess.CompletedProcess(self.argv, terminal["exitCode"], self.outcome[1], self.outcome[2])


class Guest:
    """The product as the owner's children see it, in the shapes the native rows recorded."""
    def __init__(self, root, *, quit_answer="ok", serve_exits=True, stream_exits=True, helper="native-refusal"):
        self.root, self.cli = root, LAUNCHER
        self.quit_answer, self.serve_exits, self.stream_exits = quit_answer, serve_exits, stream_exits
        self.runtime_running, self.helper, self.receipt_changes, self.signalled = False, helper, None, False
        self.controllers, self.quits, self.trace, self.births = {}, [], [], {}
        self.parks, self.finished, self.events = [], [], []
        # workspace -> seconds until its serve exits after a quit whose reply is lost, or None: never.
        self.lost_replies, self.late_exits = {}, {}
        self.clock = Clock()

    def envelope(self, code, controller, data=None, **extra):
        body = {"schemaVersion": 1, "controllerId": controller, "requestId": str(uuid.uuid4()), "ok": code == "OK",
                "code": code, "final": True, "operationId": None, "configurationRevision": 43,
                "restartRequired": False, "data": data if data is not None else {}, "warnings": []}
        body.update(extra)
        return json.dumps(body) + "\n"

    def serve_of(self, workspace):
        return next((child for child in self.owner_object.children if child.argv[1:] == ("--state-dir", workspace, "serve")
                     and child.argv[0] == self.cli), None)

    def outcome(self, child):
        argv = child.argv
        if child.label in ("help", "version"):
            return 0, "Usage: vpn-control [options] <command>\n" if child.label == "help" else "2.2.16\n", ""
        if child.label == "owned-console-interrupter":
            return self.helper_outcome(child)
        if argv[-1] == "serve":
            if self.serve_exits and (argv[2] in self.quits or self.clock.now >= self.late_exits.get(argv[2], float("inf"))):
                return 0, "", "VPN Control headless service is ready.\n"
            return None
        if child.label.startswith("stream-"):
            serve = self.serve_of(argv[2])
            if self.signalled:
                return 130, "", ""
            if self.stream_exits and serve is not None and serve.ended() is not None:
                return 2, "", "UNAVAILABLE\n"  # Its own close: the next poll finds no owner.
            return None
        return self.public(argv)

    def public(self, argv):
        workspace, rest = argv[2], list(argv[3:])
        serve = self.serve_of(workspace)
        controller = self.controllers.get(workspace) if serve is not None and serve.ended() is None else None
        if "import" in rest:
            return None  # A guarded write whose process has not ended yet.
        if rest in (["--json", "status"], ["--json", "--controller-id", controller, "status"]):
            if controller is None:
                return 2, self.envelope("UNAVAILABLE", None), ""
            return 0, self.envelope("OK", controller, {"runtimeRunning": self.runtime_running}), ""
        if rest[:3] == ["--json", "--controller-id", controller] and rest[3:] == ["quit"]:
            self.trace.append(("quit", workspace))
            if self.quit_answer == "busy":
                return 1, self.envelope("BUSY", controller), ""
            if workspace in self.lost_replies:
                # The client never got this quit's reply. Its effect, if any, is an exit some seconds later.
                delay = self.lost_replies.pop(workspace)
                if delay is not None:
                    self.late_exits[workspace] = self.clock.now + delay
                return 2, self.envelope("OUTCOME_UNKNOWN", controller), ""
            self.quits.append(workspace)
            return 0, self.envelope("OK", controller, operationId=str(uuid.uuid4())), ""
        if rest[:4] == ["--controller-id", controller, "--if-revision", "43"] and rest[4:7] == ["routing", "set", "direct-domains"]:
            # The quoted JSON reached the JVM unquoted: the parser refused it (operation 98c8c95a).
            return 1, "", ("INVALID_ARGUMENT\nController: " + controller + "\nRequest: " + str(uuid.uuid4())
                           + "\nRevision: 43\nCompletion: final\nOperation: " + str(uuid.uuid4()) + "\nRestart required: no\n")
        raise LookupError("unmodelled public call: " + " ".join(rest))  # Never mistaken for a case oracle.

    def helper_outcome(self, child):
        if self.helper == "live":
            return None
        if self.helper == "native-refusal":
            return 1, "", ("Traceback (most recent call last):\n  File \"windows_streaming_cli_cases.py\", line 296, in members\n"
                           "AssertionError: only-two-owned-console-members\n")
        client = int(child.argv[3])
        receipt = {"schemaVersion": 1, "state": "signal-submitted", "pid": client, "birthFileTimeUtc": child.argv[4],
                   "sessionId": SESSION, "consolePids": sorted([client, child.pid, RESTART]),
                   "restartChild": {"pid": RESTART, "parentPid": client, "image": "vpn-control-cli.exe", "sessionId": SESSION,
                                    "creationFileTime": str(int(child.argv[4]) + 23000)},
                   "workerPid": int(child.argv[6]), "servePid": int(child.argv[7]), "signalAttempts": 1, "replayAllowed": False}
        if self.receipt_changes is not None:
            receipt = self.receipt_changes(receipt)
        self.signalled = True
        return 0, json.dumps(receipt) + "\n", ""

    def owner(self, module, action, situation):
        owner = module.Owner.__new__(module.Owner)
        workspace = self.root / "workspace"
        owner.request = {"action": action, "cliPath": self.cli, "workspace": str(workspace), "casesPath": CASES,
                         "harnessPath": "held-harness.py", "productVersion": "2.2.16",
                         "context": {"ordinarySessionId": SESSION}, "pythonRuntime": {"interpreterPath": PYTHON}}
        owner.root, owner.children, owner.environment, owner.by_path = self.root, [], {}, {}
        owner.operation = "866c885f-27da-4a37-90c5-9dbc5861629d"
        owner.native = types.SimpleNamespace(birth=lambda handle: self.births[handle])
        guest = self
        self.owner_object = owner

        def child(label, argv, *, new_console=False, owned_desktop=None):
            self.trace.append(("submit", label, tuple(argv[3:])))
            value = GuestChild(guest, owner, label, argv, new_console)
            owner.children.append(value)
            if argv[-1] == "serve":
                self.controllers[argv[2]] = "c0ffee00-0000-4000-8000-%012d" % len(self.controllers)
            return value

        def park(reason, error=None):
            self.parks.append((reason, type(error).__name__ if error is not None else None))
            raise Parked(reason)

        def event(kind, value):
            self.events.append((kind, value))
            self.trace.append(("event", kind))

        def module_peer(path, name):
            if path == CASES:
                return types.SimpleNamespace(run=situation, fixed_full_cases=lambda workspace, identity, invoke, harness:
                                             situation(owner, workspace, identity, harness))
            return types.ModuleType("inert-held-harness")

        owner.child, owner.park, owner.event, owner.module = child, park, event, module_peer
        owner.guard = lambda: None
        owner.finish = lambda code, error=None: self.finished.append((code, type(error).__name__, str(error)))
        return owner


def run_owner(module, guest, action, situation):
    """The owner's real main and run, with an inert request pin, native and child custody."""
    owner = guest.owner(module, action, situation)
    raw = json.dumps(owner.request).encode()
    record = base64.b64encode(json.dumps({"path": "worker-request.json", "sha256": "a" * 64}).encode()).decode()
    pin = type("RequestPin", (), {"__init__": lambda self, native, record: None,
                                  "digest": lambda self, return_bytes=False, maximum=0: raw})
    argv = ["owner", "--request", "worker-request.json", "--request-sha256", "a" * 64, "--request-pin-base64", record]
    with mock.patch.object(module, "absolute", Path), mock.patch.object(module, "Native", lambda: object()), \
            mock.patch.object(module, "Pin", pin), mock.patch.object(module, "Owner", lambda request, request_pin: owner), \
            mock.patch.object(module, "time", guest.clock), mock.patch.object(module.sys, "argv", argv):
        return module.main()


def disconnected_failure(owner, workspace, identity, harness):
    """The native failing step: the human guarded routing write the product refused."""
    root = owner.root / "case files"
    root.mkdir()
    disconnected_cases.Cases(owner, workspace, identity, harness, root).human(
        "routing", "set", "direct-domains", '["Example.test"]', revision=43)


def held_harness():
    """The unchanged packaged CLI harness the owner holds, loaded by its fixed path: its envelope oracle."""
    spec = importlib.util.spec_from_file_location("_native_failures_packaged_cli_harness",
                                                  Path(__file__).resolve().parents[2] / "scripts/test_packaged_cli.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__dict__


def transfer_quit_lost(owner, workspace, identity, harness):
    """independent_transfer's own close of the second serve it started: one status, then its one quit."""
    transfer = owner.root / "transfer workspace"
    owner.child("disconnected-transfer-serve", [owner.request["cliPath"], "--state-dir", str(transfer), "serve"])
    held = held_harness()
    second = disconnected_cases.Cases(owner, transfer, held["envelope"](owner.invoke(transfer, "--json", "status"))
                                      ["controllerId"], held, owner.root)
    second.status()
    second.json("quit")  # Its reply is lost: the held envelope oracle fails on the exit 2.


def stream_client(owner, workspace, identity):
    serve = next(child for child in owner.children if child.label == "serve")
    client = owner.child("stream-status-json", [owner.request["cliPath"], "--state-dir", str(workspace),
                         "--controller-id", identity, "--json", "status", "--watch"], new_console=True)
    return serve, client


def streaming_failure(owner, workspace, identity, harness):
    """The native failing step: the console helper refused while the stream client ran."""
    serve, client = stream_client(owner, workspace, identity)
    streaming_cases._interrupt(owner, client, serve)


class KnownFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def guest(self, **options):
        return Guest(Path(tempfile.mkdtemp(dir=self.root)), **options)

    def kinds(self, guest):
        return [row for row in guest.trace if row[0] in ("event", "submit") and (row[0] == "submit" or
                row[1].startswith("known-failure"))]

    def closed_oracle(self, module, action, situation, reason, ends):
        """The owner closes what it started, by the journaled quit and own closes, and exits 1."""
        guest = self.guest()
        self.assertEqual(1, run_owner(module, guest, action, situation))
        self.assertEqual(([], [(1, "AssertionError", reason)]), (guest.parks, guest.finished))
        owner = guest.owner_object
        self.assertTrue(all(child.terminal is not None for child in owner.children))
        self.assertEqual(ends, {child.label: child.terminal["exitCode"] for child in owner.children
                                if child.label in ends})
        quits = [row for row in guest.trace if row[0] == "submit" and row[2][-1:] == ("quit",)]
        self.assertEqual(1, len(quits))  # Never replayed.
        order = [row[1] if row[0] == "event" else "quit-submitted" for row in self.kinds(guest)
                 if row[0] == "event" or row in quits]
        self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "quit-submitted",
                          "known-failure-serve-closed", "known-failure-closed"], order)
        closing = dict(guest.events)["known-failure-closing"]
        self.assertEqual((action, reason, False), (closing["action"], closing["reason"], closing["replayAllowed"]))
        return guest

    def test_a_known_disconnected_failure_quits_the_owners_serve_and_ends_one(self):
        oracle = lambda module: self.closed_oracle(module, "disconnected-cli-config", disconnected_failure,
                                                   "human-exit-code", {"serve": 0})
        with self.assertRaisesRegex(Parked, "scenario-failure-with-retained-child"):
            oracle(before_owner(self))  # RED: the native park, with only the serve running.
        oracle(process_owner)

    def test_a_known_streaming_failure_quits_the_serve_and_the_client_ends_by_its_own_close(self):
        oracle = lambda module: self.closed_oracle(module, "streaming-client-interrupt", streaming_failure,
            "owned-console-helper-failed", {"serve": 0, "stream-status-json": 2, "owned-console-interrupter": 1})
        with self.assertRaisesRegex(Parked, "scenario-failure-with-retained-child"):
            oracle(before_owner(self))  # RED: the native park, with the serve and the client running.
        guest = oracle(process_owner)
        helpers = [row for row in guest.trace if row[0] == "submit" and row[1] == "owned-console-interrupter"]
        self.assertEqual(1, len(helpers))  # The closing never signals again.

    def test_a_second_serve_a_case_started_is_quit_first_by_the_controller_its_status_names(self):
        def transfer_failure(owner, workspace, identity, harness):
            owner.child("disconnected-transfer-serve", [owner.request["cliPath"], "--state-dir",
                        str(owner.root / "transfer workspace"), "serve"])
            disconnected_failure(owner, workspace, identity, harness)
        guest = self.guest()
        self.assertEqual(1, run_owner(process_owner, guest, "disconnected-cli-config", transfer_failure))
        self.assertEqual([], guest.parks)
        transfer, primary = str(guest.root / "transfer workspace"), str(guest.root / "workspace")
        self.assertEqual([transfer, primary], guest.quits)
        closing = guest.trace.index(("event", "known-failure-closing"))
        public = [row[2] for row in guest.trace[closing:] if row[0] == "submit"]
        second, first = guest.controllers[transfer], guest.controllers[primary]
        self.assertEqual([("--json", "status"), ("--json", "--controller-id", second, "quit"),
                          ("--json", "--controller-id", first, "status"), ("--json", "--controller-id", first, "quit")],
                         public)
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))

    def test_a_serve_the_case_already_quit_is_awaited_and_never_quit_again(self):
        guest = self.guest()
        transfer, primary = str(guest.root / "transfer workspace"), str(guest.root / "workspace")
        guest.lost_replies[transfer] = 5  # That quit took effect: its serve exits 5 s later.
        self.assertEqual(1, run_owner(process_owner, guest, "disconnected-cli-config", transfer_quit_lost))
        # The case's own quit, whose outcome was unknown, is never replayed.
        self.assertEqual([("quit", transfer), ("quit", primary)], [row for row in guest.trace if row[0] == "quit"])
        self.assertEqual(([], (1, "AssertionError", "CLI exit 2, expected 0")),
                         (guest.parks, (*guest.finished[0][:2], guest.finished[0][2][:22])))
        owner = guest.owner_object
        second = next(child for child in owner.children if child.label == "disconnected-transfer-serve")
        first = next(child for child in owner.children if child.label == "serve")
        case_quit = [child.ordinal for child in owner.children if child.argv[-1] == "quit" and child.argv[2] == transfer]
        closing = guest.trace.index(("event", "known-failure-closing"))
        self.assertEqual(["known-failure-closing", "known-failure-serve-closed", "known-failure-quit-intent",
                          "known-failure-serve-closed", "known-failure-closed"],
                         [row[1] for row in guest.trace[closing:] if row[0] == "event" and row[1].startswith("known-failure")])
        events = [value for kind, value in guest.events if kind.startswith("known-failure")]
        self.assertEqual(([first.ordinal], [second.ordinal]), (events[0]["quit"], events[0]["caseQuit"]))
        self.assertEqual((second.ordinal, None, case_quit, 0), (events[1]["child"], events[1]["controllerId"],
                         events[1]["caseQuitChildren"], events[1]["terminal"]["exitCode"]))
        self.assertTrue(all(child.terminal is not None for child in owner.children))

    def test_a_serve_the_case_already_quit_that_never_exits_parks_without_another_quit(self):
        guest = self.guest()
        transfer = str(guest.root / "transfer workspace")
        guest.lost_replies[transfer] = None  # Its reply was lost, and it never exits.
        self.parked(guest, "disconnected-cli-config", transfer_quit_lost, "known-failure-case-quit-exit-unknown")
        self.assertEqual([("quit", transfer)], [row for row in guest.trace if row[0] == "quit"])
        self.assertGreaterEqual(guest.clock.now - 1000.0, process_owner.KNOWN_FAILURE_EXIT_SECONDS)

    def parked(self, guest, action, situation, reason):
        with self.assertRaises(Parked):
            run_owner(process_owner, guest, action, situation)
        self.assertEqual(reason, guest.parks[0][0])
        self.assertEqual([], guest.finished)
        return [row for row in guest.trace if row[0] == "submit" and row[2][-1:] == ("quit",)]

    def test_a_refused_quit_parks_and_is_never_sent_again(self):
        guest = self.guest(quit_answer="busy")
        quits = self.parked(guest, "disconnected-cli-config", disconnected_failure, "known-failure-quit-not-acknowledged")
        self.assertEqual(1, len(quits))
        self.assertIsNone(next(child for child in guest.owner_object.children if child.label == "serve").terminal)

    def test_a_serve_that_does_not_exit_after_its_quit_parks(self):
        guest = self.guest(serve_exits=False)
        self.assertEqual(1, len(self.parked(guest, "disconnected-cli-config", disconnected_failure,
                                            "known-failure-serve-exit-unknown")))
        self.assertGreaterEqual(guest.clock.now - 1000.0, process_owner.KNOWN_FAILURE_EXIT_SECONDS)

    def test_a_stream_client_that_does_not_end_after_its_owner_parks(self):
        guest = self.guest(stream_exits=False)
        self.assertEqual(1, len(self.parked(guest, "streaming-client-interrupt", streaming_failure,
                                            "known-failure-stream-exit-unknown")))

    def test_a_quit_is_not_sent_unless_status_admits_it(self):
        guest = self.guest()

        def running_runtime(owner, workspace, identity, harness):
            guest.runtime_running = True  # Not the disconnected owner a pass quits.
            disconnected_failure(owner, workspace, identity, harness)
        self.assertEqual([], self.parked(guest, "disconnected-cli-config", running_runtime,
                                         "known-failure-quit-admission"))

    def test_a_still_running_effect_parks_before_any_quit(self):
        def running_write(owner, workspace, identity, harness):
            owner.child("public-cli", [owner.request["cliPath"], "--state-dir", str(workspace), "--json", "--controller-id",
                        identity, "--if-revision", "43", "routing", "import", "--input", "large.json"])
            raise AssertionError("case-oracle-while-a-write-runs")

        def running_helper(owner, workspace, identity, harness):
            serve, client = stream_client(owner, workspace, identity)
            owner.child("owned-console-interrupter", [PYTHON, CASES, "--interrupt-owned-console"])
            raise AssertionError("case-oracle-while-the-helper-runs")

        for situation, action, options in ((running_write, "disconnected-cli-config", {}),
                                           (running_helper, "streaming-client-interrupt", {"helper": "live"})):
            with self.subTest(situation=situation.__name__):
                guest = self.guest(**options)
                self.assertEqual([], self.parked(guest, action, situation, "known-failure-child-outcome-open"))
                self.assertNotIn("known-failure-closing", dict(guest.events))

    def test_an_unknown_error_keeps_every_child_for_the_park(self):
        def unknown(owner, workspace, identity, harness):
            raise RuntimeError("case-outcome-unknown")
        guest = self.guest()
        self.assertEqual([], self.parked(guest, "disconnected-cli-config", unknown, "scenario-failure-with-retained-child"))
        self.assertNotIn("known-failure-closing", dict(guest.events))

    def test_only_the_two_cli_case_actions_close_a_known_failure(self):
        # Their modules start children only through this owner. The source-mode and document
        # actions keep the park: their case modules were not reviewed for a closing.
        self.assertEqual(frozenset({"disconnected-cli-config", "streaming-client-interrupt"}),
                         process_owner.KNOWN_FAILURE_ACTIONS)
        guest = self.guest()
        self.assertEqual([], self.parked(guest, "fixed-source-mode", disconnected_failure,
                                         "scenario-failure-with-retained-child"))
        self.assertNotIn("known-failure-closing", dict(guest.events))


class ReceiptTests(unittest.TestCase):
    """What the case then waits for: the client launcher's own exit after its JVM took the signal."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def interrupt(self, module, changes=None):
        guest = Guest(Path(tempfile.mkdtemp(dir=self.root)), helper="receipt")
        guest.receipt_changes = changes
        owner = guest.owner(process_owner, "streaming-client-interrupt", None)
        workspace = guest.root / "workspace"
        owner.child("serve", [LAUNCHER, "--state-dir", str(workspace), "serve"])
        serve, client = stream_client(owner, workspace, guest.controllers[str(workspace)])
        return module._interrupt(owner, client, serve), guest

    def receipt_oracle(self, module):
        terminal, guest = self.interrupt(module)
        self.assertEqual((130, {"stdout": True, "stderr": True}), (terminal["exitCode"], terminal["eof"]))
        closed = dict(guest.events)["stream-interrupt-closed"]
        self.assertEqual(RESTART, closed["consoleReceipt"]["restartChild"]["pid"])

    def test_the_receipt_with_the_restart_child_is_accepted_and_the_client_exit_awaited(self):
        with self.assertRaisesRegex(AssertionError, "owned-console-helper-receipt"):
            self.receipt_oracle(before_streaming(self))
        self.receipt_oracle(streaming_cases)

    def test_a_receipt_naming_any_other_third_process_is_refused(self):
        def restart(**changes):
            return lambda receipt: {**receipt, "restartChild": {**receipt["restartChild"], **changes}}
        controls = {
            "not-the-clients-child": restart(parentPid=WORKER),
            "other-image": restart(image="vpn-control.exe"),
            "other-session": restart(sessionId=SESSION + 1),
            "born-with-the-client": lambda receipt: {**receipt, "restartChild": {**receipt["restartChild"],
                                                    "creationFileTime": receipt["birthFileTimeUtc"]}},
            "the-serve": lambda receipt: {**receipt, "restartChild": {**receipt["restartChild"], "pid": receipt["servePid"]},
                                          "consolePids": sorted([receipt["servePid"], *(pid for pid in receipt["consolePids"]
                                                                                       if pid != RESTART)])},
            "extra-field": restart(note="x"),
            "member-list-without-it": lambda receipt: {**receipt, "consolePids": [pid for pid in receipt["consolePids"]
                                                                                   if pid != RESTART]},
            "withheld-with-three-members": lambda receipt: {**receipt, "restartChild": None},
            "no-restart-key-two-members": lambda receipt: {**{key: value for key, value in receipt.items()
                                                              if key != "restartChild"},
                                                           "consolePids": [pid for pid in receipt["consolePids"] if pid != RESTART]},
        }
        for label, change in controls.items():
            with self.subTest(label=label), self.assertRaisesRegex(AssertionError, "owned-console-helper-receipt"):
                self.interrupt(streaming_cases, change)


if __name__ == "__main__":
    unittest.main()
