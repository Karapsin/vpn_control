"""The explicit settle of an owned clone's ordinary desktop: at most two Esc keys, and only at a shell surface.

a75acf02 (NG4, Start) and adae4153 (NG5, SearchHost.exe pid 5836) show a fresh profile keeping a shell surface in the
foreground by itself, so every prompting row refuses (windows_ordinary_process_owner.interactive_desktop). No VM, host
or guest here: the real flows run over a small model of the console, whose foreground a shell surface may hold until an
Esc dismisses it. Nothing here proves a Windows, Task Scheduler, pythonw or QEMU behaviour; only a native run does.
"""
import base64
from contextlib import nullcontext
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid
import zlib

from agent_tools import readiness_windows  # Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import ssh_transport as transport
from agent_tools import windows_ordinary_process_owner as owner_rules
from agent_tools import windows_uac_decision as uac
from agent_tools.tests.test_native_vm_spec import request as vm_request
from agent_tools.tests.test_windows_idle_receipt_classes import Receipts, current_source

try:
    from agent_tools import windows_desktop_settle as settle
except ImportError:  # The unfixed tree has no such action: every test that needs it fails there.
    settle = None

MACHINE = "33333333-4444-4555-8666-777777777777"
OPERATION = "55555555-6666-4777-8888-999999999999"
USER_SID = "S-1-5-21-1-2-3-1004"
WIDTH, HEIGHT = 64, 40
SETUP = {"imageName": "Windows 11 Pro", "locale": "en-US", "user": "fixtureuser", "administrator": "fixtureadmin"}
POSIX = os.name == "posix"
CLEAN = {"lastTaskResult": 0, "stderr": "", "error": None}  # A probe that ran, exited 0 and wrote nothing to stderr.
START = {"pid": 5400, "className": "Windows.UI.Core.CoreWindow"}
SEARCH = {"pid": 5836, "className": "Windows.UI.Core.CoreWindow"}
IMAGES = {5400: "StartMenuExperienceHost.exe", 5836: "SearchHost.exe", 5600: "ShellExperienceHost.exe", 3300: "explorer.exe",
          4100: "powershell.exe"}


def absent():
    """The unfixed tree has no settle action: every test fails there instead of skipping."""
    if settle is None:
        raise AssertionError("windows_desktop_settle is absent")


def frame(kind):
    fill = {"start": 200, "search": 180, "desktop": 90}[kind]
    return b"P6\n%d %d\n255\n" % (WIDTH, HEIGHT) + bytes((fill, fill, fill)) * (WIDTH * HEIGHT)


class Console:
    """The ordinary session as the flow sees it: its foreground holders in order, each Esc dismissing a shell surface."""

    def __init__(self, holders=(START, None)):
        self.holders = list(holders)
        self.dismissed_by_esc = True
        self.keys = []
        self.calls = []
        self.labels = []
        self.sources = []
        self.session_changes = {}
        self.probe_changes = {}
        self.probe_error = None

    def holder(self):
        return self.holders[0]

    def monitor(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == "screendump":
            current = self.holder()
            kind = "desktop" if current is None or current["pid"] not in (5400, 5836) else ("start" if current["pid"] == 5400 else "search")
            Path(arguments["filename"]).write_bytes(frame(kind))
            return {}
        assert command == "send-key", command
        self.keys.append((tuple(key["data"] for key in arguments["keys"]), arguments["hold-time"]))
        current = self.holder()
        if self.dismissed_by_esc and current is not None and IMAGES.get(current["pid"], "").casefold() in owner_rules.SHELL_FOREGROUND:
            if len(self.holders) > 1:
                self.holders.pop(0)
        return {}

    def script(self, label, source):
        self.labels.append(label.rsplit("-", 1)[0] if label.startswith("login-") else label)
        self.sources.append(source)
        if label.startswith("login-session"):
            return {"machine": MACHINE.upper(), "boot": "2026-11-18T07:28:20.5000000Z", "console": 2, "expectedSid": USER_SID,
                    "tokenSid": USER_SID, "ordinary": True, "explorers": [{"Id": 3300, "SessionId": 2}],
                    "session": {"SessionId": 2, "State": 0, "Flags": 1, "User": "fixtureuser", "Logon": 5}, **self.session_changes}
        assert label.startswith("desktop-probe-"), label
        if self.probe_error is not None:
            raise self.probe_error
        current = self.holder()
        rows = [] if current is None else [{"pid": current["pid"], "parentPid": 700, "name": IMAGES[current["pid"]]}]
        return {"state": "observed", "reason": None, "window": None if current is None else dict(current), "probePid": 9100, "rows": rows,
                "cleaned": True, "lastTaskResult": 0, "stderr": "", "error": None, **self.probe_changes}


@unittest.skipUnless(POSIX, "the journals are POSIX; the VM host is Linux")
class FlowBase(unittest.TestCase):
    """Runs the real flow as the packet does, with the producer's own failure mapping."""

    def setUp(self):
        absent()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "vm"
        self.root.mkdir(mode=0o700)
        self.console = Console()
        self.clock = [100.0]

    def save(self, name, value):
        descriptor = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)

    def read(self, name):
        return json.loads((self.root / name).read_text())

    def guard(self):
        pass

    def tree(self):
        return sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*") if path.is_file())

    def classified(self):
        result = Receipts(self.root).run(current_source())
        return result["terminalCount"], sorted(row["reason"] for row in result["unresolved"])

    def run_flow(self, *, repeat=False):
        template = uac._PRELUDE + settle._PROBE
        values = {"SPEC": {"deploymentId": MACHINE}, "OPERATION": OPERATION, "SESSION_SCRIPT": "fixed session",
                  "DESKTOP_PROBE_TEMPLATE": template.replace("__CODE__", "'code'"), "DESKTOP_PROBE_REFUSALS": sorted(settle.PROBE_REFUSALS),
                  "DESKTOP_PROBE_STDERR_CHARS": settle.STDERR_CHARS, "DESKTOP_PROBE_ERROR_CHARS": settle.ERROR_CHARS,
                  "DESKTOP_SETTLE_ESC_LIMIT": settle.ESC_LIMIT, "DESKTOP_SETTLE_WAIT": settle.SETTLE_SECONDS,
                  }

        def sleep(seconds):
            self.clock[0] += seconds
        journal = settle._DesktopSettle(self.root, OPERATION)
        with mock.patch.dict(settle.__dict__, values), mock.patch.object(time, "sleep", sleep), mock.patch.object(time, "monotonic", lambda: self.clock[0]):
            try:
                if repeat:
                    return settle._desktop_settle_reply(journal, settle._desktop_settle_repeat(journal))
                return settle._desktop_settle_reply(journal, settle._desktop_settle(journal, self.root, self.save, self.read, self.console.monitor,
                                                                                  self.guard, self.console.script))
            except BaseException as error:
                reason = str(error) if type(error) is ValueError and re.fullmatch("instance_[a-z_]{1,64}", str(error)) else "instance_observation_unknown"
                return journal.reply(reason) or {"state": "blocked", "operationId": OPERATION, "reason": reason, "replayAllowed": False}

    def escs(self):
        return [codes for codes, _ in self.console.keys]


class SettleFlowTests(FlowBase):
    def test_native_start_menu_gets_one_esc_and_the_desktop_settles(self):
        """a75acf02 (NG4): Start held the foreground with no input, and the vpn-broker prompt went to the taskbar."""
        reply = self.run_flow()
        self.assertEqual(("desktop-settled", None, 1), (reply["state"], reply["reason"], reply["escapes"]))
        self.assertEqual([(("esc",), 80)], self.console.keys, "exactly one Esc, the reviewed hold, and nothing else")
        self.assertEqual([{"interactiveDesktop": {"foreground": {"pid": 5400, "image": "StartMenuExperienceHost.exe",
                                                                 "className": "Windows.UI.Core.CoreWindow", "owned": False}},
                           "unsettled": "shell-surface", **CLEAN},
                          {"interactiveDesktop": {"foreground": None}, "unsettled": None, **CLEAN}], reply["probes"])
        before, after = reply["frames"]
        self.assertEqual(("frame-before.ppm", hashlib.sha256(frame("start")).hexdigest()), (before["name"], before["sha256"]))
        self.assertEqual(("frame-after.ppm", hashlib.sha256(frame("desktop")).hexdigest()), (after["name"], after["sha256"]))
        self.assertEqual(frame("start"), zlib.decompress(base64.b64decode(reply["frameBytes"]["frame-before.ppm"])))
        self.assertEqual(["login-session", "desktop-probe-1", "desktop-probe-2"], self.console.labels)
        prefix = "windows-desktop-settle/" + OPERATION + "/"
        for name in ("settle.intent.json", "esc-1.intent.json", "frame-before.ppm", "frame-after.ppm", "settle.terminal.json"):
            self.assertIn(prefix + name, self.tree())
        self.assertEqual((1, []), self.classified(), "the fence closed: nothing is left open on the clone")

    def test_native_search_that_stays_after_one_esc_gets_a_second_and_never_a_third(self):
        """adae4153 (NG5): SearchHost.exe pid 5836 held the foreground."""
        self.console = Console((SEARCH, SEARCH, None))
        reply = self.run_flow()
        self.assertEqual(("desktop-settled", 2), (reply["state"], reply["escapes"]))
        self.assertEqual([("esc",), ("esc",)], self.escs())
        self.setUp()
        self.console.holders, self.console.dismissed_by_esc = [SEARCH], False
        reply = self.run_flow()
        self.assertEqual(("desktop-settle-refused", "desktop_settle_still_unsettled", 2), (reply["state"], reply["reason"], reply["escapes"]))
        self.assertEqual([("esc",), ("esc",)], self.escs(), "at most two Esc keys in all")
        self.assertEqual(3, len(reply["probes"]))
        self.assertEqual("frame-after.ppm", reply["frames"][-1]["name"])

    def test_an_already_settled_desktop_gets_no_key(self):
        for holder in (None, {"pid": 3300, "className": "Progman"}):
            with self.subTest(holder=holder):
                self.setUp()
                self.console.holders = [holder]
                reply = self.run_flow()
                self.assertEqual(("desktop-settled", 0, []), (reply["state"], reply["escapes"], self.console.keys))

    def test_any_other_unsettled_holder_is_named_and_gets_no_key(self):
        self.console.holders = [{"pid": 4100, "className": "ConsoleWindowClass"}]
        reply = self.run_flow()
        self.assertEqual(("desktop-settle-refused", "desktop_settle_holder_not_shell", 0, []),
                         (reply["state"], reply["reason"], reply["escapes"], self.console.keys))
        self.assertEqual({"foreground": {"pid": 4100, "image": "powershell.exe", "className": "ConsoleWindowClass", "owned": False}},
                         reply["probes"][0]["interactiveDesktop"])
        self.setUp()
        self.console.holders = [START, {"pid": 4100, "className": "ConsoleWindowClass"}]
        reply = self.run_flow()
        self.assertEqual(("desktop_settle_holder_not_shell", 1), (reply["reason"], reply["escapes"]), "no second Esc for a console")

    def test_a_probe_that_cannot_read_the_session_refuses_before_any_key(self):
        for reason in sorted(settle.PROBE_REFUSALS - {"desktop_probe_failed"}):
            with self.subTest(reason=reason):
                self.setUp()
                self.console.probe_changes = {"state": "refused", "reason": reason, "window": None, "probePid": None, "rows": [],
                                              "lastTaskResult": 1, "stderr": None}
                reply = self.run_flow()
                self.assertEqual(("desktop-settle-refused", reason, []), (reply["state"], reply["reason"], self.console.keys))
                self.assertEqual([{"refused": reason, "lastTaskResult": 1, "stderr": None, "error": None}], reply["probes"],
                                 "the task's own end is kept with the refusal")

    def test_native_probe_error_after_idle_is_kept_with_its_evidence_and_gets_no_key(self):
        """d80b34c1 (ND4, display asleep two days): the probe task ended Ready but wrote nothing, and the tool kept neither
        LastTaskResult nor stderr. The probe now always writes, so its own exception comes back typed with its evidence."""
        error = {"errorClass": "AssertionError", "message": "interactive-desktop-foreground-owner"}
        trace = "Traceback (most recent call last):\nAssertionError: interactive-desktop-foreground-owner\n"
        self.console.probe_changes = {"state": "refused", "reason": "desktop_probe_failed", "window": None, "probePid": 9100, "rows": [],
                                      "lastTaskResult": 0, "stderr": trace, "error": error}
        reply = self.run_flow()
        self.assertEqual(("desktop-settle-refused", "desktop_probe_failed", []), (reply["state"], reply["reason"], self.console.keys))
        self.assertEqual([{"refused": "desktop_probe_failed", "lastTaskResult": 0, "stderr": trace, "error": error}], reply["probes"])
        terminal = json.loads((self.root / "windows-desktop-settle" / OPERATION / "settle.terminal.json").read_text())
        self.assertEqual(trace, terminal["probes"][0]["stderr"], "the evidence is in the retained terminal too")

    def test_a_locked_or_changed_session_refuses_before_any_frame_or_key(self):
        for changes, reason in (({"session": {"SessionId": 2, "State": 0, "Flags": 0, "User": "fixtureuser", "Logon": 5}}, "instance_desktop_settle_session_locked"),
                                ({"tokenSid": "S-1-5-21-1-2-3-1003"}, "instance_desktop_settle_session_changed"),
                                ({"ordinary": False}, "instance_desktop_settle_session_changed"),
                                ({"machine": str(uuid.uuid4())}, "instance_desktop_settle_session_changed")):
            with self.subTest(reason=reason, changes=sorted(changes)):
                self.setUp()
                self.console.session_changes = changes
                reply = self.run_flow()
                self.assertEqual(("blocked", reason), (reply["state"], reply["reason"]))
                self.assertEqual(([], []), (self.console.calls, self.tree()))

    def test_a_probe_reply_of_another_shape_is_never_judged(self):
        for changes in ({"window": {"pid": 5400}}, {"rows": [{"pid": 1, "parentPid": 0, "name": "x"}]}, {"extra": 1}, {"probePid": 0},
                        {"state": "refused", "reason": "other", "window": None, "rows": []}):
            with self.subTest(changes=changes):
                self.setUp()
                self.console.probe_changes = changes
                reply = self.run_flow()
                self.assertEqual(("desktop-settle-unknown", "instance_desktop_probe_shape"), (reply["state"], reply["reason"]))
                self.assertEqual([], self.console.keys)

    def test_every_esc_is_burned_before_it_is_sent(self):
        seen = []
        real = self.console.monitor

        def monitor(command, arguments=None):
            if command == "send-key":
                seen.append(self.tree())
            return real(command, arguments)
        self.console.monitor = monitor
        self.console.holders = [SEARCH, SEARCH, None]
        self.run_flow()
        prefix = "windows-desktop-settle/" + OPERATION + "/"
        self.assertIn(prefix + "esc-1.intent.json", seen[0])
        self.assertIn("direct-guest-" + OPERATION + ".intent.json", seen[0])
        self.assertIn(prefix + "esc-2.intent.json", seen[1])
        self.assertNotIn(prefix + "esc-2.intent.json", seen[0])

    def test_a_failure_after_the_settle_began_is_unknown_and_keeps_its_fence(self):
        real = self.console.script

        def script(label, source):
            if label == "desktop-probe-2":
                raise ValueError("instance_original_guest_pending")
            return real(label, source)
        self.console.script = script
        reply = self.run_flow()
        self.assertEqual(("desktop-settle-unknown", "instance_original_guest_pending"), (reply["state"], reply["reason"]))
        self.assertEqual([("esc",)], self.escs())
        self.assertIn("original_guest_work_unresolved", self.classified()[1], "doubt stays visible on the clone")
        repeat = self.run_flow(repeat=True)
        self.assertEqual(reply, repeat, "the repeat reads the terminal")
        self.assertEqual([("esc",)], self.escs(), "and never keys again")

    def test_a_repeat_reads_the_original_terminal_and_sends_nothing(self):
        first = self.run_flow()
        keys = list(self.console.keys)
        calls = len(self.console.calls)
        self.assertEqual(first, self.run_flow(repeat=True))
        self.assertEqual((keys, calls), (self.console.keys, len(self.console.calls)))
        self.setUp()
        journal = settle._DesktopSettle(self.root, OPERATION)
        journal.begin()
        with mock.patch.dict(settle.__dict__, {"OPERATION": OPERATION}):
            unknown = settle._desktop_settle_repeat(journal)
        self.assertEqual(("desktop-settle-unknown", "instance_desktop_settle_original_unresolved"), (unknown["state"], unknown["reason"]))
        self.assertEqual("instance_desktop_settle_original_unresolved", self.run_flow()["reason"], "an original with no terminal is never replayed")
        self.assertEqual([], self.console.keys)


class PacketTests(unittest.TestCase):
    def setUp(self):
        absent()

    def binding(self):
        spec = vm_request()
        spec.update(deploymentId=MACHINE, host="fixture", root="/owned/vm")
        return {"provider": "raw-qemu-windows", "spec": spec, "setup": dict(SETUP), "context": {"hostBootId": str(uuid.uuid4()), "pending": []},
                "uri": None, "domain": None, "xmlSha256": None}

    def test_the_settle_packet_holds_one_esc_route_and_the_repeat_none(self):
        packet = settle.program(self.binding(), OPERATION)
        repeat = settle.program(self.binding(), OPERATION, repeat=True)
        self.assertIn(b"MODE='desktop-settle'", packet)
        self.assertIn(b"result=_desktop_settle_reply(desktop_settle,_desktop_settle(desktop_settle,", packet)
        # The settle's own code holds one key route, an Esc, and no pointer.
        own = "".join(inspect.getsource(item) for item in settle._SETTLE_SOURCES)
        self.assertEqual(1, own.count("'send-key'"))
        self.assertIn("monitor('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80})", own)
        for other in ("'ret'", "'meta_l'", "'tab'", "input-send-event", "query-mice"):
            self.assertNotIn(other, own)
        self.assertIn(b"MODE='desktop-settle-repeat'", repeat)
        self.assertIn(b"result=_desktop_settle_reply(desktop_settle,_desktop_settle_repeat(desktop_settle))", repeat)
        for absent in (b"DESKTOP_PROBE_TEMPLATE", b"def _desktop_settle_probe", b"def _desktop_settle(", b"def _desktop_settle_shot"):
            self.assertNotIn(absent, repeat)
        self.assertIn(b"DESKTOP_SETTLE_ESC_LIMIT=2\n", packet)

    def test_the_probe_is_the_owners_own_read_run_once_as_the_console_user(self):
        self.assertIn(inspect.getsource(owner_rules.foreground_window), settle.PROBE_PYTHON)
        compile(settle.PROBE_PYTHON, "probe", "exec")
        source = settle.probe_source(USER_SID, OPERATION.replace("-", "")[:12] + "-1")
        source.encode("ascii")
        self.assertIn("New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited", source)
        self.assertIn("pythonw.exe", source)
        self.assertIn("finally{Unregister-ScheduledTask -TaskName $name -Confirm:$false}", source)
        self.assertEqual(1, len([line for line in source.splitlines() if line.lstrip().startswith("[Console]::WriteLine(")]))
        self.assertTrue(source.rstrip().splitlines()[-1].startswith("[Console]::WriteLine("), "the guest runner frames only a last output line")
        self.assertEqual(settle.PROBE_PYTHON.encode(), base64.b64decode(re.search(r"\$code='([A-Za-z0-9+/=]+)'", source)[1]))
        for bad in (("S-1-5-18", "a" * 12 + "-1"), (USER_SID, "x"), (USER_SID + "'", "a" * 12 + "-1")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                settle.probe_source(*bad)

    def test_the_holder_rule_is_the_owners_one_rule(self):
        rows = {5400: {"pid": 5400, "parentPid": 700, "name": "StartMenuExperienceHost.exe"},
                1380: {"pid": 1380, "parentPid": 900, "name": "powershell.exe"}, 6084: {"pid": 6084, "parentPid": 1380, "name": "python.exe"}}
        self.assertEqual(({"foreground": None}, None), owner_rules.desktop_holder(None, rows, 6084))
        self.assertEqual("shell-surface", owner_rules.desktop_holder(START, rows, 6084)[1])
        self.assertEqual(None, owner_rules.desktop_holder({"pid": 1380, "className": "ConsoleWindowClass"}, rows, 6084)[1])
        self.assertEqual("foreign-console", owner_rules.desktop_holder({"pid": 1380, "className": "ConsoleWindowClass"}, rows, 9100)[1])
        self.assertIn(owner_rules.desktop_holder, settle._SETTLE_SOURCES)


class Function:
    """One fake user32 export: ctypes sets argtypes and restype on it, and the probe calls it."""

    def __init__(self, call):
        self.call = call

    def __call__(self, *arguments):
        return self.call(*arguments)


class ProbeProgramTests(unittest.TestCase):
    """The probe file the user's task runs, executed whole over a fake user32, as pythonw would run it."""

    def setUp(self):
        absent()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.out, self.err = self.folder / "probe.json", self.folder / "probe.stderr.txt"

    def run_probe(self, *, window=0x1234, owner=5400, name="Windows.UI.Core.CoreWindow", loads=True):
        def owner_pid(handle, pid):
            pid._obj.value = owner
            return 12 if owner else 0

        def class_name(handle, buffer, size):
            buffer.value = name
            return len(name)

        def load(library, use_last_error):
            if not loads:
                raise OSError("[WinError 1114] A dynamic link library (DLL) initialization routine failed")
            return types.SimpleNamespace(GetForegroundWindow=Function(lambda: window), GetWindowThreadProcessId=Function(owner_pid),
                                         GetClassNameW=Function(class_name))
        died, original = None, sys.stderr
        with mock.patch.object(ctypes, "WinDLL", load, create=True), mock.patch.object(sys, "argv", ["probe.py", str(self.out), str(self.err)]), \
                mock.patch.object(sys, "stderr", original):
            try:
                exec(compile(settle.PROBE_PYTHON, "probe.py", "exec"), {"__name__": "__main__"})
            except BaseException as error:  # pythonw would have exited here, its traceback lost.
                died = error
            finally:
                if sys.stderr is not original:
                    sys.stderr.close()
        self.assertTrue(self.out.exists(), "the probe died with no result: %r" % (died,))
        return json.loads(self.out.read_text())

    def test_a_null_foreground_was_never_a_crash_it_is_no_holder(self):
        # The coordinator's lead: a sleeping display or a suspended shell with no foreground window.
        # A control: the original probe wrote this result too (it has no "error" field), so no NULL read lost a result.
        result = self.run_probe(window=None)
        self.assertEqual((None, None), (result["window"], result.get("error")))

    def test_native_probe_whose_lookup_fails_still_writes_a_typed_error_and_its_stderr(self):
        """d80b34c1 (ND4): the task ended but probe.json was never written. The original probe raised from
        foreground_window when the foreground handle had no owner or class, before writing anything."""
        for changes, error_class, message in (({"owner": 0}, "AssertionError", "interactive-desktop-foreground-owner"),
                                              ({"name": ""}, "AssertionError", "interactive-desktop-foreground-class"),
                                              ({"loads": False}, "OSError", "[WinError 1114] A dynamic link library (DLL) initialization routine failed")):
            with self.subTest(changes=changes):
                for path in (self.out, self.err):
                    path.unlink(missing_ok=True)
                result = self.run_probe(**changes)
                self.assertEqual((None, {"errorClass": error_class, "message": message}), (result["window"], result["error"]))
                self.assertIn("Traceback (most recent call last)", self.err.read_text(), "pythonw's stderr is kept in the probe folder")
                self.assertGreater(result["probePid"], 0)

    def test_a_readable_foreground_is_written_as_before(self):
        result = self.run_probe()
        self.assertEqual(({"pid": 5400, "className": "Windows.UI.Core.CoreWindow"}, None), (result["window"], result.get("error")))
        self.assertEqual("", self.err.read_text() if self.err.exists() else "")

    def test_the_system_side_keeps_the_task_end_and_stderr_before_it_removes_them(self):
        source = settle.probe_source(USER_SID, OPERATION.replace("-", "")[:12] + "-1")
        self.assertIn("""-Argument ('-I -S -B "'+$probe+'" "'+$out+'" "'+$err+'"')""", source)
        self.assertLess(source.index("$r.lastTaskResult=[int64](Get-ScheduledTaskInfo -TaskName $name).LastTaskResult"),
                        source.index("finally{Unregister-ScheduledTask"))
        self.assertLess(source.index("$r.stderr=$text"), source.index("Remove-Item -LiteralPath $dir"))
        self.assertIn("$text.Substring($text.Length-%d)" % settle.STDERR_CHARS, source)
        self.assertIn("if($null -ne $read.error){$r.state='refused';$r.reason='desktop_probe_failed'", source)
        self.assertNotIn("__STDERR_CHARS__", source)


@unittest.skipUnless(POSIX, "private journals are POSIX")
class LocalTests(unittest.TestCase):
    def setUp(self):
        absent()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        self.packets, self.replies = [], []
        self.intent = self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")
        self.intent.parent.mkdir(parents=True, mode=0o700)
        self.deploy()
        key, known = self.work / "key", self.work / "known"
        for item in (key, known):
            item.write_text("x")
            item.chmod(0o600)
        config = self.root / ".vm-hosts.local.json"
        config.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester", "identityFile": str(key),
                                                                              "knownHostsFile": str(known)}}}))
        config.chmod(0o600)
        (self.root / ".runtime").mkdir(mode=0o755)
        for patcher in (mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=lambda config, host, timeout=30, command=(), ssh_binary="ssh": ["fake-ssh", *command]),
                        mock.patch.object(transport, "run_ssh", side_effect=self.run_ssh)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def deploy(self, **changes):
        spec = vm_request()
        spec.update(deploymentId=MACHINE, host="fixture", root="/owned/vm")
        self.intent.unlink(missing_ok=True)
        self.intent.write_text(json.dumps({"spec": spec, "setup": dict(SETUP), "context": {"hostBootId": str(uuid.uuid4()), "pending": []},
                                           "correlationId": uuid.uuid4().hex, "mode": "start", "callerSha256": "c" * 64, **changes}))
        self.intent.chmod(0o600)

    def run_ssh(self, argv, **options):
        found = re.fullmatch(r"import base64,zlib;exec\(zlib\.decompress\(base64\.b64decode\('([A-Za-z0-9+/=]+)',validate=True\)\)\)", argv[5])
        source = zlib.decompress(base64.b64decode(found[1], validate=True))
        self.packets.append({"mode": re.search(rb"\nMODE='([a-z-]+)'\n", source)[1].decode(), "options": dict(options)})
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return subprocess.CompletedProcess(argv, 0, json.dumps(reply).encode(), b"")

    def terminal(self, **changes):
        before, after = frame("start"), frame("desktop")
        rows = [{"name": "frame-before.ppm", "bytes": len(before), "sha256": hashlib.sha256(before).hexdigest()},
                {"name": "frame-after.ppm", "bytes": len(after), "sha256": hashlib.sha256(after).hexdigest()}]
        return {"state": "desktop-settled", "operationId": OPERATION, "reason": None, "escapes": 1,
                "probes": [{"interactiveDesktop": {"foreground": {"pid": 5400, "image": "StartMenuExperienceHost.exe",
                                                                  "className": "Windows.UI.Core.CoreWindow", "owned": False}}, "unsettled": "shell-surface",
                            **CLEAN},
                           {"interactiveDesktop": {"foreground": None}, "unsettled": None, **CLEAN}],
                "frames": rows, "replayAllowed": False,
                "frameBytes": {"frame-before.ppm": base64.b64encode(zlib.compress(before)).decode(),
                               "frame-after.ppm": base64.b64encode(zlib.compress(after)).decode()}, **changes}

    def call(self, **changes):
        return settle.settle(self.root, {"deploymentId": MACHINE, "operationId": OPERATION, **changes})

    def journal(self):
        directory = self.root / ".runtime/windows-desktop-settles" / OPERATION
        return sorted(path.name for path in directory.iterdir()) if directory.exists() else []

    def test_one_packet_settles_and_both_frames_are_kept_privately(self):
        self.replies = [self.terminal()]
        reply = self.call()
        self.assertEqual(("desktop-settled", True, 1), (reply["state"], reply["settled"], reply["escapes"]))
        self.assertEqual(["desktop-settle"], [packet["mode"] for packet in self.packets])
        self.assertEqual(subprocess.DEVNULL, self.packets[0]["options"]["stdin"])
        directory = self.root / ".runtime/windows-desktop-settles" / OPERATION
        self.assertEqual(frame("start"), (directory / "frame-before.ppm").read_bytes())
        self.assertEqual(0o600, (directory / "frame-after.ppm").stat().st_mode & 0o777)
        self.assertEqual([str(directory / "frame-before.ppm"), str(directory / "frame-after.ppm")], [row["path"] for row in reply["frames"]])
        self.assertNotIn("frameBytes", reply)
        self.assertEqual(["frame-after.ppm", "frame-before.ppm", "intent.json", "result.json", "settle.intent.json", "settle.py"], self.journal())
        self.assertEqual(reply, self.call(), "a kept result comes back with no packet")
        self.assertEqual(1, len(self.packets))

    def test_a_lost_reply_only_repeats_and_never_settles_again(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), self.terminal()]
        first = self.call()
        self.assertEqual(("unknown", "desktop_settle_unresolved"), (first["state"], first["reason"]))
        self.assertEqual("desktop-settled", self.call()["state"])
        self.assertEqual(["desktop-settle", "desktop-settle-repeat"], [packet["mode"] for packet in self.packets])

    def test_a_reply_cannot_claim_more_keys_another_holder_or_other_frames(self):
        before = frame("start")
        for changes in ({"escapes": 3}, {"replayAllowed": True}, {"operationId": str(uuid.uuid4())}, {"reason": "desktop_settle_still_unsettled"},
                        {"state": "desktop-settle-refused", "reason": "other"}, {"probes": []}, {"extra": 1},
                        {"frameBytes": {"frame-before.ppm": base64.b64encode(zlib.compress(before + b"x")).decode(),
                                        "frame-after.ppm": base64.b64encode(zlib.compress(frame("desktop"))).decode()}},
                        {"probes": [{"interactiveDesktop": {"foreground": {"pid": 5400, "image": "x", "className": "y", "owned": "no"}}, "unsettled": None,
                                     **CLEAN}]},
                        {"probes": [{"interactiveDesktop": {"foreground": None}, "unsettled": "shell-surface", **CLEAN}]},
                        {"probes": [{"interactiveDesktop": {"foreground": None}, "unsettled": None}]},
                        {"probes": [{"refused": "desktop_probe_failed", **CLEAN}]},
                        {"probes": [{"refused": "desktop_probe_no_output", **CLEAN, "stderr": "x" * (settle.STDERR_CHARS + 1)}]},
                        {"probes": [{"interactiveDesktop": {"foreground": None}, "unsettled": None, **CLEAN,
                                     "error": {"errorClass": "1 bad", "message": ""}}]}):
            with self.subTest(changes=sorted(changes)):
                for path in (self.root / ".runtime/windows-desktop-settles").glob("*"):
                    for item in path.iterdir():
                        item.unlink()
                    path.rmdir()
                self.replies = [self.terminal(**changes)]
                reply = self.call()
                self.assertEqual(("unknown", "desktop_settle_reply_rejected"), (reply["state"], reply["reason"]))
                self.assertNotIn("result.json", self.journal())

    def test_local_refusals_come_before_any_contact_or_journal(self):
        for bad in ({"deploymentId": MACHINE}, {"deploymentId": MACHINE, "operationId": OPERATION, "step": "x"}, {"deploymentId": "x", "operationId": OPERATION},
                    "x", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "^windows_desktop_settle_inputs$"):
                settle.settle(self.root, bad)
        self.deploy(mode="stop")
        self.assertEqual("desktop_settle_deployment_unavailable", self.call()["reason"])
        self.intent.unlink()
        self.assertEqual("desktop_settle_deployment_unavailable", self.call()["reason"])
        self.assertEqual(([], []), (self.packets, self.journal()))


class RouteTests(unittest.TestCase):
    INPUTS = {"deploymentId": MACHINE, "operationId": OPERATION}

    def setUp(self):
        absent()
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_cached_routes
        self.server = mcp_server
        bind_cached_routes(self, mcp_server, "windows_desktop_settle")

    def test_closed_inputs_refuse_before_the_adapter(self):
        for bad in ({**self.INPUTS, "extra": "x"}, {"deploymentId": MACHINE}, {**self.INPUTS, "deploymentId": "x"}, {**self.INPUTS, "key": "esc"}, {}):
            with self.subTest(bad=bad), mock.patch.object(self.server, "_agent_module", side_effect=AssertionError("refused first")):
                self.assertFalse(self.server._vm_workflow_dispatch("windows-desktop-settle", bad)["ok"])
                self.assertTrue(self.server._vm_invalid_before_recovery("windows-desktop-settle", bad))

    def test_the_route_passes_exactly_the_inputs_and_only_a_settled_desktop_is_ok(self):
        for state, ok in (("desktop-settled", True), ("desktop-settle-refused", False), ("refused", False), ("unknown", False)):
            with self.subTest(state=state), mock.patch.object(settle, "before_contact", return_value=None), \
                    mock.patch.object(settle, "settle", return_value={"state": state, "replayAllowed": False}) as called:
                result = self.server.vm_workflow("windows-desktop-settle", dict(self.INPUTS))
                called.assert_called_once_with(self.server.REPO_ROOT, self.INPUTS)
                self.assertEqual((ok, False, False, "desktop-settle-setup"),
                                 (result["ok"], result["productAction"], result["nativeActionAllowed"], result["evidenceClass"]))

    def test_the_catalog_rows_and_the_cli_name(self):
        from agent_tools import readiness_vm_dispatch as dispatch, tool_action_policy as policy
        row, visual = (policy.action_policy("vm_workflow", action) for action in ("windows-desktop-settle", "windows-uac-visual"))
        self.assertEqual((visual.requirements, visual.permitted_recoveries, visual.classification), (row.requirements, row.permitted_recoveries, row.classification))
        route = dispatch.ROUTES["windows-desktop-settle"]
        self.assertEqual(("windows_deployment", ("windows_desktop_settle",)), (route["kind"], route["modules"]))
        for module in ("windows_desktop_settle", "windows_ordinary_process_owner", "windows_uac_decision", "readiness_windows_remote"):
            self.assertIn("agent_tools/" + module + ".py", route["closure"])
        with mock.patch.object(self.server, "vm_workflow", return_value={"ok": True}) as called, \
                tempfile.NamedTemporaryFile("w", suffix=".json") as inputs:
            json.dump(self.INPUTS, inputs)
            inputs.flush()
            with mock.patch("sys.stdout"):
                self.server.main(["vm-workflow", "windows-desktop-settle", "--inputs-file", inputs.name])
        called.assert_called_once_with("windows-desktop-settle", self.INPUTS)


if __name__ == "__main__":
    unittest.main()
