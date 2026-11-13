"""The visual scene's consent prompt on a windowsUacVisual deployment: raised once, left open, cancelled once.

No VM, host or guest. The real flows run over a small model of the console: a display that sleeps until the
pointer moves, the Run dialog, the typed command, the secure desktop and consent.exe. The real host_work
classifier judges the fence. Nothing here proves a Windows, PowerShell, QEMU or secure desktop behaviour:
only a direct native run does.
"""
import base64
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import readiness_windows  # Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import ssh_transport as transport
from agent_tools import windows_uac_decision as uac
from agent_tools.tests.test_native_vm_spec import request as vm_request
from agent_tools.tests.test_windows_idle_receipt_classes import Receipts, current_source
from agent_tools.tests.test_windows_scenario_host_job import POWERSHELL
from agent_tools.windows_vm_instance import console_key_plan

try:
    from agent_tools import windows_uac_visual as visual
except ImportError:  # The unfixed tree has no such module: every test that needs it fails there.
    visual = None

MACHINE = "33333333-4444-4555-8666-777777777777"
OPERATION = "55555555-6666-4777-8888-999999999999"
ADMIN_SID = "S-1-5-21-1-2-3-1001"
BOOT = "134368653065000000"
WIDTH, HEIGHT = 640, 400
COMMAND = "powershell start powershell -verb runas"
BINDING = {"guestBoot": "2026-11-07T00:00:00.0000000Z", "bootFileTimeUtc": BOOT, "sid": ADMIN_SID, "sessionId": 1, "explorerPid": 4000,
           "explorerBirth": "134368653070000000", "explorerPath": "C:\\Windows\\explorer.exe", "profile": "C:\\Users\\fixtureadmin"}
SETUP = {"imageName": "Windows 11 Pro", "locale": "en-US", "user": "recovery", "administrator": "fixtureadmin", "purpose": "windowsUacVisual"}
POSIX = os.name == "posix"
CHARACTERS = {tuple(codes): character for character, codes in zip(COMMAND, console_key_plan(COMMAND))}


def frame(kind):
    """One synthetic console frame. The secure desktop dims every pixel; a waiting taskbar button changes a corner."""
    fill = {"black": 0, "prompt": 40}.get(kind, 120)
    pixels = bytearray(bytes((fill, fill, fill)) * (WIDTH * HEIGHT))

    def rectangle(x0, y0, x1, y1, value):
        for y in range(y0, y1):
            pixels[(y * WIDTH + x0) * 3:(y * WIDTH + x1) * 3] = bytes((value, value, value)) * (x1 - x0)
    if kind == "run":
        rectangle(4, 270, 206, 372, 240)
    elif kind == "start":
        rectangle(160, 20, 480, 370, 240)
    elif kind == "prompt":
        rectangle(206, 106, 434, 294, 250)
    elif kind == "minimized":
        rectangle(300, 384, 330, 400, 200)
    return b"P6\n%d %d\n255\n" % (WIDTH, HEIGHT) + bytes(pixels)


def binding(setup=SETUP):
    spec = vm_request()
    spec.update(deploymentId=MACHINE, host="fixture", root="/owned/vm")
    return {"provider": "raw-qemu-windows", "spec": spec, "setup": dict(setup), "context": {"hostBootId": str(uuid.uuid4()), "pending": []},
            "uri": None, "domain": None, "xmlSha256": None}


class Console:
    """The visual clone's console as the flows see it through QMP and the SYSTEM census."""

    def __init__(self):
        self.asleep = True
        self.absolute = False
        self.wakes = True
        self.screen = "desktop"
        self.win_r = "run"
        self.raises = "shown"
        self.typed = ""
        self.consent = None
        self.shells = []
        self.pointer = []
        self.keys = []
        self.calls = []
        self.labels = []
        self.census_changes = {}
        self.session_changes = {}
        self.expires_at_exit_read = None
        self.exit_reads = 0
        self.on_key = None

    def monitor(self, command, arguments=None):
        self.calls.append((command, arguments))
        if command == "screendump":
            Path(arguments["filename"]).write_bytes(frame("black" if self.asleep else self.screen))
            return {}
        if command == "query-mice":
            return [{"name": "QEMU PS/2 Mouse", "index": 2, "current": True, "absolute": self.absolute}]
        if command == "input-send-event":
            self.pointer.append(arguments["events"])
            self.asleep = self.asleep and not self.wakes
            return {}
        assert command == "send-key", command
        codes = tuple(key["data"] for key in arguments["keys"])
        if self.on_key is not None:
            self.on_key(codes)
        self.keys.append(codes)
        if codes == ("esc",):
            if self.screen == "prompt":  # The secure desktop takes the key: denied, and the requester ends.
                self.consent, self.shells, self.screen = None, [row for row in self.shells if row["sessionId"] != 1], "desktop"
            elif self.screen in ("run", "start"):
                self.screen, self.typed = "desktop", ""
        elif codes == ("meta_l", "r"):
            self.screen = {"run": "run", "start": "start"}.get(self.win_r, self.screen)
        elif self.screen == "run":
            if codes == ("backspace",):
                self.typed = ""
            elif codes == ("ret",):
                self.screen = "desktop"
                if self.typed == COMMAND:
                    self.shells = [*self.shells, {"pid": 5000, "sessionId": 1}]
                    if self.raises != "absent":
                        self.consent = {"pid": 4242, "birth": "134368653100000000", "sessionId": 1, "image": "C:\\Windows\\System32\\consent.exe",
                                        "signature": "Valid", "signer": "Microsoft Windows", "parentIsAppinfo": True, "ageSeconds": 3}
                        self.screen = "prompt" if self.raises == "shown" else "minimized"
            elif codes != ("ctrl", "a"):
                self.typed += CHARACTERS[codes]
        return {}

    def script(self, label, source):
        self.labels.append(label.rsplit("-", 1)[0])
        if label.startswith("login-session"):
            return {"machine": MACHINE.upper(), "boot": "2026-11-07T00:00:00.0000000Z", "console": 1, "expectedSid": "S-1-5-21-1-2-3-1000",
                    "tokenSid": ADMIN_SID, "ordinary": True, "explorers": [{"Id": 4000, "SessionId": 1}],
                    "session": {"SessionId": 1, "State": 0, "Flags": 1, "User": "fixtureadmin", "Logon": 5}, **self.session_changes}
        if label.startswith("login-after"):
            self.exit_reads += 1
            if self.expires_at_exit_read is not None and self.exit_reads >= self.expires_at_exit_read:
                self.consent, self.shells, self.screen = None, [], "desktop"
            return {"gone": self.consent is None}
        return {"policy": {"enableLua": 1, "promptOnSecureDesktop": 1, "consentPromptBehaviorAdmin": 5}, "preload": "00000409", "adminSid": ADMIN_SID,
                "bootFileTimeUtc": BOOT, "consents": [dict(self.consent)] if self.consent else [], "shells": list(self.shells),
                "explorers": [{"pid": 4000, "sessionId": 1, "birth": BINDING["explorerBirth"]}, {"pid": 700, "sessionId": 0, "birth": "1"}],
                **self.census_changes}


@unittest.skipUnless(POSIX, "the journals are POSIX; the VM host is Linux")
class FlowBase(unittest.TestCase):
    """Runs the real flows as the packets do, with the producer's own failure mapping."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "vm"
        self.root.mkdir(mode=0o700)
        self.console = Console()
        self.clock = [100.0]
        self.qualify()

    def qualify(self, value=None):
        path = self.root / "visual-session-qualified.json"
        path.unlink(missing_ok=True)
        path.write_text(json.dumps({"purpose": "windowsUacVisual", "binding": BINDING} if value is None else value))
        path.chmod(0o600)

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

    def run_step(self, step, *, settle=False):
        values = {"SPEC": {"deploymentId": MACHINE}, "OPERATION": OPERATION, "SESSION_SCRIPT": "fixed session", "UAC_VISUAL_CENSUS_SCRIPT": "fixed census",
                  "UAC_GATE_SECONDS": uac.GATE_SECONDS, "UAC_PROMPT_AGE": uac.PROMPT_AGE_SECONDS, "UAC_CLOSE_WAIT": uac.CLOSE_WAIT_MILLISECONDS,
                  "UAC_VISUAL_CLOSE_ROUNDS": visual.CLOSE_ROUNDS, "UAC_VISUAL_KEYS": [list(codes) for codes in console_key_plan(visual.COMMAND)],
                  "UAC_VISUAL_PARK_STEPS": visual.PARK_STEPS, "UAC_VISUAL_PARK_DELTA": visual.PARK_DELTA, "UAC_REVIEW_SETTLE": uac.REVIEW_SETTLE_SECONDS,
                  "UAC_VISUAL_STEP": step}

        def sleep(seconds):
            self.clock[0] += seconds
        owner = visual._UacVisual(self.root, OPERATION)
        console = self.console
        with mock.patch.dict(visual.__dict__, values), mock.patch.dict(uac.__dict__, {"UAC_PRELUDE": uac._PRELUDE, "UAC_EXIT": uac._EXIT}), \
                mock.patch.object(time, "sleep", sleep), mock.patch.object(time, "monotonic", lambda: self.clock[0]):
            try:
                if settle:
                    return visual._uac_visual_settle(owner, self.root, self.save, self.read, self.guard, console.script)
                if step == "raise":
                    return visual._uac_visual_raise(owner, self.root, self.save, self.read, console.monitor, self.guard, console.script)
                return visual._uac_visual_close(owner, self.root, self.save, self.read, self.guard, console.script,
                                                lambda consent: visual._uac_visual_escape(owner, consent, console.monitor, self.guard))
            except BaseException as error:
                reason = str(error) if type(error) is ValueError and re.fullmatch("instance_[a-z_]{1,64}", str(error)) else "instance_observation_unknown"
                return (owner.reply(reason) if step == "raise" and not settle else None) or {"state": "blocked", "reason": reason}

    def raised(self):
        reply = self.run_step("raise")
        self.assertEqual("visual-prompt-raised", reply["state"], reply)
        return reply

    def assert_untouched(self, reply, reason):
        """A refusal before the raise began: no pointer, no key, no fence and no folder."""
        self.assertEqual(("blocked", reason), (reply["state"], reply["reason"]))
        self.assertEqual(([], []), (self.console.pointer, self.console.keys))
        self.assertEqual([], [name for name in self.tree() if name != "visual-session-qualified.json"])
        self.assertFalse((self.root / "windows-uac").exists())


class RaiseTests(FlowBase):
    def test_a_sleeping_visual_clone_gets_the_prompt_raised_shown_and_left_open(self):
        """VIS 39242640: every frame of the frame route was black, and no reviewed route raised the scene's prompt."""
        reply = self.raised()
        console = self.console
        self.assertEqual((True, False, 3), (reply["pointerParked"], reply["promptAnswered"], reply["consent"]["ageSeconds"]))
        self.assertEqual(visual.PARK_STEPS, len(console.pointer), "one bounded park of a relative pointer")
        for events in console.pointer:
            self.assertEqual([("rel", "x", visual.PARK_DELTA), ("rel", "y", -visual.PARK_DELTA)],
                             [(event["type"], event["data"]["axis"], event["data"]["value"]) for event in events], "towards the top right, never a button")
        self.assertFalse(console.asleep, "the park woke the display")
        self.assertEqual([("esc",), ("esc",), ("meta_l", "r"), ("ctrl", "a"), ("backspace",)], console.keys[:5])
        self.assertEqual((COMMAND, ("ret",)), (console.typed, console.keys[-1]))
        self.assertEqual(5 + len(COMMAND) + 1, len(console.keys), "nothing after Enter: the prompt is left open")
        self.assertEqual("prompt", console.screen)
        self.assertEqual(hashlib.sha256(frame("prompt")).hexdigest(), reply["frameSha256"])
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified(), "the fence is open while the prompt is")
        files = self.tree()
        for name in ("visual.intent.json", "pointer.intent.json", "keys.intent.json", "keys.terminal.json", "raise.terminal.json"):
            self.assertIn("windows-uac/" + OPERATION + "/" + name, files)
        self.assertNotIn("windows-uac/" + OPERATION + "/cancel.intent.json", files)
        self.assertEqual({"login-session", "login-admission"}, set(console.labels), "every guest program is a read-only class")

    def test_the_journals_precede_the_pointer_and_the_first_key(self):
        seen = {}
        console = self.console
        real = console.monitor

        def monitor(command, arguments=None):
            if command in ("input-send-event", "send-key"):
                seen.setdefault(command, self.tree())
            return real(command, arguments)
        console.monitor = monitor
        self.raised()
        prefix = "windows-uac/" + OPERATION + "/"
        self.assertLessEqual({"direct-guest-" + OPERATION + ".intent.json", prefix + "visual.intent.json", prefix + "pointer.intent.json"},
                             set(seen["input-send-event"]))
        self.assertIn(prefix + "keys.intent.json", seen["send-key"])

    def test_an_absolute_pointer_parks_in_one_event_at_the_top_right(self):
        self.console.absolute = True
        self.raised()
        self.assertEqual([[("abs", "x", 32767), ("abs", "y", 0)]],
                         [[(event["type"], event["data"]["axis"], event["data"]["value"]) for event in events] for events in self.console.pointer])

    def test_a_display_that_stays_black_refuses_after_its_one_park_and_types_nothing(self):
        self.console.wakes = False
        reply = self.run_step("raise")
        self.assertEqual(("visual-raise-refused", "instance_uac_display_black", True), (reply["state"], reply["reason"], reply["cancelRequired"]))
        self.assertEqual((visual.PARK_STEPS, []), (len(self.console.pointer), self.console.keys))
        self.assertLessEqual(self.clock[0] - 100.0, uac.REVIEW_SETTLE_SECONDS + 5, "reading frames after the park is bounded")

    def test_nothing_is_typed_unless_the_run_dialog_is_proven(self):
        for opens in ("start", "nothing"):
            with self.subTest(opens=opens):
                shutil.rmtree(self.root / "windows-uac", ignore_errors=True)
                for path in self.root.glob("direct-guest-*"):
                    path.unlink()
                self.console = Console()
                self.console.win_r = opens
                reply = self.run_step("raise")
                self.assertEqual(("visual-raise-refused", "instance_uac_visual_run_dialog"), (reply["state"], reply["reason"]))
                self.assertEqual([("esc",), ("esc",), ("meta_l", "r"), ("esc",)], self.console.keys, "whatever opened gets one Esc, and no text")
                self.assertEqual(("", "desktop"), (self.console.typed, self.console.screen))

    def test_a_prompt_that_waits_in_the_taskbar_is_not_called_shown(self):
        self.console.raises = "minimized"
        reply = self.run_step("raise")
        self.assertEqual(("visual-raise-refused", "instance_uac_visual_prompt_not_shown", True), (reply["state"], reply["reason"], reply["cancelRequired"]))
        self.assertEqual(("ret",), self.console.keys[-1], "no key after Enter")

    def test_a_command_that_raised_nothing_refuses_within_the_gate(self):
        self.console.raises = "absent"
        reply = self.run_step("raise")
        self.assertEqual(("visual-raise-refused", "instance_uac_consent_absent"), (reply["state"], reply["reason"]))
        self.assertLessEqual(self.clock[0] - 100.0, 2 * uac.GATE_SECONDS)

    def test_every_refusal_before_the_raise_begins_touches_nothing(self):
        policy = {"enableLua": 1, "promptOnSecureDesktop": 1, "consentPromptBehaviorAdmin": 5}
        waiting = {"pid": 4242, "birth": "134368653100000000", "sessionId": 1, "image": "C:\\Windows\\System32\\consent.exe", "signature": "Valid",
                   "signer": "Microsoft Windows", "parentIsAppinfo": True, "ageSeconds": 3}
        for changes, reason in (
                ({"policy": {**policy, "enableLua": 0}}, "instance_uac_policy"),
                ({"policy": {**policy, "promptOnSecureDesktop": 0}}, "instance_uac_policy"),
                ({"policy": {**policy, "consentPromptBehaviorAdmin": 1}}, "instance_uac_policy"),
                ({"preload": "00000419"}, "instance_uac_keyboard"),
                ({"bootFileTimeUtc": "134368653065000001"}, "instance_uac_boot_changed"),
                ({"adminSid": "S-1-5-21-9-9-9-500"}, "instance_uac_administrator"),
                ({"explorers": [{"pid": 4001, "sessionId": 1, "birth": BINDING["explorerBirth"]}]}, "instance_uac_session_changed"),
                ({"explorers": [{"pid": 4000, "sessionId": 1, "birth": "134368653070000001"}]}, "instance_uac_session_changed"),
                ({"explorers": []}, "instance_uac_session_changed"),
                ({"consents": [waiting]}, "instance_uac_visual_prompt_present"),
                ({"consents": [waiting, {**waiting, "pid": 4243}]}, "instance_uac_consent_not_unique"),
                ({"consents": [{**waiting, "signer": "Someone Else"}]}, "instance_uac_consent_identity"),
                ({"consents": [{**waiting, "sessionId": 2}]}, "instance_uac_consent_identity"),
                ({"shells": [{"pid": 5000, "sessionId": 1}]}, "instance_uac_visual_shell_present"),
                ({"extra": 1}, "instance_uac_census_shape")):
            with self.subTest(changes=changes):
                self.console = Console()
                self.console.census_changes = changes
                self.assert_untouched(self.run_step("raise"), reason)
        for changes in ({"console": 2}, {"tokenSid": "S-1-5-21-1-2-3-1000"}, {"machine": str(uuid.uuid4())},
                        {"session": {"SessionId": 1, "State": 0, "Flags": 0, "User": "fixtureadmin", "Logon": 5}},
                        {"session": {"SessionId": 1, "State": 4, "Flags": 1, "User": "fixtureadmin", "Logon": 5}}):
            with self.subTest(changes=changes):
                self.console = Console()
                self.console.session_changes = changes
                self.assert_untouched(self.run_step("raise"), "instance_uac_session_changed")
        self.console = Console()
        for value in ({"purpose": "windowsUacVisual", "binding": {**BINDING, "sid": "S-1-5-18"}}, {"purpose": "ordinary", "binding": BINDING},
                      {"purpose": "windowsUacVisual", "binding": {key: BINDING[key] for key in BINDING if key != "explorerBirth"}}, ["x"]):
            with self.subTest(value=value):
                self.qualify(value)
                self.assert_untouched(self.run_step("raise"), "instance_uac_visual_unqualified")
        (self.root / "visual-session-qualified.json").unlink()
        self.assert_untouched(self.run_step("raise"), "instance_uac_visual_unqualified")
        self.assertEqual([], self.console.labels, "an unqualified deployment is refused before any guest read")

    def test_a_shell_of_another_session_is_not_this_desktops(self):
        # A SYSTEM shell in session 0 is not on the administrator's desktop: the raise is admitted, and the census
        # after Enter still finds exactly one shell there.
        self.console.shells = [{"pid": 900, "sessionId": 0}]
        self.raised()
        self.assertEqual([{"pid": 900, "sessionId": 0}, {"pid": 5000, "sessionId": 1}], self.console.shells)


class CancelTests(FlowBase):
    def test_cancel_sends_one_esc_to_that_prompt_proves_it_closed_and_closes_the_fence(self):
        self.raised()
        typed = len(self.console.keys)
        burned = {}
        self.console.on_key = lambda codes: burned.setdefault("files", self.tree())
        closed = self.run_step("cancel")
        self.assertEqual(("visual-prompt-closed", True, True, False), (closed["state"], closed["promptClosed"], closed["escSent"], closed["approvalSucceeded"]))
        self.assertEqual([("esc",)], self.console.keys[typed:], "one Esc and nothing else")
        self.assertIn("windows-uac/" + OPERATION + "/cancel.intent.json", burned["files"], "burned before the key")
        self.assertEqual(visual.PARK_STEPS, len(self.console.pointer), "cancel never moves the pointer")
        self.assertEqual((1, []), self.classified(), "the fence is closed")
        self.assertEqual({"exited": True, "exitcode": 0}, json.loads((self.root / ("direct-guest-" + OPERATION + ".terminal.json")).read_text()))
        self.assertEqual({"login-session", "login-admission", "login-after"}, set(self.console.labels))
        self.assertEqual(closed, self.run_step("cancel"), "a repeat reads the same terminal")
        self.assertEqual(typed + 1, len(self.console.keys))

    def test_a_prompt_past_the_age_rule_is_left_to_expire_with_no_key(self):
        self.raised()
        typed = len(self.console.keys)
        self.console.consent["ageSeconds"] = uac.PROMPT_AGE_SECONDS
        self.console.expires_at_exit_read = 2
        closed = self.run_step("cancel")
        self.assertEqual(("visual-prompt-closed", True, False), (closed["state"], closed["promptClosed"], closed["escSent"]))
        self.assertEqual(typed, len(self.console.keys), "an Esc could land on the desktop once the prompt has gone")
        self.assertEqual((1, []), self.classified())

    def test_a_prompt_still_up_is_reported_open_and_a_settle_closes_it_with_no_key(self):
        self.raised()
        typed = len(self.console.keys)
        self.console.consent["ageSeconds"] = uac.PROMPT_AGE_SECONDS + 5
        still = self.run_step("cancel")
        self.assertEqual(("visual-prompt-open", False), (still["state"], still["escSent"]))
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified(), "the fence stays open")
        self.assertEqual(visual.CLOSE_ROUNDS, self.console.exit_reads)
        self.console.expires_at_exit_read = self.console.exit_reads + 1
        closed = self.run_step("cancel", settle=True)
        self.assertEqual(("visual-prompt-closed", False), (closed["state"], closed["escSent"]))
        self.assertEqual(typed, len(self.console.keys))
        self.assertEqual((1, []), self.classified())

    def test_frames_taken_while_the_prompt_was_up_are_named(self):
        self.raised()
        floor = (self.root / "windows-uac" / OPERATION / "raise.terminal.json").stat().st_mtime_ns
        during, before = str(uuid.uuid4()), str(uuid.uuid4())
        for operation, offset in ((during, 5_000_000_000), (before, -5_000_000_000)):
            path = self.root / ("inspection-" + operation + ".result.json")
            path.write_text(json.dumps({"frame": "setup-frame-" + operation.replace("-", "") + ".png", "bytes": 1, "sha256": "a" * 64}))
            os.utime(path, ns=(floor + offset, floor + offset))
        closed = self.run_step("cancel")
        self.assertEqual([during], closed["framesDuringPrompt"], "the same consent process was still up when they were listed")

    def test_frames_are_not_named_once_the_prompt_has_gone(self):
        self.raised()
        path = self.root / ("inspection-" + str(uuid.uuid4()) + ".result.json")
        path.write_text("{}")
        floor = (self.root / "windows-uac" / OPERATION / "raise.terminal.json").stat().st_mtime_ns
        os.utime(path, ns=(floor + 5_000_000_000, floor + 5_000_000_000))
        self.console.consent, self.console.shells, self.console.screen = None, [], "desktop"
        closed = self.run_step("cancel")
        self.assertEqual(("visual-prompt-closed", False, []), (closed["state"], closed["escSent"], closed["framesDuringPrompt"]))

    def test_a_prompt_this_operation_did_not_raise_is_never_keyed(self):
        self.raised()
        typed = len(self.console.keys)
        self.console.consent = {**self.console.consent, "pid": 5151, "birth": "134368659900000000"}
        reply = self.run_step("cancel")
        self.assertEqual(("blocked", "instance_uac_consent_changed"), (reply["state"], reply["reason"]))
        self.assertEqual(typed, len(self.console.keys))
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified())

    def test_a_prompt_never_proven_shown_is_waited_out_and_never_keyed(self):
        self.console.raises = "minimized"
        self.assertEqual("visual-raise-refused", self.run_step("raise")["state"])
        typed = len(self.console.keys)
        self.console.expires_at_exit_read = 1
        closed = self.run_step("cancel")
        self.assertEqual(("visual-prompt-closed", False), (closed["state"], closed["escSent"]))
        self.assertEqual(typed, len(self.console.keys))
        self.assertEqual((1, []), self.classified())

    def test_a_shell_left_on_the_desktop_is_never_reported_closed(self):
        # What an approval would leave: the prompt gone and an elevated shell on the administrator's desktop.
        self.raised()
        self.console.consent, self.console.screen = None, "desktop"
        reply = self.run_step("cancel")
        self.assertEqual(("blocked", "instance_uac_visual_left_open"), (reply["state"], reply["reason"]))
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified(), "the fence stays open")
        self.assertFalse((self.root / "windows-uac" / OPERATION / "cancel.terminal.json").exists())

    def test_cancel_needs_a_raise_that_began(self):
        reply = self.run_step("cancel")
        self.assertEqual(("blocked", "instance_uac_visual_not_raised"), (reply["state"], reply["reason"]))
        self.assertEqual(([], [], []), (self.console.keys, self.console.pointer, self.console.labels))


class RepeatTests(FlowBase):
    def test_a_repeat_never_parks_types_or_escapes_again(self):
        first = self.raised()
        calls = len(self.console.calls)
        self.assertEqual(first, self.run_step("raise"), "the raise's own terminal")
        self.assertEqual(first, self.run_step("raise", settle=True))
        self.assertEqual(calls, len(self.console.calls), "no pointer, key or frame")
        closed = self.run_step("cancel")
        keys, moves = len(self.console.keys), len(self.console.pointer)
        self.assertEqual(closed, self.run_step("cancel", settle=True))
        self.assertEqual((keys, moves), (len(self.console.keys), len(self.console.pointer)))

    def test_a_raise_that_died_is_unknown_and_is_never_raised_again(self):
        owner = visual._UacVisual(self.root, OPERATION)
        owner.begin()
        self.assertEqual("visual-raise-unknown", self.run_step("raise", settle=True)["state"])
        reply = self.run_step("raise")
        self.assertEqual(("blocked", "instance_uac_visual_original_unresolved"), (reply["state"], reply["reason"]))
        self.assertEqual(([], []), (self.console.keys, self.console.pointer))
        shutil.rmtree(self.root / "windows-uac")
        self.assertEqual("no-visual-recorded", self.run_step("raise", settle=True)["state"])

    def test_an_unknown_raise_is_closed_by_cancel_without_a_key(self):
        visual._UacVisual(self.root, OPERATION).begin()
        self.save("direct-guest-" + OPERATION + ".intent.json", {"operationId": OPERATION, "label": "uac-visual", "replayAllowed": False})
        closed = self.run_step("cancel")
        self.assertEqual(("visual-prompt-closed", False), (closed["state"], closed["escSent"]))
        self.assertEqual(([], (1, [])), (self.console.keys, self.classified()))


class PacketTests(unittest.TestCase):
    def packet(self, mode, **options):
        return visual.program(binding(), mode, OPERATION, **options).decode()

    def test_the_packets_compile_and_a_settle_holds_no_key_pointer_or_frame_path(self):
        raised, cancel = self.packet("uac-visual-raise"), self.packet("uac-visual-cancel")
        for text in (raised, cancel):
            compile(text, "whole visual packet", "exec")
            for word in ("sys.stdin", "UAC_SECRET", "enter_private", "private_keys", "final-administrator", "_uac_flow", "_UacOwner"):
                self.assertNotIn(word, text, word)
        helpers = raised.split("\nSPEC=")[0]
        self.assertIn("UAC_VISUAL_KEYS=" + repr([list(codes) for codes in console_key_plan(COMMAND)]), helpers)
        self.assertIn("MODE='uac-visual-raise'", raised)
        self.assertNotIn("_uac_visual_escape", helpers, "a raise cannot answer")
        helpers = cancel.split("\nSPEC=")[0]
        self.assertEqual(1, helpers.count("monitor('send-key'"), "one Esc")
        for word in ("input-send-event", "query-mice", "UAC_VISUAL_KEYS", "_uac_visual_park", "_uac_visual_raise"):
            self.assertNotIn(word, helpers, word)
        for step in visual.STEPS:
            settle = self.packet("uac-visual-settle", step=step)
            compile(settle, "whole visual settle packet", "exec")
            helpers = settle.split("\nSPEC=")[0]
            self.assertIn("UAC_VISUAL_STEP=" + repr(step), helpers)
            for word in ("send-key", "input-send-event", "query-mice", "screendump", "monitor(", "_uac_visual_escape", "UAC_VISUAL_KEYS"):
                self.assertNotIn(word, helpers, word)

    def test_the_packet_is_not_a_generic_executor(self):
        ordinary = {key: value for key, value in SETUP.items() if key != "purpose"}
        for arguments, options in ((("uac-visual-raise", "not-a-uuid"), {}), (("uac-visual-settle", OPERATION), {}),
                                   (("uac-visual-settle", OPERATION), {"step": "approve"}), (("uac-visual-raise", OPERATION), {"step": "raise"}),
                                   (("uac-visual-approve", OPERATION), {}), (("observe", OPERATION), {})):
            with self.subTest(arguments=arguments, options=options), self.assertRaises(ValueError):
                visual.program(binding(), *arguments, **options)
        for setup in (ordinary, {**SETUP, "locale": "de-DE"}):
            with self.subTest(setup=setup), self.assertRaisesRegex(ValueError, "^windows_uac_visual_purpose$"):
                visual.program(binding(setup), "uac-visual-raise", OPERATION)
        self.assertEqual(COMMAND, visual.COMMAND, "the visual driver's own command")
        self.assertIn('"' + COMMAND + '"', (Path(visual.__file__).parents[1] / "scripts/capture_visual_windows_qemu.py").read_text(encoding="utf-8"))

    def test_census_source_follows_the_script_contract_and_only_reads(self):
        source = visual.census_source("fixtureadmin")
        source.encode("ascii")
        lines = source.rstrip().splitlines()
        self.assertEqual([len(lines) - 1], [number for number, line in enumerate(lines) if line.lstrip().startswith("[Console]::WriteLine(")])
        self.assertIn("'S-1-5-18'", source)
        self.assertNotRegex(source, r"__[A-Z_]+__")
        for word in ("Start-Process", "Register-ScheduledTask", "Set-ItemProperty", "Stop-Process", "Remove-Item"):
            self.assertNotIn(word, source)
        with self.assertRaises(ValueError):
            visual.census_source("admin';calc")

    @unittest.skipUnless(POSIX, "the fresh source loader's custody is POSIX here")
    def test_the_production_source_loader_renders_the_packets(self):
        from agent_tools import source_module_loader
        directory = Path(visual.__file__).parent
        with source_module_loader.request_scope(directory):
            adapter = source_module_loader.adapter(directory, "windows_uac_visual")
            raised = adapter.program(binding(), "uac-visual-raise", OPERATION)
            settle = adapter.program(binding(), "uac-visual-settle", OPERATION, step="cancel")
        self.assertIn(b"def _uac_visual_raise(", raised)
        self.assertIn(b"def _uac_close_fence(", settle)

    @unittest.skipUnless(POSIX, "alias pins are read through POSIX descriptors")
    def test_this_leaf_stays_out_of_every_alias_pin(self):
        pinned = {Path(path).name for path in readiness_windows._source_pins()}
        self.assertNotIn("windows_uac_visual.py", pinned)
        self.assertNotIn("windows_uac_decision.py", pinned)
        for name in pinned:
            path = Path(visual.__file__).with_name(name)
            self.assertNotIn("windows_uac_visual", path.read_text(encoding="utf-8") if path.exists() else "")

    @unittest.skipUnless(POWERSHELL, "PowerShell parser unavailable; hosted Windows and Linux runners have one")
    def test_the_census_parses(self):
        encoded = base64.b64encode(visual.census_source("fixtureadmin").encode("ascii")).decode()
        script = ("$s=[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('" + encoded + "'));$e=$null;$t=$null;"
                  "[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object{[Console]::Error.WriteLine($_.Message)};exit 1}")
        result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))


def raised_terminal(**changes):
    return {"state": "visual-prompt-raised", "operationId": OPERATION, "consent": {"pid": 4242, "birth": "134368653100000000", "sessionId": 1, "ageSeconds": 3},
            "pointerParked": True, "frameSha256": "a" * 64, "promptAnswered": False, "replayAllowed": False, **changes}


def closed_terminal(**changes):
    return {"state": "visual-prompt-closed", "operationId": OPERATION, "promptClosed": True, "escSent": True, "framesDuringPrompt": [],
            "approvalSucceeded": False, "replayAllowed": False, **changes}


@unittest.skipUnless(POSIX, "private journals are POSIX")
class LocalBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        self.packets = []
        self.replies = []
        self.intent = self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")
        self.intent.parent.mkdir(parents=True, mode=0o700)
        self.deploy()
        key, known = self.work / "key", self.work / "known"
        for item in (key, known):
            item.write_text("x")
            item.chmod(0o600)
        config = self.root / ".vm-hosts.local.json"
        config.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester", "identityFile": str(key), "knownHostsFile": str(known)}}}))
        config.chmod(0o600)
        (self.root / ".runtime").mkdir(mode=0o755)
        for patcher in (mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=lambda config, host, timeout=30, command=(), ssh_binary="ssh": ["fake-ssh", *command]),
                        mock.patch.object(transport, "run_ssh", side_effect=self.run_ssh)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def deploy(self, setup=SETUP, **changes):
        value = binding(setup)
        self.intent.unlink(missing_ok=True)
        self.intent.write_text(json.dumps({"spec": value["spec"], "setup": value["setup"], "context": value["context"], "correlationId": uuid.uuid4().hex,
                                           "mode": "start", "callerSha256": "c" * 64, **changes}))
        self.intent.chmod(0o600)

    def run_ssh(self, argv, **options):
        source = base64.b64decode(argv[5][len("import base64;exec(base64.b64decode('"):-len("'))")])
        self.packets.append({"mode": re.search(rb"\nMODE='([a-z-]+)'\n", source)[1].decode(), "source": source, "options": dict(options)})
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return subprocess.CompletedProcess(argv, 0, json.dumps(reply).encode(), b"")

    def inputs(self, step="raise", **changes):
        return {"deploymentId": MACHINE, "operationId": OPERATION, "step": step, **changes}

    def call(self, step="raise", **changes):
        return visual.prompt(self.root, self.inputs(step, **changes))

    def modes(self):
        return [packet["mode"] for packet in self.packets]

    def journal(self):
        directory = self.root / ".runtime/windows-uac-visual" / OPERATION
        return sorted(path.name for path in directory.iterdir()) if directory.exists() else []


class LocalTests(LocalBase):
    def test_raise_then_cancel_send_one_packet_each_with_no_stdin_and_no_credential(self):
        frames = [str(uuid.uuid4())]
        self.replies = [raised_terminal(), closed_terminal(framesDuringPrompt=frames)]
        raised = self.call()
        self.assertEqual({"state": "visual-prompt-raised", "promptOpen": True, "promptAnswered": False, "pointerParked": True, "consentAgeSeconds": 3,
                          "frameSha256": "a" * 64, "operationId": OPERATION, "deploymentId": MACHINE, "step": "raise", "replayAllowed": False}, raised)
        closed = self.call("cancel")
        self.assertEqual(("visual-prompt-closed", True, True, frames, False),
                         (closed["state"], closed["promptClosed"], closed["escSent"], closed["framesDuringPrompt"], closed["approvalSucceeded"]))
        self.assertEqual(["uac-visual-raise", "uac-visual-cancel"], self.modes())
        for packet in self.packets:
            self.assertEqual(subprocess.DEVNULL, packet["options"]["stdin"])
            self.assertNotIn("input", packet["options"])
        self.assertEqual(["cancel.intent.json", "cancel.py", "cancel.result.json", "intent.json", "raise.intent.json", "raise.py", "raise.result.json"],
                         self.journal())
        self.assertFalse((self.root / ".runtime/windows-vm-credentials").exists())
        self.assertEqual((raised, closed), (self.call(), self.call("cancel")), "kept results come back with no packet")
        self.assertEqual(2, len(self.packets))

    def test_a_lost_raise_reply_only_settles_and_never_raises_again(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), {"state": "blocked", "operationId": OPERATION, "reason": "instance_operator_busy",
                                                              "errorClass": "ValueError", "replayAllowed": False}, raised_terminal()]
        first = self.call()
        self.assertEqual(("unknown", "uac_visual_unresolved"), (first["state"], first["reason"]))
        busy = self.call()
        self.assertEqual(("unknown", "instance_operator_busy"), (busy["state"], busy["reason"]), "a settle that saw nothing proves nothing")
        self.assertEqual("visual-prompt-raised", self.call()["state"])
        self.assertEqual("visual-prompt-raised", self.call()["state"])
        self.assertEqual(["uac-visual-raise", "uac-visual-settle", "uac-visual-settle"], self.modes())
        for packet in self.packets[1:]:
            self.assertIn(b"UAC_VISUAL_STEP='raise'", packet["source"])
            self.assertNotIn(b"UAC_VISUAL_KEYS", packet["source"])

    def test_cancel_settles_until_the_prompt_is_proven_closed(self):
        self.replies = [raised_terminal(), {"state": "visual-prompt-open", "operationId": OPERATION, "escSent": True, "replayAllowed": False},
                        subprocess.TimeoutExpired("ssh", 1), closed_terminal()]
        self.call()
        still = self.call("cancel")
        self.assertEqual(("visual-prompt-open", False, True), (still["state"], still["promptClosed"], still["escSent"]))
        self.assertEqual("unknown", self.call("cancel")["state"])
        closed = self.call("cancel")
        self.assertEqual("visual-prompt-closed", closed["state"])
        self.assertEqual(closed, self.call("cancel"))
        self.assertEqual(["uac-visual-raise", "uac-visual-cancel", "uac-visual-settle", "uac-visual-settle"], self.modes(), "one packet could send the Esc")

    def test_a_refused_raise_ends_its_operation_and_says_whether_cancel_is_due(self):
        self.replies = [{"state": "visual-raise-refused", "operationId": OPERATION, "reason": "instance_uac_visual_run_dialog", "cancelRequired": True,
                         "replayAllowed": False}, closed_terminal(escSent=False)]
        refused = self.call()
        self.assertEqual(("refused", "instance_uac_visual_run_dialog", True), (refused["state"], refused["reason"], refused["cancelRequired"]))
        self.assertEqual(refused, self.call(), "a new operation raises again; this one never does")
        self.assertEqual("visual-prompt-closed", self.call("cancel")["state"])
        self.assertEqual(["uac-visual-raise", "uac-visual-cancel"], self.modes())
        shutil.rmtree(self.root / ".runtime/windows-uac-visual")
        self.packets.clear()
        self.replies = [{"state": "blocked", "operationId": OPERATION, "reason": "instance_uac_session_changed", "errorClass": "ValueError", "replayAllowed": False}]
        before = self.call()
        self.assertEqual(("refused", "instance_uac_session_changed", False), (before["state"], before["reason"], before["cancelRequired"]),
                         "printed only before the raise began: nothing is left to cancel")

    def test_local_refusals_come_before_any_contact_or_journal(self):
        for bad in ({**self.inputs(), "extra": "x"}, {key: value for key, value in self.inputs().items() if key != "step"}, self.inputs(step="approve"),
                    self.inputs(deploymentId="x"), self.inputs(operationId=OPERATION.replace("-", "")), self.inputs(step=7), "x", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "^windows_uac_visual_inputs$"):
                visual.prompt(self.root, bad)
        self.assertEqual(("refused", "uac_visual_not_raised"), (self.call("cancel")["state"], self.call("cancel")["reason"]))
        self.deploy({key: value for key, value in SETUP.items() if key != "purpose"})
        self.assertEqual("uac_visual_deployment_not_visual", self.call()["reason"], "an ordinary product clone has no such route")
        self.deploy(mode="stop")
        self.assertEqual("uac_visual_deployment_unavailable", self.call()["reason"])
        self.intent.unlink()
        self.assertEqual("uac_visual_deployment_unavailable", self.call()["reason"])
        self.assertEqual("uac_visual_deployment_unavailable", self.call(deploymentId=str(uuid.uuid4()))["reason"])
        self.assertEqual(([], []), (self.packets, self.journal()))
        self.deploy()
        with mock.patch.object(visual, "_EXECUTING_CODE", None), self.assertRaisesRegex(ValueError, "^windows_uac_visual_source_changed$"):
            self.call()
        with mock.patch.object(uac, "_EXECUTING_CODE", None), self.assertRaisesRegex(ValueError, "^windows_uac_visual_source_changed$"):
            self.call()
        self.assertEqual([], self.packets)

    def test_a_reply_cannot_claim_an_approval_an_answer_or_another_operation(self):
        for step, changes in (("raise", {"promptAnswered": True}), ("raise", {"pointerParked": False}), ("raise", {"operationId": str(uuid.uuid4())}),
                              ("raise", {"replayAllowed": True}), ("raise", {"extra": 1}), ("raise", {"frameSha256": "x"}),
                              ("raise", {"consent": {"pid": 1, "birth": "1", "sessionId": 1, "ageSeconds": uac.PROMPT_AGE_SECONDS}}),
                              ("raise", {"state": "visual-prompt-closed"}), ("cancel", {"approvalSucceeded": True}), ("cancel", {"promptClosed": False}),
                              ("cancel", {"escSent": "yes"}), ("cancel", {"framesDuringPrompt": ["../x"]}), ("cancel", {"state": "visual-prompt-raised"})):
            with self.subTest(step=step, changes=changes):
                shutil.rmtree(self.root / ".runtime/windows-uac-visual", ignore_errors=True)
                self.replies = [raised_terminal(**(changes if step == "raise" else {})), closed_terminal(**(changes if step == "cancel" else {}))]
                first = self.call()
                result = first if step == "raise" else self.call("cancel")
                self.assertEqual(("unknown", "uac_reply_rejected"), (result["state"], result["reason"]))
                self.assertNotIn(step + ".result.json", self.journal())

    def test_one_operation_belongs_to_one_deployment(self):
        self.replies = [raised_terminal()]
        self.call()
        other = str(uuid.uuid4())
        value = binding()
        value["spec"]["deploymentId"] = other
        path = self.intent.with_name(other + ".intent.json")
        path.write_text(json.dumps({"spec": value["spec"], "setup": value["setup"], "context": value["context"], "correlationId": uuid.uuid4().hex,
                                    "mode": "start", "callerSha256": "c" * 64}))
        path.chmod(0o600)
        self.assertEqual("uac_visual_operation_mismatch", self.call("cancel", deploymentId=other)["reason"])
        self.assertEqual(1, len(self.packets))


class RouteTests(unittest.TestCase):
    INPUTS = {"deploymentId": MACHINE, "operationId": OPERATION, "step": "raise"}

    def setUp(self):
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_cached_routes
        self.server = mcp_server
        bind_cached_routes(self, mcp_server, "windows_uac_visual")

    def test_closed_inputs_refuse_before_the_adapter(self):
        for bad in ({**self.INPUTS, "extra": "x"}, {**self.INPUTS, "step": "approve"}, {**self.INPUTS, "deploymentId": "x"},
                    {**self.INPUTS, "operationId": OPERATION.replace("-", "")}, {**self.INPUTS, "host": "fixture"}, {}):
            with self.subTest(bad=bad), mock.patch.object(self.server, "_agent_module", side_effect=AssertionError("refused first")):
                self.assertFalse(self.server._vm_workflow_dispatch("windows-uac-visual", bad)["ok"])
                self.assertTrue(self.server._vm_invalid_before_recovery("windows-uac-visual", bad))

    def test_the_route_passes_exactly_the_inputs_and_is_setup_not_an_answer(self):
        for state, ok in (("visual-prompt-raised", True), ("visual-prompt-closed", True), ("visual-prompt-open", False), ("refused", False), ("unknown", False)):
            with self.subTest(state=state), mock.patch.object(visual, "before_contact", return_value=None), \
                    mock.patch.object(visual, "prompt", return_value={"state": state, "replayAllowed": False}) as called:
                result = self.server.vm_workflow("windows-uac-visual", dict(self.INPUTS))
                called.assert_called_once_with(self.server.REPO_ROOT, self.INPUTS)
                self.assertEqual((ok, False, False, "uac-visual-setup"), (result["ok"], result["productAction"], result["nativeActionAllowed"], result["evidenceClass"]))
                self.assertNotIn("approvalSucceeded", result)
        with mock.patch.object(visual, "before_contact", return_value=None), mock.patch.object(visual, "prompt", side_effect=ValueError("private text")):
            failed = self.server.vm_workflow("windows-uac-visual", dict(self.INPUTS))
        self.assertEqual(("unknown", "uac_visual_unavailable", False), (failed["state"], failed["reason"], failed["ok"]))
        self.assertNotIn("private text", json.dumps(failed))

    def test_the_catalog_rows(self):
        from agent_tools import readiness_vm_dispatch as dispatch, tool_action_policy as policy
        row, decide = (policy.action_policy("vm_workflow", action) for action in ("windows-uac-visual", "windows-uac-decision"))
        self.assertEqual((decide.requirements, decide.permitted_recoveries, decide.classification), (row.requirements, row.permitted_recoveries, row.classification))
        route = dispatch.ROUTES["windows-uac-visual"]
        self.assertEqual(("windows_deployment", ("windows_uac_visual",)), (route["kind"], route["modules"]))
        for module in ("windows_uac_visual", "windows_uac_decision", "readiness_windows_remote", "readiness_windows_login", "windows_vm_instance",
                       "windows_visual_fixture"):
            self.assertIn(module, route["closure"])


class RouteAdmissionTests(LocalBase):
    """The public route over a real deployment intent: an owned windowsUacVisual clone has a reviewed route for its scene."""

    def setUp(self):
        super().setUp()
        from agent_tools import mcp_server
        self.server = mcp_server
        self.admissions = []
        original = mcp_server._agent_module

        def admitted(root, action, inputs, **options):
            self.admissions.append((action, inputs["step"]))
            return nullcontext()
        dispatch = types.SimpleNamespace(admitted_dispatch=admitted)

        def route(name):
            return dispatch if name == "readiness_vm_dispatch" else visual if name == "windows_uac_visual" else original(name)
        for patcher in (mock.patch.object(mcp_server, "_agent_module", side_effect=route), mock.patch.object(mcp_server, "REPO_ROOT", self.root)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_an_owned_visual_clone_has_a_reviewed_route_that_raises_and_cancels_its_prompt(self):
        """VIS 39242640: windows_scenario_not_allowlisted, a refused prompt name and no ordinary root left the scene with no route."""
        self.replies = [raised_terminal(), closed_terminal()]
        raised = self.server.vm_workflow("windows-uac-visual", self.inputs())
        self.assertEqual(("visual-prompt-raised", True, "uac-visual-setup", False), (raised.get("state"), raised.get("ok"), raised.get("evidenceClass"),
                                                                                  raised.get("productAction")), raised)
        closed = self.server.vm_workflow("windows-uac-visual", self.inputs("cancel"))
        self.assertEqual(("visual-prompt-closed", True, True), (closed["state"], closed["ok"], closed["promptClosed"]))
        self.assertEqual([("windows-uac-visual", "raise"), ("windows-uac-visual", "cancel")], self.admissions)
        self.assertEqual(["uac-visual-raise", "uac-visual-cancel"], self.modes())

    def test_a_local_refusal_never_waits_on_the_transport_admission(self):
        early = self.server.vm_workflow("windows-uac-visual", self.inputs("cancel"))
        self.assertEqual(("refused", "uac_visual_not_raised", False), (early.get("state"), early.get("reason"), early.get("ok")), early)
        self.deploy({key: value for key, value in SETUP.items() if key != "purpose"})
        self.assertEqual("uac_visual_deployment_not_visual", self.server.vm_workflow("windows-uac-visual", self.inputs())["reason"])
        self.assertEqual(([], []), (self.admissions, self.packets))

    def test_the_dispatch_names_the_deployments_own_host(self):
        from agent_tools import readiness_vm_dispatch as dispatch
        self.assertEqual("fixture", dispatch._deployment_host(self.root, self.inputs(), OPERATION))
        self.assertEqual(OPERATION, dispatch._operation(self.inputs()))


if __name__ == "__main__":
    unittest.main()
