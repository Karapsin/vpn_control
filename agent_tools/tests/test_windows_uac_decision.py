"""The one closed UAC action: proof before any key, one answer, and a repeat that only reads.

No VM, host or guest. The real screen_gate, private_keys and enter_private run against a fake monitor;
the real host_work classifier and sign-in block_prior judge the files over a real directory. Nothing here
proves a Windows, PowerShell or secure desktop behaviour: only a direct native run does.
"""
import base64
from contextlib import nullcontext
import hashlib
import importlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import uuid
import zlib

from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_windows as windows
# Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import readiness_windows
from agent_tools import readiness_windows_login as login
from agent_tools import ssh_transport as transport
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_lifecycle_runtime_stages as runtime_stages
from agent_tools import windows_tun_stages as tun_stages
from agent_tools import windows_uac_decision as decision
from agent_tools.tests.test_native_scenario_windows import Base as ScenarioBase, DriverBase, FakeSsh
from agent_tools.tests.test_native_vm_spec import request as vm_request
from agent_tools.tests.test_windows_idle_receipt_classes import Receipts, current_source
from agent_tools.tests.test_windows_scenario_host_job import Base as JobBase, POWERSHELL

update_cases = importlib.import_module("agent_tools.windows_public_updater.update_cases")

MACHINE = "33333333-4444-4555-8666-777777777777"
CORRELATION = "44444444-5555-4666-8777-888888888888"
SID = "S-1-5-21-1-2-3-1000"
ADMIN = "S-1-5-21-1-2-3-500"
BOOT = "134368653065000000"
SCENARIO = "windows-scoped-tun.restart-grant"
SECRET = b"FIXTURE_UAC_SENTINEL_A!9"
WIDTH, HEIGHT = 640, 400
CROP = [0, 0, 100, 10]
FIELD = [10, 300, 210, 320]
CONTEXT = {"operationRoot": "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-" + CORRELATION,
           "ordinarySid": SID, "ordinarySessionId": 2, "bootFileTimeUtc": BOOT}
FRESH = {"machine": MACHINE.upper(), "boot": "2026-11-07T00:00:00.0000000Z", "console": 2, "expectedSid": SID, "tokenSid": SID, "ordinary": True,
         "session": {"SessionId": 2, "State": 0, "Flags": 1, "User": "recovery", "Logon": 5}, "explorers": [{"Id": 9, "SessionId": 2}]}
SETUP = {"imageName": "Windows 11 Pro", "locale": "en-US", "user": "recovery", "administrator": "recoveryadmin"}
POSIX = os.name == "posix"


def frame(fill=200, *, dots=0):
    """One synthetic prompt; dark dots in the password box are what entered characters would add."""
    pixels = bytearray(bytes((fill, fill, fill)) * (WIDTH * HEIGHT))
    for at in range(dots):
        offset = (FIELD[1] * WIDTH + FIELD[0] + at) * 3
        pixels[offset:offset + 3] = b"\x10\x10\x10"
    return b"P6\n%d %d\n255\n" % (WIDTH, HEIGHT) + bytes(pixels)


def crop_hash(fill=200):
    return hashlib.sha256(bytes((fill, fill, fill)) * ((CROP[2] - CROP[0]) * (CROP[3] - CROP[1]))).hexdigest()


def png(raw_ppm, *, filters=(0, 1, 2, 3, 4)):
    """A QMP-shaped PNG of the same pixels, using every row filter, so the decoder is really exercised."""
    width, height, pixels = login.ppm(raw_ppm)
    stride = width * 3
    rows = bytearray()
    above = bytes(stride)
    for y in range(height):
        row = pixels[y * stride:(y + 1) * stride]
        kind = filters[y % len(filters)]
        out = bytearray(stride)
        for x in range(stride):
            left = row[x - 3] if x >= 3 else 0
            up = above[x]
            corner = above[x - 3] if x >= 3 else 0
            if kind == 1:
                value = left
            elif kind == 2:
                value = up
            elif kind == 3:
                value = (left + up) // 2
            elif kind == 4:
                estimate = left + up - corner
                near = (abs(estimate - left), abs(estimate - up), abs(estimate - corner))
                value = left if near[0] <= near[1] and near[0] <= near[2] else up if near[1] <= near[2] else corner
            else:
                value = 0
            out[x] = (row[x] - value) & 255
        rows += bytes((kind,)) + bytes(out)
        above = row

    def chunk(kind, body):
        return len(body).to_bytes(4, "big") + kind + body + (zlib.crc32(kind + body) & 0xffffffff).to_bytes(4, "big")
    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((8, 2, 0, 0, 0))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")


def consent(**changes):
    return {"pid": 4242, "birth": "134368653100000000", "sessionId": 2, "image": "C:\\Windows\\System32\\consent.exe", "signature": "Valid",
            "signer": "Microsoft Windows", "parentIsAppinfo": True, "ageSeconds": 3, **changes}


def census(**changes):
    return {"policy": {"enableLua": 1, "promptOnSecureDesktop": 1, "consentPromptBehaviorUser": 3}, "preload": "00000409", "adminSid": ADMIN, "bootFileTimeUtc": BOOT,
            "events": [{"name": "event-000009-scoped-tun-awaiting-current-input.json", "operationId": CORRELATION, "value": "restart-grant", "variant": "restart-grant"}],
            "sidValues": [ADMIN], "parked": [], "consents": [consent()], "helpers": 0, **changes}


def binding():
    spec = vm_request()
    spec.update(deploymentId=MACHINE, host="fixture", root="/owned/vm")
    return {"provider": "raw-qemu-windows", "spec": spec, "setup": dict(SETUP), "context": {"hostBootId": str(uuid.uuid4()), "pending": []},
            "uri": None, "domain": None, "xmlSha256": None}


def profile_value(prompt="vpn-broker", **changes):
    return {"schemaVersion": 1, "deploymentId": MACHINE, "prompt": prompt, "width": WIDTH, "height": HEIGHT,
            "crops": [{"rect": list(CROP), "sha256": crop_hash()}], "field": {"rect": list(FIELD), "maxDarkPixels": 4},
            "reviewedFrameSha256": "b" * 64, **changes}


@unittest.skipUnless(POSIX, "the owner and its journals are POSIX; the VM host is Linux")
class FlowBase(unittest.TestCase):
    """Runs the real flow as the packet does: gate, burn, journal, one answer, with _main's failure path."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "vm"
        self.root.mkdir(mode=0o700)
        self.decision = decision.decision_id(CORRELATION)
        self.keys = []
        self.monitor_calls = []
        self.frames = []
        self.censuses = []
        self.scripts = []
        self.gone = True
        self.first_key_files = None
        self.first_key_classification = None
        self.key_failure = None
        self.clock = [100.0]
        self.exit_failure = None
        self.script_failures = []

    def tree(self):
        return sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*") if path.is_file())

    def save(self, name, value):
        descriptor = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)

    def guard(self):
        pass

    def script(self, label, source):
        self.scripts.append((label, source))
        if self.script_failures:
            failure = self.script_failures.pop(0)
            if failure is not None:
                raise failure
        if label.startswith("login-after") or "__" not in source and "WaitForExit" in source:
            if self.exit_failure is not None:
                raise self.exit_failure
            return {"gone": self.gone}
        return self.censuses.pop(0) if len(self.censuses) > 1 else self.censuses[0]

    def monitor(self, command, arguments=None):
        self.monitor_calls.append((command, arguments))
        if command == "screendump":
            raw = self.frames.pop(0) if len(self.frames) > 1 else self.frames[0]
            Path(arguments["filename"]).write_bytes(raw)
            return {}
        if command == "query-mice":
            return [{"current": True, "absolute": True}]
        if command == "input-send-event":
            return {}
        self.assertEqual("send-key", command)
        if self.first_key_files is None:
            self.first_key_files = self.tree()
            self.first_key_classification = Receipts(self.root).run(current_source())
        self.keys.append(arguments)
        if self.key_failure is not None and len(self.keys) == self.key_failure:
            raise TimeoutError(SECRET.decode())
        return {}

    def values(self, answer, scenario, operation, attempt=1, secret=SECRET):
        row = decision.ROWS[scenario]
        return {"SPEC": {"deploymentId": MACHINE}, "OPERATION": operation, "UAC_PRELUDE": decision._PRELUDE, "UAC_EXIT": decision._EXIT, "UAC_DECISION": answer,
                "UAC_PROMPT": row["prompt"], "UAC_ROW": row, "UAC_CONTEXT": CONTEXT, "UAC_ATTEMPT": attempt,
                "UAC_SCREEN": {"width": WIDTH, "height": HEIGHT, "crops": [{"rect": list(CROP), "sha256": crop_hash()}]},
                "UAC_FIELD": {"rect": list(FIELD), "maxDarkPixels": 4}, "UAC_PROFILE_SHA": "a" * 64, "UAC_SCENARIO_OPERATION": CORRELATION,
                "UAC_CENSUS_SCRIPT": "fixed census", "UAC_GATE_SECONDS": decision.GATE_SECONDS, "UAC_PROMPT_AGE": decision.PROMPT_AGE_SECONDS,
                "UAC_CLOSE_WAIT": decision.CLOSE_WAIT_MILLISECONDS, "UAC_DARK_LEVEL": decision.DARK_LEVEL, "UAC_SECRET": secret}

    def run_owner(self, answer="approve", *, scenario=SCENARIO, operation=None, attempt=1, fresh=FRESH, frames=None, censuses=None):
        """The packet's child, with _main's own failure mapping and the real owner, over a fake clock."""
        operation = operation or self.decision
        self.frames = list(frames) if frames is not None else [frame()]
        self.censuses = list(censuses) if censuses is not None else [census()]
        owner = decision._UacOwner(self.root, operation, attempt)
        owner.prepare()
        decision._uac_create(owner.directory / (owner.prefix + ".intent.json"), {"operationId": operation, "attempt": attempt, "decision": answer, "replayAllowed": False})

        def sleep(seconds):
            self.clock[0] += seconds
        with mock.patch.dict(decision.__dict__, self.values(answer, scenario, operation, attempt)), \
                mock.patch.object(time, "sleep", sleep), mock.patch.object(time, "monotonic", lambda: self.clock[0]):
            try:
                owner.finish(decision._uac_flow(owner, self.root, self.save, self.monitor, self.guard, self.script, fresh))
            except BaseException as error:
                reason = str(error) if type(error) is ValueError and re.fullmatch("instance_[a-z_]{1,64}", str(error)) else "instance_observation_unknown"
                owner.fail(reason)
        self.owner = owner
        return owner.terminal()

    def classified(self):
        result = Receipts(self.root).run(current_source())
        return result["terminalCount"], sorted(row["reason"] for row in result["unresolved"])

    def assert_refused_no_key(self, terminal, reason):
        self.assertEqual(("input-refused", reason, False), (terminal["state"], terminal.get("reason"), terminal.get("inputAttempted")))
        self.assertEqual([], self.keys)
        self.assertEqual([], [name for name in self.tree() if "once-" in name or "input." in name or name.startswith("direct-guest")], "nothing burned, journaled or fenced")


class ProofBeforeKeyTests(FlowBase):
    def test_every_census_mismatch_refuses_with_no_key_and_nothing_burned(self):
        policy = census()["policy"]
        for changes, reason in (
                ({"policy": {**policy, "enableLua": 0}}, "instance_uac_policy"),
                ({"policy": {**policy, "promptOnSecureDesktop": 0}}, "instance_uac_policy"),
                ({"policy": {**policy, "consentPromptBehaviorUser": 0}}, "instance_uac_policy"),
                ({"preload": "00000419"}, "instance_uac_keyboard"),
                ({"bootFileTimeUtc": "134368653065000001"}, "instance_uac_boot_changed"),
                ({"parked": ["owner-parked.json"]}, "instance_uac_owner_parked"),
                ({"parked": ["task-owner-parked.json"]}, "instance_uac_owner_parked"),
                ({"events": []}, "instance_uac_event_not_pending"),
                ({"events": [{**census()["events"][0], "value": "restart-deny"}]}, "instance_uac_event_mismatch"),
                ({"events": [{**census()["events"][0], "operationId": str(uuid.uuid4())}]}, "instance_uac_event_mismatch"),
                ({"events": census()["events"] * 2}, "instance_uac_event_mismatch"),
                ({"adminSid": SID, "sidValues": [SID]}, "instance_uac_administrator"),
                ({"sidValues": ["S-1-5-21-9-9-9-500"]}, "instance_uac_administrator"),
                ({"sidValues": [ADMIN, ADMIN]}, "instance_uac_administrator"),
                ({"helpers": 1}, "instance_uac_helper_present"),
                ({"consents": [consent(), consent(pid=4243)]}, "instance_uac_consent_not_unique"),
                ({"consents": [consent(sessionId=1)]}, "instance_uac_consent_identity"),
                ({"consents": [consent(image="C:\\Windows\\Temp\\consent.exe")]}, "instance_uac_consent_identity"),
                ({"consents": [consent(signature="HashMismatch")]}, "instance_uac_consent_identity"),
                ({"consents": [consent(signer="Someone Else")]}, "instance_uac_consent_identity"),
                ({"consents": [consent(parentIsAppinfo=False)]}, "instance_uac_consent_identity"),
                ({"consents": [consent(birth="not-a-time")]}, "instance_uac_consent_identity"),
                ({"consents": [consent(ageSeconds=90)]}, "instance_uac_prompt_age"),
                ({"consents": [consent(ageSeconds=-1)]}, "instance_uac_prompt_age"),
                ({"extra": 1}, "instance_uac_census_shape")):
            with self.subTest(changes=changes):
                for path in self.root.iterdir():
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
                self.keys.clear()
                self.assert_refused_no_key(self.run_owner(censuses=[census(**changes)]), reason)

    def test_a_hold_refuses_and_nothing_is_burned(self):
        # A hold names a value no approve row accepts, and a row waiting for its fresh event finds none.
        held = [{"name": "event-000009-update-uac-action-pending.json", "operationId": CORRELATION, "value": "hold-current-prompt", "variant": "success-off"}]
        self.assert_refused_no_key(self.run_owner(scenario="windows-public-update.success-off", censuses=[census(events=held)]), "instance_uac_event_mismatch")
        shutil.rmtree(self.root / "windows-uac")
        self.assert_refused_no_key(self.run_owner(scenario="windows-public-update.install-cancelled", censuses=[census(events=[])]), "instance_uac_event_not_pending")

    def test_a_changed_consent_between_the_two_censuses_refuses(self):
        self.assert_refused_no_key(self.run_owner(censuses=[census(), census(consents=[consent(pid=4243)])]), "instance_uac_consent_changed")
        shutil.rmtree(self.root / "windows-uac")
        self.assert_refused_no_key(self.run_owner(censuses=[census(), census(consents=[consent(birth="134368653100000001")])]), "instance_uac_consent_changed")

    def test_the_session_must_be_the_scenario_session(self):
        for changes in ({"console": 3}, {"tokenSid": ADMIN}, {"ordinary": False}, {"expectedSid": ADMIN}, {"machine": str(uuid.uuid4())},
                        {"session": {**FRESH["session"], "State": 4}}):
            with self.subTest(changes=changes):
                for path in self.root.iterdir():
                    shutil.rmtree(path)
                self.assert_refused_no_key(self.run_owner(fresh={**FRESH, **changes}), "instance_uac_session_changed")

    def test_real_screen_gate_refuses_a_changed_frame_only_after_the_bound_with_no_key(self):
        changed = frame(fill=199)
        self.assert_refused_no_key(self.run_owner(frames=[changed]), "instance_uac_frame_unrecognized")
        self.assertLessEqual(self.clock[0] - 100.0, decision.GATE_SECONDS + 1)
        dumps = [call for call in self.monitor_calls if call[0] == "screendump"]
        self.assertGreater(len(dumps), 2, "only reads were retried")
        frames = [name for name in self.tree() if name.endswith(".ppm")]
        self.assertEqual(2, len(frames), "the last two frames are kept and the wait does not fill the disk")

    def test_entered_characters_in_the_field_refuse_with_no_key(self):
        self.assert_refused_no_key(self.run_owner(frames=[frame(dots=5)]), "instance_uac_field_not_empty")
        self.assertLessEqual(self.clock[0] - 100.0, decision.GATE_SECONDS + 1, "typed characters stay, so they refuse at the bound")
        self.assertGreater(sum(command == "screendump" for command, _ in self.monitor_calls), 2)

    def test_a_caret_in_the_field_is_read_again_and_the_prompt_is_answered(self):
        # The field is where the caret blinks: dark pixels that are gone a frame later never typed anything.
        terminal = self.run_owner(frames=[frame(), frame(dots=5), frame()])
        self.assertEqual("input-ack-only", terminal["state"])
        self.assertEqual(3, sum(command == "screendump" for command, _ in self.monitor_calls))

    def test_the_age_rule_holds_at_the_burn_and_counts_the_frames_read_after_the_census(self):
        # Forty unrecognized frames are ten seconds of the fake clock between the second census and the burn.
        frames = [frame()] + [frame(fill=199)] * 40 + [frame()]
        self.assert_refused_no_key(self.run_owner(frames=frames, censuses=[census(consents=[consent(ageSeconds=80)])]), "instance_uac_prompt_age")
        shutil.rmtree(self.root / "windows-uac")
        self.clock[0] = 100.0
        terminal = self.run_owner(frames=frames, censuses=[census(consents=[consent(ageSeconds=79)])])
        self.assertEqual("input-ack-only", terminal["state"], "79 s at the census and 10 s of frames is still under 90 s")

    def test_an_absent_prompt_waits_only_within_the_bound(self):
        self.assert_refused_no_key(self.run_owner(censuses=[census(consents=[])]), "instance_uac_consent_absent")
        self.assertLessEqual(self.clock[0] - 100.0, decision.GATE_SECONDS + 1)

    def test_a_prompt_that_appears_during_the_wait_is_admitted(self):
        terminal = self.run_owner(censuses=[census(consents=[]), census(consents=[]), census(), census()])
        self.assertEqual("input-ack-only", terminal["state"])

    def test_a_failed_census_read_retries_within_the_bound_and_a_guard_refusal_does_not(self):
        self.script_failures = [ValueError("instance_guest_program_failed")] * 400
        self.assert_refused_no_key(self.run_owner(), "instance_uac_census_unavailable")
        shutil.rmtree(self.root / "windows-uac")
        self.script_failures = [ValueError("instance_host_epoch")]
        self.scripts.clear()
        self.assert_refused_no_key(self.run_owner(), "instance_host_epoch")
        self.assertEqual(1, len(self.scripts))

    def test_a_black_display_gets_one_journaled_pointer_move_and_no_click_or_key(self):
        black = frame(fill=0)
        terminal = self.run_owner(frames=[black, frame()])
        self.assertEqual("input-ack-only", terminal["state"])
        moves = [arguments for command, arguments in self.monitor_calls if command == "input-send-event"]
        self.assertEqual(1, len(moves))
        self.assertEqual({"abs"}, {event["type"] for event in moves[0]["events"]}, "no button event")
        self.assertTrue((self.root / "windows-uac" / self.decision / "pointer.intent.json").exists())

    def test_a_second_black_display_refuses_instead_of_moving_again(self):
        self.assert_refused_no_key(self.run_owner(frames=[frame(fill=0)]), "instance_uac_display_black")
        self.assertEqual(1, sum(command == "input-send-event" for command, _ in self.monitor_calls))


class AnswerTests(FlowBase):
    def test_deny_is_one_esc_and_its_row_carries_no_secret(self):
        row = "windows-scoped-tun.restart-deny"
        events = [{"name": "event-000009-scoped-tun-awaiting-current-input.json", "operationId": CORRELATION, "value": "restart-deny", "variant": "restart-deny"}]
        with mock.patch.object(login, "private_keys", side_effect=AssertionError("deny validates no secret")):
            terminal = self.run_owner("deny", scenario=row, censuses=[census(events=events)])
        self.assertEqual([{"keys": [{"type": "qcode", "data": "esc"}], "hold-time": 80}], self.keys)
        self.assertEqual(("input-ack-only", True, "deny"), (terminal["state"], terminal["promptClosed"], terminal["decision"]))
        self.assertEqual(("login-after",), tuple(label[:11] for label, _ in self.scripts if label.startswith("login-after")))

    def test_approve_types_through_the_real_encoder_then_return(self):
        terminal = self.run_owner()
        self.assertEqual(len(SECRET) + 1, len(self.keys))
        self.assertEqual([{"type": "qcode", "data": "ret"}], self.keys[-1]["keys"])
        self.assertEqual(login.private_keys(SECRET), self.keys[:-1])
        self.assertEqual("input-ack-only", terminal["state"])

    def test_the_burn_journal_and_fence_exist_before_the_first_key_and_the_fence_holds(self):
        self.run_owner()
        once = [name for name in self.first_key_files if re.fullmatch(r"windows-uac/once-[0-9a-f]{64}\.json", name)]
        self.assertEqual(1, len(once))
        self.assertIn("windows-uac/" + self.decision + "/input.intent.json", self.first_key_files)
        self.assertIn("direct-guest-" + self.decision + ".intent.json", self.first_key_files)
        self.assertNotIn("windows-uac/" + self.decision + "/input.terminal.json", self.first_key_files)
        self.assertEqual(["original_guest_work_unresolved"], [row["reason"] for row in self.first_key_classification["unresolved"]], "reboot refuses while input is open")

    def test_the_fence_closes_under_the_real_classifier_after_the_answer(self):
        self.run_owner()
        self.assertEqual((1, []), self.classified())
        self.assertEqual({"exited": True, "exitcode": 0}, json.loads((self.root / ("direct-guest-" + self.decision + ".terminal.json")).read_text()))

    def test_every_census_label_is_a_read_only_class_a_lost_reply_cannot_hold_open(self):
        self.run_owner()
        labels = {label.rsplit("-", 1)[0] for label, _ in self.scripts}
        self.assertEqual({"login-admission", "login-after"}, labels)
        for label in sorted(labels | {"login-session"}):
            with self.subTest(label=label):
                for path in self.root.iterdir():
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
                receipts = Receipts(self.root)
                receipts.guest_program(label + "-0123456789ab", terminal=None)
                receipts.rpc = mock.Mock(return_value={"exited": True, "exitcode": 0})
                result = receipts.run(current_source())
                self.assertEqual((1, []), (result["terminalCount"], result["unresolved"]))

    def test_files_stay_out_of_the_flat_census_and_sign_in_history(self):
        self.run_owner()
        flat = {path.name for path in self.root.iterdir()}
        self.assertEqual({"windows-uac", *("direct-guest-" + self.decision + suffix for suffix in (".intent.json", ".ack.json", ".terminal.json"))}, flat)
        owner = login._ProtectedOwner(self.root, str(uuid.uuid4()), {}, "a" * 64, "a" * 64)
        self.assertIsNone(owner.block_prior(), "a later sign-in is not refused by anything here")

    def test_the_reply_is_ack_only_whatever_the_prompt_did(self):
        for gone in (True, False):
            with self.subTest(gone=gone):
                for path in self.root.iterdir():
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
                self.gone = gone
                self.keys.clear()
                terminal = self.run_owner()
                self.assertEqual((gone, False, False, False), (terminal["promptClosed"], terminal["approvalSucceeded"], terminal["productOutcomeProved"], terminal["replayAllowed"]))

    def test_a_wrong_password_leaves_consent_up_and_sends_nothing_more(self):
        self.gone = False
        terminal = self.run_owner()
        self.assertFalse(terminal["promptClosed"])
        self.assertEqual(len(SECRET) + 1, len(self.keys))
        self.assertEqual((1, []), self.classified(), "the fence closes: no more input can come from this decision")

    def test_a_failed_exit_read_claims_nothing_and_keeps_the_keys_as_they_were(self):
        self.exit_failure = ValueError("instance_guest_program_failed")
        terminal = self.run_owner()
        self.assertEqual(("input-ack-only", False), (terminal["state"], terminal["promptClosed"]))

    def test_no_frame_is_taken_from_the_first_key_on(self):
        self.run_owner()
        order = [command for command, _ in self.monitor_calls]
        self.assertNotIn("screendump", order[order.index("send-key"):])

    def test_the_secret_reaches_no_file_save_or_terminal(self):
        self.run_owner()
        for path in self.root.rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                self.assertNotIn(SECRET, raw, path.name)
                self.assertNotIn(b"qcode", raw, path.name)
                self.assertNotIn(b"hold-time", raw, path.name)

    def test_a_create_only_burn_refuses_a_second_decision_on_the_same_prompt(self):
        self.run_owner()
        typed = len(self.keys)
        other = decision.decision_id(str(uuid.uuid4()))
        terminal = self.run_owner(operation=other)
        self.assertEqual(("input-refused", "instance_uac_prompt_burned", False), (terminal["state"], terminal["reason"], terminal["inputAttempted"]))
        self.assertEqual(typed, len(self.keys))

    def test_a_new_prompt_is_a_new_burn(self):
        self.run_owner()
        typed = len(self.keys)
        other = decision.decision_id(str(uuid.uuid4()))
        fresh_prompt = census(consents=[consent(pid=5151, birth="134368659900000000")])
        self.assertEqual("input-ack-only", self.run_owner(operation=other, censuses=[fresh_prompt])["state"])
        self.assertEqual(2 * typed, len(self.keys))

    def test_the_same_decision_never_passes_its_owner_admission_twice(self):
        self.run_owner()
        owner = decision._UacOwner(self.root, self.decision, 2)
        with self.assertRaisesRegex(ValueError, "^instance_uac_original_input_unknown$"):
            owner.prepare()

    def test_an_attempt_refused_after_a_refusal_is_admitted_and_an_open_one_is_not(self):
        self.assert_refused_no_key(self.run_owner(censuses=[census(events=[])]), "instance_uac_event_not_pending")
        decision._UacOwner(self.root, self.decision, 2).prepare()
        directory = self.root / "windows-uac" / self.decision
        decision._uac_create(directory / "attempt-0002.intent.json", {"operationId": self.decision, "attempt": 2, "replayAllowed": False})
        with self.assertRaisesRegex(ValueError, "^instance_uac_original_unresolved$"):
            decision._UacOwner(self.root, self.decision, 3).prepare()


class LostOwnerTests(FlowBase):
    def lost_mid_password(self):
        self.key_failure = 3
        terminal = self.run_owner()
        self.assertEqual(3, len(self.keys))
        self.assertEqual(("input-owner-unknown", True), (terminal["state"], terminal["inputAttempted"]))
        return terminal

    def status(self, **options):
        values = self.values("approve", SCENARIO, self.decision)
        with mock.patch.dict(decision.__dict__, values):
            known = decision._uac_receipts(self.root, self.decision)
            if known is not None:
                return known
            return decision._uac_status_open(self.root, self.save, self.guard, self.script)

    def test_input_lost_mid_password_stays_unknown_and_its_text_stays_out(self):
        self.lost_mid_password()
        self.assertFalse((self.root / "windows-uac" / self.decision / "input.terminal.json").exists())
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified(), "unknown input keeps the fence open")
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertNotIn(SECRET, path.read_bytes())

    def test_status_never_keys_and_an_unknown_input_keeps_its_fence_open(self):
        self.lost_mid_password()
        typed = len(self.keys)
        self.monitor_calls.clear()
        self.gone = False
        self.assertEqual("input-owner-unknown", self.status()["state"])
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified())
        self.gone = True
        closed = self.status()
        self.assertEqual(("input-outcome-unknown", True, False, False), (closed["state"], closed["promptClosed"], closed["approvalSucceeded"], closed["productOutcomeProved"]))
        fence = "direct-guest-" + self.decision
        self.assertEqual([fence + ".intent.json"], sorted(path.name for path in self.root.iterdir() if path.name.startswith(fence)),
                         "no ack and no terminal: any integer exit would close the fence over an UNKNOWN input")
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified(), "reboots and new jobs on this clone still refuse")
        self.assertEqual(closed, self.status(), "a repeat reads the same record")
        self.assertEqual(typed, len(self.keys))
        self.assertEqual([], self.monitor_calls, "status has no monitor at all")

    def test_a_known_input_whose_fence_close_was_lost_is_closed_by_status(self):
        def save(name, value):
            if name.endswith(".ack.json"):
                raise OSError("the fence close is lost after the input terminal")
            FlowBase.save(self, name, value)
        self.save = save
        self.assertEqual("input-ack-only", self.run_owner()["state"])
        del self.save
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified())
        directory = self.root / "windows-uac" / self.decision
        decision._uac_create(directory / "attempt-0001.owner.json", {"operationId": self.decision, "pid": 4321, "birth": 7})
        known = self.status()
        self.assertEqual("input-ack-only", known["state"])
        self.assertEqual((1, []), self.classified(), "a known input closes its fence")
        fence = "direct-guest-" + self.decision
        self.assertEqual({"pid": 4321}, json.loads((self.root / (fence + ".ack.json")).read_text())["ack"], "the owner that typed, not the status packet")
        self.assertEqual({"exited": True, "exitcode": 0}, json.loads((self.root / (fence + ".terminal.json")).read_text()))
        self.assertEqual(known, self.status())

    def test_a_new_decision_refuses_while_that_prompt_is_up_and_not_once_it_is_gone(self):
        self.lost_mid_password()
        typed = len(self.keys)
        other = decision.decision_id(str(uuid.uuid4()))
        terminal = self.run_owner(operation=other)
        self.assertEqual(("input-refused", "instance_uac_original_input_unknown"), (terminal["state"], terminal["reason"]))
        self.assertEqual(typed, len(self.keys))
        third = decision.decision_id(str(uuid.uuid4()))
        self.key_failure = None
        terminal = self.run_owner(operation=third, censuses=[census(consents=[consent(pid=5151, birth="134368659900000000")])])
        self.assertEqual("input-ack-only", terminal["state"])

    def test_an_exit_read_that_fails_closes_nothing(self):
        self.lost_mid_password()
        self.exit_failure = ValueError("instance_guest_program_failed")
        with self.assertRaisesRegex(ValueError, "instance_guest_program_failed"):
            self.status()
        self.assertEqual((0, ["original_guest_work_unresolved"]), self.classified())

    def test_receipts_alone_answer_without_a_guest(self):
        directory = self.root / "windows-uac" / self.decision
        read = lambda: decision._uac_receipts(self.root, self.decision)
        self.assertEqual("no-input-recorded", read()["state"])
        directory.mkdir(parents=True, mode=0o700)
        self.assertEqual("no-input-recorded", read()["state"])
        decision._uac_create(directory / "attempt-0001.intent.json", {"operationId": self.decision, "attempt": 1, "replayAllowed": False})
        self.assertEqual("input-owner-unknown", read()["state"], "the intent was saved and no owner ever followed")
        decision._uac_create(directory / "attempt-0001.owner.json", {"operationId": self.decision, "pid": 77, "birth": 5})
        with mock.patch.object(decision, "_uac_birth", return_value=5):
            self.assertEqual(("input-owner-running", 1), (read()["state"], read()["attempt"]))
        with mock.patch.object(decision, "_uac_birth", return_value=6):
            self.assertEqual("input-owner-unknown", read()["state"], "another process holds that pid")
        decision._uac_create(directory / "attempt-0001.terminal.json", {"state": "input-refused", "operationId": self.decision, "attempt": 1, "reason": "instance_uac_policy", "inputAttempted": False, "replayAllowed": False})
        self.assertEqual("input-refused", read()["state"])
        decision._uac_create(directory / "input.intent.json", {"operationId": self.decision, "attempt": 1, "decision": "approve", "prompt": "vpn-broker", "consent": consent(), "replayAllowed": False})
        self.assertIsNone(read(), "input began and its owner is gone: only a census can say more")


@unittest.skipUnless(POSIX, "the owner is POSIX; the VM host is Linux")
class OwnerAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.decision = decision.decision_id(CORRELATION)

    def start(self, raw, answer="approve", fork=None, birth=None):
        owner = decision._UacOwner(self.root, self.decision, 1)
        fork = fork if fork is not None else mock.Mock(side_effect=AssertionError("no fork before a complete frame"))
        with mock.patch.dict(decision.__dict__, {"UAC_DECISION": answer}), mock.patch.object(sys, "platform", "linux"), \
                mock.patch("resource.setrlimit"), mock.patch.object(os, "fork", fork), mock.patch.object(decision, "_uac_birth", return_value=birth):
            return owner, owner.start(-1, [], types.SimpleNamespace(read=__import__("io").BytesIO(raw).read), wait_seconds=0.2)

    def test_an_incomplete_or_foreign_frame_refuses_before_any_journal_or_fork(self):
        directory = self.root / "windows-uac" / self.decision
        for raw, answer, reason in ((b"", "approve", "instance_uac_input_incomplete"), (b"\0\0\0", "approve", "instance_uac_input_incomplete"),
                                    (b"\0\0\0\0", "approve", "instance_uac_input_unsupported"), (b"\0\0\0\x41" + b"x" * 65, "approve", "instance_uac_input_unsupported"),
                                    (b"\0\0\0\5abc", "approve", "instance_uac_input_incomplete"), (b"\0\0\0\2abc", "approve", "instance_uac_input_incomplete"),
                                    (b"\0\0\0\1x", "deny", "instance_uac_input_unsupported"), (b"\0\0\0\0trailing", "deny", "instance_uac_input_incomplete")):
            with self.subTest(raw=raw, answer=answer), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                self.start(raw, answer)
            self.assertEqual([], [path.name for path in directory.iterdir()], "the attempt has no journal yet")
        with self.assertRaises(login.PrivateInputUnknown):
            self.start(b"\0\0\0\2\xc3\xa9")
        self.assertEqual([], [path.name for path in directory.iterdir()])

    def test_the_parent_reports_the_child_terminal_and_never_the_secret(self):
        def fork():
            directory = self.root / "windows-uac" / self.decision
            decision._uac_create(directory / "attempt-0001.terminal.json", {"state": "input-ack-only", "operationId": self.decision})
            return 777
        _, value = self.start(b"\0\0\0\3A!9", fork=fork, birth=9)
        self.assertEqual("input-ack-only", value["state"])
        self.assertNotIn("A!9", json.dumps(value))

    def test_the_parent_never_reads_a_terminal_still_being_written(self):
        """The detached child publishes its terminal while the decide parent polls for it.

        The parent may see no terminal yet and then the whole one, never a part of one, which it would report as an
        input whose outcome is unknown. Events order the two threads; no wait here depends on real time.
        """
        directory = self.root / "windows-uac" / self.decision
        writing, polled, writers = threading.Event(), threading.Event(), []
        real_write = os.write

        def write(descriptor, data):
            if writers and threading.current_thread() is writers[0] and not polled.is_set():
                writing.set()
                polled.wait(60)
            return real_write(descriptor, data)

        def publish():
            decision._uac_create(directory / "attempt-0001.terminal.json", {"state": "input-ack-only", "operationId": self.decision, "attempt": 1})

        def fork():
            writers.append(threading.Thread(target=publish))
            writers[0].start()
            self.assertTrue(writing.wait(60), "the child is inside its write")
            return 777

        def sleep(seconds):
            polled.set()
            writers[0].join(60)

        def release():
            polled.set()
            if writers:
                writers[0].join(60)
        self.addCleanup(release)
        owner = decision._UacOwner(self.root, self.decision, 1)
        stream = types.SimpleNamespace(read=io.BytesIO(b"\0\0\0\3A!9").read)
        with mock.patch.dict(decision.__dict__, {"UAC_DECISION": "approve"}), mock.patch.object(sys, "platform", "linux"), \
                mock.patch("resource.setrlimit"), mock.patch.object(os, "fork", fork), mock.patch.object(decision, "_uac_birth", return_value=9), \
                mock.patch.object(os, "write", write), mock.patch.object(time, "sleep", sleep):
            value = owner.start(-1, [], stream, wait_seconds=600)
        self.assertEqual("input-ack-only", value["state"], "an input that completed is never reported unknown")
        self.assertEqual([], [name for name in os.listdir(directory) if name.endswith(".tmp")])

    def test_the_parent_says_running_or_unknown_and_retains_no_stream(self):
        _, value = self.start(b"\0\0\0\3A!9", fork=lambda: 777, birth=9)
        self.assertEqual("input-owner-running", value["state"])
        shutil.rmtree(self.root / "windows-uac")
        _, value = self.start(b"\0\0\0\3A!9", fork=lambda: 777, birth=None)
        self.assertEqual("input-owner-unknown", value["state"], "dead with no terminal")

    def test_a_failed_fork_closes_its_attempt_as_a_refusal(self):
        with self.assertRaisesRegex(ValueError, "^instance_uac_owner_fork$"):
            self.start(b"\0\0\0\3A!9", fork=mock.Mock(side_effect=OSError("no process")))
        owner = decision._UacOwner(self.root, self.decision, 1)
        self.assertEqual(("input-refused", "instance_uac_owner_fork", False), (owner.terminal()["state"], owner.terminal()["reason"], owner.terminal()["inputAttempted"]))
        decision._UacOwner(self.root, self.decision, 2).prepare()

    def test_only_linux_owns_this_process(self):
        owner = decision._UacOwner(self.root, self.decision, 1)
        with mock.patch.object(sys, "platform", "darwin"), self.assertRaisesRegex(ValueError, "^instance_uac_owner_platform$"):
            owner.start(-1, [], None)

    def test_a_refused_attempt_cannot_be_reread_as_input(self):
        owner = decision._UacOwner(self.root, self.decision, 1)
        owner.prepare()
        owner.fail("instance_uac_policy")
        self.assertEqual((False, "input-refused"), (owner.terminal()["inputAttempted"], owner.terminal()["state"]))

    @unittest.skipUnless(sys.platform.startswith("linux"), "real fork and /proc: Linux runners only")
    def test_the_detached_child_keeps_the_lock_and_survives_its_parent(self):
        import fcntl
        lock = self.root / "lock"
        lock.write_bytes(b"")
        source = "import hashlib,json,os,re,sys,time,fcntl\nfrom pathlib import Path\n"
        for item in (decision.PrivateInputUnknown, decision.private_keys, decision._uac_load, decision._uac_create, decision._uac_birth, decision._UacOwner):
            source += inspect.getsource(item) + "\n"
        source += ("UAC_DECISION='approve'\nroot=Path(sys.argv[1])\nowner=decision=_UacOwner(root,sys.argv[2],1)\n"
                   "lock=os.open(root/'lock',os.O_RDONLY);fcntl.flock(lock,fcntl.LOCK_EX)\n"
                   "value=owner.start(lock,[],sys.stdin.buffer,wait_seconds=.05)\n"
                   "if type(value)is dict:print(json.dumps(value));sys.exit()\n"
                   "time.sleep(1);owner.finish({'state':'input-ack-only','length':len(value)});os._exit(0)\n")
        done = subprocess.run([sys.executable, "-I", "-B", "-c", source, str(self.root), self.decision], input=b"\0\0\0\3A!9", capture_output=True, timeout=30)
        self.assertEqual((0, b""), (done.returncode, done.stderr))
        self.assertEqual("input-owner-running", json.loads(done.stdout)["state"])
        probe = os.open(lock, os.O_RDONLY)
        self.addCleanup(os.close, probe)
        with self.assertRaises(BlockingIOError):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        terminal = self.root / "windows-uac" / self.decision / "attempt-0001.terminal.json"
        limit = time.monotonic() + 15
        while not terminal.exists() and time.monotonic() < limit:
            time.sleep(.05)
        self.assertEqual({"state": "input-ack-only", "length": 3}, json.loads(terminal.read_text()))


class PacketTests(unittest.TestCase):
    def decide(self, answer="approve", *, scenario=SCENARIO):
        return decision.program(binding(), "uac-decide", decision.decision_id(CORRELATION), attempt=1, answer=answer, prompt=decision.ROWS[scenario]["prompt"],
                                row=decision.ROWS[scenario], context=CONTEXT, profile=profile_value(), profile_sha="a" * 64, scenario_operation=CORRELATION)

    def test_whole_packets_compile_with_the_owner_before_wires_and_no_secret(self):
        raw = self.decide()
        compile(raw, "whole decide packet", "exec")
        text = raw.decode()
        self.assertLess(text.index("launched=uac_owner.start("), text.index("suffix='readiness-'+OPERATION"))
        self.assertLess(text.index("lock=os.open(root/'intent.json'"), text.index("launched=uac_owner.start("), "the owner keeps the root lock")
        self.assertIn("MODE='uac-decide'", text)
        self.assertEqual(1, text.count("globals()['UAC_SECRET']=launched"))
        self.assertNotIn(SECRET.decode(), text)
        self.assertNotIn("final-administrator", text)

    def test_a_status_packet_holds_no_key_path_and_reads_no_stdin(self):
        raw = decision.program(binding(), "uac-status", decision.decision_id(CORRELATION))
        compile(raw, "whole status packet", "exec")
        text = raw.decode()
        for word in ("send-key", "enter_private", "private_keys", "sys.stdin", "UAC_SECRET", "_uac_flow", "_UacOwner", "screendump"):
            self.assertNotIn(word, text, word)
        self.assertIn("MODE='uac-status'", text)
        self.assertLess(text.index("uac_known=_uac_receipts("), text.index("lock=os.open(root/'intent.json'"), "receipts answer without taking the lock")

    def test_the_packet_is_not_a_generic_executor(self):
        for changes in ({"context": {**CONTEXT, "operationRoot": "C:\\Users\\recovery\\AppData\\Local\\Temp"}},
                        {"context": {**CONTEXT, "operationRoot": CONTEXT["operationRoot"] + "';calc;'"}},
                        {"context": {**CONTEXT, "ordinarySid": "S-1-5-18"}},
                        {"answer": "maybe"}, {"answer": "deny"}, {"prompt": "install-helper"}, {"scenario_operation": "x"},
                        {"attempt": 0}, {"attempt": decision.ATTEMPT_LIMIT + 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decision.program(binding(), "uac-decide", decision.decision_id(CORRELATION),
                                 **{**dict(attempt=1, answer="approve", prompt="vpn-broker", row=decision.ROWS[SCENARIO], context=CONTEXT, profile=profile_value(),
                                           profile_sha="a" * 64, scenario_operation=CORRELATION), **changes})
        for mode in ("uac", "observe", "login-submit", ""):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                decision.program(binding(), mode, decision.decision_id(CORRELATION))

    @unittest.skipUnless(POSIX, "the fresh source loader's custody is POSIX here")
    def test_the_production_source_loader_renders_both_packets(self):
        from agent_tools import source_module_loader
        directory = Path(decision.__file__).parent
        with source_module_loader.request_scope(directory):
            adapter = source_module_loader.adapter(directory, "windows_uac_decision")
            status = adapter.program(binding(), "uac-status", decision.decision_id(CORRELATION))
            decide = adapter.program(binding(), "uac-decide", decision.decision_id(CORRELATION), attempt=1, answer="deny", prompt="vpn-broker",
                                     row=decision.ROWS["windows-scoped-tun.restart-deny"], context=CONTEXT, profile=profile_value(), profile_sha="a" * 64,
                                     scenario_operation=CORRELATION)
        self.assertEqual(decision.program(binding(), "uac-status", decision.decision_id(CORRELATION)).split(b"\nSPEC=")[0], status.split(b"\nSPEC=")[0])
        self.assertIn(b"class _UacOwner", decide)
        self.assertIn(b"def screen_gate(", decide)

    def test_census_source_follows_the_script_contract(self):
        source = decision.census_source(decision.ROWS[SCENARIO], CONTEXT, "recoveryadmin")
        source.encode("ascii")
        lines = source.rstrip().splitlines()
        self.assertEqual([len(lines) - 1], [number for number, line in enumerate(lines) if line.lstrip().startswith("[Console]::WriteLine(")])
        self.assertTrue(lines[-1].endswith(")"))
        self.assertIn("'S-1-5-18'", source)
        self.assertNotRegex(source, r"__[A-Z_]+__")
        self.assertNotIn("Start-Process", source)
        self.assertNotIn("send", source.casefold().replace("sendkeys", "send"))

    def test_census_tokens_are_checked_and_cannot_inject(self):
        for field in ("operationRoot",):
            with self.subTest(field=field), self.assertRaises(ValueError):
                decision.census_source(decision.ROWS[SCENARIO], {**CONTEXT, field: "C:\\x';Start-Process cmd;'"}, "recoveryadmin")
        with self.assertRaises(ValueError):
            decision.census_source(decision.ROWS[SCENARIO], CONTEXT, "admin';calc")

    def test_every_table_row_is_closed_and_has_a_helper_image(self):
        for name, row in {**decision.ROWS, **decision.DIRECT_ROWS}.items():
            with self.subTest(name=name):
                self.assertEqual({"prompt", "decision", "event", "field", "value", "variant", "sidEvent", "sidField"}, set(row))
                self.assertIn(row["prompt"], decision._HELPER_IMAGE)
                self.assertRegex(name, r"\Awindows-[a-z-]+(\.[a-z-]+)?\Z")
        update = [row for name, row in decision.ROWS.items() if name.startswith("windows-public-update.")]
        self.assertEqual({"install-helper"}, {row["prompt"] for row in update})
        self.assertEqual({"vpn-broker"}, {row["prompt"] for name, row in decision.ROWS.items() if name.startswith("windows-scoped-tun.")})
        self.assertNotIn("hold-current-prompt", {row["value"] for row in decision.ROWS.values()})

    def test_table_values_are_what_the_case_modules_publish(self):
        """The strings the owner writes: a row that drifted from them would refuse every native prompt."""
        cases = Path(update_cases.__file__).read_text(encoding="utf-8")
        tun = Path(tun_stages.__file__).read_text(encoding="utf-8")
        for name, row in decision.ROWS.items():
            with self.subTest(name=name):
                source = tun if name.startswith("windows-scoped-tun.") else cases
                self.assertIn('"' + row["event"] + '"' if source is cases else "'" + row["event"] + "'", source)
                self.assertIn(row["sidField"], source)
                if source is cases:
                    self.assertIn(row["value"], cases)
        self.assertEqual({"restart-deny"}, set(dedicated_driver.TUN_VARIANTS))
        self.assertEqual({"windows-scoped-tun." + variant for variant in dedicated_driver.TUN_VARIANTS} | {"windows-scoped-tun.restart-grant"},
                         {name for name in decision.ROWS if name.startswith("windows-scoped-tun.")},
                         "restart-grant has its answer, and the dispatcher admits it once the collector stage exists")
        # A returned CANCELLED is a known failure only for the synchronous grants: the async waits and protected storage park.
        self.assertEqual(update_cases.GRANT_VARIANTS - {"transport-loss"},
                         {name.split(".", 1)[1] for name, row in decision.ROWS.items() if name.startswith("windows-public-update.") and row["decision"] == "approve"}
                         - {"install-cancelled", "installer-wait-client-loss", "protected-storage-rejected"})

    def test_any_row_that_names_a_prompt_agrees_with_the_table(self):
        for name, row in windows.RECIPES.items():
            if "uac" in row:
                with self.subTest(name=name):
                    self.assertEqual(row["uac"], {key: decision.ROWS[name][key] for key in ("prompt", "decision", "event")})

    @unittest.skipUnless(POSIX, "alias pins are read through POSIX descriptors")
    def test_this_leaf_stays_out_of_every_alias_pin(self):
        source = inspect.getsource(readiness_windows._source_pins)
        self.assertNotIn("uac", source)
        pinned = {Path(path).name for path in readiness_windows._source_pins()}
        self.assertNotIn("windows_uac_decision.py", pinned)
        self.assertIn("readiness_windows_login.py", pinned)
        # Nothing a sign-in packet embeds, or an alias pins, imports it.
        for name in pinned:
            self.assertNotIn("windows_uac_decision", (Path(decision.__file__).with_name(name)).read_text(encoding="utf-8") if Path(decision.__file__).with_name(name).exists() else "")

    @unittest.skipUnless(POWERSHELL, "PowerShell parser unavailable; hosted Windows and Linux runners have one")
    def test_every_guest_program_parses(self):
        sources = {"census": decision.census_source(decision.ROWS[SCENARIO], CONTEXT, "recoveryadmin"),
                   "exit": decision._PRELUDE + decision._EXIT.replace("__PID__", "4242").replace("__BIRTH__", "1").replace("__WAIT__", "0")}
        for name, source in sources.items():
            with self.subTest(name=name):
                encoded = base64.b64encode(source.encode("ascii")).decode()
                script = ("$s=[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('" + encoded + "'));$e=$null;$t=$null;"
                          "[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$t,[ref]$e);if($e.Count){$e|ForEach-Object{[Console]::Error.WriteLine($_.Message)};exit 1}")
                result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
                self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))


@unittest.skipUnless(POSIX, "private profile files are POSIX")
class ProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / ".runtime").mkdir(mode=0o755)

    def review(self, raw=None, **changes):
        options = dict(crops=[CROP], field=FIELD, max_dark_pixels=4)
        options.update(changes)
        return decision.reviewed_uac_profile(self.root, MACHINE, "vpn-broker", frame() if raw is None else raw, **options)

    def test_a_reviewed_profile_is_private_create_only_and_matches_the_real_gate(self):
        profile = self.review()
        path = self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json"
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
        self.assertEqual(profile, json.loads(path.read_text()))
        self.assertTrue(login.screen_gate(frame(), {"width": WIDTH, "height": HEIGHT, "crops": profile["crops"]}))
        with self.assertRaises(FileExistsError):
            self.review()
        loaded, digest = decision._load_profile(self.root, MACHINE, "vpn-broker")
        self.assertEqual((profile, hashlib.sha256(path.read_bytes()).hexdigest()), (loaded, digest))

    def test_png_and_ppm_of_the_same_pixels_give_the_same_hashes(self):
        raw = bytearray(frame())
        at = len(raw) - WIDTH * HEIGHT * 3
        for offset in range(0, len(raw) - at, 3):
            raw[at + offset:at + offset + 3] = bytes((offset * 7 & 127 | 128, offset * 3 & 127 | 128, offset & 127 | 128))
        raw = bytes(raw)
        width, height, pixels = decision._png_pixels(png(raw))
        self.assertEqual((WIDTH, HEIGHT, login.ppm(raw)[2]), (width, height, pixels))
        from_ppm = decision.reviewed_uac_profile(self.root, MACHINE, "vpn-broker", raw, crops=[CROP], field=FIELD, max_dark_pixels=4)
        (self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json").unlink()
        from_png = decision.reviewed_uac_profile(self.root, MACHINE, "vpn-broker", png(raw), crops=[CROP], field=FIELD, max_dark_pixels=4)
        self.assertEqual(from_ppm["crops"], from_png["crops"])

    def test_a_foreign_png_refuses(self):
        good = png(frame(), filters=(0,))
        for bad in (good[:-1] + bytes((good[-1] ^ 1,)), b"\x89PNG\r\n\x1a\n", good.replace(bytes((8, 2, 0, 0, 0)), bytes((8, 6, 0, 0, 0)), 1)):
            with self.subTest(bad=bad[:16]), self.assertRaises((ValueError, struct_error())):
                decision._png_pixels(bad)

    def test_crops_leave_out_the_caret_and_the_pointer(self):
        for changes, reason in (({"crops": [[300, 190, 340, 210]]}, "windows_uac_profile_pointer_gap"),
                                ({"field": [300, 190, 340, 210]}, "windows_uac_profile_pointer_gap"),
                                ({"crops": [[0, 299, 100, 330]]}, "windows_uac_profile_caret"),
                                ({"crops": [[0, 0, WIDTH + 1, 10]]}, "windows_uac_profile"),
                                ({"crops": []}, "windows_uac_profile"),
                                ({"crops": [CROP] * 9}, "windows_uac_profile"),
                                ({"max_dark_pixels": -1}, "windows_uac_profile")):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                self.review(**changes)
        self.assertFalse((self.root / ".runtime/windows-uac-profiles").exists())

    def test_a_frame_with_characters_is_not_reviewable(self):
        with self.assertRaisesRegex(ValueError, "^windows_uac_profile_field_not_empty$"):
            self.review(frame(dots=5))

    def test_only_the_closed_prompts_have_a_profile(self):
        for prompt in ("qualification", "other", "../x"):
            with self.subTest(prompt=prompt), self.assertRaisesRegex(ValueError, "^windows_uac_profile$"):
                decision.reviewed_uac_profile(self.root, MACHINE, prompt, frame(), crops=[CROP], field=FIELD, max_dark_pixels=4)
        self.assertEqual("qualification", decision.reviewed_uac_profile(self.root, MACHINE, "qualification", frame(), crops=[CROP], field=FIELD, max_dark_pixels=4, direct=True)["prompt"])

    def test_a_profile_for_another_clone_or_prompt_is_not_read_as_this_one(self):
        self.review()
        for deployment, prompt in ((str(uuid.uuid4()), "vpn-broker"), (MACHINE, "install-helper")):
            with self.subTest(prompt=prompt), self.assertRaises((OSError, ValueError)):
                decision._load_profile(self.root, deployment, prompt)
        path = self.root / ".runtime/windows-uac-profiles" / MACHINE / "install-helper.json"
        path.write_text((self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json").read_text())
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "^windows_uac_profile$"):
            decision._load_profile(self.root, MACHINE, "install-helper")


def struct_error():
    import struct
    return struct.error


@unittest.skipUnless(POSIX, "private journals and the credential custody are POSIX")
class ExecuteBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "repository"
        self.root.mkdir()
        self.work = Path(temporary.name).resolve()
        self.decision = decision.decision_id(CORRELATION)
        self.packets = []
        self.reads = []
        self.replies = []
        self.context_reply = dict(CONTEXT)
        self.scenario = SCENARIO
        intents = self.root / ".rag_index/windows-vm-deploy-intents"
        intents.mkdir(parents=True, mode=0o700)
        spec = binding()
        path = intents / (MACHINE + ".intent.json")
        path.write_text(json.dumps({"spec": spec["spec"], "setup": spec["setup"], "context": spec["context"], "correlationId": str(uuid.uuid4()), "mode": "start", "callerSha256": "c" * 64}))
        path.chmod(0o600)
        key, known = self.work / "key", self.work / "known"
        for item in (key, known):
            item.write_text("x")
            item.chmod(0o600)
        config = self.root / ".vm-hosts.local.json"
        config.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester", "identityFile": str(key), "knownHostsFile": str(known)}}}))
        config.chmod(0o600)
        (self.root / ".runtime").mkdir(mode=0o755)
        self.credential = self.root / ".runtime/windows-vm-credentials" / MACHINE / "final-administrator.secret"
        self.credential.parent.mkdir(parents=True, mode=0o700)
        self.credential.write_bytes(SECRET + b"\n")
        self.credential.chmod(0o600)
        local = self.root / ".rag_index/native-scenario-windows" / CORRELATION
        local.mkdir(parents=True, mode=0o700)
        for name, value in (("program.json", {"program": {}, "dataDirectory": "/home/fixture/data"}), ("admission.json", {})):
            (local / name).write_text(json.dumps(value))
            (local / name).chmod(0o600)
        self.write_profile()
        for patcher in (mock.patch.object(execution, "_SCENARIOS", {*execution._SCENARIOS, *decision.ROWS, *decision.DIRECT_ROWS}),
                        mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=self.build),
                        mock.patch.object(transport, "run_ssh", side_effect=self.run_ssh)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.journal(self.scenario)

    def write_profile(self, prompt="vpn-broker"):
        path = self.root / ".runtime/windows-uac-profiles" / MACHINE / (prompt + ".json")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_text(json.dumps(profile_value(prompt)))
        path.chmod(0o600)

    def journal(self, scenario, state="submitted", **changes):
        directory = self.root / ".rag_index/native-scenario-executions"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        plan = {"scenarioId": scenario, "host": "fixture", "environment": MACHINE, "bundleHash": "a" * 64, "artifactIds": {"bundleManifest": "sha256-" + "a" * 64},
                "correlationId": CORRELATION, **changes}
        path = directory / (CORRELATION + ".json")
        path.write_text(json.dumps({"journalVersion": 1, "plan": plan, "state": state, "identity": None, "lastReason": "x", "evidencePaths": []}))
        path.chmod(0o600)

    def inputs(self, **changes):
        return {"host": "fixture", "environment": MACHINE, "correlationId": CORRELATION, "prompt": "vpn-broker", "decision": "approve", **changes}

    def build(self, config, host, timeout=30, command=(), ssh_binary="ssh"):
        return ["fake-ssh", *command]

    def run_ssh(self, argv, **options):
        command = argv[1:]
        if command[4].startswith("exec("):
            self.reads.append(command[-1])
            return subprocess.CompletedProcess(argv, 0, json.dumps({"state": "read", "value": self.context_reply}).encode(), b"")
        source = base64.b64decode(command[4][len("import base64;exec(base64.b64decode('"):-len("'))")])
        self.packets.append({"mode": re.search(rb"\nMODE='([a-z-]+)'\n", source)[1].decode(), "source": source, "argv": list(argv), "options": dict(options)})
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        if isinstance(reply, subprocess.CompletedProcess):
            return reply
        return subprocess.CompletedProcess(argv, 0, json.dumps(reply).encode(), b"")

    def ack(self, **changes):
        return {"state": "input-ack-only", "operationId": self.decision, "attempt": 1, "decision": "approve", "prompt": "vpn-broker", "promptClosed": True,
                "approvalSucceeded": False, "productOutcomeProved": False, "replayAllowed": False, **changes}

    def refused(self, reason="instance_uac_event_not_pending", attempt=1):
        return {"state": "input-refused", "operationId": self.decision, "attempt": attempt, "reason": reason, "inputAttempted": False, "replayAllowed": False}

    def execute(self, **changes):
        return decision.execute(self.root, self.inputs(**changes))

    def journal_files(self):
        directory = self.root / ".runtime/windows-uac-decisions" / self.decision
        return sorted(path.name for path in directory.iterdir()) if directory.exists() else []

    def assert_secret_nowhere(self):
        for path in self.root.rglob("*"):
            if path.is_file() and path != self.credential:
                self.assertNotIn(SECRET, path.read_bytes(), str(path))
        for packet in self.packets:
            self.assertNotIn(SECRET, packet["source"])
            self.assertNotIn(SECRET.decode(), " ".join(packet["argv"]))


class ExecuteGateTests(ExecuteBase):
    def assert_refused_before_contact(self, result, reason):
        self.assertEqual(("refused", reason, False), (result["state"], result["reason"], result["replayAllowed"]))
        self.assertEqual([], self.packets)
        self.assertEqual([], self.journal_files(), "nothing is journaled, so the call may simply be made again")

    def test_inputs_are_exactly_the_five(self):
        good = self.inputs()
        for bad in ({**good, "extra": "x"}, {key: value for key, value in good.items() if key != "decision"}, {**good, "host": "bad host"}, {**good, "host": 7},
                    {**good, "environment": "not-a-uuid"}, {**good, "environment": MACHINE.replace("-", "")}, {**good, "correlationId": CORRELATION.replace("-", "")},
                    {**good, "prompt": "msiexec"}, {**good, "prompt": "qualification"}, {**good, "decision": "maybe"}, {**good, "argv": ["cmd"]}, {**good, "path": "C:\\x"}, "x", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "^windows_uac_inputs$"):
                decision.execute(self.root, bad)
        self.assertEqual([], self.packets)

    def test_no_journal_row_or_a_foreign_plan_refuses_before_contact(self):
        self.assert_refused_before_contact(self.execute(correlationId=str(uuid.uuid4())), "uac_scenario_unknown")
        self.journal(SCENARIO, host="other")
        self.assert_refused_before_contact(self.execute(), "uac_scenario_mismatch")
        self.journal(SCENARIO, environment=str(uuid.uuid4()))
        self.assert_refused_before_contact(self.execute(), "uac_scenario_mismatch")
        self.journal("windows-ordinary-qualification")
        self.assert_refused_before_contact(self.execute(), "uac_scenario_not_in_table")

    def test_the_table_row_must_equal_the_inputs(self):
        self.assert_refused_before_contact(self.execute(decision="deny"), "uac_row_mismatch")
        self.assert_refused_before_contact(self.execute(prompt="install-helper"), "uac_row_mismatch")
        self.journal("windows-public-update.uac-denied")
        self.assert_refused_before_contact(self.execute(prompt="install-helper"), "uac_row_mismatch")

    def test_a_direct_row_is_not_reachable_through_the_public_inputs(self):
        self.journal("windows-uac-qualification.approve")
        self.assert_refused_before_contact(self.execute(), "uac_scenario_not_in_table")

    def test_a_terminal_or_unknown_journal_refuses_a_new_input(self):
        for state in ("unknown", "intent", "submitting"):
            with self.subTest(state=state):
                self.journal(SCENARIO, state=state)
                self.assert_refused_before_contact(self.execute(), "uac_scenario_not_running")

    def test_an_unreviewed_profile_refuses_before_contact(self):
        (self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json").unlink()
        self.assert_refused_before_contact(self.execute(), "uac_profile_unreviewed")
        self.assertEqual([], self.reads)

    def test_an_unreadable_context_refuses_and_opens_no_secret(self):
        with mock.patch.object(decision, "SecretFile", side_effect=AssertionError("no secret before the journal")):
            self.context_reply = {**CONTEXT, "ordinarySid": "S-1-5-18"}
            self.assert_refused_before_contact(self.execute(), "uac_context_unavailable")
            self.context_reply = {**CONTEXT, "operationRoot": "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-" + str(uuid.uuid4())}
            self.assert_refused_before_contact(self.execute(), "uac_context_unavailable")
            self.context_reply = None
            self.assert_refused_before_contact(self.execute(), "uac_context_unavailable")

    def test_a_changed_source_refuses_before_anything(self):
        with mock.patch.object(decision, "_EXECUTING_CODE", None), self.assertRaisesRegex(ValueError, "^windows_uac_source_changed$"):
            self.execute()
        self.assertEqual([], self.packets)


class ExecuteInputTests(ExecuteBase):
    def test_approve_passes_the_secret_on_stdin_only_and_acks_only(self):
        order = []
        real = decision.SecretFile

        def opened(path):
            order.append(("secret", self.journal_files()))
            return real(path)
        self.replies = [self.ack()]
        with mock.patch.object(decision, "SecretFile", side_effect=opened):
            result = self.execute()
        self.assertEqual({"state": "input-ack-only", "promptClosed": True, "approvalSucceeded": False, "productOutcomeProved": False, "attempt": 1,
                          "decisionId": self.decision, "correlationId": CORRELATION, "prompt": "vpn-broker", "decision": "approve", "replayAllowed": False}, result)
        self.assertEqual(["uac-decide"], [packet["mode"] for packet in self.packets])
        self.assertEqual(len(SECRET).to_bytes(4, "big") + SECRET, self.packets[0]["options"]["input"])
        self.assertIn("intent.json", order[0][1], "create-only journal before the credential opens")
        self.assertIn("attempt-0001.intent.json", order[0][1])
        self.assert_secret_nowhere()

    def test_the_credential_path_is_the_deployment_one_and_nothing_else_is_read(self):
        seen = []
        real = decision.SecretFile

        def opened(path):
            seen.append(path)
            return real(path)
        self.replies = [self.ack()]
        with mock.patch.object(decision, "SecretFile", side_effect=opened):
            self.execute()
        self.assertEqual([str(self.root.resolve() / ".runtime/windows-vm-credentials" / MACHINE / "final-administrator.secret")], seen)

    def test_deny_opens_no_secret_and_sends_an_empty_frame(self):
        self.journal("windows-scoped-tun.restart-deny")
        self.replies = [self.ack(decision="deny")]
        with mock.patch.object(decision, "SecretFile", side_effect=AssertionError("deny opens no credential")):
            result = self.execute(decision="deny")
        self.assertEqual("input-ack-only", result["state"])
        self.assertEqual(b"\0\0\0\0", self.packets[0]["options"]["input"])

    def test_a_repeat_is_a_status_packet_with_no_secret_and_no_stdin(self):
        self.replies = [self.ack(), self.ack()]
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.credential.unlink()
        with mock.patch.object(decision, "SecretFile", side_effect=AssertionError("a repeat opens no credential")):
            again = self.execute()
        self.assertEqual("input-ack-only", again["state"])
        self.assertEqual(["uac-decide", "uac-status"], [packet["mode"] for packet in self.packets])
        status = self.packets[1]
        self.assertNotIn("input", status["options"])
        self.assertEqual(subprocess.DEVNULL, status["options"]["stdin"])
        for word in (b"send-key", b"enter_private", b"sys.stdin"):
            self.assertNotIn(word, status["source"])

    def test_a_lost_reply_never_types_twice_and_reads_forever(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), {"state": "input-owner-running", "operationId": self.decision, "attempt": 1, "replayAllowed": False}, self.ack(), self.ack()]
        first = self.execute()
        self.assertEqual(("unknown", "uac_submission_unresolved", False), (first["state"], first["reason"], first["replayAllowed"]))
        self.assertEqual("running", self.execute()["state"])
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual(["uac-decide", "uac-status", "uac-status", "uac-status"], [packet["mode"] for packet in self.packets])
        self.assert_secret_nowhere()

    def test_a_reply_lost_on_an_exit_failure_is_unknown_too(self):
        self.replies = [subprocess.CompletedProcess([], 255, b"", b""), {"state": "no-input-recorded", "operationId": self.decision, "replayAllowed": False}]
        self.assertEqual("unknown", self.execute()["state"])
        second = self.execute()
        self.assertEqual(("unknown", "uac_original_submission_unknown"), (second["state"], second["reason"]))
        self.assertEqual(["uac-decide", "uac-status"], [packet["mode"] for packet in self.packets], "a status that saw nothing permits no new submit")

    def test_a_retained_known_refusal_permits_exactly_one_more_submit(self):
        self.replies = [self.refused(), self.ack(attempt=2)]
        first = self.execute()
        self.assertEqual(("refused", "instance_uac_event_not_pending"), (first["state"], first["reason"]))
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual(["uac-decide", "uac-decide"], [packet["mode"] for packet in self.packets])
        self.assertIn("UAC_ATTEMPT=2", self.packets[1]["source"].decode())

    def test_a_refusal_that_saw_the_prompt_due_ends_the_submits(self):
        """The status token outlives the prompt, so a polling client calls again; only a "not yet" refusal is retried."""
        for reason in ("instance_uac_consent_absent", "instance_uac_frame_unrecognized", "instance_uac_prompt_age", "instance_uac_event_mismatch"):
            with self.subTest(reason=reason):
                shutil.rmtree(self.root / ".runtime/windows-uac-decisions", ignore_errors=True)
                self.packets.clear()
                self.replies = [self.refused(reason)]
                first = self.execute()
                self.assertEqual(("refused", reason), (first["state"], first["reason"]))
                for _ in range(3):
                    self.assertEqual(first, self.execute(), "a repeat returns the same refusal")
                self.assertEqual(["uac-decide"], [packet["mode"] for packet in self.packets], "no second packet, flock or VM-root entry")
        shutil.rmtree(self.root / ".runtime/windows-uac-decisions")
        self.packets.clear()
        self.replies = [subprocess.TimeoutExpired("ssh", 1), self.refused("instance_uac_consent_absent")]
        self.assertEqual("unknown", self.execute()["state"])
        learned = self.execute()
        self.assertEqual(("refused", "instance_uac_consent_absent"), (learned["state"], learned["reason"]))
        self.assertEqual(learned, self.execute(), "a refusal learned by status ends the submits too")
        self.assertEqual(["uac-decide", "uac-status"], [packet["mode"] for packet in self.packets])

    def test_a_refusal_learned_by_status_permits_another_submit(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), self.refused(), self.ack(attempt=2)]
        self.assertEqual("unknown", self.execute()["state"])
        self.assertEqual("refused", self.execute()["state"])
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual(["uac-decide", "uac-status", "uac-decide"], [packet["mode"] for packet in self.packets])

    def test_a_pre_fork_refusal_is_known_and_permits_another_submit(self):
        self.replies = [{"state": "blocked", "operationId": self.decision, "reason": "instance_operator_busy", "errorClass": "ValueError", "replayAllowed": False}, self.ack(attempt=2)]
        first = self.execute()
        self.assertEqual(("refused", "instance_operator_busy"), (first["state"], first["reason"]))
        self.assertEqual("input-ack-only", self.execute()["state"])

    def test_a_status_blocked_reply_proves_nothing(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), {"state": "blocked", "operationId": self.decision, "reason": "instance_operator_busy", "errorClass": "ValueError", "replayAllowed": False},
                        self.ack()]
        self.execute()
        second = self.execute()
        self.assertEqual(("unknown", "instance_operator_busy"), (second["state"], second["reason"]))
        self.execute()
        self.assertEqual(["uac-decide", "uac-status", "uac-status"], [packet["mode"] for packet in self.packets])

    def test_a_typed_unsubmitted_transport_refusal_permits_another_submit(self):
        from agent_tools import readiness
        refusal = transport.PrelaunchReadinessRefusal(readiness.ReadinessBlocked("prepared_context_stale", self.decision), "a" * 64)
        self.replies = [refusal, self.ack(attempt=2)]
        first = self.execute()
        self.assertEqual(("refused", "uac_transport_unsubmitted"), (first["state"], first["reason"]))
        self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual(["uac-decide", "uac-decide"], [packet["mode"] for packet in self.packets])

    def test_a_sealed_returned_result_is_still_read(self):
        from agent_tools import readiness
        sealed = transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked("prepared_context_stale", self.decision),
                                                           subprocess.CompletedProcess([], 0, json.dumps(self.ack()).encode(), b""))
        self.replies = [sealed]
        self.assertEqual("input-ack-only", self.execute()["state"])

    def test_an_unavailable_credential_is_a_known_refusal_with_no_packet(self):
        self.credential.chmod(0o644)
        result = self.execute()
        self.assertEqual(("refused", "uac_credential_unavailable"), (result["state"], result["reason"]))
        self.assertEqual([], self.packets)
        self.credential.chmod(0o600)
        self.replies = [self.ack(attempt=2)]
        self.assertEqual("input-ack-only", self.execute()["state"])

    def test_an_echoed_secret_is_rejected_and_never_retained(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                shutil.rmtree(self.root / ".runtime/windows-uac-decisions", ignore_errors=True)
                reply = {"stdout": json.dumps(self.ack()).encode(), "stderr": b""}
                reply[stream] = reply[stream] + SECRET
                self.replies = [subprocess.CompletedProcess([], 0, reply["stdout"], reply["stderr"])]
                result = self.execute()
                self.assertEqual(("unknown", "uac_reply_rejected"), (result["state"], result["reason"]))
                self.assertNotIn(SECRET.decode(), json.dumps(result))
                self.assert_secret_nowhere()

    def test_a_reply_cannot_claim_success_or_replay(self):
        for changes in ({"approvalSucceeded": True}, {"productOutcomeProved": True}, {"replayAllowed": True}, {"promptClosed": "yes"}, {"operationId": str(uuid.uuid4())}, {"attempt": "1"},
                        {"decision": "deny"}, {"prompt": "install-helper"}, {"extra": 1}, {"state": "approved"}):
            with self.subTest(changes=changes):
                shutil.rmtree(self.root / ".runtime/windows-uac-decisions", ignore_errors=True)
                self.replies = [self.ack(**changes)]
                result = self.execute()
                self.assertEqual(("unknown", "uac_reply_rejected"), (result["state"], result["reason"]))
                self.assertNotIn("approvalSucceeded", result)

    def test_the_outcome_unknown_terminal_crosses_as_itself(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), self.ack(state="input-outcome-unknown")]
        self.execute()
        result = self.execute()
        self.assertEqual(("input-outcome-unknown", True, False, False), (result["state"], result["promptClosed"], result["approvalSucceeded"], result["productOutcomeProved"]))

    def test_refused_attempts_are_bounded(self):
        self.replies = [self.refused(attempt=number) for number in range(1, decision.ATTEMPT_LIMIT + 1)]
        for _ in range(decision.ATTEMPT_LIMIT):
            self.assertEqual("refused", self.execute()["state"])
        self.assertEqual("uac_attempts_exhausted", self.execute()["reason"])
        self.assertEqual(decision.ATTEMPT_LIMIT, len(self.packets))

    def test_status_reads_original_after_the_scenario_ended(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), self.ack()]
        self.execute()
        self.journal(SCENARIO, state="unknown")
        self.assertEqual("input-ack-only", self.execute()["state"], "a repeat reads, whatever became of the scenario")

    def test_a_create_only_race_on_the_attempt_reads_status_and_never_submits(self):
        original = decision.login._retain_local

        def raced(directory, name, value):
            if name == "attempt-0001.intent.json":
                raise FileExistsError()
            return original(directory, name, value)
        self.replies = [self.ack()]
        with mock.patch.object(decision.login, "_retain_local", side_effect=raced):
            self.assertEqual("input-ack-only", self.execute()["state"])
        self.assertEqual(["uac-status"], [packet["mode"] for packet in self.packets])

    def test_the_public_dispatch_admission_is_reused_and_a_direct_run_makes_its_own(self):
        self.replies = [self.ack()]
        self.execute()
        self.assertGreaterEqual(transport.admitted_transport.call_count, 1, "direct: this module admits the transport itself")
        transport.admitted_transport.reset_mock()
        self.replies = [self.ack()]
        with mock.patch.object(transport, "_dispatch_binding", return_value=object()):
            self.execute()
        self.assertEqual(0, transport.admitted_transport.call_count)

    def test_the_direct_rows_answer_only_with_direct_and_only_their_own_answer(self):
        self.journal("windows-uac-qualification.deny")
        self.write_profile("qualification")
        refused = decision.execute(self.root, self.inputs(prompt="qualification", decision="approve"), direct=True)
        self.assertEqual(("refused", "uac_row_mismatch"), (refused["state"], refused["reason"]))
        self.replies = [self.ack(prompt="qualification", decision="deny")]
        result = decision.execute(self.root, self.inputs(prompt="qualification", decision="deny"), direct=True)
        self.assertEqual("input-ack-only", result["state"])
        self.assertIn("whoami.exe", self.packets[0]["source"].decode())
        with self.assertRaisesRegex(ValueError, "^windows_uac_inputs$"):
            decision.execute(self.root, self.inputs(prompt="qualification", decision="deny"))


class StatusTokenTests(DriverBase):
    """The job side: the token a fixed client polls for, and the context the action reads."""

    def setUp(self):
        super().setUp()
        self.ssh = TokenSsh(self.work)
        self.row = {**windows.RECIPES["windows-ordinary-qualification"],
                    "uac": {"prompt": "vpn-broker", "decision": "deny", "event": "scoped-tun-awaiting-current-input"}}

    def started(self):
        started = self.executor().start(self.request())
        self.assertEqual("submitted", started["state"])
        return self.driver()

    def test_a_row_with_no_prompt_reads_nothing_more(self):
        driver = self.started()
        self.ssh.calls.clear()
        result = self.executor(driver).status(self.operation)
        self.assertEqual(("submitted", "original_owner_running"), (result["state"], result["reason"]))
        self.assertEqual(["observe"], self.ssh.calls)

    def test_the_token_appears_only_once_the_owner_published_its_event(self):
        driver = self.started()
        self.ssh.job_files["status.json"] = {"pendingKinds": ["child-intent"], "uacEvents": []}
        with mock.patch.dict(windows.RECIPES, {self.request()["scenarioId"]: self.row}):
            result = self.executor(driver).status(self.operation)
            self.assertEqual("original_owner_running", result["reason"])
            self.ssh.job_files["status.json"] = {"pendingKinds": ["child-intent"] * 16, "uacEvents": ["scoped-tun-awaiting-current-input"]}
            result = self.executor(driver).status(self.operation)
            self.assertEqual(("submitted", "uac-pending:vpn-broker:deny"), (result["state"], result["reason"]))

    def test_the_token_lasts_until_the_decision_has_its_input_terminal(self):
        driver = self.started()
        with mock.patch.dict(windows.RECIPES, {self.request()["scenarioId"]: self.row}):
            # The recent window alone no longer decides: sixteen later events can push the prompt out of it.
            self.ssh.job_files["status.json"] = {"pendingKinds": ["scoped-tun-awaiting-current-input"], "uacEvents": []}
            self.assertEqual("original_owner_running", self.executor(driver).status(self.operation)["reason"])
            self.ssh.job_files["status.json"] = {"uacEvents": ["scoped-tun-awaiting-current-input"],
                                                 "uacDecision": {"state": "input-ack-only", "decision": "deny", "prompt": "vpn-broker", "promptClosed": True}}
            self.assertEqual("original_owner_running", self.executor(driver).status(self.operation)["reason"])

    def test_a_missing_or_malformed_status_file_proves_nothing(self):
        driver = self.started()
        with mock.patch.dict(windows.RECIPES, {self.request()["scenarioId"]: self.row}):
            for value in (None, {"uacEvents": "scoped-tun-awaiting-current-input"}, ["x"]):
                with self.subTest(value=value):
                    self.ssh.job_files["status.json"] = value
                    self.assertEqual("original_owner_running", self.executor(driver).status(self.operation)["reason"])
            self.ssh.job_files["status.json"] = "lost"
            self.assertEqual("original_owner_running", self.executor(driver).status(self.operation)["reason"])

    def test_uac_context_reads_the_job_file_and_holds_nothing(self):
        driver = self.started()
        self.ssh.calls.clear()
        self.ssh.job_files["uac-context.json"] = dict(CONTEXT)
        self.assertEqual(CONTEXT, driver.uac_context(self.plan()))
        self.assertEqual(["read"], self.ssh.calls)
        self.ssh.job_files["uac-context.json"] = None
        with self.assertRaisesRegex(ValueError, "windows_scenario_uac_context_unavailable"):
            driver.uac_context(self.plan())

    def test_uac_context_needs_this_job(self):
        with self.assertRaisesRegex(ValueError, "windows_scenario_job_unknown"):
            self.driver().uac_context(self.plan())


class DenyRowAdmissionTests(ScenarioBase):
    """An expired prompt is the same public CANCELLED as Esc: a deny row needs its decision's terminal to pass."""

    def row(self, answer):
        return {**windows.RECIPES[self.request()["scenarioId"]], "uac": {"prompt": "vpn-broker", "decision": answer, "event": "scoped-tun-awaiting-current-input"}}

    def test_a_deny_row_is_refused_before_any_journal_until_collect_joins_the_decision(self):
        with mock.patch.dict(windows.RECIPES, {self.request()["scenarioId"]: self.row("deny")}), self.assertRaises(ValueError) as caught:
            windows.admit_start(self.root, self.request(), self.resolver)
        self.assertEqual("windows_scenario_deny_needs_decision_join", str(caught.exception))
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.root.joinpath(*windows._LOCAL_STATE).exists())

    def test_an_approve_row_is_admitted(self):
        with mock.patch.dict(windows.RECIPES, {self.request()["scenarioId"]: self.row("approve")}):
            self.assertEqual("approve", windows.admit_start(self.root, self.request(), self.resolver)["uac"]["decision"])


class TokenSsh(FakeSsh):
    def __init__(self, directory):
        super().__init__(directory)
        self.job_files = {}

    def respond(self, command):
        if command[:4] == ("python3", "-I", "-B", "-c") and command[4].startswith("exec("):
            import ast
            if ast.literal_eval(command[4][5:-1]) == windows._READ_JOB_FILE:
                value = self.job_files.get(command[6])
                if value == "lost":
                    raise OSError("lost")
                return "read", {"state": "read", "value": value} if value is not None else {"state": "unavailable"}
        return super().respond(command)


@unittest.skipUnless(POSIX, "private file modes are POSIX")
class JobContextTests(JobBase):
    def test_the_context_stage_retains_what_the_action_reads(self):
        plan, code, _ = self.run_job(stopAfter="context")
        self.assertEqual(0, code)
        value = json.loads((Path(plan["dataDirectory"]) / "uac-context.json").read_bytes())
        self.assertEqual({"operationRoot": "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"],
                          "ordinarySid": "S-1-5-21-1-2-3-1000", "ordinarySessionId": 2, "bootFileTimeUtc": "134368653065000000"}, value)
        self.assertEqual(0o600, (Path(plan["dataDirectory"]) / "uac-context.json").stat().st_mode & 0o777)
        decision._validate_context(value)
        self.assertEqual({"direct-guest"}, {path.name[:12] for path in self.vm.iterdir()}, "nothing of it reaches the VM root")


class RouteTests(unittest.TestCase):
    INPUTS = {"host": "fixture", "environment": MACHINE, "correlationId": CORRELATION, "prompt": "vpn-broker", "decision": "deny"}

    def setUp(self):
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_cached_routes
        self.server = mcp_server
        self.genuine = bind_cached_routes(self, mcp_server, "windows_uac_decision")
        # These route units fake the action itself; its local gates run against a real journal in RouteAdmissionTests.
        patcher = mock.patch.object(decision, "before_contact", return_value=None, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_closed_inputs_refuse_before_the_adapter(self):
        for bad in ({**self.INPUTS, "extra": "x"}, {**self.INPUTS, "prompt": "qualification"}, {**self.INPUTS, "decision": "maybe"}, {**self.INPUTS, "host": "a b"},
                    {**self.INPUTS, "correlationId": CORRELATION.replace("-", "")}, {**self.INPUTS, "environment": "x"}, {**self.INPUTS, "path": "C:\\x"}, {}):
            with self.subTest(bad=bad), mock.patch.object(decision, "execute", side_effect=AssertionError("refused first")):
                result = self.server.vm_workflow("windows-uac-decision", bad)
                self.assertFalse(result["ok"])

    def test_the_route_passes_exactly_the_inputs_and_keeps_the_ack_class(self):
        answer = {"state": "input-ack-only", "promptClosed": True, "approvalSucceeded": False, "productOutcomeProved": False, "replayAllowed": False}
        with mock.patch.object(decision, "execute", return_value=answer) as called:
            result = self.server.vm_workflow("windows-uac-decision", dict(self.INPUTS))
        called.assert_called_once_with(self.server.REPO_ROOT, self.INPUTS)
        self.assertEqual((True, False, False, False, "uac-input-ack-only"),
                         (result["ok"], result["approvalSucceeded"], result["productOutcomeProved"], result["productAction"], result["evidenceClass"]))

    def test_only_an_ack_is_ok_and_a_failure_is_finite(self):
        with mock.patch.object(decision, "execute", return_value={"state": "refused", "reason": "uac_row_mismatch", "replayAllowed": False}):
            self.assertFalse(self.server.vm_workflow("windows-uac-decision", dict(self.INPUTS))["ok"])
        with mock.patch.object(decision, "execute", side_effect=ValueError(SECRET.decode())):
            result = self.server.vm_workflow("windows-uac-decision", dict(self.INPUTS))
        self.assertEqual(("unknown", "uac_decision_unavailable"), (result["state"], result["reason"]))
        self.assertNotIn(SECRET.decode(), json.dumps(result))

    def test_the_catalog_rows(self):
        from agent_tools import readiness_vm_dispatch as dispatch, tool_action_policy as policy
        row = policy.action_policy("vm_workflow", "windows-uac-decision")
        self.assertEqual((frozenset({"transport"}), frozenset({"reconnect"}), "original_operation"), (row.requirements, row.permitted_recoveries, row.classification))
        route = dispatch.ROUTES["windows-uac-decision"]
        self.assertEqual(("selected_host", ("windows_uac_decision",)), (route["kind"], route["modules"]))
        for module in ("windows_uac_decision", "readiness_windows_login", "readiness_windows_remote", "private_credential_file"):
            self.assertIn(module, route["closure"])
        self.assertEqual("fixture", dispatch._selected_host(Path("/nonexistent"), self.INPUTS, route, CORRELATION))

    def test_the_review_is_a_sibling_closed_route_with_the_decisions_admission(self):
        from agent_tools import readiness_vm_dispatch as dispatch, tool_action_policy as policy
        decide, review = (policy.action_policy("vm_workflow", action) for action in ("windows-uac-decision", "windows-uac-review"))
        self.assertEqual((decide.requirements, decide.permitted_recoveries, decide.classification),
                         (review.requirements, review.permitted_recoveries, review.classification))
        self.assertEqual(dict(dispatch.ROUTES["windows-uac-decision"]), dict(dispatch.ROUTES["windows-uac-review"]))
        for bad in ({**self.INPUTS, "extra": "x"}, {**self.INPUTS, "prompt": "qualification"}, {**self.INPUTS, "decision": "review"}, {}):
            with self.subTest(bad=bad), mock.patch.object(decision, "review", side_effect=AssertionError("refused first"), create=True):
                self.assertFalse(self.server.vm_workflow("windows-uac-review", bad)["ok"])

    def test_a_review_route_reply_is_never_an_answer(self):
        retained = {"state": "review-frame-retained", "frameSha256": "a" * 64, "pointerMoved": True, "promptAnswered": False, "replayAllowed": False}
        with mock.patch.object(decision, "review", return_value=retained, create=True) as called:
            result = self.server.vm_workflow("windows-uac-review", dict(self.INPUTS))
        called.assert_called_once_with(self.server.REPO_ROOT, self.INPUTS)
        self.assertEqual((True, False, False, "uac-review-frame", False), (result["ok"], result["productAction"], result["nativeActionAllowed"],
                                                                         result["evidenceClass"], result["promptAnswered"]))
        self.assertNotIn("approvalSucceeded", result)
        with mock.patch.object(decision, "review", side_effect=ValueError(SECRET.decode()), create=True):
            failed = self.server.vm_workflow("windows-uac-review", dict(self.INPUTS))
        self.assertEqual(("unknown", "uac_review_unavailable", False), (failed["state"], failed["reason"], failed["ok"]))
        self.assertNotIn(SECRET.decode(), json.dumps(failed))

    @unittest.skipUnless(POSIX, "the server's own source custody is read through POSIX descriptors")
    def test_the_server_source_is_compiled_once_and_still_checked_on_every_adapter_load(self):
        """Each request loads several adapters, and each load compiled this 10k-line file again: over 1 s each under load."""
        import builtins
        real, compiled = builtins.compile, []

        def counting(source, filename, *args, **kwargs):
            if filename == self.server.__file__:
                compiled.append(filename)
            return real(source, filename, *args, **kwargs)
        genuine = self.genuine  # bind_cached_routes hands back the genuine loader
        with mock.patch.object(builtins, "compile", counting):
            for _ in range(3):
                genuine("tool_action_policy").close()
        self.assertLessEqual(len(compiled), 1)
        with mock.patch.object(self.server, "_MCP_EXECUTING_CODE", None), self.assertRaisesRegex(ValueError, "MCP source changed"):
            genuine("tool_action_policy")
        with mock.patch.dict(self.server._CHECK_RUNNER_SOURCE_DIGESTS, {Path(self.server.__file__).resolve(): "0" * 64}), \
                self.assertRaisesRegex(ValueError, "MCP source changed"):
            genuine("tool_action_policy")

    @unittest.skipUnless(importlib.util.find_spec("mcp") is not None, "this interpreter has no MCP package to leave out")
    def test_a_one_shot_cli_command_never_imports_the_mcp_package(self):
        """mcp_tool.sh execs the server once per native call; only `serve` ever serves."""
        done = subprocess.run([sys.executable, "-X", "importtime", self.server.__file__, "vm-workflow", "--help"], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=600)
        self.assertEqual(0, done.returncode, done.stderr[-2000:])
        self.assertIn(b"windows-uac-decision", done.stdout)
        self.assertNotIn(b"mcp.server.fastmcp", done.stderr, "a one-shot CLI command imported the MCP server package")
        self.assertIsNotNone(self.server.FastMCP, "an importer, like `serve`, still gets it")


DENY_ROW = "windows-scoped-tun.restart-deny"
DENY_EVENTS = [{"name": "event-000009-scoped-tun-awaiting-current-input.json", "operationId": CORRELATION, "value": "restart-deny", "variant": "restart-deny"}]
CENSUS_REFUSALS = (({"policy": {**census()["policy"], "enableLua": 0}}, "instance_uac_policy"),
                   ({"policy": {**census()["policy"], "promptOnSecureDesktop": 0}}, "instance_uac_policy"),
                   ({"preload": "00000419"}, "instance_uac_keyboard"), ({"bootFileTimeUtc": "134368653065000001"}, "instance_uac_boot_changed"),
                   ({"parked": ["owner-parked.json"]}, "instance_uac_owner_parked"), ({"events": []}, "instance_uac_event_not_pending"),
                   ({"events": [{**census()["events"][0], "value": "restart-deny"}]}, "instance_uac_event_mismatch"),
                   ({"events": [{**census()["events"][0], "operationId": str(uuid.uuid4())}]}, "instance_uac_event_mismatch"),
                   ({"adminSid": SID, "sidValues": [SID]}, "instance_uac_administrator"), ({"helpers": 1}, "instance_uac_helper_present"),
                   ({"consents": [consent(), consent(pid=4243)]}, "instance_uac_consent_not_unique"),
                   ({"consents": [consent(sessionId=1)]}, "instance_uac_consent_identity"),
                   ({"consents": [consent(image="C:\\Windows\\Temp\\consent.exe")]}, "instance_uac_consent_identity"),
                   ({"consents": [consent(signature="HashMismatch")]}, "instance_uac_consent_identity"),
                   ({"consents": [consent(parentIsAppinfo=False)]}, "instance_uac_consent_identity"),
                   ({"consents": [consent(ageSeconds=90)]}, "instance_uac_prompt_age"), ({"consents": []}, "instance_uac_consent_absent"),
                   ({"extra": 1}, "instance_uac_census_shape"))


def review_terminal(raw=None, *, attempt=1, answer="approve", **changes):
    """What a review packet prints for a retained frame: its terminal and the frame's exact bytes."""
    raw = frame() if raw is None else raw
    return {"state": "review-frame-retained", "operationId": decision.review_id(CORRELATION), "attempt": attempt, "decision": answer,
            "prompt": "vpn-broker", "consent": {"pid": 4242, "birth": "134368653100000000", "sessionId": 2, "ageSeconds": 5},
            "frameSha256": hashlib.sha256(raw).hexdigest(), "frameBytes": len(raw), "width": WIDTH, "height": HEIGHT, "pointerMoved": True,
            "wakeMilliseconds": 1000, "promptAnswered": False, "replayAllowed": False, "frame": base64.b64encode(zlib.compress(raw)).decode(), **changes}


class ReviewFlowTests(FlowBase):
    """The review packet's flow over a fake monitor: the decision's census, its one pointer move, one kept frame, no answer."""

    def review_values(self, answer, scenario, review, attempt):
        row = decision.ROWS[scenario]
        return {"SPEC": {"deploymentId": MACHINE}, "OPERATION": review, "UAC_DECISION": answer, "UAC_PROMPT": row["prompt"], "UAC_ROW": row,
                "UAC_CONTEXT": CONTEXT, "UAC_ATTEMPT": attempt, "UAC_SCENARIO_OPERATION": CORRELATION, "UAC_DECISION_ID": self.decision,
                "UAC_CENSUS_SCRIPT": "fixed census", "UAC_GATE_SECONDS": decision.GATE_SECONDS, "UAC_PROMPT_AGE": decision.PROMPT_AGE_SECONDS,
                "UAC_REVIEW_SETTLE": decision.REVIEW_SETTLE_SECONDS}

    def run_review(self, answer="approve", *, scenario=SCENARIO, attempt=1, fresh=FRESH, frames=None, censuses=None):
        """As the packet runs it: the flow, then the producer's failure path for any refusal."""
        review = decision.review_id(CORRELATION)
        self.frames = list(frames) if frames is not None else [frame()]
        self.censuses = list(censuses) if censuses is not None else [census()]

        def sleep(seconds):
            self.clock[0] += seconds
        with mock.patch.dict(decision.__dict__, self.review_values(answer, scenario, review, attempt)), \
                mock.patch.object(time, "sleep", sleep), mock.patch.object(time, "monotonic", lambda: self.clock[0]):
            owner = decision._UacReview(self.root, review, attempt)
            try:
                return decision._uac_review_flow(owner, self.root, self.monitor, self.guard, self.script, fresh)
            except BaseException as error:
                reason = str(error) if type(error) is ValueError and re.fullmatch("instance_[a-z_]{1,64}", str(error)) else "instance_observation_unknown"
                return owner.reply(reason) or {"state": "blocked", "reason": reason}

    def moves(self):
        return [arguments for command, arguments in self.monitor_calls if command == "input-send-event"]

    def answered(self):
        return [name for name in self.tree() if "once-" in name or "/input." in name or name.startswith("direct-guest")]

    def clear(self):
        for path in self.root.iterdir():
            shutil.rmtree(path) if path.is_dir() else path.unlink()
        self.monitor_calls.clear()
        self.keys.clear()

    def test_a_sleeping_display_with_no_profile_gets_one_post_wake_frame_and_no_key_or_burn(self):
        """NV7, run 73974d99: the vpn-broker prompt did not wake a sleeping display, and the clone had no reviewed profile."""
        black, prompt = frame(fill=0), frame()
        reply = self.run_review("deny", scenario=DENY_ROW, frames=[black, black, prompt, prompt], censuses=[census(events=DENY_EVENTS)])
        self.assertEqual(("review-frame-retained", True, False, "deny"), (reply["state"], reply["pointerMoved"], reply["promptAnswered"], reply["decision"]))
        self.assertEqual(1000, reply["wakeMilliseconds"], "the second half-second read after the move was the first lit one")
        self.assertEqual(1, len(self.moves()))
        self.assertEqual({"abs"}, {event["type"] for event in self.moves()[0]["events"]}, "a move, never a button")
        self.assertEqual([], self.keys)
        self.assertEqual(prompt, zlib.decompress(base64.b64decode(reply["frame"])), "the post-wake frame, not a black one")
        self.assertEqual(hashlib.sha256(prompt).hexdigest(), reply["frameSha256"])
        self.assertEqual([], self.answered(), "no burn, no input journal and no fence")
        self.assertIn("windows-uac/" + self.decision + "/pointer.intent.json", self.tree(), "the decision's own pointer journal")
        self.assertEqual("no-input-recorded", decision._uac_receipts(self.root, self.decision)["state"])

    def test_an_awake_display_is_kept_as_it_is_with_no_pointer_move(self):
        reply = self.run_review(frames=[frame()])
        self.assertEqual(("review-frame-retained", False, 0), (reply["state"], reply["pointerMoved"], reply["wakeMilliseconds"]))
        self.assertEqual([], self.moves())
        self.assertFalse((self.root / "windows-uac" / self.decision / "pointer.intent.json").exists())

    def test_a_repeat_never_moves_the_pointer_twice(self):
        first = self.run_review(frames=[frame(fill=0)])
        self.assertEqual(("review-refused", "instance_uac_display_black", True), (first["state"], first["reason"], first["pointerMoved"]))
        self.assertLessEqual(self.clock[0] - 100.0, decision.GATE_SECONDS + 2, "reading frames after the move is bounded")
        second = self.run_review(attempt=2, frames=[frame(fill=0)])
        self.assertEqual(("review-refused", "instance_uac_display_black", False), (second["state"], second["reason"], second["pointerMoved"]))
        third = self.run_review(attempt=3, frames=[frame()])
        self.assertEqual(("review-frame-retained", False, 0), (third["state"], third["pointerMoved"], third["wakeMilliseconds"]))
        self.assertEqual(1, len(self.moves()))
        self.assertEqual([], self.keys)

    def test_a_review_and_its_decision_move_the_pointer_once_between_them(self):
        self.assertTrue(self.run_review(frames=[frame(fill=0), frame(), frame()])["pointerMoved"])
        # The display went dark again before the decision: it refuses rather than move a second time.
        terminal = self.run_owner(frames=[frame(fill=0)])
        self.assertEqual(("input-refused", "instance_uac_display_black"), (terminal["state"], terminal["reason"]))
        self.assertEqual((1, []), (len(self.moves()), self.keys))
        self.clear()
        terminal = self.run_owner(frames=[frame(fill=0)])
        self.assertEqual("instance_uac_display_black", terminal["reason"], "the decision moved once and saw black again")
        reply = self.run_review(frames=[frame(fill=0)])
        self.assertEqual(("review-refused", "instance_uac_display_black", False), (reply["state"], reply["reason"], reply["pointerMoved"]))
        self.assertEqual(1, len(self.moves()))

    def test_the_review_never_answers_and_the_decision_then_answers_the_same_prompt(self):
        self.assertEqual("review-frame-retained", self.run_review(frames=[frame(fill=0), frame(), frame()])["state"])
        self.assertEqual([], self.keys)
        self.assertEqual((0, []), self.classified(), "nothing flat: no fence or input that a reboot or a new job waits on")
        self.assertEqual("no-input-recorded", decision._uac_receipts(self.root, self.decision)["state"])
        terminal = self.run_owner()
        self.assertEqual("input-ack-only", terminal["state"], "the same consent process: the prompt was still open")
        self.assertEqual(len(SECRET) + 1, len(self.keys))

    def test_every_census_refusal_of_the_decision_refuses_the_review_alike(self):
        cases = CENSUS_REFUSALS + tuple(({"session": changes}, "instance_uac_session_changed")
                                        for changes in ({"console": 3}, {"tokenSid": ADMIN}, {"ordinary": False}))
        for changes, reason in cases:
            with self.subTest(changes=changes):
                fresh = {**FRESH, **changes["session"]} if "session" in changes else FRESH
                censuses = [census()] if "session" in changes else [census(**changes)]
                self.clear()
                reply = self.run_review(frames=[frame(fill=0)], fresh=fresh, censuses=censuses)
                # A changed session refuses before the attempt begins, so the packet prints its plain refusal and no review file exists.
                expected = ("blocked", reason, None) if "session" in changes else ("review-refused", reason, False)
                self.assertEqual(expected, (reply.get("state"), reply.get("reason"), reply.get("pointerMoved")))
                self.assertEqual(([], []), (self.moves(), self.answered()))
                self.clear()
                self.assertEqual(reason, self.run_owner(fresh=fresh, censuses=censuses)["reason"], "the decision's own refusal")

    def test_a_prompt_its_decision_burned_is_never_reviewed(self):
        self.assertEqual("input-ack-only", self.run_owner()["state"])
        typed = len(self.keys)
        reply = self.run_review(frames=[frame(fill=0)])
        self.assertEqual(("review-refused", "instance_uac_prompt_burned", False), (reply["state"], reply["reason"], reply["pointerMoved"]))
        self.assertEqual((typed, []), (len(self.keys), self.moves()))

    def test_status_reads_files_only_and_an_attempt_that_left_nothing_ends_unknown(self):
        review = decision.review_id(CORRELATION)
        with mock.patch.dict(decision.__dict__, self.review_values("approve", SCENARIO, review, 1)):
            self.assertEqual("no-review-recorded", decision._uac_review_receipts(self.root, review)["state"])
            decision._UacReview(self.root, review, 1).begin()
            self.assertIsNone(decision._uac_review_receipts(self.root, review), "begun with no terminal: only the lock can say more")
            unknown = decision._uac_review_status_open(self.root, review)
            self.assertEqual(("review-outcome-unknown", 1, False), (unknown["state"], unknown["attempt"], unknown["promptAnswered"]))
            self.assertEqual(unknown, decision._uac_review_receipts(self.root, review))
        self.assertEqual([], self.monitor_calls)

    def test_a_kept_frame_is_read_back_whole_and_wins_over_a_late_failure(self):
        reply = self.run_review(frames=[frame()])
        review = decision.review_id(CORRELATION)
        with mock.patch.dict(decision.__dict__, self.review_values("approve", SCENARIO, review, 1)):
            self.assertEqual(reply, decision._uac_review_receipts(self.root, review))
            late = decision._UacReview(self.root, review, 1)
            late.begun = True
            self.assertEqual(reply, late.reply("instance_host_epoch"), "a terminal the attempt already has is its reply")
            frame_path = self.root / "windows-uac" / review / "attempt-0001.frame.ppm"
            self.assertEqual(0o600, frame_path.stat().st_mode & 0o777)
            frame_path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "^instance_uac_review_frame$"):
                decision._uac_review_receipts(self.root, review)

    def test_an_attempt_after_a_refusal_is_admitted_and_an_open_one_is_not(self):
        review = decision.review_id(CORRELATION)
        with mock.patch.dict(decision.__dict__, self.review_values("approve", SCENARIO, review, 1)):
            first = decision._UacReview(self.root, review, 1)
            first.begin()
            with self.assertRaisesRegex(ValueError, "^instance_uac_original_unresolved$"):
                decision._UacReview(self.root, review, 2).begin()
            first.reply("instance_uac_event_not_pending")
            decision._UacReview(self.root, review, 2).begin()


class ReviewPacketTests(unittest.TestCase):
    def review_packet(self, **changes):
        options = dict(attempt=1, answer="deny", prompt="vpn-broker", row=decision.ROWS[DENY_ROW], context=CONTEXT, scenario_operation=CORRELATION,
                       decision_operation=decision.decision_id(CORRELATION))
        options.update(changes)
        return decision.program(binding(), "uac-review", decision.review_id(CORRELATION), **options)

    def test_the_review_packets_compile_and_hold_no_key_secret_or_stdin(self):
        text = self.review_packet().decode()
        compile(text, "whole review packet", "exec")
        for word in ("send-key", "enter_private", "private_keys", "sys.stdin", "UAC_SECRET", "_uac_flow", "_UacOwner", "uac_owner.", "uac_owner=",
                     "final-administrator", "UAC_SCREEN", "UAC_FIELD", "UAC_PROFILE_SHA"):
            self.assertNotIn(word, text, word)
        self.assertIn("MODE='uac-review'", text)
        # The observe producer's own wake_display branch is in every packet; the review adds exactly one move of its own.
        helpers = text.split("\nSPEC=")[0]
        self.assertEqual(1, helpers.count("monitor('input-send-event'"), "one pointer move, the decision's")
        self.assertIn("UAC_DECISION_ID=" + repr(decision.decision_id(CORRELATION)), helpers)
        status = decision.program(binding(), "uac-review-status", decision.review_id(CORRELATION)).decode()
        compile(status, "whole review status packet", "exec")
        for word in ("send-key", "screendump", "sys.stdin", "UAC_SECRET", "enter_private"):
            self.assertNotIn(word, status, word)
        for word in ("monitor(", "script(", "input-send-event", "query-mice"):
            self.assertNotIn(word, status.split("\nSPEC=")[0], word)
        self.assertLess(status.index("uac_known=_uac_review_receipts("), status.index("lock=os.open(root/'intent.json'"),
                        "receipts answer without taking the lock")

    def test_the_review_packet_is_bound_to_its_own_scenario(self):
        for changes in ({"decision_operation": str(uuid.uuid4())}, {"scenario_operation": str(uuid.uuid4())}, {"answer": "approve"},
                        {"prompt": "install-helper"}, {"attempt": 0}, {"context": {**CONTEXT, "ordinarySid": "S-1-5-18"}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.review_packet(**changes)
        with self.assertRaises(ValueError):
            decision.program(binding(), "uac-review", decision.decision_id(CORRELATION), attempt=1, answer="deny", prompt="vpn-broker",
                             row=decision.ROWS[DENY_ROW], context=CONTEXT, scenario_operation=CORRELATION,
                             decision_operation=decision.decision_id(CORRELATION))

    @unittest.skipUnless(POSIX, "the fresh source loader's custody is POSIX here")
    def test_the_production_source_loader_renders_the_review_packets(self):
        from agent_tools import source_module_loader
        directory = Path(decision.__file__).parent
        with source_module_loader.request_scope(directory):
            adapter = source_module_loader.adapter(directory, "windows_uac_decision")
            packet = adapter.program(binding(), "uac-review", decision.review_id(CORRELATION), attempt=1, answer="deny", prompt="vpn-broker",
                                     row=decision.ROWS[DENY_ROW], context=CONTEXT, scenario_operation=CORRELATION,
                                     decision_operation=decision.decision_id(CORRELATION))
        self.assertIn(b"class _UacReview", packet)
        self.assertIn(b"def _uac_review_flow(", packet)


class ReviewExecuteTests(ExecuteBase):
    def review(self, **changes):
        return decision.review(self.root, self.inputs(**changes))

    def review_files(self):
        directory = self.root / ".runtime/windows-uac-reviews" / decision.review_id(CORRELATION)
        return sorted(path.name for path in directory.iterdir()) if directory.exists() else []

    def modes(self):
        return [packet["mode"] for packet in self.packets]

    def test_a_clone_with_no_profile_gets_a_reviewed_frame_without_key_burn_or_credential(self):
        """NV7, run 73974d99: the decision refused uac_profile_unreviewed three times before contact, and the prompt expired."""
        (self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json").unlink()
        self.assertEqual("uac_profile_unreviewed", self.execute()["reason"])
        self.replies = [review_terminal()]
        with mock.patch.object(decision, "SecretFile", side_effect=AssertionError("a review opens no credential")):
            result = self.review()
        self.assertEqual(("review-frame-retained", True, False), (result["state"], result["pointerMoved"], result["promptAnswered"]))
        self.assertEqual(1000, result["wakeMilliseconds"], "how long the display took to light: the decision gives its own move one second")
        self.assertEqual(["uac-review"], self.modes())
        self.assertEqual(subprocess.DEVNULL, self.packets[0]["options"]["stdin"])
        self.assertNotIn("input", self.packets[0]["options"])
        retained, record = decision.retained_review_frame(self.root, CORRELATION)
        self.assertEqual(frame(), retained)
        self.assertEqual((MACHINE, "vpn-broker", True, 1000), (record["environment"], record["prompt"], record["pointerMoved"], record["wakeMilliseconds"]))
        self.assertEqual((WIDTH, HEIGHT, login.ppm(frame())[2]), decision._png_pixels(Path(result["pngPath"]).read_bytes()))
        for name in ("framePath", "pngPath"):
            self.assertEqual(0o600, Path(result[name]).stat().st_mode & 0o777)
        self.assertFalse((self.root / ".runtime/windows-uac-decisions").exists(), "no decision journal")
        profile = decision.reviewed_uac_profile(self.root, record["environment"], record["prompt"], retained, crops=[CROP], field=FIELD,
                                                max_dark_pixels=4, direct=True)
        self.assertEqual(hashlib.sha256(retained).hexdigest(), profile["reviewedFrameSha256"])
        self.replies = [self.ack()]
        self.assertEqual("input-ack-only", self.execute()["state"], "the reviewed profile admits the decision on a later prompt")
        self.assertEqual(["uac-review", "uac-decide"], self.modes())
        self.assert_secret_nowhere()

    def test_a_lost_review_reply_never_sends_a_second_review_packet(self):
        self.replies = [subprocess.TimeoutExpired("ssh", 1), {"state": "blocked", "operationId": decision.review_id(CORRELATION),
                                                              "reason": "instance_operator_busy", "errorClass": "ValueError", "replayAllowed": False},
                        review_terminal()]
        first = self.review()
        self.assertEqual(("unknown", "uac_review_unresolved"), (first["state"], first["reason"]))
        busy = self.review()
        self.assertEqual(("unknown", "instance_operator_busy"), (busy["state"], busy["reason"]), "a status that saw nothing proves nothing")
        second = self.review()
        self.assertEqual("review-frame-retained", second["state"])
        self.assertEqual(second, self.review(), "a kept frame is returned again with no packet")
        self.assertEqual(["uac-review", "uac-review-status", "uac-review-status"], self.modes())

    def test_a_not_yet_refusal_permits_another_review_and_any_other_ends_them(self):
        review = decision.review_id(CORRELATION)

        def refused(reason, attempt=1, moved=False):
            return {"state": "review-refused", "operationId": review, "attempt": attempt, "reason": reason, "pointerMoved": moved, "replayAllowed": False}
        self.replies = [refused("instance_uac_event_not_pending"), review_terminal(attempt=2)]
        early = self.review()
        self.assertEqual(("refused", "instance_uac_event_not_pending"), (early["state"], early["reason"]))
        self.assertEqual("review-frame-retained", self.review()["state"])
        self.assertIn("UAC_ATTEMPT=2", self.packets[1]["source"].decode())
        for reason in ("instance_uac_consent_absent", "instance_uac_prompt_burned", "instance_uac_event_mismatch"):
            with self.subTest(reason=reason):
                shutil.rmtree(self.root / ".runtime/windows-uac-reviews")
                self.packets.clear()
                self.replies = [refused(reason)]
                first = self.review()
                self.assertEqual(("refused", reason), (first["state"], first["reason"]))
                self.assertEqual(first, self.review())
                self.assertEqual(["uac-review"], self.modes(), "no second packet")

    def test_a_display_still_black_permits_a_later_review_and_still_ends_the_decision(self):
        """A slow wake costs a call, not the run: the pointer journal on the VM host forbids the second move, not this client."""
        review = decision.review_id(CORRELATION)
        black = {"state": "review-refused", "operationId": review, "attempt": 1, "reason": "instance_uac_display_black", "pointerMoved": True,
                 "replayAllowed": False}
        self.replies = [black, {**black, "attempt": 2, "pointerMoved": False}, review_terminal(attempt=3, pointerMoved=False, wakeMilliseconds=0)]
        first = self.review()
        self.assertEqual(("refused", "instance_uac_display_black", True), (first["state"], first["reason"], first["pointerMoved"]))
        second = self.review()
        self.assertEqual(("refused", "instance_uac_display_black", False), (second["state"], second["reason"], second["pointerMoved"]))
        third = self.review()
        self.assertEqual(("review-frame-retained", False, 0, 3), (third["state"], third["pointerMoved"], third["wakeMilliseconds"], third["attempt"]))
        self.assertEqual(["uac-review"] * 3, self.modes())
        self.assertEqual(["UAC_ATTEMPT=%d" % number in packet["source"].decode() for number, packet in enumerate(self.packets, 1)], [True] * 3)
        self.assertEqual(third, self.review(), "the kept frame ends the reviews")
        self.assertEqual(3, len(self.packets))
        self.packets.clear()
        self.replies = [self.refused("instance_uac_display_black")]
        ended = self.execute()
        self.assertEqual(("refused", "instance_uac_display_black"), (ended["state"], ended["reason"]))
        self.assertEqual(ended, self.execute(), "the decision's own rule is unchanged: black after its move ends its submits")
        self.assertEqual(["uac-decide"], self.modes())

    def test_every_local_refusal_of_the_decision_refuses_the_review_before_contact(self):
        cases = ((lambda: self.journal(SCENARIO, host="other"), "uac_scenario_mismatch"),
                 (lambda: self.journal("windows-ordinary-qualification"), "uac_scenario_not_in_table"),
                 (lambda: self.journal(DENY_ROW), "uac_row_mismatch"),
                 (lambda: self.journal(SCENARIO, state="unknown"), "uac_scenario_not_running"),
                 (lambda: (self.root / ".rag_index/native-scenario-executions" / (CORRELATION + ".json")).unlink(), "uac_scenario_unknown"),
                 (lambda: (self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")).chmod(0o644), "uac_environment_unavailable"))
        for change, reason in cases:
            with self.subTest(reason=reason):
                self.journal(SCENARIO)
                (self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")).chmod(0o600)
                change()
                refused = self.review()
                self.assertEqual(("refused", reason, decision.review_id(CORRELATION)), (refused["state"], refused["reason"], refused["reviewId"]))
                self.assertEqual(reason, self.execute()["reason"], "the decision refuses alike")
                self.assertEqual(([], [], []), (self.packets, self.reads, self.review_files()))
        self.journal(SCENARIO)
        (self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")).chmod(0o600)
        self.context_reply = {**CONTEXT, "ordinarySid": "S-1-5-18"}
        self.assertEqual("uac_context_unavailable", self.review()["reason"])
        self.assertEqual(([], []), (self.packets, self.review_files()))

    def test_a_review_reply_cannot_claim_an_answer_or_carry_another_frame(self):
        consent_too_old = {"pid": 4242, "birth": "134368653100000000", "sessionId": 2, "ageSeconds": 90}
        for changes in ({"promptAnswered": True}, {"replayAllowed": True}, {"operationId": decision.decision_id(CORRELATION)}, {"frameSha256": "0" * 64},
                        {"frameBytes": 1}, {"width": WIDTH + 1}, {"frame": "not base64!"}, {"extra": 1}, {"decision": "deny"},
                        {"state": "input-ack-only"}, {"consent": consent_too_old}, {"wakeMilliseconds": 0}, {"wakeMilliseconds": -1},
                        {"wakeMilliseconds": True}, {"pointerMoved": False},
                        {"frame": base64.b64encode(zlib.compress(frame(fill=199))).decode()}):
            with self.subTest(changes=changes):
                shutil.rmtree(self.root / ".runtime/windows-uac-reviews", ignore_errors=True)
                self.replies = [review_terminal(**changes)]
                result = self.review()
                self.assertEqual(("unknown", "uac_reply_rejected"), (result["state"], result["reason"]))
                self.assertEqual([], [name for name in self.review_files() if name.startswith("frame.")])
        for correlation in (CORRELATION, str(uuid.uuid4())):
            with self.subTest(correlation=correlation), self.assertRaisesRegex(ValueError, "^windows_uac_review_frame_unavailable$"):
                decision.retained_review_frame(self.root, correlation)

    def test_the_binding_is_the_drivers_binding_without_the_sign_in_stack(self):
        profile = self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json"
        kept = profile.read_bytes()
        profile.unlink()
        program = ("import json,sys\nfrom agent_tools import windows_uac_decision as decision\n"
                   "reason=decision.execute(sys.argv[1],json.loads(sys.argv[2]))['reason']\n"
                   "print(json.dumps([reason,sorted(name for name in ('agent_tools.readiness_windows','agent_tools.native_scenario_windows',"
                   "'agent_tools.windows_scenario_host_job')if name in sys.modules)]))\n")
        done = subprocess.run([sys.executable, "-B", "-c", program, str(self.root), json.dumps(self.inputs())], cwd=Path(decision.__file__).parents[1],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
        self.assertEqual((0, b""), (done.returncode, done.stderr))
        self.assertEqual(["uac_profile_unreviewed", []], json.loads(done.stdout),
                         "a refusal local files decide loads neither the sign-in stack nor the scenario driver and its host job")
        profile.write_bytes(kept)
        profile.chmod(0o600)
        record = json.loads((self.root / ".rag_index/native-scenario-executions" / (CORRELATION + ".json")).read_text())
        plan = execution.ScenarioPlan.from_mapping(record["plan"])
        self.assertEqual(windows._binding(self.root, plan), decision._binding(self.root, plan))
        intent = self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")
        original = json.loads(intent.read_text())
        for change in (lambda value: value.update(mode="stop"), lambda value: value["spec"].update(deploymentId=str(uuid.uuid4())),
                       lambda value: value.update(extra=1), lambda value: value["spec"].update(host="other"), lambda value: value.pop("callerSha256")):
            value = json.loads(json.dumps(original))
            change(value)
            intent.write_text(json.dumps(value))
            with self.subTest(value=value):
                for reader in (windows._binding, decision._binding):
                    with self.assertRaises(ValueError):
                        reader(self.root, plan)
        intent.unlink()
        for reader in (windows._binding, decision._binding):
            with self.assertRaises(ValueError):
                reader(self.root, plan)
        intent.write_text(json.dumps(original))
        intent.chmod(0o600)


class RouteAdmissionTests(ExecuteBase):
    """The public route over a real journal: local refusals answer before the host's transport admission."""

    def setUp(self):
        super().setUp()
        from agent_tools import mcp_server
        self.server = mcp_server
        self.admissions = []
        original = mcp_server._agent_module

        def admitted(root, action, inputs, **options):
            self.admissions.append(action)
            return nullcontext()
        dispatch = types.SimpleNamespace(admitted_dispatch=admitted)

        def route(name):
            return dispatch if name == "readiness_vm_dispatch" else decision if name == "windows_uac_decision" else original(name)
        for patcher in (mock.patch.object(mcp_server, "_agent_module", side_effect=route), mock.patch.object(mcp_server, "REPO_ROOT", self.root)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_a_local_refusal_never_waits_on_the_transport_admission(self):
        (self.root / ".runtime/windows-uac-profiles" / MACHINE / "vpn-broker.json").unlink()
        result = self.server.vm_workflow("windows-uac-decision", self.inputs())
        self.assertEqual(("refused", "uac_profile_unreviewed", False), (result["state"], result["reason"], result["ok"]))
        self.assertEqual(([], [], []), (self.admissions, self.packets, self.reads),
                         "NV7, run 73974d99: this refusal waited on the host's transport admission three times")
        self.journal(SCENARIO, state="unknown")
        self.assertEqual("uac_scenario_not_running", self.server.vm_workflow("windows-uac-review", self.inputs())["reason"])
        self.assertEqual(([], [], []), (self.admissions, self.packets, self.reads), "no transport admission, context read or packet")

    def test_a_call_that_must_reach_the_host_is_admitted_first(self):
        self.replies = [self.ack(), review_terminal()]
        self.assertEqual("input-ack-only", self.server.vm_workflow("windows-uac-decision", self.inputs())["state"])
        reviewed = self.server.vm_workflow("windows-uac-review", self.inputs())
        self.assertEqual(("review-frame-retained", True, "uac-review-frame"), (reviewed["state"], reviewed["ok"], reviewed["evidenceClass"]))
        self.assertEqual(["windows-uac-decision", "windows-uac-review"], self.admissions)
        self.assertEqual(reviewed, self.server.vm_workflow("windows-uac-review", self.inputs()), "a kept frame comes back with no admission")
        self.assertEqual(["windows-uac-decision", "windows-uac-review"], self.admissions)


class FakeCli:
    """A public CLI answered by its arguments; the case module checks every envelope itself."""

    def __init__(self, workspace, controller):
        self.workspace = str(workspace)
        self.controller = controller
        self.running = False
        self.revision = 4
        self.commands = []
        self.installations = []
        self.install_reply = None
        self.operation_status = None

    def envelope(self, code="OK", *, final=True, exit_code=0, **data):
        body = {"schemaVersion": 1, "ok": exit_code == 0, "code": code, "final": final, "controllerId": self.controller, "configurationRevision": self.revision,
                "requestId": "aaaaaaaa-0000-4000-8000-000000000001", "data": data}
        return subprocess.CompletedProcess([], exit_code, json.dumps(body), "")

    def answer(self, arguments):
        words = [word for word in arguments if word not in {"--json"}]
        while words and words[0] in {"--controller-id", "--if-revision"}:
            words = words[2:]
        if "--async" in words:
            words.remove("--async")
        self.commands.append(words)
        if words == ["status"]:
            return self.envelope(runtimeRunning=self.running, activeMode="proxy-only" if self.running else None, selectedLocationId=None, activeLocationId=None)
        if words[:2] == ["updates", "transport-probe"]:
            return self.envelope()
        if words == ["updates", "check"]:
            return self.envelope()
        if words == ["updates", "status"]:
            return self.envelope(available=True, compatible=True, availableVersion="2.2.16", totalBytes=3, phase="ready", downloadedBytes=3, installations=self.installations)
        if words == ["updates", "download"]:
            body = json.loads(self.envelope("ACCEPTED", final=False).stdout)
            body["operationId"] = "bbbbbbbb-0000-4000-8000-000000000002"
            return subprocess.CompletedProcess([], 0, json.dumps(body), "")
        if words[:2] == ["operations", "wait"]:
            return self.envelope()
        if words[:2] == ["operations", "status"] and self.operation_status is not None:
            exit_code, body = self.operation_status
            return subprocess.CompletedProcess([], exit_code, json.dumps(body), "")
        if words == ["quit"]:
            return self.envelope()
        if words == ["off"]:
            self.running = False
            return self.envelope()
        if words in (["settings", "set", "mode", "proxy-only"], ["source", "set", "current-locations"], ["locations", "select", "location-1"]):
            return self.envelope()
        if words[:3] == ["locations", "add", "--input"]:
            return self.envelope(id="location-1")
        if words == ["on"]:
            self.running = True
            return self.envelope()
        raise AssertionError("unexpected public command: " + repr(words))


class FakeChild:
    def __init__(self, owner, label, argv, completed=None):
        self.owner, self.label, self.argv, self.completed_value = owner, label, tuple(argv), completed
        self.pid, self.birth, self.ordinal, self.terminal = 4100 + len(owner.children), "134368653065000001", len(owner.children), None
        self.process = types.SimpleNamespace(poll=lambda: None if self.terminal is None else 0, _handle=1)

    def wait(self):
        self.terminal = {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
        return self.terminal

    def completed(self):
        self.wait()
        return self.completed_value


class UpdateParked(BaseException):
    pass


class FakeUpdateOwner:
    """Exactly what the case reaches on the way to one public install, over declared peers."""

    def __init__(self, root):
        self.root = root
        self.operation = "2c731e91-c158-4e8a-b779-54076ce85229"
        self.children = []
        self.events = []
        self.parked = None
        self.environment = {}
        self.pins = [types.SimpleNamespace(path=Path("C:/owner"))]
        self.request = {"workspace": str(root / "workspace"), "cliPath": "C:\\app\\vpn-control-cli.exe", "casesPath": "C:\\s\\cases.py", "harnessPath": "C:\\s\\h.py",
                        "productVersion": "2.2.15", "context": {"ordinarySid": SID, "ordinarySessionId": 2, "bootIdentifier": "boot"}}
        self.by_path = {key.casefold(): types.SimpleNamespace(record={"sha256": "c" * 64}) for key in
                        ("C:\\s\\receipts.py", "C:\\s\\server.py", "C:\\s\\env.py", "C:\\s\\jdk.py", "C:\\s\\prepare.py", "C:\\s\\observer.py", "C:\\s\\lifecycle.py", "C:\\s\\collector.py",
                         self.request["cliPath"])}
        def terminate(handle, code):
            self.terminated.append(code)
            return True
        self.terminated = []
        self.native = types.SimpleNamespace(read_blocks=lambda handle: [b"abc"], birth=lambda handle: "134368653065000001",
                                            k=types.SimpleNamespace(TerminateProcess=terminate))
        self.cli = FakeCli(root / "workspace", "controller-1")
        self.install_result = None
        self.modules = {}

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, value))

    def park(self, reason, error=None):
        self.parked = (reason, error)
        raise UpdateParked(reason)

    def module(self, path, name):
        return self.modules[path]

    def invoke(self, workspace, *arguments, timeout=30):
        return self.cli.answer(list(arguments))

    def child(self, label, argv, **options):
        child = FakeChild(self, label, argv, self.install_result if label == "one-public-update-install" else None)
        self.children.append(child)
        return child


class Observation:
    def __init__(self, owner, path, directory=False):
        self.owner, self.path, self.handle, self.opening = owner, path, 1, {"security": "s"}

    def read(self, limit):
        stage = Path(str(self.path).replace("\\", "/")).stem
        inputs = self.owner.harness["UPDATE_INPUTS"]
        observations = ({"kind": inputs["variant"], "binding": inputs["faultInputs"]} if stage == "fault-ready" else
                        {"ordinaryOwner": {"token": {"sid": SID, "elevated": 0}, "pid": 4100, "creationFileTime": 134368653065000001,
                                           "image": "C:\\app\\vpn-control-cli.exe", "sha256": "c" * 64}})
        return json.dumps({"schemaVersion": 1, "ordinaryTaskOperationId": "2c731e91-c158-4e8a-b779-54076ce85229", "stage": stage, "sourceSha": "a" * 40,
                           "collectorSourceSha256": "c" * 64, "bootIdentifier": "boot", "jobId": None, "productOperationId": None,
                           "observations": observations}).encode()

    def describe(self):
        return self.opening

    def _canonical(self):
        pass

    def close(self):
        pass


class CancelledGrantUpdateTests(unittest.TestCase):
    """A prompt that expires reaches a grant as the product's own CANCELLED: known and closed, never parked."""

    def harness(self, variant="success-off", *, connected=False, reply_code="CANCELLED"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        owner = FakeUpdateOwner(Path(temporary.name))
        owner.cli.running = False
        operation = "cccccccc-0000-4000-8000-000000000003"
        body = {"schemaVersion": 1, "ok": False, "code": reply_code, "final": True, "controllerId": "controller-1", "operationId": operation,
                "requestId": "dddddddd-0000-4000-8000-000000000004", "data": {}}
        owner.install_result = subprocess.CompletedProcess([], 130, json.dumps(body), "")
        owner.cli.installations = [{"originControllerId": "controller-1", "operationId": operation, "originRequestId": "dddddddd-0000-4000-8000-000000000004",
                                    "final": True, "installed": False, "jobId": "eeeeeeee-0000-4000-8000-000000000005"}]
        self.fixture_closes = []
        lease = types.SimpleNamespace(files=[types.SimpleNamespace(digest=lambda: None)], retired=False, admitted=False)
        fixture = types.SimpleNamespace(ready={"sourceFingerprint": "f" * 64}, manifest={"assets": [{"displayVersion": "2.2.16", "sizeBytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest(), "fileName": "t.msi"}]},
                                        owner_jvm_environment=dict, closed=False)

        def close_known(*, all_update_operations_terminal, cancelled_download=False):
            fixture.closed = True
            self.fixture_closes.append(all_update_operations_terminal)
        fixture.close_known = close_known
        receipts = types.SimpleNamespace(within=lambda *_: True, InstalledApplicationLease=lambda *_: lease, installed_registration=lambda *_: {},
                                         preserve=lambda *_: None, canonical_uuid=lambda value: value, machine_security=lambda *_: None,
                                         canonical_path=lambda value: Path(str(value).replace("\\", "/")), FileObservation=Observation,
                                         handoff=update_cases.__dict__.get("_handoff") or real_handoff)
        modules = {"C:\\s\\receipts.py": receipts, "C:\\s\\server.py": types.SimpleNamespace(UpdateFixture=lambda *_: fixture),
                   "C:\\s\\env.py": types.SimpleNamespace(), "C:\\s\\jdk.py": types.SimpleNamespace(),
                   "C:\\s\\prepare.py": types.SimpleNamespace(require_install_ready=lambda *_: None, desktop_install_arguments=lambda *_, **__: ["--json", "updates", "install"]),
                   "C:\\s\\observer.py": types.SimpleNamespace(), "C:\\s\\lifecycle.py": types.SimpleNamespace(cleanup_update_traffic=lambda *_: None)}
        owner.modules = modules
        inputs = {"schemaVersion": 1, "variant": variant, "sourceSha": "a" * 40, "sourceFingerprint": "f" * 64,
                  "modules": {"receipts": "C:\\s\\receipts.py", "server": "C:\\s\\server.py", "fixture_environment": "C:\\s\\env.py", "macos_packaging_jdk_preflight": "C:\\s\\jdk.py",
                              "prepare_desktop_update_fixture": "C:\\s\\prepare.py", "broker_observer": "C:\\s\\observer.py", "lifecycle": "C:\\s\\lifecycle.py", "collector": "C:\\s\\collector.py"},
                  "fixture": {"fixtureId": "x", "content": "c", "state": "s", "certificate": "e", "privateKey": "k", "trustStore": "t", "certificateSha256": "h"},
                  "baseVersion": "2.2.15", "targetVersion": "2.2.16", "installedRoot": "C:\\app", "guiPath": "C:\\app\\VPN.exe", "baseInventory": {"a": {"sizeBytes": 1, "sha256": "a" * 64}},
                  "targetInventory": {"a": {"sizeBytes": 1, "sha256": "b" * 64}}, "baseRegistration": {}, "targetRegistration": {}, "programData": "C:\\ProgramData",
                  "evidenceRoot": "C:\\ProgramData\\update-evidence-" + owner.operation, "collectorSourceSha256": "c" * 64, "ordinarySid": SID, "ordinarySessionId": 2,
                  "approvingAdminSid": ADMIN, "initialIntent": "off", "trafficInputs": None, "faultInputs": {}, "returnGuiRequired": False, "connectionFixturePath": None}
        owner.harness = {"UPDATE_INPUTS": inputs}
        return owner, fixture

    def test_a_cancelled_grant_is_closed_and_known_where_it_used_to_park_the_clone(self):
        owner, fixture = self.harness()
        with mock.patch.object(update_cases.time, "sleep"):
            result = update_cases.run_update(owner, owner.harness)
        self.assertEqual(1, result)
        self.assertIsNone(owner.parked)
        self.assertTrue(fixture.closed)
        self.assertEqual([["quit"]], [command for command in owner.cli.commands if command == ["quit"]])
        self.assertTrue(all(child.terminal is not None for child in owner.children), "no child is left for the owner to park on")
        self.assertEqual({"variant": "success-off", "operationId": "cccccccc-0000-4000-8000-000000000003"}, owner.update_cancelled_grant)
        self.assertIn("update-grant-cancelled-known", [kind for kind, _ in owner.events])

    def test_a_cancelled_connected_grant_closes_its_sampler_and_turns_off_before_it_quits(self):
        owner, fixture = self.harness("success-reconnect")
        profile = "C:\\s\\profile.txt"
        owner.by_path[profile.casefold()] = types.SimpleNamespace(record={"sha256": "c" * 64}, digest=lambda *_: b"socks5://127.0.0.1:1080#Update%20fixture\n")
        sampler, traffic = {"child": "update-traffic-before"}, []
        owner.modules["C:\\s\\lifecycle.py"] = types.SimpleNamespace(
            prepare_update_traffic=lambda *args: traffic.append(("prepare", args[-1])) or sampler,
            cleanup_update_traffic=lambda _owner, *observations: traffic.append(("cleanup", owner.cli.running, observations)))
        owner.harness["UPDATE_INPUTS"].update(initialIntent="reconnect", trafficInputs={"schemaVersion": 1}, connectionFixturePath=profile)
        with mock.patch.object(update_cases.time, "sleep"):
            result = update_cases.run_update(owner, owner.harness)
        self.assertEqual(1, result)
        self.assertIsNone(owner.parked)
        self.assertEqual([("prepare", {"schemaVersion": 1}), ("cleanup", True, (sampler,))], traffic, "the sampler closes while connected, as on success")
        commands = owner.cli.commands
        self.assertLess(commands.index(["on"]), commands.index(["off"]))
        self.assertLess(commands.index(["off"]), commands.index(["quit"]), "the runtime it connected is off before its owner quits")
        self.assertTrue(fixture.closed)
        self.assertTrue(all(child.terminal is not None for child in owner.children), "no child is left for the owner to park on")
        self.assertEqual({"variant": "success-reconnect", "operationId": "cccccccc-0000-4000-8000-000000000003"}, owner.update_cancelled_grant)

    def test_a_cancelled_copy_lock_grant_also_closes_its_blocking_copy(self):
        owner, fixture = self.harness("participating-copy-lock")
        blocking = owner.root / "blocking"
        owner.harness["UPDATE_INPUTS"]["faultInputs"] = {"kind": "participating-copy-lock", "installedCliPath": owner.request["cliPath"], "blockingWorkspace": str(blocking)}
        with mock.patch.object(update_cases.time, "sleep"):
            result = update_cases.run_update(owner, owner.harness)
        self.assertEqual(1, result)
        self.assertIsNone(owner.parked)
        copies = [child for child in owner.children if child.label == "participating-installed-copy"]
        self.assertEqual(1, len(copies))
        self.assertEqual(("--state-dir", str(blocking), "serve"), copies[0].argv[1:])
        self.assertIsNotNone(copies[0].terminal, "the blocking copy is quit and waited on, not left for the owner to park on")
        self.assertEqual(2, owner.cli.commands.count(["quit"]), "the blocking copy and the original owner")
        self.assertTrue(fixture.closed)
        self.assertTrue(all(child.terminal is not None for child in owner.children))

    def test_a_cancelled_protected_storage_install_still_parks(self):
        # Its counterfeit storage root stays on the clone, so it never ends known, however the prompt ended.
        owner, fixture = self.harness("protected-storage-rejected")
        owner.harness["UPDATE_INPUTS"]["faultInputs"] = {"kind": "protected-storage-rejected"}
        with mock.patch.object(update_cases.time, "sleep"), self.assertRaises(UpdateParked):
            update_cases.run_update(owner, owner.harness)
        self.assertEqual("update-scenario-failed-with-retained-owned-resources", owner.parked[0])
        self.assertFalse(fixture.closed)
        self.assertFalse(hasattr(owner, "update_cancelled_grant"))

    def test_a_cancelled_installer_wait_stays_on_the_parking_path(self):
        # Seen while the async install waits, CANCELLED needs a native terminal to rule out a running helper.
        owner, fixture = self.harness("installer-wait-client-loss")
        operation = "cccccccc-0000-4000-8000-000000000003"
        common = {"schemaVersion": 1, "controllerId": "controller-1", "operationId": operation, "requestId": "dddddddd-0000-4000-8000-000000000004"}
        owner.install_result = subprocess.CompletedProcess([], 0, json.dumps({**common, "ok": True, "code": "ACCEPTED", "final": False, "data": {"handoffReady": False}}), "")
        owner.cli.operation_status = (130, {**common, "ok": False, "code": "CANCELLED", "final": True, "data": {}})
        with mock.patch.object(update_cases.time, "sleep"), self.assertRaises(UpdateParked):
            update_cases.run_update(owner, owner.harness)
        self.assertEqual([29], owner.terminated, "the wait client was lost first, as the variant requires")
        self.assertEqual("update-scenario-failed-with-retained-owned-resources", owner.parked[0])
        self.assertFalse(fixture.closed)
        self.assertFalse(hasattr(owner, "update_cancelled_grant"))

    def test_anything_but_cancelled_keeps_its_old_path_and_still_parks(self):
        owner, fixture = self.harness(reply_code="RUNTIME_FAILED")
        owner.install_result = subprocess.CompletedProcess([], 1, json.loads(json.dumps(owner.install_result.stdout)), "")
        with mock.patch.object(update_cases.time, "sleep"), self.assertRaises(UpdateParked):
            update_cases.run_update(owner, owner.harness)
        self.assertEqual("update-scenario-failed-with-retained-owned-resources", owner.parked[0])
        self.assertFalse(fixture.closed)

    def test_a_deny_row_never_takes_the_grant_path(self):
        self.assertNotIn("uac-denied", update_cases.GRANT_VARIANTS)
        self.assertNotIn("install-cancelled", update_cases.GRANT_VARIANTS)
        self.assertNotIn("installer-wait-client-loss", update_cases.GRANT_VARIANTS)
        self.assertNotIn("protected-storage-rejected", update_cases.GRANT_VARIANTS)

    def test_only_valid_cancelled_json_counts(self):
        for stdout, expected in (('{"code":"CANCELLED"}', True), ('{"code":"OK"}', False), ("not json", False), ("[1]", False)):
            with self.subTest(stdout=stdout):
                self.assertIs(expected, update_cases.returned_cancelled(types.SimpleNamespace(stdout=stdout)))


def real_handoff(result, controller):
    from agent_tools.windows_public_updater import update_receipts
    return update_receipts.handoff(result, controller)


class CancelledGrantDriverTests(unittest.TestCase):
    """The driver turns the case's proof into exit 1, and only that proof."""

    def setUp(self):
        from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.owner = DedicatedDispatchPeer(Path(temporary.name))
        patcher = mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_proven_cancelled_grant_retires_its_unused_hold_and_exits_one(self):
        self.owner.update("success-off")
        self.owner.result = 1
        self.owner.update_cancelled_grant = {"variant": "success-off", "operationId": "x"}
        self.assertEqual(1, dedicated_driver.run(self.owner, "windows-public-update"))
        self.assertNotIn(("driver-completed", 1), self.owner.calls)
        self.assertNotIn("wait-release", self.owner.calls)
        self.assertIsNone(self.owner.caller_collection_hold, "Owner.finish does not park on a hold no collector was asked to use")
        self.assertEqual("armed", self.owner.retired_collection_hold.state)
        self.assertIn("dedicated-update-grant-cancelled-known", [call[0] for call in self.owner.calls if isinstance(call, tuple)])

    def test_a_result_of_one_without_the_proof_still_parks(self):
        for proof in (None, {"variant": "different-admin", "operationId": "x"}):
            with self.subTest(proof=proof):
                from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer, DedicatedParked
                owner = DedicatedDispatchPeer(self.owner.root)
                owner.update("success-off")
                owner.result = 1
                if proof is not None:
                    owner.update_cancelled_grant = proof
                with self.assertRaises(DedicatedParked):
                    dedicated_driver.run(owner, "windows-public-update")

    def test_a_cancelled_protected_storage_grant_still_parks(self):
        # Its counterfeit storage root stays on the clone: whatever the case says, the dispatcher parks it.
        self.owner.update("protected-storage-rejected", hold=False)
        self.owner.result = 1
        self.owner.update_cancelled_grant = {"variant": "protected-storage-rejected", "operationId": "x"}
        from agent_tools.tests.test_windows_ordinary_task import DedicatedParked
        with self.assertRaisesRegex(DedicatedParked, "^protected-storage-scenario-cannot-return-known-success$"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn("dedicated-update-grant-cancelled-known", [call[0] for call in self.owner.calls if isinstance(call, tuple)])

    def tun_owner(self, variant, *, finish, inner=None, begin=None, closing=None, **changes):
        state, _ = self.owner.lifecycle("find-best-success")
        self.owner.inputs["variant"] = variant
        runtime = self.owner.inputs["runtime"]
        runtime.update(workspace=str(self.owner.root / "workspace"), ordinaryContextArtifactId="peer-context")
        path = self.owner.source("windows_tun_stages.py", "agent_tools/windows_tun_stages.py")
        self.owner.inputs["modules"]["tun"] = path
        # The join the driver checks; windows_tun_stages.begin checks the rest of the closed set.
        self.owner.inputs["tun"] = {"schemaVersion": 1, "variant": variant if inner is None else inner,
                                    "installedAdmissionArtifactId": runtime["installedAdmissionArtifactId"], "ordinaryContextArtifactId": "peer-context",
                                    "runtimeConfigPath": str(PureWindowsPath(runtime["workspace"]) / "runtime-config.json"), **changes}
        self.owner.modules[path] = types.SimpleNamespace(
            begin=begin or (lambda *args: self.owner.calls.append(("tun-begin", args[2]["variant"], args[5].WindowsNative())) or "lease"),
            finish=finish, closing=closing or (lambda *args: self.owner.calls.append(("tun-closing", args[1], args[2].WindowsNative()))),
            settled=lambda lease: tun_stages.settled(lease))
        self.owner.harness({"LIFECYCLE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        return state

    def sampler(self):
        """The bundle's own direct sampler, beside the driver, at its reviewed bytes."""
        return self.owner.source("windows_tun_direct_sampler.py", "agent_tools/windows_tun_direct_sampler.py")

    def lease(self, variant):
        """A lease as windows_tun_stages.begin leaves it: the request sent, its operation open until finish."""
        self.owner.calls.append(("tun-begin", variant))
        self.owner.tun_operation_requested = True
        lease = {"inputs": {"variant": variant, "programData": "C:\\ProgramData"}, "finished": False,
                 "baseline": {"brokers": [], "runtimes": [], "stages": [], "routes": []}}
        self.owner.tun_operation_leases = [lease]
        return lease

    def census_closing(self, owner, lease, observer):
        """The real closing of windows_tun_stages over a clean declared census."""
        self.owner.calls.append(("tun-closing", lease["inputs"]["variant"]))
        with mock.patch.object(tun_stages, "census", lambda inputs, observer, exclude=(): {"brokers": [], "runtimes": [], "stages": [], "routes": []}):
            return tun_stages.closing(owner, lease, observer)

    def test_a_deny_row_closes_the_runtime_and_passes(self):
        self.tun_owner("restart-deny", finish=lambda *args: {"terminal": {"code": "CANCELLED"}})
        self.assertEqual(0, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
        calls = self.owner.calls
        begin = calls.index(("tun-begin", "restart-deny", "declared-native-peer"))
        off = next(index for index, call in enumerate(calls) if isinstance(call, tuple) and call[0] == "off-actors")
        # Nothing scoped is left behind: the census reads after the public off and before the fixture stops.
        self.assertLess(begin, off)
        self.assertLess(off, calls.index(("tun-closing", "lease", "declared-native-peer")))
        self.assertLess(calls.index(("tun-closing", "lease", "declared-native-peer")), calls.index("stop-fixture"))
        self.assertIn(("public", "quit"), calls)
        self.assertIn(("wait", "serve", 0), calls)

    def test_a_known_tun_end_that_is_not_the_variants_own_closes_by_its_census_and_exits_one(self):
        # Each end as the real finish leaves it, closed by the real closing: a denial's refused preparation, and a grant
        # whose prompt expired, which brought no TUN up and so has no off of its own. The driver admits that grant here
        # only to reach the path its collector stage will open.
        from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer
        for variant, code, outcome, known in (("restart-deny", "RUNTIME_FAILED", {"knownFailure": "RUNTIME_FAILED"}, "RUNTIME_FAILED"),
                                              ("restart-grant", "CANCELLED", {"cancelled": True}, "cancelled")):
            with self.subTest(variant=variant), mock.patch.object(dedicated_driver, "TUN_VARIANTS", frozenset({"restart-deny", "restart-grant"})):
                self.owner = DedicatedDispatchPeer(self.owner.root)

                def finish(owner, lease, *args, code=code, outcome=outcome):
                    lease.update(finished=True, knownEnd=code)
                    return {"terminal": {"code": code}, "status": {}, "nativeRecord": None, **outcome}
                self.tun_owner(variant, finish=finish, begin=lambda *args, variant=variant: self.lease(variant), closing=self.census_closing,
                               **({"samplerPath": self.sampler()} if variant.endswith("grant") else {}))
                self.assertEqual(1, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
                calls = self.owner.calls
                off = next(index for index, call in enumerate(calls) if isinstance(call, tuple) and call[0] == "off-actors")
                self.assertLess(off, calls.index(("tun-closing", variant)))
                self.assertLess(calls.index(("tun-closing", variant)), calls.index("stop-fixture"))
                self.assertTrue(self.owner.tun_operation_leases[0]["closed"])
                self.assertIn(("public", "quit"), calls)
                closed = [call[1] for call in calls if isinstance(call, tuple) and call[0] == "dedicated-proxy-lifecycle-known-closed"]
                self.assertEqual([known], [value.get("knownFailure") for value in closed])

    def test_a_grant_runs_only_the_reviewed_sampler_beside_the_driver(self):
        # The sampler is the one helper a grant executes; like every other role it is held at its reviewed digest.
        from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer, DedicatedPinPeer
        beside = str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_tun_direct_sampler.py")
        elsewhere = str(DedicatedDispatchPeer.SOURCE_ROOT / "other" / "windows_tun_direct_sampler.py")
        reviewed = Path(tun_stages.__file__).with_name("windows_tun_direct_sampler.py")
        cases = (("other-bytes", beside, b"print('another sampler')\n", "dedicated-reviewed-source-pin"),
                 ("elsewhere", elsewhere, reviewed.read_bytes(), "dedicated-tun-sampler-role"),
                 ("absent", None, None, "dedicated-tun-sampler-role"))
        with mock.patch.object(dedicated_driver, "TUN_VARIANTS", frozenset({"restart-deny", "restart-grant"})):
            for name, path, raw, reason in cases:
                with self.subTest(case=name):
                    self.owner = DedicatedDispatchPeer(self.owner.root)
                    if path is not None:
                        self.owner.by_path[path.casefold()] = DedicatedPinPeer(path, raw)
                    self.tun_owner("restart-grant", finish=lambda *args: {}, **({} if path is None else {"samplerPath": path}))
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                    self.assertNotIn("start-runtime", self.owner.calls)
        self.assertEqual(hashlib.sha256(reviewed.read_bytes()).hexdigest(), dedicated_driver.SAMPLER_SHA)

    def test_tun_inputs_naming_another_install_context_or_config_start_nothing(self):
        from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer
        for name, value in (("installedAdmissionArtifactId", "other-package"), ("ordinaryContextArtifactId", "other-context"),
                            ("runtimeConfigPath", "C:\\Other\\runtime-config.json")):
            with self.subTest(field=name):
                self.owner = DedicatedDispatchPeer(self.owner.root)
                self.tun_owner("restart-deny", finish=lambda *args: {}, **{name: value})
                with self.assertRaisesRegex(ValueError, "^dedicated-tun-same-admission-references$"):
                    dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                self.assertNotIn("start-runtime", self.owner.calls)

    def test_a_tun_grant_waits_for_its_collector_and_starts_nothing(self):
        # An approved grant ends only with its native ready record; without one it would park over VPN B and a live broker.
        self.tun_owner("restart-grant", finish=lambda *args: {"cancelled": True})
        with self.assertRaisesRegex(ValueError, "^dedicated-finite-proxy-variants-only$"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
        self.assertNotIn("start-runtime", self.owner.calls)

    def test_the_tun_inputs_must_name_the_same_variant(self):
        from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer
        for inner in ("restart-grant", "find-best-grant", "find-best-deny", 7):
            with self.subTest(inner=inner):
                self.owner = DedicatedDispatchPeer(self.owner.root)
                self.tun_owner("restart-deny", finish=lambda *args: {}, inner=inner)
                with self.assertRaisesRegex(ValueError, "^dedicated-tun-variant-binding$"):
                    dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                self.assertNotIn("start-runtime", self.owner.calls)

    def test_the_tun_source_is_the_pinned_one(self):
        self.assertEqual(hashlib.sha256(Path(tun_stages.__file__).read_bytes()).hexdigest(), dedicated_driver.TUN_SHA)

    def test_tun_needs_its_own_inputs_and_other_names_stay_refused(self):
        self.tun_owner("restart-deny", finish=lambda *args: {})
        del self.owner.inputs["tun"]
        self.owner.harness({"LIFECYCLE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        with self.assertRaisesRegex(ValueError, "finite-proxy-variants-only"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
        self.owner.inputs.update(variant="find-best-grant", tun={"schemaVersion": 1, "variant": "find-best-grant"})
        self.owner.harness({"LIFECYCLE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        with self.assertRaisesRegex(ValueError, "finite-proxy-variants-only"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")


class TunFinishTests(unittest.TestCase):
    """The real finish_operation under a fake clock, with a prompt that outlives the old 120 s wait."""

    IDENTITY = "controller-1"
    OPERATION = "ffffffff-0000-4000-8000-000000000006"

    def setUp(self):
        self.clock = [0.0]
        self.parked = []
        for patcher in (mock.patch.object(runtime_stages.time, "monotonic", lambda: self.clock[0]),
                        mock.patch.object(runtime_stages.time, "sleep", lambda seconds: self.clock.__setitem__(0, self.clock[0] + seconds))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def owner(self, *, final_at, code="OK", exit_code=0):
        test = self

        class Owner:
            tun_operation_leases = []
            request = {"context": {}}

            def guard(self):
                pass

            def event(self, kind, value):
                test.events.append(kind)

            def park(self, reason, error=None):
                test.parked.append(reason)
                raise UpdateParked(reason)

            def invoke(self, workspace, *arguments):
                common = {"schemaVersion": 1, "controllerId": test.IDENTITY, "requestId": test.OPERATION, "ok": True}
                if arguments[-2:] == ("operations", "list"):
                    return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({**common, "final": True, "code": "OK", "data": {"operations": [
                        {"id": test.OPERATION, "controllerId": test.IDENTITY, "requestId": test.OPERATION}]}}))
                if arguments[-1] == "status" and arguments[-2] != "operations":
                    return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({**common, "final": True, "code": "OK", "restartRequired": True, "data": test.status}))
                if test.clock[0] < final_at:
                    return types.SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({**common, "operationId": test.OPERATION, "final": False, "code": "ACCEPTED"}))
                return types.SimpleNamespace(returncode=exit_code, stderr="", stdout=json.dumps({**common, "ok": exit_code == 0, "operationId": test.OPERATION, "final": True, "code": code}))
        self.events = []
        self.status = {"runtimeRunning": True, "activeLocationId": "a", "activeMode": "proxy-only", "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "vpn",
                       "selectedLocationId": "b"}
        owner = Owner()
        return owner

    def lease(self, owner, variant):
        lease = {"state": {"workspace": "w", "identity": self.IDENTITY, "actors": {"owner": "o", "runtime": "r"}},
                 "inputs": {"variant": variant, "runtimeConfigPath": "c"}, "accepted": {"operationId": self.OPERATION, "controllerId": self.IDENTITY, "code": "ACCEPTED", "final": False, "requestId": self.OPERATION},
                 "before": {"data": dict(self.status)}, "pending": {"data": dict(self.status)},
                 "activeConfig": types.SimpleNamespace(initial={"sizeBytes": 1, "sha256": "s"}), "finished": False}
        owner.tun_operation_leases = [lease]
        return lease

    def finish(self, owner, lease, **options):
        cases = types.SimpleNamespace(config_bytes=lambda path: {"sizeBytes": 1, "sha256": "s"}, exact_actor=lambda *args, **kw: None)
        observer = types.SimpleNamespace(WindowsNative=lambda: "native")
        return tun_stages.finish(owner, lease, runtime_stages, cases, observer, **options)

    def test_the_wait_outlasts_a_prompt_that_the_default_would_park_on(self):
        owner = self.owner(final_at=200.0, code="CANCELLED", exit_code=130)
        result = self.finish(owner, self.lease(owner, "restart-deny"))
        self.assertEqual("CANCELLED", result["terminal"]["code"])
        self.assertEqual([], self.parked)

    def test_a_cancelled_grant_is_known_and_keeps_the_same_active_runtime(self):
        owner = self.owner(final_at=10.0, code="CANCELLED", exit_code=130)
        result = self.finish(owner, self.lease(owner, "restart-grant"))
        self.assertTrue(result["cancelled"])
        self.assertIn("scoped-tun-grant-cancelled-known", self.events)
        self.assertNotIn("scoped-tun-public-outcome", self.events)

    def test_a_cancelled_grant_that_lost_its_runtime_is_not_known(self):
        owner = self.owner(final_at=1.0, code="CANCELLED", exit_code=130)
        lease = self.lease(owner, "restart-grant")
        self.status = {**self.status, "runtimeId": "other"}
        with self.assertRaisesRegex(AssertionError, "uac-denial-lost-active-a-or-pending-b"):
            self.finish(owner, lease)

    def test_a_granted_ok_still_requires_its_native_record(self):
        owner = self.owner(final_at=1.0)
        with self.assertRaisesRegex(AssertionError, "actual-tun-native-file-required"):
            self.finish(owner, self.lease(owner, "restart-grant"))

    def test_a_refused_preparation_on_a_denial_is_a_known_end_not_a_parked_owner(self):
        # No prompt ever came: the product's own final RUNTIME_FAILED, active A intact and nothing scoped started.
        owner = self.owner(final_at=1.0, code="RUNTIME_FAILED", exit_code=1)
        lease = self.lease(owner, "restart-deny")
        lease["inputs"]["programData"] = "C:\\ProgramData"
        lease["state"]["actors"] = {"owner": {"pid": 1}, "runtime": {"pid": 2}}
        lease["baseline"] = {"brokers": [], "runtimes": [], "stages": [], "routes": []}
        cases = types.SimpleNamespace(config_bytes=lambda path: {"sizeBytes": 1, "sha256": "s"}, exact_actor=lambda *args, **kw: None)
        observer = types.SimpleNamespace(WindowsNative=lambda: types.SimpleNamespace(processes=lambda: [{"pid": 2, "parentPid": 1, "name": "sing-box.exe"}]))
        with mock.patch.object(tun_stages, "os", types.SimpleNamespace(name="nt", environ={}, listdir=lambda path: ["Microsoft"])), \
                mock.patch.object(tun_stages, "tun_routes", lambda: [], create=True):
            result = tun_stages.finish(owner, lease, runtime_stages, cases, observer)
        self.assertEqual("RUNTIME_FAILED", result["knownFailure"])
        self.assertEqual([], self.parked)
        self.assertIn("scoped-tun-unexpected-terminal-known", self.events)

    def test_a_prompt_past_every_bound_still_parks(self):
        owner = self.owner(final_at=10000.0)
        with self.assertRaises(UpdateParked):
            self.finish(owner, self.lease(owner, "restart-grant"))
        self.assertEqual(["original-find-best-pending-no-replay"], self.parked)
        self.assertGreaterEqual(self.clock[0], 300.0)


if __name__ == "__main__":
    unittest.main()
