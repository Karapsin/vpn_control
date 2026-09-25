#!/usr/bin/env python3
"""Causal guard regressions for Windows UAC prompt observations."""

import math
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "integration"))
import windows_prompt_observation as subject


HASH = "a" * 64
QEMU = "windows-qemu-cp100"
OPERATION = "install-cp100-9d2e"


def observation(**changes):
    value = {"observedAt": 20_837.0, "screenshotSha256": HASH,
             "qemuIdentity": QEMU, "operationId": OPERATION, "operationTerminal": False}
    value.update(changes)
    return value


def cp95_login_unguarded_input_reconstruction(action):
    """CP95 login.py reconstruction: its final QMP input stage had no prompt guard."""
    action()


class WindowsPromptObservationTest(unittest.TestCase):
    def admit(self, metadata, *, now=20_840.0, maximum=15.0, action=None, **expected):
        invoked = [] if action is None else action
        result = subject.run_if_current(
            metadata, expected_qemu_identity=expected.get("qemu", QEMU),
            expected_operation_id=expected.get("operation", OPERATION),
            current_screenshot_sha256=expected.get("hash", HASH), now=now,
            max_age_seconds=maximum, action=lambda: invoked.append("called"))
        return result, invoked

    def assert_rejected(self, metadata, reason, **kwargs):
        invoked = []
        with self.assertRaisesRegex(ValueError, reason):
            self.admit(metadata, action=invoked, **kwargs)
        self.assertEqual([], invoked)

    def test_matching_fresh_observation_calls_action_once_after_all_checks(self):
        result, invoked = self.admit(observation())
        self.assertEqual({"ageSeconds": 3.0, "screenshotSha256": HASH}, result)
        self.assertEqual(["called"], invoked)

    def test_causal_cp95_stale_input_reconstruction_is_blocked_before_callback(self):
        # UAC 05:37:17 -> not-started 05:39:18 -> input 05:40:37: 200 seconds old.
        invoked = []
        input_callback = lambda: invoked.append("input")
        cp95_login_unguarded_input_reconstruction(input_callback)
        self.assertEqual(["input"], invoked)
        with self.assertRaisesRegex(ValueError, "stale"):
            subject.run_if_current(
                observation(), expected_qemu_identity=QEMU, expected_operation_id=OPERATION,
                current_screenshot_sha256=HASH, now=21_037.0, action=input_callback)
        self.assertEqual(["input"], invoked)

    def test_rejects_negative_and_nonfinite_observation_timestamps(self):
        for timestamp in (-1.0, math.inf, -math.inf, math.nan):
            with self.subTest(timestamp=timestamp):
                self.assert_rejected(observation(observedAt=timestamp), "timestamp")

    def test_rejects_changed_current_screenshot_hash(self):
        self.assert_rejected(observation(), "screenshot", hash="b" * 64)

    def test_rejects_wrong_qemu_identity(self):
        self.assert_rejected(observation(qemuIdentity="other-qemu"), "QEMU")

    def test_rejects_wrong_operation_identity(self):
        self.assert_rejected(observation(operationId="other-operation"), "operation")

    def test_rejects_terminal_operation_before_callback(self):
        self.assert_rejected(observation(operationTerminal=True), "terminal")

    def test_maximum_age_is_positive_and_cannot_exceed_safety_bound(self):
        for maximum in (0, -1, math.inf, 15.1):
            with self.subTest(maximum=maximum):
                self.assert_rejected(observation(), "max_age", maximum=maximum)

    def test_metadata_has_only_the_nonsecret_observation_fields(self):
        self.assert_rejected(observation(password="never accepted"), "metadata")


class WindowsLoginObservationTest(unittest.TestCase):
    """Real CP117 screen crops reconstruct the account switch that misdirected input."""

    FIXTURES = Path(__file__).resolve().parent / "testdata" / "windows-login"
    WIDTH = 1280
    HEIGHT = 800
    ACCOUNT = (540, 380, 742, 415)
    FIELD = (540, 446, 725, 474)
    CAPS = (580, 486, 700, 507)

    @classmethod
    def crop(cls, name):
        raw = (cls.FIXTURES / name).read_bytes()
        _, dimensions, maximum, payload = raw.split(b"\n", 3)
        width, height = map(int, dimensions.split())
        assert maximum == b"255" and len(payload) == width * height * 3
        return payload

    @classmethod
    def frame(cls, account="vpn-account.ppm", *, nonempty=False):
        pixels = bytearray(b"\x14\x20\x40" * (cls.WIDTH * cls.HEIGHT))
        for name, rect in ((account, cls.ACCOUNT),
                           ("vpn-empty-field.ppm", cls.FIELD),
                           ("vpn-caps-off.ppm", cls.CAPS)):
            crop = cls.crop(name)
            x0, y0, x1, y1 = rect
            stride = (x1 - x0) * 3
            for row, y in enumerate(range(y0, y1)):
                start = (y * cls.WIDTH + x0) * 3
                pixels[start:start + stride] = crop[row * stride:(row + 1) * stride]
        if nonempty:
            # A white masked-input mark in the previously empty portion of the real field.
            for y in range(454, 465):
                for x in range(565, 577):
                    start = (y * cls.WIDTH + x) * 3
                    pixels[start:start + 3] = b"\xff\xff\xff"
        return f"P6\n{cls.WIDTH} {cls.HEIGHT}\n255\n".encode() + pixels

    @classmethod
    def profile(cls):
        return {
            "width": cls.WIDTH, "height": cls.HEIGHT,
            "accountRect": cls.ACCOUNT, "fieldRect": cls.FIELD, "capsRect": cls.CAPS,
            "maxEmptyFieldBrightPixels": 100,
            "accountCropSha256ByName": {
                "vpncp117": hashlib.sha256(cls.crop("vpn-account.ppm")).hexdigest(),
            },
        }

    def drive(self, frames, *, age=1.0, account="vpncp117", qemu=QEMU):
        events = []
        captures = iter(frames)

        def capture():
            events.append("capture")
            return next(captures)

        def read_credential():
            events.append("read")
            return b"test-only-private-input"

        def type_credential(value):
            self.assertEqual(b"test-only-private-input", value)
            events.append("type")

        def submit():
            events.append("submit")

        kwargs = dict(
            expected_qemu_identity=QEMU, expected_account_name="vpncp117",
            profile=self.profile(), capture_frame=capture, now=20_837.0 + age,
            read_credential=read_credential, type_credential=type_credential,
            submit=submit,
        )
        metadata = {"observedAt": 20_837.0, "qemuIdentity": qemu,
                    "accountName": account}
        return metadata, kwargs, events

    def test_cp163_extra_tile_click_is_rejected_before_private_read(self):
        # The retained native sequence showed vpncp117, then the extra click
        # left Parity test user selected. Both crops came from those actual screens.
        metadata, kwargs, events = self.drive([self.frame("parity-account.ppm")])
        with self.assertRaisesRegex(ValueError, "selected account"):
            subject.run_login_if_current(metadata, **kwargs)
        self.assertEqual(["capture"], events)

    def test_lock_screen_and_nonempty_field_reject_before_private_read(self):
        for frame in (self.frame("lock-account.ppm"), self.frame(nonempty=True)):
            with self.subTest(frame=hashlib.sha256(frame).hexdigest()[:8]):
                metadata, kwargs, events = self.drive([frame])
                with self.assertRaises(ValueError):
                    subject.run_login_if_current(metadata, **kwargs)
                self.assertEqual(["capture"], events)

    def test_exact_current_account_reads_then_rechecks_before_submit(self):
        metadata, kwargs, events = self.drive([self.frame(), self.frame()])
        result = subject.run_login_if_current(metadata, **kwargs)
        self.assertEqual(["capture", "read", "type", "capture", "submit"], events)
        self.assertEqual("vpncp117", result["accountName"])

    def test_account_drift_after_typing_blocks_submission(self):
        metadata, kwargs, events = self.drive([
            self.frame(), self.frame("parity-account.ppm")])
        with self.assertRaisesRegex(ValueError, "selected account"):
            subject.run_login_if_current(metadata, **kwargs)
        self.assertEqual(["capture", "read", "type", "capture"], events)

    def test_stale_or_wrong_identity_rejects_without_reading(self):
        for changes in ({"age": 6.0}, {"qemu": "other"}, {"account": "Parity test user"}):
            metadata, kwargs, events = self.drive([self.frame()], **changes)
            with self.assertRaises(ValueError):
                subject.run_login_if_current(metadata, **kwargs)
            self.assertNotIn("read", events)


if __name__ == "__main__":
    unittest.main()
