#!/usr/bin/env python3
"""Causal guard regressions for Windows UAC prompt observations."""

import math
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


if __name__ == "__main__":
    unittest.main()
