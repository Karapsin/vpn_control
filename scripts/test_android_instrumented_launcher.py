import unittest
from types import SimpleNamespace
from unittest import mock

from run_android_instrumented_tests import run_tests


class AndroidInstrumentedLauncherTest(unittest.TestCase):
    def test_selects_only_requested_device_without_broken_agp_serial_option(self):
        original = {"ANDROID_SERIAL": "protected-device", "JAVA_HOME": "fixture-jdk"}

        def gradle(command, *, cwd, env, check):
            # AGP 8.7.3 --serial removes entries from an immutable device list.
            # Its earlier ANDROID_SERIAL filter avoids that path and selects one device.
            self.assertNotIn("--serial", command)
            self.assertEqual("emulator-5592", env["ANDROID_SERIAL"])
            self.assertEqual("fixture-jdk", env["JAVA_HOME"])
            self.assertIn("-Pandroid.testInstrumentationRunnerArguments.class=example.Smoke#socks", command)
            self.assertFalse(check)
            return SimpleNamespace(returncode=0)

        self.assertEqual(0, run_tests("emulator-5592", "example.Smoke#socks", environment=original, runner=gradle))
        self.assertEqual("protected-device", original["ANDROID_SERIAL"])

    def test_rejects_empty_multiple_and_option_serials_before_launch(self):
        runner = mock.Mock()
        for serial in ("", "emulator-5592,protected-device", "emulator-5592 protected-device", "--all", None):
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                run_tests(serial, environment={}, runner=runner)
        runner.assert_not_called()

    def test_preserves_failure_and_cancellation_without_retry(self):
        for code in (1, 130):
            runner = mock.Mock(return_value=SimpleNamespace(returncode=code))
            self.assertEqual(code, run_tests("emulator-5592", environment={}, runner=runner))
            runner.assert_called_once()


if __name__ == "__main__":
    unittest.main()
