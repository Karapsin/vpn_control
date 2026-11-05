"""Actual Windows S3 refusal text and fail-closed capability controls."""
import unittest

from agent_tools.windows_sleep_capability import observe_s3


AVAILABLE = "The following sleep states are available on this system:"
UNAVAILABLE = "The following sleep states are not available on this system:"
NATIVE = [AVAILABLE, "    Hibernate", "    Fast Startup", "", UNAVAILABLE,
          "    Standby (S1)", "\tThe system firmware does not support this standby state.",
          "\tAn internal system component has disabled this standby state.", "\t\tGraphics", "",
          "    Standby (S2)", "\tThe system firmware does not support this standby state.",
          "\tAn internal system component has disabled this standby state.", "\t\tGraphics", "",
          "    Standby (S3)", "\tAn internal system component has disabled this standby state.",
          "\t\tGraphics", "", "    Standby (S0 Low Power Idle)",
          "\tThe system firmware does not support this standby state.", "",
          "    Hybrid Sleep", "\tStandby (S3) is not available.", ""]


class WindowsSleepCapabilityTests(unittest.TestCase):
    def test_actual_native_graphics_refusal_never_allows_power(self):
        self.assertEqual({"schemaVersion": 1, "state": "unsupported", "reason": "windows_s3_unsupported",
                          "nativeReasons": ["An internal system component has disabled this standby state.",
                                            "Graphics"], "powerAllowed": False}, observe_s3(NATIVE))

    def test_reported_support_is_capability_only(self):
        result = observe_s3([AVAILABLE, "    Standby (S3)", "", UNAVAILABLE, "    Standby (S1)"])
        self.assertEqual("supported", result["state"])
        self.assertIsNone(result["reason"])
        self.assertFalse(result["powerAllowed"])

    def test_hybrid_reason_does_not_replace_an_actual_s3_row(self):
        with self.assertRaisesRegex(ValueError, "windows_sleep_capability_unrecognized"):
            observe_s3([AVAILABLE, "    Hibernate", "", UNAVAILABLE, "    Hybrid Sleep",
                        "\tStandby (S3) is not available."])

    def test_missing_ambiguous_translated_or_unexplained_observation_refuses(self):
        for lines in ([AVAILABLE, "    Standby (S3)"],
                      [AVAILABLE, "    Standby (S3)", UNAVAILABLE, "    Standby (S3)", "\tGraphics"],
                      [AVAILABLE, UNAVAILABLE, "    Standby (S3)"],
                      [AVAILABLE, AVAILABLE, UNAVAILABLE, "    Standby (S3)", "\tGraphics"],
                      ["Unknown localized heading", "    Standby (S3)"],
                      ["    Standby (S3)", AVAILABLE, UNAVAILABLE]):
            with self.subTest(lines=lines):
                with self.assertRaises(ValueError):
                    observe_s3(lines)

    def test_malformed_or_overflow_rows_refuse(self):
        for lines in (None, (), [], [True], ["x" * 1025], ["x"] * 101,
                      ["line\nsecond"], ["\0"], ["x" * 1024] * 17):
            with self.subTest(lines=lines):
                with self.assertRaises(ValueError):
                    observe_s3(lines)


if __name__ == "__main__":
    unittest.main()
