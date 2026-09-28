import base64
import unittest

from windows_qga_powershell_size import MAX_ENCODED_COMMAND_CHARS, encoded_command_size, plan_chunks


class WindowsQgaPowerShellSizeTest(unittest.TestCase):
    def test_large_inert_role_bundle_is_chunked_below_windows_command_limit(self):
        payload = base64.b64encode(bytes(range(256)) * 94).decode("ascii")
        commands = plan_chunks(payload, "0123456789abcdef")
        self.assertGreater(len(commands), 1)
        self.assertEqual(payload, "".join(chunk for _, chunk in commands))
        for script, chunk in commands:
            self.assertIn(chunk, script)
            self.assertLessEqual(encoded_command_size(script), MAX_ENCODED_COMMAND_CHARS)

    def test_rejects_unbounded_or_non_base64_input(self):
        with self.assertRaises(ValueError):
            plan_chunks("hello'; Remove-Item C:\\\\", "0123456789abcdef")
        with self.assertRaises(ValueError):
            plan_chunks("YWJj", "../outside")


if __name__ == "__main__":
    unittest.main()
