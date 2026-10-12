import base64
import gzip
import hashlib
import random
import re
import unittest

from windows_qga_powershell_size import (
    MAX_ENCODED_COMMAND_CHARS, MAX_SCRIPT_BYTES, compressed_powershell_command,
    encoded_command_size, plan_chunks,
)


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


class WindowsQgaCompressedPowerShellTest(unittest.TestCase):
    def test_deterministic_carrier_binds_exact_unicode_source_bytes(self):
        body = "[Console]::Out.WriteLine('π✓')\n"
        command = compressed_powershell_command(body)
        self.assertEqual(command, compressed_powershell_command(body))
        packed = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", command)
        self.assertIsNotNone(packed)
        raw = gzip.decompress(base64.b64decode(packed.group(1), validate=True))
        self.assertEqual(raw, body.encode("utf-8"))
        self.assertIn("$expected=" + str(len(raw)), command)
        self.assertIn(hashlib.sha256(raw).hexdigest(), command)

    def test_compressible_source_has_bounded_task_argument(self):
        body = "# inert padding\n" * 6000 + "[Console]::Out.WriteLine('inert')\n"
        self.assertGreater(encoded_command_size(body), MAX_ENCODED_COMMAND_CHARS)
        command = compressed_powershell_command(body)
        self.assertLessEqual(len("-NoProfile -NonInteractive -EncodedCommand ") +
                             encoded_command_size(command), MAX_ENCODED_COMMAND_CHARS)

    def test_source_and_incompressible_carrier_bounds_are_enforced(self):
        for body in ("", "x" * (MAX_SCRIPT_BYTES + 1)):
            with self.subTest(size=len(body)), self.assertRaises(ValueError):
                compressed_powershell_command(body)
        rng = random.Random(0)
        body = "#" + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24000))
        with self.assertRaisesRegex(ValueError, "task command exceeds bound"):
            compressed_powershell_command(body)


if __name__ == "__main__":
    unittest.main()
