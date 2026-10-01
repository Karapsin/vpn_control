"""Regression coverage for the bounded QGA PowerShell bootstrap encoder."""
from __future__ import annotations

import base64
import gzip
import hashlib
import re
import unittest

from agent_tools.windows_ps_bootstrap import (
    MAX_ENCODED_COMMAND_CHARS,
    MAX_SOURCE_BYTES,
    REMOTE_ENCODER_SOURCE,
    WindowsPowerShellBootstrapError,
    encode_verified_bootstrap,
)


def _wrapper(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-16le")


class WindowsPowerShellBootstrapTest(unittest.TestCase):
    @staticmethod
    def _remote_encoder():
        namespace = {"__builtins__": __builtins__}
        exec(REMOTE_ENCODER_SOURCE, namespace)
        return namespace["compact_ps_bootstrap"]

    def test_round_trip_embeds_deterministic_gzip_and_exact_utf8_hash(self):
        source = "$ErrorActionPreference='Stop';[Console]::Out.WriteLine('fixed')"
        first = encode_verified_bootstrap(source)
        second = encode_verified_bootstrap(source)
        self.assertEqual(first, second)
        wrapper = _wrapper(first)
        packed = re.search(r"\$packed='([^']+)'", wrapper).group(1)
        payload = gzip.decompress(base64.b64decode(packed))
        self.assertEqual(payload, source.encode("utf-8"))
        self.assertIn(hashlib.sha256(payload).hexdigest(), wrapper)
        self.assertLessEqual(len(first), MAX_ENCODED_COMMAND_CHARS)

    def test_hash_refusal_precedes_the_only_scriptblock_invocation(self):
        wrapper = _wrapper(encode_verified_bootstrap("Write-Output 'reviewed'"))
        self.assertIn("if($actual -cne $expected){throw 'BOOTSTRAP_SHA256_MISMATCH'}", wrapper)
        self.assertIn("& ([ScriptBlock]::Create($script))", wrapper)
        self.assertLess(wrapper.index("BOOTSTRAP_SHA256_MISMATCH"), wrapper.index("[ScriptBlock]::Create"))
        self.assertNotIn("-Command", wrapper)
        self.assertNotIn("Set-Content", wrapper)
        self.assertNotIn("New-Item", wrapper)

    def test_representative_25k_script_stays_inside_qga_admission(self):
        source = ("[Console]::Out.WriteLine('fixed reviewed bootstrap')\n" * 500)
        self.assertGreater(len(source), 25_000)
        self.assertLessEqual(len(encode_verified_bootstrap(source)), MAX_ENCODED_COMMAND_CHARS)

    def test_rejects_unexpected_source_and_incompressible_command_overflow(self):
        for value in (None, b"Write-Output nope", "", "ok\x00no"):
            with self.assertRaises(WindowsPowerShellBootstrapError):
                encode_verified_bootstrap(value)
        # This textual source is intentionally varied enough that its encoded
        # wrapper exceeds the fixed command envelope.
        varied = "".join(f"[Console]::Out.WriteLine('{index:05d}-{index * 7919:08x}')\n"
                         for index in range(6_000))
        with self.assertRaises(WindowsPowerShellBootstrapError):
            encode_verified_bootstrap(varied)

    def test_rejects_highly_compressible_oversize_before_guest_expansion(self):
        """REGRESSION: command length alone admitted a >10MiB gzip payload."""
        source = "Write-Output 'fixed reviewed bootstrap'\n" * 300_000
        self.assertGreater(len(source.encode("utf-8")), 10 * 1024 * 1024)
        with self.assertRaisesRegex(WindowsPowerShellBootstrapError, "decompression admission"):
            encode_verified_bootstrap(source)

        wrapper = _wrapper(encode_verified_bootstrap("Write-Output 'bounded'"))
        self.assertIn(f"$max={MAX_SOURCE_BYTES}", wrapper)
        self.assertIn("if($total -gt $max){throw 'BOOTSTRAP_SIZE'}", wrapper)
        self.assertLess(wrapper.index("BOOTSTRAP_SIZE"), wrapper.index("$output.Write"))

    def test_remote_encoder_source_is_self_contained_and_exactly_matches_host(self):
        remote = self._remote_encoder()
        source = "$ErrorActionPreference='Stop';[Console]::Out.WriteLine('v3 fixed')\n"
        self.assertEqual(remote(source), encode_verified_bootstrap(source))
        self.assertLessEqual(len(remote(source)), MAX_ENCODED_COMMAND_CHARS)

    def test_remote_encoder_rejects_bad_and_highly_compressible_oversize_source(self):
        remote = self._remote_encoder()
        for value in (None, "", "x\x00y"):
            with self.assertRaises(ValueError):
                remote(value)
        source = "Write-Output 'fixed'\n" * 600_000
        self.assertGreater(len(source.encode("utf-8")), MAX_SOURCE_BYTES)
        with self.assertRaisesRegex(ValueError, "decompression admission"):
            remote(source)


if __name__ == "__main__":
    unittest.main()
