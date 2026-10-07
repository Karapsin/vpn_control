"""Causal regression for receipt observation after a lost QGA open response."""
from __future__ import annotations

import base64
import unittest

from agent_tools import windows_guest_receipt_read as receipts
from agent_tools import windows_msi_base_prepare as base


CORR = "11111111-1111-4111-8111-111111111111"


class WindowsGuestReceiptReadTest(unittest.TestCase):
    def test_lost_guest_file_open_leaks_legacy_handle_but_process_read_has_no_handle(self):
        handles = set()

        def lost_open(_sock, method, _params):
            self.assertEqual("guest-file-open", method)
            handles.add(91)  # QGA opened it before its reply was lost.
            raise TimeoutError("lost guest-file-open response")

        legacy = {"lost_open": lost_open}
        exec(base._QGA + "\ncall=lost_open", legacy)
        with self.assertRaises(TimeoutError):
            legacy["read"]("/qga", "C:\\fixed\\result.json")
        self.assertEqual({91}, handles)

        calls = []
        receipt = b'{"correlationId":"' + CORR.encode() + b'","code":"UNKNOWN"}'

        def qga(_sock, method, params):
            calls.append((method, params))
            if method == "guest-exec":
                return {"pid": 7}
            self.assertEqual(("guest-exec-status", {"pid": 7}), (method, params))
            return {"exited": True, "exitcode": 0, "out-data": base64.b64encode(receipt).decode()}

        process = {"qga": qga, "base64": base64}
        exec(receipts.REMOTE_HELPER + "\ncall=qga", process)
        self.assertEqual(receipt, process["read_fixed_receipt"]("/qga", CORR))
        self.assertEqual(["guest-exec", "guest-exec-status"], [method for method, _ in calls])
        script = base64.b64decode(calls[0][1]["arg"][-1]).decode("utf-16le")
        self.assertIn("mcp-update-fixture-" + CORR + "\\result.json", script)
        self.assertIn("[IO.FileShare]::None", script)
        self.assertIn("$stream.Length", script)
        self.assertIn("$parent=$item.Directory", script)
        self.assertNotIn("guest-file-open", receipts.REMOTE_HELPER)

    def test_optional_truncation_flags_default_false_but_supplied_values_stay_strict(self):
        receipt = b'{"correlationId":"' + CORR.encode() + b'"}'

        def run(status):
            def qga(_sock, method, _params):
                if method == "guest-exec":
                    return {"pid": 7}
                return {"exited": True, "out-data": base64.b64encode(receipt).decode(), **status}
            namespace = {"qga": qga, "base64": base64}
            exec(receipts.REMOTE_HELPER + "\ncall=qga", namespace)
            return namespace["read_fixed_receipt"]("/qga", CORR)

        self.assertEqual(receipt, run({"exitcode": 0}))
        for status in (
            {"exitcode": 0, "out-truncated": True},
            {"exitcode": 0, "err-truncated": 0},
            {"exitcode": False},
        ):
            with self.subTest(status=status), self.assertRaises(ValueError):
                run(status)

    def test_only_a_canonical_correlation_can_form_the_fixed_receipt_path(self):
        calls = []
        namespace = {"qga": lambda *args: calls.append(args), "base64": base64}
        exec(receipts.REMOTE_HELPER + "\ncall=qga", namespace)
        with self.assertRaises(ValueError):
            namespace["read_fixed_receipt"]("/qga", "..\\arbitrary")
        self.assertEqual([], calls)
