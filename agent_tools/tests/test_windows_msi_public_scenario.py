"""Strict read-only Windows MSI protected diagnostic observation."""
from __future__ import annotations

import json
import base64
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import windows_msi_public_scenario as scenario


JOB = "9107428f-9c80-4284-9f4e-926350105a59"


def response(*, job: str = JOB, diagnostic: object = None) -> bytes:
    return json.dumps({"state": "observed", "status": {"version": 1, "jobId": job,
                       "sequence": 3, "phase": "Failed", "code": "RUNTIME_FAILED"},
                       "diagnostic": diagnostic}).encode()


class WindowsMsiPreinstallStatusTest(unittest.TestCase):
    def test_qga_short_read_without_eof_needs_second_read(self) -> None:
        """Native QGA returned 114 bytes with eof=false for the CP176 status."""
        status = response()
        protected_status = json.dumps(json.loads(status)["status"], separators=(",", ":")).encode()
        replies = iter([
            {"return": 1},
            {"return": {"count": len(protected_status), "buf-b64": base64.b64encode(protected_status).decode(), "eof": False}},
            {"return": {"count": 0, "buf-b64": "", "eof": True}},
            {"return": {}},
            {"error": {"class": "GenericError"}},
        ])

        class FakeSocket:
            def __init__(self, *args, **kwargs): self.data = bytearray()
            def settimeout(self, value): pass
            def connect(self, value): pass
            def close(self): pass
            def sendall(self, raw):
                if raw.startswith(b"\xff"):
                    sync = json.loads(raw[1:])
                    self.data.extend(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                else:
                    command = json.loads(raw)
                    self.data.extend(json.dumps(next(replies)).encode() + b"\n")
            def recv(self, size):
                take = min(size, len(self.data))
                result = bytes(self.data[:take]); del self.data[:take]
                return result

        output = io.StringIO()
        code = scenario._REMOTE_OBSERVE.replace("if not live():", "if False:")
        with (patch("socket.socket", FakeSocket),
              patch.object(sys, "argv", ["observer", "/private/qga.sock", "589342", "520739", JOB]),
              contextlib.redirect_stdout(output)):
            exec(code, {"__name__": "__main__"})
        result = scenario._parse(output.getvalue().encode(), JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("Failed", result["phase"])

    def test_exact_job_binds_fixed_diagnostic(self) -> None:
        raw = response(diagnostic={"version": 1, "stage": "EXCLUSIVE_ADMISSION", "kind": "OTHER"})
        self.assertEqual({"stage": "EXCLUSIVE_ADMISSION", "kind": "OTHER"}, scenario._parse(raw, JOB)["diagnostic"])

    def test_mismatched_job_and_unbounded_content_fail_closed(self) -> None:
        other = "11111111-1111-4111-8111-111111111111"
        self.assertEqual("unknown", scenario._parse(response(job=other), JOB)["state"])
        self.assertEqual("unknown", scenario._parse(b"x" * 8193, JOB)["state"])
        self.assertEqual("unknown", scenario._parse(response(diagnostic={"version": 1, "stage": "RAW_PATH", "kind": "OTHER"}), JOB)["state"])
        unsafe = json.loads(response())
        unsafe["status"]["code"] = "C:\\private\\credential"
        self.assertEqual("unknown", scenario._parse(json.dumps(unsafe).encode(), JOB)["state"])

    def test_missing_diagnostic_does_not_infer_admission_cause(self) -> None:
        result = scenario._parse(response(), JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("absent-or-unreadable", result["diagnostic"])
        self.assertNotIn("stage", result)

    def test_rejects_noncanonical_job_before_transport(self) -> None:
        with patch.object(scenario.ssh_transport, "load_config") as load:
            with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                scenario.preinstall_status(Path("."), "archlinux", JOB.upper())
            load.assert_not_called()

    def test_route_uses_only_configured_guest_and_fixed_program(self) -> None:
        target = types.SimpleNamespace()
        config = types.SimpleNamespace(hosts={"archlinux": target})
        done = subprocess.CompletedProcess([], 0, response(diagnostic={"version": 1, "stage": "INVENTORY", "kind": "WIN32_API"}), b"")
        with (patch.object(scenario.ssh_transport, "load_config", return_value=config),
              patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=("windows-cp117", "/private/qga.sock", 589342, 520739, "account", "sid", Path("private"))),
              patch.object(scenario.ssh_transport, "build_ssh_argv", return_value=["ssh", "fixed-host"]) as argv,
              patch.object(scenario.subprocess, "run", return_value=done)):
            result = scenario.preinstall_status(Path("."), "archlinux", JOB)
        self.assertEqual("observed", result["state"])
        self.assertEqual("INVENTORY", result["diagnostic"]["stage"])
        command = argv.call_args.kwargs["command"]
        self.assertEqual(("/private/qga.sock", "589342", "520739", JOB), command[-4:])
        self.assertNotIn("guest-exec", scenario._REMOTE_OBSERVE)

    def test_rejects_other_windows_environment(self) -> None:
        target = types.SimpleNamespace()
        config = types.SimpleNamespace(hosts={"archlinux": target})
        with (patch.object(scenario.ssh_transport, "load_config", return_value=config),
              patch.object(scenario.windows_credential_probe_ssh, "_descriptor", return_value=("other-guest", "/private/qga.sock", 589342, 520739, "account", "sid", Path("private"))),
              patch.object(scenario.subprocess, "run") as run):
            with self.assertRaises(scenario.WindowsMsiPreinstallStatusError):
                scenario.preinstall_status(Path("."), "archlinux", JOB)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
