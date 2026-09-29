"""TEST-001 contracts for the known Windows swtpm package-integrity failure."""
from __future__ import annotations

import contextlib
import base64
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import mcp_server
from agent_tools import windows_vm_swtpm_repair as repair

CORR = "123e4567-e89b-12d3-a456-426614174000"
SECRET = b"test-secret\n"
REQUEST = {"host": "archlinux", "correlationId": CORR, "timeoutSeconds": 60}


class WindowsVmSwtpmRepairTest(unittest.TestCase):
    def _credential(self, root: str, mode: int = 0o600) -> Path:
        directory = Path(root) / ".codex"
        directory.mkdir(mode=0o700)
        path = directory / "arch-sudo.local"
        path.write_bytes(SECRET); os.chmod(path, mode)
        return path

    def _program(self, mode: str) -> str:
        value = repair._REMOTE.replace("__MODE__", repr(mode)).replace("__CORR__", repr(CORR))
        compile(value, "<swtpm-repair>", "exec")
        return value

    def test_known_qkk_integrity_failure_is_categorical_and_needs_a_reinstall(self) -> None:
        program = self._program("status")
        def command(argv, **_kwargs):
            if argv[:3] == ["/usr/bin/pacman", "-Q", "swtpm"]:
                return SimpleNamespace(returncode=0, stdout=b"swtpm 0.10.2-1\n")
            if argv == ["/usr/bin/pgrep", "-x", "swtpm"]:
                return SimpleNamespace(returncode=1, stdout=b"")
            if argv == ["/usr/bin/pacman", "-Qkk", "swtpm"]:
                return SimpleNamespace(returncode=1, stdout=b"")
            return SimpleNamespace(returncode=0, stdout=b"")
        output = io.StringIO()
        with mock.patch("subprocess.run", side_effect=command), contextlib.redirect_stdout(output):
            exec(program, {"__name__": "__main__"})
        response = json.loads(output.getvalue())
        self.assertEqual(response["state"], "integrity-failed")
        self.assertFalse(response["packageIntegrityVerified"])
        self.assertFalse(response["activeSwtpmProcesses"])

    def test_same_version_failure_runs_signed_reinstall_without_needed_then_qkk_passes(self) -> None:
        program = self._program("start"); calls: list[list[str]] = []; qkk_calls = 0
        def command(argv, **_kwargs):
            nonlocal qkk_calls
            calls.append(argv)
            if argv[:3] == ["/usr/bin/pacman", "-Q", "swtpm"]:
                return SimpleNamespace(returncode=0, stdout=b"swtpm 0.10.2-1\n")
            if argv == ["/usr/bin/pgrep", "-x", "swtpm"]:
                return SimpleNamespace(returncode=1, stdout=b"")
            if argv == ["/usr/bin/pacman", "-Qkk", "swtpm"]:
                qkk_calls += 1
                return SimpleNamespace(returncode=1 if qkk_calls == 1 else 0, stdout=b"")
            return SimpleNamespace(returncode=0, stdout=b"")
        output = io.StringIO()
        with mock.patch("subprocess.run", side_effect=command), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(SECRET))), \
                contextlib.redirect_stdout(output):
            exec(program, {"__name__": "__main__"})
        transaction = next(item for item in calls if item[:2] == ["/usr/bin/sudo", "-S"])
        self.assertEqual(transaction[-1], "extra/swtpm=0.10.2-1")
        self.assertNotIn("--needed", transaction)
        self.assertIn(["/usr/bin/pacman", "-Qkk", "swtpm"], calls)
        self.assertEqual(json.loads(output.getvalue())["state"], "verified")

    def test_start_race_already_healthy_never_reads_secret_or_runs_sudo(self) -> None:
        program = self._program("start"); calls: list[list[str]] = []
        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["/usr/bin/pacman", "-Q", "swtpm"]:
                return SimpleNamespace(returncode=0, stdout=b"swtpm 0.10.2-1\n")
            if argv == ["/usr/bin/pgrep", "-x", "swtpm"]:
                return SimpleNamespace(returncode=1, stdout=b"")
            return SimpleNamespace(returncode=0, stdout=b"")
        output = io.StringIO()
        with mock.patch("subprocess.run", side_effect=command), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b""))), \
                contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):
                exec(program, {"__name__": "__main__"})
        self.assertEqual(json.loads(output.getvalue())["state"], "already-healthy")
        self.assertTrue(json.loads(output.getvalue())["packageIntegrityVerified"])
        self.assertFalse(json.loads(output.getvalue())["pacmanSignatureVerified"])
        self.assertFalse(any(item[:2] == ["/usr/bin/sudo", "-S"] for item in calls))

    def test_active_swtpm_fails_closed_before_repair_transaction(self) -> None:
        program = self._program("start"); calls: list[list[str]] = []
        def command(argv, **_kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0 if argv == ["/usr/bin/pgrep", "-x", "swtpm"] else 1,
                                   stdout=b"")
        output = io.StringIO()
        with mock.patch("subprocess.run", side_effect=command), contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):
                exec(program, {"__name__": "__main__"})
        self.assertEqual(json.loads(output.getvalue())["state"], "active-swtpm-processes")
        self.assertFalse(any(item[:2] == ["/usr/bin/sudo", "-S"] for item in calls))

    def test_preflight_never_reads_credential_and_admits_only_the_known_failure(self) -> None:
        failed = {"state": "integrity-failed", "activeSwtpmProcesses": False}
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(repair, "_remote", return_value=failed), \
                mock.patch.object(repair, "_policy", return_value=True), \
                mock.patch.object(repair, "_credential_metadata", return_value=True), \
                mock.patch.object(repair, "_read_credential", side_effect=AssertionError):
            result = repair.preflight(root, host="archlinux", correlation_id=CORR, timeout_seconds=60)
        self.assertEqual(result["state"], "ready")
        self.assertTrue(result["safeStartAllowed"])
        for remote_state in ("verified", "package-not-exact", "process-census-unavailable"):
            with tempfile.TemporaryDirectory() as root, mock.patch.object(repair, "_remote", return_value={"state": remote_state, "activeSwtpmProcesses": False}):
                self.assertEqual(repair.preflight(root, host="archlinux", correlation_id=CORR)["state"], remote_state)

    def test_credential_safety_and_response_loss_create_no_replay_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root, 0o644)
            observation = {"state": "integrity-failed", "activeSwtpmProcesses": False}
            with mock.patch.object(repair, "_remote", return_value=observation) as remote, mock.patch.object(repair, "_policy", return_value=True):
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    repair.start(root, host="archlinux", correlation_id=CORR)
            remote.assert_called_once()  # read-only observation only; no credential/intent transaction.
            self.assertFalse((Path(root) / ".rag_index" / "windows-vm-swtpm-repair" / "intent.json").exists())
            os.chmod(credential, 0o600)
            observation = {"state": "integrity-failed", "activeSwtpmProcesses": False}
            with mock.patch.object(repair, "_remote", side_effect=[observation, TimeoutError]) as remote, \
                    mock.patch.object(repair, "_policy", return_value=True):
                result = repair.start(root, host="archlinux", correlation_id=CORR)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                repair.start(root, host="archlinux", correlation_id=CORR)
            with mock.patch.object(repair, "_read_credential", side_effect=AssertionError), \
                    mock.patch.object(repair, "_remote", return_value={"state": "unknown"}) as observe:
                status = repair.status(root, host="archlinux", correlation_id=CORR)
            self.assertEqual(status["state"], "unknown")
            self.assertFalse(status["replayAllowed"])
            self.assertEqual(observe.call_args.args[2], "status")
            self.assertNotIn("credential", observe.call_args.kwargs)

    def test_fixed_credential_location_has_no_public_override(self) -> None:
        self.assertEqual(list(__import__("inspect").signature(repair.start).parameters),
                         ["root", "host", "correlation_id", "timeout_seconds"])
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root)
            self.assertEqual(repair._read_credential(root), SECRET)
            credential.unlink()
            Path(root, "alternate").write_bytes(SECRET)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                repair._read_credential(root)

    def test_policy_reuses_inherited_extra_fallback_and_rejects_explicit_bad_override(self) -> None:
        with mock.patch.object(repair.windows_vm_virt_firmware_install, "_signature_policy_state",
                               return_value="required-trusted-implicit") as policy:
            self.assertTrue(repair._policy(".", 60))
        policy.assert_called_once_with(".", 60)
        for state in ("repo-override-unreadable", "rejected", "unavailable-global-query"):
            with self.subTest(state=state), mock.patch.object(
                    repair.windows_vm_virt_firmware_install, "_signature_policy_state", return_value=state):
                self.assertFalse(repair._policy(".", 60))

    def test_remote_transport_pins_ssh_and_never_places_secret_in_command_or_environment(self) -> None:
        config = SimpleNamespace(hosts={"archlinux": object()})
        payload = {"schemaVersion": 1, "host": "archlinux", "correlationId": CORR,
                   "state": "verified", "package": "swtpm", "version": "0.10.2-1",
                   "pacmanSignatureVerified": True, "packageIntegrityVerified": True,
                   "activeSwtpmProcesses": False}
        with mock.patch.object(repair.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(repair.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(repair.ssh_transport, "build_ssh_argv", return_value=["/usr/bin/ssh", "archlinux"]) as argv, \
                mock.patch.object(repair.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode())) as run:
            repair._remote(".", CORR, "start", 60, credential=SECRET)
        self.assertEqual(run.call_args.kwargs["input"], SECRET)
        self.assertIs(run.call_args.kwargs["stderr"], repair.subprocess.DEVNULL)
        self.assertEqual(argv.call_args.kwargs["ssh_binary"], "/usr/bin/ssh")
        self.assertNotIn(SECRET.decode().strip(), " ".join(argv.call_args.kwargs["command"]))
        self.assertNotIn("env", run.call_args.kwargs)

    def test_mcp_route_accepts_only_fixed_one_shot_shape(self) -> None:
        response = {"correlationId": CORR, "host": "archlinux", "state": "unknown", "package": "swtpm", "version": "0.10.2-1", "pacmanSignatureVerified": False, "packageIntegrityVerified": False, "activeSwtpmProcesses": False, "replayAllowed": False, "nativeActionAllowed": False}
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.start.return_value = response
            result = mcp_server._vm_workflow_impl("windows-vm-swtpm-repair-start", REQUEST)
            self.assertEqual(result["state"], "unknown"); self.assertFalse(result["replayAllowed"])
            for changed in ({"host": "other"}, {"correlationId": "not-a-uuid"}, {"timeoutSeconds": True}, {"password": "forbidden"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-swtpm-repair-start", {**REQUEST, **changed})["ok"])

    def test_mcp_preserves_truthful_already_healthy_integrity_receipt(self) -> None:
        response = {"correlationId": CORR, "host": "archlinux", "state": "already-healthy", "package": "swtpm", "version": "0.10.2-1", "pacmanSignatureVerified": False, "packageIntegrityVerified": True, "activeSwtpmProcesses": False, "replayAllowed": False, "nativeActionAllowed": False}
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.start.return_value = response
            result = mcp_server._vm_workflow_impl("windows-vm-swtpm-repair-start", REQUEST)
        self.assertEqual(result["state"], "already-healthy")
        self.assertTrue(result["packageIntegrityVerified"])
        self.assertFalse(result["pacmanSignatureVerified"])

    def test_mcp_exception_fallbacks_preserve_complete_typed_schemas(self) -> None:
        with mock.patch.object(mcp_server, "_agent_module", side_effect=ValueError):
            preflight = mcp_server._vm_workflow_impl("windows-vm-swtpm-repair-preflight", REQUEST)
            start = mcp_server._vm_workflow_impl("windows-vm-swtpm-repair-start", REQUEST)
        self.assertTrue({"packageIntegrityFailed", "activeSwtpmProcesses", "safeStartAllowed", "newCorrelationRequired", "nativeActionAllowed"} <= set(preflight))
        self.assertTrue({"package", "version", "pacmanSignatureVerified", "packageIntegrityVerified", "activeSwtpmProcesses", "replayAllowed", "nativeActionAllowed"} <= set(start))

    def test_owner_observe_attributes_active_swtpm_without_raw_path_or_command_exposure(self) -> None:
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": True, "censusReason": None,
               "observedAtUnixMs": 1, "processes": [{"pid": 417, "startTicks": 9917,
               "uid": 1000, "relationship": "task-owned-swtpm-socket"}]}
        config = SimpleNamespace(hosts={"archlinux": object()})
        with mock.patch.object(repair.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(repair.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(repair.ssh_transport, "build_ssh_argv", return_value=["/usr/bin/ssh", "archlinux"]) as argv, \
                mock.patch.object(repair.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(raw).encode())):
            result = repair.owner_observe(".", host="archlinux", timeout_seconds=30)
        self.assertEqual(result, {"host": "archlinux", "state": "observed", "censusReason": None, "censusComplete": True,
                                  "activeSwtpmProcesses": True, "processes": raw["processes"],
                                  "nativeActionAllowed": False})
        command = argv.call_args.kwargs["command"][-1]
        decoded = base64.b64decode(command.split("b64decode(", 1)[1].split(")", 1)[0].strip("'\"")).decode()
        compile(decoded, "<swtpm-owner-observe>", "exec")
        self.assertIn("TPM_SOCKET", decoded)
        self.assertNotIn("cmdline", decoded)
        self.assertNotIn("kill", decoded)

    def test_owner_observe_fails_closed_on_incomplete_census_and_mcp_schema_is_fixed(self) -> None:
        raw = {"schemaVersion": 1, "host": "archlinux", "censusComplete": False, "censusReason": "fd-census-incomplete",
               "observedAtUnixMs": 1, "processes": []}
        config = SimpleNamespace(hosts={"archlinux": object()})
        with mock.patch.object(repair.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(repair.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                mock.patch.object(repair.ssh_transport, "build_ssh_argv", return_value=["/usr/bin/ssh", "archlinux"]), \
                mock.patch.object(repair.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(raw).encode())):
            self.assertEqual(repair.owner_observe(".", host="archlinux")["state"], "unknown")
        observed = {"host": "archlinux", "state": "observed", "censusReason": None, "censusComplete": True,
                    "activeSwtpmProcesses": True, "processes": [{"pid": 417, "startTicks": 9917,
                    "uid": 1000, "relationship": "unattributed-vm-or-socket-path"}], "nativeActionAllowed": False}
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.owner_observe.return_value = observed
            result = mcp_server._vm_workflow_impl("windows-vm-swtpm-owner-observe", {"host": "archlinux", "timeoutSeconds": 30})
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["processes"][0]["relationship"], "unattributed-vm-or-socket-path")
        self.assertFalse(result["nativeActionAllowed"])
        self.assertIsNone(result["censusReason"])
        with mock.patch.object(mcp_server, "_agent_module", side_effect=ValueError):
            failed = mcp_server._vm_workflow_impl("windows-vm-swtpm-owner-observe", {"host": "archlinux", "timeoutSeconds": 30})
        self.assertEqual(failed["state"], "unknown")
        self.assertEqual(failed["processes"], [])
        self.assertEqual(failed["censusReason"], "census-unavailable")

    def test_owner_observe_mcp_rejects_contradictory_state_and_census_completeness(self) -> None:
        base = {"host": "archlinux", "activeSwtpmProcesses": False, "processes": [],
                "nativeActionAllowed": False}
        for contradictory in (
                {**base, "state": "observed", "censusComplete": False, "censusReason": "fd-census-incomplete"},
                {**base, "state": "unknown", "censusComplete": True, "censusReason": None}):
            with self.subTest(contradictory=contradictory), mock.patch.object(mcp_server, "_agent_module") as module:
                module.return_value.owner_observe.return_value = contradictory
                result = mcp_server._vm_workflow_impl("windows-vm-swtpm-owner-observe", {"host": "archlinux", "timeoutSeconds": 30})
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["censusComplete"])
            self.assertEqual(result["censusReason"], "census-unavailable")

    def test_owner_observe_mountinfo_parser_handles_comma_separated_hidepid(self) -> None:
        body = repair._OWNER_OBSERVE_REMOTE.split("def visibility():", 1)[1].split("def unix():", 1)[0]
        scope: dict[str, object] = {}
        exec("import os\ndef visibility():" + body, scope)
        mount = "36 25 0:32 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=2\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=mount)), \
                mock.patch.object(repair.os, "readlink", return_value="pid:[1]"):
            self.assertEqual(scope["visibility"](), "proc-visibility-incomplete")
        complete = "36 25 0:32 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=complete)), \
                mock.patch.object(repair.os, "readlink", return_value="pid:[1]"):
            self.assertEqual(scope["visibility"](), "complete")

    def test_task_owned_socket_requires_exact_private_receipts(self) -> None:
        self.assertIn("receipt=={'pid':pid,'startTicks':start}", repair._OWNER_OBSERVE_REMOTE)
        self.assertIn("qemu-started.json", repair._OWNER_OBSERVE_REMOTE)
        self.assertIn("linked and task_claim(pid,start)", repair._OWNER_OBSERVE_REMOTE)

    def test_task_claim_rejects_stale_qemu_generation(self) -> None:
        body = repair._OWNER_OBSERVE_REMOTE.split("def live_qemu", 1)[1].split("def task_claim", 1)[0]
        scope: dict[str, object] = {"ticks": lambda _pid: 98}
        exec("def live_qemu" + body, scope)
        with mock.patch("builtins.open", mock.mock_open(read_data="qemu-system-x86_64\n")):
            self.assertFalse(scope["live_qemu"](88, 99))
        self.assertIn("live_qemu(qemu['pid'],qemu['startTicks'])", repair._OWNER_OBSERVE_REMOTE)

    def test_cli_parser_dispatches_fixed_owner_action_and_rejects_unknown_action(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            inputs = Path(root) / "inputs.json"
            inputs.write_text('{"host":"archlinux","timeoutSeconds":30}', encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(mcp_server, "vm_workflow", return_value={"ok": False, "state": "unknown"}) as dispatch, \
                    contextlib.redirect_stdout(output):
                mcp_server.main(["vm-workflow", "windows-vm-swtpm-owner-observe", "--inputs-file", str(inputs)])
            dispatch.assert_called_once_with("windows-vm-swtpm-owner-observe", {"host": "archlinux", "timeoutSeconds": 30})
            self.assertIn('"state": "unknown"', output.getvalue())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                mcp_server.main(["vm-workflow", "windows-vm-swtpm-owner-observe-mutate", "--inputs-file", str(inputs)])


if __name__ == "__main__":
    unittest.main()
