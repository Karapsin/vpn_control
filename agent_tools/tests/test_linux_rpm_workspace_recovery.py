"""Bounded, read-only Fedora workspace recovery observation."""

import ast
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from agent_tools import linux_rpm_workspace_recovery as recovery


CORRELATION = "944447ff-7ee3-42df-8ca8-f02dac670459"


class LinuxRpmWorkspaceRecoveryTest(unittest.TestCase):
    def test_cleanup_guest_programs_compile_and_reject_symlink_in_workspace(self):
        for name in ("_PRIVILEGED_CLEANUP_GUARD", "_CLEANUP", "_CLEANUP_STATUS"):
            compile(getattr(recovery, name), name, "exec")
        tree = ast.parse(recovery._CLEANUP)
        remove = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                      and node.name == "remove")
        namespace = {"os": os, "stat": stat}
        exec(compile(ast.Module(body=[remove], type_ignores=[]), "<fixed-remove>", "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            (workspace / "link").symlink_to(Path(temporary))
            fd = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaisesRegex(ValueError, "entry-unsafe"):
                    namespace["remove"](fd)
            finally:
                os.close(fd)

    def test_cleanup_requires_independent_exact_replacement_owner_quit(self):
        tree = ast.parse(recovery._CLEANUP)
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {"private", "verified_quit"}]
        namespace = {"os": os, "stat": stat, "Path": Path, "json": json}
        exec(compile(ast.Module(body=functions, type_ignores=[]), "<fixed-quit-proof>", "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            base = home / ".vpn-control-agent-owner-quit"
            job = base / recovery._OWNER_QUIT
            base.mkdir(mode=0o700)
            job.mkdir(mode=0o700)
            intent = {"correlationId": recovery._OWNER_QUIT, "pid": 84498,
                      "startTicks": 42693938, "controllerId": "4da9288d-dd73-4312-92d8-c7d96f046040",
                      "approval": "fedora-acceptance-disconnected-replacement-owner-quit"}
            receipt = {key: intent[key] for key in ("correlationId", "pid", "startTicks", "controllerId")}
            receipt.update(publicAccepted=True, exitCode=0)
            for name, value in (("intent.json", intent), ("receipt.json", receipt)):
                path = job / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            proc = home / "proc"
            proc.mkdir()
            namespace["verified_quit"](home, proc)
            pid = proc / "84498"
            pid.mkdir()
            (pid / "stat").write_text("84498 (owner) " + " ".join(
                ["S"] + ["0"] * 18 + ["42693938"]))
            with self.assertRaisesRegex(ValueError, "owner-still-live"):
                namespace["verified_quit"](home, proc)
            (pid / "stat").unlink()
            pid.rmdir()
            receipt["publicAccepted"] = False
            (job / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "owner-quit-result"):
                namespace["verified_quit"](home, proc)

    def test_guest_cleanup_executes_replacement_quit_call_with_imports(self):
        tree = ast.parse(recovery._CLEANUP)
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        action = next(node for node in tree.body if isinstance(node, ast.Try))
        call = next(node for node in action.body if isinstance(node, ast.Expr) and
                    isinstance(node.value, ast.Call) and
                    isinstance(node.value.func, ast.Name) and
                    node.value.func.id == "verified_quit")
        namespace = {"verified_quit": mock.Mock()}
        with mock.patch("pwd.getpwnam", return_value=SimpleNamespace(pw_dir="/fixture-home")):
            missing_pwd = [node for node in imports if not (
                isinstance(node, ast.Import) and any(alias.name == "pwd" for alias in node.names))]
            with self.assertRaises(NameError):
                exec(compile(ast.Module(body=[*missing_pwd, call], type_ignores=[]),
                             "<missing-pwd>", "exec"), dict(namespace))
            exec(compile(ast.Module(body=[*imports, call], type_ignores=[]),
                         "<fixed-quit-call>", "exec"), namespace)
        namespace["verified_quit"].assert_called_once_with("/fixture-home")

    def test_cleanup_status_rejects_symlink_foreign_pointer_and_inode_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cleanup = "12345678-1234-1234-1234-123456789abc"
            job = root / "workspace-recovery-jobs" / cleanup
            job.mkdir(mode=0o700, parents=True)
            evidence = Path(temporary) / "vpn-public-install-evidence-example"
            evidence.mkdir(mode=0o700)
            intent = {"correlationId": cleanup, "failedCorrelationId": recovery._FAILED_PUBLIC,
                      "evidence": str(evidence), "workspaceDev": 1, "workspaceIno": 2}
            receipt = {"correlationId": cleanup, "state": "terminal", "result": "passed",
                       "workspaceDev": 1, "workspaceIno": 2, "workspaceRemoved": True}
            for name, value in (("intent.json", intent), ("receipt.json", receipt)):
                path = job / name
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            original = (root / "native-scenario-jobs" / "fedora2328" /
                        "linux-rpm-public-install-recovery" / recovery._FAILED_PUBLIC)
            original.mkdir(parents=True)
            target = root / "pointer-target"
            target.write_text(json.dumps({"evidence": str(evidence),
                "workspace": str(evidence / "workspace")}) + "\n")
            target.chmod(0o600)
            pointer = original / "harness.stdout"
            pointer.symlink_to(target)
            def observe():
                run = subprocess.run([sys.executable, "-c", recovery._CLEANUP_STATUS,
                    str(root), recovery._FAILED_PUBLIC, cleanup], capture_output=True, text=True)
                self.assertEqual(0, run.returncode)
                return json.loads(run.stdout)
            self.assertEqual("unknown", observe()["state"])
            pointer.unlink()
            pointer.write_bytes(target.read_bytes())
            pointer.chmod(0o644)
            self.assertEqual("unknown", observe()["state"])
            pointer.chmod(0o600)
            receipt["workspaceIno"] = 3
            (job / "receipt.json").write_text(json.dumps(receipt))
            self.assertEqual("unknown", observe()["state"])

    def test_cleanup_requires_absent_scanner_before_durable_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = {"correlationId": recovery._FAILED_PUBLIC,
                       "cleanupCorrelationId": "12345678-1234-1234-1234-123456789abc"}
            with mock.patch("agent_tools.linux_owner_public_quit.status", return_value={
                    "state": "terminal", "result": "passed", "ownerGenerationGone": True}), \
                 mock.patch.object(recovery, "status", return_value={"state": "unknown"}), \
                 mock.patch("agent_tools.linux_rpm_base_prepare.preflight") as package:
                result = recovery.cleanup_start(root, request)
            self.assertEqual("blocked", result["state"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse((root / ".rag_index").exists())
            package.assert_not_called()

    def test_cleanup_response_loss_never_resubmits_same_correlation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = {"correlationId": recovery._FAILED_PUBLIC,
                       "cleanupCorrelationId": "12345678-1234-1234-1234-123456789abc"}
            driver = mock.Mock()
            driver._read_journal.return_value = {"bundleHash": "a" * 64, "artifactIds": {}}
            driver._remote.return_value = None
            config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture",
                fixture_transfer_root=PurePosixPath("/private/fedora"))})
            with mock.patch("agent_tools.linux_owner_public_quit.status", return_value={
                    "state": "terminal", "result": "passed", "ownerGenerationGone": True}), \
                 mock.patch.object(recovery, "status", return_value={
                     "state": "observed", "scannerState": "absent"}), \
                 mock.patch("agent_tools.linux_rpm_base_prepare.preflight", return_value={
                     "state": "ready", "currentNevra": recovery._TARGET_NEVRA,
                     "currentHeaderSha1": recovery._TARGET_HEADER}), \
                 mock.patch.object(recovery.rpm, "RpmPublicInstallSshDriver", return_value=driver), \
                 mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                 mock.patch("agent_tools.linux_rpm_fixture_server_lifecycle._journal",
                            return_value={"expectedTargetVersion": "2.2.0",
                                          "sourceFingerprint": "b" * 64}), \
                 mock.patch.object(recovery, "_encoded_scanner", return_value="Zml4ZWQ="):
                first = recovery.cleanup_start(root, request)
                second = recovery.cleanup_start(root, request)
            self.assertEqual(("unknown", "cleanup-response-uncertain"),
                             (first["state"], first["reason"]))
            self.assertEqual(("unknown", "existing-intent"),
                             (second["state"], second["reason"]))
            self.assertEqual(1, driver._remote.call_count)
            journal = root / ".rag_index" / "linux-rpm-workspace-cleanup" / (
                request["cleanupCorrelationId"] + ".json")
            self.assertEqual(0o600, journal.stat().st_mode & 0o777)

    def test_fixed_scanner_program_compiles_and_carries_typed_reason(self):
        root = Path(__file__).resolve().parents[2]
        program = recovery._scanner_program(root)
        compile(program, "<fixed-scanner>", "exec")
        self.assertIn("process-links-unavailable", program)

    def test_remote_observer_transports_scanner_without_control_characters(self):
        self.assertIn("base64.b64decode(scanner,validate=True)", recovery._OBSERVE)
        self.assertIn("len(program)>8192", recovery._OBSERVE)
        root = Path(__file__).resolve().parents[2]
        encoded = recovery._encoded_scanner(root)
        self.assertIsNone(re.search(r"[\x00-\x1f\x7f]", encoded))

    def test_privileged_scanner_rejects_tampered_or_symlinked_source(self):
        source = Path(__file__).resolve().parents[2] / "scripts/test_linux_public_install.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            candidate = scripts / source.name
            shutil.copyfile(source, candidate)
            self.assertTrue(recovery._scanner_program(root))
            candidate.write_text(candidate.read_text().replace(
                "return unknown('invalid-input')", "return {'state':'absent','sameUidCount':1}", 1))
            with self.assertRaises(ValueError):
                recovery._scanner_program(root)
            candidate.unlink()
            candidate.symlink_to(source)
            with self.assertRaises(ValueError):
                recovery._scanner_program(root)
            candidate.unlink()
            scripts.rmdir()
            scripts.symlink_to(source.parent)
            with self.assertRaises(ValueError):
                recovery._scanner_program(root)

    def test_status_emits_only_bounded_scanner_reason_or_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "scripts/test_linux_public_install.py").write_text(
                "def _privileged_workspace_observation(*args):\n"
                "    return {'state':'unknown','reason':'process-links-unavailable'}\n")
            public = {"state": "terminal", "correlationId": CORRELATION,
                      "exitCode": 1, "scenarioEvidence": {"result": "failed",
                      "cleanup": {"workspaceRemoved": False}}}
            journal = {"bundleHash": "a" * 64, "artifactIds": {"bundleManifest": "sha256-" + "a" * 64}}
            server_journal = {"correlationId": CORRELATION,
                              "expectedTargetVersion": "2.2.0", "sourceFingerprint": "b" * 64}
            driver = mock.Mock()
            driver.status.return_value = public
            driver._read_journal.return_value = journal
            driver._remote.return_value = {"state": "observed", "correlationId": CORRELATION,
                "scanner": {"state": "unknown", "reason": "process-links-unavailable",
                            "secret": "/private/path"}}
            config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture",
                fixture_transfer_root=PurePosixPath("/private/fedora"))})
            with mock.patch.object(recovery.rpm, "RpmPublicInstallSshDriver", return_value=driver), \
                 mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(recovery, "_scanner_program", return_value="fixed-reviewed-scanner"), \
                 mock.patch("agent_tools.linux_rpm_fixture_server_lifecycle._journal",
                            return_value=server_journal):
                result = recovery.status(root, {"correlationId": CORRELATION})
                self.assertEqual("Zml4ZWQtcmV2aWV3ZWQtc2Nhbm5lcg==",
                                 driver._remote.call_args.args[3][-1])
                self.assertEqual("process-links-unavailable", result["scannerReason"])
                self.assertEqual("unknown", result["state"])
                self.assertNotIn("secret", result)
                driver._remote.return_value["scanner"] = {
                    "state": "referenced", "pid": 84498, "startTicks": 42693938,
                    "path": "/private/path"}
                result = recovery.status(root, {"correlationId": CORRELATION})
                self.assertEqual((84498, 42693938),
                                 (result["referencePid"], result["referenceStartTicks"]))
                self.assertNotIn("path", result)
                driver._remote.return_value = {"state": "unknown", "correlationId": CORRELATION,
                                                "reason": "/private/path"}
                result = recovery.status(root, {"correlationId": CORRELATION})
                self.assertEqual("guest-observer-unavailable", result["reason"])

    def test_invalid_correlation_cannot_reach_guest(self):
        with self.assertRaises(ValueError):
            recovery.status(Path.cwd(), {"correlationId": "../other"})


if __name__ == "__main__":
    unittest.main()
