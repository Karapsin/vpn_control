"""Causal contract tests for the fixed Windows Secure Boot firmware installer."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import mcp_server
from agent_tools import ssh_transport as ssh
from agent_tools import windows_vm_virt_firmware_install as installer


CORR = "123e4567-e89b-12d3-a456-426614174000"
SECRET = b"test-secret\n"
REQUEST = {"host": "archlinux", "correlationId": CORR, "timeoutSeconds": 60}


class WindowsVmVirtFirmwareInstallTest(unittest.TestCase):
    def _credential(self, root: str, *, mode: int = 0o600) -> Path:
        path = Path(root) / "credential"
        path.write_bytes(SECRET)
        os.chmod(path, mode)
        return path

    def test_remote_program_installs_only_pinned_package_then_requires_integrity_and_tool(self) -> None:
        program = installer._REMOTE.replace("__MODE__", repr("start")).replace("__CORR__", repr(CORR))
        compile(program, "<virt-firmware-install>", "exec")
        self.assertIn("PACKAGE+'='+VERSION", program)
        self.assertIn("['/usr/bin/pacman','-Qkk',PACKAGE]", program)
        self.assertIn("'/usr/bin/virt-fw-vars'", program)
        self.assertIn("['/usr/bin/sudo','-S','-p',''", program)
        calls: list[list[str]] = []

        def command(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["/usr/bin/pacman", "-Q", "virt-firmware"]:
                return SimpleNamespace(returncode=0, stdout=b"virt-firmware 26.9-1\n")
            return SimpleNamespace(returncode=0, stdout=b"")

        output = io.StringIO()
        file_mode = SimpleNamespace(st_mode=stat.S_IFREG | 0o755)
        with mock.patch("subprocess.run", side_effect=command), \
                mock.patch("os.lstat", return_value=file_mode), \
                mock.patch("os.access", return_value=True), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(SECRET))), \
                contextlib.redirect_stdout(output):
            exec(program, {"__name__": "__main__"})
        response = json.loads(output.getvalue())
        self.assertEqual(response["state"], "verified")
        self.assertTrue(response["packageIntegrityVerified"])
        self.assertTrue(response["firmwareToolPresent"])
        self.assertIn(["/usr/bin/sudo", "-S", "-p", "", "--", "/usr/bin/pacman", "-S",
                       "--needed", "--noconfirm", "extra/virt-firmware=26.9-1"], calls)
        self.assertIn(["/usr/bin/pacman", "-Qkk", "virt-firmware"], calls)
        self.assertNotIn(SECRET.decode().strip(), output.getvalue())

    def test_private_credential_rejects_relative_symlink_wrong_mode_and_foreign_owner(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root)
            self.assertEqual(installer._read_credential(root, credential_path=credential), SECRET)
            with self.assertRaisesRegex(ValueError, "path is unsafe"):
                installer._read_credential(root, credential_path=Path("relative"))
            os.chmod(credential, 0o644)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                installer._read_credential(root, credential_path=credential)
            os.chmod(credential, 0o600)
            link = Path(root) / "credential-link"
            link.symlink_to(credential)
            with self.assertRaisesRegex(ValueError, "unavailable|unsafe"):
                installer._read_credential(root, credential_path=link)
            with mock.patch.object(installer.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    installer._read_credential(root, credential_path=credential)

    def test_symlinked_credential_parent_is_rejected_through_directory_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            real_parent = Path(root) / "real-codex"
            real_parent.mkdir(mode=0o700)
            credential = real_parent / "arch-sudo.local"
            credential.write_bytes(SECRET)
            os.chmod(credential, 0o600)
            parent_link = Path(root) / "linked-codex"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "parent is unsafe"):
                installer._read_credential(root, credential_path=parent_link / credential.name)

    def test_extra_signature_policy_requires_package_signature_and_trusted_key_before_credential(self) -> None:
        def run_for(policy: bytes):
            program = installer._SIGNATURE_POLICY_REMOTE
            output = io.StringIO()
            with mock.patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=policy)), \
                    mock.patch("os.lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755)), \
                    mock.patch("os.access", return_value=True), contextlib.redirect_stdout(output):
                exec(program, {"__name__": "__main__"})
            return json.loads(output.getvalue())

        self.assertIn("['/usr/bin/pacman-conf','--repo','extra','SigLevel']",
                      installer._SIGNATURE_POLICY_REMOTE)
        self.assertTrue(run_for(b"PackageRequired PackageTrustedOnly\n")["signaturePolicyRequired"])
        # A global Required setting cannot override an extra-specific Never or
        # PackageOptional policy. The fixed extra probe must fail closed.
        self.assertFalse(run_for(b"Required Never TrustedOnly\n")["signaturePolicyRequired"])
        self.assertFalse(run_for(b"Required PackageNever TrustedOnly\n")["signaturePolicyRequired"])
        self.assertFalse(run_for(b"Required PackageOptional TrustedOnly\n")["signaturePolicyRequired"])
        self.assertFalse(run_for(b"PackageRequired TrustAll\n")["signaturePolicyRequired"])
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(installer, "_signature_policy", return_value=False), \
                mock.patch.object(installer, "_read_credential") as read:
            with self.assertRaisesRegex(ValueError, "signature policy"):
                installer.start(root, host="archlinux", correlation_id=CORR, timeout_seconds=60)
        read.assert_not_called()

    def test_remote_sudo_or_pacman_nonzero_is_generic_without_returning_credential_or_diagnostics(self) -> None:
        program = installer._REMOTE.replace("__MODE__", repr("start")).replace("__CORR__", repr(CORR))
        # The outer sudo process reports only one transaction exit status.  A
        # password rejection and a pacman failure can both be nonzero here;
        # neither may be guessed from suppressed diagnostics.
        for failure, code in (("sudo", 1), ("pacman", 42)):
            with self.subTest(failure=failure):
                calls: list[list[str]] = []

                def command(argv, **_kwargs):
                    calls.append(argv)
                    return SimpleNamespace(returncode=code, stdout=b"")

                output = io.StringIO()
                with mock.patch("subprocess.run", side_effect=command), \
                        mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(SECRET))), \
                        contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit):
                        exec(program, {"__name__": "__main__"})
                response = json.loads(output.getvalue())
                self.assertEqual(response["state"], "transaction-failed")
                self.assertFalse(response["packageIntegrityVerified"])
                self.assertFalse(response["firmwareToolPresent"])
                self.assertEqual(calls[0][:2], ["/usr/bin/sudo", "-S"])
                self.assertNotIn(SECRET.decode().strip(), output.getvalue())

    def test_invalid_credential_rejects_before_intent_so_corrected_file_can_start(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root, mode=0o644)
            with mock.patch.object(installer, "_signature_policy", return_value=True), \
                    mock.patch.object(installer, "_remote") as remote:
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    installer.start(root, host="archlinux", correlation_id=CORR,
                                    timeout_seconds=60, credential_path=credential)
            self.assertFalse((Path(root) / ".rag_index" / "windows-vm-virt-firmware-install" / "intent.json").exists())
            remote.assert_not_called()
            os.chmod(credential, 0o600)
            with mock.patch.object(installer, "_signature_policy", return_value=True), \
                    mock.patch.object(installer, "_remote", return_value={"state": "unknown"}) as remote:
                result = installer.start(root, host="archlinux", correlation_id=CORR,
                                         timeout_seconds=60, credential_path=credential)
            self.assertEqual(result["state"], "unknown")
            remote.assert_called_once()

    def test_start_journals_before_dispatch_and_never_records_or_prints_secret(self) -> None:
        remote_result = {"state": "verified", "pacmanSignatureVerified": True,
                         "packageIntegrityVerified": True, "firmwareToolPresent": True}
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root)
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(installer, "_signature_policy", return_value=True), \
                    mock.patch.object(installer, "_remote", return_value=remote_result) as remote, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                result = installer.start(root, host="archlinux", correlation_id=CORR,
                                         timeout_seconds=60, credential_path=credential)
            self.assertEqual(result["state"], "verified")
            self.assertFalse(result["replayAllowed"])
            self.assertEqual(remote.call_args.kwargs["credential"], SECRET)
            self.assertNotIn(SECRET.decode().strip(), installer._journal(root, create=False).read_text())
            self.assertNotIn(SECRET.decode().strip(), output.getvalue() + errors.getvalue())
            with self.assertRaisesRegex(ValueError, "already exists"):
                installer.start(root, host="archlinux", correlation_id=CORR, credential_path=credential)
            remote.assert_called_once()

    def test_response_loss_is_unknown_and_status_does_not_replay_or_read_credential(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            credential = self._credential(root)
            with mock.patch.object(installer, "_signature_policy", return_value=True), \
                    mock.patch.object(installer, "_remote", side_effect=TimeoutError) as remote:
                result = installer.start(root, host="archlinux", correlation_id=CORR,
                                         timeout_seconds=60, credential_path=credential)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                installer.start(root, host="archlinux", correlation_id=CORR, credential_path=credential)
            with mock.patch.object(installer, "_read_credential", side_effect=AssertionError), \
                    mock.patch.object(installer, "_remote", return_value={"state": "unknown"}) as observe:
                status = installer.status(root, host="archlinux", correlation_id=CORR, timeout_seconds=60)
            self.assertEqual(status["state"], "unknown")
            self.assertFalse(status["replayAllowed"])
            self.assertEqual(observe.call_args.args[2], "status")
            self.assertNotIn("credential", observe.call_args.kwargs)
            self.assertEqual(remote.call_count, 1)

    def test_transport_uses_configured_ssh_and_secret_only_as_stdin(self) -> None:
        config = SimpleNamespace(hosts={"archlinux": object()})
        response = {"schemaVersion": 1, "host": "archlinux", "correlationId": CORR,
                    "state": "verified", "package": "virt-firmware", "version": "26.9-1",
                    "pacmanSignatureVerified": True, "packageIntegrityVerified": True,
                    "firmwareToolPresent": True}
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(response).encode())
        with mock.patch.object(installer.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(installer.ssh_transport, "connection_host",
                                  return_value=SimpleNamespace(password=None)), \
                mock.patch.object(installer.ssh_transport, "build_ssh_argv",
                                  return_value=["ssh", "archlinux"]) as argv, \
                mock.patch.object(installer.subprocess, "run", return_value=completed) as run:
            result = installer._remote(".", CORR, "start", 60, credential=SECRET)
        self.assertEqual(result["state"], "verified")
        self.assertEqual(run.call_args.kwargs["input"], SECRET)
        self.assertIs(run.call_args.kwargs["stderr"], installer.subprocess.DEVNULL)
        self.assertEqual(argv.call_args.kwargs["command"][0], "/usr/bin/python3")
        self.assertNotIn(SECRET.decode().strip(), " ".join(argv.call_args.kwargs["command"]))
        self.assertNotIn("SUDO_ASKPASS", run.call_args.kwargs)

    def test_installer_pins_local_and_nested_ssh_binaries_while_secret_stays_stdin(self) -> None:
        config = ssh.SshConfig(root=Path("."), hosts={
            "gateway": ssh.SshHost("gateway", "gateway.example", 22, "owner", Path("/private/id"), Path("/private/known")),
            "archlinux": ssh.SshHost("archlinux", "unused", 22, "unused", Path("/unused/id"),
                ssh.PurePosixPath("/private/nested-known"), transport="nested", gateway="gateway",
                remote_host_alias="archlinux", remote_control_path=ssh.PurePosixPath("/private/control")),
        })
        response = {"schemaVersion": 1, "host": "archlinux", "correlationId": CORR,
                    "state": "verified", "package": "virt-firmware", "version": "26.9-1",
                    "pacmanSignatureVerified": True, "packageIntegrityVerified": True,
                    "firmwareToolPresent": True}
        with mock.patch.object(installer.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(installer.subprocess, "run",
                                  return_value=SimpleNamespace(returncode=0, stdout=json.dumps(response).encode())) as run:
            installer._remote(".", CORR, "start", 60, credential=SECRET)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/ssh")
        self.assertEqual(shlex.split(argv[-1])[0], "/usr/bin/ssh")
        self.assertEqual(run.call_args.kwargs["input"], SECRET)

    def test_mcp_route_is_exact_and_response_loss_has_no_replay_route(self) -> None:
        with mock.patch.object(mcp_server, "_agent_module") as module:
            module.return_value.start.return_value = {"correlationId": CORR, "host": "archlinux",
                "state": "unknown", "package": "virt-firmware", "version": "26.9-1",
                "pacmanSignatureVerified": False, "packageIntegrityVerified": False,
                "firmwareToolPresent": False, "replayAllowed": False, "nativeActionAllowed": False}
            result = mcp_server._vm_workflow_impl("windows-vm-virt-firmware-install-start", REQUEST)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            module.return_value.start.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                correlation_id=CORR, timeout_seconds=60)
            for changed in ({"host": "other"}, {"correlationId": "not-a-uuid"},
                            {"timeoutSeconds": True}, {"password": "forbidden"}):
                with self.subTest(changed=changed):
                    rejected = mcp_server._vm_workflow_impl("windows-vm-virt-firmware-install-start",
                                                            {**REQUEST, **changed})
                    self.assertFalse(rejected["ok"])


if __name__ == "__main__":
    unittest.main()
