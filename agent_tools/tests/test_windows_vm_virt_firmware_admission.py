"""Causal tests for the read-only Arch virt-firmware privilege admission."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import windows_vm_virt_firmware_admission as admission


class WindowsVmVirtFirmwareAdmissionTest(unittest.TestCase):
    def _remote(self, *, code=0, output=b"Matching Defaults entries for kardinal on archlinux:\n"
                b"    env_reset, secure_path=/usr/bin\n\n"
                b"User kardinal may run the following commands on archlinux:\n"
                b"    (root) NOPASSWD: /usr/bin/pacman\n",
                error=b"", available=True):
        captured = io.StringIO()
        completed = SimpleNamespace(returncode=code, stdout=output, stderr=error)
        with mock.patch("os.lstat", return_value=SimpleNamespace(st_mode=0o100755)), \
             mock.patch("os.access", return_value=available), \
             mock.patch("subprocess.run", return_value=completed) as run, \
             contextlib.redirect_stdout(captured):
            exec(admission._REMOTE, {"__name__": "__main__"})
        return json.loads(captured.getvalue()), run

    def test_only_exact_noninteractive_sudo_listing_runs_without_prompt_or_install(self):
        result, run = self._remote()
        self.assertEqual(result["state"], "sudo-nopasswd-pacman")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "-l"])
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertEqual(run.call_args.kwargs["env"]["SUDO_ASKPASS"], "/bin/false")
        self.assertNotIn("-S", run.call_args.args[0])

    def test_cached_or_argument_restricted_listing_is_not_install_eligibility(self):
        for output in (b"User may run:\n    (root) /usr/bin/pacman\n",
                       b"User may run:\n    (root) NOPASSWD: /usr/bin/pacman -Q virt-firmware\n",
                       b"User may run:\n    (other) NOPASSWD: /usr/bin/pacman\n",
                       b"User may run:\n    (root) NOPASSWD: /usr/bin/pacman\n"
                       b"    (root) PASSWD: /usr/bin/pacman -S virt-firmware\n",
                       b"User may run:\n    (root) NOPASSWD: /usr/bin/pacman\n"
                       b"    (root) PASSWD: ALL\n",
                       b"User may run:\n    (root) NOPASSWD: /usr/bin/pacman, "
                       b"(root) PASSWD: /usr/bin/pacman -S virt-firmware\n",
                       b"/usr/bin/pacman\n"):
            with self.subTest(output=output):
                result, _ = self._remote(output=output)
                self.assertEqual(result["state"], "sudo-listing-inconclusive")

    def test_denied_missing_or_oversized_output_never_admits(self):
        self.assertEqual(self._remote(code=1, output=b"")[0]["state"],
                         "sudo-unavailable-or-auth-required")
        self.assertEqual(self._remote(available=False)[0]["state"], "command-unavailable")
        self.assertEqual(self._remote(output=b"x" * 8193)[0]["state"], "unknown")
        self.assertEqual(self._remote(error=b"x" * 8193)[0]["state"], "unknown")

    def test_schema_and_invalid_host_or_timeout_fail_closed_before_dispatch(self):
        self.assertTrue(admission.classify({"schemaVersion": 1, "host": "archlinux",
                                            "state": "sudo-nopasswd-pacman"})["noninteractivePacmanEligible"])
        self.assertFalse(admission.classify({"schemaVersion": 1, "host": "archlinux",
                                             "state": "sudo-listing-inconclusive"})["nativeActionAllowed"])
        self.assertEqual(admission.classify({"schemaVersion": 1, "host": "other",
                                              "state": "sudo-nopasswd-pacman"})["state"], "unknown")
        for changed in ({"host": "other"}, {"timeoutSeconds": 5},
                        {"timeoutSeconds": True}, {"extra": "x"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                admission.observe(".", {"host": "archlinux", "timeoutSeconds": 20, **changed})

    def test_fixed_ssh_transport_and_bounded_result(self):
        config = SimpleNamespace(hosts={"archlinux": object()})
        value = {"schemaVersion": 1, "host": "archlinux", "state": "sudo-nopasswd-pacman"}
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())
        with mock.patch.object(admission.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(admission.ssh_transport, "connection_host",
                               return_value=SimpleNamespace(password=None)), \
             mock.patch.object(admission.ssh_transport, "build_ssh_argv",
                               return_value=["ssh", "archlinux"]) as argv, \
             mock.patch.object(admission.subprocess, "run", return_value=completed) as run:
            result = admission.observe(".", {"host": "archlinux", "timeoutSeconds": 20})
        self.assertTrue(result["noninteractivePacmanEligible"])
        self.assertIn("sudo", argv.call_args.kwargs["command"][2])
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)


if __name__ == "__main__":
    unittest.main()
