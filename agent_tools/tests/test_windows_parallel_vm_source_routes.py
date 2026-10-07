"""Fixed MCP/CLI source inventory ingress; no SSH or VM effects."""
import copy
import os
import unittest
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import windows_parallel_vm_source_inventory as inventory


@unittest.skipUnless(hasattr(os, "getuid"), "Arch source observer requires POSIX local ownership")
class WindowsParallelSourceRoutes(unittest.TestCase):
    def setUp(self):
        boot = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        boot.start()
        self.addCleanup(boot.stop)
        self.request = {"host": "archlinux", "timeoutSeconds": 240}
        # A finite refused native observation, with separately retained receipt
        # metadata. The actual report validator remains active in every test.
        self.response = {"schemaVersion": 1, "host": "archlinux", "state": "unknown",
                         "sourceState": "unknown", "nativeActionAllowed": False,
                         "cloneAdmitted": False, "reason": "source-held",
                         "toolSources": {str(server.REPO_ROOT / "agent_tools" / name):
                             {"sha256": "a" * 64, "generation": [1, 2, 0o100600, os.getuid(), os.getgid(), 1, 100, 1, 1]}
                             for name in ("windows_parallel_vm_source_inventory.py", "ssh_transport.py",
                                          "windows_credential_probe_ssh.py", "windows_cp117_bound_absence_completion.py",
                                          "windows_vm_virt_firmware_install.py")}, "remoteProgramSha256": "a" * 64,
                         "configuredTransportAuthority": "b" * 64,
                         "evidenceLeaf": "windows-parallel-vm-source-read-" + "c" * 32,
                         "rawReceipt": {"sha256": "d" * 64, "generation": [1, 2, 0o100600, os.getuid(), os.getgid(), 1, 100, 1, 1]},
                         "transport": {"pid": 123, "stdoutEof": True, "exitCode": 0,
                                       "reason": None, "clientTerminatedForBound": False}}

    def invoke(self, request=None):
        return server._vm_workflow_impl("windows-parallel-vm-source-inventory",
                                        self.request if request is None else request)

    def test_fixed_request_preserves_original_refusal_and_receipt(self):
        original = copy.deepcopy(self.request)
        with mock.patch.object(inventory, "observe", return_value=self.response) as call:
            result = self.invoke()
        call.assert_called_once_with(server.REPO_ROOT, host="archlinux", timeout_seconds=240)
        self.assertEqual(original, self.request)
        self.assertEqual(result["reason"], "source-held")
        self.assertEqual(result["rawReceipt"], self.response["rawReceipt"])
        self.assertFalse(result["ok"])
        self.assertIs(result["nativeActionAllowed"], False)
        self.assertIs(result["cloneAdmitted"], False)
        self.assertIs(result["productAction"], False)

    def test_selectors_extra_fields_and_inexact_timeouts_never_reach_observer(self):
        requests = [{**self.request, "host": "other"}, {**self.request, "source": "/tmp/disk"},
                    {**self.request, "command": "id"}, {**self.request, "password": "fixture"},
                    {"host": "archlinux"}]
        requests += [{**self.request, "timeoutSeconds": value}
                     for value in (True, 240.0, "240", 29, 301)]
        with mock.patch.object(inventory, "observe") as call:
            for request in requests:
                with self.subTest(request=request):
                    self.assertFalse(self.invoke(request)["ok"])
        call.assert_not_called()

    def test_malformed_promotion_and_missing_receipt_refuse(self):
        malformed = []
        for key, value in (("schemaVersion", True), ("schemaVersion", 1.0),
                           ("nativeActionAllowed", True), ("cloneAdmitted", True),
                           ("foreignGrant", True), ("state", "observed")):
            malformed.append({**self.response, key: value})
        malformed.append({key: value for key, value in self.response.items() if key != "rawReceipt"})
        for response in malformed:
            with self.subTest(response=response), mock.patch.object(inventory, "observe", return_value=response):
                result = self.invoke()
                self.assertFalse(result["ok"])
                self.assertEqual(result["state"], "unknown")
                self.assertIs(result["cloneAdmitted"], False)
                self.assertIs(result["nativeActionAllowed"], False)

    def test_observer_error_remains_unknown_without_clone_authority(self):
        with mock.patch.object(inventory, "observe", side_effect=ValueError("source-changed")):
            result = self.invoke()
        self.assertFalse(result["ok"])
        self.assertEqual(result["sourceState"], "unknown")
        self.assertIs(result["cloneAdmitted"], False)


    def test_measured_connection_timeout_code_is_reported_without_exception_text(self):
        from agent_tools.ssh_transport import SshConfigError
        for message, expected in (("ssh-connect-timeout-out-of-contract", "ssh-connect-timeout-out-of-contract"),
                                  ("private diagnostic fixture", "windows-parallel-source-unavailable")):
            with self.subTest(message=message), mock.patch.object(
                    inventory, "observe", side_effect=SshConfigError(message)):
                result = self.invoke()
            self.assertEqual(result["reason"], expected)
            self.assertFalse(result["ok"])
            self.assertIs(result["nativeActionAllowed"], False)
            self.assertIs(result["cloneAdmitted"], False)

    def test_metadata_rejects_arbitrary_fields_and_inexact_pins(self):
        cases = [("rawReceipt", {"privateFixture": "unvalidated-private-value", "generation": [True]*9, "sha256": "bad"}),
                 ("transport", {"privateFixture": "unvalidated-private-value"}),
                 ("toolSources", {}), ("evidenceLeaf", "../private"),
                 ("remoteProgramSha256", "bad"), ("configuredTransportAuthority", True)]
        for key, value in cases:
            with self.subTest(key=key), mock.patch.object(inventory, "observe", return_value={**self.response, key: value}):
                result = self.invoke()
            self.assertFalse(result["ok"])
            self.assertNotIn(key, result)
            self.assertNotIn("unvalidated-private-value", str(result))


if __name__ == "__main__":
    unittest.main()
