"""Fixed permission reset routes admit only immutable receipt bindings."""
import unittest
from unittest import mock

from agent_tools import android_vpn_permission_reset as reset
from agent_tools import mcp_server as server


REQUEST = {
    "correlationId": "11111111-1111-4111-8111-111111111111",
    "artifactId": "sha256-" + "a" * 64,
    "cliStageCorrelationId": "21111111-1111-4111-8111-111111111111",
    "openingReadbackCorrelationId": "31111111-1111-4111-8111-111111111111",
    "expectedBackupSha256": "b" * 64,
    "expectedOwner": "41111111-1111-4111-8111-111111111111",
    "expectedRevision": 1,
}


class AndroidPermissionResetRouteTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_start_exact_binding(self):
        with mock.patch.object(reset, "start", return_value={
            "ok": True, "state": "submitted", "correlationId": REQUEST["correlationId"],
            "identity": {"pid": 17, "startTicks": 123}, "replayAllowed": False,
        }) as call:
            result = server._vm_workflow_impl("android-vpn-permission-reset-start", dict(REQUEST))
        self.assertTrue(result["ok"])
        call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"], REQUEST["artifactId"],
            REQUEST["cliStageCorrelationId"], REQUEST["openingReadbackCorrelationId"],
            REQUEST["expectedBackupSha256"], REQUEST["expectedOwner"], REQUEST["expectedRevision"])

    def test_malformed_submitted_reply_is_not_promoted(self):
        valid = {"ok": True, "state": "submitted", "correlationId": REQUEST["correlationId"],
                 "identity": {"pid": 17, "startTicks": 123}, "replayAllowed": False}
        for reply in ({"ok": True, "state": "submitted"},
                      {**valid, "correlationId": REQUEST["expectedOwner"]},
                      {**valid, "replayAllowed": True},
                      {**valid, "identity": {"pid": True, "startTicks": 123}}):
            with self.subTest(reply=reply), mock.patch.object(reset, "start", return_value=reply) as call:
                result = server._vm_workflow_impl("android-vpn-permission-reset-start", dict(REQUEST))
            self.assertFalse(result["ok"])
            self.assertEqual(result["state"], "unknown")
            call.assert_called_once()

    def test_bad_bindings_never_dispatch(self):
        for key in REQUEST:
            values = (None, {}, [], "", "../foreign", True, -1)
            for value in values:
                with self.subTest(key=key, value=value), mock.patch.object(reset, "start") as call:
                    result = server._vm_workflow_impl("android-vpn-permission-reset-start", {**REQUEST, key: value})
                self.assertFalse(result["ok"])
                call.assert_not_called()
        for payload in ({**REQUEST, "command": "allow"}, {**REQUEST, "host": "foreign"}, {}):
            with mock.patch.object(reset, "start") as call:
                self.assertFalse(server._vm_workflow_impl("android-vpn-permission-reset-start", payload)["ok"])
            call.assert_not_called()

    def test_status_and_collect_use_only_original_correlation(self):
        for action in ("status", "collect"):
            with mock.patch.object(reset, action, return_value={"ok": False, "state": "unknown"}) as call:
                result = server._vm_workflow_impl("android-vpn-permission-reset-" + action,
                    {"correlationId": REQUEST["correlationId"]})
                self.assertEqual("unknown", result["state"])
                call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"])
                call.reset_mock()
                self.assertFalse(server._vm_workflow_impl("android-vpn-permission-reset-" + action,
                    dict(REQUEST))["ok"])
                call.assert_not_called()
