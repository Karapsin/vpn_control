"""Fixed runtime routes reject unbound input before native dispatch."""
import unittest
from unittest import mock

from agent_tools import android_runtime_acceptance as runtime
from agent_tools import mcp_server as server


REQUEST = {
    "correlationId": "11111111-1111-4111-8111-111111111111",
    "endpointCorrelationId": "21111111-1111-4111-8111-111111111111",
    "cliStageCorrelationId": "31111111-1111-4111-8111-111111111111",
}


class AndroidRuntimeRouteTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_start_binds_only_three_correlations(self):
        with mock.patch.object(runtime, "start", return_value=runtime._reply("submitted", REQUEST["correlationId"], identity={"pid": 17, "startTicks": 123})) as call:
            result = server._vm_workflow_impl("android-runtime-acceptance-start", dict(REQUEST))
        self.assertTrue(result["ok"])
        call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"],
            REQUEST["endpointCorrelationId"], REQUEST["cliStageCorrelationId"])

    def test_invalid_binding_rejects_without_native_call(self):
        for key in REQUEST:
            for invalid in (None, {}, [], 5, "", "../foreign", "x" * 1000):
                with self.subTest(key=key, invalid=invalid), mock.patch.object(runtime, "start") as call:
                    result = server._vm_workflow_impl("android-runtime-acceptance-start", {**REQUEST, key: invalid})
                self.assertFalse(result["ok"])
                call.assert_not_called()
        for payload in ({**REQUEST, "command": "off"}, {"correlationId": REQUEST["correlationId"]}):
            with mock.patch.object(runtime, "start") as call:
                self.assertFalse(server._vm_workflow_impl("android-runtime-acceptance-start", payload)["ok"])
            call.assert_not_called()

    def test_observers_have_only_original_correlation(self):
        for action in ("status", "collect"):
            with self.subTest(action=action), mock.patch.object(runtime, action,
                    return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as call:
                result = server._vm_workflow_impl("android-runtime-acceptance-" + action,
                    {"correlationId": REQUEST["correlationId"]})
                self.assertFalse(result["ok"])
                self.assertFalse(result["replayAllowed"])
                call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"])
                call.reset_mock()
                rejected = server._vm_workflow_impl("android-runtime-acceptance-" + action, dict(REQUEST))
                self.assertFalse(rejected["ok"])
                call.assert_not_called()
