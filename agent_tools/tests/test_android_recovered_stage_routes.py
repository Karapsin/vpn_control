"""Recovered-stage collection must never imply installer/runtime admission."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_recovered_endpoint_stage_cleanup as helper
from agent_tools import android_endpoint_admission as endpoint

REQUEST = {key: f"{index}1111111-1111-4111-8111-111111111111" for index, key in enumerate(
    ("correlationId", "historicalCorrelationId", "recoveryCorrelationId", "stageCorrelationId"), 1)}
ACTION = "android-recovered-endpoint-stage-collect"

class RecoveredStageRouteTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patch.start(); self.addCleanup(patch.stop)

    def receipt(self):
        return endpoint._response("cleaned", REQUEST["correlationId"],
            recoveryCorrelationId=REQUEST["recoveryCorrelationId"],
            stageCorrelationId=REQUEST["stageCorrelationId"], stageOnly=True,
            observationOnly=False, device={"uid": "2000", "api": 29, "avd": "vpn-control-parity116-api29"})

    def test_exact_collection_projects_component_only(self):
        with mock.patch.object(helper, "collect", return_value=self.receipt()) as call:
            result = server._vm_workflow_impl(ACTION, dict(REQUEST))
        self.assertTrue(result["ok"])
        self.assertEqual("cleaned", result["state"])
        self.assertEqual("unknown", result["originalOutcome"])
        self.assertIs(result["observationOnly"], False)
        for key in ("replayAllowed", "nativeActionAllowed", "productAction", "installerTargetAdmitted"):
            self.assertIs(result[key], False)
        call.assert_called_once_with(server.REPO_ROOT, *REQUEST.values())

    def test_invalid_bindings_never_dispatch(self):
        cases = [{}, {**REQUEST, "path": "/foreign"},
                 {**REQUEST, "stageCorrelationId": REQUEST["correlationId"]}]
        for key in REQUEST:
            cases += [{**REQUEST, key: value} for value in (None, [], {}, True, "foreign")]
        for request in cases:
            with mock.patch.object(helper, "collect") as call:
                self.assertFalse(server._vm_workflow_impl(ACTION, request)["ok"])
            call.assert_not_called()

    def test_forged_receipts_cannot_publish_cleaned(self):
        cases = [{"state": "ready"}, {"ok": 1}, {"reason": "foreign"},
                 {"correlationId": "foreign"}, {"stageCorrelationId": "foreign"},
                 {"recoveryCorrelationId": "foreign"}, {"stageOnly": False},
                 {"productMutationAllowed": True}, {"installerTargetAdmitted": True},
                 {"replayAllowed": True}, {"rawSecret": "private"},
                 {"device": {"uid": "0", "api": 29, "avd": "vpn-control-parity116-api29"}},
                 {"device": {"uid": "2000", "api": True, "avd": "vpn-control-parity116-api29"}}]
        for changes in cases:
            with mock.patch.object(helper, "collect", return_value={**self.receipt(), **changes}):
                result = server._vm_workflow_impl(ACTION, dict(REQUEST))
            self.assertFalse(result["ok"]); self.assertEqual("unknown", result["state"])
            self.assertNotIn("rawSecret", result)

    def test_adapter_failure_is_unknown(self):
        with mock.patch.object(helper, "collect", side_effect=ValueError("private")):
            result = server._vm_workflow_impl(ACTION, dict(REQUEST))
        self.assertFalse(result["ok"])
        self.assertNotIn("private", str(result))
