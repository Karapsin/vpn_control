"""Actual Android fixture MCP routes preserve optional clean-source ownership."""
from __future__ import annotations

import copy
import unittest
from unittest import mock

from agent_tools import android_native_fixture_lifecycle as lifecycle
from agent_tools import mcp_server as server

REQUEST = {
    "host": "archlinux",
    "device": "api35",
    "campaignId": "11111111-1111-4111-8111-111111111111",
    "planPath": "/private/android-plan.json",
    "certificatePath": "/private/fixture-ca.pem",
    "privateKeyPath": "/private/fixture-key.pem",
}
SOURCE_ROOT = "/private/clean-source"


class AndroidCleanSourceRouteTests(unittest.TestCase):
    def setUp(self):
        boot = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        boot.start()
        self.addCleanup(boot.stop)

    def test_start_forwards_clean_source_without_changing_original_fields(self):
        with mock.patch.object(lifecycle, "start", return_value={"ok": True, "state": "running"}) as dispatch:
            inputs = {**REQUEST, "sourceRoot": SOURCE_ROOT}
            original = copy.deepcopy(inputs)
            result = server._vm_workflow_impl("android-native-fixture-start", inputs)
        self.assertTrue(result["ok"])
        dispatch.assert_called_once_with(server.REPO_ROOT, REQUEST["host"], REQUEST["device"], REQUEST["campaignId"],
                                         REQUEST["planPath"], REQUEST["certificatePath"], REQUEST["privateKeyPath"],
                                         source_root=SOURCE_ROOT)
        self.assertEqual(original, inputs)

    def test_legacy_start_has_no_source_root_keyword(self):
        with mock.patch.object(lifecycle, "start", return_value={"ok": True, "state": "running"}) as dispatch:
            result = server._vm_workflow_impl("android-native-fixture-start", dict(REQUEST))
        self.assertTrue(result["ok"])
        dispatch.assert_called_once_with(server.REPO_ROOT, REQUEST["host"], REQUEST["device"], REQUEST["campaignId"],
                                         REQUEST["planPath"], REQUEST["certificatePath"], REQUEST["privateKeyPath"])

    def test_source_root_requires_a_bounded_absolute_nul_free_string_without_dispatch(self):
        invalid = ("relative/source", "", "/private/source\0foreign", None, 3, {}, "/" + "x" * 4096)
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(lifecycle, "start") as dispatch:
                result = server._vm_workflow_impl("android-native-fixture-start", {**REQUEST, "sourceRoot": value})
            self.assertFalse(result["ok"])
            dispatch.assert_not_called()

    def test_non_start_actions_reject_source_root_without_lifecycle_method(self):
        methods = {"status": lifecycle.status, "stop": lifecycle.stop, "collect": lifecycle.collect}
        for action, method in methods.items():
            with self.subTest(action=action), mock.patch.object(lifecycle, method.__name__) as dispatch:
                result = server._vm_workflow_impl("android-native-fixture-" + action,
                                                  {"campaignId": REQUEST["campaignId"], "sourceRoot": SOURCE_ROOT})
            self.assertFalse(result["ok"])
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()

class AndroidEndpointCleanSourceRouteTests(unittest.TestCase):
    request = {
        "host": "archlinux", "device": "api35",
        "correlationId": "21111111-1111-4111-8111-111111111111",
        "campaignId": "31111111-1111-4111-8111-111111111111",
        "sourceSha": "a" * 40,
        "targetArtifactId": "sha256-" + "b" * 64,
        "caArtifactId": "sha256-" + "c" * 64,
        "backupCorrelationId": "41111111-1111-4111-8111-111111111111",
        "expectedOwner": "vpn-control", "expectedRevision": 1,
        "expectedBackupSha256": "d" * 64,
    }

    def setUp(self):
        boot = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        boot.start()
        self.addCleanup(boot.stop)
        from agent_tools import android_endpoint_admission as admission
        self.admission = admission

    def test_endpoint_start_forwards_optional_clean_source_root(self):
        source_root = "/private/android-clean-source"
        with mock.patch.object(self.admission, "start", return_value={"ok": True, "state": "ready"}) as dispatch:
            inputs = {**self.request, "sourceRoot": source_root}
            original = copy.deepcopy(inputs)
            result = server._vm_workflow_impl("android-endpoint-admission-start", inputs)
        self.assertTrue(result["ok"])
        dispatch.assert_called_once_with(server.REPO_ROOT, self.request["host"], self.request["device"],
                                         self.request["correlationId"], self.request["campaignId"],
                                         self.request["sourceSha"], self.request["targetArtifactId"],
                                         self.request["caArtifactId"], self.request["backupCorrelationId"],
                                         self.request["expectedOwner"], self.request["expectedRevision"],
                                         self.request["expectedBackupSha256"], source_root=source_root)
        self.assertEqual(original, inputs)

    def test_endpoint_legacy_start_preserves_call_shape(self):
        with mock.patch.object(self.admission, "start", return_value={"ok": True, "state": "ready"}) as dispatch:
            result = server._vm_workflow_impl("android-endpoint-admission-start", dict(self.request))
        self.assertTrue(result["ok"])
        dispatch.assert_called_once_with(server.REPO_ROOT, self.request["host"], self.request["device"],
                                         self.request["correlationId"], self.request["campaignId"],
                                         self.request["sourceSha"], self.request["targetArtifactId"],
                                         self.request["caArtifactId"], self.request["backupCorrelationId"],
                                         self.request["expectedOwner"], self.request["expectedRevision"],
                                         self.request["expectedBackupSha256"])

    def test_endpoint_source_root_is_start_only_bounded_absolute_and_nul_free(self):
        invalid = ("", "relative/source", "/private/source\0foreign", None, 3, {}, "/" + "x" * 4096)
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(self.admission, "start") as dispatch:
                result = server._vm_workflow_impl("android-endpoint-admission-start", {**self.request, "sourceRoot": value})
            self.assertFalse(result["ok"])
            dispatch.assert_not_called()
        for action, method in (("status", "status"), ("cleanup", "cleanup")):
            with self.subTest(action=action), mock.patch.object(self.admission, method) as dispatch:
                result = server._vm_workflow_impl("android-endpoint-admission-" + action,
                                                  {"correlationId": self.request["correlationId"], "sourceRoot": "/private/source"})
            self.assertFalse(result["ok"])
            dispatch.assert_not_called()
