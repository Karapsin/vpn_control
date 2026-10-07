"""Exact immutable endpoint and readmission bindings at MCP boundary."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_endpoint_admission as helper
REQUEST = {"correlationId": "11111111-1111-4111-8111-111111111111", "readmissionCorrelationId": "21111111-1111-4111-8111-111111111111"}
class EndpointReadmissionRouteTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        p.start(); self.addCleanup(p.stop)
    def test_fixed_mount_collection_suppresses_private_path(self):
        request = {"correlationId": REQUEST["correlationId"], "diagnosticCorrelationId": REQUEST["readmissionCorrelationId"]}
        parent = server.REPO_ROOT / ".rag_index/android-endpoint-admission" / ("mount-diagnostic-" + request["correlationId"] + "-" + request["diagnosticCorrelationId"])
        receipt = {**helper._response("complete", request["correlationId"], diagnosticCorrelationId=request["diagnosticCorrelationId"], observationOnly=True),
                   "ok": True, "localPath": str(parent / "mount-diagnostic.json"), "sha256": "a" * 64, "bytes": 16511}
        action = "android-endpoint-mount-diagnostic-collect"
        with mock.patch.object(helper, "mount_diagnostic_collect", return_value=receipt) as call:
            result = server._vm_workflow_impl(action, request)
        self.assertTrue(result["ok"]); self.assertNotIn("localPath", result)
        call.assert_called_once_with(server.REPO_ROOT, request["correlationId"], request["diagnosticCorrelationId"])
        for changes in ({"localPath": "/foreign"}, {"bytes": True}, {"sha256": "foreign"}, {"rawSecret": "private"}, {"productMutationAllowed": True}):
            with mock.patch.object(helper, "mount_diagnostic_collect", return_value={**receipt, **changes}):
                result = server._vm_workflow_impl(action, request)
            self.assertFalse(result["ok"]); self.assertNotIn("localPath", result); self.assertNotIn("rawSecret", result)
        for bad in ({**request, "path": "/foreign"}, {**request, "diagnosticCorrelationId": request["correlationId"]}):
            with mock.patch.object(helper, "mount_diagnostic_collect") as call:
                self.assertFalse(server._vm_workflow_impl(action, bad)["ok"])
            call.assert_not_called()
    def test_exact_two_correlations_dispatch(self):
        for suffix, method, state in (("readmission", "cleanup_readmission", "ready"), ("readmitted", "cleanup_readmitted", "cleaned")):
            with mock.patch.object(helper, method, return_value=helper._response(state, REQUEST["correlationId"], **({"readmissionCorrelationId": REQUEST["readmissionCorrelationId"], "owner": REQUEST["correlationId"], "revision": 0, "cleanupOnly": True} if suffix == "readmission" else {"result": {"state": "cleaned", "correlationId": REQUEST["correlationId"]}}))) as call:
                r = server._vm_workflow_impl("android-endpoint-cleanup-" + suffix, dict(REQUEST))
            self.assertTrue(r["ok"]); self.assertFalse(r["productAction"]); self.assertFalse(r["replayAllowed"])
            call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"], REQUEST["readmissionCorrelationId"])

    def test_readmitted_terminal_status_is_observation_only(self):
        proof = {"state": "cleaned", "reason": None, "correlationId": REQUEST["correlationId"],
                 "device": {"api": 29, "avd": "owned-api29", "uid": "2000"}, "packageSha256": "a" * 64,
                 "caSha256": "b" * 64, "owner": REQUEST["correlationId"], "revision": 0, "reversePorts": []}
        receipt = helper._response("cleaned", REQUEST["correlationId"],
                                  readmissionCorrelationId=REQUEST["readmissionCorrelationId"], observationOnly=True, result=proof)
        action = "android-endpoint-cleanup-readmitted-status"
        with mock.patch.object(helper, "cleanup_readmitted_status", return_value=receipt) as call:
            result = server._vm_workflow_impl(action, dict(REQUEST))
        call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"], REQUEST["readmissionCorrelationId"])
        self.assertTrue(result["ok"]); self.assertEqual("cleaned", result["state"])
        self.assertTrue(result["observationOnly"]); self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"]); self.assertNotIn("result", result)
        for changes in ({"correlationId": "foreign"}, {"revision": True}, {"reversePorts": [18080]},
                        {"rawSecret": "private"}, {"device": {"api": True, "uid": "2000", "avd": "owned"}},
                        {"packageSha256": []}):
            with mock.patch.object(helper, "cleanup_readmitted_status", return_value={**receipt, "result": {**proof, **changes}}):
                rejected = server._vm_workflow_impl(action, dict(REQUEST))
            self.assertFalse(rejected["ok"]); self.assertEqual("unknown", rejected["state"])
            self.assertNotIn("rawSecret", rejected); self.assertNotIn("result", rejected)
        for payload in ({}, {**REQUEST, "host": "foreign"}, {**REQUEST, "readmissionCorrelationId": REQUEST["correlationId"]}):
            with mock.patch.object(helper, "cleanup_readmitted_status") as call:
                self.assertFalse(server._vm_workflow_impl(action, payload)["ok"])
            call.assert_not_called()
        unknown = helper._response("unknown", REQUEST["correlationId"], "readmission_owner_changed",
                                   readmissionCorrelationId=REQUEST["readmissionCorrelationId"], observationOnly=True)
        with mock.patch.object(helper, "cleanup_readmitted_status", return_value=unknown):
            self.assertEqual("readmission_owner_changed", server._vm_workflow_impl(action, dict(REQUEST))["reason"])
    def test_bad_binding_never_dispatches(self):
        cases = [{}, {**REQUEST, "host": "foreign"}, {**REQUEST, "readmissionCorrelationId": REQUEST["correlationId"]}]
        for key in REQUEST:
            cases.extend({**REQUEST, key: value} for value in (None, [], {}, True, "foreign"))
        for suffix, method in (("readmission", "cleanup_readmission"), ("readmitted", "cleanup_readmitted")):
            for value in cases:
                with mock.patch.object(helper, method) as call:
                    r = server._vm_workflow_impl("android-endpoint-cleanup-"+suffix, value)
                self.assertFalse(r["ok"]); call.assert_not_called()
    def test_foreign_receipt_not_admitted(self):
        with mock.patch.object(helper, "cleanup_readmission", return_value={"ok": True, "state": "ready", "correlationId": "foreign", "productAction": True}):
            r = server._vm_workflow_impl("android-endpoint-cleanup-readmission", dict(REQUEST))
        self.assertFalse(r["ok"]); self.assertFalse(r["productAction"])

    def test_forged_second_binding_or_raw_fields_fail_closed(self):
        base = helper._response("ready", REQUEST["correlationId"], readmissionCorrelationId=REQUEST["readmissionCorrelationId"], owner=REQUEST["correlationId"], revision=0, cleanupOnly=True)
        for changes in ({"readmissionCorrelationId": "foreign"}, {"cleanupOnly": False}, {"rawSecret": "foreign"}, {"revision": True}, {"owner": []}):
            with mock.patch.object(helper, "cleanup_readmission", return_value={**base, **changes}):
                r = server._vm_workflow_impl("android-endpoint-cleanup-readmission", dict(REQUEST))
            self.assertFalse(r["ok"]); self.assertNotIn("rawSecret", r)
            self.assertEqual(REQUEST["readmissionCorrelationId"], r["readmissionCorrelationId"])

    def test_status_projects_observation_only(self):
        receipt = helper._response("partial", REQUEST["correlationId"], "readmission_receipt_absent", readmissionCorrelationId=REQUEST["readmissionCorrelationId"], observationOnly=True, freshGuardVerified=True, receiptPresent=False)
        with mock.patch.object(helper,"cleanup_readmission_status",return_value=receipt) as call:
            r=server._vm_workflow_impl("android-endpoint-cleanup-readmission-status",dict(REQUEST))
        self.assertFalse(r["ok"]); self.assertTrue(r["freshGuardVerified"]); self.assertFalse(r["nativeActionAllowed"])
        call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"], REQUEST["readmissionCorrelationId"])
        for changes in ({"rawSecret":"foreign"},{"readmissionCorrelationId":"foreign"},{"observationOnly":False},{"receiptPresent":True},{"reason":[]},{"state":[]},{"state":{}},{"reason":"readmission_owner_changed"}):
            with mock.patch.object(helper,"cleanup_readmission_status",return_value={**receipt,**changes}):
                r=server._vm_workflow_impl("android-endpoint-cleanup-readmission-status",dict(REQUEST))
            self.assertEqual("unknown",r["state"]);self.assertNotIn("rawSecret",r);self.assertNotIn("freshGuardVerified",r)

    def test_mount_diagnostic_finite_projection_no_admission(self):
        diagnostic={"targetEntryCount":1,"entries":[{"rootRelation":"target-exact","filesystem":"ext4"}],"ownCaRelation":"absent","openingTargetMountRecorded":False}
        receipt=helper._response("partial",REQUEST["correlationId"],"readmission_target_mount_observed",readmissionCorrelationId=REQUEST["readmissionCorrelationId"],observationOnly=True,mountDiagnostic=diagnostic)
        with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value=receipt) as call:
            r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
        self.assertFalse(r["ok"]);self.assertFalse(r["nativeActionAllowed"]);self.assertEqual(diagnostic,r["mountDiagnostic"])
        call.assert_called_once_with(server.REPO_ROOT,REQUEST["correlationId"],REQUEST["readmissionCorrelationId"])
        for changes in ({"ownCaRelation":[]},{"entries":[{"rootRelation":[],"filesystem":"ext4"}]},{"targetEntryCount":True},{"openingTargetMountRecorded":True},{"rawPath":"foreign"}):
            with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value={**receipt,"mountDiagnostic":{**diagnostic,**changes}}):
                r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
            self.assertEqual("unknown",r["state"]);self.assertNotIn("mountDiagnostic",r)

    def test_mount_diagnostic_preserves_only_finite_unknown_reason(self):
        receipt=helper._response("unknown",REQUEST["correlationId"],"readmission_owner_changed",readmissionCorrelationId=REQUEST["readmissionCorrelationId"],observationOnly=True)
        with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value=receipt):
            r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
        self.assertEqual("readmission_owner_changed",r["reason"])
        self.assertFalse(r["nativeActionAllowed"])
        for changes in ({"reason":"raw-secret"},{"productMutationAllowed":True},{"readmissionCorrelationId":"foreign"},{"rawSecret":"foreign"}):
            with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value={**receipt,**changes}):
                r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
            self.assertEqual("cleanup-mount-diagnostic-unavailable",r["reason"])
            self.assertNotIn("rawSecret",r)

    def test_mount_command_diagnostic_finite_unknown_projection(self):
        diagnostic={"phase":"target-ca","outcome":"nonzero","stderrClass":"permission"}
        receipt=helper._response("unknown",REQUEST["correlationId"],"command_failed",readmissionCorrelationId=REQUEST["readmissionCorrelationId"],observationOnly=True,commandDiagnostic=diagnostic)
        with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value=receipt):
            r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
        self.assertEqual(diagnostic,r.get("commandDiagnostic"))
        self.assertEqual("command_failed",r["reason"])
        self.assertFalse(r["nativeActionAllowed"])
        for value in (None, [], {**diagnostic,"stderr":"private"}, {**diagnostic,"phase":[]}, {**diagnostic,"outcome":"private"}, {**diagnostic,"stderrClass":True}):
            with mock.patch.object(helper,"cleanup_mount_diagnostic",return_value={**receipt,"commandDiagnostic":value}):
                r=server._vm_workflow_impl("android-endpoint-cleanup-mount-diagnostic",dict(REQUEST))
            self.assertNotIn("commandDiagnostic",r)
            self.assertEqual("cleanup-mount-diagnostic-unavailable",r["reason"])
