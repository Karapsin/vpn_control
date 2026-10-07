"""Fixed permission reset routes admit only immutable receipt bindings."""
import unittest
from unittest import mock

from agent_tools import android_consent_grant_acceptance as reset
from agent_tools import android_obsolete_consent_denial as denial
from agent_tools import mcp_server as server


REQUEST = {
    "host": "archlinux",
    "device": "api35",
    "correlationId": "11111111-1111-4111-8111-111111111111",
    "artifactId": "sha256-" + "a" * 64,
    "cliStageCorrelationId": "21111111-1111-4111-8111-111111111111",
    "openingReadbackCorrelationId": "31111111-1111-4111-8111-111111111111",
    "expectedBackupSha256": "b" * 64,
    "expectedOwner": "41111111-1111-4111-8111-111111111111",
    "expectedRevision": 1,
}


class AndroidConsentGrantRouteTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_obsolete_denial_collection_preserves_unknown_and_exact_proof(self):
        ident = REQUEST['correlationId']
        proof = dict(schema=1, denialId=ident, closureId=REQUEST['cliStageCorrelationId'],
            originalCorrelationId=REQUEST['openingReadbackCorrelationId'],
            observationId=REQUEST['expectedOwner'], intentSha256='a'*64,
            tapSha256='b'*64, originalOutcome='unknown', grantObserved=False,
            permissionGranted=False, runtimeStarted=False, uiAbsent=True,
            scope='obsolete-dialog-denial')
        receipt = denial._reply(ident, 'complete', proof=proof,
            remoteClaimReleased=True, claimsReleased=True)
        action = 'android-obsolete-consent-denial-collect'
        with mock.patch.object(denial, 'collect', return_value=receipt) as call:
            result = server._vm_workflow_impl(action, {'denialId':ident})
        self.assertTrue(result['ok'])
        self.assertEqual(result['originalOutcome'], 'unknown')
        self.assertFalse(result['grantObserved'])
        call.assert_called_once_with(server.REPO_ROOT, ident)
        for changes in ({'rawSecret':'secret'}, {'claimsReleased':False},
                {'proof':{**proof,'schema':True}}, {'proof':{**proof,'permissionGranted':True}},
                {'proof':{**proof,'originalCorrelationId':ident}}, {'proof':{**proof,'rawSecret':'secret'}},
                {'proof':{**proof,'intentSha256':'foreign'}}, {'denialId':'foreign'},
                {'originalOutcome':'complete'}):
            with mock.patch.object(denial,'collect',return_value={**receipt,**changes}):
                result=server._vm_workflow_impl(action,{'denialId':ident})
            self.assertFalse(result['ok'])
            self.assertNotIn('proof',result)
            self.assertNotIn('rawSecret',result)
        for request in ({'denialId':'../foreign'},{'denialId':ident,'command':'tap'},{}):
            with mock.patch.object(denial,'collect') as call:
                self.assertFalse(server._vm_workflow_impl(action,request)['ok'])
            call.assert_not_called()
        with mock.patch.object(denial,'collect',side_effect=ValueError('private secret')):
            result=server._vm_workflow_impl(action,{'denialId':ident})
        self.assertFalse(result['ok']);self.assertNotIn('secret',str(result))

    def test_prompt_collection_fixed_receipt_and_no_path_projection(self):
        observation = "51111111-1111-4111-8111-111111111111"
        request = {"correlationId": REQUEST["correlationId"], "observationId": observation}
        parent = server.REPO_ROOT / ".rag_index/android-consent-grant-acceptance" / ("prompt-" + request["correlationId"] + "-" + observation)
        receipt = reset._reply(request["correlationId"], "complete", observationId=observation,
            localPaths={name: str(parent / name) for name in reset._PROMPT_FILES},
            nativeActionAllowed=False, productAction=False, claimsReleased=False)
        with mock.patch.object(reset, "prompt_collect", return_value=receipt) as call:
            result = server._vm_workflow_impl("android-consent-grant-prompt-collect", request)
        self.assertTrue(result["ok"])
        self.assertNotIn("localPaths", result)
        call.assert_called_once_with(server.REPO_ROOT, request["correlationId"], observation)
        for bad in ({**receipt, "rawSecret": "secret"}, {**receipt, "localPaths": {**receipt["localPaths"], "ui.xml": "/foreign"}}, {**receipt, "claimsReleased": True}):
            with mock.patch.object(reset, "prompt_collect", return_value=bad):
                result = server._vm_workflow_impl("android-consent-grant-prompt-collect", request)
            self.assertFalse(result["ok"])
            self.assertNotIn("localPaths", result)
            self.assertNotIn("rawSecret", result)
        for bad in ({**request, "path": "/foreign"}, {**request, "observationId": "../foreign"}):
            with mock.patch.object(reset, "prompt_collect") as call:
                self.assertFalse(server._vm_workflow_impl("android-consent-grant-prompt-collect", bad)["ok"])
            call.assert_not_called()

    def test_start_exact_binding(self):
        with mock.patch.object(reset, "start", return_value=reset._reply(REQUEST["correlationId"], "submitted", identity={"pid": 17, "startTicks": 123})) as call:
            result = server._vm_workflow_impl("android-consent-grant-acceptance-start", dict(REQUEST))
        self.assertTrue(result["ok"])
        call.assert_called_once_with(server.REPO_ROOT, REQUEST["host"], REQUEST["device"], REQUEST["correlationId"], REQUEST["artifactId"],
            REQUEST["cliStageCorrelationId"], REQUEST["openingReadbackCorrelationId"],
            REQUEST["expectedBackupSha256"], REQUEST["expectedOwner"], REQUEST["expectedRevision"])

    def test_bad_bindings_never_dispatch(self):
        for key in REQUEST:
            values = (None, {}, [], "", "../foreign", True, -1)
            for value in values:
                with self.subTest(key=key, value=value), mock.patch.object(reset, "start") as call:
                    result = server._vm_workflow_impl("android-consent-grant-acceptance-start", {**REQUEST, key: value})
                self.assertFalse(result["ok"])
                call.assert_not_called()
        for payload in ({**REQUEST, "command": "allow"}, {**REQUEST, "host": "foreign"}, {}):
            with mock.patch.object(reset, "start") as call:
                self.assertFalse(server._vm_workflow_impl("android-consent-grant-acceptance-start", payload)["ok"])
            call.assert_not_called()

    def test_status_and_collect_use_only_original_correlation(self):
        for action in ("status", "collect"):
            with mock.patch.object(reset, action, return_value={"ok": False, "state": "unknown"}) as call:
                result = server._vm_workflow_impl("android-consent-grant-acceptance-" + action,
                    {"correlationId": REQUEST["correlationId"]})
                self.assertEqual("unknown", result["state"])
                call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"])
                call.reset_mock()
                self.assertFalse(server._vm_workflow_impl("android-consent-grant-acceptance-" + action,
                    dict(REQUEST))["ok"])
                call.assert_not_called()

    def test_diagnostic_exact_original_only_and_bounded_output(self):
        checks = {key: True for key in reset._DIAGNOSTIC_CHECKS}
        facts = dict(configuredMode="vpn",runtimeObservation="stopped",sourceMode="subscription",subscriptionBinding="empty",locationShape="array",locationCount=0,locationCountTruncated=False,operationShape="array",operationCount=0,operationCountTruncated=False,operationsTerminal=True,selectedFieldPresent=True,activeFieldPresent=True)
        receipt = reset._reply(REQUEST["correlationId"], "diagnosed", nativeActionAllowed=False,productAction=False,historicalReason="baseline_not_empty_off",observationClass="fresh-current-baseline",checks=checks,facts=facts)
        with mock.patch.object(reset, "diagnose", return_value=receipt) as call:
            result = server._vm_workflow_impl("android-consent-grant-acceptance-diagnose", {"correlationId": REQUEST["correlationId"]})
        self.assertTrue(result["ok"]); call.assert_called_once_with(server.REPO_ROOT, REQUEST["correlationId"])
        for forged in ({**receipt,"rawSecret":"foreign"}, {**receipt,"facts":{**facts,"sourceMode":[]}}, {**receipt,"checks":{**checks,"vpnMode":1}}, {**receipt,"correlationId":"foreign"}):
            with mock.patch.object(reset,"diagnose",return_value=forged):
                result=server._vm_workflow_impl("android-consent-grant-acceptance-diagnose",{"correlationId":REQUEST["correlationId"]})
            self.assertFalse(result["ok"]); self.assertNotIn("rawSecret",result); self.assertNotIn("facts",result)
        with mock.patch.object(reset,"diagnose") as call:
            self.assertFalse(server._vm_workflow_impl("android-consent-grant-acceptance-diagnose",dict(REQUEST))["ok"])
        call.assert_not_called()

    def test_reconcile_proves_no_grant_and_exact_claim_closure(self):
        proof={key:True for key in reset._NO_EFFECT_PROOF}
        proof.update(historicalSourceSettingsAvailable=False,retainedBindingsSha256="a"*64,currentSnapshotSha256="b"*64)
        receipt=reset._reply(REQUEST["correlationId"],"closed",nativeActionAllowed=False,productAction=False,proof=proof,claimsReleased=True,originalOutcome="unknown",grantObserved=False)
        with mock.patch.object(reset,"reconcile",return_value=receipt) as call:
            r=server._vm_workflow_impl("android-consent-grant-acceptance-reconcile",{"correlationId":REQUEST["correlationId"]})
        self.assertTrue(r["ok"]);self.assertFalse(r["grantObserved"])
        call.assert_called_once_with(server.REPO_ROOT,REQUEST["correlationId"])
        for changes in ({"grantObserved":True},{"originalOutcome":"complete"},{"correlationId":"foreign"},{"rawSecret":"foreign"},{"proof":{**proof,"workerTerminal":False}},{"proof":{**proof,"historicalSourceSettingsAvailable":1}}):
            with mock.patch.object(reset,"reconcile",return_value={**receipt,**changes}):
                r=server._vm_workflow_impl("android-consent-grant-acceptance-reconcile",{"correlationId":REQUEST["correlationId"]})
            self.assertFalse(r["ok"]);self.assertNotIn("rawSecret",r);self.assertNotIn("proof",r)
        with mock.patch.object(reset,"reconcile") as call:
            self.assertFalse(server._vm_workflow_impl("android-consent-grant-acceptance-reconcile",dict(REQUEST))["ok"])
        call.assert_not_called()

    def test_reconciliation_observers_exact_bounded_no_closure_projection(self):
        records=dict(workerState="terminal",grantRecords="absent",baselineRecord="absent",remoteMarker="absent",remoteClaim="owned",lockState="free")
        receipt=reset._reply(REQUEST["correlationId"],"observed",nativeActionAllowed=False,productAction=False,records=records,localMarker="absent",localClaims=dict(shared="owned",document="owned"),currentProof="not-probed")
        for suffix,method in (("status","reconcile_status"),("diagnose","reconcile_diagnose")):
            with mock.patch.object(reset,method,return_value=receipt) as call:
                r=server._vm_workflow_impl("android-consent-grant-acceptance-reconcile-"+suffix,{"correlationId":REQUEST["correlationId"]})
            self.assertTrue(r["ok"]);self.assertFalse(r["nativeActionAllowed"]);self.assertNotIn("claimsReleased",r)
            call.assert_called_once_with(server.REPO_ROOT,REQUEST["correlationId"])
            for bad in (None,[],{**receipt,"rawSecret":"foreign"},{**receipt,"records":{**records,"workerState":[]}},{**receipt,"historicalSourceSettings":None},{**receipt,"correlationId":"foreign"}):
                with mock.patch.object(reset,method,return_value=bad):
                    r=server._vm_workflow_impl("android-consent-grant-acceptance-reconcile-"+suffix,{"correlationId":REQUEST["correlationId"]})
                self.assertFalse(r["ok"]);self.assertNotIn("records",r);self.assertNotIn("rawSecret",r)
        unknown=reset._reply(REQUEST["correlationId"],"unknown","reconcile_command_timeout",checkpoint="routing",nativeActionAllowed=False,productAction=False)
        with mock.patch.object(reset,"reconcile_diagnose",return_value=unknown):
            r=server._vm_workflow_impl("android-consent-grant-acceptance-reconcile-diagnose",{"correlationId":REQUEST["correlationId"]})
        self.assertFalse(r["ok"]);self.assertEqual("routing",r["checkpoint"]);self.assertEqual("reconcile_command_timeout",r["reason"])
