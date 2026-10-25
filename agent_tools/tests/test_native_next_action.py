"""Table tests for safe next-action guidance using public workflow response shapes."""
import unittest
from unittest import mock
import hashlib
import importlib.util
import json
from pathlib import Path

from agent_tools.native_next_action import next_action

OPERATION = "cd7ae194-d72a-4bd6-9d86-190f10a2931f"


class NativeNextActionTest(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.route_adapter import bind_cached_routes
        from agent_tools import mcp_server as _route_server
        bind_cached_routes(self,_route_server,
            'native_failure_evidence',
        )

    def test_public_ssh_wrapper_preserves_fixed_recovery_guidance(self):
        from agent_tools import mcp_server, native_failure_evidence
        result = {"tool": "ssh_workflow", "host": "guest", "status": "nested_master_absent",
                  "ok": False, "recoveryHost": "archlinux"}
        with mock.patch.object(mcp_server, "_ssh_workflow_impl", return_value=result), \
                mock.patch.object(native_failure_evidence, "record_failure", return_value={}):
            actual = mcp_server.ssh_workflow("probe", "guest")
        self.assertEqual("recover-configured-ssh-master", actual["nextAction"]["kind"])
        self.assertEqual({"tool": "ssh_workflow", "action": "connection-recover",
                          "args": {"host": "archlinux"}}, actual["nextAction"]["action"])
        self.assertFalse(actual["nextAction"]["replayAllowed"])

    def test_expired_nested_probe_guidance_survives_boundary_reclassification(self):
        result = {"host": "guest", "status": "nested_master_absent", "ok": False,
                  "recoveryHost": "archlinux", "nextAction": {"action": "foreign-command"}}
        actual = next_action("ssh_workflow", "probe", result)
        self.assertEqual("recover-configured-ssh-master", actual["kind"])
        self.assertEqual({"tool": "ssh_workflow", "action": "connection-recover",
                          "args": {"host": "archlinux"}}, actual["action"])
        self.assertFalse(actual["replayAllowed"])
        for invalid in (None, [], "arch;touch /tmp/foreign", "a" * 65, ":foreign"):
            with self.subTest(host=invalid):
                rejected = next_action("ssh_workflow", "probe", {**result, "recoveryHost": invalid})
                self.assertEqual("inspect-evidence", rejected["kind"])
                self.assertNotIn("action", rejected)
        for tool, action, extra in (("vm_workflow", "probe", {}),
                                    ("ssh_workflow", "job-status", {}),
                                    ("ssh_workflow", "probe", {"status": "authentication_failed"}),
                                    ("ssh_workflow", "probe", {"ok": True})):
            self.assertNotEqual("recover-configured-ssh-master", next_action(tool, action, {**result, **extra})["kind"])

    def test_known_response_taxonomy(self):
        job = {"host": "vm", "identity": {"jobId": "job-17", "pid": 417, "startTicks": 9981}, "status": "running", "reason": "process_live", "ok": True}
        cases = (
            ("ssh_workflow", "job-status", job, "observe-job", "job-status", False),
            ("ssh_workflow", "job-status", {**job, "status": "unknown", "reason": "timeout", "ok": False}, "observe-job", "job-status", False),
            ("ssh_workflow", "job-status", {**job, "status": "terminal", "exitCode": 23}, "inspect-evidence", None, False),
            ("ssh_workflow", "probe", {"host": "vm", "status": "timeout", "ok": False, "output": "SSH probe timed out."}, "retry-readonly", "probe", True),
            ("ssh_workflow", "forward-open", {"state": "local_forward_pending", "correlationId": "forward-17", "ok": False}, "inspect-evidence", None, False),
            ("ssh_workflow", "fixture-publish", {"state": "unknown", "reason": "interrupted_or_unverified", "identity": {"correlationId": "retained"}}, "inspect-evidence", None, False),
            ("vm_workflow", "artifact-verify", {"verification": "mismatch", "ok": False}, "missing-dependency", None, False),
            ("vm_workflow", "artifact-verify", {"verification": "unverified-remote", "ok": False}, "verify-artifact", None, False),
            ("vm_workflow", "environment-status", {"freshness": "stale", "ready": False}, "refresh-measurement", None, False),
            ("vm_workflow", "scenario-start", {"state": "submitted", "correlationId": "run-17", "reason": "submitted"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-resume", {"state": "submitting", "correlationId": "run-17", "reason": "submit_response_unavailable"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-status", {"state": "unknown", "correlationId": "run-17", "reason": "observer_unavailable"}, "observe-scenario", "scenario-status", False),
            ("vm_workflow", "scenario-collect", {"state": "terminal", "correlationId": "run-17", "exitCode": 0}, "complete", None, False),
            ("vm_workflow", "scenario-collect", {"state": "terminal", "correlationId": "run-17", "exitCode": 23}, "inspect-evidence", None, False),
            ("ssh_workflow", "forward-status", {"state": "unsupported_host", "ok": False}, "unsupported", None, False),
            ("vm_workflow", "restart-unknown-installer", {"ok": False, "summary": "installer failed"}, "inspect-evidence", None, False),
            ("vm_workflow", "unknown", {"state": "unknown", "ok": False}, "inspect-evidence", None, False),
        )
        for tool, action, result, kind, suggested, replay in cases:
            with self.subTest(tool=tool, action=action, state=result.get("state", result.get("status"))):
                actual = next_action(tool, action, result)
                self.assertEqual(kind, actual["kind"])
                self.assertEqual(replay, actual["replayAllowed"])
                self.assertEqual(suggested, actual.get("action", {}).get("action"))

    def test_suggested_arguments_are_only_host_and_identity(self):
        actual = next_action("ssh_workflow", "job-status", {
            "host": "vm", "identity": {"jobId": "job-17", "pid": 417, "startTicks": 9981},
            "status": "running", "reason": "process_live", "secret": "ignored",
        })
        self.assertEqual({"host", "identity"}, set(actual["action"]["args"]))
        self.assertNotIn("secret", actual["action"]["args"])

    def test_scenario_status_uses_the_vm_inputs_envelope(self):
        actual = next_action("vm_workflow", "scenario-start", {
            "state": "submitted", "correlationId": "run-17", "reason": "submitted",
        })
        self.assertEqual({"inputs": {"correlationId": "run-17"}}, actual["action"]["args"])
        self.assertNotIn("correlationId", actual["action"]["args"])

    def test_environment_unknown_distinguishes_fresh_missing_facts_from_stale_receipts(self):
        probes_ready = next_action("vm_workflow", "environment-status", {
            "state": "UNKNOWN", "requestedProbesReady": True, "freshness": "fresh", "observations": [], "ready": False,
        })
        stale = next_action("vm_workflow", "environment-status", {
            "state": "UNKNOWN", "requestedProbesReady": False, "freshness": "fresh",
            "observations": [{"kind": "memory", "stale": True}], "ready": False,
        })
        self.assertEqual("missing-dependency", probes_ready["kind"])
        self.assertEqual("refresh-measurement", stale["kind"])

    def test_unknown_response_never_replays(self):
        actual = next_action("ssh_workflow", "fixture-publish", {"state": "unknown", "identity": "bad"})
        self.assertEqual("inspect-evidence", actual["kind"])
        self.assertFalse(actual["replayAllowed"])
        self.assertTrue(actual["requiresFreshEvidence"])

    def test_readiness_continues_only_same_result_bound_target(self):
        for tool, binding, args in (
                ("vm_workflow", {"fixtureId": "android-recovery-4"},
                 {"inputs": {"fixtureId": "android-recovery-4", "operationId": OPERATION}}),
                ("ssh_workflow", {"host": "configured-guest"},
                 {"host": "configured-guest", "identity": {"operationId": OPERATION}})):
            with self.subTest(tool=tool):
                result = {**binding, "operationId": OPERATION, "state": "not_ready", "ok": True,
                          "replayAllowed": False, "nextAction": {"action": "foreign-command"},
                          "private": "PRIVATE-MARKER"}
                actual = next_action(tool, "readiness-status", result)
                self.assertEqual(actual["kind"], "ensure_ready")
                self.assertEqual(actual["action"], {"tool": tool, "action": "readiness-ensure", "args": args})
                self.assertFalse(actual["replayAllowed"])
                self.assertNotIn("PRIVATE-MARKER", str(actual))
                for action in ("readiness-status", "readiness-ensure"):
                    ready = next_action(tool, action, {**result, "state": "ready"})
                    self.assertEqual(ready["kind"], "complete")
                    self.assertNotIn("action", ready)

    def test_readiness_blockers_and_bad_identities_never_retry(self):
        base = {"fixtureId": "android-recovery-4", "operationId": OPERATION, "state": "not_ready",
                "ok": True, "replayAllowed": False, "nextAction": "ensure_ready"}
        changes = ({"readinessBlocker": "credential_unavailable"}, {"state": "blocked"}, {"state": "unknown"},
                   {"state": []}, {"operationId": OPERATION.upper()}, {"operationId": None},
                   {"fixtureId": "../../guest"}, {"fixtureId": ""}, {"replayAllowed": True})
        for change in changes:
            with self.subTest(change=change):
                actual = next_action("vm_workflow", "readiness-status", {**base, **change})
                self.assertEqual(actual["kind"], "resolve_blocker")
                self.assertNotIn("action", actual)
                self.assertFalse(actual["replayAllowed"])
        self.assertEqual(next_action("vm_workflow", "readiness-ensure", base)["kind"], "resolve_blocker")

    def test_lease_observation_uses_same_original_identity_until_owner_terminal(self):
        base = {"fixtureId": "android-recovery-4", "operationId": OPERATION, "state": "active",
                "jobState": "running", "ok": True, "replayAllowed": False,
                "nextAction": {"tool": "foreign", "action": "restart"}}
        for state in ("active", "restore_pending", "restoring", "expired", "cancelled"):
            with self.subTest(state=state):
                actual = next_action("vm_workflow", "readiness-lease-status", {**base, "state": state, "restored": True})
                self.assertEqual(actual["kind"], "observe_original")
                self.assertEqual(actual["action"], {"tool": "vm_workflow", "action": "readiness-lease-status",
                    "args": {"inputs": {"fixtureId": "android-recovery-4", "operationId": OPERATION}}})
                self.assertFalse(actual["replayAllowed"])
        for state in ("expired", "cancelled"):
            terminal = {**base, "state": state, "jobState": "terminal", "restored": True}
            for action in ("readiness-lease-acquire", "readiness-lease-status", "readiness-lease-cancel"):
                actual = next_action("vm_workflow", action, terminal)
                self.assertEqual(actual["kind"], "complete")
                self.assertNotIn("action", actual)

    def test_lease_unknown_or_unrestored_receipts_never_complete_or_restart(self):
        base = {"fixtureId": "android-recovery-4", "operationId": OPERATION, "state": "expired",
                "jobState": "terminal", "restored": True, "ok": True, "replayAllowed": False}
        for change in ({"restored": False}, {"state": "restore_blocked"}, {"jobState": "unknown"},
                       {"state": "unknown"}, {"state": []}, {"jobState": {}}, {"ok": False},
                       {"operationId": OPERATION.upper()}, {"fixtureId": "guest;restart"}, {"replayAllowed": True}):
            with self.subTest(change=change):
                actual = next_action("vm_workflow", "readiness-lease-status", {**base, **change})
                self.assertEqual(actual["kind"], "resolve_blocker")
                self.assertFalse(actual["replayAllowed"])
                self.assertNotIn("action", actual)

    def test_lease_known_detached_admission_pending_observes_original_without_replay(self):
        base={"fixtureId":"owned-fixture","operationId":"23456789-1234-4234-9234-123456789012",
              "state":"unknown","jobState":"unknown","ok":True,"replayAllowed":False}
        for reason in ('original_owner_ack_pending','original_admission_pending'):
            actual=next_action('vm_workflow','readiness-lease-acquire',{**base,'reason':reason})
            self.assertEqual('observe_original',actual['kind'])
            self.assertEqual('readiness-lease-status',actual['action']['action'])
            self.assertEqual(base['operationId'],actual['action']['args']['inputs']['operationId'])
        for change in ({'reason':'original_owner_unresolved'}, {'reason':{}}, {'reason':'original_owner_ack_pending','ok':False}):
            actual=next_action('vm_workflow','readiness-lease-acquire',{**base,**change})
            self.assertEqual('resolve_blocker',actual['kind'])
            self.assertNotIn('action',actual)

    def test_original_android_restoration_uses_one_finite_reconcile_then_observes(self):
        import uuid
        base={"schemaVersion":1,"fixtureId":"owned-lease-fixture","operationId":OPERATION,
              "provider":"android-emulator","qualificationScope":"registered_android_fixture",
              "state":"restore_blocked","jobState":"terminal","restored":False,"ok":False,
              "replayAllowed":False,"reason":"lease_restore_not_admitted","restorationState":"unsubmitted",
              "restorationOperationId":str(uuid.uuid5(uuid.UUID(OPERATION),"temporary-keep-awake-restore-v1"))}
        for action in ("readiness-lease-status","readiness-lease-reconcile","readiness-lease-cancel","readiness-lease-acquire"):
            actual=next_action("vm_workflow",action,base)
            self.assertEqual("reconcile_original",actual["kind"])
            self.assertEqual({"tool":"vm_workflow","action":"readiness-lease-reconcile",
                "args":{"inputs":{"fixtureId":base["fixtureId"],"operationId":OPERATION}}},actual["action"])
        for change in ({"restorationState":"unknown"},{"provider":"tart-macos"},{"restorationOperationId":OPERATION},
                       {"jobState":"running"},{"reason":"unrecognized"},{"qualificationScope":"unrecognized"}):
            self.assertEqual("resolve_blocker",next_action("vm_workflow","readiness-lease-status",{**base,**change})["kind"])
        pending={**base,"state":"restoring","jobState":"running","restorationState":"running","ok":True}
        actual=next_action("vm_workflow","readiness-lease-reconcile",pending)
        self.assertEqual("observe_original",actual["kind"])
        self.assertEqual("readiness-lease-status",actual["action"]["action"])
        terminal={**pending,"state":"restored","jobState":"terminal","restorationState":"terminal","restored":True}
        self.assertEqual("complete",next_action("vm_workflow","readiness-lease-status",terminal)["kind"])

    def test_qualified_mac_cleanup_reconciles_only_the_original_terminal_owner(self):
        path=Path(__file__).parent/"fixtures/macos_lease_cleanup_guidance_before.source"
        raw=path.read_bytes()
        self.assertEqual("3de6e8fa50058e35677ac7e292ba14719030f1e84826e6a966f4d8119a968896",
                         hashlib.sha256(raw).hexdigest())
        before={"__name__":"_macos_cleanup_guidance_before"}
        exec(compile(raw,str(path),"exec"),before)
        base={"schemaVersion":1,"fixtureId":"qualified-mac-fixture","operationId":OPERATION,
              "provider":"tart-macos","qualificationScope":"registered_guest_executor",
              "state":"restore_blocked","jobState":"terminal","restored":False,"ok":False,
              "reason":"macos_assertion_release_unverified","replayAllowed":False,
              "nextAction":"reconcile_original","private":"PRIVATE-MARKER"}

        def require_original_cleanup(classifier):
            actual=classifier("vm_workflow","readiness-lease-status",base)
            self.assertEqual("reconcile_original",actual["kind"])
            self.assertEqual({"tool":"vm_workflow","action":"readiness-lease-reconcile",
                "args":{"inputs":{"fixtureId":base["fixtureId"],"operationId":OPERATION}}},actual["action"])
            self.assertFalse(actual["replayAllowed"])
            self.assertNotIn("PRIVATE-MARKER",str(actual))

        # The authentic whole previous classifier blocks this qualified native
        # cleanup result; the same assertion proves RED before and GREEN now.
        with self.assertRaises(AssertionError):require_original_cleanup(before["next_action"])
        require_original_cleanup(next_action)
        for action in ("readiness-lease-acquire","readiness-lease-status",
                       "readiness-lease-cancel","readiness-lease-reconcile"):
            self.assertEqual("readiness-lease-reconcile",
                next_action("vm_workflow",action,base)["action"]["action"])
        for change in ({"schemaVersion":True},{"schemaVersion":2},{"provider":"raw-qemu-windows"},
                       {"provider":None},{"qualificationScope":"unqualified"},{"state":"unknown"},
                       {"jobState":"unknown"},{"jobState":"running"},{"restored":None},{"restored":0},
                       {"restored":True},{"reason":"correlated_terminal"},{"reason":"unrecognized"},
                       {"nextAction":"resolve_restoration_blocker"},{"nextAction":{"action":"reacquire"}},
                       {"operationId":OPERATION.upper()},{"fixtureId":"other;vm"},{"replayAllowed":True}):
            with self.subTest(change=change):
                actual=next_action("vm_workflow","readiness-lease-status",{**base,**change})
                self.assertEqual("resolve_blocker",actual["kind"])
                self.assertNotIn("action",actual)
        pending={**base,"state":"restore_pending","jobState":"running"}
        actual=next_action("vm_workflow","readiness-lease-status",pending)
        self.assertEqual("observe_original",actual["kind"])
        self.assertEqual("readiness-lease-status",actual["action"]["action"])

    def test_qualified_normalized_mac_running_cleanup_observes_original_until_wrapper_terminal(self):
        path=Path(__file__).parent/"fixtures/macos_running_cleanup_guidance_before.source"
        raw=path.read_bytes()
        self.assertEqual('2a1960c0c8e7f4f2389bde62394dce4f2b659f9da233d567229d7a9b23148323',hashlib.sha256(raw).hexdigest())
        before={'__name__':'_mac_running_cleanup_before'};exec(compile(raw,str(path),'exec'),before)
        base={'schemaVersion':1,'provider':'tart-macos','qualificationScope':'registered_guest_executor',
              'fixtureId':'qualified-mac-fixture','operationId':OPERATION,'replayAllowed':False,
              'state':'unknown','nativeState':'restore_pending','jobState':'running','restored':False,
              'ok':True,'reason':'lease_deadline_reached','nextAction':'observe_original'}
        def require_original_status(classifier,result):
            actual=classifier('vm_workflow','readiness-lease-status',result)
            self.assertEqual('observe_original',actual['kind'])
            self.assertEqual({'tool':'vm_workflow','action':'readiness-lease-status',
                'args':{'inputs':{'fixtureId':base['fixtureId'],'operationId':OPERATION}}},actual['action'])
            self.assertFalse(actual['replayAllowed'])
        with self.assertRaises(AssertionError):require_original_status(before['next_action'],base)
        for reason in ('lease_deadline_reached','original_lease_cancelled','macos_lease_failed','macos_assertion_release_unverified'):
            for restored in (False,True):require_original_status(next_action,{**base,'reason':reason,'restored':restored})
        for change in ({'schemaVersion':True},{'schemaVersion':2},{'provider':'raw-qemu-windows'},
                       {'qualificationScope':'unqualified'},{'nativeState':'unknown'},{'jobState':'unknown'},
                       {'jobState':'terminal'},{'restored':None},{'restored':0},{'ok':False},
                       {'nextAction':'reconcile_original'},{'reason':'correlated_terminal'},
                       {'reason':'unrecognized'},{'reason':[]},{'operationId':OPERATION.upper()},
                       {'fixtureId':'../../vm'},{'replayAllowed':True}):
            with self.subTest(change=change):
                actual=next_action('vm_workflow','readiness-lease-status',{**base,**change})
                self.assertEqual('resolve_blocker',actual['kind']);self.assertNotIn('action',actual)
        for state in ('expired','cancelled'):
            pending={**base,'state':state,'nativeState':state,'restored':True}
            require_original_status(next_action,pending)
            for change in ({'nextAction':'none'},{'nextAction':'foreign'},{'schemaVersion':True},
                           {'qualificationScope':'unqualified'},{'nativeState':'unknown'},{'reason':'correlated_terminal'}):
                self.assertEqual('resolve_blocker',next_action('vm_workflow','readiness-lease-status',{**pending,**change})['kind'])
            terminal={**pending,'jobState':'terminal','nextAction':'none'}
            self.assertEqual('complete',next_action('vm_workflow','readiness-lease-status',terminal)['kind'])
            for change in ({'nextAction':'observe_original'},{'nextAction':'foreign'},{'schemaVersion':True},
                           {'restored':False},{'qualificationScope':'unqualified'},{'reason':'correlated_terminal'},
                           {'nativeState':'unknown'}):
                self.assertEqual('resolve_blocker',next_action('vm_workflow','readiness-lease-status',{**terminal,**change})['kind'])

    def test_qualified_starting_lease_observes_same_original_owner(self):
        base={"schemaVersion":1,"fixtureId":"owned-starting-lease","operationId":OPERATION,
              "state":"starting","jobState":"running","ok":True,"replayAllowed":False,
              "provider":"raw-qemu-windows","qualificationScope":"registered_guest_executor"}
        directory=Path(__file__).parent/"fixtures/lease_starting_guidance_before"
        path=directory/"native_next_action.py"
        provenance=json.loads((directory/"provenance.json").read_text())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),provenance["beforeimageSha256"])
        self.assertEqual([],provenance["modifications"])
        spec=importlib.util.spec_from_file_location("lease_starting_guidance_before",path)
        before=importlib.util.module_from_spec(spec);spec.loader.exec_module(before)
        unfixed=before.next_action("vm_workflow","readiness-lease-acquire",base)
        self.assertEqual("resolve_blocker",unfixed["kind"],"preserved source must reproduce the original missing continuation")
        self.assertNotIn("action",unfixed)
        pairs=[("raw-qemu-windows","registered_guest_executor"),("libvirt-windows","registered_guest_executor"),
               ("tart-macos","registered_guest_executor"),("android-emulator","registered_android_fixture")]
        for provider,scope in pairs:
            for owner in ("running","pending"):
                with self.subTest(provider=provider,owner=owner):
                    actual=next_action("vm_workflow","readiness-lease-acquire",{**base,"provider":provider,"qualificationScope":scope,"jobState":owner})
                    self.assertEqual("observe_original",actual["kind"])
                    self.assertEqual({"tool":"vm_workflow","action":"readiness-lease-status",
                        "args":{"inputs":{"fixtureId":base["fixtureId"],"operationId":OPERATION}}},actual["action"])
                    self.assertFalse(actual["replayAllowed"])
        for change in ({"jobState":"unknown"},{"jobState":"terminal"},{"ok":False},{"provider":"unqualified"},{"provider":{}},
                       {"qualificationScope":"unqualified"},{"qualificationScope":{}},{"schemaVersion":True},{"schemaVersion":2},
                       {"operationId":OPERATION.upper()},{"fixtureId":"guest;input"},{"replayAllowed":True}):
            with self.subTest(change=change):
                actual=next_action("vm_workflow","readiness-lease-status",{**base,**change})
                self.assertEqual("resolve_blocker",actual["kind"])
                self.assertNotIn("action",actual)

    def test_fixed_guest_and_android_program_routes_preserve_only_original_fixture_and_uuid(self):
        base={'schemaVersion':1,'durableProtocol':1,'qualificationScope':'fixed-counter',
              'fixtureId':'owned-fixture','operationId':OPERATION,'replayAllowed':False,
              'nextAction':{'tool':'foreign','action':'restart'}}
        for prefix in ('guest-program','android-program'):
            value={**base,**({'provider':'android-emulator'} if prefix=='android-program' else {})}
            for verb in ('start','status','reconcile','collect'):
                for state in ('running','pending'):
                    actual=next_action('vm_workflow',prefix+'-'+verb,{**value,'state':state})
                    self.assertEqual('reconcile_original',actual['kind'])
                    self.assertEqual({'tool':'vm_workflow','action':prefix+'-reconcile',
                        'args':{'inputs':{'fixtureId':'owned-fixture','operationId':OPERATION}}},actual['action'])
                    self.assertFalse(actual['replayAllowed'])
            for verb in ('start','status','reconcile'):
                actual=next_action('vm_workflow',prefix+'-'+verb,{**value,'state':'terminal'})
                self.assertEqual('collect_original',actual['kind'])
                self.assertEqual(prefix+'-collect',actual['action']['action'])
            terminal={**value,'state':'terminal','complete':True,'streamCapped':False}
            actual=next_action('vm_workflow',prefix+'-collect',terminal)
            self.assertEqual('complete',actual['kind'])
            self.assertNotIn('action',actual)

    def test_unknown_guest_program_only_reconciles_qualified_original_admission(self):
        base={'schemaVersion':1,'durableProtocol':1,'qualificationScope':'fixed-counter',
              'fixtureId':'owned-fixture','operationId':OPERATION,'replayAllowed':False,'state':'unknown','ok':False}
        for prefix,reasons in [('guest-program',['record_unavailable','guest_submission_unresolved','guest_original_observation_unavailable']),
                              ('android-program',[None,'android_job_admission_unknown','android_job_transport_unknown',
                                  'android_job_transport_timeout','android_job_deadline','android_job_original_owner_unresolved'])]:
            value={**base,**({'provider':'android-emulator'} if prefix=='android-program' else {})}
            for reason in reasons:
                actual=next_action('vm_workflow',prefix+'-status',{**value,'reason':reason})
                self.assertEqual('reconcile_original',actual['kind'])
            for change in ({'reason':'owner_identity_mismatch'},{'reason':'boot_changed'},{'reason':{}},
                           {'reason':'android_job_guest_identity_changed'},{'durableProtocol':True},
                           {'durableProtocol':2},{'schemaVersion':True},{'qualificationScope':'unclassified'},
                           {'replayAllowed':True},{'operationId':OPERATION.upper()},{'fixtureId':'owned;restart'}):
                actual=next_action('vm_workflow',prefix+'-status',{**value,'reason':reasons[0],**change})
                self.assertEqual('resolve_blocker',actual['kind'])
                self.assertNotIn('action',actual)

    def test_incomplete_android_collection_never_claims_complete(self):
        base={'schemaVersion':1,'durableProtocol':1,'qualificationScope':'fixed-counter','provider':'android-emulator',
              'fixtureId':'owned-fixture','operationId':OPERATION,'replayAllowed':False,'state':'terminal'}
        for change in ({'complete':False},{'complete':True,'streamCapped':True},{'complete':True,'streamCapped':{}},{}):
            actual=next_action('vm_workflow','android-program-collect',{**base,**change})
            self.assertEqual('resolve_blocker',actual['kind'])
            self.assertNotIn('action',actual)

    def test_explicit_readiness_reboot_result_does_not_reissue_power_action(self):
        value={'fixtureId':'owned-fixture','operationId':OPERATION,'state':'ready','ok':True,'replayAllowed':False}
        self.assertEqual('complete',next_action('vm_workflow','readiness-reboot',value)['kind'])
        actual=next_action('vm_workflow','readiness-reboot',{**value,'state':'unknown','ok':False})
        self.assertEqual('resolve_blocker',actual['kind'])
        self.assertNotIn('action',actual)

    def test_program_guidance_preserves_exact_identity_and_protocol_boundary(self):
        base = {"host": "configured-guest", "operationId": OPERATION, "state": "unknown",
                "replayAllowed": False, "durableProtocol": 1, "nextAction": "reconcile_original"}
        actual = next_action("ssh_workflow", "program-status", base)
        self.assertEqual(actual["kind"], "reconcile_original")
        self.assertEqual(actual["action"], {"tool": "ssh_workflow", "action": "program-reconcile",
            "args": {"host": "configured-guest", "identity": {"operationId": OPERATION}}})
        for protocol in (None, True, "1", 2):
            with self.subTest(protocol=protocol):
                rejected = next_action("ssh_workflow", "program-status", {**base, "durableProtocol": protocol})
                self.assertEqual(rejected["kind"], "resolve_blocker")
                self.assertNotIn("action", rejected)
                pending = next_action("ssh_workflow", "program-status", {**base, "state": "pending", "durableProtocol": protocol})
                self.assertEqual(pending["kind"], "observe_original")
                self.assertEqual(pending["action"]["action"], "program-status")
        for change in ({"operationId": OPERATION.upper()}, {"replayAllowed": True}, {"nextAction": {"action": "restart"}}):
            with self.subTest(change=change):
                rejected = next_action("ssh_workflow", "program-status", {**base, **change})
                self.assertEqual(rejected["kind"], "resolve_blocker")
                self.assertNotIn("action", rejected)


if __name__ == "__main__":
    unittest.main()
