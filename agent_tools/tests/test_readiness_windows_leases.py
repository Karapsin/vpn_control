"""Finite protocol tests; the native Windows compiler case never calls APIs.

Actual execution-state effects require the separately retained guest acceptance.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import importlib.util
import subprocess
import sys
import unittest
from uuid import uuid4

from agent_tools import readiness_windows_leases as leases


class WindowsLeaseProtocolTests(unittest.TestCase):
    def setUp(self):
        self.operation = str(uuid4())
        self.binding = leases.WindowsLeaseBinding('abcdef78-1234-4234-9234-123456789012',
            '2026-10-20T09:04:39.5000000Z', 'S-1-5-21-1-2-3-1000', '2:134369607007458666',
            '12345678:0003000000000847:01dd6077063bd7e7')

    def observation(self, **extra):
        return {'schemaVersion': 1, 'operationId': self.operation, 'machine': self.binding.machine,
                'boot': self.binding.boot, 'rootGeneration': self.binding.root_generation,
                'state': 'active', 'reason': 'original_owner_running', 'replayAllowed': False,
                'admissionNonce': '23456789-1234-4234-9234-123456789012', 'programSha256': 'a'*64,
                'owner': {'pid': 1234, 'birth': '134369629130736090', 'threadId': 3456, 'sessionId':2, 'accountSid':'S-1-5-18'},
                'jobState': 'running', **extra}

    def streams(self, stdout=b'', stderr=b''):
        return {name: {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest(),
                       'base64':base64.b64encode(raw).decode()} for name, raw in [('stdout',stdout),('stderr',stderr)]}

    def test_binding_rejects_unpinned_or_noncanonical_guest_identities(self):
        values = leases.asdict(self.binding)
        for key, value in [('machine',values['machine'].upper()), ('boot','today'), ('account','Administrator'),
                           ('session','2;run'), ('session','4294967295:1'), ('session','2:0'), ('root_generation','unbound')]:
            with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                leases.WindowsLeaseBinding(**{**values,key:value})

    def test_finite_program_factory_rejects_commands_credentials_and_invalid_ttl(self):
        for action in ('shell','login','powershell','shutdown'):
            with self.subTest(action=action), self.assertRaises(ValueError):
                leases.program(action,self.binding,self.operation)
        for ttl in (float('nan'),float('inf'),True,0,18001,'10'):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                leases.program('acquire',self.binding,self.operation,ttl_seconds=ttl)
        with self.assertRaises(ValueError):
            leases.program('status',self.binding,self.operation,ttl_seconds=1)
        with self.assertRaises(TypeError):
            leases.program('acquire',self.binding,self.operation,ttl_seconds=1,password='PRIVATE-MARKER')

    def test_packets_are_deterministic_and_status_has_no_acquire_payload(self):
        one=leases.program('acquire',self.binding,self.operation,ttl_seconds=1)
        self.assertEqual(one,leases.program('acquire',self.binding,self.operation,ttl_seconds=1))
        status=leases.program('status',self.binding,self.operation)
        self.assertNotEqual(one,status)
        self.assertTrue(status.endswith(b', $null,$null))\n'.replace(b', ',b',')))
        self.assertNotIn(b'PRIVATE-MARKER',one)

    def test_actual_enrollment_identity_must_match_every_pinned_field(self):
        value={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
               'rootGeneration':self.binding.root_generation}
        self.assertEqual(self.binding.root_generation,leases.validate_enrollment(value,self.binding.machine,self.binding.boot))
        for change in ({'schemaVersion':True},{'machine':str(uuid4())},{'rootGeneration':'unbound'},{'secret':'PRIVATE-MARKER'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                leases.validate_enrollment({**value,**change},self.binding.machine,self.binding.boot)

    def test_idle_inventory_requires_complete_visibility_and_every_original_terminal(self):
        value={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
               'rootGeneration':self.binding.root_generation,'visibilityComplete':True,'blockers':[], 'terminalCount':3}
        self.assertEqual(value,leases.validate_idle(value,self.binding.machine,self.binding.boot,self.binding.root_generation))
        blocked={**value,'blockers':[{'operationId':self.operation,'reason':'lease_original_work_not_terminal'}]}
        self.assertTrue(leases.validate_idle(blocked,self.binding.machine,self.binding.boot,self.binding.root_generation)['blockers'])
        for change in ({'visibilityComplete':False},{'terminalCount':True},{'blockers':[{'operationId':self.operation,'reason':'PRIVATE-MARKER'}]},
                       {'rootGeneration':None},{'boot':'other'},{'machine':str(uuid4())}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                leases.validate_idle({**value,**change},self.binding.machine,self.binding.boot,self.binding.root_generation)

    def test_unenrolled_positive_absence_is_finite_and_never_adopts_existing_root(self):
        value={'schemaVersion':1,'machine':self.binding.machine,'boot':self.binding.boot,
               'rootGeneration':None,'visibilityComplete':True,'blockers':[], 'terminalCount':0}
        self.assertEqual(value,leases.validate_idle(value,self.binding.machine,self.binding.boot,None))
        with self.assertRaises(ValueError):
            leases.validate_idle({**value,'terminalCount':1},self.binding.machine,self.binding.boot,None)
        with self.assertRaises(ValueError):
            leases.idle_source(self.binding.machine,self.binding.boot,'untrusted-root')

    def test_active_owner_is_observed_without_replacement_or_private_stream_projection(self):
        result=leases.validate_observation(self.observation(),self.binding,self.operation)
        self.assertEqual('observe_original',result['nextAction'])
        self.assertFalse(result['replayAllowed'])
        self.assertEqual(self.observation()['owner'],result['identity']['owner'])

    def test_actual_session_zero_failure_cannot_report_active_display_lease(self):
        value=self.observation()
        owner=value['owner']
        with self.assertRaises(ValueError):
            leases.validate_observation({**value,'owner':{k:v for k,v in owner.items() if k not in {'sessionId','accountSid'}}},self.binding,self.operation)
        with self.assertRaises(ValueError):
            leases.validate_observation({**value,'owner':{**owner,'sessionId':0}},self.binding,self.operation)

    def test_causal_original_native_session_zero_receipt_was_accepted_before_fix(self):
        path=Path(__file__).parent/'fixtures/readiness_windows_lease_session_zero_before.py'
        name='agent_tools._windows_lease_session_zero_before'
        spec=importlib.util.spec_from_file_location(name,path)
        before=importlib.util.module_from_spec(spec);sys.modules[name]=before
        try:
            spec.loader.exec_module(before)
            binding=before.WindowsLeaseBinding(**leases.asdict(self.binding))
            value=self.observation()
            value['owner']={key:item for key,item in value['owner'].items() if key not in {'sessionId','accountSid'}}
            # This is the exact receipt shape of native PID1920/sessionzero:
            # it claimed active while powercfg had no DISPLAY request and the
            # independent current-value display callback reported asleep.
            self.assertEqual('observe_original',before.validate_observation(value,binding,self.operation)['nextAction'])
            with self.assertRaisesRegex(ValueError,'^windows_lease_owner_invalid$'):
                leases.validate_observation(value,self.binding,self.operation)
        finally:
            sys.modules.pop(name,None)

    def test_receipt_without_closed_owner_streams_is_not_complete(self):
        value=self.observation(state='expired',reason='lease_deadline_reached',restored=True)
        result=leases.validate_observation(value,self.binding,self.operation)
        self.assertEqual('observe_original',result['nextAction'])
        with self.assertRaises(ValueError):
            leases.validate_observation({**value,'jobState':'terminal'},self.binding,self.operation)

    def test_complete_retained_streams_are_verified_then_raw_bytes_removed(self):
        value=self.observation(state='cancelled',reason='original_lease_cancelled',restored=True,
                               jobState='terminal',retainedStreams=self.streams(b'PRIVATE-RETAINED-STREAM'))
        result=leases.validate_observation(value,self.binding,self.operation)
        self.assertEqual('none',result['nextAction'])
        self.assertTrue(result['ok'])
        self.assertNotIn('PRIVATE-RETAINED-STREAM',str(result))
        self.assertNotIn('base64',json.dumps(result))
        self.assertEqual(23,result['streams']['stdout']['bytes'])

    def test_prior_boot_history_requires_correlated_restored_terminal_and_closed_streams(self):
        value=self.observation(state='expired',reason='lease_deadline_reached',restored=True,
                               jobState='terminal',retainedStreams=self.streams(),historicalTerminal=True)
        result=leases.validate_observation(value,self.binding,self.operation)
        self.assertTrue(result['historicalTerminal'])
        self.assertEqual('none',result['nextAction'])
        for change in ({'restored':False}, {'jobState':'unknown'}, {'jobState':'running'},
                       {'state':'active'}, {'historicalTerminal':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                leases.validate_observation({**value,**change},self.binding,self.operation)

    def test_causal_prior_boot_terminal_protocol_beforeimage_rejects_proven_history(self):
        path=Path(__file__).parent/'fixtures/readiness_windows_lease_boot_history_before.py'
        name='agent_tools._windows_lease_boot_history_before'
        spec=importlib.util.spec_from_file_location(name,path)
        before=importlib.util.module_from_spec(spec);sys.modules[name]=before
        try:
            spec.loader.exec_module(before)
            binding=before.WindowsLeaseBinding(**leases.asdict(self.binding))
            value=self.observation(state='expired',reason='lease_deadline_reached',restored=True,
                                   jobState='terminal',retainedStreams=self.streams(),historicalTerminal=True)
            with self.assertRaises(ValueError):
                before.validate_observation(value,binding,self.operation)
            self.assertTrue(leases.validate_observation(value,self.binding,self.operation)['historicalTerminal'])
        finally:
            sys.modules.pop(name,None)

    def test_owner_pid_generation_nonce_and_source_remain_original(self):
        value=self.observation();identity=leases.validate_observation(value,self.binding,self.operation)['identity']
        for change in ({'owner':{**value['owner'],'pid':1235}}, {'owner':{**value['owner'],'birth':'134369629130736091'}},
                       {'admissionNonce':str(uuid4())}, {'programSha256':'b'*64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                leases.validate_observation({**value,**change},self.binding,self.operation,original_identity=identity)

    def test_wrong_machine_boot_root_operation_and_malformed_shapes_fail_closed(self):
        for change in ({'schemaVersion':True},{'machine':str(uuid4())},{'boot':'other'}, {'operationId':str(uuid4())},
                       {'rootGeneration':'87654321:0003000000000847:01dd6077063bd7e7'}, {'state':{}},
                       {'owner':{'pid':True,'birth':'1','threadId':1}},{'replayAllowed':True},
                       {'reason':'PRIVATE-MARKER'},{'password':'PRIVATE-MARKER'}):
            with self.subTest(change=change), self.assertRaises(ValueError) as error:
                leases.validate_observation(self.observation(**change),self.binding,self.operation)
            self.assertNotIn('PRIVATE-MARKER',str(error.exception))

    def test_unknown_owner_or_failed_release_is_never_relaunched(self):
        for value in (self.observation(state='unknown',reason='original_owner_unresolved',jobState='unknown'),
                      self.observation(state='restore_blocked',reason='execution_state_release_unverified',
                                       restored=False,jobState='terminal',retainedStreams=self.streams())):
            result=leases.validate_observation(value,self.binding,self.operation)
            self.assertEqual('resolve_blocker',result['nextAction'])
            self.assertFalse(result['replayAllowed'])
            self.assertFalse(result['ok'])

    def test_corrupt_malformed_and_overflow_streams_never_expose_private_input(self):
        base=self.observation(state='expired',reason='lease_deadline_reached',restored=True,jobState='terminal')
        good=self.streams()
        for stream in ({**good['stdout'],'sha256':'b'*64}, {**good['stdout'],'base64':'PRIVATE-MARKER'},
                       {**good['stdout'],'bytes':4097}, {**good['stdout'],'bytes':True}):
            with self.subTest(stream=stream), self.assertRaises(ValueError) as error:
                leases.validate_observation({**base,'retainedStreams':{**good,'stdout':stream}},self.binding,self.operation)
            self.assertNotIn('PRIVATE-MARKER',str(error.exception))

    @unittest.skipUnless(os.name=='nt','actual Windows PowerShell C# compiler')
    def test_actual_windows_native_program_compiles_without_any_execution_state_effect(self):
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                               '$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))'],
                              input=leases._prefix().encode(),capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf8','replace'))

    @unittest.skipUnless(os.name=='nt','actual Windows private child-token API')
    def test_native_restore_previous_output_buffer_reproduces_ack_failure_and_null_output_restores(self):
        source=(Path(__file__).parent/'fixtures/windows_token_restore_probe.ps1').read_bytes()
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
                               '$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))'],
                              input=source,capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf8','replace'))
        self.assertEqual({'schemaVersion':1,'oldRestoreSucceeded':False,'oldRestoreError':122,
                          'fixedRestoreSucceeded':True,'originalTokenRestored':True},json.loads(result.stdout))


if __name__=='__main__':unittest.main()
