"""Inert original snapshot custody and finite normal lease outcomes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from uuid import uuid4

from agent_tools import readiness_tart_macos_lease_executor as subject
from agent_tools import readiness_tart_macos_lease_bridge as bridge
from agent_tools import readiness_tart_macos_leases as leases


class LeaseResultTests(unittest.TestCase):
    def test_only_two_finite_source_roles_are_admissible_for_originals(self):
        current=subject.source_pins()
        historical={key:value for key,value in current.items()
                    if key not in {'readiness_tart_macos_lease_executor.py','readiness_tart_macos_lease_qualification.py'}}
        self.assertTrue(subject._original_source_roles(current))
        self.assertTrue(subject._original_source_roles(historical))
        for changed in ({**historical,'arbitrary.py':'a'*64},
                        {key:value for key,value in historical.items()if key!='readiness.py'},
                        {**current,'readiness.py':True}):
            self.assertFalse(subject._original_source_roles(changed))

    def test_cleanup_reconciliation_requires_the_exact_native_terminal_proof(self):
        operation=str(uuid4())
        value={'schemaVersion':1,'operationId':operation,'provider':'tart-macos','state':'restore_blocked',
               'jobState':'terminal','restored':False,'reason':'macos_assertion_release_unverified',
               'replayAllowed':False,'nextAction':'resolve_restoration_blocker'}
        self.assertEqual(subject.normalize(value,operation)['nextAction'],'reconcile_original')
        for changed in ({'schemaVersion':True},{'restored':None}):
            with self.assertRaises(subject.mac.MacBlocked):subject.normalize({**value,**changed},operation)
        for changed in ({'state':'unknown'},{'jobState':'unknown'},{'reason':'correlated_terminal'}):
            self.assertEqual(subject.normalize({**value,**changed},operation)['nextAction'],'resolve_blocker')
            with self.assertRaises(subject.mac.MacBlocked):
                subject.normalize({**value,**changed,'nextAction':'reconcile_original'},operation)

    def test_original_custody_uses_current_observer_and_refuses_new_work_after_source_update(self):
        original=subject._OriginalMacCustody.__new__(subject._OriginalMacCustody)
        historical={key:'a'*64 for key in subject.mac._source_pins()}
        original._admitted_sources=dict(historical)
        descriptor={'sources':dict(historical)}
        with self.assertRaises(subject.mac.MacBlocked):
            subject.mac.MacCustody._check_source_custody(original,descriptor)
        original._check_source_custody(descriptor)
        changed={'sources':{**historical,'readiness.py':'b'*64}}
        with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_original_observer_source_changed'):
            original._check_source_custody(changed)
        for name in ('ordinary_guest_call','guest_probe','prepare_lease_namespace','admit_lease_namespace','admit_guest_namespace'):
            with self.subTest(method=name),self.assertRaisesRegex(subject.mac.MacBlocked,'macos_original_lease_only'):
                getattr(original,name)()
        with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_lease_action_invalid'):
            original.original_lease_call(b'not admitted','acquire',str(uuid4()),expected_sha256='a'*64,deadline=0)

    def test_native_cleanup_states_preserve_truth_in_normal_finite_schema(self):
        operation=str(uuid4())
        value={'schemaVersion':1,'operationId':operation,'provider':'tart-macos','state':'restored','jobState':'terminal',
               'restored':True,'reason':'original_assertion_owner_exited','replayAllowed':False,'nextAction':'none'}
        result=subject.normalize(value,operation)
        self.assertEqual((result['state'],result['nativeState'],result['restored']),('failed','restored',True))
        self.assertEqual(value['state'],'restored')
        for changed in ({**value,'operationId':str(uuid4())},{**value,'replayAllowed':True},
                        {**value,'state':'invented'},{**value,'state':'unsubmitted','reason':'generic_absence'}):
            with self.assertRaises(subject.mac.MacBlocked):subject.normalize(changed,operation)

    def test_invalid_snapshot_refuses_before_provider_custody_or_connection(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(subject.mac,'MacCustody',side_effect=AssertionError('no native custody')):
            for value in ({},{'schemaVersion':True},{'schemaVersion':2,'provider':'tart-macos'}):
                with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_lease_snapshot_invalid'):
                    subject.OriginalMacLeaseExecutor(temporary,value)

    def test_malformed_nested_snapshot_has_finite_refusal_before_provider_custody(self):
        snapshot={'schemaVersion':2,'provider':'tart-macos','kind':subject.KIND,
                  'fixtureId':'controlled','registration':{},'binding':{},'namespace':{},
                  'capsule':{},'sources':subject.source_pins(),'qualification':{}}
        binding={'target':'local-tart-macos-'+'a'*24,'machine':'01234567-89ab-4def-8123-0123456789ab',
                 'boot':'11234567-89AB-4DEF-8123-0123456789AB','account':'502',
                 'principal':'toolrecovery','home':'/Users/toolrecovery','session':'100237'}
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(subject.mac,'MacCustody',side_effect=AssertionError('no native custody')):
            for changed in ({'binding':[]},{'binding':binding,'namespace':[]},
                            {'binding':binding,'namespace':{'root':[]}},
                            {'binding':{**binding,'account':'PRIVATE-invalid'},
                             'namespace':{'root':bridge.ROOT}}):
                with self.subTest(changed=tuple(changed)),self.assertRaisesRegex(subject.mac.MacBlocked,'^macos_lease_snapshot_invalid$')as error:
                    subject.OriginalMacLeaseExecutor(temporary,{**snapshot,**changed})
                self.assertNotIn('PRIVATE',str(error.exception))


@unittest.skipUnless(os.name=='posix','protected original capsule FD custody')
class OriginalCapsuleTests(unittest.TestCase):
    def test_actual_protected_registration_before_refuses_runtime_path_gate_current_reaches_custody(self):
        from importlib.machinery import SourceFileLoader
        import importlib.util
        from agent_tools import readiness_fixture_registry as registry
        path=Path(__file__).parent/'fixtures/macos_lease_registration.before.source'
        loader=SourceFileLoader('agent_tools._macos_registration_before',str(path))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        before=importlib.util.module_from_spec(spec);loader.exec_module(before)
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            directory=root/'.rag_index/readiness-fixtures';directory.mkdir(mode=0o700,parents=True)
            registration=directory/'controlled.json'
            binding={'target':'local-tart-macos-'+'a'*24,'machine':'01234567-89ab-4def-8123-0123456789ab',
                     'boot':'11234567-89AB-4DEF-8123-0123456789AB','account':'502',
                     'principal':'toolrecovery','home':'/Users/toolrecovery','session':'100237'}
            for module,old in ((before,True),(subject,False)):
                descriptor={'provider':'tart-macos','schemaVersion':3,'sources':module.source_pins()}
                registration.write_text(json.dumps(descriptor));registration.chmod(0o600)
                _,pin=registry._json(registration)
                snapshot={'schemaVersion':2,'provider':'tart-macos','kind':subject.KIND,'fixtureId':'controlled',
                          'registration':{'path':str(registration),'pin':pin},'binding':binding,
                          'namespace':{'root':bridge.ROOT},'capsule':{},'sources':module.source_pins(),'qualification':{}}
                with mock.patch.object(module,'_OriginalMacCustody',side_effect=RuntimeError('controlled_custody_boundary'))as custody:
                    if old:
                        with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_record_reference_invalid'):
                            module.OriginalMacLeaseExecutor(root,snapshot)
                        custody.assert_not_called()
                    else:
                        with self.assertRaisesRegex(RuntimeError,'controlled_custody_boundary'):
                            module.OriginalMacLeaseExecutor(root,snapshot)
                        custody.assert_called_once_with(root,'controlled',descriptor,pin)
                        for bad in ({'path':str(root/'.runtime/arbitrary.json'),'pin':pin},
                                    {'path':str(registration),'pin':{**pin,'sha256':'a'*64}}):
                            with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_lease_registration_changed'):
                                module.OriginalMacLeaseExecutor(root,{**snapshot,'registration':bad})

    def test_original_observer_uses_only_admission_pinned_source_and_rejects_replacement(self):
        from agent_tools import readiness_fixture_registry as registry
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root=Path(temporary);root.chmod(0o700)
            lifecycle=root/'.runtime/lifecycle';directory=lifecycle/'lease-executors'/'capsule'
            directory.mkdir(mode=0o700,parents=True)
            binding=leases.MacLeaseBinding('local-tart-macos-'+'a'*24,'01234567-89ab-4def-8123-0123456789ab',
                         '11234567-89AB-4DEF-8123-0123456789AB','502','toolrecovery','/Users/toolrecovery','100237')
            initial=json.loads(bridge.capsule(binding))
            import base64,hashlib
            namespace={'schemaVersion':1,'root':bridge.ROOT,'target':binding.target,'machine':binding.machine,'account':binding.account,
                       'rootGeneration':[1,2],'jobGeneration':[1,3],'admissionGeneration':[1,4],
                       'sources':{name:hashlib.sha256(base64.b64decode(body)).hexdigest()for name,body in initial['files'].items()}}
            raw=bridge.capsule(binding,namespace)
            path=directory/'capsule.json';path.write_bytes(raw);path.chmod(0o600)
            _,pin=registry._json(path)
            executor=subject.OriginalMacLeaseExecutor.__new__(subject.OriginalMacLeaseExecutor)
            executor.root=root;executor.custody=type('OwnedOriginal',(),{'lifecycle_root':lifecycle})()
            executor._snapshot={'binding':initial['binding'],'namespace':namespace,'capsule':{'path':str(path),'pin':pin},'qualification':{}}
            with mock.patch.object(subject.qualification,'load',return_value=SimpleNamespace(raw=raw,namespace=namespace)), \
                    mock.patch.object(Path,'read_bytes',side_effect=AssertionError('no current source reads')):
                self.assertEqual(executor._capsule(),raw)
            path.write_bytes(raw+b' ')
            with self.assertRaisesRegex(subject.mac.MacBlocked,'macos_public_proof_changed'):executor._capsule()


if __name__=='__main__':unittest.main()
