"""Opaque exact-target creator inventory reaches the real host idle decision."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import types
import unittest
from unittest import mock
from uuid import uuid4
from agent_tools import readiness,readiness_windows as main,readiness_windows_remote as packets
from agent_tools import readiness_windows_creator_registry as registry
from agent_tools.tests import test_windows_creator_registry as registry_tests

FIXTURE=Path(__file__).parent/'fixtures/windows_creator_observer_integration'


def before(name):
    if name not in {'main.before.source','remote.before.source'}:raise ValueError('unreviewed_creator_source')
    raw=(FIXTURE/name).read_bytes();pins=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    if hashlib.sha256(raw).hexdigest()!=pins[name]:raise ValueError('creator_before_changed')
    module=types.ModuleType('agent_tools._creator_observer_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/name)
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary local private metadata')
class CreatorObserverTests(unittest.TestCase):
    def setUp(self):
        case=registry_tests.CreatorRegistryTests('test_actual_initialized_namespace_retained_then_discovered_without_transport_or_writes');case.setUp();self.addCleanup(case.doCleanups)
        self.case=case;self.binding=case.binding
        self.handle=registry.retain(case.root,case.plan,case.host,case.namespace)
        self.root=Path(self.binding['spec']['root']);self.root.mkdir(mode=0o700)

    def project(self,producer,handle=None):
        kwargs={}if handle is None else {'creator_handle':handle}
        raw=producer.program(self.binding,'observe',str(uuid4()),**kwargs)
        nodes=[n for n in ast.walk(ast.parse(raw))if isinstance(n,ast.FunctionDef)and n.name=='host_work']
        self.assertEqual(1,len(nodes))
        def require(value,reason):
            if not value:raise ValueError(reason)
        namespace={'root':self.root,'SPEC':self.binding['spec'],'os':os,'re':re,'ORIGINAL_HOST_PHASES':[],
            'CREATOR_ENROLLED':handle is not None,'require':require}
        if handle is not None:
            definitions=handle.definitions();self.assertIn(definitions.encode(),raw);exec(definitions,namespace)
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'complete generated host_work','exec'),namespace)
        return namespace['host_work']()

    def test_complete_before_presence_blocked_current_exact_empty_namespace_visible(self):
        old=self.project(before('remote.before.source'))
        self.assertFalse(old['visibilityComplete'])
        current=self.project(packets,self.handle)
        self.assertTrue(current['visibilityComplete']);self.assertEqual([],current['unresolved'])
        self.assertFalse(self.project(packets)['visibilityComplete'])
        (self.root/'managed-create-host-original.json').write_text('{}')
        self.assertFalse(self.project(packets,self.handle)['visibilityComplete'])

    def test_any_consumed_unknown_creator_blocks_even_when_controller_exited(self):
        op=str(uuid4());(Path(self.case.namespace['root'])/op).mkdir(mode=0o700)
        current=self.project(packets,self.handle)
        self.assertTrue(current['visibilityComplete'])
        self.assertIn({'receipt':'creator-'+op,'reason':'creator_bootstrap_unresolved'},current['unresolved'])

    def test_backend_before_omits_handle_current_pure_discovery_passes_it(self):
        directory=self.case.root/'.runtime';directory.mkdir(mode=0o700);credential=directory/'host-public-test.secret';credential.write_bytes(b'public-only-test');credential.chmod(0o600)
        for producer in (before('main.before.source'),main):
            backend=producer.WindowsBackend(self.case.root,self.binding,'S-1-5-21-1-2-3-1000',capabilities=frozenset({'reboot'}),credential_file=str(credential))
            self.addCleanup(backend.close)
            with mock.patch.object(producer.job_module,'namespace_binding',return_value=None),mock.patch.object(backend,'_run',side_effect=ValueError('before_transport'))as dispatch:
                with self.assertRaisesRegex(ValueError,'before_transport'):backend.observe(readiness.Requirements(frozenset({'guest_agent'})),99999999999)
            handle=dispatch.call_args.kwargs.get('creator_handle')
            self.assertEqual(producer is main,handle is not None)
            if handle is not None:self.assertEqual(self.case.namespace,handle.guard()['namespace'])

    def test_forged_foreign_replaced_original_never_crosses_packet_generation(self):
        with self.assertRaises(ValueError):packets.program(self.binding,'observe',str(uuid4()),creator_handle={'ready':True})
        foreign=json.loads(json.dumps(self.binding));foreign['spec']['memoryMiB']+=1024
        with self.assertRaises(ValueError):packets.program(foreign,'observe',str(uuid4()),creator_handle=self.handle)
        directory=registry._HANDLES[self.handle][0];path=directory/'creator-original.json'
        replacement=path.with_suffix('.replacement');replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
        with self.assertRaises(ValueError):packets.program(self.binding,'observe',str(uuid4()),creator_handle=self.handle)
        backend=main.WindowsBackend(self.case.root,self.binding,'S-1-5-21-1-2-3-1000')
        backend.capabilities=frozenset({'reboot'})
        with mock.patch.object(backend,'_run',side_effect=AssertionError('corrupt_original_crossed_transport'))as dispatch:
            with self.assertRaisesRegex(readiness.AdapterBlocked,'integrity_mismatch'):backend.observe(readiness.Requirements(frozenset({'guest_agent'})),99999999999)
        dispatch.assert_not_called()

    def test_creator_source_markers_are_required_before_dispatch(self):
        for module in (registry,registry.creator,registry.custody,registry.creator.lifecycle):
            with self.subTest(module=module.__name__),mock.patch.object(module,'_EXECUTING_CODE',None):
                with self.assertRaisesRegex(ValueError,'windows_producer_source_changed'):main._source_pins()


if __name__=='__main__':unittest.main()
