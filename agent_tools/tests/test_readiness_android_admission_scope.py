"""Causal admission checks: foreign leases and original durable seed ownership."""
import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import durable_remote_job as jobs, readiness, readiness_android as android
from agent_tools import readiness_fixture_registry as registry, readiness_lease_workflow as leases
from agent_tools import readiness_providers as providers
from agent_tools.tests import test_readiness_android as existing


def before_method(name, filename, flag):
    if not os.environ.get(flag):
        return None
    if os.environ[flag] != '1':
        raise AssertionError('causal opt-in must be literal1')
    path = Path(__file__).parent / 'fixtures' / filename
    namespace = dict(vars(android))
    exec(compile(path.read_text(), str(path), 'exec'), namespace)
    return namespace[name]


class AdmissionScopeTest(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.AndroidLifecycleTest('test_reused_original_pid_blocks_replacement')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.addCleanup(self.fixture.temporary.cleanup)
        self.root = self.fixture.root

    def test_validated_foreign_lease_cannot_block_this_target_but_unknown_and_own_work_do(self):
        backend = self.fixture.backend(); backend._operator_held = True
        backend.descriptor.update(memoryMiB=2048, jobBaseline=['init'])
        observed = readiness.Observation('owned-fixture', 'task-avd', guest='running', boot='boot')
        operation = str(uuid4()); fixture_id = 'foreign-fixture'
        state, _ = leases._paths(self.root, fixture_id, create=True)
        value = {'schemaVersion': 2, 'fixtureId': fixture_id, 'operationId': operation,
                 'provider': 'raw-qemu-windows', 'ttlSeconds': 5,
                 'executor': {'provider': 'raw-qemu-windows'},
                 'readyIdentities': ['foreign-target', 'foreign-machine', 'connection', 'boot', 'account', 'session'],
                 'sources': dict(leases._LOADED)}
        jobs._publish(state / (operation + '.json'), value)
        installers = ('Active install sessions:\n\nFinalized install sessions:\n\n'
                      'Historical install sessions:\n\nLegacy install sessions:\n{}\n'
                      'Gentle update with constraints info:\nhasPendingIdleJob=false\n')
        def command(args, deadline):
            if args == ['shell', 'ps', '-A', '-o', 'NAME']: return 'NAME\ninit\nps\n', 'same'
            if args == ['shell', 'dumpsys', 'package', 'installs']: return installers, 'same'
            if args == ['shell', 'pm', 'list', 'packages', 'com.kardinal.vpncontrol']: return '', 'same'
            self.fail('unexpected fixed probe')
        old = before_method('_idle', 'android_lease_scope_before.py', 'VPN_CONTROL_ANDROID_LEASE_SCOPE_BEFORE')
        method = lambda: old(backend, observed, time.monotonic()+5) if old else backend._idle(observed, time.monotonic()+5)
        with mock.patch.object(backend, '_current', return_value=({'pid':123,'birth':'same'}, 'live', None)), \
             mock.patch.object(backend, '_launches', return_value=[]), \
             mock.patch.object(android.visual, '_read_reservations', return_value={'android':{'memory_mib':2048,'pid':123}}), \
             mock.patch.object(backend.adb, '_command', side_effect=command), \
             mock.patch.object(leases, 'workflow', return_value={'state':'active','restored':False,'jobState':'running'}) as status:
            self.assertEqual(method().idle_visibility, readiness.IDLE_VISIBILITY)
            status.assert_not_called()
            # Same validated target identity must still observe its original.
            value['readyIdentities'][:2] = ['owned-fixture', 'task-avd']
            (state / (operation+'.json')).write_text(json.dumps(value))
            with self.assertRaisesRegex(providers.ProviderError, 'android_idle_work_active'): method()
            status.assert_called_once()
            # Invalid foreign metadata cannot be used to hide unknown work.
            value['readyIdentities'] = ['foreign-target']
            (state / (operation+'.json')).write_text(json.dumps(value))
            with self.assertRaisesRegex(providers.ProviderError, 'android_idle_visibility_incomplete'): method()
            value['readyIdentities'] = ['foreign-target', 'foreign-machine', 'connection', 'boot', 'account', 'session']
            (state / (operation+'.json')).write_text(json.dumps(value))
            jobs._publish(state / 'unclassified.json', {})
            with self.assertRaisesRegex(providers.ProviderError, 'android_idle_visibility_incomplete'): method()

    def test_same_original_durable_seed_closes_pending_resource_binding_once(self):
        native = self.root / '.runtime' / 'native-jobs'; native.mkdir(parents=True, mode=0o700)
        generation = jobs.root_generation(native); operation = str(uuid4())
        child = self.root / 'emulator'
        child.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(60)\n'); child.chmod(0o700)
        program = android.launch_program(native, operation, self.fixture.binding, [str(child)], {'PATH':os.defpath})
        jobs.submit(native, operation, self.fixture.binding, program, generation=generation)
        deadline=time.monotonic()+10
        while not (native/operation/'emulator.json').exists() and time.monotonic()<deadline: time.sleep(.01)
        actor = jobs._record(native/operation/'emulator.json')['actor']
        self.fixture.descriptor.update(initialActor=actor, memoryMiB=2048, initialOwner={
            'jobRoot':str(native),'operationId':operation,'hostBinding':vars(self.fixture.binding),
            'rootGeneration':list(generation),'programSha256':program.digest,
            'programPin':registry._body(native/operation/'program.py')[1]})
        backend=self.fixture.backend();backend._operator_held=True
        requirement=readiness.Requirements(frozenset({'guest_agent'}))
        ready=readiness.ReadyContext(str(uuid4()),'owned-fixture','task-avd','actual-adb-generation','boot',None,None,requirement)
        observed=readiness.Observation('owned-fixture','task-avd',connection='actual-adb-generation',boot='boot')
        reservations={'android':{'memory_mib':2048,'pid':0}}
        plan={'directory':str(backend.avd_root),'state':'retained','writerPid':0}; plans=mock.MagicMock()
        plans._read.return_value={'plans':{backend.storage_plan:plan}}
        def bind(value):
            self.assertEqual(value, actor)
            reservations['android']['pid']=actor['pid'];plan['writerPid']=actor['pid']
        old=before_method('reconcile_ready','android_seed_binding_before.py','VPN_CONTROL_ANDROID_SEED_BIND_BEFORE')
        method=lambda:old(backend,ready,time.monotonic()+5) if old else backend.reconcile_ready(ready,time.monotonic()+5)
        try:
            self.assertEqual(backend._current(),(actor,'live',None))
            with mock.patch.object(backend,'observe',return_value=observed), \
                 mock.patch.object(android.visual,'_read_reservations',return_value=reservations), \
                 mock.patch.object(android.storage,'StoragePlans',return_value=plans), \
                 mock.patch.object(backend,'_bind_actor',side_effect=bind) as binding:
                method();self.assertEqual(reservations['android']['pid'],actor['pid'])
                method();self.assertEqual(binding.call_count,1)
                self.assertEqual(backend._current(),(actor,'live',None))
                self.assertEqual(len(list(native.iterdir())),1)
        finally:
            if jobs._birth(actor['pid'])==actor['birth']:os.kill(actor['pid'],signal.SIGTERM)
            while time.monotonic()<deadline and jobs.observe(native,operation,self.fixture.binding,generation=generation)['state']!='terminal':time.sleep(.02)


if __name__ == '__main__':
    unittest.main()
