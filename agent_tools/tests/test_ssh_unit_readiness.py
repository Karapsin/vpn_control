"""Complete old/current unit callers stay isolated at their newly required seams."""
import contextlib,hashlib,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import readiness,ssh_transport
from agent_tools.tests import test_ssh_acceptance_route_integration as acceptance
from agent_tools.tests import test_ssh_connection_recovery as recovery
from agent_tools.tests import test_private_config_custody as private

FIXTURE=Path(__file__).parent/'fixtures/ssh_unit_readiness'

def before(name,current):
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    for path,digest in records.items():
        if hashlib.sha256((FIXTURE/path).read_bytes()).hexdigest()!=digest:raise ValueError('unit_readiness_fixture_changed')
    module=types.ModuleType('agent_tools.tests._unit_before_'+name.replace('.','_'));module.__package__='agent_tools.tests';module.__file__=current.__file__
    previous={key:sys.modules.get(key)for key in ('ssh_transport','ssh_connection_recovery')}
    try:exec(compile((FIXTURE/(name+'.before.source')).read_bytes(),str(FIXTURE/(name+'.before.source')),'exec'),vars(module))
    finally:
        for key,value in previous.items():
            if value is None:sys.modules.pop(key,None)
            else:sys.modules[key]=value
    return module

class UnitReadinessBoundaryTests(unittest.TestCase):
    def run_case(self,module,owner,method):
        result=unittest.TestResult();getattr(module,owner)(method).run(result);return result
    def test_routing_before_omits_admission_current_unit_stays_inert_and_dispatches(self):
        old=before('test_ssh_acceptance_route_integration.py',acceptance)
        server=acceptance.server;original=server._agent_module;calls=[]
        @contextlib.contextmanager
        def refused(root,host,operation,**kwargs):
            calls.append(host);raise readiness.ReadinessBlocked('controlled-unit-no-transport',operation)
            yield
        facade=types.SimpleNamespace(**{**vars(ssh_transport),'admitted_transport':refused})
        def dependency(name):
            if name=='ssh_transport':return facade
            if name=='readiness':return readiness
            return original(name)
        method='test_package_dispatch_keeps_identity_and_device'
        with mock.patch.object(server,'_agent_module',side_effect=dependency):
            result=self.run_case(old,'AcceptanceRouteIntegration',method)
            self.assertFalse(result.errors,str(result.errors));self.assertEqual(1,len(result.failures));self.assertEqual(['archlinux'],calls)
            calls.clear();result=self.run_case(acceptance,'AcceptanceRouteIntegration',method)
            self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures));self.assertFalse(calls)
    def test_builder_before_reads_coordinator_cwd_current_uses_owned_empty_context(self):
        old=before('test_ssh_connection_recovery.py',recovery);method='test_real_transport_accepts_encoded_remote_recovery_command'
        previous=Path.cwd()
        with tempfile.TemporaryDirectory()as tmp:
            directory=Path(tmp)/'.rag_index/readiness-ssh-master/gateway';directory.mkdir(parents=True,mode=0o700)
            pointer=directory/'current.json';pointer.write_text(json.dumps({'recoveryId':'a'*64}));pointer.chmod(0o600)
            try:
                os.chdir(tmp);result=self.run_case(old,'SshConnectionRecoveryTest',method)
                self.assertEqual(1,len(result.errors));self.assertIn('Admitted readiness SSH master is unavailable',result.errors[0][1])
                result=self.run_case(recovery,'SshConnectionRecoveryTest',method)
                self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures))
            finally:os.chdir(previous)
    @unittest.skipUnless(os.name=='posix','actual Python helper poison-cache proof')
    def test_complete_helper_copy_before_missing_dependency_current_keeps_actual_pyc_red_green(self):
        old=before('test_private_config_custody.py',private);method='test_helper_timestamp_valid_pyc_actual_red_and_held_bytes_green'
        result=self.run_case(old,'PrivateConfigTests',method)
        self.assertFalse(result.failures);self.assertEqual(2,len(result.errors));self.assertTrue(all('readiness' in trace for _,trace in result.errors))
        result=self.run_case(private,'PrivateConfigTests',method)
        self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures))

if __name__=='__main__':unittest.main()
