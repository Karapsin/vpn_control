"""Replay complete old/current gateway-auth tests without any external SSH child."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools.tests import test_native_fixture_preflight as current_preflight
from agent_tools.tests import test_native_scenario_ssh as current_scenario

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/native_preflight_run_boundary'


def authenticated(name):
    provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
    if provenance['schemaVersion']!=1 or set(provenance['sourceSha256'])!={'before.source','scenario.before.source','native-failure.txt'}:
        raise AssertionError('runner seam fixture scope changed')
    values={}
    for path,expected in provenance['sourceSha256'].items():
        raw=(FIXTURE/path).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:raise AssertionError('runner seam fixture changed: '+path)
        values[path]=raw
    return values[name]


class PreflightTransportSeamTests(unittest.TestCase):
    def before(self,name,original):
        # Preserve the original repository-relative data lookup while compiling
        # the complete authenticated original file with its retained trace name.
        alias='agent_tools.tests._gateway_runner_before_'+name.split('.')[0]
        module=types.ModuleType(alias);module.__file__=str(ROOT/'agent_tools/tests'/original)
        module.__package__='agent_tools.tests';sys.modules[alias]=module
        self.addCleanup(sys.modules.pop,alias,None)
        top_names=('ssh_transport','native_scenario_bundle','native_scenario_execution','native_scenario_ssh')
        previous={key:sys.modules.get(key)for key in top_names}
        try:exec(compile(authenticated(name),str(FIXTURE/name),'exec'),module.__dict__)
        finally:
            for key,value in previous.items():
                if value is None:sys.modules.pop(key,None)
                else:sys.modules[key]=value
        return module

    def reroot(self,*modules):
        # Each replayed preflight method derives SshConfig.root from __file__, and
        # build_ssh_argv probes that root's private inventory and .rag_index route
        # state. Re-root both replays at an owned directory holding only a byte copy
        # of the fixed guest helper the probe reads; the guarded boundary is unchanged.
        raw=tempfile.TemporaryDirectory();self.addCleanup(raw.cleanup);root=Path(raw.name)
        (root/'scripts').mkdir();(root/'scripts/native_fixture_preflight.py').write_bytes((ROOT/'scripts/native_fixture_preflight.py').read_bytes())
        for module in modules:self.enterContext(mock.patch.object(module,'__file__',str(root/'agent_tools/tests'/Path(module.__file__).name)))

    def replay(self,module,owner,method,transport):
        result=unittest.TestResult()
        # This is the actual central Popen boundary the obsolete mock missed.
        # No external SSH process can start during the RED replay.
        with mock.patch.object(transport,'popen_ssh',side_effect=FileNotFoundError('controlled-no-ssh-child'))as actual,\
             mock.patch.object(transport,'_private_config_path',wraps=transport._private_config_path)as inventory:
            getattr(module,owner)(method).run(result)
        # No replay may consult the checkout's private VM inventory.
        self.assertNotIn(ROOT,[Path(call.args[0]).resolve()for call in inventory.call_args_list])
        return result,actual.call_count

    def test_complete_preflight_before_mock_escapes_actual_boundary_current_intercepts(self):
        old=self.before('before.source','test_native_fixture_preflight.py');self.reroot(old,current_preflight)
        owner='NativeFixturePreflightTest';method='test_scheduled_static_probe_uses_local_gateway_auth_through_three_hosts'
        result,calls=self.replay(old,owner,method,old.ssh_transport)
        self.assertEqual([],result.errors);self.assertEqual(1,len(result.failures));self.assertIn('unexpectedly None',result.failures[0][1]);self.assertEqual(1,calls)
        result,calls=self.replay(current_preflight,owner,method,current_preflight.ssh_transport)
        self.assertTrue(result.wasSuccessful(),str(result.failures)+str(result.errors));self.assertEqual(0,calls)
        self.assertIn(b'AssertionError: unexpectedly None',authenticated('native-failure.txt'))

    def test_complete_scenario_before_mock_escapes_actual_boundary_current_intercepts(self):
        old=self.before('scenario.before.source','test_native_scenario_ssh.py')
        owner='NativeScenarioSshTest';method='test_driver_uses_local_gateway_askpass_for_nested_guest'
        result,calls=self.replay(old,owner,method,old.transport)
        self.assertEqual([],result.errors);self.assertEqual(1,len(result.failures));self.assertIn('None',result.failures[0][1]);self.assertEqual(1,calls)
        result,calls=self.replay(current_scenario,owner,method,current_scenario.transport)
        self.assertTrue(result.wasSuccessful(),str(result.failures)+str(result.errors));self.assertEqual(0,calls)


if __name__=='__main__':unittest.main()
