"""Whole hosted-dispatch counterfactual: builds do not require an old guest."""
import hashlib,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import windows_update_fixture_workflow as fixed,windows_msi_base_prepare as old_guest
from agent_tools.tests.test_windows_hosted_fixture_workflow import Runner,SHA,CORR

class GuestIndependentBuildTests(unittest.TestCase):
    def test_old_dispatch_requires_cp117_fixed_dispatch_preserves_source_and_journal_without_guest(self):
        folder=Path(__file__).parent/'fixtures/fixture_build_guest_dependency';raw=(folder/'before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((folder/'provenance.json').read_bytes())['sourceSha256'])
        name='agent_tools._fixture_guest_dependency_before';before=types.ModuleType(name);before.__package__='agent_tools';sys.modules[name]=before
        try:exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        finally:sys.modules.pop(name,None)
        inputs={'sourceSha':SHA,'baseVersion':'2.1.19','correlationId':CORR}
        with tempfile.TemporaryDirectory()as temporary,patch.object(old_guest,'readiness',side_effect=AssertionError('historical guest unavailable'))as observe:
            root=Path(temporary);red=Runner([])
            with self.assertRaisesRegex(AssertionError,'historical guest'):before.dispatch(root,inputs,runner=red)
            self.assertEqual(1,observe.call_count);self.assertFalse((root/'.runtime').exists())
            observe.reset_mock();green=Runner([(0,SHA+'\n'),(0,'')]);result=fixed.dispatch(root,inputs,runner=green)
            self.assertEqual('submitted',result['state']);observe.assert_not_called()
            journal=root/'.runtime/windows-msi-fixture-dispatch'/(CORR+'.json');record=json.loads(journal.read_bytes())
            self.assertEqual((SHA,'2.1.19','2.2.0',CORR),(record['sourceSha'],record['baseVersion'],record['targetVersion'],record['correlationId']))
            self.assertFalse(result['replayAllowed']);unchanged=journal.read_bytes()
            repeated=fixed.dispatch(root,inputs,runner=Runner([]));self.assertEqual('existing-intent',repeated['reason']);self.assertEqual(unchanged,journal.read_bytes())

if __name__=='__main__':unittest.main()
