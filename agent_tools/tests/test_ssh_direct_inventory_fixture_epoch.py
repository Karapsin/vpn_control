"""Complete historical fixture replay; archived producer graphs stay immutable."""
import hashlib,json,shutil,tempfile,types,unittest
from pathlib import Path
from agent_tools.tests import test_ssh_direct_ended_inventory_successor as current
from agent_tools.tests import test_ssh_direct_original6b_observation as original6b
from agent_tools.tests import test_ssh_direct_inventory_diagnostic as diagnostic
from agent_tools.tests import test_ssh_direct_route_local_reason as reason

FIXTURE=Path(__file__).parent/'fixtures/ssh_direct_inventory_epoch'

def authenticated(name):
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    for path,digest in records.items():
        body=(FIXTURE/path).read_bytes()
        if hashlib.sha256(body).hexdigest()!=digest:raise ValueError('epoch_beforeimage_changed')
    return (FIXTURE/name).read_bytes()

@unittest.skipUnless(current.CAPABLE,'POSIX private TempFS source custody required')
class HistoricalInventoryEpochTests(unittest.TestCase):
    def before(self,name,current_module):
        module=types.ModuleType('agent_tools.tests._epoch_'+name.replace('.','_'))
        module.__package__='agent_tools.tests';module.__file__=current_module.__file__
        exec(compile(authenticated(name),str(FIXTURE/name),'exec'),vars(module))
        return module
    def case(self,module,owner,method):
        result=unittest.TestResult();getattr(module,owner)(method).run(result);return result
    def assert_red_green(self,before,current_module,owner,method,needle):
        result=self.case(before,owner,method)
        self.assertFalse(result.errors,str(result.errors));self.assertEqual(1,len(result.failures));self.assertIn(needle,result.failures[0][1])
        result=self.case(current_module,owner,method)
        self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures))
    def replay(self,module):
        result=unittest.TestResult()
        module.EndedInventorySuccessorTests('test_real_existing_ended_history_preparation_preserves_all_prior_bytes').run(result)
        return result
    def test_complete_before_uses_live_population_fixed_uses_authenticated_archived_population(self):
        module=types.ModuleType('agent_tools.tests._before_inventory_epoch')
        module.__package__='agent_tools.tests';module.__file__=current.__file__
        exec(compile(authenticated('successor.before.source'),str(FIXTURE/'successor.before.source'),'exec'),vars(module))
        result=self.replay(module)
        self.assertEqual(1,len(result.errors));self.assertIn('ssh_direct_inventory.py',result.errors[0][1]);self.assertFalse(result.failures)
        result=self.replay(current)
        self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures))
        names=current.historical_sources()
        self.assertNotIn('ssh_direct_inventory.py',names);self.assertNotIn('private_config_custody.py',names)
        self.assertIn(b'FileNotFoundError',authenticated('native-errors.txt'))
    def test_archived_content_and_manifest_drift_never_silently_admitted(self):
        original=current.history.CURRENT_PROVIDER_SOURCE.parent
        for name in ('ssh_transport.py','provenance.json'):
            with self.subTest(name=name),tempfile.TemporaryDirectory()as tmp:
                folder=Path(tmp)/'archive';shutil.copytree(original,folder)
                path=folder/name;path.write_bytes(path.read_bytes()+b'\n')
                with self.assertRaisesRegex(ValueError,'historical_(manifest|source)_changed'):
                    current.historical_sources(folder)
    def test_complete_original6b_before_mixes_current_authority_fixed_preserves_original_epoch(self):
        before=self.before('ssh_direct_original6b_observation.before.source',original6b)
        self.assert_red_green(before,original6b,'Original6bObservationTests','test_actual_original_ended_status_appends_terminal_only',"'ended' != 'unknown'")
    def test_complete_diagnostic_before_mixes_current_custody_fixed_preserves_snapshot_epoch(self):
        before=self.before('ssh_direct_inventory_diagnostic.before.source',diagnostic)
        old_context=self.before('diagnostic_context.before.source',diagnostic.ctx)
        before.ctx=old_context
        self.assert_red_green(before,diagnostic,'DirectInventoryDiagnosticTests','test_whole_retained_builder_preserves_actual_missing_inventory_event','unclassified_inventory')
    def test_complete_terminal_before_v2_fragment_misses_v3_seed_fixed_uses_v2_protocol(self):
        before=self.before('ssh_direct_route_local_reason.before.source',reason)
        self.assert_red_green(before,reason,'ActualDirectRouteLocalReasonTests','test_preserved_missing_terminal_beforeimage_and_fixed_refusal_keep_original_unknown','intent_binding_changed')

if __name__=='__main__':unittest.main()
