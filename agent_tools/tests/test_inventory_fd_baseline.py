"""Real deferred descriptor finalization must not counterfeit an owned FD leak."""
import gc,hashlib,json,os,tempfile,types,unittest
from pathlib import Path
from agent_tools.tests import test_ssh_direct_inventory_diagnostic as current

FIXTURE=Path(__file__).parent/'fixtures/inventory_fd_baseline'

def before():
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    if set(records)!={'before.source','native-failure.txt'}:raise ValueError('fd_baseline_fixture_scope')
    for name,digest in records.items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()!=digest:raise ValueError('fd_baseline_fixture_changed')
    module=types.ModuleType('agent_tools.tests._fd_baseline_before');module.__file__=current.__file__;module.__package__='agent_tools.tests'
    exec(compile((FIXTURE/'before.source').read_bytes(),str(FIXTURE/'before.source'),'exec'),vars(module))
    return module

@unittest.skipUnless(current.COORDINATOR_CAPABLE,'actual POSIX descriptors required')
class InventoryFdBaselineTests(unittest.TestCase):
    def replay(self,module):
        gc.collect();closed=[];enabled=gc.isenabled();gc.disable()
        try:
            with tempfile.TemporaryDirectory()as tmp:
                fd=os.open(str(Path(tmp)/'unrelated-finalizer'),os.O_RDWR|os.O_CREAT,0o600)
                class Deferred:
                    def __init__(self):self.cycle=self
                    def __del__(self):os.close(fd);closed.append(fd)
                owner=Deferred();del owner
                case=module.DirectInventoryDiagnosticTests('test_invalid_diagnostic_payload_refuses_without_private_field_leak')
                original=case.test_invalid_diagnostic_payload_refuses_without_private_field_leak
                def controlled_collection():gc.collect();original()
                case.test_invalid_diagnostic_payload_refuses_without_private_field_leak=controlled_collection
                result=unittest.TestResult();case.run(result)
                self.assertEqual([fd],closed)
                return result
        finally:
            gc.collect()
            if enabled:gc.enable()

    def test_complete_before_false_leak_fixed_collects_unrelated_pending_owner_before_baseline(self):
        old=self.replay(before());self.assertFalse(old.errors);self.assertEqual(1,len(old.failures));self.assertIn('owned parent or leaf FD leaked',old.failures[0][1])
        fixed=self.replay(current);self.assertTrue(fixed.wasSuccessful(),str(fixed.failures)+str(fixed.errors))

    def test_positive_owned_retained_descriptor_still_fails_strict_equality(self):
        case=current.DirectInventoryDiagnosticTests('runTest');case.setUp()
        with tempfile.TemporaryDirectory()as tmp:
            fd=os.open(str(Path(tmp)/'owned-unclosed'),os.O_RDWR|os.O_CREAT,0o600)
            try:
                with self.assertRaisesRegex(AssertionError,'owned parent or leaf FD leaked'):case.tearDown()
            finally:os.close(fd)

if __name__=='__main__':unittest.main()
