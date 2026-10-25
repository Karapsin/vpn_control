"""Unexposed typed closure admission/source gates; no ROOT or VM qualification."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import readiness_windows_bootstrap_closure as closure
from agent_tools import readiness_windows_seed_detach as seed
from agent_tools import ssh_transport
from agent_tools.tests import test_windows_seed_detach as fixtures
from agent_tools.tests.test_windows_seed_reader_scope import controlled_request


class BootstrapClosureTests(unittest.TestCase):
    def test_public_dtos_cannot_mint_admission_or_closure_or_reach_transport(self):
        for cls in (closure.ClosureAdmission,closure.BootstrapClosure):
            with self.assertRaises(TypeError):cls()
            with self.assertRaises(ValueError):object.__new__(cls).as_dict()
        with mock.patch.object(ssh_transport,'admitted_transport',side_effect=AssertionError('unqualified transport')):
            with self.assertRaises(ValueError):closure.collect(Path('/unused'),{},object(),guard=lambda:None)
        self.assertFalse(closure.QUALIFIED_RECOVERIES)

    @unittest.skipIf(os.name!='posix'or os.geteuid()==0,'actual ordinary private original packets required')
    def test_atomic_original_admission_id_custody_and_fixed_source_only(self):
        done=[False];original_attach=seed.attach_ejection
        def inspect_original(original,packet):
            returned=original_attach(original,packet)
            if done[0]:return returned
            done[0]=True
            with tempfile.TemporaryDirectory()as directory:
                repo=Path(directory);repo.chmod(0o700)
                admitted=closure.admission(repo,original);first=admitted.as_dict()
                self.assertEqual(closure.admission(repo,original).as_dict(),first)
                request=controlled_request(seed,original,packet)
                # Controlled protocol factory solely for source composition.
                # No protected observer is simulated or native claim made.
                witness=object.__new__(seed.ReaderWitness)
                result={'complete':True,'holders':[],'observedNs':1_000_000,'deadlineNs':30_001_000_000}
                seed._READERS[witness]={'original':original,'request':__import__('json').dumps(request),'result':__import__('json').dumps(result),
                    'guards':(),'deadline':time.monotonic()+20,'consumedBy':None}
                try:
                    witness.consume(original,original.as_dict()['operationId'])
                    source=closure.program(original,witness,admitted);compile(source,'fixed typed original closure','exec')
                    self.assertTrue(first['admissionId'].encode()in source)
                    self.assertTrue(b'windows_bootstrap_foreign_closure'in source)
                    self.assertTrue(b'_reader_clock_guard(CLOSE_REQUEST,CLOSE_READERS)'in source)
                    self.assertTrue(b'ordinarySigninAllowed' in source)
                    import ast
                    self.assertFalse(any(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='_eject_selected'for node in ast.walk(ast.parse(source))))
                    self.assertIsNone(closure.reopen(repo,original))
                    root_path=closure._ADMISSIONS[admitted][0]
                    target=root_path/'admission.json';replacement=target.with_suffix('.samebytes')
                    replacement.write_bytes(target.read_bytes());replacement.chmod(0o600);os.replace(replacement,target)
                    with self.assertRaises(ValueError):admitted.as_dict()
                    with self.assertRaises(ValueError):closure.admission(repo,original)
                finally:seed._READERS.pop(witness,None)
            return returned
        with mock.patch.object(seed,'attach_ejection',side_effect=inspect_original):
            result=unittest.TestResult();fixtures.SeedOwnerSourceTests('test_fixed_ejection_builder_uses_actual_opaque_host_namespace_and_original_packet').run(result)
        self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures));self.assertTrue(done[0])


if __name__=='__main__':unittest.main()
