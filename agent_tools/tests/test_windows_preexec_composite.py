"""Full backend admission discovers accepted evidence and builds a strict idle packet."""
import ast
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest import mock
from agent_tools import readiness,readiness_windows as windows,readiness_windows_idle as idle,readiness_windows_remote as packets,readiness_windows_preexec as preexec
from agent_tools.tests import test_readiness_windows_preexec as proof_tests
PROOF_PATH=proof_tests.PROOF_PATH

FIXTURE=Path(__file__).parent/'fixtures/windows_preexec_composite'


def before(name):
    if name not in {'main.before.source','idle.before.source','remote.before.source'}:raise ValueError('unreviewed_source')
    raw=(FIXTURE/name).read_bytes();expected=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256'][name]
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('preexec_composite_before_changed')
    module=types.ModuleType('agent_tools._preexec_composite_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/name)
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class PreexecCompositeTests(unittest.TestCase):
    def setUp(self):
        self.case=proof_tests.PreexecTests('test_actual_original_controller_phase_and_native_custody_join_without_executing_old_source')
        self.case.setUp();self.addCleanup(self.case.doCleanups)
        relative=next(path for path in self.case.provenance['evidenceFiles']if path.endswith('/executor-snapshot.json'))
        self.snapshot=json.loads((self.case.root/relative).read_bytes());self.binding=self.snapshot['binding'];self.sid=self.snapshot['expectedSid']
        self.target='windows:'+self.binding['spec']['host']+':'+self.case.binding.machine
        self.proof=preexec.register_preexec_rejection(self.case.root,self.target,self.case.binding,PROOF_PATH,self.case.digest())

    def test_complete_backend_before_omits_accepted_proof_RED_fixed_admits_typed_proof_GREEN(self):
        credential=self.case.root/'.runtime/credential.secret';credential.write_bytes(b'public-test-credential\n');credential.chmod(0o600)
        for label,module in [('before',before('main.before.source')),('fixed',windows)]:
            with self.subTest(source=label):
                backend=module.WindowsBackend(self.case.root,self.binding,self.sid,capabilities=frozenset({'reboot'}),credential_file=str(credential.resolve()))
                with mock.patch.object(module.job_module,'namespace_binding',return_value=self.case.binding),mock.patch.object(backend,'_run',side_effect=ValueError('stop_before_remote'))as dispatch:
                    with self.assertRaisesRegex(ValueError,'stop_before_remote'):backend.observe(readiness.Requirements(frozenset({'guest_agent'})),99999999999)
                proofs=dispatch.call_args.kwargs.get('preexec_rejections',())
                self.assertEqual(0 if label=='before'else 1,len(proofs))
                if proofs:self.assertEqual(self.proof.guard(),proofs[0].guard())
                backend.close()

    def test_complete_packet_contains_one_original_job_definition_and_only_typed_accepted_rejection(self):
        source=packets.program(self.binding,'observe','a0000000-0000-4000-8000-000000000001',idle=True,expected_sid=self.sid,
            job_root_generation=self.case.binding.root_generation,job_admission_generation=self.case.binding.admission_generation,preexec_rejections=(self.proof,))
        nodes=ast.parse(source).body;script=next(ast.literal_eval(n.value)for n in nodes if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='IDLE_SCRIPT'for t in n.targets))
        self.assertEqual(1,script.count('class NativeJob'));self.assertEqual(1,script.count('class NativePreexecInventory'))
        _,config=preexec.inventory_component(self.case.binding.machine,self.case.binding.boot,self.case.binding.root_generation,self.case.binding.admission_generation,rejections=(self.proof,))
        self.assertEqual(self.proof.guard(),config['rejections'][0])
        self.assertIn(windows.job_module._literal(config),script)
        self.assertIn('$preexecConfig.boot=$sessionFacts.boot',script)
        self.assertEqual(self.case.binding.boot,config['rejections'][0]['boot'])
        self.assertEqual(1,sum(line.startswith('[Console]::WriteLine(')for line in script.splitlines()))

    def test_untyped_foreign_or_changed_evidence_cannot_become_a_guest_exemption(self):
        args=(self.case.binding.machine,None,'recovery',self.sid,None,self.case.binding.root_generation,self.case.binding.admission_generation)
        with self.assertRaises((ValueError,AttributeError)):idle.powershell_source(*args,preexec_rejections=({'ready':True},))
        data=self.case.root/PROOF_PATH;data.write_bytes(data.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'windows_preexec_evidence_changed'):idle.powershell_source(*args,preexec_rejections=(self.proof,))

    def test_retained_before_idle_and_packet_builders_have_no_proof_override(self):
        for name,function in [('idle.before.source','powershell_source'),('remote.before.source','program')]:
            module=before(name);self.assertNotIn('preexec_rejections',getattr(module,function).__code__.co_varnames)


if __name__=='__main__':unittest.main()
