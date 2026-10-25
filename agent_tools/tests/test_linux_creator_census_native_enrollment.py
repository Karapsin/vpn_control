"""Real Linux creator pre-VM root census coverage must execute, including privilege prerequisites."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/linux_creator_census_native_enrollment'
CASE='agent_tools.tests.test_windows_creator_prevm_refusal_recovery.LinuxRootCensusCausalTests.test_whole_before_ordinary_scan_red_generated_root_census_green'


class LinuxCreatorCensusNativeEnrollmentTests(unittest.TestCase):
    def command(self,raw):
        text=raw.decode();start=text.index('      - name: Test real Linux creator pre-VM root census\n')
        step=text[start:].split('\n      - name:',1)[0]
        self.assertIn('timeout-minutes: 5',step)
        self.assertIn('sudo -- "$pythonLocation/bin/python"',step)
        body=step.split("<<'PY'\n",1)[1].rsplit('\n          PY',1)[0]
        return '\n'.join(line.removeprefix('          ') for line in body.splitlines())

    def test_whole_before_has_no_creator_census_current_enrolls_exact_case(self):
        raw=(FIXTURE/'workflow.before.source').read_bytes();pin=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(pin['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(pin['bytes'],len(raw))
        with self.assertRaises(ValueError):self.command(raw)
        code=self.command((ROOT/'.github/workflows/fast-checks.yml').read_bytes());tree=ast.parse(code)
        self.assertIn(CASE,{node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and type(node.value)is str})
        self.assertIn('os.geteuid() != 0',code);self.assertIn('caps & (1 << 19)',code)
        # The enrolled name must still resolve to exactly one case on every host.
        self.assertEqual(1,unittest.defaultTestLoader.loadTestsFromName(CASE).countTestCases())

    def test_actual_ci_result_gate_rejects_skips_failure_and_missing_test(self):
        code=self.command((ROOT/'.github/workflows/fast-checks.yml').read_bytes());tree=ast.parse(code)
        # A skipped kernel case cannot be a passing CI substitute.
        gate=next(node for node in tree.body if isinstance(node,ast.If) and 'result.testsRun' in ast.unparse(node.test))
        compiled=compile(ast.Module(body=[gate],type_ignores=[]),'<actual-linux-creator-census-result-gate>','exec')
        from types import SimpleNamespace
        for count,skips,success in ((0,[],True),(1,[('case','no capability')],True),(1,[],False)):
            result=SimpleNamespace(testsRun=count,skipped=skips,wasSuccessful=lambda:success)
            with self.subTest(count=count,skips=skips,success=success),self.assertRaises(SystemExit):exec(compiled,{'result':result})
        exec(compiled,{'result':SimpleNamespace(testsRun=1,skipped=[],wasSuccessful=lambda:True)})


if __name__=='__main__':unittest.main()
