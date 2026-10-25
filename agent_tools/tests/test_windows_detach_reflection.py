"""Native diagnostic reflection ABI regression; no VM, process, or file effects."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest


FIXTURE = Path(__file__).parent / 'fixtures' / 'windows_jobs_reflection'
FILES = ('start.before.source', 'status.before.source', 'child.before.source',
         'reflection.before.source', 'reflection.fixed.source',
         'reflection.causal.ps1', 'native-failure.json', 'conversion.before.source',
         'reflection.causal-before-v2.source', 'native-conversion-failure.json', 'native-green.json')


def authenticated_fixture():
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if provenance['schemaVersion'] != 1 or set(provenance['sourceSha256']) != set(FILES):
        raise AssertionError('reflection fixture scope changed')
    sources = {}
    for name in FILES:
        raw = (FIXTURE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != provenance['sourceSha256'][name]:
            raise AssertionError('reflection fixture source changed: ' + name)
        sources[name] = raw
    return sources


class WindowsDetachReflectionTests(unittest.TestCase):
    def test_actual_failure_and_complete_beforeimages_authenticate_exact_old_wrapper(self):
        source = authenticated_fixture()
        failure = json.loads(source['native-failure.json'])
        self.assertEqual(1, failure['schemaVersion'])
        self.assertEqual(hashlib.sha256(source['start.before.source']).hexdigest(), failure['sourceSha256'])
        self.assertIs(True, failure['terminal']['exited'])
        self.assertEqual(1, failure['terminal']['exitcode'])
        stderr = base64.b64decode(failure['terminal']['err-data'], validate=True).decode()
        self.assertIn('System.Management.Automation.PSObject', stderr)
        self.assertIn('System.String', stderr)
        for name in ('start.before.source', 'status.before.source', 'child.before.source'):
            self.assertIn(source['reflection.before.source'], source[name])
        self.assertIn(source['reflection.before.source'].replace(b'function N(', b'function OldN('), source['reflection.causal.ps1'])
        self.assertIn(source['reflection.fixed.source'], source['reflection.causal.ps1'])
        prior = json.loads(source['native-conversion-failure.json'])
        self.assertEqual(hashlib.sha256(source['reflection.causal-before-v2.source']).hexdigest(), prior['sourceSha256'])
        self.assertEqual(1, prior['terminal']['exitcode'])
        self.assertIn('fixed_text_failed', base64.b64decode(prior['terminal']['err-data'], validate=True).decode())
        self.assertIn(source['conversion.before.source'], source['reflection.causal-before-v2.source'])
        green = json.loads(source['native-green.json'])
        self.assertEqual(hashlib.sha256(source['reflection.causal.ps1']).hexdigest(), green['sourceSha256'])
        self.assertEqual({'schemaVersion':1,'causalRed':True,'causalGreen':True,'conversionRed':True,
                          'text':True,'binary':True,'byref':True}, green['sessionFacts'])

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell reflection ABI required')
    def test_actual_old_reflection_red_fixed_text_binary_and_byref_green(self):
        authenticated_fixture()
        powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive',
                                 '-ExecutionPolicy', 'Bypass', '-File', str(FIXTURE / 'reflection.causal.ps1')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors='replace'))
        self.assertEqual({'schemaVersion':1,'causalRed':True,'causalGreen':True,'conversionRed':True,
                          'text':True,'binary':True,'byref':True}, json.loads(result.stdout))


if __name__ == '__main__':
    unittest.main()
