"""Complete inert PowerShell fixtures and exact native observation contracts.

Portable controls execute actual source fragments in explicit owned namespaces.
Only the Windows-only decoder case executes PowerShell; it retains both streams
and must reproduce the old failure before admitting the candidate-only rename.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name('fixtures') / 'windows_complete_program_transfer'
COMMIT = '9a6d4b3cf4850750253af8339a12b9d7b425e5f1'
BASE_TEST = ROOT / 'agent_tools/tests/test_windows_cp117_base_source_refresh.py'
DECODER_TEST = ROOT / 'agent_tools/tests/test_windows_cp117_c32_absence.py'
FAILURE_TEST = ROOT / 'agent_tools/tests/test_windows_secure_input_failure_execution.py'
EXPECTED = ['old-bom=rejected', 'fixed-bom=ok', 'fixed-plain=ok',
            'fixed-malformed=rejected', 'fixed-utf16=rejected']


def retained(name):
    if name not in {'carrier.before.source', 'decoder.before.fragment', 'haderrors.before.fragment'}:
        raise ValueError('Unknown PowerShell fixture source')
    metadata = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if metadata.get('schemaVersion') != 1 or metadata.get('sourceCommit') != COMMIT:
        raise ValueError('PowerShell fixture provenance changed')
    rows = [row for row in metadata['files'] if row['path'] == name]
    if len(rows) != 1:
        raise ValueError('PowerShell fixture identity changed')
    raw = (FIXTURE / name).read_bytes()
    if len(raw) != rows[0]['bytes'] or hashlib.sha256(raw).hexdigest() != rows[0]['sha256']:
        raise ValueError('PowerShell fixture bytes changed')
    return raw


def current_function(path, name):
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('Test source bound exceeded')
    matches = [node for node in ast.walk(ast.parse(raw))
               if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise ValueError('Test function identity changed')
    return matches[0]


def retained_method(name):
    # Preserve the original method indentation and multiline literal bytes.
    # A fixed class wrapper supplies only their original parsing context.
    tree = ast.parse('class OwnedFragment:\n' + retained(name).decode('utf-8'))
    nodes = tree.body[0].body
    if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
        raise ValueError('Retained method identity changed')
    return nodes[0]


def carrier(before=False):
    path = FIXTURE / 'carrier.before.source' if before else BASE_TEST
    raw = retained('carrier.before.source') if before else path.read_bytes()
    names = {'_complete_windows_fixture_carrier', '_run_complete_windows_fixture'}
    nodes = [node for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes} != names or len(nodes) != 2:
        raise ValueError('Complete carrier source changed')
    namespace = {'__file__': str(path), 'ast': ast, 'Path': Path,
                 'base64': base64, 'hashlib': hashlib, 'refresh': None}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['_complete_windows_fixture_carrier']


def assert_complete_carrier(case, factory):
    public = b'#' + b'P' * 131072 + b"\n[Console]::Out.Write('PUBLIC_COMPLETE')\n"
    argv, packet = factory(public)
    case.assertEqual(['powershell', '-NoProfile', '-NonInteractive', '-EncodedCommand'], argv[:4])
    case.assertLess(len(argv[-1]), 30000)
    case.assertLessEqual(sum(len(word.encode()) + 1 for word in argv), 60000)
    case.assertEqual(len(public), int.from_bytes(packet[:4], 'little'))
    case.assertEqual(public, packet[4:])
    loader = base64.b64decode(argv[-1], validate=True).decode('utf-16le', errors='strict')
    case.assertIn(hashlib.sha256(public).hexdigest(), loader)
    case.assertIn('$length -gt 262144', loader)
    case.assertIn('[Text.UTF8Encoding]::new($false,$true)', loader)
    case.assertIn('Parser]::ParseInput', loader)
    case.assertTrue(loader.endswith('& ([ScriptBlock]::Create($cp117Body))'))


def decoder_script(before=False):
    if before:
        node = retained_method('decoder.before.fragment')
        path = FIXTURE / 'decoder.before.fragment'
    else:
        node = current_function(DECODER_TEST, 'test_windows_result_decoder_accepts_only_utf8_with_optional_bom')
        path = DECODER_TEST
    fixed_node = current_function(ROOT / 'agent_tools/windows_cp117_c32_absence.py', '_result_decode_powershell')
    namespace = {}
    exec(compile(ast.Module(body=[fixed_node], type_ignores=[]),
                 str(ROOT / 'agent_tools/windows_cp117_c32_absence.py'), 'exec'), namespace)
    fixed = namespace['_result_decode_powershell']()
    old = '$result=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -ErrorAction Stop'
    assignments = [statement for statement in node.body if isinstance(statement, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'script' for target in statement.targets)]
    if len(assignments) != 1:
        raise ValueError('Decoder fixture script changed')
    return eval(compile(ast.Expression(assignments[0].value), str(path), 'eval'),
                {'fixed': fixed, 'old': old})


def observation_case(value, *, before=False):
    if before:
        path = FIXTURE / 'haderrors.before.fragment'
        node = retained_method(path.name)
    else:
        path = FAILURE_TEST
        node = current_function(path, 'test_managed_powershell_caught_throw_keeps_haderrors_after_success')
    namespace = {'tempfile': tempfile, 'json': json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    observed_scripts = []
    def invoke(self, directory, script):
        # This is the exact native record projected into the original method,
        # not a PowerShell engine or a claim of local native execution.
        with (Path(directory) / 'observed-script.ps1').open('xb') as stream:
            stream.write(script.encode('utf-8', errors='strict'))
        observed_scripts.append(script)
        return subprocess.CompletedProcess([], 0, json.dumps(value), '')
    method = namespace[node.name]
    case = type('OwnedNativeObservation', (unittest.TestCase,), {'runTest': method, 'invoke': invoke})()
    result = unittest.TestResult()
    case.run(result)
    return result, observed_scripts


class CompleteFixtureTests(unittest.TestCase):
    def test_complete_carrier_does_not_require_a_posix_coordinator_module(self):
        assert_complete_carrier(self, carrier(os.environ.get('POWERSHELL_FIXTURE_CARRIER_BEFORE') == '1'))

    def test_retained_carrier_dependency_refuses_then_current_source_passes(self):
        with self.assertRaisesRegex(AttributeError, "NoneType.*__file__"):
            assert_complete_carrier(self, carrier(True))
        assert_complete_carrier(self, carrier())

    def test_complete_carrier_keeps_test_and_production_bounds(self):
        factory = carrier()
        for value in (b'', b'P' * 262145, 'PUBLIC', bytearray(b'PUBLIC')):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaisesRegex(ValueError, '^test-source-bound$'):
                    factory(value)
        production = ROOT / 'agent_tools/windows_cp117_base_source_refresh.py'
        loader = current_function(production, 'repair_program')
        expression = next(statement.value for statement in loader.body if isinstance(statement, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == 'loader' for target in statement.targets))
        raw = eval(compile(ast.Expression(expression), str(production), 'eval'),
                   {'hashlib': hashlib, 'str': str, 'len': len, '__builtins__': {}}, {'public': b"'PUBLIC'"})
        self.assertEqual(1, raw.count('$length -gt 65536'))
        self.assertNotIn('$length -gt 262144', raw)

    def test_decoder_candidate_changes_only_automatic_parameter_and_flags(self):
        old, current = decoder_script(True), decoder_script()
        self.assertEqual(2, old.count('$input'))
        self.assertEqual(5, old.count('Classify -input '))
        self.assertEqual(old.replace('$input', '$candidate').replace('Classify -input ', 'Classify -candidate '), current)
        self.assertNotIn('$input', current)
        self.assertEqual(5, current.count('Classify -candidate '))

    def test_recorded_haderrors_false_same_native_assertion_red_then_typed_green(self):
        value = {'hadErrors': False, 'errors': 0, 'output': ['ACL_CAUSAL_PASS']}
        old, old_scripts = observation_case(value, before=True)
        current, current_scripts = observation_case(value)
        self.assertEqual(1, old.testsRun)
        self.assertEqual([], old.errors)
        self.assertEqual(1, len(old.failures))
        self.assertIn('hadErrors', old.failures[0][1])
        self.assertEqual(1, current.testsRun)
        self.assertTrue(current.wasSuccessful(), current.errors + current.failures)
        self.assertEqual(old_scripts, current_scripts)

    def test_typed_haderrors_keeps_exact_error_and_marker_guards(self):
        for flag in (False, True):
            result, unused = observation_case({'hadErrors': flag, 'errors': 0, 'output': ['ACL_CAUSAL_PASS']})
            self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        for value in ({'hadErrors': 0, 'errors': 0, 'output': ['ACL_CAUSAL_PASS']},
                      {'hadErrors': False, 'errors': True, 'output': ['ACL_CAUSAL_PASS']},
                      {'hadErrors': False, 'errors': 1, 'output': ['ACL_CAUSAL_PASS']},
                      {'hadErrors': False, 'errors': 0, 'output': []},
                      {'hadErrors': False, 'errors': 0, 'output': ['OTHER']},
                      {'hadErrors': False, 'errors': 0, 'output': ['ACL_CAUSAL_PASS'], 'extra': True}):
            with self.subTest(fields=sorted(value)):
                result, unused = observation_case(value)
                self.assertFalse(result.wasSuccessful())


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell.exe'), 'Native Windows decoder execution')
class NativeDecoderFixtureTests(unittest.TestCase):
    def test_actual_original_and_candidate_parameter_binding_retains_full_streams(self):
        records = []
        for before in (True, False):
            script = decoder_script(before)
            result = subprocess.run([shutil.which('powershell.exe'), '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, text=True, timeout=15, check=False, env=windows_powershell_environment(shutil.which('powershell.exe'), os.environ))
            records.append({'before': before, 'sourceSha256': hashlib.sha256(script.encode()).hexdigest(),
                            'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        print('DECODER_FIXTURE_CAUSAL ' + json.dumps(records, sort_keys=True), flush=True)
        self.assertFalse(records[0]['returncode'] == 0 and records[0]['stdout'].splitlines() == EXPECTED,
                         'The original fixture failure must actually reproduce')
        self.assertEqual(0, records[1]['returncode'], records)
        self.assertEqual(EXPECTED, records[1]['stdout'].splitlines(), records)


if __name__ == '__main__':
    unittest.main()
