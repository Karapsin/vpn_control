"""Actual native-control cleanup source, with owned processes and pipe faults."""
import ast
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stdout

FIXTURES = Path(__file__).parent / 'fixtures/android_native_observer_control'


def held(name):
    raw = (FIXTURES / name).read_bytes()
    pin = json.loads((FIXTURES / 'provenance.json').read_bytes())['files'][name]
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('observer-control-source-changed')
    return raw


def cleanup(state, birth):
    if os.environ.get('VPN_CONTROL_OBSERVER_CLEANUP_BEFORE') == '1':
        namespace = {'state': state, 'birth': birth, 'closed': None,
                     'os': os, 'base64': base64, 'hashlib': hashlib}
        try:
            exec(compile(held('cleanup.before.source'), 'actual-before-control-cleanup', 'exec'), namespace)
        except FileNotFoundError:
            pass
        return namespace['closed']
    namespace = {'__name__': 'held_actual_control_cleanup'}
    exec(compile(held('cleanup.fixed.source'), 'actual-fixed-control-cleanup', 'exec'), namespace)
    return namespace['finish_owned_child'](state, birth)


class ObserverCleanupTests(unittest.TestCase):
    def child(self):
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c',
                                  "import sys;print('ready',flush=True);sys.stdin.buffer.read(1);print('closed',flush=True)"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(child.stdout.readline(), b'ready\n')
        fd = os.open(os.devnull, os.O_RDONLY)
        state = {'child': child, 'ready': {'pid': child.pid, 'startTicks': 101},
                 'childStdout': b'ready\n', 'childStderr': b'', 'pythonFd': fd}
        self.addCleanup(self.reap, child, state)
        return state

    @staticmethod
    def reap(child, state):
        # Test ownership fallback preserves evidence even for intentional RED.
        if child.stdin is not None:
            try:
                child.stdin.close()
            except (OSError, ValueError):
                pass
            child.stdin = None
        child.communicate(timeout=5)
        if state['pythonFd'] is not None:
            try:
                os.close(state['pythonFd'])
            except OSError:
                pass
            state['pythonFd'] = None

    def assert_closed(self, result, state):
        self.assertIsNotNone(result, 'cleanup skipped original child wait and stream collection')
        self.assertEqual(result['state'], 'closed')
        self.assertTrue(result['streamsComplete'])
        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(base64.b64decode(result['stdoutBase64']), b'ready\nclosed\n')
        self.assertEqual(base64.b64decode(result['stderrBase64']), b'')
        self.assertTrue(result['interpreterClosed'])
        self.assertIsNone(state['pythonFd'])

    def test_lost_birth_observation_still_closes_waits_and_captures_owned_child(self):
        state = self.child()
        def missing(pid):
            raise FileNotFoundError(2, 'owned visibility seam')
        result = cleanup(state, missing)
        self.assert_closed(result, state)
        self.assertIn('child_birth_observation_FileNotFoundError', result['issues'])

    def test_generation_mismatch_does_not_skip_cooperative_cleanup(self):
        state = self.child()
        result = cleanup(state, lambda pid: 102)
        self.assert_closed(result, state)
        self.assertIn('child_birth_changed', result['issues'])

    def test_one_collection_failure_reobserves_same_original(self):
        state = self.child()
        child = state['child']
        real = child.communicate
        calls = []
        def observe(**kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise OSError(5, 'owned observer failure')
            return real(**kwargs)
        child.communicate = observe
        result = cleanup(state, lambda pid: 101)
        self.assert_closed(result, state)
        self.assertEqual(len(calls), 2)
        self.assertIn('child_collection_OSError', result['issues'])
        child.communicate = real

    def test_repeated_observation_failure_retains_unknown_and_closes_interpreter(self):
        state = self.child()
        child = state['child']
        real = child.communicate
        child.communicate = lambda **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired('owned', 1, output=b'partial'))
        result = cleanup(state, lambda pid: 101)
        self.assertEqual(result['state'], 'unknown')
        self.assertFalse(result['streamsComplete'])
        self.assertTrue(result['interpreterClosed'])
        self.assertEqual(base64.b64decode(result['stdoutBase64']), b'ready\npartial')
        child.communicate = real

    def test_write_failure_still_closes_pipe_and_collects(self):
        state = self.child()
        actual = state['child'].stdin
        class BrokenWriter:
            def write(self, value):
                raise BrokenPipeError(32, 'owned write seam')
            def close(self):
                actual.close()
        state['child'].stdin = BrokenWriter()
        result = cleanup(state, lambda pid: 101)
        self.assert_closed(result, state)
        self.assertIn('cooperative_input_BrokenPipeError', result['issues'])

    def test_native_source_never_signals_or_submits_a_child(self):
        tree = ast.parse(held('cleanup.fixed.source'))
        forbidden = {'kill', 'killpg', 'send_signal', 'terminate', 'Popen', 'submit', 'execve', 'fork'}
        self.assertFalse(any(isinstance(node, ast.Call) and
                             ((isinstance(node.func, ast.Attribute) and node.func.attr in forbidden) or
                              (isinstance(node.func, ast.Name) and node.func.id in forbidden))
                             for node in ast.walk(tree)))

    def test_evidence_preserves_completed_and_failing_phase(self):
        records = []
        def phase(source, digest, label):
            row = {'phase': label, 'state': 'qualified', 'records': [{'owned': label}]}
            records.append(row)
            if label == 'current':
                raise ValueError('owned_phase_observation_failed')
            return row
        namespace = {'ORIGINAL_CAPSULE': b'owned-before', 'CURRENT_CAPSULE': b'owned-current',
                     'OPERATION_ID': 'owned-unit-operation', 'PHASES': records,
                     'phase': phase, 'control_code': lambda error: error.args[0], 'json': json}
        before = os.environ.get('VPN_CONTROL_OBSERVER_EVIDENCE_BEFORE') == '1'
        source = held('evidence.before.source' if before else 'evidence.fixed.source')
        output = io.StringIO()
        with redirect_stdout(output):
            try:
                exec(compile(source, 'actual-native-control-phase-evidence', 'exec'), namespace)
            except ValueError:
                pass
        self.assertTrue(output.getvalue(), 'later phase failure discarded all completed and failing phase evidence')
        report = json.loads(output.getvalue())
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual([row['phase'] for row in report['phases']], ['before', 'current'])
        self.assertEqual(report['phases'][0]['records'], [{'owned': 'before'}])
        self.assertEqual(report['phases'][1]['records'], [{'owned': 'current'}])
        self.assertEqual(report['phases'][1]['unexpectedFailure'], 'owned_phase_observation_failed')

    def test_unknown_first_phase_stops_without_running_second(self):
        records = []
        def phase(source, digest, label):
            records.append({'phase': label, 'state': 'unknown', 'records': []})
        namespace = {'ORIGINAL_CAPSULE': b'owned-before', 'CURRENT_CAPSULE': b'owned-current',
                     'OPERATION_ID': 'owned-unit-operation', 'PHASES': records,
                     'phase': phase, 'control_code': lambda error: error.args[0], 'json': json}
        output = io.StringIO()
        with redirect_stdout(output):
            exec(compile(held('evidence.fixed.source'), 'actual-native-control-phase-evidence', 'exec'), namespace)
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(output.getvalue())['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()
