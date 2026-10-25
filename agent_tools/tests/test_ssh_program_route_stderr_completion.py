"""Original route-order case awaits its worker's error text past partial traceback reads; real local workers, no SSH, VM or network."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import types
import unittest
import uuid
from unittest import mock

from agent_tools.tests import test_ssh_program_execution as current

BEFORE = Path(__file__).parent / 'fixtures/ssh_program_route_stderr_completion/test_ssh_program_execution.py.before.source'
PROVENANCE = Path(__file__).parent / 'fixtures/ssh_program_route_stderr_completion/provenance.json'
ORIGINAL = 'test_original_route_order_failure_and_fixed_actual_worker'
# The original assertion read exactly this first line; the worker writes the final line last.
PARTIAL, FINAL = b'Traceback (most recent call last):\n', b'ValueError: program_route_changed_before_launch\n'
# The fixed case runs with each, set explicitly: the worker inherits them, and from Python 3.13 FORCE_COLOR wraps its traceback in SGR sequences.
COLORS = ({'NO_COLOR': '1'}, {'FORCE_COLOR': '1'})


def plain(raw):
    return re.sub(rb'\x1b\[[0-9;]*m', b'', raw)


@unittest.skipUnless(os.name == 'posix', 'real owned local workers')
class RouteStderrCompletionTests(unittest.TestCase):
    def before(self):
        raw = BEFORE.read_bytes(); provenance = json.loads(PROVENANCE.read_bytes())
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(raw)), (provenance['sourceSha256'], provenance['sourceBytes']))
        self.assertEqual(('agent_tools/tests/test_ssh_program_execution.py', False), (provenance['sourcePath'], provenance['nativeFailureClaimed']))
        module = types.ModuleType('_route_stderr_completion_before_' + uuid.uuid4().hex); module.__file__ = current.__file__
        exec(compile(raw, str(BEFORE), 'exec'), module.__dict__)
        return module

    def original(self, implementation):
        """The actual case; only its reads of the original worker's own stderr are controlled."""
        case = implementation.ProgramExecutionTests(ORIGINAL); workers, served = [], []
        actual_popen, actual_read, actual_start = subprocess.Popen, Path.read_bytes, case.start
        def popen(argv, *args, **kwargs):
            child = actual_popen(argv, *args, **kwargs)
            if argv[-1:] == [str(case.root / '.rag_index/ssh-program-execution' / case.operation / 'worker.py')]:
                workers.append((Path(argv[-1]).parent, child))  # The unfixed owner's saved-worker launch.
            return child
        def start(*args, **kwargs):
            with mock.patch.object(subprocess, 'Popen', side_effect=popen):
                result = actual_start(*args, **kwargs)
            for _, child in workers:
                child.wait(timeout=60)  # Its actual exit: the file now holds the complete traceback.
            return result
        def read_bytes(path):
            if not workers or path != workers[0][0] / 'worker.stderr.private':
                return actual_read(path)
            complete = actual_read(path)
            # As in the original trace, the poll's first non-empty read and the assertion's
            # immediate re-read hold only the first line; the remaining lines land afterwards.
            view = b''.join(complete.splitlines(keepends=True)[:1]) if len(served) < 2 else complete
            served.append((view, complete)); return view
        with mock.patch.object(Path, 'read_bytes', read_bytes), mock.patch.object(case, 'start', start):
            result = unittest.TestResult(); case.run(result)
        return result, workers, served

    def test_unfixed_partial_traceback_red_error_text_wait_green(self):
        provenance = json.loads(PROVENANCE.read_bytes()); trace = provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'], hashlib.sha256(('\n'.join(trace) + '\n').encode()).hexdigest())
        self.assertEqual(current.__name__ + '.ProgramExecutionTests.' + ORIGINAL, provenance['originalFailureTestId'])
        result, workers, served = self.original(self.before())
        self.assertEqual((1, 1, 0), (result.testsRun, len(result.failures), len(result.errors)), ''.join(t for _, t in result.failures + result.errors))
        # The same statement fails with the same bytes, after exactly the trace's two reads.
        failure = result.failures[0][1].splitlines()
        self.assertIn('  File "%s", %s' % (BEFORE, trace[4].split('", ', 1)[1]), failure)
        self.assertIn(trace[5], failure); self.assertEqual(trace[-1], failure[-1])
        complete = served[-1][1] if served else b''
        self.assertEqual([(PARTIAL, complete)] * 2, served); self.assertIn(FINAL, plain(complete))
        self.assertEqual([1], [child.returncode for _, child in workers])  # One original worker, failed as recorded.
        for colors in COLORS:
            with self.subTest(colors=colors), mock.patch.dict(os.environ):
                for name in ('NO_COLOR', 'FORCE_COLOR'):
                    os.environ.pop(name, None)
                os.environ.update(colors)
                result, workers, served = self.original(current)
                self.assertEqual((1, 0, 0), (result.testsRun, len(result.failures), len(result.errors)), ''.join(t for _, t in result.failures + result.errors))
                # Both partial reads were served, then the case stopped polling at its first complete
                # read and asserted on one more. A wait that never matches re-reads until its deadline.
                complete = served[-1][1] if served else b''
                self.assertGreater(len(served), 2); self.assertLessEqual(len(served), 4); self.assertIn(FINAL, plain(complete))
                self.assertEqual([(PARTIAL, complete)] * 2 + [(complete, complete)] * (len(served) - 2), served)
                self.assertEqual([1], [child.returncode for _, child in workers])


if __name__ == '__main__':
    unittest.main()
