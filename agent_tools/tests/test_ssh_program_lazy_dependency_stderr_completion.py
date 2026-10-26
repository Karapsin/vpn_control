"""Lazy-dependency case reports its original worker's whole stderr only after that worker exited; real local workers, no SSH, VM or network."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
import unittest
import uuid
from unittest import mock

from agent_tools import ssh_program_execution
from agent_tools.tests import test_ssh_program_execution as current

FIXTURE = Path(__file__).parent / 'fixtures/ssh_program_lazy_dependency_stderr_completion'
BEFORE, PROVENANCE = FIXTURE / 'test_ssh_program_execution.py.before.source', FIXTURE / 'provenance.json'
ORIGINAL = 'test_direct_source_session_lazy_dependency_before_red_current_green'
REPORT, FINAL = 'Original worker failed before terminal: ', 'ValueError: expected_source_bytes_changed'
QUOTE = 'AssertionError: "expected_source_bytes_changed" does not match "' + REPORT
IMPORT_FRAME = r'  File ".*/importlib/__init__\.py", line [0-9]+, in import_module'
# Each set explicitly: workers inherit both, and from Python 3.13 FORCE_COLOR colors their tracebacks.
COLORS = ({'NO_COLOR': '1'}, {'FORCE_COLOR': '1'})
# The unfixed owner records and reaps this fixed stdlib relay as its worker. It holds
# that worker.stderr.private, receives the actual worker's whole stderr through a pipe
# and writes it in two parts: through the importlib import_module frame line, where the
# CI read ended (CPython 3.12 writes a File line before reading its source line), and
# the rest once the gate opens. It exits only after every byte is in the file, so the
# recorded worker's exit still implies its complete stderr, as for a direct worker.
RELAY = r'''
import os,re,sys
source,gate=int(sys.argv[1]),int(sys.argv[2]);chunks=[]
while True:
    part=os.read(source,65536)
    if not part:break
    chunks.append(part)
lines=b''.join(chunks).splitlines(keepends=True)
cut=[index+1 for index,line in enumerate(lines)
     if re.fullmatch(sys.argv[3].encode()+rb'\n',re.sub(rb'\x1b\[[0-9;]*m',b'',line))]
def write(raw):
    while raw:raw=raw[os.write(2,raw):]
write(b''.join(lines[:cut[0]] if cut else lines))
if not cut:raise SystemExit(4)
if os.read(gate,1)!=b'G':raise SystemExit(5)
write(b''.join(lines[cut[0]:]))
'''


def plain(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def quoted_frames(lines):
    """File name and function of each frame in the partial traceback the mismatch quotes."""
    start = next(index for index, line in enumerate(lines) if line.startswith(QUOTE))
    return [(Path(path).name, function) for path, function in (
        re.fullmatch(r'  File "(.*)", line [0-9]+, in (.*)', line).groups()
        for line in lines[start + 1:] if line.startswith('  File "'))]


@unittest.skipUnless(os.name == 'posix', 'real owned local workers')
class LazyDependencyStderrCompletionTests(unittest.TestCase):
    def before(self):
        raw = BEFORE.read_bytes(); provenance = json.loads(PROVENANCE.read_bytes())
        self.assertEqual((hashlib.sha256(raw).hexdigest(), len(raw)), (provenance['sourceSha256'], provenance['sourceBytes']))
        self.assertEqual(('agent_tools/tests/test_ssh_program_execution.py', False), (provenance['sourcePath'], provenance['nativeFailureClaimed']))
        module = types.ModuleType('_lazy_dependency_stderr_before_' + uuid.uuid4().hex); module.__file__ = current.__file__
        exec(compile(raw, str(BEFORE), 'exec'), module.__dict__)
        return module

    def original(self, implementation):
        """The actual case; only when its original worker's own stderr bytes reach that file is controlled."""
        case = implementation.ProgramExecutionTests(ORIGINAL)
        workers, relays, observed, opened, streams, reports = [], [], [], [], [], []
        gate_read, gate_write = os.pipe()
        actual_popen, actual_status, actual_terminal = subprocess.Popen, ssh_program_execution.status, case.terminal
        def popen(argv, *args, **kwargs):
            if workers or type(argv) is not list or argv[:4] != [sys.executable, '-I', '-B', '-c'] or not hasattr(case, 'operation'):
                return actual_popen(argv, *args, **kwargs)
            worker = case.root / '.rag_index/ssh-program-execution' / case.operation / 'worker.py'
            if repr(str(worker)) not in argv[4]:
                return actual_popen(argv, *args, **kwargs)
            # The unfixed owner's saved-worker launch runs unchanged; only its stderr goes to the relay.
            source, sink = os.pipe()
            try:
                workers.append((worker.parent, actual_popen(argv, *args, **{**kwargs, 'stderr': sink})))
            finally:
                os.close(sink)
            try:
                relay = actual_popen([sys.executable, '-I', '-B', '-c', RELAY, str(source), str(gate_read), IMPORT_FRAME],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=kwargs['stderr'],
                                     pass_fds=(source, gate_read))
            finally:
                os.close(source)
            relays.append(relay); streams.append(open(worker.parent / 'worker.stderr.private', 'rb'))
            return relay
        def status(root, host, identity, *args, **kwargs):
            # The gate opens at the case's second observation of the partial file.
            if (workers and not opened and identity == {'operationId': workers[0][0].name}
                    and (workers[0][0] / 'worker.stderr.private').stat().st_size):
                observed.append(identity)
                if len(observed) == 2:
                    opened.append('case'); os.write(gate_write, b'G')
            return actual_status(root, host, identity, *args, **kwargs)
        def terminal(*args, **kwargs):
            try:
                return actual_terminal(*args, **kwargs)
            except AssertionError as error:
                reports.append(str(error)); raise
        case.terminal = terminal
        result = unittest.TestResult()
        try:
            with mock.patch.object(subprocess, 'Popen', side_effect=popen), \
                    mock.patch.object(ssh_program_execution, 'status', side_effect=status):
                case.run(result)
        finally:
            if not opened:
                opened.append('after case'); os.write(gate_write, b'G')
            os.close(gate_write); os.close(gate_read)
            for child in relays + [child for _, child in workers]:
                try:
                    child.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            stderr = [stream.read().decode(errors='backslashreplace') for stream in streams]
            for stream in streams:
                stream.close()
        diagnostics = ('\n'.join(text for _, text in result.failures + result.errors) + '\ncase reports:\n' + '\n'.join(reports)
                       + '\nworker stderr:\n' + '\n'.join(stderr))
        self.assertEqual(([1], [0], 1), ([child.returncode for _, child in workers], [relay.returncode for relay in relays], len(stderr)), diagnostics)
        complete = plain(stderr[0])
        self.assertEqual(FINAL, complete.splitlines()[-1], diagnostics)  # The intended refusal, as recorded.
        lines = complete.splitlines(keepends=True)
        prefix = ''.join(lines[:next(index + 1 for index, line in enumerate(lines) if re.fullmatch(IMPORT_FRAME + '\n', line))])
        return types.SimpleNamespace(result=result, observed=observed, opened=opened, reports=[plain(report) for report in reports],
                                     complete=complete, prefix=prefix, diagnostics=diagnostics)

    def test_unfixed_partial_stderr_red_exact_worker_exit_green(self):
        provenance = json.loads(PROVENANCE.read_bytes()); trace = provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'], hashlib.sha256(('\n'.join(trace) + '\n').encode()).hexdigest())
        self.assertEqual(current.__name__ + '.ProgramExecutionTests.' + ORIGINAL, provenance['originalFailureTestId'])
        self.assertRegex(trace[-2], '^' + IMPORT_FRAME + '$'); self.assertEqual('"', trace[-1])
        # The read ended in the lazy ssh_automatic_program import, before its refusal frame.
        self.assertEqual([('<string>', '<module>'), ('<string>', 'run'), ('worker.py', '<module>'),
                          ('source_module_loader.py', 'call'), ('source_module_loader.py', 'call'),
                          ('ssh_program_execution.py', 'worker'), ('ssh_transport.py', 'build_ssh_argv'),
                          ('ssh_transport.py', '_automatic_module'), ('source_module_loader.py', 'import_module'),
                          ('__init__.py', 'import_module')], quoted_frames(trace))
        for colors in COLORS:
            with self.subTest(implementation='unfixed', colors=colors), mock.patch.dict(os.environ):
                for name in ('NO_COLOR', 'FORCE_COLOR'):
                    os.environ.pop(name, None)
                os.environ.update(colors)
                run = self.original(self.before())
                self.assertEqual((1, 1, 0), (run.result.testsRun, len(run.result.failures), len(run.result.errors)), run.diagnostics)
                # The same statement fails as in the trace: its first non-empty observation read
                # the stderr through the import_module frame line while the worker still wrote it.
                failure = plain(run.result.failures[0][1])
                # trace[3] opens the reported message; trace[32:34] are the failing statement's frame.
                self.assertIn('  File "%s", %s\n%s\n' % (BEFORE, trace[32].split('", ', 1)[1], trace[33]), failure, run.diagnostics)
                self.assertTrue(failure.startswith(trace[3] + '\n'), run.diagnostics)
                self.assertTrue(failure.rstrip('\n').endswith(QUOTE + run.prefix + '"'), run.diagnostics)
                self.assertEqual(quoted_frames(trace), quoted_frames(failure.split('\n')), run.diagnostics)
                self.assertNotIn(FINAL, failure, run.diagnostics)
                self.assertEqual(([REPORT + run.prefix], ['after case']), (run.reports, run.opened), run.diagnostics)
                self.assertLessEqual(len(run.observed), 1, run.diagnostics)
        for colors in COLORS:
            with self.subTest(implementation='fixed', colors=colors), mock.patch.dict(os.environ):
                for name in ('NO_COLOR', 'FORCE_COLOR'):
                    os.environ.pop(name, None)
                os.environ.update(colors)
                run = self.original(current)
                # It kept observing past the partial file, reported the whole stderr once that
                # exact worker exited, and its fixed-owner half still ran the target once.
                self.assertEqual((1, 0, 0), (run.result.testsRun, len(run.result.failures), len(run.result.errors)), run.diagnostics)
                self.assertEqual(([REPORT + run.complete], ['case'], 2), (run.reports, run.opened, len(run.observed)), run.diagnostics)


if __name__ == '__main__':
    unittest.main()
