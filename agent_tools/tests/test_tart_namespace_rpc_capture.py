"""Actual controlled children and preserved whole private qualification caller."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private
from agent_tools import tart_namespace_rpc_capture as capture


@unittest.skipUnless(os.name == 'posix', 'held output descriptors and kernel process generations')
class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.directory = private.Directory(self.root); self.addCleanup(self.directory.close)

    def invoke(self, program, *, seconds=1, payload=b'public request', parent=None):
        with capture.PublicRpcCapture(self.directory, 'call-1-enroll') as retained:
            return retained.run([sys.executable, '-B', '-c', program], payload,
                deadline=time.monotonic()+seconds, birth=jobs._birth,
                parent=parent or (lambda pid: os.getpid()))

    def records(self):
        return [json.loads(line) for line in (self.root/'call-1-enroll.capture.jsonl').read_bytes().splitlines()]

    def test_complete_child_retains_both_streams_and_eof_before_external_guard_failure(self):
        with self.assertRaisesRegex(RuntimeError, 'post_source_changed'):
            result, record = self.invoke("import sys;sys.stdin.buffer.read();print('original public callback');sys.stderr.write('public stderr')")
            raise RuntimeError('post_source_changed')
        self.assertEqual(result.stdout, b'original public callback\n')
        self.assertEqual(result.stderr, b'public stderr')
        self.assertTrue(record['stdoutEof']); self.assertTrue(record['stderrEof'])
        self.assertFalse(record['partial']); self.assertTrue(record['actorAbsent'])
        self.assertEqual(self.records()[-1], record)

    def test_timeout_retains_partial_prefix_and_cleanup_drained_eof(self):
        with self.assertRaises(capture.CaptureUnknown):
            self.invoke("import sys,time;sys.stdout.write('partial stdout');sys.stdout.flush();sys.stderr.write('partial stderr');sys.stderr.flush();time.sleep(30)", seconds=.15)
        r = self.records()[-1]
        self.assertEqual((self.root/'call-1-enroll.stdout.json').read_bytes(), b'partial stdout')
        self.assertEqual((self.root/'call-1-enroll.stderr.txt').read_bytes(), b'partial stderr')
        self.assertEqual(r['failure'], 'timeout'); self.assertTrue(r['actorAbsent']); self.assertTrue(r['partial'])
        self.assertTrue(r['stdoutEof']); self.assertTrue(r['stderrEof'])
        self.assertEqual(r['originalOutcome'], 'unknown_no_replay'); self.assertFalse(r['replayAllowed'])

    def test_limits_never_retain_unbounded_communicate_output(self):
        with self.assertRaises(capture.CaptureUnknown):
            self.invoke("import os;os.write(1,b'x'*400000);os.write(2,b'y'*100000)")
        r = self.records()[-1]
        self.assertEqual(r['stdoutBytes'], 262144)
        self.assertLessEqual(r['stderrBytes'], 65536)
        self.assertTrue(r['stdoutOverflow']); self.assertTrue(r['partial'])
        self.assertTrue(r['actorAbsent'])

    def test_stderr_limit_independent(self):
        with self.assertRaises(capture.CaptureUnknown):
            self.invoke("import os;os.write(2,b'e'*100000)")
        self.assertEqual((self.root/'call-1-enroll.stderr.txt').stat().st_size, 65536)
        self.assertTrue(self.records()[-1]['stderrOverflow'])

    def test_replaced_output_name_never_redirects_raw_or_callback(self):
        with capture.PublicRpcCapture(self.directory, 'call-1-enroll') as retained:
            # Mutate the route after the prelaunch guard, from the child itself.
            path = self.root/'call-1-enroll.stdout.json'
            moved = self.root/'original-held.stdout'
            program = f"import os;os.rename({str(path)!r},{str(moved)!r});open({str(path)!r},'wb').write(b'REPLACEMENT');os.write(1,b'ORIGINAL')"
            with self.assertRaisesRegex(capture.CaptureUnknown, 'route_changed'):
                retained.run([sys.executable,'-B','-c',program], b'', deadline=time.monotonic()+1,
                             birth=jobs._birth,parent=lambda pid: os.getpid())
        self.assertEqual(moved.read_bytes(), b'ORIGINAL')
        self.assertEqual(path.read_bytes(), b'REPLACEMENT')
        self.assertTrue(self.records()[-1]['stdoutEof'])

    def test_owned_cleanup_does_not_signal_unrelated_child(self):
        other = subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(30)'])
        try:
            with self.assertRaises(capture.CaptureUnknown):
                self.invoke('import time;time.sleep(30)',seconds=.1)
            self.assertIsNone(other.poll())
        finally: other.kill(); other.wait()

    def test_wait_failure_still_retains_raw_callback_before_raise(self):
        real = subprocess.Popen.wait
        def wait(process, *a, **k):
            answer = real(process, *a, **k)
            raise OSError('controlled cleanup boundary')
        with mock.patch.object(subprocess.Popen, 'wait', wait):
            with self.assertRaises(capture.CaptureUnknown):
                self.invoke("import os;os.write(1,b'finished before wait failure')")
        self.assertEqual((self.root/'call-1-enroll.stdout.json').read_bytes(), b'finished before wait failure')
        self.assertIsNotNone(self.records()[-1]['cleanupFailure'])
        self.assertTrue(self.records()[-1]['actorAbsent'])

    def before_call(self, program, *, timeout, wait_failure=False):
        """Execute the ACTUAL whole ffdad captured_native with fixed test seams."""
        path = Path(__file__).parent/'fixtures/tart_namespace_capture_before.source'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'ffdad711ec13be0a0d3ad22788f66a471bfbb0d61dbdabc68ff3a825200b28c4')
        tree=ast.parse(raw); node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='captured_native')
        # Preserve whole function unchanged. Fixed carrier source, actual child,
        # and the old timeout are controlled only at its surrounding interfaces.
        from types import SimpleNamespace as NS
        payload=b"PARAMETERS={'action':'enroll'}\n"
        c=NS(binding=NS(tart_binary=sys.executable,vm_name='-c',guest_python=program),
            _unlock_observer_original=lambda: {'enrollment':{},'operationId':'controlled-enrollment'},idle_facts=lambda *_:{'blockers':{'unknown_jobs'},'visibility':set()},
            guest_proof={'initialPacket':{'facts':{}}})
        args=NS(target='controlled-public',operation_id='controlled-original')
        def save(path,value):
            path.write_bytes(value if type(value)is bytes else json.dumps(value).encode())
        real = subprocess.Popen
        children=[]
        def launch(argv,**kwargs):
            # Original function's exact prefix is satisfied; Python executes its
            # harmless controlled child and ignores the fixed stdin gate tail.
            child=real([sys.executable,'-B','-c',program],**kwargs);children.append(child);return child
        namespace={'guard':lambda:None,'need':lambda v,r: None if v else (_ for _ in ()).throw(RuntimeError(r)),
            'c':c,'O':NS(namespace_source=lambda *_a,**_k:payload),
            'protocol':NS(stdin_command=lambda s:((None,),None)), 'calls':[],
            'F':NS(_json=lambda p:({'enrollment':{},'operationId':'controlled-enrollment'},{})), 'intent_path':self.root/'intent',
            'packet_path':self.root/'packet','save':save,'folder':self.root,'args':args,
            'hashlib':hashlib,'subprocess':subprocess,'os':os,'J':jobs,
            'R':NS(_parent=lambda *_:os.getpid()),'actors':[],'time':time}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
        try:
            from contextlib import ExitStack
            with ExitStack() as held:
                held.enter_context(mock.patch.object(subprocess,'Popen',launch))
                if wait_failure:
                    original_wait = real.wait
                    def failed_wait(process, *a, **k):
                        original_wait(process, *a, **k)
                        raise OSError('controlled original cleanup wait')
                    held.enter_context(mock.patch.object(real,'wait',failed_wait))
                return namespace['captured_native']((sys.executable,'exec','-i','-c',program),payload,time.monotonic()+timeout)
        finally:
            for child in children:
                if child.poll()is None:child.kill();child.wait()

    def test_actual_whole_before_timeout_loses_partial_red_current_retains_green(self):
        with self.assertRaisesRegex(RuntimeError,'timeout_no_replay'):
            self.before_call("import os,time;os.write(1,b'public original stdout');os.write(2,b'public original stderr');time.sleep(30)",timeout=.15)
        self.assertFalse((self.root/'call-1-enroll.stdout.json').exists())
        self.assertFalse((self.root/'call-1-enroll.stderr.txt').exists())
        self.assertTrue((self.root/'call-1-enroll.timeout.json').exists())
        # The equivalent current complete caller retains the original prefixes.
        with self.assertRaises(capture.CaptureUnknown):
            self.invoke("import os,time;os.write(1,b'public original stdout');os.write(2,b'public original stderr');time.sleep(30)",seconds=.15)
        self.assertEqual((self.root/'call-1-enroll.stdout.json').read_bytes(),b'public original stdout')
        self.assertEqual((self.root/'call-1-enroll.stderr.txt').read_bytes(),b'public original stderr')

    def test_whole_before_cleanup_wait_failure_loses_completed_raw_current_retains(self):
        with self.assertRaisesRegex(OSError, 'controlled original cleanup wait'):
            self.before_call("import os;os.write(1,b'completed original callback')", timeout=1, wait_failure=True)
        self.assertFalse((self.root/'call-1-enroll.stdout.json').exists())
        self.assertFalse((self.root/'call-1-enroll.stderr.txt').exists())
        real_wait = subprocess.Popen.wait
        def fail_wait(process, *a, **k):
            real_wait(process, *a, **k)
            raise OSError('controlled cleanup wait')
        with mock.patch.object(subprocess.Popen, 'wait', fail_wait):
            with self.assertRaises(capture.CaptureUnknown):
                self.invoke("import os;os.write(1,b'completed original callback')")
        self.assertEqual((self.root/'call-1-enroll.stdout.json').read_bytes(), b'completed original callback')
        self.assertTrue(self.records()[-1]['actorAbsent'])

    def test_foreign_parent_never_signalled_and_callback_retained(self):
        with mock.patch.object(subprocess.Popen, 'kill', side_effect=AssertionError('signal forbidden')) as kill:
            with self.assertRaises(capture.CaptureUnknown):
                self.invoke('import time;time.sleep(.08)', parent=lambda pid: os.getpid()+100000)
        kill.assert_not_called()
        self.assertEqual(self.records()[-1]['failure'], 'actor_not_owned')
        self.assertTrue(self.records()[-1]['actorAbsent'])

    def test_missing_eof_is_bounded_and_explicit_even_after_original_actor_exit(self):
        real = subprocess.Popen
        read_fd, write_fd = os.pipe()
        def launch(argv, **kw):
            kw['stdout'] = write_fd
            child = real(argv, **kw)
            child.stdout = os.fdopen(read_fd, 'rb', buffering=0)
            return child
        try:
            with mock.patch.object(subprocess, 'Popen', launch):
                with self.assertRaises(capture.CaptureUnknown):
                    self.invoke("import os;os.write(1,b'prefix without EOF')",seconds=.1)
            receipt = self.records()[-1]
            self.assertEqual((self.root/'call-1-enroll.stdout.json').read_bytes(),b'prefix without EOF')
            self.assertFalse(receipt['stdoutEof']);self.assertTrue(receipt['stderrEof'])
            self.assertTrue(receipt['partial']);self.assertTrue(receipt['actorAbsent'])
        finally: os.close(write_fd)
