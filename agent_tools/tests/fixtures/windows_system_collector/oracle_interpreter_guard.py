"""Whole genuine barrier-pair isolation/restoration oracle; local inert child only."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time
import types
import unittest

ROOT = Path(__file__).resolve().parents[4]
CURRENT = ROOT / 'agent_tools/tests/test_windows_system_collector.py'
BEFORE = Path(__file__).with_name('oracle-cleanup.before.source')
OBSERVATION = {}
CHILDREN = []


class InterpreterRestorationTest(unittest.TestCase):
    def runTest(self):
        executable, getpid, sleep = sys.executable, os.getpid, time.sleep
        programdata = ('ProgramData' in os.environ, os.environ.get('ProgramData'))
        source, expected = Path(sys.argv[1]).resolve(), sys.argv[2]
        self.assertIn(source, (CURRENT.resolve(), BEFORE.resolve()))
        with source.open('rb') as stream:
            generation = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
            opening = generation(os.fstat(stream.fileno()))
            raw = stream.read()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
            self.assertEqual(generation(os.fstat(stream.fileno())), opening)
            self.assertEqual(generation(source.stat()), opening)
        if source == BEFORE.resolve():
            self.assertEqual(expected, 'a7d3e8f0e8dd68f23a88f7620296d01d29c8cd626e16a7bd5b1fe6f7836d8233')
        module = types.ModuleType('_actual_whole_collector_cleanup_oracle')
        # Original canonical path is the explicit ROOT-data binding for both
        # whole namespaces. No function/class/assertion source is rewritten.
        module.__file__ = str(CURRENT)
        sys.modules[module.__name__] = module
        exec(compile(raw, str(source), 'exec', dont_inherit=True), module.__dict__)
        try:
            result = unittest.TestResult()
            module.CollectorCausalPairs('test_original_live_caller_barrier').run(result)
            restored = {'executable': sys.executable == executable, 'getpid': os.getpid is getpid,
                        'sleep': time.sleep is sleep,
                        'ProgramData': ('ProgramData' in os.environ, os.environ.get('ProgramData')) == programdata}
            child_result = None
            launch_error = None
            try:
                child = subprocess.Popen([sys.executable, '-c', 'print("owned-post-oracle-child")'],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                CHILDREN.append(child)
                stdout, stderr = child.communicate(timeout=15)
                child_result = {'pid': child.pid, 'returncode': child.returncode,
                                'stdout': stdout.decode(), 'stderr': stderr.decode(),
                                'bothEof': True, 'originalHandleWaited': child.wait() == child.returncode}
            except OSError as error:
                launch_error = {'type': type(error).__name__, 'text': str(error)}
            OBSERVATION.update(sourceSha256=expected, wholeSourceExecuted=True,
                originalBarrierPair={'testsRun': result.testsRun, 'failures': len(result.failures),
                    'errors': len(result.errors), 'successful': result.wasSuccessful()},
                actualInterpreterBefore=executable, actualInterpreterAfter=sys.executable,
                restored=restored, child=child_result, launchError=launch_error)
            self.assertEqual((result.testsRun, len(result.failures), len(result.errors)), (1, 0, 0))
            self.assertEqual(restored, dict.fromkeys(restored, True),
                             'original oracle must restore actual interpreter state')
            self.assertIsNone(launch_error)
            self.assertEqual(child_result['returncode'], 0)
            self.assertEqual(child_result['stdout'], 'owned-post-oracle-child\n')
            self.assertEqual(child_result['stderr'], '')
            self.assertTrue(child_result['bothEof'] and child_result['originalHandleWaited'])
        finally:
            module._guard()
            for stream, _, _, _ in module._held.values():
                stream.close()


result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([InterpreterRestorationTest()]))
OBSERVATION.update(testsRun=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                   nativeActions=False)
print(json.dumps(OBSERVATION, sort_keys=True), flush=True)
raise SystemExit(not result.wasSuccessful())
