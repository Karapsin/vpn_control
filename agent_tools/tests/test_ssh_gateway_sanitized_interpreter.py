"""Actual whole gateway fixture under the durable owner's sanitized PATH."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

from agent_tools.tests import test_ssh_gateway_tmux_master as current

ROOT = Path(__file__).resolve().parents[2]
BEFORE = Path(__file__).resolve().parent / 'fixtures/ssh_gateway_sanitized_interpreter/test_ssh_gateway_tmux_master.py.before.source'
BEFORE_SHA = 'd61b92e38f9343d7c0931a9481a4c6ba130046c200d492831f7ea9a037ae3f37'
DRIVER = r'''
from pathlib import Path
import json,sys,types,unittest
root,source,interpreter=sys.argv[1:]
sys.path.insert(0,root)
# Some Python distributions canonicalize the launcher symlink. Retain the
# explicitly owned executable pathname so this case really exercises quoting.
sys.executable=interpreter
fixture=types.ModuleType('_whole_gateway_interpreter_fixture')
fixture.__file__=source
sys.modules[fixture.__name__]=fixture
exec(compile(Path(source).read_bytes(),source,'exec'),fixture.__dict__)
suite=unittest.defaultTestLoader.loadTestsFromName('GatewayOwnerTests.test_foreground_master_ready_after_client_subprocess_ends',fixture)
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'testsRun':result.testsRun,'successful':result.wasSuccessful(),'failures':len(result.failures),'errors':len(result.errors),'interpreter':sys.executable}),flush=True)
raise SystemExit(0 if result.wasSuccessful() else 1)
'''


@unittest.skipUnless(os.name == 'posix', 'POSIX inert process fixture')
class GatewaySanitizedInterpreterTests(unittest.TestCase):
    def test_complete_original_fixture_selects_broken_path_python_current_uses_test_interpreter(self):
        self.assertEqual(BEFORE_SHA, hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix='vct-python-choice-') as temp:
            root = Path(temp).resolve()
            binary = root / 'path-bin'; binary.mkdir(mode=0o700)
            log = root / 'path-python-used'
            # Permit the version-only fixture query, then fail interpreter
            # startup at the same SSH-G boundary as the preserved native run.
            shim = binary / 'python3'
            shim.write_text('#!/bin/sh\nprintf used\\n >> ' + shlex.quote(str(log)) + '\n'
                            + 'case "$1:$2" in */tmux:-V) exec ' + shlex.quote(sys.executable)
                            + ' -I -B "$@" ;; esac\n'
                            + "printf '%s\\n' 'Fatal Python error: init_fs_encoding' 'EOFError: marshal data too short' >&2\nexit 86\n")
            shim.chmod(0o700)
            # This deliberately includes spaces and a quote: the helper's fixed
            # shell trampoline must preserve the exact interpreter pathname.
            interpreter_dir = root / "python directory's space"; interpreter_dir.mkdir()
            interpreter = interpreter_dir / 'test python'
            interpreter.symlink_to(sys.executable)
            env = {'PATH': str(binary)}
            for source, expected_code in ((BEFORE, 1), (Path(current.__file__), 0)):
                with self.subTest(source=source.name):
                    before = log.read_bytes() if log.exists() else b''
                    result = subprocess.run([str(interpreter), '-I', '-B', '-c', DRIVER, str(ROOT), str(source), str(interpreter)],
                                            env=env, capture_output=True, timeout=30, check=False)
                    self.assertEqual(expected_code, result.returncode, result.stderr.decode(errors='replace'))
                    report = json.loads(result.stdout.splitlines()[-1])
                    self.assertEqual(1, report['testsRun'])
                    self.assertEqual(expected_code == 0, report['successful'])
                    self.assertEqual(0, report['errors'])
                    after = log.read_bytes() if log.exists() else b''
                    if source == BEFORE:
                        self.assertIn(b"'prepared' != 'unknown'", result.stderr)
                        self.assertGreater(len(after), len(before))
                    else:
                        self.assertEqual(before, after, 'current helpers must never resolve PATH python3')
                        self.assertEqual(str(interpreter), report['interpreter'])

    def test_unrecognized_helper_header_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'unexpected_inert_python_source'):
            current.inert_python('#!/foreign/python\nprint(1)\n')


if __name__ == '__main__':
    unittest.main()
