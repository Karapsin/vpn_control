"""Actual native SyntaxError beforeimage and repaired emitted byte framing."""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest

from agent_tools import android_observation

FIXTURES = Path(__file__).with_name('fixtures')
MODE = os.environ.get('VC_ROUTING_SOURCE_MODE', 'green')
SOURCE = FIXTURES / ('android_api35_routing_emitted_before.source' if MODE == 'red'
                     else 'android_api35_routing_emitted_fixed.source')


class RoutingEmittedSourceTests(unittest.TestCase):
    def final_source(self):
        source = SOURCE.read_text(encoding='utf-8')
        prefix = android_observation._canonical_cli_environment_source()
        self.assertTrue(source.startswith(prefix))
        # Exercise the same complete helper+tail assembly sent over the route.
        return prefix + source[len(prefix):]

    def test_final_emitted_program_compiles_before_native_dispatch(self):
        source = self.final_source()
        programme = 'import sys;compile(sys.stdin.buffer.read(),"FINAL_EMITTED_ROUTING_SOURCE","exec");print("compiled")'
        completed = subprocess.run([sys.executable, '-I', '-B', '-c', programme],
                                   input=source.encode(), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr.decode('utf-8', 'replace'))
        self.assertEqual(b'compiled\n', completed.stdout)
        self.assertEqual(b'', completed.stderr)

    def test_actual_emitted_frame_preserves_full_binary_and_empty_timeout_capture(self):
        tree = ast.parse(self.final_source())
        emission = ast.Module(body=tree.body[-3:], type_ignores=[])
        code = compile(ast.fix_missing_locations(emission), 'actual_routing_emission', 'exec')
        for out, error in ((b'', b''), (b'\0\xff\r\n' * 128, b'\0\xfe\n')):
            with self.subTest(stdoutBytes=len(out), stderrBytes=len(error)):
                stdout, stderr = io.BytesIO(), io.BytesIO()
                metadata = {'commandTimedOut': True, 'commandReturnCode': None,
                            'stdoutBytes': len(out), 'stderrBytes': len(error),
                            'stdoutSha256': hashlib.sha256(out).hexdigest(),
                            'stderrSha256': hashlib.sha256(error).hexdigest()}
                namespace = {'out': out, 'error': error, 'metadata': metadata,
                             'json': json, 'sys': SimpleNamespace(
                                 stdout=SimpleNamespace(buffer=stdout),
                                 stderr=SimpleNamespace(buffer=stderr))}
                exec(code, namespace)
                self.assertEqual(out, stdout.getvalue())
                original, frame = stderr.getvalue().rsplit(b'\nVC_API35_ROUTING_DIAG_META=', 1)
                self.assertEqual(error, original)
                self.assertEqual({**metadata, 'transportedCommandBytesComplete': True}, json.loads(frame))
                self.assertTrue(frame.endswith(b'\n'))
                self.assertFalse(frame.endswith(b'\\n'))


if __name__ == '__main__':
    unittest.main()
