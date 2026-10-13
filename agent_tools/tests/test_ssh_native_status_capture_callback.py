"""Historical status-callback regression; real inert children, no SSH or native effects.

The callback body is the exact executable correction from the preserved observer.
Binary stdout/stderr are retained before JSON metadata and never JSON-encoded as bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from agent_tools import ssh_fresh_nested_channel as channel

CALLBACK_SOURCE = "def retain(name,value):\n p=D/name\n with p.open('xb')as f:f.write(value if type(value)is bytes else(json.dumps(value,sort_keys=True,indent=2)+'\\n').encode());f.flush();os.fsync(f.fileno())\n p.chmod(0o600)\n\ndef capture(value):\n prefix='original-badc-native-capture-'+str(len(rawcalls));metadata=dict(value);streams={}\n for role in ('stdout','stderr'):\n  raw=metadata.pop(role)\n  if type(raw)is not bytes:raise ValueError('capture_binary_type')\n  retain(prefix+'.'+role+'.private',raw)\n  streams[role]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}\n metadata['retainedStreams']=streams\n name=prefix+'.private.json';retain(name,metadata);rawcalls.append(name)\n"

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                     'POSIX real binary status collector')
class NativeStatusCaptureCallbackTests(unittest.TestCase):
    def exercise(self, stdout, stderr, exitcode):
        program = ('import sys;sys.stdin.buffer.read();'
                   'sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));'
                   'sys.stderr.buffer.write(bytes.fromhex(sys.argv[2]));'
                   'sys.exit(int(sys.argv[3]))')
        capture = channel._collect([sys.executable, '-I', '-B', '-c', program,
                                    stdout.hex(), stderr.hex(), str(exitcode)], b'{}', 5)
        self.assertTrue(capture['complete'])
        self.assertEqual(exitcode, capture['returnCode'])
        self.assertEqual({'stdout': True, 'stderr': True}, capture['eof'])
        self.assertEqual({'stdout': len(stdout), 'stderr': len(stderr)}, capture['counts'])
        self.assertFalse(any(capture[key] for key in ('timeout', 'overflow', 'readError')))
        original = dict(capture)
        with tempfile.TemporaryDirectory(prefix='vcb-', dir=Path('/tmp').resolve()) as temporary:
            directory = Path(temporary)
            namespace = {'D': directory, 'os': os, 'json': json,
                         'hashlib': hashlib, 'rawcalls': []}
            exec(compile(CALLBACK_SOURCE, 'actual-status-callback', 'exec'), namespace)
            namespace['capture'](capture)
            self.assertEqual(original, capture)
            metadata_path = directory / 'original-badc-native-capture-0.private.json'
            metadata = json.loads(metadata_path.read_bytes())
            self.assertEqual([metadata_path.name], namespace['rawcalls'])
            for role, expected in (('stdout', stdout), ('stderr', stderr)):
                path = directory / ('original-badc-native-capture-0.' + role + '.private')
                self.assertEqual(expected, path.read_bytes())
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
                self.assertEqual({'bytes': len(expected),
                                  'sha256': hashlib.sha256(expected).hexdigest()},
                                 metadata['retainedStreams'][role])
                self.assertNotIn(role, metadata)
            self.assertEqual(0o600, stat.S_IMODE(metadata_path.stat().st_mode))
            for key in ('complete', 'returnCode', 'eof', 'counts', 'overflow', 'timeout', 'readError'):
                self.assertEqual(capture[key], metadata[key])

    def test_successful_status_with_empty_stderr_retains_terminal_and_full_eof(self):
        self.exercise(b'{"state":"ended"}\n', b'', 0)

    def test_nonzero_binary_child_retains_exact_streams_and_digests(self):
        self.exercise(b'\x00\xffbinary stdout\n', b'\x00\xfebinary stderr\n', 7)

if __name__ == '__main__':
    unittest.main()
