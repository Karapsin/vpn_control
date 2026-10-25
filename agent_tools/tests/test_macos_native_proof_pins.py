"""Actual public proof reads must not confuse access time with replacement."""
import hashlib
import os
from pathlib import Path
import tempfile
import sys
import unittest

from agent_tools import readiness_tart_macos_registry as mac


class NativeProofPinTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='darwin','actual native Mac proof-pin access-time regression')
    def test_complete_before_reader_red_atime_safe_reader_green_with_kernel_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'public-source.py';path.write_bytes(b'public native producer\n');path.chmod(0o600)
            functions={}
            for phase in ('before','after'):
                scope={'hashlib':hashlib,'mac':mac}
                source=(Path(__file__).parent/'fixtures'/('macos_public_proof_atime.'+phase+'.source')).read_bytes()
                exec(compile(source,'retained-complete-public-pin-reader','exec'),scope)
                functions[phase]=scope['ref']
            # Force a genuine first read, so the kernel advances access time.
            old=path.stat();os.utime(path,ns=(1,old.st_mtime_ns))
            with self.assertRaisesRegex(SystemExit,'^public_proof_changed$'):
                functions['before'](path)
            old=path.stat();os.utime(path,ns=(1,old.st_mtime_ns))
            result=functions['after'](path)
            self.assertEqual(result['pin']['sha256'],hashlib.sha256(b'public native producer\n').hexdigest())
            self.assertEqual(result['pin']['generation'],list(mac.private._generation(path.stat())))


if __name__=='__main__':unittest.main()
