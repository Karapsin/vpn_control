"""Real socket-path regression; consumed original implementation stays frozen."""
import hashlib
import io
import contextlib
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock
from agent_tools import windows_cp117_fixture_recovery as original
from agent_tools import windows_cp117_fixture_recovery_short_socket as current
from agent_tools.tests import test_windows_cp117_fixture_recovery as checks

# Reuse actual generated startup/claim/transport regression bodies against the
# new companion. The old module is only read, never monkeypatched or rewritten.
class CompanionChecks(checks.RecoveryTests):
    def setUp(self):
        self.scope=mock.patch.object(checks,'r',current);self.scope.start()
    def tearDown(self):self.scope.stop()

class SocketPathsTests(unittest.TestCase):
    def test_old_112_byte_bind_fails_short_actual_recipe_binds(self):
        oldpath=original.recipe()['leaf']+'/swtpm.sock';newpath=current.recipe()['leaf']+'/swtpm.sock'
        self.assertEqual(len(os.fsencode(oldpath)),112)
        with tempfile.TemporaryDirectory(dir='/tmp',prefix='vpn-sock-')as temp:
            # Exercise the exact byte lengths without writing /home/kardinal.
            oldlocal=temp+'/'+'a'*(len(os.fsencode(oldpath))-len(os.fsencode(temp))-1)
            newlocal=temp+'/'+'b'*(len(os.fsencode(newpath))-len(os.fsencode(temp))-1)
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                with self.assertRaises(OSError):sock.bind(oldlocal)
                sock.bind(newlocal)
                self.assertTrue(Path(newlocal).exists())
            finally:sock.close()

    def test_all_fixed_recipe_unix_paths_fit_linux_limit(self):
        recipe=current.recipe()
        paths=[recipe['leaf']+'/'+name for name in('swtpm.sock','qmp.sock','qga.sock')]
        self.assertTrue(all(len(os.fsencode(p))<=107 for p in paths))
        self.assertNotEqual(original.CORRELATION,current.CORRELATION)
        self.assertNotEqual(original.recipe()['leaf'],recipe['leaf'])
        self.assertEqual(original.DISK,current.DISK)

    def test_consumed_original_source_unchanged(self):
        self.assertEqual(hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest(),'4b9133adb7a4b1794dbe2f3348ad9ea4198cfb8d6a2b85e20efba3e8f84e6ac9')

    def test_generated_preflight_rejects_long_path_before_host_calls(self):
        program=current._OBSERVER.replace('__RECIPE__',repr(original.recipe())).replace('__RESERVED__',repr(current.MEMORY_BYTES))
        output=io.StringIO()
        with mock.patch('builtins.open',side_effect=AssertionError('host read attempted'))as reads,mock.patch.object(current.subprocess,'Popen')as spawn,contextlib.redirect_stdout(output):
            exec(program,{})
        self.assertIn('unix-socket-path',output.getvalue());reads.assert_not_called();spawn.assert_not_called()

if __name__=='__main__':unittest.main()
