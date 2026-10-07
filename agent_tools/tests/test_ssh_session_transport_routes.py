"""Transport selection regressions; no SSH or native guest actions."""
from pathlib import Path
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import ssh_connection_session as session
from agent_tools import ssh_transport as transport


class SessionTransportRoutes(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = transport.SshConfig(root=self.root, hosts={
            'gateway': transport.SshHost('gateway', 'gateway.invalid', 22, 'fixture',
                                        self.root/'key', self.root/'known'),
            'arch': transport.SshHost('arch', 'unused', 22, 'fixture',
                                     Path('/remote/key'), Path('/remote/known'),
                                     transport='nested', gateway='gateway',
                                     remote_host_alias='archlinux'),
        })
        (self.root/'.rag_index'/'ssh-connection-session').mkdir(parents=True)

    def test_actual_nested_builder_selects_reuse_only_outer_options(self):
        options = ['-S', '/inert/owned/socket', '-o', 'ControlMaster=no',
                   '-o', 'ControlPersist=no', '-o', 'ProxyCommand=false']
        with mock.patch.object(session, 'selected_options', return_value=options) as select:
            argv = transport.build_ssh_argv(self.config, 'arch', command=('true',))
        select.assert_called_once_with(self.config, 'arch')
        self.assertEqual(argv[-len(options)-2:-2], options)
        self.assertEqual(argv[-2], 'gateway.invalid')
        self.assertIn('archlinux', argv[-1])

    def test_consumed_unknown_session_never_builds_plain_network_fallback(self):
        with mock.patch.object(session, 'selected_options', side_effect=session.SessionUnknown('master')):
            with self.assertRaises(transport.SshConfigError):
                transport.build_ssh_argv(self.config, 'arch')

    def test_direct_outer_builder_does_not_recurse_into_session_admission(self):
        with mock.patch.object(session, 'selected_options', side_effect=AssertionError('recursion')):
            argv = transport.build_ssh_argv(self.config, 'gateway')
        self.assertEqual(argv[-1], 'true')

    def test_no_session_inventory_preserves_unconfigured_transport(self):
        (self.root/'.rag_index'/'ssh-connection-session').rmdir()
        with mock.patch.object(session, 'selected_options', side_effect=AssertionError('unconfigured')):
            argv = transport.build_ssh_argv(self.config, 'arch')
        self.assertNotIn('ProxyCommand=false', argv)

    def test_actual_ready_helper_builder_and_lost_socket_fail_closed(self):
        from agent_tools.tests import test_ssh_connection_session as fixtures
        fixture = fixtures.SessionTests('test_ready_session_reuses_original_child_without_new_launch')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.ready()
        config = transport.load_config(fixture.root)
        argv = transport.build_ssh_argv(config, 'archlinux')
        socket_path = Path(argv[argv.index('-S')+1])
        self.assertIn('ProxyCommand=false', argv)
        self.assertEqual(len(fixture.spawns), 1)
        socket_path.unlink()
        with self.assertRaises(transport.SshConfigError):
            transport.build_ssh_argv(config, 'archlinux')
        self.assertEqual(len(fixture.spawns), 1)

    def test_actual_ready_helper_rejects_nested_config_drift_in_builder(self):
        from agent_tools.tests import test_ssh_connection_session as fixtures
        fixture = fixtures.SessionTests('test_ready_session_reuses_original_child_without_new_launch')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.ready()
        config = transport.load_config(fixture.root)
        fixture.config['hosts']['archlinux']['identityFile'] = '/remote/changed-key'
        fixture.write_config()
        with self.assertRaises(transport.SshConfigError):
            transport.build_ssh_argv(config, 'archlinux')
        self.assertEqual(len(fixture.spawns), 1)

    def test_documented_top_level_cli_import_fails_closed_without_parent_pythonpath(self):
        source = Path(transport.__file__).resolve().parent
        program = '''
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import ssh_transport as t
r=Path(sys.argv[2])
c=t.SshConfig(root=r,hosts={
 'g':t.SshHost('g','invalid',22,'fixture',r/'key',r/'known'),
 'a':t.SshHost('a','unused',22,'fixture',Path('/remote/key'),Path('/remote/known'),transport='nested',gateway='g',remote_host_alias='arch')})
try:t.build_ssh_argv(c,'a')
except t.SshConfigError:print('guarded')
'''
        result = subprocess.run([sys.executable, '-I', '-c', program, str(source), str(self.root)],
                                cwd=self.root, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'guarded')

    def test_isolated_top_level_builder_reuses_actual_ready_fixture(self):
        source = Path(transport.__file__).resolve().parent
        program = '''
import sys
from pathlib import Path
parent=str(Path(sys.argv[1]).parent)
sys.path.insert(0,parent)
from agent_tools.tests import test_ssh_connection_session as fixtures
f=fixtures.SessionTests('test_ready_session_reuses_original_child_without_new_launch')
f.setUp()
try:
 f.config['hosts']['archlinux']['windowsCredentialProbe']={
  'environment':'owned-windows','qgaSocketPath':'/owned/qga.sock',
  'qemuPid':123,'qemuStartTicks':456,'accountName':'fixture',
  'expectedSid':'S-1-5-21-1-2-3-1002','credentialPath':str(f.root/'credential')}
 f.write_config()
 f.ready()
 sys.path.remove(parent)
 sys.path.insert(0,sys.argv[1])
 import ssh_transport as t
 a=t.build_ssh_argv(t.load_config(f.root),'archlinux')
 assert 'ProxyCommand=false' in a and '-S' in a
 assert len(f.spawns)==1
 assert parent not in sys.path
 print('reused')
finally:f.doCleanups()
'''
        result = subprocess.run([sys.executable, '-I', '-c', program, str(source)],
                                cwd=self.root, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'reused')

    def test_missing_or_foreign_cached_module_origin_fails_closed(self):
        for module in (SimpleNamespace(), SimpleNamespace(__file__=False),
                       SimpleNamespace(__file__='/foreign/ssh_connection_session.py')):
            with self.subTest(module=module), mock.patch.object(transport.importlib, 'import_module', return_value=module):
                with self.assertRaises(transport.SshConfigError):
                    transport.build_ssh_argv(self.config, 'arch')
