from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent_tools import windows_cp117_c32_host_archive as archive


DESCRIPTOR = ('windows-cp117', '/tmp/owned.sock', 42, 1234, 'S-1-5-21-1')
BINDING = dict(zip(('socketPath', 'pid', 'startTicks'), DESCRIPTOR[1:4])) | {
    'sourceSha': 'a' * 40, 'sourceFingerprint': 'b' * 64,
    'receiptArtifactId': 'sha256-' + 'c' * 64,
    'baseArtifactId': 'sha256-' + 'd' * 64,
    'targetArtifactId': 'sha256-' + 'e' * 64,
    'commandSha256': 'f' * 64, 'expectedSid': DESCRIPTOR[4]}
INTENT = {'leaseId': archive._C32, 'environment': DESCRIPTOR[0],
          **{k: BINDING[k] for k in ('socketPath', 'pid', 'startTicks', 'expectedSid')},
          'commandSha256': BINDING['commandSha256'],
          'request': {'correlationId': archive._C32, 'sourceSha': BINDING['sourceSha'],
                      'fixtureReceiptArtifactId': BINDING['receiptArtifactId'],
                      'baseMsiArtifactId': BINDING['baseArtifactId'],
                      'targetMsiArtifactId': BINDING['targetArtifactId']},
          'pair': {'sourceFingerprint': BINDING['sourceFingerprint']}}
GATE = {**archive._UNKNOWN, 'state': 'ready', 'hostBaseStage': 'retained'}
CENSUS = {'state': 'observed', 'baseTask': 'present', 'guestLeaf': 'present',
          'transferTask': 'absent', 'baseMsi': 'absent', 'correlationProcess': 'absent'}


@unittest.skipUnless(os.name == 'posix', 'Linux host metadata requires POSIX APIs')
class ArchiveRemoteTests(unittest.TestCase):
    def tree(self, root, archived=False):
        env = root / 'windows-cp117'
        group = env / 'windows-msi-base'
        leaf = (env / 'windows-msi-base-history' if archived else group) / archive._C32
        for path in (root, env, group, leaf.parent, leaf):
            path.mkdir(exist_ok=True); path.chmod(0o700)
        lock = group / '.environment.lock'
        lock.write_bytes(b''); lock.chmod(0o600)
        (leaf / 'binding.json').write_text(json.dumps(BINDING))
        (leaf / 'dispatch.json').write_text('{"pid":1}')
        for name in ('binding.json', 'dispatch.json'):
            (leaf / name).chmod(0o600 if archived else 0o644)
        return leaf

    def execute(self, root, operation='archive', binding=None, prefix='', env='windows-cp117', corr=None):
        # Metadata admission is exercised in a real subprocess on every POSIX
        # host. Generation admission itself remains production base._QGA.live.
        program = 'def live(sock,pid,ticks):return True\n' + prefix + archive._REMOTE_BODY
        result = subprocess.run((sys.executable, '-c', program, str(root), env,
                                 corr or archive._C32, json.dumps(binding or BINDING), operation),
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux renameat2 requires Linux')
    def test_actual_exclusive_rename_preserves_and_normalizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); leaf = self.tree(root)
            original = {p.name: p.read_bytes() for p in leaf.iterdir()}
            self.assertEqual({'state': 'archived'}, self.execute(root))
            dst = root / 'windows-cp117/windows-msi-base-history' / archive._C32
            self.assertFalse(leaf.exists())
            self.assertEqual(original, {p.name: p.read_bytes() for p in dst.iterdir()})
            for p in dst.iterdir(): self.assertEqual(0o600, p.stat().st_mode & 0o777)
            self.assertEqual({'state': 'archived'}, self.execute(root, 'status'))
            self.assertEqual({'state': 'unknown'}, self.execute(root))

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux renameat2 requires Linux')
    def test_destination_created_at_syscall_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); leaf = self.tree(root)
            dst = root / 'windows-cp117/windows-msi-base-history' / archive._C32
            prefix = '''import ctypes,os
original=ctypes.CDLL
class Rename:
 def __init__(self,fn):self.fn=fn
 def __call__(self,a,src,b,dst,flag):
  os.mkdir(os.fsdecode(dst),0o700)
  inode=os.lstat(os.fsdecode(dst)).st_ino
  with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.fsdecode(dst)))),'race-inode'),'w') as f:f.write(str(inode))
  return self.fn(a,src,b,dst,flag)
class Library:
 def __init__(self,*a,**kw):self.renameat2=Rename(original(*a,**kw).renameat2)
ctypes.CDLL=Library
'''
            self.assertEqual({'state': 'unknown'}, self.execute(root, prefix=prefix))
            self.assertTrue(leaf.exists()); self.assertEqual([], list(dst.iterdir()))
            self.assertEqual(int((root / 'race-inode').read_text()), dst.stat().st_ino)

    def test_rejections_leave_source_and_do_not_create_history(self):
        cases = ('symlink', 'dispatch-symlink', 'foreign-file', 'world-mode', 'dir-mode', 'malformed', 'duplicate',
                 'oversized', 'dispatch-schema', 'binding', 'lock-symlink', 'lock-mode',
                 'foreign-owner', 'changed-fd', 'environment', 'correlation', 'generation')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); leaf = self.tree(root); prefix = ''; env = 'windows-cp117'; corr = None
                file = leaf / 'binding.json'
                if case == 'symlink': file.unlink(); file.symlink_to(leaf / 'dispatch.json')
                elif case == 'dispatch-symlink':
                    dispatch = leaf / 'dispatch.json'; dispatch.unlink(); dispatch.symlink_to(file)
                elif case == 'foreign-file': (leaf / 'extra').write_text('x')
                elif case == 'world-mode': file.chmod(0o666)
                elif case == 'dir-mode': leaf.chmod(0o755)
                elif case == 'malformed': file.write_text('{')
                elif case == 'duplicate': file.write_text('{"pid":42,"pid":43}')
                elif case == 'oversized': file.write_bytes(b'x' * 8193)
                elif case == 'dispatch-schema': (leaf / 'dispatch.json').write_text('{"pid":true}')
                elif case == 'binding': file.write_text('{}')
                elif case == 'lock-symlink':
                    lock = leaf.parent / '.environment.lock'; lock.unlink(); lock.symlink_to(file)
                elif case == 'lock-mode': (leaf.parent / '.environment.lock').chmod(0o644)
                elif case == 'foreign-owner':
                    prefix = '''import os
original=os.fstat
def foreign(fd):
 i=original(fd)
 if i.st_size==0:return i
 v=list(i);v[4]=i.st_uid+1;return os.stat_result(v)
os.fstat=foreign
'''
                elif case == 'changed-fd':
                    prefix = '''import os
original=os.fstat
def changed(fd):
 i=original(fd)
 if i.st_size==0:return i
 v=list(i);v[1]=i.st_ino+1;return os.stat_result(v)
os.fstat=changed
'''
                elif case == 'environment': env = 'other'
                elif case == 'correlation': corr = archive._LEASE
                elif case == 'generation': prefix = 'def live(*args):return False\n'
                self.assertEqual({'state': 'unknown'}, self.execute(root, prefix=prefix, env=env, corr=corr))
                self.assertTrue(leaf.is_dir())
                self.assertFalse((leaf.parent.parent / 'windows-msi-base-history').exists())

    def test_status_requires_exact_private_archive_and_source_absence_without_writes(self):
        for case in ('ready', 'source-present', 'binding', 'dispatch-mode', 'generation', 'lock-absent'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); leaf = self.tree(root, archived=True); prefix = ''
                if case == 'source-present': (root / 'windows-cp117/windows-msi-base' / archive._C32).mkdir()
                elif case == 'binding': (leaf / 'binding.json').write_text('{}')
                elif case == 'dispatch-mode': (leaf / 'dispatch.json').chmod(0o644)
                elif case == 'generation': prefix = 'def live(*args):return False\n'
                elif case == 'lock-absent': (root / 'windows-cp117/windows-msi-base/.environment.lock').unlink()
                before = {str(p.relative_to(root)): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
                          for p in root.rglob('*')}
                self.assertEqual({'state': 'archived' if case == 'ready' else 'unknown'}, self.execute(root, 'status', prefix=prefix))
                after = {str(p.relative_to(root)): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
                         for p in root.rglob('*')}
                self.assertEqual(before, after)


@unittest.skipUnless(archive._supported(), 'private local admission requires POSIX APIs')
class ArchiveLocalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = SimpleNamespace(fixture_transfer_root=Path('/private/transfer'))
        for obj, name, result in ((archive.admission, 'preflight', GATE),
                                  (archive.base, '_descriptor', (None, self.target, DESCRIPTOR)),
                                  (archive.base, '_private_intent', INTENT),
                                  (archive.absence, 'observe', CENSUS),
                                  (archive.absence, 'retained_terminal', {'state': 'retained-terminal'}),
                                  (archive.base, '_remote', b'{"state":"archived"}')):
            patcher = mock.patch.object(obj, name, return_value=result)
            setattr(self, name, patcher.start()); self.addCleanup(patcher.stop)

    def test_unadmitted_start_creates_no_local_files(self):
        for gate in ({'state': 'blocked'}, {**GATE, 'hostBaseStage': 'absent'}, {**GATE, 'productAction': True}):
            self.preflight.return_value = gate
            self.assertEqual('blocked', archive.start(self.root, {})['state'])
        self.assertEqual([], list(self.root.iterdir())); self._remote.assert_not_called()

    def test_fresh_census_and_terminal_required_before_intent(self):
        for case in ('process', 'opaque', 'failed-terminal', 'unknown-census'):
            self.observe.return_value = {**CENSUS, 'correlationProcess': 'present' if case == 'process' else 'ambiguous'} if case in ('process', 'opaque') else CENSUS
            if case == 'unknown-census': self.observe.return_value = {'state': 'unknown'}
            self.retained_terminal.return_value = {'state': 'unknown'} if case == 'failed-terminal' else {'state': 'retained-terminal'}
            self.assertEqual('blocked', archive.start(self.root, {})['state'])
            self.assertEqual([], list(self.root.iterdir()))
        self._remote.assert_not_called()

    def test_lost_response_retains_private_intent_and_status_never_resubmits(self):
        self._remote.return_value = None
        self.assertEqual('unknown', archive.start(self.root, {})['state'])
        path = self.root / archive._DIR / 'intent.json'
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual('unknown', archive.start(self.root, {})['state'])
        self.assertEqual(1, self._remote.call_count)
        self.assertEqual('unknown', archive.status(self.root, {})['state'])
        self.assertEqual('status', self._remote.call_args.args[2][-1])
        self._remote.return_value = b'{"state":"archived"}'
        self.assertEqual('archived', archive.status(self.root, {})['state'])
        self.assertEqual('status', self._remote.call_args.args[2][-1])

    def test_status_does_not_create_files_or_trust_unadmitted_local_record(self):
        self.assertEqual('not-started', archive.status(self.root, {})['state'])
        self.assertEqual([], list(self.root.iterdir()))
        archive._intent(self.root, BINDING)
        path = self.root / archive._DIR / 'intent.json'
        for case in ('mode', 'foreign-owner', 'symlink', 'binding', 'generation'):
            with self.subTest(case=case):
                original = path.read_bytes(); path.unlink(); path.write_bytes(original); path.chmod(0o600)
                if case == 'mode': path.chmod(0o644)
                elif case == 'symlink':
                    other = path.parent / 'other'; other.write_bytes(original); path.unlink(); path.symlink_to(other)
                elif case == 'binding': path.write_text('{"correlationId":"other","binding":{}}')
                elif case == 'generation': self._private_intent.return_value = {**INTENT, 'startTicks': 999}
                owner = mock.patch.object(archive.os, 'getuid', return_value=os.getuid() + 1) if case == 'foreign-owner' else mock.patch.object(archive.os, 'getuid', wraps=os.getuid)
                self._remote.reset_mock()
                with owner: self.assertEqual('unknown', archive.status(self.root, {})['state'])
                self._remote.assert_not_called()
                if path.is_symlink(): path.unlink(); path.write_bytes(original); path.chmod(0o600)
                else: path.chmod(0o600); path.write_bytes(original)
                self._private_intent.return_value = INTENT

    def test_private_directory_and_lock_admission_and_one_shot(self):
        archive._intent(self.root, BINDING)
        with self.assertRaises(FileExistsError): archive._intent(self.root, BINDING)
        self.assertEqual(0o700, (self.root / archive._DIR).stat().st_mode & 0o777)
        lock = self.root / archive._DIR / '.environment.lock'; lock.chmod(0o644)
        with self.assertRaises(ValueError): archive._intent(self.root, BINDING)
        lock.unlink(); lock.symlink_to(self.root / archive._DIR / 'intent.json')
        with self.assertRaises(OSError): archive._intent(self.root, BINDING)

    def test_strict_inputs(self):
        for value in (None, [], {'host': 'archlinux'}, {'operation': 'archive'}):
            for fn in (archive.start, archive.status):
                with self.assertRaises(ValueError): fn(self.root, value)


class ArchiveUnavailableApiTests(unittest.TestCase):
    def test_import_and_calls_fail_closed_without_posix_apis(self):
        for missing in ('fcntl', 'getuid'):
            with self.subTest(missing=missing):
                program = '''import builtins,json,os,sys,tempfile
from pathlib import Path
if sys.argv[1]=='fcntl':
 original=builtins.__import__
 def imported(name,*args,**kwargs):
  if name=='fcntl':raise ImportError('causal missing fcntl')
  return original(name,*args,**kwargs)
 builtins.__import__=imported
else:
 if hasattr(os,'getuid'):del os.getuid
from agent_tools import windows_cp117_c32_host_archive as archive
assert archive.base is None
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp)
 assert archive.start(root,{})==archive._UNKNOWN
 assert archive.status(root,{})==archive._UNKNOWN
 assert archive.self_test(root,{})=={**archive._UNKNOWN,'componentOnly':True}
 try:archive._intent(root,{})
 except ValueError:pass
 else:raise AssertionError('unsupported intent accepted')
 assert list(root.iterdir())==[]
print('fail-closed')
'''
                result = subprocess.run((sys.executable, '-c', program, missing),
                                        cwd=Path(__file__).resolve().parents[2],
                                        capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual('fail-closed', result.stdout.strip())


@unittest.skipUnless(archive._supported(), 'remote self-test transport requires POSIX client APIs')
class ArchiveSelfTestTests(unittest.TestCase):
    def test_fixed_transport_and_strict_results(self):
        passed = {'state': 'passed', 'cases': {'exclusive-rename': 'passed', 'destination-race': 'passed'}}
        unknown = {**archive._UNKNOWN, 'componentOnly': True}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = SimpleNamespace(hosts={'archlinux': SimpleNamespace(alias='archlinux')})
            with mock.patch.object(archive.base.ssh_transport, 'load_config', return_value=config), mock.patch.object(archive.base, '_remote') as remote:
                remote.return_value = json.dumps(passed).encode()
                self.assertEqual({**unknown, **passed}, archive.self_test(root, {}))
                remote.assert_called_once_with(config, archive._SELF_TEST, (), None, 20)
                self.assertEqual([], list(root.iterdir()))
                invalid = (None, b'', b'x' * 1025, b'{',
                           {'state': 'passed'}, {**passed, 'path': '/live'},
                           {'state': 'passed', 'cases': {'exclusive-rename': 'passed', 'destination-race': 'failed'}},
                           {'state': 'failed', 'cases': passed['cases']},
                           {'state': 'passed', 'cases': {'exclusive-rename': 'passed', 'foreign-case': 'passed'}},
                           {'state': 'unknown', 'cases': {'exclusive-rename': True, 'destination-race': 'unknown'}})
                for item in invalid:
                    remote.return_value = json.dumps(item).encode() if isinstance(item, dict) else item
                    self.assertEqual(unknown, archive.self_test(root, {}))
                remote.reset_mock(); config.hosts = {}
                self.assertEqual(unknown, archive.self_test(root, {})); remote.assert_not_called()
            for value in (None, [], {'host': 'archlinux'}, {'program': 'x'}):
                with self.assertRaises(ValueError): archive.self_test(root, value)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual inert renameat2 self-test requires Linux')
    def test_actual_inert_self_test_and_overwrite_mutation(self):
        def run(program):
            result = subprocess.run((sys.executable, '-I', '-B', '-c', program), capture_output=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stderr.decode())
            self.assertEqual(b'', result.stderr)
            return json.loads(result.stdout)
        expected = {'state': 'passed', 'cases': {'exclusive-rename': 'passed', 'destination-race': 'passed'}}
        self.assertEqual(expected, run(archive._SELF_TEST))
        mutated_body = archive._REMOTE_BODY.replace('os.fsencode(dst),1)', 'os.fsencode(dst),0)')
        self.assertNotEqual(archive._REMOTE_BODY, mutated_body)
        mutated = archive._SELF_TEST.replace(repr(archive._REMOTE_BODY), repr(mutated_body), 1)
        result = run(mutated)
        self.assertEqual('passed', result['cases']['exclusive-rename'])
        self.assertEqual('failed', result['cases']['destination-race'])
        self.assertEqual('failed', result['state'])


if __name__ == '__main__': unittest.main()
