from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent_tools import windows_cp117_historical_base_archives as archive

# Original immutable CP117 artifact metadata; no current-source relabeling.
PAIR = {'baseAppJarName': 'desktopApp-492ba7672a175dfadec6ef3a9a3082a6.jar',
        'baseAppJarSha256': '586ecc7479375ed131577fd1a1bd4e5c4adf98a0ad2e6ab8080c766e94d24e5d',
        'baseArtifactId': 'sha256-0fada9685bb308346723e6ca74c102c699dc86ffda8fb097fc99303c5ab5aaa3',
        'baseCliSha256': 'ca95b4e671c3effe05eb8f888a4260dedb6ff22363fe347383290240801dd2b1',
        'baseHelperSha256': '72b12b3f02eda96caa54807730c2097117c66d8674bf7a6c86d769625bffd6ad',
        'baseRuntimeSha256': 'ca74563c93440a2e9cb73eae6a04c109d3f5efce36a385f8261a654e362d2ea3',
        'baseVersion': '2.1.19',
        'receiptArtifactId': 'sha256-d437b2931db91c7b0ad97fb2809dfa0b224cb9f98d28634f4c4948e1117a705d',
        'sourceFingerprint': 'a25b116857dee11116dd88c2ef6d658b9818a12b789d89ae26a2cd319aad39fa',
        'sourceSha': '19be9df22cbab8086c26e5ca907d9569a5a28a08',
        'targetArtifactId': 'sha256-5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234',
        'targetMsiSha256': '5ac252557106a2bae56583253a70ea037bb300827df6b5c36b2dc502e1e01234',
        'targetMsiSize': 131101044, 'targetVersion': '2.2.2'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def records(correlation):
    request, command = archive.base._unknown_recovery_profile(correlation)
    env, sock, pid, ticks, sid = archive._GENERATION
    identity = {'host': 'archlinux', 'environment': env, 'leaseId': correlation, 'operator': 'windows-base',
                'sourceSha': request['sourceSha'], 'fixtureReceiptArtifactId': request['fixtureReceiptArtifactId'],
                'baseMsiArtifactId': request['baseMsiArtifactId'], 'targetMsiArtifactId': request['targetMsiArtifactId'],
                'socketPath': sock, 'qemuPid': pid, 'startTicks': ticks}
    intent = {'request': request, 'pair': PAIR, 'leaseId': correlation, 'commandSha256': command,
              'environment': env, 'socketPath': sock, 'pid': pid, 'startTicks': ticks, 'expectedSid': sid}
    marker = {'version': 1, 'state': 'close-intent', 'correlationId': correlation,
              'commandSha256': command, 'sourceSha': request['sourceSha'],
              'guestGeneration': {'environment': env, 'socketPath': sock, 'qemuPid': pid, 'startTicks': ticks, 'expectedSid': sid},
              'preMutationEvidenceSha256': 'de39fef85a6496602b74de7e7bdf0a913873cef6269afa08b07c6650536b7526'}
    known = {'2ace6a48-ba60-4705-9200-4ff857f2aba6': '140fa6f521045e1710ed41e2a4652e5d9dffabdd2850e13b903e7d0e65bf7274',
             '45e4514a-c629-4f3b-99bc-aad599640d29': 'c6383a8ae9d5e73a5f6bf2459fd5ce901f707e972ec9985c311da915926e2cf2'}
    closed = {'version': 1, 'identity': identity, 'sequence': 3, 'state': 'closed', 'role': None,
              'correlationId': None, 'server': 'stopped', 'credentials': 'absent',
              'lastOutcome': 'unknown-cleaned', 'lastEvidenceSha256': known[correlation]}
    return copy.deepcopy((intent, marker, closed))


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':'))); path.chmod(0o600)


def fresh(correlation, closed):
    return {'state': 'observed', 'correlationId': correlation, 'campaignSha256': digest(closed),
            'remoteStage': 'absent', 'qemuPid': archive._GENERATION[2], 'startTicks': archive._GENERATION[3],
            'task': 'absent', 'leaf': 'absent', 'result': 'absent', 'correlationProcess': 'absent',
            'installer': 'absent', 'product': 'single', 'installedVersion': '2.1.19', 'expectedSid': archive._GENERATION[4]}


@unittest.skipUnless(archive._supported(), 'historical host observer requires POSIX client APIs')
class HistoricalArchiveTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.root = Path(tmp.name)
        for path in (self.root / '.rag_index', self.root / archive.base._LOCAL, self.root / archive.base.campaign_lease._DIR):
            path.mkdir(exist_ok=True); path.chmod(0o700)
        lock = self.root / archive.base.campaign_lease._DIR / '.environment.lock'
        lock.write_bytes(b''); lock.chmod(0o600)
        for corr in archive._PROFILES.values():
            intent, marker, closed = records(corr)
            write(self.root / archive.base._LOCAL / (corr + '.json'), intent)
            write(self.root / archive.base._LOCAL / (corr + '.unknown-close.json'), marker)
            write(self.root / archive.base.campaign_lease._DIR / (corr + '.closed.json'), closed)
        target = SimpleNamespace(fixture_transfer_root=Path('/fixed/private'))
        p = mock.patch.object(archive.base, '_descriptor', return_value=(None, target, archive._GENERATION))
        self.descriptor = p.start(); self.addCleanup(p.stop)
        p = mock.patch.object(archive.base, '_remote', side_effect=self.remote)
        self.transport = p.start(); self.addCleanup(p.stop)

    def remote(self, config, program, args, source, timeout):
        self.assertEqual(archive._REMOTE, program); self.assertIsNone(source); self.assertEqual(30, timeout)
        corr = args[2]; closed = json.loads(args[-2])
        return json.dumps(fresh(corr, closed)).encode()

    def test_original_stale_version_receipt_and_current_read_only_absence_are_separate(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*.json')}
        for corr in archive._PROFILES.values():
            close, pre = archive._historical_evidence(corr)
            closed = records(corr)[2]
            self.assertEqual(closed['lastEvidenceSha256'], digest(close))
            self.assertEqual('de39fef85a6496602b74de7e7bdf0a913873cef6269afa08b07c6650536b7526', digest(pre))
            self.assertEqual('2.1.17', close['afterFirst']['installedVersion'])
            old = {**close['afterFirst'], 'installedVersion': '2.1.19'}
            # The old mutation admission remains deliberately strict.
            self.assertIsNone(archive.base._unknown_cleanup_project(old, 'status', corr))
            self.assertFalse(archive.base._unknown_both_absent(old))
            self.assertIsNotNone(archive.base._unknown_cleanup_project(close['afterFirst'], 'status', corr))
        result = archive.observe(self.root, {})
        self.assertEqual({**archive._FLAGS, 'state': 'ready', 'phases': {'transfer-recovery': 'archived', 'unknown-closure': 'archived'}}, result)
        self.assertEqual(4, self.transport.call_count)
        after = {str(p): p.read_bytes() for p in self.root.rglob('*.json')}
        self.assertEqual(before, after)
        for call in self.transport.call_args_list:
            ps = base64.b64decode(call.args[2][-1]).decode('utf-16le')
            for mutation in ('Remove-Item', 'Start-Process', 'Register-ScheduledTask', 'Start-ScheduledTask', 'Stop-Process'):
                self.assertNotIn(mutation, ps)

    def test_changed_historical_schema_cannot_relabel_old_receipt(self):
        corr = archive._PROFILES['transfer-recovery']; path = self.root / archive.base.campaign_lease._DIR / (corr + '.closed.json')
        close, _ = archive._historical_evidence(corr)
        close['afterFirst']['installedVersion'] = '2.1.19'; close['afterSecond']['installedVersion'] = '2.1.19'
        value = records(corr)[2]; value['lastEvidenceSha256'] = digest(close); write(path, value)
        result = archive.observe(self.root, {})
        self.assertEqual('blocked', result['state']); self.assertEqual('local-history', result['phases']['transfer-recovery'])
        self.assertEqual(2, self.transport.call_count)

    def test_wrong_identity_hash_outcome_or_private_records_reject(self):
        corr = archive._PROFILES['transfer-recovery']
        paths = (self.root / archive.base._LOCAL / (corr + '.json'),
                 self.root / archive.base._LOCAL / (corr + '.unknown-close.json'),
                 self.root / archive.base.campaign_lease._DIR / (corr + '.closed.json'))
        originals = records(corr)
        cases = ('command', 'source', 'pair', 'marker-hash', 'marker-sid', 'closure-hash', 'outcome', 'sequence',
                 'version-bool', 'closed-extra', 'generation', 'symlink', 'mode', 'missing', 'foreign-owner', 'directory-symlink')
        for case in cases:
            with self.subTest(case=case):
                for p, value in zip(paths, originals):
                    if p.is_symlink(): p.unlink()
                    write(p, value)
                values = copy.deepcopy(originals)
                if case == 'command': values[0]['commandSha256'] = 'a' * 64
                elif case == 'source': values[0]['request']['sourceSha'] = 'b' * 40
                elif case == 'pair': values[0]['pair']['sourceFingerprint'] = 'c' * 64
                elif case == 'marker-hash': values[1]['preMutationEvidenceSha256'] = 'd' * 64
                elif case == 'marker-sid': values[1]['guestGeneration']['expectedSid'] = 'S-1-5-21-foreign'
                elif case == 'closure-hash': values[2]['lastEvidenceSha256'] = 'e' * 64
                elif case == 'outcome': values[2]['lastOutcome'] = 'failed-cleaned'
                elif case == 'sequence': values[2]['sequence'] = 2
                elif case == 'version-bool': values[2]['version'] = True
                elif case == 'closed-extra': values[2]['extra'] = 1
                elif case == 'generation': values[0]['startTicks'] += 1
                for p, value in zip(paths, values): write(p, value)
                if case == 'symlink': paths[0].unlink(); paths[0].symlink_to(paths[1])
                elif case == 'mode': paths[1].chmod(0o644)
                elif case == 'missing': paths[2].unlink()
                elif case == 'directory-symlink':
                    directory = paths[0].parent; saved = directory.with_name(directory.name + '-saved'); directory.rename(saved); directory.symlink_to(saved)
                patch = mock.patch.object(archive.os, 'getuid', return_value=os.getuid() + 1) if case == 'foreign-owner' else mock.patch.object(archive.os, 'getuid', wraps=os.getuid)
                self.transport.reset_mock()
                with patch: result = archive.observe(self.root, {})
                self.assertEqual('blocked', result['state']); self.assertEqual('local-history', result['phases']['transfer-recovery'])
                self.assertTrue(all(call.args[2][2] != corr for call in self.transport.call_args_list))
                if case == 'directory-symlink': directory.unlink(); saved.rename(directory)

    def test_fresh_projection_rejects_stale_version_process_unknown_failed_extra_and_generation(self):
        for key, changed in (('installedVersion', '2.1.17'), ('installedVersion', '2.2.2'), ('state', 'unknown'),
                             ('state', 'failed'), ('remoteStage', 'present'), ('task', 'present'), ('leaf', 'present'),
                             ('result', 'present'), ('installer', 'present'), ('correlationProcess', 'ambiguous'),
                             ('product', 'multiple'), ('campaignSha256', 'a' * 64), ('qemuPid', 1),
                             ('startTicks', 1), ('expectedSid', 'foreign'), ('extra', 'unrequested')):
            with self.subTest(key=key, changed=changed):
                def altered(config, program, args, source, timeout):
                    item = fresh(args[2], json.loads(args[-2])); item[key] = changed
                    return json.dumps(item).encode()
                self.transport.side_effect = altered
                self.assertEqual('blocked', archive.observe(self.root, {})['state'])
        self.transport.side_effect = self.remote
        self.descriptor.return_value = (None, SimpleNamespace(fixture_transfer_root=Path('/fixed/private')),
                                        (*archive._GENERATION[:3], archive._GENERATION[3] + 1, archive._GENERATION[4]))
        self.transport.reset_mock()
        self.assertEqual('blocked', archive.observe(self.root, {})['state']); self.transport.assert_not_called()

    def test_unknown_transport_and_missing_local_records_do_not_write_or_retry(self):
        self.transport.side_effect = None; self.transport.return_value = None
        self.assertEqual('blocked', archive.observe(self.root, {})['state'])
        self.assertEqual(2, self.transport.call_count)
        self.assertEqual({'transfer-recovery': 'remote-transport', 'unknown-closure': 'remote-transport'}, archive.observe(self.root, {})['phases'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.transport.reset_mock()
            self.assertEqual('blocked', archive.observe(root, {})['state'])
            self.assertEqual([], list(root.iterdir())); self.transport.assert_not_called()

    def test_finite_remote_failure_phase_projection_rejects_extra_or_unrecognized_fields(self):
        for phase in archive._REMOTE_PHASES:
            self.transport.side_effect = None
            self.transport.return_value = json.dumps({'state': 'unknown', 'phase': phase}).encode()
            result = archive.observe(self.root, {})
            self.assertEqual('blocked', result['state'])
            self.assertEqual({'transfer-recovery': 'remote-' + phase, 'unknown-closure': 'remote-' + phase}, result['phases'])
            for flag in archive._FLAGS: self.assertIs(result[flag], False)
        for value in ({'state': 'unknown', 'phase': 'raw-secret'}, {'state': 'unknown', 'phase': 'product', 'error': 'raw'},
                      {'state': 'unknown', 'phase': []}, {'state': 'failed', 'phase': 'product'}, {'state': 'unknown'}):
            self.transport.return_value = json.dumps(value).encode()
            self.assertEqual({'transfer-recovery': 'remote-output', 'unknown-closure': 'remote-output'}, archive.observe(self.root, {})['phases'])

    def test_strict_inputs(self):
        for value in (None, [], {'host': 'archlinux'}, {'correlationId': archive._PROFILES['transfer-recovery']}, {'path': '/anything'}):
            with self.assertRaises(ValueError): archive.observe(self.root, value)

    def test_active_or_unknown_local_campaign_blocks_before_remote_observation(self):
        path = self.root / archive.base.campaign_lease._DIR / 'active.json'
        for kind in ('foreign-record', 'wellformed-record', 'malformed-record', 'symlink'):
            if os.path.lexists(path): path.unlink()
            if kind == 'foreign-record': write(path, {'state': 'unknown', 'identity': 'foreign'})
            elif kind == 'wellformed-record': write(path, {**records(archive._PROFILES['transfer-recovery'])[2], 'state': 'active'})
            elif kind == 'malformed-record': path.write_text('{'); path.chmod(0o600)
            else: path.symlink_to(path.parent / 'missing-foreign-record')
            self.transport.reset_mock()
            result = archive.observe(self.root, {})
            self.assertEqual('blocked', result['state'])
            self.assertEqual({'transfer-recovery': 'local-history', 'unknown-closure': 'local-history'}, result['phases'])
            self.transport.assert_not_called()

    def test_missing_symlink_world_readable_and_foreign_lock_are_not_created_or_repaired(self):
        lock = self.root / archive.base.campaign_lease._DIR / '.environment.lock'
        for kind in ('missing', 'symlink', 'mode', 'owner'):
            if os.path.lexists(lock): lock.unlink()
            if kind == 'symlink': lock.symlink_to(lock.parent / 'missing')
            elif kind != 'missing': lock.write_bytes(b''); lock.chmod(0o644 if kind == 'mode' else 0o600)
            patch = mock.patch.object(archive.os, 'getuid', return_value=os.getuid() + 1) if kind == 'owner' else mock.patch.object(archive.os, 'getuid', wraps=os.getuid)
            self.transport.reset_mock()
            with patch: self.assertEqual('blocked', archive.observe(self.root, {})['state'])
            self.transport.assert_not_called()
            if kind == 'missing': self.assertFalse(os.path.lexists(lock))
            if kind == 'symlink': self.assertTrue(lock.is_symlink())
            if kind == 'mode': self.assertEqual(0o644, lock.stat().st_mode & 0o777)

    def test_nested_history_uses_one_actual_shared_flock_and_preserves_outer(self):
        actual=archive.fcntl.flock;calls=[]
        def tracked(fd,op):calls.append((fd,op));return actual(fd,op)
        lock=self.root/archive.base.campaign_lease._DIR/'.environment.lock'
        with mock.patch.object(archive.fcntl,'flock',side_effect=tracked):
            with archive._history_lock(self.root):
                with archive._history_lock(self.root):pass
                fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    with self.assertRaises(BlockingIOError):actual(fd,archive.fcntl.LOCK_EX|archive.fcntl.LOCK_NB)
                finally:os.close(fd)
        self.assertEqual(len(calls),1)
        fd=os.open(lock,os.O_RDONLY|os.O_NOFOLLOW)
        try:actual(fd,archive.fcntl.LOCK_EX|archive.fcntl.LOCK_NB)
        finally:os.close(fd)

    def test_nested_token_rejects_foreign_identity_fd_mode_inode_and_parent(self):
        lock=self.root/archive.base.campaign_lease._DIR/'.environment.lock'
        with archive._history_lock(self.root):
            token=archive._READ_LOCK_STATE.token
            for field,value in (('pid',token.pid+1),('thread',token.thread+1),('root',self.root/'foreign')):
                with mock.patch.object(archive._READ_LOCK_STATE,'token',token._replace(**{field:value})):
                    with self.assertRaises(ValueError):
                        with archive._history_lock(self.root):pass
            foreign=os.open(lock.parent/'foreign',os.O_CREAT|os.O_RDONLY,0o600)
            try:
                with mock.patch.object(archive._READ_LOCK_STATE,'token',token._replace(fd=foreign)):
                    with self.assertRaises(ValueError):
                        with archive._history_lock(self.root):pass
            finally:os.close(foreign)
            lock.chmod(0o644)
            try:
                with self.assertRaises(ValueError):
                    with archive._history_lock(self.root):pass
            finally:lock.chmod(0o600)
            lock.rename(lock.parent/'old-lock');lock.write_bytes(b'');lock.chmod(0o600)
            try:
                with self.assertRaises(ValueError):
                    with archive._history_lock(self.root):pass
            finally:lock.unlink();(lock.parent/'old-lock').rename(lock)
            lock.parent.chmod(0o755)
            try:
                with self.assertRaises(ValueError):
                    with archive._history_lock(self.root):pass
            finally:lock.parent.chmod(0o700)
        self.assertFalse(hasattr(archive._READ_LOCK_STATE,'token'))

    def test_nested_exit_rechecks_and_exception_does_not_release_outer(self):
        lock=self.root/archive.base.campaign_lease._DIR/'.environment.lock'
        with archive._history_lock(self.root):
            with self.assertRaisesRegex(ValueError,'synthetic'):
                with archive._history_lock(self.root):raise ValueError('synthetic')
            with self.assertRaises(ValueError):
                with archive._history_lock(self.root):lock.chmod(0o644)
            lock.chmod(0o600)
            fd=os.open(lock,os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):archive.fcntl.flock(fd,archive.fcntl.LOCK_EX|archive.fcntl.LOCK_NB)
            finally:os.close(fd)
        self.assertFalse(hasattr(archive._READ_LOCK_STATE,'token'))

    def test_queued_real_writer_waits_until_outer_nested_reader_scope_exits(self):
        lock=self.root/archive.base.campaign_lease._DIR/'.environment.lock'
        program="import os,sys,fcntl;f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW);print('queued',flush=True);fcntl.flock(f,fcntl.LOCK_EX);print('exclusive',flush=True);os.close(f)"
        proc=None
        try:
            with archive._history_lock(self.root):
                proc=subprocess.Popen([sys.executable,'-c',program,str(lock)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                self.assertTrue(select.select([proc.stdout],[],[],5)[0]);self.assertEqual(proc.stdout.readline().strip(),'queued')
                self.assertFalse(select.select([proc.stdout],[],[],.05)[0])
                with archive._history_lock(self.root):pass
                self.assertFalse(select.select([proc.stdout],[],[],.05)[0])
            self.assertTrue(select.select([proc.stdout],[],[],5)[0]);self.assertEqual(proc.stdout.readline().strip(),'exclusive');self.assertEqual(proc.wait(5),0)
        finally:
            if proc is not None:
                if proc.poll() is None:proc.kill();proc.wait(5)
                proc.stdout.close();proc.stderr.close()

    @unittest.skipUnless(hasattr(os,'fork'),'POSIX fork token inheritance')
    def test_forked_process_cannot_reuse_parent_lock_token(self):
        program="""import os,sys
from pathlib import Path
from agent_tools import windows_cp117_historical_base_archives as archive
with archive._history_lock(Path(sys.argv[1])):
 child=os.fork()
 if child==0:
  try:
   with archive._history_lock(Path(sys.argv[1])):pass
  except ValueError:os._exit(0)
  except BaseException:os._exit(2)
  os._exit(1)
 _,status=os.waitpid(child,0)
 assert os.waitstatus_to_exitcode(status)==0
"""
        result=subprocess.run([sys.executable,'-c',program,str(self.root)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_shared_history_reader_waits_for_actual_exclusive_campaign_lock(self):
        lock = self.root / archive.base.campaign_lease._DIR / '.environment.lock'
        fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
        archive.fcntl.flock(fd, archive.fcntl.LOCK_EX)
        program = '''import sys
from pathlib import Path
from agent_tools import windows_cp117_historical_base_archives as archive
original=archive.fcntl.flock
def acquired(fd,mode):
 assert mode==archive.fcntl.LOCK_SH
 print('request-shared-lock',flush=True)
 original(fd,mode)
archive.fcntl.flock=acquired
archive._admit(Path(sys.argv[1]),archive._GENERATION,archive._PROFILES['transfer-recovery'])
print('admitted',flush=True)
'''
        proc = subprocess.Popen((sys.executable, '-c', program, str(self.root)), cwd=Path(__file__).resolve().parents[2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([proc.stdout], [], [], 5)[0], 'reader did not reach lock')
            self.assertEqual('request-shared-lock', proc.stdout.readline().strip())
            self.assertFalse(select.select([proc.stdout], [], [], .1)[0], 'reader bypassed exclusive lock')
            self.assertIsNone(proc.poll())
            archive.fcntl.flock(fd, archive.fcntl.LOCK_UN); os.close(fd); fd = None
            out, err = proc.communicate(timeout=5)
            self.assertEqual(0, proc.returncode, err); self.assertEqual('admitted', out.strip())
        finally:
            if fd is not None: os.close(fd)
            if proc.poll() is None: proc.kill(); proc.communicate()


@unittest.skipUnless(archive._supported(), 'remote metadata probe needs POSIX APIs')
class HistoricalRemoteTests(unittest.TestCase):
    def test_actual_read_only_host_and_guest_envelope_admission(self):
        corr = archive._PROFILES['transfer-recovery']; closed = records(corr)[2]
        proof = {key: value for key, value in fresh(corr, closed).items()
                 if key not in {'state', 'correlationId', 'campaignSha256', 'remoteStage', 'qemuPid', 'startTicks'}}
        cases = {'ready': None, 'stage': 'stage', 'active': 'active', 'active-malformed': 'active', 'active-wellformed': 'active',
                 'active-symlink': 'active', 'foreign-campaign': 'closed', 'campaign-mode': 'closed', 'lock-symlink': 'lock',
                 'truncated': 'output-truncated', 'exit': 'output-shape', 'extra': 'output-shape', 'wrong-sid': 'identity', 'generation': 'generation',
                 'opaque-process': 'process', 'task': 'task', 'leaf': 'leaf', 'result': 'result', 'installer': 'installer',
                 'product': 'product', 'guest-failure': 'product', 'exec-error': 'exec', 'status-error': 'status', 'root-mode': 'root',
                 'parser-failed': 'parser', 'stderr-progress': None, 'stderr-progress-failed': 'output-stderr-progress',
                 'stderr-progress-truncated': 'output-truncated', 'stderr-progress-wrong-proof': 'product', 'stderr-error': 'output-stderr-error',
                 'stderr-progress-empty-proof': 'output-empty', 'stderr-invalid': 'output-stderr-other', 'stderr-oversized': 'output-stderr-other',
                 'stderr-other': 'output-stderr-other', 'stderr-mixed': 'output-stderr-other', 'stderr-entity': 'output-stderr-other',
                 'stdout-empty': 'output-empty', 'stdout-json': 'output-json', 'envelope-extra': 'output-envelope'}
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); env = root / 'windows-cp117'; campaign = env / 'windows-cp117-campaign'; group = env / 'windows-msi-base'
                for path in (root, env, campaign, group): path.mkdir(exist_ok=True); path.chmod(0o700)
                cp = campaign / (corr + '.closed.json'); write(cp, closed)
                lock = campaign / '.environment.lock'; lock.write_bytes(b''); lock.chmod(0o600)
                item = {'exited': True, 'exitcode': 0, 'out-data': base64.b64encode(json.dumps(proof).encode()).decode()}
                if case == 'stage': (group / corr).mkdir(mode=0o700)
                elif case == 'active': write(campaign / 'active.json', {'state': 'unknown', 'identity': 'foreign'})
                elif case == 'active-malformed': (campaign / 'active.json').write_text('{'); (campaign / 'active.json').chmod(0o600)
                elif case == 'active-wellformed': write(campaign / 'active.json', {**closed, 'state': 'active'})
                elif case == 'active-symlink': (campaign / 'active.json').symlink_to(campaign / 'foreign-missing')
                elif case == 'foreign-campaign': write(cp, {**closed, 'lastEvidenceSha256': 'a' * 64})
                elif case == 'campaign-mode': cp.chmod(0o644)
                elif case == 'lock-symlink': lock.unlink(); lock.symlink_to(cp)
                elif case == 'truncated': item['out-truncated'] = True
                elif case == 'exit': item['exitcode'] = 1
                elif case == 'root-mode': group.chmod(0o755)
                elif case in ('task', 'leaf', 'result', 'installer', 'product'):
                    payload = {**proof, case: 'multiple' if case == 'product' else 'present'}
                    item['out-data'] = base64.b64encode(json.dumps(payload).encode()).decode()
                elif case == 'guest-failure':
                    item['exitcode'] = 1
                    item['out-data'] = base64.b64encode(b'{"state":"unknown","phase":"product"}').decode()
                elif case.startswith('stderr-'):
                    ns = 'http://schemas.microsoft.com/powershell/2004/04'
                    progress = f'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="{ns}"><Obj S="progress" RefId="0"><MS><S N="Activity">Preparing modules</S></MS></Obj></Objs>'
                    errors = {'stderr-progress': progress,
                              'stderr-progress-failed': progress, 'stderr-progress-truncated': progress, 'stderr-progress-wrong-proof': progress,
                              'stderr-progress-empty-proof': progress, 'stderr-invalid': '#< CLIXML\r\n<Objs', 'stderr-oversized': 'x' * 8193,
                              'stderr-error': f'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="{ns}"><S S="Error">parser failed</S></Objs>',
                              'stderr-other': 'unclassified secret error bytes',
                              'stderr-mixed': f'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="{ns}"><Obj S="progress" RefId="0"/><S S="warning">warning</S></Objs>',
                              'stderr-entity': f'#< CLIXML\r\n<!DOCTYPE Objs [<!ENTITY x "boom">]><Objs Version="1.1.0.1" xmlns="{ns}"><Obj S="progress" RefId="0">&x;</Obj></Objs>'}
                    item['err-data'] = base64.b64encode(errors[case].encode()).decode()
                    if case == 'stderr-progress-failed': item['exitcode'] = 1
                    elif case == 'stderr-progress-truncated': item['err-truncated'] = True
                    elif case == 'stderr-progress-wrong-proof':
                        item['out-data'] = base64.b64encode(json.dumps({**proof, 'installedVersion': '2.1.17'}).encode()).decode()
                    elif case == 'stderr-progress-empty-proof': item['out-data'] = ''
                elif case == 'stdout-empty': item['out-data'] = ''
                elif case == 'stdout-json': item['out-data'] = base64.b64encode(b'{').decode()
                elif case == 'envelope-extra': item['unexpected'] = True
                elif case in ('extra', 'wrong-sid', 'opaque-process'):
                    payload = {**proof, **({'extra': 1} if case == 'extra' else {'expectedSid': 'foreign'} if case == 'wrong-sid' else {'correlationProcess': 'ambiguous'})}
                    item['out-data'] = base64.b64encode(json.dumps(payload).encode()).decode()
                prefix = 'import os,stat,json,sys,hashlib,base64\ndef decode(raw):return raw.decode()\n'
                prefix += 'def live(*args):return ' + ('False' if case == 'generation' else 'True') + '\n'
                actual = archive._PS.replace('@CORR@', corr).replace('@SID@', archive._GENERATION[4]).encode('utf-16le')
                parser_item = {'exited': True, 'exitcode': 1 if case == 'parser-failed' else 0,
                               'out-data': base64.b64encode(b'{"version":1,"code":"FAILED"}' if case == 'parser-failed' else b'{"version":1,"code":"OK"}').decode()}
                prefix += 'import gzip,re\nACTUAL=' + repr(actual) + '\nITEM=' + repr(item) + '\nPARSER_ITEM=' + repr(parser_item) + '\n'
                prefix += '''def call(sock,command,args):
 if command=='guest-exec':
  program=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if 'Parser]::ParseInput' in program:
   packed=re.search("FromBase64String\\('([^']+)'\\)",program).group(1)
   assert gzip.decompress(base64.b64decode(packed))==ACTUAL
   return {'pid':10}
  assert PARSER_ITEM['exitcode']==0,'invalid AST must stop actual invocation'
  assert program.encode('utf-16le')==ACTUAL
  return {'pid':9}
 return PARSER_ITEM if args['pid']==10 else ITEM
'''
                if case == 'exec-error': prefix += 'def call(*args):raise OSError("inert exec failure")\n'
                if case == 'status-error':
                    prefix += 'def call(sock,command,args):\n if command=="guest-exec":return {"pid":9}\n raise OSError("inert status failure")\n'
                # Remote only reads these private fixtures; it cannot select a cleanup mode.
                argv = (sys.executable, '-c', prefix + archive._REMOTE_BODY, str(root), archive._GENERATION[0], corr,
                        archive._GENERATION[1], str(archive._GENERATION[2]), str(archive._GENERATION[3]), archive._GENERATION[4],
                        json.dumps(closed), base64.b64encode(actual).decode())
                before = {str(p): (p.lstat().st_mode, p.read_bytes() if p.is_file() and not p.is_symlink() else None) for p in root.rglob('*')}
                result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=5)
                expected = fresh(corr, closed) if cases[case] is None else {'state': 'unknown', 'phase': cases[case]}
                self.assertEqual(expected, json.loads(result.stdout))
                after = {str(p): (p.lstat().st_mode, p.read_bytes() if p.is_file() and not p.is_symlink() else None) for p in root.rglob('*')}
                self.assertEqual(before, after)


class HistoricalUnavailableApiTests(unittest.TestCase):
    def test_import_and_observe_without_posix_apis_fail_closed(self):
        for missing in ('fcntl', 'getuid'):
            program = '''import builtins,os,sys,tempfile
from pathlib import Path
if sys.argv[1]=='fcntl':
 original=builtins.__import__
 def imported(name,*args,**kwargs):
  if name=='fcntl':raise ImportError('causal unavailable fcntl')
  return original(name,*args,**kwargs)
 builtins.__import__=imported
elif hasattr(os,'getuid'):del os.getuid
from agent_tools import windows_cp117_historical_base_archives as archive
assert archive.base is None
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp);value=archive.observe(root,{})
 assert value['state']=='unknown'
 assert value['replayAllowed'] is False and value['nativeActionAllowed'] is False and value['productAction'] is False
 assert list(root.iterdir())==[]
print('fail-closed')
'''
            result = subprocess.run((sys.executable, '-c', program, missing), cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr); self.assertEqual('fail-closed', result.stdout.strip())


if __name__ == '__main__': unittest.main()
