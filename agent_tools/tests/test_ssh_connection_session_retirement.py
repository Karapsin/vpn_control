"""Disposable completed-master history; no SSH process or guest command."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_connection_session as session
from agent_tools import ssh_connection_session_retirement as retirement


@unittest.skipUnless(os.name == 'posix', 'POSIX private session')
class CompletedSessionRetirementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        key = self.root / 'key'; key.write_bytes(b'inert-key'); key.chmod(0o600)
        known = self.root / 'known'; known.write_bytes(b'inert-host'); known.chmod(0o644)
        gateway = {'host':'gateway.invalid','port':22,'user':'fixture','identityFile':str(key),'knownHostsFile':str(known)}
        nested = {**gateway,'host':'192.0.2.1','transport':'nested','gateway':'gateway','remoteHostAlias':'arch',
                  'remoteControlPath':'/remote/master','knownHostsFile':'/remote/known'}
        self.config_path = self.root / '.vm-hosts.local.json'
        self.config_path.write_text(json.dumps({'schemaVersion':1,'hosts':{'gateway':gateway,'arch':nested}})); self.config_path.chmod(0o600)
        self.journal = session._journal(self.root, 'arch')
        (self.journal/'lock').touch(mode=0o600)
        self.parent = Path(tempfile.mkdtemp(prefix='vcss-')).resolve(); self.parent.chmod(0o700)
        self.addCleanup(lambda: shutil.rmtree(self.parent, ignore_errors=True))
        self.socket_path = self.parent/'m'; self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.socket_path)); self.socket_path.chmod(0o600); self.addCleanup(self.sock.close)
        config, outer, authority = session._snapshot(self.root, 'arch')
        intent = {'version':1,'authority':authority,'socketPath':str(self.socket_path),'parentIdentity':session._directory(self.parent)}
        session._create(self.journal/'intent.json', intent)
        _, intent_pin = session._read(self.journal/'intent.json')
        session._create(self.journal/'child.json', {'intentSha256':session._sha(session._json(intent)), 'pid':12345})
        _, child_pin = session._read(self.journal/'child.json')
        session._create(self.journal/'anchor.json', {'intentPin':intent_pin,'childPin':child_pin,'parentIdentity':intent['parentIdentity']})
        session._create(self.journal/'launch.json', {'version':1,'argvSha256':session._sha(session._json(session._launch_argv(config,outer,self.socket_path))), 'diagnosticLimit':4096})
        diagnostic = self.journal/'launch.stderr.private'; diagnostic.write_bytes(b'original startup'); diagnostic.chmod(0o600)
        raw, fp = session._bytes(diagnostic)
        session._create(self.journal/'startup.json', {'version':1,'exitCode':None,'elapsedMs':10,'stderrBytes':len(raw),'stderrSha256':session._sha(raw),'stderrFingerprint':fp})
        with mock.patch.object(session, '_master', return_value={'pid':12345,'generationSha256':'a'*64}):
            proof, _ = session._verify(self.root,'arch',self.journal,intent)
        session._create(self.journal/'ready.json', proof)
        _, pin = session._read(self.journal/'ready.json'); self.receipt = session._sha(session._json(pin))
        self.socket_path.unlink()
        diagnostic.write_bytes(b'Broken pipe\n' + b'x'*103)
        self.before = {path.name:path.read_bytes() for path in self.journal.iterdir()}
        self.ps = mock.patch.object(retirement.subprocess, 'run', return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b''))
        self.observer = self.ps.start(); self.addCleanup(self.ps.stop)

    def retire(self):
        return retirement.retire(self.root, 'arch', self.receipt)

    def test_positive_dead_completed_master_is_archived_and_original_prepare_stays_fenced_until_retired(self):
        with mock.patch.object(session, '_master', side_effect=AssertionError('no master command')):
            self.assertEqual('unknown', session.prepare(self.root,'arch')['state'])
            result = self.retire()
        self.assertEqual('retired', result['state'])
        self.assertFalse(self.journal.exists())
        archives = list(self.journal.parent.glob(self.journal.name+'-retired-dead-*'))
        self.assertEqual(1,len(archives))
        self.assertEqual(self.before,{path.name:path.read_bytes() for path in archives[0].iterdir()})
        self.assertGreaterEqual(self.observer.call_count,2)
        for call in self.observer.call_args_list:
            self.assertEqual(['/bin/ps','-p','12345','-o','pid='],call.args[0])
        self.assertFalse(result['replayAllowed'])

    def test_live_reused_or_ambiguous_pid_never_renames(self):
        for value in (SimpleNamespace(returncode=0,stdout=b'12345\n',stderr=b''),
                      SimpleNamespace(returncode=1,stdout=b' ',stderr=b''),
                      SimpleNamespace(returncode=1,stdout=b'',stderr=b'error'),
                      SimpleNamespace(returncode=2,stdout=b'',stderr=b'')):
            with self.subTest(value=value), mock.patch.object(retirement.subprocess,'run',return_value=value):
                self.assertEqual('unknown',self.retire()['state'])
            self.assertTrue(self.journal.exists())

    def test_live_socket_or_unknown_startup_without_ready_cannot_retire(self):
        self.socket_path.touch(mode=0o600)
        self.assertEqual('unknown',self.retire()['state']); self.socket_path.unlink()
        (self.journal/'ready.json').unlink()
        self.assertEqual('unknown',self.retire()['state']); self.assertTrue(self.journal.exists())

    def test_concurrent_original_session_lock_prevents_retirement(self):
        fd=os.open(self.journal/'lock',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual('unknown',self.retire()['state'])
            self.assertTrue(self.journal.exists()); self.observer.assert_not_called()
        finally:os.close(fd)

    def test_consumed_retirement_is_status_only_and_never_replays(self):
        self.assertEqual('retired',self.retire()['state'])
        with mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('must not replay')), \
                mock.patch.object(retirement.subprocess,'run',side_effect=AssertionError('status is historical')):
            self.assertEqual('retired',self.retire()['state'])
            self.assertEqual('retired',retirement.status(self.root,'arch',self.receipt)['state'])

    def test_source_record_drift_wrong_receipt_and_hardlink_fail_closed(self):
        for name in ('intent.json','child.json','anchor.json','ready.json'):
            path=self.journal/name; body=path.read_bytes(); path.write_bytes(body)
            self.assertEqual('unknown',self.retire()['state'])
        self.assertTrue(self.journal.exists())
        self.assertEqual('unknown',retirement.retire(self.root,'arch','b'*64)['state'])

    def test_after_consumption_races_are_no_effect_and_never_replayed(self):
        for attack in ('stderr','leaf','intent','socket','collision'):
            with self.subTest(attack=attack):
                # Each causal case owns a fresh disposable, completed session.
                case=CompletedSessionRetirementTests(methodName='test_live_reused_or_ambiguous_pid_never_renames')
                case.setUp()
                try:
                    create=retirement._group_create
                    def raced(directory,path,value):
                        created=create(directory,path,value)
                        if path.name.endswith('.intent.json'):
                            if attack=='stderr': (case.journal/'launch.stderr.private').write_bytes(b'changed diagnostic')
                            elif attack=='leaf':
                                case.journal.rename(case.journal.with_name(case.journal.name+'-swapped'))
                                case.journal.mkdir(mode=0o700)
                            elif attack=='intent': path.write_bytes(path.read_bytes()+b' ')
                            elif attack=='socket': case.socket_path.touch(mode=0o600)
                            else:
                                archive=retirement._paths(case.root,'arch',case.receipt)[3]
                                archive.mkdir(mode=0o700); (archive/'sentinel').write_bytes(b'preserve')
                        return created
                    with mock.patch.object(retirement,'_group_create',side_effect=raced), \
                            mock.patch.object(retirement,'_rename_no_replace',wraps=retirement._rename_no_replace) as rename:
                        self.assertEqual('unknown',case.retire()['state']); rename.assert_not_called()
                    with mock.patch.object(retirement.subprocess,'run',side_effect=AssertionError('consumed is status only')), \
                            mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('no replay')):
                        self.assertEqual('unknown',case.retire()['state'])
                finally:case.doCleanups()

    def test_pid_reuse_between_absence_observations_rejects(self):
        results=[SimpleNamespace(returncode=1,stdout=b'',stderr=b''),SimpleNamespace(returncode=0,stdout=b'12345\n',stderr=b'')]
        with mock.patch.object(retirement.subprocess,'run',side_effect=results), \
                mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('must not archive reused PID')):
            self.assertEqual('unknown',self.retire()['state'])
        self.assertTrue(self.journal.exists())

    def test_actual_exclusive_rename_never_overwrites_destination(self):
        with retirement.Directory(self.journal.parent) as directory:
            destination=self.journal.with_name('exclusive-test-destination'); destination.mkdir(mode=0o700)
            (destination/'sentinel').write_bytes(b'preserve')
            with self.assertRaises(OSError): retirement._rename_no_replace(directory.fd,self.journal.name,destination.name)
            self.assertEqual(b'preserve',(destination/'sentinel').read_bytes())
            self.assertTrue(self.journal.exists())

    def test_historical_status_survives_new_leaf_socket_and_reused_pid(self):
        self.assertEqual('retired',self.retire()['state'])
        self.journal.mkdir(mode=0o700); (self.journal/'new-owner').write_bytes(b'new session')
        self.socket_path.touch(mode=0o600)
        with mock.patch.object(retirement.subprocess,'run',side_effect=AssertionError('must not observe historical PID')), \
                mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('no historical replay')):
            self.assertEqual('retired',self.retire()['state'])
            self.assertEqual('retired',retirement.status(self.root,'arch',self.receipt)['state'])
        self.assertEqual(b'new session',(self.journal/'new-owner').read_bytes())

    def test_archive_only_crash_without_terminal_stays_consumed_unknown(self):
        create=retirement._group_create
        def fail_terminal(directory,path,value):
            if path.name.endswith('.terminal.json'):raise OSError('lost terminal')
            return create(directory,path,value)
        with mock.patch.object(retirement,'_group_create',side_effect=fail_terminal):
            self.assertEqual('unknown',self.retire()['state'])
        self.assertFalse(self.journal.exists())
        with mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('no replay')):
            self.assertEqual('unknown',self.retire()['state'])

    def test_original_source_config_and_socket_parent_authority_remain_required(self):
        with mock.patch.object(session,'_source',return_value='b'*64):
            self.assertEqual('unknown',self.retire()['state'])
        self.parent.chmod(0o755)
        self.assertEqual('unknown',self.retire()['state']); self.parent.chmod(0o700)
        self.config_path.write_bytes(self.config_path.read_bytes()+b' ')
        self.assertEqual('unknown',self.retire()['state']);self.assertTrue(self.journal.exists())

    def test_retirement_file_fsync_failure_leaves_no_replay_fence(self):
        fsync=os.fsync
        def fail_file(fd):
            if os.fstat(fd).st_size>1000:raise OSError('retirement fsync failure')
            return fsync(fd)
        with mock.patch.object(retirement.os,'fsync',side_effect=fail_file), \
                mock.patch.object(retirement,'_rename_no_replace',side_effect=AssertionError('no rename before durable intent')):
            self.assertEqual('unknown',self.retire()['state'])
        self.assertTrue(self.journal.exists())
        with mock.patch.object(retirement.subprocess,'run',side_effect=AssertionError('consumed is status only')):
            self.assertEqual('unknown',self.retire()['state'])

    def test_fresh_original_prepare_can_create_separate_owner_after_retirement(self):
        self.assertEqual('retired',self.retire()['state']); spawns=[]
        def spawn(argv,diagnostic,guard):
            guard.check();guard.require_socket_absent=False
            path=Path(argv[argv.index('-S')+1]); self.addCleanup(lambda:shutil.rmtree(path.parent,ignore_errors=True))
            sock=socket.socket(socket.AF_UNIX); sock.bind(str(path)); path.chmod(0o600); self.addCleanup(sock.close)
            session._create(diagnostic.with_name('launch.json'),{'version':1,'argvSha256':session._sha(session._json(argv)),'diagnosticLimit':4096})
            diagnostic.write_bytes(b'new-owner');diagnostic.chmod(0o600);info=diagnostic.stat()
            spawns.append(argv)
            return SimpleNamespace(pid=23456,poll=lambda:None,_session_stderr_identity=[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink])
        with mock.patch.object(session,'_spawn',side_effect=spawn), \
                mock.patch.object(session,'_master',return_value={'pid':23456,'generationSha256':'b'*64}), \
                mock.patch.object(session.time,'sleep'):
            prepared=session.prepare(self.root,'arch')
        self.assertEqual('ready',prepared['state']);self.assertEqual(1,len(spawns))
        self.assertNotEqual(self.receipt,prepared['receiptSha256'])
        self.assertEqual('retired',retirement.status(self.root,'arch',self.receipt)['state'])
        self.assertTrue(self.journal.exists())


if __name__ == '__main__': unittest.main()
