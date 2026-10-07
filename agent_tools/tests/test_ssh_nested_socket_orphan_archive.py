import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from contextlib import contextmanager, ExitStack
import unittest
from unittest import mock
from agent_tools import ssh_nested_socket_orphan_archive as tool
from agent_tools.tests import test_ssh_nested_socket_owned_home_observation as home_tests
from agent_tools.tests import test_ssh_nested_socket_retirement as old_tests


class OrphanArchiveTests(unittest.TestCase):
    @contextmanager
    def fixture(self, generated=False):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp, ExitStack() as stack:
            root=Path(tmp).resolve();spec,home,key,stdout=home_tests.OwnedHomeObserverTests().full_fixture(root)
            stack.enter_context(old_tests.ObserverTests().controlled()[0])
            stack.enter_context(mock.patch.object(tool.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(home))))
            def ssh(argv,**kwargs):
                self.assertIn('-T',argv)
                if '-G' in argv:return subprocess.CompletedProcess(argv,0,stdout,b'')
                self.assertEqual(['-O','check','target'],argv[-3:])
                return subprocess.CompletedProcess(argv,255,b'',('Control socket connect('+spec['controlPath']+'): Connection refused\n').encode())
            stack.enter_context(mock.patch.object(subprocess,'run',side_effect=ssh))
            stack.enter_context(mock.patch.object(tool,'read_table',return_value=tool.HEADER))
            stack.enter_context(mock.patch.object(tool,'net_namespace',return_value={'link':'net:[1]','generation':[1]*9}))
            result=tool.observe_remote(spec)
            wrapped={'schema':1,'host':'archlinux','correlationId':tool.OBSERVATION,'intent':tool.OBS_INTENT_PIN,'archiveAllowed':False,'result':result}
            raw=(json.dumps(wrapped,sort_keys=True,separators=(',',':'))+'\n').encode()
            pin=dict(tool.PROOF_PIN,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            stack.enter_context(mock.patch.object(tool,'PROOF_PIN',pin))
            packet={'effect':'archive-owned-orphan-correlation-directory','observationId':tool.OBSERVATION,'host':'archlinux','spec':spec,'observationBase64':base64.b64encode(raw).decode(),'archiveSourceSha256':'a'*64}
            yield root,spec,key,packet,stack

    def destination(self,packet):
        path=Path(packet['spec']['controlPath'])
        key=hashlib.sha256((tool.OBSERVATION+tool.PROOF_PIN['sha256']+str(path)).encode()).hexdigest()
        return path.parent.parent/('.retired-orphan-'+path.parent.name+'-'+key[:16]),path.parent.parent/('.orphan-retire-'+key[:24])

    def test_no_archive_from_incomplete_or_foreign_or_live_proof(self):
        for packet in ({},{'proof':{'state':'unknown'}},{'proof':{'state':'owned-orphan-observed','observations':[{'before':{'endpointCount':1}}]}}):
            with self.subTest(packet=packet),self.assertRaises(ValueError):tool.archive_remote(packet)

    def test_full_flow_archives_only_owned_directory_and_status_never_replays(self):
        with self.fixture() as (root,spec,key,packet,stack):
            destination,journal=self.destination(packet);key_before=key.stat();socket_before=tool.generation(Path(spec['controlPath']).stat())
            original_open=os.open
            def no_key(path,*args,**kwargs):
                if str(path)==key.name:raise AssertionError('key body read')
                return original_open(path,*args,**kwargs)
            stack.enter_context(mock.patch.object(os,'open',side_effect=no_key))
            value=tool.archive_remote(packet)
            self.assertEqual('archived',value['state']);self.assertFalse(value['replayAllowed'])
            self.assertFalse(Path(spec['controlPath']).parent.exists());self.assertEqual(['m'],os.listdir(destination))
            self.assertEqual(socket_before,tool.generation((destination/'m').stat()));self.assertEqual(tool.generation(key_before),tool.generation(key.stat()))
            self.assertEqual(['intent.json','lock','terminal.json'],sorted(os.listdir(journal)))
            # New recovery may legitimately reuse the original path. Historical
            # closure checks the archived leaf, never the fresh master or kernel.
            Path(spec['controlPath']).parent.mkdir(mode=0o700)
            with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')),mock.patch.object(tool,'rename_exclusive',side_effect=AssertionError('replay')):
                self.assertEqual('archived',tool.archive_remote(packet)['state'])

    def test_live_and_incomplete_kernel_tables_before_effect(self):
        for body in (b'',tool.HEADER.rstrip(b'\n'),tool.HEADER+b'broken\n','live'):
            with self.subTest(body=body),self.fixture() as (_,spec,_,packet,_),mock.patch.object(tool,'rename_exclusive') as rename:
                table=tool.HEADER+('0000: 00000002 00000000 00010000 0001 01 12 '+spec['controlPath']+'\n').encode() if body=='live' else body
                with mock.patch.object(tool,'read_table',return_value=table),self.assertRaises(ValueError):tool.archive_remote(packet)
                rename.assert_not_called()

    def test_same_bytes_metadata_foreign_extra_and_destination_collision(self):
        for attack in ('ctime','foreign','destination','key','config','symlink'):
            with self.subTest(attack=attack),self.fixture() as (_,spec,key,packet,_),mock.patch.object(tool,'rename_exclusive') as rename:
                path=Path(spec['controlPath'])
                if attack=='ctime':path.chmod(0o400);path.chmod(0o600)
                elif attack=='foreign':(path.parent/'foreign').write_text('x')
                elif attack=='destination':self.destination(packet)[0].mkdir(mode=0o700)
                elif attack=='key':key.chmod(0o400);key.chmod(0o600)
                elif attack=='config':Path(spec['configFile']).chmod(0o400);Path(spec['configFile']).chmod(0o600)
                else:path.parent.rename(path.parent.with_name('saved'));path.parent.symlink_to('saved',target_is_directory=True)
                with self.assertRaises((ValueError,OSError)):tool.archive_remote(packet)
                rename.assert_not_called()

    def test_fenced_observation_and_last_guard_drift_reject(self):
        for attack in ('second-observation-key','final-fence','final-kernel'):
            with self.subTest(attack=attack),self.fixture() as (_,spec,key,packet,_),mock.patch.object(tool,'rename_exclusive') as rename:
                original=tool.observe_remote;calls=0
                def observe(value):
                    nonlocal calls
                    calls+=1
                    if calls==2 and attack=='second-observation-key':key.chmod(0o400);key.chmod(0o600)
                    result=original(value)
                    if calls==2 and attack=='final-fence':
                        _,journal=self.destination(packet);pending=journal/'intent.json';pending.write_bytes(pending.read_bytes());pending.chmod(0o600)
                    return result
                final=tool.final_guard
                def guard(*args):
                    if attack=='final-kernel':
                        table=tool.HEADER+('0000: 00000002 00000000 00010000 0001 01 12 '+spec['controlPath']+'\n').encode()
                        with mock.patch.object(tool,'read_table',return_value=table):return final(*args)
                    return final(*args)
                with mock.patch.object(tool,'observe_remote',side_effect=observe),mock.patch.object(tool,'final_guard',side_effect=guard),self.assertRaises(ValueError):tool.archive_remote(packet)
                rename.assert_not_called()
                with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('consumed replay')):
                    self.assertEqual('consumed-unknown',tool.archive_remote(packet)['state'])

    def test_receipt_failure_before_rename_and_crash_after_rename_never_replay(self):
        for phase in ('intent','terminal'):
            with self.subTest(phase=phase),self.fixture() as (_,spec,_,packet,_):
                original=tool.create_receipt
                def create(fd,name,value):
                    if name==phase+'.json':raise OSError('inert fsync failure')
                    return original(fd,name,value)
                with mock.patch.object(tool,'create_receipt',side_effect=create),self.assertRaises(OSError):tool.archive_remote(packet)
                destination,journal=self.destination(packet)
                self.assertEqual(phase=='terminal',destination.exists())
                with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')),mock.patch.object(tool,'rename_exclusive',side_effect=AssertionError('replay')):
                    if phase=='intent':
                        with self.assertRaises(ValueError):tool.archive_remote(packet)
                    else:self.assertEqual('consumed-unknown',tool.archive_remote(packet)['state'])

    def test_generated_program_contains_complete_archive_flow_and_frozen_observer(self):
        source=tool.remote_source();tree=ast.parse(source)
        nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef)) or isinstance(n,ast.Assign) and not any(isinstance(x,ast.Name) and x.id=='packet' for t in n.targets for x in ast.walk(t))]
        ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'archive-generated','exec'),ns)
        for name in ('archive_remote','observe_remote','final_guard','rename_exclusive','journal_status'):self.assertTrue(callable(ns[name]))
        for forbidden in ('os.unlink','os.kill','SIGTERM','read_private_key'):self.assertNotIn(forbidden,source)
        with mock.patch.object(tool.observer,'remote_source',return_value='changed'),self.assertRaisesRegex(ValueError,'consumed_observer_program_changed'):tool.remote_source()

    def test_exclusive_rename_never_overwrites_collision_created_at_effect(self):
        with self.fixture() as (_,spec,_,packet,_):
            destination,_=self.destination(packet);original=tool.rename_exclusive
            def race(fd,source,target):
                destination.mkdir(mode=0o700);(destination/'foreign').write_text('preserve')
                return original(fd,source,target)
            with mock.patch.object(tool,'rename_exclusive',side_effect=race),self.assertRaises(OSError):tool.archive_remote(packet)
            self.assertTrue(Path(spec['controlPath']).exists());self.assertEqual('preserve',(destination/'foreign').read_text())
            with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')):self.assertEqual('consumed-unknown',tool.archive_remote(packet)['state'])

    def test_concurrent_lock_and_foreign_journal_never_mutate(self):
        for attack in ('locked','lock-symlink','extra'):
            with self.subTest(attack=attack),self.fixture() as (_,spec,_,packet,_):
                original=tool.create_receipt
                def fail(fd,name,value):
                    original(fd,name,value)
                    raise OSError('crash after durable fence')
                with mock.patch.object(tool,'create_receipt',side_effect=fail),self.assertRaises(OSError):tool.archive_remote(packet)
                _,journal=self.destination(packet)
                if attack=='locked':
                    fd=os.open(journal/'lock',os.O_RDONLY);tool.fcntl.flock(fd,tool.fcntl.LOCK_EX|tool.fcntl.LOCK_NB)
                elif attack=='lock-symlink':
                    (journal/'lock').rename(journal/'saved');(journal/'lock').symlink_to('saved')
                else:(journal/'foreign').write_text('x')
                try:
                    with mock.patch.object(tool,'rename_exclusive') as rename,mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')),self.assertRaises((ValueError,OSError)):tool.archive_remote(packet)
                    rename.assert_not_called();self.assertTrue(Path(spec['controlPath']).exists())
                finally:
                    if attack=='locked':os.close(fd)

    def test_actual_directory_fsync_failure_blocks_effect_and_consumes_attempt(self):
        with self.fixture() as (_,spec,_,packet,_):
            original=tool.os.fsync
            def fail(fd):
                if tool.stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert directory fsync failure')
                return original(fd)
            with mock.patch.object(os,'fsync',side_effect=fail),mock.patch.object(tool,'rename_exclusive') as rename,self.assertRaises(OSError):tool.archive_remote(packet)
            rename.assert_not_called();self.assertTrue(Path(spec['controlPath']).exists())
            with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')),self.assertRaises(OSError):tool.archive_remote(packet)

    def test_same_byte_proof_rewrite_and_consumed_terminal_drift_fail_closed(self):
        with self.fixture() as (_,spec,_,packet,_):
            changed=dict(packet);changed['observationBase64']=base64.b64encode(base64.b64decode(packet['observationBase64'])+b' ').decode()
            with mock.patch.object(tool,'rename_exclusive') as rename,self.assertRaisesRegex(ValueError,'observed_proof_changed'):tool.archive_remote(changed)
            rename.assert_not_called()
            tool.archive_remote(packet);_,journal=self.destination(packet)
            terminal=json.loads((journal/'terminal.json').read_bytes());terminal['archived']['socket'][8]+=1
            (journal/'terminal.json').write_text(json.dumps(terminal));(journal/'terminal.json').chmod(0o600)
            with mock.patch.object(tool,'observe_remote',side_effect=AssertionError('replay')),self.assertRaisesRegex(ValueError,'historical_archive_changed'):tool.archive_remote(packet)

    def test_generated_full_flow_not_just_imported_functions(self):
        with self.fixture() as (_,spec,_,packet,_):
            tree=ast.parse(tool.remote_source());nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef)) or isinstance(n,ast.Assign) and not any(isinstance(x,ast.Name) and x.id=='packet' for t in n.targets for x in ast.walk(t))]
            ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'fixed-program','exec'),ns)
            ns['read_table']=lambda:tool.HEADER;ns['net_namespace']=lambda:{'link':'net:[1]','generation':[1]*9}
            self.assertEqual('archived',ns['archive_remote'](packet)['state'])

    def test_local_completed_result_requires_full_remote_closure_not_state_string(self):
        with self.fixture() as (_,_,_,packet,_):
            original=json.loads(base64.b64decode(packet['observationBase64']))['result']
            value=tool.archive_remote(packet);self.assertTrue(tool.completed_remote(value,original))
            for field,replacement in (('terminalPin',{}),('archived',{}),('replayAllowed',True),('archivePerformed',False)):
                changed=dict(value);changed[field]=replacement;self.assertFalse(tool.completed_remote(changed,original))
            self.assertFalse(tool.completed_remote({'state':'archived'},original))
