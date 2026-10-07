import unittest
from agent_tools import ssh_nested_socket_retirement as tool


HEADER = b'Num       RefCount Protocol Flags    Type St Inode Path\n'
PATH = '/tmp/owned/r-123456789abcdef/m'


class UnixTableTests(unittest.TestCase):
    def test_live_endpoint_never_becomes_orphan(self):
        table = HEADER + ('0000000000000000: 00000002 00000000 00010000 0001 01 123 '+PATH+'\n').encode()
        with self.assertRaisesRegex(ValueError, 'kernel_endpoint_present'):
            tool.parse_unix_table(table, PATH)

    def test_incomplete_or_unknown_table_rejected(self):
        for body in (b'', HEADER.rstrip(b'\n'), HEADER+b'broken\n', HEADER+b'0000: 0 0 0 1 1 2\n'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                tool.parse_unix_table(body, PATH)

import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
from contextlib import ExitStack
from unittest import mock
from agent_tools import ssh_recovery_adoption as adoption, ssh_connection_recovery as recovery, ssh_transport
from agent_tools.private_inventory_lock import Directory, Snapshot
from agent_tools.tests import test_ssh_recovery_adoption as original_tests
inventory=original_tests.inventory


class ObserverTests(unittest.TestCase):
    def fixture(self,root):
        group=root/'r-123456789abcdef';group.mkdir(mode=0o700);path=group/'m'
        s=socket.socket(socket.AF_UNIX);s.bind(str(path));s.close();path.chmod(0o600)
        config=root/'config';config.write_text('Host target\n Hostname target.example\n');config.chmod(0o600)
        return {'controlPath':str(path),'configFile':str(config),'remoteHostAlias':'target'}

    def controlled(self):
        original=os.lstat
        def linux_ancestor(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            if Path(path)==Path.cwd().parent and info.st_mode&0o022:
                # Host workspace parent is 0777. Simulate a Linux private
                # ancestor without relaxing the actual production guard.
                names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                fields={k:getattr(info,k) for k in names};fields['st_mode']&=~0o022
                return SimpleNamespace(**fields)
            return info
        return (mock.patch.object(tool.os,'lstat',side_effect=linux_ancestor),mock.patch.object(tool,'read_table',return_value=HEADER),
                mock.patch.object(tool,'refusal',return_value={'exactConnectionRefused':True}),
                mock.patch.object(tool,'effective_route',return_value={'effectiveSha256':'a'*64,'keyMetadata':{}}),
                mock.patch.object(tool,'net_namespace',return_value={'link':'net:[123]','generation':[1]*9}))

    def test_full_orphan_observation_preserves_directory_and_socket(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
            spec=self.fixture(Path(tmp).resolve())
            for p in self.controlled():stack.enter_context(p)
            before=tool.socket_snapshot(spec['controlPath'])
            value=tool.observe_remote(spec)
            self.assertEqual('owned-orphan-observed',value['state']);self.assertEqual(2,len(value['observations']))
            self.assertEqual(before,tool.socket_snapshot(spec['controlPath']));self.assertFalse(value['credentialRead'])

    def test_live_endpoint_rejects_complete_flow_before_control_check(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
            spec=self.fixture(Path(tmp).resolve());table=HEADER+('0000: 00000002 00000000 00010000 0001 01 12 '+spec['controlPath']+'\n').encode()
            patches=self.controlled()
            for p in patches:stack.enter_context(p)
            check=tool.refusal
            with mock.patch.object(tool,'read_table',return_value=table),self.assertRaisesRegex(ValueError,'kernel_endpoint_present'):tool.observe_remote(spec)
            check.assert_not_called()

    def test_socket_directory_same_bytes_metadata_and_namespace_races_reject(self):
        for attack in ('extra','directory-swap','same-inode-ctime','namespace','key','config'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
                spec=self.fixture(Path(tmp).resolve());patches=self.controlled()
                for p in patches:stack.enter_context(p)
                def change(_):
                    path=Path(spec['controlPath'])
                    if attack=='extra':(path.parent/'foreign').write_text('x')
                    elif attack=='directory-swap':path.parent.rename(path.parent.with_name('old'));path.parent.mkdir(mode=0o700)
                    elif attack=='same-inode-ctime':path.chmod(0o400);path.chmod(0o600)
                    elif attack=='namespace':tool.net_namespace.return_value={'link':'net:[456]','generation':[2]*9}
                    elif attack=='key':tool.effective_route.return_value={'changed':True}
                    else:
                        p=Path(spec['configFile']);body=p.read_bytes();p.write_bytes(body)
                    return {'exactConnectionRefused':True}
                with mock.patch.object(tool,'refusal',side_effect=change),self.assertRaises((ValueError,FileNotFoundError)):tool.observe_remote(spec)

    def test_foreign_socket_type_mode_directory_contents_reject(self):
        for attack in ('file','mode','extra','symlink'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
                spec=self.fixture(Path(tmp).resolve());path=Path(spec['controlPath'])
                if attack=='file':path.unlink();path.write_text('not socket');path.chmod(0o600)
                elif attack=='mode':path.chmod(0o666)
                elif attack=='extra':(path.parent/'foreign').write_text('x')
                else:path.rename(path.parent/'other');path.symlink_to('other')
                with self.assertRaises(ValueError):tool.socket_snapshot(str(path))

    def test_exact_refusal_only_live_absent_or_ambiguous_rejected(self):
        spec={'controlPath':PATH,'configFile':'/private/config','remoteHostAlias':'target'}
        for code,out,err in ((0,b'',b'Master running'),(255,b'',b'No such file or directory'),(255,b'',b'Permission denied'),(255,b'x',('Control socket connect('+PATH+'): Connection refused\n').encode())):
            with mock.patch.object(tool.subprocess,'run',return_value=subprocess.CompletedProcess([],code,out,err)),self.assertRaises(ValueError):tool.refusal(spec)
        with mock.patch.object(tool.subprocess,'run',return_value=subprocess.CompletedProcess([],255,b'',('Control socket connect('+PATH+'): Connection refused\n').encode())):
            self.assertTrue(tool.refusal(spec)['exactConnectionRefused'])

    def test_complete_table_masked_pointers_and_other_namespace_entries(self):
        body=HEADER+b'00000000: 00000002 00000000 00000000 0001 01 1 /other\n00000000: 00000002 00000000 00000000 0001 01 2 @abstract\n'
        self.assertEqual(2,tool.parse_unix_table(body,PATH)['rowCount'])
        with self.assertRaises(ValueError):tool.parse_unix_table(body+body[len(HEADER):],PATH)

    def test_remote_source_has_no_effect_or_private_key_read(self):
        source=tool.remote_source();compile(source,'remote','exec')
        for forbidden in ('os.unlink','os.rename','os.kill','ssh-add','passphrase','recover(', '-N'):
            self.assertNotIn(forbidden,source)
        with mock.patch.object(tool,'file_pin',return_value={'unsupportedConfigDirectives':True}),self.assertRaisesRegex(ValueError,'config_dependency_unsupported'):
            tool.observe_remote({'configFile':'/config'})
        with self.assertRaisesRegex(ValueError,'actual_orphan_proof_review_required'):tool.retire(None)


class OwnedBindingTests(unittest.TestCase):
    def fixture(self,root):
        f=original_tests.RecoveryAdoptionTest();old='/remote/original/m';new='/remote/original/r-aaaaaaaaaaaaaaa/m'
        f.write(root,inventory(old));f.ready_intent(root,new)
        with mock.patch.object(recovery,'_socket_state',side_effect=('absent','ready')):
            self.assertEqual('ready',adoption.adopt(root,'nested',5)['state'])
        return old,new

    def read(self,root):
        with ExitStack() as stack:
            d=stack.enter_context(Directory(root));stack.source=stack.enter_context(Snapshot(d,ssh_transport.CONFIG_FILENAME))
            cfg=adoption._validate_candidate(stack.source.body,root)
            target,binding,history=tool._owned_binding(root,cfg,'nested',stack)
            for h in history:h.guard()
            return binding

    def test_only_matching_completed_recovery_and_adoption_admit(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            root=Path(tmp).resolve();self.fixture(root)
            self.assertEqual('a'*32,self.read(root)['correlationId'])

    def test_crossed_route_incomplete_duplicate_and_same_byte_history_reject(self):
        for attack in ('route','incomplete','duplicate','ctime','pending'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
                root=Path(tmp).resolve();self.fixture(root)
                terminal=next((root/'.rag_index/ssh-recovery-adoption').glob('*.adopted.json'))
                value=json.loads(terminal.read_bytes())
                if attack=='route':
                    p=root/ssh_transport.CONFIG_FILENAME;v=json.loads(p.read_bytes());v['hosts']['gateway']['host']='foreign.example';p.write_text(json.dumps(v))
                elif attack=='ctime':
                    p=next((root/'.rag_index/ssh-recovery').glob('nested-*.json'));p.chmod(0o400);p.chmod(0o600)
                elif attack=='duplicate':
                    p=terminal.with_name('b'*64+'.adopted.json');p.write_bytes(terminal.read_bytes());p.chmod(0o600)
                elif attack=='pending':
                    p=terminal.with_name(terminal.name.replace('.adopted.','.pending.'));v=json.loads(p.read_bytes());v['correlationId']='c'*32;p.write_text(json.dumps(v))
                else:value['state']='unknown';terminal.write_text(json.dumps(value))
                with self.assertRaises(ValueError):self.read(root)


class FileParentTests(unittest.TestCase):
    def test_inert_parent_exchange_cannot_retain_identical_leaf_authority(self):
        for body in (False,True):
            with self.subTest(body=body),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
                root=Path(tmp).resolve();parent=root/'keys';parent.mkdir(mode=0o700)
                key=parent/'key';key.write_bytes(b'inert private fixture');key.chmod(0o600)
                initial=tool.file_pin(key,body=body,private=True)
                moved=root/'moved';parent.rename(moved);parent.symlink_to(moved,target_is_directory=True)
                self.assertEqual(initial['generation'],tool.generation(key.stat()))
                with self.assertRaisesRegex(ValueError,'route_parent'):
                    tool.file_pin(key,body=body,private=True)

    def test_parent_same_byte_metadata_change_is_pinned(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            parent=Path(tmp).resolve()/'keys';parent.mkdir(mode=0o700)
            key=parent/'key';key.write_bytes(b'x');key.chmod(0o600)
            initial=tool.file_pin(key,private=True)
            parent.chmod(0o500);parent.chmod(0o700)
            self.assertNotEqual(initial,tool.file_pin(key,private=True))

    def test_parent_exchange_during_leaf_admission_rejects(self):
        for body in (False,True):
            with self.subTest(body=body),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
                root=Path(tmp).resolve();parent=root/'keys';parent.mkdir(mode=0o700)
                key=parent/'key';key.write_bytes(b'inert fixture');key.chmod(0o600)
                real=tool.parent_guard;exchanged=False
                def exchange(chain):
                    nonlocal exchanged
                    real(chain)
                    if not exchanged:
                        exchanged=True;parent.rename(root/'moved');parent.symlink_to(root/'moved',target_is_directory=True)
                with mock.patch.object(tool,'parent_guard',side_effect=exchange),self.assertRaisesRegex(ValueError,'route_parent'):
                    tool.file_pin(key,body=body,private=True)

    def test_closing_observer_rejects_inert_config_or_metadata_key_parent_exchange(self):
        for target in ('config','key'):
            with self.subTest(target=target),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
                root=Path(tmp).resolve();fixture=ObserverTests();spec=fixture.fixture(root)
                route_dir=root/'route';route_dir.mkdir(mode=0o700)
                cfg=route_dir/'config';cfg.write_text('Host target\n Hostname target.example\n');cfg.chmod(0o600);spec['configFile']=str(cfg)
                key_dir=root/'keys';key_dir.mkdir(mode=0o700);key=key_dir/'key';key.write_bytes(b'inert fixture');key.chmod(0o600)
                real_effective=tool.effective_route
                for p in fixture.controlled():stack.enter_context(p)
                # The real case has key/config outside socket ancestry. Hold
                # socket evidence stable to exercise the file-parent guard.
                stable_socket=tool.socket_snapshot(spec['controlPath'])
                stack.enter_context(mock.patch.object(tool,'socket_snapshot',return_value=stable_socket))
                def change(_):
                    parent=route_dir if target=='config' else key_dir
                    moved=root/('moved-'+target);parent.rename(moved);parent.symlink_to(moved,target_is_directory=True)
                    return {'exactConnectionRefused':True}
                response=subprocess.CompletedProcess([],0,('identityfile '+str(key)+'\n').encode(),b'')
                with mock.patch.object(tool,'effective_route',side_effect=real_effective),mock.patch.object(tool.subprocess,'run',return_value=response),mock.patch.object(tool,'refusal',side_effect=change),self.assertRaisesRegex(ValueError,'route_parent|orphan_admission_changed'):
                    tool.observe_remote(spec)

    def test_metadata_key_pin_never_opens_or_reads_key_body(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            key=Path(tmp).resolve()/'key';key.write_bytes(b'inert fixture');key.chmod(0o600)
            real_open=os.open
            def opening(path,*args,**kwargs):
                if str(path)==key.name:raise AssertionError('key body opened')
                return real_open(path,*args,**kwargs)
            with mock.patch.object(tool.os,'open',side_effect=opening),mock.patch.object(tool.os,'read',side_effect=AssertionError('key body read')):
                self.assertEqual(tool.generation(key.stat()),tool.file_pin(key,private=True)['generation'])
