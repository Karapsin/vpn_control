"""Inert outer-session regressions: real private files/sockets, no SSH launch."""
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import ssh_connection_session as s


@unittest.skipUnless(os.name=='posix','POSIX private session authority')
class SessionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.key=self.root/'key';self.key.write_bytes(b'inert-key');self.key.chmod(0o600)
        self.known=self.root/'known';self.known.write_bytes(b'inert-host-key');self.known.chmod(0o644)
        entry={'host':'gateway.invalid','port':2228,'user':'fixture','identityFile':str(self.key),'knownHostsFile':str(self.known)}
        nested={**entry,'host':'192.0.2.1','port':22,'transport':'nested','gateway':'gateway','remoteHostAlias':'arch','remoteControlPath':'/private/inert-master','knownHostsFile':'/private/known'}
        self.config={'schemaVersion':1,'hosts':{'gateway':entry,'archlinux':nested}}
        self.config_path=self.root/'.vm-hosts.local.json';self.write_config()
        self.sockets=[];self.parents=[];self.spawns=[]
        self.addCleanup(self.cleanup_sockets)
        self.spawn_patch=mock.patch.object(s,'_spawn',side_effect=self.spawn);self.spawn_patch.start();self.addCleanup(self.spawn_patch.stop)
        self.master_patch=mock.patch.object(s,'_master',return_value={'pid':12345,'generationSha256':'a'*64});self.master_patch.start();self.addCleanup(self.master_patch.stop)
        self.sleep=mock.patch.object(s.time,'sleep');self.sleep.start();self.addCleanup(self.sleep.stop)
    def write_config(self):
        self.config_path.write_text(json.dumps(self.config));self.config_path.chmod(0o600)
    def cleanup_sockets(self):
        for sock in self.sockets:sock.close()
        group=self.root/s._DIR
        if group.exists():
            for intent in group.glob('*/intent.json'):
                try:self.parents.append(Path(json.loads(intent.read_text())['socketPath']).parent)
                except (ValueError,KeyError):pass
        for parent in self.parents:shutil.rmtree(parent,ignore_errors=True)
    def spawn(self,argv,diagnostic,guard=None):
        if guard is not None:guard.check()
        journal=diagnostic.parent
        self.assertTrue((journal/'intent.json').exists(),'intent must precede launch')
        self.assertNotIn('true',argv);self.assertIn('-N',argv)
        path=Path(argv[argv.index('-S')+1]);self.parents.append(path.parent)
        if guard is not None:guard.require_socket_absent=False
        sock=socket.socket(socket.AF_UNIX);sock.bind(str(path));path.chmod(0o600);self.sockets.append(sock)
        diagnostic.write_bytes(b'inert startup diagnostic');diagnostic.chmod(0o600)
        self.spawns.append(argv)
        i=diagnostic.stat()
        return SimpleNamespace(pid=12345,poll=lambda:None,_session_stderr_identity=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_nlink])
    def ready(self):
        value=s.prepare(self.root,'archlinux');self.assertEqual(value['state'],'ready',value)
        return value
    def journal(self):return s._journal(self.root,'archlinux')

    def test_ready_session_reuses_original_child_without_new_launch(self):
        ready=self.ready();again=s.prepare(self.root,'archlinux')
        self.assertEqual(again['state'],'ready');self.assertEqual(again['receiptSha256'],ready['receiptSha256'])
        self.assertFalse(again['created']);self.assertEqual(len(self.spawns),1)
        options=s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(options[2:],['-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false'])
        self.assertTrue(s.verify_reuse(self.root,'archlinux',ready['receiptSha256']))

    def test_disappearing_mux_socket_cannot_fall_back_to_a_new_handshake(self):
        ready=self.ready();options=s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        path=Path(options[1]);path.unlink()
        # Model OpenSSH's mux failure: plain -S falls back to the network;
        # reuse-only admission carries an explicit failing ProxyCommand.
        def fallback_network(argv):return 'ProxyCommand=false' not in argv
        self.assertTrue(fallback_network(['-S',str(path)]))
        self.assertFalse(fallback_network(options))
        with self.assertRaises(s.SessionUnknown):s.verify_reuse(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown');self.assertEqual(len(self.spawns),1)

    def test_unknown_launch_fence_prevents_second_master_even_after_source_change(self):
        with mock.patch.object(s,'_spawn',side_effect=OSError('inert failure')):
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        self.assertTrue((self.journal()/'intent.json').exists())
        with mock.patch.object(s,'_source',return_value='b'*64):
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        self.assertEqual(self.spawns,[])

    def test_actual_prepare_named_lock_exchange_after_fence_never_launches(self):
        original_create=s._create
        def exchange(path,value,*args,**kwargs):
            original_create(path,value,*args,**kwargs)
            if path.name=='intent.json':
                lock=path.parent/'lock';lock.rename(path.parent/'old-lock')
                lock.write_bytes(b'');lock.chmod(0o600)
        with mock.patch.object(s,'_create',side_effect=exchange):value=s.prepare(self.root,'archlinux')
        self.assertEqual(value['state'],'unknown');self.assertEqual(self.spawns,[])

    def test_actual_prepare_journal_exchange_after_fence_never_launches(self):
        original_create=s._create
        def exchange(path,value,*args,**kwargs):
            original_create(path,value,*args,**kwargs)
            if path.name=='intent.json':
                path.parent.rename(path.parent.with_name(path.parent.name+'-old'))
                path.parent.mkdir(mode=0o700)
                (path.parent/'lock').write_bytes(b'');(path.parent/'lock').chmod(0o600)
        with mock.patch.object(s,'_create',side_effect=exchange):value=s.prepare(self.root,'archlinux')
        self.assertEqual(value['state'],'unknown');self.assertEqual(self.spawns,[])

    def test_config_key_known_host_or_source_drift_rejects_before_reuse(self):
        ready=self.ready()
        for path in (self.config_path,self.key,self.known):
            original=path.read_bytes();path.write_bytes(original+b' ')
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
            path.write_bytes(original)
        self.assertEqual(len(self.spawns),1)
        with mock.patch.object(s,'_source',return_value='b'*64):
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])

    def test_same_bytes_rewritten_child_anchor_and_ready_are_rejected(self):
        ready=self.ready()
        for name in ('ready.json','child.json','anchor.json','intent.json'):
            path=self.journal()/name;raw=path.read_bytes();path.write_bytes(raw)
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(len(self.spawns),1)

    def test_socket_replacement_wrong_parent_permissions_and_changed_master_are_rejected(self):
        ready=self.ready();intent,_=s._read(self.journal()/'intent.json');path=Path(intent['socketPath'])
        path.unlink();other=socket.socket(socket.AF_UNIX);other.bind(str(path));self.sockets.append(other);path.chmod(0o600)
        with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        path.parent.chmod(0o755)
        with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        path.parent.chmod(0o700)
        with mock.patch.object(s,'_master',return_value={'pid':99999,'generationSha256':'b'*64}):
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(len(self.spawns),1)

    def test_private_file_hardlinks_symlinks_and_journal_public_parent_fail_closed(self):
        ready=self.ready();child=self.journal()/'child.json';os.link(child,self.root/'child-alias')
        with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(len(self.spawns),1)
        (self.root/'.rag_index').chmod(0o755)
        self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')

    def test_outer_password_and_direct_routes_are_not_launched(self):
        self.config['hosts']['gateway']['password']='inert-secret';self.write_config()
        self.assertEqual(s.prepare(self.root,'archlinux')['phase'],'unsupported');self.assertEqual(self.spawns,[])
        self.config['hosts']['gateway'].pop('password');self.write_config()
        self.assertEqual(s.prepare(self.root,'gateway')['phase'],'unsupported');self.assertEqual(self.spawns,[])

    def test_actual_nested_route_remote_credentials_are_config_bound_not_read_locally(self):
        self.config['hosts']['archlinux']['identityFile']='/home/inert-remote/.ssh/id_ed25519'
        self.config['hosts']['archlinux']['knownHostsFile']='/home/inert-remote/.ssh/known_hosts'
        self.write_config();original_bytes=s._bytes;reads=[]
        def observed(path,*args,**kwargs):
            reads.append(str(path));return original_bytes(path,*args,**kwargs)
        with mock.patch.object(s,'_bytes',side_effect=observed):ready=self.ready()
        self.assertFalse(any(path.startswith('/home/inert-remote/') for path in reads))
        config,outer,authority=s._snapshot(self.root,'archlinux')
        self.assertEqual({p['path'] for p in authority['files']},{str(self.key),str(self.known)})
        self.config['hosts']['archlinux']['identityFile']='/home/inert-remote/.ssh/replaced_key'
        self.write_config()
        with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])
        self.assertEqual(len(self.spawns),1)

    def test_before_after_admission_detects_config_change_during_master_check(self):
        ready=self.ready()
        def changed(*args):
            self.known.write_bytes(b'changed');return {'pid':12345,'generationSha256':'a'*64}
        with mock.patch.object(s,'_master',side_effect=changed):
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])

    def test_builtin_launch_and_check_commands_never_contain_remote_payload(self):
        config,outer,_=s._snapshot(self.root,'archlinux');path=Path('/tmp/inert-private/m')
        launch=s._launch_argv(config,outer,path);check=s._check_argv(config,outer,path)
        self.assertEqual(launch[-1],'gateway.invalid');self.assertIn('-N',launch);self.assertNotIn('true',launch)
        self.assertEqual(check[-3:],['-O','check','gateway.invalid']);self.assertIn('ProxyCommand=false',check)
        self.assertEqual(launch[:3],['/usr/bin/ssh','-F','/dev/null'])
        self.assertIn('ClearAllForwardings=yes',launch);self.assertIn('ForkAfterAuthentication=no',launch)
        self.assertNotIn('inert-secret',json.dumps(launch))

    @unittest.skipUnless(Path('/usr/bin/ssh').is_file(),'OpenSSH effective config is unavailable')
    def test_actual_openssh_launch_is_noninteractive_master_not_ask(self):
        config,outer,_=s._snapshot(self.root,'archlinux')
        launch=s._launch_argv(config,outer,Path('/tmp/inert-no-connect/m'))
        # -G prints effective options and exits before any network operation.
        observed=subprocess.run([*launch[:-1],'-G',launch[-1]],stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual(observed.returncode,0)
        options=dict(line.split(' ',1) for line in observed.stdout.decode().splitlines() if ' ' in line)
        self.assertEqual(options.get('controlmaster'),'true')

    def test_master_check_pins_pid_generation_and_returns_no_raw_diagnostic(self):
        self.master_patch.stop()
        config,outer,_=s._snapshot(self.root,'archlinux')
        outputs=[SimpleNamespace(returncode=0,stdout=b'',stderr=b'Master running (pid=12345)\r\n'),
                 SimpleNamespace(returncode=0,stdout=(str(os.getuid())+' Fri Oct  3 03:00:00 2026 /usr/bin/ssh\n').encode(),stderr=b'')]
        with mock.patch.object(s.subprocess,'run',side_effect=outputs) as run:
            result=s._master(config,outer,Path('/tmp/inert/m'))
        self.assertEqual(set(result),{'pid','generationSha256'});self.assertEqual(result['pid'],12345)
        self.assertEqual(run.call_count,2)

    def test_missing_admission_does_not_create_a_journal_or_master(self):
        self.assertEqual(s.admission(self.root,'archlinux','a'*64)['state'],'unknown')
        self.assertFalse((self.root/'.rag_index').exists());self.assertEqual(self.spawns,[])

    def test_source_byte_drift_after_fence_never_rekeys_journal_to_create_master(self):
        self.ready();journal=self.journal()
        with mock.patch.object(s,'_source',return_value='b'*64):
            value=s.prepare(self.root,'archlinux')
        self.assertEqual(value['state'],'unknown');self.assertEqual(self.journal(),journal);self.assertEqual(len(self.spawns),1)

    def test_selected_options_is_readonly_no_intent_then_reuses_exact_ready(self):
        config=s.transport.load_config(self.root)
        self.assertEqual(s.selected_options(config,'archlinux'),[]);self.assertFalse((self.root/'.rag_index').exists())
        ready=self.ready()
        self.assertEqual(s.selected_options(config,'archlinux'),s.reuse_only_options(self.root,'archlinux',ready['receiptSha256']))
        self.assertEqual(s.selected_options(config,'gateway'),[])
        self.assertEqual(len(self.spawns),1)

    def test_selected_unknown_fence_has_no_plain_fallback_or_new_directory(self):
        with mock.patch.object(s,'_spawn',side_effect=OSError('inert')):s.prepare(self.root,'archlinux')
        config=s.transport.load_config(self.root);before=sorted(p.name for p in self.journal().iterdir())
        with self.assertRaises(s.SessionUnknown):s.selected_options(config,'archlinux')
        self.assertEqual(sorted(p.name for p in self.journal().iterdir()),before);self.assertEqual(self.spawns,[])

    def test_selected_options_rejects_stale_config_and_private_parent(self):
        config=s.transport.load_config(self.root);self.ready()
        self.config['hosts']['gateway']['port']=2229;self.write_config()
        with self.assertRaises(s.SessionUnknown):s.selected_options(config,'archlinux')
        current=s.transport.load_config(self.root);(self.root/'.rag_index').chmod(0o755)
        with self.assertRaises(s.SessionUnknown):s.selected_options(current,'archlinux')

    def test_actual_startup_exit255_retains_private_bounded_stderr_without_replay(self):
        self.spawn_patch.stop();actual=s._spawn
        def inert_start(argv,path,guard):
            process=actual([sys.executable,'-c',"import sys;sys.stderr.write('inert failure');sys.exit(255)"],path,guard)
            process.wait(timeout=5);return process
        with mock.patch.object(s,'_spawn',side_effect=inert_start) as spawned:
            result=s.prepare(self.root,'archlinux')
            self.assertEqual(result['state'],'unknown')
            startup,_=s._read(self.journal()/'startup.json')
            self.assertEqual(startup['exitCode'],255);self.assertEqual(startup['stderrBytes'],13)
            stderr=self.journal()/'launch.stderr.private';self.assertEqual(stderr.read_bytes(),b'inert failure');self.assertEqual(stderr.stat().st_mode & 0o777,0o600)
            self.assertNotIn('inert failure',json.dumps(result))
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown');self.assertEqual(spawned.call_count,1)

    def test_fence_rewrite_during_private_launch_record_creation_blocks_effect(self):
        self.spawn_patch.stop();original_create=s._create
        def rewrite(path,value,*args,**kwargs):
            original_create(path,value,*args,**kwargs)
            if path.name=='launch.json':
                intent=path.parent/'intent.json';intent.write_bytes(intent.read_bytes())
        with mock.patch.object(s,'_create',side_effect=rewrite),mock.patch.object(s.subprocess,'Popen') as spawned:
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        spawned.assert_not_called()

    def test_socket_parent_exchange_during_launch_record_blocks_effect(self):
        self.spawn_patch.stop();original_create=s._create
        def exchange(path,value,*args,**kwargs):
            original_create(path,value,*args,**kwargs)
            if path.name=='launch.json':
                intent,_=s._read(path.parent/'intent.json');parent=Path(intent['socketPath']).parent
                old=parent.with_name(parent.name+'-old');parent.rename(old);self.parents.append(old)
                parent.mkdir(mode=0o700)
        with mock.patch.object(s,'_create',side_effect=exchange),mock.patch.object(s.subprocess,'Popen') as spawned:
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        spawned.assert_not_called()

    def test_credential_authority_change_during_launch_record_blocks_effect(self):
        self.spawn_patch.stop();original_create=s._create
        def exchange(path,value,*args,**kwargs):
            original_create(path,value,*args,**kwargs)
            if path.name=='launch.json':self.key.write_bytes(b'replaced key')
        with mock.patch.object(s,'_create',side_effect=exchange),mock.patch.object(s.subprocess,'Popen') as spawned:
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        spawned.assert_not_called()

    def test_actual_spawn_lock_exchange_during_last_authority_read_never_launches(self):
        self.spawn_patch.stop();original_snapshot=s._snapshot;exchanged=False
        def exchange(root,host):
            nonlocal exchanged
            result=original_snapshot(root,host)
            journal=self.journal()
            if (journal/'launch.stderr.private').exists() and not exchanged:
                exchanged=True;lock=journal/'lock';lock.rename(journal/'prior-lock')
                lock.write_bytes(b'');lock.chmod(0o600)
            return result
        with mock.patch.object(s,'_snapshot',side_effect=exchange),mock.patch.object(s.subprocess,'Popen',return_value=SimpleNamespace(pid=12345,poll=lambda:None)) as spawned:
            self.assertEqual(s.prepare(self.root,'archlinux')['state'],'unknown')
        self.assertTrue(exchanged);spawned.assert_not_called()

    def test_master_generation_mismatch_rejects_same_pid(self):
        ready=self.ready()
        with mock.patch.object(s,'_master',return_value={'pid':12345,'generationSha256':'b'*64}):
            with self.assertRaises(s.SessionUnknown):s.reuse_only_options(self.root,'archlinux',ready['receiptSha256'])

    def test_spawn_receives_kernel_capped_private_diagnostic_and_no_output_pipe(self):
        self.spawn_patch.stop()
        result=SimpleNamespace(pid=12345)
        with mock.patch.object(s.subprocess,'Popen',return_value=result) as popen:
            self.assertIs(s._spawn(['/usr/bin/ssh','-N','gateway.invalid'],self.root/'diagnostic'),result)
        self.assertIsInstance(popen.call_args.kwargs['stderr'],int)
        self.assertIn('RLIMIT_FSIZE',popen.call_args.args[0][2])
        self.assertEqual(popen.call_args.kwargs['stdout'],subprocess.DEVNULL)
        diagnostic,_=s._read(self.root/'launch.json')
        self.assertEqual(set(diagnostic),{'version','argvSha256','diagnosticLimit'})
        self.assertEqual(diagnostic['diagnosticLimit'],4096)
        self.assertLess((self.root/'launch.json').stat().st_size,256)

if __name__=='__main__':unittest.main()
