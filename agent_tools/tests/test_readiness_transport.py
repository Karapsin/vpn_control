"""Actual complete generated callers and Unix control sockets, no VM/VPN."""
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import readiness
from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture
if os.name=='posix':
    from agent_tools import readiness_transport as subject
    from agent_tools import readiness_ssh_master as master
    from agent_tools import ssh_direct_nested_channel as direct


@unittest.skipUnless(os.name=='posix','POSIX owned control socket')
class ReadinessTransportTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.peer=PeerFixture(self.root)
        self.binary=self.root/'ssh'
        source=Path(__file__).parent/'fixtures/readiness_transport/ssh_peer.source'
        self.binary.write_text('#!'+sys.executable+'\n'+source.read_text());self.binary.chmod(0o700)
        self.mode=self.root/'mode'
        environment=mock.patch.dict(os.environ,{'VC_READINESS_FIXTURE_MODE':str(self.mode)})
        environment.start();self.addCleanup(environment.stop)
        original_prefix=transport.fresh_direct_prefix
        def prefix(config,host):
            argv,endpoint=original_prefix(config,host)
            return [str(self.binary),*argv[1:]],endpoint
        patched=mock.patch.object(transport,'fresh_direct_prefix',side_effect=prefix)
        patched.start();self.addCleanup(patched.stop)
        self.requirements=readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'}))
        self.context=subject.context(self.root,'explicit-peer',deadline=time.monotonic()+15,sleep=lambda _:None)
        self.children=[]
        spawn=master.session._spawn
        def spawning(*args,**kwargs):
            process=spawn(*args,**kwargs);self.children.append(process);return process
        patch_spawn=mock.patch.object(master.session,'_spawn',side_effect=spawning)
        patch_spawn.start();self.addCleanup(patch_spawn.stop)
        self.addCleanup(self.close_children)
        # Only the executable path is a declared fixture seam. Production
        # build_ssh_argv, readiness observation, fixed command and sockets run.
        builder=transport._build_ssh_argv
        def built(*args,**kwargs):
            argv=builder(*args,**kwargs);argv[0]=str(self.binary);return argv
        patch_builder=mock.patch.object(transport,'_build_ssh_argv',side_effect=built)
        patch_builder.start();self.addCleanup(patch_builder.stop)

    def close_children(self):
        for child in self.children:
            if child.poll() is None:child.terminate()
            child.wait(timeout=3)

    def ensure(self):
        return readiness.ensure_ready(self.context,self.requirements,str(uuid.uuid4()))

    def test_healthy_owned_master_binds_actual_connection_and_pure_builder_reuses(self):
        ready=self.ensure()
        self.assertTrue(ready.boot);self.assertTrue(ready.account);self.assertTrue(ready.connection)
        self.assertEqual(1,len(self.children))
        readiness.revalidate(self.context,ready)
        second=self.ensure();self.assertEqual(ready.identities(),second.identities())
        self.assertEqual(1,len(self.children))
        config=transport.load_config(self.root)
        owner=master.status(self.root,'explicit-peer',config)
        argv=transport.build_ssh_argv(config,'explicit-peer',command=('python3','-c',"print('sentinel')"))
        self.assertIn(owner['socketPath'],argv)
        result=subprocess.run(argv,capture_output=True,timeout=3)
        self.assertEqual((0,b'sentinel\n',b''),(result.returncode,result.stdout,result.stderr))
        self.assertEqual(1,len(self.children))

    def test_original_direct_getter_ignores_admitted_connection_current_reuses_it(self):
        self.ensure()
        fixture=Path(__file__).parent/'fixtures/readiness_transport'
        raw=(fixture/'ssh_transport.before-readiness-hook.source').read_bytes()
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        self.assertEqual(provenance['beforeTransportSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._before_readiness_transport')
        before.__file__=str(fixture/'ssh_transport.before-readiness-hook.source');before.__package__='agent_tools'
        sys.modules[before.__name__]=before;self.addCleanup(sys.modules.pop,before.__name__)
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        owner=master.status(self.root,'explicit-peer')
        def oracle(builder):
            argv=builder(transport.load_config(self.root),'explicit-peer')
            self.assertIn(owner['socketPath'],argv)
        with self.assertRaises(AssertionError):oracle(before.build_ssh_argv)
        oracle(transport.build_ssh_argv)
        self.assertEqual(1,len(self.children))

    def test_original_fresh_gateway_copies_conflicting_master_red_explicit_raw_route_green(self):
        self.ensure()
        fixture=Path(__file__).parent/'fixtures/readiness_transport'
        raw=(fixture/'ssh_direct_nested_channel.before-raw-prefix.source').read_bytes()
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        self.assertEqual(provenance['beforeDirectSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._before_raw_prefix')
        before.__file__=str(fixture/'ssh_direct_nested_channel.before-raw-prefix.source');before.__package__='agent_tools'
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        config=transport.load_config(self.root);target=config.hosts['explicit-peer']
        def result(provider):
            prefix,endpoint=provider.outer_prefix(config,target)
            return subprocess.run([*prefix,*direct.OUTER_OPTIONS,'-T',endpoint,
                 shlex.join(('python3','-I','-B','-c',"print('raw-prefix-sentinel')"))],capture_output=True,timeout=3)
        old=result(before)
        self.assertEqual(255,old.returncode)
        def oracle(value):self.assertEqual((0,b'raw-prefix-sentinel\n',b''),(value.returncode,value.stdout,value.stderr))
        with self.assertRaises(AssertionError):oracle(old)
        oracle(result(direct))
        self.assertEqual(1,len(self.children))

    def test_no_requirements_and_intentional_disconnect_do_not_launch(self):
        for policy in (readiness.Requirements(),readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'}),frozenset({'disconnected'}))):
            readiness.ensure_ready(self.context,policy,str(uuid.uuid4()))
        self.assertEqual([],self.children)
        self.assertFalse((self.root/master.GROUP).exists())

    def test_concurrent_callers_share_exact_one_owner(self):
        results=[];errors=[]
        def call():
            try:results.append(self.ensure())
            except Exception as error:errors.append(error)
        threads=[threading.Thread(target=call)for _ in range(3)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(10)
        self.assertEqual([],errors);self.assertEqual(3,len(results));self.assertEqual(1,len(self.children))
        self.assertEqual(1,len({value.connection for value in results}))

    def test_positive_dead_owner_gets_new_connection_retains_old_socket_and_history(self):
        before=self.ensure();old=master.status(self.root,'explicit-peer')
        self.children[0].terminate();self.children[0].wait(timeout=3)
        second=self.ensure();new=master.status(self.root,'explicit-peer')
        self.assertNotEqual(old['recoveryId'],new['recoveryId'])
        self.assertNotEqual(before.connection,second.connection)
        self.assertTrue(Path(old['socketPath']).exists())
        self.assertTrue((master._path(self.root,'explicit-peer')/(old['recoveryId']+'.retired.json')).exists())
        self.assertEqual(2,len(self.children))
        with self.assertRaises(readiness.ReadinessBlocked):readiness.revalidate(self.context,before)

    def test_original_live_unavailable_transport_red_independent_successor_green(self):
        ready=self.ensure();owner=master.status(self.root,'explicit-peer')
        fixture=Path(__file__).parent/'fixtures/readiness_transport'
        raw=(fixture/'readiness_transport.py.before-unavailable.source').read_bytes()
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        self.assertEqual(provenance['beforeUnavailableSha256']['readiness_transport.py'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._before_unavailable');before.__file__=str(fixture/'readiness_transport.py.before-unavailable.source');before.__package__='agent_tools'
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        self.mode.write_text('unavailable:'+str(owner['child']['pid']))
        original_adapter=before.TransportAdapter(self.root,'explicit-peer')
        old_context=readiness.Context('explicit-peer',original_adapter.machine,original_adapter,self.context.journal,
                                     deadline=time.monotonic()+5,sleep=lambda _:None)
        def oracle(context):return readiness.ensure_ready(context,self.requirements,str(uuid.uuid4()))
        with self.assertRaises(readiness.ReadinessBlocked):oracle(old_context)
        successor=oracle(self.context)
        self.assertNotEqual(ready.connection,successor.connection)
        self.assertEqual(2,len(self.children));self.assertIsNone(self.children[0].poll())
        self.assertTrue(Path(owner['socketPath']).exists())
        directory=master._path(self.root,'explicit-peer')
        self.assertFalse((directory/(owner['recoveryId']+'.retired.json')).exists())
        records=list(directory.glob(owner['recoveryId']+'.unavailable-*.json'))
        self.assertEqual(1,len(records));self.assertFalse(json.loads(records[0].read_bytes())['oldOwnerRetired'])
        readiness.revalidate(self.context,successor)

    def test_uncertain_spawn_ack_never_launches_another_owner(self):
        save=master._save
        def lost(directory,name,value):
            if name.endswith('.child.json'):raise OSError('lost acknowledgement inert fixture')
            return save(directory,name,value)
        with mock.patch.object(master,'_save',side_effect=lost):
            with self.assertRaises(readiness.ReadinessBlocked):self.ensure()
        self.assertEqual(1,len(self.children))
        with self.assertRaises(readiness.ReadinessBlocked):self.ensure()
        self.assertEqual(1,len(self.children))

    def test_lost_ready_publication_reconciles_same_original_live_owner(self):
        save=master._save;failures=[]
        def lost_once(directory,name,value):
            if name.endswith('.ready.json') and not failures:
                failures.append(name);raise OSError('inert lost publication acknowledgement')
            return save(directory,name,value)
        with mock.patch.object(master,'_save',side_effect=lost_once):
            ready=self.ensure()
        self.assertTrue(ready.connection);self.assertEqual(1,len(self.children))
        self.assertEqual(1,len(failures));readiness.revalidate(self.context,ready)

    def test_malformed_selected_owner_never_falls_back_to_network(self):
        self.ensure()
        path=master._path(self.root,'explicit-peer')/'current.json'
        path.write_text('{}');path.chmod(0o600)
        with self.assertRaises(transport.SshConfigError):
            transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer')
        self.assertEqual(1,len(self.children))

    def test_authentication_trust_wrong_account_and_malformed_socket_results_are_finite(self):
        self.ensure()
        for mode,reason in [('authentication','authentication_rejected'),('trust','trust_mismatch'),('wrong_account','wrong_account'),('malformed','connection_outcome_unknown')]:
            self.mode.write_text(mode)
            with self.subTest(mode=mode),self.assertRaises(readiness.ReadinessBlocked)as caught:self.ensure()
            self.assertEqual(reason,caught.exception.reason)
        self.assertEqual(1,len(self.children))

    def test_machine_digest_and_records_contain_no_credential_bytes_or_hash(self):
        ready=self.ensure()
        secret=b'PUBLIC_INERT_FIXTURE\n'
        output=json.dumps(ready.identities())+'\n'.join(p.read_text(errors='replace')for p in (self.root/master.GROUP).rglob('*.json'))
        self.assertNotIn(secret.decode().strip(),output)
        self.assertNotIn(hashlib.sha256(secret).hexdigest(),output)

    def test_preserved_implicit_daemonization_cannot_authorize_replacement(self):
        fixture=Path(__file__).parent/'fixtures/readiness_transport'
        raw=(fixture/'readiness_ssh_master.py.before.source').read_bytes()
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        self.assertEqual(provenance['beforeSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._readiness_master_before')
        before.__file__=str(fixture/'readiness_ssh_master.py.before.source');before.__package__='agent_tools'
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        config=transport.load_config(self.root)
        # The frozen creator and reader use the tempfile default as socket root; for the
        # whole scenario give it the native root the fixed reader admits, as on a real
        # host, never a runner's private TMPDIR.
        native=str(master._socket_temp_root())
        self.enterContext(mock.patch.dict(os.environ,{'TMPDIR':native,'TMP':native,'TEMP':native}));self.enterContext(mock.patch.object(tempfile,'tempdir',native))
        with mock.patch.object(before,'prefix',side_effect=master.prefix),mock.patch.dict(os.environ,{'VC_READINESS_FIXTURE_FORK':'1'}):
            value=before.start(self.root,'explicit-peer','f'*64,deadline=time.monotonic()+3)
        # Exact original local owner ended, but its daemon owns a live private
        # socket. This mirrors the preserved actual OpenSSH native failure.
        self.children[0].wait(timeout=3)
        with private_directory(master._path(self.root,'explicit-peer')) as directory:
            intent=master._read(directory,'f'*64+'.intent.json')
        result=subprocess.run([str(self.binary),'-S',intent['socketPath'],'-O','check','fixture'],capture_output=True,timeout=3)
        pid=int(result.stderr.decode().split('pid=')[1].split(')')[0])
        self.addCleanup(os.kill,pid,signal.SIGTERM)
        def oracle(owner):
            try:state=owner.status(self.root,'explicit-peer')['state']
            except ValueError as error:
                self.assertEqual('master_socket_owner_unresolved',str(error));state='unknown'
            self.assertNotEqual('dead',state)
        self.assertEqual('dead',before.status(self.root,'explicit-peer')['state'])
        with self.assertRaises(AssertionError):oracle(before)
        oracle(master)
        before_count=len(self.children)
        with self.assertRaisesRegex(master.MasterUnknown,'master_daemon_actor_unproved'):
            master.start(self.root,'explicit-peer','e'*64,deadline=time.monotonic()+3)
        self.assertEqual(before_count,len(self.children))


from agent_tools.private_inventory_lock import Directory as private_directory

if __name__=='__main__':unittest.main()
