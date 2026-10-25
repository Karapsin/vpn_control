"""Complete fixed adapter callers; private bytes never form public authority."""
import gc
import hashlib
import json
import os
from pathlib import Path
import secrets
import types
import unittest
from unittest import mock

from agent_tools import ssh_tmux_mcp_adapter as adapter
from agent_tools.tests import test_ssh_tmux_mcp_adapter as fixtures

BASE=Path(__file__).with_name('fixtures')/'tmux_private_transport_v2'
BEFORE_SHA='224141d15113544ded0c89cdbff990f4f9c9acf1bbcc43b2ce7b5fe1c85aed21'


@unittest.skipUnless(os.name=='posix','protected POSIX descriptors')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AdapterTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.driver=self.fixture.driver
        self.key=self.root/'key';self.inventory=self.root/'.vm-hosts.local.json'
        self.secret=secrets.token_hex(24).encode();self.keysecret=secrets.token_hex(24).encode()
        config=json.loads(self.inventory.read_bytes())
        config['hosts']['private_fixture']=dict(config['hosts']['archlinux'],host='unused.fixture',password=self.secret.decode())
        self.inventory.write_text(json.dumps(config));self.key.write_bytes(self.keysecret)

    def spy(self):
        original=hashlib.sha256;seen=[]
        def digest(raw=b'',*args,**kwargs):
            if self.secret in raw or self.keysecret in raw:seen.append(bytes(raw))
            return original(raw,*args,**kwargs)
        return mock.patch.object(hashlib,'sha256',side_effect=digest),seen

    def before(self):
        path=BASE/'ssh_tmux_mcp_adapter.py.before.source';raw=path.read_bytes()
        self.assertEqual(BEFORE_SHA,hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._tmux_private_transport_before')
        module.__file__=str(path);module.__package__='agent_tools'
        exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
        return module

    def test_authentic_whole_query_hashes_private_config_and_key_red_current_complete_flow_green(self):
        before=self.before();old=before.McpTmuxDriver(self.root)
        patch,seen=self.spy()
        with patch:self.assertTrue(old.availability()['available'])
        self.assertTrue(any(self.secret in data for data in seen))
        self.assertTrue(any(data==self.keysecret for data in seen))
        # The original complete pipe caller published those private digests.
        journal=self.root/'.rag_index/linux-package-fixture-build-pipe-collection'
        keyhash=hashlib.sha256(self.keysecret).hexdigest().encode()
        self.assertTrue(any(keyhash in p.read_bytes() for p in journal.rglob('*')if p.is_file()))
        prior=set(journal.iterdir());patch,seen=self.spy()
        with patch:
            self.assertTrue(self.driver.availability()['available'])
            self.assertEqual('submitted',self.fixture.start()['state'])
            self.assertEqual('unknown',self.driver.status(self.fixture.fixture.req)['state'])
            with mock.patch.object(adapter.build.FixedArchDriver,'collect',return_value={'state':'ready'}):
                self.assertEqual('ready',self.driver.collect_existing(self.fixture.fixture.req)['state'])
        self.assertEqual([],seen)
        for directory in set(journal.iterdir())-prior:
            for path in directory.rglob('*'):
                if path.is_file():
                    raw=path.read_bytes()
                    for forbidden in (self.secret,self.keysecret,keyhash):self.assertNotIn(forbidden,raw)
        intent=json.loads((self.fixture.fixture.job()/'tmux-adapter-intent.json').read_bytes())
        self.assertTrue(adapter._valid_transport(intent['transport']))
        self.assertNotIn(keyhash,json.dumps(intent).encode())
        calls=len(self.fixture.calls);self.assertEqual('unknown',self.fixture.start()['state'])
        self.assertEqual(calls,len(self.fixture.calls))

    def test_legacy_intent_is_rejected_before_any_hash_or_snapshot_in_saved_and_phase(self):
        request=self.fixture.fixture.req
        directory=adapter.build._directory(self.root,True);job=directory/request['correlationId'];job.mkdir(mode=0o700)
        old={'request':request,'transport':{'privateConfig':self.secret.decode(),'privateKey':self.keysecret.decode()}}
        path=job/'tmux-adapter-intent.json';raw=json.dumps(old).encode();path.write_bytes(raw);path.chmod(0o600)
        patch,seen=self.spy()
        with patch,mock.patch.object(self.driver,'_snapshot',side_effect=AssertionError('snapshot must not precede legacy gate')):
            for invoke in (lambda:self.driver._saved(request),lambda:self.driver._phase(adapter.old._ACTION,{'request':adapter.old.purpose(request)},job)):
                with self.assertRaisesRegex(ValueError,'legacy_transport_snapshot_blocker'):invoke()
        self.assertEqual([],seen);self.assertEqual(raw,path.read_bytes());self.assertEqual([],self.fixture.calls)

    def test_authentic_original_saved_reader_rehashes_legacy_authority_red_current_gate_green(self):
        before=self.before();old=before.McpTmuxDriver(self.root);request=self.fixture.fixture.req
        directory=adapter.build._directory(self.root,True)
        adapter.session.write_once(directory/(request['correlationId']+'.json'),adapter.session.canonical(request))
        adapter.session.write_once(directory/'archlinux.claim',adapter.session.canonical({'correlationId':request['correlationId'],'host':'archlinux'}))
        job=directory/request['correlationId'];job.mkdir(mode=0o700)
        value=old._snapshot(request);raw=adapter.session.canonical(value)
        path=job/'tmux-adapter-intent.json';adapter.session.write_once(path,raw)
        original=hashlib.sha256;hashed=[]
        def digest(value=b'',*args,**kwargs):
            if value==raw:hashed.append(True)
            return original(value,*args,**kwargs)
        with mock.patch.object(hashlib,'sha256',side_effect=digest):old._saved(request)
        self.assertTrue(hashed)
        hashed.clear()
        with mock.patch.object(hashlib,'sha256',side_effect=digest):
            with self.assertRaisesRegex(ValueError,'legacy_transport_snapshot_blocker'):self.driver._saved(request)
        self.assertEqual([],hashed);self.assertEqual(raw,path.read_bytes());self.assertEqual([],self.fixture.calls)

    def test_v2_marker_cannot_authorize_hashing_extra_private_snapshot_fields(self):
        request=self.fixture.fixture.req
        directory=adapter.build._directory(self.root,True);job=directory/request['correlationId'];job.mkdir(mode=0o700)
        value={'request':request,'transport':self.driver._transport()[1],'privateExtra':self.secret.decode()}
        path=job/'tmux-adapter-intent.json';path.write_text(json.dumps(value));path.chmod(0o600)
        patch,seen=self.spy()
        with patch,mock.patch.object(self.driver,'_snapshot',return_value={'request':request,'transport':value['transport']}):
            with self.assertRaisesRegex(ValueError,'adapter_intent_changed'):self.driver._saved(request)
        self.assertEqual([],seen);self.assertEqual([],self.fixture.calls)

    def test_replacement_inplace_and_public_knownhost_drift_never_refresh_original_owner(self):
        for kind in ('key_replace','key_inplace','config_replace','config_inplace','known'):
            with self.subTest(kind=kind):
                # A fresh owner may establish its own baseline; this owner may
                # never refresh an already held private file generation.
                driver=adapter.McpTmuxDriver(self.root);self.addCleanup(driver.close)
                original=driver._transport()[1]
                path=self.key if kind.startswith('key')else self.inventory
                if kind=='known':
                    (self.root/'known').write_bytes(b'changed public host key')
                    self.assertNotEqual(original,driver._transport()[1]);continue
                raw=path.read_bytes()
                if kind.endswith('replace'):
                    replacement=self.root/'replacement';replacement.write_bytes(raw);replacement.chmod(0o600);replacement.replace(path)
                else:path.write_bytes(raw+b' ')
                with self.assertRaises(ValueError):driver._transport()
                driver.close();path.write_bytes(raw)

    def test_postlaunch_private_change_keeps_finite_unknown_and_no_relaunch(self):
        real=self.fixture.launch;once=[]
        def launch(*args,**kwargs):
            process=real(*args,**kwargs)
            if not once:self.key.write_bytes(self.keysecret+b' changed');once.append(True)
            return process
        with mock.patch.object(adapter.subprocess,'Popen',side_effect=launch):
            with self.assertRaisesRegex(ValueError,'transport_unknown'):self.driver.availability()
        self.assertEqual(1,len(self.fixture.calls))
        receipt=next((self.root/'.rag_index/linux-package-fixture-build-pipe-collection').glob('*/receipt.json'))
        self.assertEqual('authority_changed',json.loads(receipt.read_bytes())['failure'])

    def test_close_finalizer_and_operate_exception_cancellation_always_release_private_fds(self):
        self.driver._transport();owners=list(self.driver._private_owners.values());self.driver.close();self.driver.close()
        for owner in owners:self.assertEqual([],owner._fds)
        with self.assertRaisesRegex(ValueError,'transport_custody_closed'):self.driver._transport()
        transient=adapter.McpTmuxDriver(self.root);transient._transport();owners=list(transient._private_owners.values())
        del transient;gc.collect()
        for owner in owners:self.assertEqual([],owner._fds)
        for error in (ValueError('finite'),KeyboardInterrupt()):
            created=[];original=adapter.McpTmuxDriver
            def make(*args,**kwargs):
                driver=original(*args,**kwargs);created.append(driver);return driver
            with mock.patch.object(adapter,'McpTmuxDriver',side_effect=make),mock.patch.object(original,'availability',side_effect=error):
                with self.assertRaises(type(error)):adapter.operate(self.root,'availability',{})
            self.assertTrue(created[0]._private_closed)

    def test_changed_executing_source_blocks_before_private_open_or_dispatch(self):
        with mock.patch.object(adapter,'_EXECUTING_CODE',compile('changed=1','inert','exec')):
            with self.assertRaisesRegex(ValueError,'adapter_executing_source_changed'):self.driver._transport()
        self.assertEqual({},self.driver._private_owners);self.assertEqual([],self.fixture.calls)


if __name__=='__main__':unittest.main()
