"""Actual selector/custody/builder; native facts remain declared fixture seams."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest import mock
from agent_tools import ssh_channel_selection as selection
from agent_tools import ssh_transport as transport
from agent_tools.tests import test_ssh_fresh_nested_channel as channel_fixture
from agent_tools.tests import test_ssh_transport as cli_fixture

@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'protected POSIX selector')
class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.f=channel_fixture.FreshChannelTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.root;self.corr=self.f.corr;self.remote=self.f.ready_fixture()
        self.f.stdout=json.dumps(self.remote).encode();self.f.rc=0
        self.admitted=self.f.invoke();self.receipt=self.admitted['receiptSha256']
        self.patch=mock.patch.object(subprocess,'Popen',side_effect=self.f.consumer);self.patch.start();self.addCleanup(self.patch.stop)
        self.group=self.root/'.rag_index/ssh-channel-selection'
    def select(self):return selection.select_channel(self.root,'archlinux',self.corr,self.receipt)
    def test_genuine_admission_publication_and_readonly_getter(self):
        before=self.f.f.config_path.read_bytes()
        self.assertEqual('selected',self.select()['state'])
        pointer=self.group/'current.json';body=pointer.read_bytes();generation=pointer.stat().st_mtime_ns
        metadata=selection.selected_route_options(self.root,'archlinux',transport.load_config(self.root))
        self.assertEqual(self.corr,metadata['correlationId']);self.assertEqual(self.receipt,metadata['receiptSha256'])
        self.assertEqual(before,self.f.f.config_path.read_bytes());self.assertEqual(body,pointer.read_bytes());self.assertEqual(generation,pointer.stat().st_mtime_ns)
        self.assertEqual(1,sum(call[6]=='prepare' for call in self.f.calls))
    def test_actual_builder_duplicate_package_types_routes_harmless_consumer(self):
        self.assertEqual('selected',self.select()['state'])
        for provider in (transport,cli_fixture.ssh):
            config=provider.load_config(self.root)
            argv=provider.build_ssh_argv(config,'archlinux',10,command=('printf','harmless value'))
            self.assertEqual(['-F','/dev/null'],argv[1:3]);inner=shlex.split(argv[-1])
            self.assertEqual('/tmp/vpn-channel-'+self.corr+'/m',inner[inner.index('-S')+1])
            self.assertNotIn('/private/inert-master',argv[-1]);self.assertIn('ProxyCommand=false',inner)
            actual=self.f.real_popen([sys.executable,'-I','-B','-c','import json,sys;print(json.dumps(sys.argv[1:]))',*argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            out,err=actual.communicate(timeout=3);self.assertEqual(0,actual.returncode);self.assertEqual(b'',err);self.assertEqual(argv,json.loads(out))
        # Caller values from a second dataclass namespace must still match all
        # private authority; different settings cannot be silently discarded.
        config=cli_fixture.ssh.load_config(self.root)
        from dataclasses import replace
        config.hosts['archlinux']=replace(config.hosts['archlinux'],remote_host_alias='foreign')
        with self.assertRaises(cli_fixture.ssh.SshConfigError):cli_fixture.ssh.build_ssh_argv(config,'archlinux')
    def test_actual_final_status_refusal_keeps_validated_finite_cause(self):
        original=self.f.consumer;count=[0]
        def failing(argv,**kw):
            count[0]+=1
            if count[0]==3:
                self.f.stdout=json.dumps({'state':'unknown','correlationId':self.corr,'failurePhase':'master_snapshot','launchCapture':{'private':'sentinel'},'failureReason':'fd_changed','exceptionClass':'FileNotFoundError','errno':2}).encode();self.f.rc=3
            return original(argv,**kw)
        with mock.patch.object(subprocess,'Popen',side_effect=failing):result=self.select()
        self.assertEqual('unknown',result['state']);self.assertEqual(self.corr,result['correlationId']);self.assertEqual('master_snapshot',result['failurePhase']);self.assertEqual('fd_changed',result['failureReason']);self.assertEqual('FileNotFoundError',result['exceptionClass']);self.assertEqual(2,result['errno']);self.assertFalse(result['nativeActionAllowed']);self.assertFalse(result['replayAllowed']);self.assertNotIn('sentinel',json.dumps(result));self.assertTrue((self.group/'current.json').exists())

    def test_hostile_channel_unknown_never_forwards_private_or_unsafe_tuple(self):
        valid={'state':'unknown','nativeActionAllowed':False,'replayAllowed':False,'correlationId':self.corr,'failurePhase':'master_snapshot','failureReason':'fd_changed','exceptionClass':'FileNotFoundError','errno':2}
        for changes in ({'private':'secret sentinel'},{'errno':True},{'failureReason':'secret sentinel'},{'nativeActionAllowed':True}):
            with self.subTest(changes=changes):
                def throwing(*a,**kw):raise selection.channel.ChannelUnknown({**valid,**changes})
                with mock.patch.object(selection.channel,'route_options',side_effect=throwing):result=self.select()
                self.assertNotIn('sentinel',json.dumps(result));self.assertNotIn('private',result);self.assertFalse(result['nativeActionAllowed']);self.assertNotIn('errno',result)

    def test_expired_selection_refuses_without_reconnect_or_fallback(self):
        self.select();self.f.stdout=json.dumps({'state':'ended','correlationId':self.corr,'prior':self.remote,'gatewayBoot':self.remote['master']['gatewayBoot']}).encode()
        with self.assertRaises(selection.SelectionUnknown):selection.selected_route_options(self.root,'archlinux')
        with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(transport.load_config(self.root),'archlinux')
        self.assertEqual(1,sum(call[6]=='prepare' for call in self.f.calls))
    def test_post_admission_pointer_mutation_refuses(self):
        self.select();pointer=self.group/'current.json';original=self.f.consumer
        def drift(argv,**kw):
            child=original(argv,**kw);pointer.write_bytes(pointer.read_bytes()+b' ');return child
        with mock.patch.object(subprocess,'Popen',side_effect=drift),self.assertRaises(selection.SelectionUnknown):selection.selected_route_options(self.root,'archlinux')
    def test_post_publication_config_drift_cannot_claim_selected(self):
        original=os.fsync;changed=[False]
        def drift(fd):
            original(fd)
            if (self.group/'current.json').exists() and not changed[0]:
                changed[0]=True;path=self.f.f.config_path;path.write_bytes(path.read_bytes()+b' ')
        with mock.patch.object(os,'fsync',side_effect=drift):self.assertEqual('unknown',self.select()['state'])
        with self.assertRaises(selection.SelectionUnknown):selection.selected_route_options(self.root,'archlinux')
    def test_missing_lock_pointer_and_typed_corruption_never_recreate_or_fallback(self):
        self.select();pointer=self.group/'current.json';saved=pointer.read_bytes()
        for corrupt in ({'version':True,'history':'../foreign','pin':{}},{**json.loads(saved),'extra':True}):
            pointer.write_text(json.dumps(corrupt))
            with self.assertRaises(selection.SelectionUnknown):selection.selected_route_options(self.root,'archlinux')
        pointer.write_bytes(saved);(self.group/'selection.lock').unlink()
        with self.assertRaises(selection.SelectionUnknown):selection.selected_route_options(self.root,'archlinux')
        self.assertFalse((self.group/'selection.lock').exists())
        pointer.unlink()
        with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(transport.load_config(self.root),'archlinux')
    def test_unselected_legacy_and_bad_inputs(self):
        self.assertIsNone(selection.selected_route_options(self.root,'archlinux'))
        self.assertIsNone(selection.selected_route_options(self.root,'other'))
        for corr,receipt in ((True,self.receipt),(self.corr,False),(self.corr,'x')):
            self.assertEqual('unknown',selection.select_channel(self.root,'archlinux',corr,receipt)['state'])
        self.assertFalse(self.group.exists())
        config=transport.load_config(self.root);argv=transport.build_ssh_argv(config,'archlinux')
        self.assertIn('/private/inert-master',argv[-1])
