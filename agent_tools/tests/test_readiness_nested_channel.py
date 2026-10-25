"""Original generated callers/capsules with real private source files and pipes.

Only Linux kernel/master response facts are declared endpoint fixture data;
matching real native Arch admission is preserved separately in task evidence.
"""
from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

if os.name=='posix':
    from agent_tools import readiness_nested_channel as subject
    from agent_tools import ssh_direct_nested_channel as direct
    from agent_tools import ssh_transport as transport


@unittest.skipUnless(os.name=='posix','POSIX original-capsule fixture')
class ReadinessNestedChannelTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        self.fixture=DirectChannelTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.corr=self.fixture.corr
        ready=self.fixture.invoke();self.assertEqual('ready',ready['state']);self.receipt=ready['receiptSha256']

    def peer(self):return mock.patch.object(subprocess,'Popen',side_effect=self.fixture.consumer)

    def admit(self):
        with self.peer():return subject.admit(self.root,'archlinux',self.corr,self.receipt)

    def test_original_status_only_admission_and_pure_builder_bind_same_connection(self):
        self.assertEqual('selected',self.admit()['state'])
        with self.peer():
            first=subject.route_options(self.root,'archlinux')
            second=subject.route_options(self.root,'archlinux')
            argv=transport.build_ssh_argv(transport.load_config(self.root),'archlinux',command=('printf','value with space'))
        self.assertEqual(first,second)
        self.assertEqual(self.corr,first['correlationId'])
        import shlex
        inner=shlex.split(argv[-1]);self.assertIn('/tmp/vpn-channel-'+self.corr+'/m',inner)
        self.assertEqual('none',argv[argv.index('-S')+1]);self.assertNotIn('ProxyCommand=false',argv[:-1])
        self.assertEqual(['printf','value with space'],shlex.split(inner[-1]))
        self.assertEqual(1,sum(call[6]=='prepare'for call in self.fixture.calls))
        self.assertTrue(all(call[6]=='status'for call in self.fixture.calls[1:]))
        self.fixture.assert_legacy_unchanged()

    def test_original_legacy_source_lifetime_red_current_archived_capsule_green(self):
        self.admit()
        with tempfile.TemporaryDirectory(dir=self.root)as temporary:
            folder=Path(temporary)
            for leaf in direct._SOURCE_NAMES:shutil.copyfile(Path(direct.__file__).with_name(leaf),folder/leaf)
            (folder/'mcp_server.py').write_text((folder/'mcp_server.py').read_text()+'\n# unrelated next coordinator revision\n')
            with mock.patch.object(direct,'__file__',str(folder/'ssh_direct_nested_channel.py')),self.peer():
                def oracle(provider):self.assertEqual(self.corr,provider()['correlationId'])
                with self.assertRaises(ValueError):direct.route_options(self.root,'archlinux',self.corr,self.receipt)
                oracle(lambda:subject.route_options(self.root,'archlinux'))
        self.assertEqual(1,sum(call[6]=='prepare'for call in self.fixture.calls))

    def test_changed_original_capsule_or_configuration_blocks_before_transport(self):
        self.admit();before=len(self.fixture.calls)
        directory=direct._dependencies()[1]._context_journal(self.root,'archlinux',self.corr,False,True)
        path=directory/(self.corr+'.remote.source');body=path.read_bytes();path.write_bytes(body+b' ')
        with self.peer(),self.assertRaises(subject.NestedUnknown):subject.route_options(self.root,'archlinux')
        self.assertEqual(before,len(self.fixture.calls));path.write_bytes(body)
        config=transport.load_config(self.root);config.hosts['archlinux']=replace(config.hosts['archlinux'],password='foreign protected fixture')
        with self.peer(),self.assertRaises(subject.NestedUnknown):subject.route_options(self.root,'archlinux',config)
        self.assertEqual(before,len(self.fixture.calls))

    def test_ended_is_distinct_from_unknown_and_never_submits_prepare(self):
        self.admit();prior=self.fixture.result
        self.fixture.result={'state':'ended','correlationId':self.corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        with self.peer(),self.assertRaises(subject.NestedEnded):subject.route_options(self.root,'archlinux')
        self.fixture.result={'state':'unknown','correlationId':self.corr};self.fixture.returncode=3
        with self.peer(),self.assertRaises(subject.NestedUnknown):subject.route_options(self.root,'archlinux')
        self.assertEqual(1,sum(call[6]=='prepare'for call in self.fixture.calls))

    def test_expired_original_is_observed_terminal_before_single_successor_prepare(self):
        from agent_tools import readiness,readiness_transport
        import shlex
        self.admit();prior=self.fixture.result;old=self.corr
        old_ended={'state':'ended','correlationId':old,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        consumer=self.fixture.consumer
        def changing_peer(argv,**kwargs):
            remote=shlex.split(argv[-1]);corr=remote[5]
            self.fixture.result=old_ended if corr==old else {**prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m'}
            return consumer(argv,**kwargs)
        adapter=readiness_transport.TransportAdapter(self.root,'archlinux')
        observed=readiness.Observation('archlinux',adapter.machine,transport='expired',trusted=True,integrity=True)
        with mock.patch.object(subprocess,'Popen',side_effect=changing_peer):
            adapter.recover('reconnect','c'*64,observed,time.monotonic()+10)
            current=subject.route_options(self.root,'archlinux')
        self.assertNotEqual(old,current['correlationId'])
        self.assertEqual(2,sum(call[6]=='prepare'for call in self.fixture.calls))
        self.assertEqual(1,sum(call[6]=='prepare'and call[5]==old for call in self.fixture.calls))
        directory=direct._dependencies()[1]._context_journal(self.root,'archlinux',old,False,True)
        self.assertEqual('ended',json.loads((directory/(old+'.terminal.json')).read_bytes())['state'])
        self.fixture.assert_legacy_unchanged()

    def test_retained_original_reconciliation_only_publishes_verified_ended(self):
        prior=self.fixture.result
        self.fixture.result={'state':'ended','correlationId':self.corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        with self.peer():value=direct.reconcile_original(self.root,'archlinux',self.corr)
        self.assertEqual('ended',value['state'])
        self.assertEqual('status',self.fixture.calls[-1][6])
        self.fixture.assert_legacy_unchanged()

    def test_live_or_wrong_original_reconciliation_never_publishes_terminal(self):
        with self.peer():self.assertEqual('unknown',direct.reconcile_original(self.root,'archlinux',self.corr)['state'])
        directory=direct._dependencies()[1]._context_journal(self.root,'archlinux',self.corr,False,True)
        self.assertFalse((directory/(self.corr+'.terminal.json')).exists())
        prior=self.fixture.result
        self.fixture.result={'state':'ended','correlationId':self.corr,'prior':None,'gatewayBoot':prior['master']['gatewayBoot']}
        with self.peer():self.assertEqual('unknown',direct.reconcile_original(self.root,'archlinux',self.corr)['state'])
        self.assertFalse((directory/(self.corr+'.terminal.json')).exists())


if __name__=='__main__':unittest.main()
