"""Whole-before RED/GREEN for reconnect after a membership successor ends normally."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

if os.name=='posix':
    from agent_tools import readiness
    from agent_tools import readiness_nested_channel as nested
    from agent_tools import readiness_nested_membership as proof
    from agent_tools import readiness_transport as transport_ready
    from agent_tools import ssh_fresh_nested_channel as channel
    from agent_tools import ssh_transport as transport
    from agent_tools.tests.test_nested_directory_membership import before as membership_before

FIXTURES=Path(__file__).parent/'fixtures/ssh_successor_after_ended'
OPERATIONS=('b8ed214e-b76d-4e91-bda1-1344606b0109','fc67051b-7976-4fb5-bdad-575551021f20',
            '76661036-58f8-4577-bd1c-de52cad0de53')


def pinned(leaf):
    raw=(FIXTURES/leaf).read_bytes()
    record=json.loads((FIXTURES/'provenance.json').read_bytes())['files'][leaf]
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
    return raw


def before_transport():
    """The whole unfixed adapter; its campaign capsules read the same sibling sources."""
    module=types.ModuleType('agent_tools._successor_before_readiness_transport')
    module.__package__='agent_tools';module.__file__=transport_ready.__file__
    exec(compile(pinned('readiness_transport.before.source'),str(FIXTURES/'readiness_transport.before.source'),'exec'),module.__dict__)
    return module


def before_nested(directory):
    """Isolated owned copy: the unfixed module and its unchanged helper pass their own source guards."""
    own=Path(directory)/'readiness_nested_channel.py';helper=Path(directory)/'readiness_nested_membership.py'
    own.write_bytes(pinned('readiness_nested_channel.before.source'));shutil.copyfile(proof.__file__,helper)
    membership=types.ModuleType('agent_tools._successor_before_membership')
    membership.__package__='agent_tools';membership.__file__=str(helper)
    module=types.ModuleType('agent_tools._successor_before_nested')
    module.__package__='agent_tools';module.__file__=str(own)
    with mock.patch.dict(sys.modules,{membership.__name__:membership,module.__name__:module}):
        exec(compile(helper.read_bytes(),str(helper),'exec',dont_inherit=True),membership.__dict__)
        exec(compile(own.read_bytes(),str(own),'exec',dont_inherit=True),module.__dict__)
    module.membership=membership
    return module


@unittest.skipUnless(os.name=='posix','POSIX generated SSH/ancestry sockets')
class SuccessorAfterEndedTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        self.original_remote=membership_before('ssh_fresh_nested_channel.py')._REMOTE
        case=DirectChannelTests('runTest')
        with mock.patch.object(channel,'_REMOTE',self.original_remote):case.setUp();ready=case.invoke()
        self.addCleanup(case.doCleanups)
        self.case=case;self.root=case.root;self.old=case.corr;self.prior=case.result;self.receipt=ready['receiptSha256']
        intent=self.journal()/(self.old+'.intent.json')
        self.refusal={'state':'unknown','correlationId':self.old,'failurePhase':'remote_intent','failureReason':'remote_intent_changed',
                      'exceptionClass':'ValueError','errno':None,'launchCapture':None}
        self.evidence={'state':'directory_membership_changed','correlationId':self.old,'gatewayBoot':self.prior['master']['gatewayBoot'],
                       'sourceSha256':json.loads(intent.read_bytes())['sourceSha256'],'originalIntentSha256':'a'*64,'currentIntentSha256':'b'*64}
        self.diagnostic=proof.diagnostic_source(self.original_remote)
        self.drift=False;self.ended=set();self.calls=[]
        popen=mock.patch.object(subprocess,'Popen',side_effect=self.consumer);popen.start();self.addCleanup(popen.stop)
        nested.admit(self.root,'archlinux',self.old,self.receipt)

    def consumer(self,argv,**kwargs):
        remote=shlex.split(argv[-1]);code=0
        if remote[0]=='python3' and len(remote)>6:
            source=ast.literal_eval(ast.parse(remote[4],mode='eval').body.args[0]);corr=remote[5];action=remote[6]
            if corr==self.old:
                # The unusable original is only ever observed, never prepared.
                self.assertEqual('status',action);self.assertIn(source,(self.original_remote,self.diagnostic))
                body=self.evidence if source==self.diagnostic else(self.refusal if self.drift else self.prior)
                code=3 if body is self.refusal else 0
            else:
                self.assertEqual(channel._REMOTE,source);self.calls.append((corr,action))
                result={**self.prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m'}
                body=({'state':'ended','correlationId':corr,'prior':result,'gatewayBoot':self.prior['master']['gatewayBoot']}
                      if corr in self.ended else result)
        else:
            user=transport.load_config(self.root).hosts['archlinux'].user
            body={'boot':self.prior['arch']['boot'],'uid':1000,'principal':user,'home':'/owned','connection':'192.0.2.1 1000 192.0.2.2 22'}
        program='import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));raise SystemExit(int(sys.argv[2]))'
        return self.case.real_popen([sys.executable,'-I','-B','-c',program,json.dumps(body).encode().hex(),str(code)],**kwargs)

    def journal(self):
        return channel._context_journal(self.root,'archlinux',self.old,False,True)

    def campaign(self):
        return self.root/'.rag_index/readiness-transport-v2/archlinux'

    def selected(self):
        return json.loads((nested.directory(self.root,'archlinux')/'current.json').read_bytes())['correlationId']

    def prepares(self):
        return [corr for corr,action in self.calls if action=='prepare']

    def ensure(self,module,operation,seconds=20):
        ctx=module.context(self.root,'archlinux',deadline=time.monotonic()+seconds,sleep=lambda value:time.sleep(min(value,.05)))
        return readiness.ensure_ready(ctx,readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation)

    def successor_then_normal_end(self):
        self.drift=True
        self.ensure(transport_ready,OPERATIONS[0])
        successor=self.selected();self.assertNotEqual(self.old,successor);self.assertEqual([successor],self.prepares())
        self.ended.add(successor)
        return successor

    def test_whole_before_stays_unknown_current_proves_unsubmitted_and_renews_same_candidate_once(self):
        successor=self.successor_then_normal_end()
        old=before_transport()
        for _ in range(2):
            # The unfixed adapter only ever waits out its budget; its nested
            # deadline may also surface as a changed generation.
            with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.ensure(old,OPERATIONS[1],3)
            self.assertIn(blocked.exception.reason,('recovery_outcome_unknown','connection_generation_changed'))
        stuck=json.loads((self.campaign()/'current.json').read_bytes())
        # The refused candidate never reached the remote endpoint.
        self.assertEqual([successor],self.prepares());self.assertNotIn(stuck['correlationId'],{corr for corr,_ in self.calls})
        self.assertFalse(list(self.campaign().glob('*.unsubmitted-*.json')))
        ready=self.ensure(transport_ready,OPERATIONS[1])
        self.assertEqual(OPERATIONS[1],ready.operation_identity)
        self.assertEqual([successor,stuck['correlationId']],self.prepares());self.assertEqual(stuck['correlationId'],self.selected())
        retained=json.loads((self.campaign()/(stuck['recoveryId']+'.unsubmitted-1.json')).read_bytes())
        self.assertEqual(('absent',stuck['correlationId'],False),(retained['channelIntent'],retained['correlationId'],retained['replayAllowed']))
        inherited=json.loads((self.campaign()/(stuck['recoveryId']+'.predecessor.json')).read_bytes())
        self.assertEqual((self.old,self.receipt),(inherited['correlationId'],inherited['receiptSha256']))
        self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())
        self.assertTrue((self.journal()/(successor+'.terminal.json')).exists())
        # A later caller observes the renewed connection without another producer.
        self.ensure(transport_ready,OPERATIONS[2])
        self.assertEqual(2,len(self.prepares()));self.case.assert_legacy_unchanged()

    def test_current_fresh_operation_renews_once_from_the_unresolved_original(self):
        successor=self.successor_then_normal_end()
        self.ensure(transport_ready,OPERATIONS[1])
        renewed=self.selected();self.assertNotIn(renewed,(self.old,successor))
        self.assertEqual([successor,renewed],self.prepares())
        owner=json.loads((self.campaign()/'current.json').read_bytes())['recoveryId']
        inherited=json.loads((self.campaign()/(owner+'.predecessor.json')).read_bytes())
        self.assertEqual(self.old,inherited['correlationId']);self.assertIn('inheritedFromRecoveryId',inherited)
        self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())
        self.assertFalse(list(self.campaign().glob('*.unsubmitted-*.json')))

    def test_renewal_requires_a_fresh_unusable_original(self):
        self.successor_then_normal_end()
        self.drift=False  # The original now answers its own unchanged ready record.
        with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.ensure(transport_ready,OPERATIONS[1])
        self.assertEqual('recovery_dispatch_attempts_exhausted',blocked.exception.reason)
        self.assertEqual(1,len(self.prepares()))
        owner=json.loads((self.campaign()/'current.json').read_bytes())['recoveryId']
        self.assertEqual(3,len(list(self.campaign().glob(owner+'.unsubmitted-*.json'))))
        self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())

    def test_whole_before_successor_proof_refuses_ended_selection_current_requires_its_exact_terminal(self):
        self.drift=True
        self.ensure(transport_ready,OPERATIONS[0])
        successor=self.selected()
        # A live selected successor never authorizes another channel.
        with self.assertRaisesRegex(nested.NestedUnknown,'nested_selection_binding'):
            with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):self.fail('live successor')
        self.ended.add(successor)
        self.assertEqual('ended',transport_ready.direct.reconcile_original(self.root,'archlinux',successor)['state'])
        with tempfile.TemporaryDirectory(dir=self.root)as raw:
            old=before_nested(raw)
            with self.assertRaisesRegex(old.NestedUnknown,'nested_selection_binding'):
                with old.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):self.fail('before issued proof')
        with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10)as issued:
            self.assertTrue(nested.validate_membership_successor(issued,self.root,'archlinux',previous=self.old,new_correlation='7'*32))
        terminal=self.journal()/(successor+'.terminal.json');body=terminal.read_bytes()
        changed=json.loads(body);changed['gatewayBoot']='00000000-0000-4000-8000-000000000000'
        replacement=terminal.with_name(terminal.name+'.replacement');replacement.write_text(json.dumps(changed));replacement.chmod(0o600)
        os.replace(replacement,terminal)
        with self.assertRaisesRegex(nested.NestedUnknown,'nested_selection_binding'):
            with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):self.fail('changed terminal')

    def test_whole_before_deadline_reports_changed_generation_current_reports_unavailable(self):
        requirements=readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'}))
        exhausted=nested.NestedUnknown('nested_original_deadline')
        for module,expected in ((before_transport(),None),(transport_ready,'unavailable')):
            adapter=module.TransportAdapter(self.root,'archlinux')
            with self.subTest(before=expected is None),mock.patch.object(nested,'qualified_route',side_effect=exhausted):
                if expected is None:
                    with self.assertRaisesRegex(readiness.AdapterBlocked,'connection_generation_changed'):
                        adapter.observe(requirements,time.monotonic()+10)
                else:
                    self.assertEqual(expected,adapter.observe(requirements,time.monotonic()+10).transport)
        with mock.patch.object(nested,'qualified_route',side_effect=nested.NestedUnknown('nested_binding_generation_changed')):
            with self.assertRaisesRegex(readiness.AdapterBlocked,'connection_generation_changed'):
                transport_ready.TransportAdapter(self.root,'archlinux').observe(requirements,time.monotonic()+10)

    def test_all_retained_whole_before_artifacts_have_exact_custody(self):
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        self.assertTrue(provenance['nativeFailureClaimed'])
        for leaf,pin in provenance['files'].items():
            self.assertEqual(pin['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest(),leaf)


if __name__=='__main__':unittest.main()
