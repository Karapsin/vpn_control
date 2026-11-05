"""Nested transport after gateway and local reboots: whole-before RED, current GREEN.

Native finding (2026-11-03, refused readiness operation
5be4c4ce-e252-4e48-8ffb-85af227b384c): the gateway host had rebooted, so the
selected channel's retained remote status reported ``ended`` with no prior
record under a new gateway boot. The route check, the original reconciliation
and the status parser accepted only a same-boot end, so transport readiness
refused ``connection_generation_changed`` and no successor could be prepared.
An earlier local reboot (2026-10-29) had renumbered the checkout volume
(st_dev only), so every retained pre-reboot channel record failed its exact
generation binding: ended priors failed the prepare loop, a pre-reboot
selection could not be reconciled, and the inherited unusable version-2
original could not issue its successor proof.

The local reboot is simulated at the ``os.stat``/``os.lstat``/``os.fstat``
boundary; the gateway is simulated by the existing generated-socket consumer.
Neither proves real kernel or gateway behaviour; the native rerun does.
"""
import ast
from contextlib import ExitStack, contextmanager
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

from agent_tools.tests.test_ssh_direct_nested_channel import COORDINATOR_CAPABLE

if COORDINATOR_CAPABLE:
    from agent_tools import private_inventory_lock as private
    from agent_tools import readiness
    from agent_tools import readiness_nested_channel as nested
    from agent_tools import readiness_nested_membership as proof
    from agent_tools import readiness_transport as transport_ready
    from agent_tools import ssh_connection_session as session
    from agent_tools import ssh_direct_nested_channel as direct
    from agent_tools import ssh_fresh_nested_channel as channel
    from agent_tools import ssh_transport as transport
    from agent_tools.tests.test_nested_directory_membership import before as membership_before

FIXTURES=Path(__file__).parent/'fixtures/ssh_gateway_reboot_ended'
NEW_BOOT='3f1d2c4b-5a69-4e78-9b8a-7c6d5e4f3a2b'
LATER_BOOT='4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d'
SHIFT=7
FAMILY=('ssh_fresh_nested_channel','ssh_direct_nested_channel','readiness_nested_channel')
OPERATIONS=('0b9c3f4e-2d1a-4c6b-8e7f-1a2b3c4d5e60','1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e51',
            '2d3e4f5a-6b7c-4d8e-9f0a-1b2c3d4e5f62','3e4f5a6b-7c8d-4e9f-8a1b-2c3d4e5f6a73',
            '4f5a6b7c-8d9e-4f0a-9b2c-3d4e5f6a7b84')


def pinned(leaf):
    raw=(FIXTURES/leaf).read_bytes()
    record=json.loads((FIXTURES/'provenance.json').read_bytes())['files'][leaf]
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
    return raw


def causes(error):
    """The exception chain, including contexts suppressed by ``from None``."""
    seen=[]
    while error is not None and len(seen)<16:
        seen.append((type(error).__name__,str(error)))
        error=error.__cause__ or error.__context__
    return seen


@contextmanager
def local_reboot(root):
    """Simulated remount: every stat on the checkout volume reports another st_dev.

    Inode, mode, owners, links, size and nanosecond timestamps stay unchanged.
    """
    device=os.stat(root).st_dev
    real={name:getattr(os,name) for name in ('stat','lstat','fstat')}
    keep=('st_mode','st_ino','st_dev','st_nlink','st_uid','st_gid','st_size')
    def shift(info):
        if info.st_dev!=device:return info
        values=list(info);values[2]=device+SHIFT
        return os.stat_result(values,{name:getattr(info,name) for name in dir(info) if name.startswith('st_') and name not in keep})
    def wrap(function):
        def call(*args,**kwargs):return shift(function(*args,**kwargs))
        return call
    with ExitStack()as stack:
        for name,function in real.items():stack.enter_context(mock.patch.object(os,name,wrap(function)))
        yield device+SHIFT


@contextmanager
def module_entry(name,module):
    """Patch one sys.modules key only; modules imported meanwhile stay registered."""
    missing=object();previous=sys.modules.get(name,missing);sys.modules[name]=module
    try:yield
    finally:
        if previous is missing:sys.modules.pop(name,None)
        else:sys.modules[name]=previous


@contextmanager
def family(kind,directory):
    """Current modules, or an isolated owned copy of the trio: unfixed or current bytes.

    The copy sits beside byte-equal current siblings and is installed in its
    sys.modules keys, the package attributes, the transport adapter and the
    SSH transport's nested-module lookup, so every own-source guard runs on the
    copy's bytes. The ``copy-current`` kind proves the loader itself is neutral.
    """
    if kind=='current':
        yield types.SimpleNamespace(nested=nested,direct=direct,channel=channel);return
    if kind not in ('before','copy-current'):raise ValueError(kind)
    import agent_tools as package
    source=Path(directory)/('family-'+kind);source.mkdir()
    for leaf in sorted({*direct._SOURCE_NAMES,'readiness_nested_membership.py'}):
        shutil.copyfile(Path(direct.__file__).with_name(leaf),source/leaf)
    for name in FAMILY:
        raw=pinned(name+'.before.source') if kind=='before' else Path(direct.__file__).with_name(name+'.py').read_bytes()
        (source/(name+'.py')).write_bytes(raw)
    loaded={}
    with ExitStack()as stack:
        for name in ('readiness_nested_membership',*FAMILY):
            path=source/(name+'.py')
            module=types.ModuleType('agent_tools.'+name);module.__package__='agent_tools';module.__file__=str(path)
            stack.enter_context(module_entry(module.__name__,module))
            stack.enter_context(mock.patch.object(package,name,module))
            exec(compile(path.read_bytes(),str(path),'exec',dont_inherit=True),module.__dict__)
            loaded[name]=module
        for attribute,name in (('nested_ready','readiness_nested_channel'),('direct','ssh_direct_nested_channel'),('channel','ssh_fresh_nested_channel')):
            stack.enter_context(mock.patch.object(transport_ready,attribute,loaded[name]))
        own=loaded['readiness_nested_channel']
        def nested_module():
            if Path(own.__file__).parent!=source:raise AssertionError('family_nested_module_escaped')
            return own
        stack.enter_context(mock.patch.object(transport,'_readiness_nested_module',nested_module))
        yield types.SimpleNamespace(nested=own,direct=loaded['ssh_direct_nested_channel'],channel=loaded['ssh_fresh_nested_channel'])


def write_bytes(directory,name,raw):
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def version2_records(root,corr,remote,*,ready_result=None,ended_boot=None):
    """A native-shaped version-2 direct intent, as the 2026-10-20 tooling wrote it.

    Its inventory pin is the sha256-shaped private.Snapshot pin of the private
    configuration, its outer authority is the legacy Guard authority and its
    catalog is the version-2 source list. With ``ready_result`` it is a READY
    original; with ``ended_boot`` it ended before READY (no receipt), like the
    native b75cf838 prior.
    """
    root=Path(root).resolve(strict=True)
    journal=channel._context_journal(root,'archlinux',corr,True,True)
    bodies={name:Path(direct.__file__).with_name(name).read_bytes() for name in direct.source_catalog(2)}
    with private.Directory(Path(root))as base,private.Snapshot(base,transport.CONFIG_FILENAME)as config,\
            direct.Guard(root,'archlinux',legacy=True)as guard,private.Directory(journal)as directory:
        intent={'version':2,'host':'archlinux','correlationId':corr,'transportMode':'direct',
                'sourceSha256':hashlib.sha256(bodies['ssh_fresh_nested_channel.py']).hexdigest(),
                'remoteSourceSha256':hashlib.sha256(remote.encode()).hexdigest(),'inventory':config.pin(),
                'outerAuthoritySha256':guard.authority_sha,'expectedUid':None,'expectedBoot':None,
                'directSourcePins':{name:hashlib.sha256(raw).hexdigest() for name,raw in bodies.items()}}
        for name,raw in {**bodies,'remote':remote.encode()}.items():write_bytes(directory,corr+'.'+name+'.source',raw)
        session._create(directory.path/(corr+'.intent.json'),intent,parent_fd=directory.fd)
        with private.Snapshot(directory,corr+'.intent.json')as held:
            if ready_result is not None:
                session._create(directory.path/(corr+'.ready.json'),{'intent':held.pin(),'result':ready_result},parent_fd=directory.fd)
                with private.Snapshot(directory,corr+'.ready.json')as ready:return ready.digest
            session._create(directory.path/(corr+'.terminal.json'),{'state':'ended','correlationId':corr,'receiptSha256':None,
                            'intentSha256':held.digest,'gatewayBoot':ended_boot},parent_fd=directory.fd)
    return None


@unittest.skipUnless(COORDINATOR_CAPABLE,'POSIX generated SSH/ancestry sockets')
class GatewayRebootRecoveryTests(unittest.TestCase):
    """Native-shaped history: a version-2 unusable original, ended priors, a successor selection."""
    def setUp(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        self.original_remote=membership_before('ssh_fresh_nested_channel.py')._REMOTE
        case=DirectChannelTests('runTest');case.setUp();self.addCleanup(case.doCleanups)
        self.case=case;self.root=case.root;self.old=case.corr;self.prior=case.result
        self.old_boot=self.prior['master']['gatewayBoot'];self.assertNotIn(self.old_boot,(NEW_BOOT,LATER_BOOT))
        self.receipt=version2_records(self.root,self.old,self.original_remote,ready_result=self.prior)
        self.ended_prior='e'*32
        version2_records(self.root,self.ended_prior,self.original_remote,ended_boot=self.old_boot)
        self.refusal={'state':'unknown','correlationId':self.old,'failurePhase':'remote_intent','failureReason':'remote_intent_changed',
                      'exceptionClass':'ValueError','errno':None,'launchCapture':None}
        self.source_sha=json.loads((self.journal()/(self.old+'.intent.json')).read_bytes())['sourceSha256']
        self.diagnostic=proof.diagnostic_source(self.original_remote)
        self.drift=False;self.ended=set();self.vanished=set();self.boot=self.old_boot;self.ready_boots={};self.calls=[]
        popen=mock.patch.object(subprocess,'Popen',side_effect=self.consumer);popen.start();self.addCleanup(popen.stop)
        nested.admit(self.root,'archlinux',self.old,self.receipt)

    def ready_result(self,corr):
        master={**self.prior['master'],'gatewayBoot':self.ready_boots.get(corr,self.old_boot)}
        return {**self.prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m','master':master}

    def consumer(self,argv,**kwargs):
        remote=shlex.split(argv[-1]);code=0
        if remote[0]=='python3' and len(remote)>6:
            source=ast.literal_eval(ast.parse(remote[4],mode='eval').body.args[0]);corr=remote[5];action=remote[6]
            self.calls.append((corr,action))
            vanished={'state':'ended','correlationId':corr,'prior':None,'gatewayBoot':self.boot}
            if corr==self.old:
                # The unusable original is only ever observed, never prepared.
                self.assertEqual('status',action);self.assertIn(source,(self.original_remote,self.diagnostic))
                if corr in self.vanished:body=vanished
                elif source==self.diagnostic:
                    body={'state':'directory_membership_changed','correlationId':self.old,'gatewayBoot':self.boot,
                          'sourceSha256':self.source_sha,'originalIntentSha256':'a'*64,'currentIntentSha256':'b'*64}
                elif self.drift:body=self.refusal;code=3
                else:body=self.prior
            else:
                self.assertEqual(channel._REMOTE,source)
                if action=='prepare':self.ready_boots[corr]=self.boot
                result=self.ready_result(corr)
                if action=='status' and corr in self.vanished:body=vanished
                elif action=='status' and corr in self.ended:body={'state':'ended','correlationId':corr,'prior':result,'gatewayBoot':self.boot}
                else:body=result
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

    def ensure(self,operation,seconds=30):
        ctx=transport_ready.context(self.root,'archlinux',deadline=time.monotonic()+seconds,sleep=lambda value:time.sleep(min(value,.05)))
        return readiness.ensure_ready(ctx,readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation)

    def native_history(self):
        """Before the local reboot: a successor of the unusable original, then its renewal."""
        self.drift=True
        self.ensure(OPERATIONS[0]);first=self.selected()
        self.ended.add(first)
        self.ensure(OPERATIONS[1]);second=self.selected()
        self.assertEqual([first,second],self.prepares());self.assertNotIn(self.old,(first,second))
        return first,second

    def ready_boot(self,corr):
        return json.loads((self.journal()/(corr+'.ready.json')).read_bytes())['result']['master']['gatewayBoot']

    def assert_terminal(self,corr,boot,witness):
        journal=self.journal()
        terminal=json.loads((journal/(corr+'.terminal.json')).read_bytes())
        receipt=hashlib.sha256((journal/(corr+'.ready.json')).read_bytes()).hexdigest()
        self.assertEqual({'state':'ended','correlationId':corr,'receiptSha256':receipt,
                          'intentSha256':hashlib.sha256((journal/(corr+'.intent.json')).read_bytes()).hexdigest(),
                          'gatewayBoot':boot},terminal)
        self.assert_witness(corr,boot,receipt,witness)

    def assert_witness(self,corr,boot,receipt,present):
        path=self.journal()/(corr+'.gateway-reboot-end.json')
        self.assertEqual(present,path.exists())
        if present:
            self.assertEqual({'state':'ended','cause':'gateway_reboot','correlationId':corr,'readyGatewayBoot':boot,
                              'observedGatewayBoot':NEW_BOOT,'receiptSha256':receipt},json.loads(path.read_bytes()))

    def assert_original_unresolved(self,witness):
        owner=json.loads((self.campaign()/'current.json').read_bytes())['recoveryId']
        inherited=json.loads((self.campaign()/(owner+'.predecessor.json')).read_bytes())
        self.assertEqual((self.old,self.receipt,'unavailable'),(inherited['correlationId'],inherited['receiptSha256'],inherited['state']))
        # The unusable original never gains a terminal; a cross-boot successor keeps its witness.
        self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())
        self.assert_witness(self.old,self.old_boot,self.receipt,witness)
        self.assertEqual({'status'},{action for corr,action in self.calls if corr==self.old})

    def assert_only_first_terminal(self):
        first,second=self.prepares()
        self.assertEqual({first+'.terminal.json',self.ended_prior+'.terminal.json'},
                         {path.name for path in self.journal().glob('*.terminal.json')})
        self.assertEqual([],list(self.journal().glob('*.gateway-reboot-end.json')))
        self.assertEqual(second,self.selected())

    def renew_after_local_reboot(self,kind):
        """2026-10-29 shape: the pre-reboot selection ends normally after a local reboot."""
        first,second=self.native_history()
        with tempfile.TemporaryDirectory(dir=self.root)as raw,local_reboot(self.root),family(kind,raw):
            self.ended.add(second)
            return first,second,self.ensure(OPERATIONS[2])

    def renew_after_gateway_reboot(self,kind):
        """2026-11-03 shape: every gateway stage vanished with the gateway boot."""
        first,second=self.native_history()
        self.boot=NEW_BOOT;self.vanished.update({self.old,second})
        with tempfile.TemporaryDirectory(dir=self.root)as raw,family(kind,raw):
            return first,second,self.ensure(OPERATIONS[2])

    def test_whole_before_cannot_renew_after_local_reboot(self):
        with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.renew_after_local_reboot('before')
        self.assertEqual('connection_generation_changed',blocked.exception.reason)
        self.assertIn(('NestedUnknown','nested_original_binding'),causes(blocked.exception))
        self.assert_only_first_terminal()

    def test_copy_current_loader_renews_after_local_reboot(self):
        _,_,ready=self.renew_after_local_reboot('copy-current')
        self.assertEqual(OPERATIONS[2],ready.operation_identity);self.assertEqual(3,len(self.prepares()))

    def test_current_renews_once_after_local_reboot(self):
        first,second,ready=self.renew_after_local_reboot('current')
        self.assertEqual(OPERATIONS[2],ready.operation_identity)
        third=self.selected();self.assertEqual([first,second,third],self.prepares())
        self.assert_terminal(second,self.old_boot,witness=False);self.assert_original_unresolved(witness=False)
        with local_reboot(self.root):self.ensure(OPERATIONS[3])
        self.assertEqual(3,len(self.prepares()))

    def test_whole_before_refuses_gateway_reboot_end(self):
        with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.renew_after_gateway_reboot('before')
        self.assertEqual('connection_generation_changed',blocked.exception.reason)
        self.assertIn(('NestedUnknown','nested_original_changed'),causes(blocked.exception))
        self.assert_only_first_terminal()

    def test_copy_current_loader_renews_after_gateway_reboot(self):
        _,_,ready=self.renew_after_gateway_reboot('copy-current')
        self.assertEqual(OPERATIONS[2],ready.operation_identity);self.assertEqual(3,len(self.prepares()))

    def test_current_renews_once_after_gateway_reboot(self):
        first,second,ready=self.renew_after_gateway_reboot('current')
        self.assertEqual(OPERATIONS[2],ready.operation_identity)
        third=self.selected();self.assertEqual([first,second,third],self.prepares())
        self.assertEqual(NEW_BOOT,self.ready_boot(third))
        self.assert_terminal(second,self.old_boot,witness=True);self.assert_original_unresolved(witness=True)
        self.ensure(OPERATIONS[3]);self.assertEqual(3,len(self.prepares()))
        self.case.assert_legacy_unchanged()

    def test_current_renews_after_local_reboot_then_gateway_reboot(self):
        first,second,_=self.renew_after_local_reboot('current')
        third=self.selected()
        with local_reboot(self.root):
            self.boot=NEW_BOOT;self.vanished.update({self.old,third})
            self.ensure(OPERATIONS[3])
            fourth=self.selected();self.assertEqual([first,second,third,fourth],self.prepares())
            self.assert_terminal(third,self.old_boot,witness=True);self.assert_original_unresolved(witness=True)
            self.ensure(OPERATIONS[4]);self.assertEqual(4,len(self.prepares()))

    def test_live_selection_survives_local_reboot(self):
        _,second=self.native_history()
        for kind in ('before','current'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=self.root)as raw,local_reboot(self.root),family(kind,raw):
                if kind=='before':
                    with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.ensure(OPERATIONS[2])
                    self.assertIn(('NestedUnknown','nested_original_binding'),causes(blocked.exception))
                else:
                    self.assertEqual(OPERATIONS[3],self.ensure(OPERATIONS[3]).operation_identity)
        self.assertEqual(2,len(self.prepares()));self.assertEqual(second,self.selected())

    def test_same_boot_vanished_stage_stays_unknown(self):
        _,second=self.native_history()
        self.vanished.add(second)  # The stage vanished but the gateway did not reboot.
        with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.ensure(OPERATIONS[2])
        self.assertEqual('connection_generation_changed',blocked.exception.reason)
        self.assertIn(('NestedUnknown','nested_original_changed'),causes(blocked.exception))
        self.assertEqual(2,len(self.prepares()))
        self.assertFalse((self.journal()/(second+'.terminal.json')).exists())
        self.assertFalse((self.journal()/(second+'.gateway-reboot-end.json')).exists())

    def test_original_not_ended_across_the_reboot_blocks_its_successor(self):
        _,second=self.native_history()
        # Only the selection's stage vanished; the original answers like a surviving stage.
        self.boot=NEW_BOOT;self.vanished.add(second)
        with self.assertRaises(readiness.ReadinessBlocked):self.ensure(OPERATIONS[2])
        self.assertEqual(2,len(self.prepares()))
        self.assert_terminal(second,self.old_boot,witness=True)
        self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())
        self.assertFalse((self.journal()/(self.old+'.gateway-reboot-end.json')).exists())

    def test_changed_gateway_trust_never_proves_a_cross_boot_end(self):
        _,second=self.native_history()
        self.boot=NEW_BOOT;self.vanished.update({self.old,second})
        known=self.case.f.f.known
        with open(known,'ab')as stream:stream.write(b'# replaced trust\n')
        with self.assertRaises(readiness.ReadinessBlocked)as blocked:self.ensure(OPERATIONS[2])
        self.assertIn(('NestedUnknown','nested_original_authority_changed'),causes(blocked.exception))
        self.assertEqual(2,len(self.prepares()))
        self.assertEqual([],list(self.journal().glob('*.gateway-reboot-end.json')))

    def original_terminal(self):
        intent=hashlib.sha256((self.journal()/(self.old+'.intent.json')).read_bytes()).hexdigest()
        with private.Directory(self.journal())as directory:
            session._create(directory.path/(self.old+'.terminal.json'),{'state':'ended','correlationId':self.old,'receiptSha256':self.receipt,
                            'intentSha256':intent,'gatewayBoot':self.old_boot},parent_fd=directory.fd)

    def test_original_that_already_ended_gains_no_witness(self):
        self.original_terminal()
        self.boot=NEW_BOOT;self.vanished.add(self.old)
        with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10)as issued:
            self.assertTrue(nested.validate_membership_successor(issued,self.root,'archlinux',previous=self.old,new_correlation='7'*32))
        self.assertFalse((self.journal()/(self.old+'.gateway-reboot-end.json')).exists())

    def test_changed_original_witness_refuses_the_successor_proof(self):
        self.boot=NEW_BOOT;self.vanished.add(self.old)
        with private.Directory(self.journal())as directory:
            session._create(directory.path/(self.old+'.gateway-reboot-end.json'),{'state':'ended','cause':'gateway_reboot','correlationId':self.old,
                            'readyGatewayBoot':LATER_BOOT,'observedGatewayBoot':NEW_BOOT,'receiptSha256':self.receipt},parent_fd=directory.fd)
        with self.assertRaisesRegex(nested.NestedUnknown,'nested_original_witness_changed'):
            with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):self.fail('issued')
        self.assertEqual([],self.prepares())

    def test_membership_successor_accepts_only_a_rebooted_original(self):
        self.boot=NEW_BOOT;self.vanished.add(self.old)
        for kind in ('before','current'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=self.root)as raw,family(kind,raw)as code:
                if kind=='before':
                    with self.assertRaisesRegex(code.nested.NestedUnknown,'nested_original_changed'):
                        with code.nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):
                            self.fail('before issued a successor proof')
                    self.assertFalse((self.journal()/(self.old+'.gateway-reboot-end.json')).exists())
                else:
                    with code.nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10)as issued:
                        self.assertTrue(code.nested.validate_membership_successor(issued,self.root,'archlinux',previous=self.old,
                                                                                 new_correlation='7'*32))
                    self.assert_witness(self.old,self.old_boot,self.receipt,True)
        # Same-boot disappearance never issues the proof.
        self.boot=self.old_boot
        with self.assertRaisesRegex(nested.NestedUnknown,'nested_original_changed'):
            with nested.membership_successor(self.root,'archlinux',self.old,self.receipt,time.monotonic()+10):self.fail('same boot')
        self.assertEqual([],self.prepares());self.assertFalse((self.journal()/(self.old+'.terminal.json')).exists())


@unittest.skipUnless(COORDINATOR_CAPABLE,'POSIX generated SSH/ancestry sockets')
class GatewayRebootSiteTests(unittest.TestCase):
    """Each changed decision, driven by the actual unfixed and fixed code."""
    @contextmanager
    def site(self,kind):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        case=DirectChannelTests('runTest');case.setUp();self.addCleanup(case.doCleanups)
        with tempfile.TemporaryDirectory(dir=case.root)as raw,family(kind,raw)as code:
            with mock.patch.object(subprocess,'Popen',side_effect=case.consumer):
                ready=code.direct.prepare(case.root,'archlinux',case.corr)
            self.assertEqual('ready',ready['state'])
            case.ready_result=dict(case.result)
            yield case,code,ready

    def call(self,case,code,method,body):
        case.result=body;before=len(case.calls)
        with mock.patch.object(subprocess,'Popen',side_effect=case.consumer):
            outcome=getattr(code.direct,method)(case.root,'archlinux',case.corr)
        return outcome['state'],len(case.calls)-before

    def path(self,case,leaf):
        return channel._context_journal(case.root,'archlinux',case.corr,False,True)/(case.corr+'.'+leaf)

    def vanished(self,case,boot=NEW_BOOT):
        return {'state':'ended','correlationId':case.corr,'prior':None,'gatewayBoot':boot}

    def same_boot_end(self,case):
        return {'state':'ended','correlationId':case.corr,'prior':case.ready_result,'gatewayBoot':case.ready_result['master']['gatewayBoot']}

    def witness(self,case):
        return json.loads(self.path(case,'gateway-reboot-end.json').read_bytes())

    def test_gateway_reboot_end_at_reconcile_and_status(self):
        for method in ('reconcile_original','status'):
            for kind in ('before','current'):
                with self.subTest(method=method,kind=kind),self.site(kind)as(case,code,ready):
                    boot=case.ready_result['master']['gatewayBoot']
                    # Both decisions are reached only after the one remote status observation.
                    state,calls=self.call(case,code,method,self.vanished(case))
                    self.assertEqual(1,calls)
                    if kind=='before':
                        self.assertEqual('unknown',state)
                        self.assertFalse(self.path(case,'terminal.json').exists());self.assertFalse(self.path(case,'gateway-reboot-end.json').exists())
                        continue
                    self.assertEqual('ended',state)
                    self.assertEqual(boot,json.loads(self.path(case,'terminal.json').read_bytes())['gatewayBoot'])
                    first=self.path(case,'gateway-reboot-end.json').read_bytes()
                    self.assertEqual((boot,NEW_BOOT),(self.witness(case)['readyGatewayBoot'],self.witness(case)['observedGatewayBoot']))
                    # A still newer boot is a later observation of the same witnessed end.
                    self.assertEqual(('ended',1),self.call(case,code,method,self.vanished(case,LATER_BOOT)))
                    self.assertEqual(first,self.path(case,'gateway-reboot-end.json').read_bytes())

    def test_same_boot_vanished_stage_stays_unknown_at_every_site(self):
        for method in ('reconcile_original','status'):
            with self.subTest(method=method),self.site('current')as(case,code,ready):
                boot=case.ready_result['master']['gatewayBoot']
                self.assertEqual(('unknown',1),self.call(case,code,method,self.vanished(case,boot)))
                self.assertFalse(self.path(case,'terminal.json').exists());self.assertFalse(self.path(case,'gateway-reboot-end.json').exists())

    def test_terminal_first_never_gains_a_witness_and_witness_first_completes(self):
        with self.site('current')as(case,code,ready):
            self.assertEqual(('ended',1),self.call(case,code,'status',self.same_boot_end(case)))
            self.assertEqual(('ended',1),self.call(case,code,'reconcile_original',self.vanished(case)))
            self.assertFalse(self.path(case,'gateway-reboot-end.json').exists())
        with self.site('current')as(case,code,ready):
            boot=case.ready_result['master']['gatewayBoot']
            receipt=hashlib.sha256(self.path(case,'ready.json').read_bytes()).hexdigest()
            with private.Directory(self.path(case,'ready.json').parent)as directory:
                session._create(directory.path/(case.corr+'.gateway-reboot-end.json'),{'state':'ended','cause':'gateway_reboot',
                    'correlationId':case.corr,'readyGatewayBoot':boot,'observedGatewayBoot':LATER_BOOT,'receiptSha256':receipt},parent_fd=directory.fd)
            self.assertEqual(('ended',1),self.call(case,code,'reconcile_original',self.vanished(case)))
            self.assertEqual(boot,json.loads(self.path(case,'terminal.json').read_bytes())['gatewayBoot'])
            self.assertEqual(LATER_BOOT,self.witness(case)['observedGatewayBoot'])

    def test_same_boot_end_contradicting_a_witness_refuses(self):
        with self.site('current')as(case,code,ready):
            self.assertEqual(('ended',1),self.call(case,code,'reconcile_original',self.vanished(case)))
            for method in ('status','reconcile_original'):
                with self.subTest(method):self.assertEqual(('unknown',1),self.call(case,code,method,self.same_boot_end(case)))

    def test_non_direct_status_never_ends_across_a_gateway_reboot(self):
        # A non-direct status runs over whatever outer session is current, not the
        # original's recorded authority, so it never proves a cross-boot end.
        from agent_tools.tests.test_ssh_fresh_nested_channel import FreshChannelTests
        case=FreshChannelTests('runTest');case.setUp();self.addCleanup(case.doCleanups)
        case.stdout=json.dumps(case.ready_fixture()).encode();case.rc=0
        self.assertEqual('ready',case.invoke()['state'])
        case.stdout=json.dumps({'state':'ended','correlationId':case.corr,'prior':None,'gatewayBoot':NEW_BOOT}).encode()
        self.assertEqual('unknown',case.invoke(False)['state'])
        journal=channel._context_journal(case.root,'archlinux',case.corr,False,False)
        self.assertFalse((journal/(case.corr+'.terminal.json')).exists())
        self.assertFalse((journal/(case.corr+'.gateway-reboot-end.json')).exists())

    def test_changed_witness_refuses(self):
        with self.site('current')as(case,code,ready):
            self.assertEqual(('ended',1),self.call(case,code,'reconcile_original',self.vanished(case)))
            path=self.path(case,'gateway-reboot-end.json');original=path.read_bytes();boot=case.ready_result['master']['gatewayBoot']
            edits={'readyGatewayBoot':lambda w:{**w,'readyGatewayBoot':NEW_BOOT},'cause':lambda w:{**w,'cause':'other'},
                   'receipt':lambda w:{**w,'receiptSha256':'0'*64},'observed equals ready':lambda w:{**w,'observedGatewayBoot':boot},
                   'observed malformed':lambda w:{**w,'observedGatewayBoot':'x'},'extra key':lambda w:{**w,'note':1},
                   'missing key':lambda w:{k:v for k,v in w.items() if k!='cause'}}
            for name,edit in edits.items():
                with self.subTest(name):
                    changed=edit(json.loads(original));replacement=path.with_name(path.name+'.replacement')
                    replacement.write_bytes(json.dumps(changed).encode());replacement.chmod(0o600);os.replace(replacement,path)
                    self.assertEqual('unknown',self.call(case,code,'reconcile_original',self.vanished(case))[0])
                    self.assertEqual('unknown',self.call(case,code,'status',self.vanished(case))[0])
                    restored=path.with_name(path.name+'.restored');restored.write_bytes(original);restored.chmod(0o600);os.replace(restored,path)
            self.assertEqual('ended',self.call(case,code,'reconcile_original',self.vanished(case))[0])

    def test_original_records_bind_after_local_reboot(self):
        for kind in ('before','current'):
            with self.subTest(kind=kind),self.site(kind)as(case,code,ready),local_reboot(case.root):
                if kind=='before':
                    with self.assertRaisesRegex(code.nested.NestedUnknown,'nested_original_binding'):
                        with code.nested._original_records(case.root,'archlinux',case.corr,ready['receiptSha256']):self.fail('bound')
                else:
                    with code.nested._original_records(case.root,'archlinux',case.corr,ready['receiptSha256'])as records:
                        self.assertEqual(case.corr,records[2]['correlationId'])

    def test_retained_terminal_after_local_reboot(self):
        for kind in ('before','current'):
            with self.subTest(kind=kind),self.site(kind)as(case,code,ready):
                self.assertEqual(('ended',1),self.call(case,code,'status',self.same_boot_end(case)))
                for rebooted in (False,True):
                    with ExitStack()as outer:
                        if rebooted:outer.enter_context(local_reboot(case.root))
                        directory=outer.enter_context(private.Directory(self.path(case,'intent.json').parent))
                        held=outer.enter_context(private.Snapshot(directory,case.corr+'.intent.json'))
                        value=json.loads(held.body,object_pairs_hook=transport._reject_duplicate_keys)
                        retained=code.channel._retained_v2_terminal(outer,directory,held,value,'archlinux')
                        # Without the remount both kinds accept; only the renumbering differs.
                        self.assertEqual(not(rebooted and kind=='before'),callable(retained),(kind,rebooted))

    def test_reconcile_same_boot_end_after_local_reboot(self):
        for kind in ('before','current'):
            with self.subTest(kind=kind),self.site(kind)as(case,code,ready),local_reboot(case.root):
                # The unfixed binding refuses before any remote observation.
                self.assertEqual(('unknown',0) if kind=='before' else ('ended',1),self.call(case,code,'reconcile_original',self.same_boot_end(case)))
                self.assertFalse(self.path(case,'gateway-reboot-end.json').exists())

    def test_touched_record_or_trust_still_refuses_after_local_reboot(self):
        with self.site('current')as(case,code,ready):
            intent=self.path(case,'intent.json');info=os.stat(intent)
            os.utime(intent,ns=(info.st_atime_ns,info.st_mtime_ns))  # same bytes and times, new ctime
            self.assertNotEqual(info.st_ctime_ns,os.stat(intent).st_ctime_ns)
            with local_reboot(case.root):
                with self.assertRaisesRegex(nested.NestedUnknown,'nested_original_binding'):
                    with nested._original_records(case.root,'archlinux',case.corr,ready['receiptSha256']):self.fail('bound')
                self.assertEqual(('unknown',0),self.call(case,code,'reconcile_original',self.same_boot_end(case)))
        with self.site('current')as(case,code,ready):
            with open(case.f.f.known,'ab')as stream:stream.write(b'# replaced trust\n')
            with local_reboot(case.root):
                self.assertEqual(('unknown',0),self.call(case,code,'reconcile_original',self.same_boot_end(case)))


@unittest.skipUnless(COORDINATOR_CAPABLE,'POSIX module imports')
class GatewayRebootPredicateTests(unittest.TestCase):
    """Finite refusal tables for the new decisions."""
    def ready(self,boot='0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e'):
        master={'actor':{'pid':10,'startTicks':20,'uid':1000},'socket':[1,2,0o140600,1000,1000,1,0,3,4],
                'directory':[1,2,0o40700,1000,1000],'listenerInode':'99','gatewayBoot':boot}
        return {'state':'ready','correlationId':'a'*32,'master':master,'arch':{'uid':1000,'boot':boot},
                'controlPath':'/tmp/vpn-channel-'+'a'*32+'/m'}

    def test_gateway_reboot_end_accepts_only_the_exact_cross_boot_shape(self):
        ready=self.ready();body={'state':'ended','correlationId':'a'*32,'prior':None,'gatewayBoot':NEW_BOOT}
        self.assertEqual({'state':'ended','cause':'gateway_reboot','correlationId':'a'*32,'readyGatewayBoot':ready['master']['gatewayBoot'],
                          'observedGatewayBoot':NEW_BOOT},channel.gateway_reboot_end(body,'a'*32,ready))
        refusals={'same boot':{**body,'gatewayBoot':ready['master']['gatewayBoot']},'prior present':{**body,'prior':ready},
                  'other channel':{**body,'correlationId':'b'*32},'malformed boot':{**body,'gatewayBoot':NEW_BOOT.upper()},
                  'extra field':{**body,'note':1},'missing field':{k:v for k,v in body.items() if k!='prior'},
                  'not ended':{**body,'state':'ready'},'boot type':{**body,'gatewayBoot':7}}
        for name,value in refusals.items():
            with self.subTest(name):self.assertIsNone(channel.gateway_reboot_end(value,'a'*32,ready))
        for name,value in {'no ready':None,'not ready':{**ready,'state':'unknown'},'other ready':{**ready,'correlationId':'b'*32},
                           'bad master':{**ready,'master':{**ready['master'],'listenerInode':'x'}},'extra ready key':{**ready,'note':1},
                           'other control path':{**ready,'controlPath':'/elsewhere'},'bad arch':{**ready,'arch':None},
                           'missing arch':{k:v for k,v in ready.items() if k!='arch'}}.items():
            with self.subTest(name):self.assertIsNone(channel.gateway_reboot_end(body,'a'*32,value))

    def test_record_continuity_allows_only_the_device_number(self):
        old={'generation':[5,6,0o100600,501,20,1,99,1000,2000],'size':99,'sha256':'c'*64}
        new={**old,'generation':[9,*old['generation'][1:]]}
        self.assertTrue(channel.same_record_after_local_reboot(old,old,5))
        self.assertTrue(channel.same_record_after_local_reboot(old,new,9))
        self.assertTrue(channel.same_record_after_local_reboot(old,new,9,5))
        self.assertFalse(channel.same_record_after_local_reboot(old,new,9,4))  # another old device
        for index,name in enumerate(('ino','mode','uid','gid','nlink','size','mtime','ctime'),start=1):
            changed={**new,'generation':list(new['generation'])};changed['generation'][index]+=1
            with self.subTest(name):self.assertFalse(channel.same_record_after_local_reboot(old,changed,9))
        for name,value in {'digest':{**new,'sha256':'d'*64},'size field':{**new,'size':98},'extra':{**new,'x':1},
                           'missing':{k:v for k,v in new.items() if k!='sha256'},'bool':{**new,'generation':[True,*new['generation'][1:]]},
                           'short':{**new,'generation':new['generation'][:8]}}.items():
            with self.subTest(name):self.assertFalse(channel.same_record_after_local_reboot(old,value,9))
        for name,value in {'bool link':{**old,'generation':[*old['generation'][:5],True,*old['generation'][6:]]},
                           'float size':{**old,'size':99.0}}.items():
            with self.subTest(name):self.assertFalse(channel.same_record_after_local_reboot(value,old,5))
        self.assertFalse(channel.same_record_after_local_reboot(old,new,8))  # current device is not the anchor's
        custody={'custody':'private-generation-v1','generation':old['generation'],'size':99}
        self.assertTrue(channel.same_record_after_local_reboot(custody,{**custody,'generation':new['generation']},9))
        self.assertFalse(channel.same_record_after_local_reboot(custody,{**custody,'custody':'other','generation':new['generation']},9))

    def test_record_sets_move_together_from_one_old_device(self):
        a={'generation':[5,6,0o100600,501,20,1,99,1000,2000],'size':99,'sha256':'c'*64}
        b={'generation':[5,7,0o100600,501,20,1,98,1001,2001],'size':98,'sha256':'d'*64}
        moved=lambda pin,device:{**pin,'generation':[device,*pin['generation'][1:]]}
        self.assertIsNone(channel.same_records_after_local_reboot([(a,a,5),(b,b,5)]))
        self.assertEqual(5,channel.same_records_after_local_reboot([(a,moved(a,9),9),(b,moved(b,9),9)]))
        self.assertIs(False,channel.same_records_after_local_reboot([(a,moved(a,9),9),(b,b,5)]))  # mixed
        self.assertIs(False,channel.same_records_after_local_reboot([(a,moved(a,9),9),(moved(b,4),moved(b,9),9)]))  # two old devices
        self.assertIs(False,channel.same_records_after_local_reboot([]))

    def test_authority_continuity_substitutes_the_recorded_module_and_rewinds_known_fields(self):
        legacy={'version':1,'host':'archlinux','root':'/r','sourceSha256':'1'*64,'configSha256':'2'*64,'configFingerprint':[5,1,2,3,1,9,7,8],
                'files':[{'path':'/k','sha256':'3'*64,'fingerprint':[5,11,2,3,1,9,7,8]},{'path':'/t','sha256':'4'*64,'fingerprint':[5,12,2,3,1,9,7,8]}],
                'routeAliases':['gateway','archlinux']}
        inventory={'version':2,'host':'archlinux','root':'/r','sourceSha256':'5'*64,
                   'configGeneration':{'custody':'private-generation-v1','generation':[5,1,2,3,4,1,9,7,8],'size':9},
                   'files':[{'path':'/k','generation':{'custody':'private-generation-v1','generation':[5,11,2,3,4,1,9,7,8],'size':9}},
                            {'path':'/t','sha256':'e'*64,'fingerprint':[5,12,2,3,1,9,7,8]}],'routeAliases':['gateway','archlinux']}
        def renumber(node,device):
            if type(node)is dict:return {k:renumber(v,device) for k,v in node.items()}
            if type(node)is list and len(node)in (8,9) and all(type(i)is int for i in node):return [device,*node[1:]]
            if type(node)is list:return [renumber(v,device) for v in node]
            return node
        for authority,module in ((legacy,'ssh_connection_session.py'),(inventory,'ssh_direct_inventory.py')):
            with self.subTest(module):
                intent={'outerAuthoritySha256':hashlib.sha256(session._json(authority)).hexdigest(),
                        'directSourcePins':{module:authority['sourceSha256']}}
                live={**renumber(authority,9),'sourceSha256':'f'*64}  # a later tooling revision of the computing module
                self.assertTrue(direct.recorded_authority_continuity(session,intent,{**authority,'sourceSha256':'f'*64}))
                self.assertFalse(direct.recorded_authority_continuity(session,intent,live))
                self.assertTrue(direct.recorded_authority_continuity(session,intent,live,5,9))
                self.assertFalse(direct.recorded_authority_continuity(session,intent,live,5,5))
                self.assertFalse(direct.recorded_authority_continuity(session,intent,live,4,9))
                self.assertFalse(direct.recorded_authority_continuity(session,{**intent,'directSourcePins':{}},live,5,9))
                moved=json.loads(json.dumps(live));moved['files'][0]['fingerprint' if module.startswith('ssh_connection') else 'generation']=(
                    [4,*moved['files'][0]['fingerprint'][1:]] if module.startswith('ssh_connection')
                    else {**moved['files'][0]['generation'],'generation':[4,*moved['files'][0]['generation']['generation'][1:]]})
                self.assertFalse(direct.recorded_authority_continuity(session,intent,moved,5,9))  # a record on a third device
                changed=json.loads(json.dumps(live));changed['files'][1]['sha256']='0'*64
                self.assertFalse(direct.recorded_authority_continuity(session,intent,changed,5,9))
                changed=json.loads(json.dumps(live));changed['routeAliases']=['gateway','other']
                self.assertFalse(direct.recorded_authority_continuity(session,intent,changed,5,9))
                unknown=json.loads(json.dumps(live));unknown['extra']=[9,1,2,3,4,5,6,7]  # unknown fields are never rewound
                self.assertFalse(direct.recorded_authority_continuity(session,{**intent,'outerAuthoritySha256':hashlib.sha256(
                    session._json({**authority,'extra':[5,1,2,3,4,5,6,7]})).hexdigest()},unknown,5,9))

    def test_all_whole_before_artifacts_have_exact_custody(self):
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        self.assertEqual(set(name+'.before.source' for name in FAMILY),set(provenance['files']))
        for leaf,pin in provenance['files'].items():
            with self.subTest(leaf):
                self.assertEqual(pin['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest())
                self.assertNotEqual(pin['sha256'],hashlib.sha256((Path(__file__).parents[2]/pin['path']).read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
