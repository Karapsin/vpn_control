"""Complete real provider and private TempFS custody; remote replies are inert seam.

No actual config, SSH, route or native guest. Actual local Python children consume
private stdin and emit declared remote kernel facts, like routine owner controls.
"""
import gzip,hashlib,json,os,shutil,sys,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct
from agent_tools.tests import test_ssh_direct_nested_channel as fixture_owner
if fixture_owner.COORDINATOR_CAPABLE:
    from agent_tools import ssh_connection_session as session,ssh_fresh_nested_channel as channel
    from agent_tools.native_review_source_closure import _Held

FIXTURES=Path(__file__).with_name('fixtures')/'ssh_direct_ended_v1'
# Archival transition predicates bind the entire reviewed v1 graph. The current
# v2 programme has different peer/source authority and must not be substituted
# into these historical observations. Current v2 has its own provider controls.
CURRENT_PROVIDER_SOURCE=FIXTURES/'reviewed_optimizer/ssh_fresh_nested_channel.py' if fixture_owner.COORDINATOR_CAPABLE else None
CURRENT_MCP_SOURCE=CURRENT_PROVIDER_SOURCE.with_name('mcp_server.py') if CURRENT_PROVIDER_SOURCE else None
def historical(name,expected):
    body=gzip.decompress((FIXTURES/name).read_bytes())
    if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('historical_fixture_digest')
    return body
PROVIDER_BEFORE=historical('ssh_fresh_nested_channel.before.py.gz','b957d4b6bf37ca0c603f09f7df757284a56f042706533159fb5427c1b89fdafc')
MCP_BEFORE=historical('mcp_server.before.py.gz','6ca7b4050ee5ca6977ff3948ad22b78350d49007c557ba603b9ab2a6558dc014')
# Exact approved after bytes from public Git a026d0254579a797d30a0c78c8f15d92eae74030.
# Future MCP edits do not change this historical admission edge.
MCP_REVIEWED_AFTER=historical('mcp_server.reviewed-after.py.gz','5707593229d5fa3c331998a0f6bbc2bae1ca4dff3a94fd4f5f5c8064e07a14d7')

@unittest.skipUnless(fixture_owner.COORDINATOR_CAPABLE,'POSIX private TempFS provider required')
class ProviderEndedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.owner=fixture_owner.DirectChannelTests('runTest');self.owner.setUp()
        self.addCleanup(self.owner.doCleanups)
        self.root=self.owner.root;self.corr=self.owner.corr;self.calls=self.owner.calls
        self.source=self.root/'owned-provider-source';self.source.mkdir(mode=0o700)
        for name in direct._SOURCE_NAMES:
            shutil.copyfile(Path(direct.__file__).with_name(name),self.source/name)
        for name in ('ssh_direct_nested_channel.py','ssh_transport.py'):
            (self.source/name).write_bytes(CURRENT_PROVIDER_SOURCE.with_name(name).read_bytes())
        self.provider_path=self.source/'ssh_fresh_nested_channel.py'
        self.provider_path.write_bytes(PROVIDER_BEFORE)
        (self.source/'mcp_server.py').write_bytes(MCP_BEFORE)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(direct,'__file__',str(self.source/'ssh_direct_nested_channel.py')).start()
        self.module=self.load()
        mock.patch.object(direct,'_dependencies',side_effect=lambda:(session,self.module,_Held)).start()
        self.journal=self.root/'.rag_index/ssh-direct-nested-channel'
    @property
    def result(self):return self.owner.result
    @result.setter
    def result(self,value):self.owner.result=value
    def invoke(self,*args,**kwargs):
        # Compare inert transport bytes against this selected historical/current
        # producer, rather than assuming the latest shared wire programme.
        with mock.patch.object(self.owner,'expected_remote',self.module._REMOTE):
            return self.owner.invoke(*args,**kwargs)
    def assert_legacy_unchanged(self):return self.owner.assert_legacy_unchanged()
    def load(self):
        name='agent_tools._owned_provider_'+str(id(self))
        module=types.ModuleType(name);module.__file__=str(self.provider_path);module.__package__='agent_tools'
        exec(compile(self.provider_path.read_bytes(),str(self.provider_path),'exec'),module.__dict__)
        return module
    def seed(self):
        ready=self.invoke();self.assertEqual('ready',ready['state'])
        prior=self.result
        self.result={'state':'ended','correlationId':self.corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        self.assertEqual('ended',self.invoke('status')['state'])
        self.before={name:(self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in ('intent','ready','terminal')}
        self.new='c'*32;self.result={**prior,'correlationId':self.new,'controlPath':'/tmp/vpn-channel-'+self.new+'/m'}
    def transition(self,*,equal=False,mcp_body=None):
        if not equal:(self.source/'mcp_server.py').write_bytes(MCP_REVIEWED_AFTER if mcp_body is None else mcp_body)
        self.provider_path.write_bytes(CURRENT_PROVIDER_SOURCE.read_bytes())
        self.module=self.load()
    def row(self,name):return json.loads((self.journal/(self.corr+'.'+name+'.json')).read_bytes())
    def write(self,name,value):
        path=self.journal/(self.corr+'.'+name+'.json');path.write_bytes(session._json(value))
    def mutate_intent(self,fn,*,keep_terminal_digest=True):
        value=self.row('intent');fn(value);self.write('intent',value)
        if keep_terminal_digest:
            terminal=self.row('terminal');terminal['intentSha256']=hashlib.sha256((self.journal/(self.corr+'.intent.json')).read_bytes()).hexdigest();self.write('terminal',terminal)
    def refuse(self):
        count=len(self.calls);fd=len(os.listdir('/dev/fd'))
        value=self.invoke(corr=self.new)
        self.assertEqual('unknown',value['state']);self.assertEqual(count,len(self.calls))
        self.assertFalse((self.journal/(self.new+'.intent.json')).exists());self.assertEqual(fd,len(os.listdir('/dev/fd')))
        self.assert_legacy_unchanged()
    def test_current_provider_cannot_replay_an_unresolved_original_v1_history(self):
        self.seed();(self.journal/(self.corr+'.terminal.json')).unlink();before=len(self.calls)
        self.provider_path.write_bytes(Path(channel.__file__).read_bytes());self.module=self.load()
        # Exact original handles retain original non-replay; a new explicit
        # context does not inherit this unrelated global UNKNOWN.
        value=self.invoke(corr=self.corr)
        self.assertEqual('unknown',value['state']);self.assertEqual(before,len(self.calls))
        self.assertEqual({name:body for name,body in self.before.items() if name!='terminal'},{name:(self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in self.before if name!='terminal'})
        self.assertFalse((self.journal/(self.corr+'.terminal.json')).exists());self.assert_legacy_unchanged()

    def test_actual_equal_source_ended_then_new_intent(self):
        # Seed with the actual selected provider so this is same-source on both modes.
        self.provider_path.write_bytes(CURRENT_PROVIDER_SOURCE.read_bytes());self.module=self.load()
        self.seed();fd=len(os.listdir('/dev/fd'));value=self.invoke(corr=self.new)
        self.assertEqual('ready',value['state']);self.assertEqual(fd,len(os.listdir('/dev/fd')))
        self.assertEqual(self.before,{name:(self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in self.before})
        self.assert_legacy_unchanged()
    def test_actual_old_provider_and_mcp_transition(self):
        self.seed();self.transition();fd=len(os.listdir('/dev/fd'));value=self.invoke(corr=self.new)
        self.assertEqual('ready',value['state'])
        new=self.row_for(self.new,'intent');old=self.row('intent')
        self.assertEqual(hashlib.sha256(PROVIDER_BEFORE).hexdigest(),old['sourceSha256'])
        self.assertEqual(hashlib.sha256(self.provider_path.read_bytes()).hexdigest(),new['sourceSha256'])
        self.assertEqual('6ca7b4050ee5ca6977ff3948ad22b78350d49007c557ba603b9ab2a6558dc014',old['directSourcePins']['mcp_server.py'])
        self.assertEqual('5707593229d5fa3c331998a0f6bbc2bae1ca4dff3a94fd4f5f5c8064e07a14d7',new['directSourcePins']['mcp_server.py'])
        self.assertEqual(new['sourceSha256'],new['directSourcePins']['ssh_fresh_nested_channel.py'])
        self.assertEqual(self.before,{name:(self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in self.before})
        self.assertEqual(fd,len(os.listdir('/dev/fd')));self.assert_legacy_unchanged()
    def test_unreviewed_current_or_future_mcp_refuses_without_successor(self):
        self.seed()
        bodies=[MCP_REVIEWED_AFTER+b'\n# inert unreviewed future MCP fixture\n']
        current=CURRENT_MCP_SOURCE.read_bytes()
        if current!=MCP_REVIEWED_AFTER:bodies.append(current)
        for body in bodies:
            with self.subTest(mcpSha256=hashlib.sha256(body).hexdigest()):
                self.transition(mcp_body=body)
                self.refuse()
                self.assertEqual(self.before,{name:(self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in self.before})
    def row_for(self,corr,name):return json.loads((self.journal/(corr+'.'+name+'.json')).read_bytes())
    def negative(self,kind):
        self.seed();self.transition()
        if kind=='missing_terminal':(self.journal/(self.corr+'.terminal.json')).unlink()
        elif kind in ('live','unknown','wrong_terminal_correlation','intent_digest','receipt_digest','erased_ready_receipt','terminal_boot','erased_ready_receipt'):
            value=self.row('terminal')
            if kind in ('live','unknown'):value['state']='ready' if kind=='live' else 'unknown'
            elif kind=='wrong_terminal_correlation':value['correlationId']='d'*32
            elif kind=='intent_digest':value['intentSha256']='0'*64
            elif kind=='receipt_digest':value['receiptSha256']='0'*64
            elif kind=='erased_ready_receipt':value['receiptSha256']=None
            else:value['gatewayBoot']='00000000-0000-0000-0000-000000000000'
            self.write('terminal',value)
        elif kind=='ready_boot':
            value=self.row('ready');value['result']['master']['gatewayBoot']='00000000-0000-0000-0000-000000000000';self.write('ready',value)
            terminal=self.row('terminal');terminal['receiptSha256']=hashlib.sha256((self.journal/(self.corr+'.ready.json')).read_bytes()).hexdigest();self.write('terminal',terminal)
        elif kind=='ready_intent_pin':
            value=self.row('ready');value['intent']['sha256']='0'*64;self.write('ready',value)
            terminal=self.row('terminal');terminal['receiptSha256']=hashlib.sha256((self.journal/(self.corr+'.ready.json')).read_bytes()).hexdigest();self.write('terminal',terminal)
        elif kind=='ready_arch':
            value=self.row('ready');value['result']['arch']['uid']=True;self.write('ready',value)
            terminal=self.row('terminal');terminal['receiptSha256']=hashlib.sha256((self.journal/(self.corr+'.ready.json')).read_bytes()).hexdigest();self.write('terminal',terminal)
        else:
            def mutation(value):
                if kind=='unknown_source':value['sourceSha256']='0'*64;value['directSourcePins']['ssh_fresh_nested_channel.py']='0'*64
                elif kind=='missing_population':value['directSourcePins'].pop('ssh_transport.py')
                elif kind=='extra_population':value['directSourcePins']['extra.py']='0'*64
                elif kind=='other_population':value['directSourcePins']['ssh_transport.py']='0'*64
                elif kind=='invalid_mcp_pair':value['directSourcePins']['mcp_server.py']='0'*64
                elif kind=='remote_source':value['remoteSourceSha256']='0'*64
                elif kind=='typed_version':value['version']=True
                elif kind=='forged_inventory':value['inventory']['sha256']='0'*64
                elif kind=='forged_authority':value['outerAuthoritySha256']='0'*64
                else:raise AssertionError(kind)
            self.mutate_intent(mutation)
        self.refuse()

NEGATIVE=('missing_terminal','live','unknown','wrong_terminal_correlation','intent_digest','receipt_digest','erased_ready_receipt','terminal_boot','ready_boot','ready_intent_pin','ready_arch','unknown_source','missing_population','extra_population','other_population','invalid_mcp_pair','remote_source','typed_version','forged_inventory','forged_authority')
for name in NEGATIVE:
    def test(self,name=name):self.negative(name)
    setattr(ProviderEndedHistoryTests,'test_refuses_'+name,test)


# Exact public Git bounds-extension predecessor; no actual retained journals.
OLD_CLOSURE_SHA='2a384af585bd8e2d819510d0268230fbe0aec8245512f4450a589e8d1030ac28'
CURRENT_CLOSURE_SHA='0fac471b05e0e784913f5508a5d90b279fbc48c96751b83082d1f9c14cef95ae'
BEFORE_SHA='b1a91629fe22e04a5f347af7047cfe4df8197274b3a7e2b8a1723703014295fd'
OLD_CLOSURE=historical('native_review_source_closure.before.py.gz',OLD_CLOSURE_SHA)
B1A_BEFORE=historical('ssh_fresh_nested_channel.closure-provider-before.py.gz',BEFORE_SHA)
CURRENT_CLOSURE=CURRENT_PROVIDER_SOURCE.with_name('native_review_source_closure.py').read_bytes() if CURRENT_PROVIDER_SOURCE else b''

class ProviderEndedClosureHistoryTests(ProviderEndedHistoryTests):
    def setUp(self):
        super().setUp()
        (self.source / 'native_review_source_closure.py').write_bytes(OLD_CLOSURE)

    def transition(self, **kwargs):
        (self.source / 'native_review_source_closure.py').write_bytes(CURRENT_CLOSURE)
        super().transition(**kwargs)

    def seed_b1a(self, *, old_mcp=False):
        self.provider_path.write_bytes(B1A_BEFORE)
        if not old_mcp:
            (self.source / 'mcp_server.py').write_bytes(CURRENT_MCP_SOURCE.read_bytes())
        self.module = self.load()
        self.seed()

    def test_actual_b1a_closure_only_transition_preserves_every_saved_byte(self):
        self.seed_b1a()
        self.transition(mcp_body=CURRENT_MCP_SOURCE.read_bytes())
        fd_before = len(os.listdir('/dev/fd'))
        value = self.invoke(corr=self.new)
        self.assertEqual('ready', value['state'])
        old = self.row('intent')
        new = self.row_for(self.new, 'intent')
        self.assertEqual(old['sourceSha256'], BEFORE_SHA)
        self.assertEqual(old['directSourcePins']['native_review_source_closure.py'], OLD_CLOSURE_SHA)
        self.assertEqual(new['directSourcePins']['native_review_source_closure.py'], CURRENT_CLOSURE_SHA)
        self.assertEqual(new['sourceSha256'], hashlib.sha256(self.provider_path.read_bytes()).hexdigest())
        self.assertEqual({**old['directSourcePins'], 'ssh_fresh_nested_channel.py': new['sourceSha256'],
                          'native_review_source_closure.py': CURRENT_CLOSURE_SHA}, new['directSourcePins'])
        self.assertEqual(self.before, {name: (self.journal/(self.corr+'.'+name+'.json')).read_bytes() for name in self.before})
        self.assertEqual(fd_before, len(os.listdir('/dev/fd')))
        self.assert_legacy_unchanged()

    def test_actual_b1a_cannot_add_an_unobserved_mcp_transition(self):
        self.seed_b1a(old_mcp=True)
        self.transition()
        self.refuse()


MCP_CHECKPOINT74=historical('mcp_server.checkpoint74.py.gz','60634d64854d5be19af49d0204412037eb56fd02e74d586da50d8a0920674893')
TRANSPORT_BEFORE74=historical('ssh_transport.before-reviewed74.py.gz','6e4e9bfcdf620dab84cec100a4990121198fc95b331e0468adf8b79fb2e9e372')
TRANSPORT_CHECKPOINT74=historical('ssh_transport.checkpoint74.py.gz','00bcf88a41031ee11bd356dafc2ceda5ef609fa10471c9f9ed710fa084596db4')
INVENTORY_PROVIDER_BEFORE=historical('ssh_fresh_nested_channel.inventory-provider-before.py.gz','f569a8b606d207b4d5a5623cc580216a595f2826ed93ebca5f2ab38cb1a55663')
CHECKPOINT74_PROVIDER_BEFORE=historical('ssh_fresh_nested_channel.current-provider-before.py.gz','a78e779e21716a9ccf2ab96330f47a0342308d215749f7b90a13f1a8c80b52ed')
DIRECT_BEFORE74=historical('ssh_direct_nested_channel.before-reviewed74.py.gz','99c6ce89cda8431936220be31ea0b6c989b78668d1a155b71cbb98d85c23ce0f')

@unittest.skipUnless(fixture_owner.COORDINATOR_CAPABLE,'POSIX private complete provider required')
class Checkpoint74EndedPopulationTests(unittest.TestCase):
    def setUp(self):
        self.f=ProviderEndedHistoryTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
    def seed_original(self,kind):
        f=self.f
        if kind=='b957':body,mcp,dep,closure=PROVIDER_BEFORE,MCP_BEFORE,DIRECT_BEFORE74,OLD_CLOSURE
        elif kind=='f569':body,mcp,dep,closure=INVENTORY_PROVIDER_BEFORE,MCP_REVIEWED_AFTER,DIRECT_BEFORE74,OLD_CLOSURE
        elif kind=='b1a':body,mcp,dep,closure=B1A_BEFORE,MCP_REVIEWED_AFTER,(CURRENT_PROVIDER_SOURCE.with_name('ssh_direct_nested_channel.py')).read_bytes(),OLD_CLOSURE
        elif kind=='a78':body,mcp,dep,closure=CHECKPOINT74_PROVIDER_BEFORE,MCP_REVIEWED_AFTER,(CURRENT_PROVIDER_SOURCE.with_name('ssh_direct_nested_channel.py')).read_bytes(),CURRENT_CLOSURE
        else:raise AssertionError(kind)
        for name,data in [('ssh_fresh_nested_channel.py',body),('mcp_server.py',mcp),('ssh_transport.py',TRANSPORT_BEFORE74),('ssh_direct_nested_channel.py',dep),('native_review_source_closure.py',closure)]:
            (f.source/name).write_bytes(data)
        f.module=f.load();f.seed()
    def transition(self,*,mcp=MCP_CHECKPOINT74,transport=TRANSPORT_CHECKPOINT74):
        f=self.f
        for name,data in [('ssh_fresh_nested_channel.py',CURRENT_PROVIDER_SOURCE.read_bytes()),('mcp_server.py',mcp),('ssh_transport.py',transport),('ssh_direct_nested_channel.py',CURRENT_PROVIDER_SOURCE.with_name('ssh_direct_nested_channel.py').read_bytes()),('native_review_source_closure.py',CURRENT_CLOSURE)]:
            (f.source/name).write_bytes(data)
        f.module=f.load()
    def admit(self,kind):
        self.seed_original(kind);self.transition();f=self.f;before=len(os.listdir('/dev/fd'))
        value=f.invoke(corr=f.new);self.assertEqual('ready',value['state'])
        self.assertEqual(f.before,{name:(f.journal/(f.corr+'.'+name+'.json')).read_bytes()for name in f.before})
        self.assertEqual(before,len(os.listdir('/dev/fd')));f.assert_legacy_unchanged()
        self.assertEqual(['prepare','status','prepare'],[c[6]for c in f.calls])
    def test_actual_b957_full_population_to_checkpoint74(self):self.admit('b957')
    def test_actual_f569_full_population_to_checkpoint74(self):self.admit('f569')
    def test_actual_b1a_full_population_to_checkpoint74(self):self.admit('b1a')
    def test_actual_a78_full_population_to_checkpoint74(self):self.admit('a78')
    def test_future_mcp_exact_role_bytes_refuse(self):
        self.seed_original('a78');self.transition(mcp=MCP_CHECKPOINT74+b'\n# future unreviewed MCP bytes\n');self.f.refuse()
    def test_future_transport_exact_role_bytes_refuse(self):
        self.seed_original('a78');self.transition(transport=TRANSPORT_CHECKPOINT74+b'\n# future unreviewed transport bytes\n');self.f.refuse()
    def test_missing_ready_refuses_even_with_terminal_digest(self):
        self.seed_original('a78');self.transition();(self.f.journal/(self.f.corr+'.ready.json')).unlink();self.f.refuse()
    def test_unknown_population_role_refuses(self):
        self.seed_original('a78');self.transition();self.f.mutate_intent(lambda v:v['directSourcePins'].__setitem__('private_inventory_lock.py','0'*64));self.f.refuse()
    def test_unobserved_provider_role_combination_refuses(self):
        self.seed_original('a78');self.transition();self.f.mutate_intent(lambda v:v['directSourcePins'].__setitem__('mcp_server.py',hashlib.sha256(MCP_BEFORE).hexdigest()));self.f.refuse()
    def test_unresolved_original_blocks_new_prepare_without_effect(self):
        self.seed_original('a78');self.transition();(self.f.journal/(self.f.corr+'.terminal.json')).unlink();self.f.refuse()
