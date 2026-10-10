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
CURRENT_PROVIDER_SOURCE=Path(channel.__file__) if fixture_owner.COORDINATOR_CAPABLE else None
CURRENT_MCP_SOURCE=CURRENT_PROVIDER_SOURCE.with_name('mcp_server.py') if CURRENT_PROVIDER_SOURCE else None
def historical(name,expected):
    body=gzip.decompress((FIXTURES/name).read_bytes())
    if hashlib.sha256(body).hexdigest()!=expected:raise ValueError('historical_fixture_digest')
    return body
PROVIDER_BEFORE=historical('ssh_fresh_nested_channel.before.py.gz','b957d4b6bf37ca0c603f09f7df757284a56f042706533159fb5427c1b89fdafc')
MCP_BEFORE=historical('mcp_server.before.py.gz','6ca7b4050ee5ca6977ff3948ad22b78350d49007c557ba603b9ab2a6558dc014')

@unittest.skipUnless(fixture_owner.COORDINATOR_CAPABLE,'POSIX private TempFS provider required')
class ProviderEndedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.owner=fixture_owner.DirectChannelTests('runTest');self.owner.setUp()
        self.addCleanup(self.owner.doCleanups)
        self.root=self.owner.root;self.corr=self.owner.corr;self.calls=self.owner.calls
        self.source=self.root/'owned-provider-source';self.source.mkdir(mode=0o700)
        for name in direct._SOURCE_NAMES:
            shutil.copyfile(Path(direct.__file__).with_name(name),self.source/name)
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
    def invoke(self,*args,**kwargs):return self.owner.invoke(*args,**kwargs)
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
    def transition(self,*,equal=False):
        if not equal:(self.source/'mcp_server.py').write_bytes(CURRENT_MCP_SOURCE.read_bytes())
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

