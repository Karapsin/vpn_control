"""Exact reviewed DIRECT predecessor bridge; real local history, no SSH actors."""
import ast,copy,hashlib,importlib.util,json,os,shutil,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest import mock
import agent_tools
from agent_tools import ssh_direct_nested_channel as direct
CAPABLE=(direct.coordinator_capable() and hasattr(socket,'AF_UNIX') and Path('/dev/fd').is_dir() and shutil.which('ssh') is not None)
if CAPABLE:
    from agent_tools import ssh_fresh_nested_channel as channel
    from agent_tools.tests import test_ssh_direct_nested_channel as fixtures
FIXTURES=Path(__file__).parent/'fixtures'/'ssh_direct_inventory_diagnostic'
FRESH_BEFORE='f569a8b606d207b4d5a5623cc580216a595f2826ed93ebca5f2ab38cb1a55663'
DIRECT_BEFORE='99c6ce89cda8431936220be31ea0b6c989b78668d1a155b71cbb98d85c23ce0f'
DIRECT_AFTER='5b82a0a63fbd2fbc44aa4203c76060ede36236a11cdc8399e186bf7c69cc2ff3'

def load_public(path,name):
    spec=importlib.util.spec_from_file_location('agent_tools._ended_inventory_fixture_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

@unittest.skipUnless(CAPABLE,'POSIX source custody, /dev/fd and inert local Python consumer required')
class EndedInventorySuccessorTests(unittest.TestCase):
    source_before=False
    def setUp(self):
        self.fd_before=len(os.listdir('/dev/fd'))
        self.f=fixtures.DirectChannelTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.old_dir=self.f.root/'old-public-source';self.old_dir.mkdir()
        for name in direct._SOURCE_NAMES:
            source=Path(direct.__file__).with_name(name)
            shutil.copyfile(source,self.old_dir/name)
        for name,fixture,expected in (('ssh_direct_nested_channel.py','direct_before.py',DIRECT_BEFORE),('ssh_fresh_nested_channel.py','fresh_before.py',FRESH_BEFORE)):
            body=(FIXTURES/fixture).read_bytes()
            self.assertEqual(expected,hashlib.sha256(body).hexdigest())
            (self.old_dir/name).write_bytes(body)
        self.old_direct=load_public(self.old_dir/'ssh_direct_nested_channel.py','direct')
        self.old_fresh=load_public(self.old_dir/'ssh_fresh_nested_channel.py','fresh')
    def tearDown(self):
        self.f.doCleanups()
        self.assertEqual(self.fd_before,len(os.listdir('/dev/fd')))
    def old_history(self):
        with mock.patch.object(agent_tools,'ssh_fresh_nested_channel',self.old_fresh),mock.patch.object(agent_tools,'ssh_direct_nested_channel',self.old_direct),mock.patch.object(subprocess,'Popen',side_effect=self.f.consumer):
            ready=self.old_direct.prepare(self.f.root,'archlinux',self.f.corr)
            self.assertEqual('ready',ready['state']);prior=self.f.result
            self.f.result={'state':'ended','correlationId':self.f.corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
            self.assertEqual('ended',self.old_direct.status(self.f.root,'archlinux',self.f.corr)['state'])
        directory=self.f.root/'.rag_index/ssh-direct-nested-channel'
        saved={p.name:p.read_bytes() for p in directory.iterdir() if p.name.startswith(self.f.corr)}
        return directory,saved,prior
    def successor(self,prior):
        corr='c'*32
        self.f.result={**prior,'correlationId':corr,'controlPath':'/tmp/vpn-channel-'+corr+'/m'}
        with mock.patch.object(subprocess,'Popen',side_effect=self.f.consumer):return direct.prepare(self.f.root,'archlinux',corr)
    def current_intent(self,previous):
        with direct.Guard(self.f.root) as guard:
            current={**previous,'sourceSha256':channel._source(),'directSourcePins':dict(guard.source_pins)}
            guard.guard()
        return current
    def matcher(self):
        if not self.source_before:return channel._ended_direct_intent_matches
        raw=(FIXTURES/'fresh_before.py').read_text();tree=ast.parse(raw)
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_ended_direct_intent_matches')
        namespace=dict(vars(channel))
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<authentic before matcher AST>','exec'),namespace)
        return namespace['_ended_direct_intent_matches']
    def test_authentic_matcher_exact_predecessor_and_current_tuple(self):
        directory,saved,prior=self.old_history()
        previous=json.loads(saved[self.f.corr+'.intent.json']);current=self.current_intent(previous)
        self.assertTrue(self.matcher()(previous,current),'exact prior DIRECT pin was stranded by callback-only source update')
    def test_real_existing_ended_history_preparation_preserves_all_prior_bytes(self):
        directory,saved,prior=self.old_history()
        self.assertEqual('ready',self.successor(prior)['state'])
        self.assertEqual(saved,{p.name:p.read_bytes() for p in directory.iterdir() if p.name in saved})
        self.assertEqual(2,sum(row[6]=='prepare' for row in self.f.calls))
    def test_altered_missing_other_pin_and_current_image_refuse(self):
        directory,saved,prior=self.old_history();previous=json.loads(saved[self.f.corr+'.intent.json']);current=self.current_intent(previous)
        for target,key,value in (('old','ssh_direct_nested_channel.py','0'*64),('new','ssh_direct_nested_channel.py','0'*64),('old','ssh_transport.py','0'*64),('new','ssh_transport.py','0'*64)):
            left=copy.deepcopy(previous);right=copy.deepcopy(current)
            (left if target=='old' else right)['directSourcePins'][key]=value
            self.assertFalse(channel._ended_direct_intent_matches(left,right))
        missing=copy.deepcopy(previous);missing['directSourcePins'].pop('ssh_direct_nested_channel.py')
        self.assertFalse(channel._ended_direct_intent_matches(missing,current))
        foreign=copy.deepcopy(previous);foreign['sourceSha256']='0'*64;foreign['directSourcePins']['ssh_fresh_nested_channel.py']='0'*64
        self.assertFalse(channel._ended_direct_intent_matches(foreign,current))
        with mock.patch.object(direct,'__file__',str(self.old_dir/'ssh_direct_nested_channel.py')):
            self.assertFalse(channel._ended_direct_intent_matches(previous,current))
    def test_existing_reviewed_provider_mcp_pair_remains_finite(self):
        directory,saved,prior=self.old_history();previous=json.loads(saved[self.f.corr+'.intent.json']);current=self.current_intent(previous)
        previous['sourceSha256']=channel._REVIEWED_ENDED_DIRECT_PROVIDER
        previous['directSourcePins']['ssh_fresh_nested_channel.py']=previous['sourceSha256']
        previous['directSourcePins']['mcp_server.py']='6ca7b4050ee5ca6977ff3948ad22b78350d49007c557ba603b9ab2a6558dc014'
        current['directSourcePins']['mcp_server.py']='5707593229d5fa3c331998a0f6bbc2bae1ca4dff3a94fd4f5f5c8064e07a14d7'
        self.assertTrue(channel._ended_direct_intent_matches(previous,current))
        previous['directSourcePins']['mcp_server.py']='0'*64
        self.assertFalse(channel._ended_direct_intent_matches(previous,current))
    def test_incomplete_or_nonended_history_never_starts_second_consumer(self):
        for failure in ('ready_absent','terminal_unknown'):
            with self.subTest(failure=failure):
                if failure=='terminal_unknown':
                    # The first subcase already consumed no new correlation;
                    # restore exact prior fixture bodies before the next refusal.
                    for name,body in saved.items():(directory/name).write_bytes(body)
                else:directory,saved,prior=self.old_history()
                if failure=='ready_absent':(directory/(self.f.corr+'.ready.json')).unlink()
                else:
                    path=directory/(self.f.corr+'.terminal.json');record=json.loads(path.read_bytes());record['state']='unknown';path.write_text(json.dumps(record))
                calls=len(self.f.calls);self.assertEqual('unknown',self.successor(prior)['state']);self.assertEqual(calls,len(self.f.calls))

if __name__=='__main__':unittest.main()
