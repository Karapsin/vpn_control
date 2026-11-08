"""The responsive document cases over the real cases module, the real Child and real pipes.

Local only: the CLI, document and fixture protocols and Popen are declared peers. No
product, socket, listener, Win32 call, process termination, network or native effect.
"""
from __future__ import annotations
import base64,hashlib,io,json,os,sys,tempfile,threading,time,types,unittest,uuid
from pathlib import Path
import subprocess as real_subprocess
from unittest import mock

from agent_tools import windows_document_client as documents
from agent_tools import windows_document_gated_https_fixture as gated
from agent_tools import windows_document_responsive_cases as cases
from agent_tools import windows_ordinary_process_owner as ordinary


def gen(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def sha(b):return hashlib.sha256(b).hexdigest()


class Parked(Exception):pass
class EffectFault(Exception):pass
ACTIVE=None
class ProcessPeer:
    """Explicit CreateProcess/native handle boundary. Real os.pipe pump edges."""
    def __init__(self,argv,**kw):
        self.world=ACTIVE;self.argv=tuple(argv);self.pid=110000+len(self.world.processes);self.environment=dict(kw.get('env') or {})
        self._handle=self.pid+100000;self.code=None;self.attempts=0;self.closed=False
        self.world.processes.append(self)
        self.stdout,self._stdout=self.pipe();self.stderr,self._stderr=self.pipe()
        self.world.spawn(self)
    @staticmethod
    def pipe():
        r,w=os.pipe();return os.fdopen(r,'rb',buffering=0),w
    def poll(self):return self.code
    def finish(self,code=0,stdout=b'',stderr=b''):
        if self.closed:return
        if stdout:os.write(self._stdout,stdout)
        if stderr:os.write(self._stderr,stderr)
        os.close(self._stdout);os.close(self._stderr);self.closed=True;self.code=code
    def terminate(self):
        self.attempts+=1
        child=next(c for c in self.world.owner.children if c.process is self)
        state=self.world.owner.responsive_client_effects[child.ordinal]
        record=json.loads((self.world.root/f'child-{child.ordinal:04d}.terminate-client.intent.json').read_bytes())
        assert state['attempts']==1 and state['stage']=='effect-entered'
        assert record['clientPid']==self.pid and record['clientArgv']==list(self.argv)
        assert record['ownerWorkId']==state['operationId'] and record['replayAllowed']is False
        self.world.effects.append((self,record))
        if self.world.effect_fault:raise EffectFault('declared-after-effect-unknown')
        self.finish(-15)

PEER_SUBPROCESS=types.SimpleNamespace(Popen=ProcessPeer,list2cmdline=real_subprocess.list2cmdline,
    DEVNULL=-3,PIPE=-1,CREATE_NEW_CONSOLE=16,CREATE_NO_WINDOW=0x08000000)

class FilePin:
    def __init__(self,path):
        self.path=Path(path);self.fd=self.path.open('rb');self.opening=gen(os.fstat(self.fd.fileno()))
        self.record={'path':str(self.path),'sha256':sha(self.path.read_bytes())};self.current()
    def current(self):
        assert gen(os.fstat(self.fd.fileno()))==self.opening==gen(self.path.stat())
    def digest(self,return_bytes=False,maximum=8*1024*1024):
        self.current();self.fd.seek(0);raw=self.fd.read(maximum+1);assert len(raw)<=maximum
        assert sha(raw)==self.record['sha256'];self.current();return raw if return_bytes else sha(raw)

class DataPeer:
    def __init__(self,owner,path,expected=None,directory=False):
        self.path=Path(path);self.directory=directory;self.expected=expected;self.handle=1
        self.opening=gen(self.path.stat());owner.data.append(self);self.current()
    def current(self):
        now=gen(self.path.stat())
        # Native directory helper admits stable structure, not volatile children.
        assert (now[:5]==self.opening[:5] if self.directory else now==self.opening), (str(self.path), self.directory, self.opening, now)
        if not self.directory:assert sha(self.path.read_bytes())==self.expected

class RuntimePeer:
    OwnedData=DataPeer
    def __init__(self,world):self.world=world
    def data_guard(self,owner):
        owner.guard()
        for p in owner.data:p.current()
    @staticmethod
    def scoped_trust_options(path):return '"-Djavax.net.ssl.trustStore='+path+'" -Djavax.net.ssl.trustStorePassword=changeit'
    def publish(self,owner,path,value):
        assert path.parent in (owner.root,owner.root/'fixture')
        raw=cases.encoded(value);assert len(raw)<=32768
        with path.open('xb',buffering=0)as f:f.write(raw);os.fsync(f.fileno())
        DataPeer(owner,path,sha(raw))
        if path.name.endswith('-release.json'):
            phase=path.name[:-13];self.world.release(phase)
        if path.name=='stop.json':
            self.world.fixture_process.finish(0,cases.encoded({'kind':'owned-work-fixture-terminal',
                'operationId':owner.operation,'onlyOriginalObjectsStopped':True}))
        return path
    def read_ready(self,owner,child,path,operation):
        raw=path.read_bytes();DataPeer(owner,path,sha(raw));v=json.loads(raw)
        assert v['pid']==child.pid and v['operationId']==operation;return v

class OwnerPeer:
    def __init__(self,w):
        self.world=w;self.root=w.root;self.children=[];self.environment={};self.raw_limit=1024*1024
        self.operation=str(uuid.uuid4());self.events=[];self.data=[];self.by_path={}
        self.request={'cliPath':'C:\\owned\\vpn-control.exe','workspace':str(w.root/'workspace'),
            'pythonRuntime':{'interpreterPath':'C:\\owned\\python.exe'},
            'documentAcceptance':{'contexts':[str(uuid.uuid4())for _ in range(52)]}}
        self.native=types.SimpleNamespace(birth=lambda handle:str(handle*100))
    def guard(self):
        for p in self.by_path.values():p.current()
    def event(self,kind,value):self.events.append({'kind':kind,'value':value})
    def park(self,reason,error=None):self.parked=(reason,error);raise Parked(reason) from error if isinstance(error,BaseException) else None
    def child(self,label,argv):return ordinary.Child(self,label,argv)

class World:
    def __init__(self,root,full=False):
        global ACTIVE
        self.root=root;self.processes=[];self.effects=[];self.effect_fault=False
        self.owner=OwnerPeer(self);ACTIVE=self;self.full=full;self.controller=str(uuid.uuid4())
        self.operations={};self.subscriptions={};self.settings={'refresh.policy':'every-hour','refresh.find-best-after-refresh':True}
        self.requests=0;self.revision=0;self.trace=[];self.runtime=RuntimePeer(self)
    def __enter__(self):return self
    def __exit__(self,*_):
        # Test teardown ONLY: synthetic peers own these local anonymous pipes.
        # No OS child was ever created, and no production cleanup method is used.
        for p in self.processes:p.finish(0)
        for c in self.owner.children:
            for t in c.threads.values():t.join(2);assert not t.is_alive()
            for stream in c.streams.values():
                if not stream.closed:stream.close()
            for stream in (c.process.stdout,c.process.stderr):
                if not stream.closed:stream.close()
        for p in self.owner.by_path.values():p.fd.close()
        for state in getattr(self.owner,'responsive_client_effects',{}).values():
            if state['stream']and not state['stream'].closed:state['stream'].close()
    def emit(self,p,body,code=0):p.finish(code,cases.encoded(body))
    def envelope(self,code='OK',data=None,final=True,operation=None,request=None):
        self.requests+=1
        return {'schemaVersion':1,'controllerId':self.controller,'requestId':request or 'observed-'+str(self.requests),
            'configurationRevision':self.revision,'ok':code in ('OK','ACCEPTED'),'code':code,
            'final':final,'operationId':operation,'data':data or {},'warnings':[]}
    def summary(self,o):return {k:o[k]for k in ('id','requestId','operation','phase','final','cancellable')}
    def status(self,o):
        if o['final']:return self.envelope(o['code'],o['data'],True,o['id'])
        return self.envelope('ACCEPTED',self.summary(o),False,o['id'])
    def spawn(self,p):
        argv=p.argv
        if '-I'in argv:
            config=json.loads(Path(argv[-1]).read_bytes());self.config=config;self.fixture_process=p
            self.ready={'schemaVersion':1,'operationId':self.owner.operation,'pid':p.pid,'httpsHost':'localhost',
                'httpsPort':12345,'advertisedSocksHost':'127.0.0.1','advertisedSocksPort':12346,
                'certificateSha256':sha(Path(config['certificatePath']).read_bytes()),
                'workUrls':{phase:f'https://localhost:12345/subscription/{phase}/{self.owner.operation}'for phase in cases.PHASES}}
            Path(config['readyFile']).write_bytes(cases.encoded(self.ready));return
        if argv[-1]=='serve':return
        if 'JAVA_TOOL_OPTIONS' in p.environment:
            # Every JVM the product starts reports inherited options on stderr: only serve may see them.
            p.finish(0,cases.encoded(self.envelope()),('Picked up JAVA_TOOL_OPTIONS: '+p.environment['JAVA_TOOL_OPTIONS']+'\n').encode());return
        if not self.full:return
        tail=list(argv[argv.index('--controller-id')+2:]);self.trace.append(tuple(tail))
        if '--async'in tail:tail.remove('--async')
        if tail[0]=='--if-revision':assert int(tail[1])==self.revision;tail=tail[2:]
        group=tail[:2]
        if tail==['status']:body=self.envelope(data={'runtimeRunning':False})
        elif group==['source','show']:body=self.envelope(data={'mode':'subscription'})  # A fresh workspace.
        elif group==['settings','show']:body=self.envelope(data={tail[2]:self.settings[tail[2]]})
        elif group==['settings','set']:
            self.settings[tail[2]]= {'true':True,'false':False}.get(tail[3],tail[3]);self.revision+=1;body=self.envelope()
        elif group==['subscriptions','list']:body=self.envelope(data={'subscriptions':list(self.subscriptions.values())})
        elif group==['subscriptions','add']:
            sid='sub-'+str(len(self.subscriptions));url=tail[tail.index('--source')+1]
            self.subscriptions[sid]={'id':sid,'source':url,'cachedLocations':0};self.revision+=1;body=self.envelope(data={'id':sid})
        elif group==['subscriptions','show']:body=self.envelope(data=self.subscriptions[tail[2]])
        elif group==['subscriptions','delete']:
            self.subscriptions.pop(tail[2]);self.revision+=1;body=self.envelope()
        elif group==['subscriptions','refresh']:
            sid=tail[2];phase=next(x for x in cases.PHASES if '/'+x+'/'in self.subscriptions[sid]['source'])
            oid='work-'+phase;o={'id':oid,'requestId':'original-'+phase,'operation':'subscriptions.refresh',
                'phase':'running','final':False,'cancellable':True,'code':None,'data':{},'phaseLabel':phase,'sid':sid}
            self.operations[oid]=o;self.write_event(phase,'entered',status=200)
            if '--async'in argv:self.emit(p,self.envelope('ACCEPTED',final=False,operation=oid,request=o['requestId']))
            return
        elif group==['operations','list']:body=self.envelope(data={'operations':[self.summary(o)for o in self.operations.values()]})
        elif group==['operations','status']:body=self.status(self.operations[tail[2]])
        elif group==['operations','wait']:
            o=self.operations[tail[2]]
            # The CLI's local timeout has no owner snapshot (DesktopCliJson.desktopCliJsonFailure).
            body=self.status(o)if o['final']else dict(self.envelope('TIMEOUT',{},False,o['id']),controllerId=None,
                configurationRevision=0,warnings=['OWNER_METADATA_UNAVAILABLE'])
        elif group==['operations','cancel']:
            o=self.operations[tail[2]];o['phase']='cancelling'
            # Actual HeadlessSession cancellation command: OK/default final true,
            # null operationId, operation summary in data. Not work completion.
            body=self.envelope(data=self.summary(o))
        else:raise AssertionError(('unexpected-public-command',argv,tail))
        self.emit(p,body,{'TIMEOUT':2,'CANCELLED':130}.get(body['code'],0))
    def write_event(self,phase,suffix,**extra):
        path=Path(self.config['readyFile']).parent/f'{phase}-{suffix}.json'
        with path.open('xb')as f:
            f.write(cases.encoded({'schemaVersion':1,'operationId':self.owner.operation,'phase':phase,
                'pid':self.fixture_process.pid,'requestOrdinal':1,'path':f'/subscription/{phase}/{self.owner.operation}',**extra}))
            f.flush();os.fsync(f.fileno())
    def release(self,phase):
        o=self.operations['work-'+phase];cancel=o['phase']=='cancelling'
        o.update(phase='cancelled'if cancel else'succeeded',final=True,cancellable=False,
            code='CANCELLED'if cancel else'OK',data={})
        if not cancel:self.subscriptions[o['sid']]['cachedLocations']=1  # The fixture's one owned location.
        self.write_event(phase,'ended',result='response-written')

class DocumentPeer(documents.Client):
    def __init__(self,owner):
        self.owner=owner.world.controller;self.guard=owner.guard;self.event=owner.event
        self.transfers={};self.submissions={};self.entries={};self.actions=[];self.sequence=0
    def exchange(self,payload,context=None):
        assert payload.startswith(documents.TRANSFER)
        envelope=documents.load(payload[len(documents.TRANSFER):]);command=documents.load(envelope['command'])
        assert envelope['owner']==self.owner and envelope['kind']=='command'
        ctx=envelope['context'];act=command['action'];self.actions.append((ctx,act))
        if act=='begin':
            assert command['requestId']==ctx
            if ctx not in self.entries:
                self.sequence+=1;self.entries[ctx]={'manifest':{'id':str(uuid.uuid4()),'byteCount':0,'sha256':None,'chunkBytes':65536},'data':bytearray()}
            return json.dumps(self.entries[ctx]['manifest'])
        entry=self.entries[ctx];m=entry['manifest'];assert command['id']==m['id']
        if act=='append':
            raw=base64.b64decode(command['bytes']);assert command['offset']==len(entry['data'])and m['sha256']is None
            entry['data'].extend(raw);m['byteCount']=len(entry['data'])
        elif act=='seal':
            assert command['byteCount']==len(entry['data'])and command['sha256']==sha(entry['data']);m['sha256']=command['sha256']
        elif act=='discard':self.entries.pop(ctx);return'DISCARDED'
        else:raise AssertionError(('unsupported-input-transfer-action',act))
        return json.dumps(m)

class Qualification(unittest.TestCase):
    def setUp(self):
        patcher=mock.patch.object(ordinary,'subprocess',PEER_SUBPROCESS);patcher.start();self.addCleanup(patcher.stop)

    def world(self,full=False):
        temporary=tempfile.TemporaryDirectory(prefix='owned-responsive-');self.addCleanup(temporary.cleanup)
        w=World(Path(temporary.name),full);self.addCleanup(w.__exit__);return w
    def setup_effect(self,w):
        owner=w.owner;workspace=owner.request['workspace'];serve=owner.child('serve',[owner.request['cliPath'],'--state-dir',workspace,'serve'])
        client=owner.child('original-sync',[owner.request['cliPath'],'--state-dir',workspace,'--json','--controller-id',w.controller,'subscriptions','refresh','sub-owned'])
        status=owner.child('observed-status',[owner.request['cliPath'],'--state-dir',workspace,'--json','--controller-id',w.controller,'operations','status','work-owned'])
        body=w.envelope('ACCEPTED',{'id':'work-owned','requestId':'request-owned','operation':'subscriptions.refresh','phase':'running','cancellable':True},False,'work-owned')
        status.process.finish(0,cases.encoded(body));cases.wait_original(owner,status,'qualification-status')
        return owner,workspace,serve,client,status
    def prepare_inputs(self,w,contexts=None):
        o=w.owner;files={}
        for role in ('fixtureWorkerPath','socksSourcePath','httpsSourcePath','certificatePath','privateKeyPath','trustStorePath','largeRoutingInputPath'):
            path=w.root/(role+'.input');path.write_bytes(b'\n'*(10*1024*1024+1)if role=='largeRoutingInputPath'else(role+'-declared').encode())
            pin=FilePin(path);o.by_path[str(path).casefold()]=pin;files[role]=str(path)
        return {'schemaVersion':1,**files,'contexts':contexts or[str(uuid.uuid4()),str(uuid.uuid4())]}
    def test_one_original_effect_and_duplicate_refusal(self):
        w=self.world();owner,workspace,serve,client,status=self.setup_effect(w)
        sibling=owner.child('unrelated-sibling',[owner.request['cliPath'],'untouched-sibling'])
        state=cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
        self.assertEqual(state['attempts'],1);self.assertEqual(len(w.effects),1)
        self.assertIs(w.effects[0][0],client.process);self.assertIsNone(serve.process.poll());self.assertIsNone(sibling.process.poll())
        with self.assertRaises(AssertionError):cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
        self.assertEqual(client.process.attempts,1)
    def test_wrong_argv_refuses_before_effect(self):
        w=self.world();owner,workspace,serve,client,status=self.setup_effect(w);client.argv=client.argv+('--async',)
        with self.assertRaises(AssertionError):cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
        self.assertEqual(w.effects,[]);self.assertFalse(hasattr(owner,'responsive_client_effects'))
    def test_birth_or_serve_disjointness_refuses_before_effect(self):
        for fault in ('birth','same-pid'):
            with self.subTest(fault=fault):
                w=self.world();owner,workspace,serve,client,status=self.setup_effect(w)
                if fault=='birth':client.birth='wrong'
                else:client.pid=serve.pid
                with self.assertRaises(AssertionError):cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
                self.assertEqual(w.effects,[])
    def test_uncertain_effect_retains_primary_intent_and_never_replays(self):
        w=self.world();owner,workspace,serve,client,status=self.setup_effect(w);w.effect_fault=True
        with self.assertRaises(Parked):cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
        state=owner.responsive_client_effects[client.ordinal]
        self.assertIsInstance(state['primary'],EffectFault);self.assertFalse(state['stream'].closed);self.assertEqual(state['attempts'],1)
        with self.assertRaises(AssertionError):cases.terminate_original_sync_refresh(owner,client,serve,workspace,w.controller,'sub-owned',status)
        self.assertEqual(client.process.attempts,1);self.assertIsNone(serve.process.poll())
    def test_complete_two_public_protocol_flows_original_child_and_document(self):
        w=self.world(True);o=w.owner;inputs=self.prepare_inputs(w)
        workspace=Path(o.request['workspace'])
        lease=cases.prepare_before_serve(o,workspace,inputs,w.runtime)
        serve=o.child('serve',[o.request['cliPath'],'--state-dir',str(workspace),'serve']);workspace.mkdir()
        self.assertIn('JAVA_TOOL_OPTIONS',serve.process.environment,'the scoped trust options reach serve')
        o.environment.pop('JAVA_TOOL_OPTIONS')  # What Owner.run does right after starting serve.
        cases.after_original_serve_started(o,lease,serve)
        client=DocumentPeer(o);result=cases.run(o,workspace,w.controller,client,documents,lease)
        self.assertEqual(len(result['observations']),2);self.assertFalse(result['full64Complete']);self.assertFalse(result['visual58Complete'])
        self.assertEqual(len(w.effects),1);self.assertEqual(w.effects[0][1]['ownerWorkId'],'work-client-loss')
        self.assertEqual(w.operations['work-responsive']['code'],'CANCELLED');self.assertEqual(w.operations['work-client-loss']['code'],'OK')
        self.assertEqual(w.subscriptions,{});self.assertEqual(w.settings,{'refresh.policy':'every-hour','refresh.find-best-after-refresh':True})
        self.assertEqual(client.entries,{})
        for context in inputs['contexts']:
            actions=[a for ctx,a in client.actions if ctx==context]
            self.assertEqual(actions.count('begin'),3);self.assertEqual(actions[-1],'discard');self.assertNotIn('read',actions)
        cases.stop_after_known_cases(o,lease);self.assertTrue(lease.closed);self.assertEqual(lease.child.terminal['exitCode'],0)
        self.assertIsNone(serve.process.poll())  # original owner stays live until its caller's explicit terminal path.
    def test_reserved_context_cannot_launch_fixture(self):
        w=self.world(True);o=w.owner
        inputs=self.prepare_inputs(w,[o.request['documentAcceptance']['contexts'][0],str(uuid.uuid4())])
        with self.assertRaises(AssertionError):cases.prepare_before_serve(o,Path(o.request['workspace']),inputs,w.runtime)
        self.assertEqual(o.children,[])
    def test_actual_retained_context_cannot_enter_work(self):
        w=self.world();o=w.owner;contexts=[str(uuid.uuid4()),str(uuid.uuid4())]
        client=types.SimpleNamespace(owner=w.controller,transfers={contexts[0]:{'retained':'original'}})
        with self.assertRaisesRegex(AssertionError,'actual-retained-transfers'):cases.fresh_contexts(o,contexts,client)

    def test_a_child_after_serve_that_inherited_the_trust_options_is_refused(self):
        w=self.world(True);o=w.owner;inputs=self.prepare_inputs(w)
        workspace=Path(o.request['workspace'])
        lease=cases.prepare_before_serve(o,workspace,inputs,w.runtime)
        serve=o.child('serve',[o.request['cliPath'],'--state-dir',str(workspace),'serve']);workspace.mkdir()
        cases.after_original_serve_started(o,lease,serve)  # Without the owner's removal the options leak to every later JVM.
        with self.assertRaises(Parked):cases.run(o,workspace,w.controller,DocumentPeer(o),documents,lease)
        self.assertEqual('document-responsive-longwork-unqualified-originals-retained',o.parked[0])

    def test_the_owner_removes_the_trust_options_right_after_serve(self):
        source=Path(ordinary.__file__).read_text()
        start=source.index('        serve = self.child("serve", [launcher, "--state-dir", str(workspace), "serve"])')
        self.assertIn('self.environment.pop("JAVA_TOOL_OPTIONS", None)',source[start:start+400])


class GateTests(unittest.TestCase):
    """The gated fixture's handler flow with only IO and the clock substituted."""
    def server(self,root):
        return types.SimpleNamespace(work_lock=threading.Lock(),work_states={},subscription_body='vpn://owned',work_operation=str(uuid.uuid4()),work_root=root)

    def test_heartbeats_until_the_exact_release_then_one_chunked_body(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);server=self.server(root);written=[];beats=[]
            def pause(seconds):
                beats.append(seconds)
                if len(beats)==3:gated.publish(root/'responsive-release.json',{'schemaVersion':1,'operationId':server.work_operation,
                                                                              'phase':'responsive','action':'release-original-request'})
            gated.gate_request(server,'responsive',lambda:written.append(b'HEADERS'),written.append,lambda:None,pause=pause,clock=lambda:0)
            self.assertEqual([b'HEADERS',b'1\r\n\n\r\n',b'1\r\n\n\r\n',b'1\r\n\n\r\n',b'b\r\nvpn://owned\r\n0\r\n\r\n'],written)
            ended=json.loads((root/'responsive-ended.json').read_bytes())
            self.assertEqual(('response-written',3),(ended['result'],ended['heartbeats']))
            with self.assertRaises(ValueError):
                gated.gate_request(server,'responsive',lambda:None,written.append,lambda:None,pause=pause,clock=lambda:0)

    def test_a_release_of_another_operation_is_refused_and_writes_no_body(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);server=self.server(root);written=[]
            gated.publish(root/'client-loss-release.json',{'schemaVersion':1,'operationId':str(uuid.uuid4()),'phase':'client-loss','action':'release-original-request'})
            with self.assertRaisesRegex(ValueError,'exact-work-release'):
                gated.gate_request(server,'client-loss',lambda:None,written.append,lambda:None,pause=lambda s:None,clock=lambda:0)
            self.assertEqual([],written)
            self.assertFalse((root/'client-loss-ended.json').exists())

    def test_the_gate_outlasts_the_product_client_and_reads_as_binary(self):
        self.assertEqual(600,gated.GATE_SECONDS)
        self.assertEqual(5,gated.TLS_HANDSHAKE_SECONDS)
        source=Path(gated.__file__).read_text()
        self.assertEqual(2,source.count("getattr(os,'O_BINARY',0)"))
        self.assertIn('ConnectionAbortedError,ssl.SSLError',source)


if __name__=='__main__':unittest.main()
