"""Two public subscription-work cases under the ordinary retained Owner.

No import-time effect. No new product API/transport or SSH interruption. Reached only
through the planner's closed responsiveWork input and the owner's document action.
The work fixture is the owner's own child. While no refresh of the product is in
flight with it, a failure is known: the fixture is ended by one termination of its
original handle and awaited. Only an open refresh keeps every original for a park.
"""
from __future__ import annotations
import base64,hashlib,json,os,stat,time,uuid
from pathlib import Path

CAP=1024*1024
NOTICE_SECONDS=30
TERMINATE_SECONDS=15
PHASES=('responsive','client-loss')
# How long the work fixture's ready file is awaited. It is a bound, not a measurement of this fixture: the proxy
# rows' fixture, which makes the same two listeners, was ready 1.2 to 2.0 s after its start on three native runs.
READY_SECONDS=30
FIXTURE_LABEL='owned-document-work-fixture'
# The fixture names each start step on its stdout before entering it (windows_document_gated_https_fixture.STEPS).
FIXTURE_STEPS=('input','sources','tls-context','https-listen','relay-listen','listening','certificate-digest','ready-create','ready-rename')
CODE_CHARACTERS=frozenset('abcdefghijklmnopqrstuvwxyz0123456789:_-')
NAME_CHARACTERS=frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_')

def need(ok,reason):
    if not ok:raise AssertionError(reason)
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def unchanged(opened,held,named,count,reason):
    """Change is the handle's own; the name gives only its type and identity, each refusal its check and field.

    A Windows path stat can come from the directory entry, whose size and times may lag the
    handle's while another handle is open; the volume and file id it names never lag."""
    need(stat.S_ISREG(named.st_mode) and not getattr(named,'st_file_attributes',0)&0x400,reason+':name-type')
    for field in ('dev','ino'):need(getattr(named,'st_'+field)==getattr(held,'st_'+field),reason+':identity-'+field)
    for field in ('dev','ino','mode','uid','gid','nlink','size','mtime_ns','ctime_ns'):
        need(getattr(opened,'st_'+field)==getattr(held,'st_'+field),reason+':handle-'+field)
    need(count==held.st_size,reason+':count-size')

def fresh_contexts(owner,contexts,client=None):
    reserved=owner.request['documentAcceptance']['contexts']
    need(type(reserved)is list and len(reserved)==52 and len(set(reserved))==52
         and all(type(c)is str and str(uuid.UUID(c))==c for c in reserved),'existing-fifty-two-reserved-document-contexts')
    need(not set(contexts).intersection(reserved) and owner.operation not in contexts,
         'responsive-contexts-disjoint-from-reserved-document-contexts')
    if client is not None:
        need(client.owner not in contexts and not set(contexts).intersection(client.transfers),
             'responsive-contexts-disjoint-from-actual-retained-transfers')

def raw_child(owner,child):
    need(child.owner is owner and owner.children[child.ordinal] is child and child.terminal is not None,
         'same-original-known-child')
    t=child.terminal
    need(t['pid']==child.pid and t['birthFileTimeUtc']==child.birth and t['eof']=={'stdout':True,'stderr':True}
         and t['sourceClosing']is True and t['originalHandleRetained']is True,'original-child-terminal-native-eof')
    values={}
    for name in ('stdout','stderr'):
        path=owner.root/f'child-{child.ordinal:04d}.{name}.raw'
        with path.open('rb')as f:
            before=os.fstat(f.fileno());need(before.st_size==t['counts'][name]<=CAP,'public-observation-bound')
            value=f.read(CAP+1);after=os.fstat(f.fileno())
        unchanged(before,after,path.stat(follow_symlinks=False),len(value),'original-public-raw-join')
        need(len(value)==t['counts'][name] and sha(value)==t['sha256'][name],'original-public-raw-join:terminal')
        values[name]=value
    owner.guard();return values

def wait_original(owner,child,phase,seconds=NOTICE_SECONDS):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        t=child.observe()
        if t is not None:return t
        time.sleep(.05)
    owner.park(phase,{'child':child.ordinal,'pid':child.pid,'birthFileTimeUtc':child.birth,'replayAllowed':False})
    raise AssertionError('park-returned')

def result_child(owner,child,identity,codes=('OK',),exits=(0,),final=True,operation=None):
    raw=raw_child(owner,child);body=json.loads(raw['stdout'].decode('utf-8','strict'))
    # A wait that times out may lose the owner's metadata (agent_docs/cli.md): then only the
    # documented warning, a null controllerId and the same operation identify it.
    unattributed=(operation is not None and body.get('controllerId') is None and body.get('operationId')==operation
                  and 'OWNER_METADATA_UNAVAILABLE' in [row.get('code') if type(row) is dict else row for row in body.get('warnings') or []])
    need(raw['stderr']==b'' and child.terminal['exitCode']in exits and body['schemaVersion']==1
         and (body['controllerId']==identity or unattributed) and body['code']in codes
         and (type(body['final'])is bool if final is None else body['final']is final)
         and body['ok']is(child.terminal['exitCode']==0),'same-owner-public-envelope')
    return body

def call(owner,workspace,identity,*tail,codes=('OK',),exits=(0,),final=True,operation=None):
    owner.guard();child=owner.child('responsive-public-'+tail[0],[owner.request['cliPath'],'--state-dir',str(workspace),
        '--json','--controller-id',identity,*tail])
    wait_original(owner,child,'responsive-public-observation-unknown')
    return result_child(owner,child,identity,codes,exits,final,operation),child

def assert_serve(owner,serve):
    owner.guard();need(serve.owner is owner and owner.children[serve.ordinal]is serve
        and serve.process.poll()is None and owner.native.birth(int(serve.process._handle))==serve.birth,
        'same-original-live-serve')

def terminate_original_sync_refresh(owner,client,serve,workspace,identity,subscription_id,status_child):
    """Exactly ONE original Popen termination; never process-tree/job/group kill.

    The operation selector is a retained known public status Child, not a caller
    boolean or bare ID. A failed effect/EOF retains this same Owner and latch.
    """
    expected=(owner.request['cliPath'],'--state-dir',str(workspace),'--json','--controller-id',identity,
              'subscriptions','refresh',subscription_id)
    need(client.owner is owner and owner.children[client.ordinal]is client and tuple(client.argv)==expected,
         'only-exact-original-synchronous-refresh-client')
    status=result_child(owner,status_child,identity,('ACCEPTED',),(0,),False)
    operation=status['operationId'];detail=status['data']
    need(tuple(status_child.argv)==(owner.request['cliPath'],'--state-dir',str(workspace),'--json','--controller-id',identity,
         'operations','status',operation) and detail['id']==operation and detail['operation']=='subscriptions.refresh'
         and detail['phase']=='running' and detail['cancellable']is True and detail['requestId'],
         'actual-running-original-work-status')
    assert_serve(owner,serve)
    need(client.process is not None and client.process.poll()is None and client.terminal is None
         and owner.native.birth(int(client.process._handle))==client.birth,
         'same-original-live-client-handle-birth')
    protected={os.getpid(),serve.pid}
    for child in owner.children:
        if child is not client and child.process is not None and child.process.poll()is None:
            protected.add(child.pid)
            need(int(child.process._handle)!=int(client.process._handle),'client-handle-overlaps-sibling')
    need(client.pid not in protected and client.pid>0,'client-role-disjointness')
    if not hasattr(owner,'responsive_client_effects'):owner.responsive_client_effects={}
    need(client.ordinal not in owner.responsive_client_effects,'original-client-effect-already-consumed')
    state={'stage':'intent-writing','originalChild':client,'statusChild':status_child,'stream':None,'attempts':0,
           'operationId':operation,'originalRequestId':detail['requestId'],'primary':None}
    owner.responsive_client_effects[client.ordinal]=state
    path=owner.root/f'child-{client.ordinal:04d}.terminate-client.intent.json'
    try:
        state['stream']=path.open('xb',buffering=0)
        body=encoded({'schemaVersion':1,'operationId':owner.operation,'clientChild':client.ordinal,'clientPid':client.pid,
            'clientBirthFileTimeUtc':client.birth,'clientArgv':list(expected),'ownerWorkId':operation,
            'ownerWorkRequestId':detail['requestId'],'servePid':serve.pid,'workerPid':os.getpid(),
            'protectedLivePids':sorted(protected),'effect':'one-original-Popen.terminate','replayAllowed':False})
        at=0
        while at<len(body):
            n=state['stream'].write(body[at:]);need(n is not None and n>0,'client-intent-short-write');at+=n
        state['stream'].flush();os.fsync(state['stream'].fileno())
        assert_serve(owner,serve)
        need(client.process.poll()is None and owner.native.birth(int(client.process._handle))==client.birth,
             'original-client-closing-live-birth')
        state.update(stage='effect-entered',attempts=1)
        client.process.terminate()  # Existing original Windows Popen handle only.
        state['stage']='effect-returned'
        terminal=wait_original(owner,client,'original-client-termination-eof-unknown',TERMINATE_SECONDS)
        need(terminal['exitCode']!=0 and terminal['eof']=={'stdout':True,'stderr':True},'terminated-client-positive-terminal-eof')
        raw_child(owner,client);assert_serve(owner,serve)
        state['stage']='known-client-terminal';state['stream'].close()
        owner.event('original-cli-client-response-loss-observed',{'child':client.ordinal,'pid':client.pid,
            'birthFileTimeUtc':client.birth,'ownerWorkId':operation,'ownerWorkRequestId':detail['requestId'],
            'terminal':terminal,'terminationAttempts':1,'sameController':identity,
            'ownerWorkOutcome':'unobserved-until-same-operation-status',
            'groupOrJobSignal':False,'fullMembershipComplete':False})
        return state
    except BaseException as error:
        state['primary']=error
        owner.park('original-client-effect-or-eof-unknown-no-replay',error)
        raise


def finite(value,characters=CODE_CHARACTERS,limit=80):
    """A code or name the fixture or an oracle said, or None: never free text."""
    return value if type(value)is str and 0<len(value)<=limit and set(value)<=characters else None

def fixture_said(owner,child):
    """What the work fixture said on its stdout so far: its start steps in order and its own failure record.

    Only complete lines count, and only the finite fields of each are kept."""
    said={'steps':[],'failure':None,'readySaid':False,'stdoutBytes':child.counts['stdout'],'stderrBytes':child.counts['stderr'],
          'unreadable':None}
    try:
        with (owner.root/f'child-{child.ordinal:04d}.stdout.raw').open('rb')as stream:raw=stream.read(65536)
        for line in raw.split(b'\n')[:-1]:
            try:row=json.loads(line)
            except ValueError:continue
            if type(row)is not dict:continue
            if row.get('kind')=='owned-work-fixture-step' and row.get('step')in FIXTURE_STEPS and len(said['steps'])<2*len(FIXTURE_STEPS):
                said['steps'].append(row['step'])
            elif row.get('kind')=='owned-work-fixture-failed':
                said['failure']={'step':row.get('step')if row.get('step')in FIXTURE_STEPS else None,
                    'errorClass':finite(row.get('errorClass'),NAME_CHARACTERS,64),
                    **{name:row.get(name)if type(row.get(name))is int else None for name in ('winerror','errno')},
                    'reason':finite(row.get('reason')),'listenersStopped':row.get('listenersStopped')is True}
            elif row.get('kind')=='owned-work-fixture-ready':said['readySaid']=True
    except Exception as error:said['unreadable']=type(error).__name__
    said['lastStep']=said['steps'][-1]if said['steps']else None
    return said

def await_ready(owner,child,ready):
    """The fixture's ready file within READY_SECONDS, or why the wait stopped: 'ended' or 'timeout'. Nothing parks here."""
    started=time.monotonic()
    while not ready.exists():
        if child.process.poll()is not None:return 'ended',time.monotonic()-started
        if time.monotonic()-started>=READY_SECONDS:return 'timeout',time.monotonic()-started
        time.sleep(.1)
    return None,time.monotonic()-started

def end_work_fixture(owner,child,error,reason,config,windows=None,waited=None,kind='document-work-fixture-ending'):
    """End the owner's own work fixture while no request of the product is in flight with it.

    What is there is journaled first: the child's pid and whether it lives, whether the ready file and its
    publishing name exist, the fixture folder's names, the steps and the failure the fixture itself said and,
    with the document native module, who holds each of the fixture's files, the fixture among them. A live
    child then gets exactly one termination of its original Popen handle, never a tree, job or group signal,
    and is awaited to its terminal and EOF. What cannot be known parks, keeping every original."""
    try:
        need(child.owner is owner and owner.children[child.ordinal]is child and child.label==FIXTURE_LABEL,
             'same-original-work-fixture-child')
        alive=child.terminal is None and child.process.poll()is None
        def ended():
            deadline=time.monotonic()+TERMINATE_SECONDS
            while child.observe()is None:
                if time.monotonic()>=deadline:
                    owner.park('document-work-fixture-end-unknown',{'child':child.ordinal,'pid':child.pid,
                        'birthFileTimeUtc':child.birth,'terminated':alive,'replayAllowed':False})
                time.sleep(.05)
            return fixture_said(owner,child)
        # A child that already ended is first read to its EOF, so everything it said is in its raw files.
        said=fixture_said(owner,child)if alive else ended();ready=Path(config['readyFile']);root=ready.parent
        publishing=ready.with_name(ready.name+'.publishing')
        names=sorted(entry.name for entry in root.iterdir())if root.is_dir()else[]
        value={'reason':reason,'child':child.ordinal,'pid':child.pid,'birthFileTimeUtc':child.birth,'alive':alive,
               'exitCode':child.process.poll(),'waitedSeconds':None if waited is None else round(waited,3),
               'boundSeconds':READY_SECONDS,'errorClass':type(error).__name__,**said,
               'readyExists':ready.exists(),'publishingExists':publishing.exists(),'folderCount':len(names),
               'folder':names[:16],'heldByFixture':None,'censusError':None,'replayAllowed':False}
        if windows is not None:
            # While the child is still as it was found: the kernel's own list of who has each of its files open.
            targets=[('fixture-folder',root),('ready',ready),('ready-publishing',publishing),
                     ('input',Path(child.argv[-1])),('fixture-source',Path(child.argv[3])),
                     *((role,Path(config[key]))for role,key in (('socks-source','socksSourcePath'),('https-source','httpsSourcePath'),
                                                               ('certificate','certificatePath'),('private-key','privateKeyPath')))]
            census=windows.holder_census(owner,'work','readiness',reason,None,targets)
            value['heldByFixture']=[target['role']for target in census['targets']
                                    if any(holder['pid']==child.pid for holder in target['holders'])]
            value['censusError']=census['censusError']
        owner.event(kind,value)
        if alive:
            need(owner.native.birth(int(child.process._handle))==child.birth,'original-work-fixture-live-birth')
            owner.event('document-work-fixture-terminate-intent',{'child':child.ordinal,'pid':child.pid,
                'birthFileTimeUtc':child.birth,'effect':'one-original-Popen.terminate','groupOrJobSignal':False,
                'replayAllowed':False})
            child.process.terminate()  # Existing original Windows Popen handle only.
            said=ended()
        owner.event('document-work-fixture-closed',{'child':child.ordinal,'pid':child.pid,'reason':reason,'terminated':alive,
            'terminal':child.terminal,'steps':said['steps'],'failure':said['failure'],'replayAllowed':False})
        return said
    except Exception as closing:
        owner.park('document-work-fixture-closing-unknown',closing)
        raise

def not_ready(owner,child,config,windows,reason,waited,error):
    """The known failure of a work fixture that failed before the serve existed, once the fixture is ended."""
    said=end_work_fixture(owner,child,error,reason,config,windows,waited,'document-work-fixture-not-ready')
    if reason=='timeout':code='timeout:'+(said['lastStep']or'none')
    elif reason=='ended':code='ended:%s:%s'%(child.terminal['exitCode'],(said['failure']or{}).get('step')or'none')
    else:code='refused:'+(finite(str(error))or type(error).__name__)
    return AssertionError('document-work-fixture-not-ready:'+code)

def close_known_work(owner,lease,error):
    """For the case module's known-failure closing: end the work fixture unless a refresh may be in flight.

    False keeps every original for the park: a phase whose refresh started and is not yet known final, or a
    client termination whose end was not observed."""
    if lease is not getattr(owner,'document_work_lease',None) or lease.open_phase is not None:return False
    if any(state['stage']!='known-client-terminal'for state in getattr(owner,'responsive_client_effects',{}).values()):return False
    if lease.child.terminal is None:
        end_work_fixture(owner,lease.child,error,'known-failure',lease.config,lease.windows)
    lease.closed=True
    return True


class WorkLease:
    """Original fixture Child + immutable native event files, two phases only."""
    def __init__(self,owner,child,ready,config,runtime):
        self.owner,self.child,self.ready,self.config,self.runtime=owner,child,ready,config,runtime
        self.events={};self.releases={};self.completed=set();self.subscriptions={};self.closed=False
        # The phase whose refresh the owner may still be working on: set before its client starts, cleared when known final.
        self.open_phase=None;self.windows=None
        need(ready['pid']==child.pid and ready['operationId']==owner.operation,'actual-original-fixture-child-ready')
    def guard(self):
        self.runtime.data_guard(self.owner)
        need(not self.closed and self.child.process.poll()is None
             and self.owner.native.birth(int(self.child.process._handle))==self.child.birth,'original-work-fixture-live-birth')
    def event(self,phase,suffix):
        self.guard();need(phase in PHASES and suffix in ('entered','ended'),'finite-work-event')
        key=(phase,suffix)
        if key not in self.events:
            path=Path(self.config['readyFile']).parent/(phase+'-'+suffix+'.json');deadline=time.monotonic()+NOTICE_SECONDS
            while not path.exists():
                self.guard()
                if time.monotonic()>=deadline:self.owner.park('original-owned-work-event-unobserved',{'phase':phase,'suffix':suffix})
                time.sleep(.05)
            # The size is the handle's own: a Windows path stat may lag it (see unchanged).
            with path.open('rb')as stream:
                held=os.fstat(stream.fileno());need(held.st_size<=16384,'work-event-byte-bound')
                raw=stream.read(16385);need(len(raw)==held.st_size==os.fstat(stream.fileno()).st_size,'work-event-read-count')
            pin=self.runtime.OwnedData(self.owner,path,sha(raw));pin.current();value=json.loads(raw)
            need(value['schemaVersion']==1 and value['operationId']==self.owner.operation and value['phase']==phase
                 and value['pid']==self.child.pid and value['requestOrdinal']==1
                 and value['path']==f'/subscription/{phase}/{self.owner.operation}','actual-original-http-work-event')
            self.events[key]=(value,pin)
        value,pin=self.events[key];pin.current();return value
    def release(self,phase):
        self.guard();need(phase in PHASES and phase not in self.releases,'work-release-once')
        self.releases[phase]=None  # uncertain publication can never be repeated
        path=Path(self.config['readyFile']).parent/(phase+'-release.json')
        self.runtime.publish(self.owner,path,{'schemaVersion':1,'operationId':self.owner.operation,'phase':phase,'action':'release-original-request'})
        self.releases[phase]=path
    def mark_known(self,phase,terminal):
        need(phase in self.releases and terminal['final']is True and terminal['code']in ('OK','CANCELLED'),
             'known-original-work-before-fixture-completion')
        ended=self.event(phase,'ended');need(ended['result']in ('response-written','peer-closed'),'original-http-handler-result')
        self.completed.add(phase);self.open_phase=None


def prepare_before_serve(owner,workspace,inputs,runtime,windows=None):
    """Finite existing Owner.child/publish fixture hook, BEFORE original serve.

    No serve exists yet, so the product has no part in anything here. A fixture that does not become ready
    within READY_SECONDS, ends first, or publishes a ready record an oracle refuses is journaled, ended and
    awaited (end_work_fixture, with the holder census if the document native module is given), and the
    failure raised is known: document-work-fixture-not-ready:<timeout|ended|refused>:..."""
    required={'schemaVersion','fixtureWorkerPath','socksSourcePath','httpsSourcePath','certificatePath','privateKeyPath',
              'trustStorePath','contexts','largeRoutingInputPath'}
    need(type(inputs)is dict and set(inputs)==required and inputs['schemaVersion']==1,'responsive-input-schema')
    need(type(inputs['contexts'])is list and len(inputs['contexts'])==2 and len(set(inputs['contexts']))==2
         and all(str(uuid.UUID(x))==x for x in inputs['contexts']),'two-new-responsive-document-contexts')
    fresh_contexts(owner,inputs['contexts'])
    owner.guard();need(str(workspace)==owner.request['workspace'] and not Path(workspace).exists()
         and not any(c.label=='serve' for c in owner.children),'responsive-before-original-serve')
    for role in required-{'schemaVersion','contexts'}:
        need(str(Path(inputs[role])).casefold()in owner.by_path,'responsive-source-material-role-'+role)
    root=owner.root/'fixture';need(not root.exists(),'fresh-owned-work-fixture-root');root.mkdir()
    runtime.OwnedData(owner,root,directory=True)
    config={'schemaVersion':1,'operationId':owner.operation,**{k:inputs[k] for k in
        ('socksSourcePath','httpsSourcePath','certificatePath','privateKeyPath')},'readyFile':str(root/'ready.json'),
        'controlFile':str(root/'stop.json'),'token':'owned-document-work-'+owner.operation}
    source=runtime.publish(owner,owner.root/'document-work-input.json',config)
    child=owner.child(FIXTURE_LABEL,[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',
        inputs['fixtureWorkerPath'],'--input',str(source)])
    reason=waited=None
    try:
        reason,waited=await_ready(owner,child,Path(config['readyFile']))
        need(reason is None,'work-fixture-'+str(reason))
        ready=runtime.read_ready(owner,child,Path(config['readyFile']),owner.operation)
        need(ready['certificateSha256']==owner.by_path[str(Path(inputs['certificatePath'])).casefold()].record['sha256']
             and ready['workUrls']=={p:f"https://localhost:{ready['httpsPort']}/subscription/{p}/{owner.operation}" for p in PHASES},
             'actual-work-tls-endpoints')
        need('JAVA_TOOL_OPTIONS'not in owner.environment,'no-preexisting-owner-jvm-options')
        lease=WorkLease(owner,child,ready,config,runtime)
    except Exception as error:
        raise not_ready(owner,child,config,windows,reason or'refused',waited,error) from error
    owner.environment['JAVA_TOOL_OPTIONS']=runtime.scoped_trust_options(inputs['trustStorePath'])
    lease.inputs=inputs;lease.windows=windows
    owner.document_work_lease=lease
    # The measured wait: what the bound is next judged by.
    owner.event('document-work-fixture-ready',{'child':child.ordinal,'pid':child.pid,'readySeconds':round(waited,3),
        'boundSeconds':READY_SECONDS})
    return lease


def after_original_serve_started(owner,lease,serve):
    # The owner removed the scoped trust options right after starting serve; later children never see them.
    need(lease is owner.document_work_lease and serve.owner is owner and serve in owner.children,'same-work-original-serve')
    assert_serve(owner,serve);lease.serve=serve


def run(owner,workspace,identity,client,document,lease):
    """Two cases; caller supplies SAME admitted document client and Owner."""
    try:return _run(owner,workspace,identity,client,document,lease)
    except BaseException as error:
        # A refresh the owner may still be working on keeps every original, and so does an error that is no
        # oracle's. A finite oracle failure with no phase open is the case module's to close (close_known_work).
        if lease.open_phase is not None or not isinstance(error,AssertionError):
            owner.park('document-responsive-longwork-unqualified-originals-retained',error)
        raise


def _run(owner,workspace,identity,client,document,lease):
    need(lease is owner.document_work_lease and client.owner==identity,'same-admitted-document-work-owner')
    fresh_contexts(owner,lease.inputs['contexts'],client)
    assert_serve(owner,lease.serve);lease.guard();client.guard()
    initial,_=call(owner,workspace,identity,'status')
    need(initial['data']['runtimeRunning']is False,'responsive-disconnected-owned-workspace')
    subscriptions,_=call(owner,workspace,identity,'subscriptions','list')
    need(subscriptions['data']['subscriptions']==[],'fresh-owned-workspace-no-foreign-subscription')
    saved={}
    for key,value in (('refresh.policy','off'),('refresh.find-best-after-refresh','false')):
        old,_=call(owner,workspace,identity,'settings','show',key);saved[key]=old['data'][key]
        before,_=call(owner,workspace,identity,'status')
        call(owner,workspace,identity,'--if-revision',str(before['configurationRevision']),'settings','set',key,value)
    source=owner.by_path[str(Path(lease.inputs['largeRoutingInputPath'])).casefold()]
    data=source.digest(True,maximum=64*1024*1024);need(len(data)>10*1024*1024,'retained-document-large-fixture')
    # No transfer context from the existing52 is reused, and no borrowed entry
    # is discarded on an uncertain request/owner result.
    results=[]
    for phase,context in zip(PHASES,lease.inputs['contexts']):
        baseline,_=call(owner,workspace,identity,'operations','list')
        previous={row['id']for row in baseline['data']['operations']}
        need(all(row['final']is True for row in baseline['data']['operations']),'no-other-pending-owner-work')
        before,_=call(owner,workspace,identity,'status')
        added,_=call(owner,workspace,identity,'--if-revision',str(before['configurationRevision']),
            'subscriptions','add','--source',lease.ready['workUrls'][phase],'--name','Owned '+phase)
        subscription=added['data']['id'];lease.subscriptions[phase]=subscription
        shown,_=call(owner,workspace,identity,'subscriptions','show',subscription)
        need(shown['data']['source']==lease.ready['workUrls'][phase] and shown['data']['cachedLocations']==0,
             'exact-owned-dormant-subscription')
        reference=client.upload(context,data)
        need(client.transfers[context]['sha256']==sha(data),'actual-retained-document-reference')
        owner.event('document-reference-held-for-owner-work',{'phase':phase,'context':context,
            'manifest':client.transfers[context],'referenceSha256':sha(reference.encode()),'subscriptionId':subscription})
        args=[owner.request['cliPath'],'--state-dir',str(workspace),'--json','--controller-id',identity,
              *(['--async']if phase=='responsive' else []),'subscriptions','refresh',subscription]
        lease.open_phase=phase
        original=owner.child('original-'+phase+'-refresh',args)
        accepted=None
        if phase=='responsive':
            wait_original(owner,original,'original-async-acceptance-unknown')
            accepted=result_child(owner,original,identity,('ACCEPTED',),(0,),False)
        entered=lease.event(phase,'entered');need(entered['status']==200,'actual-owned-https-work-entered')
        listed,_=call(owner,workspace,identity,'operations','list')
        fresh=[r for r in listed['data']['operations']if r['id']not in previous and r['operation']=='subscriptions.refresh']
        need(len(fresh)==1 and fresh[0]['phase']=='running' and fresh[0]['cancellable']is True and fresh[0]['requestId'],
             'one-fresh-actual-owned-subscription-work')
        operation=fresh[0]['id'];original_request=fresh[0]['requestId']
        if accepted is not None:need(accepted['operationId']==operation and accepted['requestId']==original_request,'same-accepted-original-operation')
        running,status_child=call(owner,workspace,identity,'operations','status',operation,codes=('ACCEPTED',),final=False)
        need(running['data']['requestId']==original_request and running['data']['phase']=='running','same-original-running-work')
        during,_=call(owner,workspace,identity,'status')
        need(during['data']['runtimeRunning']is False,'status-responsive-with-document-retained')
        probe_document(client,document,context,data)
        timeout,_=call(owner,workspace,identity,'operations','wait',operation,'--timeout-seconds','1',codes=('TIMEOUT',),exits=(2,),final=False,
                       operation=operation)
        need(timeout['operationId']==operation,'wait-timeout-retains-original-work')
        if phase=='responsive':
            cancel,_=call(owner,workspace,identity,'operations','cancel',operation)
            # This is the cancellation COMMAND acknowledgement, not a terminal
            # result for the underlying operation. Only wait below proves that.
            need(cancel['data']['id']==operation and cancel['data']['requestId']==original_request
                 and cancel['data']['phase']in ('cancelling','cancelled'), 'cancel-same-original-operation-ack')
        else:
            terminate_original_sync_refresh(owner,original,lease.serve,workspace,identity,subscription,status_child)
            still,_=call(owner,workspace,identity,'operations','status',operation,codes=('ACCEPTED',),final=False)
            need(still['operationId']==operation and still['data']['requestId']==original_request
                 and still['data']['phase']=='running','client-loss-must-not-cancel-owner-work')
        lease.release(phase)
        final,_=call(owner,workspace,identity,'operations','wait',operation,codes=(('CANCELLED',)if phase=='responsive'else('OK',)),
                     exits=((130,)if phase=='responsive'else(0,)),final=True)
        need(final['operationId']==operation,'same-original-terminal-work')
        retained,_=call(owner,workspace,identity,'operations','status',operation,codes=(final['code'],),exits=((130,)if phase=='responsive'else(0,)))
        need(dict(retained,requestId=final['requestId'])==final,'original-terminal-result-retained')
        lease.mark_known(phase,final);probe_document(client,document,context,data)
        # A cancelled refresh caches nothing; the one that outlived its lost client cached its one location.
        cached,_=call(owner,workspace,identity,'subscriptions','show',subscription)
        need(cached['data']['cachedLocations']==(0 if phase=='responsive' else 1),'refresh-outcome-reached-the-cache')
        source.current();need(source.digest(True,maximum=64*1024*1024)==data,'original-document-source-closing')
        client.guard();client.discard(context)
        now,_=call(owner,workspace,identity,'status')
        call(owner,workspace,identity,'--if-revision',str(now['configurationRevision']),'subscriptions','delete',subscription)
        assert_serve(owner,lease.serve)
        row={'phase':phase,'operationId':operation,'originalRequestId':original_request,'documentContext':context,
             'documentManifest':client.transfers[context],'terminal':final,'controllerId':identity,
             'sameOriginalServe':{'pid':lease.serve.pid,'birthFileTimeUtc':lease.serve.birth},
             'nativeMembershipComplete':False,'guiTransferProven':False}
        owner.event('document-responsive-longwork-observed',row);results.append(row)
    for key,value in saved.items():
        before,_=call(owner,workspace,identity,'status')
        call(owner,workspace,identity,'--if-revision',str(before['configurationRevision']),'settings','set',key,
             str(value).lower()if type(value)is bool else str(value))
        restored,_=call(owner,workspace,identity,'settings','show',key)
        need(restored['data'][key]==value,'original-owned-refresh-setting-restored')
    return {'contributionOnly':['document-persistence-transfer/responsive-status-cancel','windows-owner-lifecycle/cli-disconnect-long-work'],
            'observations':results,'full64Complete':False,'visual58Complete':False}


def probe_document(client,document,context,data):
    # DesktopControlDocuments only permits read on output kinds. For an input
    # reference, the documented idempotent begin observes the SAME sealed entry;
    # it does not append, consume, or submit the retained input as a command.
    manifest=client.transfers[context]
    value=document.manifest(client.action(context,{'action':'begin','requestId':context}))
    need(value==manifest and value['byteCount']==len(data) and value['sha256']==sha(data),
         'actual-server-sealed-document-reference-retained')
    client.event('retained-document-server-manifest-observed',{'context':context,'manifest':value,
        'fullDocumentBytesReadBack':False,'documentCommandSubmitted':False})


def stop_after_known_cases(owner,lease):
    lease.guard();need(lease.completed==set(PHASES),'both-original-work-cases-known-before-fixture-stop')
    lease.runtime.publish(owner,Path(lease.config['controlFile']),{'schemaVersion':1,'operationId':owner.operation,'action':'stop-owned-fixture'})
    t=wait_original(owner,lease.child,'original-work-fixture-shutdown-unknown')
    raw=raw_child(owner,lease.child)
    need(t['exitCode']==0 and not raw['stderr'],'original-fixture-known-terminal')
    rows=[json.loads(line)for line in raw['stdout'].splitlines()]
    need(rows[-1]=={'kind':'owned-work-fixture-terminal','operationId':owner.operation,'onlyOriginalObjectsStopped':True},'original-fixture-stop-receipt')
    lease.closed=True
