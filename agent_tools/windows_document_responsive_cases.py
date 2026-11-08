"""Two public subscription-work cases under the ordinary retained Owner.

No import-time effect. No new product API/transport or SSH interruption. Reached only
through the planner's closed responsiveWork input and the owner's document action.
"""
from __future__ import annotations
import base64,hashlib,json,os,time,uuid
from pathlib import Path

CAP=1024*1024
NOTICE_SECONDS=30
TERMINATE_SECONDS=15
PHASES=('responsive','client-loss')

def need(ok,reason):
    if not ok:raise AssertionError(reason)
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def generation(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

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
        need(generation(before)==generation(after)==generation(path.stat(follow_symlinks=False))
             and len(value)==t['counts'][name] and sha(value)==t['sha256'][name],'original-public-raw-join')
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


class WorkLease:
    """Original fixture Child + immutable native event files, two phases only."""
    def __init__(self,owner,child,ready,config,runtime):
        self.owner,self.child,self.ready,self.config,self.runtime=owner,child,ready,config,runtime
        self.events={};self.releases={};self.completed=set();self.subscriptions={};self.closed=False
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
            size=path.stat().st_size;need(size<=16384,'work-event-byte-bound')
            raw=path.read_bytes();need(len(raw)==size,'work-event-read-count')
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
        self.completed.add(phase)


def prepare_before_serve(owner,workspace,inputs,runtime):
    """Finite existing Owner.child/publish fixture hook, BEFORE original serve."""
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
    child=owner.child('owned-document-work-fixture',[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',
        inputs['fixtureWorkerPath'],'--input',str(source)])
    ready=runtime.read_ready(owner,child,Path(config['readyFile']),owner.operation)
    need(ready['certificateSha256']==owner.by_path[str(Path(inputs['certificatePath'])).casefold()].record['sha256']
         and ready['workUrls']=={p:f"https://localhost:{ready['httpsPort']}/subscription/{p}/{owner.operation}" for p in PHASES},
         'actual-work-tls-endpoints')
    need('JAVA_TOOL_OPTIONS'not in owner.environment,'no-preexisting-owner-jvm-options')
    owner.environment['JAVA_TOOL_OPTIONS']=runtime.scoped_trust_options(inputs['trustStorePath'])
    lease=WorkLease(owner,child,ready,config,runtime);lease.inputs=inputs
    owner.document_work_lease=lease
    return lease


def after_original_serve_started(owner,lease,serve):
    # The owner removed the scoped trust options right after starting serve; later children never see them.
    need(lease is owner.document_work_lease and serve.owner is owner and serve in owner.children,'same-work-original-serve')
    assert_serve(owner,serve);lease.serve=serve


def run(owner,workspace,identity,client,document,lease):
    """Two cases; caller supplies SAME admitted document client and Owner."""
    try:return _run(owner,workspace,identity,client,document,lease)
    except BaseException as error:
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
