"""Two fixed subscription-work gates over the existing TLS fixture.

No import-time listener/action. No upstream Internet, proxy/runtime/VM control.
The original ordinary Owner holds every script/TLS/input file before its Child
starts this source. Unknown retains the same fixture/thread/socket; no restart.
"""
from __future__ import annotations
import hashlib,json,os,ssl,stat,sys,threading,time,types,uuid
from pathlib import Path

PHASES=('responsive','client-loss')
# A gate stays open until its release, longer than the product's own client waits.
GATE_SECONDS=600
# The relay's own default handshake wait; a stalled peer then ends instead of holding a handler.
TLS_HANDSHAKE_SECONDS=5
SOURCES={'https':'e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4',
         'socks':'50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210'}

def need(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
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

def read_exact(path,limit):
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0));s=os.fstat(fd)
    try:
        need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=limit,'work-input-bound-type')
        blocks=[];remaining=s.st_size+1
        while remaining:
            block=os.read(fd,remaining)
            if not block:break
            blocks.append(block);remaining-=len(block)
        raw=b''.join(blocks)
        unchanged(s,os.fstat(fd),os.stat(path,follow_symlinks=False),len(raw),'work-input-closing')
        return raw
    finally:os.close(fd)

def publish(path,value):
    raw=encoded(value);need(len(raw)<=16384,'work-event-bound')
    temporary=path.with_name(path.name+'.publishing')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0),0o600)
    # Register fd in caller before calling if native source qualification needs
    # recovery. Here a failed publication parks the same handler stack below.
    at=0
    while at<len(raw):
        n=os.write(fd,raw[at:]);need(n>0,'work-event-short-write');at+=n
    os.fsync(fd);os.close(fd)
    if os.name=='nt':os.rename(temporary,path)  # Windows refuses replacement.
    else:os.link(temporary,path);temporary.unlink()

def load(path,role):
    raw=read_exact(path,1024*1024);need(sha(raw)==SOURCES[role],'work-fixture-exact-source')
    name='socks_http_fixture' if role=='socks' else '_owned_work_https'
    need(name not in sys.modules,'work-fixture-module-name')
    m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m

def gate_request(server,phase,send_headers,write,flush,*,pause=time.sleep,clock=time.monotonic):
    """Real handler flow; local controls substitute only IO/clock boundaries."""
    need(phase in PHASES,'finite-work-phase')
    with server.work_lock:
        need(phase not in server.work_states,'work-phase-no-second-request')
        state={'phase':phase,'status':'entered','heartbeats':0,'bodyBytes':0,'bodySha256':None}
        server.work_states[phase]=state
    body=server.subscription_body.encode();need(0<len(body)<=4096,'finite-work-subscription-body')
    row={'schemaVersion':1,'operationId':server.work_operation,'phase':phase,'pid':os.getpid(),
         'path':f'/subscription/{phase}/{server.work_operation}','requestOrdinal':1,'status':200}
    publish(server.work_root/(phase+'-entered.json'),row)
    send_headers()
    started=clock();digest=hashlib.sha256()
    while not (server.work_root/(phase+'-release.json')).exists():
        if clock()-started>GATE_SECONDS:
            state['status']='unknown-retained'
            while True:pause(1)  # no timeout close/retry of original handler
        write(b'1\r\n\n\r\n');flush();digest.update(b'\n');state['heartbeats']+=1
        need(state['heartbeats']<=GATE_SECONDS,'finite-work-heartbeat-bound')
        pause(1)
    release=json.loads(read_exact(server.work_root/(phase+'-release.json'),1024))
    need(release=={'schemaVersion':1,'operationId':server.work_operation,'phase':phase,'action':'release-original-request'},'exact-work-release')
    write((format(len(body),'x')+'\r\n').encode()+body+b'\r\n0\r\n\r\n');flush();digest.update(body)
    state.update(status='response-written',bodyBytes=state['heartbeats']+len(body),bodySha256=digest.hexdigest())
    publish(server.work_root/(phase+'-ended.json'),{**row,'result':'response-written','heartbeats':state['heartbeats'],
        'decodedBodyBytes':state['bodyBytes'],'decodedBodySha256':state['bodySha256']})


def fixture_class(source):
    class Handler(source._SubscriptionHandler):
        protocol_version='HTTP/1.1'
        def do_GET(self):
            server=self.server
            phase=next((p for p in PHASES if self.path==f'/subscription/{p}/{server.work_operation}'),None)
            if phase is None:self.send_error(404);return
            def headers():
                self.send_response(200);self.send_header('Content-Type','text/plain; charset=utf-8')
                self.send_header('Transfer-Encoding','chunked');self.end_headers()
            try:gate_request(server,phase,headers,self.wfile.write,self.wfile.flush)
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError,ssl.SSLError) as error:
                # Observed socket error is not a completed response. It remains
                # separately visible; original operation terminal is mandatory.
                server.work_states[phase]['status']='peer-closed'
                publish(server.work_root/(phase+'-ended.json'),{'schemaVersion':1,'operationId':server.work_operation,
                    'phase':phase,'pid':os.getpid(),'requestOrdinal':1,'path':self.path,'status':200,
                    'result':'peer-closed','errorClass':type(error).__name__})
            except BaseException as error:
                server.work_primary=error
                while True:time.sleep(1)  # retain same handler/socket/frame
    class Fixture(source.HttpsSubscriptionRelayFixture):
        def __init__(self,value):
            self.work_value=value
            super().__init__(Path(value['certificatePath']),Path(value['privateKeyPath']),Path(value['readyFile']),value['token'])
        def _publish_readiness(self,ready):
            s=self.https_server;v=self.work_value;s.work_operation=v['operationId'];s.work_root=Path(v['readyFile']).parent
            s.work_lock=threading.Lock();s.work_states={};s.work_primary=None;s.RequestHandlerClass=Handler
            publish(Path(v['readyFile']),{**ready,'operationId':v['operationId'],'pid':os.getpid(),
                'workUrls':{p:f"https://localhost:{ready['httpsPort']}/subscription/{p}/{v['operationId']}" for p in PHASES},
                'certificateSha256':sha(read_exact(v['certificatePath'],1024*1024)),
                'scope':'only-two-owned-subscription-requests','nativeAcceptance':False})
    return Fixture


def main(argv):
    need(len(argv)==2 and argv[0]=='--input','finite-work-entry')
    v=json.loads(read_exact(argv[1],16384))
    need(type(v)is dict and set(v)=={'schemaVersion','operationId','socksSourcePath','httpsSourcePath','certificatePath',
        'privateKeyPath','readyFile','controlFile','token'} and v['schemaVersion']==1,'finite-work-input-schema')
    need(str(uuid.UUID(v['operationId']))==v['operationId'] and type(v['token'])is str
         and 0<len(v['token'].encode())<=4096,'finite-work-input-identity')
    root=Path(v['readyFile']).parent
    need(root==Path(v['controlFile']).parent and not Path(v['readyFile']).exists() and not Path(v['controlFile']).exists(),'fresh-owned-work-root')
    load(v['socksSourcePath'],'socks');source=load(v['httpsSourcePath'],'https')
    source.TLS_HANDSHAKE_TIMEOUT_SECONDS=TLS_HANDSHAKE_SECONDS
    fixture=fixture_class(source)(v)
    try:
        ready=fixture.start()
        print(json.dumps({'kind':'owned-work-fixture-ready','operationId':v['operationId'],'ready':ready}),flush=True)
        while True:
            if Path(v['controlFile']).exists():
                stop=json.loads(read_exact(v['controlFile'],1024))
                need(stop=={'schemaVersion':1,'operationId':v['operationId'],'action':'stop-owned-fixture'},'exact-work-stop')
                need(fixture.https_server.work_primary is None and set(fixture.https_server.work_states)==set(PHASES)
                     and all(s['status']in ('response-written','peer-closed') for s in fixture.https_server.work_states.values()),'both-original-requests-ended-before-stop')
                break
            time.sleep(.1)
        fixture.stop()
        print(json.dumps({'kind':'owned-work-fixture-terminal','operationId':v['operationId'],'onlyOriginalObjectsStopped':True}),flush=True)
    except BaseException as error:
        # Preserve original fixture/threads/sockets, primary traceback and the
        # same lifecycle frame. No restart or second stop follows uncertainty.
        fixture.work_lifetime_primary=error
        fixture.work_lifetime_unknown=True
        while True:time.sleep(1)
    return 0
if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
