"""Current-screen admission for the preserved, recovered CP117 account.

Only the source-bound screenshot stage is currently admitted. Credential and
login effects require a reviewed current account-specific profile.
"""
from __future__ import annotations
import base64,gzip,hashlib,json,os,selectors,stat,subprocess,time,uuid
from pathlib import Path
from . import windows_cp117_recovered_guest_observe as guest
from . import windows_cp117_recovered_session_observe as session
from .windows_diagnostic_authority_capture import AuthorityCapture
GUEST_SHA='254d7495f1a4c02e68b34c6168c6dad93a693445b9569849f61fdf4ca2379b58'
SESSION_SHA='37311515a78969a7b992a848a22cecd18eb26dcf9bca214365551a1a8a56d586'
TRANSFER='/home/kardinal/.vpn-control-mcp-fixtures'
MAX_FRAME=16*1024*1024
WAKE_CORRELATION='8dc9e0e8-af9d-4f0e-8d20-7b3fa6842e56'

_SCREEN=r'''
 guards()
 import socket,gzip,base64
 parent=__TRANSFER__;diagnostic=__DIAGNOSTIC__;job='cp117-login-screen-'+diagnostic
 parentfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 parentinfo=os.fstat(parentfd);need(stat.S_ISDIR(parentinfo.st_mode)and parentinfo.st_uid==os.geteuid()and stat.S_IMODE(parentinfo.st_mode)==0o700,'screen-parent')
 need(fp(parentinfo)==fp(os.lstat(parent)),'screen-parent-generation')
 os.mkdir(job,0o700,dir_fd=parentfd);os.fsync(parentfd)
 directory=parent+'/'+job;jobfd=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd);jobinfo=fp(os.fstat(jobfd))
 def screen_guard():
  guards();need(all(getattr(os.fstat(parentfd),k)==getattr(os.lstat(parent),k)==getattr(parentinfo,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'screen-parent-drift')
  need(all(getattr(os.fstat(jobfd),k)==getattr(os.lstat(directory),k)==jobinfo[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'screen-directory-drift')
 screen_guard()
 anchor=os.open('intent.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jobfd)
 raw=json.dumps({'diagnosticId':diagnostic,'qemu':children[1]['child'],'originalRequestSha256':digest(REQUEST)},sort_keys=True).encode()
 need(os.write(anchor,raw)==len(raw),'screen-intent-write');os.fsync(anchor);os.close(anchor);os.fsync(jobfd)
 need(not os.path.lexists(directory+'/frame.ppm'),'screen-existing')
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(10);stream=None
 try:
  screen_guard();c.connect(LEAF+'/qmp.sock');stream=c.makefile('rb')
  def response(wanted):
   for _ in range(16):
    raw=stream.readline(32769);need(0<len(raw)<=32768 and raw.endswith(b'\n'),'qmp-response-cap');v=json.loads(raw)
    if wanted is None:need('QMP'in v,'qmp-greeting');return v
    if v.get('id')==wanted:need('return'in v and 'error'not in v,'qmp-response');return v['return']
    need('event'in v,'qmp-response-id')
   raise ValueError('qmp-event-cap')
  response(None)
  c.sendall(json.dumps({'execute':'qmp_capabilities','id':1}).encode()+b'\n');response(1)
  screen_guard();need(not os.path.lexists(directory+'/frame.ppm'),'screen-existing')
  c.sendall(json.dumps({'execute':'screendump','arguments':{'filename':directory+'/frame.ppm'},'id':2}).encode()+b'\n');response(2);captured_at=time.monotonic()
  screen_guard()
 finally:
  if stream is not None:stream.close()
  c.close()
 fd=os.open('frame.ppm',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jobfd)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and 0<s.st_size<=16777216,'screen-file')
  os.fchmod(fd,0o600);s=os.fstat(fd);raw=os.read(fd,16777217)
  need(len(raw)==s.st_size and fp(s)==fp(os.fstat(fd))==fp(os.stat('frame.ppm',dir_fd=jobfd,follow_symlinks=False)),'screen-file-drift')
  validate_ppm(raw);screen_guard()
__WAKE_BLOCK__
  packed=gzip.compress(raw,mtime=0);need(len(packed)<=700000,'screen-compressed-cap')
  result({'state':'observed','qemu':children[1]['child'],'bootId':R['bootId'],'frameSha256':hashlib.sha256(raw).hexdigest(),'frameGeneration':fp(s),'frameGzip':base64.b64encode(packed).decode(),'appAdmission':False,'installerAction':False})
 finally:os.close(fd);os.close(jobfd);os.close(parentfd)
except Exception as e:result({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'appAdmission':False,'installerAction':False,'replayAllowed':False})
'''

def validate_ppm(raw):
    parts=raw.split(b'\n',3)
    if len(parts)!=4 or parts[0]!=b'P6'or parts[2]!=b'255':raise ValueError('screen-format')
    fields=parts[1].split()
    if len(fields)!=2 or not all(f.isdigit()for f in fields):raise ValueError('screen-dimensions')
    width,height=map(int,fields)
    if not 1<=width<=2048 or not 1<=height<=2048 or len(parts[3])!=width*height*3:raise ValueError('screen-pixels')
    return width,height


def _validate_lockscreen(raw):
    if validate_ppm(raw)!=(1280,800):raise ValueError('lockscreen-dimensions')
    pixels=raw.split(b'\n',3)[3]
    for rect,sha in [((10, 10, 74, 74), 'd14998919223673c68582e54b9d0079c44298f8af0e8a431fd934615a3db151c'), ((1196, 10, 1260, 74), '6e65971d9cbfa5dc152a0c09bab9c2bb85916ba652af7410023dbd166c6c6829'), ((10, 656, 74, 720), 'af4760a71a9d6b11a504399488800bd7325b0ef4693a50ad8aa1589ca125901a'), ((1196, 656, 1260, 720), '145ca649fd26fbf85ba927a88bb73095768e43154f6c1f7177ba9c261d4c99da')]:
        x0,y0,x1,y1=rect;crop=b''.join(pixels[(y*1280+x0)*3:(y*1280+x1)*3]for y in range(y0,y1))
        if hashlib.sha256(crop).hexdigest()!=sha:raise ValueError('lockscreen-background')

def _guarded_wake(raw,age,verify,fence,key,capture_post):
    _validate_lockscreen(raw)
    if type(age)not in(int,float)or not 0<=age<=5:raise ValueError('lockscreen-expired')
    verify();fence();verify();key();value=capture_post();verify();return value

_WAKE_BLOCK=r'''
  def wake_fence():
   screen_guard();need(time.monotonic()-captured_at<=5,'lockscreen-expired')
   f=os.open('wake-attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jobfd)
   try:
    body=json.dumps({'state':'consumed','diagnosticId':diagnostic,'qemu':children[1]['child'],'frameSha256':hashlib.sha256(raw).hexdigest()},sort_keys=True).encode()
    need(os.write(f,body)==len(body),'wake-fence-write');os.fsync(f);need(fp(os.fstat(f))==fp(os.stat('wake-attempt.json',dir_fd=jobfd,follow_symlinks=False)),'wake-fence-name');os.fsync(jobfd);screen_guard()
   finally:os.close(f)
  w=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);w.settimeout(10);ws=None
  try:
   screen_guard();w.connect(LEAF+'/qmp.sock');ws=w.makefile('rb')
   def wr(wanted):
    for _ in range(16):
     line=ws.readline(32769);need(0<len(line)<=32768 and line.endswith(b'\n'),'wake-response-cap');v=json.loads(line)
     if wanted is None:need('QMP'in v,'wake-greeting');return v
     if v.get('id')==wanted:need('return'in v and 'error'not in v,'wake-response');return v['return']
     need('event'in v,'wake-response-id')
    raise ValueError('wake-event-cap')
   wr(None);w.sendall(json.dumps({'execute':'qmp_capabilities','id':1}).encode()+b'\n');wr(1)
   def key():
    screen_guard();need(time.monotonic()-captured_at<=5,'lockscreen-expired')
    w.sendall(json.dumps({'execute':'send-key','arguments':{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100},'id':2}).encode()+b'\n');wr(2)
   def post():
    time.sleep(.75);screen_guard();need(not os.path.lexists(directory+'/post.ppm'),'wake-post-existing')
    w.sendall(json.dumps({'execute':'screendump','arguments':{'filename':directory+'/post.ppm'},'id':3}).encode()+b'\n');wr(3);screen_guard()
    pf=os.open('post.ppm',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jobfd)
    try:
     ps=os.fstat(pf);need(stat.S_ISREG(ps.st_mode)and ps.st_nlink==1 and ps.st_uid==os.geteuid()and 0<ps.st_size<=16777216,'wake-post-shape');os.fchmod(pf,0o600);ps=os.fstat(pf);body=os.read(pf,16777217)
     need(len(body)==ps.st_size and fp(ps)==fp(os.fstat(pf))==fp(os.stat('post.ppm',dir_fd=jobfd,follow_symlinks=False)),'wake-post-drift');validate_ppm(body);return body,ps
    finally:os.close(pf)
   raw,s=_guarded_wake(raw,time.monotonic()-captured_at,screen_guard,wake_fence,key,post)
  finally:
   if ws is not None:ws.close()
   w.close()
'''

def screen_program(record,diagnostic,wake=False,session_admission=None):
    if str(uuid.UUID(diagnostic))!=diagnostic:raise ValueError('diagnostic')
    if type(wake)is not bool:raise ValueError('fixed-screen-phase')
    if wake and diagnostic!=WAKE_CORRELATION:raise ValueError('fixed-wake-correlation')
    source,_=guest.program(record,diagnostic,diagnostic,observation='session')
    marker=" guards();child=call(LEAF+'/qga.sock','guest-exec',"
    if source.count(marker)!=1:raise ValueError('screen-factory')
    prefix=source.split(marker)[0]
    if wake:
        if not isinstance(session_admission,dict)or session_admission.get('qemu')!=record['result'].get('qemu')or type(session_admission.get('observedAtNs'))is not int:raise ValueError('wake-session-admission')
        prefix=prefix.replace(' def guards():\n', ' def guards():\n  need(0<=time.time_ns()-'+repr(session_admission['observedAtNs'])+'<=15_000_000_000,\'session-expired\')\n')
    import inspect
    # Defined before guard execution; no guest-exec/task/login source follows.
    start=prefix.index('\ntry:\n children=')
    prefix=prefix[:start]+'\n'+inspect.getsource(validate_ppm)+inspect.getsource(_validate_lockscreen)+inspect.getsource(_guarded_wake)+prefix[start:]
    if type(wake)is not bool:raise ValueError('fixed-screen-phase')
    if wake and diagnostic!=WAKE_CORRELATION:raise ValueError('fixed-wake-correlation')
    body=_SCREEN.replace('__TRANSFER__',repr(TRANSFER)).replace('__DIAGNOSTIC__',repr(diagnostic)).replace('__WAKE_BLOCK__',_WAKE_BLOCK if wake else '')
    return prefix+body

def _frame_create(capture,raw):
    validate_ppm(raw);capture._check()
    fd=os.open('frame.ppm',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=capture.fd)
    try:
        offset=0
        while offset<len(raw):
            written=os.write(fd,raw[offset:]);
            if written<=0:raise ValueError('frame-write')
            offset+=written
        os.fsync(fd);s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode)or s.st_nlink!=1 or s.st_uid!=os.getuid()or stat.S_IMODE(s.st_mode)!=0o600 or guest.recovery._fp(s)!=guest.recovery._fp(os.stat('frame.ppm',dir_fd=capture.fd,follow_symlinks=False)):raise ValueError('frame-private')
        capture._check();os.fsync(capture.fd)
        return {'sha256':hashlib.sha256(raw).hexdigest(),'generation':[getattr(s,k)for k in guest.recovery._FP_FIELDS]}
    finally:os.close(fd)

def _validate_session_facts(facts):
    if not isinstance(facts,dict)or facts.get('version')!=1 or facts.get('accountCount')!=1 or facts.get('processCount')!=2:raise ValueError('wake-session-facts')
    accounts=facts.get('accounts');processes=facts.get('processes')
    if accounts!=[{'expectedSid':True,'expectedName':True,'disabled':False,'lockedOut':False,'localAccount':True}]or not isinstance(processes,list)or len(processes)!=2:raise ValueError('wake-session-account')
    kinds={p.get('kind')for p in processes}
    if kinds!={'winlogon','logonui'}or any(p.get('ownerKnown')is not True or p.get('expectedUser')is not False or p.get('sessionId')!=1 for p in processes):raise ValueError('wake-session-owner')
    winlogon=next(p for p in processes if p['kind']=='winlogon');logon=next(p for p in processes if p['kind']=='logonui')
    if logon.get('parentPid')!=winlogon.get('pid'):raise ValueError('wake-session-lineage')


def _capture(root,wake=False):
    root=Path(root).resolve(strict=True);r=guest.recovery;original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION)
    diagnostic=WAKE_CORRELATION if wake else str(uuid.uuid4());leaf='windows-cp117-lock-wake-'+diagnostic if wake else 'windows-cp117-login-screen-'+diagnostic
    if wake and (root/'.runtime/parity-evidence'/leaf).exists():
        original.close();return {'state':'unknown','phase':'wake-consumed','replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    try:
        raw=r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin']);record=json.loads(raw)
        files={Path(__file__):None,Path(guest.__file__):GUEST_SHA,Path(session.__file__):SESSION_SHA}
        pins={str(path):r.authority._read_bound_file(path)for path in files}
        def verify():
            if r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin'])!=raw:raise ValueError('original-receipt')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('original-frame')
            sources=r.authority._source_pins(root);sources['recovery']=r.authority._read_bound_file(Path(r.__file__))
            if sources!=record['request']['sources']or sources['recovery']['sha256']!=guest.RECOVERY_SHA:raise ValueError('original-sources')
            for path,sha in files.items():
                current=r.authority._read_bound_file(path)
                if current!=pins[str(path)]or(sha is not None and current['sha256']!=sha):raise ValueError('screen-source')
        verify();outer=r.authority._outer_authority(root);config,target,_=r.authority.closure.base._descriptor(root)
        if str(target.fixture_transfer_root)!=TRANSFER:raise ValueError('screen-config-root')
        session_admission=None
        if wake:
            observed=guest.observe(root,observation='session')
            if observed.get('state')!='observed':raise ValueError('wake-current-session-unknown')
            _validate_session_facts(observed.get('facts'))
            current_capture=AuthorityCapture(root,observed['evidenceLeaf'])
            try:
                session_record=json.loads(r._local_read(current_capture,'result.json',observed['receipt']))
                if session_record['result'].get('state')!='observed'or session_record['result'].get('qemu')!=record['result']['qemu']or session_record['result'].get('facts')!=observed['facts']:raise ValueError('wake-session-original-receipt')
            finally:current_capture.close()
            session_admission={'qemu':record['result']['qemu'],'observedAtNs':__import__('time').time_ns(),'receipt':observed['receipt'],'evidenceLeaf':observed['evidenceLeaf'],'facts':observed['facts']}
            verify()
        source=screen_program(record,diagnostic,wake,session_admission)
        capture.create('request.json',json.dumps({'original':guest.ORIGINAL,'outerAuthority':outer,'sources':pins,'diagnosticId':diagnostic,'wakeRequested':wake,'sessionAdmission':session_admission,'programSha256':hashlib.sha256(source.encode()).hexdigest()},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
        argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();r.authority._verify_outer(root,{'outerAuthority':outer})
        if wake:
            capture.create('attempt.json',json.dumps({'diagnosticId':diagnostic,'state':'consumed','original':guest.ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
            verify();r.authority._verify_outer(root,{'outerAuthority':outer})
        completed=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
        capture.create('transport.stdout.private',completed.stdout);capture.create('transport.stderr.private',completed.stderr);os.fsync(capture.fd)
        if completed.returncode!=0 or len(completed.stdout)>1000000 or len(completed.stderr)>131072:raise ValueError('screen-transport')
        verify();r.authority._verify_outer(root,{'outerAuthority':outer});value=json.loads(completed.stdout)
        if value.get('state')!='observed':raise ValueError('screen-'+value.get('phase','unknown'))
        packed=base64.b64decode(value.pop('frameGzip'),validate=True)
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(packed))as z:frame=z.read(MAX_FRAME+1)
        if len(frame)>MAX_FRAME or hashlib.sha256(frame).hexdigest()!=value['frameSha256']or value['qemu']!=record['result']['qemu']or value['bootId']!=r.BOOT_ID:raise ValueError('screen-frame-binding')
        framepin=_frame_create(capture,frame);value['localFramePin']=framepin
        pin=capture.create('result.json',json.dumps(value,sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'observed','framePath':str(capture.path/'frame.ppm'),'receipt':pin,'evidenceLeaf':leaf,'appAdmission':False,'installerAction':False}
    except Exception as e:
        if isinstance(e,subprocess.TimeoutExpired):
            capture.create('partial.stdout.private',(e.stdout or b'')[:1000000]);capture.create('partial.stderr.private',(e.stderr or b'')[:131072])
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'receipt':pin,'evidenceLeaf':leaf,'replayAllowed':False}
    finally:original.close();capture.close()


def screen(root):
    return _capture(root,wake=False)

def wake(root):
    """One fixed Enter on the reviewed lock screen; never enters a credential."""
    return _capture(root,wake=True)

CREDENTIAL_CORRELATION='e0ffbb2a-e724-470b-9082-8f4a260b9a0b'
_VALIDITY_SHA='cdceba0ef4f1c613ece0556390fdc069b65068b89aa8c09049c4bc35a7dcae00'
_BOOTSTRAP_SHA='13197aa96813ba790182ff57555e44361e3e8671e2b1974ab3e1dbb80b576baa'
_TASK_HELPER_SHA='ed9738cd246eda8db24d05ca039b1b870940a5eb4f189ce6997442e53bfdebb3'


def _fixed_bootstrap(root):
    """Compile only two exact tracked factory definitions, without module hooks."""
    import ast,types
    path=Path(root)/'scripts/windows_credential_validity_qga.py'
    pin,raw=guest.recovery.authority._read_bound_file(path,retain_bytes=True)
    if pin['sha256']!=_VALIDITY_SHA:raise ValueError('validity-source')
    tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('_ps_literal','_bootstrap')]
    if len(nodes)!=2:raise ValueError('validity-factory')
    namespace={'CredentialProbeAdmission':object,'OPERATION':'windows-credential-validity-v1','MAX_HELPER_BYTES':131072,'MAX_CREDENTIAL_BYTES':512}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'fixed-validity-factory','exec'),namespace)
    admission=types.SimpleNamespace(correlation_id=CREDENTIAL_CORRELATION,expected_sid=guest.SID,account_name='vpncp117',helper_sha256=_TASK_HELPER_SHA)
    body=namespace['_bootstrap'](admission)
    if guest.recovery.authority._read_bound_file(path)!=pin:raise ValueError('validity-source-drift')
    return body,pin


def _configured_secret(root):
    r=guest.recovery;config,target,_=r.authority.closure.base._descriptor(root)
    _,_,_,_,account,sid,path=r.authority.closure.base.windows_credential_probe_ssh._descriptor(target)
    if account!='vpncp117'or sid!=guest.SID:raise ValueError('credential-account')
    pin,raw=r.authority._read_bound_file(path,retain_bytes=True)
    if stat.S_IMODE(pin['generation'][2])&0o077 or not 1<=len(raw)<=512:raise ValueError('credential-private')
    return raw,path,pin


def _credential_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('credential-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>8192:raise ValueError('credential-output-cap')
    first,sep,body=raw.partition(b'\n')
    if not sep or first.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if value.get('exitcode')!=0:raise ValueError('credential-exit')
    result=json.loads(body)
    if not isinstance(result,dict)or set(result)!={'operation','correlationId','expectedSid','success','errorCategory'}or result['operation']!='windows-credential-validity-v1'or result['correlationId']!=CREDENTIAL_CORRELATION or result['expectedSid']!=guest.SID or type(result['success'])is not bool or result['errorCategory']not in('none','invalid-credentials','account-restricted','unavailable')or result['success']!=(result['errorCategory']=='none'):raise ValueError('credential-schema')
    return result

_PROBE=r'''
 guards()
 import struct,base64
 parent=__TRANSFER__;parentfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);parentinfo=os.fstat(parentfd)
 need(stat.S_ISDIR(parentinfo.st_mode)and parentinfo.st_uid==os.geteuid()and stat.S_IMODE(parentinfo.st_mode)==0o700,'probe-parent');need(fp(parentinfo)==fp(os.lstat(parent)),'probe-parent-name')
 job='cp117-credential-'+CREDENTIAL_CORRELATION;os.mkdir(job,0o700,dir_fd=parentfd);os.fsync(parentfd);jobfd=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parentfd);jobinfo=fp(os.fstat(jobfd))
 def probe_guard():
  guards()
  need(all(getattr(os.fstat(parentfd),k)==getattr(os.lstat(parent),k)==getattr(parentinfo,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'probe-parent-drift')
  named=os.stat(job,dir_fd=parentfd,follow_symlinks=False);need(fp(named)==fp(os.fstat(jobfd)),'probe-held-directory')
  need(all(getattr(named,k)==jobinfo[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'probe-directory-drift')
 def probe_create(name,value):
  probe_guard();f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jobfd)
  try:
   raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();need(os.write(f,raw)==len(raw),'probe-write');os.fsync(f);s=os.fstat(f);need(fp(s)==fp(os.stat(name,dir_fd=jobfd,follow_symlinks=False))and s.st_nlink==1,'probe-file-name');os.fsync(jobfd);probe_guard();return {'fingerprint':fp(s),'sha256':hashlib.sha256(raw).hexdigest()}
  finally:os.close(f)
 def probe_read(name,pin):
  probe_guard();f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jobfd)
  try:
   before=os.fstat(f);need(stat.S_ISREG(before.st_mode)and before.st_uid==os.geteuid()and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size<=8192,'probe-record-private');need(fp(before)==pin['fingerprint'],'probe-record-generation');raw=os.read(f,8193);need(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==pin['sha256'],'probe-record-content');need(fp(before)==fp(os.fstat(f))==fp(os.stat(name,dir_fd=jobfd,follow_symlinks=False)),'probe-record-name');probe_guard()
  finally:os.close(f)
 intentpin=probe_create('intent.json',{'diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'qemu':children[1]['child'],'state':'consumed'})
 header=sys.stdin.buffer.read(4);need(len(header)==4,'private-header');length=int.from_bytes(header,'big');need(1<=length<=512,'private-input-cap')
 secret=sys.stdin.buffer.read(length);need(len(secret)==length,'private-input-short')
 helper=base64.b64decode(__HELPER__,validate=True);need(hashlib.sha256(helper).hexdigest()==__HELPER_SHA__,'credential-helper')
 payload=struct.pack('>4sIH',b'WCV1',len(helper),len(secret))+helper+secret;secret=b''
 encoded_input=base64.b64encode(payload).decode();payload=b''
 attemptpin=probe_create('attempt.json',{'state':'consumed','diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'qemu':children[1]['child']});probe_guard();probe_read('intent.json',intentpin);probe_read('attempt.json',attemptpin)
 child=call(LEAF+'/qga.sock','guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ENCODED],'input-data':encoded_input,'capture-output':True});encoded_input=''
 need(isinstance(child,dict)and type(child.get('pid'))is int and child['pid']>0,'credential-child');pid=child['pid']
 childpin=probe_create('child.json',{'diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'qemu':children[1]['child'],'pid':pid});event({'kind':'submitted','pid':pid,'hostChildPin':childpin,'hostLeafIdentity':{k:jobinfo[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')}})
 import select
 need(bool(select.select([sys.stdin],[],[],10)[0]),'local-anchor-deadline')
 need(sys.stdin.buffer.readline().decode('ascii').strip()==digest({'diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'pid':pid}),'local-anchor-ack')
 answer=None
 for poll in range(80):
  probe_guard();probe_read('intent.json',intentpin);probe_read('attempt.json',attemptpin);probe_read('child.json',childpin);value=call(LEAF+'/qga.sock','guest-exec-status',{'pid':pid});probe_guard();probe_read('child.json',childpin);event({'kind':'poll','pid':pid,'poll':poll+1,'exited':value.get('exited')if type(value.get('exited'))is bool else None})
  if value.get('exited')is True:
   event({'kind':'terminal','pid':pid,'poll':poll+1,'payload':value})
   answer=_credential_terminal(value,NONCE,BODY_SHA,pid)
   if answer is not None:break
  time.sleep(.25)
 need(answer is not None,'credential-observation-exhausted');guards()
 result({'state':'observed','credential':answer,'qemu':children[1]['child'],'guestChildPid':pid,'appAdmission':False,'installerAction':False})
except Exception as e:
 event({'kind':'exception','phase':str(e)if isinstance(e,ValueError)else type(e).__name__})
 result({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'appAdmission':False,'installerAction':False,'replayAllowed':False})
'''

def credential_program(root,record,nonce):
    import inspect
    body,pin=_fixed_bootstrap(root);sha=hashlib.sha256(body.encode('utf-16le')).hexdigest()
    # Filled from the exact tracked bootstrap, fixed SID, helper and correlation.
    if sha!=_BOOTSTRAP_SHA:raise ValueError('credential-body-source')
    hp,hb=guest.recovery.authority._read_bound_file(Path(root)/'scripts/windows_task_admission.ps1',retain_bytes=True)
    if hp['sha256']!=_TASK_HELPER_SHA:raise ValueError('credential-helper-source')
    source,_=guest.program(record,CREDENTIAL_CORRELATION,nonce,observation='session')
    marker=" guards();child=call(LEAF+'/qga.sock','guest-exec',"
    if source.count(marker)!=1:raise ValueError('credential-factory')
    prefix=source.split(marker)[0]
    header="[Console]::Out.WriteLine(('CP117-READ "+nonce+" "+sha+" '+$PID))\n"
    encoded=base64.b64encode((header+body).encode('utf-16le')).decode()
    oldsha='BODY_SHA='+repr('5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2')
    if prefix.count(oldsha)!=1:raise ValueError('credential-source-assignment')
    prefix=prefix.replace(oldsha,'BODY_SHA='+repr(sha))
    # Replace only the fixed validated session encoded literal; no arbitrary body.
    old,_=guest.encoded_read(nonce,observation='session');assignment='ENCODED='+repr(old)
    if prefix.count(assignment)!=1:raise ValueError('credential-command-assignment')
    prefix=prefix.replace(assignment,'ENCODED='+repr(encoded))
    parser=inspect.getsource(_credential_terminal)
    if parser.count('guest.SID')!=1:raise ValueError('credential-parser-source')
    parser=parser.replace('guest.SID',repr(guest.SID))
    start=prefix.index('\ntry:\n children=');prefix=prefix[:start]+'\nCREDENTIAL_CORRELATION='+repr(CREDENTIAL_CORRELATION)+'\n'+parser+prefix[start:]
    probe=_PROBE.replace('__TRANSFER__',repr(TRANSFER)).replace('__HELPER__',repr(base64.b64encode(hb).decode())).replace('__HELPER_SHA__',repr(_TASK_HELPER_SHA))
    return prefix+probe,sha,{str(Path(root)/'scripts/windows_credential_validity_qga.py'):pin,str(Path(root)/'scripts/windows_task_admission.ps1'):hp}


def _probe_stream(argv,capture,nonce,sha,qemu,secret):
    diagnostic=CREDENTIAL_CORRELATION;recovery=guest.recovery
    if not isinstance(secret,bytes)or not 1<=len(secret)<=512:raise ValueError("private-input-cap")
    p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();events=[];child=None;deadline=time.monotonic()+60
    selector.register(p.stdout,selectors.EVENT_READ,'stdout');selector.register(p.stderr,selectors.EVENT_READ,'stderr')
    try:
        p.stdin.write(len(secret).to_bytes(4,"big")+secret);p.stdin.flush();secret=b""
        while selector.get_map():
            if time.monotonic()>=deadline:raise ValueError('observer-deadline')
            for key,_ in selector.select(.25):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(data)
                if len(chunks[key.data])>262144:raise ValueError('observer-byte-cap')
                if key.data=='stderr':
                    pending.extend(data)
                    while b'\n'in pending:
                        line,rest=pending.split(b'\n',1);pending=bytearray(rest)
                        if not line.startswith(b'CP117-OBSERVE '):continue
                        event=json.loads(line[14:])
                        if any(event.get(k)!=v for k,v in{'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'qemu':qemu}.items()):raise ValueError('event-binding')
                        if event['kind']=='submitted':
                            if child is not None or type(event.get('pid'))is not int or event['pid']<=0:raise ValueError('one-child')
                            child=event['pid']
                            hp=event.get('hostChildPin');hi=event.get('hostLeafIdentity')
                            if not isinstance(hp,dict)or set(hp)!={'fingerprint','sha256'}or not isinstance(hi,dict)or set(hi)!={'st_dev','st_ino','st_mode','st_uid','st_gid'}:raise ValueError('host-child-authority')
                        elif event['kind']in('poll','terminal'):
                            if child is None or event.get('pid')!=child:raise ValueError('same-child')
                        elif event['kind']!='exception':raise ValueError('event-kind')
                        pin=capture.create('event-%d.json'%len(events),json.dumps(event,sort_keys=True).encode());os.fsync(capture.fd)
                        events.append({'event':event,'pin':pin})
                        if event['kind']=='submitted':
                            ack=recovery._digest({'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'pid':child})
                            p.stdin.write((ack+'\n').encode());p.stdin.flush()
        if p.wait(timeout=max(.001,deadline-time.monotonic()))!=0:raise ValueError('observer-exit')
        value=json.loads(chunks['stdout']);return value,events
    except BaseException as e:
        e.events=events
        if p.poll()is None:p.kill()  # Only owned local SSH observer, never guest/VM.
        p.wait(timeout=3);raise
    finally:
        capture.create('transport.stdout.private',bytes(chunks['stdout']));capture.create('transport.stderr.private',bytes(chunks['stderr']));os.fsync(capture.fd)
        selector.close();p.stdin.close();p.stdout.close();p.stderr.close()


def credential_probe(root):
    """One fixed LogonUser validity probe; never types a GUI password."""
    root=Path(root).resolve(strict=True);r=guest.recovery;leaf='windows-cp117-credential-'+CREDENTIAL_CORRELATION
    if (root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'credential-consumed','replayAllowed':False}
    original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION)
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);events=[];secret=b''
    try:
        raw=r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin']);record=json.loads(raw)
        files={Path(__file__):None,Path(guest.__file__):GUEST_SHA,Path(session.__file__):SESSION_SHA}
        pins={str(path):r.authority._read_bound_file(path)for path in files}
        nonce=str(uuid.uuid4());source,sha,extra=credential_program(root,record,nonce)
        for path,pin in extra.items():files[Path(path)]=pin['sha256'];pins[path]=pin
        def verify():
            if r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin'])!=raw:raise ValueError('original-receipt')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('original-frame')
            sources=r.authority._source_pins(root);sources['recovery']=r.authority._read_bound_file(Path(r.__file__))
            if sources!=record['request']['sources']or sources['recovery']['sha256']!=guest.RECOVERY_SHA:raise ValueError('original-sources')
            for path,digest in files.items():
                current=r.authority._read_bound_file(path)
                if current!=pins[str(path)]or(digest is not None and current['sha256']!=digest):raise ValueError('credential-source')
        verify();outer=r.authority._outer_authority(root);config,target,_=r.authority.closure.base._descriptor(root)
        if str(target.fixture_transfer_root)!=TRANSFER:raise ValueError('credential-config-root')
        secret,secret_path,secret_pin=_configured_secret(root)
        def credential_guard():
            if r.authority._read_bound_file(secret_path)!=secret_pin:raise ValueError('credential-generation')
            verify();r.authority._verify_outer(root,{'outerAuthority':outer})
        credential_guard()
        capture.create('request.json',json.dumps({'original':guest.ORIGINAL,'outerAuthority':outer,'sources':pins,'diagnosticId':CREDENTIAL_CORRELATION,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'credentialGeneration':secret_pin['generation']},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
        argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        capture.create('attempt.json',json.dumps({'diagnosticId':CREDENTIAL_CORRELATION,'state':'consumed','original':guest.ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd);credential_guard()
        value,events=_probe_stream(argv,capture,nonce,sha,record['result']['qemu'],secret);secret=b'';credential_guard()
        if value.get('state')=='observed':
            submitted=[e['event']for e in events if e['event']['kind']=='submitted']
            if value.get('qemu')!=record['result']['qemu']or len(submitted)!=1 or value.get('guestChildPid')!=submitted[0]['pid']:raise ValueError('credential-result-binding')
            terminals=[e['event']for e in events if e['event']['kind']=='terminal']
            if not terminals or _credential_terminal(terminals[-1]['payload'],nonce,sha,value['guestChildPid'])!=value.get('credential'):raise ValueError('credential-result-proof')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'credential':value.get('credential'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False,'replayAllowed':False}
    except Exception as e:
        events=getattr(e,'events',events);pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:secret=b'';original.close();capture.close()


# Protected record pins with explicit provenance below. The original unknown
# receipt is preserved; later held-file measurements are not creation authority.
_CREDENTIAL_RECORD_PINS={
 'result.json':{'generation':[16777234,111607697,33152,503,20,1,5363,1791049669402836973,1791049669402836973],'sha256':'f14750d7345d7c9ce0837167f89144d0ddebf601e2c9fddbc15556a666b5cf5d'},
 'request.json':{'generation':[16777234,111607686,33152,503,20,1,3337,1791049668047225015,1791049668047225015],'sha256':'a5bd8961738159c8eb6a683b5fd83ea5b9eafe014bf813b3e27b9d627f51d79e'},
 'remote.py':{'generation':[16777234,111607687,33152,503,20,1,50438,1791049668047399683,1791049668047399683],'sha256':'c5d3fcf0139392dbcab17991b26d08b0790acda8a2967fee101a610e0e7813bf'},
 'attempt.json':{'generation':[16777234,111607688,33152,503,20,1,305,1791049668060252367,1791049668060252367],'sha256':'81c221ff14e57d0f3f0d27b128a74c9f227f3adb6aee3e6b0a45b85a2c67455b'},
 'observed-source-manifest.json':{'generation':[16777234,111607839,33152,503,20,1,435,1791049768194465545,1791049768194465545],'sha256':'48b5e91145e2c7a9a755b231b08ad0514f5c4de171b2a7b6ee457469acf6cc66'}}
DERIVED_CORRELATION='3f392cc1-2ec8-49b0-b33c-c7a8d5dde0b9'

def _derive_credential_record(request,observation,attempt,qemu,generation):
    if request.get('original')!=guest.ORIGINAL or request.get('diagnosticId')!=CREDENTIAL_CORRELATION or request.get('sourceSha256')!=_BOOTSTRAP_SHA or request.get('credentialGeneration')!=generation:raise ValueError('derived-request')
    if attempt!={'diagnosticId':CREDENTIAL_CORRELATION,'state':'consumed','original':guest.ORIGINAL}:raise ValueError('derived-attempt')
    value=observation['result']
    if value!={'state':'unknown','phase':'NameError','appAdmission':False,'installerAction':False,'replayAllowed':False}:raise ValueError('derived-original-outcome')
    events=[item['event']for item in observation['events']];submitted=[e for e in events if e['kind']=='submitted'];terminals=[e for e in events if e['kind']=='terminal']
    if len(submitted)!=1 or submitted[0].get('pid')!=4996 or len(terminals)!=1:raise ValueError('derived-one-child')
    for event in events:
        if any(event.get(k)!=v for k,v in {'diagnosticId':CREDENTIAL_CORRELATION,'nonce':request['nonce'],'sourceSha256':_BOOTSTRAP_SHA,'qemu':qemu}.items()):raise ValueError('derived-event-binding')
        if event['kind']in('submitted','poll','terminal')and event.get('pid')!=4996:raise ValueError('derived-same-child')
    answer=_credential_terminal(terminals[0]['payload'],request['nonce'],_BOOTSTRAP_SHA,4996)
    if answer is None:raise ValueError('derived-terminal-binding')
    return answer

def derive_credential_proof(root):
    """Validate the retained original terminal; no transport or new guest query."""
    root=Path(root).resolve(strict=True);r=guest.recovery;leaf='windows-cp117-credential-derived-'+DERIVED_CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'derived-consumed','replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    observed=AuthorityCapture(root,'windows-cp117-credential-'+CREDENTIAL_CORRELATION);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION)
    try:
        sourcepin=r.authority._read_bound_file(Path(__file__));raw={name:r._local_read(observed,name,pin)for name,pin in _CREDENTIAL_RECORD_PINS.items()}
        originalraw=r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin']);record=json.loads(originalraw)
        for i,item in enumerate(record['authority']):
            r._validate_frame(item['frame'],record['request'],record['authority'][:i])
            if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('derived-original-frame')
        request=json.loads(raw['request.json']);result=json.loads(raw['result.json']);attempt=json.loads(raw['attempt.json']);manifest=json.loads(raw['observed-source-manifest.json'])
        for name,pin in manifest.items():
            archived=r._local_read(observed,name,pin)
            expected='8fb1744a2f5e63bb74beb25662699e5a5c08e91533caca9a6f5491a1aef02fa1'if name=='observed-login-helper-8fb1.py'else'e3b25d7753283ab562606ce41a41abdb85a05b7df039010cb03f93cf229c105f'
            if hashlib.sha256(archived).hexdigest()!=expected:raise ValueError('derived-archived-source')
        if set(manifest)!={'observed-login-helper-8fb1.py','observed-login-tests-e3b2.py'}:raise ValueError('derived-source-manifest')
        for i,item in enumerate(result['events']):
            if json.loads(r._local_read(observed,'event-%d.json'%i,item['pin']))!=item['event']:raise ValueError('derived-event-pin')
        if hashlib.sha256(raw['remote.py']).hexdigest()!=request['programSha256']:raise ValueError('derived-program')
        body,_=_fixed_bootstrap(root)
        import ast
        tree=ast.parse(raw['remote.py']);assignments={t.id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)for t in n.targets if isinstance(t,ast.Name)and t.id in('ENCODED','NONCE','BODY_SHA')}
        expected="[Console]::Out.WriteLine(('CP117-READ "+request['nonce']+" "+_BOOTSTRAP_SHA+" '+$PID))\n"+body
        if assignments!={'ENCODED':base64.b64encode(expected.encode('utf-16le')).decode(),'NONCE':request['nonce'],'BODY_SHA':_BOOTSTRAP_SHA}:raise ValueError('derived-executable-source')
        secret,path,secretpin=_configured_secret(root);secret=b''
        answer=_derive_credential_record(request,result,attempt,record['result']['qemu'],secretpin['generation'])
        # All retained authority is checked again; current native VM admission is
        # deliberately separate and mandatory before the later GUI login.
        for name,pin in _CREDENTIAL_RECORD_PINS.items():
            if r._local_read(observed,name,pin)!=raw[name]:raise ValueError('derived-record-drift')
        if r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin'])!=originalraw or r.authority._read_bound_file(path)!=secretpin or r.authority._read_bound_file(Path(__file__))!=sourcepin:raise ValueError('derived-authority-drift')
        proof={'state':'derived','credential':answer,'originalUnknownReceipt':_CREDENTIAL_RECORD_PINS['result.json'],'recordPins':_CREDENTIAL_RECORD_PINS,'pinProvenance':{'result.json':'retained-during-original-observation','events':'original-event-pins-retained-in-original-result','request.json':'held-file-measured-after-original-observation','remote.py':'held-file-measured-after-original-observation','attempt.json':'held-file-measured-after-original-observation','observed-source-manifest.json':'later-archive-independently-retained'},'source':sourcepin,'qemu':record['result']['qemu'],'guestChildPid':4996,'currentConfiguredCredentialGeneration':secretpin['generation'],'historicalRequestCredentialGeneration':request['credentialGeneration'],'historicalCredentialInputGenerationIndependentlyProven':False,'currentVmAdmission':False,'appAdmission':False,'installerAction':False,'replayAllowed':False}
        pin=capture.create('proof.json',json.dumps(proof,sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'derived','credential':answer,'receipt':pin,'evidenceLeaf':leaf,'historicalCredentialInputGenerationIndependentlyProven':False,'currentVmAdmission':False,'installerAction':False,'replayAllowed':False}
    except Exception as e:
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:capture.close();observed.close();original.close()


_LAYOUT_BODY_SHA='76de39b1cb92ef4bac1f80f59b80b6ca5a2617f9269a54797e12260022b302cd'
_LAYOUT_PS=r'''Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CP117LayoutRead {
 [DllImport("user32.dll")] public static extern IntPtr GetKeyboardLayout(uint threadId);
}
'@
 $ui=@($processes|Where-Object {$_.Name -ceq 'LogonUI.exe'})
 if($ui.Count -ne 1 -or $ui[0].SessionId -ne 1){throw 'LAYOUT_OWNER'}
 $u=$ui[0];$start=$u.CreationDate.ToUniversalTime().ToString('o')
 $p=[System.Diagnostics.Process]::GetProcessById([int]$u.ProcessId)
 try {
  $ids=@($p.Threads|ForEach-Object {[int]$_.Id}|Sort-Object)
  if($ids.Count -lt 1 -or $ids.Count -gt 128){throw 'LAYOUT_BOUND'}
  $hkl=@($ids|ForEach-Object {[pscustomobject]@{threadId=$_;hkl=([CP117LayoutRead]::GetKeyboardLayout([uint32]$_).ToInt64().ToString('X16'))}})
  $p.Refresh();$after=@($p.Threads|ForEach-Object {[int]$_.Id}|Sort-Object)
  if(($ids -join ',') -cne ($after -join ',')){throw 'LAYOUT_THREADS_CHANGED'}
 }finally{$p.Dispose()}
 $same=Get-CimInstance Win32_Process -Filter ('ProcessId='+$u.ProcessId)
 if($null -eq $same -or $same.CreationDate.ToUniversalTime().ToString('o') -cne $start -or $same.SessionId -ne 1 -or $same.ParentProcessId -ne $u.ParentProcessId -or $same.Name -cne 'LogonUI.exe'){throw 'LAYOUT_GENERATION'}
 $pre=[Microsoft.Win32.Registry]::Users.OpenSubKey('.DEFAULT\Keyboard Layout\Preload',$false)
 if($null -eq $pre){throw 'LAYOUT_PRELOAD_MISSING'}
 try {$preload=@($pre.GetValueNames()|Sort-Object|ForEach-Object {[pscustomobject]@{name=$_;value=[string]$pre.GetValue($_)}})}finally{$pre.Dispose()}
 if($preload.Count -gt 8){throw 'LAYOUT_PRELOAD_BOUND'}
 $sub=[Microsoft.Win32.Registry]::Users.OpenSubKey('.DEFAULT\Keyboard Layout\Substitutes',$false)
 $substitutes=@()
 if($null -ne $sub){try{$substitutes=@($sub.GetValueNames()|Sort-Object|ForEach-Object {[pscustomobject]@{name=$_;value=[string]$sub.GetValue($_)}})}finally{$sub.Dispose()}}
 if($substitutes.Count -gt 8){throw 'LAYOUT_SUBSTITUTION_BOUND'}
 $layout=[pscustomobject]@{pid=[int]$u.ProcessId;parentPid=[int]$u.ParentProcessId;sessionId=1;startedAtUtc=$start;threadCount=$hkl.Count;threads=$hkl;preload=$preload;substitutes=$substitutes}
'''

def _layout_body():
    if hashlib.sha256(session.BODY.encode('utf-16le')).hexdigest()!='5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2':raise ValueError('layout-session-source')
    marker=" [Console]::Out.WriteLine(([pscustomobject]@{version=1;accountCount="
    if session.BODY.count(marker)!=1:raise ValueError('layout-fixed-output')
    return session.BODY.replace(marker,_LAYOUT_PS+marker).replace('processes=$rows}|ConvertTo-Json -Depth 5','processes=$rows;layout=$layout}|ConvertTo-Json -Depth 6')

def _validate_layout_facts(facts):
    if not isinstance(facts,dict)or set(facts)!={'version','accountCount','accounts','processCount','processes','layout'}:raise ValueError('layout-schema')
    _validate_session_facts(facts)
    ui=next(p for p in facts['processes']if p['kind']=='logonui');layout=facts['layout']
    if not isinstance(layout,dict)or set(layout)!={'pid','parentPid','sessionId','startedAtUtc','threadCount','threads','preload','substitutes'}or any(layout[k]!=ui[k]for k in('pid','parentPid','sessionId','startedAtUtc')):raise ValueError('layout-original-owner')
    if type(layout['threadCount'])is not int or not 1<=layout['threadCount']<=128 or not isinstance(layout['threads'],list)or len(layout['threads'])!=layout['threadCount']:raise ValueError('layout-thread-bound')
    seen=set()
    for row in layout['threads']:
        if not isinstance(row,dict)or set(row)!={'threadId','hkl'}or type(row['threadId'])is not int or row['threadId']<=0 or row['threadId']in seen or not isinstance(row['hkl'],str)or len(row['hkl'])!=16 or any(c not in'0123456789ABCDEF'for c in row['hkl']):raise ValueError('layout-thread-schema')
        seen.add(row['threadId'])
    for key in('preload','substitutes'):
        if not isinstance(layout[key],list)or len(layout[key])>8 or any(not isinstance(row,dict)or set(row)!={'name','value'}or any(not isinstance(v,str)or len(v)>64 for v in row.values())for row in layout[key]):raise ValueError('layout-registry-schema')

def _validate_us_layout(facts):
    _validate_layout_facts(facts);layout=facts['layout']
    if layout['preload']!=[{'name':'1','value':'00000409'}]or layout['substitutes']or any(row['hkl']!='0000000004090409'for row in layout['threads']):raise ValueError('layout-us-unproven')

def _layout_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('layout-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('layout-output-cap')
    first,sep,body=raw.partition(b'\n')
    if not sep or first.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if value.get('exitcode')!=0:raise ValueError('layout-exit')
    facts=json.loads(body);_validate_layout_facts(facts);return facts

def layout_program(record,diagnostic,nonce):
    import inspect
    source,_=guest.program(record,diagnostic,nonce,observation='session');old,_=guest.encoded_read(nonce,observation='session');body=_layout_body();sha=hashlib.sha256(body.encode('utf-16le')).hexdigest()
    if sha!=_LAYOUT_BODY_SHA:raise ValueError('layout-fixed-body')
    header="[Console]::Out.WriteLine(('CP117-READ "+nonce+" "+sha+" '+$PID))\n"
    replacements={'ENCODED='+repr(old):'ENCODED='+repr(base64.b64encode((header+body).encode('utf-16le')).decode()),'BODY_SHA='+repr('5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2'):'BODY_SHA='+repr(sha),inspect.getsource(session.parse_terminal):inspect.getsource(_validate_session_facts)+inspect.getsource(_validate_layout_facts)+inspect.getsource(_layout_terminal),'answer=parse_terminal(value,NONCE,BODY_SHA,pid)':'answer=_layout_terminal(value,NONCE,BODY_SHA,pid)'}
    for old,new in replacements.items():
        if source.count(old)!=1:raise ValueError('layout-fixed-factory')
        source=source.replace(old,new)
    return source,sha


def layout_observe(root):
    recovery=guest.recovery;ORIGINAL=guest.ORIGINAL;RECOVERY_SHA=guest.RECOVERY_SHA;SOCKET_PROOF_SHA=guest.SOCKET_PROOF_SHA;observation='layout'
    root=Path(root).resolve(strict=True);original=AuthorityCapture(root,'windows-cp117-recovery-'+recovery.CORRELATION)
    diagnostic=str(uuid.uuid4());nonce=str(uuid.uuid4());leaf='windows-cp117-layout-observe-'+diagnostic
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);events=[]
    try:
        raw=recovery._local_read(original,ORIGINAL['name'],ORIGINAL['pin']);record=json.loads(raw)
        def verify():
            if recovery._local_read(original,ORIGINAL['name'],ORIGINAL['pin'])!=raw:raise ValueError('original-receipt')
            for i,item in enumerate(record['authority']):
                recovery._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(recovery._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('original-frame')
            now=recovery.authority._source_pins(root);now['recovery']=recovery.authority._read_bound_file(Path(recovery.__file__))
            if now!=record['request']['sources']or now['recovery']['sha256']!=RECOVERY_SHA:raise ValueError('original-sources')
        verify();source_pin=recovery.authority._read_bound_file(Path(__file__));session_pin=None;guest_pin=recovery.authority._read_bound_file(Path(guest.__file__))
        if guest_pin['sha256']!=GUEST_SHA:raise ValueError('layout-guest-source')
        if True:
            from . import windows_cp117_recovered_session_observe as session
            session_pin=recovery.authority._read_bound_file(Path(session.__file__))
            if session_pin['sha256']!=SESSION_SHA:raise ValueError('layout-session-source')
        outer=recovery.authority._outer_authority(root)
        source,sha=layout_program(record,diagnostic,nonce)
        capture.create('request.json',json.dumps({'original':ORIGINAL,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'outerAuthority':outer,'helper':source_pin,'observation':observation,'sessionHelper':session_pin,'socketProofSha256':SOCKET_PROOF_SHA},sort_keys=True).encode())
        capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=recovery.authority.closure.base._descriptor(root)
        argv=recovery.authority.closure.base.ssh_transport.build_ssh_argv(config,recovery.HOST,60,command=recovery.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        value,events=guest._stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'])
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'facts':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events)
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()
