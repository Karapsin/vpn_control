"""One read-only observation of independently pinned recovered CP117.

The original launch is immutable. Socket ownership includes accepted connections;
no process is adopted from a PID or pathname alone. No installer admission here.
"""
from __future__ import annotations
import base64, hashlib, inspect, json, os, selectors, subprocess, time, uuid
from pathlib import Path
from . import windows_cp117_fixture_recovery_short_socket as recovery
from .windows_diagnostic_authority_capture import AuthorityCapture
COMMON_SHA='b37e6f63dbd87343fa81c5892e15f83c088bc545ce5f51e564438b5955a865c6'
RECOVERY_SHA='51538dad4c2fa6591384081f5a0aabacada1e752c1afd6a6ed50ebed9596663e'
BODY_SHA='c5f97cc111d706a19abe5582aece64407767327964b8a0520d8d5cdf394076ad'
QGA_SHA='12552968248536d1751fd3ca7cd856f6935987be2080e387e7cc1af7189550b4'
SID='S-1-5-21-2404255130-2183793310-3766671872-1002'
ORIGINAL={'name':'result.json','pin':{'sha256':'962f0d0bee476b7b87a8262fdc2f945ee3744e18d88f349e63c84df2f18ad1e7','generation':[16777234,111570305,33152,503,20,1,8597,1791040184514608701,1791040184514608701]}}
# This TPM listener was proven by the source-bound native socket census after
# QEMU accepted its connection; the launch terminal pins QGA/QMP directly.
SOCKET_PROOF_SHA='39b84d8aad1d9ae07874804e0db57d74dbeef716a2ff114440ba5a4373642534'
TPM_SOCKET={'kernelInode':'1838335','fingerprint':{'st_dev':66307,'st_ino':103557350,'st_mode':49656,'st_uid':1000,'st_gid':1000,'st_nlink':1,'st_size':0,'st_mtime_ns':1791040184294027525,'st_ctime_ns':1791040184294027525}}

def validate_socket_rows(rows,owned,listener):
    if not isinstance(rows,list)or not 1<=len(rows)<=16:raise ValueError('socket-row-cap')
    seen=set();listeners=0
    for row in rows:
        if set(row)!={'flags','type','state','inode'}:raise ValueError('socket-row-shape')
        inode=row['inode']
        if not isinstance(inode,str)or not inode.isdecimal()or inode in seen or inode not in owned:raise ValueError('socket-owner')
        seen.add(inode)
        if row['type']!='0001':raise ValueError('socket-type')
        if(row['flags'],row['state'])==('00010000','01'):
            if inode!=listener:raise ValueError('socket-listener')
            listeners+=1
        elif(row['flags'],row['state'])!=('00000000','03'):raise ValueError('socket-state')
    if listeners!=1:raise ValueError('socket-listener')
    return sorted(seen)

def unix_rows(path):
    with open('/proc/net/unix')as stream:
        return [dict(flags=f[3],type=f[4],state=f[5],inode=f[6])for f in(line.split()for line in stream)if len(f)==8 and f[7]==path]

def fd_socket_inodes(pid):
    values=set()
    for name in os.listdir('/proc/%d/fd'%pid):
        try:link=os.readlink('/proc/%d/fd/%s'%(pid,name))
        except FileNotFoundError:continue
        if link.startswith('socket:[')and link.endswith(']'):values.add(link[8:-1])
    return values

def readiness_body():
    return recovery.authority.closure.base._readiness_script('2.1.19',SID)

def encoded_read(nonce,observation='readiness'):
    if str(uuid.UUID(nonce))!=nonce:raise ValueError('nonce')
    if observation=='readiness':body=readiness_body();expected=BODY_SHA
    elif observation=='session':
        from . import windows_cp117_recovered_session_observe as session
        body=session.BODY;expected='5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2'
    else:raise ValueError('fixed-observation-catalog')
    sha=hashlib.sha256(body.encode('utf-16le')).hexdigest()
    if sha!=expected:raise ValueError('fixed-readonly-body')
    header="[Console]::Out.WriteLine(('CP117-READ "+nonce+" "+sha+" '+$PID))\n"
    return base64.b64encode((header+body).encode('utf-16le')).decode(),sha

def parse_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('guest-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('guest-output-cap')
    first,sep,body=raw.partition(b'\n')
    expected=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode()
    if not sep or first.rstrip(b'\r')!=expected:return None  # Cached/unbound terminal; same PID only.
    if value.get('exitcode')!=0:raise ValueError('guest-exit')
    result=json.loads(body)
    keys={'version','code','installedVersion','productCount','activeCount','activeKinds','activeProcesses','workspaceLockPid','ownedExplorerCount'}
    if not isinstance(result,dict)or set(result)!=keys or result['version']!=1:raise ValueError('guest-schema')
    if type(result['activeCount'])is not int or not 0<=result['activeCount']<=16 or not isinstance(result['activeProcesses'],list)or len(result['activeProcesses'])!=result['activeCount']:raise ValueError('guest-process-schema')
    return result

_REMOTE=r'''
import signal
def reader_expired(*args):raise ValueError('reader-deadline')
signal.signal(signal.SIGALRM,reader_expired);signal.setitimer(signal.ITIMER_REAL,50)
proof=__PROOF__;D=__DIAGNOSTIC__;ENCODED=__ENCODED__;NONCE=__NONCE__;BODY_SHA=__BODY_SHA__;EXPECTED_SOCKETS=__SOCKETS__
def event(value):
 value={'diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'qemu':proof[1]['frame']['value']['child'],**value}
 print('CP117-OBSERVE '+json.dumps(value,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)
try:
 children=[item['frame']['value']for item in proof if item['frame']['kind']=='child'];need(len(children)==2,'children')
 first=children[0];ROOT_FD=os.open('/home/kardinal/vpn-control-windows-msi-acceptance-cp117',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);ROOT_IDENTITY=fp(os.fstat(ROOT_FD))
 LEAF_FD=os.open(LEAF,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def guards():
  need(open('/proc/sys/kernel/random/boot_id').read().strip()==R['bootId'],'boot')
  leaf_check();need(all(getattr(os.fstat(LEAF_FD),k)==first['leafIdentity'][k]for k in first['leafIdentity']),'leaf-original')
  need(read('intent.json',first['intentPin'])==REQUEST,'intent')
  attempt=read('attempt.json',first['attemptPin']);need(attempt['state']=='consumed'and attempt['requestSha256']==digest(REQUEST),'attempt')
  for value in children:
   role=value['role'];child_guard(value['child'],R[role+'Argv']);need(read(role+'.json',value['pin'])==value['child'],'child-anchor')
   names=('swtpm.sock',)if role=='tpm'else('qga.sock','qmp.sock')
   for name in names:
    path=LEAF+'/'+name;pin=EXPECTED_SOCKETS[name];need(fp(os.lstat(path))==pin['fingerprint'],'socket-generation')
    validate_socket_rows(unix_rows(path),fd_socket_inodes(value['child']['pid']),pin['kernelInode'])
   child_guard(value['child'],R[role+'Argv'])
  qemu=children[1]['child'];held=set()
  for n in os.listdir('/proc/%d/fd'%qemu['pid']):
   try:s=os.stat('/proc/%d/fd/%s'%(qemu['pid'],n));held.add((s.st_dev,s.st_ino))
   except FileNotFoundError:pass
  for path in('/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2','/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2','/home/kardinal/vpn-control-windows-msi-acceptance-cp117/OVMF_VARS.fd'):
   e=R['files'][path]['fingerprint'];s=os.lstat(path);need((s.st_dev,s.st_ino)==(e['st_dev'],e['st_ino'])in held,'held-source')
  leaf_check();need(read('intent.json',first['intentPin'])==REQUEST,'final-intent')
 guards();child=call(LEAF+'/qga.sock','guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',ENCODED],'capture-output':True})
 need(isinstance(child,dict)and type(child.get('pid'))is int and child['pid']>0,'guest-child');pid=child['pid'];event({'kind':'submitted','pid':pid})
 import select
 need(bool(select.select([sys.stdin],[],[],10)[0]),'local-anchor-deadline')
 need(sys.stdin.readline().strip()==digest({'diagnosticId':D,'nonce':NONCE,'sourceSha256':BODY_SHA,'pid':pid}),'local-anchor-ack')
 answer=None
 for poll in range(80):
  guards();value=call(LEAF+'/qga.sock','guest-exec-status',{'pid':pid})
  event({'kind':'poll','pid':pid,'poll':poll+1,'exited':value.get('exited')if type(value.get('exited'))is bool else None})
  if value.get('exited')is True:
   event({'kind':'terminal','pid':pid,'poll':poll+1,'payload':value})  # Retained before parsing.
   answer=parse_terminal(value,NONCE,BODY_SHA,pid)
   if answer is not None:break
  time.sleep(.25)
 need(answer is not None,'guest-observation-exhausted');guards()
 result({'state':'observed','facts':answer,'qemu':children[1]['child'],'guestChildPid':pid,'appAdmission':False,'installerAction':False})
except Exception as e:
 event({'kind':'exception','phase':str(e)if isinstance(e,ValueError)else type(e).__name__})
 result({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'appAdmission':False,'installerAction':False,'replayAllowed':False})
'''

def program(record,diagnostic,nonce,observation='readiness'):
    encoded,sha=encoded_read(nonce,observation)
    if hashlib.sha256(recovery._REMOTE_COMMON.encode()).hexdigest()!=COMMON_SHA:raise ValueError('recovery-common-source')
    if record['result'].get('state')!='running' or record['request']['recipeSha256']!=recovery._digest(recovery.recipe()):raise ValueError('original-running')
    sockets={**record['result']['sockets'],'swtpm.sock':TPM_SOCKET}
    common=recovery._REMOTE_COMMON.replace('__RECIPE__',repr(recovery.recipe())).replace('__REQUEST__',repr(record['request']))
    parser=parse_terminal
    if observation=='session':
        from . import windows_cp117_recovered_session_observe as session
        parser=session.parse_terminal
        if hashlib.sha256(inspect.getsource(parser).encode()).hexdigest()!='36471e2d5deec341811a7a4335e93c65f4a58864c09675ef460a94b816e5915a':raise ValueError('session-parser-source')
    support='\n'+''.join(inspect.getsource(f)+'\n'for f in(validate_socket_rows,unix_rows,fd_socket_inodes,parser))
    remote=_REMOTE.replace('__PROOF__',repr(record['authority'])).replace('__DIAGNOSTIC__',repr(diagnostic)).replace('__ENCODED__',repr(encoded)).replace('__NONCE__',repr(nonce)).replace('__BODY_SHA__',repr(sha)).replace('__SOCKETS__',repr(sockets))
    qga=recovery.authority.closure.base._QGA.split('\ndef read(')[0]
    if hashlib.sha256(qga.encode()).hexdigest()!=QGA_SHA:raise ValueError('qga-source')
    return common+'\n'+qga+support+remote,sha

def _stream(argv,capture,diagnostic,nonce,sha,qemu):
    p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();events=[];child=None;deadline=time.monotonic()+60
    selector.register(p.stdout,selectors.EVENT_READ,'stdout');selector.register(p.stderr,selectors.EVENT_READ,'stderr')
    try:
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

def observe(root,observation='readiness'):
    root=Path(root).resolve(strict=True);original=AuthorityCapture(root,'windows-cp117-recovery-'+recovery.CORRELATION)
    diagnostic=str(uuid.uuid4());nonce=str(uuid.uuid4());leaf='windows-cp117-guest-observe-'+diagnostic
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
        verify();source_pin=recovery.authority._read_bound_file(Path(__file__));session_pin=None
        if observation=='session':
            from . import windows_cp117_recovered_session_observe as session
            session_pin=recovery.authority._read_bound_file(Path(session.__file__))
        outer=recovery.authority._outer_authority(root)
        source,sha=program(record,diagnostic,nonce,observation)
        capture.create('request.json',json.dumps({'original':ORIGINAL,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'outerAuthority':outer,'helper':source_pin,'observation':observation,'sessionHelper':session_pin,'socketProofSha256':SOCKET_PROOF_SHA},sort_keys=True).encode())
        capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=recovery.authority.closure.base._descriptor(root)
        argv=recovery.authority.closure.base.ssh_transport.build_ssh_argv(config,recovery.HOST,60,command=recovery.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        value,events=_stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'])
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'facts':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events)
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()
