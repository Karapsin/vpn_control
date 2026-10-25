"""One fixed lock-page dismissal, followed immediately by read-only diagnostics."""
import ast,base64,gzip,hashlib,inspect,io,json,os,re,stat,subprocess,time
from pathlib import Path
from . import windows_cp117_secure_input_geometry_observe as geometry
from .windows_diagnostic_authority_capture import AuthorityCapture
login=geometry.login
CORRELATION='a847019a-8191-4c24-b8b2-69c6db9672f9'
GEOMETRY_SHA='9f9efa88a58588d67afbf52f68ca201b11575aa1edf744941f1c42894f1cddcf'
LOGIN_SHA='8cf4087a82f542f9c30ce8453cd3802b7daf0ef63ee06320edeeb97bb005b779'
SLOTS={
 'before1':('8fd845a1-cd39-45f7-b749-259f703845ae','2c07e6f7-7c14-4b6b-95a5-c109647f5131'),
 'before2':('064319b6-52f8-46e8-a2c6-e3592b67acaa','ebd4536c-6f4e-4f35-bd92-b6e246a537bf'),
 'after':('c7b37d44-ccec-422a-8283-8fce20b7af75','e0589490-2c69-4af1-bb2b-8b912f523afa')}
# Filled from the reviewed fixed templates; callers cannot choose source or nonce.
SLOT_HASHES={'before1': ('e819b4fdb52e37b029bc37169aa564a159cc95d052528943ffaccba20ad55df6', '71d14217da00f6ce4b471c9ee7212927c7fd526990042308d935a00a67bf7b1e'), 'before2': ('d9aa564ba41156bf88a8df335f6fa1dffd91bb4a2ea0a24bb04ab9ad352b6979', 'e0718a796fa02dda9345506cefea76e08bbe63223049fff23c85fb798c25fe8a'), 'after': ('33af50d9df7965c4b21c6416b780d27bebdb4745c9d6ca9c3811228cc3d382fe', 'e24232bdb51c55bc67092badc56ea09c79c3b170e29720a8096d3f40c1f7df3e')}
WAKE_FACTORY_SHA='7406ba6cc52a320258126365614a2aa2e74f9824a1304cc262eceea8b31074fb'

def _check_factories():
 r=login.guest.recovery
 if r.authority._read_bound_file(Path(geometry.__file__))['sha256']!=GEOMETRY_SHA or r.authority._read_bound_file(Path(login.__file__))['sha256']!=LOGIN_SHA:raise ValueError('dismiss-factory-source')
 geometry._factories()
 if hashlib.sha256((inspect.getsource(login.screen_program)+login._SCREEN+login._WAKE_BLOCK+inspect.getsource(login._guarded_wake)+inspect.getsource(login._validate_lockscreen)+inspect.getsource(login.validate_ppm)).encode()).hexdigest()!=WAKE_FACTORY_SHA:raise ValueError('dismiss-wake-source')

def slot_program(record,slot):
 if slot not in SLOTS:raise ValueError('dismiss-fixed-slot')
 _check_factories();correlation,nonce=SLOTS[slot]
 remote,_=geometry.program(record);oldparent,oldchild,oldsha=geometry.bodies()
 child=oldchild.replace(geometry.CORRELATION,correlation).replace(geometry.NONCE,nonce)
 sha=hashlib.sha256(child.encode('utf-16le')).hexdigest()
 parent=oldparent.replace(geometry.NONCE,nonce).replace(geometry.CORRELATION,correlation).replace(oldsha,sha).replace(base64.b64encode(oldchild.encode('utf-16le')).decode(),base64.b64encode(child.encode('utf-16le')).decode())
 psha=hashlib.sha256(parent.encode('utf-16le')).hexdigest()
 if (psha,sha)!=SLOT_HASHES[slot]or len(base64.b64encode(child.encode('utf-16le')))>30000 or len(parent.encode())>65536:raise ValueError('dismiss-slot-source')
 tree=ast.parse(remote);encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
 bootstrap=base64.b64decode(encoded).decode('utf-16le').replace(geometry.NONCE,nonce).replace(geometry.PARENT_SHA,psha)
 oldinput=base64.b64encode(len(oldparent.encode()).to_bytes(4,'big')+oldparent.encode()).decode();newinput=base64.b64encode(len(parent.encode()).to_bytes(4,'big')+parent.encode()).decode()
 for old,new in [(repr(encoded),repr(base64.b64encode(bootstrap.encode('utf-16le')).decode())),(repr(oldinput),repr(newinput)),(geometry.CORRELATION,correlation),(geometry.NONCE,nonce),(geometry.CHILD_SHA,sha),(geometry.PARENT_SHA,psha)]:
  if old not in remote:raise ValueError('dismiss-slot-factory')
  remote=remote.replace(old,new)
 compile(remote,'fixed-dismiss-reader','exec');return remote,psha

def _no_edit(value):
 if value.get('state')!='observed':raise ValueError('dismiss-read-unknown')
 answer=value['facts'];geometry.validate_semantic(answer);s=answer['facts']['secureInput']
 if any(n['controlId']==50004 for n in s['nodes']):raise ValueError('dismiss-edit-present')
 return s

def _admit_pair(first,second,now):
 _no_edit(first['value']);_no_edit(second['value'])
 if not 0<=now-first['observedAtNs']<=30_000_000_000 or not 0<=now-second['observedAtNs']<=15_000_000_000:raise ValueError('dismiss-before-expired')
 a=first['value']['facts'];b=second['value']['facts']
 if a['facts']['secureInput']['nodes']!=b['facts']['secureInput']['nodes']or a['facts']['processes']!=b['facts']['processes']:raise ValueError('dismiss-before-drift')


def _frame_authority(value,qemu):
 fields={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}
 before=value.get('beforeFrameAuthority');attempt=value.get('wakeAuthority')
 if not isinstance(before,dict)or set(before)!={'path','generation','sha256'}or before['path']!=login.TRANSFER+'/cp117-login-screen-'+CORRELATION+'/frame.ppm':raise ValueError('dismiss-preframe-schema')
 def private(gen,cap):
  if not isinstance(gen,dict)or set(gen)!=fields or any(type(v)is not int for v in gen.values())or gen['st_dev']<=0 or gen['st_ino']<=0 or gen['st_mode']!=stat.S_IFREG|0o600 or gen['st_uid']!=1000 or gen['st_gid']!=1000 or gen['st_nlink']!=1 or not 0<gen['st_size']<=cap or gen['st_mtime_ns']<=0 or gen['st_ctime_ns']<=0:raise ValueError('dismiss-frame-generation')
 private(before['generation'],login.MAX_FRAME)
 if before['generation']['st_size']!=3072016 or not isinstance(before['sha256'],str)or not re.fullmatch('[0-9a-f]{64}',before['sha256']):raise ValueError('dismiss-preframe-binding')
 if not isinstance(attempt,dict)or set(attempt)!={'generation','sha256','record'}:raise ValueError('dismiss-attempt-schema')
 private(attempt['generation'],8192);record=attempt['record']
 if not isinstance(record,dict)or set(record)!={'state','diagnosticId','qemu','frameSha256'}or record!={'state':'consumed','diagnosticId':CORRELATION,'qemu':qemu,'frameSha256':before['sha256']}:raise ValueError('dismiss-attempt-binding')
 raw=json.dumps(record,sort_keys=True).encode()
 if attempt['sha256']!=hashlib.sha256(raw).hexdigest()or attempt['generation']['st_size']!=len(raw):raise ValueError('dismiss-attempt-content')
 return before


def wake_program(record,admission):
 if not isinstance(admission,dict)or type(admission.get('observedAtNs'))is not int or admission['observedAtNs']<=0:raise ValueError('dismiss-admission-shape')
 _check_factories();source=login.screen_program(record,CORRELATION,wake=False)
 if source.count("  packed=gzip.compress(raw,mtime=0);")!=1:raise ValueError('dismiss-screen-factory')
 marker='  validate_ppm(raw);screen_guard()\n'
 if source.count(marker)!=1:raise ValueError('dismiss-screen-read')
 extra=r"""  os.fsync(fd);os.fsync(jobfd);before_authority={'path':directory+'/frame.ppm','generation':fp(s),'sha256':hashlib.sha256(raw).hexdigest()};wake_authority={};original_screen_guard=screen_guard
  def screen_guard():
   original_screen_guard();need(fp(os.fstat(fd))==before_authority['generation']==fp(os.stat('frame.ppm',dir_fd=jobfd,follow_symlinks=False)),'dismiss-preframe-drift')
   if wake_authority:
    af=os.open('wake-attempt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jobfd)
    try:
     need(fp(os.fstat(af))==wake_authority['generation'],'dismiss-attempt-drift');ab=os.read(af,8193);need(hashlib.sha256(ab).hexdigest()==wake_authority['sha256']and fp(os.fstat(af))==wake_authority['generation']==fp(os.stat('wake-attempt.json',dir_fd=jobfd,follow_symlinks=False)),'dismiss-attempt-drift')
    finally:os.close(af)
   original_screen_guard()
"""
 block=login._WAKE_BLOCK.replace("os.fsync(f);need(fp(os.fstat(f))", "os.fsync(f);wake_authority.update({'generation':fp(os.fstat(f)),'sha256':hashlib.sha256(body).hexdigest(),'record':json.loads(body)});need(fp(os.fstat(f))")
 source=source.replace(marker,marker+extra+block)
 source=source.replace(" def guards():\n"," def guards():\n  need(0<=time.time_ns()-"+str(admission['observedAtNs'])+"<=15_000_000_000,'dismiss-session-expired')\n")
 source=source.replace("'appAdmission':False,'installerAction':False})","'beforeFrameAuthority':before_authority,'wakeAuthority':wake_authority,'appAdmission':False,'installerAction':False})",1)
 # Existing QMP ret hold-time 100 automatically releases; only the strict clock-page path reaches it.
 if source.count("'execute':'send-key'")!=1 or "'data':'ret'"not in source or "'hold-time':100"not in source or 'guest-exec' in source:raise ValueError('dismiss-only-one-key')
 compile(source,'fixed-dismiss-wake','exec');return source


def _sequence(read,admit,wake,record):
 first=read('before1');record('before1',first);_no_edit(first['value'])
 second=read('before2');record('before2',second);admit(first,second)
 value=wake(second);record('wake',value)
 if value.get('state')!='observed':raise ValueError('dismiss-wake-unknown')
 after=read('after');record('after',after)
 if after['value'].get('state')!='observed':raise ValueError('dismiss-after-unknown')
 return {'state':'observed','after':after['value'],'keyboardAdmission':False,'passwordTyped':False,'loginSubmitted':False,'installerAction':False}


def start(root):
 root=Path(root).resolve(strict=True);leaf='windows-cp117-dismiss-observe-'+CORRELATION
 if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'dismiss-consumed','replayAllowed':False}
 (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);r=login.guest.recovery;original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);events=[]
 try:
  raw=r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin']);record=json.loads(raw)
  modules=(geometry,geometry.secure,login,login.guest,login.session);pins={str(Path(m.__file__)):r.authority._read_bound_file(Path(m.__file__))for m in modules};own=r.authority._read_bound_file(Path(__file__));outer=r.authority._outer_authority(root)
  def verify():
   _check_factories()
   if r.authority._read_bound_file(Path(__file__))!=own or any(r.authority._read_bound_file(Path(p))!=pin for p,pin in pins.items()):raise ValueError('dismiss-source-drift')
   if r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin'])!=raw:raise ValueError('dismiss-original-drift')
   for i,item in enumerate(record['authority']):
    r._validate_frame(item['frame'],record['request'],record['authority'][:i])
    if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('dismiss-original-frame')
   sources=r.authority._source_pins(root);sources['recovery']=r.authority._read_bound_file(Path(r.__file__))
   if sources!=record['request']['sources']:raise ValueError('dismiss-original-source')
   r.authority._verify_outer(root,{'outerAuthority':outer})
  config,target,_=r.authority.closure.base._descriptor(root)
  if str(target.fixture_transfer_root)!=login.TRANSFER:raise ValueError('dismiss-transfer-root')
  verify();capture.create('request.json',json.dumps({'original':login.guest.ORIGINAL,'source':own,'sources':pins,'outerAuthority':outer,'slots':SLOTS,'slotHashes':SLOT_HASHES,'keyboardAdmission':False},sort_keys=True).encode());os.fsync(capture.fd)
  def save(name,value):capture.create(name+'.json',json.dumps(value,sort_keys=True).encode());os.fsync(capture.fd)
  def read(slot):
   corr,nonce=SLOTS[slot];local='windows-dismiss-read-'+corr;(root/'.runtime/parity-evidence'/local).mkdir(mode=0o700);c=AuthorityCapture(root,local)
   try:
    verify();source,sha=slot_program(record,slot);c.create('remote.py',source.encode());c.create('request.json',json.dumps({'slot':slot,'nonce':nonce,'sourceSha256':sha,'original':login.guest.ORIGINAL},sort_keys=True).encode());os.fsync(c.fd)
    argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source));verify()
    value,trace=login.guest._stream(argv,c,corr,nonce,sha,record['result']['qemu']);observed=time.time_ns();verify();pin=c.create('result.json',json.dumps({'result':value,'events':trace},sort_keys=True).encode());os.fsync(c.fd)
    return {'value':value,'observedAtNs':observed,'evidenceLeaf':local,'receipt':pin}
   finally:c.close()
  def admit(first,second):verify();_admit_pair(first,second,time.time_ns())
  def wake(second):
   verify();source=wake_program(record,second);capture.create('wake.remote.py',source.encode());os.fsync(capture.fd)
   argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source));verify()
   capture.create('wake-attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'before2':second['receipt']},sort_keys=True).encode());os.fsync(capture.fd);verify()
   try:completed=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
   except subprocess.TimeoutExpired as e:
    capture.create('wake.stdout.partial',(e.stdout or b'')[:1000000]);capture.create('wake.stderr.partial',(e.stderr or b'')[:131072]);os.fsync(capture.fd);raise
   capture.create('wake.stdout.private',completed.stdout[:1000000]);capture.create('wake.stderr.private',completed.stderr[:131072]);os.fsync(capture.fd);verify()
   if completed.returncode!=0 or len(completed.stdout)>1000000 or len(completed.stderr)>131072:raise ValueError('dismiss-wake-transport')
   value=json.loads(completed.stdout)
   if value.get('state')!='observed':return value
   _frame_authority(value,record['result']['qemu'])
   packed=base64.b64decode(value.pop('frameGzip'),validate=True)
   with gzip.GzipFile(fileobj=io.BytesIO(packed))as z:frame=z.read(login.MAX_FRAME+1)
   if len(frame)>login.MAX_FRAME or hashlib.sha256(frame).hexdigest()!=value['frameSha256']or value['qemu']!=record['result']['qemu']or value['bootId']!=r.BOOT_ID:raise ValueError('dismiss-post-frame')
   value['localFramePin']=login._frame_create(capture,frame);value['framePath']=str(capture.path/'frame.ppm');verify();return value
  outcome=_sequence(read,admit,wake,save);verify();pin=capture.create('result.json',json.dumps(outcome,sort_keys=True).encode());os.fsync(capture.fd)
  return {'state':'observed','evidenceLeaf':leaf,'receipt':pin,'keyboardAdmission':False,'passwordTyped':False,'loginSubmitted':False,'installerAction':False}
 except Exception as e:
  pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'replayAllowed':False},sort_keys=True).encode());os.fsync(capture.fd)
  return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
 finally:original.close();capture.close()
