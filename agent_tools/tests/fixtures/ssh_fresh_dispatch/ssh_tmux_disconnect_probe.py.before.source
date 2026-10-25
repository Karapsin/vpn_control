"""Fixed inert20 tmux probe; direct caller retains its own SSH child handle.

Use one Probe object for prepare/release/disconnect/observe. Never reconstruct a
signal target from a supplied PID. No master control, credentials or packages.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
from uuid import UUID, uuid4
import re
from . import ssh_gateway_tmux_master as pins, ssh_transport as transport
from . import private_inventory_lock as private

OWNER_SHA = '0a78dcdeafa04e58dacaff5262851656e56b2fd6c7abbe62e821c553c3267c0e'
LIMIT = 4096
EXEC = "import json,os,resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,resource.getrlimit(resource.RLIMIT_FSIZE)[1]));a=json.loads(sys.argv[1]);os.execv(a[0],a)"

# Both scripts use the already reviewed private-file/process/tmux pin utilities.
# The packet contains hashes and fixed purpose/hop/correlation, not credentials.
WORKER = r'''
import base64,hashlib,json,os,pathlib,sys,time
job=pathlib.Path(sys.argv[1]);source=(job/'owner.py').read_bytes()
if hashlib.sha256(source).hexdigest()!=sys.argv[2]:raise SystemExit(73)
ns={'__name__':'probe_pin_utilities','__file__':str(job/'owner.py')};exec(compile(source,ns['__file__'],'exec'),ns)
with ns['Authority']() as a:
 d=a.directory(job,True);intent=a.capture(job/'intent.json');packet=ns['value'](intent.body)
 own=a.capture(job/'owner.py');worker=a.capture(job/'worker.py')
 if own.pin['sha256']!=packet['ownerSha'] or worker.pin['sha256']!=packet['workerSha']:raise SystemExit(73)
 for _ in range(600):
  if (job/'release.json').exists():break
  time.sleep(.05)
 else:raise SystemExit(72)
 anchor=a.capture(job/'anchor.json');value=ns['value'](anchor.body)
 launch=a.capture(job/'launch.intent.json')
 release=a.capture(job/'release.json');gate=ns['value'](release.body)
 fence=a.capture(job/'release.intent.json')
 if gate!={'anchorPin':anchor.pin,'fencePin':fence.pin} or ns['value'](fence.body)!={'anchorPin':anchor.pin} or value['intentPin']!=intent.pin or value['sourcePin']!=own.pin or value['workerPin']!=worker.pin or ns['value'](launch.body)!={'packetSha':ns['sha'](ns['canonical'](packet))} or ns['proc'](os.getpid())!=value['pane'] or ns['boot']()!=value['bootId']:raise SystemExit(74)
 ns['owners'](a,job,value);a.guard()
 fold=hashlib.sha256()
 for sequence in range(1,21):
  time.sleep(1)
  a.guard()
  body=ns['canonical']({'sequence':sequence,'anchorPin':anchor.pin,'releasePin':release.pin,'pane':value['pane']})
  name='beat-%02d.json'%sequence;ns['create'](d,name,body);a.capture(job/name);fold.update(body)
 a.guard()
 ns['create'](d,'terminal.json',ns['canonical']({'sequence':20,'anchorPin':anchor.pin,'releasePin':release.pin,'pane':value['pane'],'heartbeatsSha256':fold.hexdigest(),'exitCode':0}))
'''.strip()

REMOTE = r'''
import base64,hashlib,json,os,pathlib,re,select,shlex,subprocess,sys,time
from uuid import UUID
if hashlib.sha256(OWNER_SOURCE).hexdigest()!=OWNER_SHA:raise ValueError('source')
ns={'__name__':'probe_pin_utilities','__file__':'held-probe-pins'};exec(compile(OWNER_SOURCE,ns['__file__'],'exec'),ns)
request=json.loads(sys.stdin.buffer.readline(16385));action=request['action'];packet=request['packet']
if set(request)!={'action','packet','anchorPin'} or action not in ('prepare','release','observe') or set(packet)!={'version','purpose','hop','correlationId','configSha','sourceSha','ownerSha','workerSha'} or type(packet['version'])is not int or packet['version']!=1 or packet['purpose']!='inert-tmux-disconnect20' or packet['hop'] not in ('gateway','archlinux') or str(UUID(packet['correlationId']))!=packet['correlationId'] or packet['ownerSha']!=OWNER_SHA or packet['workerSha']!=ns['sha'](WORKER_SOURCE) or any(not re.fullmatch('[0-9a-f]{64}',packet[k]) for k in ('configSha','sourceSha','ownerSha','workerSha')):raise ValueError('packet')
parent=pathlib.Path.home()/'.vtd';job=parent/UUID(packet['correlationId']).hex[:16];session='vtd-'+job.name
if len(os.fsencode(job/'t'))>=100:raise ValueError('path_bound')
with ns['Authority']() as a:
 home=a.directory(pathlib.Path.home())
 if action=='prepare':
  if not os.path.lexists(parent):os.mkdir('.vtd',0o700,dir_fd=home.fd);os.fsync(home.fd)
  p=a.directory(parent,True)
  os.mkdir(job.name,0o700,dir_fd=p.fd);os.fsync(p.fd);d=a.directory(job,True)
  ns['create'](d,'intent.json',ns['canonical'](packet));a.capture(job/'intent.json')
  ns['create'](d,'owner.py',OWNER_SOURCE);owner=a.capture(job/'owner.py')
  ns['create'](d,'worker.py',WORKER_SOURCE);worker=a.capture(job/'worker.py')
  ns['create'](d,'launch.intent.json',ns['canonical']({'packetSha':ns['sha'](ns['canonical'](packet))}));a.capture(job/'launch.intent.json')
  loader="import hashlib,os,pathlib,stat,sys;p=pathlib.Path(sys.argv[1]);f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW);g=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);s=os.fstat(f);b=os.read(f,262145);assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==384 and len(b)==s.st_size and hashlib.sha256(b).hexdigest()==sys.argv[2] and g(os.fstat(f))==g(s) and g(p.lstat())==g(s);sys.argv=[str(p),sys.argv[3],sys.argv[4]];exec(compile(b,str(p),'exec'))"
  command=shlex.join(['exec','/usr/bin/python3','-I','-B','-c',loader,str(job/'worker.py'),packet['workerSha'],str(job),OWNER_SHA])
  a.guard();a.generations()
  result=ns['tmux'](job,'new-session','-d','-s',session,'--',command)
  if result.returncode:raise ValueError('submit_unknown')
  for _ in range(100):
   result=ns['tmux'](job,'display-message','-p','-t',session,'#{pid} #{pane_pid}')
   if result.returncode==0 and re.fullmatch(rb'[1-9][0-9]* [1-9][0-9]*\n?',result.stdout):break
   time.sleep(.02)
  else:raise ValueError('owners_unknown')
  server,pane=map(int,result.stdout.split());socket=ns['generation']((job/'t').lstat())
  anchor={'intentPin':a.files[job/'intent.json'].pin,'sourcePin':owner.pin,'workerPin':worker.pin,'server':ns['proc'](server),'pane':ns['proc'](pane),'socket':socket,'session':session,'bootId':ns['boot']()}
  ns['owners'](a,job,anchor);a.guard();pin=ns['create'](d,'anchor.json',ns['canonical'](anchor))
  response={'state':'prepared','anchor':anchor,'anchorPin':pin}
 else:
  a.directory(parent,True);d=a.directory(job,True)
  intent=a.capture(job/'intent.json');owner=a.capture(job/'owner.py');worker=a.capture(job/'worker.py');launch=a.capture(job/'launch.intent.json')
  anchor=a.capture(job/'anchor.json');value=ns['value'](anchor.body)
  if ns['value'](intent.body)!=packet or owner.pin['sha256']!=OWNER_SHA or worker.pin['sha256']!=packet['workerSha'] or ns['value'](launch.body)!={'packetSha':ns['sha'](ns['canonical'](packet))} or anchor.pin!=request['anchorPin'] or value['intentPin']!=intent.pin or value['sourcePin']!=owner.pin or value['workerPin']!=worker.pin or value['bootId']!=ns['boot']():raise ValueError('history_changed')
  if action=='release':
   ns['owners'](a,job,value);a.guard();fence=ns['create'](d,'release.intent.json',ns['canonical']({'anchorPin':anchor.pin}));a.capture(job/'release.intent.json');a.guard()
   pin=ns['create'](d,'release.json',ns['canonical']({'anchorPin':anchor.pin,'fencePin':fence}));a.capture(job/'release.json');a.guard()
   response={'state':'released','anchorPin':anchor.pin,'releasePin':pin}
  else:
   fold=hashlib.sha256();count=0
   if (job/'release.json').exists():
    release=a.capture(job/'release.json');fence=a.capture(job/'release.intent.json')
    if ns['value'](release.body)!={'anchorPin':anchor.pin,'fencePin':fence.pin} or ns['value'](fence.body)!={'anchorPin':anchor.pin}:raise ValueError('release_changed')
    for sequence in range(1,21):
     name='beat-%02d.json'%sequence
     if not (job/name).exists():break
     beat=a.capture(job/name)
     if ns['value'](beat.body)!={'sequence':sequence,'anchorPin':anchor.pin,'releasePin':release.pin,'pane':value['pane']}:raise ValueError('heartbeat_changed')
     fold.update(beat.body);count=sequence
   if (job/'terminal.json').exists():
    terminal=a.capture(job/'terminal.json')
    if count!=20 or ns['value'](terminal.body)!={'sequence':20,'anchorPin':anchor.pin,'releasePin':release.pin,'pane':value['pane'],'heartbeatsSha256':fold.hexdigest(),'exitCode':0}:raise ValueError('terminal_changed')
    response={'state':'completed','anchorPin':anchor.pin,'sequence':20,'terminalPin':terminal.pin}
   else:
    ns['owners'](a,job,value);response={'state':'running' if count else ('released' if (job/'release.json').exists() else 'prepared'),'anchorPin':anchor.pin,'sequence':count}
   a.guard();a.generations()
 sys.stdout.buffer.write(ns['canonical'](response)+b'\n');sys.stdout.buffer.flush()
 if action=='prepare':
  # Only this new client remains connected; EOF/timeout has no worker action.
  select.select([sys.stdin.buffer],[],[],55)
'''.strip()


def _birth(child):
    pins.need(child.poll() is None,'client_ended')
    result=subprocess.run(['/bin/ps','-p',str(child.pid),'-o','uid=','-o','ppid=','-o','lstart=','-o','comm='],capture_output=True,timeout=2,check=False)
    fields=result.stdout.split();pins.need(result.returncode==0 and len(fields)>=8 and fields[:2]==[str(os.getuid()).encode(),str(os.getpid()).encode()],'client_identity')
    pins.need(child.poll() is None,'client_ended');return {'pid':child.pid,'birthSha':pins.sha(result.stdout)}


def _pin(value):
    pins.need(type(value)is dict and set(value)=={'generation','sha256'} and type(value['generation'])is list
              and len(value['generation'])==9 and all(type(x)is int and x>=0 for x in value['generation'])
              and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'reply_pin')


class Probe:
    """Single operator, single correlation. Only this object's child may close."""
    def __init__(self,root,hop,correlation_id):
        pins.need(hop in ('gateway','archlinux') and type(correlation_id)is str and str(UUID(correlation_id))==correlation_id,'inputs')
        self.root=Path(root).absolute();self.presented=private.PresentedPath(self.root);self.root=self.presented.canonical
        self.authority=pins.Authority();self.hop=hop;self.correlation=correlation_id;self.anchor=None;self.client=None;self.birth=None;self.raw_fds=[]
        for module in (sys.modules[__name__],pins,transport,private):self.authority.capture(Path(module.__file__).absolute(),private=False)
        self.config_pin=self.authority.capture(self.root/transport.CONFIG_FILENAME)
        self.config=transport.load_config(self.root);target=self.config.hosts['archlinux']
        route=transport._route_hosts(self.config.hosts,'archlinux');pins.need(len(route)==2 and target.gateway,'route')
        self.outer=route[-1];self.target=target;pins.need(self.outer.password is None,'credential_not_supported')
        for path in (self.outer.identity_file,self.outer.known_hosts_file):self.authority.capture(Path(path),private=False)
        owner=self.authority.files[Path(pins.__file__).absolute()];pins.need(owner.pin['sha256']==OWNER_SHA,'pin_source_changed')
        self.owner_raw=owner.body
        source=self.authority.files[Path(__file__).absolute()]
        self.packet={'version':1,'purpose':'inert-tmux-disconnect20','hop':hop,'correlationId':correlation_id,'configSha':self.config_pin.pin['sha256'],'sourceSha':source.pin['sha256'],'ownerSha':OWNER_SHA,'workerSha':pins.sha(WORKER.encode())}
        parent=self.root
        for name in ('.rag_index','ssh-tmux-disconnect-probe',hop):
            directory=self.authority.directory(parent)
            if not os.path.lexists(parent/name):os.mkdir(name,0o700,dir_fd=directory.fd);os.fsync(directory.fd)
            parent/=name;self.authority.directory(parent,True)
        directory=self.authority.directory(parent,True);os.mkdir(correlation_id,0o700,dir_fd=directory.fd);os.fsync(directory.fd)
        self.job=parent/correlation_id;self.directory=self.authority.directory(self.job,True)
        pins.create(self.directory,'intent.json',pins.canonical({'packet':self.packet,'authority':{str(p):c.pin for p,c in self.authority.files.items()}}));self.authority.capture(self.job/'intent.json');self._guard()

    def _guard(self):self.presented.guard();self.authority.guard();self.authority.generations()

    def _argv(self):
        program="import base64;OWNER_SOURCE=base64.b64decode("+repr(base64.b64encode(self.owner_raw).decode())+");WORKER_SOURCE=base64.b64decode("+repr(base64.b64encode(WORKER.encode()).decode())+");OWNER_SHA="+repr(OWNER_SHA)+";exec("+repr("try:\n exec(compile(base64.b64decode("+repr(base64.b64encode(REMOTE.encode()).decode())+"),'fixed-inert-probe','exec'))\nexcept Exception:\n import sys\n sys.stderr.write('probe_validation_unknown\\n')\n raise SystemExit(73)")+")"
        command=('/usr/bin/python3','-I','-B','-c',program)
        if self.hop=='archlinux':
            nested=['/usr/bin/ssh','-T']+(['-F',str(self.target.remote_config_file)] if self.target.remote_config_file else [])
            nested+=['-S',str(self.target.remote_control_path),'-o','ControlMaster=no','-o','ProxyCommand=false','-o','BatchMode=yes','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(self.target.known_hosts_file),self.target.remote_host_alias,shlex.join(command)]
            command=tuple(nested)
        argv=transport.build_ssh_argv(self.config,self.outer.alias,10,command=command,ssh_binary='/usr/bin/ssh')
        argv[1:1]=['-F','/dev/null','-T','-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no']
        return [sys.executable,'-I','-B','-c',EXEC,json.dumps(argv)]

    def _query(self,action,keep=False):
        name='query-'+uuid4().hex;os.mkdir(name,0o700,dir_fd=self.directory.fd);os.fsync(self.directory.fd)
        capsule=self.job/name;directory=self.authority.directory(capsule,True)
        out=os.open('stdout.private',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
        err=os.open('stderr.private',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
        child=None;outcome='start_error';code=None;failure=None;argv=self._argv()
        try:
            self._guard();child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=out,stderr=err);outcome='awaiting_reply'
            child.stdin.write(pins.canonical({'action':action,'packet':self.packet,'anchorPin':self.anchor})+b'\n');child.stdin.flush()
            if keep:
                self.client=child;self.client_argv=argv
                deadline=time.monotonic()+12
                while time.monotonic()<deadline and b'\n' not in os.pread(out,LIMIT+1,0) and child.poll()is None:time.sleep(.02)
                self.birth=_birth(child);outcome='connected';os.fsync(out);os.fsync(err);self.raw_fds += [out,err];out=err=-1
            else:
                child.stdin.close()
                try:child.wait(timeout=12);code=child.returncode;outcome='completed'
                except subprocess.TimeoutExpired:outcome='timeout'
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError) as exc:
            failure=exc
        finally:
            for fd in (out,err):
                if fd>=0:os.fsync(fd);os.close(fd)
        try:
            stdout=self.authority.capture(capsule/'stdout.private',maximum=LIMIT)
            stderr=self.authority.capture(capsule/'stderr.private',maximum=LIMIT)
        except (OSError,ValueError):
            pins.create(directory,'receipt.json',pins.canonical({'action':action,'outcome':'capture_unknown','replayAllowed':False}))
            raise
        pins.create(directory,'receipt.json',pins.canonical({'action':action,'outcome':outcome,'exitCode':code,'stdout':stdout.pin,'stderr':stderr.pin,'argvSha':pins.sha(pins.canonical(argv)),'client':self.birth if keep else None}))
        self._guard()
        if failure is not None:raise failure
        pins.need((outcome=='connected' if keep else outcome=='completed' and code==0) and len(stdout.body)<LIMIT and not stderr.body and stdout.body.endswith(b'\n'),'query_unknown')
        value=pins.value(stdout.body);pins.need(type(value)is dict,'reply');return value

    def prepare(self):
        try:
            pins.create(self.directory,'prepare.intent.json',b'{}');self.authority.capture(self.job/'prepare.intent.json')
            result=self._query('prepare',True)
            pins.need(set(result)=={'state','anchor','anchorPin'} and result['state']=='prepared','prepare_reply')
            anchor=result['anchor'];_pin(result['anchorPin'])
            pins.need(type(anchor)is dict and set(anchor)=={'intentPin','sourcePin','workerPin','server','pane','socket','session','bootId'}
                      and anchor['session']=='vtd-'+UUID(self.correlation).hex[:16]
                      and type(anchor['bootId'])is str and str(UUID(anchor['bootId']))==anchor['bootId'],'anchor_reply')
            for key in ('intentPin','sourcePin','workerPin'):_pin(anchor[key])
            for key in ('server','pane'):
                pins.need(type(anchor[key])is dict and set(anchor[key])=={'pid','startTicks'} and all(type(x)is int and x>0 for x in anchor[key].values()),'owner_reply')
            pins.need(anchor['server']['pid']!=anchor['pane']['pid'] and type(anchor['socket'])is list and len(anchor['socket'])==9 and all(type(x)is int and x>=0 for x in anchor['socket'])
                      and anchor['intentPin']['sha256']==pins.sha(pins.canonical(self.packet)) and anchor['sourcePin']['sha256']==OWNER_SHA
                      and anchor['workerPin']['sha256']==self.packet['workerSha'] and result['anchorPin']['sha256']==pins.sha(pins.canonical(anchor)),'anchor_binding')
            self.anchor=result['anchorPin'];pins.create(self.directory,'anchor.json',pins.canonical(result));self.authority.capture(self.job/'anchor.json');self._guard()
            return {'state':'prepared','replayAllowed':False}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return {'state':'unknown','replayAllowed':False}

    def release(self):
        try:
            pins.need(self.anchor is not None,'no_original_anchor');pins.create(self.directory,'release.intent.json',b'{}');self.authority.capture(self.job/'release.intent.json')
            result=self._query('release');pins.need(set(result)=={'state','anchorPin','releasePin'} and result['state']=='released' and result['anchorPin']==self.anchor,'release_reply')
            _pin(result['releasePin'])
            pins.create(self.directory,'release.json',pins.canonical(result));self.authority.capture(self.job/'release.json');self._guard();return {'state':'released','replayAllowed':False}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return {'state':'unknown','replayAllowed':False}

    def disconnect(self):
        try:
            pins.need(self.client is not None and self.birth is not None and self.client.args==self.client_argv,'owned_child')
            pins.create(self.directory,'disconnect.intent.json',pins.canonical(self.birth));self.authority.capture(self.job/'disconnect.intent.json')
            self._guard();pins.need(_birth(self.client)==self.birth,'client_changed');self.authority.generations()
            os.kill(self.client.pid,signal.SIGTERM);self.client.wait(timeout=3)
            pins.create(self.directory,'disconnect.json',pins.canonical({'client':self.birth,'exitCode':self.client.returncode}));self.authority.capture(self.job/'disconnect.json');self._guard()
            return {'state':'disconnected','replayAllowed':False}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return {'state':'unknown','replayAllowed':False}

    def observe(self):
        try:
            pins.need(self.anchor is not None,'no_original_anchor');result=self._query('observe')
            state=result['state'];keys={'state','anchorPin','sequence'}|({'terminalPin'} if state=='completed' else set())
            pins.need(set(result)==keys and state in ('prepared','released','running','completed') and result['anchorPin']==self.anchor and type(result['sequence'])is int and 0<=result['sequence']<=20 and (state!='completed' or result['sequence']==20),'observation_reply')
            if state=='completed':_pin(result['terminalPin'])
            self._guard();return {'state':state,'sequence':result['sequence'],'replayAllowed':False,'productAcceptance':False}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return {'state':'unknown','replayAllowed':False,'productAcceptance':False}

    def close(self):
        # Closing evidence descriptors has no signal/release/remote effect.
        for fd in self.raw_fds:os.close(fd)
        self.raw_fds=[];self.authority.close()
