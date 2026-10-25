"""One-shot recovery of preserved CP117; historical readers remain immutable.

Named/held guards exclude cooperating writers, not arbitrary external root writes.
Uncertain daemon starts are never replayed. This tool never admits an MSI install.
"""
from __future__ import annotations
import base64, contextlib, fcntl, hashlib, json, os, stat, subprocess, time
from pathlib import Path
from typing import Any
from . import windows_cp117_bound_absence_completion as authority
from . import windows_vm_virt_firmware_install as credential
from .windows_diagnostic_authority_capture import AuthorityCapture
HOST='archlinux'
ENVIRONMENT='windows-cp117-recovery'
OPERATOR='windows_operator'
MEMORY_BYTES=4294967296
HEADROOM_BYTES=8589934592
RESERVATION_ID='env-61099895289d9d31c5a57e62ad2f057d'
ROOT='/home/kardinal/vpn-control-windows-msi-acceptance-cp117'
DISK=ROOT+'/task.qcow2'
BACKING='/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2'
VARS=ROOT+'/OVMF_VARS.fd'
TPM_STATE=ROOT+'/tpm'
CODE='/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd'
QEMU='/usr/bin/qemu-system-x86_64'
SWTPM='/usr/bin/swtpm'
BOOT_ID='25515f23-b966-4c3a-ae63-d38452375578'
SSH_PORT=2329
VNC_PORT=5929
_FP_FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

class RecoveryUnknown(ValueError):
    pass

def _need(ok: bool, phase: str) -> None:
    if not ok:
        raise RecoveryUnknown(phase)

def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _fp(value: os.stat_result) -> dict[str,int]:
    return {k:getattr(value,k) for k in _FP_FIELDS}

def recipe() -> dict[str,Any]:
    leaf=ROOT+'/recovery-'+CORRELATION
    qemu=[QEMU,'-name','vpn-control-windows-cp117-recovery','-machine','q35,accel=kvm,smm=on','-cpu','host','-smp','4','-m','4096',
          '-drive','if=pflash,format=raw,readonly=on,file='+CODE,'-drive','if=pflash,format=raw,file='+VARS,
          '-global','driver=cfi.pflash01,property=secure,value=on','-drive','file='+DISK+',if=none,id=disk,format=qcow2',
          '-device','ide-hd,drive=disk,bus=ide.0','-netdev','user,id=net,hostfwd=tcp:127.0.0.1:'+str(SSH_PORT)+'-:22',
          '-device','e1000e,netdev=net','-chardev','socket,id=chrtpm,path='+leaf+'/swtpm.sock',
          '-tpmdev','emulator,id=tpm0,chardev=chrtpm','-device','tpm-tis,tpmdev=tpm0','-device','virtio-serial-pci',
          '-chardev','socket,path='+leaf+'/qga.sock,server=on,wait=off,id=qga0',
          '-device','virtserialport,chardev=qga0,name=org.qemu.guest_agent.0',
          '-qmp','unix:'+leaf+'/qmp.sock,server=on,wait=off','-vnc','127.0.0.1:'+str(VNC_PORT-5900),
          '-display','none','-vga','std','-usb','-device','usb-tablet','-rtc','base=utc']
    tpm=[SWTPM,'socket','--tpm2','--tpmstate','dir='+TPM_STATE,'--ctrl','type=unixio,path='+leaf+'/swtpm.sock','--flags','not-need-init']
    return {'version':1,'correlationId':CORRELATION,'bootId':BOOT_ID,'leaf':leaf,'qemuArgv':qemu,'tpmArgv':tpm,
            'memoryBytes':MEMORY_BYTES,'headroomBytes':HEADROOM_BYTES,'files':BASELINE,'sshPort':SSH_PORT,'vncPort':VNC_PORT}

@contextlib.contextmanager
def _claim(root: Path):
    """Read actual protected registry under its existing shared lock, bounded."""
    directory=root/'.rag_index/native-environments'
    ancestry=[(p,os.lstat(p)) for p in (root,root/'.rag_index',directory)]
    for _,s in ancestry:
        _need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o022,'claim-parent')
    fd=os.open(directory/'lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        lock=_fp(os.fstat(fd))
        _need(stat.S_ISREG(lock['st_mode']) and stat.S_IMODE(lock['st_mode'])==0o600 and lock['st_nlink']==1,'claim-lock')
        fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        def read():
            def guards():
                for p,s in ancestry:
                    now=os.lstat(p)
                    _need(all(getattr(s,k)==getattr(now,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid')),'claim-parent-drift')
                _need(_fp(os.fstat(fd))==lock==_fp(os.lstat(directory/'lock')),'claim-lock-drift')
            guards()
            value=authority._read_bound_file(directory/'reservations.json',private=True)
            rf=os.open(directory/'reservations.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try:
                original=_fp(os.fstat(rf));raw=os.read(rf,1048577)
                _need(len(raw)<=1048576 and original==_fp(os.fstat(rf))==_fp(os.lstat(directory/'reservations.json')),'claim-file-drift')
            finally:os.close(rf)
            data=json.loads(raw)
            _need(authority._read_bound_file(directory/'reservations.json',private=True)==value,'claim-file-drift')
            guards()
            records=data.get('reservations',[])
            matches=[r for r in records if r.get('id')==RESERVATION_ID]
            _need(data.get('version')==1 and len(matches)==1,'claim-record')
            record=matches[0]
            _need(record.get('hostAlias')==HOST and record.get('environment')==ENVIRONMENT and record.get('operator')==OPERATOR
                  and record.get('requestedMemoryBytes')==MEMORY_BYTES and record.get('allocationState')=='pending'
                  and record.get('activeJob')=='absent' and isinstance(record.get('token'),str) and bool(record['token']),'claim-authority')
            host=[r for r in records if r.get('hostAlias')==HOST]
            _need(all(type(r.get('requestedMemoryBytes'))is int and r['requestedMemoryBytes']>0 for r in host),'claim-accounting')
            return {'recordSha256':_digest(record),'registryPin':value,'reservedMemoryBytes':sum(r['requestedMemoryBytes']for r in host)}
        pinned=read()
        def verify():
            _need(read()==pinned,'claim-drift')
        yield pinned,verify
        verify()
    finally:
        os.close(fd)
CORRELATION='accd589f-a9c9-4470-a163-42df169fe37f'
BASELINE={'/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2': {'fingerprint': {'st_dev': 66307, 'st_ino': 103551218, 'st_mode': 33152, 'st_uid': 1000, 'st_gid': 1000, 'st_nlink': 1, 'st_size': 39685652480, 'st_mtime_ns': 1791016415522428871, 'st_ctime_ns': 1791016415522428871}}, '/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2': {'fingerprint': {'st_dev': 66307, 'st_ino': 32677688, 'st_mode': 33024, 'st_uid': 1000, 'st_gid': 1000, 'st_nlink': 1, 'st_size': 16556490752, 'st_mtime_ns': 1788782074184267062, 'st_ctime_ns': 1788782165958281514}}, '/home/kardinal/vpn-control-windows-msi-acceptance-cp117/OVMF_VARS.fd': {'fingerprint': {'st_dev': 66307, 'st_ino': 103551219, 'st_mode': 33152, 'st_uid': 1000, 'st_gid': 1000, 'st_nlink': 1, 'st_size': 540672, 'st_mtime_ns': 1790321865578186622, 'st_ctime_ns': 1790321865578186622}, 'sha256': 'fbef565d2874988406b121939d750afebf9e5adbf8c11811d0e28a25de9c38fa'}, '/home/kardinal/vpn-control-windows-msi-acceptance-cp117/tpm/tpm2-00.permall': {'fingerprint': {'st_dev': 66307, 'st_ino': 103550738, 'st_mode': 33184, 'st_uid': 1000, 'st_gid': 1000, 'st_nlink': 1, 'st_size': 5645, 'st_mtime_ns': 1790321884995174258, 'st_ctime_ns': 1790321884995174258}, 'sha256': '11ef3d0a10b4f96da12696abed6478cfffbcfb69e77b80b1e4ad5eef94924cce'}, '/home/kardinal/vpn-control-windows-msi-acceptance-cp117/tpm/.lock': {'fingerprint': {'st_dev': 66307, 'st_ino': 103551229, 'st_mode': 33152, 'st_uid': 1000, 'st_gid': 1000, 'st_nlink': 1, 'st_size': 0, 'st_mtime_ns': 1790235881221504578, 'st_ctime_ns': 1790235881221504578}, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, '/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd': {'fingerprint': {'st_dev': 66306, 'st_ino': 1459371, 'st_mode': 33188, 'st_uid': 0, 'st_gid': 0, 'st_nlink': 1, 'st_size': 3653632, 'st_mtime_ns': 1787692288000000000, 'st_ctime_ns': 1788642791584206010}, 'sha256': 'cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f'}, '/usr/bin/qemu-system-x86_64': {'fingerprint': {'st_dev': 66306, 'st_ino': 1234700, 'st_mode': 33261, 'st_uid': 0, 'st_gid': 0, 'st_nlink': 1, 'st_size': 28940536, 'st_mtime_ns': 1789559094000000000, 'st_ctime_ns': 1790008459287925436}, 'sha256': '87f21559c0449a475f5c514289ac121bf934263cbf7d2dfbb5a1d998028bbd85'}, '/usr/bin/swtpm': {'fingerprint': {'st_dev': 66306, 'st_ino': 1236533, 'st_mode': 33261, 'st_uid': 0, 'st_gid': 0, 'st_nlink': 1, 'st_size': 62184, 'st_mtime_ns': 1788776752000000000, 'st_ctime_ns': 1790008459524205857}, 'sha256': '2b883328fe5b5dabb34acb07cf95f7fa6f73bed584298dcb086b30cebfc1259e'}}

# The privileged portion is read-only. The caller's sudo bytes never reach the
# daemon environment, argv, journal, stderr or public projection.
_OBSERVER = r'''import os,stat,json,time,hashlib,subprocess,socket
R=__RECIPE__;RESERVED=__RESERVED__
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def fp(s):return {k:getattr(s,k)for k in FIELDS}
def need(v,p):
 if not v:raise ValueError(p)
def file(path,expect):
 need(os.path.realpath(path)==path,'source-path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);need(fp(s)==expect['fingerprint'] and stat.S_ISREG(s.st_mode)and s.st_nlink==1,'source-generation')
  if 'sha256'in expect:
   h=hashlib.sha256();count=0
   while True:
    b=os.read(fd,1048576)
    if not b:break
    count+=len(b);h.update(b)
   need(count==s.st_size and h.hexdigest()==expect['sha256'],'source-hash')
  need(fp(s)==fp(os.fstat(fd))==fp(os.lstat(path)),'source-drift');return fp(s)
 finally:os.close(fd)
def ps(pid):
 b=open('/proc/%d/stat'%pid,'rb').read(8192);f=b[b.rfind(b')')+2:].split();return(int(f[19]),int(f[6]),f[0])
try:
 begin=time.monotonic();boot=open('/proc/sys/kernel/random/boot_id').read().strip();need(boot==R['bootId'],'boot')
 need(not os.path.exists('/proc/589342'),'old-owner-present')
 original={p:file(p,e)for p,e in R['files'].items()};wanted={(s['st_dev'],s['st_ino'])for s in original.values()};errors=[];holders=[];qemus=[];kernel=0;users=0
 for name in os.listdir('/proc'):
  if not name.isdigit():continue
  need(time.monotonic()-begin<30,'census-deadline');pid=int(name)
  try:
   before=ps(pid)
   if before[1]&0x00200000:
    need(ps(pid)==before,'kernel-generation');kernel+=1;continue
   users+=1
   try:exe=os.readlink('/proc/%d/exe'%pid)
   except FileNotFoundError:
    if before[2]==b'Z':continue
    if not os.path.exists('/proc/%d'%pid):continue
    raise ValueError('user-exe-unavailable')
   if os.path.basename(exe).startswith('qemu-system-'):
    cmd=open('/proc/%d/cmdline'%pid,'rb').read(32769);need(len(cmd)<=32768,'qemu-command-cap');qemus.append({'pid':pid,'ticks':before[0],'argv':cmd.decode().split('\0')[:-1]})
   for n in os.listdir('/proc/%d/fd'%pid):
    try:
     s=os.stat('/proc/%d/fd/%s'%(pid,n))
     if(s.st_dev,s.st_ino)in wanted:holders.append({'pid':pid,'ticks':before[0],'fd':n})
    except FileNotFoundError:pass
   need(ps(pid)[0]==before[0],'process-generation')
  except FileNotFoundError:
   need(not os.path.exists('/proc/%d'%pid),'incomplete-process')
 need(not holders,'source-holder')
 # A new socket path is never substituted for or unlinks the old path.
 need(not os.path.lexists(R['leaf']),'attempt-exists')
 need(set(os.listdir('/home/kardinal/vpn-control-windows-msi-acceptance-cp117/tpm'))=={'.lock','tpm2-00.permall'},'tpm-inventory')
 for path in('/proc/net/tcp','/proc/net/tcp6'):
  for line in open(path):
   f=line.split()
   if len(f)>3 and f[3]=='0A':need(int(f[1].split(':')[-1],16)not in(R['sshPort'],R['vncPort']),'port-busy')
 chain=subprocess.run(['/usr/bin/qemu-img','info','--output=json','--backing-chain','/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,check=False)
 need(chain.returncode==0 and len(chain.stdout)<=32768,'image-query');images=json.loads(chain.stdout)
 need(len(images)==2 and all(i['format']=='qcow2'and not i.get('dirty-flag')and not i.get('format-specific',{}).get('data',{}).get('corrupt')for i in images),'image-shape')
 need(images[0]['filename']=='/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2'and images[0]['full-backing-filename']==images[1]['filename']=='/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2'and not images[1].get('backing-filename'),'image-chain')
 mem={}
 for line in open('/proc/meminfo'):
  f=line.split()
  if f[0]in('MemTotal:','MemAvailable:'):mem[f[0][:-1]]=int(f[1])*1024
 psi=open('/proc/pressure/memory').read(4096)
 for line in psi.splitlines():
  values=dict(p.split('=',1)for p in line.split()[1:]);need(float(values['avg10'])<1 and float(values['avg60'])<1,'memory-pressure')
 need(mem['MemAvailable']>=RESERVED+R['headroomBytes'] and mem['MemTotal']>=RESERVED+R['headroomBytes'],'memory-headroom')
 v=os.statvfs('/home/kardinal');need(v.f_bavail*v.f_frsize>=30*1024**3,'disk-headroom')
 need(os.access('/dev/kvm',os.R_OK|os.W_OK),'kvm')
 parent=os.lstat('/home/kardinal/vpn-control-windows-msi-acceptance-cp117');need(stat.S_ISDIR(parent.st_mode)and parent.st_uid==1000 and not parent.st_mode&0o022,'guest-parent')
 need(original=={p:file(p,e)for p,e in R['files'].items()},'source-post')
 need(boot==open('/proc/sys/kernel/random/boot_id').read().strip(),'boot-post')
 print(json.dumps({'state':'ready','bootId':boot,'observedAtNs':time.time_ns(),'files':original,'parent':fp(parent),'memory':mem,'reservedMemoryBytes':RESERVED,'qemuProcesses':qemus,'kernelThreads':kernel,'userProcesses':users,'holderCensusComplete':True,'holders':[],'recipeSha256':hashlib.sha256(json.dumps(R,sort_keys=True,separators=(',',':')).encode()).hexdigest()},separators=(',',':')))
except Exception as e:print(json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__},separators=(',',':')))
'''

_REMOTE_COMMON = r'''import os,stat,json,time,hashlib,subprocess,sys,fcntl
R=__RECIPE__;REQUEST=__REQUEST__;LEAF=R['leaf'];LEAF_FD=None;ROOT_FD=None;ROOT_IDENTITY=None;FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def fp(s):return{k:getattr(s,k)for k in FIELDS}
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def need(v,p):
 if not v:raise ValueError(p)
def private(path):
 s=os.lstat(path);need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o700,'private-parent');return fp(s)
def leaf_check():
 need(LEAF_FD is not None and ROOT_FD is not None,'held-directory-required')
 for s in(os.fstat(ROOT_FD),os.lstat('/home/kardinal/vpn-control-windows-msi-acceptance-cp117')):
  need(all(getattr(s,k)==ROOT_IDENTITY[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'root-directory-authority')
 named=private(LEAF);held=os.fstat(LEAF_FD)
 need(all(getattr(held,k)==named[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'held-leaf-authority')
def create(name,value):
 leaf_check();body=json.dumps(value,sort_keys=True,separators=(',',':')).encode();fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=LEAF_FD)
 try:
  need(os.write(fd,body)==len(body),'write');os.fsync(fd);s=os.fstat(fd);need(s.st_nlink==1 and fp(s)==fp(os.stat(name,dir_fd=LEAF_FD,follow_symlinks=False)),'create-name');leaf_check();os.fsync(LEAF_FD);leaf_check();return{'fingerprint':fp(s),'sha256':hashlib.sha256(body).hexdigest()}
 finally:os.close(fd)
def read(name,pin):
 leaf_check();fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=LEAF_FD)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and fp(s)==pin['fingerprint'],'authority-generation')
  body=os.read(fd,65537);need(len(body)<=65536 and fp(s)==fp(os.fstat(fd))==fp(os.stat(name,dir_fd=LEAF_FD,follow_symlinks=False))and hashlib.sha256(body).hexdigest()==pin['sha256'],'authority-hash');leaf_check();return json.loads(body)
 finally:os.close(fd)
def ticks(pid):
 b=open('/proc/%d/stat'%pid,'rb').read(8192);return int(b[b.rfind(b')')+2:].split()[19])
def identity(pid,argv):
 before=ticks(pid);raw=open('/proc/%d/cmdline'%pid,'rb').read(32769);need(raw==b'\0'.join(os.fsencode(a)for a in argv)+b'\0','child-argv')
 need(os.readlink('/proc/%d/exe'%pid)==argv[0]and os.stat('/proc/%d'%pid).st_uid==os.geteuid(),'child-executable-owner')
 need(ticks(pid)==before,'child-generation');return{'pid':pid,'startTicks':before,'argvSha256':digest(argv),'bootId':R['bootId']}
def child_guard(child,argv):need(identity(child['pid'],argv)==child,'child-authority')
def socket_guard(path,child):
 s=os.lstat(path);need(stat.S_ISSOCK(s.st_mode)and s.st_uid==os.geteuid(),'socket-shape')
 rows=[f for f in(line.split()for line in open('/proc/net/unix','rb'))if len(f)==8 and f[7]==os.fsencode(path)];need(len(rows)==1,'socket-kernel')
 inode=rows[0][6].decode();need(any(os.readlink('/proc/%d/fd/%s'%(child['pid'],n))=='socket:['+inode+']'for n in os.listdir('/proc/%d/fd'%child['pid'])),'socket-child');return{'fingerprint':fp(s),'kernelInode':inode}
def file_guard(paths):
 for p in paths:
  e=R['files'][p];need(fp(os.lstat(p))==e['fingerprint']and os.path.realpath(p)==p,'source-generation')
  if'sha256'in e:
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   try:
    s=os.fstat(fd);h=hashlib.sha256()
    while True:
     b=os.read(fd,1048576)
     if not b:break
     h.update(b)
    need(fp(s)==e['fingerprint']==fp(os.fstat(fd))==fp(os.lstat(p))and h.hexdigest()==e['sha256'],'source-hash')
   finally:os.close(fd)
def emit(kind,value):
 frame={'kind':kind,'requestSha256':digest(REQUEST),'correlationId':R['correlationId'],'value':value};sys.stderr.write('RECOVERY '+json.dumps(frame,sort_keys=True,separators=(',',':'))+'\n');sys.stderr.flush()
def result(value):print(json.dumps(value,separators=(',',':')))
'''

_REMOTE_START = r'''
try:
 secret=sys.stdin.buffer.read(513);need(1<=len(secret)<=512 and b'\0'not in secret,'credential-shape')
 if not secret.endswith(b'\n'):secret+=b'\n'
 observed=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',__OBSERVER__],input=secret,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,check=False);secret=None
 need(observed.returncode==0 and len(observed.stdout)<=65536,'readonly-transport');proof=json.loads(observed.stdout);need(proof.get('state')=='ready','readonly-'+proof.get('phase','unknown'))
 need(proof['recipeSha256']==digest(R)and proof['reservedMemoryBytes']==REQUEST['claim']['reservedMemoryBytes'],'proof-binding')
 need(0<=time.time_ns()-proof['observedAtNs']<=5_000_000_000,'proof-expired')
 parent=proof['parent'];need(fp(os.lstat('/home/kardinal/vpn-control-windows-msi-acceptance-cp117'))==parent,'parent-drift')
 ROOT_FD=os.open('/home/kardinal/vpn-control-windows-msi-acceptance-cp117',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);ROOT_IDENTITY=parent
 need(fp(os.fstat(ROOT_FD))==parent,'held-parent')
 os.mkdir(os.path.basename(LEAF),0o700,dir_fd=ROOT_FD);os.fsync(ROOT_FD);leaf=private(LEAF)
 LEAF_FD=os.open(os.path.basename(LEAF),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=ROOT_FD);leaf_check()
 lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=LEAF_FD);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);lockpin=fp(os.fstat(lock))
 intentpin=create('intent.json',REQUEST);attemptpin=create('attempt.json',{'requestSha256':digest(REQUEST),'state':'consumed','proofSha256':digest(proof)})
 def guards():
  leaf_check()
  current=private(LEAF);need(all(current[k]==leaf[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'leaf-generation')
  allowed={'lock','intent.json','attempt.json','tpm-attempt.json','tpm.stderr.private','tpm.json','swtpm.sock','qemu-attempt.json','qemu.stderr.private','qemu.json','qga.sock','qmp.sock'}
  need(set(os.listdir(LEAF))<=allowed,'foreign-leaf-entry')
  need(fp(os.fstat(lock))==lockpin==fp(os.lstat(LEAF+'/lock')),'lock-generation')
  need(read('intent.json',intentpin)==REQUEST,'intent')
  need(read('attempt.json',attemptpin)=={'requestSha256':digest(REQUEST),'state':'consumed','proofSha256':digest(proof)},'attempt')
  need(open('/proc/sys/kernel/random/boot_id').read().strip()==R['bootId'],'boot')
  now=os.lstat('/home/kardinal/vpn-control-windows-msi-acceptance-cp117');need(all(fp(now)[k]==parent[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'parent-generation')
  file_guard([p for p in R['files']if '/tpm/'not in p])
  leaf_check();need(fp(os.fstat(lock))==lockpin==fp(os.lstat(LEAF+'/lock')),'final-lock-generation')
  need(read('intent.json',intentpin)==REQUEST,'final-intent');need(read('attempt.json',attemptpin)['requestSha256']==digest(REQUEST),'final-attempt');leaf_check()
 def launch(role,argv):
  guards();need(not os.path.lexists(LEAF+'/'+role+'.json'),'role-consumed')
  # Each role fence is durable before Popen; a lost child result never permits resubmission.
  create(role+'-attempt.json',{'requestSha256':digest(REQUEST),'argvSha256':digest(argv),'state':'consumed'})
  guards()
  log=os.open(role+'.stderr.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=LEAF_FD)
  try:
   guards();need(os.access('/dev/kvm',os.R_OK|os.W_OK),'user-kvm-access')
   p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
  finally:os.close(log)
  child=identity(p.pid,argv);pin=create(role+'.json',child)
  emit('child',{'role':role,'child':child,'pin':pin,'intentPin':intentpin,'attemptPin':attemptpin,'leafIdentity':{k:leaf[k]for k in('st_dev','st_ino','st_mode','st_uid','st_gid')}})
  return child,pin
 file_guard([p for p in R['files']if '/tpm/'in p]);tpm,tpmpin=launch('tpm',R['tpmArgv'])
 for _ in range(40):
  child_guard(tpm,R['tpmArgv'])
  if os.path.lexists(LEAF+'/swtpm.sock'):
   socket_guard(LEAF+'/swtpm.sock',tpm);break
  time.sleep(.1)
 else:raise ValueError('tpm-socket-deadline')
 # VARS and disks have not yet been handed to QEMU; TPM state is already owned by the exact new child.
 guards();child_guard(tpm,R['tpmArgv']);need(read('tpm.json',tpmpin)==tpm,'tpm-anchor')
 qemu,qemupin=launch('qemu',R['qemuArgv'])
 for _ in range(80):
  child_guard(tpm,R['tpmArgv']);child_guard(qemu,R['qemuArgv'])
  if all(os.path.lexists(LEAF+'/'+n)for n in('qmp.sock','qga.sock')):
   sockets={n:socket_guard(LEAF+'/'+n,qemu)for n in('qmp.sock','qga.sock')};break
  time.sleep(.1)
 else:raise ValueError('qemu-socket-deadline')
 # The writable disk/VARS may legitimately change after QEMU starts. Verify exact held inodes instead.
 held={(os.stat('/proc/%d/fd/%s'%(qemu['pid'],n)).st_dev,os.stat('/proc/%d/fd/%s'%(qemu['pid'],n)).st_ino)for n in os.listdir('/proc/%d/fd'%qemu['pid'])}
 for p in ('/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2','/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2','/home/kardinal/vpn-control-windows-msi-acceptance-cp117/OVMF_VARS.fd'):
  e=R['files'][p]['fingerprint'];need((e['st_dev'],e['st_ino'])in held,'qemu-held-source');now=os.lstat(p);need((now.st_dev,now.st_ino)==(e['st_dev'],e['st_ino']),'source-name')
 need(read('qemu.json',qemupin)==qemu and read('tpm.json',tpmpin)==tpm,'children-anchor');child_guard(tpm,R['tpmArgv']);child_guard(qemu,R['qemuArgv'])
 terminal={'state':'running','requestSha256':digest(REQUEST),'tpm':tpm,'qemu':qemu,'sockets':sockets,'appAdmission':False,'installerAction':False};create('result.json',terminal);emit('terminal',terminal);result(terminal)
except Exception as e:result({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'appAdmission':False,'replayAllowed':False})
'''

def _observer(claim: dict[str,Any]) -> str:
    return _OBSERVER.replace('__RECIPE__',repr(recipe())).replace('__RESERVED__',repr(claim['reservedMemoryBytes']))

def _program(request: dict[str,Any]) -> str:
    return (_REMOTE_COMMON.replace('__RECIPE__',repr(recipe())).replace('__REQUEST__',repr(request))
            +_REMOTE_START.replace('__OBSERVER__',repr(_observer(request['claim']))))


def _stream(argv: list[str], secret: bytes, capture: AuthorityCapture, request: dict[str,Any]) -> tuple[dict[str,Any],list[dict[str,Any]]]:
    """Retain original child authority before waiting; no adopt-current-file path."""
    import selectors
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
    chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();frames=[];deadline=time.monotonic()+60
    try:
        assert process.stdin is not None
        process.stdin.write(secret);process.stdin.close();secret=b''
        while selector.get_map():
            _need(time.monotonic()<deadline,'transport-deadline')
            for key,_ in selector.select(min(.25,max(.001,deadline-time.monotonic()))):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(data)
                _need(len(chunks[key.data])<=(1048576 if key.data=='stdout' else 131072),'transport-byte-cap')
                if key.data=='stderr':
                    pending.extend(data)
                    while b'\n'in pending:
                        line,rest=pending.split(b'\n',1);pending=bytearray(rest)
                        if not line.startswith(b'RECOVERY '):continue
                        frame=json.loads(line[9:]);_validate_frame(frame,request,frames)
                        pin=capture.create('authority-%d.json'%len(frames),json.dumps(frame,sort_keys=True).encode())
                        os.fsync(capture.fd);capture._check()
                        frames.append({'frame':frame,'localPin':pin})
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        capture.create('transport.stdout.private',bytes(chunks['stdout']));capture.create('transport.stderr.private',bytes(chunks['stderr']))
        _need(code==0,'transport-exit');value=json.loads(chunks['stdout'])
        return value,frames
    except BaseException as error:
        # Kill only the exact owned local SSH client on observation loss. Daemons
        # remain untouched; a missing original frame is unknown, never adopted.
        capture.create('partial.stdout.private',bytes(chunks['stdout'][:1048576]));capture.create('partial.stderr.private',bytes(chunks['stderr'][:131072]))
        if process.poll()is None:process.kill()
        process.wait(timeout=3)
        error.frames=frames
        raise
    finally:
        selector.close()
        for stream in(process.stdin,process.stdout,process.stderr):
            if stream is not None:stream.close()


def _validate_frame(frame: Any, request: dict[str,Any], prior: list[dict[str,Any]]) -> None:
    _need(isinstance(frame,dict) and set(frame)=={'kind','requestSha256','correlationId','value'}
          and frame['requestSha256']==_digest(request) and frame['correlationId']==CORRELATION,'stream-request')
    expected=('tpm','qemu','terminal')
    _need(len(prior)<3,'stream-cap')
    value=frame['value']
    if len(prior)<2:
        role=expected[len(prior)]
        _need(frame['kind']=='child' and isinstance(value,dict) and value.get('role')==role,'stream-role')
        child=value.get('child',{})
        _need(set(child)=={'pid','startTicks','argvSha256','bootId'} and type(child['pid'])is int and child['pid']>0
              and type(child['startTicks'])is int and child['startTicks']>0 and child['bootId']==BOOT_ID
              and child['argvSha256']==_digest(recipe()[role+'Argv']),'stream-child')
        for name in('pin','intentPin','attemptPin'):
            pin=value.get(name,{})
            _need(set(pin)=={'fingerprint','sha256'} and isinstance(pin['fingerprint'],dict)
                  and set(pin['fingerprint'])==set(_FP_FIELDS) and isinstance(pin['sha256'],str) and len(pin['sha256'])==64,'stream-pin')
            info=pin['fingerprint']
            _need(all(type(v)is int for v in info.values())and stat.S_ISREG(info['st_mode'])
                  and stat.S_IMODE(info['st_mode'])==0o600 and info['st_uid']==1000 and info['st_nlink']==1,'stream-private-pin')
            _need(all(c in '0123456789abcdef'for c in pin['sha256']),'stream-digest')
        _need(value['pin']['sha256']==_digest(child) and value['intentPin']['sha256']==_digest(request),'stream-anchor-content')
        _need(isinstance(value.get('leafIdentity'),dict)and set(value['leafIdentity'])=={'st_dev','st_ino','st_mode','st_uid','st_gid'},'stream-leaf')
        leaf=value['leafIdentity'];_need(stat.S_ISDIR(leaf['st_mode'])and stat.S_IMODE(leaf['st_mode'])==0o700 and leaf['st_uid']==1000,'stream-private-leaf')
        if prior:
            original=prior[0]['frame']['value']
            _need(child['pid']!=original['child']['pid'] and value['intentPin']==original['intentPin']
                  and value['attemptPin']==original['attemptPin']and leaf==original['leafIdentity'],'stream-shared-authority')
    else:
        _need(frame['kind']=='terminal' and value.get('state')=='running' and value.get('requestSha256')==_digest(request),'stream-terminal')
        _need(value.get('tpm')==prior[0]['frame']['value']['child']and value.get('qemu')==prior[1]['frame']['value']['child'],'stream-terminal-children')


def start(root: Path | str) -> dict[str,Any]:
    """One fixed newly correlated start; consumed evidence permanently fences retry."""
    root=Path(root).resolve(strict=True);leaf='windows-cp117-recovery-'+CORRELATION
    directory=root/'.runtime/parity-evidence'/leaf
    _need(not directory.exists(),'attempt-consumed')
    directory.mkdir(mode=0o700)
    parent_fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
    capture=AuthorityCapture(root,leaf);request=None;frames=[]
    try:
        with _claim(root)as(claim,verify_claim):
            outer=authority._outer_authority(root)
            sources=authority._source_pins(root)
            sources['recovery']=authority._read_bound_file(Path(__file__))
            request={'version':1,'correlationId':CORRELATION,'recipeSha256':_digest(recipe()),'claim':claim,'outerAuthority':outer,'sources':sources}
            program=_program(request)
            capture.create('intent.json',json.dumps(request,sort_keys=True).encode())
            capture.create('remote.py',program.encode())
            config,_,_=authority.closure.base._descriptor(root)
            argv=authority.closure.base.ssh_transport.build_ssh_argv(config,HOST,60,command=authority.closure.base.windows_credential_probe_ssh._remote_command(program))
            verify_claim();authority._verify_outer(root,{'outerAuthority':outer})
            current=authority._source_pins(root);current['recovery']=authority._read_bound_file(Path(__file__))
            _need(current==sources,'source-drift')
            secret=credential._read_credential(root)
            # Dispatch is fenced locally before SSH; uncertainty never retries it.
            capture.create('attempt.json',json.dumps({'requestSha256':_digest(request),'programSha256':hashlib.sha256(program.encode()).hexdigest(),'state':'consumed'},sort_keys=True).encode())
            os.fsync(capture.fd);capture._check()
            verify_claim();authority._verify_outer(root,{'outerAuthority':outer})
            value,frames=_stream(argv,secret,capture,request);secret=None
            verify_claim();authority._verify_outer(root,{'outerAuthority':outer})
            current=authority._source_pins(root);current['recovery']=authority._read_bound_file(Path(__file__))
            _need(current==sources,'post-source-drift')
            if value.get('state')=='running':
                _need(len(frames)==3 and frames[-1]['frame']['value']==value,'terminal-original-authority')
            receipt=capture.create('result.json',json.dumps({'request':request,'result':value,'authority':frames},sort_keys=True).encode())
            os.fsync(capture.fd);capture._check()
            return {'state':value.get('state','unknown'),'phase':value.get('phase'),'correlationId':CORRELATION,
                    'appAdmission':False,'installerAction':False,'replayAllowed':False,'evidenceLeaf':leaf,'receipt':{'name':'result.json','pin':receipt}}
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError)as error:
        frames=getattr(error,'frames',frames)
        receipt=capture.create('unknown.json',json.dumps({'request':request,'state':'unknown','phase':str(error)if isinstance(error,RecoveryUnknown)else type(error).__name__,
                       'requestSha256':_digest(request)if request else None,'authority':frames,'replayAllowed':False},sort_keys=True).encode())
        os.fsync(capture.fd);capture._check()
        return {'state':'unknown','phase':str(error)if isinstance(error,RecoveryUnknown)else type(error).__name__,
                'correlationId':CORRELATION,'appAdmission':False,'installerAction':False,'replayAllowed':False,'evidenceLeaf':leaf,'receipt':{'name':'unknown.json','pin':receipt}}
    finally:capture.close()


def _local_read(capture: AuthorityCapture,name: str,pin: dict[str,Any]) -> bytes:
    """Use external original FD pin; reject FIFO before a nonblocking read."""
    capture._name(name);capture._check()
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=capture.fd)
    try:
        info=os.fstat(fd);capture._file(info)
        _need([getattr(info,k)for k in _FP_FIELDS]==pin['generation']and info.st_size<=1048576,'local-pin')
        raw=os.read(fd,1048577)
        _need(len(raw)==info.st_size and hashlib.sha256(raw).hexdigest()==pin['sha256']
              and _fp(info)==_fp(os.fstat(fd))==_fp(os.stat(name,dir_fd=capture.fd,follow_symlinks=False)),'local-content')
        capture._check();return raw
    finally:os.close(fd)

_REMOTE_STATUS = r'''
try:
 proof=__AUTHORITY__;need(len(proof)in(1,2,3),'original-child-unavailable')
 children=[f['frame']['value']for f in proof if f['frame']['kind']=='child'];need(len(children)in(1,2),'original-child-unavailable')
 need(open('/proc/sys/kernel/random/boot_id').read().strip()==R['bootId'],'boot')
 first=children[0];private(LEAF)
 ROOT_FD=os.open('/home/kardinal/vpn-control-windows-msi-acceptance-cp117',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);ROOT_IDENTITY=fp(os.fstat(ROOT_FD))
 LEAF_FD=os.open(LEAF,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held=LEAF_FD;heldinfo=os.fstat(held)
 def guards():
  current=os.lstat(LEAF);need(all(getattr(current,k)==first['leafIdentity'][k]==getattr(os.fstat(held),k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'leaf-authority')
  need(read('intent.json',first['intentPin'])==REQUEST,'intent-authority')
  attempt=read('attempt.json',first['attemptPin']);need(attempt['requestSha256']==digest(REQUEST)and attempt['state']=='consumed','attempt-authority')
  for value in children:
   role=value['role'];need(read(role+'.json',value['pin'])==value['child'],'child-anchor');child_guard(value['child'],R[role+'Argv'])
  current=os.lstat(LEAF);need(all(getattr(current,k)==first['leafIdentity'][k]==getattr(os.fstat(held),k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')),'leaf-post')
 guards();sockets={}
 for value in children:
  role=value['role'];names=('swtpm.sock',)if role=='tpm'else('qga.sock','qmp.sock')
  for name in names:sockets[name]=socket_guard(LEAF+'/'+name,value['child'])
 guards();result({'state':'running'if len(children)==2 else'partial-running','requestSha256':digest(REQUEST),'children':children,'sockets':sockets,'appAdmission':False,'installerAction':False,'replayAllowed':False})
except Exception as e:result({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'appAdmission':False,'replayAllowed':False})
'''


def status(root: Path | str, original_receipt: dict[str,Any]) -> dict[str,Any]:
    """Only independently pinned original children; no dispatch or file adoption."""
    root=Path(root).resolve(strict=True);leaf='windows-cp117-recovery-'+CORRELATION
    _need(set(original_receipt)=={'name','pin'}and original_receipt['name']in('result.json','unknown.json'),'original-receipt-required')
    capture=AuthorityCapture(root,leaf)
    try:
        raw=_local_read(capture,original_receipt['name'],original_receipt['pin']);record=json.loads(raw)
        request=record['request'];frames=record['authority'];_need(request and frames,'original-child-unavailable')
        for index,item in enumerate(frames):
            _validate_frame(item['frame'],request,frames[:index])
            _need(json.loads(_local_read(capture,'authority-%d.json'%index,item['localPin']))==item['frame'],'local-frame')
        sources=authority._source_pins(root);sources['recovery']=authority._read_bound_file(Path(__file__))
        _need(sources==request['sources'],'source-drift')
        outer=authority._outer_authority(root)
        # A transport session may be recovered; it supplies transport only and
        # never replaces the independently pinned guest process authority.
        program=(_REMOTE_COMMON.replace('__RECIPE__',repr(recipe())).replace('__REQUEST__',repr(request))
                 +_REMOTE_STATUS.replace('__AUTHORITY__',repr(frames)))
        config,_,_=authority.closure.base._descriptor(root)
        argv=authority.closure.base.ssh_transport.build_ssh_argv(config,HOST,20,command=authority.closure.base.windows_credential_probe_ssh._remote_command(program))
        authority._verify_outer(root,{'outerAuthority':outer})
        _need(_local_read(capture,original_receipt['name'],original_receipt['pin'])==raw,'original-receipt-drift')
        current=authority._source_pins(root);current['recovery']=authority._read_bound_file(Path(__file__))
        _need(current==sources,'post-source-drift')
        completed=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
        _need(completed.returncode==0 and len(completed.stdout)<=65536,'status-transport')
        authority._verify_outer(root,{'outerAuthority':outer})
        _need(_local_read(capture,original_receipt['name'],original_receipt['pin'])==raw,'original-receipt-drift')
        value=json.loads(completed.stdout)
        return {'state':value.get('state','unknown'),'phase':value.get('phase'),'appAdmission':False,'installerAction':False,'replayAllowed':False}
    finally:capture.close()


def preflight(root: Path | str) -> dict[str,Any]:
    """Fresh fixed read-only recipe proof; never creates a consumed start fence."""
    import uuid
    root=Path(root).resolve(strict=True);leaf='windows-cp117-recovery-preflight-'+uuid.uuid4().hex[:8]
    directory=root/'.runtime/parity-evidence'/leaf;directory.mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    try:
        with _claim(root)as(claim,verify):
            outer=authority._outer_authority(root);config,_,_=authority.closure.base._descriptor(root)
            source_pin=authority._read_bound_file(Path(__file__))
            source=_observer(claim)
            wrapper="import sys,subprocess,base64\nsecret=sys.stdin.buffer.read(513)\nif not secret.endswith(b'\\n'):secret+=b'\\n'\nr=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',base64.b64decode("+repr(base64.b64encode(source.encode()).decode())+").decode()],input=secret,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=45,check=False)\nif len(r.stdout)<=65536:sys.stdout.buffer.write(r.stdout)\nsys.exit(r.returncode)\n"
            capture.create('request.json',json.dumps({'claim':claim,'outerAuthority':outer,'recipeSha256':_digest(recipe()),'sourceSha256':hashlib.sha256(source.encode()).hexdigest()},sort_keys=True).encode())
            capture.create('remote.py',source.encode())
            argv=authority.closure.base.ssh_transport.build_ssh_argv(config,HOST,50,command=authority.closure.base.windows_credential_probe_ssh._remote_command(wrapper))
            verify();authority._verify_outer(root,{'outerAuthority':outer});secret=credential._read_credential(root)
            completed=subprocess.run(argv,input=secret,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=50,check=False);secret=None
            capture.create('transport.stdout.private',completed.stdout[:65536])
            _need(completed.returncode==0 and len(completed.stdout)<=65536,'preflight-transport');value=json.loads(completed.stdout)
            verify();authority._verify_outer(root,{'outerAuthority':outer})
            _need(authority._read_bound_file(Path(__file__))==source_pin,'preflight-source-drift')
            pin=capture.create('result.json',completed.stdout)
            return {'state':value.get('state','unknown'),'phase':value.get('phase'),'recipeSha256':_digest(recipe()),'nativeActionAllowed':False,'evidenceLeaf':leaf,'receipt':pin}
    finally:capture.close()
