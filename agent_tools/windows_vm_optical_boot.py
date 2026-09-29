"""One-shot firmware optical boot confirmation for the disposable blank Windows VM.

This uses one QMP reset and one timed QMP space key. It stops before Windows
setup input and never depends on OCR or retries an uncertain QMP result.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import native_environment, ssh_transport, windows_vm_fresh_setup as setup
except ImportError:
    import native_environment  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]
    import windows_vm_fresh_setup as setup  # type: ignore[no-redef]


HOST = "archlinux"
VM_CORRELATION = "3d03016b-1848-4626-a7e6-4e2ef44b904f"
FIRST_CORRELATION = "ca76aff1-b67b-47cf-9e82-e61b1fe76ebb"
FIRST_CLOSURE = "b76bfd72-2d7b-459a-91da-a063e35c8007"
SECOND_CORRELATION = "98b4f1e0-968c-455b-a85b-d87490f5b256"
RESERVATION_ID = "env-fc3b3308d6a07175d1e4e08330f7f3aa"
DELAY_MS = 3000
HOLD_MS = 300
POST_MS = 5000
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
SHA = re.compile(r"^[0-9a-f]{64}$")

_REMOTE = r'''import hashlib,json,os,socket,stat,struct,time
GUEST=__GUEST__;ISO=__ISO__;ISO_HASH=__ISO_HASH__;ISO_SIZE=__ISO_SIZE__;DRIVER=__DRIVER__;DRIVER_HASH=__DRIVER_HASH__
CORR=__CORR__;VM_CORR=__VM_CORR__;RESERVATION=__RESERVATION__;MODE=__MODE__;CLOSE_CORR=__CLOSE_CORR__
ATTEMPT=__ATTEMPT__;EXPECTED_CLOSURE=__EXPECTED_CLOSURE__;FIRST_CLOSURE=__FIRST_CLOSURE__
DELAY_MS=__DELAY_MS__;HOLD_MS=__HOLD_MS__;POST_MS=__POST_MS__
DISK=GUEST+'/disk.qcow2';QMP=GUEST+'/qmp.sock'
PREFIX=GUEST+('/optical-boot-' if ATTEMPT==1 else '/optical-boot-attempt2-' if ATTEMPT==2 else '/optical-boot-attempt3-')
INTENT=PREFIX+'intent.json';BEFORE=PREFIX+'before.json';RESET=PREFIX+'reset.json'
KEY_INTENT=PREFIX+'key-intent.json';KEY_ACK=PREFIX+'key-ack.json';AFTER=PREFIX+'after.json'
PRE_FRAME=PREFIX+'before-'+CORR+'.ppm';POST_FRAME=PREFIX+'after-'+CORR+'.ppm'
CLOSED=PREFIX+'pre-effect-closed.json'
FIRST_CLOSED=GUEST+'/optical-boot-pre-effect-closed.json'
ORIGINAL_CORR=__FIRST_CORR__ if ATTEMPT==1 else __SECOND_CORR__
def private(path):
 s=os.lstat(path)
 if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('unsafe-directory')
def ticks(pid):
 try:
  with open('/proc/%d/stat'%pid) as f:return int(f.read().rsplit(')',1)[1].split()[19])
 except (OSError,ValueError,IndexError):return None
def read(path,limit=4096):
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.geteuid() or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)!=0o600 or not 0<a.st_size<=limit:raise ValueError('receipt-unsafe')
  raw=os.read(fd,limit+1);b=os.fstat(fd);n=os.stat(path,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if len(raw)!=a.st_size or any(getattr(a,k)!=getattr(b,k) or getattr(a,k)!=getattr(n,k) for k in keys):raise ValueError('receipt-changed')
  return json.loads(raw)
 finally:os.close(fd)
def qmp_socket_owned(lines,fds):
 matches=[]
 for line in lines:
  parts=line.split()
  if len(parts)>=8 and parts[-1]==QMP:
   try:matches.append((int(parts[3],16),parts[5],parts[6]))
   except (ValueError,IndexError):return False
 listeners=[item for item in matches if item[0]&0x10000 and item[1]=='01']
 if len(listeners)!=1 or any(item[0]&0x10000 and item!=listeners[0] for item in matches):return False
 return all('socket:['+inode+']' in fds.values() for flags,state,inode in matches)
def claim():
 private(GUEST)
 guest=read(GUEST+'/intent.json')
 if set(guest)!={'schemaVersion','correlationId','windowsSha256','driverSha256','windowsIso','driverIso','memoryMiB','vncPort','firmware'} or guest['schemaVersion']!=1 or guest['correlationId']!=VM_CORR or guest['windowsSha256']!=ISO_HASH or guest['driverSha256']!=DRIVER_HASH or guest['windowsIso']!=ISO or guest['driverIso']!=DRIVER or guest['memoryMiB']!=6144 or guest['vncPort']!=5927:raise ValueError('guest-identity')
 started=read(GUEST+'/started.json')
 if set(started)!={'pid','startTicks'} or type(started['pid'])!=int or type(started['startTicks'])!=int:raise ValueError('started-identity')
 pid=started['pid'];generation=started['startTicks']
 if ticks(pid)!=generation:raise ValueError('qemu-generation')
 exe=os.path.basename(os.readlink('/proc/%d/exe'%pid));argv=open('/proc/%d/cmdline'%pid,'rb').read().split(b'\0')
 optical=b'file='+ISO.encode()+b',media=cdrom,readonly=on'
 diskarg=b'file='+DISK.encode()+b',if=virtio,format=qcow2'
 qmp=b'unix:'+QMP.encode()+b',server=on,wait=off'
 memory=[argv[i+1] for i,item in enumerate(argv[:-1]) if item==b'-m']
 if exe!='qemu-system-x86_64' or optical not in argv or diskarg not in argv or qmp not in argv or memory!=[b'6144']:raise ValueError('qemu-argv')
 disk=os.stat(DISK,follow_symlinks=False);iso=os.stat(ISO,follow_symlinks=False)
 if not stat.S_ISREG(disk.st_mode) or not stat.S_ISREG(iso.st_mode):raise ValueError('media-kind')
 fds={item:os.readlink('/proc/%d/fd/'%pid+item) for item in os.listdir('/proc/%d/fd'%pid)}
 diskheld=False;isoheld=False
 for item,link in fds.items():
  if link in (DISK,ISO):
   held=os.stat('/proc/%d/fd/'%pid+item)
   if link==DISK and (held.st_dev,held.st_ino)==(disk.st_dev,disk.st_ino):diskheld=True
   if link==ISO and (held.st_dev,held.st_ino)==(iso.st_dev,iso.st_ino):isoheld=True
 with open('/proc/net/unix') as f:lines=f.read().splitlines()
 if not diskheld or not isoheld or not qmp_socket_owned(lines[1:],fds) or ticks(pid)!=generation:raise ValueError('qemu-fd')
 return {'qemuPid':pid,'qemuStartTicks':generation,'diskDevice':disk.st_dev,'diskInode':disk.st_ino,'isoDevice':iso.st_dev,'isoInode':iso.st_ino}
def source():
 fd=os.open(ISO,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.geteuid() or a.st_size!=ISO_SIZE:raise ValueError('iso-unsafe')
  h=hashlib.sha256()
  while True:
   b=os.read(fd,1048576)
   if not b:break
   h.update(b)
  z=os.fstat(fd);n=os.stat(ISO,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if h.hexdigest()!=ISO_HASH or any(getattr(a,k)!=getattr(z,k) or getattr(a,k)!=getattr(n,k) for k in keys):raise ValueError('iso-changed')
  return {'device':a.st_dev,'inode':a.st_ino,'sizeBytes':a.st_size,'mtimeNs':a.st_mtime_ns,'ctimeNs':a.st_ctime_ns,'sha256':h.hexdigest()}
 finally:os.close(fd)
def same_media(value):
 s=os.stat(ISO,follow_symlinks=False)
 return stat.S_ISREG(s.st_mode) and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(value['device'],value['inode'],value['sizeBytes'],value['mtimeNs'],value['ctimeNs'])
def blank_disk():
 fd=os.open(DISK,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.geteuid() or a.st_nlink!=1 or a.st_size>1073741824:raise ValueError('disk-unsafe')
  header=os.pread(fd,104,0)
  if len(header)!=104 or header[:4]!=b'QFI\xfb':raise ValueError('disk-header')
  version=struct.unpack_from('>I',header,4)[0]
  backing=struct.unpack_from('>Q',header,8)[0];backing_size=struct.unpack_from('>I',header,16)[0]
  cluster_bits=struct.unpack_from('>I',header,20)[0];virtual=struct.unpack_from('>Q',header,24)[0]
  crypt=struct.unpack_from('>I',header,32)[0];l1_size=struct.unpack_from('>I',header,36)[0]
  l1_offset=struct.unpack_from('>Q',header,40)[0];snapshots=struct.unpack_from('>I',header,60)[0]
  if version not in (2,3) or backing or backing_size or not 9<=cluster_bits<=21 or virtual!=96*1024**3 or crypt or snapshots or not 0<l1_size<=4096 or l1_offset<104 or l1_offset+l1_size*8>a.st_size:raise ValueError('disk-not-blank')
  table=os.pread(fd,l1_size*8,l1_offset)
  z=os.fstat(fd);n=os.stat(DISK,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if len(table)!=l1_size*8 or any(table) or any(getattr(a,k)!=getattr(z,k) or getattr(a,k)!=getattr(n,k) for k in keys):raise ValueError('disk-not-blank')
  return {'device':a.st_dev,'inode':a.st_ino,'virtualSizeBytes':virtual,'allocatedGuestClusters':0}
 finally:os.close(fd)
def write_all(fd,data):
 view=memoryview(data)
 while view:
  count=os.write(fd,view)
  if count<=0 or count>len(view):raise OSError('short-write')
  view=view[count:]
def record(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 try:write_all(fd,json.dumps(value,sort_keys=True).encode());os.fsync(fd)
 finally:os.close(fd)
 dfd=os.open(GUEST,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(dfd)
 finally:os.close(dfd)
def frame(path,capture,command=None):
 claimed=None
 if capture:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  claimed=os.fstat(fd);os.close(fd)
  command('screendump',{'filename':path})
 fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.geteuid() or a.st_nlink!=1 or stat.S_IMODE(a.st_mode)!=0o600 or not 64<=a.st_size<=8388608 or (claimed and (a.st_dev,a.st_ino)!=(claimed.st_dev,claimed.st_ino)):raise ValueError('frame-unsafe')
  data=os.read(fd,8388609);z=os.fstat(fd);n=os.stat(path,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if len(data)!=a.st_size or any(getattr(a,k)!=getattr(z,k) or getattr(a,k)!=getattr(n,k) for k in keys):raise ValueError('frame-changed')
  parts=data.split(b'\n',3)
  if len(parts)!=4 or parts[0]!=b'P6' or parts[2]!=b'255':raise ValueError('frame-format')
  width,height=[int(v) for v in parts[1].split()]
  if not 320<=width<=3840 or not 240<=height<=2160 or len(parts[3])!=width*height*3:raise ValueError('frame-dimensions')
  return {'sha256':hashlib.sha256(data).hexdigest(),'width':width,'height':height,'sizeBytes':a.st_size}
 finally:os.close(fd)
def qmp_open(owner):
 sock=socket.socket(socket.AF_UNIX);sock.settimeout(5);sock.connect(QMP)
 peer=struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
 if peer[0]!=owner['qemuPid'] or peer[1]!=os.geteuid() or ticks(peer[0])!=owner['qemuStartTicks'] or claim()!=owner:raise ValueError('qmp-peer')
 stream=sock.makefile('rwb',buffering=0)
 greeting=json.loads(stream.readline(65537))
 if 'QMP' not in greeting:raise ValueError('qmp-greeting')
 def command(name,arguments=None):
  if ticks(peer[0])!=owner['qemuStartTicks'] or claim()!=owner:raise ValueError('qmp-peer-changed')
  request={'execute':name}
  if arguments is not None:request['arguments']=arguments
  stream.write(json.dumps(request).encode()+b'\r\n')
  for _ in range(32):
   line=stream.readline(65537)
   if not line or len(line)>65536:raise ValueError('qmp-response')
   value=json.loads(line)
   if 'return' in value:return value['return']
   if 'error' in value:raise ValueError('qmp-error')
  raise ValueError('qmp-response')
 command('qmp_capabilities')
 return sock,command
def expected(owner,media,disk):
 return {'schemaVersion':1,'correlationId':CORR,'vmCorrelationId':VM_CORR,'reservationId':RESERVATION,
         'owner':owner,'media':media,'blankDisk':disk,'resetDelayMs':DELAY_MS,'holdMs':HOLD_MS,'postDelayMs':POST_MS}
def validate_receipts(owner,media,disk):
 if not os.path.lexists(INTENT):
  if any(os.path.lexists(path) for path in (BEFORE,RESET,KEY_INTENT,KEY_ACK,AFTER,PRE_FRAME,POST_FRAME)):raise ValueError('orphan-boot-evidence')
  return {'state':'absent'}
 intent=read(INTENT)
 if intent!=expected(owner,media,disk):raise ValueError('intent-mismatch')
 stages=((BEFORE,'before-screen'),(RESET,'reset-ack'),(KEY_INTENT,'key-intent'),(KEY_ACK,'key-ack'),(AFTER,'after-screen'))
 present=[os.path.lexists(path) for path,name in stages]
 if any(present[i] and not all(present[:i]) for i in range(len(present))):raise ValueError('receipt-order')
 frame_hashes={}
 for index,(path,name) in enumerate(stages):
  if not present[index]:break
  value=read(path)
  if name.endswith('screen'):
   expected_frame=frame(PRE_FRAME if name=='before-screen' else POST_FRAME,False)
   if value!={'schemaVersion':1,'correlationId':CORR,'owner':owner,'frame':expected_frame}:raise ValueError('screen-receipt')
   frame_hashes['before' if name=='before-screen' else 'after']=expected_frame['sha256']
  elif value!={'schemaVersion':1,'correlationId':CORR,'owner':owner,'phase':name}:raise ValueError('phase-receipt')
 state=('intent-only','pre-screen-observed','reset-acknowledged','key-uncertain','key-acknowledged','post-screen-observed')[sum(present)]
 return {'state':state,'frameHashes':frame_hashes}
def qmp_handshake(owner):
 phase='connect';sock=None;checks={'pid':None,'uid':None,'startTicks':None,'claim':None}
 try:
  sock=socket.socket(socket.AF_UNIX);sock.settimeout(5);sock.connect(QMP)
  phase='peer'
  raw=sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
  peer=struct.unpack('3i',raw)
  checks['pid']=peer[0]==owner['qemuPid'];checks['uid']=peer[1]==os.geteuid();checks['startTicks']=ticks(peer[0])==owner['qemuStartTicks']
  if not all((checks['pid'],checks['uid'],checks['startTicks'])):raise ValueError('peer-mismatch')
  phase='peer-claim'
  checks['claim']=claim()==owner
  if not checks['claim']:raise ValueError('owner-mismatch')
  phase='greeting'
  stream=sock.makefile('rwb',buffering=0)
  line=stream.readline(65537)
  if not line or len(line)>65536 or 'QMP' not in json.loads(line):raise ValueError('greeting-invalid')
  phase='capabilities'
  if ticks(peer[0])!=owner['qemuStartTicks'] or claim()!=owner:raise ValueError('owner-changed')
  stream.write(b'{"execute":"qmp_capabilities"}\r\n')
  for _ in range(32):
   line=stream.readline(65537)
   if not line or len(line)>65536:raise ValueError('capabilities-response')
   value=json.loads(line)
   if 'error' in value:raise ValueError('capabilities-error')
   if 'return' in value:return {'state':'ready','phase':'complete','peerChecks':checks}
  raise ValueError('capabilities-response')
 except Exception as error:
  allowed={'peer-mismatch','owner-mismatch','greeting-invalid','owner-changed','capabilities-response','capabilities-error'}
  claim_errors={'guest-identity','started-identity','qemu-generation','qemu-argv','media-kind','qemu-fd','receipt-unsafe','receipt-changed','unsafe-directory'}
  reason=('claim-'+str(error) if phase=='peer-claim' and isinstance(error,ValueError) and str(error) in claim_errors
          else str(error) if isinstance(error,ValueError) and str(error) in allowed
          else 'timeout' if isinstance(error,socket.timeout)
          else 'invalid-json' if isinstance(error,json.JSONDecodeError) else type(error).__name__)
  return {'state':'unknown','phase':phase,'reason':reason,'peerChecks':checks}
 finally:
  if sock is not None:sock.close()
def closure_sample():
 if not os.path.lexists(INTENT) or any(os.path.lexists(path) for path in (BEFORE,RESET,KEY_INTENT,KEY_ACK,AFTER,PRE_FRAME,POST_FRAME)):raise ValueError('pre-effect-evidence')
 owner=claim();media=source();disk=blank_disk()
 if (owner['isoDevice'],owner['isoInode'])!=(media['device'],media['inode']) or (owner['diskDevice'],owner['diskInode'])!=(disk['device'],disk['inode']):raise ValueError('binding-changed')
 if validate_receipts(owner,media,disk).get('state')!='intent-only':raise ValueError('pre-effect-evidence')
 handshake=qmp_handshake(owner)
 if handshake.get('state')!='ready' or handshake.get('phase')!='complete' or handshake.get('peerChecks')!={'pid':True,'uid':True,'startTicks':True,'claim':True}:raise ValueError('qmp-not-ready')
 if claim()!=owner or not same_media(media) or blank_disk()!=disk:raise ValueError('source-changed')
 return {'state':'intent-only','owner':owner,'media':media,'blankDisk':disk,'qmpPeerChecks':handshake['peerChecks']}
def phase_evidence(owner):
 def observed_frame(path):
  if not os.path.lexists(path):return {'state':'absent'}
  try:
   item=os.lstat(path)
   if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_nlink!=1 or stat.S_IMODE(item.st_mode)!=0o600:return {'state':'unsafe'}
   if item.st_size==0:return {'state':'zero-byte'}
   found=frame(path,False)
   return {'state':'valid-ppm','sizeBytes':found['sizeBytes'],'sha256':found['sha256']}
  except (OSError,ValueError,IndexError):return {'state':'invalid-or-changing'}
 return {'preFrame':observed_frame(PRE_FRAME),'postFrame':observed_frame(POST_FRAME),'qmpHandshake':qmp_handshake(owner)}
def verify_first_closed(owner,media,disk):
 if ATTEMPT not in (2,3) or MODE not in ('preflight','start','phase-probe','close-preflight','close-start'):return
 first=GUEST+'/optical-boot-'
 first_intent=first+'intent.json'
 first_stages=(first+'before.json',first+'reset.json',first+'key-intent.json',first+'key-ack.json',first+'after.json',
               first+'before-'+__FIRST_CORR__+'.ppm',first+'after-'+__FIRST_CORR__+'.ppm')
 if any(os.path.lexists(path) for path in first_stages):raise ValueError('first-attempt-effect-observed')
 observed=read(first_intent);original=expected(owner,media,disk);original['correlationId']=__FIRST_CORR__
 if observed!=original:raise ValueError('first-attempt-intent-changed')
 closed=read(FIRST_CLOSED)
 handshake=qmp_handshake(owner)
 sample={'state':'intent-only','owner':owner,'media':media,'blankDisk':disk,
         'qmpPeerChecks':{'pid':True,'uid':True,'startTicks':True,'claim':True}}
 digest=hashlib.sha256(json.dumps(sample,sort_keys=True).encode()).hexdigest()
 if (not isinstance(closed,dict) or set(closed)!={'schemaVersion','originalCorrelationId','closureCorrelationId','owner','media','blankDisk','sampleSha256','sampleIntervalNs'} or
     closed.get('schemaVersion')!=1 or closed.get('originalCorrelationId')!=__FIRST_CORR__ or
     closed.get('closureCorrelationId')!=FIRST_CLOSURE or closed.get('owner')!=owner or
     closed.get('media')!=media or closed.get('blankDisk')!=disk or closed.get('sampleSha256')!=digest or
     type(closed.get('sampleIntervalNs')) is not int or closed['sampleIntervalNs']<1000000000 or
     handshake.get('state')!='ready' or handshake.get('phase')!='complete' or handshake.get('peerChecks')!=sample['qmpPeerChecks'] or
     claim()!=owner or not same_media(media) or blank_disk()!=disk):raise ValueError('first-closure-changed')
def verify_second_closed(owner,media,disk):
 if ATTEMPT!=3 or MODE not in ('preflight','start'):return
 second=GUEST+'/optical-boot-attempt2-'
 stages=(second+'before.json',second+'reset.json',second+'key-intent.json',second+'key-ack.json',second+'after.json',
         second+'before-'+__SECOND_CORR__+'.ppm',second+'after-'+__SECOND_CORR__+'.ppm')
 if any(os.path.lexists(path) for path in stages):raise ValueError('second-attempt-effect-observed')
 original=expected(owner,media,disk);original['correlationId']=__SECOND_CORR__
 if read(second+'intent.json')!=original:raise ValueError('second-attempt-intent-changed')
 closed=read(second+'pre-effect-closed.json')
 handshake=qmp_handshake(owner)
 sample={'state':'intent-only','owner':owner,'media':media,'blankDisk':disk,
         'qmpPeerChecks':{'pid':True,'uid':True,'startTicks':True,'claim':True}}
 digest=hashlib.sha256(json.dumps(sample,sort_keys=True).encode()).hexdigest()
 if (not isinstance(closed,dict) or set(closed)!={'schemaVersion','originalCorrelationId','closureCorrelationId','owner','media','blankDisk','sampleSha256','sampleIntervalNs'} or
     closed.get('schemaVersion')!=1 or closed.get('originalCorrelationId')!=__SECOND_CORR__ or
     closed.get('closureCorrelationId')!=EXPECTED_CLOSURE or closed.get('owner')!=owner or
     closed.get('media')!=media or closed.get('blankDisk')!=disk or closed.get('sampleSha256')!=digest or
     type(closed.get('sampleIntervalNs')) is not int or closed['sampleIntervalNs']<1000000000 or
     handshake.get('state')!='ready' or handshake.get('phase')!='complete' or handshake.get('peerChecks')!=sample['qmpPeerChecks'] or
     claim()!=owner or not same_media(media) or blank_disk()!=disk):raise ValueError('second-closure-changed')
def historical_closures(owner,media,disk):
 if MODE!='status' or ATTEMPT not in (2,3) or not os.path.lexists(INTENT):return
 sample={'state':'intent-only','owner':owner,'media':media,'blankDisk':disk,
         'qmpPeerChecks':{'pid':True,'uid':True,'startTicks':True,'claim':True}}
 digest=hashlib.sha256(json.dumps(sample,sort_keys=True).encode()).hexdigest()
 prior=((GUEST+'/optical-boot-',__FIRST_CORR__,FIRST_CLOSURE),)
 if ATTEMPT==3:prior+=((GUEST+'/optical-boot-attempt2-',__SECOND_CORR__,EXPECTED_CLOSURE),)
 for prefix,correlation,closure in prior:
  stages=(prefix+'before.json',prefix+'reset.json',prefix+'key-intent.json',prefix+'key-ack.json',prefix+'after.json',
          prefix+'before-'+correlation+'.ppm',prefix+'after-'+correlation+'.ppm')
  if any(os.path.lexists(path) for path in stages):raise ValueError('prior-attempt-effect-observed')
  intent=expected(owner,media,disk);intent['correlationId']=correlation
  if read(prefix+'intent.json')!=intent:raise ValueError('prior-attempt-intent-changed')
  closed=read(prefix+'pre-effect-closed.json')
  if (not isinstance(closed,dict) or set(closed)!={'schemaVersion','originalCorrelationId','closureCorrelationId','owner','media','blankDisk','sampleSha256','sampleIntervalNs'} or
      closed.get('schemaVersion')!=1 or closed.get('originalCorrelationId')!=correlation or
      closed.get('closureCorrelationId')!=closure or closed.get('owner')!=owner or
      closed.get('media')!=media or closed.get('blankDisk')!=disk or closed.get('sampleSha256')!=digest or
      type(closed.get('sampleIntervalNs')) is not int or closed['sampleIntervalNs']<1000000000):raise ValueError('prior-closure-changed')
try:
 owner=claim();media=source()
 if (owner['isoDevice'],owner['isoInode'])!=(media['device'],media['inode']):raise ValueError('iso-binding-changed')
 if MODE=='status' and os.path.lexists(INTENT):
  stored=read(INTENT);disk=stored.get('blankDisk')
  if not isinstance(disk,dict) or disk!={'device':owner['diskDevice'],'inode':owner['diskInode'],'virtualSizeBytes':96*1024**3,'allocatedGuestClusters':0}:raise ValueError('blank-admission-changed')
 elif MODE=='status':disk=None
 else:
  disk=blank_disk()
  if (owner['diskDevice'],owner['diskInode'])!=(disk['device'],disk['inode']):raise ValueError('disk-binding-changed')
 if MODE!='phase-probe':
  verify_first_closed(owner,media,disk)
  verify_second_closed(owner,media,disk)
 historical_closures(owner,media,disk)
 if MODE=='preflight':
  if os.path.lexists(INTENT) or any(os.path.lexists(path) for path in (BEFORE,RESET,KEY_INTENT,KEY_ACK,AFTER,PRE_FRAME,POST_FRAME)):raise ValueError('boot-intent-exists')
  if claim()!=owner or not same_media(media) or blank_disk()!=disk:raise ValueError('admission-changed')
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'ready','owner':owner,'media':media,'blankDisk':disk,'reservationId':RESERVATION,'nativeActionAllowed':False}))
 elif MODE=='status':
  state=validate_receipts(owner,media,disk)
  if ATTEMPT in (1,2) and os.path.lexists(CLOSED):
   closed=read(CLOSED)
   if (CORR!=ORIGINAL_CORR or state['state']!='intent-only' or
       any(os.path.lexists(path) for path in (BEFORE,RESET,KEY_INTENT,KEY_ACK,AFTER,PRE_FRAME,POST_FRAME)) or
       not isinstance(closed,dict) or set(closed)!={'schemaVersion','originalCorrelationId','closureCorrelationId','owner','media','blankDisk','sampleSha256','sampleIntervalNs'} or
       closed.get('schemaVersion')!=1 or closed.get('originalCorrelationId')!=CORR or not isinstance(closed.get('closureCorrelationId'),str) or
       (CLOSE_CORR is not None and closed['closureCorrelationId']!=CLOSE_CORR) or
       closed.get('owner')!=owner or closed.get('media')!=media or closed.get('blankDisk')!=disk or
       not isinstance(closed.get('sampleSha256'),str) or len(closed['sampleSha256'])!=64 or
       type(closed.get('sampleIntervalNs')) is not int or closed['sampleIntervalNs']<1000000000 or
       hashlib.sha256(json.dumps(closure_sample(),sort_keys=True).encode()).hexdigest()!=closed['sampleSha256']):raise ValueError('closure-receipt')
   state['state']='pre-effect-closed'
   state['closureCorrelationId']=closed['closureCorrelationId']
  if claim()!=owner:raise ValueError('owner-changed')
  evidence=phase_evidence(owner) if state['state']!='absent' else None
  if claim()!=owner:raise ValueError('owner-changed')
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,**state,'owner':owner,'phaseEvidence':evidence,'nativeActionAllowed':False}))
 elif MODE=='close-start':
  if ATTEMPT not in (1,2) or CORR!=ORIGINAL_CORR or not CLOSE_CORR or os.path.lexists(CLOSED):raise ValueError('closure-unavailable')
  first_at=time.monotonic_ns();first=closure_sample()
  time.sleep(1)
  second_at=time.monotonic_ns();second=closure_sample()
  if second_at-first_at<1000000000 or first!=second:raise ValueError('closure-samples-changed')
  verify_first_closed(first['owner'],first['media'],first['blankDisk'])
  digest=hashlib.sha256(json.dumps(first,sort_keys=True).encode()).hexdigest()
  record(CLOSED,{'schemaVersion':1,'originalCorrelationId':CORR,'closureCorrelationId':CLOSE_CORR,
                 'owner':first['owner'],'media':first['media'],'blankDisk':first['blankDisk'],
                 'sampleSha256':digest,'sampleIntervalNs':second_at-first_at})
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'closureCorrelationId':CLOSE_CORR,
                    'state':'pre-effect-closed','owner':first['owner'],'sampleSha256':digest,
                    'sampleIntervalNs':second_at-first_at,'nativeActionAllowed':False}))
 elif MODE=='close-preflight':
  if ATTEMPT not in (1,2) or CORR!=ORIGINAL_CORR or not CLOSE_CORR or os.path.lexists(CLOSED):raise ValueError('closure-unavailable')
  first_at=time.monotonic_ns();first=closure_sample()
  time.sleep(1)
  second_at=time.monotonic_ns();second=closure_sample()
  if second_at-first_at<1000000000 or first!=second:raise ValueError('closure-samples-changed')
  digest=hashlib.sha256(json.dumps(first,sort_keys=True).encode()).hexdigest()
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'closureCorrelationId':CLOSE_CORR,
                    'state':'ready','owner':first['owner'],'media':first['media'],
                    'blankDisk':first['blankDisk'],'reservationId':RESERVATION,
                    'sampleSha256':digest,
                    'sampleIntervalNs':second_at-first_at,'nativeActionAllowed':False}))
 elif MODE=='phase-probe':
  phase='admission';probe={'state':'unknown','phase':phase}
  try:
   if validate_receipts(owner,media,disk).get('state')!='intent-only' or any(os.path.lexists(path) for path in (PRE_FRAME,POST_FRAME)):
    raise ValueError('second-attempt-effect-observed')
   verify_first_closed(owner,media,disk)
   phase='qmp-open';sock,command=qmp_open(owner)
   try:
    phase='closure-with-qmp-open';verify_first_closed(owner,media,disk)
    phase='complete';probe={'state':'ready','phase':phase}
   finally:sock.close()
  except Exception as error:
   allowed={'second-attempt-effect-observed','first-attempt-effect-observed','first-attempt-intent-changed',
            'first-closure-changed','qmp-peer','qmp-greeting','qmp-peer-changed','qmp-not-ready'}
   probe={'state':'unknown','phase':phase,'reason':str(error) if isinstance(error,ValueError) and str(error) in allowed else type(error).__name__}
  print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'phase-probed','owner':owner,
                    'probe':probe,'nativeActionAllowed':False}))
 elif MODE=='start':
  if os.path.lexists(INTENT) or any(os.path.lexists(path) for path in (BEFORE,RESET,KEY_INTENT,KEY_ACK,AFTER,PRE_FRAME,POST_FRAME)):raise ValueError('boot-intent-exists')
  record(INTENT,expected(owner,media,disk))
  verify_first_closed(owner,media,disk)
  verify_second_closed(owner,media,disk)
  sock,command=qmp_open(owner)
  try:
   if claim()!=owner or not same_media(media) or blank_disk()!=disk:raise ValueError('admission-changed')
   first=frame(PRE_FRAME,True,command)
   record(BEFORE,{'schemaVersion':1,'correlationId':CORR,'owner':owner,'frame':first})
   if claim()!=owner or blank_disk()!=disk:raise ValueError('owner-changed-before-reset')
   command('system_reset')
   record(RESET,{'schemaVersion':1,'correlationId':CORR,'owner':owner,'phase':'reset-ack'})
   until=time.monotonic()+DELAY_MS/1000
   while time.monotonic()<until:time.sleep(min(.1,until-time.monotonic()))
   if claim()!=owner or not same_media(media) or blank_disk()!=disk:raise ValueError('owner-changed-before-key')
   record(KEY_INTENT,{'schemaVersion':1,'correlationId':CORR,'owner':owner,'phase':'key-intent'})
   command('send-key',{'keys':[{'type':'qcode','data':'spc'}],'hold-time':HOLD_MS})
   record(KEY_ACK,{'schemaVersion':1,'correlationId':CORR,'owner':owner,'phase':'key-ack'})
   until=time.monotonic()+POST_MS/1000
   while time.monotonic()<until:time.sleep(min(.1,until-time.monotonic()))
   if claim()!=owner or not same_media(media):raise ValueError('owner-changed-after-key')
   last=frame(POST_FRAME,True,command)
   record(AFTER,{'schemaVersion':1,'correlationId':CORR,'owner':owner,'frame':last})
   print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'post-screen-observed','owner':owner,'frameHashes':{'before':first['sha256'],'after':last['sha256']},'nativeActionAllowed':False}))
  finally:sock.close()
 else:raise ValueError('invalid-mode')
except Exception:
 print(json.dumps({'schemaVersion':1,'correlationId':CORR,'state':'unknown','nativeActionAllowed':False}))
'''


def _check(host: str, correlation_id: str, timeout_seconds: int) -> None:
    if (host != HOST or not isinstance(correlation_id, str) or not UUID.fullmatch(correlation_id)
            or correlation_id == VM_CORRELATION or type(timeout_seconds) is not int
            or not 30 <= timeout_seconds <= 300):
        raise ValueError("Windows optical boot requires fixed Arch host and new correlation")


def _reservation(root: str | Path) -> Mapping[str, Any]:
    directory, path = native_environment._root_paths(root)
    native_environment._require_private(directory, directory=True)
    records = native_environment._load(path)["reservations"]
    selected = [item for item in records if item.get("id") == RESERVATION_ID]
    if len(selected) != 1:
        raise ValueError("Windows baseline reservation is unavailable")
    record = selected[0]
    if (record.get("hostAlias") != HOST or record.get("environment") != setup.ENVIRONMENT
            or record.get("operator") != setup.OPERATOR
            or record.get("requestedMemoryBytes") != setup.MEMORY_MIB * 1024 * 1024
            or record.get("allocationState") not in ("pending", "running")):
        raise ValueError("Windows baseline reservation changed")
    return {"reservationId": RESERVATION_ID, "allocationState": record["allocationState"]}


def _intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-boot"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Windows optical boot journal is unsafe")
    return directory / "intent.json"


def _payload(correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": HOST, "correlationId": correlation_id,
            "vmCorrelationId": VM_CORRELATION, "reservationId": RESERVATION_ID,
            "guest": setup.GUEST, "isoSha256": setup.WINDOWS_SHA256,
            "resetDelayMs": DELAY_MS, "holdMs": HOLD_MS, "postDelayMs": POST_MS}


def _save(path: Path, correlation_id: str, payload: Mapping[str, Any] | None = None) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(json.dumps(_payload(correlation_id) if payload is None else payload, sort_keys=True).encode())
        while view:
            count = os.write(fd, view)
            if count <= 0 or count > len(view):
                raise OSError("Windows optical boot intent short write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read(path: Path, correlation_id: str, payload: Mapping[str, Any] | None = None) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        data = os.read(fd, 4097)
        after = os.fstat(fd)
        named = os.lstat(path)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 4096
                or len(data) != before.st_size or any(getattr(before, key) != getattr(after, key)
                    or getattr(before, key) != getattr(named, key) for key in keys)
                or json.loads(data) != (_payload(correlation_id) if payload is None else payload)):
            raise ValueError("Windows optical boot intent changed")
    finally:
        os.close(fd)


def _program(correlation_id: str, mode: str, close_correlation_id: str | None = None,
             attempt: int = 1, expected_closure: str | None = None) -> str:
    if attempt not in (1, 2, 3) or (attempt in (2, 3) and not expected_closure):
        raise ValueError("Windows optical attempt is invalid")
    program = _REMOTE
    values = {"GUEST": setup.GUEST, "ISO": setup.WINDOWS_ISO, "ISO_HASH": setup.WINDOWS_SHA256,
              "ISO_SIZE": setup.WINDOWS_SIZE, "DRIVER": setup.DRIVER_ISO, "DRIVER_HASH": setup.DRIVER_SHA256,
              "CORR": correlation_id, "VM_CORR": VM_CORRELATION,
              "RESERVATION": RESERVATION_ID, "MODE": mode, "CLOSE_CORR": close_correlation_id,
              "FIRST_CORR": FIRST_CORRELATION,
              "FIRST_CLOSURE": FIRST_CLOSURE, "SECOND_CORR": SECOND_CORRELATION,
              "ATTEMPT": attempt, "EXPECTED_CLOSURE": expected_closure,
              "DELAY_MS": DELAY_MS, "HOLD_MS": HOLD_MS, "POST_MS": POST_MS}
    for key, value in values.items():
        program = program.replace("__" + key + "__", repr(value))
    return program


def _close_intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-boot-pre-effect-close"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("Windows optical closure journal is unsafe")
    return directory / "intent.json"


def _close_payload(close_correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": HOST, "originalCorrelationId": FIRST_CORRELATION,
            "closureCorrelationId": close_correlation_id, "vmCorrelationId": VM_CORRELATION,
            "reservationId": RESERVATION_ID, "guest": setup.GUEST,
            "isoSha256": setup.WINDOWS_SHA256, "sampleGapMs": 1000}


def _remote(root: str | Path, host: str, correlation_id: str, mode: str,
            timeout_seconds: int, close_correlation_id: str | None = None,
            attempt: int = 1, expected_closure: str | None = None) -> dict[str, Any]:
    program = _program(correlation_id, mode, close_correlation_id, attempt, expected_closure)
    config = ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Configured Arch transport is unavailable")
    argv = ssh_transport.build_ssh_argv(config, host, min(timeout_seconds, 30),
                                        command=("python3", "-c", "exec(" + repr(program) + ")"))
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout_seconds, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Windows optical boot transport is unknown")
    value = json.loads(result.stdout)
    states = {"ready", "absent", "intent-only", "pre-effect-closed", "phase-probed", "pre-screen-observed", "reset-acknowledged",
              "key-uncertain", "key-acknowledged", "post-screen-observed", "unknown"}
    if (not isinstance(value, Mapping) or value.get("schemaVersion") != 1
            or value.get("correlationId") != correlation_id or value.get("nativeActionAllowed") is not False
            or value.get("state") not in states):
        raise ValueError("Windows optical boot response is invalid")
    owner = value.get("owner")
    if value.get("state") != "unknown":
        if (not isinstance(owner, Mapping)
                or set(owner) != {"qemuPid", "qemuStartTicks", "diskDevice", "diskInode", "isoDevice", "isoInode"}
                or any(type(item) is not int or item <= 0 for item in owner.values())):
            raise ValueError("Windows optical boot owner is incomplete")
    if value.get("state") == "ready":
        disk = value.get("blankDisk")
        media = value.get("media")
        if (value.get("reservationId") != RESERVATION_ID
                or not isinstance(disk, Mapping)
                or set(disk) != {"device", "inode", "virtualSizeBytes", "allocatedGuestClusters"}
                or type(disk.get("device")) is not int or type(disk.get("inode")) is not int
                or disk["device"] != owner["diskDevice"] or disk["inode"] != owner["diskInode"]
                or disk.get("allocatedGuestClusters") != 0 or disk.get("virtualSizeBytes") != 96 * 1024**3
                or not isinstance(media, Mapping)
                or set(media) != {"device", "inode", "sizeBytes", "mtimeNs", "ctimeNs", "sha256"}
                or media.get("device") != owner["isoDevice"] or media.get("inode") != owner["isoInode"]
                or media.get("sizeBytes") != setup.WINDOWS_SIZE
                or type(media.get("mtimeNs")) is not int or type(media.get("ctimeNs")) is not int
                or media.get("sha256") != setup.WINDOWS_SHA256):
            raise ValueError("Windows optical boot preflight is incomplete")
    if mode in ("close-preflight", "close-start"):
        original = FIRST_CORRELATION if attempt == 1 else SECOND_CORRELATION if attempt == 2 else None
        if (correlation_id != original or close_correlation_id is None
                or value.get("closureCorrelationId") != close_correlation_id
                or value.get("state") not in ("ready", "pre-effect-closed", "unknown")):
            raise ValueError("Windows optical closure response is invalid")
        if value["state"] != "unknown" and (not isinstance(value.get("sampleSha256"), str)
                                           or not SHA.fullmatch(value["sampleSha256"])
                                           or type(value.get("sampleIntervalNs")) is not int
                                           or value["sampleIntervalNs"] < 1_000_000_000):
            raise ValueError("Windows optical closure samples are incomplete")
    if value.get("state") == "post-screen-observed":
        hashes = value.get("frameHashes")
        if (not isinstance(hashes, Mapping) or set(hashes) != {"before", "after"}
                or any(not isinstance(item, str) or not SHA.fullmatch(item) for item in hashes.values())):
            raise ValueError("Windows optical boot frames are invalid")
    if mode == "phase-probe":
        probe = value.get("probe")
        if (value.get("state") != "phase-probed" or not isinstance(probe, Mapping)
                or probe.get("state") not in ("ready", "unknown")
                or probe.get("phase") not in ("admission", "qmp-open", "closure-with-qmp-open", "complete")
                or (probe["state"] == "ready" and (probe["phase"] != "complete" or "reason" in probe))
                or (probe["state"] == "unknown" and
                    (not isinstance(probe.get("reason"), str) or len(probe["reason"]) > 64))):
            raise ValueError("Windows optical phase probe is incomplete")
    if mode == "close-start" or (mode == "status" and value.get("state") == "pre-effect-closed"):
        original = FIRST_CORRELATION if attempt == 1 else SECOND_CORRELATION if attempt == 2 else None
        if (value.get("state") == "pre-effect-closed" and
                (correlation_id != original or
                 (close_correlation_id is not None and value.get("closureCorrelationId") != close_correlation_id))):
            raise ValueError("Windows optical closure response is invalid")
    if mode == "status" and value.get("state") not in ("unknown", "absent"):
        evidence = value.get("phaseEvidence")
        if (not isinstance(evidence, Mapping) or set(evidence) != {"preFrame", "postFrame", "qmpHandshake"}
                or any(not isinstance(evidence[key], Mapping) for key in evidence)
                or evidence["preFrame"].get("state") not in ("absent", "zero-byte", "valid-ppm", "unsafe", "invalid-or-changing")
                or evidence["postFrame"].get("state") not in ("absent", "zero-byte", "valid-ppm", "unsafe", "invalid-or-changing")
                or evidence["qmpHandshake"].get("state") not in ("ready", "unknown")
                or evidence["qmpHandshake"].get("phase") not in ("connect", "peer", "peer-claim", "greeting", "capabilities", "complete")
                or not isinstance(evidence["qmpHandshake"].get("peerChecks"), Mapping)
                or set(evidence["qmpHandshake"]["peerChecks"]) != {"pid", "uid", "startTicks", "claim"}
                or any(item is not None and type(item) is not bool for item in evidence["qmpHandshake"]["peerChecks"].values())):
            raise ValueError("Windows optical boot phase evidence is incomplete")
    return dict(value)


def preflight(root: str | Path, *, host: str, correlation_id: str,
              timeout_seconds: int = 90) -> dict[str, Any]:
    _check(host, correlation_id, timeout_seconds)
    _reservation(root)
    if setup.status(root, host=host, correlation_id=VM_CORRELATION, timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    return _remote(root, host, correlation_id, "preflight", timeout_seconds)


def start(root: str | Path, *, host: str, correlation_id: str,
          timeout_seconds: int = 90) -> dict[str, Any]:
    _check(host, correlation_id, timeout_seconds)
    _reservation(root)
    if setup.status(root, host=host, correlation_id=VM_CORRELATION, timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    path = _intent(root, create=True)
    try:
        _save(path, correlation_id)
    except FileExistsError as error:
        raise ValueError("Windows optical boot intent exists; use status") from error
    try:
        result = _remote(root, host, correlation_id, "start", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"],
            "owner": result.get("owner"), "frameHashes": result.get("frameHashes"),
            "replayAllowed": False, "nativeActionAllowed": False}


def status(root: str | Path, *, host: str, correlation_id: str,
           timeout_seconds: int = 60) -> dict[str, Any]:
    _check(host, correlation_id, timeout_seconds)
    _read(_intent(root, create=False), correlation_id)
    _reservation(root)
    try:
        result = _remote(root, host, correlation_id, "status", timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"correlationId": correlation_id, "state": result["state"],
            "owner": result.get("owner"), "frameHashes": result.get("frameHashes"),
            "phaseEvidence": result.get("phaseEvidence"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_preflight(root: str | Path, *, host: str, closure_correlation_id: str,
                    timeout_seconds: int = 90) -> dict[str, Any]:
    """Read-only proof that the first attempt has no observed VM effect."""
    _check(host, closure_correlation_id, timeout_seconds)
    if closure_correlation_id == FIRST_CORRELATION:
        raise ValueError("Closure needs a distinct correlation")
    _read(_intent(root, create=False), FIRST_CORRELATION)
    _reservation(root)
    if setup.status(root, host=host, correlation_id=VM_CORRELATION,
                    timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    result = _remote(root, host, FIRST_CORRELATION, "close-preflight", timeout_seconds,
                     closure_correlation_id)
    return {"closureCorrelationId": closure_correlation_id, "originalCorrelationId": FIRST_CORRELATION,
            "state": result["state"], "owner": result.get("owner"),
            "sampleSha256": result.get("sampleSha256"),
            "sampleIntervalNs": result.get("sampleIntervalNs"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_start(root: str | Path, *, host: str, closure_correlation_id: str,
                timeout_seconds: int = 90) -> dict[str, Any]:
    """One-shot terminal receipt for the original pre-effect attempt."""
    _check(host, closure_correlation_id, timeout_seconds)
    if closure_correlation_id == FIRST_CORRELATION:
        raise ValueError("Closure needs a distinct correlation")
    _read(_intent(root, create=False), FIRST_CORRELATION)
    _reservation(root)
    if setup.status(root, host=host, correlation_id=VM_CORRELATION,
                    timeout_seconds=timeout_seconds).get("state") != "running-observed":
        raise ValueError("Windows baseline VM is not running-observed")
    path = _close_intent(root, create=True)
    try:
        _save(path, closure_correlation_id, _close_payload(closure_correlation_id))
    except FileExistsError as error:
        raise ValueError("Windows optical closure intent exists; use close status") from error
    try:
        result = _remote(root, host, FIRST_CORRELATION, "close-start", timeout_seconds,
                         closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"closureCorrelationId": closure_correlation_id, "originalCorrelationId": FIRST_CORRELATION,
            "state": result["state"], "owner": result.get("owner"),
            "sampleSha256": result.get("sampleSha256"),
            "sampleIntervalNs": result.get("sampleIntervalNs"),
            "replayAllowed": False, "nativeActionAllowed": False}


def close_status(root: str | Path, *, host: str, closure_correlation_id: str,
                 timeout_seconds: int = 60) -> dict[str, Any]:
    _check(host, closure_correlation_id, timeout_seconds)
    if closure_correlation_id == FIRST_CORRELATION:
        raise ValueError("Closure needs a distinct correlation")
    _read(_intent(root, create=False), FIRST_CORRELATION)
    _read(_close_intent(root, create=False), closure_correlation_id,
          _close_payload(closure_correlation_id))
    _reservation(root)
    try:
        result = _remote(root, host, FIRST_CORRELATION, "status", timeout_seconds,
                         closure_correlation_id)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    state = result["state"] if result["state"] == "pre-effect-closed" else "unknown"
    return {"closureCorrelationId": closure_correlation_id, "originalCorrelationId": FIRST_CORRELATION,
            "state": state, "owner": result.get("owner"),
            "replayAllowed": False, "nativeActionAllowed": False}
