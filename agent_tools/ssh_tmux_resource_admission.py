"""Protected new-job resource binding. No reservation release or generic command.

All pending rows count, including the unbound historical builder reservation.
One cooperating root operator owns inventory/remote lifecycle during admission.
"""
from __future__ import annotations
import ast
import hashlib
import json
import math
import os
import re
from pathlib import Path
import time
from . import ssh_tmux_terminal_closure as closure
from . import ssh_tmux_mcp_adapter as adapter
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import linux_package_fixture_build as build
from . import native_host_observation as host
from . import vm_workflow
need=old.need
MEMORY=8*1024**3
HOST_SHA='f913eac3e10c7beaf4316d8e27424a5314ba889991b4ccb53dfe7574819b9c74'
VM_SHA='d0db49f7c4fc67348dd6f7ba9ebb35cfad01f055ffde374858fa36ac02f6711c'

_REMOTE=r'''
def proc_visible():
 try:
  if open('/proc/1/comm',encoding='ascii').read(128).strip()!='systemd':return False
  if os.readlink('/proc/1/ns/pid')!=os.readlink('/proc/self/ns/pid'):return False
  mounts=[]
  with open('/proc/self/mountinfo',encoding='ascii') as f:
   for line in f:
    before,after=line.strip().split(' - ',1)
    fields=before.split();tail=after.split()
    if len(fields)>=6 and fields[4]=='/proc':mounts.append((fields,tail))
  if len(mounts)!=1:return False
  fields,tail=mounts[0]
  if len(tail)<3 or tail[0]!='proc':return False
  options=set((fields[5]+','+tail[2]).split(','))
  return 'subset=pid' not in options and not any(
   option.startswith('hidepid=') and option!='hidepid=0' for option in options)
 except (OSError,ValueError,IndexError):return False
def census():
 boot=open('/proc/sys/kernel/random/boot_id').read().strip(); rows=[]
 if re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',boot)is None or not proc_visible():raise ValueError('resource_host_unknown')
 entries=os.listdir('/proc')
 if len(entries)>8192:raise ValueError('resource_census_limit')
 for entry in entries:
  if not entry.isdigit():continue
  pid=int(entry)
  base='/proc/'+entry
  start=stat(pid)
  if start is None:
   if os.path.exists(base):raise ValueError('resource_process_unknown')
   continue
  try:exe=os.path.basename(os.readlink(base+'/exe'))
  except (OSError,UnicodeError):
   after=stat(pid)
   if (after is None and os.path.exists(base)) or (after is not None and not (kernel_thread(pid,start) or terminal_zombie(pid,start))):raise ValueError('resource_process_unknown')
   continue
  if not exe.startswith('qemu-system-'):continue
  before=open(base+'/stat').read().rsplit(')',1)[1].split()
  raw=open(base+'/cmdline','rb').read(16385)
  executable=os.stat(base+'/exe');uid=os.stat(base).st_uid
  configured=parse_memory(raw.rstrip(b'\0').split(b'\0'))
  after=open(base+'/stat').read().rsplit(')',1)[1].split()
  current_executable=os.stat(base+'/exe')
  generation=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink)
  if int(before[19])!=start or before[19]!=after[19] or before[3]!=after[3] or not 0<len(raw)<=16384 or configured is None or generation(executable)!=generation(current_executable) or os.path.basename(os.readlink(base+'/exe'))!=exe or os.stat(base).st_uid!=uid:raise ValueError('resource_identity_changed')
  rows.append({'pid':pid,'startTicks':int(before[19]),'sessionId':int(before[3]),'uid':uid,'commandSha256':hashlib.sha256(raw).hexdigest(),'executableGeneration':[executable.st_dev,executable.st_ino,executable.st_mode,executable.st_uid,executable.st_gid,executable.st_size,executable.st_mtime_ns,executable.st_ctime_ns,executable.st_nlink],'configuredMemoryBytes':configured})
 if open('/proc/sys/kernel/random/boot_id').read().strip()!=boot:raise ValueError('resource_boot_changed')
 return boot,sorted(rows,key=lambda x:x['pid'])
boot,vms=census();first,physical,swap=memory();time.sleep(.05);last,physical2,swap2=memory();boot2,vms2=census()
if first is None or last is None or physical!=physical2 or boot!=boot2 or vms!=vms2:raise ValueError('resource_observation_unknown')
sudo_uid=os.environ.get('SUDO_UID','')
if re.fullmatch('[0-9]{1,10}',sudo_uid)is None or not 0<=int(sudo_uid)<2**32:raise ValueError('resource_principal_unknown')
principal=pwd.getpwuid(int(sudo_uid))
fixed=os.path.join(principal.pw_dir,'.vpn-control-mcp-fixtures')
chain=[]
try:
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append((fd,None,None,os.fstat(fd)))
 for part in fixed.split('/')[1:]:
  parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);s=os.fstat(fd);named=os.stat(part,dir_fd=parent,follow_symlinks=False)
  if (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid):raise ValueError('resource_disk_ancestor_changed')
  chain.append((fd,parent,part,s))
 if s.st_uid!=principal.pw_uid:raise ValueError('resource_disk_owner_changed')
 disk=os.fstatvfs(fd)
 for held,parent,part,before in chain:
  after=os.fstat(held)
  if (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)!=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid):raise ValueError('resource_disk_ancestor_changed')
  if parent is not None:
   named=os.stat(part,dir_fd=parent,follow_symlinks=False)
   if (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid):raise ValueError('resource_disk_ancestor_changed')
finally:
 for held,_,_,_ in reversed(chain):os.close(held)
result={'state':'observed','hostBootId':boot,'vms':vms,'physicalMemoryBytes':physical,'swapUsedBytes':swap2,'samples':[first,last],'diskAvailableBytes':disk.f_bavail*disk.f_frsize,'diskDevice':s.st_dev,'inventoryComplete':True}
print(json.dumps(result,separators=(',',':')))
'''

def host_program():
 need(hashlib.sha256(Path(host.__file__).read_bytes()).hexdigest()==HOST_SHA,'host_source_changed')
 tree=ast.parse(host._REMOTE_PROGRAM)
 functions=[ast.get_source_segment(host._REMOTE_PROGRAM,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('memory','parse_memory','stat','kernel_thread','terminal_zombie')]
 need(len(functions)==5,'host_definitions_changed')
 value='import json,os,sys,time,hashlib,re,pwd\nif os.geteuid()!=0:raise ValueError("resource_privilege_required")\nif sys.stdin.buffer.read(16385)!=b"{}":raise ValueError("resource_fixed_payload_required")\n'+'\n'.join(functions)+'\n'+_REMOTE
 compile(value,'<fixed-tmux-resource-observation>','exec');return value


def fixed_resource_query(root,program,payload,guard):
 """Closed Arch resource read through the existing bounded tmux capture."""
 need(program==host_program() and type(payload)is dict and not payload,'resource_fixed_query_required')
 from . import ssh_direct_nested_channel as direct, ssh_transport
 from .native_review_source_closure import _Held
 held=_Held();private=password=None
 try:
  source_pins={}
  for module in (host,closure,adapter,vm_workflow):
   path=Path(module.__file__).absolute();pin=closure.pipe._read(path,262144,False)[1];held.read(str(path),pin['sha256']);source_pins[str(path)]=pin
  path=Path(__file__).absolute();pin=closure.pipe._read(path,262144,False)[1];held.read(str(path),pin['sha256']);source_pins[str(path)]=pin
  with direct.Guard(Path(root)) as authority:
   def close():authority.guard();held.finish();held.final_identity_pass();guard()
   close();target=authority.config.hosts['archlinux']
   need(target.transport=='nested' and type(target.user)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',target.user)is not None,'resource_principal_unknown')
   password=target.password
   need(type(password)is str and 0<len(password.encode())<=512 and not any(c in password for c in ('\n','\r','\0')),'resource_credential_unknown')
   argv=ssh_transport.build_ssh_argv(authority.config,'archlinux',30,command=('sudo','-S','-p','','python3','-I','-B','-c','exec('+repr(program)+')'))
   private=password.encode()+b'\n{}';password=None
   def launch():
    close();return ssh_transport.popen_ssh(argv,cwd=root,stdin=adapter.subprocess.PIPE,stdout=adapter.subprocess.PIPE,stderr=adapter.subprocess.PIPE,bufsize=0)
   binding={'phase':'status','snapshot':None,'sources':source_pins,'transport':{'hostAlias':'archlinux','privilegedResourceRead':True},'local':{},'argvSha256':ssh_transport.argv_sha256(argv)}
   outcome,capsule=adapter._capture(root,authority=binding,launch=launch,payload=private,guard=close,timeout_seconds=30,private_payload=True,public_reply=_public_resource_reply);private=None
   close();need(outcome['state']=='captured','resource_capture_unknown')
   raw,pin=closure.pipe._read(capsule/'receipt.json');need(pin==outcome['receiptPin'],'resource_capture_changed');record=json.loads(raw)
   raw,pin=closure.pipe._read(capsule/'stdout',adapter.MAX_STDOUT);stderr,stderr_pin=closure.pipe._read(capsule/'stderr',adapter.MAX_STDERR)
   need(pin==record['stdoutPin'] and stderr_pin==record['stderrPin'] and not stderr,'resource_capture_changed')
   value=json.loads(raw,object_pairs_hook=closure.ssh_transport._reject_duplicate_keys)
   close();need(type(value)is dict,'resource_reply_unknown');return value,{'directory':str(capsule.relative_to(root)),'receiptPin':outcome['receiptPin'],'stdoutPin':pin}
 finally:private=password=None;held.close()


def sources(root,engineering_context=None):
 code_root=Path(root) if engineering_context is None else engineering_context.source_root
 if engineering_context is not None:
  engineering_context.require_native_consumers((Path(__file__),Path(closure.__file__),Path(adapter.__file__),Path(host.__file__),Path(vm_workflow.__file__)))
 result=closure._sources(code_root)
 for module,expected in ((host,HOST_SHA),(vm_workflow,VM_SHA)):
  path=Path(module.__file__).absolute();pin=closure.pipe._read(path,262144,False)[1];need(pin['sha256']==expected,'resource_dependency_changed');result[str(path)]=pin
 path=Path(__file__).absolute();result[str(path)]=closure.pipe._read(path,262144,False)[1];return result


def directory(root,corr,create=False):
 need(build._correlation(corr),'resource_correlation_invalid')
 parent=Path(root)/'.rag_index/ssh-tmux-resource-admission'
 if create and not os.path.lexists(parent):closure.pipe._mkdir(parent.parent,parent.name)
 if create and not os.path.lexists(parent/corr):closure.pipe._mkdir(parent,corr)
 return parent/corr


def inventory(root,request,identity):
 need(type(identity)is dict and set(identity)=={'reservationId','token','hostAlias','environment','operator'} and all(type(v)is str and v for v in identity.values()),'resource_identity_invalid')
 need(identity['hostAlias']=='archlinux' and identity['operator']=='root-tmux-build' and identity['environment']=='owned-linux-package-build-'+request['correlationId'],'resource_identity_crossed')
 raw,pin=closure.pipe._read(Path(root)/'.rag_index/native-environments/reservations.json',1048576)
 value=json.loads(raw,object_pairs_hook=closure.ssh_transport._reject_duplicate_keys)
 need(type(value)is dict and set(value)=={'version','reservations'} and type(value['reservations'])is list,'resource_inventory_invalid')
 rows=value['reservations'];ids=set();target=None;pending=[]
 for row in rows:
  need(type(row)is dict and type(row.get('id'))is str and row['id'] not in ids and type(row.get('requestedMemoryBytes'))is int and row['requestedMemoryBytes']>0 and row.get('allocationState') in ('pending','running'),'resource_inventory_invalid');ids.add(row['id'])
  if row['id']==identity['reservationId']:
   need(all(row.get(k)==identity[k] for k in ('token','hostAlias','environment','operator')) and row['requestedMemoryBytes']==MEMORY and row['allocationState']=='pending' and row.get('activeJob')=='absent' and row.get('activeJobEvidence') is None,'resource_reservation_not_fresh');target=row
  if row.get('hostAlias')=='archlinux' and row['id']!=identity['reservationId']:pending.append({'id':row['id'],'memoryBytes':row['requestedMemoryBytes']})
 need(target is not None,'resource_reservation_missing');return pin,pending


def _public_resource_reply(value):
 """Recognize only the fixed observer's public facts before pipe retention."""
 need(type(value)is dict and set(value)=={'state','hostBootId','vms','physicalMemoryBytes','swapUsedBytes','samples','diskAvailableBytes','diskDevice','inventoryComplete'} and value['state']=='observed' and value['inventoryComplete']is True and type(value['vms'])is list,'resource_measurement_invalid')
 need(all(type(value[k])is int and value[k]>=0 for k in ('physicalMemoryBytes','swapUsedBytes','diskAvailableBytes','diskDevice')) and value['physicalMemoryBytes']>0 and len(value['vms'])<=8192,'resource_measurement_invalid')
 from uuid import UUID
 need(type(value['hostBootId'])is str and str(UUID(value['hostBootId']))==value['hostBootId'],'resource_boot_invalid')
 ids=set()
 for row in value['vms']:
  need(type(row)is dict and set(row)=={'pid','startTicks','sessionId','uid','commandSha256','executableGeneration','configuredMemoryBytes'} and all(type(row[k])is int and row[k]>0 for k in ('pid','startTicks','sessionId','configuredMemoryBytes')) and type(row['uid'])is int and row['uid']>=0 and type(row['commandSha256'])is str and re.fullmatch('[0-9a-f]{64}',row['commandSha256']) is not None and type(row['executableGeneration'])is list and len(row['executableGeneration'])==9 and all(type(x)is int for x in row['executableGeneration']) and row['pid'] not in ids,'resource_principal_invalid');ids.add(row['pid'])
 need(type(value['samples'])is list and len(value['samples'])==2,'resource_measurement_invalid')
 for sample in value['samples']:
  fields={'observedAtUnixMs','availableMemoryBytes','psi','vmstat'}
  need(type(sample)is dict and set(sample) in (fields,fields|{'psiSomeAvg10','psiFullAvg10'}) and all(type(sample[k])is int and sample[k]>=0 for k in ('observedAtUnixMs','availableMemoryBytes')) and sample['observedAtUnixMs']>0 and sample['psi'] in ('normal','warning'),'resource_measurement_invalid')
  counters=sample['vmstat']
  need(type(counters)is dict and set(counters)=={'pswpin','pswpout','oomKill'} and all(type(x)is int and x>=0 for x in counters.values()),'resource_measurement_invalid')
  for key in ('psiSomeAvg10','psiFullAvg10'):
   if key in sample:need(type(sample[key]) in (int,float) and math.isfinite(sample[key]) and sample[key]>=0,'resource_measurement_invalid')
 return value


def budget(value,pending):
 value=_public_resource_reply(value)
 need(value['diskAvailableBytes']>=16*1024**3,'resource_disk_insufficient')
 measurement={'platform':'linux','physicalMemoryBytes':value['physicalMemoryBytes'],'runningConfiguredMemoryBytes':sum(x['configuredMemoryBytes'] for x in value['vms']),'availableMemoryBytes':value['samples'][-1]['availableMemoryBytes'],'swapUsedBytes':value['swapUsedBytes'],'pressure':'normal','samples':value['samples']}
 return vm_workflow.admit_plan(measurement,requested_memory_bytes=MEMORY,headroom_bytes=2*1024**3,reservations=pending)


def prepare(root,request,identity,*,source_root,engineering_context=None):
 """Root-only protected identity binding; does not create/release reservations."""
 root=Path(root).absolute();request=build._request(request);build.preflight(root,request,source_root=source_root,**({} if engineering_context is None else {'engineering_context':engineering_context}))
 with closure.claim_lock(root) as (_,lock_guard):
  pin,pending=inventory(root,request,identity);original=sources(root,engineering_context)
  def guard():lock_guard();need(sources(root,engineering_context)==original and inventory(root,request,identity)==(pin,pending),'resource_admission_changed')
  value,capture=fixed_resource_query(root,host_program(),{},guard);plan=budget(value,pending);guard()
  record={'request':request,'identity':identity,'sourceRoot':str(Path(source_root).absolute()),'sources':original,'inventoryPin':pin,'pending':pending,'host':value,'plan':plan,'capture':capture}
  target=directory(root,request['correlationId'],True);birth=closure.pipe._write_once(target/'admission.json',session.canonical(record));closure.pipe._write_once(target/'seal.json',session.canonical({'admissionPin':birth}))
 return {'state':'ready','correlationId':request['correlationId'],'resourceBound':True,'nativeActionAllowed':False}


def load(root,request,source_root=None,engineering_context=None):
 target=directory(root,request['correlationId']);raw,pin=closure.pipe._read(target/'admission.json',1048576);record=json.loads(raw)
 need(set(record)=={'request','identity','sourceRoot','sources','inventoryPin','pending','host','plan','capture'} and record['request']==request and sources(root,engineering_context)==record['sources'] and json.loads(closure.pipe._read(target/'seal.json')[0])=={'admissionPin':pin},'resource_admission_changed')
 if source_root is not None:need(str(Path(source_root).absolute())==record['sourceRoot'],'resource_source_crossed')
 return record,pin,closure.pipe._read(target/'seal.json')[1]


class ResourceDriver(adapter.McpTmuxDriver):
 def _query(self,program,payload,*,job=None,guard=None):
  if program==old._AVAILABILITY:return super()._query(program,payload,job=job,guard=guard)
  context=getattr(self,'engineering_context',None)
  request=build._request({k:payload['request'].get(k) for k in ('sourceSha','baseVersion','targetVersion','correlationId')});record,pin,seal=load(self.root,request,self.source_root,context)
  binding={'admissionPin':pin,'sealPin':seal,'request':request}
  binding_path=job/'tmux-resource-binding.json'
  if program==old._STAGE:closure.pipe._write_once(binding_path,session.canonical(binding))
  binding_raw,binding_pin=closure.pipe._read(binding_path);need(json.loads(binding_raw)==binding,'resource_birth_changed')
  effect=program==old._STAGE or payload.get('action') in ('prepare','release')
  def bound():
   need(load(self.root,request,self.source_root,context)==(record,pin,seal) and closure.pipe._read(binding_path)==(binding_raw,binding_pin),'resource_binding_changed')
   if effect:need(inventory(self.root,request,record['identity'])==(record['inventoryPin'],record['pending']),'resource_inventory_changed')
   if guard:guard()
  if effect:
   value,_=fixed_resource_query(self.root,host_program(),{},bound)
   need(value['hostBootId']==record['host']['hostBootId'] and value['vms']==record['host']['vms'] and value['diskDevice']==record['host']['diskDevice'],'resource_preserved_principal_changed');budget(value,record['pending'])
  return super()._query(program,payload,job=job,guard=bound)


def operate(root,action,raw,*,source_root=None,engineering_context=None):
 need(action in ('availability','preflight','start','status','collect') and type(raw)is dict,'resource_action_invalid')
 if action=='availability':return adapter.operate(root,action,raw,source_root=source_root)
 if action in ('status','collect'):
  need(set(raw)=={'correlationId'} and build._correlation(raw['correlationId']),'resource_request_invalid')
  if not os.path.lexists(directory(root,raw['correlationId'])):return adapter.operate(root,action,raw,source_root=source_root)
  bound_record,_,_=load(root,build._request(build._read(build._directory(Path(root),False)/(raw['correlationId']+'.json'))),engineering_context=engineering_context)
  driver=ResourceDriver(root,source_root=bound_record['sourceRoot'],engineering_context=engineering_context)
  if action=='status':return build.status(root,raw,driver=driver)
  journal=build._directory(driver.root,False);record=build._read(journal/(raw['correlationId']+'.json'));request=build._request(record);load(root,request,source_root,engineering_context);return driver.collect_existing(request)
 request=build._request(raw);load(root,request,source_root,engineering_context) # Before driver/build entry.
 driver=ResourceDriver(root,source_root=source_root,engineering_context=engineering_context)
 with closure.claim_lock(root) as (_,lock_guard):
  record,birth,seal=load(root,request,source_root,engineering_context);pin,pending=inventory(root,request,record['identity']);need((pin,pending)==(record['inventoryPin'],record['pending']),'resource_inventory_changed')
  def bound():
   lock_guard();need(load(root,request,source_root,engineering_context)==(record,birth,seal) and inventory(root,request,record['identity'])==(pin,pending),'resource_preflight_changed')
  value,_=fixed_resource_query(root,host_program(),{},bound);bound();budget(value,pending)
  need(value['hostBootId']==record['host']['hostBootId'] and value['vms']==record['host']['vms'] and value['diskDevice']==record['host']['diskDevice'],'resource_preserved_principal_changed')
  if action=='preflight':return driver.preflight(request)
  return build.start(root,request,driver=driver,source_root=source_root,admission=lambda unused,req:driver.preflight(req),**({} if engineering_context is None else {'engineering_context':engineering_context}))
