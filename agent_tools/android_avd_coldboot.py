"""One fenced cold boot of an authenticated historical task-owned AVD.

The root operator runs the fixed generated launch/status program. Launch has a
single durable fence and records the blocked child's generation before exec.
Unknown outcomes never replay, kill, adopt, wipe or restore snapshots.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
import re
import zlib
from . import android_avd_sdk_alias_census as admitted_census
from . import android_avd_launch_recovery as census
from . import android_device_availability as availability
from . import android_owned_endpoint_bind_recovery as private_io

CENSUS_ID='c9e6a170-9dcd-4a1f-83fb-e3c3ebd524c4'
CENSUS_SHA='d6b7d198a61b125f05daece9c055c2733e9cb077a2b33e408c106b062efd1266'
ADMITTED_SOURCE='98b86bf0570828af0d2f32882cbbcaf364cc826a88b6bceb9366b68165158b06'
MEMORY=2147483648
HEADROOM=8589934592
_BOOT=r'''
import ctypes,fcntl,signal,subprocess,time
LAUNCH=__LAUNCH__
def journal_read(directory,name):
 value=read_fixed(directory/name,131072);raw=value.pop('raw')
 if value['generation'][6:9]!=[0,0,1] or stat.S_IMODE(value['generation'][5])!=0o600:raise ValueError('coldboot_journal_unsafe')
 return json.loads(raw)
def journal_write(directory,name,value):
 chain,leaf=parent_fds(directory/name)
 try:
  guard_parents(chain);fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=chain[-1]['fd'])
  with os.fdopen(fd,'wb') as stream:
   previous=chain[-1]['pin'];current=fp(os.fstat(chain[-1]['fd']))
   if any(current[n]!=previous[n] for n in (0,1,5,6,7,8)):raise ValueError('coldboot_parent_changed')
   chain[-1]['pin']=current;guard_parents(chain)
   raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
   if len(raw)>131072:raise ValueError('coldboot_journal_limit')
   stream.write(raw);stream.flush();os.fsync(stream.fileno())
  os.fsync(chain[-1]['fd']);guard_parents(chain)
 finally:close_parents(chain)
def census_history():
 value=read_fixed(ROOT/('android-avd-privileged-census-'+LAUNCH['censusId']+'.json'),524288);raw=value.pop('raw')
 if value!=LAUNCH['censusPin']:raise ValueError('coldboot_census_changed')
 recorded=json.loads(raw)
 if recorded['observations'][0]!=LAUNCH['observation'] or not all(recorded['summary'][k] for k in ('stable','complete','ownedPortsFree')):raise ValueError('coldboot_census_unadmitted')
 return recorded

def selected_preflight():
 census_history();alias_history_guard()
 proof_pin=read_fixed(ROOT/('android-avd-preflight-'+CFG['proofCorrelation']+'.json'),524288);raw=proof_pin.pop('raw')
 if proof_pin!=CFG['proofPin']:raise ValueError('coldboot_original_proof_changed')
 proof=json.loads(raw);guard_proof(proof)
 chosen=LAUNCH['observation']['avds'][LAUNCH['device']];directory=pathlib.Path(chosen['directory']['path'])
 if tree_facts(directory)!=chosen['tree']:raise ValueError('coldboot_avd_disk_changed')
 ini=directory.parent/(LAUNCH['avd']+'.ini')
 if facts(ini,65536,True)!=chosen['ini'] or facts(directory/'config.ini',65536,True)!=chosen['config']:raise ValueError('coldboot_avd_config_changed')
 identities={}
 for name,item in chosen['tree'].items():
  if item['kind']=='regular':identities.setdefault(tuple(item['generation'][:2]),[]).append(LAUNCH['device']+'/'+name)
 for name,old in chosen['sdkFiles'].items():
  if facts(pathlib.Path(name),16777216,name.endswith('/package.xml'))!=old:raise ValueError('coldboot_sdk_changed')
 process=process_census(identities)
 if not process['complete'] or process['holders']:raise ValueError('coldboot_disk_holder_unknown')
 if any(p['port'] in (LAUNCH['port'],LAUNCH['port']+1) for p in ports()):raise ValueError('coldboot_port_occupied')
 for old in LAUNCH['observation']['processes']['emulators']:
  # The authenticated Windows QEMU generation stays protected, never stopped.
  if ticks(PROC/str(old['pid']))!=old['startTicks']:raise ValueError('coldboot_foreign_owner_changed')
 values={row.split(':',1)[0]:row.split(':',1)[1].strip() for row in (PROC/'meminfo').read_text().splitlines()}
 available=int(values['MemAvailable'].split()[0])*1024
 if available<LAUNCH['pendingBytes']+8589934592:raise ValueError('coldboot_resource_budget_changed')
 disk=os.statvfs(ROOT)
 if disk.f_bavail*disk.f_frsize<21474836480:raise ValueError('coldboot_disk_capacity_changed')
 if boot()!=LAUNCH['observation']['bootId']:raise ValueError('coldboot_boot_changed')
 guard_proof(proof);alias_history_guard();return {'availableMemoryBytes':available,'protectedPendingBytes':LAUNCH['pendingBytes'],'headroomBytes':8589934592,'holderCensusComplete':True}
def open_emulator():
 path=pathlib.Path(LAUNCH['argv'][0]);chain,name=parent_fds(path)
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
  wanted=LAUNCH['emulatorGeneration']
  if fp(os.fstat(fd))!=wanted or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=wanted or not wanted[5]&0o111:os.close(fd);raise ValueError('coldboot_emulator_changed')
  try:guard_parents(chain)
  except BaseException:os.close(fd);raise
  return fd,chain
 except BaseException:close_parents(chain);raise

def child_identity(pid):
 proc=PROC/str(pid);before=ticks(proc)
 link=os.readlink(proc/'exe');command=(proc/'cmdline').read_bytes()
 if len(command)>262144 or ticks(proc)!=before:raise ValueError('coldboot_child_changed')
 return {'pid':pid,'startTicks':before,'bootId':boot(),'exe':link,'exeGeneration':fp((proc/'exe').stat()),'commandSha256':hashlib.sha256(command).hexdigest()}
def qemu_fact():
 path=pathlib.Path(LAUNCH['qemuPath']);chain,name=parent_fds(path);fd=None
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd']);info=os.fstat(fd);generation=fp(info)
  if not stat.S_ISREG(info.st_mode) or generation[2]>268435456 or generation[6:9]!=[1000,1000,1] or not generation[5]&0o111:raise ValueError('coldboot_qemu_unadmitted')
  digest=hashlib.sha256();count=0
  while count<info.st_size:
   part=os.read(fd,min(65536,info.st_size-count))
   if not part:break
   digest.update(part);count+=len(part)
  if count!=info.st_size or fp(os.fstat(fd))!=generation or fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=generation:raise ValueError('coldboot_qemu_changed')
  guard_parents(chain)
  return {'generation':generation,'bytesRead':count,'sha256':digest.hexdigest(),'hashScope':'full'}
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)

def admit_once(directory):
 if os.path.lexists(directory/'ready.json'):raise ValueError('coldboot_admission_already_recorded')
 first=selected_preflight();binary=qemu_fact();second=selected_preflight()
 if qemu_fact()!=binary:raise ValueError('coldboot_qemu_changed')
 ready={'schema':1,'correlationId':LAUNCH['correlationId'],'intentSha256':LAUNCH['intentSha256'],'source':CFG['source'],'qemuFact':binary,'preflight':[first,second],'launchPerformed':False}
 journal_write(directory,'ready.json',ready)
 return {'state':'admitted-for-review','correlationId':LAUNCH['correlationId'],'qemuFact':binary,'launchPerformed':False,'guestAdmitted':False,'productAdmitted':False}
def emulator_exec(go_fd,executable_fd,log_fd):
 try:
  grant=os.read(go_fd,1);os.close(go_fd)
  if grant!=b'G':os._exit(125)
  os.dup2(log_fd,1);os.dup2(log_fd,2);os.close(log_fd)
  null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null)
  os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
  os.set_inheritable(executable_fd,True)
  os.execve('/proc/self/fd/'+str(executable_fd),LAUNCH['argv'],LAUNCH['environment'])
 except BaseException:os._exit(126)
def close_supervisor_inherited(go_fd,executable_fd,log_fd):
 # Fork inherits even CLOEXEC descriptors. Drop all unrelated locks, proof
 # descriptors, ancestry handles and transport pipes before the supervisor
 # persists; only its original GO, executable and private log are required.
 names=os.listdir('/proc/self/fd')
 if len(names)>4096 or any(not name.isdecimal() for name in names):raise ValueError('coldboot_descriptor_census_unknown')
 keep={0,1,2,go_fd,executable_fd,log_fd}
 for name in names:
  fd=int(name)
  if fd in keep:continue
  try:os.close(fd)
  except OSError as error:
   # The directory FD used by listdir is already closed on return.
   if error.errno!=9:raise
def child_exec(go_fd,executable_fd,log_fd,directory):
 # Original session supervisor survives launcher forks and keeps descendants.
 try:
  close_supervisor_inherited(go_fd,executable_fd,log_fd)
  os.setsid()
  # The long-lived supervisor must release the SSH transport pipes before
  # waiting for GO; emulator redirection alone leaves those pipes inherited.
  null=os.open('/dev/null',os.O_RDONLY);os.dup2(null,0);os.close(null)
  os.dup2(log_fd,1);os.dup2(log_fd,2)
  libc=ctypes.CDLL(None,use_errno=True)
  if libc.prctl(36,1,0,0,0)!=0:os._exit(124)
  grant=os.read(go_fd,1);os.close(go_fd)
  if grant!=b'G':os._exit(125)
  read_go,write_go=os.pipe();emulator_pid=os.fork()
  if emulator_pid==0:
   os.close(write_go);emulator_exec(read_go,executable_fd,log_fd);os._exit(126)
  os.close(read_go)
  try:
   child=child_identity(emulator_pid)
   journal_write(directory,'emulator-child.json',{'schema':1,'correlationId':LAUNCH['correlationId'],'identity':child,'sessionId':os.getpid(),'source':CFG['source'],'intentSha256':LAUNCH['intentSha256']})
   selected_preflight();ready=journal_read(directory,'ready.json')
   if qemu_fact()!=ready['qemuFact']:raise ValueError('coldboot_qemu_changed')
   os.write(write_go,b'G')
  finally:os.close(write_go)
  os.close(executable_fd);os.close(log_fd)
  while True:
   try:os.waitpid(-1,0)
   except InterruptedError:continue
   except ChildProcessError:break
  os._exit(0)
 except BaseException:os._exit(126)

def launch_once(directory):
 if os.path.lexists(directory/'attempt.json'):return {'state':'unknown','reason':'coldboot_consumed_no_replay','correlationId':LAUNCH['correlationId']}
 ready=journal_read(directory,'ready.json')
 if ready['source']!=CFG['source'] or ready['intentSha256']!=LAUNCH['intentSha256'] or qemu_fact()!=ready['qemuFact']:raise ValueError('coldboot_ready_changed')
 first=selected_preflight();second=selected_preflight()
 journal_write(directory,'attempt.json',{'schema':1,'correlationId':LAUNCH['correlationId'],'intentSha256':LAUNCH['intentSha256'],'action':'one-coldboot','source':CFG['source'],'preflight':[first,second]})
 # Source-owned fence is consumed even if a later guard/fork/response fails.
 selected_preflight();executable_fd,chain=open_emulator();go_read,go_write=os.pipe();log_fd=None;pid=None
 try:
  jchain,unused=parent_fds(directory/'__coldboot_log__')
  try:
   log_fd=os.open('emulator.stdout.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jchain[-1]['fd'])
  finally:close_parents(jchain)
  guard_parents(chain)
  pid=os.fork()
  if pid==0:
   os.close(go_write);child_exec(go_read,executable_fd,log_fd,directory);os._exit(126)
  os.close(go_read);go_read=None
  child=child_identity(pid)
  journal_write(directory,'child.json',{'schema':1,'correlationId':LAUNCH['correlationId'],'identity':child,'emulatorGeneration':LAUNCH['emulatorGeneration'],'argv':LAUNCH['argv'],'source':CFG['source'],'intentSha256':LAUNCH['intentSha256']})
  selected_preflight();guard_parents(chain)
  os.write(go_write,b'G');os.close(go_write);go_write=None
  journal_write(directory,'exec-released.json',{'schema':1,'correlationId':LAUNCH['correlationId'],'pid':pid,'startTicks':child['startTicks'],'bootId':child['bootId']})
  return {'state':'submitted','correlationId':LAUNCH['correlationId'],'child':child,'guestAdmitted':False,'productAdmitted':False}
 finally:
  for fd in (go_read,go_write,log_fd,executable_fd):
   if fd is not None:os.close(fd)
  close_parents(chain)

def session_guest(saved,ready):
 candidates=[];denied=0
 for proc in PROC.iterdir():
  if not proc.name.isdecimal():continue
  try:
   before=ticks(proc);raw=(proc/'stat').read_text()
   if len(raw)>8192:raise ValueError('coldboot_process_stat_limit')
   fields=raw.rsplit(')',1)[1].split()
   if int(fields[3])!=saved['pid']:continue
   command=(proc/'cmdline').read_bytes()
   if len(command)>262144:raise ValueError('coldboot_command_limit')
   args=[part.decode('utf-8','strict') for part in command.split(b'\0') if part]
   if not args or args[0]!=LAUNCH['qemuPath']:continue
   if args.count('-avd')!=1 or args.count('-port')!=1 or args[args.index('-avd')+1]!=LAUNCH['avd'] or args[args.index('-port')+1]!=str(LAUNCH['port']):raise ValueError('coldboot_guest_arguments_changed')
   executable=fp((proc/'exe').stat());uid_lines=[row for row in (proc/'status').read_text().splitlines() if row.startswith('Uid:')]
   if len(uid_lines)!=1 or uid_lines[0].split()[1:]!=['1000']*4 or executable!=ready['qemuFact']['generation'] or ticks(proc)!=before:raise ValueError('coldboot_guest_generation_changed')
   candidates.append({'pid':int(proc.name),'startTicks':before,'hostBootId':saved['bootId'],'sessionId':saved['pid'],'exeGeneration':executable,'commandSha256':hashlib.sha256(command).hexdigest()})
  except FileNotFoundError:continue
  except PermissionError:denied+=1
 if denied or len(candidates)!=1:return None
 return candidates[0]
def guest_probe(guest):
 path=pathlib.Path(LAUNCH['adbPath']);chain,name=parent_fds(path);fd=None
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
  if fp(os.fstat(fd))!=LAUNCH['adbFacts']['generation']:raise ValueError('coldboot_adb_changed')
  def invoke(args):
   guard_parents(chain)
   if fp(os.fstat(fd))!=LAUNCH['adbFacts']['generation']:raise ValueError('coldboot_adb_changed')
   def drop_identity():os.setgroups([1000]);os.setgid(1000);os.setuid(1000)
   result=subprocess.run([LAUNCH['adbPath'],'-s','emulator-'+str(LAUNCH['port']),*args],executable='/proc/self/fd/'+str(fd),pass_fds=(fd,),env=LAUNCH['environment'],preexec_fn=drop_identity,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=False)
   if len(result.stdout)>2048 or len(result.stderr)>2048 or result.returncode!=0:raise ValueError('coldboot_guest_read_unknown')
   guard_parents(chain)
   if fp(os.fstat(fd))!=LAUNCH['adbFacts']['generation']:raise ValueError('coldboot_adb_changed')
   return result.stdout.decode('utf-8','strict').strip()
  values={key:invoke(['shell','getprop',prop]) for key,prop in (('sdk','ro.build.version.sdk'),('abi','ro.product.cpu.abi'),('kernelAvd','ro.kernel.qemu.avd_name'),('bootAvd','ro.boot.qemu.avd_name'),('bootCompleted','sys.boot_completed'))}
  values['shellUid']=invoke(['shell','id','-u']);values['guestBootId']=invoke(['shell','cat','/proc/sys/kernel/random/boot_id'])
  expected_api='29' if LAUNCH['device']=='api29' else '35'
  values['matched']=values['sdk']==expected_api and values['abi']=='x86_64' and values['shellUid']=='2000' and values['bootCompleted']=='1' and LAUNCH['avd'] in (values['kernelAvd'],values['bootAvd']) and all(v in ('',LAUNCH['avd']) for v in (values['kernelAvd'],values['bootAvd'])) and re.fullmatch(r'[0-9a-f-]{36}',values['guestBootId']) is not None
  return values
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)
def original_status(directory):
 attempt=journal_read(directory,'attempt.json')
 if attempt['intentSha256']!=LAUNCH['intentSha256']:raise ValueError('coldboot_attempt_changed')
 try:record=journal_read(directory,'child.json')
 except FileNotFoundError:return {'state':'unknown','reason':'coldboot_child_unrecorded_no_replay'}
 if record['source']!=CFG['source'] or record['argv']!=LAUNCH['argv'] or record['emulatorGeneration']!=LAUNCH['emulatorGeneration'] or record['intentSha256']!=LAUNCH['intentSha256']:raise ValueError('coldboot_child_record_changed')
 saved=record['identity']
 if boot()!=saved['bootId']:return {'state':'unknown','reason':'coldboot_host_generation_changed'}
 try:current=child_identity(saved['pid'])
 except FileNotFoundError:return {'state':'unknown','reason':'coldboot_original_child_absent'}
 if current['startTicks']!=saved['startTicks']:return {'state':'unknown','reason':'coldboot_original_pid_reused'}
 if current['exeGeneration']!=saved['exeGeneration'] or current['commandSha256']!=saved['commandSha256'] or os.getsid(saved['pid'])!=saved['pid']:raise ValueError('coldboot_supervisor_changed')
 # Do not adopt a different QEMU PID; emulator may spawn a guest child.
 try:released=journal_read(directory,'exec-released.json')
 except FileNotFoundError:return {'state':'unknown','reason':'coldboot_exec_release_unrecorded','child':current}
 ready=journal_read(directory,'ready.json')
 if ready['source']!=CFG['source'] or ready['intentSha256']!=LAUNCH['intentSha256'] or qemu_fact()!=ready['qemuFact']:raise ValueError('coldboot_ready_changed')
 guest=session_guest(saved,ready)
 if guest is None:return {'state':'original-supervisor-observed','correlationId':LAUNCH['correlationId'],'child':current,'guestAdmitted':False,'productAdmitted':False}
 try:device=guest_probe(guest)
 except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired):return {'state':'guest-not-yet-admitted','correlationId':LAUNCH['correlationId'],'child':current,'guest':guest,'guestAdmitted':False,'productAdmitted':False}
 if child_identity(saved['pid'])!=current or session_guest(saved,ready)!=guest:raise ValueError('coldboot_guest_changed_during_probe')
 return {'state':'guest-generation-admitted' if device['matched'] else 'guest-not-yet-admitted','correlationId':LAUNCH['correlationId'],'child':current,'guest':guest,'device':device,'guestAdmitted':device['matched'],'productAdmitted':False}

def refresh_root_after_directory_create(chain,previous):
 current=fp(os.fstat(chain[-1]['fd']))
 if any(current[n]!=previous[n] for n in (0,1,5,6,7)) or current[8]!=previous[8]+1:raise ValueError('coldboot_root_changed')
 chain[-1]['pin']=current;guard_parents(chain)
def coldboot_dispatch():
 if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('coldboot_root_required')
 directory=ROOT/('android-avd-coldboot-'+LAUNCH['correlationId']);root_chain,unused=parent_fds(ROOT/'__coldboot_journal_root__')
 try:
  parent=os.fstat(root_chain[-1]['fd'])
  if parent.st_uid!=1000 or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('coldboot_root_changed')
  if LAUNCH['action']=='admit':
   guard_parents(root_chain);previous=root_chain[-1]['pin'];os.mkdir(directory.name,0o700,dir_fd=root_chain[-1]['fd']);refresh_root_after_directory_create(root_chain,previous)
   journal_write(directory,'intent.json',LAUNCH['intent'])
  info=directory.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('coldboot_journal_unsafe')
  intent=journal_read(directory,'intent.json')
  if intent!=LAUNCH['intent']:raise ValueError('coldboot_intent_changed')
  # Fixed per-device host lock never replaces the historical device claims.
  lock_name='android-avd-coldboot-'+LAUNCH['device']+'.lock'
  guard_parents(root_chain)
  lock_fd=os.open(lock_name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=root_chain[-1]['fd'])
  try:
   current=fp(os.fstat(root_chain[-1]['fd']));previous=root_chain[-1]['pin']
   if any(current[n]!=previous[n] for n in (0,1,5,6,7,8)):raise ValueError('coldboot_root_changed')
   root_chain[-1]['pin']=current;guard_parents(root_chain)
   lock=os.fstat(lock_fd)
   if not stat.S_ISREG(lock.st_mode) or lock.st_uid!=0 or stat.S_IMODE(lock.st_mode)!=0o600 or lock.st_nlink!=1:raise ValueError('coldboot_lock_unsafe')
   lock_pin=fp(lock)
   if fp(os.stat(lock_name,dir_fd=root_chain[-1]['fd'],follow_symlinks=False))!=lock_pin:raise ValueError('coldboot_lock_changed')
   fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB);guard_parents(root_chain)
   if fp(os.fstat(lock_fd))!=lock_pin or fp(os.stat(lock_name,dir_fd=root_chain[-1]['fd'],follow_symlinks=False))!=lock_pin:raise ValueError('coldboot_lock_changed')
   result=admit_once(directory) if LAUNCH['action']=='admit' else launch_once(directory) if LAUNCH['action']=='launch' else original_status(directory)
   guard_parents(root_chain)
   if fp(os.fstat(lock_fd))!=lock_pin or fp(os.stat(lock_name,dir_fd=root_chain[-1]['fd'],follow_symlinks=False))!=lock_pin:raise ValueError('coldboot_lock_changed')
   print(json.dumps(result,separators=(',',':')))
  finally:os.close(lock_fd)
 finally:close_parents(root_chain)
coldboot_dispatch()
'''

def _local_generation(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)

def _write_local_intent(path: Path,value: dict) -> None:
    """Create only this journal's private directories/intent through held FDs."""
    path=Path(path).absolute()
    if path.name!='launch.json' or path.parent.parent.name!='android-avd-coldboot' or path.parent.parent.parent.name!='.rag_index' or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',path.parent.name):raise ValueError('coldboot_local_journal_scope')
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>262144:raise ValueError('coldboot_local_intent_limit')
    chain=[];intent_fd=None;gid=os.getgid();uid=os.getuid()
    def guard():
        for index,item in enumerate(chain):
            named=os.stat('/',follow_symlinks=False) if index==0 else os.stat(item['name'],dir_fd=chain[index-1]['fd'],follow_symlinks=False)
            if _local_generation(os.fstat(item['fd']))!=item['pin'] or _local_generation(named)!=item['pin']:raise ValueError('coldboot_local_ancestry_changed')
    def progress(index,link_delta):
        old=chain[index]['pin'];current=_local_generation(os.fstat(chain[index]['fd']))
        if any(current[n]!=old[n] for n in (0,1,5,6,7)) or current[8]!=old[8]+link_delta:raise ValueError('coldboot_local_parent_changed')
        chain[index]['pin']=current;guard()
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append({'fd':fd,'name':'/','pin':_local_generation(os.fstat(fd))})
        for index,name in enumerate(path.parts[1:-1],1):
            guard();private=index>=len(path.parts)-4
            try:fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
            except FileNotFoundError:
                if not private:raise ValueError('coldboot_local_root_absent') from None
                os.mkdir(name,0o700,dir_fd=chain[-1]['fd']);os.fsync(chain[-1]['fd']);progress(len(chain)-1,1)
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or private and (info.st_uid!=uid or info.st_gid!=gid or stat.S_IMODE(info.st_mode)!=0o700):os.close(fd);raise ValueError('coldboot_local_private_parent_unsafe')
            chain.append({'fd':fd,'name':name,'pin':_local_generation(info)});guard()
        guard();intent_fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=chain[-1]['fd'])
        progress(len(chain)-1,1 if sys.platform=='darwin' else 0)
        before=os.fstat(intent_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_gid!=gid or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600:raise ValueError('coldboot_local_intent_unsafe')
        offset=0
        while offset<len(raw):
            written=os.write(intent_fd,raw[offset:])
            if written<=0:raise ValueError('coldboot_local_intent_partial')
            offset+=written
        os.fsync(intent_fd);os.lseek(intent_fd,0,os.SEEK_SET);readback=b''
        while len(readback)<=len(raw):
            chunk=os.read(intent_fd,min(65536,len(raw)+1-len(readback)))
            if not chunk:break
            readback+=chunk
        after=os.fstat(intent_fd);named=os.stat(path.name,dir_fd=chain[-1]['fd'],follow_symlinks=False)
        if readback!=raw or any(_local_generation(after)[n]!=_local_generation(before)[n] for n in (0,1,5,6,7,8)) or _local_generation(after)!=_local_generation(named) or after.st_uid!=uid or after.st_gid!=gid or after.st_nlink!=1 or stat.S_IMODE(after.st_mode)!=0o600 or not stat.S_ISREG(after.st_mode):raise ValueError('coldboot_local_intent_changed')
        os.fsync(chain[-1]['fd']);guard()
    finally:
        if intent_fd is not None:os.close(intent_fd)
        for item in reversed(chain):os.close(item['fd'])

def prepare(root: Path,device: str,correlation: str,reservation: dict,action: str='admit') -> dict:
    root=Path(root).absolute()
    if device not in ('api29','api35') or action not in ('admit','launch','status'):raise ValueError('coldboot_fixed_scope')
    prepared=admitted_census.prepare_census(root,correlation)
    dependency=Path(admitted_census.__file__).absolute()
    if hashlib.sha256(prepared['snapshots'][dependency][1]).hexdigest()!=ADMITTED_SOURCE:raise ValueError('coldboot_consumed_census_changed')
    base=root/'.runtime/parity-evidence'/('android-avd-sdk-alias-census-'+CENSUS_ID);saved={}
    for name in ('remote-full.json','result.json'):
        path=base/name;pin,raw=availability._snapshot(path);prepared['snapshots'][path]=(pin,raw);saved[name]=json.loads(raw)
        if name=='remote-full.json' and hashlib.sha256(raw).hexdigest()!=CENSUS_SHA:raise ValueError('coldboot_complete_census_changed')
    proof=saved['remote-full.json'];pin=saved['result.json']['pin']
    if proof['correlationId']!=CENSUS_ID or pin['sha256']!=CENSUS_SHA or not all(proof['summary'].get(k) is True for k in ('stable','complete','ownedPortsFree')) or any(o['processes']['holders'] for o in proof['observations']):raise ValueError('coldboot_census_unadmitted')
    registry=root/'.rag_index/native-environments/reservations.json';registry_pin,registry_raw=availability._snapshot(registry);prepared['snapshots'][registry]=(registry_pin,registry_raw);records=json.loads(registry_raw)['reservations']
    if set(reservation)!={'reservationId','token','hostAlias','environment','operator'}:raise ValueError('coldboot_reservation_identity')
    matching=[r for r in records if r['id']==reservation['reservationId']]
    if len(matching)!=1:raise ValueError('coldboot_reservation_missing')
    row=matching[0];identity={'reservationId':row['id'],'token':row['token'],'hostAlias':row['hostAlias'],'environment':row['environment'],'operator':row['operator']}
    if identity!=reservation or row['hostAlias']!='archlinux' or row['environment']!='owned-android-'+device+'-coldboot' or row['operator']!='root-android' or row['requestedMemoryBytes']!=MEMORY or row['allocationState'] not in ({'pending'} if action in ('admit','launch') else {'pending','running'}):raise ValueError('coldboot_reservation_unadmitted')
    pending=sum(r['requestedMemoryBytes'] for r in records if r['hostAlias']=='archlinux' and r['allocationState']=='pending')
    selected=proof['observations'][0]['avds'][device];owned=census.preflight.OWNED[device];sdk=selected['sdkFiles'];emulator=owned['emulator']
    argv=[emulator,'-avd',owned['avd'],'-port',str(owned['port']),'-memory','2048','-cores','2','-no-window','-no-audio','-no-snapshot-load','-no-snapshot-save','-no-boot-anim','-gpu','swiftshader_indirect']
    if device=='api29':argv+=['-prop','dalvik.vm.heapgrowthlimit=48m']
    environment={'HOME':'/home/kardinal','USER':'kardinal','LOGNAME':'kardinal','PATH':'/usr/bin:/bin','ANDROID_HOME':owned['sdk'],'ANDROID_SDK_ROOT':owned['sdk'],'ANDROID_AVD_HOME':owned['avdHome']}
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);prepared['snapshots'][own]=(own_pin,own_raw);prepared['binding']['source'][str(own.relative_to(root))]=hashlib.sha256(own_raw).hexdigest()
    intent={'schema':1,'correlationId':correlation,'device':device,'source':prepared['binding']['source'],'reservation':reservation,'registrySha256':hashlib.sha256(registry_raw).hexdigest(),'censusPin':pin,'argv':argv,'environment':environment,'historicalUnknownsPreserved':True}
    intent_raw=(json.dumps(intent,sort_keys=True,separators=(',',':'))+'\n').encode();launch={'action':action,'correlationId':correlation,'device':device,'avd':owned['avd'],'port':owned['port'],'argv':argv,'environment':environment,'emulatorGeneration':sdk[emulator]['generation'],'qemuPath':str(Path(emulator).parent/'qemu/linux-x86_64/qemu-system-x86_64-headless'),'adbPath':'/opt/android-sdk/platform-tools/adb','adbFacts':sdk['/opt/android-sdk/platform-tools/adb'],'censusId':CENSUS_ID,'censusPin':pin,'observation':proof['observations'][0],'pendingBytes':pending,'intent':intent,'intentSha256':hashlib.sha256(intent_raw).hexdigest()}
    local=root/'.rag_index/android-avd-coldboot'/correlation/'launch.json'
    if action=='admit':
        if local.exists() or local.is_symlink():raise ValueError('coldboot_local_intent_exists_no_resubmit')
        _write_local_intent(local,launch)
    else:
        preserved=private_io._private(local,262144)[0]
        if preserved['correlationId']!=correlation or preserved['device']!=device or preserved['intent']['reservation']!=reservation or preserved['intent']['source']!=prepared['binding']['source'] or preserved['argv']!=argv or preserved['environment']!=environment:raise ValueError('coldboot_local_intent_changed')
        # The admission intent remains immutable. This dispatch's budget comes
        # from the current FD-verified registry snapshot, guarded before and
        # after transport alongside the preserved local intent.
        launch={**preserved,'action':action,'pendingBytes':pending}
    local_pin,local_raw=availability._snapshot(local);prepared['snapshots'][local]=(local_pin,local_raw)
    program=prepared['program']
    tree=ast.parse(program);assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CFG' for t in n.targets));lines=program.splitlines(keepends=True);lines[assignment.lineno-1:assignment.end_lineno]=['CFG='+repr(prepared['binding'])+'\n'];program=''.join(lines)
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_BOOT' for t in n.targets)))
    if not program.endswith('capture()\n'):raise ValueError('coldboot_composition_changed')
    program=program[:-len('capture()\n')]+template.replace('__LAUNCH__',repr(launch));compile(program,'<fixed-avd-coldboot>','exec');prepared['program']=program;census.guard_prepared(prepared);return prepared

def guard_prepared(prepared: dict) -> None:
    census.guard_prepared(prepared)


def ssh_carrier(prepared: dict) -> str:
    """Safe one-line carrier for the fixed program, below Linux argv limits."""
    guard_prepared(prepared)
    packed=base64.b64encode(zlib.compress(prepared['program'].encode('utf-8'),9)).decode('ascii')
    return "exec(__import__('zlib').decompress(__import__('base64').b64decode("+repr(packed)+")))"


# These anchors authenticate the immutable original producer and native launch.
EXISTING_API35_CORRELATION='e3e97a65-b14a-4c32-8954-a441ac28ec47'
EXISTING_API35_LAUNCH_SHA='1864421e02b45ee331080e4ce16fa33a3e884c39e505bbd948e75eea4d10cdb2'
EXISTING_API35_INTENT_SHA='ab23f91532ce2ae4778825b75350bc673638509a669b78f6473313cf0c18b00c'
EXISTING_API35_PRODUCER_SHA='7d90c06070ffad1439e613c9ad5d63f979d43b738944f0630b2b15187f09fec6'
_READONLY_REMOVED={'admit_once','launch_once','child_exec','emulator_exec','close_supervisor_inherited','journal_write','refresh_root_after_directory_create','write_capsule','capture','selected_preflight','open_emulator','census_history'}

def existing_readonly_program(program):
    """Separate read-only definition; historical native records retain old source."""
    tree=ast.parse(program)
    dispatch=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='coldboot_dispatch')
    admissions=[n for n in ast.walk(dispatch) if isinstance(n,ast.If) and ast.unparse(n.test)=="LAUNCH['action'] == 'admit'"]
    results=[n for n in ast.walk(dispatch) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='result'for t in n.targets)]
    locks=[n for n in ast.walk(dispatch) if isinstance(n,ast.Call) and ast.unparse(n.func)=='os.open' and n.args and ast.unparse(n.args[0])=='lock_name']
    if len(admissions)!=1 or len(results)!=1 or not isinstance(results[0].value,ast.IfExp) or len(locks)!=1:raise ValueError('coldboot_readonly_composition_changed')
    for node in ast.walk(dispatch):
        for field,value in ast.iter_fields(node):
            if isinstance(value,list) and admissions[0] in value:value.remove(admissions[0])
    results[0].value=ast.parse('original_status(directory)',mode='eval').body
    locks[0].args[1]=ast.parse('os.O_RDWR | os.O_NOFOLLOW',mode='eval').body
    status=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='original_status')
    class HistoricalStatus(ast.NodeTransformer):
        count=0
        def visit_Subscript(self,node):
            if ast.unparse(node)=="CFG['source']":
                self.count+=1;return ast.copy_location(ast.parse("LAUNCH['intent']['source']",mode='eval').body,node)
            return self.generic_visit(node)
    transform=HistoricalStatus();transform.visit(status)
    if transform.count!=2:raise ValueError('coldboot_readonly_status_source_changed')
    tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in _READONLY_REMOVED]
    value=ast.unparse(ast.fix_missing_locations(tree))+'\n'
    validate_existing_readonly(value);return value

def validate_existing_readonly(program):
    tree=ast.parse(program)
    forbidden_calls={'os.mkdir','os.makedirs','os.write','os.fchmod','os.chmod','os.fork','os.execv','os.execve','os.kill','os.system','os.unlink','os.remove','os.rmdir','os.rename','os.replace','subprocess.call','subprocess.check_call','subprocess.check_output','shutil.rmtree'}
    for node in ast.walk(tree):
        if isinstance(node,ast.FunctionDef) and node.name in _READONLY_REMOVED:raise ValueError('coldboot_readonly_definition_required')
        if isinstance(node,ast.Call):
            name=ast.unparse(node.func)
            if name in forbidden_calls or name in _READONLY_REMOVED:raise ValueError('coldboot_readonly_syntax_required')
            if isinstance(node.func,ast.Attribute) and node.func.attr in {'mkdir','makedirs','write_bytes','write_text','unlink','rmdir','rename','replace','chmod'}:raise ValueError('coldboot_readonly_method_required')
            if any(isinstance(n,ast.Attribute) and n.attr in {'O_CREAT','O_EXCL','O_TRUNC','O_WRONLY'}for n in ast.walk(node)):raise ValueError('coldboot_readonly_open_required')
    calls=[n for n in tree.body if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='coldboot_dispatch']
    if len(calls)!=1 or calls[0] is not tree.body[-1]:raise ValueError('coldboot_readonly_dispatch_required')
    compile(program,'<existing-api35-readonly>','exec',dont_inherit=True)

def prepare_existing_api35_readonly(root: Path,correlation: str,reservation: dict,historical_producer: dict) -> dict:
    root=Path(root).absolute();device='api35';action='status'
    if not isinstance(correlation,str) or re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',correlation) is None or correlation==EXISTING_API35_CORRELATION:raise ValueError('coldboot_readonly_correlation')
    if device not in ('api29','api35') or action not in ('admit','launch','status'):raise ValueError('coldboot_fixed_scope')
    prepared=admitted_census.prepare_census(root,correlation)
    dependency=Path(admitted_census.__file__).absolute()
    if hashlib.sha256(prepared['snapshots'][dependency][1]).hexdigest()!=ADMITTED_SOURCE:raise ValueError('coldboot_consumed_census_changed')
    base=root/'.runtime/parity-evidence'/('android-avd-sdk-alias-census-'+CENSUS_ID);saved={}
    for name in ('remote-full.json','result.json'):
        path=base/name;pin,raw=availability._snapshot(path);prepared['snapshots'][path]=(pin,raw);saved[name]=json.loads(raw)
        if name=='remote-full.json' and hashlib.sha256(raw).hexdigest()!=CENSUS_SHA:raise ValueError('coldboot_complete_census_changed')
    proof=saved['remote-full.json'];pin=saved['result.json']['pin']
    if proof['correlationId']!=CENSUS_ID or pin['sha256']!=CENSUS_SHA or not all(proof['summary'].get(k) is True for k in ('stable','complete','ownedPortsFree')) or any(o['processes']['holders'] for o in proof['observations']):raise ValueError('coldboot_census_unadmitted')
    registry=root/'.rag_index/native-environments/reservations.json';registry_pin,registry_raw=availability._snapshot(registry);prepared['snapshots'][registry]=(registry_pin,registry_raw);records=json.loads(registry_raw)['reservations']
    if set(reservation)!={'reservationId','token','hostAlias','environment','operator'}:raise ValueError('coldboot_reservation_identity')
    matching=[r for r in records if r['id']==reservation['reservationId']]
    if len(matching)!=1:raise ValueError('coldboot_reservation_missing')
    row=matching[0];identity={'reservationId':row['id'],'token':row['token'],'hostAlias':row['hostAlias'],'environment':row['environment'],'operator':row['operator']}
    if identity!=reservation or row['hostAlias']!='archlinux' or row['environment']!='owned-android-'+device+'-coldboot' or row['operator']!='root-android' or row['requestedMemoryBytes']!=MEMORY or row['allocationState'] not in ({'pending'} if action in ('admit','launch') else {'pending','running'}):raise ValueError('coldboot_reservation_unadmitted')
    pending=sum(r['requestedMemoryBytes'] for r in records if r['hostAlias']=='archlinux' and r['allocationState']=='pending')
    selected=proof['observations'][0]['avds'][device];owned=census.preflight.OWNED[device];sdk=selected['sdkFiles'];emulator=owned['emulator']
    argv=[emulator,'-avd',owned['avd'],'-port',str(owned['port']),'-memory','2048','-cores','2','-no-window','-no-audio','-no-snapshot-load','-no-snapshot-save','-no-boot-anim','-gpu','swiftshader_indirect']
    if device=='api29':argv+=['-prop','dalvik.vm.heapgrowthlimit=48m']
    environment={'HOME':'/home/kardinal','USER':'kardinal','LOGNAME':'kardinal','PATH':'/usr/bin:/bin','ANDROID_HOME':owned['sdk'],'ANDROID_SDK_ROOT':owned['sdk'],'ANDROID_AVD_HOME':owned['avdHome']}
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);prepared['snapshots'][own]=(own_pin,own_raw);prepared['binding']['source'][str(own.relative_to(root))]=hashlib.sha256(own_raw).hexdigest()
    intent={'schema':1,'correlationId':correlation,'device':device,'source':prepared['binding']['source'],'reservation':reservation,'registrySha256':hashlib.sha256(registry_raw).hexdigest(),'censusPin':pin,'argv':argv,'environment':environment,'historicalUnknownsPreserved':True}
    intent_raw=(json.dumps(intent,sort_keys=True,separators=(',',':'))+'\n').encode();launch={'action':action,'correlationId':correlation,'device':device,'avd':owned['avd'],'port':owned['port'],'argv':argv,'environment':environment,'emulatorGeneration':sdk[emulator]['generation'],'qemuPath':str(Path(emulator).parent/'qemu/linux-x86_64/qemu-system-x86_64-headless'),'adbPath':'/opt/android-sdk/platform-tools/adb','adbFacts':sdk['/opt/android-sdk/platform-tools/adb'],'censusId':CENSUS_ID,'censusPin':pin,'observation':proof['observations'][0],'pendingBytes':pending,'intent':intent,'intentSha256':hashlib.sha256(intent_raw).hexdigest()}
    local=root/'.rag_index/android-avd-coldboot'/EXISTING_API35_CORRELATION/'launch.json'
    preserved,historical_sha,historical_fp=private_io._private(local,262144)
    if historical_sha!=EXISTING_API35_LAUNCH_SHA or historical_fp[2]!=67499:raise ValueError('coldboot_readonly_historical_launch_changed')
    if type(historical_producer)is not dict or set(historical_producer)!={'path','generation','sha256'} or type(historical_producer['path'])is not str or type(historical_producer['generation'])is not list or len(historical_producer['generation'])!=9 or any(type(x)is not int for x in historical_producer['generation']) or historical_producer['sha256']!=EXISTING_API35_PRODUCER_SHA:raise ValueError('coldboot_readonly_historical_producer_unknown')
    producer=Path(historical_producer['path']).absolute();producer_pin,producer_raw=availability._snapshot(producer)
    if list(producer_pin)!=historical_producer['generation'] or hashlib.sha256(producer_raw).hexdigest()!=EXISTING_API35_PRODUCER_SHA:raise ValueError('coldboot_readonly_historical_producer_changed')
    prepared['snapshots'][producer]=(producer_pin,producer_raw)
    historical_intent=preserved['intent']
    historical_raw=(json.dumps(historical_intent,sort_keys=True,separators=(',',':'))+'\n').encode()
    if hashlib.sha256(historical_raw).hexdigest()!=EXISTING_API35_INTENT_SHA or preserved['intentSha256']!=EXISTING_API35_INTENT_SHA or historical_intent['source'].get('agent_tools/android_avd_coldboot.py')!=EXISTING_API35_PRODUCER_SHA:raise ValueError('coldboot_readonly_historical_intent_changed')
    if preserved['correlationId']!=EXISTING_API35_CORRELATION or preserved['device']!=device or historical_intent['correlationId']!=EXISTING_API35_CORRELATION or historical_intent['device']!=device or historical_intent['reservation']!=reservation or preserved['argv']!=argv or preserved['environment']!=environment:raise ValueError('coldboot_readonly_existing_identity_changed')
    launch={**preserved,'action':'status','pendingBytes':pending}
    local_pin,local_raw=availability._snapshot(local);prepared['snapshots'][local]=(local_pin,local_raw)
    program=prepared['program']
    tree=ast.parse(program);assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CFG' for t in n.targets));lines=program.splitlines(keepends=True);lines[assignment.lineno-1:assignment.end_lineno]=['CFG='+repr(prepared['binding'])+'\n'];program=''.join(lines)
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_BOOT' for t in n.targets)))
    if not program.endswith('capture()\n'):raise ValueError('coldboot_composition_changed')
    program=program[:-len('capture()\n')]+template.replace('__LAUNCH__',repr(launch))
    prepared['program']=existing_readonly_program(program);prepared['readonlyCorrelationId']=correlation
    validate_existing_readonly(prepared['program']);census.guard_prepared(prepared);return prepared
