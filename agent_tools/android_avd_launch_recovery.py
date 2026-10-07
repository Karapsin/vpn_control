"""Source-bound privileged read-only census before owned AVD recovery.

This module currently grants no launch authority. The root operator executes the
returned fixed program and collects its private capsule through a privileged
route. Original device claims and historical unknown outcomes are unchanged.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re
from . import android_avd_fixture_recovery as preflight
from . import android_device_availability as availability
from . import android_endpoint_admission as endpoint
from . import android_owned_endpoint_bind_recovery as private_io

PROOF_ID='89279720-5b73-44ee-9ebe-1beca8a1a50b'
PROOF_SHA='16595376cccce218cb83cfe6ed4ae9180a74174ea9d400cd2ed00840a25cf5dd'
PREFLIGHT_SHA='ef59c18409c4d28f5558d2dab815fd1c6f4f371f089d8b1363bcc8ac1da2ceb7'
_REMOTE_ROOT='/home/kardinal/.vpn-control-mcp-fixtures'
_CENSUS=r'''
import hashlib,json,os,pathlib,re,stat
CFG=__CFG__
ROOT=pathlib.Path('/home/kardinal/.vpn-control-mcp-fixtures');PROC=pathlib.Path('/proc')
def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink]
def parent_fds(path):
 path=pathlib.Path(path)
 if not path.is_absolute() or any(part in ('..','.') for part in path.parts[1:]):raise ValueError('census_ancestry_invalid')
 chain=[]
 try:
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append({'fd':fd,'name':'/','pin':fp(os.fstat(fd))})
  for name in path.parts[1:-1]:
   fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd']);chain.append({'fd':fd,'name':name,'pin':fp(os.fstat(fd))})
  guard_parents(chain)
  return chain,path.name
 except BaseException:
  close_parents(chain);raise
def close_parents(chain):
 for item in reversed(chain):os.close(item['fd'])
def guard_parents(chain):
 for number,item in enumerate(chain):
  try:
   named=os.stat('/',follow_symlinks=False) if number==0 else os.stat(item['name'],dir_fd=chain[number-1]['fd'],follow_symlinks=False)
   if fp(os.fstat(item['fd']))!=item['pin'] or fp(named)!=item['pin']:raise ValueError('census_ancestry_changed')
  except FileNotFoundError:raise ValueError('census_ancestry_changed') from None
def read_fixed(path,limit):
 chain,name=parent_fds(path);fd=None
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd']);before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:raise ValueError('census_file_type')
  count=min(before.st_size,limit);raw=bytearray()
  while len(raw)<count:
   part=os.read(fd,min(count-len(raw),65536))
   if not part:break
   raw.extend(part)
  raw=bytes(raw)
  if len(raw)!=count or fp(before)!=fp(os.fstat(fd)) or fp(before)!=fp(os.stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False)):raise ValueError('census_file_changed')
  guard_parents(chain)
  return {'generation':fp(before),'bytesRead':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hashScope':'full' if len(raw)==before.st_size else 'prefix','raw':raw}
 finally:
  if fd is not None:os.close(fd)
  close_parents(chain)
def facts(path,limit=65536,text=False):
 try:
  value=read_fixed(path,limit);raw=value.pop('raw')
  if text:
   if value['hashScope']!='full':raise ValueError('census_metadata_limit')
   value['text']=raw.decode('utf-8','strict')
  return {'present':True,'kind':'regular',**value}
 except FileNotFoundError:return {'present':False}
def boot():
 raw=(PROC/'sys/kernel/random/boot_id').read_text().strip()
 if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',raw):raise ValueError('census_boot_unknown')
 return raw

def guard_proof(proof):
 expected=proof['observations'][0]
 if boot()!=expected['bootId']:raise ValueError('census_host_boot_changed')
 for alias,claim in expected['claims'].items():
  if facts(ROOT/('android-native-device-'+alias+'.lease'),8192,True)!=claim:raise ValueError('census_claim_changed')

def tree_facts(root):
 result={};pending=[root];seen=0
 while pending:
  directory=pending.pop();chain,unused=parent_fds(directory/'__census_directory_descriptor__')
  try:
   directory_fd=chain[-1]['fd'];before=os.fstat(directory_fd)
   if not stat.S_ISDIR(before.st_mode) or before.st_uid!=1000:raise ValueError('census_tree_type')
   result[str(directory.relative_to(root))]={'kind':'directory','generation':fp(before)}
   names=sorted(os.listdir(directory_fd))
   for name in names:
    seen+=1
    if seen>4096 or not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('census_tree_limit')
    path=directory/name;info=os.stat(name,dir_fd=directory_fd,follow_symlinks=False);relative=str(path.relative_to(root))
    if stat.S_ISDIR(info.st_mode):pending.append(path)
    elif stat.S_ISREG(info.st_mode):
     if info.st_uid!=1000:raise ValueError('census_tree_owner')
     result[relative]={'kind':'regular',**facts(path)}
    else:raise ValueError('census_tree_type')
   guard_parents(chain)
  finally:close_parents(chain)
 return result

def metadata(proof):
 expected=proof['observations'][0];avds={};identities={}
 for alias in ('api29','api35'):
  saved=expected['avds'][alias];directory=pathlib.Path(saved['avdDirectory']['path'])
  if fp(directory.lstat())!=saved['avdDirectory']['generation']:raise ValueError('census_avd_directory_changed')
  if facts(directory.parent/(saved['historicalSelection']['avd']+'.ini'),65536,True)!=saved['ini'] or facts(directory/'config.ini',65536,True)!=saved['config']:raise ValueError('census_avd_config_changed')
  tree=tree_facts(directory)
  for name,old in saved['inventory'].items():
   current=tree.get(name)
   if old['kind']=='directory':
    if current!={'kind':'directory','generation':old['generation']}:raise ValueError('census_avd_inventory_changed')
   elif old['kind']=='regular':
    compare={k:v for k,v in old.items() if k!='text'}
    if current!=compare:raise ValueError('census_avd_disk_changed')
   else:raise ValueError('census_avd_inventory_type')
  if sorted(saved['inventory'])!=sorted(name for name in tree if name!='.' and '/' not in name):raise ValueError('census_avd_inventory_changed')
  sdk={}
  for name,old in saved['sdkFiles'].items():
   current=facts(pathlib.Path(name),16777216,name.endswith('/package.xml'))
   if current!=old:raise ValueError('census_sdk_changed')
   sdk[name]=current
  avds[alias]={'directory':saved['avdDirectory'],'tree':tree,'sdkFiles':sdk,'ini':saved['ini'],'config':saved['config'],'diskFullHistoricalShaVerified':False}
  for name,value in tree.items():
   if value['kind']=='regular':identities.setdefault(tuple(value['generation'][:2]),[]).append(alias+'/'+name)
  for name,value in sdk.items():
   if value.get('kind')=='regular':identities.setdefault(tuple(value['generation'][:2]),[]).append(alias+'/sdk/'+name)
 return avds,identities

def ticks(proc):
 with (proc/'stat').open('r') as stream:raw=stream.read(8193)
 if len(raw)>8192:raise ValueError('census_process_stat_limit')
 return int(raw.rsplit(')',1)[1].split()[19])
def process_census(identities):
 pids=sorted((p for p in PROC.iterdir() if p.name.isdecimal()),key=lambda p:int(p.name))
 if len(pids)>32768:raise ValueError('census_process_limit')
 denied=0;vanished=0;found=[];emulators=[]
 for proc in pids:
  try:
   start=ticks(proc)
   with (proc/'cmdline').open('rb') as stream:cmd=stream.read(65537)
   if len(cmd)>65536:raise ValueError('census_process_command_limit')
   try:exe=os.readlink(proc/'exe').rsplit('/',1)[-1]
   except FileNotFoundError:exe=''
   args=cmd.split(b'\0');name=args[0].rsplit(b'/',1)[-1]
   if exe.startswith('qemu-system-') or exe=='emulator' or name.startswith(b'qemu-system-') or name==b'emulator':emulators.append({'pid':int(proc.name),'startTicks':start,'executableName':exe})
   fds=list((proc/'fd').iterdir())
   if len(fds)>65536:raise ValueError('census_fd_limit')
   matches=[]
   for fd in fds:
    try:i=fd.stat()
    except FileNotFoundError:continue
    matches.extend(identities.get((i.st_dev,i.st_ino),[]))
   if ticks(proc)!=start:raise ValueError('census_pid_reused')
   if matches:found.append({'pid':int(proc.name),'startTicks':start,'files':sorted(set(matches))})
  except FileNotFoundError:vanished+=1
  except PermissionError:denied+=1
 return {'complete':denied==0,'unreadableProcessCount':denied,'vanishedProcessCount':vanished,'holders':found,'emulators':emulators}

def ports():
 found=[]
 for family in ('tcp','tcp6'):
  for row in (PROC/'net'/family).read_text().splitlines()[1:]:
   fields=row.split()
   if len(fields)<10:raise ValueError('census_ports_unknown')
   number=int(fields[1].rsplit(':',1)[1],16)
   if number in (5682,5683,5684,5685):found.append({'family':family,'port':number,'state':fields[3],'inode':fields[9]})
 return sorted(found,key=lambda v:(v['family'],v['port'],v['inode']))
def observe(proof):
 guard_proof(proof);avds,identities=metadata(proof);processes=process_census(identities);bindings=ports();after,ignored=metadata(proof);guard_proof(proof)
 if avds!=after:raise ValueError('census_inventory_changed_during_scan')
 return {'bootId':boot(),'avds':avds,'processes':processes,'ports':bindings}
def summary(observations):
 successful=len(observations)==2 and all('error' not in o for o in observations)
 stable=successful and all(observations[0][k]==observations[1][k] for k in ('bootId','avds','ports'))
 complete=successful and all(o['processes']['complete'] for o in observations)
 return {'stable':stable,'complete':complete,'holderCount':sum(len(o.get('processes',{}).get('holders',[])) for o in observations),'emulatorCount':sum(len(o.get('processes',{}).get('emulators',[])) for o in observations),'ownedPortsFree':successful and all(not o['ports'] for o in observations),'lifecycleAllowed':False,'productAdmitted':False}
def write_capsule(root_chain,name,data):
 if not re.fullmatch(r'android-avd-privileged-census-[0-9a-f-]{36}\.json',name) or len(data)>524288:raise ValueError('census_capture_binding')
 guard_parents(root_chain)
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root_chain[-1]['fd'])
 with os.fdopen(fd,'wb') as stream:
  # This create changes the held parent; the named route and ancestors remain pinned.
  current=fp(os.fstat(root_chain[-1]['fd']));previous=root_chain[-1]['pin']
  if any(current[index]!=previous[index] for index in (0,1,5,6,7,8)):raise ValueError('census_parent_changed')
  root_chain[-1]['pin']=current;guard_parents(root_chain)
  stream.write(data);stream.flush();os.fsync(stream.fileno())
 os.fsync(root_chain[-1]['fd']);guard_parents(root_chain)
def capture():
 if os.getuid()!=0 or os.geteuid()!=0:raise ValueError('census_privileged_principal_required')
 root_chain,unused=parent_fds(ROOT/'__census_root_descriptor__')
 try:
  parent=os.fstat(root_chain[-1]['fd'])
  if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=1000 or stat.S_IMODE(parent.st_mode)!=0o700:raise ValueError('census_parent_changed')
  path=ROOT/('android-avd-preflight-'+CFG['proofCorrelation']+'.json');value=read_fixed(path,524288);raw=value.pop('raw')
  if value!=CFG['proofPin'] or value['generation'][6:9]!=[1000,1000,1] or stat.S_IMODE(value['generation'][5])!=0o600:raise ValueError('census_proof_changed')
  proof=json.loads(raw)
  if proof['correlationId']!=CFG['proofCorrelation'] or proof['source']!=CFG['proofSource'] or proof['localClaims']!=CFG['localClaims'] or not proof['stable'] or proof['lifecycleAllowed'] is not False:raise ValueError('census_proof_binding')
  capsule=ROOT/('android-avd-privileged-census-'+CFG['correlationId']+'.json')
  try:os.stat(capsule.name,dir_fd=root_chain[-1]['fd'],follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise ValueError('census_capture_exists')
  observations=[]
  for number in range(2):
   try:observations.append(observe(proof))
   except (OSError,ValueError,UnicodeError) as exc:
    reason=str(exc) if str(exc).startswith('census_') and len(str(exc))<80 else 'census_observation_unknown'
    observations.append({'error':reason,'pass':number+1})
  if read_fixed(path,524288)!=dict(CFG['proofPin'],raw=raw):raise ValueError('census_proof_changed')
  guard_parents(root_chain)
  result={'schema':1,'kind':'readonly-privileged-owned-avd-census','correlationId':CFG['correlationId'],'proofCorrelation':CFG['proofCorrelation'],'proofPin':CFG['proofPin'],'source':CFG['source'],'localClaims':CFG['localClaims'],'observations':observations,'summary':summary(observations),'lifecycleAllowed':False,'historicalOutcomesPreserved':True}
  data=(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode()
  if len(data)>524288:raise ValueError('census_capture_limit')
  write_capsule(root_chain,capsule.name,data)
  pin=read_fixed(capsule,524288);pin.pop('raw');guard_parents(root_chain)
  print(json.dumps({'state':'captured','correlationId':CFG['correlationId'],'name':capsule.name,'pin':pin,'summary':result['summary']},separators=(',',':')))
 finally:close_parents(root_chain)

capture()
'''

def prepare_privileged_census(root: Path,correlation: str) -> dict:
    """Build fixed read-only program; caller retains binding and guards dispatch.

    No SSH/native operation occurs here. Execute as root only. The returned
    capsule is root-owned600, so collection also requires a privileged reader.
    """
    root=Path(root).absolute()
    if not isinstance(correlation,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',correlation) or correlation==PROOF_ID:raise ValueError('census_correlation')
    cfg,snapshots,claims,config=preflight._prepare(root,PROOF_ID)
    proof_path=root/'.runtime/parity-evidence/android-current'/('owned-avd-preflight-'+PROOF_ID+'.json')
    proof_pin,proof_raw=availability._snapshot(proof_path);snapshots[proof_path]=(proof_pin,proof_raw)
    if hashlib.sha256(proof_raw).hexdigest()!=PROOF_SHA:raise ValueError('census_local_proof_changed')
    receipt_path=proof_path.with_name(proof_path.stem+'.receipt.json');receipt_pin,receipt_raw=availability._snapshot(receipt_path);snapshots[receipt_path]=(receipt_pin,receipt_raw)
    receipt=json.loads(receipt_raw);proof=json.loads(proof_raw)
    if receipt['cfg']!=cfg or receipt['result']['pin']['sha256']!=PROOF_SHA or receipt['result']['pin']['generation'][2]!=len(proof_raw) or proof['source']!=cfg['source'] or not proof['stable']:raise ValueError('census_receipt_changed')
    if cfg['source'].get('agent_tools/android_avd_fixture_recovery.py')!=PREFLIGHT_SHA:raise ValueError('census_consumed_preflight_changed')
    for alias in ('api29','api35'):
        saved=proof['observations'][0]['avds'][alias]
        if saved['historicalSelection']!=preflight.OWNED[alias] or saved['avdDirectory']['path']!=preflight.OWNED[alias]['avdHome']+'/'+preflight.OWNED[alias]['avd']+'.avd':raise ValueError('census_owned_path_changed')
    for dependency,wanted in (
        (Path(availability.__file__).absolute(),'cf1c73ef15a432ff57eff452fd99cf27f2f9927f7305b56f642ee7c544e838ef'),
        (Path(endpoint.__file__).absolute(),'8274fffd51310221658a60686c8ffe4858ee4f5baa87197132b118df096cfca7'),
        (Path(private_io.__file__).absolute(),'eb038ed44e150f0a053805abc107f9092122a61112aa43bb8f905b58e69c3f4b'),
    ):
        pin,raw=availability._snapshot(dependency)
        if hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError('census_dependency_changed')
        snapshots[dependency]=(pin,raw)
    own=Path(__file__).absolute();own_pin,own_raw=availability._snapshot(own);snapshots[own]=(own_pin,own_raw)
    source=dict(cfg['source']);source.update({str(p.relative_to(root)):hashlib.sha256(value[1]).hexdigest() for p,value in snapshots.items() if 'agent_tools' in p.parts})
    binding={'correlationId':correlation,'proofCorrelation':PROOF_ID,'proofPin':receipt['result']['pin'],'proofSource':cfg['source'],'source':source,'localClaims':cfg['localClaims']}
    template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_CENSUS' for t in n.targets)))
    program=template.replace('__CFG__',repr(binding));compile(program,'<fixed-privileged-avd-census>','exec')
    return {'program':program,'binding':binding,'snapshots':snapshots,'claims':claims,'lifecycleAllowed':False}

def guard_prepared(prepared: dict) -> None:
    """Call immediately before and after the root operator's fixed dispatch."""
    for path,wanted in prepared['snapshots'].items():
        if availability._snapshot(path)!=wanted:raise ValueError('census_local_source_changed')
    for path,wanted in prepared['claims'].items():
        if (endpoint._recovery_local_snapshot(path) if path.exists() or path.is_symlink() else None)!=wanted:raise ValueError('census_local_claim_changed')
