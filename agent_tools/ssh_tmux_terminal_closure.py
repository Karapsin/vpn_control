"""Completed86 claim archival only; never release its unbound resource row.

The single cooperating operator pauses remote lifecycle operations during closure.
The new resource bridge uses the same local claim lock. No external-writer CAS is
claimed. Terminal/history/artifacts remain immutable; consumed fences never retry.
"""
from __future__ import annotations
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys
import time
from uuid import UUID,uuid4
from . import ssh_tmux_mcp_adapter as adapter
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import linux_package_fixture_build as build
from . import native_artifact_registry as registry
from . import ssh_transport
from .private_inventory_lock import Directory
if os.name=='posix':
 from . import ssh_tmux_bounded_pipe_collection as pipe
 import fcntl
else:pipe=fcntl=None
need=old.need
CORRELATION='86fcac2e-2fb5-47a8-bf1e-eb62d4accfd0'
ADAPTER_SHA='e18776b55a426c52d4f3b65cc3373c1930705a1ab13556bfb6e7357322466dd6'


def _sources(root):
 values=adapter._sources(root)
 need(values[str(Path(adapter.__file__).absolute())]['sha256']==ADAPTER_SHA,'adapter_source_changed')
 path=Path(__file__).absolute();values[str(path)]=pipe._read(path,262144,False)[1]
 companion=Path(__file__).with_name('ssh_tmux_resource_admission.py').absolute();values[str(companion)]=pipe._read(companion,262144,False)[1]
 return values


def _directory(root):
 base=Path(root)/'.rag_index';need(base.is_dir(),'closure_index_absent')
 target=base/'ssh-tmux-terminal-closure'
 if not os.path.lexists(target):pipe._mkdir(base,target.name)
 with Directory(target):pass
 return target


@contextmanager
def claim_lock(root):
 need(os.name=='posix','unsupported_coordinator_platform')
 directory=Path(root)/build._JOURNAL
 with Directory(directory) as parent:
  fd=os.open('claim.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent.fd)
  try:
   info=os.fstat(fd);pin=session.generation(info)
   need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size==0,'claim_lock_unsafe')
   need(pin==session.generation(os.stat('claim.lock',dir_fd=parent.fd,follow_symlinks=False)),'claim_lock_changed');os.fsync(fd);os.fsync(parent.fd)
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);parent.guard()
   def guard():
    parent.guard();need(pin==session.generation(os.fstat(fd))==session.generation(os.stat('claim.lock',dir_fd=parent.fd,follow_symlinks=False)),'claim_lock_changed')
   guard();yield parent,guard;guard()
  finally:os.close(fd)


_DISPATCH="""if action=='prepare':result=ns['start'](job,source,request)
elif action=='release':result=ns['release'](job,source,payload['anchorPin'])
elif action=='status':result=ns['status'](job,source,payload['anchorPin'])
else:result=ns['collect'](job,source,payload['anchorPin'],payload['terminalPin'],payload['offset'],payload['limit'],payload['resultPin'])"""
_CENSUS=r'''
import time
if set(payload)!={'action','request','stagePin','anchorPin'} or action!='status':raise ValueError('closure_fixed_status_required')
if request!=FIXED_REQUEST or payload['stagePin']!=FIXED_STAGE or payload['anchorPin']!=FIXED_ANCHOR:raise ValueError('closure_original_authority_changed')
def reference_census():
 deadline=time.monotonic()+8;entries=list(pathlib.Path('/proc').iterdir())
 if len(entries)>8192:raise ValueError('closure_census_limit')
 rows=[];references=[];pane=anchor['pane']
 principal=pathlib.Path('/proc')/str(pane['pid'])
 if principal.exists():
  try:principal_fields=(principal/'stat').read_bytes().rsplit(b')',1)[1].split()
  except (OSError,ValueError,IndexError):raise ValueError('closure_original_principal_unknown')
  if int(principal_fields[19])==pane['startTicks'] and principal_fields[0]!=b'Z':raise ValueError('closure_original_worker_live')
 for item in entries:
  if not item.name.isdigit() or int(item.name)==os.getpid():continue
  pid=int(item.name)
  try:
   if item.stat().st_uid!=os.getuid():continue
   with (item/'stat').open('rb') as f:before=f.read(8193)
   if len(before)>8192:raise ValueError('closure_process_unknown')
   fields=before.rsplit(b')',1)[1].split();ticks=int(fields[19]);state=fields[0]
   with (item/'cmdline').open('rb') as f:argv=f.read(65537)
   cwd=os.readlink(item/'cwd') if state!=b'Z' else ''
   with (item/'stat').open('rb') as f:after=f.read(8193)
  except (OSError,ValueError,IndexError):raise ValueError('closure_process_unknown')
  if fields[19]!=after.rsplit(b')',1)[1].split()[19] or (fields[0]==b'Z')!=(after.rsplit(b')',1)[1].split()[0]==b'Z') or len(argv)>65536:raise ValueError('closure_process_changed')
  rows.append([pid,ticks])
  if pid==pane['pid'] and ticks==pane['startTicks'] and state!=b'Z':raise ValueError('closure_original_worker_live')
  fixed=os.fsencode(job);tokens=argv.split(b'\0')
  if state!=b'Z' and (cwd==str(job) or cwd.startswith(str(job)+'/') or any(t==fixed or t.startswith(fixed+b'/') for t in tokens)):references.append([pid,ticks])
  if time.monotonic()>deadline:raise ValueError('closure_census_timeout')
 if references:raise ValueError('closure_workspace_referenced')
 return {'complete':True,'originalPaneEnded':True,'references':[],'rowCount':len(rows),'tableSha256':hashlib.sha256(json.dumps(sorted(rows)).encode()).hexdigest()}
status=ns['status'](job,source,payload['anchorPin'])
if status!={'state':'terminal','correlationId':request['correlationId'],'exitCode':0,'terminalPin':FIXED_TERMINAL,'artifactVerification':'required','replayAllowed':False}:raise ValueError('closure_terminal_changed')
anchor=ns['_anchor'](job,source,payload['anchorPin'])
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
first=reference_census();second=reference_census()
if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot or ns['status'](job,source,payload['anchorPin'])!=status:raise ValueError('closure_generation_changed')
result={'state':'completed-unreferenced','request':request,'hostBootId':boot,'terminal':status,'anchorPin':payload['anchorPin'],'stagePin':payload['stagePin'],'observations':[first,second],'nativeActionAllowed':False,'replayAllowed':False}
'''


def remote_program():
 need(old._ACTION.count(_DISPATCH)==1,'closure_dispatch_changed')
 text=_CENSUS.replace('FIXED_REQUEST',repr(old.purpose(pipe.REQUEST))).replace('FIXED_STAGE',repr(pipe.STAGE)).replace('FIXED_ANCHOR',repr(pipe.ANCHOR)).replace('FIXED_TERMINAL',repr(pipe.TERMINAL))
 result=old._ACTION.replace(_DISPATCH,text)
 compile(result,'<fixed-completed-tmux-reference-proof>','exec');return result


def fixed_query(root,program,payload,guard,snapshot=None):
 """Internal closed query; callers supply only one of the two reviewed factories."""
 allowed=[remote_program()]
 # Resource companion supplies its source-closed host program by exact equality.
 from . import ssh_tmux_resource_admission as resource
 allowed.append(resource.host_program())
 need(program in allowed,'unsupported_closed_query')
 sources=_sources(root);sources[str(Path(resource.__file__).absolute())]=pipe._read(Path(resource.__file__).absolute(),262144,False)[1]
 driver=adapter.McpTmuxDriver(root);config,transport=driver._transport()
 need(ssh_transport.connection_host(config,'archlinux').password is None,'password_transport_not_supported')
 argv=ssh_transport.build_ssh_argv(config,'archlinux',10,command=['python3','-I','-B','-c','exec('+repr(program)+')'])
 def close_guard():
  current=_sources(root);current[str(Path(resource.__file__).absolute())]=pipe._read(Path(resource.__file__).absolute(),262144,False)[1]
  need(current==sources and driver._transport()[1]==transport,'closure_route_changed');guard()
 def launch():
  close_guard();return adapter.subprocess.Popen(argv,cwd=root,stdin=adapter.subprocess.PIPE,stdout=adapter.subprocess.PIPE,stderr=adapter.subprocess.PIPE,bufsize=0)
 authority={'phase':'status','snapshot':snapshot,'sources':sources,'transport':transport,'local':{},'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest()}
 outcome,capsule=adapter._capture(root,authority=authority,launch=launch,payload=session.canonical(payload),guard=close_guard)
 need(outcome['state']=='captured','closure_transport_unknown')
 raw,pin=pipe._read(capsule/'receipt.json');need(pin==outcome['receiptPin'],'closure_capture_changed');record=json.loads(raw)
 raw,pin=pipe._read(capsule/'stdout',adapter.MAX_STDOUT);need(pin==record['stdoutPin'] and pipe._read(capsule/'stderr',adapter.MAX_STDERR)[1]==record['stderrPin'],'closure_capture_changed')
 value=json.loads(raw,object_pairs_hook=ssh_transport._reject_duplicate_keys);close_guard();need(type(value)is dict,'closure_reply_unknown')
 return value,{'directory':str(capsule.relative_to(root)),'receiptPin':outcome['receiptPin'],'stdoutPin':pin}


def local_proof(root):
 driver=adapter.McpTmuxDriver(root);job,snapshot=driver._saved(pipe.REQUEST)
 need(pipe._read(job.parent/'archlinux.claim')[1]==pipe.HISTORY_PINS[str((job.parent/'archlinux.claim').relative_to(root))],'original_claim_changed')
 proof=old.output_record(job,pipe.REQUEST,old.result_record(job));need(json.loads(pipe._read(job/'tmux-output-ready.json')[0])==proof,'closure_output_not_ready')
 paths=build._verify_built(job/'output',pipe.REQUEST);timings=build._timing_inventory(job/'output/.rag_index/build-timings',pipe.REQUEST)
 pins={};artifacts=[]
 for name in ('tmux-adapter-intent.json','tmux-stage.json','tmux-anchor.json','tmux-collection.json','tmux-output-ready.json'):
  relative=str((job/name).relative_to(root));pins[relative]=pipe._read(job/name)[1]
  if relative in pipe.HISTORY_PINS:need(pins[relative]==pipe.HISTORY_PINS[relative],'closure_original_history_changed')
 need(pins[str((job/'tmux-output-ready.json').relative_to(root))]=={'generation':[16777234,111589426,33152,503,20,449,1791046388572402413,1791046388572402413,1],'sha256':'3d873bfd0781d7ca46368592ca3e97d4fe3d1d0643bd2470bae1dfecf554722e'},'closure_original_output_changed')
 pins[str((job.parent/'archlinux.claim').relative_to(root))]=pipe._read(job.parent/'archlinux.claim')[1]
 for path in paths:
  if path.name!='fixture-receipt.json' and 'packages' not in path.parts:continue
  pin=old.file_pin(path,1024**3);record=registry.verify_artifact(root,'sha256-'+pin['sha256'])
  a=record.get('artifact',{});location=record.get('location',{})
  need(record.get('verification')=='verified' and a.get('sourceSha')==pipe.REQUEST['sourceSha'] and a.get('platform')=='linux' and a.get('sha256')==pin['sha256'] and a.get('size')==pin['generation'][5] and location.get('evidenceClass')=='local-verified' and location.get('localPath')==str(path),'closure_artifact_unverified')
  artifacts.append({'artifactId':a['artifactId'],'pin':pin})
  pins[str(path.relative_to(root))]=pin
  metadata=root/registry.INDEX_RELATIVE/(a['artifactId']+'.json');pins[str(metadata.relative_to(root))]=pipe._read(metadata,registry.MAX_RECORD_BYTES)[1]
 for path in timings:
  published=root/'.rag_index/build-timings'/path.name;pin=pipe._read(path,4096)[1]
  need(build._digest(path,4096)==build._digest(published,4096),'closure_timing_changed');pins[str(path.relative_to(root))]=pin;pins[str(published.relative_to(root))]=pipe._read(published,4096)[1]
 need(len(artifacts)==10 and len(timings)==12,'closure_evidence_incomplete')
 pins[str((job/'result.tar').relative_to(root))]=old.file_pin(job/'result.tar',session.MAX_RESULT)
 result_pin=old.result_record(job);archive_pin=pins[str((job/'result.tar').relative_to(root))]
 need(archive_pin['sha256']==result_pin['sha256'] and archive_pin['generation'][5]==result_pin['generation'][5],'closure_result_changed')
 for name in ('record.json','seal.json'):pins[str((job/'result-authority'/name).relative_to(root))]=pipe._read(job/'result-authority'/name)[1]
 # Resource inventory is observed unchanged, never interpreted as an old-job link.
 pins['.rag_index/native-environments/reservations.json']=pipe._read(root/'.rag_index/native-environments/reservations.json',1048576)[1]
 return {'snapshot':snapshot,'sources':_sources(root),'pins':pins,'artifacts':artifacts,'outputProof':proof}


def guard_local(root,local):
 need(_sources(root)==local['sources'],'closure_source_changed')
 adapter.McpTmuxDriver(root)._guard(pipe.REQUEST,local['snapshot'])
 for relative,pin in local['pins'].items():
  path=Path(root)/relative
  with Directory(path.parent) as parent:
   fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent.fd)
   try:
    parent.guard();need(session.generation(os.fstat(fd))==pin['generation']==session.generation(os.stat(path.name,dir_fd=parent.fd,follow_symlinks=False)),'closure_local_generation_changed');parent.guard()
   finally:os.close(fd)


def validate_remote(value):
 need(type(value)is dict and set(value)=={'state','request','hostBootId','terminal','anchorPin','stagePin','observations','nativeActionAllowed','replayAllowed'} and value['state']=='completed-unreferenced' and value['request']==old.purpose(pipe.REQUEST) and value['anchorPin']==pipe.ANCHOR and value['stagePin']==pipe.STAGE and value['terminal']=={'state':'terminal','correlationId':CORRELATION,'exitCode':0,'terminalPin':pipe.TERMINAL,'artifactVerification':'required','replayAllowed':False} and type(value['terminal']['exitCode'])is int and value['terminal']['replayAllowed']is False and value['nativeActionAllowed']is False and value['replayAllowed']is False,'closure_remote_proof_unknown')
 need(type(value['hostBootId'])is str and str(UUID(value['hostBootId']))==value['hostBootId'] and type(value['observations'])is list and len(value['observations'])==2,'closure_remote_proof_unknown')
 for row in value['observations']:
  need(type(row)is dict and set(row)=={'complete','originalPaneEnded','references','rowCount','tableSha256'} and row['complete']is True and row['originalPaneEnded']is True and row['references']==[] and type(row['rowCount'])is int and 0<=row['rowCount']<=8192 and type(row['tableSha256'])is str and re.fullmatch('[0-9a-f]{64}',row['tableSha256']) is not None,'closure_reference_unknown')
 return value


def observe(root,correlation_id=CORRELATION):
 need(type(correlation_id)is str and correlation_id==CORRELATION,'closure_fixed_correlation_required');root=Path(root).absolute()
 with claim_lock(root) as (_,lock_guard):
  local=local_proof(root)
  def guard():lock_guard();guard_local(root,local)
  value,capture=fixed_query(root,remote_program(),{'action':'status','request':old.purpose(pipe.REQUEST),'stagePin':pipe.STAGE,'anchorPin':pipe.ANCHOR},guard,local['snapshot']);validate_remote(value);guard()
  directory=pipe._mkdir(_directory(root),str(uuid4()));proof={'correlationId':CORRELATION,'observedAtUnixMs':time.time_ns()//1000000,'local':local,'remote':value,'capture':capture,'oldResourceReservationUnchanged':True}
  pin=pipe._write_once(directory/'proof.json',session.canonical(proof))
  return {'state':'ready','correlationId':CORRELATION,'proofId':directory.name,'proofPin':pin,'resourceReleaseAllowed':False,'nativeActionAllowed':False,'replayAllowed':False}


def _rename_function():
 need(sys.platform in ('darwin','linux'),'unsupported_archive_platform')
 function=ctypes.CDLL(None,use_errno=True).renameatx_np if sys.platform=='darwin' else ctypes.CDLL(None,use_errno=True).renameat2
 function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];function.restype=ctypes.c_int
 return function


def _rename(source,source_name,target,target_name,function=None):
 function=function or _rename_function()
 need(function(source.fd,os.fsencode(source_name),target.fd,os.fsencode(target_name),4 if sys.platform=='darwin' else 1)==0,'closure_archive_failed')
 os.fsync(source.fd);os.fsync(target.fd)


def status(root,identity):
 need(type(identity)is dict and set(identity)=={'proofId','proofPin'} and type(identity['proofId'])is str and str(UUID(identity['proofId']))==identity['proofId'] and session._valid_pin(identity['proofPin']),'closure_identity_invalid')
 directory=Path(root)/'.rag_index/ssh-tmux-terminal-closure'/identity['proofId'];raw,pin=pipe._read(directory/'proof.json',1048576);need(pin==identity['proofPin'],'closure_proof_changed')
 proof=json.loads(raw);need(type(proof)is dict and set(proof)=={'correlationId','observedAtUnixMs','local','remote','capture','oldResourceReservationUnchanged'} and proof['correlationId']==CORRELATION and type(proof['observedAtUnixMs'])is int and proof['oldResourceReservationUnchanged']is True,'closure_proof_invalid');validate_remote(proof['remote'])
 if not os.path.lexists(directory/'fence.json'):return {'state':'observed','replayAllowed':False,'resourceReleaseAllowed':False}
 if not os.path.lexists(directory/'terminal.json'):return {'state':'unknown','replayAllowed':False,'resourceReleaseAllowed':False}
 terminal=json.loads(pipe._read(directory/'terminal.json')[0]);need(type(terminal)is dict and set(terminal)=={'proofPin','fencePin','archivedClaimPin','capture','resourceReleaseAllowed'} and terminal['resourceReleaseAllowed']is False,'closure_terminal_invalid');need(terminal['proofPin']==pin and terminal['fencePin']==pipe._read(directory/'fence.json')[1] and terminal['archivedClaimPin']==pipe._read(directory/'archived-claim')[1],'closure_history_changed')
 return {'state':'closed','correlationId':CORRELATION,'replayAllowed':False,'resourceReleaseAllowed':False,'oldIntentPreserved':True}


def close(root,identity):
 root=Path(root).absolute();observed=status(root,identity)
 if observed['state']!='observed':return observed
 directory=root/'.rag_index/ssh-tmux-terminal-closure'/identity['proofId'];raw,pin=pipe._read(directory/'proof.json',1048576);proof=json.loads(raw)
 need(0<=time.time_ns()//1000000-proof['observedAtUnixMs']<=120000,'closure_proof_stale')
 with claim_lock(root) as (parent,lock_guard),Directory(directory) as target:
  need(status(root,identity)['state']=='observed','closure_consumed')
  local=local_proof(root);need(local==proof['local'],'closure_local_authority_changed')
  rename_function=_rename_function()
  fence=pipe._write_once(directory/'fence.json',session.canonical({'proofPin':pin,'resourceReleaseAllowed':False}))
  def guard():lock_guard();target.guard();need(pipe._read(directory/'fence.json')[1]==fence and pipe._read(directory/'proof.json',1048576)[1]==pin  ,'closure_authority_changed');guard_local(root,local)
  value,capture=fixed_query(root,remote_program(),{'action':'status','request':old.purpose(pipe.REQUEST),'stagePin':pipe.STAGE,'anchorPin':pipe.ANCHOR},guard,local['snapshot']);validate_remote(value);need(value['hostBootId']==proof['remote']['hostBootId'],'closure_host_changed')
  guard();need(local['pins'][str((root/build._JOURNAL/'archlinux.claim').relative_to(root))]['generation']==session.generation(os.stat('archlinux.claim',dir_fd=parent.fd,follow_symlinks=False)),'closure_claim_changed');_rename(parent,'archlinux.claim',target,'archived-claim',rename_function)
  archived=pipe._read(directory/'archived-claim')[1];original=local['pins'][str((root/build._JOURNAL/'archlinux.claim').relative_to(root))]
  need(archived['sha256']==original['sha256'] and all(archived['generation'][i]==original['generation'][i] for i in (0,1,2,3,4,5,6,8)),'closure_archive_changed')
  pipe._write_once(directory/'terminal.json',session.canonical({'proofPin':pin,'fencePin':fence,'archivedClaimPin':archived,'capture':capture,'resourceReleaseAllowed':False}))
 return status(root,identity)
