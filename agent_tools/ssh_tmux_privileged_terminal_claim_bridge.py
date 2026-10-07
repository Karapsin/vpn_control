"""Fresh privileged census bridge for one terminal claim archival.

This bridge never releases a reservation, archives a workspace, or signals a
process. It archives only the completed 86 coordinator claim after two fresh
owner->root->owner observations under the existing claim lock.
"""
from __future__ import annotations
import hashlib,json,os,time
from pathlib import Path
from uuid import UUID,uuid4
from . import ssh_tmux_terminal_closure as closure
from . import ssh_tmux_privileged_terminal_closure as privileged
from . import ssh_tmux_bounded_pipe_collection as pipe
from . import ssh_tmux_session as session
from . import linux_package_fixture_build as build
from .private_inventory_lock import Directory

CORRELATION=closure.CORRELATION
PRIVILEGED_SHA='155639b124fd0e400863b8abf82e4d87b94056c1697c0da902136d6bd33f56ca'
MAX_AGE_MS=120000

def _sources(root):
 values=closure._sources(root)
 need=closure.need
 need(hashlib.sha256(Path(privileged.__file__).read_bytes()).hexdigest()==PRIVILEGED_SHA,'privileged_source_changed')
 values[str(Path(privileged.__file__).absolute())]=pipe._read(Path(privileged.__file__).absolute(),262144,False)[1]
 path=Path(__file__).absolute();values[str(path)]=pipe._read(path,262144,False)[1]
 return values

def _fresh(root):
 value=privileged.observe_diagnostic(root)
 closure.need(type(value)is dict and value.get('state')=='complete-root-census' and value.get('correlationId')==CORRELATION and value.get('workspaceProof')is False and value.get('nativeActionAllowed')is False and value.get('replayAllowed')is False and session._valid_pin(value.get('receiptPin')),'privileged_census_not_complete')
 return {'boot':value['hostBootId'],'pane':value['pane'],'receiptPin':value['receiptPin'],'result':value}

def _base(root):
 local=closure.local_proof(root)
 return {'local':local,'sources':_sources(root)}

def _directory(root):
 base=root/'.rag_index'
 if not os.path.lexists(base):base.mkdir(mode=0o700)
 pipe._mkdir(base,'ssh-tmux-privileged-terminal-claim-bridge') if not os.path.lexists(base/'ssh-tmux-privileged-terminal-claim-bridge') else None
 return base/'ssh-tmux-privileged-terminal-claim-bridge'

def _valid_proof(value):
 closure.need(type(value)is dict and set(value)=={'correlationId','observedAtUnixMs','base','fresh','resourceReleaseAllowed','replayAllowed'} and value['correlationId']==CORRELATION and type(value['observedAtUnixMs'])is int and value['resourceReleaseAllowed']is False and value['replayAllowed']is False,'bridge_proof_invalid')

def _proof_fresh(proof):
 closure.need(0<=time.time_ns()//1000000-proof['observedAtUnixMs']<=MAX_AGE_MS,'bridge_proof_stale')

def observe(root):
 root=Path(root).absolute()
 with closure.claim_lock(root) as (_,lock_guard):
  base=_base(root);fresh=_fresh(root)
  closure.need(_base(root)==base,'bridge_authority_changed');lock_guard()
  directory=pipe._mkdir(_directory(root),str(uuid4()))
  proof={'correlationId':CORRELATION,'observedAtUnixMs':time.time_ns()//1000000,'base':base,'fresh':fresh,'resourceReleaseAllowed':False,'replayAllowed':False}
  pin=pipe._write_once(directory/'proof.json',session.canonical(proof))
  return {'state':'ready','correlationId':CORRELATION,'proofId':directory.name,'proofPin':pin,'resourceReleaseAllowed':False,'nativeActionAllowed':False,'replayAllowed':False}

def _proof(root,identity):
 closure.need(type(identity)is dict and set(identity)=={'proofId','proofPin'} and type(identity['proofId'])is str and str(UUID(identity['proofId']))==identity['proofId'] and session._valid_pin(identity['proofPin']),'bridge_identity_invalid')
 directory=_directory(root)/identity['proofId'];raw,pin=pipe._read(directory/'proof.json',1048576);closure.need(pin==identity['proofPin'],'bridge_proof_changed');value=json.loads(raw);_valid_proof(value);return directory,value,pin

def status(root,identity):
 directory,proof,pin=_proof(Path(root).absolute(),identity)
 if not os.path.lexists(directory/'fence.json'):return {'state':'observed','resourceReleaseAllowed':False,'replayAllowed':False}
 if not os.path.lexists(directory/'terminal.json'):return {'state':'unknown','resourceReleaseAllowed':False,'replayAllowed':False}
 raw,terminal_pin=pipe._read(directory/'terminal.json');terminal=json.loads(raw)
 closure.need(type(terminal)is dict and set(terminal)=={'proofPin','fencePin','archivedClaimPin','resourceReleaseAllowed'} and terminal['proofPin']==pin and terminal['resourceReleaseAllowed']is False and terminal['fencePin']==pipe._read(directory/'fence.json')[1] and terminal['archivedClaimPin']==pipe._read(directory/'archived-claim')[1],'bridge_terminal_invalid')
 return {'state':'closed','correlationId':CORRELATION,'resourceReleaseAllowed':False,'replayAllowed':False}

def close(root,identity):
 root=Path(root).absolute();directory,proof,pin=_proof(root,identity)
 if status(root,identity)['state']!='observed':return status(root,identity)
 _proof_fresh(proof)
 with closure.claim_lock(root) as (parent,lock_guard),Directory(directory) as target:
  closure.need(status(root,identity)['state']=='observed','bridge_consumed')
  base=_base(root);closure.need(base==proof['base'],'bridge_local_changed')
  fresh=_fresh(root);closure.need(fresh['boot']==proof['fresh']['boot'] and fresh['pane']==proof['fresh']['pane'],'bridge_fresh_census_changed')
  _proof_fresh(proof)
  fence=pipe._write_once(directory/'fence.json',session.canonical({'proofPin':pin,'resourceReleaseAllowed':False}))
  def guard():
   lock_guard();target.guard();closure.need(_base(root)==base and pipe._read(directory/'proof.json',1048576)[1]==pin and pipe._read(directory/'fence.json')[1]==fence,'bridge_authority_changed')
  guard()
  _proof_fresh(proof)
  claim=base['local']['pins'][str((root/build._JOURNAL/'archlinux.claim').relative_to(root))]
  closure.need(claim['generation']==session.generation(os.stat('archlinux.claim',dir_fd=parent.fd,follow_symlinks=False)),'bridge_claim_changed')
  closure._rename(parent,'archlinux.claim',target,'archived-claim')
  archived=pipe._read(directory/'archived-claim')[1]
  closure.need(archived['sha256']==claim['sha256'] and all(archived['generation'][i]==claim['generation'][i] for i in (0,1,2,3,4,5,6,8)),'bridge_archive_changed')
  pipe._write_once(directory/'terminal.json',session.canonical({'proofPin':pin,'fencePin':fence,'archivedClaimPin':archived,'resourceReleaseAllowed':False}))
 return status(root,identity)
