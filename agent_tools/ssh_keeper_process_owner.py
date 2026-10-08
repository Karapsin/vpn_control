"""Original subprocess/raw/terminal ownership; no kill, detach, or replay."""
from pathlib import Path
from contextlib import ExitStack
import hashlib,json,os,subprocess,time,uuid
from agent_tools import native_review_source_closure as closure
from agent_tools import ssh_channel_keeper_entry as entry
from agent_tools import private_inventory_lock as private
from agent_tools import ssh_channel_keeper as core
def save(path,value):entry.save(path,value)

def load(raw):return json.loads(raw,object_pairs_hook=closure._pairs)

def clean_environment(root):
 env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
 env['PYTHONPATH']=str(root);env['PYTHONDONTWRITEBYTECODE']='1';return env

class Owner:
 def __init__(self,root,output,guard,*,spawn=subprocess.Popen,clock=time.time,emit=lambda v:print(json.dumps(v,sort_keys=True),flush=True)):
  self.root=root;self.output=output;self.guard=guard;self.spawn=spawn;self.clock=clock;self.emit=emit;self.children=[]
 def start(self,role,args):
  self.guard();start=self.clock();out=self.output/(role+'.stdout.private');err=self.output/(role+'.stderr.private')
  of=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);ef=None
  try:
   ef=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   # Raw output setup can expose a late source change. Reclose the joined
   # source population immediately before the single original Popen.
   self.guard()
   p=self.spawn(args,stdout=of,stderr=ef,env=clean_environment(self.root),cwd=self.root)
  finally:
   if ef is not None:os.close(ef)
   os.close(of)
  self.children.append((role,p));actor=entry.actor(p.pid)
  save(self.output/(role+'.process.json'),{'localActor':actor,'prePopenStartEpoch':start,'automaticReplay':False})
  self.emit({'stage':role,'localActor':actor});return p,start,actor
 def finish(self,role,p):
  # Wait without replacing the original process. The parent stays alive even if
  # first-query validation failed. No timeout/kill/relaunch is supplied here.
  rc=p.wait();held=closure._Held()
  public=getattr(self.guard,'holder',getattr(self.guard,'__self__',None))
  holders=[held]+([public] if isinstance(public,closure._Held) else [])
  def record(name,value):
   path=self.output/name;body=json.dumps(value,sort_keys=True,separators=(',',':')).encode();digest=hashlib.sha256(body).hexdigest()
   fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=held.directory(str(path.parent)));held.fds.append(fd)
   at=0
   while at<len(body):
    n=os.write(fd,body[at:])
    if n<=0:raise OSError('record_write')
    at+=n
   os.fsync(fd);gen=closure.generation(os.fstat(fd))
   if os.pread(fd,len(body)+1,0)!=body:raise ValueError('record_readback')
   closure._pin({'generation':list(gen),'sha256':digest});os.fsync(held.directory(str(path.parent)))
   held.files[str(path)]=(fd,gen,digest,body);held.final_identity_pass()
  def joined():
   # ALL raw/source body work finishes before repeating ALL parent checks.
   held.finish();self.guard()
   for holder in holders:holder.final_identity_pass()
   # No body or parent observations follow this final pure ALL-leaf pass.
   for holder in holders:
    for path,(fd,generation,sha,raw)in holder.files.items():
     parent,name=os.path.split(path)
     if closure.generation(os.fstat(fd))!=generation or closure.generation(os.stat(name,dir_fd=holder.parents[parent][0],follow_symlinks=False))!=generation:raise ValueError('owner_joined_terminal_closing')
  try:
   record(role+'.terminal.json',{'returnCode':rc,'automaticReplay':False})
   bodies={}
   for stream in ('stdout','stderr'):
    path=self.output/(role+'.'+stream+'.private');info=os.lstat(path)
    if info.st_size>16777216:raise ValueError('owner_raw_cap')
    # Original fd/name/generation is retained through parsing and source closing.
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);raw=os.read(fd,16777217);os.close(fd)
    bodies[stream]=held.read(str(path),hashlib.sha256(raw).hexdigest(),closure.generation(info))
   joined()
   record(role+'.raw.json',{'returnCode':rc,'raw':{k:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}for k,v in bodies.items()},'originalProcessTerminal':True})
   if rc!=0:raise ValueError('original_child_nonzero')
   result=load(bodies['stdout']);joined();return result
  finally:held.close()
 def invoke(self,role,args):
  p,_,_=self.start(role,args);return self.finish(role,p)
 def wait_all(self):
  for role,p in self.children:
   if p.poll() is None:p.wait()
