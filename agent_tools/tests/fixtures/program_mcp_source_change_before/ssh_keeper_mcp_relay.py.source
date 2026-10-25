"""Owned original stdio server: persist every byte before forwarding to SDK."""
import hashlib,json,os,selectors,stat,subprocess,sys,time
from pathlib import Path
from agent_tools.ssh_keeper_mcp_delivery import FrameObserver
ROOT=Path(__file__).resolve().parents[1]
def save(name,value):
 raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();fd=os.open(OUTPUT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  at=0
  while at<len(raw):at+=os.write(fd,raw[at:])
  os.fsync(fd)
 finally:os.close(fd)
def actor(pid):
 result=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=','-o','lstart='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,env={**os.environ,'LC_ALL':'C'},check=False)
 if result.returncode or result.stderr:raise ValueError('actor')
 return {'pid':pid,'uid':os.getuid(),'sessionId':os.getsid(pid),'birthSha256':hashlib.sha256(result.stdout).hexdigest()}
def main(output,expected):
 global OUTPUT,EXPECTED
 OUTPUT=Path(output);EXPECTED=expected
 server=ROOT/'agent_tools/mcp_server.py';python=ROOT/'.agent_venv/bin/python'
 if hashlib.sha256(server.read_bytes()).hexdigest()!=EXPECTED:raise ValueError('server_source_changed')
 logs={name:os.open(OUTPUT/('server.'+name),os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600) for name in ('stdin','stdout','stderr')};counts={name:0 for name in logs};eof={'stdout':False,'stderr':False};flags={'overflow':False,'readError':False};fds={};proc=None;delivery=FrameObserver()
 try:
  proc=subprocess.Popen([str(python),'-B',str(server),'serve'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=ROOT,env={k:v for k,v in os.environ.items() if k!='DYLD_INSERT_LIBRARIES'})
  save('server-intent.json',{'schema':1,'serverActor':actor(proc.pid),'relayActor':actor(os.getpid()),'sourceSha256':EXPECTED,'action':'serve','automaticReplay':False})
  selector=selectors.DefaultSelector();selector.register(sys.stdin.buffer,selectors.EVENT_READ,'stdin');selector.register(proc.stdout,selectors.EVENT_READ,'stdout');selector.register(proc.stderr,selectors.EVENT_READ,'stderr')
  with selector:
   while selector.get_map():
    for key,_ in selector.select(1):
     name=key.data;raw=os.read(key.fileobj.fileno(),65536)
     if not raw:
      selector.unregister(key.fileobj)
      if name=='stdin':proc.stdin.close()
      else:eof[name]=True
      continue
     if counts[name]+len(raw)>16777216:flags['overflow']=True;raise ValueError('stream_cap')
     at=0
     while at<len(raw):at+=os.write(logs[name],raw[at:])
     counts[name]+=len(raw);os.fsync(logs[name])
     # Only forward after original bytes are durable; SDK has not parsed them yet.
     destination=proc.stdin.fileno() if name=='stdin' else 1 if name=='stdout' else 2
     at=0
     while at<len(raw):at+=os.write(destination,raw[at:])
     if name=='stdin':
      for event in delivery.add(raw,at):save('delivery-%04d.json'%event['frameOrdinal'],event)
    if proc.poll() is not None and eof['stdout'] and eof['stderr']:
     for key in list(selector.get_map().values()):selector.unregister(key.fileobj)
  rc=proc.wait(timeout=2);manifest={}
  for name,fd in logs.items():
   os.fsync(fd);info=os.fstat(fd)
   if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError('raw_shape')
   body=os.pread(fd,16777217,0)
   if len(body)!=counts[name]:raise ValueError('raw_count')
   generation=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   pin=generation(info)
   if generation(os.stat(OUTPUT/('server.'+name),follow_symlinks=False))!=pin or generation(os.fstat(fd))!=pin:raise ValueError('raw_closing')
   manifest[name]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'generation':list(pin)}
  if hashlib.sha256(server.read_bytes()).hexdigest()!=EXPECTED:raise ValueError('server_source_changed')
  save('server-terminal.json',{'returnCode':rc,'eof':eof,**flags,'complete':all(eof.values()) and not any(flags.values()),'raw':manifest,'delivery':delivery.summary(),'automaticReplay':False})
 finally:
  for fd in logs.values():os.close(fd)
  if proc is not None:
   for stream in (proc.stdin,proc.stdout,proc.stderr):stream.close()

if __name__=='__main__':main(*sys.argv[1:])
