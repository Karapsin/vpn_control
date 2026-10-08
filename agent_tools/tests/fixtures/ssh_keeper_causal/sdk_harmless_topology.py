"""Actual installed SDK process launcher, harmless controlled descendants only."""
import os,sys,json,subprocess,hashlib,time
from pathlib import Path
from agent_tools.ssh_channel_keeper_entry import actor
P=Path(sys.argv[2]);role=sys.argv[1]
from agent_tools.ssh_keeper_mcp_relay import actor as raw_actor
def save(name,value):
 fd=os.open(P/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,json.dumps(value).encode());os.fsync(fd)
 finally:os.close(fd)
def child(role):return subprocess.Popen([sys.executable,'-B',__file__,role,str(P)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if role=='keeper':
 save('keeper.json',actor());sys.stdin.buffer.read(1)
elif role in ('relay','server'):
 c=child('server' if role=='relay' else 'keeper')
 if role=='relay':save('server-intent.json',{'schema':1,'serverActor':raw_actor(c.pid),'relayActor':raw_actor(os.getpid()),'sourceSha256':json.loads((P/'request.json').read_bytes())['serverSHA'],'action':'serve','automaticReplay':False})
 sys.stdin.buffer.read(1);c.stdin.close();c.wait();c.stdout and c.stdout.close();c.stderr and c.stderr.close()
elif role=='sdk':
 import anyio
 from mcp.client.stdio import _create_platform_compatible_process
 async def run():
  with open(os.devnull,'wb') as null:
   c=await _create_platform_compatible_process(sys.executable,['-B',__file__,'relay',str(P)],dict(os.environ),null,None)
   value=json.loads((P/'request.json').read_bytes())
   save('client-intent.json',{'mode':'call_once','request':value['request'],'clientPid':os.getpid(),'sourceSha256':value['serverSHA'],'sdkVersion':'1.29.1','automaticReplay':False})
   await anyio.to_thread.run_sync(lambda:sys.stdin.buffer.read(1))
   await c.stdin.aclose();await c.wait();await c.aclose()
 anyio.run(run)
