"""Whole-before RED/GREEN for the managed creator status's Linux listener identity.

Linux /proc/net/unix prints the sun_path a socket was bound with verbatim. The
unix-address creator (6ad3dae7) binds credentials.sock through its held job
descriptor, /proc/self/fd/<d>/credentials.sock, but its status accepted only a
row at the canonical job pathname, so listenerReady stayed false on every Linux
HOST (Fast Checks run 40187427911). The actual status code of the committed
whole before and of the current creator runs over one synthetic kernel-format
/proc (socket:[inode] and job-directory descriptor links, /proc/net/unix rows)
with real private job records and a real socket node; on Linux it also runs over
the actual kernel. Synthetic input only: no connection, credential or VM effect.

The kernel ends a row only at a newline and prints a name's bytes verbatim, so a
local socket name can carry row text. A review of the first fix (39f54981, never
landed) found that its text splitlines() parse let such a row name a creator
socket that was not its live listener; the current join parses bytes, needs the
matched inode in exactly one row and re-reads the creator's descriptors after it.
"""
from contextlib import redirect_stdout
from pathlib import Path
import builtins,hashlib,io,json,os,pathlib,socket,subprocess,sys,tempfile,types,unittest
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_managed_create as NEW
FIXTURES=Path(__file__).parent/'fixtures/windows_managed_creator_listener_identity'
BEFORE='6ad3dae753c961c5576d76bc8a3f080a6ac79397c8d74d54423f800d222eda1c'
OP,OTHER='6b1f6a8e-2c39-5a7e-9d0b-4f3e21c7a915','9a4c0e52-7d13-5b86-a2f1-0c8e6d4b3a27'
OWNER,CREATOR,BIRTH,MACHINE=41000,41001,'linux:156243015','0123456789abcdef0123456789abcdef'
LISTENER,PEER,FOREIGN,SECOND='52817','52818','61234','52819'
EXPECTED={'operationId':OP,'binding':{'machine':MACHINE},'rootGeneration':[1,2]}
REFUSED='windows_managed_creator_observation_unresolved'
# Line ends for Python's str.splitlines() that never end a kernel row.
SPLITLINES=('\r','\x0b','\x0c','\x1c','\x1d','\x1e','\x85',' ',' ')
# Explicit controlled owner boundary: durable-job and original-owner authentication
# stay qualified by the native CredentialWireTests; this owns the listener decision.
OWNER_SOURCE=b"""class MachineBinding:
    def __init__(self,machine):self.machine=machine
    @classmethod
    def from_dict(cls,value):return cls(value['machine'])
def _binding_live(binding):pass
def _root(path,generation):pass
def observe(root,operation,binding,generation):return {'state':'running'}
"""
CHILD=("import os,socket,sys\nfd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n"
 "if sys.argv[2]=='listen':s=socket.socket(socket.AF_UNIX);s.bind('/proc/self/fd/'+str(fd)+'/credentials.sock');os.chmod(os.path.join(sys.argv[1],'credentials.sock'),0o600);s.listen(1)\n"
 "print('ready',fd,flush=True);sys.stdin.read()\n")
pin=lambda i:[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
structure=lambda i:[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid]
def before():
 path=FIXTURES/'managed_create_listener.before.source';raw=path.read_bytes()
 assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURES/'provenance.json').read_bytes())['files']['managed_create_listener.before.source']['sha256']==BEFORE
 module=types.ModuleType('agent_tools._owned_listener_identity_before');module.__package__='agent_tools';module.__file__=str(path);sys.modules[module.__name__]=module;exec(compile(raw,str(path),'exec'),module.__dict__);return module
OLD=before()
def row(inode,path=None,flags=0x10000,kind=1,state=1):
 """One /proc/net/unix line in the kernel's unix_seq_show format (%pK hidden)."""
 return '0000000000000000: %08X %08X %08X %04X %02X %5s'%(2,0,flags,kind,state,inode)+(''if path is None else ' '+path)
def carried(inode,path,separator='\n'):
 """A foreign abstract socket's row whose verbatim name (NUL as '@', at most 107 bytes) carries one row's text."""
 name='@x'+separator+row(inode,path);assert len(name.encode())<=108,name
 return row(FOREIGN,name)
def status(test,module,job,owner,proc=None,magic=None,read=None):
 """The actual whole status function; only pathlib('/proc...'), magic-link names and the owner boundary are controlled.

 read runs when the status names /proc/net/unix: for the current join between its
 two descriptor scans, for the before ahead of its single scan."""
 magic=magic or {};effects=[];imports,fake,system=builtins.__import__,types.ModuleType('pathlib'),types.ModuleType('os');fake.__dict__.update(vars(pathlib));system.__dict__.update(vars(os))
 def Path(*parts):
  text=str(pathlib.Path(*parts))
  if text=='/proc/net/unix'and read is not None:read();effects.append(text)
  return pathlib.Path(str(proc)+text[5:])if proc is not None and(text=='/proc'or text.startswith('/proc/'))else pathlib.Path(*parts)
 # A /proc descriptor link names its open file's path but resolves to the file itself.
 fake.Path=Path;system.readlink=lambda path,*args,**kwargs:magic[str(path)]if str(path)in magic else os.readlink(path,*args,**kwargs)
 authority=types.SimpleNamespace(_record=jobs._record,_private=jobs._private,_birth=jobs._birth if proc is None else lambda pid:BIRTH if pid==CREATOR else None)
 controlled={'pathlib':fake,'os':system}
 namespace={**vars(module),'__builtins__':{**vars(builtins),'__import__':lambda name,*args,**kwargs:controlled.get(name)or imports(name,*args,**kwargs)},
  'host_machine':lambda:MACHINE,'_creator_admission':lambda *args:{'operationId':OP},
  '_channel_identity':lambda *args,**kwargs:(authority,{},{'pid':owner},b'EXPLICIT_CONTROLLED_SOURCE_BOUNDARY')}
 entries=sorted(os.listdir(job))
 try:
  with redirect_stdout(io.StringIO())as output:types.FunctionType(module._creator_status.__code__,namespace)(str(job),EXPECTED,OWNER_SOURCE,'listener-vm','/never-created-vm')
 finally:sys.modules.pop('fixed_creator_status_owner',None)
 # Pure status: it never touches the socket and writes nothing; a read effect ran once and completed.
 test.assertEqual(sorted(os.listdir(job)),entries);test.assertEqual(len(effects),int(read is not None));return json.loads(output.getvalue())
def tree(test):
 directory=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());test.addCleanup(directory.cleanup)
 root=Path(directory.name);root.chmod(0o700);(root/'jobs').mkdir(mode=0o700);job=root/'jobs'/OP;job.mkdir(mode=0o700);return root,job
def publish(job,pid,birth,exe):
 jobs._publish(job/'creator-listener.json',{'operationId':OP,'actor':{'pid':pid,'birth':birth},'executableGeneration':pin(os.stat(exe)),'socketIdentity':structure(os.lstat(job/'credentials.sock'))})
class Host:
 """Real private job records and socket node; a kernel-format /proc for one creator process."""
 def __init__(self,test):
  self.test=test;self.root,self.job=tree(test);self.other=self.root/'jobs'/OTHER;self.other.mkdir(mode=0o700);self.endpoint=self.job/'credentials.sock';self.magic={};self.read=None
  with socket.socket(socket.AF_UNIX)as node:node.bind(str(self.endpoint))
  self.endpoint.chmod(0o600);self.proc=self.root/'proc';self.fd=self.proc/str(CREATOR)/'fd';self.fd.mkdir(parents=True);(self.proc/'net').mkdir()
  exe=self.root/'python3';exe.write_bytes(b'\x7fELF');(self.proc/str(CREATOR)/'exe').symlink_to(exe)
  (self.proc/str(CREATOR)/'stat').write_text('%d (python3) S %d %d %d 0 -1 4194560 1043 0 0 0 1 0 0 0 20 0 1 0 156243015 21037056 2460\n'%(CREATOR,OWNER,OWNER,OWNER))
  publish(self.job,CREATOR,BIRTH,exe)
  self.links({'0':'/dev/null','1':str(self.job/'stdout.bin'),'2':str(self.job/'stderr.bin'),'3':'socket:['+LISTENER+']','4':str(self.job),'5':'socket:['+PEER+']'})
 def links(self,values):
  for name in os.listdir(self.fd):os.unlink(self.fd/name)
  for name,target in values.items():os.symlink(target,self.fd/name)
 def unix(self,*rows):
  ambient=(row('18001','/run/systemd/journal/stdout'),row('18002','@/tmp/.X11-unix/X0'),row(PEER,flags=0,state=3))
  (self.proc/'net/unix').write_bytes(b'Num       RefCount Protocol Flags    Type St Inode Path\n'+b''.join((line if type(line)is bytes else line.encode())+b'\n'for line in ambient+rows))
 def status(self,module):
  # Each status meets the same descriptors, whatever its read closed.
  links={name:os.readlink(self.fd/name)for name in os.listdir(self.fd)}
  try:return status(self.test,module,self.job,OWNER,self.proc,self.magic,self.read)
  finally:self.links(links)
class ListenerIdentity(unittest.TestCase):
 def test_whole_before_red_current_green_for_the_creator_held_descriptor_listener(self):
  host=Host(self);host.unix(row(LISTENER,'/proc/self/fd/4/credentials.sock'))
  old,new=host.status(OLD),host.status(NEW)
  # RED: the kernel's verbatim held-descriptor sun_path never equals the canonical pathname.
  self.assertEqual((old['listenerReady'],old.get('reason'),old['status']),(False,REFUSED,{'state':'running'}),old)
  self.assertEqual((new['listenerReady'],new.get('reason'),new['status'],new['replayAllowed']),(True,None,{'state':'running'},False),new)
 def test_canonical_pathname_listener_stays_ready_in_both_so_the_red_is_the_held_descriptor(self):
  host=Host(self);host.unix(row(LISTENER,str(host.endpoint)))
  self.assertEqual([host.status(module)['listenerReady']for module in (OLD,NEW)],[True,True])
 def test_foreign_other_job_stale_replaced_and_nonlistening_sockets_are_never_ready(self):
  held='/proc/self/fd/4/credentials.sock'
  def foreign_held(host):host.unix(row(LISTENER,flags=0,state=3),row(FOREIGN,held))
  def foreign_canonical(host):host.unix(row(LISTENER,flags=0,state=3),row(FOREIGN,str(host.endpoint)))
  def unheld_listener(host):host.links({'0':'/dev/null','4':str(host.job)});host.unix(row(LISTENER,held))
  def other_job_directory(host):host.links({'3':'socket:['+LISTENER+']','4':str(host.other)});host.unix(row(LISTENER,held))
  def aliased_job_directory(host):alias=host.root/'alias';alias.symlink_to(host.job);host.links({'3':'socket:['+LISTENER+']','4':str(alias)});host.unix(row(LISTENER,held))
  # An overmounted job pathname: the held descriptor's kernel path names the job, its directory is another.
  def overmounted_job_path(host):host.links({'3':'socket:['+LISTENER+']','4':str(host.other)});host.magic[str(host.fd/'4')]=str(host.job);host.unix(row(LISTENER,held))
  def other_descriptor(host):host.unix(row(LISTENER,'/proc/self/fd/7/credentials.sock'))
  def stale_descriptor(host):host.links({'3':'socket:['+LISTENER+']','4':'/dev/null'});host.unix(row(LISTENER,held))
  def other_name(host):host.unix(row(LISTENER,'/proc/self/fd/4/credentials.sock.old'))
  def replaced_endpoint(host):
   replacement=host.job/'replacement.sock'
   with socket.socket(socket.AF_UNIX)as node:node.bind(str(replacement))
   replacement.chmod(0o600);os.replace(replacement,host.endpoint);host.unix(row(LISTENER,held))
  def bound_not_listening(host):host.unix(row(LISTENER,held,flags=0))
  def accepted_connection(host):host.unix(row(LISTENER,held,flags=0,state=3))
  def datagram(host):host.unix(row(LISTENER,held,kind=2))
  # Listening flags with St 04 (SS_DISCONNECTING), and a name whose last word is the held path.
  def listening_flags_other_state(host):host.unix(row(LISTENER,held,state=4))
  def whitespace_path(host):host.unix(row(LISTENER,'x '+held))
  def two_listeners(host):host.links({'3':'socket:['+LISTENER+']','4':str(host.job),'6':'socket:['+SECOND+']'});host.unix(row(LISTENER,held),row(SECOND,str(host.endpoint)))
  # A foreign name carrying a copy of the live listener's row after b'\n': two rows
  # share its inode, so the status cannot tell which one is the kernel's (fail-closed).
  def carried_live_listener_row(host):host.unix(row(LISTENER,held),carried(LISTENER,held))
  # Each is one mutation of the ready held-descriptor host. The before refused
  # every one too, except a second creator listener at the canonical pathname.
  for case,before in ((foreign_held,False),(foreign_canonical,False),(unheld_listener,False),(other_job_directory,False),(aliased_job_directory,False),(overmounted_job_path,False),(other_descriptor,False),(stale_descriptor,False),
   (other_name,False),(replaced_endpoint,False),(bound_not_listening,False),(accepted_connection,False),(datagram,False),(listening_flags_other_state,False),(whitespace_path,False),(two_listeners,True),(carried_live_listener_row,False)):
   with self.subTest(case.__name__):
    host=Host(self);case(host);old,new=host.status(OLD),host.status(NEW)
    self.assertEqual((new['listenerReady'],new.get('reason')),(False,REFUSED),new);self.assertEqual(old['listenerReady'],before,old)
 def test_rows_carried_in_foreign_names_or_closed_after_the_scan_never_join(self):
  held='/proc/self/fd/4/credentials.sock'
  # A foreign name carries a row naming the creator's connected socket (its own row
  # repeats that inode), split by b'\n' or only by Python's line ends; or the creator
  # closes its listener or job descriptor once the status names the table.
  cases=[('carried_peer_row'+(''if separator=='\n'else repr(separator)),carried(PEER,held,separator),None)for separator in('\n',)+SPLITLINES]
  cases+=[('closed_listener_carried_row',carried(LISTENER,held),'3'),('listener_closed_after_the_read',row(LISTENER,held),'3'),('job_descriptor_closed_after_the_read',row(LISTENER,held),'4')]
  # RED on the first fix, which trusted any one row of splitlines() and never re-read.
  for name,line,closed in cases:
   with self.subTest(name):
    host=Host(self);host.unix(line);host.read=closed and(lambda:os.unlink(host.fd/closed));old,new=host.status(OLD),host.status(NEW)
    self.assertEqual((new['listenerReady'],new.get('reason')),(False,REFUSED),new);self.assertFalse(old['listenerReady'],old)
 def test_other_rows_names_and_sockets_never_hide_the_live_listener(self):
  held='/proc/self/fd/4/credentials.sock'
  # Only b'\n' ends a kernel row: other line ends and undecodable bytes stay in their own
  # name. The text is process-relative, so a foreign creator of another job may print the
  # same held path; neither it nor another creator listener in the job is this listener.
  cases=[('carried'+repr(separator),carried(LISTENER,held,separator))for separator in SPLITLINES]+[('undecodable',row(FOREIGN).encode()+b' @x\xff\xfe'),
   ('foreign_same_text',row(FOREIGN,held)),('other_creator_listener',row(SECOND,held+'.old'))]
  for name,line in cases:
   with self.subTest(name):
    host=Host(self);os.symlink('socket:['+SECOND+']',host.fd/'6');host.unix(row(LISTENER,held),line);old,new=host.status(OLD),host.status(NEW)
    self.assertEqual((new['listenerReady'],new.get('reason')),(True,None),new);self.assertFalse(old['listenerReady'],old)
 @unittest.skipUnless(sys.platform.startswith('linux')and os.geteuid()>0,'actual Linux /proc/net/unix and descriptor links')
 def test_actual_linux_kernel_before_red_current_green_and_foreign_listener_never_ready(self):
  def child(job,mode):
   process=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(job),mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
   def stop():
    process.stdin.close()
    try:process.wait(5)
    except subprocess.TimeoutExpired:process.kill();process.wait(5)
    process.stdout.close()
   self.addCleanup(stop);ready=process.stdout.readline().split();self.assertEqual(ready[:1],['ready'],ready);return process,ready[1]
  _,job=tree(self);(creator,fd)=child(job,'listen');publish(job,creator.pid,jobs._birth(creator.pid),'/proc/%d/exe'%creator.pid)
  # The cause on the actual kernel: the creator's own socket row keeps the held-descriptor sun_path.
  inodes={os.readlink(link)[8:-1].encode()for link in Path('/proc/%d/fd'%creator.pid).iterdir()if os.readlink(link).startswith('socket:[')}
  rows=[text.split(None,7)for text in Path('/proc/net/unix').read_bytes().split(b'\n')[1:]];held='/proc/self/fd/'+fd+'/credentials.sock'
  found=[line for line in rows if len(line)==8 and line[6]in inodes and line[7].endswith(b'credentials.sock')];self.assertEqual([line[7]for line in found],[held.encode()],rows)
  old,new=status(self,OLD,job,os.getpid()),status(self,NEW,job,os.getpid())
  self.assertEqual((old['listenerReady'],old.get('reason')),(False,REFUSED),old);self.assertEqual((new['listenerReady'],new.get('reason')),(True,None),new)
  # The kernel prints a name verbatim: a foreign name carrying the listener's row after
  # b'\n' repeats its inode in a second row (refused); after a Python-only line end it is one row.
  for separator,ready in (('\n',False),('\x1c',True)):
   with self.subTest(separator=separator),socket.socket(socket.AF_UNIX)as carrier:
    name=(str(os.getpid())+separator+row(found[0][6].decode(),held)).encode();carrier.bind(b'\0'+name)
    self.assertIn(b' @'+name+b'\n',Path('/proc/net/unix').read_bytes())
    reply=status(self,NEW,job,os.getpid());self.assertEqual((reply['listenerReady'],reply.get('reason')),(ready,None if ready else REFUSED),reply)
  # A foreign process listens through its own held descriptor of the same job
  # directory; the named creator holds that directory but no socket at all.
  _,job=tree(self);child(job,'listen');holder,_=child(job,'hold');publish(job,holder.pid,jobs._birth(holder.pid),'/proc/%d/exe'%holder.pid)
  for module in (OLD,NEW):
   reply=status(self,module,job,os.getpid());self.assertEqual((reply['listenerReady'],reply.get('reason')),(False,REFUSED),(module.__name__,reply))
class Provenance(unittest.TestCase):
 def test_retained_whole_before_has_exact_custody_and_its_ci_failure(self):
  provenance=json.loads((FIXTURES/'provenance.json').read_bytes());self.assertFalse(provenance['nativeFailureClaimed'])
  self.assertEqual(provenance['files'],{'managed_create_listener.before.source':{'path':'agent_tools/readiness_windows_managed_create.py','sha256':BEFORE}})
  self.assertEqual(hashlib.sha256((FIXTURES/'managed_create_listener.before.source').read_bytes()).hexdigest(),BEFORE)
  failure=provenance['ciFailure'];self.assertEqual((failure['runId'],failure['jobId'],failure['headSha']),(40187427911,121151078435,'cc2873b5ed0ada7b09c24e854539c85660a627c2'))
  self.assertEqual(failure['publicTestId'],'agent_tools.tests.test_windows_managed_create.CredentialWireTests.test_fixed_generated_sender_original_owner_lost_ack_never_resends')
if __name__=='__main__':unittest.main()
