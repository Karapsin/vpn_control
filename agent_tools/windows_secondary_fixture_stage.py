"""Secondary Windows base fixture staging; no automatic SSH or guest actions.

The receiver is the directly proven finite host boundary. A reviewed caller must
admit the source-matched registry artifact and exact configured SSH route before
using the generated source or input-FD client. Guest transfer and installers are
outside this module.
"""
from __future__ import annotations
import hashlib,json,os,re,selectors,subprocess,time,uuid
from agent_tools import windows_parallel_vm_prepare_transport as transport
STDERR_LIMIT=8192
_RECEIVER = r'''from pathlib import Path
import os,stat,sys,hashlib,json
ROOT='/home/kardinal/vpn-control-secondary-base-input-1502d4fc-afd4-4322-bc98-75880be02d78'
SIZE=131101044
SHA='539504d691d396745d8426551e12107475281f3b189f75f3f802c5476920d1cd'
p=Path(ROOT);home=p.parent;st=home.lstat()
if os.geteuid()!=1000 or str(home)!='/home/kardinal' or not stat.S_ISDIR(st.st_mode) or st.st_uid!=1000 or st.st_mode&0o022 or os.path.realpath(home)!=str(home):raise ValueError('host-input-parent')
def identity(st):return [st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid]
def gen(st):return identity(st)+[st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
ancestors=[(q,identity(q.lstat())) for q in [home,*home.parents]]
if any(not stat.S_ISDIR(pin[2]) or pin[2]&0o022 for _,pin in ancestors):raise ValueError('host-input-ancestry')
parent=os.open(home,os.O_DIRECTORY|os.O_NOFOLLOW);directory=None;fd=None;count=0;h=hashlib.sha256();state='UNKNOWN';reason=None
try:
 if identity(os.fstat(parent))!=identity(st):raise ValueError('host-input-parent-fd')
 os.mkdir(p.name,0o700,dir_fd=parent);directory=os.open(p.name,os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);root_identity=identity(os.fstat(directory))
 def roots():
  if identity(os.fstat(parent))!=identity(st) or identity(home.lstat())!=identity(st):raise ValueError('host-input-parent-name')
  if identity(os.fstat(directory))!=root_identity or identity(os.stat(p.name,dir_fd=parent,follow_symlinks=False))!=root_identity:raise ValueError('host-input-root-name')
  if any(identity(q.lstat())!=pin for q,pin in ancestors):raise ValueError('host-input-ancestry-closing')
 roots();fd=os.open('base.msi',os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_RDWR,0o600,dir_fd=directory)
 while count<SIZE:
  block=sys.stdin.buffer.read(min(1048576,SIZE-count))
  if not block:raise ValueError('host-input-short')
  offset=0
  while offset<len(block):
   n=os.write(fd,block[offset:])
   if n<=0:raise ValueError('host-input-write')
   offset+=n
  h.update(block);count+=len(block)
 if sys.stdin.buffer.read(1):raise ValueError('host-input-extra')
 os.fsync(fd);roots();frozen=gen(os.fstat(fd));root_generation=gen(os.fstat(directory));named=gen(os.stat('base.msi',dir_fd=directory,follow_symlinks=False))
 if frozen!=named or frozen[5]!=1 or frozen[6]!=SIZE or h.hexdigest()!=SHA:raise ValueError('host-input-fullsha')
 os.lseek(fd,0,0);readback=hashlib.sha256()
 while True:
  block=os.read(fd,1048576)
  if not block:break
  readback.update(block)
 roots()
 if readback.hexdigest()!=SHA or gen(os.fstat(fd))!=frozen or gen(os.stat('base.msi',dir_fd=directory,follow_symlinks=False))!=frozen or gen(os.fstat(directory))!=root_generation:raise ValueError('host-input-readback-generation')
 result={'state':'HOST_INPUT_STAGED','path':str(p/'base.msi'),'length':count,'sha256':h.hexdigest(),'fileGeneration':frozen,'rootIdentity':root_identity,'guestEffect':False,'installerStarted':False,'replayAllowed':False}
 roots()
 if gen(os.fstat(fd))!=frozen or gen(os.stat('base.msi',dir_fd=directory,follow_symlinks=False))!=frozen or gen(os.fstat(directory))!=root_generation:raise ValueError('host-input-publication-generation')
 print(json.dumps(result,sort_keys=True),flush=True);state='HOST_INPUT_STAGED'
except Exception as error:
 reason=str(error) if isinstance(error,ValueError) else type(error).__name__
 print(json.dumps({'state':'UNKNOWN','reason':reason,'path':str(p/'base.msi'),'length':count,'sha256':h.hexdigest(),'guestEffect':False,'installerStarted':False,'replayAllowed':False},sort_keys=True),flush=True)
 raise
finally:
 if fd is not None:os.close(fd)
 if directory is not None:os.close(directory)
 os.close(parent)
'''

def secondary_base_host_input_program(correlation: str, expected_sha256: str, expected_size: int) -> str:
    """Fixed ordinary Arch receiver for one uniquely owned secondary base MSI."""
    if not isinstance(correlation,str) or str(uuid.UUID(correlation))!=correlation:
        raise ValueError('secondary-stage-correlation')
    if not isinstance(expected_sha256,str) or not re.fullmatch(r'[0-9a-f]{64}',expected_sha256):
        raise ValueError('secondary-stage-sha256')
    if type(expected_size) is not int or not 0<expected_size<=1073741824:
        raise ValueError('secondary-stage-size')
    rows=_RECEIVER.splitlines(keepends=True)
    for i,row in enumerate(rows):
        if row.startswith('ROOT='): rows[i]='ROOT='+repr('/home/kardinal/vpn-control-secondary-base-input-'+correlation)+'\n'
        elif row.startswith('SIZE='): rows[i]='SIZE='+str(expected_size)+'\n'
        elif row.startswith('SHA='): rows[i]='SHA='+repr(expected_sha256)+'\n'
    return ''.join(rows)

class SecondaryFixtureInputClient(transport.RetainedClient):

    def __init__(self, argv, input_fd, capture):
        self.stderr_fd = os.open('transport.stderr.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=capture.fd)
        self.stderr_raw = bytearray()
        self.stderr_bytes = 0
        self.stderr_eof = False
        self.capture = capture
        self.raw_fd = os.open('transport.stdout.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=capture.fd)
        self.raw = bytearray()
        self.eof = False
        self.child = None
        self.selector = None
        self.initialization_unknown = False
        self.fallback_readiness = False
        self.child = subprocess.Popen(argv, stdin=input_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
            self.selector.register(self.child.stderr, selectors.EVENT_READ)
        except BaseException as error:
            self.initialization_unknown = True
            self.fallback_readiness = True
            raise transport.ClientUnknown('client-initialization-unknown', self) from error

    def _verify_stderr(self):
        """Authenticate original retained bytes and their persisted filename."""
        from agent_tools import windows_parallel_vm_source_inventory as inventory
        import stat
        try:
            before = inventory.generation(os.fstat(self.stderr_fd))
            named = inventory.generation(os.stat('transport.stderr.private', dir_fd=self.capture.fd, follow_symlinks=False))
            transport.need(before == named and stat.S_ISREG(before[2]) and before[3] == os.getuid() and stat.S_IMODE(before[2]) == 0o600 and before[5] == 1 and before[6] == len(self.stderr_raw), 'secondary-stage-stderr-identity')
            os.lseek(self.stderr_fd, 0, os.SEEK_SET)
            observed = bytearray()
            while len(observed) <= len(self.stderr_raw):
                block = os.read(self.stderr_fd, min(4096, len(self.stderr_raw) + 1 - len(observed)))
                if not block:
                    break
                observed.extend(block)
            transport.need(bytes(observed) == bytes(self.stderr_raw) and hashlib.sha256(observed).hexdigest() == hashlib.sha256(self.stderr_raw).hexdigest(), 'secondary-stage-stderr-bytes')
            transport.need(inventory.generation(os.fstat(self.stderr_fd)) == before and inventory.generation(os.stat('transport.stderr.private', dir_fd=self.capture.fd, follow_symlinks=False)) == before, 'secondary-stage-stderr-closing')
            return {'generation': before, 'sha256': hashlib.sha256(observed).hexdigest()}
        except (OSError, ValueError, TypeError) as error:
            raise transport.ClientUnknown('secondary-stage-stderr-custody', self) from error

    def _stderr_block(self):
        block = os.read(self.child.stderr.fileno(), 4096)
        if not block:
            self.stderr_eof = True
            if self.selector is not None:
                try:
                    self.selector.unregister(self.child.stderr)
                except KeyError:
                    pass
            return
        self.stderr_bytes += len(block)
        retain = block[:max(0, STDERR_LIMIT + 1 - len(self.stderr_raw))]
        self.stderr_raw.extend(retain)
        offset = 0
        while offset < len(retain):
            n = os.write(self.stderr_fd, retain[offset:])
            transport.need(n > 0, 'diagnostic-stderr-write')
            offset += n
        os.fsync(self.stderr_fd)

    def ready(self, remaining):
        if self.fallback_readiness:
            import select
            pipes = [self.child.stdout] + ([] if self.stderr_eof else [self.child.stderr])
            ready, _, _ = select.select(pipes, [], [], remaining)
        else:
            ready = [key.fileobj for key, _ in self.selector.select(remaining)]
        result = []
        for pipe in ready:
            if pipe is self.child.stderr:
                self._stderr_block()
            else:
                result.append(pipe)
        return result

    def observe(self, seconds):
        import time
        deadline = time.monotonic() + seconds
        error = None
        try:
            super().observe(seconds)
        except transport.ClientUnknown as e:
            error = e
        if self.eof and self.child.poll() is not None:
            while not self.stderr_eof and time.monotonic() < deadline:
                self.ready(min(0.1, max(0, deadline - time.monotonic())))
        self._verify_stderr()
        self.capture.create('stderr-observation-' + __import__('uuid').uuid4().hex + '.json', json.dumps(self.stderr_observation(), sort_keys=True).encode())
        if error is not None:
            raise error
        if not self.stderr_eof:
            raise transport.ClientUnknown('diagnostic-stderr-eof-unknown', self)

    def stderr_observation(self):
        pin = self._verify_stderr()
        return {'rawGeneration': pin['generation'],'originalPid': None if self.child is None else self.child.pid, 'stdoutEof': self.eof, 'stderrEof': self.stderr_eof, 'exitCode': None if self.child is None else self.child.poll(), 'outputBytes': self.stderr_bytes, 'retainedBytes': len(self.stderr_raw), 'overflow': self.stderr_bytes > STDERR_LIMIT, 'rawSha256': hashlib.sha256(self.stderr_raw).hexdigest(), 'productAcceptance': False, 'replayAllowed': False}

    def close_terminal(self):
        transport.need(self.eof and self.stderr_eof and (self.child.poll() is not None), 'diagnostic-original-not-terminal')
        self._verify_stderr()
        self.child.stderr.close()
        os.close(self.stderr_fd)
        super().close_terminal()
