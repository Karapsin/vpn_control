"""Finite sudo Python saved-file carriers; no credential is part of a plan.

An ordinary-account receiver stages source.  Only the caller's one admitted
execution invokes sudo.  Its root verifier captures checked source and creates a
root-owned, create-once execution claim before executing any original code.
"""
from __future__ import annotations

import base64
import zlib
import sys

_EXECUTING_CODE = sys._getframe().f_code


class PrivilegedProgramError(ValueError):
    pass


def split_prefix(prefix):
    """Recognize only repository sudo forms, never arbitrary privilege options."""
    prefix = tuple(prefix)
    if not prefix or prefix[0] not in ('sudo', '/usr/bin/sudo'):
        return None
    index = 1
    if index < len(prefix) and prefix[index] == '-k':
        index += 1
    if prefix[index:index + 1] == ('-n',):
        password = False
        index += 1
    elif prefix[index:index + 3] == ('-S', '-p', ''):
        password = True
        index += 3
    else:
        raise PrivilegedProgramError('automatic_privileged_command_form')
    if prefix[index:index + 1] == ('--',):
        index += 1
    sudo = prefix[:index]
    python = prefix[index:]
    if (not python or python[0] not in ('python3', '/usr/bin/python3') or
            any(flag not in ('-I', '-B', '-u') for flag in python[1:]) or
            len(set(python[1:])) != len(python[1:])):
        raise PrivilegedProgramError('automatic_privileged_command_form')
    return sudo, python, password


def program(command):
    """Return the same prefix/source/arguments shape as the ordinary parser."""
    command = tuple(command)
    if not command or command[0] not in ('sudo', '/usr/bin/sudo'):
        return None
    # Source is data even when it contains strings which resemble flags.
    try:
        index = command.index('-c')
    except ValueError:
        raise PrivilegedProgramError('automatic_privileged_command_form') from None
    split_prefix(command[:index])
    if index + 1 >= len(command):
        raise PrivilegedProgramError('automatic_privileged_command_form')
    return command[:index], command[index + 1].encode('utf-8', 'strict'), command[index + 2:]


def receiver_prefix(prefix):
    parsed = split_prefix(prefix)
    return parsed[1] if parsed else tuple(prefix)


_ROOT_LOADER = r'''
expected=json.loads(sys.argv[1]);arguments=sys.argv[2:];path=expected['directory'];before=identity()
uid=expected['identity']['uid'];principal=expected['identity']['principal']
if (before['uid']!=0 or os.getuid()!=0 or not isinstance(uid,int) or isinstance(uid,bool) or uid<=0
 or expected['identity']['boot']!=before['boot'] or os.environ.get('SUDO_UID')!=str(uid)
 or os.environ.get('SUDO_USER')!=principal or pwd.getpwuid(uid).pw_name!=principal):raise ValueError('automatic_privileged_identity')
if (len(path)>4096 or not path.endswith('/vpn-control-auto-'+expected['correlationId'])
 or len(expected['correlationId'])!=32 or any(c not in '0123456789abcdef' for c in expected['correlationId'])):raise ValueError('automatic_privileged_filename')
directory,parents=anchored(path)
claim_fds=[]
try:
 for fd in parents[:-1]:
  s=os.fstat(fd)
  if s.st_uid not in (0,uid) or s.st_mode&0o022 and not (s.st_uid==0 and s.st_mode&stat.S_ISVTX):raise ValueError('automatic_privileged_ancestry')
 ds=os.fstat(directory)
 if gen(ds)[:5]!=expected['directoryIdentity'] or ds.st_uid!=uid or stat.S_IMODE(ds.st_mode)!=0o700:raise ValueError('automatic_privileged_directory')
 f=os.open('program.source',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
 try:
  s=os.fstat(f)
  if (not stat.S_ISREG(s.st_mode) or s.st_uid!=uid or stat.S_IMODE(s.st_mode)!=0o600
   or s.st_nlink!=1 or gen(s)!=expected['generation'] or s.st_size!=expected['programBytes']
   or not 0<s.st_size<=8388608):raise ValueError('automatic_privileged_program_metadata')
  raw=bytearray();digest=hashlib.sha256()
  while len(raw)<s.st_size:
   part=os.read(f,min(65536,s.st_size-len(raw)))
   if not part:raise ValueError('automatic_privileged_source_short')
   raw.extend(part);digest.update(part)
  if (os.read(f,1) or digest.hexdigest()!=expected['programSha256'] or gen(os.fstat(f))!=gen(s)
   or gen(os.stat('program.source',dir_fd=directory,follow_symlinks=False))!=gen(s)):raise ValueError('automatic_privileged_source_changed')
  same_path(path,parents)
  if identity()!=before:raise ValueError('automatic_privileged_identity_changed')
  # A root-owned claim cannot be removed/replaced by the staging account.  No
  # existing claim is interpreted as permission to run, even after lost ACK.
  claim_parent=os.path.realpath('/var/tmp');parent,claim_fds=anchored(claim_parent)
  for fd in claim_fds:
   check=os.fstat(fd)
   if check.st_uid!=0 or check.st_mode&0o022 and not check.st_mode&stat.S_ISVTX:raise ValueError('automatic_privileged_claim_ancestry')
  leaf='vpn-control-auto-root-'+expected['correlationId']
  try:os.mkdir(leaf,0o700,dir_fd=parent)
  except FileExistsError:raise ValueError('automatic_privileged_execution_already_claimed') from None
  claim=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);claim_fds.append(claim)
  cs=os.fstat(claim)
  if cs.st_uid!=0 or stat.S_IMODE(cs.st_mode)!=0o700:raise ValueError('automatic_privileged_claim')
  create(claim,'execution-intent.json',json.dumps(expected,sort_keys=True,separators=(',',':')).encode())
  os.fsync(claim);os.fsync(parent)
  same_path(claim_parent,claim_fds[:-1]);same_path(path,parents)
  # The -S wrapper inserts a public frame.  With cached/NOPASSWD sudo the
  # unused secret line is discarded here; it never reaches original code.
  if os.environ.pop('VPN_CONTROL_AUTO_STDIN_FRAME',None) is not None:raise ValueError('automatic_privileged_environment')
  if __PASSWORD_FRAME__:
   header=('VPNCONTROL_AUTO_STDIN_V1 '+expected['correlationId']+'\n').encode('ascii')
   def line(limit):
    value=bytearray()
    while len(value)<=limit:
     part=os.read(sys.stdin.fileno(),1)
     if not part:raise ValueError('automatic_privileged_stdin_frame')
     value.extend(part)
     if part==b'\n':return value
    raise ValueError('automatic_privileged_stdin_frame')
   first=line(513)
   if first!=header:
    if not 1<len(first)<=513 or b'\0' in first or b'\r' in first:raise ValueError('automatic_privileged_stdin_frame')
    first.clear();first=line(128)
   if first!=header:raise ValueError('automatic_privileged_stdin_frame')
   first.clear()
  sys.argv=['-c',*arguments]
  scope={'__name__':'__main__','__package__':None,'__spec__':None,'__loader__':__loader__,'__doc__':None,'__builtins__':__builtins__}
  try:exec(compile(bytes(raw),path+'/program.source','exec'),scope)
  finally:
   if (gen(os.fstat(f))!=gen(s) or gen(os.stat('program.source',dir_fd=directory,follow_symlinks=False))!=gen(s)
    or identity()!=before):raise ValueError('automatic_privileged_closing_changed')
   same_path(path,parents)
 finally:os.close(f)
finally:
 for fd in reversed(claim_fds):os.close(fd)
 for fd in reversed(parents):os.close(fd)
'''


_PASSWORD_WRAPPER = r'''import json,os,select,subprocess,sys,threading,time
command=json.loads(sys.argv[1]);correlation=sys.argv[2]
secret=bytearray();credential=bytearray();deadline=time.monotonic()+__TIMEOUT__
def fail():raise ValueError('automatic_privileged_input_unknown')
try:
 while not secret.endswith(b'\n'):
  remaining=deadline-time.monotonic()
  if remaining<=0:fail()
  ready,_,_=select.select([sys.stdin.fileno()],[],[],min(.1,remaining))
  if not ready:continue
  part=os.read(sys.stdin.fileno(),1)
  if not part or len(secret)>=513:fail()
  secret.extend(part)
 if not 1<len(secret)<=513 or b'\0' in secret or b'\r' in secret:fail()
 credential.extend(secret[:-1])
 child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 errors=[]
 def send():
  payload=bytearray()
  try:
   payload.extend(secret);secret.clear();payload.extend(('VPNCONTROL_AUTO_STDIN_V1 '+correlation+'\n').encode('ascii'))
   view=memoryview(payload)
   while view:
    n=os.write(child.stdin.fileno(),view[:65536])
    if n<=0:fail()
    view=view[n:]
   view.release();payload.clear()
   while True:
    part=os.read(sys.stdin.fileno(),65536)
    if not part:break
    view=memoryview(part)
    while view:
     n=os.write(child.stdin.fileno(),view)
     if n<=0:fail()
     view=view[n:]
  except BaseException:errors.append(True)
  finally:
   payload.clear()
   try:child.stdin.close()
   except OSError:pass
 sender=threading.Thread(target=send,daemon=True);sender.start()
 # Do not expose raw sudo output.  Authentication failures and a misbehaving
 # sudo implementation may echo input.  Bound and redact before any release.
 streams={child.stdout:bytearray(),child.stderr:bytearray()};opened=list(streams);overflow=False;total=0
 while opened:
  ready,_,_=select.select(opened,[],[],.1)
  for stream in ready:
   part=os.read(stream.fileno(),65536)
   if not part:opened.remove(stream);continue
   total+=len(part)
   if total>8388608:overflow=True
   if not overflow:streams[stream].extend(part)
 code=child.wait()
 # The original caller owns execution timeout/cancellation.  This wrapper
 # never kills or repeats an admitted root program on disconnect or overflow.
 sender.join(timeout=1)
 if overflow or sender.is_alive() or errors:fail()
 for source,target in ((child.stdout,sys.stdout.buffer),(child.stderr,sys.stderr.buffer)):
  target.write(bytes(streams[source]).replace(bytes(credential),b'[REDACTED]'));target.flush()
 raise SystemExit(code)
finally:secret.clear();credential.clear()
'''



def loader(common, *, password):
    if type(password) is not bool:
        raise PrivilegedProgramError('automatic_privileged_command_form')
    return common + _ROOT_LOADER.replace('__PASSWORD_FRAME__', repr(password))


def _carrier(source):
    encoded = base64.b64encode(zlib.compress(source.encode(), 9)).decode()
    return "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(" + repr(encoded) + ")), '<automatic-privileged-transport>', 'exec'))"


def execution_command(prefix, root_loader, receipt_json, arguments, correlation, timeout):
    """Bind public code/metadata only; the credential remains caller stdin."""
    parsed = split_prefix(prefix)
    if parsed is None:
        raise PrivilegedProgramError('automatic_privileged_command_form')
    sudo, python, password = parsed
    command = (*sudo, *python, '-c', _carrier(root_loader), receipt_json, *arguments)
    if not password:
        return command
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise PrivilegedProgramError('automatic_privileged_timeout')
    import json
    wrapper = _PASSWORD_WRAPPER.replace('__TIMEOUT__', str(timeout))
    return (*python, '-c', _carrier(wrapper), json.dumps(command,separators=(',',':')), correlation)
