"""One-shot host metadata archive for the fixed completed CP117 c32 baseline."""
from __future__ import annotations

try:
    import fcntl
except ImportError:  # Windows can discover the module, but cannot dispatch it.
    fcntl = None
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

def _supported() -> bool:
    return (fcntl is not None and callable(getattr(os, 'getuid', None))
            and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'))


if _supported():
    from . import windows_msi_base_prepare as base
    from . import windows_cp117_c32_archive_admission as admission
    from . import windows_cp117_c32_absence as absence
else:
    # These host-only dependencies also import POSIX APIs. Defer them on an
    # unsupported client, before a journal or remote observation can be created.
    base = admission = absence = None

_C32 = 'c32cb108-4d48-407e-9153-40774559ba50'
_LEASE = '67eeeedb-a618-42d5-8e31-821650d16302'
_DIR = '.rag_index/windows-cp117-c32-host-archive'
_UNKNOWN = {'state': 'unknown', 'replayAllowed': False,
            'nativeActionAllowed': False, 'productAction': False}

# Only metadata is moved. The read-only status executes the same admission and
# fd validation, but never creates a lock, directory, or chmods historical files.
_REMOTE_BODY = r'''import ctypes,fcntl,json,os,stat,sys
root,env,corr,text,operation=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def directory(p):
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 return i
def same(a,b):return (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
def unique(pairs):
 value={}
 for key,item in pairs:
  if key in value:raise ValueError()
  value[key]=item
 return value
def load(raw):return json.loads(raw,object_pairs_hook=unique)
def metadata(p,modes):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  i=os.fstat(fd)
  if not same(i,os.lstat(p)) or not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode) not in modes or not 0<i.st_size<=8192:raise ValueError()
  raw=os.read(fd,8193)
  if len(raw)!=i.st_size or len(raw)>8192:raise ValueError()
  value=load(raw)
  return fd,i,value
 except Exception:os.close(fd);raise
def sync(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def bound_leaf(p,modes):
 di=directory(p)
 if set(os.listdir(p))!={'binding.json','dispatch.json'}:raise ValueError()
 files=[]
 try:
  for name in ('binding.json','dispatch.json'):files.append(metadata(os.path.join(p,name),modes))
  if files[0][2]!=expected:raise ValueError()
  dispatch=files[1][2]
  if not isinstance(dispatch,dict) or set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
  return di,files
 except Exception:
  for fd,_,_ in files:os.close(fd)
  raise
def unchanged(p,di,files,modes):
 if not same(di,directory(p)) or set(os.listdir(p))!={'binding.json','dispatch.json'}:raise ValueError()
 for name,(fd,i,value) in zip(('binding.json','dispatch.json'),files):
  now=os.fstat(fd)
  if not same(i,now) or not same(now,os.lstat(os.path.join(p,name))) or now.st_uid!=os.geteuid() or stat.S_IMODE(now.st_mode) not in modes:raise ValueError()
  os.lseek(fd,0,0)
  if load(os.read(fd,8193))!=value:raise ValueError()
lock=None;files=[]
try:
 if env!='windows-cp117' or corr!='c32cb108-4d48-407e-9153-40774559ba50' or operation not in {'archive','status'} or not os.path.isabs(root) or os.path.normpath(root)!=root:raise ValueError()
 expected=load(text)
 if not isinstance(expected,dict) or set(expected)!={'socketPath','pid','startTicks','sourceSha','sourceFingerprint','receiptArtifactId','baseArtifactId','targetArtifactId','commandSha256','expectedSid'}:raise ValueError()
 if type(expected['pid']) is not int or expected['pid']<=0 or type(expected['startTicks']) is not int or expected['startTicks']<=0 or not live(expected['socketPath'],str(expected['pid']),str(expected['startTicks'])):raise ValueError()
 parent=os.path.join(root,env);group=os.path.join(parent,'windows-msi-base');src=os.path.join(group,corr);history=os.path.join(parent,'windows-msi-base-history');dst=os.path.join(history,corr)
 parents=[(p,directory(p)) for p in (root,parent,group)]
 lockpath=os.path.join(group,'.environment.lock')
 lock=os.open(lockpath,os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT if operation=='archive' else 0),0o600)
 li=os.fstat(lock)
 if not stat.S_ISREG(li.st_mode) or li.st_uid!=os.geteuid() or stat.S_IMODE(li.st_mode)!=0o600 or not same(li,os.lstat(lockpath)):raise ValueError()
 fcntl.flock(lock,fcntl.LOCK_EX)
 if not same(li,os.lstat(lockpath)):raise ValueError()
 if operation=='status':
  if os.path.lexists(src):raise ValueError()
  directory(history);di,files=bound_leaf(dst,{0o600});unchanged(dst,di,files,{0o600})
 else:
  if set(os.listdir(group))!={'.environment.lock',corr} or os.path.lexists(dst):raise ValueError()
  if os.path.lexists(history):directory(history)
  di,files=bound_leaf(src,{0o600,0o644});unchanged(src,di,files,{0o600,0o644})
  for p,i in parents:
   if not same(i,directory(p)):raise ValueError()
  # Obtain the Linux exclusive rename before altering metadata or creating history.
  libc=ctypes.CDLL(None,use_errno=True);rename=libc.renameat2
  rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
  for fd,_,_ in files:os.fchmod(fd,0o600);os.fsync(fd)
  unchanged(src,di,files,{0o600})
  if not os.path.lexists(history):os.mkdir(history,0o700);sync(parent)
  hi=directory(history)
  unchanged(src,di,files,{0o600})
  if not same(hi,directory(history)) or not live(expected['socketPath'],str(expected['pid']),str(expected['startTicks'])):raise ValueError()
  if rename(-100,os.fsencode(src),-100,os.fsencode(dst),1)!=0:raise OSError(ctypes.get_errno(),'exclusive archive rename failed')
  sync(group);sync(history)
  if os.path.lexists(src):raise ValueError()
  unchanged(dst,di,files,{0o600})
 for p,i in parents:
  if not same(i,directory(p)):raise ValueError()
 if not live(expected['socketPath'],str(expected['pid']),str(expected['startTicks'])):raise ValueError()
 out({'state':'archived'})
except Exception:out({'state':'unknown'})
finally:
 for fd,_,_ in files:os.close(fd)
 if lock is not None:os.close(lock)
'''
_REMOTE = (base._QGA if base is not None else '') + _REMOTE_BODY


# An inert component probe: paths exist only beneath TemporaryDirectory, and
# live() is replaced only in these test child interpreters. No QGA code is sent.
_SELF_TEST = 'BODY=' + repr(_REMOTE_BODY) + '\n' + r'''import ctypes,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
cases={'exclusive-rename':'unknown','destination-race':'unknown'}
def out(state):print(json.dumps({'state':state,'cases':cases},separators=(',',':'),sort_keys=True))
def tree(root):
 env=root/'windows-cp117';group=env/'windows-msi-base';leaf=group/'c32cb108-4d48-407e-9153-40774559ba50'
 for p in (root,env,group,leaf):p.mkdir(exist_ok=True);p.chmod(0o700)
 lock=group/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o600)
 binding={'socketPath':'/inert-test-only.sock','pid':42,'startTicks':1234,'sourceSha':'a'*40,'sourceFingerprint':'b'*64,'receiptArtifactId':'sha256-'+'c'*64,'baseArtifactId':'sha256-'+'d'*64,'targetArtifactId':'sha256-'+'e'*64,'commandSha256':'f'*64,'expectedSid':'S-1-5-21-1'}
 (leaf/'binding.json').write_text(json.dumps(binding));(leaf/'dispatch.json').write_text('{"pid":1}')
 for p in leaf.iterdir():p.chmod(0o644)
 dst=env/'windows-msi-base-history'/leaf.name
 return leaf,dst,binding
def execute(root,binding,prefix=''):
 program='def live(sock,pid,ticks):return True\n'+prefix+BODY
 result=subprocess.run([sys.executable,'-I','-B','-c',program,str(root),'windows-cp117','c32cb108-4d48-407e-9153-40774559ba50',json.dumps(binding),'archive'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
 if result.returncode!=0 or result.stderr or not 0<len(result.stdout)<=1024:raise ValueError()
 value=json.loads(result.stdout)
 if value not in ({'state':'archived'},{'state':'unknown'}):raise ValueError()
 return value
try:
 if len(sys.argv)!=1 or not sys.platform.startswith('linux'):raise ValueError()
 with tempfile.TemporaryDirectory(prefix='vpn-control-c32-rename-self-test-') as tmp:
  root=Path(tmp);leaf,dst,binding=tree(root);before={p.name:p.read_bytes() for p in leaf.iterdir()}
  passed=(execute(root,binding)=={'state':'archived'} and not os.path.lexists(leaf) and dst.is_dir()
   and before=={p.name:p.read_bytes() for p in dst.iterdir()} and stat.S_IMODE(dst.stat().st_mode)==0o700
   and all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in dst.iterdir()))
  cases['exclusive-rename']='passed' if passed else 'failed'
 with tempfile.TemporaryDirectory(prefix='vpn-control-c32-rename-self-test-') as tmp:
  root=Path(tmp);leaf,dst,binding=tree(root);before={p.name:p.read_bytes() for p in leaf.iterdir()}
  prefix="""import ctypes,os
original=ctypes.CDLL
class Rename:
 def __init__(self,fn):self.fn=fn
 def __call__(self,a,src,b,dst,flag):
  os.mkdir(os.fsdecode(dst),0o700)
  inode=os.lstat(os.fsdecode(dst)).st_ino
  with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.fsdecode(dst)))),'race-inode'),'w') as f:f.write(str(inode))
  return self.fn(a,src,b,dst,flag)
class Library:
 def __init__(self,*a,**kw):self.renameat2=Rename(original(*a,**kw).renameat2)
ctypes.CDLL=Library
"""
  result=execute(root,binding,prefix)
  passed=(result=={'state':'unknown'} and leaf.is_dir() and dst.is_dir() and list(dst.iterdir())==[]
   and dst.stat().st_ino==int((root/'race-inode').read_text()) and before=={p.name:p.read_bytes() for p in leaf.iterdir()})
  cases['destination-race']='passed' if passed else 'failed'
 out('passed' if all(v=='passed' for v in cases.values()) else 'failed')
except Exception:out('unknown')
'''


def _uid() -> int:
    if not _supported():
        raise ValueError('archive requires local POSIX ownership and locking APIs')
    return os.getuid()


def _directory(path: Path) -> None:
    uid = _uid()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('unsafe archive journal')


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate archive metadata field')
        value[key] = item
    return value


def _read(path: Path) -> dict[str, Any]:
    uid = _uid()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 8192
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError('unsafe archive intent')
        raw = stream.read(8193)
        if len(raw) != info.st_size:
            raise ValueError('changed archive intent')
        value = json.loads(raw, object_pairs_hook=_unique)
    if not isinstance(value, dict):
        raise ValueError('invalid archive intent')
    return value


@contextmanager
def _reservation(root: Path):
    uid = _uid()
    parent = root / '.rag_index'
    parent.mkdir(mode=0o700, exist_ok=True)
    _directory(parent)
    directory = root / _DIR
    directory.mkdir(mode=0o700, exist_ok=True)
    _directory(directory)
    lockpath = directory / '.environment.lock'
    fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (lockpath.lstat().st_dev, lockpath.lstat().st_ino)):
            raise ValueError('unsafe archive lock')
        fcntl.flock(fd, fcntl.LOCK_EX)
        _directory(parent); _directory(directory)
        yield directory
    finally:
        os.close(fd)


def _intent(root: Path, binding: Mapping[str, Any]) -> Path:
    with _reservation(root) as directory:
        path = directory / 'intent.json'
        raw = json.dumps({'correlationId': _C32, 'binding': binding},
                         sort_keys=True, separators=(',', ':')).encode()
        if len(raw) > 8192:
            raise ValueError('oversized archive intent')
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        _sync(directory); _sync(directory.parent); _sync(root)
        return path


def _binding(root: Path, descriptor: tuple[Any, ...]) -> dict[str, Any]:
    if (not isinstance(descriptor, tuple) or len(descriptor) != 5
            or descriptor[0] != 'windows-cp117'
            or not isinstance(descriptor[1], str) or not descriptor[1].startswith('/')
            or type(descriptor[2]) is not int or descriptor[2] <= 0
            or type(descriptor[3]) is not int or descriptor[3] <= 0
            or not isinstance(descriptor[4], str)):
        raise ValueError('invalid historical generation')
    intent = base._private_intent(root, _C32)
    if (not isinstance(intent, dict) or intent.get('leaseId') != _C32
            or (intent.get('environment'), intent.get('socketPath'), intent.get('pid'),
                intent.get('startTicks'), intent.get('expectedSid')) != descriptor
            or intent['request']['correlationId'] != _C32):
        raise ValueError('changed historical generation')
    request, pair = intent['request'], intent['pair']
    return {'socketPath': descriptor[1], 'pid': descriptor[2], 'startTicks': descriptor[3],
            'sourceSha': request['sourceSha'], 'sourceFingerprint': pair['sourceFingerprint'],
            'receiptArtifactId': request['fixtureReceiptArtifactId'],
            'baseArtifactId': request['baseMsiArtifactId'],
            'targetArtifactId': request['targetMsiArtifactId'],
            'commandSha256': intent['commandSha256'], 'expectedSid': descriptor[4]}


def _proof(config: Any, target: Any, descriptor: tuple[Any, ...], binding: dict[str, Any], operation: str) -> bool:
    raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), descriptor[0], _C32,
                       json.dumps(binding, sort_keys=True, separators=(',', ':')), operation), None, 30)
    if not isinstance(raw, (str, bytes)) or not 0 < len(raw) <= 1024:
        return False
    return json.loads(raw, object_pairs_hook=_unique) == {'state': 'archived'}


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value != {}:
        raise ValueError('fixed archive takes no inputs')
    if not _supported() or base is None:
        return dict(_UNKNOWN)
    path = Path(root).resolve(strict=True)
    try:
        gate = admission.preflight(path, {'leaseId': _LEASE})
        if (gate.get('state') != 'ready' or gate.get('hostBaseStage') != 'retained'
                or any(gate.get(k) is not False for k in ('replayAllowed', 'nativeActionAllowed', 'productAction'))):
            return {**_UNKNOWN, 'state': 'blocked'}
        config, target, descriptor = base._descriptor(path)
        census = absence.observe(path, config, target, descriptor)
        if (census.get('state') != 'observed' or census.get('baseTask') != 'present'
                or census.get('guestLeaf') != 'present'
                or any(census.get(k) != 'absent' for k in ('transferTask', 'baseMsi', 'correlationProcess'))
                or absence.retained_terminal(path, config, target, descriptor).get('state') != 'retained-terminal'):
            return {**_UNKNOWN, 'state': 'blocked'}
        binding = _binding(path, descriptor)
        _intent(path, binding)
        return {**_UNKNOWN, 'state': 'archived'} if _proof(config, target, descriptor, binding, 'archive') else dict(_UNKNOWN)
    except (OSError, ValueError, KeyError, TypeError):
        return dict(_UNKNOWN)


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value != {}:
        raise ValueError('fixed archive takes no inputs')
    if not _supported() or base is None:
        return dict(_UNKNOWN)
    path = Path(root).resolve(strict=True)
    try:
        directory = path / _DIR
        if not os.path.lexists(directory):
            return {**_UNKNOWN, 'state': 'not-started'}
        _directory(directory.parent); _directory(directory)
        record = _read(directory / 'intent.json')
        config, target, descriptor = base._descriptor(path)
        binding = _binding(path, descriptor)
        if record != {'correlationId': _C32, 'binding': binding}:
            return dict(_UNKNOWN)
        return {**_UNKNOWN, 'state': 'archived'} if _proof(config, target, descriptor, binding, 'status') else dict(_UNKNOWN)
    except (OSError, ValueError, KeyError, TypeError):
        return dict(_UNKNOWN)



def self_test(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Run two fixed inert Linux filesystem cases on configured archlinux only."""
    if not isinstance(value, Mapping) or value != {}:
        raise ValueError('fixed archive self-test takes no inputs')
    unknown = {**_UNKNOWN, 'componentOnly': True}
    if not _supported() or base is None:
        return unknown
    path = Path(root).resolve(strict=True)
    try:
        config = base.ssh_transport.load_config(path)
        target = config.hosts.get('archlinux')
        if target is None or target.alias != 'archlinux':
            return unknown
        raw = base._remote(config, _SELF_TEST, (), None, 20)
        if not isinstance(raw, (str, bytes)) or not 0 < len(raw) <= 1024:
            return unknown
        result = json.loads(raw, object_pairs_hook=_unique)
        cases = result.get('cases') if isinstance(result, dict) else None
        if (not isinstance(result, dict) or set(result) != {'state', 'cases'}
                or result['state'] not in {'passed', 'failed', 'unknown'}
                or not isinstance(cases, dict) or set(cases) != {'exclusive-rename', 'destination-race'}
                or any(type(item) is not str or item not in {'passed', 'failed', 'unknown'} for item in cases.values())
                or (result['state'] == 'passed') != all(item == 'passed' for item in cases.values())):
            return unknown
        return {**unknown, **result}
    except (OSError, ValueError, TypeError, AttributeError):
        return unknown
