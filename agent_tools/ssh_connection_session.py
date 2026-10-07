"""One fenced outer gateway SSH connection; no remote command execution API.

An unknown creation remains observation-only. Reuse options deliberately disable
network fallback if the exact admitted local multiplex socket disappears.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

from . import ssh_transport as transport

_DIR='.rag_index/ssh-connection-session'
_MAX=262144
_PHASES={'configuration','private','generation','intent','launch','socket','master','authority','unsupported'}

class SessionUnknown(ValueError):
    def __init__(self,phase):
        self.phase=phase if phase in _PHASES else 'authority'
        super().__init__(self.phase)

def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def _fp(i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]

def _directory(path):
    i=os.lstat(path)
    if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise SessionUnknown('private')
    return [i.st_dev,i.st_ino,i.st_mode,i.st_uid]

def _bytes(path,private=True,parent_fd=None):
    name=path if parent_fd is None else path.name
    before=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1
        or not 0<before.st_size<=_MAX or before.st_mode & 0o022
        or private and stat.S_IMODE(before.st_mode) not in {0o400,0o600}):raise SessionUnknown('private')
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent_fd)
    with os.fdopen(fd,'rb') as stream:
        if _fp(os.fstat(stream.fileno()))!=_fp(before):raise SessionUnknown('generation')
        raw=stream.read(_MAX+1)
        if len(raw)!=before.st_size or _fp(os.fstat(stream.fileno()))!=_fp(before):raise SessionUnknown('generation')
    if _fp(os.stat(name,dir_fd=parent_fd,follow_symlinks=False))!=_fp(before):raise SessionUnknown('generation')
    return raw,_fp(before)

def _unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise SessionUnknown('authority')
        value[key]=item
    return value

def _read(path,parent_fd=None):
    raw,fp=_bytes(path,parent_fd=parent_fd)
    value=json.loads(raw,object_pairs_hook=_unique)
    if not isinstance(value,dict):raise SessionUnknown('authority')
    return value,{'sha256':_sha(raw),'fingerprint':fp}

def _create(path,value,parent_fd=None):
    fd=os.open(path if parent_fd is None else path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
    with os.fdopen(fd,'wb') as stream:
        stream.write(_json(value));stream.flush();os.fsync(stream.fileno())
    parent=parent_fd if parent_fd is not None else os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:
        if parent_fd is None:os.close(parent)

class _JournalGuard:
    """Retain ancestry and the named lock until the connection action ends."""
    def __init__(self,root,journal,lock_fd=None,lock_identity=None):
        self.fds=[];self.paths=[];self.lock_fd=lock_fd;self.lock_identity=lock_identity;self.fence=None;self.socket_parent=None;self.require_socket_absent=False;self.authority=None
        try:
            for path in (root,root/'.rag_index',root/_DIR,journal):
                before=os.lstat(path)
                if not stat.S_ISDIR(before.st_mode) or before.st_uid!=os.getuid():raise SessionUnknown('private')
                if path!=root and stat.S_IMODE(before.st_mode)!=0o700:raise SessionUnknown('private')
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                self.fds.append(fd);self.paths.append((path,[before.st_dev,before.st_ino,before.st_mode,before.st_uid]))
            self.check()
        except Exception:
            self.close();raise
    @property
    def journal_fd(self):return self.fds[-1]
    def _held_named(self):
        for fd,(path,identity) in zip(self.fds,self.paths):
            current=os.lstat(path);held=os.fstat(fd)
            if [current.st_dev,current.st_ino,current.st_mode,current.st_uid]!=identity or [held.st_dev,held.st_ino,held.st_mode,held.st_uid]!=identity:raise SessionUnknown('generation')
        if self.lock_fd is not None:
            path=self.paths[-1][0]/'lock'
            if _fp(os.fstat(self.lock_fd))!=self.lock_identity or _fp(os.lstat(path))!=self.lock_identity:raise SessionUnknown('generation')
        if self.fence is not None:
            path,content,pin=self.fence
            if _read(path,self.journal_fd)!=(content,pin):raise SessionUnknown('intent')
        if self.socket_parent is not None:
            path,identity=self.socket_parent
            if _directory(path.parent)!=identity:raise SessionUnknown('generation')
            if self.require_socket_absent and os.path.lexists(path):raise SessionUnknown('socket')
    def check(self):
        self._held_named()
        if self.authority is not None:
            root,host,expected=self.authority
            if _snapshot(root,host)[2]!=expected:raise SessionUnknown('generation')
        # Authority reads can race a named-path exchange. Recheck all held and
        # named generations after those reads, immediately before a launch.
        # The flock coordinates cooperating tools; this is not an atomic CAS
        # against arbitrary external writers after this final observation.
        self._held_named()
    def read(self,path):
        if path.parent!=self.paths[-1][0]:raise SessionUnknown('authority')
        self.check();result=_read(path,self.journal_fd);self.check();return result
    def create(self,path,value):
        self.check();_create(path,value,self.journal_fd);self.check()
    def snapshot(self,root,host):
        self.check();result=_snapshot(root,host);self.check();return result
    def close(self):
        for fd in self.fds:os.close(fd)
        self.fds=[]

def _source():return _sha(Path(__file__).read_bytes())

def _snapshot(root,host):
    path=transport._private_config_path(root)
    raw,fp=_bytes(path)
    config=transport.load_config(root)
    route=transport._route_hosts(config.hosts,host)
    # A direct host is not silently converted to an outer gateway campaign.
    if len(route)<2 or route[-1].transport!='direct':raise SessionUnknown('unsupported')
    outer=route[-1]
    if outer.password is not None:raise SessionUnknown('unsupported')
    pins=[]
    for entry in (outer,):
        # Only the outer connection opens local credential files. Nested SSH
        # identity paths may be represented as Path too, but live on that hop.
        # Their complete paths/settings remain bound by exact config bytes.
        for candidate,private in ((entry.identity_file,True),(entry.known_hosts_file,False)):
            if not isinstance(candidate,Path):continue
            data,identity=_bytes(candidate,private)
            pins.append({'path':str(candidate),'sha256':_sha(data),'fingerprint':identity})
    again,after=_bytes(path)
    if raw!=again or fp!=after:raise SessionUnknown('generation')
    authority={'version':1,'host':host,'root':str(root),'sourceSha256':_source(),
               'configSha256':_sha(raw),'configFingerprint':fp,'files':pins,
               'routeAliases':[entry.alias for entry in route]}
    return config,outer,authority

def _journal(root,host,create=True):
    parent=root/'.rag_index'
    if not parent.exists() and create:parent.mkdir(mode=0o700)
    _directory(parent)
    group=root/_DIR
    if not group.exists() and create:group.mkdir(mode=0o700)
    _directory(group)
    leaf=group/_sha((str(root)+'\0'+host).encode())[:24]
    if not leaf.exists() and create:leaf.mkdir(mode=0o700)
    _directory(leaf)
    return leaf

def _socket(path,parent_identity):
    if _directory(path.parent)!=parent_identity:raise SessionUnknown('generation')
    i=os.lstat(path)
    if not stat.S_ISSOCK(i.st_mode) or i.st_uid!=os.getuid() or i.st_nlink!=1 or stat.S_IMODE(i.st_mode)&0o077:raise SessionUnknown('socket')
    return _fp(i)

def _outer_prefix(config,outer):
    argv=transport.build_ssh_argv(config,outer.alias,10,command=('true',),ssh_binary='/usr/bin/ssh')
    # All endpoint/key/known-host authority comes from the pinned project config;
    # inherited user config must not add forwards or launch hooks to a master.
    return [argv[0],'-F','/dev/null',*argv[1:-2]],argv[-2]

def _launch_argv(config,outer,path):
    prefix,endpoint=_outer_prefix(config,outer)
    return [*prefix,'-S',str(path),'-o','ControlMaster=yes','-o','ControlPersist=no',
            '-o','ClearAllForwardings=yes','-o','ForkAfterAuthentication=no',
            '-o','UpdateHostKeys=no','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=3','-N',endpoint]

def _check_argv(config,outer,path):
    prefix,endpoint=_outer_prefix(config,outer)
    return [*prefix,'-S',str(path),'-o','ControlMaster=no','-o','ControlPersist=no',
            '-o','ProxyCommand=false','-O','check',endpoint]

def _pid_generation(pid):
    if type(pid)is not int or pid<=0:raise SessionUnknown('master')
    result=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=','-o','lstart=','-o','comm='],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,check=False)
    if result.returncode!=0 or len(result.stdout)>1024:raise SessionUnknown('master')
    value=result.stdout.decode('ascii').strip()
    fields=value.split()
    if len(fields)<7 or fields[0]!=str(os.getuid()) or Path(fields[-1]).name!='ssh':raise SessionUnknown('master')
    return {'pid':pid,'generationSha256':_sha(value.encode())}

def _master(config,outer,path):
    result=subprocess.run(_check_argv(config,outer,path),stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,check=False)
    raw=result.stdout+result.stderr
    if result.returncode!=0 or len(raw)>4096:raise SessionUnknown('master')
    match=re.fullmatch(rb'Master running \(pid=([1-9][0-9]{0,9})\)\r?\n?',raw)
    if match is None:raise SessionUnknown('master')
    return _pid_generation(int(match[1]))

_LIMITED_EXEC="import json,os,resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096));a=json.loads(sys.argv[1]);os.execv(a[0],a)"

def _spawn(argv,stderr_path,guard=None):
    # A fixed exec wrapper applies a kernel cap before SSH can write diagnostics.
    # It keeps the same PID and avoids an unbounded pipe/background drainer.
    value={'version':1,'argvSha256':_sha(_json(argv)),'diagnosticLimit':4096}
    record=stderr_path.with_name('launch.json')
    if guard is None:_create(record,value)
    else:guard.create(record,value)
    parent_fd=None if guard is None else guard.journal_fd
    fd=os.open(stderr_path if parent_fd is None else stderr_path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
    try:
        i=os.fstat(fd);identity=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_nlink]
        if guard is not None:guard.check()
        process=subprocess.Popen([sys.executable,'-c',_LIMITED_EXEC,json.dumps(argv)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=fd,start_new_session=True)
        process._session_stderr_identity=identity
        if guard is not None:guard.require_socket_absent=False
        return process
    finally:os.close(fd)

def _startup_diagnostic(journal,guard,process,started):
    guard.check();path=journal/'launch.stderr.private'
    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=guard.journal_fd)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1
            or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>4096):raise SessionUnknown('private')
        if [before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink]!=getattr(process,'_session_stderr_identity',None):raise SessionUnknown('generation')
        raw=os.read(fd,4096)
        after=os.fstat(fd)
        if [before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink]!=[after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink] or after.st_size>4096:raise SessionUnknown('generation')
        named=os.stat(path.name,dir_fd=guard.journal_fd,follow_symlinks=False)
        if _fp(named)!=_fp(after):raise SessionUnknown('generation')
        guard.check()
        guard.create(journal/'startup.json',{'version':1,'exitCode':process.poll(),'elapsedMs':max(0,round((time.monotonic()-started)*1000)),
                     'stderrBytes':len(raw),'stderrSha256':_sha(raw),'stderrFingerprint':_fp(after)})
    finally:os.close(fd)

def _verify(root,host,journal,intent,ready=None,guard=None):
    if set(intent)!={'version','authority','socketPath','parentIdentity'} or intent['version']!=1:raise SessionUnknown('authority')
    read=_read if guard is None else guard.read
    snapshot=_snapshot if guard is None else guard.snapshot
    config,outer,current=snapshot(root,host)
    if current!=intent['authority']:raise SessionUnknown('generation')
    path=Path(intent['socketPath'])
    if (not path.is_absolute() or path.name!='m' or len(os.fsencode(path))>=90
        or path.parent.parent!=Path(tempfile.gettempdir()).resolve()):raise SessionUnknown('socket')
    identity=_socket(path,intent['parentIdentity'])
    original_intent,intent_pin=read(journal/'intent.json')
    if original_intent!=intent:raise SessionUnknown('authority')
    child,child_pin=read(journal/'child.json')
    anchor,anchor_pin=read(journal/'anchor.json')
    if anchor!={'intentPin':intent_pin,'childPin':child_pin,'parentIdentity':intent['parentIdentity']}:raise SessionUnknown('authority')
    if set(child)!={'intentSha256','pid'} or child['intentSha256']!=_sha(_json(intent)):raise SessionUnknown('authority')
    master=_master(config,outer,path)
    if guard is not None:guard.check()
    if master['pid']!=child['pid']:raise SessionUnknown('master')
    if (_socket(path,intent['parentIdentity'])!=identity or snapshot(root,host)[2]!=current
        or read(journal/'intent.json')!=(original_intent,intent_pin)
        or read(journal/'child.json')!=(child,child_pin)
        or read(journal/'anchor.json')!=(anchor,anchor_pin)):raise SessionUnknown('generation')
    proof={'version':1,'intentSha256':_sha(_json(intent)),'childPin':child_pin,
           'intentPin':intent_pin,'anchorPin':anchor_pin,'socketFingerprint':identity,
           'master':master,'authoritySha256':_sha(_json(current))}
    if ready is not None and proof!=ready:raise SessionUnknown('authority')
    return proof,path

def prepare(root:Path|str,host:str)->dict[str,Any]:
    """Create one configured gateway connection or observe its consumed intent."""
    try:
        root=Path(root).resolve(strict=True)
        config,outer,authority=_snapshot(root,host)
        journal=_journal(root,host)
        lockpath=journal/'lock'
        if not lockpath.exists():
            fd=os.open(lockpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        i=os.lstat(lockpath)
        if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.getuid() or i.st_nlink!=1 or stat.S_IMODE(i.st_mode)!=0o600:raise SessionUnknown('private')
        fd=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
        guard=None
        try:
            if _fp(os.fstat(fd))!=_fp(i):raise SessionUnknown('generation')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            guard=_JournalGuard(root,journal,fd,_fp(i))
            guard.authority=(root,host,authority);guard.check()
            intentpath=journal/'intent.json'
            if not os.path.lexists(intentpath):
                parent=Path(tempfile.mkdtemp(prefix='vcss-')).resolve(strict=True)
                parent.chmod(0o700);identity=_directory(parent);path=parent/'m'
                intent={'version':1,'authority':authority,'socketPath':str(path),'parentIdentity':identity}
                guard.create(intentpath,intent)  # Fence precedes process launch.
                if guard.snapshot(root,host)[2]!=authority:raise SessionUnknown('generation')
                stored,intent_pin=guard.read(intentpath)
                if stored!=intent:raise SessionUnknown('intent')
                guard.fence=(intentpath,intent,intent_pin)
                guard.socket_parent=(path,identity);guard.require_socket_absent=True
                guard.check()  # Exact named fence/lock/ancestry before the effect.
                started=time.monotonic()
                process=_spawn(_launch_argv(config,outer,path),journal/'launch.stderr.private',guard)
                guard.check()
                if guard.read(intentpath)!=(intent,intent_pin):raise SessionUnknown('intent')
                guard.create(journal/'child.json',{'intentSha256':_sha(_json(intent)),'pid':process.pid})
                _,child_pin=guard.read(journal/'child.json')
                guard.create(journal/'anchor.json',{'intentPin':intent_pin,'childPin':child_pin,'parentIdentity':identity})
                # Fixed bounded readiness observation, never another launch.
                for _ in range(30):
                    if path.exists() or process.poll() is not None:break
                    time.sleep(.1)
                _startup_diagnostic(journal,guard,process,started)
            else:intent,_=guard.read(intentpath)
            ready_path=journal/'ready.json'
            ready,_=guard.read(ready_path) if os.path.lexists(ready_path) else (None,None)
            proof,_=_verify(root,host,journal,intent,ready,guard)
            if ready is None:guard.create(ready_path,proof)
            if _fp(os.lstat(lockpath))!=_fp(i):raise SessionUnknown('generation')
            stored,ready_pin=guard.read(ready_path)
            if stored!=proof:raise SessionUnknown('authority')
            return {'state':'ready','host':host,'receiptSha256':_sha(_json(ready_pin)),'created':ready is None}
        finally:
            if guard is not None:guard.close()
            os.close(fd)
    except SessionUnknown as error:return {'state':'unknown','host':host,'phase':error.phase}
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return {'state':'unknown','host':host,'phase':'authority'}

def reuse_only_options(root:Path|str,host:str,receipt_sha256:str)->list[str]:
    """Return transport options after fresh admission; never run a remote command."""
    if not isinstance(receipt_sha256,str) or not re.fullmatch('[0-9a-f]{64}',receipt_sha256):raise SessionUnknown('authority')
    try:
        root=Path(root).resolve(strict=True);journal=_journal(root,host,False)
        lockpath=journal/'lock';i=os.lstat(lockpath)
        if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.getuid() or i.st_nlink!=1 or stat.S_IMODE(i.st_mode)!=0o600:raise SessionUnknown('private')
        fd=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW);guard=None
        try:
            if _fp(os.fstat(fd))!=_fp(i):raise SessionUnknown('generation')
            fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            guard=_JournalGuard(root,journal,fd,_fp(i))
            intent,intent_pin=guard.read(journal/'intent.json');ready,ready_pin=guard.read(journal/'ready.json')
            guard.fence=(journal/'intent.json',intent,intent_pin)
            guard.authority=(root,host,intent['authority']);guard.check()
            if _sha(_json(ready_pin))!=receipt_sha256:raise SessionUnknown('authority')
            proof,path=_verify(root,host,journal,intent,ready,guard)
            if proof!=ready or guard.read(journal/'ready.json')!=(ready,ready_pin):raise SessionUnknown('authority')
            guard.check()
            return ['-S',str(path),'-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false']
        finally:
            if guard is not None:guard.close()
            os.close(fd)
    except SessionUnknown:raise
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):raise SessionUnknown('authority') from None

def admission(root:Path|str,host:str,receipt_sha256:str)->dict[str,Any]:
    """Fresh read-only authority check for the existing transport caller."""
    try:
        reuse_only_options(root,host,receipt_sha256)
        return {'state':'ready','host':host,'receiptSha256':receipt_sha256}
    except SessionUnknown as error:return {'state':'unknown','host':host,'phase':error.phase}

def verify_reuse(root:Path|str,host:str,receipt_sha256:str)->bool:
    """Caller must verify again after its existing transport operation."""
    reuse_only_options(root,host,receipt_sha256)
    return True

def selected_options(config:transport.SshConfig,host:str)->list[str]:
    """Select an already fenced nested session, never silently replace unknown."""
    try:
        route=transport._route_hosts(config.hosts,host)
        if len(route)<2:return []  # Direct gateway builders cannot recurse.
        root=Path(config.root).resolve(strict=True)
        fresh=transport.load_config(root)
        if (fresh.root!=config.root or set(fresh.hosts)!=set(config.hosts)
            or any(vars(fresh.hosts[alias])!=vars(config.hosts[alias]) for alias in fresh.hosts)):raise SessionUnknown('generation')
        parent=root/'.rag_index';group=root/_DIR
        leaf=group/_sha((str(root)+'\0'+host).encode())[:24]
        for path in (parent,group,leaf):
            if not os.path.lexists(path):return []
            _directory(path)
        if not os.path.lexists(leaf/'intent.json'):return []
        ready,ready_pin=_read(leaf/'ready.json')
        receipt=_sha(_json(ready_pin))
        return reuse_only_options(root,host,receipt)
    except SessionUnknown:raise
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):raise SessionUnknown('authority') from None
