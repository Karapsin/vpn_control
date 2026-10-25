"""Fixed ordinary-account, read-only session observer for per-event fencing.

This pure builder grants no input authority. The provider must close complete
source/host/guest custody before each logical GUI group and compare every reply
against the original admitted machine, raw boot, account and console session.
"""
from __future__ import annotations

import inspect
import re
from pathlib import PurePosixPath

from . import readiness_tart_macos as backend
from . import readiness_tart_macos_registry as registry

_PROBE = "b144862272b3bbb5464bcdb3ed57403d76d4f5418c4388c859195f9afb3c38ab"


def guest_session_source(binding):
    if type(binding) is not backend.MacBinding:
        raise backend.MacBlocked("macos_session_binding_invalid")
    prefix = str(PurePosixPath(binding.guest_python).parents[2])
    if not re.fullmatch(r"/usr/local/libexec/vpn-tool-recovery(?:-[a-z0-9-]+)?", prefix):
        raise backend.MacBlocked("macos_session_binding_invalid")
    parameters = {"prefix": prefix, "probeSha256": _PROBE, "target": binding.target,
                  "machine": binding.machine, "uid": binding.ordinary_uid,
                  "principal": binding.ordinary_account, "home": binding.ordinary_home}
    return ("PARAMETERS=" + repr(parameters) + "\n" +
            inspect.getsource(registry._console_login_done) + "\n" +
            inspect.getsource(_load_verified_probe) + "\n" + _OBSERVER).encode()


def _load_verified_probe(raw, filename):
    import sys, types
    module = types.ModuleType('_fixed_owned_mac_session_probe')
    sys.modules[module.__name__] = module
    exec(compile(raw, filename, 'exec'), module.__dict__)
    return module


_OBSERVER = r'''import ctypes as C,hashlib,json,os,pathlib,pwd,stat,subprocess
p=PARAMETERS
def need(value):
 if not value:raise SystemExit(73)
user=pwd.getpwuid(os.geteuid())
need((user.pw_uid,user.pw_name,user.pw_dir)==(p['uid'],p['principal'],p['home']))
need(80 not in os.getgrouplist(user.pw_name,user.pw_gid))
prefix=pathlib.Path(p['prefix']);probe=prefix/'guest-probe.py'
def protected(path):
 for parent in (path,*path.parents):
  info=parent.lstat();need(info.st_uid==0 and not info.st_mode&0o022 and not stat.S_ISLNK(info.st_mode))
 need(path.is_file() and path.stat().st_nlink==1)
protected(probe);before=probe.stat();raw_source=probe.read_bytes();need(hashlib.sha256(raw_source).hexdigest()==p['probeSha256'])
need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
     (probe.stat().st_dev,probe.stat().st_ino,probe.stat().st_size,probe.stat().st_mtime_ns,probe.stat().st_ctime_ns))
module=_load_verified_probe(raw_source,str(probe))
native=module.Native();boot,_=native.boot()
raw=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],timeout=3).decode('ascii').strip()
need(raw.lower()==boot and native.machine()==p['machine'])
parent=os.getppid();info=module._Bsd();buffer=C.create_string_buffer(4096)
need(native.proc.proc_pidinfo(parent,3,0,C.byref(info),C.sizeof(info))==C.sizeof(info)
     and info.pid==parent and info.ppid==1 and info.uid==p['uid'])
length=native.proc.proc_pidpath(parent,buffer,len(buffer));agent=prefix/'tart-guest-agent';protected(agent)
need(0<length<len(buffer) and buffer.value.decode()==str(agent))
console=native.console();entry=native.io.IORegistryGetRootEntry(0)
try:rows=native.property(entry,'IOConsoleUsers')if entry else None
finally:
 if entry:native.io.IOObjectRelease(entry)
console['loginDone']=_console_login_done(console,rows,p['uid'],p['principal'])
display=native.displays();need(native.boot()[0]==boot)
print(json.dumps({'target':p['target'],'machine':p['machine'],'boot':boot,'rawBoot':raw,
 'uid':user.pw_uid,'principal':user.pw_name,'home':user.pw_dir,'console':console,'display':display,
 'agent':{'pid':parent,'birth':'darwin:'+str(info.start_seconds)+':'+str(info.start_microseconds),'uid':info.uid}},sort_keys=True))
'''
