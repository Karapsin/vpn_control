"""Fixed read-only guest kernel check for a future Mac fixture server stop.

The future server controller must create a private ready file at the fixed
source/correlation path and retain its digest and generation in a trusted
one-shot start journal. This observer only rechecks that generation; it never
signals a process or claims that a stop was requested.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Mapping

from . import macos_machine_acceptance as gate
from .macos_machine_receipts import MacReceiptError, _uuid
from .macos_machine_tart_readonly import TartReadOnlyProvider


_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_START = re.compile(r"darwin:[1-9][0-9]*:[0-9]{1,6}\Z")
_GUEST_PROBE = r'''import ctypes,errno,hashlib,json,os,pathlib,socket,stat,sys,uuid
source,correlation=sys.argv[1:]
if len(source)!=40 or any(c not in '0123456789abcdef' for c in source):raise ValueError('source')
if str(uuid.UUID(correlation))!=correlation:raise ValueError('correlation')
root=pathlib.Path('/Users/admin/macos-parity'+source[:7])
path=root/'state'/'acceptance-evidence'/correlation/'server-ready.json'
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
try:
 for index,part in enumerate(path.parts[1:-1]):
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
  info=os.fstat(child)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,501) or info.st_mode & 0o022 or (index>=3 and (info.st_uid!=501 or stat.S_IMODE(info.st_mode)!=0o700)):
   os.close(child);raise ValueError('ancestor')
  os.close(parent);parent=child
 fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=501 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=16384:raise ValueError('ready')
  raw=os.read(fd,16385);after=os.fstat(fd);now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_uid,before.st_mode,before.st_nlink)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_uid,after.st_mode,after.st_nlink) or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_uid,before.st_mode,before.st_nlink)!=(now.st_dev,now.st_ino,now.st_size,now.st_mtime_ns,now.st_uid,now.st_mode,now.st_nlink):raise ValueError('changed')
 finally:os.close(fd)
finally:os.close(parent)
ready=json.loads(raw)
pid=ready.get('serverPid');start=ready.get('serverProcessStartIdentity');port=ready.get('port')
if type(pid)!=int or pid<=0 or type(port)!=int or not 0<port<65536 or not isinstance(start,str) or not start.startswith('darwin:'):raise ValueError('identity')
class Info(ctypes.Structure):
 _fields_=[('flags',ctypes.c_uint32),('status',ctypes.c_uint32),('xstatus',ctypes.c_uint32),('pid',ctypes.c_uint32),('ppid',ctypes.c_uint32),('uid',ctypes.c_uint32),('gid',ctypes.c_uint32),('ruid',ctypes.c_uint32),('rgid',ctypes.c_uint32),('svuid',ctypes.c_uint32),('svgid',ctypes.c_uint32),('rfu_1',ctypes.c_uint32),('comm',ctypes.c_char*16),('name',ctypes.c_char*32),('nfiles',ctypes.c_uint32),('pgid',ctypes.c_uint32),('pjobc',ctypes.c_uint32),('tdev',ctypes.c_uint32),('tpgid',ctypes.c_uint32),('nice',ctypes.c_int32),('startsec',ctypes.c_uint64),('startusec',ctypes.c_uint64)]
lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True);fn=lib.proc_pidinfo
fn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];fn.restype=ctypes.c_int
info=Info();ctypes.set_errno(0);size=fn(pid,3,0,ctypes.byref(info),ctypes.sizeof(info))
if size==0:
 try:os.kill(pid,0)
 except ProcessLookupError:pass
 except PermissionError:raise ValueError('process inaccessible')
 else:raise ValueError('process ambiguous')
 generation_alive=False
elif size==ctypes.sizeof(info) and info.pid==pid and info.startsec>0 and info.startusec<1000000:
 generation_alive=('darwin:'+str(info.startsec)+':'+str(info.startusec))==start
else:raise ValueError('process ambiguous')
results=[]
for family,address in ((socket.AF_INET,('127.0.0.1',port)),(socket.AF_INET6,('::1',port,0,0))):
 connection=socket.socket(family,socket.SOCK_STREAM);connection.settimeout(0.5)
 try:
  result=connection.connect_ex(address)
  if result not in (0,errno.ECONNREFUSED):raise ValueError('listener ambiguous')
  results.append(result)
 finally:connection.close()
listener_open=any(result==0 for result in results)
print(json.dumps({'schemaVersion':1,'sourceSha':source,'correlationId':correlation,
 'readySha256':hashlib.sha256(raw).hexdigest(),'serverInstanceId':ready.get('serverInstanceId'),
 'serverPid':pid,'serverProcessStartIdentity':start,'port':port,
 'pidGenerationAlive':generation_alive,'listenerOpen':listener_open},sort_keys=True,separators=(',',':')))
'''


def observe_server_generation(source_sha: str, correlation_id: str, *, expected_ready_sha256: str,
                              expected_instance_id: str, expected_pid: int,
                              expected_start: str, runner=subprocess.run) -> Mapping[str, Any]:
    """Require a matching fixed ready file and fresh absence of its server."""
    if not isinstance(source_sha, str) or not _SOURCE.fullmatch(source_sha):
        raise MacReceiptError("Mac server source is invalid.")
    _uuid(correlation_id)
    _uuid(expected_instance_id)
    if not isinstance(expected_ready_sha256, str) or not _SHA.fullmatch(expected_ready_sha256) or \
            type(expected_pid) is not int or expected_pid <= 0 or \
            not isinstance(expected_start, str) or not _START.fullmatch(expected_start):
        raise MacReceiptError("Mac server start journal identity is invalid.")
    try:
        TartReadOnlyProvider(runner=runner)._require_running()
        result = runner(["tart", "exec", gate.VM_NAME, "/usr/bin/python3", "-c", _GUEST_PROBE,
                         source_sha, correlation_id], capture_output=True, text=True,
                        timeout=30, check=False)
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise ValueError()
        value = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as error:
        raise MacReceiptError("Fresh Mac server kernel observation is unavailable.") from error
    expected = {"schemaVersion": 1, "sourceSha": source_sha, "correlationId": correlation_id,
                "readySha256": expected_ready_sha256, "serverInstanceId": expected_instance_id,
                "serverPid": expected_pid, "serverProcessStartIdentity": expected_start,
                "pidGenerationAlive": False, "listenerOpen": False}
    if not isinstance(value, dict) or set(value) != {*expected, "port"} or \
            type(value.get("schemaVersion")) is not int or type(value.get("serverPid")) is not int or \
            type(value.get("port")) is not int or not 0 < value["port"] < 65536 or \
            value.get("pidGenerationAlive") is not False or value.get("listenerOpen") is not False or \
            any(value.get(key) != item for key, item in expected.items()):
        raise MacReceiptError("Fresh Mac server generation is not absent.")
    return value
