"""One-shot, non-product CP117 guest-to-Arch loopback endpoint probe.

This is deliberately narrower than a transfer implementation.  It proves only
that the already-admitted SLIRP guest can reach a fresh, one-use HTTP endpoint
bound on the Arch host's loopback address.  The remote listener is always
stopped and its disappearance is proven before this module publishes a result.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any, Mapping

from . import windows_msi_base_prepare as base


class WindowsMsiTransferEndpointError(ValueError):
    pass


_CORRELATION = base._TRANSFER_RECOVERY_CORRELATION
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_UNKNOWN = {"state": "unknown", "reachable": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}

# The parent binds the random endpoint fields to this exact remote stage.  The
# worker has no filesystem input other than its private stage and accepts one
# request whose origin-form path and body digest match exactly.
_REMOTE_START = r"""import hashlib,json,os,re,signal,socket,stat,subprocess,sys,time
root,env,corr,sock,pid,ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def safe_dir(p,create=False):
 if create and not os.path.exists(p):os.mkdir(p,0o700)
 i=os.lstat(p)
 if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
def write_once(p,v):
 raw=json.dumps(v,separators=(',',':'),sort_keys=True).encode();fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def ticks_of(p):
 try:
  raw=open('/proc/'+str(p)+'/stat','rb').read().split();return raw[21].decode() if len(raw)>=22 else ''
 except OSError:return ''
def stop(pid,tick,port):
 if type(pid) is not int or type(port) is not int or not 1<=port<=65535:raise ValueError()
 if ticks_of(pid)==tick:
  os.killpg(pid,signal.SIGTERM)
  for _ in range(100):
   if ticks_of(pid)!=tick:break
   time.sleep(.02)
  else:raise ValueError()
 probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM);probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',port));probe.close()
worker=r'''import hashlib,http.server,json,os,socket,sys,time
stage=sys.argv[1:][0]
raw=sys.stdin.buffer.read(1025);payload=json.loads(raw.decode('utf-8')) if 0<len(raw)<=1024 else None
if not isinstance(payload,dict) or set(payload)!={'path','token','port'} or not isinstance(payload['port'],int) or not 1<=payload['port']<=65535:raise SystemExit(2)
path=payload['path'];token=payload['token'];port=payload['port']
def write(p,v):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(json.dumps(v,separators=(',',':'),sort_keys=True).encode());f.flush();os.fsync(f.fileno())
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  if self.path!=path or self.headers.get('Proxy-Connection') is not None:
   self.send_response(404);self.end_headers();return
  body=token.encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers();self.wfile.write(body);self.server.seen=True
 def do_CONNECT(self):self.send_response(405);self.end_headers()
class Server(http.server.HTTPServer):
 allow_reuse_address=False
server=Server(('127.0.0.1',port),Handler);server.timeout=.2;server.seen=False
write(os.path.join(stage,'ready.json'),{'pid':os.getpid(),'startTicks':open('/proc/self/stat','rb').read().split()[21].decode(),'port':port,'pathSha256':hashlib.sha256(path.encode()).hexdigest(),'tokenSha256':hashlib.sha256(token.encode()).hexdigest()})
deadline=time.monotonic()+20
while time.monotonic()<deadline and not server.seen:server.handle_request()
server.server_close()
write(os.path.join(stage,'worker-stopped.json'),{'seen':server.seen})'''
try:
 child=None;worker_tick='';port=0
 raw=sys.stdin.buffer.read(1025)
 payload=json.loads(raw.decode('utf-8')) if 0<len(raw)<=1024 else None
 if not isinstance(payload,dict) or set(payload)!={'path','token'}:raise ValueError()
 path=payload['path'];token=payload['token']
 if env!='windows-cp117' or corr!='45e4514a-c629-4f3b-99bc-aad599640d29' or not re.fullmatch(r'/[A-Za-z0-9_-]{24,128}',path) or not re.fullmatch(r'[A-Za-z0-9_-]{24,128}',token):raise ValueError()
 for value in (sock,):
  if not re.fullmatch(r'/[A-Za-z0-9._/-]+',value):raise ValueError()
 for value in (pid,ticks):
  if not value.isdigit() or int(value)<=0:raise ValueError()
 safe_dir(root);parent=os.path.join(root,env);safe_dir(parent,True);group=os.path.join(parent,'windows-msi-transfer-endpoint');safe_dir(group,True);stage=os.path.join(group,corr)
 if os.path.lexists(stage):raise ValueError()
 os.mkdir(stage,0o700);safe_dir(stage)
 write_once(os.path.join(stage,'binding.json'),{'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'pathSha256':hashlib.sha256(path.encode()).hexdigest(),'tokenSha256':hashlib.sha256(token.encode()).hexdigest()})
 reserve=socket.socket(socket.AF_INET,socket.SOCK_STREAM);reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1];reserve.close()
 child=subprocess.Popen((sys.executable,'-c',worker,stage),stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True)
 worker_tick=ticks_of(child.pid)
 if not worker_tick:raise ValueError()
 write_once(os.path.join(stage,'worker.json'),{'pid':child.pid,'startTicks':worker_tick,'port':port,'pathSha256':hashlib.sha256(path.encode()).hexdigest(),'tokenSha256':hashlib.sha256(token.encode()).hexdigest()})
 worker_payload=json.dumps({'path':path,'token':token,'port':port},separators=(',',':')).encode()
 child.stdin.write(worker_payload);child.stdin.close()
 for _ in range(100):
  ready=os.path.join(stage,'ready.json')
  if os.path.exists(ready):break
  if child.poll() is not None:raise ValueError()
  time.sleep(.02)
 else:raise ValueError()
 value=json.load(open(ready));expected={'pid','startTicks','port','pathSha256','tokenSha256'}
 if set(value)!=expected or value['pid']!=child.pid or value['startTicks']!=ticks_of(child.pid) or type(value['port']) is not int or not 1<=value['port']<=65535 or value['pathSha256']!=hashlib.sha256(path.encode()).hexdigest() or value['tokenSha256']!=hashlib.sha256(token.encode()).hexdigest():raise ValueError()
 out({'state':'ready','port':value['port']})
except Exception:
 try:
  if child is not None:stop(child.pid,worker_tick,port)
 except Exception:pass
 out({'state':'unknown'})
"""

_REMOTE_PROBE = base._QGA + base._TRANSFER_NETWORK_QEMU_TOPOLOGY + r'''import time
sock,pid,ticks,port,path,expected=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
try:
 if not live(sock,pid,ticks) or not port.isdigit() or not 1<=int(port)<=65535 or not re.fullmatch(r'/[A-Za-z0-9_-]{24,128}',path) or not re.fullmatch(r'[0-9a-f]{64}',expected):raise ValueError()
 user_network(pid)
 url='http://10.0.2.2:'+port+path
 script="$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Net.Http;$handler=[System.Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false;$client=[System.Net.Http.HttpClient]::new($handler);try{$response=$client.GetAsync('"+url+"').GetAwaiter().GetResult();if(-not $response.IsSuccessStatusCode){throw 'HTTP'};$body=$response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($body))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($hash -cne '"+expected+"'){throw 'BODY'};[Console]::Out.WriteLine(([pscustomobject]@{version=1;bodySha256=$hash;proxy=$handler.UseProxy}|ConvertTo-Json -Compress))}finally{$client.Dispose();$handler.Dispose()}"
 encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
 if len(encoded)>=30000:raise ValueError()
 child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(40):
  item=call(sock,'guest-exec-status',{'pid':child})
  if item.get('exited') is True:break
  if item.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 else:raise ValueError()
 if (set(item)-{'exited','exitcode','out-data','err-data','out-truncated','err-truncated'} or type(item.get('exitcode')) is not int or item['exitcode']!=0 or ('out-truncated' in item and item['out-truncated'] is not False) or ('err-truncated' in item and item['err-truncated'] is not False)):raise ValueError()
 raw=base64.b64decode(item.get('out-data',''),validate=True)
 if not 0<len(raw)<=512:raise ValueError()
 lines=[line for line in decode(raw).splitlines() if line.startswith('{') and line.endswith('}')]
 value=json.loads(lines[0]) if len(lines)==1 else None
 if value!={'version':1,'bodySha256':expected,'proxy':False}:raise ValueError()
 out({'state':'observed','bodySha256':expected})
except Exception:out({'state':'unknown'})
'''

_REMOTE_STOP = r'''import json,os,signal,socket,stat,sys,time
root,env,corr,sock,qemu_pid,qemu_ticks,mode=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def ticks(p):
 try:
  raw=open('/proc/'+str(p)+'/stat','rb').read().split();return raw[21].decode() if len(raw)>=22 else ''
 except OSError:return ''
def socket_inodes(pid):
 result=set()
 for name in os.listdir('/proc/'+str(pid)+'/fd'):
  try:
   value=os.readlink('/proc/'+str(pid)+'/fd/'+name)
   if value.startswith('socket:[') and value.endswith(']'):result.add(value[8:-1])
  except OSError:pass
 return result
def listeners(port):
 result=set()
 for path in ('/proc/net/tcp','/proc/net/tcp6'):
  for line in open(path).read().splitlines()[1:]:
   fields=line.split()
   if len(fields)>=10 and fields[3]=='0A':
    local=fields[1].split(':')
    if len(local)==2 and int(local[1],16)==port:result.add(fields[9])
 return result
try:
 stage=os.path.join(root,env,'windows-msi-transfer-endpoint',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 worker=json.load(open(os.path.join(stage,'worker.json')));binding=json.load(open(os.path.join(stage,'binding.json')));required={'pid','startTicks','port','pathSha256','tokenSha256'}
 if mode not in ('cleanup','reconcile') or set(worker)!=required or set(binding)!={'socketPath','qemuPid','startTicks','pathSha256','tokenSha256'} or binding!={'socketPath':sock,'qemuPid':int(qemu_pid),'startTicks':int(qemu_ticks),'pathSha256':worker['pathSha256'],'tokenSha256':worker['tokenSha256']} or type(worker['pid']) is not int or type(worker['port']) is not int or not 1<=worker['port']<=65535 or not isinstance(worker['startTicks'],str):raise ValueError()
 bound=listeners(worker['port']);owned=socket_inodes(worker['pid']) if ticks(worker['pid'])==worker['startTicks'] else set()
 if mode=='reconcile' and not (len(bound)==1 and next(iter(bound)) in owned):raise ValueError()
 if ticks(worker['pid'])==worker['startTicks']:
  os.killpg(worker['pid'],signal.SIGTERM)
  for _ in range(100):
   if ticks(worker['pid'])!=worker['startTicks']:break
   time.sleep(.02)
  else:raise ValueError()
 # Prove no listener survives at the exact port. A new listener makes the
 # cleanup unknown rather than treating an unrelated process as harmless.
 probe=socket.socket(socket.AF_INET,socket.SOCK_STREAM);probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',worker['port']));probe.close()
 out({'state':'stopped'})
except Exception:out({'state':'unknown'})
'''

_REMOTE_STATUS = r'''import json,os,stat,sys
root,env,corr,sock,qemu_pid,qemu_ticks=sys.argv[1:]
def out(v):print(json.dumps(v,separators=(',',':'),sort_keys=True))
def ticks(p):
 try:
  raw=open('/proc/'+str(p)+'/stat','rb').read().split();return raw[21].decode() if len(raw)>=22 else ''
 except OSError:return ''
def socket_inodes(pid):
 result=set()
 for name in os.listdir('/proc/'+str(pid)+'/fd'):
  try:
   value=os.readlink('/proc/'+str(pid)+'/fd/'+name)
   if value.startswith('socket:[') and value.endswith(']'):result.add(value[8:-1])
  except OSError:pass
 return result
def listeners(port):
 result=set()
 for path in ('/proc/net/tcp','/proc/net/tcp6'):
  for line in open(path).read().splitlines()[1:]:
   fields=line.split()
   if len(fields)>=10 and fields[3]=='0A':
    local=fields[1].split(':')
    if len(local)==2 and int(local[1],16)==port:result.add(fields[9])
 return result
def private_json(path,expected):
 info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1024:raise ValueError()
 value=json.load(open(path))
 return value if isinstance(value,dict) and set(value)==expected else None
try:
 stage=os.path.join(root,env,'windows-msi-transfer-endpoint',corr);info=os.lstat(stage)
 if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 worker=private_json(os.path.join(stage,'worker.json'),{'pid','startTicks','port','pathSha256','tokenSha256'});binding=private_json(os.path.join(stage,'binding.json'),{'socketPath','qemuPid','startTicks','pathSha256','tokenSha256'});required={'pid','startTicks','port','pathSha256','tokenSha256'}
 if set(worker)!=required or set(binding)!={'socketPath','qemuPid','startTicks','pathSha256','tokenSha256'} or binding!={'socketPath':sock,'qemuPid':int(qemu_pid),'startTicks':int(qemu_ticks),'pathSha256':worker['pathSha256'],'tokenSha256':worker['tokenSha256']} or type(worker['pid']) is not int or type(worker['port']) is not int or not 1<=worker['port']<=65535 or not isinstance(worker['startTicks'],str):raise ValueError()
 ready_path=os.path.join(stage,'ready.json');stopped_path=os.path.join(stage,'worker-stopped.json')
 if not os.path.exists(ready_path):startup='missing';receipt='unknown'
 else:
  ready=private_json(ready_path,required)
  if ready is None or ready!=worker:raise ValueError()
  startup='ready'
  if not os.path.exists(stopped_path):receipt='unknown'
  else:
   stopped=private_json(stopped_path,{'seen'})
   if stopped is None or type(stopped['seen']) is not bool:raise ValueError()
   receipt='seen' if stopped['seen'] else 'not-seen'
 live=ticks(worker['pid'])==worker['startTicks'];bound=listeners(worker['port'])
 if live:
  owned=socket_inodes(worker['pid'])
  if len(bound)==1 and next(iter(bound)) in owned:out({'state':'observed','worker':'running','listener':'owned','port':'bound','startup':startup,'receipt':receipt})
  elif not bound:out({'state':'observed','worker':'running','listener':'absent','port':'free','startup':startup,'receipt':receipt})
  else:out({'state':'observed','worker':'running','listener':'unattributed','port':'bound','startup':startup,'receipt':receipt})
 else:
  if not bound:out({'state':'observed','worker':'stopped','listener':'absent','port':'free','startup':startup,'receipt':receipt})
  else:out({'state':'observed','worker':'stopped','listener':'unattributed','port':'bound','startup':startup,'receipt':receipt})
except Exception:out({'state':'unknown'})
'''


def _exact(value: Any, expected: Mapping[str, Any]) -> bool:
    return isinstance(value, dict) and value == dict(expected)


def _read(raw: bytes | None) -> Any:
    if raw is None or len(raw) > 512:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def _unknown(correlation: str, *, cleanup: str = "not-started") -> dict[str, Any]:
    return {**_UNKNOWN, "correlationId": correlation, "cleanup": cleanup}


def _stop(config: Any, target: Any, guest: tuple[str, str, int, int, str], mode: str = "cleanup") -> str:
    """Return a public cleanup fact; never let a listener escape an unknown."""
    try:
        env, sock, pid, ticks, _sid = guest
        result = _read(base._remote(config, _REMOTE_STOP,
            (str(target.fixture_transfer_root), env, _CORRELATION, sock, str(pid), str(ticks), mode), None, 10))
    except (OSError, ValueError, TypeError, KeyError):
        return "unknown"
    return "stopped" if _exact(result, {"state": "stopped"}) else "unknown"


def _start(config: Any, target: Any, args: tuple[str, ...], path: str, token: str) -> Any:
    """Keep one-time endpoint secrets out of remote process arguments."""
    payload = json.dumps({"path": path, "token": token}, separators=(",", ":")).encode()
    if not 0 < len(payload) <= 1024:
        raise WindowsMsiTransferEndpointError("Endpoint token payload is invalid.")
    with tempfile.NamedTemporaryFile(mode="wb", prefix="vpn-control-endpoint-", delete=True) as stream:
        os.chmod(stream.name, 0o600)
        stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        return base._remote(config, _REMOTE_START, args, Path(stream.name), 10)


def _bound_endpoint(root: Path | str) -> tuple[Path, Any, Any, tuple[str, str, int, int, str]]:
    """Return only the current, source-bound CP117 record for correlation 45e."""
    resolved = Path(root).resolve(strict=True)
    config, target, guest = base._descriptor(resolved)
    env, sock, pid, ticks, sid = guest
    request, command_hash = base._UNKNOWN_RECOVERY_PROFILES[_CORRELATION]
    intent = base._private_intent(resolved, _CORRELATION)
    if (env != "windows-cp117" or target.fixture_transfer_root is None or intent is None
            or intent.get("request") != request or intent.get("commandSha256") != command_hash
            or intent.get("leaseId") != _CORRELATION
            or any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
                ("pid", pid), ("startTicks", ticks), ("expectedSid", sid)))):
        raise WindowsMsiTransferEndpointError("Endpoint worker binding changed.")
    return resolved, config, target, guest


def _status(config: Any, target: Any, guest: tuple[str, str, int, int, str]) -> dict[str, Any] | None:
    env, sock, pid, ticks, _sid = guest
    result = _read(base._remote(config, _REMOTE_STATUS,
        (str(target.fixture_transfer_root), env, _CORRELATION, sock, str(pid), str(ticks)), None, 10))
    allowed = (
        {"state": "observed", "worker": "running", "listener": "owned", "port": "bound", "startup": "ready", "receipt": "unknown"},
        {"state": "observed", "worker": "running", "listener": "absent", "port": "free", "startup": "ready", "receipt": "unknown"},
        {"state": "observed", "worker": "running", "listener": "unattributed", "port": "bound", "startup": "ready", "receipt": "unknown"},
        {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free", "startup": "ready", "receipt": "seen"},
        {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free", "startup": "ready", "receipt": "not-seen"},
        {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free", "startup": "ready", "receipt": "unknown"},
        {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free", "startup": "missing", "receipt": "unknown"},
        {"state": "observed", "worker": "stopped", "listener": "unattributed", "port": "bound", "startup": "ready", "receipt": "seen"},
        {"state": "observed", "worker": "stopped", "listener": "unattributed", "port": "bound", "startup": "ready", "receipt": "not-seen"},
        {"state": "observed", "worker": "stopped", "listener": "unattributed", "port": "bound", "startup": "ready", "receipt": "unknown"},
        {"state": "observed", "worker": "stopped", "listener": "unattributed", "port": "bound", "startup": "missing", "receipt": "unknown"},
    )
    return result if result in allowed else None


def endpoint_probe_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Read the exact persisted listener identity after a lost cleanup response."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or value.get("correlationId") != _CORRELATION:
        raise WindowsMsiTransferEndpointError("Endpoint status requires the reviewed transfer correlationId.")
    try:
        _, config, target, guest = _bound_endpoint(root)
        observed = _status(config, target, guest)
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiTransferEndpointError):
        observed = None
    if observed is None:
        return {"state": "unknown", "correlationId": _CORRELATION, "worker": "unknown", "listener": "unknown",
                "port": "unknown", "startup": "unknown", "receipt": "unknown", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    return {**observed, "correlationId": _CORRELATION, "replayAllowed": False,
            "nativeActionAllowed": observed["listener"] == "owned", "productAction": False}


def endpoint_probe_reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Stop only an exactly observed owned endpoint worker; then re-observe it."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or value.get("correlationId") != _CORRELATION:
        raise WindowsMsiTransferEndpointError("Endpoint reconciliation requires the reviewed transfer correlationId.")
    initial = endpoint_probe_status(root, value)
    safe = {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free"}
    if {key: initial.get(key) for key in safe} == safe:
        return {**initial, "state": "stopped", "outcome": "already-stopped", "nativeActionAllowed": False}
    required = {"state": "observed", "worker": "running", "listener": "owned", "port": "bound", "startup": "ready"}
    if {key: initial.get(key) for key in required} != required:
        return {**initial, "state": "unknown", "outcome": "not-owned", "nativeActionAllowed": False}
    try:
        _, config, target, guest = _bound_endpoint(root)
        stop_result = _stop(config, target, guest, "reconcile")
        after = _status(config, target, guest)
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiTransferEndpointError):
        after = None
        stop_result = None
    if isinstance(after, Mapping) and {key: after.get(key) for key in safe} == safe:
        return {"state": "stopped", "correlationId": _CORRELATION, "outcome": "reconciled",
                "worker": "stopped", "listener": "absent", "port": "free", "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    return {"state": "unknown", "correlationId": _CORRELATION, "outcome": "cleanup-unconfirmed",
            "worker": "unknown", "listener": "unknown", "port": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


def endpoint_probe(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    """Run exactly one disposable network probe for the reviewed transfer loss."""
    if not isinstance(value, Mapping) or set(value) != {"correlationId"} or value.get("correlationId") != _CORRELATION:
        raise WindowsMsiTransferEndpointError("Endpoint probe requires the reviewed transfer correlationId.")
    correlation = _CORRELATION
    try:
        admission = base.transfer_network_admission(root, value)
        if admission != {"state": "ready", "correlationId": correlation, "qga": "healthy", "network": "slirp",
                         "endpointEligibility": "eligible", "hostBindAddress": "127.0.0.1",
                         "guestHostAddress": "10.0.2.2", "replayAllowed": False, "nativeActionAllowed": False}:
            return _unknown(correlation)
        resolved = Path(root).resolve(strict=True)
        config, target, guest = base._descriptor(resolved)
        env, sock, pid, ticks, _sid = guest
        if env != "windows-cp117" or target.fixture_transfer_root is None:
            return _unknown(correlation)
        request, command_hash = base._UNKNOWN_RECOVERY_PROFILES[correlation]
        intent = base._private_intent(resolved, correlation)
        if (intent is None or intent.get("request") != request or intent.get("commandSha256") != command_hash
                or intent.get("leaseId") != correlation
                or any(intent.get(key) != observed for key, observed in (("environment", env), ("socketPath", sock),
                    ("pid", pid), ("startTicks", ticks), ("expectedSid", _sid)))):
            return _unknown(correlation)
        token = secrets.token_urlsafe(32).replace("-", "_")
        path = "/" + secrets.token_urlsafe(32).replace("-", "_")
        if not re.fullmatch(r"/[A-Za-z0-9_]{24,128}", path) or not re.fullmatch(r"[A-Za-z0-9_]{24,128}", token):
            return _unknown(correlation)
        digest = hashlib.sha256(token.encode()).hexdigest()
        start_attempted = True
        started = _read(_start(config, target,
            (str(target.fixture_transfer_root), env, correlation, sock, str(pid), str(ticks)), path, token))
        if not isinstance(started, dict) or set(started) != {"state", "port"} or started.get("state") not in {"ready", "unknown"}:
            return _unknown(correlation, cleanup=_stop(config, target, guest))
        cleanup = "unknown"
        try:
            if started["state"] != "ready" or type(started.get("port")) is not int or not 1 <= started["port"] <= 65535:
                observed = None
            else:
                observed = _read(base._remote(config, _REMOTE_PROBE,
                    (sock, str(pid), str(ticks), str(started["port"]), path, digest), None, 20))
        finally:
            cleanup = _stop(config, target, guest)
        if cleanup != "stopped":
            return _unknown(correlation, cleanup=cleanup)
        if _exact(observed, {"state": "observed", "bodySha256": digest}):
            return {"state": "reachable", "correlationId": correlation, "reachable": True, "cleanup": cleanup,
                    "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        if _exact(observed, {"state": "blocked"}):
            return {"state": "blocked", "correlationId": correlation, "reachable": False, "cleanup": cleanup,
                    "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        return _unknown(correlation, cleanup=cleanup)
    except (OSError, ValueError, TypeError, KeyError, WindowsMsiTransferEndpointError):
        # If transport lost the start response, its remote child may still be
        # alive.  A best-effort stop is mandatory and only a proven stop is
        # exposed; failure stays unknown.
        if "start_attempted" in locals() and start_attempted and "config" in locals() and "target" in locals() and "guest" in locals():
            return _unknown(correlation, cleanup=_stop(config, target, guest))
        return _unknown(correlation, cleanup="unknown")
