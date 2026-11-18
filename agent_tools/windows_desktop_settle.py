"""Settle an owned clone's ordinary desktop before a review: at most two Esc keys, only at a shell surface.

``vm_workflow windows-desktop-settle`` takes exactly deploymentId and operationId. A fresh Windows 11 profile keeps a
shell surface in the foreground by itself (a75acf02 on NG4: Start; adae4153 on NG5: Search), and a consent prompt asked
for behind it goes to the taskbar, so every prompting row refuses (windows_ordinary_process_owner.interactive_desktop).
This action, run explicitly by an operator, proves the console is the fixture user's unlocked session, keeps a frame,
and probes the foreground in that session: a one-shot InteractiveToken task of the user runs a fixed windowless
pythonw probe built from the owner's own foreground_window, and the owner's desktop_holder rule judges what it read.
Only a shell surface (Start, Search, a shell flyout) gets one Esc through the guest input path, burned before it is
sent, and is probed again; at most two Esc keys in all. Any other unsettled holder is refused, named, with no key.
The last frame is kept beside the first.

Setup class: never product evidence, never an approval, and never run by a prompting row. The first call sends its
packet under a create-only journal; a repeat is a settle packet that reads the original's terminal and keys nothing,
and an original with no terminal is unknown, never replayed.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import time
from types import SimpleNamespace

from . import readiness_windows_login as login
from . import readiness_windows_remote as packets
from . import windows_ordinary_process_owner as owner_rules
from . import windows_uac_decision as uac
from .windows_ordinary_process_owner import desktop_holder
from .windows_uac_decision import _uac_close_fence, _uac_create, _uac_directory, _uac_load

_EXECUTING_CODE = inspect.currentframe().f_code

INPUT_FIELDS = frozenset({"deploymentId", "operationId"})
ESC_LIMIT = 2  # Esc keys in all, each followed by a probe.
SETTLE_SECONDS = 1.5  # After an Esc, before the next probe.
_SETTLES = ".runtime/windows-desktop-settles"
_OPERATION = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
# The probe's own refusals, named before any key.
PROBE_REFUSALS = frozenset({"desktop_probe_python_absent", "desktop_probe_unfinished", "desktop_probe_no_output"})
# The action's typed ends.
REFUSALS = PROBE_REFUSALS | {"desktop_settle_holder_not_shell", "desktop_settle_still_unsettled"}

# The windowless probe the user's task runs: the owner's own foreground read, its result written create-only.
PROBE_PYTHON = ("import ctypes,json,os,sys\nfrom ctypes import wintypes as W\n\n\n" + inspect.getsource(owner_rules.foreground_window)
                + "\n\nwindow=foreground_window()\nwith open(sys.argv[1],'x',encoding='ascii') as stream:\n"
                + "    stream.write(json.dumps({'window':window,'probePid':os.getpid()},separators=(',',':')))\n")

# SYSTEM registers one InteractiveToken task of the console user, runs the probe once, removes the task and its folder.
_PROBE = r"""$sid=__SID__;$nonce=__NONCE__;$code=__CODE__
$r=[ordered]@{state='observed';reason=$null;window=$null;probePid=$null;rows=@();cleaned=$true}
$profile=@(Get-CimInstance Win32_UserProfile -OperationTimeoutSec 5|Where-Object{$_.SID -ceq $sid})
$python=$null
if($profile.Count -eq 1){$python=Join-Path ([string]$profile[0].LocalPath) 'AppData\Local\Programs\Python\Python313\pythonw.exe'}
if($null -eq $python -or -not (Test-Path -LiteralPath $python -PathType Leaf)){$r.state='refused';$r.reason='desktop_probe_python_absent'}
else{
 $name='VpnControlDesktopProbe-'+$nonce;$dir=Join-Path $env:ProgramData $name
 if((Test-Path -LiteralPath $dir) -or $null -ne (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)){throw 'DESKTOP_PROBE_ORIGINAL_EXISTS'}
 New-Item -ItemType Directory -Path $dir|Out-Null
 & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' ('*'+$sid+':(OI)(CI)M')|Out-Null
 if($LASTEXITCODE -ne 0){throw 'DESKTOP_PROBE_ACL'}
 $probe=Join-Path $dir 'probe.py';$out=Join-Path $dir 'probe.json'
 [IO.File]::WriteAllBytes($probe,[Convert]::FromBase64String($code))
 $action=New-ScheduledTaskAction -Execute $python -Argument ('-I -S -B "'+$probe+'" "'+$out+'"') -WorkingDirectory $dir
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings|Out-Null
 $done=$false
 try{
  Start-ScheduledTask -TaskName $name
  $until=[DateTime]::UtcNow.AddSeconds(20)
  while(-not $done -and [DateTime]::UtcNow -lt $until){
   Start-Sleep -Milliseconds 250
   $info=Get-ScheduledTaskInfo -TaskName $name
   $done=((Get-ScheduledTask -TaskName $name).State -eq 'Ready') -and $info.LastTaskResult -ne 267009 -and $info.LastTaskResult -ne 267011
  }
 }finally{Unregister-ScheduledTask -TaskName $name -Confirm:$false}
 if(-not $done){$r.state='refused';$r.reason='desktop_probe_unfinished'}
 elseif(-not (Test-Path -LiteralPath $out -PathType Leaf)){$r.state='refused';$r.reason='desktop_probe_no_output'}
 else{
  $raw=[IO.File]::ReadAllText($out)
  if($raw.Length -gt 4096){throw 'DESKTOP_PROBE_BOUND'}
  $read=$raw|ConvertFrom-Json;$r.window=$read.window;$r.probePid=[int]$read.probePid
  if($null -ne $read.window){$r.rows=@(foreach($x in @(Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$read.window.pid) -OperationTimeoutSec 5)){[ordered]@{pid=[int]$x.ProcessId;parentPid=[int]$x.ParentProcessId;name=[string]$x.Name}})}
 }
 try{Remove-Item -LiteralPath $dir -Recurse -Force}catch{$r.cleaned=$false}
}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 6 -Compress))
"""


def probe_source(sid, nonce):
    """The fixed SYSTEM probe for one console user and one probe of one operation; ASCII, every value checked."""
    if type(sid) is not str or re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", sid) is None:
        raise ValueError("windows_desktop_settle_account")
    if type(nonce) is not str or re.fullmatch(r"[0-9a-f]{12}-[1-9]", nonce) is None:
        raise ValueError("windows_desktop_settle_nonce")
    code = base64.b64encode(PROBE_PYTHON.encode("ascii")).decode("ascii")
    source = uac._PRELUDE + _PROBE
    for marker, value in (("__SID__", uac._ps_literal(sid)), ("__NONCE__", uac._ps_literal(nonce)), ("__CODE__", "'" + code + "'")):
        if source.count(marker) != 1:
            raise ValueError("windows_desktop_settle_marker")
        source = source.replace(marker, value)
    source.encode("ascii")
    return source


# Everything from here to _desktop_settle_repeat runs on the VM host, embedded by inspect.getsource.
class _DesktopSettle:
    """One settle, in its own folder of the VM root: its intent, each Esc burned before it is sent, and its terminal."""
    def __init__(self,root,operation):
        self.root=root;self.operation=operation;self.begun=False
        self.parent=root/'windows-desktop-settle';self.directory=self.parent/operation
    def known(self,name):
        import os
        path=self.directory/name
        return _uac_load(path)if os.path.lexists(path)else None
    def begin(self):
        """The folder and the intent exist before the fence, the first frame or any key."""
        import os
        for path in (self.parent,self.directory):_uac_directory(path)
        for path in (self.parent,self.root):
            descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        _uac_create(self.directory/'settle.intent.json',{'operationId':self.operation,'mode':'desktop-settle','replayAllowed':False})
        self.begun=True
    def finish(self,value):
        """The first terminal wins, and the reply is always that terminal."""
        import os
        path=self.directory/'settle.terminal.json'
        if not os.path.lexists(path):_uac_create(path,value)
        return _uac_load(path)
    def reply(self,reason):
        """The failure path of a begun settle: unknown, its fence left open, and never replayed."""
        if not self.begun:return None
        return self.finish({'state':'desktop-settle-unknown','operationId':self.operation,'reason':reason,'replayAllowed':False})

def _desktop_settle_probe(script,fresh,count):
    """One probe of the console user's foreground: (what holds it, why it is unsettled or None), or a typed refusal."""
    def need(ok,code):
        if not ok:raise ValueError(code)
    nonce=OPERATION.replace('-','')[:12]+'-'+str(count)
    need(type(fresh['expectedSid'])is str and re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',fresh['expectedSid'])is not None,'instance_desktop_settle_session_changed')
    value=script('desktop-probe-'+str(count),DESKTOP_PROBE_TEMPLATE.replace('__SID__',"'"+fresh['expectedSid']+"'").replace('__NONCE__',"'"+nonce+"'"))
    need(type(value)is dict and set(value)=={'state','reason','window','probePid','rows','cleaned'}and type(value['cleaned'])is bool,'instance_desktop_probe_shape')
    if value['state']=='refused':
        need(value['reason']in DESKTOP_PROBE_REFUSALS,'instance_desktop_probe_shape')
        return None,value['reason']
    window=value['window'];rows=value['rows']
    need(value['state']=='observed'and value['reason']is None and type(value['probePid'])is int and value['probePid']>0
         and (window is None or type(window)is dict and set(window)=={'pid','className'}and type(window['pid'])is int and window['pid']>0
              and type(window['className'])is str and 0<len(window['className'])<=256)
         and type(rows)is list and len(rows)<=1 and all(type(row)is dict and set(row)=={'pid','parentPid','name'}
              and type(row['pid'])is int and type(row['parentPid'])is int and type(row['name'])is str and len(row['name'])<=260
              and window is not None and row['pid']==window['pid']for row in rows),'instance_desktop_probe_shape')
    return desktop_holder(window,{row['pid']:row for row in rows},value['probePid']),None

def _desktop_settle_shot(settle,monitor,guard,name):
    """One whole frame of the console, kept beside the journal under its own name."""
    import hashlib,os,stat
    path=settle.directory/name
    if os.path.lexists(path):raise ValueError('instance_desktop_settle_frame_identity')
    guard();monitor('screendump',{'filename':str(path),'format':'ppm'});s=os.lstat(path)
    if not(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and s.st_nlink==1 and 0<s.st_size<=16*1024**2):raise ValueError('instance_desktop_settle_frame_identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        raw=b''
        while len(raw)<=16*1024**2:
            chunk=os.read(fd,65536)
            if not chunk:break
            raw+=chunk
    finally:os.close(fd)
    if len(raw)!=s.st_size:raise ValueError('instance_desktop_settle_frame_changed')
    guard();return {'name':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def _desktop_settle(settle,root,save,read,monitor,guard,script):
    """The session proven, a frame, a probe; only a shell surface gets one burned Esc and a probe again, at most twice."""
    import os,time
    def need(ok,code):
        if not ok:raise ValueError(code)
    def durable(name,value):
        save(name,value)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    known=settle.known('settle.terminal.json')
    if known is not None:return known
    need(settle.known('settle.intent.json')is None,'instance_desktop_settle_original_unresolved')
    fresh=script('login-session-'+os.urandom(6).hex(),SESSION_SCRIPT);session=fresh['session']
    need(fresh['machine'].lower()==SPEC['deploymentId']and fresh['ordinary']is True and fresh['tokenSid']==fresh['expectedSid']
         and session['SessionId']==fresh['console']and session['State']==0,'instance_desktop_settle_session_changed')
    # A locked console shows the lock screen: an Esc there is not the desktop's.
    need(session['Flags']==1,'instance_desktop_settle_session_locked')
    guard();settle.begin()
    durable('direct-guest-'+OPERATION+'.intent.json',{'operationId':OPERATION,'label':'desktop-settle','replayAllowed':False})
    frames=[_desktop_settle_shot(settle,monitor,guard,'frame-before.ppm')]
    probes=[];escapes=0
    def probe():
        found,refused=_desktop_settle_probe(script,fresh,len(probes)+1)
        probes.append({'refused':refused}if found is None else {'interactiveDesktop':found[0],'unsettled':found[1]})
        return found,refused
    def end(state,reason):
        frames.append(_desktop_settle_shot(settle,monitor,guard,'frame-after.ppm'))
        guard();_uac_close_fence(root,durable,OPERATION,os.getpid(),0)
        return settle.finish({'state':state,'operationId':OPERATION,'reason':reason,'escapes':escapes,'probes':probes,'frames':frames,'replayAllowed':False})
    found,refused=probe()
    while True:
        if found is None:return end('desktop-settle-refused',refused)
        if found[1]is None:return end('desktop-settled',None)
        # Only Start, Search or a shell flyout is dismissed; any other holder is named and left as it is.
        if found[1]!='shell-surface':return end('desktop-settle-refused','desktop_settle_holder_not_shell')
        if escapes>=DESKTOP_SETTLE_ESC_LIMIT:return end('desktop-settle-refused','desktop_settle_still_unsettled')
        escapes+=1
        guard();_uac_create(settle.directory/('esc-%d.intent.json'%escapes),{'operationId':OPERATION,'holder':found[0],'replayAllowed':False})
        monitor('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80});guard()
        time.sleep(DESKTOP_SETTLE_WAIT)
        found,refused=probe()

def _desktop_settle_reply(settle,terminal):
    """A known terminal as a reply carries it: each kept frame's exact bytes, read back and checked against its name."""
    import base64,hashlib,os,stat,zlib
    if type(terminal)is not dict or terminal.get('state')not in ('desktop-settled','desktop-settle-refused'):return terminal
    carried={}
    for row in terminal['frames']:
        descriptor=os.open(settle.directory/row['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(descriptor);raw=bytearray()
            if not stat.S_ISREG(info.st_mode)or info.st_uid!=os.geteuid()or info.st_size!=row['bytes']:raise ValueError('instance_desktop_settle_frame_changed')
            while len(raw)<info.st_size:
                chunk=os.read(descriptor,min(1048576,info.st_size-len(raw)))
                if not chunk:raise ValueError('instance_desktop_settle_frame_changed')
                raw+=chunk
        finally:os.close(descriptor)
        if hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('instance_desktop_settle_frame_changed')
        carried[row['name']]=base64.b64encode(zlib.compress(bytes(raw),6)).decode()
    return {**terminal,'frameBytes':carried}

def _desktop_settle_repeat(settle):
    """A repeat sends nothing: it reads the original's terminal, and an original with none is unknown."""
    known=settle.known('settle.terminal.json')
    if known is not None:return known
    return {'state':'desktop-settle-unknown'if settle.known('settle.intent.json')is not None else'no-settle-recorded','operationId':OPERATION,
            'reason':'instance_desktop_settle_original_unresolved','replayAllowed':False}


_COMMON_SOURCES = (_uac_load, _uac_create, _uac_directory, _DesktopSettle, _desktop_settle_reply)
_SETTLE_SOURCES = (*_COMMON_SOURCES, _uac_close_fence, desktop_holder, _desktop_settle_probe, _desktop_settle_shot, _desktop_settle)
# A repeat packet embeds no key, frame or probe code at all.
_REPEAT_SOURCES = (*_COMMON_SOURCES, _desktop_settle_repeat)


def program(binding, operation, *, repeat=False):
    """A fixed packet patched from the observe producer, as windows_uac_visual does; no pinned source moves."""
    if not uac._canonical(operation) or type(repeat) is not bool:
        raise ValueError("windows_desktop_settle_action")
    packets.validate_binding(binding)
    mode = "desktop-settle-repeat" if repeat else "desktop-settle"
    bindings = {}
    if repeat:
        sources = _REPEAT_SOURCES
        call = "            result=_desktop_settle_reply(desktop_settle,_desktop_settle_repeat(desktop_settle))\n"
    else:
        template = uac._PRELUDE + _PROBE
        code = base64.b64encode(PROBE_PYTHON.encode("ascii")).decode("ascii")
        bindings = {"DESKTOP_PROBE_TEMPLATE": template.replace("__CODE__", "'" + code + "'"), "DESKTOP_PROBE_REFUSALS": sorted(PROBE_REFUSALS),
                    "DESKTOP_SETTLE_ESC_LIMIT": ESC_LIMIT, "DESKTOP_SETTLE_WAIT": SETTLE_SECONDS,
                    "SHELL_FOREGROUND": sorted(owner_rules.SHELL_FOREGROUND), "CONSOLE_CLASS": owner_rules.CONSOLE_CLASS}
        sources = _SETTLE_SOURCES
        call = ("            require(state=='running','instance_guest_not_ready')\n"
                "            result=_desktop_settle_reply(desktop_settle,_desktop_settle(desktop_settle,root,save,read,monitor,vm_guard,script))\n")
    source = packets.program(binding, "observe", operation).decode()
    source = uac._replace_once(source, "MODE='observe'", "MODE=" + repr(mode))
    marker = "        elif MODE in {'observe','idle-inventory','reboot'}:\n"
    source = uac._replace_once(source, marker, "        elif MODE==" + repr(mode) + ":\n"
                               "            desktop_settle=_DesktopSettle(root,OPERATION)\n" + call + marker)
    if not repeat:
        # A begun settle always ends with a terminal; one it cannot write is unknown, and never replayed.
        source = uac._replace_once(source, "        print(json.dumps({'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}))",
                                   "        failed={'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}\n"
                                   "        if locals().get('desktop_settle')is not None:\n"
                                   "            try:failed=desktop_settle.reply(reason)or failed\n"
                                   "            except BaseException:failed={'state':'desktop-settle-unknown','operationId':OPERATION,'reason':reason,'replayAllowed':False}\n"
                                   "        print(json.dumps(failed))")
    helpers = "import hashlib,json,os,re\n" + "".join(key + "=" + repr(value) + "\n" for key, value in bindings.items())
    helpers += "".join(inspect.getsource(item) + "\n" for item in sources)
    raw = (helpers + source).encode()
    compile(raw, "fixed Windows desktop settle", "exec")
    return raw


def validate_inputs(inputs):
    """Exactly the deployment and one operation of the caller's choosing."""
    if (type(inputs) is not dict or set(inputs) != INPUT_FIELDS or any(type(value) is not str for value in inputs.values())
            or not uac._canonical(inputs["deploymentId"]) or not uac._canonical(inputs["operationId"])):
        raise ValueError("windows_desktop_settle_inputs")
    return inputs


def _binding(root, deployment):
    """The deployment's original start intent, as the scenario driver and the visual route read one."""
    from . import readiness_fixture_registry as registry
    try:
        value, _ = registry._json(root / ".rag_index/windows-vm-deploy-intents" / (deployment + ".intent.json"))
        if (set(value) != {"spec", "setup", "context", "correlationId", "mode", "callerSha256"} or value["mode"] != "start"
                or type(value["spec"]) is not dict or value["spec"].get("deploymentId") != deployment):
            raise ValueError("desktop_settle_deployment_unavailable")
        binding = {"provider": "raw-qemu-windows", "spec": value["spec"], "setup": value["setup"], "context": value["context"],
                   "uri": None, "domain": None, "xmlSha256": None}
        provider, spec, _, _ = packets.validate_binding(binding)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("desktop_settle_deployment_unavailable") from None
    if provider != "raw-qemu-windows" or spec.deployment_id != deployment:
        raise ValueError("desktop_settle_deployment_unavailable")
    return binding


def _refused(reason, inputs):
    return {"state": "refused", "reason": reason, "operationId": inputs["operationId"], "deploymentId": inputs["deploymentId"],
            "replayAllowed": False}


def _gates(root, inputs):
    """Every gate before the first contact, on local files alone; nothing is written."""
    validate_inputs(inputs)
    root = Path(root).resolve(strict=True)
    for code, module in ((_EXECUTING_CODE, __file__), (uac._EXECUTING_CODE, uac.__file__)):
        current = Path(module)
        if code != compile(current.read_bytes(), str(current), "exec", dont_inherit=True):
            raise ValueError("windows_desktop_settle_source_changed")
    deployment, operation = inputs["deploymentId"], inputs["operationId"]
    try:
        binding = _binding(root, deployment)
    except ValueError as error:
        return _refused(str(error), inputs), None
    directory = root / _SETTLES / operation
    if os.path.lexists(directory / "intent.json") and json.loads(uac._read_private(directory / "intent.json")).get("deploymentId") != deployment:
        return _refused("desktop_settle_operation_mismatch", inputs), None
    if os.path.lexists(directory / "result.json"):
        return json.loads(uac._read_private(directory / "result.json")), None
    return None, SimpleNamespace(root=root, binding=binding, directory=directory, repeat=os.path.lexists(directory / "settle.intent.json"))


def before_contact(root, inputs):
    """The reply settle gives from local files alone, or None when it must reach the host."""
    reply, _ = _gates(root, inputs)
    return reply


def _holder(value):
    """One probe's holder as it may cross, or None."""
    if type(value) is not dict or set(value) != {"foreground"}:
        return None
    found = value["foreground"]
    if found is None:
        return {"foreground": None}
    if (type(found) is not dict or set(found) != {"pid", "image", "className", "owned"} or type(found["pid"]) is not int or found["pid"] <= 0
            or not (found["image"] is None or type(found["image"]) is str and len(found["image"]) <= 260)
            or type(found["className"]) is not str or not 0 < len(found["className"]) <= 256 or type(found["owned"]) is not bool):
        return None
    return {"foreground": dict(found)}


def _project(value, inputs, frames):
    """Only closed fields cross: the end, its reason, the Esc keys sent, each probe's holder and the kept frames."""
    public = {"operationId": inputs["operationId"], "deploymentId": inputs["deploymentId"], "replayAllowed": False}
    unknown = {"state": "unknown", "reason": "desktop_settle_reply_rejected", **public}
    if type(value) is not dict or value.get("operationId") != inputs["operationId"] or value.get("replayAllowed") is not False:
        return unknown
    state, reason = value.get("state"), value.get("reason")
    if state in {"desktop-settled", "desktop-settle-refused"}:
        probes, escapes = value.get("probes"), value.get("escapes")
        if (set(value) != {"state", "operationId", "reason", "escapes", "probes", "frames", "replayAllowed"}
                or type(escapes) is not int or not 0 <= escapes <= ESC_LIMIT or type(probes) is not list or not 1 <= len(probes) <= ESC_LIMIT + 1
                or (state == "desktop-settled") != (reason is None) or state == "desktop-settle-refused" and reason not in REFUSALS):
            return unknown
        holders = []
        for row in probes:
            if type(row) is dict and set(row) == {"refused"} and row["refused"] in PROBE_REFUSALS:
                holders.append({"refused": row["refused"]})
                continue
            holder = _holder(row.get("interactiveDesktop")) if type(row) is dict and set(row) == {"interactiveDesktop", "unsettled"} else None
            if holder is None or row["unsettled"] not in (None, "shell-surface", "foreign-console"):
                return unknown
            holders.append({"interactiveDesktop": holder, "unsettled": row["unsettled"]})
        last = holders[-1]
        if state == "desktop-settled" and last.get("unsettled", "refused") is not None:
            return unknown
        return {"state": state, "settled": state == "desktop-settled", **({"reason": reason} if reason else {}), "escapes": escapes,
                "probes": holders, "frames": frames, **public}
    if state == "desktop-settle-unknown":
        return {"state": "unknown", "reason": reason if type(reason) is str and uac._PUBLIC_REASON.fullmatch(reason) else "desktop_settle_unknown",
                "escapesMayHaveBeenSent": True, **public}
    if state == "blocked" and type(reason) is str and uac._PUBLIC_REASON.fullmatch(reason) is not None:
        # Printed only before the settle began: no frame, probe or key.
        return {"state": "refused", "reason": reason, **public}
    if state == "no-settle-recorded":
        return {"state": "unknown", "reason": "desktop_settle_original_unknown", **public}
    return unknown


def _frames(directory, value):
    """The kept frames a terminal names, carried back as their exact bytes: retained here as private PPM files."""
    frames = value.get("frames") if type(value) is dict else None
    carried = value.get("frameBytes") if type(value) is dict else None
    if type(frames) is not list or not 1 <= len(frames) <= 2 or type(carried) is not dict:
        return None
    kept = []
    for row in frames:
        if (type(row) is not dict or set(row) != {"name", "bytes", "sha256"} or row["name"] not in {"frame-before.ppm", "frame-after.ppm"}
                or type(row["bytes"]) is not int or not 0 < row["bytes"] <= 16 * 1024 ** 2 or type(row["sha256"]) is not str
                or _HEX.fullmatch(row["sha256"]) is None or type(carried.get(row["name"])) is not str):
            return None
        raw = __import__("zlib").decompress(base64.b64decode(carried[row["name"]], validate=True))
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            return None
        try:
            login._retain_local(directory, row["name"], raw)
        except FileExistsError:
            if hashlib.sha256(uac._read_private(directory / row["name"], 16 * 1024 ** 2)).hexdigest() != row["sha256"]:
                return None
        kept.append({"name": row["name"], "sha256": row["sha256"], "path": str(directory / row["name"])})
    return kept


def settle(root, inputs, *, deadline=None):
    """One settle of one clone's ordinary desktop. A direct call and the public route run this same function.

    The first call sends its packet under a create-only journal; every later call is a repeat packet, so a lost reply
    never probes, frames or keys a second time.
    """
    if deadline is None:
        deadline = time.monotonic() + uac.SUBMIT_SECONDS + 10
    reply, admitted = _gates(root, inputs)
    if reply is not None:
        return reply
    root, binding = admitted.root, admitted.binding
    operation = inputs["operationId"]
    directory = uac._journal_directory(root, operation, _SETTLES)
    intended = {"operationId": operation, "deploymentId": inputs["deploymentId"], "host": binding["spec"]["host"], "replayAllowed": False}
    try:
        login._retain_local(directory, "intent.json", intended)
    except FileExistsError:
        if json.loads(uac._read_private(directory / "intent.json")) != intended:
            raise ValueError("windows_desktop_settle_original_changed") from None
    first = not admitted.repeat
    if first:
        source = program(binding, operation)
        try:
            login._retain_local(directory, "settle.intent.json", {"operationId": operation, "sourceSha256": hashlib.sha256(source).hexdigest(),
                                                                  "replayAllowed": False})
        except FileExistsError:
            first = False
        else:
            login._retain_local(directory, "settle.py", source)
    if not first:
        source = program(binding, operation, repeat=True)
    try:
        result = uac._send(root, binding["spec"]["host"], operation, source, None, deadline)
    except uac._Unsubmitted:
        projected = _refused("desktop_settle_transport_unsubmitted", inputs) if first else {**_refused("desktop_settle_transport_unsubmitted", inputs), "state": "unknown"}
    except Exception:  # A lost reply: the packet may still be running, so this operation only reads its terminal from now on.
        return {**_refused("desktop_settle_unresolved", inputs), "state": "unknown"}
    else:
        value = uac._reply(result, None)
        frames = _frames(directory, value) if type(value) is dict and value.get("state") in {"desktop-settled", "desktop-settle-refused"} else []
        projected = {"state": "unknown", "reason": "desktop_settle_reply_rejected", "operationId": operation,
                     "deploymentId": inputs["deploymentId"], "replayAllowed": False} if frames is None else _project(
                         {key: item for key, item in value.items() if key != "frameBytes"} if type(value) is dict else value, inputs, frames)
    if projected["state"] in {"desktop-settled", "desktop-settle-refused", "refused"}:
        uac._retain_once(directory, "result.json", projected)
    return projected
