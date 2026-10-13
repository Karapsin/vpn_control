#!/usr/bin/env python3
"""Fixed owned Linux GUI lifecycle scenario; never stops a protected owner.

The direct engineering functions are retained below. Receipt admission supplies
current actor identities; historical PIDs, displays and package lineage are not
execution defaults. Xlib executes only in a separate fixed helper interpreter.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, stat, subprocess, sys, threading, time, traceback, uuid
from pathlib import Path

SCENARIO = "linux-owner-gui-lifecycle"
SCHEMA = "vpn-control.linux-owner-gui-lifecycle.input"
RECEIPT_SCHEMA = "vpn-control.linux-owner-gui-lifecycle.receipt"
LAUNCHER = "/opt/vpn-control/bin/vpn-control"
BODY = b"owned-linux-proxy-traffic-proof\n"
class ScenarioError(RuntimeError): pass
class OutcomeUnknown(ScenarioError): pass

def require(value, reason):
    if not value: raise ScenarioError(reason)

def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result

def start_gui():
    global gui, gui_birth, gui_counter
    gui_counter += 1
    label = 'gui-' + str(gui_counter)
    with private_stream(R / (label + '.stdout.private')) as out, private_stream(R / (label + '.stderr.private')) as err:
        gui = subprocess.Popen(['/opt/vpn-control/bin/vpn-control', '--state-dir', str(W)], stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=owner_env, start_new_session=True)
    gui_birth = birth(gui.pid)
    if 'owned_actors' in globals(): owned_actors.append({'pid':gui.pid,'startTicks':gui_birth,'uid':os.getuid(),'role':'frontend'})
    durable(R / (label + '.handle.public.json'), {'pid': gui.pid, 'startTicks': gui_birth, 'uid': os.getuid(), 'ownerControllerId': cid, 'privateDisplay': display_env['DISPLAY']})
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        assert gui.poll() is None and birth(gui.pid) == gui_birth
        p = subprocess.run(['/usr/bin/xdotool', 'search', '--onlyvisible', '--pid', str(gui.pid)], capture_output=True, env=display_env, timeout=5)
        windows = []
        for leaf in p.stdout.decode().splitlines():
            if not leaf.isdecimal():
                continue
            width, height, mapped = window_state(int(leaf))
            if width >= 500 and height >= 300 and (mapped == 'IsViewable'):
                windows.append(int(leaf))
        if windows:
            assert len(windows) == 1
            window = windows[0]
            prop = subprocess.run(['/usr/bin/xprop', '-id', str(window), '_NET_WM_PID'], capture_output=True, env=display_env, timeout=5)
            assert prop.returncode == 0 and prop.stdout.decode().strip().endswith('= ' + str(gui.pid))
            return window
        time.sleep(0.2)
    raise RuntimeError('owned_gui_window_not_ready')


def window_state(window):
  p=subprocess.run(['/usr/bin/xwininfo','-id',str(window)],capture_output=True,env=display_env,timeout=5);assert p.returncode==0 and not p.stderr
  s=p.stdout.decode();width=int(re.search(r'Width: (\d+)',s).group(1));height=int(re.search(r'Height: (\d+)',s).group(1));mapped=re.search(r'Map State: (\w+)',s).group(1)
  return width,height,mapped


def visible_main():
 assert gui.poll()is None and birth(gui.pid)==gui_birth
 p=subprocess.run(['/usr/bin/xdotool','search','--onlyvisible','--pid',str(gui.pid)],capture_output=True,env=display_env,timeout=5);rows=[]
 for leaf in p.stdout.decode().splitlines():
  if not leaf.isdecimal():continue
  q=subprocess.run(['/usr/bin/xwininfo','-id',leaf],capture_output=True,env=display_env,timeout=5)
  if q.returncode:continue
  text=q.stdout.decode();width=int(re.search(r'Width: (\d+)',text).group(1));height=int(re.search(r'Height: (\d+)',text).group(1))
  if width>=500 and height>=300 and 'Map State: IsViewable'in text:rows.append(int(leaf))
 return rows


def visible_window():
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  rows=visible_main()
  if rows:assert len(rows)==1;return rows[0]
  time.sleep(.1)
 raise RuntimeError('frontend_not_visible')


def hidden_frontend():
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  assert gui.poll()is None and birth(gui.pid)==gui_birth
  if not visible_main():return
  time.sleep(.1)
 raise RuntimeError('frontend_not_hidden')


def matched_status():
 v=invoke('status');assert owner.poll()is None and v['controllerId']==cid and v['data']['runtimeRunning']is True and v['data']['runtimeId']==runtime_id and v['data']['configuredMode']==v['data']['activeMode']=='proxy-only';return v


def checkpoint(label,start):
  time.sleep(1.6);matched_status();assert not flow_errors and stream.is_alive()and len(frames)-start>=10;slices.append({'action':label,'frames':len(frames)-start,'sameController':True,'sameRuntime':True})


def request_owned_wm_close(window, pid, start_ticks, display_env, admitted_display):
    import ctypes as c
    import ctypes.util
    import os
    from pathlib import Path
    if any(type(value) is not int or value <= 0 for value in (window, pid, start_ticks)):
        raise RuntimeError('invalid_owned_window_identity')
    def process_matches():
        proc = Path('/proc') / str(pid)
        return (proc.exists() and proc.stat().st_uid == os.getuid()
                and int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]) == start_ticks)
    if not process_matches() or display_env['DISPLAY'] != admitted_display:
        raise RuntimeError('owned_window_process_changed')
    class Data(c.Union):
        _fields_ = [('bytes', c.c_char * 20), ('shorts', c.c_short * 10), ('longs', c.c_long * 5)]
    class Message(c.Structure):
        _fields_ = [('type', c.c_int), ('serial', c.c_ulong), ('send_event', c.c_int),
                    ('display', c.c_void_p), ('window', c.c_ulong), ('message_type', c.c_ulong),
                    ('format', c.c_int), ('data', Data)]
    class Event(c.Union):
        _fields_ = [('message', Message), ('pad', c.c_long * 24)]
    if c.sizeof(c.c_long) != 8 or c.sizeof(Event) != 192 or Message.data.offset != 56:
        raise RuntimeError('unsupported_native_xlib_abi')
    library = ctypes.util.find_library('X11')
    if library != 'libX11.so.6':
        raise RuntimeError('native_xlib_unavailable')
    x = c.CDLL(library)
    signatures = {
        'XOpenDisplay': ([c.c_char_p], c.c_void_p),
        'XDefaultRootWindow': ([c.c_void_p], c.c_ulong),
        'XInternAtom': ([c.c_void_p, c.c_char_p, c.c_int], c.c_ulong),
        'XGrabServer': ([c.c_void_p], c.c_int),
        'XUngrabServer': ([c.c_void_p], c.c_int),
        'XGetWindowProperty': ([c.c_void_p,c.c_ulong,c.c_ulong,c.c_long,c.c_long,c.c_int,c.c_ulong,
                               c.POINTER(c.c_ulong),c.POINTER(c.c_int),c.POINTER(c.c_ulong),
                               c.POINTER(c.c_ulong),c.POINTER(c.POINTER(c.c_ubyte))],c.c_int),
        'XGetWMProtocols': ([c.c_void_p,c.c_ulong,c.POINTER(c.POINTER(c.c_ulong)),c.POINTER(c.c_int)],c.c_int),
        'XFree': ([c.c_void_p],c.c_int),
        'XSendEvent': ([c.c_void_p,c.c_ulong,c.c_int,c.c_long,c.POINTER(Event)],c.c_int),
        'XSync': ([c.c_void_p,c.c_int],c.c_int),
        'XCloseDisplay': ([c.c_void_p],c.c_int),
        'XSetErrorHandler': ([c.c_void_p],c.c_void_p),
    }
    for name,(arguments,result) in signatures.items():
        getattr(x,name).argtypes=arguments;getattr(x,name).restype=result
    prior=os.environ.get('XAUTHORITY');os.environ['XAUTHORITY']=display_env['XAUTHORITY']
    errors=[]
    @c.CFUNCTYPE(c.c_int,c.c_void_p,c.c_void_p)
    def error_handler(display,error):
        errors.append(True);return 0
    old_handler=x.XSetErrorHandler(c.cast(error_handler,c.c_void_p))
    display=None;grabbed=False
    try:
        display=x.XOpenDisplay(admitted_display.encode('ascii'))
        if not display:raise RuntimeError('owned_display_unavailable')
        root=x.XDefaultRootWindow(display)
        x.XGrabServer(display);grabbed=True
        actual_type=c.c_ulong();format=c.c_int();count=c.c_ulong();remaining=c.c_ulong();value=c.POINTER(c.c_ubyte)()
        cardinal=x.XInternAtom(display,b'CARDINAL',False);pid_atom=x.XInternAtom(display,b'_NET_WM_PID',True)
        rc=x.XGetWindowProperty(display,window,pid_atom,0,1,False,cardinal,c.byref(actual_type),c.byref(format),c.byref(count),c.byref(remaining),c.byref(value))
        try:
            if rc!=0 or actual_type.value!=cardinal or format.value!=32 or count.value!=1 or remaining.value!=0 or not value or c.cast(value,c.POINTER(c.c_ulong))[0]!=pid:
                raise RuntimeError('owned_window_pid_changed')
        finally:
            if value:x.XFree(value)
        protocols=c.POINTER(c.c_ulong)();size=c.c_int()
        rc=x.XGetWMProtocols(display,window,c.byref(protocols),c.byref(size))
        try:
            delete=x.XInternAtom(display,b'WM_DELETE_WINDOW',True)
            if not rc or not protocols or not 0<size.value<=64 or not delete or delete not in protocols[:size.value]:
                raise RuntimeError('owned_window_graceful_close_unsupported')
        finally:
            if protocols:x.XFree(protocols)
        if errors or not process_matches():raise RuntimeError('owned_window_process_changed')
        atom=x.XInternAtom(display,b'_NET_CLOSE_WINDOW',True)
        if not atom:raise RuntimeError('window_manager_close_unavailable')
        event=Event();event.message.type=33;event.message.send_event=True;event.message.display=display
        event.message.window=window;event.message.message_type=atom;event.message.format=32
        event.message.data.longs[0]=0;event.message.data.longs[1]=2
        if not x.XSendEvent(display,root,False,(1<<19)|(1<<20),c.byref(event)):
            raise RuntimeError('window_manager_close_send_failed')
        x.XUngrabServer(display);grabbed=False;x.XSync(display,False)
        if errors:raise RuntimeError('window_manager_close_x_error')
    finally:
        if display:
            if grabbed:x.XUngrabServer(display)
            x.XCloseDisplay(display)
        x.XSetErrorHandler(old_handler)
        if prior is None:os.environ.pop('XAUTHORITY',None)
        else:os.environ['XAUTHORITY']=prior


def _uuid(value):
    try: require(type(value) is str and str(uuid.UUID(value)) == value, 'invalid_uuid')
    except (ValueError, AttributeError, TypeError): raise ScenarioError('invalid_uuid')
    return value

def _sha(value, length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value), 'invalid_sha')
    return value

def _artifact(value):
    require(type(value) is str and re.fullmatch('sha256-[0-9a-f]{64}', value), 'invalid_artifact')
    return value

def exact(value, keys, label):
    require(type(value) is dict and set(value) == set(keys), label + '_keys')
    return value

def absolute(value):
    require(type(value) is str and value.startswith('/') and str(Path(value)) == value
            and not any(p in ('', '.', '..') for p in value.split('/')[1:])
            and not any(ord(c) < 32 for c in value), 'unsafe_absolute_path')
    return Path(value)

def validate_input(document, correlation=None):
    exact(document, ('schema','schemaVersion','scenarioId','correlationId','sourceIdentity',
        'installedPackage','guestAdmissionArtifactId','displayAdmissionArtifactId',
        'fixtureAdmissionArtifactId','protectedOwnerArtifactId','maxObservationSeconds'), 'input')
    require(document['schema'] == SCHEMA and type(document['schemaVersion']) is int
            and document['schemaVersion'] == 1 and document['scenarioId'] == SCENARIO, 'input_schema')
    _uuid(document['correlationId'])
    require(correlation is None or document['correlationId'] == correlation, 'correlation_mismatch')
    source = exact(document['sourceIdentity'], ('sourceSha','sourceFingerprint','artifactSetId'), 'source')
    _sha(source['sourceSha'],40); _sha(source['sourceFingerprint'])
    require(type(source['artifactSetId']) is str and re.fullmatch('artifact-set-[0-9a-f]{64}',source['artifactSetId']), 'artifact_set_identity')
    package = exact(document['installedPackage'], ('artifactId','version','sha256','desktopMainJarSha256'), 'package')
    _artifact(package['artifactId']); _sha(package['sha256']); _sha(package['desktopMainJarSha256'])
    require(package['artifactId'] == 'sha256-'+package['sha256'], 'package_digest_binding')
    require(type(package['version']) is str and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.+]+)?',package['version']), 'package_version')
    for field in ('guestAdmissionArtifactId','displayAdmissionArtifactId','fixtureAdmissionArtifactId','protectedOwnerArtifactId'):
        _artifact(document[field])
    require(type(document['maxObservationSeconds']) is int and document['maxObservationSeconds'] == 180, 'flow_duration')
    return document

def durable(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, sort_keys=True); out.write('\n');out.flush();os.fsync(out.fileno())
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(d)
    finally: os.close(d)

def birth(pid):
    return int(Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()[19])

def private_stream(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')

def process_matches(actor, *, executable=None, state=None, role=None):
    exact(actor, ('pid','startTicks','uid'), 'actor')
    require(all(type(actor[k]) is int and actor[k] > 0 for k in ('pid','startTicks'))
            and type(actor['uid']) is int and actor['uid'] == os.getuid(), 'actor_identity')
    p = Path('/proc')/str(actor['pid'])
    require(p.stat().st_uid == actor['uid'] and birth(actor['pid']) == actor['startTicks'], 'actor_generation')
    if executable: require(os.readlink(p/'exe') == executable, 'actor_executable')
    if state is not None:
        args=(p/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        require(str(state).encode() in args and (b'serve' in args if role=='owner' else b'serve' not in args), 'actor_role')
    require(birth(actor['pid']) == actor['startTicks'], 'actor_generation')

class OwnedProcess:
    def __init__(self, process):
        self.process=process;self.pid=process.pid;self.tick=birth(self.pid)
        self.actor={'pid':self.pid,'startTicks':self.tick,'uid':os.getuid()}
    def poll(self):
        rc=self.process.poll()
        if rc is None: process_matches(self.actor)
        return rc
    def wait(self,timeout): return self.process.wait(timeout=timeout)

def invoke(*args, timeout=40):
    global counts
    counts += 1;label='cli-'+str(counts)
    durable(R/(label+'.intent.public.json'), {'argvTail':list(args),'controllerId':cid,'replayAllowed':False})
    with private_stream(R/(label+'.stdout.private')) as out,private_stream(R/(label+'.stderr.private')) as err:
        p=subprocess.Popen([LAUNCHER,'--state-dir',str(W),'--json',*(['--controller-id',cid] if cid else []),*args],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env)
        durable(R/(label+'.handle.public.json'),{'pid':p.pid,'startTicks':birth(p.pid),'uid':os.getuid()})
        try: code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired: raise OutcomeUnknown('accepted_cli_timeout')
    raw=(R/(label+'.stdout.private')).read_bytes();require(len(raw)<1048576,'cli_bound')
    v=json.loads(raw,object_pairs_hook=pairs)
    durable(R/(label+'.result.public.json'),{'code':v.get('code'),'final':v.get('final'),'controllerId':v.get('controllerId'),'operationId':v.get('operationId'),'exitCode':code})
    require(code==0 and v.get('code')=='OK' and v.get('final') is True and (cid is None or v.get('controllerId')==cid),'cli_rejected_or_unresolved')
    return v

def fixed_source():
    return source_custody().body(FixedGuiSourceCustody.DRIVER)

def isolated_helper(arguments):
    custody=source_custody();command=custody.python_command(arguments)
    # argv and output configuration are complete before the joined closing.
    options={'env':display_env,'stdin':subprocess.DEVNULL,'capture_output':True,'timeout':10}
    custody.finish();custody.finish()
    return subprocess.run(command,**options)


def start_fixture_child(input_path,admissions_path,root,out,err):
    custody=source_custody()
    command=custody.python_command(['--fixture-worker',str(input_path),str(admissions_path),str(root)])
    options={'stdin':subprocess.DEVNULL,'stdout':out,'stderr':err,'start_new_session':True}
    custody.finish();custody.finish()
    return subprocess.Popen(command,**options)


def wm_close(window):
    done=isolated_helper(['--wm-close-helper',str(window),str(gui.pid),str(gui_birth),display_env['DISPLAY']])
    require(done.returncode==0 and not done.stdout and not done.stderr,'wm_close_helper_unknown')


def wm_close_show_cycle(window):
    start=len(frames);wm_close(window);hidden_frontend();checkpoint('graceful-close-to-tray',start)
    start=len(frames);invoke('gui','show');window=visible_window();checkpoint('show-after-legitimate-XID-change',start)
    return window

def wait_crash_lease(absent_pids):
    require(all(type(pid) is int and pid>0 for pid in absent_pids),'invalid_absence_set')
    require(all(not Path('/proc/%d'%pid).exists() for pid in absent_pids),'crashed_actor_not_absent')
    start=len(frames);deadline=time.monotonic()+16
    while time.monotonic()<deadline:
        require(owner.poll() is None and not any(Path('/proc/%d'%pid).exists() for pid in absent_pids)
                and not flow_errors,'crash_lease_identity_or_traffic')
        time.sleep(.1)
    checkpoint('bounded-crash-lease-expiry-with-runtime-traffic',start)

def pin_worker_source(original, bind):
    digest = hashlib.sha256(original).hexdigest()
    bound = bind(original)
    return bound, digest

def worker_source():
    # The immutable actually used worker is hashed before any role/path binding.
    source=source_custody().body(FixedGuiSourceCustody.SOCKS)
    return pin_worker_source(source, lambda value: value)

def tray_owner():
    done=isolated_helper(['--tray-owner-helper',display_env['DISPLAY']])
    require(done.returncode==0 and not done.stderr and done.stdout.strip().isdigit(),'tray_observation_unknown')
    return int(done.stdout.strip())


def _tray_owner_helper(display_name):
    import ctypes as c
    x=c.CDLL('libX11.so.6');x.XOpenDisplay.argtypes=[c.c_char_p];x.XOpenDisplay.restype=c.c_void_p
    x.XInternAtom.argtypes=[c.c_void_p,c.c_char_p,c.c_int];x.XInternAtom.restype=c.c_ulong
    x.XGetSelectionOwner.argtypes=[c.c_void_p,c.c_ulong];x.XGetSelectionOwner.restype=c.c_ulong
    x.XCloseDisplay.argtypes=[c.c_void_p]
    d=x.XOpenDisplay(display_name.encode('ascii'));require(bool(d),'display_authentication')
    try: print(int(x.XGetSelectionOwner(d,x.XInternAtom(d,b'_NET_SYSTEM_TRAY_S0',False))))
    finally: x.XCloseDisplay(d)


def regular(path, maximum, private=False, single_link=True):
    path=absolute(str(path));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and (not single_link or before.st_nlink==1) and 0<before.st_size<=maximum,'unsafe_regular_file')
        if private: require(before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600,'unsafe_private_file')
        raw=os.read(fd,maximum+1);after=os.fstat(fd)
        require(len(raw)==before.st_size and generation(before)==generation(after)==generation(path.lstat()),'file_generation_drift')
        return raw
    finally: os.close(fd)

def generation(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def private_directory(path):
    path=absolute(str(path));cursor=Path('/')
    for leaf in path.parts[1:]:
        cursor/=leaf;st=cursor.lstat();require(stat.S_ISDIR(st.st_mode),'unsafe_directory_ancestry')
    st=path.lstat();require(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,'unsafe_private_directory')
    return path

def protected_status(admission):
    actor=admission['owner'];state=absolute(admission['stateDir']);process_matches(actor,state=state,role='owner')
    p=subprocess.run([LAUNCHER,'--state-dir',str(state),'--json','--controller-id',admission['controllerId'],'status'],capture_output=True,env=env,timeout=15)
    require(p.returncode==0 and len(p.stdout)<1048576,'protected_status_unavailable')
    v=json.loads(p.stdout,object_pairs_hook=pairs);d=v.get('data')
    require(v.get('controllerId')==admission['controllerId'] and v.get('final') is True
        and v.get('code')=='OK' and type(d) is dict
        and {k:d.get(k) for k in admission['runtime']}==admission['runtime'],'protected_owner_or_runtime_changed')
    process_matches(actor,state=state,role='owner')
    require(hashlib.sha256(regular(state/'workspace.json',4*1024*1024,True)).hexdigest()==admission['workspaceSha256'],'protected_workspace_changed')
    return True

PRIVILEGED_READ_CAPABILITY = r'''
import json,os,sys
from pathlib import Path
def demand(ok, reason):
 if not ok:raise RuntimeError(reason)
demand(os.getuid()==0 and os.geteuid()==0,'read_capability_root_required')
v=json.loads(sys.argv[1]);demand(set(v)=={'boot','uid','caller','ticks'},'read_capability_schema')
demand(all(type(v[k])is int and v[k]>0 for k in('uid','caller','ticks')),'read_capability_identity')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();demand(boot==v['boot'],'read_capability_boot_changed')
def identity(p):
 return p.stat().st_uid,int((p/'stat').read_text().rsplit(')',1)[1].split()[19])
caller=Path('/proc')/str(v['caller']);demand(identity(caller)==(v['uid'],v['ticks']),'read_capability_caller_changed')
count=0
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:
  uid,ticks=identity(p)
  if uid!=v['uid']:continue
  if(p/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':continue
  for leaf in[p/'cwd',p/'root',*list((p/'fd').iterdir())]:
   try:os.readlink(leaf)
   except FileNotFoundError:continue
  demand(identity(p)==(uid,ticks),'read_capability_process_changed');count+=1
 except FileNotFoundError:continue
demand(identity(caller)==(v['uid'],v['ticks'])and count>0,'read_capability_caller_changed')
print(json.dumps({'schemaVersion':1,'complete':True,'effectiveUid':os.geteuid(),'realUid':os.getuid(),'boot':boot,'caller':v['caller'],'callerUid':v['uid'],'ticks':v['ticks'],'observedProcesses':count},separators=(',',':')))
'''

def _admit_privileged_read_capability():
    import sys
    caller=os.getpid();ticks=birth(caller);uid=os.getuid();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    value={'boot':boot,'uid':uid,'caller':caller,'ticks':ticks}
    p=subprocess.run(['/usr/bin/sudo','-n',sys.executable,'-I','-c',PRIVILEGED_READ_CAPABILITY,json.dumps(value,separators=(',',':'))],capture_output=True,timeout=15)
    require(p.returncode==0 and not p.stderr and len(p.stdout)<4096,'privileged_read_capability_unavailable')
    try:result=json.loads(p.stdout,object_pairs_hook=pairs)
    except (ValueError,TypeError):raise ScenarioError('privileged_read_capability_malformed')
    require(type(result)is dict and set(result)=={'schemaVersion','complete','effectiveUid','realUid','boot','caller','callerUid','ticks','observedProcesses'},'privileged_read_capability_malformed')
    require(all(type(result[k])is int for k in('schemaVersion','effectiveUid','realUid','caller','callerUid','ticks','observedProcesses'))
        and result['schemaVersion']==1 and result['complete']is True and result['effectiveUid']==result['realUid']==0 and result['observedProcesses']>0,'privileged_read_capability_incomplete')
    require(result['boot']==boot and result['caller']==caller and result['callerUid']==uid and result['ticks']==ticks and birth(caller)==ticks,'privileged_read_capability_identity_changed')
    return result

def admission_probe(spec, admissions):
    global env,display_env
    require(sys.platform.startswith('linux') and os.getuid()!=0,'linux_owned_user_required')
    exact(admissions,('guest','display','fixture','protected','source'),'admissions')
    guest=admissions['guest'];display=admissions['display'];fixture=admissions['fixture'];protected=admissions['protected']
    exact(guest,('schema','schemaVersion','host','environment','bootId','uid','allocation','ownedRoot'),'guest')
    require(guest['schema']=='vpn-control.linux-owner-gui.guest' and type(guest['schemaVersion']) is int and guest['schemaVersion']==1,'guest_schema')
    require(guest['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and guest['uid']==os.getuid(),'guest_generation')
    _admit_privileged_read_capability()
    owned_root=private_directory(guest['ownedRoot'])
    for retained in owned_root.iterdir():
        if retained.name.startswith('gui-lifecycle-'):
            st=retained.lstat();require(stat.S_ISDIR(st.st_mode) and st.st_uid==os.getuid(),'retained_original_directory')
            require(not (retained/'workspace').exists() and not (retained/'workspace').is_symlink(),'prior_original_workspace_retained')
    require(int(next(row.split()[1] for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemAvailable:')))*1024>1073741824,'guest_memory')
    exact(display,('schema','schemaVersion','bootId','uid','display','xauthorityPath','xauthorityGeneration','xserver','wm','tray','dependencies'),'display')
    require(display['schema']=='vpn-control.linux-owner-gui.display' and type(display['schemaVersion']) is int and display['schemaVersion']==1
            and display['bootId']==guest['bootId'] and display['uid']==guest['uid'],'display_guest_binding')
    require(type(display['display']) is str and re.fullmatch(':[1-9][0-9]{0,3}',display['display']),'private_display')
    auth=absolute(display['xauthorityPath']);info=auth.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600
            and list(generation(info))==display['xauthorityGeneration'],'xauthority_metadata')
    sock=Path('/tmp/.X11-unix')/('X'+display['display'][1:]);st=sock.lstat()
    require(stat.S_ISSOCK(st.st_mode) and st.st_uid==os.getuid(),'private_display_socket')
    for role in ('xserver','wm','tray'): process_matches(display[role])
    dependencies=display['dependencies']
    expected={'Xvfb','openbox','xdotool','xwininfo','xprop','xauth','trayer','curl','openssl'}
    require(type(dependencies) is dict and set(dependencies)==expected,'dependency_inventory')
    for name,record in dependencies.items():
        exact(record,('path','sha256','package','version'),'dependency')
        require(record['path']=='/usr/bin/'+name,'dependency_path')
        require(hashlib.sha256(regular(record['path'],16*1024*1024)).hexdigest()==_sha(record['sha256']),'dependency_bytes')
        result=subprocess.run(['dpkg-query','-W','-f=${Version}',record['package']],capture_output=True,timeout=10)
        require(result.returncode==0 and result.stdout.decode()==record['version'],'dependency_package')
    env=dict(os.environ)
    for key in ('DISPLAY','WAYLAND_DISPLAY','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):env.pop(key,None)
    display_env={**env,'DISPLAY':display['display'],'XAUTHORITY':str(auth)}
    require(tray_owner()!=0,'tray_unavailable')
    query=subprocess.run(['dpkg-query','-W','-f=${Version}','vpn-control'],capture_output=True,timeout=10)
    require(query.returncode==0 and query.stdout.decode()==spec['installedPackage']['version'],'installed_package_version')
    jars=list(Path('/opt/vpn-control/lib/app').glob('desktopApp-*.jar'))
    require(len(jars)==1 and hashlib.sha256(regular(jars[0],128*1024*1024)).hexdigest()==spec['installedPackage']['desktopMainJarSha256'],'installed_jar')
    source=admissions['source'];require(source['targetSourceSha']==spec['sourceIdentity']['sourceSha']
            and source['packageSha256']==spec['installedPackage']['sha256'],'source_package_binding')
    require(type(source['installedFiles']) is list and source['installedFiles'],'installed_file_inventory')
    for record in source['installedFiles']:
        require(record['path'].startswith('/opt/vpn-control/'),'installed_file_path')
        if 'symlinkTarget' in record:
            exact(record,('path','sha256','symlinkTarget'),'installed_link')
            require(absolute(record['path']).is_symlink() and os.readlink(record['path'])==record['symlinkTarget']
                    and hashlib.sha256(record['symlinkTarget'].encode()).hexdigest()==_sha(record['sha256']),'installed_link_changed')
        else:
            exact(record,('path','sha256'),'installed_file')
            require(hashlib.sha256(regular(record['path'],256*1024*1024,single_link=False)).hexdigest()==_sha(record['sha256']),'installed_file_digest')
    exact(fixture,('schema','schemaVersion','bootId','uid','sourceSha256','certificatePath','certificateSha256','keyPath','trustStorePath','trustStoreSha256','socksPort','httpsPort'),'fixture')
    require(fixture['schema']=='vpn-control.linux-owner-gui.fixture' and type(fixture['schemaVersion']) is int and fixture['schemaVersion']==1
            and fixture['bootId']==guest['bootId'] and fixture['uid']==guest['uid'],'fixture_guest_binding')
    require(fixture['sourceSha256']==worker_source()[1],'fixture_source_pin')
    for label in ('certificate','trustStore'):
        require(hashlib.sha256(regular(fixture[label+'Path'],1048576,True)).hexdigest()==_sha(fixture[label+'Sha256']),'fixture_trust_bytes')
    key=absolute(fixture['keyPath']);st=key.lstat();require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,'fixture_key_metadata')
    ports=(fixture['socksPort'],fixture['httpsPort']);require(len(set(ports))==2 and all(type(p) is int and 1024<=p<=65535 for p in ports),'fixture_ports')
    for name in ('tcp','tcp6'):
        for row in (Path('/proc/net')/name).read_text().splitlines()[1:]:
            cols=row.split();require(not(cols[3]=='0A' and int(cols[1].rsplit(':',1)[1],16) in ports),'fixture_foreign_listener')
    exact(protected,('schema','schemaVersion','bootId','uid','stateDir','owner','controllerId','runtime','workspaceSha256'),'protected')
    require(protected['schema']=='vpn-control.linux-owner-gui.protected' and type(protected['schemaVersion']) is int and protected['schemaVersion']==1
            and protected['bootId']==guest['bootId'] and protected['uid']==guest['uid'],'protected_guest_binding')
    _uuid(protected['controllerId']);_sha(protected['workspaceSha256'])
    exact(protected['runtime'],('runtimeId','runtimeRunning','configuredMode','activeMode','activeLocationId','selectedLocationId'),'protected_runtime')
    protected_status(protected)
    owned=absolute(guest['ownedRoot']);other=absolute(protected['stateDir'])
    require(owned!=other and owned not in other.parents and other not in owned.parents,'protected_workspace_overlap')
    return {'ready':True,'scope':'fresh-guest-fixed-gui-admission'}


def fixture_worker(spec, admission, root):
    from socks_http_fixture import FixtureServer
    import http.server, ssl
    fixture=admission['fixture'];guest=admission['guest']
    require(guest['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip() and guest['uid']==os.getuid(),'worker_guest_identity')
    cert=regular(fixture['certificatePath'],1048576,True);trust=regular(fixture['trustStorePath'],1048576,True)
    require(hashlib.sha256(cert).hexdigest()==fixture['certificateSha256'] and hashlib.sha256(trust).hexdigest()==fixture['trustStoreSha256'],'worker_trust_bytes')
    class Forward(FixtureServer):
        def should_forward(self,host,port):return host in ('localhost','127.0.0.1','::1') and port==fixture['httpsPort']
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path!='/traffic':self.send_error(404);return
            self.send_response(200);self.send_header('Content-Length',str(len(BODY)));self.end_headers();self.wfile.write(BODY)
        def log_message(self,*args):pass
    certfd=os.open(fixture['certificatePath'],os.O_RDONLY|os.O_NOFOLLOW);keyfd=os.open(fixture['keyPath'],os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(keyfd);require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,'worker_private_key')
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/proc/self/fd/'+str(certfd),'/proc/self/fd/'+str(keyfd))
    finally:os.close(certfd);os.close(keyfd)
    tls=http.server.ThreadingHTTPServer(('127.0.0.1',fixture['httpsPort']),Handler);tls.daemon_threads=True;tls.socket=context.wrap_socket(tls.socket,server_side=True)
    ledger=root/'socks-ledger.private.jsonl';ledger.touch(mode=0o600,exist_ok=False)
    relay=Forward('127.0.0.1',fixture['socksPort'],'owned',ledger,forward_host='localhost',forward_port=fixture['httpsPort'])
    servers=[tls,relay];threads=[]
    for server in servers:
        t=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.1},daemon=True);t.start();threads.append(t)
    # Creation is not readiness: authenticate TLS hostname and body before publishing.
    import urllib.request
    context=ssl.create_default_context(cafile=fixture['certificatePath'])
    with urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context)).open('https://localhost:%d/traffic'%fixture['httpsPort'],timeout=5) as response:
        require(response.read(4096)==BODY,'worker_tls_self_probe')
    durable(root/'fixture-ready.public.json',{'pid':os.getpid(),'startTicks':birth(os.getpid()),'uid':os.getuid(),
        'relayPort':fixture['socksPort'],'tlsPort':fixture['httpsPort'],'trustVerified':True})
    while not (root/'fixture-stop.private').exists(): time.sleep(.1)
    for server in servers:server.shutdown();server.server_close()
    for thread in threads:thread.join(timeout=5);require(not thread.is_alive(),'fixture_thread_retained')
    durable(root/'fixture-terminal.public.json',{'pid':os.getpid(),'startTicks':birth(os.getpid()),'threadsClosed':True,'stopMarkerObserved':True})

def _listeners_absent(ports):
    for name in ('tcp','tcp6'):
        for row in (Path('/proc/net')/name).read_text().splitlines()[1:]:
            fields=row.split()
            if int(fields[1].rsplit(':',1)[1],16) in ports:
                require(fields[3]!='0A' and fields[9]=='0','fixture_socket_retained')

def _verify_worker_ports(worker,ports):
    process_matches(worker.actor)
    sockets=set()
    for path in (Path('/proc')/str(worker.pid)/'fd').iterdir():
        try:target=os.readlink(path)
        except FileNotFoundError:continue
        if target.startswith('socket:['):sockets.add(target[8:-1])
    observed=set()
    for name in ('tcp','tcp6'):
        for row in (Path('/proc/net')/name).read_text().splitlines()[1:]:
            fields=row.split();port=int(fields[1].rsplit(':',1)[1],16)
            if port in ports and fields[3]=='0A':
                require(fields[9] in sockets,'fixture_foreign_socket');observed.add(port)
    require(observed==set(ports),'fixture_socket_ownership')

def _stop_owned_tray(actor):
    process_matches(actor,executable='/usr/bin/trayer')
    durable(R/'tray-stop-intent.public.json',{'actor':actor,'display':display_env['DISPLAY'],'nonProductDisplayFixtureOnly':True})
    os.kill(actor['pid'],15);deadline=time.monotonic()+15
    while Path('/proc/%d'%actor['pid']).exists() and time.monotonic()<deadline:
        process_matches(actor);time.sleep(.1)
    require(not Path('/proc/%d'%actor['pid']).exists(),'tray_stop_unknown')

def _crash_owned_frontend():
    process_matches({'pid':gui.pid,'startTicks':gui_birth,'uid':os.getuid()},state=W,role='frontend')
    require(gui.pid!=owner.pid and os.readlink('/proc/%d/exe'%gui.pid).startswith('/opt/vpn-control/'),'frontend_only_crash')
    durable(R/'frontend-crash-intent.public.json',{'pid':gui.pid,'startTicks':gui_birth,'controllerId':cid,'runtimeId':runtime_id,'frontendOnly':True})
    gui.kill();gui.wait(timeout=15)
    require(not Path('/proc/%d'%gui.pid).exists(),'frontend_crash_unknown')

def run_scenario(spec,admissions,receipt_path):
    global R,W,cid,runtime_id,owner,env,owner_env,display_env,gui,gui_birth,gui_counter,counts,frames,slices,flow_errors,stream,owned_actors
    gui=None;gui_birth=None;gui_counter=counts=0;frames=[];slices=[];flow_errors=[];cid=None;owned_actors=[]
    flow_stop=threading.Event();worker=None;new_tray=None;owner=None;stream=None
    record={'schema':RECEIPT_SCHEMA,'schemaVersion':1,'scenarioId':SCENARIO,'correlationId':spec['correlationId'],
        'result':'unknown','sourceIdentity':spec['sourceIdentity'],'packageSourceSha':admissions['source']['packageSourceSha'],
        'cleanup':{'state':'not-started','ownerStopped':False,'protectedPreserved':False,'workspaceRemoved':False,'referencesAbsent':False},'replayAllowed':False}
    try:
        record['preflight']=admission_probe(spec,admissions)
        parent=private_directory(admissions['guest']['ownedRoot']);R=parent/('gui-lifecycle-'+spec['correlationId']);R.mkdir(mode=0o700)
        W=R/'workspace';W.mkdir(mode=0o700)
        auth=display_env['XAUTHORITY'];display=display_env['DISPLAY']
        for key,leaf in [('XDG_CACHE_HOME','xdg-cache'),('XDG_CONFIG_HOME','xdg-config'),('XDG_DATA_HOME','xdg-data'),('XDG_RUNTIME_DIR','xdg-runtime')]:
            p=R/leaf;p.mkdir(mode=0o700);display_env[key]=str(p)
        home=R/'java-home';home.mkdir(mode=0o700)
        require(' ' not in str(home) and ' ' not in admissions['fixture']['trustStorePath'],'java_property_path')
        options='-Duser.home='+str(home)+' -Djavax.net.ssl.trustStore='+admissions['fixture']['trustStorePath']+' -Djavax.net.ssl.trustStorePassword=changeit'
        env={**env,'JAVA_TOOL_OPTIONS':options};owner_env={**display_env,'VPN_CONTROL_LINUX_TRAY_BACKEND':'awt','JAVA_TOOL_OPTIONS':options}
        with private_stream(R/'fixture.stdout.private') as out,private_stream(R/'fixture.stderr.private') as err:
            worker=OwnedProcess(start_fixture_child(spec_path,admissions_path,R,out,err))
        durable(R/'fixture-handle.public.json',worker.actor);owned_actors.append({**worker.actor,'role':'fixture'})
        deadline=time.monotonic()+20
        while not (R/'fixture-ready.public.json').exists() and time.monotonic()<deadline:
            require(worker.poll() is None,'fixture_worker_exit');time.sleep(.1)
        ready=json.loads(regular(R/'fixture-ready.public.json',4096,True),object_pairs_hook=pairs)
        require({k:ready[k] for k in worker.actor}==worker.actor and ready['trustVerified'] is True,'fixture_readiness_identity')
        fixture=admissions['fixture'];ports=(fixture['socksPort'],fixture['httpsPort']);_verify_worker_ports(worker,ports)
        with private_stream(R/'owner.stdout.private') as out,private_stream(R/'owner.stderr.private') as err:
            owner=OwnedProcess(subprocess.Popen([LAUNCHER,'--state-dir',str(W),'serve'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,start_new_session=True))
        durable(R/'owner-handle.public.json',owner.actor);owned_actors.append({**owner.actor,'role':'owner'})
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            require(owner.poll() is None,'owner_exit')
            try:
                status=invoke('status');cid=_uuid(status['controllerId']);break
            except (ScenarioError,ValueError,KeyError):time.sleep(.2)
        require(cid is not None,'owner_not_ready');process_matches(owner.actor,state=W,role='owner')
        # The direct headless producer observes existing locations before adding its own.
        require(not invoke('locations','list')['data']['locations'],'fresh_locations_expected')
        location=R/'owned-location.txt'
        with private_stream(location) as out:out.write(('socks://127.0.0.1:'+str(fixture['socksPort'])+'#owned-runtime-'+spec['correlationId']+'\n').encode());out.flush();os.fsync(out.fileno())
        invoke('source','set','current-locations');invoke('locations','add','--input',str(location))
        locations=invoke('locations','list')['data']['locations'];require(len(locations)==1,'owned_location_population')
        invoke('locations','select','1');invoke('routing','set','ignore-rules','true');invoke('settings','set','mode','proxy-only')
        invoke('settings','set','validation.test-url','https://localhost:%d/traffic'%fixture['httpsPort']);invoke('on',timeout=90)
        active=invoke('status');runtime_id=_uuid(active['data']['runtimeId']);matched_status()
        config=json.loads(regular(W/'runtime-config.json',4*1024*1024,True),object_pairs_hook=pairs)
        require(not any(v.get('type')=='tun' for v in config['inbounds']),'synthetic_proxy_only')
        peers=[v for v in config['outbounds'] if v.get('type')=='socks']
        require(len(peers)==1 and peers[0].get('server')=='127.0.0.1' and peers[0].get('server_port')==fixture['socksPort'],'owned_fixture_outbound')
        listens=[v['listen_port'] for v in config['inbounds'] if v.get('type')=='mixed' and v.get('tag')=='mixed-in' and v.get('listen')=='127.0.0.1'];require(len(listens)==1,'mixed_listener')
        listen=listens[0];flow_start=time.monotonic();expected=hashlib.sha256(BODY).hexdigest()
        def flowing():
            with private_stream(R/'continuous-traffic.private.jsonl') as out:
                try:
                    while not flow_stop.is_set():
                        require(time.monotonic()-flow_start<180 and owner.poll() is None and worker.poll() is None,'traffic_actor_or_bound')
                        p=subprocess.run(['/usr/bin/curl','--silent','--show-error','--noproxy','','--proxy','socks5h://127.0.0.1:'+str(listen),
                            '--cacert',fixture['certificatePath'],'--max-time','3','https://localhost:%d/traffic'%fixture['httpsPort']],capture_output=True,timeout=5)
                        row={'index':len(frames),'exit':p.returncode,'stderrBytes':len(p.stderr),'bodySha256':hashlib.sha256(p.stdout).hexdigest()}
                        out.write((json.dumps(row)+'\n').encode());out.flush()
                        require(p.returncode==0 and not p.stderr and row['bodySha256']==expected,'continuous_traffic_failed');frames.append(row);time.sleep(.08)
                except Exception as error:flow_errors.append(type(error).__name__)
        stream=threading.Thread(target=flowing,daemon=True);stream.start()
        start=len(frames);window=start_gui();invoke('gui','show');visible_window();checkpoint('fresh-frontend-attach',start)
        start=len(frames);invoke('gui','hide');hidden_frontend();checkpoint('hide',start)
        start=len(frames);invoke('gui','show');window=visible_window();checkpoint('show-with-fresh-XID',start)
        window=wm_close_show_cycle(window)
        start=len(frames);matched_status();crashed_pid=gui.pid;_crash_owned_frontend();checkpoint('exact-frontend-crash',start)
        _stop_owned_tray(admissions['display']['tray']);wait_crash_lease([crashed_pid,admissions['display']['tray']['pid']]);require(tray_owner()==0,'no_tray_selection_required')
        start=len(frames);window=start_gui();invoke('gui','show');visible_window();checkpoint('fresh-frontend-without-tray',start)
        start=len(frames);wm_close(window);require(gui.wait(timeout=20)==0,'normal_no_tray_detach');checkpoint('graceful-close-detach-without-tray',start)
        with private_stream(R/'new-trayer.stdout.private') as out,private_stream(R/'new-trayer.stderr.private') as err:
            new_tray=OwnedProcess(subprocess.Popen(['/usr/bin/trayer','--edge','top','--align','right','--widthtype','request','--height','24'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=display_env,start_new_session=True))
        durable(R/'new-trayer-handle.public.json',new_tray.actor);owned_actors.append({**new_tray.actor,'role':'display-restoration'});deadline=time.monotonic()+10
        while tray_owner()==0 and time.monotonic()<deadline:require(new_tray.poll() is None,'restored_tray_exit');time.sleep(.1)
        require(tray_owner()!=0,'restored_tray_unavailable')
        start=len(frames);start_gui();invoke('gui','show');visible_window();checkpoint('reattach-same-original-owner',start)
        flow_stop.set();stream.join(timeout=5);require(not stream.is_alive() and not flow_errors and len(frames)>=80,'traffic_not_complete')
        matched_status();protected_status(admissions['protected']);record['frames']=len(frames);record['slices']=slices
        # Only the fresh scenario owner receives ordinary OFF/quit.
        process_matches(owner.actor,state=W,role='owner');invoke('off',timeout=90)
        off=invoke('status');require(off['data']['runtimeRunning'] is False,'ordinary_off_unconfirmed')
        invoke('quit',timeout=30);require(owner.wait(timeout=30)==0,'ordinary_quit_unconfirmed')
        require(gui.wait(timeout=30)==0,'frontend_quit_unconfirmed');record['cleanup']['ownerStopped']=True
        durable(R/'fixture-stop.private',{'correlationId':spec['correlationId']});require(worker.wait(timeout=15)==0,'fixture_stop_unconfirmed')
        terminal=json.loads(regular(R/'fixture-terminal.public.json',4096,True));require(terminal.get('threadsClosed') is True and terminal.get('stopMarkerObserved') is True,'fixture_thread_cleanup')
        # Restore display ownership by retaining the replacement tray; it is
        # separately bound in this receipt, not discarded or treated as absent.
        process_matches(new_tray.actor,executable='/usr/bin/trayer');record['displayRestoration']=new_tray.actor
        _listeners_absent(ports);require(not any(Path('/proc/%d'%p).exists() for p in (owner.pid,worker.pid,gui.pid)),'actor_retained')
        assert_no_workspace_refs(W)
        protected_status(admissions['protected']);record['cleanup']['protectedPreserved']=True
        parent_fd,workspace_fd=_owned_synthetic_workspace(W,R)
        try:
            _no_process_uses_workspace(W,owned_cleanup_fd=workspace_fd)
            _remove_owned_workspace_tree(workspace_fd)
        finally:os.close(workspace_fd)
        try:os.rmdir(W.name,dir_fd=parent_fd)
        finally:os.close(parent_fd)
        require(not W.exists(),'workspace_retained')
        record['cleanup'].update(state='complete',workspaceRemoved=True,referencesAbsent=True)
        record.update(result='passed',ownerControllerId=cid,runtimeId=runtime_id)
    except Exception as error:
        record.update(result='unknown',failureClass=type(error).__name__,replayAllowed=False)
        record['cleanup']['state']='preserved-for-recovery'
        flow_stop.set()
        if stream is not None:stream.join(timeout=5)
        # An unresolved mutation retains original owner, fixture and private state.
        if 'R' in globals():
            with private_stream(R/'failure.stderr.private') as out:
                with os.fdopen(os.dup(out.fileno()),'w') as text:traceback.print_exc(file=text)
    record['ownedActors']=owned_actors;record['frames']=len(frames);record['slices']=slices
    if cid is not None:record['ownerControllerId']=cid
    if 'R' in globals():record['originalEvidenceDirectory']=str(R)
    durable(receipt_path,record)
    return 0 if record['result']=='passed' and record['cleanup']['state']=='complete' else 1

def _unprivileged_assert_no_workspace_refs(workspace):
    # Fail closed on uninspectable same-UID entries. Namespace and fd proof is
    # independent of child wait() and public quit acknowledgements.
    needle=str(workspace)
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal() or int(proc.name)==os.getpid():continue
        try:
            if proc.stat().st_uid!=os.getuid():continue
            ticks=birth(int(proc.name));tail=(proc/'stat').read_text().rsplit(')',1)[1].split()
            if tail[0]=='Z':continue
            args=(proc/'cmdline').read_bytes()
            require(needle.encode() not in args,'workspace_cmdline_reference')
            for selected in [proc/'cwd',proc/'root',*list((proc/'fd').iterdir())]:
                try:target=os.readlink(selected)
                except FileNotFoundError:continue
                require(target!=needle and not target.startswith(needle+'/'),'workspace_fd_namespace_reference')
            require(birth(int(proc.name))==ticks,'cleanup_process_generation_changed')
        except FileNotFoundError:continue
        except PermissionError:raise OutcomeUnknown('cleanup_proc_uninspectable')
PRIVILEGED_CENSUS = r'''
import json,os,stat,sys
from pathlib import Path
def demand(ok, reason):
 if not ok:raise RuntimeError(reason)
demand(os.geteuid()==0,'root_read_capability_required')
v=json.loads(sys.argv[1]);demand(set(v)=={'workspace','uid','caller','ticks','boot','ownedFd','excludeCaller'},'census_schema')
demand(type(v['uid'])is int and v['uid']>0 and type(v['caller'])is int and v['caller']>0 and type(v['ticks'])is int and v['ticks']>0,'census_identity')
demand(type(v['excludeCaller'])is bool and(v['ownedFd']is None or type(v['ownedFd'])is int and v['ownedFd']>=0),'census_policy')
demand(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==v['boot'],'census_boot_changed')
w=Path(v['workspace']);demand(w.is_absolute()and w.name=='workspace'and w.resolve(strict=True)==w,'census_workspace')
ws=w.stat();demand(stat.S_ISDIR(ws.st_mode)and ws.st_uid==v['uid'],'census_workspace_owner')
def identity(p):
 return p.stat().st_uid,int((p/'stat').read_text().rsplit(')',1)[1].split()[19])
caller=Path('/proc')/str(v['caller']);demand(identity(caller)==(v['uid'],v['ticks']),'census_caller_changed')
if v['ownedFd']is not None:
 held=caller/'fd'/str(v['ownedFd']);h=held.stat();demand((h.st_dev,h.st_ino)==(ws.st_dev,ws.st_ino)and os.readlink(held)==str(w),'census_owned_fd_changed')
needle=str(w);count=0
for p in Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:
  uid,ticks=identity(p)
  if uid!=v['uid']:continue
  if (p/'stat').read_text().rsplit(')',1)[1].split()[0]=='Z':continue
  if v['excludeCaller']and int(p.name)==v['caller']:continue
  count+=1;demand(needle.encode()not in(p/'cmdline').read_bytes(),'workspace_cmdline_reference')
  for leaf in[p/'cwd',p/'root',*list((p/'fd').iterdir())]:
   if int(p.name)==v['caller']and leaf.parent.name=='fd'and leaf.name==str(v['ownedFd']):continue
   try:target=os.readlink(leaf)
   except FileNotFoundError:continue
   demand(target!=needle and not target.startswith(needle+'/'),'workspace_fd_namespace_reference')
  demand(identity(p)==(uid,ticks),'census_process_generation_changed')
 except FileNotFoundError:continue
demand(identity(caller)==(v['uid'],v['ticks']),'census_caller_changed')
demand((w.stat().st_dev,w.stat().st_ino)==(ws.st_dev,ws.st_ino),'census_workspace_generation_changed')
print(json.dumps({'schemaVersion':1,'complete':True,'referencesAbsent':True,'uid':v['uid'],'caller':v['caller'],'ticks':v['ticks'],'boot':v['boot'],'workspaceDevice':ws.st_dev,'workspaceInode':ws.st_ino,'processCount':count},separators=(',',':')))
'''

def _privileged_workspace_census(workspace, owned_cleanup_fd=None, exclude_caller=False):
    import sys
    caller=os.getpid();ticks=birth(caller);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    value={'workspace':str(workspace),'uid':os.getuid(),'caller':caller,'ticks':ticks,'boot':boot,'ownedFd':owned_cleanup_fd,'excludeCaller':exclude_caller}
    p=subprocess.run(['/usr/bin/sudo','-n',sys.executable,'-I','-c',PRIVILEGED_CENSUS,json.dumps(value,separators=(',',':'))],capture_output=True,timeout=15)
    require(p.returncode==0 and not p.stderr and len(p.stdout)<4096,'privileged_cleanup_census_unavailable')
    result=json.loads(p.stdout,object_pairs_hook=pairs)
    require(type(result.get('schemaVersion'))is int and result['schemaVersion']==1 and result.get('complete')is True and result.get('referencesAbsent')is True,'privileged_cleanup_census_incomplete')
    require(all(result.get(k)==value[k]for k in('uid','caller','ticks','boot')),'privileged_cleanup_census_identity_changed')
    require(birth(caller)==ticks,'cleanup_caller_generation_changed')
    return result

def assert_no_workspace_refs(workspace):
    try:return _unprivileged_assert_no_workspace_refs(workspace)
    except OutcomeUnknown as error:
        if not isinstance(error.__context__,PermissionError):raise
        return _privileged_workspace_census(workspace,exclude_caller=True)



def _owned_synthetic_workspace(workspace, evidence):
    """Open the exact workspace child without trusting a replaced pathname."""
    workspace = Path(workspace)
    evidence = Path(evidence)
    require(workspace.parent == evidence and workspace.name == 'workspace', 'Cleanup target is not the owned synthetic workspace')
    evidence = evidence.resolve(strict=True)
    workspace = workspace.resolve(strict=True)
    require(workspace.parent == evidence and workspace.name == 'workspace', 'Synthetic workspace was replaced')
    current = Path('/')
    for part in evidence.parts[1:]:
        current /= part
        info = os.lstat(current)
        require(not stat.S_ISLNK(info.st_mode), 'Synthetic workspace ancestry was replaced')
    evidence_info = os.lstat(evidence)
    require(stat.S_ISDIR(evidence_info.st_mode) and evidence_info.st_uid == os.geteuid() and (not evidence_info.st_mode & 63), 'Synthetic evidence directory is untrusted')
    evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    workspace_fd = None
    try:
        workspace_fd = os.open('workspace', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=evidence_fd)
        workspace_info = os.fstat(workspace_fd)
        named_info = os.lstat(workspace)
        require(stat.S_ISDIR(workspace_info.st_mode) and workspace_info.st_uid == os.geteuid() and ((workspace_info.st_dev, workspace_info.st_ino) == (named_info.st_dev, named_info.st_ino)), 'Synthetic workspace was replaced')
        return (evidence_fd, workspace_fd)
    except Exception:
        if workspace_fd is not None:
            os.close(workspace_fd)
        os.close(evidence_fd)
        raise


def _unprivileged__no_process_uses_workspace(workspace, proc=Path('/proc'), owned_cleanup_fd=None):
    """Reject same-UID references while terminal protected state closes privileged work.

    The protected terminal receipt is the ownership proof for the privileged
    installer. Foreign-UID processes are outside this fixture's ownership;
    every same-UID cwd/fd observation must succeed, except the exact descriptor
    this cleanup invocation holds for descriptor-relative removal.
    """
    require(proc.is_dir(), 'Cannot prove synthetic workspace has no process owner')
    workspace_text = str(Path(workspace))
    prefix = workspace_text + '/'
    own_pid = str(os.getpid())
    require(owned_cleanup_fd is None or (isinstance(owned_cleanup_fd, int) and owned_cleanup_fd >= 0), 'Cleanup workspace descriptor is invalid')

    def require_process_gone(entry):
        try:
            os.stat(entry, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as error:
            raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
        raise RuntimeError('Cannot inspect process ownership of synthetic workspace')
    try:
        entries = list(proc.iterdir())
    except OSError as error:
        raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            process_info = os.stat(entry, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
        if process_info.st_uid != os.geteuid():
            continue
        for target in (entry / 'cwd',):
            try:
                reference = os.readlink(target)
            except FileNotFoundError:
                require_process_gone(entry)
                continue
            except OSError as error:
                raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
            require(reference != workspace_text and (not reference.startswith(prefix)), 'A process still owns the synthetic workspace')
        fds = entry / 'fd'
        try:
            descriptors = list(fds.iterdir())
        except FileNotFoundError:
            require_process_gone(entry)
            continue
        except OSError as error:
            raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
        for descriptor in descriptors:
            if entry.name == own_pid and owned_cleanup_fd is not None and (descriptor.name == str(owned_cleanup_fd)):
                continue
            try:
                reference = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RuntimeError('Cannot inspect process ownership of synthetic workspace') from error
            require(reference != workspace_text and (not reference.startswith(prefix)), 'A process still owns the synthetic workspace')
def _no_process_uses_workspace(workspace,proc=Path('/proc'),owned_cleanup_fd=None):
    try:return _unprivileged__no_process_uses_workspace(workspace,proc,owned_cleanup_fd)
    except RuntimeError as error:
        if proc!=Path('/proc')or not isinstance(error.__cause__,PermissionError):raise
        return _privileged_workspace_census(workspace,owned_cleanup_fd=owned_cleanup_fd)



def _remove_owned_workspace_tree(directory_fd):
    """Remove a current-user directory tree through descriptor-relative names."""
    for entry in os.scandir(directory_fd):
        info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        require(info.st_uid == os.geteuid() and (not stat.S_ISLNK(info.st_mode)), 'Synthetic workspace contains an untrusted entry')
        if stat.S_ISDIR(info.st_mode):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                _remove_owned_workspace_tree(child)
            finally:
                os.close(child)
            os.rmdir(entry.name, dir_fd=directory_fd)
        else:
            require(stat.S_ISREG(info.st_mode), 'Synthetic workspace contains a non-file entry')
            os.unlink(entry.name, dir_fd=directory_fd)

def validate_preparation(value):
    exact(value,('schema','schemaVersion','host','environment','correlationId','sourceIdentity','installedPackage','guest','display','fixture','protected'),'preparation')
    require(value['schema']=='vpn-control.linux-owner-gui-lifecycle.preparation' and type(value['schemaVersion']) is int and value['schemaVersion']==1,'preparation_schema')
    _uuid(value['correlationId'])
    for key in ('host','environment'):
        require(type(value[key]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',value[key]),'preparation_route')
    # Reuse the actual execution schema for source, package and duration policy.
    validate_input({'schema':SCHEMA,'schemaVersion':1,'scenarioId':SCENARIO,'correlationId':value['correlationId'],
        'sourceIdentity':value['sourceIdentity'],'installedPackage':value['installedPackage'],
        **{key:'sha256-'+'0'*64 for key in ('guestAdmissionArtifactId','displayAdmissionArtifactId','fixtureAdmissionArtifactId','protectedOwnerArtifactId')},'maxObservationSeconds':180})
    guest=exact(value['guest'],('bootId','uid','allocation','ownedRoot'),'guest_selector')
    _uuid(guest['bootId']);require(type(guest['uid']) is int and guest['uid']>0,'guest_uid');absolute(guest['ownedRoot'])
    display=exact(value['display'],('display','xauthorityPath','xserver','wm','tray'),'display_selector')
    require(type(display['display']) is str and re.fullmatch(':[1-9][0-9]{0,3}',display['display']),'display_selector_name')
    absolute(display['xauthorityPath'])
    for key in ('xserver','wm','tray'):
        actor=exact(display[key],('pid','startTicks','uid'),'display_actor')
        require(all(type(actor[k]) is int and actor[k]>0 for k in ('pid','startTicks')) and actor['uid']==guest['uid'],'display_actor_identity')
    fixture=exact(value['fixture'],('certificatePath','keyPath','trustStorePath','socksPort','httpsPort'),'fixture_selector')
    for key in ('certificatePath','keyPath','trustStorePath'):absolute(fixture[key])
    require(all(type(fixture[k]) is int and 1024<=fixture[k]<=65535 for k in ('socksPort','httpsPort')) and fixture['socksPort']!=fixture['httpsPort'],'fixture_selector_ports')
    protected=exact(value['protected'],('stateDir','owner','controllerId'),'protected_selector')
    absolute(protected['stateDir']);_uuid(protected['controllerId'])
    actor=exact(protected['owner'],('pid','startTicks','uid'),'protected_selector_actor')
    require(all(type(actor[k]) is int and actor[k]>0 for k in ('pid','startTicks')) and actor['uid']==guest['uid'],'protected_selector_identity')
    return value

def observe_preparation(value,source):
    """Fixed read-only producer. Selectors identify actors; actual probes emit facts.

    No caller ready/success flags are admitted. No fixture, GUI, VM or runtime is
    started here. The original allocation is checked by the coordinator first.
    """
    global env,display_env
    validate_preparation(value);require(sys.platform.startswith('linux') and os.getuid()==value['guest']['uid'],'preparation_owned_guest')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();require(boot==value['guest']['bootId'],'preparation_guest_boot')
    guest={'schema':'vpn-control.linux-owner-gui.guest','schemaVersion':1,'host':value['host'],'environment':value['environment'],
        **value['guest']}
    private_directory(guest['ownedRoot'])
    selected=value['display'];display={'schema':'vpn-control.linux-owner-gui.display','schemaVersion':1,'bootId':boot,'uid':os.getuid(),**selected}
    info=absolute(selected['xauthorityPath']).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'preparation_auth_metadata')
    display['xauthorityGeneration']=list(generation(info))
    for role,executable in (('xserver','/usr/bin/Xvfb'),('wm','/usr/bin/openbox'),('tray','/usr/bin/trayer')):
        actor=selected[role];process_matches(actor,executable=executable)
        raw=(Path('/proc')/str(actor['pid'])/'cmdline').read_bytes()
        if role=='xserver':
            args=raw.rstrip(b'\0').split(b'\0');require(selected['display'].encode() in args and str(selected['xauthorityPath']).encode() in args,'display_server_role')
        else:
            # Inspect only DISPLAY in the owned process environment; no values
            # or raw environment are emitted into any receipt.
            fd=os.open(Path('/proc')/str(actor['pid'])/'environ',os.O_RDONLY|os.O_NOFOLLOW)
            try:environment=os.read(fd,65537)
            finally:os.close(fd)
            require(len(environment)<=65536 and environment.rstrip(b'\0').split(b'\0').count(b'DISPLAY='+selected['display'].encode())==1,'display_actor_namespace')
        process_matches(actor,executable=executable)
    dependencies={}
    for name in ('Xvfb','openbox','xdotool','xwininfo','xprop','xauth','trayer','curl','openssl'):
        path='/usr/bin/'+name;digest=hashlib.sha256(regular(path,16*1024*1024)).hexdigest()
        owner=subprocess.run(['dpkg-query','-S',path],capture_output=True,timeout=10)
        require(owner.returncode==0 and not owner.stderr and len(owner.stdout)<4096,'dependency_owner_unavailable')
        rows=owner.stdout.decode().strip().splitlines();require(len(rows)==1 and rows[0].endswith(': '+path),'dependency_owner_population')
        package=rows[0][:-len(': '+path)];require(re.fullmatch('[A-Za-z0-9.+:-]+',package),'dependency_owner_package')
        version=subprocess.run(['dpkg-query','-W','-f=${Version}',package],capture_output=True,timeout=10)
        require(version.returncode==0 and not version.stderr and 0<len(version.stdout)<200,'dependency_version_unavailable')
        dependencies[name]={'path':path,'sha256':digest,'package':package,'version':version.stdout.decode()}
    display['dependencies']=dependencies
    fixture={'schema':'vpn-control.linux-owner-gui.fixture','schemaVersion':1,'bootId':boot,'uid':os.getuid(),**value['fixture'],
        'sourceSha256':worker_source()[1]}
    for label in ('certificate','trustStore'):
        fixture[label+'Sha256']=hashlib.sha256(regular(fixture[label+'Path'],1048576,True)).hexdigest()
    env=dict(os.environ)
    for key in ('DISPLAY','WAYLAND_DISPLAY','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'):env.pop(key,None)
    p=value['protected'];process_matches(p['owner'],state=absolute(p['stateDir']),role='owner')
    observed=subprocess.run([LAUNCHER,'--state-dir',p['stateDir'],'--json','--controller-id',p['controllerId'],'status'],capture_output=True,env=env,timeout=15)
    require(observed.returncode==0 and len(observed.stdout)<1048576,'protected_original_status')
    row=json.loads(observed.stdout,object_pairs_hook=pairs);require(row.get('code')=='OK' and row.get('final') is True and row.get('controllerId')==p['controllerId'] and type(row.get('data')) is dict,'protected_original_controller')
    runtime={k:row['data'][k] for k in ('runtimeId','runtimeRunning','configuredMode','activeMode','activeLocationId','selectedLocationId')}
    require(type(runtime['runtimeRunning']) is bool,'protected_original_runtime_shape')
    protected={'schema':'vpn-control.linux-owner-gui.protected','schemaVersion':1,'bootId':boot,'uid':os.getuid(),**p,
        'runtime':runtime,'workspaceSha256':hashlib.sha256(regular(absolute(p['stateDir'])/'workspace.json',4*1024*1024,True)).hexdigest()}
    admissions={'guest':guest,'display':display,'fixture':fixture,'protected':protected,'source':source}
    spec={'schema':SCHEMA,'schemaVersion':1,'scenarioId':SCENARIO,'correlationId':value['correlationId'],
        'sourceIdentity':value['sourceIdentity'],'installedPackage':value['installedPackage'],
        **{key:'sha256-'+'0'*64 for key in ('guestAdmissionArtifactId','displayAdmissionArtifactId','fixtureAdmissionArtifactId','protectedOwnerArtifactId')},'maxObservationSeconds':180}
    admission_probe(spec,admissions)
    # Reidentify every actor and the protected workspace after the entire probe.
    for role in ('xserver','wm','tray'):process_matches(display[role])
    protected_status(protected)
    require(list(generation(absolute(display['xauthorityPath']).lstat()))==display['xauthorityGeneration'],'preparation_auth_changed')
    return {'state':'observed','admissions':{k:v for k,v in admissions.items() if k!='source'},'scenarioInput':spec,'nativeActionAllowed':False,'productAcceptance':False}


class FixedGuiSourceCustody:
    """Custody of this recipe's finite original source/input population only.

    Bytes come from the manifest-authenticated receiver, or its authenticated
    memory-only read probe. Staged names are checked through held descriptors;
    compilation always uses original immutable bytes, never a reread pathname.
    """
    DRIVER='scripts/integration/linux_owner_lifecycle_scenario.py'
    SOCKS='scripts/integration/socks_http_fixture.py'
    RUNNER='scripts/native_fixture_run.sh'
    NAMES=(DRIVER,SOCKS,RUNNER,'native-scenario-manifest.json','scenario-input.json','admissions.json')

    @staticmethod
    def _generation(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    @staticmethod
    def _structural(value):
        return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)

    def __init__(self,capsule):
        import base64
        require(type(capsule) is dict and set(capsule)=={'stage','inputs','parents','manifestSha256'},'source_capsule_fields')
        self._stage=capsule['stage'];self._fds=[];self._parents={};self._files={};self._closed=False
        self._serialized=(json.dumps(capsule,sort_keys=True,separators=(',',':'))+'\n').encode()
        self._seal=hashlib.sha256(self._serialized).hexdigest()
        require(type(capsule['inputs']) is list,'source_capsule_inventory')
        expected=self.NAMES if self._stage is not None else self.NAMES[:2]
        require(tuple(x.get('path') if type(x) is dict else None for x in capsule['inputs'])==expected,'source_capsule_inventory')
        rows=[]
        for row in capsule['inputs']:
            require(set(row)=={'path','body','sha256','generation'},'source_capsule_entry')
            require(type(row['body']) is str and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'source_capsule_digest')
            raw=base64.b64decode(row['body'],validate=True)
            require(0<len(raw)<=8*1024*1024 and hashlib.sha256(raw).hexdigest()==row['sha256'],'source_capsule_bytes')
            gen=row['generation']
            if self._stage is not None:
                require(type(gen) is list and len(gen)==9 and all(type(x) is int and x>=0 for x in gen),'source_capsule_generation')
                require(stat.S_ISREG(gen[2]) and gen[3]==os.getuid() and gen[5]==1 and stat.S_IMODE(gen[2])==0o600 and gen[6]==len(raw),'source_capsule_leaf')
                gen=tuple(gen)
            else:require(gen is None,'memory_source_has_no_named_generation')
            rows.append((row['path'],raw,row['sha256'],gen))
        self._inputs=tuple(rows)
        self._expected_parents=tuple(sorted((p,tuple(v)) for p,v in capsule['parents'].items()))
        if self._stage is None:
            require(not self._expected_parents and capsule['manifestSha256'] is None,'memory_source_no_named_authority')
            return
        absolute(self._stage)
        manifest=self.body('native-scenario-manifest.json')
        require(hashlib.sha256(manifest).hexdigest()==capsule['manifestSha256'],'original_manifest_digest')
        value=json.loads(manifest,object_pairs_hook=pairs)
        require(type(value) is dict and set(value)=={'schemaVersion','scenarioId','files'} and type(value['schemaVersion']) is int and value['schemaVersion']==1
                and value['scenarioId']=='linux-owner-gui-lifecycle-driver','original_manifest_identity')
        require(value['files']==[{'path':p,'sha256':digest,'sizeBytes':len(raw)} for p,raw,digest,_ in self._inputs[:3]],'original_manifest_population')
        try:
            for relative,raw,digest,gen in self._inputs:
                path=str(Path(self._stage)/relative);parent,name=os.path.split(path)
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory(parent));self._fds.append(fd)
                require(self._generation(os.fstat(fd))==gen,'original_source_generation')
                self._files[path]=(fd,gen,digest,len(raw))
            require(set(self._parents)=={p for p,_ in self._expected_parents},'source_parent_population')
            for path,expected in self._expected_parents:require(self._parents[path][1]==expected,'original_source_parent')
            self.finish();self.finish()
        except BaseException:
            self.close();raise

    @classmethod
    def memory(cls,source,socks):
        import base64
        rows=[{'path':path,'body':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest(),'generation':None}
            for path,raw in ((cls.DRIVER,source),(cls.SOCKS,socks))]
        return cls({'stage':None,'inputs':rows,'parents':{},'manifestSha256':None})

    def _directory(self,path):
        if path in self._parents:return self._parents[path][0]
        if path=='/':fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        else:
            parent,name=os.path.split(path);fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._directory(parent or '/'))
        self._fds.append(fd);info=os.fstat(fd);require(stat.S_ISDIR(info.st_mode),'source_non_directory')
        self._parents[path]=(fd,self._structural(info));return fd

    def body(self,relative):
        require(not self._closed and hashlib.sha256(self._serialized).hexdigest()==self._seal,'source_custody_closed_or_changed')
        matches=[raw for path,raw,_,_ in self._inputs if path==relative]
        require(len(matches)==1,'source_role_not_registered');return matches[0]

    def path(self,relative):
        require(self._stage is not None and relative in self.NAMES,'source_named_role_required')
        return str(Path(self._stage)/relative)

    def finish(self):
        require(not self._closed and hashlib.sha256(self._serialized).hexdigest()==self._seal,'source_custody_closed_or_changed')
        for _,raw,digest,_ in self._inputs:require(hashlib.sha256(raw).hexdigest()==digest,'immutable_source_bytes_changed')
        # Join every held file hash before every ancestor and then the final
        # pure held/named leaf generation pass. No population closes early.
        for path,(fd,gen,digest,size) in self._files.items():
            os.lseek(fd,0,os.SEEK_SET);hasher=hashlib.sha256();count=0
            while chunk:=os.read(fd,min(65536,size+1-count)):
                count+=len(chunk);require(count<=size,'source_size_changed');hasher.update(chunk)
            require(count==size and hasher.hexdigest()==digest,'original_source_bytes_changed')
        for path,(fd,expected) in self._parents.items():
            if path=='/':named=os.lstat('/')
            else:
                parent,name=os.path.split(path);named=os.stat(name,dir_fd=self._parents[parent or '/'][0],follow_symlinks=False)
            require(self._structural(os.fstat(fd))==expected and self._structural(named)==expected,'source_parent_changed')
        for path,(fd,gen,_,_) in self._files.items():
            parent,name=os.path.split(path);named=os.stat(name,dir_fd=self._parents[parent][0],follow_symlinks=False)
            require(self._generation(os.fstat(fd))==gen and self._generation(named)==gen,'original_source_generation_changed')

    def python_command(self,arguments):
        import base64,zlib
        require(type(arguments) is list and all(type(x) is str for x in arguments),'fixed_child_arguments')
        wire=json.loads(self._serialized)
        for row in wire['inputs']:row['body']=base64.b64decode(row['body'],validate=True).decode('utf-8')
        encoded=base64.b64encode(zlib.compress(json.dumps(wire,sort_keys=True,separators=(',',':')).encode('utf-8'))).decode('ascii')
        command='import base64,hashlib,json,sys,types,zlib;wire=json.loads(zlib.decompress(base64.b64decode('+repr(encoded)+')));\nfor row in wire["inputs"]:row["body"]=base64.b64encode(row["body"].encode("utf-8")).decode("ascii")\nraw=(json.dumps(wire,sort_keys=True,separators=(",",":"))+chr(10)).encode("utf-8");assert hashlib.sha256(raw).hexdigest()=='+repr(self._seal)+';capsule=wire;rows={x["path"]:x for x in capsule["inputs"]};source=base64.b64decode(rows["'+self.DRIVER+'"]["body"]);socks=base64.b64decode(rows["'+self.SOCKS+'"]["body"]);ns={"__name__":"immutable_gui_driver","__file__":"immutable_gui_driver","_FIXED_SOURCE":source,"_SOCKS_SOURCE":socks};exec(compile(source,"immutable_gui_driver","exec"),ns);custody=ns["FixedGuiSourceCustody"](capsule);ns["_CUSTODY"]=custody;\ntry:\n custody.finish();custody.finish();module=types.ModuleType("socks_http_fixture");module.__file__="immutable_socks_fixture";exec(compile(socks,"immutable_socks_fixture","exec"),module.__dict__);sys.modules["socks_http_fixture"]=module;sys.argv=["immutable_gui_driver",*sys.argv[1:]];custody.finish();custody.finish();raise SystemExit(ns["main"]())\nfinally:\n custody.close()'
        require(len(command.encode())<65536,'fixed_child_command_bound')
        return [sys.executable,'-I','-B','-c',command,*arguments]

    def close(self):
        if self._closed:return
        failures=[]
        for fd in reversed(self._fds):
            try:os.close(fd)
            except OSError as error:failures.append(error)
        self._fds.clear();self._closed=True
        if failures:raise failures[0]


def source_custody():
    value=globals().get('_CUSTODY')
    require(type(value) is FixedGuiSourceCustody,'original_source_custody_required')
    require(value.body(value.DRIVER)==globals().get('_FIXED_SOURCE') and value.body(value.SOCKS)==globals().get('_SOCKS_SOURCE'),'original_source_namespace_binding')
    return value


def main():
    global spec_path,admissions_path,display_env
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',type=Path);parser.add_argument('--admissions',type=Path);parser.add_argument('--receipt',type=Path)
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--wm-close-helper',nargs=4);parser.add_argument('--tray-owner-helper')
    parser.add_argument('--fixture-worker',nargs=3)
    args=parser.parse_args()
    if args.wm_close_helper:
        window,pid,ticks,display=args.wm_close_helper
        request_owned_wm_close(int(window),int(pid),int(ticks),{'DISPLAY':display,'XAUTHORITY':os.environ['XAUTHORITY']},display);return 0
    if args.tray_owner_helper:_tray_owner_helper(args.tray_owner_helper);return 0
    if args.fixture_worker:
        p,a,r=args.fixture_worker
        custody=source_custody();require(p==custody.path('scenario-input.json') and a==custody.path('admissions.json'),'fixture_original_input_names')
        spec=validate_input(json.loads(custody.body('scenario-input.json'),object_pairs_hook=pairs))
        admissions=json.loads(custody.body('admissions.json'),object_pairs_hook=pairs)
        fixture_worker(spec,admissions,private_directory(r));return 0
    require(args.input and args.admissions,'fixed_input_and_admissions_required')
    spec_path=args.input;admissions_path=args.admissions
    custody=source_custody();require(str(spec_path)==custody.path('scenario-input.json') and str(admissions_path)==custody.path('admissions.json'),'original_input_names')
    spec=validate_input(json.loads(custody.body('scenario-input.json'),object_pairs_hook=pairs))
    admissions=json.loads(custody.body('admissions.json'),object_pairs_hook=pairs)
    if args.preflight:
        print(json.dumps(admission_probe(spec,admissions),separators=(',',':')));return 0
    require(args.receipt and not args.receipt.exists(),'fresh_receipt_required')
    return run_scenario(spec,admissions,args.receipt)

if __name__=='__main__':raise SystemExit(main())
