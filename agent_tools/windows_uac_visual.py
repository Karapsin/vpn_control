"""One Windows consent prompt for the visual scene, raised and cancelled on an owned windowsUacVisual deployment.

``vm_workflow windows-uac-visual`` takes exactly deploymentId, operationId and step. ``raise`` proves the
deployment's own qualified filtered-administrator session in a SYSTEM census, parks the pointer once, which
also wakes a sleeping display, opens the Run dialog and types the visual driver's fixed command,
``powershell start powershell -verb runas``, then proves the prompt in a second census and in the pixels: a
dimmed full screen, not a button waiting in the taskbar. It stops with the prompt open, so the reviewed
frame route can capture the scene. ``cancel`` sends one Esc to that same prompt while it is younger than
the age rule, or lets it expire, proves it closed with no shell left behind and closes the fence.

Setup class: never product evidence and never an approval. No credential is read, no profile is needed and
nothing is ever approved. A repeat of a step is a settle packet that holds no key or pointer path. This
module is a leaf beside windows_uac_decision: no sign-in packet embeds it, and
readiness_windows._source_pins does not list it.
"""
from __future__ import annotations

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
from . import windows_uac_decision as uac
from .readiness_windows_login import ppm
from .windows_uac_decision import _uac_close_fence, _uac_create, _uac_directory, _uac_exit_source, _uac_load
from .windows_vm_instance import console_key_plan

_EXECUTING_CODE = inspect.currentframe().f_code

STEPS = ("raise", "cancel")
INPUT_FIELDS = frozenset({"deploymentId", "operationId", "step"})
PURPOSE = "windowsUacVisual"
# The command scripts/capture_visual_windows_qemu.py types into the Run dialog for the same scene.
COMMAND = "powershell start powershell -verb runas"
# One journaled pointer park: an absolute device jumps to the top right corner, where one column of the arrow shows
# and nothing answers a hover; a relative one gets this many steps of this size, more than the frame is wide.
PARK_STEPS = 16
PARK_DELTA = 120
# cancel waits this many exit reads of CLOSE_WAIT_MILLISECONDS each before it reports the prompt still open.
CLOSE_ROUNDS = 2
_VISUALS = ".runtime/windows-uac-visual"
_RAISED = frozenset({"state", "operationId", "consent", "pointerParked", "frameSha256", "promptAnswered", "replayAllowed"})
_CLOSED = frozenset({"state", "operationId", "promptClosed", "escSent", "framesDuringPrompt", "approvalSucceeded", "replayAllowed"})
_OPERATION = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")

_CENSUS = r"""$administrator=__ADMINISTRATOR__
$policy=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$adminSid=(Get-LocalUser -Name $administrator).SID.Value
$preload=(Get-ItemProperty -LiteralPath ('Registry::HKEY_USERS\'+$adminSid+'\Keyboard Layout\Preload')).'1'
$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5).LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
$appinfo=[int](Get-CimInstance Win32_Service -Filter "Name='Appinfo'" -OperationTimeoutSec 5).ProcessId
$all=@(Get-CimInstance Win32_Process -OperationTimeoutSec 10)
$consents=@(foreach($c in @($all|Where-Object{$_.Name -ieq 'consent.exe'}|Select-Object -First 8)){
 $p=Get-Process -Id ([int]$c.ProcessId);$start=$p.StartTime.ToUniversalTime();$sig=Get-AuthenticodeSignature -LiteralPath ([string]$c.ExecutablePath)
 [ordered]@{pid=[int]$c.ProcessId;birth=$start.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture);sessionId=[int]$c.SessionId;image=[string]$c.ExecutablePath;signature=[string]$sig.Status;signer=[string]$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);parentIsAppinfo=([int]$c.ParentProcessId -eq $appinfo);ageSeconds=[int][math]::Floor(([DateTime]::UtcNow-$start).TotalSeconds)}
})
$shells=@(foreach($c in @($all|Where-Object{$_.Name -ieq 'powershell.exe' -and [int]$_.ProcessId -ne $PID}|Select-Object -First 16)){[ordered]@{pid=[int]$c.ProcessId;sessionId=[int]$c.SessionId}})
$explorers=@(foreach($c in @($all|Where-Object{$_.Name -ieq 'explorer.exe'}|Select-Object -First 16)){[ordered]@{pid=[int]$c.ProcessId;sessionId=[int]$c.SessionId;birth=(Get-Process -Id ([int]$c.ProcessId)).StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)}})
$r=[ordered]@{policy=[ordered]@{enableLua=[int]$policy.EnableLUA;promptOnSecureDesktop=[int]$policy.PromptOnSecureDesktop;consentPromptBehaviorAdmin=[int]$policy.ConsentPromptBehaviorAdmin};preload=[string]$preload;adminSid=[string]$adminSid;bootFileTimeUtc=[string]$boot;consents=$consents;shells=$shells;explorers=$explorers}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 6 -Compress))
"""


def census_source(administrator):
    """The fixed read-only SYSTEM census of the visual session; ASCII, and its one value is a checked token."""
    source = uac._PRELUDE + _CENSUS
    if source.count("__ADMINISTRATOR__") != 1:
        raise ValueError("windows_uac_visual_census_marker")
    source = source.replace("__ADMINISTRATOR__", uac._ps_literal(administrator))
    source.encode("ascii")
    return source


# Everything from here to _uac_visual_settle runs on the VM host, embedded by inspect.getsource.
class _UacVisual:
    """One visual prompt, in its own folder of windows-uac: what was begun, and the terminal of each step."""
    def __init__(self,root,operation):
        self.root=root;self.operation=operation;self.begun=False
        self.parent=root/'windows-uac';self.directory=self.parent/operation
    def known(self,name):
        import os
        path=self.directory/name
        return _uac_load(path)if os.path.lexists(path)else None
    def begin(self):
        """The folder and the intent exist before the fence, the pointer or any key."""
        import os
        for path in (self.parent,self.directory):_uac_directory(path)
        for path in (self.parent,self.root):
            descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        _uac_create(self.directory/'visual.intent.json',{'operationId':self.operation,'mode':'uac-visual','replayAllowed':False})
        self.begun=True
    def finish(self,name,value):
        """The first terminal of a step wins, and the reply is always that terminal."""
        import os
        path=self.directory/name
        if not os.path.lexists(path):_uac_create(path,value)
        return _uac_load(path)
    def reply(self,reason):
        """The raise packet's failure path: a begun raise ends refused, and only cancel closes what it left."""
        if not self.begun:return None
        return self.finish('raise.terminal.json',{'state':'visual-raise-refused','operationId':self.operation,'reason':reason,'cancelRequired':True,'replayAllowed':False})

def _uac_visual_binding(read):
    """The filtered-administrator session this deployment's own visual qualification recorded in its VM root."""
    try:value=read('visual-session-qualified.json')
    except (OSError,ValueError):raise ValueError('instance_uac_visual_unqualified')from None
    binding=value.get('binding')if type(value)is dict else None
    if (type(value)is not dict or set(value)!={'purpose','binding'}or value['purpose']!='windowsUacVisual'or type(binding)is not dict
            or set(binding)!={'guestBoot','bootFileTimeUtc','sid','sessionId','explorerPid','explorerBirth','explorerPath','profile'}
            or type(binding['sid'])is not str or re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',binding['sid'])is None
            or type(binding['sessionId'])is not int or not 0<binding['sessionId']<=16383 or type(binding['explorerPid'])is not int or binding['explorerPid']<=0
            or any(type(binding[key])is not str or re.fullmatch('[1-9][0-9]{0,19}',binding[key])is None for key in ('bootFileTimeUtc','explorerBirth'))):raise ValueError('instance_uac_visual_unqualified')
    return binding

def _uac_visual_session(fresh,binding,unlocked):
    """The console is still that session of that administrator; before the prompt it is unlocked as well."""
    session=fresh['session']
    if not(fresh['machine'].lower()==SPEC['deploymentId']and fresh['console']==binding['sessionId']and fresh['tokenSid']==binding['sid']
           and session['SessionId']==fresh['console']and session['State']==0 and (session['Flags']==1 or not unlocked)):raise ValueError('instance_uac_session_changed')

def _uac_visual_census(value,binding):
    """One census against the qualified session: (the console's one consent or None, shells in that session)."""
    def need(ok,code):
        if not ok:raise ValueError(code)
    need(type(value)is dict and set(value)=={'policy','preload','adminSid','bootFileTimeUtc','consents','shells','explorers'},'instance_uac_census_shape')
    policy=value['policy']
    need(type(policy)is dict and policy.get('enableLua')==1 and policy.get('promptOnSecureDesktop')==1 and policy.get('consentPromptBehaviorAdmin')in (2,5),'instance_uac_policy')
    need(value['preload']=='00000409','instance_uac_keyboard')
    need(value['bootFileTimeUtc']==binding['bootFileTimeUtc'],'instance_uac_boot_changed')
    need(value['adminSid']==binding['sid'],'instance_uac_administrator')
    consents=value['consents'];shells=value['shells'];explorers=value['explorers']
    need(type(consents)is list and type(explorers)is list and type(shells)is list
         and all(type(row)is dict and set(row)=={'pid','sessionId'}and type(row['pid'])is int and type(row['sessionId'])is int for row in shells),'instance_uac_census_shape')
    # The qualified desktop's own shell, by pid and birth: a new explorer is another desktop.
    need([row for row in explorers if type(row)is dict and row.get('sessionId')==binding['sessionId']]
         ==[{'pid':binding['explorerPid'],'sessionId':binding['sessionId'],'birth':binding['explorerBirth']}],'instance_uac_session_changed')
    count=sum(row['sessionId']==binding['sessionId']for row in shells)
    if not consents:return None,count
    need(len(consents)==1,'instance_uac_consent_not_unique')
    row=consents[0]
    need(type(row)is dict and set(row)=={'pid','birth','sessionId','image','signature','signer','parentIsAppinfo','ageSeconds'}
         and type(row['pid'])is int and row['pid']>0 and type(row['birth'])is str and re.fullmatch('[1-9][0-9]{0,19}',row['birth'])is not None
         and type(row['sessionId'])is int and row['sessionId']==binding['sessionId']and type(row['image'])is str and row['image'].casefold()==r'c:\windows\system32\consent.exe'
         and row['signature']=='Valid'and row['signer']=='Microsoft Windows'and row['parentIsAppinfo']is True and type(row['ageSeconds'])is int and row['ageSeconds']>=0,'instance_uac_consent_identity')
    return {'pid':row['pid'],'birth':row['birth'],'sessionId':row['sessionId'],'ageSeconds':row['ageSeconds']},count

def _uac_visual_read(script,guard,binding,limit):
    """One census. A failed read proves nothing, so only reads are retried, and only within the bound."""
    import os,time
    while True:
        guard()
        try:value=script('login-admission-'+os.urandom(6).hex(),UAC_VISUAL_CENSUS_SCRIPT)
        except OSError:value=None
        except ValueError as error:
            if re.fullmatch('instance_[a-z_]{1,64}',str(error))and str(error)not in {'instance_guest_program_failed','instance_original_guest_pending','instance_guest_output','instance_guest_output_bound','instance_guest_exec_ack'}:raise
            value=None
        if value is not None:return _uac_visual_census(value,binding)
        if time.monotonic()>=limit:raise ValueError('instance_uac_census_unavailable')
        time.sleep(1)

def _uac_visual_shot(visual,monitor,guard,kept,count):
    """One frame of the console, read whole; the last two stay beside the journal."""
    import os,stat
    count[0]+=1;path=visual.directory/('frame-%02d.ppm'%count[0])
    guard();monitor('screendump',{'filename':str(path),'format':'ppm'});s=os.lstat(path)
    if not(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and s.st_nlink==1 and s.st_size<=16*1024**2):raise ValueError('instance_uac_frame_identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        raw=b''
        while len(raw)<=16*1024**2:
            chunk=os.read(fd,65536)
            if not chunk:break
            raw+=chunk
    finally:os.close(fd)
    if len(raw)!=s.st_size:raise ValueError('instance_uac_frame_changed')
    kept.append(path)
    if len(kept)>2:os.unlink(kept.pop(0))
    guard();return raw

def _uac_visual_changed(before,after):
    """Sampled pixels that differ between two frames: (all, those in the Run dialog's corner, samples taken)."""
    w,h,a=ppm(before);x,y,b=ppm(after)
    if (w,h)!=(x,y):raise ValueError('instance_uac_frame_changed')
    total=inside=samples=0
    for row in range(0,h,4):
        base=row*w*3
        if a[base:base+w*3]==b[base:base+w*3]:samples+=(w+3)//4;continue
        for column in range(0,w,4):
            at=base+column*3;samples+=1
            if a[at:at+3]!=b[at:at+3]:
                total+=1
                # Run opens bottom left, above the taskbar: the left 3/8 and the lower 3/8 of the frame hold it.
                if column*8<w*3 and row*8>=h*5:inside+=1
    return total,inside,samples

def _uac_visual_park(visual,monitor,guard):
    """The one journaled pointer move of this operation, with no button: out of the scene, and a display wake."""
    import os,time
    moved=visual.directory/'pointer.intent.json'
    if os.path.lexists(moved):raise ValueError('instance_uac_visual_original_unresolved')
    mice=monitor('query-mice',None);selected=[x for x in mice if type(x)is dict and x.get('current')is True]
    if len(selected)!=1 or type(selected[0].get('absolute'))is not bool:raise ValueError('instance_uac_mouse_unrecognized')
    guard();_uac_create(moved,{'operationId':OPERATION,'absolute':selected[0]['absolute'],'replayAllowed':False})
    if selected[0]['absolute']:monitor('input-send-event',{'events':[{'type':'abs','data':{'axis':'x','value':32767}},{'type':'abs','data':{'axis':'y','value':0}}]})
    else:
        for _ in range(UAC_VISUAL_PARK_STEPS):
            monitor('input-send-event',{'events':[{'type':'rel','data':{'axis':'x','value':UAC_VISUAL_PARK_DELTA}},{'type':'rel','data':{'axis':'y','value':-UAC_VISUAL_PARK_DELTA}}]})
            time.sleep(.03)
    guard()

def _uac_visual_raise(visual,root,save,read,monitor,guard,script):
    """Proof of the qualified session, one pointer park, the Run dialog proven before the fixed command is typed,
    then the prompt proven in a census and in a dimmed frame. It stops with the prompt open for the frame route."""
    import os,time
    def need(ok,code):
        if not ok:raise ValueError(code)
    def durable(name,value):
        save(name,value)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    def key(codes):
        monitor('send-key',{'keys':[{'type':'qcode','data':code}for code in codes],'hold-time':10});time.sleep(.025)
    binding=_uac_visual_binding(read)
    known=visual.known('raise.terminal.json')
    if known is not None:return known
    need(visual.known('visual.intent.json')is None,'instance_uac_visual_original_unresolved')
    fresh=script('login-session-'+os.urandom(6).hex(),SESSION_SCRIPT);_uac_visual_session(fresh,binding,True)
    consent,shells=_uac_visual_read(script,guard,binding,time.monotonic()+UAC_GATE_SECONDS)
    need(consent is None,'instance_uac_visual_prompt_present');need(shells==0,'instance_uac_visual_shell_present')
    guard();visual.begin()
    durable('direct-guest-'+OPERATION+'.intent.json',{'operationId':OPERATION,'label':'uac-visual','replayAllowed':False})
    kept=[];count=[0]
    def shot():return _uac_visual_shot(visual,monitor,guard,kept,count)
    _uac_visual_park(visual,monitor,guard)
    settle=time.monotonic()+UAC_REVIEW_SETTLE
    while True:
        time.sleep(.5);desktop=shot()
        if any(ppm(desktop)[2]):break
        need(time.monotonic()<settle,'instance_uac_display_black')
    time.sleep(1);desktop=shot();need(any(ppm(desktop)[2]),'instance_uac_display_black')
    guard();_uac_create(visual.directory/'keys.intent.json',{'operationId':OPERATION,'keys':len(UAC_VISUAL_KEYS),'replayAllowed':False})
    key(['esc']);key(['esc']);key(['meta_l','r']);time.sleep(1.5)
    run=shot();total,inside,samples=_uac_visual_changed(desktop,run)
    if not(inside*50>=samples and inside*10>=total*9):
        # Nothing is typed into a screen that is not the Run dialog: whatever opened gets one Esc.
        key(['esc']);raise ValueError('instance_uac_visual_run_dialog')
    key(['ctrl','a']);key(['backspace'])
    for codes in UAC_VISUAL_KEYS:key(codes)
    key(['ret'])
    _uac_create(visual.directory/'keys.terminal.json',{'operationId':OPERATION,'enterSent':True,'replayAllowed':False})
    limit=time.monotonic()+UAC_GATE_SECONDS
    while True:
        consent,shells=_uac_visual_read(script,guard,binding,limit)
        if consent is not None:break
        need(time.monotonic()<limit,'instance_uac_consent_absent');time.sleep(1)
    need(shells==1,'instance_uac_visual_requester');need(consent['ageSeconds']<UAC_PROMPT_AGE,'instance_uac_prompt_age')
    raw=shot();need(any(ppm(raw)[2]),'instance_uac_display_black')
    # A prompt that waits as a taskbar button changes a corner; the secure desktop dims the whole frame.
    total,inside,samples=_uac_visual_changed(run,raw);need(total*2>=samples,'instance_uac_visual_prompt_not_shown')
    return visual.finish('raise.terminal.json',{'state':'visual-prompt-raised','operationId':OPERATION,'consent':consent,'pointerParked':True,
                                                'frameSha256':hashlib.sha256(raw).hexdigest(),'promptAnswered':False,'replayAllowed':False})

def _uac_visual_frames(visual,root):
    """Frame operations whose result was written after this prompt was raised; the caller proves it is still up."""
    import os
    floor=os.lstat(visual.directory/'raise.terminal.json').st_mtime_ns;found=[]
    for name in sorted(os.listdir(root)):
        match=re.fullmatch(r'inspection-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.result\.json',name)
        if match and os.lstat(root/name).st_mtime_ns>floor:found.append(match[1])
    return found[:16]

def _uac_visual_escape(visual,consent,monitor,guard):
    """The one Esc of this operation, burned before it is sent."""
    import os
    burn=visual.directory/'cancel.intent.json'
    if os.path.lexists(burn):return
    guard();_uac_create(burn,{'operationId':OPERATION,'consent':{'pid':consent['pid'],'birth':consent['birth']},'replayAllowed':False})
    monitor('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80});guard()

def _uac_visual_close(visual,root,save,read,guard,script,escape):
    """Proves the prompt closed with no shell left behind, then closes the fence. Without escape it sends nothing.

    Only the prompt this operation proved shown is keyed, once, and only while it is younger than the age rule: an
    older one expires by itself, which is the same denial. A prompt it never recorded is waited out, never keyed.
    """
    import os,time
    def need(ok,code):
        if not ok:raise ValueError(code)
    def durable(name,value):
        save(name,value)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    binding=_uac_visual_binding(read)
    need(visual.known('visual.intent.json')is not None,'instance_uac_visual_not_raised')
    known=visual.known('cancel.terminal.json')
    if known is not None:return known
    raised=visual.known('raise.terminal.json');shown=type(raised)is dict and raised.get('state')=='visual-prompt-raised'
    fresh=script('login-session-'+os.urandom(6).hex(),SESSION_SCRIPT);_uac_visual_session(fresh,binding,False)
    consent,shells=_uac_visual_read(script,guard,binding,time.monotonic()+UAC_GATE_SECONDS)
    frames=[]
    if consent is not None:
        mine=shown and (consent['pid'],consent['birth'])==(raised['consent']['pid'],raised['consent']['birth'])
        need(mine or not shown,'instance_uac_consent_changed')
        if mine:
            frames=_uac_visual_frames(visual,root)
            if escape is not None and consent['ageSeconds']<UAC_PROMPT_AGE:escape(consent)
        gone=False
        for _ in range(UAC_VISUAL_CLOSE_ROUNDS):
            guard()
            try:gone=script('login-after-'+os.urandom(6).hex(),_uac_exit_source(consent,UAC_CLOSE_WAIT)).get('gone')is True
            except (OSError,ValueError):gone=False
            if gone:break
        if not gone:return {'state':'visual-prompt-open','operationId':OPERATION,'escSent':os.path.lexists(visual.directory/'cancel.intent.json'),'replayAllowed':False}
        consent,shells=_uac_visual_read(script,guard,binding,time.monotonic()+UAC_GATE_SECONDS)
    # An approved prompt would leave its elevated shell on that desktop: none is left, so nothing was approved.
    need(consent is None and shells==0,'instance_uac_visual_left_open')
    guard();_uac_close_fence(root,durable,OPERATION,os.getpid(),0)
    return visual.finish('cancel.terminal.json',{'state':'visual-prompt-closed','operationId':OPERATION,'promptClosed':True,
                                                 'escSent':os.path.lexists(visual.directory/'cancel.intent.json'),'framesDuringPrompt':frames,
                                                 'approvalSucceeded':False,'replayAllowed':False})

def _uac_visual_settle(visual,root,save,read,guard,script):
    """A repeat. It raises and keys nothing: a raise reads its terminal, a cancel finishes closing."""
    if UAC_VISUAL_STEP=='raise':
        known=visual.known('raise.terminal.json')
        if known is not None:return known
        # Under the root lock no raise packet lives: one that began and left no terminal ended unknown.
        return {'state':'visual-raise-unknown'if visual.known('visual.intent.json')is not None else'no-visual-recorded','operationId':OPERATION,'replayAllowed':False}
    return _uac_visual_close(visual,root,save,read,guard,script,None)


_COMMON_SOURCES = (ppm, _uac_load, _uac_create, _uac_directory, _uac_exit_source, _uac_close_fence, _UacVisual, _uac_visual_binding,
                   _uac_visual_session, _uac_visual_census, _uac_visual_read)
_RAISE_SOURCES = (*_COMMON_SOURCES, _uac_visual_shot, _uac_visual_changed, _uac_visual_park, _uac_visual_raise)
_CANCEL_SOURCES = (*_COMMON_SOURCES, _uac_visual_frames, _uac_visual_escape, _uac_visual_close)
# A settle packet embeds no pointer, key or frame code at all.
_SETTLE_SOURCES = (*_COMMON_SOURCES, _uac_visual_frames, _uac_visual_close, _uac_visual_settle)


def program(binding, mode, operation, *, step=None):
    """A fixed packet patched from the observe producer, as windows_uac_decision does; no pinned source moves."""
    if (mode not in {"uac-visual-raise", "uac-visual-cancel", "uac-visual-settle"} or not uac._canonical(operation)
            or (step not in STEPS if mode == "uac-visual-settle" else step is not None)):
        raise ValueError("windows_uac_visual_action")
    _, _, setup, _ = packets.validate_binding(binding)
    if setup.get("purpose") != PURPOSE or setup["locale"] != "en-US":
        raise ValueError("windows_uac_visual_purpose")
    bindings = {"UAC_PRELUDE": uac._PRELUDE, "UAC_EXIT": uac._EXIT, "UAC_VISUAL_CENSUS_SCRIPT": census_source(setup["administrator"]),
                "UAC_GATE_SECONDS": uac.GATE_SECONDS, "UAC_PROMPT_AGE": uac.PROMPT_AGE_SECONDS, "UAC_CLOSE_WAIT": uac.CLOSE_WAIT_MILLISECONDS,
                "UAC_VISUAL_CLOSE_ROUNDS": CLOSE_ROUNDS}
    source = packets.program(binding, "observe", operation).decode()
    source = uac._replace_once(source, "MODE='observe'", "MODE=" + repr(mode))
    marker = "        elif MODE in {'observe','idle-inventory','reboot'}:\n"
    opening = ("        elif MODE==" + repr(mode) + ":\n"
               "            uac_visual=_UacVisual(root,OPERATION)\n")
    if mode == "uac-visual-raise":
        bindings.update(UAC_VISUAL_KEYS=[list(codes) for codes in console_key_plan(COMMAND)], UAC_VISUAL_PARK_STEPS=PARK_STEPS,
                        UAC_VISUAL_PARK_DELTA=PARK_DELTA, UAC_REVIEW_SETTLE=uac.REVIEW_SETTLE_SECONDS)
        sources = _RAISE_SOURCES
        source = uac._replace_once(source, marker, opening +
                                   "            require(state=='running','instance_guest_not_ready')\n"
                                   "            result=_uac_visual_raise(uac_visual,root,save,read,monitor,vm_guard,script)\n" + marker)
        # A begun raise always ends with a terminal; one it cannot write is unknown, and cancel closes either.
        source = uac._replace_once(source, "        print(json.dumps({'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}))",
                                   "        failed={'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}\n"
                                   "        if locals().get('uac_visual')is not None:\n"
                                   "            try:failed=uac_visual.reply(reason)or failed\n"
                                   "            except BaseException:failed={'state':'visual-raise-unknown','operationId':OPERATION,'replayAllowed':False}\n"
                                   "        print(json.dumps(failed))")
    elif mode == "uac-visual-cancel":
        sources = _CANCEL_SOURCES
        source = uac._replace_once(source, marker, opening +
                                   "            require(state=='running','instance_guest_not_ready')\n"
                                   "            result=_uac_visual_close(uac_visual,root,save,read,vm_guard,script,lambda consent:_uac_visual_escape(uac_visual,consent,monitor,vm_guard))\n" + marker)
    else:
        bindings["UAC_VISUAL_STEP"] = step
        sources = _SETTLE_SOURCES
        source = uac._replace_once(source, marker, opening +
                                   "            require(UAC_VISUAL_STEP=='raise'or state=='running','instance_guest_not_ready')\n"
                                   "            result=_uac_visual_settle(uac_visual,root,save,read,vm_guard,script)\n" + marker)
    helpers = "import hashlib,json,os,re\n" + "".join(key + "=" + repr(value) + "\n" for key, value in bindings.items())
    helpers += "".join(inspect.getsource(item) + "\n" for item in sources)
    raw = (helpers + source).encode()
    compile(raw, "fixed Windows UAC visual prompt", "exec")
    return raw


def validate_inputs(inputs):
    """Exactly the three fields: the deployment, one operation of the caller's choosing, and the step."""
    if (type(inputs) is not dict or set(inputs) != INPUT_FIELDS or any(type(value) is not str for value in inputs.values())
            or not uac._canonical(inputs["deploymentId"]) or not uac._canonical(inputs["operationId"]) or inputs["step"] not in STEPS):
        raise ValueError("windows_uac_visual_inputs")
    return inputs


def _binding(root, deployment):
    """The deployment's original start intent, as the scenario driver reads one, and only a windowsUacVisual one."""
    from . import readiness_fixture_registry as registry
    try:
        value, _ = registry._json(root / ".rag_index/windows-vm-deploy-intents" / (deployment + ".intent.json"))
        if (set(value) != {"spec", "setup", "context", "correlationId", "mode", "callerSha256"} or value["mode"] != "start"
                or type(value["spec"]) is not dict or value["spec"].get("deploymentId") != deployment):
            raise ValueError("windows_uac_visual_deployment")
        binding = {"provider": "raw-qemu-windows", "spec": value["spec"], "setup": value["setup"], "context": value["context"],
                   "uri": None, "domain": None, "xmlSha256": None}
        provider, spec, setup, _ = packets.validate_binding(binding)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("uac_visual_deployment_unavailable") from None
    if provider != "raw-qemu-windows" or spec.deployment_id != deployment:
        raise ValueError("uac_visual_deployment_unavailable")
    if setup.get("purpose") != PURPOSE or setup["locale"] != "en-US":
        raise ValueError("uac_visual_deployment_not_visual")
    return binding


def _refused(reason, inputs):
    return {"state": "refused", "reason": reason, "operationId": inputs["operationId"], "deploymentId": inputs["deploymentId"],
            "step": inputs["step"], "replayAllowed": False}


def _retained(directory, step):
    path = directory / (step + ".result.json")
    return json.loads(uac._read_private(path)) if os.path.lexists(path) else None


def _gates(root, inputs):
    """Every gate before the first contact, on local files alone; nothing is written.

    (reply, None) ends the call with no contact. Otherwise admitted.repeat says whether this step was sent before:
    a repeat is a settle packet.
    """
    validate_inputs(inputs)
    root = Path(root).resolve(strict=True)
    for code, module in ((_EXECUTING_CODE, __file__), (uac._EXECUTING_CODE, uac.__file__)):
        current = Path(module)
        if code != compile(current.read_bytes(), str(current), "exec", dont_inherit=True):
            raise ValueError("windows_uac_visual_source_changed")
    deployment, operation, step = inputs["deploymentId"], inputs["operationId"], inputs["step"]
    try:
        binding = _binding(root, deployment)
    except ValueError as error:
        return _refused(str(error), inputs), None
    directory = root / _VISUALS / operation
    if os.path.lexists(directory / "intent.json") and json.loads(uac._read_private(directory / "intent.json")).get("deploymentId") != deployment:
        return _refused("uac_visual_operation_mismatch", inputs), None
    known = _retained(directory, step)
    if known is not None:
        return known, None
    if step == "cancel" and not os.path.lexists(directory / "raise.intent.json"):
        return _refused("uac_visual_not_raised", inputs), None
    if step == "raise" and os.path.lexists(directory / "cancel.intent.json"):
        return _refused("uac_visual_cancel_begun", inputs), None
    return None, SimpleNamespace(root=root, binding=binding, directory=directory, repeat=os.path.lexists(directory / (step + ".intent.json")))


def before_contact(root, inputs):
    """The reply prompt gives from local files alone, or None when it must reach the host."""
    reply, _ = _gates(root, inputs)
    return reply


def _project(value, inputs, *, first):
    """Only closed fields cross. Nothing here is an approval, and a raised prompt is still unanswered."""
    public = {"operationId": inputs["operationId"], "deploymentId": inputs["deploymentId"], "step": inputs["step"], "replayAllowed": False}
    unknown = {"state": "unknown", "reason": "uac_reply_rejected", **public}
    if value is None or value.get("operationId") != inputs["operationId"] or value.get("replayAllowed") is not False:
        return unknown
    state, reason = value.get("state"), value.get("reason")
    if state == "visual-prompt-raised" and inputs["step"] == "raise":
        consent = value.get("consent")
        if (set(value) != _RAISED or value["pointerParked"] is not True or value["promptAnswered"] is not False
                or type(value["frameSha256"]) is not str or re.fullmatch("[0-9a-f]{64}", value["frameSha256"]) is None
                or type(consent) is not dict or set(consent) != {"pid", "birth", "sessionId", "ageSeconds"}
                or type(consent["ageSeconds"]) is not int or not 0 <= consent["ageSeconds"] < uac.PROMPT_AGE_SECONDS):
            return unknown
        return {"state": "visual-prompt-raised", "promptOpen": True, "promptAnswered": False, "pointerParked": True,
                "consentAgeSeconds": consent["ageSeconds"], "frameSha256": value["frameSha256"], **public}
    if state == "visual-raise-refused" and inputs["step"] == "raise":
        if (set(value) != {"state", "operationId", "reason", "cancelRequired", "replayAllowed"} or value["cancelRequired"] is not True
                or type(reason) is not str or uac._PUBLIC_REASON.fullmatch(reason) is None):
            return unknown
        return {"state": "refused", "reason": reason, "cancelRequired": True, **public}
    if state == "visual-raise-unknown" and inputs["step"] == "raise":
        return {"state": "unknown", "reason": "uac_visual_raise_unknown", "cancelRequired": True, **public}
    if state == "visual-prompt-closed" and inputs["step"] == "cancel":
        frames = value.get("framesDuringPrompt")
        if (set(value) != _CLOSED or value["promptClosed"] is not True or type(value["escSent"]) is not bool or value["approvalSucceeded"] is not False
                or type(frames) is not list or len(frames) > 16 or any(type(item) is not str or _OPERATION.fullmatch(item) is None for item in frames)):
            return unknown
        return {"state": "visual-prompt-closed", "promptClosed": True, "escSent": value["escSent"], "framesDuringPrompt": frames,
                "approvalSucceeded": False, **public}
    if state == "visual-prompt-open" and inputs["step"] == "cancel" and type(value.get("escSent")) is bool:
        return {"state": "visual-prompt-open", "promptClosed": False, "escSent": value["escSent"], **public}
    if state == "blocked" and type(reason) is str and uac._PUBLIC_REASON.fullmatch(reason) is not None:
        # A first raise prints this only before it begins, so nothing is left to cancel. A cancel or a settle that
        # ends this way closed nothing, and the next call settles again.
        if first and inputs["step"] == "raise":
            return {"state": "refused", "reason": reason, "cancelRequired": False, **public}
        return {"state": "unknown", "reason": reason, **public}
    if state == "no-visual-recorded":
        return {"state": "unknown", "reason": "uac_original_submission_unknown", **public}
    return unknown


def _final(projected, step):
    """What ends a step for good: a raise that is known either way, and a cancel only once the prompt is proven closed."""
    if step == "cancel":
        return projected["state"] == "visual-prompt-closed"
    return projected["state"] in {"visual-prompt-raised", "refused"} or projected.get("reason") == "uac_visual_raise_unknown"


def prompt(root, inputs, *, deadline=None):
    """One step of one visual consent prompt. A direct call and the public route run this same function.

    The first call of a step sends its packet under a create-only journal; every later call is a settle packet, so
    a lost reply never parks the pointer, types the command or sends the Esc a second time.
    """
    if deadline is None:
        deadline = time.monotonic() + uac.SUBMIT_SECONDS + 10
    reply, admitted = _gates(root, inputs)
    if reply is not None:
        return reply
    root, binding = admitted.root, admitted.binding
    operation, step = inputs["operationId"], inputs["step"]
    directory = uac._journal_directory(root, operation, _VISUALS)
    intended = {"operationId": operation, "deploymentId": inputs["deploymentId"], "host": binding["spec"]["host"], "replayAllowed": False}
    try:
        login._retain_local(directory, "intent.json", intended)
    except FileExistsError:
        if json.loads(uac._read_private(directory / "intent.json")) != intended:
            raise ValueError("windows_uac_visual_original_changed") from None
    first = not admitted.repeat
    if first:
        source = program(binding, "uac-visual-" + step, operation)
        try:
            # Public packet custody and the step's journal, both before anything is sent.
            login._retain_local(directory, step + ".intent.json", {"operationId": operation, "step": step,
                                                                  "sourceSha256": hashlib.sha256(source).hexdigest(), "replayAllowed": False})
        except FileExistsError:
            first = False
        else:
            login._retain_local(directory, step + ".py", source)
    if not first:
        source = program(binding, "uac-visual-settle", operation, step=step)
    try:
        result = uac._send(root, binding["spec"]["host"], operation, source, None, deadline)
    except uac._Unsubmitted:
        # Nothing reached the host. A first packet that was never sent ends its step: a new operation starts clean.
        projected = _refused("uac_transport_unsubmitted", inputs) if first else {**_refused("uac_transport_unsubmitted", inputs), "state": "unknown"}
    except Exception:  # A lost reply: the packet may still be running, so this step only settles from now on.
        return {**_refused("uac_visual_unresolved", inputs), "state": "unknown"}
    else:
        projected = _project(uac._reply(result, None), inputs, first=first)
    if _final(projected, step):
        uac._retain_once(directory, step + ".result.json", projected)
    return projected
