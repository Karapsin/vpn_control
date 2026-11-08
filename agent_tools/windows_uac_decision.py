"""One closed answer to an open UAC prompt on an owned Windows fixture.

``vm_workflow windows-uac-decision`` takes exactly host, environment, correlationId,
prompt and decision. Proof comes before any key: reviewed pixel crops read through QMP,
and a SYSTEM census of consent.exe, the owner's pending event and the UAC policy.
Nothing runs on the secure desktop. Deny is one Esc and opens no credential. Approve
reads final-administrator.secret only through SecretFile and passes it over SSH stdin
to a detached memory-only child. A create-only burn per prompt precedes the first key,
so a lost reply never types twice, and a repeat is a status packet with no key path.
The reply is an acknowledgement: it never claims that the approval or the product
outcome succeeded. This module is a leaf; no sign-in packet embeds it, and
readiness_windows._source_pins does not list it.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile
import time
from uuid import UUID, uuid5
import zlib

from . import native_scenario_execution as execution
from . import native_scenario_windows as windows
from . import readiness_windows_login as login
from . import readiness_windows_remote as packets
from . import ssh_transport as transport
from .private_credential_file import SecretFile
from .readiness_windows_login import PrivateInputUnknown, enter_private, ppm, private_keys, screen_gate

_EXECUTING_CODE = inspect.currentframe().f_code

PROMPTS = ("install-helper", "vpn-broker")
DECISIONS = ("approve", "deny")
INPUT_FIELDS = frozenset({"host", "environment", "correlationId", "prompt", "decision"})
GATE_SECONDS = 30
PROMPT_AGE_SECONDS = 90
CLOSE_WAIT_MILLISECONDS = 20000
OWNER_WAIT_SECONDS = 70
SUBMIT_SECONDS = 100
ATTEMPT_LIMIT = 16
DARK_LEVEL = 110
_HELPER_IMAGE = {"install-helper": "vpn-control-install-helper.exe", "vpn-broker": "vpn-control-vpn-broker.exe",
                 "qualification": "whoami.exe"}
_DECISION_NAMESPACE = "windows-uac-decision"
_PROFILE_FIELDS = frozenset({"schemaVersion", "deploymentId", "prompt", "width", "height", "crops", "field", "reviewedFrameSha256"})
_ATTEMPT_INTENT = re.compile(r"attempt-([0-9]{4})\.intent\.json\Z")
_ROOT_FORM = r"C:\\Users\\[A-Za-z0-9_.-]{1,64}\\AppData\\Local\\VpnControlOrdinary-"
_SID_FORM = re.compile(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\Z")
_BIRTH_FORM = re.compile(r"[1-9][0-9]{0,19}\Z")
_LITERAL = re.compile(r"[A-Za-z0-9_.:\\ -]{0,512}\Z")
_PUBLIC_REASON = re.compile(r"instance_[a-z_]{1,64}\Z")
# Refusals that prove only "not yet": a hold or an early call, a read or the lock that failed, or nothing sent.
# Any other refusal saw the prompt due or the fixture wrong, so the prompt is left to expire and a repeat
# returns that refusal with no packet. The status token outlives the prompt; this keeps a polling client cheap.
_RETRY_REASONS = frozenset({"instance_uac_event_not_pending", "instance_uac_census_unavailable", "instance_operator_busy",
                            "instance_guest_program_failed", "instance_original_guest_pending", "instance_guest_output",
                            "instance_guest_output_bound", "instance_guest_exec_ack", "uac_transport_unsubmitted",
                            "uac_credential_unavailable"})


def _update_row(decision, event, field, value, variant=None):
    return {"prompt": "install-helper", "decision": decision, "event": event, "field": field, "value": value, "variant": variant,
            "sidEvent": "update-uac-action-pending", "sidField": "approvingAdminSid"}


def _approve_update(variant):
    return _update_row("approve", "update-uac-action-pending", "action", "approve-current-prompt", variant)


# Closed table: one prompt per scenario, by dotted scenario name. A hold-current-prompt event matches
# no row, so an early call refuses and burns nothing. A name reaches a guest only once RECIPES lists it.
ROWS = {
    "windows-public-update.uac-denied": _update_row("deny", "update-uac-action-pending", "action", "deny-current-prompt", "uac-denied"),
    **{"windows-public-update." + variant: _approve_update(variant)
       for variant in ("success-off", "success-reconnect", "different-admin", "wait-client-loss",
                       "participating-copy-lock", "native-install-failed", "protected-storage-rejected")},
    "windows-public-update.install-cancelled": _update_row(
        "approve", "update-install-cancel-requested-before-authorization", "freshPromptAction",
        "approve-current-prompt-after-cancellation-request"),
    "windows-public-update.installer-wait-client-loss": _update_row(
        "approve", "update-installer-wait-client-lost", "freshPromptAction",
        "approve-current-prompt-after-wait-client-loss"),
    "windows-scoped-tun.restart-deny": {"prompt": "vpn-broker", "decision": "deny", "event": "scoped-tun-awaiting-current-input",
                                        "field": "variant", "value": "restart-deny", "variant": None,
                                        "sidEvent": "scoped-tun-awaiting-current-input", "sidField": "expectedApprovingAdminSid"},
    "windows-scoped-tun.restart-grant": {"prompt": "vpn-broker", "decision": "approve", "event": "scoped-tun-awaiting-current-input",
                                         "field": "variant", "value": "restart-grant", "variant": None,
                                         "sidEvent": "scoped-tun-awaiting-current-input", "sidField": "expectedApprovingAdminSid"},
}
# Reached only through execute(direct=True), never through MCP: the first rung of a direct proof, one name per answer.
DIRECT_ROWS = {
    "windows-uac-qualification." + answer: {"prompt": "qualification", "decision": answer, "event": "child-intent", "field": "label",
                                            "value": "qualification", "variant": None, "sidEvent": None, "sidField": None}
    for answer in DECISIONS
}

_PRELUDE = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM_REQUIRED'}\n")

_CENSUS = r"""$root=__ROOT__;$kind=__KIND__;$field=__FIELD__;$sidKind=__SID_KIND__;$sidField=__SID_FIELD__;$administrator=__ADMINISTRATOR__;$helper=__HELPER__
function Read-Owned([string]$path){
 $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{
  if($stream.Length -gt 262144){throw 'UAC_EVENT_BOUND'}
  $raw=New-Object byte[] ([int]$stream.Length);$at=0
  while($at -lt $raw.Length){$count=$stream.Read($raw,$at,$raw.Length-$at);if($count -le 0){throw 'UAC_EVENT_SHORT'};$at+=$count}
 }finally{$stream.Dispose()}
 return ([Text.UTF8Encoding]::new($false,$true).GetString($raw)|ConvertFrom-Json)
}
function Named([string]$wanted){
 if([String]::IsNullOrEmpty($wanted)){return @()}
 $pattern='\Aevent-[0-9]{6}-'+[regex]::Escape($wanted)+'\.json\z'
 return @(Get-ChildItem -LiteralPath $root -File -Force|Where-Object{$_.Name -cmatch $pattern}|Select-Object -First 8)
}
$events=@(foreach($file in (Named $kind)){$e=Read-Owned $file.FullName;[ordered]@{name=[string]$file.Name;operationId=[string]$e.operationId;value=[string]$e.value.$field;variant=[string]$e.value.variant}})
$sids=@(foreach($file in (Named $sidKind)){$e=Read-Owned $file.FullName;[string]$e.value.$sidField})
$parked=@(foreach($name in @('owner-parked.json','task-owner-parked.json')){if(Test-Path -LiteralPath (Join-Path $root $name)){$name}})
$policy=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$preload=(Get-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload').'1'
$adminSid=(Get-LocalUser -Name $administrator).SID.Value
$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5).LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
$appinfo=[int](Get-CimInstance Win32_Service -Filter "Name='Appinfo'" -OperationTimeoutSec 5).ProcessId
$all=@(Get-CimInstance Win32_Process -OperationTimeoutSec 10)
$consents=@(foreach($c in @($all|Where-Object{$_.Name -ieq 'consent.exe'}|Select-Object -First 8)){
 $p=Get-Process -Id ([int]$c.ProcessId);$start=$p.StartTime.ToUniversalTime();$sig=Get-AuthenticodeSignature -LiteralPath ([string]$c.ExecutablePath)
 [ordered]@{pid=[int]$c.ProcessId;birth=$start.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture);sessionId=[int]$c.SessionId;image=[string]$c.ExecutablePath;signature=[string]$sig.Status;signer=[string]$sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false);parentIsAppinfo=([int]$c.ParentProcessId -eq $appinfo);ageSeconds=[int][math]::Floor(([DateTime]::UtcNow-$start).TotalSeconds)}
})
$r=[ordered]@{policy=[ordered]@{enableLua=[int]$policy.EnableLUA;promptOnSecureDesktop=[int]$policy.PromptOnSecureDesktop;consentPromptBehaviorUser=[int]$policy.ConsentPromptBehaviorUser};preload=[string]$preload;adminSid=[string]$adminSid;bootFileTimeUtc=[string]$boot;events=$events;sidValues=$sids;parked=$parked;consents=$consents;helpers=@($all|Where-Object{$_.Name -ieq $helper}).Count}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 6 -Compress))
"""

_EXIT = r"""$process=Get-Process -Id __PID__ -ErrorAction SilentlyContinue
$gone=$null -eq $process
if(-not $gone){$gone=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) -cne '__BIRTH__'}
if(-not $gone){$gone=$process.WaitForExit(__WAIT__)}
[Console]::WriteLine((@{gone=[bool]$gone}|ConvertTo-Json -Compress))
"""


def _ps_literal(value):
    """A closed token as a PowerShell literal; quotes and control characters never reach a program."""
    if type(value) is not str or _LITERAL.fullmatch(value) is None:
        raise ValueError("windows_uac_literal")
    return "'" + value + "'"


def census_source(row, context, administrator):
    """The fixed read-only SYSTEM census of one closed row; ASCII, and every value is a checked token."""
    source = _PRELUDE + _CENSUS
    for marker, value in (("__ROOT__", context["operationRoot"]), ("__KIND__", row["event"]), ("__FIELD__", row["field"]),
                          ("__SID_KIND__", row["sidEvent"] or ""), ("__SID_FIELD__", row["sidField"] or ""),
                          ("__ADMINISTRATOR__", administrator), ("__HELPER__", _HELPER_IMAGE[row["prompt"]])):
        if source.count(marker) != 1:
            raise ValueError("windows_uac_census_marker")
        source = source.replace(marker, _ps_literal(value))
    source.encode("ascii")
    return source


# Everything from here to _uac_status_open runs on the VM host, embedded by inspect.getsource.
def _uac_load(path):
    """One bounded private receipt, read once."""
    import json,os,stat
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=os.geteuid()or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=65536:raise ValueError('instance_uac_receipt')
        raw=os.read(descriptor,65537)
        if len(raw)!=info.st_size:raise ValueError('instance_uac_receipt')
    finally:os.close(descriptor)
    value=json.loads(raw)
    if type(value)is not dict:raise ValueError('instance_uac_receipt')
    return value

def _uac_create(path,value):
    """Create-only, whole and durable before it returns: the burn and the journal precede the first key.

    The name appears only with every byte behind it, because the decide parent and status read these files
    while an owner may still be writing them. A link to a complete file publishes it and refuses an existing name.
    """
    import json,os,uuid
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();offset=0
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);temporary='.'+path.name+'.'+uuid.uuid4().hex+'.tmp'
    try:
        descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            while offset<len(raw):offset+=os.write(descriptor,raw[offset:])
            os.fsync(descriptor)
        finally:os.close(descriptor)
        os.link(temporary,path.name,src_dir_fd=directory,dst_dir_fd=directory,follow_symlinks=False)
    finally:
        try:
            try:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass
        finally:
            try:os.fsync(directory)
            finally:os.close(directory)

def _uac_birth(pid):
    try:
        with open('/proc/'+str(pid)+'/stat')as stream:row=stream.read(8193).rsplit(')',1)[1].split()
        return None if row[0]in {'Z','X'}else int(row[19])
    except (OSError,ValueError,IndexError):return None

def _uac_exit_source(consent,wait):
    """A fixed read of one consent process; it cannot name another program."""
    if type(consent['pid'])is not int or consent['pid']<=0 or re.fullmatch('[1-9][0-9]{0,19}',consent['birth'])is None or type(wait)is not int or not 0<=wait<=20000:raise ValueError('instance_uac_consent_identity')
    return UAC_PRELUDE+UAC_EXIT.replace('__PID__',str(consent['pid'])).replace('__BIRTH__',consent['birth']).replace('__WAIT__',str(wait))

def _uac_close_fence(root,save,decision,pid,code):
    """Closes only what this decision opened; the fence never exists without its journal."""
    import os
    prefix='direct-guest-'+decision
    if not os.path.lexists(root/(prefix+'.intent.json')):return
    if not os.path.lexists(root/(prefix+'.ack.json')):save(prefix+'.ack.json',{'operationId':decision,'ack':{'pid':pid},'replayAllowed':False})
    if not os.path.lexists(root/(prefix+'.terminal.json')):save(prefix+'.terminal.json',{'exited':True,'exitcode':code})

class _UacOwner:
    """One detached memory-only owner; no SSH descriptor or private stream survives the fork."""
    def __init__(self,root,decision,attempt):
        self.root=root;self.decision=decision;self.attempt=attempt;self.child=False;self.burned=False
        self.parent=root/'windows-uac';self.directory=self.parent/decision;self.prefix='attempt-%04d'%attempt
    def _directory(self,path):
        import os,stat
        try:os.mkdir(path,0o700)
        except FileExistsError:pass
        s=os.lstat(path)
        if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.geteuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('instance_uac_directory')
    def prepare(self):
        """The subdirectory keeps these files out of the flat VM-root census; flat names belong to sign-in."""
        import os
        self._directory(self.parent);self._directory(self.directory)
        for path in (self.parent,self.root):
            descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
        if os.path.lexists(self.directory/'input.intent.json'):raise ValueError('instance_uac_original_input_unknown')
        names=os.listdir(self.directory)
        if len(names)>256:raise ValueError('instance_uac_history_bound')
        # This packet holds the root lock, so no earlier owner of this decision is alive.
        for name in names:
            found=re.fullmatch(r'attempt-([0-9]{4})\.intent\.json',name)
            if found is None:continue
            closed=self.directory/('attempt-'+found[1]+'.terminal.json')
            if not os.path.lexists(closed)or _uac_load(closed).get('state')!='input-refused':raise ValueError('instance_uac_original_unresolved')
    def terminal(self):
        import os
        path=self.directory/(self.prefix+'.terminal.json')
        return _uac_load(path)if os.path.lexists(path)else None
    def start(self,lock,held,stream,*,wait_seconds=70):
        import os,resource,sys,time
        if not sys.platform.startswith('linux'):raise ValueError('instance_uac_owner_platform')
        self.prepare();resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        # A complete framed payload is admitted before any wire or GUI effect. Deny carries an empty frame.
        header=stream.read(4)
        if len(header)!=4:raise ValueError('instance_uac_input_incomplete')
        count=int.from_bytes(header,'big')
        if not(count==0 if UAC_DECISION=='deny'else 1<=count<=64):raise ValueError('instance_uac_input_unsupported')
        secret=stream.read(count)
        if len(secret)!=count or stream.read(1):raise ValueError('instance_uac_input_incomplete')
        if UAC_DECISION=='approve':private_keys(secret)
        _uac_create(self.directory/(self.prefix+'.intent.json'),{'operationId':self.decision,'attempt':self.attempt,'decision':UAC_DECISION,'replayAllowed':False})
        try:pid=os.fork()
        except OSError:
            # No owner exists, so nothing can type: this attempt closes as a refusal and another may follow.
            secret=None;self.fail('instance_uac_owner_fork');raise ValueError('instance_uac_owner_fork')from None
        if pid:
            secret=None;public={'operationId':self.decision,'attempt':self.attempt,'replayAllowed':False}
            try:
                limit=time.monotonic()+wait_seconds
                while time.monotonic()<limit:
                    value=self.terminal()
                    if value is not None:
                        try:os.waitpid(pid,os.WNOHANG)
                        except ChildProcessError:pass
                        return value
                    if _uac_birth(pid)is None:return {'state':'input-owner-unknown',**public}
                    time.sleep(.05)
                return {'state':'input-owner-running',**public}
            except BaseException:return {'state':'input-owner-unknown',**public}
        self.child=True
        try:
            os.setsid();keep=set(held)|{lock}
            for name in os.listdir('/proc/self/fd'):
                fd=int(name)
                if fd>2 and fd not in keep:
                    try:os.close(fd)
                    except OSError:pass
            null=os.open(os.devnull,os.O_RDWR)
            for fd in (0,1,2):os.dup2(null,fd)
            if null>2:os.close(null)
            birth=_uac_birth(os.getpid())
            if birth is None:raise ValueError('instance_uac_owner_generation')
            _uac_create(self.directory/(self.prefix+'.owner.json'),{'operationId':self.decision,'pid':os.getpid(),'birth':birth})
            return secret
        except BaseException:os._exit(70)
    def finish(self,result):
        import os
        path=self.directory/(self.prefix+'.terminal.json')
        if not os.path.lexists(path):_uac_create(path,result)
    def fail(self,reason):
        """Nothing burned means no key was possible. After the burn the input stays unknown until status reads it."""
        import os
        if os.path.lexists(self.directory/'input.terminal.json'):return self.finish(_uac_load(self.directory/'input.terminal.json'))
        self.finish({'state':'input-owner-unknown'if self.burned else'input-refused','operationId':self.decision,'attempt':self.attempt,'reason':reason,'inputAttempted':self.burned,'replayAllowed':False})

def _uac_census(value,fresh):
    """One census against the closed row. None means the prompt has not appeared yet."""
    def need(ok,code):
        if not ok:raise ValueError(code)
    context=UAC_CONTEXT
    need(type(value)is dict and set(value)=={'policy','preload','adminSid','bootFileTimeUtc','events','sidValues','parked','consents','helpers'},'instance_uac_census_shape')
    policy=value['policy']
    need(type(policy)is dict and policy.get('enableLua')==1 and policy.get('promptOnSecureDesktop')==1 and policy.get('consentPromptBehaviorUser')in (1,3),'instance_uac_policy')
    need(value['preload']=='00000409','instance_uac_keyboard')
    need(value['bootFileTimeUtc']==context['bootFileTimeUtc'],'instance_uac_boot_changed')
    need(value['parked']==[],'instance_uac_owner_parked')
    events=value['events']
    # Too early, or a hold that has not ended: nothing is burned and the client may call again.
    need(type(events)is list and events!=[],'instance_uac_event_not_pending')
    need(len(events)==1 and type(events[0])is dict and events[0].get('operationId')==UAC_SCENARIO_OPERATION and events[0].get('value')==UAC_ROW['value']
         and (UAC_ROW['variant']is None or events[0].get('variant')==UAC_ROW['variant']),'instance_uac_event_mismatch')
    administrator=value['adminSid']
    need(type(administrator)is str and re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',administrator)is not None and administrator!=context['ordinarySid'],'instance_uac_administrator')
    if UAC_ROW['sidEvent']is not None:need(value['sidValues']==[administrator],'instance_uac_administrator')
    need(value['helpers']==0,'instance_uac_helper_present')
    consents=value['consents']
    need(type(consents)is list,'instance_uac_census_shape')
    if not consents:return None
    need(len(consents)==1,'instance_uac_consent_not_unique')
    row=consents[0]
    need(type(row)is dict and set(row)=={'pid','birth','sessionId','image','signature','signer','parentIsAppinfo','ageSeconds'}
         and type(row['pid'])is int and row['pid']>0 and type(row['birth'])is str and re.fullmatch('[1-9][0-9]{0,19}',row['birth'])is not None
         and type(row['sessionId'])is int and row['sessionId']==fresh['console'] and type(row['image'])is str and row['image'].casefold()==r'c:\windows\system32\consent.exe'
         and row['signature']=='Valid' and row['signer']=='Microsoft Windows' and row['parentIsAppinfo']is True and type(row['ageSeconds'])is int,'instance_uac_consent_identity')
    need(0<=row['ageSeconds']<UAC_PROMPT_AGE,'instance_uac_prompt_age')
    return {'pid':row['pid'],'birth':row['birth'],'sessionId':row['sessionId'],'ageSeconds':row['ageSeconds'],'event':events[0]['name']}

def _uac_field_empty(raw):
    """Dark pixels in the password box: an entered character would add more than the review allowed."""
    w,h,pixels=ppm(raw);x0,y0,x1,y1=UAC_FIELD['rect'];dark=0
    for y in range(y0,y1):
        row=pixels[(y*w+x0)*3:(y*w+x1)*3]
        dark+=sum(max(row[at:at+3])<UAC_DARK_LEVEL for at in range(0,len(row),3))
    return dark<=UAC_FIELD['maxDarkPixels']

def _uac_prior_open(root,consent):
    """A new decision never types into a prompt whose earlier input stays unknown."""
    import os
    parent=root/'windows-uac';names=os.listdir(parent)
    if len(names)>4096:raise ValueError('instance_uac_history_bound')
    for name in names:
        if name==OPERATION or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',name)is None:continue
        prior=parent/name
        if os.path.lexists(prior/'input.intent.json')and not os.path.lexists(prior/'input.terminal.json'):
            known=_uac_load(prior/'input.intent.json')['consent']
            if known['pid']==consent['pid']and known['birth']==consent['birth']:raise ValueError('instance_uac_original_input_unknown')

def _uac_gate(owner,root,monitor,guard,script,fresh):
    """Reads only, bounded: a refusal here burned nothing and may be called again."""
    import os,stat,time
    def need(ok,code):
        if not ok:raise ValueError(code)
    context=UAC_CONTEXT;session=fresh['session'];directory=owner.directory;limit=time.monotonic()+UAC_GATE_SECONDS;kept=[];shots=[0]
    need(fresh['machine'].lower()==SPEC['deploymentId']and fresh['ordinary']is True and fresh['expectedSid']==context['ordinarySid']and fresh['tokenSid']==context['ordinarySid']
         and fresh['console']==context['ordinarySessionId']and session['SessionId']==fresh['console']and session['State']==0,'instance_uac_session_changed')
    def census():
        """A failed read proves nothing, so only reads are retried, and only within the bound.

        The consent row comes with the monotonic time its read began: the age it reports holds from then on.
        """
        while True:
            guard();started=time.monotonic()
            try:value=script('login-admission-'+os.urandom(6).hex(),UAC_CENSUS_SCRIPT)
            except OSError:value=None
            except ValueError as error:
                if re.fullmatch('instance_[a-z_]{1,64}',str(error))and str(error)not in {'instance_guest_program_failed','instance_original_guest_pending','instance_guest_output','instance_guest_output_bound','instance_guest_exec_ack'}:raise
                value=None
            if value is not None:
                found=_uac_census(value,fresh)
                if found is not None:return found,started
            need(time.monotonic()<limit,'instance_uac_consent_absent'if value is not None else'instance_uac_census_unavailable')
            time.sleep(1)
    def shot():
        shots[0]+=1;path=directory/('frame-%04d-%02d.ppm'%(owner.attempt,shots[0]))
        guard();monitor('screendump',{'filename':str(path),'format':'ppm'});s=os.lstat(path)
        need(stat.S_ISREG(s.st_mode)and s.st_uid==os.geteuid()and s.st_nlink==1 and s.st_size<=16*1024**2,'instance_uac_frame_identity')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            raw=b''
            while len(raw)<=16*1024**2:
                chunk=os.read(fd,65536)
                if not chunk:break
                raw+=chunk
        finally:os.close(fd)
        need(len(raw)==s.st_size,'instance_uac_frame_changed')
        # The last two frames are the evidence; a thirty second wait keeps no more than that.
        kept.append(path)
        if len(kept)>2:os.unlink(kept.pop(0))
        guard();return raw
    def recognized():
        """The reviewed prompt with an empty field, or a refusal. A black display gets one journaled pointer move and no click.

        The field is where the caret blinks, so a dark field is read again like an unrecognized frame; typed
        characters stay, and only they refuse at the bound.
        """
        while True:
            raw=shot()
            if not any(ppm(raw)[2]):
                moved=directory/'pointer.intent.json'
                need(not os.path.lexists(moved),'instance_uac_display_black')
                mice=monitor('query-mice',None);selected=[x for x in mice if type(x)is dict and x.get('current')is True]
                need(len(selected)==1 and type(selected[0].get('absolute'))is bool,'instance_uac_mouse_unrecognized')
                events=([{'type':'abs','data':{'axis':'x','value':16384}},{'type':'abs','data':{'axis':'y','value':16384}}]if selected[0]['absolute']else[{'type':'rel','data':{'axis':'x','value':1}}])
                guard();_uac_create(moved,{'operationId':OPERATION,'replayAllowed':False});monitor('input-send-event',{'events':events});guard()
                time.sleep(1);continue
            try:
                screen_gate(raw,UAC_SCREEN)
                if _uac_field_empty(raw):return raw
                failed='instance_uac_field_not_empty'
            except ValueError as error:
                if str(error)!='instance_login_screen_unrecognized':raise
                failed='instance_uac_frame_unrecognized'
            need(time.monotonic()<limit,failed)
            guard();time.sleep(.25)
    first,_=census();recognized()
    second,read=census();need((second['pid'],second['birth'])==(first['pid'],first['birth']),'instance_uac_consent_changed')
    raw=recognized();_uac_prior_open(root,second)
    return {'consent':second,'frameSha256':hashlib.sha256(raw).hexdigest(),'censusStarted':read}

def _uac_flow(owner,root,save,monitor,guard,script,fresh):
    """Proof, then the burn, the journal and the fence, then one answer. A lost owner's input stays unknown."""
    import os,time
    def durable(name,value):
        save(name,value)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    admitted=_uac_gate(owner,root,monitor,guard,script,fresh);consent=admitted['consent']
    once=hashlib.sha256(json.dumps([SPEC['deploymentId'],UAC_CONTEXT['bootFileTimeUtc'],consent['pid'],consent['birth']],separators=(',',':')).encode()).hexdigest()
    # The 90 s rule bounds a prompt that ends under the keys, so it holds at the burn: frames read since the census count.
    if consent['ageSeconds']+time.monotonic()-admitted['censusStarted']>=UAC_PROMPT_AGE:raise ValueError('instance_uac_prompt_age')
    guard();owner.burned=True
    try:_uac_create(owner.parent/('once-'+once+'.json'),{'operationId':OPERATION,'consentPid':consent['pid'],'consentBirth':consent['birth'],'replayAllowed':False})
    except FileExistsError:
        owner.burned=False;raise ValueError('instance_uac_prompt_burned')from None
    _uac_create(owner.directory/'input.intent.json',{'operationId':OPERATION,'attempt':owner.attempt,'decision':UAC_DECISION,'prompt':UAC_PROMPT,'consent':consent,'frameSha256':admitted['frameSha256'],'profileSha256':UAC_PROFILE_SHA,'onceSha256':once,'replayAllowed':False})
    durable('direct-guest-'+OPERATION+'.intent.json',{'operationId':OPERATION,'label':'uac-decision','replayAllowed':False})
    guard()
    if UAC_DECISION=='deny':monitor('send-key',{'keys':[{'type':'qcode','data':'esc'}],'hold-time':80})
    else:
        secret=globals().pop('UAC_SECRET')
        try:enter_private(secret,lambda arguments:monitor('send-key',arguments),guard)
        finally:secret=None
    # No frame from the first key until consent exits: wrong focus could show plaintext.
    try:closed=script('login-after-'+os.urandom(6).hex(),_uac_exit_source(consent,UAC_CLOSE_WAIT)).get('gone')is True
    except (OSError,ValueError):closed=False
    terminal={'state':'input-ack-only','operationId':OPERATION,'attempt':owner.attempt,'decision':UAC_DECISION,'prompt':UAC_PROMPT,'promptClosed':closed,'approvalSucceeded':False,'productOutcomeProved':False,'replayAllowed':False}
    _uac_create(owner.directory/'input.terminal.json',terminal)
    _uac_close_fence(root,durable,OPERATION,os.getpid(),0)
    return terminal

def _uac_receipts(root,decision):
    """What this decision's own receipts say: files only, no guest, no monitor, no lock and never a key."""
    import os
    directory=root/'windows-uac'/decision;public={'operationId':decision,'replayAllowed':False}
    if not os.path.lexists(directory):return {'state':'no-input-recorded',**public}
    if os.path.lexists(directory/'input.terminal.json'):
        known=_uac_load(directory/'input.terminal.json');fence='direct-guest-'+decision
        # A known input whose fence never closed is closed under the lock; left alone it would block the clone for good.
        if known.get('state')=='input-ack-only'and os.path.lexists(root/(fence+'.intent.json'))and not os.path.lexists(root/(fence+'.terminal.json')):return None
        return known
    numbers=sorted(found[1]for found in (re.fullmatch(r'attempt-([0-9]{4})\.intent\.json',name)for name in os.listdir(directory))if found)
    if not numbers:return {'state':'no-input-recorded',**public}
    owner=directory/('attempt-'+numbers[-1]+'.owner.json');closed=directory/('attempt-'+numbers[-1]+'.terminal.json');public={**public,'attempt':int(numbers[-1])}
    if os.path.lexists(owner):
        running=_uac_load(owner)
        if _uac_birth(running['pid'])==running['birth']:return {'state':'input-owner-running',**public}
    if os.path.lexists(directory/'input.intent.json'):return None
    return _uac_load(closed)if os.path.lexists(closed)else {'state':'input-owner-unknown',**public}

def _uac_status_open(root,save,guard,script):
    """Under the root lock no owner of this decision lives, and this types nothing.

    A known input whose fence close was lost gets that close, with the pid of the owner that typed. An input
    whose owner died stays UNKNOWN: status records a prompt seen gone and leaves the fence open, so reboots and
    new jobs on this clone refuse until the original is read. Any integer exit would close it.
    """
    import os
    def durable(name,value):
        save(name,value)
        descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
    directory=root/'windows-uac'/OPERATION
    if os.path.lexists(directory/'input.terminal.json'):
        known=_uac_load(directory/'input.terminal.json')
        if known.get('state')=='input-ack-only':
            typed=_uac_load(directory/('attempt-%04d.owner.json'%known['attempt']))
            guard();_uac_close_fence(root,durable,OPERATION,typed['pid'],0)
        return known
    intent=_uac_load(directory/'input.intent.json')
    guard();value=script('login-admission-'+os.urandom(6).hex(),_uac_exit_source(intent['consent'],0))
    public={'operationId':OPERATION,'attempt':intent['attempt'],'replayAllowed':False}
    if value.get('gone')is not True:return {'state':'input-owner-unknown',**public}
    terminal={'state':'input-outcome-unknown','decision':intent['decision'],'prompt':intent['prompt'],'promptClosed':True,'approvalSucceeded':False,'productOutcomeProved':False,**public}
    guard();_uac_create(directory/'input.terminal.json',terminal)
    return terminal


_DECIDE_SOURCES = (PrivateInputUnknown, private_keys, enter_private, ppm, screen_gate, _uac_load, _uac_create, _uac_birth, _uac_exit_source,
                   _uac_close_fence, _UacOwner, _uac_census, _uac_field_empty, _uac_prior_open, _uac_gate, _uac_flow)
_STATUS_SOURCES = (_uac_load, _uac_create, _uac_birth, _uac_exit_source, _uac_close_fence, _uac_receipts, _uac_status_open)


def _replace_once(source, marker, replacement):
    if source.count(marker) != 1:
        raise ValueError("windows_uac_producer_changed")
    return source.replace(marker, replacement, 1)


def program(binding, mode, decision, *, attempt=None, answer=None, prompt=None, row=None, context=None, profile=None, profile_sha=None,
            scenario_operation=None):
    """A fixed packet patched from the observe producer, as readiness_windows_login does; no pinned source moves.

    uac-status embeds no input code at all: its source holds no key path and it reads no stdin.
    """
    if mode not in {"uac-decide", "uac-status"} or type(decision) is not str or str(UUID(decision)) != decision:
        raise ValueError("windows_uac_action")
    helpers = "import hashlib,json,os,re\n"
    helpers += "UAC_PRELUDE=" + repr(_PRELUDE) + "\nUAC_EXIT=" + repr(_EXIT) + "\n"
    source = packets.program(binding, "observe", decision).decode()
    source = _replace_once(source, "MODE='observe'", "MODE=" + repr(mode))
    marker = "        elif MODE in {'observe','idle-inventory','reboot'}:\n"
    if mode == "uac-status":
        helpers += "".join(inspect.getsource(item) + "\n" for item in _STATUS_SOURCES)
        source = _replace_once(source, "        epoch();chain()",
                               "        epoch();chain()\n"
                               "        uac_known=_uac_receipts(root,OPERATION)\n"
                               "        if uac_known is not None:print(json.dumps(uac_known));return")
        source = _replace_once(source, marker,
                               "        elif MODE=='uac-status':\n"
                               "            require(state=='running','instance_guest_not_ready')\n"
                               "            result=_uac_status_open(root,save,vm_guard,script)\n" + marker)
    else:
        if (answer not in DECISIONS or type(attempt) is not int or not 1 <= attempt <= ATTEMPT_LIMIT or type(row) is not dict
                or row.get("decision") != answer or row.get("prompt") != prompt or not _canonical(scenario_operation)):
            raise ValueError("windows_uac_action")
        _validate_context(context)
        screen = {"width": profile["width"], "height": profile["height"], "crops": profile["crops"]}
        census = census_source(row, context, binding["setup"]["administrator"])
        bindings = {"UAC_DECISION": answer, "UAC_PROMPT": prompt, "UAC_ATTEMPT": attempt, "UAC_ROW": row, "UAC_CONTEXT": context, "UAC_SCREEN": screen,
                    "UAC_FIELD": profile["field"], "UAC_PROFILE_SHA": profile_sha, "UAC_SCENARIO_OPERATION": scenario_operation, "UAC_CENSUS_SCRIPT": census,
                    "UAC_GATE_SECONDS": GATE_SECONDS, "UAC_PROMPT_AGE": PROMPT_AGE_SECONDS, "UAC_CLOSE_WAIT": CLOSE_WAIT_MILLISECONDS, "UAC_DARK_LEVEL": DARK_LEVEL}
        helpers += "".join(key + "=" + repr(value) + "\n" for key, value in bindings.items())
        helpers += "".join(inspect.getsource(item) + "\n" for item in _DECIDE_SOURCES)
        source = _replace_once(source, "        epoch();chain()",
                               "        epoch();chain()\n"
                               "        uac_owner=_UacOwner(root,OPERATION,UAC_ATTEMPT)\n"
                               "        import sys")
        # The owner forks after the root lock and before opening provider connections or wire files.
        source = _replace_once(source, "        if PROVIDER=='libvirt-windows':\n            import libvirt,libvirt_qemu",
                               "        launched=uac_owner.start(lock,held,sys.stdin.buffer,wait_seconds=" + repr(OWNER_WAIT_SECONDS) + ")\n"
                               "        if type(launched)is dict:print(json.dumps(launched));return\n"
                               "        globals()['UAC_SECRET']=launched;launched=None\n"
                               "        if PROVIDER=='libvirt-windows':\n            import libvirt,libvirt_qemu")
        source = _replace_once(source, marker,
                               "        elif MODE=='uac-decide':\n"
                               "            require(state=='running','instance_guest_not_ready')\n"
                               "            fresh=script('login-session-'+os.urandom(6).hex(),SESSION_SCRIPT)\n"
                               "            result=_uac_flow(uac_owner,root,save,monitor,vm_guard,script,fresh)\n" + marker)
        source = _replace_once(source, "        vm_guard();print(json.dumps(result))",
                               "        vm_guard()\n"
                               "        if uac_owner.child:uac_owner.finish(result)\n"
                               "        print(json.dumps(result))")
        source = _replace_once(source, "        print(json.dumps({'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}))",
                               "        failed={'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}\n"
                               "        if locals().get('uac_owner')is not None and uac_owner.child:\n"
                               "            try:uac_owner.fail(reason)\n"
                               "            except BaseException:pass\n"
                               "        print(json.dumps(failed))")
        source = _replace_once(source, "        for descriptor in reversed(held):os.close(descriptor)",
                               "        for descriptor in reversed(held):os.close(descriptor)\n"
                               "        if locals().get('uac_owner')is not None and uac_owner.child:os._exit(0)")
    raw = (helpers + source).encode()
    compile(raw, "fixed Windows UAC decision", "exec")
    return raw


def decision_id(correlation_id):
    """One decision per scenario: a repeat of the same inputs reads the same journal."""
    return str(uuid5(UUID(correlation_id), _DECISION_NAMESPACE))


def _canonical(value):
    try:
        return type(value) is str and str(UUID(value)) == value
    except ValueError:
        return False


def validate_inputs(inputs, *, direct=False):
    """Exactly the five fields. The direct prompt never reaches this through MCP."""
    if (type(inputs) is not dict or set(inputs) != INPUT_FIELDS or any(type(value) is not str for value in inputs.values())
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", inputs["host"]) is None
            or not _canonical(inputs["environment"]) or not _canonical(inputs["correlationId"])
            or inputs["decision"] not in DECISIONS
            or inputs["prompt"] not in (*PROMPTS, *(("qualification",) if direct else ()))):
        raise ValueError("windows_uac_inputs")
    return inputs


def _validate_context(context):
    if (type(context) is not dict or set(context) != {"operationRoot", "ordinarySid", "ordinarySessionId", "bootFileTimeUtc"}
            or type(context["operationRoot"]) is not str or type(context["ordinarySid"]) is not str
            or _SID_FORM.fullmatch(context["ordinarySid"]) is None or type(context["ordinarySessionId"]) is not int
            or context["ordinarySessionId"] < 0 or type(context["bootFileTimeUtc"]) is not str
            or _BIRTH_FORM.fullmatch(context["bootFileTimeUtc"]) is None
            or re.fullmatch(_ROOT_FORM + "[0-9a-f-]{36}", context["operationRoot"]) is None):
        raise ValueError("windows_uac_context")
    return context


def validate_profile(profile, deployment, prompt):
    """A reviewed profile: exact crops that leave out the caret's field and the pointer's parking place."""
    def rect(value, width, height):
        if type(value) is not list or len(value) != 4 or any(type(item) is not int for item in value):
            raise ValueError("windows_uac_profile")
        x0, y0, x1, y1 = value
        if not 0 <= x0 < x1 <= width or not 0 <= y0 < y1 <= height:
            raise ValueError("windows_uac_profile")
        return value

    def overlaps(left, right):
        return left[0] < right[2] and right[0] < left[2] and left[1] < right[3] and right[1] < left[3]
    if (type(profile) is not dict or set(profile) != _PROFILE_FIELDS or type(profile["schemaVersion"]) is not int or profile["schemaVersion"] != 1 or profile["deploymentId"] != deployment
            or profile["prompt"] != prompt or type(profile["width"]) is not int or type(profile["height"]) is not int
            or not 320 <= profile["width"] <= 4096 or not 200 <= profile["height"] <= 2160
            or type(profile["crops"]) is not list or not 1 <= len(profile["crops"]) <= 8
            or type(profile["reviewedFrameSha256"]) is not str or re.fullmatch("[0-9a-f]{64}", profile["reviewedFrameSha256"]) is None):
        raise ValueError("windows_uac_profile")
    width, height = profile["width"], profile["height"]
    field = profile["field"]
    if (type(field) is not dict or set(field) != {"rect", "maxDarkPixels"} or type(field["maxDarkPixels"]) is not int or field["maxDarkPixels"] < 0):
        raise ValueError("windows_uac_profile")
    box = rect(field["rect"], width, height)
    # A pointer move for a black display parks the arrow here: abs 16384 of 32767 is the centre of the frame.
    pointer = [width // 2 - 4, height // 2 - 4, width // 2 + 24, height // 2 + 40]
    if overlaps(box, pointer):
        raise ValueError("windows_uac_profile_pointer_gap")
    for row in profile["crops"]:
        if type(row) is not dict or set(row) != {"rect", "sha256"} or type(row["sha256"]) is not str or re.fullmatch("[0-9a-f]{64}", row["sha256"]) is None:
            raise ValueError("windows_uac_profile")
        crop = rect(row["rect"], width, height)
        if overlaps(crop, pointer):
            raise ValueError("windows_uac_profile_pointer_gap")
        if overlaps(crop, box):
            raise ValueError("windows_uac_profile_caret")
    return profile


def _png_pixels(raw):
    """The RGB rows of one QMP screendump PNG; truecolor, 8 bit, not interlaced, and nothing else."""
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("windows_uac_frame_format")
    at = 8
    width = height = None
    compressed = bytearray()
    while at < len(raw):
        size = struct.unpack(">I", raw[at:at + 4])[0]
        kind, body = raw[at + 4:at + 8], raw[at + 8:at + 8 + size]
        if at + 12 + size > len(raw) or zlib.crc32(kind + body) & 0xffffffff != struct.unpack(">I", raw[at + 8 + size:at + 12 + size])[0]:
            raise ValueError("windows_uac_frame_format")
        at += 12 + size
        if kind == b"IHDR":
            width, height, depth, color, compression, method, interlace = struct.unpack(">IIBBBBB", body)
            if (depth, color, compression, method, interlace) != (8, 2, 0, 0, 0):
                raise ValueError("windows_uac_frame_format")
        elif kind == b"IDAT":
            compressed.extend(body)
        elif kind == b"IEND":
            break
    if width is None or not 320 <= width <= 4096 or not 200 <= height <= 2160:
        raise ValueError("windows_uac_frame_format")
    stride = width * 3
    rows = zlib.decompress(bytes(compressed))
    if len(rows) != height * (stride + 1):
        raise ValueError("windows_uac_frame_format")
    pixels = bytearray(height * stride)
    above = bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, row = rows[start], bytearray(rows[start + 1:start + 1 + stride])
        if kind > 4:
            raise ValueError("windows_uac_frame_format")
        for x in range(stride):
            left = row[x - 3] if x >= 3 else 0
            up = above[x]
            corner = above[x - 3] if x >= 3 else 0
            if kind == 1:
                value = left
            elif kind == 2:
                value = up
            elif kind == 3:
                value = (left + up) // 2
            elif kind == 4:
                estimate = left + up - corner
                near = (abs(estimate - left), abs(estimate - up), abs(estimate - corner))
                value = left if near[0] <= near[1] and near[0] <= near[2] else up if near[1] <= near[2] else corner
            else:
                value = 0
            row[x] = (row[x] + value) & 255
        pixels[y * stride:(y + 1) * stride] = row
        above = row
    return width, height, bytes(pixels)


def reviewed_uac_profile(root, deployment, prompt, frame, crops, field, max_dark_pixels, *, direct=False):
    """Hash the reviewed regions of a frame the reviewer opened, with the prompt up and unanswered.

    Direct setup only, with no MCP route. The frame shows public pixels and an empty field, and
    the profile is create-only: a changed layout is a new review of a new clone.
    """
    if type(deployment) is not str or not _canonical(deployment) or prompt not in (*PROMPTS, *(("qualification",) if direct else ())):
        raise ValueError("windows_uac_profile")
    width, height, pixels = _png_pixels(frame) if frame.startswith(b"\x89PNG") else ppm(frame)

    def region(rect):
        return b"".join(pixels[(y * width + rect[0]) * 3:(y * width + rect[2]) * 3] for y in range(rect[1], rect[3]))
    rows = [{"rect": list(rect), "sha256": hashlib.sha256(region(rect)).hexdigest()} for rect in crops]
    profile = {"schemaVersion": 1, "deploymentId": deployment, "prompt": prompt, "width": width, "height": height, "crops": rows,
               "field": {"rect": list(field), "maxDarkPixels": max_dark_pixels}, "reviewedFrameSha256": hashlib.sha256(frame).hexdigest()}
    validate_profile(profile, deployment, prompt)
    inside = region(field)
    if sum(max(inside[at:at + 3]) < DARK_LEVEL for at in range(0, len(inside), 3)) > max_dark_pixels:
        raise ValueError("windows_uac_profile_field_not_empty")
    directory = Path(root).resolve(strict=True) / ".runtime/windows-uac-profiles" / deployment
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path in (directory.parent, directory):
        os.chmod(path, 0o700)
    login._retain_local(directory, prompt + ".json", profile)
    return profile


def _read_private(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 65536):
            raise ValueError("windows_uac_private_file")
        raw = os.read(descriptor, 65537)
    finally:
        os.close(descriptor)
    if len(raw) != info.st_size:
        raise ValueError("windows_uac_private_file")
    return raw


def _load_profile(root, deployment, prompt):
    raw = _read_private(root / ".runtime/windows-uac-profiles" / deployment / (prompt + ".json"))
    return validate_profile(json.loads(raw), deployment, prompt), hashlib.sha256(raw).hexdigest()


def _scenario_record(root, correlation):
    journal = root / ".rag_index/native-scenario-executions"
    if not os.path.lexists(journal / (correlation + ".json")):
        return None
    return execution.ScenarioExecutor(journal, None)._read(correlation)


def _journal_directory(root, decision):
    parent = root / ".runtime/windows-uac-decisions"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for path, mask in ((root / ".runtime", 0o022), (parent, 0o077)):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & mask:
            raise ValueError("windows_uac_journal_owner")
    directory = parent / decision
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("windows_uac_journal_owner")
    return directory


def _next_attempt(directory):
    """(next attempt, None), or (None, original) when an earlier submit has no retained known refusal."""
    if not os.path.lexists(directory):
        return 1, None
    numbers = sorted(int(found[1]) for found in (_ATTEMPT_INTENT.fullmatch(name) for name in os.listdir(directory)) if found)
    for number in numbers:
        path = directory / ("attempt-%04d.result.json" % number)
        if not os.path.lexists(path) or json.loads(_read_private(path)).get("state") != "refused":
            return None, number
    return (numbers[-1] + 1 if numbers else 1), None


def _final_refusal(directory, number):
    """The retained refusal of that attempt when it ends this decision's submits, else None."""
    if number < 1:
        return None
    value = json.loads(_read_private(directory / ("attempt-%04d.result.json" % number)))
    return value if value.get("reason") not in _RETRY_REASONS else None


def _retain_once(directory, name, value):
    try:
        login._retain_local(directory, name, value)
    except FileExistsError:
        pass


def _command(source):
    return ["python3", "-I", "-B", "-c", "import base64;exec(base64.b64decode(" + repr(base64.b64encode(source).decode()) + "))"]


@contextmanager
def _admitted(root, config, host, operation, deadline):
    if transport._dispatch_binding(config, host) is not None:
        yield  # The public dispatch boundary already admitted this host.
        return
    with transport.admitted_transport(root, host, operation, deadline=deadline):
        yield


class _Unsubmitted(Exception):
    """Typed proof that this packet never reached the target."""


def _send(root, host, operation, source, frame, deadline):
    """One SSH child. Only stdin carries a secret; a typed unsubmitted refusal alone permits another submit."""
    from . import readiness
    consumed = False
    try:
        config = transport.load_config(root)
        with _admitted(root, config, host, operation, deadline):
            argv = transport.build_ssh_argv(config, host, command=_command(source))
            connection = transport.connection_host(config, host)
            remaining = deadline - time.monotonic()
            if not math.isfinite(remaining) or remaining <= 0:
                raise _Unsubmitted()

            def run(environment=None):
                options = {"stdin": subprocess.DEVNULL} if frame is None else {"input": frame}
                return transport.run_ssh(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(SUBMIT_SECONDS, remaining),
                                         env=environment, check=False, **options)
            consumed = True
            try:
                if connection.password is not None:
                    with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
                        return run(transport._askpass_environment(connection.password, Path(directory))[1])
                return run()
            except (transport.PrelaunchReadinessRefusal, transport.StagedExecutionUnsubmitted):
                consumed = False
                raise
            except transport.SubmittedResultReadinessChanged as error:
                return error.take_submitted_result()
    except (_Unsubmitted, transport.SshConfigError, readiness.ReadinessBlocked) as error:
        if consumed:
            raise
        raise _Unsubmitted() from error


def _reply(result, private):
    """A finite parse of the reply. Bytes from a private path are scanned and never retained, hashed or measured."""
    if private and (private in result.stdout or private in result.stderr):
        return None
    if result.returncode or result.stderr or len(result.stdout) > 262144:
        return None
    try:
        value = json.loads(result.stdout, object_pairs_hook=transport._reject_duplicate_keys)
    except ValueError:
        return None
    return value if type(value) is dict else None


_ACK_FIELDS = frozenset({"state", "operationId", "attempt", "decision", "prompt", "promptClosed", "approvalSucceeded", "productOutcomeProved", "replayAllowed"})


def _project(value, decision, inputs, *, submitted):
    """Only closed fields cross: the reply is ack-only and never claims approval or a product outcome."""
    public = {"decisionId": decision, "correlationId": inputs["correlationId"], "prompt": inputs["prompt"], "decision": inputs["decision"], "replayAllowed": False}
    unknown = {"state": "unknown", "reason": "uac_reply_rejected", **public}
    if value is None or value.get("operationId") != decision or value.get("replayAllowed") is not False:
        return unknown
    state = value.get("state")
    if state in {"input-ack-only", "input-outcome-unknown"}:
        if (set(value) != _ACK_FIELDS or type(value["promptClosed"]) is not bool or type(value["attempt"]) is not int or value["approvalSucceeded"] is not False
                or value["productOutcomeProved"] is not False or value["decision"] != inputs["decision"] or value["prompt"] != inputs["prompt"]):
            return unknown
        return {"state": state, "promptClosed": value["promptClosed"], "approvalSucceeded": False, "productOutcomeProved": False,
                "attempt": value["attempt"], **public}
    reason = value.get("reason")
    if state == "input-refused":
        if (value.get("inputAttempted") is not False or type(reason) is not str or _PUBLIC_REASON.fullmatch(reason) is None
                or type(value.get("attempt")) is not int):
            return unknown
        return {"state": "refused", "reason": reason, "attempt": value["attempt"], **public}
    if state == "blocked" and type(reason) is str and _PUBLIC_REASON.fullmatch(reason) is not None:
        # A decide packet prints this only before its fork, so no owner exists. Status proves nothing by it.
        return ({"state": "refused", "reason": reason, **public} if submitted else {"state": "unknown", "reason": reason, **public})
    if state == "input-owner-running":
        return {"state": "running", "reason": "uac_original_owner_running", **public}
    if state == "input-owner-unknown":
        return {"state": "unknown", "reason": "uac_original_input_unknown", **public}
    if state == "no-input-recorded":
        return {"state": "unknown", "reason": "uac_original_submission_unknown", **public}
    return unknown


def _refused(reason, decision, inputs):
    return {"state": "refused", "reason": reason, "decisionId": decision, "correlationId": inputs["correlationId"], "prompt": inputs["prompt"],
            "decision": inputs["decision"], "replayAllowed": False}


def _retain_result(directory, attempt, result):
    """Known results only: a retained refusal is what permits another submit."""
    if type(attempt) is int and result["state"] in {"refused", "input-ack-only", "input-outcome-unknown"}:
        _retain_once(directory, "attempt-%04d.result.json" % attempt, result)


def _status(root, binding, decision, inputs, directory, attempt, deadline):
    source = program(binding, "uac-status", decision)
    try:
        result = _send(root, inputs["host"], decision, source, None, deadline)
    except Exception:  # A status read proves nothing by failing, and it is only ever read again.
        return {**_refused("uac_status_unavailable", decision, inputs), "state": "unknown"}
    value = _project(_reply(result, None), decision, inputs, submitted=False)
    # Status may name another attempt only if this client lost that reply; the journal says which one is open.
    _retain_result(directory, attempt if value.get("attempt") == attempt else None, value)
    return value


def execute(root, inputs, *, deadline=None, direct=False):
    """Gates, then one journaled packet. A repeat is a status packet, forever, unless a known refusal was retained:
    one that proved nothing yet permits another submit, and any other is returned again with no packet."""
    validate_inputs(inputs, direct=direct)
    root = Path(root).resolve(strict=True)
    if deadline is None:
        deadline = time.monotonic() + SUBMIT_SECONDS + 10
    current = Path(__file__)
    if _EXECUTING_CODE != compile(current.read_bytes(), str(current), "exec", dont_inherit=True):
        raise ValueError("windows_uac_source_changed")
    correlation = inputs["correlationId"]
    decision = decision_id(correlation)
    try:
        record = _scenario_record(root, correlation)
    except ValueError:
        return _refused("uac_scenario_journal_invalid", decision, inputs)
    if record is None:
        return _refused("uac_scenario_unknown", decision, inputs)
    plan = execution.ScenarioPlan.from_mapping(record["plan"])
    table = {**ROWS, **(DIRECT_ROWS if direct else {})}
    row = table.get(plan.scenario_id)
    if (plan.host, plan.environment) != (inputs["host"], inputs["environment"]) or plan.correlation_id != correlation:
        return _refused("uac_scenario_mismatch", decision, inputs)
    if row is None:
        return _refused("uac_scenario_not_in_table", decision, inputs)
    if row["prompt"] != inputs["prompt"] or row["decision"] != inputs["decision"]:
        return _refused("uac_row_mismatch", decision, inputs)
    try:
        binding = windows._binding(root, plan)
    except ValueError:
        return _refused("uac_environment_unavailable", decision, inputs)
    directory = root / ".runtime/windows-uac-decisions" / decision
    attempt, original = _next_attempt(directory)
    if attempt is None:
        return _status(root, binding, decision, inputs, directory, original, deadline)
    final = _final_refusal(directory, attempt - 1)
    if final is not None:
        return final
    if attempt > ATTEMPT_LIMIT:
        return _refused("uac_attempts_exhausted", decision, inputs)
    if record["state"] != execution.ExecutionState.SUBMITTED.value:
        return _refused("uac_scenario_not_running", decision, inputs)
    try:
        profile, profile_sha = _load_profile(root, inputs["environment"], inputs["prompt"])
    except (OSError, ValueError):
        return _refused("uac_profile_unreviewed", decision, inputs)
    try:
        context = _validate_context(windows.NativeScenarioWindowsDriver(root, lambda _plan: None).uac_context(plan))
    except (OSError, ValueError):
        return _refused("uac_context_unavailable", decision, inputs)
    if re.fullmatch(_ROOT_FORM + re.escape(correlation), context["operationRoot"]) is None:
        return _refused("uac_context_unavailable", decision, inputs)
    source = program(binding, "uac-decide", decision, attempt=attempt, answer=inputs["decision"], prompt=inputs["prompt"], row=row, context=context,
                     profile=profile, profile_sha=profile_sha, scenario_operation=correlation)
    directory = _journal_directory(root, decision)
    intended = {"decisionId": decision, "correlationId": correlation, "host": inputs["host"], "environment": inputs["environment"],
                "scenarioId": plan.scenario_id, "prompt": inputs["prompt"], "decision": inputs["decision"], "replayAllowed": False}
    try:
        login._retain_local(directory, "intent.json", intended)
    except FileExistsError:
        if json.loads(_read_private(directory / "intent.json")) != intended:
            raise ValueError("windows_uac_original_changed") from None
    label = "attempt-%04d" % attempt
    try:
        # Public packet custody and the attempt's journal, both before the credential opens.
        login._retain_local(directory, label + ".intent.json", {"decisionId": decision, "attempt": attempt, "sourceSha256": hashlib.sha256(source).hexdigest(), "replayAllowed": False})
    except FileExistsError:
        return _status(root, binding, decision, inputs, directory, attempt, deadline)
    login._retain_local(directory, label + ".py", source)
    private = frame = secret = None
    try:
        if inputs["decision"] == "approve":
            path = root / ".runtime/windows-vm-credentials" / inputs["environment"] / "final-administrator.secret"
            try:
                secret = SecretFile(str(path))
                private = secret.text.encode("ascii")
                private_keys(private)
                secret.guard()
            except (OSError, ValueError):
                refused = _refused("uac_credential_unavailable", decision, inputs)
                _retain_result(directory, attempt, refused)
                return refused
        frame = (b"\x00\x00\x00\x00" if private is None else len(private).to_bytes(4, "big") + private)
        try:
            result = _send(root, inputs["host"], decision, source, frame, deadline)
        except _Unsubmitted:
            refused = _refused("uac_transport_unsubmitted", decision, inputs)
            _retain_result(directory, attempt, refused)
            return refused
        except Exception:  # A lost reply: the child may still be running, so this decision only reads from now on.
            return {**_refused("uac_submission_unresolved", decision, inputs), "state": "unknown"}
        value = _reply(result, private)
        if secret is not None:
            secret.guard()
        projected = _project(value, decision, inputs, submitted=True)
        _retain_result(directory, attempt, projected)
        return projected
    finally:
        private = None
        frame = None
        if secret is not None:
            secret.close()
