"""Original retained input observer for a named, configured Windows guest.

This schema/renderer does not mint native admission. The owning producer must
supply context internally from its named configured profile and actual owner
admission metadata, retain the corresponding source/input/route pins, and join
this task's actual accepted ACK and binding before any key. Do not expose the
context, guard source, paths or policy flags as MCP selectors.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import PureWindowsPath
import hashlib
import re
import uuid

@dataclass(frozen=True)
class GuardProcessFacts:
    pid: int
    parent_pid: int
    birth: int

@dataclass(frozen=True)
class CurrentGuestContext:
    profile_name: str
    ordinary_sid: str
    session_id: int
    boot_utc: str
    console_pid: int
    console_birth: int
    owner_wrapper: GuardProcessFacts
    owner: GuardProcessFacts
    frontend: GuardProcessFacts
    install_directory: str
    input_parent_directory: str
    state_directory: str
    task_parent_directory: str
    owner_controller_id: str
    package_sha256: str
    package_bytes: int
    helper_sha256: str
    caller_source_sha: str
    caller_content_fingerprint: str
    package_source_sha: str


def _guard_integer(value: int, maximum: int) -> str:
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError('GUARD_CONTEXT_INTEGER')
    return str(value)


def _guard_path(value: str) -> str:
    if type(value) is not str or not value or len(value) > 8192 or "'" in value or any(ord(c) < 32 for c in value):
        raise ValueError('GUARD_CONTEXT_PATH')
    path = PureWindowsPath(value)
    if not path.is_absolute() or path.drive.startswith('\\\\') or '..' in path.parts or '.' in path.parts:
        raise ValueError('GUARD_CONTEXT_PATH')
    return str(path)


def _guard_epoch(birth: int) -> str:
    _guard_integer(birth, (1 << 63) - 1)
    epoch = birth // 10000 - 11644473600000
    return _guard_integer(epoch, (1 << 63) - 1)


def _guard_slot_values(context: CurrentGuestContext) -> dict[str, str]:
    if type(context) is not CurrentGuestContext:
        raise ValueError('GUARD_CONTEXT_SCHEMA')
    if type(context.profile_name) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', context.profile_name):
        raise ValueError('GUARD_CONTEXT_PROFILE')
    if type(context.ordinary_sid) is not str or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', context.ordinary_sid):
        raise ValueError('GUARD_CONTEXT_SID')
    # Token policy remains explicit; the session comes from current admission.
    if type(context.session_id) is not int or not 0 < context.session_id <= 16383:
        raise ValueError('GUARD_CONTEXT_SESSION_POLICY')
    if type(context.boot_utc) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z', context.boot_utc):
        raise ValueError('GUARD_CONTEXT_BOOT')
    for name in ('package_sha256', 'helper_sha256', 'caller_content_fingerprint'):
        value = getattr(context, name)
        if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('GUARD_CONTEXT_SHA')
    for name in ('caller_source_sha', 'package_source_sha'):
        value = getattr(context, name)
        if type(value) is not str or not re.fullmatch(r'[0-9a-f]{40}', value):
            raise ValueError('GUARD_CONTEXT_SOURCE_SHA')
    if type(context.owner_controller_id) is not str or str(uuid.UUID(context.owner_controller_id)) != context.owner_controller_id:
        raise ValueError('GUARD_CONTEXT_CONTROLLER')
    rows = []
    for role, cli in ((context.owner_wrapper, True), (context.owner, True), (context.frontend, False)):
        if type(role) is not GuardProcessFacts:
            raise ValueError('GUARD_CONTEXT_ROLE_SCHEMA')
        pid = _guard_integer(role.pid, (1 << 31) - 1)
        parent = _guard_integer(role.parent_pid, (1 << 31) - 1)
        birth = _guard_integer(role.birth, (1 << 63) - 1)
        rows.append('@{pid='+pid+';parent='+parent+';birth='+birth+';cli='+('$true' if cli else '$false')+'}')
    if len({context.owner_wrapper.pid, context.owner.pid, context.frontend.pid}) != 3 or context.owner.parent_pid != context.owner_wrapper.pid or context.frontend.parent_pid != context.owner.pid:
        raise ValueError('GUARD_CONTEXT_ROLE_CHAIN')
    install = PureWindowsPath(_guard_path(context.install_directory))
    input_parent = _guard_path(context.input_parent_directory)
    state = _guard_path(context.state_directory)
    _guard_path(context.task_parent_directory)
    session = str(context.session_id)
    return {
        'ROLE_ROWS': '@('+','.join(rows)+')',
        'SID': context.ordinary_sid,
        'CLI_PATH': str(install / 'vpn-control-cli.exe'),
        'GUI_PATH': str(install / 'vpn-control.exe'),
        'HELPER_PATH': str(install / 'app' / 'native' / 'windows-amd64' / 'vpn-control-install-helper.exe'),
        'INPUT_PARENT': input_parent,
        'STATE_DIRECTORY': state,
        'CONSOLE_PID': _guard_integer(context.console_pid, (1 << 31) - 1),
        'CONSOLE_BIRTH': _guard_integer(context.console_birth, (1 << 63) - 1),
        'OWNER_PID': str(context.owner.pid),
        'OWNER_BIRTH': str(context.owner.birth),
        'OWNER_WRAPPER_PID': str(context.owner_wrapper.pid),
        'OWNER_WRAPPER_BIRTH': str(context.owner_wrapper.birth),
        'FRONTEND_PID': str(context.frontend.pid),
        'OWNER_EPOCH': _guard_epoch(context.owner.birth),
        'FRONTEND_EPOCH': _guard_epoch(context.frontend.birth),
        'PACKAGE_SHA': context.package_sha256,
        'PACKAGE_BYTES': _guard_integer(context.package_bytes, (1 << 63) - 1),
        'BOOT_UTC': context.boot_utc,
        'SESSION_CSHARP': 'Info(t,12)!='+session,
        'SESSION_TOKEN': "$t[5] -cne '"+session+"'",
        'SESSION_ROW': 'session='+session,
        'SESSION_CONSOLE': '$explorer.SessionId -ne '+session,
        'SESSION_OWNER': '$owner.SessionId -ne '+session,
        'SESSION_CONSENT_CIM': '$_.SessionId -eq '+session,
        'SESSION_CONSENT_NATIVE': '$consentActor.sessionId -ne '+session,
        'SESSION_OUTPUT': 'sessionId='+session,
    }


def _guard_token_values(policy):
    # Select one exact ordinary token class; full/elevated administrators and
    # inconsistent membership/type combinations never qualify.
    if type(policy) is not transport.WindowsInputTokenPolicy:
        raise ValueError('GUARD_TOKEN_POLICY')
    values = (policy.kind, policy.elevation, policy.elevation_type, policy.admin_member, policy.admin_enabled)
    if (type(policy.kind) is not str or type(policy.elevation) is not int
            or type(policy.elevation_type) is not int or type(policy.admin_member) is not bool
            or type(policy.admin_enabled) is not bool or values not in (
                ('ordinaryFilteredAdmin', 0, 3, True, False),
                ('ordinaryStandardUser', 0, 1, False, False))):
        raise ValueError('GUARD_TOKEN_POLICY')
    return {'TOKEN_TYPE': str(policy.elevation_type),
            'ADMIN_MEMBER': str(policy.admin_member),
            'ADMIN_MEMBER_CSHARP': str(policy.admin_member).lower()}


def render_unbound_current_guest_guard(context: CurrentGuestContext, token_policy) -> str:
    # Only the embedded, fixed template is accepted. Actual binding is joined later.
    if hashlib.sha256(CURRENT_GUEST_GUARD_TEMPLATE.encode('utf-8')).hexdigest() != CURRENT_GUEST_GUARD_TEMPLATE_SHA256:
        raise ValueError('GUARD_TEMPLATE_SOURCE')
    values = {**_guard_slot_values(context), **_guard_token_values(token_policy)}
    body = CURRENT_GUEST_GUARD_TEMPLATE
    for key, value in values.items():
        body = body.replace('__CTX_'+key+'__', value)
    if '__CTX_' in body or body.count('__CURRENT_BINDING__') != 1:
        raise ValueError('GUARD_TEMPLATE_SLOTS')
    if len(body.encode('utf-8')) > 65536:
        raise ValueError('GUARD_BODY_BOUND')
    return body


def configured_task_root(context: CurrentGuestContext, planned_correlation: str) -> str:
    # The owning producer must require this context's parent from the named profile.
    if type(planned_correlation) is not str or str(uuid.UUID(planned_correlation)) != planned_correlation:
        raise ValueError('GUARD_PLANNED_CORRELATION')
    return str(PureWindowsPath(_guard_path(context.task_parent_directory)) / ('install-operation-'+planned_correlation))

CURRENT_GUEST_GUARD_ORIGINAL_SHA256 = 'c8e6b921c0cc88cedf0826a7658429cbd84619a59fbcf4f4dc7d24bfd49d5f77'
CURRENT_GUEST_GUARD_TEMPLATE_SHA256 = '5c04984b733531ea9529b2490f265d203b849bd07080e6c985e0c43b6d336d20'
CURRENT_GUEST_GUARD_TEMPLATE = r"""$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$b='__CURRENT_BINDING__'|ConvertFrom-Json
$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'

using System; using System.ComponentModel; using System.Runtime.InteropServices; using System.Security.Principal;
public static class Cp117OwnerToken {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr p,out long creation,out long exit,out long kernel,out long user);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int kind,IntPtr data,int size,out int needed);
 static int Info(IntPtr t,int kind) { IntPtr b=Marshal.AllocHGlobal(4); try { int n;if(!GetTokenInformation(t,kind,b,4,out n)||n!=4)throw new Win32Exception(Marshal.GetLastWin32Error());return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);} }
 [StructLayout(LayoutKind.Sequential)]struct Group { public IntPtr sid;public uint attributes; }
 [StructLayout(LayoutKind.Sequential)]struct Groups { public uint count;public Group first; }
 static bool[] Admin(IntPtr t) {
  int n;GetTokenInformation(t,2,IntPtr.Zero,0,out n);if(n<=0||n>32768)throw new InvalidOperationException("groups-bound");IntPtr b=Marshal.AllocHGlobal(n);
  try {int used;if(!GetTokenInformation(t,2,b,n,out used)||used>n)throw new Win32Exception(Marshal.GetLastWin32Error());int count=Marshal.ReadInt32(b);if(count<0||count>256)throw new InvalidOperationException("groups-count");int offset=Marshal.OffsetOf(typeof(Groups),"first").ToInt32(),stride=Marshal.SizeOf(typeof(Group));bool member=false,enabled=false;
   if(offset+count*stride>used)throw new InvalidOperationException("groups-shape");
   for(int i=0;i<count;i++){Group g=(Group)Marshal.PtrToStructure(IntPtr.Add(b,offset+i*stride),typeof(Group));if(new SecurityIdentifier(g.sid).Value=="S-1-5-32-544"){member=true;enabled=(g.attributes&4)!=0&&(g.attributes&16)==0;}}
   return new bool[]{member,enabled};
  }finally{Marshal.FreeHGlobal(b);}
 }
 public static WindowsImpersonationContext Impersonate(int pid,long creation) {
  IntPtr p=OpenProcess(0x1000,false,pid),t=IntPtr.Zero;if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=creation)throw new InvalidOperationException("process-generation");
   if(!OpenProcessToken(p,10,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(WindowsIdentity id=new WindowsIdentity(t)){bool[] admin=Admin(t);if(id.User.Value!="__CTX_SID__"||Info(t,20)!=0||Info(t,18)!=__CTX_TOKEN_TYPE__||admin[0]!=__CTX_ADMIN_MEMBER_CSHARP__||admin[1]||__CTX_SESSION_CSHARP__)throw new InvalidOperationException("impersonation-token");}
   return WindowsIdentity.Impersonate(t);
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }

 public static string[] Read(int pid,long creation) {
  IntPtr p=OpenProcess(0x1000,false,pid),t=IntPtr.Zero;if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=creation)throw new InvalidOperationException("process-generation");
   if(!OpenProcessToken(p,10,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(WindowsIdentity id=new WindowsIdentity(t)) {bool[] admin=Admin(t);
    return new string[]{id.User.Value,Info(t,20).ToString(),Info(t,18).ToString(),admin[0].ToString(),admin[1].ToString(),Info(t,12).ToString()}; }
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }
}

'@ -ReferencedAssemblies @('System','System.Core')
$cli='__CTX_CLI_PATH__';$gui='__CTX_GUI_PATH__';
function CurrentGui {
$expected=__CTX_ROLE_ROWS__;$seen=@();foreach($r in $expected){$p=$null;try{$path=if($r.cli){$cli}else{$gui};$p=Get-Process -Id $r.pid;$null=$p.Handle;$t=[Cp117OwnerToken]::Read($p.Id,$r.birth);$x=Get-CimInstance Win32_Process -Filter ('ProcessId='+$r.pid);if($p.HasExited -or $p.StartTime.ToFileTimeUtc() -ne $r.birth -or $p.Path -ine $path -or $t[0] -cne $b.originalSid -or $t[1] -cne '0' -or $t[2] -cne '__CTX_TOKEN_TYPE__' -or $t[3] -cne '__CTX_ADMIN_MEMBER__' -or $t[4] -cne 'False' -or __CTX_SESSION_TOKEN__ -or -not $x -or $x.ParentProcessId -ne $r.parent){throw 'CURRENT_PERSISTENT_ROLE_WITNESS'};$seen+=@{pid=$p.Id;parentPid=$x.ParentProcessId;birth=$r.birth;cimUtc=$x.CreationDate.ToUniversalTime().ToString('o');role=$(if($r.cli){'persistentCLI'}else{'GUIFrontend'})}}finally{if($p){$p.Dispose()}}};return @{ownerMode='persistentServe';ownerPid=__CTX_OWNER_PID__;ownerBirth=__CTX_OWNER_BIRTH__;chain=$seen;sid=$b.originalSid;__CTX_SESSION_ROW__;elevationType=__CTX_TOKEN_TYPE__;guiAttached=$true}
}
$null=CurrentGui
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class ChainToken{[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("advapi32.dll",SetLastError=true)]public static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);[DllImport("advapi32.dll",SetLastError=true)]public static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,uint n,out uint r);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}'
function Info($token,[int]$kind){$buf=[Runtime.InteropServices.Marshal]::AllocHGlobal(4);try{[uint32]$count=0;if(-not[ChainToken]::GetTokenInformation($token,$kind,$buf,4,[ref]$count)-or $count -ne 4){throw 'TOKEN_INFO'};return [Runtime.InteropServices.Marshal]::ReadInt32($buf)}finally{[Runtime.InteropServices.Marshal]::FreeHGlobal($buf)}}
$explorer=Get-Process -Id __CTX_CONSOLE_PID__ -ErrorAction Stop;if($explorer.StartTime.ToFileTimeUtc() -ne __CTX_CONSOLE_BIRTH__ -or __CTX_SESSION_CONSOLE__){throw 'CONSOLE_BIRTH'}
$ph=[ChainToken]::OpenProcess(0x1000,$false,__CTX_CONSOLE_PID__);$token=[IntPtr]::Zero;if($ph -eq [IntPtr]::Zero){throw 'CONSOLE_PROCESS'}
try{if(-not[ChainToken]::OpenProcessToken($ph,10,[ref]$token)){throw 'CONSOLE_TOKEN'};$identity=[Security.Principal.WindowsIdentity]::new($token);try{$sid=$identity.User.Value;$enabled=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);$elevated=Info $token 20;$type=Info $token 18;if($sid -cne $b.originalSid -or $enabled -or $elevated -ne 0 -or $type -ne __CTX_TOKEN_TYPE__){throw 'ORDINARY_TOKEN_CHANGED'};$consoleToken=[Cp117OwnerToken]::Read(__CTX_CONSOLE_PID__,__CTX_CONSOLE_BIRTH__);if($consoleToken[3] -cne '__CTX_ADMIN_MEMBER__' -or $consoleToken[4] -cne 'False'){throw 'ORDINARY_TOKEN_MEMBERSHIP_CHANGED'}}finally{$identity.Dispose()}}finally{if($token -ne [IntPtr]::Zero){[ChainToken]::CloseHandle($token)|Out-Null};[ChainToken]::CloseHandle($ph)|Out-Null}
$owner=Get-Process -Id __CTX_OWNER_PID__ -ErrorAction Stop;$launcher=Get-Process -Id __CTX_OWNER_WRAPPER_PID__ -ErrorAction Stop;[Console]::Out.WriteLine((@{state='CURRENT_TYPED_GETPROCESS_BIRTHS';explorer__CTX_CONSOLE_PID__=$explorer.StartTime.ToFileTimeUtc();owner__CTX_OWNER_PID__=$owner.StartTime.ToFileTimeUtc();launcher__CTX_OWNER_WRAPPER_PID__=$launcher.StartTime.ToFileTimeUtc();source='GetProcess.StartTime.ToFileTimeUtc';effects=$false}|ConvertTo-Json -Compress));if($owner.StartTime.ToFileTimeUtc() -ne __CTX_OWNER_BIRTH__ -or $launcher.StartTime.ToFileTimeUtc() -ne __CTX_OWNER_WRAPPER_BIRTH__ -or __CTX_SESSION_OWNER__){throw 'ORIGINAL_OWNER_BIRTH'}
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;using System.Text;public static class ChainConsent{[StructLayout(LayoutKind.Sequential)]public struct FT{public uint lo,hi;}[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint size);[DllImport("kernel32.dll",SetLastError=true)]public static extern bool GetProcessTimes(IntPtr process,out FT creation,out FT exit,out FT kernel,out FT user);[DllImport("kernel32.dll",SetLastError=true)]public static extern bool ProcessIdToSessionId(uint pid,out uint session);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr handle);}'
function Read-CurrentConsentIdentity([uint32]$pidValue){$handle=[ChainConsent]::OpenProcess(0x1000,$false,$pidValue);if($handle -eq [IntPtr]::Zero){throw 'CONSENT_NATIVE_HANDLE'};try{$path=[Text.StringBuilder]::new(32768);[uint32]$size=32768;$c=[ChainConsent+FT]::new();$e=[ChainConsent+FT]::new();$k=[ChainConsent+FT]::new();$u=[ChainConsent+FT]::new();[uint32]$session=0;if(-not[ChainConsent]::QueryFullProcessImageName($handle,0,$path,[ref]$size)-or -not[ChainConsent]::GetProcessTimes($handle,[ref]$c,[ref]$e,[ref]$k,[ref]$u)-or -not[ChainConsent]::ProcessIdToSessionId($pidValue,[ref]$session)){throw 'CONSENT_NATIVE_METADATA'};$image=$path.ToString();$signature=Get-AuthenticodeSignature -LiteralPath $image -ErrorAction Stop;$signer=if($signature.SignerCertificate){$signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}else{$null};return @{pid=$pidValue;sessionId=$session;birth=([uint64]$c.hi*4294967296+[uint64]$c.lo).ToString();image=$image;imageSha256=(Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant();signatureStatus=[string]$signature.Status;signerName=$signer;signerThumbprint=if($signature.SignerCertificate){$signature.SignerCertificate.Thumbprint}else{$null}}}finally{[ChainConsent]::CloseHandle($handle)|Out-Null}}
function Read-CurrentInternalRequest($binding){$process=[ChainToken]::OpenProcess(0x1000,$false,__CTX_CONSOLE_PID__);$token=[IntPtr]::Zero;$identity=$null;$context=$null;if($process -eq [IntPtr]::Zero){throw 'INPUT_PRINCIPAL_HANDLE'};try{if(-not[ChainToken]::OpenProcessToken($process,10,[ref]$token)){throw 'INPUT_PRINCIPAL_TOKEN'};$identity=[Security.Principal.WindowsIdentity]::new($token);if($identity.User.Value -cne $binding.originalSid){throw 'INPUT_PRINCIPAL_SID'};$context=$identity.Impersonate();$path='__CTX_INPUT_PARENT__\'+$binding.jobId+'\request.json';$current=$path;while($current){if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INPUT_REPARSE'};$parent=Split-Path -Parent $current;if($parent -eq $current){break};$current=$parent};$bytes=[IO.File]::ReadAllBytes($path);if($bytes.Length -gt 65536){throw 'INPUT_SIZE'};$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};if($hash -cne $binding.internalRequestSha256){throw 'CURRENT_INPUT_BYTES_CHANGED'};$r=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json;$required=@('version','jobId','principalSid','ownerPid','ownerStartedAtEpochMillis','launcher','packageFile','packageSha256','packageSize','stateDirectory');$keys=@($r.PSObject.Properties.Name);$allowed=$required+@('frontendPid','frontendStartedAtEpochMillis');if(@($keys|Where-Object {$_ -notin $allowed}).Count -or @($required|Where-Object {$_ -notin $keys}).Count -or (($keys -contains 'frontendPid') -ne ($keys -contains 'frontendStartedAtEpochMillis'))){throw 'INPUT_SCHEMA'};foreach($key in @('version','ownerPid','ownerStartedAtEpochMillis','packageSize')){if(-not($r.$key -is [int] -or $r.$key -is [long])){throw 'INPUT_INTEGER_DOMAIN'}};foreach($key in @('jobId','principalSid','launcher','packageFile','packageSha256','stateDirectory')){if(-not($r.$key -is [string])){throw 'INPUT_TEXT_DOMAIN'}};if($keys -contains 'frontendPid'){foreach($key in @('frontendPid','frontendStartedAtEpochMillis')){if(-not($r.$key -is [int] -or $r.$key -is [long])){throw 'INPUT_FRONTEND_INTEGER_DOMAIN'}}};if($r.version -ne 1 -or $r.jobId -cne $binding.jobId -or $r.principalSid -cne $binding.originalSid -or $r.ownerPid -ne __CTX_OWNER_PID__ -or $r.ownerStartedAtEpochMillis -ne __CTX_OWNER_EPOCH__ -or $r.launcher -cne '__CTX_GUI_PATH__' -or $r.packageFile -cne ('__CTX_INPUT_PARENT__\'+$binding.jobId+'\package.msi') -or $r.packageSha256 -cne '__CTX_PACKAGE_SHA__' -or $r.packageSize -ne __CTX_PACKAGE_BYTES__ -or $r.stateDirectory -cne '__CTX_STATE_DIRECTORY__' -or ($keys -contains 'frontendPid' -and ($r.frontendPid -ne __CTX_FRONTEND_PID__ -or $r.frontendStartedAtEpochMillis -ne __CTX_FRONTEND_EPOCH__))){throw 'CURRENT_INTERNAL_REQUEST_BINDING'}}finally{if($context){$context.Undo();$context.Dispose()};if($identity){$identity.Dispose()};if($token -ne [IntPtr]::Zero){[ChainToken]::CloseHandle($token)|Out-Null};[ChainToken]::CloseHandle($process)|Out-Null}}
$all=@(Get-CimInstance Win32_Process -OperationTimeoutSec 5);if(@($all|Where-Object {$_.Name -ieq 'sing-box.exe'}).Count -ne 0){throw 'RUNTIME_ACTIVE'}
$helpers=@($all|Where-Object {$_.Name -ieq 'vpn-control-install-helper.exe'});$msi=@($all|Where-Object {$_.Name -ieq 'msiexec.exe'});if($helpers.Count -ne 0 -or $msi.Count -ne 0){throw 'PRE_GRANT_INSTALLER_ACTOR'}
$helper='__CTX_HELPER_PATH__';$hash=(Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash.ToLowerInvariant();if($hash -cne $b.helperSha256){throw 'HELPER_FULL_BYTES'}
$consents=@($all|Where-Object {$_.Name -ieq 'consent.exe' -and __CTX_SESSION_CONSENT_CIM__});if($consents.Count -ne 1){throw 'PRE_GRANT_UNIQUE_CONSOLE_CONSENT'}
$consentActor=Read-CurrentConsentIdentity ([uint32]$consents[0].ProcessId)
if(__CTX_SESSION_CONSENT_NATIVE__ -or -not[String]::Equals($consentActor.image,(Join-Path $env:SystemRoot 'System32\consent.exe'),[StringComparison]::OrdinalIgnoreCase) -or $consentActor.signatureStatus -cne 'Valid' -or $consentActor.signerName -cne 'Microsoft Windows' -or $consentActor.birth -notmatch '^[1-9][0-9]+$' -or $consentActor.imageSha256 -notmatch '^[0-9a-f]{64}$'){throw 'PRE_GRANT_AUTHENTIC_CONSENT'}
Read-CurrentInternalRequest $b
$actors=@()
$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 5).LastBootUpTime.ToUniversalTime().ToString('o');if($boot -cne '__CTX_BOOT_UTC__'){throw 'GUEST_BOOT_CHANGED'}
[Console]::Out.WriteLine((@{state='CURRENT_BOUND_GUEST_GREEN';jobId=$b.jobId;sid=$sid;elevated=$elevated;elevationType=$type;consolePid=__CTX_CONSOLE_PID__;__CTX_SESSION_OUTPUT__;helperActors=$actors;consentActor=$consentActor;ownerPid=__CTX_OWNER_PID__;ownerBirth=__CTX_OWNER_BIRTH__;boot=$boot;effects=$false}|ConvertTo-Json -Depth 6 -Compress))
"""


# Runtime wire/carrier source is selected from the authentic direct observer.
_GATEWAY_PROGRAM = r"""import os,sys,json,subprocess,tempfile,shlex,pwd,stat,hashlib,time,re,selectors
from pathlib import Path
def owned_home_identity(value):
    if not isinstance(value,str) or '%' in value or '..' in value.split('/') or any(ord(c)<32 for c in value):raise ValueError('effective_key_not_literal')
    if value.startswith('~/'):
        home=Path(pwd.getpwuid(os.getuid()).pw_dir)
        if not home.is_absolute():raise ValueError('effective_home_unknown')
        info=os.lstat(home)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('effective_home_foreign')
        return {'path':str(home/value[2:]),'home':str(home),'homePin':generation(info)}
    if value.startswith('~') or not Path(value).is_absolute():raise ValueError('effective_key_unknown')
    return {'path':value,'home':None,'homePin':None}

def generation(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]

def parent_guard(chain):
    for index,(fd,name,pin) in enumerate(chain):
        named=os.stat('/',follow_symlinks=False) if index==0 else os.stat(name,dir_fd=chain[index-1][0],follow_symlinks=False)
        if generation(os.fstat(fd))!=pin or generation(named)!=pin or not stat.S_ISDIR(named.st_mode):
            raise ValueError('route_parent_changed')

def file_pin(path, *, body=False, private=False):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('route_parent_unsafe')
    chain=[];leaf=-1
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        try:
            fd=os.open('/',flags);chain.append((fd,None,generation(os.fstat(fd))))
            for name in path.parent.parts[1:]:
                fd=os.open(name,flags,dir_fd=chain[-1][0]);chain.append((fd,name,generation(os.fstat(fd))))
        except OSError as exc:raise ValueError('route_parent_unsafe') from exc
        final=os.fstat(chain[-1][0])
        if final.st_uid!=os.getuid() or final.st_mode&0o022:raise ValueError('route_parent_unsafe')
        parent_guard(chain)
        before=os.stat(path.name,dir_fd=chain[-1][0],follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or before.st_mode&0o022 or private and stat.S_IMODE(before.st_mode)!=0o600:
            raise ValueError('route_file_unsafe')
        pin={'generation':generation(before),'parents':[{'name':name,'generation':meta} for _,name,meta in chain]}
        if body:
            leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1][0])
            if generation(os.fstat(leaf))!=pin['generation']:raise ValueError('route_file_changed')
            parent_guard(chain)
            chunks=[];total=0
            while True:
                chunk=os.read(leaf,65536)
                if not chunk:break
                chunks.append(chunk);total+=len(chunk)
                if total>1048576:raise ValueError('route_file_unbounded')
            raw=b''.join(chunks)
            if len(raw)!=before.st_size or generation(os.fstat(leaf))!=pin['generation']:raise ValueError('route_file_changed')
            pin.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                       unsupportedConfigDirectives=any(re.match(rb'\s*(include|match)\b',line,re.I) for line in raw.splitlines()))
        if generation(os.stat(path.name,dir_fd=chain[-1][0],follow_symlinks=False))!=pin['generation']:raise ValueError('route_file_changed')
        parent_guard(chain)
        return pin
    finally:
        if leaf>=0:os.close(leaf)
        for fd,_,_ in reversed(chain):os.close(fd)

def ssh_options(spec):
    return ['ssh','-T','-F',spec['configFile'],'-S',spec['controlPath'],'-o','ControlMaster=no','-o','ControlPersist=no',
            '-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no','-o','ProxyCommand=false']

def effective_route(spec):
    result=subprocess.run([*ssh_options(spec),'-G',spec['remoteHostAlias']],capture_output=True,timeout=5)
    if result.returncode!=0 or len(result.stdout)>65536 or result.stderr:raise ValueError('effective_route_unknown')
    values={}
    for line in result.stdout.decode('utf-8',errors='strict').splitlines():
        name,_,value=line.partition(' ')
        if name=='identityfile':values.setdefault(name,[]).append(value)
    keys=values.get('identityfile',[])
    if not keys:raise ValueError('effective_key_unknown')
    identities=[owned_home_identity(p) for p in keys]
    keys=[item['path'] for item in identities]
    homes={item['home']:item['homePin'] for item in identities if item['home'] is not None}
    existing={p:file_pin(p,private=True) for p in keys if os.path.lexists(p)}
    if not existing:raise ValueError('effective_key_unavailable')
    for home,pin in homes.items():
        if generation(os.lstat(home))!=pin:raise ValueError('effective_home_changed')
    return {'effectiveSha256':hashlib.sha256(result.stdout).hexdigest(),'keyMetadata':existing,'ownedHomePins':homes}


request_raw=bytearray()
while len(request_raw)<=4096:
 chunk=os.read(0,1)
 if not chunk:raise ValueError('staging-envelope-eof')
 if chunk==b'\n':break
 request_raw.extend(chunk)
else:raise ValueError('staging-envelope-bound')
request=json.loads(bytes(request_raw));assert set(request)=={'passphrase'} and isinstance(request['passphrase'],str) and 0<len(request['passphrase'])<=512
config,profile,programme,programme_sha=sys.argv[1:];programme_raw=programme.encode('utf-8')
if not 0<len(programme_raw)<=65536 or not re.fullmatch('[0-9a-f]{64}',programme_sha) or hashlib.sha256(programme_raw).hexdigest()!=programme_sha:raise ValueError('FIXED_KEY_PROGRAMME_BYTES')
config=config or str(Path.home()/'.ssh/config');spec={'configFile':config,'controlPath':'/tmp/vpn-readonly-diagnostic-unselected','remoteHostAlias':profile}
a=file_pin(config,body=True);assert not a['unsupportedConfigDirectives'];b=effective_route(spec)
def guard():
 assert file_pin(config,body=True)==a and effective_route(spec)==b
guard()
with tempfile.TemporaryDirectory(prefix='vpn-readonly-askpass-') as stage:
 os.chmod(stage,0o700);password=stage+'/password';helper=stage+'/askpass'
 fd=os.open(password,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:f.write(request['passphrase'])
 fd=os.open(helper,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
 with os.fdopen(fd,'w') as f:f.write('#!/bin/sh\ncat "$VPN_CONTROL_SSH_PASSWORD_FILE"\n')
 env=os.environ.copy();env.update(SSH_ASKPASS=helper,SSH_ASKPASS_REQUIRE='force',DISPLAY='vpn-readonly-diagnostic',VPN_CONTROL_SSH_PASSWORD_FILE=password)
 args=['ssh','-F',config,'-S','none','-o','ControlMaster=no','-o','ControlPersist=no','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','UpdateHostKeys=no','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','BatchMode=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=10','-T',profile,shlex.join(('python3','-I','-B','-c',programme))]
 guard();child=subprocess.Popen(args,stdin=0,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer,env=env)
 try:code=child.wait(timeout=300)
 except subprocess.TimeoutExpired:
  child.terminate()
  try:child.wait(timeout=5)
  except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
  raise
 guard();sys.exit(code)
"""


# The first frame precedes the application request. A current accepted request
# and this task's Limited-produced binding are joined later on the same child.
# A key ACK is transport evidence only; it is never an installer result.
import base64
try:
    import fcntl
except ImportError:
    fcntl = None
import gzip
import inspect
import json
import os
import select
import shlex
import stat
import subprocess
import tempfile
import threading
import time
import zlib
from dataclasses import asdict, fields
from pathlib import Path
from . import ssh_direct_nested_channel as channel
from . import ssh_transport as transport
from .native_review_source_closure import _Held, generation
from scripts.capture_visual_windows_qemu import convert_ppm_to_png, read_ppm
from scripts.windows_qga_powershell_size import (
    compressed_powershell_command, encoded_command_size)

_HOST = 'archlinux'
# Five mandatory frame rows plus thirteen protocol rows, each bounded above
# by the existing one-MiB collector line limit. Optional observations consume
# this same finite budget; exhaustion remains UNKNOWN without replay.
_MAX_STDOUT_BYTES = 18 * (1048576 + 1)
_STAGE = {'focus': ('tab', False, False), 'expand': ('spc', False, True),
          'approve': ('y', True, True)}
_SESSIONS = {}
_SESSIONS_LOCK = threading.Lock()


def _uuid(value):
    if type(value) is not str or str(uuid.UUID(value)) != value:
        raise ValueError('INPUT_UUID')
    return value


def _sha256(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('INPUT_SHA256')
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('INPUT_DUPLICATE_FIELD')
        result[name] = value
    return result


def _parse(raw):
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_unique)


def _context(raw, profile_name, profile):
    value = _parse(raw)
    if type(value) is not dict or set(value) != {f.name for f in fields(CurrentGuestContext)}:
        raise ValueError('INPUT_CONTEXT_SCHEMA')
    values = dict(value)
    for key in ('owner_wrapper', 'owner', 'frontend'):
        row = value[key]
        if type(row) is not dict or set(row) != {'pid', 'parent_pid', 'birth'}:
            raise ValueError('INPUT_CONTEXT_ROLE_SCHEMA')
        values[key] = GuardProcessFacts(**row)
    context = CurrentGuestContext(**values)
    _guard_slot_values(context)
    if (context.profile_name != profile_name or context.ordinary_sid != profile.expected_sid
            or context.session_id != profile.session_id
            or context.install_directory != str(profile.installed_root)
            or context.task_parent_directory != str(profile.task_root_parent)):
        raise ValueError('INPUT_CONFIGURED_CONTEXT')
    root = str(profile.profile_root).casefold() + '\\'
    if any(not str(PureWindowsPath(path)).casefold().startswith(root)
           for path in (context.input_parent_directory, context.state_directory)):
        raise ValueError('INPUT_CONTEXT_ROOT')
    return context


def validate_accepted_ack(ack, context):
    if type(ack) is not dict or set(ack) != {'requestId', 'operationId', 'controllerId', 'code', 'final'}:
        raise ValueError('INPUT_ACCEPTED_ACK_SCHEMA')
    for name in ('requestId', 'operationId', 'controllerId'):
        _uuid(ack[name])
    if ack['code'] != 'ACCEPTED' or ack['final'] is not False or ack['controllerId'] != context.owner_controller_id:
        raise ValueError('INPUT_ACCEPTED_ACK_BINDING')
    return dict(ack)


def validate_current_binding(binding, request, ack, context):
    # The ACK alone is not authority: this current guest task's request/binding
    # must agree with it, and the native guard runs again before every key batch.
    validate_accepted_ack(ack, context)
    names = {'controllerId', 'helperSha256', 'inputBound', 'internalRequestSha256',
             'jobId', 'limited', 'operationId', 'originalSid', 'ownerPid', 'requestId', 'sessionId'}
    if type(binding) is not dict or not names.issubset(binding) or type(request) is not dict:
        raise ValueError('INPUT_BINDING_SCHEMA')
    for name in ('jobId', 'requestId', 'operationId', 'controllerId'):
        _uuid(binding[name])
    _sha256(binding['internalRequestSha256'])
    for name in ('requestId', 'operationId', 'controllerId', 'code', 'final'):
        if request.get(name) != ack[name] or type(request.get(name)) is not type(ack[name]):
            raise ValueError('INPUT_CURRENT_REQUEST')
    if any(binding[name] != ack[name] for name in ('requestId', 'operationId', 'controllerId')):
        raise ValueError('INPUT_CURRENT_BINDING')
    if (type(binding['ownerPid']) is not int or binding['ownerPid'] != context.owner.pid
            or type(binding['sessionId']) is not int or binding['sessionId'] != context.session_id
            or binding['originalSid'] != context.ordinary_sid or binding['helperSha256'] != context.helper_sha256
            or binding['limited'] is not True or binding['inputBound'] is not True):
        raise ValueError('INPUT_PRINCIPAL_HELPER')
    return {name: binding[name] for name in sorted(names)}


def decision_events(decision, stage, binding_sha, frame_sha):
    if stage not in _STAGE:
        raise ValueError('INPUT_STAGE')
    key, expanded, focused = _STAGE[stage]
    names = {'action', 'frameSha256', 'bindingSha256', 'promptVerified',
             'expandedDetailsVerified', 'detailsFocusVerified'}
    if (type(decision) is not dict or set(decision) != names or decision['action'] != stage
            or decision['bindingSha256'] != _sha256(binding_sha)
            or decision['frameSha256'] != _sha256(frame_sha)
            or decision['promptVerified'] is not True
            or decision['expandedDetailsVerified'] is not expanded
            or decision['detailsFocusVerified'] is not focused):
        raise ValueError('INPUT_FRESH_VISUAL_DECISION')
    sequence = [('alt', True), ('y', True), ('y', False), ('alt', False)] if stage == 'approve' else [(key, True), (key, False)]
    return [{'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': name}}}
            for name, down in sequence]


def guard_command(context, binding, token_policy):
    source = render_unbound_current_guest_guard(context, token_policy)
    literal = _json(binding).decode('ascii')
    if "'" in literal or source.count('__CURRENT_BINDING__') != 1:
        raise ValueError('INPUT_GUARD_BINDING')
    source = source.replace('__CURRENT_BINDING__', literal)
    if not 0 < len(source.encode('utf-8')) <= 65536:
        raise ValueError('INPUT_GUARD_BODY_BOUND')
    wrapper = compressed_powershell_command(source)
    encoded = base64.b64encode(wrapper.encode('utf-16le')).decode('ascii')
    if len('powershell.exe -NoProfile -NonInteractive -EncodedCommand ') + len(encoded) > 30000:
        raise ValueError('INPUT_GUARD_COMMAND_BOUND')
    return source, encoded


def _bounded_frame(row):
    if type(row) is not dict or row.get('state') != 'FRESH_CHAIN_FRAME':
        raise ValueError('INPUT_FRAME_SCHEMA')
    digest = _sha256(row.get('sha256'))
    packed = row.get('frameGzip')
    if type(packed) is not str or not 0 < len(packed) <= 933336:
        raise ValueError('INPUT_FRAME_PACKED_BOUND')
    compressed = base64.b64decode(packed, validate=True)
    if len(compressed) > 700000:
        raise ValueError('INPUT_FRAME_PACKED_BOUND')
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(compressed, 16777216)
    if len(raw) >= 16777216 or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
        raise ValueError('INPUT_FRAME_BODY_BOUND')
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('INPUT_FRAME_SHA256')
    return raw


def _render_frame(raw, ppm, png):
    # Use the existing stdlib converter; no runtime Pillow dependency.
    _write(ppm, raw)
    width, height, pixels = read_ppm(ppm)
    if not 0 < width <= 4096 or not 0 < height <= 4096 or len(pixels) >= 16777216:
        raise ValueError('INPUT_FRAME_DIMENSIONS')
    convert_ppm_to_png(ppm, png)
    return {'width': width, 'height': height, 'pngSha256': hashlib.sha256(png.read_bytes()).hexdigest()}


def _renderer_preflight():
    with tempfile.TemporaryDirectory(prefix='vpn-input-renderer-') as directory:
        _render_frame(b'P6\n2 1\n255\n\x00\x01\x02\x03\x04\x05', Path(directory)/'frame.ppm', Path(directory)/'frame.png')


def _source_epoch(root):
    from . import mcp_server
    if Path(mcp_server.REPO_ROOT).resolve() != root:
        raise ValueError('INPUT_REPOSITORY_ROOT')
    result = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        raise ValueError('INPUT_SOURCE_EPOCH')
    return result.stdout.strip(), mcp_server._snapshot_fingerprint()


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('INPUT_CAPTURE_WRITE')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _append(fd, raw):
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError('INPUT_CAPTURE_WRITE')
        view = view[written:]


def _directory(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError('INPUT_DIRECTORY')
    return path


def _unknown(**extra):
    return {'ok': False, 'state': 'UNKNOWN', 'replayAllowed': False,
            'nativeInputAdmitted': False, 'installerResultProved': False, **extra}


def _input_schema(action, inputs):
    shared = {'host', 'profile', 'correlationId'}
    allowed = {
        'windows-input-start': shared,
        'windows-input-observe': shared | {'inputId'},
        'windows-input-finish': shared | {'inputId'},
        'windows-input-join': shared | {'inputId', 'acceptedAck'},
        'windows-input-decision': shared | {'inputId', 'decision'},
    }
    if action not in allowed or type(inputs) is not dict or set(inputs) != allowed[action]:
        raise ValueError('INPUT_REQUEST_SCHEMA')
    if inputs['host'] != _HOST or type(inputs['profile']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', inputs['profile']):
        raise ValueError('INPUT_PROFILE_SELECTOR')
    _uuid(inputs['correlationId'])
    if action != 'windows-input-start':
        _uuid(inputs['inputId'])
    if action == 'windows-input-decision':
        value = inputs['decision']
        if (type(value) is not dict or set(value) != {'action','frameSha256','bindingSha256','promptVerified',
                'expandedDetailsVerified','detailsFocusVerified'} or value['action'] not in _STAGE
                or any(type(value[key]) is not bool for key in ('promptVerified','expandedDetailsVerified','detailsFocusVerified'))):
            raise ValueError('INPUT_DECISION_SCHEMA')
        _sha256(value['frameSha256']);_sha256(value['bindingSha256'])
    return dict(inputs)


def build_remote_program(profile, context, correlation, context_sha):
    # PROFILE/CONTEXT come from the held configured record, never MCP inputs.
    guard = render_unbound_current_guest_guard(context, profile.token_policy)
    profile_values = asdict(profile)
    for name, value in tuple(profile_values.items()):
        if isinstance(value, (Path, PureWindowsPath)) or hasattr(value, 'as_posix'):
            profile_values[name] = str(value)
    constants = {'PROFILE': profile_values, 'CONTEXT': asdict(context),
                 'PARAMETERS': {'correlationId': _uuid(correlation), 'taskRoot': configured_task_root(context, correlation)},
                 'CONTEXT_SHA256': _sha256(context_sha), 'GUARD_SOURCE': guard,
                 'GUARD_SHA256': hashlib.sha256(guard.encode()).hexdigest(),
                 'GUARD_TEMPLATE_SHA256': CURRENT_GUEST_GUARD_TEMPLATE_SHA256}
    helper = inspect.getsource(encoded_command_size) + '\n' + inspect.getsource(compressed_powershell_command)
    source = ('import base64,gzip,hashlib,json,os,re,secrets,socket,stat,sys,tempfile,time,select,zlib\n'
              'MAX_SCRIPT_BYTES=131000\nMAX_ENCODED_COMMAND_CHARS=30000\n'
              + ''.join(name+'='+repr(value)+'\n' for name, value in constants.items())
              + helper + '\n' + _REMOTE_RUNTIME)
    if not 0 < len(source.encode('utf-8')) <= 65536:
        raise ValueError('INPUT_REMOTE_PROGRAM_BOUND')
    compile(source, '<windows-guest-input>', 'exec')
    return source


def _launch(guard, program):
    target = guard.config.hosts[_HOST]
    outer = transport.connection_host(guard.config, _HOST)
    if target.transport != 'nested' or not target.password or not target.remote_host_alias:
        raise ValueError('INPUT_CONFIGURED_DIRECT_ROUTE')
    prefix, endpoint = channel.outer_prefix(guard.config, outer)
    digest = hashlib.sha256(program.encode()).hexdigest()
    argv = [*prefix, endpoint, shlex.join(('python3', '-I', '-B', '-c', _GATEWAY_PROGRAM,
            str(target.remote_config_file or ''), target.remote_host_alias, program, digest))]
    envelope = _json({'passphrase': target.password}) + b'\n'
    if len(envelope) > 4096 or max(map(len, argv)) > 120000:
        raise ValueError('INPUT_TRANSPORT_ARGUMENT_BOUND')
    return argv, envelope


def _pin_sources(guard, context, root):
    # Reuse the configured route's held sources and add this producer/template,
    # converter and bounded emitter to the same retained set.
    for path in (Path(__file__), Path(inspect.getfile(convert_ppm_to_png)),
                 Path(inspect.getfile(compressed_powershell_command))):
        guard.held.read(str(path.resolve()), hashlib.sha256(path.read_bytes()).hexdigest())
    if _source_epoch(root) != (context.caller_source_sha, context.caller_content_fingerprint):
        raise ValueError('INPUT_CURRENT_SOURCE')
    guard.guard()


class _Observer:
    def __init__(self, root, inputs, profile, context, context_sha, guard, directory, lock_fd, intent_sha):
        self.root, self.inputs, self.profile, self.context = root, inputs, profile, context
        self.context_sha, self.guard, self.directory = context_sha, guard, directory
        self.lock_fd, self.intent_sha = lock_fd, intent_sha
        self.input_id = directory.name
        self.process = None
        self.condition = threading.Condition(threading.RLock())
        self.events = []
        self.version = 0
        self.frame = None
        self.binding = None
        self.stage = 'focus'
        self.uncertain = None
        self.closed = False
        self.thread = None
        self.attached = threading.Event()
        self.raw_fds = []

    def source_guard(self):
        # The held set shares FD offsets; serialize verification and closure.
        with self.condition:
            raw = self.guard.held.read(str(self.directory/'intent.json'), self.intent_sha, max_bytes=8192)
            if _parse(raw)['inputId'] != self.input_id:
                raise ValueError('INPUT_INTENT_BINDING')
            _pin_sources(self.guard, self.context, self.root)

    def _event(self, row):
        with self.condition:
            self.version += 1
            self.events.append((self.version, row))
            self.events = self.events[-64:]
            self.condition.notify_all()

    def _accept(self, row):
        self.source_guard()
        if (type(row) is not dict or row.get('contextSha256') != self.context_sha
                or row.get('guardTemplateSha256') != CURRENT_GUEST_GUARD_TEMPLATE_SHA256
                or row.get('correlationId') != self.inputs['correlationId']):
            raise ValueError('INPUT_REMOTE_CONTEXT')
        state = row.get('state')
        public = {name: value for name, value in row.items() if name not in {'frameGzip', 'remoteCapture', 'result'}}
        if state == 'FRESH_CHAIN_FRAME':
            raw = _bounded_frame(row)
            index = self.version
            ppm, png = self.directory/('frame-'+str(index)+'.ppm'), self.directory/('frame-'+str(index)+'.png')
            dimensions = _render_frame(raw, ppm, png)
            binding = row.get('binding')
            digest = row.get('bindingSha256')
            if binding is None:
                if digest is not None:
                    raise ValueError('INPUT_UNBOUND_FRAME_DIGEST')
            else:
                if self.binding is None or binding != self.binding or digest != hashlib.sha256(_json(binding)).hexdigest():
                    raise ValueError('INPUT_FRAME_CURRENT_BINDING')
            public.update(state='INPUT_FRAME_READY', frame=str(png), **dimensions)
            self.frame = public
        elif state == 'INPUT_JOB_JOINED':
            binding = row.get('binding')
            # The remote source checks this task's actual request too. Local ACK
            # storage prevents a different reply from replacing this original join.
            self.binding = validate_current_binding(binding, self.ack, self.ack, self.context)
            if row.get('bindingSha256') != hashlib.sha256(_json(self.binding)).hexdigest():
                raise ValueError('INPUT_JOIN_DIGEST')
        elif state == 'ORIGINAL_KEY_CHAIN_ACK':
            if self.binding is None or row.get('jobId') != self.binding['jobId'] or row.get('stage') != self.stage:
                raise ValueError('INPUT_ACK_BINDING')
            public.update(state='INPUT_KEY_ACK_ONLY', inputAcknowledged=True, uiSuccess=False)
            if self.stage != 'approve':
                self.stage = 'expand' if self.stage == 'focus' else 'approve'
        elif state not in {'SAME_GUEST_GUARD_ACCEPTED', 'SAME_GUEST_GUARD_TERMINAL',
                           'SAME_GUEST_GUARD_UNKNOWN', 'SAME_GUEST_GUARD_TERMINAL_REFUSED',
                           'SAME_FIXTURE_MARKER_ACCEPTED', 'SAME_FIXTURE_MARKER_TERMINAL',
                           'SAME_FIXTURE_MARKER_UNKNOWN', 'ORIGINAL_KEY_CHAIN_CLOSED'}:
            raise ValueError('INPUT_REMOTE_STATE')
        self._event(public)

    def _collect(self):
        total = {'stdout': 0, 'stderr': 0}
        pending = bytearray()
        try:
            streams = {self.process.stdout: 'stdout', self.process.stderr: 'stderr'}
            while streams:
                ready, _, _ = select.select(list(streams), [], [], .2)
                for stream in ready:
                    chunk = os.read(stream.fileno(), 65536)
                    name = streams[stream]
                    if not chunk:
                        del streams[stream]
                        if name == 'stdout' and pending:
                            raise ValueError('INPUT_COLLECTOR_PARTIAL_LINE')
                        continue
                    total[name] += len(chunk)
                    if total[name] > (_MAX_STDOUT_BYTES if name == 'stdout' else 2097152):
                        raise ValueError('INPUT_CAPTURE_BOUND')
                    fd = self.raw_fds[0 if name == 'stdout' else 1]
                    _append(fd, chunk)
                    if name == 'stdout':
                        pending.extend(chunk)
                        while b'\n' in pending:
                            raw, _, rest = pending.partition(b'\n'); pending = bytearray(rest)
                            if len(raw) > 1048576:
                                raise ValueError('INPUT_LINE_BOUND')
                            self._accept(_parse(raw))
                        if len(pending) > 1048576:
                            raise ValueError('INPUT_LINE_BOUND')
            self.process.wait()
            if self.process.returncode != 0 or not any(row.get('state') == 'ORIGINAL_KEY_CHAIN_CLOSED' for _, row in self.events):
                raise ValueError('INPUT_ORIGINAL_TRANSPORT_REFUSED')
            self.source_guard()
        except BaseException as error:
            with self.condition:
                self.uncertain = type(error).__name__ + ':' + (str(error) if isinstance(error, ValueError) else 'collector')
                self.condition.notify_all()
            # Never close live original custody or replay after interrupted collection.
            live_streams = [stream for stream in (self.process.stdout, self.process.stderr) if not stream.closed]
            while self.process.poll() is None:
                ready, _, _ = select.select(live_streams, [], [], .1) if live_streams else ([], [], [])
                for stream in ready:
                    if not os.read(stream.fileno(), 65536):
                        live_streams.remove(stream)
                if not live_streams:
                    time.sleep(.1)
        finally:
            if self.process.poll() is not None:
                self._close_terminal()

    def _close_terminal(self):
        # The held set shares FD offsets; serialize verification and closure.
        with self.condition:
            errors = []
            callbacks = [('stdin', self.process.stdin.close), ('stdout', self.process.stdout.close),
                         ('stderr', self.process.stderr.close)]
            for fd in self.raw_fds:
                callbacks.extend([('capture_flush', lambda fd=fd: os.fsync(fd)),
                                  ('capture_close', lambda fd=fd: os.close(fd))])
            callbacks.extend([('guard', self.guard.close), ('lock', lambda: os.close(self.lock_fd))])
            for name, callback in callbacks:
                try:
                    callback()
                except BaseException as error:
                    errors.append((name, type(error).__name__))
            if errors:
                self.uncertain = self.uncertain or 'INPUT_CLEANUP_REFUSED'
            if self.uncertain is None:
                try:
                    _write(self.directory/'terminal.json', _json({'inputId': self.input_id, 'returncode': self.process.returncode,
                           'originalTerminal': True, 'sourceClosing': True, 'replayAllowed': False}))
                except BaseException:
                    self.uncertain = 'INPUT_TERMINAL_CAPTURE_REFUSED'
            with self.condition:
                self.closed = not errors
                self.condition.notify_all()

    def _collect_attached(self):
        self.attached.wait()
        if self.process is not None:
            self._collect()

    def launch(self, argv, envelope):
        self.source_guard()
        for name in ('stdout.private', 'stderr.private'):
            self.raw_fds.append(os.open(self.directory/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600))
        # Allocate the collector before the first transport effect. A thread
        # resource refusal cannot leave an accepted original without its reader.
        self.thread = threading.Thread(target=self._collect_attached, name='windows-input-'+self.input_id, daemon=True)
        self.thread.start()
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        finally:
            self.attached.set()
        if self.process is None:
            self.thread.join(timeout=5)
        try:
            self.process.stdin.write(envelope); self.process.stdin.flush()
        except BaseException as error:
            self.uncertain = type(error).__name__+':envelope'
            raise

    def snapshot(self, row=None):
        with self.condition:
            extra = {'inputId': self.input_id, 'correlationId': self.inputs['correlationId'],
                     'profile': self.inputs['profile'], 'originalPid': self.process.pid,
                     'originalTerminal': self.process.poll() is not None, 'holdersClosed': self.closed}
            if self.uncertain:
                return _unknown(error=self.uncertain, **extra)
            if row is None:
                row = self.frame
            if row is None:
                return _unknown(**extra)
            return {'ok': True, 'replayAllowed': False, 'nativeInputAdmitted': False,
                    'installerResultProved': False, **row, **extra}

    def wait(self, expected, baseline=0, timeout=30):
        end = time.monotonic()+timeout
        with self.condition:
            while True:
                for serial, row in self.events:
                    if serial > baseline and row.get('state') in ((expected,) if isinstance(expected, str) else expected):
                        return self.snapshot(row)
                if self.uncertain or self.closed:
                    if self.closed and self.uncertain is None:
                        self.uncertain = 'INPUT_EXPECTED_RESPONSE_LOST'
                    return self.snapshot()
                remaining = end-time.monotonic()
                if remaining <= 0:
                    self.uncertain = 'INPUT_RESPONSE_UNKNOWN'
                    return self.snapshot()
                self.condition.wait(remaining)

    def send(self, action, value=None):
        with self.condition:
            if self.closed or self.process.poll() is not None:
                return self.snapshot({'state': 'INPUT_CLOSED'}) if self.closed and self.uncertain is None else self.snapshot()
            if self.uncertain and action not in {'observe', 'finish'}:
                return self.snapshot()
            try:
                self.source_guard()
                command = {'action': action}
                expected = 'INPUT_FRAME_READY'
                if action == 'join':
                    if self.binding is not None or hasattr(self, 'ack'):
                        raise ValueError('INPUT_ALREADY_JOINED')
                    self.ack = validate_accepted_ack(value, self.context)
                    command['acceptedAck'] = self.ack
                    expected = ('INPUT_JOB_JOINED', 'INPUT_FRAME_READY')
                elif action in _STAGE:
                    if self.binding is None or self.frame is None or self.frame.get('bindingSha256') != hashlib.sha256(_json(self.binding)).hexdigest():
                        raise ValueError('INPUT_UNBOUND_DECISION')
                    decision_events(value, self.stage, hashlib.sha256(_json(self.binding)).hexdigest(), self.frame['sha256'])
                    command = value
                    expected = 'INPUT_KEY_ACK_ONLY'
                elif action == 'finish':
                    expected = 'ORIGINAL_KEY_CHAIN_CLOSED'
                elif action != 'observe':
                    raise ValueError('INPUT_ACTION')
                raw = _json(command)+b'\n'
                if len(raw) > 8192:
                    raise ValueError('INPUT_COMMAND_BOUND')
                baseline = self.version
                self.process.stdin.write(raw); self.process.stdin.flush()
            except BaseException as error:
                self.uncertain = type(error).__name__+':input'
                return self.snapshot()
        result = self.wait(expected, baseline)
        if action == 'finish' and result.get('ok'):
            with self.condition:
                self.condition.wait_for(lambda: self.closed, timeout=30)
            if not self.closed:
                self.uncertain = 'INPUT_TERMINAL_COLLECTION_UNKNOWN'
                return self.snapshot()
            return self.snapshot({'state': 'INPUT_CLOSED'})
        return result


def _start(root, inputs):
    _renderer_preflight()  # dependency/render failures precede Guard, intent and SSH
    guard = channel.Guard(root)
    lock_fd = None
    observer = None
    try:
        target = guard.config.hosts[_HOST]
        profile = target.windows_input_profiles.get(inputs['profile'])
        if profile is None:
            raise ValueError('INPUT_CONFIGURED_PROFILE_MISSING')
        raw = guard.held.read(str(profile.native_context_path), profile.native_context_sha256, max_bytes=32768)
        context = _context(raw, inputs['profile'], profile)
        _pin_sources(guard, context, root)
        program = build_remote_program(profile, context, inputs['correlationId'], profile.native_context_sha256)
        argv, envelope = _launch(guard, program)
        parent = _directory(root/'.rag_index')
        parent = _directory(parent/'windows-guest-input')
        slot = hashlib.sha256(str(profile.qga_socket_path).encode()).hexdigest()
        lock_fd = os.open(parent/(slot+'.lock'), os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Persisted unknown intents keep the environment closed after server loss.
        for item in parent.iterdir():
            if not re.fullmatch('[0-9a-f-]{36}', item.name):
                continue
            intent = _parse((item/'intent.json').read_bytes())
            if intent.get('slot') == slot and not (item/'terminal.json').exists():
                raise ValueError('INPUT_ORIGINAL_INTENT_UNKNOWN')
            if intent.get('correlationId') == inputs['correlationId']:
                raise ValueError('INPUT_ORIGINAL_INTENT_REPLAY')
        input_id = str(uuid.uuid4())
        directory = parent/input_id; directory.mkdir(mode=0o700)
        record = {'inputId': input_id, **inputs, 'slot': slot, 'contextSha256': profile.native_context_sha256,
                  'remoteSha256': hashlib.sha256(program.encode()).hexdigest(), 'replayAllowed': False}
        raw = _json(record)
        _write(directory/'intent.json', raw)
        _write(directory/'remote.source.py', program.encode())
        _write(directory/'gateway.source.py', _GATEWAY_PROGRAM.encode())
        observer = _Observer(root, inputs, profile, context, profile.native_context_sha256, guard, directory, lock_fd,
                             hashlib.sha256(raw).hexdigest())
        observer.source_guard()
        with _SESSIONS_LOCK:
            _SESSIONS[(str(root), input_id)] = observer
        observer.launch(argv, envelope)
        return observer.wait('INPUT_FRAME_READY')
    except BaseException as error:
        if observer is not None and observer.process is not None:
            observer.uncertain = observer.uncertain or type(error).__name__+':start'
            return observer.snapshot()
        if observer is None or observer.process is None:
            if observer is not None:
                with _SESSIONS_LOCK:
                    if _SESSIONS.get((str(root), observer.input_id)) is observer:
                        del _SESSIONS[(str(root), observer.input_id)]
                observer.attached.set()
                if observer.thread is not None and observer.thread.ident is not None:
                    observer.thread.join(timeout=5)
                for fd in observer.raw_fds:
                    os.close(fd)
            if lock_fd is not None:
                os.close(lock_fd)
            guard.close()
        # A started original belongs to its collector even if response delivery
        # is interrupted. Caller receives UNKNOWN and can observe only that id.
        raise


def dispatch(root, action, inputs):
    inputs = _input_schema(action, inputs)
    root = Path(root).resolve(strict=True)
    if action == 'windows-input-start':
        if not channel.coordinator_capable():
            return _unknown(errorClass='UnsupportedCoordinator', correlationId=inputs['correlationId'])
        # A duplicate call returns the original in-memory state, never Popen.
        with _SESSIONS_LOCK:
            for (owner_root, _), observer in _SESSIONS.items():
                if owner_root == str(root) and observer.inputs == inputs:
                    return observer.snapshot()
        try:
            return _start(root, inputs)
        except BaseException as error:
            return _unknown(errorClass=type(error).__name__, correlationId=inputs['correlationId'])
    with _SESSIONS_LOCK:
        observer = _SESSIONS.get((str(root), inputs['inputId']))
    if observer is None or any(inputs[name] != observer.inputs[name] for name in ('host', 'profile', 'correlationId')):
        return _unknown(inputId=inputs['inputId'], correlationId=inputs['correlationId'])
    action = action.removeprefix('windows-input-')
    if action == 'decision':
        value = inputs['decision']
        if type(value) is not dict:
            raise ValueError('INPUT_DECISION_SCHEMA')
        return observer.send(value.get('action'), value)
    return observer.send(action, inputs.get('acceptedAck'))

_REMOTE_RUNTIME = r"""# Fixed source-only remote fragment; producer supplies audited source/prefix globals.
# PROFILE/PARAMETERS/CONTEXT/GUARD_SOURCE and source digests are not stdin selectors.
import base64,hashlib,json,os,re,secrets,socket,stat,sys,tempfile,gzip,time,select,struct
from pathlib import PureWindowsPath
QEMU_PID=str(PROFILE['qemu_pid']);QEMU_TICKS=str(PROFILE['qemu_start_ticks'])
QGA_SOCKET=PROFILE['qga_socket_path'];QMP_SOCKET=PROFILE['qmp_socket_path'];LEAF=os.path.dirname(QGA_SOCKET)
TASK_PARENT=PROFILE['task_root_parent']
STAGES={'focus':('tab',False,False),'expand':('spc',False,True),'approve':('y',True,True)}
UUID_RE=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
def live(sock,pid,ticks):
 if not stat.S_ISSOCK(os.lstat(sock).st_mode):return False
 raw=open('/proc/%s/stat'%pid,'rb').read().split()
 if len(raw)<22 or raw[21].decode()!=ticks:return False
 inodes=set()
 for name in os.listdir('/proc/%s/fd'%pid):
  try:
   link=os.readlink('/proc/%s/fd/%s'%(pid,name))
   if link.startswith('socket:[') and link.endswith(']'):inodes.add(link[8:-1].encode())
  except OSError:pass
 return any(len(f)==8 and f[6] in inodes and f[7]==os.fsencode(sock) for f in (line.split() for line in open('/proc/net/unix','rb')))

def verify_peer(client,sock):
 peer=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
 if peer[:2]!=(int(QEMU_PID),PROFILE['qemu_uid']):raise ValueError('QEMU_CONNECTED_PEER')
 identity()

def call(sock,command,args,_deadline=None):
 received=bytearray();primary=None
 deadline=min(time.monotonic()+20,_deadline) if _deadline is not None else time.monotonic()+20
 c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 def budget():
  remaining=deadline-time.monotonic()
  if remaining<=0:raise TimeoutError('collection-deadline')
  c.settimeout(min(20,remaining))
 def receive():
  budget();return c.recv(1)
 def send(data):
  budget();c.sendall(data)
 try:
  budget();c.connect(sock);verify_peer(c,sock);sid=secrets.randbits(63)
  send(b'\xff'+json.dumps({'execute':'guest-sync-delimited','arguments':{'id':sid}},separators=(',',':')).encode()+b'\n')
  for i in range(8192):
   x=receive();received.extend(x)
   if x==b'\xff':break
  else:raise ValueError()
  def line():
   raw=bytearray()
   for i in range(262144):
    x=receive();received.extend(x)
    if x==b'\n':
     os.write(wire,bytes(raw)+b'\n');os.fsync(wire);return json.loads(raw)
    if not x:raise ValueError()
    raw.extend(x)
   raise ValueError()
  if line().get('return')!=sid:raise ValueError()
  send(json.dumps({'execute':command,'arguments':args},separators=(',',':')).encode()+b'\n')
  result=line()
  if 'return' not in result:raise ValueError()
  return result['return']
 except BaseException as error:
  primary=error;raise
 finally:
  try:
   os.write(partial_wire,bytes(received));os.fsync(partial_wire)
  except OSError as error:
   if primary is None:raise
   primary.readonlyQgaCaptureFailure={'stage':'raw_capture','errorClass':type(error).__name__,'errno':error.errno}
  finally:c.close()

def read(sock,path,maxsize=8192,deadline=None):
 handle=call(sock,'guest-file-open',{'path':path,'mode':'rb'},_deadline=deadline)
 if type(handle)is not int or handle<=0:raise ValueError('GUEST_FILE_OPEN_UNKNOWN')
 raw=bytearray()
 try:
  while len(raw)<maxsize:
   v=call(sock,'guest-file-read',{'handle':handle,'count':min(4096,maxsize-len(raw))},_deadline=deadline)
   part=base64.b64decode(v['buf-b64'],validate=True)
   if v.get('count')!=len(part):raise ValueError()
   raw.extend(part)
   if v.get('eof') is True or not part:return bytes(raw)
  raise ValueError()
 finally:call(sock,'guest-file-close',{'handle':handle},_deadline=time.monotonic()+20)

def decode(raw):
 if raw.startswith(b'\xff\xfe'):return raw.decode('utf-16')
 if raw.startswith(b'\xef\xbb\xbf'):return raw.decode('utf-8-sig')
 return raw.decode('utf-8')

def decision_guard(command,stage,binding_digest,fresh_digest):
 key,expanded,focused=STAGES[stage]
 if set(command)!={'action','frameSha256','bindingSha256','promptVerified','expandedDetailsVerified','detailsFocusVerified'} or command['action']!=stage or command['bindingSha256']!=binding_digest or command['frameSha256']!=fresh_digest or command['promptVerified']is not True or command['expandedDetailsVerified']is not expanded or command['detailsFocusVerified']is not focused:raise ValueError('FRESH_VISUAL_DECISION_REFUSED')
 return key

def guarded_events(command,stage,binding_digest,fresh_digest):
 key=decision_guard(command,stage,binding_digest,fresh_digest)
 return [{'type':'key','data':{'down':down,'key':{'type':'qcode','data':k}}} for k,down in ([('alt',True),('y',True),('y',False),('alt',False)] if stage=='approve' else [(key,True),(key,False)])]

def send_guarded(command,stage,binding_digest,fresh_digest,send):
 return send('input-send-event',{'events':guarded_events(command,stage,binding_digest,fresh_digest)})

def save(path,body):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:os.write(fd,body);os.fsync(fd)
 finally:os.close(fd)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def valid_uuid(value):return type(value)is str and UUID_RE.fullmatch(value)is not None

def emit(row):
 row={**row,'contextSha256':CONTEXT_SHA256,'guardTemplateSha256':GUARD_TEMPLATE_SHA256,'guardSourceSha256':GUARD_SHA256,'correlationId':PARAMETERS['correlationId']}
 print(json.dumps(row),flush=True)

def validate_globals():
 profile_keys={'environment','qga_socket_path','qmp_socket_path','qemu_pid','qemu_start_ticks','qemu_parent_pid','qemu_uid','qemu_argv_sha256','host_boot_id','account_name','expected_sid','session_id','profile_root','installed_root','task_root_parent','native_context_path','native_context_sha256','token_policy'}
 if type(PROFILE)is not dict or set(PROFILE)!=profile_keys or type(CONTEXT)is not dict:raise ValueError('FIXED_RUNTIME_GLOBAL_SCHEMA')
 for key in ('qemu_pid','qemu_start_ticks','qemu_parent_pid','session_id'):
  if type(PROFILE[key])is not int or PROFILE[key]<=0:raise ValueError('PROFILE_INTEGER')
 if type(PROFILE['qemu_uid'])is not int or PROFILE['qemu_uid']<0:raise ValueError('PROFILE_UID')
 if not valid_uuid(PROFILE['host_boot_id']) or QGA_SOCKET==QMP_SOCKET or any(type(PROFILE[k])is not str or not os.path.isabs(PROFILE[k])for k in ('qga_socket_path','qmp_socket_path')):raise ValueError('PROFILE_SOCKETS_BOOT')
 for value in (PROFILE['qemu_argv_sha256'],PROFILE['native_context_sha256'],CONTEXT_SHA256,GUARD_SHA256,GUARD_TEMPLATE_SHA256):
  if type(value)is not str or re.fullmatch('[0-9a-f]{64}',value)is None:raise ValueError('SOURCE_DIGEST')
 policy=PROFILE['token_policy']
 if type(policy)is not dict or set(policy)!={'kind','elevation','elevation_type','admin_member','admin_enabled'}:raise ValueError('PROFILE_TOKEN_POLICY')
 if type(policy['kind'])is not str or type(policy['elevation'])is not int or type(policy['elevation_type'])is not int or type(policy['admin_member'])is not bool or type(policy['admin_enabled'])is not bool or (policy['kind'],policy['elevation'],policy['elevation_type'],policy['admin_member'],policy['admin_enabled'])not in (('ordinaryFilteredAdmin',0,3,True,False),('ordinaryStandardUser',0,1,False,False)):raise ValueError('PROFILE_TOKEN_POLICY')
 if CONTEXT_SHA256!=PROFILE['native_context_sha256']:raise ValueError('CONFIGURED_CONTEXT_SOURCE')
 # CONTEXT is the source-pinned decoded expected facts; raw context file digest is
 # supplied separately. No canonical-JSON rehash is represented as native proof.
 required={'profile_name','ordinary_sid','session_id','boot_utc','console_pid','console_birth','owner_wrapper','owner','frontend','install_directory','input_parent_directory','state_directory','task_parent_directory','owner_controller_id','package_sha256','package_bytes','helper_sha256','caller_source_sha','caller_content_fingerprint','package_source_sha'}
 if set(CONTEXT)!=required:raise ValueError('CONTEXT_SCHEMA')
 for name in ('owner_wrapper','owner','frontend'):
  role=CONTEXT[name]
  if type(role)is not dict or set(role)!={'pid','parent_pid','birth'} or any(type(role[k])is not int or role[k]<=0 for k in role):raise ValueError('CONTEXT_ROLE')
 if CONTEXT['ordinary_sid']!=PROFILE['expected_sid'] or type(CONTEXT['session_id'])is not int or CONTEXT['session_id']!=PROFILE['session_id'] or not 0<CONTEXT['session_id']<=16383 or CONTEXT['install_directory']!=PROFILE['installed_root'] or CONTEXT['task_parent_directory']!=TASK_PARENT:raise ValueError('CONFIGURED_CONTEXT')
 if not valid_uuid(CONTEXT['owner_controller_id']):raise ValueError('CONTEXT_CONTROLLER')
 for k in ('console_pid','console_birth','package_bytes'):
  if type(CONTEXT[k])is not int or CONTEXT[k]<=0:raise ValueError('CONTEXT_INTEGER')
 for k in ('package_sha256','helper_sha256','caller_content_fingerprint'):
  if type(CONTEXT[k])is not str or re.fullmatch('[0-9a-f]{64}',CONTEXT[k])is None:raise ValueError('CONTEXT_SHA')
 for k in ('caller_source_sha','package_source_sha'):
  if type(CONTEXT[k])is not str or re.fullmatch('[0-9a-f]{40}',CONTEXT[k])is None:raise ValueError('CONTEXT_SOURCE')
 if type(GUARD_SOURCE)is not str or GUARD_SOURCE.count('__CURRENT_BINDING__')!=1 or '__CTX_'in GUARD_SOURCE or len(GUARD_SOURCE.encode('utf-8'))>65536 or hashlib.sha256(GUARD_SOURCE.encode('utf-8')).hexdigest()!=GUARD_SHA256:raise ValueError('INTERNAL_GUARD_SOURCE')

def validate_parameters(parameters):
 if type(parameters)is not dict or set(parameters)!={'correlationId','taskRoot'}:raise ValueError('ONE_IMMUTABLE_TASK_ROOT')
 correlation=parameters['correlationId']
 if not valid_uuid(correlation) or type(parameters['taskRoot'])is not str or parameters['taskRoot']!=str(PureWindowsPath(TASK_PARENT)/('install-operation-'+correlation)) or "'"in parameters['taskRoot']:raise ValueError('ONE_IMMUTABLE_TASK_ROOT')
 return correlation

def ack_fields(ack):
 if type(ack)is not dict:raise ValueError('CURRENT_ACCEPTED_ACK')
 keys={'requestId','operationId','controllerId','code','final'}
 if not keys.issubset(ack) or any(not valid_uuid(ack[k])for k in ('requestId','operationId','controllerId')) or ack['code']!='ACCEPTED' or ack['final']is not False or ack['controllerId']!=CONTEXT['owner_controller_id']:raise ValueError('CURRENT_ACCEPTED_ACK')
 return {k:ack[k]for k in keys}

def validate_binding(binding,request,ack):
 expected={'controllerId','helperSha256','inputBound','internalRequestSha256','jobId','limited','operationId','originalSid','ownerPid','requestId','sessionId'}
 if type(binding)is not dict or type(request)is not dict or type(ack)is not dict or set(ack)!={'requestId','operationId','controllerId','code','final'} or type(binding.get('ownerPid'))is not int or type(binding.get('sessionId'))is not int or not expected.issubset(binding) or any(not valid_uuid(binding.get(k))for k in ('jobId','requestId','operationId','controllerId')):raise ValueError('BINDING_SCHEMA')
 if canonical(ack_fields(request))!=canonical(ack_fields(ack)) or any(binding[k]!=request.get(k)for k in ('requestId','operationId','controllerId')):raise ValueError('CURRENT_REQUEST_BINDING')
 if type(binding['internalRequestSha256'])is not str or re.fullmatch('[0-9a-f]{64}',binding['internalRequestSha256'])is None:raise ValueError('INTERNAL_REQUEST_SHA')
 if binding['originalSid']!=CONTEXT['ordinary_sid'] or binding['sessionId']!=CONTEXT['session_id'] or binding['limited']is not True or binding['ownerPid']!=CONTEXT['owner']['pid'] or binding['helperSha256']!=CONTEXT['helper_sha256'] or binding['inputBound']is not True:raise ValueError('PRINCIPAL_HELPER_BINDING')
 return {k:binding[k]for k in expected}

def identity():
 s=open('/proc/'+QEMU_PID+'/stat','rb').read().split();argv=open('/proc/'+QEMU_PID+'/cmdline','rb').read();boot=open('/proc/sys/kernel/random/boot_id').read().strip();image=os.readlink('/proc/'+QEMU_PID+'/exe')
 if len(s)<22 or s[3]!=str(PROFILE['qemu_parent_pid']).encode() or s[21]!=QEMU_TICKS.encode() or os.stat('/proc/'+QEMU_PID).st_uid!=PROFILE['qemu_uid'] or hashlib.sha256(argv).hexdigest()!=PROFILE['qemu_argv_sha256'] or boot!=PROFILE['host_boot_id'] or os.path.basename(image)!='qemu-system-x86_64' or not live(QMP_SOCKET,QEMU_PID,QEMU_TICKS) or not live(QGA_SOCKET,QEMU_PID,QEMU_TICKS) or os.fsencode(QMP_SOCKET)not in argv or os.fsencode(QGA_SOCKET)not in argv:raise ValueError('QEMU_SOCKET_IDENTITY')
 return [s[0].decode(),s[3].decode(),s[21].decode(),PROFILE['qemu_uid'],image,hashlib.sha256(argv).hexdigest(),boot]

class BindingUnavailable(ValueError):pass

def load_binding(ack):
 b=read(QGA_SOCKET,PARAMETERS['taskRoot']+'\\uac-binding.json',maxsize=8192)
 r=read(QGA_SOCKET,PARAMETERS['taskRoot']+'\\request.json',maxsize=24576)
 if b is None or r is None:raise BindingUnavailable('CURRENT_BINDING_UNAVAILABLE')
 return validate_binding(json.loads(decode(b)),json.loads(decode(r)),ack)

def powershell_command(source,reason):
 if type(source)is not str or len(source.encode('utf-8'))>65536:raise ValueError(reason+'_BODY_BOUND')
 wrapper=compressed_powershell_command(source)
 if type(wrapper)is not str:raise ValueError(reason+'_COMMAND_EMITTER')
 enc=base64.b64encode(wrapper.encode('utf-16le')).decode('ascii')
 if len(enc)>30000 or len('powershell.exe')+len(' -NoProfile -NonInteractive -EncodedCommand ')+len(enc)>30000:raise ValueError(reason+'_FULL_COMMAND_BOUND')
 return enc

def current_guest_guard(binding):
 validate_globals();literal=canonical(binding).decode('utf-8')
 if "'"in literal or GUARD_SOURCE.count('__CURRENT_BINDING__')!=1:raise ValueError('GUARD_BINDING_LITERAL')
 ps=GUARD_SOURCE.replace('__CURRENT_BINDING__',literal);source_bytes=ps.encode('utf-8')
 if len(source_bytes)>65536:raise ValueError('GUARD_BODY_BOUND')
 body_sha=hashlib.sha256(source_bytes).hexdigest();enc=powershell_command(ps,'GUARD')
 ack=call(QGA_SOCKET,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',enc],'capture-output':True})
 if type(ack.get('pid'))is not int or ack['pid']<=0:raise ValueError('GUARD_ACK_UNAVAILABLE')
 emit({'state':'SAME_GUEST_GUARD_ACCEPTED','guestPid':ack['pid'],'jobId':binding['jobId'],'guardBodySha256':body_sha,'bindingSha256':digest(binding)})
 result=None
 for _ in range(80):
  z=call(QGA_SOCKET,'guest-exec-status',{'pid':ack['pid']})
  if z.get('exited')is True:result=z;break
  time.sleep(.1)
 if result is None:
  emit({'state':'SAME_GUEST_GUARD_UNKNOWN','guestPid':ack['pid'],'replayAllowed':False});raise ValueError('CURRENT_GUEST_GUARD_UNKNOWN')
 if type(result.get('exitcode'))is not int or result['exitcode']!=0:
  emit({'state':'SAME_GUEST_GUARD_TERMINAL_REFUSED','guestPid':ack['pid'],'result':result,'replayAllowed':False});raise ValueError('CURRENT_GUEST_GUARD_REFUSED')
 emit({'state':'SAME_GUEST_GUARD_TERMINAL','guestPid':ack['pid'],'result':result})
 rows=[json.loads(line)for line in base64.b64decode(result['out-data'],validate=True).decode('utf-8-sig').splitlines()]
 if len(rows)!=2 or type(rows[0])is not dict or type(rows[1])is not dict or rows[0].get('state')!='CURRENT_TYPED_GETPROCESS_BIRTHS' or rows[0].get('effects')is not False or rows[0].get('source')!='GetProcess.StartTime.ToFileTimeUtc':raise ValueError('GUEST_GUARD_TYPED_ROWS')
 for key,wanted in (('explorer'+str(CONTEXT['console_pid']),CONTEXT['console_birth']),('owner'+str(CONTEXT['owner']['pid']),CONTEXT['owner']['birth']),('launcher'+str(CONTEXT['owner_wrapper']['pid']),CONTEXT['owner_wrapper']['birth'])):
  if type(rows[0].get(key))is not int or rows[0][key]!=wanted:raise ValueError('GUEST_GUARD_TYPED_BIRTH')
 row=rows[1]
 if row.get('state')!='CURRENT_BOUND_GUEST_GREEN' or row.get('jobId')!=binding['jobId'] or row.get('sid')!=CONTEXT['ordinary_sid'] or row.get('sessionId')!=CONTEXT['session_id'] or row.get('consolePid')!=CONTEXT['console_pid'] or row.get('ownerPid')!=CONTEXT['owner']['pid'] or row.get('ownerBirth')!=CONTEXT['owner']['birth'] or row.get('boot')!=CONTEXT['boot_utc'] or type(row.get('elevated'))is not int or row['elevated']!=0 or type(row.get('elevationType'))is not int or row['elevationType']!=PROFILE['token_policy']['elevation_type'] or row.get('effects')is not False or row.get('helperActors')!=[]:raise ValueError('GUEST_GUARD_PROJECTION')
 return row,body_sha

def perform_current_stage(decision,stage,binding,ack,prior_consent,opening,frame_reader,send,capture_directory):
 # Production main calls this actual function for every atomic QMP key packet.
 current=load_binding(ack)
 if current!=binding:raise ValueError('ORIGINAL_JOB_CHANGED')
 row,body_sha=current_guest_guard(binding);consent=row.get('consentActor')
 if type(consent)is not dict:raise ValueError('CURRENT_CONSENT_PROJECTION')
 if prior_consent is not None and consent!=prior_consent:raise ValueError('ORIGINAL_CONSENT_CHANGED')
 if identity()!=opening:raise ValueError('GUEST_IDENTITY_CHANGED')
 if load_binding(ack)!=binding:raise ValueError('CURRENT_BINDING_CHANGED')
 fresh=frame_reader();frame_sha=hashlib.sha256(fresh).hexdigest();binding_sha=digest(binding)
 decision_guard(decision,stage,binding_sha,frame_sha)
 save(capture_directory+'/before-'+str(time.monotonic_ns())+'.ppm',fresh)
 command_id,reply=send_guarded(decision,stage,binding_sha,frame_sha,send)
 emit({'state':'ORIGINAL_KEY_CHAIN_ACK','stage':stage,'commandId':command_id,'reply':reply,'jobId':binding['jobId'],'frameSha256':frame_sha,'bindingSha256':binding_sha,'guardBodySha256':body_sha,'acceptedAckSha256':digest(ack),'replayAllowed':False,'uiSuccess':False})
 return consent,body_sha,command_id,frame_sha

def publish_key_ack(binding,command_id,frame_sha,body_sha,accepted_ack):
 marker={'schema':1,'state':'FIXTURE_APPROVAL_KEY_ACK_ONLY','correlationId':PARAMETERS['correlationId'],'jobId':binding['jobId'],'requestId':binding['requestId'],'operationId':binding['operationId'],'controllerId':binding['controllerId'],'commandId':command_id,'frameSha256':frame_sha,'inputAcknowledged':True,'approvalSucceeded':False,'contextSha256':CONTEXT_SHA256,'guardTemplateSha256':GUARD_TEMPLATE_SHA256,'guardSourceSha256':GUARD_SHA256,'guardBodySha256':body_sha,'bindingSha256':digest(binding),'acceptedAckSha256':digest(accepted_ack)}
 encoded_raw=base64.b64encode(canonical(marker)).decode();destination=PARAMETERS['taskRoot']+'\\uac-grant-key-acknowledged.json'
 if "'"in destination:raise ValueError('MARKER_PATH')
 ps="$ErrorActionPreference='Stop';$b=[Convert]::FromBase64String('"+encoded_raw+"');$f=[IO.File]::Open('"+destination+"',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()};Write-Output 'FIXTURE_KEY_ACK_PUBLISHED'"
 enc=powershell_command(ps,'MARKER');ack=call(QGA_SOCKET,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',enc],'capture-output':True})
 if type(ack.get('pid'))is not int or ack['pid']<=0:raise ValueError('MARKER_ACK_UNAVAILABLE')
 emit({'state':'SAME_FIXTURE_MARKER_ACCEPTED','guestPid':ack['pid'],'sourceSha256':hashlib.sha256(ps.encode()).hexdigest(),'replayAllowed':False})
 for _ in range(80):
  result=call(QGA_SOCKET,'guest-exec-status',{'pid':ack['pid']})
  if result.get('exited')is True:
   emit({'state':'SAME_FIXTURE_MARKER_TERMINAL','guestPid':ack['pid'],'result':result,'replayAllowed':False})
   if type(result.get('exitcode'))is not int or result['exitcode']!=0:raise ValueError('FIXTURE_MARKER_REFUSED')
   return
  time.sleep(.1)
 emit({'state':'SAME_FIXTURE_MARKER_UNKNOWN','guestPid':ack['pid'],'replayAllowed':False});raise ValueError('FIXTURE_MARKER_UNKNOWN')

def main():
 global wire,partial_wire
 wire=partial_wire=None;c=reader=None;primary=None
 try:
  validate_globals();validate_parameters(PARAMETERS)
  opening=identity();directory=tempfile.mkdtemp(prefix='agent-secondary-key-chain-',dir=LEAF);os.chmod(directory,0o700);wire=os.open(directory+'/original-wire.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);partial_wire=os.open(directory+'/partial-wire.private',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(10);c.connect(QMP_SOCKET);verify_peer(c,QMP_SOCKET);reader=c.makefile('rb');next_id=1
  def response(wanted):
   for _ in range(32):
    raw=reader.readline(32769)
    if not 0<len(raw)<=32768:raise ValueError('QMP_REPLY_BOUND')
    os.write(wire,raw);os.fsync(wire);v=json.loads(raw)
    if wanted is None:
     if 'QMP'not in v:raise ValueError('QMP_GREETING')
     return v
    if v.get('id')==wanted:
     if 'return'not in v or 'error'in v:raise ValueError('QMP_MATCHING_REPLY_REFUSED')
     return v['return']
    if 'event'not in v:raise ValueError('QMP_UNRELATED_REPLY')
   raise ValueError('QMP_REPLY_BOUND')
  def command(name,args=None):
   nonlocal next_id
   i=next_id;next_id+=1;v={'execute':name,'id':i}
   if args is not None:v['arguments']=args
   c.sendall(json.dumps(v,separators=(',',':')).encode()+b'\n');return i,response(i)
  def frame():
   path=directory+'/frame-'+str(next_id)+'.ppm';i,_=command('screendump',{'filename':path});fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   try:
    st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=PROFILE['qemu_uid'] or st.st_nlink!=1 or not 0<st.st_size<16777216:raise ValueError('FRAME_FILE')
    raw=os.read(fd,st.st_size+1)
    if len(raw)!=st.st_size:raise ValueError('FRAME_LENGTH')
   finally:os.close(fd)
   return raw
  def emit_frame(binding=None,stage='observe'):
   raw=frame();packed=gzip.compress(raw,mtime=0)
   if len(packed)>700000:raise ValueError('FRAME_BOUND')
   binding_sha=digest(binding)if binding is not None else None
   emit({'state':'FRESH_CHAIN_FRAME','stage':stage,'sha256':hashlib.sha256(raw).hexdigest(),'frameGzip':base64.b64encode(packed).decode(),'binding':binding,'bindingSha256':binding_sha,'remoteCapture':directory,'inputAckIsUiProof':False,'joined':original_binding is not None,'joinRequired':original_binding is None})
   return binding_sha
  response(None);command('qmp_capabilities');stage='focus';original_binding=None;original_consent=None;accepted_ack=None;deadline=time.monotonic()+240;actions=0;finished=False;emit_frame()
  while time.monotonic()<deadline:
   ready,_,_=select.select([sys.stdin],[],[],max(0,deadline-time.monotonic()))
   if not ready:raise ValueError('ORIGINAL_CHAIN_INPUT_DEADLINE')
   raw=sys.stdin.buffer.readline(8193)
   if not raw or len(raw)>8192:raise ValueError('ORIGINAL_CHAIN_COMMAND_BOUND')
   save(directory+'/decision-'+str(actions)+'.json',raw);decision=json.loads(raw)
   if decision=={'action':'finish'}:finished=True;break
   if type(decision)is dict and decision.get('action')=='join':
    if set(decision)!={'action','acceptedAck'} or original_binding is not None or type(decision['acceptedAck'])is not dict or set(decision['acceptedAck'])!={'requestId','operationId','controllerId','code','final'}:raise ValueError('ONE_ACCEPTED_ACK_JOIN')
    if accepted_ack is not None:raise ValueError('ONE_ACCEPTED_ACK_JOIN')
    accepted_ack=ack_fields(decision['acceptedAck'])
    try:binding=load_binding(accepted_ack)
    except BindingUnavailable:binding=None
    if binding is not None:
     original_binding=binding;emit({'state':'INPUT_JOB_JOINED','binding':binding,'bindingSha256':digest(binding),'acceptedAckSha256':digest(accepted_ack),'nativeGuardClaimed':False})
    actions+=1;emit_frame(binding,stage);continue
   if decision=={'action':'observe'}:
    try:binding=load_binding(accepted_ack)if accepted_ack is not None else None
    except BindingUnavailable:binding=None
    if original_binding is not None and binding!=original_binding:raise ValueError('ORIGINAL_JOB_CHANGED')
    if binding is not None and original_binding is None:
     original_binding=binding;emit({'state':'INPUT_JOB_JOINED','binding':binding,'bindingSha256':digest(binding),'acceptedAckSha256':digest(accepted_ack),'nativeGuardClaimed':False})
    emit_frame(binding,stage);actions+=1;continue
   if original_binding is None:raise ValueError('CURRENT_ACK_JOIN_REQUIRED')
   original_consent,body_sha,command_id,frame_sha=perform_current_stage(decision,stage,original_binding,accepted_ack,original_consent,opening,frame,command,directory)
   if stage=='approve':publish_key_ack(original_binding,command_id,frame_sha,body_sha,accepted_ack)
   actions+=1;time.sleep(.35);emit_frame(original_binding,stage)
   if stage=='approve':finished=True;break
   stage='expand'if stage=='focus'else'approve'
  if not finished:raise ValueError('ORIGINAL_CHAIN_INPUT_DEADLINE')
 except BaseException as error:
  primary=error;raise
 finally:
  failures=[]
  callbacks=[]
  if reader is not None:callbacks.append(('reader',reader.close))
  if c is not None:callbacks.append(('socket',c.close))
  if wire is not None:callbacks.append(('wire',lambda:os.close(wire)))
  if partial_wire is not None:callbacks.append(('partial_wire',lambda:os.close(partial_wire)))
  for name,close in callbacks:
   try:close()
   except BaseException as error:failures.append((name,error))
  if failures:
   if primary is None:raise failures[0][1]
   try:primary.windowsGuestInputCleanupFailures=tuple((name,type(error).__name__)for name,error in failures)
   except BaseException:pass
 if identity()!=opening:raise ValueError('SOURCE_CLOSING_GUEST_IDENTITY')
 emit({'state':'ORIGINAL_KEY_CHAIN_CLOSED','allOwnedQmpHoldersClosed':True,'replayAllowed':False})

if __name__=='__main__':main()
"""
