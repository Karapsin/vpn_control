"""Fixed same-session SYSTEM diagnostic for recovered CP117 secure input.

Creates only a bounded, source-bound diagnostic process and private receipts.
No authentication, keyboard input, registry write, or account change.
"""
import base64,hashlib,inspect,json,os,uuid
from pathlib import Path
from . import windows_cp117_recovered_login as login
from .windows_diagnostic_authority_capture import AuthorityCapture
LOGIN_SHA='8cf4087a82f542f9c30ce8453cd3802b7daf0ef63ee06320edeeb97bb005b779'
CORRELATION='bdd32853-f9ac-4ba8-90a8-e4d5e2b85c6e'
NONCE='4a298f67-a9af-4fe0-a993-a263461b6a18'
NATIVE_SHA='ca66d3aead0c278b4a69b2baf02628acf4c906d2d9d227cf053483e236137858'
CHILD_SHA='4b014f9c3f283a813b3cb7a8fc712b92d3d39914229a8db7545c1b3860979b1a'
PARENT_SHA='8bd4ceff3bc81e2cd9f14202f0d2e4357eb906f92710c06b6c069392666ae0a4'
UI={'pid':1096,'parentPid':792,'sessionId':1,'startedAtUtc':'2026-10-03T15:09:52.5087070Z'}

_NATIVE=r'''using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class CP117SessionRead {
 [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] public struct TP { public uint Count; public LUID Id; public uint Attributes; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct SI { public int cb; public string reserved,desktop,title; public uint x,y,xSize,ySize,xChars,yChars,fill,flags; public short show,reserved2; public IntPtr reservedPtr,input,output,error; }
 [StructLayout(LayoutKind.Sequential)] public struct PI { public IntPtr process,thread; public uint pid,tid; }
 [StructLayout(LayoutKind.Sequential)] public struct SA { public int length; public IntPtr descriptor; public int inherit; }
 [StructLayout(LayoutKind.Sequential)] public struct FT { public uint lo,hi; }
 [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID id);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TP state,int size,IntPtr previous,IntPtr returned);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr token,uint access,IntPtr attributes,int level,int type,out IntPtr result);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int kind,ref uint session,uint size);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string application,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string directory,ref SI startup,out PI process);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint revision,out IntPtr result,out uint size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string path,ref SA attributes);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr process,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr process,out uint code);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetProcessTimes(IntPtr process,out FT creation,out FT exit,out FT kernel,out FT user);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool ProcessIdToSessionId(uint pid,out uint session);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder path,ref uint size);
 static void Need(bool value) { if(!value)throw new Win32Exception(Marshal.GetLastWin32Error()); }
 static void Enable(IntPtr token,string name) { LUID id;Need(LookupPrivilegeValue(null,name,out id));TP p=new TP();p.Count=1;p.Id=id;p.Attributes=2;Need(AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero));int e=Marshal.GetLastWin32Error();if(e!=0)throw new Win32Exception(e); }
 static readonly object ownership=new object();static PI owned;static bool created,expired;
 static System.Threading.Timer timer;
 public static void Deadline(){timer=new System.Threading.Timer(delegate { lock(ownership){expired=true;if(Cleanup())Environment.Exit(124);else Console.Error.WriteLine("SECURE_OWNED_CLEANUP_UNKNOWN");} },null,40000,System.Threading.Timeout.Infinite);}
 static void Held(PI p){if(!created||p.process!=owned.process||p.thread!=owned.thread||p.pid!=owned.pid||p.tid!=owned.tid)throw new InvalidOperationException("SECURE_HANDLE_AUTHORITY");}
 public static bool Cleanup(){lock(ownership){
  if(!created)return true;
  uint state=WaitForSingleObject(owned.process,0);
  if(state==258){if(!TerminateProcess(owned.process,125)||WaitForSingleObject(owned.process,3000)!=0)return false;}
  else if(state!=0)return false;
  CloseHandle(owned.thread);CloseHandle(owned.process);owned=new PI();created=false;return true;
 }}
 public static uint Resume(PI p){lock(ownership){Held(p);return ResumeThread(p.thread);}}
 public static uint Wait(PI p){lock(ownership){Held(p);return WaitForSingleObject(p.process,25000);}}
 public static uint ExitCode(PI p){lock(ownership){Held(p);uint code;Need(GetExitCodeProcess(p.process,out code));return code;}}
 public static void PrivateDirectory(string path) { IntPtr descriptor;uint size;Need(ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYG:SYD:P(A;;FA;;;SY)",1,out descriptor,out size));try{SA a=new SA();a.length=Marshal.SizeOf(typeof(SA));a.descriptor=descriptor;Need(CreateDirectory(path,ref a));}finally{LocalFree(descriptor);} }
 public static PI Suspended(string application,string encoded,string directory) {
  lock(ownership){if(expired)throw new InvalidOperationException("SECURE_DEADLINE_EXPIRED");if(created)throw new InvalidOperationException("SECURE_ALREADY_CREATED");
  IntPtr original=IntPtr.Zero,copy=IntPtr.Zero;
  try { Need(OpenProcessToken(GetCurrentProcess(),0x2B,out original));Enable(original,"SeTcbPrivilege");Enable(original,"SeIncreaseQuotaPrivilege");Enable(original,"SeAssignPrimaryTokenPrivilege");Need(DuplicateTokenEx(original,0x02000000,IntPtr.Zero,2,1,out copy));uint session=1;Need(SetTokenInformation(copy,12,ref session,4));SI s=new SI();s.cb=Marshal.SizeOf(typeof(SI));s.desktop=@"WinSta0\Winlogon";PI result;StringBuilder command=new StringBuilder("\""+application+"\" -NoProfile -NonInteractive -EncodedCommand "+encoded,32768);Need(CreateProcessAsUser(copy,application,command,IntPtr.Zero,IntPtr.Zero,false,0x08000004,IntPtr.Zero,directory,ref s,out result));owned=result;created=true;return result;
  } finally { if(copy!=IntPtr.Zero)CloseHandle(copy);if(original!=IntPtr.Zero)CloseHandle(original); }
  }
 }
 public static string Birth(PI process) { lock(ownership){Held(process);FT c,e,k,u;Need(GetProcessTimes(process.process,out c,out e,out k,out u));return (((ulong)c.hi<<32)|c.lo).ToString(); }}
 public static string Image(PI process) { lock(ownership){Held(process);StringBuilder path=new StringBuilder(32768);uint size=32768;Need(QueryFullProcessImageName(process.process,0,path,ref size));return path.ToString(); }}
 public static uint Session(PI process) { lock(ownership){Held(process);uint session;Need(ProcessIdToSessionId(process.pid,out session));return session; }}
}'''

_CHILD_HEAD=r'''$ErrorActionPreference='Stop'
$dir='__DIR__';$nonce='__NONCE__'
Add-Type -TypeDefinition 'public static class CP117ChildDeadline { static System.Threading.Timer timer; public static void Begin(){timer=new System.Threading.Timer(delegate {System.Environment.Exit(124);},null,20000,System.Threading.Timeout.Infinite);} }'
[CP117ChildDeadline]::Begin()
function WritePrivate($name,$value){$raw=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 12 -Compress));$f=[IO.FileStream]::new((Join-Path $dir $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough);try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}}
$birth=Get-Content -LiteralPath (Join-Path $dir 'child.json') -Raw|ConvertFrom-Json
$self=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)
$selfCreation=[Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
if($birth.creationFileTime -cne $selfCreation -or $birth.nonce -cne $nonce -or $birth.pid -ne $PID -or $self.SessionId -ne 1 -or $self.ParentProcessId -ne $birth.parentPid -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SECURE_READER_IDENTITY'}
$encoded=($self.CommandLine -split '\s+')[-1]
$h=[Security.Cryptography.SHA256]::Create();try{$sourceHash=([BitConverter]::ToString($h.ComputeHash([Convert]::FromBase64String($encoded)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
if($sourceHash -cne $birth.sourceSha256){throw 'SECURE_READER_SOURCE'}
'''

_PARENT=r'''$ErrorActionPreference='Stop'
$dir='__DIR__';$nonce='__NONCE__';$childSource='__ENCODED__';$childSha='__CHILD_SHA__'
function WritePrivate($name,$value){$raw=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 12 -Compress));$f=[IO.FileStream]::new((Join-Path $dir $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough);try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}}
function GuardUI {
 $ui=Get-CimInstance Win32_Process -Filter 'ProcessId=1096'
 if($null -eq $ui -or $ui.Name -cne 'LogonUI.exe' -or $ui.SessionId -ne 1 -or $ui.ParentProcessId -ne 792 -or $ui.CreationDate.ToUniversalTime().ToString('o') -cne '2026-10-03T15:09:52.5087070Z'){throw 'SECURE_UI_GENERATION'}
 $owner=Invoke-CimMethod -InputObject $ui -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'").Count -ne 0){throw 'SECURE_UI_OWNER'}
 $account=@(Get-CimInstance Win32_UserAccount -Filter "Name='vpncp117' AND LocalAccount=TRUE")
 if($account.Count -ne 1 -or $account[0].SID -cne 'S-1-5-21-2404255130-2183793310-3766671872-1002' -or $account[0].Disabled -or $account[0].Lockout){throw 'SECURE_ACCOUNT'}
}
$pi=$null;$resumed=$false;$completed=$false
try {
 if([IntPtr]::Size -ne 8 -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0){throw 'SECURE_PARENT_IDENTITY'}
 Add-Type -TypeDefinition @'
__NATIVE__
'@
 [CP117SessionRead]::Deadline();$budget=[Diagnostics.Stopwatch]::StartNew()
 GuardUI
 if(([IO.File]::GetAttributes('C:\ProgramData') -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'SECURE_PARENT_REPARSE'}
 [CP117SessionRead]::PrivateDirectory($dir)
 WritePrivate 'intent.json' @{nonce=$nonce;sourceSha256=$childSha;uiPid=1096;uiStartedAtUtc='2026-10-03T15:09:52.5087070Z';state='consumed'}
 $application='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
 if(([IO.File]::GetAttributes($application) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'SECURE_APPLICATION_REPARSE'}
 $applicationSha=(Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash
 GuardUI;WritePrivate 'attempt.json' @{nonce=$nonce;sourceSha256=$childSha;state='consumed'};GuardUI
 if($budget.Elapsed.TotalSeconds -gt 12){throw 'SECURE_ADMISSION_DEADLINE'}
 $pi=[CP117SessionRead]::Suspended($application,$childSource,$dir)
 $birth=[CP117SessionRead]::Birth($pi)
 if([CP117SessionRead]::Session($pi) -ne 1 -or [CP117SessionRead]::Image($pi) -ine $application -or (Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash -cne $applicationSha){throw 'SECURE_CHILD_GENERATION'}
 $record=@{nonce=$nonce;sourceSha256=$childSha;pid=[int]$pi.pid;parentPid=$PID;creationFileTime=$birth;sessionId=1;applicationSha256=$applicationSha}
 WritePrivate 'child.json' $record;GuardUI
 if($budget.Elapsed.TotalSeconds -gt 15 -or [CP117SessionRead]::Birth($pi) -cne $birth -or [CP117SessionRead]::Resume($pi) -ne 1){throw 'SECURE_RESUME'}
 $resumed=$true
 $wait=[CP117SessionRead]::Wait($pi)
 if($wait -ne 0){throw 'SECURE_CHILD_DEADLINE'}
 $completed=$true;$exit=[CP117SessionRead]::ExitCode($pi)
 if($exit -ne 0){throw 'SECURE_CHILD_EXIT'}
 GuardUI
 $path=Join-Path $dir 'result.json'
 if(([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'SECURE_RESULT_REPARSE'}
 $f=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($f.Length -gt 32768 -or $f.Length -le 0){throw 'SECURE_RESULT_BOUND'};$bytes=New-Object byte[] ([int]$f.Length);if($f.Read($bytes,0,$bytes.Length) -ne $bytes.Length){throw 'SECURE_RESULT_SHORT'};$value=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json}finally{$f.Dispose()}
 if($value.reader.nonce -cne $nonce -or $value.reader.pid -ne $pi.pid -or $value.reader.sessionId -ne 1 -or $value.reader.sourceSha256 -cne $childSha -or $value.reader.parentPid -ne $PID -or $value.reader.expectedSystem -ne $true){throw 'SECURE_RESULT_BINDING'}
 [Console]::Out.WriteLine((@{facts=$value.facts;reader=$value.reader;birth=$record}|ConvertTo-Json -Depth 12 -Compress))
}catch{[Console]::Out.WriteLine((@{version=1;code='UNKNOWN';phase=$_.Exception.Message;readerCreated=($null -ne $pi);readerResumed=$resumed}|ConvertTo-Json -Compress));exit 1}
finally{
 if(-not [CP117SessionRead]::Cleanup()){[Console]::Error.WriteLine('SECURE_OWNED_CLEANUP_UNKNOWN')}
}

'''

_FOCUS_CS=r''' [StructLayout(LayoutKind.Sequential)] public struct Rect {public int left,top,right,bottom;}
 [StructLayout(LayoutKind.Sequential)] public struct Gui {public uint size,flags;public IntPtr active,focus,capture,menu,move,caret;public Rect rect;}
 public class Focus {public uint threadId,windowThreadId,ownerPid;public string hkl;public bool hasFocus;public int error;}
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetGUIThreadInfo(uint id,ref Gui gui);
 [DllImport("user32.dll",SetLastError=true)] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 public static Focus ReadFocus(uint id){Focus f=new Focus();f.threadId=id;f.hkl=GetKeyboardLayout(id).ToInt64().ToString("X16");Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(id,ref g)){f.error=Marshal.GetLastWin32Error();return f;}if(g.focus!=IntPtr.Zero){f.hasFocus=true;uint owner;f.windowThreadId=GetWindowThreadProcessId(g.focus,out owner);f.ownerPid=owner;}return f;}
'''

def bodies(nonce):
    if nonce!=NONCE:raise ValueError('secure-fixed-nonce')
    directory='C:\\ProgramData\\cp117-secure-layout-'+CORRELATION
    head=_CHILD_HEAD.replace('__DIR__',directory).replace('__NONCE__',nonce)
    body=login._layout_body()
    declaration=' [DllImport("user32.dll")] public static extern IntPtr GetKeyboardLayout(uint threadId);'
    if body.count(declaration)!=1:raise ValueError('secure-focus-factory')
    body=body.replace(declaration,declaration+'\n'+_FOCUS_CS)
    marker_refresh='  $p.Refresh();$after='
    if body.count(marker_refresh)!=1:raise ValueError('secure-focus-inventory')
    body=body.replace(marker_refresh,'  $focus=@($ids|ForEach-Object {[CP117LayoutRead]::ReadFocus([uint32]$_)})\n'+marker_refresh)
    marker=" [Console]::Out.WriteLine(([pscustomobject]@{version=1;accountCount=$accounts.Count;accounts=$accounts;processCount=$rows.Count;processes=$rows;layout=$layout}|ConvertTo-Json -Depth 6 -Compress))"
    if body.count(marker)!=1:raise ValueError('secure-fixed-child-factory')
    body=body.replace(marker," $facts=[pscustomobject]@{version=1;accountCount=$accounts.Count;accounts=$accounts;processCount=$rows.Count;processes=$rows;layout=$layout};WritePrivate 'result.json' @{facts=$facts;reader=@{nonce=$nonce;pid=$PID;parentPid=[int]$self.ParentProcessId;sessionId=[int]$self.SessionId;expectedSystem=$true;creationFileTime=$selfCreation;sourceSha256=$sourceHash;focus=$focus}}")
    child=head+body;child_sha=hashlib.sha256(child.encode('utf-16le')).hexdigest()
    parent=_PARENT.replace('__DIR__',directory).replace('__NONCE__',nonce).replace('__NATIVE__',_NATIVE).replace('__CHILD_SHA__',child_sha).replace('__ENCODED__',base64.b64encode(child.encode('utf-16le')).decode())
    return parent,child,child_sha


def secure_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('secure-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('secure-output-cap')
    first,sep,body=raw.partition(b'\n')
    if not sep or first.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if value.get('exitcode')!=0:raise ValueError('secure-reader-exit')
    answer=json.loads(body)
    if set(answer)!={'facts','reader','birth'}:raise ValueError('secure-result-schema')
    reader=answer['reader'];birth=answer['birth']
    if set(reader)!={'nonce','pid','parentPid','sessionId','expectedSystem','creationFileTime','sourceSha256','focus'}or reader['nonce']!=nonce or reader['parentPid']!=pid or reader['sessionId']!=1 or reader['expectedSystem']is not True or type(reader['pid'])is not int or reader['pid']<=0:raise ValueError('secure-reader-binding')
    if set(birth)!={'nonce','sourceSha256','pid','parentPid','creationFileTime','sessionId','applicationSha256'}or any(birth[k]!=reader[k]for k in('nonce','sourceSha256','pid','parentPid','sessionId','creationFileTime'))or not isinstance(birth['creationFileTime'],str)or not birth['creationFileTime'].isdigit():raise ValueError('secure-birth-binding')
    if reader['sourceSha256']!=CHILD_SHA:raise ValueError('secure-child-source')
    validate_layout(answer['facts']);validate_focus(answer);return answer


def validate_layout(facts):
    login._validate_layout_facts(facts)
    if any(facts['layout'][k]!=v for k,v in UI.items()):raise ValueError('secure-original-ui')



def validate_focus(answer):
    facts=answer['facts'];validate_layout(facts);rows=answer['reader']['focus'];expected={r['threadId']:r['hkl']for r in facts['layout']['threads']}
    if not isinstance(rows,list)or len(rows)!=len(expected):raise ValueError('secure-focus-bound')
    seen=set();focused=[]
    for row in rows:
        if not isinstance(row,dict)or set(row)!={'threadId','windowThreadId','ownerPid','hkl','hasFocus','error'}or type(row['threadId'])is not int or row['threadId']in seen or row['threadId']not in expected or row['hkl']!=expected[row['threadId']]or type(row['hasFocus'])is not bool or any(type(row[k])is not int or not 0<=row[k]<=4294967295 for k in('windowThreadId','ownerPid','error')):raise ValueError('secure-focus-schema')
        seen.add(row['threadId'])
        if row['hkl']=='0000000000000000':
            # These rows provide no input-layout authority. Only the measured
            # unresolved/windowless/error87 shape may coexist with a positively
            # bound US input thread; this does not classify them as non-GUI.
            if row['error']!=87 or row['hasFocus']or row['ownerPid']or row['windowThreadId']:raise ValueError('secure-zero-input-layout')
        elif row['hkl']!='0000000004090409' or row['error']!=0:raise ValueError('secure-foreign-input-layout')
        if not row['hasFocus']and(row['ownerPid']or row['windowThreadId']):raise ValueError('secure-unfocused-window')
        if row['hasFocus']:focused.append(row)
    if not focused or any(r['ownerPid']!=1096 or r['windowThreadId']!=r['threadId']or r['error']!=0 or r['hkl']=='0000000000000000'for r in focused):raise ValueError('secure-original-focus')
    if facts['layout']['preload']!=[{'name':'1','value':'00000409'}]or facts['layout']['substitutes']:raise ValueError('secure-layout-registry')

def program(record,nonce):
    if hashlib.sha256(Path(login.__file__).read_bytes()).hexdigest()!=LOGIN_SHA:raise ValueError('secure-login-source')
    source,_=login.guest.program(record,CORRELATION,nonce,observation='session');old,_=login.guest.encoded_read(nonce,observation='session');parent,child,child_sha=bodies(nonce)
    if hashlib.sha256(_NATIVE.encode()).hexdigest()!=NATIVE_SHA or child_sha!=CHILD_SHA:raise ValueError('secure-fixed-source')
    sha=hashlib.sha256(parent.encode('utf-16le')).hexdigest()
    if sha!=PARENT_SHA:raise ValueError('secure-parent-source')
    header="[Console]::Out.WriteLine(('CP117-READ "+nonce+" "+sha+" '+$PID))\n"
    # QGA's command-line remains below Windows' 32K limit. Only the exact
    # fixed public diagnostic body travels on its bounded stdin pipe.
    bootstrap=header+"""$i=[Console]::OpenStandardInput();$n=0;for($j=0;$j -lt 4;$j++){$b=$i.ReadByte();if($b -lt 0){throw 'SOURCE_HEADER'};$n=$n*256+$b};if($n -le 0 -or $n -gt 65536){throw 'SOURCE_BOUND'};$bytes=New-Object byte[] $n;$o=0;while($o -lt $n){$r=$i.Read($bytes,$o,$n-$o);if($r -le 0){throw 'SOURCE_SHORT'};$o+=$r};$s=[Text.Encoding]::UTF8.GetString($bytes);$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::Unicode.GetBytes($s)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($actual -cne '__SHA__'){throw 'SOURCE_HASH'};&([ScriptBlock]::Create($s))""".replace('__SHA__',sha)
    payload=parent.encode();input_parent=base64.b64encode(len(payload).to_bytes(4,'big')+payload).decode()
    if len(payload)>65536 or len(base64.b64encode(bootstrap.encode('utf-16le')))>30000 or len(base64.b64encode(child.encode('utf-16le')))>30000:raise ValueError('secure-command-cap')
    support=inspect.getsource(login._validate_session_facts)+inspect.getsource(login._validate_layout_facts)+inspect.getsource(validate_layout).replace('login._validate_layout_facts','_validate_layout_facts')+inspect.getsource(validate_focus).replace('login._validate_us_layout','_validate_us_layout')+inspect.getsource(login._validate_us_layout)+inspect.getsource(secure_terminal)
    support='UI='+repr(UI)+'\nCHILD_SHA='+repr(CHILD_SHA)+'\n'+support
    replacements={'ENCODED='+repr(old):'ENCODED='+repr(base64.b64encode(bootstrap.encode('utf-16le')).decode()),'BODY_SHA='+repr('5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2'):'BODY_SHA='+repr(sha),inspect.getsource(login.session.parse_terminal):support,'answer=parse_terminal(value,NONCE,BODY_SHA,pid)':'answer=secure_terminal(value,NONCE,BODY_SHA,pid)'}
    for old,new in replacements.items():
        if source.count(old)!=1:raise ValueError('secure-fixed-factory')
        source=source.replace(old,new)
    command="'capture-output':True}"
    if source.count(command)!=1:raise ValueError('secure-input-factory')
    source=source.replace(command,"'capture-output':True,'input-data':"+repr(input_parent)+"}")
    return source,sha


def observe(root):
    recovery=login.guest.recovery;ORIGINAL=login.guest.ORIGINAL;RECOVERY_SHA=login.guest.RECOVERY_SHA;SOCKET_PROOF_SHA=login.guest.SOCKET_PROOF_SHA;observation='secure-layout'
    root=Path(root).resolve(strict=True);leaf='windows-cp117-secure-layout-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'secure-consumed','replayAllowed':False}
    root=Path(root).resolve(strict=True);original=AuthorityCapture(root,'windows-cp117-recovery-'+recovery.CORRELATION)
    diagnostic=CORRELATION;nonce=NONCE
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);events=[]
    try:
        raw=recovery._local_read(original,ORIGINAL['name'],ORIGINAL['pin']);record=json.loads(raw)
        def verify():
            if recovery._local_read(original,ORIGINAL['name'],ORIGINAL['pin'])!=raw:raise ValueError('original-receipt')
            for i,item in enumerate(record['authority']):
                recovery._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(recovery._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('original-frame')
            now=recovery.authority._source_pins(root);now['recovery']=recovery.authority._read_bound_file(Path(recovery.__file__))
            if now!=record['request']['sources']or now['recovery']['sha256']!=RECOVERY_SHA:raise ValueError('original-sources')
        verify();source_pin=recovery.authority._read_bound_file(Path(__file__));session_pin=None;login_pin=recovery.authority._read_bound_file(Path(login.__file__));guest_pin=recovery.authority._read_bound_file(Path(login.guest.__file__))
        if login_pin['sha256']!=LOGIN_SHA or guest_pin['sha256']!=login.GUEST_SHA:raise ValueError('secure-factory-source')
        if True:
            from . import windows_cp117_recovered_session_observe as session
            session_pin=recovery.authority._read_bound_file(Path(session.__file__))
            if session_pin['sha256']!=login.SESSION_SHA:raise ValueError('secure-session-source')
        outer=recovery.authority._outer_authority(root)
        source,sha=program(record,nonce)
        capture.create('request.json',json.dumps({'original':ORIGINAL,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'outerAuthority':outer,'helper':source_pin,'observation':observation,'sessionHelper':session_pin,'socketProofSha256':SOCKET_PROOF_SHA},sort_keys=True).encode())
        capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=recovery.authority.closure.base._descriptor(root)
        argv=recovery.authority.closure.base.ssh_transport.build_ssh_argv(config,recovery.HOST,60,command=recovery.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'nonce':NONCE,'original':ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        value,events=login.guest._stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'])
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'secureObservation':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events)
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()
