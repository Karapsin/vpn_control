"""Fixed read-only UIA tuple diagnosis; never grants keyboard authority.

Original semantic predicates remain unchanged. Only finite property matches and
numeric provider identities are returned; no field Name/Value text is returned.
"""
import ast,base64,gzip,hashlib,inspect,json,os
from pathlib import Path
from . import windows_cp117_secure_layout_observe as secure
from .windows_diagnostic_authority_capture import AuthorityCapture
login=secure.login
from . import windows_cp117_secure_input_observe as original_semantic
ORIGINAL_SEMANTIC_SHA='836d2d13dea8604d8d9f3c409db7d15fde349ceb0ecade06ce704a3a2693f590'
LOGIN_SHA=secure.LOGIN_SHA
SECURE_SHA='bbcb1de84c89b44d7e541a35a2634ba0cf644e89f5cef7d9061e3a33e6499782'
CORRELATION='e52ebc68-a216-4bd0-a397-315b418bf236'
NONCE='bc0f88e3-3e15-468e-bebb-56c17f51b0e6'
NATIVE_SHA='7299c749a56d3a0f9e52ca14cae97289a07dabcb821f8ed1d2b278833c7b07ec'
CHILD_SHA='a4fe4a76bac90129467fc0562247914f00097248cc496587da44b2217a11a95e'
PARENT_SHA='e889999038cd109299f6e34696f573360493e39d227dc8e656f612aa09acc3b2'
FACTORY_SHA='b1fb87e5624b274f9643d096e74ecce7204014d0dab22d3a0355c2a129a0ba6e'
STREAM_SHA='94fbd47203ecd52c32611f89ce6244150d1d595de44cc3e2f3e2402d56ce43f4'
SUPPORT_SHA='ab7cd2d1b25f4ed1ea5d2a17202d14ba8952ba6344812848c6f573cac2890401'

_SEMANTIC_CS='using System;\nusing System.Runtime.InteropServices;\nusing System.Text;\nusing System.Windows.Automation;\npublic static class CP117InputRead {\n [StructLayout(LayoutKind.Sequential)] struct Rect { public int left,top,right,bottom; }\n [StructLayout(LayoutKind.Sequential)] struct Gui { public uint size,flags;public IntPtr active,focus,capture,menu,move,caret;public Rect rect; }\n [DllImport("user32.dll",SetLastError=true)] static extern bool GetGUIThreadInfo(uint id,ref Gui gui);\n [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);\n [DllImport("user32.dll")] static extern IntPtr GetKeyboardLayout(uint id);\n [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);\n [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();\n [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();\n [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int kind,StringBuilder name,uint size,out uint needed);\n static void Need(bool v,string code){if(!v)throw new InvalidOperationException(code);}\n static string ObjectName(IntPtr h){StringBuilder s=new StringBuilder(128);uint n;Need(h!=IntPtr.Zero&&GetUserObjectInformation(h,2,s,256,out n)&&n<=256,"SEMANTIC_DESKTOP");return s.ToString();}\n static bool Equal(int[] a,int[] b){if(a==null||b==null||a.Length==0||a.Length!=b.Length||a.Length>32)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}\n static IntPtr Focus(uint[] threads,out uint thread){IntPtr selected=IntPtr.Zero;thread=0;foreach(uint t in threads){Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(t,ref g))continue;if(g.focus==IntPtr.Zero)continue;uint owner;uint actual=GetWindowThreadProcessId(g.focus,out owner);Need(owner==1096&&actual==t&&GetKeyboardLayout(t).ToInt64().ToString("X16")=="0000000004090409","SEMANTIC_FOCUS_OWNER");Need(selected==IntPtr.Zero||selected==g.focus,"SEMANTIC_FOCUS_AMBIGUOUS");selected=g.focus;thread=t;}Need(selected!=IntPtr.Zero,"SEMANTIC_FOCUS_ABSENT");return selected;}\n public interface IProvider {int Pid{get;}int ControlId{get;}int NativeHandle{get;}bool Password{get;}bool Focused{get;}bool Focusable{get;}bool Enabled{get;}bool Onscreen{get;}bool PasswordLabel{get;}}\n public class Snapshot:IProvider {public int Pid{get;set;}public int ControlId{get;set;}public int NativeHandle{get;set;}public bool Password{get;set;}public bool Focused{get;set;}public bool Focusable{get;set;}public bool Enabled{get;set;}public bool Onscreen{get;set;}public bool PasswordLabel{get;set;}}\n public class Facts {public int actualPid,controlTypeId,nativeHandle;public bool ownerMatches,edit,password,keyboardFocus,keyboardFocusable,enabled,onscreen,passwordLabel,supported,keyboardAdmission;public uint threadId;public long focusWindow;public string hkl,windowStation,desktop;}\n public static Facts Describe(IProvider p){Need(p!=null,"TUPLE_PROVIDER_NULL");var f=new Facts{actualPid=p.Pid,controlTypeId=p.ControlId,nativeHandle=p.NativeHandle,ownerMatches=p.Pid==1096,edit=p.ControlId==ControlType.Edit.Id,password=p.Password,keyboardFocus=p.Focused,keyboardFocusable=p.Focusable,enabled=p.Enabled,onscreen=p.Onscreen,passwordLabel=p.PasswordLabel,keyboardAdmission=false};f.supported=f.ownerMatches&&f.edit&&f.password&&f.keyboardFocus&&f.keyboardFocusable&&f.enabled&&f.onscreen&&f.passwordLabel;return f;}\n static Snapshot Capture(AutomationElement e){var p=e.Current;return new Snapshot{Pid=p.ProcessId,ControlId=p.ControlType==null?0:p.ControlType.Id,NativeHandle=p.NativeWindowHandle,Password=p.IsPassword,Focused=p.HasKeyboardFocus,Focusable=p.IsKeyboardFocusable,Enabled=p.IsEnabled,Onscreen=!p.IsOffscreen,PasswordLabel=p.Name=="Password"};}\n static bool Same(Snapshot a,Snapshot b){return a.Pid==b.Pid&&a.ControlId==b.ControlId&&a.NativeHandle==b.NativeHandle&&a.Password==b.Password&&a.Focused==b.Focused&&a.Focusable==b.Focusable&&a.Enabled==b.Enabled&&a.Onscreen==b.Onscreen&&a.PasswordLabel==b.PasswordLabel;}\n public static Facts Read(uint[] threads){Need(ObjectName(GetProcessWindowStation())=="WinSta0"&&ObjectName(GetThreadDesktop(GetCurrentThreadId()))=="Winlogon","SEMANTIC_DESKTOP");uint thread;IntPtr hwnd=Focus(threads,out thread);AutomationElement e=AutomationElement.FocusedElement;Need(e!=null,"SEMANTIC_UIA_UNAVAILABLE");var before=Capture(e);var facts=Describe(before);uint afterThread;Need(Focus(threads,out afterThread)==hwnd&&afterThread==thread&&Equal(AutomationElement.FocusedElement.GetRuntimeId(),e.GetRuntimeId())&&Same(before,Capture(e)),"TUPLE_PROVIDER_DRIFT");facts.threadId=thread;facts.focusWindow=hwnd.ToInt64();facts.hkl="0000000004090409";facts.windowStation="WinSta0";facts.desktop="Winlogon";return facts;}\n}'

_CHILD_FAILURE=r"""}catch{$e=$_.Exception.GetBaseException();$phase=$e.Message;if($phase -cnotmatch '^(SEMANTIC|TUPLE)_[A-Z_]{1,64}$'){$phase='SEMANTIC_UNCLASSIFIED'};$details=($_|Out-String);if($details.Length -gt 2048){$details=$details.Substring(0,2048)};WritePrivate 'failure.json' @{reader=$birth;phase=$phase;hresult=[int]$e.HResult;details=$details};$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');[IO.File]::SetAccessControl((Join-Path $dir 'failure.json'),$acl);exit 1}
"""


def validate_semantic(answer):
    base_answer=dict(answer);base_answer['facts']={k:v for k,v in answer['facts'].items()if k!='secureInput'}
    secure.validate_layout(base_answer['facts']);secure.validate_focus(base_answer)
    s=answer['facts'].get('secureInput');flags=('ownerMatches','edit','password','keyboardFocus','keyboardFocusable','enabled','onscreen','passwordLabel')
    if not isinstance(s,dict)or set(s)!=set(flags)|{'actualPid','controlTypeId','nativeHandle','supported','keyboardAdmission','threadId','focusWindow','hkl','windowStation','desktop'}:raise ValueError('tuple-schema')
    if any(type(s[k])is not bool for k in flags+('supported','keyboardAdmission'))or s['keyboardAdmission']is not False or s['supported']!=all(s[k]for k in flags):raise ValueError('tuple-no-authority')
    if type(s['actualPid'])is not int or not 0<=s['actualPid']<=2147483647 or type(s['controlTypeId'])is not int or not 0<=s['controlTypeId']<=100000 or type(s['nativeHandle'])is not int or not -2147483648<=s['nativeHandle']<=2147483647:raise ValueError('tuple-metadata')
    if s['ownerMatches']!=(s['actualPid']==1096)or s['edit']!=(s['controlTypeId']==50004):raise ValueError('tuple-property-consistency')
    focused=[r['threadId']for r in answer['reader']['focus']if r['hasFocus']]
    if type(s['threadId'])is not int or s['threadId']not in focused or type(s['focusWindow'])is not int or s['focusWindow']<=0 or s['hkl']!='0000000004090409' or s['windowStation']!='WinSta0' or s['desktop']!='Winlogon':raise ValueError('tuple-current-focus')
    return s


def bodies():
    if hashlib.sha256(Path(secure.__file__).read_bytes()).hexdigest()!=SECURE_SHA or hashlib.sha256(_SEMANTIC_CS.encode()).hexdigest()!=NATIVE_SHA:raise ValueError('semantic-factory-source')
    oldparent,child,_=secure.bodies(secure.NONCE)
    olddir='C:\\ProgramData\\cp117-secure-layout-'+secure.CORRELATION;directory='C:\\ProgramData\\cp117-secure-input-'+CORRELATION
    if child.count(olddir)!=1 or child.count(secure.NONCE)!=1:raise ValueError('semantic-fixed-child')
    child=child.replace(olddir,directory).replace(secure.NONCE,NONCE)
    marker=' $facts=[pscustomobject]@{version=1;'
    if child.count(marker)!=1:raise ValueError('semantic-child-marker')
    packed=base64.b64encode(gzip.compress(_SEMANTIC_CS.encode(),mtime=0)).decode()
    insertion=" 'UIAutomationClient','UIAutomationTypes','WindowsBase'|ForEach-Object {[void][Reflection.Assembly]::LoadWithPartialName($_)}\n"
    insertion+="$memory=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$zip=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionMode]::Decompress);$buffer=New-Object byte[] 16385;$offset=0;try{while($offset -lt $buffer.Length){$n=$zip.Read($buffer,$offset,$buffer.Length-$offset);if($n -eq 0){break};$offset+=$n}}finally{$zip.Dispose();$memory.Dispose()};if($offset -ne "+str(len(_SEMANTIC_CS.encode()))+"){throw 'SEMANTIC_CODE_BOUND'};$code=[Text.Encoding]::UTF8.GetString($buffer,0,$offset);$hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($code)))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};if($actual -cne '"+NATIVE_SHA+"'){throw 'SEMANTIC_CODE_HASH'}\n"
    insertion+=" Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition $code\n $inputFacts=[CP117InputRead]::Read([uint32[]]$ids)\n"

    child=child.replace(marker,insertion+marker).replace('processes=$rows;layout=$layout};WritePrivate','processes=$rows;layout=$layout;secureInput=$inputFacts};WritePrivate')
    oldcatch="}catch{[Console]::Out.WriteLine('{\"version\":1,\"code\":\"UNKNOWN\"}');exit 1}\n"
    if child.count(oldcatch)!=1:raise ValueError('semantic-child-failure-factory')
    child=child.replace(oldcatch,_CHILD_FAILURE)
    sha=hashlib.sha256(child.encode('utf-16le')).hexdigest()
    parent=secure._PARENT.replace('__DIR__',directory).replace('__NONCE__',NONCE).replace('__NATIVE__',secure._NATIVE).replace('__CHILD_SHA__',sha).replace('__ENCODED__',base64.b64encode(child.encode('utf-16le')).decode())
    marker="if($exit -ne 0){throw 'SECURE_CHILD_EXIT'}"
    failure_read=r"""function GuardFailureAcl($acl){
 $expected=[Security.AccessControl.FileSecurity]::new();$expected.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');$sid=[Security.Principal.SecurityIdentifier]
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner($sid).Value -cne $expected.GetOwner($sid).Value -or $acl.GetGroup($sid).Value -cne $expected.GetGroup($sid).Value){throw 'SEMANTIC_FAILURE_ACL'}
 $rules=@($acl.GetAccessRules($true,$true,$sid));if($rules.Count -ne 1 -or @($acl.GetAuditRules($true,$true,$sid)).Count -ne 0){throw 'SEMANTIC_FAILURE_ACL'};$r=$rules[0]
 if($r.IdentityReference.Value -cne $expected.GetOwner($sid).Value -or $r.IsInherited -or $r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or [int]$r.FileSystemRights -ne 2032127 -or [int]$r.InheritanceFlags -ne 0 -or [int]$r.PropagationFlags -ne 0){throw 'SEMANTIC_FAILURE_ACL'}
}
if($exit -ne 0){
 GuardUI;$failurePath=Join-Path $dir 'failure.json'
 if(([IO.File]::GetAttributes($failurePath) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'SEMANTIC_FAILURE_REPARSE'}
 $f=[IO.FileStream]::new($failurePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$acl=[IO.File]::GetAccessControl($failurePath);GuardFailureAcl $acl;$aclBefore=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All);$before=[IO.FileInfo]::new($failurePath);$generation=@($before.CreationTimeUtc.Ticks,$before.LastWriteTimeUtc.Ticks,$before.Length,[int]$before.Attributes);if($f.Length -le 0 -or $f.Length -gt 16384){throw 'SEMANTIC_FAILURE_BOUND'};$bytes=New-Object byte[] ([int]$f.Length);if($f.Read($bytes,0,$bytes.Length) -ne $bytes.Length){throw 'SEMANTIC_FAILURE_SHORT'};$hash=[Security.Cryptography.SHA256]::Create();try{$failureHash=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()};$after=[IO.FileInfo]::new($failurePath);if(($generation -join ',') -cne (@($after.CreationTimeUtc.Ticks,$after.LastWriteTimeUtc.Ticks,$after.Length,[int]$after.Attributes) -join ',') -or [IO.File]::GetAccessControl($failurePath).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All) -cne $aclBefore){throw 'SEMANTIC_FAILURE_FILE_DRIFT'};$failure=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json}finally{$f.Dispose()}
 if((($failure.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'details,hresult,phase,reader' -or $failure.details -isnot [string] -or $failure.details.Length -gt 2048 -or $failure.hresult -isnot [int] -or $failure.phase -cnotmatch '^(SEMANTIC|TUPLE)_[A-Z_]{1,64}$'){throw 'SEMANTIC_FAILURE_SCHEMA'}
 $b=$failure.reader
 foreach($k in @('nonce','sourceSha256','pid','parentPid','creationFileTime','sessionId','applicationSha256')){if($b.$k -cne $record.$k){throw 'SEMANTIC_FAILURE_BINDING'}}
 if((($b.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'applicationSha256,creationFileTime,nonce,parentPid,pid,sessionId,sourceSha256'){throw 'SEMANTIC_FAILURE_BINDING'}
 GuardUI;[Console]::Out.WriteLine((@{version=1;code='UNKNOWN';phase=$failure.phase;diagnosticFailure=$failure;failureRecord=@{sha256=$failureHash;generation=$generation};readerCreated=$true;readerResumed=$resumed}|ConvertTo-Json -Depth 6 -Compress));exit 1
} """
    if parent.count(marker)!=1:raise ValueError('semantic-parent-failure-factory')
    parent=parent.replace(marker,failure_read)
    if len(child.encode('utf-16le'))*4//3>30000 or len(parent.encode())>65536:raise ValueError('semantic-command-cap')
    if sha!=CHILD_SHA or hashlib.sha256(parent.encode('utf-16le')).hexdigest()!=PARENT_SHA:raise ValueError('semantic-generated-source')
    return parent,child,sha


def _bound_terminal(value,nonce,sha,pid):
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
    semantic=answer['facts'].pop('secureInput',None);secure.validate_layout(answer['facts']);secure.validate_focus(answer);answer['facts']['secureInput']=semantic;return answer


def parse_terminal(value,nonce,sha,pid):
    # Existing strict reader/birth/frame binding unchanged except fixed new child.
    result=_bound_terminal(value,nonce,sha,pid)
    if result is not None:validate_semantic(result)
    return result


def _factories():
    if hashlib.sha256(Path(original_semantic.__file__).read_bytes()).hexdigest()!=ORIGINAL_SEMANTIC_SHA:raise ValueError('tuple-original-source')
    functions=(secure.program,secure.bodies,secure.secure_terminal,secure.validate_layout,secure.validate_focus,login._layout_body,login._validate_layout_facts,login._validate_session_facts,login._validate_us_layout,login.guest.program,login.guest.encoded_read,login.session.parse_terminal)
    if hashlib.sha256(''.join(inspect.getsource(f)for f in functions).encode()).hexdigest()!=FACTORY_SHA or hashlib.sha256(inspect.getsource(login.guest._stream).encode()).hexdigest()!=STREAM_SHA:raise ValueError('semantic-imported-factory')


def program(record):
    _factories()
    parent,child,childsha=bodies()
    source,oldsha=secure.program(record,secure.NONCE)
    oldparent,oldchild,oldchildsha=secure.bodies(secure.NONCE)
    oldinput=base64.b64encode(len(oldparent.encode()).to_bytes(4,'big')+oldparent.encode()).decode();newinput=base64.b64encode(len(parent.encode()).to_bytes(4,'big')+parent.encode()).decode()
    tree=ast.parse(source);encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets));bootstrap=base64.b64decode(encoded).decode('utf-16le').replace(secure.NONCE,NONCE).replace(oldsha,PARENT_SHA)
    support=inspect.getsource(_bound_terminal).replace('secure.validate_layout','validate_layout').replace('secure.validate_focus','validate_focus')+inspect.getsource(validate_semantic).replace("secure.validate_layout",'validate_layout').replace('secure.validate_focus','validate_focus')+inspect.getsource(parse_terminal)
    if hashlib.sha256(support.encode()).hexdigest()!=SUPPORT_SHA:raise ValueError('semantic-support-source')
    substitutions={'D='+repr(secure.CORRELATION):'D='+repr(CORRELATION),'NONCE='+repr(secure.NONCE):'NONCE='+repr(NONCE),'BODY_SHA='+repr(oldsha):'BODY_SHA='+repr(PARENT_SHA),'CHILD_SHA='+repr(oldchildsha):'CHILD_SHA='+repr(childsha),'ENCODED='+repr(encoded):'ENCODED='+repr(base64.b64encode(bootstrap.encode('utf-16le')).decode()),repr(oldinput):repr(newinput),'answer=secure_terminal(value,NONCE,BODY_SHA,pid)':support+'\nanswer=parse_terminal(value,NONCE,BODY_SHA,pid)'}
    # Functions must be top level, not injected at an indented callsite.
    substitutions.pop('answer=secure_terminal(value,NONCE,BODY_SHA,pid)')
    for old,new in substitutions.items():
        if source.count(old)!=1:raise ValueError('semantic-transport-factory')
        source=source.replace(old,new)
    marker=inspect.getsource(secure.secure_terminal)
    if source.count(marker)!=1:raise ValueError('semantic-parser-factory')
    source=source.replace(marker,marker.replace("validate_layout(answer['facts']);validate_focus(answer);return answer","semantic=answer['facts'].pop('secureInput',None);validate_layout(answer['facts']);validate_focus(answer);answer['facts']['secureInput']=semantic;return answer")+'\n'+support).replace('answer=secure_terminal(value,NONCE,BODY_SHA,pid)','answer=parse_terminal(value,NONCE,BODY_SHA,pid)')
    compile(source,'semantic-fixed-reader','exec');return source,PARENT_SHA


def observe(root):
    recovery=login.guest.recovery;ORIGINAL=login.guest.ORIGINAL;RECOVERY_SHA=login.guest.RECOVERY_SHA;SOCKET_PROOF_SHA=login.guest.SOCKET_PROOF_SHA;observation='secure-tuple'
    root=Path(root).resolve(strict=True);leaf='windows-cp117-secure-tuple-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'semantic-consumed','replayAllowed':False}
    root=Path(root).resolve(strict=True);original_capture=AuthorityCapture(root,'windows-cp117-recovery-'+recovery.CORRELATION)
    diagnostic=CORRELATION;nonce=NONCE
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);events=[]
    try:
        raw=recovery._local_read(original_capture,ORIGINAL['name'],ORIGINAL['pin']);record=json.loads(raw)
        def verify():
            if recovery._local_read(original_capture,ORIGINAL['name'],ORIGINAL['pin'])!=raw:raise ValueError('original-receipt')
            for i,item in enumerate(record['authority']):
                recovery._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(recovery._local_read(original_capture,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('original-frame')
            now=recovery.authority._source_pins(root);now['recovery']=recovery.authority._read_bound_file(Path(recovery.__file__))
            if now!=record['request']['sources']or now['recovery']['sha256']!=RECOVERY_SHA:raise ValueError('original-sources')
        verify();_factories();original_pin=recovery.authority._read_bound_file(Path(original_semantic.__file__));secure_pin=recovery.authority._read_bound_file(Path(secure.__file__));
        if secure_pin['sha256']!=SECURE_SHA:raise ValueError('semantic-secure-source')
        source_pin=recovery.authority._read_bound_file(Path(__file__));session_pin=None;login_pin=recovery.authority._read_bound_file(Path(login.__file__));guest_pin=recovery.authority._read_bound_file(Path(login.guest.__file__))
        if login_pin['sha256']!=LOGIN_SHA or guest_pin['sha256']!=login.GUEST_SHA:raise ValueError('secure-factory-source')
        if True:
            from . import windows_cp117_recovered_session_observe as session
            session_pin=recovery.authority._read_bound_file(Path(session.__file__))
            if session_pin['sha256']!=login.SESSION_SHA:raise ValueError('secure-session-source')
        outer=recovery.authority._outer_authority(root)
        source,sha=program(record)
        capture.create('request.json',json.dumps({'original':ORIGINAL,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'outerAuthority':outer,'helper':source_pin,'originalSemantic':original_pin,'keyboardAdmission':False,'observation':observation,'sessionHelper':session_pin,'socketProofSha256':SOCKET_PROOF_SHA},sort_keys=True).encode())
        capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=recovery.authority.closure.base._descriptor(root)
        argv=recovery.authority.closure.base.ssh_transport.build_ssh_argv(config,recovery.HOST,60,command=recovery.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        if recovery.authority._read_bound_file(Path(secure.__file__))!=secure_pin or recovery.authority._read_bound_file(Path(original_semantic.__file__))!=original_pin:raise ValueError('tuple-factory-source-drift')
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'nonce':NONCE,'original':ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        _factories();stream=login.guest._stream
        value,events=stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'])
        _factories()
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        if recovery.authority._read_bound_file(Path(secure.__file__))!=secure_pin or recovery.authority._read_bound_file(Path(original_semantic.__file__))!=original_pin:raise ValueError('tuple-factory-source-drift')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'secureObservation':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events)
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original_capture.close();capture.close()
