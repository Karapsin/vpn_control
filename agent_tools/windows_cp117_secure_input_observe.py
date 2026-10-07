"""Fixed read-only CP117 secure password-control semantics; never reads text.

Supports only a positively bound standard native password Edit. Unsupported
UIA providers or unavailable OS length remain unknown. No keyboard operations.
"""
import ast,base64,gzip,hashlib,inspect,json,os
from pathlib import Path
from . import windows_cp117_secure_layout_observe as secure
from .windows_diagnostic_authority_capture import AuthorityCapture
login=secure.login
LOGIN_SHA=secure.LOGIN_SHA
SECURE_SHA='bbcb1de84c89b44d7e541a35a2634ba0cf644e89f5cef7d9061e3a33e6499782'
CORRELATION='67150855-2e4f-436c-b8d8-9720b4d2a3c8'
NONCE='eb2a4c65-dccd-4ddf-9ea7-7ef7927dfce6'
NATIVE_SHA='edb0d54452f87501a8528b346874bbd3eab1bee45f27a7bd1a4c3e78b51e0544'
CHILD_SHA='0c152f3e671a61dc47ef47355a3ff5509e3c7471ae0153d967d5a74452c78b95'
PARENT_SHA='a93697d178a3fb79a731b8bc7cc721574f25d16068dd8a24fc46e2f6f98d6994'
FACTORY_SHA='b1fb87e5624b274f9643d096e74ecce7204014d0dab22d3a0355c2a129a0ba6e'
STREAM_SHA='94fbd47203ecd52c32611f89ce6244150d1d595de44cc3e2f3e2402d56ce43f4'
SUPPORT_SHA='d47789ac0d7c1e9a32169c886bef19b97fbf47bcf456070da0969c432cd2d1e3'

_SEMANTIC_CS=r'''using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Automation;
public static class CP117InputRead {
 [StructLayout(LayoutKind.Sequential)] struct Rect { public int left,top,right,bottom; }
 [StructLayout(LayoutKind.Sequential)] struct Gui { public uint size,flags;public IntPtr active,focus,capture,menu,move,caret;public Rect rect; }
 [DllImport("user32.dll",SetLastError=true)] static extern bool GetGUIThreadInfo(uint id,ref Gui gui);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);
 [DllImport("user32.dll")] static extern IntPtr GetKeyboardLayout(uint id);
 [DllImport("user32.dll")] static extern short GetKeyState(int key);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr w,StringBuilder s,int n);
 [DllImport("user32.dll",EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr w,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr w,uint m,UIntPtr p,IntPtr l,uint flags,uint timeout,out UIntPtr result);
 [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);
 [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
 [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int kind,StringBuilder name,uint size,out uint needed);
 static void Need(bool v,string code){if(!v)throw new InvalidOperationException(code);}
 static string ObjectName(IntPtr h){StringBuilder s=new StringBuilder(128);uint n;Need(h!=IntPtr.Zero&&GetUserObjectInformation(h,2,s,256,out n)&&n<=256,"SEMANTIC_DESKTOP");return s.ToString();}
 static bool Equal(int[] a,int[] b){if(a==null||b==null||a.Length==0||a.Length!=b.Length||a.Length>32)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 static IntPtr Focus(uint[] threads,out uint thread){IntPtr selected=IntPtr.Zero;thread=0;foreach(uint t in threads){Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(t,ref g))continue;if(g.focus==IntPtr.Zero)continue;uint owner;uint actual=GetWindowThreadProcessId(g.focus,out owner);Need(owner==1096&&actual==t&&GetKeyboardLayout(t).ToInt64().ToString("X16")=="0000000004090409","SEMANTIC_FOCUS_OWNER");Need(selected==IntPtr.Zero||selected==g.focus,"SEMANTIC_FOCUS_AMBIGUOUS");selected=g.focus;thread=t;}Need(selected!=IntPtr.Zero,"SEMANTIC_FOCUS_ABSENT");return selected;}
 static uint Length(IntPtr window){UIntPtr count;Need(SendMessageTimeout(window,0x000E,UIntPtr.Zero,IntPtr.Zero,3,500,out count)!=IntPtr.Zero,"SEMANTIC_LENGTH_UNAVAILABLE");ulong n=count.ToUInt64();Need(n<=64,"SEMANTIC_LENGTH_BOUND");return (uint)n;}
 public class Facts {public uint ownerPid,threadId;public string hkl,windowStation,desktop,controlType,controlName,className;public bool isPassword,keyboardFocus,enabled,offscreen,expectedAccount,capsLock,lengthAvailable,nativeHandleMatches;public int accountCount,editCount;public uint passwordLength;public long window;public int[] runtimeId;}
 public static Facts Read(uint[] threads){
  Need(ObjectName(GetProcessWindowStation())=="WinSta0"&&ObjectName(GetThreadDesktop(GetCurrentThreadId()))=="Winlogon","SEMANTIC_DESKTOP");
  uint thread;IntPtr hwnd=Focus(threads,out thread);AutomationElement e=AutomationElement.FocusedElement;Need(e!=null,"SEMANTIC_UIA_UNAVAILABLE");
  AutomationElement.AutomationElementInformation p=e.Current;Need(p.ProcessId==1096&&p.ControlType==ControlType.Edit&&p.IsPassword&&p.HasKeyboardFocus&&p.IsKeyboardFocusable&&p.IsEnabled&&!p.IsOffscreen&&p.Name=="Password","SEMANTIC_PASSWORD_CONTROL");
  Need(p.NativeWindowHandle!=0&&new IntPtr(p.NativeWindowHandle)==hwnd,"SEMANTIC_NATIVE_HANDLE_UNAVAILABLE");
  StringBuilder cn=new StringBuilder(128);Need(GetClassName(hwnd,cn,128)>0&&cn.ToString()=="Edit"&&(GetWindowLongPtr(hwnd,-16).ToInt64()&0x20)!=0,"SEMANTIC_STANDARD_PASSWORD_EDIT");
  AutomationElement native=AutomationElement.FromHandle(hwnd);Need(native!=null&&Equal(native.GetRuntimeId(),e.GetRuntimeId()),"SEMANTIC_UIA_NATIVE_IDENTITY");
  System.Windows.Rect b=p.BoundingRectangle;Need(b.X>=494&&b.Y>=443&&b.Right<=786&&b.Bottom<=478&&b.Width>0&&b.Height>0,"SEMANTIC_PASSWORD_GEOMETRY");
  AutomationElement container=e;bool found=false;int accountCount=0,editCount=0;
  for(int level=0;level<16;level++){
   container=TreeWalker.ControlViewWalker.GetParent(container);if(container==null)break;
   Need(container.Current.ProcessId==1096,"SEMANTIC_CONTAINER_OWNER");
   AutomationElementCollection labels=container.FindAll(TreeScope.Descendants,new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Text),new PropertyCondition(AutomationElement.NameProperty,"vpncp117")));
   Need(labels.Count<=16,"SEMANTIC_ACCOUNT_BOUND");accountCount=0;
   for(int i=0;i<labels.Count;i++){var v=labels[i].Current;System.Windows.Rect r=v.BoundingRectangle;if(v.ProcessId==1096&&v.IsEnabled&&!v.IsOffscreen&&r.X>=580&&r.Y>=381&&r.Right<=702&&r.Bottom<=412&&r.Width>0&&r.Height>0)accountCount++;}
   if(accountCount==0)continue;
   Need(accountCount==1,"SEMANTIC_ACCOUNT_AMBIGUOUS");
   var edits=container.FindAll(TreeScope.Descendants,new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Edit));Need(edits.Count<=16,"SEMANTIC_EDIT_BOUND");editCount=0;
   for(int i=0;i<edits.Count;i++){var v=edits[i].Current;if(v.ProcessId==1096&&v.IsPassword&&!v.IsOffscreen){editCount++;Need(Equal(edits[i].GetRuntimeId(),e.GetRuntimeId()),"SEMANTIC_FOREIGN_PASSWORD_EDIT");}}
   Need(editCount==1,"SEMANTIC_EDIT_AMBIGUOUS");found=true;break;
  }
  Need(found,"SEMANTIC_SELECTED_ACCOUNT_UNAVAILABLE");
  bool caps=(GetKeyState(0x14)&1)!=0;uint length=Length(hwnd);uint afterThread;Need(Focus(threads,out afterThread)==hwnd&&afterThread==thread&&Equal(AutomationElement.FocusedElement.GetRuntimeId(),e.GetRuntimeId())&&Length(hwnd)==length&&((GetKeyState(0x14)&1)!=0)==caps,"SEMANTIC_INPUT_DRIFT");
  var final=e.Current;Need(final.ProcessId==1096&&final.HasKeyboardFocus&&final.IsPassword&&final.IsEnabled&&!final.IsOffscreen&&final.ControlType==ControlType.Edit&&final.Name=="Password"&&new IntPtr(final.NativeWindowHandle)==hwnd,"SEMANTIC_UIA_DRIFT");
  return new Facts{ownerPid=1096,threadId=thread,hkl="0000000004090409",windowStation="WinSta0",desktop="Winlogon",controlType="Edit",controlName="Password",className="Edit",isPassword=true,keyboardFocus=true,enabled=true,offscreen=false,expectedAccount=true,capsLock=caps,lengthAvailable=true,nativeHandleMatches=true,accountCount=accountCount,editCount=editCount,passwordLength=length,window=hwnd.ToInt64(),runtimeId=e.GetRuntimeId()};
 }
}'''

_CHILD_FAILURE=r"""}catch{$e=$_.Exception.GetBaseException();$phase=$e.Message;if($phase -cnotmatch '^SEMANTIC_[A-Z_]{1,64}$'){$phase='SEMANTIC_UNCLASSIFIED'};$details=($_|Out-String);if($details.Length -gt 2048){$details=$details.Substring(0,2048)};WritePrivate 'failure.json' @{reader=$birth;phase=$phase;hresult=[int]$e.HResult;details=$details};$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');[IO.File]::SetAccessControl((Join-Path $dir 'failure.json'),$acl);exit 1}
"""


def validate_semantic(answer):
    base_answer=dict(answer);base_answer['facts']={k:v for k,v in answer['facts'].items()if k!='secureInput'}
    secure.validate_layout(base_answer['facts']);secure.validate_focus(base_answer)
    s=answer['facts'].get('secureInput')
    expected={'ownerPid':1096,'hkl':'0000000004090409','windowStation':'WinSta0','desktop':'Winlogon','controlType':'Edit','controlName':'Password','className':'Edit','isPassword':True,'keyboardFocus':True,'enabled':True,'offscreen':False,'expectedAccount':True,'capsLock':False,'lengthAvailable':True,'nativeHandleMatches':True,'accountCount':1,'editCount':1}
    if not isinstance(s,dict)or set(s)!=set(expected)|{'threadId','passwordLength','window','runtimeId'}:raise ValueError('semantic-schema')
    if any(type(s[k])is not type(v)or s[k]!=v for k,v in expected.items()):raise ValueError('semantic-input-owner-or-control')
    focused=[r['threadId']for r in answer['reader']['focus']if r['hasFocus']]
    if type(s['threadId'])is not int or s['threadId']not in focused or type(s['window'])is not int or s['window']<=0:raise ValueError('semantic-focused-identity')
    if type(s['passwordLength'])is not int or not 0<=s['passwordLength']<=64:raise ValueError('semantic-length-unavailable')
    rid=s['runtimeId']
    if not isinstance(rid,list)or not 1<=len(rid)<=32 or any(type(v)is not int or not -2147483648<=v<=2147483647 for v in rid):raise ValueError('semantic-runtime-identity')
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
 if((($failure.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'details,hresult,phase,reader' -or $failure.details -isnot [string] -or $failure.details.Length -gt 2048 -or $failure.hresult -isnot [int] -or $failure.phase -cnotmatch '^SEMANTIC_[A-Z_]{1,64}$'){throw 'SEMANTIC_FAILURE_SCHEMA'}
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
    recovery=login.guest.recovery;ORIGINAL=login.guest.ORIGINAL;RECOVERY_SHA=login.guest.RECOVERY_SHA;SOCKET_PROOF_SHA=login.guest.SOCKET_PROOF_SHA;observation='secure-input'
    root=Path(root).resolve(strict=True);leaf='windows-cp117-secure-input-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'semantic-consumed','replayAllowed':False}
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
        verify();_factories();secure_pin=recovery.authority._read_bound_file(Path(secure.__file__));
        if secure_pin['sha256']!=SECURE_SHA:raise ValueError('semantic-secure-source')
        source_pin=recovery.authority._read_bound_file(Path(__file__));session_pin=None;login_pin=recovery.authority._read_bound_file(Path(login.__file__));guest_pin=recovery.authority._read_bound_file(Path(login.guest.__file__))
        if login_pin['sha256']!=LOGIN_SHA or guest_pin['sha256']!=login.GUEST_SHA:raise ValueError('secure-factory-source')
        if True:
            from . import windows_cp117_recovered_session_observe as session
            session_pin=recovery.authority._read_bound_file(Path(session.__file__))
            if session_pin['sha256']!=login.SESSION_SHA:raise ValueError('secure-session-source')
        outer=recovery.authority._outer_authority(root)
        source,sha=program(record)
        capture.create('request.json',json.dumps({'original':ORIGINAL,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'outerAuthority':outer,'helper':source_pin,'observation':observation,'sessionHelper':session_pin,'socketProofSha256':SOCKET_PROOF_SHA},sort_keys=True).encode())
        capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=recovery.authority.closure.base._descriptor(root)
        argv=recovery.authority.closure.base.ssh_transport.build_ssh_argv(config,recovery.HOST,60,command=recovery.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        if recovery.authority._read_bound_file(Path(secure.__file__))!=secure_pin:raise ValueError('semantic-secure-source-drift')
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'nonce':NONCE,'original':ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        _factories();stream=login.guest._stream
        value,events=stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'])
        _factories()
        verify();recovery.authority._verify_outer(root,{'outerAuthority':outer})
        if recovery.authority._read_bound_file(Path(__file__))!=source_pin or recovery.authority._read_bound_file(Path(login.__file__))!=login_pin or recovery.authority._read_bound_file(Path(login.guest.__file__))!=guest_pin:raise ValueError('observer-source')
        if session_pin is not None and recovery.authority._read_bound_file(Path(session.__file__))!=session_pin:raise ValueError('session-source')
        if recovery.authority._read_bound_file(Path(secure.__file__))!=secure_pin:raise ValueError('semantic-secure-source-drift')
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'secureObservation':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'appAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events)
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()
