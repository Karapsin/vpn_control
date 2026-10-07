"""Fixed current secure-field provider observation and unconsumed login preparation.

Reports finite account predicates and provider capabilities; never reads Value or password length. Keyboard clear/type remains disabled pending a supported write-only provider route.
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
CORRELATION='8f9181ea-d94c-44c4-b9ce-50dcb5e06287'
NONCE='d1fda59c-47bf-402f-931d-b6c7dc3e88a3'
NATIVE_SHA='8a9701b709223573191f44dc4417ee50358bec5aacb471da493f5ccb7afa6cfb'
CHILD_SHA='afee661398d235c6a15d2dac957fc469cf4e21c3991e85b541c8e7524d0ae24e'
PARENT_SHA='143e2d9c6f64907e53038c771b7ba6bf30539f937a954515b7fcd68c3a622cc3'
FACTORY_SHA='b1fb87e5624b274f9643d096e74ecce7204014d0dab22d3a0355c2a129a0ba6e'
STREAM_SHA='94fbd47203ecd52c32611f89ce6244150d1d595de44cc3e2f3e2402d56ce43f4'
SUPPORT_SHA='4a7fbfbe7bf768317eb8f848328747747d4336522b6185daa91764357c99dd41'

_SEMANTIC_CS='using System;using System.Runtime.InteropServices;using System.Text;using System.Windows.Automation;public static class CP117InputRead{[StructLayout(LayoutKind.Sequential)] struct Rect{public int left,top,right,bottom;}[StructLayout(LayoutKind.Sequential)] struct Gui{public uint size,flags;public IntPtr active,focus,capture,menu,move,caret;public Rect rect;}[DllImport("user32.dll",SetLastError=true)] static extern bool GetGUIThreadInfo(uint id,ref Gui gui);[DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr w,out uint pid);[DllImport("user32.dll")] static extern IntPtr GetKeyboardLayout(uint id);[DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint id);[DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();[DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();[DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformation(IntPtr h,int kind,StringBuilder name,uint size,out uint needed);static void Need(bool v,string code){if(!v)throw new InvalidOperationException(code);}static string ObjectName(IntPtr h){StringBuilder s=new StringBuilder(128);uint n;Need(h!=IntPtr.Zero&&GetUserObjectInformation(h,2,s,256,out n)&&n<=256,"SEMANTIC_DESKTOP");return s.ToString();}static bool Equal(int[] a,int[] b){if(a==null||b==null||a.Length==0||a.Length!=b.Length||a.Length>32)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}static IntPtr Focus(uint[] threads,out uint thread){IntPtr selected=IntPtr.Zero;thread=0;foreach(uint t in threads){Gui g=new Gui();g.size=(uint)Marshal.SizeOf(typeof(Gui));if(!GetGUIThreadInfo(t,ref g))continue;if(g.focus==IntPtr.Zero)continue;uint owner;uint actual=GetWindowThreadProcessId(g.focus,out owner);Need(owner==1096&&actual==t&&GetKeyboardLayout(t).ToInt64().ToString("X16")=="0000000004090409","SEMANTIC_FOCUS_OWNER");Need(selected==IntPtr.Zero||selected==g.focus,"SEMANTIC_FOCUS_AMBIGUOUS");selected=g.focus;thread=t;}Need(selected!=IntPtr.Zero,"SEMANTIC_FOCUS_ABSENT");return selected;}public class NodeFacts{public int pid,controlId,nativeHandle,depth;public int[] runtimeId,parentId;public bool isEmpty,isPassword,keyboardFocus,keyboardFocusable,enabled,offscreen,passwordName,accountName;public double x,y,width,height;public NodeFacts Freeze(){var f=(NodeFacts)MemberwiseClone();f.runtimeId=(int[])runtimeId.Clone();f.parentId=parentId==null?null:(int[])parentId.Clone();return f;}}public interface INode{NodeFacts Capture();INode FirstChild();INode NextSibling();}static string Key(NodeFacts f){Need(f.runtimeId!=null&&f.runtimeId.Length>0&&f.runtimeId.Length<=32,"CENSUS_RUNTIME_BOUND");return string.Join(",",f.runtimeId);}static string Fingerprint(NodeFacts f){return string.Join(":",new object[]{Key(f),f.pid,f.controlId,f.nativeHandle,f.depth,f.isEmpty,BitConverter.DoubleToInt64Bits(f.x),BitConverter.DoubleToInt64Bits(f.y),BitConverter.DoubleToInt64Bits(f.width),BitConverter.DoubleToInt64Bits(f.height),f.isPassword,f.keyboardFocus,f.keyboardFocusable,f.enabled,f.offscreen,f.passwordName,f.accountName, f.parentId==null?"":string.Join(",",f.parentId)});}static void Visit(INode node,int depth,int[] parent,System.Collections.Generic.List<NodeFacts> rows,System.Collections.Generic.Dictionary<string,string> seen,ref int visits){Need(node!=null&&++visits<=128,"CENSUS_EDGE_BOUND");Need(depth<=8,"CENSUS_DEPTH_BOUND");NodeFacts source=node.Capture();Need(source!=null&&source.pid==1096,"CENSUS_FOREIGN_NODE");Key(source);source.parentId=parent;NodeFacts f=source.Freeze();string key=Key(f),fp=Fingerprint(f);string previous;if(seen.TryGetValue(key,out previous)){throw new InvalidOperationException("CENSUS_RUNTIME_DUPLICATE");}Need(rows.Count<64,"CENSUS_NODE_BOUND");seen.Add(key,fp);f.depth=depth;rows.Add(f);INode child=node.FirstChild();while(child!=null){Visit(child,depth+1,f.runtimeId,rows,seen,ref visits);child=child.NextSibling();}}public static NodeFacts[] Collect(INode root){var rows=new System.Collections.Generic.List<NodeFacts>();var seen=new System.Collections.Generic.Dictionary<string,string>();int visits=0;Visit(root,0,null,rows,seen,ref visits);return rows.ToArray();}public static NodeFacts[] Stable(INode root){var a=Collect(root);var b=Collect(root);Need(a.Length==b.Length,"CENSUS_TREE_DRIFT");for(int i=0;i<a.Length;i++)Need(a[i].depth==b[i].depth&&Fingerprint(a[i])==Fingerprint(b[i]),"CENSUS_TREE_DRIFT");return a;}class UiNode:INode{AutomationElement e;public UiNode(AutomationElement value){e=value;}public INode FirstChild(){var value=TreeWalker.RawViewWalker.GetFirstChild(e);return value==null?null:new UiNode(value);}public INode NextSibling(){var value=TreeWalker.RawViewWalker.GetNextSibling(e);return value==null?null:new UiNode(value);}public NodeFacts Capture(){var p=e.Current;Need(p.ProcessId==1096,"CENSUS_FOREIGN_NODE");var r=p.BoundingRectangle;if(p.NativeWindowHandle!=0){uint pid;GetWindowThreadProcessId(new IntPtr(p.NativeWindowHandle),out pid);Need(pid==1096,"CENSUS_NATIVE_OWNER");}bool l=(p.ControlType==ControlType.Text||p.ControlType==ControlType.Edit)&&p.Name=="Password";bool a=p.ControlType==ControlType.Text&&p.Name=="vpncp117";bool c=p.ControlType==ControlType.Edit||l||a;return new NodeFacts{isPassword=c&&p.IsPassword,keyboardFocus=c&&p.HasKeyboardFocus,keyboardFocusable=c&&p.IsKeyboardFocusable,enabled=c&&p.IsEnabled,offscreen=c&&p.IsOffscreen,accountName=a,passwordName=l,pid=p.ProcessId,controlId=p.ControlType==null?0:p.ControlType.Id,nativeHandle=p.NativeWindowHandle,runtimeId=e.GetRuntimeId(),isEmpty=r.IsEmpty,x=r.X,y=r.Y,width=r.Width,height=r.Height};}}public static NodeFacts[] Roles(NodeFacts[] rows){var edits=new System.Collections.Generic.List<NodeFacts>();foreach(var r in rows)if(r.controlId==50004)edits.Add(r);if(edits.Count==0)return new NodeFacts[0];NodeFacts field=null;foreach(var r in edits)if(r.keyboardFocus){Need(field==null,"ROLE_FOCUS_AMBIGUOUS");field=r;}Need(field!=null&&field.isPassword&&field.keyboardFocusable&&field.enabled&&!field.offscreen&&!field.isEmpty,"ROLE_PASSWORD_FOCUS");NodeFacts wrapper=null,pane=null,account=null,inner=null,label=null;foreach(var r in rows)if(Equal(r.runtimeId,field.parentId))wrapper=r;Need(wrapper!=null&&wrapper.controlId==50033,"ROLE_FIELD_PARENT");foreach(var r in rows)if(Equal(r.runtimeId,wrapper.parentId))pane=r;Need(pane!=null&&pane.controlId==50026,"ROLE_PANE_PARENT");foreach(var r in rows){if(r.controlId==50020&&r.accountName&&Equal(r.parentId,pane.runtimeId)){Need(account==null,"ROLE_ACCOUNT_AMBIGUOUS");account=r;}if(r.controlId==50004&&Equal(r.parentId,field.runtimeId)){Need(inner==null,"ROLE_INNER_AMBIGUOUS");inner=r;}if(r.controlId==50020&&r.passwordName&&Equal(r.parentId,field.runtimeId)&&!r.offscreen){Need(label==null,"ROLE_PLACEHOLDER_AMBIGUOUS");label=r;}}Need(account!=null&&account.enabled&&!account.offscreen&&!account.isEmpty&&inner!=null&&inner.isPassword&&inner.enabled&&!inner.offscreen,"ROLE_SELECTED_ACCOUNT");var found=new System.Collections.Generic.List<NodeFacts>();found.Add(pane);found.Add(account);found.Add(wrapper);found.Add(field);found.Add(inner);if(label!=null)found.Add(label);foreach(var r in found)Need(r.pid==1096&&!r.isEmpty&&!double.IsNaN(r.x)&&!double.IsInfinity(r.x)&&!double.IsNaN(r.y)&&!double.IsInfinity(r.y)&&!double.IsNaN(r.width)&&!double.IsInfinity(r.width)&&!double.IsNaN(r.height)&&!double.IsInfinity(r.height)&&Math.Abs(r.x)<=4096&&Math.Abs(r.y)<=4096&&r.width>0&&r.width<=4096&&r.height>0&&r.height<=4096,"ROLE_GEOMETRY");Need(field.x>=pane.x&&field.y>=pane.y&&field.x+field.width<=pane.x+pane.width&&field.y+field.height<=pane.y+pane.height,"ROLE_PANE_CONTAINMENT");return found.ToArray();}public interface IValueAccess{bool Supported();bool ReadOnly();}public static bool[] Capability(IValueAccess access){bool supported=access.Supported();return new bool[]{supported,supported&&access.ReadOnly()};}class UiValueAccess:IValueAccess{ValuePattern pattern;public UiValueAccess(AutomationElement edit){object value;if(edit.TryGetCurrentPattern(ValuePattern.Pattern,out value))pattern=value as ValuePattern;}public bool Supported(){return pattern!=null;}public bool ReadOnly(){Need(pattern!=null,"ROLE_VALUE_UNSUPPORTED");return pattern.Current.IsReadOnly;}}static bool[] CurrentCapability(NodeFacts[] rows){if(rows.Length==0)return new bool[]{false,false};AutomationElement edit=AutomationElement.FocusedElement;Need(edit!=null,"ROLE_VALUE_FOCUS");var p=edit.Current;Need(p.ProcessId==1096&&p.ControlType==ControlType.Edit&&p.IsPassword&&p.HasKeyboardFocus&&p.IsEnabled&&!p.IsOffscreen&&Equal(edit.GetRuntimeId(),rows[3].runtimeId),"ROLE_VALUE_FIELD");return Capability(new UiValueAccess(edit));}public class Facts{public uint threadId;public long focusWindow;public string hkl,windowStation,desktop;public int maxNodes,maxDepth;public bool keyboardAdmission,valuePatternSupported,valuePatternReadOnly;public NodeFacts[] nodes;}public static Facts Read(uint[] threads){Need(ObjectName(GetProcessWindowStation())=="WinSta0"&&ObjectName(GetThreadDesktop(GetCurrentThreadId()))=="Winlogon","SEMANTIC_DESKTOP");uint thread;IntPtr hwnd=Focus(threads,out thread);Need(hwnd.ToInt64()==65626,"CENSUS_ROOT_HANDLE");var root=AutomationElement.FromHandle(hwnd);Need(root!=null,"CENSUS_ROOT_UNAVAILABLE");var p=root.Current;Need(p.ProcessId==1096&&p.ControlType==ControlType.Window&&p.NativeWindowHandle==65626,"CENSUS_ROOT_OWNER");var rows=Roles(Stable(new UiNode(root)));var value=CurrentCapability(rows);uint afterThread;Need(Focus(threads,out afterThread)==hwnd&&afterThread==thread,"CENSUS_FOCUS_DRIFT");var afterValue=CurrentCapability(rows);Need(value[0]==afterValue[0]&&value[1]==afterValue[1],"ROLE_VALUE_DRIFT");return new Facts{threadId=thread,focusWindow=65626,hkl="0000000004090409",windowStation="WinSta0",desktop="Winlogon",maxNodes=64,maxDepth=8,keyboardAdmission=false,valuePatternSupported=value[0],valuePatternReadOnly=value[1],nodes=rows};}}'

_CHILD_FAILURE="}catch{$e=$_.Exception.GetBaseException();$p=$e.Message;if($p -cnotmatch '^(SEMANTIC|CENSUS|ROLE)_[A-Z_]{1,64}$'){$p='CENSUS_OTHER'};$d=($_|Out-String);if($d.Length -gt 2048){$d=$d.Substring(0,2048)};WritePrivate 'failure.json' @{reader=$birth;phase=$p;hresult=[int]$e.HResult;details=$d};$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)');[IO.File]::SetAccessControl((Join-Path $dir 'failure.json'),$acl);exit 1}\n"


def validate_semantic(answer):
    base_answer=dict(answer);base_answer['facts']={k:v for k,v in answer['facts'].items()if k!='secureInput'}
    secure.validate_layout(base_answer['facts']);secure.validate_focus(base_answer)
    s=answer['facts'].get('secureInput')
    if not isinstance(s,dict)or set(s)!={'threadId','focusWindow','hkl','windowStation','desktop','maxNodes','maxDepth','keyboardAdmission','valuePatternSupported','valuePatternReadOnly','nodes'}or s['keyboardAdmission']is not False or any(type(s[k])is not bool for k in('valuePatternSupported','valuePatternReadOnly')) or s['maxNodes']!=64 or s['maxDepth']!=8:raise ValueError('role-schema')
    focused=[r['threadId']for r in answer['reader']['focus']if r['hasFocus']]
    if type(s['threadId'])is not int or s['threadId']not in focused or s['focusWindow']!=65626 or s['hkl']!='0000000004090409' or s['windowStation']!='WinSta0' or s['desktop']!='Winlogon':raise ValueError('role-current-root')
    nodes=s['nodes'];seen=set()
    if not isinstance(nodes,list)or len(nodes)not in(0,5,6):raise ValueError('role-count')
    for n in nodes:
        flags=('isEmpty','isPassword','keyboardFocus','keyboardFocusable','enabled','offscreen','passwordName','accountName')
        if not isinstance(n,dict)or set(n)!={'pid','controlId','nativeHandle','depth','runtimeId','parentId','x','y','width','height'}|set(flags)or any(type(n[k])is not bool for k in flags):raise ValueError('role-node-schema')
        if n['pid']!=1096 or type(n['depth'])is not int or not 0<=n['depth']<=8 or n['isEmpty']or any(type(n[k])not in(int,float)or not -4096<=n[k]<=4096 for k in('x','y'))or any(type(n[k])not in(int,float)or not 0<n[k]<=4096 for k in('width','height')):raise ValueError('role-node-owner-geometry')
        for k in('runtimeId','parentId'):
            r=n[k]
            if not isinstance(r,list)or not 1<=len(r)<=32 or any(type(v)is not int or not -2147483648<=v<=2147483647 for v in r):raise ValueError('role-runtime')
        if tuple(n['runtimeId'])in seen:raise ValueError('role-duplicate')
        seen.add(tuple(n['runtimeId']))
    if not nodes:return s
    pane,account,wrapper,field,inner=nodes[:5]
    if [n['controlId']for n in nodes[:5]]!=[50026,50020,50033,50004,50004]or account['accountName']is not True or account['parentId']!=pane['runtimeId']or wrapper['parentId']!=pane['runtimeId']or field['parentId']!=wrapper['runtimeId']or inner['parentId']!=field['runtimeId']:raise ValueError('role-selected-account-lineage')
    if not all(field[k]for k in('isPassword','keyboardFocus','keyboardFocusable','enabled'))or field['offscreen']or not inner['isPassword']or not inner['enabled']or inner['offscreen']or not account['enabled']or account['offscreen']:raise ValueError('role-current-password-focus')
    if len(nodes)==6:
        label=nodes[5]
        if label['controlId']!=50020 or label['parentId']!=field['runtimeId']or not label['passwordName']or label['offscreen']or not label['enabled']:raise ValueError('role-placeholder-lineage')
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
    insertion+="$m=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GZipStream]::new($m,[IO.Compression.CompressionMode]0);$cb=[byte[]]::new(16385);$o=0;try{while($o -lt 16385){$n=$z.Read($cb,$o,16385-$o);if($n -eq 0){break};$o+=$n}}finally{$z.Dispose();$m.Dispose()};if($o -ne "+str(len(_SEMANTIC_CS.encode()))+"){throw 'CENSUS_CS_BOUND'};$c=[Text.Encoding]::UTF8.GetString($cb,0,$o);$ch=[Security.Cryptography.SHA256]::Create();try{$ca=([BitConverter]::ToString($ch.ComputeHash($cb,0,$o))).Replace('-','').ToLowerInvariant()}finally{$ch.Dispose()};if($ca -cne '"+NATIVE_SHA+"'){throw 'CENSUS_CS_HASH'}\n"
    insertion+=" Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll',[Windows.Automation.AutomationElement].Assembly.Location,[Windows.Automation.ControlType].Assembly.Location,[Windows.Rect].Assembly.Location) -TypeDefinition $c\n $cf=[CP117InputRead]::Read([uint32[]]$ids)\n"

    child=child.replace(marker,insertion+marker).replace('processes=$rows;layout=$layout};WritePrivate','processes=$rows;layout=$layout;secureInput=$cf};WritePrivate')
    oldcatch="}catch{[Console]::Out.WriteLine('{\"version\":1,\"code\":\"UNKNOWN\"}');exit 1}\n"
    if child.count(oldcatch)!=1:raise ValueError('semantic-child-failure-factory')
    child=child.replace(oldcatch,_CHILD_FAILURE)
    # Fixed generated PS/C# has no indentation-sensitive text payload.
    child='\n'.join(line.lstrip(' ')for line in child.splitlines())+'\n'
    plain=child.encode();packed=base64.b64encode(gzip.compress(plain,mtime=0)).decode()
    if not 0<len(plain)<=16384:raise ValueError('role-full-body-bound')
    child="$vp=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$vq=[IO.Compression.GZipStream]::new($vp,[IO.Compression.CompressionMode]0);$vr=[byte[]]::new(16385);$vs=0;try{while($vs -lt 16385){$vt=$vq.Read($vr,$vs,16385-$vs);if($vt -eq 0){break};$vs+=$vt}}finally{$vq.Dispose();$vp.Dispose()};if($vs -ne "+str(len(plain))+" ){throw 'ROLE_FULL_BODY_BOUND'};$vu=[Security.Cryptography.SHA256]::Create();try{$vv=([BitConverter]::ToString($vu.ComputeHash($vr,0,$vs))).Replace('-','').ToLowerInvariant()}finally{$vu.Dispose()};if($vv -cne '"+hashlib.sha256(plain).hexdigest()+"'){throw 'ROLE_FULL_BODY_HASH'};&([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($vr,0,$vs)))\n"
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
 if((($failure.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'details,hresult,phase,reader' -or $failure.details -isnot [string] -or $failure.details.Length -gt 2048 -or $failure.hresult -isnot [int] -or $failure.phase -cnotmatch '^(SEMANTIC|CENSUS|ROLE)_[A-Z_]{1,64}$'){throw 'SEMANTIC_FAILURE_SCHEMA'}
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


from . import windows_cp117_recovered_gui_login as legacy
from . import windows_cp117_recovered_owner_observe as owner

LEGACY_SHA='7d4a73a2ee267a1a4ac6d9468b63f244af5a158104060bdd3c1a2a4b3d7160f8'
def _us_keys(secret):
    """Validate the entire private input before any key effect; never log it."""
    if not isinstance(secret,bytes)or not 1<=len(secret)<=64:raise ValueError('gui-private-input-bound')
    try:text=secret.decode('ascii')
    except UnicodeError:raise ValueError('gui-private-input-alphabet')from None
    plain={' ':'spc','-':'minus','=':'equal','[':'bracket_left',']':'bracket_right',';':'semicolon',"'":'apostrophe',',':'comma','.':'dot','/':'slash','\\':'backslash','`':'grave_accent'}
    shifted=dict(zip('!@#$%^&*()_+{}:"<>?|~','1234567890-=[];\',./\\`'))
    result=[]
    for c in text:
        shift=False
        if 'a'<=c<='z'or '0'<=c<='9':key=c
        elif 'A'<=c<='Z':key=c.lower();shift=True
        elif c in plain:key=plain[c]
        elif c in shifted:
            unshifted=shifted[c];key=plain.get(unshifted,unshifted);shift=True
        else:raise ValueError('gui-private-input-alphabet')
        result.append((['shift']if shift else [])+[key])
    return result

def _field_identity(answer):
    state=validate_semantic(answer)
    if not state['nodes']or not state['valuePatternSupported']or state['valuePatternReadOnly']:raise ValueError('gui-current-field-or-value-pattern')
    pane,account,wrapper,field,inner=state['nodes'][:5]
    return {'pane':pane['runtimeId'],'account':account['runtimeId'],'wrapper':wrapper['runtimeId'],'field':field['runtimeId'],'inner':inner['runtimeId'],'rectangle':[field[k]for k in('x','y','width','height')]}

def _effect_gate(answer,focus_age,raw,screen_age,mode):
    if type(focus_age)not in(int,float)or not 0<=focus_age<=5 or type(screen_age)not in(int,float)or not 0<=screen_age<=5:raise ValueError('gui-current-proof-expired')
    state=validate_semantic(answer)
    if login.validate_ppm(raw)!=(1280,800):raise ValueError('gui-frame-dimensions')
    if mode=='clock':
        if state['nodes']:raise ValueError('gui-clock-has-edit')
        login._validate_lockscreen(raw);return None
    identity=_field_identity(answer)
    if mode not in('field','empty','filled'):raise ValueError('gui-fixed-field-mode')
    placeholder=len(state['nodes'])==6
    if mode=='empty'and not placeholder or mode=='filled'and placeholder:raise ValueError('gui-placeholder-state')
    return identity

def _validate_prior(prior,phase):
    if phase not in('typing','enter')or not isinstance(prior,dict)or set(prior)!={'identity','pins','frames'}:raise ValueError('gui-prior-schema')
    identity=prior['identity']
    if not isinstance(identity,dict)or set(identity)!={'st_dev','st_ino','st_mode','st_uid','st_gid'}or any(type(v)is not int for v in identity.values())or identity['st_dev']<=0 or identity['st_ino']<=0 or identity['st_mode']!=16832:raise ValueError('gui-prior-directory')
    frames={'clear-before.ppm','clear-after.ppm'};records={n+'.json'for n in frames}|{'clear-attempt.json','cleared.json'}
    if phase=='enter':
        frames|={'typing-before.ppm','typing-after.ppm'};records|={'typing-before.ppm.json','typing-after.ppm.json','typing-attempt.json','typed.json'}
    if not isinstance(prior['pins'],dict)or set(prior['pins'])!=records or not isinstance(prior['frames'],dict)or set(prior['frames'])!=frames:raise ValueError('gui-prior-fixed-leaves')
    for pin in list(prior['pins'].values())+list(prior['frames'].values()):
        if not isinstance(pin,dict)or set(pin)!={'fingerprint','sha256'}or not isinstance(pin['fingerprint'],dict)or set(pin['fingerprint'])!={'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'}or any(type(v)is not int for v in pin['fingerprint'].values()):raise ValueError('gui-prior-full-generation')
        f=pin['fingerprint']
        if f['st_dev']<=0 or f['st_ino']<=0 or f['st_mode']!=33152 or f['st_uid']!=identity['st_uid']or f['st_gid']!=identity['st_gid']or f['st_nlink']!=1 or f['st_size']<=0 or f['st_mtime_ns']<=0 or f['st_ctime_ns']<=0 or not isinstance(pin['sha256'],str)or len(pin['sha256'])!=64 or any(c not in'0123456789abcdef'for c in pin['sha256']):raise ValueError('gui-prior-private-generation')
    return prior


def _remote_input_action(answer,focus_started,phase,keys,prior):
    """Generated fixed host-side action; never emits the private key sequence."""
    if phase in('clear','typing'):raise ValueError('gui-keyboard-password-disabled')
    import socket,stat,struct
    need(phase in('prepare','clear','typing','enter'),'gui-fixed-phase')
    if phase in('typing','enter'):_validate_prior(prior,phase)
    parent=TRANSFER;name='cp117-windowless-gui-'+FLOW+('-prepare'if phase=='prepare'else'')
    pf=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);pi=os.fstat(pf)
    need(stat.S_ISDIR(pi.st_mode)and pi.st_uid==os.geteuid()and stat.S_IMODE(pi.st_mode)==0o700,'gui-parent')
    need(fp(pi)==fp(os.lstat(parent)),'gui-parent-name')
    if phase in('prepare','clear'):os.mkdir(name,0o700,dir_fd=pf);os.fsync(pf)
    directory=parent+'/'+name;jf=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=pf);ji=os.fstat(jf)
    identity={k:getattr(ji,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')}
    need(stat.S_ISDIR(ji.st_mode)and ji.st_uid==os.geteuid()and stat.S_IMODE(ji.st_mode)==0o700,'gui-directory')
    pins={};frames={}
    def guard():
        guards()
        for held,named,pinned in((os.fstat(pf),os.lstat(parent),{k:getattr(pi,k)for k in identity}),(os.fstat(jf),os.stat(name,dir_fd=pf,follow_symlinks=False),identity)):
            need(all(getattr(held,k)==getattr(named,k)==v for k,v in pinned.items()),'gui-directory-drift')
        for leaf,pin in pins.items():read_pin(leaf,pin)
        for leaf,pin in frames.items():read_frame_pin(leaf,pin)
        # Recheck held/named ancestry after the last protected authority read.
        for held,named,pinned in((os.fstat(pf),os.lstat(parent),{k:getattr(pi,k)for k in identity}),(os.fstat(jf),os.stat(name,dir_fd=pf,follow_symlinks=False),identity)):
            need(all(getattr(held,k)==getattr(named,k)==v for k,v in pinned.items()),'gui-directory-drift')
        guards()
    def read_frame_pin(leaf,pin):
        f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
        try:
            s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=16777216 and fp(s)==pin['fingerprint'],'gui-frame-pin');raw=os.read(f,16777217)
            need(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==pin['sha256']and fp(s)==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-frame-pin')
        finally:os.close(f)
    def read_pin(leaf,pin):
        f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
        try:
            s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=32768,'gui-record-shape');raw=os.read(f,32769)
            need(fp(s)==pin['fingerprint']==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False))and hashlib.sha256(raw).hexdigest()==pin['sha256'],'gui-record-pin');return json.loads(raw)
        finally:os.close(f)
    def create(leaf,value):
        guard();raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();need(0<len(raw)<=32768,'gui-record-cap')
        f=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jf)
        try:
            need(os.write(f,raw)==len(raw),'gui-record-write');os.fsync(f);s=os.fstat(f);need(stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and fp(s)==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-record-name');pin={'fingerprint':fp(s),'sha256':hashlib.sha256(raw).hexdigest()};os.fsync(jf)
        finally:os.close(f)
        pins[leaf]=pin;guard();return pin
    c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(5);stream=None;serial=0
    try:
        if phase in('typing','enter'):
            need(isinstance(prior,dict)and set(prior)=={'identity','pins','frames'}and prior['identity']==identity,'gui-original-typed-authority')
            pins.update(prior['pins']);frames.update(prior['frames']);guard()
            previous='cleared'if phase=='typing'else'typed';bound=read_pin(previous+'.json',pins[previous+'.json']);need(bound=={'state':previous,'flow':FLOW,'qemu':children[1]['child'],'field':_field_identity(answer)},'gui-original-field-record')
        guard();c.connect(LEAF+'/qmp.sock');peer=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(peer[0]==children[1]['child']['pid']and peer[1]==os.geteuid(),'gui-qmp-peer');guard();stream=c.makefile('rb')
        def response(wanted):
            for _ in range(16):
                raw=stream.readline(32769);need(0<len(raw)<=32768 and raw.endswith(b'\n'),'gui-qmp-cap');v=json.loads(raw)
                if wanted is None:need('QMP'in v,'gui-qmp-greeting');return
                if v.get('id')==wanted:need('return'in v and 'error'not in v,'gui-qmp-response');return
                need('event'in v,'gui-qmp-id')
            raise ValueError('gui-qmp-event-cap')
        def command(kind,args=None):
            nonlocal serial
            guard();serial+=1;packet={'execute':kind,'id':serial}
            if args is not None:packet['arguments']=args
            c.sendall(json.dumps(packet,separators=(',',':')).encode()+b'\n');response(serial);guard()
        response(None);command('qmp_capabilities')
        def capture(leaf):
            guard();need(not os.path.lexists(directory+'/'+leaf),'gui-frame-existing');command('screendump',{'filename':directory+'/'+leaf});sampled=time.monotonic()
            f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
            try:
                s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and 0<s.st_size<=16777216,'gui-frame-shape');os.fchmod(f,0o600);s=os.fstat(f);raw=os.read(f,16777217)
                need(len(raw)==s.st_size and fp(s)==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-frame-drift');validate_ppm(raw);os.fsync(f);os.fsync(jf);frames[leaf]={'fingerprint':fp(s),'sha256':hashlib.sha256(raw).hexdigest()};create(leaf+'.json',frames[leaf]);guard();return raw,sampled
            finally:os.close(f)
        before,sampled=capture(phase+'-before.ppm')
        mode='clock'if phase=='prepare'and not answer['facts']['secureInput']['nodes']else'field'if phase in('prepare','clear')else'empty'if phase=='typing'else'filled'
        field_identity=_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,mode)
        def fence():return create(phase+'-attempt.json',{'state':'consumed','flow':FLOW,'phase':phase,'qemu':children[1]['child'],'nonce':NONCE,'sourceSha256':BODY_SHA})
        if phase=='prepare':
            if mode=='clock':
                def current():guard();_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,'clock')
                def key():current();command('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100})
                def post():time.sleep(.75);return capture('prepare-after.ppm')
                after,post_at=_guarded_wake(before,time.monotonic()-sampled,current,fence,key,post)
            else:after,post_at=before,sampled
            state='prepared'
        else:
            fence();_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,mode);guard()
            if phase=='clear':
                for chord in (['ctrl','a'],['backspace']):
                    _effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,'field');command('send-key',{'keys':[{'type':'qcode','data':key}for key in chord],'hold-time':100});time.sleep(.15)
                after,post_at=capture('clear-after.ppm');create('cleared.json',{'state':'cleared','flow':FLOW,'qemu':children[1]['child'],'field':field_identity});state='cleared'
            elif phase=='typing':
                need(isinstance(keys,list)and 1<=len(keys)<=64,'gui-input-count')
                for chord in keys:
                    _effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,'empty');command('send-key',{'keys':[{'type':'qcode','data':key}for key in chord],'hold-time':20});time.sleep(.025)
                keys.clear();after,post_at=capture('typing-after.ppm');create('typed.json',{'state':'typed','flow':FLOW,'qemu':children[1]['child'],'field':field_identity});state='typed'
            else:
                _effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,'filled');command('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100});time.sleep(.75);after,post_at=capture('enter-after.ppm');state='entered'
        guard()
        return {'state':'observed','phase':state,'qemu':children[1]['child'],'guestChildPid':pid,'hostAuthority':{'identity':identity,'pins':pins,'frames':frames},'frameSha256':hashlib.sha256(after).hexdigest(),'frameAuthority':{'identity':identity,'pins':pins,'frames':frames},'appAdmission':False,'installerAction':False,'replayAllowed':False}
    except Exception as e:
        e.frameAuthority={'identity':identity,'frames':frames,'pins':pins};raise
    finally:
        if stream is not None:stream.close()
        c.close();os.close(jf);os.close(pf)

def _stream(argv,capture,diagnostic,nonce,sha,qemu,secret):
    import selectors,subprocess
    r=login.guest.recovery
    if not isinstance(secret,bytes)or len(secret)>512:raise ValueError('gui-private-input-bound')
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();events=[];child=None;deadline=time.monotonic()+60
    selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
    try:
        process.stdin.write(len(secret).to_bytes(4,'big')+secret);process.stdin.flush();secret=b''
        while selector.get_map():
            if time.monotonic()>=deadline:raise ValueError('gui-observer-deadline')
            for key,_ in selector.select(.25):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(data)
                if len(chunks[key.data])>262144:raise ValueError('gui-observer-byte-cap')
                if key.data=='stderr':
                    pending.extend(data)
                    while b'\n'in pending:
                        line,rest=pending.split(b'\n',1);pending=bytearray(rest)
                        if not line.startswith(b'CP117-OBSERVE '):continue
                        event=json.loads(line[14:])
                        if any(event.get(k)!=v for k,v in{'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'qemu':qemu}.items()):raise ValueError('gui-event-binding')
                        if event['kind']=='submitted':
                            if child is not None or type(event.get('pid'))is not int or event['pid']<=0:raise ValueError('gui-one-child')
                            child=event['pid']
                        elif event['kind']in('poll','terminal'):
                            if child is None or event.get('pid')!=child:raise ValueError('gui-same-child')
                        elif event['kind']!='exception':raise ValueError('gui-event-kind')
                        pin=capture.create(diagnostic+'-event-%d.json'%len(events),json.dumps(event,sort_keys=True).encode());os.fsync(capture.fd);events.append({'event':event,'pin':pin})
                        if event['kind']=='submitted':
                            ack=r._digest({'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'pid':child});process.stdin.write((ack+'\n').encode());process.stdin.flush()
        if process.wait(timeout=max(.001,deadline-time.monotonic()))!=0:raise ValueError('gui-observer-exit')
        value=json.loads(chunks['stdout']);return value,events
    except BaseException as e:
        e.events=events
        if process.poll()is None:process.kill()  # Only this local observer, never VM/app.
        process.wait(timeout=3);raise
    finally:
        capture.create(diagnostic+'-transport.stdout.private',bytes(chunks['stdout']));capture.create(diagnostic+'-transport.stderr.private',bytes(chunks['stderr']));os.fsync(capture.fd)
        selector.close();process.stdin.close();process.stdout.close();process.stderr.close()


_PHASES={
 'prepare':('36ee07d9-781b-4229-a2e2-9a1c2c21f290','703f73d8-c8a5-4faa-8fe1-3fd676d94ee1'),
 'clear':('c5f4810c-c47a-4b7d-8715-a6e54fcb5ef7','d48e32a5-8bda-46ec-b919-aa417fe6d559'),
 'typing':('72bacb7d-2b99-4c6f-9e04-96fb8dc54aed','3ec3a1b7-1cb9-42b6-9bd1-81c1e02d5bd9'),
 'enter':('ba2c62a2-9751-4856-9be5-f416722a5f88','cd4a924f-93f4-43a9-b2df-a6111e7eefbe')}
_READ_SHA={'prepare': ('9db5572793ab2517dee25b766b1276837db67a17d298a88ca780e682999aa6e8', 'b3304f0132aee1933ea60e39bb229d6fae79e86b6e942381650f9a09f928ff2d'), 'clear': ('0ac3356f1d2fbb0b4ecd68cefd438c0ff27b40e376f3e90d0f61cc4c2819e2a7', '43faca465daedf6e7ba005b2ffe345e80e3f64e060e4ddd621526b7f1b130e29'), 'typing': ('459497ced3b87f1b74e5c137fe8e8d3b6fb2bd036146030aec1b89a022e76c3b', '3a20247178ed86dbf7f7de4a6afb9d66edea19786a674b63840b5c3ef03c190b'), 'enter': ('7c2d289339187a01c738999e46d0c6fe7fd28b3e1fd2063d26e84f9158dca6e7', 'fe9baaf7d42fb2d3dd7dcfe449caa3fdefa649567204b92ae99818465aa828c8')}
AUTH_CORRELATION='78e5fa8f-cc0b-4c34-a2e0-005f15ad1826'
AUTH_NONCE='81ea1cbb-7a9f-494f-a3c3-e2c9e499a0d5'
OWNER_CORRELATION='11c50589-b332-4708-97ad-e0e42ec67215'
OWNER_NONCE='469401fa-1b09-48f1-a730-9f60107339b1'

def _role_reader(record,phase):
    if phase not in _PHASES:raise ValueError('gui-fixed-phase')
    correlation,nonce=_PHASES[phase];expected_parent,expected_child=_READ_SHA[phase]
    namespace=dict(globals());namespace.update(CORRELATION=correlation,NONCE=nonce,PARENT_SHA=expected_parent,CHILD_SHA=expected_child)
    exec(compile(inspect.getsource(bodies),'fixed-role-bodies','exec'),namespace)
    parent,child,sha=namespace['bodies']()
    source,oldsha=program(record);oldparent,oldchild,oldchildsha=bodies()
    tree=ast.parse(source);encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    bootstrap=base64.b64decode(encoded).decode('utf-16le').replace(NONCE,nonce).replace(PARENT_SHA,expected_parent)
    oldinput=base64.b64encode(len(oldparent.encode()).to_bytes(4,'big')+oldparent.encode()).decode();newinput=base64.b64encode(len(parent.encode()).to_bytes(4,'big')+parent.encode()).decode()
    replacements={'D='+repr(CORRELATION):'D='+repr(correlation),'NONCE='+repr(NONCE):'NONCE='+repr(nonce),'BODY_SHA='+repr(PARENT_SHA):'BODY_SHA='+repr(expected_parent),'CHILD_SHA='+repr(CHILD_SHA):'CHILD_SHA='+repr(expected_child),'ENCODED='+repr(encoded):'ENCODED='+repr(base64.b64encode(bootstrap.encode('utf-16le')).decode()),repr(oldinput):repr(newinput)}
    for old,new in replacements.items():
        if source.count(old)!=1:raise ValueError('gui-role-phase-factory')
        source=source.replace(old,new)
    compile(source,'fixed-role-phase','exec');return source,expected_parent,expected_child

def _phase_program(record,phase,prior=None):
    if phase not in _PHASES or(phase in('prepare','clear')and prior is not None)or(phase in('typing','enter')and not isinstance(prior,dict)):raise ValueError('gui-phase-authority')
    if phase in('typing','enter'):_validate_prior(prior,phase)
    source,sha,childsha=_role_reader(record,phase)
    support='FLOW='+repr(CORRELATION)+'\nTRANSFER='+repr(login.TRANSFER)+'\n'+inspect.getsource(login.validate_ppm)+inspect.getsource(login._validate_lockscreen)+inspect.getsource(login._guarded_wake)+inspect.getsource(_us_keys)+inspect.getsource(_field_identity)+inspect.getsource(_effect_gate).replace('login.validate_ppm','validate_ppm').replace('login._validate_lockscreen','_validate_lockscreen')+inspect.getsource(_validate_prior)+inspect.getsource(_remote_input_action)
    marker='\ntry:\n children='
    if source.count(marker)!=1:raise ValueError('gui-phase-compose')
    source=source.replace(marker,'\n'+support+marker)
    launch=" guards();child=call(LEAF+'/qga.sock','guest-exec',"
    prefix=" guards();nraw=sys.stdin.buffer.read(4);need(len(nraw)==4,'gui-input-header');n=int.from_bytes(nraw,'big');need("+('1<=n<=64'if phase=='typing'else'n==0')+",'gui-input-bound');private_input=sys.stdin.buffer.read(n);need(len(private_input)==n,'gui-input-short');keys="+('_us_keys(private_input)'if phase=='typing'else'[]')+";private_input=b'';focus_started=time.monotonic();child=call(LEAF+'/qga.sock','guest-exec',"
    if source.count(launch)!=1:raise ValueError('gui-phase-launch')
    source=source.replace(launch,prefix)
    terminal=" result({'state':'observed','facts':answer,'qemu':children[1]['child'],'guestChildPid':pid,'appAdmission':False,'installerAction':False})"
    if source.count(terminal)!=1:raise ValueError('gui-phase-terminal')
    source=source.replace(terminal," result(_remote_input_action(answer,focus_started,"+repr(phase)+",keys,"+repr(prior)+"))")
    failure="'installerAction':False,'replayAllowed':False})"
    if source.count(failure)!=1:raise ValueError('gui-phase-failure')
    source=source.replace(failure,"'installerAction':False,'replayAllowed':False,'frameAuthority':getattr(e,'frameAuthority',None)})")
    compile(source,'fixed-gui-role-action','exec');return source,sha,childsha

def _auth_program(root,record):
    if hashlib.sha256(Path(login.__file__).read_bytes()).hexdigest()!=LOGIN_SHA:raise ValueError('gui-auth-factory')
    source,oldsha,pins=login.credential_program(root,record,AUTH_NONCE);body,_=login._fixed_bootstrap(root)
    newbody=body.replace(login.CREDENTIAL_CORRELATION,AUTH_CORRELATION);newsha=hashlib.sha256(newbody.encode('utf-16le')).hexdigest()
    oldheader="[Console]::Out.WriteLine(('CP117-READ "+AUTH_NONCE+" "+oldsha+" '+$PID))\n";newheader=oldheader.replace(oldsha,newsha)
    oldencoded=base64.b64encode((oldheader+body).encode('utf-16le')).decode();newencoded=base64.b64encode((newheader+newbody).encode('utf-16le')).decode()
    if len(newencoded)>=30000 or source.count(repr(oldencoded))!=1 or source.count('BODY_SHA='+repr(oldsha))!=1:raise ValueError('gui-auth-fixed-command')
    source=source.replace(repr(oldencoded),repr(newencoded)).replace('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(newsha)).replace(login.CREDENTIAL_CORRELATION,AUTH_CORRELATION)
    compile(source,'fixed-new-credential-validation','exec');return source,newsha,pins

def _owner_program(record):
    source,sha=owner.program(record);body=owner.body()
    oldheader="[Console]::Out.WriteLine(('CP117-READ "+owner.NONCE+" "+sha+" '+$PID))\n";newheader=oldheader.replace(owner.NONCE,OWNER_NONCE)
    oldencoded=base64.b64encode((oldheader+body).encode('utf-16le')).decode();newencoded=base64.b64encode((newheader+body).encode('utf-16le')).decode()
    if source.count(repr(oldencoded))!=1:raise ValueError('gui-owner-fixed-command')
    source=source.replace(repr(oldencoded),repr(newencoded)).replace(owner.CORRELATION,OWNER_CORRELATION).replace(owner.NONCE,OWNER_NONCE)
    compile(source,'fixed-new-ordinary-owner','exec');return source,sha

def _sequence(run,save):
    auth=run('auth',None);save('auth',auth)
    credential=auth.get('credential')
    if auth.get('state')!='observed'or not isinstance(credential,dict)or credential.get('success')is not True or credential.get('expectedSid')!=login.guest.SID or credential.get('correlationId')!=AUTH_CORRELATION or credential.get('errorCategory')!='none':raise ValueError('gui-fresh-auth-refused')
    prepared=run('prepare',None);save('prepare',prepared)
    if prepared.get('state')!='observed'or prepared.get('phase')!='prepared':raise ValueError('gui-prepare-unknown')
    cleared=run('clear',None);save('clear',cleared)
    if cleared.get('state')!='observed'or cleared.get('phase')!='cleared':raise ValueError('gui-clear-unknown')
    typed=run('typing',cleared['hostAuthority']);save('typing',typed)
    if typed.get('state')!='observed'or typed.get('phase')!='typed':raise ValueError('gui-typing-unknown')
    entered=run('enter',typed['hostAuthority']);save('enter',entered)
    if entered.get('state')!='observed'or entered.get('phase')!='entered':raise ValueError('gui-enter-unknown')
    observed=run('owner',None);save('owner',observed)
    if observed.get('state')!='observed':raise ValueError('gui-owner-unknown')
    owner.validate_facts(observed['facts'])
    return {'state':'observed','phase':'ordinary-session','owner':observed['facts'],'passwordTyped':True,'loginSubmitted':True,'installerAction':False,'replayAllowed':False}

OWNER_SHA='9ff8275a77e71e8b1a7ae90ee4e7dd5a1910ad130720e4621ff85a6fe9b38342'

def start(root):
    r=login.guest.recovery;root=Path(root).resolve(strict=True);leaf='windows-cp117-windowless-gui-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'gui-consumed','replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);secret=b'';events=[];phase_records={}
    try:
        raw=r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin']);record=json.loads(raw)
        files={Path(__file__):None,Path(secure.__file__):SECURE_SHA,Path(login.__file__):LOGIN_SHA,Path(login.guest.__file__):login.GUEST_SHA,Path(login.session.__file__):login.SESSION_SHA,Path(legacy.__file__):LEGACY_SHA,Path(owner.__file__):OWNER_SHA}
        pins={str(p):r.authority._read_bound_file(p)for p in files};secret,credential_path,credential_pin=login._configured_secret(root);_us_keys(secret)
        auth_source,auth_sha,auth_files=_auth_program(root,record);pins.update(auth_files)
        outer=r.authority._outer_authority(root);config,target,_=r.authority.closure.base._descriptor(root)
        if str(target.fixture_transfer_root)!=login.TRANSFER:raise ValueError('gui-transfer-root')
        def verify():
            if r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin'])!=raw:raise ValueError('gui-original-receipt')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('gui-original-frame')
            current=r.authority._source_pins(root);current['recovery']=r.authority._read_bound_file(Path(r.__file__))
            if current!=record['request']['sources']:raise ValueError('gui-original-source')
            for path,pin in pins.items():
                expected=files.get(Path(path));now=r.authority._read_bound_file(Path(path))
                if now!=pin or(expected is not None and now['sha256']!=expected):raise ValueError('gui-source-generation')
            if r.authority._read_bound_file(credential_path)!=credential_pin:raise ValueError('gui-credential-generation')
            for phase,(saved,saved_pin)in phase_records.items():
                if r._local_read(capture,phase+'-result.json',saved_pin)!=saved:raise ValueError('gui-positive-phase-generation')
            r.authority._verify_outer(root,{'outerAuthority':outer})
        verify();capture.create('intent.json',json.dumps({'state':'consumed','flow':CORRELATION,'original':login.guest.ORIGINAL,'sources':pins,'outerAuthority':outer,'credentialGeneration':credential_pin['generation'],'historicalCredentialInputGenerationIndependentlyProven':False,'currentAuthRequired':True,'installerAction':False},sort_keys=True).encode());os.fsync(capture.fd)
        def save(phase,value):
            phase_raw=json.dumps({'result':value,'events':[]},sort_keys=True).encode();pin=capture.create(phase+'-result.json',phase_raw);os.fsync(capture.fd);phase_records[phase]=(phase_raw,pin)
        def run(phase,prior):
            nonlocal secret
            verify()
            if phase=='auth':source,sha,childsha=auth_source,auth_sha,None;diagnostic,nonce=AUTH_CORRELATION,AUTH_NONCE
            elif phase=='owner':source,sha=_owner_program(record);childsha=None;diagnostic,nonce=OWNER_CORRELATION,OWNER_NONCE
            else:source,sha,childsha=_phase_program(record,phase,prior);diagnostic,nonce=_PHASES[phase]
            capture.create(phase+'-remote.py',source.encode());capture.create(phase+'-request.json',json.dumps({'flow':CORRELATION,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'childSourceSha256':childsha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'original':login.guest.ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
            argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
            capture.create(phase+'-attempt.json',json.dumps({'state':'consumed','flow':CORRELATION,'phase':phase},sort_keys=True).encode());os.fsync(capture.fd);verify()
            value,trace=_stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'],secret if phase in('auth','typing')else b'');events.extend(trace)
            if phase=='typing':secret=b''
            verify();capture.create(phase+'-events.json',json.dumps(trace,sort_keys=True).encode());os.fsync(capture.fd)
            submitted=[e['event']for e in trace if e['event']['kind']=='submitted']
            if len(submitted)!=1 or value.get('qemu')!=record['result']['qemu']or value.get('guestChildPid')!=submitted[0]['pid']:raise ValueError('gui-phase-child-binding')
            return value
        outcome=_sequence(run,save);verify();pin=capture.create('result.json',json.dumps(outcome,sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'observed','phase':'ordinary-session','evidenceLeaf':leaf,'receipt':pin,'ordinaryOwnerAdmission':True,'passwordTyped':True,'loginSubmitted':True,'installerAction':False,'replayAllowed':False}
    except Exception as e:
        events.extend(getattr(e,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events,'replayAllowed':False},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:secret=b'';original.close();capture.close()
