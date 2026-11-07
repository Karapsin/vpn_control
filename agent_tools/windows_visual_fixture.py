"""Explicit blank-VM visual setup; never ordinary-product acceptance.

The read-only native query is unqualified until run directly on its owned VM.
Python validation/emission is not native Windows acceptance or capture authority.
The fixed security mutation remains windows_vm_guest.secure_instance unchanged.
"""
from __future__ import annotations
import inspect,re
from . import windows_vm_guest as standard
from .windows_vm_unattend import parse_setup

PURPOSE='windowsUacVisual'

_WITNESS=r'''Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;using System.Security.Principal;
public sealed class VcVisualExplorer:IDisposable {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,int p);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageName(IntPtr p,int f,StringBuilder b,ref int n);
 [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr p,uint t);
 [DllImport("kernel32.dll")]public static extern uint WTSGetActiveConsoleSessionId();
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,int n,out int z);
 [StructLayout(LayoutKind.Sequential)]struct Group {public IntPtr sid;public uint attributes;}
 [StructLayout(LayoutKind.Sequential)]struct Groups {public uint count;public Group first;}
 IntPtr process,token;public readonly int Pid;
 public VcVisualExplorer(int pid){Pid=pid;process=OpenProcess(0x101000,false,pid);if(process==IntPtr.Zero)throw new InvalidOperationException("VISUAL_OPEN");}
 static int Info(IntPtr t,int c){IntPtr b=Marshal.AllocHGlobal(4);try{int n;if(!GetTokenInformation(t,c,b,4,out n)||n!=4)throw new InvalidOperationException("VISUAL_TOKEN");return Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);}}
 public string[] Read(){
  if(process==IntPtr.Zero||WaitForSingleObject(process,0)!=258)throw new InvalidOperationException("VISUAL_EXITED");
  if(token!=IntPtr.Zero){CloseHandle(token);token=IntPtr.Zero;}if(!OpenProcessToken(process,8,out token))throw new InvalidOperationException("VISUAL_TOKEN_OPEN");
  long c,e,k,u;if(!GetProcessTimes(process,out c,out e,out k,out u)||c<=0)throw new InvalidOperationException("VISUAL_BIRTH");
  StringBuilder path=new StringBuilder(32768);int size=path.Capacity;if(!QueryFullProcessImageName(process,0,path,ref size)||size<=0||size>=32768)throw new InvalidOperationException("VISUAL_PATH");
  int n;GetTokenInformation(token,2,IntPtr.Zero,0,out n);if(n<=0||n>32768)throw new InvalidOperationException("VISUAL_GROUP_BOUND");IntPtr b=Marshal.AllocHGlobal(n);bool member=false,enabled=false,deny=false;
  try{int used;if(!GetTokenInformation(token,2,b,n,out used)||used>n)throw new InvalidOperationException("VISUAL_GROUPS");int count=Marshal.ReadInt32(b);int offset=Marshal.OffsetOf(typeof(Groups),"first").ToInt32(),stride=Marshal.SizeOf(typeof(Group));if(count<0||count>256||offset+count*stride>used)throw new InvalidOperationException("VISUAL_GROUP_SHAPE");for(int i=0;i<count;i++){Group g=(Group)Marshal.PtrToStructure(IntPtr.Add(b,offset+i*stride),typeof(Group));if(new SecurityIdentifier(g.sid).Value=="S-1-5-32-544"){if(member)throw new InvalidOperationException("VISUAL_GROUP_DUP");member=true;enabled=(g.attributes&4)!=0;deny=(g.attributes&16)!=0;}}}finally{Marshal.FreeHGlobal(b);}
  using(WindowsIdentity id=new WindowsIdentity(token)){return new string[]{c.ToString(System.Globalization.CultureInfo.InvariantCulture),path.ToString(),id.User.Value,Info(token,20).ToString(),Info(token,18).ToString(),member.ToString(),enabled.ToString(),deny.ToString(),Info(token,12).ToString()};}
 }
 public void Dispose(){if(token!=IntPtr.Zero){CloseHandle(token);token=IntPtr.Zero;}if(process!=IntPtr.Zero){CloseHandle(process);process=IntPtr.Zero;}}
}
'@
$active=[VcVisualExplorer]::WTSGetActiveConsoleSessionId()
if($active -eq 0 -or $active -gt 16383){throw 'VISUAL_ACTIVE_SESSION'}
$rows=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'")
if($rows.Count -gt 16){throw 'VISUAL_EXPLORER_BOUND'}
$visualWitness=$null;$visualOpening=$null
try {
 foreach($row in $rows){
  $candidate=[VcVisualExplorer]::new([int]$row.ProcessId)
  try{$facts=$candidate.Read();if($facts[2] -ceq $admin.SID.Value -and [int]$facts[8] -eq [int]$active){if($visualWitness){throw 'VISUAL_EXPLORER_DUP'};$visualWitness=$candidate;$visualOpening=$facts;$candidate=$null}}finally{if($candidate){$candidate.Dispose()}}
 }
 if(-not $visualWitness){throw 'VISUAL_EXPLORER_MISSING'}
 $adminProfiles=@(Get-CimInstance Win32_UserProfile -Filter ("SID='"+$admin.SID.Value+"'"))
 if($adminProfiles.Count -ne 1){throw 'VISUAL_PROFILE'}
 $visualSession=[ordered]@{activeConsoleSession=[int]$active;closingConsoleSession=$null;administratorProfile=$adminProfiles[0].LocalPath;explorerPid=$visualWitness.Pid;opening=$visualOpening;closing=$null;bootFileTimeUtc=$os.LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)}
'''


def powershell_source(setup,operation_id):
    setup=parse_setup(setup)
    if setup.get('purpose')!=PURPOSE:raise ValueError('visual_setup_purpose')
    source=standard.powershell_source(setup,operation_id)
    marker='$result=[ordered]@{\n';ending='[Console]::WriteLine(($result | ConvertTo-Json -Depth 8 -Compress))\n'
    if source.count(marker)!=1 or source.count(ending)!=1:raise ValueError('visual_setup_template')
    source=source.replace(marker,_WITNESS+marker,1).replace(ending,
        "$visualSession.closing=$visualWitness.Read()\n"
        "$visualSession.closingConsoleSession=[int][VcVisualExplorer]::WTSGetActiveConsoleSessionId()\n"
        "if($visualSession.closingConsoleSession -ne $visualSession.activeConsoleSession){throw 'VISUAL_CONSOLE_CHANGED'}\n"
        "if(($visualSession.opening -join '|') -cne ($visualSession.closing -join '|')){throw 'VISUAL_EXPLORER_CHANGED'}\n"
        "$result['visualSession']=$visualSession\n"+ending+
        "} finally {if($visualWitness){$visualWitness.Dispose()}}\n",1)
    # Existing qualification uses -EncodedCommand. Refuse here before any
    # submission rather than introducing an unqualified second carrier.
    import base64
    if len(base64.b64encode(source.encode('utf-16le')))+256>30000:raise ValueError('visual_setup_command_bound')
    return source


def _visual_session(value,operation_id,setup):
    from datetime import datetime
    if type(value)is not dict or 'visualSession'not in value:raise ValueError('instance_visual_result')
    base={k:v for k,v in value.items()if k!='visualSession'}
    _standard_validate_setup_result(base,operation_id,setup)
    session=value['visualSession']
    if type(session)is not dict or set(session)!={'activeConsoleSession','closingConsoleSession','administratorProfile','explorerPid','opening','closing','bootFileTimeUtc'}:raise ValueError('instance_visual_fields')
    def positive(v,maximum):return type(v)is int and 0<v<=maximum
    if (not positive(session['activeConsoleSession'],16383) or type(session['closingConsoleSession'])is not int
            or session['closingConsoleSession']!=session['activeConsoleSession'] or not positive(session['explorerPid'],2**31-1)):raise ValueError('instance_visual_identity')
    filetime=session['bootFileTimeUtc']
    if type(filetime)is not str or re.fullmatch('[1-9][0-9]{0,18}',filetime)is None or int(filetime)>2**63-1:raise ValueError('instance_visual_identity')
    boot=value['os']['bootTime']
    match=re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{7})Z',boot)if type(boot)is str else None
    if match is None:raise ValueError('instance_visual_boot')
    try:delta=datetime.strptime(match[1]+'.'+match[2][:6],'%Y-%m-%dT%H:%M:%S.%f')-datetime(1601,1,1)
    except ValueError:raise ValueError('instance_visual_boot')from None
    expected=((delta.days*86400+delta.seconds)*1000000+delta.microseconds)*10+int(match[2][-1])
    if expected!=int(filetime):raise ValueError('instance_visual_boot')
    profile=session['administratorProfile']
    if type(profile)is not str or len(profile)>512 or profile.casefold()!=('C:\\Users\\'+setup['administrator']).casefold():raise ValueError('instance_visual_profile')
    opening=session['opening'];closing=session['closing']
    if (type(opening)is not list or len(opening)!=9 or any(type(v)is not str or len(v)>32768 for v in opening)
            or type(closing)is not list or closing!=opening):raise ValueError('instance_visual_explorer')
    if (not re.fullmatch('[1-9][0-9]{0,18}',opening[0]) or int(opening[0])>2**63-1
            or not re.fullmatch('C:\\\\Windows\\\\explorer\\.exe',opening[1],re.IGNORECASE)
            or opening[2]!=value['administrator']['sid'] or opening[2]==value['user']['sid'] or opening[3:8]!=['0','3','True','False','True']
            or opening[8]!=str(session['activeConsoleSession'])):raise ValueError('instance_visual_token')
    return {'guestBoot':value['os']['bootTime'],'bootFileTimeUtc':session['bootFileTimeUtc'],
            'sid':opening[2],'sessionId':session['activeConsoleSession'],'explorerPid':session['explorerPid'],
            'explorerBirth':opening[0],'explorerPath':opening[1],'profile':profile}


def _validate_visual_setup_result(value,operation_id,setup):
    if setup.get('purpose')!='windowsUacVisual':raise ValueError('instance_visual_purpose')
    _visual_session(value,operation_id,setup)
    return value


def _qualify_visual_instance(spec,setup,operation_id,status_only,root,read,save,process,owns,instance_intent,closing,observed,script_source=None):
    # The unchanged QGA custody producer calls the strict validator above.
    # It initially computes standard-user readiness, which is intentionally
    # false in this separate visual administrator session.
    if setup.get('purpose')!='windowsUacVisual':raise ValueError('instance_visual_purpose')
    result=_standard_qualify_instance(spec,setup,operation_id,status_only,root,read,save,process,owns,instance_intent,closing,observed,script_source)
    if result['state']!='setup-observed':return result
    value=result['result'];binding=_visual_session(value,operation_id,setup)
    ready=value['setup']['ready'];user=value['user'];admin=value['administrator']
    qualified=bool(result['imageMatchesRequest'] and type(ready)is dict and ready.get('state')=='ready'
        and type(ready.get('installerExit'))is int and ready['installerExit']in (0,3010)
        and type(value['setup']['systemSetupInProgress'])is int and value['setup']['systemSetupInProgress']==0
        and type(value['setup']['oobeInProgress'])is int and value['setup']['oobeInProgress']==0 and value['setup']['imageState']=='IMAGE_STATE_COMPLETE'
        and value['setup']['taskState']in ('Ready','Disabled') and user['enabled'] and not user['isAdministrator']
        and user['isUsersMember'] and admin['enabled'] and admin['isAdministrator'] and value['guestAgent']['state']=='Running'
        and value['updatePolicy']=={'noAutoUpdate':1,'storeAutoDownload':2})
    if qualified:
        # Only the original successful full qualification may create this
        # immutable binding. Post-security requalification must match it.
        path=root/'visual-session-qualified.json'
        if path.exists():
            if read(path.name)!={'purpose':'windowsUacVisual','binding':binding}:raise ValueError('instance_visual_session_changed')
        else:save(path.name,{'purpose':'windowsUacVisual','binding':binding})
        instance_intent();closing()
    result['setupReady']=qualified
    result['result']={**value,'visualFilteredAdminReady':qualified}
    return result


def definitions():
    """Compose complete native definitions; ordinary emission never uses them."""
    body=inspect.getsource(standard.validate_setup_result)+'\n_standard_validate_setup_result=validate_setup_result\n'
    body+=inspect.getsource(standard.qualify_instance)+'\n_standard_qualify_instance=qualify_instance\n'
    body+=inspect.getsource(_visual_session)+'\n'+inspect.getsource(_validate_visual_setup_result)+'\n'+inspect.getsource(_qualify_visual_instance)+'\n'
    body+='validate_setup_result=_validate_visual_setup_result\nqualify_instance=_qualify_visual_instance\n'
    return body
