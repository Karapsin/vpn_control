"""Fixed recovered CP117 ordinary-owner census. No app bootstrap or MSI action."""
import base64,hashlib,json,inspect,os
from pathlib import Path
from .windows_diagnostic_authority_capture import AuthorityCapture
from . import windows_cp117_recovered_guest_observe as guest
SID=guest.SID
CORRELATION='9c5810bc-e84c-4ea4-a442-a2371897a58b'
NONCE='bace021e-ff83-49bc-b55c-ceef56a6083d'

_TOKEN_CS=r'''
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
 public static string[] Read(int pid,long creation) {
  IntPtr p=OpenProcess(0x1000,false,pid),t=IntPtr.Zero;if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  try {long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=creation)throw new InvalidOperationException("process-generation");
   if(!OpenProcessToken(p,8,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(WindowsIdentity id=new WindowsIdentity(t)) {bool[] admin=Admin(t);
    return new string[]{id.User.Value,Info(t,20).ToString(),Info(t,18).ToString(),admin[0].ToString(),admin[1].ToString(),Info(t,12).ToString()}; }
  }finally{if(t!=IntPtr.Zero)CloseHandle(t);CloseHandle(p);}
 }
}
'''

def validate_facts(value):
    keys={'version','account','profile','explorers','apps','runtimeCount','installerCount','publicStatusObserved'}
    if not isinstance(value,dict)or set(value)!=keys or value['version']!=1:raise ValueError('owner-schema')
    if value['account']!={'expectedSid':True,'enabled':True,'local':True}or value['profile']!={'expectedSid':True,'expectedPath':True,'loaded':True}:raise ValueError('owner-account-profile')
    if value['publicStatusObserved']is not False:raise ValueError('owner-public-status-claim')
    if type(value['runtimeCount'])is not int or value['runtimeCount']!=0 or type(value['installerCount'])is not int or value['installerCount']!=0:raise ValueError('owner-runtime-installer')
    if not isinstance(value['explorers'],list)or len(value['explorers'])!=1 or not isinstance(value['apps'],list)or len(value['apps'])>1:raise ValueError('owner-process-count')
    for p in value['explorers']+value['apps']:
        fields={'pid','startFileTime','sessionId','expectedSid','elevated','elevationType','adminMember','adminEnabled'}
        if not isinstance(p,dict)or set(p)!=fields or type(p['pid'])is not int or p['pid']<=0 or not isinstance(p['startFileTime'],str)or not p['startFileTime'].isdigit()or p['sessionId']!=1 or p['expectedSid']is not True:raise ValueError('owner-token-binding')
        if p['elevated']is not False or p['adminEnabled']is not False or type(p['adminMember'])is not bool or p['elevationType']not in(1,3):raise ValueError('owner-token-privilege')
    return value

_PS=r'''$ErrorActionPreference='Stop'
try {
 $sid='S-1-5-21-2404255130-2183793310-3766671872-1002'
 Add-Type -TypeDefinition @'
__TOKEN_CS__
'@
 $accounts=@(Get-CimInstance Win32_UserAccount -Filter "SID='$sid'")
 $profiles=@(Get-CimInstance Win32_UserProfile -Filter "SID='$sid'")
 if($accounts.Count -ne 1 -or $profiles.Count -ne 1){throw 'OWNER_ACCOUNT_PROFILE'}
 $all=@(Get-CimInstance Win32_Process)
 $explorers=@($all|Where-Object {$_.Name -ceq 'explorer.exe'})
 $apps=@($all|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli)\.exe$'})
 if($explorers.Count -gt 16 -or $apps.Count -gt 16){throw 'OWNER_PROCESS_BOUND'}
 function Snapshot($items) {
  foreach($item in $items) {
   $p=[Diagnostics.Process]::GetProcessById([int]$item.ProcessId)
   try {
    $stamp=$p.StartTime.ToUniversalTime().ToFileTimeUtc()
    if($p.HasExited -or $p.SessionId -ne $item.SessionId -or $stamp -ne $item.CreationDate.ToUniversalTime().ToFileTimeUtc()){throw 'OWNER_PROCESS_GENERATION'}
    $t=[Cp117OwnerToken]::Read([int]$item.ProcessId,$stamp)
    if([int]$t[5] -ne $item.SessionId){throw 'OWNER_TOKEN_SESSION'}
    $again=Get-CimInstance Win32_Process -Filter "ProcessId=$($item.ProcessId)"
    if($null -eq $again -or $again.CreationDate -ne $item.CreationDate -or $again.SessionId -ne $item.SessionId -or $again.Name -cne $item.Name -or $p.HasExited -or $p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $stamp){throw 'OWNER_PROCESS_CHANGED'}
    [pscustomobject]@{pid=[int]$item.ProcessId;startFileTime=$stamp.ToString();sessionId=[int]$item.SessionId;expectedSid=($t[0] -ceq $sid);elevated=($t[1] -ceq '1');elevationType=[int]$t[2];adminMember=($t[3] -ceq 'True');adminEnabled=($t[4] -ceq 'True')}
   }finally{$p.Dispose()}
  }
 }
 $facts=@{version=1;account=@{expectedSid=($accounts[0].SID -ceq $sid);enabled=(-not $accounts[0].Disabled -and -not $accounts[0].Lockout);local=[bool]$accounts[0].LocalAccount};profile=@{expectedSid=($profiles[0].SID -ceq $sid);expectedPath=($profiles[0].LocalPath -ieq 'C:\Users\vpncp117');loaded=[bool]$profiles[0].Loaded};explorers=@(Snapshot $explorers);apps=@(Snapshot $apps);runtimeCount=@($all|Where-Object {$_.Name -ceq 'sing-box.exe'}).Count;installerCount=@($all|Where-Object {$_.Name -match '^(msiexec|consent)\.exe$'}).Count;publicStatusObserved=$false}
 [Console]::Out.WriteLine(($facts|ConvertTo-Json -Depth 8 -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"OWNER_UNKNOWN"}');exit 1}
'''

def body():
    value=_PS.replace('__TOKEN_CS__',_TOKEN_CS)
    if hashlib.sha256(value.encode('utf-16le')).hexdigest()!=BODY_SHA:raise ValueError('owner-fixed-source')
    return value

def parse_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('owner-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('owner-output-cap')
    first,sep,payload=raw.partition(b'\n')
    if not sep or first.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if value.get('exitcode')!=0:raise ValueError('owner-guest-exit')
    return validate_facts(json.loads(payload))

BODY_SHA='737569c984a62128c0311f53f537f14ae56bdae5f241baa9858f3c53ea83f208'

GUEST_SHA='254d7495f1a4c02e68b34c6168c6dad93a693445b9569849f61fdf4ca2379b58'
REMOTE_SHA='9743e163a7b5b5074f1bc53c244e793a1ab122dd210e3d7bc101c26c33f603a7'
FACTORY_SHA='97faed0f4aed4fa9bdbba0cc1be795b39d833393bcce5377b91ba11e11f1bfdf'
PARSER_SHA='6f3ac5200d29912cc8c6864a97b2012ad7c41d61d5df1d60ec7ee65e86c70998'
VALIDATOR_SHA='51f88b56ffaffab68964d1af2a32217d8dedcdb7ee3b584c5cb80c28b3e5c8e0'


def program(record):
    if hashlib.sha256(Path(guest.__file__).read_bytes()).hexdigest()!=GUEST_SHA or hashlib.sha256(guest._REMOTE.encode()).hexdigest()!=REMOTE_SHA or hashlib.sha256(inspect.getsource(guest.program).encode()).hexdigest()!=FACTORY_SHA:raise ValueError('owner-original-reader-source')
    if hashlib.sha256(inspect.getsource(parse_terminal).encode()).hexdigest()!=PARSER_SHA or hashlib.sha256(inspect.getsource(validate_facts).encode()).hexdigest()!=VALIDATOR_SHA:raise ValueError('owner-parser-source')
    value=body();header="[Console]::Out.WriteLine(('CP117-READ "+NONCE+" "+BODY_SHA+" '+$PID))\n"
    encoded=base64.b64encode((header+value).encode('utf-16le')).decode()
    if len(encoded)>=30000:raise ValueError('owner-command-cap')
    source,oldsha=guest.program(record,CORRELATION,NONCE)
    oldencoded,_=guest.encoded_read(NONCE)
    oldparser=inspect.getsource(guest.parse_terminal)
    replacement=inspect.getsource(validate_facts)+"\n"+inspect.getsource(parse_terminal)
    for before,after in((repr(oldencoded),repr(encoded)),('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(BODY_SHA)),(oldparser,replacement)):
        if source.count(before)!=1:raise ValueError('owner-reader-factory')
        source=source.replace(before,after)
    compile(source,'fixed-ordinary-owner-reader','exec');return source,BODY_SHA


def observe(root):
    r=guest.recovery;root=Path(root).resolve(strict=True);leaf='windows-cp117-owner-observe-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'owner-consumed','replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);events=[]
    try:
        raw=r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin']);record=json.loads(raw)
        files={Path(__file__):None,Path(guest.__file__):GUEST_SHA};pins={str(p):r.authority._read_bound_file(p)for p in files}
        def verify():
            if r._local_read(original,guest.ORIGINAL['name'],guest.ORIGINAL['pin'])!=raw:raise ValueError('owner-original-receipt')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('owner-original-frame')
            now=r.authority._source_pins(root);now['recovery']=r.authority._read_bound_file(Path(r.__file__))
            if now!=record['request']['sources']or now['recovery']['sha256']!=guest.RECOVERY_SHA:raise ValueError('owner-original-sources')
            for p,sha in files.items():
                current=r.authority._read_bound_file(p)
                if current!=pins[str(p)]or(sha is not None and current['sha256']!=sha):raise ValueError('owner-observer-source')
        verify();outer=r.authority._outer_authority(root);source,sha=program(record)
        capture.create('request.json',json.dumps({'original':guest.ORIGINAL,'diagnosticId':CORRELATION,'nonce':NONCE,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'sources':pins,'outerAuthority':outer,'ordinaryRequesterAdmission':False,'installerAction':False},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=r.authority.closure.base._descriptor(root);argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        verify();r.authority._verify_outer(root,{'outerAuthority':outer});value,events=guest._stream(argv,capture,CORRELATION,NONCE,sha,record['result']['qemu']);verify();r.authority._verify_outer(root,{'outerAuthority':outer})
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':value['state'],'phase':value.get('phase'),'facts':value.get('facts'),'evidenceLeaf':leaf,'receipt':pin,'ordinaryRequesterAdmission':False,'installerAction':False}
    except Exception as e:
        events=getattr(e,'events',events);pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()
