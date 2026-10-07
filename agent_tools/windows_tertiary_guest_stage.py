"""Finite tertiary fixture write primitive; never grants environment admission.

The caller owns the source FD, current peer/guest proofs and original QGA file
handle. This module dispatches neither SSH nor an installer or product command.
"""
import base64
import hashlib
import os
import time

TARGET_SIZE = 131101044
CHUNK_SIZE = 49152
BUDGET_SECONDS = 180
MAX_CALL_BUDGET = ((TARGET_SIZE+CHUNK_SIZE-1)//CHUNK_SIZE)*4+2


class StageDeadlineMixin:
    """Clip the existing SDK socket deadline to this writer's absolute deadline."""
    def _with_deadline(self, connection, deadline):
        return super()._with_deadline(connection,min(deadline,getattr(self,'_stage_deadline',deadline)))


class GuestWriteUnknown(ValueError):
    def __init__(self, cause, handle, transferred, calls, operation):
        super().__init__('TERTIARY_STAGE_WRITE_UNKNOWN:'+type(cause).__name__)
        self.original_handle=handle
        self.transferred=transferred
        self.calls=calls
        self.operation=operation
        self.replay_allowed=False


def write_target(client, source_fd, handle, guard):
    """One bounded original handle; each SDK subcall shares the whole deadline."""
    transferred=0
    calls=0
    operation='admission'
    remaining=TARGET_SIZE
    deadline=time.monotonic()+BUDGET_SECONDS
    digest=hashlib.sha256()
    original_timeout=client.timeout_seconds
    client._stage_deadline=deadline
    def current():
        guard()
        if time.monotonic()>=deadline:raise TimeoutError('TERTIARY_STAGE_TRANSFER_DEADLINE')
    def exchange(command,args):
        nonlocal calls,operation
        operation=command;current()
        if calls>=MAX_CALL_BUDGET:raise ValueError('TERTIARY_STAGE_CALL_BUDGET')
        calls+=1
        # StageDeadlineMixin clips each actual SDK socket to this absolute
        # deadline; the SDK's frozen timeout configuration stays unchanged.
        result=client._exchange(command,args)
        return result
    try:
        if type(original_timeout)not in (float,int) or not 0<original_timeout<=3:raise ValueError('TERTIARY_STAGE_SDK_TIMEOUT')
        while remaining:
            current();part=os.read(source_fd,min(CHUNK_SIZE,remaining));current()
            if not 0<len(part)<=remaining:raise ValueError('TERTIARY_STAGE_SOURCE_EOF')
            remaining-=len(part);offset=0;digest.update(part)
            while offset<len(part):
                written=exchange('guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part[offset:]).decode()})
                count=written.get('count')
                if type(count)is not int or not 0<count<=len(part)-offset:raise ValueError('TERTIARY_STAGE_WRITE_COUNT')
                offset+=count;transferred+=count;current()
        current();trailing=os.read(source_fd,1);current()
        if trailing!=b'':raise ValueError('TERTIARY_STAGE_SOURCE_TRAILING')
        exchange('guest-file-flush',{'handle':handle});current()
        exchange('guest-file-close',{'handle':handle});current()
        return {'transferred':transferred,'sha256':digest.hexdigest(),'closed':True,'calls':calls}
    except Exception as error:
        raise GuestWriteUnknown(error,handle,transferred,calls,operation) from error
    finally:
        del client._stage_deadline

# Win32 patterns adapted from the reviewed fixed secondary directory source.
# These are deliberately a finite tertiary primitive, not a guest dispatcher.
PRIVATE_CS = r'''using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class TertiaryPrivateStage {
 [StructLayout(LayoutKind.Sequential)] public struct Info {public uint Attr,CH,CL,AH,AL,WH,WL,Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow;}
 [StructLayout(LayoutKind.Sequential)] struct SA {public uint Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint revision,out IntPtr descriptor,IntPtr size);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectory(string p,ref SA sa);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sa,uint create,uint flags,IntPtr template);
 [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileWithSecurity(string p,uint access,uint share,ref SA sa,uint create,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out Info i);
 public static void CreateExclusive(string p,string sddl) {
  IntPtr sd;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out sd,IntPtr.Zero))throw new IOException("TERTIARY_PRIVATE_SD");
  try {var sa=new SA{Length=(uint)Marshal.SizeOf(typeof(SA)),Descriptor=sd,Inherit=false};if(!CreateDirectory(p,ref sa))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
  finally {LocalFree(sd);}
 }
 public static string Pin(SafeFileHandle h,bool directory) {
  Info i;if(h.IsInvalid||!GetFileInformationByHandle(h.DangerousGetHandle(),out i)||(i.Attr&0x400)!=0||(((i.Attr&0x10)!=0)!=directory)||(!directory&&i.Links!=1))throw new IOException("TERTIARY_NATIVE_IDENTITY");
  return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL;
 }
 public static SafeFileHandle Hold(string p,bool directory) {
  var h=CreateFile(p,0x80000000,3,IntPtr.Zero,3,directory?0x02200000u:0x00200000u,IntPtr.Zero);
  try {Pin(h,directory);return h;}catch{h.Dispose();throw;}
 }
 // Default owner is retained for existing scratch sharing controls only.
 public static SafeFileHandle CreateTarget(string p) {
  var h=CreateFile(p,0x80000000,3,IntPtr.Zero,1,0x00200000,IntPtr.Zero);
  try {Pin(h,false);return h;}catch{h.Dispose();throw;}
 }
 public static SafeFileHandle CreateTargetOwned(string p,string ownerSid) {
  new System.Security.Principal.SecurityIdentifier(ownerSid);
  IntPtr sd;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+ownerSid,1,out sd,IntPtr.Zero))throw new IOException("TERTIARY_TARGET_OWNER_SD");
  try {var sa=new SA{Length=(uint)Marshal.SizeOf(typeof(SA)),Descriptor=sd,Inherit=false};
   var h=CreateFileWithSecurity(p,0x80000000,3,ref sa,1,0x00200000,IntPtr.Zero);
   try {Pin(h,false);return h;}catch{h.Dispose();throw;}
  }finally {LocalFree(sd);}
 }
 public static SafeFileHandle CreateDefaultTargetForOwnerControl(string p) {
  var h=CreateFile(p,0x80000000,3,IntPtr.Zero,1,0x00200000,IntPtr.Zero);
  try {Pin(h,false);return h;}catch{h.Dispose();throw;}
 }
 // Historical metadata-only access is confined to causal scratch controls.
 public static SafeFileHandle HoldMetadataForControl(string p,bool directory) {
  var h=CreateFile(p,0x80,3,IntPtr.Zero,3,directory?0x02200000u:0x00200000u,IntPtr.Zero);
  try {Pin(h,directory);return h;}catch{h.Dispose();throw;}
 }
 public static SafeFileHandle CreateMetadataTargetForControl(string p) {
  var h=CreateFile(p,0x80,3,IntPtr.Zero,1,0x00200000,IntPtr.Zero);
  try {Pin(h,false);return h;}catch{h.Dispose();throw;}
 }
 public static void Match(string p,SafeFileHandle original,string expected,bool directory) {
  if(Pin(original,directory)!=expected)throw new IOException("TERTIARY_FD_DRIFT");
  using(var named=Hold(p,directory)){if(Pin(named,directory)!=expected)throw new IOException("TERTIARY_NAME_DRIFT");}
 }
}'''



def sid_rule_probe_script():
    """Real Windows in-memory control for measured AddAccessRule failure."""
    return r'''
$sidControlAcl=[Security.AccessControl.DirectorySecurity]::new();$oldSidFailed=$false
try {
 $oldSidRule=[Security.AccessControl.FileSystemAccessRule]::new('S-1-5-32-544',[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]3,[Security.AccessControl.PropagationFlags]0,[Security.AccessControl.AccessControlType]::Allow)
 $sidControlAcl.AddAccessRule($oldSidRule)
} catch {if($_.Exception.ToString() -notmatch 'IdentityNotMappedException'){throw};$oldSidFailed=$true}
if(-not $oldSidFailed){throw 'OLD_SID_STRING_CONTROL'}
$typedSid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$typedSidRule=[Security.AccessControl.FileSystemAccessRule]::new($typedSid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]3,[Security.AccessControl.PropagationFlags]0,[Security.AccessControl.AccessControlType]::Allow)
$sidControlAcl.AddAccessRule($typedSidRule)
$typedRules=@($sidControlAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($typedRules.Count -ne 1 -or $typedRules[0].IdentityReference.Value -cne 'S-1-5-32-544'){throw 'TYPED_SID_CONTROL'}
$sidRuleControl=[ordered]@{oldIdentityTranslationFailed=$oldSidFailed;typedSid=$typedRules[0].IdentityReference.Value}
'''


def custody_share_probe_script():
    """Real Windows old metadata vs participating data-access custody controls."""
    return r'''
$oldFile=Join-Path $root 'metadata-only.msi';$oldFileHeld=[TertiaryPrivateStage]::CreateMetadataTargetForControl($oldFile)
try{[IO.File]::Move($oldFile,(Join-Path $root 'metadata-only-moved.msi'));$metadataFileRenamed=$true}finally{$oldFileHeld.Dispose()}
$oldDirectory=Join-Path $root 'metadata-directory';[IO.Directory]::CreateDirectory($oldDirectory)|Out-Null
$oldDirectoryHeld=[TertiaryPrivateStage]::HoldMetadataForControl($oldDirectory,$true)
try{[IO.Directory]::Move($oldDirectory,(Join-Path $root 'metadata-directory-moved'));$metadataDirectoryRenamed=$true}finally{$oldDirectoryHeld.Dispose()}
$sharedFile=Join-Path $root 'participating-read.msi';$sharedFileHeld=[TertiaryPrivateStage]::CreateTarget($sharedFile);$sharedFilePin=[TertiaryPrivateStage]::Pin($sharedFileHeld,$false)
$sharedDirectory=Join-Path $root 'participating-directory';[IO.Directory]::CreateDirectory($sharedDirectory)|Out-Null
$sharedDirectoryHeld=[TertiaryPrivateStage]::Hold($sharedDirectory,$true);$sharedDirectoryPin=[TertiaryPrivateStage]::Pin($sharedDirectoryHeld,$true)
try {
 $fileRefused=$false;$fileError=$null;try{[IO.File]::Move($sharedFile,(Join-Path $root 'participating-read-moved.msi'))}catch{$fileError=$_.Exception.InnerException.HResult -band 65535;$fileRefused=$true}
 if(-not $fileRefused -or $fileError -ne 32){throw 'PARTICIPATING_FILE_RENAME_CONTROL'}
 $directoryRefused=$false;$directoryError=$null;try{[IO.Directory]::Move($sharedDirectory,(Join-Path $root 'participating-directory-moved'))}catch{$directoryError=$_.Exception.InnerException.HResult -band 65535;$directoryRefused=$true}
 if(-not $directoryRefused -or $directoryError -ne 32){throw 'PARTICIPATING_DIRECTORY_RENAME_CONTROL'}
 $writer=[IO.File]::Open($sharedFile,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
 try{$bytes=[Text.Encoding]::ASCII.GetBytes('PUBLIC');$writer.Write($bytes,0,$bytes.Length);$writer.Flush($true)}finally{$writer.Dispose()}
 if([IO.File]::ReadAllText($sharedFile) -cne 'PUBLIC'){throw 'PARTICIPATING_WRITER_CONTROL'}
 [TertiaryPrivateStage]::Match($sharedFile,$sharedFileHeld,$sharedFilePin,$false)
 [TertiaryPrivateStage]::Match($sharedDirectory,$sharedDirectoryHeld,$sharedDirectoryPin,$true)
 $shareControl=[ordered]@{metadataFileRenamed=$metadataFileRenamed;metadataDirectoryRenamed=$metadataDirectoryRenamed;participatingFileRenameRefused=$fileRefused;participatingDirectoryRenameRefused=$directoryRefused;fileRenameError=$fileError;directoryRenameError=$directoryError;compatibleWriterObserved=$true;heldAndNamedIdentityClosed=$true}
}finally{$sharedDirectoryHeld.Dispose();$sharedFileHeld.Dispose()}
'''

def atomic_probe_script(correlation):
    """Native causal probe in one exclusive owned scratch root; never executes it.

    This script retains test effects/evidence. Local source preparation is not
    equivalent to running the Windows APIs. The dispatcher separately admits
    the current tertiary guest and records its original process/terminal state.
    """
    import uuid
    if str(uuid.UUID(correlation)) != correlation:
        raise ValueError('TERTIARY_STAGE_CORRELATION')
    root = r'C:\ProgramData\VpnControlTertiaryStageProbe-' + correlation
    return ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "$root='" + root + "';$corr='" + correlation + "'\n"
            "if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'PROBE_ACTOR'}\n"
            "if((Get-CimInstance Win32_ComputerSystem).UserName -cne 'VPNPARITYX64\\parityagent'){throw 'PROBE_INTERACTIVE'}\n"
            "$sessions=@(Get-Process -Name explorer -ErrorAction Stop|Select-Object -ExpandProperty SessionId -Unique);if($sessions.Count -ne 1 -or $sessions[0] -ne 1){throw 'PROBE_SESSION'}\n"
            "$interactiveSid=(New-Object Security.Principal.NTAccount('VPNPARITYX64\\parityagent')).Translate([Security.Principal.SecurityIdentifier]).Value;if($interactiveSid -cne 'S-1-5-21-606332539-4179368406-55829832-1000'){throw 'PROBE_SID'}\n"
            +release_guard_control_script()+sid_rule_probe_script()+"Add-Type -TypeDefinition @'\n" + PRIVATE_CS + "\n'@ -ReferencedAssemblies @('System','System.Core')\n" + r'''
$heldDrive=[TertiaryPrivateStage]::Hold('C:\',$true)
$heldParent=[TertiaryPrivateStage]::Hold('C:\ProgramData',$true)
$drivePin=[TertiaryPrivateStage]::Pin($heldDrive,$true);$parentPin=[TertiaryPrivateStage]::Pin($heldParent,$true)
$heldRoot=$null;$heldFile=$null
try {
 [TertiaryPrivateStage]::CreateExclusive($root,'O:SYD:P(A;OICI;FA;;;SY)')
 $heldRoot=[TertiaryPrivateStage]::Hold($root,$true);$rootPin=[TertiaryPrivateStage]::Pin($heldRoot,$true)
'''+custody_share_probe_script()+r'''
 $foreign=Join-Path $root 'foreign';[TertiaryPrivateStage]::CreateExclusive($foreign,'O:SYD:P(A;OICI;FA;;;SY)')
 $originalSddl=(Get-Acl -LiteralPath $foreign).Sddl
 # Reproduce the original foreign-winner branch: prior absence was observed,
 # then a directory exists by the time CreateDirectory and Set-Acl execute.
 [IO.Directory]::CreateDirectory($foreign)|Out-Null
 $acl=Get-Acl -LiteralPath $foreign
 $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]3,[Security.AccessControl.PropagationFlags]0,[Security.AccessControl.AccessControlType]::Allow)
 $acl.AddAccessRule($rule);Set-Acl -LiteralPath $foreign -AclObject $acl
 $oldRed=(Get-Acl -LiteralPath $foreign).Sddl -cne $originalSddl
 if(-not $oldRed){throw 'OLD_DIRECTORY_RACE_NOT_REPRODUCED'}
 $before=(Get-Acl -LiteralPath $foreign).Sddl;$refused=$false
 try{[TertiaryPrivateStage]::CreateExclusive($foreign,'O:SYD:P(A;OICI;FA;;;SY)')}catch{$refused=$true}
 if(-not $refused -or (Get-Acl -LiteralPath $foreign).Sddl -cne $before){throw 'FOREIGN_DIRECTORY_MODIFIED'}
 $target=Join-Path $root 'foreign.msi';[IO.File]::WriteAllBytes($target,[Text.Encoding]::ASCII.GetBytes('PUBLIC'))
 $fileRefused=$false;try{$unexpected=[TertiaryPrivateStage]::CreateTarget($target);$unexpected.Dispose()}catch{$fileRefused=$true}
 if(-not $fileRefused -or [IO.File]::ReadAllText($target) -cne 'PUBLIC'){throw 'FOREIGN_FILE_MODIFIED'}
 $owned=Join-Path $root 'owned.msi';$heldFile=[TertiaryPrivateStage]::CreateTarget($owned);$filePin=[TertiaryPrivateStage]::Pin($heldFile,$false)
 $exchangeRefused=$false;try{[IO.File]::Move($owned,(Join-Path $root 'moved.msi'))}catch{$exchangeRefused=$true}
 if(-not $exchangeRefused){throw 'HELD_FILE_EXCHANGED'}
 [TertiaryPrivateStage]::Match($owned,$heldFile,$filePin,$false)
 [TertiaryPrivateStage]::Match($root,$heldRoot,$rootPin,$true)
 [TertiaryPrivateStage]::Match('C:\ProgramData',$heldParent,$parentPin,$true)
 [TertiaryPrivateStage]::Match('C:\',$heldDrive,$drivePin,$true)

 $birth=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().Ticks
 $ready=[ordered]@{correlationId=$corr;pid=$PID;birthTicks=$birth;root=$root;target=$owned;targetNativeId=$filePin;rootNativeId=$rootPin}
 $readyBytes=[Text.Encoding]::UTF8.GetBytes(($ready|ConvertTo-Json -Compress))
 $readyStream=[IO.File]::Open((Join-Path $root 'qga-ready.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$readyStream.Write($readyBytes,0,$readyBytes.Length);$readyStream.Flush($true)}finally{$readyStream.Dispose()}
 $releasePath=Join-Path $root 'qga-release.json';$deadline=[DateTime]::UtcNow.AddSeconds(60)
 while(-not [IO.File]::Exists($releasePath)){
  [TertiaryPrivateStage]::Match($owned,$heldFile,$filePin,$false);[TertiaryPrivateStage]::Match($root,$heldRoot,$rootPin,$true)
  if([DateTime]::UtcNow -ge $deadline){throw 'QGA_CONTROL_RELEASE_DEADLINE'};Start-Sleep -Milliseconds 100
 }
 $releaseStream=$null
 while($null -eq $releaseStream){
  if([DateTime]::UtcNow -ge $deadline){throw 'QGA_CONTROL_RELEASE_DEADLINE'}
  [TertiaryPrivateStage]::Match($owned,$heldFile,$filePin,$false);[TertiaryPrivateStage]::Match($root,$heldRoot,$rootPin,$true)
  try{$releaseStream=[IO.File]::Open($releasePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}catch{if(($_.Exception.InnerException.HResult -band 65535) -ne 32){throw};Start-Sleep -Milliseconds 50}
 }
 try{if($releaseStream.Length -le 0 -or $releaseStream.Length -gt 1024){throw 'QGA_RELEASE_BOUND'};$reader=[IO.StreamReader]::new($releaseStream,[Text.Encoding]::UTF8);$token=$reader.ReadToEnd()|ConvertFrom-Json}finally{$releaseStream.Dispose()}
 if(FIXED_RELEASE_GUARD){throw 'QGA_RELEASE_IDENTITY'}
 $read=[IO.File]::Open($owned,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  $before=Get-Item -LiteralPath $owned -ErrorAction Stop
  if($read.Length -ne 6){throw 'QGA_PUBLIC_SIZE'}
  $alg=[Security.Cryptography.SHA256]::Create();try{$sha=[BitConverter]::ToString($alg.ComputeHash($read)).Replace('-','').ToLowerInvariant()}finally{$alg.Dispose()}
  if($sha -cne 'd9262e7fb868c502061473089e5212378ac3935e2f96294266da6d7eec7d44e0'){throw 'QGA_PUBLIC_HASH'}
  [TertiaryPrivateStage]::Match($owned,$heldFile,$filePin,$false);[TertiaryPrivateStage]::Match($root,$heldRoot,$rootPin,$true)
  $after=Get-Item -LiteralPath $owned -ErrorAction Stop
  if($before.Length -ne $after.Length -or $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks -or $before.CreationTimeUtc.Ticks -ne $after.CreationTimeUtc.Ticks){throw 'QGA_PUBLIC_GENERATION'}
  $qgaControl=[ordered]@{pid=$PID;birthTicks=$birth;target=$owned;targetNativeId=$filePin;rootNativeId=$rootPin;originalFileHandle=$token.originalFileHandle;closed=$true;length=6;sha256=$sha;heldAndNamedIdentityClosed=$true}
 }finally{$read.Dispose()}
 [ordered]@{correlationId=$corr;root=$root;sidRuleControl=$sidRuleControl;shareControl=$shareControl;releaseGuardControl=$releaseGuardControl;qgaControl=$qgaControl;oldDirectoryRaceObserved=$oldRed;exclusiveDirectoryRefused=$refused;exclusiveTargetRefused=$fileRefused;heldTargetExchangeRefused=$exchangeRefused;rootNativeId=$rootPin;targetNativeId=$filePin;installerStarted=$false;productAcceptance=$false}|ConvertTo-Json -Compress
}finally{if($heldFile){$heldFile.Dispose()};if($heldRoot){$heldRoot.Dispose()};$heldParent.Dispose();$heldDrive.Dispose()}
''').replace('FIXED_RELEASE_GUARD',release_guard_predicate())


def terminal_failure_projection(pid, terminal, journal):
    """Keep diagnostic identity/locators while raw bytes remain in private receipt."""
    if type(pid)is not int or pid<=0 or type(terminal)is not dict or terminal.get('exited')is not True:
        raise ValueError('TERTIARY_TERMINAL_IDENTITY')
    exitcode=terminal.get('exitcode')
    if type(exitcode)is not int or not isinstance(journal,str)or not journal:
        raise ValueError('TERTIARY_TERMINAL_RECEIPT')
    result={'state':'unknown','originalGuestPid':pid,'nativeExitCode':exitcode,
            'terminalReceipt':journal,'replayAllowed':False}
    for label,prefix in [('stdout','out'),('stderr','err')]:
        encoded=terminal.get(prefix+'-data','')
        if not isinstance(encoded,str):raise ValueError('TERTIARY_TERMINAL_ENCODING')
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>16384:raise ValueError('TERTIARY_TERMINAL_BOUND')
        truncated=terminal.get(prefix+'-truncated',False)
        if type(truncated)is not bool:raise ValueError('TERTIARY_TERMINAL_TRUNCATION')
        result.update({label+'Bytes':len(raw),label+'Sha256':hashlib.sha256(raw).hexdigest(),label+'Truncated':truncated})
        if label=='stderr':result['stderrPreview']=raw.decode('utf-8-sig',errors='replace')[:512]
    return result


def actor_admission(observed):
    """Missing current actor is a retained observation, never an admission."""
    if type(observed)is not dict:raise ValueError('TERTIARY_ACTOR_OBSERVATION')
    expected='VPNPARITYX64'+chr(92)+'parityagent'
    sid='S-1-5-21-606332539-4179368406-55829832-1000'
    admitted=(observed.get('processCensusComplete')is True and observed.get('actual')==expected
              and observed.get('sid')==sid and observed.get('sessions')==[1]
              and type(observed.get('explorers'))is list and len(observed['explorers'])>0)
    return {'interactiveActorAdmitted':admitted,'observation':dict(observed)}


def validate_target_request(request,correlation):
    import uuid
    from agent_tools.windows_tertiary_fixture_stage import TARGET_SHA256, SOURCE_SHA
    for c in (request.get('correlation'),correlation):
        if str(uuid.UUID(c))!=c:raise ValueError('TERTIARY_CUSTODY_CORRELATION')
    directory=r'C:\ProgramData\VpnControlTertiaryFixture-'+request['correlation']
    sid='S-1-5-21-606332539-4179368406-55829832-1000'
    if (request.get('guestStage')!=directory or request.get('expectedSid')!=sid
        or request.get('targetSize')!=TARGET_SIZE or request.get('targetSha256')!=TARGET_SHA256
        or request.get('sourceSha')!=SOURCE_SHA or request.get('installerAuthorized')is not False):
        raise ValueError('TERTIARY_CUSTODY_BINDING')
    return directory


def custodian_script(request, correlation):
    """Build one fixed, bounded guest process; source only, no dispatch authority."""
    from agent_tools.windows_tertiary_fixture_stage import TARGET_SHA256
    directory=validate_target_request(request,correlation)
    sid=request['expectedSid']
    prefix=("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "$root='"+directory+"';$corr='"+correlation+"';$sid='"+sid+"'\n"
            "$expectedSha='"+TARGET_SHA256+"';$expectedSize="+str(TARGET_SIZE)+"\n"
            "Add-Type -TypeDefinition @'\n"+PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n")
    return prefix+r'''
function Assert-Actor {
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'CUSTODY_ACTOR'}
 $name=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
 if($name -cne 'VPNPARITYX64\parityagent'){throw 'CUSTODY_INTERACTIVE_USER'}
 $actualSid=(New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier]).Value
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$sessions=@($all|Where-Object {$_.Name -ceq 'explorer.exe'}|Select-Object -ExpandProperty SessionId -Unique)
 if($actualSid -cne $sid -or $sessions.Count -ne 1 -or $sessions[0] -ne 1){throw 'CUSTODY_INTERACTIVE_SESSION'}
 $effectOwners=@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','sing-box.exe','msiexec.exe','vpn-control-windows-vpn-broker.exe') -or ($_.ExecutablePath -and $_.ExecutablePath.StartsWith('C:\Users\parityagent\AppData\Local\vpn-control\',[StringComparison]::OrdinalIgnoreCase))}|ForEach-Object {[ordered]@{pid=$_.ProcessId;parentPid=$_.ParentProcessId;name=$_.Name;path=$_.ExecutablePath;session=$_.SessionId;birth=$_.CreationDate}})
 if($effectOwners.Count -ne 0){throw 'CUSTODY_EXISTING_EFFECT_OWNER'}
 return [ordered]@{observerSid='S-1-5-18';interactiveUser=$name;interactiveSid=$actualSid;session=1;processCensusComplete=$true;processCount=$all.Count;effectOwners=$effectOwners;publicOFF='UNRESOLVED'}
}
function Observe-Acl([string]$path,[bool]$directory) {
 $acl=Get-Acl -LiteralPath $path -ErrorAction Stop
 if($acl.AreAccessRulesProtected -ne $directory -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18'){throw 'CUSTODY_ACL_OWNER'}
 $inheritance=if($directory){3}else{0};$inherited=-not $directory
 $records=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {[ordered]@{sid=$_.IdentityReference.Value;rights=[int]$_.FileSystemRights;type=$_.AccessControlType.ToString();inherited=$_.IsInherited;inheritance=[int]$_.InheritanceFlags;propagation=[int]$_.PropagationFlags}})
 $expected=@{'S-1-5-18'=2032127;'S-1-5-32-544'=2032127};$expected[$sid]=1179817;$seen=@{}
 if($records.Count -ne 3){throw 'CUSTODY_ACL_COUNT'}
 foreach($r in $records){if($r.type -cne 'Allow' -or $r.inherited -ne $inherited -or $r.inheritance -ne $inheritance -or $r.propagation -ne 0 -or $seen.ContainsKey($r.sid) -or -not $expected.ContainsKey($r.sid) -or $expected[$r.sid] -ne $r.rights){throw 'CUSTODY_ACL_RULE'};$seen[$r.sid]=$true}
 return [ordered]@{path=$path;ownerSid='S-1-5-18';protected=$directory;acl=$records}
}
function Publish-New([string]$name,$value) {
 $data=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 7 -Compress))
 $s=[IO.File]::Open((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$s.Write($data,0,$data.Length);$s.Flush($true)}finally{$s.Dispose()}
}
$ownerObservation=Assert-Actor
$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
if($disk.FreeSpace -lt 3221225472){throw 'CUSTODY_SPACE'}
$heldDrive=[TertiaryPrivateStage]::Hold('C:\',$true);$drivePin=[TertiaryPrivateStage]::Pin($heldDrive,$true)
$heldParent=$null;$heldRoot=$null;$heldTarget=$null;$created=$false
try {
 $heldParent=[TertiaryPrivateStage]::Hold('C:\ProgramData',$true);$parentPin=[TertiaryPrivateStage]::Pin($heldParent,$true)
 [TertiaryPrivateStage]::Match('C:\',$heldDrive,$drivePin,$true)
 [TertiaryPrivateStage]::CreateExclusive($root,('O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;'+$sid+')'));$created=$true
 $heldRoot=[TertiaryPrivateStage]::Hold($root,$true);$rootPin=[TertiaryPrivateStage]::Pin($heldRoot,$true)
 $target=Join-Path $root 'vpn-control-2.2.2.msi';$heldTarget=[TertiaryPrivateStage]::CreateTargetOwned($target,'S-1-5-18');$targetPin=[TertiaryPrivateStage]::Pin($heldTarget,$false)
 function Assert-Custody {
  [TertiaryPrivateStage]::Match('C:\',$heldDrive,$drivePin,$true)
  [TertiaryPrivateStage]::Match('C:\ProgramData',$heldParent,$parentPin,$true)
  [TertiaryPrivateStage]::Match($root,$heldRoot,$rootPin,$true)
  [TertiaryPrivateStage]::Match($target,$heldTarget,$targetPin,$false)
 }
 Assert-Custody;$acl=Observe-Acl $root $true;$targetAcl=Observe-Acl $target $false;$birth=(Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().Ticks
 $ready=[ordered]@{state='custodian-ready';correlationId=$corr;pid=$PID;birthTicks=$birth;stage=$root;target=$target;targetNativeId=$targetPin;rootNativeId=$rootPin;parentNativeId=$parentPin;driveNativeId=$drivePin;acl=$acl;targetAcl=$targetAcl;ownerObservation=$ownerObservation;installerAction=$false;replayAllowed=$false}
 Publish-New 'custodian-ready.json' $ready;Assert-Custody
 $deadline=[DateTime]::UtcNow.AddSeconds(300);$release=Join-Path $root 'custodian-release.json'
 while(-not [IO.File]::Exists($release)){Assert-Custody;if([DateTime]::UtcNow -ge $deadline){throw 'CUSTODY_DEADLINE'};Start-Sleep -Milliseconds 100}
 Assert-Custody
 $tokenStream=$null
 while($null -eq $tokenStream){
  Assert-Custody;if([DateTime]::UtcNow -ge $deadline){throw 'CUSTODY_RELEASE_DEADLINE'}
  try{$tokenStream=[IO.File]::Open($release,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}catch{if(($_.Exception.InnerException.HResult -band 65535) -ne 32){throw};Start-Sleep -Milliseconds 50}
 }
 try{if($tokenStream.Length -le 0 -or $tokenStream.Length -gt 1024){throw 'CUSTODY_RELEASE_BOUND'};$reader=[IO.StreamReader]::new($tokenStream,[Text.Encoding]::UTF8);$token=$reader.ReadToEnd()|ConvertFrom-Json;if($token.correlationId -cne $corr -or $token.transferCompleted -isnot [bool] -or -not $token.transferCompleted -or $token.pid -ne $PID -or $token.birthTicks -ne $birth -or $token.targetNativeId -cne $targetPin -or ($token.originalFileHandle -isnot [int] -and $token.originalFileHandle -isnot [long]) -or $token.originalFileHandle -le 0){throw 'CUSTODY_RELEASE_IDENTITY'}}finally{$tokenStream.Dispose()}
 # The read stream forbids writes while complete hash and closing generation
 # are measured; no-delete target/ancestor custody has never been released.
 $read=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {
  Assert-Custody;$before=Get-Item -LiteralPath $target -Force -ErrorAction Stop
  if($read.Length -ne $expectedSize){throw 'CUSTODY_TARGET_SIZE'}
  $algorithm=[Security.Cryptography.SHA256]::Create()
  try{$sha=[BitConverter]::ToString($algorithm.ComputeHash($read)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
  if($sha -cne $expectedSha){throw 'CUSTODY_TARGET_HASH'}
  Assert-Custody;$closingOwner=Assert-Actor;$after=Get-Item -LiteralPath $target -Force -ErrorAction Stop
  if($before.Length -ne $after.Length -or $before.CreationTimeUtc.Ticks -ne $after.CreationTimeUtc.Ticks -or $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks){throw 'CUSTODY_TARGET_GENERATION'}
  $closingAcl=Observe-Acl $root $true;$closingTargetAcl=Observe-Acl $target $false
  $complete=[ordered]@{state='custodian-complete';originalFileHandle=$token.originalFileHandle;originalFileClosed=$true;correlationId=$corr;pid=$PID;birthTicks=$birth;stage=$root;targetNativeId=$targetPin;rootNativeId=$rootPin;sha256=$sha;length=$read.Length;targetBirthTicks=$after.CreationTimeUtc.Ticks;targetWriteTicks=$after.LastWriteTimeUtc.Ticks;acl=$closingAcl;targetAcl=$closingTargetAcl;ownerObservation=$closingOwner;installerAction=$false;replayAllowed=$false}
  Publish-New 'custodian-complete.json' $complete;Assert-Custody
  [Console]::Out.WriteLine(($complete|ConvertTo-Json -Depth 7 -Compress))
 }finally{$read.Dispose()}
} catch {
 if($created){try{Publish-New 'custodian-unknown.json' ([ordered]@{state='unknown';correlationId=$corr;pid=$PID;errorType=$_.Exception.GetType().FullName;errorDetail=$_.Exception.Message;installerAction=$false;replayAllowed=$false})}catch{}}
 throw
} finally {if($heldTarget){$heldTarget.Dispose()};if($heldRoot){$heldRoot.Dispose()};if($heldParent){$heldParent.Dispose()};$heldDrive.Dispose()}
'''


def decode_lock_png(data):
    """Decode only the exact bounded QMP truecolor8, noninterlaced 1280x800 PNG."""
    import struct,zlib
    if not isinstance(data,bytes)or len(data)>1048576 or not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('TERTIARY_LOCK_PNG')
    pos=8;compressed=bytearray();header=False;ended=False
    while pos<len(data):
        if pos+12>len(data):raise ValueError('TERTIARY_LOCK_CHUNK')
        size=struct.unpack('>I',data[pos:pos+4])[0];kind=data[pos+4:pos+8];body=data[pos+8:pos+8+size]
        if size>1048576 or pos+12+size>len(data)or zlib.crc32(kind+body)&0xffffffff!=struct.unpack('>I',data[pos+8+size:pos+12+size])[0]:
            raise ValueError('TERTIARY_LOCK_CRC')
        pos+=size+12
        if kind==b'IHDR':
            if header or len(body)!=13 or struct.unpack('>IIBBBBB',body)!=(1280,800,8,2,0,0,0):raise ValueError('TERTIARY_LOCK_LAYOUT')
            header=True
        elif kind==b'IDAT':
            if not header or ended:raise ValueError('TERTIARY_LOCK_ORDER')
            compressed.extend(body)
        elif kind==b'IEND':
            if body or pos!=len(data):raise ValueError('TERTIARY_LOCK_END')
            ended=True;break
        elif kind[0]&32==0:raise ValueError('TERTIARY_LOCK_CRITICAL_CHUNK')
    if not header or not ended:raise ValueError('TERTIARY_LOCK_INCOMPLETE')
    stride=3840;expected=800*(stride+1);decoder=zlib.decompressobj();raw=decoder.decompress(bytes(compressed),expected+1)
    if len(raw)!=expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:raise ValueError('TERTIARY_LOCK_DEFLATE')
    pixels=bytearray(800*stride);previous=bytearray(stride)
    for y in range(800):
        start=y*(stride+1);kind=raw[start];row=bytearray(raw[start+1:start+1+stride])
        if kind>4:raise ValueError('TERTIARY_LOCK_FILTER')
        for x in range(stride):
            left=row[x-3]if x>=3 else 0;above=previous[x];corner=previous[x-3]if x>=3 else 0
            if kind==1:value=left
            elif kind==2:value=above
            elif kind==3:value=(left+above)//2
            elif kind==4:
                p=left+above-corner;a=abs(p-left);b=abs(p-above);c=abs(p-corner)
                value=left if a<=b and a<=c else above if b<=c else corner
            else:value=0
            row[x]=(row[x]+value)&255
        pixels[y*stride:(y+1)*stride]=row;previous=row
    return bytes(pixels)


LOCK_CLOCK_RECT=(530,140,750,224)
LOCK_ROLE_SHA256='11b87590a5d1d4a4ecf8c685c6524542cd453c54545287e73b7f294137544456'


def lock_role_digest(data):
    """Only the reviewed clock rectangle is excluded; every other pixel binds."""
    pixels=bytearray(decode_lock_png(data));left,top,right,bottom=LOCK_CLOCK_RECT
    for y in range(top,bottom):pixels[(y*1280+left)*3:(y*1280+right)*3]=bytes((right-left)*3)
    return hashlib.sha256(pixels).hexdigest()


def known_lock_frame(data):
    return lock_role_digest(data)==LOCK_ROLE_SHA256



def decode_native_source(encoded, expected_size, expected_sha256):
    """Strict one-frame gzip carrier; bounded full source identity before execution."""
    import base64,hashlib,re,zlib
    if (type(expected_size)is not int or not 0<expected_size<=131000
        or not isinstance(expected_sha256,str) or not re.fullmatch('[0-9a-f]{64}',expected_sha256)
        or not isinstance(encoded,str) or len(encoded)>65536):
        raise ValueError('TERTIARY_NATIVE_SOURCE_BOUND')
    try:
        packed=base64.b64decode(encoded,validate=True)
        if not 0<len(packed)<=49152:raise ValueError('TERTIARY_NATIVE_GZIP_BOUND')
        decoder=zlib.decompressobj(31)
        raw=decoder.decompress(packed,expected_size+1)
        if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(raw)!=expected_size or hashlib.sha256(raw).hexdigest()!=expected_sha256):
            raise ValueError('TERTIARY_NATIVE_SOURCE_IDENTITY')
        return raw.decode('utf-8',errors='strict')
    except (ValueError,zlib.error,UnicodeError) as error:
        raise ValueError('TERTIARY_NATIVE_SOURCE_FRAMING') from error


def compressed_native_wrapper(program):
    """Carry this fixed reviewed native source below the SSH mux command budget.

    No SSH, credential read, guest process, or source execution occurs here.
    Caller admission must close the exact generated bytes and configured argv.
    """
    import gzip,hashlib,inspect
    if not isinstance(program,str):raise ValueError('TERTIARY_NATIVE_PROGRAM_TYPE')
    raw=program.encode('utf-8',errors='strict')
    if not 0<len(raw)<=131000:raise ValueError('TERTIARY_NATIVE_PROGRAM_BOUND')
    compile(program,'reviewed tertiary native source','exec')
    packed=gzip.compress(raw,compresslevel=9,mtime=0)
    encoded=base64.b64encode(packed).decode('ascii')
    digest=hashlib.sha256(raw).hexdigest()
    # Exercise the same decoder emitted below before returning any wrapper.
    if decode_native_source(encoded,len(raw),digest)!=program:
        raise ValueError('TERTIARY_NATIVE_PROGRAM_ROUNDTRIP')
    wrapper=('import sys,subprocess\n'+inspect.getsource(decode_native_source)+'\n'
             +'PROGRAM=decode_native_source('+repr(encoded)+','+str(len(raw))+','+repr(digest)+')\n'
             +"secret=sys.stdin.buffer.read(513)\nif not 1<=len(secret)<=512 or b'\\0' in secret:raise SystemExit(2)\n"
             +"if not secret.endswith(b'\\n'):secret+=b'\\n'\n"
             +"p=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',PROGRAM],stdin=subprocess.PIPE,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer)\n"
             +"p.stdin.write(secret);p.stdin.close();secret=None\nraise SystemExit(p.wait())\n")
    if len(wrapper.encode('utf-8'))>49152:raise ValueError('TERTIARY_NATIVE_WRAPPER_BOUND')
    compile(wrapper,'reviewed tertiary compressed wrapper','exec')
    return wrapper


PUBLIC6_SHA256 = hashlib.sha256(b'PUBLIC').hexdigest()


def public6_ready_script(correlation, pid):
    """One bounded read of the original producer's create-only readiness file."""
    import uuid
    if str(uuid.UUID(correlation)) != correlation or type(pid)is not int or pid<=0:
        raise ValueError('PUBLIC6_READY_BINDING')
    root=r'C:\ProgramData\VpnControlTertiaryStageProbe-'+correlation
    return "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$root='"+root+"';$corr='"+correlation+"';$ownerPid="+str(pid)+";"+r'''
$deadline=[DateTime]::UtcNow.AddSeconds(20);$path=Join-Path $root 'qga-ready.json';$stream=$null
while($null -eq $stream){
 $owner=Get-Process -Id $ownerPid -ErrorAction Stop
 if([DateTime]::UtcNow -ge $deadline){throw 'PUBLIC6_READY_DEADLINE'}
 if([IO.File]::Exists($path)){try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}catch{if(($_.Exception.InnerException.HResult -band 65535) -ne 32){throw}}}
 if($null -eq $stream){Start-Sleep -Milliseconds 50}
}
try{
 if($stream.Length -le 0 -or $stream.Length -gt 2048){throw 'PUBLIC6_READY_BOUND'}
 $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8);$raw=$reader.ReadToEnd();$ready=$raw|ConvertFrom-Json
 if($ready.correlationId -cne $corr -or $ready.root -cne $root -or $ready.target -cne (Join-Path $root 'owned.msi') -or $ready.pid -ne $ownerPid -or $ready.birthTicks -ne (Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().Ticks){throw 'PUBLIC6_READY_IDENTITY'}
 [Console]::Out.WriteLine($raw)
}finally{$stream.Dispose()}
'''


def public6_release_script(correlation, ready, handle):
    """CreateNew release only after the original QGA file close is confirmed."""
    import json
    validate_public6_ready(correlation,ready['pid'],ready)
    if type(handle)is not int or handle<=0:raise ValueError('PUBLIC6_RELEASE_HANDLE')
    token={k:ready[k] for k in ('pid','birthTicks','targetNativeId')}
    token.update(correlationId=correlation,originalFileHandle=handle,closed=True)
    encoded=base64.b64encode(json.dumps(token,sort_keys=True,separators=(',',':')).encode()).decode()
    return "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$path='"+ready['root']+r"\qga-release.json';$ownerPid="+str(ready['pid'])+";$birth="+str(ready['birthTicks'])+";$data=[Convert]::FromBase64String('"+encoded+"');"+r'''
if((Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().Ticks -ne $birth){throw 'PUBLIC6_RELEASE_OWNER'}
$s=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$s.Write($data,0,$data.Length);$s.Flush($true)}finally{$s.Dispose()}
[Console]::Out.WriteLine('{"releaseCreated":true}')
'''


def validate_public6_ready(correlation,pid,ready):
    root=r'C:\ProgramData\VpnControlTertiaryStageProbe-'+correlation
    if (type(ready)is not dict or set(ready)!={'correlationId','pid','birthTicks','root','target','targetNativeId','rootNativeId'}
        or ready['correlationId']!=correlation or type(ready['pid'])is not int or ready['pid']!=pid
        or type(ready['birthTicks'])is not int or ready['birthTicks']<=0 or ready['root']!=root or ready['target']!=root+r'\owned.msi'
        or any(type(ready[k])is not str or not 0<len(ready[k])<160 for k in ('targetNativeId','rootNativeId'))):
        raise ValueError('PUBLIC6_READY_IDENTITY')
    return ready


def public6_qga_handshake(client,correlation,pid,ps_once,guard,record):
    """Finite test-only PUBLIC write on one original handle held by one producer.

    ps_once retains each original guest PID/terminal; guard binds current peer,
    producer and source. Failure never reopens, retries uncertain operations or
    publishes release. Projection tests are not native sharing proof.
    """
    handle=None;transferred=0;calls=0;operation='ready';closed=False
    deadline=time.monotonic()+45;original_timeout=client.timeout_seconds
    client._stage_deadline=deadline
    def current():
        guard()
        if time.monotonic()>=deadline:raise TimeoutError('PUBLIC6_DEADLINE')
    def exchange(command,args):
        nonlocal calls,operation
        current();operation=command
        if calls>=9:raise ValueError('PUBLIC6_CALL_BUDGET')
        calls+=1  # actual socket deadline is clipped by StageDeadlineMixin
        result=client._exchange(command,args);return result
    try:
        if type(original_timeout)not in (int,float)or not 0<original_timeout<=3:raise ValueError('PUBLIC6_TIMEOUT')
        current();ready=ps_once('public-six-ready',public6_ready_script(correlation,pid),True);current()
        validate_public6_ready(correlation,pid,ready);record('public-six-ready-observed.json',ready)
        record('public-six-open-intent.json',dict(ready,mode='wb',replayAllowed=False))
        handle=exchange('guest-file-open',{'path':ready['target'],'mode':'wb'})
        if type(handle)is not int or handle<=0:raise ValueError('PUBLIC6_HANDLE')
        record('public-six-opened.json',{'originalHandle':handle});current()
        while transferred<6:
            part=b'PUBLIC'[transferred:]
            result=exchange('guest-file-write',{'handle':handle,'buf-b64':base64.b64encode(part).decode()})
            count=result.get('count') if type(result)is dict else None
            if type(count)is not int or not 0<count<=len(part):raise ValueError('PUBLIC6_WRITE_COUNT')
            transferred+=count;record('public-six-write-'+('one','two','three','four','five','six','seven','eight','nine')[calls-1]+'.json',{'originalHandle':handle,'count':count,'transferred':transferred});current()
        exchange('guest-file-flush',{'handle':handle});current();exchange('guest-file-close',{'handle':handle});closed=True
        record('public-six-closed.json',{'originalHandle':handle,'closed':True,'length':6,'sha256':PUBLIC6_SHA256})
        current();operation='release';released=ps_once('public-six-release',public6_release_script(correlation,ready,handle),False)
        if type(released)is not dict or released.get('releaseCreated')is not True:raise ValueError('PUBLIC6_RELEASE_RECEIPT')
        return {'ready':ready,'originalHandle':handle,'closed':True,'transferred':transferred,'calls':calls}
    except BaseException as error:
        unknown=GuestWriteUnknown(error,handle,transferred,calls,operation)
        unknown.closed=closed;raise unknown from error
    finally:
        del client._stage_deadline


def validate_public6_receipt(receipt,handshake):
    control=receipt.get('releaseGuardControl')
    wanted_control={'oldLongForeignAccepted':True,'fixedForeignRefused':True,'positiveIntAndLongAccepted':True,'cases':10}
    if type(control)is not dict or set(control)!=set(wanted_control)or any(type(control[k])is not type(v)or control[k]!=v for k,v in wanted_control.items()):
        raise ValueError('PUBLIC6_RELEASE_GUARD_CONTROL')
    q=receipt.get('qgaControl');ready=handshake['ready']
    expected={k:ready[k]for k in ('pid','birthTicks','target','targetNativeId','rootNativeId')}
    expected.update(originalFileHandle=handshake['originalHandle'],closed=True,length=6,sha256=PUBLIC6_SHA256,heldAndNamedIdentityClosed=True)
    if type(q)is not dict or set(q)!=set(expected) or any(type(q[k])is not type(v)or q[k]!=v for k,v in expected.items()):
        raise ValueError('PUBLIC6_TERMINAL_BINDING')
    share=receipt.get('shareControl')
    wanted={'metadataFileRenamed':True,'metadataDirectoryRenamed':True,'participatingFileRenameRefused':True,'participatingDirectoryRenameRefused':True,'fileRenameError':32,'directoryRenameError':32,'compatibleWriterObserved':True,'heldAndNamedIdentityClosed':True}
    if type(share)is not dict or set(share)!=set(wanted)or any(type(share[k])is not type(v)or share[k]!=v for k,v in wanted.items()):
        raise ValueError('PUBLIC6_SHARE_CONTROL')
    return q


def missing_optional_probe_record(name,error):
    """Absent optional diagnostic record cannot suppress original terminal read."""
    allowed={'public6-ready-started.json','public6-ready-terminal.json','public6-ready-observed.json','public6-open-intent.json','unknown.json'}
    if name not in allowed or type(error)is not FileNotFoundError or error.errno!=2:
        raise ValueError('TERTIARY_OPTIONAL_RECORD_ERROR') from error
    return {'name':name,'present':False,'diagnosticOnly':True,'authority':False}


HISTORICAL_RELEASE_PREDICATE = '$token.correlationId -cne $corr -or $token.pid -ne $PID -or $token.birthTicks -ne $birth -or $token.targetNativeId -cne $filePin -or $token.originalFileHandle -isnot [int] -and $token.originalFileHandle -isnot [long] -or $token.originalFileHandle -le 0 -or $token.closed -isnot [bool] -or -not $token.closed'


def release_guard_predicate():
    return HISTORICAL_RELEASE_PREDICATE.replace('$token.originalFileHandle -isnot [int] -and $token.originalFileHandle -isnot [long]', '($token.originalFileHandle -isnot [int] -and $token.originalFileHandle -isnot [long])')


def release_guard_control_script():
    """Actual in-memory Windows old/new producer predicate causal control."""
    old=HISTORICAL_RELEASE_PREDICATE.replace("'","''")
    new=release_guard_predicate().replace("'","''")
    return "$releaseGuardControl=&{$oldGuard=[ScriptBlock]::Create('"+old+"');$newGuard=[ScriptBlock]::Create('"+new+"');"+r'''
$corr='PUBLIC-CORRELATION';$birth=[long]123456789;$filePin='PUBLIC-NATIVE-ID';$cases=0
foreach($kind in @('int','long')){
 foreach($foreign in @('none','correlationId','pid','birthTicks','targetNativeId')){
  $h=if($kind -ceq 'int'){[int]71}else{[long]71}
  $token=[pscustomobject]@{correlationId=$corr;pid=$PID;birthTicks=$birth;targetNativeId=$filePin;originalFileHandle=$h;closed=$true}
  switch($foreign){'correlationId'{$token.correlationId='FOREIGN'};'pid'{$token.pid=$PID+1};'birthTicks'{$token.birthTicks=$birth+1};'targetNativeId'{$token.targetNativeId='FOREIGN'}}
  $oldRefuses=&$oldGuard;$newRefuses=&$newGuard
  if($foreign -ceq 'none'){if($oldRefuses -or $newRefuses){throw 'RELEASE_POSITIVE_CONTROL'}}
  else{if(-not $newRefuses){throw 'RELEASE_FOREIGN_ACCEPTED'};if($kind -ceq 'long' -and $oldRefuses){throw 'RELEASE_OLD_RED_NOT_REPRODUCED'}}
  $cases++
 }
}
return [ordered]@{oldLongForeignAccepted=$true;fixedForeignRefused=$true;positiveIntAndLongAccepted=$true;cases=$cases}
}
'''



def validate_target_custody_acl(root_acl,target_acl,request):
    """Finite native root AND file owner/inheritance closure; no admission grant."""
    sid=request['expectedSid'];directory=request['guestStage']
    expected={'S-1-5-18':2032127,'S-1-5-32-544':2032127,sid:1179817}
    for value,path,protected in ((root_acl,directory,True),(target_acl,directory+r'\vpn-control-2.2.2.msi',False)):
        if (type(value)is not dict or set(value)!={'path','ownerSid','protected','acl'} or value['path']!=path
            or value['ownerSid']!='S-1-5-18' or value['protected']is not protected or type(value['acl'])is not list or len(value['acl'])!=3):
            raise ValueError('TERTIARY_TARGET_ACL_OWNER')
        seen={}
        for row in value['acl']:
            if (type(row)is not dict or set(row)!={'sid','rights','type','inherited','inheritance','propagation'}
                or type(row['sid'])is not str or row['sid']not in expected or row['sid']in seen
                or type(row['rights'])is not int or row['rights']!=expected[row['sid']] or row['type']!='Allow'
                or row['inherited']is not (not protected) or type(row['inheritance'])is not int or row['inheritance']!=(3 if protected else 0)
                or type(row['propagation'])is not int or row['propagation']!=0):
                raise ValueError('TERTIARY_TARGET_ACL_RULE')
            seen[row['sid']]=row['rights']
    return True


def target_ready_script(request,correlation,pid):
    """Bounded current original custodian readiness, no absence admission."""
    validate_target_request(request,correlation)
    if type(pid)is not int or pid<=0:raise ValueError('TARGET_READY_PID')
    return "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$root='"+request['guestStage']+"';$corr='"+correlation+"';$ownerPid="+str(pid)+";"+r'''
$deadline=[DateTime]::UtcNow.AddSeconds(30);$path=Join-Path $root 'custodian-ready.json';$stream=$null
while($null -eq $stream){
 $owner=Get-Process -Id $ownerPid -ErrorAction Stop
 if([DateTime]::UtcNow -ge $deadline){throw 'TARGET_READY_DEADLINE'}
 if([IO.File]::Exists($path)){try{$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)}catch{if(($_.Exception.InnerException.HResult -band 65535) -ne 32){throw}}}
 if($null -eq $stream){Start-Sleep -Milliseconds 50}
}
try{
 if($stream.Length -le 0 -or $stream.Length -gt 12000){throw 'TARGET_READY_BOUND'}
 $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8);$raw=$reader.ReadToEnd();$ready=$raw|ConvertFrom-Json
 if($ready.state -cne 'custodian-ready' -or $ready.correlationId -cne $corr -or $ready.stage -cne $root -or $ready.target -cne (Join-Path $root 'vpn-control-2.2.2.msi') -or $ready.pid -ne $ownerPid -or $ready.birthTicks -ne (Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().Ticks){throw 'TARGET_READY_IDENTITY'}
 [Console]::Out.WriteLine($raw)
}finally{$stream.Dispose()}
'''


def target_release_script(request,correlation,ready,handle):
    """Fixed CreateNew token; one positively closed original QGA handle only."""
    import json
    validate_target_request(request,correlation)
    if (type(handle)is not int or handle<=0 or type(ready)is not dict or ready.get('correlationId')!=correlation
        or ready.get('stage')!=request['guestStage'] or type(ready.get('pid'))is not int or ready['pid']<=0
        or type(ready.get('birthTicks'))is not int or ready['birthTicks']<=0
        or type(ready.get('targetNativeId'))is not str or not 0<len(ready['targetNativeId'])<160):
        raise ValueError('TARGET_RELEASE_BINDING')
    token={k:ready[k]for k in ('pid','birthTicks','targetNativeId')}
    token.update(correlationId=correlation,originalFileHandle=handle,transferCompleted=True)
    encoded=base64.b64encode(json.dumps(token,sort_keys=True,separators=(',',':')).encode()).decode()
    return "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$path='"+request['guestStage']+r"\custodian-release.json';$ownerPid="+str(ready['pid'])+";$birth="+str(ready['birthTicks'])+";$data=[Convert]::FromBase64String('"+encoded+"');"+r'''
if((Get-Process -Id $ownerPid -ErrorAction Stop).StartTime.ToUniversalTime().Ticks -ne $birth){throw 'TARGET_RELEASE_OWNER'}
$s=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$s.Write($data,0,$data.Length);$s.Flush($true)}finally{$s.Dispose()}
[Console]::Out.WriteLine('{"releaseCreated":true}')
'''


def validate_custody_owner(observed):
    expected='S-1-5-21-606332539-4179368406-55829832-1000'
    if (type(observed)is not dict or observed.get('observerSid')!='S-1-5-18'
        or observed.get('interactiveUser')!='VPNPARITYX64'+chr(92)+'parityagent' or observed.get('interactiveSid')!=expected
        or type(observed.get('session'))is not int or observed['session']!=1 or observed.get('processCensusComplete')is not True
        or type(observed.get('processCount'))is not int or observed['processCount']<=0 or observed.get('effectOwners')!=[]
        or observed.get('publicOFF')!='UNRESOLVED'):
        raise ValueError('TERTIARY_TARGET_CURRENT_OWNER')
    return True


# Fixed tertiary composition; generated only under separate dispatcher admission.
TARGET_STAGE_BODY = "# SOURCE-ONLY fixed tertiary QGA staging and read-only MSI observation.\nfd=None;source_fd=None;host_fd=None;handle=None;custodian_pid=None;custodian_terminal=None;native_failure=None\nvalue={'state':'unknown','reason':'tertiary-target-stage','installerAction':False,'productAcceptance':False,'replayAllowed':False}\nphase='host-admission';transferred=0\nclass BoundAccessClient(StageDeadlineMixin,AccessClient):\n def _exchange(self,command,args):\n  self.calls=getattr(self,'calls',0)+1\n  need(self.calls<=40000,'tertiary-stage-total-call-budget')\n  return super()._exchange(command,args)\ntry:\n validate_target_retry_binding(HOST_STAGE_REQUEST,STAGE_REQUEST,CORRELATION)\n need(os.geteuid()==0,'tertiary-stage-privilege');proc=Path('/proc');protected=tertiary_phase(proc,PROOF)\n row=NEWBOOT['guests'][0];need(row['pid']==3847348 and row['startTicks']==22216504 and row['uid']==1000,'tertiary-stage-identity');observed_process(proc,row)\n pp=int((proc/str(row['pid'])/'stat').read_text().rsplit(')',1)[1].split()[1]);need(pp==3847343 and process_birth(proc,pp)==22216490,'tertiary-stage-parent')\n parent={'pid':pp,'startTicks':22216490,'uid':0,'binary':PROOF['original']['supervisor']['binary']};observed_process(proc,parent,BOOT_PROGRAM_SHA)\n guest=fixed_guest('tertiary');state=guest.root/'vm-r-e7e110ff';sock=state/'qga.sock';sstat=sock.lstat();need(stat.S_ISSOCK(sstat.st_mode)and sstat.st_uid==1000,'tertiary-stage-socket')\n host=Path(STAGE_REQUEST['hostStage']);host_fd=os.open(host,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);hst=os.fstat(host_fd);need(generation(hst)==generation(host.lstat()),'tertiary-stage-host-held-name');need(stat.S_ISDIR(hst.st_mode)and hst.st_uid==1000 and stat.S_IMODE(hst.st_mode)==0o700,'tertiary-stage-host-directory')\n need(set(os.listdir(host))=={'binding.json','upload-intent.json','target.msi','complete.json'},'tertiary-stage-host-census')\n for n in ('binding.json','upload-intent.json','complete.json','target.msi'):\n  i=(host/n).lstat();need(stat.S_ISREG(i.st_mode)and i.st_uid==1000 and i.st_nlink==1 and stat.S_IMODE(i.st_mode)==0o600,'tertiary-stage-host-file')\n need(json.loads((host/'binding.json').read_bytes())==HOST_STAGE_REQUEST,'tertiary-stage-host-binding')\n need(json.loads((host/'complete.json').read_bytes())=={'state':'staged','sha256':STAGE_REQUEST['targetSha256'],'length':STAGE_REQUEST['targetSize']},'tertiary-stage-host-complete')\n source=host/'target.msi';source_fd=os.open('target.msi',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=host_fd);spin=generation(os.fstat(source_fd));need(spin==generation(source.lstat())and spin[6]==STAGE_REQUEST['targetSize'],'tertiary-stage-source-generation')\n digest=hashlib.sha256()\n while True:\n  part=os.read(source_fd,65536)\n  if not part:break\n  digest.update(part)\n need(digest.hexdigest()==STAGE_REQUEST['targetSha256']and generation(os.fstat(source_fd))==spin==generation(source.lstat()),'tertiary-stage-source-hash');os.lseek(source_fd,0,0)\n need(os.statvfs(host).f_bavail*os.statvfs(host).f_frsize>=3*(1<<30),'tertiary-stage-host-space')\n journal=guest.root/('target-stage-'+CORRELATION);journal.mkdir(mode=0o700);fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);pin=parent_identity(os.fstat(fd))\n prepare.record_at(fd,'intent.json',{'correlationId':CORRELATION,'stageRequest':STAGE_REQUEST,'actions':['one-bounded-native-custodian','one-original-QGA-file-handle-write','readonly-MSI-database','explicit-custodian-terminal-handoff'],'installerAction':False,'replayAllowed':False})\n client=BoundAccessClient(str(sock),timeout_seconds=3,max_response_bytes=16384).bind({'rootFd':fd},guest,row)\n def guard(custodian_live=True):\n  global native_failure\n  observed_process(proc,row);observed_process(proc,parent,BOOT_PROGRAM_SHA)\n  need(tertiary_phase(proc,PROOF)==protected and generation(sock.lstat())==generation(sstat)and generation(os.fstat(source_fd))==spin==generation(source.lstat())and generation(os.fstat(host_fd))==generation(host.lstat())==generation(hst),'tertiary-stage-current-closure')\n  if custodian_live and custodian_pid is not None:\n   status=client.guest_exec_status(custodian_pid)\n   if status.get('exited')is True:\n    prepare.record_at(fd,'custodian-unexpected-terminal.json',status)\n    native_failure=terminal_failure_projection(custodian_pid,status,str(journal/'custodian-unexpected-terminal.json'));raise ValueError('tertiary-custodian-terminal-before-handoff')\n   need(status.get('exited')is False,'tertiary-custodian-state')\n def ps_once(name,script,post_custodian_live=True):\n  global native_failure\n  guard();prepare.record_at(fd,name+'-intent.json',{'scriptSha256':hashlib.sha256(script.encode()).hexdigest(),'submitted':True,'replayAllowed':False})\n  created=client._exchange('guest-exec',{'path':r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoLogo','-NoProfile','-NonInteractive','-Command',script],'capture-output':True})\n  need(type(created)is dict and type(created.get('pid'))is int and created['pid']>0,'tertiary-stage-guest-pid');prepare.record_at(fd,name+'-started.json',created)\n  deadline=time.monotonic()+60\n  while True:\n   guard(custodian_live=post_custodian_live);result=client.guest_exec_status(created['pid']);guard(custodian_live=post_custodian_live)\n   if result.get('exited')is True:break\n   need(time.monotonic()<deadline,'tertiary-stage-guest-deadline');time.sleep(.25)\n  prepare.record_at(fd,name+'-terminal.json',result)\n  if not(type(result.get('exitcode'))is int and result['exitcode']==0 and result.get('out-truncated',False)is False and result.get('err-truncated',False)is False):\n   native_failure=terminal_failure_projection(created['pid'],result,str(journal/(name+'-terminal.json')));raise ValueError('tertiary-stage-guest-terminal')\n  raw=base64.b64decode(result.get('out-data',''),validate=True);need(0<len(raw)<=12000,'tertiary-stage-output-bound')\n  guard(custodian_live=post_custodian_live);return json.loads(raw.decode('utf-8-sig'))\n\n client._exchange('guest-ping',{});guard()\n phase='custodian-start';prepare.record_at(fd,'custodian-intent.json',{'scriptSha256':hashlib.sha256(CUSTODIAN_SCRIPT.encode()).hexdigest(),'submitted':True,'replayAllowed':False})\n created=client._exchange('guest-exec',{'path':r'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','arg':['-NoLogo','-NoProfile','-NonInteractive','-Command',CUSTODIAN_SCRIPT],'capture-output':True})\n need(type(created)is dict and type(created.get('pid'))is int and created['pid']>0,'tertiary-custodian-pid');custodian_pid=created['pid'];prepare.record_at(fd,'custodian-started.json',created)\n phase='custodian-ready';ready=ps_once('custodian-ready-read',target_ready_script(STAGE_REQUEST,CORRELATION,custodian_pid))\n need(ready.get('state')=='custodian-ready' and ready.get('correlationId')==CORRELATION and type(ready.get('pid'))is int and ready['pid']==custodian_pid and type(ready.get('birthTicks'))is int and ready['birthTicks']>0 and ready.get('stage')==STAGE_REQUEST['guestStage'],'tertiary-custodian-ready-identity')\n destination=STAGE_REQUEST['guestStage']+r'\\vpn-control-2.2.2.msi';need(ready.get('target')==destination,'tertiary-custodian-target')\n validate_target_custody_acl(ready['acl'],ready['targetAcl'],STAGE_REQUEST);validate_custody_owner(ready['ownerObservation'])\n for key in ('targetNativeId','rootNativeId','parentNativeId','driveNativeId'):need(type(ready.get(key))is str and 0<len(ready[key])<160,'tertiary-custodian-native-identity')\n prepare.record_at(fd,'custodian-ready-observed.json',ready)\n phase='open-file';guard();prepare.record_at(fd,'file-open-intent.json',{'path':destination,'mode':'wb','custodianPid':custodian_pid,'custodianBirthTicks':ready['birthTicks'],'targetNativeId':ready['targetNativeId'],'submitted':True,'replayAllowed':False})\n handle=client._exchange('guest-file-open',{'path':destination,'mode':'wb'});need(type(handle)is int and handle>0,'tertiary-stage-file-handle');prepare.record_at(fd,'file-opened.json',{'handle':handle})\n original_file_handle=handle\n phase='write-file';written=write_target(client,source_fd,handle,guard);transferred=written['transferred']\n need(written['closed']is True and transferred==STAGE_REQUEST['targetSize'] and written['sha256']==STAGE_REQUEST['targetSha256'],'tertiary-stage-stream-closure')\n prepare.record_at(fd,'file-closed.json',{'originalHandle':handle,**written});handle=None\n phase='MSI-metadata';metadata=ps_once('msi-metadata',INSPECT_SCRIPT)\n need(metadata['sha256']==STAGE_REQUEST['targetSha256'] and type(metadata['length'])is int and metadata['length']==STAGE_REQUEST['targetSize'] and type(metadata['databaseMode'])is int and metadata['databaseMode']==0 and metadata.get('observerSid')=='S-1-5-18','tertiary-stage-readback')\n phase='custodian-release';released=ps_once('custodian-release',target_release_script(STAGE_REQUEST,CORRELATION,ready,original_file_handle),post_custodian_live=False)\n need(released.get('releaseCreated')is True,'tertiary-custodian-release')\n # Completion is observed through the original registered QGA guest PID.\n # Do not call guard() here: an expected terminal handoff is now permitted.\n deadline=time.monotonic()+60\n while True:\n  observed_process(proc,row);observed_process(proc,parent,BOOT_PROGRAM_SHA)\n  need(tertiary_phase(proc,PROOF)==protected and generation(sock.lstat())==generation(sstat),'tertiary-custodian-terminal-owner')\n  custodian_terminal=client.guest_exec_status(custodian_pid)\n  if custodian_terminal.get('exited')is True:break\n  need(custodian_terminal.get('exited')is False and time.monotonic()<deadline,'tertiary-custodian-terminal-deadline');time.sleep(.25)\n prepare.record_at(fd,'custodian-terminal.json',custodian_terminal)\n if not(type(custodian_terminal.get('exitcode'))is int and custodian_terminal['exitcode']==0 and custodian_terminal.get('out-truncated',False)is False and custodian_terminal.get('err-truncated',False)is False):\n  native_failure=terminal_failure_projection(custodian_pid,custodian_terminal,str(journal/'custodian-terminal.json'));raise ValueError('tertiary-custodian-terminal')\n raw=base64.b64decode(custodian_terminal.get('out-data',''),validate=True);need(0<len(raw)<=12000,'tertiary-custodian-terminal-bound');complete=json.loads(raw.decode('utf-8-sig'))\n need(complete.get('state')=='custodian-complete' and complete.get('correlationId')==CORRELATION and type(complete.get('pid'))is int and complete['pid']==custodian_pid and type(complete.get('birthTicks'))is int and complete['birthTicks']==ready['birthTicks'] and complete.get('stage')==STAGE_REQUEST['guestStage'] and complete.get('targetNativeId')==ready['targetNativeId'] and complete.get('rootNativeId')==ready['rootNativeId'] and complete.get('sha256')==STAGE_REQUEST['targetSha256'] and type(complete.get('length'))is int and complete['length']==STAGE_REQUEST['targetSize'],'tertiary-custodian-final-binding')\n validate_target_custody_acl(complete['acl'],complete['targetAcl'],STAGE_REQUEST);validate_custody_owner(complete['ownerObservation']);need(type(complete.get('originalFileHandle'))is int and complete['originalFileHandle']==original_file_handle and complete.get('originalFileClosed')is True,'tertiary-custodian-original-close');custodian_pid=None\n guard();need(pin==parent_identity(os.fstat(fd))==parent_identity(journal.lstat()),'tertiary-stage-journal-closing')\n os.lseek(source_fd,0,0);closing_digest=hashlib.sha256()\n while True:\n  part=os.read(source_fd,65536)\n  if not part:break\n  closing_digest.update(part)\n need(closing_digest.hexdigest()==STAGE_REQUEST['targetSha256'] and generation(os.fstat(source_fd))==spin==generation(source.lstat()),'tertiary-stage-source-closing-hash')\n value={'state':'tertiary-target-staged','correlationId':CORRELATION,'guestStage':STAGE_REQUEST['guestStage'],'transferred':transferred,'custodian':complete,'metadata':metadata,'journal':str(journal),'installerAction':False,'productAcceptance':False,'publicOFF':'UNRESOLVED','replayAllowed':False};prepare.record_at(fd,'result.json',value)\nexcept BaseException as error:\n value=dict(value,phase=phase,errorType=type(error).__name__,errorDetail=str(error)[:256],transferred=getattr(error,'transferred',transferred),originalGuestFileHandle=handle,originalCustodianPid=custodian_pid,terminalDiagnostic=native_failure)\n if fd is not None:prepare.record_at(fd,'unknown.json',value)\nfinally:\n if source_fd is not None:os.close(source_fd)\n if host_fd is not None:os.close(host_fd)\nprint(json.dumps(value,sort_keys=True),flush=True)\n"


def target_owner_probe_script(*, system_guest=False, correlation=None):
    """One disposable native control; production SYSTEM remains separately bound."""
    if type(system_guest)is not bool:raise ValueError('TERTIARY_OWNER_CONTROL_SCOPE')
    if system_guest:
        import uuid
        if str(uuid.UUID(correlation))!=correlation:raise ValueError('TERTIARY_OWNER_CORRELATION')
        root_line="$root='C:\\ProgramData\\VpnControlTertiaryOwnerControl-"+correlation+"'\n"
        actor_line="if((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName -cne 'VPNPARITYX64\\parityagent'){throw 'OWNER_INTERACTIVE'};if((New-Object Security.Principal.NTAccount('VPNPARITYX64\\parityagent')).Translate([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-21-606332539-4179368406-55829832-1000'){throw 'OWNER_INTERACTIVE_SID'};if((@(Get-Process -Name explorer -ErrorAction Stop|Select-Object -ExpandProperty SessionId -Unique) -join ',') -cne '1'){throw 'OWNER_SESSION'}\n"
    else:
        root_line="$root=Join-Path ([IO.Path]::GetTempPath()) ('VpnControlOwnerControl-'+[Guid]::NewGuid().ToString('D'))\n"
        actor_line=''
    return ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "Add-Type -TypeDefinition @'\n"+PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"
            "$requireSystem="+('$true'if system_guest else'$false')+'\n'+root_line+actor_line+r'''
$ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($requireSystem -and $ownerSid -cne 'S-1-5-18'){throw 'OWNER_SYSTEM_ACTOR'}
$sddl='O:'+$ownerSid+'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
if($ownerSid -notin @('S-1-5-18','S-1-5-32-544')){$sddl+='(A;OICI;FA;;;'+$ownerSid+')'}
[TertiaryPrivateStage]::CreateExclusive($root,$sddl)
$rootHeld=$null;$oldHeld=$null;$newHeld=$null
try {
 $rootHeld=[TertiaryPrivateStage]::Hold($root,$true);$rootPin=[TertiaryPrivateStage]::Pin($rootHeld,$true)
 $old=Join-Path $root 'old-default.msi';$new=Join-Path $root 'explicit-owner.msi'
 $oldHeld=[TertiaryPrivateStage]::CreateDefaultTargetForOwnerControl($old)
 $oldOwner=(Get-Acl -LiteralPath $old -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($requireSystem -and $oldOwner -cne 'S-1-5-32-544'){throw 'OWNER_OLD_SYSTEM_CONTROL'}
 $newHeld=[TertiaryPrivateStage]::CreateTargetOwned($new,$ownerSid);$newPin=[TertiaryPrivateStage]::Pin($newHeld,$false)
 $acl=Get-Acl -LiteralPath $new -ErrorAction Stop
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $ownerSid -or $acl.AreAccessRulesProtected){throw 'OWNER_EXPLICIT_CONTROL'}
 $rootRules=@((Get-Acl -LiteralPath $root).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value+':'+[int]$_.FileSystemRights+':'+$_.AccessControlType.ToString()}|Sort-Object)
 $fileRules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {if(-not $_.IsInherited -or [int]$_.InheritanceFlags -ne 0 -or [int]$_.PropagationFlags -ne 0){throw 'OWNER_INHERITED_FLAGS'};$_.IdentityReference.Value+':'+[int]$_.FileSystemRights+':'+$_.AccessControlType.ToString()}|Sort-Object)
 if(($rootRules -join '|') -cne ($fileRules -join '|')){throw 'OWNER_DACL_CHANGED'}
 $writer=[IO.File]::Open($new,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
 try{$bytes=[Text.Encoding]::ASCII.GetBytes('PUBLIC6');$writer.Write($bytes,0,$bytes.Length);$writer.Flush($true)}finally{$writer.Dispose()}
 $renameError=$null;try{[IO.File]::Move($new,$new+'.foreign')}catch{$renameError=$_.Exception.GetBaseException().HResult -band 65535}
 if($renameError -ne 32){throw 'OWNER_NO_DELETE_CONTROL'}
 [TertiaryPrivateStage]::Match($root,$rootHeld,$rootPin,$true);[TertiaryPrivateStage]::Match($new,$newHeld,$newPin,$false)
 [ordered]@{observerSid=$ownerSid;oldOwnerSid=$oldOwner;oldOwnerMatchesCurrentUser=($oldOwner -ceq $ownerSid);explicitOwnerMatchesCurrentUser=$true;inheritedDaclUnchanged=$true;nativeIdentityStable=$true;writerCompatible=$true;renameError=$renameError;rootNativeId=$rootPin;targetNativeId=$newPin;root=$root;systemGuest=$requireSystem;installerAction=$false;productAcceptance=$false}|ConvertTo-Json -Depth 4 -Compress
} finally {
 if($newHeld){$newHeld.Dispose()};if($oldHeld){$oldHeld.Dispose()};if($rootHeld){$rootHeld.Dispose()}
 # Retain the tiny terminal-owned scratch evidence; no foreign cleanup.
}
''')


def validate_target_owner_control(receipt, *, system_guest=False):
    if type(system_guest)is not bool or type(receipt)is not dict:raise ValueError('TERTIARY_OWNER_CONTROL_RECEIPT')
    flags=('explicitOwnerMatchesCurrentUser','inheritedDaclUnchanged','nativeIdentityStable','writerCompatible')
    if (any(receipt.get(k)is not True for k in flags)
        or type(receipt.get('oldOwnerMatchesCurrentUser'))is not bool
        or type(receipt.get('renameError'))is not int or receipt['renameError']!=32
        or receipt.get('systemGuest')is not system_guest
        or receipt.get('installerAction')is not False or receipt.get('productAcceptance')is not False
        or any(type(receipt.get(k))is not str or not receipt[k]for k in ('observerSid','oldOwnerSid','rootNativeId','targetNativeId','root'))):
        raise ValueError('TERTIARY_OWNER_CONTROL_RECEIPT')
    if system_guest and (receipt['observerSid']!='S-1-5-18' or receipt['oldOwnerSid']!='S-1-5-32-544' or receipt['oldOwnerMatchesCurrentUser']is not False):
        raise ValueError('TERTIARY_OWNER_SYSTEM_CONTROL')
    return True


def validate_target_retry_binding(host_request, guest_request, correlation):
    if type(host_request)is not dict or type(guest_request)is not dict:raise ValueError('TERTIARY_TARGET_REQUEST_TYPE')
    validate_target_request(host_request,correlation)
    validate_target_request(guest_request,correlation)
    expected=dict(host_request,correlation=guest_request['correlation'],guestStage=guest_request['guestStage'])
    if (guest_request.keys()!=expected.keys() or any(type(guest_request[k])is not type(expected[k]) or guest_request[k]!=expected[k]for k in expected)
        or guest_request['correlation']==host_request['correlation']):
        raise ValueError('TERTIARY_TARGET_FRESH_BINDING')
    return True


def classify_transport_stderr(raw):
    """Bounded diagnostic label; neither execution absence nor cause is inferred."""
    if type(raw) is not bytes or len(raw) > 4096:
        raise ValueError('tertiary-transport-stderr-bound')
    category = 'unclassified'
    if raw == b'mm_send_fd: sendmsg(2): Message too long\nmux_client_request_session: send fds failed\n':
        category = 'mux-fd-send-failed'
    elif raw == b'Connection closed by UNKNOWN port 65535\r\n':
        category = 'connection-closed'
    return {'category': category, 'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'outcome': 'unknown', 'causeEstablished': False, 'replayAllowed': False}


def direct_nested_ssh_argv(argv, outer_control, inner_control, outer_host, inner_alias):
    """Bypass mux for one fixed two-hop command; leave both masters intact.

    The caller authenticates all five inputs and the original transport context.
    This transforms argv only and supplies no network or guest authority.
    """
    import shlex
    if (type(argv)is not list or len(argv)<5 or any(type(x)is not str or '\0'in x for x in argv)
        or any(type(x)is not str or not x for x in (outer_control,inner_control,outer_host,inner_alias))
        or argv[0]not in ('ssh','/usr/bin/ssh') or argv[-2]!=outer_host):
        raise ValueError('TERTIARY_DIRECT_ROUTE')
    outer=argv[:-2]
    if outer.count('-S')!=1:raise ValueError('TERTIARY_OUTER_MUX_SHAPE')
    index=outer.index('-S')
    if index+1>=len(outer)or outer[index+1]!=outer_control:raise ValueError('TERTIARY_OUTER_MUX_BINDING')
    if any(x.startswith('ControlMaster=')and x!='ControlMaster=no' for x in outer):raise ValueError('TERTIARY_OUTER_MASTER_MODE')
    outer[index+1]='none'
    if 'ControlMaster=no'not in outer:outer+=['-o','ControlMaster=no']
    inner=shlex.split(argv[-1])
    if len(inner)<5 or inner[0]not in ('ssh','/usr/bin/ssh')or inner[-2]!=inner_alias:raise ValueError('TERTIARY_INNER_ROUTE')
    prefix=inner[:-2]
    if prefix.count('-S')!=1:raise ValueError('TERTIARY_INNER_MUX_SHAPE')
    index=prefix.index('-S')
    if index+1>=len(prefix)or prefix[index+1]!=inner_control:raise ValueError('TERTIARY_INNER_MUX_BINDING')
    if any(x.startswith('ControlMaster=')for x in prefix):raise ValueError('TERTIARY_INNER_MASTER_MODE')
    prefix[index+1]='none';prefix+=['-o','ControlMaster=no']
    return [*outer,outer_host,shlex.join([*prefix,*inner[-2:]])]


def conserved_custodian_script(request, correlation):
    """Fixed prior-state conservation for a new tertiary correlation only."""
    script=custodian_script(request,correlation)
    old=r'C:\ProgramData\VpnControlTertiaryFixture-72193b20-9f5f-4fd1-9b2a-34db296b17c7'
    absent=r'C:\ProgramData\VpnControlTertiaryFixture-55043a46-02e2-4204-9ea8-995ce90b098e'
    if request['guestStage'] in (old,absent):raise ValueError('tertiary-conservation-new-root')
    fragment=CONSERVATION_PS
    for variable in ('ready','complete'):
        anchor=" Publish-New 'custodian-"+variable+".json' $"+variable+";Assert-Custody"
        if script.count(anchor)!=1:raise ValueError('tertiary-conservation-receipt-anchor')
        script=script.replace(anchor," $"+variable+"['priorConservation']=Observe-Historical\n"+anchor,1)
    anchor="try {\n $heldParent=[TertiaryPrivateStage]::Hold"
    if script.count(anchor)!=1:raise ValueError('tertiary-conservation-try-anchor')
    script=script.replace(anchor,"$historicalHolders=@();$historicalStreams=@()\ntry {\n"+fragment+" $heldParent=[TertiaryPrivateStage]::Hold",1)
    anchor='function Assert-Custody {\n'
    if script.count(anchor)!=1:raise ValueError('tertiary-conservation-custody-anchor')
    script=script.replace(anchor,anchor+'  Assert-Historical\n',1)
    anchor='$heldDrive.Dispose()}\n'
    if script.count(anchor)!=1:raise ValueError('tertiary-conservation-finally-anchor')
    return script.replace(anchor,'$heldDrive.Dispose();foreach($stream in $historicalStreams){$stream.Dispose()};foreach($holder in $historicalHolders){$holder.Dispose()}}\n',1)


CONSERVATION_PS = r'''
$historicalRoot='C:\ProgramData\VpnControlTertiaryFixture-72193b20-9f5f-4fd1-9b2a-34db296b17c7'
$absentRoot='C:\ProgramData\VpnControlTertiaryFixture-55043a46-02e2-4204-9ea8-995ce90b098e'
$historicalHolders=@();$historicalStreams=@();$historicalRows=@()
function Assert-Absent([string]$path){
 try{$null=Get-Item -LiteralPath $path -Force -ErrorAction Stop;throw 'CONSERVATION_FOREIGN_PRESENT'}
 catch{if($_.Exception -isnot [Management.Automation.ItemNotFoundException] -or $_.FullyQualifiedErrorId -cne 'PathNotFound,Microsoft.PowerShell.Commands.GetItemCommand'){throw}}
}
function Observe-Historical {
 Assert-Historical
 return [ordered]@{historicalState='UNKNOWN';replayAllowed=$false;oldPartialLength=0;oldRoot=$historicalRoot;prior38Root=$absentRoot;prior38CurrentlyAbsent=$true;heldNativeRows=@($historicalRows|ForEach-Object {[ordered]@{path=$_.path;nativeId=$_.nativeId;directory=$_.directory}})}
}
function Assert-Historical {
 foreach($r in $historicalRows){[TertiaryPrivateStage]::Match($r.path,$r.handle,$r.nativeId,$r.directory)}
 if(@(Get-ChildItem -LiteralPath $historicalRoot -Force -ErrorAction Stop).Count -ne 2){throw 'CONSERVATION_CENSUS_CHANGED'}
 Assert-Absent $absentRoot
}
try{
 foreach($path in @('C:\','C:\ProgramData',$historicalRoot)){
  $h=[TertiaryPrivateStage]::Hold($path,$true);$historicalHolders+=@($h);$historicalRows+=@([ordered]@{path=$path;handle=$h;nativeId=[TertiaryPrivateStage]::Pin($h,$true);directory=$true})
 }
 if((Get-Acl -LiteralPath $historicalRoot -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18'){throw 'CONSERVATION_ROOT_OWNER'}
 $names=@(Get-ChildItem -LiteralPath $historicalRoot -Force -ErrorAction Stop|Select-Object -ExpandProperty Name|Sort-Object)
 if(($names -join '|') -cne 'custodian-unknown.json|vpn-control-2.2.2.msi'){throw 'CONSERVATION_CENSUS'}
 foreach($name in $names){
  $path=Join-Path $historicalRoot $name;$h=[TertiaryPrivateStage]::Hold($path,$false);$historicalHolders+=@($h);$historicalRows+=@([ordered]@{path=$path;handle=$h;nativeId=[TertiaryPrivateStage]::Pin($h,$false);directory=$false})
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$historicalStreams+=@($stream)
  if($name -ceq 'vpn-control-2.2.2.msi'){
   if($stream.Length -ne 0 -or (Get-Acl -LiteralPath $path -ErrorAction Stop).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'CONSERVATION_PARTIAL_TARGET'}
  }else{
   if($stream.Length -le 0 -or $stream.Length -gt 1024){throw 'CONSERVATION_UNKNOWN_BOUND'}
   $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true,1024,$true);$v=$reader.ReadToEnd()|ConvertFrom-Json;$reader.Dispose();$stream.Position=0
   if($v.state -cne 'unknown' -or $v.correlationId -cne 'c461c2a0-c144-47cc-9d01-cf993ffd8964' -or ($v.pid -isnot [int] -and $v.pid -isnot [long]) -or $v.pid -ne 6836 -or $v.errorDetail -cne 'CUSTODY_ACL_OWNER' -or $v.installerAction -isnot [bool] -or $v.installerAction -or $v.replayAllowed -isnot [bool] -or $v.replayAllowed){throw 'CONSERVATION_UNKNOWN_BINDING'}
  }
 }
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 $foreign=@($all|Where-Object {$_.ProcessId -ne $PID -and $_.Name -ceq 'powershell.exe' -and $_.CommandLine -and ($_.CommandLine.Contains($historicalRoot) -or $_.CommandLine.Contains($absentRoot) -or $_.CommandLine.Contains('38f85f3c-504c-42ab-bea0-80798f152090'))})
 if($foreign.Count -ne 0){throw 'CONSERVATION_OLD_CUSTODIAN'}
 Assert-Historical
}catch{foreach($stream in $historicalStreams){$stream.Dispose()};foreach($holder in $historicalHolders){$holder.Dispose()};throw}
'''


def conserved_target_stage_body():
    """Require current prior38 journal absence without changing its UNKNOWN."""
    body=TARGET_STAGE_BODY
    anchor=" journal=guest.root/('target-stage-'+CORRELATION);"
    if body.count(anchor)!=1:raise ValueError('tertiary-conservation-journal-anchor')
    check=" prior38=guest.root/'target-stage-38f85f3c-504c-42ab-bea0-80798f152090';need(not os.path.lexists(prior38),'tertiary-prior38-current-journal-absent')\n"
    body=body.replace(anchor,check+anchor,1)
    anchor='  observed_process(proc,row);observed_process(proc,parent,BOOT_PROGRAM_SHA)\n'
    if body.count(anchor)!=2:raise ValueError('tertiary-conservation-guard-anchor')
    return body.replace(anchor,anchor+"  need(not os.path.lexists(prior38),'tertiary-prior38-current-journal-absent')\n")


def omit_unused_pair_launcher(header):
    """Omit only the inherited, unreferenced VM launcher from a stage carrier."""
    import ast
    tree=ast.parse(header)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='launch_pair']
    if len(nodes)!=1 or any(isinstance(n,ast.Name)and n.id=='launch_pair'for n in ast.walk(tree)):
        raise ValueError('tertiary-stage-unused-launcher-proof')
    tree.body.remove(nodes[0])
    return ast.unparse(tree)+'\n'


def msi_scope_script(request, retained_custodian, correlation):
    """Read the single positively staged MSI through participating read custody."""
    directory=validate_target_request(request,correlation)
    if retained_custodian.get('state')!='custodian-complete' or retained_custodian.get('stage')!=directory or retained_custodian.get('sha256')!=request['targetSha256'] or type(retained_custodian.get('length'))is not int or retained_custodian['length']!=TARGET_SIZE:
        raise ValueError('tertiary-msi-scope-retained-stage')
    for key in ('rootNativeId','targetNativeId'):
        if type(retained_custodian.get(key))is not str or not 0<len(retained_custodian[key])<160:raise ValueError('tertiary-msi-scope-native-binding')
    original=custodian_script(request,correlation)
    start=original.index('function Assert-Actor {');end=original.index('function Publish-New(')
    prefix="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
    prefix+="$root="+repr(directory)+";$sid="+repr(request['expectedSid'])+";$expectedRoot="+repr(retained_custodian['rootNativeId'])+";$expectedTarget="+repr(retained_custodian['targetNativeId'])+"\n"
    # Python repr escapes backslashes; PowerShell single quotes keep them literal.
    prefix=prefix.replace('\\\\','\\')
    prefix+="Add-Type -TypeDefinition @'\n"+PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"+original[start:end]
    return prefix+MSI_SCOPE_PS


MSI_SCOPE_PS=r'''
$holders=@();$read=$null;$database=$null;$installer=$null
try{
 foreach($path in @('C:\','C:\ProgramData',$root)){ $h=[TertiaryPrivateStage]::Hold($path,$true);$holders+=@($h) }
 $rootId=[TertiaryPrivateStage]::Pin($holders[2],$true);if($rootId -cne $expectedRoot){throw 'SCOPE_ROOT_ID'}
 $target=Join-Path $root 'vpn-control-2.2.2.msi';$file=[TertiaryPrivateStage]::Hold($target,$false);$holders+=@($file)
 $targetId=[TertiaryPrivateStage]::Pin($file,$false);if($targetId -cne $expectedTarget){throw 'SCOPE_TARGET_ID'}
 $pins=@();for($i=0;$i -lt $holders.Count;$i++){$pins+=@([TertiaryPrivateStage]::Pin($holders[$i],($i -lt 3)))}
 function Assert-Scope {
  $paths=@('C:\','C:\ProgramData',$root,$target)
  for($i=0;$i -lt $holders.Count;$i++){[TertiaryPrivateStage]::Match($paths[$i],$holders[$i],$pins[$i],($i -lt 3))}
 }
 Assert-Scope;$actor=Assert-Actor;$rootAcl=Observe-Acl $root $true;$targetAcl=Observe-Acl $target $false
 $read=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if($read.Length -ne 131101044){throw 'SCOPE_LENGTH'}
 $algorithm=[Security.Cryptography.SHA256]::Create();try{$sha=[BitConverter]::ToString($algorithm.ComputeHash($read)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
 if($sha -cne 'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc'){throw 'SCOPE_SHA'}
 $installer=New-Object -ComObject WindowsInstaller.Installer;$database=$installer.OpenDatabase($target,0)
 function Text-Cell($r,[int]$column){$v=$r.StringData($column);if($v.Length -gt 512){throw 'SCOPE_CELL_BOUND'};return [string]$v}
 $properties=@();$v=$database.OpenView('SELECT `Property`,`Value` FROM `Property`');$v.Execute()
 try{while($r=$v.Fetch()){if($properties.Count -ge 128){throw 'SCOPE_PROPERTY_BOUND'};$properties+=@([ordered]@{name=(Text-Cell $r 1);value=(Text-Cell $r 2)})}}finally{$v.Close()}
 $directories=@();$v=$database.OpenView('SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`');$v.Execute()
 try{while($r=$v.Fetch()){if($directories.Count -ge 128){throw 'SCOPE_DIRECTORY_BOUND'};$directories+=@([ordered]@{directory=(Text-Cell $r 1);parent=(Text-Cell $r 2);defaultDir=(Text-Cell $r 3)})}}finally{$v.Close()}
 $groups=@{};$componentCount=0;$v=$database.OpenView('SELECT `Directory_`,`Attributes` FROM `Component`');$v.Execute()
 try{while($r=$v.Fetch()){if($componentCount -ge 4096){throw 'SCOPE_COMPONENT_BOUND'};$d=Text-Cell $r 1;$a=[int]$r.IntegerData(2);$key=$d+'|'+$a.ToString();if(-not $groups.ContainsKey($key)){if($groups.Count -ge 64){throw 'SCOPE_GROUP_BOUND'};$groups[$key]=[ordered]@{directory=$d;attributes=$a;count=0}};$groups[$key].count++;$componentCount++}}finally{$v.Close()}
 $upgrades=@();$v=$database.OpenView('SELECT `UpgradeCode`,`VersionMin`,`VersionMax`,`Language`,`Attributes`,`Remove`,`ActionProperty` FROM `Upgrade`');$v.Execute()
 try{while($r=$v.Fetch()){if($upgrades.Count -ge 16){throw 'SCOPE_UPGRADE_BOUND'};$upgrades+=@([ordered]@{code=(Text-Cell $r 1);min=(Text-Cell $r 2);max=(Text-Cell $r 3);language=(Text-Cell $r 4);attributes=[int]$r.IntegerData(5);remove=(Text-Cell $r 6);actionProperty=(Text-Cell $r 7)})}}finally{$v.Close()}
 Assert-Scope;$closingActor=Assert-Actor;$closingRootAcl=Observe-Acl $root $true;$closingTargetAcl=Observe-Acl $target $false
 $out=[ordered]@{state='readonly-msi-authored-scope';path=$target;rootNativeId=$rootId;targetNativeId=$targetId;sha256=$sha;length=$read.Length;databaseMode=0;properties=$properties;directories=$directories;componentCount=$componentCount;componentGroups=@($groups.Keys|Sort-Object|ForEach-Object {$groups[$_]});upgrades=$upgrades;rootAcl=$closingRootAcl;targetAcl=$closingTargetAcl;ownerObservation=$closingActor;installerAction=$false;productAcceptance=$false;publicOFF='UNRESOLVED';installScopeInferred=$false}
 $json=$out|ConvertTo-Json -Depth 8 -Compress;if([Text.Encoding]::UTF8.GetByteCount($json) -gt 12000){throw 'SCOPE_OUTPUT_BOUND'}
 Assert-Scope;[Console]::Out.WriteLine($json)
}finally{if($read){$read.Dispose()};foreach($h in $holders){$h.Dispose()};if($database){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)};if($installer){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)}}
'''


def validate_msi_scope(receipt, request, retained_custodian):
    """Validate observed authored rows; absent ALLUSERS grants no install scope."""
    def require(ok):
        if not ok:raise ValueError('tertiary-msi-authored-scope')
    require(type(receipt)is dict and receipt.get('state')=='readonly-msi-authored-scope')
    require(set(receipt)=={'state','path','rootNativeId','targetNativeId','sha256','length','databaseMode','properties','directories','componentCount','componentGroups','upgrades','rootAcl','targetAcl','ownerObservation','installerAction','productAcceptance','publicOFF','installScopeInferred'})
    import json
    require(len(json.dumps(receipt,ensure_ascii=False,separators=(',',':')).encode('utf-8'))<=12000)
    require(receipt.get('path')==request['guestStage']+r'\vpn-control-2.2.2.msi' and receipt.get('rootNativeId')==retained_custodian['rootNativeId'] and receipt.get('targetNativeId')==retained_custodian['targetNativeId'])
    require(receipt.get('sha256')==request['targetSha256'] and type(receipt.get('length'))is int and receipt['length']==TARGET_SIZE and type(receipt.get('databaseMode'))is int and receipt['databaseMode']==0)
    require(all(receipt.get(k)is False for k in ('installerAction','productAcceptance','installScopeInferred')) and receipt.get('publicOFF')=='UNRESOLVED')
    validate_target_custody_acl(receipt['rootAcl'],receipt['targetAcl'],request);validate_custody_owner(receipt['ownerObservation'])
    schemas={'properties':({'name','value'},128),'directories':({'directory','parent','defaultDir'},128),'componentGroups':({'directory','attributes','count'},64),'upgrades':({'code','min','max','language','attributes','remove','actionProperty'},16)}
    for key,(fields,bound)in schemas.items():
        rows=receipt.get(key);require(type(rows)is list and len(rows)<=bound)
        for row in rows:
            require(type(row)is dict and set(row)==fields)
            for field,value in row.items():
                if field in ('attributes','count'):require(type(value)is int and value>=0)
                else:require(type(value)is str and len(value)<=512)
    properties=receipt['properties'];require(len({r['name']for r in properties})==len(properties))
    values={r['name']:r['value']for r in properties}
    require(values.get('ProductName')=='vpn-control' and values.get('ProductVersion')=='2.2.2' and values.get('ProductCode')=='{2D8D2946-3492-3C19-A837-87C54F9311A9}' and values.get('UpgradeCode')=='{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}')
    directories=receipt['directories'];names={r['directory']for r in directories};require(len(names)==len(directories) and bool(names))
    require(all(not r['parent'] or r['parent']in names for r in directories))
    require(type(receipt.get('componentCount'))is int and 0<receipt['componentCount']<=4096)
    groups=receipt['componentGroups'];require(sum(r['count']for r in groups)==receipt['componentCount'] and all(r['count']>0 and r['directory']in names for r in groups))
    require(len({(r['directory'],r['attributes'])for r in groups})==len(groups))
    return True


def installed_cli_dispatch_script():
    """Inspect fixed historical installed launcher dispatch; execute no bytecode."""
    return "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\nAdd-Type -AssemblyName System.IO.Compression.FileSystem\nAdd-Type -AssemblyName System.IO.Compression\nAdd-Type -TypeDefinition @'\n"+PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"+INSTALLED_DISPATCH_PS


INSTALLED_DISPATCH_PS=r'''
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'DISPATCH_OBSERVER'}
$install='C:\Users\parityagent\AppData\Local\vpn-control';$app=Join-Path $install 'app';$holders=@();$streams=@();$rows=@();$cfg=$null
try{
 foreach($path in @('C:\','C:\Users','C:\Users\parityagent','C:\Users\parityagent\AppData','C:\Users\parityagent\AppData\Local',$install,$app)){
  $h=[TertiaryPrivateStage]::Hold($path,$true);$holders+=@($h);$rows+=@([ordered]@{path=$path;handle=$h;directory=$true;nativeId=[TertiaryPrivateStage]::Pin($h,$true)})
 }
 function Held-Read([string]$path){
  $h=[TertiaryPrivateStage]::Hold($path,$false);$script:holders+=@($h);$script:rows+=@([ordered]@{path=$path;handle=$h;directory=$false;nativeId=[TertiaryPrivateStage]::Pin($h,$false)})
  $s=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:streams+=@($s);return $s
 }
 function Hash-Stream($s){$s.Position=0;$a=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($a.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$a.Dispose()};$s.Position=0;return $v}
 function Assert-Dispatch {foreach($r in $rows){[TertiaryPrivateStage]::Match($r.path,$r.handle,$r.nativeId,$r.directory)}}
 $all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$owners=@($all|Where-Object {$_.Name -in @('vpn-control.exe','vpn-control-cli.exe','sing-box.exe','msiexec.exe','vpn-control-windows-vpn-broker.exe') -or ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($install+'\',[StringComparison]::OrdinalIgnoreCase))})
 if($owners.Count -ne 0){throw 'DISPATCH_EXISTING_OWNER'}
 $name=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
 if($name -cne 'VPNPARITYX64\parityagent'){throw 'DISPATCH_INTERACTIVE'}
 $sid=([Security.Principal.NTAccount]::new([string]$name)).Translate([Security.Principal.SecurityIdentifier]).Value
 $sessions=@($all|Where-Object {$_.Name -ceq 'explorer.exe'}|Select-Object -ExpandProperty SessionId -Unique)
 if($sid -cne 'S-1-5-21-606332539-4179368406-55829832-1000' -or $sessions.Count -ne 1 -or $sessions[0] -ne 1){throw 'DISPATCH_SID_SESSION'}
 $cli=Held-Read (Join-Path $install 'vpn-control-cli.exe');$cliSha=Hash-Stream $cli
 if($cli.Length -ne 791040 -or $cliSha -cne '576f34076f6a96c55d6b3df04264cbd62c096b41e9803cc575ca4c11b196fd88'){throw 'DISPATCH_HISTORICAL_LAUNCHER'}
 $cfgPath=Join-Path $app 'vpn-control-cli.cfg'
 $null=Get-Item -LiteralPath $cfgPath -Force -ErrorAction Stop;$cfg=Held-Read $cfgPath
 if($cfg.Length -le 0 -or $cfg.Length -gt 32768){throw 'DISPATCH_CFG_BOUND'}
 $cfgSha=Hash-Stream $cfg;$cfgBytes=New-Object byte[] ([int]$cfg.Length);$offset=0;while($offset -lt $cfgBytes.Length){$n=$cfg.Read($cfgBytes,$offset,$cfgBytes.Length-$offset);if($n -le 0){throw 'DISPATCH_CFG_EOF'};$offset+=$n};$cfg.Position=0
 $reader=[IO.StreamReader]::new($cfg,[Text.UTF8Encoding]::new($false,$true),$true,1024,$true);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}
 $lines=@($text -split '\r?\n');$main=@($lines|Where-Object {$_ -cmatch '^app.mainclass='});if($main.Count -ne 1){throw 'DISPATCH_MAIN_CLASS'}
 $mainClass=$main[0].Substring(14);if($mainClass -cnotmatch '^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$' -or $mainClass.Length -gt 256){throw 'DISPATCH_MAIN_CLASS_SHAPE'}
 $entryNames=@(($mainClass.Replace('.','/')+'.class'),'com/kardinal/vpncontrol/desktop/MainKt.class','com/kardinal/vpncontrol/desktop/DesktopCli.class','com/kardinal/vpncontrol/desktop/DesktopWorkspacePaths.class','com/kardinal/vpncontrol/control/ControlCliParser.class')|Select-Object -Unique;$classpath=@();foreach($line in $lines){if($line -cmatch '^app.classpath='){foreach($member in $line.Substring(14).Split(';')){if($member -cnotmatch '^\$APPDIR[\\/][A-Za-z0-9_. -]+\.jar$'){throw 'DISPATCH_CLASSPATH_MEMBER'};$leaf=$member.Substring(8);$classpath+=@(Join-Path $app $leaf)}}};if($classpath.Count -ne (@($classpath|Select-Object -Unique)).Count){throw 'DISPATCH_CLASSPATH_DUPLICATE'};$jars=@($classpath|ForEach-Object {Get-Item -LiteralPath $_ -Force -ErrorAction Stop})
 if($jars.Count -le 0 -or $jars.Count -gt 128){throw 'DISPATCH_JAR_CENSUS'}
 if(($jars|Measure-Object -Property Length -Sum).Sum -gt 268435456){throw 'DISPATCH_JAR_TOTAL_BOUND'}
 $matches=@();$jarRows=@();$jarIndex=-1;$decodedTotal=0
 foreach($jar in $jars){
  $jarIndex++;$h=[TertiaryPrivateStage]::Hold($jar.FullName,$false);$s=[IO.File]::Open($jar.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$zip=$null
  try{
   if($s.Length -gt 67108864){throw 'DISPATCH_JAR_BOUND'}
   $id=[TertiaryPrivateStage]::Pin($h,$false);$zip=[IO.Compression.ZipArchive]::new($s,[IO.Compression.ZipArchiveMode]::Read,$true);$found=@()
   foreach($entryName in $entryNames){$entry=$zip.GetEntry($entryName)
   if($entry){
    if($entry.Length -le 0 -or $entry.Length -gt 262144){throw 'DISPATCH_CLASS_BOUND'}
    $es=$entry.Open();$ms=[IO.MemoryStream]::new();try{$buffer=New-Object byte[] 1024;while(($n=$es.Read($buffer,0,[Math]::Min(1024,262145-[int]$ms.Length))) -gt 0){$ms.Write($buffer,0,$n);if($ms.Length -gt 262144){throw 'DISPATCH_EXPANDED_CLASS_BOUND'}};$bytes=$ms.ToArray()}finally{$ms.Dispose();$es.Dispose()}
    if($bytes.Length -ne $entry.Length){throw 'DISPATCH_CLASS_LENGTH'};$decodedTotal+=$bytes.Length;if($decodedTotal -gt 393216){throw 'DISPATCH_TOTAL_CLASS_BOUND'}
    $found+=@([ordered]@{entry=$entryName;classLength=$bytes.Length;classBase64=[Convert]::ToBase64String($bytes)})
   }}
    $zip.Dispose();$zip=$null;$sha=Hash-Stream $s
    [TertiaryPrivateStage]::Match($jar.FullName,$h,$id,$false)
    $holders+=@($h);$streams+=@($s);$rows+=@([ordered]@{path=$jar.FullName;handle=$h;directory=$false;nativeId=$id});$h=$null;$s=$null
    $jarRows+=@([ordered]@{path=$jar.FullName;sha256=$sha;nativeId=$id;index=$jarIndex});if($found.Count -gt 0){$matches+=@([ordered]@{path=$jar.FullName;sha256=$sha;nativeId=$id;index=$jarIndex;classes=$found})}
  }finally{if($zip){$zip.Dispose()};if($s){$s.Dispose()};if($h){$h.Dispose()}}
 }
 $captured=@($matches|ForEach-Object {$_.classes}|ForEach-Object {$_['entry']})
 if($captured.Count -ne $entryNames.Count -or (@($captured|Sort-Object) -join '|') -cne (@($entryNames|Sort-Object) -join '|')){throw 'DISPATCH_CLASSES_MISSING_OR_AMBIGUOUS'}
 Assert-Dispatch
 $out=[ordered]@{state='readonly-installed-dispatch';observerSid='S-1-5-18';interactiveSid=$sid;session=1;launcherSha256=$cliSha;cfgPath=$cfgPath;cfgLength=$cfg.Length;cfgSha256=$cfgSha;cfgBase64=[Convert]::ToBase64String($cfgBytes);mainClass=$mainClass;classpath=$jarRows;jars=$matches;nativeRows=@($rows|ForEach-Object {[ordered]@{path=$_.path;directory=$_.directory;nativeId=$_.nativeId}});launcherExecuted=$false;bytecodeExecuted=$false;installerAction=$false;publicOFF='UNRESOLVED';productAcceptance=$false}
 $json=$out|ConvertTo-Json -Depth 6 -Compress;if([Text.Encoding]::UTF8.GetByteCount($json) -gt 600000){throw 'DISPATCH_OUTPUT_BOUND'}
 Assert-Dispatch;[Console]::Out.WriteLine($json)
}finally{foreach($s in $streams){$s.Dispose()};foreach($h in $holders){$h.Dispose()}}
'''


def validate_installed_dispatch(receipt):
    """Authenticate bounded captured bytes; historical grammar stays unproved."""
    import base64,hashlib,json,re
    def require(ok):
        if not ok:raise ValueError('tertiary-installed-dispatch-schema')
    require(type(receipt)is dict and set(receipt)=={'state','observerSid','interactiveSid','session','launcherSha256','cfgPath','cfgLength','cfgSha256','cfgBase64','mainClass','classpath','jars','nativeRows','launcherExecuted','bytecodeExecuted','installerAction','publicOFF','productAcceptance'})
    require(receipt['state']=='readonly-installed-dispatch' and receipt['observerSid']=='S-1-5-18' and receipt['interactiveSid']=='S-1-5-21-606332539-4179368406-55829832-1000' and type(receipt['session'])is int and receipt['session']==1)
    require(all(receipt[k]is False for k in ('launcherExecuted','bytecodeExecuted','installerAction','productAcceptance')) and receipt['publicOFF']=='UNRESOLVED')
    require(len(json.dumps(receipt,ensure_ascii=False,separators=(',',':')).encode())<=600000)
    require(receipt['launcherSha256']=='576f34076f6a96c55d6b3df04264cbd62c096b41e9803cc575ca4c11b196fd88')
    app=r'C:\Users\parityagent\AppData\Local\vpn-control\app'
    require(receipt['cfgPath']==app+r'\vpn-control-cli.cfg' and type(receipt['cfgLength'])is int and 0<receipt['cfgLength']<=32768 and type(receipt['cfgBase64'])is str and len(receipt['cfgBase64'])<=43692)
    cfg=base64.b64decode(receipt['cfgBase64'],validate=True)
    require(len(cfg)==receipt['cfgLength'] and hashlib.sha256(cfg).hexdigest()==receipt['cfgSha256'])
    lines=cfg.decode('utf-8-sig',errors='strict').splitlines()
    require([s[14:]for s in lines if s.startswith('app.mainclass=')]==[receipt['mainClass']])
    configured=[]
    for line in lines:
        if line.startswith('app.classpath='):
            for member in line[14:].split(';'):
                require(re.fullmatch(r'\$APPDIR[\\/][A-Za-z0-9_. -]+\.jar',member)is not None)
                configured.append(app+'\\'+member[8:])
    require(1<=len(configured)<=128 and len({p.casefold()for p in configured})==len(configured))
    require(type(receipt['mainClass'])is str and 0<len(receipt['mainClass'])<=256 and re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+',receipt['mainClass'])is not None)
    expected={receipt['mainClass'].replace('.','/')+'.class','com/kardinal/vpncontrol/desktop/MainKt.class','com/kardinal/vpncontrol/desktop/DesktopCli.class','com/kardinal/vpncontrol/desktop/DesktopWorkspacePaths.class','com/kardinal/vpncontrol/control/ControlCliParser.class'}
    jars=receipt['jars'];require(type(jars)is list and 1<=len(jars)<=5)
    captured=[]
    for jar in jars:
        require(type(jar)is dict and set(jar)=={'path','sha256','nativeId','index','classes'} and type(jar['path'])is str and jar['path'].startswith(app+'\\') and '\\'not in jar['path'][len(app)+1:] and jar['path'].endswith('.jar') and type(jar['sha256'])is str and re.fullmatch('[0-9a-f]{64}',jar['sha256'])is not None and type(jar['index'])is int)
        require(type(jar['nativeId'])is str and 0<len(jar['nativeId'])<160 and type(jar['classes'])is list and 1<=len(jar['classes'])<=5)
        for row in jar['classes']:
            require(type(row)is dict and set(row)=={'entry','classLength','classBase64'} and row['entry']in expected and type(row['classLength'])is int and 0<row['classLength']<=262144 and type(row['classBase64'])is str and len(row['classBase64'])<=349528)
            raw=base64.b64decode(row['classBase64'],validate=True);require(len(raw)==row['classLength'] and raw.startswith(b'\xca\xfe\xba\xbe'));captured.append(row['entry'])
    require(set(captured)==expected and len(captured)==len(expected))
    classpath=receipt['classpath'];require(type(classpath)is list and 1<=len(classpath)<=128 and len(classpath)==len(configured))
    require(all(type(r)is dict and set(r)=={'path','sha256','nativeId','index'} and type(r['index'])is int and r['index']==i and r['path']==configured[i] and type(r['sha256'])is str and re.fullmatch('[0-9a-f]{64}',r['sha256'])is not None and type(r['nativeId'])is str and 0<len(r['nativeId'])<160 for i,r in enumerate(classpath)) and len(classpath)==len(configured))
    require(all(0<=j['index']<len(classpath) and {k:j[k]for k in ('path','sha256','nativeId','index')}==classpath[j['index']]for j in jars))
    require(sum(r['classLength']for j in jars for r in j['classes'])<=393216)
    rows=receipt['nativeRows'];require(type(rows)is list and 10<=len(rows)<=137)
    for row in rows:require(type(row)is dict and set(row)=={'path','directory','nativeId'} and type(row['path'])is str and len(row['path'])<=512 and type(row['directory'])is bool and type(row['nativeId'])is str and 0<len(row['nativeId'])<160)
    require(len({r['path']for r in rows})==len(rows))
    require(receipt['cfgPath']in {r['path']for r in rows if r['directory']is False} and all(any(r['path']==j['path']and r['nativeId']==j['nativeId']and r['directory']is False for r in rows)for j in classpath))
    return True


def compact_installed_dispatch(receipt, raw):
    """Project authenticated bytes into bounded transport output, retaining no code."""
    import hashlib,json
    validate_installed_dispatch(receipt)
    if type(raw)is not bytes or not 0<len(raw)<=600000 or json.loads(raw.decode('utf-8-sig'))!=receipt:
        raise ValueError('tertiary-installed-dispatch-raw')
    return dict(state=receipt['state'],observerSid=receipt['observerSid'],interactiveSid=receipt['interactiveSid'],session=receipt['session'],mainClass=receipt['mainClass'],cfgSha256=receipt['cfgSha256'],cfgLength=receipt['cfgLength'],launcherSha256=receipt['launcherSha256'],rawLength=len(raw),rawSha256=hashlib.sha256(raw).hexdigest(),classes=[dict(entry=c['entry'],length=c['classLength'],sha256=hashlib.sha256(__import__('base64').b64decode(c['classBase64'],validate=True)).hexdigest(),jarPath=j['path'],jarSha256=j['sha256'],classpathIndex=j['index'])for j in receipt['jars']for c in j['classes']],launcherExecuted=False,bytecodeExecuted=False,installerAction=False,productAcceptance=False,publicOFF='UNRESOLVED')


def installed_dispatch_terminal_diagnostic(result, created, terminal_path, terminal_pin):
    """Bounded original child facts; locator is diagnostic, never acceptance."""
    import base64,hashlib
    if type(created)is not dict or type(created.get('pid'))is not int or created['pid']<=0:
        raise ValueError('tertiary-dispatch-diagnostic-pid')
    if type(result)is not dict or result.get('exited')is not True or type(result.get('exitcode'))is not int:
        raise ValueError('tertiary-dispatch-diagnostic-terminal')
    for key in ['out-truncated','err-truncated']:
        if key in result and type(result[key])is not bool:
            raise ValueError('tertiary-dispatch-diagnostic-truncation')
    decoded=[]
    for key,maximum in [('out-data',600000),('err-data',16384)]:
        encoded=result.get(key,'')
        if type(encoded)is not str or len(encoded)>4*((maximum+2)//3):
            raise ValueError('tertiary-dispatch-diagnostic-bound')
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>maximum:raise ValueError('tertiary-dispatch-diagnostic-bound')
        decoded.append(raw)
    out,err=decoded
    return dict(guestPid=created['pid'],exitcode=result['exitcode'],stdoutLength=len(out),stdoutSha256=hashlib.sha256(out).hexdigest(),stderrLength=len(err),stderrSha256=hashlib.sha256(err).hexdigest(),stderrPrefixBase64=base64.b64encode(err[:4096]).decode(),outTruncated=result.get('out-truncated',False),errTruncated=result.get('err-truncated',False),path=str(terminal_path),pin=terminal_pin,authority=False,diagnosticOnly=True,continuousCustody=False,replayAllowed=False)


def installed_dispatch_terminal_tail():
    """Pin the original terminal before refusal; publish no stale authority."""
    return r"""
try:
    terminal_path=journal/'probe-terminal.json'
    terminal_fd=os.open('probe-terminal.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
    terminal_pin=file_hash(terminal_fd,1048576)
    need(terminal_pin['generation']==generation(terminal_path.lstat()),'tertiary-dispatch-terminal-name')
    terminal_expected=(json.dumps(result,sort_keys=True)+'\n').encode()
    need(terminal_pin['sha256']==hashlib.sha256(terminal_expected).hexdigest() and terminal_pin['generation'][6]==len(terminal_expected),'tertiary-dispatch-terminal-content')
    guard()
    need(file_hash(terminal_fd,1048576)==terminal_pin and generation(terminal_path.lstat())==terminal_pin['generation'],'tertiary-dispatch-terminal-closing')
    terminal_diagnostic=installed_dispatch_terminal_diagnostic(result,created,terminal_path,terminal_pin)
    need(result['exitcode']==0 and result.get('out-truncated')is not True and result.get('err-truncated')is not True,'tertiary-probe-terminal')
    raw=base64.b64decode(result.get('out-data',''),validate=True)
    need(0<len(raw)<=600000,'tertiary-probe-bound')
    receipt=compact_installed_dispatch(json.loads(raw.decode('utf-8-sig')),raw)
    need(type(receipt)is dict,'tertiary-actor-result')
    guard()
    need(file_hash(terminal_fd,1048576)==terminal_pin and generation(terminal_path.lstat())==terminal_pin['generation'],'tertiary-dispatch-terminal-closing')
    value={'state':'tertiary-actor-observed','correlationId':CORRELATION,'guestPid':created['pid'],'receipt':receipt,'journal':str(journal),'installerAction':False,'productAcceptance':False,'replayAllowed':False,'originalTerminal':dict(path=str(terminal_path),pin=terminal_pin)}
    prepare.record_at(fd,'result.json',value)
    guard()
    need(file_hash(terminal_fd,1048576)==terminal_pin and generation(terminal_path.lstat())==terminal_pin['generation'],'tertiary-dispatch-terminal-closing')
except BaseException as error:
    value={'state':'unknown','correlationId':CORRELATION,'journal':str(journal),'errorType':type(error).__name__,'errorDetail':str(error)[:256],'diagnosticOnly':True,'installerAction':False,'productAcceptance':False,'replayAllowed':False}
    try:
        guard()
        need(terminal_pin['sha256']==hashlib.sha256(terminal_expected).hexdigest() and terminal_pin['generation'][6]==len(terminal_expected) and file_hash(terminal_fd,1048576)==terminal_pin and generation(terminal_path.lstat())==terminal_pin['generation'],'tertiary-dispatch-diagnostic-closing')
        value['terminalDiagnostic']=installed_dispatch_terminal_diagnostic(result,created,terminal_path,terminal_pin)
    except BaseException as diagnostic_error:
        value['terminalDiagnosticError']=type(diagnostic_error).__name__+':'+str(diagnostic_error)[:256]
    if fd is not None:prepare.record_at(fd,'unknown.json',value)
"""


def observe_installed_dispatch_original_status(client,created,guard):
    """Exactly one diagnostic query; never relaunch or adopt the old attempt."""
    if type(created)is not dict or set(created)!={'pid'} or type(created['pid'])is not int or created['pid']<=0:
        raise ValueError('tertiary-original-status-pid')
    if type(client.timeout_seconds)not in (int,float) or client.timeout_seconds!=15 or type(client.max_response_bytes)is not int or client.max_response_bytes!=1048576:
        raise ValueError('tertiary-original-status-limits')
    guard()
    result=client.guest_exec_status(created['pid'])
    guard()
    if type(result)is not dict or type(result.get('exited'))is not bool or (result['exited'] and type(result.get('exitcode'))is not int):
        raise ValueError('tertiary-original-status-terminal')
    return result


INSTALLED_CONTEXT_CS='using System;\nusing System.Text;\nusing System.Collections.Generic;\nusing System.Runtime.InteropServices;\npublic static class TertiaryInstalledContext {\n public sealed class Row {public string ProductCode,Sid,Name,Version,InstallLocation,LocalPackage,State;public Assignment AssignmentType;public uint Context;}\n public sealed class Snapshot {public int Enumerated;public uint Thread;public Row[] Selected;}\n [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint MsiEnumProductsExW(string product,string sid,uint context,uint index,StringBuilder code,out uint installedContext,StringBuilder userSid,ref uint userSidLength);\n [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern uint MsiGetProductInfoExW(string product,string sid,uint context,string property,StringBuilder value,ref uint valueLength);\n [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();\n static string Read(string code,string sid,uint context,string property) {uint length=4096;StringBuilder value=new StringBuilder(4097);uint rc=MsiGetProductInfoExW(code,context==4?null:sid,context,property,value,ref length);if(rc!=0 || length>4096)throw new InvalidOperationException("MSI_CONTEXT_INFO:"+property+":"+rc);return value.ToString();}\n public sealed class Assignment {public bool available,legacyRejected;public uint returnCode;public string value;}\n public static Assignment ProjectAssignment(uint rc,string value) {\n  if(rc==1608)return new Assignment{available=false,returnCode=rc,value=null,legacyRejected=false};\n  if(rc!=0 || (value!="0" && value!="1"))throw new InvalidOperationException("MSI_CONTEXT_ASSIGNMENT:"+rc);\n  return new Assignment{available=true,returnCode=0,value=value,legacyRejected=false};\n }\n static Assignment ReadAssignment(string product,string sid,uint context) {\n  uint length=4096;StringBuilder raw=new StringBuilder(4097);uint rc=MsiGetProductInfoExW(product,context==4?null:sid,context,"AssignmentType",raw,ref length);\n  if(length>4096)throw new InvalidOperationException("MSI_CONTEXT_ASSIGNMENT_BOUND");\n  Assignment result=ProjectAssignment(rc,rc==0?raw.ToString():null);\n  try{string old=Read(product,sid,context,"AssignmentType");if(!result.available || old!=result.value)throw new InvalidOperationException("MSI_CONTEXT_ASSIGNMENT_CONTROL");}\n  catch(InvalidOperationException error){if(rc!=1608 || error.Message!="MSI_CONTEXT_INFO:AssignmentType:1608")throw;result.legacyRejected=true;}\n  return result;\n }\n public static Assignment ControlFirstMachineAssignment() {\n  StringBuilder code=new StringBuilder(39),sid=new StringBuilder(185);uint sidLength=184,context;\n  uint rc=MsiEnumProductsExW(null,null,4,0,code,out context,sid,ref sidLength);\n  if(rc==259)return null;\n  if(rc!=0 || context!=4 || sidLength>184 || sid.Length!=0)throw new InvalidOperationException("MSI_CONTEXT_CONTROL_ENUM:"+rc);\n  return ReadAssignment(code.ToString(),"",4);\n }\n public static Snapshot Enumerate() {\n  List<Row> rows=new List<Row>();uint thread=GetCurrentThreadId();\n  for(uint index=0;index<256;index++) {\n   StringBuilder code=new StringBuilder(39),sid=new StringBuilder(185);uint sidLength=184,context;\n   uint rc=MsiEnumProductsExW(null,"S-1-1-0",7,index,code,out context,sid,ref sidLength);\n   if(rc==259){rows.Sort((a,b)=>String.CompareOrdinal(a.ProductCode+"|"+a.Context+"|"+a.Sid,b.ProductCode+"|"+b.Context+"|"+b.Sid));return new Snapshot{Enumerated=(int)index,Thread=thread,Selected=rows.ToArray()};}\n   if(rc!=0 || sidLength>184 || (context!=1 && context!=2 && context!=4) || GetCurrentThreadId()!=thread)throw new InvalidOperationException("MSI_CONTEXT_ENUM:"+rc);\n   string product=code.ToString(),user=sid.ToString();if(context==4 && user.Length!=0)throw new InvalidOperationException("MSI_CONTEXT_MACHINE_SID");\n   string name=Read(product,user,context,"InstalledProductName");\n   if(product=="{87F491A1-A193-3271-8AE2-C0877718FAB0}" || product=="{2D8D2946-3492-3C19-A837-87C54F9311A9}" || name=="vpn-control" || name=="VPN Control")\n    rows.Add(new Row{ProductCode=product,Sid=user,Context=context,Name=name,Version=Read(product,user,context,"VersionString"),AssignmentType=ReadAssignment(product,user,context),InstallLocation=Read(product,user,context,"InstallLocation"),LocalPackage=Read(product,user,context,"LocalPackage"),State=Read(product,user,context,"State")});\n  }\n  throw new InvalidOperationException("MSI_CONTEXT_ENUM_BOUND");\n }\n public sealed class IdentityRow {public string ProductCode,Sid;public uint Context;}\n public static IdentityRow[] Catalogue() {\n  List<IdentityRow> rows=new List<IdentityRow>();uint thread=GetCurrentThreadId();\n  for(uint index=0;index<256;index++) {\n   StringBuilder code=new StringBuilder(39),sid=new StringBuilder(185);uint sidLength=184,context;\n   uint rc=MsiEnumProductsExW(null,"S-1-1-0",7,index,code,out context,sid,ref sidLength);\n   if(rc==259){rows.Sort((a,b)=>String.CompareOrdinal(a.ProductCode+"|"+a.Context+"|"+a.Sid,b.ProductCode+"|"+b.Context+"|"+b.Sid));return rows.ToArray();}\n   if(rc!=0 || sidLength>184 || (context!=1 && context!=2 && context!=4) || GetCurrentThreadId()!=thread || (context==4 && sid.Length!=0))throw new InvalidOperationException("FIXTURE_CATALOGUE:"+rc);\n   rows.Add(new IdentityRow{ProductCode=code.ToString(),Sid=sid.ToString(),Context=context});\n  }\n  throw new InvalidOperationException("FIXTURE_CATALOGUE_BOUND");\n }\n\n}\n'

INSTALLED_CONTEXT_PS="\n# SOURCE DRAFT: prepend exact frozen msi_scope_script prefix/actor/private Win32 type.\nAdd-Type -TypeDefinition @'\n__EXACT_CONTEXT_CS__\n'@ -ReferencedAssemblies @('System','System.Core')\n$holders=@();$streams=@();$databases=@();$installer=$null;$rows=@();$cacheRows=@()\ntry{\n function Hold-ContextPath([string]$path,[bool]$directory){\n  $handle=[TertiaryPrivateStage]::Hold($path,$directory);$script:holders+=@($handle)\n  $id=[TertiaryPrivateStage]::Pin($handle,$directory);$script:rows+=@([ordered]@{path=$path;handle=$handle;nativeId=$id;directory=$directory});return $handle\n }\n function Assert-ContextFiles {foreach($row in $rows){[TertiaryPrivateStage]::Match($row.path,$row.handle,$row.nativeId,$row.directory)}}\n function Hash-ContextStream($stream){$stream.Position=0;$algorithm=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}}\n foreach($path in @('C:\\','C:\\ProgramData',$root,'C:\\Windows','C:\\Windows\\Installer','C:\\Users','C:\\Users\\parityagent','C:\\Users\\parityagent\\AppData','C:\\Users\\parityagent\\AppData\\Local','C:\\Users\\parityagent\\AppData\\Local\\Temp')){$null=Hold-ContextPath $path $true}\n if([TertiaryPrivateStage]::Pin($holders[2],$true) -cne $expectedRoot){throw 'CONTEXT_TARGET_ROOT_ID'}\n $target=Join-Path $root 'vpn-control-2.2.2.msi';$targetHandle=Hold-ContextPath $target $false\n if([TertiaryPrivateStage]::Pin($targetHandle,$false) -cne $expectedTarget){throw 'CONTEXT_TARGET_FILE_ID'}\n $targetRead=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams+=@($targetRead)\n if($targetRead.Length -ne 131101044 -or (Hash-ContextStream $targetRead) -cne 'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc'){throw 'CONTEXT_TARGET_SOURCE'}\n $actor=Assert-Actor;$snapshot=[TertiaryInstalledContext]::Enumerate();$installer=New-Object -ComObject WindowsInstaller.Installer\n if($snapshot.Selected.Count -gt 8){throw 'CONTEXT_SELECTED_BOUND'}\n foreach($product in $snapshot.Selected){\n  if($product.State -cne '5'){throw 'CONTEXT_RELEVANT_NOT_INSTALLED'}\n  $cache=[IO.Path]::GetFullPath($product.LocalPackage)\n  if($cache -notmatch '^C:\\\\Windows\\\\Installer\\\\[A-Za-z0-9_-]+\\.msi$'){throw 'CONTEXT_CACHED_PATH'}\n  $file=Hold-ContextPath $cache $false;$stream=[IO.File]::Open($cache,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams+=@($stream)\n  if($stream.Length -le 0 -or $stream.Length -gt 268435456){throw 'CONTEXT_CACHED_SIZE'}\n  $hash=Hash-ContextStream $stream;$database=$installer.OpenDatabase($cache,0);$databases+=@($database)\n  $view=$database.OpenView('SELECT `Property`,`Value` FROM `Property`');$view.Execute();$properties=@();$propertyCount=0\n  try{while($record=$view.Fetch()){if($propertyCount -ge 128){throw 'CONTEXT_PROPERTY_BOUND'};$propertyCount++;$name=[string]$record.StringData(1);$value=[string]$record.StringData(2);if($name.Length -gt 512 -or $value.Length -gt 512){throw 'CONTEXT_PROPERTY_SIZE'};if($name -cin @('ProductCode','ProductVersion','ProductName','UpgradeCode','ALLUSERS','MSIINSTALLPERUSER')){$properties+=@([ordered]@{name=$name;value=$value})}}}finally{$view.Close()}\n  $cacheRows+=@([ordered]@{productCode=$product.ProductCode;context=$product.Context;sid=$product.Sid;name=$product.Name;version=$product.Version;assignmentType=$product.AssignmentType;installLocation=$product.InstallLocation;state=$product.State;path=$cache;sha256=$hash;length=$stream.Length;nativeId=[TertiaryPrivateStage]::Pin($file,$false);properties=$properties;databaseMode=0})\n }\n # Known state paths are observed, never created or cleared. Unexpected state blocks provisioning.\n $statePaths=@('C:\\Users\\parityagent\\.vpn-control-desktop','C:\\Users\\parityagent\\AppData\\Local\\Temp\\vpn-control-tertiary-scenarios');$statePresence=@()\n foreach($path in $statePaths){$exists=$true;try{$null=[IO.File]::GetAttributes($path)}catch [IO.FileNotFoundException]{$exists=$false}catch [IO.DirectoryNotFoundException]{$exists=$false};$statePresence+=@([ordered]@{path=$path;exists=$exists});if($exists){throw 'CONTEXT_PREEXISTING_STATE_HOLD'}}\n Assert-ContextFiles;$closingActor=Assert-Actor;$closing=[TertiaryInstalledContext]::Enumerate()\n if(($snapshot|ConvertTo-Json -Depth 6 -Compress) -cne ($closing|ConvertTo-Json -Depth 6 -Compress)){throw 'CONTEXT_ENUM_CLOSING'}\n foreach($path in $statePaths){$exists=$true;try{$null=[IO.File]::GetAttributes($path)}catch [IO.FileNotFoundException]{$exists=$false}catch [IO.DirectoryNotFoundException]{$exists=$false};if($exists){throw 'CONTEXT_STATE_CLOSING'}}\n $out=[ordered]@{state='readonly-tertiary-install-context';observerSid='S-1-5-18';ownerObservation=$closingActor;enumerated=$snapshot.Enumerated;products=$cacheRows;statePresence=$statePresence;targetRootNativeId=$expectedRoot;targetNativeId=$expectedTarget;targetSha256='f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc';targetLength=131101044;rootAcl=(Observe-Acl $root $true);targetAcl=(Observe-Acl $target $false);installerAction=$false;productAcceptance=$false;publicOFF='UNRESOLVED';installAdmitted=$false}\n $json=$out|ConvertTo-Json -Depth 8 -Compress;if([Text.Encoding]::UTF8.GetByteCount($json) -gt 16384){throw 'CONTEXT_OUTPUT_BOUND'}\n Assert-ContextFiles;[Console]::Out.WriteLine($json)\n}finally{foreach($database in $databases){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)};if($installer){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)};foreach($stream in $streams){$stream.Dispose()};foreach($handle in $holders){$handle.Dispose()}}\n"

def installed_fixture_context_script(request,retained_custodian,correlation):
    """Observe collision facts before proposing any fixture installer command."""
    original=msi_scope_script(request,retained_custodian,correlation)
    if original.count(MSI_SCOPE_PS)!=1:raise ValueError('tertiary-context-prefix')
    if INSTALLED_CONTEXT_PS.count('__EXACT_CONTEXT_CS__')!=1:raise ValueError('tertiary-context-native-source')
    return original.split(MSI_SCOPE_PS,1)[0]+INSTALLED_CONTEXT_PS.replace('__EXACT_CONTEXT_CS__',INSTALLED_CONTEXT_CS,1)


def validate_installed_fixture_context(receipt,request,retained_custodian):
    """Typed read-only facts; even a matching context does not admit an install."""
    import json,re
    def require(value):
        if not value:raise ValueError('tertiary-install-context')
    require(type(receipt)is dict and set(receipt)=={'state','observerSid','ownerObservation','enumerated','products','statePresence','targetRootNativeId','targetNativeId','targetSha256','targetLength','rootAcl','targetAcl','installerAction','productAcceptance','publicOFF','installAdmitted'})
    require(receipt['state']=='readonly-tertiary-install-context'and receipt['observerSid']=='S-1-5-18')
    require(all(receipt[key]is False for key in ('installerAction','productAcceptance','installAdmitted'))and receipt['publicOFF']=='UNRESOLVED')
    require(len(json.dumps(receipt,ensure_ascii=False,separators=(',',':')).encode())<=16384)
    require(type(receipt['enumerated'])is int and 0<=receipt['enumerated']<256)
    require(receipt['targetRootNativeId']==retained_custodian['rootNativeId']and receipt['targetNativeId']==retained_custodian['targetNativeId']and receipt['targetSha256']==request['targetSha256']and type(receipt['targetLength'])is int and receipt['targetLength']==TARGET_SIZE)
    validate_custody_owner(receipt['ownerObservation']);validate_target_custody_acl(receipt['rootAcl'],receipt['targetAcl'],request)
    expected=[r'C:\Users\parityagent\.vpn-control-desktop',r'C:\Users\parityagent\AppData\Local\Temp\vpn-control-tertiary-scenarios']
    require(type(receipt['statePresence'])is list and len(receipt['statePresence'])==2)
    for row,path in zip(receipt['statePresence'],expected):require(type(row)is dict and set(row)=={'path','exists'}and row['path']==path and row['exists']is False)
    require(type(receipt['products'])is list and len(receipt['products'])<=8)
    seen=set()
    for row in receipt['products']:
        require(type(row)is dict and set(row)=={'productCode','context','sid','name','version','assignmentType','installLocation','state','path','sha256','length','nativeId','properties','databaseMode'})
        require(type(row['context'])is int and row['context']in (1,2,4)and type(row['sid'])is str and (row['sid']==''if row['context']==4 else re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+){1,15}',row['sid'])is not None and len(row['sid'])<=184))
        assignment=row['assignmentType']
        require(type(assignment)is dict and set(assignment)=={'available','returnCode','value','legacyRejected'}and type(assignment['returnCode'])is int and type(assignment['available'])is bool and type(assignment['legacyRejected'])is bool)
        if assignment['returnCode']==1608:require(assignment['available']is False and assignment['value']is None and assignment['legacyRejected']is True)
        else:require(assignment['returnCode']==0 and assignment['available']is True and assignment['legacyRejected']is False and assignment['value']==('1'if row['context']==4 else '0'))
        require(type(row['productCode'])is str and re.fullmatch(r'\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}',row['productCode'])is not None)
        identity=(row['productCode'],row['context'],row['sid']);require(identity not in seen);seen.add(identity)
        require(row['name']in ('vpn-control','VPN Control')and row['state']=='5'and type(row['version'])is str and len(row['version'])<=32)
        require(type(row['path'])is str and re.fullmatch(r'C:\\Windows\\Installer\\[A-Za-z0-9_-]+\.msi',row['path'],re.IGNORECASE|re.ASCII)is not None)
        require(type(row['installLocation'])is str and len(row['installLocation'])<=4096 and type(row['nativeId'])is str and 0<len(row['nativeId'])<160)
        require(type(row['length'])is int and 0<row['length']<=268435456 and type(row['sha256'])is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])is not None and type(row['databaseMode'])is int and row['databaseMode']==0)
        require(type(row['properties'])is list and len(row['properties'])<=6)
        properties={}
        for item in row['properties']:
            require(type(item)is dict and set(item)=={'name','value'}and item['name']in ('ProductCode','ProductVersion','ProductName','UpgradeCode','ALLUSERS','MSIINSTALLPERUSER')and item['name']not in properties and type(item['value'])is str and len(item['value'])<=512)
            properties[item['name']]=item['value']
        require(properties.get('ProductCode')==row['productCode']and properties.get('ProductVersion')==row['version']and properties.get('ProductName')==row['name']and type(properties.get('UpgradeCode'))is str and re.fullmatch(r'\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}',properties['UpgradeCode'])is not None)
    return True


def compact_installed_fixture_context(receipt,raw,request,retained_custodian):
    """Keep the bounded context receipt intact; no installer admission derived."""
    import json
    validate_installed_fixture_context(receipt,request,retained_custodian)
    if type(raw)is not bytes or not 0<len(raw)<=16384 or json.loads(raw.decode('utf-8-sig'))!=receipt:
        raise ValueError('tertiary-install-context-raw')
    return receipt


FIXTURE_PROCESS_CS='using System;\nusing System.ComponentModel;\nusing System.IO;\nusing System.Threading;\nusing System.Threading.Tasks;\nusing System.Security.Cryptography;\nusing System.Runtime.InteropServices;\npublic static class TertiaryFixtureProcess {\n [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);\n [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int tokenClass,IntPtr buffer,int length,out int returned);\n public static long Birth(IntPtr process) {\n  long creation,exit,kernel,user;\n  if(!GetProcessTimes(process,out creation,out exit,out kernel,out user))throw new Win32Exception(Marshal.GetLastWin32Error());\n  if(creation<=0)throw new InvalidOperationException("FIXTURE_PROCESS_BIRTH");\n  return creation;\n }\n public static bool Elevated(IntPtr token) {\n  IntPtr buffer=Marshal.AllocHGlobal(4);\n  try{int returned;if(!GetTokenInformation(token,20,buffer,4,out returned)||returned!=4)throw new Win32Exception(Marshal.GetLastWin32Error());return Marshal.ReadInt32(buffer)!=0;}\n  finally{Marshal.FreeHGlobal(buffer);}\n }\n public sealed class DrainResult {public long bytes;public int retainedBytes;public string sha256;}\n public static Task<DrainResult> StartDrain(Stream input,Stream retained,int cap) {return Task.Factory.StartNew(()=>Drain(input,retained,cap),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);}\n public static DrainResult Drain(Stream input,Stream retained,int cap) {\n  if(cap<0 || cap>2097152)throw new ArgumentOutOfRangeException("cap");\n  byte[] buffer=new byte[65536];long total=0;int kept=0;\n  using(SHA256 hash=SHA256.Create()) {\n   int count;\n   while((count=input.Read(buffer,0,buffer.Length))>0) {\n    checked{total+=count;}\n    hash.TransformBlock(buffer,0,count,buffer,0);\n    int copy=Math.Min(count,cap-kept);if(copy>0){retained.Write(buffer,0,copy);kept+=copy;}\n   }\n   hash.TransformFinalBlock(new byte[0],0,0);retained.Flush();\n   return new DrainResult{bytes=total,retainedBytes=kept,sha256=BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant()};\n  }\n }\n\n}\n'


FIXTURE_LIMITED_PS = 'param([Parameter(Mandatory=$true)][string]$ExpectedBodySha256,[Parameter(Mandatory=$true)][string]$ExpectedMsiexecSha256,[Parameter(Mandatory=$true)][string]$ExpectedMsiexecNativeId,[Parameter(Mandatory=$true)][string]$ExpectedRootNativeId)\n$ErrorActionPreference=\'Stop\';Set-StrictMode -Version 2\n# Fixed factory replaces only these source-owned placeholders.\n$correlation=\'__CORRELATION__\';$recipientSid=\'S-1-5-21-606332539-4179368406-55829832-1000\';$root=\'__PRIVATE_ROOT__\'\n$msi=\'C:\\ProgramData\\VpnControlTertiaryFixture-67bdf8b5-d34c-42e1-83ec-a6b3e0af7943\\vpn-control-2.2.2.msi\'\n$expectedMsiId=\'275438598:720896:143164:8224:128959732:31282499\';$expectedMsiHash=\'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc\'\nAdd-Type -TypeDefinition @\'\n__PRIVATE_CS__\n\'@ -ReferencedAssemblies @(\'System\',\'System.Core\')\nAdd-Type -TypeDefinition @\'\n__PROCESS_CS__\n\'@ -ReferencedAssemblies @(\'System\',\'System.Core\')\nAdd-Type -TypeDefinition @\'\n__SYSTEM_INSTALLER_CS__\n\'@ -ReferencedAssemblies @(\'System\',\'System.Core\')\n$fixturePhase=\'limited-source-admission\';$fixturePurpose=\'original-limited-fixture\';$fixtureOperand=\'body.ps1\';$holders=@();$readers=@();$writers=@();$process=$null;$outCopy=$null;$errCopy=$null;$started=$false;$admitted=$false;$originalHandle=[IntPtr]::Zero;$originalBirth=0L\nfunction Hash-Stream([IO.Stream]$stream){$stream.Position=0;$hash=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace(\'-\',\'\').ToLowerInvariant()}finally{$hash.Dispose();$stream.Position=0}}\nfunction Hold-Path([string]$path,[bool]$directory){$h=[TertiaryPrivateStage]::Hold($path,$directory);$script:holders+=@($h);return $h}\nfunction Create-OwnedFile([string]$name){if($name -cnotmatch \'^[a-z-]+\\.(json|raw|log|complete)$\'){throw \'FIXTURE_FILE_ROLE\'};$path=Join-Path $root $name;$h=[TertiaryPrivateStage]::CreateTargetOwned($path,$recipientSid);$script:holders+=@($h);return [ordered]@{path=$path;handle=$h}}\nfunction Write-Record([string]$name,[object]$value){\n $bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 8 -Compress));if($bytes.Length -gt 32768){throw \'FIXTURE_RECORD_BOUND\'}\n $file=Create-OwnedFile $name;$w=[IO.File]::Open($file.path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)\n try{$w.Write($bytes,0,$bytes.Length);$w.Flush($true)}finally{$w.Dispose()}\n $r=[IO.File]::Open($file.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:readers+=@($r)\n $id=[TertiaryPrivateStage]::Pin($file.handle,$false);[TertiaryPrivateStage]::Match($file.path,$file.handle,$id,$false)\n $algorithm=[Security.Cryptography.SHA256]::Create();try{$expected=[BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace(\'-\',\'\').ToLowerInvariant()}finally{$algorithm.Dispose()}\n if((Hash-Stream $r) -cne $expected){throw \'FIXTURE_RECORD_BYTES\'}\n # Consumer cannot observe partially written JSON: ready is created only after the deny-write reader seals it.\n $null=Create-OwnedFile ($name.Split(\'.\')[0]+\'.complete\')\n}\nfunction Finish-Drains {\n $tasks=@();if($outCopy){$tasks+=@($outCopy)};if($errCopy){$tasks+=@($errCopy)}\n if($tasks.Count -gt 0){[Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks)}\n foreach($writer in $writers){$writer.Flush($true);$writer.Dispose()};$script:writers=@()\n}\ntry{\n $self=[IO.Path]::GetFullPath($PSCommandPath);if($self -cne (Join-Path $root \'body.ps1\')){throw \'FIXTURE_BODY_PATH\'}\n foreach($ancestor in @(\'C:\\\',\'C:\\ProgramData\',\'C:\\Windows\',\'C:\\Windows\\System32\')){$null=Hold-Path $ancestor $true}\n $rootHandle=Hold-Path $root $true;$rootId=[TertiaryPrivateStage]::Pin($rootHandle,$true);if($rootId -cne $ExpectedRootNativeId){throw \'FIXTURE_ROOT_NATIVE_ID\'}\n $bodyHandle=Hold-Path $self $false;$bodyReader=[IO.File]::Open($self,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$readers+=@($bodyReader)\n if((Hash-Stream $bodyReader) -cne $ExpectedBodySha256){throw \'FIXTURE_BODY_SHA\'}\n $identity=[Security.Principal.WindowsIdentity]::GetCurrent();try{if($identity.User.Value -cne $recipientSid -or [TertiaryFixtureProcess]::Elevated($identity.Token)){throw \'FIXTURE_LIMITED_ACTOR\'}}finally{$identity.Dispose()}\n $selfProcess=[Diagnostics.Process]::GetCurrentProcess();$selfHandle=$selfProcess.Handle;$selfBirth=[TertiaryFixtureProcess]::Birth($selfHandle)\n if($selfProcess.SessionId -ne 1 -or -not [Environment]::Is64BitProcess){throw \'FIXTURE_SESSION_ARCH\'}\n $all=@(Get-CimInstance Win32_Process -ErrorAction Stop);if(@($all|Where-Object{$_.Name -in @(\'vpn-control.exe\',\'vpn-control-cli.exe\',\'sing-box.exe\',\'msiexec.exe\',\'consent.exe\')}).Count -ne 0){throw \'FIXTURE_EFFECT_OWNER\'}\n $admitted=$true\n Write-Record \'body-started.json\' ([ordered]@{correlation=$correlation;bodyPid=$PID;bodyBirth=$selfBirth;bodySha256=$ExpectedBodySha256;sid=$recipientSid;session=1;limited=$true;rootNativeId=$rootId;desktopFolder=[Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory);programsFolder=[Environment]::GetFolderPath([Environment+SpecialFolder]::Programs);replayAllowed=$false;productAcceptance=$false})\n $msiRoot=Hold-Path ([IO.Path]::GetDirectoryName($msi)) $true;if([TertiaryPrivateStage]::Pin($msiRoot,$true) -cne \'275438598:851968:143163:8208:128917546:31282499\'){throw \'FIXTURE_MSI_ROOT_ID\'};$msiHandle=Hold-Path $msi $false\n [TertiaryPrivateStage]::Match($msi,$msiHandle,$expectedMsiId,$false)\n $msiReader=[IO.File]::Open($msi,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$readers+=@($msiReader)\n if($msiReader.Length -ne 131101044 -or (Hash-Stream $msiReader) -cne $expectedMsiHash){throw \'FIXTURE_MSI_BYTES\'}\n $fixturePhase=\'system-installer-source\';$fixturePurpose=\'fixed-system-installer-read\';$fixtureOperand=\'C:\\Windows\\System32\\msiexec.exe\';$exe=\'C:\\Windows\\System32\\msiexec.exe\';$exeHandle=[TertiarySystemInstaller]::Hold();$holders+=@($exeHandle);$exeId=[TertiarySystemInstaller]::Pin($exeHandle);if($exeId -cne $ExpectedMsiexecNativeId){throw \'FIXTURE_SYSTEM_INSTALLER_ID\'};$exeReader=[IO.File]::Open($exe,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$readers+=@($exeReader)\n if((Hash-Stream $exeReader) -cne $ExpectedMsiexecSha256){throw \'FIXTURE_SYSTEM_INSTALLER_SHA\'}\n $log=Create-OwnedFile \'installer.log\';$out=Create-OwnedFile \'stdout.raw\';$err=Create-OwnedFile \'stderr.raw\'\n $outWriter=[IO.File]::Open($out.path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$writers+=@($outWriter)\n $errWriter=[IO.File]::Open($err.path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$writers+=@($errWriter)\n $arguments=\'/i "\'+$msi+\'" /qn /norestart /l*v "\'+$log.path+\'"\'\n Write-Record \'intent.json\' ([ordered]@{correlation=$correlation;sid=$recipientSid;session=1;limited=$true;bodyPid=$PID;bodyBirth=$selfBirth;bodySha256=$ExpectedBodySha256;packageSha256=$expectedMsiHash;packageNativeId=$expectedMsiId;exe=$exe;exeSha256=$ExpectedMsiexecSha256;exeNativeId=$exeId;arguments=$arguments;rootNativeId=$rootId;logNativeId=[TertiaryPrivateStage]::Pin($log.handle,$false);replayAllowed=$false;fixtureProvision=$true;productAcceptance=$false})\n [TertiaryPrivateStage]::Match($root,$rootHandle,$rootId,$true);[TertiaryPrivateStage]::Match($msi,$msiHandle,$expectedMsiId,$false);[TertiarySystemInstaller]::Match($exeHandle,$exeId);if((Hash-Stream $exeReader) -cne $ExpectedMsiexecSha256){throw \'FIXTURE_SYSTEM_INSTALLER_CLOSING_SHA\'}\n $process=New-Object Diagnostics.Process;$info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$exe;$info.Arguments=$arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.WorkingDirectory=$root;$process.StartInfo=$info\n $fixturePhase=\'installer-dispatch\';$fixturePurpose=\'original-limited-msiexec\';$fixtureOperand=$exe;if(-not $process.Start()){throw \'FIXTURE_INSTALLER_START\'};$started=$true;$originalHandle=$process.Handle;$originalPid=$process.Id\n # Native delegates avoid PowerShell runspace assumptions on drain threads.\n $outCopy=[TertiaryFixtureProcess]::StartDrain($process.StandardOutput.BaseStream,$outWriter,2097152)\n $errCopy=[TertiaryFixtureProcess]::StartDrain($process.StandardError.BaseStream,$errWriter,2097152)\n $originalBirth=[TertiaryFixtureProcess]::Birth($originalHandle)\n Write-Record \'started.json\' ([ordered]@{correlation=$correlation;bodyPid=$PID;bodyBirth=$selfBirth;originalPid=$originalPid;originalBirth=$originalBirth;bodySha256=$ExpectedBodySha256;packageSha256=$expectedMsiHash;replayAllowed=$false;productAcceptance=$false})\n $watch=[Diagnostics.Stopwatch]::StartNew();$pendingWritten=$false\n while(-not $process.WaitForExit(1000)){\n  if([TertiaryFixtureProcess]::Birth($originalHandle) -ne $originalBirth){throw \'FIXTURE_ORIGINAL_PROCESS_BIRTH\'}\n  if($watch.Elapsed.TotalSeconds -ge 180 -and -not $pendingWritten){Write-Record \'pending.json\' ([ordered]@{state=\'UNKNOWN\';originalPid=$originalPid;originalBirth=$originalBirth;correlation=$correlation;replayAllowed=$false;cancelled=$false;restarted=$false});$pendingWritten=$true}\n }\n [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($outCopy,$errCopy));$outResult=$outCopy.Result;$errResult=$errCopy.Result\n Finish-Drains\n if([TertiaryFixtureProcess]::Birth($originalHandle) -ne $originalBirth){throw \'FIXTURE_ORIGINAL_TERMINAL_BIRTH\'}\n $logReader=[IO.File]::Open($log.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$readers+=@($logReader);if($logReader.Length -gt 16777216){throw \'FIXTURE_LOG_BOUND\'}\n $logSha=Hash-Stream $logReader\n [TertiaryPrivateStage]::Match($root,$rootHandle,$rootId,$true);[TertiaryPrivateStage]::Match($msi,$msiHandle,$expectedMsiId,$false);[TertiarySystemInstaller]::Match($exeHandle,$exeId);if((Hash-Stream $exeReader) -cne $ExpectedMsiexecSha256){throw \'FIXTURE_SYSTEM_INSTALLER_CLOSING_SHA\'}\n Write-Record \'terminal.json\' ([ordered]@{state=\'original-installer-terminal\';correlation=$correlation;sid=$recipientSid;session=1;bodyPid=$PID;bodyBirth=$selfBirth;originalPid=$originalPid;originalBirth=$originalBirth;exitCode=$process.ExitCode;stdout=$outResult;stderr=$errResult;logLength=$logReader.Length;logSha256=$logSha;logNativeId=[TertiaryPrivateStage]::Pin($log.handle,$false);bodySha256=$ExpectedBodySha256;packageSha256=$expectedMsiHash;replayAllowed=$false;fixtureProvision=$true;productAcceptance=$false})\n}catch{\n $originalError=$_;$diagnostic=[ordered]@{diagnosticOnly=$true;authority=$false;phase=$fixturePhase;purpose=$fixturePurpose;operand=$fixtureOperand;errorType=$originalError.Exception.GetType().FullName;errorMessage=([string]$originalError.Exception.Message).Substring(0,[Math]::Min(1024,([string]$originalError.Exception.Message).Length));scriptStackTrace=([string]$originalError.ScriptStackTrace).Substring(0,[Math]::Min(2048,([string]$originalError.ScriptStackTrace).Length));positionMessage=([string]$originalError.InvocationInfo.PositionMessage).Substring(0,[Math]::Min(1024,([string]$originalError.InvocationInfo.PositionMessage).Length));replayAllowed=$false};[Console]::Error.WriteLine(($diagnostic|ConvertTo-Json -Depth 3 -Compress))\n if($admitted){try{Write-Record \'failure.json\' ([ordered]@{state=\'UNKNOWN\';correlation=$correlation;bodyPid=$PID;bodyBirth=$selfBirth;bodySha256=$ExpectedBodySha256;phase=$fixturePhase;purpose=$fixturePurpose;operand=$fixtureOperand;scriptStackTrace=([string]$_.ScriptStackTrace).Substring(0,[Math]::Min(2048,([string]$_.ScriptStackTrace).Length));errorType=$_.Exception.GetType().FullName;errorMessage=([string]$_.Exception.Message).Substring(0,[Math]::Min(4096,([string]$_.Exception.Message).Length));installerStarted=$started;originalBirth=$originalBirth;replayAllowed=$false;productAcceptance=$false})}catch{}}\n # After creation, retain the same Process handle until actual natural exit.\n if($started -and $process){if(-not $process.HasExited){while(-not $process.WaitForExit(1000)){}};try{Finish-Drains}catch{}}\n throw\n}finally{\n foreach($writer in $writers){$writer.Dispose()};foreach($reader in $readers){$reader.Dispose()};foreach($holder in $holders){$holder.Dispose()}\n if($process -and $process.HasExited){$process.Dispose()}\n}\n'
FIXTURE_BOOTSTRAP_PS = '\nAdd-Type -TypeDefinition @\'\n__SYSTEM_INSTALLER_CS__\n\'@ -ReferencedAssemblies @(\'System\',\'System.Core\')\n\n# Exact pre-context prefix has already compiled the native types and proved old/current product identity.\n$correlation=\'__CORRELATION__\';$provisionRoot=\'__PRIVATE_ROOT__\';$bodySha=\'__BODY_SHA__\';$bodyBytesLength=__BODY_LENGTH__;$bodyGzip=\'__BODY_GZIP__\'\n$recipientSid=\'S-1-5-21-606332539-4179368406-55829832-1000\';$taskName=\'VpnControlTertiaryFixture-\'+$correlation\nif($preContext.products.Count -ne 1){throw \'FIXTURE_RELEVANT_CATALOGUE\'}\n$old=$preContext.products[0];$oldProperties=@{};foreach($item in $old.properties){$oldProperties[$item.name]=$item.value}\nif($old.productCode -cne \'{87F491A1-A193-3271-8AE2-C0877718FAB0}\' -or $old.context -ne 2 -or $old.sid -cne $recipientSid -or $old.version -cne \'2.1.8\' -or $oldProperties.UpgradeCode -cne \'{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}\' -or $old.installLocation -ine \'C:\\Users\\parityagent\\AppData\\Local\\vpn-control\\\' -or $old.sha256 -cne \'dae25cab85d53e8e0fce098536bd807097971746cfe40a24e3680af63180b093\'){throw \'FIXTURE_PRE_CONTEXT_BINDING\'}\nif(([IO.DriveInfo]::new(\'C:\\\')).AvailableFreeSpace -lt 1073741824){throw \'FIXTURE_DISK_RESERVE\'}\n$preCatalogue=@([TertiaryInstalledContext]::Catalogue());$preCatalogueJson=$preCatalogue|ConvertTo-Json -Depth 4 -Compress\n$fixturePhase=\'system-source-admission\';$fixturePurpose=\'fixed-source-custody\';$fixtureOperand=\'private-provision-root\';$exeHandle=$null;$exeReader=$null;$holders=@();$streams=@();$recordPins=@();$observedRecords=@{};$taskStarted=$false;$rootCreated=$false\nfunction Hold-FixturePath([string]$path,[bool]$directory){$h=[TertiaryPrivateStage]::Hold($path,$directory);$script:holders+=@($h);return $h}\nfunction Write-FixtureSource([string]$path,[byte[]]$bytes){$h=[TertiaryPrivateStage]::CreateTargetOwned($path,\'S-1-5-18\');$script:holders+=@($h);$w=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);try{$w.Write($bytes,0,$bytes.Length);$w.Flush($true)}finally{$w.Dispose()};$r=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:streams+=@($r);return [ordered]@{path=$path;handle=$h;reader=$r;nativeId=[TertiaryPrivateStage]::Pin($h,$false);sha256=(Hash-ContextStream $r)}}\nfunction Read-FixtureRecord([string]$name,[int]$cap){\n $readyPath=Join-Path $provisionRoot ($name.Split(\'.\')[0]+\'.complete\');$ready=Hold-FixturePath $readyPath $false;$readyId=[TertiaryPrivateStage]::Pin($ready,$false)\n $readyReader=[IO.File]::Open($readyPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:streams+=@($readyReader);if($readyReader.Length -ne 0){throw \'FIXTURE_READY_LENGTH\'}\n $path=Join-Path $provisionRoot $name;$h=Hold-FixturePath $path $false;$r=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$script:streams+=@($r)\n if($r.Length -le 0 -or $r.Length -gt $cap){throw \'FIXTURE_READ_BOUND\'};$bytes=New-Object byte[] ([int]$r.Length);$offset=0\n while($offset -lt $bytes.Length){$count=$r.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){throw \'FIXTURE_RECORD_EOF\'};$offset+=$count};$r.Position=0\n $nativeId=[TertiaryPrivateStage]::Pin($h,$false);$sha=Hash-ContextStream $r;[TertiaryPrivateStage]::Match($path,$h,$nativeId,$false)\n $script:recordPins+=@([ordered]@{path=$path;handle=$h;reader=$r;nativeId=$nativeId;sha256=$sha;length=$bytes.Length;readyPath=$readyPath;ready=$ready;readyId=$readyId})\n return [ordered]@{value=([Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json);path=$path;nativeId=$nativeId;sha256=$sha;length=$bytes.Length}\n}\nfunction Assert-FixtureRecords {if($exeHandle){[TertiarySystemInstaller]::Match($exeHandle,$exeId);if($exeReader -and (Hash-ContextStream $exeReader) -cne $exeSha){throw \'FIXTURE_SYSTEM_INSTALLER_CLOSING_SHA\'}};foreach($pin in $recordPins){[TertiaryPrivateStage]::Match($pin.path,$pin.handle,$pin.nativeId,$false);[TertiaryPrivateStage]::Match($pin.readyPath,$pin.ready,$pin.readyId,$false);if($pin.reader.Length -ne $pin.length -or (Hash-ContextStream $pin.reader) -cne $pin.sha256){throw \'FIXTURE_RECORD_CLOSING\'}}}\nfunction Sid-Of([string]$user){if($user -cmatch \'^S-1-\') {return ([Security.Principal.SecurityIdentifier]::new($user)).Value};if([string]::IsNullOrWhiteSpace($user)){throw \'FIXTURE_TASK_USER\'};return ([Security.Principal.NTAccount]::new($user)).Translate([Security.Principal.SecurityIdentifier]).Value}\nfunction Assert-FixtureTask([string]$expectedArguments){$t=Get-ScheduledTask -TaskPath \'\\\' -TaskName $taskName -ErrorAction Stop;$actions=@($t.Actions);if((Sid-Of ([string]$t.Principal.UserId)) -cne $recipientSid -or [string]$t.Principal.LogonType -cne \'Interactive\' -or [string]$t.Principal.RunLevel -cne \'Limited\' -or @($t.Triggers | Where-Object {$null -ne $_}).Count -ne 0 -or $t.Settings.RestartCount -ne 0 -or [string]$t.Settings.MultipleInstances -cne \'IgnoreNew\' -or [string]$t.Settings.ExecutionTimeLimit -cne \'PT0S\' -or $actions.Count -ne 1 -or $actions[0].Execute -cne \'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\' -or $actions[0].Arguments -cne $expectedArguments){$facts=@([ordered]@{name=\'sid\';actual=(Sid-Of ([string]$t.Principal.UserId));expected=$recipientSid},[ordered]@{name=\'logonType\';actual=[string]$t.Principal.LogonType;expected=\'Interactive\'},[ordered]@{name=\'runLevel\';actual=[string]$t.Principal.RunLevel;expected=\'Limited\'},[ordered]@{name=\'triggers\';actual=@($t.Triggers | Where-Object {$null -ne $_}).Count;expected=0},[ordered]@{name=\'restartCount\';actual=$t.Settings.RestartCount;expected=0},[ordered]@{name=\'multipleInstances\';actual=[string]$t.Settings.MultipleInstances;expected=\'IgnoreNew\'},[ordered]@{name=\'executionTimeLimit\';actual=[string]$t.Settings.ExecutionTimeLimit;expected=\'PT0S\'},[ordered]@{name=\'actionCount\';actual=$actions.Count;expected=1},[ordered]@{name=\'execute\';actual=if($actions.Count -eq 1){$actions[0].Execute}else{$null};expected=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\'},[ordered]@{name=\'arguments\';actual=if($actions.Count -eq 1){$actions[0].Arguments}else{$null};expected=$expectedArguments});$failed=@();foreach($f in $facts){if($f.actual -cne $f.expected){$failed+=@([ordered]@{name=$f.name;actual=$f.actual;expected=$f.expected;actualType=if($null -eq $f.actual){$null}else{$f.actual.GetType().FullName};expectedType=$f.expected.GetType().FullName})}};$diagnostic=[ordered]@{state=\'task-binding-operand\';diagnosticOnly=$true;authority=$false;taskName=$taskName;failed=$failed;replayAllowed=$false};$taskDiagnosticJson=$diagnostic|ConvertTo-Json -Depth 5 -Compress;if([Text.Encoding]::UTF8.GetByteCount($taskDiagnosticJson) -le 32768){[Console]::Error.WriteLine($taskDiagnosticJson)};throw \'FIXTURE_TASK_BINDING\'};return $t}\ntry{\n foreach($ancestor in @(\'C:\\\',\'C:\\ProgramData\',\'C:\\Windows\',\'C:\\Windows\\System32\')){$null=Hold-FixturePath $ancestor $true}\n $null=Assert-Actor\n [TertiaryPrivateStage]::CreateExclusive($provisionRoot,(\'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;\'+$recipientSid+\')\'));$rootCreated=$true\n $rootHandle=Hold-FixturePath $provisionRoot $true;$rootId=[TertiaryPrivateStage]::Pin($rootHandle,$true)\n Add-Type -AssemblyName System.IO.Compression\n $compressed=[Convert]::FromBase64String($bodyGzip);$input=New-Object IO.MemoryStream(,$compressed);$gzip=New-Object IO.Compression.GZipStream($input,[IO.Compression.CompressionMode]::Decompress);$output=New-Object IO.MemoryStream\n try{$buffer=New-Object byte[] 4096;while(($count=$gzip.Read($buffer,0,$buffer.Length)) -gt 0){if($output.Length+$count -gt 32768){throw \'FIXTURE_BODY_DECODE_BOUND\'};$output.Write($buffer,0,$count)};$bodyBytes=$output.ToArray()}finally{$gzip.Dispose();$input.Dispose();$output.Dispose()}\n if($bodyBytes.Length -ne $bodyBytesLength -or ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bodyBytes))).Replace(\'-\',\'\').ToLowerInvariant() -cne $bodySha){throw \'FIXTURE_BODY_DECODE_BYTES\'}\n $body=Write-FixtureSource (Join-Path $provisionRoot \'body.ps1\') $bodyBytes;if($body.sha256 -cne $bodySha){throw \'FIXTURE_BODY_WRITTEN_SHA\'}\n $fixturePhase=\'system-installer-source\';$fixturePurpose=\'fixed-system-installer-read\';$fixtureOperand=\'C:\\Windows\\System32\\msiexec.exe\';$exePath=\'C:\\Windows\\System32\\msiexec.exe\';$exeHandle=[TertiarySystemInstaller]::Hold();$holders+=@($exeHandle);$exeId=[TertiarySystemInstaller]::Pin($exeHandle);$exeReader=[IO.File]::Open($exePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams+=@($exeReader);$exeSha=Hash-ContextStream $exeReader\n $arguments=\'-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "\'+$body.path+\'" -ExpectedBodySha256 \'+$bodySha+\' -ExpectedMsiexecSha256 \'+$exeSha+\' -ExpectedMsiexecNativeId \'+$exeId+\' -ExpectedRootNativeId \'+$rootId\n if($arguments.Length -gt 8192){throw \'FIXTURE_TASK_ARGUMENT_BOUND\'}\n $intent=[ordered]@{correlation=$correlation;rootNativeId=$rootId;bodySha256=$bodySha;taskName=$taskName;taskArguments=$arguments;originalActorSid=$recipientSid;session=1;runLevel=\'Limited\';logonType=\'Interactive\';preCatalogue=$preCatalogue;preContext=$preContext;targetProductCode=\'{2D8D2946-3492-3C19-A837-87C54F9311A9}\';targetUpgradeCode=\'{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}\';targetSha256=\'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc\';ALLUSERS=@{present=$false;value=$null};MSIINSTALLPERUSER=@{present=$false;value=$null};fixtureProvision=$true;productAcceptance=$false;replayAllowed=$false}\n $intentSource=Write-FixtureSource (Join-Path $provisionRoot \'dispatch.json\') ([Text.Encoding]::UTF8.GetBytes(($intent|ConvertTo-Json -Depth 10 -Compress)))\n $action=New-ScheduledTaskAction -Execute \'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\' -Argument $arguments\n $principal=New-ScheduledTaskPrincipal -UserId $recipientSid -LogonType Interactive -RunLevel Limited\n $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n Register-ScheduledTask -TaskPath \'\\\' -TaskName $taskName -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null\n $null=Assert-FixtureTask $arguments;$null=Assert-Actor\n if(($preCatalogue|ConvertTo-Json -Depth 4 -Compress) -cne ([TertiaryInstalledContext]::Catalogue()|ConvertTo-Json -Depth 4 -Compress)){throw \'FIXTURE_PRE_CATALOGUE_CLOSING\'}\n [TertiaryPrivateStage]::Match($provisionRoot,$rootHandle,$rootId,$true);[TertiaryPrivateStage]::Match($body.path,$body.handle,$body.nativeId,$false);if((Hash-ContextStream $body.reader) -cne $bodySha){throw \'FIXTURE_PRE_BODY_CLOSING\'}\n $fixturePhase=\'limited-task-dispatch\';$fixturePurpose=\'original-limited-msiexec\';$fixtureOperand=$taskName;Start-ScheduledTask -TaskPath \'\\\' -TaskName $taskName -ErrorAction Stop;$taskStarted=$true\n $watch=[Diagnostics.Stopwatch]::StartNew();$state=\'UNKNOWN\';$terminal=$null;$bodyStarted=$null;$installerStarted=$null;$failure=$null\n while($watch.Elapsed.TotalSeconds -lt 190){\n  $task=Assert-FixtureTask $arguments\n  foreach($role in @(\'body-started.json\',\'started.json\',\'terminal.json\',\'failure.json\')){\n   $readyPath=Join-Path $provisionRoot ($role.Split(\'.\')[0]+\'.complete\');if($observedRecords.ContainsKey($role)){continue};try{$attr=[IO.File]::GetAttributes($readyPath)}catch [IO.FileNotFoundException]{continue}\n   $record=Read-FixtureRecord $role 32768;$observedRecords[$role]=$record;if($record.value.correlation -cne $correlation -or $record.value.bodySha256 -cne $bodySha -or $record.value.replayAllowed -ne $false){throw \'FIXTURE_RECORD_BINDING\'}\n   switch($role){\'body-started.json\'{$bodyStarted=$record};\'started.json\'{$installerStarted=$record};\'terminal.json\'{$terminal=$record};\'failure.json\'{$failure=$record}}\n  }\n  if($terminal -and [string]$task.State -cne \'Running\'){$state=\'original-fixture-installer-terminal\';break}\n  if($failure -and [string]$task.State -cne \'Running\'){break}\n  Start-Sleep -Milliseconds 250\n }\n Assert-FixtureRecords\n $postCatalogue=@([TertiaryInstalledContext]::Catalogue());$all=@(Get-CimInstance Win32_Process -ErrorAction Stop);$effects=@($all|Where-Object{$_.Name -in @(\'vpn-control.exe\',\'vpn-control-cli.exe\',\'sing-box.exe\',\'msiexec.exe\',\'consent.exe\')}|ForEach-Object{[ordered]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;command=$_.CommandLine;created=$_.CreationDate;session=$_.SessionId}})\n __POST_IMAGE_PS__\n [TertiaryPrivateStage]::Match($provisionRoot,$rootHandle,$rootId,$true);[TertiaryPrivateStage]::Match($body.path,$body.handle,$body.nativeId,$false);if((Hash-ContextStream $body.reader) -cne $bodySha){throw \'FIXTURE_POST_BODY_CLOSING\'}\n Assert-FixtureRecords\n if($postImage){\n  Assert-FixtureImageMembership\n  if(($postCatalogue|ConvertTo-Json -Depth 4 -Compress) -cne ([TertiaryInstalledContext]::Catalogue()|ConvertTo-Json -Depth 4 -Compress)){throw \'FIXTURE_POST_CATALOGUE_CLOSING\'}\n }\n $interactive=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName\n if($interactive -cne \'VPNPARITYX64\\parityagent\'){throw \'FIXTURE_POST_INTERACTIVE_USER\'}\n $interactiveSid=([Security.Principal.NTAccount]::new($interactive)).Translate([Security.Principal.SecurityIdentifier]).Value\n $currentProcesses=@(Get-CimInstance Win32_Process -ErrorAction Stop);$currentSessions=@($currentProcesses|Where-Object{$_.Name -ceq \'explorer.exe\'}|Select-Object -ExpandProperty SessionId -Unique)\n if($interactiveSid -cne $recipientSid -or $currentSessions.Count -ne 1 -or $currentSessions[0] -ne 1){throw \'FIXTURE_POST_INTERACTIVE_SESSION\'}\n $effects=@($currentProcesses|Where-Object{$_.Name -in @(\'vpn-control.exe\',\'vpn-control-cli.exe\',\'sing-box.exe\',\'msiexec.exe\',\'consent.exe\')}|ForEach-Object{[ordered]@{pid=$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;command=$_.CommandLine;created=$_.CreationDate;session=$_.SessionId}})\n $result=[ordered]@{state=$state;correlation=$correlation;root=$provisionRoot;rootNativeId=$rootId;taskName=$taskName;bodyStarted=$bodyStarted;installerStarted=$installerStarted;terminal=$terminal;failure=$failure;preCatalogue=$preCatalogue;postCatalogue=$postCatalogue;postEffects=$effects;postImage=$postImage;postSelected=$postSelected;postShortcuts=$postShortcuts;postRegistry=$postRegistry;postState=$postState;taskState=[string]$task.State;taskStarted=$taskStarted;fixtureProvision=$true;installerAction=$true;productAcceptance=$false;replayAllowed=$false;fullInstalledImageVerified=$false}\n Assert-FixtureRecords\n $json=$result|ConvertTo-Json -Depth 14 -Compress;if($postImage){Assert-FixtureImageMembership};if([Text.Encoding]::UTF8.GetByteCount($json) -gt 262144){throw \'FIXTURE_TRANSACTION_OUTPUT_BOUND\'};[Console]::Out.WriteLine($json)\n}catch{\n $diagnostic=[ordered]@{diagnosticOnly=$true;authority=$false;phase=$fixturePhase;purpose=$fixturePurpose;operand=$fixtureOperand;errorType=$_.Exception.GetType().FullName;errorMessage=([string]$_.Exception.Message).Substring(0,[Math]::Min(1024,([string]$_.Exception.Message).Length));scriptStackTrace=([string]$_.ScriptStackTrace).Substring(0,[Math]::Min(2048,([string]$_.ScriptStackTrace).Length));positionMessage=([string]$_.InvocationInfo.PositionMessage).Substring(0,[Math]::Min(1024,([string]$_.InvocationInfo.PositionMessage).Length));replayAllowed=$false};[Console]::Error.WriteLine(($diagnostic|ConvertTo-Json -Depth 3 -Compress));throw\n}finally{\n # Leave the exact task and all evidence in place. No timeout cancellation or cleanup replay.\n foreach($stream in $streams){$stream.Dispose()};foreach($holder in $holders){$holder.Dispose()}\n}\n'
FIXTURE_POST_IMAGE_PS="# Read-only terminal footprint observation. This does not launch installed code.\n$postImage=$null;$postSelected=$null;$postShortcuts=@();$postRegistry=$null;$postState=@()\nif($state -ceq 'original-fixture-installer-terminal' -and $terminal.value.exitCode -eq 0){\n if(-not $bodyStarted -or -not $installerStarted){throw 'FIXTURE_MISSING_ORIGINAL_RECORD'}\n foreach($record in @($bodyStarted,$installerStarted,$terminal)){\n  if($record.value.bodyPid -isnot [int] -or $record.value.bodyPid -le 0 -or ($record.value.bodyBirth -isnot [long] -and $record.value.bodyBirth -isnot [int]) -or $record.value.bodyBirth -le 0){throw 'FIXTURE_BODY_NATIVE_ID_TYPE'}\n  if($record.value.bodyPid -ne $bodyStarted.value.bodyPid -or $record.value.bodyBirth -ne $bodyStarted.value.bodyBirth){throw 'FIXTURE_BODY_NATIVE_ID_BINDING'}\n }\n foreach($record in @($installerStarted,$terminal)){\n  if($record.value.originalPid -isnot [int] -or $record.value.originalPid -le 0 -or ($record.value.originalBirth -isnot [long] -and $record.value.originalBirth -isnot [int]) -or $record.value.originalBirth -le 0 -or $record.value.originalPid -ne $installerStarted.value.originalPid -or $record.value.originalBirth -ne $installerStarted.value.originalBirth){throw 'FIXTURE_ORIGINAL_INSTALLER_BINDING'}\n }\n if($terminal.value.exitCode -isnot [int] -or $terminal.value.sid -cne $recipientSid -or $terminal.value.session -ne 1 -or $terminal.value.packageSha256 -cne 'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc'){throw 'FIXTURE_ORIGINAL_TERMINAL_BINDING'}\n $snapshot=[TertiaryInstalledContext]::Enumerate();$postSelected=@($snapshot.Selected)\n if($postSelected.Count -ne 1 -or $postSelected[0].ProductCode -cne '{2D8D2946-3492-3C19-A837-87C54F9311A9}' -or $postSelected[0].Context -ne 2 -or $postSelected[0].Sid -cne $recipientSid -or $postSelected[0].Version -cne '2.2.2' -or $postSelected[0].State -cne '5' -or $postSelected[0].InstallLocation -ine 'C:\\Users\\parityagent\\AppData\\Local\\vpn-control\\'){throw 'FIXTURE_POST_CONTEXT'}\n $installRoot='C:\\Users\\parityagent\\AppData\\Local\\vpn-control';$imagePins=@();$imageRows=@();$directoryRows=@();$stack=New-Object 'Collections.Generic.Stack[string]';$stack.Push($installRoot)\n foreach($ancestor in @('C:\\Users','C:\\Users\\parityagent','C:\\Users\\parityagent\\AppData','C:\\Users\\parityagent\\AppData\\Local')){$null=Hold-FixturePath $ancestor $true}\n while($stack.Count -gt 0){\n  $directory=$stack.Pop();$dh=Hold-FixturePath $directory $true;$did=[TertiaryPrivateStage]::Pin($dh,$true);$members=@([IO.Directory]::GetFileSystemEntries($directory));$directoryRows+=@([ordered]@{path=$directory.Substring($installRoot.Length).Replace('\\','/');nativeId=$did;handle=$dh;fullPath=$directory;members=$members})\n  if($directoryRows.Count -gt 64){throw 'FIXTURE_IMAGE_DIRECTORY_BOUND'}\n  foreach($path in $members){\n   if(-not $path.StartsWith($installRoot+'\\',[StringComparison]::OrdinalIgnoreCase)){throw 'FIXTURE_IMAGE_ROOT'}\n   $attributes=[IO.File]::GetAttributes($path);if(($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'FIXTURE_IMAGE_REPARSE'}\n   if(($attributes -band [IO.FileAttributes]::Directory) -ne 0){$stack.Push($path);continue}\n   if($imageRows.Count -ge 209){throw 'FIXTURE_IMAGE_FILE_BOUND'}\n   $h=Hold-FixturePath $path $false;$id=[TertiaryPrivateStage]::Pin($h,$false);$r=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams+=@($r)\n   if($r.Length -le 0 -or $r.Length -gt 268435456){throw 'FIXTURE_IMAGE_SIZE_BOUND'}\n   $sha=Hash-ContextStream $r;$relative=$path.Substring($installRoot.Length+1).Replace('\\','/')\n   $imageRows+=@([ordered]@{path=$relative;length=$r.Length;sha256=$sha;nativeId=$id});$imagePins+=@([ordered]@{path=$path;handle=$h;nativeId=$id;reader=$r;length=$r.Length;sha256=$sha})\n  }\n }\n if($imageRows.Count -ne 209){throw 'FIXTURE_IMAGE_FILE_COUNT'}\n # User folders come from the actual original Limited task, not the SYSTEM observer's folders.\n foreach($folder in @($bodyStarted.value.desktopFolder,$bodyStarted.value.programsFolder)){\n  if($folder -isnot [string] -or -not $folder.StartsWith('C:\\Users\\parityagent\\',[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFullPath($folder) -cne $folder){throw 'FIXTURE_USER_FOLDER'}\n }\n $shortcutFolders=@($bodyStarted.value.desktopFolder,(Join-Path $bodyStarted.value.programsFolder 'VPN Control'));$shell=New-Object -ComObject WScript.Shell\n try{foreach($folder in $shortcutFolders){$null=Hold-FixturePath $folder $true;foreach($name in @('vpn-control','vpn-control-cli')){\n  $path=Join-Path $folder ($name+'.lnk');$h=Hold-FixturePath $path $false;$id=[TertiaryPrivateStage]::Pin($h,$false);$r=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams+=@($r)\n  if($r.Length -le 0 -or $r.Length -gt 65536){throw 'FIXTURE_SHORTCUT_SIZE'}\n  $link=$shell.CreateShortcut($path);try{$postShortcuts+=@([ordered]@{path=$path;target=$link.TargetPath;arguments=$link.Arguments;workingDirectory=$link.WorkingDirectory;length=$r.Length;sha256=(Hash-ContextStream $r);nativeId=$id})}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)}\n  [TertiaryPrivateStage]::Match($path,$h,$id,$false)\n }}}finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}\n $registry=[Microsoft.Win32.Registry]::Users.OpenSubKey(($recipientSid+'\\Software\\Kardinal\\vpn-control\\2.2.2'),$false)\n if(-not $registry){throw 'FIXTURE_REGISTRY_MISSING'}\n try{$names=@($registry.GetValueNames());if($names.Count -ne 1 -or $names[0] -cne 'ProductCode'){throw 'FIXTURE_REGISTRY_VALUES'};$postRegistry=[ordered]@{hive='HKEY_USERS';sid=$recipientSid;key='Software\\Kardinal\\vpn-control\\2.2.2';name='ProductCode';value=$registry.GetValue('ProductCode');kind=$registry.GetValueKind('ProductCode').ToString()}}finally{$registry.Dispose()}\n foreach($path in @('C:\\Users\\parityagent\\.vpn-control-desktop','C:\\Users\\parityagent\\AppData\\Local\\Temp\\vpn-control-tertiary-scenarios')){$exists=$true;try{$null=[IO.File]::GetAttributes($path)}catch [IO.FileNotFoundException]{$exists=$false}catch [IO.DirectoryNotFoundException]{$exists=$false};$postState+=@([ordered]@{path=$path;exists=$exists});if($exists){throw 'FIXTURE_POST_STATE_MUTATION'}}\n foreach($pin in $imagePins){[TertiaryPrivateStage]::Match($pin.path,$pin.handle,$pin.nativeId,$false);if($pin.reader.Length -ne $pin.length -or (Hash-ContextStream $pin.reader) -cne $pin.sha256){throw 'FIXTURE_IMAGE_CLOSING'}}\n foreach($directory in $directoryRows){[TertiaryPrivateStage]::Match(($installRoot+$directory.path.Replace('/','\\')),$directory.handle,$directory.nativeId,$true)}\n Assert-FixtureImageMembership\n $postImage=[ordered]@{root=$installRoot;files=@($imageRows|Sort-Object path);directories=@($directoryRows|ForEach-Object{[ordered]@{path=$_.path;nativeId=$_.nativeId;members=@($_.members|ForEach-Object{[IO.Path]::GetFileName($_)})}}|Sort-Object path);fullHash=$true;nativeReadCustody=$true;launchExecuted=$false}\n}\n"


SYSTEM_INSTALLER_CS = 'using System;\nusing System.IO;\nusing System.Runtime.InteropServices;\nusing Microsoft.Win32.SafeHandles;\npublic static class TertiarySystemInstaller {\n const string SystemPath=@"C:\\Windows\\System32\\msiexec.exe";\n [StructLayout(LayoutKind.Sequential)] struct Info {public uint Attr,CH,CL,AH,AL,WH,WL,Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow;}\n [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint access,uint share,IntPtr sa,uint create,uint flags,IntPtr template);\n [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out Info i);\n public static string Pin(SafeFileHandle h) {\n  Info i;if(h==null||h.IsInvalid||!GetFileInformationByHandle(h.DangerousGetHandle(),out i)||(i.Attr&0x400)!=0||(i.Attr&0x10)!=0||i.Links!=2)throw new IOException("SYSTEM_INSTALLER_NATIVE_IDENTITY");\n  return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL+":"+i.Links;\n }\n public static SafeFileHandle Hold() {\n  if(Path.GetFileName(SystemPath)!="msiexec.exe")throw new IOException("SYSTEM_INSTALLER_FIXED_ROLE_PATH");\n  var h=CreateFile(SystemPath,0x80000000,1,IntPtr.Zero,3,0x00200000u,IntPtr.Zero);\n  try{Pin(h);return h;}catch{h.Dispose();throw;}\n }\n public static void Match(SafeFileHandle held,string expected) {\n  if(Pin(held)!=expected)throw new IOException("SYSTEM_INSTALLER_HELD_IDENTITY");\n  using(var named=Hold()){if(Pin(named)!=expected)throw new IOException("SYSTEM_INSTALLER_NAMED_IDENTITY");}\n }\n}'

def fixture_provision_script(request,retained_custodian,correlation):
    """Fixed ordinary-recipient transaction; no execution is performed here."""
    import gzip,base64,hashlib,re
    if type(correlation)is not str or re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',correlation)is None:
        raise ValueError('tertiary-fixture-correlation')
    private_root='C:\\ProgramData\\VpnControlTertiaryProvision-'+correlation
    body=FIXTURE_LIMITED_PS
    for key,value in {'__CORRELATION__':correlation,'__PRIVATE_ROOT__':private_root,'__PRIVATE_CS__':PRIVATE_CS,'__PROCESS_CS__':FIXTURE_PROCESS_CS,'__SYSTEM_INSTALLER_CS__':SYSTEM_INSTALLER_CS}.items():
        if body.count(key)!=1:raise ValueError('tertiary-fixture-body-placeholder')
        body=body.replace(key,value,1)
    body_bytes=body.encode('utf-8')
    if not 0<len(body_bytes)<=32768:raise ValueError('tertiary-fixture-body-bound')
    body_sha=hashlib.sha256(body_bytes).hexdigest()
    pre=installed_fixture_context_script(request,retained_custodian,correlation)
    publication='Assert-ContextFiles;[Console]::Out.WriteLine($json)'
    if pre.count(publication)!=1:raise ValueError('tertiary-fixture-pre-context-publication')
    pre=pre.replace(publication,'Assert-ContextFiles;$script:preContext=$out',1)
    post=FIXTURE_BOOTSTRAP_PS
    values={'__SYSTEM_INSTALLER_CS__':SYSTEM_INSTALLER_CS,'__CORRELATION__':correlation,'__PRIVATE_ROOT__':private_root,'__BODY_SHA__':body_sha,'__BODY_LENGTH__':str(len(body_bytes)),'__BODY_GZIP__':base64.b64encode(gzip.compress(body_bytes,mtime=0)).decode(),'__POST_IMAGE_PS__':FIXTURE_IMAGE_MEMBERSHIP_PS+FIXTURE_POST_IMAGE_PS}
    for key,value in values.items():
        if post.count(key)!=1:raise ValueError('tertiary-fixture-bootstrap-placeholder:'+key)
        post=post.replace(key,value,1)
    result=pre+post
    # QGA launches Windows PowerShell with one -Command string. Refuse before guest-exec if it cannot fit.
    carrier=fixture_powershell_carrier(result)
    return carrier,body,{'correlation':correlation,'privateRoot':private_root,'bodySha256':body_sha,'bodyLength':len(body_bytes),'targetSha256':'f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc','targetSize':TARGET_SIZE,'targetProductCode':'{2D8D2946-3492-3C19-A837-87C54F9311A9}','oldProductCode':'{87F491A1-A193-3271-8AE2-C0877718FAB0}','sid':'S-1-5-21-606332539-4179368406-55829832-1000'}


def validate_fixture_provision(receipt,binding,catalogue):
    """Admit only a naturally terminal exact footprint, never public acceptance."""
    import json,re
    def need(value):
        if not value:raise ValueError('tertiary-fixture-provision-receipt')
    def integer(value,minimum=0,maximum=(1<<63)-1):return type(value)is int and minimum<=value<=maximum
    def sha(value):return type(value)is str and re.fullmatch('[a-f0-9]{64}',value)is not None
    def native(value):return type(value)is str and re.fullmatch('[0-9]+(?::[0-9]+){5}',value)is not None
    def product_rows(rows):
        need(type(rows)is list and len(rows)<256);result=set()
        for row in rows:
            need(type(row)is dict and set(row)=={'ProductCode','Sid','Context'}and type(row['ProductCode'])is str and re.fullmatch(r'\{[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}\}',row['ProductCode'])is not None and integer(row['Context'],1,4)and row['Context']in (1,2,4)and type(row['Sid'])is str)
            need(row['Sid']==''if row['Context']==4 else re.fullmatch(r'S-1-[0-9]+(?:-[0-9]+){1,15}',row['Sid'])is not None)
            identity=(row['ProductCode'],row['Context'],row['Sid']);need(identity not in result);result.add(identity)
        return result
    need(type(receipt)is dict and receipt.get('correlation')==binding['correlation']and receipt.get('root')==binding['privateRoot']and native(receipt.get('rootNativeId')))
    need(receipt.get('fixtureProvision')is True and receipt.get('installerAction')is True and receipt.get('productAcceptance')is False and receipt.get('replayAllowed')is False and receipt.get('fullInstalledImageVerified')is False)
    need(len(json.dumps(receipt,ensure_ascii=False,separators=(',',':')).encode())<=262144)
    need(receipt.get('state')in ('UNKNOWN','original-fixture-installer-terminal')and receipt.get('taskStarted')is True and receipt.get('taskName')=='VpnControlTertiaryFixture-'+binding['correlation'])
    before=product_rows(receipt.get('preCatalogue'));after=product_rows(receipt.get('postCatalogue'))
    old=(binding['oldProductCode'],2,binding['sid']);target=(binding['targetProductCode'],2,binding['sid']);need(old in before and target not in before)
    if receipt['state']=='UNKNOWN':return False
    need(receipt.get('taskState')=='Ready'and receipt.get('failure')is None)
    records={}
    for role in ('bodyStarted','installerStarted','terminal'):
        row=receipt.get(role);need(type(row)is dict and set(row)=={'value','path','nativeId','sha256','length'}and native(row['nativeId'])and sha(row['sha256'])and integer(row['length'],1,32768))
        need(row['path']==binding['privateRoot']+'\\'+{'bodyStarted':'body-started.json','installerStarted':'started.json','terminal':'terminal.json'}[role])
        value=row['value'];need(type(value)is dict and value.get('correlation')==binding['correlation']and value.get('bodySha256')==binding['bodySha256']and value.get('replayAllowed')is False and integer(value.get('bodyPid'),1)and integer(value.get('bodyBirth'),1))
        records[role]=value
    body=records['bodyStarted'];started=records['installerStarted'];terminal=records['terminal']
    need(body.get('sid')==binding['sid']and integer(body.get('session'),1,1)and body.get('limited')is True)
    for record in (started,terminal):need(record['bodyPid']==body['bodyPid']and record['bodyBirth']==body['bodyBirth']and integer(record.get('originalPid'),1)and integer(record.get('originalBirth'),1))
    need(started['originalPid']==terminal['originalPid']and started['originalBirth']==terminal['originalBirth']and integer(terminal.get('exitCode'),0,65535))
    need(terminal.get('sid')==binding['sid']and integer(terminal.get('session'),1,1)and terminal.get('packageSha256')==binding['targetSha256'])
    for key in ('stdout','stderr'):
        row=terminal.get(key);need(type(row)is dict and set(row)=={'bytes','retainedBytes','sha256'}and integer(row['bytes'])and integer(row['retainedBytes'],0,2097152)and row['retainedBytes']==min(row['bytes'],2097152)and sha(row['sha256']))
    need(integer(terminal.get('logLength'),0,16777216)and sha(terminal.get('logSha256'))and native(terminal.get('logNativeId')))
    if terminal['exitCode']!=0:return False
    need(after==(before-{old})|{target})
    selected=receipt.get('postSelected');need(type(selected)is list and len(selected)==1)
    product=selected[0];need(type(product)is dict and product.get('ProductCode')==binding['targetProductCode']and integer(product.get('Context'),2,2)and product.get('Sid')==binding['sid']and product.get('Version')=='2.2.2'and product.get('State')=='5'and product.get('InstallLocation')==r'C:\Users\parityagent\AppData\Local\vpn-control'+chr(92))
    need(type(receipt.get('postEffects'))is list and not receipt['postEffects'])
    if catalogue is None:return False  # Native component only; exact expected image is checked by the pinned local caller.
    need(catalogue.get('targetMsiSha256')==binding['targetSha256']and catalogue.get('targetMsiBytes')==binding['targetSize']and catalogue.get('fileCount')==209)
    need(catalogue.get('property',{}).get('ProductCode')==binding['targetProductCode']and catalogue.get('propertyPresence')=={'ALLUSERS':{'present':False,'value':None},'MSIINSTALLPERUSER':{'present':False,'value':None}})
    expected={row['path'].removeprefix('vpn-control/'):(row['sizeBytes'],row['sha256'])for row in catalogue['files']};need(len(expected)==209)
    image=receipt.get('postImage');need(type(image)is dict and image.get('root')==r'C:\Users\parityagent\AppData\Local\vpn-control'and image.get('fullHash')is True and image.get('nativeReadCustody')is True and image.get('launchExecuted')is False and type(image.get('files'))is list and len(image['files'])==209)
    actual={}
    for row in image['files']:
        need(type(row)is dict and set(row)=={'path','length','sha256','nativeId'}and type(row['path'])is str and row['path']in expected and row['path']not in actual and integer(row['length'],1,268435456)and sha(row['sha256'])and native(row['nativeId']))
        actual[row['path']]=(row['length'],row['sha256'])
    need(actual==expected)
    directories=image.get('directories');need(type(directories)is list and 0<len(directories)<=64)
    expected_directories={''}
    for path in expected:
        pieces=path.split('/')
        expected_directories.update('/'+'/'.join(pieces[:index])for index in range(1,len(pieces)))
    empty_directories=catalogue.get('authoredEmptyDirectories',[])
    need(type(empty_directories)is list and empty_directories in ([],['app/resources']))
    for path in empty_directories:
        pieces=path.split('/')
        expected_directories.update('/'+'/'.join(pieces[:index])for index in range(1,len(pieces)+1))
    observed_directories=set()
    for directory in directories:
        need(type(directory)is dict and set(directory)=={'path','nativeId','members'}and type(directory['path'])is str and directory['path']in expected_directories and directory['path']not in observed_directories and native(directory['nativeId'])and type(directory['members'])is list and len(directory['members'])<=512)
        observed_directories.add(directory['path'])
        prefix=directory['path'].lstrip('/')
        descendants=[p[len(prefix)+1:]if prefix else p for p in expected if (p.startswith(prefix+'/')if prefix else True)]
        expected_members={p.split('/')[0]for p in descendants}
        descendant_directories=[p.lstrip('/')[len(prefix)+1:]if prefix else p.lstrip('/')for p in expected_directories if p.lstrip('/')!=prefix and (p.lstrip('/').startswith(prefix+'/')if prefix else bool(p))]
        expected_members.update(p.split('/')[0]for p in descendant_directories)
        need(all(type(member)is str for member in directory['members'])and len(set(directory['members']))==len(directory['members'])and set(directory['members'])==expected_members)
    need(observed_directories==expected_directories)
    need(type(receipt.get('postState'))is list and len(receipt['postState'])==2 and all(type(row)is dict and set(row)=={'path','exists'}and row['exists']is False for row in receipt['postState'])and receipt['postState']==[dict(path=r'C:\Users\parityagent\.vpn-control-desktop',exists=False),dict(path=r'C:\Users\parityagent\AppData\Local\Temp\vpn-control-tertiary-scenarios',exists=False)])
    registry=receipt.get('postRegistry');need(type(registry)is dict and registry==dict(hive='HKEY_USERS',sid=binding['sid'],key=r'Software\Kardinal\vpn-control\2.2.2',name='ProductCode',value=binding['targetProductCode'],kind='String'))
    links=receipt.get('postShortcuts');need(type(links)is list and len(links)==4)
    expected_links={(folder+'\\'+name+'.lnk'):name for folder in (body['desktopFolder'],body['programsFolder']+'\\VPN Control')for name in ('vpn-control','vpn-control-cli')}
    need(len(expected_links)==4 and {row.get('path')for row in links}==set(expected_links))
    for row in links:
        need(row.get('target')==image['root']+'\\'+expected_links[row['path']]+'.exe'and row.get('arguments')==''and row.get('workingDirectory')==image['root']and integer(row.get('length'),1,65536)and sha(row.get('sha256'))and native(row.get('nativeId')))
    return True


def compact_fixture_provision(receipt,raw,binding,catalogue):
    import json
    if type(raw)is not bytes or not 0<len(raw)<=262144 or json.loads(raw.decode('utf-8-sig'))!=receipt:raise ValueError('tertiary-fixture-provision-raw')
    verified=validate_fixture_provision(receipt,binding,catalogue)
    return {'transaction':receipt,'fixtureProvisionVerified':verified,'productAcceptance':False,'replayAllowed':False}


def fixture_powershell_carrier(source):
    """Fit exactly one public authenticated source into Windows' command limit."""
    import base64,gzip,hashlib
    if type(source)is not str or not 0<len(source.encode('utf-8'))<=98304:raise ValueError('tertiary-fixture-source-bound')
    raw=source.encode('utf-8');payload=base64.b64encode(gzip.compress(raw,mtime=0)).decode();digest=hashlib.sha256(raw).hexdigest()
    command=r"""$ErrorActionPreference='Stop';Add-Type -AssemblyName System.IO.Compression
$c=[Convert]::FromBase64String('__PAYLOAD__');$i=New-Object IO.MemoryStream(,$c);$g=New-Object IO.Compression.GZipStream($i,[IO.Compression.CompressionMode]::Decompress);$o=New-Object IO.MemoryStream
try{$b=New-Object byte[] 4096;while(($n=$g.Read($b,0,$b.Length)) -gt 0){if($o.Length+$n -gt 98304){throw 'FIXTURE_SOURCE_BOUND'};$o.Write($b,0,$n)};$r=$o.ToArray()}finally{$g.Dispose();$i.Dispose();$o.Dispose()}
$h=[Security.Cryptography.SHA256]::Create();try{$s=[BitConverter]::ToString($h.ComputeHash($r)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
if($r.Length -ne __LENGTH__ -or $s -cne '__SHA__'){throw 'FIXTURE_SOURCE_BINDING'}
$utf8=New-Object Text.UTF8Encoding($false,$true);. ([ScriptBlock]::Create($utf8.GetString($r)))
"""
    command=command.replace('__PAYLOAD__',payload,1).replace('__LENGTH__',str(len(raw)),1).replace('__SHA__',digest,1)
    if len(command.encode('utf-16-le'))//2+160>=32767:raise ValueError('tertiary-fixture-windows-command-bound')
    return command


FIXTURE_IMAGE_MEMBERSHIP_PS=r"""
function Assert-FixtureImageMembership {
 foreach($directory in $directoryRows){
  $actual=@([IO.Directory]::GetFileSystemEntries($directory.fullPath))
  if($actual.Count -gt 512 -or $actual.Count -ne $directory.members.Count){throw 'FIXTURE_IMAGE_MEMBERSHIP'}
  $expected=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
  foreach($member in $directory.members){if(-not $expected.Add($member)){throw 'FIXTURE_IMAGE_MEMBERSHIP_DUPLICATE'}}
  foreach($member in $actual){if(-not $expected.Remove($member)){throw 'FIXTURE_IMAGE_MEMBERSHIP'}}
  if($expected.Count -ne 0){throw 'FIXTURE_IMAGE_MEMBERSHIP'}
 }
}
"""
