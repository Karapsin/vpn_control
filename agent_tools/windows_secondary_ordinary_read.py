"""Fixed, read-only secondary actor census and native NTAccount regression.

This module emits source only. It cannot start SSH, a guest task, or an installer.
"""
from __future__ import annotations

import uuid
import base64
import hashlib

NT_ACCOUNT_GUARD = r"""
function Get-VpnParityGuardedAccount {
 param($RawName)
 if(-not ($RawName -is [string]) -or [string]::IsNullOrWhiteSpace($RawName)){
  return [ordered]@{accepted=$false;constructorCalled=$false;reason='INTERACTIVE_NAME_UNAVAILABLE'}
 }
 $account=[Security.Principal.NTAccount]::new([string]$RawName)
 return [ordered]@{accepted=$true;constructorCalled=$true;value=$account.Value}
}
"""

NT_ACCOUNT_CASES = r"""
$old=[ordered]@{failed=$false;errorId=$null}
try{$oldNull=$null;$unused=(New-Object Security.Principal.NTAccount($oldNull))}catch{$old.failed=$true;$old.errorId=$_.FullyQualifiedErrorId}
$cases=@()
foreach($item in @(@{label='null';raw=$null},@{label='empty';raw=''},@{label='number';raw=1},@{label='name';raw='vpn-control-causal-probe'})){
 $case=Get-VpnParityGuardedAccount -RawName $item.raw
 $cases+=,[ordered]@{label=$item.label;result=$case}
}
$regression=[ordered]@{oldNull=$old;guarded=$cases}
"""


def nt_account_regression_powershell() -> str:
    """Use this exact native case body in routine checks and the guest census."""
    return (
        "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);\n"
        + NT_ACCOUNT_GUARD + NT_ACCOUNT_CASES
        + "[Console]::Out.WriteLine(($regression|ConvertTo-Json -Depth 8 -Compress))\n"
    )


def validate_nt_account_regression(value: object) -> None:
    """Reject an incomplete or falsely green actual native causal result."""
    if not isinstance(value, dict):
        raise ValueError('secondary-account-regression')
    old = value.get('oldNull')
    if not isinstance(old, dict) or old.get('failed') is not True or not str(old.get('errorId', '')).startswith('CannotFindAppropriateCtor,'):
        raise ValueError('secondary-account-original-red')
    rows = value.get('guarded')
    if not isinstance(rows, list) or [row.get('label') for row in rows if isinstance(row, dict)] != ['null', 'empty', 'number', 'name']:
        raise ValueError('secondary-account-case-set')
    for row in rows[:3]:
        result = row.get('result')
        if not isinstance(result, dict) or set(result) != {'accepted', 'constructorCalled', 'reason'} or result.get('accepted') is not False or result.get('constructorCalled') is not False or result.get('reason') != 'INTERACTIVE_NAME_UNAVAILABLE':
            raise ValueError('secondary-account-missing-actor')
    result = rows[3].get('result')
    if not isinstance(result, dict) or set(result) != {'accepted', 'constructorCalled', 'value'} or result.get('accepted') is not True or result.get('constructorCalled') is not True or result.get('value') != 'vpn-control-causal-probe':
        raise ValueError('secondary-account-native-constructor')


def ordinary_actor_census_powershell(correlation: str) -> str:
    """Observe nullable current actor and all Explorer owners without side effects."""
    if not isinstance(correlation, str) or str(uuid.UUID(correlation)) != correlation:
        raise ValueError('secondary-actor-correlation')
    prefix = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$self=Get-Process -Id $PID;$birth=$self.StartTime.ToUniversalTime()
$identity=[ordered]@{state='ORIGINAL_ACTOR_CENSUS_STARTED';correlationId='@CORR@';pid=$PID;birthUtc=$birth.ToString('o');birthTicks=$birth.Ticks;sessionId=$self.SessionId;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;installerStarted=$false;productAcceptance=$false;replayAllowed=$false}
[Console]::Out.WriteLine(($identity|ConvertTo-Json -Compress))
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$name=(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
$boot=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
$explorers=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop|ForEach-Object{
 $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
 [ordered]@{pid=$_.ProcessId;sessionId=$_.SessionId;birthUtc=$_.CreationDate.ToUniversalTime().ToString('o');ownerResult=$owner.ReturnValue;ownerSid=$owner.Sid}
})
$current=[ordered]@{correlationId='@CORR@';win32UserName=$name;win32UserNameType=$(if($null -eq $name){'null'}else{$name.GetType().FullName});bootUtc=$boot;explorers=$explorers;taskObserved=$false;cliStarted=$false;runtimeOffProven=$false;installerStarted=$false;productAcceptance=$false;replayAllowed=$false}
# Publish the nullable actor facts before any account translation.
[Console]::Out.WriteLine(($current|ConvertTo-Json -Depth 8 -Compress))
""".replace('@CORR@', correlation)
    tail = r"""
$oldObserved=[ordered]@{accepted=$false;errorId=$null;value=$null}
try{$legacy=(New-Object Security.Principal.NTAccount($name));$oldObserved.accepted=$true;$oldObserved.value=$legacy.Value}catch{$oldObserved.errorId=$_.FullyQualifiedErrorId}
$observedAccount=Get-VpnParityGuardedAccount -RawName $name
$translatedSid=$null
if($observedAccount.accepted -eq $true -and $name -ceq 'VPNPARITYX64\parityagent'){$translatedSid=([Security.Principal.NTAccount]::new([string]$name)).Translate([Security.Principal.SecurityIdentifier]).Value}
[Console]::Out.WriteLine(([ordered]@{correlationId='@CORR@';regression=$regression;oldObservedAccount=$oldObserved;observedAccount=$observedAccount;observedSid=$translatedSid;actorAdmitted=$false;runtimeOffProven=$false;installerStarted=$false;productAcceptance=$false;replayAllowed=$false}|ConvertTo-Json -Depth 10 -Compress))
""".replace('@CORR@', correlation)
    # The original process identity precedes validation/parser failures. The
    # native parser still validates the entire fixed read-only body before it runs.
    boundary = prefix.index('[Console]::OutputEncoding=')
    early = prefix[:boundary]
    body = prefix[boundary:] + NT_ACCOUNT_GUARD + NT_ACCOUNT_CASES + tail
    raw = body.encode('utf-8')
    digest = hashlib.sha256(raw).hexdigest()
    early = early.replace("installerStarted=$false;productAcceptance=$false", "bodySha256='" + digest + "';sourceValidated=$false;installerStarted=$false;productAcceptance=$false")
    reader = (
        "$bytes=[Convert]::FromBase64String('" + base64.b64encode(raw).decode() + "');"
        "if($bytes.Length -ne " + str(len(raw)) + " -or "
        "[BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes)).Replace('-','').ToLowerInvariant() -cne '" + digest + "'){throw 'ACTOR_FIXED_BODY'};"
        "$body=[Text.Encoding]::UTF8.GetString($bytes);$tokens=$null;$errors=$null;"
        "[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors);"
        "if($errors.Count -ne 0){throw 'ACTOR_CENSUS_PS51_PARSE'};"
        "& ([ScriptBlock]::Create($body))\n"
    )
    return early + reader

# Fixed projection: no Message, command line, account, machine, or raw XML output.
BOOT_EVENT_PROJECTION = r"""
function Convert-VpnParityBootEvent {
 param([int]$Id,[long]$RecordId,[DateTime]$TimeCreated,[string]$Provider,[string]$Xml)
 if($Id -notin @(1074,6005,6006,6008,41) -or $RecordId -le 0){throw 'BOOT_EVENT_ID'}
 if($Provider -notmatch '^[A-Za-z0-9_. -]{1,128}$'){throw 'BOOT_EVENT_PROVIDER'}
 if($Xml.Length -gt 65536 -or $Xml -match '(?i)<!DOCTYPE|<!ENTITY'){throw 'BOOT_EVENT_XML'}
 $doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.LoadXml($Xml)
 $data=@{};$nodes=@($doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))
 if($nodes.Count -gt 64){throw 'BOOT_EVENT_DATA_BOUND'}
 foreach($node in $nodes){$key=$node.GetAttribute('Name');if($key -notin @('param1','param4','param5','ProcessName','ReasonCode','ShutdownType','BugcheckCode')){continue};if($data.ContainsKey($key)){throw 'BOOT_EVENT_DUPLICATE_DATA'};$data[$key]=$node.InnerText}
 $reason=$null;$process=$null;$kind=$null;$bugcheck=$null
 if($Id -eq 1074){
  $candidate=$(if($data.ContainsKey('ReasonCode')){$data['ReasonCode']}else{$data['param4']})
  if($candidate -match '^(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$'){$reason=$candidate}
  $candidate=$(if($data.ContainsKey('ProcessName')){$data['ProcessName']}else{$data['param1']})
  if($candidate -match '(?i)(?:^|\\)([a-z0-9_.-]{1,128}\.exe)(?:\s*\([^)]*\))?$'){$process=$Matches[1]}
  $candidate=$(if($data.ContainsKey('ShutdownType')){$data['ShutdownType']}else{$data['param5']})
  if($candidate -in @('restart','shutdown','power off')){$kind=$candidate}
 }
 if($Id -eq 41 -and $data['BugcheckCode'] -match '^[0-9]{1,20}$'){$bugcheck=$data['BugcheckCode']}
 return [ordered]@{id=$Id;recordId=$RecordId;timeUtc=$TimeCreated.ToUniversalTime().ToString('o');provider=$Provider;reasonCode=$reason;processExecutable=$process;shutdownKind=$kind;bugcheckCode=$bugcheck}
}
"""


def boot_projection_regression_powershell() -> str:
    """Run the actual projection against public hostile/unrelated XML fixtures."""
    fixture = r"""
$xml='<Event><EventData><Data Name="param1">C:\PRIVATE_PATH_SENTINEL\svchost.exe (PRIVATE_MACHINE_SENTINEL)</Data><Data Name="param2">PRIVATE_MACHINE_SENTINEL</Data><Data Name="param3">PRIVATE_REASON_SENTINEL</Data><Data Name="param4">0x80020010</Data><Data Name="param5">restart</Data><Data Name="param6">PRIVATE_USER_SENTINEL</Data><Data Name="Message">PRIVATE_MESSAGE_SENTINEL</Data></EventData></Event>'
$projected=Convert-VpnParityBootEvent -Id 1074 -RecordId 1 -TimeCreated ([DateTime]'2026-10-06T00:00:00Z') -Provider 'User32' -Xml $xml
$text=$projected|ConvertTo-Json -Compress
if($text -match 'SENTINEL' -or $projected.processExecutable -cne 'svchost.exe' -or $projected.reasonCode -cne '0x80020010' -or $projected.shutdownKind -cne 'restart'){throw 'BOOT_PROJECTION_LEAK'}
$bad=$xml.Replace('0x80020010','PRIVATE_REASON_SENTINEL').Replace('svchost.exe (PRIVATE_MACHINE_SENTINEL)','svchost.exe PRIVATE_ARGUMENT_SENTINEL')
$rejected=Convert-VpnParityBootEvent -Id 1074 -RecordId 2 -TimeCreated ([DateTime]'2026-10-06T00:00:00Z') -Provider 'User32' -Xml $bad
if($null -ne $rejected.processExecutable -or $null -ne $rejected.reasonCode){throw 'BOOT_PROJECTION_FOREIGN_FIELD'}
$refused=$false;try{$unused=Convert-VpnParityBootEvent -Id 999 -RecordId 1 -TimeCreated ([DateTime]'2026-10-06T00:00:00Z') -Provider 'User32' -Xml $xml}catch{$refused=$true}
if(-not $refused){throw 'BOOT_PROJECTION_FOREIGN_ID'}
$refused=$false;try{$unused=Convert-VpnParityBootEvent -Id 1074 -RecordId 1 -TimeCreated ([DateTime]'2026-10-06T00:00:00Z') -Provider 'User32' -Xml '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///PRIVATE_EXTERNAL_SENTINEL">]><Event/>'}catch{$refused=$true}
if(-not $refused){throw 'BOOT_PROJECTION_EXTERNAL_ENTITY'}
$unnamed='<Event><EventData><Data>PRIVATE_UNNAMED_SENTINEL</Data><Data>PRIVATE_UNNAMED_SENTINEL</Data></EventData></Event>'
$event6008=Convert-VpnParityBootEvent -Id 6008 -RecordId 3 -TimeCreated ([DateTime]'2026-10-06T00:00:00Z') -Provider 'EventLog' -Xml $unnamed
if(($event6008|ConvertTo-Json -Compress) -match 'SENTINEL' -or $null -ne $event6008.processExecutable){throw 'BOOT_PROJECTION_UNNAMED_DATA'}
[Console]::Out.WriteLine('projection-green')
"""
    return "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';\n" + BOOT_EVENT_PROJECTION + fixture


def boot_diagnosis_powershell(correlation: str) -> str:
    """Bounded latest System shutdown/start/crash facts; never changes settings."""
    if not isinstance(correlation, str) or str(uuid.UUID(correlation)) != correlation:
        raise ValueError('secondary-boot-correlation')
    body = boot_projection_regression_powershell() + r"""
$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$boot=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
$events=@();$noMatchingEvents=$false
try{$events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=@(1074,6005,6006,6008,41)} -MaxEvents 20 -ErrorAction Stop)}catch{
 if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$noMatchingEvents=$true}else{throw}
}
$rows=@($events|ForEach-Object{Convert-VpnParityBootEvent -Id $_.Id -RecordId $_.RecordId -TimeCreated $_.TimeCreated -Provider $_.ProviderName -Xml ($_.ToXml())})
[Console]::Out.WriteLine(([ordered]@{correlationId='@CORR@';lastBootUtc=$boot;logName='System';eventIds=@(1074,6005,6006,6008,41);maxEvents=20;projectionRegressionObserved=$true;events=$rows;noMatchingEvents=$noMatchingEvents;taskStarted=$false;cliStarted=$false;settingsChanged=$false;runtimeOffProven=$false;installerStarted=$false;productAcceptance=$false;replayAllowed=$false}|ConvertTo-Json -Depth 8 -Compress))
""".replace('@CORR@', correlation)
    raw = body.encode('utf-8')
    digest = hashlib.sha256(raw).hexdigest()
    return r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$self=Get-Process -Id $PID;$birth=$self.StartTime.ToUniversalTime()
[Console]::Out.WriteLine(([ordered]@{state='ORIGINAL_BOOT_DIAGNOSIS_STARTED';correlationId='@CORR@';pid=$PID;birthUtc=$birth.ToString('o');birthTicks=$birth.Ticks;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;bodySha256='@SHA@';sourceValidated=$false;productAcceptance=$false;replayAllowed=$false}|ConvertTo-Json -Compress))
$bytes=[Convert]::FromBase64String('@BODY@');if($bytes.Length -ne @SIZE@ -or [BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes)).Replace('-','').ToLowerInvariant() -cne '@SHA@'){throw 'BOOT_FIXED_BODY'}
$body=[Text.Encoding]::UTF8.GetString($bytes);$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors);if($errors.Count -ne 0){throw 'BOOT_DIAGNOSIS_PS51_PARSE'};& ([ScriptBlock]::Create($body))
""".replace('@CORR@', correlation).replace('@SHA@', digest).replace('@BODY@', base64.b64encode(raw).decode()).replace('@SIZE@', str(len(raw)))


def decode_native_source(encoded, expected_size, expected_sha256):
    """Strict one-frame gzip carrier; bounded full source identity before execution."""
    import base64,hashlib,re,zlib
    if (type(expected_size)is not int or not 0<expected_size<=131000
        or not isinstance(expected_sha256,str) or not re.fullmatch('[0-9a-f]{64}',expected_sha256)
        or not isinstance(encoded,str) or len(encoded)>65536):
        raise ValueError('SECONDARY_NATIVE_SOURCE_BOUND')
    try:
        packed=base64.b64decode(encoded,validate=True)
        if not 0<len(packed)<=49152:raise ValueError('SECONDARY_NATIVE_GZIP_BOUND')
        decoder=zlib.decompressobj(31)
        raw=decoder.decompress(packed,expected_size+1)
        if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or len(raw)!=expected_size or hashlib.sha256(raw).hexdigest()!=expected_sha256):
            raise ValueError('SECONDARY_NATIVE_SOURCE_IDENTITY')
        return raw.decode('utf-8',errors='strict')
    except (ValueError,zlib.error,UnicodeError) as error:
        raise ValueError('SECONDARY_NATIVE_SOURCE_FRAMING') from error

def compressed_native_wrapper(program):
    """Carry this fixed reviewed native source below the SSH mux command budget.

    No SSH, credential read, guest process, or source execution occurs here.
    Caller admission must close the exact generated bytes and configured argv.
    """
    import gzip,hashlib,inspect
    if not isinstance(program,str):raise ValueError('SECONDARY_NATIVE_PROGRAM_TYPE')
    raw=program.encode('utf-8',errors='strict')
    if not 0<len(raw)<=131000:raise ValueError('SECONDARY_NATIVE_PROGRAM_BOUND')
    compile(program,'reviewed secondary native source','exec')
    packed=gzip.compress(raw,compresslevel=9,mtime=0)
    encoded=base64.b64encode(packed).decode('ascii')
    digest=hashlib.sha256(raw).hexdigest()
    # Exercise the same decoder emitted below before returning any wrapper.
    if decode_native_source(encoded,len(raw),digest)!=program:
        raise ValueError('SECONDARY_NATIVE_PROGRAM_ROUNDTRIP')
    wrapper=('import sys,subprocess\n'+inspect.getsource(decode_native_source)+'\n'
             +'PROGRAM=decode_native_source('+repr(encoded)+','+str(len(raw))+','+repr(digest)+')\n'
             +"secret=sys.stdin.buffer.read(513)\nif not 1<=len(secret)<=512 or b'\\0' in secret:raise SystemExit(2)\n"
             +"if not secret.endswith(b'\\n'):secret+=b'\\n'\n"
             +"p=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',PROGRAM],stdin=subprocess.PIPE,stdout=sys.stdout.buffer,stderr=sys.stderr.buffer)\n"
             +"p.stdin.write(secret);p.stdin.close();secret=None\nraise SystemExit(p.wait())\n")
    if len(wrapper.encode('utf-8'))>49152:raise ValueError('SECONDARY_NATIVE_WRAPPER_BOUND')
    compile(wrapper,'reviewed secondary compressed wrapper','exec')
    return wrapper


def shared_frame_client(base):
    """Caller-local class: same existing journal, one finite frame sequence."""
    class SharedFrameClient(base):
        def bind(self, run, guest, identity):
            result=super().bind(run,guest,identity)
            if 'responseFrameSequence' not in run:run['responseFrameSequence']=0
            if type(run['responseFrameSequence'])is not int or not 0<=run['responseFrameSequence']<=40000:
                raise ValueError('secondary-base-frame-sequence')
            return result
        def _retain_response(self, raw, complete, reason):
            previous=self.run['responseFrameSequence']
            if type(previous)is not int or not 0<=previous<40000:raise ValueError('secondary-base-frame-sequence')
            self.frames=previous
            try:return super()._retain_response(raw,complete,reason)
            finally:self.run['responseFrameSequence']=self.frames
    return SharedFrameClient


NATIVE_ERROR_FAMILY_CONTROL = 'function Get-ExpectedNativeErrorCode([Exception]$failure,[ValidateSet(\'Win32\',\'IO\')][string]$kind) {\n $current=$failure\n for($depth=0;$depth -lt 4 -and $null -ne $current;$depth++){\n  if($kind -ceq \'Win32\' -and $current -is [ComponentModel.Win32Exception]){return [int]$current.NativeErrorCode}\n  if($kind -ceq \'IO\' -and $current -is [IO.IOException]){return [int]($current.HResult -band 65535)}\n  $current=$current.InnerException\n }\n throw \'PUBLIC_NATIVE_ERROR_TYPE\'\n}\nAdd-Type -TypeDefinition @\'\npublic static class SecondaryNativeErrorControl {\n public static void ThrowFive(){throw new System.ComponentModel.Win32Exception(5);}\n public static void ThrowThirtyTwo(){throw new System.IO.IOException("PUBLIC sharing denied", unchecked((int)0x80070020));}\n}\n\'@\n$prototype=[ComponentModel.Win32Exception]::new(5)\nif(($prototype.HResult -band 65535) -eq 5 -or (Get-ExpectedNativeErrorCode $prototype \'Win32\') -ne 5){throw \'PUBLIC_WIN32_DIRECT_CONTROL\'}\n$wrappedFive=$null;try{[SecondaryNativeErrorControl]::ThrowFive()}catch{$wrappedFive=$_.Exception}\nif($null -eq $wrappedFive -or (Get-ExpectedNativeErrorCode $wrappedFive \'Win32\') -ne 5){throw \'PUBLIC_WIN32_WRAPPED_CONTROL\'}\n$directIO=[IO.IOException]::new(\'PUBLIC sharing denied\',[int]-2147024864)\nif((Get-ExpectedNativeErrorCode $directIO \'IO\') -ne 32){throw \'PUBLIC_IO_DIRECT_CONTROL\'}\n$wrappedIO=$null;try{[SecondaryNativeErrorControl]::ThrowThirtyTwo()}catch{$wrappedIO=$_.Exception}\nif($null -eq $wrappedIO -or ($wrappedIO.HResult -band 65535) -eq 32 -or (Get-ExpectedNativeErrorCode $wrappedIO \'IO\') -ne 32){throw \'PUBLIC_IO_WRAPPED_CONTROL\'}\nif((Get-ExpectedNativeErrorCode ([ComponentModel.Win32Exception]::new(80)) \'Win32\') -eq 5 -or (Get-ExpectedNativeErrorCode ([IO.IOException]::new(\'PUBLIC wrong\',[int]-2147024816)) \'IO\') -eq 32){throw \'PUBLIC_WRONG_CODE_CONTROL\'}\nforeach($case in @(@{failure=[IO.IOException]::new(\'PUBLIC foreign\');kind=\'Win32\'},@{failure=[ComponentModel.Win32Exception]::new(32);kind=\'IO\'},@{failure=[Exception]::new(\'PUBLIC unrelated\');kind=\'IO\'})){\n $refused=$false;try{[void](Get-ExpectedNativeErrorCode $case.failure $case.kind)}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_ERROR_TYPE\'){throw};$refused=$true};if(-not $refused){throw \'PUBLIC_FOREIGN_TYPE_CONTROL\'}\n}\n$deep=$directIO;for($n=0;$n -lt 3;$n++){$deep=[Exception]::new(\'PUBLIC wrapper\',$deep)}\nif((Get-ExpectedNativeErrorCode $deep \'IO\') -ne 32){throw \'PUBLIC_ALLOWED_DEPTH_CONTROL\'}\n$deep=[Exception]::new(\'PUBLIC wrapper\',$deep);$deepRefused=$false;try{[void](Get-ExpectedNativeErrorCode $deep \'IO\')}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_ERROR_TYPE\'){throw};$deepRefused=$true};if(-not $deepRefused){throw \'PUBLIC_DEPTH_CONTROL\'}\n$nativeErrorControl=[ordered]@{oldHresultMasked=$prototype.HResult -band 65535;oldPolicyRejected=$true;nativeErrorCode=(Get-ExpectedNativeErrorCode $wrappedFive \'Win32\');actualWrappedType=$wrappedFive.GetType().FullName;wrongCodeRejected=$true;foreignTypeRefused=$true;oldWrappedIOPolicyRejected=$true;ioNativeErrorCode=(Get-ExpectedNativeErrorCode $wrappedIO \'IO\');boundedDepthRefused=$deepRefused}\n'

SYSTEM_RECORD_PUBLISHER = "# SOURCE ONLY. Fixed future publisher body; no current old-root action.\nfunction Publish-SystemRecordNew([string]$name,$value) {\n if($name -cnotin @('custodian-ready.json','custodian-unknown.json','custodian-complete.json')){throw 'SYSTEM_RECORD_ROLE'}\n if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM_RECORD_ACTOR'}\n $data=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 7 -Compress));if($data.Length -le 0 -or $data.Length -gt 16384){throw 'SYSTEM_RECORD_BOUND'}\n $security=[Security.AccessControl.FileSecurity]::new()\n $security.SetSecurityDescriptorSddlForm(('O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;'+$sid+')'))\n $path=Join-Path $root $name\n $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough,$security)\n try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}\n}\n"


def demote_closed_observation(value, error):
    """A failed closing guard cannot publish stale observed authority."""
    value['state'] = 'UNKNOWN'
    value.pop('inspection', None)
    value.pop('originalRecords', None)
    value.update({'errorType': type(error).__name__, 'errorDetail': str(error)[:256]})


def cleanup_custody_identity(value):
    """Compare native ownership facts; the native reader enforces resource floors."""
    return {key: value[key] for key in (
        'qemuPid', 'qemuStartTicks', 'parentPid', 'parentStartTicks',
        'descriptorRoles', 'protectedPeerPids',
    )}


def publish_cleanup_observation(value, publish, close, has_terminals):
    """Keep create-only journal snapshots provisional until postwrite closing.

    The original transport captures the final value only after this boundary.
    A closing failure retains actual effects and an immutable UNKNOWN record.
    Callers keep original file and parent descriptors live throughout this call.
    """
    if type(has_terminals) is not bool:
        raise ValueError('cleanup-terminal-presence-type')
    try:
        close()
    except BaseException as error:
        demote_closed_observation(value, error)
    pending = dict(value)
    pending.update(state='UNKNOWN', publicationPending=True,
                   originalTerminalCustodyClosed=False,
                   capturedRecordPinsNotClosingAuthority=True)
    publish('result.json', pending)
    try:
        close()
        value['originalTerminalCustodyClosed'] = has_terminals
        value['publicationPending'] = False
    except BaseException as error:
        demote_closed_observation(value, error)
        value['originalTerminalCustodyClosed'] = False
        value['publicationPending'] = False
        publish('result-publication-unknown.json', value)


# Full original readonly consumer, parameterized only at its bound public inputs.
READONLY_ADMISSION_CONSUMER = r"""value = {'state': 'UNKNOWN', 'phase': 'secondary-current-readonly-admission', 'correlationId': CORR, 'taskStarted': False, 'cliStarted': False, 'actorAdmitted': False, 'runtimeOffProven': False, 'installerStarted': False, 'productAcceptance': False, 'replayAllowed': False}
fd = None
terminalfd = None
terminalpin = None
journal = None
journalpin = None
terminalpath = None

def close_admission():
    after = readonly_custody()
    need(cleanup_custody_identity(after) == cleanup_custody_identity(before), 'admission-custody-closing')
    if terminalfd is not None:
        need(file_hash(terminalfd, 1048576) == terminalpin, 'admission-terminal-bytes')
    if terminalfd is not None:
        need(generation(os.fstat(terminalfd)) == terminalpin['generation'] and generation(terminalpath.lstat()) == terminalpin['generation'], 'admission-terminal-population')
    if fd is not None:
        need(parent_identity(os.fstat(fd)) == journalpin and parent_identity(journal.lstat()) == journalpin, 'admission-journal-population')
try:
    before = readonly_custody()
    journal = Path(PREPARED['template']).parent / ('secondary-current-admission-' + CORR)
    need(not os.path.lexists(journal), 'admission-journal-once')
    journal.mkdir(mode=448)
    fd = os.open(journal, os.O_DIRECTORY | os.O_NOFOLLOW)
    journalpin = parent_identity(os.fstat(fd))
    need(parent_identity(journal.lstat()) == journalpin and stat.S_IMODE(journalpin[2]) == 448 and (journalpin[3:] == [0, 0]), 'admission-journal-private')
    guest = fixed_guest('secondary')
    client = shared_frame_client(AccessClient)(str(guest.root / 'vm-r-a85c4b4f/qga.sock'), timeout_seconds=15, max_response_bytes=1048576).bind({'rootFd': fd}, guest, ROW)
    prepare.record_at(fd, 'admission-intent.json', {'correlationId': CORR, 'scriptSha256': ADMISSION_SCRIPT_SHA, 'installerStarted': False, 'publicCliStarted': False, 'replayAllowed': False})
    need(cleanup_custody_identity(readonly_custody()) == cleanup_custody_identity(before), 'admission-predispatch-custody')
    original = client._exchange('guest-exec', {'path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'arg': ADMISSION_ARGUMENTS, 'capture-output': True})
    need(type(original) is dict and set(original) == {'pid'} and (type(original['pid']) is int) and (original['pid'] > 0), 'admission-original-pid')
    prepare.record_at(fd, 'admission-started.json', original)
    value['originalGuestPid'] = original['pid']
    deadline = time.monotonic() + 90
    while True:
        terminal = client.guest_exec_status(original['pid'])
        need(type(terminal) is dict, 'admission-status-type')
        if terminal.get('exited') is True:
            break
        need(terminal.get('exited') is False and time.monotonic() < deadline, 'admission-original-deadline')
        time.sleep(0.2)
    prepare.record_at(fd, 'admission-terminal.json', terminal)
    terminalpath = journal / 'admission-terminal.json'
    terminalfd = os.open('admission-terminal.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    terminalpin = file_hash(terminalfd, 1048576)
    need(generation(terminalpath.lstat()) == terminalpin['generation'], 'admission-terminal-name')
    raw = base64.b64decode(terminal.get('out-data', ''), validate=True)
    err = base64.b64decode(terminal.get('err-data', ''), validate=True)
    value.update({'originalGuestExitCode': terminal.get('exitcode'), 'stdoutLength': len(raw), 'stdoutSha256': hashlib.sha256(raw).hexdigest(), 'guestStderrLength': len(err), 'guestStderrSha256': hashlib.sha256(err).hexdigest(), 'guestStderrPrefixBase64': base64.b64encode(err[:4096]).decode(), 'originalTerminal': {'path': str(terminalpath), 'pin': terminalpin, 'pinObservedBeforeClosing': True}, 'journalPath': str(journal)})
    need(0 < len(raw) <= 32768, 'admission-output-bound')
    lines = [json.loads(line) for line in raw.decode('utf-8-sig').splitlines() if line.startswith('{')]
    need(len(lines) >= 1, 'admission-original-identity')
    identity = lines[0]
    need(type(identity) is dict and identity.get('state') == 'ORIGINAL_ACTOR_CENSUS_STARTED' and (type(identity.get('pid')) is int) and (identity.get('pid') == original['pid']) and (type(identity.get('birthTicks')) is int) and (identity['birthTicks'] > 0) and (identity.get('correlationId') == CORR) and (identity.get('bodySha256') == ADMISSION_BODY_SHA) and (identity.get('sourceValidated') is False) and (identity.get('sid') == 'S-1-5-18'), 'admission-original-binding')
    need(type(terminal.get('exitcode')) is int and terminal.get('exitcode') == 0 and ('out-truncated' not in terminal or terminal['out-truncated'] is False) and ('err-truncated' not in terminal or terminal['err-truncated'] is False) and (len(lines) == 4), 'admission-original-terminal')
    actor, cases, processes = lines[1:]
    need(all((type(row) is dict and row.get('correlationId') == CORR for row in (actor, cases, processes))), 'admission-projection-binding')
    validate_nt_account_regression(cases['regression'])
    need((actor.get('win32UserName') is None or type(actor.get('win32UserName')) is str) and type(actor.get('bootUtc')) is str and (type(actor.get('explorers')) is list) and (len(actor['explorers']) <= 64), 'admission-actor-schema')
    need(processes.get('processCensusComplete') is True and type(processes.get('processCount')) is int and (0 < processes['processCount'] <= 8192) and (type(processes.get('effectOwners')) is list) and (len(processes['effectOwners']) <= 64), 'admission-process-schema')
    for row in processes['effectOwners']:
        need(type(row) is dict and set(row) == {'pid', 'name', 'sessionId', 'birthUtc', 'executablePath'} and (type(row['pid']) is int) and (row['pid'] > 0) and (type(row['sessionId']) is int) and (row['sessionId'] >= 0) and (type(row['name']) is str) and (len(row['name']) <= 128) and (row['birthUtc'] is None or type(row['birthUtc']) is str) and (row['executablePath'] is None or (type(row['executablePath']) is str and len(row['executablePath']) <= 4096)), 'admission-process-row')
    for row in (actor, processes):
        need(row.get('runtimeOffProven') is False and row.get('installerStarted') is False and (row.get('productAcceptance') is False) and (row.get('replayAllowed') is False), 'admission-no-authority-flags')
    close_admission()
    value.update({'state': 'CURRENT_READONLY_ADMISSION_OBSERVED', 'inspection': {'originalNativeIdentity': identity, 'actorCensus': actor, 'accountRegression': cases, 'processCensus': processes}, 'nativeCustodyObserved': True})
except BaseException as error:
    value['state'] = 'UNKNOWN'
    value['errorType'] = type(error).__name__
    if isinstance(error, ValueError) and re.fullmatch('[a-z-]{1,80}', str(error)):
        value['reason'] = str(error)
finally:
    try:
        if fd is not None:
            publish_cleanup_observation(value, lambda name, body: prepare.record_at(fd, name, body), close_admission, terminalfd is not None)
    finally:
        if terminalfd is not None:
            os.close(terminalfd)
        if fd is not None:
            os.close(fd)
    raw = json.dumps(value, sort_keys=True).encode()
    need(len(raw) <= 48000, 'admission-result-bound')
    print(raw.decode(), flush=True)
"""

def readonly_admission_consumer(correlation, script_sha256, body_sha256, arguments):
    """Emit the complete original-PID, terminal-journal and closing consumer.

    The caller separately authenticates the native custody/SDK prefix. This
    factory cannot renew a route or dispatch a process on its own.
    """
    import re
    if type(correlation) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", correlation):
        raise ValueError('admission-correlation')
    if any(type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value) for value in (script_sha256, body_sha256)):
        raise ValueError('admission-source-digest')
    if type(arguments) is not list or not arguments or any(type(value) is not str for value in arguments):
        raise ValueError('admission-arguments')
    header = ('CORR=' + repr(correlation) + '\nADMISSION_SCRIPT_SHA=' + repr(script_sha256)
              + '\nADMISSION_BODY_SHA=' + repr(body_sha256)
              + '\nADMISSION_ARGUMENTS=' + repr(arguments) + '\n')
    return header + READONLY_ADMISSION_CONSUMER
