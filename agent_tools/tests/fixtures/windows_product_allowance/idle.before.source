"""Read-only Windows work census; missing visibility is never idle proof."""
import re
import sys
from uuid import UUID

from . import readiness_windows_guest as guest
from . import readiness_windows_leases as leases
from . import readiness_windows_processes as processes
from . import readiness_windows_jobs as jobs
from . import readiness_windows_preexec as preexec

_EXECUTING_CODE=sys._getframe().f_code


def powershell_source(machine,boot,user,sid,root_generation,job_root_generation=None,job_admission_generation=None,*,preexec_rejections=()):
    if type(machine)is not str or str(UUID(machine))!=machine:
        raise ValueError('windows_idle_machine')
    # Reuse the strict fixed identity validators; no command or source input.
    leases.idle_source(machine,'2000-01-01T00:00:00.0000000Z'if boot is None else boot,root_generation)
    jobs.inventory_source(machine,'2000-01-01T00:00:00.0000000Z'if boot is None else boot,
                          job_root_generation,job_admission_generation)
    if type(sid)is not str or re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',sid)is None:
        raise ValueError('windows_idle_account')
    if type(preexec_rejections)is not tuple:raise ValueError('windows_idle_preexec_invalid')
    extra='';preexec_config=None
    if preexec_rejections:
        known_boot=preexec_rejections[0].guard()['boot']if boot is None else boot
        extra,preexec_config=preexec.inventory_component(machine,known_boot,job_root_generation,job_admission_generation,rejections=preexec_rejections)
    session=guest.powershell_source(user)
    marker='[Console]::WriteLine(($result|ConvertTo-Json -Depth 6 -Compress))'
    if session.count(marker)!=1:raise ValueError('windows_idle_source')
    # NativeLease's fixed prefix already contains the complete WTS definition.
    observation=guest.OBSERVE.replace(marker,'$sessionFacts=$result')
    prefix=leases._prefix()+processes.powershell_source()+jobs._prefix()+extra+"$ExpectedUser="+repr(user)+'\n'+observation
    generation='$null'if root_generation is None else repr(root_generation)
    source=prefix+"$leaseConfig=@{machine="+repr(machine)+";boot=$sessionFacts.boot;rootGeneration="+generation+"}|ConvertTo-Json -Compress\n"
    source+="$leaseFacts=([NativeLease]::Inventory($leaseConfig)|ConvertFrom-Json)\n"
    job_generation='$null'if job_root_generation is None else repr(job_root_generation)
    job_admission='$null'if job_admission_generation is None else repr(job_admission_generation)
    source+="$jobConfig=@{machine="+repr(machine)+";boot=$sessionFacts.boot;rootGeneration="+job_generation+";admissionGeneration="+job_admission+"}|ConvertTo-Json -Compress\n"
    if preexec_config is None:
        source+="$jobFacts=([NativeJob]::Inventory($jobConfig)|ConvertFrom-Json)\n"
    else:
        source+="$preexecConfig=("+jobs._literal(preexec_config)+"|ConvertFrom-Json);$preexecConfig.boot=$sessionFacts.boot\n"
        source+="$jobFacts=([NativePreexecInventory]::Run([NativeJob],($preexecConfig|ConvertTo-Json -Depth 12 -Compress))|ConvertFrom-Json)\n"
    source+="$Machine="+repr(machine)+";$Boot="+('$sessionFacts.boot'if boot is None else repr(boot))+";$Account="+repr(sid)+'\n'+_OBSERVE
    return source


def validate(value,machine,boot,user,sid,root_generation,job_root_generation=None,job_admission_generation=None,*,preexec_rejections=()):
    fields={'schemaVersion','sessionFacts','leaseFacts','jobFacts','processes','lifecycle','blockers','visibilityComplete'}
    if type(value)is not dict or set(value)!=fields or type(value['schemaVersion'])is not int or value['schemaVersion']!=1:
        raise ValueError('windows_idle_fields')
    current=guest.validate_session(value['sessionFacts'],sid,user,machine)
    if current['boot']!=boot:raise ValueError('windows_idle_epoch')
    leases.validate_idle(value['leaseFacts'],machine,boot,root_generation)
    if preexec_rejections:
        preexec.validate_inventory(value['jobFacts'],machine,boot,job_root_generation,job_admission_generation,rejections=preexec_rejections)
    else:jobs.validate_inventory(value['jobFacts'],machine,boot,job_root_generation,job_admission_generation)
    if type(value['visibilityComplete'])is not bool or type(value['processes'])is not list or len(value['processes'])>1024:
        raise ValueError('windows_idle_visibility')
    for row in value['processes']:
        if (type(row)is not dict or set(row)!={'pid','name','session','knownSystem','self'}
                or type(row['pid'])is not int or not 0<=row['pid']<2**32
                or type(row['name'])is not str or re.fullmatch('[A-Za-z0-9_. -]{1,128}',row['name'])is None
                or type(row['session'])is not int or not 0<=row['session']<2**32
                or type(row['knownSystem'])is not bool or type(row['self'])is not bool):
            raise ValueError('windows_idle_process')
    if type(value['lifecycle'])is not dict or set(value['lifecycle'])!={'setupComplete','fixtureTaskDisabled','installerAbsent'} or any(type(v)is not bool for v in value['lifecycle'].values()):
        raise ValueError('windows_idle_lifecycle')
    if type(value['blockers'])is not list or len(value['blockers'])>1030 or any(type(v)is not str or v not in {'operators','protected_processes','installers','lifecycle_phases','running_jobs','unknown_jobs'}for v in value['blockers']):
        raise ValueError('windows_idle_blockers')
    blockers=set(value['blockers'])
    if current['competingSessions']:blockers.add('operators')
    if value['leaseFacts']['blockers']:blockers.update({'running_jobs','unknown_jobs'})
    if value['jobFacts']['blockers']:blockers.update({'running_jobs','unknown_jobs'})
    if not value['leaseFacts']['visibilityComplete'] or not value['jobFacts']['visibilityComplete'] or not value['visibilityComplete']:blockers.add('unknown_jobs')
    if not all(value['lifecycle'].values()):blockers.add('lifecycle_phases')
    for row in value['processes']:
        if not row['self']and not row['knownSystem']:blockers.add('unknown_jobs')
    return {'session':current,'blockers':frozenset(blockers),'visibilityComplete':value['visibilityComplete']and value['leaseFacts']['visibilityComplete']and value['jobFacts']['visibilityComplete']}


_OBSERVE=r'''
if($sessionFacts.machine.ToLowerInvariant() -ne $Machine -or $sessionFacts.boot -ne $Boot -or $sessionFacts.expectedSid -ne $Account -or -not $sessionFacts.ordinary){throw 'IDLE_IDENTITY_CHANGED'}
$blockers=[Collections.Generic.List[string]]::new()
$processes=@(Get-CimInstance Win32_Process)
if($processes.Count -gt 1024){throw 'IDLE_PROCESS_BOUND'}
$RecoveryRoleProcessMap=@{}
foreach($process in $processes){
 $processId=[UInt32]$process.ProcessId
 if($RecoveryRoleProcessMap.ContainsKey($processId)){throw 'IDLE_PROCESS_IDENTITY'}
 $RecoveryRoleProcessMap[$processId]=$process
}
$baseline=@('System Idle Process','System','Registry','smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe','lsm.exe','svchost.exe','fontdrvhost.exe','dwm.exe','winlogon.exe','LogonUI.exe','sihost.exe','taskhostw.exe','ctfmon.exe','explorer.exe','RuntimeBroker.exe','SearchHost.exe','SearchIndexer.exe','SearchProtocolHost.exe','SearchFilterHost.exe','StartMenuExperienceHost.exe','ShellExperienceHost.exe','ShellHost.exe','TextInputHost.exe','dllhost.exe','conhost.exe','spoolsv.exe','WmiPrvSE.exe','audiodg.exe','SecurityHealthService.exe','SecurityHealthSystray.exe','SgrmBroker.exe','sppsvc.exe','wlanext.exe','WUDFHost.exe','dasHost.exe','msdtc.exe','unsecapp.exe','VSSVC.exe','VSSVC.exe','AggregatorHost.exe','CompatTelRunner.exe','MoUsoCoreWorker.exe','NisSrv.exe','MsMpEng.exe','MpDefenderCoreService.exe','MpCopyAccelerator.exe','vmcompute.exe','vmwp.exe','SystemSettingsBroker.exe','backgroundTaskHost.exe','UserOOBEBroker.exe','tasklist.exe')
$rows=@(foreach($p in $processes){
 $self=([UInt32]$p.ProcessId -eq [UInt32]$PID)
 $name=[string]$p.Name
 $native=[RecoveryProcessIdentity]::Read([UInt32]$p.ProcessId)
 $creation=if($null -eq $p.CreationDate){''}else{$p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}
 $identity=[RecoveryProcessIdentity]::Image($native,$name,$creation)
 $path=if($identity){[string]$native.image}else{''}
 $systemPath=($path.StartsWith(($env:SystemRoot+'\'),[StringComparison]::OrdinalIgnoreCase))
 $defender=($path.StartsWith(($env:ProgramData+'\Microsoft\Windows Defender\Platform\'),[StringComparison]::OrdinalIgnoreCase))
 $known=($identity -and $baseline -contains $name -and ($systemPath -or $defender))
 if([RecoveryProcessIdentity]::Kernel($native,$name,[UInt32]$p.ParentProcessId,[UInt32]$p.SessionId,$creation)){$known=$true}
 if($identity -and $name -eq 'qemu-ga.exe' -and $path -eq ($env:ProgramFiles+'\qemu-ga\qemu-ga.exe')){$known=$true}
 if($identity -and -not $known -and -not $self){$known=[bool](Test-RecoveryExtraRole $p $native $Account ([UInt32]$sessionFacts.console))}
 if($name -match '^(sing-box|vpn.?control|wireguard|openvpn|tailscale)(\.exe)?$'){$blockers.Add('protected_processes')}
 if($name -match '^(msiexec|setup|setuphost|setupprep|TrustedInstaller|TiWorker|wuauclt|MpSigStub)\.exe$'){$blockers.Add('installers')}
 if(-not $self -and $name -match '^(powershell|pwsh|cmd|wscript|cscript|csc|vbc|python|python3)\.exe$'){$blockers.Add('running_jobs')}
 if(-not $self -and -not $known){$blockers.Add('unknown_jobs')}
 [ordered]@{pid=[UInt32]$p.ProcessId;name=$name;session=[UInt32]$p.SessionId;knownSystem=[bool]$known;self=[bool]$self}
})
$setup=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
$task=Get-ScheduledTask -TaskName 'VpnControlFixtureInitialize'
$installer=(Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress')
$lifecycle=[ordered]@{setupComplete=($setup.SystemSetupInProgress -eq 0 -and $setup.OOBEInProgress -eq 0);fixtureTaskDisabled=($task.State -eq 'Disabled');installerAbsent=(-not $installer)}
if(-not $lifecycle.setupComplete -or -not $lifecycle.fixtureTaskDisabled -or -not $lifecycle.installerAbsent){$blockers.Add('lifecycle_phases')}
$result=[ordered]@{schemaVersion=1;sessionFacts=$sessionFacts;leaseFacts=$leaseFacts;jobFacts=$jobFacts;processes=$rows;lifecycle=$lifecycle;blockers=@($blockers|Select-Object -Unique);visibilityComplete=$true}
[Console]::WriteLine(($result|ConvertTo-Json -Depth 10 -Compress))
'''
