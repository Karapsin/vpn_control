param([Parameter(Mandatory=$true)][string]$RequestFile)
$ErrorActionPreference='Stop'
$data=Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$env:ProgramData=$data.root
$global:complete=$false
$global:msiCalls=0
$global:taskCalls=0
$global:sleeps=0
$global:LASTEXITCODE=0
# Only OS/installer/task boundaries are replaced. The preserved and corrected
# complete programmes execute unchanged in actual Windows PowerShell 5.1.
function Start-Transcript {param($Path,[switch]$NoClobber)}
function Stop-Transcript {}
function Get-Volume {[pscustomobject]@{DriveLetter=$env:SystemDrive.Substring(0,1)}}
function Test-Path {
 param($LiteralPath)
 if($LiteralPath -match '(guest-agent.*qemu-ga|vioserial)'){return $true}
 Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
}
function pnputil.exe {$global:LASTEXITCODE=0}
function icacls.exe {$global:LASTEXITCODE=0}
function Copy-Item {param($LiteralPath,$Destination) [IO.File]::WriteAllText($Destination,'PUBLIC_STAGED_SOURCE')}
function Get-FileHash {param($LiteralPath) [pscustomobject]@{Hash=('A'*64)}}
function New-ScheduledTaskAction {param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Argument=$Argument}}
function New-ScheduledTaskTrigger {param([switch]$AtStartup,[switch]$AtLogOn) [pscustomobject]@{Startup=[bool]$AtStartup}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) [pscustomobject]@{User=$UserId}}
function New-ScheduledTaskSettingsSet {param($MultipleInstances,$ExecutionTimeLimit) [pscustomobject]@{Instances=$MultipleInstances}}
function Register-ScheduledTask {
 param($TaskName,$Action,$Trigger,$Principal,$Settings)
 $global:taskCalls++
 if($Principal.User -ne 'S-1-5-18'){throw 'WRONG_TASK_PRINCIPAL'}
}
function Get-ItemProperty {
 param($LiteralPath)
 if($LiteralPath -eq 'HKLM:\SYSTEM\Setup'){
  return [pscustomobject]@{SystemSetupInProgress=[int](-not $global:complete);OOBEInProgress=[int](-not $global:complete)}
 }
 if($LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'){
  return [pscustomobject]@{ImageState=$(if($global:complete){'IMAGE_STATE_COMPLETE'}else{'IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE'})}
 }
 throw 'UNEXPECTED_REGISTRY_READ'
}
function Start-Sleep {param($Seconds) $global:sleeps++;$global:complete=$true}
function Start-Process {
 param($FilePath,$ArgumentList,[switch]$PassThru,[switch]$Wait)
 $global:msiCalls++
 [IO.File]::AppendAllText((Join-Path $data.root 'installer-calls.txt'),'called;')
 if(-not $global:complete){throw 'MSI_BEFORE_SETUP_COMPLETE'}
 $process=[pscustomobject]@{ExitCode=0;Unknown=($data.mode -eq 'fixedUnknown')}
 $process | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($Milliseconds) -not $this.Unknown}
 return $process
}
function Set-Service {param($Name,$StartupType)}
function Start-Service {param($Name)}
try {
 if($data.mode -eq 'beforeEarly') { & $data.before }
 else {
  if($data.mode -ne 'retry') { & $data.initialize }
  if($data.mode -in @('fixedReady','fixedUnknown','retry')) {
   & $data.install
   if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
  }
 }
 $outcome='completed'
} catch {
 $outcome=$_.Exception.Message
}
@{outcome=$outcome;msiCalls=$global:msiCalls;taskCalls=$global:taskCalls;sleeps=$global:sleeps;complete=$global:complete} | ConvertTo-Json -Compress
