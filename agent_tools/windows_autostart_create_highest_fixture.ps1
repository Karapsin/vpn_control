# The owned legacy autostart task as the pre-migration product left it: "VPN Control", RunLevel HighestAvailable,
# an interactive token for the ordinary user. That product elevated itself at launch and ran schtasks /RL HIGHEST
# elevated; an unelevated ordinary token may not register a HighestAvailable task (native 5594b6f5, E_ACCESSDENIED).
# So the SYSTEM run plants it, in its own process, from its pinned bytes, before the ordinary owner starts and before
# any public toggle. Its one result goes to the pipeline, never to the console the SYSTEM run replies on.
param([Parameter(Mandatory=$true)][string]$GuiPath,
      [Parameter(Mandatory=$true)][string]$Workspace,
      [Parameter(Mandatory=$true)][string]$PrincipalSid)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Test-TaskAbsent($record) {
 # Only ERROR_FILE_NOT_FOUND (0x80070002) anywhere in the exception chain proves the task absent. Native Windows
 # PowerShell raises it from Task Scheduler as a bare FileNotFoundException, other hosts as a COMException or wrapped
 # in a MethodInvocationException, so no exception type is matched. Access denied and every other error is not absence.
 $x = $record.Exception
 while ($null -ne $x) { if ($x.HResult -eq -2147024894) { return $true }; $x = $x.InnerException }
 return $false
}
function Get-StartupTask($folder) {
 # Only the lookup itself may prove absence; a later read of a present task that fails is never absence.
 try { return $folder.GetTask('VPN Control') } catch { if (-not (Test-TaskAbsent $_)) { throw } }
 return $null
}
# schtasks /Create /SC ONLOGON runs the task "whenever any user logs on": its logon trigger names no user. Native
# 7ca6638a registered a trigger for the ordinary SID instead, and Task Scheduler stored that user as an account name.
# The definition is registered as this XML, so the trigger keeps the explicit Enabled the product's recognizer reads
# (DesktopAutostartManager WindowsTaskXml); the object model's Enabled=true left no element (7ca6638a).
$template = @'
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>VPN Control owned acceptance legacy run-level fixture</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{0}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{1}</Command>
      <Arguments>--autostart --state-dir "{2}"</Arguments>
    </Exec>
  </Actions>
</Task>
'@
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
 if ($identity.User.Value -cne 'S-1-5-18') { throw 'FIXTURE_SYSTEM_PLANTER' }
 if ($PrincipalSid -cnotmatch '\AS-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\z') { throw 'FIXTURE_ORDINARY_PRINCIPAL' }
 foreach ($value in @($GuiPath,$Workspace)) {
  # A local drive path only, on any host's .NET: IsPathRooted also takes \x and, off Windows, refuses C:\x.
  if ($value -cnotmatch '\A[A-Za-z]:\\' -or $value.IndexOfAny([char[]]"`r`n`0`"") -ge 0) { throw 'FIXTURE_EXACT_PATH' }
 }
 $xml = [string]::Format($template, $PrincipalSid, [Security.SecurityElement]::Escape($GuiPath),
  [Security.SecurityElement]::Escape($Workspace))
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $folder = $service.GetFolder('\')
 if ($null -ne (Get-StartupTask $folder)) { throw 'EXISTING_STARTUP_TASK_REFUSED' }
 # TASK_CREATE=2. A raced same-name task fails; never replace or update it. No SDDL: the scheduler's own default,
 # as the legacy elevated schtasks /Create left it.
 $registered = $folder.RegisterTask('VPN Control',$xml,2,$PrincipalSid,$null,3,$null)
 if ($registered.Path -cne '\VPN Control') { throw 'FIXTURE_REGISTERED_WRONG_PATH' }
 '{"schemaVersion":1,"taskPath":"\\VPN Control","runLevel":"HighestAvailable"}'
} finally { $identity.Dispose() }
