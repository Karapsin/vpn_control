param([Parameter(Mandatory=$true)][string]$GuiPath,
      [Parameter(Mandatory=$true)][string]$Workspace,
      [Parameter(Mandatory=$true)][string]$ExpectedSid)
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
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
 if ($identity.User.Value -cne $ExpectedSid) { throw 'FIXTURE_ORDINARY_SID' }
 foreach ($value in @($GuiPath,$Workspace)) {
  if (-not [IO.Path]::IsPathRooted($value) -or $value.StartsWith('\\') -or $value.IndexOfAny([char[]]"`r`n`0`"") -ge 0) { throw 'FIXTURE_EXACT_PATH' }
 }
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $folder = $service.GetFolder('\')
 if ($null -ne (Get-StartupTask $folder)) { throw 'EXISTING_STARTUP_TASK_REFUSED' }
 $task = $service.NewTask(0)
 $task.RegistrationInfo.Description = 'VPN Control owned acceptance legacy run-level fixture'
 $task.Principal.Id = 'Author'
 $task.Principal.UserId = $ExpectedSid
 $task.Principal.LogonType = 3
 $task.Principal.RunLevel = 1
 $task.Settings.Enabled = $true
 $task.Settings.DisallowStartIfOnBatteries = $false
 $task.Settings.StopIfGoingOnBatteries = $false
 $task.Settings.ExecutionTimeLimit = 'PT0S'
 $trigger = $task.Triggers.Create(9)
 $trigger.Enabled = $true
 $trigger.UserId = $ExpectedSid
 $task.Actions.Context = 'Author'
 $action = $task.Actions.Create(0)
 $action.Path = $GuiPath
 $action.Arguments = '--autostart --state-dir "' + $Workspace + '"'
 # TASK_CREATE=2. A raced same-name task fails; never replace or update it.
 $registered = $folder.RegisterTaskDefinition('VPN Control',$task,2,$ExpectedSid,$null,3,$null)
 if ($registered.Path -cne '\VPN Control') { throw 'FIXTURE_REGISTERED_WRONG_PATH' }
 [Console]::WriteLine('{"schemaVersion":1,"taskPath":"\\VPN Control","runLevel":"HighestAvailable"}')
} finally { $identity.Dispose() }
