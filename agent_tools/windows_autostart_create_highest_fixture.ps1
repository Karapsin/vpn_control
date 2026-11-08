param([Parameter(Mandatory=$true)][string]$GuiPath,
      [Parameter(Mandatory=$true)][string]$Workspace,
      [Parameter(Mandatory=$true)][string]$ExpectedSid)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
 if ($identity.User.Value -cne $ExpectedSid) { throw 'FIXTURE_ORDINARY_SID' }
 foreach ($value in @($GuiPath,$Workspace)) {
  if (-not [IO.Path]::IsPathRooted($value) -or $value.StartsWith('\\') -or $value.IndexOfAny([char[]]"`r`n`0`"") -ge 0) { throw 'FIXTURE_EXACT_PATH' }
 }
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $folder = $service.GetFolder('\')
 try { $existing=$folder.GetTask('VPN Control'); throw 'EXISTING_STARTUP_TASK_REFUSED' }
 catch [System.Runtime.InteropServices.COMException] { if ($_.Exception.HResult -ne -2147024894) { throw } }
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
