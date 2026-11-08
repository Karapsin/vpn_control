param([Parameter(Mandatory=$true)][string]$GuiPath,
      [Parameter(Mandatory=$true)][string]$Workspace,
      [Parameter(Mandatory=$true)][string]$ExpectedSid)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Runs the product's own registered autostart task once, exactly as its logon trigger
# would start it. It registers, changes and deletes nothing, and never runs elevated.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
 if ($identity.User.Value -cne $ExpectedSid) { throw 'START_ORDINARY_SID' }
 $service = New-Object -ComObject 'Schedule.Service'
 $service.Connect()
 $task = $service.GetFolder('\').GetTask('VPN Control')
 $definition = $task.Definition
 if ($definition.Actions.Count -ne 1 -or $definition.Triggers.Count -ne 1) { throw 'START_TASK_SHAPE' }
 $action = $definition.Actions.Item(1)
 if ($action.Type -ne 0 -or $action.Path -ine $GuiPath -or $action.Arguments -cne ('--autostart --state-dir "' + $Workspace + '"')) { throw 'START_TASK_ACTION' }
 if ($definition.Principal.LogonType -ne 3 -or $definition.Principal.RunLevel -ne 0 -or -not $task.Enabled) { throw 'START_TASK_PRINCIPAL' }
 if (@($task.GetInstances(0)).Count -ne 0) { throw 'START_TASK_ALREADY_RUNNING' }
 $running = $task.Run($null)
 [Console]::WriteLine((@{schemaVersion=1; taskPath=[string]$task.Path; instanceGuid=[string]$running.InstanceGuid} | ConvertTo-Json -Compress))
} finally { $identity.Dispose() }
