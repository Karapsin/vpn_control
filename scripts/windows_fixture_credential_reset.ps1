param(
    [Parameter(Mandatory=$true)][string]$AccountName,
    [Parameter(Mandatory=$true)][string]$ExpectedSid,
    [Parameter(Mandatory=$true)][string]$TaskName,
    [Parameter(Mandatory=$true)][string]$TaskPath,
    [Parameter(Mandatory=$true)][string]$ExpectedTaskState,
    [Parameter(Mandatory=$true)][UInt32]$ExpectedLastResult,
    [Parameter(Mandatory=$true)][string]$ExpectedTaskExecute,
    [Parameter(Mandatory=$true)][string]$ExpectedTaskPrincipal,
    [Parameter(Mandatory=$true)][string]$ExpectedTaskArgumentsSha256,
    [Parameter(Mandatory=$true)][string]$CorrelationId
)
# Fixed task-account repair. The private inventory supplies identity; stdin supplies the password.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$operation = 'windows-fixture-password-reset-v1'
$secret = New-Object Security.SecureString
$bytes = New-Object byte[] 512
$chars = $null
$attempted = $false
$stage = 'caller'
function Emit([bool]$success, [string]$category) {
    [ordered]@{operation=$operation;correlationId=$CorrelationId;success=$success;category=$category;stage=$stage;accountSid=$ExpectedSid} | ConvertTo-Json -Compress
}
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18') { throw 'caller' }
    $stage = 'account'
    $account = Get-LocalUser -Name $AccountName
    if ($null -eq $account -or $account.SID.Value -cne $ExpectedSid -or !$account.Enabled) { throw 'account' }
    $stage = 'task-state'
    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath
    if ([string]$task.State -cne $ExpectedTaskState -or $taskInfo.LastTaskResult -ne $ExpectedLastResult) { throw 'task' }
    $stage = 'task-owner'
    if ($task.Principal.UserId -cne $ExpectedTaskPrincipal -or @($task.Actions).Count -ne 1) { throw 'task-owner' }
    $action = @($task.Actions)[0]
    $stage = 'task-action'
    if ($action.Execute -cne $ExpectedTaskExecute) { throw 'task-action' }
    $stage = 'task-arguments'
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $actualArgumentsSha256 = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($action.Arguments)))).Replace('-','').ToLowerInvariant()
    } finally { $sha.Dispose() }
    if ($actualArgumentsSha256 -cne $ExpectedTaskArgumentsSha256) { throw 'task-arguments' }
    $stage = 'installer'
    if (@(Get-CimInstance Win32_Process -Filter "Name = 'msiexec.exe'").Count -ne 0) { throw 'installer' }
    $stage = 'session'
    if ($null -ne (Get-CimInstance Win32_ComputerSystem).UserName) { throw 'session' }
    $stage = 'input'
    $stream = [Console]::OpenStandardInput()
    $count = 0
    while ($count -lt 512) {
        $n = $stream.Read($bytes, $count, 512 - $count)
        if ($n -le 0) { break }
        $count += $n
    }
    if ($count -lt 1 -or $stream.ReadByte() -ne -1) { throw 'input' }
    for ($i = 0; $i -lt $count; $i++) {
        if ($bytes[$i] -eq 0 -or $bytes[$i] -eq 10 -or $bytes[$i] -eq 13) { throw 'input' }
    }
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $chars = $utf8.GetChars($bytes, 0, $count)
    foreach ($character in $chars) { $secret.AppendChar($character) }
    $secret.MakeReadOnly()
    $stage = 'mutation'
    $attempted = $true
    Set-LocalUser -Name $AccountName -Password $secret
    $after = Get-LocalUser -Name $AccountName
    if ($after.SID.Value -cne $ExpectedSid -or !$after.Enabled) { throw 'postcondition' }
    $stage = 'complete'
    Emit $true 'none'
} catch {
    if ($attempted) { Emit $false 'unknown' } else { Emit $false 'admission-rejected' }
} finally {
    if ($null -ne $chars) { [Array]::Clear($chars, 0, $chars.Length) }
    [Array]::Clear($bytes, 0, $bytes.Length)
    $secret.Dispose()
}
