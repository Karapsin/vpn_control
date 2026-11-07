param([Parameter(Mandatory=$true)][string]$Value)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Start-Sleep -Milliseconds 500
[Console]::Out.Write('stdout|'+$Value)
[Console]::Error.Write('stderr|'+$Value)
exit 7
