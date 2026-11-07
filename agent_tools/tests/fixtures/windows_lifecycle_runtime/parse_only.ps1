param([Parameter(Mandatory=$true)][string]$SourcePath)
$ErrorActionPreference='Stop'
$tokens=$null
$errors=$null
$null=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if(@($errors).Count -ne 0){$errors|ForEach-Object {[Console]::Error.WriteLine($_.Message)};exit 1}
[Console]::WriteLine('{"parsed":true,"executedTarget":false}')
