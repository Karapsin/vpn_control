param([string]$FixtureRoot)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop';$results=[Collections.Generic.List[object]]::new();$failed=0
foreach($name in @('recovery.task.ps1','bootstrap.preserve.ps1','bootstrap.preserve.consumer.ps1')){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $FixtureRoot $name),[ref]$tokens,[ref]$errors)
 $rows=@($errors|ForEach-Object {[pscustomobject]@{errorId=$_.ErrorId;line=$_.Extent.StartLineNumber;column=$_.Extent.StartColumnNumber;message=$_.Message}})
 if($rows.Count){$failed++}
 $results.Add([pscustomobject]@{name=$name;errorCount=$rows.Count;errors=$rows})
}
[pscustomobject]@{PSVersion=$PSVersionTable.PSVersion.ToString();files=$results.ToArray();failedFiles=$failed}|ConvertTo-Json -Depth 10 -Compress
if($failed){exit 1};exit 0
