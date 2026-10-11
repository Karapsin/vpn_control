param([ValidateSet('before','corrected','after')][string]$Stage,[string]$WorkRoot)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$taskPath=if($Stage -ceq 'corrected'){Join-Path $PSScriptRoot 'before-corrected-one-root.task.ps1'}else{Join-Path $PSScriptRoot ($Stage+'/recovery.task.ps1')}
$bootstrapRole=if($Stage -ceq 'after'){'after'}else{'before'};$bootstrapPath=Join-Path $PSScriptRoot ($bootstrapRole+'/bootstrap.preserve.ps1')
function Parse-Owned([string]$path){$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'SOURCE_PARSE'};return $ast}
function Read-Root($ast){$rows=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [Management.Automation.Language.VariableExpressionAst] -and $n.Left.VariablePath.UserPath -ceq 'root'},$true));if($rows.Count -ne 1){throw 'ROOT_ASSIGNMENT_COUNT'};$values=@($rows[0].Right.FindAll({param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst]},$true));if($values.Count -ne 1 -or $rows[0].Right.Extent.Text -cne ("'"+$values[0].Value+"'")){throw 'ROOT_NOT_LITERAL'};return $values[0].Value}
$taskAst=Parse-Owned $taskPath;$bootAst=Parse-Owned $bootstrapPath
$taskRoot=Read-Root $taskAst;$bootstrapRoot=Read-Root $bootAst
$prefix='C:\Users\parityagent\AppData\Local\VpnControl'
function Map-Root([string]$value){if(-not $value.StartsWith($prefix+'\',[StringComparison]::Ordinal)){throw 'ROOT_PREFIX'};$mapped=$WorkRoot;foreach($part in $value.Substring($prefix.Length+1).Split('\')){if(-not $part -or $part -eq '..' -or $part.Contains('/')){throw 'ROOT_SEGMENT'};$mapped=Join-Path $mapped $part};return $mapped}
$durable=@($taskAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Durable'},$true));if($durable.Count -ne 1){throw 'DURABLE_COUNT'}
. ([scriptblock]::Create($durable[0].Extent.Text))
$write=@($taskAst.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Durable' -and $n.Extent.StartLineNumber -eq 68 -and $n.Extent.Text.Contains("(`$name+'.json')")},$true));if($write.Count -ne 1){throw 'QUERY_STATUS_WRITE_COUNT'}
$lines=[IO.File]::ReadAllLines($bootstrapPath)
$root=Map-Root $bootstrapRoot
# Only the exact authentic staging directory/source/payload boundaries execute.
. ([scriptblock]::Create($lines[51]+"`n"+$lines[55]))
$body=[IO.File]::ReadAllBytes($taskPath);$digest=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($digest.ComputeHash($body))).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose()}
$PayloadFiles=@([pscustomobject]@{name='recovery.task.ps1';base64=[Convert]::ToBase64String($body);bytes=$body.Length;sha256=$hash})
. ([scriptblock]::Create($lines[56]))
$stagedRoot=$root;$stagedTask=Join-Path $stagedRoot 'recovery.task.ps1'
$root=Map-Root $taskRoot;$name='status';$raw='{"fixtureOnly":true}'
$written=$false;$errorTypes=[Collections.Generic.List[string]]::new()
try{. ([scriptblock]::Create($write[0].Extent.Text));$written=$true}catch{$e=$_.Exception;while($e){$errorTypes.Add($e.GetType().FullName);$e=$e.InnerException}}
$declaredStatus=Join-Path $stagedRoot 'status.json';$actualStatus=Join-Path $root 'status.json'
$pass=$written -and [IO.File]::Exists($declaredStatus) -and [IO.File]::ReadAllText($declaredStatus) -ceq $raw -and $root -ceq $stagedRoot -and [IO.File]::ReadAllBytes($stagedTask).Length -eq $body.Length
[pscustomobject]@{stage=$Stage;PSVersion=$PSVersionTable.PSVersion.ToString();taskRootLiteral=$taskRoot;bootstrapRootLiteral=$bootstrapRoot;mappedTaskRoot=$root;mappedStagedRoot=$stagedRoot;stagedTaskExists=[IO.File]::Exists($stagedTask);statusWriteSucceeded=$written;declaredStatusExists=[IO.File]::Exists($declaredStatus);actualStatusExists=[IO.File]::Exists($actualStatus);errorTypes=$errorTypes.ToArray();pass=$pass;productCLIInvocations=0;nativeGuestEffects=0;scope='actual Durable and selected staging/write source on mapped own TempFS only'}|ConvertTo-Json -Depth 8 -Compress
if(-not $pass){exit 1};exit 0
