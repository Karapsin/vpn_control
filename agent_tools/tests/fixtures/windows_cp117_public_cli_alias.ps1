param([string]$BeforeFile,[string]$AfterFile)
$ErrorActionPreference='Stop'
function SelectTask([string]$file,[string]$name){
 $text=[IO.File]::ReadAllText($file);$tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'TASK_PARSE'}
 $f=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -ceq $name},$true))
 $c=@($ast.FindAll({param($a)$a -is [Management.Automation.Language.CommandAst] -and $a.GetCommandName() -ceq $name},$true))
 if($f.Count -ne 1 -or $c.Count -ne 14){throw 'TASK_GRAPH'}
 return @{function=$f[0].Extent.Text;calls=@($c|ForEach-Object{$_.Extent.Text});functionAst=$f[0];callAst=$c}
}
# Admit the preserved old name as a negative control; dispatch must still fail.
$afterName=if([IO.File]::ReadAllText($AfterFile) -cmatch '(?m)^function Invoke-Cp117PublicCli\('){'Invoke-Cp117PublicCli'}else{'Cli'}
$old=SelectTask $BeforeFile 'Cli';$new=SelectTask $AfterFile $afterName
$command=Get-Command Cli;$alias=Get-Alias cli
if($command.CommandType.ToString() -cne 'Alias' -or $command.Definition -cne 'Clear-Item' -or $alias.Definition -cne 'Clear-Item'){throw 'ALIAS_ENVIRONMENT'}
# Stops at the genuine first PublicPrincipal boundary before identity/process/I/O.
$script:reached=@()
function PublicPrincipal{
 $script:reached+=,@{name=$name;command=$command;seconds=$seconds}
 throw 'SOURCE_BINDING_REACHED'
}
. ([scriptblock]::Create($old.function))
$initial=@($old.calls|Where-Object{$_ -ceq "Cli 'initial-status' 'status'"})
if($initial.Count -ne 1){throw 'INITIAL_CALL'}
$oldFailure=$null
try{. ([scriptblock]::Create($initial[0]));throw 'OLD_UNEXPECTED_SUCCESS'}catch{$oldFailure=$_}
if($oldFailure.Exception -isnot [Management.Automation.ParameterBindingException] -or $oldFailure.FullyQualifiedErrorId -cne 'PositionalParameterNotFound,Microsoft.PowerShell.Commands.ClearItemCommand' -or $script:reached.Count -ne 0){throw 'OLD_NOT_CAUSAL'}
. ([scriptblock]::Create($new.function))
$name='poll';$id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';$entry=@('settings','settings show');$installRequest=[pscustomobject]@{value=[pscustomobject]@{operationId=$id}}
$results=@()
foreach($call in $new.calls){
 $count=$script:reached.Count;$errorValue=$null
 try{. ([scriptblock]::Create($call));throw 'NEW_UNEXPECTED_SUCCESS'}catch{$errorValue=$_}
 if($errorValue.Exception.Message -cne 'SOURCE_BINDING_REACHED' -or $script:reached.Count -ne $count+1){throw ('NEW_NOT_CAUSAL:'+ $errorValue.Exception.GetType().FullName+':'+$errorValue.FullyQualifiedErrorId)}
 $results+=,@{call=$call;binding=$script:reached[-1];refusal=$errorValue.Exception.Message}
}
if($results[1].binding.name -cne 'initial-status' -or $results[1].binding.command -cne 'status' -or $results[1].binding.seconds -ne 15){throw 'INITIAL_ARGUMENTS'}
if((Get-Command Invoke-Cp117PublicCli).CommandType.ToString() -cne 'Function'){throw 'NEW_RESOLUTION'}
if((Get-Alias cli).Definition -cne 'Clear-Item' -or (Get-Command Cli).CommandType.ToString() -cne 'Alias'){throw 'ALIAS_MUTATED'}
# AST full-byte inverse is checked by Python; here compare every actual argument AST.
for($i=0;$i -lt 14;$i++){
 $x=$old.callAst[$i].CommandElements;$y=$new.callAst[$i].CommandElements
 if($x.Count -ne $y.Count){throw 'ARGUMENT_COUNT_CHANGED'}
 for($k=1;$k -lt $x.Count;$k++){if($x[$k].Extent.Text -cne $y[$k].Extent.Text){throw 'ARGUMENT_CHANGED'}}
}
@{scope='SOURCE_ONLY';native=$false;commandResolution=@{name=$command.Name;type=$command.CommandType.ToString();definition=$command.Definition;alias=$alias.Definition};old=@{outcome='RED';type=$oldFailure.Exception.GetType().FullName;message=$oldFailure.Exception.Message;fullyQualifiedErrorId=$oldFailure.FullyQualifiedErrorId;functionReached=$false};new=@{outcome='GREEN';functionReachedCount=$script:reached.Count;guardRefusal='SOURCE_BINDING_REACHED';calls=$results};parseBefore=$true;parseAfter=$true;argumentsUnchanged=$true;aliasPreserved=$true;nativeAdmission=$false;processCreated=$false}|ConvertTo-Json -Depth 8 -Compress
