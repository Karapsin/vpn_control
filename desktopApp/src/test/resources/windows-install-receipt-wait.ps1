$ErrorActionPreference='Stop'
$gzip=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('__CAPTURED_WORKER_GZIP__')),[IO.Compression.CompressionMode]::Decompress)
$reader=[IO.StreamReader]::new($gzip,[Text.UTF8Encoding]::new($false,$true))
try{$source=$reader.ReadToEnd()}finally{$reader.Dispose()}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Invalid worker syntax'}
$loops=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.WhileStatementAst] -and $node.Extent.Text.Contains('$lastSequence')},$true))
if($loops.Count -ne 1){throw 'Missing original-worker receipt wait'}
$loop=[ScriptBlock]::Create($loops[0].Extent.Text)
# Only receipt visibility and time are controlled. The actual original-worker
# wait must distinguish initial CREATE_NEW publication from loss or corruption.
function Test-Path {param([string]$LiteralPath) return $true}
function Start-Sleep {param([int]$Milliseconds)}
function Read-ProtectedReceipt {
 param([string]$Job,[string]$JobId)
 $script:reads++
 switch($script:scenario){
  'initial-missing' {if($script:reads -eq 1){throw [ComponentModel.Win32Exception]::new(2)};return @{sequence=3L;phase='INSTALLING'}}
  'corrupt-first' {throw [IO.InvalidDataException]::new('corrupt receipt')}
  'missing-after-first' {if($script:reads -eq 1){return @{sequence=0L;phase='PREPARING'}};throw [ComponentModel.Win32Exception]::new(2)}
  'regressed-sequence' {if($script:reads -eq 1){return @{sequence=1L;phase='AUTHORIZED'}};return @{sequence=0L;phase='PREPARING'}}
  default {throw 'Unknown scenario'}
 }
}
$job='C:\unused-fixture';$JobId='00000000-0000-0000-0000-000000000001'
foreach($scenario in @('initial-missing','corrupt-first','missing-after-first','regressed-sequence')){
 $script:scenario=$scenario;$script:reads=0;$lastSequence=-1L;$receipt=$null
 $deadline=[DateTime]::UtcNow.AddSeconds(1)
 $failure=$null
 try{. $loop}catch{$failure=$_}
 if($scenario -ceq 'initial-missing'){
  if($failure){throw $failure}
  if($script:reads -ne 2 -or $receipt['phase'] -cne 'INSTALLING'){throw 'First atomic receipt was not observed'}
 }else{
  if(-not $failure){throw ('Unsafe receipt state accepted: '+$scenario)}
  $expected=if($scenario -ceq 'corrupt-first'){1}else{2}
  if($script:reads -ne $expected){throw ('Unsafe receipt failure was retried: '+$scenario)}
 }
}
Write-Output 'FIXED_RECEIPT_WAIT_OK'
