function Run-Case($name,$caseRoot) {
 if(-not (Test-Path -LiteralPath $caseRoot)){New-Item -ItemType Directory -Path $caseRoot | Out-Null}
 $request=Join-Path $root ($name+'.request.json')
 @{mode=$name;root=$caseRoot;before=(Join-Path $root 'before.ps1');initialize=(Join-Path $root 'initialize.ps1');install=(Join-Path $root 'install.ps1')} | ConvertTo-Json | Set-Content -LiteralPath $request -Encoding UTF8
 $out=Join-Path $root ($name+'.out');$err=Join-Path $root ($name+'.err')
 $args=@('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+(Join-Path $root 'harness.ps1')+'"'),'-RequestFile',('"'+$request+'"'))
 $p=Start-Process powershell.exe -ArgumentList $args -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
 $null=$p.Handle
 @{pid=$p.Id;birth=$p.StartTime.ToFileTimeUtc()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root ($name+'.ack.json'))
 if(-not $p.WaitForExit(20000)){throw 'CONTROL_CHILD_UNKNOWN'}
 $errorText=[IO.File]::ReadAllText($err)
 if($errorText.Length -ne 0){throw ('CONTROL_CHILD_STDERR_'+$name)}
 $text=[IO.File]::ReadAllText($out).Trim()
 $value=if($text){$text | ConvertFrom-Json}else{$null}
 return @{code=$p.ExitCode;value=$value}
}
