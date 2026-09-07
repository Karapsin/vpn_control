$ErrorActionPreference='Stop'
$gzip=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String('__CAPTURED_NATIVE_GZIP__')),[IO.Compression.CompressionMode]::Decompress)
$reader=[IO.StreamReader]::new($gzip,[Text.UTF8Encoding]::new($false,$true))
try{$source=$reader.ReadToEnd()}finally{$reader.Dispose()}
# Native IO, sharing, rename packets and path checks are unchanged. Like the JVM
# native backend tests, only the receipt method's trust policy permits the exact
# current SID for this new temporary fixture. No elevation or machine writes.
$start=$source.IndexOf('public static void ReplaceReceipt(')
$end=$source.IndexOf('public static void CreateDirectory(', $start)
if($start -lt 0 -or $end -le $start){throw 'Missing captured receipt publisher'}
$method=$source.Substring($start,$end-$start)
$policy=',false,null);'
if(-not $method.Contains($policy)){throw 'Missing protected receipt inspection'}
$method=$method.Replace($policy,',false,WindowsIdentity.GetCurrent().User.Value);')
$source=$source.Substring(0,$start)+$method+$source.Substring($end)
Add-Type -TypeDefinition $source
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('vpn-fixed-receipt-'+[Guid]::NewGuid().ToString())
$acl='O:'+$sid+'G:'+$sid+'D:P(A;OICI;FA;;;'+$sid+')(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'
[VpnInstallNative]::CreateDirectory($fixture,$acl)
$directory=$null;$retained=$null
try{
 $directory=[VpnInstallNative]::OpenDirectory($fixture)
 [VpnInstallNative]::Inspect($directory,$true,$false,$sid)
 $first='status-'+[Guid]::NewGuid().ToString()+'.tmp'
 $file=[VpnInstallNative]::CreateFile((Join-Path $fixture $first),$acl,[Text.Encoding]::UTF8.GetBytes('complete-first-receipt'))
 $file.Dispose()
 [VpnInstallNative]::ReplaceReceipt($directory,$first)
 $target=Join-Path $fixture 'status.json'
 if([IO.File]::ReadAllText($target) -cne 'complete-first-receipt'){throw 'First receipt was not published'}
 $retained=[IO.FileStream]::new([VpnInstallNative]::OpenReceipt($target),[IO.FileAccess]::Read)
 $moved=$false
 try{[IO.Directory]::Move($fixture,$fixture+'-moved');$moved=$true}catch{}
 if($moved){throw 'Publisher released its directory pin'}
 $rewritten=$false
 try{[IO.File]::WriteAllText($target,'untrusted-rewrite');$rewritten=$true}catch{}
 if($rewritten){throw 'Retained receipt allowed writes'}
 $second='status-'+[Guid]::NewGuid().ToString()+'.tmp'
 $file=[VpnInstallNative]::CreateFile((Join-Path $fixture $second),$acl,[Text.Encoding]::UTF8.GetBytes('complete-second-receipt'))
 $file.Dispose()
 [VpnInstallNative]::ReplaceReceipt($directory,$second)
 if([IO.File]::ReadAllText($target) -cne 'complete-second-receipt'){throw 'Replacement receipt was not published'}
 $old=[byte[]]::new([int]$retained.Length)
 if($retained.Read($old,0,$old.Length) -ne $old.Length -or [Text.Encoding]::UTF8.GetString($old) -cne 'complete-first-receipt'){throw 'Retained reader lost its original receipt'}
 if([IO.File]::Exists((Join-Path $fixture $first)) -or [IO.File]::Exists((Join-Path $fixture $second))){throw 'Published temporary receipt remained'}
 $rejected=$false
 try{[VpnInstallNative]::ReplaceReceipt($directory,'..\status.json')}catch{$rejected=$true}
 if(-not $rejected){throw 'Publisher accepted a caller-chosen path'}
 $privatePath=Join-Path $fixture 'private-input.bin'
 $file=[VpnInstallNative]::CreateFile($privatePath,$acl,[Text.Encoding]::UTF8.GetBytes('private-input'))
 $file.Dispose()
 $privatePin=[VpnInstallNative]::OpenRead($privatePath,$false)
 try{
  $deleted=$false
  try{[IO.File]::Delete($privatePath);$deleted=$true}catch{}
  if($deleted){throw 'Receipt sharing policy weakened private input pins'}
 }finally{$privatePin.Dispose()}
 Write-Output 'FIXED_NATIVE_RECEIPT_OK'
}finally{
 if($retained){$retained.Dispose()}
 if($directory){$directory.Dispose()}
 [IO.Directory]::Delete($fixture,$true)
}
