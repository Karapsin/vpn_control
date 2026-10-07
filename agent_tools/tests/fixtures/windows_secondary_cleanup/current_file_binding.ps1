function Close-FileBinding($entry) {
 $expected=$entry.expected
 if([TertiaryPrivateStage]::Pin($entry.handle,$false) -cne $expected.nativeId){throw 'CLEANUP_HELD_ID'}
 $named=$entry.named;$stream=$entry.stream
 if($null -eq $named -or $named.IsClosed -or $null -eq $stream -or -not $stream.CanRead){throw 'CLEANUP_NAMED_LIFETIME'}
 $stream.Position=0
 . {
  if($stream.Length -ne $expected.length){throw 'CLEANUP_SIZE'}
  $h=[Security.Cryptography.SHA256]::Create();try{$sha=[BitConverter]::ToString($h.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}
  if($sha -cne $expected.sha256){throw 'CLEANUP_HASH'}
  $info=Get-Item -LiteralPath $entry.path -Force -ErrorAction Stop
  if($info.CreationTimeUtc.Ticks -ne $expected.creationTicks -or $info.LastWriteTimeUtc.Ticks -ne $expected.writeTicks -or $info.LinkType -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CLEANUP_GENERATION'}
  Assert-RecordedAcl $entry.path $expected.acl
  if([TertiaryPrivateStage]::Pin($named,$false) -cne $expected.nativeId -or [TertiaryPrivateStage]::Pin($entry.handle,$false) -cne $expected.nativeId){throw 'CLEANUP_FILE_CLOSING'}
 }
}
