function Open-OriginalDelete([string]$path,[bool]$directory,[string]$nativeId) {
 $flags=[uint32]2097152;if($directory){$flags=[uint32]35651584}
 $h=[StaleLockNative]::CreateFile($path,[uint32]2147549184,[uint32]3,[IntPtr]::Zero,[uint32]3,$flags,[IntPtr]::Zero)
 if($h.IsInvalid){$h.Dispose();throw 'CLEANUP_DELETE_HANDLE'}
 try{if([TertiaryPrivateStage]::Pin($h,$directory) -cne $nativeId){throw 'CLEANUP_DELETE_ID'}}catch{$h.Dispose();throw}
 return $h
}
function Open-NamedReader([string]$path,[bool]$directory,[string]$nativeId) {
 $flags=[uint32]2097152;if($directory){$flags=[uint32]35651584}
 $h=[StaleLockNative]::CreateFile($path,[uint32]2147483648,[uint32]5,[IntPtr]::Zero,[uint32]3,$flags,[IntPtr]::Zero)
 if($h.IsInvalid){$h.Dispose();throw 'CLEANUP_NAMED_HANDLE'}
 try{if([TertiaryPrivateStage]::Pin($h,$directory) -cne $nativeId){throw 'CLEANUP_NAMED_ID'}}catch{$h.Dispose();throw}
 return $h
}
