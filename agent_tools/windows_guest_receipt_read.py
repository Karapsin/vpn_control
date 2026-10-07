"""Bounded, process-scoped reads of fixed Windows fixture receipts."""

from __future__ import annotations


# This source is appended after windows_msi_base_prepare._QGA.  It deliberately
# uses guest-exec output rather than guest-file-open: a lost open response can
# leave an otherwise unaddressable QGA handle in the guest agent.
REMOTE_HELPER = r'''import time,uuid
def read_fixed_receipt(sock,corr):
 try:
  if not isinstance(corr,str) or str(uuid.UUID(corr))!=corr:raise ValueError()
  path='C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-update-fixture-'+corr+'\\result.json'
  script="$ErrorActionPreference='Stop';$path='"+path+"';if(-not [IO.File]::Exists($path)){exit 3};$item=Get-Item -LiteralPath $path -Force;if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 2};for($parent=$item.Directory;$null -ne $parent;$parent=$parent.Parent){if(($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 2}};$stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None);try{$length=$stream.Length;if($length -lt 1 -or $length -gt 8192){exit 2};$bytes=New-Object byte[] ([int]$length);$offset=0;while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -le 0){exit 2};$offset+=$count};[Console]::OpenStandardOutput().Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}"
  encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
  if len(encoded)>=30000:raise ValueError()
  child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
  if type(child) is not int or child<=0:raise ValueError()
  for _ in range(40):
   item=call(sock,'guest-exec-status',{'pid':child})
   if item.get('exited') is True:break
   if item.get('exited') is not False:raise ValueError()
   time.sleep(.25)
  else:raise ValueError()
  if (item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False
      or type(item.get('exitcode')) is not int):raise ValueError()
  raw=base64.b64decode(item.get('out-data',''),validate=True)
  if item.get('exitcode')==3:
   if raw:raise ValueError()
   return None
  if item.get('exitcode')!=0 or not 0<len(raw)<=8192:raise ValueError()
  return raw
 except Exception:raise ValueError()
'''
