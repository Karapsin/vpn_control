"""Bound encoded PowerShell commands used by the inert CP117 QGA fixture."""

import base64
import gzip
import hashlib
import re


MAX_ENCODED_COMMAND_CHARS = 30000
MAX_SCRIPT_BYTES = 131000


def compressed_powershell_command(script: str) -> str:
    """Emit one bounded, source-bound task invocation; never execute its body."""
    if not isinstance(script, str):
        raise ValueError("PowerShell source must be text")
    raw = script.encode("utf-8", errors="strict")
    if not 0 < len(raw) <= MAX_SCRIPT_BYTES:
        raise ValueError("PowerShell source exceeds byte bound")
    packed = base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    command = r"""$ErrorActionPreference='Stop'
$expected=@SIZE@;$packed=[Convert]::FromBase64String('@PACKED@')
if($expected -le 0 -or $expected -gt 131000 -or $packed.Length -gt 49152){throw 'TASK_BODY_BOUND'}
$input=[IO.MemoryStream]::new([byte[]]$packed)
$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress)
$output=[IO.MemoryStream]::new();$buffer=[byte[]]::new(4096)
try{
 while($true){
  $count=$gzip.Read($buffer,0,[Math]::Min($buffer.Length,($expected+1-[int]$output.Length)))
  if($count -eq 0){break}
  $output.Write($buffer,0,$count)
  if($output.Length -gt $expected){throw 'TASK_BODY_LENGTH'}
 }
 $bytes=$output.ToArray()
}finally{$gzip.Dispose();$input.Dispose();$output.Dispose()}
if($bytes.Length -ne $expected){throw 'TASK_BODY_LENGTH'}
$hash=[Security.Cryptography.SHA256]::Create()
try{$actual=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
if($actual -cne '@SHA@'){throw 'TASK_BODY_SHA256'}
$body=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseInput($body,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'TASK_BODY_PARSE'}
& ([ScriptBlock]::Create($body))
""".replace("@SIZE@", str(len(raw))).replace("@PACKED@", packed).replace("@SHA@", digest)
    prefix = "-NoProfile -NonInteractive -EncodedCommand "
    if len(prefix) + encoded_command_size(command) > MAX_ENCODED_COMMAND_CHARS:
        raise ValueError("Compressed PowerShell task command exceeds bound")
    return command


def encoded_command_size(script: str) -> int:
    return len(base64.b64encode(script.encode("utf-16le")))


def plan_chunks(payload: str, nonce: str) -> list[tuple[str, str]]:
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", payload) or not re.fullmatch(r"[0-9a-f]{16}", nonce):
        raise ValueError("QGA fixture payload or nonce rejected")
    commands = []
    for index, start in enumerate(range(0, len(payload), 6000)):
        chunk = payload[start : start + 6000]
        prelude = "$dir=Join-Path $env:TEMP 'vpn-role-cp176-" + nonce + "'; "
        if index == 0:
            prelude += "if ([IO.Directory]::Exists($dir)) { throw 'Fixture exists' }; [IO.Directory]::CreateDirectory($dir) | Out-Null; "
        else:
            prelude += "if (-not [IO.Directory]::Exists($dir)) { throw 'Fixture missing' }; "
        command = prelude + "[IO.File]::AppendAllText((Join-Path $dir 'bundle.b64'),'" + chunk + "')"
        if encoded_command_size(command) > MAX_ENCODED_COMMAND_CHARS:
            raise ValueError("QGA PowerShell command exceeds bound")
        commands.append((command, chunk))
    return commands
