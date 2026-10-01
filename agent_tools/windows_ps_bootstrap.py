"""Bounded, verified PowerShell bootstrap encoding for QGA guest commands.

The caller supplies reviewed, fixed PowerShell source.  This module never
selects a shell, constructs a ``-Command`` invocation, writes a temporary
file, or executes anything locally.  It returns only the value for
PowerShell's ``-EncodedCommand`` argument.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
from typing import Final


MAX_ENCODED_COMMAND_CHARS: Final = 30_000
"""Conservative QGA/Windows command admission limit, including wrapper."""

MAX_SOURCE_BYTES: Final = 256_000
"""Maximum reviewed bootstrap payload admitted before compression."""


class WindowsPowerShellBootstrapError(ValueError):
    """The fixed bootstrap cannot safely fit the QGA command boundary."""


def _deterministic_gzip(value: bytes) -> bytes:
    """Compress without timestamps, filenames, or platform-dependent headers."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
        stream.write(value)
    return output.getvalue()


def encode_verified_bootstrap(source: str) -> str:
    """Return the base64 value for a verified PowerShell ``-EncodedCommand``.

    ``source`` must be the caller's already-reviewed fixed script.  The guest
    wrapper decompresses UTF-8 bytes in memory, verifies their SHA-256 before
    decoding or invoking them, and fails closed on any mismatch.
    """
    if not isinstance(source, str):
        raise WindowsPowerShellBootstrapError("PowerShell bootstrap source must be text.")
    if not source or "\x00" in source:
        raise WindowsPowerShellBootstrapError("PowerShell bootstrap source is invalid.")

    payload = source.encode("utf-8")
    if len(payload) > MAX_SOURCE_BYTES:
        raise WindowsPowerShellBootstrapError("PowerShell bootstrap source exceeds decompression admission.")
    compressed = _deterministic_gzip(payload)
    packed = base64.b64encode(compressed).decode("ascii")
    expected = hashlib.sha256(payload).hexdigest()

    # All dynamic values are base64 or lowercase hex generated above.  The
    # wrapper has a single fixed invocation path and keeps every byte in memory.
    wrapper = (
        "$ErrorActionPreference='Stop';"
        f"$packed='{packed}';$expected='{expected}';"
        "$input=[IO.MemoryStream]::new([Convert]::FromBase64String($packed));"
        "$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress);"
        "$output=[IO.MemoryStream]::new();"
        f"$max={MAX_SOURCE_BYTES};$buffer=New-Object byte[] 8192;$total=0;"
        "try{while(($read=$gzip.Read($buffer,0,$buffer.Length)) -gt 0){$total+=$read;if($total -gt $max){throw 'BOOTSTRAP_SIZE'};$output.Write($buffer,0,$read)};$bytes=$output.ToArray()}finally{$gzip.Dispose();$input.Dispose();$output.Dispose()};"
        "$actual=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-','').ToLowerInvariant();"
        "if($actual -cne $expected){throw 'BOOTSTRAP_SHA256_MISMATCH'};"
        "$script=[Text.Encoding]::UTF8.GetString($bytes);"
        "& ([ScriptBlock]::Create($script))"
    )
    encoded = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
    if len(encoded) > MAX_ENCODED_COMMAND_CHARS:
        raise WindowsPowerShellBootstrapError("Verified PowerShell bootstrap exceeds QGA command admission.")
    return encoded


# This source is injected into the fixed remote Python QGA program.  Keep it
# self-contained: an Arch host executing it has no repository import path.
REMOTE_ENCODER_SOURCE: Final = r'''import base64
import gzip
import hashlib
import io

_COMPACT_PS_MAX_ENCODED_COMMAND_CHARS = 30000
_COMPACT_PS_MAX_SOURCE_BYTES = 256000

def _compact_ps_gzip(value):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
        stream.write(value)
    return output.getvalue()

def compact_ps_bootstrap(script):
    if not isinstance(script, str):
        raise ValueError("PowerShell bootstrap source must be text.")
    if not script or "\x00" in script:
        raise ValueError("PowerShell bootstrap source is invalid.")
    payload = script.encode("utf-8")
    if len(payload) > _COMPACT_PS_MAX_SOURCE_BYTES:
        raise ValueError("PowerShell bootstrap source exceeds decompression admission.")
    packed = base64.b64encode(_compact_ps_gzip(payload)).decode("ascii")
    expected = hashlib.sha256(payload).hexdigest()
    wrapper = (
        "$ErrorActionPreference='Stop';"
        f"$packed='{packed}';$expected='{expected}';"
        "$input=[IO.MemoryStream]::new([Convert]::FromBase64String($packed));"
        "$gzip=[IO.Compression.GzipStream]::new($input,[IO.Compression.CompressionMode]::Decompress);"
        "$output=[IO.MemoryStream]::new();"
        f"$max={_COMPACT_PS_MAX_SOURCE_BYTES};$buffer=New-Object byte[] 8192;$total=0;"
        "try{while(($read=$gzip.Read($buffer,0,$buffer.Length)) -gt 0){$total+=$read;if($total -gt $max){throw 'BOOTSTRAP_SIZE'};$output.Write($buffer,0,$read)};$bytes=$output.ToArray()}finally{$gzip.Dispose();$input.Dispose();$output.Dispose()};"
        "$actual=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-','').ToLowerInvariant();"
        "if($actual -cne $expected){throw 'BOOTSTRAP_SHA256_MISMATCH'};"
        "$script=[Text.Encoding]::UTF8.GetString($bytes);"
        "& ([ScriptBlock]::Create($script))"
    )
    encoded = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
    if len(encoded) > _COMPACT_PS_MAX_ENCODED_COMMAND_CHARS:
        raise ValueError("Verified PowerShell bootstrap exceeds QGA command admission.")
    return encoded
'''
