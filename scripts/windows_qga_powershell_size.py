"""Bound encoded PowerShell commands used by the inert CP117 QGA fixture."""

import base64
import re


MAX_ENCODED_COMMAND_CHARS = 30000


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
