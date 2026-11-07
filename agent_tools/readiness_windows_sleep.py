"""Read-only Windows sleep decision for one owned fixture boot.

The fixed probe asks a Microsoft-signed powercfg for its capability table and
nothing else. It sends no input and requests no power state. A reported S3 row is
a capability, never permission to sleep; other languages or shapes refuse.
"""
import re
import sys
from uuid import UUID

from . import windows_sleep_capability as capability

_EXECUTING_CODE = sys._getframe().f_code

_PUBLISHERS = ("'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US',"
               "'CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US',"
               "'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'")

_BOOT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z")


def _machine(machine):
    if type(machine) is not str or str(UUID(machine)) != machine:
        raise ValueError("windows_sleep_machine")
    return machine


def _boot(boot):
    if type(boot) is not str or _BOOT.fullmatch(boot) is None:
        raise ValueError("windows_sleep_boot")
    return boot


def powershell_source(machine, boot):
    _machine(machine); _boot(boot)
    return ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n"
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "function Guard {\n"
            " if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM_REQUIRED'}\n"
            " $m=([Guid](Get-CimInstance Win32_ComputerSystemProduct).UUID).ToString('D')\n"
            " $b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')\n"
            " if($m -ne '" + machine + "' -or $b -ne '" + boot + "'){throw 'SLEEP_EPOCH_CHANGED'}\n"
            "}\n"
            "Guard\n"
            "$path=Join-Path $env:SystemRoot 'System32\\powercfg.exe'\n"
            "$item=Get-Item -LiteralPath $path -Force\n"
            "if(-not ($item -is [IO.FileInfo]) -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'SLEEP_BINARY_IDENTITY'}\n"
            "$signature=Get-AuthenticodeSignature -LiteralPath $path\n"
            "$publishers=@(" + _PUBLISHERS + ")\n"
            "if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $publishers -notcontains $signature.SignerCertificate.Subject){throw 'SLEEP_BINARY_TRUST'}\n"
            "$output=@(& $path /a 2>&1|ForEach-Object {[string]$_});$code=$LASTEXITCODE\n"
            "if($code -ne 0 -or $output.Count -gt 100 -or ($output -join \"`n\").Length -gt 16384){throw 'SLEEP_CAPABILITIES_UNAVAILABLE'}\n"
            "Guard\n"
            "[Console]::WriteLine((@{schemaVersion=1;machine='" + machine + "';boot='" + boot + "';readOnly=$true;inputAuthority=$false;powerSubmitted=$false;binaryMicrosoftSigned=$true;exitCode=$code;lines=$output}|ConvertTo-Json -Depth 4 -Compress))\n")


def validate(value, machine, boot):
    """Return the fixed projection; every unrecognized observation refuses."""
    _machine(machine); _boot(boot)
    fields = {"schemaVersion", "machine", "boot", "readOnly", "inputAuthority", "powerSubmitted",
              "binaryMicrosoftSigned", "exitCode", "lines"}
    if (type(value) is not dict or set(value) != fields or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["machine"] != machine or value["boot"] != boot
            or value["readOnly"] is not True or value["inputAuthority"] is not False
            or value["powerSubmitted"] is not False or value["binaryMicrosoftSigned"] is not True
            or type(value["exitCode"]) is not int or value["exitCode"] != 0):
        raise ValueError("windows_sleep_capability_unrecognized")
    return capability.observe_s3(value["lines"])


def decision(projection, *, machine, boot, reason=None):
    """The scenario's whole outcome. No branch here or later submits power."""
    base = {"machine": machine, "boot": boot, "powerAllowed": False, "powerSubmitted": False, "replayAllowed": False}
    if projection is None:
        return {**base, "ok": False, "state": "unknown", "reason": reason or "windows_sleep_capability_unrecognized",
                "nativeReasons": [], "nextAction": "resolve_blocker"}
    if projection["state"] == "unsupported":
        return {**base, "ok": False, "state": "refused", "reason": projection["reason"],
                "nativeReasons": projection["nativeReasons"], "nextAction": "complete"}
    return {**base, "ok": True, "state": "supported", "reason": None, "nativeReasons": [], "nextAction": "complete"}
