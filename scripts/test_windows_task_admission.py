#!/usr/bin/env python3
"""Deterministic PowerShell fixture for batch-logon admission classification."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HELPER = ROOT / "windows_task_admission.ps1"


def main() -> int:
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        print("PowerShell dependency missing: run this Windows fixture with pwsh or Windows PowerShell.", file=sys.stderr)
        return 2

    helper = str(HELPER).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
. '{helper}'
$secure = New-Object Security.SecureString
$secure.AppendChar([char]120)
$secure.MakeReadOnly()
$synthetic = @('[Unicode]','Unicode=yes','[Privilege Rights]','SeBatchLogonRight = *S-1-5-21-1','SeDenyBatchLogonRight = *S-1-5-32-545')
function R {{ throw 'alias collision must not be invoked' }}
$rights = Get-TaskAdmissionPrivilegeRights -Lines $synthetic
if ($rights['SeBatchLogonRight'] -ne '*S-1-5-21-1' -or $rights['SeDenyBatchLogonRight'] -ne '*S-1-5-32-545') {{ throw 'unambiguous privilege-right parser failed' }}
$closed = @()
$deny = Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$false; Win32Error=[uint32]1385; Token=[IntPtr]::Zero }} }} -CloseToken {{ param($t) throw 'denied admission must not close a zero token' }}
if ($deny.admitted -or $deny.logonType -ne 4 -or $deny.win32Error -ne 1385 -or ('0x{{0:X8}}' -f $deny.hresult) -ne '0x80070569') {{ throw 'RED batch-logon denial was not classified causally' }}
foreach ($case in @(@{{ error=[uint32]524289; expected=[uint32]2147942401 }}, @{{ error=[uint32]2147500037; expected=[uint32]2147500037 }})) {{
    $boundary = Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$false; Win32Error=$case.error; Token=[IntPtr]::Zero }} }} -CloseToken {{ param($t) throw 'boundary denial must not close a zero token' }}
    if ($boundary.admitted -or $boundary.hresult -ne $case.expected) {{ throw 'HRESULT_FROM_WIN32 boundary conversion failed' }}
}}
$credentials = Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$false; Win32Error=[uint32]1326; Token=[IntPtr]::Zero }} }} -CloseToken {{ param($t) throw 'bad credentials must not close a zero token' }}
if ($credentials.admitted -or $credentials.win32Error -ne 1326 -or ('0x{{0:X8}}' -f $credentials.hresult) -ne '0x8007052E') {{ throw 'bad credentials was conflated with batch-right denial' }}
$invalidClosed = @()
try {{ Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$false; Win32Error=[uint32]0; Token=[IntPtr]99 }} }} -CloseToken {{ param($t) $script:invalidClosed += $t.ToInt64() }}; throw 'invalid native status was accepted' }} catch {{ if ($_.Exception.Message -eq 'invalid native status was accepted') {{ throw }} }}
if ($invalidClosed.Count -ne 1 -or $invalidClosed[0] -ne 99) {{ throw 'invalid native status did not close its token' }}
try {{ Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$true; Win32Error=[uint32]0; Token=[IntPtr]::Zero }} }} -CloseToken {{ param($t) throw 'zero success token must not close' }}; throw 'zero-token success was accepted' }} catch {{ if ($_.Exception.Message -eq 'zero-token success was accepted') {{ throw }} }}
$allow = Test-BatchLogonAdmission -UserName 'fixture-user' -Password $secure -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$true; Win32Error=[uint32]0; Token=[IntPtr]42 }} }} -CloseToken {{ param($t) $script:closed += $t.ToInt64() }}
if (-not $allow.admitted -or $allow.logonType -ne 4 -or $allow.win32Error -ne 0 -or $allow.hresult -ne 0 -or $closed.Count -ne 1 -or $closed[0] -ne 42) {{ throw 'GREEN batch-logon admission or token close failed' }}

try {{
    $admission = [pscustomobject]@{{
        operation = 'windows-credential-validity-v1'
        accountName = 'fixture-user'
        expectedAccountSid = 'S-1-5-21-1-2-3-1002'
        approvedCallerSid = 'S-1-5-18'
    }}
    $nativeCalls = 0
    $closedTokens = @()
    $valid = Test-WindowsCredentialValidityAdmission -Admission $admission `
        -ResolveAccountSid {{ param($name) 'S-1-5-21-1-2-3-1002' }} `
        -GetCallerSid {{ 'S-1-5-18' }} `
        -Credential $secure `
        -NativeInvoker {{ param($u,$p) $script:nativeCalls++; [pscustomobject]@{{ Success=$true; Win32Error=[uint32]0; Token=[IntPtr]74 }} }} `
        -CloseToken {{ param($token) $script:closedTokens += $token.ToInt64() }}
    if ($valid.success -ne $true -or $valid.errorCategory -ne 'none' -or $nativeCalls -ne 1 -or $closedTokens.Count -ne 1 -or $closedTokens[0] -ne 74) {{ throw 'credential validity GREEN result or token cleanup failed' }}

    foreach ($case in @(
        @{{ error=[uint32]1326; expected='invalid-credentials' }},
        @{{ error=[uint32]1331; expected='account-restricted' }},
        @{{ error=[uint32]5; expected='unavailable' }}
    )) {{
        $closedTokens = @()
        $result = Test-WindowsCredentialValidityAdmission -Admission $admission `
            -ResolveAccountSid {{ param($name) 'S-1-5-21-1-2-3-1002' }} -GetCallerSid {{ 'S-1-5-18' }} `
            -Credential $secure `
            -NativeInvoker {{ param($u,$p) [pscustomobject]@{{ Success=$false; Win32Error=$case.error; Token=[IntPtr]75 }} }} `
            -CloseToken {{ param($token) $script:closedTokens += $token.ToInt64() }}
        if ($result.success -or $result.errorCategory -ne $case.expected -or $closedTokens.Count -ne 1 -or $closedTokens[0] -ne 75) {{ throw 'credential validity failure category or cleanup failed' }}
    }}

    foreach ($bad in @(
        [pscustomobject]@{{ operation='wrong'; accountName='fixture-user'; expectedAccountSid='S-1-5-21-1-2-3-1002'; approvedCallerSid='S-1-5-18' }},
        [pscustomobject]@{{ operation='windows-credential-validity-v1'; accountName='fixture-user'; expectedAccountSid='S-1-5-21-1-2-3-1003'; approvedCallerSid='S-1-5-18' }},
        [pscustomobject]@{{ operation='windows-credential-validity-v1'; accountName='fixture-user'; expectedAccountSid='S-1-5-21-1-2-3-1002'; approvedCallerSid='S-1-5-18'; ownedVm=$true }}
    )) {{
        $nativeCalls = 0
        try {{ Test-WindowsCredentialValidityAdmission -Admission $bad -Credential $secure -ResolveAccountSid {{ param($name) 'S-1-5-21-1-2-3-1002' }} -GetCallerSid {{ 'S-1-5-18' }} -NativeInvoker {{ $script:nativeCalls++; throw 'native invocation reached' }}; throw 'invalid credential admission reached native invocation' }} catch {{ if ($_.Exception.Message -eq 'invalid credential admission reached native invocation') {{ throw }} }}
        if ($nativeCalls -ne 0) {{ throw 'invalid credential admission invoked native authentication' }}
    }}
    $nonSystemCalls = 0
    try {{ Test-WindowsCredentialValidityAdmission -Admission $admission -Credential $secure -ResolveAccountSid {{ param($name) 'S-1-5-21-1-2-3-1002' }} -GetCallerSid {{ 'S-1-5-21-9-8-7-1002' }} -NativeInvoker {{ $script:nonSystemCalls++; throw 'native invocation reached' }}; throw 'non-SYSTEM caller reached native invocation' }} catch {{ if ($_.Exception.Message -eq 'non-SYSTEM caller reached native invocation') {{ throw }} }}
    if ($nonSystemCalls -ne 0) {{ throw 'non-SYSTEM caller invoked native authentication' }}
}}
finally {{ $secure.Dispose() }}
Write-Output 'WINDOWS_TASK_ADMISSION_FIXTURE_OK'
"""
    try:
        result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], text=True, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        print("PowerShell fixture timed out after 60 seconds.", file=sys.stderr)
        return 124
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
