Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('VpnControl.BatchLogonNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace VpnControl {
    public static class BatchLogonNative {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LogonUserW(
            string userName, string domain, IntPtr password, int logonType,
            int logonProvider, out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
}

function Invoke-NativeBatchLogon {
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][Security.SecureString]$Password
    )

    $passwordBuffer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Password)
    try {
        $account = $UserName
        $domain = $null
        if ($UserName -match '^(?<domain>[^\\]+)\\(?<account>[^\\]+)$') {
            $domain = $Matches.domain
            $account = $Matches.account
        }
        $token = [IntPtr]::Zero
        $success = [VpnControl.BatchLogonNative]::LogonUserW($account, $domain, $passwordBuffer, 4, 0, [ref]$token)
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [pscustomobject]@{
            Success = $success
            Win32Error = if ($success) { [UInt32]0 } else { [UInt32]$lastError }
            Token = $token
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordBuffer)
    }
}

function Close-BatchLogonToken {
    param([Parameter(Mandatory = $true)][IntPtr]$Token)
    if (-not [VpnControl.BatchLogonNative]::CloseHandle($Token)) {
        throw 'Batch-logon token close failed.'
    }
}

function Get-TaskAdmissionPrivilegeRights {
    param([Parameter(Mandatory = $true)][string[]]$Lines)

    $rights = @{}
    $inPrivilegeRights = $false
    foreach ($line in $Lines) {
        if ($line -eq '[Privilege Rights]') { $inPrivilegeRights = $true; continue }
        if ($line -match '^\[') { $inPrivilegeRights = $false }
        if ($inPrivilegeRights -and $line -match '^([^=]+)\s*=\s*(.*)$') {
            $rights[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $rights
}

function New-BatchLogonAdmissionResult {
    param(
        [Parameter(Mandatory = $true)][bool]$Succeeded,
        [Parameter(Mandatory = $true)][UInt32]$Win32Error
    )

    if ($Succeeded -and $Win32Error -ne 0) {
        throw 'A successful batch logon cannot include a Win32 error.'
    }
    if (-not $Succeeded -and $Win32Error -eq 0) {
        throw 'A failed batch logon must include its Win32 error.'
    }

    [pscustomobject]@{
        admitted = $Succeeded
        logonType = 4 # LOGON32_LOGON_BATCH
        win32Error = $Win32Error
        hresult = if ($Succeeded) { [UInt32]0 }
            elseif ($Win32Error -ge [UInt32]2147483648) { $Win32Error }
            else { [UInt32](0x80070000 -bor ($Win32Error -band 0xFFFF)) }
    }
}

function Test-BatchLogonAdmission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][Security.SecureString]$Password,
        [scriptblock]$NativeInvoker = ${function:Invoke-NativeBatchLogon},
        [scriptblock]$CloseToken = ${function:Close-BatchLogonToken}
    )

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        throw 'Batch-logon admission requires an account name.'
    }

    # NativeInvoker returns only Success, Win32Error, and Token.  The caller must
    # never log the password or marshal it into a command line.
    $native = & $NativeInvoker $UserName $Password
    if ($null -eq $native -or $null -eq $native.Success -or $null -eq $native.Win32Error -or $null -eq $native.Token) {
        throw 'Native batch-logon result is incomplete.'
    }

    $token = [IntPtr]$native.Token
    try {
        if ([bool]$native.Success -and $token -eq [IntPtr]::Zero) {
            throw 'Successful native batch logon returned no token.'
        }
        return New-BatchLogonAdmissionResult -Succeeded ([bool]$native.Success) -Win32Error ([UInt32]$native.Win32Error)
    }
    finally {
        if ($token -ne [IntPtr]::Zero) {
            & $CloseToken $token
        }
    }
}
