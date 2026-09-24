#!/usr/bin/env python3
"""Build and verify the ACL for a Windows MSI fixture staging directory.

The staging directory is deliberately protected from inherited ProgramData ACLs.
Only SYSTEM and Administrators receive FullControl; the exact interactive fixture
recipient receives ReadAndExecute.  The generated PowerShell verifies that state
before it emits a receipt, while this module validates the receipt on the host.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
FULL_CONTROL = 0x1F01FF
READ_AND_EXECUTE = 0x1200A9
_INTERACTIVE_SID = re.compile(r"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", re.IGNORECASE)
_WINDOWS_DIRECTORY = re.compile(r"^[A-Za-z]:\\(?:[^\\/:*?\"<>|]+\\)*[^\\/:*?\"<>|]+$")


class StageAclValidationError(ValueError):
    """The guest's ACL receipt cannot attest the required isolated stage."""


def _validate_sid(recipient_sid: str) -> str:
    if not isinstance(recipient_sid, str) or _INTERACTIVE_SID.fullmatch(recipient_sid) is None:
        raise ValueError("recipient SID must be a canonical interactive user SID")
    return recipient_sid.upper()


def _validate_directory(directory: str) -> str:
    if not isinstance(directory, str) or _WINDOWS_DIRECTORY.fullmatch(directory) is None:
        raise ValueError("stage directory must be an absolute, non-root Windows directory")
    components = directory[3:].split("\\")
    if any(component in {".", ".."} or component[-1] in {".", " "} for component in components):
        raise ValueError("stage directory must not contain Windows alias components")
    return directory


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAclValidationError(f"{label} must be an object")
    return value


def _decode_guest_output(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract the PowerShell JSON object from a native QGA status receipt."""
    if "verify" not in receipt:
        # The generator's final JSON object is a documented direct local input.
        # It has no QGA process-capture fields to attest.
        return receipt
    verify = receipt["verify"]
    verify = _require_mapping(verify, "ACL verification")
    if verify.get("exited") is not True:
        raise StageAclValidationError("ACL verification did not reach a terminal QGA state")
    if verify.get("out-truncated") is not False or verify.get("err-truncated") is not False:
        raise StageAclValidationError("ACL verification QGA capture is truncated")
    exitcode = verify.get("exitcode")
    if isinstance(exitcode, bool) or not isinstance(exitcode, int) or exitcode != 0:
        raise StageAclValidationError("ACL verification PowerShell did not exit successfully")
    encoded = verify.get("out-data")
    if not isinstance(encoded, str) or not encoded:
        raise StageAclValidationError("ACL verification QGA capture is missing output")
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8-sig")
        return _require_mapping(json.loads(decoded), "ACL verification output")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StageAclValidationError("ACL verification output is not valid UTF-8 JSON") from error


def validate_stage_acl_receipt(receipt: Mapping[str, Any], recipient_sid: str,
                               expected_directory: str) -> None:
    """Require the complete, protected three-principal stage ACL in *receipt*."""
    expected_recipient = _validate_sid(recipient_sid)
    expected_stage = _validate_directory(expected_directory)
    observed = _decode_guest_output(_require_mapping(receipt, "stage receipt"))
    if observed.get("stage") != expected_stage:
        raise StageAclValidationError("stage ACL receipt does not attest the requested stage directory")
    if observed.get("protected") is not True:
        raise StageAclValidationError("stage ACL receipt must attest protected inheritance")
    entries = observed.get("acl")
    if not isinstance(entries, list):
        raise StageAclValidationError("stage ACL receipt must contain an ACL list")
    expected = {
        SYSTEM_SID: FULL_CONTROL,
        ADMINISTRATORS_SID: FULL_CONTROL,
        expected_recipient: READ_AND_EXECUTE,
    }
    actual: dict[str, int] = {}
    for entry in entries:
        item = _require_mapping(entry, "stage ACL entry")
        sid = item.get("sid")
        rights = item.get("rights")
        if not isinstance(sid, str) or isinstance(rights, bool) or not isinstance(rights, int):
            raise StageAclValidationError("stage ACL entry must contain a SID and numeric rights")
        normalized_sid = sid.upper()
        if item.get("type") != "Allow" or item.get("inherited") is not False:
            raise StageAclValidationError("stage ACL must contain only explicit allow entries")
        if item.get("inheritance") != 3 or item.get("propagation") != 0:
            raise StageAclValidationError("stage ACL inheritance flags are not fixture-safe")
        if normalized_sid in actual:
            raise StageAclValidationError(f"stage ACL repeats principal {sid}")
        actual[normalized_sid] = rights
    if actual != expected:
        raise StageAclValidationError("stage ACL principals or rights differ from the required fixture ACL")


def stage_acl_powershell(directory: str, recipient_sid: str) -> str:
    """Return terminating-error PowerShell that applies and self-verifies the ACL."""
    stage = _validate_directory(directory)
    recipient = _validate_sid(recipient_sid)
    encoded_stage = base64.b64encode(stage.encode("utf-16le")).decode("ascii")
    return f'''$ErrorActionPreference = 'Stop'
$stage = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded_stage}'))
$recipientSid = [Security.Principal.SecurityIdentifier]::new('{recipient}')
$systemSid = [Security.Principal.SecurityIdentifier]::new('{SYSTEM_SID}')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('{ADMINISTRATORS_SID}')
$inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow
$stageItem = Get-Item -LiteralPath $stage -Force -ErrorAction Stop
if (-not $stageItem.PSIsContainer) {{ throw 'fixture stage directory is missing' }}
for ($ancestor = $stageItem; $null -ne $ancestor; $ancestor = $ancestor.Parent) {{
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ throw 'fixture stage path contains a reparse point' }}
}}
$acl = Get-Acl -LiteralPath $stage -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleSpecific($entry) }}
foreach ($rule in @(
    [Security.AccessControl.FileSystemAccessRule]::new($systemSid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow),
    [Security.AccessControl.FileSystemAccessRule]::new($administratorsSid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, $allow),
    [Security.AccessControl.FileSystemAccessRule]::new($recipientSid, [Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritance, $propagation, $allow)
)) {{ [void]$acl.AddAccessRule($rule) }}
Set-Acl -LiteralPath $stage -AclObject $acl -ErrorAction Stop
$verified = Get-Acl -LiteralPath $stage -ErrorAction Stop
$records = @($verified.Access | ForEach-Object {{
    [ordered]@{{
        sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        rights = [int]$_.FileSystemRights
        type = $_.AccessControlType.ToString()
        inherited = $_.IsInherited
        inheritance = [int]$_.InheritanceFlags
        propagation = [int]$_.PropagationFlags
    }}
}})
$expected = @{{
    '{SYSTEM_SID}' = {FULL_CONTROL}
    '{ADMINISTRATORS_SID}' = {FULL_CONTROL}
    '{recipient}' = {READ_AND_EXECUTE}
}}
if (-not $verified.AreAccessRulesProtected) {{ throw 'fixture stage ACL inheritance remains unprotected' }}
if ($records.Count -ne $expected.Count) {{ throw 'fixture stage ACL principal count differs' }}
$seen = @{{}}
foreach ($record in $records) {{
    if ($record.type -ne 'Allow' -or $record.inherited -or $record.inheritance -ne 3 -or $record.propagation -ne 0) {{ throw 'fixture stage ACL entry is unsafe' }}
    if ($seen.ContainsKey($record.sid)) {{ throw 'fixture stage ACL repeats a principal' }}
    $seen[$record.sid] = $true
    if (-not $expected.ContainsKey($record.sid) -or $expected[$record.sid] -ne $record.rights) {{ throw 'fixture stage ACL principal or rights differ' }}
}}
foreach ($expectedSid in $expected.Keys) {{
    if (-not $seen.ContainsKey($expectedSid)) {{ throw 'fixture stage ACL is missing a required principal' }}
}}
[ordered]@{{ stage = $stage; protected = $verified.AreAccessRulesProtected; acl = $records }} | ConvertTo-Json -Compress -Depth 3
'''


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or verify a protected Windows fixture stage ACL")
    parser.add_argument("--stage-directory", required=True,
                        help="absolute Windows directory to generate or attest")
    parser.add_argument("--receipt", type=Path, help="guest-stage receipt JSON to validate")
    parser.add_argument("--recipient-sid", required=True, help="exact interactive fixture recipient SID")
    arguments = parser.parse_args()
    if arguments.receipt is None:
        try:
            command = stage_acl_powershell(arguments.stage_directory, arguments.recipient_sid)
        except ValueError as error:
            parser.error(str(error))
        print(command, end="")
        return 0
    try:
        receipt = json.loads(arguments.receipt.read_text(encoding="utf-8"))
        validate_stage_acl_receipt(receipt, arguments.recipient_sid, arguments.stage_directory)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    print("stage ACL receipt is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
