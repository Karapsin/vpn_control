$stage='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-add035da-53b7-4b5b-8131-38d838a7d840';
$verified = Get-Acl -LiteralPath $stage -ErrorAction Stop
$records = @($verified.Access | ForEach-Object {
    [ordered]@{
        sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        rights = [int]$_.FileSystemRights
        type = $_.AccessControlType.ToString()
        inherited = $_.IsInherited
        inheritance = [int]$_.InheritanceFlags
        propagation = [int]$_.PropagationFlags
    }
})
$expected = @{
    'S-1-5-18' = 2032127
    'S-1-5-32-544' = 2032127
    'S-1-5-21-2404255130-2183793310-3766671872-1002' = 1179817
}
if (-not $verified.AreAccessRulesProtected) { throw 'fixture stage ACL inheritance remains unprotected' }
if ($records.Count -ne $expected.Count) { throw 'fixture stage ACL principal count differs' }
$seen = @{}
foreach ($record in $records) {
    if ($record.type -ne 'Allow' -or $record.inherited -or $record.inheritance -ne 3 -or $record.propagation -ne 0) { throw 'fixture stage ACL entry is unsafe' }
    if ($seen.ContainsKey($record.sid)) { throw 'fixture stage ACL repeats a principal' }
    $seen[$record.sid] = $true
    if (-not $expected.ContainsKey($record.sid) -or $expected[$record.sid] -ne $record.rights) { throw 'fixture stage ACL principal or rights differ' }
}
foreach ($expectedSid in $expected.Keys) {
    if (-not $seen.ContainsKey($expectedSid)) { throw 'fixture stage ACL is missing a required principal' }
}

$stage='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-add035da-53b7-4b5b-8131-38d838a7d840\content';
$verified = Get-Acl -LiteralPath $stage -ErrorAction Stop
$records = @($verified.Access | ForEach-Object {
    [ordered]@{
        sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        rights = [int]$_.FileSystemRights
        type = $_.AccessControlType.ToString()
        inherited = $_.IsInherited
        inheritance = [int]$_.InheritanceFlags
        propagation = [int]$_.PropagationFlags
    }
})
$expected = @{
    'S-1-5-18' = 2032127
    'S-1-5-32-544' = 2032127
    'S-1-5-21-2404255130-2183793310-3766671872-1002' = 1179817
}
if (-not $verified.AreAccessRulesProtected) { throw 'fixture stage ACL inheritance remains unprotected' }
if ($records.Count -ne $expected.Count) { throw 'fixture stage ACL principal count differs' }
$seen = @{}
foreach ($record in $records) {
    if ($record.type -ne 'Allow' -or $record.inherited -or $record.inheritance -ne 3 -or $record.propagation -ne 0) { throw 'fixture stage ACL entry is unsafe' }
    if ($seen.ContainsKey($record.sid)) { throw 'fixture stage ACL repeats a principal' }
    $seen[$record.sid] = $true
    if (-not $expected.ContainsKey($record.sid) -or $expected[$record.sid] -ne $record.rights) { throw 'fixture stage ACL principal or rights differ' }
}
foreach ($expectedSid in $expected.Keys) {
    if (-not $seen.ContainsKey($expectedSid)) { throw 'fixture stage ACL is missing a required principal' }
}

$stage='C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-fixture-add035da-53b7-4b5b-8131-38d838a7d840\server-state';
$verified = Get-Acl -LiteralPath $stage -ErrorAction Stop
$records = @($verified.Access | ForEach-Object {
    [ordered]@{
        sid = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        rights = [int]$_.FileSystemRights
        type = $_.AccessControlType.ToString()
        inherited = $_.IsInherited
        inheritance = [int]$_.InheritanceFlags
        propagation = [int]$_.PropagationFlags
    }
})
$expected = @{
    'S-1-5-18' = 2032127
    'S-1-5-32-544' = 2032127
    'S-1-5-21-2404255130-2183793310-3766671872-1002' = 2032127
}
if (-not $verified.AreAccessRulesProtected) { throw 'fixture stage ACL inheritance remains unprotected' }
if ($records.Count -ne $expected.Count) { throw 'fixture stage ACL principal count differs' }
$seen = @{}
foreach ($record in $records) {
    if ($record.type -ne 'Allow' -or $record.inherited -or $record.inheritance -ne 3 -or $record.propagation -ne 0) { throw 'fixture stage ACL entry is unsafe' }
    if ($seen.ContainsKey($record.sid)) { throw 'fixture stage ACL repeats a principal' }
    $seen[$record.sid] = $true
    if (-not $expected.ContainsKey($record.sid) -or $expected[$record.sid] -ne $record.rights) { throw 'fixture stage ACL principal or rights differ' }
}
foreach ($expectedSid in $expected.Keys) {
    if (-not $seen.ContainsKey($expectedSid)) { throw 'fixture stage ACL is missing a required principal' }
}


if(@(Get-ChildItem $state -Force).Count -ne 0 -or ((@(Get-ChildItem $cp117NewContent -Recurse -File -Force|%{$_.FullName.Substring($cp117NewContent.Length+1)}|Sort-Object)) -join '|') -cne ($expected -join '|')){throw 'COMPLETE_CATALOGUE_DRIFT'}