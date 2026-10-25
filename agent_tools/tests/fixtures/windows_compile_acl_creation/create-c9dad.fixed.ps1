# Fixed .NET Framework creation primitive. Source-only until native qualified.
function NewPrivateCompileFile([string]$path,[IO.FileShare]$share){
 $acl=[Security.AccessControl.FileSecurity]::new()
 $acl.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;FA;;;SY)')
 [Security.AccessControl.FileSystemRights]$rights=[Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::Synchronize
 # Apply the actual ACL atomically at CreateNew, not via a write-data-only FD.
 $file=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,$rights,$share,4096,[IO.FileOptions]::None,$acl)
 try{
  $actual=$file.GetAccessControl()
  if(-not $actual.AreAccessRulesProtected -or -not $actual.AreAccessRulesCanonical -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18' -or $actual.GetGroup([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18'){throw 'COMPILE_CREATE_ACL_OWNER'}
  $rules=@($actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules.Count -ne 1 -or $rules[0].IsInherited -or $rules[0].IdentityReference.Value -cne 'S-1-5-18' -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){throw 'COMPILE_CREATE_ACL_RULE'}
  return $file
 }catch{$file.Dispose();throw}
}
