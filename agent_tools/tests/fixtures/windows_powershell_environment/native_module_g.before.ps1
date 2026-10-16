$ErrorActionPreference='Stop'
$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($null -eq $actor){throw 'PUBLIC_NATIVE_ACTOR_MISSING'}
# A fresh -NoProfile child can begin with Utility loaded. Remove only the
# authentic module from this runtime so both cases actually exercise autoload.
$runtimeRoot=[IO.Path]::GetFullPath([string]$PSHOME).TrimEnd('\')+'\'
$utilityRoot=[IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME,'Modules\Microsoft.PowerShell.Utility')).TrimEnd('\')
if(-not [IO.Directory]::Exists($utilityRoot)){throw 'PUBLIC_NATIVE_UTILITY_ROOT_MISSING'}
$utility=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)
if($utility.Count -gt 8){throw 'PUBLIC_NATIVE_UTILITY_MODULE_COUNT'}
foreach($module in $utility){if($module.Name -cne 'Microsoft.PowerShell.Utility' -or [IO.Path]::GetFullPath($module.ModuleBase).TrimEnd('\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_UTILITY_MODULE_IDENTITY'};Remove-Module -ModuleInfo $module -Force -ErrorAction Stop}
# PUBLIC_COLD_OBSERVATION_BEGIN
$coldBefore=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)
$coldHash=@();foreach($candidate in @(Get-Command -Name 'Get-FileHash*' -ListImported -ErrorAction SilentlyContinue)){if($candidate.Name -ieq 'Get-FileHash'){$coldHash+=,$candidate}}
$coldAfter=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)
[Console]::Out.WriteLine(('PUBLIC_NATIVE_COLD_OBSERVATION:'+([string]$coldBefore.Count)+':'+([string]$coldAfter.Count)+':'+([string]$coldHash.Count)))
if($coldBefore.Count -or $coldAfter.Count -or $coldHash.Count){throw 'PUBLIC_NATIVE_UTILITY_NOT_COLD'}
# PUBLIC_COLD_OBSERVATION_END
[Console]::Out.WriteLine(('PUBLIC_NATIVE_UTILITY_COLD:'+([string]$utility.Count)))
$missing=@();foreach($name in @('Get-Acl','Get-FileHash')){
    try{$commands=@(Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop)}catch{$missing+=,$name;continue}
    if($commands.Count -ne 1){throw 'PUBLIC_NATIVE_COMMAND_COUNT'}
    $command=$commands[0];$kind=[string]$command.CommandType;$moduleName=[string]$command.ModuleName;$runtimeType=$command.GetType().FullName
    $expectedModule=if($name -ceq 'Get-Acl'){'Microsoft.PowerShell.Security'}else{'Microsoft.PowerShell.Utility'}
    if($moduleName -cne $expectedModule -or $null -eq $command.Module){throw 'PUBLIC_NATIVE_COMMAND_MODULE'}
    if(($kind -ceq 'Cmdlet' -and $runtimeType -ceq 'System.Management.Automation.CmdletInfo' -and $command -is [Management.Automation.CmdletInfo]) -or ($kind -ceq 'Function' -and $runtimeType -ceq 'System.Management.Automation.FunctionInfo' -and $command -is [Management.Automation.FunctionInfo])){}else{throw 'PUBLIC_NATIVE_COMMAND_TYPE'}
    $modulePath=[IO.Path]::GetFullPath($command.Module.Path)
    if(-not $modulePath.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($modulePath)){throw 'PUBLIC_NATIVE_COMMAND_RUNTIME'}
    if($name -ceq 'Get-FileHash' -and [IO.Path]::GetFullPath($command.Module.ModuleBase).TrimEnd('\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_HASH_MODULE_RUNTIME'}
    [Console]::Out.WriteLine(('PUBLIC_NATIVE_COMMAND:'+$name+':'+$moduleName+':'+$kind+':'+$runtimeType))
}
if($missing.Count){[Console]::Error.WriteLine(('PUBLIC_NATIVE_MISSING:'+($missing -join ',')));exit 11}
$path=$args[0];$expectedHash=$args[1]
$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$physical=[IO.File]::GetAccessControl($path)
$sections=[Security.AccessControl.AccessControlSections]::All;$sidType=[Security.Principal.SecurityIdentifier]
if($acl.Sddl -cne $physical.GetSecurityDescriptorSddlForm($sections) -or $acl.GetOwner($sidType).Value -cne $physical.GetOwner($sidType).Value){throw 'PUBLIC_NATIVE_ACL_MISMATCH'}
$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if($actualHash -cne $expectedHash){throw 'PUBLIC_NATIVE_HASH_MISMATCH'}
[Console]::Out.WriteLine('PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')
