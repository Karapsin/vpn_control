$ErrorActionPreference='Stop'
# Provider admission is literal data plus the live typed export graph. It never
# imports a module, evaluates a manifest, or queries a second command provider.
function Read-PublicNativeManifestStrings($node,[Collections.Generic.List[string]]$values,[int]$depth){
    if($depth -gt 8 -or $null -eq $node){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
    if($node -is [Management.Automation.Language.StatementBlockAst]){
        if($node.Traps.Count -or $node.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
        Read-PublicNativeManifestStrings $node.Statements[0] $values ($depth+1);return
    }
    if($node -is [Management.Automation.Language.PipelineAst]){
        if($node.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
        $element=$node.PipelineElements[0]
        if($element -isnot [Management.Automation.Language.CommandExpressionAst] -or $element.Redirections.Count -or $node.Extent.StartOffset -ne $element.Expression.Extent.StartOffset -or $node.Extent.EndOffset -ne $element.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
        Read-PublicNativeManifestStrings $element.Expression $values ($depth+1);return
    }
    if($node -is [Management.Automation.Language.ArrayExpressionAst]){
        if($node.SubExpression.Traps.Count){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
        foreach($statement in $node.SubExpression.Statements){Read-PublicNativeManifestStrings $statement $values ($depth+1)};return
    }
    if($node -is [Management.Automation.Language.ArrayLiteralAst]){
        foreach($element in $node.Elements){Read-PublicNativeManifestStrings $element $values ($depth+1)};return
    }
    if($node -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}
    $value=[string]$node.Value
    if($values.Count -ge 1024 -or [Text.Encoding]::UTF8.GetByteCount($value) -gt 4096 -or $value.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL_BOUND'}
    $values.Add($value)
}
function Read-PublicNativeUtilityManifest([byte[]]$raw){
    if($raw.Length -lt 1 -or $raw.Length -gt 131072){throw 'PUBLIC_NATIVE_MANIFEST_BOUND'}
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($raw)
    if($text.Length -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
    $tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    if($errors.Count -or $tree.ScriptRequirements -or $null -ne $tree.ParamBlock -or $null -ne $tree.BeginBlock -or $null -ne $tree.ProcessBlock -or $null -ne $tree.DynamicParamBlock -or $tree.UsingStatements.Count -or $null -eq $tree.EndBlock -or $tree.EndBlock.Traps.Count -or -not $tree.EndBlock.Unnamed -or $tree.EndBlock.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}
    $clean=$tree.PSObject.Properties['CleanBlock'];if($null -ne $clean -and $null -ne $clean.Value){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}
    $statement=$tree.EndBlock.Statements[0]
    if($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}
    $expression=$statement.PipelineElements[0]
    if($expression -isnot [Management.Automation.Language.CommandExpressionAst] -or $expression.Redirections.Count -or $expression.Expression -isnot [Management.Automation.Language.HashtableAst] -or $statement.Extent.StartOffset -ne $expression.Expression.Extent.StartOffset -or $statement.Extent.EndOffset -ne $expression.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}
    $pairs=$expression.Expression.KeyValuePairs
    if($pairs.Count -lt 1 -or $pairs.Count -gt 64){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}
    $fields=[Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($pair in $pairs){
        if($pair.Item1 -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}
        $key=[string]$pair.Item1.Value
        if($key -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}
        $values=[Collections.Generic.List[string]]::new()
        Read-PublicNativeManifestStrings $pair.Item2 $values 0
        $fields.Add($key,$values.ToArray())
    }
    foreach($key in @('GUID','ModuleVersion','NestedModules','CmdletsToExport')){if(-not $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_REQUIRED'}}
    if($fields['GUID'].Count -ne 1 -or $fields['ModuleVersion'].Count -ne 1 -or $fields.ContainsKey('ModuleToProcess')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}
    if($fields.ContainsKey('RootModule') -and ($fields['RootModule'].Count -ne 1 -or $fields['RootModule'][0] -cne '')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}
    if($fields['NestedModules'].Count -ne 1 -or $fields['NestedModules'][0] -cne 'Microsoft.PowerShell.Commands.Utility.dll'){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}
    if(-not $fields.ContainsKey('FunctionsToExport') -or $fields['FunctionsToExport'].Count){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$selected=0
    foreach($export in $fields['CmdletsToExport']){
        if($export.Length -eq 0 -or [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($export) -or -not $seen.Add($export)){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}
        if($export -ceq 'Get-FileHash'){$selected++}
    }
    if($selected -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}
    return ,$fields
}
function Assert-PublicNativeUtilityCmdletProvider([Management.Automation.CmdletInfo]$command){
    if($null -eq $command -or $command.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $command.Name -cne 'Get-FileHash' -or $command.ModuleName -cne 'Microsoft.PowerShell.Utility' -or $command.Source -cne 'Microsoft.PowerShell.Utility'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_COMMAND'}
    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)
    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$manifestDirectory=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')
    $manifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psd1'))
    $dllPath=[IO.Path]::GetFullPath([IO.Path]::Combine($providerHome,'Microsoft.PowerShell.Commands.Utility.dll'))
    $module=$command.Module
    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $module.Name -cne 'Microsoft.PowerShell.Utility' -or [string]$module.ModuleType -cne 'Manifest' -or [IO.Path]::GetFullPath($module.Path) -ine $manifestPath -or [string]$module.RootModule -cne ''){throw 'PUBLIC_NATIVE_HASH_PROVIDER_MANIFEST'}
    # Windows FileShare.Read denies concurrent replacement/writes while both
    # files are held. The named metadata and held bytes are checked again.
    $directories=@($providerHome,$modulesPath,$manifestDirectory)
    $directoryStates=@()
    foreach($path in $directories){$info=[IO.DirectoryInfo]::new($path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'};$directoryStates+=,([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}
    $manifestInfo=[IO.FileInfo]::new($manifestPath);$dllInfo=[IO.FileInfo]::new($dllPath)
    foreach($info in @($manifestInfo,$dllInfo)){$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE'}}
    if($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 131072 -or $dllInfo.Length -lt 1 -or $dllInfo.Length -gt 8388608){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE_BOUND'}
    $manifestState=([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes)
    $dllState=([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes)
    $manifestStream=$null;$dllStream=$null;$sha=$null
    try{
        $manifestStream=[IO.File]::Open($manifestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $dllStream=[IO.File]::Open($dllPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if($manifestStream.Length -ne $manifestInfo.Length -or $dllStream.Length -ne $dllInfo.Length){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}
        $raw=[byte[]]::new([int]$manifestStream.Length);$offset=0
        while($offset -lt $raw.Length){$count=$manifestStream.Read($raw,$offset,$raw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'};$offset+=$count}
        if($manifestStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'}
        $sha=[Security.Cryptography.SHA256]::Create();$manifestHash=[Convert]::ToBase64String($sha.ComputeHash($raw));$dllHash=[Convert]::ToBase64String($sha.ComputeHash($dllStream))
        $fields=Read-PublicNativeUtilityManifest $raw
        if($module.Guid -ne [Guid]::Parse($fields['GUID'][0]) -or $module.Version -ne [Version]::Parse($fields['ModuleVersion'][0])){throw 'PUBLIC_NATIVE_HASH_PROVIDER_IDENTITY'}
        $nested=@($module.NestedModules)
        if($nested.Count -ne 1 -or $null -eq $nested[0] -or $nested[0].GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $nested[0] -isnot [Management.Automation.PSModuleInfo] -or [string]$nested[0].ModuleType -cne 'Binary' -or $nested[0].Name -cne 'Microsoft.PowerShell.Commands.Utility' -or [IO.Path]::GetFullPath($nested[0].Path) -ine $dllPath){throw 'PUBLIC_NATIVE_HASH_PROVIDER_NESTED'}
        $type=$command.ImplementingType;$assembly=if($null -ne $type){$type.Assembly}else{$null}
        if($null -eq $type -or $type.FullName -cne 'Microsoft.PowerShell.Commands.GetFileHashCommand' -or $null -eq $assembly -or $assembly.IsDynamic -or [IO.Path]::GetFullPath($assembly.Location) -ine $dllPath -or -not [Object]::ReferenceEquals($nested[0].ImplementingAssembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_ASSEMBLY'}
        # ModuleBase must come from this manifest/nested-provider graph, not
        # merely from an arbitrary directory somewhere below the runtime.
        $baseComparison=if([IO.Path]::DirectorySeparatorChar -eq [char]92){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
        $baseTrim=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
        if([string]::IsNullOrWhiteSpace([string]$module.ModuleBase) -or [string]::IsNullOrWhiteSpace([string]$nested[0].ModuleBase)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}
        $selectedBase=[IO.Path]::GetFullPath([string]$module.ModuleBase).TrimEnd($baseTrim)
        $nestedBase=[IO.Path]::GetFullPath([string]$nested[0].ModuleBase).TrimEnd($baseTrim)
        $manifestBase=[IO.Path]::GetFullPath($manifestDirectory).TrimEnd($baseTrim)
        $assemblyBase=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($dllPath)).TrimEnd($baseTrim)
        if(-not [string]::Equals($nestedBase,$assemblyBase,$baseComparison) -or (-not [string]::Equals($selectedBase,$manifestBase,$baseComparison) -and -not [string]::Equals($selectedBase,$nestedBase,$baseComparison))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}
        $exported=$null;$exportCount=0
        foreach($entry in $module.ExportedCmdlets.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$exported=$entry.Value;$exportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}}}
        if($exportCount -ne 1 -or $null -eq $exported -or $exported.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $exported -isnot [Management.Automation.CmdletInfo] -or $exported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($exported.ImplementingType,$type) -or -not [Object]::ReferenceEquals($exported.ImplementingType.Assembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}
        $manifestStream.Position=0;$dllStream.Position=0
        if([Convert]::ToBase64String($sha.ComputeHash($manifestStream)) -cne $manifestHash -or [Convert]::ToBase64String($sha.ComputeHash($dllStream)) -cne $dllHash){throw 'PUBLIC_NATIVE_HASH_PROVIDER_SOURCE_CHANGED'}
        $manifestInfo.Refresh();$dllInfo.Refresh()
        if(([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes) -cne $manifestState -or ([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes) -cne $dllState){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}
        for($index=0;$index -lt $directories.Count;$index++){$info=[IO.DirectoryInfo]::new($directories[$index]);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $directoryStates[$index]){throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'}}
    }finally{
        try{if($null -ne $sha){$sha.Dispose()}}finally{try{if($null -ne $dllStream){$dllStream.Dispose()}}finally{if($null -ne $manifestStream){$manifestStream.Dispose()}}}
    }
}
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
    # Diagnostic metadata cannot replace the byte-identical refusal below.
    if($name -ceq 'Get-FileHash' -and [IO.Path]::GetFullPath($command.Module.ModuleBase).TrimEnd('\') -ine $utilityRoot){
        try{
            $script:cp117ProviderDiagnosticBytesV2=0
            function Write-PublicNativeProviderLine([string]$line){
                $width=[Text.Encoding]::UTF8.GetByteCount($line)+2
                if($width -gt 16384 -or $script:cp117ProviderDiagnosticBytesV2+$width -gt 262144){throw 'PUBLIC_NATIVE_PROVIDER_OUTPUT_BOUND'}
                $script:cp117ProviderDiagnosticBytesV2+=$width
                [Console]::Out.WriteLine($line)
            }
            function Write-PublicNativeProviderField([string]$field,[string]$value){
                if($field -cnotmatch '^[a-z][a-zA-Z0-9_.]{0,63}$'){throw 'PUBLIC_NATIVE_PROVIDER_FIELD'}
                $raw=[Text.Encoding]::UTF8.GetBytes($value)
                if($raw.Length -gt 4096){throw 'PUBLIC_NATIVE_PROVIDER_FIELD_BOUND'}
                Write-PublicNativeProviderLine ('PUBLIC_NATIVE_PROVIDER_V1:'+$field+':'+([string]$raw.Length)+':'+[Convert]::ToBase64String($raw))
            }
            Write-PublicNativeProviderLine 'PUBLIC_NATIVE_PROVIDER_BEGIN:1:35'
            Write-PublicNativeProviderField 'moduleBaseRaw' ([string]$command.Module.ModuleBase)
            Write-PublicNativeProviderField 'moduleBaseNormalized' ([IO.Path]::GetFullPath($command.Module.ModuleBase).TrimEnd('\'))
            Write-PublicNativeProviderField 'expectedUtilityBaseRaw' ([IO.Path]::Combine([string]$PSHOME,'Modules\Microsoft.PowerShell.Utility'))
            Write-PublicNativeProviderField 'expectedUtilityBaseNormalized' $utilityRoot
            $cp117EffectiveModulePath=[Environment]::GetEnvironmentVariable('PSModulePath',[EnvironmentVariableTarget]::Process)
            Write-PublicNativeProviderField 'psModulePathPresent' ([string]($null -ne $cp117EffectiveModulePath))
            Write-PublicNativeProviderField 'psModulePath' ([string]$cp117EffectiveModulePath)
            Write-PublicNativeProviderField 'psHomeRaw' ([string]$PSHOME)
            Write-PublicNativeProviderField 'psHomeNormalized' ([IO.Path]::GetFullPath([string]$PSHOME))
            Write-PublicNativeProviderField 'psVersion' ([string]$PSVersionTable.PSVersion)
            Write-PublicNativeProviderField 'psEdition' ([string]$PSVersionTable.PSEdition)
            Write-PublicNativeProviderField 'commandName' ([string]$command.Name)
            Write-PublicNativeProviderField 'commandKind' $kind
            Write-PublicNativeProviderField 'commandRuntimeType' $runtimeType
            Write-PublicNativeProviderField 'commandSource' ([string]$command.Source)
            Write-PublicNativeProviderField 'commandModuleName' $moduleName
            Write-PublicNativeProviderField 'moduleName' ([string]$command.Module.Name)
            Write-PublicNativeProviderField 'modulePathRaw' ([string]$command.Module.Path)
            Write-PublicNativeProviderField 'modulePathNormalized' $modulePath
            Write-PublicNativeProviderField 'moduleType' ([string]$command.Module.ModuleType)
            Write-PublicNativeProviderField 'moduleRootModule' ([string]$command.Module.RootModule)
            Write-PublicNativeProviderField 'moduleGuid' ([string]$command.Module.Guid)
            Write-PublicNativeProviderField 'moduleVersion' ([string]$command.Module.Version)
            $functionBlock=$null;$functionModule=$null;$implementingType=$null;$implementingAssembly=$null
            $functionFile='';$functionModulePath='';$functionModuleBase='';$implementingTypeName='';$implementingAssemblyName='';$implementingAssemblyLocation=''
            if($kind -ceq 'Function'){$functionBlock=$command.ScriptBlock;if($null -ne $functionBlock){$functionFile=[string]$functionBlock.File;$functionModule=$functionBlock.Module;if($null -ne $functionModule){$functionModulePath=[string]$functionModule.Path;$functionModuleBase=[string]$functionModule.ModuleBase}}}
            if($kind -ceq 'Cmdlet'){$implementingType=$command.ImplementingType;if($null -ne $implementingType){$implementingTypeName=[string]$implementingType.FullName;$implementingAssembly=$implementingType.Assembly;if($null -ne $implementingAssembly){$implementingAssemblyName=[string]$implementingAssembly.FullName;$implementingAssemblyLocation=[string]$implementingAssembly.Location}}}
            Write-PublicNativeProviderField 'functionBlockPresent' ([string]($null -ne $functionBlock))
            Write-PublicNativeProviderField 'functionScriptBlockFile' $functionFile
            Write-PublicNativeProviderField 'functionModulePresent' ([string]($null -ne $functionModule))
            Write-PublicNativeProviderField 'functionModulePath' $functionModulePath
            Write-PublicNativeProviderField 'functionModuleBase' $functionModuleBase
            Write-PublicNativeProviderField 'cmdletImplementingTypePresent' ([string]($null -ne $implementingType))
            Write-PublicNativeProviderField 'cmdletImplementingType' $implementingTypeName
            Write-PublicNativeProviderField 'cmdletAssemblyPresent' ([string]($null -ne $implementingAssembly))
            Write-PublicNativeProviderField 'cmdletAssemblyName' $implementingAssemblyName
            Write-PublicNativeProviderField 'cmdletAssemblyLocation' $implementingAssemblyLocation
            $utilityManifest=[IO.Path]::GetFullPath([IO.Path]::Combine($utilityRoot,'Microsoft.PowerShell.Utility.psd1'))
            Write-PublicNativeProviderField 'utilityManifestPath' $utilityManifest
            Write-PublicNativeProviderField 'utilityManifestExists' ([string][IO.File]::Exists($utilityManifest))
            Write-PublicNativeProviderField 'runtimeContainmentPrefix' $runtimeRoot
            Write-PublicNativeProviderLine 'PUBLIC_NATIVE_PROVIDER_END:1:35'
        }catch{
            # A diagnostic failure is public and bounded, and never admission.
            try{[Console]::Out.WriteLine('PUBLIC_NATIVE_PROVIDER_DIAGNOSTIC_ERROR:1')}catch{}
        }
    }
    if($name -ceq 'Get-FileHash'){
        if($kind -ceq 'Function'){
            if([IO.Path]::GetFullPath($command.Module.ModuleBase).TrimEnd('\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_HASH_MODULE_RUNTIME'}
        }else{Assert-PublicNativeUtilityCmdletProvider $command}
    }
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
