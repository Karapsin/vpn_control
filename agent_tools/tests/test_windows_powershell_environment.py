"""Actual inert-child controls for the PowerShell fixture environment seam.

Portable children execute this Python runtime and stop the actual retained
caller at its native boundary. A Windows-only control invokes Windows
PowerShell against owned inert files. The original failed module-path value
was not retained; controlled missing-command proof remains distinct from it.
"""
import argparse
import ast
import base64
import builtins
from collections import UserDict
from contextlib import ExitStack, redirect_stdout
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
import uuid

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


PUBLIC_MODULE_PATH = 'PUBLIC inherited module directory'
PUBLIC_SENTINEL = 'PUBLIC environment forwarding sentinel'
ROOT = Path(__file__).resolve().parents[2]
AUTHENTIC_FIXTURE = Path(__file__).parent / 'fixtures/windows_powershell_environment'
AUTHENTIC_BEFORE_SHA256 = '903bcbb3eba1d92e50baec2243ed0788f616942c64a02eb6284aac583a98bb38'
AUTHENTIC_STAGE_SHA256 = 'fb2dab95628f1d03e30711d5bcdd0eb2440ef75c3b2cd900ad5e3ffda09bef05'
NATIVE_C_SCRIPT_SHA256 = '4fc533a02a779ae4c00691837ba95d3077486c53c474e1ba3576deaa978ffe39'
NATIVE_G_SCRIPT_SHA256 = '44adab1cf63866aad566cd49624ef7e23f3e08be20a044341008b10222bd1635'
NATIVE_G_DOCUMENT_SHA256 = '1aea351d4fecee39c7fe330edc65f11bf8381d8f15fa606aa2bcfea84102d6e5'
NATIVE_DOCUMENT_CA1_SHA256 = 'e10c6535655a51c3244f93dfb29c819789bb69247a14e021d850703422080924'
CHILD_OBSERVER = (
    "import json,os;print(json.dumps({"
    "'modulePaths':{key.upper():value for key,value in os.environ.items() "
    "if key.upper()=='PSMODULEPATH'},"
    "'sentinel':os.environ.get('VPN_FIXTURE_ENV_SENTINEL')},sort_keys=True))"
)
NATIVE_MODULE_SCRIPT = "$ErrorActionPreference='Stop'\nfunction ConvertFrom-PublicNativeProviderBytes([byte[]]$raw){\n    if($null -eq $raw -or $raw.Length -lt 1 -or $raw.Length -gt 8388608){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_BOUND'}\n    # Raw bytes are held and hashed by the caller before decoding. Windows\n    # PowerShell manifest output is documented UTF-16LE with an explicit BOM.\n    if($raw.Length -ge 2 -and $raw[0] -eq 255 -and $raw[1] -eq 254){\n        if(($raw.Length-2)%2 -or ($raw.Length -ge 4 -and $raw[2] -eq 0 -and $raw[3] -eq 0)){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'}\n        $text=[Text.UnicodeEncoding]::new($false,$false,$true).GetString($raw,2,$raw.Length-2)\n    }else{\n        if($raw.Length -ge 2 -and $raw[0] -eq 254 -and $raw[1] -eq 255){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'}\n        $text=[Text.UTF8Encoding]::new($false,$true).GetString($raw)\n        if($raw.Length -ge 3 -and $raw[0] -eq 239 -and $raw[1] -eq 187 -and $raw[2] -eq 191){$text=$text.Substring(1)}\n    }\n    if($text.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'}\n    return $text\n}\n# Provider admission is literal data plus the live typed export graph. It never\n# imports a module, evaluates a manifest, or queries a second command provider.\nfunction Read-PublicNativeManifestStrings($node,[Collections.Generic.List[string]]$values,[int]$depth){\n    if($depth -gt 8 -or $null -eq $node){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n    if($node -is [Management.Automation.Language.StatementBlockAst]){\n        if(($null -ne $node.Traps -and $node.Traps.Count) -or $node.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        Read-PublicNativeManifestStrings $node.Statements[0] $values ($depth+1);return\n    }\n    if($node -is [Management.Automation.Language.PipelineAst]){\n        if($node.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        $element=$node.PipelineElements[0]\n        if($element -isnot [Management.Automation.Language.CommandExpressionAst] -or $element.Redirections.Count -or $node.Extent.StartOffset -ne $element.Expression.Extent.StartOffset -or $node.Extent.EndOffset -ne $element.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        Read-PublicNativeManifestStrings $element.Expression $values ($depth+1);return\n    }\n    if($node -is [Management.Automation.Language.ArrayExpressionAst]){\n        if(($null -ne $node.SubExpression.Traps -and $node.SubExpression.Traps.Count)){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        foreach($statement in $node.SubExpression.Statements){Read-PublicNativeManifestStrings $statement $values ($depth+1)};return\n    }\n    if($node -is [Management.Automation.Language.ArrayLiteralAst]){\n        foreach($element in $node.Elements){Read-PublicNativeManifestStrings $element $values ($depth+1)};return\n    }\n    if($node -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n    $value=[string]$node.Value\n    if($values.Count -ge 1024 -or [Text.Encoding]::UTF8.GetByteCount($value) -gt 4096 -or $value.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL_BOUND'}\n    $values.Add($value)\n}\nfunction Read-PublicNativeUtilityManifest([byte[]]$raw){\n    if($raw.Length -lt 1 -or $raw.Length -gt 131072){throw 'PUBLIC_NATIVE_MANIFEST_BOUND'}\n    $text=ConvertFrom-PublicNativeProviderBytes $raw\n    $tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)\n    if($errors.Count -or $tree.ScriptRequirements -or $null -ne $tree.ParamBlock -or $null -ne $tree.BeginBlock -or $null -ne $tree.ProcessBlock -or $null -ne $tree.DynamicParamBlock -or $tree.UsingStatements.Count -or $null -eq $tree.EndBlock -or ($null -ne $tree.EndBlock.Traps -and $tree.EndBlock.Traps.Count) -or -not $tree.EndBlock.Unnamed -or $tree.EndBlock.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $clean=$tree.PSObject.Properties['CleanBlock'];if($null -ne $clean -and $null -ne $clean.Value){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $statement=$tree.EndBlock.Statements[0]\n    if($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $expression=$statement.PipelineElements[0]\n    if($expression -isnot [Management.Automation.Language.CommandExpressionAst] -or $expression.Redirections.Count -or $expression.Expression -isnot [Management.Automation.Language.HashtableAst] -or $statement.Extent.StartOffset -ne $expression.Expression.Extent.StartOffset -or $statement.Extent.EndOffset -ne $expression.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $pairs=$expression.Expression.KeyValuePairs\n    if($pairs.Count -lt 1 -or $pairs.Count -gt 64){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $fields=[Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::OrdinalIgnoreCase)\n    foreach($pair in $pairs){\n        if($pair.Item1 -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}\n        $key=[string]$pair.Item1.Value\n        if($key -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}\n        $values=[Collections.Generic.List[string]]::new()\n        Read-PublicNativeManifestStrings $pair.Item2 $values 0\n        $fields.Add($key,$values.ToArray())\n    }\n    foreach($key in @('GUID','ModuleVersion','NestedModules','CmdletsToExport')){if(-not $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_REQUIRED'}}\n    if($fields['GUID'].Count -ne 1 -or $fields['ModuleVersion'].Count -ne 1 -or $fields.ContainsKey('ModuleToProcess')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}\n    if($fields.ContainsKey('RootModule') -and ($fields['RootModule'].Count -ne 1 -or $fields['RootModule'][0] -cne '')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}\n    if($fields['NestedModules'].Length -lt 1 -or $fields['NestedModules'].Length -gt 2 -or -not $fields.ContainsKey('FunctionsToExport')){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n    $nestedNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)\n    foreach($nestedName in $fields['NestedModules']){\n        if(($nestedName -cne 'Microsoft.PowerShell.Commands.Utility.dll' -and $nestedName -cne 'Microsoft.PowerShell.Utility.psm1') -or -not $nestedNames.Add($nestedName)){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n    }\n    foreach($key in @('CmdletsToExport','FunctionsToExport')){\n        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)\n        foreach($export in $fields[$key]){if($export.Length -eq 0 -or [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($export) -or -not $seen.Add($export)){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}}\n    }\n    return ,$fields\n}\nfunction Assert-PublicNativeUtilityCmdletProvider([Management.Automation.CmdletInfo]$command){\n    if($null -eq $command -or $command.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $command.Name -cne 'Get-FileHash' -or $command.ModuleName -cne 'Microsoft.PowerShell.Utility' -or $command.Source -cne 'Microsoft.PowerShell.Utility'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_COMMAND'}\n    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)\n    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$manifestDirectory=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')\n    $manifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psd1'))\n    $dllPath=[IO.Path]::GetFullPath([IO.Path]::Combine($providerHome,'Microsoft.PowerShell.Commands.Utility.dll'))\n    $module=$command.Module\n    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $module.Name -cne 'Microsoft.PowerShell.Utility' -or [string]$module.ModuleType -cne 'Manifest' -or [IO.Path]::GetFullPath($module.Path) -ine $manifestPath -or [string]$module.RootModule -cne ''){throw 'PUBLIC_NATIVE_HASH_PROVIDER_MANIFEST'}\n    # Windows FileShare.Read denies concurrent replacement/writes while both\n    # files are held. The named metadata and held bytes are checked again.\n    $directories=@($providerHome,$modulesPath,$manifestDirectory)\n    $directoryStates=@()\n    foreach($path in $directories){$info=[IO.DirectoryInfo]::new($path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'};$directoryStates+=,([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}\n    $manifestInfo=[IO.FileInfo]::new($manifestPath);$dllInfo=[IO.FileInfo]::new($dllPath)\n    foreach($info in @($manifestInfo,$dllInfo)){$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE'}}\n    if($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 131072 -or $dllInfo.Length -lt 1 -or $dllInfo.Length -gt 8388608){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE_BOUND'}\n    $manifestState=([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes)\n    $dllState=([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes)\n    $manifestStream=$null;$dllStream=$null;$sha=$null\n    try{\n        $manifestStream=[IO.File]::Open($manifestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        $dllStream=[IO.File]::Open($dllPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        if($manifestStream.Length -ne $manifestInfo.Length -or $dllStream.Length -ne $dllInfo.Length){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}\n        $raw=[byte[]]::new([int]$manifestStream.Length);$offset=0\n        while($offset -lt $raw.Length){$count=$manifestStream.Read($raw,$offset,$raw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'};$offset+=$count}\n        if($manifestStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'}\n        $sha=[Security.Cryptography.SHA256]::Create();$manifestHash=[Convert]::ToBase64String($sha.ComputeHash($raw));$dllHash=[Convert]::ToBase64String($sha.ComputeHash($dllStream))\n        $fields=Read-PublicNativeUtilityManifest $raw\n        if($fields['NestedModules'].Length -ne 1 -or $fields['NestedModules'][0] -cne 'Microsoft.PowerShell.Commands.Utility.dll'){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n        if($fields['FunctionsToExport'].Length -ne 0 -or -not ($fields['CmdletsToExport'] -ccontains 'Get-FileHash')){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}\n        if($module.Guid -ne [Guid]::Parse($fields['GUID'][0]) -or $module.Version -ne [Version]::Parse($fields['ModuleVersion'][0])){throw 'PUBLIC_NATIVE_HASH_PROVIDER_IDENTITY'}\n        $nested=@($module.NestedModules)\n        if($nested.Count -ne 1 -or $null -eq $nested[0] -or $nested[0].GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $nested[0] -isnot [Management.Automation.PSModuleInfo] -or [string]$nested[0].ModuleType -cne 'Binary' -or $nested[0].Name -cne 'Microsoft.PowerShell.Commands.Utility' -or [IO.Path]::GetFullPath($nested[0].Path) -ine $dllPath){throw 'PUBLIC_NATIVE_HASH_PROVIDER_NESTED'}\n        $type=$command.ImplementingType;$assembly=if($null -ne $type){$type.Assembly}else{$null}\n        if($null -eq $type -or $type.FullName -cne 'Microsoft.PowerShell.Commands.GetFileHashCommand' -or $null -eq $assembly -or $assembly.IsDynamic -or [IO.Path]::GetFullPath($assembly.Location) -ine $dllPath -or -not [Object]::ReferenceEquals($nested[0].ImplementingAssembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_ASSEMBLY'}\n        # ModuleBase must come from this manifest/nested-provider graph, not\n        # merely from an arbitrary directory somewhere below the runtime.\n        $baseComparison=if([IO.Path]::DirectorySeparatorChar -eq [char]92){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}\n        $baseTrim=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)\n        if([string]::IsNullOrWhiteSpace([string]$module.ModuleBase) -or [string]::IsNullOrWhiteSpace([string]$nested[0].ModuleBase)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}\n        $selectedBase=[IO.Path]::GetFullPath([string]$module.ModuleBase).TrimEnd($baseTrim)\n        $nestedBase=[IO.Path]::GetFullPath([string]$nested[0].ModuleBase).TrimEnd($baseTrim)\n        $manifestBase=[IO.Path]::GetFullPath($manifestDirectory).TrimEnd($baseTrim)\n        $assemblyBase=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($dllPath)).TrimEnd($baseTrim)\n        if(-not [string]::Equals($nestedBase,$assemblyBase,$baseComparison) -or (-not [string]::Equals($selectedBase,$manifestBase,$baseComparison) -and -not [string]::Equals($selectedBase,$nestedBase,$baseComparison))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}\n        $exported=$null;$exportCount=0\n        foreach($entry in $module.ExportedCmdlets.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$exported=$entry.Value;$exportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}}}\n        if($exportCount -ne 1 -or $null -eq $exported -or $exported.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $exported -isnot [Management.Automation.CmdletInfo] -or $exported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($exported.ImplementingType,$type) -or -not [Object]::ReferenceEquals($exported.ImplementingType.Assembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}\n        $manifestStream.Position=0;$dllStream.Position=0\n        if([Convert]::ToBase64String($sha.ComputeHash($manifestStream)) -cne $manifestHash -or [Convert]::ToBase64String($sha.ComputeHash($dllStream)) -cne $dllHash){throw 'PUBLIC_NATIVE_HASH_PROVIDER_SOURCE_CHANGED'}\n        $manifestInfo.Refresh();$dllInfo.Refresh()\n        if(([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes) -cne $manifestState -or ([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes) -cne $dllState){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}\n        for($index=0;$index -lt $directories.Count;$index++){$info=[IO.DirectoryInfo]::new($directories[$index]);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $directoryStates[$index]){throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'}}\n    }finally{\n        try{if($null -ne $sha){$sha.Dispose()}}finally{try{if($null -ne $dllStream){$dllStream.Dispose()}}finally{if($null -ne $manifestStream){$manifestStream.Dispose()}}}\n    }\n}\nfunction Assert-PublicNativeUtilityFunctionOrigins([string]$manifestPath,[string]$selectedPath,[string]$selectedBase,[string]$scriptPath,[string]$scriptFile,[string]$definingPath,[string]$definingBase,[StringComparison]$comparison){\n    # Inputs are already normalized by the native caller. This is also the\n    # application-controlled decision exercised by retained-field controls.\n    if($comparison -ne [StringComparison]::Ordinal -and $comparison -ne [StringComparison]::OrdinalIgnoreCase){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n    foreach($value in @($manifestPath,$selectedPath,$selectedBase,$scriptPath,$scriptFile,$definingPath,$definingBase)){\n        if([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 32768 -or $value.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n    }\n    if(-not [string]::Equals($selectedPath,$manifestPath,$comparison) -or -not [string]::Equals($scriptFile,$scriptPath,$comparison) -or -not [string]::Equals($definingPath,$scriptPath,$comparison) -or -not [string]::Equals($selectedBase,$definingBase,$comparison)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n}\nfunction Assert-PublicNativeUtilityFunctionProvider([Management.Automation.FunctionInfo]$command){\n    if($null -eq $command -or $command.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $command.Name -cne 'Get-FileHash' -or $command.ModuleName -cne 'Microsoft.PowerShell.Utility' -or $command.Source -cne 'Microsoft.PowerShell.Utility'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_COMMAND'}\n    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)\n    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$manifestDirectory=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')\n    $manifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psd1'))\n    $scriptPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psm1'))\n    $comparison=if([IO.Path]::DirectorySeparatorChar -eq [char]92){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}\n    $baseTrim=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)\n    $module=$command.Module;$block=$command.ScriptBlock\n    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $module.Name -cne 'Microsoft.PowerShell.Utility' -or [string]$module.ModuleType -cne 'Manifest' -or [string]$module.RootModule -cne ''){throw 'PUBLIC_NATIVE_HASH_FUNCTION_MANIFEST'}\n    if($null -eq $block -or $block -isnot [Management.Automation.ScriptBlock] -or $null -eq $block.Module -or $block.Module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $block.Module -isnot [Management.Automation.PSModuleInfo]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_BLOCK'}\n    foreach($path in @([string]$module.Path,[string]$module.ModuleBase,[string]$block.File,[string]$block.Module.Path,[string]$block.Module.ModuleBase)){if([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}}\n    Assert-PublicNativeUtilityFunctionOrigins $manifestPath ([IO.Path]::GetFullPath($module.Path)) ([IO.Path]::GetFullPath($module.ModuleBase).TrimEnd($baseTrim)) $scriptPath ([IO.Path]::GetFullPath($block.File)) ([IO.Path]::GetFullPath($block.Module.Path)) ([IO.Path]::GetFullPath($block.Module.ModuleBase).TrimEnd($baseTrim)) $comparison\n    $directories=@($providerHome,$modulesPath,$manifestDirectory);$directoryStates=@()\n    foreach($path in $directories){$info=[IO.DirectoryInfo]::new($path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DIRECTORY'};$directoryStates+=,([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}\n    $manifestInfo=[IO.FileInfo]::new($manifestPath);$scriptInfo=[IO.FileInfo]::new($scriptPath)\n    foreach($info in @($manifestInfo,$scriptInfo)){$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_HASH_FUNCTION_FILE'}}\n    if($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 131072 -or $scriptInfo.Length -lt 1 -or $scriptInfo.Length -gt 8388608){throw 'PUBLIC_NATIVE_HASH_FUNCTION_FILE_BOUND'}\n    $manifestState=([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes)\n    $scriptState=([string]$scriptInfo.Length+':'+[string]$scriptInfo.CreationTimeUtc.Ticks+':'+[string]$scriptInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$scriptInfo.Attributes)\n    $manifestStream=$null;$scriptStream=$null;$sha=$null\n    try{\n        $manifestStream=[IO.File]::Open($manifestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        $scriptStream=[IO.File]::Open($scriptPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        if($manifestStream.Length -ne $manifestInfo.Length -or $scriptStream.Length -ne $scriptInfo.Length){throw 'PUBLIC_NATIVE_HASH_FUNCTION_GENERATION'}\n        $manifestRaw=[byte[]]::new([int]$manifestStream.Length);$offset=0\n        while($offset -lt $manifestRaw.Length){$count=$manifestStream.Read($manifestRaw,$offset,$manifestRaw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'};$offset+=$count}\n        if($manifestStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'}\n        $scriptRaw=[byte[]]::new([int]$scriptStream.Length);$offset=0\n        while($offset -lt $scriptRaw.Length){$count=$scriptStream.Read($scriptRaw,$offset,$scriptRaw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'};$offset+=$count}\n        if($scriptStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'}\n        $sha=[Security.Cryptography.SHA256]::Create();$manifestHash=[Convert]::ToBase64String($sha.ComputeHash($manifestRaw));$scriptHash=[Convert]::ToBase64String($sha.ComputeHash($scriptRaw))\n        $fields=Read-PublicNativeUtilityManifest $manifestRaw\n        if($module.Guid -ne [Guid]::Parse($fields['GUID'][0]) -or $module.Version -ne [Version]::Parse($fields['ModuleVersion'][0])){throw 'PUBLIC_NATIVE_HASH_FUNCTION_IDENTITY'}\n        if($fields['NestedModules'].Length -ne 2 -or -not ($fields['NestedModules'] -ccontains 'Microsoft.PowerShell.Utility.psm1') -or -not ($fields['NestedModules'] -ccontains 'Microsoft.PowerShell.Commands.Utility.dll') -or -not ($fields['FunctionsToExport'] -ccontains 'Get-FileHash')){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DECLARATION'}\n        $nested=@($module.NestedModules);$scriptNode=$null;$scriptCount=0;$binaryCount=0\n        if($nested.Count -ne 2){throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n        foreach($node in $nested){\n            if($null -eq $node -or $node.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $node -isnot [Management.Automation.PSModuleInfo]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n            if([string]$node.ModuleType -ceq 'Script' -and $node.Name -ceq 'Microsoft.PowerShell.Utility'){$scriptNode=$node;$scriptCount++}\n            elseif([string]$node.ModuleType -ceq 'Binary' -and $node.Name -ceq 'Microsoft.PowerShell.Commands.Utility'){$binaryCount++}\n            else{throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n        }\n        if($scriptCount -ne 1 -or $binaryCount -ne 1 -or -not [Object]::ReferenceEquals($scriptNode,$block.Module)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DEFINING_MODULE'}\n        # The declared script node authenticates the Function provider. Its\n        # genuine ModuleBase is only compared for graph consistency: no path\n        # is derived from it and no unmeasured GAC/DLL layout is assumed.\n        $exported=$null;$exportCount=0\n        foreach($entry in $module.ExportedFunctions.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$exported=$entry.Value;$exportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}}}\n        if($exportCount -ne 1 -or $null -eq $exported -or $exported.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $exported -isnot [Management.Automation.FunctionInfo] -or $exported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($exported.ScriptBlock,$block)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}\n        $nestedExported=$null;$nestedExportCount=0\n        foreach($entry in $scriptNode.ExportedFunctions.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$nestedExported=$entry.Value;$nestedExportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}}}\n        if($nestedExportCount -ne 1 -or $null -eq $nestedExported -or $nestedExported.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $nestedExported -isnot [Management.Automation.FunctionInfo] -or $nestedExported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($nestedExported.ScriptBlock,$block)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}\n        $tokens=$null;$errors=$null;$scriptTree=[Management.Automation.Language.Parser]::ParseInput((ConvertFrom-PublicNativeProviderBytes $scriptRaw),[ref]$tokens,[ref]$errors)\n        if($null -ne $errors -and $errors.Length){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_PARSE'}\n        $definitions=@($scriptTree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ieq 'Get-FileHash'},$true))\n        if($definitions.Count -ne 1 -or $definitions[0].Name -cne 'Get-FileHash' -or $block.Ast -isnot [Management.Automation.Language.ScriptBlockAst] -or $block.Ast.Extent.Text -cne $definitions[0].Body.Extent.Text){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_BODY'}\n        $manifestStream.Position=0;$scriptStream.Position=0\n        if([Convert]::ToBase64String($sha.ComputeHash($manifestStream)) -cne $manifestHash -or [Convert]::ToBase64String($sha.ComputeHash($scriptStream)) -cne $scriptHash){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_CHANGED'}\n        $manifestInfo.Refresh();$scriptInfo.Refresh()\n        if(([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes) -cne $manifestState -or ([string]$scriptInfo.Length+':'+[string]$scriptInfo.CreationTimeUtc.Ticks+':'+[string]$scriptInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$scriptInfo.Attributes) -cne $scriptState){throw 'PUBLIC_NATIVE_HASH_FUNCTION_GENERATION'}\n        for($index=0;$index -lt $directories.Count;$index++){$info=[IO.DirectoryInfo]::new($directories[$index]);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $directoryStates[$index]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DIRECTORY'}}\n    }finally{\n        try{if($null -ne $sha){$sha.Dispose()}}finally{try{if($null -ne $scriptStream){$scriptStream.Dispose()}}finally{if($null -ne $manifestStream){$manifestStream.Dispose()}}}\n    }\n}\n$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($null -eq $actor){throw 'PUBLIC_NATIVE_ACTOR_MISSING'}\n# A fresh -NoProfile child can begin with Utility loaded. Remove only the\n# authentic module from this runtime so both cases actually exercise autoload.\n$runtimeRoot=[IO.Path]::GetFullPath([string]$PSHOME).TrimEnd('\\')+'\\'\n$utilityRoot=[IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME,'Modules\\Microsoft.PowerShell.Utility')).TrimEnd('\\')\nif(-not [IO.Directory]::Exists($utilityRoot)){throw 'PUBLIC_NATIVE_UTILITY_ROOT_MISSING'}\n$utility=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\nif($utility.Count -gt 8){throw 'PUBLIC_NATIVE_UTILITY_MODULE_COUNT'}\nforeach($module in $utility){if($module.Name -cne 'Microsoft.PowerShell.Utility' -or [IO.Path]::GetFullPath($module.ModuleBase).TrimEnd('\\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_UTILITY_MODULE_IDENTITY'};Remove-Module -ModuleInfo $module -Force -ErrorAction Stop}\n# PUBLIC_COLD_OBSERVATION_BEGIN\n$coldBefore=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\n$coldHash=@();foreach($candidate in @(Get-Command -Name 'Get-FileHash*' -ListImported -ErrorAction SilentlyContinue)){if($candidate.Name -ieq 'Get-FileHash'){$coldHash+=,$candidate}}\n$coldAfter=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\n[Console]::Out.WriteLine(('PUBLIC_NATIVE_COLD_OBSERVATION:'+([string]$coldBefore.Count)+':'+([string]$coldAfter.Count)+':'+([string]$coldHash.Count)))\nif($coldBefore.Count -or $coldAfter.Count -or $coldHash.Count){throw 'PUBLIC_NATIVE_UTILITY_NOT_COLD'}\n# PUBLIC_COLD_OBSERVATION_END\n[Console]::Out.WriteLine(('PUBLIC_NATIVE_UTILITY_COLD:'+([string]$utility.Count)))\n$missing=@();foreach($name in @('Get-Acl','Get-FileHash')){\n    try{$commands=@(Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop)}catch{$missing+=,$name;continue}\n    if($commands.Count -ne 1){throw 'PUBLIC_NATIVE_COMMAND_COUNT'}\n    $command=$commands[0];$kind=[string]$command.CommandType;$moduleName=[string]$command.ModuleName;$runtimeType=$command.GetType().FullName\n    $expectedModule=if($name -ceq 'Get-Acl'){'Microsoft.PowerShell.Security'}else{'Microsoft.PowerShell.Utility'}\n    if($moduleName -cne $expectedModule -or $null -eq $command.Module){throw 'PUBLIC_NATIVE_COMMAND_MODULE'}\n    if(($kind -ceq 'Cmdlet' -and $runtimeType -ceq 'System.Management.Automation.CmdletInfo' -and $command -is [Management.Automation.CmdletInfo]) -or ($kind -ceq 'Function' -and $runtimeType -ceq 'System.Management.Automation.FunctionInfo' -and $command -is [Management.Automation.FunctionInfo])){}else{throw 'PUBLIC_NATIVE_COMMAND_TYPE'}\n    $modulePath=[IO.Path]::GetFullPath($command.Module.Path)\n    if(-not $modulePath.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($modulePath)){throw 'PUBLIC_NATIVE_COMMAND_RUNTIME'}\n    if($name -ceq 'Get-FileHash'){\n        if($kind -ceq 'Function'){Assert-PublicNativeUtilityFunctionProvider $command}else{Assert-PublicNativeUtilityCmdletProvider $command}\n    }\n    [Console]::Out.WriteLine(('PUBLIC_NATIVE_COMMAND:'+$name+':'+$moduleName+':'+$kind+':'+$runtimeType))\n}\nif($missing.Count){[Console]::Error.WriteLine(('PUBLIC_NATIVE_MISSING:'+($missing -join ',')));exit 11}\n$path=$args[0];$expectedHash=$args[1]\n$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$physical=[IO.File]::GetAccessControl($path)\n$sections=[Security.AccessControl.AccessControlSections]::All;$sidType=[Security.Principal.SecurityIdentifier]\nif($acl.Sddl -cne $physical.GetSecurityDescriptorSddlForm($sections) -or $acl.GetOwner($sidType).Value -cne $physical.GetOwner($sidType).Value){throw 'PUBLIC_NATIVE_ACL_MISMATCH'}\n$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()\nif($actualHash -cne $expectedHash){throw 'PUBLIC_NATIVE_HASH_MISMATCH'}\n[Console]::Out.WriteLine('PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')\n"

NATIVE_COLD_F_BEFORE = "if(@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop).Count -or @(Get-Command -Name Get-FileHash -ListImported -ErrorAction SilentlyContinue).Count){throw 'PUBLIC_NATIVE_UTILITY_NOT_COLD'}\n"
NATIVE_COLD_F_BEFORE_SHA256 = '13ca824a7a3b5ba08f5940e6758803e89c49131081fc836ea5d1ccd3660c5b12'


def _emit_native_public_json(value):
    """One bounded public diagnostic line; never an execution receipt."""
    line = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:' + json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(line.encode('utf-8', errors='strict')) + 1 > 16384:
        raise ValueError('native-public-line-bound')
    print(line, flush=True)


def emit_native_capture_marker(case, stdout, stderr, returncode, *, stdout_eof,
                               stderr_eof, completed_process_returned, source_closing):
    """Retain exact existing controlled streams in ordered bounded chunks."""
    if type(case) is not str or case not in ('bad_module_path', 'sanitized', 'exact_c', 'unfixed_g'):
        raise ValueError('native-public-case')
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError('native-public-stream-type')
    flags = (stdout_eof, stderr_eof, completed_process_returned, source_closing)
    if any(type(value) is not bool for value in flags):
        raise ValueError('native-public-terminal-type')
    if completed_process_returned:
        if (type(returncode) is not int or not -(2 ** 31) <= returncode < 2 ** 32
                or not stdout_eof or not stderr_eof or not source_closing):
            raise ValueError('native-public-terminal-closure')
    elif returncode is not None or stdout_eof or stderr_eof or source_closing:
        raise ValueError('native-public-terminal-closure')
    capture_id = uuid.uuid4().hex
    streams = {'stdout': stdout, 'stderr': stderr}
    summaries = {name: {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest(),
                        'chunks': (len(value) + 8191) // 8192}
                 for name, value in streams.items()}
    _emit_native_public_json(
        {'schemaVersion': 1, 'kind': 'capture', 'captureId': capture_id, 'case': case,
         'returncode': returncode, 'stdoutEof': stdout_eof, 'stderrEof': stderr_eof,
         'completedProcessReturned': completed_process_returned, 'sourceClosing': source_closing,
         'stdout': summaries['stdout'], 'stderr': summaries['stderr']})
    for name, value in streams.items():
        summary = summaries[name]
        for index in range(summary['chunks']):
            offset = index * 8192
            chunk = value[offset:offset + 8192]
            _emit_native_public_json(
                {'schemaVersion': 1, 'kind': 'streamChunk', 'captureId': capture_id,
                 'case': case, 'stream': name, 'chunkIndex': index,
                 'chunkCount': summary['chunks'], 'rawOffset': offset,
                 'bytes': len(chunk), 'chunkSha256': hashlib.sha256(chunk).hexdigest(),
                 'streamBytes': summary['bytes'], 'streamSha256': summary['sha256'],
                 'base64': base64.b64encode(chunk).decode('ascii')})
    return capture_id


def emit_native_causal_marker(proof):
    """Emit the existing persisted proof unchanged inside a fixed envelope."""
    flags = ('sourceClosing', 'allThreeCompletedProcessReturned', 'allThreeStdoutEof',
             'allThreeStderrEof', 'historicalCActualCommandTypeStillUnknown',
             'sameSanitizedEnvironment', 'sameOwnedDataBytesAndHash',
             'sameOwnedDataFileArgument', 'physicalAclAndHashOracleCompleted')
    keys = {'schemaVersion', 'state', 'cExit', 'correctedExit', 'observedHashCommand', 'cMissing', *flags}
    if (type(proof) is not dict or set(proof) != keys
            or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
            or proof['state'] != 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN'
            or type(proof['cExit']) is not int or proof['cExit'] != 11
            or type(proof['correctedExit']) is not int or proof['correctedExit'] != 0
            or any(type(proof[key]) is not bool or proof[key] is not True for key in flags)):
        raise ValueError('native-public-proof-schema')
    expected_command = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                        'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
    if (type(proof['observedHashCommand']) is not dict
            or proof['observedHashCommand'] != expected_command
            or any(type(value) is not str for value in proof['observedHashCommand'].values())
            or type(proof['cMissing']) is not tuple
            or proof['cMissing'] not in (('Get-FileHash',), ('Get-Acl', 'Get-FileHash'))):
        raise ValueError('native-public-proof-observation')
    _emit_native_public_json({'schemaVersion': 1, 'kind': 'causalProof', 'proof': proof})


def emit_native_g_causal_marker(proof):
    """Distinct exact-G proof; never admit it through the strict exact-C codec."""
    flags = ('sourceClosing', 'allThreeCompletedProcessReturned', 'allThreeStdoutEof',
             'allThreeStderrEof', 'sameSanitizedEnvironment', 'sameOwnedDataBytesAndHash',
             'sameOwnedDataFileArgument', 'physicalAclAndHashOracleCompleted',
             'exactCProofSeparate')
    keys = {'schemaVersion', 'state', 'gExit', 'correctedExit', 'gGuard', 'gSourceSha256',
            'gSourceBytes', 'correctedSourceSha256', 'dataSha256', 'observedHashCommand', *flags}
    if (type(proof) is not dict or set(proof) != keys
            or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
            or type(proof['state']) is not str
            or proof['state'] != 'EXACT_G_PROVIDER_GUARD_RED_CORRECTED_PHYSICAL_ORACLE_GREEN'
            or type(proof['gExit']) is not int or proof['gExit'] != 1
            or type(proof['correctedExit']) is not int or proof['correctedExit'] != 0
            or type(proof['gGuard']) is not str or proof['gGuard'] != 'PUBLIC_NATIVE_HASH_MODULE_RUNTIME'
            or type(proof['gSourceSha256']) is not str or proof['gSourceSha256'] != NATIVE_G_SCRIPT_SHA256
            or type(proof['gSourceBytes']) is not int or proof['gSourceBytes'] != 3981
            or any(type(proof[key]) is not bool or proof[key] is not True for key in flags)):
        raise ValueError('native-public-g-proof-schema')
    for key in ('correctedSourceSha256', 'dataSha256'):
        value = proof[key]
        if type(value) is not str or len(value) != 64 or set(value) - set('0123456789abcdef'):
            raise ValueError('native-public-g-proof-source')
    expected = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
    if (type(proof['observedHashCommand']) is not dict or proof['observedHashCommand'] != expected
            or any(type(value) is not str for value in proof['observedHashCommand'].values())):
        raise ValueError('native-public-g-proof-observation')
    _emit_native_public_json({'schemaVersion': 1, 'kind': 'gProviderCausalProof', 'proof': proof})


def native_c_before_script():
    """Read the exact retained C script; it is evidence, not executable Python."""
    from agent_tools import source_module_loader
    path = (AUTHENTIC_FIXTURE / 'native_module_script_c.before.ps1').resolve()
    with source_module_loader._bootstrap_source(path) as (raw, closing):
        if hashlib.sha256(raw).hexdigest() != NATIVE_C_SCRIPT_SHA256:
            raise ValueError('native-command-c-before-source')
        script = raw.decode('utf-8', errors='strict')
        closing()
        return script


def modeled_native_precheck_missing(script, observations):
    """Execute the exact source-selected CommandType filter on typed facts.

    This portable model neither runs PowerShell nor predicts autoload, native
    command availability, module provenance, ACLs, or file hashing. Native
    observations and the physical oracle remain required on Windows.
    """
    marker = 'Get-Command -Name $name -CommandType '
    if type(script) is not str or script.count(marker) != 1:
        raise ValueError('native-command-model-selector')
    selected, separator, unused = script.split(marker, 1)[1].partition(' -ErrorAction Stop')
    if not separator or selected not in ('Cmdlet', 'Cmdlet,Function'):
        raise ValueError('native-command-model-selector')
    allowed_types = tuple(selected.split(','))
    if type(observations) is not tuple:
        raise ValueError('native-command-model-observations')
    by_name = {}
    expected = {'Get-Acl': 'Microsoft.PowerShell.Security',
                'Get-FileHash': 'Microsoft.PowerShell.Utility'}
    for observation in observations:
        if (type(observation) is not dict
                or set(observation) != {'name', 'moduleName', 'commandType', 'runtimeType'}
                or any(type(value) is not str for value in observation.values())):
            raise ValueError('native-command-model-observation')
        name, kind = observation['name'], observation['commandType']
        if (name not in expected or name in by_name
                or observation['moduleName'] != expected[name]
                or kind not in ('Cmdlet', 'Function')
                or observation['runtimeType'] != 'System.Management.Automation.' + kind + 'Info'):
            raise ValueError('native-command-model-observation')
        by_name[name] = observation
    return tuple(name for name in expected
                 if name not in by_name or by_name[name]['commandType'] not in allowed_types)


def native_command_observations(stdout):
    """Strictly decode bounded public facts from the actual native child."""
    if type(stdout) is not bytes or len(stdout) > 4096:
        raise ValueError('native-command-observation-bound')
    lines = stdout.decode('ascii', errors='strict').splitlines()
    cold = None
    if lines and lines[0].startswith('PUBLIC_NATIVE_COLD_OBSERVATION:'):
        fields = lines.pop(0).split(':')
        if (len(fields) != 4 or any(value not in tuple(str(index) for index in range(9))
                                    for value in fields[1:])):
            raise ValueError('native-command-cold-observation')
        cold = tuple(int(value) for value in fields[1:])
        if cold != (0, 0, 0):
            raise ValueError('native-command-not-cold')
    if not lines or not lines[0].startswith('PUBLIC_NATIVE_UTILITY_COLD:'):
        raise ValueError('native-command-utility-observation')
    loaded = lines.pop(0).removeprefix('PUBLIC_NATIVE_UTILITY_COLD:')
    if loaded not in tuple(str(index) for index in range(9)):
        raise ValueError('native-command-utility-observation')
    passed = bool(lines and lines[-1] == 'PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')
    if passed:
        lines.pop()
    observations = []
    for line in lines:
        fields = line.split(':')
        if len(fields) != 5 or fields[0] != 'PUBLIC_NATIVE_COMMAND':
            raise ValueError('native-command-observation-schema')
        observations.append(dict(zip(('name', 'moduleName', 'commandType', 'runtimeType'), fields[1:])))
    facts = tuple(observations)
    modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT, facts)
    if [item['name'] for item in facts] not in ([], ['Get-Acl'], ['Get-FileHash'], ['Get-Acl', 'Get-FileHash']):
        raise ValueError('native-command-observation-order')
    return {'utilityModulesUnloaded': int(loaded), 'commands': facts, 'oraclePassed': passed,
            'coldObservation': cold}


class NativeCommandDiscoveryModelPositive(unittest.TestCase):
    """Portable typed Function filter model; no native result is implied."""
    script = NATIVE_MODULE_SCRIPT

    def test_exact_source_selected_precheck_accepts_typed_function_model(self):
        self.observations = (
            {'name': 'Get-Acl', 'moduleName': 'Microsoft.PowerShell.Security',
             'commandType': 'Cmdlet', 'runtimeType': 'System.Management.Automation.CmdletInfo'},
            {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
             'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
        )
        self.missing = modeled_native_precheck_missing(self.script, self.observations)
        self.assertEqual(self.missing, (), 'NATIVE_FUNCTION_DISCOVERY_MUST_BE_ACCEPTED')


def legacy_copied_environment(executable, inherited):
    """Model of copied-environment passthrough; not a native execution model."""
    return dict(inherited)


def observed_child_environment(factory, executable, key='PsMoDuLePaTh'):
    """Observe the actual child env without changing the real parent env."""
    parent_before = dict(os.environ)
    inherited = {name: value for name, value in parent_before.items()
                 if name.casefold() != 'psmodulepath'}
    inherited[key] = PUBLIC_MODULE_PATH
    inherited['VPN_FIXTURE_ENV_SENTINEL'] = PUBLIC_SENTINEL
    supplied_before = dict(inherited)
    child_environment = factory(executable, inherited)
    if inherited != supplied_before or dict(os.environ) != parent_before:
        raise AssertionError('parent-environment-mutated')
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD_OBSERVER],
                               env=child_environment, capture_output=True,
                               text=True, timeout=20, check=False)
    if completed.returncode != 0:
        raise AssertionError({'exit': completed.returncode, 'stdout': completed.stdout,
                              'stderr': completed.stderr})
    if completed.stderr or inherited != supplied_before or dict(os.environ) != parent_before:
        raise AssertionError('child-environment-observation-not-closed')
    value = json.loads(completed.stdout)
    if type(value) is not dict or set(value) != {'modulePaths', 'sentinel'}:
        raise AssertionError('child-environment-observation-schema')
    return value


def authentic_native_owner_boundary(before):
    """Run the genuine unwrapped method only up to its native-call boundary."""
    from agent_tools import source_module_loader
    before_path = (AUTHENTIC_FIXTURE / 'native_owner.before.source').resolve()
    current_path = ROOT / 'agent_tools/tests/test_windows_tertiary_guest_stage.py'
    stage_path = ROOT / 'agent_tools/windows_tertiary_guest_stage.py'
    with ExitStack() as held:
        sources = {path: held.enter_context(source_module_loader._bootstrap_source(path))
                   for path in (before_path, current_path, stage_path)}
        if (hashlib.sha256(sources[before_path][0]).hexdigest() != AUTHENTIC_BEFORE_SHA256
                or hashlib.sha256(sources[stage_path][0]).hexdigest() != AUTHENTIC_STAGE_SHA256):
            raise ValueError('authentic-environment-source-changed')
        path = before_path if before else current_path
        tree = ast.parse(sources[path][0])
        imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                    not imports and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                imports.append(node)
            else:
                break
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'NativeTargetOwnerTests']
        if len(classes) != 1:
            raise ValueError('authentic-environment-method-identity')
        namespace = {'__name__': 'owned_native_owner_boundary', '__file__': str(path)}
        class BoundaryReached(BaseException):
            pass
        def boundary_run(argv, **options):
            stage = namespace['stage']
            generator = inspect.unwrap(stage.target_owner_probe_script)
            if (Path(stage.__file__).resolve() != stage_path or generator.__globals__ is not vars(stage)
                    or generator.__code__.co_filename != str(stage_path)):
                raise ValueError('authentic-stage-generator-identity')
            for unused, guard in sources.values():
                guard()
            script = generator()
            if argv != ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script]:
                raise ValueError('authentic-native-call-changed')
            observed = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD_OBSERVER],
                                      env=options.get('env'), capture_output=True,
                                      text=True, timeout=20, check=False)
            if observed.returncode or observed.stderr:
                raise AssertionError((observed.returncode, observed.stdout, observed.stderr))
            raise BoundaryReached({'environment': json.loads(observed.stdout),
                                   'scriptSha256': hashlib.sha256(script.encode()).hexdigest(),
                                   'methodFilename': str(path), 'environmentExplicit': 'env' in options,
                                   'nativePowerShellExecuted': False, 'stoppedBeforeNativeAssertions': True})
        view = types.ModuleType('subprocess')
        view.__getattr__ = lambda name: getattr(subprocess, name)
        view.run = boundary_run
        def importing(name, globals=None, locals=None, fromlist=(), level=0):
            if name == 'subprocess' and level == 0:
                return view
            return builtins.__import__(name, globals, locals, fromlist, level)
        namespace['__builtins__'] = {**vars(builtins), '__import__': importing}
        exec(compile(ast.Module(body=[*imports, classes[0]], type_ignores=[]),
                     str(path), 'exec', dont_inherit=True), namespace)
        method = inspect.unwrap(namespace['NativeTargetOwnerTests'].
                                test_actual_windows_creation_time_owner_and_inherited_custody)
        if method.__globals__ is not namespace or method.__code__.co_filename != str(path):
            raise ValueError('authentic-method-source-binding')
        try:
            method(unittest.TestCase())
        except BoundaryReached as stopped:
            answer = stopped.args[0]
        else:
            raise AssertionError('authentic-native-boundary-not-reached')
        for unused, guard in sources.values():
            guard()
        answer['sourceClosing'] = True
        return answer


class AuthenticNativeOwnerEnvironmentPositive(unittest.TestCase):
    before = False

    def test_actual_native_owner_method_forwards_its_environment(self):
        parent_before = dict(os.environ)
        environment = {key: value for key, value in parent_before.items()
                       if key.casefold() != 'psmodulepath'}
        environment.update(PsMoDuLePaTh=PUBLIC_MODULE_PATH, VPN_FIXTURE_ENV_SENTINEL=PUBLIC_SENTINEL)
        wrapper = ("import json,sys;sys.path.insert(0,sys.argv[1]);"
                   "from agent_tools.tests.test_windows_powershell_environment import authentic_native_owner_boundary;"
                   "print(json.dumps(authentic_native_owner_boundary(sys.argv[2]=='before'),sort_keys=True))")
        # Isolated mode ignores inherited PYTHONPYCACHEPREFIX; select a fresh
        # cache explicitly so another Python patch's valid-tag cache is absent.
        with tempfile.TemporaryDirectory(prefix='native-owner-boundary-cache-') as temporary:
            cache = Path(temporary) / 'pycache'
            cache.mkdir(mode=0o700)
            self.assertEqual(list(cache.iterdir()), [])
            child = subprocess.run([sys.executable, '-I', '-B', '-X',
                                    'pycache_prefix=' + str(cache), '-c', wrapper, str(ROOT),
                                    'before' if self.before else 'current'], env=environment,
                                   capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(child.returncode, 0, (child.stdout, child.stderr))
        self.assertEqual(child.stderr, '')
        self.assertEqual(dict(os.environ), parent_before)
        self.observation = json.loads(child.stdout)
        self.assertIs(self.observation['sourceClosing'], True)
        self.assertIs(self.observation['nativePowerShellExecuted'], False)
        self.assertIs(self.observation['stoppedBeforeNativeAssertions'], True)
        self.assertEqual(self.observation['environment']['sentinel'], PUBLIC_SENTINEL)
        self.assertEqual(self.observation['environment']['modulePaths'], {},
                         'AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH')


class WindowsPowerShellEnvironmentPositive(unittest.TestCase):
    environment_factory = staticmethod(windows_powershell_environment)

    def test_windows_powershell_child_rebuilds_its_module_path(self):
        actual = observed_child_environment(self.environment_factory, 'powershell.exe')
        self.assertEqual(actual['sentinel'], PUBLIC_SENTINEL)
        self.assertEqual(actual['modulePaths'], {},
                         'PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL')


class WindowsPowerShellEnvironmentTests(unittest.TestCase):
    def test_exact_c_selector_typed_function_model_red_then_current_green(self):
        cases = []
        for script in (native_c_before_script(), NATIVE_MODULE_SCRIPT):
            case = NativeCommandDiscoveryModelPositive(
                'test_exact_source_selected_precheck_accepts_typed_function_model')
            case.script = script
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('NATIVE_FUNCTION_DISCOVERY_MUST_BE_ACCEPTED', old.failures[0][1])
        self.assertEqual(old_case.missing, ('Get-FileHash',))
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observations, current_case.observations)

    def test_typed_filter_model_refuses_malformed_facts_and_unknown_selector(self):
        valid = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                 'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
        for wrong in (None, [], ({},), ({**valid, 'commandType': True},),
                      ({**valid, 'commandType': 'Alias'},), ({**valid, 'moduleName': 'PUBLIC foreign'},),
                      ({**valid, 'runtimeType': 'System.Management.Automation.CmdletInfo'},), (valid, valid)):
            with self.subTest(observations=wrong):
                with self.assertRaisesRegex(ValueError, '^native-command-model-observation'):
                    modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT, wrong)
        for wrong in ('', NATIVE_MODULE_SCRIPT.replace('Cmdlet,Function -ErrorAction Stop',
                                                      'All -ErrorAction Stop', 1)):
            with self.subTest(selector=wrong):
                with self.assertRaisesRegex(ValueError, '^native-command-model-selector$'):
                    modeled_native_precheck_missing(wrong, (valid,))

    def test_only_exact_windows_runtime_basenames_remove_all_key_spellings(self):
        inherited = UserDict({'PSModulePath': 'PUBLIC one', 'PsMoDuLePaTh': 'PUBLIC two',
                              'PSMODULEPATH': 'PUBLIC three', 'OTHER': 'PUBLIC unchanged',
                              'EMPTY_VALUE': ''})
        original = dict(inherited)
        for executable in ('powershell', 'powershell.exe', 'POWERSHELL.EXE',
                           'public/runtime/powershell', r'public\runtime\powershell.exe',
                           r'public\runtime with spaces\PoWeRsHeLl.ExE'):
            with self.subTest(executable=executable):
                actual = windows_powershell_environment(executable, inherited)
                self.assertIs(type(actual), dict)
                self.assertEqual(actual, {'OTHER': 'PUBLIC unchanged', 'EMPTY_VALUE': ''})
                self.assertEqual(dict(inherited), original)

    def test_actual_child_receives_alias_cleanup_and_other_runtime_passthrough(self):
        for key in ('PSModulePath', 'PsMoDuLePaTh'):
            with self.subTest(key=key):
                actual = observed_child_environment(windows_powershell_environment,
                                                    'public/runtime/powershell', key)
                self.assertEqual(actual, {'modulePaths': {}, 'sentinel': PUBLIC_SENTINEL})
        for executable in ('pwsh', r'public\runtime\pwsh.exe', 'other-public-runtime'):
            with self.subTest(executable=executable):
                actual = observed_child_environment(windows_powershell_environment, executable)
                self.assertEqual(actual, {'modulePaths': {'PSMODULEPATH': PUBLIC_MODULE_PATH},
                                          'sentinel': PUBLIC_SENTINEL})

    def test_absent_module_path_still_returns_an_independent_copy(self):
        inherited = {'OTHER': 'PUBLIC unchanged'}
        for executable in ('powershell', 'pwsh.exe'):
            with self.subTest(executable=executable):
                actual = windows_powershell_environment(executable, inherited)
                self.assertEqual(actual, inherited)
                self.assertIsNot(actual, inherited)
                actual['OTHER'] = 'PUBLIC modified copy'
                self.assertEqual(inherited, {'OTHER': 'PUBLIC unchanged'})

    def test_malformed_inputs_refuse_without_mutating_parent_or_mapping(self):
        parent_before = dict(os.environ)
        inherited = {'PSModulePath': PUBLIC_MODULE_PATH, 'OTHER': 'PUBLIC unchanged'}
        for executable in (None, True, 1, b'powershell', Path('powershell'), '', 'power\0shell'):
            with self.subTest(executable=repr(executable)):
                with self.assertRaisesRegex(ValueError, '^windows-powershell-executable$'):
                    windows_powershell_environment(executable, inherited)
        for malformed in (None, [], [('PSModulePath', PUBLIC_MODULE_PATH)],
                          {1: 'PUBLIC'}, {'PUBLIC': 1}, {'': 'PUBLIC'},
                          {'PUBLIC\0KEY': 'PUBLIC'}, {'PUBLIC': 'PUBLIC\0VALUE'}):
            with self.subTest(kind=repr(malformed)):
                with self.assertRaisesRegex(ValueError, '^windows-powershell-environment$'):
                    windows_powershell_environment('powershell.exe', malformed)
        self.assertEqual(inherited, {'PSModulePath': PUBLIC_MODULE_PATH, 'OTHER': 'PUBLIC unchanged'})
        self.assertEqual(dict(os.environ), parent_before)

    def test_same_actual_child_positive_is_passthrough_red_then_current_green(self):
        observations = []
        for factory in (legacy_copied_environment, windows_powershell_environment):
            case = WindowsPowerShellEnvironmentPositive('test_windows_powershell_child_rebuilds_its_module_path')
            case.environment_factory = factory
            result = unittest.TestResult()
            case.run(result)
            observations.append(result)
        old, current = observations
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)),
                         (1, 1, 0, 0))
        self.assertIn('PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)),
                         (1, 0, 0, 0))

    def test_actual_preserved_native_owner_method_red_then_current_green(self):
        cases = []
        for before in (True, False):
            case = AuthenticNativeOwnerEnvironmentPositive('test_actual_native_owner_method_forwards_its_environment')
            case.before = before
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observation['scriptSha256'], current_case.observation['scriptSha256'])
        self.assertIs(old_case.observation['environmentExplicit'], False)
        self.assertIs(current_case.observation['environmentExplicit'], True)


@unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell module/ACL/hash control')
class NativeWindowsPowerShellEnvironmentTests(unittest.TestCase):
    def test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete(self):
        # The two distinct causal proofs use separate exact retained programs,
        # one sanitized environment, and one unchanged physical data file.
        # Portable inherited-environment coverage remains separate.
        executable = shutil.which('powershell.exe')
        self.assertIsNotNone(executable, 'Windows requires the real PowerShell module/ACL/hash control')
        public = b'PUBLIC native module byte oracle\r\n'
        digest = hashlib.sha256(public).hexdigest()
        corrected_raw = NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')
        parent_before = dict(os.environ)
        from agent_tools import source_module_loader
        c_path = (AUTHENTIC_FIXTURE / 'native_module_script_c.before.ps1').resolve()
        g_path = (AUTHENTIC_FIXTURE / 'native_module_g.before.ps1').resolve()
        runtime = ROOT / '.runtime'
        runtime.mkdir(mode=0o700, exist_ok=True)
        evidence = Path(tempfile.mkdtemp(prefix='windows-powershell-native-c-g-', dir=str(runtime)))

        def preserve(name, value):
            fd = os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())

        def document(name, value):
            preserve(name, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'))
            if name == 'causal-proof.private.json':
                emit_native_causal_marker(value)
            elif name == 'g-causal-proof.private.json':
                emit_native_g_causal_marker(value)

        with tempfile.TemporaryDirectory(prefix='windows-native-module-path-') as directory, \
                source_module_loader._bootstrap_source(c_path) as (c_raw, c_closing), \
                source_module_loader._bootstrap_source(g_path) as (g_raw, g_closing):
            self.assertEqual((len(c_raw), hashlib.sha256(c_raw).hexdigest()), (1076, NATIVE_C_SCRIPT_SHA256))
            self.assertEqual((len(g_raw), hashlib.sha256(g_raw).hexdigest()), (3981, NATIVE_G_SCRIPT_SHA256))
            owned = Path(directory)
            empty_modules = owned / 'empty-modules'
            empty_modules.mkdir(mode=0o700)
            data = owned / 'PUBLIC.bytes'
            with data.open('xb') as stream:
                stream.write(public)
            preserve('PUBLIC.bytes', public)
            inherited = {key: value for key, value in parent_before.items() if key.casefold() != 'psmodulepath'}
            inherited['PSModulePath'] = str(empty_modules)
            supplied_before = dict(inherited)
            sanitized_environment = windows_powershell_environment(executable, inherited)
            self.assertEqual(inherited, supplied_before)
            self.assertEqual(dict(os.environ), parent_before)
            records = []

            def run_owned(label, raw, environment):
                # Every child has one saved intent. A timeout/unknown result is
                # persisted and raised; there is no retry or fallback submission.
                case = owned / label
                case.mkdir(mode=0o700)
                script = case / 'control.ps1'
                carrier = b'\xef\xbb\xbf' + raw
                with script.open('xb') as stream:
                    stream.write(carrier)
                preserve(label + '.control.ps1', carrier)
                argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                        str(script), str(data), digest]
                self.assertLessEqual(sum(len(part.encode('utf-8', errors='strict')) + 1 for part in argv), 60000)
                environment_before = dict(environment)
                with source_module_loader._bootstrap_source(script) as (held_carrier, carrier_closing), \
                        source_module_loader._bootstrap_source(data) as (held_data, data_closing):
                    self.assertEqual(held_carrier, carrier)
                    self.assertEqual(held_data, public)
                    c_closing()
                    g_closing()
                    document(label + '.intent.private.json',
                             {'schemaVersion': 1, 'state': 'SINGLE_OWNED_NATIVE_SUBMISSION_INTENT_NO_REPLAY',
                              'argv': argv, 'sourceSha256': hashlib.sha256(raw).hexdigest(),
                              'carrierSha256': hashlib.sha256(carrier).hexdigest(), 'dataSha256': digest,
                              'sourceHeld': True, 'sameOwnedDataFileArgument': True,
                              'sanitizedEnvironment': True})
                    try:
                        result = subprocess.run(argv, env=environment, capture_output=True, timeout=30, check=False)
                    except subprocess.TimeoutExpired as failure:
                        preserve(label + '.stdout.private', failure.stdout or b'')
                        preserve(label + '.stderr.private', failure.stderr or b'')
                        document(label + '.terminal.private.json',
                                 {'state': 'TIMEOUT_NO_REPLAY', 'exit': None, 'stdoutEof': False,
                                  'stderrEof': False, 'completedProcessReturned': False, 'sourceClosing': False})
                        emit_native_capture_marker(label, failure.stdout or b'', failure.stderr or b'', None,
                                                   stdout_eof=False, stderr_eof=False,
                                                   completed_process_returned=False, source_closing=False)
                        raise
                    preserve(label + '.stdout.private', result.stdout)
                    preserve(label + '.stderr.private', result.stderr)
                    preserve(label + '.exit.private', str(result.returncode).encode('ascii'))
                    try:
                        carrier_closing()
                        data_closing()
                        c_closing()
                        g_closing()
                        self.assertEqual(environment, environment_before)
                        self.assertEqual(inherited, supplied_before)
                        self.assertEqual(dict(os.environ), parent_before)
                        self.assertEqual(script.read_bytes(), carrier)
                        self.assertEqual(data.read_bytes(), public)
                    except BaseException:
                        document(label + '.terminal.private.json',
                                 {'state': 'SOURCE_OR_ENVIRONMENT_CLOSURE_REFUSED_NO_REPLAY', 'exit': result.returncode,
                                  'stdoutEof': True, 'stderrEof': True,
                                  'completedProcessReturned': True, 'sourceClosing': False})
                        raise
                    document(label + '.terminal.private.json',
                             {'schemaVersion': 1, 'state': 'NATIVE_CAPTURED_NO_PASS_CLAIM',
                              'exit': result.returncode, 'stdoutEof': True, 'stderrEof': True,
                              'completedProcessReturned': True, 'sourceClosing': True,
                              'sourceSha256': hashlib.sha256(raw).hexdigest(),
                              'carrierSha256': hashlib.sha256(carrier).hexdigest(), 'dataSha256': digest})
                    emit_native_capture_marker(label, result.stdout, result.stderr, result.returncode,
                                               stdout_eof=True, stderr_eof=True,
                                               completed_process_returned=True, source_closing=True)
                    record = {'case': label, 'exit': result.returncode, 'stdout': result.stdout,
                              'stderr': result.stderr, 'stdoutEof': True, 'stderrEof': True,
                              'completedProcessReturned': True, 'sourceClosing': True, 'evidence': str(evidence)}
                    records.append(record)
                    return record

            counterfactual_g = run_owned('unfixed_g', g_raw, sanitized_environment)
            current = run_owned('sanitized', corrected_raw, sanitized_environment)
            counterfactual_c = run_owned('exact_c', c_raw, sanitized_environment)
            self.assertEqual(sanitized_environment, windows_powershell_environment(executable, inherited))
            self.assertEqual(current['exit'], 0, records)
            self.assertEqual(current['stderr'], b'', records)
            current_facts = native_command_observations(current['stdout'])
            self.assertEqual(current_facts['coldObservation'], (0, 0, 0), records)
            self.assertIs(current_facts['oraclePassed'], True, records)
            self.assertEqual([item['name'] for item in current_facts['commands']], ['Get-Acl', 'Get-FileHash'], records)
            self.assertEqual(modeled_native_precheck_missing(NATIVE_MODULE_SCRIPT, current_facts['commands']), (), records)
            current_hash = next(item for item in current_facts['commands'] if item['name'] == 'Get-FileHash')
            self.assertEqual((current_hash['moduleName'], current_hash['commandType'], current_hash['runtimeType']),
                             ('Microsoft.PowerShell.Utility', 'Function', 'System.Management.Automation.FunctionInfo'), records)

            # The historical exact-C filter proof keeps its original schema and
            # remains separate from G's provider-origin refusal.
            c_missing = modeled_native_precheck_missing(c_raw.decode('utf-8', errors='strict'), current_facts['commands'])
            self.assertIn('Get-FileHash', c_missing, records)
            self.assertEqual(counterfactual_c['exit'], 11, records)
            self.assertEqual(counterfactual_c['stdout'], b'', records)
            self.assertEqual(counterfactual_c['stderr'].splitlines(),
                             [('PUBLIC_NATIVE_MISSING:' + ','.join(c_missing)).encode('ascii')], records)
            document('causal-proof.private.json',
                     {'schemaVersion': 1, 'state': 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
                      'cExit': counterfactual_c['exit'], 'correctedExit': current['exit'],
                      'observedHashCommand': current_hash, 'cMissing': c_missing,
                      'sourceClosing': True, 'allThreeCompletedProcessReturned': True,
                      'allThreeStdoutEof': True, 'allThreeStderrEof': True,
                      'historicalCActualCommandTypeStillUnknown': True, 'sameSanitizedEnvironment': True,
                      'sameOwnedDataBytesAndHash': True, 'sameOwnedDataFileArgument': True,
                      'physicalAclAndHashOracleCompleted': True})

            self.assertEqual(counterfactual_g['exit'], 1, records)
            guard = b'PUBLIC_NATIVE_HASH_MODULE_RUNTIME'
            self.assertEqual(counterfactual_g['stderr'].splitlines()[0], guard, records)
            error_ids = [b' '.join(line.split()) for line in counterfactual_g['stderr'].splitlines()
                         if b'FullyQualifiedErrorId' in line]
            self.assertEqual(error_ids, [b'+ FullyQualifiedErrorId : ' + guard], records)
            g_facts = native_command_observations(counterfactual_g['stdout'])
            self.assertEqual(g_facts['coldObservation'], (0, 0, 0), records)
            self.assertEqual([item['name'] for item in g_facts['commands']], ['Get-Acl'], records)
            self.assertIs(g_facts['oraclePassed'], False, records)
            document('g-causal-proof.private.json',
                     {'schemaVersion': 1, 'state': 'EXACT_G_PROVIDER_GUARD_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
                      'gExit': counterfactual_g['exit'], 'correctedExit': current['exit'],
                      'gGuard': guard.decode('ascii'), 'gSourceSha256': NATIVE_G_SCRIPT_SHA256, 'gSourceBytes': len(g_raw),
                      'correctedSourceSha256': hashlib.sha256(corrected_raw).hexdigest(), 'dataSha256': digest,
                      'observedHashCommand': current_hash, 'sourceClosing': True,
                      'allThreeCompletedProcessReturned': True, 'allThreeStdoutEof': True, 'allThreeStderrEof': True,
                      'sameSanitizedEnvironment': True, 'sameOwnedDataBytesAndHash': True,
                      'sameOwnedDataFileArgument': True, 'physicalAclAndHashOracleCompleted': True,
                      'exactCProofSeparate': True})


def _native_causal_proof_control_value():
    """Typed local codec model only; callers must capture its diagnostic text."""
    return {'schemaVersion': 1, 'state': 'EXACT_C_PRECHECK_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
            'cExit': 11, 'correctedExit': 0,
            'observedHashCommand': {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                                    'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
            'cMissing': ('Get-FileHash',), 'sourceClosing': True,
            'allThreeCompletedProcessReturned': True, 'allThreeStdoutEof': True,
            'allThreeStderrEof': True, 'historicalCActualCommandTypeStillUnknown': True,
            'sameSanitizedEnvironment': True, 'sameOwnedDataBytesAndHash': True,
            'sameOwnedDataFileArgument': True, 'physicalAclAndHashOracleCompleted': True}


def actual_native_document_boundary(before):
    """Execute actual retained/current nested IO with owned closed inputs.

    All synthetic proof text remains inside StringIO. This local control does
    not run PowerShell or assert that a native proof happened.
    """
    from agent_tools import source_module_loader
    producer = Path(__file__).resolve()
    fragment = (AUTHENTIC_FIXTURE / 'native_capture_document_ca1.before.fragment').resolve()
    with ExitStack() as held:
        sources = {path: held.enter_context(source_module_loader._bootstrap_source(path))
                   for path in (producer, fragment)}
        if hashlib.sha256(sources[fragment][0]).hexdigest() != NATIVE_DOCUMENT_CA1_SHA256:
            raise ValueError('native-document-before-source')
        tree = ast.parse(sources[producer][0], filename=str(producer))
        imports = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                    not imports and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                imports.append(node)
            else:
                break
        helper_names = ('_emit_native_public_json', 'emit_native_capture_marker', 'emit_native_causal_marker')
        emitters = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in helper_names]
        if tuple(node.name for node in emitters) != helper_names:
            raise ValueError('native-document-emitter-identity')
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'NativeWindowsPowerShellEnvironmentTests']
        if len(classes) != 1:
            raise ValueError('native-document-producer-class')
        methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
                   and node.name == 'test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete']
        if len(methods) != 1:
            raise ValueError('native-document-producer-method')
        path = fragment if before else producer
        if before:
            nested = ast.parse(textwrap.dedent(sources[fragment][0].decode('utf-8', errors='strict')),
                               filename=str(fragment)).body
        else:
            nested = [node for node in ast.walk(methods[0]) if isinstance(node, ast.FunctionDef)
                      and node.name in ('preserve', 'document')]
        if [node.name for node in nested if isinstance(node, ast.FunctionDef)] != ['preserve', 'document'] or len(nested) != 2:
            raise ValueError('native-document-definitions')
        value = _native_causal_proof_control_value()
        with tempfile.TemporaryDirectory(prefix='native-document-local-codec-') as directory:
            evidence = Path(directory)
            if list(evidence.iterdir()):
                raise ValueError('native-document-owned-input')
            namespace = {'__name__': 'owned_native_document_boundary', '__file__': str(path), 'evidence': evidence}
            exec(compile(ast.Module(body=[*imports, *emitters], type_ignores=[]),
                         str(producer), 'exec', dont_inherit=True), namespace)
            exec(compile(ast.Module(body=nested, type_ignores=[]),
                         str(path), 'exec', dont_inherit=True), namespace)
            if any(namespace[name].__globals__ is not namespace or namespace[name].__code__.co_filename != str(path)
                   for name in ('preserve', 'document')):
                raise ValueError('native-document-source-binding')
            for unused, closing in sources.values():
                closing()
            captured = io.StringIO()
            with redirect_stdout(captured):
                namespace['document']('causal-proof.private.json', value)
            persisted = (evidence / 'causal-proof.private.json').read_bytes()
            for unused, closing in sources.values():
                closing()
            return {'stdout': captured.getvalue(), 'persisted': persisted,
                    'expected': (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'),
                    'sourceClosing': True, 'nativePowerShellExecuted': False}


class NativeCaptureDocumentPositive(unittest.TestCase):
    """Same local positive against genuine retained/current nested document."""
    before = False

    def test_actual_persisted_document_emits_public_causal_marker(self):
        self.observation = actual_native_document_boundary(self.before)
        self.assertEqual(self.observation['persisted'], self.observation['expected'])
        self.assertIs(self.observation['sourceClosing'], True)
        self.assertIs(self.observation['nativePowerShellExecuted'], False)
        lines = self.observation['stdout'].splitlines()
        self.assertEqual(len(lines), 1, 'PERSISTED_NATIVE_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED')
        self.assertLessEqual(len(lines[0].encode('utf-8')) + 1, 16384)
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        self.assertTrue(lines[0].startswith(prefix))
        envelope = json.loads(lines[0][len(prefix):])
        self.assertEqual(set(envelope), {'schemaVersion', 'kind', 'proof'})
        self.assertEqual(envelope['schemaVersion'], 1)
        self.assertEqual(envelope['kind'], 'causalProof')
        self.assertEqual(envelope['proof'], json.loads(self.observation['persisted']))


class NativePublicCaptureControlTests(unittest.TestCase):
    """Local diagnostic transport controls; no Windows execution is implied."""
    def _decode(self, text):
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        lines = text.splitlines()
        self.assertTrue(lines)
        records = []
        for line in lines:
            self.assertLessEqual(len(line.encode('utf-8')) + 1, 16384)
            self.assertTrue(line.startswith(prefix))
            records.append(json.loads(line[len(prefix):]))
        manifest = records.pop(0)
        self.assertEqual(set(manifest), {'schemaVersion', 'kind', 'captureId', 'case', 'returncode',
                                        'stdoutEof', 'stderrEof', 'completedProcessReturned',
                                        'sourceClosing', 'stdout', 'stderr'})
        self.assertEqual((manifest['schemaVersion'], manifest['kind']), (1, 'capture'))
        self.assertIs(type(manifest['captureId']), str)
        identity = uuid.UUID(hex=manifest['captureId'])
        self.assertEqual((identity.hex, identity.version), (manifest['captureId'], 4))
        self.assertIn(manifest['case'], ('bad_module_path', 'sanitized', 'exact_c', 'unfixed_g'))
        for key in ('stdoutEof', 'stderrEof', 'completedProcessReturned', 'sourceClosing'):
            self.assertIs(type(manifest[key]), bool)
        if manifest['completedProcessReturned']:
            self.assertIs(type(manifest['returncode']), int)
            self.assertTrue(manifest['stdoutEof'] and manifest['stderrEof'] and manifest['sourceClosing'])
        else:
            self.assertIsNone(manifest['returncode'])
            self.assertFalse(manifest['stdoutEof'] or manifest['stderrEof'] or manifest['sourceClosing'])
        streams = {}
        position = 0
        for name in ('stdout', 'stderr'):
            summary = manifest[name]
            self.assertEqual(set(summary), {'bytes', 'sha256', 'chunks'})
            self.assertIs(type(summary['bytes']), int)
            self.assertGreaterEqual(summary['bytes'], 0)
            self.assertIs(type(summary['chunks']), int)
            self.assertEqual(summary['chunks'], (summary['bytes'] + 8191) // 8192)
            self.assertIs(type(summary['sha256']), str)
            self.assertEqual(len(summary['sha256']), 64)
            self.assertEqual(set(summary['sha256']) - set('0123456789abcdef'), set())
            parts = []
            for index in range(summary['chunks']):
                record = records[position]
                position += 1
                self.assertEqual(set(record), {'schemaVersion', 'kind', 'captureId', 'case', 'stream',
                                               'chunkIndex', 'chunkCount', 'rawOffset', 'bytes',
                                               'chunkSha256', 'streamBytes', 'streamSha256', 'base64'})
                self.assertEqual((record['schemaVersion'], record['kind'], record['captureId'],
                                  record['case'], record['stream'], record['chunkIndex'],
                                  record['chunkCount'], record['rawOffset']),
                                 (1, 'streamChunk', manifest['captureId'], manifest['case'], name,
                                  index, summary['chunks'], index * 8192))
                self.assertEqual((record['streamBytes'], record['streamSha256']),
                                 (summary['bytes'], summary['sha256']))
                self.assertIs(type(record['base64']), str)
                part = base64.b64decode(record['base64'], validate=True)
                self.assertEqual((record['bytes'], record['chunkSha256']),
                                 (len(part), hashlib.sha256(part).hexdigest()))
                self.assertGreater(len(part), 0)
                self.assertLessEqual(len(part), 8192)
                parts.append(part)
            streams[name] = b''.join(parts)
            self.assertEqual((len(streams[name]), hashlib.sha256(streams[name]).hexdigest()),
                             (summary['bytes'], summary['sha256']))
        self.assertEqual(position, len(records))
        return manifest, streams

    def test_actual_retained_document_marker_red_then_current_green(self):
        cases = []
        for before in (True, False):
            case = NativeCaptureDocumentPositive('test_actual_persisted_document_emits_public_causal_marker')
            case.before = before
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn('PERSISTED_NATIVE_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observation['persisted'], current_case.observation['persisted'])
        self.assertEqual(old_case.observation['stdout'], '')

    def test_saved_inert_python_child_streams_roundtrip_multiple_chunks(self):
        # Saved owned Python only; binary public stream patterns exercise full
        # chunking, including NUL/non-UTF8 bytes and CRLF without normalization.
        program = ("import os\n"
                   "for fd,pattern,count in ((1,b'PUBLIC stdout\\x00\\xff\\r\\n',4000),(2,b'PUBLIC stderr\\r\\n',5000)):\n"
                   " value=memoryview(pattern*count)\n"
                   " while value:value=value[os.write(fd,value):]\n"
                   "raise SystemExit(7)\n")
        with tempfile.TemporaryDirectory(prefix='native-public-codec-child-') as directory:
            path = Path(directory) / 'owned-public-child.py'
            with path.open('xb') as stream:
                stream.write(program.encode('utf-8'))
            argv = [sys.executable, '-I', '-B', str(path)]
            self.assertLessEqual(sum(len(part.encode('utf-8')) + 1 for part in argv), 60000)
            child = subprocess.run(argv, capture_output=True, timeout=20, check=False)
            self.assertEqual(path.read_bytes(), program.encode('utf-8'))
        self.assertEqual(child.returncode, 7)
        self.assertEqual(child.stdout, b'PUBLIC stdout\x00\xff\r\n' * 4000)
        self.assertEqual(child.stderr, b'PUBLIC stderr\r\n' * 5000)
        captured = io.StringIO()
        with redirect_stdout(captured):
            identity = emit_native_capture_marker('sanitized', child.stdout, child.stderr, child.returncode,
                                                  stdout_eof=True, stderr_eof=True,
                                                  completed_process_returned=True, source_closing=True)
        manifest, streams = self._decode(captured.getvalue())
        self.assertEqual((manifest['captureId'], manifest['returncode']), (identity, child.returncode))
        self.assertEqual(streams, {'stdout': child.stdout, 'stderr': child.stderr})
        self.assertGreater(manifest['stdout']['chunks'], 1)
        self.assertGreater(manifest['stderr']['chunks'], 1)

    def test_partial_frame_model_and_typed_refusals(self):
        # Codec-only partial frame; no native or actual process closure claim.
        arguments = {'case': 'exact_c', 'stdout': b'PUBLIC partial stdout\r',
                     'stderr': b'PUBLIC partial stderr', 'returncode': None,
                     'stdout_eof': False, 'stderr_eof': False,
                     'completed_process_returned': False, 'source_closing': False}
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_capture_marker(**arguments)
        manifest, streams = self._decode(captured.getvalue())
        self.assertIsNone(manifest['returncode'])
        self.assertFalse(manifest['stdoutEof'] or manifest['stderrEof']
                         or manifest['completedProcessReturned'] or manifest['sourceClosing'])
        self.assertEqual(streams, {'stdout': arguments['stdout'], 'stderr': arguments['stderr']})
        for change in ({'case': 'foreign'}, {'case': True}, {'stdout': 'PUBLIC text'}, {'stderr': None},
                       {'returncode': True}, {'stdout_eof': 1}, {'source_closing': True},
                       {'stderr_eof': True}, {'completed_process_returned': True}):
            with self.subTest(change=change):
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-'):
                    emit_native_capture_marker(**{**arguments, **change})
                self.assertEqual(captured.getvalue(), '')
        proof = _native_causal_proof_control_value()
        for wrong in ({**proof, 'argv': ['PUBLIC forbidden field']}, {**proof, 'sourceClosing': 1},
                      {**proof, 'observedHashCommand': {**proof['observedHashCommand'], 'commandType': 'Cmdlet'}}):
            captured = io.StringIO()
            with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-'):
                emit_native_causal_marker(wrong)
            self.assertEqual(captured.getvalue(), '')




def _native_g_causal_proof_control_value():
    """Typed codec-only value; it is never a native execution receipt."""
    return {'schemaVersion': 1, 'state': 'EXACT_G_PROVIDER_GUARD_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
            'gExit': 1, 'correctedExit': 0, 'gGuard': 'PUBLIC_NATIVE_HASH_MODULE_RUNTIME',
            'gSourceSha256': NATIVE_G_SCRIPT_SHA256, 'gSourceBytes': 3981,
            'correctedSourceSha256': '1' * 64, 'dataSha256': '2' * 64,
            'observedHashCommand': {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                                    'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
            'sourceClosing': True, 'allThreeCompletedProcessReturned': True,
            'allThreeStdoutEof': True, 'allThreeStderrEof': True, 'sameSanitizedEnvironment': True,
            'sameOwnedDataBytesAndHash': True, 'sameOwnedDataFileArgument': True,
            'physicalAclAndHashOracleCompleted': True, 'exactCProofSeparate': True}


class NativeGPublicCaptureControlTests(unittest.TestCase):
    """Portable codec controls only; they never submit a native child."""
    def test_unfixed_g_capture_label_roundtrips_exact_bytes(self):
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_capture_marker('unfixed_g', b'PUBLIC G stdout\r\n', b'PUBLIC G stderr\x00\xff', 1,
                                       stdout_eof=True, stderr_eof=True,
                                       completed_process_returned=True, source_closing=True)
        manifest, streams = NativePublicCaptureControlTests()._decode(captured.getvalue())
        self.assertEqual((manifest['case'], manifest['returncode']), ('unfixed_g', 1))
        self.assertEqual(streams, {'stdout': b'PUBLIC G stdout\r\n', 'stderr': b'PUBLIC G stderr\x00\xff'})

    def test_g_proof_has_a_distinct_exact_envelope(self):
        proof = _native_g_causal_proof_control_value()
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_g_causal_marker(proof)
        lines = captured.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        self.assertTrue(lines[0].startswith(prefix))
        self.assertEqual(json.loads(lines[0][len(prefix):]),
                         {'schemaVersion': 1, 'kind': 'gProviderCausalProof', 'proof': proof})
        with self.assertRaisesRegex(ValueError, '^native-public-proof-schema$'):
            emit_native_causal_marker(proof)

    def test_g_proof_rejects_wrong_types_sources_and_observations(self):
        proof = _native_g_causal_proof_control_value()
        changes = ({'schemaVersion': True}, {'gExit': True}, {'gExit': 11}, {'gSourceBytes': True},
                   {'gSourceSha256': '0' * 64}, {'gWholeSourceSha256': '0' * 64}, {'gWholeSourceBytes': True},
                   {'correctedSourceSha256': 'x' * 64}, {'dataSha256': None},
                   {'sourceClosing': 1}, {'gGuard': 'PUBLIC_NATIVE_COMMAND_RUNTIME'},
                   {'extra': 'PUBLIC forbidden'},
                   {'observedHashCommand': {**proof['observedHashCommand'], 'commandType': 'Cmdlet'}})
        for change in changes:
            with self.subTest(change=change):
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-g-'):
                    emit_native_g_causal_marker({**proof, **change})
                self.assertEqual(captured.getvalue(), '')


# Routine G document-boundary causal controls. Existing C controls stay unchanged.
def actual_native_g_document_boundary(before):
    """Run authentic nested document IO only; synthetic proof output stays local."""
    from agent_tools import source_module_loader
    producer = Path(__file__).resolve()
    retained = (AUTHENTIC_FIXTURE / 'native_g_document.before.fragment').resolve()
    with ExitStack() as held:
        sources = {path: held.enter_context(source_module_loader._bootstrap_source(path))
                   for path in (producer, retained)}
        if (len(sources[retained][0]) != 433
                or hashlib.sha256(sources[retained][0]).hexdigest() != NATIVE_G_DOCUMENT_SHA256):
            raise ValueError('native-g-document-before-source')
        current_tree = ast.parse(sources[producer][0], filename=str(producer))
        imports = []
        for node in current_tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) or (
                    not imports and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)):
                imports.append(node)
            else:
                break
        names = ('_emit_native_public_json', 'emit_native_g_causal_marker')
        emitters = [node for node in current_tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        if tuple(node.name for node in emitters) != names:
            raise ValueError('native-g-document-emitter-identity')
        constants = [node for node in current_tree.body if isinstance(node, ast.Assign)
                     and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id in ('NATIVE_G_SCRIPT_SHA256', 'NATIVE_G_DOCUMENT_SHA256')]
        values = {node.targets[0].id: ast.literal_eval(node.value) for node in constants}
        if (len(constants) != 2 or values != {'NATIVE_G_SCRIPT_SHA256': NATIVE_G_SCRIPT_SHA256,
                                            'NATIVE_G_DOCUMENT_SHA256': NATIVE_G_DOCUMENT_SHA256}):
            raise ValueError('native-g-document-source-constants')
        path = retained if before else producer
        tree = ast.parse(sources[path][0], filename=str(path))
        if before:
            nested = tree.body
        else:
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                       and node.name == 'NativeWindowsPowerShellEnvironmentTests']
            if len(classes) != 1:
                raise ValueError('native-g-document-producer-class')
            methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
                       and node.name == 'test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete']
            if len(methods) != 1:
                raise ValueError('native-g-document-producer-method')
            nested = [node for node in ast.walk(methods[0]) if isinstance(node, ast.FunctionDef)
                      and node.name in ('preserve', 'document')]
        if (len(nested) != 2 or any(not isinstance(node, ast.FunctionDef) for node in nested)
                or [node.name for node in nested] != ['preserve', 'document']):
            raise ValueError('native-g-document-definitions')
        value = _native_g_causal_proof_control_value()
        with tempfile.TemporaryDirectory(prefix='native-g-document-local-codec-') as directory:
            evidence = Path(directory)
            if list(evidence.iterdir()):
                raise ValueError('native-g-document-owned-input')
            namespace = {'__name__': 'owned_native_g_document_boundary', '__file__': str(path), 'evidence': evidence}
            exec(compile(ast.Module(body=[*imports, *constants, *emitters], type_ignores=[]),
                         str(producer), 'exec', dont_inherit=True), namespace)
            exec(compile(ast.Module(body=nested, type_ignores=[]),
                         str(path), 'exec', dont_inherit=True), namespace)
            if any(namespace[name].__globals__ is not namespace or namespace[name].__code__.co_filename != str(path)
                   for name in ('preserve', 'document')):
                raise ValueError('native-g-document-source-binding')
            for unused, closing in sources.values():
                closing()
            captured = io.StringIO()
            with redirect_stdout(captured):
                namespace['document']('g-causal-proof.private.json', value)
            persisted = (evidence / 'g-causal-proof.private.json').read_bytes()
            for unused, closing in sources.values():
                closing()
            return {'stdout': captured.getvalue(), 'persisted': persisted,
                    'expected': (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8'),
                    'expectedEnvelope': {'schemaVersion': 1, 'kind': 'gProviderCausalProof', 'proof': value},
                    'sourceClosing': True, 'nativePowerShellExecuted': False}


class NativeGDocumentPositive(unittest.TestCase):
    before = False

    def test_actual_persisted_g_document_emits_public_marker(self):
        self.observation = actual_native_g_document_boundary(self.before)
        self.assertIs(self.observation['nativePowerShellExecuted'], False)
        self.assertIs(self.observation['sourceClosing'], True)
        self.assertEqual(self.observation['persisted'], self.observation['expected'])
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        lines = self.observation['stdout'].splitlines()
        self.assertTrue(all(line.startswith(prefix) for line in lines))
        records = [json.loads(line[len(prefix):]) for line in lines]
        expected = [self.observation['expectedEnvelope']]
        self.assertEqual(records, expected, 'PERSISTED_NATIVE_G_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED')


class NativeGDocumentBoundaryControlTests(unittest.TestCase):
    """Same local positive against authentic G/current nested document bodies."""
    def test_authentic_g_document_marker_red_then_current_green(self):
        cases = []
        for before in (True, False):
            case = NativeGDocumentPositive('test_actual_persisted_g_document_emits_public_marker')
            case.before = before
            result = unittest.TestResult()
            case.run(result)
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
        self.assertIn("self.assertEqual(records, expected, 'PERSISTED_NATIVE_G_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED')", old.failures[0][1])
        self.assertIn('PERSISTED_NATIVE_G_CAUSAL_RECEIPT_MUST_BE_PUBLICLY_RETAINED', old.failures[0][1])
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors), len(current.skipped)), (1, 0, 0, 0))
        self.assertEqual(old_case.observation['persisted'], current_case.observation['persisted'])
        self.assertEqual(old_case.observation['stdout'], '')


def native_cold_observation_fragment(script):
    """Select actual contiguous guard bytes, without interpreting PowerShell."""
    begin = '# PUBLIC_COLD_OBSERVATION_BEGIN\n'
    end = '# PUBLIC_COLD_OBSERVATION_END\n'
    if (type(script) is not str or script.count(begin) != 1
            or script.count(end) != 1):
        raise ValueError('native-cold-source-selector')
    first = script.index(begin)
    last = script.index(end, first) + len(end)
    return script[first:last]


def controlled_cold_catalog_program(fragment, *, initially_imported=False):
    """Real-engine component fixture with an explicitly controlled catalog.

    Its exact-name lookup deliberately imports a modeled command. This proves
    the guard's sensitivity to discovery side effects; it does not establish
    the original Windows host's branch, module availability, ACL, or hash.
    """
    if (type(initially_imported) is not bool or type(fragment) is not str
            or fragment not in (NATIVE_COLD_F_BEFORE,
                                native_cold_observation_fragment(NATIVE_MODULE_SCRIPT))):
        raise ValueError('native-cold-catalog-selector')
    if hashlib.sha256(NATIVE_COLD_F_BEFORE.encode()).hexdigest() != NATIVE_COLD_F_BEFORE_SHA256:
        raise ValueError('native-cold-f-before-changed')
    prelude = r"""$ErrorActionPreference='Stop'
$script:catalogImported=__IMPORTED__
function Get-Module {param([string]$Name,[switch]$All,[string]$ErrorAction)
 if($Name -cne 'Microsoft.PowerShell.Utility' -or -not $All){throw 'PUBLIC_CATALOG_MODULE_QUERY'}
 if($script:catalogImported){[pscustomobject]@{Name='Microsoft.PowerShell.Utility'}}
}
function Get-Command {param([string]$Name,[switch]$ListImported,[string]$ErrorAction)
 if(-not $ListImported){throw 'PUBLIC_CATALOG_COMMAND_QUERY'}
 if($Name -ceq 'Get-FileHash'){$script:catalogImported=$true;[pscustomobject]@{Name='Get-FileHash'};return}
 if($Name -cne 'Get-FileHash*'){throw 'PUBLIC_CATALOG_COMMAND_QUERY'}
 if($script:catalogImported){[pscustomobject]@{Name='Get-FileHash'}}
}
try {
""".replace('__IMPORTED__', '$true' if initially_imported else '$false')
    return (prelude + fragment + r"""
 if($script:catalogImported){throw 'PUBLIC_CONTROLLED_CATALOG_NOT_COLD'}
 [Console]::Out.WriteLine('PUBLIC_CONTROLLED_CATALOG_PASS')
 exit 0
}catch{[Console]::Error.WriteLine($_.Exception.Message);exit 11}
""")


class NativeColdObservationProtocolPositive(unittest.TestCase):
    """Synthetic wire control only; no native execution receipt is emitted."""
    decoder = staticmethod(native_command_observations)

    def test_diagnostic_counts_precede_native_command_facts(self):
        self.facts = self.decoder(
            b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0:0\n'
            b'PUBLIC_NATIVE_UTILITY_COLD:1\n')
        self.assertEqual(self.facts['coldObservation'], (0, 0, 0))
        self.assertEqual(self.facts['utilityModulesUnloaded'], 1)
        self.assertEqual(self.facts['commands'], ())
        self.assertIs(self.facts['oraclePassed'], False)


class PowerShellColdCatalogPositive(unittest.TestCase):
    """Execute actual guard bytes against a declared private catalog model."""
    fragment = None
    initially_imported = False

    def setUp(self):
        self.executable = shutil.which('powershell.exe' if os.name == 'nt' else 'pwsh')
        if os.name == 'nt':
            self.assertIsNotNone(self.executable, 'Windows PowerShell is required')
        elif self.executable is None:
            self.skipTest('PowerShell engine is unavailable for the controlled catalog component')

    def test_source_selected_discovery_keeps_controlled_catalog_cold(self):
        fragment = (native_cold_observation_fragment(NATIVE_MODULE_SCRIPT)
                    if self.fragment is None else self.fragment)
        program = controlled_cold_catalog_program(fragment, initially_imported=self.initially_imported)
        with tempfile.TemporaryDirectory(prefix='controlled-cold-catalog-') as temporary:
            path = Path(temporary).resolve() / 'catalog.ps1'
            raw = b'\xef\xbb\xbf' + program.encode('utf-8', errors='strict')
            with path.open('xb') as stream:
                stream.write(raw)
            environment = windows_powershell_environment(self.executable, dict(os.environ))
            self.completed = subprocess.run(
                [self.executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(path)],
                capture_output=True, check=False, timeout=30, env=environment)
            self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(self.completed.returncode, 0,
                         (self.completed.stdout, self.completed.stderr))
        self.assertEqual(self.completed.stderr, b'')
        self.assertEqual(self.completed.stdout.splitlines(),
                         [b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0:0',
                          b'PUBLIC_CONTROLLED_CATALOG_PASS'])


class NativeColdObservationTests(unittest.TestCase):
    def test_count_protocol_refuses_warm_malformed_and_duplicate_records(self):
        suffix = b'PUBLIC_NATIVE_UTILITY_COLD:0\n'
        for prefix in (b'PUBLIC_NATIVE_COLD_OBSERVATION:1:0:0\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:0:1:0\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0:1\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0:9\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:False:0:0\n',
                       b'PUBLIC_NATIVE_COLD_OBSERVATION:0:0:0\n' * 2):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                native_command_observations(prefix + suffix)
        self.assertIsNone(native_command_observations(suffix)['coldObservation'])

    def test_catalog_source_selection_refuses_unknown_programs(self):
        for wrong in ('', NATIVE_MODULE_SCRIPT, NATIVE_COLD_F_BEFORE + '# changed\n'):
            with self.subTest(source=wrong), self.assertRaisesRegex(ValueError, '^native-cold-catalog-selector$'):
                controlled_cold_catalog_program(wrong)
        for wrong in ('', NATIVE_MODULE_SCRIPT.replace('# PUBLIC_COLD_OBSERVATION_BEGIN', '# missing')):
            with self.subTest(source=wrong), self.assertRaisesRegex(ValueError, '^native-cold-source-selector$'):
                native_cold_observation_fragment(wrong)

    def test_actual_f_guard_red_current_guard_green_on_controlled_catalog(self):
        cases = []
        for fragment in (NATIVE_COLD_F_BEFORE, native_cold_observation_fragment(NATIVE_MODULE_SCRIPT)):
            case = PowerShellColdCatalogPositive('test_source_selected_discovery_keeps_controlled_catalog_cold')
            case.fragment = fragment
            result = unittest.TestResult()
            case.run(result)
            if result.skipped:
                self.skipTest(result.skipped[0][1])
            cases.append((case, result))
        (old_case, old), (current_case, current) = cases
        self.assertEqual((old.testsRun, len(old.failures), len(old.errors)), (1, 1, 0), old.errors)
        self.assertEqual(old_case.completed.returncode, 11)
        self.assertIn(b'PUBLIC_NATIVE_UTILITY_NOT_COLD', old_case.completed.stderr)
        self.assertEqual((current.testsRun, len(current.failures), len(current.errors)), (1, 0, 0),
                         (current.failures, current.errors))

    def test_warm_controlled_catalog_still_refuses(self):
        case = PowerShellColdCatalogPositive('test_source_selected_discovery_keeps_controlled_catalog_cold')
        case.initially_imported = True
        result = unittest.TestResult()
        case.run(result)
        if result.skipped:
            self.skipTest(result.skipped[0][1])
        self.assertEqual((result.testsRun, len(result.failures), len(result.errors)), (1, 1, 0), result.errors)
        self.assertEqual(case.completed.returncode, 11)
        self.assertIn(b'PUBLIC_NATIVE_COLD_OBSERVATION:1:1:1', case.completed.stdout)
        self.assertIn(b'PUBLIC_NATIVE_UTILITY_NOT_COLD', case.completed.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--legacy-red', action='store_true')
    parser.add_argument('--authentic-before-red', action='store_true')
    arguments, remaining = parser.parse_known_args()
    if arguments.authentic_before_red:
        if remaining or arguments.legacy_red:
            parser.error('The authentic causal mode accepts no other selectors')
        case = AuthenticNativeOwnerEnvironmentPositive('test_actual_native_owner_method_forwards_its_environment')
        case.before = True
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([case]))
        expected_red = ((result.testsRun, len(result.failures), len(result.errors), len(result.skipped))
                        == (1, 1, 0, 0) and
                        'AUTHENTIC_NATIVE_OWNER_MUST_REMOVE_INHERITED_MODULE_PATH' in result.failures[0][1])
        raise SystemExit(1 if expected_red else 2)
    if arguments.legacy_red:
        if remaining:
            parser.error('The causal passthrough mode accepts no unittest selectors')
        case = WindowsPowerShellEnvironmentPositive('test_windows_powershell_child_rebuilds_its_module_path')
        case.environment_factory = legacy_copied_environment
        result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([case]))
        expected_red = ((result.testsRun, len(result.failures), len(result.errors), len(result.skipped))
                        == (1, 1, 0, 0) and
                        'PSMODULEPATH_MUST_BE_REBUILT_BY_WINDOWS_POWERSHELL' in result.failures[0][1])
        raise SystemExit(1 if expected_red else 2)
    unittest.main(argv=[sys.argv[0], *remaining])
