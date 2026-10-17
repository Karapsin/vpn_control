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
from contextlib import ExitStack, redirect_stdout, contextmanager
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
import uuid
import zipfile

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


PUBLIC_MODULE_PATH = 'PUBLIC inherited module directory'
PUBLIC_SENTINEL = 'PUBLIC environment forwarding sentinel'
ROOT = Path(__file__).resolve().parents[2]
AUTHENTIC_FIXTURE = Path(__file__).parent / 'fixtures/windows_powershell_environment'
AUTHENTIC_BEFORE_SHA256 = '903bcbb3eba1d92e50baec2243ed0788f616942c64a02eb6284aac583a98bb38'
AUTHENTIC_STAGE_SHA256 = 'fb2dab95628f1d03e30711d5bcdd0eb2440ef75c3b2cd900ad5e3ffda09bef05'
NATIVE_C_SCRIPT_SHA256 = '4fc533a02a779ae4c00691837ba95d3077486c53c474e1ba3576deaa978ffe39'
NATIVE_I_SCRIPT_SHA256 = 'f69211aa4bffac9873dc1526f696d6a78c81ec8163f6065cbf00460174233887'
NATIVE_PROVIDER_WRAPPER_SHA256 = '405c3d27478c1d0433ddf21a34b2b602319c79aecda7c610a046d71d740e2fa0'
NATIVE_PROVIDER_EVIDENCE_ENV = 'VPN_CONTROL_NATIVE_PROVIDER_EVIDENCE_ROOT'
NATIVE_G_SCRIPT_SHA256 = '44adab1cf63866aad566cd49624ef7e23f3e08be20a044341008b10222bd1635'
NATIVE_G_DOCUMENT_SHA256 = '1aea351d4fecee39c7fe330edc65f11bf8381d8f15fa606aa2bcfea84102d6e5'
NATIVE_DOCUMENT_CA1_SHA256 = 'e10c6535655a51c3244f93dfb29c819789bb69247a14e021d850703422080924'
CHILD_OBSERVER = (
    "import json,os;print(json.dumps({"
    "'modulePaths':{key.upper():value for key,value in os.environ.items() "
    "if key.upper()=='PSMODULEPATH'},"
    "'sentinel':os.environ.get('VPN_FIXTURE_ENV_SENTINEL')},sort_keys=True))"
)
NATIVE_MODULE_SCRIPT = "$ErrorActionPreference='Stop'\nfunction Resolve-PublicNativeProviderNoBomCodePage([Version]$engineVersion,[string]$edition,[int]$activeCodePage,[PlatformID]$platform,[string]$coreAssemblyName){\n    if($null -eq $engineVersion){throw 'PUBLIC_NATIVE_PROVIDER_ENCODING_CONTEXT'}\n    if($engineVersion.Major -eq 5 -and $engineVersion.Minor -eq 1 -and $edition -ceq 'Desktop' -and $platform -eq [PlatformID]::Win32NT -and $coreAssemblyName -ceq 'mscorlib'){\n        if($activeCodePage -lt 1 -or $activeCodePage -gt 65535 -or $activeCodePage -in @(1200,1201,12000,12001,65000)){throw 'PUBLIC_NATIVE_PROVIDER_ENCODING_CONTEXT'}\n        return $activeCodePage\n    }\n    if($engineVersion.Major -ge 6 -and $edition -ceq 'Core' -and $activeCodePage -eq 65001 -and $coreAssemblyName -ceq 'System.Private.CoreLib'){return 65001}\n    throw 'PUBLIC_NATIVE_PROVIDER_ENCODING_CONTEXT'\n}\nfunction ConvertFrom-PublicNativeProviderBytes([byte[]]$raw,[int]$noBomCodePage=65001){\n    if($null -eq $raw -or $raw.Length -lt 1 -or $raw.Length -gt 8388608){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_BOUND'}\n    # Generic reads stay strict UTF-8. Provider callers supply the live engine's\n    # no-BOM policy; an explicit Unicode BOM always takes precedence.\n    $offset=0;$codePage=$noBomCodePage\n    if($raw.Length -ge 2 -and $raw[0] -eq 255 -and $raw[1] -eq 254){\n        if(($raw.Length-2)%2 -or ($raw.Length -ge 4 -and $raw[2] -eq 0 -and $raw[3] -eq 0)){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'}\n        $offset=2;$codePage=1200\n    }elseif($raw.Length -ge 2 -and $raw[0] -eq 254 -and $raw[1] -eq 255){\n        throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'\n    }elseif($raw.Length -ge 3 -and $raw[0] -eq 239 -and $raw[1] -eq 187 -and $raw[2] -eq 191){\n        $offset=3;$codePage=65001\n    }elseif($noBomCodePage -lt 1 -or $noBomCodePage -gt 65535 -or $noBomCodePage -in @(1200,1201,12000,12001,65000)){\n        throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'\n    }\n    $encoding=[Text.Encoding]::GetEncoding($codePage,[Text.EncoderExceptionFallback]::new(),[Text.DecoderExceptionFallback]::new())\n    $text=$encoding.GetString($raw,$offset,$raw.Length-$offset)\n    if($text.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING'}\n    if($encoding.GetByteCount($text) -ne $raw.Length-$offset){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ROUNDTRIP'}\n    $roundtrip=$encoding.GetBytes($text)\n    for($index=0;$index -lt $roundtrip.Length;$index++){\n        if($roundtrip[$index] -ne $raw[$index+$offset]){throw 'PUBLIC_NATIVE_PROVIDER_TEXT_ROUNDTRIP'}\n    }\n    return $text\n}\n# Provider admission is literal data plus the live typed export graph. It never\n# imports a module, evaluates a manifest, or queries a second command provider.\nfunction Read-PublicNativeManifestStrings($node,[Collections.Generic.List[string]]$values,[int]$depth){\n    if($depth -gt 8 -or $null -eq $node){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n    if($node -is [Management.Automation.Language.StatementBlockAst]){\n        if(($null -ne $node.Traps -and $node.Traps.Count) -or $node.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        Read-PublicNativeManifestStrings $node.Statements[0] $values ($depth+1);return\n    }\n    if($node -is [Management.Automation.Language.PipelineAst]){\n        if($node.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        $element=$node.PipelineElements[0]\n        if($element -isnot [Management.Automation.Language.CommandExpressionAst] -or $element.Redirections.Count -or $node.Extent.StartOffset -ne $element.Expression.Extent.StartOffset -or $node.Extent.EndOffset -ne $element.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        Read-PublicNativeManifestStrings $element.Expression $values ($depth+1);return\n    }\n    if($node -is [Management.Automation.Language.ArrayExpressionAst]){\n        if(($null -ne $node.SubExpression.Traps -and $node.SubExpression.Traps.Count)){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n        foreach($statement in $node.SubExpression.Statements){Read-PublicNativeManifestStrings $statement $values ($depth+1)};return\n    }\n    if($node -is [Management.Automation.Language.ArrayLiteralAst]){\n        foreach($element in $node.Elements){Read-PublicNativeManifestStrings $element $values ($depth+1)};return\n    }\n    if($node -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL'}\n    $value=[string]$node.Value\n    if($values.Count -ge 1024 -or [Text.Encoding]::UTF8.GetByteCount($value) -gt 4096 -or $value.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_MANIFEST_LITERAL_BOUND'}\n    $values.Add($value)\n}\nfunction Read-PublicNativeUtilityManifest([byte[]]$raw,[int]$noBomCodePage=65001){\n    if($raw.Length -lt 1 -or $raw.Length -gt 131072){throw 'PUBLIC_NATIVE_MANIFEST_BOUND'}\n    $text=ConvertFrom-PublicNativeProviderBytes $raw $noBomCodePage\n    $tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)\n    if($errors.Count -or $tree.ScriptRequirements -or $null -ne $tree.ParamBlock -or $null -ne $tree.BeginBlock -or $null -ne $tree.ProcessBlock -or $null -ne $tree.DynamicParamBlock -or $tree.UsingStatements.Count -or $null -eq $tree.EndBlock -or ($null -ne $tree.EndBlock.Traps -and $tree.EndBlock.Traps.Count) -or -not $tree.EndBlock.Unnamed -or $tree.EndBlock.Statements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $clean=$tree.PSObject.Properties['CleanBlock'];if($null -ne $clean -and $null -ne $clean.Value){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $statement=$tree.EndBlock.Statements[0]\n    if($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $expression=$statement.PipelineElements[0]\n    if($expression -isnot [Management.Automation.Language.CommandExpressionAst] -or $expression.Redirections.Count -or $expression.Expression -isnot [Management.Automation.Language.HashtableAst] -or $statement.Extent.StartOffset -ne $expression.Expression.Extent.StartOffset -or $statement.Extent.EndOffset -ne $expression.Expression.Extent.EndOffset){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $pairs=$expression.Expression.KeyValuePairs\n    if($pairs.Count -lt 1 -or $pairs.Count -gt 64){throw 'PUBLIC_NATIVE_MANIFEST_SHAPE'}\n    $fields=[Collections.Generic.Dictionary[string,string[]]]::new([StringComparer]::OrdinalIgnoreCase)\n    foreach($pair in $pairs){\n        if($pair.Item1 -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}\n        $key=[string]$pair.Item1.Value\n        if($key -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,63}$' -or $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_KEY'}\n        $values=[Collections.Generic.List[string]]::new()\n        Read-PublicNativeManifestStrings $pair.Item2 $values 0\n        $fields.Add($key,$values.ToArray())\n    }\n    foreach($key in @('GUID','ModuleVersion','NestedModules','CmdletsToExport')){if(-not $fields.ContainsKey($key)){throw 'PUBLIC_NATIVE_MANIFEST_REQUIRED'}}\n    if($fields['GUID'].Count -ne 1 -or $fields['ModuleVersion'].Count -ne 1 -or $fields.ContainsKey('ModuleToProcess')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}\n    if($fields.ContainsKey('RootModule') -and ($fields['RootModule'].Count -ne 1 -or $fields['RootModule'][0] -cne '')){throw 'PUBLIC_NATIVE_MANIFEST_ROOT'}\n    if($fields['NestedModules'].Length -lt 1 -or $fields['NestedModules'].Length -gt 2 -or -not $fields.ContainsKey('FunctionsToExport')){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n    $nestedNames=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)\n    foreach($nestedName in $fields['NestedModules']){\n        if(($nestedName -cne 'Microsoft.PowerShell.Commands.Utility.dll' -and $nestedName -cne 'Microsoft.PowerShell.Utility.psm1') -or -not $nestedNames.Add($nestedName)){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n    }\n    foreach($key in @('CmdletsToExport','FunctionsToExport')){\n        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)\n        foreach($export in $fields[$key]){if($export.Length -eq 0 -or [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($export) -or -not $seen.Add($export)){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}}\n    }\n    return ,$fields\n}\nfunction Assert-PublicNativeUtilityCmdletProvider([Management.Automation.CmdletInfo]$command){\n    $noBomCodePage=Resolve-PublicNativeProviderNoBomCodePage ([Version]$PSVersionTable.PSVersion) ([string]$PSVersionTable.PSEdition) ([Text.Encoding]::Default.CodePage) ([Environment]::OSVersion.Platform) ([Object].Assembly.GetName().Name)\n    if($null -eq $command -or $command.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $command.Name -cne 'Get-FileHash' -or $command.ModuleName -cne 'Microsoft.PowerShell.Utility' -or $command.Source -cne 'Microsoft.PowerShell.Utility'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_COMMAND'}\n    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)\n    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$manifestDirectory=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')\n    $manifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psd1'))\n    $dllPath=[IO.Path]::GetFullPath([IO.Path]::Combine($providerHome,'Microsoft.PowerShell.Commands.Utility.dll'))\n    $module=$command.Module\n    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $module.Name -cne 'Microsoft.PowerShell.Utility' -or [string]$module.ModuleType -cne 'Manifest' -or [IO.Path]::GetFullPath($module.Path) -ine $manifestPath -or [string]$module.RootModule -cne ''){throw 'PUBLIC_NATIVE_HASH_PROVIDER_MANIFEST'}\n    # Windows FileShare.Read denies concurrent replacement/writes while both\n    # files are held. The named metadata and held bytes are checked again.\n    $directories=@($providerHome,$modulesPath,$manifestDirectory)\n    $directoryStates=@()\n    foreach($path in $directories){$info=[IO.DirectoryInfo]::new($path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'};$directoryStates+=,([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}\n    $manifestInfo=[IO.FileInfo]::new($manifestPath);$dllInfo=[IO.FileInfo]::new($dllPath)\n    foreach($info in @($manifestInfo,$dllInfo)){$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE'}}\n    if($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 131072 -or $dllInfo.Length -lt 1 -or $dllInfo.Length -gt 8388608){throw 'PUBLIC_NATIVE_HASH_PROVIDER_FILE_BOUND'}\n    $manifestState=([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes)\n    $dllState=([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes)\n    $manifestStream=$null;$dllStream=$null;$sha=$null\n    try{\n        $manifestStream=[IO.File]::Open($manifestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        $dllStream=[IO.File]::Open($dllPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        if($manifestStream.Length -ne $manifestInfo.Length -or $dllStream.Length -ne $dllInfo.Length){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}\n        $raw=[byte[]]::new([int]$manifestStream.Length);$offset=0\n        while($offset -lt $raw.Length){$count=$manifestStream.Read($raw,$offset,$raw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'};$offset+=$count}\n        if($manifestStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EOF'}\n        $sha=[Security.Cryptography.SHA256]::Create();$manifestHash=[Convert]::ToBase64String($sha.ComputeHash($raw));$dllHash=[Convert]::ToBase64String($sha.ComputeHash($dllStream))\n        Confirm-PublicNativeProviderDecodeInput 'manifest' $manifestPath $raw $manifestHash $noBomCodePage\n        $fields=Read-PublicNativeUtilityManifest $raw $noBomCodePage\n        if($fields['NestedModules'].Length -ne 1 -or $fields['NestedModules'][0] -cne 'Microsoft.PowerShell.Commands.Utility.dll'){throw 'PUBLIC_NATIVE_MANIFEST_NESTED'}\n        if($fields['FunctionsToExport'].Length -ne 0 -or -not ($fields['CmdletsToExport'] -ccontains 'Get-FileHash')){throw 'PUBLIC_NATIVE_MANIFEST_EXPORT'}\n        if($module.Guid -ne [Guid]::Parse($fields['GUID'][0]) -or $module.Version -ne [Version]::Parse($fields['ModuleVersion'][0])){throw 'PUBLIC_NATIVE_HASH_PROVIDER_IDENTITY'}\n        $nested=@($module.NestedModules)\n        if($nested.Count -ne 1 -or $null -eq $nested[0] -or $nested[0].GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $nested[0] -isnot [Management.Automation.PSModuleInfo] -or [string]$nested[0].ModuleType -cne 'Binary' -or $nested[0].Name -cne 'Microsoft.PowerShell.Commands.Utility' -or [IO.Path]::GetFullPath($nested[0].Path) -ine $dllPath){throw 'PUBLIC_NATIVE_HASH_PROVIDER_NESTED'}\n        $type=$command.ImplementingType;$assembly=if($null -ne $type){$type.Assembly}else{$null}\n        if($null -eq $type -or $type.FullName -cne 'Microsoft.PowerShell.Commands.GetFileHashCommand' -or $null -eq $assembly -or $assembly.IsDynamic -or [IO.Path]::GetFullPath($assembly.Location) -ine $dllPath -or -not [Object]::ReferenceEquals($nested[0].ImplementingAssembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_ASSEMBLY'}\n        # ModuleBase must come from this manifest/nested-provider graph, not\n        # merely from an arbitrary directory somewhere below the runtime.\n        $baseComparison=if([IO.Path]::DirectorySeparatorChar -eq [char]92){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}\n        $baseTrim=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)\n        if([string]::IsNullOrWhiteSpace([string]$module.ModuleBase) -or [string]::IsNullOrWhiteSpace([string]$nested[0].ModuleBase)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}\n        $selectedBase=[IO.Path]::GetFullPath([string]$module.ModuleBase).TrimEnd($baseTrim)\n        $nestedBase=[IO.Path]::GetFullPath([string]$nested[0].ModuleBase).TrimEnd($baseTrim)\n        $manifestBase=[IO.Path]::GetFullPath($manifestDirectory).TrimEnd($baseTrim)\n        $assemblyBase=[IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($dllPath)).TrimEnd($baseTrim)\n        if(-not [string]::Equals($nestedBase,$assemblyBase,$baseComparison) -or (-not [string]::Equals($selectedBase,$manifestBase,$baseComparison) -and -not [string]::Equals($selectedBase,$nestedBase,$baseComparison))){throw 'PUBLIC_NATIVE_HASH_PROVIDER_BASE'}\n        $exported=$null;$exportCount=0\n        foreach($entry in $module.ExportedCmdlets.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$exported=$entry.Value;$exportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}}}\n        if($exportCount -ne 1 -or $null -eq $exported -or $exported.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $exported -isnot [Management.Automation.CmdletInfo] -or $exported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($exported.ImplementingType,$type) -or -not [Object]::ReferenceEquals($exported.ImplementingType.Assembly,$assembly)){throw 'PUBLIC_NATIVE_HASH_PROVIDER_EXPORT'}\n        $manifestStream.Position=0;$dllStream.Position=0\n        if([Convert]::ToBase64String($sha.ComputeHash($manifestStream)) -cne $manifestHash -or [Convert]::ToBase64String($sha.ComputeHash($dllStream)) -cne $dllHash){throw 'PUBLIC_NATIVE_HASH_PROVIDER_SOURCE_CHANGED'}\n        $manifestInfo.Refresh();$dllInfo.Refresh()\n        if(([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes) -cne $manifestState -or ([string]$dllInfo.Length+':'+[string]$dllInfo.CreationTimeUtc.Ticks+':'+[string]$dllInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$dllInfo.Attributes) -cne $dllState){throw 'PUBLIC_NATIVE_HASH_PROVIDER_GENERATION'}\n        for($index=0;$index -lt $directories.Count;$index++){$info=[IO.DirectoryInfo]::new($directories[$index]);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $directoryStates[$index]){throw 'PUBLIC_NATIVE_HASH_PROVIDER_DIRECTORY'}}\n    }finally{\n        try{if($null -ne $sha){$sha.Dispose()}}finally{try{if($null -ne $dllStream){$dllStream.Dispose()}}finally{if($null -ne $manifestStream){$manifestStream.Dispose()}}}\n    }\n}\nfunction Assert-PublicNativeUtilityFunctionOrigins([string]$manifestPath,[string]$selectedPath,[string]$selectedBase,[string]$scriptPath,[string]$scriptFile,[string]$definingPath,[string]$definingBase,[StringComparison]$comparison){\n    # Inputs are already normalized by the native caller. This is also the\n    # application-controlled decision exercised by retained-field controls.\n    if($comparison -ne [StringComparison]::Ordinal -and $comparison -ne [StringComparison]::OrdinalIgnoreCase){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n    foreach($value in @($manifestPath,$selectedPath,$selectedBase,$scriptPath,$scriptFile,$definingPath,$definingBase)){\n        if([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 32768 -or $value.IndexOf([char]0) -ge 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n    }\n    if(-not [string]::Equals($selectedPath,$manifestPath,$comparison) -or -not [string]::Equals($scriptFile,$scriptPath,$comparison) -or -not [string]::Equals($definingPath,$scriptPath,$comparison) -or -not [string]::Equals($selectedBase,$definingBase,$comparison)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}\n}\nfunction Stop-PublicNativeUtilityFunctionGraph([string]$token,[int]$index,[object]$node,[object]$block){\n    # Refusal details are bounded, best effort and never replace the guard.\n    $message=$token\n    try{\n        $name='';$kind='';$same=$false\n        if($null -ne $node){$name=[string]$node.Name;$kind=[string]$node.ModuleType}\n        if($null -ne $block){$same=[Object]::ReferenceEquals($node,$block.Module)}\n        $utf8=[Text.UTF8Encoding]::new($false,$true)\n        $nameRaw=$utf8.GetBytes($name);$kindRaw=$utf8.GetBytes($kind)\n        if($nameRaw.Length -gt 1024 -or $kindRaw.Length -gt 128){throw 'GRAPH_DETAIL_BOUND'}\n        $message=$token+':index='+[string]$index+':moduleTypeBase64='+[Convert]::ToBase64String($kindRaw)+':nameBase64='+[Convert]::ToBase64String($nameRaw)+':scriptReference='+[string][int]$same\n        if($utf8.GetByteCount($message) -gt 4096){throw 'GRAPH_DETAIL_BOUND'}\n    }catch{$message=$token+':detailsUnavailable=1'}\n    throw $message\n}\nfunction Resolve-PublicNativeUtilityFunctionNodes([object]$module,[object]$block,[string]$declaredBinaryDll){\n    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $null -eq $block -or $block -isnot [Management.Automation.ScriptBlock]){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' -1 $null $null}\n    if([string]::IsNullOrWhiteSpace($declaredBinaryDll) -or [IO.Path]::GetFileName($declaredBinaryDll) -cne $declaredBinaryDll -or -not $declaredBinaryDll.EndsWith('.dll',[StringComparison]::Ordinal)){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' -1 $null $block}\n    $expectedAssemblyName=[IO.Path]::GetFileNameWithoutExtension($declaredBinaryDll)\n    $nested=@($module.NestedModules);$scriptNode=$null;$binaryNode=$null;$scriptCount=0;$binaryCount=0\n    if($nested.Count -ne 2){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' -1 $null $block}\n    for($index=0;$index -lt $nested.Count;$index++){\n        $node=$nested[$index]\n        if($null -eq $node -or $node.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $node -isnot [Management.Automation.PSModuleInfo]){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' $index $node $block}\n        if([Object]::ReferenceEquals($node,$block.Module)){\n            if([string]$node.ModuleType -cne 'Script'){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' $index $node $block}\n            $scriptNode=$node;$scriptCount++\n        }elseif([string]$node.ModuleType -ceq 'Binary'){$binaryNode=$node;$binaryCount++}\n        else{Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' $index $node $block}\n    }\n    if($scriptCount -ne 1 -or $binaryCount -ne 1 -or -not [Object]::ReferenceEquals($scriptNode,$block.Module)){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_DEFINING_MODULE' -1 $scriptNode $block}\n    $assembly=$binaryNode.ImplementingAssembly\n    if($null -eq $assembly -or $assembly -isnot [Reflection.Assembly] -or $assembly.IsDynamic -or $assembly.GetName().Name -cne $expectedAssemblyName){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED' -1 $binaryNode $block}\n    # A manifest can export a strict subset of its binary child's commands.\n    # Join that actual nonempty subset, not unexported binary extras.\n    $anchors=0\n    foreach($entry in $module.ExportedCmdlets.GetEnumerator()){\n        $selected=$entry.Value\n        if($null -eq $selected -or $selected.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $selected -isnot [Management.Automation.CmdletInfo] -or $entry.Key -cne $selected.Name -or -not $binaryNode.ExportedCmdlets.ContainsKey($entry.Key)){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT' -1 $binaryNode $block}\n        $counterpart=$binaryNode.ExportedCmdlets[$entry.Key]\n        $selectedType=$selected.ImplementingType;$binaryType=if($null -ne $counterpart){$counterpart.ImplementingType}else{$null}\n        if($null -eq $counterpart -or $counterpart.GetType().FullName -cne 'System.Management.Automation.CmdletInfo' -or $counterpart -isnot [Management.Automation.CmdletInfo] -or $counterpart.Name -cne $entry.Key -or $null -eq $selectedType -or $selectedType -isnot [Type] -or $null -eq $binaryType -or $binaryType -isnot [Type] -or -not [Object]::ReferenceEquals($selectedType,$binaryType) -or -not [Object]::ReferenceEquals($selectedType.Assembly,$assembly) -or -not [Object]::ReferenceEquals($binaryType.Assembly,$assembly)){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT' -1 $binaryNode $block}\n        $anchors++\n    }\n    if($anchors -lt 1){Stop-PublicNativeUtilityFunctionGraph 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT' -1 $binaryNode $block}\n    return ,$scriptNode\n}\nfunction Assert-PublicNativeUtilityFunctionProvider([Management.Automation.FunctionInfo]$command){\n    $noBomCodePage=Resolve-PublicNativeProviderNoBomCodePage ([Version]$PSVersionTable.PSVersion) ([string]$PSVersionTable.PSEdition) ([Text.Encoding]::Default.CodePage) ([Environment]::OSVersion.Platform) ([Object].Assembly.GetName().Name)\n    if($null -eq $command -or $command.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $command.Name -cne 'Get-FileHash' -or $command.ModuleName -cne 'Microsoft.PowerShell.Utility' -or $command.Source -cne 'Microsoft.PowerShell.Utility'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_COMMAND'}\n    $providerHome=[IO.Path]::GetFullPath([string]$PSHOME)\n    $modulesPath=[IO.Path]::Combine($providerHome,'Modules');$manifestDirectory=[IO.Path]::Combine($modulesPath,'Microsoft.PowerShell.Utility')\n    $manifestPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psd1'))\n    $scriptPath=[IO.Path]::GetFullPath([IO.Path]::Combine($manifestDirectory,'Microsoft.PowerShell.Utility.psm1'))\n    $comparison=if([IO.Path]::DirectorySeparatorChar -eq [char]92){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}\n    $baseTrim=[char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)\n    $module=$command.Module;$block=$command.ScriptBlock\n    if($null -eq $module -or $module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $module -isnot [Management.Automation.PSModuleInfo] -or $module.Name -cne 'Microsoft.PowerShell.Utility' -or [string]$module.ModuleType -cne 'Manifest' -or [string]$module.RootModule -cne ''){throw 'PUBLIC_NATIVE_HASH_FUNCTION_MANIFEST'}\n    if($null -eq $block -or $block -isnot [Management.Automation.ScriptBlock] -or $null -eq $block.Module -or $block.Module.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $block.Module -isnot [Management.Automation.PSModuleInfo]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_BLOCK'}\n    foreach($path in @([string]$module.Path,[string]$module.ModuleBase,[string]$block.File,[string]$block.Module.Path,[string]$block.Module.ModuleBase)){if([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN'}}\n    Assert-PublicNativeUtilityFunctionOrigins $manifestPath ([IO.Path]::GetFullPath($module.Path)) ([IO.Path]::GetFullPath($module.ModuleBase).TrimEnd($baseTrim)) $scriptPath ([IO.Path]::GetFullPath($block.File)) ([IO.Path]::GetFullPath($block.Module.Path)) ([IO.Path]::GetFullPath($block.Module.ModuleBase).TrimEnd($baseTrim)) $comparison\n    $directories=@($providerHome,$modulesPath,$manifestDirectory);$directoryStates=@()\n    foreach($path in $directories){$info=[IO.DirectoryInfo]::new($path);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DIRECTORY'};$directoryStates+=,([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes)}\n    $manifestInfo=[IO.FileInfo]::new($manifestPath);$scriptInfo=[IO.FileInfo]::new($scriptPath)\n    foreach($info in @($manifestInfo,$scriptInfo)){$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory))){throw 'PUBLIC_NATIVE_HASH_FUNCTION_FILE'}}\n    if($manifestInfo.Length -lt 1 -or $manifestInfo.Length -gt 131072 -or $scriptInfo.Length -lt 1 -or $scriptInfo.Length -gt 8388608){throw 'PUBLIC_NATIVE_HASH_FUNCTION_FILE_BOUND'}\n    $manifestState=([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes)\n    $scriptState=([string]$scriptInfo.Length+':'+[string]$scriptInfo.CreationTimeUtc.Ticks+':'+[string]$scriptInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$scriptInfo.Attributes)\n    $manifestStream=$null;$scriptStream=$null;$sha=$null\n    try{\n        $manifestStream=[IO.File]::Open($manifestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        $scriptStream=[IO.File]::Open($scriptPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)\n        if($manifestStream.Length -ne $manifestInfo.Length -or $scriptStream.Length -ne $scriptInfo.Length){throw 'PUBLIC_NATIVE_HASH_FUNCTION_GENERATION'}\n        $manifestRaw=[byte[]]::new([int]$manifestStream.Length);$offset=0\n        while($offset -lt $manifestRaw.Length){$count=$manifestStream.Read($manifestRaw,$offset,$manifestRaw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'};$offset+=$count}\n        if($manifestStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'}\n        $scriptRaw=[byte[]]::new([int]$scriptStream.Length);$offset=0\n        while($offset -lt $scriptRaw.Length){$count=$scriptStream.Read($scriptRaw,$offset,$scriptRaw.Length-$offset);if($count -le 0){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'};$offset+=$count}\n        if($scriptStream.ReadByte() -ne -1){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EOF'}\n        $sha=[Security.Cryptography.SHA256]::Create();$manifestHash=[Convert]::ToBase64String($sha.ComputeHash($manifestRaw));$scriptHash=[Convert]::ToBase64String($sha.ComputeHash($scriptRaw))\n        Confirm-PublicNativeProviderDecodeInput 'manifest' $manifestPath $manifestRaw $manifestHash $noBomCodePage\n        $fields=Read-PublicNativeUtilityManifest $manifestRaw $noBomCodePage\n        if($module.Guid -ne [Guid]::Parse($fields['GUID'][0]) -or $module.Version -ne [Version]::Parse($fields['ModuleVersion'][0])){throw 'PUBLIC_NATIVE_HASH_FUNCTION_IDENTITY'}\n        if($fields['NestedModules'].Length -ne 2 -or -not ($fields['NestedModules'] -ccontains 'Microsoft.PowerShell.Utility.psm1') -or -not ($fields['NestedModules'] -ccontains 'Microsoft.PowerShell.Commands.Utility.dll') -or -not ($fields['FunctionsToExport'] -ccontains 'Get-FileHash')){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DECLARATION'}\n        $declaredBinaryDll=$null\n        foreach($declared in $fields['NestedModules']){if($declared -ceq 'Microsoft.PowerShell.Commands.Utility.dll'){$declaredBinaryDll=[string]$declared}}\n        $scriptNode=Resolve-PublicNativeUtilityFunctionNodes $module $block $declaredBinaryDll\n        # The declared script node authenticates the Function provider. Its\n        # genuine ModuleBase is only compared for graph consistency: no path\n        # is derived from it and no unmeasured GAC/DLL layout is assumed.\n        $exported=$null;$exportCount=0\n        foreach($entry in $module.ExportedFunctions.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$exported=$entry.Value;$exportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}}}\n        if($exportCount -ne 1 -or $null -eq $exported -or $exported.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $exported -isnot [Management.Automation.FunctionInfo] -or $exported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($exported.ScriptBlock,$block)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}\n        $nestedExported=$null;$nestedExportCount=0\n        foreach($entry in $scriptNode.ExportedFunctions.GetEnumerator()){if($entry.Key -ieq 'Get-FileHash'){$nestedExported=$entry.Value;$nestedExportCount++;if($entry.Key -cne 'Get-FileHash'){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}}}\n        if($nestedExportCount -ne 1 -or $null -eq $nestedExported -or $nestedExported.GetType().FullName -cne 'System.Management.Automation.FunctionInfo' -or $nestedExported -isnot [Management.Automation.FunctionInfo] -or $nestedExported.Name -cne 'Get-FileHash' -or -not [Object]::ReferenceEquals($nestedExported.ScriptBlock,$block)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT'}\n        Confirm-PublicNativeProviderDecodeInput 'script' $scriptPath $scriptRaw $scriptHash $noBomCodePage\n        $tokens=$null;$errors=$null;$scriptTree=[Management.Automation.Language.Parser]::ParseInput((ConvertFrom-PublicNativeProviderBytes $scriptRaw $noBomCodePage),[ref]$tokens,[ref]$errors)\n        if($null -ne $errors -and $errors.Length){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_PARSE'}\n        $definitions=@($scriptTree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ieq 'Get-FileHash'},$true))\n        if($definitions.Count -ne 1 -or $definitions[0].Name -cne 'Get-FileHash' -or $block.Ast -isnot [Management.Automation.Language.ScriptBlockAst] -or $block.Ast.Extent.Text -cne $definitions[0].Body.Extent.Text){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_BODY'}\n        $manifestStream.Position=0;$scriptStream.Position=0\n        if([Convert]::ToBase64String($sha.ComputeHash($manifestStream)) -cne $manifestHash -or [Convert]::ToBase64String($sha.ComputeHash($scriptStream)) -cne $scriptHash){throw 'PUBLIC_NATIVE_HASH_FUNCTION_SOURCE_CHANGED'}\n        $manifestInfo.Refresh();$scriptInfo.Refresh()\n        if(([string]$manifestInfo.Length+':'+[string]$manifestInfo.CreationTimeUtc.Ticks+':'+[string]$manifestInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$manifestInfo.Attributes) -cne $manifestState -or ([string]$scriptInfo.Length+':'+[string]$scriptInfo.CreationTimeUtc.Ticks+':'+[string]$scriptInfo.LastWriteTimeUtc.Ticks+':'+[string][int]$scriptInfo.Attributes) -cne $scriptState){throw 'PUBLIC_NATIVE_HASH_FUNCTION_GENERATION'}\n        for($index=0;$index -lt $directories.Count;$index++){$info=[IO.DirectoryInfo]::new($directories[$index]);$info.Refresh();if(-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ([string]$info.CreationTimeUtc.Ticks+':'+[string][int]$info.Attributes) -cne $directoryStates[$index]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DIRECTORY'}}\n    }finally{\n        try{if($null -ne $sha){$sha.Dispose()}}finally{try{if($null -ne $scriptStream){$scriptStream.Dispose()}}finally{if($null -ne $manifestStream){$manifestStream.Dispose()}}}\n    }\n}\n$actor=[Security.Principal.WindowsIdentity]::GetCurrent().User;if($null -eq $actor){throw 'PUBLIC_NATIVE_ACTOR_MISSING'}\n# A fresh -NoProfile child can begin with Utility loaded. Remove only the\n# authentic module from this runtime so both cases actually exercise autoload.\n$runtimeRoot=[IO.Path]::GetFullPath([string]$PSHOME).TrimEnd('\\')+'\\'\n$utilityRoot=[IO.Path]::GetFullPath([IO.Path]::Combine([string]$PSHOME,'Modules\\Microsoft.PowerShell.Utility')).TrimEnd('\\')\nif(-not [IO.Directory]::Exists($utilityRoot)){throw 'PUBLIC_NATIVE_UTILITY_ROOT_MISSING'}\n$utility=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\nif($utility.Count -gt 8){throw 'PUBLIC_NATIVE_UTILITY_MODULE_COUNT'}\nforeach($module in $utility){if($module.Name -cne 'Microsoft.PowerShell.Utility' -or [IO.Path]::GetFullPath($module.ModuleBase).TrimEnd('\\') -ine $utilityRoot){throw 'PUBLIC_NATIVE_UTILITY_MODULE_IDENTITY'};Remove-Module -ModuleInfo $module -Force -ErrorAction Stop}\n# PUBLIC_COLD_OBSERVATION_BEGIN\n$coldBefore=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\n$coldHash=@();foreach($candidate in @(Get-Command -Name 'Get-FileHash*' -ListImported -ErrorAction SilentlyContinue)){if($candidate.Name -ieq 'Get-FileHash'){$coldHash+=,$candidate}}\n$coldAfter=@(Get-Module -Name Microsoft.PowerShell.Utility -All -ErrorAction Stop)\n[Console]::Out.WriteLine(('PUBLIC_NATIVE_COLD_OBSERVATION:'+([string]$coldBefore.Count)+':'+([string]$coldAfter.Count)+':'+([string]$coldHash.Count)))\nif($coldBefore.Count -or $coldAfter.Count -or $coldHash.Count){throw 'PUBLIC_NATIVE_UTILITY_NOT_COLD'}\n# PUBLIC_COLD_OBSERVATION_END\n[Console]::Out.WriteLine(('PUBLIC_NATIVE_UTILITY_COLD:'+([string]$utility.Count)))\n$missing=@();foreach($name in @('Get-Acl','Get-FileHash')){\n    try{$commands=@(Get-Command -Name $name -CommandType Cmdlet,Function -ErrorAction Stop)}catch{$missing+=,$name;continue}\n    if($commands.Count -ne 1){throw 'PUBLIC_NATIVE_COMMAND_COUNT'}\n    $command=$commands[0];$kind=[string]$command.CommandType;$moduleName=[string]$command.ModuleName;$runtimeType=$command.GetType().FullName\n    $expectedModule=if($name -ceq 'Get-Acl'){'Microsoft.PowerShell.Security'}else{'Microsoft.PowerShell.Utility'}\n    if($moduleName -cne $expectedModule -or $null -eq $command.Module){throw 'PUBLIC_NATIVE_COMMAND_MODULE'}\n    if(($kind -ceq 'Cmdlet' -and $runtimeType -ceq 'System.Management.Automation.CmdletInfo' -and $command -is [Management.Automation.CmdletInfo]) -or ($kind -ceq 'Function' -and $runtimeType -ceq 'System.Management.Automation.FunctionInfo' -and $command -is [Management.Automation.FunctionInfo])){}else{throw 'PUBLIC_NATIVE_COMMAND_TYPE'}\n    $modulePath=[IO.Path]::GetFullPath($command.Module.Path)\n    if(-not $modulePath.StartsWith($runtimeRoot,[StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($modulePath)){throw 'PUBLIC_NATIVE_COMMAND_RUNTIME'}\n    if($name -ceq 'Get-FileHash'){\n        if($kind -ceq 'Function'){Assert-PublicNativeUtilityFunctionProvider $command}else{Assert-PublicNativeUtilityCmdletProvider $command}\n    }\n    [Console]::Out.WriteLine(('PUBLIC_NATIVE_COMMAND:'+$name+':'+$moduleName+':'+$kind+':'+$runtimeType))\n}\nif($missing.Count){[Console]::Error.WriteLine(('PUBLIC_NATIVE_MISSING:'+($missing -join ',')));exit 11}\n$path=$args[0];$expectedHash=$args[1]\n$acl=Get-Acl -LiteralPath $path -ErrorAction Stop;$physical=[IO.File]::GetAccessControl($path)\n$sections=[Security.AccessControl.AccessControlSections]::All;$sidType=[Security.Principal.SecurityIdentifier]\nif($acl.Sddl -cne $physical.GetSecurityDescriptorSddlForm($sections) -or $acl.GetOwner($sidType).Value -cne $physical.GetOwner($sidType).Value){throw 'PUBLIC_NATIVE_ACL_MISMATCH'}\n$actualHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()\nif($actualHash -cne $expectedHash){throw 'PUBLIC_NATIVE_HASH_MISMATCH'}\n[Console]::Out.WriteLine('PUBLIC_NATIVE_MODULE_ACL_HASH_PASS')\n"

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
    if type(case) is not str or case not in ('bad_module_path', 'sanitized', 'exact_c', 'unfixed_g', 'unfixed_i'):
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


J_NATIVE_OWNED_SETUP_BEFORE = b"owned = Path(directory)\nempty_modules = owned / 'empty-modules'\nempty_modules.mkdir(mode=0o700)\ndata = owned / 'PUBLIC.bytes'\nwith data.open('xb') as stream:\n    stream.write(public)\n"
J_NATIVE_OWNED_SETUP_PROVENANCE = {'sourceCommit': '95f18a92bdd4dc450aca0cbf26fb01e894e03e3a', 'sourcePath': 'agent_tools/tests/test_windows_powershell_environment.py', 'wholeSourceSha256': 'c1e6acb0e937ed97c5ab8192c6d3e906cb7e41cdf73c16ee8b14e125b5e01ba6', 'wholeSourceBytes': 168227, 'firstLine': 575, 'lastLine': 580, 'spanStartByte': 67206, 'spanEndByte': 67485, 'indentedSpanSha256': '86259c5b1c0b9defdf9bf23ac5dd9ed9226a9e8baf760a572a7cc91c19afc4dd', 'indentedSpanBytes': 279, 'transformation': 'textwrap.dedent only; complete original owned/data setup statement block, no reconstructed old logic', 'fragmentSha256': '2ecf957e77b872f5fea52d9c610645efd7e2a687b6368939a5fb1db11d26f11a', 'fragmentBytes': 183}


def native_provider_canonical_owned_data(owned, data, expected):
    """Normalize an admitted owned file name; aliases never bypass custody."""
    from agent_tools import source_module_loader
    owned, data = Path(owned), Path(data)
    if data.parent != owned or not owned.is_absolute():
        raise ValueError('native-provider-owned-data-parent')
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    generation = lambda path: tuple(getattr(path.stat(follow_symlinks=False), key) for key in fields)
    # The original spelling is opened first. This must reject a reparse/symlink
    # before resolve() can erase that evidence; its ancestors remain held here.
    with source_module_loader._bootstrap_source(data) as (original, original_closing):
        if original != expected or hashlib.sha256(original).digest() != hashlib.sha256(expected).digest():
            raise ValueError('native-provider-owned-data-bytes')
        original_file = generation(data)
        original_parent = generation(owned)
        canonical_data = data.resolve(strict=True)
        canonical_owned = canonical_data.parent
        with source_module_loader._bootstrap_source(canonical_data) as (observed, canonical_closing):
            if (not data.samefile(canonical_data) or not owned.samefile(canonical_owned)
                    or generation(canonical_data) != original_file
                    or generation(canonical_owned) != original_parent):
                raise ValueError('native-provider-owned-data-identity')
            if observed != original or hashlib.sha256(observed).digest() != hashlib.sha256(expected).digest():
                raise ValueError('native-provider-owned-data-bytes')
            original_closing()
            canonical_closing()
        original_closing()
    return canonical_owned, canonical_data


@unittest.skipUnless(os.name == 'nt', 'Actual Windows PowerShell module/ACL/hash control')
class NativeWindowsPowerShellEnvironmentTests(unittest.TestCase):
    def test_owned_missing_module_path_old_refuses_current_acl_and_hash_complete(self):
        # Three distinct causal proofs use separate exact retained programs,
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
        i_path = (AUTHENTIC_FIXTURE / 'native_module_i.before.ps1').resolve()
        wrapper_path = (AUTHENTIC_FIXTURE / 'native_provider_custody.ps1').resolve()
        runtime = native_provider_evidence_root()
        evidence = runtime / ('windows-powershell-native-c-g-i-' + uuid.uuid4().hex)
        evidence.mkdir(mode=0o700)

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
            elif name == 'i-causal-proof.private.json':
                emit_native_i_causal_marker(value)

        provider_directories = {}
        try:
            with tempfile.TemporaryDirectory(prefix='windows-native-module-path-') as directory, \
                    source_module_loader._bootstrap_source(c_path) as (c_raw, c_closing), \
                    source_module_loader._bootstrap_source(g_path) as (g_raw, g_closing), \
                    source_module_loader._bootstrap_source(i_path) as (i_raw, i_closing), \
                    source_module_loader._bootstrap_source(wrapper_path) as (wrapper_raw, wrapper_closing):
                self.assertEqual((len(c_raw), hashlib.sha256(c_raw).hexdigest()), (1076, NATIVE_C_SCRIPT_SHA256))
                self.assertEqual((len(g_raw), hashlib.sha256(g_raw).hexdigest()), (3981, NATIVE_G_SCRIPT_SHA256))
                self.assertEqual((len(i_raw), hashlib.sha256(i_raw).hexdigest()), (30316, NATIVE_I_SCRIPT_SHA256))
                self.assertEqual((len(wrapper_raw), hashlib.sha256(wrapper_raw).hexdigest()), (18076, NATIVE_PROVIDER_WRAPPER_SHA256))
                owned = Path(directory)
                empty_modules = owned / 'empty-modules'
                empty_modules.mkdir(mode=0o700)
                data = owned / 'PUBLIC.bytes'
                with data.open('xb') as stream:
                    stream.write(public)
                owned, data = native_provider_canonical_owned_data(owned, data, public)
                preserve('PUBLIC.bytes', public)
                inherited = {key: value for key, value in parent_before.items() if key.casefold() != 'psmodulepath'}
                inherited['PSModulePath'] = str(empty_modules)
                supplied_before = dict(inherited)
                sanitized_environment = windows_powershell_environment(executable, inherited)
                self.assertEqual(inherited, supplied_before)
                self.assertEqual(dict(os.environ), parent_before)
                records = []
                native_transport_bytes = 0

                def publish_capture(label, stdout, stderr, returncode, **flags):
                    nonlocal native_transport_bytes
                    captured = io.StringIO()
                    with redirect_stdout(captured):
                        emit_native_capture_marker(label, stdout, stderr, returncode, **flags)
                    text = captured.getvalue()
                    native_transport_bytes += len(text.encode('utf-8', errors='strict'))
                    self.assertLessEqual(native_transport_bytes, 16777216)
                    print(text, end='', flush=True)

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
                    provider_directory = None
                    custody_nonce = None
                    if label in ('unfixed_i', 'sanitized'):
                        custody_nonce = uuid.uuid4().hex
                        provider_directory = evidence / (label + '.' + custody_nonce)
                        provider_directory.mkdir(mode=0o700)
                        provider_directories[label] = provider_directory
                        argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(wrapper_path),
                                '-SourcePath', str(script), '-DataPath', str(data), '-ExpectedDataSha256', digest,
                                '-EvidenceDirectory', str(provider_directory), '-Case', label,
                                '-ExpectedSourceSha256', hashlib.sha256(raw).hexdigest(),
                                '-ExpectedSourceBytes', str(len(raw)), '-CustodyNonce', custody_nonce]
                    else:
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
                        i_closing()
                        wrapper_closing()
                        document(label + '.intent.private.json',
                                 {'schemaVersion': 1, 'state': 'SINGLE_OWNED_NATIVE_SUBMISSION_INTENT_NO_REPLAY',
                                  'argv': argv, 'sourceSha256': hashlib.sha256(raw).hexdigest(),
                                  'carrierSha256': hashlib.sha256(carrier).hexdigest(), 'dataSha256': digest,
                                  'sourceHeld': True, 'sameOwnedDataFileArgument': True,
                                  'sanitizedEnvironment': True, 'custodyNonce': custody_nonce,
                                  'providerEvidenceDirectory': None if provider_directory is None else str(provider_directory),
                                  'wrapperSha256': None if provider_directory is None else NATIVE_PROVIDER_WRAPPER_SHA256})
                        try:
                            result = subprocess.run(argv, env=environment, capture_output=True, timeout=30, check=False)
                        except subprocess.TimeoutExpired as failure:
                            preserve(label + '.stdout.private', failure.stdout or b'')
                            preserve(label + '.stderr.private', failure.stderr or b'')
                            document(label + '.terminal.private.json',
                                     {'state': 'TIMEOUT_NO_REPLAY', 'exit': None, 'stdoutEof': False,
                                      'stderrEof': False, 'completedProcessReturned': False, 'sourceClosing': False})
                            publish_capture(label, failure.stdout or b'', failure.stderr or b'', None,
                                                       stdout_eof=False, stderr_eof=False,
                                                       completed_process_returned=False, source_closing=False)
                            raise
                        preserve(label + '.stdout.private', result.stdout)
                        preserve(label + '.stderr.private', result.stderr)
                        preserve(label + '.exit.private', str(result.returncode).encode('ascii'))
                        self.assertLessEqual(len(result.stdout), 2097152, 'NATIVE_STDOUT_2MIB_BOUND')
                        self.assertLessEqual(len(result.stderr), 2097152, 'NATIVE_STDERR_2MIB_BOUND')
                        try:
                            carrier_closing()
                            data_closing()
                            c_closing()
                            g_closing()
                            i_closing()
                            wrapper_closing()
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
                        publish_capture(label, result.stdout, result.stderr, result.returncode,
                                                   stdout_eof=True, stderr_eof=True,
                                                   completed_process_returned=True, source_closing=True)
                        record = {'case': label, 'exit': result.returncode, 'stdout': result.stdout,
                                  'stderr': result.stderr, 'stdoutEof': True, 'stderrEof': True,
                                  'completedProcessReturned': True, 'sourceClosing': True, 'evidence': str(evidence)}
                        if provider_directory is not None:
                            try:
                                record['providerCapture'] = native_provider_file_snapshot(provider_directory)
                                record['providerCapture']['case'] = label
                                record['providerCaptureError'] = None
                            except BaseException as failure:
                                record['providerCapture'] = {'case': label, 'directory': str(provider_directory), 'files': {}}
                                record['providerCaptureError'] = repr(failure)
                            record['providerSource'] = raw
                            record['providerCarrier'] = carrier
                            record['providerScript'] = str(script)
                            record['custodyNonce'] = custody_nonce
                        records.append({key: value for key, value in record.items()
                                    if not key.startswith('provider') and key != 'custodyNonce'})
                        return record

                counterfactual_g = run_owned('unfixed_g', g_raw, sanitized_environment)
                counterfactual_i = run_owned('unfixed_i', i_raw, sanitized_environment)
                current = run_owned('sanitized', corrected_raw, sanitized_environment)
                counterfactual_c = run_owned('exact_c', c_raw, sanitized_environment)
                self.assertEqual(sanitized_environment, windows_powershell_environment(executable, inherited))
                custody_error = None
                common_i = common_current = None
                try:
                    for item in (counterfactual_i, current):
                        if item['providerCaptureError'] is not None:
                            raise ValueError(item['providerCaptureError'])
                    common_i = native_provider_custody_admission(
                        counterfactual_i['providerCapture'], 'unfixed_i', i_raw, counterfactual_i['providerCarrier'],
                        counterfactual_i['providerScript'], data, public, digest, counterfactual_i['custodyNonce'])
                    common_current = native_provider_custody_admission(
                        current['providerCapture'], 'sanitized', corrected_raw, current['providerCarrier'],
                        current['providerScript'], data, public, digest, current['custodyNonce'])
                    same_inputs = common_i == common_current and all(
                        counterfactual_i['providerCapture']['files'][name] == current['providerCapture']['files'][name]
                        for name in ('manifest.raw', 'script.raw'))
                    if not same_inputs:
                        raise ValueError('native-provider-crosscase-inputs-changed')
                except (ValueError, KeyError, UnicodeError) as failure:
                    custody_error = repr(failure)
                    same_inputs = False
                provider_public = io.StringIO()
                with redirect_stdout(provider_public):
                    provider_packet = emit_native_provider_custody_capture(
                        [counterfactual_i['providerCapture'], current['providerCapture']], same_inputs, native_transport_bytes)
                decoded_packet = decode_native_provider_custody_capture(provider_public.getvalue())
                self.assertEqual(decoded_packet['archive'], provider_packet['archive'])
                print(provider_public.getvalue(), end='', flush=True)
                document('provider-custody-transport.private.json',
                         {'schemaVersion': 1, 'state': 'DIAGNOSTIC_ONLY_NOT_NATIVE_ADMISSION',
                          'nativeTransportBytes': native_transport_bytes,
                          'providerTransportBytes': provider_packet['transportBytes'],
                          'archiveSha256': hashlib.sha256(provider_packet['archive']).hexdigest(),
                          'equivalent': same_inputs, 'custodyError': custody_error,
                          'allObservedFilesPubliclyRetained': provider_packet['manifest']['allObservedFilesPubliclyRetained'],
                          'omittedSecondaryRawBytes': provider_packet['manifest']['omittedSecondaryRawBytes'],
                          'bothFullPrivatePairsRequireAlwaysUploadedOwnedRoot': True})
                self.assertIsNone(custody_error, records)
                self.assertTrue(same_inputs, records)
                self.assertTrue(provider_packet['manifest']['allObservedFilesPubliclyRetained'], records)
                self.assertEqual(provider_packet['manifest']['omittedSecondaryRawBytes'], 0, records)
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

                self.assertEqual(counterfactual_i['exit'], 1, records)
                i_error_ids = [b' '.join(line.split()) for line in counterfactual_i['stderr'].splitlines()
                               if b'FullyQualifiedErrorId' in line]
                self.assertEqual(i_error_ids, [b'+ FullyQualifiedErrorId : DecoderFallbackException'], records)
                self.assertIn(b'[Text.UTF8Encoding]::new($false,$true).GetString($raw)', counterfactual_i['stderr'], records)
                i_facts = native_command_observations(counterfactual_i['stdout'])
                self.assertEqual(i_facts['coldObservation'], (0, 0, 0), records)
                self.assertEqual([item['name'] for item in i_facts['commands']], ['Get-Acl'], records)
                self.assertIs(i_facts['oraclePassed'], False, records)
                provider_raw_bytes = sum(len(counterfactual_i['providerCapture']['files'][name]) for name in ('manifest.raw', 'script.raw'))
                self.assertLessEqual(provider_raw_bytes, 8519680, records)
                c_closing(); g_closing(); i_closing(); wrapper_closing()
                document('i-causal-proof.private.json',
                         {'schemaVersion': 1, 'state': 'EXACT_I_STRICT_UTF8_DECODER_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
                          'iExit': counterfactual_i['exit'], 'correctedExit': current['exit'],
                          'iErrorId': 'DecoderFallbackException', 'iSourceSha256': NATIVE_I_SCRIPT_SHA256,
                          'iSourceBytes': len(i_raw), 'correctedSourceSha256': hashlib.sha256(corrected_raw).hexdigest(),
                          'dataSha256': digest, 'providerInputsSha256': hashlib.sha256(_native_provider_json(common_i)).hexdigest(),
                          'providerRawBytes': provider_raw_bytes, 'observedHashCommand': current_hash,
                          'sourceClosing': True, 'allFourCompletedProcessReturned': all(item['completedProcessReturned'] for item in records),
                          'allFourStdoutEof': all(item['stdoutEof'] for item in records),
                          'allFourStderrEof': all(item['stderrEof'] for item in records),
                          'sameSanitizedEnvironment': True, 'sameOwnedDataBytesAndHash': True,
                          'sameOwnedDataFileArgument': True, 'physicalAclAndHashOracleCompleted': True,
                          'sameHeldProviderInputsAndPolicyContext': same_inputs, 'providerRawRetainedOnce': True,
                          'exactCGProofsSeparate': True, 'historicalIFailureInputAttributionStillUnknown': True})
        finally:
            original_error = sys.exc_info()[1]
            try:
                document('artifact-manifest.private.json', native_provider_artifact_manifest(evidence, provider_directories))
            except BaseException as failure:
                preserve('artifact-manifest-error.private', repr(failure).encode('utf-8', errors='strict'))
                if original_error is None:
                    raise
                print('PUBLIC_NATIVE_ARTIFACT_MANIFEST_REFUSED:' + repr(failure), file=sys.stderr, flush=True)


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
        self.assertIn(manifest['case'], ('bad_module_path', 'sanitized', 'exact_c', 'unfixed_g', 'unfixed_i'))
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


_NATIVE_PROVIDER_FILES = ('body-intent.record', 'closing.record', 'context.record',
                          'control.input.record', 'manifest.input.record', 'manifest.join.record',
                          'manifest.raw', 'public-data.input.record', 'script.input.record',
                          'script.join.record', 'script.raw')
_NATIVE_PROVIDER_INPUT_KEYS = 'schemaVersion kind case role pathUtf8Base64 bytes sha256 leadingBytesBase64 generation rawEof shareReadDenyWriteDelete savedRaw recordComplete'.split()
_NATIVE_PROVIDER_JOIN_KEYS = 'schemaVersion kind case role pathUtf8Base64 bytes sha256 existingShaBase64 noBomCodePage exactSnapshotBytesEqual heldGenerationEqual heldHashEqual snapshotRawEof recordComplete'.split()
_NATIVE_PROVIDER_SCHEMAS = {
    'context.record': 'schemaVersion kind case nonce sourcePathUtf8Base64 expectedSourceSha256 expectedSourceBytes dataPathUtf8Base64 dataSha256 psHomeUtf8Base64 psVersion psEdition platform coreAssembly clrVersion defaultCodePage noBomCodePage crossCaseContinuousLock nativeStdoutModified providerLookupBeforeBody recordComplete'.split(),
    'body-intent.record': 'schemaVersion kind case sourceSha256 carrierSha256 sourceBytes originalArgumentCount originalArgumentStringsPreserved bothProviderInputsHeld recordComplete'.split(),
    'closing.record': 'schemaVersion kind case bodyStarted bodyCompleted bodyExit bodyThrew bodyErrorIdUtf8Base64 bodyErrorTypeUtf8Base64 enrolledHandles disposedHandles custodyClosingOk manifestJoin scriptJoin cleanupErrorsUtf8Base64 crossCaseContinuousLock rawPairTransported nativeAdmissionClaim recordComplete'.split(),
    **{name: _NATIVE_PROVIDER_INPUT_KEYS for name in ('control.input.record', 'public-data.input.record', 'manifest.input.record', 'script.input.record')},
    **{name: _NATIVE_PROVIDER_JOIN_KEYS for name in ('manifest.join.record', 'script.join.record')},
}


@contextmanager
def native_provider_data_files(paths):
    """Held retained DATA only; executable SourcePath keeps the source bootstrap.

    All DATA use the existing native open/ancestor/fd ownership mechanism before
    reading under explicit caps, including empty retained outputs/partials.
    Existing finish/final_identity_pass/close guards and source caps are unchanged.
    """
    if os.name != 'nt':
        # Portable data controls are small/nonempty; the existing4MiB source
        # guard is unchanged. This is not a general POSIX data reader.
        from agent_tools import source_module_loader
        with ExitStack() as stack:
            result = {}; closings = []
            for path, cap in paths:
                raw, closing = stack.enter_context(source_module_loader._bootstrap_source(path))
                if len(raw) > cap:
                    raise ValueError('native-provider-data-bound')
                result[path] = raw; closings.append(closing)
            for closing in closings: closing()
            yield result
            for closing in closings: closing()
        return
    from agent_tools import windows_source_custody as windows
    import msvcrt
    held = windows.WindowsHeld()
    try:
        # Authenticate the executing primitive at its self-attested source hash.
        held.read(str(Path(windows.__file__).absolute()), windows.LOADED_SHA)
        result = {}
        for path, cap in paths:
            if (type(cap) is not int or cap < 1 or not path.is_absolute() or not path.drive
                    or path.drive.startswith('\\\\') or '..' in path.parts or path in result):
                raise ValueError('native-provider-data-path-or-bound')
            # DATA files are opened with native no-reparse/deny-write-delete
            # custody and pinned ancestors BEFORE any data byte is read.
            for parent in reversed(path.parents):
                if str(parent) not in held.directories:
                    held.directories[str(parent)] = held._open(parent, True)
            handle, identity = held._open(path, False)
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                held.kernel.CloseHandle(handle); raise
            try:
                # Enroll the owned fd before fallible reads, including empty or
                # partial DATA. Executable SourcePath never enters this seam.
                held.files[str(path)] = (fd, identity, b'', hashlib.sha256(b'').hexdigest())
                if not 0 <= identity[4] <= cap: raise ValueError('native-provider-data-bound')
                pieces = []; size = 0
                while True:
                    chunk = os.read(fd, min(65536, cap + 1 - size))
                    if not chunk: break
                    pieces.append(chunk); size += len(chunk)
                    if size > cap: raise ValueError('native-provider-data-bound')
                raw = b''.join(pieces)
                if len(raw) != identity[4]: raise ValueError('native-provider-data-size-or-eof')
                digest = hashlib.sha256(raw).hexdigest()
                held.files[str(path)] = (fd, identity, raw, digest)
            except BaseException:
                if str(path) not in held.files: os.close(fd)
                raise
            held.finish(); held.final_identity_pass(); result[path] = raw
        held.finish(); held.final_identity_pass()
        yield result
        held.finish(); held.final_identity_pass()
    finally:
        held.close()


def native_provider_file_snapshot(directory):
    """Retain whatever exists before admission; partial custody cannot pass."""
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)):
        raise ValueError('native-provider-snapshot-directory')
    paths = sorted(directory.iterdir(), key=lambda path: path.name)
    if len(paths) > 32: raise ValueError('native-provider-snapshot-count')
    bounded = [(path, 8388608 if path.name == 'script.raw' else 131072 if path.name == 'manifest.raw' else 65536) for path in paths]
    with native_provider_data_files(bounded) as held:
        files = {path.name: held[path] for path in paths}
        if sorted(directory.iterdir(), key=lambda path: path.name) != paths:
            raise ValueError('native-provider-snapshot-directory-changed')
    return {'directory': str(directory), 'files': files}


def native_provider_record(raw, name, case):
    if type(raw) is not bytes or not 1 <= len(raw) <= 65536 or b'\r' in raw or not raw.endswith(b'\n'):
        raise ValueError('native-provider-record-bytes')
    text = raw.decode('ascii', errors='strict')
    lines = text[:-1].split('\n')
    if any(len(line.encode('ascii')) + 1 > 16384 or '=' not in line for line in lines):
        raise ValueError('native-provider-record-line')
    pairs = [line.split('=', 1) for line in lines]
    if [key for key, value in pairs] != _NATIVE_PROVIDER_SCHEMAS[name]:
        raise ValueError('native-provider-record-schema')
    row = dict(pairs)
    if row['schemaVersion'] != '1' or row['recordComplete'] != '1' or row['case'] != case:
        raise ValueError('native-provider-record-identity')
    for key, value in pairs:
        if key.endswith('Utf8Base64'):
            data = base64.b64decode(value, validate=True)
            if len(data) > 8192 or base64.b64encode(data).decode('ascii') != value:
                raise ValueError('native-provider-field-base64')
            row[key] = data.decode('utf-8', errors='strict')
        elif key in ('leadingBytesBase64', 'existingShaBase64'):
            data = base64.b64decode(value, validate=True)
            if base64.b64encode(data).decode('ascii') != value:
                raise ValueError('native-provider-field-base64')
            row[key] = data
        elif key.lower().endswith('sha256'):
            if len(value) != 64 or set(value) - set('0123456789abcdef'):
                raise ValueError('native-provider-field-sha256')
        elif key == 'generation':
            values = value.split(':')
            if len(values) != 4 or any(not v.isascii() or not v.isdecimal() or str(int(v)) != v for v in values):
                raise ValueError('native-provider-generation')
        elif key == 'bodyExit':
            if value != 'none' and (str(int(value)) != value or not -(2 ** 31) <= int(value) < 2 ** 31):
                raise ValueError('native-provider-body-exit')
        elif key not in ('kind', 'case', 'role', 'nonce', 'psVersion', 'psEdition', 'platform', 'coreAssembly', 'clrVersion'):
            if not value.isascii() or not value.isdecimal() or str(int(value)) != value:
                raise ValueError('native-provider-field-integer')
    return row


def native_provider_custody_admission(snapshot, case, source, carrier, script, data, public, digest, nonce):
    files = snapshot['files']
    names = set(_NATIVE_PROVIDER_FILES)
    if case == 'unfixed_i':
        names -= {'manifest.join.record', 'script.join.record'}
    if set(files) != names:
        raise ValueError('native-provider-file-set')
    rows = {name: native_provider_record(raw, name, case) for name, raw in files.items() if name.endswith('.record')}
    context = rows['context.record']; intent = rows['body-intent.record']; closing = rows['closing.record']
    source_sha = hashlib.sha256(source).hexdigest()
    if (context['kind'] != 'PROVIDER_CUSTODY_CONTEXT_V1' or context['nonce'] != nonce
            or context['sourcePathUtf8Base64'] != str(script) or context['expectedSourceSha256'] != source_sha
            or context['expectedSourceBytes'] != str(len(source)) or context['dataPathUtf8Base64'] != str(data)
            or context['dataSha256'] != digest or not context['psHomeUtf8Base64']
            or any(context[key] != '0' for key in ('crossCaseContinuousLock', 'nativeStdoutModified', 'providerLookupBeforeBody'))
            or not 1 <= int(context['noBomCodePage']) <= 65535):
        raise ValueError('native-provider-context')
    if (intent['kind'] != 'PROVIDER_CUSTODY_BODY_INTENT_V1' or intent['sourceSha256'] != source_sha
            or intent['carrierSha256'] != hashlib.sha256(carrier).hexdigest() or intent['sourceBytes'] != str(len(source))
            or intent['originalArgumentCount'] != '2'
            or intent['originalArgumentStringsPreserved'] != '1' or intent['bothProviderInputsHeld'] != '1'):
        raise ValueError('native-provider-intent')
    # This native Windows test uses native path semantics. No Windows path is
    # normalized on a foreign host by this admission routine.
    utility = Path(context['psHomeUtf8Base64']) / 'Modules' / 'Microsoft.PowerShell.Utility'
    expected = {'control': (carrier, str(script), False), 'public-data': (public, str(data), False),
                'manifest': (files['manifest.raw'], str(utility / 'Microsoft.PowerShell.Utility.psd1'), True),
                'script': (files['script.raw'], str(utility / 'Microsoft.PowerShell.Utility.psm1'), True)}
    for role, (raw, path, saved) in expected.items():
        row = rows[role + '.input.record']
        cap = 8388608 if role == 'script' else 131072 if role in ('manifest', 'control') else 34
        if (not 1 <= len(raw) <= cap or row['kind'] != 'PROVIDER_CUSTODY_INPUT_V1' or row['role'] != role
                or row['pathUtf8Base64'] != path or row['bytes'] != str(len(raw))
                or row['sha256'] != hashlib.sha256(raw).hexdigest() or row['leadingBytesBase64'] != raw[:4]
                or row['generation'].split(':')[0] != str(len(raw))
                or row['rawEof'] != '1' or row['shareReadDenyWriteDelete'] != '1'
                or row['savedRaw'] != str(int(saved))):
            raise ValueError('native-provider-input')
    if (closing['kind'] != 'PROVIDER_CUSTODY_CLOSING_V1' or closing['bodyStarted'] != '1'
            or closing['enrolledHandles'] != '4' or closing['disposedHandles'] != '4'
            or closing['custodyClosingOk'] != '1' or closing['cleanupErrorsUtf8Base64'] != ''
            or any(closing[key] != '0' for key in ('crossCaseContinuousLock', 'rawPairTransported', 'nativeAdmissionClaim'))):
        raise ValueError('native-provider-closing')
    if case == 'unfixed_i':
        if (closing['bodyCompleted'] != '0' or closing['bodyThrew'] != '1' or closing['bodyExit'] != 'none'
                or closing['bodyErrorIdUtf8Base64'] != 'DecoderFallbackException'
                or not closing['bodyErrorTypeUtf8Base64'] or closing['manifestJoin'] != '0' or closing['scriptJoin'] != '0'):
            raise ValueError('native-provider-unfixed-i-outcome')
    else:
        if (closing['bodyCompleted'] != '1' or closing['bodyThrew'] != '0' or closing['bodyExit'] != '0'
                or closing['bodyErrorIdUtf8Base64'] != '' or closing['bodyErrorTypeUtf8Base64'] != ''
                or closing['manifestJoin'] != '1' or closing['scriptJoin'] != '1'):
            raise ValueError('native-provider-current-outcome')
        for role in ('manifest', 'script'):
            joined = rows[role + '.join.record']; held = rows[role + '.input.record']
            if (joined['kind'] != 'PROVIDER_CUSTODY_DECODE_JOIN_V1' or joined['role'] != role
                    or any(joined[key] != held[key] for key in ('pathUtf8Base64', 'bytes', 'sha256'))
                    or joined['existingShaBase64'] != bytes.fromhex(held['sha256'])
                    or joined['noBomCodePage'] != context['noBomCodePage']
                    or any(joined[key] != '1' for key in ('exactSnapshotBytesEqual', 'heldGenerationEqual', 'heldHashEqual', 'snapshotRawEof'))):
                raise ValueError('native-provider-decode-join')
    common = {key: context[key] for key in ('psHomeUtf8Base64', 'psVersion', 'psEdition', 'platform', 'coreAssembly', 'clrVersion', 'defaultCodePage', 'noBomCodePage')}
    common['inputs'] = [{key: rows[role + '.input.record'][key] for key in ('role', 'pathUtf8Base64', 'bytes', 'sha256', 'generation')} for role in ('manifest', 'script')]
    return common


def _native_provider_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')


def _native_provider_archive(captures, equivalent, omit_secondary):
    entries = []; stored = {}
    for capture in captures:
        case = capture['case']
        for name, raw in sorted(capture['files'].items()):
            if name not in _NATIVE_PROVIDER_FILES or type(raw) is not bytes:
                raise ValueError('native-provider-transport-file')
            cap = 8388608 if name == 'script.raw' else 131072 if name == 'manifest.raw' else 65536
            if len(raw) > cap:
                raise ValueError('native-provider-transport-bound')
            archive_name = case + '/' + name
            if equivalent and case == 'sanitized' and name.endswith('.raw'):
                archive_name = 'unfixed_i/' + name
            if omit_secondary and case == 'sanitized' and name.endswith('.raw'):
                archive_name = None
            if archive_name is not None:
                if archive_name in stored and stored[archive_name] != raw:
                    raise ValueError('native-provider-false-dedupe')
                stored[archive_name] = raw
            entries.append({'case': case, 'name': name, 'privatePath': str(Path(capture['directory']) / name),
                            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'archiveName': archive_name})
    metadata = sum(len(raw) for c in captures for name, raw in c['files'].items() if not name.endswith('.raw'))
    if metadata > 196608:
        raise ValueError('native-provider-metadata-bound')
    manifest = {'schemaVersion': 1, 'kind': 'PROVIDER_CUSTODY_DIAGNOSTIC_ARCHIVE_V1', 'nativeAcceptance': False,
                'equivalent': equivalent, 'allObservedFilesPubliclyRetained': not omit_secondary,
                'omittedSecondaryRawBytes': sum(row['bytes'] for row in entries if row['archiveName'] is None), 'files': entries}
    manifest_raw = _native_provider_json(manifest)
    if len(manifest_raw) > 196608:
        raise ValueError('native-provider-manifest-bound')
    stored['provider-custody.json'] = manifest_raw
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(stored.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); entry.create_system = 3; entry.external_attr = 0o100600 << 16
            archive.writestr(entry, raw)
    return output.getvalue(), manifest


def emit_native_provider_custody_capture(captures, equivalent, existing_transport_bytes):
    """Bounded diagnostic archive, never an additional native actor or PASS."""
    if (type(equivalent) is not bool or type(existing_transport_bytes) is not int or existing_transport_bytes < 0
            or type(captures) is not list or [row['case'] for row in captures] != ['unfixed_i', 'sanitized']):
        raise ValueError('native-provider-transport-input')
    if equivalent:
        for name in ('manifest.raw', 'script.raw'):
            if captures[0]['files'].get(name) != captures[1]['files'].get(name) or name not in captures[0]['files']:
                raise ValueError('native-provider-false-dedupe')
    packet_id = uuid.uuid4().hex
    def render(payload):
        count = (len(payload) + 8191) // 8192; digest = hashlib.sha256(payload).hexdigest()
        frames = [{'schemaVersion': 1, 'kind': 'providerCustodyCapture', 'captureId': packet_id,
                   'bytes': len(payload), 'sha256': digest, 'chunks': count, 'nativeAcceptance': False}]
        for index in range(count):
            part = payload[index * 8192:(index + 1) * 8192]
            frames.append({'schemaVersion': 1, 'kind': 'providerCustodyChunk', 'captureId': packet_id,
                           'chunkIndex': index, 'chunkCount': count, 'rawOffset': index * 8192,
                           'bytes': len(part), 'chunkSha256': hashlib.sha256(part).hexdigest(),
                           'streamBytes': len(payload), 'streamSha256': digest,
                           'base64': base64.b64encode(part).decode('ascii')})
        lines = [('PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:' + _native_provider_json(row).decode('ascii') + '\n') for row in frames]
        if any(len(line.encode('ascii')) > 16384 for line in lines):
            raise ValueError('native-provider-public-line-bound')
        return ''.join(lines)
    payload, manifest = _native_provider_archive(captures, equivalent, False); text = render(payload)
    if len(text.encode('ascii')) > 12582912 and not equivalent:
        payload, manifest = _native_provider_archive(captures, equivalent, True); text = render(payload)
    if len(text.encode('ascii')) > 12582912 or len(text.encode('ascii')) + existing_transport_bytes > 16777216:
        raise ValueError('native-provider-public-packet-bound')
    print(text, end='', flush=True)
    return {'archive': payload, 'manifest': manifest, 'transportBytes': len(text.encode('ascii'))}


def _decode_native_provider_custody_capture(text):
    """Reconstruct the actual emitted bytes; reject partial, reordered or forged frames."""
    if type(text) is not str or not text.endswith('\n') or len(text.encode('utf-8')) > 12582912 or '\r' in text:
        raise ValueError('native-provider-public-text')
    frames = []
    for line in text.splitlines():
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        if not line.startswith(prefix) or len(line.encode('utf-8')) + 1 > 16384:
            raise ValueError('native-provider-public-line')
        row = json.loads(line[len(prefix):])
        if _native_provider_json(row).decode('ascii') != line[len(prefix):]:
            raise ValueError('native-provider-public-canonical-json')
        frames.append(row)
    header = frames[0]
    if (set(header) != {'schemaVersion', 'kind', 'captureId', 'bytes', 'sha256', 'chunks', 'nativeAcceptance'}
            or type(header['schemaVersion']) is not int or header['schemaVersion'] != 1
            or header['kind'] != 'providerCustodyCapture' or header['nativeAcceptance'] is not False
            or type(header['captureId']) is not str or uuid.UUID(hex=header['captureId']).hex != header['captureId']
            or uuid.UUID(hex=header['captureId']).version != 4 or type(header['bytes']) is not int or header['bytes'] < 1
            or type(header['chunks']) is not int or header['chunks'] != (header['bytes'] + 8191) // 8192
            or len(frames) != header['chunks'] + 1):
        raise ValueError('native-provider-public-header')
    parts = []
    for index, row in enumerate(frames[1:]):
        if (set(row) != {'schemaVersion', 'kind', 'captureId', 'chunkIndex', 'chunkCount', 'rawOffset', 'bytes', 'chunkSha256', 'streamBytes', 'streamSha256', 'base64'}
                or type(row['schemaVersion']) is not int or row['schemaVersion'] != 1 or row['kind'] != 'providerCustodyChunk'
                or row['captureId'] != header['captureId']
                or any(type(row[key]) is not int for key in ('chunkIndex', 'chunkCount', 'rawOffset', 'bytes', 'streamBytes'))
                or (row['chunkIndex'], row['chunkCount'], row['rawOffset'], row['streamBytes'], row['streamSha256'])
                != (index, header['chunks'], index * 8192, header['bytes'], header['sha256'])):
            raise ValueError('native-provider-public-chunk')
        raw = base64.b64decode(row['base64'], validate=True)
        if (not 1 <= len(raw) <= 8192 or row['bytes'] != len(raw) or row['chunkSha256'] != hashlib.sha256(raw).hexdigest()
                or base64.b64encode(raw).decode('ascii') != row['base64']):
            raise ValueError('native-provider-public-chunk-hash')
        parts.append(raw)
    payload = b''.join(parts)
    if len(payload) != header['bytes'] or hashlib.sha256(payload).hexdigest() != header['sha256']:
        raise ValueError('native-provider-public-stream-hash')
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        infos = archive.infolist(); names = [row.filename for row in infos]
        if len(names) != len(set(names)) or 'provider-custody.json' not in names or any(row.compress_type != zipfile.ZIP_STORED or row.external_attr >> 16 != 0o100600 for row in infos):
            raise ValueError('native-provider-archive-entries')
        if archive.getinfo('provider-custody.json').file_size > 196608:
            raise ValueError('native-provider-archive-manifest-bound')
        manifest_raw = archive.read('provider-custody.json'); manifest = json.loads(manifest_raw)
        if (_native_provider_json(manifest) != manifest_raw or set(manifest) != {'schemaVersion', 'kind', 'nativeAcceptance', 'equivalent', 'allObservedFilesPubliclyRetained', 'omittedSecondaryRawBytes', 'files'}
                or type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 1
                or manifest['kind'] != 'PROVIDER_CUSTODY_DIAGNOSTIC_ARCHIVE_V1' or manifest['nativeAcceptance'] is not False
                or type(manifest['equivalent']) is not bool or type(manifest['allObservedFilesPubliclyRetained']) is not bool
                or type(manifest['omittedSecondaryRawBytes']) is not int or manifest['omittedSecondaryRawBytes'] < 0
                or type(manifest['files']) is not list):
            raise ValueError('native-provider-archive-manifest')
        keys = []; expected_names = {'provider-custody.json'}; files = {}; omitted = 0; metadata = 0
        for row in manifest['files']:
            if (type(row) is not dict or set(row) != {'case', 'name', 'privatePath', 'bytes', 'sha256', 'archiveName'}
                    or row['case'] not in ('unfixed_i', 'sanitized') or row['name'] not in _NATIVE_PROVIDER_FILES
                    or type(row['privatePath']) is not str or not row['privatePath'] or len(row['privatePath'].encode('utf-8')) > 8192
                    or type(row['bytes']) is not int or row['bytes'] < 0 or type(row['sha256']) is not str
                    or len(row['sha256']) != 64 or set(row['sha256']) - set('0123456789abcdef')):
                raise ValueError('native-provider-archive-file')
            key = (row['case'], row['name']); keys.append(key)
            cap = 8388608 if row['name'] == 'script.raw' else 131072 if row['name'] == 'manifest.raw' else 65536
            if row['bytes'] > cap:
                raise ValueError('native-provider-archive-file-bound')
            if not row['name'].endswith('.raw'): metadata += row['bytes']
            name = row['archiveName']
            if name is None:
                if manifest['equivalent'] or manifest['allObservedFilesPubliclyRetained'] or row['case'] != 'sanitized' or not row['name'].endswith('.raw'):
                    raise ValueError('native-provider-archive-omission')
                omitted += row['bytes']; files[key] = None; continue
            expected = row['case'] + '/' + row['name']
            if manifest['equivalent'] and row['case'] == 'sanitized' and row['name'].endswith('.raw'): expected = 'unfixed_i/' + row['name']
            if name != expected:
                raise ValueError('native-provider-archive-alias')
            expected_names.add(name)
            if archive.getinfo(name).file_size != row['bytes']:
                raise ValueError('native-provider-archive-size')
            raw = archive.read(name)
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('native-provider-archive-sha256')
            files[key] = raw
        order = sorted(keys, key=lambda key: (('unfixed_i', 'sanitized').index(key[0]), key[1]))
        if keys != order or len(keys) != len(set(keys)) or expected_names != set(names) or metadata > 196608 or omitted != manifest['omittedSecondaryRawBytes']:
            raise ValueError('native-provider-archive-order-or-completeness')
        if manifest['allObservedFilesPubliclyRetained'] != (omitted == 0):
            raise ValueError('native-provider-archive-retention-claim')
    return {'archive': payload, 'manifest': manifest, 'files': files}


def emit_native_i_causal_marker(proof):
    """Separate actual-I decoder proof, never admitted by the C/G schemas."""
    flags = ('sourceClosing', 'allFourCompletedProcessReturned', 'allFourStdoutEof',
             'allFourStderrEof', 'sameSanitizedEnvironment', 'sameOwnedDataBytesAndHash',
             'sameOwnedDataFileArgument', 'physicalAclAndHashOracleCompleted',
             'sameHeldProviderInputsAndPolicyContext', 'providerRawRetainedOnce',
             'exactCGProofsSeparate', 'historicalIFailureInputAttributionStillUnknown')
    keys = {'schemaVersion', 'state', 'iExit', 'correctedExit', 'iErrorId',
            'iSourceSha256', 'iSourceBytes', 'correctedSourceSha256', 'dataSha256',
            'providerInputsSha256', 'providerRawBytes', 'observedHashCommand', *flags}
    if (type(proof) is not dict or set(proof) != keys
            or type(proof['schemaVersion']) is not int or proof['schemaVersion'] != 1
            or type(proof['state']) is not str
            or proof['state'] != 'EXACT_I_STRICT_UTF8_DECODER_RED_CORRECTED_PHYSICAL_ORACLE_GREEN'
            or type(proof['iExit']) is not int or proof['iExit'] != 1
            or type(proof['correctedExit']) is not int or proof['correctedExit'] != 0
            or type(proof['iErrorId']) is not str or proof['iErrorId'] != 'DecoderFallbackException'
            or type(proof['iSourceSha256']) is not str or proof['iSourceSha256'] != NATIVE_I_SCRIPT_SHA256
            or type(proof['iSourceBytes']) is not int or proof['iSourceBytes'] != 30316
            or type(proof['providerRawBytes']) is not int or not 1 <= proof['providerRawBytes'] <= 8519680
            or any(type(proof[key]) is not bool or proof[key] is not True for key in flags)):
        raise ValueError('native-public-i-proof-schema')
    for key in ('correctedSourceSha256', 'dataSha256', 'providerInputsSha256'):
        value = proof[key]
        if type(value) is not str or len(value) != 64 or set(value) - set('0123456789abcdef'):
            raise ValueError('native-public-i-proof-source')
    expected = {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'}
    if (type(proof['observedHashCommand']) is not dict or proof['observedHashCommand'] != expected
            or any(type(value) is not str for value in proof['observedHashCommand'].values())):
        raise ValueError('native-public-i-proof-observation')
    _emit_native_public_json({'schemaVersion': 1, 'kind': 'iEncodingCausalProof', 'proof': proof})


def _native_i_causal_proof_control_value():
    """Typed local codec-only value, never a native execution receipt."""
    return {'schemaVersion': 1, 'state': 'EXACT_I_STRICT_UTF8_DECODER_RED_CORRECTED_PHYSICAL_ORACLE_GREEN',
            'iExit': 1, 'correctedExit': 0, 'iErrorId': 'DecoderFallbackException',
            'iSourceSha256': NATIVE_I_SCRIPT_SHA256, 'iSourceBytes': 30316,
            'correctedSourceSha256': '1' * 64, 'dataSha256': '2' * 64,
            'providerInputsSha256': '3' * 64, 'providerRawBytes': 128,
            'observedHashCommand': {'name': 'Get-FileHash', 'moduleName': 'Microsoft.PowerShell.Utility',
                                    'commandType': 'Function', 'runtimeType': 'System.Management.Automation.FunctionInfo'},
            'sourceClosing': True, 'allFourCompletedProcessReturned': True,
            'allFourStdoutEof': True, 'allFourStderrEof': True, 'sameSanitizedEnvironment': True,
            'sameOwnedDataBytesAndHash': True, 'sameOwnedDataFileArgument': True,
            'physicalAclAndHashOracleCompleted': True, 'sameHeldProviderInputsAndPolicyContext': True,
            'providerRawRetainedOnce': True, 'exactCGProofsSeparate': True,
            'historicalIFailureInputAttributionStillUnknown': True}


class NativeIPublicCaptureControlTests(unittest.TestCase):
    """Portable codec controls only; no native child or execution claim."""
    def test_unfixed_i_capture_label_roundtrips_exact_bytes(self):
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_capture_marker('unfixed_i', b'PUBLIC I stdout\r\n', b'PUBLIC I stderr\x00\xff', 1,
                                       stdout_eof=True, stderr_eof=True,
                                       completed_process_returned=True, source_closing=True)
        manifest, streams = NativePublicCaptureControlTests()._decode(captured.getvalue())
        self.assertEqual((manifest['case'], manifest['returncode']), ('unfixed_i', 1))
        self.assertEqual(streams, {'stdout': b'PUBLIC I stdout\r\n', 'stderr': b'PUBLIC I stderr\x00\xff'})

    def test_i_proof_has_a_distinct_exact_envelope(self):
        proof = _native_i_causal_proof_control_value()
        captured = io.StringIO()
        with redirect_stdout(captured):
            emit_native_i_causal_marker(proof)
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        lines = captured.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(prefix))
        self.assertEqual(json.loads(lines[0][len(prefix):]),
                         {'schemaVersion': 1, 'kind': 'iEncodingCausalProof', 'proof': proof})
        with self.assertRaisesRegex(ValueError, '^native-public-proof-schema$'):
            emit_native_causal_marker(proof)
        with self.assertRaisesRegex(ValueError, '^native-public-g-proof-schema$'):
            emit_native_g_causal_marker(proof)

    def test_i_proof_rejects_wrong_types_sources_and_closure(self):
        proof = _native_i_causal_proof_control_value()
        changes = ({'schemaVersion': True}, {'iExit': True}, {'iExit': 0}, {'iSourceBytes': True},
                   {'iSourceSha256': '0' * 64}, {'iErrorId': 'RuntimeException'},
                   {'correctedSourceSha256': 'x' * 64}, {'dataSha256': None},
                   {'providerInputsSha256': 'X' * 64}, {'providerRawBytes': True},
                   {'providerRawBytes': 0}, {'providerRawBytes': 8519681},
                   {'sourceClosing': 1}, {'sameHeldProviderInputsAndPolicyContext': False},
                   {'historicalIFailureInputAttributionStillUnknown': False}, {'extra': 'PUBLIC forbidden'})
        for change in changes:
            with self.subTest(change=change):
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaisesRegex(ValueError, '^native-public-i-'):
                    emit_native_i_causal_marker({**proof, **change})
                self.assertEqual(captured.getvalue(), '')


def decode_native_provider_custody_capture(text):
    try:
        return _decode_native_provider_custody_capture(text)
    except (ValueError, KeyError, TypeError, IndexError, UnicodeError, zipfile.BadZipFile) as failure:
        raise ValueError('native-provider-capture-refused') from failure


def native_provider_evidence_root():
    """An exact workflow scope, or a newly created owned local-native root."""
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        value = os.environ.get(NATIVE_PROVIDER_EVIDENCE_ENV)
        runner_temp = os.environ.get('RUNNER_TEMP')
        run_id = os.environ.get('GITHUB_RUN_ID'); attempt = os.environ.get('GITHUB_RUN_ATTEMPT'); job = os.environ.get('GITHUB_JOB')
        if not value or not runner_temp or not run_id or not attempt or not job:
            raise ValueError('native-provider-workflow-root-required')
        root = Path(value)
        expected = Path(runner_temp) / ('vpn-control-native-provider-' + run_id + '-' + attempt + '-' + job)
        if root != expected or not root.is_absolute():
            raise ValueError('native-provider-workflow-root-scope')
    else:
        runtime = ROOT / '.runtime'; runtime.mkdir(mode=0o700, exist_ok=True)
        root = runtime / ('native-provider-local-' + uuid.uuid4().hex)
    for parent in root.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)):
            raise ValueError('native-provider-root-parent')
    root.mkdir(mode=0o700)  # CreateNew semantics: any pre-existing root is preserved/refused.
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)
            or (hasattr(os, 'getuid') and info.st_uid != os.getuid()) or list(root.iterdir())):
        raise ValueError('native-provider-root-owner-or-not-empty')
    return root


def native_provider_artifact_manifest(evidence, provider_directories):
    """Finite retained DATA only; no redundant log ZIP or Base64 payload copy."""
    roles = ('unfixed_g', 'unfixed_i', 'sanitized', 'exact_c')
    carriers = {'unfixed_g': 3984, 'unfixed_i': 30319,
                'sanitized': len(NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')) + 3, 'exact_c': 1079}
    caps = {'PUBLIC.bytes': 34, 'provider-custody-transport.private.json': 65536,
            'causal-proof.private.json': 16384, 'g-causal-proof.private.json': 16384,
            'i-causal-proof.private.json': 16384, 'artifact-manifest.private.json': 65536,
            'artifact-manifest-error.private': 65536}
    for role in roles:
        caps.update({role + '.control.ps1': carriers[role], role + '.intent.private.json': 131072,
                     role + '.terminal.private.json': 65536, role + '.exit.private': 11,
                     role + '.stdout.private': 2097152, role + '.stderr.private': 2097152})
    if (type(provider_directories) is not dict or set(provider_directories) - {'unfixed_i', 'sanitized'}
            or len(set(provider_directories.values())) != len(provider_directories)):
        raise ValueError('native-provider-artifact-constructor-map')
    for role, path in provider_directories.items():
        nonce = path.name.removeprefix(role + '.')
        if path.parent != evidence or path.name != role + '.' + nonce or len(nonce) != 32 or set(nonce) - set('0123456789abcdef'):
            raise ValueError('native-provider-artifact-constructor-nonce')
    if sorted(evidence.parent.iterdir()) != [evidence]:
        raise ValueError('native-provider-artifact-root-ownership')
    paths = []; boundaries = {}; tree = sorted(evidence.iterdir(), key=lambda path: path.name); seen_directories = set()
    for path in tree:
        info = path.lstat()
        if path.name in caps:
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)):
                raise ValueError('native-provider-artifact-file-kind')
            paths.append((path, caps[path.name]))
        else:
            if (path not in provider_directories.values() or not stat.S_ISDIR(info.st_mode)
                    or stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024)):
                raise ValueError('native-provider-artifact-directory')
            seen_directories.add(path)
            files = sorted(path.iterdir(), key=lambda file: file.name); boundaries[path] = files
            allowed = set(_NATIVE_PROVIDER_FILES) | {name + '.pending' for name in _NATIVE_PROVIDER_SCHEMAS}
            if any(file.name not in allowed for file in files): raise ValueError('native-provider-artifact-file-name')
            for file in files:
                name = file.name.removesuffix('.pending')
                cap = 8388608 if name == 'script.raw' else 131072 if name == 'manifest.raw' else 65536
                paths.append((file, cap))
    if seen_directories != set(provider_directories.values()):
        raise ValueError('native-provider-artifact-constructor-directory-missing')
    observed = []; root_bytes = 0
    with native_provider_data_files(paths) as held:
        for path, cap in paths:
            raw = held[path]; root_bytes += len(raw)
            if root_bytes > 41943040 - 65536: raise ValueError('native-provider-artifact-root-40mib-bound')
            observed.append({'path': path.relative_to(evidence).as_posix(), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'byteBound': cap})
        if (sorted(evidence.parent.iterdir()) != [evidence]
                or sorted(evidence.iterdir(), key=lambda path: path.name) != tree
                or any(sorted(path.iterdir(), key=lambda file: file.name) != files for path, files in boundaries.items())):
            raise ValueError('native-provider-artifact-tree-changed')
    observed_names = {row['path'] for row in observed}
    result = {'schemaVersion': 1, 'kind': 'FINITE_NATIVE_PROVIDER_ARTIFACT_MANIFEST',
              'caseDirectory': str(evidence), 'exactOwnedRoot': str(evidence.parent),
              'observedFiles': observed, 'rootBytesBeforeThisManifest': root_bytes,
              'rootBytesBound': 41943040, 'manifestReserveBytes': 65536,
              'allObservedFilesRetainedInExactOwnedRoot': True,
              'bothFullProviderRawPairsPresent': all(role in provider_directories and all(
                  (provider_directories[role] / name).relative_to(evidence).as_posix() in observed_names
                  for name in ('manifest.raw', 'script.raw')) for role in ('unfixed_i', 'sanitized')),
              'allFourNativeStdoutStderrPresent': all(role + suffix in observed_names for role in roles for suffix in ('.stdout.private', '.stderr.private')),
              'durableArtifactUploadCompleted': False, 'noDeletionOrTemporaryCleanup': True,
              'alwaysUploadExactOwnedRootRequired': True, 'nativeAdmissionClaim': False}
    if len((json.dumps(result, sort_keys=True, indent=2) + '\n').encode('utf-8')) > 65536:
        raise ValueError('native-provider-artifact-manifest-bound')
    return result


def _native_provider_transport_control_values():
    """Modeled diagnostic bytes only; no fake native PASS or custody admission."""
    files = {'context.record': b'PUBLIC MODELED transport metadata only\n',
             'manifest.raw': b'PUBLIC MODELED literal manifest\x00\xff',
             'script.raw': bytes(range(256)) * 80}
    return [{'case': case, 'directory': '/PUBLIC-MODELED/' + case, 'files': dict(files)}
            for case in ('unfixed_i', 'sanitized')]


class NativeProviderTransportControlTests(unittest.TestCase):
    """Execute the actual packet emitter and decoder using owned local StringIO."""
    def test_actual_emitted_dedup_packet_reconstructs_exact_ordered_bytes(self):
        captures = _native_provider_transport_control_values()
        output = io.StringIO()
        with redirect_stdout(output):
            result = emit_native_provider_custody_capture(captures, True, 0)
        decoded = decode_native_provider_custody_capture(output.getvalue())
        self.assertEqual(decoded['archive'], result['archive'])
        self.assertIs(decoded['manifest']['nativeAcceptance'], False)
        self.assertIs(decoded['manifest']['equivalent'], True)
        self.assertIs(decoded['manifest']['allObservedFilesPubliclyRetained'], True)
        self.assertEqual(decoded['manifest']['omittedSecondaryRawBytes'], 0)
        self.assertEqual(result['transportBytes'], len(output.getvalue().encode('ascii')))
        expected = {(case['case'], name): raw for case in captures for name, raw in case['files'].items()}
        self.assertEqual(decoded['files'], expected)
        self.assertEqual([(row['case'], row['name']) for row in decoded['manifest']['files']],
                         sorted(expected, key=lambda key: (('unfixed_i', 'sanitized').index(key[0]), key[1])))
        with zipfile.ZipFile(io.BytesIO(decoded['archive'])) as archive:
            self.assertIn('unfixed_i/script.raw', archive.namelist())
            self.assertNotIn('sanitized/script.raw', archive.namelist())
            self.assertEqual(archive.read('unfixed_i/script.raw'), captures[0]['files']['script.raw'])
        self.assertGreater(len(output.getvalue().splitlines()), 3)

    def test_packet_refuses_partial_reordered_tampered_and_false_dedup(self):
        captures = _native_provider_transport_control_values(); output = io.StringIO()
        with redirect_stdout(output):
            emit_native_provider_custody_capture(captures, True, 0)
        text = output.getvalue(); lines = text.splitlines(True)
        malformed = [text[:-1], ''.join(lines[:-1]), ''.join([lines[0], *reversed(lines[1:])]), text + lines[-1]]
        prefix = 'PUBLIC_NATIVE_ENV_DIAGNOSTIC_JSON:'
        header = json.loads(lines[0][len(prefix):]); header['bytes'] = True
        malformed.append(prefix + _native_provider_json(header).decode('ascii') + '\n' + ''.join(lines[1:]))
        chunk = json.loads(lines[1][len(prefix):]); raw = bytearray(base64.b64decode(chunk['base64'], validate=True)); raw[0] ^= 1
        chunk['base64'] = base64.b64encode(raw).decode('ascii')
        malformed.append(lines[0] + prefix + _native_provider_json(chunk).decode('ascii') + '\n' + ''.join(lines[2:]))
        for index, value in enumerate(malformed):
            with self.subTest(index=index), self.assertRaises(ValueError):
                decode_native_provider_custody_capture(value)
        wrong = _native_provider_transport_control_values(); wrong[1]['files']['script.raw'] += b'PUBLIC mismatch'
        rejected_output = io.StringIO()
        with redirect_stdout(rejected_output), self.assertRaisesRegex(ValueError, '^native-provider-false-dedupe$'):
            emit_native_provider_custody_capture(wrong, True, 0)
        self.assertEqual(rejected_output.getvalue(), '')
        # Partial diagnostic data must stay explicitly diagnostic; native custody
        # admission itself rejects the missing exact required file set.
        partial = _native_provider_transport_control_values(); del partial[1]['files']['script.raw']
        with self.assertRaisesRegex(ValueError, '^native-provider-file-set$'):
            native_provider_custody_admission(partial[1], 'sanitized', b'', b'', '', '', b'', '', '')




class NativeProviderOwnedPathAdmissionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt' or (os.name == 'posix' and hasattr(os, 'O_NOFOLLOW')),
                         'Owned alias admission needs Windows custody or POSIX nofollow')
    def test_authentic_j_assignment_red_then_current_same_file_green(self):
        from agent_tools import source_module_loader
        public = b'PUBLIC native module byte oracle\r\n'
        self.assertEqual((len(J_NATIVE_OWNED_SETUP_BEFORE), hashlib.sha256(J_NATIVE_OWNED_SETUP_BEFORE).hexdigest()),
                         (183, '2ecf957e77b872f5fea52d9c610645efd7e2a687b6368939a5fb1db11d26f11a'))
        self.assertEqual(J_NATIVE_OWNED_SETUP_PROVENANCE['wholeSourceSha256'],
                         'c1e6acb0e937ed97c5ab8192c6d3e906cb7e41cdf73c16ee8b14e125b5e01ba6')
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='native-j-assignment-causal-', dir=parent) as name:
            real = Path(name)
            fixture = real / 'fixture'; fixture.mkdir()
            if os.name == 'nt':
                import ctypes
                # Ask Win32 for a real existing alias; never invent RUNNER~1.
                short_path = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
                short_path.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
                short_path.restype = ctypes.c_uint32
                needed = short_path(str(fixture), None, 0)
                if not needed:
                    self.skipTest('Actual GetShortPathNameW capability unavailable: ' + str(ctypes.get_last_error()))
                self.assertLessEqual(needed, 32768)
                buffer = ctypes.create_unicode_buffer(needed)
                observed = short_path(str(fixture), buffer, needed)
                if not observed:
                    self.skipTest('Actual GetShortPathNameW capability unavailable: ' + str(ctypes.get_last_error()))
                self.assertLess(observed, needed)
                alias = Path(buffer.value)
                if str(alias).casefold() == str(alias.resolve(strict=True)).casefold():
                    self.skipTest('Actual owned fixture has no distinct non-casing Win32 short-name alias')
            else:
                # SYNTHETIC_NON_WINDOWS: real repeated-root spelling, not 8.3.
                alias = Path('//' + str(fixture).lstrip('/'))
            self.assertTrue(alias.is_absolute())
            self.assertTrue(alias.samefile(fixture))
            # This original spelling must enter the unchanged bootstrap first.
            program = real / 'authentic-j-owned-data-setup.py'
            component = b'from pathlib import Path\n' + J_NATIVE_OWNED_SETUP_BEFORE
            with program.open('xb') as stream:
                stream.write(component)
            with source_module_loader._bootstrap_source(program) as (held, closing):
                self.assertEqual(held, component)
                namespace = {'__file__': str(program), '__name__': '__authentic_j_owned_data_setup__',
                             'directory': str(alias), 'public': public}
                exec(compile(held, str(program), 'exec'), namespace)
                closing()
            owned, data = namespace['owned'], namespace['data']
            with source_module_loader._bootstrap_source(data) as (admitted, closing):
                self.assertEqual(admitted, public)
                closing()
            first = data.stat(follow_symlinks=False)

            class SamePositive(unittest.TestCase):
                def __init__(self, current):
                    super().__init__('runTest')
                    self.current = current
                    self.observation = None
                def runTest(self):
                    selected_owned, selected_data = owned, data
                    if self.current:
                        selected_owned, selected_data = native_provider_canonical_owned_data(owned, data, public)
                    with source_module_loader._bootstrap_source(selected_data) as (raw, closing):
                        self.assertEqual(raw, public)
                        self.assertTrue(data.samefile(selected_data))
                        state = selected_data.stat(follow_symlinks=False)
                        self.observation = (state.st_dev, state.st_ino, hashlib.sha256(raw).hexdigest())
                        closing()
                    # Caller ingress invariant; the separate real-PS control executes
                    # authentic wrapper141. This is not native Windows acceptance.
                    self.assertEqual(str(selected_data), str(selected_data.resolve(strict=True)),
                                     'AUTHENTIC_J_OWNED_PATH_MUST_BE_CANONICAL_BEFORE_NATIVE_WRAPPER')
                    self.assertEqual(str(selected_owned), str(selected_owned.resolve(strict=True)))

            cases = []
            for current in (False, True):
                case = SamePositive(current); result = unittest.TestResult(); case.run(result)
                cases.append((case, result))
            (old_case, old), (fixed_case, fixed) = cases
            self.assertEqual((old.testsRun, len(old.failures), len(old.errors), len(old.skipped)), (1, 1, 0, 0))
            self.assertIn('AUTHENTIC_J_OWNED_PATH_MUST_BE_CANONICAL_BEFORE_NATIVE_WRAPPER', old.failures[0][1])
            self.assertEqual((fixed.testsRun, len(fixed.failures), len(fixed.errors), len(fixed.skipped)), (1, 0, 0, 0))
            self.assertEqual(old_case.observation, fixed_case.observation)
            self.assertEqual(old_case.observation[:2], (first.st_dev, first.st_ino))
            self.assertEqual(data.read_bytes(), public)
            self.assertEqual(program.read_bytes(), component)

    def test_existing_owned_path_and_non_windows_alias_keep_exact_identity_and_bytes(self):
        public = b'PUBLIC native module byte oracle\r\n'
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='native-owned-path-admission-', dir=parent) as name:
            actual = Path(name)
            data = actual / 'PUBLIC.bytes'
            data.write_bytes(public)
            spelling = actual if os.name == 'nt' else Path('//' + str(actual).lstrip('/'))
            original = spelling / 'PUBLIC.bytes'
            canonical, observed = native_provider_canonical_owned_data(spelling, original, public)
            self.assertEqual(canonical, actual.resolve(strict=True))
            self.assertEqual(observed, data.resolve(strict=True))
            self.assertTrue(original.samefile(observed))
            self.assertTrue(spelling.samefile(canonical))
            self.assertEqual(observed.read_bytes(), public)
            if os.name != 'nt':
                self.assertNotEqual(str(original), str(observed), 'SYNTHETIC_NON_WINDOWS_ALIAS_COMPONENT')

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'Original-name nofollow control')
    def test_original_symlink_is_refused_before_resolve_is_called(self):
        from unittest import mock
        public = b'PUBLIC native module byte oracle\r\n'
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='native-owned-path-nofollow-', dir=parent) as name:
            owned = Path(name)
            target = owned / 'actual.bytes'; target.write_bytes(public)
            alias = owned / 'PUBLIC.bytes'; alias.symlink_to(target)
            with mock.patch.object(Path, 'resolve', side_effect=AssertionError('resolve-before-original-custody')) as resolver:
                with self.assertRaises((OSError, ValueError)):
                    native_provider_canonical_owned_data(owned, alias, public)
                resolver.assert_not_called()

    def test_resolved_foreign_same_bytes_file_is_refused(self):
        from unittest import mock
        public = b'PUBLIC native module byte oracle\r\n'
        parent = Path(tempfile.gettempdir()).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix='native-owned-path-identity-', dir=parent) as name:
            owned = Path(name)
            data = owned / 'PUBLIC.bytes'; data.write_bytes(public)
            other = owned / 'other'; other.mkdir()
            foreign = other / 'PUBLIC.bytes'; foreign.write_bytes(public)
            with mock.patch.object(Path, 'resolve', return_value=foreign):
                with self.assertRaisesRegex(ValueError, '^native-provider-owned-data-identity$'):
                    native_provider_canonical_owned_data(owned, data, public)
            self.assertEqual(data.read_bytes(), public)
            self.assertEqual(foreign.read_bytes(), public)


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
