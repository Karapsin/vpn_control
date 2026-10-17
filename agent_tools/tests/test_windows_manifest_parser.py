"""Real-engine literal parser controls; no provider or Windows oracle executes.

PROSPECTIVE: enroll only if the source helpers enter NATIVE_MODULE_SCRIPT.
The retained manifest is parsed solely as inert data on every host.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment
from agent_tools.tests.test_windows_powershell_environment import NATIVE_MODULE_SCRIPT


FIXTURES = Path(__file__).parent / 'fixtures/windows_manifest_parser'
BEFORE_SHA256 = '0c3375490ff3dec0243adc61a42dd9834fb2e8a8a511bd1ca1f4d511fd9a5315'
MANIFEST_SHA256 = '50285639e097ccada4af8c5699c660d055b19bbe12b99db0910124411fb07ab6'
PARSER_CONTROL = '$ErrorActionPreference=\'Stop\'\nSet-StrictMode -Version Latest\n$sourcePath=$args[0];$manifestPath=$args[1];$variant=$args[2]\n$source=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($sourcePath))\n$sourceTokens=$null;$sourceErrors=$null\n$sourceTree=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$sourceTokens,[ref]$sourceErrors)\nif($null -ne $sourceErrors -and $sourceErrors.Length){throw \'PARSER_SOURCE_SYNTAX\'}\nif($variant -ceq \'before\'){\n $names=@(\'Read-PublicNativeManifestStrings\',\'Read-PublicNativeUtilityManifest\')\n}elseif($variant -ceq \'current\'){\n $names=@(\'ConvertFrom-PublicNativeProviderBytes\',\'Read-PublicNativeManifestStrings\',\'Read-PublicNativeUtilityManifest\')\n}else{throw \'PARSER_SOURCE_VARIANT\'}\n$definitions=[Collections.Generic.Dictionary[string,Management.Automation.Language.FunctionDefinitionAst]]::new([StringComparer]::Ordinal)\nforeach($statement in $sourceTree.EndBlock.Statements){\n if($statement -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -ccontains $statement.Name){\n  if($definitions.ContainsKey($statement.Name)){throw \'PARSER_SOURCE_DUPLICATE\'}\n  $definitions.Add($statement.Name,$statement)\n }\n}\nif($definitions.Count -ne $names.Length){throw \'PARSER_SOURCE_MISSING\'}\nforeach($name in $names){. ([scriptblock]::Create($definitions[$name].Extent.Text))}\n$raw=[IO.File]::ReadAllBytes($manifestPath)\n[Console]::Out.WriteLine(\'PARSER_SAME_AUTHENTIC_17125_POSITIVE_BEGIN\')\n$fields=Read-PublicNativeUtilityManifest $raw\nif($fields[\'GUID\'][0] -ine \'1DA87E53-152B-403E-98DC-74D7B4D63D59\' -or $fields[\'ModuleVersion\'][0] -cne \'7.0.0.0\' -or $null -eq $fields[\'FunctionsToExport\'] -or $fields[\'FunctionsToExport\'].Length -ne 0){throw \'PARSER_SAME_AUTHENTIC_POSITIVE_RESULT\'}\n[Console]::Out.WriteLine(\'PARSER_SAME_AUTHENTIC_POSITIVE_PASS\')\nif($variant -ceq \'current\'){\n $tokens=$null;$errors=$null;$text=[Text.UTF8Encoding]::new($false,$true).GetString($raw)\n $tree=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)\n if($errors.Count){throw \'PARSER_ACTUAL_MANIFEST_PARSE\'}\n $empty=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.ArrayExpressionAst] -and $node.Extent.Text -ceq \'@()\'},$true))\n if($empty.Count -ne 1 -or $null -eq $empty[0].SubExpression.Statements -or $empty[0].SubExpression.Statements.Count -ne 0){throw \'PARSER_GENUINE_EMPTY_ARRAY_IDENTITY\'}\n $values=[Collections.Generic.List[string]]::new();Read-PublicNativeManifestStrings $empty[0] $values 0\n if($values.Count -ne 0){throw \'PARSER_GENUINE_EMPTY_ARRAY_VALUES\'}\n [Console]::Out.WriteLine(\'PARSER_GENUINE_EMPTY_ARRAY_ACCEPTED\')\n $trapText="@(trap { \'PUBLIC_INERT_TRAP_BODY_NEVER_EXECUTED\' }; \'PUBLIC literal\')"\n $tokens=$null;$errors=$null;$trapTree=[Management.Automation.Language.Parser]::ParseInput($trapText,[ref]$tokens,[ref]$errors)\n if($errors.Count){throw \'PARSER_INERT_TRAP_AST_PARSE\'}\n $array=$trapTree.EndBlock.Statements[0].PipelineElements[0].Expression\n if($array -isnot [Management.Automation.Language.ArrayExpressionAst] -or $null -eq $array.SubExpression.Traps -or $array.SubExpression.Traps.Count -ne 1){throw \'PARSER_INERT_NONEMPTY_TRAP_AST_IDENTITY\'}\n foreach($kind in @(\'statement\',\'array\')){\n  $node=if($kind -ceq \'statement\'){$array.SubExpression}else{$array}\n  $values=[Collections.Generic.List[string]]::new();$refused=$false\n  try{Read-PublicNativeManifestStrings $node $values 0}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_MANIFEST_LITERAL\'){throw};$refused=$true}\n  if(-not $refused){throw \'PARSER_INERT_NONEMPTY_TRAP_ADMITTED\'}\n  [Console]::Out.WriteLine((\'PARSER_NONEMPTY_TRAP_REFUSED:\'+$kind))\n }\n $rootTrap="trap { \'PUBLIC_ROOT_TRAP_BODY_NEVER_EXECUTED\' }; @{}"\n $refused=$false\n try{$null=Read-PublicNativeUtilityManifest ([Text.Encoding]::UTF8.GetBytes($rootTrap))}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_MANIFEST_SHAPE\'){throw};$refused=$true}\n if(-not $refused){throw \'PARSER_ROOT_TRAP_ADMITTED\'}\n [Console]::Out.WriteLine(\'PARSER_NONEMPTY_TRAP_REFUSED:root\')\n function Assert-PublicParserSameFields($expected,$actual){\n  if($null -eq $expected -or $null -eq $actual -or $expected.Count -ne $actual.Count){throw \'PARSER_DECODER_FIELDS_CHANGED\'}\n  $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)\n  foreach($key in $expected.Keys){$null=$keys.Add($key)}\n  foreach($key in $actual.Keys){\n   if(-not $keys.Contains($key) -or $null -eq $actual[$key] -or $expected[$key].Length -ne $actual[$key].Length){throw \'PARSER_DECODER_FIELDS_CHANGED\'}\n   for($index=0;$index -lt $expected[$key].Length;$index++){if($expected[$key][$index] -cne $actual[$key][$index]){throw \'PARSER_DECODER_FIELDS_CHANGED\'}}\n  }\n }\n # Every variant enters the actual selected Read helper; decoder bytes are not\n # interpreted by a Python model or by a replacement PowerShell decoder.\n $authenticText=ConvertFrom-PublicNativeProviderBytes $raw\n $utf8=[Text.UTF8Encoding]::new($false,$true)\n $utf16=[Text.UnicodeEncoding]::new($false,$true,$true)\n $positive=[ordered]@{\n  \'authentic-utf8\'=$raw\n  \'utf8-bom\'=[byte[]](@(239,187,191)+$utf8.GetBytes($authenticText))\n  \'utf16le-bom\'=[byte[]]($utf16.GetPreamble()+$utf16.GetBytes($authenticText))\n }\n foreach($entry in $positive.GetEnumerator()){\n  $decodedFields=Read-PublicNativeUtilityManifest ([byte[]]$entry.Value)\n  Assert-PublicParserSameFields $fields $decodedFields\n  [Console]::Out.WriteLine((\'PARSER_DECODER_SAME_RESULT:\'+$entry.Key))\n }\n # This inert literal models the official Function-schema shape, not observed H manifest bytes.\n $functionText="@{GUID=\'1DA87E53-152B-403E-98DC-74D7B4D63D59\';ModuleVersion=\'3.1.0.0\';NestedModules=@(\'Microsoft.PowerShell.Commands.Utility.dll\',\'Microsoft.PowerShell.Utility.psm1\');CmdletsToExport=@();FunctionsToExport=@(\'Get-FileHash\')}"\n $functionFields=Read-PublicNativeUtilityManifest ($utf8.GetBytes($functionText))\n if($functionFields[\'NestedModules\'].Length -ne 2 -or $functionFields[\'FunctionsToExport\'].Length -ne 1 -or $functionFields[\'FunctionsToExport\'][0] -cne \'Get-FileHash\'){throw \'PARSER_FUNCTION_SCHEMA_RESULT\'}\n Assert-PublicParserSameFields $functionFields (Read-PublicNativeUtilityManifest ([byte[]]($utf16.GetPreamble()+$utf16.GetBytes($functionText))))\n [Console]::Out.WriteLine(\'PARSER_FUNCTION_SCHEMA_READ_ACCEPTED\')\n foreach($wrong in @($functionText.Replace(\'Microsoft.PowerShell.Utility.psm1\',\'PUBLIC.foreign.psm1\'),$functionText.Replace(\'Microsoft.PowerShell.Utility.psm1\',\'Microsoft.PowerShell.Commands.Utility.dll\'),$functionText.Replace("FunctionsToExport=@(\'Get-FileHash\')","FunctionsToExport=@(\'Get-*\')"))){\n  $refused=$false;try{$null=Read-PublicNativeUtilityManifest ($utf8.GetBytes($wrong))}catch{if($_.Exception.Message -cnotin @(\'PUBLIC_NATIVE_MANIFEST_NESTED\',\'PUBLIC_NATIVE_MANIFEST_EXPORT\')){throw};$refused=$true}\n  if(-not $refused){throw \'PARSER_FOREIGN_FUNCTION_SCHEMA_ADMITTED\'}\n }\n [Console]::Out.WriteLine(\'PARSER_FUNCTION_SCHEMA_STRICT_REFUSALS\')\n $negative=[ordered]@{\n  \'malformed-utf8\'=[byte[]]@(195,40)\n  \'odd-utf16le\'=[byte[]]@(255,254,65)\n  \'unpaired-surrogate\'=[byte[]]@(255,254,0,216)\n  \'utf16be\'=[byte[]]@(254,255,0,65)\n  \'utf32le\'=[byte[]]@(255,254,0,0,65,0,0,0)\n  \'nul\'=[byte[]]@(65,0,66)\n }\n foreach($entry in $negative.GetEnumerator()){\n  $refused=$false\n  try{$null=ConvertFrom-PublicNativeProviderBytes ([byte[]]$entry.Value)}catch{\n   if($entry.Key -ceq \'malformed-utf8\' -or $entry.Key -ceq \'unpaired-surrogate\'){\n    $exception=$_.Exception;$fallback=$false;$depth=0\n    while($null -ne $exception -and $depth -lt 8){\n     if($exception -is [Text.DecoderFallbackException]){$fallback=$true;break}\n     $exception=$exception.InnerException;$depth++\n    }\n    if(-not $fallback){throw}\n   }elseif($_.Exception.Message -cne \'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING\'){throw}\n   $refused=$true\n  }\n  if(-not $refused){throw \'PARSER_DECODER_INVALID_BYTES_ADMITTED\'}\n  [Console]::Out.WriteLine((\'PARSER_DECODER_STRICT_REFUSAL:\'+$entry.Key))\n }\n}\n[Console]::Out.WriteLine(\'PARSER_CAUSAL_CASE_COMPLETE\')\n'
PASS_LINES = [b'PARSER_SAME_AUTHENTIC_17125_POSITIVE_BEGIN', b'PARSER_SAME_AUTHENTIC_POSITIVE_PASS', b'PARSER_GENUINE_EMPTY_ARRAY_ACCEPTED', b'PARSER_NONEMPTY_TRAP_REFUSED:statement', b'PARSER_NONEMPTY_TRAP_REFUSED:array', b'PARSER_NONEMPTY_TRAP_REFUSED:root', b'PARSER_DECODER_SAME_RESULT:authentic-utf8', b'PARSER_DECODER_SAME_RESULT:utf8-bom', b'PARSER_DECODER_SAME_RESULT:utf16le-bom', b'PARSER_FUNCTION_SCHEMA_READ_ACCEPTED', b'PARSER_FUNCTION_SCHEMA_STRICT_REFUSALS', b'PARSER_DECODER_STRICT_REFUSAL:malformed-utf8', b'PARSER_DECODER_STRICT_REFUSAL:odd-utf16le', b'PARSER_DECODER_STRICT_REFUSAL:unpaired-surrogate', b'PARSER_DECODER_STRICT_REFUSAL:utf16be', b'PARSER_DECODER_STRICT_REFUSAL:utf32le', b'PARSER_DECODER_STRICT_REFUSAL:nul', b'PARSER_CAUSAL_CASE_COMPLETE']


def _actual_manifest_parser_case(case, *, before=False):
    executable = shutil.which('powershell.exe' if os.name == 'nt' else 'pwsh')
    if os.name == 'nt':
        case.assertIsNotNone(executable, 'Windows requires the real PowerShell parser control')
    elif executable is None:
        case.skipTest('PowerShell engine is unavailable for the literal parser control')
    from agent_tools import source_module_loader
    parent = dict(os.environ)
    before_path = (FIXTURES / 'native-v3.before.ps1').resolve()
    manifest_path = (FIXTURES / 'Utility.literal.before.psd1').resolve()
    with ExitStack() as held:
        old, old_closing = held.enter_context(source_module_loader._bootstrap_source(before_path))
        manifest, manifest_closing = held.enter_context(source_module_loader._bootstrap_source(manifest_path))
        case.assertEqual((len(old), hashlib.sha256(old).hexdigest()), (23685, BEFORE_SHA256))
        case.assertEqual((len(manifest), hashlib.sha256(manifest).hexdigest()), (17125, MANIFEST_SHA256))
        source = old if before else NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')
        with tempfile.TemporaryDirectory(prefix='literal-manifest-parser-') as temporary:
            directory = Path(temporary).resolve()
            paths = {name: directory / name for name in ('source.ps1', 'manifest.psd1', 'control.ps1')}
            inputs = {'source.ps1': source, 'manifest.psd1': manifest,
                      'control.ps1': PARSER_CONTROL.encode('utf-8', errors='strict')}
            for name, raw in inputs.items():
                fd = os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
            argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    str(paths['control.ps1']), str(paths['source.ps1']),
                    str(paths['manifest.psd1']), 'before' if before else 'current']
            case.assertLessEqual(sum(len(part.encode('utf-8', errors='strict')) + 1 for part in argv), 60000)
            completed = subprocess.run(argv, capture_output=True, check=False, timeout=30,
                                       env=windows_powershell_environment(executable, parent))
            for name, raw in inputs.items():
                case.assertEqual(paths[name].read_bytes(), raw)
            case.assertLessEqual(len(completed.stdout) + len(completed.stderr), 1048576)
            old_closing()
            manifest_closing()
    case.assertEqual(dict(os.environ), parent)
    return completed


class PowerShellManifestParserTests(unittest.TestCase):
    def test_actual_source_parser_keeps_empty_arrays_and_refuses_nonempty_traps(self):
        completed = _actual_manifest_parser_case(self)
        self.assertEqual(completed.returncode, 0, (completed.stdout, completed.stderr))
        self.assertEqual(completed.stderr, b'')
        self.assertEqual(completed.stdout.splitlines(), PASS_LINES)

    def test_actual_unfixed_nullable_traps_red_current_same_positive_green(self):
        old = _actual_manifest_parser_case(self, before=True)
        current = _actual_manifest_parser_case(self)
        self.assertEqual(old.returncode, 1, (old.stdout, old.stderr))
        self.assertEqual(old.stdout.splitlines(), [PASS_LINES[0]])
        self.assertIn(b'Count', old.stderr)
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(current.stderr, b'')
        self.assertEqual(current.stdout.splitlines(), PASS_LINES)


# Retained-H post-normalization component; typed graph and physical oracle stay native-only.
H_G_FIXTURE = Path(__file__).parent / 'fixtures/windows_powershell_environment/native_module_g.before.ps1'
H_G_SHA256 = '44adab1cf63866aad566cd49624ef7e23f3e08be20a044341008b10222bd1635'
H_AUTHORITY_SHA256 = '2761b6216ac16cb2159dce7fe86f10b1a960b7682134bc42d9dacd063acf97ed'
H_ORIGIN_CONTROL = '$ErrorActionPreference=\'Stop\'\nSet-StrictMode -Version Latest\n$currentPath=$args[0];$oldPath=$args[1];$mode=$args[2]\n$current=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($currentPath))\n$old=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($oldPath))\n$tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseInput($current,[ref]$tokens,[ref]$errors)\nif($null -ne $errors -and $errors.Length){throw \'H_ORIGIN_CURRENT_SOURCE_PARSE\'}\n$definitions=@()\nforeach($statement in $tree.EndBlock.Statements){if($statement -is [Management.Automation.Language.FunctionDefinitionAst] -and $statement.Name -ceq \'Assert-PublicNativeUtilityFunctionOrigins\'){$definitions+=,$statement}}\nif($definitions.Count -ne 1){throw \'H_ORIGIN_CURRENT_SOURCE_IDENTITY\'}\n. ([scriptblock]::Create($definitions[0].Extent.Text))\n$tokens=$null;$errors=$null;$oldTree=[Management.Automation.Language.Parser]::ParseInput($old,[ref]$tokens,[ref]$errors)\nif($null -ne $errors -and $errors.Length){throw \'H_ORIGIN_OLD_SOURCE_PARSE\'}\n$guards=@($oldTree.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value -ceq \'PUBLIC_NATIVE_HASH_MODULE_RUNTIME\'},$true))\nif($guards.Count -ne 1){throw \'H_ORIGIN_OLD_GUARD_IDENTITY\'}\n$oldIf=$guards[0].Parent\nwhile($null -ne $oldIf -and $oldIf -isnot [Management.Automation.Language.IfStatementAst]){$oldIf=$oldIf.Parent}\nif($null -eq $oldIf){throw \'H_ORIGIN_OLD_GUARD_PARENT\'}\n$decisions=@($oldIf.FindAll({param($node) $node -is [Management.Automation.Language.BinaryExpressionAst] -and $node.Operator -eq [Management.Automation.Language.TokenKind]::Ine},$true))\nif($decisions.Count -ne 1){throw \'H_ORIGIN_OLD_DECISION_IDENTITY\'}\n# Only the native normalization expression is projected to the already\n# authenticated normalized string. The original -ine decision remains source.\n$normalization=$decisions[0].Left\n$offset=$normalization.Extent.StartOffset-$oldIf.Extent.StartOffset\n$width=$normalization.Extent.EndOffset-$normalization.Extent.StartOffset\n$projected=$oldIf.Extent.Text.Substring(0,$offset)+\'$selectedBase\'+$oldIf.Extent.Text.Substring($offset+$width)\n$retainedDecision=[scriptblock]::Create("param([string]`$selectedBase,[string]`$utilityRoot)`n`$name=\'Get-FileHash\'`n"+$projected)\n$cases=@(\n    @{manifestPath=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1\';selectedPath=\'C:\\windows\\system32\\windowspowershell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1\';selectedBase=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\';scriptPath=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';scriptFile=\'C:\\windows\\system32\\windowspowershell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';definingPath=\'C:\\windows\\system32\\windowspowershell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';definingBase=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\';utilityRoot=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\'},\n    @{manifestPath=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1\';selectedPath=\'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1\';selectedBase=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\';scriptPath=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';scriptFile=\'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';definingPath=\'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psm1\';definingBase=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\';utilityRoot=\'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\'}\n)\n$accepted=0\nfor($index=0;$index -lt $cases.Count;$index++){\n    $row=$cases[$index];$refusal=\'\'\n    try{\n        if($mode -ceq \'before\'){& $retainedDecision $row.selectedBase $row.utilityRoot}\n        elseif($mode -ceq \'current\'){\n            Assert-PublicNativeUtilityFunctionOrigins $row.manifestPath $row.selectedPath $row.selectedBase $row.scriptPath $row.scriptFile $row.definingPath $row.definingBase ([StringComparison]::OrdinalIgnoreCase)\n        }else{throw \'H_ORIGIN_MODE\'}\n    }catch{\n        $expected=if($mode -ceq \'before\'){\'PUBLIC_NATIVE_HASH_MODULE_RUNTIME\'}else{\'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN\'}\n        if($_.Exception.Message -cne $expected){throw};$refusal=$_.Exception.Message\n    }\n    if($refusal){[Console]::Out.WriteLine((\'H_ORIGIN_CASE:\'+([string]$index)+\':REFUSED:\'+$refusal))}\n    else{$accepted++;[Console]::Out.WriteLine((\'H_ORIGIN_CASE:\'+([string]$index)+\':ACCEPTED\'))}\n}\ntry{\n    if($accepted -ne $cases.Count){throw \'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_MUST_ADMIT\'}\n}catch{\n    if($_.Exception.Message -cne \'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_MUST_ADMIT\'){throw}\n    [Console]::Error.WriteLine(\'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_MUST_ADMIT\')\n    exit 1\n}\n[Console]::Out.WriteLine(\'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_PASS\')\n# These finite negatives call the genuine current string-relation helper.\n# They assert no typed provider, filesystem normalization, source-body or oracle fact.\n$base=$cases[0];$keys=@(\'manifestPath\',\'selectedPath\',\'selectedBase\',\'scriptPath\',\'scriptFile\',\'definingPath\',\'definingBase\')\n$negative=0\nforeach($key in $keys){\n    $changed=@{};foreach($name in $base.Keys){$changed[$name]=$base[$name]};$changed[$key]=$base[$key]+\'\\PUBLIC_foreign\'\n    $refused=$false\n    try{Assert-PublicNativeUtilityFunctionOrigins $changed.manifestPath $changed.selectedPath $changed.selectedBase $changed.scriptPath $changed.scriptFile $changed.definingPath $changed.definingBase ([StringComparison]::OrdinalIgnoreCase)}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN\'){throw};$refused=$true}\n    if(-not $refused){throw \'H_ORIGIN_SINGLE_FIELD_TAMPER_ADMITTED\'}\n    [Console]::Out.WriteLine((\'H_ORIGIN_TAMPER_REFUSED:\'+([string]$negative)));$negative++\n}\nforeach($value in @(\'\',\' \',([string][char]0),(\'x\'*32769))){\n    $refused=$false\n    try{Assert-PublicNativeUtilityFunctionOrigins $base.manifestPath $base.selectedPath $value $base.scriptPath $base.scriptFile $base.definingPath $base.definingBase ([StringComparison]::OrdinalIgnoreCase)}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN\'){throw};$refused=$true}\n    if(-not $refused){throw \'H_ORIGIN_BASE_SCHEMA_TAMPER_ADMITTED\'}\n    [Console]::Out.WriteLine((\'H_ORIGIN_TAMPER_REFUSED:\'+([string]$negative)));$negative++\n}\n$refused=$false\ntry{Assert-PublicNativeUtilityFunctionOrigins $base.manifestPath $base.selectedPath $base.selectedBase $base.scriptPath $base.scriptFile $base.definingPath $base.definingBase ([StringComparison]::CurrentCulture)}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_HASH_FUNCTION_ORIGIN\'){throw};$refused=$true}\nif(-not $refused){throw \'H_ORIGIN_COMPARISON_TAMPER_ADMITTED\'}\n[Console]::Out.WriteLine((\'H_ORIGIN_TAMPER_REFUSED:\'+([string]$negative)))\n[Console]::Out.WriteLine(\'H_ORIGIN_COMPONENT_COMPLETE_METADATA_ONLY\')\n'


class PowerShellFunctionOriginComponentTests(unittest.TestCase):
    def test_authentic_h_normalized_origin_decision_old_red_current_green(self):
        executable = shutil.which('powershell.exe' if os.name == 'nt' else 'pwsh')
        if os.name == 'nt':
            self.assertIsNotNone(executable, 'Windows requires the real PowerShell origin component')
        elif executable is None:
            self.skipTest('PowerShell engine is unavailable for the origin component')
        from agent_tools import source_module_loader
        parent = dict(os.environ)
        with ExitStack() as held:
            old, old_closing = held.enter_context(source_module_loader._bootstrap_source(H_G_FIXTURE.resolve()))
            self.assertEqual((len(old), hashlib.sha256(old).hexdigest()), (3981, H_G_SHA256))
            current = NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')
            with tempfile.TemporaryDirectory(prefix='h-origin-metadata-component-') as temporary, ExitStack() as copied:
                directory = Path(temporary).resolve()
                inputs = {'current.ps1': current, 'old.ps1': old,
                          'control.ps1': b'\xef\xbb\xbf' + H_ORIGIN_CONTROL.encode('utf-8', errors='strict')}
                paths = {name: directory / name for name in inputs}
                for name, raw in inputs.items():
                    fd = os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
                for name, raw in inputs.items():
                    captured, closing = copied.enter_context(source_module_loader._bootstrap_source(paths[name]))
                    self.assertEqual(captured, raw)
                results = []
                environment = windows_powershell_environment(executable, parent)
                supplied = dict(environment)
                for mode in ('before', 'current'):
                    argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                            str(paths['control.ps1']), str(paths['current.ps1']), str(paths['old.ps1']), mode]
                    self.assertLessEqual(sum(len(item.encode('utf-8', errors='strict')) + 1 for item in argv), 60000)
                    results.append(subprocess.run(argv, capture_output=True, check=False, timeout=30, env=environment))
                    old_closing()
                    for name, raw in inputs.items():
                        self.assertEqual(paths[name].read_bytes(), raw)
                    self.assertEqual(environment, supplied)
                    self.assertEqual(dict(os.environ), parent)
                old_closing()
                # Context exit closes every held copied source generation too.
        old, current = results
        self.assertEqual(old.returncode, 1, (old.stdout, old.stderr))
        self.assertEqual(old.stdout.splitlines(), [
            b'H_ORIGIN_CASE:0:REFUSED:PUBLIC_NATIVE_HASH_MODULE_RUNTIME',
            b'H_ORIGIN_CASE:1:REFUSED:PUBLIC_NATIVE_HASH_MODULE_RUNTIME'])
        common = b'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_MUST_ADMIT'
        # Fixed component-only receipt comes only from the exact common
        # admission assertion catch; unrelated errors retain engine rendering.
        self.assertEqual(old.stderr.splitlines(), [common])
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(current.stderr, b'')
        expected = [b'H_ORIGIN_CASE:0:ACCEPTED', b'H_ORIGIN_CASE:1:ACCEPTED',
                    b'H_ORIGIN_SAME_AUTHENTIC_NORMALIZED_STRINGS_PASS']
        expected += [('H_ORIGIN_TAMPER_REFUSED:' + str(index)).encode('ascii') for index in range(12)]
        expected += [b'H_ORIGIN_COMPONENT_COMPLETE_METADATA_ONLY']
        self.assertEqual(current.stdout.splitlines(), expected)


# This tests the actual source helpers with controlled legacy-format bytes.
# The installed Windows provider bytes and physical oracle remain native-only.
I_ENCODING_BEFORE = Path(__file__).parent / 'fixtures/windows_powershell_environment/native_module_i.before.ps1'
I_ENCODING_BEFORE_SHA256 = 'f69211aa4bffac9873dc1526f696d6a78c81ec8163f6065cbf00460174233887'
ENCODING_CONTROL = '$ErrorActionPreference=\'Stop\'\nSet-StrictMode -Version Latest\n$sourcePath=$args[0];$manifestPath=$args[1];$variant=$args[2];$retainedParserControlPath=$args[3]\n$source=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($sourcePath))\n$sourceTokens=$null;$sourceErrors=$null\n$sourceTree=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$sourceTokens,[ref]$sourceErrors)\nif($null -ne $sourceErrors -and $sourceErrors.Length){throw \'ENCODING_SOURCE_SYNTAX\'}\n$names=@(\'ConvertFrom-PublicNativeProviderBytes\',\'Read-PublicNativeManifestStrings\',\'Read-PublicNativeUtilityManifest\')\nif($variant -ceq \'current\'){$names=@(\'Resolve-PublicNativeProviderNoBomCodePage\')+$names}elseif($variant -cne \'before\'){throw \'ENCODING_SOURCE_VARIANT\'}\n$definitions=[Collections.Generic.Dictionary[string,Management.Automation.Language.FunctionDefinitionAst]]::new([StringComparer]::Ordinal)\nforeach($statement in $sourceTree.EndBlock.Statements){\n if($statement -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -ccontains $statement.Name){\n  if($definitions.ContainsKey($statement.Name)){throw \'ENCODING_SOURCE_DUPLICATE\'}\n  $definitions.Add($statement.Name,$statement)\n }\n}\nif($definitions.Count -ne $names.Length){throw \'ENCODING_SOURCE_MISSING\'}\nforeach($name in $names){. ([scriptblock]::Create($definitions[$name].Extent.Text))}\nfunction Assert-PublicEncodingSameFields($expected,$actual){\n if($null -eq $expected -or $null -eq $actual -or $expected.Count -ne $actual.Count){throw \'ENCODING_SAME_FIELDS_REQUIRED\'}\n $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)\n foreach($key in $expected.Keys){$null=$keys.Add($key)}\n foreach($key in $actual.Keys){\n  if(-not $keys.Contains($key) -or $null -eq $actual[$key] -or $expected[$key].Length -ne $actual[$key].Length){throw \'ENCODING_SAME_FIELDS_REQUIRED\'}\n  for($index=0;$index -lt $expected[$key].Length;$index++){if($expected[$key][$index] -cne $actual[$key][$index]){throw \'ENCODING_SAME_FIELDS_REQUIRED\'}}\n }\n}\nfunction Test-PublicEncodingActualDecoderFallback($exception){\n $depth=0\n while($null -ne $exception -and $depth -lt 8){\n  if($exception -is [Text.DecoderFallbackException]){return $true}\n  $exception=$exception.InnerException;$depth++\n }\n return $false\n}\n$authenticRaw=[IO.File]::ReadAllBytes($manifestPath)\nif($authenticRaw.Length -ne 17125){throw \'ENCODING_AUTHENTIC_ASCII_WIDTH\'}\nforeach($octet in $authenticRaw){if($octet -gt 127){throw \'ENCODING_AUTHENTIC_ASCII_REQUIRED\'}}\n$authenticText=[Text.UTF8Encoding]::new($false,$true).GetString($authenticRaw)\n$expectedFields=Read-PublicNativeUtilityManifest $authenticRaw\n# MODELED format only: authentic ASCII literal data plus an inert public copyright comment.\n# These are controlled bytes, not observed I Windows provider bytes or native acceptance.\n$legacyText=$authenticText+"`n# PUBLIC MODELED legacy copyright "+[char]0x00A9+"`n"\n$legacyEncoder=[Text.Encoding]::GetEncoding(1252,[Text.EncoderExceptionFallback]::new(),[Text.DecoderExceptionFallback]::new())\n$legacyRaw=$legacyEncoder.GetBytes($legacyText)\nif($legacyRaw.Length -ne $authenticRaw.Length+37 -or $legacyRaw[$legacyRaw.Length-2] -ne 169){throw \'ENCODING_CONTROLLED_1252_BYTE_IDENTITY\'}\n[Console]::Out.WriteLine(\'ENCODING_SAME_MODELED_1252_MANIFEST_POSITIVE_BEGIN\')\n$legacyFields=$null;$observedFallback=$false\ntry{\n if($variant -ceq \'before\'){$legacyFields=Read-PublicNativeUtilityManifest $legacyRaw}else{\n  # Explicit modeled Desktop context. No actual Mac/Windows host fact is substituted.\n  $modeledCodePage=Resolve-PublicNativeProviderNoBomCodePage ([Version]\'5.1\') \'Desktop\' 1252 ([PlatformID]::Win32NT) \'mscorlib\'\n  if($modeledCodePage -ne 1252){throw \'ENCODING_MODELED_CONTEXT_RESULT\'}\n  $legacyFields=Read-PublicNativeUtilityManifest $legacyRaw $modeledCodePage\n }\n}catch{\n if(-not (Test-PublicEncodingActualDecoderFallback $_.Exception)){throw}\n $observedFallback=$true\n}\n# This one admission assertion is shared by old/current. Only actual DecoderFallback\n# from the authentic old Read call may qualify the expected RED.\nif($null -eq $legacyFields){\n if($variant -ceq \'before\' -and $observedFallback){\n  [Console]::Out.WriteLine(\'ENCODING_OBSERVED_ACTUAL_EXCEPTION:System.Text.DecoderFallbackException\')\n  [Console]::Error.WriteLine(\'ENCODING_SAME_MODELED_MANIFEST_MUST_ADMIT:System.Text.DecoderFallbackException\');exit 1\n }\n throw \'ENCODING_SAME_MODELED_MANIFEST_MUST_ADMIT\'\n}\nAssert-PublicEncodingSameFields $expectedFields $legacyFields\n[Console]::Out.WriteLine(\'ENCODING_SAME_MODELED_1252_MANIFEST_POSITIVE_PASS\')\nif($variant -cne \'current\'){throw \'ENCODING_BEFORE_UNEXPECTED_ADMISSION\'}\n# Retain every existing actual-engine parser control byte and assertion. Dot sourcing\n# executes only its selected three parser helpers and inert literal/byte controls.\n. $retainedParserControlPath $sourcePath $manifestPath \'current\'\n$liveCodePage=Resolve-PublicNativeProviderNoBomCodePage $PSVersionTable.PSVersion $PSVersionTable.PSEdition ([Text.Encoding]::Default.CodePage) ([Environment]::OSVersion.Platform) ([object].Assembly.GetName().Name)\n$expectedLiveCodePage=if($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and $PSVersionTable.PSEdition -ceq \'Desktop\'){[Text.Encoding]::Default.CodePage}else{65001}\nif($liveCodePage -ne $expectedLiveCodePage){throw \'ENCODING_ACTUAL_ENGINE_CONTEXT_RESULT\'}\nAssert-PublicEncodingSameFields $expectedFields (Read-PublicNativeUtilityManifest $authenticRaw $liveCodePage)\n[Console]::Out.WriteLine(\'ENCODING_POLICY_ACTUAL_ENGINE_ACCEPTED\')\n$desktopUtf8=Resolve-PublicNativeProviderNoBomCodePage ([Version]\'5.1\') \'Desktop\' 65001 ([PlatformID]::Win32NT) \'mscorlib\'\nif($desktopUtf8 -ne 65001){throw \'ENCODING_MODELED_DESKTOP_UTF8_CONTEXT_RESULT\'}\nAssert-PublicEncodingSameFields $expectedFields (Read-PublicNativeUtilityManifest $authenticRaw $desktopUtf8)\n[Console]::Out.WriteLine(\'ENCODING_POLICY_MODELED_DESKTOP_65001_ACCEPTED\')\n$wrongContexts=@(\n @([Version]\'5.1\',\'Desktop\',1252,[PlatformID]::Unix,\'mscorlib\'),\n @([Version]\'5.1\',\'Desktop\',1252,[PlatformID]::Win32NT,\'System.Private.CoreLib\'),\n @([Version]\'5.1\',\'Core\',1252,[PlatformID]::Win32NT,\'mscorlib\'),\n @([Version]\'5.0\',\'Desktop\',1252,[PlatformID]::Win32NT,\'mscorlib\'),\n @([Version]\'7.5.4\',\'Core\',1252,[PlatformID]::Unix,\'System.Private.CoreLib\'),\n @([Version]\'7.5.4\',\'Core\',65001,[PlatformID]::Unix,\'mscorlib\'),\n @($null,\'Desktop\',1252,[PlatformID]::Win32NT,\'mscorlib\'),\n @([Version]\'5.1\',\'Desktop\',1200,[PlatformID]::Win32NT,\'mscorlib\')\n)\nfor($case=0;$case -lt $wrongContexts.Length;$case++){\n $context=$wrongContexts[$case];$refused=$false\n try{$null=Resolve-PublicNativeProviderNoBomCodePage $context[0] $context[1] $context[2] $context[3] $context[4]}catch{if($_.Exception.Message -cne \'PUBLIC_NATIVE_PROVIDER_ENCODING_CONTEXT\'){throw};$refused=$true}\n if(-not $refused){throw \'ENCODING_WRONG_POLICY_CONTEXT_ADMITTED\'}\n [Console]::Out.WriteLine((\'ENCODING_POLICY_CONTEXT_REFUSED:\'+$case))\n}\n$utf8=[Text.UTF8Encoding]::new($false,$true);$utf16=[Text.UnicodeEncoding]::new($false,$true,$true)\n$bomPositives=[ordered]@{\n \'utf8-bom-overrides-modeled-1252\'=[byte[]](@(239,187,191)+$utf8.GetBytes($legacyText))\n \'utf16le-bom-overrides-modeled-1252\'=[byte[]]($utf16.GetPreamble()+$utf16.GetBytes($legacyText))\n}\nforeach($entry in $bomPositives.GetEnumerator()){\n Assert-PublicEncodingSameFields $expectedFields (Read-PublicNativeUtilityManifest ([byte[]]$entry.Value) 1252)\n [Console]::Out.WriteLine((\'ENCODING_EXPLICIT_BOM_PRECEDENCE_PASS:\'+$entry.Key))\n}\n$additionalNegatives=[ordered]@{\n \'legacy-under-desktop-65001\'=[byte[]]$legacyRaw\n \'malformed-utf8-bom-under-1252\'=[byte[]]@(239,187,191,195,40)\n \'utf16be-under-1252\'=[byte[]]@(254,255,0,65)\n \'utf32le-under-1252\'=[byte[]]@(255,254,0,0,65,0,0,0)\n}\nforeach($entry in $additionalNegatives.GetEnumerator()){\n $codePage=if($entry.Key -ceq \'legacy-under-desktop-65001\'){$desktopUtf8}else{1252};$refused=$false\n try{$null=ConvertFrom-PublicNativeProviderBytes ([byte[]]$entry.Value) $codePage}catch{\n  if($entry.Key -ceq \'legacy-under-desktop-65001\' -or $entry.Key -ceq \'malformed-utf8-bom-under-1252\'){\n   if(-not (Test-PublicEncodingActualDecoderFallback $_.Exception)){throw}\n  }elseif($_.Exception.Message -cne \'PUBLIC_NATIVE_PROVIDER_TEXT_ENCODING\'){throw}\n  $refused=$true\n }\n if(-not $refused){throw \'ENCODING_CONFLICTING_FORMAT_ADMITTED\'}\n [Console]::Out.WriteLine((\'ENCODING_CONFLICTING_FORMAT_REFUSED:\'+$entry.Key))\n}\n[Console]::Out.WriteLine(\'ENCODING_COMPONENT_COMPLETE_MODELED_FORMAT_NOT_WINDOWS_ACCEPTANCE\')\n'


def _actual_provider_encoding_case(case, *, before):
    executable = shutil.which('powershell.exe' if os.name == 'nt' else 'pwsh')
    if os.name == 'nt':
        case.assertIsNotNone(executable, 'Windows requires the real encoding parser control')
    elif executable is None:
        case.skipTest('PowerShell engine is unavailable for the encoding parser control')
    from agent_tools import source_module_loader
    parent = dict(os.environ)
    with ExitStack() as held:
        old, old_closing = held.enter_context(source_module_loader._bootstrap_source(I_ENCODING_BEFORE.resolve()))
        manifest, manifest_closing = held.enter_context(source_module_loader._bootstrap_source((FIXTURES / 'Utility.literal.before.psd1').resolve()))
        case.assertEqual((len(old), hashlib.sha256(old).hexdigest()), (30316, I_ENCODING_BEFORE_SHA256))
        case.assertEqual((len(manifest), hashlib.sha256(manifest).hexdigest()), (17125, MANIFEST_SHA256))
        current = NATIVE_MODULE_SCRIPT.encode('utf-8', errors='strict')
        with tempfile.TemporaryDirectory(prefix='provider-encoding-parser-') as temporary, ExitStack() as copied:
            directory = Path(temporary).resolve()
            inputs = {'source.ps1': old if before else current, 'manifest.psd1': manifest,
                      'control.ps1': b'\xef\xbb\xbf' + ENCODING_CONTROL.encode('utf-8', errors='strict'),
                      'retained.ps1': b'\xef\xbb\xbf' + PARSER_CONTROL.encode('utf-8', errors='strict')}
            paths = {name: directory / name for name in inputs}
            closings = []
            for name, raw in inputs.items():
                fd = os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                captured, closing = copied.enter_context(source_module_loader._bootstrap_source(paths[name]))
                case.assertEqual(captured, raw)
                closings.append(closing)
            environment = windows_powershell_environment(executable, parent)
            supplied = dict(environment)
            argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    str(paths['control.ps1']), str(paths['source.ps1']), str(paths['manifest.psd1']),
                    'before' if before else 'current', str(paths['retained.ps1'])]
            case.assertLessEqual(sum(len(part.encode('utf-8', errors='strict')) + 1 for part in argv), 60000)
            completed = subprocess.run(argv, capture_output=True, check=False, timeout=30, env=environment)
            case.assertEqual(environment, supplied)
            case.assertLessEqual(len(completed.stdout) + len(completed.stderr), 1048576)
            for name, raw in inputs.items():
                case.assertEqual(paths[name].read_bytes(), raw)
            for closing in closings:
                closing()
            old_closing()
            manifest_closing()
    case.assertEqual(dict(os.environ), parent)
    return completed


class PowerShellProviderEncodingTests(unittest.TestCase):
    def test_actual_i_strict_utf8_red_engine_selected_lossless_decoder_green(self):
        old = _actual_provider_encoding_case(self, before=True)
        self.assertEqual(old.returncode, 1, (old.stdout, old.stderr))
        self.assertEqual(old.stdout.splitlines(), [
            b'ENCODING_SAME_MODELED_1252_MANIFEST_POSITIVE_BEGIN',
            b'ENCODING_OBSERVED_ACTUAL_EXCEPTION:System.Text.DecoderFallbackException'])
        self.assertEqual(old.stderr.splitlines(), [
            b'ENCODING_SAME_MODELED_MANIFEST_MUST_ADMIT:System.Text.DecoderFallbackException'])
        current = _actual_provider_encoding_case(self, before=False)
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(current.stderr, b'')
        lines = current.stdout.splitlines()
        expected = [b'ENCODING_SAME_MODELED_1252_MANIFEST_POSITIVE_BEGIN',
                    b'ENCODING_SAME_MODELED_1252_MANIFEST_POSITIVE_PASS', *PASS_LINES,
                    b'ENCODING_POLICY_ACTUAL_ENGINE_ACCEPTED',
                    b'ENCODING_POLICY_MODELED_DESKTOP_65001_ACCEPTED',
                    *[b'ENCODING_POLICY_CONTEXT_REFUSED:' + str(index).encode('ascii') for index in range(8)],
                    b'ENCODING_EXPLICIT_BOM_PRECEDENCE_PASS:utf8-bom-overrides-modeled-1252',
                    b'ENCODING_EXPLICIT_BOM_PRECEDENCE_PASS:utf16le-bom-overrides-modeled-1252',
                    b'ENCODING_CONFLICTING_FORMAT_REFUSED:legacy-under-desktop-65001',
                    b'ENCODING_CONFLICTING_FORMAT_REFUSED:malformed-utf8-bom-under-1252',
                    b'ENCODING_CONFLICTING_FORMAT_REFUSED:utf16be-under-1252',
                    b'ENCODING_CONFLICTING_FORMAT_REFUSED:utf32le-under-1252',
                    b'ENCODING_COMPONENT_COMPLETE_MODELED_FORMAT_NOT_WINDOWS_ACCEPTANCE']
        self.assertEqual(lines, expected)


# Exact K program region, not a reconstructed selector. The surrounding native
# function still authenticates paths/bytes/manifest and exports/body/closing.
K_GRAPH_BEFORE = b"        $nested=@($module.NestedModules);$scriptNode=$null;$scriptCount=0;$binaryCount=0\n        if($nested.Count -ne 2){throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n        foreach($node in $nested){\n            if($null -eq $node -or $node.GetType().FullName -cne 'System.Management.Automation.PSModuleInfo' -or $node -isnot [Management.Automation.PSModuleInfo]){throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n            if([string]$node.ModuleType -ceq 'Script' -and $node.Name -ceq 'Microsoft.PowerShell.Utility'){$scriptNode=$node;$scriptCount++}\n            elseif([string]$node.ModuleType -ceq 'Binary' -and $node.Name -ceq 'Microsoft.PowerShell.Commands.Utility'){$binaryCount++}\n            else{throw 'PUBLIC_NATIVE_HASH_FUNCTION_NESTED'}\n        }\n        if($scriptCount -ne 1 -or $binaryCount -ne 1 -or -not [Object]::ReferenceEquals($scriptNode,$block.Module)){throw 'PUBLIC_NATIVE_HASH_FUNCTION_DEFINING_MODULE'}\n"
K_GRAPH_BEFORE_SHA256 = '85068740611abaf64efccc798ec717335e9a1bdf07029800cf044735ddeaf146'
K_GRAPH_BEFORE_PROVENANCE = {
    'commit': '33cedbedc222286d8fa2cdb80c7b3aebc44bf77f',
    'pythonPath': 'agent_tools/tests/test_windows_powershell_environment.py',
    'pythonSha256': 'ac3f01fccc9a9394a728b299abae6f6bc7096b22db46f276a8a9f137fb01c023',
    'literalName': 'NATIVE_MODULE_SCRIPT',
    'literalSha256': 'cc691b159e226e59bd133dfb5867c65b9edb8cd926c866cd1d6c989a0a0b3a7e',
    'utf8Start': 24106, 'utf8End': 25031, 'lines': [202, 210],
    'transformation': 'none; exact 925 UTF-8 bytes including terminal LF',
}
NESTED_GRAPH_CONTROL = 'param([string]$sourcePath,[string]$beforePath,[string]$workRoot,[string]$variant)\nSet-StrictMode -Version Latest\n$ErrorActionPreference=\'Stop\'\n# SYNTHETIC_GRAPH_COMPONENT: genuine imported typed nodes, not Windows/native acceptance.\n$utf8=[Text.UTF8Encoding]::new($false,$true)\n$errors=$null;$tokens=$null\n$tree=[Management.Automation.Language.Parser]::ParseInput([IO.File]::ReadAllText($sourcePath,$utf8),[ref]$tokens,[ref]$errors)\nif($null -ne $errors -and $errors.Length){throw \'GRAPH_CURRENT_SOURCE_SYNTAX\'}\n$names=@(\'Stop-PublicNativeUtilityFunctionGraph\',\'Resolve-PublicNativeUtilityFunctionNodes\')\n$definitions=[Collections.Generic.Dictionary[string,Management.Automation.Language.FunctionDefinitionAst]]::new([StringComparer]::Ordinal)\nforeach($statement in $tree.EndBlock.Statements){\n    if($statement -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -ccontains $statement.Name){\n        if($definitions.ContainsKey($statement.Name)){throw \'GRAPH_CURRENT_SOURCE_DUPLICATE\'}\n        $definitions.Add($statement.Name,$statement)\n    }\n}\nif($definitions.Count -ne 2){throw \'GRAPH_CURRENT_SOURCE_MISSING\'}\nforeach($name in $names){. ([ScriptBlock]::Create($definitions[$name].Extent.Text))}\n$before=[IO.File]::ReadAllText($beforePath,$utf8)\n$oldSelector=[ScriptBlock]::Create(\'param($module,$block)\'+"`n"+$before+"`nreturn ,`$scriptNode")\nfunction Quote-GraphLiteral([string]$value){return "\'"+$value.Replace("\'","\'\'")+"\'"}\nfunction Find-GraphBinary([Management.Automation.PSModuleInfo]$module){\n    $nodes=@();foreach($node in $module.NestedModules){if([string]$node.ModuleType -ceq \'Binary\'){$nodes+=,$node}}\n    if($nodes.Count -ne 1 -or $null -eq $nodes[0].ImplementingAssembly -or $nodes[0].ImplementingAssembly.IsDynamic){throw \'GRAPH_REAL_BINARY_ADMISSION\'}\n    return ,$nodes[0]\n}\nfunction Import-GraphInstalledModule([string]$name){\n    $path=[IO.Path]::Combine([string]$PSHOME,\'Modules\',$name,$name+\'.psd1\')\n    $modules=@(Import-Module -Name $path -Force -PassThru -ErrorAction Stop)\n    if($modules.Count -ne 1 -or $modules[0] -isnot [Management.Automation.PSModuleInfo] -or [string]$modules[0].ModuleType -cne \'Manifest\'){throw \'GRAPH_REAL_MANIFEST_ADMISSION\'}\n    return ,$modules[0]\n}\n$utility=Import-GraphInstalledModule \'Microsoft.PowerShell.Utility\'\n$realBinary=Find-GraphBinary $utility\n$assembly=$realBinary.ImplementingAssembly\n$binaryPath=[string]$assembly.Location\nif([string]::IsNullOrWhiteSpace($binaryPath) -or -not [IO.Path]::IsPathRooted($binaryPath) -or -not [IO.File]::Exists($binaryPath) -or $assembly.GetName().Name -cne \'Microsoft.PowerShell.Commands.Utility\'){throw \'GRAPH_REAL_ASSEMBLY_ADMISSION\'}\n$declaredDll=[IO.Path]::GetFileName($binaryPath)\nif($declaredDll -cne \'Microsoft.PowerShell.Commands.Utility.dll\'){throw \'GRAPH_REAL_DLL_DECLARATION_ADMISSION\'}\n$keys=[string[]]@($realBinary.ExportedCmdlets.Keys);[Array]::Sort($keys,[StringComparer]::Ordinal)\nif($keys.Length -lt 2){throw \'GRAPH_REAL_EXPORTED_SUBSET_ADMISSION\'}\n$anchor=$keys[0]\nfunction New-GraphFixture([string]$label,[string[]]$binaryPaths,[string[]]$extraScripts,[string[]]$exports,[string]$extraBody){\n    if($label -cnotmatch \'^[a-z][a-z0-9-]{0,31}$\'){throw \'GRAPH_FIXTURE_LABEL\'}\n    $directory=[IO.Path]::Combine($workRoot,$label)\n    if([IO.Directory]::Exists($directory) -or [IO.File]::Exists($directory)){throw \'GRAPH_FIXTURE_REUSE\'}\n    [void][IO.Directory]::CreateDirectory($directory)\n    $scriptName=\'ActualGraph_\'+$label+\'.psm1\'\n    $scriptPath=[IO.Path]::Combine($directory,$scriptName)\n    # The function is never invoked: it supplies genuine exported FunctionInfo/ScriptBlock identity only.\n    $body="function Get-FileHash { throw \'SYNTHETIC_GRAPH_FUNCTION_MUST_NOT_EXECUTE\' }`n"+$extraBody+"`nExport-ModuleMember -Function Get-FileHash"\n    [IO.File]::WriteAllText($scriptPath,$body,$utf8)\n    $nested=[Collections.Generic.List[string]]::new()\n    foreach($path in $binaryPaths){[void]$nested.Add((Quote-GraphLiteral $path))}\n    [void]$nested.Add((Quote-GraphLiteral $scriptName))\n    foreach($name in $extraScripts){\n        $path=[IO.Path]::Combine($directory,$name)\n        [IO.File]::WriteAllText($path,"function Get-SyntheticExtra { throw \'SYNTHETIC_EXTRA_MUST_NOT_EXECUTE\' }`nExport-ModuleMember -Function Get-SyntheticExtra",$utf8)\n        [void]$nested.Add((Quote-GraphLiteral $name))\n    }\n    $exportText=[Collections.Generic.List[string]]::new();foreach($name in $exports){[void]$exportText.Add((Quote-GraphLiteral $name))}\n    $manifest="@{RootModule=\'\';ModuleVersion=\'1.0.0\';GUID=\'cab1f57b-69af-40c9-9aaf-bd968882464c\';NestedModules=@("+[string]::Join(\',\',$nested.ToArray())+");CmdletsToExport=@("+[string]::Join(\',\',$exportText.ToArray())+");FunctionsToExport=@(\'Get-FileHash\')}"\n    $manifestPath=[IO.Path]::Combine($directory,\'Fixture_\'+$label+\'.psd1\')\n    [IO.File]::WriteAllText($manifestPath,$manifest,$utf8)\n    $loaded=@(Import-Module -Name $manifestPath -Force -PassThru -ErrorAction Stop)\n    if($loaded.Count -ne 1 -or $loaded[0] -isnot [Management.Automation.PSModuleInfo] -or [string]$loaded[0].ModuleType -cne \'Manifest\' -or -not $loaded[0].ExportedFunctions.ContainsKey(\'Get-FileHash\')){throw \'GRAPH_FIXTURE_IMPORT_ADMISSION\'}\n    $command=$loaded[0].ExportedFunctions[\'Get-FileHash\']\n    if($command -isnot [Management.Automation.FunctionInfo] -or $command.ScriptBlock -isnot [Management.Automation.ScriptBlock] -or $command.ScriptBlock.Module -isnot [Management.Automation.PSModuleInfo] -or [IO.Path]::GetFullPath($command.ScriptBlock.File) -cne [IO.Path]::GetFullPath($scriptPath)){throw \'GRAPH_FIXTURE_FUNCTION_ADMISSION\'}\n    return @{module=$loaded[0];block=$command.ScriptBlock;path=$scriptPath;manifest=$manifestPath}\n}\n$positive=New-GraphFixture \'positive\' @($binaryPath) @() @($anchor) \'\'\nif($positive.block.Module.Name -ceq \'Microsoft.PowerShell.Utility\' -or $positive.module.ExportedCmdlets.Count -ne 1){throw \'GRAPH_CONTROLLED_POSITIVE_IDENTITY\'}\n$actualNodes=@($positive.module.NestedModules)\nif($actualNodes.Count -ne 2 -or $actualNodes[0] -isnot [Management.Automation.PSModuleInfo] -or $actualNodes[1] -isnot [Management.Automation.PSModuleInfo]){throw \'GRAPH_CONTROLLED_POSITIVE_TYPED_NODES\'}\nif($variant -ceq \'before\'){\n    $refused=$false\n    try{$null=& $oldSelector $positive.module $positive.block}catch{\n        if($_.Exception.Message -cne \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'){throw}\n        $refused=$true\n    }\n    if(-not $refused){throw \'GRAPH_BEFORE_UNEXPECTED_ADMISSION\'}\n    [Console]::Out.WriteLine(\'SYNTHETIC_GRAPH_OLD_REFUSED:PUBLIC_NATIVE_HASH_FUNCTION_NESTED\')\n    [Console]::Error.WriteLine(\'SYNTHETIC_GRAPH_COMMON_POSITIVE_MUST_ADMIT\')\n    exit 1\n}\nif($variant -cne \'current\'){throw \'GRAPH_SOURCE_VARIANT\'}\n$selected=Resolve-PublicNativeUtilityFunctionNodes $positive.module $positive.block $declaredDll\nif(-not [Object]::ReferenceEquals($selected,$positive.block.Module)){throw \'GRAPH_CURRENT_EXACT_SCRIPT_REFERENCE\'}\n[Console]::Out.WriteLine(\'SYNTHETIC_GRAPH_SAME_TYPED_POSITIVE_ACCEPTED\')\nfunction Require-GraphRefusal([string]$label,[object]$module,[object]$block,[string]$dll,[string]$prefix){\n    $refused=$false\n    try{$null=Resolve-PublicNativeUtilityFunctionNodes $module $block $dll}catch{\n        $message=[string]$_.Exception.Message\n        if(-not $message.StartsWith($prefix,[StringComparison]::Ordinal)){throw}\n        if($utf8.GetByteCount($message) -gt 4096 -or $message.IndexOf("`n") -ge 0 -or $message.IndexOf("`r") -ge 0){throw \'GRAPH_REFUSAL_DETAIL_BOUND\'}\n        $refused=$true\n    }\n    if(-not $refused){throw (\'GRAPH_NEGATIVE_ADMITTED:\'+ $label)}\n    [Console]::Out.WriteLine(\'SYNTHETIC_GRAPH_REFUSED:\'+ $label)\n}\n$other=New-GraphFixture \'other-reference\' @($binaryPath) @() @($anchor) \'\'\nRequire-GraphRefusal \'foreign-script-reference\' $positive.module $other.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\n$one=New-GraphFixture \'one-node\' @() @() @() \'\'\nRequire-GraphRefusal \'missing-binary\' $one.module $one.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\n$three=New-GraphFixture \'three-nodes\' @($binaryPath) @(\'Extra.psm1\') @($anchor) \'\'\nRequire-GraphRefusal \'extra-node\' $three.module $three.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\n$twoScripts=New-GraphFixture \'two-scripts\' @() @(\'Extra.psm1\') @() \'\'\nRequire-GraphRefusal \'wrong-node-type\' $twoScripts.module $twoScripts.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\nRequire-GraphRefusal \'missing-script-block\' $positive.module $null $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\n$empty=New-GraphFixture \'empty-exports\' @($binaryPath) @() @() \'\'\nRequire-GraphRefusal \'empty-export-subset\' $empty.module $empty.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT\'\n$management=Import-GraphInstalledModule \'Microsoft.PowerShell.Management\'\n$foreignBinary=Find-GraphBinary $management\n$foreignPath=[string]$foreignBinary.ImplementingAssembly.Location\n$foreignKeys=[string[]]@($foreignBinary.ExportedCmdlets.Keys);[Array]::Sort($foreignKeys,[StringComparer]::Ordinal)\n$foreignName=$null;foreach($name in $foreignKeys){if(-not $realBinary.ExportedCmdlets.ContainsKey($name)){$foreignName=$name;break}}\nif($null -eq $foreignName -or $foreignBinary.ImplementingAssembly.GetName().Name -ceq $assembly.GetName().Name){throw \'GRAPH_REAL_FOREIGN_ASSEMBLY_ADMISSION\'}\n$foreign=New-GraphFixture \'foreign-assembly\' @($foreignPath) @() @($foreignName) \'\'\nRequire-GraphRefusal \'foreign-assembly\' $foreign.module $foreign.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_NESTED\'\n$managementPath=[IO.Path]::Combine([string]$PSHOME,\'Modules\',\'Microsoft.PowerShell.Management\',\'Microsoft.PowerShell.Management.psd1\')\n$extraBody=\'Import-Module -Name \'+(Quote-GraphLiteral $managementPath)+\' -Force -ErrorAction Stop\'+"`nExport-ModuleMember -Cmdlet "+(Quote-GraphLiteral $foreignName)\n$foreignExport=New-GraphFixture \'foreign-export\' @($binaryPath) @() @($foreignName) $extraBody\nif($foreignExport.module.ExportedCmdlets.Count -lt 1 -or -not $foreignExport.module.ExportedCmdlets.ContainsKey($foreignName)){throw \'GRAPH_REAL_FOREIGN_EXPORT_ADMISSION\'}\nRequire-GraphRefusal \'foreign-export-counterpart\' $foreignExport.module $foreignExport.block $declaredDll \'PUBLIC_NATIVE_HASH_FUNCTION_EXPORT\'\n[Console]::Out.WriteLine(\'SYNTHETIC_GRAPH_COMPONENT_COMPLETE_NO_NATIVE_ACCEPTANCE\')\n'


def _actual_nested_function_graph_case(case, *, before):
    executable = shutil.which('powershell.exe' if os.name == 'nt' else 'pwsh')
    if os.name == 'nt':
        case.assertIsNotNone(executable, 'Windows requires the real typed module graph component')
    elif executable is None:
        case.skipTest('PowerShell engine is unavailable for the synthetic typed graph component')
    from agent_tools import source_module_loader
    import ast
    parent = dict(os.environ)
    case.assertEqual((len(K_GRAPH_BEFORE), hashlib.sha256(K_GRAPH_BEFORE).hexdigest()),
                     (925, K_GRAPH_BEFORE_SHA256))
    producer = Path(__file__).with_name('test_windows_powershell_environment.py')
    with ExitStack() as held:
        raw, producer_closing = held.enter_context(source_module_loader._bootstrap_source(producer))
        tree = ast.parse(raw, filename=str(producer))
        assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'NATIVE_MODULE_SCRIPT'
                               for target in node.targets)]
        case.assertEqual(len(assignments), 1)
        actual = ast.literal_eval(assignments[0].value)
        case.assertEqual(actual, NATIVE_MODULE_SCRIPT)
        with tempfile.TemporaryDirectory(prefix='synthetic-native-graph-') as temporary, ExitStack() as copied:
            directory = Path(temporary).resolve()
            inputs = {'current.ps1': actual.encode('utf-8', errors='strict'),
                      'before.ps1': K_GRAPH_BEFORE,
                      'control.ps1': b'\xef\xbb\xbf' + NESTED_GRAPH_CONTROL.encode('utf-8', errors='strict')}
            paths = {name: directory / name for name in inputs}
            closings = []
            for name, content in inputs.items():
                fd = os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(content)
                admitted, closing = copied.enter_context(source_module_loader._bootstrap_source(paths[name]))
                case.assertEqual(admitted, content)
                closings.append(closing)
            work = directory / 'typed-modules'
            work.mkdir(mode=0o700)
            argv = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    str(paths['control.ps1']), str(paths['current.ps1']), str(paths['before.ps1']),
                    str(work), 'before' if before else 'current']
            case.assertLessEqual(sum(len(part.encode('utf-8', errors='strict')) + 1 for part in argv), 60000)
            environment = windows_powershell_environment(executable, parent)
            supplied = dict(environment)
            completed = subprocess.run(argv, capture_output=True, check=False, timeout=30, env=environment)
            case.assertLessEqual(len(completed.stdout) + len(completed.stderr), 1048576)
            case.assertEqual(environment, supplied)
            case.assertEqual(dict(os.environ), parent)
            for name, content in inputs.items():
                case.assertEqual(paths[name].read_bytes(), content)
            for closing in closings:
                closing()
            producer_closing()
    return completed


class PowerShellNestedFunctionGraphTests(unittest.TestCase):
    def test_authentic_k_selector_red_current_genuine_graph_and_refusals(self):
        # Actual imported typed graph; the harmless function is never invoked.
        # The controlled display name is not an assertion about K's unprinted node.
        old = _actual_nested_function_graph_case(self, before=True)
        current = _actual_nested_function_graph_case(self, before=False)
        self.assertEqual(old.returncode, 1, (old.stdout, old.stderr))
        self.assertEqual(old.stdout.splitlines(), [
            b'SYNTHETIC_GRAPH_OLD_REFUSED:PUBLIC_NATIVE_HASH_FUNCTION_NESTED'])
        self.assertEqual(old.stderr.splitlines(), [b'SYNTHETIC_GRAPH_COMMON_POSITIVE_MUST_ADMIT'])
        import io
        class SamePositive(unittest.TestCase):
            def runTest(inner):
                inner.assertEqual(inner.actual.returncode, 0, (inner.actual.stdout, inner.actual.stderr))
        outcomes = []
        for actual in (old, current):
            positive = SamePositive()
            positive.actual = actual
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite([positive]))
            outcomes.append((result.testsRun, len(result.failures), len(result.errors), len(result.skipped)))
        self.assertEqual(outcomes, [(1, 1, 0, 0), (1, 0, 0, 0)])
        self.assertEqual(current.returncode, 0, (current.stdout, current.stderr))
        self.assertEqual(current.stderr, b'')
        self.assertEqual(current.stdout.splitlines(), [
            b'SYNTHETIC_GRAPH_SAME_TYPED_POSITIVE_ACCEPTED',
            b'SYNTHETIC_GRAPH_REFUSED:foreign-script-reference',
            b'SYNTHETIC_GRAPH_REFUSED:missing-binary',
            b'SYNTHETIC_GRAPH_REFUSED:extra-node',
            b'SYNTHETIC_GRAPH_REFUSED:wrong-node-type',
            b'SYNTHETIC_GRAPH_REFUSED:missing-script-block',
            b'SYNTHETIC_GRAPH_REFUSED:empty-export-subset',
            b'SYNTHETIC_GRAPH_REFUSED:foreign-assembly',
            b'SYNTHETIC_GRAPH_REFUSED:foreign-export-counterpart',
            b'SYNTHETIC_GRAPH_COMPONENT_COMPLETE_NO_NATIVE_ACCEPTANCE'])
