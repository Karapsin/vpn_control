"""Executable Hash-order regression, independent of POSIX operator imports.

Only the generated Hash/CensusLeaf execution is exercised. Protected ACL and
journal admission remain covered by the native scenario and structural checks.
"""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest


class TerminalPrefixExecutionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "requires Windows pwsh for NTAccount translation")
    def test_actual_generated_hash_dependency_old_fails_fixed_runs(self):
        path=Path(__file__).parents[1]/"windows_cp117_bound_absence_completion.py"
        tree=ast.parse(path.read_text())
        # Load exact production generator/leaf source without importing the
        # Linux/Mac operator's POSIX lock modules into Windows CI.
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="_effect_source"]
        leaf=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="_CENSUS_LEAF" for t in node.targets))
        namespace={"json":json,"closure":types.SimpleNamespace(_EQUAL=""),"_readonly_journal":lambda:"","_CENSUS_LEAF":leaf}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),"exec"),namespace)
        generated=namespace["_effect_source"]("",{"value":1},{})
        prefix=generated.split("$current=CensusLeaf 'binding.json'",1)[0]
        hash_definition=next(line for line in prefix.splitlines(True) if line.startswith("function Hash("))
        with tempfile.TemporaryDirectory() as directory:
            fixture=Path(directory)/"binding.json";fixture.write_text('{"value":1}',encoding="utf-8")
            setup="""
$JournalRoot=$args[0];$MaxBytes=16384
function Get-Acl {param($LiteralPath,$ErrorAction) return @{Owner=[Security.Principal.WindowsIdentity]::GetCurrent().Name}}
function AclRows {param($path) return 'inert-acl'}
function Assert-Leaf {param($name) return Get-Item -LiteralPath (Join-Path $JournalRoot $name)}
function EqualJson {param($left,$right) return (($left|ConvertTo-Json -Compress) -ceq ($right|ConvertTo-Json -Compress))}
$result=CensusLeaf 'binding.json' $wanted
[Console]::Out.WriteLine($result.state)
"""
            for label,script,expected in (("old",prefix.replace(hash_definition,"",1),"invalid-protected-read"),("fixed",prefix,"present-valid")):
                entry=Path(directory)/(label+".ps1");entry.write_text(script+setup,encoding="utf-8")
                result=subprocess.run([shutil.which("pwsh"),"-NoProfile","-NonInteractive","-File",str(entry),directory],capture_output=True,text=True,timeout=15,check=True)
                self.assertEqual(result.stdout.strip(),expected,label+": "+result.stderr)


if __name__ == "__main__":unittest.main()
