"""Append-only routine candidate: actual assembled PS parser, never body execution."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

class CompleteServerBodyParserTests(unittest.TestCase):
    def test_actual_finally_loss_whole_body_refuses_restored_body_parses(self):
        interpreter = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
        if interpreter is None:
            if os.name == "nt":
                self.fail("PowerShell is required for the Windows full-body parser regression")
            self.skipTest("PowerShell parser is unavailable on this host")
        fixture = Path(__file__).parent / "fixtures/windows_cp117_server_preflight"
        expected = {'finally-loss': '24001dcaed1e666438e18497abde4594b6f3121b28c339a569b11955da0d3a21', 'finally-restored': 'dc4ea223703ea8b16faa07d1b6d231d45b30d078f09e4e1e4954241a3be9efa6'}
        bodies = {name: (fixture / (name + ".source")).read_bytes() for name in expected}
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256(bodies[name]).hexdigest(), digest)
        closing = b"}finally{foreach($cp117Held in $cp117StageHandles){$cp117Held.Dispose()}}\n"
        self.assertEqual(bodies["finally-loss"] + closing, bodies["finally-restored"])
        parser = "$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors);[Console]::WriteLine(($errors|ForEach-Object {$_.ErrorId}) -join ',');if($errors.Count){exit 1}"
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "parse-only.ps1"
            script.write_text(parser, encoding="utf-8")
            results = {}
            for name, body in bodies.items():
                target = Path(directory) / (name + ".ps1")
                target.write_bytes(body)
                results[name] = subprocess.run([interpreter, "-NoProfile", "-NonInteractive", "-File", str(script), str(target)], capture_output=True, timeout=15)
        old = results["finally-loss"]
        current = results["finally-restored"]
        self.assertEqual(old.returncode, 1, old.stderr.decode(errors="replace"))
        self.assertEqual(set(old.stdout.decode().strip().split(",")), {"MissingEndCurlyBrace", "MissingCatchOrFinally"})
        self.assertEqual(current.returncode, 0, current.stderr.decode(errors="replace"))
        self.assertEqual(current.stdout.strip(), b"")

if __name__ == "__main__":
    unittest.main()
