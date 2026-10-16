"""Owned path-context regressions for the unchanged historical catalogue guard.

The portable interpreter covers only the retained Substring prefix decision.
Actual provider normalization and the complete guard run on Windows with inert
temporary files; these tests make no VM or product acceptance claim.
"""
from __future__ import annotations

import ast
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from uuid import uuid4

from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


FIXTURE = Path(__file__).parent / "fixtures/windows_cp117_catalogue_path_context"
FRAGMENT_SHA256 = "484337e71329e9b291f1a3cd8b6b849b018c72ba2982d3353d17bd4544a51b60"
NORMALIZE = ("$cp117FixtureRawState=$state;$cp117FixtureRawContent=$cp117NewContent;"
             "$state=(Get-Item -LiteralPath $state -ErrorAction Stop).FullName;"
             "$cp117NewContent=(Get-Item -LiteralPath $cp117NewContent -ErrorAction Stop).FullName;")
NAMES = tuple("catalogue-owned-public-file-%02d.fixture" % index for index in range(5))


def actual_normalization():
    """Read the one current fixture statement without importing its factories."""
    path = Path(__file__).with_name("test_windows_cp117_server_read_binding.py")
    limit = 2 * 1024**2
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("catalogue current fixture source bound")
    tree = ast.parse(raw, filename=str(path))
    methods = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and node.name == "test_actual_catalogue_through_three_acl_fragments_old_collision_unique_binding"]
    if len(methods) != 1:
        raise ValueError("catalogue current fixture method is not unique")
    statements = [node.value.value for node in ast.walk(methods[0])
                  if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)
                  and isinstance(node.target, ast.Name) and node.target.id == "setup"
                  and isinstance(node.value, ast.Constant) and type(node.value.value) is str
                  and node.value.value.startswith("$cp117FixtureRawState")]
    if len(statements) != 1 or statements[0] != NORMALIZE:
        raise ValueError("catalogue current fixture normalization changed")
    return statements[0]


def retained_guard():
    raw = (FIXTURE / "catalogue-fragment.before.ps1").read_bytes()
    if hashlib.sha256(raw).hexdigest() != FRAGMENT_SHA256:
        raise ValueError("catalogue original fragment changed")
    guard = raw.decode("utf-8", "strict").splitlines()[-1]
    if not guard.startswith("if(@(Get-ChildItem $state -Force).Count"):
        raise ValueError("catalogue original final guard unavailable")
    return guard


def prefix_projection(supplied_root, provider_full_names):
    """Interpret only the exact retained .NET UTF-16 Substring offset.

    Explicit provider FullName strings are input observations here. No host path
    is discovered, normalized through a different OS, or granted authority.
    """
    guard = retained_guard()
    offsets = re.findall(r"\$_\.FullName\.Substring\(\$cp117NewContent\.Length\+([0-9]+)\)", guard)
    if len(offsets) != 1:
        raise ValueError("catalogue original prefix expression changed")
    if type(supplied_root) is not str or not ntpath.isabs(supplied_root) or "\0" in supplied_root:
        raise ValueError("catalogue explicit Windows root required")
    units = len(supplied_root.encode("utf-16-le", "surrogatepass")) // 2 + int(offsets[0])
    answer = []
    for full_name in provider_full_names:
        if type(full_name) is not str or not ntpath.isabs(full_name) or "\0" in full_name:
            raise ValueError("catalogue explicit provider FullName required")
        raw = full_name.encode("utf-16-le", "surrogatepass")
        if units * 2 > len(raw):
            raise ValueError("catalogue .NET Substring index outside FullName")
        answer.append(raw[units * 2:].decode("utf-16-le", "surrogatepass"))
    return tuple(sorted(answer))


def bound_provider_root(lexical_root, provider_full_name):
    """A portable fixture-input seam, separate from actual provider admission."""
    if (type(lexical_root) is not str or type(provider_full_name) is not str
            or not ntpath.isabs(lexical_root) or not ntpath.isabs(provider_full_name)
            or "\0" in lexical_root or "\0" in provider_full_name
            or ntpath.normpath(provider_full_name) != provider_full_name
            or ntpath.normcase(ntpath.normpath(lexical_root)) != ntpath.normcase(provider_full_name)):
        raise ValueError("catalogue provider context does not name the explicit Windows root")
    return provider_full_name


class PortableCataloguePrefixTests(unittest.TestCase):
    def test_valid_parent_alias_projects_wrong_names_until_provider_root_is_supplied(self):
        for owned_parent in (r"Q:\owned fixture\run-a", r"D:\explicit\longer-parent\run-b"):
            with self.subTest(parent=owned_parent):
                lexical = owned_parent + r"\existing-parent\..\content"
                provider = owned_parent + r"\content"
                observed = tuple(provider + "\\" + name for name in NAMES)
                self.assertNotEqual(NAMES, prefix_projection(lexical, observed))
                self.assertEqual(NAMES, prefix_projection(bound_provider_root(lexical, provider), observed))

    def test_normalized_projection_retains_exact_foreign_missing_duplicate_and_case_refusals(self):
        provider = r"Q:\explicit fixture\run-current\content"
        observed = tuple(provider + "\\" + name for name in NAMES)
        self.assertEqual(NAMES, prefix_projection(provider, observed))
        alternatives = (observed + (provider + r"\foreign.fixture",), observed[:-1],
                        observed + observed[:1],
                        (provider + "\\" + NAMES[0].upper(),) + observed[1:])
        for changed in alternatives:
            with self.subTest(names=changed):
                self.assertNotEqual(NAMES, prefix_projection(provider, changed))

    def test_provider_context_cannot_relabel_an_unrelated_root(self):
        with self.assertRaises(ValueError):
            bound_provider_root(r"Q:\explicit\existing-parent\..\content", r"Q:\other\content")
        with self.assertRaises(ValueError):
            bound_provider_root(r"Q:\explicit\existing-parent\..\content", r"Q:\explicit\other\..\content")

    def test_preserved_complete_original_method_and_fragment_match_exact_b_provenance(self):
        provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
        expected = {"before.fragment": "f7b72d3ecded96b1c78cbdbe9a016b621a61231af146131edb49dac5a6e9c013",
                    "catalogue-fragment.before.ps1": FRAGMENT_SHA256}
        rows = provenance.get("beforeimages")
        self.assertIs(type(rows), list)
        self.assertEqual(len(expected), len(rows))
        self.assertTrue(all(type(row) is dict and type(row.get("file")) is str for row in rows))
        names = [row["file"] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(expected), set(names))
        for item in rows:
            self.assertEqual(expected[item["file"]], item.get("sha256"))
            raw = (FIXTURE / item["file"]).read_bytes()
            self.assertEqual(item["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("COMPLETE_CATALOGUE_DRIFT", retained_guard())
        self.assertEqual(NORMALIZE, actual_normalization())


@unittest.skipUnless(os.name == "nt", "actual Windows provider FullName and PowerShell guard")
class NativeCatalogueProviderTests(unittest.TestCase):
    def run_saved(self, executable, evidence, name, source):
        path = evidence / (name + ".ps1")
        raw = b"\xef\xbb\xbf" + source.encode("utf-8", "strict")
        with path.open("xb") as stream:
            stream.write(raw)
        command = [executable, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)]
        self.assertLessEqual(sum(len(word.encode("utf-8")) + 1 for word in command), 60_000)
        environment = windows_powershell_environment(executable, os.environ)
        record = {"schemaVersion": 1, "case": name, "argv": command,
                  "scriptSha256": hashlib.sha256(raw).hexdigest(), "timedOut": False,
                  "nativeProductAcceptance": False}
        try:
            result = subprocess.run(command, capture_output=True, timeout=20, check=False, env=environment)
            stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, returncode = error.stdout or b"", error.stderr or b"", None
            record["timedOut"] = True
        for stream_name, body in (("stdout", stdout), ("stderr", stderr)):
            with (evidence / (name + "." + stream_name)).open("xb") as stream:
                stream.write(body)
            record[stream_name] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        record["returncode"] = returncode
        with (evidence / (name + ".json")).open("x", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True, indent=2)
        self.assertFalse(record["timedOut"], "owned fixture timed out; raw streams retained at " + str(evidence))
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    def test_actual_alias_red_provider_normalization_green_and_foreign_file_refused(self):
        executable = shutil.which("powershell.exe") or shutil.which("powershell")
        self.assertIsNotNone(executable, "Windows routine requires actual Windows PowerShell")
        repository = Path(__file__).resolve().parents[2]
        evidence_parent = repository / ".runtime/windows-catalogue-path-context"
        evidence_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        evidence = evidence_parent / str(uuid4())
        evidence.mkdir(mode=0o700)
        literal = lambda value: "'" + str(value).replace("'", "''") + "'"
        guard = retained_guard()
        normalization = actual_normalization()
        with tempfile.TemporaryDirectory(prefix="cp117-catalogue-path-") as temporary:
            root = Path(temporary).resolve()
            existing_parent = root / "existing-parent"
            existing_parent.mkdir()
            state, content = root / "state", root / "content"
            state.mkdir()
            content.mkdir()
            for name in NAMES:
                (content / name).write_bytes(b"PUBLIC")
            # This existing alias is valid independently of optional 8.3 names.
            raw_state = existing_parent / ".." / "state"
            raw_content = existing_parent / ".." / "content"
            setup = ("$ErrorActionPreference='Stop';$state=" + literal(raw_state)
                     + ";$cp117NewContent=" + literal(raw_content)
                     + ";$expected=@(" + ",".join(literal(name) for name in NAMES) + ");\n")
            old = self.run_saved(executable, evidence, "raw-prefix-red", setup + guard + "\n")
            self.assertNotEqual(0, old.returncode, "raw alias unexpectedly matched; evidence " + str(evidence))
            self.assertIn(b"COMPLETE_CATALOGUE_DRIFT", old.stderr + old.stdout)
            normalized = setup + normalization + "\n" + guard + "\n"
            current = self.run_saved(executable, evidence, "provider-normalized-green",
                                     normalized + "[Console]::Out.Write('CATALOGUE_PROVIDER_GREEN')\n")
            self.assertEqual(0, current.returncode, "evidence " + str(evidence) + "; stderr=" + repr(current.stderr))
            self.assertEqual(b"CATALOGUE_PROVIDER_GREEN", current.stdout)
            (content / "foreign.fixture").write_bytes(b"FOREIGN")
            foreign = self.run_saved(executable, evidence, "foreign-file-negative", normalized)
            self.assertNotEqual(0, foreign.returncode, "foreign catalogue admitted; evidence " + str(evidence))
            self.assertIn(b"COMPLETE_CATALOGUE_DRIFT", foreign.stderr + foreign.stdout)


if __name__ == "__main__":
    unittest.main()
