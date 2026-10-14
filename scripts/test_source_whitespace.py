import pathlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import check_source_whitespace as checker


class SourceWhitespaceTest(unittest.TestCase):
    def test_actual_fast_checks_boundary_preserves_only_authenticated_archives(self):
        repository = pathlib.Path(__file__).resolve().parents[1]
        workflow = pathlib.Path(os.environ.get(
            "SOURCE_WHITESPACE_WORKFLOW", repository / ".github/workflows/fast-checks.yml"))
        lines = workflow.read_text(encoding="utf-8").splitlines()
        start = lines.index("      - name: Check whitespace")
        run = next(i for i in range(start + 1, len(lines))
                   if lines[i].lstrip().startswith("run:"))
        command = lines[run].split("run:", 1)[1].strip()
        if command == "|":
            body = []
            for line in lines[run + 1:]:
                if line and not line.startswith("          "):
                    break
                body.append(line[10:] if line else "")
            command = "\n".join(body)
        names = tuple(checker.HISTORICAL_BYTE_ARCHIVES)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "scripts").mkdir()
            shutil.copy2(repository / "scripts/check_source_whitespace.py",
                         root / "scripts/check_source_whitespace.py")
            for name in names:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((repository / name).read_bytes())
            subprocess.run(["git", "add", "."], cwd=root, check=True)

            def check(expected, path=None):
                env = dict(os.environ, PATH=str(pathlib.Path(sys.executable).parent)
                           + os.pathsep + os.environ.get("PATH", os.defpath))
                result = subprocess.run(["bash", "-c", command], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
                if path is not None:
                    self.assertIn(path, result.stdout + result.stderr)

            check(0)
            for name in names:
                with self.subTest(archive=name):
                    target = root / name
                    original = target.read_bytes()
                    target.write_bytes(original + b"# changed authenticated bytes\n")
                    check(1, name)
                    target.write_bytes(original)
            # Exact bytes at an unlisted path remain ordinary source, as do
            # both tracked and not-yet-staged source edits.
            (root / "unlisted.source").write_bytes((root / names[0]).read_bytes())
            subprocess.run(["git", "add", "unlisted.source"], cwd=root, check=True)
            check(1, "unlisted.source")
            (root / "unlisted.source").write_bytes(b"ordinary source\n")
            (root / "new.py").write_bytes(b"ordinary source \n")
            check(1, "new.py")
            (root / "new.py").write_bytes(b"ordinary source\n")
            check(0)

    def test_untracked_source_is_checked_before_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / '.gitignore').write_text('ignored/\n')
            (root / 'new.py').write_bytes(b'except Exception: \n    pass\n')
            (root / 'tracked.txt').write_bytes(b'clean\n')
            subprocess.run(['git', 'add', 'tracked.txt'], cwd=root, check=True)
            (root / 'ignored').mkdir()
            (root / 'ignored' / 'secret').write_bytes(b'ignored \n')
            (root / 'binary').write_bytes(b'prefix \n\0binary')
            self.assertEqual(['new.py'], checker.violations(root))
            (root / 'new.py').write_bytes(b'except Exception:\n    pass\n')
            self.assertEqual([], checker.violations(root))

    def test_only_exact_authenticated_historical_bytes_are_exempt(self):
        repository = pathlib.Path(__file__).resolve().parents[1]
        names = [f"agent_tools/tests/fixtures/android_api35_historical_{part}.source"
                 for part in ("arm", "metadata", "readmission")]
        names.append("agent_tools/tests/fixtures/windows_cp117_historical_factory/provider_f54029cf.source")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((repository / name).read_bytes())
            self.assertEqual([], checker.violations(root))
            (root / "unlisted.source").write_bytes(b"ordinary \n")
            for name in names:
                with self.subTest(archive=name):
                    changed = root / name
                    original = changed.read_bytes()
                    changed.write_bytes(original + b"changed \n")
                    self.assertEqual([name, "unlisted.source"], checker.violations(root))
                    changed.write_bytes(original)

    def test_chunk_boundary_crlf_and_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            for name, data in {'boundary': b'x' * 65534 + b' \r\n', 'eof': b'x\t', 'clean': b'ok\r\n'}.items():
                (root / name).write_bytes(data)
            self.assertEqual(['boundary', 'eof'], checker.violations(root))


if __name__ == '__main__':
    unittest.main()
