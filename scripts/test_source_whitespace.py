import pathlib
import subprocess
import tempfile
import unittest

import check_source_whitespace as checker


class SourceWhitespaceTest(unittest.TestCase):
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
