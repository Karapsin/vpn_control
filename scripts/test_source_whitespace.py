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

    def test_chunk_boundary_crlf_and_eof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            for name, data in {'boundary': b'x' * 65534 + b' \r\n', 'eof': b'x\t', 'clean': b'ok\r\n'}.items():
                (root / name).write_bytes(data)
            self.assertEqual(['boundary', 'eof'], checker.violations(root))


if __name__ == '__main__':
    unittest.main()
