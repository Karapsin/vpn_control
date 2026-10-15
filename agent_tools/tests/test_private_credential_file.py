"""Real private credential custody; never prints or hashes the credential."""
import os,tempfile,unittest
from pathlib import Path
from agent_tools.private_credential_file import SecretFile

@unittest.skipUnless(os.name=='posix','POSIX secret-file ownership')
class SecretFileTests(unittest.TestCase):
    def test_explicit_path_single_line_and_source_exchange_are_guarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'credential';path.write_bytes(b'PUBLIC_SENTINEL\n');path.chmod(0o600)
            with SecretFile(str(path.resolve())) as held:
                self.assertEqual('PUBLIC_SENTINEL',held.text);held.guard()
                replacement=path.with_suffix('.replacement');replacement.write_bytes(b'PUBLIC_SENTINEL\n');replacement.chmod(0o600);replacement.replace(path)
                with self.assertRaises(ValueError):held.guard()
            self.assertIsNone(held.text)
    def test_unowned_modes_links_and_multiple_lines_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'credential'
            for body,mode in ((b'PUBLIC',0o644),(b'PUBLIC\nSECOND',0o600)):
                path.write_bytes(body);path.chmod(mode)
                with self.assertRaises(ValueError):SecretFile(str(path.resolve()))
            path.write_bytes(b'PUBLIC');path.chmod(0o600);link=root/'link';link.symlink_to(path)
            with self.assertRaises(ValueError):SecretFile(str(link.absolute()))

if __name__=='__main__':unittest.main()
