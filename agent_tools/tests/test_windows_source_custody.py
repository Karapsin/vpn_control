"""Real Windows file sharing/reparse policy; other hosts explicitly skip."""
import hashlib,os,tempfile,unittest
from pathlib import Path
from agent_tools.windows_source_custody import WindowsHeld

@unittest.skipUnless(os.name=='nt','Windows native source handles required')
class WindowsSourceTests(unittest.TestCase):
    def test_sources_and_parent_names_remain_pinned_until_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'owned';base.mkdir();path=base/'source.py';path.write_bytes(b'PUBLIC_SOURCE')
            held=WindowsHeld()
            try:
                self.assertEqual(b'PUBLIC_SOURCE',held.read(str(path),hashlib.sha256(path.read_bytes()).hexdigest()))
                with self.assertRaises(OSError):path.write_bytes(b'REPLACED')
                with self.assertRaises(OSError):base.rename(base.with_name('renamed'))
                (base/'new-evidence.json').write_bytes(b'PUBLIC_EVIDENCE')
                held.finish();held.final_identity_pass()
            finally:held.close()
            path.write_bytes(b'AFTER_CLOSE')
    def test_wrong_digest_refuses_without_leaking_a_write_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'source.py';path.write_bytes(b'PUBLIC_SOURCE');held=WindowsHeld()
            try:
                with self.assertRaises(ValueError):held.read(str(path),'0'*64)
            finally:held.close()
            path.write_bytes(b'AFTER_CLOSE')

if __name__=='__main__':unittest.main()
