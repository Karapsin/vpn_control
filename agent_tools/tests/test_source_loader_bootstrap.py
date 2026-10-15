"""Bootstrap custody precedes closure code execution on owned source copies."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/source_loader_bootstrap'
LIMIT=4*1024**2


class BootstrapFixture:
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()
        self.tools=self.root/'agent_tools';self.tools.mkdir(mode=0o700)
        self.marker=self.root/'unsafe-closure-executed'
        source=os.environ.get('VPN_BOOTSTRAP_LOADER_SOURCE')
        self.loader_path=self.tools/'source_module_loader.py'
        shutil.copyfile(Path(source) if source else ROOT/'agent_tools/source_module_loader.py',self.loader_path)
        self.closure=self.tools/'native_review_source_closure.py'
        self.closure.write_bytes((ROOT/'agent_tools/native_review_source_closure.py').read_bytes())
        (self.tools/'fixture_entry.py').write_text('VALUE=42\n')
        name='agent_tools._bootstrap_fixture_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(name,self.loader_path)
        self.loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.loader)
    def marked(self):
        return self.closure.read_bytes()+('\nfrom pathlib import Path as _MarkerPath\n_MarkerPath('+repr(str(self.marker))+').write_text("executed")\n').encode()
    def refuse_before_exec(self,directory=None):
        prefixes={name for name in sys.modules if name.startswith('_vpn_source_')}
        descriptors=Path('/dev/fd') if Path('/dev/fd').is_dir() else Path('/proc/self/fd')
        count=len(os.listdir(descriptors)) if descriptors.is_dir() else None
        rejected=False
        try:adapter=self.loader.Adapter(directory or self.tools,'fixture_entry')
        except (OSError,ValueError):rejected=True
        else:adapter.close()
        self.assertFalse(self.marker.exists(),'unsafe closure executed before bootstrap custody')
        self.assertTrue(rejected,'unsafe bootstrap must refuse before adapter construction')
        self.assertEqual(prefixes,{name for name in sys.modules if name.startswith('_vpn_source_')})
        if count is not None:self.assertEqual(count,len(os.listdir(descriptors)),'bootstrap descriptors leaked')
    def valid_source(self):
        adapter=self.loader.Adapter(self.tools,'fixture_entry')
        try:self.assertEqual(42,adapter.VALUE);adapter._session.guard()
        finally:adapter.close()


@unittest.skipUnless(os.name=='posix','POSIX nofollow/current UID source bootstrap required')
class PosixBootstrapTests(BootstrapFixture,unittest.TestCase):
    def test_regular_helper_retains_normal_transitive_custody(self):self.valid_source()
    def test_symlinked_helper_never_executes_before_refusal(self):
        raw=self.marked();target=self.root/'untrusted.py';target.write_bytes(raw)
        self.closure.unlink();self.closure.symlink_to(target)
        self.refuse_before_exec()
    def test_hardlinked_helper_never_executes_before_refusal(self):
        self.closure.write_bytes(self.marked());os.link(self.closure,self.root/'extra-link.py')
        self.refuse_before_exec()
    def test_symlinked_ancestor_never_executes_before_refusal(self):
        self.closure.write_bytes(self.marked());link=self.root/'linked-tools';link.symlink_to(self.tools,target_is_directory=True)
        self.refuse_before_exec(link)
    def test_oversized_helper_never_executes_before_refusal(self):
        self.closure.write_bytes(self.marked()+b'\n#'+b'x'*LIMIT)
        self.refuse_before_exec()
    def test_foreign_uid_helper_never_executes_before_refusal(self):
        self.closure.write_bytes(self.marked());inode=self.closure.stat().st_ino;real=os.fstat
        def foreign(fd):
            info=real(fd)
            if info.st_ino!=inode:return info
            result=types.SimpleNamespace(**{name:getattr(info,name) for name in dir(info) if name.startswith('st_')})
            result.st_uid=os.getuid()+1;return result
        with mock.patch.object(os,'fstat',side_effect=foreign):self.refuse_before_exec()
    def exchange_during_read(self,ancestor):
        raw=self.marked();self.closure.write_bytes(raw);inode=self.closure.stat().st_ino
        real=os.read;changed=[]
        def read(fd,size):
            body=real(fd,size)
            if body and not changed and os.fstat(fd).st_ino==inode:
                changed.append(True)
                if ancestor:
                    self.tools.rename(self.root/'original-tools');self.tools.mkdir(mode=0o700)
                else:self.closure.rename(self.root/'original-closure.py')
                self.closure.write_bytes(raw)
            return body
        with mock.patch.object(os,'read',side_effect=read):self.refuse_before_exec()
        self.assertEqual([True],changed)
    def test_same_byte_helper_generation_exchange_before_exec_refuses(self):self.exchange_during_read(False)
    def test_named_ancestor_exchange_before_exec_refuses(self):self.exchange_during_read(True)
    def test_preserved_bootstrap_beforeimage_executes_unsafe_marker(self):
        raw=(FIXTURE/'before.source').read_bytes();proof=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(proof['beforeSha256'],hashlib.sha256(raw).hexdigest())
        self.loader_path.write_bytes(raw)
        name='agent_tools._bootstrap_before_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_file_location(name,self.loader_path)
        self.loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.loader)
        target=self.root/'untrusted.py';target.write_bytes(self.marked())
        self.closure.unlink();self.closure.symlink_to(target)
        with self.assertRaisesRegex(AssertionError,'unsafe closure executed before bootstrap custody'):
            self.refuse_before_exec()


@unittest.skipUnless(os.name=='nt','Native WindowsHeld bootstrap requires Windows')
class WindowsBootstrapTests(BootstrapFixture,unittest.TestCase):
    def test_regular_helper_keeps_native_windows_handles(self):self.valid_source()
    def test_hardlinked_helper_never_executes_before_windows_refusal(self):
        self.closure.write_bytes(self.marked());os.link(self.closure,self.root/'extra-link.py')
        self.refuse_before_exec()


if __name__=='__main__':unittest.main()
