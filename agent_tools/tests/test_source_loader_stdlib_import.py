"""Actual isolated import hook before/fix, including the scoped resolver."""
import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path


@unittest.skipUnless(os.name=='posix','POSIX copied-source custody fixture')
class StdlibImportTests(unittest.TestCase):
    def test_new_stdlib_submodule_is_imported_and_repository_resolver_stays_scoped(self):
        folder=Path(__file__).parent/'fixtures/source_loader_stdlib_import'
        old=(folder/'before.source').read_bytes();meta=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(meta['sourceSha256'],hashlib.sha256(old).hexdigest())
        current=(Path(__file__).parents[1]/'source_module_loader.py').read_bytes()
        for raw,fixed in ((old,False),(current,True)):
            with self.subTest(fixed=fixed),tempfile.TemporaryDirectory() as temporary:
                directory=Path(temporary).resolve()/'agent_tools';directory.mkdir()
                (directory/'source_module_loader.py').write_bytes(raw)
                custody=Path(__file__).parents[1]/'native_review_source_closure.py'
                (directory/custody.name).write_bytes(custody.read_bytes())
                (directory/'owned.py').write_text('VALUE=43\n')
                (directory/'entry.py').write_text('import importlib.metadata\nimport importlib.resources\nfrom importlib import import_module\ndef read():\n return importlib.metadata.version("pycdlib"),import_module("agent_tools.owned").VALUE\n')
                programme='''import importlib.util,sys
path=sys.argv[1];spec=importlib.util.spec_from_file_location('owned_loader',path+'/source_module_loader.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with module.request_scope(path):
 value=module.adapter(path,'entry').read()
 assert value==('1.14.0',43),value
'''
                result=subprocess.run([sys.executable,'-I','-B','-c',programme,str(directory)],capture_output=True,timeout=10)
                if fixed:self.assertEqual(0,result.returncode,result.stderr.decode())
                else:
                    self.assertNotEqual(0,result.returncode)
                    self.assertIn(b"has no attribute 'metadata'",result.stderr)


if __name__=='__main__':unittest.main()
