"""Actual fixed host-program causal checks, with explicit local projections.

TempFS path, UID1000 metadata, disk budget and public six-byte input are seams.
These tests prove neither SSH, native Windows, artifact provenance nor owner state.
"""
import ast
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import windows_tertiary_fixture_stage as stage


class HostStageTests(unittest.TestCase):
    def test_capture_requires_existing_private_leaf_before_dispatch(self):
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            (root/'.runtime/parity-evidence').mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                AuthorityCapture(root,'fixed-tertiary-upload')
            self.assertEqual(list((root/'.runtime/parity-evidence').iterdir()),[])
            leaf=root/'.runtime/parity-evidence/fixed-tertiary-upload'
            leaf.mkdir(mode=0o700)
            capture=AuthorityCapture(root,leaf.name)
            try:
                capture.create('intent.json',b'{"guestAction":false}')
                self.assertEqual((leaf/'intent.json').read_bytes(),b'{"guestAction":false}')
            finally:capture.close()

    def execute(self, *, exchange=False, ancestor_exchange=False, file_exchange=False, publish_exchange=False, content_drift=False):
        correlation='11111111-1111-4111-8111-111111111111'
        request={'correlation':correlation,'hostStage':stage.ROOT+'/fixture-'+correlation,
                 'targetSha256':stage.TARGET_SHA256,'targetSize':stage.TARGET_SIZE,
                 'sourceSha':stage.SOURCE_SHA,'installerAuthorized':False}
        programme=stage.host_stage_program(request)
        tree=ast.parse(programme)
        # Only the public test input fields change; execute the full production body.
        request=dict(request,targetSize=6,targetSha256=__import__('hashlib').sha256(b'PUBLIC').hexdigest())
        tree.body[0]=ast.parse('REQUEST='+repr(request)).body[0]
        with tempfile.TemporaryDirectory() as tmp:
            top=Path(tmp)
            def mapped(path):
                if isinstance(path,int):return path
                value=os.fspath(path)
                return str(top/value.lstrip('/')) if value.startswith('/') else value
            for path in ('/home','/home/kardinal',stage.ROOT):Path(mapped(path)).mkdir(mode=0o700,parents=True,exist_ok=True)
            target=Path(mapped(request['hostStage']));held=target.with_name(target.name+'-held')
            def metadata(info):
                values={n:getattr(info,n) for n in dir(info) if n.startswith('st_')}
                values['st_uid']=1000;values['st_gid']=1000
                return SimpleNamespace(**values)
            def exchange_stage():
                target.rename(held);target.mkdir(mode=0o700)
                (target/'foreign').write_bytes(b'KEEP')
            class OsView:
                def __getattr__(self,name):return getattr(os,name)
                def geteuid(self):return 1000
                def lstat(self,p):return metadata(os.lstat(mapped(p)))
                def stat(self,p,**kw):return metadata(os.stat(mapped(p),**kw))
                def fstat(self,fd):return metadata(os.fstat(fd))
                def mkdir(self,p,mode=0o777):return os.mkdir(mapped(p),mode)
                def open(self,p,*a,**kw):
                    if publish_exchange and p=='complete.json':exchange_stage()
                    if content_drift and p=='complete.json':(target/'target.msi').write_bytes(b'FORGED')
                    return os.open(mapped(p),*a,**kw)
                def statvfs(self,p):return SimpleNamespace(f_bavail=1<<30,f_frsize=4096)
            class Input(io.BytesIO):
                fired=False
                def read(self,n=-1):
                    if (exchange or ancestor_exchange or file_exchange) and not self.fired:
                        self.fired=True
                        if ancestor_exchange:
                            root=Path(mapped(stage.ROOT));root.rename(root.with_name(root.name+'-held'));root.mkdir(mode=0o700)
                            target.mkdir(mode=0o700)
                        elif file_exchange:
                            (target/'target.msi').rename(target/'target-held.msi')
                            (target/'target.msi').write_bytes(b'KEEP')
                        else:exchange_stage()
                        if ancestor_exchange:(target/'foreign').write_bytes(b'KEEP')
                    return super().read(n)
            stdin=Input(b'PUBLIC');proxy=OsView();real_import=__import__
            def imports(name,*a,**kw):
                if name=='os':return proxy
                if name=='sys':return SimpleNamespace(stdin=SimpleNamespace(buffer=stdin))
                return real_import(name,*a,**kw)
            builtins=dict(vars(__import__('builtins')),__import__=imports)
            output=io.StringIO();error=None
            try:
                with redirect_stdout(output):exec(compile(tree,'actual-fixed-host-stage','exec'),{'__builtins__':builtins})
            except Exception as e:error=e
            files=set(p.name for p in target.iterdir()) if target.exists() else set()
            foreign=(target/'foreign').read_bytes() if 'foreign' in files else (target/'target.msi').read_bytes() if file_exchange else None
            return error,output.getvalue(),files,foreign

    def test_whole_entry_refuses_stage_exchange_before_success_or_foreign_change(self):
        error,out,files,foreign=self.execute(exchange=True)
        self.assertIsInstance(error,ValueError)
        self.assertNotIn('"staged"',out)
        self.assertEqual(files,{'foreign'})
        self.assertEqual(foreign,b'KEEP')

    def test_whole_entry_refuses_ancestor_exchange(self):
        error,out,files,foreign=self.execute(ancestor_exchange=True)
        self.assertIsInstance(error,ValueError)
        self.assertNotIn('"staged"',out)
        self.assertEqual(files,{'foreign'})
        self.assertEqual(foreign,b'KEEP')

    def test_whole_entry_refuses_target_file_exchange(self):
        error,out,files,foreign=self.execute(file_exchange=True)
        self.assertIsInstance(error,ValueError)
        self.assertNotIn('"staged"',out)
        self.assertNotIn('complete.json',files)
        self.assertEqual(foreign,b'KEEP')

    def test_whole_entry_refuses_stage_exchange_during_completion_publication(self):
        error,out,files,foreign=self.execute(publish_exchange=True)
        self.assertIsInstance(error,ValueError)
        self.assertNotIn('"staged"',out)
        self.assertEqual(files,{'foreign'})
        self.assertEqual(foreign,b'KEEP')

    def test_whole_entry_refuses_same_inode_content_drift_during_completion(self):
        error,out,_,_=self.execute(content_drift=True)
        self.assertIsInstance(error,ValueError)
        self.assertNotIn('"staged"',out)

    def test_whole_entry_streams_completes_and_emits_exact_receipt(self):
        error,out,files,foreign=self.execute()
        self.assertIsNone(error)
        self.assertEqual(json.loads(out),{'state':'staged','sha256':__import__('hashlib').sha256(b'PUBLIC').hexdigest(),'length':6})
        self.assertEqual(files,{'binding.json','upload-intent.json','target.msi','complete.json'})
        self.assertIsNone(foreign)

    def test_factory_rejects_foreign_root_source_and_package(self):
        request={'correlation':'11111111-1111-4111-8111-111111111111','hostStage':stage.ROOT+'/fixture-11111111-1111-4111-8111-111111111111','targetSha256':stage.TARGET_SHA256,'targetSize':stage.TARGET_SIZE,'sourceSha':stage.SOURCE_SHA,'installerAuthorized':False}
        for key,value in [('hostStage','/foreign'),('sourceSha','0'*40),('targetSha256','0'*64),('targetSize',6),('installerAuthorized',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):stage.host_stage_program(dict(request,**{key:value}))
