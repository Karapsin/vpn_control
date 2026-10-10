"""Same offline tests against authentic beforeimage or narrow streaming candidate."""
import ast
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import pathlib
import re
import stat
import sys
import tempfile
import tracemalloc
import types
import unittest

ROOT = Path(__file__).resolve().parents[2]

def public_literal(path, name):
    tree=ast.parse(path.read_bytes())
    nodes=[node for node in tree.body if isinstance(node,ast.Assign)
      and any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
    assert len(nodes)==1
    return ast.literal_eval(nodes[0].value)

class OwnUidView:
    """Only owns TempFS and a synthetic UID; no native principal is asserted."""
    def __init__(self): self.read_hook = None;self.opened=set()
    def __getattr__(self, name): return getattr(os, name)
    def statview(self, result):
        return types.SimpleNamespace(**{n:1000 if n in ('st_uid','st_gid') else getattr(result,n)
          for n in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')})
    def stat(self,*args,**kwargs):return self.statview(os.stat(*args,**kwargs))
    def fstat(self,*args,**kwargs):return self.statview(os.fstat(*args,**kwargs))
    def open(self,*args,**kwargs):
        fd=os.open(*args,**kwargs);self.opened.add(fd);return fd
    def close(self,fd):
        try:return os.close(fd)
        finally:self.opened.discard(fd)
    def read(self,fd,count):
        value=os.read(fd,count)
        if self.read_hook is not None:self.read_hook(fd,value)
        return value

def context():
    census=ast.parse(public_literal(ROOT/'agent_tools/android_avd_launch_recovery.py','_CENSUS'))
    getter=ast.parse(public_literal(ROOT/'agent_tools/android_api35_coldboot_product_observation.py','_GETTER'))
    names={'fp','parent_fds','guard_parents','close_parents','read_fixed','facts','tree_facts'}
    selected=[node for node in census.body if isinstance(node,ast.FunctionDef) and node.name in names]
    getter_node=next(node for node in getter.body if isinstance(node,ast.FunctionDef) and node.name=='getter_stage')
    selected.append(getter_node)
    assert {node.name for node in selected}==names|{'getter_stage'}
    ns=dict(os=OwnUidView(),pathlib=pathlib,Path=Path,hashlib=hashlib,stat=stat,re=re,json=json)
    exec(compile(ast.Module(body=selected,type_ignores=[]),'<public-getter-streaming-control>','exec',dont_inherit=True),ns)
    helper=next((node for node in getter_node.body if isinstance(node,ast.FunctionDef) and node.name=='hash_file'),None)
    if helper is not None:
        exec(compile(ast.Module(body=[helper],type_ignores=[]),'<public-nested-hash-extent>','exec',dont_inherit=True),ns)
    return ns

def wrapped_context():
    ns=context()
    trace=ast.parse(public_literal(ROOT/'agent_tools/android_avd_census_diagnostic.py','_TRACE'))
    alias=ast.parse(public_literal(ROOT/'agent_tools/android_avd_sdk_alias_census.py','_SAFE'))
    names={'finite_reason','ancestry_facts','remember','wrap_reader'}
    nodes=[n for n in trace.body if isinstance(n,ast.FunctionDef)and n.name in names]
    nodes += [n for n in alias.body if isinstance(n,ast.FunctionDef)and n.name in {'alias_history_guard','admitted_alias_read'}]
    reasons=next(ast.literal_eval(n.value)for n in trace.body if isinstance(n,ast.Assign)
      and any(isinstance(t,ast.Name)and t.id=='REASONS'for t in n.targets))
    ns.update(errno=errno,TAGS={},FAILURE={},ACTIVE='observation',REASONS=reasons,
      KNOWN_ALIAS={'files':{f'/owned/unrelated-alias-{i}':{'unused':True}for i in range(5)}})
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<public-authenticated-diagnostic-alias-context>','exec',dont_inherit=True),ns)
    for name in ('parent_fds','read_fixed','facts','tree_facts'):ns[name]=ns['wrap_reader'](ns[name],name)
    ns['_original_fixed_reader']=ns['read_fixed'];ns['read_fixed']=ns['admitted_alias_read']
    return ns

@unittest.skipUnless(os.name=='posix' and all(hasattr(os,name) for name in ('O_DIRECTORY','O_NOFOLLOW')),
    'real POSIX directory/file descriptor controls required')
class StreamingControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='stream-control-')
        self.root=Path(self.temp.name).resolve();self.ns=context()
    def tearDown(self):
        self.temp.cleanup()
        self.assertEqual(self.ns['os'].opened,set())
    def test_default_raw_and_prefix_contract(self):
        path=self.root/'body';raw=b'owned-raw-utf8-\xe2\x98\x83';path.write_bytes(raw)
        for limit in (len(raw),5):
            result=self.ns['read_fixed'](path,limit)
            self.assertEqual(result['raw'],raw[:limit]);self.assertEqual(result['bytesRead'],min(len(raw),limit))
            self.assertEqual(result['sha256'],hashlib.sha256(raw[:limit]).hexdigest())
            self.assertEqual(result['hashScope'],'full'if limit>=len(raw)else'prefix')
    def test_streaming_cap_and_short_read_refuse_truthfully(self):
        path=self.root/'bounded';raw=b'abcd'*65536;path.write_bytes(raw)
        reader=self.ns['hash_file']if 'hash_file' in self.ns else self.ns['read_fixed']
        kwargs={}
        result=reader(path,37,**kwargs)
        self.assertEqual(result['bytesRead'],37);self.assertEqual(result['hashScope'],'prefix')
        self.assertEqual(result['sha256'],hashlib.sha256(raw[:37]).hexdigest())
        actual=self.ns['os'].read
        def short(fd,count):return b''
        self.ns['os'].read=short
        try:
            with self.assertRaisesRegex(ValueError,'census_file_changed'):reader(path,len(raw),**kwargs)
        finally:self.ns['os'].read=actual
    def test_changed_body_and_named_inode_refuse(self):
        for case in ('body','named'):
            path=self.root/case;path.write_bytes(b'abcdefgh'*16384)
            fired=[False]
            def hook(fd,raw):
                if fired[0]:return
                fired[0]=True
                if case=='body':
                    with path.open('r+b')as target:target.write(b'changed!')
                else:
                    replacement=self.root/(case+'-replacement');replacement.write_bytes(b'abcdefgh'*16384)
                    os.replace(replacement,path)
            self.ns['os'].read_hook=hook
            with self.assertRaisesRegex(ValueError,'census_file_changed|census_ancestry_changed'):
                if 'hash_file' in self.ns:self.ns['hash_file'](path,1<<20)
                else:self.ns['read_fixed'](path,1<<20)
            self.ns['os'].read_hook=None
    def test_closed_descriptor_refuses_with_existing_sequential_cleanup_limit(self):
        path=self.root/'closed';path.write_bytes(b'x'*131072);fired=[False]
        def hook(fd,raw):
            if not fired[0]:fired[0]=True;os.close(fd)
        self.ns['os'].read_hook=hook
        # Existing helper finally closes the file before parents; declare this
        # concrete sequential cleanup limitation rather than calling it fixed.
        try:
            with self.assertRaises(OSError):
                if 'hash_file' in self.ns:self.ns['hash_file'](path,1<<20)
                else:self.ns['read_fixed'](path,1<<20)
            if 'hash_file' in self.ns:
                self.assertEqual(self.ns['os'].opened,set(),'nested leaf close skipped held parent cleanup')
        finally:
            self.ns['os'].read_hook=None
            for fd in tuple(self.ns['os'].opened):
                try:os.close(fd)
                except OSError:pass
                finally:self.ns['os'].opened.discard(fd)
    def test_getter_hashes_complete_body_without_discarded_large_allocation(self):
        stage=self.root/'android-cli-stage-control';tree=stage/'tree';tree.mkdir(parents=True)
        path=tree/'large.jar';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:os.ftruncate(fd,16<<20)
        finally:os.close(fd)
        with path.open('rb')as reader:digest=hashlib.file_digest(reader,'sha256').hexdigest()
        manifest={'directories':[],'files':[{'path':'large.jar','size':16<<20,'mode':0o600,'sha256':digest}]}
        getter={'stageId':'control','manifest':manifest,'manifestSha256':'c'*64,'rpmSha256':'d'*64,'cli':'/owned/control/cli'}
        for name,value in [('intent.json',{k:getter[k]for k in ('manifest','manifestSha256','rpmSha256')}),
          ('receipt.json',{'state':'published','cliPath':getter['cli'],'manifestSha256':getter['manifestSha256'],'rpmSha256':getter['rpmSha256']})]:
            target=stage/name;target.write_bytes(json.dumps(value).encode());target.chmod(0o600)
        self.ns.update(ROOT=self.root,GETTER=getter)
        before_read=self.ns['read_fixed'];observed=[]
        def observer(path,limit,**kwargs):
            result=before_read(path,limit,**kwargs)
            if path.name=='large.jar'and limit==268435456:observed.append((result['bytesRead'],result['sha256'],result['raw']is None))
            return result
        self.ns['read_fixed']=observer
        tracemalloc.start()
        try:pins=self.ns['getter_stage']();unused,peak=tracemalloc.get_traced_memory()
        finally:tracemalloc.stop()
        self.assertEqual(pins['large.jar']['sha256'],digest);self.assertEqual(pins['large.jar']['generation'][2],16<<20)
        if 'hash_file' in self.ns:observed=[(pins['large.jar']['bytesRead'],pins['large.jar']['sha256'],peak<=1<<20)]
        self.assertEqual([(n,h)for n,h,retained in observed],[(16<<20,digest)])
        self.assertLessEqual(peak,1<<20,'discarded getter body materialized in full')
        self.assertTrue(observed[0][2])

    def wrapped_stage(self):
        stage=self.root/'android-cli-stage-control';tree=stage/'tree';tree.mkdir(parents=True)
        path=tree/'small.jar';path.write_bytes(b'abcd'*65536);path.chmod(0o600)
        getter={'stageId':'control','manifest':{'directories':[],'files':[{'path':'small.jar','size':path.stat().st_size,'mode':0o600,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}]},
          'manifestSha256':'c'*64,'rpmSha256':'d'*64,'cli':'/owned/control/getter'}
        for name,value in [('intent.json',{k:getter[k]for k in ('manifest','manifestSha256','rpmSha256')}),
          ('receipt.json',{'state':'published','cliPath':getter['cli'],'manifestSha256':getter['manifestSha256'],'rpmSha256':getter['rpmSha256']})]:
            target=stage/name;target.write_text(json.dumps(value));target.chmod(0o600)
        return path,getter
    def test_authentic_wrapped_success_keeps_output_and_alias_population(self):
        path,getter=self.wrapped_stage();bare=self.ns;wrapped=wrapped_context()
        for ns in (bare,wrapped):ns.update(ROOT=self.root,GETTER=getter)
        before=copy.deepcopy(wrapped['KNOWN_ALIAS'])
        try:
            self.assertEqual(wrapped['getter_stage'](),bare['getter_stage']())
            self.assertEqual(wrapped['KNOWN_ALIAS'],before);self.assertEqual(wrapped['FAILURE'],{})
        finally:self.assertEqual(wrapped['os'].opened,set())
    def test_authentic_wrapped_failure_keeps_first_diagnostic_and_alias_population(self):
        path,getter=self.wrapped_stage();wrapped=wrapped_context();wrapped.update(ROOT=self.root,GETTER=getter)
        original=copy.deepcopy(wrapped['KNOWN_ALIAS']);info=path.stat();reads=[0]
        def hook(fd,raw):
            i=os.fstat(fd)
            if (i.st_dev,i.st_ino)==(info.st_dev,info.st_ino):
                reads[0]+=1
                if reads[0]==2:raise OSError(errno.EIO,'own injected read error')
        wrapped['os'].read_hook=hook
        try:
            with self.assertRaises(OSError):wrapped['getter_stage']()
            self.assertTrue(wrapped['FAILURE'],'actual first read diagnostic discarded')
            self.assertEqual(wrapped['FAILURE']['reader'],'read_fixed')
            self.assertEqual(wrapped['FAILURE']['reason'],'io-error')
            self.assertTrue(wrapped['FAILURE']['ancestry'])
            self.assertEqual(wrapped['KNOWN_ALIAS'],original)
        finally:self.assertEqual(wrapped['os'].opened,set())

if __name__ == '__main__':
    unittest.main()
