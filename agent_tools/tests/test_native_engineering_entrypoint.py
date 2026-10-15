"""Actual future clean producer imports and fixed local protocol, no native calls."""
import io
import hashlib
import stat
import shutil
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_execution_context as context
from agent_tools.tests import test_native_execution_context as fixture

_HARNESS=r'''
import io,json,sys
from pathlib import Path
from unittest.mock import patch
source=Path(sys.argv[1]);root=Path(sys.argv[2]);packet=json.loads(sys.stdin.buffer.read() if sys.argv[3]=='-' else sys.argv[3])
sys.path.insert(0,str(source))
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_execution_context as context
from agent_tools import ssh_tmux_resource_admission as resource
from agent_tools import ssh_tmux_session_ssh as old
assert Path(build.__file__).resolve().is_relative_to(source)
assert Path(resource.__file__).resolve().is_relative_to(source)
seen=[]
def fixed_local_effect(storage,operation,raw,*,source_root,engineering_context):
 assert Path(storage)==root and Path(source_root)==source
 assert type(engineering_context)is context.EngineeringExecutionContext
 assert engineering_context.coordinator_root==root and engineering_context.source_root==source
 engineering_context.require_native_consumers((Path(build.__file__),Path(old.__file__)))
 seen.append(operation)
 if operation=='preflight':return {'state':'ready','sourceSha':raw['sourceSha'],'baseVersion':raw['baseVersion'],'targetVersion':raw['targetVersion'],'host':'archlinux','packageFamilies':['default','arch'],'nativeActionAllowed':False,'reason':'available'}
 return {'state':'unknown','correlationId':raw['correlationId'],'reason':'submission-response-uncertain' if operation=='start' else 'missing-journal','replayAllowed':False}
class In:
 buffer=io.BytesIO(json.dumps(packet).encode())
class Out:
 buffer=io.BytesIO()
result=Out()
with patch.object(resource,'operate',side_effect=fixed_local_effect),patch.object(resource,'directory',return_value=root),patch.object(sys,'stdin',In()),patch.object(sys,'stdout',result):
 build._engineering_main(root)
output=json.loads(result.buffer.getvalue());assert seen==[packet['operation']] or (packet['operation']=='start' and not seen and output.get('reason')=='already-journaled')
print(json.dumps(output,separators=(',',':')))
'''

# Test-only saved programmes. Every __file__ below is its real owned saved file.
_CACHE_PATH_PROGRAM=r'''
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
def verify(fd,path,expected):
 before=os.fstat(fd);named=path.lstat()
 pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid()
 assert pin(before)==pin(named) and 0<before.st_size<=2097152
 raw=os.pread(fd,before.st_size+1,0)
 assert len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected
 assert pin(before)==pin(os.fstat(fd))==pin(path.lstat())
 return pin(before)
helper=Path(sys.argv[1]);held=int(sys.argv[2]);programme=int(sys.argv[3])
verify(programme,Path(__file__),sys.argv[4]);verify(held,helper,sys.argv[5])
assert sys.pycache_prefix is None,'isolated-pre-guard-cache-prefix'
cache=importlib.util.cache_from_source(str(helper))
verify(programme,Path(__file__),sys.argv[4]);verify(held,helper,sys.argv[5])
print(json.dumps({'sourcePath':str(helper),'sourceSha256':sys.argv[5],
                  'pycachePrefix':sys.pycache_prefix,'cachePath':cache},sort_keys=True))
'''

_CACHE_TEST_PROGRAM=r'''
import hashlib,importlib,io,json,os,stat,sys,unittest
from pathlib import Path
def verify(fd,path,expected):
 before=os.fstat(fd);pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid()
 assert 0<before.st_size<=2097152 and pin(before)==pin(path.lstat())
 raw=os.pread(fd,before.st_size+1,0)
 assert len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==expected
 assert pin(before)==pin(os.fstat(fd))==pin(path.lstat())
root=Path(sys.argv[1]);test=Path(sys.argv[2]);held=int(sys.argv[3]);programme=int(sys.argv[4])
verify(programme,Path(__file__),sys.argv[5]);verify(held,test,sys.argv[6])
assert test==root/'agent_tools/tests/test_native_engineering_entrypoint.py'
assert sys.pycache_prefix==sys.argv[7]
os.umask(0o077)
sys.path.insert(0,str(root))
module=importlib.import_module('agent_tools.tests.test_native_engineering_entrypoint')
assert Path(module.__file__).resolve()==test.resolve()
suite=unittest.defaultTestLoader.loadTestsFromName('NativeEngineeringEntrypointTest.test_actual_script_rejects_stale_matching_bytecode_before_any_repository_import',module)
result=unittest.TextTestRunner(verbosity=2).run(suite)
verify(programme,Path(__file__),sys.argv[5]);verify(held,test,sys.argv[6])
print(json.dumps({'actualTestFile':module.__file__,'testSha256':sys.argv[6],
                  'pycachePrefix':sys.pycache_prefix,'testsRun':result.testsRun},sort_keys=True))
raise SystemExit(0 if result.wasSuccessful()else 1)
'''


def _fixture_pin(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


@contextmanager
def _held_fixture_source(path):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb')as held:
        info=os.fstat(held.fileno())
        if not (stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                and 0<=info.st_size<=2097152 and _fixture_pin(info)==_fixture_pin(path.lstat())):
            raise ValueError('fixture-source-shape')
        raw=held.read(info.st_size+1);held.seek(0)
        if len(raw)!=info.st_size:raise ValueError('fixture-source-length')
        try:yield held,raw
        finally:
            held.seek(0);closing=held.read(info.st_size+1)
            if (closing!=raw or _fixture_pin(info)!=_fixture_pin(os.fstat(held.fileno()))
                    or _fixture_pin(info)!=_fixture_pin(path.lstat())):
                raise ValueError('fixture-source-closing')


def _save_fixture_program(path,raw):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as saved:
        saved.write(raw);saved.flush();os.fsync(saved.fileno())
    return path


def _fixture_argv_bound(argv):
    if sum(len(os.fsencode(value))+1 for value in argv)>60000:
        raise ValueError('fixture-command-bound')
    return argv


@unittest.skipUnless(os.name=='posix','Local private frozen producer control')
class NativeEngineeringEntrypointTest(unittest.TestCase):
    setUp=fixture.NativeExecutionContextTest.setUp
    git=fixture.NativeExecutionContextTest.git
    engineering=fixture.NativeExecutionContextTest.engineering
    def packet(self,artifact,operation='preflight'):
        return {'operation':operation,'request':self.request,'artifactIds':[artifact['artifactId']]}
    def run_frozen(self,packet):
        child=subprocess.run([sys.executable,'-I','-B','-c',_HARNESS,str(self.native),str(self.coordinator),json.dumps(packet)],capture_output=True,text=True,timeout=30)
        self.assertEqual(0,child.returncode,child.stderr)
        return json.loads(child.stdout)
    def test_actual_future_frozen_producer_local_main_enrolls_and_observes_original_after_ref_advance(self):
        artifact,_=self.engineering()
        first=self.run_frozen(self.packet(artifact))
        self.assertEqual('ready',first['state']);self.assertFalse(first['finalAcceptance'])
        self.assertEqual(self.sha,first['sourceSha']);self.assertEqual('2.2.9',first['originalPackageVersion'])
        target=first['targetSha'];enrollment=self.coordinator/build._JOURNAL/(self.request['correlationId']+'.engineering.json')
        original=enrollment.read_bytes()
        (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 3\n')
        self.git('add','agent_tools/check_output_retention.py');self.git('commit','-m','later unrelated checkpoint');self.git('push','origin','dev')
        observed=self.run_frozen(self.packet(artifact,'status'))
        self.assertEqual(target,observed['targetSha']);self.assertEqual(original,enrollment.read_bytes())
        with self.assertRaisesRegex(context.ExecutionContextError,'native_target_ref_changed'):
            build._engineering_context(self.coordinator,self.native,self.request,(artifact['artifactId'],),'start')
    def test_real_isolated_script_mode_rejects_extra_packet_fields_before_platform_effects(self):
        child=subprocess.run([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)],input=b'{"operation":"status","driver":"arbitrary"}',capture_output=True,timeout=10)
        self.assertNotEqual(0,child.returncode);self.assertIn(b'Engineering packet fields differ',child.stderr)
    def test_dispatch_rejects_arbitrary_mode_command_or_foreign_source_before_child(self):
        artifact,_=self.engineering()
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        for operation,raw in (('release',inputs),('start',{**inputs,'command':'caller'}),
                              ('status',{**inputs,'engineeringContext':{**inputs['engineeringContext'],'admission':False}})):
            with self.subTest(operation=operation),patch('subprocess.Popen',side_effect=AssertionError('No child/native effect')) as child:
                with self.assertRaises((ValueError,TypeError)):context.dispatch_linux_engineering(self.coordinator,operation,raw)
                child.assert_not_called()

    def test_actual_bounded_parent_invoker_serializes_fixed_packet_to_frozen_producer(self):
        artifact,_=self.engineering()
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        actual_popen=subprocess.Popen;seen=[]
        def inert_local_launch(argv,*args,**kwargs):
            if len(argv)>3 and argv[0]==sys.executable and argv[3]==str(self.native/'agent_tools/linux_package_fixture_build.py'):
                self.assertEqual([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)],argv)
                self.assertEqual(self.native,kwargs['cwd']);seen.append(argv)
                argv=[sys.executable,'-I','-B','-c',_HARNESS,str(self.native),str(self.coordinator),'-']
            return actual_popen(argv,*args,**kwargs)
        with patch.object(subprocess,'Popen',side_effect=inert_local_launch):
            result=context.dispatch_linux_engineering(self.coordinator,'preflight',inputs)
        self.assertEqual(1,len(seen));self.assertTrue(result['ok']);self.assertFalse(result['nativeActionAllowed'])
        self.assertFalse(result['finalAcceptance']);self.assertEqual(self.sha,result['sourceSha'])
        self.assertNotIn('sourceRoot',result);self.assertNotIn('authority',result)
        capsules=list((self.coordinator/'.rag_index').glob('ssh-tmux-pipe-*'))
        # The existing capture helper retains both streams and its EOF receipt.
        receipts=list((self.coordinator/'.rag_index').rglob('receipt.json'))
        self.assertTrue(receipts)
    def test_unknown_parent_start_capture_is_consumed_before_child_launch_and_never_replayed(self):
        from agent_tools import ssh_tmux_mcp_adapter as adapter
        artifact,_=self.engineering()
        build._engineering_context(self.coordinator,self.native,self.request,(artifact['artifactId'],),'preflight')
        inputs={**self.request,'engineeringContext':{'sourceRoot':str(self.native),'artifactIds':[artifact['artifactId']]}}
        with patch.object(adapter,'_capture',side_effect=TimeoutError('Original local response unavailable')) as capture:
            with self.assertRaises(TimeoutError):context.dispatch_linux_engineering(self.coordinator,'start',inputs)
            second=context.dispatch_linux_engineering(self.coordinator,'start',inputs)
        self.assertEqual(1,capture.call_count);self.assertEqual('unknown',second['state'])
        self.assertEqual('already-journaled',second['reason']);self.assertFalse(second['replayAllowed'])
        self.assertFalse(second['finalAcceptance'])

    def test_actual_child_uncertain_start_dispatch_is_never_replayed_by_direct_cli(self):
        artifact,_=self.engineering()
        self.run_frozen(self.packet(artifact))
        first=self.run_frozen(self.packet(artifact,'start'))
        self.assertEqual('unknown',first['state']);self.assertEqual('submission-response-uncertain',first['reason'])
        second=self.run_frozen(self.packet(artifact,'start'))
        self.assertEqual('already-journaled',second['reason']);self.assertFalse(second['replayAllowed'])
        burn=self.coordinator/build._JOURNAL/(self.request['correlationId']+'.engineering-child-start.json')
        self.assertEqual(self.request,json.loads(burn.read_bytes())['request'])
    def test_actual_script_rejects_stale_matching_bytecode_before_any_repository_import(self):
        import importlib._bootstrap_external
        import marshal
        helper=self.native/'agent_tools/native_execution_context.py';marker=self.base/'cached-helper-executed'
        parent_prefix=sys.pycache_prefix
        programme=_save_fixture_program(self.base/'isolated-cache-path.py',_CACHE_PATH_PROGRAM.encode('utf-8'))
        with _held_fixture_source(helper)as(held,original):
            with _held_fixture_source(programme)as(programme_held,programme_raw):
                argv=_fixture_argv_bound([sys.executable,'-I','-B',str(programme),str(helper),str(held.fileno()),
                      str(programme_held.fileno()),hashlib.sha256(programme_raw).hexdigest(),hashlib.sha256(original).hexdigest()])
                observed=subprocess.run(argv,pass_fds=(held.fileno(),programme_held.fileno()),capture_output=True,timeout=10)
                self.assertEqual(0,observed.returncode,observed.stderr)
                location=json.loads(observed.stdout)
            self.assertTrue(programme_held.closed)
            self.assertEqual(str(helper),location['sourcePath'])
            self.assertEqual(hashlib.sha256(original).hexdigest(),location['sourceSha256'])
            self.assertIsNone(location['pycachePrefix'])
            cache=Path(location['cachePath'])
            # Poison the actual isolated child's normal PRE-guard cache. The
            # fixed producer still redirects its own cache reads to /dev/null.
            self.assertEqual(helper.parent/'__pycache__',cache.parent)
            self.assertEqual(helper.stem+'.'+sys.implementation.cache_tag+'.pyc',cache.name)
            cache.parent.mkdir(parents=True,exist_ok=True)
            stale=compile(original.decode('utf-8')+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("stale cache executed")\n',str(helper),'exec')
            info=os.fstat(held.fileno())
            cached=importlib._bootstrap_external._code_to_timestamp_pyc(stale,int(info.st_mtime),info.st_size)
            importlib._bootstrap_external._validate_timestamp_pyc(cached,int(info.st_mtime),info.st_size,str(helper),{})
            self.assertEqual(stale,marshal.loads(cached[16:]))
            _save_fixture_program(cache,cached)
            child=subprocess.run(_fixture_argv_bound([sys.executable,'-I','-B',str(self.native/'agent_tools/linux_package_fixture_build.py'),'--engineering-local',str(self.coordinator)]),input=b'{"operation":"status","driver":"caller"}',capture_output=True,timeout=10)
            self.assertNotEqual(0,child.returncode);self.assertIn(b'Engineering packet fields differ',child.stderr)
            self.assertEqual(original,helper.read_bytes());self.assertFalse(marker.exists())
        self.assertTrue(held.closed)
        self.assertEqual(parent_prefix,sys.pycache_prefix)


@unittest.skipUnless(os.name=='posix','Owned local source/FD and isolated Python cache control')
class NativeEngineeringCacheFixtureTests(unittest.TestCase):
    setUp=fixture.NativeExecutionContextTest.setUp
    git=fixture.NativeExecutionContextTest.git

    def test_authentic_old_fresh_prefix_red_current_same_caller_green(self):
        parent_prefix=sys.pycache_prefix
        folder=Path(__file__).parent/'fixtures/native_engineering_bytecode_cache'
        provenance=json.loads((folder/'provenance.json').read_bytes())
        before=(folder/'entrypoint.before.source').read_bytes()
        self.assertEqual('d0cb496543e5930ccd1addb9577a09479d1f7f9922e6a55469666ac60dc19a52',hashlib.sha256(before).hexdigest())
        self.assertEqual('d0cb496543e5930ccd1addb9577a09479d1f7f9922e6a55469666ac60dc19a52',provenance['sourceSha256'])
        programme=_save_fixture_program(self.base/'fresh-prefix-caller.py',_CACHE_TEST_PROGRAM.encode('utf-8'))
        with _held_fixture_source(Path(__file__))as(current_held,current):
            for label,source in (('before',before),('current',current)):
                with self.subTest(variant=label):
                    # Existing fixture setUp already captures the complete real
                    # producer dependency graph. Copy it physically, retaining
                    # package paths; no __file__ or module-name substitution.
                    layout=self.base/('caller-'+label)
                    shutil.copytree(self.coordinator,layout,ignore=shutil.ignore_patterns('.git','.rag_index'))
                    tests=layout/'agent_tools/tests';tests.mkdir(parents=True,exist_ok=True)
                    for name in ('__init__.py','test_native_execution_context.py'):
                        path=Path(__file__).with_name(name)
                        if path.is_file():
                            with _held_fixture_source(path)as(original_held,raw):
                                _save_fixture_program(tests/name,raw)
                            self.assertTrue(original_held.closed)
                    target=_save_fixture_program(tests/'test_native_engineering_entrypoint.py',source)
                    prefix=self.base/('empty-cache-'+label)
                    with _held_fixture_source(target)as(test_held,test_raw),_held_fixture_source(programme)as(programme_held,programme_raw):
                        argv=_fixture_argv_bound([sys.executable,'-I','-B','-X','pycache_prefix='+str(prefix),str(programme),
                              str(layout),str(target),str(test_held.fileno()),str(programme_held.fileno()),
                              hashlib.sha256(programme_raw).hexdigest(),hashlib.sha256(test_raw).hexdigest(),str(prefix)])
                        child=subprocess.run(argv,pass_fds=(test_held.fileno(),programme_held.fileno()),capture_output=True,timeout=30)
                        self.assertEqual(1 if label=='before'else 0,child.returncode,child.stderr)
                        if label=='before':self.assertIn(b'FileNotFoundError',child.stderr)
                        observed=json.loads(child.stdout.splitlines()[-1])
                        self.assertEqual(str(target),observed['actualTestFile'])
                        self.assertEqual(hashlib.sha256(test_raw).hexdigest(),observed['testSha256'])
                        self.assertEqual(str(prefix),observed['pycachePrefix'])
                        self.assertEqual(1,observed['testsRun'])
                    self.assertTrue(test_held.closed);self.assertTrue(programme_held.closed)
        self.assertTrue(current_held.closed)
        self.assertEqual(parent_prefix,sys.pycache_prefix)
