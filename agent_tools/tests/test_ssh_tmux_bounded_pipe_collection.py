"""Inert local processes only: original mux FD limit and durable bounded reads."""
import json
import os
from pathlib import Path
try:import resource
except ImportError:resource=None
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools import ssh_tmux_bounded_pipe_collection as collection
from agent_tools import ssh_tmux_session as session
from agent_tools.tests import test_ssh_tmux_session_ssh as original_tests

PIN={'generation':[1,2,33152,getattr(os,'getuid',lambda:0)(),getattr(os,'getgid',lambda:0)(),10,1,1,1],'sha256':'a'*64}
AUTH={'sourceSha':'a'*40,'intentPin':PIN,'anchorPin':PIN,'terminalPin':PIN,'action':'collect','collectorSourcePin':PIN,'argvSha256':'b'*64}
WRITER="import os,sys;sys.stdin.buffer.read();os.write(1,b'x'*8192)"


def process(code,limit=False):
    def limited():resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096))
    return subprocess.Popen([sys.executable,'-I','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,preexec_fn=limited if limit else None)


@unittest.skipUnless(os.name=='posix' and resource is not None,'POSIX pipe/private-fd coordinator')
class BoundedPipeCollectionTest(unittest.TestCase):
    def test_current_catalogue_exact_source_bytes_and_no_historical_adoption(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();tools=root/'agent_tools';tools.mkdir()
            source=Path(__file__).resolve().parents[2]/'agent_tools'
            for name in collection.CURRENT_SOURCES:
                shutil.copyfile(source/name,tools/name)
            pins=collection._current_sources(root)
            self.assertEqual(len(pins),5)
            with self.assertRaisesRegex(collection.CollectionError,'frozen_source_changed'):
                collection._sources(root)
            # Each successor is exact bytes, not a source label or caller hash.
            for name in collection.CURRENT_SOURCES:
                path=tools/name;raw=path.read_bytes();path.write_bytes(raw+b'\n')
                with self.assertRaisesRegex(collection.CollectionError,'current_source_changed'):
                    collection._current_sources(root)
                path.write_bytes(raw)
            self.assertEqual(len(collection._current_sources(root)),5)

    def test_historical_catalogue_retains_exact_original_bytes_and_refuses_mutation(self):
        from agent_tools.tests.fixtures.tmux_historical_source import family
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();tools=root/'agent_tools';tools.mkdir()
            for name in family.PINS:
                (tools/(name+'.py')).write_bytes(family.source(name)[1])
            pins=collection._sources(root)
            self.assertEqual(len(pins),5)
            for name in family.PINS:
                path=tools/(name+'.py');raw=path.read_bytes();path.write_bytes(raw+b'\n')
                with self.assertRaisesRegex(collection.CollectionError,'frozen_source_changed'):
                    collection._sources(root)
                path.write_bytes(raw)
            # This checks source custody only; it does not admit an old native job.
            self.assertEqual(collection.FROZEN['ssh_tmux_session_ssh.py'],family.PINS['ssh_tmux_session_ssh'])

    def receipt(self,path):return json.loads((path/'receipt.json').read_bytes())

    def test_low_fsize_regular_fd_truncates_but_same_limit_pipe_keeps_full_query(self):
        with tempfile.TemporaryDirectory() as root:
            regular=Path(root)/'regular'
            def limited():resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096))
            with regular.open('wb') as out:subprocess.run([sys.executable,'-I','-c',WRITER],stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,preexec_fn=limited,check=False)
            self.assertEqual(4096,regular.stat().st_size)
            result,capsule=collection._capture(Path(root).resolve(),authority=AUTH,launch=lambda:process(WRITER,True),payload=b'{}',guard=lambda:None)
            self.assertEqual('captured',result['state']);self.assertEqual(8192,(capsule/'stdout').stat().st_size)
            self.assertFalse(self.receipt(capsule)['capped']);self.assertFalse(self.receipt(capsule)['replayAllowed'])

    def test_partial_writes_are_completed_and_actual_pin_matches_whole_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve()/'capture';real=os.write
            def short(fd,data):return real(fd,memoryview(data)[:2])
            with mock.patch.object(os,'write',side_effect=short):pin=collection._write_once(path,b'whole-private-body')
            self.assertEqual(b'whole-private-body',path.read_bytes());self.assertEqual(pin,collection._read(path)[1])

    def test_parent_exchange_after_open_rejects_before_private_body_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp).resolve();parent=base/'owned';parent.mkdir(mode=0o700);foreign=base/'foreign';foreign.mkdir(mode=0o700);real=os.open
            def exchange(path,flags,*args,**kwargs):
                fd=real(path,flags,*args,**kwargs)
                if path=='capture':parent.rename(base/'moved');parent.symlink_to(foreign,target_is_directory=True)
                return fd
            with mock.patch.object(os,'open',side_effect=exchange),self.assertRaises(ValueError):collection._write_once(parent/'capture',b'private')
            self.assertFalse((foreign/'capture').exists());self.assertEqual(b'',(base/'moved'/'capture').read_bytes())

    def test_leaf_exchange_and_directory_fsync_failures_never_report_valid_capture(self):
        for attack in ('leaf','directory-fsync'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as tmp:
                parent=Path(tmp).resolve();path=parent/'capture';real=os.fsync;done=[]
                def drift(fd):
                    if attack=='leaf' and not done:
                        other=parent/'other';other.write_bytes(b'private');other.chmod(0o600);other.replace(path);done.append(True)
                    if attack=='directory-fsync' and collection.stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert fsync failure')
                    return real(fd)
                with mock.patch.object(os,'fsync',side_effect=drift),self.assertRaises((ValueError,OSError)):collection._write_once(path,b'private')

    def test_guard_drift_prevents_launch_and_is_finite(self):
        with tempfile.TemporaryDirectory() as root,mock.patch.object(subprocess,'Popen') as launch:
            with self.assertRaisesRegex(collection.CollectionError,'^authority_changed$'):
                collection._capture(Path(root).resolve(),authority=AUTH,launch=launch,payload=b'{}',guard=lambda:(_ for _ in ()).throw(RuntimeError('private secret')))
            launch.assert_not_called()

    def test_overflow_timeout_and_launch_failure_retain_finite_final_receipts(self):
        cases=[('overflow',"import os,sys;sys.stdin.buffer.read();os.write(1,b'x'*"+str(collection.MAX_STDOUT+4096)+")",1),('timeout',"import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(10)",.05),('launch',None,1)]
        for label,code,timeout in cases:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as root:
                def launch():
                    if code is None:raise OSError('private exception marker')
                    return process(code)
                result,capsule=collection._capture(Path(root).resolve(),authority=AUTH,launch=launch,payload=b'{}',guard=lambda:None,timeout_seconds=timeout)
                receipt=self.receipt(capsule)
                self.assertEqual('unknown',result['state']);self.assertFalse(result['replayAllowed']);self.assertNotIn('private exception marker',json.dumps(receipt))
                self.assertEqual(label=='overflow',receipt['capped']);self.assertEqual(label=='timeout',receipt['timedOut'])
                self.assertLessEqual((capsule/'stdout').stat().st_size,collection.MAX_STDOUT+1)
                self.assertEqual(collection._read(capsule/'stdout',collection.MAX_STDOUT+1)[1],receipt['stdoutPin'])

    def test_stdin_nonreader_times_out_without_blocking_and_post_guard_drift_retained(self):
        with tempfile.TemporaryDirectory() as root:
            result,capsule=collection._capture(Path(root).resolve(),authority=AUTH,launch=lambda:process('import time;time.sleep(10)'),payload=b'x'*16384,guard=lambda:None,timeout_seconds=.05)
            self.assertEqual('unknown',result['state']);self.assertTrue(self.receipt(capsule)['timedOut']);self.assertLessEqual(self.receipt(capsule)['stdinBytesWritten'],16384)
        with tempfile.TemporaryDirectory() as root:
            count=0
            def guard():
                nonlocal count
                count+=1
                if count==3:raise ValueError('private drift marker')
            result,capsule=collection._capture(Path(root).resolve(),authority=AUTH,launch=lambda:process(WRITER),payload=b'{}',guard=guard)
            self.assertEqual('unknown',result['state']);self.assertEqual('authority_changed',self.receipt(capsule)['failure']);self.assertEqual(8192,(capsule/'stdout').stat().st_size)

    def test_collect_only_and_malformed_authority_cannot_launch(self):
        driver=object.__new__(collection._PipeDriver)
        for program,payload in [(collection.old._AVAILABILITY,{}),(collection.recovery.STAGE_V2,{}),(collection.old._ACTION,{'action':'release'}),(collection.old._ACTION,{'action':'collect','request':{}})]:
            with self.subTest(payload=payload),mock.patch.object(subprocess,'Popen') as call,self.assertRaises(ValueError):driver._query(program,payload)
            call.assert_not_called()
        for method in ('submit','release','availability','preflight'):
            with self.subTest(method=method),self.assertRaises(ValueError):getattr(driver,method)(*(() if method=='availability' else ({},)))
        with tempfile.TemporaryDirectory() as root,mock.patch.object(subprocess,'Popen') as call,self.assertRaises(ValueError):collection.collect_existing(root,'../arbitrary')
        call.assert_not_called()

    def test_two_actual_pipe_chunk_queries_bind_original_four_field_request_and_real_pins(self):
        fixture=original_tests.DriverTests('test_coordinator_injected_driver_retains_authority_before_release');fixture.setUp();fixture.root=fixture.root.resolve()
        try:
            driver=object.__new__(collection._PipeDriver);driver.root=fixture.root
            original={'coordinator':{'records':{'intent':PIN}}};sources={str(Path(collection.__file__).absolute()):PIN}
            config=collection.ssh_transport.load_config(fixture.root);client=subprocess.Popen
            payload={'action':'collect','request':collection.old.purpose(collection.REQUEST),'stagePin':collection.STAGE,'anchorPin':collection.ANCHOR,'terminalPin':collection.TERMINAL,'offset':0,'limit':1048576,'resultPin':None}
            code="import json,sys;v=json.loads(sys.stdin.buffer.read());print(json.dumps({'offset':v['offset'],'data':'x'*8192}))"
            def launch(argv,**kwargs):return client([sys.executable,'-I','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            with mock.patch.object(driver,'_snapshot',return_value=original) as snapshot,mock.patch.object(driver,'_transport',return_value=(config,{'identity':'same'})),mock.patch.object(collection,'_sources',return_value=sources),mock.patch.object(collection,'_history'),mock.patch.object(subprocess,'Popen',side_effect=launch):
                for offset in (0,1048576):
                    value=driver._query(collection.old._ACTION,{**payload,'offset':offset},guard=lambda:None)
                    self.assertEqual(offset,value['offset']);self.assertEqual(8192,len(value['data']))
            self.assertTrue(all(call.args==(collection.REQUEST,) for call in snapshot.call_args_list))
            capsules=list((fixture.root/'.rag_index/linux-package-fixture-build-pipe-collection').iterdir());self.assertEqual(2,len(capsules))
            for capsule in capsules:
                intent=json.loads((capsule/'intent.json').read_bytes());authority=intent['authority']
                self.assertEqual(collection.ANCHOR,authority['anchorPin']);self.assertEqual(collection.TERMINAL,authority['terminalPin']);self.assertEqual(PIN,authority['intentPin']);self.assertFalse(self.receipt(capsule)['replayAllowed'])
        finally:fixture.doCleanups()

    def test_full_inherited_collection_uses_pipe_chunks_verifies_packages_and_never_rebuilds(self):
        fixture=original_tests.DriverTests('test_coordinator_injected_driver_retains_authority_before_release');fixture.setUp();fixture.root=fixture.root.resolve()
        try:
            fixture.req=dict(collection.REQUEST)
            self.assertEqual('submitted',fixture.start()['state']);fixture.archive()
            archive=fixture.root/'test-remote.tar';archive.write_bytes(fixture.remote.archive)
            session.write_once(fixture.job()/'tmux-collection.json',session.canonical({'request':fixture.req,'terminalPin':original_tests.pin(3)}))
            driver=object.__new__(collection._PipeDriver);driver.root=fixture.root
            sources={str(Path(collection.__file__).absolute()):PIN};client=subprocess.Popen
            code="import json,sys,pathlib,hashlib,base64;v=json.loads(sys.stdin.buffer.read());b=pathlib.Path(sys.argv[1]).read_bytes();p=json.loads(sys.argv[2]);p['generation'][5]=len(b);p['sha256']=hashlib.sha256(b).hexdigest();print(json.dumps({'offset':v['offset'],'totalBytes':len(b),'chunkBase64':base64.b64encode(b[v['offset']:v['offset']+v['limit']]).decode(),'resultSha256':p['sha256'],'resultPin':p,'artifactVerification':'required','replayAllowed':False}))"
            def launch(argv,**kwargs):return client([sys.executable,'-I','-c',code,str(archive),json.dumps(original_tests.pin(4))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            with mock.patch.object(collection,'STAGE',original_tests.pin(1)),mock.patch.object(collection,'ANCHOR',original_tests.pin(2)),mock.patch.object(collection,'TERMINAL',original_tests.pin(3)),mock.patch.object(driver,'_snapshot',side_effect=fixture.driver._snapshot),mock.patch.object(collection,'_sources',return_value=sources),mock.patch.object(collection,'_history'),mock.patch.object(subprocess,'Popen',side_effect=launch),mock.patch.object(collection.recovery.build.FixedArchDriver,'collect',return_value={'state':'ready'}) as register:
                result=driver.collect_existing(collection.REQUEST)
            self.assertEqual({'state':'ready'},result);register.assert_called_once()
            self.assertEqual(1,fixture.remote.builds)
            job=fixture.job();self.assertTrue((job/'tmux-output-ready.json').is_file());self.assertEqual(fixture.remote.archive,(job/'result.tar').read_bytes())
            self.assertGreater(len(list((fixture.root/'.rag_index/linux-package-fixture-build-pipe-collection').iterdir())),1)
            self.assertEqual(12,len(list((job/'output/.rag_index/build-timings').iterdir())))
        finally:fixture.doCleanups()

    def test_capture_evidence_source_has_no_resource_import_or_generic_actions(self):
        import ast
        tree=ast.parse(Path(collection.__file__).read_text())
        self.assertFalse(any(isinstance(node,ast.Import) and any(alias.name=='resource' for alias in node.names) for node in tree.body))
        with mock.patch.object(collection.os,'name','nt'),self.assertRaisesRegex(ValueError,'unsupported_coordinator'):collection.collect_existing(Path.cwd(),collection.CORRELATION)
