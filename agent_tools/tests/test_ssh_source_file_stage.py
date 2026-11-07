"""Actual saved-file receiver controls; no VM or product process is launched."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_source_file_stage as subject
from agent_tools import ssh_source_file_stage_direct as direct_subject


@unittest.skipIf(os.name != "posix", "owned POSIX SSH coordinator storage")
class SourceFileStageTests(unittest.TestCase):
    correlation = "ab" * 16

    def setUp(self):
        from agent_tools.tests.route_adapter import bind_cached_routes
        from agent_tools import mcp_server as _route_server
        bind_cached_routes(self,_route_server,
            'ssh_source_file_stage',
            'ssh_source_file_stage_direct',
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    @property
    def stage(self):
        return self.root / ("vpn-control-windows-caller-" + self.correlation)

    def receive(self, payload):
        return subject.receive_source(self.correlation, io.BytesIO(payload), str(self.root))

    def test_whole_saved_large_program_arrives_as_exact_file_without_execution(self):
        source = ("VALUES=" + repr([hashlib.sha256(str(i).encode()).hexdigest()
                                   for i in range(2000)]) + "\nraise RuntimeError('must not execute')\n").encode()
        saved = self.root / "whole program.py"
        saved.write_bytes(source)
        result = self.receive(subject.source_payload(saved.read_bytes()))
        self.assertGreater(len(source), 60000)
        self.assertEqual(source, (self.stage / "caller.py").read_bytes())
        self.assertEqual(hashlib.sha256(source).hexdigest(), result["sha256"])
        self.assertEqual(len(source), result["bytes"])
        self.assertFalse(result["sourceExecuted"])
        self.assertEqual(result, json.loads((self.stage / "receipt.json").read_bytes()))
        self.assertEqual(0o600, (self.stage / "caller.py").stat().st_mode & 0o777)
        self.assertEqual(0o700, self.stage.stat().st_mode & 0o777)

    def test_actual_emitted_receiver_imports_and_argument_quoting(self):
        source = b"raise RuntimeError('inert')\n"
        emitted = subject.receiver_program(self.correlation)
        # The only test seam supplies an isolated filesystem root to the same entry.
        emitted = emitted.replace(",sys.stdin.buffer)", ",sys.stdin.buffer," + repr(str(self.root)) + ")")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", emitted],
                                input=subject.source_payload(source), capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        self.assertEqual(b"", result.stderr)
        self.assertEqual(source, Path(json.loads(result.stdout)["path"]).read_bytes())
        self.assertLess(len(emitted.encode()), 60000)

    def test_emitted_receiver_has_truthful_bounded_terminal_refusal(self):
        emitted = subject.receiver_program(self.correlation)
        emitted = emitted.replace(",sys.stdin.buffer)", ",sys.stdin.buffer," + repr(str(self.root)) + ")")
        payload = subject.source_payload(b"print('PUBLIC')\n")[:-1] + b"X"
        result = subprocess.run([sys.executable, "-I", "-B", "-c", emitted],
                                input=payload, capture_output=True, timeout=5)
        self.assertEqual(64, result.returncode)
        self.assertEqual(b"", result.stderr)
        terminal = json.loads(result.stdout)
        self.assertEqual("refused", terminal["state"])
        self.assertEqual("source_stage_digest", terminal["reason"])
        self.assertFalse(terminal["sourceExecuted"])
        self.assertFalse((self.stage / "receipt.json").exists())

    def test_partial_transfer_is_retained_and_not_replayed(self):
        payload = subject.source_payload(b"print('PUBLIC')\n")
        with self.assertRaisesRegex(ValueError, "source_stage_truncated"):
            self.receive(payload[:-3])
        self.assertTrue((self.stage / "caller.py").is_file())
        self.assertFalse((self.stage / "receipt.json").exists())
        before = (self.stage / "caller.py").read_bytes()
        with self.assertRaises(FileExistsError):
            self.receive(payload)
        self.assertEqual(before, (self.stage / "caller.py").read_bytes())

    def test_digest_or_trailing_bytes_cannot_publish_receipt(self):
        for kind in ("digest", "trailing"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as root:
                Path(root).chmod(0o700)
                payload = subject.source_payload(b"print('PUBLIC')\n")
                payload = payload[:-1] + b"X" if kind == "digest" else payload + b"trailing"
                with self.assertRaisesRegex(ValueError, "source_stage_" + kind):
                    subject.receive_source(self.correlation, io.BytesIO(payload), root)
                self.assertFalse((Path(root) / self.stage.name / "receipt.json").exists())

    def test_existing_symlink_directory_never_changes_destination(self):
        other = self.root / "unrelated"
        other.mkdir()
        sentinel = other / "caller.py"
        sentinel.write_bytes(b"UNRELATED")
        self.stage.symlink_to(other, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.receive(subject.source_payload(b"print('PUBLIC')\n"))
        self.assertEqual(b"UNRELATED", sentinel.read_bytes())

    def test_metadata_refusals_precede_remote_directory_creation(self):
        for payload in (b"x" * 4097, b'{"bytes":1,"bytes":1,"sha256":"' + b"0" * 64 + b'"}\nX',
                        b'{"bytes":true,"sha256":"' + b"0" * 64 + b'"}\nX'):
            with self.assertRaises(ValueError):
                self.receive(payload)
            self.assertFalse(self.stage.exists())

    def test_invalid_source_or_correlation_refuses_locally(self):
        for source in (b"", b"def broken(", "not bytes", b"\xff"):
            with self.assertRaises((ValueError, SyntaxError, UnicodeError)):
                subject.source_payload(source)
        for correlation in (None, "../escape", self.correlation + "x"):
            with self.assertRaises(ValueError):
                subject.receiver_program(correlation)

    def test_saved_driver_cannot_replace_loader_custody_globals(self):
        source = b"fd=-1\npath='not the loaded file'\ninfo=None\nexpected='PUBLIC'\nprint('PUBLIC_SUCCESS')\n"
        path = self.root / "whole driver with spaces.py"
        path.write_bytes(source);path.chmod(0o600)
        result = subprocess.run([sys.executable,"-I","-B","-c",direct_subject.LOADER,
                                 str(path),hashlib.sha256(source).hexdigest(),str(len(source))],
                                capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr.decode())
        self.assertEqual(b"PUBLIC_SUCCESS\n",result.stdout)
        self.assertEqual(b"",result.stderr)

    def test_gateway_whole_module_imports_and_contains_exact_saved_source(self):
        # Use a valid Unicode-containing programme with ordinary sibling names.
        source="LABEL='PUBLIC Ω spaced label'\nfd=-1\n".encode()
        programme=subject.gateway_program(source)
        namespace={'__name__':'inert_complete_gateway'}
        exec(compile(programme,'complete deployed file gateway','exec'),namespace)
        self.assertEqual(source,namespace['PROBE'].encode())
        self.assertTrue(callable(namespace['stage_main']))
        self.assertTrue(callable(namespace['start_fixed']))

    def test_loader_rejects_tampering_symlinks_and_physical_exchange(self):
        source=b"print('PUBLIC')\n"
        original=self.root/'original.py';original.write_bytes(source);original.chmod(0o600)
        link=self.root/'link.py';link.symlink_to(original)
        for path,digest in ((original,'0'*64),(link,hashlib.sha256(source).hexdigest())):
            result=subprocess.run([sys.executable,'-I','-B','-c',direct_subject.LOADER,
                                   str(path),digest,str(len(source))],capture_output=True,timeout=5)
            self.assertNotEqual(0,result.returncode)
            self.assertEqual(b'',result.stdout)
        replacement=self.root/'replacement.py'
        source=("from pathlib import Path\nPath(__file__).unlink()\n"
                "Path(__file__).write_text('PUBLIC_CHANGED')\nprint('PUBLIC_BODY')\n").encode()
        replacement.write_bytes(source);replacement.chmod(0o600)
        result=subprocess.run([sys.executable,'-I','-B','-c',direct_subject.LOADER,str(replacement),
                               hashlib.sha256(source).hexdigest(),str(len(source))],capture_output=True,timeout=5)
        self.assertNotEqual(0,result.returncode)
        self.assertIn(b'saved_driver_changed',result.stderr)

    def test_complete_child_streams_retained_before_error_projection(self):
        child="import sys;sys.stdin.buffer.read();sys.stdout.write('PUBLIC_OUT');sys.stderr.write('PUBLIC_ERR')"
        with self.assertRaisesRegex(ValueError,'source_stage_control_unverified'):
            direct_subject._run(self.root,[sys.executable,'-I','-B','-c',child],b'PUBLIC_INPUT','control')
        self.assertEqual(b'PUBLIC_OUT',(self.root/'control-stdout.private').read_bytes())
        self.assertEqual(b'PUBLIC_ERR',(self.root/'control-stderr.private').read_bytes())
        self.assertTrue(json.loads((self.root/'control-terminal.json').read_bytes())['complete'])

    def test_mcp_exact_schema_rejects_command_or_extra_authority_before_submission(self):
        from agent_tools import mcp_server
        for transfer in ({'command':'PUBLIC'},
                         {'sourceFile':'PUBLIC','sourceSha256':'0'*64,'correlationId':self.correlation,'ready':True}):
            with mock.patch.object(direct_subject,'publish') as publish:
                result=mcp_server._ssh_workflow_impl('windows-caller-file-stage',host='archlinux',transfer=transfer)
            self.assertFalse(result['ok']);publish.assert_not_called()

    def test_mcp_stage_requires_fixed_phase_budget(self):
        from agent_tools import mcp_server
        transfer={'sourceFile':'PUBLIC','sourceSha256':'0'*64,'correlationId':self.correlation}
        for seconds in (1,15,59,61,True):
            with mock.patch.object(direct_subject,'publish') as publish:
                result=mcp_server._ssh_workflow_impl('windows-caller-file-stage',host='archlinux',timeout_seconds=seconds,transfer=transfer)
            self.assertFalse(result['ok']);publish.assert_not_called()

    def test_retained_receipt_requires_closing_and_never_claims_remote_readiness(self):
        directory=self.root/'.rag_index'/'ssh-source-file-stage'/self.correlation
        directory.mkdir(parents=True,mode=0o700)
        for parent in (directory.parent,directory.parent.parent):parent.chmod(0o700)
        source=b"print('PUBLIC')\n";digest=hashlib.sha256(source).hexdigest()
        intent={'host':'archlinux','correlationId':self.correlation,'sourceSha256':digest,'sourceBytes':len(source)}
        result={'state':'staged','correlationId':self.correlation,'bytes':len(source),'sha256':digest,
                'path':'/tmp/vpn-control-windows-caller-'+self.correlation+'/caller.py','sourceExecuted':False}
        for name,value in (('intent.json',intent),('result.json',result)):
            (directory/name).write_text(json.dumps(value));(directory/name).chmod(0o600)
        (directory/'caller.py').write_bytes(source);(directory/'caller.py').chmod(0o600)
        self.assertEqual('unknown',direct_subject.retained_receipt(self.root,self.correlation)['state'])

        (directory/'closing.json').write_text(json.dumps({'sourceClosing':True,'correlationId':self.correlation}))
        (directory/'closing.json').chmod(0o600)
        value=direct_subject.retained_receipt(self.root,self.correlation)
        self.assertEqual('recorded',value['state']);self.assertFalse(value['remoteReadiness'])
        self.assertEqual('staged',value['originalState'])
        (directory/'unknown.json').write_text(json.dumps({'reason':'PUBLIC_UNKNOWN'}))
        (directory/'unknown.json').chmod(0o600)
        self.assertEqual('unknown',direct_subject.retained_receipt(self.root,self.correlation)['state'])

    def test_complete_native_entry_consumes_raw_producer_not_adapter_fields(self):
        fixtures=Path(__file__).parent/'fixtures'/'windows_file_native_envelope'
        value=json.loads((fixtures/'native.json').read_bytes())
        expected={'before':3,'after':0}
        for label,code in expected.items():
            with self.subTest(source=label):
                path=fixtures/('gateway.before.source' if label=='before' else 'gateway.after.source')
                scope={'__name__':'controlled_native_entry','_DECODED_SOURCE_SHA':'0'*64}
                exec(compile(path.read_bytes(),str(path),'exec'),scope)
                class Custody:
                    raw={'stdout':bytearray(json.dumps(value).encode()),'tty':bytearray()}
                    closed=True
                    child=type('Child',(),{'stdin':io.BytesIO()})()
                    def observe(self,_):
                        return {'complete':True,'refusal':None,'returnCode':0}
                # IO is isolated; the complete consumed entry, imports, parser,
                # argument consumers, projector and real writer remain in use.
                scope['bounded_envelope']=lambda _: {'passphrase':'PUBLIC'}
                scope['file_pin']=lambda *_args,**_kwargs: {'unsupportedConfigDirectives':False}
                scope['effective_route']=lambda _: {'keyMetadata':['PUBLIC']}
                scope['start_fixed']=lambda *_: Custody()
                output=io.StringIO()
                with mock.patch.object(sys,'argv',['saved','ab'*16,'PUBLIC_CONFIG','archlinux','0'*64]),contextlib.redirect_stdout(output):
                    actual=scope['stage_main']()
                self.assertEqual(code,actual)
                result=json.loads(output.getvalue())
                self.assertEqual('unknown' if label=='before' else 'observed',result['state'])
                if label=='before':self.assertEqual('source_run_identity',result['reason'])
                else:
                    from agent_tools.windows_vm_baseline_inventory import classify
                    classified=classify(result['run'])
                    self.assertFalse(classified['nativeActionAllowed'])
                    self.assertFalse(classified['inventoryComplete'])



@unittest.skipUnless(os.name == 'posix','authenticated POSIX file publisher')
@unittest.skipUnless(os.name=='posix','POSIX source owner/temporary-root fixture')
class SourceFileInstanceIdentityTests(unittest.TestCase):
    def test_complete_publisher_uses_current_principal_and_physical_temporary_roots(self):
        self.complete_publisher('archlinux')
    def test_a_new_configured_host_alias_needs_only_an_input_change(self):
        self.complete_publisher('rebuilt-lab')
    def complete_publisher(self,host):
        import pwd
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            (root/'.rag_index').mkdir(mode=0o700)
            runtime=root/'.runtime';runtime.mkdir(mode=0o700)
            source=runtime/'complete caller.py';source.write_text("raise RuntimeError('never execute the caller')\n")
            source.chmod(0o600);sha=hashlib.sha256(source.read_bytes()).hexdigest();corr='ce'*16
            user=pwd.getpwuid(os.geteuid()).pw_name
            gateway_root=root/'gateway-current';gateway_root.mkdir(mode=0o700)
            arch_root=root/'arch-current';arch_root.mkdir(mode=0o700)
            class Held:
                def read(self,path,digest,max_bytes=subject.MAX_SOURCE_BYTES):
                    body=Path(path).read_bytes()
                    if len(body)>max_bytes or hashlib.sha256(body).hexdigest()!=digest:raise ValueError('physical_source_changed')
                    return body
            class Guard:
                def __init__(self,_,host='archlinux'):
                    self.held=Held();self.source_pins={};self.authority_sha='0'*64
                    self.config=SimpleNamespace(hosts={
                        host:SimpleNamespace(alias=host,transport='nested',gateway='gateway',remote_config_file=None,remote_host_alias='current-peer',password='PUBLIC',user=user),
                        'gateway':SimpleNamespace(alias='gateway',transport='direct',gateway=None),
                    })
                def __enter__(self):return self
                def __exit__(self,*_):self.close()
                def guard(self):pass
                def close(self):pass
            phases=[]
            def run(directory,argv,payload,label):
                phases.append(label)
                if label=='gateway':
                    # The actual complete receiver creates and rereads physical
                    # files. Only SSH transport is isolated; identity is observed.
                    return subject.receive_source(corr,io.BytesIO(payload),str(gateway_root))
                if label!='arch':raise AssertionError(label)
                stage=subject.receive_source(corr,io.BytesIO(subject.source_payload(source.read_bytes())),str(arch_root))
                return {'state':'observed','correlationId':corr,'stage':stage}
            with mock.patch.object(direct_subject.direct,'Guard',Guard),mock.patch.object(direct_subject.transport,'connection_host',return_value=SimpleNamespace(user=user)),mock.patch.object(direct_subject.direct,'outer_prefix',return_value=(['ssh'],'PUBLIC_ENDPOINT')),mock.patch.object(direct_subject,'_run',side_effect=run):
                result=direct_subject.publish(root,host,str(source),sha,corr)
            self.assertEqual('staged',result['state'])
            self.assertEqual(['gateway','arch'],phases)
            self.assertEqual(os.geteuid(),result['uid']);self.assertEqual(user,result['principal'])
            self.assertEqual(str(arch_root),result['temporaryRoot'])
            self.assertEqual(source.read_bytes(),Path(result['path']).read_bytes())
            recorded=direct_subject.retained_receipt(root,corr,host=host)
            self.assertEqual('recorded',recorded['state']);self.assertFalse(recorded['remoteReadiness'])
            with self.assertRaises(ValueError):direct_subject.retained_receipt(root,corr,host='different-peer')

    def test_receiver_refuses_writable_nonsticky_owned_parent_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o777)
            with self.assertRaisesRegex(ValueError,'source_stage_parent'):
                subject.receive_source('ed'*16,io.BytesIO(subject.source_payload(b"print('PUBLIC')\n")),str(root))
            self.assertEqual([],list(root.iterdir()))


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.name=='posix','inert local pipe/source-staging custody')
class SourceStageCustodyRegressionTests(unittest.TestCase):
    def before(self):
        import types,agent_tools
        fixture=Path(__file__).parent/'fixtures/capture_custody'
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        def load(name):
            path=fixture/(name+'.py.before.source')
            raw=path.read_bytes();self.assertEqual(provenance['sources'][path.name]['sha256'],hashlib.sha256(raw).hexdigest())
            module=types.ModuleType('agent_tools._custody_before_'+name)
            module.__package__='agent_tools';module.__file__=str(path)
            exec(compile(raw,str(path),'exec'),module.__dict__);return module
        android=load('android_qualified_cli_observation')
        with mock.patch.object(agent_tools,'android_qualified_cli_observation',android), \
             mock.patch.dict(sys.modules,{'agent_tools.android_qualified_cli_observation':android}):
            return load('ssh_source_file_stage_direct')

    def cleanup(self,owner):
        child=getattr(owner,'child',None)
        if child is None or getattr(owner,'closed',False):return
        if hasattr(owner,'captureErrors'):owner.finish_naturally();return
        if not child.stdin.closed:child.stdin.close()
        child.wait()
        for name in ('stdout','stderr'):
            stream=getattr(child,name)
            if not stream.closed:stream.read();stream.close()
        if hasattr(owner,'selector'):owner.selector.close()

    def run_case(self,module,fault):
        import select as select_module
        real_init=module.FileCapture.__init__;real_read=os.read
        owners=[];error=None;fired=[]
        def init(owner,*args,**kwargs):owners.append(owner);return real_init(owner,*args,**kwargs)
        with tempfile.TemporaryDirectory(prefix='owned-stage-capture-') as temporary:
            directory=Path(temporary)
            script="import sys,time,json;time.sleep(.05);data=sys.stdin.buffer.read();print(json.dumps({'bytes':len(data)}))"
            payload=b'x'*(1024*1024 if fault in ('writer','observe','writer_start') else 32)
            patches=contextlib.ExitStack()
            try:
                patches.enter_context(mock.patch.object(module.FileCapture,'__init__',init))
                if fault=='setup':patches.enter_context(mock.patch.object(module.os,'set_blocking',side_effect=OSError('inert setup failure')))
                elif fault=='read':
                    def read(fd,size):
                        if owners and getattr(owners[0],'child',None) is not None and fd in (owners[0].child.stdout.fileno(),owners[0].child.stderr.fileno()) and not fired:
                            fired.append(True);raise OSError('inert retained read failure')
                        return real_read(fd,size)
                    patches.enter_context(mock.patch.object(module.os,'read',side_effect=read))
                elif fault=='select':
                    real_selector=module.selectors.DefaultSelector
                    class OneSelectFailure:
                        def __init__(self):self.actual=real_selector()
                        def __getattr__(self,name):return getattr(self.actual,name)
                        def select(self,*args):
                            if not fired:fired.append(True);raise OSError('inert retained select failure')
                            return self.actual.select(*args)
                    patches.enter_context(mock.patch.object(module.selectors,'DefaultSelector',OneSelectFailure))
                elif fault=='writer_start':
                    real_start=module.threading.Thread.start
                    def start(writer):real_start(writer);raise OSError('inert failure after writer accepted')
                    patches.enter_context(mock.patch.object(module.threading.Thread,'start',start))
                elif fault in ('writer','timeout','observe'):

                    original_observe=module.FileCapture.observe
                    def observe(owner,seconds):
                        original_observe(owner,.000001)
                        if fault=='observe':raise OSError('inert observation failure')
                        if fault=='timeout':owner.writer.join();owner.finish_naturally()
                        return owner.snapshot()
                    patches.enter_context(mock.patch.object(module.FileCapture,'observe',observe))
                try:value=module._run(directory,[sys.executable,'-I','-B','-c',script],payload,'custody')
                except (OSError,ValueError) as caught:error=caught;value=None
                data={p.name:p.read_bytes() for p in directory.iterdir()}
                self.assertEqual(1,len(owners));owner=owners[0]
                result={'error':error,'value':value,'closed':getattr(owner,'closed',False),
                        'terminal':owner.child.poll()is not None,'files':data,'owner':owner,'payloadBytes':len(payload)}
                return result
            finally:
                patches.close()
                for owner in owners:self.cleanup(owner)

    def test_direct_constructor_failure_retains_original_terminal_streams(self):
        before=self.run_case(self.before(),'setup')
        with self.assertRaises(AssertionError):self.assertTrue(before['closed'])
        self.assertNotIn('custody-terminal.json',before['files'])
        current=self.run_case(direct_subject,'setup')
        self.assertIsInstance(current['error'],OSError)
        self.assertTrue(current['closed']);self.assertTrue(current['terminal'])
        terminal=json.loads(current['files']['custody-terminal.json'])
        self.assertTrue(terminal['complete']);self.assertTrue(all(terminal['eof'].values()))
        self.assertEqual('setup',terminal['captureErrors'][0]['phase'])
        self.assertEqual(b'',current['files']['custody-stderr.private'])
        self.assertEqual(0,json.loads(current['files']['custody-stdout.private'])['bytes'])

    def test_direct_read_error_latches_unknown_without_losing_streams(self):self.io_case('read')
    def test_direct_select_error_latches_unknown_without_losing_streams(self):self.io_case('select')
    def io_case(self,fault):
        before=self.run_case(self.before(),fault)
        self.assertIsInstance(before['error'],OSError)
        self.assertNotIn('custody-terminal.json',before['files'])
        current=self.run_case(direct_subject,fault)
        self.assertIsInstance(current['error'],ValueError)
        self.assertTrue(current['closed']);self.assertTrue(current['terminal'])
        final=json.loads(current['files']['custody-terminal.json'])
        self.assertTrue(final['complete']);self.assertTrue(all(final['eof'].values()))
        self.assertEqual(fault,final['captureErrors'][0]['phase'])
        self.assertEqual(current['payloadBytes'],json.loads(current['files']['custody-stdout.private'])['bytes'])
        self.assertEqual(b'',current['files']['custody-stderr.private'])

    def test_active_original_writer_keeps_stdin_through_natural_drain(self):
        before=self.run_case(self.before(),'writer')
        before_size=json.loads(before['files']['custody-stdout.private'])['bytes']
        with self.assertRaises(AssertionError):self.assertEqual(before['payloadBytes'],before_size)
        self.assertLess(before_size,before['payloadBytes'])
        current=self.run_case(direct_subject,'writer')
        self.assertIsInstance(current['error'],ValueError,'the initial timeout remains UNKNOWN')
        self.assertTrue(current['closed']);self.assertTrue(current['terminal'])
        self.assertEqual([],current['owner'].writer_errors);self.assertFalse(current['owner'].writer.is_alive())
        self.assertEqual(current['payloadBytes'],json.loads(current['files']['custody-stdout.private'])['bytes'])
        final=json.loads(current['files']['custody-terminal.json']);self.assertTrue(final['timeout']);self.assertTrue(final['complete'])

    def test_direct_complete_after_timeout_cannot_publish_success(self):
        before=self.run_case(self.before(),'timeout')
        with self.assertRaises(AssertionError):self.assertIsInstance(before['error'],ValueError)
        self.assertIsNone(before['error']);self.assertEqual({'bytes':32},before['value'])
        current=self.run_case(direct_subject,'timeout')
        self.assertIsInstance(current['error'],ValueError);self.assertIsNone(current['value'])
        final=json.loads(current['files']['custody-terminal.json']);self.assertTrue(final['complete']);self.assertTrue(final['timeout'])

    def test_direct_observation_failure_preserves_active_writer_and_all_final_bytes(self):self.after_start_fault('observe')
    def test_direct_thread_start_failure_preserves_already_started_original_writer(self):self.after_start_fault('writer_start')
    def after_start_fault(self,fault):
        before=self.run_case(self.before(),fault)
        self.assertIsInstance(before['error'],OSError)
        self.assertNotIn('custody-terminal.json',before['files'])
        current=self.run_case(direct_subject,fault)
        self.assertIsInstance(current['error'],OSError)
        self.assertTrue(current['closed']);self.assertTrue(current['terminal'])
        self.assertEqual([],current['owner'].writer_errors);self.assertFalse(current['owner'].writer.is_alive())
        final=json.loads(current['files']['custody-terminal.json'])
        self.assertTrue(final['complete']);self.assertTrue(all(final['eof'].values()))
        self.assertEqual(current['payloadBytes'],json.loads(current['files']['custody-stdout.private'])['bytes'])

    def publish_setup_fault(self,module):
        from types import SimpleNamespace
        from agent_tools.native_review_source_closure import _Held
        real_popen=subprocess.Popen;children=[];closing=[];held=_Held();held_closed=[False]
        def popen(argv,**kwargs):
            child=real_popen([sys.executable,'-I','-B','-c',
                "import sys,time;time.sleep(.05);sys.stdin.buffer.read();sys.stdout.write('ORIGINAL_OUT');sys.stderr.write('ORIGINAL_ERR')"],**kwargs)
            children.append(child);return child
        with tempfile.TemporaryDirectory(prefix='owned-publish-custody-') as temporary:
            root=Path(temporary).resolve();root.chmod(0o700);(root/'.rag_index').mkdir(mode=0o700)
            runtime=root/'.runtime';runtime.mkdir(mode=0o700);source=runtime/'caller.py'
            source.write_bytes(b"raise RuntimeError('staged only, never execute')\n");source.chmod(0o600)
            class Guard:
                def __init__(self,_,host='archlinux'):
                    self.held=held;self.source_pins={};self.authority_sha='0'*64
                    self.config=SimpleNamespace(hosts={'archlinux':SimpleNamespace(alias='archlinux',transport='nested',gateway='gateway',remote_config_file=None,remote_host_alias='peer',password='PUBLIC',user='fixture'),'gateway':SimpleNamespace(alias='gateway',transport='direct',gateway=None)})
                def __enter__(self):return self
                def __exit__(self,*_):self.close()
                def guard(self):held.finish();held.final_identity_pass()
                def close(self):
                    if held_closed[0]:return
                    held.finish();held.final_identity_pass()
                    child=children[0]
                    closing.append({'code':child.poll(),'stdoutClosed':child.stdout.closed,'stderrClosed':child.stderr.closed,
                                    'heldFiles':len(held.files),'heldDescriptorsOpen':all(os.fstat(fd) for fd in held.fds)})
                    held.close();held_closed[0]=True
            try:
                with mock.patch.object(module.direct,'Guard',Guard), \
                     mock.patch.object(module.transport,'connection_host',return_value=SimpleNamespace(user='fixture')), \
                     mock.patch.object(module.direct,'outer_prefix',return_value=(['inert-local-only'],'PUBLIC_ENDPOINT')), \
                     mock.patch.object(module.subprocess,'Popen',side_effect=popen), \
                     mock.patch.object(module.os,'set_blocking',side_effect=OSError('inert publisher attachment')):
                    result=module.publish(root,'archlinux',str(source),hashlib.sha256(source.read_bytes()).hexdigest(),'dc'*16)
                self.assertEqual(1,len(children));self.assertEqual('unknown',result['state'])
                terminal=root/'.rag_index/ssh-source-file-stage'/('dc'*16)/'gateway-terminal.json'
                return {'closing':closing,'terminal':json.loads(terminal.read_bytes()) if terminal.exists() else None}
            finally:
                if not held_closed[0]:held.close()
                for child in children:
                    if not child.stdin.closed:child.stdin.close()
                    child.wait()
                    for stream in (child.stdout,child.stderr):
                        if not stream.closed:stream.read();stream.close()

    def test_complete_publisher_keeps_real_source_handles_until_original_setup_failure_drains(self):
        before=self.publish_setup_fault(self.before())
        self.assertIsNone(before['closing'][0]['code']);self.assertFalse(before['closing'][0]['stdoutClosed'])
        self.assertIsNone(before['terminal'])
        current=self.publish_setup_fault(direct_subject)
        self.assertEqual(0,current['closing'][0]['code']);self.assertTrue(current['closing'][0]['stdoutClosed']);self.assertTrue(current['closing'][0]['stderrClosed'])
        self.assertGreater(current['closing'][0]['heldFiles'],0);self.assertTrue(current['closing'][0]['heldDescriptorsOpen'])
        self.assertTrue(current['terminal']['complete']);self.assertTrue(all(current['terminal']['eof'].values()))


@unittest.skipUnless(os.name == 'posix', 'local retained pipe and PTY custody')
class GatewayCustodyFailureTests(unittest.TestCase):
    """Run the complete current emitted gateway with finite local IO peers."""
    def run_gateway(self, failure=None, delayed=False, legacy=None, producer=None):
        import errno
        import pty
        import select
        import selectors
        import threading
        import time
        from types import SimpleNamespace
        programme=(subject if producer is None else producer).gateway_program(b"raise RuntimeError('never execute staged source')\n")
        scope={'__name__':'inert_whole_emitted_gateway','_DECODED_SOURCE_SHA':'0'*64}
        exec(compile(programme,'whole current emitted source gateway','exec'),scope)
        corr='bd'*16;owners=[];children=[];ptys=[];threads=[];guard_events=[]
        base=scope['Custody']
        class Tracked(base):
            def __new__(cls,*args,**kwargs):
                owner=object.__new__(cls);owners.append(owner);return owner
        scope['Custody']=Tracked
        scope['bounded_envelope']=lambda _: {'passphrase':'PUBLIC_INERT_SECRET'}
        def file_pin(*_args,**_kwargs):
            guard_events.append({'childCode':children[-1].poll() if children else None,'ownerClosed':getattr(owners[-1],'closed',False) if owners else False})
            return {'unsupportedConfigDirectives':False}
        scope['file_pin']=file_pin
        scope['effective_route']=lambda _: {'keyMetadata':['/PUBLIC_INERT_KEY'],'user':'PUBLIC_USER'}
        peer="""import hashlib,json,os,sys,time
header=json.loads(sys.stdin.buffer.readline());body=sys.stdin.buffer.read()
time.sleep(DELAY)
value={'state':'staged','correlationId':'CORRELATION','uid':os.geteuid(),'principal':'PUBLIC_USER','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'sourceExecuted':False}
sys.stdout.write(json.dumps(value));sys.stdout.flush();sys.stderr.write('PUBLIC_TTY');sys.stderr.flush()
""".replace('DELAY',repr(.08 if delayed else 0)).replace('CORRELATION',corr)
        # A failed pre-writer setup receives EOF and exits without awaiting input.
        if failure in ('setup','keys','register'):peer="import sys;sys.stdin.buffer.read();sys.stdout.write('PUBLIC_SETUP_OUT');sys.stderr.write('PUBLIC_SETUP_TTY')"
        real_popen=subprocess.Popen;real_openpty=pty.openpty;real_set_blocking=os.set_blocking
        real_read=os.read;real_fsencode=os.fsencode;real_select=select.select;real_selector=selectors.DefaultSelector;real_thread=threading.Thread
        fired=[];writer_release=threading.Event()
        def popen(_argv,**kwargs):
            child=real_popen([sys.executable,'-I','-B','-c',peer],**kwargs);children.append(child);return child
        def openpty():
            pair=real_openpty();ptys.extend(pair);return pair
        def set_blocking(fd,value):
            if failure=='setup' and not fired:fired.append('setup');raise OSError(errno.EIO,'inert attachment fault')
            return real_set_blocking(fd,value)
        def fsencode(value):
            if failure=='keys' and children and value=='/PUBLIC_INERT_KEY' and not fired:
                fired.append('keys');raise UnicodeError('inert constructor attachment fault')
            return real_fsencode(value)
        def read(fd,count):
            if failure=='read' and children and fd==children[0].stdout.fileno() and not fired:
                fired.append('read');raise OSError(errno.EBADF,'inert transient read fault')
            return real_read(fd,count)
        def selection(*args):
            if failure=='select' and not fired:fired.append('select');raise OSError(errno.EIO,'inert selector fault')
            return real_select(*args)
        class Selector:
            def __init__(self):self.delegate=real_selector()
            def register(self,*args):
                if failure=='register' and children and args[0]==children[0].stdout.fileno() and not fired:
                    fired.append('register');raise OSError(errno.EIO,'inert partial attachment fault')
                return self.delegate.register(*args)
            def unregister(self,*args):return self.delegate.unregister(*args)
            def close(self):return self.delegate.close()
            def select(self,*args):
                if failure=='select' and not fired:fired.append('select');raise OSError(errno.EIO,'inert selector fault')
                return self.delegate.select(*args)
        def thread_factory(*,target,daemon):
            def run():
                target()
                # Keep this injected writer live until its actual owner joins it.
                if failure=='writer_start':writer_release.wait()
            thread=real_thread(target=run,daemon=daemon);threads.append(thread)
            if failure=='writer_start':
                real_start=thread.start;real_join=thread.join
                def start():real_start();raise RuntimeError('inert error after writer start')
                def join(timeout=None):
                    writer_release.set()
                    return real_join(timeout)
                thread.start=start
                thread.join=join
            return thread
        real_observe=base.observe
        def observe(owner,seconds):
            # Both implementations first hit a real short observation deadline.
            # Their original child and IO then finish, but the timeout stays set.
            if failure=='timeout' and seconds==60:
                first=real_observe(owner,.001)
                self.assertTrue(first['timeout']);self.assertFalse(first['complete'])
                owner.finish_naturally()
            return real_observe(owner,seconds)
        scope['subprocess']=SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE)
        real_start=scope['start_fixed']
        if legacy=='unreserved':
            scope['start_fixed']=lambda argv,secret,keys,**_kwargs: real_start(argv,secret,keys)
        elif legacy=='constructor':
            def normal_constructor(argv,secret,keys,**_kwargs):
                master,slave=openpty()
                child=popen(argv,stdin=subprocess.PIPE,stderr=slave,stdout=subprocess.PIPE)
                return Tracked(child,master,slave,child.stdout,secret,keys)
            scope['start_fixed']=normal_constructor
        output=io.StringIO();raised=None;returned_alive=None
        try:
            with mock.patch.object(os,'fsencode',side_effect=fsencode),mock.patch.object(pty,'openpty',side_effect=openpty),mock.patch.object(os,'set_blocking',side_effect=set_blocking),mock.patch.object(os,'read',side_effect=read),mock.patch.object(select,'select',side_effect=selection),mock.patch.object(selectors,'DefaultSelector',Selector),mock.patch.object(threading,'Thread',side_effect=thread_factory),mock.patch.object(Tracked,'observe',observe),mock.patch.object(sys,'argv',['saved',corr,'PUBLIC_CONFIG','archlinux','0'*64]),contextlib.redirect_stdout(output):
                try:code=scope['stage_main']()
                except BaseException as error:raised=error;code=None
            if producer is not None and failure=='writer_start':
                # Observe late without releasing the injected writer's gate.
                for thread in threads:real_thread.join(thread,.30)
            returned_alive=any(t.is_alive() for t in threads)
            captures=[json.loads(line) for line in output.getvalue().splitlines()]
            return {'code':code,'raised':raised,'value':captures[-1] if captures else None,
                    'owner':owners[-1] if owners else None,'children':children,
                    'writerAliveAtReturn':returned_alive,'failureInjected':list(fired),
                    'renderedSha256':hashlib.sha256(programme).hexdigest(),'guardEvents':guard_events,
                    'ownerClosedAtReturn':getattr(owners[-1],'closed',False) if owners else False}
        finally:
            # The authentic old implementation can lose a constructor's owner.
            # Clean only these finite local peers, without signals or a retry.
            # Release the old producer's unjoined writer before local cleanup.
            writer_release.set()
            for child in children:
                if child.stdin is not None and not child.stdin.closed:child.stdin.close()
            for fd in ptys[1::2]:
                try:os.close(fd)
                except OSError:pass
            for child in children:
                pending=[]
                if child.stdout is not None and not child.stdout.closed:pending.append(child.stdout.fileno())
                for fd in ptys[::2]:
                    try:os.fstat(fd);pending.append(fd)
                    except OSError:pass
                deadline=time.monotonic()+5
                while pending or child.poll() is None:
                    if time.monotonic()>=deadline:raise AssertionError('finite local peer failed to drain naturally')
                    for fd in real_select(pending,[],[],.01)[0]:
                        try:block=real_read(fd,4096)
                        except OSError as error:
                            if error.errno not in (errno.EIO,errno.EBADF):raise
                            block=b''
                        if not block:pending.remove(fd)
                child.wait(timeout=1)
                if child.stdout is not None and not child.stdout.closed:child.stdout.close()
            for thread in threads:thread.join(5)
            for fd in ptys[::2]:
                try:os.close(fd)
                except OSError:pass

    def test_gateway_nominal_complete_whole_emission_keeps_original_child_and_streams(self):
        result=self.run_gateway()
        self.assertIsNone(result['raised']);self.assertEqual(0,result['code'])
        self.assertEqual('observed',result['value']['state'])
        self.assertTrue(result['owner'].closed)
        self.assertEqual(1,len(result['children']))
        self.assertEqual(b'PUBLIC_TTY',bytes(result['owner'].raw['tty']))
        self.assertTrue(all(result['owner'].eof.values()))
        self.assertEqual(3,len(result['guardEvents']))
        self.assertEqual(0,result['guardEvents'][-1]['childCode'])
        self.assertTrue(result['guardEvents'][-1]['ownerClosed'])

    def test_gateway_post_popen_attachment_error_keeps_reserved_owner(self):
        result=self.run_gateway('setup')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual('unknown',result['value']['state'])
        self.assertIsNotNone(result['value']['capture'])
        self.assertEqual(result['children'][0].pid,result['value']['capture']['pid'])
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(result['owner'].raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(result['owner'].raw['tty']))
        self.assertTrue(result['owner'].closed)
        self.assertTrue(all(result['owner'].eof.values()))

    def test_gateway_read_error_is_unknown_and_not_a_fabricated_eof(self):
        result=self.run_gateway('read')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual('capture_read',result['value']['capture']['refusal'])
        self.assertEqual('staged',json.loads(bytes(result['owner'].raw['stdout']))['state'])
        self.assertTrue(result['owner'].closed)
        self.assertTrue(all(result['owner'].eof.values()))
        self.assertEqual([{'phase':'read','errorClass':'OSError'}],result['value']['capture']['captureErrors'])

    def test_gateway_select_error_stays_unknown_after_original_streams_drain(self):
        result=self.run_gateway('select')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual('capture_select',result['value']['capture']['refusal'])
        self.assertEqual('staged',json.loads(bytes(result['owner'].raw['stdout']))['state'])
        self.assertTrue(result['owner'].closed)
        self.assertEqual([{'phase':'select','errorClass':'OSError'}],result['value']['capture']['captureErrors'])

    def test_gateway_latched_timeout_cannot_be_accepted_after_complete(self):
        result=self.run_gateway('timeout',delayed=True)
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual('unknown',result['value']['state'])
        self.assertTrue(result['value']['capture']['timeout'])
        self.assertTrue(result['value']['capture']['complete'])
        self.assertTrue(result['owner'].closed)

    def test_gateway_writer_started_before_error_is_joined_with_original_child(self):
        result=self.run_gateway('writer_start')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual('unknown',result['value']['state'])
        self.assertFalse(result['writerAliveAtReturn'])
        self.assertTrue(result['owner'].closed)
        self.assertEqual(1,len(result['children']))

    def test_gateway_normal_legacy_constructor_drains_post_start_setup_error(self):
        result=self.run_gateway('setup',legacy='constructor')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertTrue(result['ownerClosedAtReturn'])
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(result['owner'].raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(result['owner'].raw['tty']))

    def test_gateway_unreserved_start_alias_drains_post_start_setup_error(self):
        result=self.run_gateway('setup',legacy='unreserved')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertTrue(result['ownerClosedAtReturn'])
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(result['owner'].raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(result['owner'].raw['tty']))

    def test_gateway_late_output_after_exception_is_in_one_final_unknown_frame(self):
        import base64
        result=self.run_gateway('writer_start',delayed=True)
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        value=result['value']
        self.assertEqual('unknown',value['state'])
        self.assertEqual(0,value['_operatorPrivateCapture']['stdout']['bytes'])
        self.assertTrue(value['finalCapture']['complete'])
        self.assertTrue(all(value['finalCapture']['eof'].values()))
        self.assertEqual(bytes(result['owner'].raw['stdout']),base64.b64decode(value['_operatorPrivateFinalCapture']['stdout']['base64']))
        self.assertEqual(b'PUBLIC_TTY',base64.b64decode(value['_operatorPrivateFinalCapture']['tty']['base64']))
        self.assertFalse(value['replayAllowed'])
        self.assertFalse(result['writerAliveAtReturn'])

    def test_gateway_normal_constructor_key_attachment_error_drains_same_child(self):
        result=self.run_gateway('keys',legacy='constructor')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertEqual(['keys'],result['failureInjected'])
        self.assertTrue(result['ownerClosedAtReturn'])
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(result['owner'].raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(result['owner'].raw['tty']))

    def test_gateway_partial_selector_registration_keeps_both_original_streams(self):
        result=self.run_gateway('register')
        self.assertIsNone(result['raised']);self.assertEqual(3,result['code'])
        self.assertTrue(result['ownerClosedAtReturn'])
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(result['owner'].raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(result['owner'].raw['tty']))
        self.assertTrue(all(result['owner'].eof.values()))

    def test_gateway_real_high_descriptor_pipe_and_pty_finish_naturally(self):
        import fcntl
        import resource
        import time
        programme=subject.gateway_program(b"raise RuntimeError('never executed')\n")
        scope={'__name__':'inert_whole_high_fd_gateway'}
        exec(compile(programme,'whole actual high-fd gateway','exec'),scope)
        old_limit=resource.getrlimit(resource.RLIMIT_NOFILE)
        if old_limit[1]<1200:self.skipTest('local hard fd limit below high-descriptor control')
        if old_limit[0]<1200:resource.setrlimit(resource.RLIMIT_NOFILE,(1200,old_limit[1]))
        custody=None;first=None;original_stdout=None;original_master=None
        try:
            custody=scope['start_fixed']([sys.executable,'-I','-B','-c',"import sys;sys.stdout.write('PUBLIC_HIGH_OUT');sys.stderr.write('PUBLIC_HIGH_TTY')"],b'PUBLIC',[])
            # Alias the same original pipe/PTY endpoints; no process is replaced.
            high_master=fcntl.fcntl(custody.master,fcntl.F_DUPFD,1100)
            high_stdout=fcntl.fcntl(custody.stdout.fileno(),fcntl.F_DUPFD,1100)
            original_master=custody.master;original_stdout=custody.stdout
            if getattr(custody,'selector',None) is not None:
                custody.selector.unregister(original_master);custody.selector.unregister(original_stdout.fileno())
            os.close(original_master);original_stdout.close()
            custody.master=high_master;custody.stdout=os.fdopen(high_stdout,'rb',buffering=0)
            custody.child.stdout=custody.stdout
            if hasattr(custody,'registered'):custody.registered.clear()
            elif getattr(custody,'selector',None) is not None:
                custody.selector.register(high_master,scope['selectors'].EVENT_READ,'tty')
                custody.selector.register(high_stdout,scope['selectors'].EVENT_READ,'stdout')
            self.assertGreaterEqual(high_master,1100);self.assertGreaterEqual(high_stdout,1100)
            first=custody.observe(.3)
        finally:
            if custody is not None and not custody.closed:
                # The preserved select.select candidate cannot read high fds.
                # Return aliases to low numbers only to drain that finite RED
                # control's same original pipe/PTY after its bounded observer.
                if first is not None and not first['complete'] and not hasattr(custody,'registered'):
                    master=os.dup(custody.master);stdout=os.fdopen(os.dup(custody.stdout.fileno()),'rb',buffering=0)
                    os.close(custody.master);custody.stdout.close();custody.master=master;custody.stdout=stdout;custody.child.stdout=stdout
                custody.finish_naturally()
            resource.setrlimit(resource.RLIMIT_NOFILE,old_limit)
        self.assertTrue(first['complete'])
        self.assertFalse(first['timeout']);self.assertIsNone(first['refusal'])
        self.assertEqual(b'PUBLIC_HIGH_OUT',bytes(custody.raw['stdout']))
        self.assertEqual(b'PUBLIC_HIGH_TTY',bytes(custody.raw['tty']))

    def test_gateway_preserved_complete_before_producer_exposes_causal_failures(self):
        import importlib.util
        fixtures=Path(__file__).parent/'fixtures'/'capture_custody'
        stage=(fixtures/'ssh_source_file_stage.py.before.source').read_bytes()
        gateway=(fixtures/'ssh_source_file_gateway.source.before.source').read_bytes()
        self.assertEqual('0fc515e7e118b846ea154cd979e5571afdfc1ea474beb4197c9e1a8237d2b3c9',hashlib.sha256(stage).hexdigest())
        self.assertEqual('17ea428f8dc8be814f7906dc478dcb67a4119015a2e48d1ba754a8855598f17b',hashlib.sha256(gateway).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);root.chmod(0o700)
            path=root/'ssh_source_file_stage.py';path.write_bytes(stage)
            (root/'ssh_source_file_gateway.source').write_bytes(gateway)
            name='owned_complete_before_gateway_producer'
            spec=importlib.util.spec_from_file_location(name,path)
            producer=importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules,{name:producer}):
                spec.loader.exec_module(producer)
                nominal=self.run_gateway(producer=producer)
                self.assertEqual(0,nominal['code'])
                setup=self.run_gateway('setup',producer=producer)
                self.assertIsNone(setup['value']['capture']);self.assertFalse(setup['ownerClosedAtReturn'])
                read=self.run_gateway('read',producer=producer)
                self.assertEqual(b'',bytes(read['owner'].raw['stdout']))
                selection=self.run_gateway('select',producer=producer)
                self.assertIsNone(selection['value']['capture']['refusal'])
                timeout=self.run_gateway('timeout',delayed=True,producer=producer)
                self.assertEqual(0,timeout['code']);self.assertTrue(timeout['value']['capture']['timeout'])
                writer=self.run_gateway('writer_start',delayed=True,producer=producer)
                self.assertTrue(writer['writerAliveAtReturn']);self.assertNotIn('finalCapture',writer['value'])
                for kind in ('constructor','unreserved'):
                    legacy=self.run_gateway('setup',legacy=kind,producer=producer)
                    self.assertFalse(legacy['ownerClosedAtReturn'])
                keys=self.run_gateway('keys',legacy='constructor',producer=producer)
                self.assertFalse(keys['ownerClosedAtReturn'])
                register=self.run_gateway('register',producer=producer)
                self.assertIsNone(register['value']['capture']);self.assertFalse(register['ownerClosedAtReturn'])

    def reserved_no_child_failure(self,producer):
        from types import SimpleNamespace
        scope={'__name__':'inert_complete_reserved_gateway'}
        raw=producer.gateway_program(b"raise RuntimeError('never executed')\n")
        exec(compile(raw,'whole emitted no-child gateway','exec'),scope)
        owner=scope['Custody']();selector=owner.selector;error=None
        try:
            scope['subprocess']=SimpleNamespace(Popen=mock.Mock(side_effect=AssertionError('no child may start')))
            with mock.patch.object(scope['os'],'fsencode',side_effect=UnicodeError('inert prelaunch key attachment')):
                try:scope['start_fixed']([],b'PUBLIC',['PUBLIC_KEY'],custody=owner)
                except UnicodeError as caught:error=caught
            self.assertIsNone(owner.child);self.assertIsInstance(error,UnicodeError)
            scope['subprocess'].Popen.assert_not_called()
            return owner.selector is None,selector.get_map() is None
        finally:
            selector.close()

    def test_gateway_reserved_no_child_setup_error_closes_only_owned_selector(self):
        import importlib.util
        fixtures=Path(__file__).parent/'fixtures/capture_custody'
        provenance=json.loads((fixtures/'provenance.json').read_bytes())
        with tempfile.TemporaryDirectory(prefix='owned-no-child-before-') as temporary:
            root=Path(temporary)
            for name,leaf in [('ssh_source_file_stage.py','ssh_source_file_stage.reserved-selector.before.source'),('ssh_source_file_gateway.source','ssh_source_file_gateway.reserved-selector.before.source')]:
                raw=(fixtures/leaf).read_bytes()
                self.assertEqual(provenance['sources'][leaf]['sha256'],hashlib.sha256(raw).hexdigest())
                (root/name).write_bytes(raw)
            path=root/'ssh_source_file_stage.py';spec=importlib.util.spec_from_file_location('owned_before_reserved_gateway',path)
            before=importlib.util.module_from_spec(spec);spec.loader.exec_module(before)
            closed,physical_closed=self.reserved_no_child_failure(before)
            with self.assertRaises(AssertionError):self.assertTrue(closed)
            self.assertFalse(closed);self.assertFalse(physical_closed)
        self.assertEqual((True,True),self.reserved_no_child_failure(subject))


@unittest.skipUnless(os.name == 'posix', 'finite local Windows gateway pipe/PTY controls')
class WindowsDeploymentGatewayCustodyTests(unittest.TestCase):
    # The current producer binds a schema-valid response and its credential-bearing
    # reply is metadata-only. Preserved producers predate both, so they keep their
    # original harness call, echoing peer and raw streams.
    DEPLOYMENT='00000000-0000-4000-8000-000000000001';OPERATION='00000000-0000-4000-8000-000000000002'
    RESULT={'deploymentId':DEPLOYMENT,'mode':'secure-continue','state':'secured-observed','operationId':OPERATION,'productReady':False,'setupSecured':True,'replayAllowed':False}
    PROMPT=b"Enter passphrase for key '/PUBLIC_KEY': "
    # Each 5-byte item re-encodes as 20 ('1000000000000000.0, '): stdout inside the
    # 5 MiB file CAP becomes a result of about 20 MiB, with only a short tty stream.
    LIST_ITEMS=1048575
    def windows_gateway(self, failure=None, producer=None):
        import errno
        from types import SimpleNamespace
        current=producer is None
        if current:
            from agent_tools import windows_vm_deploy as producer
        receipt={'uid':os.geteuid(),'principal':'PUBLIC_USER','path':'/PUBLIC/caller.py','sha256':'0'*64,'bytes':1}
        payload=failure not in ('observed_list','late_prompt','spawn')
        options={'input_payload':payload,'file_output':failure in ('large','observed_large','observed_list')}
        if current and payload:options['response']={'deploymentId':self.DEPLOYMENT,'mode':'secure-continue','operationId':self.OPERATION,'checks':('instance_known_check',)}
        raw=producer.gateway_program(receipt,**options)
        scope={'__name__':'inert_whole_windows_gateway','_DECODED_SOURCE_SHA':'0'*64}
        exec(compile(raw,'actual complete Windows VM gateway','exec'),scope)
        owners=[];children=[];guards=[];fired=[]
        base=scope['Custody']
        class Tracked(base):
            def __new__(cls,*args,**kwargs):
                owner=object.__new__(cls);owners.append(owner);return owner
        scope['Custody']=Tracked
        scope['bounded_envelope']=lambda _: {'passphrase':'PUBLIC_INERT_SECRET',**({'payload':{'public':'input'}} if payload else {})}
        def pin(*_args,**_kwargs):
            guards.append({'childCode':children[-1].poll() if children else None,'closed':getattr(owners[-1],'closed',False) if owners else False})
            return {'unsupportedConfigDirectives':False}
        scope['file_pin']=pin
        scope['effective_route']=lambda _: {'keyMetadata':['/PUBLIC_KEY'],'user':'PUBLIC_USER'}
        peer="import json,sys,time;raw=sys.stdin.buffer.read();time.sleep(.06);sys.stdout.write(json.dumps({'publicResult':True,'input':json.loads(raw)}));sys.stderr.write('PUBLIC_WINDOWS_TTY')"
        if current:peer="import json,sys,time;assert json.loads(sys.stdin.buffer.read())=={'public':'input'};time.sleep(.06);sys.stdout.write(%r);sys.stderr.write('PUBLIC_WINDOWS_TTY')"%json.dumps(self.RESULT)
        if failure=='setup':peer="import sys;sys.stdin.buffer.read();sys.stdout.write('PUBLIC_SETUP_OUT');sys.stderr.write('PUBLIC_SETUP_TTY')"
        if failure=='large':
            peer="import os,sys;sys.stdin.buffer.read();a=b'A'*4096;b=b'B'*4096\nfor _ in range(1280):\n for fd,block in ((1,a),(2,b)):\n  view=memoryview(block)\n  while view: view=view[os.write(fd,view):]\n"
        if failure=='observed_large':
            peer="import json,os,sys;payload=json.loads(sys.stdin.buffer.read());value={'publicResult':True,'input':payload,'data':''};value['data']='A'*(5*1024**2-len(json.dumps(value).encode()));out=json.dumps(value).encode();err=b'B'*(5*1024**2)\nfor offset in range(0,len(out),4096):\n for fd,block in ((1,out[offset:offset+4096]),(2,err[offset:offset+4096])):\n  view=memoryview(block)\n  while view: view=view[os.write(fd,view):]\n"
        if failure=='observed_list':
            peer="import os,sys;sys.stdin.buffer.read();view=memoryview(b'['+b'1E15,'*%d+b'1E15]')\nwhile view:view=view[os.write(1,view):]\nsys.stderr.write('PUBLIC_WINDOWS_TTY')"%(self.LIST_ITEMS-1)
        gate=None
        if failure=='late_prompt':
            # The gate is the ordering, not a delay: this peer can neither prompt nor end
            # until the failure handler's drain starts, so the observation always expires
            # first. Exit 0 proves the secret really arrived through the original PTY.
            gate=os.pipe();released=[];self.addCleanup(os.close,gate[0])
            def release():
                if not released:released.append(True);os.close(gate[1])
            self.addCleanup(release)
            peer="import os,sys;os.read(%d,1);os.write(2,%r);sys.exit(0 if os.read(2,64)==b'PUBLIC_INERT_SECRET\\n' else 9)"%(gate[0],self.PROMPT)
        real_popen=subprocess.Popen;real_read=os.read;real_block=os.set_blocking;real_observe=base.observe;real_finish=base.finish_naturally
        def popen(_argv,**kwargs):
            if failure=='spawn':raise OSError(errno.ENOENT,'inert spawn fault')
            if gate:kwargs['pass_fds']=(gate[0],)
            child=real_popen([sys.executable,'-I','-B','-c',peer],**kwargs);children.append(child);return child
        scope['subprocess']=SimpleNamespace(Popen=popen,PIPE=subprocess.PIPE)
        def block(fd,value):
            if failure=='setup' and children and not fired:fired.append('setup');raise OSError(errno.EIO,'inert post-start attachment fault')
            return real_block(fd,value)
        pending=bytearray()
        def read(fd,count):
            if failure in ('read','capture_errors') and children and fd==children[-1].stdout.fileno() and not fired:
                fired.append('read');raise OSError(errno.EBADF,'inert transient read fault')
            if failure not in ('large','observed_large') or not owners or fd!=owners[-1].master:return real_read(fd,count)
            # Only the read size changes: the same PTY bytes in order, then its real EOF.
            # A macOS PTY yields 1 KiB per read and custody rescans all retained tty per
            # read, about 60 s of CPU for this 5 MiB stimulus: past both 15 s and observe(60).
            try:chunk=real_read(fd,count)
            except BlockingIOError:raise
            except OSError:
                if not pending:raise
                chunk=b''
            pending.extend(chunk)
            if chunk and len(pending)<256*1024:raise BlockingIOError(errno.EAGAIN,'inert coalesced PTY read')
            whole=bytes(pending);pending.clear();return whole
        def finish(owner):
            if gate:release()
            if failure=='drain_fault':raise RuntimeError('inert drain fault')
            return real_finish(owner)
        def observe(owner,seconds):
            if failure=='late_prompt' and seconds==60:return real_observe(owner,.001)
            if failure=='large' and seconds==60:
                import time
                end=time.monotonic()+15
                while min(owner.counts.values())<4*1024**2:
                    self.assertLess(time.monotonic(),end)
                    owner._step(.01)
                raise RuntimeError('inert exception after large original prefix')
            if failure=='late' and seconds==60:raise RuntimeError('inert exception before late original output')
            if failure=='drain_fault' and seconds==60:raise RuntimeError('inert exception before the failed drain')
            if failure=='timeout' and seconds==60:
                initial=real_observe(owner,.001)
                self.assertTrue(initial['timeout']);self.assertFalse(initial['complete'])
                owner.finish_naturally()
            result=real_observe(owner,seconds)
            if failure=='capture_errors' and seconds==60:
                self.assertTrue(result['complete']);self.assertTrue(result['captureErrors'])
                # A bounded negative projection: the real OS read error and its
                # complete raw streams remain; each rejection field must work
                # independently even if the older refusal field is omitted.
                result=dict(result);result['refusal']=None
            return result
        output=io.StringIO()
        with mock.patch.object(os,'set_blocking',side_effect=block),mock.patch.object(os,'read',side_effect=read),mock.patch.object(Tracked,'observe',observe),mock.patch.object(Tracked,'finish_naturally',finish),mock.patch.object(sys,'argv',['saved','ae'*16,'PUBLIC_CONFIG','archlinux','0'*64]),contextlib.redirect_stdout(output):
            if failure=='drain_fault':
                # The fault replaced the handler's drain, so the harness reaps the harmless peer.
                with self.assertRaisesRegex(RuntimeError,'inert drain fault'):scope['_gateway_main']()
                code=None;real_finish(owners[-1])
            else:code=scope['_gateway_main']()
        frames=output.getvalue().splitlines();self.assertEqual(1,len(frames))
        if current:self.assertNotIn('PUBLIC_INERT_SECRET',frames[0])
        owner=owners[-1]
        if failure=='spawn':
            self.assertEqual([],children);return code,json.loads(frames[0]),owner,guards
        self.assertTrue(owner.closed)
        self.assertTrue(all(owner.eof.values()))
        self.assertEqual(1,len(children));self.assertIsNotNone(children[0].poll())
        return code,json.loads(frames[0]),owner,guards

    def assert_closed_unknown(self,code,value,owner,error_class,reason,capture,credential=False):
        # The whole frame: closed facts from the failure, then final custody facts from
        # after the natural drain. No field exists that could carry a stream or an echo.
        final=value['finalCapture']
        self.assertEqual(3,code)
        self.assertEqual({'state':'unknown','correlationId':'ae'*16,'errorClass':error_class,'reason':reason,'capture':capture,'finalCapture':final,
                          '_operatorPrivateCapture':{'retention':'metadata-only','counts':final['counts'],'eof':final['eof'],'credentialSent':credential}},value)
        self.assertEqual({'pid','returnCode','complete','timeout','refusal','credentialSent','counts','eof','captureErrors'},set(final))
        self.assertEqual(owner.child.pid,final['pid']);self.assertEqual(0,final['returnCode'])
        self.assertTrue(final['complete']);self.assertEqual({'stdout':True,'tty':True},final['eof'])
        self.assertEqual(credential,final['credentialSent'])
        self.assertEqual({name:len(owner.raw[name]) for name in ('stdout','tty')},final['counts'])
        return final

    @contextlib.contextmanager
    def preserved_producer(self,relative,digest):
        import importlib.util
        before=(Path(__file__).parent/'fixtures'/relative).read_bytes()
        self.assertEqual(digest,hashlib.sha256(before).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'windows_vm_deploy.py';path.write_bytes(before)
            name='agent_tools._capture_custody_red_windows_vm_deploy'
            spec=importlib.util.spec_from_file_location(name,path);producer=importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules,{name:producer}):
                spec.loader.exec_module(producer);yield producer

    def test_windows_gateway_failed_drain_still_names_the_closed_reason(self):
        # The reply follows the drain, so a drain that raises must not lose the frame.
        code,value,_,_=self.windows_gateway('drain_fault')
        self.assertIsNone(code)
        self.assertEqual(('unknown','RuntimeError','unclassified'),(value['state'],value['errorClass'],value['reason']))
        self.assertIsNone(value['finalCapture'])
        self.assertEqual({'state','correlationId','errorClass','reason','capture','finalCapture','_operatorPrivateCapture'},set(value))
        self.assertEqual('metadata-only',value['_operatorPrivateCapture']['retention'])
        # A handler that prints only after its drain loses the whole frame.
        with self.preserved_producer('capture_custody/windows_vm_deploy.duplicate-output.before.source','f38835e5deb0d58be37fc19c7b8985711f947cf9617f9da05fb32d5e7217e243') as producer:
            with self.assertRaisesRegex(AssertionError,'1 != 0'):self.windows_gateway('drain_fault',producer)

    def test_windows_gateway_spawn_failure_is_one_closed_unknown_with_no_child(self):
        code,value,owner,_=self.windows_gateway('spawn')
        self.assertEqual(3,code);self.assertIsNone(owner.child)
        self.assertEqual(('unknown','FileNotFoundError','unclassified',None),(value['state'],value['errorClass'],value['reason'],value['capture']))
        self.assertIsNone(value['finalCapture']['pid']);self.assertFalse(value['finalCapture']['complete'])
        self.assertEqual({'retention':'metadata-only','counts':{'stdout':0,'tty':0},'eof':{'stdout':False,'tty':False},'credentialSent':False},value['_operatorPrivateCapture'])

    def test_windows_gateway_large_echoing_output_is_refused_without_any_stream_in_the_frame(self):
        # The preserved observed-framing stimulus, on the current producer: it echoes the
        # protected payload, so the echo check refuses it before any reply bound.
        code,value,owner,_=self.windows_gateway('observed_large')
        self.assert_closed_unknown(code,value,owner,'ValueError','private_output_refused',{'complete':True,'returnCode':0,'timeout':False,'refusal':None})
        self.assertEqual(5*1024**2,len(owner.raw['stdout']))

    def test_windows_gateway_nominal_closing_guard_follows_original_child_and_eof(self):
        code,value,owner,guards=self.windows_gateway()
        self.assertEqual(0,code);self.assertEqual('observed',value['state'])
        self.assertEqual(self.RESULT,value['result'])
        self.assertEqual(owner.child.pid,value['capture']['pid']);self.assertTrue(value['capture']['complete'])
        self.assertEqual({'retention':'metadata-only','counts':value['capture']['counts'],'eof':{'stdout':True,'tty':True},'credentialSent':False},value['_operatorPrivateCapture'])
        self.assertEqual(3,len(guards));self.assertEqual({'childCode':0,'closed':True},guards[-1])

    def test_windows_gateway_complete_after_real_timeout_stays_unknown(self):
        code,value,owner,guards=self.windows_gateway('timeout')
        final=self.assert_closed_unknown(code,value,owner,'ValueError','program_observation_unknown',{'complete':True,'returnCode':0,'timeout':True,'refusal':None})
        self.assertTrue(final['timeout'])
        self.assertEqual(2,len(guards))

    def test_windows_gateway_post_start_setup_error_retains_original_owner_and_raw(self):
        code,value,owner,guards=self.windows_gateway('setup')
        final=self.assert_closed_unknown(code,value,owner,'OSError','unclassified',{'complete':False,'returnCode':None,'timeout':False,'refusal':'capture_setup'})
        self.assertEqual('capture_setup',final['refusal']);self.assertEqual({'phase':'setup','errorClass':'OSError'},final['captureErrors'][0])
        # The owner retains the original streams; the reply carries only their counts.
        self.assertEqual(b'PUBLIC_SETUP_OUT',bytes(owner.raw['stdout']))
        self.assertEqual(b'PUBLIC_SETUP_TTY',bytes(owner.raw['tty']))
        self.assertEqual(2,len(guards))

    def test_windows_gateway_late_output_after_exception_is_one_complete_unknown(self):
        code,value,owner,guards=self.windows_gateway('late')
        # capture is the moment of the exception; the one frame follows the late output.
        final=self.assert_closed_unknown(code,value,owner,'RuntimeError','unclassified',{'complete':False,'returnCode':None,'timeout':False,'refusal':None})
        self.assertEqual(len(b'PUBLIC_WINDOWS_TTY'),final['counts']['tty'])
        self.assertEqual(self.RESULT,json.loads(bytes(owner.raw['stdout'])))
        self.assertEqual(b'PUBLIC_WINDOWS_TTY',bytes(owner.raw['tty']))
        self.assertEqual(2,len(guards))

    def test_windows_gateway_real_read_error_stays_unknown_after_complete_drain(self):
        code,value,owner,guards=self.windows_gateway('read')
        final=self.assert_closed_unknown(code,value,owner,'ValueError','program_observation_unknown',{'complete':True,'returnCode':0,'timeout':False,'refusal':'capture_read'})
        self.assertEqual([{'phase':'read','errorClass':'OSError'}],final['captureErrors'])
        self.assertEqual(self.RESULT,json.loads(bytes(owner.raw['stdout'])))
        self.assertEqual(2,len(guards))

    def test_windows_gateway_capture_error_gate_rejects_complete_projection_independently(self):
        code,value,owner,guards=self.windows_gateway('capture_errors')
        # The harness nulls refusal in observe's result, so captureErrors alone closes the
        # gate. The closed facts name custody's own refusal, not that projection.
        final=self.assert_closed_unknown(code,value,owner,'ValueError','program_observation_unknown',{'complete':True,'returnCode':0,'timeout':False,'refusal':'capture_read'})
        self.assertEqual([{'phase':'read','errorClass':'OSError'}],final['captureErrors'])
        self.assertEqual(2,len(guards))

    def test_windows_gateway_prompt_after_timed_out_observation_is_a_final_credential_fact(self):
        code,value,owner,guards=self.windows_gateway('late_prompt')
        final=self.assert_closed_unknown(code,value,owner,'ValueError','program_observation_unknown',{'complete':False,'returnCode':None,'timeout':True,'refusal':None},credential=True)
        self.assertTrue(final['timeout']);self.assertIsNone(final['refusal']);self.assertEqual([],final['captureErrors'])
        self.assertEqual(self.PROMPT,bytes(owner.raw['tty']));self.assertEqual(b'',bytes(owner.raw['stdout']))
        self.assertEqual(2,len(guards))
        # Preserved F6a producer: its one reply precedes the drain, so it denies a credential
        # the same custody then sends, and it has no later frame to correct that.
        with self.preserved_producer('windows_gateway_unknown_reason/windows_vm_deploy.py.before.source','a3c913796009f96d7c03c5a136b5653204eba16fbd8e40fab8ec03e4016e95d5') as producer:
            code,value,owner,guards=self.windows_gateway('late_prompt',producer=producer)
            self.assertEqual(3,code);self.assertEqual('unknown',value['state']);self.assertNotIn('finalCapture',value)
            self.assertFalse(value['_operatorPrivateCapture']['credentialSent']);self.assertTrue(owner.sent)
            self.assertEqual(0,owner.child.returncode)

    def test_windows_gateway_complete_preserved_before_producer_exposes_original_gates(self):
        import importlib.util
        before=(Path(__file__).parent/'fixtures'/'capture_custody'/'windows_vm_deploy.py.before.source').read_bytes()
        self.assertEqual('00c22a5c39414ce9f3f58e75df72cd37c8a199d34d97e9e6b4ddee1db4e6f0d9',hashlib.sha256(before).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'windows_vm_deploy.py';path.write_bytes(before)
            name='agent_tools._capture_before_windows_vm_deploy'
            spec=importlib.util.spec_from_file_location(name,path)
            producer=importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules,{name:producer}):
                spec.loader.exec_module(producer)
                self.assertEqual(0,self.windows_gateway(producer=producer)[0])
                code,value,_,guards=self.windows_gateway('timeout',producer=producer)
                self.assertEqual(0,code);self.assertEqual('observed',value['state']);self.assertTrue(value['capture']['timeout'])
                code,value,_,guards=self.windows_gateway('setup',producer=producer)
                self.assertEqual(3,code);self.assertIsNone(value['_operatorPrivateCapture']);self.assertNotIn('finalCapture',value)
                code,value,_,guards=self.windows_gateway('late',producer=producer)
                self.assertEqual(3,code);self.assertEqual(0,value['_operatorPrivateCapture']['stdout']['bytes']);self.assertNotIn('finalCapture',value)
                self.assertEqual(0,self.windows_gateway('capture_errors',producer=producer)[0])

    def test_windows_gateway_large_file_output_unknown_stays_within_outer_bound(self):
        code,value,owner,guards=self.windows_gateway('large')
        # The stimulus that makes the preserved duplicate-output frame exceed the bound
        # below. Here the exception follows a 4 MiB prefix of each stream (RuntimeError,
        # not the hook's budget assertion) and neither stream can enter the frame.
        final=self.assert_closed_unknown(code,value,owner,'RuntimeError','unclassified',{'complete':False,'returnCode':None,'timeout':False,'refusal':None})
        self.assertLessEqual(len(json.dumps(value,sort_keys=True).encode())+1,16*1024**2)
        for name,letter in (('stdout',b'A'),('tty',b'B')):
            self.assertEqual(5*1024**2,final['counts'][name])
            self.assertEqual(letter*(5*1024**2),bytes(owner.raw[name]))
        self.assertEqual(2,len(guards))

    def test_windows_gateway_preserved_duplicate_output_before_exceeds_outer_bound(self):
        import importlib.util
        before=(Path(__file__).parent/'fixtures'/'capture_custody'/'windows_vm_deploy.duplicate-output.before.source').read_bytes()
        self.assertEqual('f38835e5deb0d58be37fc19c7b8985711f947cf9617f9da05fb32d5e7217e243',hashlib.sha256(before).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'windows_vm_deploy.py';path.write_bytes(before)
            name='agent_tools._capture_duplicate_output_before_windows_vm_deploy'
            spec=importlib.util.spec_from_file_location(name,path);producer=importlib.util.module_from_spec(spec)
            with mock.patch.dict(sys.modules,{name:producer}):
                spec.loader.exec_module(producer)
                code,value,owner,guards=self.windows_gateway('large',producer=producer)
                self.assertEqual(3,code);self.assertEqual('unknown',value['state'])
                self.assertGreater(len(json.dumps(value,sort_keys=True).encode())+1,16*1024**2)
                self.assertGreaterEqual(value['_operatorPrivateCapture']['stdout']['bytes'],4*1024**2)
                self.assertEqual(5*1024**2,value['_operatorPrivateFinalCapture']['stdout']['bytes'])

    def test_windows_gateway_observed_large_reply_is_bounded_unknown_with_original_complete_streams(self):
        code,value,owner,guards=self.windows_gateway('observed_list')
        self.assertLessEqual(len(json.dumps(value,sort_keys=True).encode())+1,16*1024**2)
        final=self.assert_closed_unknown(code,value,owner,'ValueError','program_reply_bound',{'complete':True,'returnCode':0,'timeout':False,'refusal':None})
        self.assertFalse(final['timeout']);self.assertIsNone(final['refusal'])
        self.assertEqual({'stdout':5*self.LIST_ITEMS+1,'tty':len(b'PUBLIC_WINDOWS_TTY')},final['counts'])
        # The owner keeps both complete streams, and the result alone crosses the bound:
        # no raw stream can enter this reply, so only an oversized result can reach it.
        parsed=json.loads(bytes(owner.raw['stdout']));self.assertEqual(self.LIST_ITEMS,len(parsed))
        self.assertGreater(len(json.dumps(parsed).encode()),16*1024**2)
        self.assertEqual(b'PUBLIC_WINDOWS_TTY',bytes(owner.raw['tty']))
        self.assertEqual(3,len(guards));self.assertEqual({'childCode':0,'closed':True},guards[-1])

    def test_windows_gateway_preserved_befores_emit_the_same_list_reply_over_outer_bound(self):
        for filename,digest in (('windows_vm_deploy.py.before.source','00c22a5c39414ce9f3f58e75df72cd37c8a199d34d97e9e6b4ddee1db4e6f0d9'),
                                ('windows_vm_deploy.observed-output.before.source','f4a5c34029f644edcbbb54dadd51bed8d56e351506cf4f032cf5ada54bb3ac0f')):
            with self.subTest(source=filename),self.preserved_producer('capture_custody/'+filename,digest) as producer:
                code,value,owner,guards=self.windows_gateway('observed_list',producer=producer)
                self.assertEqual(0,code);self.assertEqual('observed',value['state'])
                self.assertEqual(self.LIST_ITEMS,len(value['result']))
                self.assertGreater(len(json.dumps(value,sort_keys=True).encode())+1,16*1024**2)

    def test_windows_gateway_preserved_observed_output_befores_exceed_unchanged_outer_bound(self):
        import importlib.util
        fixtures=Path(__file__).parent/'fixtures'/'capture_custody'
        sources=(('canonical','windows_vm_deploy.py.before.source','00c22a5c39414ce9f3f58e75df72cd37c8a199d34d97e9e6b4ddee1db4e6f0d9'),
                 ('observed','windows_vm_deploy.observed-output.before.source','f4a5c34029f644edcbbb54dadd51bed8d56e351506cf4f032cf5ada54bb3ac0f'))
        for label,filename,digest in sources:
            with self.subTest(source=label),tempfile.TemporaryDirectory() as temporary:
                before=(fixtures/filename).read_bytes()
                self.assertEqual(digest,hashlib.sha256(before).hexdigest())
                path=Path(temporary)/'windows_vm_deploy.py';path.write_bytes(before)
                name='agent_tools._capture_observed_output_before_windows_vm_deploy'
                spec=importlib.util.spec_from_file_location(name,path);producer=importlib.util.module_from_spec(spec)
                with mock.patch.dict(sys.modules,{name:producer}):
                    spec.loader.exec_module(producer)
                    code,value,owner,guards=self.windows_gateway('observed_large',producer=producer)
                    self.assertEqual(0,code);self.assertEqual('observed',value['state'])
                    self.assertGreater(len(json.dumps(value,sort_keys=True).encode())+1,16*1024**2)
                    self.assertEqual(owner.child.pid,value['capture']['pid'])
                    self.assertTrue(value['capture']['complete']);self.assertFalse(value['capture']['timeout'])
                    self.assertEqual(5*1024**2,value['_operatorPrivateCapture']['stdout']['bytes'])
                    self.assertEqual(5*1024**2,value['_operatorPrivateCapture']['tty']['bytes'])
