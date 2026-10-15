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
