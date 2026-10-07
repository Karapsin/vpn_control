"""Actual writer causal coverage; local FD/clock/SDK projections, no guest proof."""
import base64
import tempfile
import socket
import unittest
from unittest.mock import patch

from agent_tools import windows_tertiary_guest_stage as stage


class GuestWriteTests(unittest.TestCase):
    def exercise(self, *, size=200, delay=2, count=1, drift_on_guard=False):
        class Client:
            timeout_seconds=3
            now=0
            calls=[]
            received=bytearray()
            def _exchange(self,command,args):
                self.calls.append((command,dict(args),self.timeout_seconds))
                self.now+=delay
                if delay>self.timeout_seconds:raise TimeoutError('SDK projected deadline')
                if command=='guest-file-write':
                    data=base64.b64decode(args['buf-b64'])
                    n=len(data) if count is None else count
                    if type(n)is int and n>0:self.received.extend(data[:n])
                    return {'count':n}
                return {}
        client=Client();client.calls=[];client.received=bytearray();guard_calls=0
        def guard():
            nonlocal guard_calls
            guard_calls+=1
            if drift_on_guard and guard_calls>1:raise ValueError('source/peer projected drift')
        error=None;result=None
        with tempfile.TemporaryFile() as f:
            f.write(b'X'*size);f.seek(0)
            with patch.object(stage,'TARGET_SIZE',size),patch.object(stage.time,'monotonic',lambda:client.now):
                try:result=stage.write_target(client,f.fileno(),71,guard)
                except Exception as e:error=e
        return client,error,result,guard_calls

    def test_partial_count_cannot_run_past_whole_write_budget(self):
        client,error,result,_=self.exercise()
        self.assertIsNotNone(error)
        self.assertIsNone(result)
        self.assertLessEqual(client.now,stage.BUDGET_SECONDS)
        self.assertNotIn('guest-file-close',[c[0]for c in client.calls])
        self.assertEqual(error.original_handle,71)
        self.assertFalse(error.replay_allowed)
        self.assertEqual(client.timeout_seconds,3)

    def test_partial_count_rechecks_current_admission_each_subcall(self):
        client,error,result,_=self.exercise(size=4,delay=0,drift_on_guard=True)
        self.assertIsNotNone(error)
        self.assertIsNone(result)
        self.assertLessEqual(len(client.calls),1)
        self.assertNotIn('guest-file-close',[c[0]for c in client.calls])

    def test_full_count_retains_actual_bytes_and_closes_only_after_complete(self):
        client,error,result,_=self.exercise(size=200,delay=0,count=None)
        self.assertIsNone(error)
        self.assertEqual(bytes(client.received),b'X'*200)
        self.assertEqual(result['transferred'],200)
        self.assertEqual([c[0]for c in client.calls],['guest-file-write','guest-file-flush','guest-file-close'])

    def test_invalid_count_never_retries_or_closes_unknown_handle(self):
        for count in [True,0,-1,201]:
            with self.subTest(count=count):
                client,error,result,_=self.exercise(size=200,delay=0,count=count)
                self.assertIsNotNone(error)
                self.assertIsNone(result)
                self.assertEqual([c[0]for c in client.calls],['guest-file-write'])

    def test_absolute_outer_deadline_clips_actual_sdk_socket_timeout(self):
        from scripts.native_fixture_qga import QgaReadOnlyClient
        class Bound(stage.StageDeadlineMixin,QgaReadOnlyClient):pass
        client=Bound('unused',timeout_seconds=3)
        client._stage_deadline=180
        first,second=socket.socketpair()
        try:
            with patch.object(stage.time,'monotonic',lambda:179):
                client._with_deadline(first,182)
                self.assertEqual(first.gettimeout(),1)
            with patch.object(stage.time,'monotonic',lambda:180),self.assertRaises(TimeoutError):
                client._with_deadline(first,182)
        finally:first.close();second.close()

    def test_partial_counts_cannot_exceed_finite_call_budget(self):
        with patch.object(stage,'MAX_CALL_BUDGET',3):
            client,error,result,_=self.exercise(size=8,delay=0,count=1)
        self.assertIsNotNone(error)
        self.assertIsNone(result)
        self.assertEqual(error.calls,3)
        self.assertEqual(len(client.calls),3)
        self.assertNotIn('guest-file-close',[c[0]for c in client.calls])


class NativeDiagnosticTests(unittest.TestCase):
    def test_actual_failed_terminal_keeps_original_identity_and_error_locator(self):
        # Actual native PID1480 failed pre-entry, with empty stdout omitted by QGA.
        terminal={'exited':True,'exitcode':1,'err-truncated':False,
                  'err-data':base64.b64encode(b'PROBE_INTERACTIVE\r\n').decode()}
        result=stage.terminal_failure_projection(1480,terminal,'/owned/probe-terminal.json')
        self.assertEqual(result['originalGuestPid'],1480)
        self.assertEqual(result['nativeExitCode'],1)
        self.assertEqual(result['stderrBytes'],19)
        self.assertEqual(result['stderrPreview'],'PROBE_INTERACTIVE\r\n')
        self.assertEqual(result['terminalReceipt'],'/owned/probe-terminal.json')
        self.assertEqual(result['stdoutBytes'],0)
        self.assertFalse(result['replayAllowed'])

    def test_observed_absent_user_and_explorer_never_admits_interactive_actor(self):
        observed={'actual':None,'actualCodepoints':[],'sid':None,'sessions':[],
                  'explorers':[],'observerSid':'S-1-5-18','processCensusComplete':True}
        result=stage.actor_admission(observed)
        self.assertFalse(result['interactiveActorAdmitted'])
        self.assertEqual(result['observation'],observed)


class LockClockTests(unittest.TestCase):
    def frames(self):
        from pathlib import Path
        root=Path(__file__).parent/'fixtures/windows_tertiary_recovery'
        return (root/'lock-325.png').read_bytes(),(root/'lock-327.png').read_bytes()

    def test_actual_different_minute_frames_match_only_fixed_clock_exclusion(self):
        first,second=self.frames()
        self.assertNotEqual(first,second)
        self.assertEqual(stage.lock_role_digest(first),stage.lock_role_digest(second))
        self.assertTrue(stage.known_lock_frame(first))
        self.assertTrue(stage.known_lock_frame(second))

    def test_foreign_pixel_and_foreign_layout_outside_clock_refuse(self):
        import struct,zlib
        first,_=self.frames();pixels=bytearray(stage.decode_lock_png(first))
        # Re-encode the actual reference with one foreign top-left pixel.
        pixels[0]^=1
        def chunk(kind,body):return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)
        raw=b''.join(b'\0'+pixels[y*3840:(y+1)*3840]for y in range(800))
        changed=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',1280,800,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(raw))+chunk(b'IEND',b'')
        self.assertFalse(stage.known_lock_frame(changed))
        with self.assertRaises(ValueError):stage.known_lock_frame(b'not-a-PNG')


class NativeMuxWrapperTests(unittest.TestCase):
    """Measured mux failure's bounded source carrier; no Windows native claim."""
    def generated_decoder(self, wrapper):
        import ast
        tree=ast.parse(wrapper)
        before=[]
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='PROGRAM' for t in node.targets):break
            before.append(node)
        ns={};exec(compile(ast.Module(body=before,type_ignores=[]),'actual emitted decoder','exec'),ns)
        return ns['decode_native_source']

    def test_complete_generation_reduces_actual_route_frame_and_preserves_source(self):
        import ast,inspect,json,subprocess,sys
        from pathlib import Path,PurePosixPath
        from agent_tools import ssh_transport as ssh,windows_credential_probe_ssh as probe,windows_parallel_vm_prepare_transport as old
        source='# PUBLIC SOURCE\n'*6500+"print('PUBLIC')\n"
        node=next(n for n in ast.walk(ast.parse(inspect.getsource(old._dispatch))) if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='wrapper'for t in n.targets))
        previous=eval(compile(ast.Expression(node.value),'actual prior wrapper','eval'),{'program':source,'base64':base64})
        new=stage.compressed_native_wrapper(source)
        with tempfile.TemporaryDirectory() as tmp:
            config=ssh.SshConfig(Path(tmp),{'gateway':ssh.SshHost('gateway','gateway.example',22,'public',Path('/public/key'),Path('/public/known')),'arch':ssh.SshHost('arch','arch',22,'public',Path('/public/key'),PurePosixPath('/public/known'),transport='nested',gateway='gateway',remote_host_alias='arch',remote_control_path=PurePosixPath('/public/socket'))})
            before=ssh.build_ssh_argv(config,'arch',command=probe._remote_command(previous))
            after=ssh.build_ssh_argv(config,'arch',command=probe._remote_command(new))
        self.assertGreater(max(len(x.encode())+1 for x in before),65536)
        self.assertLess(max(len(x.encode())+1 for x in after),32768)
        tree=ast.parse(new);nodes=[]
        for n in tree.body:
            if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='secret'for t in n.targets):break
            nodes.append(n)
        body=ast.unparse(ast.Module(body=nodes,type_ignores=[]))+"\nprint(__import__('json').dumps({'length':len(PROGRAM.encode()),'sha256':__import__('hashlib').sha256(PROGRAM.encode()).hexdigest()}))"
        c=subprocess.run([sys.executable,'-c',body],capture_output=True,timeout=3,check=True)
        self.assertEqual(json.loads(c.stdout),{'length':len(source.encode()),'sha256':__import__('hashlib').sha256(source.encode()).hexdigest()})
        self.assertIn('secret=sys.stdin.buffer.read(513)',new)
        self.assertIn('stderr=sys.stderr.buffer',new)
        self.assertNotIn('stderr=subprocess.DEVNULL',new)

    def test_emitted_strict_gzip_refuses_corruption_trailing_and_caps(self):
        import gzip,hashlib
        source=b"print('PUBLIC')\n";packed=gzip.compress(source,mtime=0)
        wrapper=stage.compressed_native_wrapper(source.decode());decode=self.generated_decoder(wrapper)
        sha=hashlib.sha256(source).hexdigest()
        self.assertEqual(decode(base64.b64encode(packed).decode(),len(source),sha),source.decode())
        cases=[('not base64!',len(source),sha),(base64.b64encode(b'not gzip').decode(),len(source),sha),(base64.b64encode(packed[:-8]+bytes([packed[-8]^1])+packed[-7:]).decode(),len(source),sha),(base64.b64encode(packed[:-1]).decode(),len(source),sha),(base64.b64encode(packed+b'trailing').decode(),len(source),sha),(base64.b64encode(packed+packed).decode(),len(source),sha),(base64.b64encode(packed).decode(),len(source)-1,sha),(base64.b64encode(packed).decode(),len(source)+1,sha),(base64.b64encode(packed).decode(),len(source),'0'*64),(base64.b64encode(gzip.compress(b'A'*131001,mtime=0)).decode(),131001,sha)]
        for data,size,digest in cases:
            with self.subTest(size=size,data=data[:20]),self.assertRaises(ValueError):decode(data,size,digest)

    def test_source_and_transport_size_caps_refuse_before_wrapper_submission(self):
        import random
        with self.assertRaises(ValueError):stage.compressed_native_wrapper('#'+'A'*131001)
        # Valid source with a deliberately incompressible public literal.
        text=random.Random(20261006).randbytes(50000).hex()
        with self.assertRaises(ValueError):stage.compressed_native_wrapper('PUBLIC='+repr(text))


class NativeSidRuleTests(unittest.TestCase):
    def test_actual_probe_passes_sid_identity_reference_not_ntaccount_string(self):
        # Native 3c/PID4740 failed AddAccessRule's string identity translation.
        # Inspect the actual emitted statement, not a separate fixture writer.
        script=stage.atomic_probe_script('3c436273-aac9-4f47-a4c4-78aa37f094f5')
        statement=next(row for row in script.splitlines()if '$rule=' in row)
        self.assertIn("FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),",statement)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows ACL translation required')
    def test_actual_windows_in_memory_translation_control_and_typed_sid(self):
        import subprocess,json
        script="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"+stage.sid_rule_probe_script()+"\n$sidRuleControl|ConvertTo-Json -Compress"
        c=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=15,check=True)
        self.assertEqual(json.loads(c.stdout.decode('utf-8-sig')),{'oldIdentityTranslationFailed':True,'typedSid':'S-1-5-32-544'})


class NativeShareCustodyTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name=='nt','actual Windows share arbitration required')
    def test_actual_windows_metadata_and_data_share_controls(self):
        import subprocess,json
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='tertiary-share-control-') as tmp:
            encoded=base64.b64encode(str(Path(tmp)).encode('utf-16le')).decode('ascii')
            script="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n$root=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('"+encoded+"'))\nAdd-Type -TypeDefinition @'\n"+stage.PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"+stage.custody_share_probe_script()+"\n$shareControl|ConvertTo-Json -Compress"
            c=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=True)
            value=json.loads(c.stdout.decode('utf-8-sig'))
            self.assertTrue(value['metadataFileRenamed'])
            self.assertTrue(value['metadataDirectoryRenamed'])
            self.assertTrue(value['participatingFileRenameRefused'])
            self.assertTrue(value['participatingDirectoryRenameRefused'])
            self.assertTrue(value['compatibleWriterObserved'])
            self.assertEqual(value['fileRenameError'],32)
            self.assertEqual(value['directoryRenameError'],32)
            self.assertTrue(value['heldAndNamedIdentityClosed'])


class Public6HandshakeTests(unittest.TestCase):
    correlation='39fc9409-22ee-492b-b078-d27fc1281c26'
    def exercise(self,count=1,fail=None,delay=0,ready_mutation=None,drift_after_open=False):
        import json
        root=r'C:\ProgramData\VpnControlTertiaryStageProbe-'+self.correlation
        ready=dict(correlationId=self.correlation,pid=6536,birthTicks=123456789,root=root,target=root+r'\owned.msi',targetNativeId='file-native',rootNativeId='root-native')
        if ready_mutation:ready.update(ready_mutation)
        class Client:
            timeout_seconds=3
            now=0
            calls=[]
            received=b''
            def _exchange(self,command,args):
                self.calls.append((command,args.copy()));self.now+=delay
                if fail==command:raise TimeoutError('uncertain original response')
                if command=='guest-file-open':return 71
                if command=='guest-file-write':
                    part=base64.b64decode(args['buf-b64']);n=count
                    if type(n)is int and n>0:self.received+=part[:n]
                    return {'count':n}
                return {}
        c=Client();c.calls=[];events=[];scripts=[]
        def guard():
            if drift_after_open and c.calls:raise ValueError('fresh source/peer drift after open')
        def ps_once(name,script,live):
            scripts.append((name,script,live));return ready if name=='public-six-ready'else {'releaseCreated':True}
        result=None;error=None
        with patch.object(stage.time,'monotonic',lambda:c.now):
            try:result=stage.public6_qga_handshake(c,self.correlation,6536,ps_once,guard,lambda n,v:events.append((n,v)))
            except Exception as e:error=e
        return c,result,error,events,scripts

    def test_actual_composed_partial_writer_preserves_handle_and_release_order(self):
        c,result,error,events,scripts=self.exercise()
        self.assertIsNone(error);self.assertEqual(c.received,b'PUBLIC')
        self.assertEqual([x[0]for x in c.calls],['guest-file-open']+['guest-file-write']*6+['guest-file-flush','guest-file-close'])
        self.assertTrue(all(x[1].get('handle',71)==71 for x in c.calls))
        self.assertEqual(scripts[-1][0],'public-six-release');self.assertFalse(scripts[-1][2])
        self.assertIn('[IO.FileMode]::CreateNew',scripts[-1][1]);self.assertEqual(result['originalHandle'],71)
        self.assertEqual(c.timeout_seconds,3)

    def test_unknown_response_never_reopens_or_publishes_release(self):
        for command in ('guest-file-open','guest-file-write','guest-file-flush','guest-file-close'):
            with self.subTest(command=command):
                c,result,error,events,scripts=self.exercise(fail=command)
                self.assertIsNone(result);self.assertFalse(error.replay_allowed)
                self.assertEqual(sum(x[0]==command for x in c.calls),1)
                self.assertEqual(len(scripts),1)
                self.assertEqual(error.original_handle,None if command=='guest-file-open'else 71)

    def test_positive_open_handle_retained_when_following_guard_refuses(self):
        c,result,error,events,scripts=self.exercise(drift_after_open=True)
        self.assertEqual(error.original_handle,71);self.assertEqual([x[0]for x in c.calls],['guest-file-open']);self.assertEqual(len(scripts),1)

    def test_wrong_ready_actor_or_foreign_target_refuses_before_open(self):
        for mutation in ({'pid':True},{'birthTicks':True},{'pid':1},{'root':'foreign'},{'target':'foreign'},{'correlationId':'foreign'},{'targetNativeId':False}):
            with self.subTest(mutation=mutation):
                c,result,error,events,scripts=self.exercise(ready_mutation=mutation)
                self.assertIsNotNone(error);self.assertEqual(c.calls,[])

    def test_malformed_counts_and_deadline_stop_without_release(self):
        for count in (True,0,-1,7):
            with self.subTest(count=count):
                c,result,error,events,scripts=self.exercise(count=count)
                self.assertIsNotNone(error);self.assertEqual(len(scripts),1)
        c,result,error,events,scripts=self.exercise(delay=8)
        self.assertIsNotNone(error);self.assertEqual(len(scripts),1)
        self.assertNotIn('guest-file-close',[x[0]for x in c.calls])

    def test_receipt_requires_actual_types_ids_hash_and_all_share_controls(self):
        c,handshake,error,events,scripts=self.exercise(count=6)
        ready=handshake['ready'];q={k:ready[k]for k in ('pid','birthTicks','target','targetNativeId','rootNativeId')}
        q.update(originalFileHandle=71,closed=True,length=6,sha256=stage.PUBLIC6_SHA256,heldAndNamedIdentityClosed=True)
        share=dict(metadataFileRenamed=True,metadataDirectoryRenamed=True,participatingFileRenameRefused=True,participatingDirectoryRenameRefused=True,fileRenameError=32,directoryRenameError=32,compatibleWriterObserved=True,heldAndNamedIdentityClosed=True)
        receipt={'qgaControl':q,'shareControl':share,'releaseGuardControl':dict(oldLongForeignAccepted=True,fixedForeignRefused=True,positiveIntAndLongAccepted=True,cases=10)}
        self.assertEqual(stage.validate_public6_receipt(receipt,handshake),q)
        for field,value in [('closed',1),('length',True),('originalFileHandle',True),('sha256','wrong'),('targetNativeId','foreign')]:
            with self.subTest(field=field),self.assertRaises(ValueError):stage.validate_public6_receipt(dict(receipt,qgaControl=dict(q,**{field:value})),handshake)
        with self.assertRaises(ValueError):stage.validate_public6_receipt(dict(receipt,shareControl=dict(share,metadataFileRenamed=1)),handshake)
        with self.assertRaises(ValueError):stage.validate_public6_receipt(dict(receipt,releaseGuardControl=dict(receipt['releaseGuardControl'],oldLongForeignAccepted=1)),handshake)


class FrozenQgaClientTests(unittest.TestCase):
    def test_actual_sdk_frozen_timeout_supports_original_public6_handshake(self):
        from scripts.native_fixture_qga import QgaReadOnlyClient
        class Client(stage.StageDeadlineMixin,QgaReadOnlyClient):
            def _exchange(self,command,args):
                self.calls.append(command)
                if command=='guest-file-open':return 71
                if command=='guest-file-write':return {'count':6}
                return {}
        client=Client('unused',timeout_seconds=3);client.calls=[]
        corr='39fc9409-22ee-492b-b078-d27fc1281c26';root=r'C:\ProgramData\VpnControlTertiaryStageProbe-'+corr
        ready=dict(correlationId=corr,pid=2592,birthTicks=123456789,root=root,target=root+r'\owned.msi',targetNativeId='file-native',rootNativeId='root-native')
        def ps_once(name,script,live):return ready if name=='public-six-ready'else {'releaseCreated':True}
        result=stage.public6_qga_handshake(client,corr,2592,ps_once,lambda:None,lambda name,value:None)
        self.assertTrue(result['closed']);self.assertEqual(client.timeout_seconds,3)
        self.assertEqual(client.calls,['guest-file-open','guest-file-write','guest-file-flush','guest-file-close'])

    def test_actual_sdk_frozen_timeout_preserves_original_write_failure(self):
        from scripts.native_fixture_qga import QgaReadOnlyClient
        class Client(stage.StageDeadlineMixin,QgaReadOnlyClient):
            def _exchange(self,command,args):raise TimeoutError('actual original uncertain exchange')
        c=Client('unused',timeout_seconds=3)
        with tempfile.TemporaryFile()as f:
            f.write(b'PUBLIC');f.seek(0)
            with patch.object(stage,'TARGET_SIZE',6),self.assertRaises(stage.GuestWriteUnknown)as caught:
                stage.write_target(c,f.fileno(),71,lambda:None)
        self.assertIsInstance(caught.exception.__cause__,TimeoutError)
        self.assertEqual(caught.exception.original_handle,71);self.assertEqual(c.timeout_seconds,3)


class OptionalProbeDiagnosticTests(unittest.TestCase):
    def test_actual_missing_optional_record_retains_absence_without_admission(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory()as directory:
            try:(Path(directory)/'public6-ready-started.json').read_bytes()
            except FileNotFoundError as error:
                self.assertEqual(stage.missing_optional_probe_record('public6-ready-started.json',error),{'name':'public6-ready-started.json','present':False,'diagnosticOnly':True,'authority':False})
            else:self.fail('missing fixture unexpectedly present')
        for name,error in [('probe-started.json',FileNotFoundError(2,'missing')),('foreign',FileNotFoundError(2,'missing')),('public6-ready-started.json',PermissionError(13,'denied')),('public6-ready-started.json',FileNotFoundError(5,'other'))]:
            with self.subTest(name=name),self.assertRaises(ValueError):stage.missing_optional_probe_record(name,error)


class RealReceiptIngressTests(unittest.TestCase):
    def test_actual_sdk_and_actual_receipt_writer_complete_public_handshake(self):
        from pathlib import Path
        import os,json
        from scripts.native_fixture_qga import QgaReadOnlyClient
        from agent_tools.windows_parallel_vm_prepare import record_at
        class Client(stage.StageDeadlineMixin,QgaReadOnlyClient):
            def _exchange(self,command,args):
                if command=='guest-file-open':return 71
                if command=='guest-file-write':return {'count':1}
                return {}
        corr='39fc9409-22ee-492b-b078-d27fc1281c26';root=r'C:\ProgramData\VpnControlTertiaryStageProbe-'+corr
        ready=dict(correlationId=corr,pid=2592,birthTicks=123456789,root=root,target=root+r'\owned.msi',targetNativeId='file-native',rootNativeId='root-native')
        client=Client('unused',timeout_seconds=3)
        with tempfile.TemporaryDirectory()as directory:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                def record(name,value):record_at(fd,name,value)
                def ps_once(name,script,live):
                    record(name+'-intent.json',{'sourceOnlyProjection':True});return ready if name.endswith('-ready')else {'releaseCreated':True}
                result=stage.public6_qga_handshake(client,corr,2592,ps_once,lambda:None,record)
                self.assertTrue(result['closed'])
                names={p.name for p in Path(directory).iterdir()}
                self.assertEqual(len(names),12)
                self.assertTrue(all('6'not in n and not any(c.isdigit()for c in n)for n in names))
            finally:os.close(fd)


class ReleasePrecedenceTests(unittest.TestCase):
    def test_actual_producer_predicate_foreign_long_cannot_cancel_identity(self):
        # Actual source expression interpreted with PowerShell's documented
        # equal and/or precedence, left-to-right; this is a language projection.
        import re
        expr=stage.release_guard_predicate()
        values={"$token.correlationId -cne $corr":True,"$token.pid -ne $PID":False,"$token.birthTicks -ne $birth":False,"$token.targetNativeId -cne $filePin":False,"$token.originalFileHandle -isnot [int]":True,"$token.originalFileHandle -isnot [long]":False,"$token.originalFileHandle -le 0":False,"$token.closed -isnot [bool]":False,"-not $token.closed":False}
        for term,value in values.items():expr=expr.replace(term,str(value))
        tokens=re.findall(r'True|False|\(|\)|-and|-or',expr);self.assertEqual(''.join(tokens),re.sub(r'\s+','',expr))
        def read(index):
            if tokens[index]=='(':
                value,index=group(index+1);self.assertEqual(tokens[index],')');return value,index+1
            return tokens[index]=='True',index+1
        def group(index):
            value,index=read(index)
            while index<len(tokens)and tokens[index]!=')':
                op=tokens[index];right,index=read(index+1);value=(value and right)if op=='-and'else(value or right)
            return value,index
        value,index=group(0);self.assertEqual(index,len(tokens));self.assertTrue(value)


class NativeReleaseGuardTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name=='nt','actual PowerShell Windows control required')
    def test_actual_windows_in_memory_old_new_release_predicate(self):
        import subprocess,json
        ps="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"+stage.release_guard_control_script()+";$releaseGuardControl|ConvertTo-Json -Compress"
        completed=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',ps],capture_output=True,timeout=30,check=True)
        self.assertEqual(json.loads(completed.stdout.decode('utf-8-sig')),dict(oldLongForeignAccepted=True,fixedForeignRefused=True,positiveIntAndLongAccepted=True,cases=10))


class TargetCustodyAclTests(unittest.TestCase):
    def test_exact_native_root_and_target_supplement_and_foreign_refusals(self):
        import copy
        sid='S-1-5-21-606332539-4179368406-55829832-1000';path=r'C:\ProgramData\VpnControlTertiaryFixture-72193b20-9f5f-4fd1-9b2a-34db296b17c7'
        request={'expectedSid':sid,'guestStage':path};rights={'S-1-5-18':2032127,'S-1-5-32-544':2032127,sid:1179817}
        def acl(path,directory):return dict(path=path,ownerSid='S-1-5-18',protected=directory,acl=[dict(sid=s,rights=r,type='Allow',inherited=not directory,inheritance=3 if directory else 0,propagation=0)for s,r in rights.items()])
        root=acl(path,True);target=acl(path+r'\vpn-control-2.2.2.msi',False)
        self.assertTrue(stage.validate_target_custody_acl(root,target,request))
        for field,value in [('ownerSid',sid),('protected',True),('path','foreign')]:
            with self.subTest(field=field),self.assertRaises(ValueError):stage.validate_target_custody_acl(root,dict(target,**{field:value}),request)
        for field,value in [('sid','foreign'),('rights',True),('type','Deny'),('inherited',1),('inheritance',3),('propagation',True)]:
            t=copy.deepcopy(target);t['acl'][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):stage.validate_target_custody_acl(root,t,request)
        t=copy.deepcopy(target);t['acl'].append(t['acl'][0])
        with self.assertRaises(ValueError):stage.validate_target_custody_acl(root,t,request)


class TargetOwnerReceiptTests(unittest.TestCase):
    def test_native_actor_and_complete_census_are_required_and_off_unresolved(self):
        o=dict(observerSid='S-1-5-18',interactiveUser='VPNPARITYX64'+chr(92)+'parityagent',interactiveSid='S-1-5-21-606332539-4179368406-55829832-1000',session=1,processCensusComplete=True,processCount=140,effectOwners=[],publicOFF='UNRESOLVED')
        self.assertTrue(stage.validate_custody_owner(o))
        for field,value in [('session',True),('processCensusComplete',1),('processCount',True),('effectOwners',[{'pid':5}]),('publicOFF','OFF'),('interactiveUser',None),('interactiveSid','S-1-5-18')]:
            with self.subTest(field=field),self.assertRaises(ValueError):stage.validate_custody_owner(dict(o,**{field:value}))


class ActualTargetCompositionTests(unittest.TestCase):
    def test_actual_release_body_keeps_natural_terminal_and_real_receipt_roles(self):
        import ast,json,os
        from pathlib import Path
        from agent_tools.windows_parallel_vm_prepare import record_at
        from scripts.native_fixture_qga import QgaReadOnlyClient
        source=ast.parse(stage.TARGET_STAGE_BODY)
        ps=next(n for n in ast.walk(source)if isinstance(n,ast.FunctionDef)and n.name=='ps_once')
        release=next(n for n in ast.walk(source)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='ps_once'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value=='custodian-release')
        self.assertEqual([(x.arg,x.value.value)for x in release.keywords],[('post_custodian_live',False)])
        class Client(stage.StageDeadlineMixin,QgaReadOnlyClient):
            def _exchange(self,command,args):
                self.producer_exited=True;return {'pid':42}
            def guest_exec_status(self,pid):
                self.observed.append(pid)
                return {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"releaseCreated":true}').decode()}
        client=Client('unused',timeout_seconds=3);client.producer_exited=False;client.observed=[]
        calls=[]
        def guard(custodian_live=True):
            calls.append(custodian_live)
            if custodian_live and client.producer_exited:raise ValueError('old natural terminal falsely refused')
        with tempfile.TemporaryDirectory()as directory:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                namespace=dict(client=client,guard=guard,prepare=type('P',(),{'record_at':staticmethod(record_at)}),fd=fd,journal=Path(directory),need=lambda ok,reason:None if ok else (_ for _ in ()).throw(ValueError(reason)),time=stage.time,hashlib=stage.hashlib,base64=base64,json=json,terminal_failure_projection=stage.terminal_failure_projection,native_failure=None)
                exec(compile(ast.fix_missing_locations(ast.Module(body=[ps],type_ignores=[])),'actual fixed target ps_once','exec'),namespace)
                result=namespace['ps_once']('custodian-release','PUBLIC_SOURCE_ONLY',post_custodian_live=False)
                self.assertTrue(result['releaseCreated']);self.assertEqual(client.observed,[42])
                self.assertEqual(calls,[True,False,False,False])
                self.assertEqual({p.name for p in Path(directory).iterdir()},{'custodian-release-intent.json','custodian-release-started.json','custodian-release-terminal.json'})
            finally:os.close(fd)

    def test_actual_target_composition_is_compilable_and_wrapper_ast_identity_closed(self):
        import ast
        compile(stage.TARGET_STAGE_BODY,'actual fixed tertiary target body','exec')
        canonical=ast.unparse(ast.parse(stage.TARGET_STAGE_BODY))+'\n'
        self.assertEqual(ast.dump(ast.parse(canonical),include_attributes=False),ast.dump(ast.parse(stage.TARGET_STAGE_BODY),include_attributes=False))
        wrapped=stage.compressed_native_wrapper(canonical)
        self.assertIn('decode_native_source',wrapped)


class ActualTargetReceiptTypeTests(unittest.TestCase):
    def test_actual_emitted_ready_and_final_guards_reject_float_and_bool(self):
        import ast,copy
        source=ast.parse(stage.TARGET_STAGE_BODY)
        calls={n.args[1].value:n for n in ast.walk(source)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and len(n.args)==2 and isinstance(n.args[1],ast.Constant)}
        root=r'C:\ProgramData\VpnControlTertiaryFixture-72193b20-9f5f-4fd1-9b2a-34db296b17c7';corr='39fc9409-22ee-492b-b078-d27fc1281c26'
        request=dict(guestStage=root,targetSha256='f8a8741bcfd22c04be50836aa22da77009105ab1b63df4d9b7648397779a8dfc',targetSize=131101044)
        ready=dict(state='custodian-ready',correlationId=corr,pid=42,birthTicks=123456789,stage=root,targetNativeId='native-file',rootNativeId='native-root')
        complete=dict(ready,state='custodian-complete',sha256=request['targetSha256'],length=request['targetSize'])
        def check(reason,r=ready,c=complete):
            expr=ast.Expression(body=calls[reason].args[0]);return eval(compile(ast.fix_missing_locations(expr),'actual fixed target receipt predicate','eval'),dict(ready=r,complete=c,CORRELATION=corr,custodian_pid=42,STAGE_REQUEST=request))
        self.assertTrue(check('tertiary-custodian-ready-identity'));self.assertTrue(check('tertiary-custodian-final-binding'))
        for field,value in [('pid',42.0),('pid',True),('birthTicks',123456789.0),('birthTicks',True),('length',131101044.0),('length',True)]:
            with self.subTest(field=field,value=value):self.assertFalse(check('tertiary-custodian-final-binding',c=dict(complete,**{field:value})))
        with self.subTest(ready_float_pid=True):self.assertFalse(check('tertiary-custodian-ready-identity',r=dict(ready,pid=42.0)))


class NativeTargetOwnerTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name=='nt','actual Windows creation-time owner control required')
    def test_actual_windows_creation_time_owner_and_inherited_custody(self):
        import subprocess,json
        ps=stage.target_owner_probe_script()
        completed=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',ps],capture_output=True,timeout=30,check=True)
        result=json.loads(completed.stdout.decode('utf-8-sig'))
        self.assertTrue(result['explicitOwnerMatchesCurrentUser'])
        self.assertTrue(result['inheritedDaclUnchanged'])
        self.assertTrue(result['nativeIdentityStable'])
        self.assertTrue(result['writerCompatible'])
        self.assertEqual(result['renameError'],32)
        self.assertIs(type(result['oldOwnerMatchesCurrentUser']),bool)


class TargetOwnerFactoryTests(unittest.TestCase):
    def test_complete_factory_has_actual_owner_control_for_system_guest(self):
        # Native execution remains the Windows test and actual guest scenario.
        # The complete factory must expose that actual control before dispatch.
        script=stage.target_owner_probe_script(system_guest=True,correlation='bc9ce4fa-94b2-4e90-a1b6-097c8f6d94a1')
        self.assertIn("'S-1-5-18'",script)
        self.assertIn("'S-1-5-32-544'",script)
        self.assertIn('OWNER_OLD_SYSTEM_CONTROL',script)
        self.assertIn('CreateTargetOwned',script)


class TargetOwnerReceiptTests(unittest.TestCase):
    def test_actual_control_receipt_requires_strict_native_role_and_types(self):
        r=dict(explicitOwnerMatchesCurrentUser=True,inheritedDaclUnchanged=True,nativeIdentityStable=True,writerCompatible=True,oldOwnerMatchesCurrentUser=False,renameError=32,systemGuest=True,installerAction=False,productAcceptance=False,observerSid='S-1-5-18',oldOwnerSid='S-1-5-32-544',rootNativeId='root',targetNativeId='file',root=r'C:\owned')
        self.assertTrue(stage.validate_target_owner_control(r,system_guest=True))
        for key,value in [('renameError',32.0),('explicitOwnerMatchesCurrentUser',1),('oldOwnerMatchesCurrentUser',0),('oldOwnerSid','S-1-5-18'),('observerSid','foreign'),('targetNativeId',None),('systemGuest',1)]:
            with self.subTest(key=key),self.assertRaises(ValueError):stage.validate_target_owner_control(dict(r,**{key:value}),system_guest=True)


class FreshGuestBindingTests(unittest.TestCase):
    def test_actual_host_binding_guard_keeps_original_host_manifest(self):
        import ast,json
        from pathlib import Path
        expression=next(n.args[0]for n in ast.walk(ast.parse(stage.TARGET_STAGE_BODY))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and len(n.args)>1 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='tertiary-stage-host-binding')
        host_request={'correlation':'original','guestStage':'old','hostStage':'same','targetSha256':'same'}
        guest_request=dict(host_request,correlation='fresh',guestStage='new')
        with tempfile.TemporaryDirectory()as directory:
            host=Path(directory);(host/'binding.json').write_text(json.dumps(host_request))
            context={'json':json,'host':host,'HOST_STAGE_REQUEST':host_request,'STAGE_REQUEST':guest_request}
            self.assertTrue(eval(compile(ast.Expression(expression),'actual host binding guard','eval'),context))
            (host/'binding.json').write_text(json.dumps(guest_request))
            self.assertFalse(eval(compile(ast.Expression(expression),'actual host binding guard','eval'),context))

    def test_fresh_guest_can_only_change_exact_two_directory_fields(self):
        from agent_tools.windows_tertiary_fixture_stage import TARGET_SHA256,SOURCE_SHA
        old='72193b20-9f5f-4fd1-9b2a-34db296b17c7';new='55043a46-02e2-4204-9ea8-995ce90b098e';corr='bc9ce4fa-94b2-4e90-a1b6-097c8f6d94a1'
        host=dict(correlation=old,guestStage='C:\\ProgramData\\VpnControlTertiaryFixture-'+old,expectedSid='S-1-5-21-606332539-4179368406-55829832-1000',targetSize=stage.TARGET_SIZE,targetSha256=TARGET_SHA256,sourceSha=SOURCE_SHA,installerAuthorized=False,hostStage='/same/owned/source',nativeGo=False)
        guest=dict(host,correlation=new,guestStage='C:\\ProgramData\\VpnControlTertiaryFixture-'+new)
        self.assertTrue(stage.validate_target_retry_binding(host,guest,corr))
        for change in [{'targetSize':float(stage.TARGET_SIZE)},{'nativeGo':0},{'hostStage':'/foreign'},{'extra':'foreign'},host]:
            with self.subTest(change=change),self.assertRaises(ValueError):stage.validate_target_retry_binding(host,dict(guest,**change),corr)


class DirectSshCarrierTests(unittest.TestCase):
    def test_actual_openssh_parser_and_two_hop_option_precedence(self):
        import subprocess,shlex
        ssh=__import__('shutil').which('ssh')
        if ssh is None:self.skipTest('local OpenSSH option parser unavailable')
        inner=['ssh','-F','/dev/null','-S','/tmp/owned-inner','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/tmp/public-known-hosts','archlinux','python3 -c "print(7)"']
        argv=['ssh','-F','/dev/null','-S','/tmp/owned-outer','-o','ControlMaster=no','-o','ProxyCommand=false','gateway',shlex.join(inner)]
        bypass=stage.direct_nested_ssh_argv(argv,'/tmp/owned-outer','/tmp/owned-inner','gateway','archlinux')
        actual_inner=shlex.split(bypass[-1]);self.assertEqual(actual_inner[-1],inner[-1]);self.assertEqual(bypass[-2],argv[-2])
        for command in [bypass[:-1],actual_inner[:-1]]:
            result=subprocess.run([ssh,'-G',*command[1:]],capture_output=True,check=True,timeout=5)
            values=dict(line.split(' ',1)for line in result.stdout.decode().splitlines()if ' 'in line)
            self.assertIn(values.get('controlpath'),(None,'none'));self.assertEqual(values['controlmaster'],'false')
        self.assertIn('StrictHostKeyChecking=yes',actual_inner);self.assertIn('UserKnownHostsFile=/tmp/public-known-hosts',actual_inner)
        self.assertEqual(argv[argv.index('-S')+1],'/tmp/owned-outer')
        with self.assertRaises(ValueError):stage.direct_nested_ssh_argv(argv,'/foreign','/tmp/owned-inner','gateway','archlinux')

    def test_actual_strict_client_constructor_gets_complete_large_bypass_argv(self):
        import os,json,hashlib,sys,subprocess,shlex
        from pathlib import Path
        from agent_tools import windows_secondary_fixture_stage as client_module
        large='python3 -c '+shlex.quote('print('+repr('X'*49010)+')')
        argv=['ssh','-S','/tmp/owned-outer','-o','ControlMaster=no','gateway',shlex.join(['ssh','-S','/tmp/owned-inner','-o','BatchMode=yes','archlinux',large])]
        bypass=stage.direct_nested_ssh_argv(argv,'/tmp/owned-outer','/tmp/owned-inner','gateway','archlinux')
        expected=hashlib.sha256(json.dumps(bypass,ensure_ascii=False,separators=(',',':')).encode()).hexdigest();real_popen=subprocess.Popen
        def spawn(actual,**kwargs):
            self.assertEqual(actual,bypass)
            code="import sys,json,hashlib;print(hashlib.sha256(json.dumps(sys.argv[1:],ensure_ascii=False,separators=(',',':')).encode()).hexdigest());print('public-stderr',file=sys.stderr)"
            return real_popen([sys.executable,'-I','-c',code,*actual],**kwargs)
        with tempfile.TemporaryDirectory()as directory:
            class Capture:
                fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
                def create(self,name,data):
                    f=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=self.fd)
                    try:os.write(f,data)
                    finally:os.close(f)
                def close(self):
                    os.close(self.fd);self.fd=-1
            capture=Capture();read,write=os.pipe();os.write(write,b'PUBLIC\n');os.close(write);client=None
            try:
                with patch.object(client_module.subprocess,'Popen',spawn):client=client_module.SecondaryFixtureInputClient(bypass,read,capture)
                os.close(read);read=None;client.observe(5)
                self.assertTrue(client.eof and client.stderr_eof);self.assertEqual(client.child.poll(),0)
                self.assertEqual(bytes(client.raw).decode().strip(),expected);self.assertEqual(bytes(client.stderr_raw),b'public-stderr\n')
                client.close_terminal();client=None
            finally:
                if read is not None:os.close(read)
                if capture.fd!=-1:os.close(capture.fd)


class TransportStderrClassifierTests(unittest.TestCase):
    def test_exact_observed_errors_remain_unknown_without_cause_claim(self):
        cases=[(b'mm_send_fd: sendmsg(2): Message too long\nmux_client_request_session: send fds failed\n','mux-fd-send-failed'),(b'Connection closed by UNKNOWN port 65535\r\n','connection-closed')]
        for raw,category in cases:
            with self.subTest(category=category):
                result=stage.classify_transport_stderr(raw)
                self.assertEqual(result['category'],category)
                self.assertEqual(result['outcome'],'unknown')
                self.assertFalse(result['causeEstablished'])
                self.assertFalse(result['replayAllowed'])
                self.assertEqual(result['length'],len(raw))
                self.assertEqual(result['sha256'],__import__('hashlib').sha256(raw).hexdigest())

    def test_bounded_classifier_refuses_invalid_inputs_and_does_not_echo(self):
        for raw in ['foreign',bytearray(b'foreign'),b'X'*4097]:
            with self.subTest(kind=type(raw).__name__),self.assertRaises(ValueError):stage.classify_transport_stderr(raw)
        self.assertEqual(stage.classify_transport_stderr(b'foreign-private-text')['category'],'unclassified')
        self.assertNotIn('foreign-private-text',repr(stage.classify_transport_stderr(b'foreign-private-text')))


class ConservedCustodianFactoryTests(unittest.TestCase):
    def test_only_unreferenced_launcher_is_removed_from_complete_header(self):
        import ast
        source="def launch_pair():\n raise RuntimeError('unused')\ndef guard():\n return 'mandatory'\nassert guard()=='mandatory'\n"
        reduced=stage.omit_unused_pair_launcher(source)
        original=ast.parse(source);original.body=original.body[1:]
        self.assertEqual(ast.dump(ast.parse(reduced),include_attributes=False),ast.dump(original,include_attributes=False))
        exec(compile(reduced,'actual finite header reduction','exec'),{})
        for malformed in [source+'launch_pair()\n',source.replace('def launch_pair():','def foreign():')]:
            with self.assertRaises(ValueError):stage.omit_unused_pair_launcher(malformed)

    def test_actual_conservation_body_refuses_current_prior_journal(self):
        import ast
        body=stage.conserved_target_stage_body();compile(body,'conserved actual target body','exec')
        checks=[n.args[0]for n in ast.walk(ast.parse(body))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need'and len(n.args)>1 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='tertiary-prior38-current-journal-absent']
        self.assertEqual(len(checks),3)
        with tempfile.TemporaryDirectory()as directory:
            path=__import__('pathlib').Path(directory)/'old-journal'
            for expression in checks:
                code=compile(ast.Expression(expression),'actual conservation predicate','eval')
                self.assertTrue(eval(code,dict(os=__import__('os'),prior38=path)))
                path.mkdir();self.assertFalse(eval(code,dict(os=__import__('os'),prior38=path)));path.rmdir()

    def test_actual_factory_preserves_old_roots_and_cleanup_boundary(self):
        from agent_tools.windows_tertiary_fixture_stage import TARGET_SHA256,SOURCE_SHA
        old='72193b20-9f5f-4fd1-9b2a-34db296b17c7';new='a4f6ba55-bdfb-4710-8a87-0cf56807fc54';corr='efb9a8d6-2a86-42b6-bebb-aebd0f51bfa4'
        request=dict(correlation=new,guestStage='C:\\ProgramData\\VpnControlTertiaryFixture-'+new,expectedSid='S-1-5-21-606332539-4179368406-55829832-1000',targetSize=stage.TARGET_SIZE,targetSha256=TARGET_SHA256,sourceSha=SOURCE_SHA,installerAuthorized=False,nativeGo=False,hostStage='/same/owned/source')
        script=stage.conserved_custodian_script(request,corr)
        self.assertEqual(script.count(stage.CONSERVATION_PS),1)
        self.assertLess(script.index(stage.CONSERVATION_PS),script.index('[TertiaryPrivateStage]::CreateExclusive($root'))
        self.assertIn('function Assert-Custody {\n  Assert-Historical\n',script)
        self.assertIn('$heldDrive.Dispose();foreach($stream in $historicalStreams)',script)
        self.assertIn('C:\\ProgramData\\VpnControlTertiaryFixture-'+old,script)
        for previous in [old,'55043a46-02e2-4204-9ea8-995ce90b098e']:
            with self.subTest(previous=previous),self.assertRaises(ValueError):stage.conserved_custodian_script(dict(request,correlation=previous,guestStage='C:\\ProgramData\\VpnControlTertiaryFixture-'+previous),corr)


class AuthoredMsiScopeTests(unittest.TestCase):
    @staticmethod
    def fixture():
        from agent_tools.windows_tertiary_fixture_stage import TARGET_SHA256,SOURCE_SHA
        sid='S-1-5-21-606332539-4179368406-55829832-1000';identifier='67bdf8b5-d34c-42e1-83ec-a6b3e0af7943'
        request=dict(correlation=identifier,guestStage='C:\\ProgramData\\VpnControlTertiaryFixture-'+identifier,expectedSid=sid,targetSize=stage.TARGET_SIZE,targetSha256=TARGET_SHA256,sourceSha=SOURCE_SHA,installerAuthorized=False,nativeGo=False,hostStage='/same/owned/source')
        retained=dict(state='custodian-complete',stage=request['guestStage'],sha256=TARGET_SHA256,length=stage.TARGET_SIZE,rootNativeId='root-native',targetNativeId='target-native')
        def acl(directory):
            return dict(path=request['guestStage']+(''if directory else r'\vpn-control-2.2.2.msi'),ownerSid='S-1-5-18',protected=directory,acl=[dict(sid=s,rights=r,type='Allow',inherited=not directory,inheritance=3 if directory else 0,propagation=0)for s,r in [('S-1-5-18',2032127),('S-1-5-32-544',2032127),(sid,1179817)]])
        receipt=dict(state='readonly-msi-authored-scope',path=request['guestStage']+r'\vpn-control-2.2.2.msi',rootNativeId='root-native',targetNativeId='target-native',sha256=TARGET_SHA256,length=stage.TARGET_SIZE,databaseMode=0,properties=[dict(name=n,value=v)for n,v in [('ProductName','vpn-control'),('ProductVersion','2.2.2'),('ProductCode','{2D8D2946-3492-3C19-A837-87C54F9311A9}'),('UpgradeCode','{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}')]],directories=[dict(directory='TARGETDIR',parent='',defaultDir='SourceDir'),dict(directory='APPLICATIONFOLDER',parent='TARGETDIR',defaultDir='vpn-control')],componentCount=1,componentGroups=[dict(directory='APPLICATIONFOLDER',attributes=256,count=1)],upgrades=[],rootAcl=acl(True),targetAcl=acl(False),ownerObservation=dict(observerSid='S-1-5-18',interactiveUser='VPNPARITYX64\\parityagent',interactiveSid=sid,session=1,processCensusComplete=True,processCount=130,effectOwners=[],publicOFF='UNRESOLVED'),installerAction=False,productAcceptance=False,publicOFF='UNRESOLVED',installScopeInferred=False)
        return request,retained,receipt

    def test_actual_authored_schema_absent_allusers_grants_no_install_scope(self):
        import copy
        request,retained,receipt=self.fixture()
        self.assertTrue(stage.validate_msi_scope(receipt,request,retained))
        for key,value in [('databaseMode',0.0),('length',float(stage.TARGET_SIZE)),('componentCount',True),('installScopeInferred',True),('targetNativeId','foreign')]:
            with self.subTest(key=key),self.assertRaises(ValueError):stage.validate_msi_scope(dict(receipt,**{key:value}),request,retained)
        for section,key,value in [('componentGroups','attributes',256.0),('componentGroups','count',True),('componentGroups','directory','foreign'),('directories','parent','foreign'),('properties','value','foreign-product')]:
            altered=copy.deepcopy(receipt);altered[section][0][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):stage.validate_msi_scope(altered,request,retained)

    def test_all_actual_table_bounds_and_cell_bound_refuse(self):
        import copy
        request,retained,receipt=self.fixture()
        for key,count in [('properties',129),('directories',129),('componentGroups',65),('upgrades',17)]:
            changed=copy.deepcopy(receipt);row=changed[key][0]if changed[key]else dict(code='',min='',max='',language='',attributes=0,remove='',actionProperty='');changed[key]=[row]*count
            with self.subTest(key=key),self.assertRaises(ValueError):stage.validate_msi_scope(changed,request,retained)
        changed=copy.deepcopy(receipt);changed['directories'][0]['defaultDir']='X'*513
        with self.assertRaises(ValueError):stage.validate_msi_scope(changed,request,retained)
        changed=copy.deepcopy(receipt);changed['properties']+=[dict(name='extra'+str(i),value='X'*512)for i in range(24)]
        with self.assertRaises(ValueError):stage.validate_msi_scope(changed,request,retained)

    def test_complete_ps_factory_is_readonly_and_native_identity_bound(self):
        request,retained,_=self.fixture();corr='e238c623-c733-4d28-bc20-3097c1c4c923'
        script=stage.msi_scope_script(request,retained,corr)
        self.assertIn("$root='"+request['guestStage']+"'",script)
        self.assertIn('$database=$installer.OpenDatabase($target,0)',script)
        self.assertIn('SCOPE_OUTPUT_BOUND',script)
        self.assertNotIn('CreateExclusive($root',script)
        self.assertNotIn('CreateTargetOwned($target',script)
        with self.assertRaises(ValueError):stage.msi_scope_script(request,dict(retained,state='unknown'),corr)


class InstalledDispatchTests(unittest.TestCase):
    @staticmethod
    def fixture():
        import base64,hashlib
        app=r'C:\Users\parityagent\AppData\Local\vpn-control\app'
        cfg=b'[Application]\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\napp.classpath=$APPDIR\\desktop.jar;$APPDIR\\core.jar\n'
        def row(entry,length):return dict(entry=entry,classLength=length,classBase64=base64.b64encode(b'\xca\xfe\xba\xbe'+b'X'*(length-4)).decode())
        paths=[dict(path=app+'\\'+n+'.jar',sha256=str(i+1)*64,nativeId='native-'+n,index=i)for i,n in enumerate(['desktop','core'])]
        jars=[dict(paths[0],classes=[row('com/kardinal/vpncontrol/desktop/'+n+'.class',length)for n,length in [('MainKt',232404),('DesktopCli',25804),('DesktopWorkspacePaths',12369)]]),dict(paths[1],classes=[row('com/kardinal/vpncontrol/control/ControlCliParser.class',21669)])]
        ancestors=['C:\\',r'C:\Users',r'C:\Users\parityagent',r'C:\Users\parityagent\AppData',r'C:\Users\parityagent\AppData\Local',r'C:\Users\parityagent\AppData\Local\vpn-control',app]
        return dict(state='readonly-installed-dispatch',observerSid='S-1-5-18',interactiveSid='S-1-5-21-606332539-4179368406-55829832-1000',session=1,launcherSha256='576f34076f6a96c55d6b3df04264cbd62c096b41e9803cc575ca4c11b196fd88',cfgPath=app+r'\vpn-control-cli.cfg',cfgLength=len(cfg),cfgSha256=hashlib.sha256(cfg).hexdigest(),cfgBase64=base64.b64encode(cfg).decode(),mainClass='com.kardinal.vpncontrol.desktop.MainKt',classpath=paths,jars=jars,nativeRows=[dict(path=p,directory=True,nativeId='directory-'+str(i))for i,p in enumerate(ancestors)]+[dict(path=app+r'\vpn-control-cli.cfg',directory=False,nativeId='cfg'),dict(path=app.rsplit('\\',1)[0]+r'\vpn-control-cli.exe',directory=False,nativeId='cli')]+[dict(path=r['path'],directory=False,nativeId=r['nativeId'])for r in paths],launcherExecuted=False,bytecodeExecuted=False,installerAction=False,publicOFF='UNRESOLVED',productAcceptance=False)

    def test_measured_main_class_size_captured_and_compact_preserves_bytes_binding(self):
        import json,hashlib
        receipt=self.fixture();raw=json.dumps(receipt).encode()
        self.assertTrue(stage.validate_installed_dispatch(receipt))
        compact=stage.compact_installed_dispatch(receipt,raw)
        self.assertEqual(compact['rawSha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(compact['classes'][0]['length'],232404)
        self.assertLess(len(json.dumps(compact)),4096)
        self.assertNotIn('Base64',json.dumps(compact))
        self.assertFalse(compact['launcherExecuted'])

    def test_actual_cfg_binding_rejects_sidecar_shadow_and_malformed_types(self):
        import copy,base64,hashlib
        original=self.fixture()
        for key,value in [('session',True),('cfgLength',float(original['cfgLength'])),('mainClass','foreign.Main'),('launcherExecuted',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):stage.validate_installed_dispatch(dict(original,**{key:value}))
        for section,key,value in [('classpath','index',0.0),('classpath','path',original['classpath'][0]['path'].replace('desktop','sidecar')),('classpath','sha256',1),('jars','index',1)]:
            altered=copy.deepcopy(original);altered[section][0][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):stage.validate_installed_dispatch(altered)
        for member in [b'$APPDIR\\..\\foreign.jar',b'C:\\foreign.jar',b'$APPDIR\\desktop.jar;$APPDIR\\DESKTOP.jar']:
            altered=copy.deepcopy(original);cfg=b'app.mainclass=com.kardinal.vpncontrol.desktop.MainKt\napp.classpath='+member+b'\n';altered.update(cfgLength=len(cfg),cfgSha256=hashlib.sha256(cfg).hexdigest(),cfgBase64=base64.b64encode(cfg).decode())
            with self.subTest(member=member),self.assertRaises(ValueError):stage.validate_installed_dispatch(altered)

    def test_actual_factory_no_bare_scriptblock_and_no_code_execution(self):
        source=stage.installed_cli_dispatch_script()
        self.assertNotIn('   {\n    $zip.Dispose()',source)
        self.assertIn('$zip.Dispose();$zip=$null;$sha=Hash-Stream $s',source)
        self.assertIn('DISPATCH_CLASSES_MISSING_OR_AMBIGUOUS',source)
        self.assertIn('600000',source)
        for forbidden in ['Start-Process','Register-ScheduledTask','java.exe','Set-Acl','CreateExclusive($install']:
            self.assertNotIn(forbidden,source)


class InstalledDispatchTerminalClosingTests(unittest.TestCase):
    @staticmethod
    def run_actual_tail(source,drift,guard_failure=False,preexisting_drift=False,result_override=None):
        import os,json,types,hashlib
        from pathlib import Path
        from agent_tools import windows_parallel_vm_prepare as prepare,windows_parallel_vm_launch as launch,windows_parallel_vm_source_inventory as inventory
        with tempfile.TemporaryDirectory()as tmp:
            journal=Path(tmp);fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY)
            original={'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"bounded":"PUBLIC"}').decode()}if result_override is None else result_override
            prepare.record_at(fd,'probe-terminal.json',original)
            if preexisting_drift:(journal/'probe-terminal.json').write_bytes(b'FOREIGN')
            def record(directory,name,value):
                prepare.record_at(directory,name,value)
                if drift and name=='result.json':
                    with (journal/'probe-terminal.json').open('r+b')as output:output.write(b'FORGED');output.flush();os.fsync(output.fileno())
            def need(ok,reason):
                if not ok:raise ValueError(reason)
            calls=0
            def guard():
                nonlocal calls
                calls+=1
                if guard_failure and calls==2:raise ValueError('tertiary-probe-current')
            namespace=dict(os=os,json=json,hashlib=hashlib,journal=journal,fd=fd,file_hash=launch.file_hash,generation=inventory.generation,need=need,guard=guard,CORRELATION='owned',created={'pid':42},receipt={'bounded':'PUBLIC'},result=original,base64=base64,compact_installed_dispatch=lambda receipt,raw:receipt,installed_dispatch_terminal_diagnostic=stage.installed_dispatch_terminal_diagnostic,prepare=types.SimpleNamespace(record_at=record),value={'state':'unknown'})
            try:
                exec(compile(source,'actual emitted installed terminal tail','exec'),namespace)
                emitted=namespace['value'];result=json.loads((journal/'result.json').read_bytes())if (journal/'result.json').exists()else None
                return emitted,result
            finally:
                if 'terminal_fd'in namespace:os.close(namespace['terminal_fd'])
                os.close(fd)

    def test_actual_emitted_tail_drift_never_keeps_observed_authority(self):
        value,recorded=self.run_actual_tail(stage.installed_dispatch_terminal_tail(),True)
        self.assertEqual(value['state'],'unknown')
        self.assertTrue(value['diagnosticOnly'])
        self.assertNotIn('originalTerminal',value)
        self.assertNotIn('receipt',value)
        self.assertEqual(value['errorDetail'],'tertiary-dispatch-terminal-closing')

    def test_actual_positive_tail_retains_bounded_authenticated_locator(self):
        value,recorded=self.run_actual_tail(stage.installed_dispatch_terminal_tail(),False)
        self.assertEqual(value['state'],'tertiary-actor-observed')
        self.assertEqual(value,recorded)
        self.assertGreater(value['originalTerminal']['pin']['generation'][6],54)

    def test_exact_original_terminal_bytes_and_later_current_guard_are_binding(self):
        value,recorded=self.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,preexisting_drift=True)
        self.assertEqual(value['state'],'unknown');self.assertIsNone(recorded)
        self.assertEqual(value['errorDetail'],'tertiary-dispatch-terminal-content')
        value,recorded=self.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,guard_failure=True)
        self.assertEqual(value['state'],'unknown');self.assertTrue(value['diagnosticOnly'])
        self.assertNotIn('originalTerminal',value);self.assertNotIn('receipt',value)


class NativeInstalledCompressionTests(unittest.TestCase):
    def test_actual_production_preamble_explicitly_loads_ziparchive_assembly(self):
        header=stage.installed_cli_dispatch_script().split('Add-Type -TypeDefinition',1)[0]
        self.assertEqual(header.count('Add-Type -AssemblyName System.IO.Compression\n'),1)
        self.assertIn('Add-Type -AssemblyName System.IO.Compression.FileSystem\n',header)

    @unittest.skipUnless(__import__('os').name=='nt','actual fresh Windows PowerShell assembly resolution required')
    def test_actual_fresh_powershell_old_type_refusal_and_explicit_reference(self):
        import subprocess,json
        header=stage.installed_cli_dispatch_script().split('Add-Type -TypeDefinition',1)[0]
        reference='Add-Type -AssemblyName System.IO.Compression\n'
        self.assertEqual(header.count(reference),1)
        old=header.replace(reference,'',1)
        control=old+"$oldResolved=$false;$oldError=$null;try{$null=[IO.Compression.ZipArchive];$oldResolved=$true}catch{$oldError=$_.FullyQualifiedErrorId};\n"+header+"""
$memory=[IO.MemoryStream]::new();try{
 $writer=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true);$writer.Dispose();$memory.Position=0
 $reader=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Read,$true);try{$emptyRead=($reader.Entries.Count -eq 0);$typeName=$reader.GetType().FullName}finally{$reader.Dispose()}
 [ordered]@{oldResolved=$oldResolved;oldError=$oldError;newReadSucceeded=$emptyRead;typeName=$typeName;memoryOnly=$true}|ConvertTo-Json -Compress
}finally{$memory.Dispose()}
"""
        completed=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',control],capture_output=True,timeout=20,check=True)
        result=json.loads(completed.stdout.decode('utf-8-sig'))
        self.assertIs(type(result['oldResolved']),bool)
        if result['oldResolved']is False:self.assertEqual(result['oldError'],'TypeNotFound')
        self.assertIs(result['newReadSucceeded'],True);self.assertIs(result['memoryOnly'],True)
        self.assertEqual(result['typeName'],'System.IO.Compression.ZipArchive')


class NativeOrderedEntryTests(unittest.TestCase):
    def test_actual_production_ordered_dictionary_entry_projection(self):
        source=stage.installed_cli_dispatch_script()
        self.assertNotIn('Select-Object -ExpandProperty entry',source)
        self.assertIn("ForEach-Object {$_['entry']}",source)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows PowerShell ordered dictionary required')
    def test_actual_old_dictionary_projection_refuses_and_key_lookup_succeeds(self):
        import subprocess,json
        source=stage.installed_cli_dispatch_script()
        line=next(line for line in source.splitlines()if line.strip().startswith('$captured=@('))
        old=line.replace("ForEach-Object {$_['entry']}",'Select-Object -ExpandProperty entry')
        script="$ErrorActionPreference='Stop';$matches=@([ordered]@{classes=@([ordered]@{entry='PUBLIC.Main.class'},[ordered]@{entry='PUBLIC.Parser.class'})});$oldError=$null;try{"+old+"}catch{$oldError=$_.FullyQualifiedErrorId};"+line+";[ordered]@{oldError=$oldError;captured=@($captured)}|ConvertTo-Json -Compress"
        result=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=True)
        row=json.loads(result.stdout.decode('utf-8-sig'))
        self.assertEqual(row['oldError'],'ExpandPropertyNotFound,Microsoft.PowerShell.Commands.SelectObjectCommand')
        self.assertEqual(row['captured'],['PUBLIC.Main.class','PUBLIC.Parser.class'])


class InstalledDispatchFailureDiagnosticTests(unittest.TestCase):
    def test_actual_emitted_nonzero_terminal_is_unknown_with_authenticated_diagnostic(self):
        result={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'PUBLIC measured failure').decode()}
        value,recorded=InstalledDispatchTerminalClosingTests.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,result_override=result)
        self.assertEqual(value['state'],'unknown');self.assertIsNone(recorded)
        self.assertEqual(value['terminalDiagnostic']['guestPid'],42)
        self.assertEqual(value['terminalDiagnostic']['exitcode'],1)
        self.assertIs(value['terminalDiagnostic']['authority'],False)
        self.assertEqual(base64.b64decode(value['terminalDiagnostic']['stderrPrefixBase64']),b'PUBLIC measured failure')
        self.assertNotIn('originalTerminal',value);self.assertNotIn('receipt',value)

    def test_actual_nonzero_terminal_drift_and_substitution_drop_diagnostics(self):
        original={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'PUBLIC').decode()}
        value,_=InstalledDispatchTerminalClosingTests.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,preexisting_drift=True,result_override=original)
        self.assertEqual(value['state'],'unknown');self.assertNotIn('terminalDiagnostic',value)
        self.assertNotIn('originalTerminal',value);self.assertNotIn('receipt',value)

    def test_actual_nonzero_terminal_types_encoding_and_bounds_are_binding(self):
        positive={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'PUBLIC').decode()}
        for changes in [{'exitcode':1.0},{'exitcode':True},{'exited':1},{'err-truncated':1},{'err-data':'!'}, {'err-data':base64.b64encode(b'X'*16385).decode()}]:
            with self.subTest(changes={key:type(value).__name__ for key,value in changes.items()}):
                value,_=InstalledDispatchTerminalClosingTests.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,result_override=dict(positive,**changes))
                self.assertEqual(value['state'],'unknown');self.assertNotIn('terminalDiagnostic',value)
                self.assertNotIn('originalTerminal',value);self.assertNotIn('receipt',value)

    def test_actual_large_stderr_prefix_retains_complete_hash_and_count(self):
        import hashlib
        err=b'PUBLIC'*2000
        original={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(err).decode()}
        value,_=InstalledDispatchTerminalClosingTests.run_actual_tail(stage.installed_dispatch_terminal_tail(),False,result_override=original)
        row=value['terminalDiagnostic']
        self.assertEqual(row['stderrLength'],len(err));self.assertEqual(row['stderrSha256'],hashlib.sha256(err).hexdigest())
        self.assertEqual(base64.b64decode(row['stderrPrefixBase64']),err[:4096])
        self.assertIs(row['continuousCustody'],False);self.assertIs(row['replayAllowed'],False)


class OriginalInstalledStatusTests(unittest.TestCase):
    @staticmethod
    def real_sdk_response(timeout,delay,response):
        import os,json,time,threading
        from pathlib import Path
        from scripts.native_fixture_qga import QgaReadOnlyClient
        operations=[];errors=[]
        with tempfile.TemporaryDirectory()as directory:
            path=str(Path(directory)/'q.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(path);listener.listen(1)
            def serve():
                try:
                    connection,_=listener.accept()
                    with connection:
                        def line():
                            data=bytearray()
                            while not data.endswith(b'\n'):
                                part=connection.recv(1)
                                if not part:raise EOFError('test client closed')
                                data.extend(part)
                            return bytes(data)
                        sync=json.loads(line().lstrip(b'\xff'));operations.append(sync['execute'])
                        connection.sendall(b'\xff'+json.dumps({'return':sync['arguments']['id']}).encode()+b'\n')
                        operation=json.loads(line());operations.append(operation)
                        time.sleep(delay)
                        try:connection.sendall(response)
                        except BrokenPipeError:pass
                except BaseException as error:errors.append(error)
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            client=QgaReadOnlyClient(path,timeout_seconds=timeout,max_response_bytes=1048576)
            try:
                result=client.guest_exec_status(42)if timeout==3 else stage.observe_installed_dispatch_original_status(client,{'pid':42},lambda:None)
                return result,operations
            finally:
                thread.join(5);listener.close()
                if thread.is_alive():raise AssertionError('test server remained live')
                if errors:raise errors[0]

    def test_real_sdk_delayed_complete_response_old_unknown_new_bounded_status(self):
        import json
        from scripts.native_fixture_qga import QgaObservationUnknown
        terminal={'exited':True,'exitcode':0,'out-data':base64.b64encode(b'PUBLIC'*60000).decode(),'err-data':''}
        response=json.dumps({'return':terminal}).encode()+b'\n'
        with self.assertRaises(QgaObservationUnknown):self.real_sdk_response(3,3.2,response)
        result,ops=self.real_sdk_response(15,3.2,response)
        self.assertEqual(result,terminal)
        self.assertEqual(ops,['guest-sync-delimited',{'execute':'guest-exec-status','arguments':{'pid':42}}])

    def test_actual_status_factory_refuses_pid_types_malformed_and_never_replays(self):
        class Client:
            timeout_seconds=15;max_response_bytes=1048576
            def __init__(self,result):self.result=result;self.calls=[]
            def guest_exec_status(self,pid):self.calls.append(pid);return self.result
        for pid in [True,42.0,-1,0,'42']:
            client=Client({'exited':False})
            with self.assertRaises(ValueError):stage.observe_installed_dispatch_original_status(client,{'pid':pid},lambda:None)
            self.assertEqual(client.calls,[])
        for result in [{'exited':1},{'exited':True,'exitcode':True},{'exited':True,'exitcode':1.0},None]:
            client=Client(result)
            with self.assertRaises(ValueError):stage.observe_installed_dispatch_original_status(client,{'pid':42},lambda:None)
            self.assertEqual(client.calls,[42])
        client=Client({'exited':False})
        self.assertEqual(stage.observe_installed_dispatch_original_status(client,{'pid':42},lambda:None),{'exited':False})
        self.assertEqual(client.calls,[42])

    def test_real_sdk_incomplete_response_and_malformed_are_not_replayed(self):
        from scripts.native_fixture_qga import QgaObservationUnknown,QgaProtocolError
        with self.assertRaises(QgaObservationUnknown):self.real_sdk_response(15,0,b'{')
        with self.assertRaises(QgaProtocolError):self.real_sdk_response(15,0,b'FOREIGN\n')


class InstalledFixtureContextTests(unittest.TestCase):
    @staticmethod
    def receipt():
        request,retained,scope=AuthoredMsiScopeTests.fixture()
        code='{87F491A1-A193-3271-8AE2-C0877718FAB0}'
        product=dict(productCode=code,context=4,sid='',name='vpn-control',version='2.1.8',assignmentType=dict(available=True,returnCode=0,value='1',legacyRejected=False),installLocation=r'C:\Users\parityagent\AppData\Local\vpn-control',state='5',path=r'C:\Windows\Installer\public.msi',sha256='a'*64,length=4096,nativeId='native-cache-id',properties=[dict(name='ProductCode',value=code),dict(name='ProductVersion',value='2.1.8'),dict(name='ProductName',value='vpn-control'),dict(name='UpgradeCode',value='{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}')],databaseMode=0)
        receipt=dict(state='readonly-tertiary-install-context',observerSid='S-1-5-18',ownerObservation=scope['ownerObservation'],enumerated=1,products=[product],statePresence=[dict(path=r'C:\Users\parityagent\.vpn-control-desktop',exists=False),dict(path=r'C:\Users\parityagent\AppData\Local\Temp\vpn-control-tertiary-scenarios',exists=False)],targetRootNativeId=retained['rootNativeId'],targetNativeId=retained['targetNativeId'],targetSha256=request['targetSha256'],targetLength=stage.TARGET_SIZE,rootAcl=scope['rootAcl'],targetAcl=scope['targetAcl'],installerAction=False,productAcceptance=False,publicOFF='UNRESOLVED',installAdmitted=False)
        return request,retained,receipt

    def test_machine_or_foreign_user_context_remains_observation_not_admission(self):
        import copy
        request,retained,receipt=self.receipt()
        self.assertTrue(stage.validate_installed_fixture_context(receipt,request,retained));self.assertIs(receipt['installAdmitted'],False)
        user=copy.deepcopy(receipt);user['products'][0].update(context=2,sid='S-1-5-21-1-2-3-9999',assignmentType=dict(available=True,returnCode=0,value='0',legacyRejected=False))
        self.assertTrue(stage.validate_installed_fixture_context(user,request,retained));self.assertIs(user['installAdmitted'],False)

    def test_exact_context_types_scope_cached_properties_and_owned_state_are_binding(self):
        import copy
        request,retained,receipt=self.receipt()
        for key,value in [('context',4.0),('context',True),('context',7),('sid','S-1-5-18'),('assignmentType','0'),('length',4096.0),('length',True),('databaseMode',False),('path',r'C:\foreign.msi'),('sha256','foreign'),('productCode','{'+('-'*36)+'}')]:
            changed=copy.deepcopy(receipt);changed['products'][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):stage.validate_installed_fixture_context(changed,request,retained)
        for key,value in [('targetLength',stage.TARGET_SIZE*1.0),('enumerated',True),('installAdmitted',True)]:
            changed=copy.deepcopy(receipt);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):stage.validate_installed_fixture_context(changed,request,retained)
        changed=copy.deepcopy(receipt);changed['products'][0]['properties'][0]['value']='foreign'
        with self.assertRaises(ValueError):stage.validate_installed_fixture_context(changed,request,retained)
        changed=copy.deepcopy(receipt);changed['statePresence'][0]['exists']=0
        with self.assertRaises(ValueError):stage.validate_installed_fixture_context(changed,request,retained)

    def test_actual_context_factory_reuses_exact_readonly_target_prefix(self):
        request,retained,receipt=self.receipt()
        source=stage.installed_fixture_context_script(request,retained,request['correlation'])
        self.assertEqual(source.count(stage.INSTALLED_CONTEXT_CS),1)
        self.assertEqual(source.split(stage.INSTALLED_CONTEXT_PS.split('__EXACT_CONTEXT_CS__')[0],1)[0],stage.msi_scope_script(request,retained,request['correlation']).split(stage.MSI_SCOPE_PS,1)[0])
        self.assertNotIn('Win32_Product',source);self.assertNotIn('Start-Process',source);self.assertNotIn('Set-Acl',source)
        self.assertIn('$installer.OpenDatabase($cache,0)',source)
        self.assertIn('$propertyCount -ge 128',source)


class OptionalAssignmentTypeTests(unittest.TestCase):
    def test_actual_context_receipt_unknown_property_is_typed_not_defaulted(self):
        request,retained,receipt=InstalledFixtureContextTests.receipt()
        receipt['products'][0]['assignmentType']=dict(available=False,returnCode=1608,value=None,legacyRejected=True)
        self.assertTrue(stage.validate_installed_fixture_context(receipt,request,retained))
        self.assertEqual(receipt['products'][0]['context'],4);self.assertIs(receipt['installAdmitted'],False)

    def test_optional_property_malformed_and_other_errors_refuse(self):
        import copy
        request,retained,receipt=InstalledFixtureContextTests.receipt()
        valid=dict(available=False,returnCode=1608,value=None,legacyRejected=True)
        for key,value in [('returnCode',1608.0),('returnCode',True),('returnCode',1605),('available',0),('available',True),('value','0'),('legacyRejected',False),('legacyRejected',1)]:
            with self.subTest(key=key,value=value):
                bad=copy.deepcopy(receipt);bad['products'][0]['assignmentType']=dict(valid,**{key:value})
                with self.assertRaises(ValueError):stage.validate_installed_fixture_context(bad,request,retained)
        missing=copy.deepcopy(receipt);missing['products'][0]['assignmentType']=dict(available=True,returnCode=0,value=None,legacyRejected=False)
        with self.assertRaises(ValueError):stage.validate_installed_fixture_context(missing,request,retained)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows MSI property API and C# projection required')
    def test_actual_native_property_control_and_optional_projection(self):
        import subprocess,json
        script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'\n"+stage.INSTALLED_CONTEXT_CS+"\n'@ -ReferencedAssemblies @('System','System.Core');\n"+r"""
$control=[TertiaryInstalledContext]::ControlFirstMachineAssignment()
if($null -eq $control){[Console]::Out.WriteLine('{"noMachineProduct":true}');exit 0}
$public=[TertiaryInstalledContext]::ProjectAssignment(1608,$null)
$hardRefused=$false;try{$null=[TertiaryInstalledContext]::ProjectAssignment(1605,$null)}catch{$hardRefused=$true}
[ordered]@{control=$control;publicUnknownProperty=$public;otherCodeRefused=$hardRefused}|ConvertTo-Json -Depth 5 -Compress
"""
        completed=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=True)
        row=json.loads(completed.stdout.decode('utf-8-sig'))
        if row.get('noMachineProduct')is True:self.skipTest('native machine MSI catalog has no product')
        self.assertIs(row['otherCodeRefused'],True)
        self.assertEqual(row['publicUnknownProperty'],dict(available=False,returnCode=1608,value=None,legacyRejected=False))
        field=row['control']
        self.assertIs(type(field['available']),bool);self.assertIs(type(field['returnCode']),int)
        if field['returnCode']==1608:self.assertIs(field['available'],False);self.assertIs(field['value'],None);self.assertIs(field['legacyRejected'],True)
        else:self.assertEqual(field['returnCode'],0);self.assertIs(field['available'],True);self.assertIn(field['value'],['0','1']);self.assertIs(field['legacyRejected'],False)


class CachedContextPathCaseTests(unittest.TestCase):
    # Exact native observed operand from original8140, source metadata only.
    OBSERVED=r'C:\WINDOWS\Installer\1c98ca4.msi'

    def test_actual_emitted_guard_accepts_observed_uppercase_and_refuses_foreign(self):
        import re
        operator,pattern=re.search(r"\$cache (-cnotmatch|-notmatch) '([^']+)'",stage.INSTALLED_CONTEXT_PS).groups()
        flags=0 if operator=='-cnotmatch' else re.IGNORECASE|re.ASCII
        self.assertIsNotNone(re.fullmatch(pattern,self.OBSERVED,flags))
        for path in [r'C:\Windows\InstallerBackup\1c98ca4.msi',r'C:\Windows\Installer\..\foreign.msi',r'C:\\Windows\\Installer\\1c98ca4.msi',r'D:\WINDOWS\Installer\1c98ca4.msi',r'C:\WİNDOWS\Installer\1c98ca4.msi']:
            with self.subTest(path=path):self.assertIsNone(re.fullmatch(pattern,path,flags))

    def test_actual_context_schema_accepts_observed_case_without_scope_inference(self):
        request,retained,receipt=InstalledFixtureContextTests.receipt();receipt['products'][0]['path']=self.OBSERVED
        self.assertTrue(stage.validate_installed_fixture_context(receipt,request,retained))
        self.assertIs(receipt['installAdmitted'],False)
        receipt['products'][0]['path']=r'C:\WİNDOWS\Installer\1c98ca4.msi'
        with self.assertRaises(ValueError):stage.validate_installed_fixture_context(receipt,request,retained)

    @unittest.skipUnless(__import__('os').name=='nt','actual emitted PowerShell path predicate required')
    def test_actual_native_uppercase_old_refusal_and_current_guard(self):
        import re,subprocess,json
        operator,pattern=re.search(r"\$cache (-cnotmatch|-notmatch) '([^']+)'",stage.INSTALLED_CONTEXT_PS).groups()
        script="$ErrorActionPreference='Stop';$path='"+self.OBSERVED+"';$pattern='"+pattern+"';[ordered]@{oldRefused=($path -cnotmatch $pattern);currentRefused=($path "+operator+" $pattern);foreignRefused=('C:\\foreign.msi' "+operator+" $pattern)}|ConvertTo-Json -Compress"
        completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=10,check=True)
        self.assertEqual(json.loads(completed.stdout.decode('utf-8-sig')),dict(oldRefused=True,currentRefused=False,foreignRefused=True))


class NativeFixtureProcessTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name=='nt','actual Windows original process handle and token required')
    def test_original_handle_retains_birth_after_fast_exit_and_bounds_stream(self):
        import subprocess,json,hashlib
        script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'\n"+stage.FIXTURE_PROCESS_CS+"\n'@ -ReferencedAssemblies @('System','System.Core');\n"+r"""
$process=New-Object Diagnostics.Process
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName='C:\Windows\System32\cmd.exe';$info.Arguments='/d /c exit 7';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$process.StartInfo=$info
try{
 if(-not $process.Start()){throw 'PUBLIC_PROCESS_START'}
 $originalHandle=$process.Handle;$originalPid=$process.Id
 if(-not $process.WaitForExit(5000)){throw 'PUBLIC_PROCESS_DEADLINE'}
 $birth=[TertiaryFixtureProcess]::Birth($originalHandle)
 $input=New-Object IO.MemoryStream(,[Text.Encoding]::ASCII.GetBytes('PUBLIC-PUBLIC'))
 $retained=New-Object IO.MemoryStream
 try{$drain=[TertiaryFixtureProcess]::StartDrain($input,$retained,6).Result;$prefix=[Text.Encoding]::ASCII.GetString($retained.ToArray())}finally{$input.Dispose();$retained.Dispose()}
 [ordered]@{pid=$originalPid;birth=$birth;exitCode=$process.ExitCode;birthAfterTerminal=([TertiaryFixtureProcess]::Birth($originalHandle));elevated=[TertiaryFixtureProcess]::Elevated([Security.Principal.WindowsIdentity]::GetCurrent().Token);drain=$drain;prefix=$prefix}|ConvertTo-Json -Depth 5 -Compress
}finally{$process.Dispose()}
"""
        completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=15,check=True)
        row=json.loads(completed.stdout.decode('utf-8-sig'))
        self.assertIs(type(row['pid']),int);self.assertGreater(row['pid'],0)
        self.assertIs(type(row['birth']),int);self.assertGreater(row['birth'],0);self.assertEqual(row['birth'],row['birthAfterTerminal'])
        self.assertEqual(row['exitCode'],7);self.assertIs(type(row['elevated']),bool)
        self.assertEqual(row['drain'],dict(bytes=13,retainedBytes=6,sha256=hashlib.sha256(b'PUBLIC-PUBLIC').hexdigest()))
        self.assertEqual(row['prefix'],'PUBLIC')


class FixtureProvisionFlowTests(unittest.TestCase):
    @staticmethod
    def flow():
        import gzip,base64,re
        request,retained,_=AuthoredMsiScopeTests.fixture()
        corr='11111111-2222-3333-4444-555555555555'
        carrier,body,binding=stage.fixture_provision_script(request,retained,corr)
        encoded=re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)",carrier).group(1)
        source=gzip.decompress(base64.b64decode(encoded)).decode('utf-8')
        return carrier,source,body,binding

    def test_whole_fixed_flow_fits_windows_and_authenticates_public_source(self):
        import re,hashlib,gzip,base64
        carrier,source,body,binding=self.flow()
        self.assertGreater(len(source),32767)
        self.assertLess(len(carrier.encode('utf-16-le'))//2+160,32767)
        self.assertIn(hashlib.sha256(source.encode()).hexdigest(),carrier)
        self.assertEqual(hashlib.sha256(body.encode()).hexdigest(),binding['bodySha256'])
        self.assertEqual(binding['privateRoot'],r'C:\ProgramData\VpnControlTertiaryProvision-'+binding['correlation'])
        encoded=re.search(r"\$bodyGzip='([A-Za-z0-9+/=]+)'",source).group(1)
        self.assertEqual(gzip.decompress(base64.b64decode(encoded)),body.encode())
        self.assertNotIn('__PRIVATE',source);self.assertNotIn('__BODY',source)
        self.assertNotIn('ALLUSERS=',body);self.assertNotIn('MSIINSTALLPERUSER=',body)
        for invalid in ('',None,'foreign'):
            with self.assertRaises(ValueError):stage.fixture_powershell_carrier(invalid if invalid!='foreign'else 'a'*98305)

    @staticmethod
    def receipt():
        import hashlib
        _,_,_,b=FixtureProvisionFlowTests.flow();sid=b['sid'];birth=639268599999999999;nid='1:2:3:4:5:6';sha=hashlib.sha256(b'PUBLIC').hexdigest()
        body=dict(correlation=b['correlation'],bodyPid=30,bodyBirth=birth,bodySha256=b['bodySha256'],sid=sid,session=1,limited=True,desktopFolder=r'C:\Users\parityagent\Desktop',programsFolder=r'C:\Users\parityagent\AppData\Roaming\Microsoft\Windows\Start Menu\Programs',replayAllowed=False)
        started=dict(correlation=b['correlation'],bodyPid=30,bodyBirth=birth,bodySha256=b['bodySha256'],originalPid=42,originalBirth=birth+1,replayAllowed=False)
        terminal=dict(started,sid=sid,session=1,packageSha256=b['targetSha256'],exitCode=0,stdout=dict(bytes=6,retainedBytes=6,sha256=sha),stderr=dict(bytes=0,retainedBytes=0,sha256=hashlib.sha256(b'').hexdigest()),logLength=6,logSha256=sha,logNativeId=nid)
        def record(role,value):return dict(value=value,path=b['privateRoot']+'\\'+role+'.json',nativeId=nid,sha256=sha,length=100)
        files=[dict(path='vpn-control/public-'+str(i),sizeBytes=6,sha256=sha)for i in range(209)]
        cat=dict(targetMsiSha256=b['targetSha256'],targetMsiBytes=b['targetSize'],fileCount=209,property=dict(ProductCode=b['targetProductCode']),propertyPresence={'ALLUSERS':dict(present=False,value=None),'MSIINSTALLPERUSER':dict(present=False,value=None)},files=files)
        image=dict(root=r'C:\Users\parityagent\AppData\Local\vpn-control',files=[dict(path=x['path'].removeprefix('vpn-control/'),length=6,sha256=sha,nativeId=nid)for x in files],directories=[dict(path='',nativeId=nid,members=['public-'+str(i)for i in range(209)])],fullHash=True,nativeReadCustody=True,launchExecuted=False)
        links=[dict(path=folder+'\\'+name+'.lnk',target=image['root']+'\\'+name+'.exe',arguments='',workingDirectory=image['root'],length=6,sha256=sha,nativeId=nid)for folder in (body['desktopFolder'],body['programsFolder']+'\\VPN Control')for name in ('vpn-control','vpn-control-cli')]
        row=dict(state='original-fixture-installer-terminal',correlation=b['correlation'],root=b['privateRoot'],rootNativeId=nid,taskName='VpnControlTertiaryFixture-'+b['correlation'],fixtureProvision=True,installerAction=True,productAcceptance=False,replayAllowed=False,fullInstalledImageVerified=False,taskStarted=True,taskState='Ready',failure=None,bodyStarted=record('body-started',body),installerStarted=record('started',started),terminal=record('terminal',terminal),preCatalogue=[dict(ProductCode=b['oldProductCode'],Context=2,Sid=sid)],postCatalogue=[dict(ProductCode=b['targetProductCode'],Context=2,Sid=sid)],postEffects=[],postSelected=[dict(ProductCode=b['targetProductCode'],Context=2,Sid=sid,Version='2.2.2',State='5',InstallLocation=image['root']+chr(92))],postImage=image,postState=[dict(path=r'C:\Users\parityagent\.vpn-control-desktop',exists=False),dict(path=r'C:\Users\parityagent\AppData\Local\Temp\vpn-control-tertiary-scenarios',exists=False)],postRegistry=dict(hive='HKEY_USERS',sid=sid,key=r'Software\Kardinal\vpn-control\2.2.2',name='ProductCode',value=b['targetProductCode'],kind='String'),postShortcuts=links)
        return row,b,cat

    def test_exact_image_catalogue_and_original_process_typed_receipt(self):
        import copy
        row,b,cat=self.receipt();self.assertTrue(stage.validate_fixture_provision(row,b,cat));self.assertIs(stage.validate_fixture_provision(row,b,None),False)
        for field,value in [('originalPid',42.0),('originalPid',True),('originalBirth',float(row['terminal']['value']['originalBirth'])),('exitCode',False)]:
            bad=copy.deepcopy(row);bad['terminal']['value'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):stage.validate_fixture_provision(bad,b,cat)
        for edit in ('file-hash','duplicate-file','foreign-product','machine-context','state-created','foreign-registry','bad-shortcut','live-owner','directory-membership'):
            bad=copy.deepcopy(row)
            if edit=='file-hash':bad['postImage']['files'][0]['sha256']='0'*64
            if edit=='duplicate-file':bad['postImage']['files'][0]=bad['postImage']['files'][1]
            if edit=='foreign-product':bad['postCatalogue'].append(dict(ProductCode='{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}',Context=4,Sid=''))
            if edit=='machine-context':bad['postCatalogue'][0].update(Context=4,Sid='')
            if edit=='state-created':bad['postState'][0]['exists']=True
            if edit=='foreign-registry':bad['postRegistry']['sid']='S-1-5-18'
            if edit=='bad-shortcut':bad['postShortcuts'][0]['target']='foreign.exe'
            if edit=='live-owner':bad['postEffects']=[dict(pid=1,name='vpn-control.exe')]
            if edit=='directory-membership':bad['postImage']['directories'][0]['members'].append('foreign.txt')
            with self.subTest(edit=edit),self.assertRaises(ValueError):stage.validate_fixture_provision(bad,b,cat)
        row['terminal']['value']['exitCode']=3010;self.assertIs(stage.validate_fixture_provision(row,b,cat),False)
        row['state']='UNKNOWN';self.assertIs(stage.validate_fixture_provision(row,b,cat),False)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows in-memory carrier and full PowerShell parser required')
    def test_actual_native_carrier_and_complete_flow_parser_without_effects(self):
        import subprocess,json,base64
        carrier,source,body,_=self.flow()
        public="[Console]::Out.WriteLine('PUBLIC')"
        command=stage.fixture_powershell_carrier(public)
        completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],capture_output=True,timeout=15,check=True)
        self.assertEqual(completed.stdout.decode('utf-8-sig').strip(),'PUBLIC')
        import hashlib
        bad=command.replace(hashlib.sha256(public.encode()).hexdigest(),'0'*64)
        refused=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',bad],capture_output=True,timeout=15)
        self.assertNotEqual(refused.returncode,0);self.assertNotIn(b'PUBLIC',refused.stdout)
        # Parse the actual complete scripts in memory, without evaluating their AST.
        scripts=base64.b64encode(json.dumps([source,body]).encode()).decode()
        parser="$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+scripts+"'))|ConvertFrom-Json;$counts=@();foreach($text in $s){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);$counts+=@($errors.Count);if($errors.Count){throw ($errors|Out-String)}};$counts|ConvertTo-Json -Compress"
        checked=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',stage.fixture_powershell_carrier(parser)],capture_output=True,timeout=20,check=True)
        self.assertEqual(json.loads(checked.stdout.decode('utf-8-sig')),[0,0])


class FixtureProvisionStateBooleanTests(unittest.TestCase):
    def test_integer_zero_cannot_claim_absent_original_settings(self):
        row,b,cat=FixtureProvisionFlowTests.receipt()
        row['postState'][0]['exists']=0
        with self.assertRaises(ValueError):stage.validate_fixture_provision(row,b,cat)


class NativeFixtureImageMembershipTests(unittest.TestCase):
    @unittest.skipUnless(__import__('os').name=='nt','actual emitted Windows native directory-sharing/membership control required')
    def test_actual_identity_only_old_guard_allows_new_child_and_membership_refuses(self):
        import subprocess,json,re
        old=re.search(r" foreach\(\$directory in \$directoryRows\)\{\[TertiaryPrivateStage\]::Match\([^\n]+",stage.FIXTURE_POST_IMAGE_PS).group(0)
        script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'\n"+stage.PRIVATE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core');\n"+stage.FIXTURE_IMAGE_MEMBERSHIP_PS+r"""
$installRoot=Join-Path ([IO.Path]::GetTempPath()) ('vpn-tertiary-membership-'+[Guid]::NewGuid().ToString())
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
[TertiaryPrivateStage]::CreateExclusive($installRoot,('O:'+ $sid+'G:'+ $sid+'D:P(A;OICI;FA;;;'+$sid+')'))
$h=$null
try{
 $h=[TertiaryPrivateStage]::Hold($installRoot,$true);$id=[TertiaryPrivateStage]::Pin($h,$true)
 $directoryRows=@([ordered]@{path='';fullPath=$installRoot;nativeId=$id;handle=$h;members=@([IO.Directory]::GetFileSystemEntries($installRoot))})
 Assert-FixtureImageMembership
 [IO.File]::WriteAllText((Join-Path $installRoot 'foreign.txt'),'PUBLIC')
 $oldRejected=$false;try{__OLD_GUARD__}catch{$oldRejected=$true}
 $newRejected=$false;try{Assert-FixtureImageMembership}catch{if($_.Exception.Message -cne 'FIXTURE_IMAGE_MEMBERSHIP'){throw};$newRejected=$true}
 [ordered]@{oldRejected=$oldRejected;newRejected=$newRejected;identityUnchanged=([TertiaryPrivateStage]::Pin($h,$true) -ceq $id)}|ConvertTo-Json -Compress
}finally{if($h){$h.Dispose()};[IO.Directory]::Delete($installRoot,$true)}
"""
        script=script.replace('__OLD_GUARD__',old,1)
        completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=True)
        self.assertEqual(json.loads(completed.stdout.decode('utf-8-sig')),dict(oldRejected=False,newRejected=True,identityUnchanged=True))


class FixtureAuthoredEmptyDirectoryTests(unittest.TestCase):
    def test_exact_authored_empty_resources_is_in_expected_footprint(self):
        row,b,cat=FixtureProvisionFlowTests.receipt()
        cat['authoredEmptyDirectories']=['app/resources']
        row['postImage']['directories'][0]['members'].append('app')
        row['postImage']['directories']+= [dict(path='/app',nativeId='1:2:3:4:5:6',members=['resources']),dict(path='/app/resources',nativeId='1:2:3:4:5:6',members=[])]
        self.assertTrue(stage.validate_fixture_provision(row,b,cat))


class FixtureCarrierScopeTests(unittest.TestCase):
    def test_authenticated_complete_source_uses_current_script_scope(self):
        carrier=stage.fixture_powershell_carrier("$holders=@();$script:holders+=@('PUBLIC')")
        self.assertIn(";. ([ScriptBlock]::Create($utf8.GetString($r)))",carrier)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows PowerShell scope semantics required')
    def test_actual_carrier_old_child_scope_red_and_dot_source_green(self):
        import subprocess,json,re
        function=re.search(r" function Hold-ContextPath\([^\n]+\)\{\n.*?\n \}",stage.INSTALLED_CONTEXT_PS,re.S).group(0)
        primitive="""$holders=@();$rows=@();
Add-Type -TypeDefinition 'public static class TertiaryPrivateStage { public static object Hold(string p,bool d){return p;} public static string Pin(object h,bool d){return h.ToString();} }'
"""+function+"""
foreach($path in @('PUBLIC-A','PUBLIC-B','PUBLIC-C')){$null=Hold-ContextPath $path $true}
[ordered]@{localCount=$holders.Count;scriptCount=$script:holders.Count}|ConvertTo-Json -Compress
"""
        fixed=stage.fixture_powershell_carrier(primitive)
        self.assertIn(";. ([ScriptBlock]::Create",fixed)
        old=fixed.replace(";. ([ScriptBlock]::Create",";& ([ScriptBlock]::Create",1)
        rows=[]
        for carrier in (old,fixed):
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',carrier],capture_output=True,timeout=15,check=True)
            rows.append(json.loads(result.stdout.decode('utf-8-sig')))
        self.assertEqual(rows[0],{'localCount':0,'scriptCount':3})
        self.assertEqual(rows[1],{'localCount':3,'scriptCount':3})


class FixedSystemInstallerRoleTests(unittest.TestCase):
    def test_fixed_system_role_does_not_change_private_single_link_guard(self):
        self.assertIn('(!directory&&i.Links!=1)',stage.PRIVATE_CS)
        self.assertIn(r'C:\Windows\System32\msiexec.exe',stage.SYSTEM_INSTALLER_CS)
        self.assertIn('i.Links!=2',stage.SYSTEM_INSTALLER_CS)
        self.assertIn('CreateFile(SystemPath,0x80000000,1',stage.SYSTEM_INSTALLER_CS)
        self.assertNotIn('public static SafeFileHandle Hold(string',stage.SYSTEM_INSTALLER_CS)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows hardlinks/native handles required')
    def test_actual_private_single_link_red_fixed_system_role_green(self):
        import subprocess,json,tempfile,pathlib
        with tempfile.TemporaryDirectory(prefix='vpn-control-system-role-')as temp:
            path=str(pathlib.PureWindowsPath(temp)/'msiexec.exe')
            alias=str(pathlib.PureWindowsPath(temp)/'PUBLIC-alias.bin')
            third=str(pathlib.PureWindowsPath(temp)/'PUBLIC-third.bin')
            source=stage.SYSTEM_INSTALLER_CS.replace(r'C:\Windows\System32\msiexec.exe',path)
            self.assertNotEqual(source,stage.SYSTEM_INSTALLER_CS)
            wrong_source=source.replace('TertiarySystemInstaller','TertiarySystemInstallerWrongRole').replace(path,str(pathlib.PureWindowsPath(temp)/'foreign.exe'))
            junction=str(pathlib.PureWindowsPath(temp)/'reparse'/'msiexec.exe')
            reparse_source=source.replace('TertiarySystemInstaller','TertiarySystemInstallerReparse').replace(path,junction)
            script="$ErrorActionPreference='Stop';Add-Type -TypeDefinition @'\n"+stage.PRIVATE_CS+"\n'@;Add-Type -TypeDefinition @'\n"+source+"\n'@;Add-Type -TypeDefinition @'\n"+wrong_source+"\n'@;Add-Type -TypeDefinition @'\n"+reparse_source+"\n'@;\n"+r"""
$path='__PATH__';$alias='__ALIAS__';$third='__THIRD__';[IO.File]::WriteAllBytes($path,[Text.Encoding]::ASCII.GetBytes('PUBLIC'))
New-Item -ItemType HardLink -Path $alias -Target $path -ErrorAction Stop|Out-Null
$wrongRoleRefused=$false;try{$wrong=[TertiarySystemInstallerWrongRole]::Hold();$wrong.Dispose()}catch{$wrongRoleRefused=$_.Exception.Message -match 'SYSTEM_INSTALLER_FIXED_ROLE_PATH'}
$junction='__JUNCTION__';$null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($junction));$null=New-Item -ItemType Junction -Path $junction -Target ([IO.Path]::GetDirectoryName($path));$reparseObserved=(([IO.File]::GetAttributes($junction) -band 0x400) -ne 0);$reparseRefused=$false;try{$reparse=[TertiarySystemInstallerReparse]::Hold();$reparse.Dispose()}catch{$reparseRefused=$_.Exception.Message -match 'SYSTEM_INSTALLER_NATIVE_IDENTITY'}
$oldRefused=$false;$h=$null
try{try{$old=[TertiaryPrivateStage]::Hold($path,$false);$old.Dispose()}catch{$oldRefused=$_.Exception.Message -match 'TERTIARY_NATIVE_IDENTITY'}
 $h=[TertiarySystemInstaller]::Hold();$nativeId=[TertiarySystemInstaller]::Pin($h);[TertiarySystemInstaller]::Match($h,$nativeId)
 $thirdCreated=$false;$thirdError=$null
 try{New-Item -ItemType HardLink -Path $third -Target $path -ErrorAction Stop|Out-Null;$thirdCreated=$true}catch{$thirdError=[string]$_.Exception.Message}
 $heldClosingRefused=$false;try{[TertiarySystemInstaller]::Match($h,$nativeId)}catch{$heldClosingRefused=$true}
 if($thirdCreated -and -not $heldClosingRefused){throw 'PUBLIC_CHANGED_LINK_NOT_REFUSED'}
 if(-not $thirdCreated -and $heldClosingRefused){throw 'PUBLIC_UNCHANGED_LINK_REFUSED'}
 $h.Dispose();$h=$null
 if(-not $thirdCreated){New-Item -ItemType HardLink -Path $third -Target $path -ErrorAction Stop|Out-Null}
 $changedRefused=$false;try{$next=[TertiarySystemInstaller]::Hold();$next.Dispose()}catch{$changedRefused=$_.Exception.Message -match 'SYSTEM_INSTALLER_NATIVE_IDENTITY'}
 [ordered]@{oldRefused=$oldRefused;fixedReturned=($null -ne $nativeId);changedRefused=$changedRefused;wrongRoleRefused=$wrongRoleRefused;reparseObserved=$reparseObserved;reparseRefused=$reparseRefused;thirdCreatedWhileHeld=$thirdCreated;thirdError=$thirdError;heldClosingRefused=$heldClosingRefused}|ConvertTo-Json -Compress
}finally{if($h){$h.Dispose()}}
""".replace('__PATH__',path).replace('__ALIAS__',alias).replace('__THIRD__',third).replace('__JUNCTION__',junction)
            completed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=20,check=True)
            row=json.loads(completed.stdout.decode('utf-8-sig'));self.assertIs(row['oldRefused'],True);self.assertIs(row['fixedReturned'],True);self.assertIs(row['changedRefused'],True);self.assertIs(row['wrongRoleRefused'],True);self.assertIs(row['reparseObserved'],True);self.assertIs(row['reparseRefused'],True);self.assertIs(type(row['thirdCreatedWhileHeld']),bool);self.assertEqual(row['heldClosingRefused'],row['thirdCreatedWhileHeld']);self.assertEqual(row['thirdError']is None,row['thirdCreatedWhileHeld'])


class FixtureTaskTriggerTests(unittest.TestCase):
    def test_guard_excludes_null_but_retains_real_triggers(self):
        self.assertIn('@($t.Triggers | Where-Object {$null -ne $_}).Count -ne 0',stage.FIXTURE_BOOTSTRAP_PS)

    @unittest.skipUnless(__import__('os').name=='nt','actual Windows PowerShell trigger collection required')
    def test_actual_null_trigger_old_count_red_filtered_count_green(self):
        import subprocess,json
        expression='@($t.Triggers | Where-Object {$null -ne $_}).Count'
        self.assertEqual(stage.FIXTURE_BOOTSTRAP_PS.count(expression+" -ne 0"),1)
        old='@($t.Triggers).Count'
        script="$ErrorActionPreference='Stop';"+r"""
$cases=@([ordered]@{name='null';value=$null},[ordered]@{name='empty';value=@()},[ordered]@{name='one';value=@([pscustomobject]@{Kind='PUBLIC-one'})},[ordered]@{name='two';value=@([pscustomobject]@{Kind='PUBLIC-one'},[pscustomobject]@{Kind='PUBLIC-two'})},[ordered]@{name='mixed';value=@($null,[pscustomobject]@{Kind='PUBLIC-one'})})
$rows=@();foreach($case in $cases){$t=[pscustomobject]@{Triggers=$case.value};$rows+=@([ordered]@{name=$case.name;oldCount=__OLD__;newCount=__NEW__})}
$rows|ConvertTo-Json -Compress
""".replace('__OLD__',old).replace('__NEW__',expression)
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=15,check=True)
        self.assertEqual(json.loads(result.stdout.decode('utf-8-sig')),[dict(name=n,oldCount=a,newCount=b)for n,a,b in [('null',1,0),('empty',0,0),('one',1,1),('two',2,2),('mixed',2,1)]])


class FixtureRecoveryStreamTests(unittest.TestCase):
    OLD_READ = "$sha=Hash-ContextStream $r;$bytes=New-Object byte[] ([int]$r.Length);$offset=0;while($offset -lt $bytes.Length){$n=$r.Read($bytes,$offset,$bytes.Length-$offset);if($n -le 0){throw 'RECOVERY_SOURCE_EOF'};$offset+=$n};$r.Position=0;"
    FIXED_READ = "$sha=Hash-ContextStream $r;$r.Position=0;$bytes=New-Object byte[] ([int]$r.Length);$offset=0;while($offset -lt $bytes.Length){$n=$r.Read($bytes,$offset,$bytes.Length-$offset);if($n -le 0){throw 'RECOVERY_SOURCE_EOF'};$offset+=$n};$r.Position=0;"

    @unittest.skipUnless(__import__('os').name=='nt','actual .NET stream/hash semantics required')
    def test_actual_hash_consumes_stream_old_eof_red_rewind_green(self):
        import subprocess,json,re
        hashing=re.search(r" function Hash-ContextStream\([^\n]+\)\{[^\n]+\}",stage.INSTALLED_CONTEXT_PS).group(0)
        rows=[]
        for code in (self.OLD_READ,self.FIXED_READ):
            script="$ErrorActionPreference='Stop';"+hashing+";$r=[IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes('PUBLIC'));$failed=$false;$bytes=$null;try{"+code+"}catch{if($_.Exception.Message -cne 'RECOVERY_SOURCE_EOF'){throw};$failed=$true}finally{$r.Dispose()};[ordered]@{failed=$failed;bytes=if($null -eq $bytes){$null}else{[Text.Encoding]::ASCII.GetString($bytes)};sha256=$sha}|ConvertTo-Json -Compress"
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=15,check=True)
            rows.append(json.loads(result.stdout.decode('utf-8-sig')))
        self.assertIs(rows[0]['failed'],True)
        self.assertEqual(rows[1],dict(failed=False,bytes='PUBLIC',sha256=__import__('hashlib').sha256(b'PUBLIC').hexdigest()))
