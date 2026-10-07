"""Actual harmless socket private channel; no SSH, QGA, VM or credentials."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest

from agent_tools import windows_source_fixture_login as login


class PrivateChannelTest(unittest.TestCase):
    SECRET=b'PUBLIC_FIXTURE_A!9'

    def exchange(self, mode):
        client,server=socket.socketpair();received=[]
        def peer():
            try:
                raw=bytearray()
                while not raw.endswith(b'\n'):raw.extend(server.recv(4096))
                received.append(json.loads(raw))
                if mode=='success':server.sendall(b'{"return":{},"id":"fixture-one"}\n')
                elif mode=='echo-error':server.sendall(json.dumps({'id':'fixture-one','error':{'desc':self.SECRET.decode(),'request':received[0]}}).encode()+b'\n')
                elif mode=='overflow':server.sendall(b'X'*4097)
                elif mode=='timeout':time.sleep(.06)
            finally:server.close()
        thread=threading.Thread(target=peer);thread.start();out=io.StringIO();error=None;value=None
        try:
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):
                try:value=login.private_qmp_command(client,'send-key',login.private_key_requests(self.SECRET)[0],'fixture-one',time.monotonic()+.03)
                except login.PrivateLoginUnknown as e:error=str(e)
        finally:client.close();thread.join()
        return value,error,out.getvalue(),received

    def test_actual_private_reply_does_not_emit_secret_or_keycodes(self):
        value,error,raw,requests=self.exchange('success')
        self.assertTrue(value);self.assertIsNone(error);self.assertEqual(raw,'')
        self.assertEqual(requests[0]['execute'],'send-key')

    def test_actual_echo_error_eof_deadline_overflow_are_finite_private(self):
        for mode in ('echo-error','eof','timeout','overflow'):
            with self.subTest(mode=mode):
                value,error,raw,requests=self.exchange(mode)
                self.assertIsNone(value);self.assertEqual(error,'private-reply-unknown');self.assertEqual(raw,'')
                self.assertNotIn(self.SECRET.decode(),error+raw)
                self.assertNotIn(json.dumps(requests[0]['arguments']),error+raw)

    def test_actual_unsupported_private_input_never_echoes_bytes(self):
        with self.assertRaisesRegex(login.PrivateLoginUnknown,'^private-input-unsupported$'):
            login.private_key_requests(b'PRIVATE\x00BYTE')

    def test_actual_secret_source_has_no_password_hash_or_persistence(self):
        source=Path(login.__file__).read_text()
        self.assertNotIn('hashlib',__import__('inspect').getsource(login.private_source_credential))
        self.assertNotIn('record_at',__import__('inspect').getsource(login.private_qmp_command))
        self.assertNotIn('PUBLIC_FIXTURE_A!9',source)


class SourceCredentialTest(unittest.TestCase):
    def test_actual_private_fs_shape_closing_and_account_binding(self):
        import tempfile
        from unittest.mock import patch
        from agent_tools import windows_parallel_vm_source_inventory as inv
        actual_fstat=os.fstat;actual_lstat=Path.lstat
        class ProjectedStat:
            def __init__(self, value):self.value=value
            def __getattr__(self,key):return 1000 if key=='st_uid' else getattr(self.value,key)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'credentials.json'
            raw=json.dumps({'username':login.ACCOUNT,'password':'FIXTURE_ONLY!9'}).encode()
            path.write_bytes(raw+b' '*(75-len(raw)));path.chmod(0o600)
            def named(obj,*args,**kwargs):return ProjectedStat(actual_lstat(obj,*args,**kwargs))
            with patch.object(os,'fstat',side_effect=lambda fd:ProjectedStat(actual_fstat(fd))),patch.object(Path,'lstat',new=named):
                pin=inv.generation(path.lstat());parent=inv.parent_identity(root.lstat())
                with patch.object(login,'SOURCE_ROOT',root),patch.object(login,'CREDENTIAL_GENERATION',pin),patch.object(login,'SOURCE_PARENT',parent):
                    out=io.StringIO()
                    with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):
                        self.assertEqual(login.private_source_credential(path),b'FIXTURE_ONLY!9')
                    self.assertEqual(out.getvalue(),'')
                    path.chmod(0o644)
                    with self.assertRaisesRegex(ValueError,'^source-login-credential-shape$'):
                        login.private_source_credential(path)

    def test_actual_secret_requests_never_reach_process_argv_or_fs(self):
        import subprocess
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            before=set(Path(d).iterdir())
            with patch.object(subprocess,'Popen',side_effect=AssertionError('unexpected process')):
                requests=login.private_key_requests(b'PRIVATE_C!9')
                self.assertGreater(len(requests),1)
            self.assertEqual(set(Path(d).iterdir()),before)


def factory_inputs():
    from agent_tools.tests.test_windows_parallel_vm_launch import controller_boot
    from agent_tools import windows_parallel_vm_launch as launch
    import stat,uuid
    prepared={'state':'prepared','template':str(launch.prepare.TEMPLATE_ROOT/'template.qcow2'),
        'nativeGuestStarted':False,'launchAdmitted':False,'productAcceptance':False,
        'ordinaryQemuReadAccessConfigured':True,'correlationId':str(uuid.uuid4()),'templateSha256':'a'*64,
        'templateGeneration':[1,2,stat.S_IFREG|0o440,0,1000,1,1,0,0],
        'overlays':[{'path':str(Path(p)/'disk.qcow2'),'generation':[1,i+3,stat.S_IFREG|0o600,1000,1000,1,1,0,0],
                    'guestGeneration':[1,i+7,stat.S_IFDIR|0o700,1000,1000]} for i,p in enumerate(launch.inventory.DESTINATIONS)]}
    observed={'state':'boot-observed','nativeGuestStarted':False,'productAcceptance':False,'boot':controller_boot()}
    identity={'pid':3726886,'startTicks':21863571,'uid':1000,'binary':[], 'argv':[]}
    return prepared,observed,identity,str(uuid.uuid4())


class GeneratedProducerTest(unittest.TestCase):
    def test_actual_generated_publish_accepts_fixed_private_metadata_names(self):
        import ast,tempfile
        from agent_tools import windows_parallel_vm_prepare as prepare
        source=login.login_program(*factory_inputs());tree=ast.parse(source)
        publish=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='publish')
        with tempfile.TemporaryDirectory() as d:
            fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
            try:
                ns={'prepare':prepare,'fd':fd,'index':[0],'private_receipt_name':login.private_receipt_name}
                exec(compile(ast.Module([publish],type_ignores=[]),'actual generated metadata publisher','exec'),ns)
                for _ in range(68):ns['publish']({'phase':'PUBLIC_ONLY','replayAllowed':False})
                self.assertEqual(len(list(Path(d).iterdir())),68)
                self.assertFalse(any('keys' in p.read_text() or 'PUBLIC_FIXTURE_A!9' in p.read_text() for p in Path(d).iterdir()))
            finally:os.close(fd)


class ActualChildPrivateFlowTest(unittest.TestCase):
    def test_actual_child_whole_private_flow_keeps_source_argv_journal_output_private(self):
        import inspect,subprocess,sys,tempfile
        for mode in ('success','echo-error','timeout'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);client,server=socket.socketpair();requests=[]
                script='import json,os,re,socket,time\n'
                for fn in (login.PrivateLoginUnknown,login.private_key_requests,login.private_qmp_command,login.perform_private_login):
                    script+=inspect.getsource(fn)+'\n'
                script+='''
payload=json.loads(os.read(0,4096));secret=payload['secret'].encode();connection=socket.socket(fileno=int(__import__('sys').argv[1]));directory=__import__('sys').argv[2]
index=[0]
def guard():os.kill(os.getpid(),0)
def publish(value):
 path=os.path.join(directory,'public-'+str(index[0])+'.json');index[0]+=1
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:os.write(fd,json.dumps(value).encode());os.fsync(fd)
 finally:os.close(fd)
try:result=perform_private_login(connection,secret,'fixture',guard,publish)
except PrivateLoginUnknown as error:result={'state':'unknown','reason':str(error),'replayAllowed':False}
print(json.dumps(result),flush=True)
'''
                program=root/'child.py';program.write_text(script);secret='ONLY_PRIVATE_Z!9'
                self.assertNotIn(secret,script)
                child=subprocess.Popen([sys.executable,str(program),str(client.fileno()),str(root)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(client.fileno(),))
                self.assertNotIn(secret,json.dumps(child.args));client.close()
                def peer():
                    stream=server.makefile('rb')
                    try:
                        while True:
                            raw=stream.readline(4097)
                            if not raw:break
                            request=json.loads(raw);requests.append(request)
                            if mode=='timeout':time.sleep(3.1);break
                            if mode=='echo-error':
                                server.sendall(json.dumps({'id':request['id'],'error':{'desc':secret,'request':request}}).encode()+b'\n');break
                            server.sendall(json.dumps({'return':{},'id':request['id']}).encode()+b'\n')
                            if request['id'].endswith('-submit'):break
                    finally:stream.close();server.close()
                thread=threading.Thread(target=peer);thread.start()
                stdout,stderr=child.communicate(json.dumps({'secret':secret}).encode(),timeout=5)
                thread.join(timeout=4);self.assertFalse(thread.is_alive());self.assertEqual(child.returncode,0)
                self.assertEqual(stderr,b'');result=json.loads(stdout)
                self.assertEqual(result['state'],'login-submitted' if mode=='success' else 'unknown')
                journal=''.join(p.read_text() for p in root.glob('public-*.json'))
                public=stdout.decode()+stderr.decode()+journal+program.read_text()+json.dumps(child.args)
                self.assertNotIn(secret,public)
                self.assertNotIn('"keys":',public);self.assertNotIn('"qcode"',journal)
                self.assertEqual(sum(r['id'].endswith('-submit') for r in requests),1 if mode=='success' else 0)


class FactoryRoundtripTest(unittest.TestCase):
    def test_actual_saved_request_reordering_keeps_exact_factory_bytes(self):
        args=factory_inputs();first=login.login_program(*args)
        second=login.login_program(*json.loads(json.dumps(args,sort_keys=True)))
        self.assertEqual(first,second);compile(first,'actual private producer','exec')
        self.assertNotIn('ONLY_PRIVATE_Z!9',first)


class ActualAccountAdmissionTest(unittest.TestCase):
    def test_actual_generated_account_guard_requires_real_json_boolean(self):
        import ast
        source=login.login_program(*factory_inputs());tree=ast.parse(source)
        guard=next(n for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
            and len(n.value.args)==2 and isinstance(n.value.args[1],ast.Constant)
            and n.value.args[1].value=='source-login-account-current')
        code=compile(ast.Module([guard],type_ignores=[]),'actual generated account gate','exec')
        from agent_tools import windows_parallel_vm_launch as launch
        valid={'account':login.ACCOUNT,'fullName':'Parity test user','sid':login.SID,'enabled':True,'loginKeyboard':'00000409'}
        exec(code,{'need':launch.need,'account':valid,'ACCOUNT':login.ACCOUNT,'SID':login.SID})
        for malformed in (1,1.0,False,0,None,'true'):
            with self.subTest(enabled=malformed),self.assertRaisesRegex(ValueError,'source-login-account-current'):
                exec(code,{'need':launch.need,'account':dict(valid,enabled=malformed),'ACCOUNT':login.ACCOUNT,'SID':login.SID})


class ActualPublicFramingJournalTest(unittest.TestCase):
    def test_actual_generated_clients_keep_one_evidence_sequence(self):
        import ast,tempfile
        from types import SimpleNamespace
        from agent_tools import windows_parallel_vm_launch as launch
        tree=ast.parse(login.login_program(*factory_inputs()))
        body=next(n for n in tree.body if isinstance(n,ast.Try)).body
        qga_setup=next(n for n in body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='qga_client' for t in n.targets))
        framing=[n for n in body if isinstance(n,ast.Assign) and any(
            isinstance(t,ast.Name) and t.id=='framer' or isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name) and t.value.id=='framer'
            for t in n.targets)]
        with tempfile.TemporaryDirectory() as d:
            fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY);left,right=socket.socketpair()
            try:
                ns={'AccessClient':launch.AccessClient,'state':Path(d),'fd':fd,'guest':SimpleNamespace(slot='secondary'),'ROW':{'pid':os.getpid(),'uid':os.getuid()}}
                exec(compile(ast.Module([qga_setup],type_ignores=[]),'actual generated QGA setup','exec'),ns)
                right.sendall(b'{"return":{"pid":1234}}\n')
                self.assertEqual(ns['qga_client']._read_response(left,time.monotonic()+1),b'{"return":{"pid":1234}}')
                exec(compile(ast.Module(framing,type_ignores=[]),'actual generated QMP setup','exec'),ns)
                right.sendall(b'{"QMP":{"version":{}}}\n')
                self.assertEqual(ns['framer']._read_qmp_response(left,time.monotonic()+1),b'{"QMP":{"version":{}}}')
                self.assertEqual(ns['framer'].max_response_bytes,4096)
                self.assertEqual((Path(d)/'qga-secondary-1.private').read_bytes(),b'{"return":{"pid":1234}}\n')
                self.assertEqual((Path(d)/'qga-secondary-2.private').read_bytes(),b'{"QMP":{"version":{}}}\n')
            finally:left.close();right.close();os.close(fd)


class FixedGuestTargetTest(unittest.TestCase):
    def test_actual_tertiary_factory_is_fixed_and_saved_request_stable(self):
        import ast
        args=list(factory_inputs());args[2]=dict(args[2],pid=3847348,startTicks=22216504)
        source=login.login_program(*args,slot='tertiary')
        self.assertEqual(source,login.login_program(*json.loads(json.dumps(args,sort_keys=True)),slot='tertiary'))
        tree=ast.parse(source);bindings={}
        for node in tree.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('SLOT','STATE_NAME','ROW'):
                bindings[node.targets[0].id]=ast.literal_eval(node.value)
        self.assertEqual(bindings['SLOT'],'tertiary');self.assertEqual(bindings['STATE_NAME'],'vm-r-e7e110ff')
        self.assertEqual(bindings['ROW']['pid'],3847348);self.assertEqual(bindings['ROW']['startTicks'],22216504)
        compile(source,'actual fixed tertiary source login','exec')

    def test_wrong_guest_and_untyped_identity_refuse_before_any_private_read(self):
        from unittest.mock import patch
        args=list(factory_inputs())
        with patch.object(login,'private_source_credential',side_effect=AssertionError('private read')):
            for slot,row in [('tertiary',args[2]),('secondary',dict(args[2],pid=3847348,startTicks=22216504)),('secondary',dict(args[2],uid=1000.0))]:
                with self.subTest(slot=slot,row=row),self.assertRaisesRegex(ValueError,'source-login-identity'):
                    login.login_program(args[0],args[1],row,args[3],slot=slot)
            for slot in (None,True,0,'CP117','tertiary/../../foreign'):
                with self.subTest(slot=slot),self.assertRaisesRegex(ValueError,'source-login-target'):
                    login.login_program(*args,slot=slot)


class TargetFieldAdmissionTest(unittest.TestCase):
    def test_actual_generated_complete_field_guard_is_target_specific(self):
        import ast,tempfile
        from agent_tools import windows_parallel_vm_source_inventory as inv,windows_parallel_vm_launch as launch
        hashes={'secondary':'09e6fad22ba0972293fd489c60163259e7401d6725328fc8212919dc3a7dbefa',
                'tertiary':'9bed1ae596597faf24cdf97d7225bdd89cfd737149a92751add910c6d1afc6c3'}
        class NativeOwnerStat:
            def __init__(self,value):self.value=value
            def __getattr__(self,key):return 1000 if key in ('st_uid','st_gid') else getattr(self.value,key)
        with tempfile.TemporaryDirectory() as d:
            screen=Path(d)/'current.png';screen.write_bytes(b'PUBLIC_NATIVE_IMAGE_FIXTURE');screen.chmod(0o600)
            def generation(v):return inv.generation(NativeOwnerStat(v))
            native=generation(screen.lstat())
            for slot in hashes:
                args=list(factory_inputs())
                if slot=='tertiary':args[2]=dict(args[2],pid=3847348,startTicks=22216504)
                tree=ast.parse(login.login_program(*args,slot=slot));bindings={}
                for n in tree.body:
                    if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='FIELD_SHA':bindings['FIELD_SHA']=ast.literal_eval(n.value)
                guard=next(n for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and len(n.value.args)==2 and isinstance(n.value.args[1],ast.Constant) and n.value.args[1].value=='source-login-current-field')
                code=compile(ast.Module([guard],type_ignores=[]),'actual generated complete field admission','exec')
                for candidate in (hashes[slot],hashes['tertiary' if slot=='secondary' else 'secondary'],'0'*64):
                    ns={**bindings,'need':launch.need,'pin':{'generation':native,'sha256':candidate},'generation':generation,'screen':screen}
                    if candidate==hashes[slot]:exec(code,ns)
                    else:
                        with self.subTest(slot=slot,frame=candidate),self.assertRaisesRegex(ValueError,'source-login-current-field'):exec(code,ns)
