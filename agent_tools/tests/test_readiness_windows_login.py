"""Protected credential channel, recognized screens and saved caller boundaries."""
import contextlib,hashlib,inspect,io,json,socket,tempfile,threading,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness_windows_login as login

class PrivateInputTests(unittest.TestCase):
    def test_whole_input_is_validated_before_first_key(self):
        sent=[]
        for value in (b'valid-then-\x00',b'\xff',b'',b'x'*65):
            with self.assertRaisesRegex(login.PrivateInputUnknown,'^instance_login_input_unsupported$'):login.enter_private(value,sent.append,lambda:None)
        self.assertEqual([],sent)
    def test_echo_refusal_timeout_and_lost_ack_have_only_finite_private_results(self):
        secret=b'FIXTURE_PRIVATE_A!9'
        for failure in (ValueError(secret.decode()),TimeoutError(secret.decode()),OSError(json.dumps(login.private_keys(secret)))):
            output=io.StringIO();sent=[]
            def send(value):sent.append(value);raise failure
            with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output),self.assertRaisesRegex(login.PrivateInputUnknown,'^instance_login_entry_unknown$')as caught:
                login.enter_private(secret,send,lambda:None)
            self.assertEqual(1,len(sent));self.assertEqual('',output.getvalue());self.assertNotIn(secret.decode(),str(caught.exception));self.assertIsNone(caught.exception.__cause__)
    def test_real_socket_child_channel_emits_no_private_receipt(self):
        client,server=socket.socketpair();self.addCleanup(client.close);self.addCleanup(server.close);requests=[]
        def peer():
            stream=server.makefile('rwb',buffering=0)
            for _ in range(3):
                value=json.loads(stream.readline());requests.append(value);stream.write(b'{"return":{}}\n')
        worker=threading.Thread(target=peer);worker.start()
        def send(value):
            client.sendall(json.dumps(value).encode()+b'\n');answer=client.recv(4096)
            if answer!=b'{"return":{}}\n':raise ValueError('bad')
        output=io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output),mock.patch.object(time,'sleep',return_value=None):login.enter_private(b'A!',send,lambda:None)
        worker.join();self.assertEqual(3,len(requests));self.assertEqual('',output.getvalue())
    def test_private_encoder_has_no_hash_logger_files_or_processes(self):
        import os,subprocess
        sent=[]
        with mock.patch.object(hashlib,'sha256',side_effect=AssertionError('private hash')),mock.patch.object(os,'open',side_effect=AssertionError('private persistence')),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('private process')),mock.patch.object(time,'sleep',return_value=None):
            login.enter_private(b'X9!',sent.append,lambda:None)
        self.assertEqual(4,len(sent))

class ScreenTests(unittest.TestCase):
    def test_unrecognized_or_changed_field_blocks_before_any_secret(self):
        raw=b'P6\n320 200\n255\n'+b'A'*(320*200*3);crop=b'A'*30
        profile={'width':320,'height':200,'crops':[{'rect':[0,0,10,1],'sha256':hashlib.sha256(crop).hexdigest()}]}
        self.assertTrue(login.screen_gate(raw,profile));changed=raw[:-1]+b'B'
        # The selected crop is intentionally narrow; changes within that exact
        # recognized field, rather than unrelated background, block admission.
        changed=raw.replace(b'AAA',b'BAA',1)
        with self.assertRaisesRegex(ValueError,'screen_unrecognized'):login.screen_gate(changed,profile)
        for invalid in (b'',b'P6\n99999 99999\n255\n',raw+b'overflow'):
            with self.assertRaises(ValueError):login.screen_gate(invalid,profile)


class ExecutorAdmissionTests(unittest.TestCase):
    def run_missing(self,module):
        from agent_tools import ssh_transport as transport
        from agent_tools.tests.test_native_vm_spec import request
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);root.chmod(0o700);(root/'.runtime').mkdir(mode=0o755);(root/'.runtime').chmod(0o755)
            spec=request();binding={'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
            backend=types.SimpleNamespace(root=root,binding=binding,machine=spec['deploymentId'],expected_sid='S-1-5-21-1-2-3-1000',_guard=lambda:None)
            ctx=mock.MagicMock();ctx.__enter__.return_value.revalidate.return_value=None
            with mock.patch.object(transport,'admitted_transport',return_value=ctx),mock.patch('agent_tools.readiness_windows_login_continuation.observe_launch_absence',return_value={'controlled':'account barrier'}):
                return module.execute(backend,str(uuid.uuid4()),{}, {},str(root/'MISSING_SECRET'),time.monotonic()+10)
    def test_actual_preserved_parent_refusal_red_then_private_subgroup_green(self):
        folder=Path(__file__).parent/'fixtures/windows_login_runtime_parent';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_parent_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with self.assertRaisesRegex(ValueError,'windows_login_journal_owner'):self.run_missing(before)
        value=self.run_missing(login);self.assertEqual('credential_unavailable',value['reason']);self.assertEqual('blocked',value['state'])


class RemoteCredentialFenceTests(unittest.TestCase):
    def run_sequence(self,*,lost=False,wrong=False,changed=False,sleeping=False,animated=False,module=login,ready_after=False,changed_session=False):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);operation=str(uuid.uuid4());machine=str(uuid.uuid4());sid='S-1-5-21-1-2-3-1000'
            raw=b'P6\n320 200\n255\n'+b'A'*(320*200*3);profile={'width':320,'height':200,'crops':[{'rect':[0,0,10,1],'sha256':hashlib.sha256(b'A'*30).hexdigest()}]}
            expected={'actor':{'pid':123,'startTicks':456},'hostBoot':'HOST','controlConnection':'control','boot':'BOOT','console':1,'logon':0,'user':''}
            before={k:expected[k]for k in ('actor','hostBoot','controlConnection')}
            fresh={'machine':machine,'boot':'BOOT','console':1,'expectedSid':sid,'ordinary':True,'tokenSid':None,'session':{'SessionId':1,'Logon':0,'User':'','Flags':0,'State':1},'explorers':[]}
            if wrong:fresh['session']['User']='administrator';fresh['tokenSid']='S-1-5-21-1-2-3-999'
            records={};keys=[];screens=[];screen_state=['black'if sleeping else'field'];fade_frames=[0]
            lockraw=raw.replace(b'A',b'L')
            if sleeping and (module is login or animated):
                profile={'password':profile,'lockscreen':{'width':320,'height':200,'crops':[{'rect':[0,0,10,1],'sha256':hashlib.sha256(b'L'*30).hexdigest()}]}}
            def save(name,value):
                with (root/name).open('xb')as stream:stream.write(json.dumps(value).encode())
                records[name]=value
            def script(label,source):
                if label.startswith('login-account'):return {'name':'recovery','sid':sid,'enabled':True,'loginKeyboard':'00000409'}
                if changed_session and label.startswith('login-admission'):
                    return {**fresh,'session':{**fresh['session'],'Logon':99}}
                if ready_after and label.startswith('login-after'):
                    fresh['tokenSid']=sid;fresh['session'].update(User='recovery',Logon=123,Flags=1,State=0);fresh['explorers']=[{'SessionId':1}]
                return fresh
            def monitor(command,args):
                if command=='screendump':
                    screens.append(command);frame=(raw.replace(b'A',b'\0')if screen_state[0]=='black'else lockraw if screen_state[0]=='lock'else raw)
                    if screen_state[0]=='fade':
                        fade_frames[0]+=1;frame=raw.replace(b'A',b'B')if fade_frames[0]==1 else raw
                    Path(args['filename']).write_bytes(frame if not changed else frame.replace(b'AAA',b'BAA',1));Path(args['filename']).chmod(0o600);return {}
                if command=='query-mice':return [{'current':True,'absolute':True}]
                if command=='input-send-event':screen_state[0]='lock';return {}
                self.assertEqual('send-key',command)
                if screen_state[0]=='lock':screen_state[0]='fade'if animated else'field';return {}
                keys.append(args)
                if lost:raise TimeoutError('FIXTURE_PRIVATE_PASSWORD_A!9')
                return {}
            values={'SPEC':{'deploymentId':machine},'SETUP':{'user':'recovery'},'LOGIN_SID':sid,'LOGIN_ACCOUNT_SCRIPT':'fixedaccount','SESSION_SCRIPT':'fixedsession','LOGIN_PROFILE':profile,'LOGIN_EXPECTED':expected,'OPERATION':operation,'LOGIN_MODE':'login-submit'}
            with mock.patch.dict(module.__dict__,values),mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(b'FIXTURE_PRIVATE_PASSWORD_A!9'))),mock.patch.object(time,'sleep',return_value=None):
                if lost:
                    with self.assertRaisesRegex(login.PrivateInputUnknown,'^instance_login_entry_unknown$'):module._login_flow(root,records.__getitem__,save,monitor,lambda:None,script,fresh,before)
                elif wrong or changed or changed_session:
                    with self.assertRaises(ValueError):module._login_flow(root,records.__getitem__,save,monitor,lambda:None,script,fresh,before)
                    self.assertEqual([],keys);self.assertEqual({},records);return
                else:module._login_flow(root,records.__getitem__,save,monitor,lambda:None,script,fresh,before)
                original_count=len(keys);module.LOGIN_MODE='login-status'
                value=module._login_flow(root,records.__getitem__,save,monitor,lambda:None,script,fresh,before)
                self.assertEqual(original_count,len(keys));self.assertEqual(4 if animated else 3 if sleeping else 1,len(screens));self.assertEqual('ready'if ready_after else'credential-submission-unresolved',value['login']['state'])
                self.assertEqual((3 if sleeping else 1)+(1 if ready_after else 0),len(records))
                for path in root.glob('*.json'):
                    text=path.read_text();self.assertNotIn('FIXTURE_PRIVATE_PASSWORD_A!9',text);self.assertNotIn('hold-time',text);self.assertNotIn('qcode',text)
    def test_actual_preserved_sleeping_screen_failure_red_then_precredential_recovery_green(self):
        folder=Path(__file__).parent/'fixtures/windows_login_sleeping_screen';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_sleep_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):self.run_sequence(sleeping=True,module=before)
        self.run_sequence(sleeping=True)
    def test_actual_preserved_single_fade_capture_red_then_exact_known_roi_wait_green(self):
        folder=Path(__file__).parent/'fixtures/windows_login_animation';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_animation_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):self.run_sequence(sleeping=True,animated=True,module=before)
        self.run_sequence(sleeping=True,animated=True)
    def test_consumed_private_intent_survives_lost_ack_and_status_never_retypes(self):self.run_sequence(lost=True)
    def test_completed_private_sequence_status_has_no_input_or_screenshot(self):self.run_sequence()
    def test_original_ready_terminal_is_retained_without_private_input_metadata(self):self.run_sequence(ready_after=True)
    def test_wrong_account_and_changed_field_never_create_private_intent(self):
        self.run_sequence(wrong=True);self.run_sequence(changed=True)
    def test_changed_actual_session_during_preparation_blocks_before_private_intent(self):self.run_sequence(changed_session=True)


class OriginalFrameBoundTests(unittest.TestCase):
    def response(self,module):
        import random
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);old=str(uuid.uuid4());machine=str(uuid.uuid4());sid='S-1-5-21-1-2-3-1000';generator=random.Random(481)
            for index in range(4):
                pixels=b'\0'*(640*480*3*3//4)+generator.randbytes(640*480*3//4)
                p=root/('login-'+old+'-'+str(index)+'.ppm');p.write_bytes(b'P6\n640 480\n255\n'+pixels);p.chmod(0o600)
            values={'SPEC':{'deploymentId':machine},'LOGIN_SID':sid,'LOGIN_MODE':'login-original-screens','LOGIN_ORIGINAL':old,'LOGIN_FRAME':0}
            fresh={'machine':machine,'expectedSid':sid,'ordinary':True}
            with mock.patch.dict(module.__dict__,values):
                value=module._login_flow(root,lambda _:None,lambda *_:None,lambda *_:None,lambda:None,lambda *_:None,fresh,{})
            return len(json.dumps(value).encode()),len(value['login']['frames'])
    def test_actual_preserved_full_reply_overflow_red_then_one_frame_green(self):
        folder=Path(__file__).parent/'fixtures/windows_login_frame_pagination';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_frames_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        size,count=self.response(before)
        with self.assertRaises(AssertionError):self.assertLessEqual(size,1048576)
        self.assertEqual(4,count);size,count=self.response(login);self.assertLessEqual(size,1048576);self.assertEqual(1,count)


class ProtectedDispatchRetryTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        from agent_tools import ssh_transport as transport
        self.fixture=ReadinessTransportTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.root=self.fixture.root
        # The fixture SSH executable forwards stdin over its real Unix socket;
        # the reviewed production transport and dispatch retry remain intact.
        peer=self.fixture.binary.read_text().replace('result=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,',"result=subprocess.run(command,input=base64.b64decode(request.get('stdin','')),capture_output=True,").replace("client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)","if '-O' not in args:request['stdin']=base64.b64encode(sys.stdin.buffer.read()).decode()\n client.sendall(json.dumps(request).encode()+b'\\n');reply=receive(client)")
        self.fixture.binary.write_text(peer)
        from agent_tools.tests.test_native_vm_spec import request
        from agent_tools.tests.test_readiness_windows_guest import facts,SID,MACHINE
        self.facts=facts();spec=request();spec['host']='explicit-peer';spec['deploymentId']=MACHINE
        self.binding={'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        self.backend=types.SimpleNamespace(root=self.root,binding=self.binding,machine=MACHINE,expected_sid=SID,_guard=lambda:None)
        self.private=self.root/'private.secret';self.private.write_text('FIXTURE_PROTECTED_A!9\n');self.private.chmod(0o600)
        self.operations={};self.submissions=[]
    def producer(self,binding,mode,operation,**kwargs):
        counter=self.root/('private-counter-'+operation)
        self.operations[operation]=counter
        outcome={'state':'observed','operationId':operation,'provider':'raw-qemu-windows','machine':self.backend.machine,'hostBoot':'fixture','guest':'running','actor':{},'controlConnection':'fixture','sessionFacts':self.facts,'displayFacts':None,'guestAgent':True,'idleFacts':None,'hostWork':None,'login':{'state':'ready','operationId':operation,'interactiveSessionVerified':True,'replayAllowed':False}}
        source='import json,sys\nfrom pathlib import Path\n'
        if mode=='login-submit':source+='private=sys.stdin.buffer.read();assert private;path=Path('+repr(str(counter))+');path.write_text(str(int(path.read_text())+1)if path.exists()else"1")\n'
        return (source+'print(json.dumps('+repr(outcome)+'))\n').encode()
    def invoke(self,module,operation):
        with mock.patch.object(module,'program',side_effect=self.producer),mock.patch('agent_tools.readiness_windows_login_continuation.observe_launch_absence',return_value={'controlled':'complete read-only launch barrier'}):
            return module.execute(self.backend,operation,{}, {'boot':self.facts['boot']},str(self.private),time.monotonic()+30)
    def test_private_fresh_submit_proven_prelaunch_refreshes_once_and_repeat_never_reopens_input(self):
        from agent_tools import ssh_transport as transport,ssh_dispatch_admission as admissions,readiness
        original=transport.run_ssh;failed=[]
        def run(argv,**kwargs):
            if isinstance(kwargs.get('input'),bytes)and kwargs['input'].endswith(b'FIXTURE_PROTECTED_A!9')and not failed:
                failed.append(True);admission=admissions.current(self.root,'explicit-peer');owner=admission.operation_identity
                admissions.add_dispatch_guard(admission,lambda:(_ for _ in ()).throw(readiness.ReadinessBlocked('prepared_context_stale',owner)))
            return original(argv,**kwargs)
        folder=Path(__file__).parent/'fixtures/windows_login_dispatch_retry';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_dispatch_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        old_operation=str(uuid.uuid4())
        with mock.patch.object(transport,'run_ssh',side_effect=run):red=self.invoke(before,old_operation)
        with self.assertRaises(AssertionError):self.assertEqual('observed',red['state'])
        self.assertEqual('unknown',red['state']);self.assertFalse(self.operations[old_operation].exists());failed.clear()
        operation=str(uuid.uuid4())
        with mock.patch.object(transport,'run_ssh',side_effect=run):value=self.invoke(login,operation)
        self.assertEqual('observed',value['state']);self.assertEqual('1',self.operations[operation].read_text());self.assertEqual(1,len(failed))
        self.private.unlink();again=self.invoke(login,operation);self.assertEqual('observed',again['state']);self.assertEqual('1',self.operations[operation].read_text())
        for parent in (self.root/'.runtime/readiness-windows-login',self.root/'.rag_index/ssh-dispatch-retry'):
            for path in parent.rglob('*'):
                if path.is_file():self.assertNotIn(b'FIXTURE_PROTECTED_A!9',path.read_bytes())
    def test_private_unknown_after_actual_execution_is_observation_only(self):
        from agent_tools import ssh_transport as transport
        import subprocess
        original=transport.run_ssh;lost=[];operation=str(uuid.uuid4())
        def run(argv,**kwargs):
            result=original(argv,**kwargs)
            if isinstance(kwargs.get('input'),bytes)and kwargs['input'].endswith(b'FIXTURE_PROTECTED_A!9')and not lost:lost.append(True);raise subprocess.TimeoutExpired('public',1)
            return result
        with mock.patch.object(transport,'run_ssh',side_effect=run):value=self.invoke(login,operation)
        self.assertEqual('unknown',value['state']);self.assertEqual('1',self.operations[operation].read_text())
        self.private.unlink();self.assertEqual('observed',self.invoke(login,operation)['state']);self.assertEqual('1',self.operations[operation].read_text())



    def test_preserved_collector_multiline_carrier_red_then_bounded_safe_inline_green(self):
        import ast
        from agent_tools import ssh_transport as transport
        folder=Path(__file__).parent/'fixtures/windows_login_collector_carrier';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest());tree=ast.parse(raw)
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='collect_terminal');assignment=next(node for node in ast.walk(function)if isinstance(node,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='command'for x in node.targets));namespace={'source':"print('fixed public collector')\n"};exec(compile(ast.Module(body=[assignment],type_ignores=[]),'actual preserved collector command','exec'),namespace);config=transport.load_config(self.root)
        with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(config,'explicit-peer',command=namespace['command'])
        command=login._terminal_command(namespace['source']);argv=transport.build_ssh_argv(config,'explicit-peer',command=command);self.assertTrue(argv);self.assertLess(sum(len(x.encode())for x in argv),60000);self.assertNotIn('\n',command[-1])

    def test_preserved_spent_budget_still_dispatches_red_then_owner_blocks_before_dispatch_green(self):
        from agent_tools import ssh_dispatch_retry,ssh_transport as transport
        original_run=transport.run_ssh;real_clock=time.monotonic;calls=[]
        folder=Path(__file__).parent/'fixtures/windows_login_deadline';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._windows_login_deadline_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        def record(argv,**kwargs):
            if isinstance(kwargs.get('input'),bytes)and kwargs['input'].endswith(b'FIXTURE_PROTECTED_A!9'):calls.append(True)
            return original_run(argv,**kwargs)
        def exhausted(scope_root,host,operation_identity,**options):
            with options['admission_factory'](scope_root,host,operation_identity,deadline=options['deadline'])as admission:
                argv=options['build'](admission,1)
                def clock():
                    frame=inspect.currentframe().f_back
                    return options['deadline']+1 if frame.f_code.co_name=='submit'else real_clock()
                with mock.patch.object(time,'monotonic',new=clock):return options['submit'](argv)
        with mock.patch.object(ssh_dispatch_retry,'run_original',side_effect=exhausted),mock.patch.object(transport,'run_ssh',side_effect=record):
            red=self.invoke(before,str(uuid.uuid4()));self.assertGreater(len(calls),0);self.assertNotEqual('blocked',red['state']);calls.clear()
            # Close the owned controlled endpoint and use a separate GREEN
            # fixture; the original native evidence remains retained.
            self.fixture.doCleanups();self.setUp()
            green=self.invoke(login,str(uuid.uuid4()));self.assertEqual('deadline_before_submission',green['reason']);self.assertEqual('blocked',green['state']);self.assertEqual([],calls)


class ReferenceEnvelopeTests(unittest.TestCase):
    def test_actual_preserved_single_frame_envelope_failure_red_then_precredential_decoder_green(self):
        import ast,base64,random,zlib
        folder=Path(__file__).parent/'fixtures/windows_login_reference_bound';before=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(before).hexdigest())
        source=before.decode();tree=ast.parse(source);guard=next(node for node in ast.walk(tree)if isinstance(node,ast.If)and 'len(result.stdout)>1048576'in ast.get_source_segment(source,node).replace(' ',''))
        raw=b'P6\n1280 800\n255\n'+random.Random(42).randbytes(1280*800*3);reply=json.dumps({'state':'observed','login':{'state':'precredential-reference','originalCredentialIntentAbsent':True,'screenZlib':base64.b64encode(zlib.compress(raw)).decode(),'screenBytes':len(raw)}}).encode()
        self.assertGreater(len(reply),1048576)
        with self.assertRaisesRegex(ValueError,'original_transport_outcome_unknown'):exec(compile(ast.Module(body=[guard],type_ignores=[]),'actual preserved diagnostic envelope','exec'),{'result':types.SimpleNamespace(returncode=0,stdout=reply,stderr=b'')})
        self.assertEqual(raw,login.decode_precredential_reference(reply)[1])
        with self.assertRaises(ValueError):login.decode_precredential_reference(reply,b'echo rejected')
        value=json.loads(reply);value['login']['originalCredentialIntentAbsent']=False
        with self.assertRaises(ValueError):login.decode_precredential_reference(json.dumps(value).encode())

class HistoricalTerminalTests(unittest.TestCase):
    def test_literal_binding_order_preserves_exact_producer_but_changed_code_does_not(self):
        original=b"LOGIN_PROFILE={'password':{'width':1280,'height':800},'lockscreen':{}}\nLOGIN_EXPECTED={'boot':'BOOT','console':2}\nprint('fixed observer')\n"
        reordered=b"LOGIN_PROFILE={'lockscreen':{},'password':{'height':800,'width':1280}}\nLOGIN_EXPECTED={'console':2,'boot':'BOOT'}\nprint('fixed observer')\n"
        self.assertTrue(login._terminal_source_matches(original,reordered));self.assertFalse(login._terminal_source_matches(original,reordered.replace(b'fixed observer',b'other code')));self.assertFalse(login._terminal_source_matches(original,reordered.replace(b"'BOOT'",b"'OTHER'")))

    @contextlib.contextmanager
    def fixture(self):
        import os,pwd,shutil
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            parent=Path(temporary);root=parent/'fixture';root.mkdir(mode=0o700);boot=parent/'boot';boot.write_text('HOSTBOOT');op=str(uuid.uuid4());sid='S-1-5-21-1-2-3-1000'
            binding={'spec':{'root':str(root)},'setup':{},'context':{'hostBootId':'HOSTBOOT'}};identity={'operationId':op,'expectedSid':sid,'profile':{},'expected':{'boot':'GUESTBOOT','console':2}};original={'identity':identity};stages=[];directories=[]
            def write(path,value):path.write_bytes(value if type(value)is bytes else json.dumps(value).encode());path.chmod(0o600)
            def gen(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
            try:
                for source in (b'fixed original submit source',b'fixed original status source'):
                    corr=uuid.uuid4().hex;directory=Path('/tmp').resolve()/('vpn-control-auto-'+corr);directory.mkdir(mode=0o700);directories.append(directory);write(directory/'program.source',source)
                    user=pwd.getpwuid(os.getuid());stage={'identity':{'uid':os.getuid(),'principal':user.pw_name,'home':user.pw_dir,'boot':'HOSTBOOT'},'directory':str(directory),'correlationId':corr,'directoryIdentity':gen(directory.stat())[:5],'generation':gen((directory/'program.source').stat()),'programBytes':len(source),'programSha256':hashlib.sha256(source).hexdigest()};write(directory/'receipt.json',stage);write(directory/'execution-intent.json',stage);stages.append(stage)
                write(root/'intent.json',{'schemaVersion':1,'spec':binding['spec'],'setup':{},'hostBootId':'HOSTBOOT','rootIdentity':gen(root.stat())[:5],'assetIdentities':{'firmwareCode':{},'installer':{},'drivers':{}}})
                write(root/('login-credential-'+op+'.intent.json'),{'operationId':op,'expected':identity['expected'],'profile':{},'account':sid,'replayAllowed':False});terminal={'operationId':op,'state':'ready','boot':'GUESTBOOT','account':sid,'console':2,'logon':123,'settingsChanged':False,'replayAllowed':False};write(root/('login-credential-'+op+'.terminal.json'),terminal)
                yield binding,original,stages,root,boot,write
            finally:
                for directory in directories:shutil.rmtree(directory)
    def observe(self,values):
        binding,original,stages,root,boot,write=values
        return login._collect_terminal_remote(binding,original,stages,str(boot),str(Path('/tmp').resolve()))
    def test_completed_original_is_historical_only_without_guest_or_private_access(self):
        import subprocess
        with self.fixture()as values,mock.patch.object(subprocess,'run',side_effect=AssertionError('no guest or private process')):
            result=self.observe(values);self.assertEqual('terminal',result['state']);self.assertIs(result['currentDesktopVerified'],False);self.assertIs(result['replayAllowed'],False)
    def test_missing_terminal_changed_source_account_or_boot_remain_unknown(self):
        for change in ('terminal','source','account','boot'):
            with self.subTest(change=change),self.fixture()as values:
                binding,original,stages,root,boot,write=values;op=original['identity']['operationId']
                if change=='terminal':(root/('login-credential-'+op+'.terminal.json')).unlink()
                elif change=='source':write(Path(stages[-1]['directory'])/'program.source',b'changed producer')
                elif change=='account':
                    path=root/('login-credential-'+op+'.intent.json');v=json.loads(path.read_bytes());v['account']='different';write(path,v)
                else:boot.write_text('OTHERBOOT')
                result=self.observe(values);self.assertEqual('unknown',result['state']);self.assertIs(result['replayAllowed'],False)

if __name__=='__main__':unittest.main()

class DurableProtectedOwnerTests(unittest.TestCase):
    """Real detached processes and a real private Unix monitor channel."""
    def setUp(self):
        import os
        self.temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700)
        (self.root/'intent.json').write_text('{"fixed":"owned fixture"}\n');(self.root/'intent.json').chmod(0o600)
        self.operation=str(uuid.uuid4());self.host_boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()if Path('/proc/sys/kernel/random/boot_id').exists()else None
        if self.host_boot is None:self.skipTest('Linux detached owner qualification requires procfs')
        self.identity={'hostBoot':self.host_boot,'fixture':'controlled','expected':{'boot':'fixture-boot'},'profile':{},'account':'SID','user':'recovery','machine':'controlled'}
        self.received=[];self.first=threading.Event();self.release=threading.Event();self.done=threading.Event();self.errors=[]
        self.channel=self.root/'monitor.sock';self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(self.channel));self.listener.listen(1);self.listener.settimeout(5);self.addCleanup(self.listener.close)
        def peer():
            try:
                client,_=self.listener.accept()
                with client:
                    stream=client.makefile('rwb',buffering=0)
                    while True:
                        row=stream.readline()
                        if not row:break
                        # Never retain the key request, just the mutation count.
                        value=json.loads(row);self.assertEqual({'keys','hold-time'},set(value));self.received.append(1);self.first.set()
                        if len(self.received)==1:self.release.wait(3)
                        time.sleep(.1);stream.write(b'{"return":{}}\n')
            except (OSError,ValueError,AssertionError)as error:self.errors.append(type(error).__name__)
            finally:self.done.set()
        self.worker=threading.Thread(target=peer,daemon=True);self.worker.start()
    def source(self,module,detached=True,extra=''):
        import textwrap
        source='import os,sys,json,time,fcntl,socket\nfrom pathlib import Path\n'
        for fn in (module.PrivateInputUnknown,module.private_keys,module.enter_private):source+=inspect.getsource(fn)+'\n'
        if detached:source+=login._publication_source()+'\n'+inspect.getsource(module._ProtectedOwner)+'\n'
        source+='root=Path('+repr(str(self.root))+');operation='+repr(self.operation)+'\n'
        source+="lock=os.open(root/'intent.json',os.O_RDONLY|os.O_NOFOLLOW);fcntl.flock(lock,fcntl.LOCK_EX)\n"
        if detached:
            source+='identity='+repr(self.identity)+"\nowner=_ProtectedOwner(root,operation,identity,sys.argv[1],sys.argv[1])\n"
            source+="existing=owner.existing()\nif existing is not None:print(json.dumps(existing));sys.exit()\n"
            source+="value=owner.start(lock,[],sys.stdin.buffer,wait_seconds=3)\nif type(value)is dict:print(json.dumps(value));sys.exit()\nsecret=value\n"
        else:source+='secret=sys.stdin.buffer.read()\n'
        source+=extra+'\nclient=socket.socket(socket.AF_UNIX);client.connect('+repr(str(self.channel))+')\n'
        source+="def send(value):\n client.sendall(json.dumps(value).encode()+b'\\n');answer=client.recv(4096)\n if answer!=b'{\"return\":{}}\\n':raise ValueError('finite')\n"
        source+="enter_private(secret,send,"+('owner.guard'if detached else'lambda:None')+")\nclient.close()\n"
        if detached:source+="owner.finish({'state':'blocked','operationId':operation,'reason':'instance_login_entry_unknown'});os._exit(0)\n"
        return source
    def spawn(self,source,payload):
        import subprocess,sys
        path=self.root/('caller-'+uuid.uuid4().hex+'.py');path.write_text(source);path.chmod(0o600)
        digest=hashlib.sha256(source.encode()).hexdigest()
        process=subprocess.Popen([sys.executable,'-I','-B',str(path),digest],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process.stdin.write(payload);process.stdin.close();process.stdin=None
        self.addCleanup(lambda:process.poll()is None and process.kill())
        return process,digest
    def test_before_foreground_dies_red_then_same_original_detached_owner_completes_green(self):
        folder=Path(__file__).parent/'fixtures/windows_login_durable_owner';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._login_owner_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');__import__('sys').modules[before.__name__]=before;exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        # This test invokes the actual old private-entry helper in a foreground
        # process; a transport/client loss kills it after the first mutation.
        old,_=self.spawn(self.source(before,False),b'A!9');self.assertTrue(self.first.wait(3));old.kill();old.communicate(timeout=3);self.release.set();self.assertTrue(self.done.wait(3))
        with self.assertRaises(AssertionError):self.assertEqual(4,len(self.received))
        self.assertEqual(1,len(self.received))
        # New original gets an independent root/socket, exactly as production
        # forbids replacing or replaying the uncertain historical operation.
        self.worker.join();self.listener.close();self.temporary.cleanup();self.setUp()
        source=self.source(login);process,digest=self.spawn(source,b'\x00\x00\x00\x03A!9');self.assertTrue(self.first.wait(3));process.kill();process.communicate(timeout=3);self.release.set()
        self.assertTrue(self.done.wait(4));self.worker.join();self.assertEqual([],self.errors);self.assertEqual(4,len(self.received))
        terminal=self.root/('login-owner-'+self.operation+'.terminal.json');limit=time.monotonic()+3
        while not terminal.exists()and time.monotonic()<limit:time.sleep(.02)
        self.assertTrue(terminal.exists());value=json.loads(terminal.read_bytes());self.assertEqual('instance_login_entry_unknown',value['packet']['reason'])
        self.assertEqual(digest,value['admission']['sourceSha256']);self.assertEqual(value['admission']['lock'][0:2],[self.root.stat().st_dev,(self.root/'intent.json').stat().st_ino])
        identity=self.identity;observer=login._ProtectedOwner(self.root,self.operation,identity,digest,digest)
        for _ in range(3):self.assertEqual('terminal',observer.existing()['state'])
        self.assertEqual(4,len(self.received))
        for path in self.root.glob('*.json'):
            body=path.read_bytes();self.assertNotIn(b'A!9',body);self.assertNotIn(b'qcode',body);self.assertNotIn(b'hold-time',body)
    def test_truncated_payload_never_admits_owner_or_performs_an_effect(self):
        process,_=self.spawn(self.source(login),b'\x00\x00\x00\x03A')
        out,err=process.communicate(timeout=3);self.assertNotEqual(0,process.returncode)
        self.assertFalse((self.root/('login-owner-'+self.operation+'.intent.json')).exists());self.assertEqual([],self.received)
        self.assertNotIn(b"b'A'",out+err)
    def test_replaced_lock_blocks_before_private_effect_even_with_same_contents(self):
        extra="replacement=root/'replacement';replacement.write_bytes((root/'intent.json').read_bytes());replacement.chmod(0o600);os.replace(replacement,root/'intent.json')"
        process,digest=self.spawn(self.source(login,extra=extra),b'\x00\x00\x00\x03A!9')
        process.communicate(timeout=4);time.sleep(.2);self.assertEqual([],self.received)
        observer=login._ProtectedOwner(self.root,self.operation,self.identity,digest,digest)
        with self.assertRaisesRegex(ValueError,'instance_login_owner_lock_changed'):observer.existing()
    def test_missing_original_owner_and_changed_binding_never_authorize_another_fork(self):
        source=self.source(login,extra='os._exit(70)');process,digest=self.spawn(source,b'\x00\x00\x00\x03A!9');process.communicate(timeout=4)
        observer=login._ProtectedOwner(self.root,self.operation,self.identity,digest,digest)
        self.assertEqual('unknown',observer.existing()['state']);self.assertEqual([],self.received)
        observer=login._ProtectedOwner(self.root,self.operation,{**self.identity,'fixture':'different'},digest,digest)
        with self.assertRaisesRegex(ValueError,'instance_login_owner_identity'):observer.existing()

    def approved(self,operation,digest):
        return {operation:{'sourceSha256':digest,'identitySha256':hashlib.sha256(json.dumps(self.identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()}}
    def with_approval(self,source,approved):
        return source.replace('identity,sys.argv[1],sys.argv[1])','identity,sys.argv[1],sys.argv[1],approved='+repr(approved)+')')
    def test_dead_original_before_per_uuid_only_red_then_new_uuid_blocked_green(self):
        before=_incident_before()
        def run(module):
            self.release.set();first=self.operation
            process,digest=self.spawn(self.source(module,extra='os._exit(70)'),b'\x00\x00\x00\x03A!9');process.communicate(timeout=4)
            approved=self.approved(first,digest);self.operation=str(uuid.uuid4());source=self.source(module)
            if module is login:source=self.with_approval(source,approved)
            process,_=self.spawn(source,b'\x00\x00\x00\x03A!9');out,err=process.communicate(timeout=4)
            return out,err
        run(before);self.assertTrue(self.done.wait(3));self.worker.join()
        with self.assertRaises(AssertionError):self.assertEqual([],self.received)
        self.assertEqual(4,len(self.received));self.listener.close();self.temporary.cleanup();self.setUp()
        out,err=run(login);self.assertEqual([],self.received);self.assertIn(b'instance_login_prior_owner_unresolved',err)
        self.assertFalse((self.root/('login-owner-'+self.operation+'.intent.json')).exists())
    def test_two_concurrent_uuids_share_actual_root_lock_and_only_first_can_enter(self):
        self.release.set();first=self.operation;source=self.source(login,extra='time.sleep(.4)');process,digest=self.spawn(source,b'\x00\x00\x00\x03A!9')
        path=self.root/('login-owner-'+first+'.owner.json');limit=time.monotonic()+3
        while not path.exists()and time.monotonic()<limit:time.sleep(.01)
        self.assertTrue(path.exists());self.operation=str(uuid.uuid4());second=self.with_approval(self.source(login),self.approved(first,digest));other,_=self.spawn(second,b'\x00\x00\x00\x03A!9')
        process.communicate(timeout=4);out,err=other.communicate(timeout=4);self.assertTrue(self.done.wait(3));self.worker.join()
        self.assertEqual(4,len(self.received));self.assertIn(b'instance_login_prior_owner_unresolved',err);self.assertFalse((self.root/('login-owner-'+self.operation+'.intent.json')).exists())
    def test_correlated_ready_original_allows_next_incident_and_unclosed_legacy_blocks(self):
        self.release.set();first=self.operation
        packet={'state':'observed','operationId':first,'login':{'state':'ready'},'sessionFacts':{'boot':'fixture-boot','expectedSid':'SID','ordinary':True,'tokenSid':'SID','console':1,'session':{'User':'recovery','Flags':1,'State':0,'Logon':123},'explorers':[{'SessionId':1}]}}
        source=self.source(login);source=source[:source.index('client=socket.socket')]+"owner.phase('credential','not-needed')\nowner.finish("+repr(packet)+");os._exit(0)\n"
        process,digest=self.spawn(source,b'\x00\x00\x00\x03A!9');process.communicate(timeout=4);approved=self.approved(first,digest)
        # Unclosed legacy public preparation remains a blocker even alongside
        # a fully source-correlated ready original. Preserve the negative file.
        legacy=str(uuid.uuid4());path=self.root/('login-preparation-'+legacy+'-wake.intent.json');path.write_text('{}');path.chmod(0o600)
        operation=str(uuid.uuid4());owner=login._ProtectedOwner(self.root,operation,self.identity,'a'*64,'a'*64,approved)
        with self.assertRaisesRegex(ValueError,'instance_login_legacy_original_unresolved'):owner.block_prior()
        self.assertEqual([],self.received);path.rename(path.with_suffix('.retained-negative'))
        self.operation=str(uuid.uuid4());source=self.with_approval(self.source(login),approved);process,_=self.spawn(source,b'\x00\x00\x00\x03A!9');process.communicate(timeout=4)
        self.assertTrue(self.done.wait(3));self.worker.join();self.assertEqual(4,len(self.received))


class ProtectedTerminalProjectionTests(unittest.TestCase):
    def test_terminal_projects_only_known_fields_and_never_retains_private_echo(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);root.chmod(0o700);operation=str(uuid.uuid4());sid='S-1-5-21-1-2-3-1000';secret='FIXTURE_UNTRUSTED_PRIVATE_A!9'
            owner=login._ProtectedOwner(root,operation,{'hostBoot':'fixture','expected':{'boot':'fixture-boot'},'account':sid,'user':'recovery'},'a'*64,'a'*64);owner.intent={'known':'admission'};owner.owner={'known':'owner'};saved=[]
            packet={'state':'observed','operationId':operation,'login':{'state':'ready'},'sessionFacts':{'boot':'fixture-boot','expectedSid':sid,'ordinary':True,'tokenSid':sid,'console':1,'session':{'User':'recovery','Flags':1,'State':0,'Logon':123,'untrusted':secret},'explorers':[{'SessionId':1}],'untrusted':secret},'untrusted':secret}
            with mock.patch.object(owner,'guard'),mock.patch.object(owner,'_save',side_effect=lambda name,value:saved.append((name,value))):owner.finish(packet)
            self.assertEqual('owner-terminal',saved[0][1]['packet']['state']);self.assertNotIn(secret,json.dumps(saved));self.assertNotIn('qcode',json.dumps(saved))
            packet['sessionFacts']['session']['User']=secret;saved.clear()
            with mock.patch.object(owner,'guard'),mock.patch.object(owner,'_save',side_effect=lambda name,value:saved.append((name,value))),self.assertRaisesRegex(ValueError,'^instance_login_owner_terminal$'):owner.finish(packet)
            self.assertEqual([],saved)
            with mock.patch.object(owner,'guard'),mock.patch.object(owner,'_save',side_effect=lambda name,value:saved.append((name,value))):owner.finish({'state':'blocked','reason':secret})
            self.assertEqual('instance_login_entry_unknown',saved[0][1]['packet']['reason']);self.assertNotIn(secret,json.dumps(saved))
    def test_whole_generated_callers_compile_with_owner_before_wire_and_bounded_public_metadata(self):
        from agent_tools.tests.test_native_vm_spec import request
        binding={'provider':'raw-qemu-windows','spec':request(),'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        for mode in ('login-submit','login-status','login-probe','login-reference','login-lock-fixture'):
            source=login.program(binding,mode,str(uuid.uuid4()),expected_sid='S-1-5-21-1-2-3-1000',expected={},profile={});compile(source,'whole fixed protected caller','exec')
            text=source.decode();self.assertLess(text.index('launched=login_owner.start('),text.index("suffix='readiness-'+OPERATION"));self.assertIn("login_owner.guard(login_owner.child);plain_guard()",text)

def _incident_before():
    import sys
    folder=Path(__file__).parent/'fixtures/windows_login_owner_incident';raw=(folder/'before.source').read_bytes()
    if json.loads((folder/'provenance.json').read_bytes())['sourceSha256']!=hashlib.sha256(raw).hexdigest():raise AssertionError('beforeimage changed')
    module=types.ModuleType('agent_tools._login_incident_before');module.__package__='agent_tools';module.__file__=str(folder/'before.source');sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module

class OriginalOwnerIncidentSchemaTests(unittest.TestCase):
    def test_mixed_case_authenticated_ordinary_account_before_red_then_projection_green(self):
        def run(module):
            with tempfile.TemporaryDirectory()as temporary:
                owner=module._ProtectedOwner(Path(temporary),str(uuid.uuid4()),{'hostBoot':'fixture','expected':{'boot':'boot'},'account':'SID','user':'recovery'},'a'*64,'a'*64);owner.intent={};owner.owner={};saved=[]
                packet={'state':'observed','operationId':owner.operation,'login':{'state':'ready'},'sessionFacts':{'boot':'boot','expectedSid':'SID','ordinary':True,'tokenSid':'SID','console':1,'session':{'User':'ReCoVeRy','Flags':1,'State':0,'Logon':1},'explorers':[{'SessionId':1}]}}
                with mock.patch.object(owner,'guard'),mock.patch.object(owner,'_save',side_effect=lambda name,value:saved.append(value)):owner.finish(packet)
                return saved
        with self.assertRaisesRegex(ValueError,'instance_login_owner_terminal'):run(_incident_before())
        self.assertEqual('ready',run(login)[0]['packet']['loginState'])
    def test_float_schema_before_accepted_red_then_exact_integer_green(self):
        def run(module):
            with tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);operation=str(uuid.uuid4());identity={'hostBoot':'fixture'};owner=module._ProtectedOwner(root,operation,identity,'a'*64,'a'*64);(root/(owner.prefix+'.intent.json')).touch()
                admitted={'schemaVersion':2.0,'operationId':operation,'identity':identity,'sourceSha256':'a'*64,'root':[1]*5,'lock':[1]*9,'hostBoot':'fixture','creator':{'pid':1,'birth':1},'deadlineNs':1,'replayAllowed':False}
                child={'operationId':operation,'sourceSha256':'a'*64,'pid':1,'birth':1}
                with mock.patch.object(owner,'_read',side_effect=lambda name:admitted if name=='.intent.json'else child),mock.patch.object(owner,'guard'),mock.patch.object(owner,'_birth',return_value=1):return owner.existing()
        self.assertEqual('running',run(_incident_before())['state'])
        with self.assertRaisesRegex(ValueError,'instance_login_owner_identity'):run(login)
    def test_approvals_require_the_whole_retained_canonical_original_artifact(self):
        from agent_tools.tests.test_native_vm_spec import request
        from agent_tools.native_review_source_closure import _Held
        from agent_tools.ssh_source_file_stage_direct import _retain
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);root.chmod(0o700);parent=root/'.runtime/readiness-windows-login';parent.mkdir(mode=0o700,parents=True);operation=str(uuid.uuid4());directory=parent/operation;directory.mkdir(mode=0o700)
            spec=request();binding={'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None};sid='S-1-5-21-1-2-3-1000';expected={'boot':'boot'}
            identity={'operationId':operation,'binding':binding,'expectedSid':sid,'profile':{},'expected':expected};source=login.program(binding,'login-submit',operation,expected_sid=sid,profile={},expected=expected)
            intent={'identity':identity,'callerSha256':hashlib.sha256(source).hexdigest(),'replayAllowed':False};_retain(directory,'credential.intent.json',intent);_retain(directory,'login-submit-original.py',source)
            backend=types.SimpleNamespace(root=root,machine=spec['deploymentId'],binding=binding);held=_Held()
            try:
                approved=login._approved_predecessors(backend,str(uuid.uuid4()),held);self.assertEqual({operation},set(approved));held.finish();held.final_identity_pass()
            finally:held.close()
            # Updating an arbitrary SHA in JSON cannot bless changed code.
            changed=source+b'\nraise ValueError("arbitrary program")\n';(directory/'login-submit-original.py').write_bytes(changed);intent['callerSha256']=hashlib.sha256(changed).hexdigest();(directory/'credential.intent.json').write_text(json.dumps(intent));held=_Held()
            try:
                with self.assertRaisesRegex(ValueError,'windows_login_prior_source_untrusted'):login._approved_predecessors(backend,str(uuid.uuid4()),held)
            finally:held.close()

class AtomicProtectedOwnerPublicationTests(unittest.TestCase):
    def test_actual_partial_publication_red_then_fsynced_create_only_publish_green(self):
        import os,sys
        folder=Path(__file__).parent/'fixtures/windows_login_atomic_owner';raw=(folder/'before.source').read_bytes();self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._login_atomic_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');sys.modules[before.__name__]=before;exec(compile(raw,before.__file__,'exec'),before.__dict__)
        def run(module):
            with tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);owner=module._ProtectedOwner(root,str(uuid.uuid4()),{'hostBoot':'fixture'},'a'*64,'a'*64);target=root/(owner.prefix+'.terminal.json');entered=threading.Event();release=threading.Event();errors=[];value={'state':'finite','operationId':owner.operation};original=os.fdopen
                class PausedStream:
                    def __init__(self,stream):self.stream=stream
                    def __enter__(self):return self
                    def __exit__(self,*args):self.stream.close()
                    def write(self,raw):
                        self.stream.write(raw[:len(raw)//2]);self.stream.flush();entered.set();release.wait(3);return self.stream.write(raw[len(raw)//2:])
                    def flush(self):return self.stream.flush()
                    def fileno(self):return self.stream.fileno()
                def publish():
                    try:owner._save('.terminal.json',value)
                    except BaseException as error:errors.append(type(error).__name__)
                with mock.patch.object(os,'fdopen',side_effect=lambda *args,**kwargs:PausedStream(original(*args,**kwargs))):
                    worker=threading.Thread(target=publish);worker.start();self.assertTrue(entered.wait(2));visible=target.exists()
                    if visible:
                        with self.assertRaises(json.JSONDecodeError):json.loads(target.read_bytes())
                    release.set();worker.join(3)
                self.assertFalse(worker.is_alive());self.assertEqual([],errors);self.assertEqual(value,json.loads(target.read_bytes()))
                with self.assertRaises(FileExistsError):owner._save('.terminal.json',{'state':'replacement'})
                self.assertEqual(value,json.loads(target.read_bytes()));return visible
        self.assertTrue(run(before));self.assertFalse(run(login))

class AtomicLocalLoginPublicationTests(unittest.TestCase):
    def test_actual_concurrent_partial_local_claim_red_then_atomic_durable_green(self):
        import os,sys
        folder=Path(__file__).parent/'fixtures/windows_login_local_publication';provenance=json.loads((folder/'provenance.json').read_bytes())
        for name,digest in provenance['sources'].items():self.assertEqual(digest,hashlib.sha256((folder/name).read_bytes()).hexdigest())
        before=types.ModuleType('agent_tools._login_local_retainer_before');before.__package__='agent_tools';before.__file__=str(folder/'retainer.before.source');sys.modules[before.__name__]=before;exec(compile((folder/'retainer.before.source').read_bytes(),before.__file__,'exec'),before.__dict__)
        def run(retain):
            with tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);target=root/'credential.intent.json';entered=threading.Event();release=threading.Event();errors=[];writer=[None];first=[True];syncs=[];value={'operationId':str(uuid.uuid4()),'callerSha256':'a'*64};original=os.write;sync=os.fsync
                def write(fd,raw):
                    if threading.get_ident()==writer[0]and first[0]:
                        first[0]=False;count=original(fd,raw[:len(raw)//2]);entered.set();release.wait(3);return count
                    return original(fd,raw)
                def publish():
                    writer[0]=threading.get_ident()
                    try:retain(root,target.name,value)
                    except BaseException as error:errors.append(type(error).__name__)
                def fsync(fd):
                    import stat
                    syncs.append(stat.S_ISDIR(os.fstat(fd).st_mode));return sync(fd)
                with mock.patch.object(os,'write',side_effect=write),mock.patch.object(os,'fsync',side_effect=fsync):
                    worker=threading.Thread(target=publish);worker.start();self.assertTrue(entered.wait(2));visible=target.exists()
                    if visible:
                        with self.assertRaises(json.JSONDecodeError):json.loads(target.read_bytes())
                    release.set();worker.join(3)
                self.assertFalse(worker.is_alive());self.assertEqual([],errors);self.assertEqual(value,json.loads(target.read_bytes()))
                with self.assertRaises(FileExistsError):retain(root,target.name,{'replacement':True})
                self.assertEqual(value,json.loads(target.read_bytes()));return visible,any(syncs)
        self.assertEqual((True,False),run(before._retain));self.assertEqual((False,True),run(login._retain_local))
    def test_two_local_publishers_never_overwrite_and_unsafe_directory_refuses(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);root.chmod(0o700);barrier=threading.Barrier(3);results=[]
            def publish(value):
                barrier.wait()
                try:login._retain_local(root,'intent.json',value);results.append('published')
                except FileExistsError:results.append('retained')
            workers=[threading.Thread(target=publish,args=({'owner':i},))for i in (1,2)]
            for worker in workers:worker.start()
            barrier.wait()
            for worker in workers:worker.join(3);self.assertFalse(worker.is_alive())
            self.assertEqual(['published','retained'],sorted(results));self.assertIn(json.loads((root/'intent.json').read_bytes()),({'owner':1},{'owner':2}));self.assertEqual(['intent.json'],sorted(p.name for p in root.iterdir()))
            root.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'windows_login_journal_owner'):login._retain_local(root,'unsafe.json',{})


class NoReplaceLoginPublicationTests(unittest.TestCase):
    def test_actual_paused_publisher_after_publication_hardlink_red_then_single_inode_green(self):
        import ctypes,os,sys
        folder=Path(__file__).parent/'fixtures/windows_login_noreplace_publication';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._login_link_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source');sys.modules[before.__name__]=before;exec(compile(raw,before.__file__,'exec'),before.__dict__)
        def run(module,local):
            with tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);owner=module._ProtectedOwner(root,str(uuid.uuid4()),{'hostBoot':'fixture'},'a'*64,'a'*64);name=owner.prefix+'.terminal.json';value={'finite':'complete'};entered=threading.Event();release=threading.Event();errors=[]
                def pause():entered.set();release.wait(5)
                original_link=os.link;original_library=ctypes.CDLL
                def link(*args,**kwargs):
                    result=original_link(*args,**kwargs);pause();return result
                class Function:
                    def __init__(self,function):object.__setattr__(self,'function',function)
                    def __setattr__(self,name,value):setattr(self.function,name,value)
                    def __call__(self,*args):
                        result=self.function(*args)
                        if result==0:pause()
                        return result
                class Library:
                    def __init__(self,*args,**kwargs):self.library=original_library(*args,**kwargs)
                    def __getattr__(self,name):
                        function=getattr(self.library,name)
                        return Function(function)if name in {'renameat2','renameatx_np'}else function
                def publish():
                    try:
                        if local:module._retain_local(root,name,value)
                        else:owner._save('.terminal.json',value)
                    except BaseException as error:errors.append(type(error).__name__)
                with mock.patch.object(os,'link',side_effect=link),mock.patch.object(ctypes,'CDLL',side_effect=Library):
                    worker=threading.Thread(target=publish);worker.start()
                    try:
                        self.assertTrue(entered.wait(3));links=(root/name).stat().st_nlink
                        try:observed=owner._read('.terminal.json')
                        except ValueError:observed=None
                    finally:release.set();worker.join(5)
                self.assertFalse(worker.is_alive());self.assertEqual([],errors);self.assertEqual(value,owner._read('.terminal.json'));return links,observed
        for local in (False,True):
            with self.subTest(local=local):
                self.assertEqual((2,None),run(before,local));self.assertEqual((1,{'finite':'complete'}),run(login,local))
