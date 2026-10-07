import ast,base64,copy,hashlib,json,unittest
from unittest.mock import patch
from agent_tools import windows_cp117_recovered_gui_login as gui
from agent_tools.tests import test_windows_cp117_recovered_login as fixtures
from agent_tools.tests import test_windows_cp117_secure_layout_observe as secure_fixtures

class ProspectiveGateTests(unittest.TestCase):
    def test_complete_private_input_validates_before_any_key_and_us_shift_chords(self):
        self.assertEqual(gui._us_keys(b'aA1!;:[]{}\\|'),[['a'],['shift','a'],['1'],['shift','1'],['semicolon'],['shift','semicolon'],['bracket_left'],['bracket_right'],['shift','bracket_left'],['shift','bracket_right'],['backslash'],['shift','backslash']])
        for value in(b'',b'a'*65,b'abc\n',b'abc\t',b'abc\x80'):
            with self.assertRaises(ValueError):gui._us_keys(value)
    def test_current_focused_input_proof_required_even_when_screen_matches(self):
        answer=secure_fixtures.ActualInputDestinationCausalTests().measured_answer()
        with patch.object(gui,'_screen_gate')as screen:
            gui._effect_gate(answer,4.9,b'fixture',4.9,True);screen.assert_called_once()
            for age in(-1,5.01):
                with self.assertRaisesRegex(ValueError,'gui-focus-expired'):gui._effect_gate(answer,age,b'fixture',1,True)
            bad=copy.deepcopy(answer);bad['reader']['focus'][11]['hasFocus']=False
            with self.assertRaises(ValueError):gui._effect_gate(bad,1,b'fixture',1,True)
    def test_screen_age_selected_account_caps_and_empty_field_are_all_required(self):
        expected={rect:sha for rect,sha in gui._PROFILE+[gui._EMPTY]}
        with patch.object(gui,'_crop_sha',side_effect=lambda raw,rect:expected[rect]):
            gui._screen_gate(b'fixture',5,True)
            with self.assertRaises(ValueError):gui._screen_gate(b'fixture',5.01,True)
            with self.assertRaises(ValueError):gui._screen_gate(b'fixture',1,False)
            for rect,_ in gui._PROFILE:
                old=expected[rect];expected[rect]='foreign'
                with self.assertRaises(ValueError):gui._screen_gate(b'fixture',1,True)
                expected[rect]=old
    def test_fresh_reader_fixed_two_sources_not_consumed_bdd_replay(self):
        for phase in('typing','enter'):
            source,sha,childsha=gui._fresh_reader(fixtures.ScreenTests().record(),phase)
            self.assertNotEqual(sha,gui.secure.PARENT_SHA);self.assertNotEqual(childsha,gui.secure.CHILD_SHA)
            self.assertNotIn(gui.secure.CORRELATION,source)
            self.assertIn(gui._PHASES[phase][0],source);self.assertIn(gui._PHASES[phase][1],source)
            self.assertEqual(source.count("'guest-exec',"),1)
            self.assertNotIn("'send-key'",source);self.assertNotIn('LogonUser',source)
        with self.assertRaises(ValueError):gui._fresh_reader({},'foreign')
        with patch.object(gui.secure,'_PARENT',gui.secure._PARENT+'\nforeign'):
            with self.assertRaises(ValueError):gui._fresh_reader(fixtures.ScreenTests().record(),'typing')

class ActualRemoteActionTests(unittest.TestCase):
    def _action_flow(self,variant='positive'):
        import io,json,os,socket,struct,tempfile,time,types
        from pathlib import Path
        with tempfile.TemporaryDirectory()as d:
            parent=Path(d);os.chmod(parent,0o700);packets=[];sample=b'P6\n1 1\n255\n'+b'\0'*3;pid=111
            if variant=='large-success':sample=b'P6\n1280 800\n255\n'+__import__('random').Random(99).randbytes(1280*800*3)
            class Stream:
                def __init__(self):self.greet=True
                def readline(self,*args):
                    if self.greet:self.greet=False;return b'{"QMP":{}}\n'
                    return json.dumps({'id':packets[-1]['id'],'return':{}}).encode()+b'\n'
                def close(self):pass
            class Socket:
                def settimeout(self,v):pass
                def connect(self,path):pass
                def getsockopt(self,*a):return struct.pack('3i',pid+1 if variant=='foreign-peer'else pid,os.geteuid(),os.getgid())
                def makefile(self,mode):return Stream()
                def sendall(self,raw):
                    p=json.loads(raw);packets.append(p)
                    if p['execute']=='screendump':Path(p['arguments']['filename']).write_bytes(sample)
                    if p['execute']=='send-key':
                        job=parent/('cp117-gui-'+gui.CORRELATION+('-wake'if variant.startswith('wake')else''))
                        required='wake-attempt.json'if variant.startswith('wake')else'enter-attempt.json'if p['arguments']['keys']==[{'type':'qcode','data':'ret'}]else'typing-attempt.json'
                        self_check.assertTrue((job/required).exists())
                        if variant in('partial','wake-partial'):raise OSError('lost-response')
                def close(self):pass
            self_check=self
            source=inspect_source=__import__('inspect').getsource(gui._remote_input_action)
            ns={'os':os,'json':json,'time':time,'hashlib':hashlib,'base64':base64,'TRANSFER':d,'FLOW':gui.CORRELATION,'pid':456,'LEAF':'fixed','children':[{}, {'child':{'pid':111}}],'NONCE':'fixed','BODY_SHA':'fixed','guards':lambda:None,'need':lambda v,p:None if v else (_ for _ in()).throw(ValueError(p)),'fp':lambda s:{k:getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},'validate_ppm':gui.login.validate_ppm,'_effect_gate':lambda *a:None,'_screen_gate':lambda *a:None}
            checks=[]
            def gate(*args):
                checks.append(1)
                if variant=='photo-refusal':raise ValueError('gui-selected-account-field-or-caps')
                if variant=='expiry'and len(checks)>=4:raise ValueError('gui-focus-expired')
            ns['_effect_gate']=gate
            exec(source,ns)
            ns['_validate_lockscreen']=lambda raw:None
            exec(__import__('inspect').getsource(gui.login._guarded_wake),ns)
            with patch('socket.socket',return_value=Socket()),patch.object(socket,'SO_PEERCRED',17,create=True),patch('time.sleep'):
                if variant.startswith('wake'):
                    if variant=='wake-partial':
                        with self.assertRaises(OSError):ns['_remote_input_action']({},time.monotonic(),'wake',[],None)
                    else:
                        value=ns['_remote_input_action']({},time.monotonic(),'wake',[],None);self.assertEqual(value['phase'],'woken')
                    self.assertEqual([p['arguments']['keys']for p in packets if p['execute']=='send-key'],[[{'type':'qcode','data':'ret'}]])
                    with self.assertRaises(FileExistsError):ns['_remote_input_action']({},time.monotonic(),'wake',[],None)
                    self.assertEqual(sum(p['execute']=='send-key'for p in packets),1);return
                if variant in('partial','foreign-peer','expiry','photo-refusal'):
                    with self.assertRaises((ValueError,OSError))as caught:ns['_remote_input_action']({},time.monotonic(),'typing',[['a'],['shift','b']],None)
                    if variant=='photo-refusal':
                        frame=caught.exception.frameAuthority['frames']['typing-before.ppm'];self.assertEqual(frame['sha256'],hashlib.sha256(sample).hexdigest());self.assertTrue((parent/('cp117-gui-'+gui.CORRELATION)/'typing-before.ppm.json').exists())
                    count=sum(p['execute']=='send-key'for p in packets)
                    self.assertEqual(count,1 if variant in('partial','expiry')else 0)
                    with self.assertRaises(FileExistsError):ns['_remote_input_action']({},time.monotonic(),'typing',[['a']],None)
                    self.assertEqual(sum(p['execute']=='send-key'for p in packets),count);return
                typed=ns['_remote_input_action']({},time.monotonic(),'typing',[['a'],['shift','b']],None)
                self.assertEqual(typed['phase'],'typed')
                if variant in('typed-drift','typed-frame-drift'):
                    path=parent/('cp117-gui-'+gui.CORRELATION)/('typing-after.ppm'if variant=='typed-frame-drift'else'typed.json');raw=path.read_bytes();path.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError,'gui-frame-pin'if variant=='typed-frame-drift'else'gui-record-pin'):ns['_remote_input_action']({},time.monotonic(),'enter',[],typed['hostAuthority'])
                    self.assertEqual(sum(p['execute']=='send-key'for p in packets),2);return
                entering=ns['_remote_input_action']({},time.monotonic(),'enter',[],typed['hostAuthority'])
            keys=[p['arguments']['keys']for p in packets if p['execute']=='send-key']
            self.assertEqual(keys,[[{'type':'qcode','data':'a'}],[{'type':'qcode','data':'shift'},{'type':'qcode','data':'b'}],[{'type':'qcode','data':'ret'}]])
            self.assertEqual(entering['phase'],'entered')
            # A lost original outcome cannot retype or press Enter again.
            before=len(keys)
            with patch('socket.socket',return_value=Socket()),patch.object(socket,'SO_PEERCRED',17,create=True),patch('time.sleep'):
                with self.assertRaises(FileExistsError):ns['_remote_input_action']({},time.monotonic(),'typing',[['a']],None)
                with self.assertRaises((FileExistsError,ValueError)):ns['_remote_input_action']({},time.monotonic(),'enter',[],typed['hostAuthority'])
            self.assertEqual(sum(p['execute']=='send-key'for p in packets),before)

    def test_real_large_valid_photo_success_retains_metadata_without_inline_cap(self):self._action_flow('large-success')
    def test_actual_typing_fences_then_exact_original_authority_enters_once(self):self._action_flow()
    def test_partial_input_no_retype_or_enter(self):self._action_flow('partial')
    def test_actual_guarded_wake_fences_before_one_enter_no_replay(self):self._action_flow('wake')
    def test_partial_wake_never_presses_enter_again(self):self._action_flow('wake-partial')
    def test_failed_photo_retains_original_fd_metadata_before_guard_refusal(self):self._action_flow('photo-refusal')
    def test_expiry_during_input_stops_without_retype(self):self._action_flow('expiry')
    def test_foreign_qmp_peer_has_zero_keys(self):self._action_flow('foreign-peer')
    def test_same_byte_original_typed_photo_rewrite_refuses_enter(self):self._action_flow('typed-frame-drift')
    def test_same_byte_typed_record_rewrite_refuses_enter(self):self._action_flow('typed-drift')

class ClosedFactoryCausalTests(unittest.TestCase):
    def test_unreviewed_action_tail_refused_before_generated_dispatch(self):
        original=gui.inspect.getsource
        def changed(function):
            raw=original(function)
            return raw+"\nos.system('foreign')\n"if function is gui._remote_input_action else raw
        with patch.object(gui.inspect,'getsource',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'gui-support-source'):gui._phase_program(fixtures.ScreenTests().record(),'typing')
    def test_changed_phase_nonce_refused_by_exact_ps_digest(self):
        catalog=dict(gui._PHASES);catalog['typing']=('57836929-c56c-470c-ae27-0207a7933fe2','foreign')
        with patch.object(gui,'_PHASES',catalog):
            with self.assertRaisesRegex(ValueError,'gui-reader-source'):gui._fresh_reader(fixtures.ScreenTests().record(),'typing')

class WholePhaseCompositionTests(unittest.TestCase):
    def execute_flow(self,stale=False,foreign=False,invalid_input=False,phase='typing'):
        import io,types,signal
        o=gui.login.guest;recipe=o.recovery.recipe();request={'recipeSha256':o.recovery._digest(recipe)}
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        sockets['swtpm.sock']=o.TPM_SOCKET
        record={'request':request,'authority':proof,'result':{'state':'running','sockets':sockets}}
        diagnostic,nonce=gui._PHASES[phase];source,sha,childsha=gui._phase_program(record,phase);tree=ast.parse(source)
        # Execute every generated definition/constant, then the unchanged entire
        # operation. Only OS/transport authority observations are inert fixtures.
        self.assertIsInstance(tree.body[-1],ast.Try)
        ns={}
        with patch('signal.signal'),patch('signal.setitimer'):
            exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'complete-generated-definitions','exec'),ns)
        class FakeOS:
            O_RDONLY=0;O_DIRECTORY=0;O_NOFOLLOW=0
            def open(self,*a):return 1
            def fstat(self,*a):return types.SimpleNamespace(**identity)
            def lstat(self,path):
                if path.endswith('.sock'):return sockets[path.split('/')[-1]]['fingerprint']
                if path in recipe['files']:return types.SimpleNamespace(**recipe['files'][path]['fingerprint'])
                return types.SimpleNamespace(**identity)
            def listdir(self,path):return ['0','1','2']
            def stat(self,path):
                paths=(o.recovery.DISK,o.recovery.BACKING,o.recovery.VARS)
                return types.SimpleNamespace(**recipe['files'][paths[int(path.split('/')[-1])]]['fingerprint'])
        queries=[];anchors=[];out=io.StringIO();err=io.StringIO()
        def protected_read(name,pin):
            anchors.append(name)
            if name=='intent.json':return request
            if name=='attempt.json':return {'state':'consumed','requestSha256':o.recovery._digest(request)}
            return next(c['child']for c in children if name==c['role']+'.json')
        def call(path,op,args):
            queries.append((op,args))
            if op=='guest-exec':return {'pid':456}
            answer=secure_fixtures.SecureLayoutTests().answer();answer['reader']['nonce']=nonce;answer['birth']['nonce']=nonce;answer['reader']['sourceSha256']=childsha;answer['birth']['sourceSha256']=childsha
            raw=('CP117-READ '+('old'if stale else nonce)+' '+sha+' 456\n'+json.dumps(answer)).encode()
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        def rows(path):
            name=path.split('/')[-1];inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'pid':456})
        ns.update(os=FakeOS(),fp=lambda s:s if isinstance(s,dict)else vars(s),read=protected_read,leaf_check=lambda:None,child_guard=lambda c,a:None,unix_rows=rows,fd_socket_inodes=lambda p:{s['kernelInode']for s in sockets.values()},call=call,open=lambda p:io.StringIO(recipe['bootId']),sys=types.SimpleNamespace(stderr=err,stdin=io.TextIOWrapper(io.BytesIO((0 if phase=='wake'else 2 if invalid_input else 1).to_bytes(4,'big')+(b''if phase=='wake'else b'a\n'if invalid_input else b'a')+(ack+'\n').encode()))),time=types.SimpleNamespace(sleep=lambda n:None,monotonic=lambda:0),result=lambda v:out.write(json.dumps(v)))
        actions=[]
        def action(answer,started,phase,keys,prior):
            actions.append((phase,keys,prior));return {'state':'observed','phase':'typed'}
        ns['_remote_input_action']=action
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer'):
            exec(compile(ast.Module(body=tree.body[-1:],type_ignores=[]),'complete-generated-operation','exec'),ns)
        return json.loads(out.getvalue()),queries,anchors,actions

    def test_complete_actual_phase_consumes_secret_before_one_submit_then_same_pid(self):
        result,calls,anchors,actions=self.execute_flow()
        self.assertEqual(result['state'],'observed');self.assertEqual(actions,[('typing',[['a']],None)])
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
        self.assertTrue({'intent.json','attempt.json','tpm.json','qemu.json'}<=set(anchors))
    def test_complete_actual_wake_has_zero_private_input_one_submit(self):
        result,calls,anchors,actions=self.execute_flow(phase='wake')
        self.assertEqual(result['state'],'observed');self.assertEqual(actions,[('wake',[],None)])
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status'])
    def test_invalid_complete_input_has_zero_guest_submission_or_action(self):
        result,calls,anchors,actions=self.execute_flow(invalid_input=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(calls,[]);self.assertEqual(actions,[])
    def test_stale_terminal_never_types_and_polls_only_original_child(self):
        result,calls,anchors,actions=self.execute_flow(stale=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(len(calls),81);self.assertEqual(actions,[])
        self.assertTrue(all(args=={'pid':456}for op,args in calls if op=='guest-exec-status'))

class ConsumedLocalFlowTests(unittest.TestCase):
    def test_existing_local_flow_never_dispatches_or_reads_secret(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'.runtime/parity-evidence'/('windows-cp117-gui-login-'+gui.CORRELATION)).mkdir(parents=True)
            with patch.object(gui,'_stream')as stream,patch.object(gui.login,'_configured_secret')as secret:
                value=gui.start(root)
            self.assertEqual(value['phase'],'gui-consumed');stream.assert_not_called();secret.assert_not_called()

class HistoricalProofSchemaCausalTests(unittest.TestCase):
    def run_gate(self,proof):
        import inspect
        tree=ast.parse(inspect.getsource(gui.start))
        node=next(n for n in ast.walk(tree)if isinstance(n,ast.If)and any(isinstance(x,ast.Constant)and x.value=='gui-historical-credential-proof'for x in ast.walk(n)))
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-historical-proof-gate','exec'),{'proof':proof,'credential_pin':{'generation':[1,2,3]},'login':gui.login})
    def proof(self):return {'state':'derived','credential':{'success':True,'expectedSid':gui.login.guest.SID},'currentConfiguredCredentialGeneration':[1,2,3],'historicalCredentialInputGenerationIndependentlyProven':False,'currentVmAdmission':False}
    def test_actual_derived_schema_with_explicit_limits_is_accepted(self):self.run_gate(self.proof())
    def test_failure_sid_current_generation_or_overclaimed_authority_refused(self):
        for update in ({'state':'observed'},{'historicalCredentialInputGenerationIndependentlyProven':True},{'currentVmAdmission':True},{'currentConfiguredCredentialGeneration':[9]}, {'credential':{'success':False,'expectedSid':gui.login.guest.SID}},{'credential':{'success':True,'expectedSid':'foreign'}}):
            proof=self.proof();proof.update(update)
            with self.assertRaises(ValueError):self.run_gate(proof)

class ProspectiveWakeCausalTests(unittest.TestCase):
    def test_fixed_wake_program_has_new_read_and_original_guarded_one_enter(self):
        source,sha,childsha=gui._phase_program(fixtures.ScreenTests().record(),'wake')
        self.assertEqual(source.count("'guest-exec',"),1)
        self.assertIn("_guarded_wake(before",source)
        self.assertIn("phase+'-attempt.json'",source)
        self.assertNotIn(gui.login.WAKE_CORRELATION,source)
    def test_wake_profile_refuses_login_field_and_stale_layout_or_image(self):
        answer=secure_fixtures.ActualInputDestinationCausalTests().measured_answer()
        with patch.object(gui.login,'_validate_lockscreen',side_effect=ValueError('foreign-profile')):
            with self.assertRaisesRegex(ValueError,'foreign-profile'):gui._effect_gate(answer,1,b'login-screen',1,None)

class ReviewedNativeProfileCausalTests(unittest.TestCase):
    native=('5d0c1ff177801e0869d4a61cfeb979f6ed8748e8e05147f357825f4b3c7d4822','1011eb69fa040bb40c3320eeab05483f27daabd723a7e18ad86d79a20fd9890b','3ad44c3c1045da71622a06150c9daa8c7faf42116aca2b34032f2cf734f27d70','7490be5176e9bff4862d1de9943f6422f981438b6b7867e238311dbbb09a542f')
    def crops(self,values):return dict(zip([r for r,_ in gui._PROFILE+[gui._EMPTY]],values))
    def test_actual_reviewed_92f_native_whole_profile_accepts(self):
        values=self.crops(self.native)
        with patch.object(gui,'_crop_sha',side_effect=lambda raw,rect:values[rect]):gui._screen_gate(b'actual-native-crops',1,True)
    def test_mixed_profile_filled_caps_or_foreign_account_refuse_typing(self):
        old=tuple(h for _,h in gui._PROFILE+[gui._EMPTY])
        variants=[tuple(self.native[i]if i==j else old[i]for i in range(4))for j in range(4)]
        variants+=[tuple('foreign'if i==j else self.native[i]for i in range(4))for j in range(4)]
        for variant in variants:
            values=self.crops(variant)
            with patch.object(gui,'_crop_sha',side_effect=lambda raw,rect:values[rect]):
                with self.assertRaises(ValueError):gui._screen_gate(b'fixture',1,True)
