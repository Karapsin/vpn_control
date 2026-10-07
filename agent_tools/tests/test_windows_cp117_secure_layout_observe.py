import ast,base64,copy,hashlib,inspect,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import windows_cp117_secure_layout_observe as secure
from agent_tools.tests import test_windows_cp117_recovered_login as fixtures

class SecureLayoutTests(unittest.TestCase):
    def answer(self):
        facts=fixtures.LayoutTests().facts();reader={'nonce':secure.NONCE,'pid':999,'parentPid':456,'sessionId':1,'expectedSystem':True,'creationFileTime':'133400000000000000','sourceSha256':secure.CHILD_SHA,'focus':[{'threadId':111,'windowThreadId':111,'ownerPid':1096,'hkl':'0000000004090409','hasFocus':True,'error':0},{'threadId':222,'windowThreadId':0,'ownerPid':0,'hkl':'0000000004090409','hasFocus':False,'error':0}]};birth={k:reader[k]for k in('nonce','pid','parentPid','sessionId','sourceSha256','creationFileTime')};birth['applicationSha256']='A'*64
        return {'facts':facts,'reader':reader,'birth':birth}
    def terminal(self,answer=None,nonce=None):
        raw=('CP117-READ '+(nonce or secure.NONCE)+' '+secure.PARENT_SHA+' 456\n'+json.dumps(answer or self.answer())).encode()
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
    def test_parent_source_changed_tail_rejected_before_guest_dispatch(self):
        with patch.object(secure,'_PARENT',secure._PARENT+'\nStop-Service Foreign\n'):
            with self.assertRaisesRegex(ValueError,'secure-parent-source'):secure.program(fixtures.ScreenTests().record(),secure.NONCE)
    def test_actual_session0_layout_cannot_become_session1_authority(self):
        answer=self.answer();secure.login._validate_us_layout(answer['facts'])
        answer['reader']['sessionId']=0;answer['birth']['sessionId']=0
        with self.assertRaisesRegex(ValueError,'secure-reader-binding'):secure.secure_terminal(self.terminal(answer),secure.NONCE,secure.PARENT_SHA,456)
    def test_observed_zero_hkls_stay_refused_even_with_default_us(self):
        answer=self.answer()
        for r in answer['facts']['layout']['threads']:r['hkl']='0000000000000000'
        for r in answer['reader']['focus']:r['hkl']='0000000000000000'
        with self.assertRaises(ValueError):secure.secure_terminal(self.terminal(answer),secure.NONCE,secure.PARENT_SHA,456)
    def test_focused_original_secure_us_reader_accepts(self):
        self.assertEqual(secure.secure_terminal(self.terminal(),secure.NONCE,secure.PARENT_SHA,456),self.answer())
    def test_reader_generation_sid_session_source_and_focus_drifts_refused(self):
        for change in(lambda a:a['reader'].update(expectedSystem=False),lambda a:a['reader'].update(sourceSha256='0'*64),lambda a:a['reader'].update(pid=888),lambda a:a['birth'].update(creationFileTime='other'),lambda a:a['reader']['focus'][0].update(ownerPid=88),lambda a:a['reader']['focus'][0].update(windowThreadId=99),lambda a:a['reader']['focus'][0].update(hasFocus=False),lambda a:a['reader']['focus'][0].update(hkl='0000000004190419')):
            answer=copy.deepcopy(self.answer());change(answer)
            with self.assertRaises(ValueError):secure.secure_terminal(self.terminal(answer),secure.NONCE,secure.PARENT_SHA,456)
    def test_stale_or_reused_parent_terminal_rejected(self):
        self.assertIsNone(secure.secure_terminal(self.terminal(nonce='old'),secure.NONCE,secure.PARENT_SHA,456))
        self.assertIsNone(secure.secure_terminal(self.terminal(),secure.NONCE,secure.PARENT_SHA,789))
    def test_generated_parser_complete_namespace(self):
        source,sha=secure.program(fixtures.ScreenTests().record(),secure.NONCE);compile(source,'secure','exec');tree=ast.parse(source)
        names={'_validate_session_facts','_validate_layout_facts','_validate_us_layout','validate_layout','validate_focus','secure_terminal'}
        defs=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in names]
        self.assertEqual(len(defs),len(names));ns={'base64':base64,'json':json,'UI':secure.UI,'CHILD_SHA':secure.CHILD_SHA}
        exec(compile(ast.Module(body=defs,type_ignores=[]),'actual-secure-parser','exec'),ns)
        self.assertEqual(ns['secure_terminal'](self.terminal(),secure.NONCE,sha,456),self.answer())
    def test_actual_windows_command_length_uses_fixed_bounded_stdin(self):
        parent,child,_=secure.bodies(secure.NONCE)
        # The naïve nested EncodedCommand exceeds CreateProcess' command limit.
        self.assertGreater(len(base64.b64encode(parent.encode('utf-16le'))),32768)
        source,sha=secure.program(fixtures.ScreenTests().record(),secure.NONCE);tree=ast.parse(source)
        encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
        self.assertLess(len(encoded),30000);self.assertLess(len(base64.b64encode(child.encode('utf-16le'))),30000)
        bootstrap=base64.b64decode(encoded).decode('utf-16le');self.assertIn(sha,bootstrap);self.assertIn('SOURCE_HASH',bootstrap)
        self.assertEqual(source.count("'guest-exec',"),1);self.assertEqual(source.count("'input-data':"),1)
        self.assertNotIn('LogonUser',source);self.assertNotIn("'send-key'",source)
    def test_actual_generated_attempt_and_birth_precede_launch_and_resume(self):
        parent,child,sha=secure.bodies(secure.NONCE)
        self.assertLess(parent.index("WritePrivate 'attempt.json'"),parent.index('::Suspended('))
        self.assertLess(parent.index("WritePrivate 'child.json'"),parent.index('::Resume('))
        self.assertIn('$f.Flush($true)',parent)
        self.assertIn('0x08000004',secure._NATIVE);self.assertIn('s.desktop=@"WinSta0\\Winlogon"',secure._NATIVE)
        self.assertIn('OpenProcessToken(GetCurrentProcess()',secure._NATIVE)
        self.assertNotIn('OpenProcess(1096',secure._NATIVE)
        self.assertIn('$birth.creationFileTime -cne $selfCreation',child)
        self.assertIn('25000',parent);self.assertIn('20000',child);self.assertIn('40000',secure._NATIVE)
    def test_existing_consumed_native_attempt_has_no_replay(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'.runtime/parity-evidence'/('windows-cp117-secure-layout-'+secure.CORRELATION)).mkdir(parents=True)
            with patch.object(secure.login.guest,'_stream')as stream:
                result=secure.observe(root)
            self.assertEqual(result['phase'],'secure-consumed');stream.assert_not_called()
    def test_fixed_nonce_and_child_native_catalog(self):
        with self.assertRaises(ValueError):secure.program(fixtures.ScreenTests().record(),'different')
        for name in('_NATIVE','_FOCUS_CS','_CHILD_HEAD'):
            with patch.object(secure,name,getattr(secure,name)+'\nforeign\n'):
                with self.assertRaises(ValueError):secure.program(fixtures.ScreenTests().record(),secure.NONCE)

class CompleteGeneratedFlowTests(unittest.TestCase):
    answer=SecureLayoutTests.answer
    terminal=SecureLayoutTests.terminal
    def execute_flow(self,stale=False,foreign=False):
        import io,types
        o=secure.login.guest;recipe=o.recovery.recipe();request={'recipeSha256':o.recovery._digest(recipe)}
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        sockets['swtpm.sock']=o.TPM_SOCKET
        record={'request':request,'authority':proof,'result':{'state':'running','sockets':sockets}}
        source,sha=secure.program(record,secure.NONCE);tree=ast.parse(source)
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
            return self.terminal(nonce='old'if stale else None)
        def rows(path):
            name=path.split('/')[-1];inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':secure.CORRELATION,'nonce':secure.NONCE,'sourceSha256':sha,'pid':456})
        ns.update(os=FakeOS(),fp=lambda s:s if isinstance(s,dict)else vars(s),read=protected_read,leaf_check=lambda:None,child_guard=lambda c,a:None,unix_rows=rows,fd_socket_inodes=lambda p:{s['kernelInode']for s in sockets.values()},call=call,open=lambda p:io.StringIO(recipe['bootId']),sys=types.SimpleNamespace(stderr=err,stdin=io.StringIO(ack+'\n')),time=types.SimpleNamespace(sleep=lambda n:None),result=lambda v:out.write(json.dumps(v)))
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer'):
            exec(compile(ast.Module(body=tree.body[-1:],type_ignores=[]),'complete-generated-operation','exec'),ns)
        return json.loads(out.getvalue()),queries,anchors
    def test_complete_generated_one_submit_fixed_child_and_public_source_input(self):
        result,calls,anchors=self.execute_flow()
        self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.answer())
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
        payload=base64.b64decode(calls[0][1]['input-data'],validate=True);parent,_,_=secure.bodies(secure.NONCE)
        self.assertEqual(int.from_bytes(payload[:4],'big'),len(payload)-4);self.assertEqual(payload[4:],parent.encode())
        self.assertTrue({'intent.json','attempt.json','tpm.json','qemu.json'}<=set(anchors))
    def test_complete_generated_stale_terminal_exhausts_original_pid_only(self):
        result,calls,_=self.execute_flow(stale=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],'guest-observation-exhausted')
        self.assertEqual(len(calls),81);self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1)
        self.assertTrue(all(args=={'pid':456}for op,args in calls if op=='guest-exec-status'))
    def test_complete_generated_foreign_listener_has_no_submit(self):
        result,calls,_=self.execute_flow(foreign=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(calls,[])

class StandaloneImportCausalTests(unittest.TestCase):
    def test_actual_package_observer_import_requires_absolute_standalone_route(self):
        # The first ignored standalone observer copied this actual import and
        # failed before dispatch. Execute that exact import in its actual lost
        # package context, then the narrowly corrected standalone import.
        imports=[n for n in ast.walk(ast.parse(inspect.getsource(secure.observe)))if isinstance(n,ast.ImportFrom)and n.level==1]
        self.assertEqual(len(imports),1)
        with self.assertRaises(ImportError):
            exec(compile(ast.Module(body=imports,type_ignores=[]),'original-standalone-import','exec'),{'__package__':None,'__name__':'__main__'})
        fixed=copy.deepcopy(imports[0]);fixed.level=0;fixed.module='agent_tools';ns={'__package__':None,'__name__':'__main__'}
        exec(compile(ast.Module(body=[fixed],type_ignores=[]),'fixed-standalone-import','exec'),ns)
        self.assertIs(ns['session'],secure.login.session)

class ActualInputDestinationCausalTests(unittest.TestCase):
    answer=SecureLayoutTests.answer
    def measured_answer(self):
        answer=self.answer()
        # Source/nonce/PID-bound native3469 observation: ten US HKLs,
        # seven zero/error87/windowless rows; actual input focus3656/UI1096.
        ids=[604,1100,1152,1156,1180,1332,1936,2608,2672,3284,3632,3656,3712,3756,3848,3852,3964]
        unresolved={1156,1332,2608,2672,3284,3632,3964}
        answer['facts']['layout']['threadCount']=len(ids)
        answer['facts']['layout']['threads']=[{'threadId':i,'hkl':'0000000000000000'if i in unresolved else '0000000004090409'}for i in ids]
        answer['reader']['focus']=[{'threadId':i,'windowThreadId':3656 if i==3656 else 0,'ownerPid':1096 if i==3656 else 0,'hkl':'0000000000000000'if i in unresolved else '0000000004090409','hasFocus':i==3656,'error':87 if i in unresolved else 0}for i in ids]
        return answer
    def test_actual_ten_us_seven_unresolved_reject_old_predicate_accept_input_proof(self):
        answer=self.measured_answer()
        with self.assertRaisesRegex(ValueError,'layout-us-unproven'):secure.login._validate_us_layout(answer['facts'])
        secure.validate_focus(answer)
    def test_input_proof_refuses_zero_gui_success_zero_focus_and_foreign_hkl(self):
        for change in (lambda a:a['reader']['focus'][3].update(error=0),lambda a:a['reader']['focus'][3].update(error=5),lambda a:a['reader']['focus'][3].update(ownerPid=1096),lambda a:a['reader']['focus'][3].update(windowThreadId=1156),lambda a:a['reader']['focus'][11].update(ownerPid=999),lambda a:a['reader']['focus'][11].update(hasFocus=False),lambda a:a['facts']['layout']['preload'][0].update(value='00000419'),lambda a:a['facts']['layout'].update(substitutes=[{'name':'a','value':'b'}])):
            answer=self.measured_answer();change(answer)
            with self.assertRaises(ValueError):secure.validate_focus(answer)
        for index,value in ((11,'0000000000000000'),(0,'0000000004190419')):
            answer=self.measured_answer();answer['facts']['layout']['threads'][index]['hkl']=value;answer['reader']['focus'][index]['hkl']=value
            with self.assertRaises(ValueError):secure.validate_focus(answer)
    def test_complete_generated_actual_input_destination_proof(self):
        fixture=CompleteGeneratedFlowTests();fixture.answer=self.measured_answer
        result,calls,_=fixture.execute_flow()
        self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.measured_answer())
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status'])
        self.assertEqual(calls[1][1],{'pid':456})
