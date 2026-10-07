import ast,base64,copy,json,unittest
from unittest.mock import patch
from agent_tools import windows_cp117_recovered_owner_observe as owner
class OwnerFactsTests(unittest.TestCase):
    def facts(self):
        p={'pid':123,'startFileTime':'134355320000000000','sessionId':1,'expectedSid':True,'elevated':False,'elevationType':3,'adminMember':True,'adminEnabled':False}
        return {'version':1,'account':{'expectedSid':True,'enabled':True,'local':True},'profile':{'expectedSid':True,'expectedPath':True,'loaded':True},'explorers':[p],'apps':[],'runtimeCount':0,'installerCount':0,'publicStatusObserved':False}
    def test_filtered_ordinary_target_token_membership_measured_not_current_system(self):
        value=self.facts();self.assertEqual(owner.validate_facts(value),value)
        for fields in({'expectedSid':False},{'elevated':True},{'adminEnabled':True},{'elevationType':2},{'sessionId':0}):
            value=self.facts();value['explorers'][0].update(fields)
            with self.assertRaises(ValueError):owner.validate_facts(value)
    def test_missing_or_foreign_profile_and_process_counts_refuse(self):
        for mutate in(lambda v:v['profile'].update(loaded=False),lambda v:v['explorers'].clear(),lambda v:v['explorers'].append(copy.deepcopy(v['explorers'][0])),lambda v:v.update(runtimeCount=1),lambda v:v.update(installerCount=1),lambda v:v.update(publicStatusObserved=True)):
            value=self.facts();mutate(value)
            with self.assertRaises(ValueError):owner.validate_facts(value)

class WholeOwnerReaderTests(unittest.TestCase):
    def execute_flow(self,stale=False,foreign=False):
        import io,types,signal
        o=owner.guest;recipe=o.recovery.recipe();request={'recipeSha256':o.recovery._digest(recipe)}
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        sockets['swtpm.sock']=o.TPM_SOCKET
        record={'request':request,'authority':proof,'result':{'state':'running','sockets':sockets}}
        source,sha=owner.program(record);tree=ast.parse(source)
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
            raw=('CP117-READ '+('old'if stale else owner.NONCE)+' '+sha+' 456\n'+json.dumps(OwnerFactsTests().facts())).encode()
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        def rows(path):
            name=path.split('/')[-1];inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':owner.CORRELATION,'nonce':owner.NONCE,'sourceSha256':sha,'pid':456})
        ns.update(os=FakeOS(),fp=lambda s:s if isinstance(s,dict)else vars(s),read=protected_read,leaf_check=lambda:None,child_guard=lambda c,a:None,unix_rows=rows,fd_socket_inodes=lambda p:{s['kernelInode']for s in sockets.values()},call=call,open=lambda p:io.StringIO(recipe['bootId']),sys=types.SimpleNamespace(stderr=err,stdin=io.StringIO(ack+'\n')),time=types.SimpleNamespace(sleep=lambda n:None),result=lambda v:out.write(json.dumps(v)))
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer'):
            exec(compile(ast.Module(body=tree.body[-1:],type_ignores=[]),'complete-generated-operation','exec'),ns)
        return json.loads(out.getvalue()),queries,anchors

    def test_actual_generated_readonly_flow_one_submit_original_pid_and_schema(self):
        value,calls,anchors=self.execute_flow();self.assertEqual(value['facts'],OwnerFactsTests().facts())
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
        self.assertTrue({'intent.json','attempt.json','tpm.json','qemu.json'}<=set(anchors))
    def test_stale_result_same_pid_only_original_cap(self):
        value,calls,_=self.execute_flow(stale=True);self.assertEqual(value['state'],'unknown');self.assertEqual(len(calls),81)
        self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1)
    def test_foreign_listener_no_query(self):
        value,calls,_=self.execute_flow(foreign=True);self.assertEqual(value['state'],'unknown');self.assertEqual(calls,[])
    def test_fixed_body_and_original_transport_tail_refused(self):
        from agent_tools.tests import test_windows_cp117_recovered_login as fixture
        with patch.object(owner,'_TOKEN_CS',owner._TOKEN_CS+'\nforeign'):
            with self.assertRaisesRegex(ValueError,'owner-fixed-source'):owner.program(fixture.ScreenTests().record())
        with patch.object(owner.guest,'_REMOTE',owner.guest._REMOTE+'\nforeign'):
            with self.assertRaisesRegex(ValueError,'owner-original-reader-source'):owner.program(fixture.ScreenTests().record())
    def test_consumed_query_has_no_replay(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'.runtime/parity-evidence'/('windows-cp117-owner-observe-'+owner.CORRELATION)).mkdir(parents=True)
            with patch.object(owner.guest,'_stream')as stream:value=owner.observe(root)
            self.assertEqual(value['phase'],'owner-consumed');stream.assert_not_called()
