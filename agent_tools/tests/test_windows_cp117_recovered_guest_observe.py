import os
import socket
import sys
import tempfile
import unittest
from agent_tools import windows_cp117_recovered_guest_observe as o

class SocketGraphTests(unittest.TestCase):
    def rows(self):
        return [dict(flags='00010000',type='0001',state='01',inode='456'),dict(flags='00000000',type='0001',state='03',inode='457')]
    def test_actual_measured_listener_and_accept(self):
        rows=self.rows()
        self.assertNotEqual(len(rows),1)  # Original socket_guard rejects this graph.
        self.assertEqual(o.validate_socket_rows(rows,{'456','457'},'456'),['456','457'])
    def test_foreign_accepted_row_refused(self):
        with self.assertRaises(ValueError):o.validate_socket_rows(self.rows(),{'456'},'456')
    def test_reused_listener_refused(self):
        with self.assertRaises(ValueError):o.validate_socket_rows(self.rows(),{'456','457'},'999')
    def test_extra_listener_or_duplicate_refused(self):
        for row in (self.rows()[0],dict(flags='00010000',type='0001',state='01',inode='458')):
            with self.assertRaises(ValueError):o.validate_socket_rows(self.rows()+[row],{'456','457','458'},'456')
    def test_unknown_shapes_refused(self):
        for change in ({'state':'02'},{'type':'0002'},{'flags':'00000001'},{'inode':'bad'}):
            rows=self.rows();rows[1].update(change)
            with self.assertRaises(ValueError):o.validate_socket_rows(rows,{'456','457','bad'},'456')
    @unittest.skipUnless(sys.platform.startswith('linux'),'Actual /proc/net/unix graph requires Linux')
    def test_real_listen_accept_graph(self):
        with tempfile.TemporaryDirectory() as d:
            path=d+'/s';listener=socket.socket(socket.AF_UNIX);client=socket.socket(socket.AF_UNIX)
            try:
                listener.bind(path);listener.listen(1);client.connect(path);accepted,_=listener.accept()
                try:
                    rows=o.unix_rows(path);owned=o.fd_socket_inodes(os.getpid())
                    self.assertEqual(len(rows),2)
                    pinned=next(row['inode']for row in rows if row['flags']=='00010000')
                    self.assertEqual(set(o.validate_socket_rows(rows,owned,pinned)),{r['inode']for r in rows})
                finally:accepted.close()
            finally:client.close();listener.close()

import base64
import hashlib
import inspect
import json
from pathlib import Path
from unittest.mock import patch
from agent_tools.tests.fixtures import historical_source

HISTORICAL = Path(__file__).parent / "fixtures/windows_cp117_recovery/short_socket_51538dad.source"

class GuestBindingTests(unittest.TestCase):
    nonce='172e0c53-c748-4f83-b8a8-64d3b1d73116'
    facts=dict(version=1,code='READY',installedVersion='2.1.19',productCount=1,activeCount=0,activeKinds=[],activeProcesses=[],workspaceLockPid=None,ownedExplorerCount=1)
    def terminal(self,nonce=None,sha=None,pid=456):
        out='CP117-READ %s %s %d\n%s'%(nonce or self.nonce,sha or o.BODY_SHA,pid,json.dumps(self.facts))
        return dict(exited=True,exitcode=0,**{'out-data':base64.b64encode(out.encode()).decode()})
    def test_fresh_header_preserves_original_facts(self):
        self.assertEqual(o.parse_terminal(self.terminal(),self.nonce,o.BODY_SHA,456),self.facts)
    def test_cached_same_schema_unbound_rejected(self):
        value=self.terminal();value['out-data']=base64.b64encode(json.dumps(self.facts).encode()).decode()
        self.assertEqual(json.loads(base64.b64decode(value['out-data'])),self.facts) # Old JSON-only reader accepts.
        self.assertIsNone(o.parse_terminal(value,self.nonce,o.BODY_SHA,456))
    def test_wrong_nonce_source_pid_rejected(self):
        for args in({'nonce':'old'},{'sha':'0'*64},{'pid':999}):
            self.assertIsNone(o.parse_terminal(self.terminal(**args),self.nonce,o.BODY_SHA,456))
    def test_fixed_body_tail_refused_before_catalog(self):
        with patch.object(o,'readiness_body',return_value=o.readiness_body()+'\nStop-Service ForeignService'):
            with self.assertRaisesRegex(ValueError,'fixed-readonly-body'):o.encoded_read(self.nonce)
    def test_header_precedes_unchanged_body(self):
        encoded,sha=o.encoded_read(self.nonce);raw=base64.b64decode(encoded).decode('utf-16le')
        self.assertTrue(raw.endswith(o.readiness_body()));self.assertTrue(raw.startswith('[Console]::Out.WriteLine'))
        self.assertEqual(sha,o.BODY_SHA)
    def test_truncated_and_exit_and_schema_refused(self):
        for changes in ({'out-truncated':True},{'exitcode':1}):
            with self.assertRaises(ValueError):o.parse_terminal({**self.terminal(),**changes},self.nonce,o.BODY_SHA,456)
    def test_generated_program_does_not_override_protected_read(self):
        record={'request':{'recipeSha256':o.recovery._digest(o.recovery.recipe())},'result':{'state':'running','sockets':{}},'authority':[]}
        source,_=o.program(record,self.nonce,self.nonce)
        self.assertEqual(source.count('def read('),1)
        self.assertIn('def read(name,pin):',source)
        self.assertNotIn('def read(sock,path',source)
        compile(source,'generated-observer','exec')
    def test_protocol_source_mutation_refused(self):
        record={'request':{'recipeSha256':o.recovery._digest(o.recovery.recipe())},'result':{'state':'running','sockets':{}},'authority':[]}
        with patch.object(o.recovery.authority.closure.base,'_QGA','foreign'):
            with self.assertRaisesRegex(ValueError,'qga-source'):o.program(record,self.nonce,self.nonce)

class OriginalGuardTests(unittest.TestCase):
    def test_generated_original_guard_uses_all_three_sockets(self):
        self.assertIn("names=('swtpm.sock',)if role=='tpm'else('qga.sock','qmp.sock')",o._REMOTE)
        self.assertIn("child_guard(value['child'],R[role+'Argv'])",o._REMOTE)
        self.assertIn("read(role+'.json',value['pin'])",o._REMOTE)
        self.assertIn("read('intent.json',first['intentPin'])",o._REMOTE)
        self.assertIn("read('attempt.json',first['attemptPin'])",o._REMOTE)
    def test_consumed_recovery_source_unchanged(self):
        historical=historical_source.load(HISTORICAL,o.RECOVERY_SHA)
        self.assertEqual(hashlib.sha256(Path(historical.__file__).read_bytes()).hexdigest(),o.RECOVERY_SHA)
        # Execute the real historical pure factory; no claim/observe/start call.
        self.assertEqual(historical._digest(historical.recipe()),o.recovery._digest(o.recovery.recipe()))

    def test_historical_factory_without_fcntl_never_grants_locking(self):
        import builtins
        real_import=builtins.__import__
        calls=[]
        def unavailable(name,*args,**kwargs):
            if name=='fcntl':
                calls.append(name)
                raise ModuleNotFoundError("No module named 'fcntl'",name='fcntl')
            return real_import(name,*args,**kwargs)
        with patch.object(builtins,'__import__',unavailable):
            historical=historical_source.load(HISTORICAL,o.RECOVERY_SHA)
            self.assertTrue(historical.recipe())
        self.assertEqual(calls,[])  # Isolated historical seam, no native API import.
        with tempfile.TemporaryDirectory()as directory,patch.object(builtins,'__import__',unavailable):
            with self.assertRaisesRegex(o.recovery.RecoveryUnknown,'posix-locking-unsupported'):
                with o.recovery._claim(Path(directory)):
                    self.fail('current production claim must refuse missing POSIX API')
        self.assertEqual(calls,['fcntl'])
        for name in ('flock','LOCK_SH','LOCK_EX','LOCK_NB','LOCK_UN'):
            with self.subTest(api=name),self.assertRaisesRegex(RuntimeError,'historical_native_locking_forbidden'):
                getattr(historical.fcntl,name)
        historical_source.verify(historical,HISTORICAL,o.RECOVERY_SHA)

    def test_altered_and_current_recovery_source_refused(self):
        with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):
            historical_source.load(o.recovery.__file__,o.RECOVERY_SHA)
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'altered.source';path.write_bytes(HISTORICAL.read_bytes()+b'\n# altered\n')
            with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):
                historical_source.load(path,o.RECOVERY_SHA)

    def test_mixed_current_recovery_function_refused(self):
        historical=historical_source.load(HISTORICAL,o.RECOVERY_SHA)
        historical._digest=o.recovery._digest
        with self.assertRaisesRegex(ValueError,'historical_function_binding_changed'):
            historical_source.verify(historical,HISTORICAL,o.RECOVERY_SHA)

    def test_production_observe_refuses_current_recovery_before_transport(self):
        recovery=o.recovery;authority=recovery.authority
        raw=json.dumps({'authority':[], 'request':{'sources':{'recovery':{'sha256':o.RECOVERY_SHA}}}}).encode()
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);evidence=root/'.runtime/parity-evidence';evidence.mkdir(parents=True)
            (evidence/('windows-cp117-recovery-'+recovery.CORRELATION)).mkdir(mode=0o700)
            with patch.object(recovery,'_local_read',return_value=raw), \
                    patch.object(authority,'_source_pins',return_value={}), \
                    patch.object(authority,'_read_bound_file',side_effect=lambda path:{'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest()}), \
                    patch.object(o,'_stream')as transport:
                result=o.observe(root)
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(result['phase'],'original-sources')
            self.assertFalse(result['replayAllowed'])
            transport.assert_not_called()

class StreamRetentionTests(unittest.TestCase):
    def run_script(self,script):
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();(root/'.runtime').mkdir();(root/'.runtime/parity-evidence').mkdir();(root/'.runtime/parity-evidence/test').mkdir(mode=0o700)
            capture=AuthorityCapture(root,'test')
            try:return o._stream([sys.executable,'-c',script],capture,'diag','nonce','sha',{'pid':12})
            finally:capture.close()
    def event(self,kind,**extra):
        return {'diagnosticId':'diag','nonce':'nonce','sourceSha256':'sha','qemu':{'pid':12},'kind':kind,**extra}
    def test_actual_stream_child_capture_ack_before_poll(self):
        event=self.event('submitted',pid=456)
        ack=o.recovery._digest({'diagnosticId':'diag','nonce':'nonce','sourceSha256':'sha','pid':456})
        script="import sys,json\nprint('CP117-OBSERVE '+"+repr(json.dumps(event))+",file=sys.stderr,flush=True)\nassert sys.stdin.readline().strip()=="+repr(ack)+"\nprint('{}')\n"
        value,events=self.run_script(script)
        self.assertEqual(value,{});self.assertEqual(events[0]['event']['pid'],456)
        self.assertEqual(events[0]['pin']['generation'][5],1)
    def test_actual_stream_wrong_pid_rejected_retains_original_child(self):
        events=[self.event('submitted',pid=456),self.event('poll',pid=999,poll=1,exited=False)]
        script="import sys\nprint('CP117-OBSERVE '+"+repr(json.dumps(events[0]))+",file=sys.stderr,flush=True)\nsys.stdin.readline()\nprint('CP117-OBSERVE '+"+repr(json.dumps(events[1]))+",file=sys.stderr,flush=True)\nprint('{}')"
        with self.assertRaisesRegex(ValueError,'same-child')as caught:self.run_script(script)
        self.assertEqual(caught.exception.events[0]['event']['pid'],456)
    def test_actual_stream_malformed_terminal_retains_child_and_raw(self):
        event=self.event('submitted',pid=456)
        script="import sys\nprint('CP117-OBSERVE '+"+repr(json.dumps(event))+",file=sys.stderr,flush=True)\nsys.stdin.readline()\nprint('malformed')"
        with self.assertRaises(json.JSONDecodeError)as caught:self.run_script(script)
        self.assertEqual(caught.exception.events[0]['event']['pid'],456)

class GeneratedCallgraphTests(GuestBindingTests):
    def execute(self,stale=False,foreign=False):
        import io
        import types
        recipe=o.recovery.recipe();request={'test':'bound'};leaf=recipe['leaf']
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        class FakeOS:
            O_RDONLY=0;O_DIRECTORY=0;O_NOFOLLOW=0
            def open(self,*args):return 1
            def fstat(self,*args):return types.SimpleNamespace(**identity)
            def lstat(self,path):
                if path.endswith('.sock'):return sockets[path.split('/')[-1]]['fingerprint']
                if path in recipe['files']:return types.SimpleNamespace(**recipe['files'][path]['fingerprint'])
                return types.SimpleNamespace(**identity)
            def listdir(self,path):return ['0','1','2']
            def stat(self,path):
                paths=(o.recovery.DISK,o.recovery.BACKING,o.recovery.VARS)
                return types.SimpleNamespace(**recipe['files'][paths[int(path.split('/')[-1])]]['fingerprint'])
        queries=[];anchors=[];sockets_checked=[];out=io.StringIO();err=io.StringIO()
        def protected_read(name,pin):
            anchors.append(name)
            if name=='intent.json':return request
            if name=='attempt.json':return {'state':'consumed','requestSha256':o.recovery._digest(request)}
            return next(c['child']for c in children if name==c['role']+'.json')
        def call(path,op,args):
            queries.append((op,args))
            if op=='guest-exec':return {'pid':456}
            if stale:return self.terminal(nonce='old')
            return self.terminal()
        def rows(path):
            name=path.split('/')[-1];sockets_checked.append(name);inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':'diag','nonce':self.nonce,'sourceSha256':o.BODY_SHA,'pid':456})
        ns={'os':FakeOS(),'R':recipe,'REQUEST':request,'LEAF':leaf,'fp':lambda s:s if isinstance(s,dict)else vars(s),'need':o.recovery._need,'digest':o.recovery._digest,'read':protected_read,'leaf_check':lambda:None,'child_guard':lambda c,a:None,'unix_rows':rows,'fd_socket_inodes':lambda p:{'100','101','102'},'validate_socket_rows':o.validate_socket_rows,'parse_terminal':o.parse_terminal,'call':call,'open':lambda p:io.StringIO(recipe['bootId']),'sys':types.SimpleNamespace(stderr=err,stdin=io.StringIO(ack+'\n')),'json':json,'time':types.SimpleNamespace(sleep=lambda n:None),'result':lambda v:out.write(json.dumps(v))}
        source=o._REMOTE.replace('__PROOF__',repr(proof)).replace('__DIAGNOSTIC__',repr('diag')).replace('__ENCODED__',repr('fixed')).replace('__NONCE__',repr(self.nonce)).replace('__BODY_SHA__',repr(o.BODY_SHA)).replace('__SOCKETS__',repr(sockets))
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer'):exec(source,ns)
        return json.loads(out.getvalue()),queries,anchors,sockets_checked
    def test_actual_generated_flow_one_submit_fixed_pid_fresh_success(self):
        result,calls,anchors,sockets=self.execute()
        self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.facts)
        self.assertEqual([c[0]for c in calls],['guest-exec','guest-exec-status'])
        self.assertEqual(calls[1][1],{'pid':456})
        self.assertTrue({'intent.json','attempt.json','tpm.json','qemu.json'}<=set(anchors))
        self.assertTrue({'swtpm.sock','qga.sock','qmp.sock'}<=set(sockets))
    def test_actual_generated_stale_terminal_exhausts_same_child(self):
        result,calls,_,_=self.execute(stale=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],'guest-observation-exhausted')
        self.assertEqual(len(calls),81);self.assertEqual(sum(c[0]=='guest-exec'for c in calls),1)
        self.assertTrue(all(args=={'pid':456}for op,args in calls if op=='guest-exec-status'))
    def test_actual_generated_foreign_listener_no_submit(self):
        result,calls,_,_=self.execute(foreign=True)
        self.assertEqual(result['state'],'unknown');self.assertEqual(calls,[])

class OriginalSocketCausalTests(unittest.TestCase):
    def test_unchanged_consumed_socket_guard_rejects_actual_accept_graph(self):
        import io,types
        common=o.recovery._REMOTE_COMMON.replace('__RECIPE__',repr(o.recovery.recipe())).replace('__REQUEST__','{}')
        ns={};exec(common,ns)
        path='/fixed/sock'
        rows='a: 00000002 00000000 00010000 0001 01 456 '+path+'\n'+'b: 00000003 00000000 00000000 0001 03 457 '+path+'\n'
        fake=types.SimpleNamespace(lstat=lambda p:types.SimpleNamespace(st_mode=49645,st_uid=1000),geteuid=lambda:1000,fsencode=os.fsencode)
        ns['os']=fake;ns['open']=lambda *a:io.StringIO(rows)
        with self.assertRaisesRegex(ValueError,'socket-kernel'):ns['socket_guard'](path,{'pid':123})
        self.assertEqual(o.validate_socket_rows([dict(flags='00010000',type='0001',state='01',inode='456'),dict(flags='00000000',type='0001',state='03',inode='457')],{'456','457'},'456'),['456','457'])

class CommonSourceTests(unittest.TestCase):
    def test_mutated_common_factory_rejected_before_program(self):
        with patch.object(o.recovery,'_REMOTE_COMMON',o.recovery._REMOTE_COMMON+'\nos.system("foreign")'):
            with self.assertRaisesRegex(ValueError,'recovery-common-source'):
                o.program({},'diag',GuestBindingTests.nonce)
