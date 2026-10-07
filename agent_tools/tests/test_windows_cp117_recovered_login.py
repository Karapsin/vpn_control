import hashlib,os,json,stat,tempfile,unittest,uuid
from pathlib import Path
from unittest.mock import patch
from agent_tools import windows_cp117_recovered_login as login
from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture

class ScreenTests(unittest.TestCase):
    diagnostic='bb6c3716-2f3a-4dba-a7ea-a46078475969'
    def record(self):
        return {'request':{'recipeSha256':login.guest.recovery._digest(login.guest.recovery.recipe())},'result':{'state':'running','sockets':{}},'authority':[]}
    def ppm(self):return b'P6\n2 1\n255\n'+b'\0'*6
    def test_readonly_program_has_no_guest_execution_or_keyboard(self):
        source=login.screen_program(self.record(),self.diagnostic)
        compile(source,'screen','exec')
        for effect in ("'guest-exec'","'send-key'","'input-send-event'","'system_reset'"):
            self.assertNotIn(effect,source)
        self.assertEqual(source.count("'execute':'screendump'"),1)
        self.assertIn("validate_socket_rows(unix_rows(path),fd_socket_inodes",source)
        self.assertIn("read('intent.json',first['intentPin'])",source)
        self.assertIn("read(role+'.json',value['pin'])",source)
    def test_changed_fixed_factory_refused(self):
        with patch.object(login.guest,'program',return_value=('foreign',None)):
            with self.assertRaisesRegex(ValueError,'screen-factory'):login.screen_program(self.record(),self.diagnostic)
    def test_diagnostic_only_uuid(self):
        with self.assertRaises(ValueError):login.screen_program(self.record(),'../foreign')
    def test_ppm_bounds_and_full_pixels(self):
        self.assertEqual(login.validate_ppm(self.ppm()),(2,1))
        for raw in (b'P3\n2 1\n255\n'+b'\0'*6,b'P6\n4096 4096\n255\n',self.ppm()[:-1],self.ppm()+b'x'):
            with self.assertRaises(ValueError):login.validate_ppm(raw)
    def test_capture_private_create_only_and_durable(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d).resolve();leaf=root/'.runtime/parity-evidence/screen';leaf.mkdir(parents=True,mode=0o700)
            capture=AuthorityCapture(root,'screen')
            try:
                calls=[];real=os.fsync
                with patch.object(login.os,'fsync',side_effect=lambda fd:(calls.append(fd),real(fd))[-1]):pin=login._frame_create(capture,self.ppm())
                self.assertEqual(pin['sha256'],hashlib.sha256(self.ppm()).hexdigest());self.assertIn(capture.fd,calls)
                s=os.lstat(leaf/'frame.ppm');self.assertEqual(stat.S_IMODE(s.st_mode),0o600);self.assertEqual(s.st_nlink,1)
                with self.assertRaises(FileExistsError):login._frame_create(capture,self.ppm())
            finally:capture.close()
    def test_existing_symlink_or_fifo_not_opened(self):
        for kind in('symlink','fifo'):
            with tempfile.TemporaryDirectory()as d:
                root=Path(d).resolve();leaf=root/'.runtime/parity-evidence/screen';leaf.mkdir(parents=True,mode=0o700)
                if kind=='symlink':(leaf/'frame.ppm').symlink_to('/dev/null')
                else:os.mkfifo(leaf/'frame.ppm',0o600)
                capture=AuthorityCapture(root,'screen')
                try:
                    with self.assertRaises(FileExistsError):login._frame_create(capture,self.ppm())
                finally:capture.close()
    def test_completed_observer_sources_unchanged(self):
        self.assertEqual(hashlib.sha256(Path(login.guest.__file__).read_bytes()).hexdigest(),login.GUEST_SHA)
        self.assertEqual(hashlib.sha256(Path(login.session.__file__).read_bytes()).hexdigest(),login.SESSION_SHA)


import gzip,base64
class WakeTests(unittest.TestCase):
    WALLPAPER='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'
    def frame(self):
        pixels=bytearray(1280*800*3);crop=gzip.decompress(base64.b64decode(self.WALLPAPER));rects=[(10, 10, 74, 74), (1196, 10, 1260, 74), (10, 656, 74, 720), (1196, 656, 1260, 720)]
        for index,(x0,y0,x1,y1)in enumerate(rects):
            patch=crop[index*12288:(index+1)*12288]
            for row,y in enumerate(range(y0,y1)):pixels[(y*1280+x0)*3:(y*1280+x1)*3]=patch[row*192:(row+1)*192]
        return b'P6\n1280 800\n255\n'+bytes(pixels)
    def test_reviewed_lockscreen_one_enter_after_durable_fence(self):
        events=[]
        result=login._guarded_wake(self.frame(),.2,lambda:events.append('guard'),lambda:events.append('fence'),lambda:events.append('ret'),lambda:(events.append('post'),b'frame')[1])
        self.assertEqual(result,b'frame');self.assertEqual(events,['guard','fence','guard','ret','post','guard'])
    def test_foreign_screen_zero_effects(self):
        raw=bytearray(self.frame());raw[-400000]=123;calls=[]
        # Replace the reviewed static wallpaper crop.
        pixels=raw.split(b'\n',3)[3];pixels[(10*1280+10)*3]=123
        frame=b'P6\n1280 800\n255\n'+pixels
        with self.assertRaises(ValueError):login._guarded_wake(frame,0,lambda:None,lambda:calls.append('fence'),lambda:calls.append('ret'),lambda:b'')
        self.assertEqual(calls,[])
    def test_stale_screen_zero_effects(self):
        calls=[]
        with self.assertRaises(ValueError):login._guarded_wake(self.frame(),6,lambda:None,lambda:calls.append('fence'),lambda:calls.append('ret'),lambda:b'')
        self.assertEqual(calls,[])
    def test_unknown_key_never_repeated(self):
        calls=[]
        def key():calls.append('ret');raise ValueError('lost-response')
        with self.assertRaisesRegex(ValueError,'lost-response'):login._guarded_wake(self.frame(),0,lambda:None,lambda:calls.append('fence'),key,lambda:calls.append('post'))
        self.assertEqual(calls,['fence','ret'])
    def test_actual_generated_wake_exact_one_enter_no_credential(self):
        record=ScreenTests().record();record['result']['qemu']={'pid':12};source=login.screen_program(record,login.WAKE_CORRELATION,wake=True,session_admission={'qemu':{'pid':12},'observedAtNs':123});compile(source,'wake','exec')
        self.assertEqual(source.count("'execute':'send-key'"),1);self.assertIn("'data':'ret'",source)
        self.assertIn("'wake-attempt.json'",source);self.assertIn('os.fsync(jobfd)',source)
        self.assertNotIn("'guest-exec'",source);self.assertNotIn('input-data',source)
    def test_consumed_original_wake_no_remote_submit(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d).resolve();leaf=root/'.runtime/parity-evidence'/('windows-cp117-lock-wake-'+login.WAKE_CORRELATION);leaf.mkdir(parents=True)
            with patch.object(login,'AuthorityCapture')as capture,patch.object(login.subprocess,'run')as transport:
                result=login.wake(root)
            self.assertEqual(result['phase'],'wake-consumed');transport.assert_not_called()
    def test_fixed_wake_correlation_refused(self):
        with self.assertRaisesRegex(ValueError,'fixed-wake-correlation'):login.screen_program(ScreenTests().record(),ScreenTests.diagnostic,wake=True)

    def test_dynamic_clock_content_excluded(self):
        raw=self.frame();parts=raw.split(b'\n',3);pixels=bytearray(parts[3])
        for y in range(145,225):pixels[(y*1280+540)*3:(y*1280+742)*3]=b'\xff'*(202*3)
        login._validate_lockscreen(b'P6\n1280 800\n255\n'+pixels)
    def facts(self):
        return {'version':1,'accountCount':1,'accounts':[{'expectedSid':True,'expectedName':True,'disabled':False,'lockedOut':False,'localAccount':True}],'processCount':2,'processes':[{'kind':'winlogon','pid':792,'parentPid':708,'sessionId':1,'ownerKnown':True,'expectedUser':False},{'kind':'logonui','pid':1096,'parentPid':792,'sessionId':1,'ownerKnown':True,'expectedUser':False}]}
    def test_current_session_positive_and_foreign_or_missing_rejected(self):
        login._validate_session_facts(self.facts())
        for change in (lambda f:f['processes'][1].update(kind='explorer'),lambda f:f['accounts'][0].update(expectedSid=False),lambda f:f['processes'][1].update(sessionId=2),lambda f:f['processes'][1].update(parentPid=999),lambda f:f['processes'][1].update(ownerKnown=False)):
            facts=self.facts();change(facts)
            with self.assertRaises(ValueError):login._validate_session_facts(facts)
    def test_current_session_ttl_in_actual_generated_guard(self):
        record=ScreenTests().record();record['result']['qemu']={'pid':12}
        source=login.screen_program(record,login.WAKE_CORRELATION,wake=True,session_admission={'qemu':{'pid':12},'observedAtNs':123})
        self.assertIn('time.time_ns()-123<=15_000_000_000',source)


class CredentialTests(unittest.TestCase):
    nonce='fb0a9a9d-eac2-43b0-a332-5fd766ce65a4'
    root=Path(__file__).resolve().parents[2]
    def answer(self):return {'operation':'windows-credential-validity-v1','correlationId':login.CREDENTIAL_CORRELATION,'expectedSid':login.guest.SID,'success':True,'errorCategory':'none'}
    def terminal(self,nonce=None,pid=456):
        import base64
        raw=('CP117-READ '+(nonce or self.nonce)+' '+login._BOOTSTRAP_SHA+' '+str(pid)+'\n'+json.dumps(self.answer())).encode()
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
    def test_exact_fixed_bootstrap_and_generated_command(self):
        import ast,base64
        body,pin=login._fixed_bootstrap(self.root)
        self.assertEqual(hashlib.sha256(body.encode('utf-16le')).hexdigest(),login._BOOTSTRAP_SHA)
        source,sha,pins=login.credential_program(self.root,ScreenTests().record(),self.nonce)
        compile(source,'credential','exec');tree=ast.parse(source)
        encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
        self.assertEqual(base64.b64decode(encoded).decode('utf-16le'),'[Console]::Out.WriteLine((\'CP117-READ '+self.nonce+' '+sha+' \'+$PID))\n'+body)
        self.assertEqual(source.count("'guest-exec',"),1)
        self.assertNotIn("'send-key'",source)
        self.assertIn('for poll in range(80)',source)
        self.assertLess(source.index("attemptpin=probe_create('attempt.json'"),source.index("child=call(LEAF+'/qga.sock','guest-exec'"))
        self.assertLess(source.index("childpin=probe_create('child.json'"),source.index('for poll in range(80)'))
    def test_modified_tracked_bootstrap_rejected(self):
        original=login.guest.recovery.authority._read_bound_file
        def changed(path,**kwargs):
            result=original(path,**kwargs)
            if kwargs.get('retain_bytes')and str(path).endswith('windows_credential_validity_qga.py'):
                pin,raw=result;return dict(pin,sha256='0'*64),raw+b'\nforeign'
            return result
        with patch.object(login.guest.recovery.authority,'_read_bound_file',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'validity-source'):login._fixed_bootstrap(self.root)
    def test_same_schema_stale_terminal_rejected_current_accepted(self):
        stale=self.terminal(nonce='old')
        # Prior body schema alone would accept the same valid credential object.
        import base64
        self.assertEqual(json.loads(base64.b64decode(stale['out-data']).split(b'\n',1)[1]),self.answer())
        self.assertIsNone(login._credential_terminal(stale,self.nonce,login._BOOTSTRAP_SHA,456))
        self.assertIsNone(login._credential_terminal(self.terminal(pid=999),self.nonce,login._BOOTSTRAP_SHA,456))
        self.assertEqual(login._credential_terminal(self.terminal(),self.nonce,login._BOOTSTRAP_SHA,456),self.answer())
    def test_schema_exit_and_truncated_fail_closed(self):
        for change in ({'exitcode':1},{'out-truncated':True},{'out-data':'!'}):
            value=self.terminal();value.update(change)
            with self.assertRaises((ValueError,Exception)):login._credential_terminal(value,self.nonce,login._BOOTSTRAP_SHA,456)
    def test_consumed_probe_no_secret_read_or_transport(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'.runtime/parity-evidence'/('windows-cp117-credential-'+login.CREDENTIAL_CORRELATION)).mkdir(parents=True)
            with patch.object(login,'_configured_secret')as secret,patch.object(login,'_probe_stream')as stream:
                self.assertEqual(login.credential_probe(root)['phase'],'credential-consumed')
            secret.assert_not_called();stream.assert_not_called()
    def test_actual_stream_private_stdin_and_durable_ack(self):
        import sys
        with tempfile.TemporaryDirectory()as d:
            root=Path(d).resolve();leaf=root/'.runtime/parity-evidence/probe';leaf.mkdir(parents=True,mode=0o700);capture=AuthorityCapture(root,'probe')
            try:
                event={'kind':'submitted','diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'qemu':{'pid':12},'pid':456,'hostChildPin':{'fingerprint':{'st_ino':1},'sha256':'a'*64},'hostLeafIdentity':{'st_dev':1,'st_ino':1,'st_mode':16832,'st_uid':1,'st_gid':1}}
                ack=login.guest.recovery._digest({'diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'pid':456})
                script="import sys,json\nn=int.from_bytes(sys.stdin.buffer.read(4),'big');assert sys.stdin.buffer.read(n)==b'inert-secret'\nsys.stderr.write('CP117-OBSERVE '+"+repr(json.dumps(event))+"+'\\n');sys.stderr.flush()\nassert sys.stdin.buffer.readline().decode().strip()=="+repr(ack)+"\nprint('{\"state\":\"observed\"}')"
                result,events=login._probe_stream([sys.executable,'-c',script],capture,self.nonce,login._BOOTSTRAP_SHA,{'pid':12},b'inert-secret')
                self.assertEqual(result['state'],'observed');self.assertEqual(events[0]['event']['pid'],456)
                self.assertNotIn(b'inert-secret',b''.join(p.read_bytes()for p in leaf.iterdir()if p.is_file()))
                self.assertEqual(stat.S_IMODE(os.lstat(leaf/'event-0.json').st_mode),0o600)
            finally:capture.close()
    def test_actual_probe_fixed_child_stale_then_fresh_and_anchor_drift(self):
        import io,types,base64,select
        for drift in (False,True):
            with tempfile.TemporaryDirectory()as d:
                parent=Path(d);os.chmod(parent,0o700);calls=[];events=[];results=[]
                ack=login.guest.recovery._digest({'diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'pid':456})
                stdin=types.SimpleNamespace(buffer=io.BytesIO((3).to_bytes(4,'big')+b'abc'+(ack+'\n').encode()))
                sysfake=types.SimpleNamespace(stdin=stdin)
                source=login._PROBE.replace('__TRANSFER__',repr(str(parent))).replace('__HELPER__',repr(base64.b64encode(b'inert').decode())).replace('__HELPER_SHA__',repr(hashlib.sha256(b'inert').hexdigest()))
                def need(ok,message):
                    if not ok:raise ValueError(message)
                def call(path,method,args):
                    calls.append((method,args))
                    if method=='guest-exec':return {'pid':456}
                    if drift:
                        child=parent/('cp117-credential-'+login.CREDENTIAL_CORRELATION)/'child.json';child.write_text('{}');os.chmod(child,0o600)
                    return self.terminal(nonce='old')if len(calls)==2 else self.terminal()
                ns={'guards':lambda:None,'os':os,'stat':stat,'fp':lambda s:{k:getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},'need':need,'json':json,'hashlib':hashlib,'CREDENTIAL_CORRELATION':login.CREDENTIAL_CORRELATION,'D':login.CREDENTIAL_CORRELATION,'NONCE':self.nonce,'BODY_SHA':login._BOOTSTRAP_SHA,'ENCODED':'fixed','LEAF':'fixed','children':[{}, {'child':{'pid':12}}],'sys':sysfake,'call':call,'event':events.append,'result':results.append,'digest':login.guest.recovery._digest,'_credential_terminal':login._credential_terminal,'time':types.SimpleNamespace(sleep=lambda _:None)}
                with patch.object(select,'select',return_value=([stdin],[],[])):exec('try:\n'+source,ns)
                self.assertEqual(sum(c[0]=='guest-exec'for c in calls),1)
                self.assertTrue(all(c[1]=={'pid':456}for c in calls if c[0]=='guest-exec-status'))
                if drift:self.assertEqual(results[0]['phase'],'probe-record-generation');self.assertEqual(len(calls),2)
                else:self.assertEqual(results[0].get('state'),'observed',results);self.assertEqual(results[0]['credential'],self.answer());self.assertEqual(len(calls),3)

    def test_protected_configured_secret_guard(self):
        from types import SimpleNamespace
        base=login.guest.recovery.authority.closure.base
        for kind in ('valid','public','symlink','fifo','hardlink','empty','oversize','wrong-account'):
            with tempfile.TemporaryDirectory()as d:
                path=Path(d).resolve()/'credential'
                if kind=='fifo':os.mkfifo(path,0o600)
                elif kind=='symlink':path.symlink_to('/dev/null')
                else:
                    path.write_bytes(b'abc'if kind!='empty'else b'');os.chmod(path,0o600)
                    if kind=='public':os.chmod(path,0o644)
                    if kind=='hardlink':os.link(path,Path(d)/'other')
                    if kind=='oversize':path.write_bytes(b'a'*513)
                target=SimpleNamespace()
                descriptor=(None,None,None,None,'foreign'if kind=='wrong-account'else 'vpncp117',login.guest.SID,path)
                with patch.object(base,'_descriptor',return_value=(None,target,None)),patch.object(base.windows_credential_probe_ssh,'_descriptor',return_value=descriptor):
                    if kind=='valid':self.assertEqual(login._configured_secret(self.root)[0],b'abc')
                    else:
                        with self.assertRaises(Exception):login._configured_secret(self.root)
    def test_lost_stream_retains_original_child_and_raw_before_parse(self):
        import sys
        with tempfile.TemporaryDirectory()as d:
            root=Path(d).resolve();leaf=root/'.runtime/parity-evidence/probe';leaf.mkdir(parents=True,mode=0o700);capture=AuthorityCapture(root,'probe')
            try:
                event={'kind':'submitted','diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'qemu':{'pid':12},'pid':456,'hostChildPin':{'fingerprint':{'st_ino':1},'sha256':'a'*64},'hostLeafIdentity':{'st_dev':1,'st_ino':1,'st_mode':16832,'st_uid':1,'st_gid':1}}
                script="import sys\nn=int.from_bytes(sys.stdin.buffer.read(4),'big');sys.stdin.buffer.read(n)\nsys.stderr.write('CP117-OBSERVE '+"+repr(json.dumps(event))+"+'\\n');sys.stderr.flush()\nsys.stdin.buffer.readline()\nprint('malformed')"
                with self.assertRaises(ValueError)as error:login._probe_stream([sys.executable,'-c',script],capture,self.nonce,login._BOOTSTRAP_SHA,{'pid':12},b'inert')
                self.assertEqual(error.exception.events[0]['event']['pid'],456)
                self.assertEqual((leaf/'transport.stdout.private').read_bytes(),b'malformed\n')
                self.assertEqual(json.loads((leaf/'event-0.json').read_bytes())['pid'],456)
            finally:capture.close()

    def test_actual_generated_terminal_parser_has_complete_remote_namespace(self):
        import ast,base64
        source,_,_=login.credential_program(self.root,ScreenTests().record(),self.nonce)
        tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_credential_terminal')
        namespace={'base64':base64,'json':json,'CREDENTIAL_CORRELATION':login.CREDENTIAL_CORRELATION}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-generated-parser','exec'),namespace)
        self.assertEqual(namespace['_credential_terminal'](self.terminal(),self.nonce,login._BOOTSTRAP_SHA,456),self.answer())

    def derived_fixture(self):
        qemu={'pid':12};generation=[1,2,3];request={'original':login.guest.ORIGINAL,'diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'credentialGeneration':generation}
        common={'diagnosticId':login.CREDENTIAL_CORRELATION,'nonce':self.nonce,'sourceSha256':login._BOOTSTRAP_SHA,'qemu':qemu,'pid':4996}
        events=[dict(common,kind='submitted'),dict(common,kind='poll',poll=1,exited=True),dict(common,kind='terminal',poll=1,payload=self.terminal(pid=4996))]
        result={'result':{'state':'unknown','phase':'NameError','appAdmission':False,'installerAction':False,'replayAllowed':False},'events':[{'event':e}for e in events]}
        attempt={'diagnosticId':login.CREDENTIAL_CORRELATION,'state':'consumed','original':login.guest.ORIGINAL}
        return request,result,attempt,qemu,generation
    def test_derived_original_terminal_without_relabeling_unknown(self):
        request,result,attempt,qemu,generation=self.derived_fixture()
        answer=login._derive_credential_record(request,result,attempt,qemu,generation)
        self.assertEqual(answer,self.answer());self.assertEqual(result['result']['state'],'unknown')
    def test_derived_changed_generation_nonce_pid_source_and_unknown_refused(self):
        import copy
        changes=[lambda a:a[0].update(credentialGeneration=[9]),lambda a:a[0].update(nonce='wrong'),lambda a:a[0].update(sourceSha256='0'*64),lambda a:a[1]['events'][0]['event'].update(pid=999),lambda a:a[1]['events'][2]['event'].update(qemu={'pid':99}),lambda a:a[1]['result'].update(state='observed'),lambda a:a[2].update(state='ready')]
        for change in changes:
            args=copy.deepcopy(self.derived_fixture());change(args)
            with self.assertRaises(ValueError):login._derive_credential_record(*args)
    def test_derived_api_has_no_new_guest_or_transport_dispatch(self):
        import ast,inspect
        tree=ast.parse(inspect.getsource(login.derive_credential_proof));calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)]
        self.assertFalse(any(isinstance(c.func,ast.Attribute)and c.func.attr in ('observe','screen','_probe_stream','run','Popen','build_ssh_argv')for c in calls))

    def test_derived_proof_explicitly_labels_later_pins_and_input_uncertainty(self):
        import ast,inspect
        tree=ast.parse(inspect.getsource(login.derive_credential_proof))
        proof=next(n.value for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='proof'for t in n.targets))
        fields={ast.literal_eval(k):v for k,v in zip(proof.keys,proof.values)}
        self.assertFalse(ast.literal_eval(fields['historicalCredentialInputGenerationIndependentlyProven']))
        self.assertFalse(ast.literal_eval(fields['currentVmAdmission']))
        provenance=ast.literal_eval(fields['pinProvenance'])
        self.assertEqual(provenance['result.json'],'retained-during-original-observation')
        self.assertEqual(provenance['events'],'original-event-pins-retained-in-original-result')
        for name in('request.json','remote.py','attempt.json'):self.assertEqual(provenance[name],'held-file-measured-after-original-observation')
        self.assertEqual(provenance['observed-source-manifest.json'],'later-archive-independently-retained')
        self.assertNotIn('originalRecords',fields);self.assertNotIn('credentialGeneration',fields)


class LayoutTests(unittest.TestCase):
    def facts(self):
        facts=WakeTests().facts()
        for p in facts['processes']:p['startedAtUtc']='2026-10-03T15:09:52.5087070Z'
        facts['layout']={'pid':1096,'parentPid':792,'sessionId':1,'startedAtUtc':'2026-10-03T15:09:52.5087070Z','threadCount':2,'threads':[{'threadId':111,'hkl':'0000000004090409'},{'threadId':222,'hkl':'0000000004090409'}],'preload':[{'name':'1','value':'00000409'}],'substitutes':[]}
        return facts
    def test_actual_secure_thread_layout_overrides_system_default_assumption(self):
        facts=self.facts();login._validate_us_layout(facts)
        # A US DEFAULT/Session0 assumption cannot authorize foreign secure HKL.
        facts['layout']['threads'][1]['hkl']='0000000004190419'
        login._validate_layout_facts(facts)
        with self.assertRaisesRegex(ValueError,'layout-us-unproven'):login._validate_us_layout(facts)
    def test_zero_unavailable_or_mixed_layout_never_admits_keyboard(self):
        for hkl in('0000000000000000','FFFFFFFFFFFFFFFF','0000000008090809'):
            facts=self.facts();facts['layout']['threads'][0]['hkl']=hkl
            with self.assertRaises(ValueError):login._validate_us_layout(facts)
    def test_layout_generation_thread_and_registry_bounds(self):
        import copy
        for change in(lambda f:f['layout'].update(pid=999),lambda f:f['layout'].update(startedAtUtc='other'),lambda f:f['layout']['threads'].append({'threadId':111,'hkl':'0000000004090409'}),lambda f:f['layout'].update(preload=[{'name':'1','value':'00000419'}]),lambda f:f['layout'].update(substitutes=[{'name':'00000409','value':'00000419'}])):
            facts=copy.deepcopy(self.facts());change(facts)
            with self.assertRaises(ValueError):login._validate_us_layout(facts)
    def test_generated_parser_complete_namespace_and_terminal_nonce(self):
        import ast,base64
        nonce=CredentialTests.nonce;source,sha=login.layout_program(ScreenTests().record(),ScreenTests.diagnostic,nonce);compile(source,'layout','exec')
        tree=ast.parse(source);defs=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('_validate_session_facts','_validate_layout_facts','_layout_terminal')]
        self.assertEqual(len(defs),3);namespace={'base64':base64,'json':json};exec(compile(ast.Module(body=defs,type_ignores=[]),'layout-parser','exec'),namespace)
        terminal={'exited':True,'exitcode':0,'out-data':base64.b64encode(('CP117-READ '+nonce+' '+sha+' 456\n'+json.dumps(self.facts())).encode()).decode()}
        self.assertEqual(namespace['_layout_terminal'](terminal,nonce,sha,456),self.facts())
        self.assertIsNone(namespace['_layout_terminal'](terminal,'old',sha,456))
        self.assertEqual(source.count("'guest-exec',"),1);self.assertNotIn("'send-key'",source);self.assertNotIn('input-data',source)
    def test_fixed_body_uses_actual_logonui_threads_and_readonly_registry(self):
        body=login._layout_body();self.assertEqual(hashlib.sha256(body.encode('utf-16le')).hexdigest(),login._LAYOUT_BODY_SHA)
        self.assertIn('$p=[System.Diagnostics.Process]::GetProcessById([int]$u.ProcessId)',body)
        self.assertIn('$ids=@($p.Threads',body);self.assertIn('GetKeyboardLayout([uint32]$_)',body)
        self.assertNotIn('GetKeyboardLayout(0)',body);self.assertNotIn('SetValue',body);self.assertNotIn('LoadKeyboardLayout',body)
        self.assertIn('LAYOUT_GENERATION',body);self.assertIn('LAYOUT_THREADS_CHANGED',body)
    def test_modified_body_factory_rejected_before_transport(self):
        with patch.object(login,'_LAYOUT_PS',login._LAYOUT_PS+'\nStop-Service Foreign\n'):
            with self.assertRaisesRegex(ValueError,'layout-fixed-body'):login.layout_program(ScreenTests().record(),ScreenTests.diagnostic,CredentialTests.nonce)
