from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import HistoricalFactoryTestCase as HistoryCase, provider as historical_provider
import ast,base64,copy,gzip,json,os,re,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import installed as historical_installed
b=historical_installed()
from agent_tools import windows_cp117_recovered_owner_observe as owner
from agent_tools.tests.test_windows_cp117_recovered_owner_observe import OwnerFactsTests
from agent_tools.tests.test_windows_cp117_recovered_owner_diagnostic import ActualStreamTests

class InstalledTests(HistoryCase):
    def value(self):
        package={name:b.PAIR_EXPECTED[expected]for name,expected in (('cliSha256','baseCliSha256'),('jarSha256','baseAppJarSha256'),('helperSha256','baseHelperSha256'),('runtimeSha256','baseRuntimeSha256'))}
        package.update(jarCount=1,registeredPathMatches=True,jarNameMatches=True,cliSignerStatus='NotSigned',helperSignerStatus='NotSigned',identitiesStable=True)
        readiness={'version':1,'code':'READY','installedVersion':'2.1.19','productCount':1,'activeCount':0,'activeKinds':[],'activeProcesses':[],'workspaceLockPid':248,'ownedExplorerCount':1}
        return {'version':1,'correlationId':b.CORRELATION,'outcome':'complete','stage':'complete','category':'none','errorType':'none','hresult':0,'observations':[],'facts':{'owner':OwnerFactsTests().facts(),'readiness':readiness,'package':package},'details':''}
    def execute_flow(self,stale=False,foreign=False):
        import io,types,signal
        o=owner.guest;recipe=o.recovery.recipe();request={'recipeSha256':o.recovery._digest(recipe)}
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        sockets['swtpm.sock']=o.TPM_SOCKET
        record={'request':request,'authority':proof,'result':{'state':'running','sockets':sockets}}
        source,sha=b.program(record,b.PAIR_EXPECTED);tree=ast.parse(source)
        # Execute every generated definition/constant, then the unchanged entire
        # operation. Only OS/transport authority observations are inert fixtures.
        self.assertIsInstance(tree.body[-1],ast.Try)
        ns={}
        with patch('signal.signal'),patch('signal.setitimer',create=True),patch('signal.ITIMER_REAL',0,create=True),patch('signal.SIGALRM',0,create=True):
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
            raw=('CP117-READ '+('old'if stale else b.NONCE)+' '+sha+' 456\n'+json.dumps(self.value())).encode()
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        def rows(path):
            name=path.split('/')[-1];inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':b.CORRELATION,'nonce':b.NONCE,'sourceSha256':sha,'pid':456})
        ns.update(os=FakeOS(),fp=lambda s:s if isinstance(s,dict)else vars(s),read=protected_read,leaf_check=lambda:None,child_guard=lambda c,a:None,unix_rows=rows,fd_socket_inodes=lambda p:{s['kernelInode']for s in sockets.values()},call=call,open=lambda p:io.StringIO(recipe['bootId']),sys=types.SimpleNamespace(stderr=err,stdin=io.StringIO(ack+'\n')),time=types.SimpleNamespace(sleep=lambda n:None),result=lambda v:out.write(json.dumps(v)))
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer',create=True),patch('signal.ITIMER_REAL',0,create=True),patch('signal.SIGALRM',0,create=True):
            exec(compile(ast.Module(body=tree.body[-1:],type_ignores=[]),'complete-generated-operation','exec'),ns)
        return json.loads(out.getvalue()),queries,anchors



    def test_complete_actual_factory_single_submit_and_positive_strict_parser(self):
        answer,calls,anchors=self.execute_flow();self.assertEqual(answer['facts'],self.value())
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
        self.assertTrue(b.summary(answer['facts'],b.PAIR_EXPECTED)['baseBytesMatched'])
        self.assertFalse(b.summary(answer['facts'],b.PAIR_EXPECTED)['installerAction'])
    def test_stale_same_child_original_cap_and_foreign_zero_submit(self):
        answer,calls,_=self.execute_flow(stale=True);self.assertEqual(answer['state'],'unknown');self.assertEqual(len(calls),81)
        self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1)
        self.assertTrue(all(args=={'pid':456}for op,args in calls if op=='guest-exec-status'))
        answer,calls,_=self.execute_flow(foreign=True);self.assertEqual(answer['state'],'unknown');self.assertEqual(calls,[])
    def test_genuine_byte_mismatch_stays_observed_false_not_ready(self):
        for key in ('cliSha256','jarSha256','helperSha256','runtimeSha256'):
            value=self.value();value['facts']['package'][key]='f'*64
            report=b.summary(b.validate(value),b.PAIR_EXPECTED);self.assertFalse(report['baseBytesMatched']);self.assertFalse(report['matches'][key])
            self.assertFalse(report['artifactCapabilitiesMatched']);self.assertFalse(report['ordinaryRequesterAdmission'])
    def test_strict_keys_types_signer_hash_and_owner_refusals(self):
        for update in ({'jarCount':True},{'jarNameMatches':1},{'identitiesStable':False},{'cliSha256':'F'*64},{'helperSignerStatus':'foreign'},{'runtimeSha256':'x'},{'extra':1}):
            value=self.value();value['facts']['package'].update(update)
            with self.assertRaises(ValueError):b.validate(value)
        for group,key,bad in (('readiness','version',True),('readiness','productCount',True),('readiness','installedVersion','foreign'),('owner','runtimeCount',False)):
            value=self.value();value['facts'][group][key]=bad
            with self.assertRaises(ValueError):b.validate(value)
        value=self.value();value['facts']['owner']['explorers'][0]['elevated']=True
        with self.assertRaises(ValueError):b.validate(value)
    def test_complete_compressed_source_roundtrip_hash_size_and_fixed_catalog(self):
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        source,sha=b.program(ScreenTests().record(),b.PAIR_EXPECTED)
        tree=ast.parse(source);encoded=next(n.value for n in ast.walk(tree)if isinstance(n,ast.Constant)and isinstance(n.value,str)and n.value.startswith('JABFAHI'))
        bootstrap=base64.b64decode(encoded).decode('utf-16le')
        packed=re.search(r"FromBase64String\('([^']+)'\)",bootstrap).group(1);raw=gzip.decompress(base64.b64decode(packed))
        self.assertTrue(raw.decode().endswith(b.body(b.PAIR_EXPECTED)))
        self.assertIn(str(len(raw)),bootstrap);self.assertIn(__import__('hashlib').sha256(raw).hexdigest(),bootstrap)
        self.assertIn('[IO.Compression.CompressionMode]::Decompress',bootstrap)
        self.assertLess(len(encoded),30000);self.assertLess(len(raw),65536)
        self.assertIn('entry.Length',b.FILE_CS);self.assertIn('RUNTIME_EXPANSION',b.FILE_CS)
        with self.assertRaises(ValueError):b.body(dict(b.PAIR_EXPECTED,baseAppJarName="x';Start-Process foreign;#"))
        for forbidden in ('Start-Process','Start-ScheduledTask','Register-ScheduledTask','LogonUser(', 'SetValue(', 'SendInput('):self.assertNotIn(forbidden,raw.decode())
    def test_source_and_factory_drift_rejects(self):
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        with patch.object(b.precise,'body',return_value=b.precise.body()+'\nforeign'):
            with self.assertRaises(ValueError):b.program(ScreenTests().record(),b.PAIR_EXPECTED)
    def test_consumed_correlation_never_submits(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'.runtime/parity-evidence'/('windows-cp117-installed-base-'+b.CORRELATION)).mkdir(parents=True)
            with patch.object(b.flow,'_stream')as stream:value=b.observe(root)
            self.assertEqual(value['stage'],'consumed');stream.assert_not_called()

class ActualFileReaderExecutionTests(HistoryCase):
    @unittest.skipUnless(os.name=='nt','actual Windows held-file and runtime reader')
    def test_actual_file_hash_identity_runtime_and_missing_entry(self):
        import subprocess,zipfile,hashlib
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'public.bin';path.write_bytes(b'CP117_PUBLIC_INERT')
            jar=Path(directory)/'public.jar'
            with zipfile.ZipFile(jar,'w')as archive:archive.writestr('bin/windows-amd64/sing-box.exe',b'CP117_PUBLIC_RUNTIME')
            missing=Path(directory)/'missing.jar'
            with zipfile.ZipFile(missing,'w')as archive:archive.writestr('wrong',b'public')
            literal=lambda p:"'"+str(p).replace("'","''")+"'"
            script="$ErrorActionPreference='Stop';Add-Type -AssemblyName System.IO.Compression;Add-Type -TypeDefinition @'\n"+b.FILE_CS+"\n'@ -ReferencedAssemblies @('System','System.Core','System.IO.Compression');"
            script+="$a=[Cp117InstalledFile]::Read("+literal(path)+");$z=[Cp117InstalledFile]::Read("+literal(path)+");if($a[0] -cne '"+hashlib.sha256(path.read_bytes()).hexdigest()+"' -or $a[1] -cne $z[1]){throw 'FILE_CASE'};"
            script+="if([Cp117InstalledFile]::Runtime("+literal(jar)+") -cne '"+hashlib.sha256(b'CP117_PUBLIC_RUNTIME').hexdigest()+"'){throw 'RUNTIME_CASE'};$failed=$false;try{[Cp117InstalledFile]::Runtime("+literal(missing)+")|Out-Null}catch{$failed=$true};if(!$failed){throw 'MISSING_ACCEPTED'};'INSTALLED_FILE_CASES_PASS'"
            result=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=script.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'));self.assertEqual(result.stdout.decode().strip(),'INSTALLED_FILE_CASES_PASS')

@unittest.skipIf(os.name=='nt','POSIX protected local transport capture')
class ActualWrapperTests(HistoryCase):
    def test_actual_wrapper_pins_package_and_attempt_before_ack_only_dispatch(self):
        from contextlib import ExitStack
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        r=b.precise.owner.guest.recovery;record=ScreenTests().record();record['authority']=[];record['result']['qemu']={'pid':12}
        owner_value=__import__('agent_tools.tests.test_windows_cp117_recovered_owner_diagnostic',fromlist=['DiagnosticTests']).DiagnosticTests().value()
        owner_value.update(outcome='complete',stage='complete',category='none',errorType='none',hresult=0,details='',facts=OwnerFactsTests().facts())
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();(root/'.runtime/parity-evidence').mkdir(parents=True)
            for name in ('windows-cp117-recovery-'+r.CORRELATION,'windows-cp117-owner-diagnostic-'+b.precise.CORRELATION):(root/'.runtime/parity-evidence'/name).mkdir(mode=0o700)
            def local_read(capture,name,pin):return json.dumps({'result':{'facts':owner_value}}if pin==b.OWNER_PROOF else record).encode()
            def native_boundary(argv,capture,correlation,nonce,sha,qemu,private):
                self.assertIsNone(private);self.assertEqual(correlation,b.CORRELATION)
                leaf=root/'.runtime/parity-evidence'/('windows-cp117-installed-base-'+b.CORRELATION)
                for filename in ('attempt.json','remote.py','request.json'):self.assertTrue((leaf/filename).is_file())
                compile((leaf/'remote.py').read_text(),'actual-package-wrapper','exec')
                return {'state':'observed','facts':InstalledTests().value()},[]
            with ExitStack()as stack:
                stack.enter_context(patch.object(r,'_local_read',side_effect=local_read))
                stack.enter_context(patch.object(b,'pair',return_value=b.PAIR_EXPECTED))
                stack.enter_context(patch.object(b.flow,'_execution_source_proof',return_value={'historical':False}))
                stack.enter_context(patch.object(r.authority,'_outer_authority',return_value={'fixed':True}))
                stack.enter_context(patch.object(r.authority,'_verify_outer'))
                stack.enter_context(patch.object(r.authority.closure.base,'_descriptor',return_value=({},None,None)))
                stack.enter_context(patch.object(r.authority.closure.base.ssh_transport,'build_ssh_argv',return_value=['fixed-observer']))
                boundary=stack.enter_context(patch.object(b.flow,'_stream',side_effect=native_boundary))
                answer=b.observe(root)
            self.assertEqual(answer['state'],'observed');self.assertTrue(answer['baseBytesMatched']);self.assertEqual(boundary.call_count,1)

class CrossPlatformImportTests(HistoryCase):
    def test_fresh_import_has_no_posix_effect_requirement(self):
        import subprocess
        script="import builtins\nold=builtins.__import__\ndef restricted(name,*a,**k):\n if name=='fcntl':raise ImportError('inert-Windows-fcntl-unavailable')\n return old(name,*a,**k)\nbuiltins.__import__=restricted\nimport agent_tools.windows_cp117_installed_base_observe\nprint('IMPORT_PASS')\n"
        result=subprocess.run([sys.executable,'-c',script],cwd=Path(__file__).resolve().parents[2],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'));self.assertEqual(result.stdout.decode().strip(),'IMPORT_PASS')
