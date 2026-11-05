"""Complete saved gateway, real SSH child/socket, untrusted output boundaries.

The endpoint implements only declared SSH IO and -G metadata. It never claims
native Windows/SSH acceptance. No secret-bearing request is written to disk.
"""
import ast,base64,hashlib,importlib.util,json,os,pwd,socket,struct,sys,tempfile,threading,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_deploy as current,ssh_source_file_stage_direct as stage

FIXTURE=Path(__file__).parent/'fixtures/windows_deploy_private_output'
# F6a: the gateway that answered a natively booted start with a cause-free UNKNOWN.
UNKNOWN_FIXTURE=Path(__file__).parent/'fixtures/windows_gateway_unknown_reason'
# The preserved harness whose whole-process clock expired its own route checks.
HARNESS=Path(__file__).parent/'fixtures/windows_deploy_private_output_clock'
# The timeout case accelerates only the observed session. Envelope input and both
# 'ssh -G' route checks keep their real 5 s budgets: a whole-process clock made them
# 50 ms, and a slow interpreter start expired them before any session existed.
# At 30x, observe(60) leaves 2 s of real time for the session's output (up to
# 0.45 s after spawn on this macOS host under load 19); its 2.5 s linger outlasts it.
TIMEOUT_CLOCK=("import time\nclock=time.monotonic;epoch=[]\n"
    "time.monotonic=lambda:clock()if not epoch else epoch[0]+(clock()-epoch[0])*30\n"
    "import subprocess\nspawn=subprocess.Popen.__init__\n"
    "def popen(self,args,*rest,**options):\n spawn(self,args,*rest,**options)\n if not epoch and '-G' not in args:epoch.append(clock())\n"
    "subprocess.Popen.__init__=popen\n")

def _rmdir_if_empty(path):
    # rmdir never removes content: any concurrent owner's entry keeps the directory.
    try:path.rmdir()
    except OSError:pass

@unittest.skipUnless(os.name=='posix','owned POSIX socket gateway fixture')
class PrivateGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Config ancestry must model the stable owned guest SSH directory;
        # the coordinator's shared /tmp changes while unrelated workers run.
        # The gateway pins every ancestor, so stay in the quiet checkout but leave
        # nothing there: drop the empty owned base, and .runtime only if made here.
        runtime=Path(__file__).resolve().parents[2]/'.runtime';cls.base=runtime/'windows-private-output-tests'
        try:runtime.mkdir();cls.addClassCleanup(_rmdir_if_empty,runtime)
        except FileExistsError:pass
        cls.addClassCleanup(_rmdir_if_empty,cls.base);cls.base.mkdir(mode=0o700,exist_ok=True)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='vc-pg-',dir=self.base);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        sockets=tempfile.TemporaryDirectory(prefix='vc-pgs-',dir=Path('/tmp').resolve());self.addCleanup(sockets.cleanup)
        self.endpoint=Path(sockets.name)/'peer';self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(self.endpoint));self.listener.listen();self.listener.settimeout(.1);self.addCleanup(self.listener.close)
        self.key=self.root/'key';self.key.write_text('PUBLIC_KEY_FIXTURE');self.key.chmod(0o600)
        self.config=self.root/'config';self.config.write_text('Host fixture\n  User '+pwd.getpwuid(os.getuid()).pw_name+'\n');self.config.chmod(0o600)
        self.binary=self.root/'ssh';self.binary.write_text('#!'+sys.executable+'\n'+r'''
import json,os,socket,struct,sys,time
if '-G'in sys.argv:
 print('user '+__USER__);print('identityfile '+__KEY__);raise SystemExit(0)
s=socket.socket(socket.AF_UNIX);s.connect(__ENDPOINT__)
raw=json.dumps({'argv':sys.argv[1:]}).encode();s.sendall(struct.pack('!I',len(raw))+raw)
while True:
 raw=os.read(0,65536)
 if not raw:break
 s.sendall(raw)
s.shutdown(socket.SHUT_WR);raw=bytearray()
while True:
 part=s.recv(65536)
 if not part:break
 raw.extend(part)
s.close();outsize,errsize,linger,status=struct.unpack('!iidi',raw[:20]);out=raw[20:20+outsize];err=raw[20+outsize:]
if len(err)!=errsize:raise SystemExit(97)
os.write(1,out);os.write(2,err)
if linger:time.sleep(linger)
raise SystemExit(status)
'''.replace('__USER__',repr(pwd.getpwuid(os.getuid()).pw_name)).replace('__KEY__',repr(str(self.key))).replace('__ENDPOINT__',repr(str(self.endpoint))));self.binary.chmod(0o700)
        self.deployment=str(uuid.uuid4());self.operation=str(uuid.uuid4());self.calls=[]
        raw=(FIXTURE/'windows_vm_deploy.py.before.source').read_bytes();manifest=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(manifest['beforeSha256'],hashlib.sha256(raw).hexdigest())
        self.old=types.ModuleType('agent_tools._private_gateway_before');self.old.__package__='agent_tools';self.old.__file__=str(FIXTURE/'windows_vm_deploy.py.before.source')
        exec(compile(raw,self.old.__file__,'exec'),self.old.__dict__)
        raw=(UNKNOWN_FIXTURE/'windows_vm_deploy.py.before.source').read_bytes();manifest=json.loads((UNKNOWN_FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(manifest['beforeSha256'],hashlib.sha256(raw).hexdigest());self.native_envelope=set(manifest['nativeEnvelopeKeys'])
        self.unverified=types.ModuleType('agent_tools._gateway_unknown_before');self.unverified.__package__='agent_tools';self.unverified.__file__=str(UNKNOWN_FIXTURE/'windows_vm_deploy.py.before.source')
        exec(compile(raw,self.unverified.__file__,'exec'),self.unverified.__dict__)

    def public_result(self,mode):
        if mode=='secure-continue':return {'deploymentId':self.deployment,'mode':mode,'state':'secured-observed','operationId':self.operation,'productReady':False,'setupSecured':True,'replayAllowed':False}
        result={'schemaVersion':1,'deploymentId':self.deployment,'mode':mode,'state':'booted-observed'if mode=='start'else'secured-observed','reason':None,'nativeActionAllowed':False,'replayAllowed':False}
        if mode=='start':result.update(qemu={'pid':41,'startTicks':42},swtpm={'pid':43,'startTicks':44},qemuStatus='running',guestAgentReady=False,ordinarySessionObserved=False,osName=None,productReady=False)
        else:result.update(operationId=self.operation,productReady=False,setupSecured=True)
        return result

    def run_gateway(self,producer,case='healthy',mode='start'):
        # Another process creating an entry in a pinned ancestor (other sessions'
        # lock files in the home directory) can trip the gateway guard before any
        # session starts. Only such a pre-session trip reruns the case, twice at
        # most; every other failure, and any trip after a session, fails at once.
        for attempt in range(3):
            calls=len(self.calls);folder,errors,marker=self.gateway_once(producer,case,mode,attempt)
            closed=self.closed_envelope(folder)if errors else None
            tripped=(len(self.calls)==calls and type(closed)is dict and (closed.get('state'),closed.get('errorClass'))==('unknown','ValueError')
                     and closed.get('reason','config_or_keys_changed')in ('config_or_keys_changed','route_parent_changed'))
            if not errors or not tripped:break
        self.last_folder=folder;self.assertEqual([],errors,closed)
        observed=json.loads((folder/'native-stdout.private').read_bytes())
        serialized=b'\n'.join(p.read_bytes()for p in folder.iterdir()if p.is_file())
        return observed,serialized,marker,len(self.calls)

    @staticmethod
    def closed_envelope(folder):
        """The envelope's closed fields only, never its private capture."""
        envelope=folder/'native-stdout.private'
        if not envelope.is_file():return None
        try:return {k:v for k,v in json.loads(envelope.read_bytes()).items()if k in ('state','errorClass','reason','capture')}
        except ValueError:return 'envelope-unparsed'

    def gateway_once(self,producer,case,mode,attempt):
        folder=self.root/(case+'-'+mode+'-'+producer.__name__.rsplit('.',1)[-1]+('-rerun%d'%attempt if attempt else ''));folder.mkdir(mode=0o700)
        values={'passphrase':'PRIVATE_SSH_PASSPHRASE_!42','sudo':'PRIVATE_SUDO_PASSWORD_!42','payload':({'user':'User8!PRIVATE_NEW_USER_42','administrator':'Admin8!PRIVATE_NEW_ADMIN_42'}if mode=='start'else{'password':'Final8!PRIVATE_FINAL_42'})}
        privileged=mode!='secure-continue'
        if not privileged:values.pop('sudo')
        marker=next(iter(values['payload'].values())).encode();result=self.public_result(mode)
        out=json.dumps(result).encode();err=b'';linger=0;status=0
        if case=='echo':out=marker
        elif case=='tty':err=marker
        elif case=='malformed':out=b'{"partial":'+marker[:12]
        elif case=='overflow':out=marker[:12]+b'X'*8192
        elif case=='timeout':out=marker;linger=2.5
        elif case=='base64':out=json.dumps({'echo':base64.b64encode(json.dumps(values['payload']).encode()).decode()}).encode()
        elif case=='extra':result['unrecognized']=marker[:12].decode();out=json.dumps(result).encode()
        elif case=='os-prefix':result['osName']=marker[:12].decode();out=json.dumps(result).encode()
        elif case=='wrong-operation':result.update(operationId=str(uuid.uuid4()));out=json.dumps(result).encode()
        elif case=='wrong-type':result['setupSecured']=1;out=json.dumps(result).encode()
        elif case=='nonzero':status=7
        elif case=='free-check':
            result={'schemaVersion':1,'deploymentId':self.deployment,'mode':mode,'state':'unknown','reason':'instance_effect_or_observation_unknown','failurePhase':'credentials','failureClass':'ValueError','failureCheck':'instance_unapproved_private_prefix','nativeActionAllowed':False,'replayAllowed':False};out=json.dumps(result).encode()
        # One run owns its endpoint errors; an earlier run's leftover never fails a later one.
        finished=threading.Event();errors=[]
        def serve():
            try:
                # Wait on the actual gateway child for as long as its stage runs, polling:
                # a fixed accept budget expired under load and stranded a late client, and
                # Darwin can drop the wakeup for its SHUT_WR, so recheck until real EOF.
                while True:
                    try:connection,_=self.listener.accept();break
                    except socket.timeout:
                        if finished.is_set():raise
                with connection:
                    raw=bytearray();connection.settimeout(.1)
                    while True:
                        try:part=connection.recv(65536)
                        except socket.timeout:
                            if finished.is_set():raise
                            continue
                        if not part:break
                        raw.extend(part)
                    connection.settimeout(None)
                    size=struct.unpack('!I',raw[:4])[0];request=json.loads(raw[4:4+size]);payload=bytes(raw[4+size:]);self.calls.append(request)
                    self.assertLess(len(request['argv'][-1].encode()),60000)
                    if privileged:
                        self.assertTrue(payload.startswith(values['sudo'].encode()+b'\n'));payload=payload.split(b'\n',1)[1]
                    self.assertEqual(values['payload'],json.loads(payload))
                    # A concurrent entry under the pinned config parent while the remote runs.
                    if case=='route-drift':(self.root/(folder.name+'.entry')).write_bytes(b'')
                    connection.sendall(struct.pack('!iidi',len(out),len(err),linger,status)+out+err)
            except BaseException as error:errors.append(error)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        receipt={'path':'/tmp/vpn-control-windows-caller-'+'a'*32+'/caller.py','sha256':'ab'*32,'bytes':123,'uid':os.getuid(),'principal':pwd.getpwuid(os.getuid()).pw_name}
        options={'privileged':privileged,'input_payload':True}
        if producer is not self.old:options['response']={'deploymentId':self.deployment,'mode':mode,'operationId':None if mode=='start'else self.operation,'checks':('instance_known_check',)}
        source=producer.gateway_program(receipt,**options);self.assertNotIn(marker,source)
        path=folder/'gateway.py';path.write_bytes(source);path.chmod(0o600);digest=hashlib.sha256(source).hexdigest();corr=uuid.uuid4().hex
        # Accelerate only the session's monotonic clock for an actual timeout; the
        # complete gateway/collector remains unmodified and awaits natural original
        # child closure. No second child or target replay is allowed.
        loader=(TIMEOUT_CLOCK if case=='timeout'else'')+stage.LOADER
        argv=[sys.executable,'-I','-B','-c',loader,str(path),digest,str(len(source)),corr,str(self.config),'fixture',digest]
        with mock.patch.dict(os.environ,{'PATH':str(self.root)+os.pathsep+os.environ.get('PATH','')}):
            try:stage._run(folder,argv,json.dumps(values).encode(),'native')
            except ValueError:pass
            finally:finished.set()
        thread.join(60);self.assertFalse(thread.is_alive())
        return folder,errors,marker

    def assert_private_boundary(self,observed,serialized,marker):
        capture=observed['_operatorPrivateCapture'];self.assertEqual('metadata-only',capture['retention'])
        self.assertNotIn('sha256',json.dumps(capture));self.assertNotIn('base64',json.dumps(capture))
        self.assertNotIn(marker,serialized);self.assertNotIn(base64.b64encode(marker),serialized)
        self.assertNotIn(marker[:12],serialized)
        for field in ('stdout','tty'):
            self.assertNotIn(field,capture)

    def test_preserved_whole_gateway_echo_red_and_current_finite_failure(self):
        for case in ('echo','tty','malformed','overflow','timeout','base64','extra'):
            with self.subTest(case=case):
                before,raw,marker,count=self.run_gateway(self.old,case)
                capture=before['_operatorPrivateCapture'];decoded=b''.join(base64.b64decode(capture[k]['base64'])for k in ('stdout','tty'))
                self.assertTrue(marker in decoded or marker[:12]in decoded or b'echo'in decoded)
                self.assertIn('sha256',json.dumps(capture))
                after,raw,marker,aftercount=self.run_gateway(current,case)
                self.assertEqual('unknown',after['state']);self.assert_private_boundary(after,raw,marker)
                self.assertEqual(count+1,aftercount)

    def test_slow_route_check_preserved_harness_red_session_clock_green(self):
        # TEST-001: macOS spawns of the fake 'ssh -G' took 43-164 ms; the preserved
        # harness's 100x whole-process clock gave effective_route 50 ms, so no session
        # started and the endpoint accept timed out. A 0.2 s route check models that host.
        path=HARNESS/'test_windows_deploy_private_output.py.before.source';raw=path.read_bytes()
        self.assertEqual(json.loads((HARNESS/'provenance.json').read_bytes())['beforeSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools.tests._private_gateway_harness_before');before.__file__=__file__;before.__package__=__package__
        exec(compile(raw,str(path),'exec',dont_inherit=True),before.__dict__)
        def slow(test):
            source=test.binary.read_text();needle="if '-G'in sys.argv:\n"
            self.assertEqual(1,source.count(needle));test.binary.write_text(source.replace(needle,needle+' time.sleep(.2)\n'))
        before.PrivateGatewayTests.base=self.base
        old=before.PrivateGatewayTests('test_preserved_whole_gateway_echo_red_and_current_finite_failure');old.setUp();self.addCleanup(old.doCleanups);slow(old)
        with self.assertRaisesRegex(AssertionError,'TimeoutError'):old.run_gateway(old.old,'timeout')
        self.assertEqual(([],[TimeoutError]),(old.calls,[type(e)for e in old.errors]))
        # Shared list (base64/extra cascade): a later preserved run still fails on the
        # earlier run's endpoint error, which stays first in the setUp-wide list.
        leftover=old.errors[0]
        with self.assertRaisesRegex(AssertionError,'TimeoutError'):old.run_gateway(old.old,'extra')
        self.assertIs(leftover,old.errors[0])
        slow(self);observed,_,_,count=self.run_gateway(self.old,'timeout')
        self.assertEqual(('unknown','ValueError',1),(observed['state'],observed['errorClass'],count))
        # Per-run list: a run whose route check fails keeps its own endpoint error,
        # and the next run is clean.
        source=self.binary.read_text();needle="if '-G'in sys.argv:\n"
        self.binary.write_text(source.replace(needle,needle+' raise SystemExit(1)\n'))
        with self.assertRaisesRegex(AssertionError,'TimeoutError'):self.run_gateway(self.old,'base64')
        self.binary.write_text(source);self.run_gateway(self.old,'extra')

    def test_unknown_names_one_closed_reason_and_capture_facts(self):
        # F6a: a native start booted its VM, yet the gateway's UNKNOWN kept only
        # errorClass ValueError and stream counts. Each case is a different gateway
        # decision; the preserved gateway answers all of them with the native envelope.
        facts=lambda complete=True,refusal=None,code=0,timeout=False:{'complete':complete,'refusal':refusal,'returnCode':code,'timeout':timeout}
        cases={'nonzero':('program_observation_unknown',facts(code=7)),
               'overflow':('program_observation_unknown',facts(refusal='capture_overflow')),
               'timeout':('program_observation_unknown',facts(complete=False,code=None,timeout=True)),
               'echo':('private_output_refused',facts()),
               'extra':('private_result_refused',facts()),
               'route-drift':('config_or_keys_changed',facts())}
        returned=lambda:json.loads((self.last_folder/'native-terminal.json').read_bytes())['returnCode']
        for case,expected in cases.items():
            with self.subTest(case=case):
                before,_,_,_=self.run_gateway(self.unverified,case)
                self.assertEqual(('unknown','ValueError',3),(before['state'],before['errorClass'],returned()))
                self.assertEqual(self.native_envelope,set(before))
                after,raw,marker,_=self.run_gateway(current,case)
                # The diagnosis changes nothing downstream: still UNKNOWN with exit 3.
                self.assertEqual(('unknown','ValueError',3),(after['state'],after['errorClass'],returned()))
                self.assertEqual(expected,(after.get('reason'),after.get('capture')))
                self.assert_private_boundary(after,raw,marker)

    def test_shipped_value_errors_and_refusals_are_the_closed_token_sets(self):
        receipt={'path':'/tmp/vpn-control-windows-caller-'+'a'*32+'/caller.py','sha256':'ab'*32,'bytes':123,'uid':os.getuid(),'principal':'fixture'}
        response={'deploymentId':self.deployment,'mode':'start','operationId':None,'checks':('instance_known_check',)}
        for file_output in (False,True):
            source=current.gateway_program(receipt,privileged=True,input_payload=True,file_output=file_output,response=response).decode()
            tree=ast.parse(source)
            raised=[n.exc for n in ast.walk(tree)if isinstance(n,ast.Raise)and isinstance(n.exc,ast.Call)and getattr(n.exc.func,'id',None)=='ValueError']
            self.assertTrue(raised)
            self.assertTrue(all(len(c.args)==1 and not c.keywords and isinstance(c.args[0],ast.Constant)and type(c.args[0].value)is str for c in raised))
            refusals={c.value for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Attribute)and t.attr=='refusal'for t in n.targets)
                      for c in ast.walk(n.value)if isinstance(c,ast.Constant)and type(c.value)is str}
            namespace={'__name__':'saved_gateway_definitions'};exec(compile(source,'complete saved gateway','exec'),namespace)
            self.assertEqual({c.args[0].value for c in raised},set(namespace['GATEWAY_REASONS']))
            self.assertEqual(refusals,set(namespace['GATEWAY_REFUSALS']))
            unknown=namespace['_gateway_unknown_facts']
            for token in namespace['GATEWAY_REASONS']:self.assertEqual({'reason':token,'capture':None},unknown(ValueError(token),None))
            for error in (ValueError('PRIVATE_SSH_PASSPHRASE_!42'),ValueError('private_ssh_passphrase'),ValueError('not enough values to unpack (expected 4, got 3)'),
                          json.JSONDecodeError('Expecting value','User8!PRIVATE',0),UnicodeDecodeError('utf-8',b'\xff',0,1,'invalid start byte'),
                          OSError(5,'Input/output error'),KeyboardInterrupt()):
                self.assertEqual({'reason':'unclassified','capture':None},unknown(error,None))
            custody=types.SimpleNamespace(child=types.SimpleNamespace(returncode=None),eof={'stdout':True,'tty':False},timeout=False,refusal='PRIVATE free text')
            self.assertEqual({'complete':False,'refusal':'unclassified','returnCode':None,'timeout':False},unknown(ValueError('route_identity'),custody)['capture'])

    def test_secret_operation_and_schema_bound_before_any_saved_output(self):
        for case in ('wrong-operation','wrong-type','free-check'):
            with self.subTest(case=case):
                value,raw,marker,_=self.run_gateway(current,case,mode='secure')
                self.assertEqual('unknown',value['state']);self.assert_private_boundary(value,raw,marker)

    def test_healthy_bootstrap_and_secure_preserve_public_result_without_raw_hashes(self):
        for mode in ('start','secure','secure-continue'):
            value,raw,marker,_=self.run_gateway(current,mode=mode)
            self.assertEqual('observed',value['state'],json.dumps(value));self.assertEqual(self.public_result(mode),value['result'])
            self.assert_private_boundary(value,raw,marker)

    def test_free_guest_label_cannot_release_partial_private_prefix(self):
        before,raw,marker,_=self.run_gateway(self.old,'os-prefix')
        self.assertIn(marker[:12],json.dumps(before).encode())
        after,raw,marker,_=self.run_gateway(current,'os-prefix')
        self.assertEqual('observed',after['state']);self.assertIsNone(after['result']['osName'])
        self.assert_private_boundary(after,raw,marker)

if __name__=='__main__':unittest.main()
