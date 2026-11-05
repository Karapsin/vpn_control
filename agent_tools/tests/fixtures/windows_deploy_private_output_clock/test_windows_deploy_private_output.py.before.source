"""Complete saved gateway, real SSH child/socket, untrusted output boundaries.

The endpoint implements only declared SSH IO and -G metadata. It never claims
native Windows/SSH acceptance. No secret-bearing request is written to disk.
"""
import base64,hashlib,importlib.util,json,os,pwd,socket,struct,sys,tempfile,threading,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_deploy as current,ssh_source_file_stage_direct as stage

FIXTURE=Path(__file__).parent/'fixtures/windows_deploy_private_output'

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
s.close();outsize,errsize,linger=struct.unpack('!iid',raw[:16]);out=raw[16:16+outsize];err=raw[16+outsize:]
if len(err)!=errsize:raise SystemExit(97)
os.write(1,out);os.write(2,err)
if linger:time.sleep(linger)
'''.replace('__USER__',repr(pwd.getpwuid(os.getuid()).pw_name)).replace('__KEY__',repr(str(self.key))).replace('__ENDPOINT__',repr(str(self.endpoint))));self.binary.chmod(0o700)
        self.deployment=str(uuid.uuid4());self.operation=str(uuid.uuid4());self.calls=[];self.errors=[]
        raw=(FIXTURE/'windows_vm_deploy.py.before.source').read_bytes();manifest=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(manifest['beforeSha256'],hashlib.sha256(raw).hexdigest())
        self.old=types.ModuleType('agent_tools._private_gateway_before');self.old.__package__='agent_tools';self.old.__file__=str(FIXTURE/'windows_vm_deploy.py.before.source')
        exec(compile(raw,self.old.__file__,'exec'),self.old.__dict__)

    def public_result(self,mode):
        if mode=='secure-continue':return {'deploymentId':self.deployment,'mode':mode,'state':'secured-observed','operationId':self.operation,'productReady':False,'setupSecured':True,'replayAllowed':False}
        result={'schemaVersion':1,'deploymentId':self.deployment,'mode':mode,'state':'booted-observed'if mode=='start'else'secured-observed','reason':None,'nativeActionAllowed':False,'replayAllowed':False}
        if mode=='start':result.update(qemu={'pid':41,'startTicks':42},swtpm={'pid':43,'startTicks':44},qemuStatus='running',guestAgentReady=False,ordinarySessionObserved=False,osName=None,productReady=False)
        else:result.update(operationId=self.operation,productReady=False,setupSecured=True)
        return result

    def run_gateway(self,producer,case='healthy',mode='start'):
        folder=self.root/(case+'-'+mode+('-before'if producer is self.old else'-current'));folder.mkdir(mode=0o700)
        values={'passphrase':'PRIVATE_SSH_PASSPHRASE_!42','sudo':'PRIVATE_SUDO_PASSWORD_!42','payload':({'user':'User8!PRIVATE_NEW_USER_42','administrator':'Admin8!PRIVATE_NEW_ADMIN_42'}if mode=='start'else{'password':'Final8!PRIVATE_FINAL_42'})}
        privileged=mode!='secure-continue'
        if not privileged:values.pop('sudo')
        marker=next(iter(values['payload'].values())).encode();result=self.public_result(mode)
        out=json.dumps(result).encode();err=b'';linger=0
        if case=='echo':out=marker
        elif case=='tty':err=marker
        elif case=='malformed':out=b'{"partial":'+marker[:12]
        elif case=='overflow':out=marker[:12]+b'X'*8192
        elif case=='timeout':out=marker;linger=.8
        elif case=='base64':out=json.dumps({'echo':base64.b64encode(json.dumps(values['payload']).encode()).decode()}).encode()
        elif case=='extra':result['unrecognized']=marker[:12].decode();out=json.dumps(result).encode()
        elif case=='os-prefix':result['osName']=marker[:12].decode();out=json.dumps(result).encode()
        elif case=='wrong-operation':result.update(operationId=str(uuid.uuid4()));out=json.dumps(result).encode()
        elif case=='wrong-type':result['setupSecured']=1;out=json.dumps(result).encode()
        elif case=='free-check':
            result={'schemaVersion':1,'deploymentId':self.deployment,'mode':mode,'state':'unknown','reason':'instance_effect_or_observation_unknown','failurePhase':'credentials','failureClass':'ValueError','failureCheck':'instance_unapproved_private_prefix','nativeActionAllowed':False,'replayAllowed':False};out=json.dumps(result).encode()
        finished=threading.Event()
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
                    connection.sendall(struct.pack('!iid',len(out),len(err),linger)+out+err)
            except BaseException as error:self.errors.append(error)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        receipt={'path':'/tmp/vpn-control-windows-caller-'+'a'*32+'/caller.py','sha256':'ab'*32,'bytes':123,'uid':os.getuid(),'principal':pwd.getpwuid(os.getuid()).pw_name}
        options={'privileged':privileged,'input_payload':True}
        if producer is current:options['response']={'deploymentId':self.deployment,'mode':mode,'operationId':None if mode=='start'else self.operation,'checks':('instance_known_check',)}
        source=producer.gateway_program(receipt,**options);self.assertNotIn(marker,source)
        path=folder/'gateway.py';path.write_bytes(source);path.chmod(0o600);digest=hashlib.sha256(source).hexdigest();corr=uuid.uuid4().hex
        # Accelerate only the process's monotonic clock for an actual timeout;
        # the complete gateway/collector remains unmodified and awaits natural
        # original child closure. No second child or target replay is allowed.
        loader=("import time\nclock=time.monotonic;epoch=clock();time.monotonic=lambda:epoch+(clock()-epoch)*100\n"if case=='timeout'else'')+stage.LOADER
        argv=[sys.executable,'-I','-B','-c',loader,str(path),digest,str(len(source)),corr,str(self.config),'fixture',digest]
        with mock.patch.dict(os.environ,{'PATH':str(self.root)+os.pathsep+os.environ.get('PATH','')}):
            try:stage._run(folder,argv,json.dumps(values).encode(),'native')
            except ValueError:pass
            finally:finished.set()
        thread.join(60);self.assertFalse(thread.is_alive());self.assertEqual([],self.errors)
        observed=json.loads((folder/'native-stdout.private').read_bytes())
        serialized=b'\n'.join(p.read_bytes()for p in folder.iterdir()if p.is_file())
        return observed,serialized,marker,len(self.calls)

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
