"""Whole unexposed collector beforeimage: source-only proof and spent dispatch."""
import hashlib,json,os
from pathlib import Path
import socket,subprocess,sys,tempfile,time,unittest
from contextlib import contextmanager
from types import ModuleType,SimpleNamespace
from unittest import mock
from agent_tools import readiness_windows_bootstrap_closure as current
from agent_tools import readiness_windows_seed_detach as seed
from agent_tools import readiness_windows_host_jobs as host
from agent_tools import durable_remote_job as jobs
from agent_tools.tests import test_windows_seed_detach as fixtures
from agent_tools.tests.test_windows_seed_reader_scope import controlled_request

FIXTURE=Path(__file__).parent/'fixtures/windows_bootstrap_reopen'
def subject():
    if os.environ.get('VPN_CONTROL_BOOTSTRAP_REOPEN_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    value=ModuleType('agent_tools._bootstrap_reopen_before');value.__package__='agent_tools';value.__file__=str(FIXTURE/'before.source')
    sys.modules[value.__name__]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__);return value

@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary private original HOST packets required')
class BootstrapReopenTests(unittest.TestCase):
    def _original(self,check):
        done=[False];original_attach=seed.attach_ejection
        def intercept(original,packet):
            result=original_attach(original,packet)
            if not done[0]:done[0]=True;check(original,packet)
            return result
        with mock.patch.object(seed,'attach_ejection',side_effect=intercept):
            result=unittest.TestResult();fixtures.SeedOwnerSourceTests('test_fixed_ejection_builder_uses_actual_opaque_host_namespace_and_original_packet').run(result)
        self.assertTrue(done[0]);self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures))

    def test_constant_only_source_and_partial_local_reply_cannot_mint_opaque_proof(self):
        module=subject()
        def check(original,packet):
            with tempfile.TemporaryDirectory()as directory:
                root=Path(directory);root.chmod(0o700);admitted=module.admission(root,original);local=admitted.as_dict()
                body,_,_=seed._body(original);_,actual,owner=host._load(packet);request=controlled_request(seed,original,packet)
                readers={'complete':True,'holders':[],'observedNs':100,'deadlineNs':10000}
                constants={'CLOSE_ADMISSION_ID':local['admissionId'],'CLOSE_REQUEST':request,'CLOSE_READERS':readers,
                    'SEED_ORIGINAL':body,'SEED_DETACH_SOURCE':actual,'SEED_DETACH_OWNER':owner}
                # No executable dispatch, SYSTEM result or remote file generation.
                fake_source=('\n'.join(k+'='+repr(v)for k,v in constants.items())+'\n').encode()
                fake={'currentRequest':request,'currentReaders':readers,'closure':{
                    'admissionId':local['admissionId'],'machine':body['binding']['spec']['deploymentId'],
                    'creatorOperationId':body['creatorOperationId'],'seedOperationId':body['operationId'],
                    'ordinarySigninAllowed':True,'replayAllowed':False}}
                path=module._ADMISSIONS[admitted][0]/'proof';path.mkdir(mode=0o700)
                jobs._publish(path/'closure.json',fake);jobs._create(path/'closure-program.source',fake_source)
                host._create_custody(path,'proof-custody.json',('closure.json','closure-program.source'))
                with mock.patch.object(module.transport,'admitted_transport',side_effect=AssertionError('must remain local')):
                    self.assertIsNone(module.reopen(root,original),'source-only local files were promoted to collected opaque proof')
        self._original(check)

    def test_source_preparation_exhausted_deadline_never_contacts_actual_channel(self):
        module=subject()
        def check(original,packet):
            with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
                root=Path(directory);root.chmod(0o700);wire=root/'channel.sock';ready=root/'ready';contacted=root/'contacted'
                server=subprocess.Popen([sys.executable,'-I','-B','-c',
                    'import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(3);Path(sys.argv[2]).touch();\ntry:\n c,_=s.accept();assert c.recv(8)==b"dispatch";Path(sys.argv[3]).touch();c.close()\nexcept TimeoutError:pass\ns.close()',str(wire),str(ready),str(contacted)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                request=controlled_request(seed,original,packet);witness=object.__new__(seed.ReaderWitness)
                readers={'complete':True,'holders':[],'observedNs':100,'deadlineNs':10000}
                seed._READERS[witness]={'original':original,'request':json.dumps(request),'result':json.dumps(readers),'guards':(),
                    'deadline':time.monotonic()+20,'consumedBy':None}
                @contextmanager
                def admitted(*a,**kw):yield SimpleNamespace(revalidate=lambda:None)
                class Authority:
                    config={}
                    def __init__(self,*a,**kw):pass
                    def __enter__(self):return self
                    def __exit__(self,*a):pass
                    def guard(self):pass
                def build(*a,**kw):
                    time.sleep(.25)
                    return [sys.executable,'-I','-B','-c','import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b"dispatch");s.close()',str(wire)]
                def transport_boundary(argv,**kwargs):
                    # The test measures whether submission is entered at all;
                    # this controlled socket command gets its own fixed bound.
                    kwargs.pop('timeout');return subprocess.run(argv,timeout=1,**kwargs)
                try:
                    end=time.monotonic()+5
                    while not ready.exists():self.assertIsNone(server.poll());self.assertLess(time.monotonic(),end);time.sleep(.01)
                    with mock.patch.object(module.transport,'admitted_transport',admitted),mock.patch.object(module.deploy.direct,'Guard',Authority),\
                        mock.patch.object(module.transport,'build_ssh_argv',side_effect=build),mock.patch.object(module.transport,'run_ssh',side_effect=transport_boundary),\
                        mock.patch.object(seed.ReaderWitness,'guard_dispatch',return_value=None):
                        with self.assertRaises(ValueError):module.collect(root,original,witness,guard=lambda:None,deadline=time.monotonic()+.15)
                    server.communicate(timeout=5)
                    self.assertFalse(contacted.exists(),'spent absolute budget still submitted the generated caller')
                finally:
                    seed._READERS.pop(witness,None)
                    if server.poll()is None:server.terminate();server.communicate(timeout=3)
        self._original(check)

if __name__=='__main__':unittest.main()
