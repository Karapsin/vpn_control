"""Controlled backend contracts, not native Mac/provider qualification."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_tart_macos as subject
from agent_tools import readiness_tart_vnc as rfb
from agent_tools import readiness_qemu_jobs as protocol
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


def binding():
    return subject.MacBinding('local-tart-macos-'+'a'*24, '01234567-89ab-4def-8123-0123456789ab',
                             'vpn-tool-recovery-tart-macos-controlled', '/controlled/tart',
                             '/controlled/vpn-tool-recovery-tart-macos-controlled', 'toolrecovery', 501,
                             '/Users/toolrecovery', '/Volumes/ReadOnly/python/bin/python3', 4096, 'controlled-storage')


def facts():
    return {'machine':binding().machine,'boot':'11234567-89ab-4def-8123-0123456789ab',
            'bootTime':{'seconds':100,'microseconds':50},'uid':501,'account':'toolrecovery','home':'/Users/toolrecovery',
            'observerUid':0,'observerAccount':'root','observerHome':'/var/root',
            'console':{'name':'toolrecovery','uid':501,'onConsole':True,'locked':False,'session':'101','loginDone':True},
            'display':'ready','processVisibilityComplete':True,'processes':[], 'protectedProcesses':[],
            'installerVisibilityComplete':True,'installerBlockers':[],'jobVisibilityComplete':False,
            'runningJobs':[],'unknownJobs':[{'role':'macos_launchd_and_durable_job_baseline_unqualified'}]}


class ReadOnlyPeer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    def __init__(self):
        self.value={'facts':facts(),'agent':{'actor':{'pid':42,'birth':'darwin:100:50'},'uid':501,
                    'principal':'toolrecovery','home':'/Users/toolrecovery','python':binding().guest_python,
                    'rawBoot':facts()['boot'].upper()}}
        self.calls=[]
        peer=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                request=json.loads(self.rfile.readline(1025));peer.calls.append(request)
                self.wfile.write(json.dumps(peer.value).encode()+b'\n')
        super().__init__(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        self.thread.start()
    def close(self):
        self.shutdown();self.server_close();self.thread.join(1)


class ControlledProof:
    """Only this test fixture supplies authority; production has no Mac factory."""
    def __init__(self, actions):self.actions=actions;self.changed=False
    def guard(self,binding,pins):
        if self.changed:raise RuntimeError('private proof diagnostic')


class ControlledCustody:
    def __init__(self,root,peer,actions=frozenset()):
        self.root,self.peer=root,peer
        self.proof=ControlledProof(actions) if actions else None
        self.host={'state':'running','connection':'controlled-tart-actor','actor':{'pid':41,'birth':'darwin:100:49'},
                   'operator':{'pid':40,'birth':'darwin:100:48'},'operationId':str(uuid4()),'jobState':'running'}
        self.effects=[];self.scopes=0;self.endpoint=None;self.actual_calls=0;self.lost_ack=False
    def qualifications(self,*args):return self.proof
    def guard(self,**kwargs):return deepcopy(self.host)
    @contextmanager
    def operator(self,**kwargs):
        self.scopes+=1
        try:yield
        finally:self.scopes-=1
    def guest_probe(self,bind,deadline):
        with socket.create_connection(self.peer.server_address,timeout=1) as client:
            client.sendall(b'{"action":"fixed-root-probe"}\n')
            value=json.loads(client.makefile('rb').readline(1048577))
        if value=={'phase':'authenticated-agent-starting'}:raise subject.MacAgentStarting()
        return value
    def idle_facts(self,*args):return {'visibility':readiness.IDLE_VISIBILITY,'blockers':frozenset()}
    def dispatch_recovery(self,action,rid,observed,deadline):
        path=self.root/(rid+'.json')
        try:
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        except FileExistsError:return 'original_observed'
        with os.fdopen(fd,'w')as stream:json.dump({'action':action,'recoveryId':rid,'state':'unknown'},stream);stream.flush();os.fsync(stream.fileno())
        self.effects.append((action,rid))
        if self.lost_ack:raise RuntimeError('private lost acknowledgment')
        return 'submitted'
    def ordinary_guest_call(self,bind,argv,payload,deadline):
        self.actual_calls+=1
        return subprocess.run([sys.executable,*argv[1:]],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2)
    def gui_endpoint(self,*args):return self.endpoint
    def reconcile_ready(self,*args):return None


class MacBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.peer=ReadOnlyPeer();self.addCleanup(self.peer.close)
        self.custody=ControlledCustody(self.root,self.peer)
        self.backend=subject.MacTartBackend(binding(),self.custody)
    def observe(self):return self.backend.observe(readiness.Requirements(frozenset({'guest_agent'})),time.monotonic()+5)
    def ready(self):
        observed=self.observe()
        return readiness.ReadyContext(str(uuid4()),observed.target,observed.machine,observed.connection,
                                     observed.boot,observed.account,observed.session,
                                     readiness.Requirements(frozenset({'interactive_desktop'})))
    def enable(self,actions):
        self.custody.proof=ControlledProof(frozenset(actions));self.backend=subject.MacTartBackend(binding(),self.custody)
    def endpoint(self,guard=lambda:None,capture_safe=lambda:True):
        endpoint=RfbEndpoint();self.addCleanup(endpoint.close)
        reader,writer=os.pipe();os.write(writer,b'controlled-rfb-auth');os.close(writer);self.addCleanup(os.close,reader)
        self.custody.endpoint=subject.MacGuiEndpoint(endpoint.port,reader,guard,lambda:None,capture_safe)
        return endpoint

    def test_constructor_has_no_transport_or_native_authority_and_linux_identity_is_rejected(self):
        self.assertEqual([],self.peer.calls);self.assertEqual(frozenset(),self.backend.capabilities)
        self.assertEqual([],self.custody.effects)
        for changes in ({'machine':'a'*32},{'ordinary_uid':0},{'ordinary_uid':501.0},{'ordinary_home':'/var/root'},
                        {'ordinary_account':'root'},{'guest_python':'python3'}):
            with self.subTest(changes=changes),self.assertRaises(subject.MacBlocked):replace(binding(),**changes)
        with self.assertRaisesRegex(subject.MacBlocked,'macos_recovery_unqualified'):
            self.backend.recover('start','a'*64,self.observe(),time.monotonic()+3)
        self.assertEqual([],self.custody.effects)

    def test_full_socket_probe_binds_uuid_actual_agent_console_and_keeps_unknown_idle(self):
        observed=self.observe()
        self.assertEqual('ready',observed.ordinary_session);self.assertTrue(observed.guest_agent)
        self.assertEqual(facts()['boot']+':console:101',observed.session)
        self.assertTrue(observed.connection.endswith(':agent:42:darwin:100:50'))
        self.assertNotIn('running_jobs',observed.idle_visibility);self.assertNotIn('unknown_jobs',observed.idle_visibility)
        self.assertIn('unknown_jobs',observed.idle_blockers)
        self.assertEqual([{'action':'fixed-root-probe'}],self.peer.calls)
        self.assertEqual([],self.custody.effects)

    def test_locked_wrong_account_absent_lock_and_signedout_are_distinct(self):
        original=deepcopy(self.peer.value)
        for console,expected in [({**facts()['console'],'locked':True},'locked'),
                                 ({**facts()['console'],'uid':502,'name':'another'},'wrong_account'),
                                 ({**facts()['console'],'locked':None},'unknown'),
                                 ({'name':'loginwindow','uid':0,'onConsole':None,'locked':None,'session':None},'unknown')]:
            self.peer.value=deepcopy(original);self.peer.value['facts']['console']=console
            self.assertEqual(expected,self.observe().ordinary_session)
        self.assertEqual([],self.custody.effects)

    def test_authenticated_agent_starting_waits_but_malformed_machine_and_account_never_do(self):
        original=deepcopy(self.peer.value);self.peer.value={'phase':'authenticated-agent-starting'}
        observed=self.observe();self.assertEqual('booting',observed.guest);self.assertFalse(observed.guest_agent)
        for key,value in [('machine',str(uuid4())),('uid',502),('observerUid',501),('processes',['untyped'])]:
            self.peer.value=deepcopy(original);self.peer.value['facts'][key]=value
            with self.subTest(key=key),self.assertRaises(subject.MacBlocked):self.observe()

    def test_missing_false_or_ambiguous_login_done_never_admits_a_desktop(self):
        original=deepcopy(self.peer.value)
        for value in (None,False,'missing'):
            self.peer.value=deepcopy(original)
            if value=='missing':del self.peer.value['facts']['console']['loginDone']
            else:self.peer.value['facts']['console']['loginDone']=value
            self.assertEqual('unknown',self.observe().ordinary_session)
        for malformed in (0,1,'true',[]):
            self.peer.value=deepcopy(original);self.peer.value['facts']['console']['loginDone']=malformed
            with self.assertRaisesRegex(subject.MacBlocked,'macos_console_invalid'):self.observe()

    def test_idle_proof_and_unknown_work_block_reboot_and_original_lost_ack_never_replaces(self):
        self.enable({'reboot'});before=self.observe()
        with self.assertRaisesRegex(subject.MacBlocked,'macos_idle_proof_incomplete'):
            self.backend.recover('reboot','a'*64,before,time.monotonic()+3)
        self.assertEqual([],self.custody.effects)
        self.peer.value['facts'].update(jobVisibilityComplete=True,unknownJobs=[])
        before=self.observe();self.custody.lost_ack=True
        with self.assertRaisesRegex(subject.MacBlocked,'^macos_custody_unavailable$'):
            self.backend.recover('reboot','b'*64,before,time.monotonic()+3)
        self.assertEqual('original_observed',self.backend.recover('reboot','b'*64,before,time.monotonic()+3))
        self.assertEqual([('reboot','b'*64)],self.custody.effects)
        self.assertEqual('unknown',json.loads((self.root/('b'*64+'.json')).read_text())['state'])

    def test_qualified_ordinary_executor_uses_verified_stdin_and_stale_context_stops_before_spawn(self):
        with self.backend.guest_job_executor(deadline=time.monotonic()+5)as executor:
            source="print('controlled guest marker')\n";argv,payload=protocol.stdin_command(source)
            result=executor.execute(argv,payload=payload)
            self.assertEqual(b'controlled guest marker\n',result.stdout);self.assertEqual(0,result.returncode)
            self.peer.value['facts']['console']['session']='102'
            with self.assertRaisesRegex(subject.MacBlocked,'macos_ready_identity_changed'):executor.execute(argv,payload=payload)
            self.assertEqual(1,self.custody.actual_calls)
        self.assertEqual(0,self.custody.scopes)

    def test_actual_framed_job_keeps_raw_darwin_boot_original_red_current_green(self):
        before=Path(__file__).parent/'fixtures/tart_macos_raw_boot.before.source'
        self.assertEqual('672f12a69174f3e01abe6c163ae5a1c2423cc6825471a0df5420e91a6f80615f',hashlib.sha256(before.read_bytes()).hexdigest())
        stage=self.root/'before';stage.mkdir();path=stage/'readiness_tart_macos.py';path.write_bytes(before.read_bytes())
        owner=Path(subject.__file__).parent
        for name in ('tart_macos_probe.py','durable_remote_job.py','private_inventory_lock.py'):
            (stage/name).write_bytes((owner/name).read_bytes())
        loader=SourceFileLoader('agent_tools._mac_raw_boot_before',str(path));spec=importlib.util.spec_from_loader(loader.name,loader)
        old=importlib.util.module_from_spec(spec);sys.modules[loader.name]=old;self.addCleanup(sys.modules.pop,loader.name,None);loader.exec_module(old)
        raw_boot=facts()['boot'].upper()
        def assert_complete_job(backend):
            with backend.guest_job_executor(deadline=time.monotonic()+5)as executor:
                argv,payload=protocol.stdin_command('print('+repr(executor.boot)+')\n')
                reply=executor.execute(argv,payload=payload)
            self.assertEqual((raw_boot+'\n').encode(),reply.stdout)
        del self.peer.value['agent']['rawBoot']
        with self.assertRaises(AssertionError):assert_complete_job(old.MacTartBackend(old.MacBinding(**asdict(binding())),self.custody))
        self.peer.value['agent']['rawBoot']=raw_boot
        assert_complete_job(self.backend)
        with self.backend.guest_job_executor(deadline=time.monotonic()+5)as executor:
            self.peer.value['agent']['rawBoot']=raw_boot.lower()
            argv,payload=protocol.stdin_command("print('must not dispatch')\n");before_calls=self.custody.actual_calls
            with self.assertRaisesRegex(subject.MacBlocked,'macos_ready_identity_changed'):executor.execute(argv,payload=payload)
            self.assertEqual(before_calls,self.custody.actual_calls)

    @unittest.skipUnless(os.name=='posix','protected RFB FD path')
    def test_actual_rfb_capture_public_input_and_private_capture_refusal(self):
        endpoint=self.endpoint();ready=self.ready()
        result=self.backend.vnc_action([('key','Space',('MacMeta',)),('capture',)],str(uuid4()),ready,5)
        self.assertTrue(result['capture'].startswith(b'\x89PNG'));self.assertEqual(4,len(endpoint.wait_events(4)))
        other=self.endpoint(capture_safe=lambda:False)
        with self.assertRaisesRegex(subject.MacBlocked,'macos_capture_private_input_possible'):
            self.backend.vnc_action([('capture',)],str(uuid4()),self.ready(),5)
        self.assertEqual([],other.requests)

    @unittest.skipUnless(os.name=='posix','protected RFB FD path')
    def test_secret_group_fd_only_remains_unknown_until_separate_provider_session_observation(self):
        self.enable({'login'});self.peer.value['facts']['console']['locked']=True
        endpoint=self.endpoint();observed=self.observe();operation=str(uuid4())
        directory=self.root/'secret-journal';directory.mkdir(mode=0o700)
        journal=rfb.SecretInputJournal(directory,str(uuid4()))
        reader,writer=os.pipe();self.addCleanup(os.close,reader);os.write(writer,b'fixture-only-secret');os.close(writer)
        result=self.backend.submit_ordinary_credential_from_fd(reader,operation_identity=operation,observed=observed,journal=journal,timeout=5)
        self.assertEqual('unknown',result['state']);self.assertEqual(38,len(endpoint.wait_events(38)))
        self.assertEqual('locked',self.observe().ordinary_session)
        self.assertNotIn('fixture-only-secret',(directory/(operation+'.json')).read_text())

    def test_invalid_public_command_rejected_before_probe_or_endpoint_credential(self):
        ready=self.ready();before=len(self.peer.calls)
        for commands in ([('type','not allowed')],[('key','Enter',([],))],['key','Enter'],[('mouse',-1,0,0)]):
            with self.assertRaises(subject.MacBlocked):self.backend.vnc_action(commands,str(uuid4()),ready,5)
        self.assertEqual(before,len(self.peer.calls));self.assertEqual([],self.custody.effects)


if __name__=='__main__':unittest.main()
