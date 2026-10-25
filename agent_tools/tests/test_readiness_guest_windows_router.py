"""Complete generic/Windows callers over a controlled socket and real journals.

Windows OS/SID facts are modeled; this is not native Windows qualification.
The actual facade, typed executor, source/stream validation, admission and local
historical readers execute unchanged. Only the fixed native transport is owned
by the portable peer below.
"""
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
from types import ModuleType,SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4,uuid5,NAMESPACE_URL

from agent_tools import durable_remote_job as local
from agent_tools import readiness
from agent_tools import readiness_guest_jobs as current
from agent_tools import readiness_windows_jobs as windows
from agent_tools.tests.test_readiness_windows import snapshot
from agent_tools.tests.test_readiness import Provider,SocketAdapter
from agent_tools.tests import test_readiness_guest_jobs as posix_tests


def subject():
    if not os.environ.get('VPN_CONTROL_GUEST_WINDOWS_ROUTER_BEFORE'):return current
    assert os.environ['VPN_CONTROL_GUEST_WINDOWS_ROUTER_BEFORE']=='1'
    folder=Path(__file__).parent/'fixtures/guest_windows_router_before'
    path=folder/'readiness_guest_jobs.py.source';raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((folder/'provenance.json').read_text())['sha256']
    module=ModuleType('agent_tools._guest_windows_router_before');module.__file__=str(path);module.__package__='agent_tools'
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


class GuestWindowsRoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.calls=[];self.lookups=[];self.fixtures={};self.executors={};self.submissions=[];case=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                row=json.loads(self.rfile.readline(262145));case.calls.append(row)
                binding=windows.WindowsJobBinding(**row['binding']);operation=row['operation'];count=row['count']
                target=case.root/'effects';target.mkdir(mode=0o700,exist_ok=True);marker=target/operation
                if row['action']=='job-start':
                    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'execution\n');os.close(fd)
                    case.submissions.append((row['target'],operation))
                assert marker.read_bytes()==b'execution\n'
                config=windows._config(binding,operation,count,row['intervalSeconds'])
                source=(windows._prefix()+'[NativeJob]::Own('+windows._literal(config)+')\n').encode()
                assert hashlib.sha256(windows.program('start',binding,operation,count=count,interval_seconds=row['intervalSeconds'])).hexdigest()==row['packetSha256']
                lines=b''.join(str(n).encode()+b'\n'for n in range(count))
                streams={name:{'bytes':len(body),'base64':base64.b64encode(body).decode(),'sha256':hashlib.sha256(body).hexdigest()}
                    for name,body in {'stdout':lines,'stderr':b'guest sentinel retained stderr\n','counter':b'execution\n'+lines}.items()}
                value={'schemaVersion':1,'operationId':operation,'machine':binding.machine,'boot':binding.boot,
                    'rootGeneration':binding.root_generation,'admissionGeneration':binding.admission_generation,
                    'state':'terminal','reason':'original_terminal_retained','replayAllowed':False,'admissionNonce':str(uuid5(NAMESPACE_URL,operation)),
                    'programSha256':hashlib.sha256(source).hexdigest(),'owner':{'pid':1234,'birth':'134369629130736090','accountSid':'S-1-5-18','sessionId':0},
                    'exitCode':0,'streams':streams}
                self.wfile.write(json.dumps(value).encode()+b'\n')
        self.server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01},daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(windows,'_source_pins',return_value={'controlled-public-source':'fixed'}).start()
        mock.patch.object(windows,'_run',side_effect=self.remote).start()
        mock.patch.object(windows,'executor_from_snapshot',side_effect=self.from_snapshot).start()
        mock.patch.object(current.registry,'registered_fixture',side_effect=self.resolve).start()
        self.module=subject()

    def remote(self,backend,action,operation,deadline,*,binding,count,interval_seconds,**kwargs):
        source=windows.program('start',binding,operation,count=count,interval_seconds=interval_seconds)
        with socket.create_connection(self.server.server_address,timeout=2)as channel:
            channel.sendall(json.dumps({'target':backend.target,'action':action,'operation':operation,
                'binding':windows.asdict(binding),'count':count,'intervalSeconds':interval_seconds,
                'packetSha256':hashlib.sha256(source).hexdigest()}).encode()+b'\n')
            return json.loads(channel.makefile('rb').readline(262145))

    def resolve(self,root,fixture):
        self.lookups.append(fixture);return self.fixtures[fixture]

    def from_snapshot(self,root,saved):
        executor=self.executors[saved['guest']['machine']]
        self.assertEqual(executor.snapshot(),saved);return executor

    def fixture(self,name,provider):
        saved=snapshot();machine=str(uuid4());saved['provider']=provider;saved['binding']['provider']=provider
        saved['binding']['spec']['deploymentId']=machine
        target='windows:controlled:'+machine
        guest=windows.WindowsJobBinding(machine,'2026-10-20T09:04:39.5000000Z','12345678:0003000000000847:01dd6077063bd7e7','12345678:0003000000000848:01dd6077063bd7e8')
        saved['guest']=windows.asdict(guest);saved['sources']={'controlled-public-source':'fixed'}
        backend=SimpleNamespace(root=self.root,target=target,machine=machine,provider=provider,binding=saved['binding'],expected_sid=saved['expectedSid'])
        executor=windows.WindowsJobExecutor(backend,saved);self.executors[machine]=executor
        backend.windows_job_executor=lambda **options:executor
        case=self
        class Adapter:
            capabilities=frozenset()
            def observe(self,requirements,deadline):
                return readiness.Observation(target,machine,connection='controlled',boot=guest.boot,
                    transport='ready',guest='running',guest_agent=True,trusted=True,owned=True,integrity=True)
            def recover(self,*args):raise AssertionError('healthy target recovered')
        adapter=Adapter();adapter.backend=backend
        directory=self.root/name;directory.mkdir(mode=0o700)
        def context(**options):return readiness.Context(target,machine,adapter,readiness.RecoveryJournal(directory),**options)
        self.fixtures[name]=SimpleNamespace(target=target,machine=machine,adapter=adapter,context=context)
        return self.fixtures[name]

    def inputs(self,name,operation=None,**extra):return {'fixtureId':name,'operationId':operation or str(uuid4()),**extra}

    def test_new_start_routes_both_actual_windows_factories_without_posix_uid(self):
        for name,provider in [('fixture-a','raw-qemu-windows'),('fixture-b','libvirt-windows')]:
            self.fixture(name,provider)
            inputs=self.inputs(name,count=121,intervalSeconds=.01)
            result=self.module.workflow(self.root,'start',inputs)
            self.assertEqual((result['provider'],result['executions'],result['counterValues']),(provider,1,121))
            self.assertEqual(self.submissions[-1],(self.fixtures[name].target,inputs['operationId']))
            self.assertFalse((self.root/'.runtime/readiness-guest-jobs').exists())

    def test_original_windows_local_status_collect_and_retry_ignore_removed_registry(self):
        self.fixture('fixture-a','raw-qemu-windows');inputs=self.inputs('fixture-a',count=3,intervalSeconds=.01)
        expected=windows.workflow(self.root,'start',inputs)
        self.fixtures.clear()
        with mock.patch.object(current.registry,'registered_fixture',side_effect=AssertionError('historical lookup')):
            for action in ('status','collect','reconcile'):
                self.assertEqual(self.module.workflow(self.root,action,{k:inputs[k]for k in ('fixtureId','operationId')}),expected)
            self.assertEqual(self.module.workflow(self.root,'start',inputs),expected)
        self.assertEqual(len(self.submissions),1)

    def test_missing_original_nonstart_never_resolves_fixture_or_creates_state(self):
        for action in ('status','collect','reconcile'):
            with self.assertRaises(ValueError):self.module.workflow(self.root,action,self.inputs('missing'))
        self.assertEqual(self.lookups,[]);self.assertEqual(list(self.root.iterdir()),[])

    def test_ambiguous_local_originals_block_before_registry_or_transport(self):
        self.fixture('fixture-a','raw-qemu-windows');inputs=self.inputs('fixture-a',count=3,intervalSeconds=.01)
        windows.workflow(self.root,'start',inputs)
        directory=current._operation(current._directory(self.root,'fixture-a',create=True),inputs['operationId'],create=True)
        intent={'schemaVersion':1,'fixtureId':'fixture-a','operationId':inputs['operationId'],
            'binding':{'target':'posix-a','machine':'machine-a','boot':'boot-a','account':'1000'},'namespace':{},'spec':{'count':3,'intervalSeconds':.01}}
        local._publish(directory/'intent.json',intent);self.lookups.clear();before=list(self.calls)
        with self.assertRaisesRegex(ValueError,'guest_original_provider_ambiguous'):
            self.module.workflow(self.root,'status',self.inputs('fixture-a',inputs['operationId']))
        self.assertEqual(self.lookups,[]);self.assertEqual(self.calls,before)


class OriginalPosixTargetFenceTests(unittest.TestCase):
    def test_whole_original_reconcile_cannot_recover_different_registered_vm(self):
        fixture=posix_tests.RegisteredGuestJobsTests('test_real_socket_lost_submission_ack_fresh_caller_observes_once_and_local_tools')
        fixture.setUp();self.addCleanup(fixture.tearDown)
        operation=str(uuid4());current.start(fixture.root,'fixture',operation,count=40,interval_seconds=.02)
        original_fixture=current.registry.registered_fixture.return_value
        temporary=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);server=Provider(root/'provider.sock')
        server.observation=replace(server.observation,target='different-vm',machine='different-machine',transport='dead')
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        adapter=SocketAdapter(root/'provider.sock');adapter.backend=original_fixture.adapter.backend
        (root/'journal').mkdir(mode=0o700)
        other=SimpleNamespace(target='different-vm',machine='different-machine',adapter=adapter,
            context=lambda **kwargs:readiness.Context('different-vm','different-machine',adapter,readiness.RecoveryJournal(root/'journal'),**kwargs))
        try:
            current.registry.registered_fixture.return_value=other
            with self.assertRaises(ValueError):subject().reconcile(fixture.root,'fixture',operation)
            self.assertEqual(server.effects,[],'original retry recovered a different actual provider socket')
        finally:
            current.registry.registered_fixture.return_value=original_fixture
            fixture.finish(operation)

    def test_original_posix_terminal_ignores_new_windows_registry_metadata(self):
        fixture=posix_tests.RegisteredGuestJobsTests('test_real_socket_lost_submission_ack_fresh_caller_observes_once_and_local_tools')
        fixture.setUp();self.addCleanup(fixture.tearDown)
        operation=str(uuid4());current.start(fixture.root,'fixture',operation,count=1,interval_seconds=.01)
        expected=fixture.finish(operation)
        with mock.patch.object(current.registry,'registered_fixture',side_effect=AssertionError('local history resolved new Windows metadata')):
            for action in ('status','collect','reconcile'):
                result=subject().workflow(fixture.root,action,{'fixtureId':'fixture','operationId':operation})
                self.assertEqual(result,expected)
            self.assertEqual(subject().workflow(fixture.root,'start',{'fixtureId':'fixture','operationId':operation,
                'count':1,'intervalSeconds':.01}),expected)


if __name__=='__main__':unittest.main()
