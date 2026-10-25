"""Exact original host phases end bookkeeping; all other work stays blocking."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import re
import socket
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import uuid4
from agent_tools import readiness,readiness_windows as windows,readiness_windows_remote as packets,readiness_windows_host_work as work
from agent_tools.tests import test_readiness_windows_host_work as evidence
from agent_tools.tests import test_readiness_windows_sockets as sockets

FIXTURE=Path(__file__).parent/'fixtures/windows_host_phase_integration'


def before(name):
    if name not in {'main.before.source','remote.before.source'}:raise ValueError('unreviewed_host_phase_source')
    raw=(FIXTURE/name).read_bytes();provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
    if hashlib.sha256(raw).hexdigest()!=provenance['sourceSha256'][name]:raise ValueError('host_phase_before_changed')
    module=types.ModuleType('agent_tools._host_phase_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/name)
    exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class BackendOriginalHostPhaseTests(unittest.TestCase):
    def setUp(self):
        self.case=evidence.HostWorkTests('test_exact_actual_original_documents_source_graph_and_complete_eof_join');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.args=self.case.arguments();self.target='windows:'+self.args['spec']['host']+':'+self.args['spec']['deploymentId']
        work.register_libvirt_lifecycle_proofs(self.case.root,self.target,**self.args)
        self.binding={'provider':'libvirt-windows','spec':self.args['spec'],'setup':self.args['setup'],'context':{'hostBootId':self.args['host_boot'],'pending':[]},
          'uri':'qemu+unix:///session?socket=/home/kardinal/.cache/libvirt/virtqemud-sock','domain':'vc-recovery-libvirt-6e848ad1','xmlSha256':'d8a62b4aea128bc662365780295ce23b15e0dffb268794383bb30ce3ddf72eec'}
        self.credential=self.case.root/'.runtime/public-test.secret';self.credential.write_bytes(b'public-test-only\n');self.credential.chmod(0o600)

    def discover(self,module):
        backend=module.WindowsBackend(self.case.root,self.binding,'S-1-5-21-1325923382-2858512530-2380919517-1000',capabilities=frozenset({'reboot'}),credential_file=str(self.credential.resolve()))
        self.addCleanup(backend.close)
        with mock.patch.object(module.job_module,'namespace_binding',return_value=None),mock.patch.object(backend,'_run',side_effect=ValueError('controlled_stop_before_transport'))as dispatch:
            with self.assertRaisesRegex(ValueError,'controlled_stop_before_transport'):backend.observe(readiness.Requirements(frozenset({'guest_agent'})),99999999999)
        return dispatch.call_args.kwargs.get('original_host_phases',())

    def test_whole_backend_before_omits_proof_RED_fixed_passes_exact_two_GREEN(self):
        with self.assertRaises(AssertionError):self.assertEqual(2,len(self.discover(before('main.before.source'))))
        proofs=self.discover(windows);self.assertEqual(2,len(proofs))
        self.assertTrue(all(proof.guard()['machine']==self.binding['spec']['deploymentId']for proof in proofs))

    def test_changed_original_evidence_blocks_before_transport(self):
        self.case.write(self.args['define_capture'],self.case.payloads['define.capture.json']+b' ')
        backend=windows.WindowsBackend(self.case.root,self.binding,'S-1-5-21-1325923382-2858512530-2380919517-1000',capabilities=frozenset({'reboot'}),credential_file=str(self.credential.resolve()));self.addCleanup(backend.close)
        with mock.patch.object(windows.job_module,'namespace_binding',return_value=None),mock.patch.object(backend,'_run',side_effect=AssertionError('changed_original_capture_reached_transport_boundary'))as dispatch:
            with self.assertRaisesRegex(readiness.AdapterBlocked,'integrity_mismatch'):backend.observe(readiness.Requirements(frozenset({'guest_agent'})),99999999999)
        dispatch.assert_not_called()

    def test_native_before_projection_authenticates_only_two_owned_failures(self):
        raw=(FIXTURE/'native-before.json').read_bytes();provenance=json.loads((FIXTURE/'provenance.json').read_bytes());self.assertEqual(provenance['sourceSha256']['native-before.json'],hashlib.sha256(raw).hexdigest())
        value=json.loads(raw);self.assertEqual(22,value['totalNativeUnresolved']);self.assertEqual({'libvirt-define.intent.json','libvirt-start.intent.json'},{r['receipt']for r in value['unresolvedOriginalPhases']})

    def test_actual_host_inventory_decision_requires_nested_namespace_visibility(self):
        (self.case.root/'lifecycle-jobs').mkdir(mode=0o700)
        results=[]
        for producer in (before('remote.before.source'),packets):
            tree=ast.parse(producer.program(self.binding,'observe',str(uuid4())))
            nodes=[node for node in ast.walk(tree)if isinstance(node,ast.FunctionDef)and node.name=='host_work']
            self.assertEqual(1,len(nodes))
            def require(value,reason):
                if not value:raise ValueError(reason)
            namespace={'root':self.case.root,'SPEC':self.binding['spec'],'os':os,'re':re,'ORIGINAL_HOST_PHASES':[],'CREATOR_ENROLLED':False,'require':require}
            exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<actual-generated-host-inventory>','exec'),namespace)
            results.append(namespace['host_work']())
        self.assertTrue(results[0]['visibilityComplete'])
        self.assertFalse(results[1]['visibilityComplete'])
        self.assertIn({'receipt':'lifecycle-jobs','reason':'lifecycle_host_work_visibility_missing'},results[1]['unresolved'])

    def test_creator_namespace_or_retained_original_requires_complete_inventory(self):
        root=self.case.root/'vm';root.mkdir(mode=0o700)
        creator=self.case.root/'.cache/vpn-control-fixture-creators'/self.binding['spec']['deploymentId']
        marker=root/'managed-create-host-original.json'
        for path in (creator,marker):
            if path==creator:path.mkdir(mode=0o700,parents=True)
            else:path.write_text('{}')
            results=[]
            for producer in (before('remote.before.source'),packets):
                tree=ast.parse(producer.program(self.binding,'observe',str(uuid4())))
                nodes=[node for node in ast.walk(tree)if isinstance(node,ast.FunctionDef)and node.name=='host_work']
                def require(value,reason):
                    if not value:raise ValueError(reason)
                namespace={'root':root,'SPEC':self.binding['spec'],'os':os,'re':re,'ORIGINAL_HOST_PHASES':[],'CREATOR_ENROLLED':False,'require':require}
                exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<actual-creator-inventory-decision>','exec'),namespace)
                results.append(namespace['host_work']())
            self.assertTrue(results[0]['visibilityComplete'])
            self.assertFalse(results[1]['visibilityComplete'])
            self.assertIn({'receipt':'creator-namespace','reason':'creator_work_visibility_missing'},results[1]['unresolved'])
            if path==creator:path.rmdir()
            else:path.unlink()


@unittest.skipUnless(os.name=='posix','actual Unix socket fixture ABI')
class ControlledIdleEndpointTests(unittest.TestCase):
    def test_actual_endpoint_before_missing_idle_shape_RED_current_idle_reply_GREEN(self):
        provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
        for name in ('test.before.source','endpoint-native-failure.json'):
            self.assertEqual(provenance['sourceSha256'][name],hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest())
        failure=json.loads((FIXTURE/'endpoint-native-failure.json').read_bytes())
        self.assertEqual(('failed',8,4,0),(failure['state'],failure['testsRun'],failure['errors'],failure['failures']))
        session=sockets.facts();machine=session['machine'].lower()
        from agent_tools import readiness_windows_idle
        source=readiness_windows_idle.powershell_source(machine,None,'recovery',sockets.SID,None)
        for name,fixed in (('endpoint.before.source',False),('endpoint.py',True)):
            raw=(FIXTURE/name).read_bytes();self.assertEqual(provenance['sourceSha256'][name],hashlib.sha256(raw).hexdigest())
            with tempfile.TemporaryDirectory(prefix='vc-idle-abi-',dir='/tmp')as temporary:
                root=Path(temporary)
                (root/'fixture.json').write_text(json.dumps({'machine':machine,'sessionFacts':session}))
                for leaf in ('disk.qcow2','uefi-vars.fd'):(root/leaf).write_bytes(b'public-owned-fixture')
                child=subprocess.Popen([sys.executable,'-I','-B',str(FIXTURE/name),str(root),'qemu'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                try:
                    deadline=time.monotonic()+5
                    while not(root/'qga.sock.ready').exists():
                        self.assertIsNone(child.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
                    def request(command,arguments):
                        with socket.socket(socket.AF_UNIX)as channel:
                            channel.settimeout(5);channel.connect(str(root/'qga.sock'))
                            channel.sendall((json.dumps({'execute':command,'arguments':arguments})+'\n').encode())
                            with channel.makefile('rb')as stream:return json.loads(stream.readline(262145))['return']
                    ack=request('guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-Command','-'],'input-data':base64.b64encode(source.encode()).decode()})
                    terminal=request('guest-exec-status',{'pid':ack['pid']})
                    value=json.loads(base64.b64decode(terminal['out-data']))
                    if fixed:self.assertEqual(session,value['sessionFacts'])
                    else:
                        with self.assertRaises(KeyError):value['sessionFacts']
                finally:
                    child.terminate();child.communicate(timeout=5)


@unittest.skipUnless(sys.platform=='linux','actual Linux process, FD and QMP/QGA sockets')
class CompleteHostPhaseSocketTests(unittest.TestCase):
    def setUp(self):
        with mock.patch.object(sockets,'ENDPOINT',FIXTURE/'endpoint.py'):
            sockets.CompleteWindowsSocketTests.setUp(self)
    run_packet=sockets.CompleteWindowsSocketTests.run_packet

    def accepted(self):
        case=evidence.HostWorkTests('test_exact_actual_original_documents_source_graph_and_complete_eof_join');case.setUp();self.addCleanup(case.doCleanups)
        result=[]
        # Only the trusted local proof-issuance boundary is controlled here:
        # relocate authenticated historical documents into this harmless kernel
        # fixture. Actual source/EOF/metadata authentication runs in the backend
        # and host-work module tests. The generated caller/VM guards are real.
        for proof in case.proofs():
            value=proof.guard();value.update(machine=self.machine,root=str(self.root),hostBoot=self.binding['context']['hostBootId'])
            for field,name in [('intent','intentName'),('result','resultName')]:
                path=self.root/value[name];path.write_text(json.dumps(value[field]));path.chmod(0o600)
            result.append(work.OriginalPhaseProof(work._canonical(value),proof._root,proof._pins,work._AUTHORITY))
        return tuple(result)

    def pending(self,value):return {r['receipt']for r in value['hostWork']['unresolved']}

    def test_whole_before_schema_mismatch_RED_fixed_original_phase_ended_GREEN(self):
        proofs=self.accepted();names={p.guard()['intentName']for p in proofs}
        old=self.run_packet(producer=before('remote.before.source'),idle=True,expected_sid=sockets.SID)
        with self.assertRaises(AssertionError):self.assertFalse(names&self.pending(old))
        (self.root/'unrelated.intent.json').write_text('{}');(self.root/'unrelated.intent.json').chmod(0o600)
        current=self.run_packet(idle=True,expected_sid=sockets.SID,original_host_phases=proofs)
        self.assertFalse(names&self.pending(current));self.assertIn('unrelated.intent.json',self.pending(current))
        counters=json.loads((self.root/'counters.json').read_bytes());self.assertEqual(0,counters['inputCount'])

    def test_nested_host_namespace_before_ignored_RED_fixed_visibility_blocked_GREEN(self):
        (self.root/'lifecycle-jobs').mkdir(mode=0o700)
        old=self.run_packet(producer=before('remote.before.source'),idle=True,expected_sid=sockets.SID)
        self.assertTrue(old['hostWork']['visibilityComplete'])
        current=self.run_packet(idle=True,expected_sid=sockets.SID)
        self.assertFalse(current['hostWork']['visibilityComplete'])
        self.assertIn({'receipt':'lifecycle-jobs','reason':'lifecycle_host_work_visibility_missing'},current['hostWork']['unresolved'])
        self.assertEqual(0,json.loads((self.root/'counters.json').read_bytes())['inputCount'])

    def test_missing_or_changed_current_original_document_remains_blocker(self):
        proofs=self.accepted();name=proofs[0].guard()['resultName'];path=self.root/name;original=path.read_bytes();path.unlink()
        value=self.run_packet(idle=True,expected_sid=sockets.SID,original_host_phases=proofs);self.assertIn(proofs[0].guard()['intentName'],self.pending(value))
        path.write_bytes(original+b' ');path.chmod(0o600)
        document=json.loads(original);document['state']='forged';path.write_text(json.dumps(document));path.chmod(0o600)
        value=self.run_packet(idle=True,expected_sid=sockets.SID,original_host_phases=proofs);self.assertIn(proofs[0].guard()['intentName'],self.pending(value))

    def test_absent_intent_and_untyped_or_foreign_authority_never_hide_work(self):
        proofs=self.accepted();name=proofs[0].guard()['intentName'];(self.root/name).unlink()
        value=self.run_packet(idle=True,expected_sid=sockets.SID,original_host_phases=proofs);self.assertIn(name,self.pending(value))
        for invalid in (({'ready':True},),[proofs[0]]):
            with self.assertRaisesRegex(ValueError,'windows_host_work_authority_invalid'):packets.program(self.binding,'observe',str(uuid4()),original_host_phases=invalid)
        body=proofs[0].guard();body['machine']=str(uuid4());foreign=work.OriginalPhaseProof(work._canonical(body),proofs[0]._root,proofs[0]._pins,work._AUTHORITY)
        with self.assertRaisesRegex(ValueError,'windows_host_work_identity_changed'):packets.program(self.binding,'observe',str(uuid4()),original_host_phases=(foreign,))


if __name__=='__main__':unittest.main()
