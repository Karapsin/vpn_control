"""Actual historical schemas, strict source/EOF custody and controller boundaries."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from agent_tools import readiness_windows_host_work as work

FIXTURE=Path(__file__).parent/'fixtures/windows_host_work'


def fixtures():
    provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
    if provenance['schemaVersion']!=1 or set(provenance['sourceSha256'])!=set(provenance['originalPaths']):
        raise AssertionError('host work fixture scope changed')
    result={}
    for name,expected in provenance['sourceSha256'].items():
        raw=(FIXTURE/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise AssertionError('host work fixture changed: '+name)
        result[name]=raw
    return provenance,result


class HostWorkTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.provenance,self.payloads=fixtures()
        for name,path in self.provenance['originalPaths'].items():self.write(path,self.payloads[name])
        self.constants={}
        for node in ast.parse(self.payloads['define.source']).body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                self.constants[node.targets[0].id]=ast.literal_eval(node.value)

    def write(self,path,raw):
        actual=self.root/path;actual.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        actual.write_bytes(raw);actual.chmod(0o600)

    def arguments(self):
        p=self.provenance['originalPaths'];c=self.constants
        return dict(snapshot_path=p['documents.result.json'],
            define_source=p['define.source'],define_capture=p['define.capture.json'],define_closing=p['define.closing.json'],
            start_source=p['start.source'],start_capture=p['start.capture.json'],start_closing=p['start.closing.json'],
            spec=c['SPEC'],setup=c['SETUP'],host_boot=c['CONTEXT']['hostBootId'])

    def proofs(self):
        return work.libvirt_lifecycle_proofs(self.root,**self.arguments())

    def test_exact_actual_original_documents_source_graph_and_complete_eof_join(self):
        values=self.proofs()
        self.assertEqual(2,len(values))
        for proof,state in zip(values,('libvirt_defined','libvirt_running')):
            expected=proof.guard()
            self.assertEqual(state,expected['result']['state'])
            observed=work.original_phase_terminal(expected['intent'],expected['result'],proof)
            self.assertTrue(observed['controllerTerminal'])
            self.assertFalse(observed['guestWorkComplete'])
            self.assertFalse(observed['currentBindingAuthorized'])
            self.assertFalse(observed['replayAllowed'])
            self.assertEqual('qemu:///session',expected['result']['uri'])
        namespace={};exec(compile(work.protocol_source(),'<current-phase-protocol>','exec'),namespace)
        expected=values[0].guard()
        self.assertEqual(work.original_phase_terminal(expected['intent'],expected['result'],values[0]),
                         namespace['_original_phase_terminal'](expected['intent'],expected['result'],expected))

    def test_actual_old_consumer_schema_failure_and_strict_original_phase_green(self):
        # Full beforeimage and native c810 failure are retained. This is the finite
        # nested host_work projection; whole generated-caller integration is owned
        # by the Windows remote/socket tests, not claimed by this projection.
        tree=ast.parse(self.payloads['remote.before.source'])
        nodes=[n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='host_work']
        self.assertEqual(1,len(nodes))
        files={}
        snapshot=json.loads(self.payloads['documents.result.json'])
        for row in snapshot['records']:
            for item in row['files']:
                if item.get('present')is True and 'publicBody'in item:files[item['name']]=item['publicBody']
        directory=self.root/'projection';directory.mkdir()
        for name,body in files.items():(directory/name).write_text(json.dumps(body))
        def require(value,reason):
            if not value:raise ValueError(reason)
        namespace={'root':directory,'os':os,'re':re,'read':lambda name:files[name],
                   'read_guest_terminal':lambda name:files[name],'require':require}
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),'<preserved-host-work>','exec'),namespace)
        old=namespace['host_work']()
        self.assertEqual(0,old['terminalCount'])
        self.assertEqual({'libvirt-define.intent.json','libvirt-start.intent.json'},
                         {r['receipt']for r in old['unresolved']})
        self.assertEqual({'original_lifecycle_unresolved'},{r['reason']for r in old['unresolved']})
        for proof in self.proofs():
            expected=proof.guard()
            self.assertTrue(work.original_phase_terminal(files[expected['intentName']],files[expected['resultName']],proof)['controllerTerminal'])

    def test_source_changed_native_eof_incomplete_or_custody_changed_never_closes(self):
        for name,change in (
                ('define.source',lambda raw:raw.replace(b"value={'state':'libvirt_defined'",b"value={'state':'defined'",1)),
                ('define.capture.json',lambda raw:json.dumps(dict(json.loads(raw),capture={**json.loads(raw)['capture'],'eof':{'stdout':False,'tty':True}})).encode()),
                ('start.closing.json',lambda raw:json.dumps(dict(json.loads(raw),sourceClosing=False)).encode()),
                ('documents.source',lambda raw:raw+b'\n# different observer\n')):
            with self.subTest(name=name):
                path=self.provenance['originalPaths'][name]
                self.write(path,change(self.payloads[name]))
                with self.assertRaises(ValueError):self.proofs()
                self.write(path,self.payloads[name])
        proof=self.proofs()[0]
        path=self.provenance['originalPaths']['define.closing.json']
        actual=self.root/path;raw=actual.read_bytes();actual.unlink();self.write(path,raw)
        with self.assertRaisesRegex(ValueError,'evidence_changed'):proof.guard()

    def test_intent_result_source_xml_uuid_or_phase_changes_do_not_match_original_proof(self):
        for proof in self.proofs():
            expected=proof.guard()
            for key,value in (('operationId','00000000-0000-4000-8000-000000000001'),('uuid','00000000-0000-4000-8000-000000000002'),
                              ('uri','qemu+unix:///session?socket=/different'),('domain','different'),('state','running'),('replayAllowed',True)):
                with self.subTest(phase=expected['kind'],key=key):
                    result=dict(expected['result']);result[key]=value
                    with self.assertRaisesRegex(ValueError,'original_changed'):
                        work.original_phase_terminal(expected['intent'],result,proof)
        forged=work.OriginalPhaseProof('{}',self.root,(),object())
        with self.assertRaisesRegex(ValueError,'authority_invalid'):forged.guard()

    def test_accepted_metadata_is_explicit_create_only_and_normal_lookup_is_pure(self):
        args=self.arguments();identity={k:args[k]for k in ('spec','setup','host_boot')}
        before=sorted(str(p.relative_to(self.root))for p in self.root.rglob('*'))
        self.assertEqual((),work.accepted_libvirt_lifecycle_proofs(self.root,'fixture-target',**identity))
        self.assertEqual(before,sorted(str(p.relative_to(self.root))for p in self.root.rglob('*')))
        work.register_libvirt_lifecycle_proofs(self.root,'fixture-target',**args)
        work.register_libvirt_lifecycle_proofs(self.root,'fixture-target',**args)
        proof=work.accepted_libvirt_lifecycle_proofs(self.root,'fixture-target',**identity)
        self.assertEqual(2,len(proof))
        self.assertEqual(self.proofs()[0].guard(),proof[0].guard())
        actual=self.root/self.provenance['originalPaths']['start.closing.json']
        actual.write_bytes(actual.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'evidence_changed'):proof[0].guard()

    def controller(self):
        operation='12345678-1234-4234-8234-123456789012';label='job-status-abcd1234'
        script='# Fixed public controller fixture.\n';digest=hashlib.sha256(script.encode()).hexdigest()
        host='12345678-1234-4234-8234-123456789013';actor={'pid':100,'startTicks':500}
        machine='12345678-1234-4234-8234-123456789014';path='.runtime/controller-fixture.py'
        source=('OPERATION='+repr(operation)+'\nMODE="job-status"\nSPEC='+repr({'deploymentId':machine})+
                '\nCONTEXT='+repr({'hostBootId':host})+'\nSESSION_SCRIPT='+repr(script)+'\n').encode()
        self.write(path,source)
        proof=work.controller_proof(self.root,path,hashlib.sha256(source).hexdigest(),script_name='SESSION_SCRIPT',
                                    operation=operation,label=label,machine=machine,host_boot=host,actor=actor)
        frame={'schemaVersion':1,'operationId':operation,'label':label,'sourceSha256':digest}
        intent={**frame,'hostBoot':host,'actor':actor,'replayAllowed':False,'controllerIdentity':dict(frame)}
        ack={'operationId':operation,'label':label,'replayAllowed':False,'ack':{'pid':123}}
        body={**frame,'owner':{'pid':123,'birth':'134369916462713843'},'result':{'state':'running'}}
        terminal={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(body).encode()).decode()}
        args={'proof':proof}
        return intent,ack,terminal,args,body

    def test_original_framed_controller_terminal_never_completes_running_guest_job(self):
        intent,ack,terminal,args,body=self.controller()
        value=work.controller_terminal(intent,ack,terminal,**args)
        self.assertTrue(value['controllerTerminal']);self.assertFalse(value['guestWorkComplete']);self.assertFalse(value['replayAllowed'])
        terminal['exitcode']=7
        self.assertEqual(7,work.controller_terminal(intent,ack,terminal,**args)['exitCode'])
        for owner in ({'pid':124,'birth':body['owner']['birth']},{'pid':123,'birth':'0'},{'pid':True,'birth':'1'}):
            changed={**body,'owner':owner};terminal['out-data']=base64.b64encode(json.dumps(changed).encode()).decode()
            with self.assertRaisesRegex(ValueError,'identity_changed'):work.controller_terminal(intent,ack,terminal,**args)

    def test_missing_ack_unframed_echo_truncation_and_bool_schema_are_blocked_without_disclosure(self):
        intent,ack,terminal,args,body=self.controller()
        for name,value in (('out-data',base64.b64encode(b'PRIVATE-CANARY-NOT-A-FRAME').decode()),('out-truncated',True),('exited',False)):
            changed={**terminal,name:value}
            with self.assertRaises(ValueError)as caught:work.controller_terminal(intent,ack,changed,**args)
            self.assertNotIn('PRIVATE-CANARY',str(caught.exception))
        with self.assertRaises(ValueError):work.controller_terminal(intent,{},terminal,**args)
        intent['controllerIdentity']['schemaVersion']=True
        with self.assertRaises(ValueError):work.controller_terminal(intent,ack,terminal,**args)

    def test_controller_source_is_original_held_packet_not_reconstructed_current_source(self):
        intent,ack,terminal,args,body=self.controller()
        path=self.root/'.runtime/controller-fixture.py'
        path.write_bytes(path.read_bytes()+b'# replaced generation\n')
        with self.assertRaisesRegex(ValueError,'evidence_changed'):
            work.controller_terminal(intent,ack,terminal,**args)
        with self.assertRaisesRegex(ValueError,'authority_invalid'):
            work.controller_terminal(intent,ack,terminal,{})


if __name__=='__main__':unittest.main()
