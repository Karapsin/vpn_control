"""Fixed route/privacy tests with inert upstream getters and real private files."""
import base64
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_api35_remaining_proxy_status_routes as routes

OWNER='58d546ea-8208-40a3-bba4-e8759768284e'
def value():
    final={'kind':'clear','settings':{'rows':{'global_http_proxy_exclusion_list':''},'values':{'global_http_proxy_exclusion_list':'','global_http_proxy_host':'null','global_http_proxy_port':'null','global_http_proxy_pac':'null','http_proxy':'null'}},'binder':{'schema':1,'uid':2000,'state':'observed','correlationId':routes.getter.diagnostic.original.PROBE_CORRELATION,'reads':[{'global':None,'defaultForShell':None}]*2}}
    record={'present':True,'generation':[66307,103963732,2730,1791079923423144884,1791079923423144884,33152,0,0,1],'sha256':'e8708b421210231777df69c231632b3f63ef4c5ff099d090da47df96f720925f','value':{'final':final},'rawBase64':'PRIVATE_RAW_LITERAL'}
    public=[]
    for i in range(4):
        envelope={'schemaVersion':1,'ok':True,'code':'OK','final':True,'controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'} if i%2==0 else {'operations':[]}}
        public.append({'returncode':0,'stdout':envelope,'captureComplete':True,'stderrRaw':'','stdoutRaw':'PRIVATE_RAW_LITERAL','componentRuntime':'EXTERNAL_JDK','backendSourceSha256':routes.getter.diagnostic.original.COMPONENT_SOURCE})
    return {'state':'remaining-proxy-restored','closingGuardsVerified':True,'correlationId':routes.CORRELATION,'originalOperationOutcome':'unknown','historicalUnknownsPreserved':True,'replayAllowed':False,'pacEffectSubmitted':False,'productAdmitted':False,'acceptanceComplete':False,'currentControllerId':OWNER,'result':{'record':record},'records':{'partialPublic':public,'partialJournals':[{'terminal.json':{'present':False}}]}}


def chunks(item):
    record={'returncode':0,'stdoutB64':base64.b64encode(json.dumps(item).encode()).decode(),'stderrB64':'','timedOut':False,'outputLimit':False};raw=json.dumps(record).encode()
    return (json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})+'\n').encode()+b''.join(base64.b64encode(raw[n:n+1536])+b'\n' for n in range(0,len(raw),1536))
class RoutesTests(unittest.TestCase):
    def test_actual_success_projection_has_observed_reason(self):
        result=routes._projection(value(),{'sha256':'a'*64,'bytes':233907},value()['result']['record'])
        self.assertTrue(result['ok']);self.assertEqual('observed',result['reason'])
    def test_projection_rejects_noncanonical_owner(self):
        for owner in ('-'*36,'a'*36,'401cea62-1852-4642-bd4d-a9d5ed37239-'):
            item=value();item['currentControllerId']=owner
            for record in item['records']['partialPublic']:record['stdout']['controllerId']=owner
            self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1},value()['result']['record'])['ok'])
    def test_projection_rejects_boolean_exit_code(self):
        item=value();item['records']['partialPublic'][0]['returncode']=False
        self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1},value()['result']['record'])['ok'])
    def fixture(self,root):
        p=root/'.rag_index/native-environments';p.mkdir(parents=True);p.chmod(0o700)
        row={'id':routes.RESERVATION,'token':'PRIVATE_RESERVATION_TOKEN','hostAlias':'archlinux','environment':'owned-android-api35-coldboot','operator':'root-android','requestedMemoryBytes':2147483648,'allocationState':'running'}
        (p/'reservations.json').write_text(json.dumps({'reservations':[row]}));(p/'reservations.json').chmod(0o600)
        (root/'.codex').mkdir(mode=0o700);(root/'.codex/arch-sudo.local').write_bytes(b'PRIVATE_SUDO_SECRET');(root/'.codex/arch-sudo.local').chmod(0o600)
        (root/routes.ssh_transport.CONFIG_FILENAME).write_text('{}');(root/routes.ssh_transport.CONFIG_FILENAME).chmod(0o600)
        proof=root/'.runtime/parity-evidence'/routes.CAPSULE;proof.mkdir(parents=True,mode=0o700);file=proof/'status-remote-stdout-0.private';file.write_bytes(json.dumps(value()).encode());file.chmod(0o600)
    def mocks(self,stack,transport):
        stack.enter_context(mock.patch.object(routes.getter,'status',return_value={'snapshots':{},'claims':{},'program':'fixed readonly actual status'}));stack.enter_context(mock.patch.object(routes.getter,'guard_prepared'))
        stack.enter_context(mock.patch.object(routes.getter,'carrier',return_value='fixed-carrier'))
        stack.enter_context(mock.patch.object(routes.ssh_transport,'load_config',return_value=types.SimpleNamespace(hosts={'archlinux':object()})))
        stack.enter_context(mock.patch.object(routes.ssh_transport,'connection_host',return_value=types.SimpleNamespace(password=None)))
        stack.enter_context(mock.patch.object(routes,'PROOF_SHA',hashlib.sha256(json.dumps(value()).encode()).hexdigest()))
        build=stack.enter_context(mock.patch.object(routes.ssh_transport,'build_ssh_argv',return_value=['fixed-ssh']))
        run=stack.enter_context(mock.patch.object(routes,'_transport',side_effect=transport));return build,run
    def test_invalid_input_never_reads_credential_or_prepares_action(self):
        for data in ({'device':'api35'},{'pid':1},{'path':'/tmp'},None,[]):
            with mock.patch.object(routes.getter,'status') as prepare,mock.patch.object(routes.private,'Snapshot') as private:
                result=routes.dispatch(Path('/unused'),routes.ACTION,data);self.assertEqual('invalid_inputs',result['reason']);prepare.assert_not_called();private.assert_not_called()
    def test_valid_flow_is_private_and_credential_only_transport_stdin(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root);seen=[]
            def transport(argv,credential,record):seen.append((argv,credential));record.update(stdout=chunks(value()),returncode=0)
            build,run=self.mocks(stack,transport);result=routes.dispatch(root,routes.ACTION,{})
            self.assertTrue(result['ok']);self.assertTrue(result['runtimeOff']);self.assertEqual(4,result['recordCount']);public=json.dumps(result)
            for text in ('PRIVATE_RULE_LITERAL','PRIVATE_RAW_LITERAL','PRIVATE_RESERVATION_TOKEN','PRIVATE_SUDO_SECRET',str(root)):self.assertNotIn(text,public)
            self.assertNotIn('PRIVATE_SUDO_SECRET',repr(build.call_args));self.assertEqual(b'PRIVATE_SUDO_SECRET',seen[0][1]);run.assert_called_once()
            capsule=next((root/'.runtime/parity-evidence/android-api35-remaining-proxy-status-mcp').glob('*/result.json'));self.assertEqual(0o600,capsule.stat().st_mode&0o777);self.assertEqual(0o700,capsule.parent.stat().st_mode&0o777);self.assertEqual(result['receiptSha256'],hashlib.sha256(capsule.read_bytes()).hexdigest());self.assertIn('PRIVATE_RAW_LITERAL',capsule.read_text())
    def test_timeout_retains_partial_private_receipt_without_resubmission(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root)
            def transport(argv,credential,record):record.update(stdout=b'partial-private-bytes',timedOut=True);raise TimeoutError('PRIVATE_EXCEPTION')
            _,run=self.mocks(stack,transport);result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);self.assertNotIn('PRIVATE_EXCEPTION',json.dumps(result));run.assert_called_once()
            receipt=json.loads(next((root/'.runtime/parity-evidence/android-api35-remaining-proxy-status-mcp').glob('*/receipt.json')).read_bytes());self.assertEqual(b'partial-private-bytes',base64.b64decode(receipt['transport']['stdoutB64']));self.assertTrue(receipt['transport']['timedOut'])
    def test_post_transport_guard_drift_keeps_unknown_receipt(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root)
            def transport(argv,credential,record):record.update(stdout=chunks(value()),returncode=0);p=root/'.rag_index/native-environments/reservations.json';p.write_text(p.read_text()+' ')
            _,run=self.mocks(stack,transport);result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);run.assert_called_once()
    def test_wrong_frozen_source_rejects_before_credentials_transport(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root);_,run=self.mocks(stack,lambda *args:None);stack.enter_context(mock.patch.object(routes,'FROZEN','0'*64));result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);run.assert_not_called();self.assertFalse((root/'.runtime/parity-evidence/android-api35-remaining-proxy-status-mcp').exists())
    def test_chunk_binding_drift_and_noncanonical_types_reject(self):
        good=chunks(value());self.assertEqual(OWNER,routes._decode(good)[1]['currentControllerId'])
        with self.assertRaises(ValueError):routes._decode(good.replace(b'"bytes":',b'"bytes":true,"ignored":'))
        with self.assertRaises(Exception):routes._decode(good[:-5]+b'AAAA\n')
    def test_actual_transport_subprocess_capture_is_bounded_and_partial_on_timeout(self):
        import sys
        record={'stdout':b'','stderr':b'','returncode':None,'timedOut':False}
        routes._transport([sys.executable,'-c','import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b"bounded");sys.stderr.buffer.write(b"private")'],b'inert',record)
        self.assertEqual(b'bounded',record['stdout']);self.assertTrue(record['stderr'].endswith(b'private'));self.assertEqual(0,record['returncode'])
    def test_actual_transport_timeout_retains_partial_bytes(self):
        import sys,time
        record={'stdout':b'','stderr':b'','returncode':None,'timedOut':False};started=time.monotonic();real_clock=time.monotonic
        clock=lambda:691 if record['stdout'].endswith(b'partial') or real_clock()-started>2 else 0
        with mock.patch.object(routes.time,'monotonic',side_effect=clock),self.assertRaises(TimeoutError):
            routes._transport([sys.executable,'-c','import sys,time;sys.stdin.buffer.read();sys.stdout.buffer.write(b"partial");sys.stdout.flush();time.sleep(10)'],b'inert',record)
        self.assertTrue(record['timedOut']);self.assertEqual(b'partial',record['stdout'])
    def test_same_byte_source_generation_change_after_transport_rejects(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root);changed=[];original=routes.availability._snapshot;helper=Path(routes.getter.__file__).absolute()
            def snapshot(path):
                pin,raw=original(path)
                if Path(path)==helper and changed:pin=(*pin[:4],pin[4]+1,*pin[5:])
                return pin,raw
            def transport(argv,credential,record):record.update(stdout=chunks(value()),returncode=0);changed.append(True)
            _,run=self.mocks(stack,transport);stack.enter_context(mock.patch.object(routes.availability,'_snapshot',side_effect=snapshot));result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);run.assert_called_once()
    def test_symlink_capture_parent_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'foreign').mkdir();(root/'.runtime').symlink_to(root/'foreign',target_is_directory=True)
            with self.assertRaises(ValueError):routes._directory(root,'11111111-1111-4111-8111-111111111111')
            self.assertEqual([],list((root/'foreign').iterdir()))
    def test_actual_frozen_status_factory_no_mutation_dispatch(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        history=install(self,globals(),'routes')
        history.remaining_context(routes.getter)
        admitted=routes.getter.admit(history.root,history.reservation,routes.CORRELATION)
        authority=admitted['remainingBinding']['authority'];owner=routes.getter.OWNER
        expected={'schema':1,'binding':authority,'currentControllerId':owner,'originalOperationOutcome':'unknown','replayAllowed':False}
        raw=(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode()
        record={'value':expected,'generation':[1,2,len(raw),3,4,33152,0,0,1],'sha256':hashlib.sha256(raw).hexdigest()}
        response={'state':'remaining-admitted','correlationId':authority['correlationId'],'closingGuardsVerified':True,'historicalUnknownsPreserved':True,'replayAllowed':False,'originalOperationOutcome':'unknown','currentControllerId':owner,'result':{'record':record}}
        routes.getter.retain_admission(history.root,admitted,json.dumps(response).encode())
        prepared=routes.getter.status(history.root,history.reservation,routes.CORRELATION)
        self.assertEqual('status',prepared['remainingBinding']['action']);self.assertEqual(routes.CORRELATION,prepared['remainingBinding']['authority']['correlationId'])
        self.assertEqual(routes.FROZEN,prepared['remainingBinding']['authority']['sourceSha256'])
        tree=ast.parse(prepared['program']);self.assertEqual('coldboot_dispatch()',ast.unparse(tree.body[-1]))
        binding=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='REMAINING' for t in n.targets))
        self.assertEqual('status',ast.literal_eval(binding.value)['action']);routes.getter.guard_prepared(prepared)
    def test_actual_generated_status_path_real_journal_fds_routine(self):
        from agent_tools.tests.test_android_api35_remaining_proxy_cleanup import RoutineRemainingTests
        temporary,directory,env,effects=RoutineRemainingTests().fixture()
        try:
            admitted=env['observed_getter'](None);record=admitted['result']['record'];env['REMAINING'].update(action='restore',controllerId=admitted['currentControllerId'],admissionPin={k:record[k] for k in ('generation','sha256')})
            restored=env['observed_getter'](None);expected=restored['result']['record'];before={p.name:p.read_bytes() for p in directory.iterdir()}
            env['REMAINING']['action']='status';status=env['observed_getter'](None)
            self.assertEqual('remaining-proxy-restored',status['state']);self.assertTrue(status['closingGuardsVerified']);self.assertEqual(expected,status['result']['record']);self.assertEqual(list(routes.getter.KEYS),effects);self.assertEqual(before,{p.name:p.read_bytes() for p in directory.iterdir()})
            self.assertEqual({'present':False},status['records']['partialJournals'][-1]['terminal.json'])
        finally:temporary.cleanup()
    def test_malformed_raw_saved_before_decode_and_guard_routine(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root);events=[]
            def transport(argv,credential,record):record.update(stdout=b'malformed-private-output',returncode=0)
            self.mocks(stack,transport);write=routes._write_receipt;decode=routes._decode
            def persist(directory,value,**kwargs):
                if kwargs.get('name')!='prepared.json':events.append('capture')
                return write(directory,value,**kwargs)
            def parse(raw):
                self.assertEqual(['capture'],events);self.assertTrue(next((root/'.runtime/parity-evidence/android-api35-remaining-proxy-status-mcp').glob('*/receipt.json')).is_file());events.append('parse');return decode(raw)
            stack.enter_context(mock.patch.object(routes,'_write_receipt',side_effect=persist));stack.enter_context(mock.patch.object(routes,'_decode',side_effect=parse))
            result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);self.assertEqual(['capture','parse'],events)
            receipt=json.loads(next((root/'.runtime/parity-evidence/android-api35-remaining-proxy-status-mcp').glob('*/receipt.json')).read_bytes());self.assertEqual(b'malformed-private-output',base64.b64decode(receipt['transport']['stdoutB64']))
    def test_retained_terminal_difference_never_projects_positive(self):
        item=value();item['result']['record']['generation'][4]+=1
        self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1},value()['result']['record'])['ok'])
        item=value();item['result']['record']['value']['final']['settings']['rows']['global_http_proxy_host']=''
        self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1},item['result']['record'])['ok'])

    def test_actual_remote_wrapper_framing_and_sudo_stdin_are_composed(self):
        import io,sys,subprocess
        emitted=[];calls=[];script='import sys;sys.stdin.buffer.read();sys.stdout.write('+repr(json.dumps(value()))+')'
        def launch(argv,**kwargs):calls.append(argv);return subprocess.Popen([sys.executable,'-c',script],**kwargs)
        scope={'sys':types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(b'INERT_SECRET'))),'subprocess':types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE),'base64':base64,'json':json,'hashlib':hashlib,'os':os,'select':__import__('select'),'time':__import__('time'),'print':lambda line:emitted.append(line)}
        tree=ast.parse(routes._REMOTE.replace('__CARRIER__',repr('fixed-inert-carrier')));tree.body=[node for node in tree.body if not isinstance(node,(ast.Import,ast.ImportFrom))]
        exec(compile(tree,'<actual-remote-readonly-wrapper>','exec'),scope)
        output=('\n'.join(emitted)+'\n').encode();record,result=routes._decode(output)
        self.assertEqual(OWNER,result['currentControllerId']);self.assertFalse(record['timedOut']);self.assertFalse(record['outputLimit']);self.assertTrue(all(len(line)<=2048 for line in emitted[1:]));self.assertEqual('/usr/bin/sudo',calls[0][0]);self.assertNotIn('INERT_SECRET',repr(calls))
