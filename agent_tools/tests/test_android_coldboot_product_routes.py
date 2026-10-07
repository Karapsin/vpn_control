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
from agent_tools import android_coldboot_product_routes as routes

OWNER='401cea62-1852-4642-bd4d-a9d5ed372394'
def value():
    envelope={'ok':True,'code':'OK','final':True,'controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[],'routing':{'private':'PRIVATE_RULE_LITERAL'}}}
    return {'state':'current-product-getters-admitted','productAdmitted':True,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'controllerId':OWNER,'configurationRevision':0,'records':{key:{'returncode':0,'stdout':envelope,'stdoutRaw':'PRIVATE_RAW_LITERAL','stderrRaw':''} for key in ('statusBefore','operations','routing','statusAfter')}}
def chunks(item):
    record={'returncode':0,'stdoutB64':base64.b64encode(json.dumps(item).encode()).decode(),'stderrB64':'','timedOut':False,'outputLimit':False};raw=json.dumps(record).encode()
    return (json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})+'\n').encode()+b''.join(base64.b64encode(raw[n:n+1536])+b'\n' for n in range(0,len(raw),1536))
class RoutesTests(unittest.TestCase):
    def test_actual_success_projection_has_observed_reason(self):
        result=routes._projection(value(),{'sha256':'a'*64,'bytes':233907})
        self.assertTrue(result['ok']);self.assertEqual('observed',result['reason'])
    def test_projection_rejects_noncanonical_owner(self):
        for owner in ('-'*36,'a'*36,'401cea62-1852-4642-bd4d-a9d5ed37239-'):
            item=value();item['controllerId']=owner
            for record in item['records'].values():record['stdout']['controllerId']=owner
            self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1})['ok'])
    def test_projection_rejects_boolean_exit_code(self):
        item=value();item['records']['routing']['returncode']=False
        self.assertFalse(routes._projection(item,{'sha256':'a'*64,'bytes':1})['ok'])
    def fixture(self,root):
        from agent_tools.tests.fixtures import historical_source
        archive=Path(__file__).parent/'fixtures/android_component_legacy/product_observer.source'
        raw=archive.read_bytes();destination=root/'public-historical-getter.py';destination.write_bytes(raw)
        historical=historical_source.load(destination,routes.FROZEN)
        self.current_getter=routes.getter
        patch=mock.patch.object(routes,'getter',historical);patch.start();self.addCleanup(patch.stop)
        p=root/'.rag_index/native-environments';p.mkdir(parents=True);p.chmod(0o700)
        row={'id':routes.RESERVATION,'token':'PRIVATE_RESERVATION_TOKEN','hostAlias':'archlinux','environment':'owned-android-api29-coldboot','operator':'root-android','requestedMemoryBytes':2147483648,'allocationState':'running'}
        (p/'reservations.json').write_text(json.dumps({'reservations':[row]}));(p/'reservations.json').chmod(0o600)
        (root/'.codex').mkdir(mode=0o700);(root/'.codex/arch-sudo.local').write_bytes(b'PRIVATE_SUDO_SECRET');(root/'.codex/arch-sudo.local').chmod(0o600)
        (root/routes.ssh_transport.CONFIG_FILENAME).write_text('{}');(root/routes.ssh_transport.CONFIG_FILENAME).chmod(0o600)
    def mocks(self,stack,transport):
        stack.enter_context(mock.patch.object(routes.getter,'prepare',return_value={'snapshots':{},'claims':{}}));stack.enter_context(mock.patch.object(routes.getter,'guard_prepared'))
        stack.enter_context(mock.patch.object(routes.getter,'ssh_carrier',return_value='fixed-carrier'))
        stack.enter_context(mock.patch.object(routes.ssh_transport,'load_config',return_value=types.SimpleNamespace(hosts={'archlinux':object()})))
        stack.enter_context(mock.patch.object(routes.ssh_transport,'connection_host',return_value=types.SimpleNamespace(password=None)))
        build=stack.enter_context(mock.patch.object(routes.ssh_transport,'build_ssh_argv',return_value=['fixed-ssh']))
        run=stack.enter_context(mock.patch.object(routes,'_transport',side_effect=transport));return build,run
    def test_invalid_input_never_reads_credential_or_prepares_action(self):
        for data in ({'device':'api35'},{'pid':1},{'path':'/tmp'},None,[]):
            with mock.patch.object(routes.getter,'prepare') as prepare,mock.patch.object(routes.private,'Snapshot') as private:
                result=routes.dispatch(Path('/unused'),routes.ACTION,data);self.assertEqual('invalid_inputs',result['reason']);prepare.assert_not_called();private.assert_not_called()
    def test_current_source_incompatibility_refuses_before_transport(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root)
            _,run=self.mocks(stack,lambda *args:self.fail('source mismatch dispatched'))
            stack.enter_context(mock.patch.object(routes,'getter',self.current_getter))
            result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);run.assert_not_called()
            self.assertFalse((root/'.runtime').exists())

    def test_valid_flow_is_private_and_credential_only_transport_stdin(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root);seen=[]
            def transport(argv,credential,record):seen.append((argv,credential));record.update(stdout=chunks(value()),returncode=0)
            build,run=self.mocks(stack,transport);result=routes.dispatch(root,routes.ACTION,{})
            self.assertTrue(result['ok']);self.assertTrue(result['runtimeOff']);self.assertEqual(4,result['recordCount']);public=json.dumps(result)
            for text in ('PRIVATE_RULE_LITERAL','PRIVATE_RAW_LITERAL','PRIVATE_RESERVATION_TOKEN','PRIVATE_SUDO_SECRET',str(root)):self.assertNotIn(text,public)
            self.assertNotIn('PRIVATE_SUDO_SECRET',repr(build.call_args));self.assertEqual(b'PRIVATE_SUDO_SECRET',seen[0][1]);run.assert_called_once()
            capsule=next((root/'.runtime/parity-evidence/android-coldboot-product-mcp').glob('*/receipt.json'));self.assertEqual(0o600,capsule.stat().st_mode&0o777);self.assertEqual(0o700,capsule.parent.stat().st_mode&0o777);self.assertEqual(result['receiptSha256'],hashlib.sha256(capsule.read_bytes()).hexdigest());self.assertIn('PRIVATE_RULE_LITERAL',capsule.read_text())
    def test_timeout_retains_partial_private_receipt_without_resubmission(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();self.fixture(root)
            def transport(argv,credential,record):record.update(stdout=b'partial-private-bytes',timedOut=True);raise TimeoutError('PRIVATE_EXCEPTION')
            _,run=self.mocks(stack,transport);result=routes.dispatch(root,routes.ACTION,{})
            self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);self.assertNotIn('PRIVATE_EXCEPTION',json.dumps(result));run.assert_called_once()
            receipt=json.loads(next((root/'.runtime/parity-evidence/android-coldboot-product-mcp').glob('*/receipt.json')).read_bytes());self.assertEqual(b'partial-private-bytes',base64.b64decode(receipt['transport']['stdoutB64']));self.assertTrue(receipt['transport']['timedOut'])
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
            self.assertFalse(result['ok']);run.assert_not_called();self.assertFalse((root/'.runtime').exists())
    def test_chunk_binding_drift_and_noncanonical_types_reject(self):
        good=chunks(value());self.assertEqual(OWNER,routes._decode(good)[1]['controllerId'])
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
        clock=lambda:181 if record['stdout'].endswith(b'partial') or real_clock()-started>2 else 0
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
    def test_actual_remote_wrapper_framing_and_sudo_stdin_are_composed(self):
        import io,sys,subprocess
        emitted=[];calls=[];script='import sys;sys.stdin.buffer.read();sys.stdout.write('+repr(json.dumps(value()))+')'
        def launch(argv,**kwargs):calls.append(argv);return subprocess.Popen([sys.executable,'-c',script],**kwargs)
        scope={'sys':types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(b'INERT_SECRET'))),'subprocess':types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE),'base64':base64,'json':json,'hashlib':hashlib,'os':os,'select':__import__('select'),'time':__import__('time'),'print':lambda line:emitted.append(line)}
        tree=ast.parse(routes._REMOTE.replace('__CARRIER__',repr('fixed-inert-carrier')));tree.body=[node for node in tree.body if not isinstance(node,(ast.Import,ast.ImportFrom))]
        exec(compile(tree,'<actual-remote-readonly-wrapper>','exec'),scope)
        output=('\n'.join(emitted)+'\n').encode();record,result=routes._decode(output)
        self.assertEqual(OWNER,result['controllerId']);self.assertFalse(record['timedOut']);self.assertFalse(record['outputLimit']);self.assertTrue(all(len(line)<=2048 for line in emitted[1:]));self.assertEqual('/usr/bin/sudo',calls[0][0]);self.assertNotIn('INERT_SECRET',repr(calls))
