"""Bounded pipe, strict private projection and immutable source guard checks."""
import ast
import base64
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_api35_large_routing_routes as route

try:
    import resource as _resource
except ImportError:
    _resource=None


def _posix_capable(platform_name=None):
    return (os.name if platform_name is None else platform_name)=='posix' and all(hasattr(os,name)for name in ('O_DIRECTORY','O_NOFOLLOW','pread'))


POSIX_CAPABLE=_posix_capable()
RESOURCE_CAPABLE=_resource is not None and hasattr(_resource,'RLIMIT_FSIZE') and hasattr(_resource,'setrlimit')


def chunks(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'encoding':'base64','chunkBytes':65536,'chunks':[base64.b64encode(raw[i:i+65536]).decode()for i in range(0,len(raw),65536)]}
def envelope(data):return {'schemaVersion':1,'ok':True,'final':True,'code':'OK','controllerId':route.getter.OWNER,'configurationRevision':0,'requestId':'a1e9d7b1-5d43-4a56-a96d-c43f454aaeb3','data':data}
def value():
    records={'observedPackageBefore':route.getter.original.APK,'observedPackageAfter':route.getter.original.APK}
    for key in ('statusBefore','statusAfter','operationsBefore','operationsAfter'):
        data={'runtimeRunning':False,'runtimeObservation':'stopped'}if key.startswith('status')else {'operations':[]}
        records[key]={'returncode':0,'stdout':chunks(json.dumps(envelope(data)).encode()),'stderr':chunks(b'')}
    for index,key in enumerate(('routingBefore','routingAfter')):
        routing={'type':'vpn_control_routing_rules','version':7,'exported_at':str(index),'rules':{'ignore_rules':False,'block_quic_udp_443':False,'direct_domain_suffixes':['PRIVATE_RULE_LITERAL'],'proxy_packages':[]}}
        e=envelope({'routing':routing});raw=json.dumps({k:routing[k]for k in ('type','version','rules')},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        records[key]={'returncode':0,'stdout':chunks(json.dumps(e).encode()),'stderr':chunks(b''),'semanticSha256':hashlib.sha256(raw).hexdigest(),'semanticBytes':len(raw),'envelope':{k:e.get(k)for k in ('schemaVersion','controllerId','requestId','ok','code','final','configurationRevision','operationId','restartRequired','warnings')}}
    pin={'generation':[1,2,3,4,5,0o100600,1000,1000,1],'bytesRead':3,'sha256':'a'*64,'hashScope':'full'}
    stage={'intent.json':pin,'receipt.json':copy.deepcopy(pin)}
    return {'state':'current-large-routing-observed','reason':None,'currentRoutingVerified':True,'productAdmitted':False,'acceptanceComplete':False,'historicalUnknownsPreserved':True,'semanticComparison':'full-type-version-rules-excluding-generated-exported_at-only','cliStagePins':[stage,copy.deepcopy(stage)],'records':records}
def wire(raw,**override):
    header={'returncode':0,'timedOut':False,'outputLimit':False,'reaped':True,'stdoutBytes':len(raw),'stdoutSha256':hashlib.sha256(raw).hexdigest(),'stderrBytes':0,'stderrSha256':hashlib.sha256(b'').hexdigest()};header.update(override)
    return (json.dumps(header)+'\n').encode()+b''.join(b'out:'+base64.b64encode(raw[i:i+1536])+b'\n'for i in range(0,len(raw),1536))


class RouteTests(unittest.TestCase):
    def fixture(self,root):
        directory=root/'.rag_index/native-environments';directory.mkdir(parents=True);directory.chmod(0o700)
        row={'id':route.RESERVATION,'token':'PRIVATE_TOKEN','hostAlias':'archlinux','environment':'owned-android-api35-coldboot','operator':'root-android','requestedMemoryBytes':2147483648,'allocationState':'pending'}
        p=directory/'reservations.json';p.write_text(json.dumps({'reservations':[row]}));p.chmod(0o600)
        (root/'.codex').mkdir(mode=0o700);p=root/'.codex/arch-sudo.local';p.write_bytes(b'PRIVATE_PASSWORD');p.chmod(0o600)
        p=root/route.ssh_transport.CONFIG_FILENAME;p.write_text('{}');p.chmod(0o600)
    def mocks(self,stack,transport):
        stack.enter_context(mock.patch.object(route.getter,'prepare',return_value={'program':'fixed','snapshots':{}}));stack.enter_context(mock.patch.object(route.getter,'guard_prepared'));stack.enter_context(mock.patch.object(route.getter,'ssh_carrier',return_value='fixed-carrier'))
        stack.enter_context(mock.patch.object(route.ssh_transport,'load_config',return_value=types.SimpleNamespace(hosts={'archlinux':object()})));stack.enter_context(mock.patch.object(route.ssh_transport,'connection_host',return_value=types.SimpleNamespace(password=None)))
        build=stack.enter_context(mock.patch.object(route.ssh_transport,'build_ssh_argv',return_value=['fixed-ssh']));run=stack.enter_context(mock.patch.object(route,'_transport',side_effect=transport));return build,run
    def capture(self,root):return route._capture(root,'a1e9d7b1-5d43-4a56-a96d-c43f454aaeb3')

    def test_projection_valid_privacy_and_strict_false_flags(self):
        result=route._projection(value());self.assertTrue(result['ok']);self.assertTrue(result['currentRoutingVerified']);self.assertIs(result['productAdmitted'],False);self.assertIs(result['acceptanceComplete'],False);self.assertNotIn('PRIVATE_RULE_LITERAL',json.dumps(result))
        for key in ('currentRoutingVerified','productAdmitted','acceptanceComplete','historicalUnknownsPreserved'):
            v=value();v[key]=int(v[key]);self.assertFalse(route._projection(v)['ok'])
    def test_projection_boolean_exit_revision_or_chunk_count_rejects(self):
        for kind in ('exit','revision','bytes','hash','semantic','stage','owner','rules'):
            v=value();item=v['records']['routingAfter']
            if kind=='exit':item['returncode']=False
            elif kind=='bytes':item['stdout']['bytes']=True
            elif kind=='hash':item['stdout']['sha256']='0'*64
            elif kind=='semantic':item['semanticBytes']=True
            elif kind=='stage':v['cliStagePins'][1]['intent.json']['generation'][4]=True
            else:
                e=json.loads(b''.join(base64.b64decode(x)for x in item['stdout']['chunks']))
                if kind=='revision':e['configurationRevision']=False
                elif kind=='owner':e['controllerId']='foreign'
                else:e['data']['routing']['rules']['direct_domain_suffixes'].append('CHANGED')
                item['stdout']=chunks(json.dumps(e).encode())
            self.assertFalse(route._projection(v)['ok'],kind)
    def test_simulated_nt_gates_skip_only_posix_fixtures(self):
        self.assertFalse(_posix_capable('nt'))
        tree=ast.parse(Path(__file__).read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='RouteTests')
        # Reapply the actual decorators with capability flags disabled, without
        # changing os.name globally or pretending Windows has POSIX descriptors.
        env={'unittest':unittest,'POSIX_CAPABLE':False,'RESOURCE_CAPABLE':False}
        exec(compile(ast.Module(body=[cls],type_ignores=[]),'<simulated-nt-test-gates>','exec'),env)
        generated=env['RouteTests']
        for name in ('test_registered_action_fixed_native_flow_once_private_receipt','test_actual_pipe_bypasses_RLIMIT_file4096_and_full_frames_collect','test_actual_remote_generator_has_stdin_secret_and1536_frames','test_actual_pipe_timeout_retains_decoded_partial_before_reap'):
            self.assertTrue(getattr(getattr(generated,name),'__unittest_skip__',False))
        for name in ('test_projection_valid_privacy_and_strict_false_flags','test_projection_boolean_exit_revision_or_chunk_count_rejects','test_invalid_inputs_before_private_effects','test_collector_malformed_bool_hash_duplicate_and_caps_reject'):
            self.assertFalse(getattr(getattr(generated,name),'__unittest_skip__',False))
        # A POSIX host lacking resource keeps descriptor tests, but skips RLIMIT.
        env.update(POSIX_CAPABLE=True,RESOURCE_CAPABLE=False)
        exec(compile(ast.Module(body=[cls],type_ignores=[]),'<missing-resource-test-gates>','exec'),env)
        self.assertTrue(env['RouteTests'].test_actual_pipe_bypasses_RLIMIT_file4096_and_full_frames_collect.__unittest_skip__)
        self.assertFalse(getattr(env['RouteTests'].test_registered_action_fixed_native_flow_once_private_receipt,'__unittest_skip__',False))

    def test_invalid_inputs_before_private_effects(self):
        for inputs in (None,[],{'device':'api35'},{'command':'routing show'},{'timeout':300}):
            with mock.patch.object(route.getter,'prepare')as prepare,mock.patch.object(route.private,'Snapshot')as snapshot:
                self.assertEqual('invalid_inputs',route.dispatch('/unused',route.ACTION,inputs)['reason']);prepare.assert_not_called();snapshot.assert_not_called()
    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_registered_action_fixed_native_flow_once_private_receipt(self):
        with tempfile.TemporaryDirectory()as tmp,ExitStack()as stack:
            root=Path(tmp).resolve();self.fixture(root);seen=[]
            def transport(argv,secret,collector,record):seen.append(secret);collector.feed(wire(json.dumps(value()).encode()));record['returncode']=0
            build,run=self.mocks(stack,transport);result=route.dispatch(root,route.ACTION,{})
            self.assertTrue(result['ok']);run.assert_called_once();self.assertEqual([b'PRIVATE_PASSWORD'],seen);self.assertNotIn('PRIVATE_PASSWORD',repr(build.call_args))
            public=json.dumps(result)
            for literal in ('PRIVATE_PASSWORD','PRIVATE_TOKEN','PRIVATE_RULE_LITERAL',str(root)):self.assertNotIn(literal,public)
            receipt=next((root/'.runtime/parity-evidence').glob('*/receipt.json'));self.assertEqual(0o600,receipt.stat().st_mode&0o777);self.assertEqual(0o700,receipt.parent.stat().st_mode&0o777);self.assertEqual(result['receiptSha256'],hashlib.sha256(receipt.read_bytes()).hexdigest())
            self.assertNotIn('PRIVATE_RULE_LITERAL',receipt.read_text());self.assertTrue(list(receipt.parent.glob('out-*.private')))
    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_disconnect_retains_partial_private_chunks_no_resubmit(self):
        with tempfile.TemporaryDirectory()as tmp,ExitStack()as stack:
            root=Path(tmp).resolve();self.fixture(root)
            def transport(argv,secret,collector,record):collector.feed(wire(b'private-result')[:-8]);record['timedOut']=True;raise TimeoutError('PRIVATE_ERROR')
            _,run=self.mocks(stack,transport);result=route.dispatch(root,route.ACTION,{})
            self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);run.assert_called_once();self.assertNotIn('PRIVATE_ERROR',json.dumps(result));self.assertTrue(list((root/'.runtime/parity-evidence').glob('*/incomplete-frame.private')))
    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_source_registry_config_credential_drift_retains_unknown(self):
        for kind in ('source','registry','config','credential'):
            with tempfile.TemporaryDirectory()as tmp,ExitStack()as stack:
                root=Path(tmp).resolve();self.fixture(root);changed=[];original=route.availability._snapshot
                def snapshot(path):
                    pin,raw=original(path)
                    if kind=='source'and changed and Path(path)==Path(route.getter.__file__).absolute():pin=(*pin[:4],pin[4]+1,*pin[5:])
                    return pin,raw
                def transport(argv,secret,collector,record):
                    collector.feed(wire(json.dumps(value()).encode()));record['returncode']=0;changed.append(True)
                    paths={'registry':root/'.rag_index/native-environments/reservations.json','config':root/route.ssh_transport.CONFIG_FILENAME,'credential':root/'.codex/arch-sudo.local'}
                    if kind in paths:p=paths[kind];p.write_bytes(p.read_bytes()+b' ')
                _,run=self.mocks(stack,transport);stack.enter_context(mock.patch.object(route.availability,'_snapshot',side_effect=snapshot));result=route.dispatch(root,route.ACTION,{})
                self.assertFalse(result['ok']);self.assertIn('receiptSha256',result);run.assert_called_once()
    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_frozen_source_wrong_before_transport(self):
        with tempfile.TemporaryDirectory()as tmp,ExitStack()as stack:
            root=Path(tmp).resolve();self.fixture(root);_,run=self.mocks(stack,lambda *a:None);stack.enter_context(mock.patch.object(route,'FROZEN','0'*64));result=route.dispatch(root,route.ACTION,{})
            self.assertFalse(result['ok']);run.assert_not_called();self.assertFalse((root/'.runtime').exists())
    @unittest.skipUnless(POSIX_CAPABLE and RESOURCE_CAPABLE,'POSIX descriptors, pipe selection and RLIMIT_FSIZE required')
    def test_actual_pipe_bypasses_RLIMIT_file4096_and_full_frames_collect(self):
        # Causal old regular-file RLIMIT fails/truncates8192; PIPE survives.
        import resource
        code='import resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096));sys.stdout.buffer.write(b"x"*8192);sys.stdout.flush()'
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();p=root/'old';fd=p.open('wb');old=subprocess.run([sys.executable,'-I','-c',code],stdout=fd,stderr=subprocess.DEVNULL);fd.close();self.assertNotEqual(0,old.returncode);self.assertEqual(4096,p.stat().st_size)
            capture=self.capture(root)
            try:
                collector=route.Collector(capture);record={'timedOut':False,'reaped':True,'returncode':None}
                protocol=wire(b'x'*8192);script='import resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096));sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(protocol)+');sys.stdout.flush()'
                route._transport([sys.executable,'-I','-c',script],b'inert',collector,record)
                self.assertEqual(0,record['returncode']);self.assertTrue(collector.finish()['framesVerified']);self.assertEqual(b'x'*8192,collector.read_output())
            finally:capture.close()
    def test_collector_malformed_bool_hash_duplicate_and_caps_reject(self):
        # Pure framing uses a portable file FD for fsync and an inert capture;
        # no no-follow ancestry, POSIX pipe select or native transport required.
        with tempfile.TemporaryFile()as file:
            capture=types.SimpleNamespace(fd=file.fileno(),create=lambda name,raw:{'sha256':hashlib.sha256(raw).hexdigest(),'generation':[]})
            for payload in (wire(b'x',stdoutBytes=True),wire(b'x',returncode=False),b'{}\n',b'{"returncode":0,"returncode":1}\n',b'x'*2053):
                with self.assertRaises(Exception):route.Collector(capture).feed(payload)
            collector=route.Collector(capture);collector.feed(wire(b'x',stdoutSha256='0'*64));self.assertFalse(collector.finish()['framesVerified'])

    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_actual_remote_generator_has_stdin_secret_and1536_frames(self):
        emitted=[];calls=[];raw=b'x'*8192;real=subprocess.Popen
        def launch(argv,**kwargs):calls.append(argv);return real([sys.executable,'-I','-c','import sys;sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(raw)+')'],**kwargs)
        env={'sys':types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(b'PRIVATE_SECRET'))),'subprocess':types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired),'os':os,'time':__import__('time'),'select':__import__('select'),'hashlib':hashlib,'base64':base64,'json':json,'print':lambda line,**kw:emitted.append(line)}
        tree=ast.parse(route._REMOTE.replace('__CARRIER__',repr('fixed-carrier')));tree.body=[n for n in tree.body if not isinstance(n,(ast.Import,ast.ImportFrom))];exec(compile(tree,'<actual-remote>','exec'),env)
        self.assertNotIn('PRIVATE_SECRET',repr(calls));self.assertEqual('/usr/bin/sudo',calls[0][0]);self.assertTrue(all(len(line)<=2052 for line in emitted[1:]));h=json.loads(emitted[0]);self.assertEqual(8192,h['stdoutBytes']);self.assertEqual(hashlib.sha256(raw).hexdigest(),h['stdoutSha256'])
    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_actual_pipe_timeout_retains_decoded_partial_before_reap(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();capture=self.capture(root)
            try:
                collector=route.Collector(capture);record={'timedOut':False,'reaped':True,'returncode':None}
                script='import sys,time;sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(wire(b'partial'))+');sys.stdout.flush();time.sleep(10)'
                clock=lambda:1251 if collector.counts['out'] else 0
                with mock.patch.object(route.time,'monotonic',side_effect=clock),self.assertRaises(TimeoutError):route._transport([sys.executable,'-I','-c',script],b'inert',collector,record)
                self.assertTrue(record['timedOut']);self.assertTrue(collector.finish()['framesVerified']);self.assertEqual(b'partial',collector.read_output())
            finally:capture.close()

    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_actual_local_wire_and_remote_decoded_caps_keep_partial(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();capture=self.capture(root)
            try:
                collector=route.Collector(capture);record={'timedOut':False,'reaped':True,'returncode':None};protocol=wire(b'x'*2048)
                with mock.patch.object(route,'WIRE_LIMIT',400),self.assertRaises(ValueError):route._transport([sys.executable,'-I','-c','import sys;sys.stdin.buffer.read();sys.stdout.buffer.write('+repr(protocol)+');sys.stdout.flush()'],b'inert',collector,record)
                self.assertGreater(record['wireBytes'],400);collector.finish();self.assertTrue((capture.path/'incomplete-frame.private').exists())
            finally:capture.close()
        emitted=[];real=subprocess.Popen
        def launch(argv,**kwargs):return real([sys.executable,'-I','-c','import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b"x"*2048)'],**kwargs)
        env={'sys':types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(b'inert'))),'subprocess':types.SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired),'os':os,'time':__import__('time'),'select':__import__('select'),'hashlib':hashlib,'base64':base64,'json':json,'print':lambda line,**kw:emitted.append(line)}
        source=route._REMOTE.replace('__CARRIER__',repr('fixed-carrier')).replace('104857601','1025').replace('104857600','1024')
        tree=ast.parse(source);tree.body=[n for n in tree.body if not isinstance(n,(ast.Import,ast.ImportFrom))];exec(compile(tree,'<scaled-actual-output-cap>','exec'),env)
        header=json.loads(emitted[0]);self.assertTrue(header['outputLimit']);self.assertEqual(1025,header['stdoutBytes']);self.assertIsNone(header['returncode'])

    @unittest.skipUnless(POSIX_CAPABLE,'POSIX descriptors and pipe selection required')
    def test_symlink_private_capture_parent_refuses(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();foreign=root/'foreign';foreign.mkdir();(root/'.runtime').symlink_to(foreign,target_is_directory=True)
            with self.assertRaises(Exception):self.capture(root)
            self.assertEqual([],list(foreign.iterdir()))


if __name__=='__main__':unittest.main()
