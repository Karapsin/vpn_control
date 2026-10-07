import ast,json,os,pathlib,stat,subprocess,tempfile,unittest
from unittest import mock
from agent_tools import android_device_availability as availability
from agent_tools import android_observation

BOOT='25515f23-b966-4c3a-ae63-d38452375578';SERIAL='emulator-5684'
MISSING={'exit':1,'stdout':'','stderr':"error: device 'emulator-5684' not found\n"}
class AvailabilityTests(unittest.TestCase):
    def payload(self,read=MISSING):return {'schema':1,'serial':SERIAL,'bootId':BOOT,'expectedBootId':None,'adbGeneration':[66306,1851411,33261,0,9429624,1786829182000000000,1786829255273910802,1],'observations':[read,dict(read)]}
    def test_actual_null_baseline_old_validator_red_missing_adb_green(self):
        old={'baseline':{'uid':None,'sdk':None,'kernelAvd':None,'bootAvd':None,'proxy':{x:{'state':'unknown'} for x in android_observation._PROXY_FIELDS}},'admitted':False}
        self.assertEqual('malformed_observation',android_observation._result(0,json.dumps(old).encode())['reason'])
        result=availability.classify(0,json.dumps(self.payload()).encode(),SERIAL);self.assertEqual('configured_device_not_found',result['reason']);self.assertEqual('unavailable',result['outcome']);self.assertFalse(result['productAdmitted'])
    def test_generic_adb_failure_never_becomes_absence(self):
        result=availability.classify(0,json.dumps(self.payload({'exit':1,'stdout':'','stderr':'permission denied'})),SERIAL);self.assertEqual('unknown',result['outcome'])
    def test_two_read_drift_rejects(self):
        value=self.payload();value['observations'][1]={'exit':0,'stdout':'device\n','stderr':''};self.assertEqual('availability_changed',availability.classify(0,json.dumps(value),SERIAL)['reason'])
    def test_visible_transport_never_admits_product_or_launch(self):
        result=availability.classify(0,json.dumps(self.payload({'exit':0,'stdout':'device\n','stderr':''})),SERIAL);self.assertTrue(result['available']);self.assertFalse(result['productAdmitted']);self.assertFalse(result['lifecycleActionAllowed'])
    def test_changed_boot_does_not_reuse_continuity(self):
        value=self.payload();previous='11111111-1111-1111-1111-111111111111';value['expectedBootId']=previous
        self.assertEqual('changed',availability.classify(0,json.dumps(value),SERIAL,previous)['bootContinuity'])
    def test_actual_remote_fixed_adb_read_and_generation_guard(self):
        nodes=[n for n in ast.parse(availability._REMOTE).body if not isinstance(n,ast.If)];scope={'__name__':'fixture'};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-availability>','exec'),scope);scope['boot']=lambda:BOOT
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'adb';path.write_text('#!/bin/sh\nprintf "error: device \'%s\' not found\\n" "$2" >&2\nexit 1\n');path.chmod(0o700)
            original=subprocess.Popen
            def portable_fixture(argv,**kwargs):
                self.assertEqual(['-s',SERIAL,'get-state'],argv[1:]);self.assertTrue(argv[0].startswith('/proc/self/fd/'))
                if not pathlib.Path('/proc/self/fd').exists():argv=[str(path),*argv[1:]]  # macOS lacks Linux descriptor execution; native Linux remains required.
                kwargs['env']={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
                return original(argv,**kwargs)
            with mock.patch.object(scope['subprocess'],'Popen',side_effect=portable_fixture):value=scope['probe'](str(path),SERIAL,2,None)
            self.assertEqual([MISSING,MISSING],value['observations'])
            self.assertEqual('configured_device_not_found',availability.classify(0,json.dumps(value),SERIAL)['reason'])
    def test_actual_remote_host_boot_drift_rejects(self):
        nodes=[n for n in ast.parse(availability._REMOTE).body if not isinstance(n,ast.If)];scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-availability>','exec'),scope)
        scope['boot']=mock.Mock(side_effect=[BOOT,'11111111-1111-1111-1111-111111111111']);scope['adb_read']=lambda *_:MISSING
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'adb';path.write_text('fixture');path.chmod(0o700)
            with self.assertRaisesRegex(ValueError,'host_or_adb_generation_changed'):scope['probe'](str(path),SERIAL,2,None)
    def test_actual_remote_same_bytes_adb_exchange_rejects(self):
        nodes=[n for n in ast.parse(availability._REMOTE).body if not isinstance(n,ast.If)];scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-availability>','exec'),scope);scope['boot']=lambda:BOOT
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'adb';path.write_text('fixture');path.chmod(0o700);calls=[]
            def read(*_):
                calls.append(None)
                if len(calls)==1:
                    raw=path.read_bytes();path.rename(path.with_name('old-adb'));path.write_bytes(raw);path.chmod(0o700)
                return MISSING
            scope['adb_read']=read
            with self.assertRaisesRegex(ValueError,'host_or_adb_generation_changed'):scope['probe'](str(path),SERIAL,2,None)
    def test_actual_shared_ssh_builder_accepts_exact_probe_carrier(self):
        host=availability.ssh_transport.SshHost(alias='arch',host='127.0.0.1',port=22,user='fixture',identity_file=pathlib.Path('/tmp/key'),known_hosts_file=pathlib.Path('/tmp/known'))
        config=availability.ssh_transport.SshConfig(root=pathlib.Path('.').absolute(),hosts={'arch':host})
        profile={'adb':'/remote/tools/adb','cli':'/remote/tools/vpn-control','serial':SERIAL,'expectedAvd':'api29','api':29}
        builder=availability.ssh_transport.build_ssh_argv
        with mock.patch.object(availability.ssh_transport,'load_config',return_value=config),mock.patch.object(availability.ssh_transport,'build_ssh_argv',wraps=builder) as actual,mock.patch.object(availability.android_observation,'_run_probe',return_value=(0,json.dumps(self.payload()).encode())) as probe:
            result=availability.observe(pathlib.Path('.'),'arch',profile)
        self.assertEqual('configured_device_not_found',result['reason']);probe.assert_called_once()
        command=actual.call_args.kwargs['command'];self.assertFalse(any('\n' in arg for arg in command))
        expression=ast.parse(command[2]).body[0].value;self.assertEqual('exec',expression.func.id);self.assertEqual(availability._REMOTE,ast.literal_eval(expression.args[0]))
    def test_source_symlink_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'source';path.symlink_to('/dev/null')
            with self.assertRaises(OSError):availability._snapshot(path)
