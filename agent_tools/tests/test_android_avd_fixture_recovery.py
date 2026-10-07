import ast,json,os,pathlib,tempfile,types,unittest
from unittest import mock
from agent_tools import android_avd_fixture_recovery as recovery

class AvdPreflightTests(unittest.TestCase):
    def scope(self,names):
        nodes=[n for n in ast.parse(recovery._REMOTE).body if isinstance(n,(ast.Import,ast.ImportFrom)) or isinstance(n,ast.FunctionDef) and n.name in names]
        scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-avd-preflight>','exec'),scope);return scope
    def test_only_historically_owned_names_are_selected(self):
        self.assertEqual({'api29','api35'},set(recovery.OWNED));self.assertEqual({5682,5684},{x['port'] for x in recovery.OWNED.values()});self.assertFalse(hasattr(recovery,'launch'))
    def test_actual_bounded_disk_hash_is_explicit_prefix(self):
        scope=self.scope({'fp','fixed_read','facts'})
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'userdata-qemu.img';path.write_bytes(b'disk'*100)
            result=scope['facts'](path,16);self.assertEqual('prefix',result['hashScope']);self.assertEqual(16,result['bytesRead']);self.assertEqual(400,result['generation'][2])
    def test_actual_disk_named_generation_exchange_rejects(self):
        scope=self.scope({'fp','fixed_read'});normal=os.read
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'disk';path.write_bytes(b'disk');changed=[]
            def swap(fd,size):
                raw=normal(fd,size)
                if not changed:
                    path.rename(path.with_name('old'));path.write_bytes(b'disk');changed.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=swap),self.assertRaisesRegex(ValueError,'preflight_file_changed'):scope['fixed_read'](path)
    def test_actual_ini_duplicate_and_identity_data_parser(self):
        scope=self.scope({'parse_ini'});self.assertEqual({'path':'/owned.avd'},scope['parse_ini']('path=/owned.avd\n'))
        with self.assertRaisesRegex(ValueError,'preflight_ini_invalid'):scope['parse_ini']('path=/owned.avd\npath=/foreign.avd\n')
    def test_actual_pid_reuse_during_holder_census_rejects(self):
        scope=self.scope({'holders'})
        with tempfile.TemporaryDirectory() as tmp:
            proc=pathlib.Path(tmp)/'proc';proc.mkdir();pid=proc/'17';pid.mkdir();(pid/'fd').mkdir();(pid/'cmdline').write_bytes(b'qemu-system-x86_64\0-avd\0fixture\0')
            scope['pathlib']=types.SimpleNamespace(Path=lambda value:proc if value=='/proc' else pathlib.Path(value));scope['start_ticks']=mock.Mock(side_effect=[10,20])
            with self.assertRaisesRegex(ValueError,'preflight_pid_reused'):scope['holders']({'api29':{'inventory':{}}})
    def test_actual_foreign_port_remains_blocking_fact(self):
        scope=self.scope({'sockets'})
        with tempfile.TemporaryDirectory() as tmp:
            proc=pathlib.Path(tmp);(proc/'tcp').write_text('header\n0: 0100007F:1634 00000000:0000 0A 0:0 0:0 0 1000 0 999\n');(proc/'tcp6').write_text('header\n')
            scope['pathlib']=types.SimpleNamespace(Path=lambda value:proc/pathlib.Path(value).name)
            self.assertEqual(5684,scope['sockets']()[0]['port'])
    def test_snapshot_preserves_current_lease_and_partial_layout(self):
        scope=self.scope({'snapshot'});scope['OWNED']=recovery.OWNED
        scope.update({'avd_facts':lambda alias:(_ for _ in ()).throw(ValueError('preflight_layout_unadmitted')),'facts':lambda path,*_: {'present':True,'generation':[1],'text':'original claim'},'root':pathlib.Path('/fixed/root'),'boot':lambda:'current-boot','sockets':lambda:[],'holders':lambda _: {'complete':False,'holders':[],'emulators':[]},'resources':lambda:{'budgetSatisfied':True}})
        value=scope['snapshot']();self.assertEqual('original claim',value['claims']['api29']['text']);self.assertEqual('preflight_layout_unadmitted',value['avds']['api29']['error'])
    def test_capture_keeps_drift_evidence_without_lifecycle_authority(self):
        scope=self.scope({'fp','fixed_read','capture'})
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);root.chmod(0o700);scope['root']=root;scope['capsule']=root/'capture.json';scope['CFG']={'correlationId':'new','source':{},'history':{},'localClaims':{}}
            first={'bootId':'one','avds':{},'claims':{'api29':'old'},'ports':[],'holderCensus':{'complete':False,'emulators':[],'holders':[]},'resources':{'budgetSatisfied':True}};second={**first,'claims':{'api29':'changed'}};scope['snapshot']=mock.Mock(side_effect=[first,second])
            with mock.patch('builtins.print'):scope['capture']()
            result=json.loads(scope['capsule'].read_bytes());self.assertFalse(result['stable']);self.assertFalse(result['lifecycleAllowed']);self.assertFalse(result['productAdmitted']);self.assertEqual([first,second],result['observations'])
    def test_fetch_replacement_rejects_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'android-avd-preflight-11111111-1111-4111-8111-111111111111.json';path.write_text('{}');path.chmod(0o600)
            scope=self.scope({'fp','fixed_read'});pin=scope['fixed_read'](path);pin.pop('raw');path.rename(path.with_name('old'));path.write_text('{}');path.chmod(0o600)
            with mock.patch('sys.argv',['fetch',tmp,path.name,json.dumps(pin),'0']),self.assertRaisesRegex(ValueError,'fetch_generation'):exec(recovery._FETCH,{})
    def test_collection_transport_failure_reuses_same_capsule_without_capture(self):
        from agent_tools import android_device_availability as availability
        import base64,hashlib
        correlation='7bd3c75c-83d1-438b-8129-70dc6a0f1c11'
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp).resolve();(root/'.runtime/parity-evidence/android-current').mkdir(parents=True);sdk=root/'scripts/android_avd_sdk_preflight.py';sdk.parent.mkdir();sdk.write_text('fixture-sdk')
            own=pathlib.Path(recovery.__file__).absolute();snapshots={p:availability._snapshot(p) for p in (own,sdk)};cfg={'correlationId':correlation,'remoteRoot':'/fixed/root','source':{},'localClaims':{},'history':{}}
            host=recovery.endpoint.ssh_transport.SshHost(alias='archlinux',host='127.0.0.1',port=22,user='fixture',identity_file=pathlib.Path('/tmp/key'),known_hosts_file=pathlib.Path('/tmp/known'));config=recovery.endpoint.ssh_transport.SshConfig(root=root,hosts={'archlinux':host})
            raw=json.dumps({'correlationId':correlation,'source':{},'localClaims':{},'lifecycleAllowed':False}).encode();pin={'generation':[1,2,len(raw),4,5,0o100600,1000,1000,1],'sha256':hashlib.sha256(raw).hexdigest()};result={'state':'captured','correlationId':correlation,'pin':pin,'summary':{'lifecycleAllowed':False}}
            with mock.patch.object(recovery,'_prepare',return_value=(cfg,snapshots,{},config)),mock.patch.object(recovery.endpoint.android_observation,'_run_probe',side_effect=[(0,json.dumps(result).encode()),TimeoutError('lost chunk')]):
                with self.assertRaises(TimeoutError):recovery.preflight(root,correlation)
            with mock.patch.object(recovery,'_prepare',return_value=(cfg,snapshots,{},config)),mock.patch.object(recovery.endpoint.android_observation,'_run_probe',return_value=(0,json.dumps({'offset':0,'data':base64.b64encode(raw).decode()}).encode())) as transport:
                completed=recovery.collect(root,correlation)
            self.assertEqual('captured',completed['state']);transport.assert_called_once();self.assertFalse(completed['lifecycleAllowed'])
            command=transport.call_args.args[0][-1];self.assertNotIn('capture()',command)
