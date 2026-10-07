"""Fast causal tests for the actual fixed cold-boot program; no native launch."""
import ast
import hashlib
import json
import os
import select
import fcntl
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_avd_coldboot as coldboot
from agent_tools import android_avd_launch_recovery as census

class ColdbootTests(unittest.TestCase):
    def scope(self):
        nodes=[n for source in (census._CENSUS,coldboot._BOOT) for n in ast.parse(source).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        scope={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-coldboot-program>','exec'),scope);return scope
    def launch_scope(self,directory,fail=None):
        scope=self.scope();events=[];scope['CFG']={'source':{'helper':'exact'}};scope['LAUNCH']={'correlationId':'new','intentSha256':'intent','emulatorGeneration':[1],'argv':['fixed']};scope['selected_preflight']=lambda:{'budget':True};scope['qemu_fact']=lambda:{'full':'hash'};scope['journal_read']=lambda *args:{'source':scope['CFG']['source'],'intentSha256':'intent','qemuFact':{'full':'hash'}}
        def journal(path,name,value):
            events.append(name)
            if name==fail:raise OSError('lost metadata response')
            (path/name).write_text(json.dumps(value))
        scope['journal_write']=journal;scope['child_identity']=lambda pid:{'pid':pid,'startTicks':10,'bootId':'boot'};scope['guard_parents']=lambda _:None;scope['close_parents']=lambda chain:[os.close(item['fd']) for item in chain]
        scope['parent_fds']=lambda path:([{'fd':os.open(directory,os.O_RDONLY),'pin':[]}],path.name)
        # Real scratch descriptors, simulated fork only: no child is launched.
        scope['open_emulator']=lambda:(os.open('/dev/null',os.O_RDONLY),[])
        proxy=types.SimpleNamespace(**vars(os));proxy.fork=lambda:123;real_write=os.write
        def release(fd,data):events.append('GO');return len(data)
        proxy.write=release;scope['os']=proxy
        return scope,events
    def test_actual_launch_fence_and_child_record_precede_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();scope,events=self.launch_scope(root);result=scope['launch_once'](root)
            self.assertEqual('submitted',result['state']);self.assertLess(events.index('attempt.json'),events.index('child.json'));self.assertLess(events.index('child.json'),events.index('GO'));self.assertLess(events.index('GO'),events.index('exec-released.json'))
    def test_lost_child_record_never_releases_exec_and_never_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();scope,events=self.launch_scope(root,'child.json')
            with self.assertRaises(OSError):scope['launch_once'](root)
            self.assertNotIn('GO',events);before=list(events);result=scope['launch_once'](root);self.assertEqual('unknown',result['state']);self.assertEqual(before,events)
    def test_lost_release_receipt_retains_child_authority_and_no_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();scope,events=self.launch_scope(root,'exec-released.json')
            with self.assertRaises(OSError):scope['launch_once'](root)
            self.assertIn('GO',events);self.assertTrue((root/'child.json').exists());before=list(events);self.assertEqual('unknown',scope['launch_once'](root)['state']);self.assertEqual(before,events)
    def test_actual_status_pid_reuse_rejects_without_guest_probe(self):
        scope=self.scope();scope['LAUNCH']={'intentSha256':'intent','argv':['fixed'],'emulatorGeneration':[1]};scope['CFG']={'source':{'helper':'exact'}};saved={'pid':123,'startTicks':10,'bootId':'boot'}
        def read(directory,name):
            if name=='attempt.json':return {'intentSha256':'intent'}
            return {'source':scope['CFG']['source'],'argv':['fixed'],'emulatorGeneration':[1],'intentSha256':'intent','identity':saved}
        scope['journal_read']=read;scope['boot']=lambda:'boot';scope['child_identity']=lambda _: {**saved,'startTicks':11};scope['guest_probe']=lambda _:(_ for _ in ()).throw(AssertionError('unowned guest probe'))
        self.assertEqual('coldboot_original_pid_reused',scope['original_status'](Path('/fixed'))['reason'])
    def test_submitted_child_record_loss_is_unknown_and_no_adoption(self):
        scope=self.scope();scope['LAUNCH']={'intentSha256':'intent'}
        def read(directory,name):
            if name=='attempt.json':return {'intentSha256':'intent'}
            raise FileNotFoundError('no retained child')
        scope['journal_read']=read;scope['child_identity']=lambda _:(_ for _ in ()).throw(AssertionError('unowned PID adoption'))
        self.assertEqual('coldboot_child_unrecorded_no_replay',scope['original_status'](Path('/fixed'))['reason'])
    def test_actual_qemu_full_hash_and_generation_exchange_rejects(self):
        scope=self.scope();real_read=os.read
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();binary=root/'qemu';binary.write_bytes(b'qemu'*100);binary.chmod(0o755);scope['LAUNCH']={'qemuPath':str(binary)};wanted=binary.stat().st_ino;proxy=types.SimpleNamespace(**vars(os))
            def owner(info):
                if info.st_ino!=wanted:return info
                keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink');value=types.SimpleNamespace(**{key:getattr(info,key) for key in keys});value.st_uid=value.st_gid=1000;return value
            proxy.fstat=lambda fd:owner(os.fstat(fd));proxy.stat=lambda *args,**kwargs:owner(os.stat(*args,**kwargs));scope['os']=proxy
            positive=scope['qemu_fact']();self.assertEqual('full',positive['hashScope']);self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(),positive['sha256'])
            changed=[]
            def exchange(fd,n):
                raw=real_read(fd,n)
                if os.fstat(fd).st_ino==wanted and not changed:binary.rename(root/'old');binary.write_bytes(b'qemu'*100);binary.chmod(0o755);changed.append(True)
                return raw
            proxy.read=exchange
            with self.assertRaisesRegex(ValueError,'coldboot_qemu_changed'):scope['qemu_fact']()
    def test_sdk_alias_and_resource_drift_stops_before_attempt_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();scope,events=self.launch_scope(root);scope['selected_preflight']=lambda:(_ for _ in ()).throw(ValueError('coldboot_resource_budget_changed'))
            with self.assertRaisesRegex(ValueError,'coldboot_resource_budget_changed'):scope['launch_once'](root)
            self.assertEqual([],events);self.assertFalse((root/'attempt.json').exists())
    def test_actual_guest_probe_requires_matching_sdk_abi_avd_and_shell_uid(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();adb=root/'adb';adb.write_bytes(b'adb');adb.chmod(0o755);scope['LAUNCH']={'adbPath':str(adb),'adbFacts':{'generation':scope['fp'](adb.stat())},'port':5684,'environment':{},'device':'api29','avd':'owned-api29'}
            values={'ro.build.version.sdk':'29','ro.product.cpu.abi':'x86_64','ro.kernel.qemu.avd_name':'owned-api29','ro.boot.qemu.avd_name':'','sys.boot_completed':'1'}
            def response(argv,**kwargs):
                last=argv[-1];value=values.get(last,'2000' if last=='-u' else '11111111-1111-4111-8111-111111111111');return types.SimpleNamespace(stdout=value.encode(),stderr=b'',returncode=0)
            with mock.patch.object(scope['subprocess'],'run',side_effect=response):self.assertTrue(scope['guest_probe']({})['matched'])
            values['ro.product.cpu.abi']='arm64-v8a'
            with mock.patch.object(scope['subprocess'],'run',side_effect=response):self.assertFalse(scope['guest_probe']({})['matched'])
    def test_actual_guest_probe_shell_root_is_unadmitted(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();adb=root/'adb';adb.write_bytes(b'adb');adb.chmod(0o755);scope['LAUNCH']={'adbPath':str(adb),'adbFacts':{'generation':scope['fp'](adb.stat())},'port':5684,'environment':{},'device':'api29','avd':'owned-api29'}
            values={'ro.build.version.sdk':'29','ro.product.cpu.abi':'x86_64','ro.kernel.qemu.avd_name':'owned-api29','ro.boot.qemu.avd_name':'','sys.boot_completed':'1','-u':'0','/proc/sys/kernel/random/boot_id':'11111111-1111-4111-8111-111111111111'}
            with mock.patch.object(scope['subprocess'],'run',side_effect=lambda argv,**kwargs:types.SimpleNamespace(stdout=values[argv[-1]].encode(),stderr=b'',returncode=0)):self.assertFalse(scope['guest_probe']({})['matched'])
    def test_actual_supervisor_records_emulator_child_before_second_go(self):
        scope=self.scope();events=[];scope['CFG']={'source':{}};scope['LAUNCH']={'correlationId':'new','intentSha256':'intent'}
        scope['selected_preflight']=lambda:{};scope['qemu_fact']=lambda:{'fact':'exact'};scope['journal_read']=lambda *args:{'qemuFact':{'fact':'exact'}};scope['child_identity']=lambda pid:{'pid':pid,'startTicks':10}
        scope['journal_write']=lambda path,name,body:events.append(name)
        proxy=types.SimpleNamespace(**vars(os));proxy.setsid=lambda:None;proxy.getpid=lambda:45;proxy.fork=lambda:123;proxy.read=lambda fd,n:b'G';proxy.write=lambda fd,data:events.append('GO') or len(data);proxy.close=lambda fd:None;proxy.waitpid=lambda *args:(_ for _ in ()).throw(ChildProcessError());exit_codes=[]
        def leave(code):exit_codes.append(code);raise SystemExit(code)
        proxy._exit=leave;proxy.dup2=lambda *args:None;proxy.open=lambda *args:12;proxy.listdir=lambda path:[];scope['os']=proxy;scope['ctypes']=types.SimpleNamespace(CDLL=lambda *args,**kwargs:types.SimpleNamespace(prctl=lambda *args:0));proxy.pipe=lambda:(10,11)
        with self.assertRaises(SystemExit):scope['child_exec'](1,2,3,Path('/fixed'))
        self.assertLess(events.index('emulator-child.json'),events.index('GO'));self.assertEqual(0,exit_codes[0])
    def test_actual_fork_supervisor_closes_transport_pipes_before_blocked_go(self):
        # Real fork/descriptors, no emulator fork or exec: the original
        # supervisor is held at its first GO until the assertion finishes.
        scope=self.scope();scope['ctypes']=types.SimpleNamespace(CDLL=lambda *args,**kwargs:types.SimpleNamespace(prctl=lambda *args:0))
        # Production enumerates Linux procfd; macOS's equivalent is used only
        # for this inert child descriptor census, with real close/flock calls.
        proxy=types.SimpleNamespace(**vars(os));proxy.listdir=lambda path:os.listdir('/dev/fd' if not Path('/proc/self/fd').exists() else path);scope['os']=proxy
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'private-log';log=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            lock_path=Path(tmp)/'device.lock';lock=os.open(lock_path,os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            extra_read,extra_write=os.pipe();go_read,go_write=os.pipe();out_read,out_write=os.pipe();err_read,err_write=os.pipe();pid=os.fork()
            if pid==0:
                os.close(go_write);os.close(out_read);os.close(err_read);os.dup2(out_write,1);os.dup2(err_write,2);os.close(out_write);os.close(err_write)
                scope['child_exec'](go_read,-1,log,Path(tmp));os._exit(127)
            os.close(go_read);os.close(out_write);os.close(err_write);os.close(log);os.close(lock);os.close(extra_write)
            try:
                for descriptor in (out_read,err_read):
                    ready,_,_=select.select([descriptor],[],[],1)
                    self.assertEqual([descriptor],ready,'live supervisor retains SSH output pipes')
                self.assertEqual(b'',os.read(out_read,1));self.assertEqual(b'',os.read(err_read,1));self.assertEqual((0,0),os.waitpid(pid,os.WNOHANG))
                fresh_lock=os.open(lock_path,os.O_RDWR)
                try:fcntl.flock(fresh_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fresh_lock)
                self.assertEqual([extra_read],select.select([extra_read],[],[],1)[0]);self.assertEqual(b'',os.read(extra_read,1))
            finally:
                os.write(go_write,b'X');os.close(go_write);_,status=os.waitpid(pid,0);os.close(out_read);os.close(err_read);os.close(extra_read)
            self.assertEqual(125,os.waitstatus_to_exitcode(status))
    def test_singleline_carrier_preserves_large_actual_program_bytes(self):
        program='# inert padding\n'*16000+'value="unicode Ω"\n';prepared={'program':program,'snapshots':{},'claims':{}}
        carrier=coldboot.ssh_carrier(prepared);self.assertNotIn('\n',carrier);self.assertLess(len(carrier.encode()),131072)
        namespace={};exec(carrier,namespace);self.assertEqual('unicode Ω',namespace['value'])
    def test_fresh_local_journal_creates_private_parents_and_exact_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'.rag_index/android-avd-coldboot/11111111-1111-4111-8111-111111111111/launch.json'
            coldboot._write_local_intent(path,{'source':'pinned','intent':{'correlationId':'new'}})
            self.assertEqual({'source':'pinned','intent':{'correlationId':'new'}},json.loads(path.read_bytes()))
            self.assertEqual(0o600,path.stat().st_mode&0o777)
            for parent in (path.parent,path.parent.parent):self.assertEqual(0o700,parent.stat().st_mode&0o777)
    def test_local_journal_symlink_parent_is_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();private=root/'.rag_index';private.mkdir(mode=0o700);foreign=root/'foreign';foreign.mkdir();(private/'android-avd-coldboot').symlink_to(foreign,target_is_directory=True)
            path=private/'android-avd-coldboot/11111111-1111-4111-8111-111111111111/launch.json'
            with self.assertRaises(OSError):coldboot._write_local_intent(path,{'intent':'pinned'})
            self.assertEqual([],list(foreign.iterdir()))
    def test_local_journal_parent_route_exchange_rejects_without_foreign_write(self):
        normal=os.open;changed=[]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();private=root/'.rag_index';private.mkdir(mode=0o700);owner=private/'android-avd-coldboot';owner.mkdir(mode=0o700);foreign=root/'foreign';foreign.mkdir();correlation='11111111-1111-4111-8111-111111111111'
            def exchange(name,flags,*args,**kwargs):
                fd=normal(name,flags,*args,**kwargs)
                if name=='android-avd-coldboot' and not changed:owner.rename(private/'moved');owner.symlink_to(foreign,target_is_directory=True);changed.append(True)
                return fd
            with mock.patch.object(coldboot.os,'open',side_effect=exchange),self.assertRaisesRegex(ValueError,'coldboot_local_ancestry_changed'):coldboot._write_local_intent(owner/correlation/'launch.json',{'intent':'pinned'})
            self.assertEqual([],list(foreign.iterdir()))
    def test_local_journal_partial_creation_stays_unknown_and_cannot_resubmit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'.rag_index/android-avd-coldboot/11111111-1111-4111-8111-111111111111/launch.json'
            with mock.patch.object(coldboot.os,'write',side_effect=OSError('measured write failure')),self.assertRaises(OSError):coldboot._write_local_intent(path,{'intent':'pinned'})
            self.assertTrue(path.exists());self.assertEqual(b'',path.read_bytes())
            with self.assertRaises(FileExistsError):coldboot._write_local_intent(path,{'intent':'pinned'})
    def test_local_intent_leaf_generation_exchange_rejects(self):
        normal=os.write;changed=[]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();path=root/'.rag_index/android-avd-coldboot/11111111-1111-4111-8111-111111111111/launch.json'
            def exchange(fd,data):
                count=normal(fd,data)
                if not changed:path.rename(path.with_name('old'));path.write_bytes(data);path.chmod(0o600);changed.append(True)
                return count
            with mock.patch.object(coldboot.os,'write',side_effect=exchange),self.assertRaisesRegex(ValueError,'coldboot_local_intent_changed'):coldboot._write_local_intent(path,{'intent':'pinned'})
    def test_actual_prepare_fresh_filesystem_writes_intent_without_writer_mock(self):
        # Only upstream proof/config admission is an inert fixture. The complete
        # prepare path, journal creation/writer/readback and guards are real.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();helper=root/'agent_tools/android_avd_coldboot.py';helper.parent.mkdir();helper.write_bytes(Path(coldboot.__file__).read_bytes())
            registry=root/'.rag_index/native-environments/reservations.json';registry.parent.mkdir(parents=True,mode=0o700);registry.parent.parent.chmod(0o700)
            row={'id':'env-fixture','token':'fixture-token','hostAlias':'archlinux','environment':'owned-android-api29-coldboot','operator':'root-android','requestedMemoryBytes':coldboot.MEMORY,'allocationState':'pending'};registry.write_text(json.dumps({'reservations':[row]}));registry.chmod(0o600)
            identity={key:row[{'reservationId':'id'}.get(key,key)] for key in ('reservationId','token','hostAlias','environment','operator')}
            emulator=census.preflight.OWNED['api29']['emulator'];proof={'correlationId':coldboot.CENSUS_ID,'summary':{'stable':True,'complete':True,'ownedPortsFree':True},'observations':[{'processes':{'holders':[]},'avds':{'api29':{'sdkFiles':{emulator:{'generation':[1]*9},'/opt/android-sdk/platform-tools/adb':{'generation':[2]*9}}}}}]}
            base=root/'.runtime/parity-evidence'/('android-avd-sdk-alias-census-'+coldboot.CENSUS_ID);base.mkdir(parents=True);raw=json.dumps(proof).encode();digest=hashlib.sha256(raw).hexdigest();(base/'remote-full.json').write_bytes(raw);(base/'result.json').write_text(json.dumps({'pin':{'sha256':digest,'generation':[1,2,len(raw),4,5,0o100600,0,0,1]}}))
            dependency=Path(coldboot.admitted_census.__file__).absolute();snapshot=coldboot.availability._snapshot(dependency)
            upstream={'program':'CFG={}\ncapture()\n','binding':{'source':{}},'snapshots':{dependency:snapshot},'claims':{}}
            correlation='11111111-1111-4111-8111-111111111111'
            with mock.patch.object(coldboot,'__file__',str(helper)),mock.patch.object(coldboot,'CENSUS_SHA',digest),mock.patch.object(coldboot.admitted_census,'prepare_census',return_value=upstream):prepared=coldboot.prepare(root,'api29',correlation,identity,'admit')
            local=root/'.rag_index/android-avd-coldboot'/correlation/'launch.json';self.assertTrue(local.exists());self.assertEqual('admit',json.loads(local.read_bytes())['action']);coldboot.guard_prepared(prepared)
    def test_actual_prepare_launch_uses_new_pending_rows_preserving_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();helper=root/'agent_tools/android_avd_coldboot.py';helper.parent.mkdir();helper.write_bytes(Path(coldboot.__file__).read_bytes())
            registry=root/'.rag_index/native-environments/reservations.json';registry.parent.mkdir(parents=True,mode=0o700);registry.parent.parent.chmod(0o700)
            row={'id':'env-fixture','token':'fixture-token','hostAlias':'archlinux','environment':'owned-android-api29-coldboot','operator':'root-android','requestedMemoryBytes':coldboot.MEMORY,'allocationState':'pending'}
            protected={'id':'protected-old','hostAlias':'archlinux','requestedMemoryBytes':20*1073741824,'allocationState':'pending'}
            registry.write_text(json.dumps({'reservations':[row,protected]}));registry.chmod(0o600)
            identity={key:row[{'reservationId':'id'}.get(key,key)] for key in ('reservationId','token','hostAlias','environment','operator')}
            emulator=census.preflight.OWNED['api29']['emulator'];proof={'correlationId':coldboot.CENSUS_ID,'summary':{'stable':True,'complete':True,'ownedPortsFree':True},'observations':[{'processes':{'holders':[]},'avds':{'api29':{'sdkFiles':{emulator:{'generation':[1]*9},'/opt/android-sdk/platform-tools/adb':{'generation':[2]*9}}}}}]}
            base=root/'.runtime/parity-evidence'/('android-avd-sdk-alias-census-'+coldboot.CENSUS_ID);base.mkdir(parents=True);raw=json.dumps(proof).encode();digest=hashlib.sha256(raw).hexdigest();(base/'remote-full.json').write_bytes(raw);(base/'result.json').write_text(json.dumps({'pin':{'sha256':digest,'generation':[1,2,len(raw),4,5,0o100600,0,0,1]}}))
            dependency=Path(coldboot.admitted_census.__file__).absolute();snapshot=coldboot.availability._snapshot(dependency)
            def upstream(*args):return {'program':'CFG={}\ncapture()\n','binding':{'source':{}},'snapshots':{dependency:snapshot},'claims':{}}
            correlation='11111111-1111-4111-8111-111111111111'
            with mock.patch.object(coldboot,'__file__',str(helper)),mock.patch.object(coldboot,'CENSUS_SHA',digest),mock.patch.object(coldboot.admitted_census,'prepare_census',side_effect=upstream):
                admitted=coldboot.prepare(root,'api29',correlation,identity,'admit');local=root/'.rag_index/android-avd-coldboot'/correlation/'launch.json';original=local.read_bytes()
                newer={'id':'protected-new','hostAlias':'archlinux','requestedMemoryBytes':4*1073741824,'allocationState':'pending'};registry.write_text(json.dumps({'reservations':[row,protected,newer]}))
                launch=coldboot.prepare(root,'api29',correlation,identity,'launch')
            def body(program):return ast.literal_eval(next(n.value for n in ast.parse(program).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='LAUNCH' for t in n.targets)))
            old=body(admitted['program']);fresh=body(launch['program']);self.assertEqual(22*1073741824,old['pendingBytes']);self.assertEqual(26*1073741824,fresh['pendingBytes']);self.assertEqual(original,local.read_bytes());self.assertEqual(old['intent'],fresh['intent'])
            coldboot.guard_prepared(launch);registry.write_text(json.dumps({'reservations':[row]}))
            with self.assertRaisesRegex(ValueError,'census_local_source_changed'):coldboot.guard_prepared(launch)

class ExistingReadonlyTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import Context
        self.temporary=tempfile.TemporaryDirectory(prefix='coldboot-public-history-')
        self.addCleanup(self.temporary.cleanup)
        self.history=Context(Path(self.temporary.name))
        self.addCleanup(self.history.close)
        self.current_coldboot=coldboot
        from agent_tools.tests.fixtures.android_remaining_hermetic import existing_reader
        patch=mock.patch.dict(globals(),coldboot=existing_reader(self.history,coldboot))
        patch.start();self.addCleanup(patch.stop)
    def require_history(self):
        ROOT=self.history.root
        path=ROOT/'.rag_index/android-avd-coldboot'/coldboot.EXISTING_API35_CORRELATION/'launch.json'
        self.assertTrue(path.is_file(),'synthetic historical ledger missing')

    def evidence(self):
        p=Path(__file__).parent/'fixtures/android_existing_readonly/coldboot_producer.source'
        pin,raw=coldboot.availability._snapshot(p.resolve())
        return {'path':str(p.resolve()),'generation':list(pin),'sha256':hashlib.sha256(raw).hexdigest()}

    def prepare(self):
        self.require_history()
        import uuid
        ROOT=self.history.root
        return coldboot.prepare_existing_api35_readonly(ROOT,str(uuid.uuid4()),
                                                       self.history.reservation,self.evidence())

    def test_actual_existing_prepare_separates_maps_and_source_closing(self):
        value=self.prepare();tree=ast.parse(value['program'])
        def assignment(name):
            return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)))
        cfg=assignment('CFG');launch=assignment('LAUNCH')
        self.assertNotEqual(cfg['source'],launch['intent']['source'])
        self.assertNotEqual(cfg['correlationId'],launch['correlationId'])
        self.assertEqual(coldboot.EXISTING_API35_PRODUCER_SHA,
                         launch['intent']['source']['agent_tools/android_avd_coldboot.py'])
        coldboot.validate_existing_readonly(value['program']);coldboot.guard_prepared(value)
        original=coldboot.availability._snapshot;producer=Path(self.evidence()['path'])
        def changed(path):
            pin,raw=original(path)
            return (pin,raw+b'drift') if Path(path)==producer else (pin,raw)
        with mock.patch.object(coldboot.census.availability,'_snapshot',side_effect=changed), \
             self.assertRaisesRegex(ValueError,'census_local_source_changed'):
            coldboot.guard_prepared(value)

    def test_actual_old_route_remains_strict_and_new_correlation_is_fresh(self):
        self.require_history()
        ROOT=self.history.root
        with self.assertRaisesRegex(ValueError,'coldboot_local_intent_changed'):
            coldboot.prepare(ROOT,'api35',coldboot.EXISTING_API35_CORRELATION,
                             self.history.reservation,'status')
        with self.assertRaisesRegex(ValueError,'coldboot_readonly_correlation'):
            coldboot.prepare_existing_api35_readonly(ROOT,coldboot.EXISTING_API35_CORRELATION,
                                                     self.history.reservation,self.evidence())

    def test_actual_historical_reader_refuses_coherent_substitution_and_pin_drift(self):
        self.require_history()
        import copy,uuid
        ROOT=self.history.root
        original=coldboot.private_io._private
        path=ROOT/'.rag_index/android-avd-coldboot'/coldboot.EXISTING_API35_CORRELATION/'launch.json'
        launch,_,_=original(path,262144)
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            foreign=Path(tmp)/'foreign';foreign.write_text(json.dumps(dict(launch,device='api29')));foreign.chmod(0o600)
            # Redirect only this historical OS read to a real changed file.
            def read(p,limit=1048576):return original(foreign if Path(p)==path else p,limit)
            with mock.patch.object(coldboot.private_io,'_private',side_effect=read), \
                 self.assertRaisesRegex(ValueError,'coldboot_readonly_historical_launch_changed'):
                coldboot.prepare_existing_api35_readonly(ROOT,str(uuid.uuid4()),
                                                         self.history.reservation,self.evidence())
        for field,value in [('sha256','f'*64),('generation',[False]*9)]:
            evidence=self.evidence();evidence[field]=value
            with self.assertRaisesRegex(ValueError,'coldboot_readonly_historical_producer_unknown'):
                coldboot.prepare_existing_api35_readonly(ROOT,str(uuid.uuid4()),
                                                         self.history.reservation,evidence)
        evidence=self.evidence();evidence['generation'][1]+=1
        with self.assertRaisesRegex(ValueError,'coldboot_readonly_historical_producer_changed'):
            coldboot.prepare_existing_api35_readonly(ROOT,str(uuid.uuid4()),
                                                     self.history.reservation,evidence)

    def status_scope(self,root):
        # Real admission/launch producers create the records. Fork/native facts
        # are the explicit existing ColdbootTests OS seams; no child executes.
        producer,events=ColdbootTests().launch_scope(root)
        historic={'producer':'historical'}
        identity={'pid':123,'startTicks':10,'bootId':'boot','exeGeneration':[1],'commandSha256':'abc'}
        producer['CFG']={'source':historic};producer['LAUNCH']['intent']={'source':historic}
        producer['child_identity']=lambda pid:dict(identity)
        producer['admit_once'](root);producer['launch_once'](root)
        for p in root.glob('*.json'):p.chmod(0o600)
        current=ColdbootTests().scope();current['CFG']={'source':{'producer':'current'}}
        current['LAUNCH']=producer['LAUNCH']
        # Only the Linux guardian UID/GID and process observations are modeled.
        # Actual journal read_fixed/name/parent/file/raw checks still execute.
        proxy=types.SimpleNamespace(**vars(os))
        def metadata(i):
            keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
            v=types.SimpleNamespace(**{k:getattr(i,k)for k in keys});v.st_uid=0;v.st_gid=0;return v
        proxy.fstat=lambda fd:metadata(os.fstat(fd));proxy.stat=lambda *a,**k:metadata(os.stat(*a,**k))
        proxy.getsid=lambda pid:pid;current['os']=proxy
        current['boot']=lambda:'boot';current['child_identity']=lambda pid:dict(identity)
        current['qemu_fact']=producer['qemu_fact'];current['session_guest']=lambda saved,ready:{'pid':456}
        current['guest_probe']=lambda guest:{'matched':True}
        program=census._CENSUS.replace('__CFG__',repr(current['CFG']))
        tree=ast.parse(program);tree.body.pop();program=ast.unparse(tree)+'\n'+coldboot._BOOT.replace('__LAUNCH__',repr(current['LAUNCH']))
        rendered=ast.parse(coldboot.existing_readonly_program(program))
        status=next(n for n in rendered.body if isinstance(n,ast.FunctionDef)and n.name=='original_status')
        fixed=types.FunctionType(next(c for c in compile(ast.Module(body=[status],type_ignores=[]),'<actual-readonly-status>','exec',dont_inherit=True).co_consts if isinstance(c,types.CodeType)),current)
        return current,fixed

    def test_actual_producer_real_fd_original_status_red_then_readonly_green(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as tmp:
            root=Path(tmp).resolve();scope,fixed=self.status_scope(root)
            with self.assertRaisesRegex(ValueError,'coldboot_child_record_changed'):
                scope['original_status'](root)
            self.assertEqual('guest-generation-admitted',fixed(root)['state'])
            for name,code in [('child.json','coldboot_child_record_changed'),('ready.json','coldboot_ready_changed')]:
                p=root/name;old=p.read_bytes();value=json.loads(old);value['source']=scope['CFG']['source']
                p.write_text(json.dumps(value));p.chmod(0o600)
                with self.assertRaisesRegex(ValueError,code):fixed(root)
                p.write_bytes(old)
            identity=scope['child_identity'](123);identity['startTicks']+=1
            scope['child_identity']=lambda pid:identity
            self.assertEqual('coldboot_original_pid_reused',fixed(root)['reason'])
